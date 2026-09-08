"""RED contracts for server-authoritative profile-release reconciliation.

The suite intentionally contains no real authority, DSN, membership, label, or
evidence bytes.  Every hostile value below is a synthetic canary.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import secrets
import threading
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from pydantic import ValidationError
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itda.api.dependencies import (
    Phase3Principal,
    get_evaluation_repository,
    get_phase3_principal,
)
from itda.api.main import create_app
from itda.api.routes.evaluation import (
    ProfileReleaseDraftCleanupUnknownResponse,
    ProfileReleaseErrorResponse,
    _profile_release_authority_service,
)
from itda.cli import manage_profile_release
from itda.contracts import profile_release, profile_release_authority
from itda.contracts.profile_release_authority import (
    ProfileReleaseBuildAuthorityResolution,
    _fixed_root_build_resolution,
)
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.session import (
    create_database_engine,
    create_session_factory,
    sqlalchemy_url_from_dsn,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from tests.integration.test_profile_release import (
    _assert_single_head_contains_revision,
    profile_release_build_authority,
    register_profile_release_builder_admin,
    unregister_profile_release_builder_admin,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
EXPECTED_HEAD = "0010_phase3_profile_release_build_reconciliation"
RAW_BUILD_NONCE = "1" * 64
RAW_TRANSITION_NONCE = "2" * 64
BUILD_NONCE_SHA256 = hashlib.sha256(RAW_BUILD_NONCE.encode("ascii")).hexdigest()
TRANSITION_NONCE_SHA256 = hashlib.sha256(RAW_TRANSITION_NONCE.encode("ascii")).hexdigest()
_TEST_AUTHORIZATION_KEY_HEX = "41" * 32

PROTECTED_CANARIES = (
    "synthetic-authority-token-canary",
    "synthetic-capability-canary",
    "synthetic-password-canary",
    "postgresql://synthetic.invalid/private",
    "/synthetic/private/path",
    "synthetic-dev-membership-canary",
    "synthetic-blind-order-complement-canary",
    "synthetic-raw-label-revision-canary",
    "synthetic-evidence-body-canary",
)

BUILD_OUTCOME_KEYS = {
    "outcome",
    "release_sha256",
    "state",
    "receipt_sha256",
    "nonce_sha256",
    "binding_sha256",
    "completion",
}
POINTER_KEYS = {"active_release_sha256", "state", "receipt_sha256"}
STATE_KEYS = {
    "release_sha256",
    "state",
    "lifecycle_head_receipt_sha256",
    "provenance_kind",
    "provenance_receipt_sha256",
}
TRANSITION_OUTCOME_KEYS = {
    "outcome",
    "action",
    "release_sha256",
    "previous_release_sha256",
    "expected_current_sha256",
    "receipt_sha256",
    "nonce_sha256",
    "binding_sha256",
    "completion",
}


def _alembic_script() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(ALEMBIC_CONFIG)))


def _migration_config(postgres_harness: object, role_names: Mapping[str, str]) -> Config:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["database_name"] = postgres_harness.database_name
    for capability in ("runtime", "dev", "sealer", "evaluator"):
        config.attributes[f"{capability}_role"] = postgres_harness.role_names[capability]
    for capability, role_name in role_names.items():
        config.attributes[f"label_{capability}_role"] = role_name
    config.attributes["profile_release_authorization_hmac_key"] = _TEST_AUTHORIZATION_KEY_HEX
    return config


class _AuthorityResolvedTestRepository(EvaluationRepository):
    """Keep lifecycle tests focused while production rejects unresolved BUILD calls."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        builder_factory: sessionmaker[Session],
        authority_connection_factory: sessionmaker[Session],
    ) -> None:
        super().__init__(factory, authority_connection_factory=authority_connection_factory)
        self._builder_repository = EvaluationRepository(
            builder_factory,
            authority_connection_factory=authority_connection_factory,
        )

    def build_profile_release(
        self,
        candidate: profile_release.ProfileReleaseCandidate,
        *,
        authenticated_principal: str,
        reconciliation_nonce: str,
        client_actor_id: str | None = None,
    ) -> profile_release.ProfileReleaseBuildOutcome:
        return self._builder_repository.build_profile_release(
            _authority(candidate, repository=self._builder_repository),
            authenticated_principal=authenticated_principal,
            reconciliation_nonce=reconciliation_nonce,
            client_actor_id=client_actor_id,
        )

    def build_profile_release_from_draft(
        self,
        draft_ref: str,
        *,
        authenticated_principal: str,
        nonce_sha256: str,
        reconciliation_only: bool = False,
    ) -> profile_release.ProfileReleaseBuildOutcome:
        authority_resolution = None
        if not reconciliation_only:
            candidate = self._builder_repository.get_profile_release_build_draft_candidate(
                draft_ref,
                authenticated_principal=authenticated_principal,
                nonce_sha256=nonce_sha256,
            )
            if candidate is not None:
                authority_resolution = _authority(
                    candidate,
                    repository=self._builder_repository,
                )
        return self._builder_repository.build_profile_release_from_draft(
            draft_ref,
            authenticated_principal=authenticated_principal,
            nonce_sha256=nonce_sha256,
            authority_resolution=authority_resolution,
            reconciliation_only=reconciliation_only,
        )


@pytest.fixture(scope="module")
def reconciliation_runtime(
    postgres_harness: object,
) -> Iterator[tuple[Config, Mapping[str, str], EvaluationRepository]]:
    suffix = secrets.token_hex(4)
    capabilities = (
        "evaluator_a",
        "evaluator_b",
        "evaluator_c",
        "adjudicator",
        "model_runner",
        "builder",
        "approver",
    )
    role_names = {
        capability: f"itda_reconciliation_{capability}_{suffix}" for capability in capabilities
    }
    authority_owner = "itda_profile_release_write_authority"
    authority_service = "itda_profile_release_authority_service"
    authority_password = secrets.token_urlsafe(24)
    builder_password = "synthetic-builder-role-password"
    with postgres_harness.connect("admin", autocommit=True) as connection:
        for role_name in role_names.values():
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOINHERIT"
                ).format(sql.Identifier(role_name))
            )
        connection.execute(
            sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(role_names["builder"]),
                sql.Literal(builder_password),
            )
        )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(role_names["builder"]),
            )
        )
        connection.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
            ).format(sql.Identifier(authority_owner))
        )
        connection.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOINHERIT"
            ).format(
                sql.Identifier(authority_service),
                sql.Literal(authority_password),
            )
        )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(authority_service),
            )
        )
    config = _migration_config(postgres_harness, role_names)
    command.upgrade(config, "head")
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    builder_dsn = make_conninfo(
        **(
            admin_info
            | {
                "user": role_names["builder"],
                "password": builder_password,
            }
        )
    )
    admin_engine = create_database_engine(postgres_harness.dsns["admin"])
    builder_engine = create_database_engine(builder_dsn)
    authority_dsn = make_conninfo(
        **(
            admin_info
            | {
                "user": authority_service,
                "password": authority_password,
            }
        )
    )
    authority_engine = create_database_engine(authority_dsn)
    repository = _AuthorityResolvedTestRepository(
        create_session_factory(admin_engine),
        builder_factory=create_session_factory(builder_engine),
        authority_connection_factory=create_session_factory(authority_engine),
    )
    register_profile_release_builder_admin(role_names["builder"], postgres_harness.dsns["admin"])
    try:
        yield config, role_names, repository
    finally:
        unregister_profile_release_builder_admin(role_names["builder"])
        admin_engine.dispose()
        builder_engine.dispose()
        authority_engine.dispose()
        with postgres_harness.connect("admin", autocommit=True) as connection:
            connection.execute(
                "TRUNCATE dev_eval.profile_release_build_capabilities_v1, "
                "dev_eval.profile_release_build_authorizations_v1, "
                "dev_eval.profile_release_fixed_root_authorities_v1, "
                "dev_eval.profile_release_build_draft_consumptions, "
                "dev_eval.profile_release_build_drafts, "
                "dev_eval.profile_release_build_receipts, "
                "dev_eval.profile_release_build_nonce_reservations, "
                "dev_eval.profile_release_nonce_quarantine_0010 CASCADE"
            )
        command.downgrade(config, "0007_phase3_evidence_reviews")
        with postgres_harness.connect("admin", autocommit=True) as connection:
            for role_name in reversed(tuple(role_names.values())):
                connection.execute(
                    sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role_name))
                )
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_name))
                )
            for role_name in (authority_service, authority_owner):
                connection.execute(
                    sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role_name))
                )
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_name))
                )


def _public_fields(model_name: str) -> set[str]:
    model = getattr(profile_release, model_name)
    return set(model.model_fields)


def test_0010_is_the_single_linear_head_and_sole_0009_successor() -> None:
    script = _alembic_script()
    _assert_single_head_contains_revision(
        script,
        "0014_phase4_profile_release_write_boundary",
    )
    assert script.get_revision(EXPECTED_HEAD).down_revision == (
        "0009_phase3_profile_pin_privileges"
    )


def _candidate(release_id: str) -> profile_release.ProfileReleaseCandidate:
    return profile_release.ProfileReleaseCandidate(
        release_id=release_id,
        builder_principal="phase3-builder",
        canonical_lineage_sha256="a" * 64,
        dev_lineage_sha256="b" * 64,
        profile_schema_sha256="c" * 64,
        label_freeze_sha256="d" * 64,
        candidate_run_sha256="e" * 64,
        reviewed_manifest_sha256="f" * 64,
        rights_manifest_sha256="1" * 64,
        source_manifest_sha256="2" * 64,
        code_sha256="3" * 64,
        config_sha256="4" * 64,
        cohort=tuple(
            profile_release.ProfileReleaseCohortMember(
                place_ref=f"synthetic-place-{index:02d}",
                label_ready=True,
                rights_ready=True,
                evidence_ready=True,
                description_lane="READY",
                odii_lane="MISSING" if index % 3 == 0 else "READY",
                profile_sha256=f"{index + 1:064x}",
                label_export_sha256=f"{index + 101:064x}",
                candidate_manifest_sha256=f"{index + 201:064x}",
                reviewed_evidence_manifest_sha256=f"{index + 301:064x}",
                accepted_review_set_sha256=f"{index + 401:064x}",
                rights_sha256=f"{index + 501:064x}",
                source_sha256=f"{index + 601:064x}",
            )
            for index in range(24)
        ),
    )


def _authority(
    candidate: profile_release.ProfileReleaseCandidate,
    *,
    repository: EvaluationRepository | None = None,
) -> ProfileReleaseBuildAuthorityResolution:
    if repository is not None:
        return profile_release_build_authority(repository, candidate)
    authority_root = canonical_sha256(candidate.model_dump(mode="json"))
    return _fixed_root_build_resolution(
        candidate=candidate,
        authority_root_sha256=authority_root,
        authority_registry_id=uuid5(NAMESPACE_URL, authority_root),
        builder_database_principal="synthetic-builder-database",
        expected_predecessor_sha256=None,
    )


def _archived_build_proof(
    outcome: profile_release.ProfileReleaseBuildOutcome,
    *,
    raw_nonce: str,
) -> dict[str, str]:
    return {
        "builder_principal": "phase3-builder",
        "raw_nonce": raw_nonce,
        "nonce_sha256": outcome.nonce_sha256,
        "binding_sha256": outcome.binding_sha256,
        "release_sha256": outcome.release_sha256,
        "receipt_sha256": outcome.receipt_sha256,
    }


def _configure_predecessor_backfill(
    config: Config,
    tmp_path: Path,
    blocked: Exception,
    receipts: list[dict[str, str]],
) -> None:
    database_match = re.search(r"database_identity_sha256=([0-9a-f]{64})", str(blocked))
    snapshot_match = re.search(r"predecessor_snapshot_sha256=([0-9a-f]{64})", str(blocked))
    assert database_match is not None and snapshot_match is not None
    manifest = {
        "schema_version": "itda.profile-release-build-provenance-backfill.v1",
        "database_identity_sha256": database_match.group(1),
        "predecessor_snapshot_sha256": snapshot_match.group(1),
        "receipts": receipts,
    }
    manifest_path = tmp_path / "synthetic-profile-release-backfill.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    manifest_sha256 = canonical_sha256(manifest)
    approval_sha256 = canonical_sha256(
        {
            "schema_version": "itda.profile-release-build-provenance-approval.v1",
            "database_identity_sha256": database_match.group(1),
            "predecessor_snapshot_sha256": snapshot_match.group(1),
            "manifest_sha256": manifest_sha256,
        }
    )
    config.attributes["profile_release_provenance_backfill_path"] = str(manifest_path)
    config.attributes["profile_release_provenance_backfill_approval_sha256"] = approval_sha256


def test_build_repository_reconciles_same_binding_and_rejects_divergence(
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    first = _candidate("synthetic-reconciliation-first")
    created = repository.build_profile_release(
        first,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=RAW_BUILD_NONCE,
    )
    replayed = repository.build_profile_release(
        first,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=RAW_BUILD_NONCE,
    )
    assert created.completion.value == "MUTATION_COMMITTED"
    assert replayed.completion.value == "RELOOKUP_CONFIRMED"
    assert replayed.receipt_sha256 == created.receipt_sha256
    assert (
        repository.get_profile_release_build_outcome_by_nonce(
            BUILD_NONCE_SHA256,
            "phase3-builder",
        )
        == replayed
    )
    assert (
        repository.get_profile_release_build_outcome_by_nonce(
            RAW_BUILD_NONCE,
            "phase3-builder",
        )
        is None
    )

    with pytest.raises(profile_release.ProfileReleaseReplayError):
        repository.build_profile_release(
            _candidate("synthetic-reconciliation-divergent"),
            authenticated_principal="phase3-builder",
            reconciliation_nonce=RAW_BUILD_NONCE,
        )
    with pytest.raises((IntegrityError, profile_release.ProfileReleaseReplayError)):
        repository.build_profile_release(
            first,
            authenticated_principal="phase3-builder",
            reconciliation_nonce="3" * 64,
        )


def test_repository_rejects_unresolved_raw_build_without_lifecycle_writes(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    unresolved_repository = EvaluationRepository(repository._factory)
    tables = (
        "profile_releases",
        "profile_release_lifecycle_heads",
        "profile_release_build_receipts",
    )

    def counts() -> tuple[int, ...]:
        with postgres_harness.connect("admin", autocommit=True) as connection:
            return tuple(
                connection.execute(f"SELECT count(*) FROM dev_eval.{table}").fetchone()[0]
                for table in tables
            )

    before = counts()
    with pytest.raises(TypeError, match="authority resolution"):
        unresolved_repository.build_profile_release(
            _candidate("synthetic-unresolved-raw-build"),
            authenticated_principal="phase3-builder",
            reconciliation_nonce="d" * 64,
        )
    assert counts() == before


def test_build_draft_persists_only_a_digest_handle_and_builds_exact_candidate(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate("synthetic-server-side-draft")
    draft = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="9" * 64,
        draft_ref="D" * 43,
    )
    replayed = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="9" * 64,
        draft_ref="D" * 43,
    )
    assert replayed == draft
    with pytest.raises(profile_release.ProfileReleaseReplayError):
        repository.create_profile_release_build_draft(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce="9" * 64,
            draft_ref="Z" * 43,
        )
    draft_digest = hashlib.sha256(draft.draft_ref.encode("ascii")).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        stored = connection.execute(
            "SELECT draft_ref_sha256, builder_principal, candidate_payload, nonce_sha256 "
            "FROM dev_eval.profile_release_build_drafts WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone()
        assert stored is not None
        assert stored[0] == draft_digest
        assert stored[1] == "phase3-builder"
        assert stored[2]["cohort"][0]["place_ref"] == "synthetic-place-00"
        assert stored[3] == draft.nonce_sha256
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE builder_principal = %s AND nonce_sha256 = %s",
            ("phase3-builder", draft.nonce_sha256),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE draft_ref_sha256 = %s",
            (draft.draft_ref,),
        ).fetchone() == (0,)
    outcome = repository.build_profile_release_from_draft(
        draft.draft_ref,
        authenticated_principal="phase3-builder",
        nonce_sha256=draft.nonce_sha256,
    )
    assert outcome.release_sha256 == candidate.release_sha256
    assert outcome.nonce_sha256 == draft.nonce_sha256
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT candidate_sha256, receipt_sha256 FROM "
            "dev_eval.profile_release_build_draft_consumptions "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (outcome.release_sha256, outcome.receipt_sha256)
    replay_after_response_loss = repository.build_profile_release_from_draft(
        draft.draft_ref,
        authenticated_principal="phase3-builder",
        nonce_sha256=draft.nonce_sha256,
    )
    assert replay_after_response_loss.receipt_sha256 == outcome.receipt_sha256
    recreated_after_consumption = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="9" * 64,
        draft_ref="D" * 43,
    )
    assert recreated_after_consumption.draft_ref == draft.draft_ref
    assert recreated_after_consumption.nonce_sha256 == draft.nonce_sha256
    with pytest.raises(profile_release.ProfileReleaseReplayError):
        repository.create_profile_release_build_draft(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce="9" * 64,
            draft_ref="Y" * 43,
        )
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE builder_principal = %s AND nonce_sha256 = %s",
            ("phase3-builder", draft.nonce_sha256),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_draft_consumptions "
            "WHERE builder_principal = %s AND nonce_sha256 = %s",
            ("phase3-builder", draft.nonce_sha256),
        ).fetchone() == (1,)


def test_direct_build_then_draft_reconciles_without_protected_payload(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate("synthetic-direct-then-draft")
    raw_nonce = "6" * 64
    direct = repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=raw_nonce,
    )
    draft_ref = "Q" * 43
    reconciled = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=raw_nonce,
        draft_ref=draft_ref,
    )
    assert reconciled.draft_ref == draft_ref
    assert reconciled.nonce_sha256 == direct.nonce_sha256

    replayed = repository.build_profile_release_from_draft(
        draft_ref,
        authenticated_principal="phase3-builder",
        nonce_sha256=reconciled.nonce_sha256,
    )
    assert replayed.receipt_sha256 == direct.receipt_sha256
    assert replayed.release_sha256 == direct.release_sha256

    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE builder_principal = %s AND nonce_sha256 = %s",
            ("phase3-builder", direct.nonce_sha256),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_draft_consumptions "
            "WHERE builder_principal = %s AND nonce_sha256 = %s",
            ("phase3-builder", direct.nonce_sha256),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT candidate_sha256, draft_ref_sha256 FROM "
            "dev_eval.profile_release_build_nonce_reservations "
            "WHERE builder_principal = %s AND nonce_sha256 = %s",
            ("phase3-builder", direct.nonce_sha256),
        ).fetchone() == (direct.release_sha256, None)

    with pytest.raises(profile_release.ProfileReleaseReplayError):
        repository.create_profile_release_build_draft(
            _candidate("synthetic-direct-then-draft-conflict"),
            authenticated_principal="phase3-builder",
            reconciliation_nonce=raw_nonce,
            draft_ref="W" * 43,
        )


def test_existing_receipt_draft_build_deletes_exact_payload_before_consumption(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate("synthetic-existing-receipt-draft-cleanup")
    raw_nonce = "0" * 64
    draft = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=raw_nonce,
        draft_ref="V" * 43,
    )
    direct = repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=raw_nonce,
    )
    draft_digest = hashlib.sha256(draft.draft_ref.encode("ascii")).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (1,)

    replayed = repository.build_profile_release_from_draft(
        draft.draft_ref,
        authenticated_principal="phase3-builder",
        nonce_sha256=draft.nonce_sha256,
    )
    assert replayed.receipt_sha256 == direct.receipt_sha256
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT candidate_sha256, receipt_sha256 FROM "
            "dev_eval.profile_release_build_draft_consumptions "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (direct.release_sha256, direct.receipt_sha256)


def test_builder_role_can_atomically_consume_successful_draft(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, role_names, authority_repository = reconciliation_runtime
    builder_role = role_names["builder"]
    builder_password = "synthetic-builder-role-password"
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(builder_role),
                sql.Literal(builder_password),
            )
        )
    role_url = sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).set(
        username=builder_role,
        password=builder_password,
    )
    engine = create_engine(role_url, pool_size=1, max_overflow=0)
    candidate = _candidate("synthetic-builder-role-draft")
    try:
        with engine.connect() as connection:
            repository = EvaluationRepository(
                sessionmaker(bind=connection, expire_on_commit=False),
                authority_connection_factory=(authority_repository._authority_connection_factory),
            )
            draft = repository.create_profile_release_build_draft(
                candidate,
                authenticated_principal="phase3-builder",
                reconciliation_nonce="7" * 64,
                draft_ref="E" * 43,
            )
            outcome = repository.build_profile_release_from_draft(
                draft.draft_ref,
                authenticated_principal="phase3-builder",
                nonce_sha256=draft.nonce_sha256,
                authority_resolution=_authority(candidate, repository=repository),
            )
    finally:
        engine.dispose()
        with postgres_harness.connect("admin", autocommit=True) as connection:
            connection.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(builder_role)))
    assert outcome.release_sha256 == candidate.release_sha256
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE builder_principal = %s",
            ("phase3-builder",),
        ).fetchone() == (0,)


def test_draft_build_reconciles_cleanup_after_commit_response_loss(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate("synthetic-draft-cleanup-commit-loss")
    raw_nonce = "d" * 63 + "1"
    draft = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=raw_nonce,
        draft_ref="J" * 43,
    )
    original_commit = Session.commit
    raised = False

    def commit_then_lose_response(session: Session) -> None:
        nonlocal raised
        original_commit(session)
        if not raised:
            raised = True
            raise DBAPIError("COMMIT", {}, RuntimeError("synthetic response loss"), True)

    with monkeypatch.context() as scoped:
        scoped.setattr(Session, "commit", commit_then_lose_response)
        outcome = repository.build_profile_release_from_draft(
            draft.draft_ref,
            authenticated_principal="phase3-builder",
            nonce_sha256=draft.nonce_sha256,
        )
    assert raised is True
    draft_digest = hashlib.sha256(draft.draft_ref.encode("ascii")).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT candidate_sha256, receipt_sha256 FROM "
            "dev_eval.profile_release_build_draft_consumptions "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (outcome.release_sha256, outcome.receipt_sha256)


def test_concurrent_exact_draft_build_retries_converge_on_one_receipt(
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate("synthetic-concurrent-exact-draft")
    draft = repository.create_profile_release_build_draft(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="8" * 63 + "1",
        draft_ref="Q" * 43,
    )

    def build(_: int) -> profile_release.ProfileReleaseBuildOutcome:
        return repository.build_profile_release_from_draft(
            draft.draft_ref,
            authenticated_principal="phase3-builder",
            nonce_sha256=draft.nonce_sha256,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(build, (1, 2)))
    assert outcomes[0].release_sha256 == outcomes[1].release_sha256
    assert outcomes[0].receipt_sha256 == outcomes[1].receipt_sha256
    assert outcomes[0].nonce_sha256 == outcomes[1].nonce_sha256


def test_expired_build_draft_cleanup_is_explicit_and_independent_of_creation(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    draft = repository.create_profile_release_build_draft(
        _candidate("synthetic-expired-server-side-draft"),
        authenticated_principal="phase3-builder",
        reconciliation_nonce="8" * 64,
        draft_ref="F" * 43,
    )
    draft_digest = hashlib.sha256(draft.draft_ref.encode("ascii")).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "UPDATE dev_eval.profile_release_build_drafts SET "
            "created_at = CURRENT_TIMESTAMP - INTERVAL '2 minutes', "
            "expires_at = CURRENT_TIMESTAMP - INTERVAL '1 minute' "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        )
    purge = repository.purge_expired_profile_release_build_drafts(
        authenticated_principal="phase3-builder",
    )
    assert purge.deleted_count == 1
    assert purge.remaining_expired_count == 0
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
            "WHERE draft_ref_sha256 = %s",
            (draft_digest,),
        ).fetchone() == (0,)


def test_repository_validates_all_four_lifecycle_provenance_forms_and_v1_receipts(
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    first = _candidate("synthetic-lifecycle-first")
    second = _candidate("synthetic-lifecycle-second")
    repository.build_profile_release(
        first,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="4" * 64,
    )
    repository.build_profile_release(
        second,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="5" * 64,
    )
    built = repository.get_profile_release_state(str(first.release_sha256))
    assert built is not None
    assert built.state.value == "BUILT_UNAPPROVED"
    assert built.provenance_kind == "BUILD"
    first_build_nonce_sha256 = hashlib.sha256(("4" * 64).encode("ascii")).hexdigest()

    def assert_first_build_receipt_is_immutable() -> None:
        outcome = repository.get_profile_release_build_outcome_by_nonce(
            first_build_nonce_sha256,
            "phase3-builder",
        )
        assert outcome is not None
        assert outcome.release_sha256 == first.release_sha256
        assert outcome.completion.value == "RELOOKUP_CONFIRMED"

    repository.approve_profile_release(
        str(first.release_sha256),
        authenticated_principal="phase3-approver",
    )
    repository.approve_profile_release(
        str(second.release_sha256),
        authenticated_principal="phase3-approver",
    )
    approved = repository.get_profile_release_state(str(first.release_sha256))
    assert approved is not None
    assert approved.state.value == "APPROVED_INACTIVE"
    assert approved.provenance_kind == "APPROVAL"
    assert_first_build_receipt_is_immutable()

    first_activation = repository.activate_profile_release(
        str(first.release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce=RAW_TRANSITION_NONCE,
    )
    replayed = repository.activate_profile_release(
        str(first.release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce=RAW_TRANSITION_NONCE,
    )
    assert replayed.receipt_sha256 == first_activation.receipt_sha256
    assert replayed.completion.value == "RELOOKUP_CONFIRMED"
    with pytest.raises(ValueError, match="client actor or principal fields are forbidden"):
        repository.activate_profile_release(
            str(first.release_sha256),
            expected_current=None,
            authenticated_principal="phase3-approver",
            nonce=RAW_TRANSITION_NONCE,
            client_actor_id="forged-client-approver",
        )
    assert (
        repository.get_profile_release_transition_outcome_by_nonce(
            RAW_TRANSITION_NONCE,
            "phase3-approver",
        )
        is None
    )
    first_outcome = repository.get_profile_release_transition_outcome_by_nonce(
        TRANSITION_NONCE_SHA256,
        "phase3-approver",
    )
    assert first_outcome is not None
    assert first_outcome.action == "ACTIVATE"
    assert_first_build_receipt_is_immutable()
    assert first_outcome.binding_sha256 == canonical_sha256(
        {
            "action": "ACTIVATE",
            "target": first.release_sha256,
            "expected": None,
        }
    )
    with pytest.raises(profile_release.ProfileReleaseReplayError):
        repository.rollback_profile_release(
            str(first.release_sha256),
            expected_current=str(first.release_sha256),
            authenticated_principal="phase3-approver",
            reason="합성 교차 액션 충돌",
            nonce=RAW_TRANSITION_NONCE,
        )

    second_activation = repository.activate_profile_release(
        str(second.release_sha256),
        expected_current=str(first.release_sha256),
        authenticated_principal="phase3-approver",
        nonce="6" * 64,
    )
    displaced = repository.get_profile_release_state(str(first.release_sha256))
    active = repository.get_profile_release_state(str(second.release_sha256))
    pointer = repository.get_profile_release_active_pointer()
    assert displaced is not None and displaced.provenance_kind == "TRANSITION"
    assert active is not None and active.provenance_kind == "TRANSITION"
    assert displaced.provenance_receipt_sha256 == second_activation.receipt_sha256
    assert pointer.active_release_sha256 == second.release_sha256
    assert pointer.receipt_sha256 == second_activation.receipt_sha256
    assert_first_build_receipt_is_immutable()

    rollback = repository.rollback_profile_release(
        str(first.release_sha256),
        expected_current=str(second.release_sha256),
        authenticated_principal="phase3-approver",
        reason="  합성 복구 사유  ",
        nonce="7" * 64,
    )
    rollback_digest = hashlib.sha256(("7" * 64).encode("ascii")).hexdigest()
    rollback_outcome = repository.get_profile_release_transition_outcome_by_nonce(
        rollback_digest,
        "phase3-approver",
    )
    assert rollback_outcome is not None
    assert rollback_outcome.action == "ROLLBACK"
    assert rollback_outcome.receipt_sha256 == rollback.receipt_sha256
    with pytest.raises(ValueError, match="client actor or principal fields are forbidden"):
        repository.rollback_profile_release(
            str(first.release_sha256),
            expected_current=str(second.release_sha256),
            authenticated_principal="phase3-approver",
            reason="  합성 복구 사유  ",
            nonce="7" * 64,
            client_approver_id="forged-client-approver",
        )
    assert repository.get_profile_release_active_pointer().active_release_sha256 == (
        first.release_sha256
    )
    assert_first_build_receipt_is_immutable()


@pytest.mark.parametrize("pin_kind", ("session", "result"))
@pytest.mark.parametrize("corruption", ("pointer", "head", "receipt"))
def test_pin_rejects_corrupt_active_provenance_without_writing(
    pin_kind: str,
    corruption: str,
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate(f"synthetic-pin-corrupt-{pin_kind}-{corruption}")
    repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=hashlib.sha256(f"build:{pin_kind}:{corruption}".encode()).hexdigest(),
    )
    repository.approve_profile_release(
        str(candidate.release_sha256),
        authenticated_principal="phase3-approver",
    )
    current = repository.get_profile_release_active_pointer().active_release_sha256
    activation = repository.activate_profile_release(
        str(candidate.release_sha256),
        expected_current=current,
        authenticated_principal="phase3-approver",
        nonce=hashlib.sha256(f"activate:{pin_kind}:{corruption}".encode()).hexdigest(),
    )
    receipt_sha256 = str(activation.receipt.receipt_sha256)
    owner_ref = f"synthetic-{pin_kind}-corrupt-{corruption}"
    if corruption == "pointer":
        relation = "profile_release_active_pointer"
        update_sql = (
            "UPDATE dev_eval.profile_release_active_pointer SET receipt_sha256 = %s "
            "WHERE slot = 'DEV'"
        )
        corrupt_params = ("9" * 64,)
        restore_params: tuple[str, ...] = (receipt_sha256,)
    elif corruption == "head":
        relation = "profile_release_lifecycle_heads"
        update_sql = (
            "UPDATE dev_eval.profile_release_lifecycle_heads SET head_receipt_sha256 = %s "
            "WHERE release_sha256 = %s"
        )
        corrupt_params = ("9" * 64, str(candidate.release_sha256))
        restore_params = (receipt_sha256, str(candidate.release_sha256))
    else:
        relation = "profile_release_nonce_ledger"
        update_sql = (
            "UPDATE dev_eval.profile_release_nonce_ledger SET payload = %s::jsonb "
            "WHERE receipt_sha256 = %s"
        )
        corrupt_params = ("{}", receipt_sha256)
        restore_params = (
            activation.receipt.model_dump_json(),
            receipt_sha256,
        )

    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(f"ALTER TABLE dev_eval.{relation} DISABLE TRIGGER USER")
        try:
            connection.execute(update_sql, corrupt_params)
            with pytest.raises(ValueError, match="active|pointer|provenance|transition|binding"):
                if pin_kind == "session":
                    repository.pin_profile_release_session(owner_ref)
                else:
                    repository.pin_profile_release_result(owner_ref)
            pin_relation = f"profile_release_{pin_kind}_pins"
            owner_column = f"{pin_kind}_ref"
            assert connection.execute(
                f"SELECT count(*) FROM dev_eval.{pin_relation} WHERE {owner_column} = %s",
                (owner_ref,),
            ).fetchone() == (0,)
        finally:
            connection.execute(update_sql, restore_params)
            connection.execute(f"ALTER TABLE dev_eval.{relation} ENABLE TRIGGER USER")


@pytest.mark.parametrize(
    "corruption",
    (
        "build_binding",
        "build_receipt",
        "approval_digest",
        "transition_receipt",
        "ledger_binding",
        "rollback_reason",
    ),
)
def test_pin_validator_recomputes_canonical_provenance_digests(
    corruption: str,
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    first = _candidate(f"synthetic-pin-crypto-{corruption}-first")
    repository.build_profile_release(
        first,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=hashlib.sha256(f"build:{corruption}:first".encode()).hexdigest(),
    )
    repository.approve_profile_release(
        str(first.release_sha256),
        authenticated_principal="phase3-approver",
    )
    current = repository.get_profile_release_active_pointer().active_release_sha256
    first_activation = repository.activate_profile_release(
        str(first.release_sha256),
        expected_current=current,
        authenticated_principal="phase3-approver",
        nonce=hashlib.sha256(f"activate:{corruption}:first".encode()).hexdigest(),
    )
    active_release = str(first.release_sha256)
    active_receipt = str(first_activation.receipt_sha256)

    if corruption == "rollback_reason":
        second = _candidate(f"synthetic-pin-crypto-{corruption}-second")
        repository.build_profile_release(
            second,
            authenticated_principal="phase3-builder",
            reconciliation_nonce=hashlib.sha256(f"build:{corruption}:second".encode()).hexdigest(),
        )
        repository.approve_profile_release(
            str(second.release_sha256),
            authenticated_principal="phase3-approver",
        )
        second_activation = repository.activate_profile_release(
            str(second.release_sha256),
            expected_current=active_release,
            authenticated_principal="phase3-approver",
            nonce=hashlib.sha256(f"activate:{corruption}:second".encode()).hexdigest(),
        )
        rollback = repository.rollback_profile_release(
            active_release,
            expected_current=str(second.release_sha256),
            authenticated_principal="phase3-approver",
            reason="canonical rollback reason",
            nonce=hashlib.sha256(f"rollback:{corruption}".encode()).hexdigest(),
        )
        active_receipt = str(rollback.receipt_sha256)
        assert second_activation.receipt_sha256 != active_receipt

    wrong_digest = "9" * 64
    with postgres_harness.connect("admin") as connection:
        assert connection.execute(
            "SELECT dev_eval.validate_active_profile_release_for_pin_v1(%s, %s)",
            (active_release, active_receipt),
        ).fetchone() == (True,)
        if corruption == "build_binding":
            relation = "profile_release_build_receipts"
            mutation = (
                "UPDATE dev_eval.profile_release_build_receipts "
                "SET binding_sha256 = %s WHERE release_sha256 = %s"
            )
            params = (wrong_digest, active_release)
        elif corruption == "build_receipt":
            relation = "profile_release_build_receipts"
            mutation = (
                "UPDATE dev_eval.profile_release_build_receipts "
                "SET receipt_sha256 = %s WHERE release_sha256 = %s"
            )
            params = (wrong_digest, active_release)
        elif corruption == "approval_digest":
            relation = "profile_release_approvals"
            mutation = (
                "UPDATE dev_eval.profile_release_approvals SET approval_sha256 = %s, "
                "payload = jsonb_set(payload, '{approval_sha256}', to_jsonb(%s::text)) "
                "WHERE release_sha256 = %s"
            )
            params = (wrong_digest, wrong_digest, active_release)
        elif corruption == "transition_receipt":
            relation = "profile_release_transition_events"
            mutation = (
                "UPDATE dev_eval.profile_release_transition_events SET "
                "payload = jsonb_set(payload, '{reason}', to_jsonb(%s::text)) "
                "WHERE receipt_sha256 = %s"
            )
            params = ("forged reason", active_receipt)
        elif corruption == "ledger_binding":
            relation = "profile_release_nonce_ledger"
            mutation = (
                "UPDATE dev_eval.profile_release_nonce_ledger SET binding_sha256 = %s "
                "WHERE receipt_sha256 = %s"
            )
            params = (wrong_digest, active_receipt)
        else:
            relation = "profile_release_rollback_receipts"
            mutation = (
                "UPDATE dev_eval.profile_release_rollback_receipts SET reason_sha256 = %s "
                "WHERE receipt_sha256 = %s"
            )
            params = (wrong_digest, active_receipt)

        connection.execute(f"ALTER TABLE dev_eval.{relation} DISABLE TRIGGER USER")
        try:
            connection.execute(mutation, params)
            assert connection.execute(
                "SELECT dev_eval.validate_active_profile_release_for_pin_v1(%s, %s)",
                (active_release, active_receipt),
            ).fetchone() == (False,)
        finally:
            connection.rollback()


@pytest.mark.parametrize("pin_kind", ("session", "result"))
def test_concurrent_first_profile_release_pins_are_exactly_once(
    pin_kind: str,
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    candidate = _candidate(f"synthetic-concurrent-first-{pin_kind}")
    repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=hashlib.sha256(
            f"build:concurrent-first:{pin_kind}".encode()
        ).hexdigest(),
    )
    repository.approve_profile_release(
        str(candidate.release_sha256),
        authenticated_principal="phase3-approver",
    )
    current = repository.get_profile_release_active_pointer().active_release_sha256
    repository.activate_profile_release(
        str(candidate.release_sha256),
        expected_current=current,
        authenticated_principal="phase3-approver",
        nonce=hashlib.sha256(f"activate:concurrent-first:{pin_kind}".encode()).hexdigest(),
    )
    assert repository.get_profile_release_active_pointer().active_release_sha256 == (
        candidate.release_sha256
    )

    relation = f"profile_release_{pin_kind}_pins"
    owner_column = f"{pin_kind}_ref"
    owner_ref = f"synthetic-concurrent-first-{pin_kind}-owner"
    barrier = threading.Barrier(2)
    engine = repository._factory.kw["bind"]

    def synchronize_first_inserts(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if f"INSERT INTO dev_eval.{relation}" in statement:
            barrier.wait(timeout=10)

    event.listen(engine, "before_cursor_execute", synchronize_first_inserts)
    try:
        pin = (
            repository.pin_profile_release_session
            if pin_kind == "session"
            else repository.pin_profile_release_result
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(pin, (owner_ref, owner_ref)))
    finally:
        event.remove(engine, "before_cursor_execute", synchronize_first_inserts)

    assert outcomes[0] == outcomes[1]
    assert outcomes[0].release_sha256 == candidate.release_sha256
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            f"SELECT count(*) FROM dev_eval.{relation} WHERE {owner_column} = %s",
            (owner_ref,),
        ).fetchone() == (1,)


def test_active_pointer_reconciliation_uses_one_repeatable_read_snapshot(
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    old = _candidate("synthetic-snapshot-old")
    new = _candidate("synthetic-snapshot-new")
    for index, candidate in enumerate((old, new), start=20):
        repository.build_profile_release(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce=f"{index:064x}",
        )
        repository.approve_profile_release(
            str(candidate.release_sha256),
            authenticated_principal="phase3-approver",
        )
    current = repository.get_profile_release_active_pointer().active_release_sha256
    repository.activate_profile_release(
        str(old.release_sha256),
        expected_current=current,
        authenticated_principal="phase3-approver",
        nonce="a" * 63 + "1",
    )

    pointer_read = threading.Event()
    transition_committed = threading.Event()

    class BarrierRepository(EvaluationRepository):
        def _get_profile_release_state_from_session(
            self,
            session: Any,
            release_sha256: str,
        ) -> profile_release.ProfileReleaseStateProjection | None:
            pointer_read.set()
            assert transition_committed.wait(timeout=10)
            return super()._get_profile_release_state_from_session(session, release_sha256)

    reader = BarrierRepository(repository._factory)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(reader.get_profile_release_active_pointer)
        assert pointer_read.wait(timeout=10)
        repository.activate_profile_release(
            str(new.release_sha256),
            expected_current=str(old.release_sha256),
            authenticated_principal="phase3-approver",
            nonce="a" * 63 + "2",
        )
        transition_committed.set()
        snapshot = future.result(timeout=10)
    assert snapshot.active_release_sha256 == old.release_sha256
    assert repository.get_profile_release_active_pointer().active_release_sha256 == (
        new.release_sha256
    )


def test_all_mutations_reconcile_after_commit_response_loss(
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, repository = reconciliation_runtime

    def with_commit_response_loss(call: Any) -> Any:
        original_commit = Session.commit
        raised = False

        def commit_then_lose_response(session: Session) -> None:
            nonlocal raised
            original_commit(session)
            if not raised:
                raised = True
                raise DBAPIError("COMMIT", {}, RuntimeError("synthetic response loss"), True)

        with monkeypatch.context() as scoped:
            scoped.setattr(Session, "commit", commit_then_lose_response)
            result = call()
        assert raised is True
        return result

    draft_candidate = _candidate("synthetic-draft-create-commit-loss")
    draft = with_commit_response_loss(
        lambda: repository.create_profile_release_build_draft(
            draft_candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce="a" * 63 + "1",
            draft_ref="G" * 43,
        )
    )
    assert draft.draft_ref == "G" * 43
    with repository._factory() as session:
        assert (
            session.execute(
                text(
                    "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
                    "WHERE builder_principal = :builder AND nonce_sha256 = :nonce"
                ),
                {"builder": "phase3-builder", "nonce": draft.nonce_sha256},
            ).scalar_one()
            == 1
        )

    first = _candidate("synthetic-commit-loss-first")
    built = with_commit_response_loss(
        lambda: repository.build_profile_release(
            first,
            authenticated_principal="phase3-builder",
            reconciliation_nonce="a" * 63 + "3",
        )
    )
    assert built.completion is profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED
    approval = with_commit_response_loss(
        lambda: repository.approve_profile_release(
            str(first.release_sha256),
            authenticated_principal="phase3-approver",
        )
    )
    assert approval.release_sha256 == first.release_sha256
    expected_current = repository.get_profile_release_active_pointer().active_release_sha256
    activation = with_commit_response_loss(
        lambda: repository.activate_profile_release(
            str(first.release_sha256),
            expected_current=expected_current,
            authenticated_principal="phase3-approver",
            nonce="a" * 63 + "4",
        )
    )
    assert activation.completion is profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED

    second = _candidate("synthetic-commit-loss-second")
    repository.build_profile_release(
        second,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="a" * 63 + "5",
    )
    repository.approve_profile_release(
        str(second.release_sha256),
        authenticated_principal="phase3-approver",
    )
    repository.activate_profile_release(
        str(second.release_sha256),
        expected_current=str(first.release_sha256),
        authenticated_principal="phase3-approver",
        nonce="a" * 63 + "6",
    )
    rollback = with_commit_response_loss(
        lambda: repository.rollback_profile_release(
            str(first.release_sha256),
            expected_current=str(second.release_sha256),
            authenticated_principal="phase3-approver",
            reason="합성 응답 손실 복구",
            nonce="a" * 63 + "7",
        )
    )
    assert rollback.completion is profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED


def test_database_engine_hides_protected_statement_parameters(
    postgres_harness: object,
) -> None:
    engine = create_database_engine(postgres_harness.dsns["admin"])
    try:
        assert engine.hide_parameters is True
        candidate_canary = "synthetic-protected-candidate-payload-canary"
        error = DBAPIError(
            "INSERT INTO protected_table(candidate_payload) VALUES (%s)",
            {"candidate_payload": candidate_canary},
            RuntimeError("synthetic database failure"),
            hide_parameters=engine.hide_parameters,
            connection_invalidated=False,
        )
        assert candidate_canary not in str(error)
        assert candidate_canary not in repr(error)
    finally:
        engine.dispose()


def test_all_mutations_bound_serialization_retries_before_safe_abort() -> None:
    class SyntheticSerializationFailure(RuntimeError):
        sqlstate = "40001"

    class EmptyPreflightResult:
        def all(self) -> list[object]:
            return []

        def scalar_one(self) -> str:
            return "synthetic-builder-database"

    class AlwaysSerializationAbortFactory:
        def __init__(self) -> None:
            self.attempts = 0

        def __call__(self) -> AlwaysSerializationAbortFactory:
            return self

        def __enter__(self) -> AlwaysSerializationAbortFactory:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> EmptyPreflightResult:
            del args, kwargs
            return EmptyPreflightResult()

        def connection(self, **kwargs: object) -> None:
            del kwargs
            self.attempts += 1
            raise DBAPIError(
                "BEGIN",
                {},
                SyntheticSerializationFailure("synthetic serialization abort"),
                False,
            )

    candidate = _candidate("synthetic-serialization-retry")
    mutations = {
        "BUILD": lambda repository: repository._build_profile_release_with_nonce_sha256(
            candidate,
            authority_resolution=_authority(candidate),
            authenticated_principal="phase3-builder",
            nonce_sha256=hashlib.sha256(("1" * 64).encode("ascii")).hexdigest(),
            capability_id="00000000-0000-0000-0000-000000000001",
        ),
        "APPROVE": lambda repository: repository.approve_profile_release(
            str(candidate.release_sha256),
            authenticated_principal="phase3-approver",
        ),
        "ACTIVATE": lambda repository: repository.activate_profile_release(
            str(candidate.release_sha256),
            expected_current=None,
            authenticated_principal="phase3-approver",
            nonce="2" * 64,
        ),
        "ROLLBACK": lambda repository: repository.rollback_profile_release(
            str(candidate.release_sha256),
            expected_current="3" * 64,
            authenticated_principal="phase3-approver",
            reason="synthetic rollback",
            nonce="4" * 64,
        ),
    }
    for action, mutation in mutations.items():
        factory = AlwaysSerializationAbortFactory()
        repository = EvaluationRepository(factory)  # type: ignore[arg-type]
        with pytest.raises(profile_release.ProfileReleaseRetryableAbortError) as caught:
            mutation(repository)
        assert caught.value.action == action
        assert factory.attempts == 3


def test_concurrent_global_nonce_uniqueness_keeps_one_transition_and_no_partial_pointer(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    _, _, repository = reconciliation_runtime
    base = _candidate("synthetic-concurrent-base")
    left = _candidate("synthetic-concurrent-left")
    right = _candidate("synthetic-concurrent-right")
    for index, candidate in enumerate((base, left, right), start=9):
        repository.build_profile_release(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce=f"{index:064x}",
        )
        repository.approve_profile_release(
            str(candidate.release_sha256),
            authenticated_principal="phase3-approver",
        )
    current_before_base = repository.get_profile_release_active_pointer().active_release_sha256
    repository.activate_profile_release(
        str(base.release_sha256),
        expected_current=current_before_base,
        authenticated_principal="phase3-approver",
        nonce="c" * 64,
    )

    shared_nonce = "d" * 64
    barrier = threading.Barrier(2)

    def activate(candidate: profile_release.ProfileReleaseCandidate) -> object:
        barrier.wait(timeout=10)
        try:
            return repository.activate_profile_release(
                str(candidate.release_sha256),
                expected_current=str(base.release_sha256),
                authenticated_principal="phase3-approver",
                nonce=shared_nonce,
            )
        except profile_release.ProfileReleaseReplayError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(activate, (left, right)))
    receipts = tuple(
        result
        for result in results
        if isinstance(result, profile_release.ProfileReleaseTransitionMutationResult)
    )
    conflicts = tuple(
        result
        for result in results
        if isinstance(result, profile_release.ProfileReleaseReplayError)
    )
    assert len(receipts) == 1
    assert len(conflicts) == 1
    pointer = repository.get_profile_release_active_pointer()
    assert pointer.active_release_sha256 == receipts[0].release_sha256
    nonce_sha256 = hashlib.sha256(shared_nonce.encode("ascii")).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 = %s",
            (nonce_sha256,),
        ).fetchone() == (1,)


def test_0009_to_0010_requires_exact_archived_build_provenance_before_mutation(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
    tmp_path: Path,
) -> None:
    config, role_names, repository = reconciliation_runtime
    config.attributes["profile_release_database_identity_sha256"] = "d" * 64
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "TRUNCATE dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1, "
            "dev_eval.profile_releases, "
            "dev_eval.profile_release_nonce_ledger, "
            "dev_eval.profile_release_build_drafts, "
            "dev_eval.profile_release_build_nonce_reservations, "
            "dev_eval.profile_release_nonce_quarantine_0010 CASCADE"
        )
    build_nonces = ("a" * 64, "b" * 64, "c" * 64, "e" * 64)
    candidates = tuple(_candidate(f"synthetic-predecessor-state-{index}") for index in range(4))
    outcomes = tuple(
        repository.build_profile_release(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce=nonce,
        )
        for candidate, nonce in zip(candidates, build_nonces, strict=True)
    )
    repository.approve_profile_release(
        str(candidates[1].release_sha256),
        authenticated_principal="phase3-approver",
    )
    for candidate in candidates[2:]:
        repository.approve_profile_release(
            str(candidate.release_sha256),
            authenticated_principal="phase3-approver",
        )
    repository.activate_profile_release(
        str(candidates[2].release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce="4" * 64,
    )
    repository.activate_profile_release(
        str(candidates[3].release_sha256),
        expected_current=str(candidates[2].release_sha256),
        authenticated_principal="phase3-approver",
        nonce="5" * 64,
    )
    repository.rollback_profile_release(
        str(candidates[2].release_sha256),
        expected_current=str(candidates[3].release_sha256),
        authenticated_principal="phase3-approver",
        reason="합성 predecessor 복구",
        nonce="6" * 64,
    )
    archived = [
        _archived_build_proof(outcome, raw_nonce=nonce)
        for outcome, nonce in zip(outcomes, build_nonces, strict=True)
    ]
    with postgres_harness.connect("admin", autocommit=True) as connection:
        predecessor_before = {
            "releases": connection.execute(
                "SELECT release_sha256, payload FROM dev_eval.profile_releases "
                "ORDER BY release_sha256"
            ).fetchall(),
            "heads": connection.execute(
                "SELECT release_sha256, state, head_receipt_sha256 FROM "
                "dev_eval.profile_release_lifecycle_heads ORDER BY release_sha256"
            ).fetchall(),
            "events": connection.execute(
                "SELECT receipt_sha256, payload FROM "
                "dev_eval.profile_release_transition_events ORDER BY receipt_sha256"
            ).fetchall(),
            "pointer": connection.execute(
                "SELECT slot, release_sha256, receipt_sha256 FROM "
                "dev_eval.profile_release_active_pointer"
            ).fetchall(),
        }
        connection.execute(
            "TRUNCATE dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1, "
            "dev_eval.profile_release_build_draft_consumptions, "
            "dev_eval.profile_release_build_receipts, "
            "dev_eval.profile_release_build_nonce_reservations CASCADE"
        )
    command.downgrade(config, "0009_phase3_profile_pin_privileges")
    with pytest.raises(RuntimeError, match="populated 0009 predecessor") as blocked:
        command.upgrade(config, "head")
    assert all(secret not in str(blocked.value) for secret in PROTECTED_CANARIES)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT to_regclass('dev_eval.profile_release_build_receipts')"
        ).fetchone() == (None,)
        predecessor_after = {
            "releases": connection.execute(
                "SELECT release_sha256, payload FROM dev_eval.profile_releases "
                "ORDER BY release_sha256"
            ).fetchall(),
            "heads": connection.execute(
                "SELECT release_sha256, state, head_receipt_sha256 FROM "
                "dev_eval.profile_release_lifecycle_heads ORDER BY release_sha256"
            ).fetchall(),
            "events": connection.execute(
                "SELECT receipt_sha256, payload FROM "
                "dev_eval.profile_release_transition_events ORDER BY receipt_sha256"
            ).fetchall(),
            "pointer": connection.execute(
                "SELECT slot, release_sha256, receipt_sha256 FROM "
                "dev_eval.profile_release_active_pointer"
            ).fetchall(),
        }
    assert predecessor_after == predecessor_before
    _configure_predecessor_backfill(config, tmp_path, blocked.value, archived)
    command.upgrade(config, "head")
    states = tuple(
        repository.get_profile_release_state(str(candidate.release_sha256))
        for candidate in candidates
    )
    assert tuple(state.state.value for state in states if state is not None) == (
        "BUILT_UNAPPROVED",
        "APPROVED_INACTIVE",
        "ACTIVE",
        "APPROVED_INACTIVE",
    )
    assert states[2] is not None and states[2].provenance_kind == "TRANSITION"
    assert states[3] is not None and states[3].provenance_kind == "TRANSITION"
    pointer = repository.get_profile_release_active_pointer()
    assert pointer.active_release_sha256 == candidates[2].release_sha256
    with postgres_harness.connect("admin", autocommit=True) as connection:
        stored_receipts = connection.execute(
            "SELECT builder_principal, nonce_sha256, binding_sha256, release_sha256, "
            "receipt_sha256 FROM dev_eval.profile_release_build_receipts "
            "ORDER BY release_sha256"
        ).fetchall()
        expected_receipts = sorted(
            [
                (
                    row["builder_principal"],
                    row["nonce_sha256"],
                    row["binding_sha256"],
                    row["release_sha256"],
                    row["receipt_sha256"],
                )
                for row in archived
            ],
            key=lambda row: row[3],
        )
        assert stored_receipts == expected_receipts
    with pytest.raises(RuntimeError, match="intentionally irreversible"):
        command.downgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert (
            connection.execute(
                "SELECT builder_principal, nonce_sha256, binding_sha256, release_sha256, "
                "receipt_sha256 FROM dev_eval.profile_release_build_receipts "
                "ORDER BY release_sha256"
            ).fetchall()
            == expected_receipts
        )
        privileges = set(
            connection.execute(
                "SELECT grantee, privilege_type FROM information_schema.table_privileges "
                "WHERE table_schema = 'dev_eval' AND "
                "table_name = 'profile_release_build_receipts'"
            ).fetchall()
        )
        assert (role_names["builder"], "INSERT") not in privileges
        assert (role_names["builder"], "SELECT") in privileges
        assert (role_names["approver"], "INSERT") not in privileges
        assert ("PUBLIC", "SELECT") not in privileges
        routine_privileges = set(
            connection.execute(
                "SELECT grantee, privilege_type FROM information_schema.routine_privileges "
                "WHERE specific_schema = 'dev_eval' AND "
                "routine_name = 'insert_profile_release_build_receipt_v1'"
            ).fetchall()
        )
        assert (role_names["builder"], "EXECUTE") in routine_privileges
        assert ("PUBLIC", "EXECUTE") not in routine_privileges
    config.attributes.pop("profile_release_provenance_backfill_path", None)
    config.attributes.pop("profile_release_provenance_backfill_approval_sha256", None)
    _assert_single_head_contains_revision(
        _alembic_script(),
        "0014_phase4_profile_release_write_boundary",
    )


def test_0010_duplicate_nonce_without_authority_fails_before_mutation(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
) -> None:
    config, _, _ = reconciliation_runtime
    config.attributes["profile_release_database_identity_sha256"] = "d" * 64
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "TRUNCATE dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1, "
            "dev_eval.profile_releases, "
            "dev_eval.profile_release_nonce_ledger, "
            "dev_eval.profile_release_build_drafts, "
            "dev_eval.profile_release_build_nonce_reservations, "
            "dev_eval.profile_release_nonce_quarantine_0010 CASCADE"
        )
    command.downgrade(config, "0009_phase3_profile_pin_privileges")
    duplicate_nonce = "9" * 64
    with postgres_harness.connect("admin", autocommit=True) as connection:
        for index in (1, 2):
            connection.execute(
                "INSERT INTO dev_eval.profile_release_nonce_ledger "
                "(binding_sha256, nonce_sha256, receipt_sha256, payload) VALUES "
                "(%s, %s, %s, '{}'::jsonb)",
                (f"{index:064x}", duplicate_nonce, f"{index + 20:064x}"),
            )
    with pytest.raises(RuntimeError, match="authority is absent or ambiguous"):
        command.upgrade(config, "head")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 = %s",
            (duplicate_nonce,),
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT to_regclass('dev_eval.profile_release_nonce_quarantine_0010')"
        ).fetchone() == (None,)
        connection.execute("TRUNCATE dev_eval.profile_release_nonce_ledger")
    command.upgrade(config, "head")


def test_0010_duplicate_transition_nonce_preflight_fails_without_rewriting_0009_rows(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
    tmp_path: Path,
) -> None:
    config, _, repository = reconciliation_runtime
    config.attributes["profile_release_database_identity_sha256"] = "d" * 64
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "TRUNCATE dev_eval.profile_releases, "
            "dev_eval.profile_release_nonce_ledger, "
            "dev_eval.profile_release_build_drafts, "
            "dev_eval.profile_release_build_nonce_reservations, "
            "dev_eval.profile_release_nonce_quarantine_0010 CASCADE"
        )
    candidate = _candidate("synthetic-authoritative-duplicate-transition")
    raw_build_nonce = "7" * 64
    build_outcome = repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce=raw_build_nonce,
    )
    repository.approve_profile_release(
        str(candidate.release_sha256),
        authenticated_principal="phase3-approver",
    )
    raw_transition_nonce = "8" * 64
    transition = repository.activate_profile_release(
        str(candidate.release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce=raw_transition_nonce,
    )
    transition_nonce_sha256 = hashlib.sha256(raw_transition_nonce.encode("ascii")).hexdigest()
    with postgres_harness.connect("admin", autocommit=True) as connection:
        authoritative_ledger = connection.execute(
            "SELECT binding_sha256, nonce_sha256, receipt_sha256, payload FROM "
            "dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 = %s",
            (transition_nonce_sha256,),
        ).fetchone()
        connection.execute(
            "TRUNCATE dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1, "
            "dev_eval.profile_release_build_draft_consumptions, "
            "dev_eval.profile_release_build_receipts, "
            "dev_eval.profile_release_build_nonce_reservations CASCADE"
        )
    command.downgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "INSERT INTO dev_eval.profile_release_nonce_ledger "
            "(binding_sha256, nonce_sha256, receipt_sha256, payload) VALUES "
            "(%s, %s, %s, '{}'::jsonb)",
            ("1" * 64, transition_nonce_sha256, "2" * 64),
        )
    with pytest.raises(RuntimeError, match="provenance backfill") as backfill_blocked:
        command.upgrade(config, "head")
    _configure_predecessor_backfill(
        config,
        tmp_path,
        backfill_blocked.value,
        [_archived_build_proof(build_outcome, raw_nonce=raw_build_nonce)],
    )
    with pytest.raises(RuntimeError, match="exact human approval") as blocked:
        command.upgrade(config, "head")
    approval_match = re.search(r"approval_sha256=([0-9a-f]{64})", str(blocked.value))
    assert approval_match is not None
    approved = approval_match.group(1)
    assert transition_nonce_sha256 not in str(blocked.value)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        rows = connection.execute(
            "SELECT binding_sha256, nonce_sha256, receipt_sha256 FROM "
            "dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 = %s "
            "ORDER BY binding_sha256",
            (transition_nonce_sha256,),
        ).fetchall()
        assert len(rows) == 2
        connection.execute(
            "INSERT INTO dev_eval.profile_release_nonce_ledger "
            "(binding_sha256, nonce_sha256, receipt_sha256, payload) VALUES "
            "(%s, %s, %s, '{}'::jsonb)",
            ("3" * 64, transition_nonce_sha256, "4" * 64),
        )
    config.attributes.pop("profile_release_provenance_backfill_path", None)
    config.attributes.pop("profile_release_provenance_backfill_approval_sha256", None)
    with pytest.raises(RuntimeError, match="provenance backfill") as refreshed_backfill:
        command.upgrade(config, "head")
    _configure_predecessor_backfill(
        config,
        tmp_path,
        refreshed_backfill.value,
        [_archived_build_proof(build_outcome, raw_nonce=raw_build_nonce)],
    )
    config.attributes["profile_release_nonce_reconciliation_approval_sha256"] = approved
    with pytest.raises(RuntimeError, match="approval_sha256") as stale_approval:
        command.upgrade(config, "head")
    refreshed_match = re.search(r"approval_sha256=([0-9a-f]{64})", str(stale_approval.value))
    assert refreshed_match is not None
    approved = refreshed_match.group(1)
    config.attributes["profile_release_nonce_reconciliation_approval_sha256"] = approved
    command.upgrade(config, "head")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        ledger = connection.execute(
            "SELECT binding_sha256, receipt_sha256, payload FROM "
            "dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 = %s",
            (transition_nonce_sha256,),
        ).fetchall()
        assert ledger == [
            (
                authoritative_ledger[0],
                authoritative_ledger[2],
                authoritative_ledger[3],
            )
        ]
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_nonce_quarantine_0010 "
            "WHERE nonce_sha256 = %s",
            (transition_nonce_sha256,),
        ).fetchone() == (2,)
    lookup = repository.get_profile_release_transition_outcome_by_nonce(
        transition_nonce_sha256,
        "phase3-approver",
    )
    assert lookup is not None and lookup.receipt_sha256 == transition.receipt_sha256
    state = repository.get_profile_release_state(str(candidate.release_sha256))
    pointer = repository.get_profile_release_active_pointer()
    assert state is not None and state.state.value == "ACTIVE"
    assert pointer.active_release_sha256 == candidate.release_sha256
    with pytest.raises(RuntimeError, match="intentionally irreversible"):
        command.downgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        preserved = connection.execute(
            "SELECT binding_sha256, receipt_sha256, payload FROM "
            "dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 = %s",
            (transition_nonce_sha256,),
        ).fetchall()
        assert preserved == [
            (
                authoritative_ledger[0],
                authoritative_ledger[2],
                authoritative_ledger[3],
            )
        ]
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.profile_release_nonce_quarantine_0010 "
            "WHERE nonce_sha256 = %s",
            (transition_nonce_sha256,),
        ).fetchone() == (2,)


@pytest.mark.parametrize(
    "corruption",
    ("missing-head", "mismatched-builder", "forged-binding", "forged-receipt"),
)
def test_build_receipt_schema_rejects_partial_or_cross_builder_provenance(
    postgres_harness: object,
    reconciliation_runtime: tuple[Config, Mapping[str, str], EvaluationRepository],
    corruption: str,
) -> None:
    del reconciliation_runtime
    candidate = _candidate(f"synthetic-direct-corruption-{corruption}")
    release_sha256 = str(candidate.release_sha256)
    with postgres_harness.connect("admin") as connection:
        connection.execute(
            "INSERT INTO dev_eval.profile_releases ("
            "release_sha256, release_id, builder_principal, canonical_lineage_sha256, "
            "dev_lineage_sha256, profile_schema_sha256, payload) VALUES ("
            "%s, %s, %s, %s, %s, %s, %s::jsonb)",
            (
                release_sha256,
                candidate.release_id,
                candidate.builder_principal,
                candidate.canonical_lineage_sha256,
                candidate.dev_lineage_sha256,
                candidate.profile_schema_sha256,
                candidate.model_dump_json(),
            ),
        )
        if corruption != "missing-head":
            connection.execute(
                "INSERT INTO dev_eval.profile_release_lifecycle_heads "
                "(release_sha256, state, head_receipt_sha256) VALUES "
                "(%s, 'BUILT_UNAPPROVED', NULL)",
                (release_sha256,),
            )
        inserted_builder = (
            "synthetic-other-builder"
            if corruption == "mismatched-builder"
            else candidate.builder_principal
        )
        nonce_sha256 = "d" * 64
        binding_sha256 = profile_release.profile_release_build_binding_sha256_v1(
            builder_principal=inserted_builder,
            release_sha256=release_sha256,
        )
        if corruption == "forged-binding":
            binding_sha256 = "e" * 64
        receipt_sha256 = str(
            profile_release.ProfileReleaseBuildReceipt(
                release_sha256=release_sha256,
                builder_principal=inserted_builder,
                nonce_sha256=nonce_sha256,
                binding_sha256=binding_sha256,
            ).receipt_sha256
        )
        if corruption == "forged-receipt":
            receipt_sha256 = "f" * 64
        with pytest.raises(psycopg.Error) as captured:
            connection.execute(
                "INSERT INTO dev_eval.profile_release_build_receipts ("
                "builder_principal, nonce_sha256, binding_sha256, release_sha256, "
                "receipt_sha256) VALUES (%s, %s, %s, %s, %s)",
                (
                    inserted_builder,
                    nonce_sha256,
                    binding_sha256,
                    release_sha256,
                    receipt_sha256,
                ),
            )
        assert captured.value.sqlstate == "23514"
        connection.rollback()


@pytest.mark.parametrize(
    ("model_name", "expected_fields"),
    (
        ("ProfileReleaseBuildOutcome", BUILD_OUTCOME_KEYS),
        ("ProfileReleaseActivePointerProjection", POINTER_KEYS),
        ("ProfileReleaseStateProjection", STATE_KEYS),
        ("ProfileReleaseTransitionOutcome", TRANSITION_OUTCOME_KEYS),
    ),
)
def test_reconciliation_contracts_have_exact_public_allowlists(
    model_name: str, expected_fields: set[str]
) -> None:
    assert _public_fields(model_name) == expected_fields


def test_build_receipt_contract_omits_payload_actor_and_raw_nonce() -> None:
    assert _public_fields("ProfileReleaseBuildReceipt") == {
        "schema_version",
        "release_sha256",
        "builder_principal",
        "nonce_sha256",
        "binding_sha256",
        "receipt_sha256",
    }
    assert RAW_BUILD_NONCE != BUILD_NONCE_SHA256


def test_existing_activate_and_rollback_v1_binding_vectors_are_frozen() -> None:
    target = "a" * 64
    expected = "b" * 64
    reason_sha256 = hashlib.sha256("합성 복구 사유".encode()).hexdigest()
    activate = profile_release.profile_release_activate_binding_sha256_v1(
        target_sha256=target,
        expected_current_sha256=expected,
    )
    rollback = profile_release.profile_release_rollback_binding_sha256_v1(
        target_sha256=target,
        expected_current_sha256=expected,
        reason_sha256=reason_sha256,
        approver_principal="synthetic-approver",
    )
    assert activate == canonical_sha256(
        {"action": "ACTIVATE", "target": target, "expected": expected}
    )
    assert rollback == canonical_sha256(
        {
            "action": "ROLLBACK",
            "target": target,
            "expected": expected,
            "reason_sha256": reason_sha256,
            "approver": "synthetic-approver",
        }
    )


@pytest.mark.parametrize(
    ("state", "kind", "head", "provenance", "valid"),
    (
        ("BUILT_UNAPPROVED", "BUILD", None, "b" * 64, True),
        ("BUILT_UNAPPROVED", "APPROVAL", None, "b" * 64, False),
        ("APPROVED_INACTIVE", "APPROVAL", "b" * 64, "b" * 64, True),
        ("APPROVED_INACTIVE", "TRANSITION", "b" * 64, "b" * 64, True),
        ("APPROVED_INACTIVE", "BUILD", "b" * 64, "b" * 64, False),
        ("APPROVED_INACTIVE", "APPROVAL", "c" * 64, "b" * 64, False),
        ("ACTIVE", "TRANSITION", "b" * 64, "b" * 64, True),
        ("ACTIVE", "APPROVAL", "b" * 64, "b" * 64, False),
        ("ACTIVE", "TRANSITION", None, "b" * 64, False),
    ),
)
def test_state_projection_enforces_exact_provenance_matrix(
    state: str,
    kind: str,
    head: str | None,
    provenance: str,
    valid: bool,
) -> None:
    payload = {
        "release_sha256": "a" * 64,
        "state": state,
        "lifecycle_head_receipt_sha256": head,
        "provenance_kind": kind,
        "provenance_receipt_sha256": provenance,
    }
    if valid:
        profile_release.ProfileReleaseStateProjection.model_validate(payload)
    else:
        with pytest.raises(ValidationError):
            profile_release.ProfileReleaseStateProjection.model_validate(payload)


@pytest.mark.parametrize(
    ("action", "previous", "expected", "valid"),
    (
        ("ACTIVATE", None, None, True),
        ("ACTIVATE", "a" * 64, "a" * 64, True),
        ("ACTIVATE", "a" * 64, "b" * 64, False),
        ("ROLLBACK", "a" * 64, "a" * 64, True),
        ("ROLLBACK", None, None, False),
        ("ROLLBACK", "a" * 64, "b" * 64, False),
    ),
)
def test_transition_contracts_reject_impossible_compare_and_swap_provenance(
    action: str,
    previous: str | None,
    expected: str | None,
    valid: bool,
) -> None:
    outcome = {
        "action": action,
        "release_sha256": "c" * 64,
        "previous_release_sha256": previous,
        "expected_current_sha256": expected,
        "receipt_sha256": "d" * 64,
        "nonce_sha256": "e" * 64,
        "binding_sha256": "f" * 64,
        "completion": "RELOOKUP_CONFIRMED",
    }
    if valid:
        profile_release.ProfileReleaseTransitionOutcome.model_validate(outcome)
    else:
        with pytest.raises(ValidationError):
            profile_release.ProfileReleaseTransitionOutcome.model_validate(outcome)


def test_replayed_transition_receipt_remains_digest_valid_and_immutable() -> None:
    persisted = profile_release.ProfileReleaseTransitionReceipt(
        action="ACTIVATE",
        release_sha256="a" * 64,
        previous_release_sha256=None,
        expected_current_sha256=None,
        approver_principal="phase3-approver",
        nonce_sha256="b" * 64,
        completion=profile_release.ProfileReleaseCompletion.MUTATION_COMMITTED,
    )
    outcome = profile_release.ProfileReleaseTransitionOutcome(
        action="ACTIVATE",
        release_sha256="a" * 64,
        previous_release_sha256=None,
        expected_current_sha256=None,
        receipt_sha256=str(persisted.receipt_sha256),
        nonce_sha256="b" * 64,
        binding_sha256="c" * 64,
        completion=profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
    )
    replayed_receipt = EvaluationRepository._receipt_from_outcome(
        outcome,
        authenticated_principal="phase3-approver",
        reason=None,
    )
    fresh = profile_release.ProfileReleaseTransitionMutationResult(
        receipt=persisted,
        completion=profile_release.ProfileReleaseCompletion.MUTATION_COMMITTED,
    )
    replayed = profile_release.ProfileReleaseTransitionMutationResult(
        receipt=replayed_receipt,
        completion=profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
    )
    assert fresh.receipt == replayed.receipt
    assert replayed.completion is profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED
    assert replayed.receipt.completion is (
        profile_release.ProfileReleaseCompletion.MUTATION_COMMITTED
    )
    assert (
        profile_release.ProfileReleaseTransitionReceipt.model_validate_json(
            replayed.receipt.model_dump_json()
        )
        == replayed.receipt
    )


def test_build_repository_signature_requires_raw_reconciliation_nonce() -> None:
    signature = inspect.signature(EvaluationRepository.build_profile_release)
    assert "reconciliation_nonce" in signature.parameters
    assert signature.parameters["reconciliation_nonce"].default is inspect.Parameter.empty


@pytest.mark.parametrize(
    "method_name",
    (
        "get_profile_release_build_outcome_by_nonce",
        "get_profile_release_active_pointer",
        "get_profile_release_state",
        "get_profile_release_transition_outcome_by_nonce",
        "get_profile_release_session_pin",
    ),
)
def test_repository_exposes_read_only_reconciliation_and_session_pin_methods(
    method_name: str,
) -> None:
    assert callable(getattr(EvaluationRepository, method_name))


def test_static_reconciliation_routes_precede_dynamic_state_route() -> None:
    paths = list(create_app().openapi()["paths"])
    required = {
        "/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}",
        "/internal/evaluation/profile-releases/active-pointer",
        "/internal/evaluation/profile-releases/{release_sha256}/state",
        "/internal/evaluation/profile-releases/transition-receipts/by-nonce/{nonce_sha256}",
        "/internal/evaluation/profile-releases/sessions/{session_ref}/pin",
    }
    assert required <= set(paths)
    assert paths.index(
        "/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}"
    ) < paths.index("/internal/evaluation/profile-releases/{release_sha256}/state")
    assert paths.index(
        "/internal/evaluation/profile-releases/transition-receipts/by-nonce/{nonce_sha256}"
    ) < paths.index("/internal/evaluation/profile-releases/{release_sha256}/state")


def test_profile_release_openapi_declares_security_conflicts_and_unknown_outcomes() -> None:
    document = create_app().openapi()
    mutation_operations = (
        ("/internal/evaluation/profile-releases/build-drafts", "post"),
        ("/internal/evaluation/profile-releases/build-drafts/build", "post"),
        ("/internal/evaluation/profile-releases/build", "post"),
        ("/internal/evaluation/profile-releases/{release_sha256}/approve", "post"),
        ("/internal/evaluation/profile-releases/{release_sha256}/activate", "post"),
        ("/internal/evaluation/profile-releases/{release_sha256}/rollback", "post"),
        ("/internal/evaluation/profile-releases/sessions/{session_ref}/pin", "post"),
        ("/internal/evaluation/profile-releases/results/{result_ref}/pin", "post"),
    )
    for path, method in mutation_operations:
        operation = document["paths"][path][method]
        assert {"401", "403", "404", "409", "503"} <= set(operation["responses"])
        retry_schema = operation["responses"]["503"]["content"]["application/json"]["schema"]
        if path == "/internal/evaluation/profile-releases/build-drafts":
            assert retry_schema == {"$ref": "#/components/schemas/ProfileReleaseErrorResponse"}
        elif path == "/internal/evaluation/profile-releases/build-drafts/build":
            assert retry_schema["anyOf"] == [
                {"$ref": "#/components/schemas/ProfileReleaseUnknownOutcomeResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseRetryableAbortResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseBuildUnavailableResponse"},
                {"$ref": ("#/components/schemas/ProfileReleaseDraftCleanupUnknownResponse")},
            ]
        elif path == "/internal/evaluation/profile-releases/build":
            assert retry_schema["anyOf"] == [
                {"$ref": "#/components/schemas/ProfileReleaseUnknownOutcomeResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseRetryableAbortResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseBuildUnavailableResponse"},
            ]
        else:
            assert retry_schema["anyOf"] == [
                {"$ref": "#/components/schemas/ProfileReleaseUnknownOutcomeResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseRetryableAbortResponse"},
            ]
        assert operation["responses"]["422"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ProfileReleaseErrorResponse"
        }
        assert {"Phase3Capability": []} in operation["security"]
    read_paths = (
        "/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}",
        "/internal/evaluation/profile-releases/active-pointer",
        "/internal/evaluation/profile-releases/transition-receipts/by-nonce/{nonce_sha256}",
        "/internal/evaluation/profile-releases/{release_sha256}/state",
        "/internal/evaluation/profile-releases/sessions/{session_ref}/pin",
    )
    for path in read_paths:
        operation = document["paths"][path]["get"]
        assert operation["responses"]["503"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/ProfileReleaseErrorResponse"
        }


def test_profile_release_manifest_digests_are_required_in_openapi() -> None:
    schema = create_app().openapi()["components"]["schemas"]["ProfileReleaseBuildRequest"]
    assert {
        "label_freeze_sha256",
        "candidate_run_sha256",
        "reviewed_manifest_sha256",
        "rights_manifest_sha256",
        "source_manifest_sha256",
    } <= set(schema["required"])


class _RouteRepository:
    def __init__(self) -> None:
        self.lookups: list[str] = []
        self.build_outcome: profile_release.ProfileReleaseBuildOutcome | None = None
        self.transition_outcome: profile_release.ProfileReleaseTransitionOutcome | None = None
        self.state_projection: profile_release.ProfileReleaseStateProjection | None = None
        self.session_pin_projection: profile_release.ProfileReleaseSessionPinProjection | None = (
            None
        )
        self.transition_result: profile_release.ProfileReleaseTransitionMutationResult | None = None
        self.raise_integrity = False
        self.read_error: Exception | None = None
        self.draft_error: Exception | None = None
        self.draft_build_error: Exception | None = None
        self.purge_error: Exception | None = None
        self.drafts: dict[str, tuple[profile_release.ProfileReleaseCandidate, str]] = {}
        self.authority_reviewed_records: dict[str, dict[str, str]] = {}

    @staticmethod
    def profile_release_builder_database_principal() -> str:
        return "synthetic-builder-database"

    def get_reviewed_evidence_manifest(self, manifest_sha256: str) -> object | None:
        self.lookups.append(f"reviewed-authority:{manifest_sha256}")
        return self.authority_reviewed_records.get(manifest_sha256)

    def get_profile_release_build_draft_candidate(
        self,
        draft_ref: str,
        *,
        authenticated_principal: str,
        nonce_sha256: str,
    ) -> profile_release.ProfileReleaseCandidate | None:
        self.lookups.append(f"draft-authority:{authenticated_principal}")
        stored = self.drafts.get(draft_ref)
        if stored is None:
            return None
        candidate, nonce = stored
        if hashlib.sha256(nonce.encode("ascii")).hexdigest() != nonce_sha256:
            return None
        return candidate

    def build_profile_release(
        self,
        authority_resolution: ProfileReleaseBuildAuthorityResolution,
        *,
        authenticated_principal: str,
        reconciliation_nonce: str,
    ) -> profile_release.ProfileReleaseBuildOutcome:
        self.lookups.append(f"build:{authenticated_principal}")
        candidate = authority_resolution.candidate
        nonce_sha256 = hashlib.sha256(reconciliation_nonce.encode("ascii")).hexdigest()
        binding = profile_release.profile_release_build_binding_sha256_v1(
            builder_principal=authenticated_principal,
            release_sha256=str(candidate.release_sha256),
        )
        receipt = profile_release.ProfileReleaseBuildReceipt(
            release_sha256=str(candidate.release_sha256),
            builder_principal=authenticated_principal,
            nonce_sha256=nonce_sha256,
            binding_sha256=binding,
        )
        self.build_outcome = profile_release.ProfileReleaseBuildOutcome(
            release_sha256=str(candidate.release_sha256),
            receipt_sha256=str(receipt.receipt_sha256),
            nonce_sha256=nonce_sha256,
            binding_sha256=binding,
            completion=profile_release.ProfileReleaseCompletion.MUTATION_COMMITTED,
        )
        return self.build_outcome

    def create_profile_release_build_draft(
        self,
        candidate: profile_release.ProfileReleaseCandidate,
        *,
        authenticated_principal: str,
        reconciliation_nonce: str,
        draft_ref: str,
    ) -> profile_release.ProfileReleaseBuildDraftReference:
        self.lookups.append(f"draft:{authenticated_principal}")
        if self.draft_error is not None:
            raise self.draft_error
        self.drafts[draft_ref] = (candidate, reconciliation_nonce)
        return profile_release.ProfileReleaseBuildDraftReference(
            draft_ref=draft_ref,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            nonce_sha256=hashlib.sha256(reconciliation_nonce.encode("ascii")).hexdigest(),
        )

    def build_profile_release_from_draft(
        self,
        draft_ref: str,
        *,
        authenticated_principal: str,
        nonce_sha256: str,
        authority_resolution: ProfileReleaseBuildAuthorityResolution | None = None,
        reconciliation_only: bool = False,
    ) -> profile_release.ProfileReleaseBuildOutcome:
        self.lookups.append(f"draft-build:{authenticated_principal}")
        if self.draft_build_error is not None:
            raise self.draft_build_error
        candidate, nonce = self.drafts[draft_ref]
        if reconciliation_only:
            raise profile_release.ProfileReleaseBuildUnavailableError(
                retry_path="/internal/evaluation/profile-releases/build-drafts/build"
            )
        if authority_resolution is not None:
            assert candidate == authority_resolution.candidate
        assert hashlib.sha256(nonce.encode("ascii")).hexdigest() == nonce_sha256
        return self.build_profile_release(
            _authority(candidate),
            authenticated_principal=authenticated_principal,
            reconciliation_nonce=nonce,
        )

    def purge_expired_profile_release_build_drafts(
        self,
        *,
        authenticated_principal: str,
    ) -> profile_release.ProfileReleaseDraftPurgeResult:
        self.lookups.append(f"draft-purge:{authenticated_principal}")
        if self.purge_error is not None:
            raise self.purge_error
        return profile_release.ProfileReleaseDraftPurgeResult(
            deleted_count=2,
            remaining_expired_count=0,
        )

    def get_profile_release_build_outcome_by_nonce(
        self,
        nonce_sha256: str,
        authenticated_principal: str,
    ) -> profile_release.ProfileReleaseBuildOutcome | None:
        self.lookups.append(f"build-read:{authenticated_principal}")
        if self.read_error is not None:
            raise self.read_error
        if self.raise_integrity:
            raise ValueError("synthetic corrupt build receipt")
        if self.build_outcome is None or nonce_sha256 != self.build_outcome.nonce_sha256:
            return None
        return self.build_outcome.model_copy(
            update={"completion": profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED}
        )

    def get_profile_release_active_pointer(
        self,
    ) -> profile_release.ProfileReleaseActivePointerProjection:
        self.lookups.append("pointer")
        if self.read_error is not None:
            raise self.read_error
        return profile_release.ProfileReleaseActivePointerProjection(
            active_release_sha256=None,
            state=None,
            receipt_sha256=None,
        )

    def get_profile_release_state(
        self,
        release_sha256: str,
    ) -> profile_release.ProfileReleaseStateProjection | None:
        self.lookups.append("state")
        if self.read_error is not None:
            raise self.read_error
        if self.raise_integrity:
            raise ValueError("synthetic corrupt lifecycle")
        if self.state_projection is None or self.state_projection.release_sha256 != release_sha256:
            return None
        return self.state_projection

    def get_profile_release_transition_outcome_by_nonce(
        self,
        nonce_sha256: str,
        authenticated_principal: str,
    ) -> profile_release.ProfileReleaseTransitionOutcome | None:
        self.lookups.append(f"transition:{authenticated_principal}")
        if self.read_error is not None:
            raise self.read_error
        if self.raise_integrity:
            raise ValueError("synthetic corrupt transition receipt")
        if self.transition_outcome is None or nonce_sha256 != self.transition_outcome.nonce_sha256:
            return None
        return self.transition_outcome

    def get_profile_release_session_pin(
        self,
        session_ref: str,
    ) -> profile_release.ProfileReleaseSessionPinProjection | None:
        self.lookups.append("session-pin")
        if self.read_error is not None:
            raise self.read_error
        if (
            self.session_pin_projection is None
            or self.session_pin_projection.session_ref != session_ref
        ):
            return None
        return self.session_pin_projection

    def activate_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        assert self.transition_result is not None
        return self.transition_result

    def rollback_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        assert self.transition_result is not None
        return self.transition_result


def _route_client(
    role: str,
    repository_provider: Any,
    *,
    enforce_authority: bool = False,
) -> tuple[TestClient, Any]:
    app = create_app()
    principal = Phase3Principal(
        actor_id=f"phase3-{role.replace('_', '-')}",
        role=role,
    )
    app.dependency_overrides[get_phase3_principal] = lambda: principal
    app.dependency_overrides[get_evaluation_repository] = repository_provider
    if not enforce_authority:
        app.dependency_overrides[_profile_release_authority_service] = _LegacyRouteAuthorityService
    return TestClient(app, raise_server_exceptions=False), app


def _build_request_payload(release_id: str) -> dict[str, Any]:
    candidate = _candidate(release_id)
    payload = candidate.model_dump(
        mode="json",
        exclude={"state", "builder_principal", "release_sha256"},
    )
    payload["reconciliation_nonce"] = RAW_BUILD_NONCE
    return payload


_AUTHORITY_ENVIRONMENTS = {
    "label_freeze": (
        "ITDA_PHASE3_PROFILE_RELEASE_LABEL_FREEZE_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_LABEL_FREEZE_SHA256",
    ),
    "candidate_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_CANDIDATE_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_CANDIDATE_SHA256",
    ),
    "reviewed_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_REVIEWED_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_REVIEWED_SHA256",
    ),
    "rights_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_RIGHTS_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_RIGHTS_SHA256",
    ),
    "source_manifest": (
        "ITDA_PHASE3_PROFILE_RELEASE_SOURCE_MANIFEST",
        "ITDA_PHASE3_PROFILE_RELEASE_SOURCE_SHA256",
    ),
}


def _authority_digest(label: str) -> str:
    return canonical_sha256({"synthetic-authority": label})


def _authority_self_hash(payload: dict[str, Any], field: str = "manifest_sha256") -> None:
    payload[field] = canonical_sha256(
        {key: value for key, value in payload.items() if key != field}
    )


def _authority_bundle() -> dict[str, dict[str, Any]]:
    canonical = _authority_digest("canonical")
    dev = _authority_digest("dev")
    profile_schema = _authority_digest("profile-schema")
    label_source_root = _authority_digest("label-source-root")
    accepted_revisions = _authority_digest("accepted-revisions")
    adjudicated_label_export = _authority_digest("adjudicated-export")
    freeze: dict[str, Any] = {
        "schema_version": "phase3-label-freeze-receipt-v1",
        "status": "APPROVED_FROZEN",
        "accepted_revision_set_sha256": accepted_revisions,
        "adjudicated_label_export_sha256": adjudicated_label_export,
        "aggregate_set_sha256": _authority_digest("aggregate-set"),
        "rubric_sha256": _authority_digest("rubric"),
        "source_root_sha256": label_source_root,
        "dev_lineage_sha256": dev,
        "code_version_sha256": _authority_digest("freeze-code"),
        "config_version_sha256": _authority_digest("freeze-config"),
        "authority_grants": [],
        "frozen_at": "2026-08-06T00:00:00Z",
    }
    _authority_self_hash(freeze, "receipt_sha256")

    source_members: list[dict[str, Any]] = []
    rights_members: list[dict[str, Any]] = []
    candidate_members: list[dict[str, Any]] = []
    reviewed_members: list[dict[str, Any]] = []
    for index in range(24):
        place_ref = f"synthetic-authority-place-{index:02d}"
        source_sha256 = _authority_digest(f"source-{index}")
        lanes = {
            "description_lane": "READY",
            "odii_lane": "MISSING" if index % 3 == 0 else "READY",
        }
        source_members.append(
            {
                "place_ref": place_ref,
                "source_sha256": source_sha256,
                **lanes,
                "source_eligible": True,
            }
        )
        rights_members.append(
            {
                "place_ref": place_ref,
                "source_sha256": source_sha256,
                "rights_sha256": _authority_digest(f"rights-{index}"),
                "rights_eligible": True,
            }
        )
        candidate_member = {
            "place_ref": place_ref,
            "source_sha256": source_sha256,
            "label_export_sha256": adjudicated_label_export,
            "profile_sha256": _authority_digest(f"profile-{index}"),
            **lanes,
            "complete": True,
        }
        _authority_self_hash(candidate_member, "candidate_manifest_sha256")
        candidate_members.append(candidate_member)
        reviewed_member = {
            "place_ref": place_ref,
            "candidate_manifest_sha256": candidate_member["candidate_manifest_sha256"],
            "accepted_review_set_sha256": _authority_digest(f"review-{index}"),
            **lanes,
            "evidence_eligible": True,
        }
        _authority_self_hash(reviewed_member, "reviewed_evidence_manifest_sha256")
        reviewed_members.append(reviewed_member)

    source: dict[str, Any] = {
        "schema_version": "itda.profile-release-source-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "label_source_root_sha256": label_source_root,
        "members": source_members,
    }
    _authority_self_hash(source)
    rights: dict[str, Any] = {
        "schema_version": "itda.profile-release-rights-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "source_manifest_sha256": source["manifest_sha256"],
        "members": rights_members,
    }
    _authority_self_hash(rights)
    candidate: dict[str, Any] = {
        "schema_version": "itda.profile-release-candidate-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "profile_schema_sha256": profile_schema,
        "label_freeze_sha256": freeze["receipt_sha256"],
        "adjudicated_label_export_sha256": adjudicated_label_export,
        "source_manifest_sha256": source["manifest_sha256"],
        "accepted_revision_set_sha256": accepted_revisions,
        "code_sha256": _authority_digest("candidate-code"),
        "config_sha256": _authority_digest("candidate-config"),
        "members": candidate_members,
    }
    _authority_self_hash(candidate)
    reviewed: dict[str, Any] = {
        "schema_version": "itda.profile-release-reviewed-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "profile_schema_sha256": profile_schema,
        "candidate_manifest_sha256": candidate["manifest_sha256"],
        "members": reviewed_members,
    }
    _authority_self_hash(reviewed)
    return {
        "label_freeze": freeze,
        "candidate_manifest": candidate,
        "reviewed_manifest": reviewed,
        "rights_manifest": rights,
        "source_manifest": source,
    }


def _configure_authority_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    payloads: dict[str, dict[str, Any]],
) -> profile_release.ProfileReleaseCandidate:
    monkeypatch.setenv(
        "ITDA_PROFILE_RELEASE_AUTHORITY_REGISTRY_ID",
        str(uuid5(NAMESPACE_URL, "synthetic-profile-release-authority-registry")),
    )
    paths: dict[str, Path] = {}
    for name, payload in payloads.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_json_bytes(payload))
        paths[name] = path
        path_environment, digest_environment = _AUTHORITY_ENVIRONMENTS[name]
        monkeypatch.setenv(path_environment, str(path))
        digest_field = "receipt_sha256" if name == "label_freeze" else "manifest_sha256"
        monkeypatch.setenv(digest_environment, str(payload[digest_field]))
    request = {
        "release_id": "synthetic-authoritative-route",
        "builder_principal": "phase3-builder",
        "canonical_lineage_sha256": payloads["source_manifest"]["canonical_lineage_sha256"],
        "dev_lineage_sha256": payloads["source_manifest"]["dev_lineage_sha256"],
        "profile_schema_sha256": payloads["candidate_manifest"]["profile_schema_sha256"],
        "label_freeze_sha256": payloads["label_freeze"]["receipt_sha256"],
        "candidate_manifest_sha256": payloads["candidate_manifest"]["manifest_sha256"],
        "reviewed_manifest_sha256": payloads["reviewed_manifest"]["manifest_sha256"],
        "rights_manifest_sha256": payloads["rights_manifest"]["manifest_sha256"],
        "source_manifest_sha256": payloads["source_manifest"]["manifest_sha256"],
    }
    return profile_release_authority.resolve_authoritative_profile_release_candidate(
        request=request,
        paths=profile_release_authority.ProfileReleaseAuthorityPaths(**paths),
    )


def _write_authority_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    payloads: dict[str, dict[str, Any]],
) -> None:
    for name, payload in payloads.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_json_bytes(payload))
        path_environment, digest_environment = _AUTHORITY_ENVIRONMENTS[name]
        monkeypatch.setenv(path_environment, str(path))
        digest_field = "receipt_sha256" if name == "label_freeze" else "manifest_sha256"
        monkeypatch.setenv(digest_environment, str(payload[digest_field]))


def _mutate_authority_label_export_binding(
    candidate: profile_release.ProfileReleaseCandidate,
    payloads: dict[str, dict[str, Any]],
) -> profile_release.ProfileReleaseCandidate:
    candidate_member = payloads["candidate_manifest"]["members"][0]
    reviewed_member = payloads["reviewed_manifest"]["members"][0]
    candidate_member["label_export_sha256"] = _authority_digest("substituted-label-export")
    _authority_self_hash(candidate_member, "candidate_manifest_sha256")
    reviewed_member["candidate_manifest_sha256"] = candidate_member["candidate_manifest_sha256"]
    _authority_self_hash(reviewed_member, "reviewed_evidence_manifest_sha256")
    _authority_self_hash(payloads["candidate_manifest"])
    payloads["reviewed_manifest"]["candidate_manifest_sha256"] = payloads["candidate_manifest"][
        "manifest_sha256"
    ]
    _authority_self_hash(payloads["reviewed_manifest"])

    candidate_payload = candidate.model_dump(
        mode="json",
        exclude={"release_sha256", "state"},
    )
    candidate_payload["candidate_run_sha256"] = payloads["candidate_manifest"]["manifest_sha256"]
    candidate_payload["reviewed_manifest_sha256"] = payloads["reviewed_manifest"]["manifest_sha256"]
    candidate_payload["cohort"][0]["label_export_sha256"] = candidate_member["label_export_sha256"]
    candidate_payload["cohort"][0]["candidate_manifest_sha256"] = candidate_member[
        "candidate_manifest_sha256"
    ]
    candidate_payload["cohort"][0]["reviewed_evidence_manifest_sha256"] = reviewed_member[
        "reviewed_evidence_manifest_sha256"
    ]
    return profile_release.ProfileReleaseCandidate.model_validate(candidate_payload)


def _authoritative_build_payload(
    candidate: profile_release.ProfileReleaseCandidate,
    *,
    release_id: str,
) -> dict[str, Any]:
    payload = candidate.model_copy(update={"release_id": release_id}).model_dump(
        mode="json",
        exclude={"state", "builder_principal", "release_sha256"},
    )
    payload["reconciliation_nonce"] = RAW_BUILD_NONCE
    return payload


def _register_authoritative_reviewed_records(
    repository: _RouteRepository,
    candidate: profile_release.ProfileReleaseCandidate,
) -> None:
    for member in candidate.cohort:
        repository.authority_reviewed_records[member.reviewed_evidence_manifest_sha256] = {
            "manifest_sha256": member.reviewed_evidence_manifest_sha256,
            "candidate_manifest_sha256": member.candidate_manifest_sha256,
            "accepted_review_set_sha256": member.accepted_review_set_sha256,
        }


class _LegacyRouteAuthorityService:
    """Keep unrelated route tests focused on their original lifecycle behavior."""

    @staticmethod
    def resolve_request(
        request: Any,
        *,
        principal: Phase3Principal,
        repository: object,
    ) -> ProfileReleaseBuildAuthorityResolution:
        del repository
        excluded = {"draft_ref", "reconciliation_nonce"}
        return _authority(
            profile_release.ProfileReleaseCandidate(
                **request.model_dump(mode="python", exclude=excluded),
                builder_principal=principal.actor_id,
            )
        )

    @staticmethod
    def resolve_candidate(
        candidate: profile_release.ProfileReleaseCandidate,
        *,
        principal: Phase3Principal,
        repository: object,
    ) -> ProfileReleaseBuildAuthorityResolution:
        del principal, repository
        return _authority(candidate)


@pytest.mark.parametrize(
    "path",
    (
        "/internal/evaluation/profile-releases/build",
        "/internal/evaluation/profile-releases/build-drafts",
    ),
)
def test_self_asserted_release_readiness_fails_without_server_authority(
    path: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    for path_environment, digest_environment in _AUTHORITY_ENVIRONMENTS.values():
        monkeypatch.delenv(path_environment, raising=False)
        monkeypatch.delenv(digest_environment, raising=False)
    repository = _RouteRepository()
    payload = _build_request_payload("synthetic-self-asserted-route")
    if path.endswith("build-drafts"):
        payload["draft_ref"] = "S" * 43
    client, app = _route_client(
        "builder",
        lambda: repository,
        enforce_authority=True,
    )
    try:
        response = client.post(path, json=payload)
    finally:
        client.close()
        app.dependency_overrides.clear()

    assert response.status_code == 503
    if path.endswith("build-drafts"):
        assert response.json() == {
            "detail": "profile release draft persistence is temporarily unavailable"
        }
    else:
        assert response.json() == {
            "detail": {
                "outcome": "BUILD_UNAVAILABLE",
                "action": "BUILD",
                "retry_path": "/internal/evaluation/profile-releases/build",
            }
        }
    assert repository.lookups == []
    observed = repr((response.json(), caplog.messages))
    assert RAW_BUILD_NONCE not in observed
    assert all(canary not in observed for canary in PROTECTED_CANARIES)


@pytest.mark.parametrize(
    "hostile_change",
    (
        "missing-path",
        "missing-digest",
        "missing-registry-id",
        "configured-digest-drift",
        "manifest-tamper",
        "reviewed-record-missing",
        "reviewed-record-mismatch",
    ),
)
def test_authoritative_release_build_rejects_missing_or_tampered_server_bundle(
    hostile_change: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    payloads = _authority_bundle()
    candidate = _configure_authority_bundle(monkeypatch, tmp_path, payloads)
    repository = _RouteRepository()
    _register_authoritative_reviewed_records(repository, candidate)
    request = _authoritative_build_payload(candidate, release_id="synthetic-hostile-route")
    if hostile_change == "missing-path":
        monkeypatch.delenv(_AUTHORITY_ENVIRONMENTS["rights_manifest"][0])
    elif hostile_change == "missing-digest":
        monkeypatch.delenv(_AUTHORITY_ENVIRONMENTS["source_manifest"][1])
    elif hostile_change == "missing-registry-id":
        monkeypatch.delenv("ITDA_PROFILE_RELEASE_AUTHORITY_REGISTRY_ID")
    elif hostile_change == "configured-digest-drift":
        monkeypatch.setenv(_AUTHORITY_ENVIRONMENTS["candidate_manifest"][1], "0" * 64)
    elif hostile_change == "manifest-tamper":
        source_path = Path(os.environ[_AUTHORITY_ENVIRONMENTS["source_manifest"][0]])
        source_path.write_bytes(b'{"synthetic-evidence-body-canary":true}')
    elif hostile_change == "reviewed-record-missing":
        repository.authority_reviewed_records.pop(
            candidate.cohort[0].reviewed_evidence_manifest_sha256
        )
    else:
        repository.authority_reviewed_records[
            candidate.cohort[0].reviewed_evidence_manifest_sha256
        ]["accepted_review_set_sha256"] = "0" * 64
    client, app = _route_client(
        "builder",
        lambda: repository,
        enforce_authority=True,
    )
    try:
        response = client.post(
            "/internal/evaluation/profile-releases/build",
            json=request,
        )
    finally:
        client.close()
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "outcome": "BUILD_UNAVAILABLE",
            "action": "BUILD",
            "retry_path": "/internal/evaluation/profile-releases/build",
        }
    }
    assert not any(item.startswith("build:") for item in repository.lookups)
    observed = repr((response.json(), caplog.messages))
    assert all(canary not in observed for canary in PROTECTED_CANARIES)


@pytest.mark.parametrize("mutation_path", ("direct", "draft", "draft-build"))
def test_authoritative_release_rejects_rehashed_member_label_export_substitution(
    mutation_path: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = _authority_bundle()
    baseline = _configure_authority_bundle(monkeypatch, tmp_path, payloads)
    hostile_candidate = _mutate_authority_label_export_binding(baseline, payloads)
    _write_authority_environment(monkeypatch, tmp_path, payloads)
    repository = _RouteRepository()
    _register_authoritative_reviewed_records(repository, hostile_candidate)
    client, app = _route_client(
        "builder",
        lambda: repository,
        enforce_authority=True,
    )
    try:
        if mutation_path == "direct":
            response = client.post(
                "/internal/evaluation/profile-releases/build",
                json=_authoritative_build_payload(
                    hostile_candidate,
                    release_id="synthetic-hostile-label-direct",
                ),
            )
        elif mutation_path == "draft":
            request = _authoritative_build_payload(
                hostile_candidate,
                release_id="synthetic-hostile-label-draft",
            )
            request["draft_ref"] = "L" * 43
            response = client.post(
                "/internal/evaluation/profile-releases/build-drafts",
                json=request,
            )
        else:
            draft_ref = "M" * 43
            reconciliation_nonce = "hostile-label-export-draft-nonce"
            repository.drafts[draft_ref] = (
                hostile_candidate,
                reconciliation_nonce,
            )
            response = client.post(
                "/internal/evaluation/profile-releases/build-drafts/build",
                json={
                    "draft_ref": draft_ref,
                    "nonce_sha256": hashlib.sha256(
                        reconciliation_nonce.encode("ascii")
                    ).hexdigest(),
                },
            )
    finally:
        client.close()
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert not any(
        lookup.startswith(("build:", "draft:", "draft-build:")) for lookup in repository.lookups
    )


def test_authoritative_bundle_overrides_client_readiness_for_direct_and_draft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = _authority_bundle()
    candidate = _configure_authority_bundle(monkeypatch, tmp_path, payloads)
    repository = _RouteRepository()
    _register_authoritative_reviewed_records(repository, candidate)
    payload = _authoritative_build_payload(candidate, release_id="synthetic-authoritative-direct")
    for member in payload["cohort"]:
        member["label_ready"] = False
        member["rights_ready"] = False
        member["evidence_ready"] = False

    client, app = _route_client(
        "builder",
        lambda: repository,
        enforce_authority=True,
    )
    try:
        direct = client.post(
            "/internal/evaluation/profile-releases/build",
            json=payload,
        )
        draft_payload = deepcopy(payload)
        draft_payload["release_id"] = "synthetic-authoritative-draft"
        draft_payload["reconciliation_nonce"] = "9" * 64
        draft_payload["draft_ref"] = "A" * 43
        created = client.post(
            "/internal/evaluation/profile-releases/build-drafts",
            json=draft_payload,
        )
        assert direct.status_code == 201
        assert created.status_code == 201
        source_path = Path(os.environ[_AUTHORITY_ENVIRONMENTS["source_manifest"][0]])
        source_bytes = source_path.read_bytes()
        source_path.unlink()
        blocked = client.post(
            "/internal/evaluation/profile-releases/build-drafts/build",
            json={
                "draft_ref": created.json()["draft_ref"],
                "nonce_sha256": created.json()["nonce_sha256"],
            },
        )
        source_path.write_bytes(source_bytes)
        built = client.post(
            "/internal/evaluation/profile-releases/build-drafts/build",
            json={
                "draft_ref": created.json()["draft_ref"],
                "nonce_sha256": created.json()["nonce_sha256"],
            },
        )
    finally:
        client.close()
        app.dependency_overrides.clear()

    assert direct.status_code == 201 and set(direct.json()) == BUILD_OUTCOME_KEYS
    assert created.status_code == 201
    assert blocked.status_code == 503
    assert blocked.json()["detail"]["outcome"] == "BUILD_UNAVAILABLE"
    assert built.status_code == 201 and set(built.json()) == BUILD_OUTCOME_KEYS
    assert repository.lookups.count("draft-build:phase3-builder") == 1
    persisted_candidates = [stored_candidate for stored_candidate, _ in repository.drafts.values()]
    assert persisted_candidates
    assert all(
        member.label_ready and member.rights_ready and member.evidence_ready
        for member in persisted_candidates[0].cohort
    )


class _UnknownMutationRepository(_RouteRepository):
    @staticmethod
    def _unknown(action: str, lookup_path: str) -> None:
        raise profile_release.ProfileReleaseUnknownOutcomeError(
            action=action,
            lookup_path=lookup_path,
        )

    def build_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._unknown("BUILD", "/synthetic/build-lookup")

    def approve_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._unknown("APPROVE", "/synthetic/approval-lookup")

    def activate_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._unknown("ACTIVATE", "/synthetic/activation-lookup")

    def rollback_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._unknown("ROLLBACK", "/synthetic/rollback-lookup")


class _RetryableAbortMutationRepository(_RouteRepository):
    @staticmethod
    def _abort(action: str) -> None:
        raise profile_release.ProfileReleaseRetryableAbortError(action=action)

    def build_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._abort("BUILD")

    def approve_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._abort("APPROVE")

    def activate_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._abort("ACTIVATE")

    def rollback_profile_release(self, *args: Any, **kwargs: Any) -> Any:
        self._abort("ROLLBACK")


def test_nonce_bound_build_and_digest_only_build_recovery_have_exact_keys() -> None:
    repository = _RouteRepository()
    client, app = _route_client("builder", lambda: repository)
    try:
        built = client.post(
            "/internal/evaluation/profile-releases/build",
            json=_build_request_payload("synthetic-route-build"),
        )
        assert built.status_code == 201
        assert set(built.json()) == BUILD_OUTCOME_KEYS
        assert built.json()["completion"] == "MUTATION_COMMITTED"
        raw_lookup = client.get(
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{RAW_BUILD_NONCE}"
        )
        digest_lookup = client.get(
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/"
            f"{built.json()['nonce_sha256']}"
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert raw_lookup.status_code == 404
    assert raw_lookup.json() == {"detail": "profile release outcome UNKNOWN"}
    assert digest_lookup.status_code == 200
    assert set(digest_lookup.json()) == BUILD_OUTCOME_KEYS
    assert digest_lookup.json()["receipt_sha256"] == built.json()["receipt_sha256"]
    assert digest_lookup.json()["completion"] == "RELOOKUP_CONFIRMED"
    observed = repr((built.json(), raw_lookup.json(), digest_lookup.json()))
    assert RAW_BUILD_NONCE not in observed
    assert all(canary not in observed for canary in PROTECTED_CANARIES)


def test_opaque_build_draft_routes_never_return_or_route_protected_candidate_data() -> None:
    repository = _RouteRepository()
    payload = _build_request_payload("synthetic-route-draft")
    payload["draft_ref"] = "D" * 43
    protected_place_ref = payload["cohort"][0]["place_ref"]
    client, app = _route_client("builder", lambda: repository)
    try:
        created = client.post(
            "/internal/evaluation/profile-releases/build-drafts",
            json=payload,
        )
        assert created.status_code == 201
        assert set(created.json()) == {"draft_ref", "expires_at", "nonce_sha256"}
        serialized = repr(created.json())
        assert str(protected_place_ref) not in serialized
        built = client.post(
            "/internal/evaluation/profile-releases/build-drafts/build",
            json={
                "draft_ref": created.json()["draft_ref"],
                "nonce_sha256": created.json()["nonce_sha256"],
            },
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert built.status_code == 201
    assert set(built.json()) == BUILD_OUTCOME_KEYS
    assert str(protected_place_ref) not in repr(built.json())


def test_build_draft_route_sanitizes_database_failures_without_payload_leakage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository = _RouteRepository()
    payload = _build_request_payload("synthetic-route-draft-database-failure")
    payload["draft_ref"] = "H" * 43
    protected_place_ref = str(payload["cohort"][0]["place_ref"])
    repository.draft_error = DBAPIError(
        "INSERT INTO dev_eval.profile_release_build_drafts(candidate_payload)",
        {"candidate_payload": payload},
        RuntimeError("synthetic database unavailable"),
        False,
    )
    client, app = _route_client("builder", lambda: repository)
    try:
        response = client.post(
            "/internal/evaluation/profile-releases/build-drafts",
            json=payload,
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json() == {
        "detail": "profile release draft persistence is temporarily unavailable"
    }
    observed = repr((response.json(), caplog.messages))
    assert protected_place_ref not in observed
    assert all(canary not in observed for canary in PROTECTED_CANARIES)


def test_draft_build_cleanup_unknown_runtime_body_matches_published_contract() -> None:
    repository = _RouteRepository()
    nonce_sha256 = "a" * 64
    lookup_path = f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}"
    retry_path = "/internal/evaluation/profile-releases/build-drafts/build"
    repository.draft_build_error = profile_release.ProfileReleaseDraftCleanupUnknownError(
        lookup_path=lookup_path,
        retry_path=retry_path,
    )
    client, app = _route_client("builder", lambda: repository)
    try:
        response = client.post(
            retry_path,
            json={"draft_ref": "I" * 43, "nonce_sha256": nonce_sha256},
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "outcome": "DRAFT_CLEANUP_UNKNOWN",
            "action": "BUILD",
            "lookup_path": lookup_path,
            "retry_path": retry_path,
        }
    }
    assert ProfileReleaseDraftCleanupUnknownResponse.model_validate(response.json())


def test_draft_build_pre_mutation_unavailable_has_distinct_safe_contract() -> None:
    repository = _RouteRepository()
    retry_path = "/internal/evaluation/profile-releases/build-drafts/build"
    repository.draft_build_error = profile_release.ProfileReleaseBuildUnavailableError(
        retry_path=retry_path
    )
    client, app = _route_client("builder", lambda: repository)
    try:
        response = client.post(
            retry_path,
            json={"draft_ref": "U" * 43, "nonce_sha256": "a" * 64},
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "outcome": "BUILD_UNAVAILABLE",
            "action": "BUILD",
            "retry_path": retry_path,
        }
    }


@pytest.mark.parametrize(
    "mutation",
    ("short", "long", "duplicate-place", "duplicate-profile", "invalid-release-id"),
)
@pytest.mark.parametrize(
    "path",
    (
        "/internal/evaluation/profile-releases/build",
        "/internal/evaluation/profile-releases/build-drafts",
    ),
)
def test_build_route_rejects_structurally_invalid_candidates_as_422(
    mutation: str,
    path: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    payload = _build_request_payload("synthetic-route-invalid")
    cohort = payload["cohort"]
    assert isinstance(cohort, list)
    cohort[0]["place_ref"] = "synthetic-dev-membership-canary"
    if mutation == "short":
        cohort.pop()
    elif mutation == "long":
        extra = dict(cohort[-1])
        extra["place_ref"] = "synthetic-place-24"
        extra["profile_sha256"] = f"{25:064x}"
        cohort.append(extra)
    elif mutation == "duplicate-place":
        cohort[1]["place_ref"] = cohort[0]["place_ref"]
    elif mutation == "duplicate-profile":
        cohort[1]["profile_sha256"] = cohort[0]["profile_sha256"]
    else:
        payload["release_id"] = "synthetic-dev-membership-canary invalid"
    if path.endswith("build-drafts"):
        payload["draft_ref"] = "K" * 43
    repository = _RouteRepository()
    client, app = _route_client("builder", lambda: repository)
    try:
        response = client.post(
            path,
            json=payload,
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 422
    assert response.json() == {"detail": "profile release request is structurally invalid"}
    observed = repr((response.json(), caplog.messages))
    assert "input" not in response.text
    assert "ctx" not in response.text
    assert "synthetic-dev-membership-canary" not in observed
    assert RAW_BUILD_NONCE not in observed
    assert repository.lookups == []


def test_draft_build_validation_redacts_reference_and_nonce_canaries(
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository = _RouteRepository()
    client, app = _route_client("builder", lambda: repository)
    try:
        response = client.post(
            "/internal/evaluation/profile-releases/build-drafts/build",
            json={
                "draft_ref": "synthetic-draft-reference-canary",
                "nonce_sha256": "synthetic-raw-nonce-canary",
            },
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 422
    assert response.json() == {"detail": "profile release request is structurally invalid"}
    observed = repr((response.json(), caplog.messages))
    assert "synthetic-draft-reference-canary" not in observed
    assert "synthetic-raw-nonce-canary" not in observed
    assert repository.lookups == []


@pytest.mark.parametrize(
    ("path", "payload", "canaries"),
    (
        (
            f"/internal/evaluation/profile-releases/{'a' * 64}/activate",
            {
                "expected_current_sha256": None,
                "nonce": "synthetic-raw-activation-nonce-canary",
            },
            ("synthetic-raw-activation-nonce-canary",),
        ),
        (
            f"/internal/evaluation/profile-releases/{'a' * 64}/rollback",
            {
                "expected_current_sha256": "b" * 64,
                "nonce": "synthetic-raw-rollback-nonce-canary",
                "reason": "synthetic-rollback-reason-canary" * 20,
            },
            (
                "synthetic-raw-rollback-nonce-canary",
                "synthetic-rollback-reason-canary",
            ),
        ),
    ),
)
def test_transition_validation_redacts_body_and_matches_openapi_error_contract(
    path: str,
    payload: dict[str, object],
    canaries: tuple[str, ...],
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository = _RouteRepository()
    client, app = _route_client("approver", lambda: repository)
    try:
        response = client.post(path, json=payload)
    finally:
        client.close()
        app.dependency_overrides.clear()

    assert response.status_code == 422
    assert ProfileReleaseErrorResponse.model_validate(response.json()).detail == (
        "profile release request is structurally invalid"
    )
    observed = repr((response.json(), caplog.messages))
    assert "input" not in response.text
    assert "ctx" not in response.text
    assert all(canary not in observed for canary in canaries)
    assert repository.lookups == []


@pytest.mark.parametrize(
    ("action", "path", "payload"),
    (
        ("BUILD", "/internal/evaluation/profile-releases/build", "BUILD"),
        (
            "APPROVE",
            f"/internal/evaluation/profile-releases/{'a' * 64}/approve",
            None,
        ),
        (
            "ACTIVATE",
            f"/internal/evaluation/profile-releases/{'a' * 64}/activate",
            {"expected_current_sha256": None, "nonce": "b" * 64},
        ),
        (
            "ROLLBACK",
            f"/internal/evaluation/profile-releases/{'a' * 64}/rollback",
            {
                "expected_current_sha256": "b" * 64,
                "nonce": "c" * 64,
                "reason": "합성 복구",
            },
        ),
    ),
)
def test_unknown_mutation_outcomes_are_explicit_503_with_lookup(
    action: str,
    path: str,
    payload: object,
) -> None:
    repository = _UnknownMutationRepository()
    role = "builder" if action == "BUILD" else "approver"
    body = _build_request_payload("synthetic-route-unknown") if payload == "BUILD" else payload
    client, app = _route_client(role, lambda: repository)
    try:
        response = client.post(path, json=body)
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["outcome"] == "UNKNOWN"
    assert detail["action"] == action
    assert detail["lookup_path"].startswith("/synthetic/")
    assert all(canary not in repr(response.json()) for canary in PROTECTED_CANARIES)


@pytest.mark.parametrize(
    ("action", "path", "payload"),
    (
        ("BUILD", "/internal/evaluation/profile-releases/build", "BUILD"),
        ("APPROVE", f"/internal/evaluation/profile-releases/{'a' * 64}/approve", None),
        (
            "ACTIVATE",
            f"/internal/evaluation/profile-releases/{'a' * 64}/activate",
            {"expected_current_sha256": None, "nonce": "b" * 64},
        ),
        (
            "ROLLBACK",
            f"/internal/evaluation/profile-releases/{'a' * 64}/rollback",
            {
                "expected_current_sha256": "b" * 64,
                "nonce": "c" * 64,
                "reason": "합성 복구",
            },
        ),
    ),
)
def test_serialization_retry_exhaustion_is_explicitly_safe_to_retry(
    action: str,
    path: str,
    payload: object,
) -> None:
    repository = _RetryableAbortMutationRepository()
    role = "builder" if action == "BUILD" else "approver"
    body = _build_request_payload("synthetic-route-retry") if payload == "BUILD" else payload
    client, app = _route_client(role, lambda: repository)
    try:
        response = client.post(path, json=body)
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json() == {"detail": {"outcome": "RETRYABLE_ABORT", "action": action}}
    assert "lookup_path" not in repr(response.json())
    assert all(canary not in repr(response.json()) for canary in PROTECTED_CANARIES)


def test_transition_replay_route_reports_relookup_without_mutating_signed_receipt() -> None:
    repository = _RouteRepository()
    receipt = profile_release.ProfileReleaseTransitionReceipt(
        action="ACTIVATE",
        release_sha256="a" * 64,
        previous_release_sha256=None,
        expected_current_sha256=None,
        approver_principal="phase3-approver",
        nonce_sha256="b" * 64,
        completion=profile_release.ProfileReleaseCompletion.MUTATION_COMMITTED,
    )
    repository.transition_result = profile_release.ProfileReleaseTransitionMutationResult(
        receipt=receipt,
        completion=profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
    )
    client, app = _route_client("approver", lambda: repository)
    try:
        response = client.post(
            f"/internal/evaluation/profile-releases/{'a' * 64}/activate",
            json={"expected_current_sha256": None, "nonce": "c" * 64},
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 200
    assert response.json()["completion"] == "RELOOKUP_CONFIRMED"
    assert receipt.completion is profile_release.ProfileReleaseCompletion.MUTATION_COMMITTED
    assert (
        profile_release.ProfileReleaseTransitionReceipt.model_validate_json(
            receipt.model_dump_json()
        )
        == receipt
    )


def test_proven_integrity_rejection_remains_409_not_unknown() -> None:
    class IntegrityRepository(_RouteRepository):
        def build_profile_release(self, *args: Any, **kwargs: Any) -> Any:
            raise IntegrityError(
                "INSERT",
                {},
                RuntimeError("synthetic proven constraint rejection"),
            )

    client, app = _route_client("builder", IntegrityRepository)
    try:
        response = client.post(
            "/internal/evaluation/profile-releases/build",
            json=_build_request_payload("synthetic-integrity-rejection"),
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 409
    assert response.json() == {"detail": "phase 3 profile release transition rejected"}


def test_pointer_state_and_transition_routes_enforce_exact_projection_allowlists() -> None:
    repository = _RouteRepository()
    release_sha256 = "a" * 64
    receipt_sha256 = "b" * 64
    repository.state_projection = profile_release.ProfileReleaseStateProjection(
        release_sha256=release_sha256,
        state=profile_release.ProfileReleaseState.BUILT_UNAPPROVED,
        lifecycle_head_receipt_sha256=None,
        provenance_kind="BUILD",
        provenance_receipt_sha256=receipt_sha256,
    )
    transition_nonce = "c" * 64
    repository.transition_outcome = profile_release.ProfileReleaseTransitionOutcome(
        action="ACTIVATE",
        release_sha256=release_sha256,
        previous_release_sha256=None,
        expected_current_sha256=None,
        receipt_sha256=receipt_sha256,
        nonce_sha256=transition_nonce,
        binding_sha256="d" * 64,
        completion=profile_release.ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
    )

    builder_client, builder_app = _route_client("builder", lambda: repository)
    try:
        pointer = builder_client.get("/internal/evaluation/profile-releases/active-pointer")
        state_response = builder_client.get(
            f"/internal/evaluation/profile-releases/{release_sha256}/state"
        )
        forbidden_transition = builder_client.get(
            f"/internal/evaluation/profile-releases/transition-receipts/by-nonce/{transition_nonce}"
        )
    finally:
        builder_client.close()
        builder_app.dependency_overrides.clear()
    assert pointer.status_code == 200 and set(pointer.json()) == POINTER_KEYS
    assert state_response.status_code == 200 and set(state_response.json()) == STATE_KEYS
    assert forbidden_transition.status_code == 403

    approver_client, approver_app = _route_client("approver", lambda: repository)
    try:
        transition = approver_client.get(
            f"/internal/evaluation/profile-releases/transition-receipts/by-nonce/{transition_nonce}"
        )
        forbidden_build = approver_client.get(
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{BUILD_NONCE_SHA256}"
        )
    finally:
        approver_client.close()
        approver_app.dependency_overrides.clear()
    assert transition.status_code == 200
    assert set(transition.json()) == TRANSITION_OUTCOME_KEYS
    assert forbidden_build.status_code == 403


@pytest.mark.parametrize(
    ("role", "path"),
    (
        (
            "evaluator_a",
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{BUILD_NONCE_SHA256}",
        ),
        ("model_runner", "/internal/evaluation/profile-releases/active-pointer"),
        ("adjudicator", f"/internal/evaluation/profile-releases/{'a' * 64}/state"),
        (
            "builder",
            f"/internal/evaluation/profile-releases/transition-receipts/by-nonce/{'b' * 64}",
        ),
    ),
)
def test_denied_roles_fail_before_repository_dependency_lookup(role: str, path: str) -> None:
    repository_looked_up = False

    def forbidden_repository_lookup() -> _RouteRepository:
        nonlocal repository_looked_up
        repository_looked_up = True
        raise AssertionError("denied reconciliation read reached repository dependency")

    client, app = _route_client(
        role,
        forbidden_repository_lookup,
        enforce_authority=True,
    )
    try:
        response = client.get(path)
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 403
    assert repository_looked_up is False


@pytest.mark.parametrize(
    ("role", "path", "payload"),
    (
        ("approver", "/internal/evaluation/profile-releases/build", "BUILD"),
        ("approver", "/internal/evaluation/profile-releases/build-drafts", "BUILD"),
        (
            "approver",
            "/internal/evaluation/profile-releases/build-drafts/build",
            {"draft_ref": "D" * 43},
        ),
        (
            "builder",
            f"/internal/evaluation/profile-releases/{'a' * 64}/approve",
            None,
        ),
        (
            "builder",
            f"/internal/evaluation/profile-releases/{'a' * 64}/activate",
            {"expected_current_sha256": None, "nonce": "b" * 64},
        ),
        (
            "builder",
            f"/internal/evaluation/profile-releases/{'a' * 64}/rollback",
            {
                "expected_current_sha256": "b" * 64,
                "nonce": "c" * 64,
                "reason": "합성 복구",
            },
        ),
        (
            "approver",
            "/internal/evaluation/profile-releases/sessions/synthetic-session/pin",
            None,
        ),
        (
            "approver",
            "/internal/evaluation/profile-releases/results/synthetic-result/pin",
            None,
        ),
    ),
)
def test_wrong_role_mutations_fail_before_repository_construction(
    role: str,
    path: str,
    payload: object,
) -> None:
    repository_looked_up = False

    def forbidden_repository_lookup() -> _RouteRepository:
        nonlocal repository_looked_up
        repository_looked_up = True
        raise AssertionError("wrong-role mutation reached repository dependency")

    body = _build_request_payload("synthetic-wrong-role") if payload == "BUILD" else payload
    client, app = _route_client(role, forbidden_repository_lookup)
    try:
        response = client.post(path, json=body)
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 403
    assert repository_looked_up is False


def test_unauthenticated_reconciliation_read_is_401_before_repository_lookup() -> None:
    repository_looked_up = False

    def forbidden_repository_lookup() -> _RouteRepository:
        nonlocal repository_looked_up
        repository_looked_up = True
        raise AssertionError("unauthenticated reconciliation read reached repository")

    app = create_app()
    app.dependency_overrides[get_evaluation_repository] = forbidden_repository_lookup
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/internal/evaluation/profile-releases/active-pointer")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 401
    assert repository_looked_up is False


def test_missing_and_corrupt_reconciliation_reads_are_never_success() -> None:
    repository = _RouteRepository()
    client, app = _route_client("builder", lambda: repository)
    try:
        missing = client.get(
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{BUILD_NONCE_SHA256}"
        )
        repository.raise_integrity = True
        corrupt = client.get(
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{BUILD_NONCE_SHA256}"
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert missing.status_code == 404
    assert corrupt.status_code == 409
    assert missing.json() == {"detail": "profile release outcome UNKNOWN"}
    assert corrupt.json() == {"detail": "phase 3 profile release transition rejected"}


@pytest.mark.parametrize(
    ("role", "path"),
    (
        (
            "builder",
            f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{BUILD_NONCE_SHA256}",
        ),
        ("builder", "/internal/evaluation/profile-releases/active-pointer"),
        (
            "approver",
            f"/internal/evaluation/profile-releases/transition-receipts/by-nonce/{'a' * 64}",
        ),
        ("builder", f"/internal/evaluation/profile-releases/{'a' * 64}/state"),
    ),
)
def test_reconciliation_read_database_outages_are_retryable_503_without_details(
    role: str,
    path: str,
) -> None:
    repository = _RouteRepository()
    repository.read_error = DBAPIError(
        "SELECT synthetic protected query",
        {"protected": PROTECTED_CANARIES[0]},
        RuntimeError("synthetic database outage"),
        False,
    )
    client, app = _route_client(role, lambda: repository)
    try:
        response = client.get(path)
    finally:
        client.close()
        app.dependency_overrides.clear()
    assert response.status_code == 503
    assert response.json() == {"detail": "profile release state is temporarily unavailable"}
    assert "UNKNOWN" not in repr(response.json())
    assert all(canary not in repr(response.json()) for canary in PROTECTED_CANARIES)


def test_cli_rejects_raw_candidate_build_without_repository_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = _candidate("synthetic-cli-reconciliation")
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_bytes(canonical_json_bytes(candidate.model_dump(mode="json")))
    repository = _RouteRepository()
    principal = Phase3Principal(actor_id="phase3-builder", role="builder")
    monkeypatch.setattr(manage_profile_release, "_principal", lambda: principal)
    monkeypatch.setattr(
        manage_profile_release,
        "get_evaluation_repository",
        lambda _principal: repository,
    )

    with pytest.raises(SystemExit) as blocked:
        manage_profile_release.main(["--build", str(candidate_path), "--nonce", RAW_BUILD_NONCE])
    assert blocked.value.code == 2
    assert capsys.readouterr().out == ""
    assert repository.lookups == []


def test_cli_exposes_explicit_expired_build_draft_retention(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _RouteRepository()
    principal = Phase3Principal(actor_id="phase3-builder", role="builder")
    monkeypatch.setattr(manage_profile_release, "_principal", lambda: principal)
    monkeypatch.setattr(
        manage_profile_release,
        "get_evaluation_repository",
        lambda _principal: repository,
    )

    assert manage_profile_release.main(["--purge-expired-build-drafts"]) == 0
    assert capsys.readouterr().out.strip() == (
        '{"event":"profile_release_build_draft_purge","status":"SUCCEEDED",'
        '"deleted_count":2,"remaining_expired_count":0}'
    )
    assert repository.lookups == ["draft-purge:phase3-builder"]


def test_cli_retention_failure_is_nonzero_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _RouteRepository()
    repository.purge_error = RuntimeError("synthetic-private-dsn-canary")
    principal = Phase3Principal(actor_id="phase3-builder", role="builder")
    monkeypatch.setattr(manage_profile_release, "_principal", lambda: principal)
    monkeypatch.setattr(
        manage_profile_release,
        "get_evaluation_repository",
        lambda _principal: repository,
    )
    assert manage_profile_release.main(["--purge-expired-build-drafts"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "event": "profile_release_build_draft_purge",
        "status": "FAILED",
        "error_code": "PURGE_UNAVAILABLE",
    }
    assert "synthetic-private-dsn-canary" not in captured.err


def test_cli_retention_missing_capability_is_nonzero_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ITDA_PHASE3_CAPABILITY", raising=False)

    assert manage_profile_release.main(["--purge-expired-build-drafts"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "event": "profile_release_build_draft_purge",
        "status": "FAILED",
        "error_code": "PURGE_UNAVAILABLE",
    }
    assert "ITDA_PHASE3_CAPABILITY" not in captured.err


def test_cli_retention_rejects_wrong_role_before_repository_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    principal = Phase3Principal(actor_id="phase3-approver", role="approver")
    repository_bootstrapped = False

    def _unexpected_repository(_principal: Phase3Principal) -> object:
        nonlocal repository_bootstrapped
        repository_bootstrapped = True
        raise AssertionError("repository must not be bootstrapped for an approver")

    monkeypatch.setattr(manage_profile_release, "_principal", lambda: principal)
    monkeypatch.setattr(
        manage_profile_release,
        "get_evaluation_repository",
        _unexpected_repository,
    )

    assert manage_profile_release.main(["--purge-expired-build-drafts"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error_code"] == "PURGE_UNAVAILABLE"
    assert repository_bootstrapped is False


def test_cli_retention_repository_bootstrap_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    principal = Phase3Principal(actor_id="phase3-builder", role="builder")
    monkeypatch.setattr(manage_profile_release, "_principal", lambda: principal)

    def _unavailable_repository(_principal: Phase3Principal) -> object:
        raise RuntimeError("postgresql://private-user:private-password@private-host")

    monkeypatch.setattr(
        manage_profile_release,
        "get_evaluation_repository",
        _unavailable_repository,
    )

    assert manage_profile_release.main(["--purge-expired-build-drafts"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "event": "profile_release_build_draft_purge",
        "status": "FAILED",
        "error_code": "PURGE_UNAVAILABLE",
    }
    assert "private-password" not in captured.err


def test_raw_wire_nonce_and_stored_digest_are_distinct_vocabularies() -> None:
    assert RAW_BUILD_NONCE != BUILD_NONCE_SHA256
    assert RAW_TRANSITION_NONCE != TRANSITION_NONCE_SHA256
    assert hashlib.sha256(RAW_BUILD_NONCE.encode("ascii")).hexdigest() == BUILD_NONCE_SHA256
    assert (
        hashlib.sha256(RAW_TRANSITION_NONCE.encode("ascii")).hexdigest() == TRANSITION_NONCE_SHA256
    )
