"""Focused authority regressions for the Phase 3 release migration."""

from __future__ import annotations

import hashlib
import importlib
import json
import secrets
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.profile_release import (
    ProfileReleaseBuildOutcome,
    ProfileReleaseCandidate,
    ProfileReleaseCohortMember,
    ProfileReleaseCompletion,
    ProfileReleaseTransitionReceipt,
)
from itda.contracts.profile_release_candidate_validation import (
    validate_profile_release_candidate_payload_v1,
)
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.session import (
    create_database_engine,
    create_session_factory,
    sqlalchemy_url_from_dsn,
)
from itda.domain.canonical import canonical_sha256
from tests.integration.profile_release_test_support import (
    PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
    ensure_profile_release_authority_roles,
)
from tests.integration.test_profile_release import (
    profile_release_build_authority,
    register_profile_release_builder_admin,
    unregister_profile_release_builder_admin,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
MIGRATION = importlib.import_module(
    "migrations.versions.0010_phase3_profile_release_build_reconciliation"
)
_TEST_AUTHORIZATION_KEY_HEX = "41" * 32


def _config(postgres_harness: object) -> Config:
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
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    config.attributes["label_approver_role"] = postgres_harness.role_names["evaluator"]
    config.attributes["profile_release_authorization_hmac_key"] = _TEST_AUTHORIZATION_KEY_HEX
    return config


def _candidate(release_id: str, *, seed: int = 0) -> ProfileReleaseCandidate:
    digest = f"{seed + 40:064x}"
    return ProfileReleaseCandidate(
        release_id=release_id,
        builder_principal="phase3-builder",
        canonical_lineage_sha256="a" * 64,
        dev_lineage_sha256="b" * 64,
        profile_schema_sha256="c" * 64,
        label_freeze_sha256=digest,
        candidate_run_sha256=f"{seed + 41:064x}",
        reviewed_manifest_sha256=f"{seed + 42:064x}",
        rights_manifest_sha256=f"{seed + 43:064x}",
        source_manifest_sha256=f"{seed + 44:064x}",
        code_sha256=f"{seed + 45:064x}",
        config_sha256=f"{seed + 46:064x}",
        cohort=tuple(
            ProfileReleaseCohortMember(
                place_ref=f"synthetic-place-{seed:02d}-{index:02d}",
                label_ready=True,
                rights_ready=True,
                evidence_ready=True,
                description_lane="READY",
                odii_lane="MISSING" if index % 3 == 0 else "READY",
                profile_sha256=f"{seed * 100 + index + 1:064x}",
                label_export_sha256=f"{seed * 100 + index + 101:064x}",
                candidate_manifest_sha256=f"{seed * 100 + index + 201:064x}",
                reviewed_evidence_manifest_sha256=(f"{seed * 100 + index + 301:064x}"),
                accepted_review_set_sha256=f"{seed * 100 + index + 401:064x}",
                rights_sha256=f"{seed * 100 + index + 501:064x}",
                source_sha256=f"{seed * 100 + index + 601:064x}",
            )
            for index in range(24)
        ),
    )


class _AuthorityResolvedTestRepository(EvaluationRepository):
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
        candidate: ProfileReleaseCandidate,
        *,
        authenticated_principal: str,
        reconciliation_nonce: str,
        client_actor_id: str | None = None,
    ) -> ProfileReleaseBuildOutcome:
        return self._builder_repository.build_profile_release(
            profile_release_build_authority(self._builder_repository, candidate),
            authenticated_principal=authenticated_principal,
            reconciliation_nonce=reconciliation_nonce,
            client_actor_id=client_actor_id,
        )


@pytest.mark.parametrize(
    ("scope", "field_name"),
    [
        ("candidate", "label_freeze_sha256"),
        ("candidate", "candidate_run_sha256"),
        ("candidate", "reviewed_manifest_sha256"),
        ("candidate", "rights_manifest_sha256"),
        ("candidate", "source_manifest_sha256"),
        ("candidate", "code_sha256"),
        ("candidate", "config_sha256"),
        ("member", "label_export_sha256"),
        ("member", "candidate_manifest_sha256"),
        ("member", "reviewed_evidence_manifest_sha256"),
        ("member", "accepted_review_set_sha256"),
        ("member", "rights_sha256"),
        ("member", "source_sha256"),
    ],
)
def test_shared_candidate_validator_matches_every_optional_digest_pattern(
    scope: str,
    field_name: str,
) -> None:
    candidate = _candidate("synthetic-shared-candidate-validator")
    payload = candidate.model_dump(mode="json")
    assert validate_profile_release_candidate_payload_v1(payload) == payload
    malformed = deepcopy(payload)
    target = malformed if scope == "candidate" else malformed["cohort"][0]
    assert isinstance(target, dict)
    target[field_name] = "A" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        validate_profile_release_candidate_payload_v1(malformed)
    with pytest.raises(ValidationError):
        ProfileReleaseCandidate.model_validate(malformed)


@pytest.mark.parametrize(
    ("scope", "field_name"),
    [
        ("candidate", "label_freeze_sha256"),
        ("candidate", "candidate_run_sha256"),
        ("candidate", "reviewed_manifest_sha256"),
        ("candidate", "rights_manifest_sha256"),
        ("candidate", "source_manifest_sha256"),
        ("candidate", "code_sha256"),
        ("candidate", "config_sha256"),
        ("member", "label_export_sha256"),
        ("member", "candidate_manifest_sha256"),
        ("member", "reviewed_evidence_manifest_sha256"),
        ("member", "accepted_review_set_sha256"),
        ("member", "rights_sha256"),
        ("member", "source_sha256"),
    ],
)
def test_database_candidate_boundary_mirrors_every_optional_digest_pattern(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
    scope: str,
    field_name: str,
) -> None:
    del release_authority_runtime
    payload = _candidate(f"synthetic-db-optional-{scope}-{field_name}").model_dump(mode="json")
    target = payload if scope == "candidate" else payload["cohort"][0]
    assert isinstance(target, dict)
    target[field_name] = "A" * 64
    payload["release_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "release_sha256"}
    )
    connection = postgres_harness.connect("admin")
    try:
        with pytest.raises(psycopg.Error) as captured:
            connection.execute(
                "INSERT INTO dev_eval.profile_releases ("
                "release_sha256, release_id, builder_principal, canonical_lineage_sha256, "
                "dev_lineage_sha256, profile_schema_sha256, payload) VALUES ("
                "%s, %s, %s, %s, %s, %s, %s::jsonb)",
                (
                    payload["release_sha256"],
                    payload["release_id"],
                    payload["builder_principal"],
                    payload["canonical_lineage_sha256"],
                    payload["dev_lineage_sha256"],
                    payload["profile_schema_sha256"],
                    psycopg.types.json.Jsonb(payload),
                ),
            )
        assert captured.value.sqlstate == "23514"
    finally:
        connection.rollback()
        connection.close()


@pytest.mark.parametrize(
    ("scope", "field_name", "wrong_type"),
    [
        ("candidate", "schema_version", 1),
        ("candidate", "release_id", []),
        ("candidate", "state", 1),
        ("candidate", "builder_principal", []),
        ("candidate", "canonical_lineage_sha256", 1),
        ("candidate", "dev_lineage_sha256", 1),
        ("candidate", "profile_schema_sha256", 1),
        ("candidate", "cohort", {}),
        ("candidate", "release_sha256", 1),
        ("member", "place_ref", 1),
        ("member", "label_ready", "true"),
        ("member", "rights_ready", "true"),
        ("member", "evidence_ready", "true"),
        ("member", "description_lane", 1),
        ("member", "odii_lane", 1),
        ("member", "profile_sha256", 1),
    ],
)
@pytest.mark.parametrize("mutation", ["null", "missing", "wrong_type"])
def test_database_candidate_authority_rejects_required_null_missing_and_wrong_type(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
    scope: str,
    field_name: str,
    wrong_type: object,
    mutation: str,
) -> None:
    del release_authority_runtime
    payload = _candidate(f"synthetic-db-required-{scope}-{field_name}-{mutation}").model_dump(
        mode="json"
    )
    target = payload if scope == "candidate" else payload["cohort"][0]
    assert isinstance(target, dict)
    if mutation == "missing":
        target.pop(field_name)
    elif mutation == "null":
        target[field_name] = None
    else:
        target[field_name] = wrong_type

    construction_time_release_digest = (
        scope == "candidate" and field_name == "release_sha256" and mutation in {"null", "missing"}
    )
    if not construction_time_release_digest:
        with pytest.raises(ValueError):
            validate_profile_release_candidate_payload_v1(payload)
    if (
        not (
            scope == "candidate"
            and mutation == "missing"
            and field_name in {"schema_version", "state", "release_sha256"}
        )
        and not construction_time_release_digest
    ):
        with pytest.raises(ValidationError):
            ProfileReleaseCandidate.model_validate(payload)

    with postgres_harness.connect("admin", autocommit=True) as connection:
        valid = connection.execute(
            "SELECT dev_eval.validate_profile_release_candidate_payload_v1(%s::jsonb)",
            (psycopg.types.json.Jsonb(payload),),
        ).fetchone()
    assert valid == (False,)


@pytest.fixture
def release_authority_runtime(
    postgres_harness: object,
) -> Iterator[tuple[Config, EvaluationRepository]]:
    authority_password = secrets.token_urlsafe(24)
    ensure_profile_release_authority_roles(
        postgres_harness,
        authority_service_password=authority_password,
    )
    config = _config(postgres_harness)
    command.upgrade(config, "head")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "TRUNCATE dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1, "
            "dev_eval.profile_release_build_draft_consumptions, "
            "dev_eval.profile_release_build_drafts, "
            "dev_eval.profile_release_build_receipts, "
            "dev_eval.profile_release_build_nonce_reservations, "
            "dev_eval.profile_release_nonce_quarantine_0010, "
            "dev_eval.profile_releases, dev_eval.profile_release_nonce_ledger CASCADE"
        )
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    authority_dsn = make_conninfo(
        **(
            admin_info
            | {
                "user": PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
                "password": authority_password,
            }
        )
    )
    admin_engine = create_database_engine(postgres_harness.dsns["admin"])
    builder_engine = create_database_engine(postgres_harness.dsns["dev"])
    authority_engine = create_database_engine(authority_dsn)
    builder_database_principal = postgres_harness.role_names["dev"]
    register_profile_release_builder_admin(
        builder_database_principal,
        postgres_harness.dsns["admin"],
    )
    try:
        yield (
            config,
            _AuthorityResolvedTestRepository(
                create_session_factory(admin_engine),
                builder_factory=create_session_factory(builder_engine),
                authority_connection_factory=create_session_factory(authority_engine),
            ),
        )
    finally:
        unregister_profile_release_builder_admin(builder_database_principal)
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
                "dev_eval.profile_release_nonce_quarantine_0010, "
                "dev_eval.profile_releases, dev_eval.profile_release_nonce_ledger CASCADE"
            )


def test_duplicate_authority_accepts_first_replacement_rollback_and_superseded_history(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
) -> None:
    _, repository = release_authority_runtime
    candidates = tuple(
        _candidate(f"synthetic-history-{index}", seed=index + 1) for index in range(3)
    )
    for index, candidate in enumerate(candidates):
        repository.build_profile_release(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce=f"{index + 1:064x}",
        )
        repository.approve_profile_release(
            str(candidate.release_sha256),
            authenticated_principal="phase3-approver",
        )
    transitions = (
        repository.activate_profile_release(
            str(candidates[0].release_sha256),
            expected_current=None,
            authenticated_principal="phase3-approver",
            nonce="a" * 64,
        ),
        repository.activate_profile_release(
            str(candidates[1].release_sha256),
            expected_current=str(candidates[0].release_sha256),
            authenticated_principal="phase3-approver",
            nonce="b" * 64,
        ),
        repository.rollback_profile_release(
            str(candidates[0].release_sha256),
            expected_current=str(candidates[1].release_sha256),
            authenticated_principal="phase3-approver",
            reason="synthetic rollback authority check",
            nonce="c" * 64,
        ),
        repository.activate_profile_release(
            str(candidates[2].release_sha256),
            expected_current=str(candidates[0].release_sha256),
            authenticated_principal="phase3-approver",
            nonce="d" * 64,
        ),
    )
    engine = create_engine(
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]),
        future=True,
    )
    try:
        with engine.connect() as connection:
            history = MIGRATION._validated_transition_history(connection)
            assert set(history) == {transition.receipt.receipt_sha256 for transition in transitions}
            ledger_rows = connection.execute(
                text(
                    "SELECT binding_sha256, nonce_sha256, receipt_sha256, payload "
                    "FROM dev_eval.profile_release_nonce_ledger"
                )
            ).mappings()
            for ledger_row in ledger_rows:
                assert MIGRATION._duplicate_transition_is_authoritative(
                    connection, dict(ledger_row)
                )
            final_receipt = transitions[-1].receipt.receipt_sha256
            final_heads = connection.execute(
                text(
                    "SELECT release_sha256, state, head_receipt_sha256 FROM "
                    "dev_eval.profile_release_lifecycle_heads "
                    "WHERE head_receipt_sha256 = :receipt ORDER BY state"
                ),
                {"receipt": final_receipt},
            ).all()
            assert len(final_heads) == 2
            assert {row.state for row in final_heads} == {
                "ACTIVE",
                "APPROVED_INACTIVE",
            }
            authority = next(iter(history.values()))
            forged = {
                "binding_sha256": "f" * 64,
                "nonce_sha256": authority["nonce_sha256"],
                "receipt_sha256": next(iter(history)),
                "payload": authority["payload"],
            }
            assert not MIGRATION._duplicate_transition_is_authoritative(connection, forged)
    finally:
        engine.dispose()


def test_duplicate_authority_rejects_digest_valid_relookup_completion(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
) -> None:
    _, repository = release_authority_runtime
    candidate = _candidate("synthetic-history-relookup-completion", seed=20)
    repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="2" * 64,
    )
    repository.approve_profile_release(
        str(candidate.release_sha256),
        authenticated_principal="phase3-approver",
    )
    committed = repository.activate_profile_release(
        str(candidate.release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce="e" * 64,
    ).receipt
    forged = ProfileReleaseTransitionReceipt(
        **{
            **committed.model_dump(exclude={"completion", "receipt_sha256"}, mode="json"),
            "completion": ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
        }
    )
    engine = create_engine(
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]),
        future=True,
    )
    try:
        with engine.connect() as connection:
            connection.execute(
                text("ALTER TABLE dev_eval.profile_release_transition_events DISABLE TRIGGER USER")
            )
            connection.execute(
                text(
                    "UPDATE dev_eval.profile_release_transition_events SET "
                    "receipt_sha256 = :forged_receipt, payload = CAST(:payload AS jsonb) "
                    "WHERE receipt_sha256 = :committed_receipt"
                ),
                {
                    "forged_receipt": forged.receipt_sha256,
                    "payload": forged.model_dump_json(),
                    "committed_receipt": committed.receipt_sha256,
                },
            )
            with pytest.raises(
                ValueError,
                match="persisted transition completion is not authoritative",
            ):
                MIGRATION._validated_transition_history(connection)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "forgery",
    ["missing_approval", "wrong_approver", "builder_as_approver"],
)
def test_duplicate_authority_rejects_digest_valid_forged_activation_authority(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
    forgery: str,
) -> None:
    _, repository = release_authority_runtime
    candidate = _candidate(f"synthetic-history-forged-{forgery}", seed=30)
    repository.build_profile_release(
        candidate,
        authenticated_principal="phase3-builder",
        reconciliation_nonce="3" * 64,
    )
    approval = repository.approve_profile_release(
        str(candidate.release_sha256),
        authenticated_principal="phase3-approver",
    )
    committed = repository.activate_profile_release(
        str(candidate.release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce="f" * 64,
    ).receipt
    engine = create_engine(
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]),
        future=True,
    )
    try:
        with engine.connect() as connection:
            connection.execute(
                text("ALTER TABLE dev_eval.profile_release_approvals DISABLE TRIGGER USER")
            )
            if forgery == "missing_approval":
                connection.execute(
                    text(
                        "DELETE FROM dev_eval.profile_release_approvals "
                        "WHERE release_sha256 = :release"
                    ),
                    {"release": candidate.release_sha256},
                )
            elif forgery == "builder_as_approver":
                independence_constraint = connection.execute(
                    text(
                        "SELECT conname FROM pg_constraint WHERE conrelid = "
                        "'dev_eval.profile_release_approvals'::regclass AND "
                        "pg_get_constraintdef(oid) LIKE "
                        "'%builder_principal <> approver_principal%'"
                    )
                ).scalar_one()
                connection.execute(
                    text(
                        "ALTER TABLE dev_eval.profile_release_approvals DROP CONSTRAINT "
                        f'"{independence_constraint}"'
                    )
                )
                forged_payload = approval.model_dump(
                    exclude={"approval_sha256", "approver_principal"}, mode="json"
                )
                forged_payload["approver_principal"] = "phase3-builder"
                forged_payload["approval_sha256"] = canonical_sha256(forged_payload)
                connection.execute(
                    text(
                        "UPDATE dev_eval.profile_release_approvals SET "
                        "approval_sha256 = :approval, approver_principal = :approver, "
                        "payload = CAST(:payload AS jsonb) WHERE release_sha256 = :release"
                    ),
                    {
                        "approval": forged_payload["approval_sha256"],
                        "approver": "phase3-builder",
                        "payload": json.dumps(forged_payload, separators=(",", ":")),
                        "release": candidate.release_sha256,
                    },
                )
            else:
                forged = ProfileReleaseTransitionReceipt(
                    **{
                        **committed.model_dump(
                            exclude={"approver_principal", "receipt_sha256"},
                            mode="json",
                        ),
                        "approver_principal": "phase3-other-approver",
                    }
                )
                for relation in (
                    "profile_release_transition_events",
                    "profile_release_lifecycle_heads",
                    "profile_release_active_pointer",
                ):
                    connection.execute(
                        text(f"ALTER TABLE dev_eval.{relation} DISABLE TRIGGER USER")
                    )
                connection.execute(
                    text(
                        "UPDATE dev_eval.profile_release_transition_events SET "
                        "receipt_sha256 = :forged_receipt, "
                        "approver_principal = :approver, payload = CAST(:payload AS jsonb) "
                        "WHERE receipt_sha256 = :committed_receipt"
                    ),
                    {
                        "forged_receipt": forged.receipt_sha256,
                        "approver": forged.approver_principal,
                        "payload": forged.model_dump_json(),
                        "committed_receipt": committed.receipt_sha256,
                    },
                )
                for relation, column in (
                    ("profile_release_lifecycle_heads", "head_receipt_sha256"),
                    ("profile_release_active_pointer", "receipt_sha256"),
                ):
                    connection.execute(
                        text(
                            f"UPDATE dev_eval.{relation} SET {column} = :forged "
                            f"WHERE {column} = :committed"
                        ),
                        {
                            "forged": forged.receipt_sha256,
                            "committed": committed.receipt_sha256,
                        },
                    )
            with pytest.raises((ValidationError, ValueError)):
                MIGRATION._validated_transition_history(connection)
    finally:
        engine.dispose()


def test_duplicate_authority_rejects_digest_valid_incompatible_rollback_lineage(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
) -> None:
    _, repository = release_authority_runtime
    target = _candidate("synthetic-history-rollback-target", seed=40)
    current_payload = _candidate("synthetic-history-rollback-current", seed=41).model_dump(
        mode="json"
    )
    current_payload["dev_lineage_sha256"] = "d" * 64
    current_payload["release_sha256"] = None
    current = ProfileReleaseCandidate.model_validate(current_payload)
    for index, candidate in enumerate((target, current), start=4):
        repository.build_profile_release(
            candidate,
            authenticated_principal="phase3-builder",
            reconciliation_nonce=str(index) * 64,
        )
        repository.approve_profile_release(
            str(candidate.release_sha256),
            authenticated_principal="phase3-approver",
        )
    repository.activate_profile_release(
        str(target.release_sha256),
        expected_current=None,
        authenticated_principal="phase3-approver",
        nonce="6" * 64,
    )
    repository.activate_profile_release(
        str(current.release_sha256),
        expected_current=str(target.release_sha256),
        authenticated_principal="phase3-approver",
        nonce="7" * 64,
    )
    reason = "digest-valid incompatible lineage rollback"
    forged = ProfileReleaseTransitionReceipt(
        action="ROLLBACK",
        release_sha256=str(target.release_sha256),
        previous_release_sha256=str(current.release_sha256),
        expected_current_sha256=str(current.release_sha256),
        approver_principal="phase3-approver",
        nonce_sha256="8" * 64,
        reason=reason,
        completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
    )
    engine = create_engine(
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]),
        future=True,
    )
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "INSERT INTO dev_eval.profile_release_transition_events ("
                    "receipt_sha256, action, release_sha256, previous_release_sha256, "
                    "expected_current_sha256, approver_principal, nonce_sha256, payload) "
                    "VALUES (:receipt, 'ROLLBACK', :target, :current, :current, "
                    ":approver, :nonce, CAST(:payload AS jsonb))"
                ),
                {
                    "receipt": forged.receipt_sha256,
                    "target": target.release_sha256,
                    "current": current.release_sha256,
                    "approver": forged.approver_principal,
                    "nonce": forged.nonce_sha256,
                    "payload": forged.model_dump_json(),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO dev_eval.profile_release_rollback_receipts ("
                    "receipt_sha256, transition_receipt_sha256, release_sha256, "
                    "approver_principal, reason, reason_sha256, payload) VALUES ("
                    ":receipt, :receipt, :target, :approver, :reason, :reason_sha256, "
                    "CAST(:payload AS jsonb))"
                ),
                {
                    "receipt": forged.receipt_sha256,
                    "target": target.release_sha256,
                    "approver": forged.approver_principal,
                    "reason": reason,
                    "reason_sha256": hashlib.sha256(reason.encode()).hexdigest(),
                    "payload": forged.model_dump_json(),
                },
            )
            for relation in (
                "profile_release_lifecycle_heads",
                "profile_release_active_pointer",
            ):
                connection.execute(text(f"ALTER TABLE dev_eval.{relation} DISABLE TRIGGER USER"))
            connection.execute(
                text(
                    "UPDATE dev_eval.profile_release_lifecycle_heads SET "
                    "state = CASE WHEN release_sha256 = :target THEN 'ACTIVE' "
                    "ELSE 'APPROVED_INACTIVE' END, head_receipt_sha256 = :receipt "
                    "WHERE release_sha256 IN (:target, :current)"
                ),
                {
                    "target": target.release_sha256,
                    "current": current.release_sha256,
                    "receipt": forged.receipt_sha256,
                },
            )
            connection.execute(
                text(
                    "UPDATE dev_eval.profile_release_active_pointer SET "
                    "release_sha256 = :target, receipt_sha256 = :receipt "
                    "WHERE slot = 'DEV'"
                ),
                {
                    "target": target.release_sha256,
                    "receipt": forged.receipt_sha256,
                },
            )
            with pytest.raises(
                ValueError, match="rollback target has incompatible immutable lineage"
            ):
                MIGRATION._validated_transition_history(connection)
    finally:
        engine.dispose()


def _wait_for_downgrade_lock(postgres_harness: object, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with postgres_harness.connect("admin", autocommit=True) as connection:
            waiting = connection.execute(
                "SELECT 1 FROM pg_locks locks "
                "WHERE locks.relation = "
                "'dev_eval.profile_release_build_receipts'::regclass "
                "AND locks.mode = 'AccessExclusiveLock' AND NOT locks.granted"
            ).fetchone()
        if waiting is not None:
            return
        time.sleep(0.02)
    raise AssertionError("downgrade did not reach the writer-blocking lock")


def test_downgrade_refuses_and_preserves_reservation_only_authority(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
) -> None:
    config, _ = release_authority_runtime
    reservation = (
        "phase3-builder",
        "9" * 64,
        "a" * 64,
        None,
    )
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.reserve_profile_release_build_nonce_v1(%s, %s, %s, %s)",
            reservation,
        )
    with pytest.raises(
        RuntimeError,
        match="intentionally irreversible after protected state exists",
    ):
        command.downgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert (
            connection.execute(
                "SELECT builder_principal, nonce_sha256, candidate_sha256, "
                "draft_ref_sha256 FROM dev_eval.profile_release_build_nonce_reservations"
            ).fetchone()
            == reservation
        )
        connection.execute("TRUNCATE dev_eval.profile_release_build_nonce_reservations CASCADE")
    command.downgrade(config, "0009_phase3_profile_pin_privileges")
    command.upgrade(config, "head")


def test_downgrade_zero_check_is_closed_against_two_session_writer_race(
    postgres_harness: object,
    release_authority_runtime: tuple[Config, EvaluationRepository],
) -> None:
    config, _ = release_authority_runtime
    reservation = (
        "phase3-builder",
        f"{901:064x}",
        f"{902:064x}",
        f"{903:064x}",
    )
    blocker = postgres_harness.connect("admin")
    blocker.execute("LOCK TABLE dev_eval.profile_release_build_receipts IN ACCESS SHARE MODE")
    started = threading.Event()

    def downgrade() -> BaseException | None:
        started.set()
        try:
            command.downgrade(config, "0009_phase3_profile_pin_privileges")
        except BaseException as error:  # the protected writer may win the queue
            return error
        return None

    def protected_writer() -> BaseException | None:
        try:
            with postgres_harness.connect("dev") as connection:
                assert connection.execute("SELECT current_user").fetchone() == (
                    postgres_harness.role_names["dev"],
                )
                connection.execute(
                    "SELECT dev_eval.reserve_profile_release_build_nonce_v1(%s, %s, %s, %s)",
                    reservation,
                )
                connection.commit()
        except BaseException as error:
            return error
        return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        downgrade_future = pool.submit(downgrade)
        assert started.wait(timeout=2)
        _wait_for_downgrade_lock(postgres_harness)
        writer_future = pool.submit(protected_writer)
        blocker.commit()
        blocker.close()
        downgrade_error = downgrade_future.result(timeout=10)
        writer_error = writer_future.result(timeout=10)

    if downgrade_error is None:
        assert isinstance(writer_error, psycopg.Error)
        removal_error = str(writer_error)
        assert writer_error.sqlstate in {"40P01", "42P01", "42883"} or (
            writer_error.sqlstate == "XX000"
            and "could not open relation with OID" in removal_error
            and "reserve_profile_release_build_nonce_v1" in removal_error
        )
    else:
        assert isinstance(downgrade_error, RuntimeError)
        assert writer_error is None
        with postgres_harness.connect("admin", autocommit=True) as connection:
            assert (
                connection.execute(
                    "SELECT builder_principal, nonce_sha256, candidate_sha256, "
                    "draft_ref_sha256 FROM "
                    "dev_eval.profile_release_build_nonce_reservations"
                ).fetchone()
                == reservation
            )
            connection.execute("TRUNCATE dev_eval.profile_release_build_nonce_reservations CASCADE")
        command.downgrade(config, "0009_phase3_profile_pin_privileges")
    command.upgrade(config, "head")
