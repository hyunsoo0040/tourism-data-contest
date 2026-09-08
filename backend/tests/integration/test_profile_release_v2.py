"""PostgreSQL persistence and authority contracts for profile-release v2."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

import psycopg
import pytest
from alembic import command
from alembic.script import ScriptDirectory
from psycopg import sql
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from itda.api.dependencies import _evaluation_repository_for_dsn
from itda.contracts.profile_release import (
    ProfileReleaseCandidate,
    ProfileReleaseCompletion,
    ProfileReleaseReplayError,
    ProfileReleaseRetryableAbortError,
)
from itda.contracts.profile_release_authority import (
    ProfileReleaseAuthorityPathsV2,
    ProfileReleaseBuildAuthorityResolution,
    resolve_authoritative_profile_release_build_authority_v2,
)
from itda.contracts.profile_release_v2 import (
    ProfileReleaseCandidateV2,
    ProfileReleaseTransitionProofV2,
    build_exact_predecessor_transition_proof,
)
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from tests.contract.test_profile_release_authority_v2 import (
    _authority_payloads,
    _predecessor_payload,
    _request,
    _resolve,
    _self_hash,
    _write_bundle,
)
from tests.integration.test_profile_release import (
    PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
    PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
    ProfileReleaseConnections,
    _assert_single_head_contains_revision,
    _clear_profile_release_state_for_downgrade,
    _migration_config,
    register_profile_release_build_authority,
)
from tests.integration.test_profile_release import (
    profile_release_build_authority as _profile_release_build_authority,
)
from tests.integration.test_profile_release import (
    profile_release_connections as _profile_release_connections_fixture,  # noqa: F401
)


@pytest.fixture
def profile_release_connections(request: pytest.FixtureRequest) -> ProfileReleaseConnections:
    """Expose the imported Phase 3 capability fixture under its public name."""

    return cast(
        ProfileReleaseConnections,
        request.getfixturevalue("_profile_release_connections_fixture"),
    )


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _profile_release_write_state(postgres_harness: object) -> tuple[int, int, int, int, int]:
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        return cast(
            tuple[int, int, int, int, int],
            connection.execute(
                "SELECT (SELECT count(*) FROM dev_eval.profile_releases), "
                "(SELECT count(*) FROM dev_eval.profile_release_lifecycle_heads), "
                "(SELECT count(*) FROM dev_eval.profile_release_fixed_root_authorities_v1), "
                "(SELECT count(*) FROM dev_eval.profile_release_build_authorizations_v1), "
                "(SELECT count(*) FROM dev_eval.profile_release_build_capabilities_v1)"
            ).fetchone(),
        )


def _repository(
    dsn: str,
    authority_dsn: str,
) -> tuple[EvaluationRepository, Any]:
    engine = create_database_engine(dsn)
    authority_engine = create_database_engine(authority_dsn)
    return (
        EvaluationRepository(
            create_session_factory(engine),
            authority_connection_factory=create_session_factory(authority_engine),
        ),
        engine,
    )


class _SyntheticSerializationFailure(RuntimeError):
    sqlstate = "40001"


class _AbortAfterPreflightSession:
    def __init__(self, session: Session, *, abort_connection: bool) -> None:
        self._session = session
        self._abort_connection = abort_connection

    def __enter__(self) -> _AbortAfterPreflightSession:
        self._session.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        self._session.__exit__(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    def connection(self, **kwargs: object) -> Any:
        if self._abort_connection:
            raise DBAPIError(
                "BEGIN",
                {},
                _SyntheticSerializationFailure("synthetic post-issuance serialization abort"),
                False,
            )
        return self._session.connection(**kwargs)


class _AbortAfterPreflightFactory:
    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.calls = 0
        self.aborts = 0

    def __call__(self) -> _AbortAfterPreflightSession:
        self.calls += 1
        abort_connection = 2 <= self.calls <= 4
        if abort_connection:
            self.aborts += 1
        return _AbortAfterPreflightSession(
            self._delegate(),
            abort_connection=abort_connection,
        )


def _repository_with_post_issuance_aborts(
    repository: EvaluationRepository,
) -> tuple[EvaluationRepository, _AbortAfterPreflightFactory]:
    aborting_factory = _AbortAfterPreflightFactory(repository._factory)
    return (
        EvaluationRepository(
            aborting_factory,  # type: ignore[arg-type]
            authority_connection_factory=repository._authority_connection_factory,
        ),
        aborting_factory,
    )


def _profile_build_authority_counts(
    postgres_harness: object,
    *,
    release_sha256: str,
) -> tuple[tuple[object, ...], tuple[object, ...], tuple[object, ...]]:
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        authorization = connection.execute(
            "SELECT count(*), count(*) FILTER (WHERE consumed_at IS NOT NULL) "
            "FROM dev_eval.profile_release_build_authorizations_v1 "
            "WHERE candidate_sha256 = %s",
            (release_sha256,),
        ).fetchone()
        capability = connection.execute(
            "SELECT count(*), "
            "count(*) FILTER (WHERE consumed_at IS NOT NULL), "
            "count(*) FILTER (WHERE consumed_at IS NULL AND retired_at IS NULL) "
            "FROM dev_eval.profile_release_build_capabilities_v1 "
            "WHERE candidate_sha256 = %s",
            (release_sha256,),
        ).fetchone()
        release = connection.execute(
            "SELECT "
            "(SELECT count(*) FROM dev_eval.profile_releases WHERE release_sha256 = %s), "
            "(SELECT count(*) FROM dev_eval.profile_release_lifecycle_heads "
            " WHERE release_sha256 = %s), "
            "(SELECT count(*) FROM dev_eval.profile_release_build_receipts "
            " WHERE release_sha256 = %s)",
            (release_sha256, release_sha256, release_sha256),
        ).fetchone()
    assert authorization is not None and capability is not None and release is not None
    return authorization, capability, release


def _v1_candidate(label: str) -> ProfileReleaseCandidate:
    payload = _predecessor_payload()[0]
    payload["release_id"] = f"synthetic-{label}"
    payload["release_sha256"] = None
    return ProfileReleaseCandidate.model_validate(payload)


def _build_candidate(
    builder_dsn: str,
    authority_dsn: str,
    candidate: ProfileReleaseCandidate | ProfileReleaseCandidateV2,
    *,
    nonce: str,
) -> object:
    repository, engine = _repository(builder_dsn, authority_dsn)
    try:
        return repository.build_profile_release(
            _profile_release_build_authority(repository, candidate),
            authenticated_principal=candidate.builder_principal,
            reconciliation_nonce=nonce,
        )
    finally:
        engine.dispose()


def _seed_active_predecessor(
    admin_dsn: str,
    builder_dsn: str,
    authority_dsn: str,
    *,
    build_nonce: str = "v2-predecessor-build",
    activate_nonce: str = "v2-predecessor-activate",
) -> tuple[EvaluationRepository, Any, ProfileReleaseCandidate]:
    candidate = ProfileReleaseCandidate.model_validate(_predecessor_payload()[0])
    _build_candidate(
        builder_dsn,
        authority_dsn,
        candidate,
        nonce=_nonce(build_nonce),
    )
    repository, engine = _repository(admin_dsn, authority_dsn)
    repository.approve_profile_release(
        cast(str, candidate.release_sha256),
        authenticated_principal="synthetic-v2-approver",
    )
    repository.activate_profile_release(
        cast(str, candidate.release_sha256),
        expected_current=None,
        authenticated_principal="synthetic-v2-approver",
        nonce=_nonce(activate_nonce),
    )
    return repository, engine, candidate


def _resolve_for_active_predecessor(
    root: Path,
    repository: EvaluationRepository,
) -> ProfileReleaseCandidateV2:
    payloads = _authority_payloads()
    pointer = repository.get_profile_release_active_pointer()
    payloads["predecessor"]["lifecycle_receipt_sha256"] = pointer.receipt_sha256
    _self_hash(payloads["predecessor"])
    return cast(ProfileReleaseCandidateV2, _resolve(root, payloads))


def _resolve_authority_for_active_predecessor(
    root: Path,
    repository: EvaluationRepository,
) -> ProfileReleaseBuildAuthorityResolution:
    payloads = _authority_payloads()
    pointer = repository.get_profile_release_active_pointer()
    payloads["predecessor"]["lifecycle_receipt_sha256"] = pointer.receipt_sha256
    _self_hash(payloads["predecessor"])
    names = _write_bundle(root, payloads)
    return resolve_authoritative_profile_release_build_authority_v2(
        request=_request(payloads),
        paths=ProfileReleaseAuthorityPathsV2(root=root, **names),
        authority_registry_id=uuid5(NAMESPACE_URL, f"fixed-v2:{root}"),
        builder_database_principal=(repository.profile_release_builder_database_principal()),
    )


@pytest.fixture(autouse=True)
def clean_profile_release_v2_state(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> Iterator[None]:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    command.upgrade(config, "head")
    _clear_profile_release_state_for_downgrade(postgres_harness)
    try:
        yield
    finally:
        command.upgrade(config, "head")
        _clear_profile_release_state_for_downgrade(postgres_harness)


def test_0013_upgrades_from_0012_preserves_v1_and_persists_exact_successor(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    script = ScriptDirectory.from_config(config)
    _assert_single_head_contains_revision(
        script,
        "0014_phase4_profile_release_write_boundary",
    )
    assert script.get_revision("0013_phase4_profile_releases").down_revision == (
        "0012_phase3_profile_pin_provenance"
    )

    command.downgrade(config, "0012_phase3_profile_pin_provenance")
    predecessor = ProfileReleaseCandidate.model_validate(_predecessor_payload()[0])
    predecessor_receipt_sha256 = "9" * 64
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "INSERT INTO dev_eval.profile_releases (release_sha256, release_id, "
            "builder_principal, canonical_lineage_sha256, dev_lineage_sha256, "
            "profile_schema_sha256, payload) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                predecessor.release_sha256,
                predecessor.release_id,
                predecessor.builder_principal,
                predecessor.canonical_lineage_sha256,
                predecessor.dev_lineage_sha256,
                predecessor.profile_schema_sha256,
                psycopg.types.json.Jsonb(predecessor.model_dump(mode="json")),
            ),
        )
        connection.execute(
            "INSERT INTO dev_eval.profile_release_lifecycle_heads VALUES (%s, 'ACTIVE', %s)",
            (predecessor.release_sha256, predecessor_receipt_sha256),
        )
        connection.execute(
            "INSERT INTO dev_eval.profile_release_active_pointer VALUES ('DEV', %s, %s)",
            (predecessor.release_sha256, predecessor_receipt_sha256),
        )
    engine: Any | None = None
    try:
        with postgres_harness.connect("admin") as connection:
            before = connection.execute(
                "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = %s",
                (predecessor.release_sha256,),
            ).fetchone()
        assert before == (predecessor.model_dump(mode="json"),)

        command.upgrade(config, "head")
        repository, engine = _repository(
            profile_release_connections.dsns["builder"],
            profile_release_connections.dsns["authority_service"],
        )
        payloads = _authority_payloads()
        payloads["predecessor"]["lifecycle_receipt_sha256"] = predecessor_receipt_sha256
        _self_hash(payloads["predecessor"])
        successor = cast(ProfileReleaseCandidateV2, _resolve(tmp_path, payloads))
        outcome = repository.build_profile_release(
            _profile_release_build_authority(repository, successor),
            authenticated_principal=successor.builder_principal,
            reconciliation_nonce=_nonce("v2-successor-build"),
        )
        assert outcome.release_sha256 == successor.release_sha256
        expected_proof = build_exact_predecessor_transition_proof(
            successor=successor,
            predecessor=predecessor,
        )

        with postgres_harness.connect("admin") as connection:
            preserved = connection.execute(
                "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = %s",
                (predecessor.release_sha256,),
            ).fetchone()
            stored = connection.execute(
                "SELECT canonical_lineage_sha256, dev_lineage_sha256, "
                "profile_schema_sha256, payload FROM dev_eval.profile_releases "
                "WHERE release_sha256 = %s",
                (successor.release_sha256,),
            ).fetchone()
            proof_row = connection.execute(
                "SELECT predecessor_release_sha256, proof_sha256, payload FROM "
                "dev_eval.profile_release_v2_transition_proofs "
                "WHERE successor_release_sha256 = %s",
                (successor.release_sha256,),
            ).fetchone()
            validators = connection.execute(
                "SELECT "
                "dev_eval.validate_profile_release_candidate_payload_v1(%s::jsonb), "
                "dev_eval.validate_profile_release_candidate_payload_v2(%s::jsonb), "
                "dev_eval.validate_profile_release_candidate_payload_dispatch_v1(%s::jsonb)",
                (
                    predecessor.model_dump_json(),
                    successor.model_dump_json(),
                    successor.model_dump_json(),
                ),
            ).fetchone()

        assert preserved == before
        assert stored == (
            successor.lineage.canonical_lineage_sha256,
            successor.lineage.dev_lineage_sha256,
            successor.lineage.profile_schema_sha256,
            successor.model_dump(mode="json"),
        )
        assert proof_row == (
            predecessor.release_sha256,
            expected_proof.proof_sha256,
            expected_proof.model_dump(mode="json"),
        )
        assert ProfileReleaseTransitionProofV2.model_validate(proof_row[2]) == expected_proof
        assert validators == (True, True, True)
    finally:
        if engine is not None:
            engine.dispose()


def test_0014_write_boundary_has_exact_roles_owners_and_least_privilege(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    script = ScriptDirectory.from_config(config)
    _assert_single_head_contains_revision(
        script,
        "0014_phase4_profile_release_write_boundary",
    )
    assert (
        script.get_revision("0014_phase4_profile_release_write_boundary").down_revision
        == "0013_phase4_profile_releases"
    )

    builder = profile_release_connections.role_names["builder"]
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s",
            (PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,),
        ).fetchone() == (False, False, False, False, False, False, False)
        assert connection.execute(
            "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, "
            "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s",
            (PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,),
        ).fetchone() == (True, False, False, False, False, False, False)
        assert connection.execute(
            "SELECT pg_has_role(%s, %s, 'MEMBER'), pg_has_role(%s, %s, 'MEMBER'), "
            "pg_has_role(%s, %s, 'MEMBER'), pg_has_role(%s, %s, 'MEMBER')",
            (
                builder,
                PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
                PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
                builder,
                builder,
                PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
                PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
                builder,
            ),
        ).fetchone() == (False, False, False, False)
        assert connection.execute(
            "SELECT c.relname, c.relowner::regrole::text FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'dev_eval' "
            "AND c.relname IN ('profile_release_build_capabilities_v1', "
            "'profile_release_fixed_root_authorities_v1') ORDER BY c.relname"
        ).fetchall() == [
            ("profile_release_build_capabilities_v1", PROFILE_RELEASE_WRITE_AUTHORITY_ROLE),
            ("profile_release_fixed_root_authorities_v1", PROFILE_RELEASE_WRITE_AUTHORITY_ROLE),
        ]
        function_rows = connection.execute(
            "SELECT p.oid::regprocedure::text, p.proowner::regrole::text, "
            "p.prosecdef, p.proconfig "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'dev_eval' AND p.proname IN ("
            "'issue_profile_release_build_capability_v1', "
            "'consume_profile_release_build_capability_v1') ORDER BY 1"
        ).fetchall()
        assert function_rows == [
            (
                "dev_eval.consume_profile_release_build_capability_v1(uuid)",
                PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
                True,
                ["search_path=pg_catalog, pg_temp"],
            ),
            (
                "dev_eval.issue_profile_release_build_capability_v1(jsonb,text,text)",
                PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
                False,
                ["search_path=pg_catalog, pg_temp"],
            ),
        ]

        before = _profile_release_write_state(postgres_harness)
        with pytest.raises(
            psycopg.errors.FeatureNotSupported,
            match="legacy capability issuer retired",
        ):
            connection.execute(
                "SELECT * FROM dev_eval.issue_profile_release_build_capability_v1(%s,%s,%s)",
                (psycopg.types.json.Jsonb({}), builder, None),
            )
        assert _profile_release_write_state(postgres_harness) == before

    with profile_release_connections.connect(
        "authority_service", autocommit=True
    ) as authority_connection:
        assert authority_connection.execute(
            "SELECT has_table_privilege(session_user, "
            "'dev_eval.profile_release_fixed_root_authorities_v1', 'SELECT'), "
            "has_table_privilege(session_user, "
            "'dev_eval.profile_release_fixed_root_authorities_v1', 'INSERT'), "
            "has_table_privilege(session_user, "
            "'dev_eval.profile_release_fixed_root_authorities_v1', 'UPDATE'), "
            "has_table_privilege(session_user, "
            "'dev_eval.profile_release_fixed_root_authorities_v1', 'DELETE')"
        ).fetchone() == (False, False, False, False)

    with profile_release_connections.connect("builder", autocommit=True) as builder_connection:
        for relation in ("profile_releases", "profile_release_lifecycle_heads"):
            assert builder_connection.execute(
                "SELECT has_table_privilege(session_user, %s, 'INSERT'), "
                "has_table_privilege(session_user, %s, 'UPDATE'), "
                "has_table_privilege(session_user, %s, 'DELETE')",
                (f"dev_eval.{relation}",) * 3,
            ).fetchone() == (False, False, False)
        assert builder_connection.execute(
            "SELECT has_function_privilege(session_user, "
            "'dev_eval.consume_profile_release_build_capability_v1(uuid)', 'EXECUTE'), "
            "has_function_privilege(session_user, "
            "'dev_eval.issue_profile_release_build_capability_v1(jsonb,text,text)', "
            "'EXECUTE'), has_table_privilege(session_user, "
            "'dev_eval.profile_release_build_capabilities_v1', 'SELECT')"
        ).fetchone() == (True, False, False)


def test_capability_blocks_coherent_valid_forgery_guessing_and_replay(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    seed_repository, seed_engine, _ = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="v2-capability-predecessor-build",
        activate_nonce="v2-capability-predecessor-activate",
    )
    del seed_repository
    repository, engine = _repository(
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
    )
    resolution = _resolve_authority_for_active_predecessor(tmp_path, repository)
    successor = cast(ProfileReleaseCandidateV2, resolution.candidate)
    alternate = _successor_variant(successor, release_id="coherent-unresolved-alternate")
    candidate_json = psycopg.types.json.Jsonb(successor.model_dump(mode="json"))

    def lifecycle_counts() -> tuple[int, int]:
        with postgres_harness.connect("admin", autocommit=True) as connection:
            return cast(
                tuple[int, int],
                connection.execute(
                    "SELECT (SELECT count(*) FROM dev_eval.profile_releases), "
                    "(SELECT count(*) FROM dev_eval.profile_release_lifecycle_heads)"
                ).fetchone(),
            )

    before = lifecycle_counts()
    try:
        with postgres_harness.connect("admin", autocommit=True) as admin:
            register_profile_release_build_authority(admin, resolution)
        registered_state = _profile_release_write_state(postgres_harness)
        with profile_release_connections.connect("builder", autocommit=True) as builder:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                builder.execute(
                    "SELECT dev_eval.issue_profile_release_build_capability_v1(%s,%s,%s)",
                    (
                        candidate_json,
                        resolution.builder_database_principal,
                        successor.lineage.predecessor_release_sha256,
                    ),
                )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                builder.execute(
                    "INSERT INTO dev_eval.profile_releases (release_sha256, release_id, "
                    "builder_principal, canonical_lineage_sha256, dev_lineage_sha256, "
                    "profile_schema_sha256, payload) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (
                        successor.release_sha256,
                        successor.release_id,
                        successor.builder_principal,
                        successor.lineage.canonical_lineage_sha256,
                        successor.lineage.dev_lineage_sha256,
                        successor.lineage.profile_schema_sha256,
                        candidate_json,
                    ),
                )
            with pytest.raises(psycopg.errors.CheckViolation):
                builder.execute(
                    "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                    ("00000000-0000-0000-0000-000000000001",),
                )
        assert lifecycle_counts() == before

        forged = resolution.model_dump(mode="json")
        forged["candidate"] = alternate.model_dump(mode="json")
        forged["candidate_sha256"] = alternate.release_sha256
        forged["resolution_sha256"] = canonical_sha256(
            {key: value for key, value in forged.items() if key != "resolution_sha256"}
        )
        with profile_release_connections.connect("authority_service", autocommit=True) as authority:
            with pytest.raises(psycopg.errors.CheckViolation):
                authority.execute(
                    "SELECT * FROM dev_eval.record_profile_release_build_authorization_v1(%s)",
                    (psycopg.types.json.Jsonb(forged),),
                )
            assert _profile_release_write_state(postgres_harness) == registered_state
            authorization_id = authority.execute(
                "SELECT authorization_id FROM "
                "dev_eval.record_profile_release_build_authorization_v1(%s)",
                (psycopg.types.json.Jsonb(resolution.model_dump(mode="json")),),
            ).fetchone()[0]
            capability_id = authority.execute(
                "SELECT capability_id FROM dev_eval.issue_profile_release_build_capability_v2(%s)",
                (authorization_id,),
            ).fetchone()[0]

        with profile_release_connections.connect("builder", autocommit=True) as builder:
            assert builder.execute(
                "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                (capability_id,),
            ).fetchone() == (successor.release_sha256,)
            with pytest.raises(psycopg.errors.CheckViolation):
                builder.execute(
                    "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                    (capability_id,),
                )
    finally:
        engine.dispose()
        seed_engine.dispose()

    with profile_release_connections.connect(
        "authority_service", autocommit=True
    ) as authority_connection:
        assert authority_connection.execute(
            "SELECT has_function_privilege(session_user, "
            "'dev_eval.issue_profile_release_build_capability_v1(jsonb,text,text)', "
            "'EXECUTE'), has_function_privilege(session_user, "
            "'dev_eval.record_profile_release_build_authorization_v1(jsonb)', "
            "'EXECUTE'), has_function_privilege(session_user, "
            "'dev_eval.issue_profile_release_build_capability_v2(uuid)', "
            "'EXECUTE'), has_function_privilege(session_user, "
            "'dev_eval.consume_profile_release_build_capability_v1(uuid)', 'EXECUTE'), "
            "has_table_privilege(session_user, "
            "'dev_eval.profile_release_build_capabilities_v1', 'SELECT')"
        ).fetchone() == (False, True, True, False, False)


def test_build_retry_reuses_or_rotates_post_issuance_capability_atomically(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine = _repository(
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
    )
    try:
        reusable = _v1_candidate("post-issuance-retry")
        reusable_resolution = _profile_release_build_authority(repository, reusable)
        aborting, aborting_factory = _repository_with_post_issuance_aborts(repository)
        with pytest.raises(ProfileReleaseRetryableAbortError) as retryable:
            aborting.build_profile_release(
                reusable_resolution,
                authenticated_principal=reusable.builder_principal,
                reconciliation_nonce=_nonce("post-issuance-retry"),
            )
        assert retryable.value.action == "BUILD"
        assert aborting_factory.aborts == 3
        assert _profile_build_authority_counts(
            postgres_harness,
            release_sha256=cast(str, reusable.release_sha256),
        ) == ((1, 0), (1, 0, 1), (0, 0, 0))

        created = repository.build_profile_release(
            reusable_resolution,
            authenticated_principal=reusable.builder_principal,
            reconciliation_nonce=_nonce("post-issuance-retry"),
        )
        replayed = repository.build_profile_release(
            reusable_resolution,
            authenticated_principal=reusable.builder_principal,
            reconciliation_nonce=_nonce("post-issuance-retry"),
        )
        assert created.completion is ProfileReleaseCompletion.MUTATION_COMMITTED
        assert replayed.completion is ProfileReleaseCompletion.RELOOKUP_CONFIRMED
        assert replayed.receipt_sha256 == created.receipt_sha256
        assert _profile_build_authority_counts(
            postgres_harness,
            release_sha256=cast(str, reusable.release_sha256),
        ) == ((1, 1), (1, 1, 0), (1, 1, 1))

        expiring = _v1_candidate("post-issuance-expiry")
        expiring_resolution = _profile_release_build_authority(repository, expiring)
        aborting_expired, expired_factory = _repository_with_post_issuance_aborts(repository)
        with pytest.raises(ProfileReleaseRetryableAbortError):
            aborting_expired.build_profile_release(
                expiring_resolution,
                authenticated_principal=expiring.builder_principal,
                reconciliation_nonce=_nonce("post-issuance-expiry"),
            )
        assert expired_factory.aborts == 3
        with postgres_harness.connect("admin", autocommit=True) as connection:
            connection.execute(
                "UPDATE dev_eval.profile_release_build_capabilities_v1 "
                "SET issued_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes', "
                "expires_at = CURRENT_TIMESTAMP - INTERVAL '5 minutes' "
                "WHERE candidate_sha256 = %s "
                "AND consumed_at IS NULL AND retired_at IS NULL",
                (expiring.release_sha256,),
            )
        repository.build_profile_release(
            expiring_resolution,
            authenticated_principal=expiring.builder_principal,
            reconciliation_nonce=_nonce("post-issuance-expiry"),
        )
        assert _profile_build_authority_counts(
            postgres_harness,
            release_sha256=cast(str, expiring.release_sha256),
        ) == ((1, 1), (2, 1, 0), (1, 1, 1))
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("unsafe_flag", "restore_flag"),
    [
        ("SUPERUSER", "NOSUPERUSER"),
        ("CREATEDB", "NOCREATEDB"),
        ("CREATEROLE", "NOCREATEROLE"),
        ("REPLICATION", "NOREPLICATION"),
        ("BYPASSRLS", "NOBYPASSRLS"),
        ("INHERIT", "NOINHERIT"),
        ("NOLOGIN", "LOGIN"),
    ],
)
def test_authorization_rejects_every_unsafe_builder_role_flag(
    unsafe_flag: str,
    restore_flag: str,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine = _repository(
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
    )
    candidate = ProfileReleaseCandidate.model_validate(_predecessor_payload()[0])
    resolution = _profile_release_build_authority(repository, candidate)
    builder_role = profile_release_connections.role_names["builder"]
    before = _profile_release_write_state(postgres_harness)
    try:
        with postgres_harness.connect("admin", autocommit=True) as admin:
            admin.execute(
                sql.SQL("ALTER ROLE {} {}").format(
                    sql.Identifier(builder_role),
                    sql.SQL(unsafe_flag),
                )
            )
        with (
            profile_release_connections.connect("authority_service", autocommit=True) as authority,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            authority.execute(
                "SELECT * FROM dev_eval.record_profile_release_build_authorization_v1(%s)",
                (psycopg.types.json.Jsonb(resolution.model_dump(mode="json")),),
            )
        assert _profile_release_write_state(postgres_harness) == before
    finally:
        with postgres_harness.connect("admin", autocommit=True) as admin:
            admin.execute(
                sql.SQL("ALTER ROLE {} {}").format(
                    sql.Identifier(builder_role),
                    sql.SQL(restore_flag),
                )
            )
        engine.dispose()


def test_authorization_rejects_unexpected_safe_database_role(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine = _repository(
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
    )
    candidate = ProfileReleaseCandidate.model_validate(_predecessor_payload()[0])
    legitimate = _profile_release_build_authority(repository, candidate)
    forged = legitimate.model_dump(mode="json")
    forged["builder_database_principal"] = profile_release_connections.role_names["evaluator_a"]
    unsigned = {key: value for key, value in forged.items() if key != "resolution_sha256"}
    forged["resolution_sha256"] = canonical_sha256(unsigned)
    before = _profile_release_write_state(postgres_harness)
    try:
        with (
            profile_release_connections.connect("authority_service", autocommit=True) as authority,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            authority.execute(
                "SELECT * FROM dev_eval.record_profile_release_build_authorization_v1(%s)",
                (psycopg.types.json.Jsonb(forged),),
            )
        assert _profile_release_write_state(postgres_harness) == before
    finally:
        engine.dispose()


def test_runtime_bootstrap_rejects_misbound_builder_role(
    monkeypatch: pytest.MonkeyPatch,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    _evaluation_repository_for_dsn.cache_clear()
    monkeypatch.setenv(
        "ITDA_LABEL_BUILDER_ROLE",
        profile_release_connections.role_names["evaluator_a"],
    )
    try:
        with pytest.raises(RuntimeError, match="builder database role is invalid"):
            _evaluation_repository_for_dsn(
                profile_release_connections.dsns["builder"],
                profile_release_connections.dsns["authority_service"],
            )
    finally:
        _evaluation_repository_for_dsn.cache_clear()


def test_0013_downgrade_refuses_and_preserves_active_v2_release(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    repository, engine, predecessor = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="v2-downgrade-predecessor-build",
        activate_nonce="v2-downgrade-predecessor-activate",
    )
    successor = _resolve_for_active_predecessor(tmp_path, repository)
    release_sha256 = cast(str, successor.release_sha256)
    try:
        _build_candidate(
            profile_release_connections.dsns["builder"],
            profile_release_connections.dsns["authority_service"],
            successor,
            nonce=_nonce("v2-downgrade-successor-build"),
        )
        repository.approve_profile_release(
            release_sha256,
            authenticated_principal="synthetic-v2-approver",
        )
        repository.activate_profile_release(
            release_sha256,
            expected_current=cast(str, predecessor.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("v2-downgrade-successor-activate"),
        )

        with postgres_harness.connect("admin", autocommit=True) as connection:
            before = (
                connection.execute(
                    "SELECT release_sha256, payload FROM dev_eval.profile_releases "
                    "ORDER BY release_sha256"
                ).fetchall(),
                connection.execute(
                    "SELECT successor_release_sha256, predecessor_release_sha256, "
                    "proof_sha256, payload "
                    "FROM dev_eval.profile_release_v2_transition_proofs"
                ).fetchall(),
                connection.execute(
                    "SELECT release_sha256, state, head_receipt_sha256 "
                    "FROM dev_eval.profile_release_lifecycle_heads "
                    "ORDER BY release_sha256"
                ).fetchall(),
                connection.execute(
                    "SELECT slot, release_sha256, receipt_sha256 "
                    "FROM dev_eval.profile_release_active_pointer"
                ).fetchall(),
            )
            migration_version_before = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchone()

        with pytest.raises(
            RuntimeError,
            match="0014 downgrade.*intentionally irreversible.*capability state",
        ):
            command.downgrade(config, "0012_phase3_profile_pin_provenance")

        with postgres_harness.connect("admin", autocommit=True) as connection:
            assert (
                connection.execute("SELECT version_num FROM alembic_version").fetchone()
                == migration_version_before
            )
            after = (
                connection.execute(
                    "SELECT release_sha256, payload FROM dev_eval.profile_releases "
                    "ORDER BY release_sha256"
                ).fetchall(),
                connection.execute(
                    "SELECT successor_release_sha256, predecessor_release_sha256, "
                    "proof_sha256, payload "
                    "FROM dev_eval.profile_release_v2_transition_proofs"
                ).fetchall(),
                connection.execute(
                    "SELECT release_sha256, state, head_receipt_sha256 "
                    "FROM dev_eval.profile_release_lifecycle_heads "
                    "ORDER BY release_sha256"
                ).fetchall(),
                connection.execute(
                    "SELECT slot, release_sha256, receipt_sha256 "
                    "FROM dev_eval.profile_release_active_pointer"
                ).fetchall(),
            )
        assert after == before

        _clear_profile_release_state_for_downgrade(postgres_harness)
        command.downgrade(config, "0012_phase3_profile_pin_provenance")
        command.upgrade(config, "head")
    finally:
        engine.dispose()


def test_successor_persistence_is_sealed_immutable_and_least_privilege(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine, predecessor = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="v2-sealed-predecessor-build",
        activate_nonce="v2-sealed-predecessor-activate",
    )
    successor = _resolve_for_active_predecessor(tmp_path, repository)
    release_sha256 = cast(str, successor.release_sha256)
    try:
        with pytest.raises(TypeError, match="server authority resolution"):
            repository.build_profile_release(
                cast(Any, successor),
                authenticated_principal=successor.builder_principal,
                reconciliation_nonce=_nonce("unsealed-successor"),
            )

        _build_candidate(
            profile_release_connections.dsns["builder"],
            profile_release_connections.dsns["authority_service"],
            successor,
            nonce=_nonce("sealed-successor"),
        )
        approval = repository.approve_profile_release(
            release_sha256,
            authenticated_principal="synthetic-v2-approver",
        )
        assert approval.release_sha256 == release_sha256
        with pytest.raises((ValueError, ProfileReleaseReplayError)):
            repository.approve_profile_release(
                release_sha256,
                authenticated_principal="synthetic-v2-approver",
            )
        with pytest.raises((IntegrityError, ProfileReleaseReplayError)):
            _build_candidate(
                profile_release_connections.dsns["builder"],
                profile_release_connections.dsns["authority_service"],
                successor,
                nonce=_nonce("duplicate-successor"),
            )

        with postgres_harness.connect("admin") as connection:
            before = connection.execute(
                "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = %s",
                (release_sha256,),
            ).fetchone()
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                connection.execute(
                    "UPDATE dev_eval.profile_releases SET payload = '{}'::jsonb "
                    "WHERE release_sha256 = %s",
                    (release_sha256,),
                )
            connection.rollback()
            after = connection.execute(
                "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = %s",
                (release_sha256,),
            ).fetchone()
        assert before == after == (successor.model_dump(mode="json"),)

        for capability in ("evaluator_a", "evaluator_b", "adjudicator", "model_runner"):
            with (
                profile_release_connections.connect(capability) as denied,
                pytest.raises(psycopg.errors.InsufficientPrivilege),
            ):
                denied.execute(
                    "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = %s",
                    (release_sha256,),
                ).fetchone()
        with (
            profile_release_connections.connect("approver") as denied_approver,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            denied_approver.execute(
                "INSERT INTO dev_eval.profile_release_v2_transition_proofs ("
                "successor_release_sha256, predecessor_release_sha256, proof_sha256, payload) "
                "VALUES (%s, %s, %s, '{}'::jsonb)",
                (
                    release_sha256,
                    predecessor.release_sha256,
                    canonical_sha256({"hostile": "proof"}),
                ),
            )
    finally:
        engine.dispose()


def _successor_variant(
    candidate: ProfileReleaseCandidateV2,
    *,
    release_id: str,
    predecessor_release_sha256: str | None = None,
) -> ProfileReleaseCandidateV2:
    payload = candidate.model_dump(mode="json", exclude={"release_sha256"})
    payload["release_id"] = release_id
    if predecessor_release_sha256 is not None:
        lineage = dict(payload["lineage"])
        lineage["predecessor_release_sha256"] = predecessor_release_sha256
        lineage.pop("lineage_sha256")
        payload["lineage"] = lineage
    return ProfileReleaseCandidateV2.model_validate(payload)


def _persist_successor_without_proof(
    postgres_harness: object,
    candidate: ProfileReleaseCandidateV2,
) -> None:
    with postgres_harness.connect("admin") as connection:
        connection.execute(
            "INSERT INTO dev_eval.profile_releases ("
            "release_sha256, release_id, builder_principal, canonical_lineage_sha256, "
            "dev_lineage_sha256, profile_schema_sha256, payload) VALUES ("
            "%s, %s, %s, %s, %s, %s, %s)",
            (
                candidate.release_sha256,
                candidate.release_id,
                candidate.builder_principal,
                candidate.lineage.canonical_lineage_sha256,
                candidate.lineage.dev_lineage_sha256,
                candidate.lineage.profile_schema_sha256,
                psycopg.types.json.Jsonb(candidate.model_dump(mode="json")),
            ),
        )
        connection.execute(
            "INSERT INTO dev_eval.profile_release_lifecycle_heads "
            "(release_sha256, state, head_receipt_sha256) "
            "VALUES (%s, 'BUILT_UNAPPROVED', NULL)",
            (candidate.release_sha256,),
        )


def test_builder_can_only_insert_db_derived_exact_predecessor_proof(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine, predecessor = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="v2-db-proof-predecessor-build",
        activate_nonce="v2-db-proof-predecessor-activate",
    )
    successor = _resolve_for_active_predecessor(tmp_path, repository)
    expected_proof = build_exact_predecessor_transition_proof(
        successor=successor,
        predecessor=predecessor,
    )
    try:
        _persist_successor_without_proof(postgres_harness, successor)
        with profile_release_connections.connect("builder", autocommit=True) as builder:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                builder.execute(
                    "INSERT INTO dev_eval.profile_release_v2_transition_proofs ("
                    "successor_release_sha256, predecessor_release_sha256, "
                    "proof_sha256, payload) VALUES (%s, %s, %s, '{}'::jsonb)",
                    (
                        successor.release_sha256,
                        predecessor.release_sha256,
                        canonical_sha256({"hostile": "proof"}),
                    ),
                )
            returned = builder.execute(
                "SELECT dev_eval.insert_profile_release_v2_transition_proof_v1(%s)",
                (successor.release_sha256,),
            ).fetchone()
        assert returned == (expected_proof.proof_sha256,)

        with postgres_harness.connect("admin", autocommit=True) as connection:
            stored = connection.execute(
                "SELECT predecessor_release_sha256, proof_sha256, payload "
                "FROM dev_eval.profile_release_v2_transition_proofs "
                "WHERE successor_release_sha256 = %s",
                (successor.release_sha256,),
            ).fetchone()
            routine = connection.execute(
                "SELECT prosecdef, proisstrict, "
                "proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[] "
                "FROM pg_proc WHERE oid = to_regprocedure("
                "'dev_eval.insert_profile_release_v2_transition_proof_v1(text)')"
            ).fetchone()
            execute_grantees = connection.execute(
                "SELECT grantee FROM information_schema.routine_privileges "
                "WHERE routine_schema = 'dev_eval' "
                "AND routine_name = 'insert_profile_release_v2_transition_proof_v1' "
                "AND privilege_type = 'EXECUTE' ORDER BY grantee"
            ).fetchall()
        assert stored == (
            predecessor.release_sha256,
            expected_proof.proof_sha256,
            expected_proof.model_dump(mode="json"),
        )
        assert routine == (True, True, True)
        assert set(execute_grantees) == {
            (profile_release_connections.role_names["builder"],),
            (postgres_harness.role_names["admin"],),
        }
    finally:
        engine.dispose()


def test_builder_proof_function_rejects_self_hashed_forged_predecessor(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine, _ = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="v2-forged-predecessor-build",
        activate_nonce="v2-forged-predecessor-activate",
    )
    valid = _resolve_for_active_predecessor(tmp_path, repository)
    payload = valid.model_dump(mode="json", exclude={"release_sha256"})
    payload["release_id"] = "synthetic-v2-forged-predecessor"
    lineage = dict(payload["lineage"])
    lineage["predecessor_release_sha256"] = "f" * 64
    lineage["lineage_sha256"] = canonical_sha256(
        {key: value for key, value in lineage.items() if key != "lineage_sha256"}
    )
    payload["lineage"] = lineage
    forged = ProfileReleaseCandidateV2.model_validate(payload)
    try:
        _persist_successor_without_proof(postgres_harness, forged)
        with (
            profile_release_connections.connect("builder", autocommit=True) as builder,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            builder.execute(
                "SELECT dev_eval.insert_profile_release_v2_transition_proof_v1(%s)",
                (forged.release_sha256,),
            )
        with postgres_harness.connect("admin", autocommit=True) as connection:
            assert connection.execute(
                "SELECT count(*) FROM dev_eval.profile_release_v2_transition_proofs "
                "WHERE successor_release_sha256 = %s",
                (forged.release_sha256,),
            ).fetchone() == (0,)
    finally:
        engine.dispose()


@pytest.mark.parametrize("mutation", ["adoption_scope", "fusion_policy", "lineage_scope"])
def test_database_v2_validator_rejects_self_hashed_scope_mutations(
    mutation: str,
    tmp_path: Path,
    postgres_harness: object,
) -> None:
    candidate = cast(ProfileReleaseCandidateV2, _resolve(tmp_path, _authority_payloads()))
    payload = candidate.model_dump(mode="json", exclude={"release_sha256"})
    if mutation == "adoption_scope":
        payload["adoption_state"] = "CONDITIONAL_ADOPT"
        payload["adopted_attributes"] = ["H1", "H1"]
    elif mutation == "fusion_policy":
        policy = dict(payload["fusion_policy"])
        policy["mode"] = "SENSITIVITY_ONLY"
        policy["release_eligible"] = False
        policy["policy_sha256"] = canonical_sha256(
            {key: value for key, value in policy.items() if key != "policy_sha256"}
        )
        payload["fusion_policy"] = policy
    else:
        lineage = dict(payload["lineage"])
        lineage["human_review_manifest_sha256"] = None
        lineage["lineage_sha256"] = canonical_sha256(
            {key: value for key, value in lineage.items() if key != "lineage_sha256"}
        )
        payload["lineage"] = lineage
    payload["release_sha256"] = canonical_sha256(payload)

    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT dev_eval.validate_profile_release_candidate_payload_v2(%s)",
            (psycopg.types.json.Jsonb(payload),),
        ).fetchone() == (False,)


@pytest.mark.parametrize("mutation", ["lane", "axis", "confidence", "label"])
def test_database_v2_validator_rejects_rehashed_nested_semantic_mutations(
    mutation: str,
    tmp_path: Path,
    postgres_harness: object,
) -> None:
    candidate = cast(ProfileReleaseCandidateV2, _resolve(tmp_path, _authority_payloads()))
    payload = candidate.model_dump(mode="json", exclude={"release_sha256"})
    member = payload["cohort"][0]
    profile = member["fused_profile"]
    if mutation == "lane":
        lane = profile["attributes"][0]["lanes"][0]
        lane["included"] = False
        lane["exclusion_reason"] = "REHASHED_FORGERY"
        attribute = profile["attributes"][0]
        attribute["attribute_sha256"] = canonical_sha256(
            {key: value for key, value in attribute.items() if key != "attribute_sha256"}
        )
    elif mutation == "axis":
        axis = profile["axes"][0]
        axis["score_milli"] += 1
        axis["score_percent"] = (axis["score_milli"] + 20) // 40
        axis["axis_sha256"] = canonical_sha256(
            {key: value for key, value in axis.items() if key != "axis_sha256"}
        )
    elif mutation == "confidence":
        confidence = profile["confidence"]
        confidence["publication_state"] = (
            "EXCLUDED_MANUAL_REVIEW"
            if confidence["publication_state"] == "PUBLISHABLE"
            else "PUBLISHABLE"
        )
        confidence["profile_confidence_sha256"] = canonical_sha256(
            {key: value for key, value in confidence.items() if key != "profile_confidence_sha256"}
        )
    else:
        label = profile["display_label"]
        label["label_ko"] = "위조된 표시 라벨"
        label["label_sha256"] = canonical_sha256(
            {key: value for key, value in label.items() if key != "label_sha256"}
        )
    profile["profile_fusion_sha256"] = canonical_sha256(
        {key: value for key, value in profile.items() if key != "profile_fusion_sha256"}
    )
    member["member_sha256"] = canonical_sha256(
        {key: value for key, value in member.items() if key != "member_sha256"}
    )
    payload["release_sha256"] = canonical_sha256(payload)

    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute(
            "SELECT dev_eval.validate_profile_release_candidate_payload_v2(%s)",
            (psycopg.types.json.Jsonb(payload),),
        ).fetchone() == (False,)


def test_successor_lifecycle_requires_exact_predecessor_and_exact_rollback(
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    repository, engine, predecessor = _seed_active_predecessor(
        postgres_harness.dsns["admin"],
        profile_release_connections.dsns["builder"],
        profile_release_connections.dsns["authority_service"],
        build_nonce="v2-lifecycle-predecessor-build",
        activate_nonce="v2-lifecycle-predecessor-activate",
    )
    base = _resolve_for_active_predecessor(tmp_path, repository)
    successor = _successor_variant(base, release_id="successor-exact")
    sibling = _successor_variant(base, release_id="successor-sibling")
    unrelated = _successor_variant(
        base,
        release_id="successor-unrelated",
        predecessor_release_sha256="f" * 64,
    )
    approver = "synthetic-v2-approver"
    try:
        for label, candidate in (("exact", successor), ("sibling", sibling)):
            _build_candidate(
                profile_release_connections.dsns["builder"],
                profile_release_connections.dsns["authority_service"],
                candidate,
                nonce=_nonce(f"v2-lifecycle-{label}-build"),
            )
        with pytest.raises(ValueError, match="independent|distinct|differs"):
            repository.approve_profile_release(
                cast(str, successor.release_sha256),
                authenticated_principal=successor.builder_principal,
            )
        for candidate in (successor, sibling):
            repository.approve_profile_release(
                cast(str, candidate.release_sha256),
                authenticated_principal=approver,
            )
        with pytest.raises(ValueError, match="exact active predecessor"):
            _build_candidate(
                profile_release_connections.dsns["builder"],
                profile_release_connections.dsns["authority_service"],
                unrelated,
                nonce=_nonce("v2-lifecycle-unrelated-build"),
            )

        activation_nonce = _nonce("v2-lifecycle-exact-activation")
        activated = repository.activate_profile_release(
            cast(str, successor.release_sha256),
            expected_current=cast(str, predecessor.release_sha256),
            authenticated_principal=approver,
            nonce=activation_nonce,
        )
        assert activated.receipt.release_sha256 == successor.release_sha256
        with pytest.raises(ValueError, match="exact predecessor"):
            repository.activate_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, successor.release_sha256),
                authenticated_principal=approver,
                nonce=_nonce("v2-lifecycle-sibling-activation"),
            )
        with pytest.raises(ProfileReleaseReplayError, match="stale expected-current"):
            repository.activate_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, predecessor.release_sha256),
                authenticated_principal=approver,
                nonce=_nonce("v2-lifecycle-stale-activation"),
            )
        with pytest.raises(ProfileReleaseReplayError, match="another transition"):
            repository.activate_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, successor.release_sha256),
                authenticated_principal=approver,
                nonce=activation_nonce,
            )

        rolled_back = repository.rollback_profile_release(
            cast(str, predecessor.release_sha256),
            expected_current=cast(str, successor.release_sha256),
            authenticated_principal=approver,
            reason="successor rollback verification",
            nonce=_nonce("v2-lifecycle-exact-rollback"),
        )
        assert rolled_back.receipt.release_sha256 == predecessor.release_sha256
        with pytest.raises(ValueError, match="lifecycle epoch is stale"):
            repository.activate_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, predecessor.release_sha256),
                authenticated_principal=approver,
                nonce=_nonce("v2-lifecycle-stale-epoch-activation"),
            )
        with pytest.raises(ValueError, match="exact predecessor|prior-active"):
            repository.rollback_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, predecessor.release_sha256),
                authenticated_principal=approver,
                reason="never-active sibling must fail",
                nonce=_nonce("v2-lifecycle-sibling-rollback"),
            )
    finally:
        engine.dispose()


def test_successor_cli_exposes_digest_only_lifecycle_subcommands() -> None:
    from itda.cli.manage_profile_release_v2 import build_parser

    parser = build_parser()
    for action in ("build", "approve", "activate", "rollback", "status"):
        args = parser.parse_args([action])
        assert args.action == action


def test_successor_cli_rejects_fabricated_candidate_before_database_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.api.dependencies import Phase3Principal
    from itda.cli import manage_profile_release_v2 as cli

    candidate = _resolve(tmp_path / "bundle", _authority_payloads())
    request_path = tmp_path / "fabricated-candidate.json"
    request_path.write_bytes(canonical_json_bytes(candidate.model_dump(mode="json")))
    database_mutated = False

    class ReadOnlyRepository:
        def profile_release_builder_database_principal(self) -> str:
            return "synthetic-db-builder"

        def build_profile_release(self, *_args: object, **_kwargs: object) -> object:
            nonlocal database_mutated
            database_mutated = True
            raise AssertionError("database must not be mutated for fabricated authority")

    monkeypatch.setattr(
        cli,
        "_principal",
        lambda: Phase3Principal(actor_id="synthetic-v2-builder", role="builder"),
    )
    monkeypatch.setattr(cli, "_AUTHORITY_ROOT", tmp_path)
    monkeypatch.setenv(
        "ITDA_PROFILE_RELEASE_AUTHORITY_REGISTRY_ID",
        str(uuid5(NAMESPACE_URL, "cli")),
    )
    (tmp_path / "request.json").write_bytes(request_path.read_bytes())
    monkeypatch.setattr(cli, "get_evaluation_repository", lambda _principal: ReadOnlyRepository())

    with pytest.raises(ValueError):
        cli.main(
            [
                "build",
                "--nonce",
                _nonce("fabricated-cli-candidate"),
            ]
        )

    assert database_mutated is False


def test_successor_cli_authority_request_read_is_bounded_and_no_follow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import manage_profile_release_v2 as cli

    monkeypatch.setattr(cli, "_AUTHORITY_ROOT", tmp_path)
    outside = tmp_path.parent / f"{tmp_path.name}-outside-request.json"
    outside.write_bytes(b"{}")
    request = tmp_path / "request.json"
    request.symlink_to(outside)
    with pytest.raises(OSError):
        cli._read_authority_request()

    request.unlink()
    request.write_bytes(b"x" * (cli._MAX_REQUEST_BYTES + 1))
    with pytest.raises(ValueError, match="bounded regular file"):
        cli._read_authority_request()
