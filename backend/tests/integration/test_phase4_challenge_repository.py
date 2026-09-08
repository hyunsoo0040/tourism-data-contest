"""Live PostgreSQL execution for Phase 4 release-lineage challenges."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import psycopg
import pytest
from alembic import command
from sqlalchemy import Engine

from itda.contracts.profile_release import (
    ProfileReleaseCandidate,
    ProfileReleaseReplayError,
)
from itda.contracts.profile_release_authority import ProfileReleaseBuildAuthorityResolution
from itda.contracts.profile_release_v2 import ProfileReleaseCandidateV2
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_sha256
from tests.contract.test_profile_release_authority_v2 import _predecessor_payload
from tests.integration.test_profile_release import (
    ProfileReleaseConnections,
    _clear_profile_release_state_for_downgrade,
    _migration_config,
)
from tests.integration.test_profile_release import (
    profile_release_build_authority as _profile_release_build_authority,
)
from tests.integration.test_profile_release import (
    profile_release_connections as _profile_release_connections_fixture,  # noqa: F401
)
from tests.integration.test_profile_release_v2 import (
    _resolve_for_active_predecessor,
    _successor_variant,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CHALLENGE_PACK = REPOSITORY_ROOT / "fixtures/synthetic/phase4/challenge-pack.json"

REPOSITORY_SCENARIOS = frozenset(
    {
        "nested_profile_direct_sql",
        "pin_stability",
        "sibling_rollback",
        "stale_predecessor",
    }
)


@dataclass(slots=True)
class _Repositories:
    builder: EvaluationRepository
    approver: EvaluationRepository
    engines: tuple[Engine, ...]

    def close(self) -> None:
        for engine in self.engines:
            engine.dispose()


@pytest.fixture
def profile_release_connections(
    request: pytest.FixtureRequest,
) -> ProfileReleaseConnections:
    return cast(
        ProfileReleaseConnections,
        request.getfixturevalue("_profile_release_connections_fixture"),
    )


@pytest.fixture(autouse=True)
def clean_phase4_challenge_repository_state(
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


def _nonce(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _repositories(connections: ProfileReleaseConnections) -> _Repositories:
    builder_engine = create_database_engine(connections.dsns["builder"])
    approver_engine = create_database_engine(connections.dsns["approver"])
    authority_engine = create_database_engine(connections.dsns["authority_service"])
    return _Repositories(
        builder=EvaluationRepository(
            create_session_factory(builder_engine),
            authority_connection_factory=create_session_factory(authority_engine),
        ),
        approver=EvaluationRepository(create_session_factory(approver_engine)),
        engines=(builder_engine, approver_engine, authority_engine),
    )


def _seed_active_predecessor(
    repositories: _Repositories,
    *,
    label: str,
) -> ProfileReleaseCandidate:
    candidate = ProfileReleaseCandidate.model_validate(_predecessor_payload()[0])
    repositories.builder.build_profile_release(
        _profile_release_build_authority(repositories.builder, candidate),
        authenticated_principal=candidate.builder_principal,
        reconciliation_nonce=_nonce(f"{label}-predecessor-build"),
    )
    repositories.approver.approve_profile_release(
        cast(str, candidate.release_sha256),
        authenticated_principal="synthetic-v2-approver",
    )
    repositories.approver.activate_profile_release(
        cast(str, candidate.release_sha256),
        expected_current=None,
        authenticated_principal="synthetic-v2-approver",
        nonce=_nonce(f"{label}-predecessor-activate"),
    )
    return candidate


def _lifecycle_snapshot(postgres_harness: object) -> tuple[tuple[object, ...], ...]:
    statements = (
        "SELECT release_sha256, payload::text FROM dev_eval.profile_releases ORDER BY 1",
        "SELECT release_sha256, state, head_receipt_sha256 FROM "
        "dev_eval.profile_release_lifecycle_heads ORDER BY 1",
        "SELECT slot, release_sha256, receipt_sha256 FROM "
        "dev_eval.profile_release_active_pointer ORDER BY 1",
        "SELECT successor_release_sha256, predecessor_release_sha256, proof_sha256, "
        "payload::text FROM dev_eval.profile_release_v2_transition_proofs ORDER BY 1",
        "SELECT receipt_sha256, release_sha256, builder_principal, nonce_sha256, "
        "binding_sha256 FROM dev_eval.profile_release_build_receipts ORDER BY 1",
        "SELECT receipt_sha256, action, release_sha256, previous_release_sha256, "
        "payload::text FROM dev_eval.profile_release_transition_events ORDER BY 1",
        "SELECT receipt_sha256, release_sha256, payload::text FROM "
        "dev_eval.profile_release_rollback_receipts ORDER BY 1",
        "SELECT session_ref, release_sha256, pin_sha256 FROM "
        "dev_eval.profile_release_session_pins ORDER BY 1",
        "SELECT result_ref, release_sha256, pin_sha256 FROM "
        "dev_eval.profile_release_result_pins ORDER BY 1",
    )
    with postgres_harness.connect("admin", autocommit=True) as connection:
        return tuple(
            tuple(tuple(row) for row in connection.execute(statement).fetchall())
            for statement in statements
        )


def _authority_snapshot(postgres_harness: object) -> tuple[tuple[object, ...], ...]:
    statements = (
        "SELECT authority_registry_id, candidate_payload::text, candidate_sha256, "
        "authority_root_sha256, builder_database_principal, "
        "expected_predecessor_sha256, expected_predecessor_lifecycle_receipt_sha256, "
        "resolution_sha256, retired_at::text FROM "
        "dev_eval.profile_release_fixed_root_authorities_v1 ORDER BY 1",
        "SELECT authorization_id::text, authority_registry_id, resolution_payload::text, "
        "resolution_sha256, authority_root_sha256, candidate_sha256, "
        "builder_database_principal, expected_predecessor_sha256, "
        "expected_predecessor_lifecycle_receipt_sha256, consumed_at::text FROM "
        "dev_eval.profile_release_build_authorizations_v1 ORDER BY 1",
        "SELECT capability_id::text, authorization_id::text, candidate_payload::text, "
        "candidate_sha256, builder_database_principal, expected_predecessor_sha256, "
        "expected_predecessor_lifecycle_receipt_sha256, expires_at::text, "
        "consumed_at::text FROM dev_eval.profile_release_build_capabilities_v1 ORDER BY 1",
    )
    with postgres_harness.connect("admin", autocommit=True) as connection:
        return tuple(
            tuple(tuple(row) for row in connection.execute(statement).fetchall())
            for statement in statements
        )


def _issue_capability(
    connections: ProfileReleaseConnections,
    candidate: ProfileReleaseCandidateV2,
) -> str:
    repositories = _repositories(connections)
    resolution = _profile_release_build_authority(repositories.builder, candidate)
    with connections.connect("authority_service", autocommit=True) as authority:
        authorization = authority.execute(
            "SELECT authorization_id::text, candidate_sha256 FROM "
            "dev_eval.record_profile_release_build_authorization_v1(%s)",
            (psycopg.types.json.Jsonb(resolution.model_dump(mode="json")),),
        ).fetchone()
        assert authorization == (authorization[0], candidate.release_sha256)
        row = authority.execute(
            "SELECT capability_id::text, candidate_sha256 FROM "
            "dev_eval.issue_profile_release_build_capability_v2(%s)",
            (authorization[0],),
        ).fetchone()
    for engine in repositories.engines:
        engine.dispose()
    assert row == (row[0], candidate.release_sha256)
    return cast(str, row[0])


def _build_and_approve(
    repositories: _Repositories,
    candidate: ProfileReleaseCandidateV2,
    *,
    label: str,
) -> None:
    repositories.builder.build_profile_release(
        _profile_release_build_authority(repositories.builder, candidate),
        authenticated_principal=candidate.builder_principal,
        reconciliation_nonce=_nonce(f"{label}-build"),
    )
    repositories.approver.approve_profile_release(
        cast(str, candidate.release_sha256),
        authenticated_principal="synthetic-v2-approver",
    )


def _execute_stale_predecessor(
    case: dict[str, Any],
    tmp_path: Path,
    postgres_harness: object,
    connections: ProfileReleaseConnections,
) -> str:
    repositories = _repositories(connections)
    try:
        predecessor = _seed_active_predecessor(repositories, label="stale")
        base = _resolve_for_active_predecessor(tmp_path / "stale", repositories.builder)
        stale = _successor_variant(
            base,
            release_id="challenge-stale-predecessor",
            predecessor_release_sha256="f" * 64,
        )
        stale_resolution = _profile_release_build_authority(repositories.builder, stale)
        before_build = _lifecycle_snapshot(postgres_harness)
        with pytest.raises(ValueError, match="exact active predecessor"):
            repositories.builder.build_profile_release(
                stale_resolution,
                authenticated_principal=stale.builder_principal,
                reconciliation_nonce=_nonce("challenge-stale-build"),
            )
        assert _lifecycle_snapshot(postgres_harness) == before_build

        successor = _successor_variant(base, release_id="challenge-stale-successor")
        sibling = _successor_variant(base, release_id="challenge-stale-sibling")
        _build_and_approve(repositories, successor, label="challenge-stale-successor")
        _build_and_approve(repositories, sibling, label="challenge-stale-sibling")
        repositories.approver.activate_profile_release(
            cast(str, successor.release_sha256),
            expected_current=cast(str, predecessor.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("challenge-stale-successor-activate"),
        )
        before_activation = _lifecycle_snapshot(postgres_harness)
        with pytest.raises(ProfileReleaseReplayError, match="stale expected-current"):
            repositories.approver.activate_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, predecessor.release_sha256),
                authenticated_principal="synthetic-v2-approver",
                nonce=_nonce("challenge-stale-sibling-activate"),
            )
        assert _lifecycle_snapshot(postgres_harness) == before_activation
        return cast(str, case["expected"]["result"])
    finally:
        repositories.close()


def _execute_sibling_rollback(
    case: dict[str, Any],
    tmp_path: Path,
    postgres_harness: object,
    connections: ProfileReleaseConnections,
) -> str:
    repositories = _repositories(connections)
    try:
        predecessor = _seed_active_predecessor(repositories, label="sibling")
        base = _resolve_for_active_predecessor(tmp_path / "sibling", repositories.builder)
        successor = _successor_variant(base, release_id="challenge-rollback-successor")
        sibling = _successor_variant(base, release_id="challenge-rollback-sibling")
        _build_and_approve(repositories, successor, label="challenge-rollback-successor")
        _build_and_approve(repositories, sibling, label="challenge-rollback-sibling")
        repositories.approver.activate_profile_release(
            cast(str, successor.release_sha256),
            expected_current=cast(str, predecessor.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("challenge-rollback-successor-activate"),
        )
        before = _lifecycle_snapshot(postgres_harness)
        with pytest.raises(ValueError, match="prior-active|exact predecessor"):
            repositories.approver.rollback_profile_release(
                cast(str, sibling.release_sha256),
                expected_current=cast(str, successor.release_sha256),
                authenticated_principal="synthetic-v2-approver",
                reason="hostile sibling rollback",
                nonce=_nonce("challenge-sibling-rollback"),
            )
        assert _lifecycle_snapshot(postgres_harness) == before
        return cast(str, case["expected"]["result"])
    finally:
        repositories.close()


def _execute_nested_profile_direct_sql(
    case: dict[str, Any],
    tmp_path: Path,
    postgres_harness: object,
    connections: ProfileReleaseConnections,
) -> str:
    repositories = _repositories(connections)
    try:
        predecessor = _seed_active_predecessor(repositories, label="capability")
        candidate = _resolve_for_active_predecessor(tmp_path / "capability", repositories.builder)
        alternate = _successor_variant(candidate, release_id="challenge-coherent-alternate")
        builder_a = connections.role_names["builder"]
        builder_b = connections.role_names["evaluator_b"]
        assert len({builder_a, builder_b, connections.role_names["approver"]}) == 3
        before = _lifecycle_snapshot(postgres_harness)
        candidate_json = psycopg.types.json.Jsonb(alternate.model_dump(mode="json"))

        with connections.connect("builder", autocommit=True) as builder:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                builder.execute(
                    "INSERT INTO dev_eval.profile_releases (release_sha256, release_id, "
                    "builder_principal, canonical_lineage_sha256, dev_lineage_sha256, "
                    "profile_schema_sha256, payload) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (
                        alternate.release_sha256,
                        alternate.release_id,
                        alternate.builder_principal,
                        alternate.lineage.canonical_lineage_sha256,
                        alternate.lineage.dev_lineage_sha256,
                        alternate.lineage.profile_schema_sha256,
                        candidate_json,
                    ),
                )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                builder.execute(
                    "SELECT dev_eval.validate_profile_release_candidate_payload_dispatch_v1(%s)",
                    (candidate_json,),
                )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                builder.execute(
                    "SELECT dev_eval.issue_profile_release_build_capability_v1(%s,%s,%s)",
                    (candidate_json, builder_a, alternate.lineage.predecessor_release_sha256),
                )
            with pytest.raises(psycopg.errors.CheckViolation):
                builder.execute(
                    "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                    ("00000000-0000-0000-0000-000000000001",),
                )
        assert _lifecycle_snapshot(postgres_harness) == before

        bound_to_a = _issue_capability(connections, candidate)
        after_bound_to_a = _lifecycle_snapshot(postgres_harness)
        with (
            connections.connect("evaluator_b", autocommit=True) as hostile_builder_b,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            hostile_builder_b.execute(
                "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                (bound_to_a,),
            )
        assert _lifecycle_snapshot(postgres_harness) == after_bound_to_a

        exact_alternate = _profile_release_build_authority(repositories.builder, alternate)
        hostile_payload = exact_alternate.model_dump(mode="json")
        hostile_payload["builder_database_principal"] = builder_b
        hostile_payload["resolution_sha256"] = canonical_sha256(
            {key: value for key, value in hostile_payload.items() if key != "resolution_sha256"}
        )
        hostile_resolution = ProfileReleaseBuildAuthorityResolution.model_validate(hostile_payload)
        before_hostile_resolution = (
            _lifecycle_snapshot(postgres_harness),
            _authority_snapshot(postgres_harness),
        )
        with (
            connections.connect("authority_service", autocommit=True) as authority_service,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            authority_service.execute(
                "SELECT authorization_id::text FROM "
                "dev_eval.record_profile_release_build_authorization_v1(%s)",
                (psycopg.types.json.Jsonb(hostile_resolution.model_dump(mode="json")),),
            )
        assert (
            _lifecycle_snapshot(postgres_harness),
            _authority_snapshot(postgres_harness),
        ) == before_hostile_resolution

        intervening = _successor_variant(
            candidate,
            release_id="challenge-capability-intervening",
        )
        _build_and_approve(
            repositories,
            intervening,
            label="challenge-capability-intervening",
        )
        repositories.approver.activate_profile_release(
            cast(str, intervening.release_sha256),
            expected_current=cast(str, predecessor.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("challenge-capability-intervening-activate"),
        )
        after_intervening = _lifecycle_snapshot(postgres_harness)
        with (
            connections.connect("builder", autocommit=True) as builder,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            builder.execute(
                "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                (bound_to_a,),
            )
        assert _lifecycle_snapshot(postgres_harness) == after_intervening
        repositories.approver.rollback_profile_release(
            cast(str, predecessor.release_sha256),
            expected_current=cast(str, intervening.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            reason="restore predecessor after stale capability challenge",
            nonce=_nonce("challenge-capability-intervening-rollback"),
        )
        fresh = _resolve_for_active_predecessor(
            tmp_path / "capability-fresh",
            repositories.builder,
        )
        fresh_token = _issue_capability(connections, fresh)
        with connections.connect("builder", autocommit=True) as builder:
            assert builder.execute(
                "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                (fresh_token,),
            ).fetchone() == (fresh.release_sha256,)
            with pytest.raises(psycopg.errors.CheckViolation):
                builder.execute(
                    "SELECT dev_eval.consume_profile_release_build_capability_v1(%s)",
                    (fresh_token,),
                )
        with postgres_harness.connect("admin", autocommit=True) as observer:
            assert observer.execute(
                "SELECT state, head_receipt_sha256 FROM "
                "dev_eval.profile_release_lifecycle_heads WHERE release_sha256 = %s",
                (fresh.release_sha256,),
            ).fetchone() == ("BUILT_UNAPPROVED", None)
            assert observer.execute(
                "SELECT count(*) FROM dev_eval.profile_releases WHERE release_sha256 = %s",
                (alternate.release_sha256,),
            ).fetchone() == (0,)
            assert observer.execute(
                "SELECT consumed_at IS NOT NULL FROM "
                "dev_eval.profile_release_build_capabilities_v1 WHERE capability_id = %s",
                (fresh_token,),
            ).fetchone() == (True,)
            assert observer.execute(
                "SELECT release_sha256 FROM dev_eval.profile_release_active_pointer "
                "WHERE slot = 'DEV'"
            ).fetchone() == (predecessor.release_sha256,)
        return cast(str, case["expected"]["result"])
    finally:
        repositories.close()


def _execute_pin_stability(
    case: dict[str, Any],
    tmp_path: Path,
    postgres_harness: object,
    connections: ProfileReleaseConnections,
) -> str:
    repositories = _repositories(connections)
    try:
        predecessor = _seed_active_predecessor(repositories, label="pin")
        predecessor_sha256 = cast(str, predecessor.release_sha256)
        before_session = repositories.builder.pin_profile_release_session("challenge-before")
        before_result = repositories.builder.pin_profile_release_result("challenge-before")

        first = _resolve_for_active_predecessor(tmp_path / "pin-first", repositories.builder)
        _build_and_approve(repositories, first, label="challenge-pin-first")
        repositories.approver.activate_profile_release(
            cast(str, first.release_sha256),
            expected_current=predecessor_sha256,
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("challenge-pin-first-activate"),
        )
        after_session = repositories.builder.pin_profile_release_session("challenge-after")
        after_result = repositories.builder.pin_profile_release_result("challenge-after")
        with postgres_harness.connect("admin", autocommit=True) as observer:
            immutable_before = observer.execute(
                "SELECT releases.payload::text, events.payload::text FROM "
                "dev_eval.profile_releases releases JOIN "
                "dev_eval.profile_release_transition_events events "
                "ON events.release_sha256 = releases.release_sha256 "
                "WHERE releases.release_sha256 = %s AND events.action = 'ACTIVATE'",
                (predecessor_sha256,),
            ).fetchone()
            pin_rows_before = (
                observer.execute(
                    "SELECT session_ref, release_sha256, pin_sha256 FROM "
                    "dev_eval.profile_release_session_pins ORDER BY 1"
                ).fetchall(),
                observer.execute(
                    "SELECT result_ref, release_sha256, pin_sha256 FROM "
                    "dev_eval.profile_release_result_pins ORDER BY 1"
                ).fetchall(),
            )

        repositories.approver.rollback_profile_release(
            predecessor_sha256,
            expected_current=cast(str, first.release_sha256),
            authenticated_principal="synthetic-v2-approver",
            reason="pin stability rollback",
            nonce=_nonce("challenge-pin-rollback"),
        )
        second_base = _resolve_for_active_predecessor(tmp_path / "pin-second", repositories.builder)
        second = _successor_variant(second_base, release_id="challenge-pin-reactivated")
        _build_and_approve(repositories, second, label="challenge-pin-second")
        repositories.approver.activate_profile_release(
            cast(str, second.release_sha256),
            expected_current=predecessor_sha256,
            authenticated_principal="synthetic-v2-approver",
            nonce=_nonce("challenge-pin-second-activate"),
        )
        final_session = repositories.builder.pin_profile_release_session("challenge-final")
        final_result = repositories.builder.pin_profile_release_result("challenge-final")

        assert repositories.builder.pin_profile_release_session("challenge-before") == (
            before_session
        )
        assert repositories.builder.pin_profile_release_result("challenge-before") == before_result
        assert repositories.builder.pin_profile_release_session("challenge-after") == after_session
        assert repositories.builder.pin_profile_release_result("challenge-after") == after_result
        assert before_session.release_sha256 == before_result.release_sha256 == predecessor_sha256
        assert after_session.release_sha256 == after_result.release_sha256 == first.release_sha256
        assert final_session.release_sha256 == final_result.release_sha256 == second.release_sha256

        with postgres_harness.connect("admin", autocommit=True) as observer:
            immutable_after = observer.execute(
                "SELECT releases.payload::text, events.payload::text FROM "
                "dev_eval.profile_releases releases JOIN "
                "dev_eval.profile_release_transition_events events "
                "ON events.release_sha256 = releases.release_sha256 "
                "WHERE releases.release_sha256 = %s AND events.action = 'ACTIVATE'",
                (predecessor_sha256,),
            ).fetchone()
            pin_rows_after = (
                observer.execute(
                    "SELECT session_ref, release_sha256, pin_sha256 FROM "
                    "dev_eval.profile_release_session_pins "
                    "WHERE session_ref <> 'challenge-final' ORDER BY 1"
                ).fetchall(),
                observer.execute(
                    "SELECT result_ref, release_sha256, pin_sha256 FROM "
                    "dev_eval.profile_release_result_pins "
                    "WHERE result_ref <> 'challenge-final' ORDER BY 1"
                ).fetchall(),
            )
        assert immutable_after == immutable_before
        assert pin_rows_after == pin_rows_before
        assert case["expected"]["pin_stable"] is True
        return cast(str, case["expected"]["result"])
    finally:
        repositories.close()


_REPOSITORY_EXECUTORS: dict[
    str,
    Callable[
        [dict[str, Any], Path, object, ProfileReleaseConnections],
        str,
    ],
] = {
    "nested_profile_direct_sql": _execute_nested_profile_direct_sql,
    "pin_stability": _execute_pin_stability,
    "sibling_rollback": _execute_sibling_rollback,
    "stale_predecessor": _execute_stale_predecessor,
}


def _release_lineage_cases() -> list[dict[str, Any]]:
    pack = json.loads(CHALLENGE_PACK.read_bytes())
    return [case for case in pack["cases"] if case["category"] == "release_lineage"]


def test_every_release_lineage_challenge_has_a_live_repository_executor() -> None:
    declared = {case["scenario"] for case in _release_lineage_cases()}
    assert declared == REPOSITORY_SCENARIOS
    assert set(_REPOSITORY_EXECUTORS) == declared


@pytest.mark.parametrize("case", _release_lineage_cases(), ids=lambda case: case["scenario"])
def test_release_lineage_challenge_executes_live_repository(
    case: dict[str, Any],
    tmp_path: Path,
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    executor = _REPOSITORY_EXECUTORS[case["scenario"]]
    result = executor(case, tmp_path, postgres_harness, profile_release_connections)

    assert result == case["expected"]["result"]
    assert case["expected"]["release_authority"] == "DENIED"
    assert case["expected"]["protected_evidence_claim"] == "NONE"
