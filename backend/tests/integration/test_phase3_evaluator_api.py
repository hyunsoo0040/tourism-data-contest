"""Focused PostgreSQL-backed API evidence for immutable evaluator receipts."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from types import MappingProxyType

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from sqlalchemy import Engine

from itda.api.dependencies import (
    Phase3Principal,
    _evaluation_repository_for_dsn,
    get_daily_release_overlay_reader,
    get_evaluation_repository,
    get_phase3_principal,
)
from itda.api.main import create_app
from itda.contracts.mvp_daily_refresh import DailyRefreshRunStatus
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.mvp_release_overlay import (
    DailyRefreshStatusRecord,
    DailyRefreshStoreError,
)
from itda.db.session import create_database_engine, create_session_factory, sqlalchemy_url_from_dsn

PHASE3_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)
SUBMITTED_AT = datetime(2026, 8, 4, tzinfo=UTC)


@pytest.fixture(autouse=True)
def clear_evaluation_repository_cache() -> Iterator[None]:
    _evaluation_repository_for_dsn.cache_clear()
    try:
        yield
    finally:
        _evaluation_repository_for_dsn.cache_clear()


def test_builder_repository_requires_distinct_authority_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = Phase3Principal(actor_id="phase3-builder", role="builder")
    builder_dsn = "postgresql+psycopg://builder:secret@localhost/itda"
    monkeypatch.setenv("ITDA_PHASE3_BUILDER_DATABASE_URL", builder_dsn)
    monkeypatch.delenv("ITDA_PHASE4_PROFILE_RELEASE_AUTHORITY_DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="authority database capability"):
        get_evaluation_repository(principal)

    monkeypatch.setenv("ITDA_PHASE4_PROFILE_RELEASE_AUTHORITY_DATABASE_URL", builder_dsn)
    with pytest.raises(RuntimeError, match="distinct from builder"):
        get_evaluation_repository(principal)


@dataclass(frozen=True, slots=True)
class Phase3ApiConnections:
    dsns: Mapping[str, str] = field(repr=False)
    role_names: Mapping[str, str]
    admin_dsn: str = field(repr=False)
    database_name: str

    def connect(
        self, capability: str, *, autocommit: bool = False
    ) -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(self.dsns[capability], autocommit=autocommit)


def _migration_config(postgres_harness: object, role_names: Mapping[str, str]) -> Config:
    config = Config("backend/alembic.ini")
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
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    return config


@pytest.fixture(scope="module")
def phase3_api_connections(postgres_harness: object) -> Iterator[Phase3ApiConnections]:
    suffix = secrets.token_hex(4)
    role_names = {
        capability: f"itda_label_api_{capability}_{suffix}" for capability in PHASE3_CAPABILITIES
    }
    passwords = {capability: secrets.token_urlsafe(24) for capability in PHASE3_CAPABILITIES}
    authority_owner = "itda_profile_release_write_authority"
    authority_service = "itda_profile_release_authority_service"
    authority_password = secrets.token_urlsafe(24)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    with postgres_harness.connect("admin", autocommit=True) as connection:
        for capability in PHASE3_CAPABILITIES:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOINHERIT"
                ).format(
                    sql.Identifier(role_names[capability]),
                    sql.Literal(passwords[capability]),
                )
            )
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(postgres_harness.database_name),
                    sql.Identifier(role_names[capability]),
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
    try:
        command.upgrade(config, "head")
        dsns = {
            capability: make_conninfo(
                **(
                    admin_info
                    | {
                        "user": role_names[capability],
                        "password": passwords[capability],
                    }
                )
            )
            for capability in PHASE3_CAPABILITIES
        }
        yield Phase3ApiConnections(
            dsns=MappingProxyType(dsns),
            role_names=MappingProxyType(role_names),
            admin_dsn=postgres_harness.dsns["admin"],
            database_name=postgres_harness.database_name,
        )
    finally:
        command.downgrade(config, "0003_real_manifest")
        with postgres_harness.connect("admin", autocommit=True) as connection:
            for capability in reversed(PHASE3_CAPABILITIES):
                role_name = role_names[capability]
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


@contextmanager
def _client_as(
    connections: Phase3ApiConnections,
    capability: str,
) -> Iterator[TestClient]:
    principals = {
        "evaluator_a": Phase3Principal(actor_id="phase3-evaluator-a", role="evaluator_a"),
        "evaluator_b": Phase3Principal(actor_id="phase3-evaluator-b", role="evaluator_b"),
    }
    engine: Engine = create_database_engine(connections.dsns[capability])
    repository = EvaluationRepository(create_session_factory(engine))
    application = create_app()
    application.dependency_overrides[get_phase3_principal] = lambda: principals[capability]
    application.dependency_overrides[get_evaluation_repository] = lambda: repository
    try:
        with TestClient(application) as client:
            yield client
    finally:
        application.dependency_overrides.clear()
        engine.dispose()


def _submission(*, rubric_version: str = "synthetic-rubric-v1") -> dict[str, object]:
    return {
        "assignment_id": "synthetic-assignment-api",
        "primary_axis": "HISTORY_TRADITION",
        "rubric_version": rubric_version,
        "source_snapshot_version": "synthetic-source-v1",
        "submitted_at": SUBMITTED_AT.isoformat(),
        "judgments": [
            {
                "attribute_id": attribute_id,
                "score": 2,
                "unknown_reason": None,
                "unknown_note": None,
                "evidence": [],
            }
            for attribute_id in (
                "H1",
                "H2",
                "H3",
                "H4",
                "I1",
                "I2",
                "I3",
                "I4",
                "R1",
                "R2",
                "R3",
                "R4",
            )
        ],
    }


def test_create_returns_canonical_stored_revision_fields_and_201(
    phase3_api_connections: Phase3ApiConnections,
) -> None:
    with _client_as(phase3_api_connections, "evaluator_a") as client:
        response = client.post("/internal/evaluation/revisions", json=_submission())

    assert response.status_code == 201
    assert set(response.json()) == {
        "revision_sha256",
        "receipt_sha256",
        "evaluator_principal",
        "revision",
        "created_at",
    }
    assert response.json()["revision"]["evaluator_pseudonym"] == "phase3-evaluator-a"


def test_exact_replay_returns_original_receipt_and_one_immutable_row(
    phase3_api_connections: Phase3ApiConnections,
) -> None:
    with _client_as(phase3_api_connections, "evaluator_a") as client:
        first = client.post("/internal/evaluation/revisions", json=_submission())
        replay = client.post("/internal/evaluation/revisions", json=_submission())

    assert first.status_code == replay.status_code == 201
    assert replay.json() == first.json()
    with phase3_api_connections.connect("evaluator_a", autocommit=True) as connection:
        row = connection.execute(
            "SELECT count(*), min(created_at), max(created_at) FROM dev_eval.own_label_revisions_v1"
        ).fetchone()
    assert row is not None
    assert row[0] == 1
    assert row[1] == row[2]


def test_successor_creation_preserves_predecessor_receipt(
    phase3_api_connections: Phase3ApiConnections,
) -> None:
    with _client_as(phase3_api_connections, "evaluator_a") as client:
        predecessor = client.post("/internal/evaluation/revisions", json=_submission())
        predecessor_body = predecessor.json()
        successor_payload = _submission(rubric_version="synthetic-rubric-v2")
        successor_payload["correction_reason"] = "합성 평가 수정"
        successor = client.post(
            f"/internal/evaluation/revisions/{predecessor_body['revision_sha256']}/corrections",
            json=successor_payload,
        )

    assert predecessor.status_code == successor.status_code == 201
    assert successor.json()["revision_sha256"] != predecessor_body["revision_sha256"]
    assert successor.json()["receipt_sha256"] != predecessor_body["receipt_sha256"]
    with phase3_api_connections.connect("evaluator_a", autocommit=True) as connection:
        predecessor_after = connection.execute(
            "SELECT receipt_sha256, payload, created_at "
            "FROM dev_eval.own_label_revisions_v1 WHERE revision_sha256 = %s",
            (predecessor_body["revision_sha256"],),
        ).fetchone()
    assert predecessor_after is not None
    assert str(predecessor_after[0]) == predecessor_body["receipt_sha256"]
    assert predecessor_after[1]["rubric_version"] == "synthetic-rubric-v1"
    assert predecessor_after[2] == datetime.fromisoformat(
        predecessor_body["created_at"].replace("Z", "+00:00")
    )


@pytest.mark.parametrize("identity_field", ["actor_id", "role", "evaluator_principal"])
def test_create_rejects_client_identity_fields(
    phase3_api_connections: Phase3ApiConnections,
    identity_field: str,
) -> None:
    payload = _submission()
    payload[identity_field] = "synthetic-forged-principal"
    with _client_as(phase3_api_connections, "evaluator_a") as client:
        response = client.post("/internal/evaluation/revisions", json=payload)

    assert response.status_code == 422
    assert response.json() == {"detail": "client identity fields are forbidden"}


def test_own_receipt_lookup_equals_post_replay_and_is_read_only(
    phase3_api_connections: Phase3ApiConnections,
) -> None:
    with _client_as(phase3_api_connections, "evaluator_a") as client:
        created = client.post("/internal/evaluation/revisions", json=_submission())
        replay = client.post("/internal/evaluation/revisions", json=_submission())
        with phase3_api_connections.connect("evaluator_a", autocommit=True) as connection:
            before = connection.execute(
                "SELECT count(*), min(created_at), max(created_at) "
                "FROM dev_eval.own_label_revisions_v1"
            ).fetchone()
        recovered = client.get(
            f"/internal/evaluation/revisions/{created.json()['revision_sha256']}/receipt"
        )
        with phase3_api_connections.connect("evaluator_a", autocommit=True) as connection:
            after = connection.execute(
                "SELECT count(*), min(created_at), max(created_at) "
                "FROM dev_eval.own_label_revisions_v1"
            ).fetchone()

    assert created.status_code == replay.status_code == 201
    assert recovered.status_code == 200
    assert recovered.json() == replay.json() == created.json()
    assert before == after


def test_receipt_denial_is_identical_for_missing_and_peer_owned_digest(
    phase3_api_connections: Phase3ApiConnections,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with _client_as(phase3_api_connections, "evaluator_b") as peer_client:
        peer = peer_client.post("/internal/evaluation/revisions", json=_submission())
    assert peer.status_code == 201

    with _client_as(phase3_api_connections, "evaluator_a") as client:
        missing = client.get(f"/internal/evaluation/revisions/{'f' * 64}/receipt")
        peer_owned = client.get(
            f"/internal/evaluation/revisions/{peer.json()['revision_sha256']}/receipt"
        )

    expected = {"detail": "revision receipt not found"}
    assert missing.status_code == peer_owned.status_code == 404
    assert missing.json() == peer_owned.json() == expected
    diagnostics = "\n".join(record.getMessage() for record in caplog.records)
    forbidden = (
        phase3_api_connections.role_names["evaluator_b"],
        peer.json()["evaluator_principal"],
        peer.json()["revision_sha256"],
        "MODEL_OUTPUT_SENTINEL",
        "BLIND_MEMBERSHIP_SENTINEL",
    )
    assert all(value not in missing.text + peer_owned.text + diagnostics for value in forbidden)


def test_receipt_authentication_failure_precedes_repository_lookup_and_redacts(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw_capability = "synthetic-invalid-capability-secret"
    monkeypatch.setenv(
        "ITDA_PHASE3_EVALUATOR_A_CAPABILITY_SHA256",
        hashlib.sha256(b"configured-other-capability").hexdigest(),
    )
    repository_looked_up = False

    def forbidden_repository_lookup() -> EvaluationRepository:
        nonlocal repository_looked_up
        repository_looked_up = True
        raise AssertionError("repository lookup must follow authentication")

    application = create_app()
    application.dependency_overrides[get_evaluation_repository] = forbidden_repository_lookup
    try:
        with TestClient(application) as client:
            response = client.get(
                f"/internal/evaluation/revisions/{'e' * 64}/receipt",
                headers={"X-ITDA-Phase3-Capability": raw_capability},
            )
    finally:
        application.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json() == {"detail": "phase 3 capability rejected"}
    assert repository_looked_up is False
    diagnostics = response.text + "\n" + "\n".join(record.getMessage() for record in caplog.records)
    assert raw_capability not in diagnostics
    assert "postgresql" not in diagnostics.lower()
    assert "MODEL_OUTPUT_SENTINEL" not in diagnostics
    assert "BLIND_MEMBERSHIP_SENTINEL" not in diagnostics


class _DailyStatusReader:
    def __init__(self, record: DailyRefreshStatusRecord | None) -> None:
        self.record = record

    def status(self) -> DailyRefreshStatusRecord | None:
        return self.record


@pytest.mark.parametrize("role", ["builder", "approver"])
def test_daily_glm_status_allows_release_readers_and_returns_closed_projection(
    role: str,
) -> None:
    record = DailyRefreshStatusRecord(
        run_date=date(2026, 9, 6),
        status=DailyRefreshRunStatus.RELEASE_ACTIVATED,
        changed_count=3,
        failed_count=1,
        call_count=4,
        active_release_sha256="a" * 64,
        safe_reason=None,
    )
    application = create_app()
    application.dependency_overrides[get_phase3_principal] = lambda: Phase3Principal(
        actor_id=f"phase3-{role}",
        role=role,
    )
    application.dependency_overrides[get_daily_release_overlay_reader] = lambda: (
        _DailyStatusReader(record)
    )
    try:
        with TestClient(application) as client:
            response = client.get("/internal/evaluation/daily-glm-refresh/status")
    finally:
        application.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        "schema_version",
        "run_date",
        "status",
        "changed_count",
        "failed_count",
        "call_count",
        "active_release_sha256",
        "next_run_at",
        "safe_reason",
    }
    assert payload | {"next_run_at": None} == {
        "schema_version": "mvp-daily-refresh-status.v1",
        "run_date": "2026-09-06",
        "status": "RELEASE_ACTIVATED",
        "changed_count": 3,
        "failed_count": 1,
        "call_count": 4,
        "active_release_sha256": "a" * 64,
        "next_run_at": None,
        "safe_reason": None,
    }
    assert payload["next_run_at"].endswith("Z")


def test_daily_glm_status_empty_state_has_zero_counts() -> None:
    application = create_app()
    application.dependency_overrides[get_phase3_principal] = lambda: Phase3Principal(
        actor_id="phase3-builder",
        role="builder",
    )
    application.dependency_overrides[get_daily_release_overlay_reader] = lambda: (
        _DailyStatusReader(None)
    )
    try:
        with TestClient(application) as client:
            response = client.get("/internal/evaluation/daily-glm-refresh/status")
    finally:
        application.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json() | {"next_run_at": None} == {
        "schema_version": "mvp-daily-refresh-status.v1",
        "run_date": None,
        "status": None,
        "changed_count": 0,
        "failed_count": 0,
        "call_count": 0,
        "active_release_sha256": None,
        "next_run_at": None,
        "safe_reason": None,
    }


def test_daily_glm_status_rejects_non_release_reader_before_store_lookup() -> None:
    store_looked_up = False

    def forbidden_store_lookup() -> _DailyStatusReader:
        nonlocal store_looked_up
        store_looked_up = True
        raise AssertionError("store lookup must follow authorization")

    application = create_app()
    application.dependency_overrides[get_phase3_principal] = lambda: Phase3Principal(
        actor_id="phase3-evaluator-a",
        role="evaluator_a",
    )
    application.dependency_overrides[get_daily_release_overlay_reader] = forbidden_store_lookup
    try:
        with TestClient(application) as client:
            response = client.get("/internal/evaluation/daily-glm-refresh/status")
    finally:
        application.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {
        "detail": "phase 3 profile release read capability required"
    }
    assert store_looked_up is False


def test_daily_glm_status_redacts_store_failure() -> None:
    class UnavailableReader:
        def status(self) -> None:
            raise DailyRefreshStoreError("postgresql://private-user:private-password@host")

    application = create_app()
    application.dependency_overrides[get_phase3_principal] = lambda: Phase3Principal(
        actor_id="phase3-approver",
        role="approver",
    )
    application.dependency_overrides[get_daily_release_overlay_reader] = UnavailableReader
    try:
        with TestClient(application) as client:
            response = client.get("/internal/evaluation/daily-glm-refresh/status")
    finally:
        application.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"detail": "daily GLM refresh status unavailable"}
    assert "private-password" not in response.text
