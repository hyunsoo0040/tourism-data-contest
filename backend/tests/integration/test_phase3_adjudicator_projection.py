"""Focused PostgreSQL/API evidence for the Phase 3 adjudicator projection."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

import itda.api.dependencies as api_dependencies
import itda.api.routes.evaluation as evaluation_routes
import itda.contracts.labeling as labeling
from itda.api.main import create_app
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.session import create_database_engine, create_session_factory, sqlalchemy_url_from_dsn
from tests.integration.profile_release_test_support import (
    ensure_profile_release_authority_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
FIXTURE_PATH = REPOSITORY_ROOT / "fixtures" / "synthetic" / "phase3" / "e2e-runtime.json"
PHASE3_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)
EVALUATOR_CAPABILITIES = PHASE3_CAPABILITIES[:3]
SUBMITTED_AT = datetime(2026, 8, 4, 8, 0, tzinfo=UTC)


def _principal_pseudonym(principal: str) -> str:
    digest = hashlib.sha256(f"phase3-pseudonym-v1\n{principal}".encode()).hexdigest()
    return f"phase3-{digest[:24]}"


class PostgresHarness(Protocol):
    dsns: Mapping[str, str]
    role_names: Mapping[str, str]
    database_name: str

    def connect(
        self,
        capability: str,
        *,
        autocommit: bool = False,
    ) -> psycopg.Connection[tuple[object, ...]]: ...


@dataclass(frozen=True, slots=True)
class ProjectionConnections:
    dsns: Mapping[str, str] = field(repr=False)
    role_names: Mapping[str, str]
    admin_dsn: str = field(repr=False)
    schema_available: bool

    def connect(
        self,
        capability: str,
        *,
        autocommit: bool = False,
    ) -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(self.dsns[capability], autocommit=autocommit)


def _configure_migration(postgres_harness: PostgresHarness, roles: Mapping[str, str]) -> Config:
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
    for capability, role_name in roles.items():
        config.attributes[f"label_{capability}_role"] = role_name
    return config


@pytest.fixture(scope="module")
def projection_connections(
    postgres_harness: PostgresHarness,
) -> Iterator[ProjectionConnections]:
    ensure_profile_release_authority_roles(postgres_harness)
    suffix = secrets.token_hex(4)
    role_names = {
        capability: f"itda_projection_{capability}_{suffix}" for capability in PHASE3_CAPABILITIES
    }
    passwords = {capability: secrets.token_urlsafe(24) for capability in PHASE3_CAPABILITIES}
    admin_info = cast(dict[str, str], conninfo_to_dict(postgres_harness.dsns["admin"]))
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

    try:
        command.upgrade(_configure_migration(postgres_harness, role_names), "head")
        with postgres_harness.connect("admin", autocommit=True) as connection:
            relation = connection.execute(
                "SELECT to_regclass('dev_eval.adjudicator_label_revisions_v1')"
            ).fetchone()
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
        yield ProjectionConnections(
            dsns=MappingProxyType(dsns),
            role_names=MappingProxyType(role_names),
            admin_dsn=postgres_harness.dsns["admin"],
            schema_available=relation == ("dev_eval.adjudicator_label_revisions_v1",),
        )
    finally:
        with postgres_harness.connect("admin", autocommit=True) as connection:
            for capability in reversed(PHASE3_CAPABILITIES):
                role_name = role_names[capability]
                connection.execute(
                    sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role_name))
                )
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_name))
                )


def _fixture() -> dict[str, object]:
    return cast(dict[str, object], json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))


def _official_source(
    *,
    assignment_id: str | None = None,
) -> labeling.AdjudicationSourceManifest:
    payload = _fixture()
    assignment = cast(dict[str, object], payload["assignment"])
    sources = cast(list[dict[str, object]], payload["sources"])
    evidence_items = cast(list[dict[str, object]], payload["evidence_items"])
    source_type = labeling.AdjudicationOfficialSource
    manifest_type = labeling.AdjudicationSourceManifest
    evidence_by_source: dict[str, list[str]] = {}
    for evidence in evidence_items:
        evidence_by_source.setdefault(str(evidence["source_id"]), []).append(
            str(evidence["evidence_id"])
        )
    source_models = tuple(
        source_type(
            source_id=str(source["source_id"]),
            lane=labeling.EvidenceLane(str(source["lane"])),
            original_text=str(source["text_ko"]),
            source_text_sha256=hashlib.sha256(str(source["text_ko"]).encode("utf-8")).hexdigest(),
            evidence_ids=tuple(sorted(evidence_by_source[str(source["source_id"])])),
        )
        for source in sources
    )
    return manifest_type(
        assignment_id=assignment_id or str(assignment["assignment_id"]),
        source_snapshot_version=str(assignment["source_snapshot_version"]),
        sources=source_models,
    )


def _evidence(*, lane: str, evidence_id: str, source_id: str, cluster: str) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "source_id": source_id,
        "lane": lane,
        "dedup_cluster_id": cluster,
        "direct": True,
        "concordance_key": "synthetic-runtime-concordance-a",
        "supports_absence": False,
        "complete_context": False,
    }


def _submission(
    evaluator_index: int,
    *,
    assignment_id: str | None = None,
    parent_revision_sha256: str | None = None,
    correction_reason: str | None = None,
    minute: int = 0,
) -> dict[str, object]:
    fixture = _fixture()
    assignment = cast(dict[str, object], fixture["assignment"])
    desc = _evidence(
        lane="DESCRIPTION",
        evidence_id="synthetic-runtime-desc-a",
        source_id="synthetic-runtime-description-alpha",
        cluster="synthetic-runtime-cluster-a",
    )
    odii = _evidence(
        lane="ODII",
        evidence_id="synthetic-runtime-odii-a",
        source_id="synthetic-runtime-odii-alpha",
        cluster="synthetic-runtime-cluster-b",
    )
    h1_scores = (1, 3, 4)
    axes = ("HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION")
    judgments: list[dict[str, object]] = []
    for attribute_id in ("H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"):
        score: int | None = h1_scores[evaluator_index] if attribute_id == "H1" else 2
        unknown_reason: str | None = None
        unknown_note: str | None = None
        evidence: list[dict[str, object]] = []
        if attribute_id == "H1" and evaluator_index == 1:
            evidence = [desc]
        elif attribute_id == "H1" and evaluator_index == 2:
            evidence = [desc, odii]
        elif attribute_id == "H2" and evaluator_index == 2:
            score = None
            unknown_reason = "INSUFFICIENT_EVIDENCE"
            unknown_note = "합성 원문만으로는 강도를 확정할 수 없음"
        judgments.append(
            {
                "attribute_id": attribute_id,
                "score": score,
                "unknown_reason": unknown_reason,
                "unknown_note": unknown_note,
                "evidence": evidence,
            }
        )
    return {
        "assignment_id": assignment_id or assignment["assignment_id"],
        "rubric_version": assignment["rubric_version"],
        "source_snapshot_version": assignment["source_snapshot_version"],
        "primary_axis": axes[evaluator_index],
        "parent_revision_sha256": parent_revision_sha256,
        "correction_reason": correction_reason,
        "submitted_at": SUBMITTED_AT.replace(minute=minute).isoformat(),
        "judgments": judgments,
    }


def _submit(
    connection: psycopg.Connection[tuple[object, ...]],
    payload: dict[str, object],
) -> str:
    row = connection.execute(
        "SELECT revision_sha256 FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
        (psycopg.types.json.Jsonb(payload),),
    ).fetchone()
    assert row is not None
    return str(row[0])


def _repository(connections: ProjectionConnections) -> EvaluationRepository:
    engine = create_database_engine(connections.dsns["adjudicator"])
    return EvaluationRepository(create_session_factory(engine))


def _seed_projection_assignment(
    connections: ProjectionConnections,
    assignment_id: str,
) -> tuple[EvaluationRepository, tuple[str, str, str]]:
    tips: list[str] = []
    for evaluator_index, evaluator_capability in enumerate(EVALUATOR_CAPABILITIES):
        with connections.connect(evaluator_capability, autocommit=True) as connection:
            root = _submit(
                connection,
                _submission(evaluator_index, assignment_id=assignment_id),
            )
            tips.append(
                _submit(
                    connection,
                    _submission(
                        evaluator_index,
                        assignment_id=assignment_id,
                        parent_revision_sha256=root,
                        correction_reason="합성 정정 사유",
                        minute=evaluator_index + 1,
                    ),
                )
            )
    return _repository(connections), cast(tuple[str, str, str], tuple(tips))


def _configure_http_runtime(
    monkeypatch: pytest.MonkeyPatch,
    connections: ProjectionConnections,
) -> Mapping[str, str]:
    raw_capabilities: dict[str, str] = {}
    for capability in PHASE3_CAPABILITIES:
        raw = f"synthetic-projection-{capability}-{secrets.token_urlsafe(24)}"
        prefix = f"ITDA_PHASE3_{capability.upper()}"
        monkeypatch.setenv(
            f"{prefix}_CAPABILITY_SHA256",
            hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        )
        monkeypatch.setenv(f"{prefix}_DATABASE_URL", connections.dsns[capability])
        raw_capabilities[capability] = raw
    monkeypatch.setenv("ITDA_E2E_PHASE3_TEST_SUPPORT", "1")
    api_dependencies._evaluation_repository_for_dsn.cache_clear()
    return MappingProxyType(raw_capabilities)


def _capability_header(raw_capability: str) -> dict[str, str]:
    return {"X-ITDA-Phase3-Capability": raw_capability}


@pytest.fixture(scope="module")
def populated_projection(
    projection_connections: ProjectionConnections,
) -> tuple[EvaluationRepository, tuple[str, str, str]]:
    assert projection_connections.schema_available
    return _seed_projection_assignment(
        projection_connections,
        "synthetic-runtime-assignment-alpha",
    )


def test_migration_is_linear_security_barrier_and_adjudicator_only(
    projection_connections: ProjectionConnections,
) -> None:
    assert projection_connections.schema_available
    migration_path = (
        REPOSITORY_ROOT
        / "backend"
        / "migrations"
        / "versions"
        / "0006_phase3_adjudicator_projection.py"
    )
    source = migration_path.read_text(encoding="utf-8")
    assert 'revision = "0006_phase3_adjudicator_projection"' in source
    assert 'down_revision = "0005_phase3_adjudication"' in source

    with projection_connections.connect("adjudicator", autocommit=True) as connection:
        options = connection.execute(
            "SELECT reloptions FROM pg_class WHERE oid = "
            "'dev_eval.adjudicator_label_revisions_v1'::regclass"
        ).fetchone()
        assert options is not None
        assert "security_barrier=true" in cast(list[str], options[0])
        assert connection.execute(
            "SELECT has_table_privilege(current_user, "
            "'dev_eval.adjudicator_label_revisions_v1', 'SELECT')"
        ).fetchone() == (True,)

    with psycopg.connect(projection_connections.admin_dsn, autocommit=True) as connection:
        for capability in (
            "evaluator_a",
            "evaluator_b",
            "evaluator_c",
            "model_runner",
            "builder",
            "approver",
        ):
            assert connection.execute(
                "SELECT has_table_privilege(%s, "
                "'dev_eval.adjudicator_label_revisions_v1', 'SELECT')",
                (projection_connections.role_names[capability],),
            ).fetchone() == (False,)


def test_repository_projects_linear_pseudonymous_chains_and_exact_triggers(
    populated_projection: tuple[EvaluationRepository, tuple[str, str, str]],
) -> None:
    repository, tips = populated_projection
    official_source = _official_source()
    projection = repository.get_adjudicator_projection(
        "synthetic-runtime-assignment-alpha",
        official_source,
    )

    assert len(projection.chains) == 3
    assert {chain.tip_revision_sha256 for chain in projection.chains} == set(tips)
    assert all(len(chain.revisions) == 2 for chain in projection.chains)
    assert all(chain.accepted_head is None for chain in projection.chains)
    assert projection.accepted_revision_set_sha256 is None
    assert projection.release_blocked is True
    assert projection.review_triggers == ()
    assert projection.official_source_sha256 == official_source.official_source_sha256

    serialized = projection.model_dump(mode="json")
    forbidden = {
        "evaluator_principal",
        "selected_by",
        "model_output",
        "traveler",
        "session",
        "partition",
        "membership",
        "order",
        "complement",
        "capability",
        "dsn",
        "path",
    }

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(serialized)


def test_digest_bound_selection_rejects_stale_chain_without_event(
    projection_connections: ProjectionConnections,
) -> None:
    assignment_id = "synthetic-runtime-assignment-alpha-r0-e0-w2"
    repository, tips = _seed_projection_assignment(projection_connections, assignment_id)
    source = _official_source(assignment_id=assignment_id)
    before = repository.get_adjudicator_projection(
        assignment_id,
        source,
    )
    chains_by_tip = {chain.tip_revision_sha256: chain for chain in before.chains}
    evaluator_a_chain = chains_by_tip[tips[0]]

    with psycopg.connect(projection_connections.admin_dsn, autocommit=True) as connection:
        count_before = connection.execute(
            "SELECT count(*) FROM dev_eval.accepted_label_revisions"
        ).fetchone()
    assert count_before is not None

    with projection_connections.connect("evaluator_a", autocommit=True) as connection:
        newest_tip = _submit(
            connection,
            _submission(
                0,
                assignment_id=assignment_id,
                parent_revision_sha256=tips[0],
                correction_reason="합성 최신 정정 사유",
                minute=8,
            ),
        )
    assert newest_tip != tips[0]

    with pytest.raises(labeling.LabelExportBlocked, match="incomplete or stale"):
        repository.select_accepted_head(
            tips[0],
            reason="합성 accepted head 선택",
            selected_at=SUBMITTED_AT.replace(minute=9),
            expected_chain_sha256=cast(str, evaluator_a_chain.chain_sha256),
        )

    with psycopg.connect(projection_connections.admin_dsn, autocommit=True) as connection:
        count_after = connection.execute(
            "SELECT count(*) FROM dev_eval.accepted_label_revisions"
        ).fetchone()
    assert count_after == count_before


def test_adjudicator_route_returns_exact_source_raw_chains_and_triggers(
    monkeypatch: pytest.MonkeyPatch,
    projection_connections: ProjectionConnections,
) -> None:
    assignment_id = "synthetic-runtime-assignment-alpha-r0-e0-w1"
    repository, _ = _seed_projection_assignment(projection_connections, assignment_id)
    source = _official_source(assignment_id=assignment_id)
    before = repository.get_adjudicator_projection(
        assignment_id,
        source,
    )
    for chain in before.chains:
        repository.select_accepted_head(
            chain.tip_revision_sha256,
            reason="합성 adjudicator 선택",
            selected_at=SUBMITTED_AT.replace(minute=12),
            expected_chain_sha256=cast(str, chain.chain_sha256),
        )

    capabilities = _configure_http_runtime(monkeypatch, projection_connections)
    application = create_app()
    with TestClient(application) as client:
        response = client.get(
            f"/internal/evaluation/assignments/{assignment_id}/adjudication-projection",
            headers=_capability_header(capabilities["adjudicator"]),
        )

    assert response.status_code == 200
    payload = cast(dict[str, object], response.json())
    assert payload["release_blocked"] is False
    assert payload["accepted_revision_set_sha256"] is not None
    assert cast(list[object], payload["review_triggers"])
    serialized = response.text
    for official_text in (
        "가상의 기록관은 오래된 생활 도구의 쓰임과 조용한 안뜰을 설명한다.",
        "가상의 해설은 기록의 쓰임과 안뜰을 천천히 둘러보는 방법을 들려준다.",
        "합성 원문만으로는 강도를 확정할 수 없음",
    ):
        assert official_text in serialized
    fixture_release = cast(dict[str, object], _fixture()["release"])
    for canary in fixture_release.values():
        assert str(canary) not in serialized
    for forbidden in (
        "evaluator_principal",
        "selected_by",
        "model_output",
        "traveler",
        "session_id",
        "partition",
        "membership",
        "complement",
        "capability",
        "database_url",
        "source_path",
    ):
        assert forbidden not in serialized


def test_all_non_adjudicators_are_denied_before_source_or_projection_lookup(
    monkeypatch: pytest.MonkeyPatch,
    projection_connections: ProjectionConnections,
) -> None:
    capabilities = _configure_http_runtime(monkeypatch, projection_connections)
    calls = {"source": 0, "repository": 0}

    def reject_source(*args: object, **kwargs: object) -> object:
        calls["source"] += 1
        raise AssertionError("source lookup must follow adjudicator authorization")

    def reject_repository(*args: object, **kwargs: object) -> object:
        calls["repository"] += 1
        raise AssertionError("repository lookup must follow adjudicator authorization")

    monkeypatch.setattr(evaluation_routes, "_load_official_source_manifest", reject_source)
    monkeypatch.setattr(evaluation_routes, "get_evaluation_repository", reject_repository)
    application = create_app()
    with TestClient(application) as client:
        for capability in (
            "evaluator_a",
            "evaluator_b",
            "evaluator_c",
            "model_runner",
            "builder",
            "approver",
        ):
            response = client.get(
                "/internal/evaluation/assignments/"
                "synthetic-runtime-assignment-alpha/adjudication-projection",
                headers=_capability_header(capabilities[capability]),
            )
            assert response.status_code == 403
            assert "synthetic-runtime" not in response.text
    assert calls == {"source": 0, "repository": 0}


def test_official_source_manifest_is_digest_pinned_and_rejects_symlinks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    raw = FIXTURE_PATH.read_bytes()
    manifest_path = tmp_path / "official-source.json"
    manifest_path.write_bytes(raw)
    monkeypatch.delenv("ITDA_E2E_PHASE3_TEST_SUPPORT", raising=False)
    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_MANIFEST", str(manifest_path))
    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_SHA256", hashlib.sha256(raw).hexdigest())

    manifest = evaluation_routes._load_official_source_manifest(
        "synthetic-runtime-assignment-alpha"
    )
    assert manifest.official_source_sha256 is not None

    symlink_path = tmp_path / "official-source-link.json"
    symlink_path.symlink_to(manifest_path)
    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_MANIFEST", str(symlink_path))
    with pytest.raises(labeling.LabelExportBlocked, match="incomplete or stale"):
        evaluation_routes._load_official_source_manifest("synthetic-runtime-assignment-alpha")

    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_MANIFEST", str(manifest_path))
    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_SHA256", "0" * 64)
    with pytest.raises(labeling.LabelExportBlocked, match="incomplete or stale"):
        evaluation_routes._load_official_source_manifest("synthetic-runtime-assignment-alpha")


def test_e2e_source_manifest_binds_only_valid_attempt_namespaces(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ITDA_E2E_PHASE3_TEST_SUPPORT", "1")
    assignment_id = "synthetic-runtime-assignment-alpha-r0-e1-w2"

    manifest = evaluation_routes._load_official_source_manifest(assignment_id)

    assert manifest.assignment_id == assignment_id
    with pytest.raises(labeling.LabelExportBlocked, match="incomplete or stale"):
        evaluation_routes._load_official_source_manifest(
            "synthetic-runtime-assignment-alpha-private"
        )

    raw = FIXTURE_PATH.read_bytes()
    manifest_path = tmp_path / "official-source.json"
    manifest_path.write_bytes(raw)
    monkeypatch.delenv("ITDA_E2E_PHASE3_TEST_SUPPORT")
    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_MANIFEST", str(manifest_path))
    monkeypatch.setenv("ITDA_PHASE3_OFFICIAL_SOURCE_SHA256", hashlib.sha256(raw).hexdigest())
    with pytest.raises(labeling.LabelExportBlocked, match="incomplete or stale"):
        evaluation_routes._load_official_source_manifest(assignment_id)


def test_correction_after_route_read_makes_accepted_head_request_stale(
    monkeypatch: pytest.MonkeyPatch,
    projection_connections: ProjectionConnections,
) -> None:
    assignment_id = "synthetic-runtime-assignment-alpha-r0-e0-w0"
    for evaluator_index, evaluator_capability in enumerate(EVALUATOR_CAPABILITIES):
        with projection_connections.connect(
            evaluator_capability,
            autocommit=True,
        ) as connection:
            _submit(
                connection,
                _submission(evaluator_index, assignment_id=assignment_id),
            )
    capabilities = _configure_http_runtime(monkeypatch, projection_connections)
    application = create_app()
    url = f"/internal/evaluation/assignments/{assignment_id}/adjudication-projection"
    with TestClient(application) as client:
        projection_response = client.get(
            url,
            headers=_capability_header(capabilities["adjudicator"]),
        )
        assert projection_response.status_code == 200
        projection = labeling.AdjudicationProjection.model_validate(projection_response.json())
        stale_chain = projection.chains[0]

        with psycopg.connect(projection_connections.admin_dsn, autocommit=True) as connection:
            count_before = connection.execute(
                "SELECT count(*) FROM dev_eval.accepted_label_revisions"
            ).fetchone()
        assert count_before is not None

        evaluator_capability = next(
            capability
            for capability in EVALUATOR_CAPABILITIES
            if _principal_pseudonym(projection_connections.role_names[capability])
            == stale_chain.evaluator_pseudonym
        )
        with projection_connections.connect(evaluator_capability, autocommit=True) as connection:
            newest = _submit(
                connection,
                _submission(
                    EVALUATOR_CAPABILITIES.index(evaluator_capability),
                    assignment_id=assignment_id,
                    parent_revision_sha256=stale_chain.tip_revision_sha256,
                    correction_reason="합성 route 이후 정정 사유",
                    minute=18,
                ),
            )
        assert newest != stale_chain.tip_revision_sha256

        stale_response = client.post(
            f"/internal/evaluation/revisions/{stale_chain.tip_revision_sha256}/accepted-head",
            headers=_capability_header(capabilities["adjudicator"]),
            json={
                "reason": "합성 stale route 선택",
                "selected_at": SUBMITTED_AT.replace(minute=19).isoformat(),
                "expected_chain_sha256": stale_chain.chain_sha256,
            },
        )

    assert stale_response.status_code == 409
    assert stale_response.json() == {"detail": "phase 3 label state is incomplete or stale"}
    with psycopg.connect(projection_connections.admin_dsn, autocommit=True) as connection:
        count_after = connection.execute(
            "SELECT count(*) FROM dev_eval.accepted_label_revisions"
        ).fetchone()
    assert count_after == count_before
