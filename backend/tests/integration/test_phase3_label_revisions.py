"""Wave 0 RED PostgreSQL contracts for immutable Phase 3 label revisions."""

from __future__ import annotations

import secrets
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from itda.db.session import sqlalchemy_url_from_dsn
from tests.integration.profile_release_test_support import (
    ensure_profile_release_authority_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
PHASE3_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)
SUBMITTED_AT = datetime(2026, 8, 3, tzinfo=UTC)
BOUNDARY_ASCII_WHITESPACE = " \t\n\r\f\v"


@dataclass(frozen=True, slots=True)
class Phase3Connections:
    admin_dsn: str = field(repr=False)
    dsns: Mapping[str, str] = field(repr=False)
    role_names: Mapping[str, str]
    schema_available: bool

    def connect(
        self, capability: str, *, autocommit: bool = False
    ) -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(self.dsns[capability], autocommit=autocommit)


def _configure_migration(postgres_harness: object, phase3_roles: Mapping[str, str]) -> Config:
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
    for capability, role_name in phase3_roles.items():
        config.attributes[f"label_{capability}_role"] = role_name
    return config


@pytest.fixture(scope="module")
def phase3_connections(postgres_harness: object) -> Iterator[Phase3Connections]:
    ensure_profile_release_authority_roles(postgres_harness)
    suffix = secrets.token_hex(4)
    role_names = {
        capability: f"itda_label_{capability}_{suffix}" for capability in PHASE3_CAPABILITIES
    }
    passwords = {capability: secrets.token_urlsafe(24) for capability in PHASE3_CAPABILITIES}
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

    try:
        command.upgrade(_configure_migration(postgres_harness, role_names), "head")
        with postgres_harness.connect("admin", autocommit=True) as connection:
            relations = connection.execute(
                "SELECT to_regclass('dev_eval.label_revisions'), "
                "to_regclass('dev_eval.accepted_label_revisions')"
            ).fetchone()
        schema_available = relations == (
            "dev_eval.label_revisions",
            "dev_eval.accepted_label_revisions",
        )
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
        yield Phase3Connections(
            admin_dsn=postgres_harness.dsns["admin"],
            dsns=MappingProxyType(dsns),
            role_names=MappingProxyType(role_names),
            schema_available=schema_available,
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


def _require_phase3_schema(connections: Phase3Connections) -> None:
    if not connections.schema_available:
        pytest.fail("PHASE3-MISSING:label-revision-schema", pytrace=False)


def _assert_sqlstate(
    connection: psycopg.Connection[tuple[object, ...]],
    expected: str,
    statement: str,
    params: tuple[object, ...] | None = None,
) -> None:
    try:
        connection.execute(statement, params)
    except psycopg.Error as error:
        assert error.sqlstate == expected
    else:
        raise AssertionError("hostile label-revision operation unexpectedly succeeded")


def _synthetic_submission(
    *,
    parent_revision_sha256: str | None = None,
    correction_reason: str | None = None,
    actor_id: str | None = None,
    role: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "assignment_id": "synthetic-assignment-alpha",
        "rubric_version": "synthetic-rubric-v1",
        "source_snapshot_version": "synthetic-source-v1",
        "primary_axis": None,
        "parent_revision_sha256": parent_revision_sha256,
        "correction_reason": correction_reason,
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
    if actor_id is not None:
        payload["actor_id"] = actor_id
    if role is not None:
        payload["role"] = role
    return payload


def _submit(
    connection: psycopg.Connection[tuple[object, ...]], payload: dict[str, object]
) -> tuple[str, str]:
    row = connection.execute(
        "SELECT revision_sha256, evaluator_principal "
        "FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
        (psycopg.types.json.Jsonb(payload),),
    ).fetchone()
    assert row is not None
    return str(row[0]), str(row[1])


def _score_four_submission(
    *, second_lane: str, second_cluster: str, second_concordance_key: str
) -> dict[str, object]:
    payload = _synthetic_submission()
    judgments = payload["judgments"]
    assert isinstance(judgments, list)
    judgments[0] = {
        "attribute_id": "H1",
        "score": 4,
        "unknown_reason": None,
        "unknown_note": None,
        "evidence": [
            {
                "evidence_id": "synthetic-first",
                "source_id": "synthetic-description-source",
                "lane": "DESCRIPTION",
                "dedup_cluster_id": "synthetic-cluster-a",
                "direct": True,
                "concordance_key": "synthetic-theme-a",
                "supports_absence": False,
                "complete_context": False,
            },
            {
                "evidence_id": "synthetic-second",
                "source_id": f"synthetic-{second_lane.lower()}-source",
                "lane": second_lane,
                "dedup_cluster_id": second_cluster,
                "direct": True,
                "concordance_key": second_concordance_key,
                "supports_absence": False,
                "complete_context": False,
            },
        ],
    }
    return payload


def _unknown_note_submission(note: object) -> dict[str, object]:
    payload = _synthetic_submission()
    judgments = payload["judgments"]
    assert isinstance(judgments, list)
    judgments[0] = {
        "attribute_id": "H1",
        "score": None,
        "unknown_reason": "NO_EVIDENCE",
        "unknown_note": note,
        "evidence": [],
    }
    return payload


@pytest.mark.parametrize(
    "note",
    [
        True,
        7,
        3.5,
        *[f"{boundary}합성 설명" for boundary in BOUNDARY_ASCII_WHITESPACE],
        *[f"합성 설명{boundary}" for boundary in BOUNDARY_ASCII_WHITESPACE],
    ],
)
def test_direct_evaluator_rejects_nonstring_or_ascii_untrimmed_unknown_note(
    phase3_connections: Phase3Connections,
    note: object,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT * FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
            (psycopg.types.json.Jsonb(_unknown_note_submission(note)),),
        )


@pytest.mark.parametrize("note", ["true", "7", "3.5", "\u00a0합성 설명\u2003", "\u00a0\u2003"])
def test_direct_evaluator_preserves_valid_unknown_note_strings(
    phase3_connections: Phase3Connections,
    note: str,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        revision_sha256, _ = _submit(connection, _unknown_note_submission(note))
    with psycopg.connect(phase3_connections.admin_dsn, autocommit=True) as connection:
        stored_note = connection.execute(
            "SELECT payload->'judgments'->0->>'unknown_note' "
            "FROM dev_eval.label_revisions WHERE revision_sha256 = %s",
            (revision_sha256,),
        ).fetchone()

    assert stored_note == (note,)


@pytest.mark.parametrize(
    "malformation",
    [
        "missing_score",
        "string_score",
        "missing_direct",
        "string_direct",
        "missing_supports_absence",
        "string_supports_absence",
        "missing_complete_context",
        "string_complete_context",
        "missing_concordance_key",
        "unknown_evidence_key",
    ],
)
def test_direct_evaluator_submission_rejects_noncanonical_judgment_shape(
    phase3_connections: Phase3Connections,
    malformation: str,
) -> None:
    payload = (
        _score_four_submission(
            second_lane="DESCRIPTION",
            second_cluster="synthetic-cluster-b",
            second_concordance_key="synthetic-theme-z",
        )
        if malformation == "string_score"
        else _synthetic_submission()
    )
    judgments = payload["judgments"]
    assert isinstance(judgments, list)
    judgment = judgments[0]
    assert isinstance(judgment, dict)
    evidence = judgment["evidence"]
    assert isinstance(evidence, list)
    if not evidence:
        evidence.append(
            {
                "evidence_id": "synthetic-first",
                "source_id": "synthetic-description-source",
                "lane": "DESCRIPTION",
                "dedup_cluster_id": "synthetic-cluster-a",
                "direct": True,
                "concordance_key": "synthetic-theme-a",
                "supports_absence": False,
                "complete_context": False,
            }
        )
    evidence_item = evidence[0]
    assert isinstance(evidence_item, dict)

    if malformation == "missing_score":
        judgment.pop("score")
    elif malformation == "string_score":
        judgment["score"] = "4"
    elif malformation.startswith("missing_"):
        evidence_item.pop(malformation.removeprefix("missing_"))
    elif malformation.startswith("string_"):
        evidence_item[malformation.removeprefix("string_")] = "false"
    else:
        evidence_item["unexpected"] = "forbidden"

    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT * FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
            (psycopg.types.json.Jsonb(payload),),
        )


@pytest.mark.parametrize(
    "malformation",
    [
        "numeric_assignment_id",
        "numeric_rubric_version",
        "numeric_source_snapshot_version",
        "invalid_rubric_version",
        "invalid_source_snapshot_version",
        "missing_primary_axis",
        "missing_parent_revision_sha256",
        "missing_correction_reason",
        "missing_submitted_at",
        "numeric_submitted_at",
        "non_utc_submitted_at",
        "malformed_parent_revision_sha256",
        "empty_correction_reason",
        "overlong_correction_reason",
        "untrimmed_correction_reason",
        "control_whitespace_correction_reason",
    ],
)
def test_direct_evaluator_submission_rejects_noncanonical_top_level_shape(
    phase3_connections: Phase3Connections,
    malformation: str,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        payload = _synthetic_submission()
        if malformation.endswith("correction_reason"):
            parent_sha256, _ = _submit(connection, payload)
            payload = _synthetic_submission(
                parent_revision_sha256=parent_sha256,
                correction_reason="합성 correction 사유",
            )

        if malformation == "numeric_assignment_id":
            payload["assignment_id"] = 7
        elif malformation == "numeric_rubric_version":
            payload["rubric_version"] = 7
        elif malformation == "numeric_source_snapshot_version":
            payload["source_snapshot_version"] = 7
        elif malformation == "invalid_rubric_version":
            payload["rubric_version"] = "Invalid Version"
        elif malformation == "invalid_source_snapshot_version":
            payload["source_snapshot_version"] = "INVALID"
        elif malformation.startswith("missing_"):
            payload.pop(malformation.removeprefix("missing_"))
        elif malformation == "numeric_submitted_at":
            payload["submitted_at"] = 1_786_000_000
        elif malformation == "non_utc_submitted_at":
            payload["submitted_at"] = "2026-08-03T09:00:00+09:00"
        elif malformation == "malformed_parent_revision_sha256":
            payload["parent_revision_sha256"] = "g" * 64
            payload["correction_reason"] = "합성 correction 사유"
        elif malformation == "empty_correction_reason":
            payload["correction_reason"] = ""
        elif malformation == "overlong_correction_reason":
            payload["correction_reason"] = "가" * 301
        elif malformation == "control_whitespace_correction_reason":
            payload["correction_reason"] = "\t합성 correction 사유\n"
        else:
            payload["correction_reason"] = " 앞뒤 공백 "

        _assert_sqlstate(
            connection,
            "22023",
            "SELECT * FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
            (psycopg.types.json.Jsonb(payload),),
        )


@pytest.mark.parametrize(
    ("second_lane", "second_concordance_key"),
    [
        ("DESCRIPTION", "synthetic-theme-z"),
        ("ODII", "synthetic-theme-z"),
    ],
)
def test_score_four_accepts_two_distinct_direct_clusters_in_any_lane_layout(
    phase3_connections: Phase3Connections,
    second_lane: str,
    second_concordance_key: str,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        revision_sha256, _ = _submit(
            connection,
            _score_four_submission(
                second_lane=second_lane,
                second_cluster="synthetic-cluster-b",
                second_concordance_key=second_concordance_key,
            ),
        )

    assert len(revision_sha256) == 64


def test_score_four_rejects_duplicate_cluster_across_lanes_and_concordance_keys(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT * FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
            (
                psycopg.types.json.Jsonb(
                    _score_four_submission(
                        second_lane="ODII",
                        second_cluster="synthetic-cluster-a",
                        second_concordance_key="synthetic-theme-z",
                    )
                ),
            ),
        )


def test_server_principal_owns_submission_and_body_actor_role_are_rejected(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT * FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
            (
                psycopg.types.json.Jsonb(
                    _synthetic_submission(actor_id="synthetic-forged-actor", role="adjudicator")
                ),
            ),
        )
        revision_sha256, principal = _submit(connection, _synthetic_submission())

    assert principal == phase3_connections.role_names["evaluator_a"]
    assert len(revision_sha256) == 64


def test_submitted_revision_rejects_update_delete_and_grant(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        revision_sha256, _ = _submit(connection, _synthetic_submission())
        for statement in (
            "UPDATE dev_eval.label_revisions SET payload = '{}'::jsonb WHERE revision_sha256 = %s",
            "DELETE FROM dev_eval.label_revisions WHERE revision_sha256 = %s",
            "GRANT SELECT ON dev_eval.label_revisions TO PUBLIC",
        ):
            params = (revision_sha256,) if "%s" in statement else None
            _assert_sqlstate(connection, "42501", statement, params)


def test_correction_appends_reason_bound_parent_without_mutating_predecessor(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        parent_sha256, _ = _submit(connection, _synthetic_submission())
        parent_bytes = connection.execute(
            "SELECT convert_to(payload::text, 'UTF8') FROM dev_eval.own_label_revisions_v1 "
            "WHERE revision_sha256 = %s",
            (parent_sha256,),
        ).fetchone()
        assert parent_bytes is not None

        for payload in (
            _synthetic_submission(parent_revision_sha256=parent_sha256),
            _synthetic_submission(correction_reason="합성 correction 사유"),
            _synthetic_submission(
                parent_revision_sha256="0" * 64,
                correction_reason="합성 correction 사유",
            ),
        ):
            _assert_sqlstate(
                connection,
                "22023",
                "SELECT * FROM dev_eval.submit_label_revision_v1(%s::jsonb)",
                (psycopg.types.json.Jsonb(payload),),
            )

        correction_sha256, _ = _submit(
            connection,
            _synthetic_submission(
                parent_revision_sha256=parent_sha256,
                correction_reason="합성 correction 사유",
            ),
        )
        parent_after = connection.execute(
            "SELECT convert_to(payload::text, 'UTF8') FROM dev_eval.own_label_revisions_v1 "
            "WHERE revision_sha256 = %s",
            (parent_sha256,),
        ).fetchone()

    assert correction_sha256 != parent_sha256
    assert parent_after == parent_bytes
