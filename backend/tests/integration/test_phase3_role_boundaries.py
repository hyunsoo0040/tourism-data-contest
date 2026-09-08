"""Wave 0 RED denial matrix for Phase 3 labeling capabilities."""

from __future__ import annotations

import ast
import secrets
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
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
RUNTIME_REPOSITORY = REPOSITORY_ROOT / "backend/src/itda/db/repositories.py"
PHASE3_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)


@dataclass(frozen=True, slots=True)
class Phase3Connections:
    dsns: Mapping[str, str] = field(repr=False)
    role_names: Mapping[str, str]
    runtime_dsn: str = field(repr=False)
    schema_available: bool

    def connect(
        self, capability: str, *, autocommit: bool = False
    ) -> psycopg.Connection[tuple[object, ...]]:
        if capability == "runtime":
            return psycopg.connect(self.runtime_dsn, autocommit=autocommit)
        return psycopg.connect(self.dsns[capability], autocommit=autocommit)


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
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
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
        command.upgrade(_migration_config(postgres_harness, role_names), "head")
        with postgres_harness.connect("admin", autocommit=True) as connection:
            relation = connection.execute(
                "SELECT to_regclass('dev_eval.label_revisions')"
            ).fetchone()
        schema_available = relation == ("dev_eval.label_revisions",)
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
            dsns=MappingProxyType(dsns),
            role_names=MappingProxyType(role_names),
            runtime_dsn=postgres_harness.dsns["runtime"],
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
        pytest.fail("PHASE3-MISSING:label-role-boundary-schema", pytrace=False)


def _assert_sqlstate(
    connection: psycopg.Connection[tuple[object, ...]],
    expected: str,
    statement: object,
    params: tuple[object, ...] | None = None,
) -> None:
    try:
        connection.execute(statement, params)
    except psycopg.Error as error:
        assert error.sqlstate == expected
    else:
        raise AssertionError("hostile Phase 3 role operation unexpectedly succeeded")


def test_peer_revision_read_and_identity_switch_fail_closed(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("evaluator_a", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        _assert_sqlstate(
            connection,
            "42501",
            "SELECT * FROM dev_eval.get_label_revision_v1(%s)",
            ("synthetic-peer-revision",),
        )
        _assert_sqlstate(
            connection,
            "42501",
            sql.SQL("SET ROLE {}").format(
                sql.Identifier(phase3_connections.role_names["evaluator_b"])
            ),
        )
        _assert_sqlstate(
            connection,
            "42501",
            sql.SQL("SET SESSION AUTHORIZATION {}").format(
                sql.Identifier(phase3_connections.role_names["adjudicator"])
            ),
        )


@pytest.mark.parametrize("capability", ["runtime", "model_runner", "builder", "approver"])
def test_non_adjudication_roles_cannot_read_label_payloads_or_evaluation_relations(
    phase3_connections: Phase3Connections, capability: str
) -> None:
    with phase3_connections.connect(capability, autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        for relation in (
            "dev_eval.label_revisions",
            "dev_eval.accepted_label_revisions",
            "dev_eval.adjudicated_label_exports",
        ):
            _assert_sqlstate(
                connection,
                "42501",
                sql.SQL("SELECT * FROM {}").format(sql.SQL(relation)),
            )


def test_pre_adjudication_projection_exposes_status_only(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("builder", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        columns = connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'dev_eval' "
            "AND table_name = 'label_submission_status_v1' "
            "ORDER BY ordinal_position"
        ).fetchall()

    assert tuple(column[0] for column in columns) == (
        "evaluator_pseudonym",
        "submission_status",
        "latest_server_event_at",
        "all_required_submissions_exist",
    )


def test_adjudicator_cannot_grant_or_change_raw_revision_bytes(
    phase3_connections: Phase3Connections,
) -> None:
    with phase3_connections.connect("adjudicator", autocommit=True) as connection:
        _require_phase3_schema(phase3_connections)
        for statement in (
            "UPDATE dev_eval.label_revisions SET payload = '{}'::jsonb",
            "DELETE FROM dev_eval.label_revisions",
            sql.SQL("GRANT SELECT ON dev_eval.label_revisions TO {}").format(
                sql.Identifier(phase3_connections.role_names["model_runner"])
            ),
        ):
            _assert_sqlstate(connection, "42501", statement)


def test_runtime_repository_source_has_no_evaluation_repository_or_schema_access() -> None:
    source = RUNTIME_REPOSITORY.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }

    assert all("evaluation_repositories" not in imported for imported in imports)
    assert "dev_eval" not in source
    assert "blind_eval" not in source
