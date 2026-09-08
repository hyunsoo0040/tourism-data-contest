"""Wave 0 RED fault contract for atomic profile release transitions."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import secrets
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType, ModuleType
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
from sqlalchemy import Engine

from itda.api.dependencies import (
    Phase3Principal,
    get_evaluation_repository,
    get_phase3_principal,
)
from itda.api.main import create_app
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
from itda.domain.canonical import canonical_sha256

CAPABILITY_MODULE = "itda.contracts.profile_release"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
PROFILE_RELEASE_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)
PROFILE_RELEASE_WRITE_AUTHORITY_ROLE = "itda_profile_release_write_authority"
PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE = "itda_profile_release_authority_service"
TEST_PROFILE_RELEASE_AUTHORIZATION_HMAC_KEY_HEX = "41" * 32
_TEST_ADMIN_DSN_BY_BUILDER: dict[str, str] = {}
PIN_RELATIONS = (
    "profile_release_session_pins",
    "profile_release_result_pins",
)


@dataclass(frozen=True, slots=True)
class ProfileReleaseConnections:
    dsns: Mapping[str, str] = field(repr=False)
    role_names: Mapping[str, str]
    runtime_dsn: str = field(repr=False)
    base_role_names: Mapping[str, str]

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
    config.attributes["profile_release_authorization_hmac_key"] = (
        TEST_PROFILE_RELEASE_AUTHORIZATION_HMAC_KEY_HEX
    )
    return config


def _assert_single_head_contains_revision(
    script: ScriptDirectory,
    revision: str,
) -> None:
    head = script.get_current_head()
    assert head is not None
    assert revision in {candidate.revision for candidate in script.iterate_revisions(head, "base")}


def profile_release_build_authority(
    repository: EvaluationRepository,
    candidate: Any,
) -> Any:
    """Provision one exact synthetic authority through the test admin boundary."""

    builder = repository.profile_release_builder_database_principal()
    authority_root = canonical_sha256(
        {
            "schema_version": "itda.synthetic-fixed-root.v1",
            "candidate": candidate.model_dump(mode="json"),
        }
    )
    resolution = _fixed_root_build_resolution(
        candidate=candidate,
        authority_root_sha256=authority_root,
        authority_registry_id=uuid5(
            NAMESPACE_URL,
            f"{authority_root}:{candidate.release_sha256}:{builder}",
        ),
        builder_database_principal=builder,
        expected_predecessor_sha256=(
            candidate.lineage.predecessor_release_sha256 if hasattr(candidate, "lineage") else None
        ),
    )
    admin_dsn = _TEST_ADMIN_DSN_BY_BUILDER.get(builder)
    if admin_dsn is None:
        raise AssertionError("test fixed-root registry admin is unavailable")
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        register_profile_release_build_authority(connection, resolution)
    return resolution


def register_profile_release_builder_admin(builder: str, admin_dsn: str) -> None:
    """Bind one synthetic builder principal to its explicit test admin boundary."""

    existing = _TEST_ADMIN_DSN_BY_BUILDER.setdefault(builder, admin_dsn)
    if existing != admin_dsn:
        raise AssertionError("test builder is already bound to a different registry admin")


def unregister_profile_release_builder_admin(builder: str) -> None:
    _TEST_ADMIN_DSN_BY_BUILDER.pop(builder, None)


def register_profile_release_build_authority(
    connection: psycopg.Connection[tuple[object, ...]],
    resolution: ProfileReleaseBuildAuthorityResolution,
) -> None:
    """Populate the DB-owned registry using a test-only admin connection."""

    connection.execute(
        "INSERT INTO dev_eval.profile_release_fixed_root_authorities_v1 ("
        "authority_registry_id, candidate_payload, candidate_sha256, "
        "authority_root_sha256, builder_database_principal, "
        "expected_predecessor_sha256, "
        "expected_predecessor_lifecycle_receipt_sha256, resolution_sha256) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
        (
            str(resolution.authority_registry_id),
            psycopg.types.json.Jsonb(resolution.candidate.model_dump(mode="json")),
            resolution.candidate_sha256,
            resolution.authority_root_sha256,
            resolution.builder_database_principal,
            resolution.expected_predecessor_sha256,
            resolution.expected_predecessor_lifecycle_receipt_sha256,
            resolution.resolution_sha256,
        ),
    )
    stored = connection.execute(
        "SELECT candidate_payload, candidate_sha256, authority_root_sha256, "
        "builder_database_principal, expected_predecessor_sha256, "
        "expected_predecessor_lifecycle_receipt_sha256, resolution_sha256 "
        "FROM dev_eval.profile_release_fixed_root_authorities_v1 "
        "WHERE candidate_sha256 = %s",
        (resolution.candidate_sha256,),
    ).fetchone()
    assert stored == (
        resolution.candidate.model_dump(mode="json"),
        resolution.candidate_sha256,
        resolution.authority_root_sha256,
        resolution.builder_database_principal,
        resolution.expected_predecessor_sha256,
        resolution.expected_predecessor_lifecycle_receipt_sha256,
        resolution.resolution_sha256,
    )


@pytest.fixture(scope="module")
def profile_release_connections(
    postgres_harness: object,
) -> Iterator[ProfileReleaseConnections]:
    suffix = secrets.token_hex(4)
    role_names = {
        capability: f"itda_profile_{capability}_{suffix}"
        for capability in PROFILE_RELEASE_CAPABILITIES
    }
    role_names["write_authority"] = PROFILE_RELEASE_WRITE_AUTHORITY_ROLE
    role_names["authority_service"] = PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE
    passwords = {
        capability: secrets.token_urlsafe(24) for capability in PROFILE_RELEASE_CAPABILITIES
    }
    passwords["authority_service"] = secrets.token_urlsafe(24)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    with postgres_harness.connect("admin", autocommit=True) as connection:
        for capability in PROFILE_RELEASE_CAPABILITIES:
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
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS NOINHERIT"
            ).format(sql.Identifier(PROFILE_RELEASE_WRITE_AUTHORITY_ROLE))
        )
        connection.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
            ).format(
                sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE),
                sql.Literal(passwords["authority_service"]),
            )
        )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE),
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
            for capability in PROFILE_RELEASE_CAPABILITIES
        }
        dsns["authority_service"] = make_conninfo(
            **(
                admin_info
                | {
                    "user": PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
                    "password": passwords["authority_service"],
                }
            )
        )
        register_profile_release_builder_admin(
            role_names["builder"], postgres_harness.dsns["admin"]
        )
        yield ProfileReleaseConnections(
            dsns=MappingProxyType(dsns),
            role_names=MappingProxyType(role_names),
            runtime_dsn=postgres_harness.dsns["runtime"],
            base_role_names=postgres_harness.role_names,
        )
    finally:
        unregister_profile_release_builder_admin(role_names["builder"])
        with postgres_harness.connect("admin", autocommit=True) as connection:
            for capability in reversed(PROFILE_RELEASE_CAPABILITIES):
                role_name = role_names[capability]
                connection.execute(
                    sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role_name))
                )
                connection.execute(
                    sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_name))
                )
            connection.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(
                    sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE)
                )
            )
            connection.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(
                    sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE)
                )
            )
            connection.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(
                    sql.Identifier(PROFILE_RELEASE_WRITE_AUTHORITY_ROLE)
                )
            )
            connection.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(
                    sql.Identifier(PROFILE_RELEASE_WRITE_AUTHORITY_ROLE)
                )
            )


@pytest.fixture(autouse=True)
def restore_profile_release_migration_head(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> Iterator[None]:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    try:
        yield
    finally:
        command.upgrade(config, "head")


def _privilege_snapshot(
    connection: psycopg.Connection[tuple[object, ...]],
) -> tuple[tuple[str, ...], ...]:
    rows = connection.execute(
        "SELECT 'TABLE', table_name, grantee, privilege_type, is_grantable "
        "FROM information_schema.table_privileges "
        "WHERE table_schema = 'dev_eval' "
        "UNION ALL "
        "SELECT 'ROUTINE', routine_name, grantee, privilege_type, is_grantable "
        "FROM information_schema.routine_privileges "
        "WHERE routine_schema = 'dev_eval' "
        "ORDER BY 1, 2, 3, 4, 5"
    ).fetchall()
    return tuple(tuple(str(value) for value in row) for row in rows)


def _pin_privilege_row(*, relation: str, grantee: str, privilege: str) -> tuple[str, ...]:
    return ("TABLE", relation, grantee, privilege, "NO")


def test_profile_pin_migration_is_linear_idempotent_and_exactly_scoped(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    script = ScriptDirectory.from_config(config)
    _assert_single_head_contains_revision(
        script,
        "0014_phase4_profile_release_write_boundary",
    )
    assert script.get_revision("0012_phase3_profile_pin_provenance").down_revision == (
        "0011_phase3_score4_evidence_rule"
    )
    assert script.get_revision("0009_phase3_profile_pin_privileges").down_revision == (
        "0008_phase3_profile_releases"
    )

    command.downgrade(config, "0008_phase3_profile_releases")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        before = _privilege_snapshot(connection)

    command.upgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        after = _privilege_snapshot(connection)

    builder = profile_release_connections.role_names["builder"]
    approver = profile_release_connections.role_names["approver"]
    expected_added = {
        _pin_privilege_row(relation=relation, grantee=builder, privilege="INSERT")
        for relation in PIN_RELATIONS
    }
    expected_removed = {
        _pin_privilege_row(relation=relation, grantee=approver, privilege="INSERT")
        for relation in PIN_RELATIONS
    }
    assert set(after) - set(before) == expected_added
    assert set(before) - set(after) == expected_removed

    for relation in PIN_RELATIONS:
        assert _pin_privilege_row(relation=relation, grantee=builder, privilege="SELECT") in after
        assert _pin_privilege_row(relation=relation, grantee=approver, privilege="SELECT") in after
        for denied_role in (
            *(
                profile_release_connections.role_names[capability]
                for capability in PROFILE_RELEASE_CAPABILITIES
                if capability not in {"builder", "approver"}
            ),
            *(
                profile_release_connections.base_role_names[capability]
                for capability in ("runtime", "dev", "sealer", "evaluator")
            ),
            "PUBLIC",
        ):
            assert (
                _pin_privilege_row(relation=relation, grantee=denied_role, privilege="INSERT")
                not in after
            )

    command.upgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert _privilege_snapshot(connection) == after

    command.downgrade(config, "0008_phase3_profile_releases")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert _privilege_snapshot(connection) == before

    command.upgrade(config, "0009_phase3_profile_pin_privileges")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert _privilege_snapshot(connection) == after
    command.upgrade(config, "head")
    _assert_single_head_contains_revision(
        ScriptDirectory.from_config(config),
        "0014_phase4_profile_release_write_boundary",
    )


def test_profile_pin_provenance_migration_grants_only_narrow_execute(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    command.downgrade(config, "0011_phase3_score4_evidence_rule")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        before = _privilege_snapshot(connection)
        assert connection.execute(
            "SELECT to_regprocedure("
            "'dev_eval.validate_active_profile_release_for_pin_v1(text,text)')"
        ).fetchone() == (None,)

    command.upgrade(config, "0012_phase3_profile_pin_provenance")
    builder = profile_release_connections.role_names["builder"]
    expected_execute = (
        "ROUTINE",
        "validate_active_profile_release_for_pin_v1",
        builder,
        "EXECUTE",
        "NO",
    )
    with postgres_harness.connect("admin", autocommit=True) as connection:
        after = _privilege_snapshot(connection)
        added = set(after) - set(before)
        assert expected_execute in added
        assert {
            row for row in added if row[2] != profile_release_connections.base_role_names["admin"]
        } == {expected_execute}
        assert connection.execute(
            "SELECT prosecdef, provolatile, proisstrict, "
            "proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[] "
            "FROM pg_proc WHERE oid = "
            "to_regprocedure("
            "'dev_eval.validate_active_profile_release_for_pin_v1(text,text)')"
        ).fetchone() == (True, "s", True, True)
        assert (
            "ROUTINE",
            "validate_active_profile_release_for_pin_v1",
            "PUBLIC",
            "EXECUTE",
            "NO",
        ) not in after

    command.downgrade(config, "0011_phase3_score4_evidence_rule")
    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert _privilege_snapshot(connection) == before
    command.upgrade(config, "head")


@contextmanager
def _client_as(
    connections: ProfileReleaseConnections,
    capability: str,
) -> Iterator[TestClient]:
    principal = Phase3Principal(
        actor_id=f"phase3-{capability.replace('_', '-')}",
        role=capability,
    )
    engine: Engine = create_database_engine(
        connections.runtime_dsn if capability == "runtime" else connections.dsns[capability]
    )
    authority_engine: Engine | None = None
    authority_factory = None
    if capability == "builder":
        authority_engine = create_database_engine(connections.dsns["authority_service"])
        authority_factory = create_session_factory(authority_engine)
    repository = EvaluationRepository(
        create_session_factory(engine),
        authority_connection_factory=authority_factory,
    )
    application = create_app()
    application.dependency_overrides[get_phase3_principal] = lambda: principal
    application.dependency_overrides[get_evaluation_repository] = lambda: repository
    try:
        with TestClient(application, raise_server_exceptions=False) as client:
            yield client
    finally:
        application.dependency_overrides.clear()
        engine.dispose()
        if authority_engine is not None:
            authority_engine.dispose()


def _seed_corrupt_active_profile_release(
    postgres_harness: object,
    *,
    release_sha256: str,
    release_id: str,
) -> None:
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "INSERT INTO dev_eval.profile_releases ("
            "release_sha256, release_id, builder_principal, canonical_lineage_sha256, "
            "dev_lineage_sha256, profile_schema_sha256, payload) VALUES ("
            "%s, %s, 'phase3-builder', %s, %s, %s, '{}'::jsonb) "
            "ON CONFLICT (release_sha256) DO NOTHING",
            (release_sha256, release_id, "a" * 64, "b" * 64, "c" * 64),
        )
        connection.execute(
            "INSERT INTO dev_eval.profile_release_lifecycle_heads ("
            "release_sha256, state, head_receipt_sha256) VALUES (%s, 'ACTIVE', %s) "
            "ON CONFLICT (release_sha256) DO UPDATE SET state = 'ACTIVE', "
            "head_receipt_sha256 = EXCLUDED.head_receipt_sha256",
            (release_sha256, "d" * 64),
        )
        connection.execute(
            "INSERT INTO dev_eval.profile_release_active_pointer ("
            "slot, release_sha256, receipt_sha256) VALUES ('DEV', %s, %s) "
            "ON CONFLICT (slot) DO UPDATE SET release_sha256 = EXCLUDED.release_sha256, "
            "receipt_sha256 = EXCLUDED.receipt_sha256",
            (release_sha256, "d" * 64),
        )


def _remove_corrupt_active_profile_release(
    postgres_harness: object,
    *,
    release_sha256: str,
) -> None:
    with postgres_harness.connect("admin", autocommit=True) as connection:
        stored = connection.execute(
            "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = %s",
            (release_sha256,),
        ).fetchone()
        if stored != ({},):
            raise AssertionError("corrupt profile release cleanup targeted an unexpected row")
        connection.execute("TRUNCATE dev_eval.profile_releases CASCADE")


def _clear_profile_release_state_for_downgrade(postgres_harness: object) -> None:
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(
            "TRUNCATE dev_eval.profile_releases, "
            "dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1, "
            "dev_eval.profile_release_build_drafts, "
            "dev_eval.profile_release_build_receipts, "
            "dev_eval.profile_release_build_nonce_reservations, "
            "dev_eval.profile_release_nonce_quarantine_0010 CASCADE"
        )


def _seed_active_profile_release(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
    *,
    release_id: str,
) -> str:
    payload = _candidate_payload(release_id=release_id)
    payload["builder_principal"] = "phase3-builder"
    candidate = _capability().ProfileReleaseCandidate.model_validate(payload)
    builder_engine = create_database_engine(profile_release_connections.dsns["builder"])
    approver_engine = create_database_engine(profile_release_connections.dsns["approver"])
    authority_engine = create_database_engine(profile_release_connections.dsns["authority_service"])
    builder_repository = EvaluationRepository(
        create_session_factory(builder_engine),
        authority_connection_factory=create_session_factory(authority_engine),
    )
    approver_repository = EvaluationRepository(create_session_factory(approver_engine))
    release_sha256 = str(candidate.release_sha256)
    try:
        builder_repository.build_profile_release(
            profile_release_build_authority(builder_repository, candidate),
            authenticated_principal="phase3-builder",
            reconciliation_nonce=hashlib.sha256(f"build:{release_id}".encode()).hexdigest(),
        )
        approver_repository.approve_profile_release(
            release_sha256,
            authenticated_principal="phase3-approver",
        )
        current = approver_repository.get_profile_release_active_pointer().active_release_sha256
        approver_repository.activate_profile_release(
            release_sha256,
            expected_current=current,
            authenticated_principal="phase3-approver",
            nonce=hashlib.sha256(f"activate:{release_id}".encode()).hexdigest(),
        )
    finally:
        builder_engine.dispose()
        approver_engine.dispose()
        authority_engine.dispose()
    return release_sha256


def _assert_sqlstate(
    connection: psycopg.Connection[tuple[object, ...]],
    expected: str,
    statement: object,
    params: tuple[object, ...],
) -> None:
    try:
        connection.execute(statement, params)
    except psycopg.Error as error:
        assert error.sqlstate == expected
    else:
        raise AssertionError("hostile profile pin mutation unexpectedly succeeded")


def _direct_pin_insert(
    connections: ProfileReleaseConnections,
    capability: str,
    *,
    relation: str,
    owner_column: str,
    owner_ref: str,
    release_sha256: str,
) -> None:
    statement = sql.SQL(
        "INSERT INTO dev_eval.{} ({}, release_sha256, pin_sha256) VALUES (%s, %s, %s)"
    ).format(sql.Identifier(relation), sql.Identifier(owner_column))
    pin_sha256 = hashlib.sha256(owner_ref.encode("utf-8")).hexdigest()
    with connections.connect(capability, autocommit=True) as connection:
        _assert_sqlstate(
            connection,
            "42501",
            statement,
            (owner_ref, release_sha256, pin_sha256),
        )


def test_builder_can_pin_session_and_result_while_other_roles_cannot(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    _clear_profile_release_state_for_downgrade(postgres_harness)
    command.downgrade(config, "0008_phase3_profile_releases")
    release_sha256 = "1" * 64
    _seed_corrupt_active_profile_release(
        postgres_harness,
        release_sha256=release_sha256,
        release_id="synthetic-pin-authority-red",
    )

    with _client_as(profile_release_connections, "builder") as client:
        pre_0009_session = client.post(
            "/internal/evaluation/profile-releases/sessions/synthetic-session-authority/pin"
        )
        pre_0009_result = client.post(
            "/internal/evaluation/profile-releases/results/synthetic-result-authority/pin"
        )
    assert pre_0009_session.status_code == pre_0009_result.status_code == 500

    command.upgrade(config, "0009_phase3_profile_pin_privileges")
    _remove_corrupt_active_profile_release(
        postgres_harness,
        release_sha256=release_sha256,
    )
    command.upgrade(config, "head")
    release_sha256 = _seed_active_profile_release(
        postgres_harness,
        profile_release_connections,
        release_id="synthetic-pin-authority",
    )
    with profile_release_connections.connect("builder", autocommit=True) as connection:
        assert connection.execute(
            "SELECT dev_eval.validate_active_profile_release_for_pin_v1("
            "%s, (SELECT receipt_sha256 FROM "
            "dev_eval.profile_release_active_pointer WHERE slot = 'DEV'))",
            (release_sha256,),
        ).fetchone() == (True,)
    with _client_as(profile_release_connections, "builder") as client:
        session_response = client.post(
            "/internal/evaluation/profile-releases/sessions/synthetic-session-authority/pin"
        )
        result_response = client.post(
            "/internal/evaluation/profile-releases/results/synthetic-result-authority/pin"
        )

    assert session_response.status_code == result_response.status_code == 201
    assert session_response.json()["release_sha256"] == release_sha256
    assert result_response.json()["release_sha256"] == release_sha256
    with postgres_harness.connect("admin", autocommit=True) as connection:
        stored_session = connection.execute(
            "SELECT release_sha256, pin_sha256 FROM "
            "dev_eval.profile_release_session_pins WHERE session_ref = %s",
            ("synthetic-session-authority",),
        ).fetchone()
        stored_result = connection.execute(
            "SELECT release_sha256, pin_sha256 FROM "
            "dev_eval.profile_release_result_pins WHERE result_ref = %s",
            ("synthetic-result-authority",),
        ).fetchone()
    assert stored_session == (
        session_response.json()["release_sha256"],
        session_response.json()["pin_sha256"],
    )
    assert stored_result == (
        result_response.json()["release_sha256"],
        result_response.json()["pin_sha256"],
    )

    for capability in (
        "approver",
        "evaluator_a",
        "evaluator_b",
        "evaluator_c",
        "adjudicator",
        "model_runner",
    ):
        with _client_as(profile_release_connections, capability) as client:
            assert (
                client.post(
                    f"/internal/evaluation/profile-releases/sessions/"
                    f"synthetic-session-{capability}/pin"
                ).status_code
                == 403
            )
            assert (
                client.post(
                    f"/internal/evaluation/profile-releases/results/"
                    f"synthetic-result-{capability}/pin"
                ).status_code
                == 403
            )

    with profile_release_connections.connect("approver", autocommit=True) as connection:
        assert (
            connection.execute(
                "SELECT release_sha256, pin_sha256 FROM "
                "dev_eval.profile_release_session_pins WHERE session_ref = %s",
                ("synthetic-session-authority",),
            ).fetchone()
            == stored_session
        )
        assert (
            connection.execute(
                "SELECT release_sha256, pin_sha256 FROM "
                "dev_eval.profile_release_result_pins WHERE result_ref = %s",
                ("synthetic-result-authority",),
            ).fetchone()
            == stored_result
        )

    for capability in PROFILE_RELEASE_CAPABILITIES:
        if capability == "builder":
            continue
        for relation, owner_column in (
            ("profile_release_session_pins", "session_ref"),
            ("profile_release_result_pins", "result_ref"),
        ):
            _direct_pin_insert(
                profile_release_connections,
                capability,
                relation=relation,
                owner_column=owner_column,
                owner_ref=f"synthetic-direct-{capability}-{relation}",
                release_sha256=release_sha256,
            )

    for capability in ("runtime", "dev", "sealer", "evaluator"):
        for relation, owner_column in (
            ("profile_release_session_pins", "session_ref"),
            ("profile_release_result_pins", "result_ref"),
        ):
            statement = sql.SQL(
                "INSERT INTO dev_eval.{} ({}, release_sha256, pin_sha256) VALUES (%s, %s, %s)"
            ).format(sql.Identifier(relation), sql.Identifier(owner_column))
            owner_ref = f"synthetic-base-{capability}-{relation}"
            with postgres_harness.connect(capability, autocommit=True) as connection:
                _assert_sqlstate(
                    connection,
                    "42501",
                    statement,
                    (
                        owner_ref,
                        release_sha256,
                        hashlib.sha256(owner_ref.encode("utf-8")).hexdigest(),
                    ),
                )

    repository_looked_up = False

    def forbidden_repository_lookup() -> EvaluationRepository:
        nonlocal repository_looked_up
        repository_looked_up = True
        raise AssertionError("unauthenticated pin request reached the repository")

    application = create_app()
    application.dependency_overrides[get_evaluation_repository] = forbidden_repository_lookup
    try:
        with TestClient(application, raise_server_exceptions=False) as client:
            unauthenticated = client.post(
                "/internal/evaluation/profile-releases/sessions/"
                "synthetic-session-unauthenticated/pin"
            )
    finally:
        application.dependency_overrides.clear()
    assert unauthenticated.status_code == 401
    assert repository_looked_up is False


def test_database_pins_remain_copy_once_across_active_pointer_changes(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    config = _migration_config(postgres_harness, profile_release_connections.role_names)
    _clear_profile_release_state_for_downgrade(postgres_harness)
    command.downgrade(config, "0008_phase3_profile_releases")
    corrupt_release = "2" * 64
    _seed_corrupt_active_profile_release(
        postgres_harness,
        release_sha256=corrupt_release,
        release_id="synthetic-copy-once-first-red",
    )
    session_path = "/internal/evaluation/profile-releases/sessions/synthetic-session-copy-once/pin"
    result_path = "/internal/evaluation/profile-releases/results/synthetic-result-copy-once/pin"

    with _client_as(profile_release_connections, "builder") as client:
        pre_0009_session = client.post(session_path)
        pre_0009_result = client.post(result_path)
    assert pre_0009_session.status_code == pre_0009_result.status_code == 500

    command.upgrade(config, "0009_phase3_profile_pin_privileges")
    _remove_corrupt_active_profile_release(
        postgres_harness,
        release_sha256=corrupt_release,
    )
    command.upgrade(config, "head")
    first_release = _seed_active_profile_release(
        postgres_harness,
        profile_release_connections,
        release_id="synthetic-copy-once-first",
    )
    with _client_as(profile_release_connections, "builder") as client:
        first_session = client.post(session_path)
        first_result = client.post(result_path)
    assert first_session.status_code == first_result.status_code == 201
    with postgres_harness.connect("admin", autocommit=True) as connection:
        before = (
            connection.execute(
                "SELECT session_ref, release_sha256, pin_sha256, pinned_at FROM "
                "dev_eval.profile_release_session_pins WHERE session_ref = %s",
                ("synthetic-session-copy-once",),
            ).fetchone(),
            connection.execute(
                "SELECT result_ref, release_sha256, pin_sha256, pinned_at FROM "
                "dev_eval.profile_release_result_pins WHERE result_ref = %s",
                ("synthetic-result-copy-once",),
            ).fetchone(),
        )

    _seed_active_profile_release(
        postgres_harness,
        profile_release_connections,
        release_id="synthetic-copy-once-second",
    )
    with _client_as(profile_release_connections, "builder") as client:
        replayed_session = client.post(session_path)
        replayed_result = client.post(result_path)

    assert replayed_session.status_code == replayed_result.status_code == 201
    assert replayed_session.json() == first_session.json()
    assert replayed_result.json() == first_result.json()
    assert first_session.json()["release_sha256"] == first_release
    assert first_result.json()["release_sha256"] == first_release
    with postgres_harness.connect("admin", autocommit=True) as connection:
        after = (
            connection.execute(
                "SELECT session_ref, release_sha256, pin_sha256, pinned_at FROM "
                "dev_eval.profile_release_session_pins WHERE session_ref = %s",
                ("synthetic-session-copy-once",),
            ).fetchone(),
            connection.execute(
                "SELECT result_ref, release_sha256, pin_sha256, pinned_at FROM "
                "dev_eval.profile_release_result_pins WHERE result_ref = %s",
                ("synthetic-result-copy-once",),
            ).fetchone(),
        )
    assert after == before


def test_approver_reads_existing_session_pin_without_mutation(
    postgres_harness: object,
    profile_release_connections: ProfileReleaseConnections,
) -> None:
    session_ref = "synthetic-session-approver-read-only"
    release_sha256 = _seed_active_profile_release(
        postgres_harness,
        profile_release_connections,
        release_id="synthetic-approver-pin-projection",
    )
    path = f"/internal/evaluation/profile-releases/sessions/{session_ref}/pin"
    with _client_as(profile_release_connections, "builder") as client:
        created = client.post(path)
    assert created.status_code == 201

    with profile_release_connections.connect("approver", autocommit=True) as connection:
        before = connection.execute(
            "SELECT session_ref, release_sha256, pin_sha256, pinned_at FROM "
            "dev_eval.profile_release_session_pins WHERE session_ref = %s",
            (session_ref,),
        ).fetchone()
    assert before is not None

    with _client_as(profile_release_connections, "approver") as client:
        observed = client.get(path)
    assert observed.status_code == 200, observed.text
    assert observed.json() == {
        "session_ref": session_ref,
        "release_sha256": release_sha256,
        "pin_sha256": created.json()["pin_sha256"],
        "pinned_at": before[3].isoformat().replace("+00:00", "Z"),
    }

    with profile_release_connections.connect("approver", autocommit=True) as connection:
        after = connection.execute(
            "SELECT session_ref, release_sha256, pin_sha256, pinned_at FROM "
            "dev_eval.profile_release_session_pins WHERE session_ref = %s",
            (session_ref,),
        ).fetchone()
    assert after == before


def _capability() -> ModuleType:
    try:
        available = importlib.util.find_spec(CAPABILITY_MODULE) is not None
    except ModuleNotFoundError:
        available = False
    if not available:
        pytest.fail("PHASE3-MISSING:profile-release-lifecycle", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _cohort() -> list[dict[str, object]]:
    return [
        {
            "place_ref": f"synthetic-place-{index:02d}",
            "label_ready": True,
            "rights_ready": True,
            "evidence_ready": True,
            "description_lane": "READY",
            "odii_lane": "MISSING" if index % 3 == 0 else "READY",
            "profile_sha256": f"{index + 1:064x}",
            "label_export_sha256": f"{index + 101:064x}",
            "candidate_manifest_sha256": f"{index + 201:064x}",
            "reviewed_evidence_manifest_sha256": f"{index + 301:064x}",
            "accepted_review_set_sha256": f"{index + 401:064x}",
            "rights_sha256": f"{index + 501:064x}",
            "source_sha256": f"{index + 601:064x}",
        }
        for index in range(24)
    ]


def _candidate_payload(*, release_id: str = "synthetic-release-a") -> dict[str, object]:
    return {
        "schema_version": "itda.profile-release-candidate.v1",
        "release_id": release_id,
        "state": "BUILT_UNAPPROVED",
        "builder_principal": "synthetic-builder",
        "canonical_lineage_sha256": "a" * 64,
        "dev_lineage_sha256": "b" * 64,
        "profile_schema_sha256": "c" * 64,
        "label_freeze_sha256": "d" * 64,
        "candidate_run_sha256": "e" * 64,
        "reviewed_manifest_sha256": "f" * 64,
        "rights_manifest_sha256": "1" * 64,
        "source_manifest_sha256": "2" * 64,
        "code_sha256": "3" * 64,
        "config_sha256": "4" * 64,
        "cohort": _cohort(),
    }


def _snapshot(store: Any) -> dict[str, object]:
    return deepcopy(store.snapshot())


def _assert_unchanged(store: Any, before: dict[str, object]) -> None:
    assert store.snapshot() == before


def test_candidate_requires_one_complete_atomic_cohort() -> None:
    capability = _capability()
    complete = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    assert complete.state.value == "BUILT_UNAPPROVED"

    for mutation in ("missing", "extra", "unresolved", "source-less", "rights"):
        payload = _candidate_payload(release_id=f"synthetic-{mutation}")
        cohort = payload["cohort"]
        assert isinstance(cohort, list)
        if mutation == "missing":
            cohort.pop()
        elif mutation == "extra":
            cohort.append(deepcopy(cohort[-1]))
        elif mutation == "unresolved":
            cohort[0]["label_ready"] = False
        elif mutation == "source-less":
            cohort[0]["evidence_ready"] = False
        else:
            cohort[0]["rights_ready"] = False
        with pytest.raises(ValidationError):
            capability.ProfileReleaseCandidate.model_validate(payload)


@pytest.mark.parametrize("fault", ["incomplete-set", "interrupted", "path-swap"])
def test_publication_failure_keeps_visible_directory_absent(tmp_path: Path, fault: str) -> None:
    capability = _capability()
    candidate = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    visible = tmp_path / "visible-release"

    with pytest.raises((OSError, ValueError)):
        capability.publish_profile_release(candidate, output=visible, inject_fault=fault)

    assert not os.path.lexists(visible)


def test_collision_and_exact_existing_recovery_never_replace_bytes(tmp_path: Path) -> None:
    capability = _capability()
    candidate = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    visible = tmp_path / "visible-release"
    first = capability.publish_profile_release(candidate, output=visible)
    before = capability.snapshot_release_directory(visible)

    recovered = capability.publish_profile_release(candidate, output=visible)
    assert recovered.release_sha256 == first.release_sha256
    assert capability.snapshot_release_directory(visible) == before

    changed = capability.ProfileReleaseCandidate.model_validate(
        _candidate_payload(release_id="synthetic-release-b")
    )
    with pytest.raises(FileExistsError, match="collision|existing|immutable"):
        capability.publish_profile_release(changed, output=visible)
    assert capability.snapshot_release_directory(visible) == before


@pytest.mark.parametrize("entry_kind", ["symlink", "hardlink"])
def test_path_substitution_is_rejected_without_visible_mutation(
    tmp_path: Path, entry_kind: str
) -> None:
    capability = _capability()
    candidate = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    source = tmp_path / "synthetic-source.json"
    source.write_text(json.dumps({"safe": True}), encoding="utf-8")
    substituted = tmp_path / "substituted.json"
    if entry_kind == "symlink":
        substituted.symlink_to(source)
    else:
        os.link(source, substituted)

    with pytest.raises((OSError, ValueError), match="link|path|regular"):
        capability.publish_profile_release(
            candidate,
            output=tmp_path / "visible-release",
            injected_source=substituted,
        )
    assert not os.path.lexists(tmp_path / "visible-release")


def test_approval_is_independent_and_does_not_activate(tmp_path: Path) -> None:
    capability = _capability()
    store = capability.ProfileReleaseStore(tmp_path)
    candidate = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    store.build(candidate)
    before_pointer = store.active_release_sha256

    approval = store.approve(
        candidate.release_sha256,
        authenticated_principal="synthetic-approver",
        client_approver_id=None,
    )

    assert approval.state.value == "APPROVED_INACTIVE"
    assert store.active_release_sha256 == before_pointer
    with pytest.raises(ValueError, match="builder|independent"):
        store.approve(
            candidate.release_sha256,
            authenticated_principal="synthetic-builder",
            client_approver_id=None,
        )


def test_concurrent_activation_commits_at_most_one_cas_transition(tmp_path: Path) -> None:
    capability = _capability()
    store = capability.ProfileReleaseStore(tmp_path)
    candidate = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    store.build(candidate)
    store.approve(
        candidate.release_sha256,
        authenticated_principal="synthetic-approver",
        client_approver_id=None,
    )
    before = _snapshot(store)

    def activate(index: int) -> object:
        return store.activate(
            candidate.release_sha256,
            expected_current=None,
            authenticated_principal="synthetic-approver",
            nonce=f"{index + 1:064x}",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = tuple(executor.submit(activate, index) for index in range(8))
    successes, failures = [], []
    for future in futures:
        try:
            successes.append(future.result())
        except (ValueError, capability.ProfileReleaseReplayError) as exc:
            failures.append(exc)

    assert len(successes) == 1
    assert len(failures) == 7
    assert store.active_release_sha256 == candidate.release_sha256
    assert len(store.transition_receipts) == len(before["transition_receipts"]) + 1


def test_nonce_replay_uncertain_completion_and_exact_relookup_are_idempotent(
    tmp_path: Path,
) -> None:
    capability = _capability()
    store = capability.ProfileReleaseStore(tmp_path)
    candidate = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    store.build(candidate)
    store.approve(
        candidate.release_sha256,
        authenticated_principal="synthetic-approver",
        client_approver_id=None,
    )
    nonce = "d" * 64

    receipt = store.activate(
        candidate.release_sha256,
        expected_current=None,
        authenticated_principal="synthetic-approver",
        nonce=nonce,
        inject_fault="uncertain-after-commit",
    )
    assert receipt.completion.value == "RELOOKUP_CONFIRMED"
    assert len(store.transition_receipts) == 1
    assert store.transition_receipts[0].completion.value == "MUTATION_COMMITTED"

    with pytest.raises(capability.ProfileReleaseReplayError):
        store.activate(
            candidate.release_sha256,
            expected_current=None,
            authenticated_principal="synthetic-approver",
            nonce=nonce,
        )
    assert len(store.transition_receipts) == 1


@pytest.mark.parametrize(
    "case",
    ["stale-cas", "wrong-target", "client-approver", "invalid-reason"],
)
def test_invalid_transition_preserves_pointer_chain_and_session_pins(
    tmp_path: Path, case: str
) -> None:
    capability = _capability()
    store = capability.ProfileReleaseStore(tmp_path)
    first = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    second = capability.ProfileReleaseCandidate.model_validate(
        _candidate_payload(release_id="synthetic-release-b")
    )
    store.seed_active_history((first,), current=first.release_sha256)
    store.seed_approved(second)
    store.pin_session("synthetic-session-pinned")
    before = _snapshot(store)

    with pytest.raises((ValueError, capability.ProfileReleaseReplayError)):
        if case in {"stale-cas", "wrong-target"}:
            store.activate(
                "f" * 64 if case == "wrong-target" else second.release_sha256,
                expected_current="e" * 64,
                authenticated_principal="synthetic-approver",
                nonce="3" * 64,
            )
        else:
            store.rollback(
                first.release_sha256,
                expected_current=second.release_sha256,
                authenticated_principal="synthetic-approver",
                client_approver_id=(
                    "synthetic-forged-approver" if case == "client-approver" else None
                ),
                reason=" " if case == "invalid-reason" else "합성 장애 복구",
                nonce="4" * 64,
            )

    _assert_unchanged(store, before)


@pytest.mark.parametrize("case", ["not-prior-active", "incompatible"])
def test_rollback_rejects_unsafe_targets_and_preserves_all_state(tmp_path: Path, case: str) -> None:
    capability = _capability()
    store = capability.ProfileReleaseStore(tmp_path)
    first = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    second_payload = _candidate_payload(release_id="synthetic-release-b")
    if case == "incompatible":
        second_payload["profile_schema_sha256"] = "e" * 64
    second = capability.ProfileReleaseCandidate.model_validate(second_payload)
    store.seed_active_history((first, second), current=second.release_sha256)
    before = _snapshot(store)
    target = "f" * 64 if case == "not-prior-active" else first.release_sha256

    with pytest.raises(ValueError, match="prior|compatible|lineage"):
        store.rollback(
            target,
            expected_current=second.release_sha256,
            authenticated_principal="synthetic-approver",
            client_approver_id=None,
            reason="합성 장애 복구",
            nonce="e" * 64,
        )

    _assert_unchanged(store, before)


def test_sessions_pin_once_across_activation_and_rollback(tmp_path: Path) -> None:
    capability = _capability()
    store = capability.ProfileReleaseStore(tmp_path)
    first = capability.ProfileReleaseCandidate.model_validate(_candidate_payload())
    second = capability.ProfileReleaseCandidate.model_validate(
        _candidate_payload(release_id="synthetic-release-b")
    )
    store.seed_active_history((first,), current=first.release_sha256)
    old_pin = store.pin_session("synthetic-session-old")
    old_result_pin = store.pin_result("synthetic-result-old")
    store.seed_approved(second)
    store.activate(
        second.release_sha256,
        expected_current=first.release_sha256,
        authenticated_principal="synthetic-approver",
        nonce="1" * 64,
    )
    new_pin = store.pin_session("synthetic-session-new")
    new_result_pin = store.pin_result("synthetic-result-new")
    store.rollback(
        first.release_sha256,
        expected_current=second.release_sha256,
        authenticated_principal="synthetic-approver",
        client_approver_id=None,
        reason="합성 장애 복구",
        nonce="2" * 64,
    )

    assert store.session_release_sha256("synthetic-session-old") == old_pin
    assert store.session_release_sha256("synthetic-session-new") == new_pin
    assert store.result_release_sha256("synthetic-result-old") == old_result_pin
    assert store.result_release_sha256("synthetic-result-new") == new_result_pin
    assert old_pin == first.release_sha256
    assert new_pin == second.release_sha256
    assert old_result_pin == first.release_sha256
    assert new_result_pin == second.release_sha256
