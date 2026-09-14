"""Provision production database principals and apply the schema."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy.exc import SQLAlchemyError

from itda.cli.initialize_authenticity_release import ensure_initial_authenticity_release
from itda.cli.initialize_grounded_release import ensure_initial_grounded_release
from itda.db.session import sqlalchemy_url_from_dsn

ALEMBIC_INI = Path(__file__).resolve().parents[3] / "alembic.ini"
_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_OWNER_ROLES = (
    "itda_profile_release_write_authority",
    "itda_photo_write_authority",
    "itda_current_profile_session_owner",
    "itda_daily_glm_refresh_write_authority",
)
_SERVICE_PASSWORD_ENVIRONMENTS = {
    "itda_profile_release_authority_service": ("ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD"),
    "itda_photo_service": "ITDA_PHOTO_SERVICE_PASSWORD",
    "itda_current_profile_session_service": "ITDA_PROFILE_SESSION_SERVICE_PASSWORD",
    "itda_daily_glm_refresh_service": "ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD",
}


class DeploymentConfigurationError(RuntimeError):
    def __init__(self, variable: str, reason: str) -> None:
        self.variable = variable
        self.reason = reason
        super().__init__(f"{variable} {reason}")


_KNOWN_FAILURES = {
    "deployment PostgreSQL roles must be distinct": "DATABASE_ROLES_NOT_DISTINCT",
    "managed deployment roles must not have role memberships": "DATABASE_ROLE_MEMBERSHIPS",
    "initial grounded release initialization rejected": "LEGACY_RELEASE_INITIALIZATION_FAILED",
    "AUTHENTICITY_DEPLOYMENT_PIN_REQUIRED": "AUTHENTICITY_DEPLOYMENT_PIN_REQUIRED",
    "AUTHENTICITY_PUBLIC_DEPLOYMENT_PIN_MISMATCH": "AUTHENTICITY_PUBLIC_DEPLOYMENT_PIN_MISMATCH",
    "AUTHENTICITY_PREVIOUS_RELEASE_PIN_INVALID": "AUTHENTICITY_PREVIOUS_RELEASE_PIN_INVALID",
    "AUTHENTICITY_ACTIVATION_READBACK_MISMATCH": "AUTHENTICITY_ACTIVATION_READBACK_MISMATCH",
    "ACTIVE_RELEASE_CHANGED": "ACTIVE_RELEASE_CHANGED",
}
_PUBLIC_ENVIRONMENTS = {
    "ITDA_AUTHENTICITY_RELEASE_DIR",
    "ITDA_AUTHENTICITY_RELEASE_SHA256",
    "ITDA_AUTHENTICITY_EXPECTED_PLACES",
}


def deployment_failure(error: Exception, stage: str) -> dict[str, str]:
    """Emit a useful closed diagnostic without SQL, passwords, DSNs or payloads."""
    result = {
        "event": "deployment_database_failed",
        "stage": stage,
        "error_type": type(error).__name__,
        "code": "DEPLOYMENT_STAGE_FAILED",
    }
    if isinstance(error, DeploymentConfigurationError):
        result.update(code="DEPLOYMENT_CONFIGURATION_INVALID", variable=error.variable)
    elif (
        isinstance(error, KeyError)
        and error.args
        and isinstance(error.args[0], str)
        and error.args[0] in _PUBLIC_ENVIRONMENTS
    ):
        result.update(code="DEPLOYMENT_CONFIGURATION_MISSING", variable=error.args[0])
    elif isinstance(error, FileNotFoundError):
        result["code"] = "DEPLOYMENT_FILE_MISSING"
    elif isinstance(error, (SQLAlchemyError, psycopg.Error)):
        result["code"] = "DATABASE_OPERATION_FAILED"
        original = getattr(error, "orig", error)
        state = getattr(original, "sqlstate", None)
        if isinstance(state, str) and re.fullmatch(r"[0-9A-Z]{5}", state):
            result["sqlstate"] = state
    elif error.args and isinstance(error.args[0], str):
        result["code"] = _KNOWN_FAILURES.get(error.args[0], result["code"])
    return result


@dataclass(frozen=True, slots=True)
class DeploymentDatabaseSettings:
    admin_dsn: str
    database_name: str
    login_passwords: dict[str, str]
    runtime_role: str
    builder_role: str
    approver_role: str


def _required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise DeploymentConfigurationError(name, "is required")
    return value


def _identifier(name: str) -> str:
    value = _required(name)
    if _IDENTIFIER.fullmatch(value) is None:
        raise DeploymentConfigurationError(name, "must be a safe lowercase PostgreSQL identifier")
    return value


def load_settings() -> DeploymentDatabaseSettings:
    runtime_role = _identifier("ITDA_RUNTIME_ROLE")
    builder_role = _identifier("ITDA_LABEL_BUILDER_ROLE")
    approver_role = _identifier("ITDA_LABEL_APPROVER_ROLE")
    login_passwords = {
        runtime_role: _required("ITDA_RUNTIME_PASSWORD"),
        builder_role: _required("ITDA_LABEL_BUILDER_PASSWORD"),
        approver_role: _required("ITDA_LABEL_APPROVER_PASSWORD"),
        **{
            role: _required(environment)
            for role, environment in _SERVICE_PASSWORD_ENVIRONMENTS.items()
        },
    }
    managed_roles = {*_OWNER_ROLES, *login_passwords}
    if len(managed_roles) != len(_OWNER_ROLES) + len(login_passwords):
        raise RuntimeError("deployment PostgreSQL roles must be distinct")
    return DeploymentDatabaseSettings(
        admin_dsn=_required("ITDA_POSTGRES_ADMIN_DSN"),
        database_name=_identifier("ITDA_POSTGRES_DB"),
        login_passwords=login_passwords,
        runtime_role=runtime_role,
        builder_role=builder_role,
        approver_role=approver_role,
    )


def _create_or_reconcile_owner(connection: psycopg.Connection[object], role: str) -> None:
    connection.execute(
        sql.SQL(
            "DO $block$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {}) THEN "
            "CREATE ROLE {} NOLOGIN; END IF; END $block$"
        ).format(sql.Literal(role), sql.Identifier(role))
    )
    connection.execute(
        sql.SQL(
            "ALTER ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS NOINHERIT"
        ).format(sql.Identifier(role))
    )


def _create_or_reconcile_login(
    connection: psycopg.Connection[object], role: str, password: str
) -> None:
    connection.execute(
        sql.SQL(
            "DO $block$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {}) THEN "
            "CREATE ROLE {} LOGIN; END IF; END $block$"
        ).format(sql.Literal(role), sql.Identifier(role))
    )
    connection.execute(
        "SELECT pg_catalog.set_config('itda.deployment_role_password', %s, false)",
        (password,),
    )
    connection.execute(
        sql.SQL(
            "DO $block$ BEGIN EXECUTE pg_catalog.format("
            "'ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS NOINHERIT', {}, "
            "pg_catalog.current_setting('itda.deployment_role_password')); END $block$"
        ).format(sql.Literal(role))
    )
    connection.execute("RESET itda.deployment_role_password")


def _assert_no_managed_memberships(
    connection: psycopg.Connection[object], roles: tuple[str, ...]
) -> None:
    membership = connection.execute(
        "SELECT parent.rolname, member.rolname "
        "FROM pg_catalog.pg_auth_members membership "
        "JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid "
        "JOIN pg_catalog.pg_roles member ON member.oid = membership.member "
        "WHERE parent.rolname = ANY(%s) OR member.rolname = ANY(%s) LIMIT 1",
        (list(roles), list(roles)),
    ).fetchone()
    if membership is not None:
        raise RuntimeError("managed deployment roles must not have role memberships")


def provision_roles(settings: DeploymentDatabaseSettings) -> None:
    with psycopg.connect(settings.admin_dsn, autocommit=True) as connection:
        for role in _OWNER_ROLES:
            _create_or_reconcile_owner(connection, role)
        for role, password in settings.login_passwords.items():
            _create_or_reconcile_login(connection, role, password)
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(settings.database_name), sql.Identifier(role)
                )
            )
        _assert_no_managed_memberships(
            connection, (*_OWNER_ROLES, *settings.login_passwords.keys())
        )


def upgrade_schema(settings: DeploymentDatabaseSettings) -> None:
    database_url = sqlalchemy_url_from_dsn(settings.admin_dsn).render_as_string(hide_password=False)
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["runtime_role"] = settings.runtime_role
    config.attributes["database_name"] = settings.database_name
    config.attributes["label_builder_role"] = settings.builder_role
    config.attributes["label_approver_role"] = settings.approver_role
    command.upgrade(config, "head")


def main() -> int:
    stage = "configuration"
    try:
        settings = load_settings()
        stage = "roles"
        print("Deployment database setup: roles.", flush=True)
        provision_roles(settings)
        stage = "schema"
        print("Deployment database setup: schema.", flush=True)
        upgrade_schema(settings)
        if os.environ.get("ITDA_AUTHENTICITY_RELEASE_DIR"):
            stage = "public_release"
            print("Deployment database setup: PUBLIC authenticity release.", flush=True)
            authenticity = ensure_initial_authenticity_release(
                os.environ, admin_dsn=settings.admin_dsn
            )
            print(
                f"Authenticity PUBLIC release is ready ({authenticity['state']}, "
                f"{authenticity['places']} places, {authenticity['release_sha256']}).",
                flush=True,
            )
        else:
            stage = "legacy_release"
            print("Deployment database setup: legacy grounded release.", flush=True)
            release = ensure_initial_grounded_release(os.environ, admin_dsn=settings.admin_dsn)
            print(f"Grounded recommendation release is ready ({release.state}).", flush=True)
    except Exception as error:
        print("Deployment database setup failed.", flush=True)
        print(json.dumps(deployment_failure(error, stage), sort_keys=True), flush=True)
        return 1
    print("Deployment database is at the current schema revision.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
