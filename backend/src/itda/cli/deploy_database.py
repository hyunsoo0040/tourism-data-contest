"""Provision production database principals and apply the schema."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql

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
    "itda_profile_release_authority_service": (
        "ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD"
    ),
    "itda_photo_service": "ITDA_PHOTO_SERVICE_PASSWORD",
    "itda_current_profile_session_service": "ITDA_PROFILE_SESSION_SERVICE_PASSWORD",
    "itda_daily_glm_refresh_service": "ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD",
}


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
        raise RuntimeError(f"{name} is required")
    return value


def _identifier(name: str) -> str:
    value = _required(name)
    if _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError(f"{name} must be a safe lowercase PostgreSQL identifier")
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
    database_url = sqlalchemy_url_from_dsn(settings.admin_dsn).render_as_string(
        hide_password=False
    )
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.attributes["runtime_role"] = settings.runtime_role
    config.attributes["database_name"] = settings.database_name
    config.attributes["label_builder_role"] = settings.builder_role
    config.attributes["label_approver_role"] = settings.approver_role
    command.upgrade(config, "head")


def main() -> int:
    try:
        settings = load_settings()
        provision_roles(settings)
        upgrade_schema(settings)
    except Exception:
        print("Deployment database setup failed.", flush=True)
        return 1
    print("Deployment database is at the current schema revision.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
