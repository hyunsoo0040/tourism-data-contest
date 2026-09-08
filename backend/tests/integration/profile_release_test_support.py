"""Shared PostgreSQL role support for cross-phase migration tests."""

from __future__ import annotations

import secrets
from typing import Protocol

import psycopg
from psycopg import sql

PROFILE_RELEASE_WRITE_AUTHORITY_ROLE = "itda_profile_release_write_authority"
PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE = "itda_profile_release_authority_service"

PROFILE_SESSION_OWNER_ROLE = "itda_current_profile_session_owner"
PROFILE_SESSION_SERVICE_ROLE = "itda_current_profile_session_service"

PHOTO_WRITE_AUTHORITY_ROLE = "itda_photo_write_authority"
PHOTO_AUTHORITY_SERVICE_ROLE = "itda_photo_service"

DAILY_GLM_WRITE_AUTHORITY_ROLE = "itda_daily_glm_refresh_write_authority"
DAILY_GLM_SERVICE_ROLE = "itda_daily_glm_refresh_service"


class _PostgresHarness(Protocol):
    database_name: str

    def connect(
        self,
        capability: str,
        *,
        autocommit: bool = False,
    ) -> psycopg.Connection[tuple[object, ...]]: ...


def ensure_profile_session_roles(
    postgres_harness: _PostgresHarness,
    *,
    service_password: str | None = None,
) -> str:
    """Provision migration 0019's fixed session roles in a test cluster.

    Existing roles must already carry the exact production-safe flags; the
    helper never repairs an unsafe topology. Returns the resolved service
    password so callers can build the service DSN.
    """

    expected = {
        PROFILE_SESSION_OWNER_ROLE: (False, False, False, False, False, False, False),
        PROFILE_SESSION_SERVICE_ROLE: (True, False, False, False, False, False, False),
    }
    resolved_password = service_password or secrets.token_urlsafe(24)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        rows = connection.execute(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (%s, %s)",
            (PROFILE_SESSION_OWNER_ROLE, PROFILE_SESSION_SERVICE_ROLE),
        ).fetchall()
        found = {str(row[0]): tuple(bool(value) for value in row[1:]) for row in rows}
        for role_name, flags in found.items():
            if flags != expected[role_name]:
                raise AssertionError(f"unsafe pre-existing profile session test role: {role_name}")
        if PROFILE_SESSION_OWNER_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(sql.Identifier(PROFILE_SESSION_OWNER_ROLE))
            )
        if PROFILE_SESSION_SERVICE_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(
                    sql.Identifier(PROFILE_SESSION_SERVICE_ROLE),
                    sql.Literal(resolved_password),
                )
            )
        else:
            connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(PROFILE_SESSION_SERVICE_ROLE),
                    sql.Literal(resolved_password),
                )
            )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(PROFILE_SESSION_SERVICE_ROLE),
            )
        )
    return resolved_password


def ensure_profile_release_authority_roles(
    postgres_harness: _PostgresHarness,
    *,
    authority_service_password: str | None = None,
) -> None:
    """Provision migration 0014's fixed roles in a disposable test cluster.

    Existing roles must already have the exact production-safe flags. The helper
    never repairs or relaxes an unsafe topology.
    """

    expected = {
        PROFILE_RELEASE_WRITE_AUTHORITY_ROLE: (
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        ),
        PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE: (
            True,
            False,
            False,
            False,
            False,
            False,
            False,
        ),
    }
    with postgres_harness.connect("admin", autocommit=True) as connection:
        rows = connection.execute(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (%s, %s)",
            (
                PROFILE_RELEASE_WRITE_AUTHORITY_ROLE,
                PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE,
            ),
        ).fetchall()
        found = {str(row[0]): tuple(bool(value) for value in row[1:]) for row in rows}
        for role_name, flags in found.items():
            if flags != expected[role_name]:
                raise AssertionError(f"unsafe pre-existing profile release test role: {role_name}")

        if PROFILE_RELEASE_WRITE_AUTHORITY_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(sql.Identifier(PROFILE_RELEASE_WRITE_AUTHORITY_ROLE))
            )
        if PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(
                    sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE),
                    sql.Literal(authority_service_password or secrets.token_urlsafe(24)),
                )
            )
        elif authority_service_password is not None:
            connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE),
                    sql.Literal(authority_service_password),
                )
            )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(PROFILE_RELEASE_AUTHORITY_SERVICE_ROLE),
            )
        )


def ensure_photo_lifecycle_roles(
    postgres_harness: _PostgresHarness,
    *,
    photo_service_password: str | None = None,
) -> dict[str, str]:
    """Provision migration 0018's fixed photo roles in a disposable test cluster.

    Existing roles must already have the exact production-safe flags. The
    helper never repairs or relaxes an unsafe topology. Returns the DSN
    fragments needed to connect as the fixed photo service principal.
    """

    expected = {
        PHOTO_WRITE_AUTHORITY_ROLE: (False, False, False, False, False, False, False),
        PHOTO_AUTHORITY_SERVICE_ROLE: (True, False, False, False, False, False, False),
    }
    resolved_password = photo_service_password or secrets.token_urlsafe(24)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        rows = connection.execute(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (%s, %s)",
            (PHOTO_WRITE_AUTHORITY_ROLE, PHOTO_AUTHORITY_SERVICE_ROLE),
        ).fetchall()
        found = {str(row[0]): tuple(bool(value) for value in row[1:]) for row in rows}
        for role_name, flags in found.items():
            if flags != expected[role_name]:
                raise AssertionError(f"unsafe pre-existing photo lifecycle test role: {role_name}")

        if PHOTO_WRITE_AUTHORITY_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(sql.Identifier(PHOTO_WRITE_AUTHORITY_ROLE))
            )
        if PHOTO_AUTHORITY_SERVICE_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(
                    sql.Identifier(PHOTO_AUTHORITY_SERVICE_ROLE),
                    sql.Literal(resolved_password),
                )
            )
        else:
            # Keep the returned DSN authoritative even across repeated
            # calls within one module: reset to the resolved password.
            connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(PHOTO_AUTHORITY_SERVICE_ROLE),
                    sql.Literal(resolved_password),
                )
            )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(PHOTO_AUTHORITY_SERVICE_ROLE),
            )
        )
    ensure_daily_glm_refresh_roles(postgres_harness)
    return {
        "service_role": PHOTO_AUTHORITY_SERVICE_ROLE,
        "service_password": resolved_password,
    }


def ensure_daily_glm_refresh_roles(
    postgres_harness: _PostgresHarness,
    *,
    service_password: str | None = None,
) -> dict[str, str]:
    expected = {
        DAILY_GLM_WRITE_AUTHORITY_ROLE: (
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        ),
        DAILY_GLM_SERVICE_ROLE: (True, False, False, False, False, False, False),
    }
    resolved_password = service_password or secrets.token_urlsafe(24)
    with postgres_harness.connect("admin", autocommit=True) as connection:
        rows = connection.execute(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (%s, %s)",
            (DAILY_GLM_WRITE_AUTHORITY_ROLE, DAILY_GLM_SERVICE_ROLE),
        ).fetchall()
        found = {str(row[0]): tuple(bool(value) for value in row[1:]) for row in rows}
        for role_name, flags in found.items():
            if flags != expected[role_name]:
                raise AssertionError(f"unsafe pre-existing daily GLM test role: {role_name}")
        if DAILY_GLM_WRITE_AUTHORITY_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(sql.Identifier(DAILY_GLM_WRITE_AUTHORITY_ROLE))
            )
        if DAILY_GLM_SERVICE_ROLE not in found:
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
                ).format(
                    sql.Identifier(DAILY_GLM_SERVICE_ROLE),
                    sql.Literal(resolved_password),
                )
            )
        else:
            connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(DAILY_GLM_SERVICE_ROLE),
                    sql.Literal(resolved_password),
                )
            )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),
                sql.Identifier(DAILY_GLM_SERVICE_ROLE),
            )
        )
    return {
        "service_role": DAILY_GLM_SERVICE_ROLE,
        "service_password": resolved_password,
    }
