from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BACKEND_SOURCE = REPOSITORY_ROOT / "backend" / "src"
COMPOSE_FILE = REPOSITORY_ROOT / "infra" / "compose.yaml"

# uv's editable .pth path is not loaded reliably when the checkout contains non-ASCII
# characters. Keep the test import boundary explicit and local to the backend harness.
if str(BACKEND_SOURCE) not in sys.path:
    sys.path.insert(0, str(BACKEND_SOURCE))

_CAPABILITIES = ("runtime", "dev", "sealer", "evaluator")


@dataclass(frozen=True, slots=True)
class PostgresHarness:
    """Connection contract for an isolated PostgreSQL 17 test cluster."""

    database_name: str
    dsns: Mapping[str, str] = field(repr=False)
    role_names: Mapping[str, str]

    def connect(
        self, capability: str, *, autocommit: bool = False
    ) -> psycopg.Connection[tuple[object, ...]]:
        if capability not in self.dsns:
            raise KeyError(f"unknown PostgreSQL capability: {capability}")
        return psycopg.connect(self.dsns[capability], autocommit=autocommit)


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _compose(command: list[str], *, environment: Mapping[str, str], timeout: float) -> None:
    completed = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *command],
        cwd=REPOSITORY_ROOT,
        env=dict(environment),
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    if completed.returncode == 0:
        return

    password = environment.get("ITDA_POSTGRES_ADMIN_PASSWORD", "")
    details = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if password:
        details = details.replace(password, "<redacted>")
    raise RuntimeError(f"docker compose failed with exit {completed.returncode}: {details}")


def _wait_for_postgres(admin_dsn: str, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(admin_dsn, connect_timeout=2) as connection:
                version = connection.execute(
                    "SELECT current_setting('server_version_num')::integer"
                ).fetchone()
                if version is not None and version[0] // 10000 == 17:
                    return
        except psycopg.Error as error:
            last_error = error
        time.sleep(0.25)
    raise TimeoutError("PostgreSQL 17 did not become ready within 30 seconds") from last_error


def _create_roles(
    admin_dsn: str,
    *,
    database_name: str,
    role_names: Mapping[str, str],
    passwords: Mapping[str, str],
) -> None:
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        for capability in _CAPABILITIES:
            role_name = role_names[capability]
            connection.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOINHERIT"
                ).format(sql.Identifier(role_name), sql.Literal(passwords[capability]))
            )
            connection.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database_name), sql.Identifier(role_name)
                )
            )


def _drop_test_state(
    admin_postgres_dsn: str,
    *,
    database_name: str,
    role_names: Mapping[str, str],
) -> None:
    with psycopg.connect(admin_postgres_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            (database_name,),
        )
        connection.execute(
            sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database_name))
        )
        for capability in reversed(_CAPABILITIES):
            connection.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_names[capability]))
            )


@pytest.fixture(scope="module")
def postgres_harness() -> Iterator[PostgresHarness]:
    suffix = f"{os.getpid()}_{uuid.uuid4().hex[:8]}"
    project_name = f"itda_test_{suffix}"
    database_name = f"itda_test_{suffix}"
    admin_name = f"itda_admin_{suffix}"
    admin_password = secrets.token_urlsafe(24)
    port = _available_port()

    role_names = {"admin": admin_name}
    role_names.update({capability: f"itda_{capability}_{suffix}" for capability in _CAPABILITIES})
    passwords = {capability: secrets.token_urlsafe(24) for capability in _CAPABILITIES}

    compose_environment = os.environ.copy()
    compose_environment.update(
        {
            "COMPOSE_PROJECT_NAME": project_name,
            "ITDA_POSTGRES_ADMIN_PASSWORD": admin_password,
            "ITDA_POSTGRES_ADMIN_USER": admin_name,
            "ITDA_POSTGRES_DB": database_name,
            "ITDA_POSTGRES_PORT": str(port),
        }
    )

    admin_dsn = make_conninfo(
        host="127.0.0.1",
        port=port,
        dbname=database_name,
        user=admin_name,
        password=admin_password,
    )
    admin_postgres_dsn = make_conninfo(
        host="127.0.0.1",
        port=port,
        dbname="postgres",
        user=admin_name,
        password=admin_password,
    )

    compose_attempted = False
    started = False
    try:
        compose_attempted = True
        _compose(
            ["up", "-d", "--wait", "--wait-timeout", "60", "postgres"],
            environment=compose_environment,
            timeout=120,
        )
        started = True
        _wait_for_postgres(admin_dsn)
        _create_roles(
            admin_dsn,
            database_name=database_name,
            role_names=role_names,
            passwords=passwords,
        )

        dsns = {"admin": admin_dsn}
        dsns.update(
            {
                capability: make_conninfo(
                    host="127.0.0.1",
                    port=port,
                    dbname=database_name,
                    user=role_names[capability],
                    password=passwords[capability],
                )
                for capability in _CAPABILITIES
            }
        )
        yield PostgresHarness(
            database_name=database_name,
            dsns=MappingProxyType(dsns),
            role_names=MappingProxyType(role_names),
        )
    finally:
        try:
            if started:
                _drop_test_state(
                    admin_postgres_dsn,
                    database_name=database_name,
                    role_names=role_names,
                )
        finally:
            if compose_attempted:
                _compose(
                    ["down", "--volumes", "--remove-orphans", "--timeout", "5"],
                    environment=compose_environment,
                    timeout=30,
                )


@pytest.fixture
def postgres_connections(
    postgres_harness: PostgresHarness,
) -> Iterator[Mapping[str, psycopg.Connection[tuple[object, ...]]]]:
    connections = {
        capability: postgres_harness.connect(capability)
        for capability in postgres_harness.dsns
    }
    try:
        yield MappingProxyType(connections)
    finally:
        for connection in connections.values():
            try:
                connection.rollback()
            finally:
                connection.close()
