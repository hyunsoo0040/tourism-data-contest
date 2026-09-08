"""Synchronous SQLAlchemy engine and session construction."""

from __future__ import annotations

from typing import cast

from psycopg.conninfo import conninfo_to_dict
from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session, sessionmaker


def sqlalchemy_url_from_dsn(dsn: str) -> URL:
    """Convert either a SQLAlchemy URL or a libpq conninfo DSN safely."""

    if "://" in dsn:
        url = make_url(dsn)
        if url.drivername in {"postgres", "postgresql", "postgresql+psycopg"}:
            return url.set(drivername="postgresql+psycopg")
        raise ValueError("IT-DA requires a PostgreSQL psycopg database URL")

    values = conninfo_to_dict(dsn)
    if not values.get("dbname") and not values.get("service"):
        raise ValueError("PostgreSQL DSN must include dbname or service")
    port_value = values.get("port")
    url_fields = {"user", "password", "host", "port", "dbname"}
    query = {
        key: str(value)
        for key, value in values.items()
        if key not in url_fields and value is not None
    }
    return URL.create(
        "postgresql+psycopg",
        username=cast(str | None, values.get("user")),
        password=cast(str | None, values.get("password")),
        host=cast(str | None, values.get("host")),
        port=int(port_value) if port_value else None,
        database=cast(str | None, values.get("dbname")),
        query=query,
    )


def create_database_engine(dsn: str) -> Engine:
    """Create the bounded synchronous engine used by app repositories."""

    return create_engine(
        sqlalchemy_url_from_dsn(dsn),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=0,
        hide_parameters=True,
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create sessions whose validated values remain available after commit."""

    return sessionmaker(bind=engine, expire_on_commit=False)
