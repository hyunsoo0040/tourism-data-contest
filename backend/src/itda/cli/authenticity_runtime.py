"""Package and start a local authenticity journey without altering legacy active pointers."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy.engine import URL

from itda.authenticity.auxiliary import from_national
from itda.authenticity.contracts import Assessment, SourceBundle
from itda.authenticity.publication_scope import PublicationSelection
from itda.authenticity.release import build_release, load_release
from itda.authenticity.repository import Repository, install_release
from itda.cli.collect_national_public_catalog import _environment
from itda.db.session import create_database_engine, sqlalchemy_url_from_dsn


def local_configuration(repository: Path, *, origin: str) -> dict[str, str]:
    path = repository / ".secrets/itda-authenticity-runtime.env"
    if path.exists():
        return _environment(path)
    container = "itda_national_20260910-postgres-1"
    inspected = json.loads(subprocess.check_output(["docker", "inspect", container], text=True))[0]
    env = dict(item.split("=", 1) for item in inspected["Config"]["Env"] if "=" in item)
    port = inspected["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
    user = env["POSTGRES_USER"]
    password = env["POSTGRES_PASSWORD"]
    database = env["POSTGRES_DB"]
    admin = URL.create(
        "postgresql+psycopg",
        username=user,
        password=password,
        host="127.0.0.1",
        port=int(port),
        database=database,
    ).render_as_string(hide_password=False)
    runtime_role = "itda_auth_runtime_" + secrets.token_hex(4)
    runtime_password = secrets.token_urlsafe(32)
    with psycopg.connect(
        host="127.0.0.1",
        port=int(port),
        dbname=database,
        user=user,
        password=password,
        autocommit=True,
    ) as connection:
        connection.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(runtime_role), sql.Literal(runtime_password)
            )
        )
    runtime = URL.create(
        "postgresql+psycopg",
        username=runtime_role,
        password=runtime_password,
        host="127.0.0.1",
        port=int(port),
        database=database,
    ).render_as_string(hide_password=False)
    values = {
        "ITDA_AUTHENTICITY_DATABASE_URL": runtime,
        "ITDA_AUTHENTICITY_ADMIN_DATABASE_URL": admin,
        "ITDA_AUTHENTICITY_RUNTIME_ROLE": runtime_role,
        "ITDA_AUTHENTICITY_ALLOW_DEVELOPMENT": "1",
        "ITDA_AUTHENTICITY_PHOTO_ENABLED": "1",
        "ITDA_MODEL_SESSION_LIMIT": "5",
        "ITDA_CANONICAL_APP_ORIGIN": origin,
    }
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write("".join(k + "=" + v + "\n" for k, v in values.items()))
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("package", "setup-local", "serve"))
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--analysis", type=Path, default=Path("artifacts/authenticity-v1/20260911/diagnostic")
    )
    parser.add_argument(
        "--release",
        type=Path,
        default=Path("artifacts/authenticity-v1/20260911/development-release"),
    )
    parser.add_argument("--origin", default="http://127.0.0.1:3082")
    parser.add_argument("--port", type=int, default=8086)
    parser.add_argument("--public", action="store_true")
    parser.add_argument("--publication-selection", type=Path)
    args = parser.parse_args()
    if args.command == "package":
        manifest = json.loads((args.analysis / "manifest.json").read_text())
        rows = tuple(
            Assessment.model_validate_json(p.read_bytes())
            for p in sorted((args.analysis / "final-assessments/photo-er").glob("*.json"))
        )
        if args.public:
            from itda.authenticity.promotion import verify_public_recipe

            verify_public_recipe(args.analysis, rows)
        selection = None
        if args.public and args.publication_selection is None:
            raise ValueError("PUBLIC_REQUIRES_SOURCE_CITED_PUBLICATION_SELECTION")
        expected_ids = tuple(m["place_id"] for m in manifest["members"])
        if args.publication_selection is not None:
            selection = PublicationSelection.model_validate_json(
                args.publication_selection.read_bytes()
            )
            if selection.parent_manifest_sha256 != manifest["manifest_sha256"]:
                raise ValueError("PUBLICATION_SELECTION_PARENT_CHANGED")
            sources = {
                m["place_id"]: SourceBundle.model_validate_json(Path(m["source_file"]).read_bytes())
                for m in manifest["members"]
            }
            if any(
                sources[m["place_id"]].bundle_sha256 != m["source_bundle_sha256"]
                for m in manifest["members"]
            ):
                raise ValueError("PUBLICATION_MANIFEST_SOURCE_CHANGED")
            selection.verify_sources(sources)
            if set(expected_ids) != {a.source.place.place_id for a in rows}:
                raise ValueError("PUBLICATION_REQUIRES_ALL_ANALYZED_ASSESSMENTS")
            expected_ids = selection.eligible_ids
            rows = tuple(a for a in rows if a.source.place.place_id in set(expected_ids))
        created_at = (
            load_release(args.release)[0].created_at
            if (args.release / "release.json").exists()
            else datetime.now(UTC)
        )
        release = build_release(
            assessments=rows,
            directory=args.release,
            expected_ids=expected_ids,
            parent_manifest_sha256=manifest["manifest_sha256"],
            scope="PUBLIC" if args.public else "DEVELOPMENT",
            created_at=created_at,
            auxiliary=from_national(rows, args.repository),
            publication_selection=selection,
        )
        print(
            json.dumps(
                {
                    "release_sha256": release.release_sha256,
                    "places": len(rows),
                    "scope": release.scope,
                }
            )
        )
        return 0
    if args.command == "setup-local":
        values = local_configuration(args.repository, origin=args.origin)
        role = values["ITDA_AUTHENTICITY_RUNTIME_ROLE"]
        if not re.fullmatch("[A-Za-z_][A-Za-z0-9_]*", role):
            raise ValueError("INVALID_RUNTIME_ROLE")
        config = Config(str(args.repository / "backend/alembic.ini"))
        config.set_main_option(
            "sqlalchemy.url",
            sqlalchemy_url_from_dsn(values["ITDA_AUTHENTICITY_ADMIN_DATABASE_URL"])
            .render_as_string(hide_password=False)
            .replace("%", "%%"),
        )
        config.attributes["authenticity_runtime_role"] = role
        command.upgrade(config, "head")
        admin = create_database_engine(values["ITDA_AUTHENTICITY_ADMIN_DATABASE_URL"])
        runtime = create_database_engine(values["ITDA_AUTHENTICITY_DATABASE_URL"])
        try:
            previous = Repository(runtime).active_release()
            release = install_release(
                admin,
                args.release,
                expected_previous=previous.release_sha256 if previous else None,
                activate=True,
            )
            print(
                json.dumps(
                    {
                        "active_release": release.release_sha256,
                        "places": len(release.members),
                        "scope": release.scope,
                        "legacy_active_pointer_changed": False,
                    }
                )
            )
        finally:
            admin.dispose()
            runtime.dispose()
        return 0
    values = _environment(args.repository / ".secrets/itda-authenticity-runtime.env")
    values.update(_environment(args.repository / ".secrets/itda-api-all.env"))
    for key, value in values.items():
        os.environ[key] = value
    os.environ["ITDA_MODEL_SESSION_LIMIT"] = "5"
    import uvicorn

    uvicorn.run("itda.api.main:app", host="127.0.0.1", port=args.port, access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
