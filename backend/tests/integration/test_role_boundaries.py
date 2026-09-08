from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql

from itda.contracts.manifest import SplitManifest
from itda.db.session import sqlalchemy_url_from_dsn
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BACKEND_SOURCE = REPOSITORY_ROOT / "backend" / "src"
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
SYNTHETIC_MANIFEST = REPOSITORY_ROOT / "fixtures" / "synthetic" / "synthetic-split-manifest.json"
EXPECTED_COLUMNS = (
    "manifest_version",
    "member_ordinal",
    "synthetic_place_id",
    "split",
    "canonicalization_version",
    "manifest_sha256",
    "sealed_at",
)
SEAL_FUNCTION_CALL = "SELECT blind_eval.seal_manifest_v1(%s, %s, %s)"


def _config(postgres_harness: object) -> Config:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["database_name"] = postgres_harness.database_name
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    for capability in ("runtime", "dev", "sealer", "evaluator"):
        config.attributes[f"{capability}_role"] = postgres_harness.role_names[capability]
    return config


def _assert_sqlstate(
    connection: psycopg.Connection[tuple[object, ...]],
    expected_sqlstate: str,
    statement: object,
    params: tuple[object, ...] | None = None,
) -> None:
    try:
        if params is None:
            connection.execute(statement)
        else:
            connection.execute(statement, params)
    except psycopg.Error as error:
        assert error.sqlstate == expected_sqlstate, (
            f"expected {expected_sqlstate}, received {error.sqlstate}: {error}"
        )
    else:
        raise AssertionError(f"statement unexpectedly succeeded: {statement!s}")


def _assert_42501(
    connection: psycopg.Connection[tuple[object, ...]],
    statement: object,
    params: tuple[object, ...] | None = None,
) -> None:
    _assert_sqlstate(connection, "42501", statement, params)


def _manifest_material(
    payload: dict[str, object] | None = None,
) -> tuple[SplitManifest, str, str]:
    manifest_payload = payload or json.loads(SYNTHETIC_MANIFEST.read_text(encoding="utf-8"))
    manifest = SplitManifest.model_validate(manifest_payload)
    canonical_text = canonical_json_bytes(manifest.canonical_payload()).decode("utf-8")
    return manifest, canonical_text, canonical_sha256(manifest.canonical_payload())


def _mixed_locale_manifest_material() -> tuple[SplitManifest, str, str]:
    payload = json.loads(SYNTHETIC_MANIFEST.read_text(encoding="utf-8"))
    payload["manifest_version"] = "synthetic-locale-v1"
    mixed_ids = (
        "synthetic:dev:Alpha",
        "synthetic:dev:alpha",
        "synthetic:dev:Éclair",
        "synthetic:dev:한글",
    )
    for member, synthetic_place_id in zip(payload["members"], mixed_ids, strict=False):
        member["synthetic_place_id"] = synthetic_place_id
    return _manifest_material(payload)


def _run_real_seal_cli(postgres_harness: object) -> subprocess.CompletedProcess[str]:
    cli_command = [
        sys.executable,
        "-m",
        "itda.cli.seal_manifest",
        "--manifest",
        str(SYNTHETIC_MANIFEST),
        "--dsn",
        postgres_harness.dsns["sealer"],
        "--sealed-at",
        "2026-07-22T12:00:00+00:00",
    ]
    assert postgres_harness.dsns["admin"] not in cli_command
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(BACKEND_SOURCE),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return subprocess.run(
        cli_command,
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )


def test_postgres_roles_enforce_the_hostile_privilege_matrix(
    postgres_harness: object,
) -> None:
    command.upgrade(_config(postgres_harness), "head")
    _, canonical_text, canonical_digest = _manifest_material()
    sealed_at = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)

    for capability in ("runtime", "dev", "evaluator"):
        with postgres_harness.connect(capability, autocommit=True) as connection:
            _assert_42501(
                connection,
                SEAL_FUNCTION_CALL,
                (canonical_text, canonical_digest, sealed_at),
            )

    for capability in ("runtime", "dev"):
        with postgres_harness.connect(capability, autocommit=True) as connection:
            for relation in (
                "blind_eval.manifest_seals",
                "blind_eval.manifest_members",
                "blind_eval.evaluator_manifest_v1",
            ):
                _assert_42501(connection, sql.SQL("SELECT * FROM {}").format(sql.SQL(relation)))

    with postgres_harness.connect("dev", autocommit=True) as connection:
        assert connection.execute("SELECT count(*) FROM dev_eval.manifest_members").fetchone() == (
            0,
        )

    with postgres_harness.connect("sealer", autocommit=True) as connection:
        _assert_sqlstate(
            connection,
            "22023",
            SEAL_FUNCTION_CALL,
            (canonical_text, "0" * 64, sealed_at),
        )
        _assert_42501(
            connection,
            "INSERT INTO blind_eval.manifest_seals "
            "(manifest_version, canonicalization_version, manifest_sha256, sealed_at) "
            "VALUES ('bypass', 'canonical-json-v1', repeat('0', 64), now())",
        )
        for relation in (
            "app.preference_profiles",
            "dev_eval.manifest_members",
            "blind_eval.manifest_seals",
            "blind_eval.manifest_members",
            "blind_eval.evaluator_manifest_v1",
            "blind_eval.internal_manifest_v1",
        ):
            _assert_42501(
                connection,
                sql.SQL("SELECT * FROM {}").format(sql.SQL(relation)),
            )

    with postgres_harness.connect("admin", autocommit=True) as connection:
        assert connection.execute("SELECT count(*) FROM blind_eval.manifest_seals").fetchone() == (
            0,
        )

    first_cli = _run_real_seal_cli(postgres_harness)
    assert first_cli.returncode == 0, first_cli.stderr
    cli_seal = json.loads(first_cli.stdout)
    assert cli_seal["manifest_version"] == "synthetic-split-v1"
    assert cli_seal["member_count"] == 36

    with postgres_harness.connect("dev", autocommit=True) as connection:
        rows = connection.execute(
            "SELECT member_ordinal, synthetic_place_id, split "
            "FROM dev_eval.manifest_members ORDER BY member_ordinal"
        ).fetchall()
        assert len(rows) == 24
        assert rows[0] == (1, "synthetic:dev:001", "DEV")
        assert rows[-1] == (24, "synthetic:dev:024", "DEV")

    with postgres_harness.connect("evaluator", autocommit=True) as connection:
        columns = connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'blind_eval' "
            "AND table_name = 'evaluator_manifest_v1' ORDER BY ordinal_position"
        ).fetchall()
        assert tuple(column[0] for column in columns) == EXPECTED_COLUMNS
        rows = connection.execute(
            "SELECT * FROM blind_eval.evaluator_manifest_v1 ORDER BY member_ordinal"
        ).fetchall()
        assert len(rows) == 36
        assert rows[0][1:4] == (1, "synthetic:dev:001", "DEV")
        assert rows[-1][1:4] == (36, "synthetic:blind:012", "BLIND")
        assert all(row[5] == cli_seal["manifest_sha256"] for row in rows)

        for relation in (
            "app.preference_profiles",
            "dev_eval.manifest_members",
            "blind_eval.manifest_seals",
            "blind_eval.manifest_members",
            "blind_eval.internal_manifest_v1",
        ):
            _assert_42501(connection, sql.SQL("SELECT * FROM {}").format(sql.SQL(relation)))

        evaluator_hostile_statements = (
            "UPDATE blind_eval.manifest_seals SET manifest_sha256 = repeat('0', 64)",
            "DELETE FROM blind_eval.manifest_seals",
            "TRUNCATE blind_eval.manifest_seals CASCADE",
            "ALTER TABLE blind_eval.manifest_seals ADD COLUMN evaluator_pwned text",
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(postgres_harness.role_names["runtime"]),
                sql.Identifier(postgres_harness.role_names["evaluator"]),
            ),
        )
        for statement in evaluator_hostile_statements:
            _assert_42501(connection, statement)

        # PostgreSQL reports an unauthorized object re-grant as a warning/no-op,
        # so prove the target role still has no effective view privilege.
        connection.execute(
            sql.SQL("GRANT SELECT ON blind_eval.evaluator_manifest_v1 TO {}").format(
                sql.Identifier(postgres_harness.role_names["runtime"])
            )
        )

    with postgres_harness.connect("runtime", autocommit=True) as connection:
        _assert_42501(connection, "SELECT * FROM blind_eval.evaluator_manifest_v1")

    with postgres_harness.connect("sealer", autocommit=True) as connection:
        hostile_statements = (
            "UPDATE blind_eval.manifest_seals SET manifest_sha256 = repeat('0', 64)",
            "DELETE FROM blind_eval.manifest_seals",
            "TRUNCATE blind_eval.manifest_seals CASCADE",
            "ALTER TABLE blind_eval.manifest_seals ADD COLUMN pwned text",
            sql.SQL("GRANT SELECT ON blind_eval.manifest_seals TO {}").format(
                sql.Identifier(postgres_harness.role_names["sealer"])
            ),
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(postgres_harness.role_names["runtime"]),
                sql.Identifier(postgres_harness.role_names["sealer"]),
            ),
        )
        for statement in hostile_statements:
            _assert_42501(connection, statement)

    public_probe = "itda_public_only_probe"
    with postgres_harness.connect("admin", autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(public_probe)))
        try:
            connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(public_probe)))
            for relation in (
                "app.journey_drafts",
                "app.preference_profiles",
                "dev_eval.manifest_members",
                "blind_eval.manifest_seals",
                "blind_eval.manifest_members",
                "blind_eval.evaluator_manifest_v1",
                "blind_eval.internal_manifest_v1",
            ):
                _assert_42501(
                    connection,
                    sql.SQL("SELECT * FROM {}").format(sql.SQL(relation)),
                )
            _assert_42501(
                connection,
                SEAL_FUNCTION_CALL,
                (canonical_text, canonical_digest, sealed_at),
            )
        finally:
            connection.execute("RESET ROLE")
            connection.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(public_probe)))

    _, mixed_canonical_text, mixed_digest = _mixed_locale_manifest_material()
    with postgres_harness.connect("sealer") as connection:
        connection.execute(
            SEAL_FUNCTION_CALL,
            (mixed_canonical_text, mixed_digest, sealed_at),
        )
        connection.rollback()

    second_cli = _run_real_seal_cli(postgres_harness)
    assert second_cli.returncode != 0
    with postgres_harness.connect("evaluator", autocommit=True) as connection:
        assert connection.execute(
            "SELECT count(*) FROM blind_eval.evaluator_manifest_v1"
        ).fetchone() == (36,)
