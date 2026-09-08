"""PostgreSQL integration for the exclusive Phase 6 photo mutation authority.

Migration 0020 must make exact-purpose SECURITY DEFINER functions the only
photo lifecycle mutation path. This module proves against real PostgreSQL 17:

- restart/lease/ownership/reconciliation behavior through the functions only
- direct INSERT/UPDATE/DELETE/TRUNCATE denial for every application role on
  all seven lifecycle relations (jobs, markers, candidates, confirmed,
  ledger, review drafts, confirmation receipts)
- schema CREATE denial, PUBLIC marker SELECT removal, PUBLIC EXECUTE removal
- illegal transitions fail through the function and cannot succeed directly
- typed batch cardinality/null/duplicate/order fuzz and receipt idempotency
- role flags, membership, session_user, and default-privilege fail-closure

The module is provider-free: no provider client is constructed, no
credential is resolved, and no BLIND-12 path is opened.
"""

from __future__ import annotations

import contextlib
import secrets
from collections.abc import Iterator
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from itda.db.session import sqlalchemy_url_from_dsn
from tests.integration.profile_release_test_support import (
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
    ensure_profile_session_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"

DISPATCH_MARKERS = ("reserved", "prepared", "client_constructed", "send_boundary")
ROLE_CAPABILITIES = ("runtime", "job", "ledger")

LIFECYCLE_TABLES = (
    "dev_eval.photo_jobs",
    "dev_eval.photo_job_dispatch_markers",
    "dev_eval.photo_trait_candidates",
    "dev_eval.photo_confirmed_traits",
    "dev_eval.photo_deletion_ledger",
    "dev_eval.photo_review_drafts",
    "dev_eval.photo_confirmation_receipts",
)


def _migration_config(postgres_harness: object) -> Config:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(  # type: ignore[attr-defined]
            hide_password=False
        ),
    )
    config.attributes["database_name"] = postgres_harness.database_name  # type: ignore[attr-defined]
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    for capability in ("runtime", "dev", "sealer", "evaluator"):
        config.attributes[f"{capability}_role"] = postgres_harness.role_names[capability]  # type: ignore[attr-defined]
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]  # type: ignore[attr-defined]
    return config


@pytest.fixture(scope="module")
def phase6_roles(postgres_harness: object) -> Iterator[dict[str, str]]:
    """Random per-run denial-matrix roles plus the fixed photo principal."""

    ensure_profile_release_authority_roles(postgres_harness)  # type: ignore[attr-defined]
    ensure_profile_session_roles(postgres_harness)  # type: ignore[attr-defined]
    ensure_photo_lifecycle_roles(
        postgres_harness,  # type: ignore[attr-defined]
        photo_service_password=secrets.token_urlsafe(24),
    )
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])  # type: ignore[attr-defined]
    suffix = secrets.token_hex(4)
    role_names = {
        capability: f"itda_photo_{capability}_{suffix}" for capability in ROLE_CAPABILITIES
    }
    passwords = {capability: secrets.token_urlsafe(24) for capability in ROLE_CAPABILITIES}
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        for capability in ROLE_CAPABILITIES:
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
                    sql.Identifier(postgres_harness.database_name),  # type: ignore[attr-defined]
                    sql.Identifier(role_names[capability]),
                )
            )
    yield {
        capability: make_conninfo(
            **(admin_info | {"user": role_names[capability], "password": passwords[capability]})
        )
        for capability in ROLE_CAPABILITIES
    }
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        for capability in reversed(ROLE_CAPABILITIES):
            connection.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role_names[capability]))
            )
            connection.execute(
                sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_names[capability]))
            )


@pytest.fixture(scope="module")
def phase6_schema(
    postgres_harness: object, phase6_roles: dict[str, str]
) -> Iterator[dict[str, str]]:
    """Upgrade to head; the working ``job`` DSN is the fixed service role."""

    fixed = ensure_photo_lifecycle_roles(postgres_harness)  # type: ignore[attr-defined]
    try:
        command.upgrade(_migration_config(postgres_harness), "head")
    except Exception as error:  # noqa: BLE001 - RED gate must name the failure
        pytest.fail(f"PHASE6-MISSING:photo-job-schema-migration ({error})", pytrace=False)
    with postgres_harness.connect("admin") as connection:  # type: ignore[attr-defined]
        for table in (
            "dev_eval.photo_jobs",
            "dev_eval.photo_deletion_ledger",
            "dev_eval.photo_review_drafts",
            "dev_eval.photo_confirmation_receipts",
        ):
            found = connection.execute(f"SELECT to_regclass('{table}')").fetchone()
            if found != (table,):
                pytest.fail(
                    f"PHASE6-MISSING:photo-job-schema-migration ({table} absent)",
                    pytrace=False,
                )
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])  # type: ignore[attr-defined]
    fixed_job = make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )
    yield {
        **phase6_roles,
        "job": fixed_job,
    }


def _admin(postgres_harness: object) -> psycopg.Connection[tuple[object, ...]]:
    return postgres_harness.connect("admin", autocommit=True)  # type: ignore[attr-defined]


def _insert_queued_job(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
) -> None:
    connection.execute(
        "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)",
        (job_id, profile_id),
    )


def _read_status(
    connection: psycopg.Connection[tuple[object, ...]],
    job_id: str,
    profile_id: str,
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
        (job_id, profile_id),
    ).fetchone()


def _force_status(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
    to_status: str,
    cause: str | None = None,
) -> None:
    current = _read_status(connection, job_id, profile_id)
    assert current is not None
    from_status = str(current[0])
    if from_status == "queued" and to_status == "running":
        connection.execute(
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
            (job_id, profile_id),
        )
        return
    assert cause is not None
    if from_status in {"queued", "running"}:
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
    reason_code = f"PHOTO_{cause.upper()}"
    operation_key = _terminal_operation_key(job_id, profile_id, cause, reason_code)
    residue_digest = _terminal_residue_digest(operation_key)
    connection.execute(
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s, %s, %s, %s, %s, 0, %s)",
        (job_id, profile_id, cause, reason_code, operation_key, residue_digest),
    )
    connection.execute(
        "SELECT dev_eval.finalize_photo_job_terminal_v3(%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            job_id,
            profile_id,
            from_status,
            to_status,
            cause,
            reason_code,
            operation_key,
            residue_digest,
        ),
    )


def _assert_sqlstate(
    connection: psycopg.Connection[tuple[object, ...]],
    expected: str,
    statement: object,
    params: tuple[object, ...] | None = None,
) -> None:
    try:
        connection.execute(statement, params)
    except psycopg.Error as error:
        assert error.sqlstate == expected, (statement, error.sqlstate)
    else:
        raise AssertionError(
            f"hostile Phase 6 role operation unexpectedly succeeded: {statement} "
            f"as {connection.info.user}"
        )


def _terminal_operation_key(job_id: str, profile_id: str, cause: str, reason_code: str) -> str:
    import hashlib

    canonical = "|".join(("photo-terminal-v1", job_id, profile_id, cause, reason_code))
    first = hashlib.md5(canonical.encode(), usedforsecurity=False).hexdigest()
    second = hashlib.md5(f"{canonical}|second-half".encode(), usedforsecurity=False).hexdigest()
    return first + second


def _terminal_residue_digest(operation_key: str) -> str:
    import hashlib

    return hashlib.sha256(f"photo-residue-v1|{operation_key}|0".encode()).hexdigest()


def _candidate_batch(job_id: str, *, count: int = 2) -> dict[str, object]:
    candidate_ids = [secrets.token_hex(32) for _ in range(count)]
    return {
        "candidate_ids": candidate_ids,
        "trait_ids": ["M1", "M2"][:count],
        "texts_ko": ["조용한 산책로", "역사 이야기"][:count],
        "candidate_set_sha256s": [secrets.token_hex(32) for _ in range(count)],
    }


def _confirmed_projection_fixture(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    profile_id: str,
    included_flags: list[bool],
) -> tuple[str, str, dict[str, object]]:
    job_id = secrets.token_hex(32)
    draft_digest = secrets.token_hex(32)
    stored_name = secrets.token_hex(16)
    batch = _candidate_batch(job_id, count=len(included_flags))
    _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
    connection.execute(
        "SELECT dev_eval.reserve_photo_image_slot_v3(%s, %s, 1, %s, 'image/jpeg')",
        (job_id, profile_id, stored_name),
    )
    connection.execute(
        "SELECT dev_eval.commit_photo_image_slot_v3(%s, %s, 1, %s, 128)",
        (job_id, profile_id, stored_name),
    )
    _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
    _force_status(
        connection,
        job_id=job_id,
        profile_id=profile_id,
        to_status="succeeded",
        cause="success",
    )
    connection.execute(
        "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
        (
            job_id,
            profile_id,
            batch["candidate_ids"],
            batch["trait_ids"],
            batch["texts_ko"],
            batch["candidate_set_sha256s"],
        ),
    )
    for candidate_id, included in zip(
        batch["candidate_ids"], included_flags, strict=True  # type: ignore[arg-type]
    ):
        if not included:
            connection.execute(
                "SELECT dev_eval.annotate_photo_candidate_v3(%s, %s, %s, NULL, true)",
                (job_id, profile_id, candidate_id),
            )
    connection.execute(
        "SELECT dev_eval.save_photo_review_draft_v3(%s, %s, %s, %s, %s, %s, %s)",
        (
            job_id,
            profile_id,
            draft_digest,
            batch["candidate_ids"],
            batch["trait_ids"],
            [None] * len(included_flags),
            [not included for included in included_flags],
        ),
    )
    connection.execute(
        "SELECT dev_eval.confirm_photo_traits_v3(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            job_id,
            profile_id,
            draft_digest,
            batch["trait_ids"],
            batch["texts_ko"],
            batch["candidate_ids"],
            included_flags,
            [False] * len(included_flags),
            secrets.token_hex(16),
        ),
    )
    return job_id, draft_digest, batch


# ---------------------------------------------------------------------------
# Migration 0020: exclusive-function authority
# ---------------------------------------------------------------------------


def test_photo_job_schema_owner_is_named_by_red_gate(
    phase6_schema: dict[str, str],
) -> None:
    assert set(phase6_schema) >= {"job", "runtime", "ledger"}


def test_service_identity_flags_membership_and_session_user(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    """The service principal carries exact flags, no memberships, exact name."""

    with psycopg.connect(phase6_schema["job"]) as connection:
        identity = connection.execute("SELECT session_user, current_user").fetchone()
        assert identity == ("itda_photo_service", "itda_photo_service")
    with _admin(postgres_harness) as connection:
        roles = connection.execute(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN ('itda_photo_write_authority', 'itda_photo_service')"
        ).fetchall()
        flags = {str(row[0]): tuple(bool(v) for v in row[1:]) for row in roles}
        assert flags == {
            "itda_photo_write_authority": (False, False, False, False, False, False, False),
            "itda_photo_service": (True, False, False, False, False, False, False),
        }
        related = connection.execute(
            "SELECT pg_has_role('itda_photo_service', 'itda_photo_write_authority', "
            "'MEMBER'), pg_has_role('itda_photo_write_authority', "
            "'itda_photo_service', 'MEMBER')"
        ).fetchone()
        assert related == (False, False), "photo roles must not be member-related"
        owned = connection.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='dev_eval' AND c.relname LIKE 'photo_%' "
            "AND r.rolname='itda_photo_write_authority'"
        ).fetchone()
        assert owned is not None and int(owned[0]) >= 7, "owner owns every lifecycle table"


def test_direct_dml_is_denied_for_every_application_role(
    phase6_schema: dict[str, str],
) -> None:
    """No application role may mutate any lifecycle relation directly."""

    for capability in ("job", "runtime"):
        with psycopg.connect(phase6_schema[capability], autocommit=True) as connection:
            for table in LIFECYCLE_TABLES:
                _assert_sqlstate(
                    connection,
                    "42501",
                    f"INSERT INTO {table} SELECT * FROM {table}",
                )
                _assert_sqlstate(
                    connection,
                    "42501",
                    f"UPDATE {table} SET job_id = job_id",
                )
                _assert_sqlstate(connection, "42501", f"DELETE FROM {table}")
                _assert_sqlstate(connection, "42501", f"TRUNCATE {table}")
    with psycopg.connect(phase6_schema["ledger"], autocommit=True) as connection:
        for table in LIFECYCLE_TABLES:
            _assert_sqlstate(connection, "42501", f"UPDATE {table} SET job_id = job_id")
            _assert_sqlstate(connection, "42501", f"DELETE FROM {table}")
            _assert_sqlstate(connection, "42501", f"TRUNCATE {table}")


def test_schema_create_and_public_projection_are_denied(
    phase6_schema: dict[str, str],
) -> None:
    """Schema CREATE and PUBLIC marker/function access are gone.

    The fixed photo service keeps its exact SELECT projection (it must read
    markers for reconciliation); every other application role — and PUBLIC
    itself — loses marker SELECT and legacy/v2 EXECUTE entirely.
    """

    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _assert_sqlstate(
            connection,
            "42501",
            "CREATE TABLE dev_eval.hostile_schema_create_probe (x integer)",
        )
        _assert_sqlstate(
            connection,
            "42501",
            "SELECT dev_eval.transition_photo_job_status_v1('a', 'b', 'c', 'd', NULL)",
        )
    for capability in ("runtime", "ledger"):
        with psycopg.connect(phase6_schema[capability], autocommit=True) as connection:
            _assert_sqlstate(
                connection,
                "42501",
                "CREATE TABLE dev_eval.hostile_schema_create_probe (x integer)",
            )
            _assert_sqlstate(
                connection,
                "42501",
                "SELECT count(*) FROM dev_eval.photo_job_dispatch_markers",
            )
            _assert_sqlstate(
                connection,
                "42501",
                "SELECT dev_eval.create_photo_job_v3('a', 'b', NULL)",
            )


def test_function_only_lifecycle_and_illegal_transition_denied(
    phase6_schema: dict[str, str],
) -> None:
    """One legal lifecycle through functions; illegal pair fails everywhere."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-exclusive-fn"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        row = _read_status(connection, job_id, profile_id)
        assert row == ("running",)
        # The nonterminal function rejects terminal and reverse targets.
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'running', 'queued', NULL)",
            (job_id, profile_id),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'running', 'succeeded', NULL)",
            (job_id, "profile-attacker"),
        )
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        row = _read_status(connection, job_id, profile_id)
        assert row == ("succeeded",)


def test_0021_proof_bound_terminal_authority_denies_legacy_and_mismatched_proof(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-proof-bound"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _assert_sqlstate(
            connection,
            "42501",
            "SELECT dev_eval.transition_photo_job_status_v2"
            "(%s, %s, 'queued', 'running', NULL, NULL)",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
            (job_id, profile_id),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'running', 'succeeded', NULL)",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        operation_key = _terminal_operation_key(job_id, profile_id, "success", "PHOTO_SUCCESS")
        residue_digest = _terminal_residue_digest(operation_key)
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.finalize_photo_job_terminal_v3"
            "(%s, %s, 'running', 'succeeded', 'success', 'PHOTO_SUCCESS', %s, %s)",
            (job_id, profile_id, operation_key, residue_digest),
        )
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3"
            "(%s, %s, 'success', 'PHOTO_SUCCESS', %s, 0, %s)",
            (job_id, profile_id, operation_key, residue_digest),
        )
        for field, value in (
            ("cause", "timeout"),
            ("reason", "PHOTO_TIMEOUT"),
            ("operation", "a" * 64),
            ("digest", "b" * 64),
        ):
            params = {
                "cause": "success",
                "reason": "PHOTO_SUCCESS",
                "operation": operation_key,
                "digest": residue_digest,
            }
            params[field] = value
            _assert_sqlstate(
                connection,
                "23514",
                "SELECT dev_eval.finalize_photo_job_terminal_v3"
                "(%s, %s, 'running', 'succeeded', %s, %s, %s, %s)",
                (
                    job_id,
                    profile_id,
                    params["cause"],
                    params["reason"],
                    params["operation"],
                    params["digest"],
                ),
            )
        connection.execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3"
            "(%s, %s, 'running', 'succeeded', 'success', 'PHOTO_SUCCESS', %s, %s)",
            (job_id, profile_id, operation_key, residue_digest),
        )
        assert _read_status(connection, job_id, profile_id) == ("succeeded",)


def test_0021_v3_create_is_the_only_service_create_authority(
    phase6_schema: dict[str, str],
) -> None:
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        for candidate in (secrets.token_hex(16), secrets.token_hex(32)):
            _assert_sqlstate(
                connection,
                "42501",
                "SELECT dev_eval.create_photo_job_v2(%s, %s, NULL)",
                (candidate, "profile-v2-create-denied"),
            )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)",
            (secrets.token_hex(16), "profile-v3-short-rejected"),
        )
        exact = secrets.token_hex(32)
        assert connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)",
            (exact, "profile-v3-exact"),
        ).fetchone() == (True,)
        assert _read_status(connection, exact, "profile-v3-exact") == ("queued",)


def test_0021_v3_wrappers_are_the_only_service_write_authority(
    phase6_schema: dict[str, str],
) -> None:
    legacy_writes = (
        ("record_photo_dispatch_marker_v2", "(%s, %s, 1, 'reserved')"),
        (
            "record_photo_candidate_batch_v2",
            "(%s, %s, ARRAY['a'], ARRAY['M1'], ARRAY['x'], ARRAY['b'])",
        ),
        ("annotate_photo_candidate_v2", "(%s, %s, 'a', NULL, true)"),
        (
            "save_photo_review_draft_v2",
            "(%s, %s, 'a', ARRAY['b'], ARRAY['M1'], ARRAY[NULL]::text[], ARRAY[false])",
        ),
        ("discard_photo_review_draft_v2", "(%s, %s)"),
        (
            "confirm_photo_traits_v2",
            "(%s, %s, 'a', ARRAY['M1'], ARRAY['x'], ARRAY['b'], "
            "ARRAY[true], ARRAY[false], 'receipt')",
        ),
    )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        for name, arguments in legacy_writes:
            _assert_sqlstate(
                connection,
                "42501",
                f"SELECT dev_eval.{name}{arguments}",
                (secrets.token_hex(32), "profile-v2-write-denied"),
            )

    production = "\n".join(
        path.read_text()
        for path in (
            REPOSITORY_ROOT / "backend/src/itda/db/photo_repositories.py",
            REPOSITORY_ROOT / "backend/src/itda/photo/jobs.py",
        )
    )
    for legacy in (
        "create_photo_job_v2",
        "record_photo_dispatch_marker_v2",
        "record_photo_candidate_batch_v2",
        "annotate_photo_candidate_v2",
        "save_photo_review_draft_v2",
        "discard_photo_review_draft_v2",
        "confirm_photo_traits_v2",
    ):
        assert legacy not in production


def test_0021_filesystem_binding_claim_is_exact_and_direct_access_denied(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-binding-v3"
    digest = secrets.token_hex(32)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        assert connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
        assert connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone() == (False,)
        _assert_sqlstate(
            connection,
            "42883",
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s, %s)",
            (job_id, profile_id, digest),
        )
        assert connection.execute(
            "SELECT binding_claimed FROM dev_eval.read_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
        _assert_sqlstate(
            connection,
            "42501",
            "SELECT * FROM dev_eval.photo_job_filesystem_bindings",
        )


def test_candidate_batch_fuzz_rejects_null_duplicate_and_wrong_cardinality(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-candidate-fuzz"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        batch = _candidate_batch(job_id, count=2)
        args = (
            job_id,
            profile_id,
            batch["candidate_ids"],
            batch["trait_ids"],
            batch["texts_ko"],
            batch["candidate_set_sha256s"],
        )
        connection.execute(
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            args,
        )
        rows = connection.execute(
            "SELECT candidate_id FROM dev_eval.list_photo_candidates_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
        assert len(rows) == 2

        empty = _candidate_batch(job_id, count=0)
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT dev_eval.record_photo_candidate_batch_v3"
            "(%s, %s, %s::text[], %s::text[], %s::text[], %s::text[])",
            (
                job_id,
                profile_id,
                empty["candidate_ids"],
                empty["trait_ids"],
                empty["texts_ko"],
                empty["candidate_set_sha256s"],
            ),
        )
        seven = _candidate_batch(job_id, count=2)
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                [*seven["candidate_ids"], *seven["candidate_ids"]],  # type: ignore[list-item]
                [*seven["trait_ids"], *seven["trait_ids"]],  # type: ignore[list-item]
                [*seven["texts_ko"], *seven["texts_ko"]],  # type: ignore[list-item]
                [*seven["candidate_set_sha256s"], *seven["candidate_set_sha256s"]],  # type: ignore[list-item]
            ),
        )
        null_trait = _candidate_batch(job_id, count=2)
        null_trait["trait_ids"] = ["M1", None]  # type: ignore[list-item]
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                null_trait["candidate_ids"],
                null_trait["trait_ids"],
                null_trait["texts_ko"],
                null_trait["candidate_set_sha256s"],
            ),
        )
        dup = _candidate_batch(job_id, count=2)
        dup["candidate_ids"] = [dup["candidate_ids"][0], dup["candidate_ids"][0]]  # type: ignore[index]
        _assert_sqlstate(
            connection,
            "22023",
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                dup["candidate_ids"],
                dup["trait_ids"],
                dup["texts_ko"],
                dup["candidate_set_sha256s"],
            ),
        )


def test_review_draft_confirm_receipt_and_idempotency(
    phase6_schema: dict[str, str],
) -> None:
    """Draft CAS/read/discard and atomic confirm receipt with opaque shape."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-draft-receipt"
    draft_digest = secrets.token_hex(32)
    receipt_id = secrets.token_hex(16)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        batch = _candidate_batch(job_id, count=2)
        connection.execute(
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                batch["candidate_ids"],
                batch["trait_ids"],
                batch["texts_ko"],
                batch["candidate_set_sha256s"],
            ),
        )
        connection.execute(
            "SELECT dev_eval.annotate_photo_candidate_v3(%s, %s, %s, %s, %s)",
            (job_id, profile_id, batch["candidate_ids"][0], "편집됨", True),
        )
        connection.execute(
            "SELECT dev_eval.annotate_photo_candidate_v3(%s, %s, %s, %s, %s)",
            (job_id, profile_id, batch["candidate_ids"][1], None, True),
        )
        saved = connection.execute(
            "SELECT dev_eval.save_photo_review_draft_v3(%s, %s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                draft_digest,
                batch["candidate_ids"],
                batch["trait_ids"],
                ["편집됨", None],
                [True, True],
            ),
        ).fetchone()
        assert saved == (True,)
        draft = connection.execute(
            "SELECT draft_digest FROM dev_eval.read_photo_review_draft_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert draft == (draft_digest,)

        # All-excluded confirmation is valid, idempotent, zero included rows.
        # The submission must carry EVERY draft row with the draft's
        # effective text for each candidate (edited text at position 0) so
        # the database-side cardinality and draft verification pass.
        for _ in range(2):
            receipt = connection.execute(
                "SELECT dev_eval.confirm_photo_traits_v3(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    job_id,
                    profile_id,
                    draft_digest,
                    batch["trait_ids"],
                    ["편집됨", batch["texts_ko"][1]],
                    batch["candidate_ids"],
                    [False, False],
                    [False, False],
                    receipt_id,
                ),
            ).fetchone()
            assert receipt is not None and receipt[0] == receipt_id
        stored_receipt = connection.execute(
            "SELECT included_count FROM dev_eval.read_photo_confirmation_receipt_v2(%s, %s, %s)",
            (job_id, profile_id, receipt_id),
        ).fetchone()
        assert stored_receipt == (0,), "repeated identical confirmation is idempotent"
        confirmed_rows = connection.execute(
            "SELECT included FROM dev_eval.list_photo_confirmed_traits_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
        assert confirmed_rows == [
            (False,),
            (False,),
        ], "all-excluded batch confirms no included rows"
        discarded = connection.execute(
            "SELECT dev_eval.discard_photo_review_draft_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert discarded == (True,)


def test_receipt_columns_are_exactly_minimized(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    """Receipts carry only opaque ID, ownership FKs, digest, count, time."""

    with _admin(postgres_harness) as connection:
        rows = connection.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='dev_eval' AND table_name='photo_confirmation_receipts' "
            "ORDER BY column_name"
        ).fetchall()
        columns = {str(row[0]) for row in rows}
    assert columns == {
        "receipt_id",
        "job_id",
        "profile_id",
        "draft_digest",
        "included_count",
        "created_at",
    }


def test_default_privileges_cannot_restore_authority(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    """Hostile default ACLs for creator/owner roles stay closed."""

    with _admin(postgres_harness) as connection:
        leaked = connection.execute(
            "SELECT count(*) FROM pg_catalog.pg_default_acl d "
            "JOIN pg_catalog.pg_roles r ON r.oid=d.defaclrole "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a "
            "WHERE r.rolname IN ('itda_photo_write_authority', 'itda_photo_service') "
            "AND d.defaclobjtype IN ('r','S','f') "
            "AND NOT (a.grantee=d.defaclrole)"
        ).fetchone()
        assert leaked == (0,), "default privileges must not grant photo authority"


def test_function_definitions_pin_search_path_and_qualify_relations(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    """Every 0020 definer function pins search_path and uses no dynamic SQL."""

    with _admin(postgres_harness) as connection:
        rows = connection.execute(
            "SELECT p.proname, p.proconfig, pg_get_functiondef(p.oid) "
            "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
            "ON n.oid=p.pronamespace "
            "WHERE n.nspname='dev_eval' AND p.proname LIKE '%_v2'"
        ).fetchall()
        configs = {str(name): tuple(config or ()) for name, config, _body in rows}
        definitions = {str(name): str(body) for name, _config, body in rows}
    expected = {
        "create_photo_job_v2",
        "transition_photo_job_status_v2",
        "claim_photo_job_v2",
        "record_photo_dispatch_marker_v2",
        "record_photo_candidate_batch_v2",
        "annotate_photo_candidate_v2",
        "append_photo_deletion_ledger_v2",
        "save_photo_review_draft_v2",
        "discard_photo_review_draft_v2",
        "confirm_photo_traits_v2",
    }
    assert expected <= set(definitions), sorted(definitions)
    for name in expected:
        assert any("search_path" in str(item) for item in configs[name]), name
        body = definitions[name]
        assert "dev_eval.photo_" in body, name
        assert "EXECUTE " not in body, f"{name} must not use dynamic SQL"


# ---------------------------------------------------------------------------
# Durable lifecycle behavior through functions only
# ---------------------------------------------------------------------------


def test_queued_and_running_rows_survive_simulated_worker_restart(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-restart-durability"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, profile_id)
    assert row == ("queued",)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, profile_id)
    assert row == ("running",)


def test_stale_running_startup_reconciliation_never_blindly_retries_provider(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    from itda.photo import jobs as photo_jobs

    job_id = secrets.token_hex(32)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id="profile-stale-running")
        _force_status(
            connection, job_id=job_id, profile_id="profile-stale-running", to_status="running"
        )
    with _admin(postgres_harness) as connection:
        connection.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at = now() - interval '1 minute' "
            "WHERE job_id = %s",
            (job_id,),
        )
    with (
        psycopg.connect(phase6_schema["job"], autocommit=True) as connection,
        pytest.raises(photo_jobs.PhotoJobError),
    ):
        photo_jobs.reconcile_interrupted_jobs(connection)
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, "profile-stale-running")
    assert row == ("running",)


def test_reconciliation_requires_durable_markers_and_fails_after_uncertain_send(
    phase6_schema: dict[str, str],
) -> None:
    from itda.photo import jobs as photo_jobs

    job_id = secrets.token_hex(32)
    profile_id = "profile-uncertain"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        for marker in DISPATCH_MARKERS:
            connection.execute(
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, %s)",
                (job_id, profile_id, marker),
            )
    with (
        psycopg.connect(phase6_schema["job"], autocommit=True) as connection,
        pytest.raises(photo_jobs.PhotoJobError),
    ):
        photo_jobs.reconcile_interrupted_jobs(connection)
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, profile_id)
        markers = connection.execute(
            "SELECT marker, attempt_count FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
    assert row == ("running",)
    assert len(markers) == len(DISPATCH_MARKERS)
    assert all(int(count) == 1 for _marker, count in markers), (
        "uncertain completion must never spawn a second attempt"
    )


def test_concurrent_claim_exclusion_admits_exactly_one_worker(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-claim-race"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
    with (
        psycopg.connect(phase6_schema["job"]) as worker_a,
        psycopg.connect(phase6_schema["job"]) as worker_b,
    ):
        with worker_a.transaction():
            claimed_a = worker_a.execute(
                "SELECT dev_eval.transition_photo_job_nonterminal_v3"
                "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
                (job_id, profile_id),
            ).fetchone()[0]
        with pytest.raises(psycopg.Error) as denied, worker_b.transaction():
            worker_b.execute(
                "SELECT dev_eval.transition_photo_job_nonterminal_v3"
                "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
                (job_id, profile_id),
            )
    assert claimed_a == "queued"
    assert denied.value.sqlstate == "23514"


@pytest.mark.parametrize(
    ("crash_point", "expected_status"),
    (
        ("before_decode", "failed"),
        ("before_client_constructed", "failed"),
        ("before_send_boundary", "failed"),
        ("after_provider_return", "failed"),
    ),
)
def test_crash_points_reconcile_without_provider_retry(
    phase6_schema: dict[str, str],
    crash_point: str,
    expected_status: str,
) -> None:
    from itda.photo import jobs as photo_jobs

    job_id = secrets.token_hex(32)
    profile_id = f"profile-crash-{crash_point}"
    markers = {
        "before_decode": ("reserved",),
        "before_client_constructed": ("reserved", "prepared"),
        "before_send_boundary": ("reserved", "prepared", "client_constructed"),
        "after_provider_return": DISPATCH_MARKERS,
    }[crash_point]
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        for marker in markers:
            connection.execute(
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, %s)",
                (job_id, profile_id, marker),
            )
    with (
        psycopg.connect(phase6_schema["job"], autocommit=True) as connection,
        pytest.raises(photo_jobs.PhotoJobError),
    ):
        photo_jobs.reconcile_interrupted_jobs(connection)
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, profile_id)
        markers = connection.execute(
            "SELECT marker, attempt_count FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
    assert row == ("running",)
    assert expected_status == "failed"
    assert markers, "seeded markers must remain visible"
    assert all(int(count) == 1 for _marker, count in markers), (
        "uncertain completion must never spawn a second attempt"
    )


def test_role_denial_matrix_blocks_mutation_escalation_and_bypass(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    """Runtime/job/ledger roles stay least-privilege over photo relations."""

    for capability in ("runtime", "job"):
        with psycopg.connect(phase6_schema[capability], autocommit=True) as connection:
            # A grant attempt from a non-owner can never widen PUBLIC's
            # authority: whatever PostgreSQL does with the statement, the
            # raw catalog ACL must show no PUBLIC privilege afterwards.
            with contextlib.suppress(psycopg.Error):
                connection.execute("GRANT ALL ON dev_eval.photo_jobs TO PUBLIC")
            leaked = connection.execute(
                "SELECT has_table_privilege('public', 'dev_eval.photo_jobs', 'SELECT'), "
                "has_table_privilege('public', 'dev_eval.photo_jobs', 'INSERT'), "
                "has_table_privilege('public', 'dev_eval.photo_jobs', 'UPDATE')"
            ).fetchone()
            assert leaked == (False, False, False)
            _assert_sqlstate(
                connection,
                "42501",
                sql.SQL("SET ROLE {}").format(
                    sql.Identifier(postgres_harness.role_names["admin"])  # type: ignore[attr-defined]
                ),
            )
            _assert_sqlstate(
                connection,
                "42501",
                "SET SESSION AUTHORIZATION itda_photo_write_authority",
            )
    with psycopg.connect(phase6_schema["ledger"], autocommit=True) as connection:
        _assert_sqlstate(
            connection,
            "42501",
            "SELECT * FROM dev_eval.photo_jobs",
        )


def test_runtime_role_cannot_read_cross_job_dispatch_markers(
    phase6_schema: dict[str, str],
) -> None:
    """Runtime lost every photo read: the SELECT itself must be denied."""

    with psycopg.connect(phase6_schema["runtime"]) as connection:
        try:
            connection.execute(
                "SELECT count(*) FROM dev_eval.photo_job_dispatch_markers WHERE job_id = %s",
                ("f" * 64,),
            )
        except psycopg.Error as error:
            assert error.sqlstate == "42501"
        else:
            raise AssertionError("runtime photo marker SELECT must be denied")


def test_service_table_select_is_denied_everywhere(
    phase6_schema: dict[str, str],
) -> None:
    """No role — including the service — holds any direct table SELECT."""

    for capability in ("job", "runtime"):
        with psycopg.connect(phase6_schema[capability], autocommit=True) as connection:
            for table in LIFECYCLE_TABLES:
                _assert_sqlstate(connection, "42501", f"SELECT count(*) FROM {table}")


def test_confirm_requires_exact_persisted_draft(
    phase6_schema: dict[str, str],
) -> None:
    """Fake/stale digests, absent drafts, and foreign profiles fail closed."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-confirm-strict"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        batch = _candidate_batch(job_id, count=1)
        connection.execute(
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                batch["candidate_ids"],
                batch["trait_ids"],
                batch["texts_ko"],
                batch["candidate_set_sha256s"],
            ),
        )
        real_digest = "cd" * 32
        connection.execute(
            "SELECT dev_eval.save_photo_review_draft_v3(%s, %s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                real_digest,
                batch["candidate_ids"],
                batch["trait_ids"],
                [None],
                [False],
            ),
        )
        confirm = "SELECT dev_eval.confirm_photo_traits_v3(%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        good = (
            job_id,
            profile_id,
            real_digest,
            batch["trait_ids"],
            batch["texts_ko"],
            batch["candidate_ids"],
            [True],
            [False],
            secrets.token_hex(16),
        )
        # Fake digest: rejected.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (job_id, profile_id, "ef" * 32, *good[3:]),
        )
        # Foreign profile: rejected even with the right digest.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (job_id, "anonymous:attacker", real_digest, *good[3:]),
        )
        # Absent job: rejected.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (secrets.token_hex(32), profile_id, real_digest, *good[3:]),
        )
        # Fake candidate id inside the batch: rejected.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (
                job_id,
                profile_id,
                real_digest,
                batch["trait_ids"],
                batch["texts_ko"],
                [secrets.token_hex(32)],
                [True],
                [False],
                secrets.token_hex(16),
            ),
        )
        # Foreign trait id on the candidate row: rejected.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (
                job_id,
                profile_id,
                real_digest,
                ["M6"],
                batch["texts_ko"],
                batch["candidate_ids"],
                [True],
                [False],
                secrets.token_hex(16),
            ),
        )
        # Text that is neither the model text nor a draft edit: rejected.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (
                job_id,
                profile_id,
                real_digest,
                batch["trait_ids"],
                ["변조된 문구"],
                batch["candidate_ids"],
                [True],
                [False],
                secrets.token_hex(16),
            ),
        )
        # The exact draft + matching rows confirm and stay idempotent.
        first = connection.execute(confirm, good).fetchone()
        second = connection.execute(confirm, good).fetchone()
        assert first == second
        # Receipt idempotency never bypasses semantic validation: malformed
        # repeats using the already-receipted live digest still fail closed.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (
                job_id,
                profile_id,
                real_digest,
                batch["trait_ids"],
                batch["texts_ko"],
                batch["candidate_ids"],
                [False],
                [False],
                secrets.token_hex(16),
            ),
        )
        # Confirming a stale (different) digest after the receipt exists
        # still fails closed — idempotency binds to the exact draft only.
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (job_id, profile_id, "ab" * 32, *good[3:]),
        )


def test_confirm_rejects_partial_reordered_null_and_forged_drafts(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-confirm-adversarial"
    digest = secrets.token_hex(32)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        batch = _candidate_batch(job_id, count=2)
        connection.execute(
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                batch["candidate_ids"],
                batch["trait_ids"],
                batch["texts_ko"],
                batch["candidate_set_sha256s"],
            ),
        )
        save = "SELECT dev_eval.save_photo_review_draft_v3(%s, %s, %s, %s, %s, %s, %s)"
        for candidate_ids, trait_ids, edited, excluded in (
            (
                [secrets.token_hex(32), batch["candidate_ids"][1]],
                batch["trait_ids"],
                [None, None],
                [False, False],
            ),
            (
                batch["candidate_ids"],
                ["M6", batch["trait_ids"][1]],
                [None, None],
                [False, False],
            ),
            (
                batch["candidate_ids"],
                batch["trait_ids"],
                ["위조 편집", None],
                [False, False],
            ),
            (
                batch["candidate_ids"],
                batch["trait_ids"],
                [None, None],
                [True, False],
            ),
        ):
            _assert_sqlstate(
                connection,
                "23514",
                save,
                (
                    job_id,
                    profile_id,
                    digest,
                    candidate_ids,
                    trait_ids,
                    edited,
                    excluded,
                ),
            )
        connection.execute(
            save,
            (
                job_id,
                profile_id,
                digest,
                batch["candidate_ids"],
                batch["trait_ids"],
                [None, None],
                [False, False],
            ),
        )
        confirm = "SELECT dev_eval.confirm_photo_traits_v3(%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (
                job_id,
                profile_id,
                digest,
                [batch["trait_ids"][0]],
                [batch["texts_ko"][0]],
                [batch["candidate_ids"][0]],
                [True],
                [False],
                secrets.token_hex(16),
            ),
        )
        _assert_sqlstate(
            connection,
            "23514",
            confirm,
            (
                job_id,
                profile_id,
                digest,
                list(reversed(batch["trait_ids"])),
                list(reversed(batch["texts_ko"])),
                list(reversed(batch["candidate_ids"])),
                [True, True],
                [False, False],
                secrets.token_hex(16),
            ),
        )
        _assert_sqlstate(
            connection,
            "22023",
            confirm,
            (
                job_id,
                profile_id,
                digest,
                batch["trait_ids"],
                batch["texts_ko"],
                [None, batch["candidate_ids"][1]],
                [True, True],
                [False, False],
                secrets.token_hex(16),
            ),
        )
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.list_photo_confirmed_traits_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.read_photo_confirmation_receipt_v2(%s, %s, %s)",
            (job_id, profile_id, secrets.token_hex(16)),
        ).fetchone() == (0,)


def test_receipt_idempotency_binds_to_exact_draft_only(
    phase6_schema: dict[str, str],
) -> None:
    """The same batch under a different digest must not reuse the receipt."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-digest-bind"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        batch = _candidate_batch(job_id, count=1)
        connection.execute(
            "SELECT dev_eval.record_photo_candidate_batch_v3(%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                batch["candidate_ids"],
                batch["trait_ids"],
                batch["texts_ko"],
                batch["candidate_set_sha256s"],
            ),
        )
        digest = "dd" * 32
        connection.execute(
            "SELECT dev_eval.save_photo_review_draft_v3(%s, %s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                digest,
                batch["candidate_ids"],
                batch["trait_ids"],
                [None],
                [False],
            ),
        )
        confirm = "SELECT dev_eval.confirm_photo_traits_v3(%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        args = (
            job_id,
            profile_id,
            digest,
            batch["trait_ids"],
            batch["texts_ko"],
            batch["candidate_ids"],
            [True],
            [False],
            secrets.token_hex(16),
        )
        first = connection.execute(confirm, args).fetchone()
        # Draft replaced with a new digest; the same batch under the NEW
        # digest cannot silently replay the old receipt — and because the
        # job already holds its confirmed batch, the append fails closed
        # instead of producing a second receipt.
        new_digest = "ee" * 32
        connection.execute(
            "SELECT dev_eval.save_photo_review_draft_v3(%s, %s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                new_digest,
                batch["candidate_ids"],
                batch["trait_ids"],
                [None],
                [False],
            ),
        )
        try:
            connection.execute(
                confirm,
                (job_id, profile_id, new_digest, *args[3:]),
            )
        except psycopg.Error as error:
            assert error.sqlstate in {"23505", "23514"}, error.sqlstate
        else:
            raise AssertionError("a second confirmation must not create another receipt")
        assert first is not None


def test_recommendation_projection_returns_only_owned_included_traits(
    phase6_schema: dict[str, str],
) -> None:
    profile_id = "profile-recommendation-projection"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        job_id, draft_digest, batch = _confirmed_projection_fixture(
            connection,
            profile_id=profile_id,
            included_flags=[True, False],
        )
        rows = connection.execute(
            "SELECT draft_digest, included_count, images_count, "
            "confirmation_seq, trait_id, text_ko "
            "FROM dev_eval.read_photo_recommendation_projection_v1(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
        assert rows == [
            (
                draft_digest,
                1,
                1,
                1,
                (batch["trait_ids"])[0],  # type: ignore[index]
                (batch["texts_ko"])[0],  # type: ignore[index]
            )
        ]
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT * FROM dev_eval.read_photo_recommendation_projection_v1(%s, %s)",
            (job_id, "profile:foreign"),
        )


def test_recommendation_projection_rejects_unconfirmed_and_all_excluded_jobs(
    phase6_schema: dict[str, str],
) -> None:
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        unconfirmed_job = secrets.token_hex(32)
        profile_id = "profile-recommendation-unconfirmed"
        stored_name = secrets.token_hex(16)
        _insert_queued_job(connection, job_id=unconfirmed_job, profile_id=profile_id)
        connection.execute(
            "SELECT dev_eval.reserve_photo_image_slot_v3(%s, %s, 1, %s, 'image/jpeg')",
            (unconfirmed_job, profile_id, stored_name),
        )
        connection.execute(
            "SELECT dev_eval.commit_photo_image_slot_v3(%s, %s, 1, %s, 128)",
            (unconfirmed_job, profile_id, stored_name),
        )
        _force_status(
            connection,
            job_id=unconfirmed_job,
            profile_id=profile_id,
            to_status="running",
        )
        _force_status(
            connection,
            job_id=unconfirmed_job,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT * FROM dev_eval.read_photo_recommendation_projection_v1(%s, %s)",
            (unconfirmed_job, profile_id),
        )

        excluded_job, _digest, _batch = _confirmed_projection_fixture(
            connection,
            profile_id="profile-recommendation-excluded",
            included_flags=[False, False],
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT * FROM dev_eval.read_photo_recommendation_projection_v1(%s, %s)",
            (excluded_job, "profile-recommendation-excluded"),
        )


def test_recommendation_projection_has_exact_definer_acl(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    signature = "dev_eval.read_photo_recommendation_projection_v1(text,text)"
    with _admin(postgres_harness) as connection:
        definition = connection.execute(
            "SELECT r.rolname, p.prosecdef, p.proconfig, pg_get_functiondef(p.oid) "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "JOIN pg_catalog.pg_roles r ON r.oid=p.proowner "
            "WHERE p.oid=%s::regprocedure",
            (signature,),
        ).fetchone()
        assert definition is not None
        assert definition[0] == "itda_photo_write_authority"
        assert definition[1] is True
        assert "search_path=pg_catalog, pg_temp" in tuple(definition[2] or ())
        assert "EXECUTE " not in str(definition[3])
        privileges = connection.execute(
            "SELECT has_function_privilege('public', %s, 'EXECUTE'), "
            "has_function_privilege(%s, %s, 'EXECUTE'), "
            "has_function_privilege(%s, %s, 'EXECUTE'), "
            "has_function_privilege('itda_photo_service', %s, 'EXECUTE')",
            (
                signature,
                postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
                signature,
                postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
                signature,
                signature,
            ),
        ).fetchone()
        assert privileges == (False, False, False, True)


def test_malicious_role_memberships_fail_the_topology(
    postgres_harness: object,
    phase6_roles: dict[str, str],
    phase6_schema: dict[str, str],
) -> None:
    """A hostile membership among the four authority roles is rejected.

    The migration itself rejects an unsafe topology at upgrade time; this
    case proves the membership directions the coordinator named are all
    observable in the live catalog and none exists after 0020.
    """

    pairs = (
        ("itda_photo_service", "itda_photo_write_authority"),
        ("itda_photo_write_authority", "itda_photo_service"),
        ("itda_photo_service", postgres_harness.role_names["runtime"]),  # type: ignore[attr-defined]
        (postgres_harness.role_names["runtime"], "itda_photo_service"),  # type: ignore[attr-defined]
        (postgres_harness.role_names["dev"], "itda_photo_service"),  # type: ignore[attr-defined]
        ("itda_photo_service", postgres_harness.role_names["dev"]),  # type: ignore[attr-defined]
    )
    with _admin(postgres_harness) as connection:
        for member, granted in pairs:
            related = connection.execute(
                "SELECT pg_has_role(%s, %s, 'MEMBER')", (member, granted)
            ).fetchone()
            assert related == (False,), (member, granted)


def test_unexpected_service_execute_grant_would_be_rejected(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    """Zero photo functions outside the allowlist grant the service EXECUTE."""

    allowed = {
        "dev_eval.create_photo_job_v3(text,text,text)",
        "dev_eval.claim_photo_job_filesystem_binding_v3(text,text)",
        "dev_eval.read_photo_job_filesystem_binding_v3(text,text)",
        "dev_eval.lock_photo_job_operation_v3(text,text,text)",
        "dev_eval.list_photo_cleanup_candidates_v3()",
        "dev_eval.transition_photo_job_nonterminal_v3"
        "(text,text,text,text,timestamp with time zone)",
        "dev_eval.append_photo_deletion_ledger_v3(text,text,text,text,text,integer,text)",
        "dev_eval.finalize_photo_job_terminal_v3(text,text,text,text,text,text,text,text)",
        "dev_eval.finalize_photo_job_unbound_explicit_deletion_v3(text,text)",
        "dev_eval.record_photo_dispatch_marker_v3(text,text,integer,text)",
        "dev_eval.record_photo_candidate_batch_v3(text,text,text[],text[],text[],text[])",
        "dev_eval.annotate_photo_candidate_v3(text,text,text,text,boolean)",
        "dev_eval.save_photo_review_draft_v3(text,text,text,text[],text[],text[],boolean[])",
        "dev_eval.discard_photo_review_draft_v3(text,text)",
        "dev_eval.confirm_photo_traits_v3(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
        "dev_eval.read_photo_job_v2(text,text)",
        "dev_eval.list_photo_candidates_v2(text,text)",
        "dev_eval.list_photo_confirmed_traits_v2(text,text)",
        "dev_eval.list_photo_dispatch_markers_v2(text,text)",
        "dev_eval.read_photo_review_draft_v2(text,text)",
        "dev_eval.read_photo_confirmation_receipt_v2(text,text,text)",
        "dev_eval.list_photo_deletion_ledger_v3(text,text)",
        "dev_eval.read_photo_cleanup_status_v3(text,text)",
        "dev_eval.complete_photo_filesystem_cleanup_v3(text,text,text,text)",
        "dev_eval.pending_photo_filesystem_release_v3(text,text,text,text)",
        "dev_eval.read_photo_filesystem_release_v3(text,text)",
        "dev_eval.reserve_photo_image_slot_v3(text,text,integer,text,text)",
        "dev_eval.commit_photo_image_slot_v3(text,text,integer,text,integer)",
        "dev_eval.read_photo_image_slots_v3(text,text)",
        "dev_eval.read_photo_recommendation_projection_v1(text,text)",
    }
    with psycopg.connect(phase6_schema["job"]) as connection:
        photo_functions = connection.execute(
            "SELECT p.proname, p.oid::regprocedure::text "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='dev_eval' "
            "AND p.proname ~ '(^|_)photo_'"
        ).fetchall()
        service_executes = set()
        for _proname, signature in photo_functions:
            granted = connection.execute(
                "SELECT has_function_privilege(current_user, %s, 'EXECUTE')",
                (str(signature),),
            ).fetchone()
            if granted == (True,):
                service_executes.add(str(signature))
    assert service_executes == allowed, "service EXECUTE set must exactly equal the allowlist"


def test_ledger_append_requires_exact_owned_legal_lifecycle(
    phase6_schema: dict[str, str],
) -> None:
    """Arbitrary hex ids, foreign profiles, and illegal states append nothing."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-ledger-strict"
    digest = secrets.token_hex(32)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        append = (
            "SELECT dev_eval.append_photo_deletion_ledger_v3"
            "(%s, %s, 'explicit_deletion', 'PHOTO_EXPLICIT_DELETION', %s, 0, %s)"
        )
        operation_key = secrets.token_hex(32)
        # Arbitrary hex job id with no row: rejected.
        _assert_sqlstate(
            connection,
            "23514",
            append,
            (secrets.token_hex(32), profile_id, operation_key, digest),
        )
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        # Foreign profile on a real job: rejected.
        _assert_sqlstate(
            connection, "23514", append, (job_id, "anonymous:attacker", operation_key, digest)
        )
        # Illegal caller state (deleted is terminal/non-appendable): rejected.
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="succeeded",
            cause="success",
        )
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="deleted",
            cause="explicit_deletion",
        )
        _assert_sqlstate(connection, "23514", append, (job_id, profile_id, operation_key, digest))


# ---------------------------------------------------------------------------
# Rev11: dedicated dispatch-marker authority and canonical Phase-B proof
# ---------------------------------------------------------------------------

VALID_MARKER_SETS = (
    ("reserved",),
    ("reserved", "prepared"),
    ("reserved", "prepared", "client_constructed"),
    DISPATCH_MARKERS,
)


def _seed_running_with_markers(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
    markers: tuple[str, ...],
) -> None:
    _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
    connection.execute(
        "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
        (job_id, profile_id),
    )
    _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
    for marker in markers:
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, %s)",
            (job_id, profile_id, marker),
        )


def _admin_seed_running(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
) -> None:
    connection.execute(
        "INSERT INTO dev_eval.photo_jobs (job_id, profile_id, status, lease_expires_at) "
        "VALUES (%s, %s, 'running', now() - interval '1 minute')",
        (job_id, profile_id),
    )


def _admin_pending(
    connection: psycopg.Connection[tuple[object, ...]],
    job_id: str,
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT filesystem_cleanup_pending FROM dev_eval.photo_jobs WHERE job_id=%s",
        (job_id,),
    ).fetchone()


def test_rev11_dispatch_marker_state_machine_rejects_skips_and_out_of_order(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-marker-machine"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 0, 'reserved')",
            (job_id, profile_id),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 2, 'reserved')",
            (job_id, profile_id),
        )
        for skip in ("prepared", "client_constructed", "send_boundary"):
            _assert_sqlstate(
                connection,
                "23514",
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, %s)",
                (job_id, profile_id, skip),
            )
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'reserved')",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'reserved')",
            (job_id, profile_id),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'client_constructed')",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'prepared')",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'client_constructed')",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'send_boundary')",
            (job_id, profile_id),
        )
        # Exact duplicates stay idempotent after the send boundary; no new
        # marker value exists to attempt, so the closed-vocabulary end state
        # is exactly the four durable markers.
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'send_boundary')",
            (job_id, profile_id),
        )
        markers = connection.execute(
            "SELECT marker FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
    assert sorted(str(row[0]) for row in markers) == sorted(DISPATCH_MARKERS)


def test_rev11_dispatch_marker_requires_running_state(
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-marker-running"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'reserved')",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'reserved')",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'prepared')",
            (job_id, profile_id),
        )
        _force_status(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            to_status="failed",
            cause="provider_error",
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'client_constructed')",
            (job_id, profile_id),
        )


@pytest.mark.parametrize("marker_set", VALID_MARKER_SETS)
def test_rev11_valid_marker_prefix_sets_reconcile_to_failed(
    phase6_schema: dict[str, str],
    marker_set: tuple[str, ...],
) -> None:
    from itda.photo import jobs as photo_jobs

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-prefix-" + secrets.token_hex(4)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _seed_running_with_markers(
            connection, job_id=job_id, profile_id=profile_id, markers=marker_set
        )
    with (
        psycopg.connect(phase6_schema["job"], autocommit=True) as connection,
        pytest.raises(photo_jobs.PhotoJobError),
    ):
        photo_jobs.reconcile_interrupted_jobs(connection)
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, profile_id)
    assert row == ("running",), "quarantine authority absence must keep the row untouched"


@pytest.mark.parametrize(
    "marker_set",
    (
        ("send_boundary",),
        ("reserved", "send_boundary"),
        ("prepared",),
        ("client_constructed",),
        ("client_constructed", "send_boundary"),
        ("prepared", "client_constructed"),
    ),
)
def test_rev11_malformed_marker_sets_never_count_as_uncertain_send(
    postgres_harness: object,
    phase6_schema: dict[str, str],
    marker_set: tuple[str, ...],
) -> None:
    from itda.photo import jobs as photo_jobs

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-malformed-" + secrets.token_hex(4)
    with _admin(postgres_harness) as connection:
        _admin_seed_running(connection, job_id=job_id, profile_id=profile_id)
        for marker in marker_set:
            connection.execute(
                "INSERT INTO dev_eval.photo_job_dispatch_markers (job_id, attempt, marker) "
                "VALUES (%s, 1, %s)",
                (job_id, marker),
            )
    with (
        psycopg.connect(phase6_schema["job"], autocommit=True) as connection,
        pytest.raises(photo_jobs.PhotoJobError),
    ):
        photo_jobs.reconcile_interrupted_jobs(connection)
    with psycopg.connect(phase6_schema["job"]) as connection:
        row = _read_status(connection, job_id, profile_id)
    assert row == ("running",), (
        "a malformed historical marker set must never be treated as an uncertain "
        "send, and reconciliation without quarantine authority must fail closed "
        "without transitioning the row"
    )


def test_rev11_reason_only_forged_ledger_is_not_projected_or_locked(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-forged-reason"
    canonical_reason = "PHOTO_PROVIDER_ERROR"
    canonical_key = _terminal_operation_key(job_id, profile_id, "provider_error", canonical_reason)
    canonical_digest = _terminal_residue_digest(canonical_key)
    forged_reason = "PHOTO_FORGED_REASON"
    forged_key = _terminal_operation_key(job_id, profile_id, "provider_error", forged_reason)
    forged_digest = _terminal_residue_digest(forged_key)
    with _admin(postgres_harness) as connection:
        _admin_seed_running(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "UPDATE dev_eval.photo_jobs SET status='failed', terminal_cause='provider_error', "
            "terminal_operation_key=%s, terminal_proof_digest=%s "
            "WHERE job_id = %s",
            (canonical_key, canonical_digest, job_id),
        )
        connection.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, operation_key, residue_count, residue_proof_digest) "
            "VALUES (%s, 'provider_error', %s, %s, 0, %s)",
            (job_id, forged_reason, forged_key, forged_digest),
        )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        candidates = connection.execute(
            "SELECT job_id, cleanup_class FROM dev_eval.list_photo_cleanup_candidates_v3()"
        ).fetchall()
        assert (job_id, "orphan_cleanup") not in [
            (str(row[0]), str(row[1])) for row in candidates
        ], "reason-only forged ledger must not project as a cleanup candidate"
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT status, lease_expires_at, binding_claimed "
            "FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'reconcile')",
            (job_id, profile_id),
        )


def test_rev11_arbitrary_operation_key_keeps_pending_and_release_rejected(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-arbitrary-key"
    cause = "provider_error"
    reason_code = "PHOTO_PROVIDER_ERROR"
    canonical_key = _terminal_operation_key(job_id, profile_id, cause, reason_code)
    canonical_digest = _terminal_residue_digest(canonical_key)
    arbitrary_key = secrets.token_hex(32)
    arbitrary_digest = _terminal_residue_digest(arbitrary_key)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3(%s, %s, %s, %s, %s, 0, %s)",
            (job_id, profile_id, cause, reason_code, canonical_key, canonical_digest),
        )
        connection.execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                "running",
                "failed",
                cause,
                reason_code,
                canonical_key,
                canonical_digest,
            ),
        )
        release = connection.execute(
            "SELECT operation_key, proof_digest "
            "FROM dev_eval.read_photo_filesystem_release_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert release == (canonical_key, canonical_digest), (
            "the release projection must derive and return the canonical pair"
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.pending_photo_filesystem_release_v3(%s, %s, %s, %s)",
            (job_id, profile_id, arbitrary_key, arbitrary_digest),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s, %s, %s, %s)",
            (job_id, profile_id, arbitrary_key, arbitrary_digest),
        )
        completed = connection.execute(
            "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s, %s, %s, %s)",
            (job_id, profile_id, canonical_key, canonical_digest),
        ).fetchone()
        assert completed == (True,)
    with _admin(postgres_harness) as connection:
        after = _admin_pending(connection, job_id)
    assert after == (False,)


def test_rev11_reason_only_corruption_keeps_pending_release_rejected(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-reason-corruption"
    cause = "provider_error"
    reason_code = "PHOTO_PROVIDER_ERROR"
    canonical_key = _terminal_operation_key(job_id, profile_id, cause, reason_code)
    canonical_digest = _terminal_residue_digest(canonical_key)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3(%s, %s, %s, %s, %s, 0, %s)",
            (job_id, profile_id, cause, reason_code, canonical_key, canonical_digest),
        )
        connection.execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                job_id,
                profile_id,
                "running",
                "failed",
                cause,
                reason_code,
                canonical_key,
                canonical_digest,
            ),
        )
    with _admin(postgres_harness) as connection:
        other_reason = "PHOTO_OTHER_REASON"
        other_key = _terminal_operation_key(job_id, profile_id, cause, other_reason)
        connection.execute(
            "UPDATE dev_eval.photo_deletion_ledger "
            "SET reason_code=%s, operation_key=%s "
            "WHERE job_id=%s AND cause=%s",
            (other_reason, other_key, job_id, cause),
        )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        release = connection.execute(
            "SELECT operation_key, proof_digest "
            "FROM dev_eval.read_photo_filesystem_release_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert release is None, (
            "reason-corrupted ledger must not project a releasable canonical pair"
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.pending_photo_filesystem_release_v3(%s, %s, %s, %s)",
            (job_id, profile_id, canonical_key, canonical_digest),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s, %s, %s, %s)",
            (job_id, profile_id, canonical_key, canonical_digest),
        )
    with _admin(postgres_harness) as connection:
        pending = _admin_pending(connection, job_id)
    assert pending == (True,), "reason corruption must keep filesystem_cleanup_pending"


def test_rev11_fabricated_key_digest_pair_rejects_candidate_lock_pending_complete(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev11-fabricated"
    fabricated_key = secrets.token_hex(32)
    fabricated_digest = _terminal_residue_digest(fabricated_key)
    with _admin(postgres_harness) as connection:
        _admin_seed_running(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "UPDATE dev_eval.photo_jobs SET status='failed', terminal_cause='worker_crash', "
            "terminal_operation_key=%s, terminal_proof_digest=%s "
            "WHERE job_id = %s",
            (fabricated_key, fabricated_digest, job_id),
        )
        connection.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, operation_key, residue_count, residue_proof_digest) "
            "VALUES (%s, 'worker_crash', 'PHOTO_WORKER_CRASH', %s, 0, %s)",
            (job_id, fabricated_key, fabricated_digest),
        )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        candidates = connection.execute(
            "SELECT job_id FROM dev_eval.list_photo_cleanup_candidates_v3()"
        ).fetchall()
        assert job_id not in [str(row[0]) for row in candidates], (
            "fabricated K+SHA(K) must not project as a cleanup candidate"
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT status, lease_expires_at, binding_claimed "
            "FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'reconcile')",
            (job_id, profile_id),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.pending_photo_filesystem_release_v3(%s, %s, %s, %s)",
            (job_id, profile_id, fabricated_key, fabricated_digest),
        )
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s, %s, %s, %s)",
            (job_id, profile_id, fabricated_key, fabricated_digest),
        )


# ---------------------------------------------------------------------------
# Rev12: nullable legacy residue_count cannot authorize terminal transition
# ---------------------------------------------------------------------------


def _admin_seed_running_bound(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
) -> None:
    _admin_seed_running(connection, job_id=job_id, profile_id=profile_id)
    connection.execute(
        "INSERT INTO dev_eval.photo_job_filesystem_bindings (job_id, profile_id) VALUES (%s, %s)",
        (job_id, profile_id),
    )


def _finalize_provider_error(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
    operation_key: str,
    residue_digest: str,
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT dev_eval.finalize_photo_job_terminal_v3"
        "(%s, %s, 'running', 'failed', 'provider_error', "
        "'PHOTO_PROVIDER_ERROR', %s, %s)",
        (job_id, profile_id, operation_key, residue_digest),
    ).fetchone()


def _admin_terminal_state(
    connection: psycopg.Connection[tuple[object, ...]],
    job_id: str,
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT status, terminal_cause, terminal_operation_key, "
        "terminal_proof_digest, filesystem_cleanup_pending "
        "FROM dev_eval.photo_jobs WHERE job_id=%s",
        (job_id,),
    ).fetchone()


def test_rev12_unbound_running_job_cannot_begin_dispatch_markers(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev12-unbound-dispatch"
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _insert_queued_job(connection, job_id=job_id, profile_id=profile_id)
        _force_status(connection, job_id=job_id, profile_id=profile_id, to_status="running")
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, 'reserved')",
            (job_id, profile_id),
        )
        markers = connection.execute(
            "SELECT marker FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
        assert markers == []
    with _admin(postgres_harness) as connection:
        assert connection.execute(
            "SELECT count(*) FROM dev_eval.photo_job_dispatch_markers WHERE job_id=%s",
            (job_id,),
        ).fetchone() == (0,)


def test_rev12_bound_running_job_accepts_exact_dispatch_prefix(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev12-bound-dispatch"
    with _admin(postgres_harness) as connection:
        _admin_seed_running_bound(connection, job_id=job_id, profile_id=profile_id)
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        for marker in ("reserved", "prepared", "send_boundary"):
            connection.execute(
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, %s)",
                (job_id, profile_id, marker),
            )
        markers = connection.execute(
            "SELECT marker FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
    assert {str(row[0]) for row in markers} == {
        "reserved",
        "prepared",
        "send_boundary",
    }


def test_rev12_null_residue_count_cannot_authorize_initial_terminal_transition(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev12-null-residue"
    operation_key = _terminal_operation_key(
        job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
    )
    residue_digest = _terminal_residue_digest(operation_key)
    with _admin(postgres_harness) as connection:
        _admin_seed_running_bound(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, operation_key, residue_count, "
            "residue_proof_digest) VALUES "
            "(%s, 'provider_error', 'PHOTO_PROVIDER_ERROR', %s, NULL, %s)",
            (job_id, operation_key, residue_digest),
        )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        _assert_sqlstate(
            connection,
            "23514",
            "SELECT dev_eval.finalize_photo_job_terminal_v3"
            "(%s, %s, 'running', 'failed', 'provider_error', "
            "'PHOTO_PROVIDER_ERROR', %s, %s)",
            (job_id, profile_id, operation_key, residue_digest),
        )
    with _admin(postgres_harness) as connection:
        assert _admin_terminal_state(connection, job_id) == (
            "running",
            None,
            None,
            None,
            False,
        )


def test_rev12_legacy_null_row_does_not_combine_with_valid_zero_row(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev12-null-plus-valid"
    operation_key = _terminal_operation_key(
        job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
    )
    residue_digest = _terminal_residue_digest(operation_key)
    with _admin(postgres_harness) as connection:
        _admin_seed_running_bound(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, operation_key, residue_count, "
            "residue_proof_digest) VALUES "
            "(%s, 'provider_error', 'PHOTO_PROVIDER_ERROR', NULL, NULL, %s), "
            "(%s, 'provider_error', 'PHOTO_PROVIDER_ERROR', %s, 0, %s)",
            (
                job_id,
                secrets.token_hex(32),
                job_id,
                operation_key,
                residue_digest,
            ),
        )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        assert _finalize_provider_error(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=operation_key,
            residue_digest=residue_digest,
        ) == ("running",)
    with _admin(postgres_harness) as connection:
        assert _admin_terminal_state(connection, job_id) == (
            "failed",
            "provider_error",
            operation_key,
            residue_digest,
            True,
        )


def test_rev12_valid_zero_row_finalizer_remains_idempotent(
    postgres_harness: object,
    phase6_schema: dict[str, str],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev12-valid-idempotent"
    operation_key = _terminal_operation_key(
        job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
    )
    residue_digest = _terminal_residue_digest(operation_key)
    with _admin(postgres_harness) as connection:
        _admin_seed_running_bound(connection, job_id=job_id, profile_id=profile_id)
        connection.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, operation_key, residue_count, "
            "residue_proof_digest) VALUES "
            "(%s, 'provider_error', 'PHOTO_PROVIDER_ERROR', %s, 0, %s)",
            (job_id, operation_key, residue_digest),
        )
    with psycopg.connect(phase6_schema["job"], autocommit=True) as connection:
        assert _finalize_provider_error(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=operation_key,
            residue_digest=residue_digest,
        ) == ("running",)
        assert _finalize_provider_error(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=operation_key,
            residue_digest=residue_digest,
        ) == ("failed",)
    with _admin(postgres_harness) as connection:
        assert _admin_terminal_state(connection, job_id) == (
            "failed",
            "provider_error",
            operation_key,
            residue_digest,
            True,
        )
