"""Controlled-RED DB+filesystem contracts for Phase 6 deletion truth.

Wave 0 freezes PHOT-08 before any deletion owner exists: every one of
the nine terminal causes must converge to

1. removal of all original quarantine objects (filesystem truth), and
2. an append-only public-safe ledger row (database truth), and
3. a descriptor-based residue sweep proving both.

Terminal completion requires BOTH subsystems; a ledger row alone or a
clean directory alone never proves deletion. Failure injection between
unlink, directory fsync, ledger insertion, and status mutation must
leave the job in a non-terminal ``cleanup_pending`` internal phase that
projects as UI cleanup pending, and repeated delete/sweep after lost
responses must be idempotent. Ledger UPDATE/DELETE/TRUNCATE are denied
and public ledger rows expose only opaque IDs, cause/reason codes,
timestamps, and proof digests.

The module is provider-free and opens no BLIND-12 path.
"""

from __future__ import annotations

import multiprocessing
import os
import re
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from itda.db.session import sqlalchemy_url_from_dsn
from itda.photo import deletion as photo_deletion
from tests.integration.profile_release_test_support import (
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
    ensure_profile_session_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"


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
def phase6_deletion_schema(postgres_harness: object) -> Iterator[None]:
    """Migrate the module's harness database to head once.

    Migration 0020 is intentionally irreversible, so teardown truncates the
    deletion state instead of downgrading.
    """

    ensure_profile_release_authority_roles(postgres_harness)  # type: ignore[attr-defined]
    ensure_profile_session_roles(postgres_harness)  # type: ignore[attr-defined]
    ensure_photo_lifecycle_roles(postgres_harness)  # type: ignore[attr-defined]
    command.upgrade(_migration_config(postgres_harness), "head")
    yield
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        connection.execute("TRUNCATE dev_eval.photo_deletion_ledger")
        connection.execute("TRUNCATE dev_eval.photo_jobs CASCADE")


TERMINAL_CAUSES = (
    "success",
    "rejection",
    "validation_failure",
    "provider_error",
    "timeout",
    "worker_crash",
    "explicit_deletion",
    "expiry",
    "orphan_cleanup",
)
CAUSE_KINDS: dict[str, str] = {
    "success": "job_success",
    "rejection": "job_failure",
    "validation_failure": "job_failure",
    "provider_error": "job_failure",
    "timeout": "job_failure",
    "worker_crash": "job_failure",
    "explicit_deletion": "user_requested",
    "expiry": "lifecycle",
    "orphan_cleanup": "lifecycle",
}
FAILURE_INJECTION_POINTS = (
    "after_unlink",
    "after_dir_fsync",
    "after_ledger_insert",
    "after_terminal_mutation",
    "after_terminal_commit",
    "after_binding_unlink",
    "before_directory_rmdir",
    "after_filesystem_release",
)
PUBLIC_LEDGER_COLUMNS = (
    "job_id",
    "cause",
    "reason_code",
    "recorded_at",
    "residue_proof_digest",
)

O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@pytest.fixture
def quarantine_root(tmp_path: Path) -> Path:
    root = tmp_path / "quarantine"
    root.mkdir(mode=0o700)
    return root


def _seed_quarantine_objects(
    root: Path, job_id: str, profile_id: str, *, count: int = 3
) -> list[Path]:
    """Create generated-name quarantine objects the way the writer must."""

    job_dir = root / job_id
    job_dir.mkdir(mode=0o700)
    job_dir_fd = os.open(job_dir, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    binding_fd = os.open(
        ".itda-owner-v1",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        dir_fd=job_dir_fd,
        mode=0o600,
    )
    with os.fdopen(binding_fd, "wb") as binding:
        binding.write(f"{job_id}\n{profile_id}\n".encode())
    written = []
    for index in range(count):
        target = job_dir / secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC
        fd = os.open(target.name, flags, dir_fd=job_dir_fd, mode=0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(b"\x89PNG\r\n\x1a\n" + bytes([index]) * 32)
        written.append(target)
    os.close(job_dir_fd)
    return written


def _fs_residue(root: Path, job_id: str) -> list[str]:
    """Descriptor-free residue inventory used only by the RED test itself."""

    job_dir = root / job_id
    if not job_dir.exists():
        return []
    return sorted(entry.name for entry in job_dir.iterdir())


def _exit_phase_a_boundary(
    service_dsn: str,
    quarantine_root: str,
    job_id: str,
    profile_id: str,
    boundary: str,
    exit_code: int,
) -> None:
    def terminate_at_boundary(injection_point: str | None, reached: str) -> None:
        if injection_point == reached == boundary:
            os._exit(exit_code)

    photo_deletion._inject = terminate_at_boundary  # type: ignore[assignment]  # noqa: SLF001
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=Path(quarantine_root),
            job_id=job_id,
            profile_id=profile_id,
            cause="worker_crash",
            reason_code="PHOTO_WORKER_CRASH",
            from_status="running",
            to_status="failed",
            injection_point=boundary,
        )


def _exit_after_filesystem_release(
    service_dsn: str, quarantine_root: str, job_id: str, profile_id: str
) -> None:
    """Child crash after terminal commit and FS release, before DB completion."""

    def terminate_at_boundary(injection_point: str | None, boundary: str) -> None:
        if injection_point == boundary == "after_filesystem_release":
            os._exit(73)

    photo_deletion._inject = terminate_at_boundary  # type: ignore[assignment]  # noqa: SLF001
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=Path(quarantine_root),
            job_id=job_id,
            profile_id=profile_id,
            cause="worker_crash",
            reason_code="PHOTO_WORKER_CRASH",
            from_status="running",
            to_status="failed",
        )
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=Path(quarantine_root),
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
            injection_point="after_filesystem_release",
        )


def _exit_after_binding_unlink(
    service_dsn: str, quarantine_root: str, job_id: str, profile_id: str
) -> None:
    def terminate_at_boundary(injection_point: str | None, boundary: str) -> None:
        if injection_point == boundary == "after_binding_unlink":
            os._exit(74)

    photo_deletion._inject = terminate_at_boundary  # type: ignore[assignment]  # noqa: SLF001
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        pointer = connection.execute(
            "SELECT terminal_operation_key,terminal_proof_digest "
            "FROM dev_eval.list_photo_cleanup_candidates_v3() WHERE job_id=%s",
            (job_id,),
        ).fetchone()
        assert pointer is not None
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=Path(quarantine_root),
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(pointer[0]),
            proof_digest=str(pointer[1]),
            injection_point="after_binding_unlink",
        )


def _ledger_rows(
    connection: psycopg.Connection[tuple[object, ...]],
    job_id: str,
    profile_id: str,
) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT * FROM dev_eval.list_photo_deletion_ledger_v3(%s, %s)",
        (job_id, profile_id),
    ).fetchall()


def _service_dsn(postgres_harness: object) -> str:
    """The fixed photo service DSN: the only principal allowed to append."""

    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles

    fixed = ensure_photo_lifecycle_roles(postgres_harness)  # type: ignore[arg-type]
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])  # type: ignore[attr-defined]
    return make_conninfo(
        **(admin_info | {"user": fixed["service_role"], "password": fixed["service_password"]})
    )


def _require_photo_deletion_owner() -> None:
    """Import the Phase 6 deletion owner or name its absence."""

    try:
        from itda.photo import deletion, jobs  # noqa: F401
    except ModuleNotFoundError as error:
        pytest.fail(f"PHASE6-MISSING:photo-deletion-owner ({error})", pytrace=False)


def test_nine_terminal_causes_are_exactly_parameterized() -> None:
    _require_photo_deletion_owner()
    from itda.photo import deletion as photo_deletion

    assert tuple(photo_deletion.TERMINAL_CAUSES) == TERMINAL_CAUSES
    assert len(photo_deletion.TERMINAL_CAUSES) == 9


LEDGER_CALLER_STATES: dict[str, tuple[str, str]] = {
    "success": ("running", "succeeded"),
    "rejection": ("queued", "failed"),
    "validation_failure": ("queued", "failed"),
    "provider_error": ("running", "failed"),
    "timeout": ("running", "failed"),
    "worker_crash": ("running", "failed"),
    "explicit_deletion": ("queued", "deleted"),
    "expiry": ("queued", "expired"),
    "orphan_cleanup": ("expired", "deleted"),
}


def _seed_owned_lifecycle(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    job_id: str,
    profile_id: str,
    state: str,
) -> None:
    """Create one owned job and transition it to the cause's caller state."""

    connection.execute(
        "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)",
        (job_id, profile_id),
    )
    connection.execute(
        "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
        (job_id, profile_id),
    )
    if state == "queued":
        return
    connection.execute(
        "SELECT dev_eval.transition_photo_job_nonterminal_v3"
        "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
        (job_id, profile_id),
    )
    if state == "running":
        return
    if state != "expired":
        raise AssertionError(f"unsupported proof-bound seed state: {state}")
    operation = photo_deletion._operation_key(  # noqa: SLF001 - exact integration proof
        job_id, profile_id, "expiry", "PHOTO_EXPIRY"
    )
    digest = photo_deletion._proof_digest(operation, 0)  # noqa: SLF001
    connection.execute(
        "SELECT dev_eval.append_photo_deletion_ledger_v3"
        "(%s, %s, 'expiry', 'PHOTO_EXPIRY', %s, 0, %s)",
        (job_id, profile_id, operation, digest),
    )
    connection.execute(
        "SELECT dev_eval.finalize_photo_job_terminal_v3"
        "(%s, %s, 'running', 'expired', 'expiry', 'PHOTO_EXPIRY', %s, %s)",
        (job_id, profile_id, operation, digest),
    )


@pytest.mark.parametrize("cause", TERMINAL_CAUSES)
def test_every_cause_requires_dual_truth_before_terminal_completion(
    postgres_harness: object,
    quarantine_root: Path,
    cause: str,
    phase6_deletion_schema: None,
) -> None:
    """Ledger truth AND descriptor-derived zero residue are jointly required.

    Each of the nine causes is appended from its real lifecycle caller
    state through the ownership-locked ledger function.
    """

    _require_photo_deletion_owner()
    from itda.photo import deletion as photo_deletion

    job_id = secrets.token_hex(32)
    profile_id = f"anonymous:ledger-{cause}"
    written = _seed_quarantine_objects(quarantine_root, job_id, profile_id)
    assert written

    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        from_status, to_status = LEDGER_CALLER_STATES[cause]
        _seed_owned_lifecycle(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            state=from_status,
        )
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause=cause,
            reason_code=f"PHOTO_{cause.upper()}",
            from_status=from_status,
            to_status=to_status,
        )
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )
        rows = _ledger_rows(connection, job_id, profile_id)
    assert _fs_residue(quarantine_root, job_id) == [], "original objects must be gone"
    assert sum(row[2] == cause for row in rows) == 1, (
        "exactly one idempotent ledger row per terminal operation"
    )
    assert outcome.complete is True
    assert outcome.residue_count == 0
    assert outcome.proof_digest is not None


@pytest.mark.parametrize("cause", TERMINAL_CAUSES)
def test_ledger_rows_expose_only_public_safe_columns(cause: str) -> None:
    """The ledger row schema must carry opaque IDs and proof digests only."""

    _require_photo_deletion_owner()
    from itda.photo import deletion as photo_deletion

    columns = tuple(photo_deletion.PUBLIC_LEDGER_COLUMNS)
    assert set(columns) == set(PUBLIC_LEDGER_COLUMNS)
    for forbidden in ("filename", "original_name", "path", "image_bytes", "trait", "provider"):
        assert forbidden not in columns
    assert photo_deletion.cause_kind(cause) == CAUSE_KINDS[cause]


@pytest.mark.parametrize("injection_point", FAILURE_INJECTION_POINTS)
def test_failure_injection_rolls_back_terminal_state_and_converges_on_retry(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    injection_point: str,
) -> None:
    """Pre-commit boundaries roll back; a fresh retry converges.

    Phase-B injection points are post-commit boundaries: the terminal row and
    ledger survive, and startup reconciliation completes the pending marker
    from either a half-released or fully released directory.
    """

    from itda.photo.jobs import reconcile_interrupted_jobs

    job_id = secrets.token_hex(32)
    profile_id = f"anonymous:injection-{injection_point}"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            state="running",
        )
        outcome = None
        if injection_point == "after_terminal_commit":
            with pytest.raises(photo_deletion.DeletionIncomplete):
                photo_deletion.execute_terminal_deletion_with_failure_injection(
                    connection=connection,
                    quarantine_root=quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    cause="provider_error",
                    reason_code="PHOTO_PROVIDER_ERROR",
                    injection_point=injection_point,
                    from_status="running",
                    to_status="failed",
                )
            state = connection.execute(
                "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            assert state == ("failed",)
            pending = connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            assert pending == (True,)
            report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
            assert report.examined >= 1
            final_pending = connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            assert final_pending == (False,)
            assert _fs_residue(quarantine_root, job_id) == []
            return
        if injection_point in {
            "after_binding_unlink",
            "before_directory_rmdir",
            "after_filesystem_release",
        }:
            outcome = photo_deletion.execute_terminal_deletion(
                connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                cause="provider_error",
                reason_code="PHOTO_PROVIDER_ERROR",
                from_status="running",
                to_status="failed",
            )
            with pytest.raises(photo_deletion.DeletionIncomplete):
                photo_deletion.release_filesystem_cleanup(
                    connection,
                    quarantine_root=quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    operation_key=str(outcome.operation_key),
                    proof_digest=str(outcome.proof_digest),
                    injection_point=injection_point,
                )
            state = connection.execute(
                "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            assert state == ("failed",)
            pending = connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            assert pending == (True,)
            report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
            assert report.examined >= 1
            final_pending = connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            assert final_pending == (False,)
            assert _fs_residue(quarantine_root, job_id) == []
            return
        with pytest.raises(photo_deletion.DeletionIncomplete):
            photo_deletion.execute_terminal_deletion_with_failure_injection(
                connection=connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                cause="provider_error",
                reason_code="PHOTO_PROVIDER_ERROR",
                injection_point=injection_point,
                from_status="running",
                to_status="failed",
            )
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert state == ("running",)
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
    assert outcome.complete is True
    assert state == ("failed",)
    assert _fs_residue(quarantine_root, job_id) == []


@pytest.mark.parametrize(
    ("boundary", "exit_code"),
    (
        ("after_unlink", 81),
        ("after_dir_fsync", 82),
        ("after_ledger_insert", 83),
        ("after_terminal_mutation", 84),
    ),
)
def test_actual_phase_a_process_exit_rolls_back_and_startup_converges(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    boundary: str,
    exit_code: int,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = f"profile-phase-a-exit-{boundary}"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute' "
            "WHERE job_id=%s",
            (job_id,),
        )
    child = multiprocessing.get_context("fork").Process(
        target=_exit_phase_a_boundary,
        args=(service_dsn, str(quarantine_root), job_id, profile_id, boundary, exit_code),
    )
    child.start()
    child.join(timeout=15)
    assert child.exitcode == exit_code
    assert (quarantine_root / job_id / ".itda-owner-v1").is_file()
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT status,terminal_operation_key,terminal_proof_digest,"
            "filesystem_cleanup_pending FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("running", None, None, False)
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s",
            (job_id,),
        ).fetchone() == (0,)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
        assert report.examined >= 1
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT status,terminal_cause,filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("failed", "worker_crash", False)
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s",
            (job_id,),
        ).fetchone() == (1,)
    assert not (quarantine_root / job_id).exists()


def test_actual_post_commit_pre_release_exit_lifespan_converges(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-post-commit-exit"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    child = multiprocessing.get_context("fork").Process(
        target=_exit_phase_a_boundary,
        args=(service_dsn, str(quarantine_root), job_id, profile_id, "after_terminal_commit", 85),
    )
    child.start()
    child.join(timeout=15)
    assert child.exitcode == 85
    assert _fs_residue(quarantine_root, job_id) == [".itda-owner-v1"]
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT status,terminal_cause,filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("failed", "worker_crash", True)
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s",
            (job_id,),
        ).fetchone() == (1,)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
        assert report.examined >= 1
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT status,terminal_cause,filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("failed", "worker_crash", False)
    assert not (quarantine_root / job_id).exists()


def test_process_exit_after_filesystem_release_keeps_terminal_and_startup_completes(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "anonymous:process-exit"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_KEY", raising=False)
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    monkeypatch.delenv("BIGMODEL_API_KEY", raising=False)

    child = multiprocessing.get_context("fork").Process(
        target=_exit_after_filesystem_release,
        args=(service_dsn, str(quarantine_root), job_id, profile_id),
    )
    child.start()
    child.join(timeout=15)
    assert child.exitcode == 73, "child crashed before the release boundary"
    # Terminal truth committed; FS released; completion marker still pending.
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert state == ("failed",)
        pending = connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert pending == (True,)
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
        assert report.examined >= 1
        final_state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        rows = _ledger_rows(connection, job_id, profile_id)
        final_pending = connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
    assert final_state == ("failed",)
    assert sum(row[2] == "worker_crash" for row in rows) == 1
    assert final_pending == (False,)


def test_repeated_deletion_and_sweep_are_idempotent_after_lost_response(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    _require_photo_deletion_owner()
    from itda.photo import deletion as photo_deletion

    job_id = secrets.token_hex(32)
    profile_id = "anonymous:ledger-idempotent"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        success_operation = photo_deletion._operation_key(  # noqa: SLF001
            job_id, profile_id, "success", "PHOTO_SUCCESS"
        )
        success_digest = photo_deletion._proof_digest(success_operation, 0)  # noqa: SLF001
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3"
            "(%s, %s, 'success', 'PHOTO_SUCCESS', %s, 0, %s)",
            (job_id, profile_id, success_operation, success_digest),
        )
        connection.execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3"
            "(%s, %s, 'running', 'succeeded', 'success', 'PHOTO_SUCCESS', %s, %s)",
            (job_id, profile_id, success_operation, success_digest),
        )
        first = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="explicit_deletion",
            reason_code="PHOTO_EXPLICIT_DELETION",
            from_status="succeeded",
            to_status="deleted",
        )
        second = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="explicit_deletion",
            reason_code="PHOTO_EXPLICIT_DELETION",
            from_status="succeeded",
            to_status="deleted",
        )
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(second.operation_key),
            proof_digest=str(second.proof_digest),
        )
        rows = _ledger_rows(connection, job_id, profile_id)
    assert first.complete is True
    assert second.complete is True
    assert _fs_residue(quarantine_root, job_id) == []
    assert sum(row[2] == "explicit_deletion" for row in rows) == 1, (
        "repeated deletion must not duplicate operation evidence"
    )
    assert second.ledger_row_created is False


@pytest.mark.parametrize("cause", ("explicit_deletion", "orphan_cleanup"))
def test_uncertain_completion_requires_real_transaction_authority(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    cause: str,
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = f"anonymous:reconcile-{cause}"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection,
            job_id=job_id,
            profile_id=profile_id,
            state="running" if cause == "orphan_cleanup" else "queued",
        )
        from_status = "queued"
        if cause == "explicit_deletion":
            with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
                admin.execute(
                    "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute'"
                    " WHERE job_id=%s",
                    (job_id,),
                )
        if cause == "orphan_cleanup":
            prior_operation = photo_deletion._operation_key(  # noqa: SLF001
                job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
            )
            prior_digest = photo_deletion._proof_digest(prior_operation, 0)  # noqa: SLF001
            connection.execute(
                "SELECT dev_eval.append_photo_deletion_ledger_v3"
                "(%s, %s, 'provider_error', 'PHOTO_PROVIDER_ERROR', %s, 0, %s)",
                (job_id, profile_id, prior_operation, prior_digest),
            )
            connection.execute(
                "SELECT dev_eval.finalize_photo_job_terminal_v3"
                "(%s, %s, 'running', 'failed', 'provider_error', "
                "'PHOTO_PROVIDER_ERROR', %s, %s)",
                (job_id, profile_id, prior_operation, prior_digest),
            )
            from_status = "failed"
        outcome = photo_deletion.reconcile_after_uncertain_completion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause=cause,
            reason_code=(
                "PHOTO_EXPLICIT_DELETION"
                if cause == "explicit_deletion"
                else "PHOTO_ORPHAN_CLEANUP"
            ),
            from_status=from_status,
            to_status="deleted",
        )
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )
    assert outcome.complete is True
    assert _fs_residue(quarantine_root, job_id) == []


def test_residue_sweep_uses_no_follow_descriptor_traversal(
    quarantine_root: Path,
) -> None:
    _require_photo_deletion_owner()
    from itda.photo import deletion as photo_deletion

    job_id = secrets.token_hex(32)
    job_dir = quarantine_root / job_id
    job_dir.mkdir(mode=0o700)
    outside = quarantine_root / "outside-sentinel.png"
    outside.write_bytes(b"sentinel")
    link = job_dir / secrets.token_hex(16)
    os.symlink(outside, link)

    binding = job_dir / ".itda-owner-v1"
    binding.write_text(f"{job_id}\nanonymous:symlink\n")
    binding.chmod(0o600)
    with pytest.raises(photo_deletion.DeletionIncomplete):
        photo_deletion.sweep_residue(
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id="anonymous:symlink",
        )
    assert outside.exists(), "sweep must never follow symlinks out of the job root"
    assert stat.S_ISLNK(link.lstat().st_mode)


def test_ledger_role_denies_update_delete_and_truncate(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    """The ledger role cannot UPDATE, DELETE, or TRUNCATE ledger truth."""

    suffix = secrets.token_hex(4)
    role_name = f"itda_photo_ledger_{suffix}"
    password = secrets.token_urlsafe(24)
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        from psycopg import sql

        connection.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOINHERIT"
            ).format(sql.Identifier(role_name), sql.Literal(password))
        )
        connection.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(postgres_harness.database_name),  # type: ignore[attr-defined]
                sql.Identifier(role_name),
            )
        )
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])  # type: ignore[attr-defined]
    ledger_dsn = make_conninfo(**(admin_info | {"user": role_name, "password": password}))
    try:
        with psycopg.connect(ledger_dsn, autocommit=True) as connection:
            for statement in (
                "UPDATE dev_eval.photo_deletion_ledger SET residue_proof_digest = repeat('0', 64)",
                "DELETE FROM dev_eval.photo_deletion_ledger",
                "TRUNCATE dev_eval.photo_deletion_ledger",
            ):
                try:
                    connection.execute(statement)
                except psycopg.Error as error:
                    assert error.sqlstate == "42501", (statement, error.sqlstate)
                else:
                    raise AssertionError(f"hostile ledger role operation succeeded: {statement}")
    finally:
        with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
            from psycopg import sql

            connection.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role_name))
            )
            connection.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role_name)))


def test_terminal_completion_cannot_be_asserted_from_one_subsystem(
    quarantine_root: Path,
) -> None:
    """A clean directory without a ledger row is NOT deletion completion."""

    _require_photo_deletion_owner()
    from itda.photo import deletion as photo_deletion

    job_id = secrets.token_hex(32)
    profile_id = "anonymous:one-subsystem"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id)
    photo_deletion.remove_all_objects(
        quarantine_root=quarantine_root, job_id=job_id, profile_id=profile_id
    )
    assert _fs_residue(quarantine_root, job_id) == [".itda-owner-v1"]
    with pytest.raises(photo_deletion.DeletionIncomplete):
        photo_deletion.assert_terminal_complete(ledger_rows=(), residue_count=0)


def test_canonical_identity_and_owner_binding_reject_collisions_before_bytes(
    quarantine_root: Path,
) -> None:
    from itda.photo import quarantine

    root_fd = os.open(quarantine_root, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    try:
        with pytest.raises(quarantine.QuarantineError):
            import anyio

            async def shortened() -> None:
                async def chunks():
                    yield b"x"

                await quarantine.stream_to_quarantine(
                    root_fd=root_fd,
                    job_directory=secrets.token_hex(16),
                    profile_id="profile-canonical",
                    image_index=1,
                    chunks=chunks(),
                    policy=quarantine.QuarantinePolicy(),
                    binding_claim_created=True,
                )

            anyio.run(shortened)
        full = secrets.token_hex(32)
        (quarantine_root / full).mkdir(mode=0o700)
        with pytest.raises(quarantine.QuarantineError):
            import anyio

            async def unbound() -> None:
                async def chunks():
                    yield b"x"

                await quarantine.stream_to_quarantine(
                    root_fd=root_fd,
                    job_directory=full,
                    profile_id="profile-canonical",
                    image_index=1,
                    chunks=chunks(),
                    policy=quarantine.QuarantinePolicy(),
                    binding_claim_created=True,
                )

            anyio.run(unbound)
        assert list((quarantine_root / full).iterdir()) == []
    finally:
        os.close(root_fd)


def test_exact_ledger_cause_reason_operation_and_digest_are_required() -> None:
    from itda.photo import deletion as photo_deletion

    operation_key = "c" * 64
    exact = (
        1,
        "a" * 64,
        "success",
        "PHOTO_SUCCESS",
        object(),
        operation_key,
        0,
        "b" * 64,
    )
    evidence = {
        "residue_count": 0,
        "job_id": "a" * 64,
        "cause": "success",
        "reason_code": "PHOTO_SUCCESS",
        "operation_key": operation_key,
        "proof_digest": "b" * 64,
    }
    photo_deletion.assert_terminal_complete(ledger_rows=(exact,), **evidence)
    unrelated = (
        2,
        "a" * 64,
        "timeout",
        "PHOTO_TIMEOUT",
        object(),
        "d" * 64,
        0,
        "e" * 64,
    )
    photo_deletion.assert_terminal_complete(
        ledger_rows=(unrelated, exact),
        **evidence,
    )
    for change in (
        exact[:2] + ("timeout",) + exact[3:],
        exact[:3] + ("PHOTO_TIMEOUT",) + exact[4:],
        exact[:5] + ("d" * 64,) + exact[6:],
        exact[:6] + (1,) + exact[7:],
        exact[:7] + ("",),
        exact[:7] + ("d" * 64,),
    ):
        with pytest.raises(photo_deletion.DeletionIncomplete):
            photo_deletion.assert_terminal_complete(
                ledger_rows=(change,),
                **evidence,
            )

    with pytest.raises(photo_deletion.DeletionIncomplete):
        photo_deletion.assert_terminal_complete(
            ledger_rows=(exact,),
            residue_count=0,
            job_id="a" * 64,
            cause="success",
            reason_code="PHOTO_SUCCESS",
            proof_digest="b" * 64,
        )


def test_non_enoent_inspection_error_and_type_substitution_fail_closed(
    quarantine_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from itda.photo import deletion as photo_deletion

    job_id = secrets.token_hex(32)
    profile_id = "profile-inspection-error"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    real_stat = photo_deletion.os.stat

    def denied(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if isinstance(path, str) and re.fullmatch(r"[0-9a-f]{32}", path):
            raise PermissionError("synthetic inspection denial")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(photo_deletion.os, "stat", denied)
    with pytest.raises(photo_deletion.DeletionIncomplete):
        photo_deletion.sweep_residue(
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
        )


@pytest.mark.parametrize(
    ("failure_kind", "cause"),
    (
        ("timeout", "timeout"),
        ("validation", "validation_failure"),
        ("rejection", "rejection"),
        ("provider", "provider_error"),
    ),
)
def test_gateway_submit_failure_boundaries_create_exact_terminal_proof(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    cause: str,
) -> None:
    from pathlib import Path as FilePath

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import create_database_engine, create_session_factory
    from itda.photo.preprocessing import PhotoUploadPreprocessingError

    failure: Exception = {
        "timeout": TimeoutError(),
        "validation": PhotoUploadPreprocessingError(),
        "rejection": ValueError("rejection boundary"),
        "provider": RuntimeError("provider boundary"),
    }[failure_kind]
    service_dsn = _service_dsn(postgres_harness)
    gateway = PhotoLifecycleGateway(
        factory=create_session_factory(create_database_engine(service_dsn)),
        service_dsn=service_dsn,
        quarantine_root=FilePath(quarantine_root),
        runtime_role=postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
        builder_role=postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
    )
    job_id = secrets.token_hex(32)
    profile_id = f"profile-submit-{cause}"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
        written = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
        connection.execute(
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s, %s, 1, %s, %s)",
            (job_id, profile_id, written[0].name, "image/png"),
        ).fetchone()
        connection.execute(
            "SELECT dev_eval.commit_photo_image_slot_v3(%s, %s, 1, %s, %s)",
            (job_id, profile_id, written[0].name, written[0].stat().st_size),
        )
    gateway._stored[job_id] = {1: (written[0].name, "image/png")}  # noqa: SLF001
    monkeypatch.setattr(
        gateway,
        "_analyze_stored_images",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )

    from itda.photo.jobs import PhotoJobError

    with pytest.raises(PhotoJobError):
        gateway.submit_job(job_id=job_id, profile_id=profile_id)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        matching = [row for row in _ledger_rows(connection, job_id, profile_id) if row[2] == cause]
    assert state == ("failed",)
    assert len(matching) == 1
    assert (
        photo_deletion.inspect_job_residue_count(
            quarantine_root=quarantine_root, job_id=job_id, profile_id=profile_id
        )
        == 0
    )


def test_startup_projection_is_bounded_and_actual_lifespan_converges_all_classes(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.api.main import create_app
    from itda.api.routes import photo as photo_route
    from itda.db.session import create_database_engine, create_session_factory

    service_dsn = _service_dsn(postgres_harness)
    gateway = photo_route.PhotoLifecycleGateway(
        factory=create_session_factory(create_database_engine(service_dsn)),
        service_dsn=service_dsn,
        quarantine_root=quarantine_root,
        runtime_role=postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
        builder_role=postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
    )
    candidates = {
        "worker_crash": (secrets.token_hex(32), "running"),
        "expiry": (secrets.token_hex(32), "queued"),
        "orphan_cleanup_failed": (secrets.token_hex(32), "failed"),
        "orphan_cleanup_expired": (secrets.token_hex(32), "expired"),
    }
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for label, (job_id, state) in candidates.items():
            profile_id = f"profile-startup-{label}"
            _seed_owned_lifecycle(
                connection,
                job_id=job_id,
                profile_id=profile_id,
                state="running" if state in {"running", "failed", "expired"} else "queued",
            )
            _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
            if state == "failed":
                photo_deletion.execute_terminal_deletion(
                    connection,
                    quarantine_root=quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    cause="provider_error",
                    reason_code="PHOTO_PROVIDER_ERROR",
                    from_status="running",
                    to_status="failed",
                )
            elif state == "expired":
                photo_deletion.execute_terminal_deletion(
                    connection,
                    quarantine_root=quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    cause="expiry",
                    reason_code="PHOTO_EXPIRY",
                    from_status="running",
                    to_status="expired",
                )
        admin_dsn = postgres_harness.dsns["admin"]  # type: ignore[attr-defined]
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute' "
                "WHERE job_id=ANY(%s) AND status IN ('running','queued')",
                ([job_id for job_id, _state in candidates.values()],),
            )
        projected = connection.execute(
            "SELECT job_id, profile_id, status, cleanup_class "
            "FROM dev_eval.list_photo_cleanup_candidates_v3()"
        ).fetchall()
    assert len(projected) <= 256
    assert {
        str(row[3]) for row in projected if str(row[0]) in {v[0] for v in candidates.values()}
    } == {
        "worker_crash",
        "expiry",
        "filesystem_release",
    }

    monkeypatch.setenv("ITDA_DATABASE_URL", service_dsn)
    monkeypatch.setenv("ITDA_PHOTO_SERVICE_DATABASE_URL", service_dsn)
    monkeypatch.setattr("itda.api.main.validate_profile_session_startup", lambda: None)
    monkeypatch.setattr("itda.api.main.get_photo_lifecycle", lambda: gateway)
    with TestClient(create_app()) as client:
        assert client.app is not None

    expected = {
        "worker_crash": ("failed", "worker_crash"),
        "expiry": ("expired", "expiry"),
        "orphan_cleanup_failed": ("failed", "provider_error"),
        "orphan_cleanup_expired": ("expired", "expiry"),
    }
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for label, (job_id, _state) in candidates.items():
            profile_id = f"profile-startup-{label}"
            state = connection.execute(
                "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            causes = [str(row[2]) for row in _ledger_rows(connection, job_id, profile_id)]
            assert state == (expected[label][0],)
            assert causes[-1] == expected[label][1]
            assert (
                photo_deletion.inspect_job_residue_count(
                    quarantine_root=quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                )
                == 0
            )


def test_cleanup_projection_race_is_rechecked_under_operation_lock(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-cleanup-race"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
    with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute' "
            "WHERE job_id=%s",
            (job_id,),
        )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT cleanup_class FROM dev_eval.list_photo_cleanup_candidates_v3() WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("expiry",)
    with psycopg.connect(postgres_harness.dsns["admin"], autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()+interval '5 minutes' "
            "WHERE job_id=%s",
            (job_id,),
        )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
    assert report.examined >= 0
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone() == ("queued",)
        assert _ledger_rows(connection, job_id, profile_id) == []


def test_route_gateway_success_uses_full_identity_and_dual_proof(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    from pathlib import Path as FilePath

    from sqlalchemy.orm import sessionmaker

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import create_database_engine, create_session_factory

    service_dsn = _service_dsn(postgres_harness)
    factory = create_session_factory(create_database_engine(service_dsn))
    gateway = PhotoLifecycleGateway(
        factory=factory,
        service_dsn=service_dsn,
        quarantine_root=FilePath(quarantine_root),
        runtime_role=postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
        builder_role=postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
    )
    assert isinstance(factory, sessionmaker)
    job_id = secrets.token_hex(32)
    profile_id = "profile-route-success"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="success",
            reason_code="PHOTO_SUCCESS",
            from_status="running",
            to_status="succeeded",
        )
        pending = connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        assert pending == (True,)
        assert (quarantine_root / job_id / ".itda-owner-v1").exists()
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        rows = _ledger_rows(connection, job_id, profile_id)
    assert gateway.authorize_image_upload.__self__ is gateway
    assert outcome.complete and state == ("succeeded",) and len(rows) == 1
    assert not (quarantine_root / job_id).exists()


# ---------------------------------------------------------------------------
# Rev6 findings F-03/F-04/F-05: exact v3 lock authority, terminal proof
# pointer, restart-safe inventory, and durable cleanup_pending semantics.
# ---------------------------------------------------------------------------

V3_WRAPPER_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("create_photo_job_v3", "(text,text,text)"),
    ("claim_photo_job_filesystem_binding_v3", "(text,text)"),
    ("read_photo_job_filesystem_binding_v3", "(text,text)"),
    ("lock_photo_job_operation_v3", "(text,text,text)"),
    ("list_photo_cleanup_candidates_v3", "()"),
    ("transition_photo_job_nonterminal_v3", "(text,text,text,text,timestamptz)"),
    ("record_photo_dispatch_marker_v3", "(text,text,integer,text)"),
    ("record_photo_candidate_batch_v3", "(text,text,text[],text[],text[],text[])"),
    ("annotate_photo_candidate_v3", "(text,text,text,text,boolean)"),
    ("save_photo_review_draft_v3", "(text,text,text,text[],text[],text[],boolean[])"),
    ("discard_photo_review_draft_v3", "(text,text)"),
    (
        "confirm_photo_traits_v3",
        "(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
    ),
    ("append_photo_deletion_ledger_v3", "(text,text,text,text,text,integer,text)"),
    ("finalize_photo_job_terminal_v3", "(text,text,text,text,text,text,text,text)"),
    ("finalize_photo_job_unbound_explicit_deletion_v3", "(text,text)"),
    ("list_photo_deletion_ledger_v3", "(text,text)"),
    ("read_photo_cleanup_status_v3", "(text,text)"),
    ("complete_photo_filesystem_cleanup_v3", "(text,text,text,text)"),
    ("pending_photo_filesystem_release_v3", "(text,text,text,text)"),
    ("read_photo_filesystem_release_v3", "(text,text)"),
    ("reserve_photo_image_slot_v3", "(text,text,integer,text,text)"),
    ("commit_photo_image_slot_v3", "(text,text,integer,text,integer)"),
    ("read_photo_image_slots_v3", "(text,text)"),
)


def _f03_admin_query(postgres_harness: object, statement: str, params: tuple) -> object:
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        return connection.execute(statement, params).fetchone()


def test_f03_every_v3_wrapper_is_defined_with_closed_service_authority(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    """F-03: all fifteen v3 wrappers exist, SECURITY DEFINER, owner-closed ACLs."""

    for name, signature in V3_WRAPPER_SIGNATURES:
        identity = f"dev_eval.{name}{signature}"
        definition = _f03_admin_query(
            postgres_harness,
            "SELECT p.prosecdef, pg_catalog.pg_get_userbyid(p.proowner), p.proconfig "
            "FROM pg_catalog.pg_proc p "
            "WHERE p.oid = pg_catalog.to_regprocedure(%s)",
            (identity,),
        )
        assert definition is not None, f"F-03 missing v3 wrapper {identity}"
        security_definer, owner, proconfig = definition
        assert security_definer is True, f"F-03 {identity} is not SECURITY DEFINER"
        assert owner == "itda_photo_write_authority", f"F-03 {identity} owner leaked"
        assert proconfig is not None and any(
            "search_path=pg_catalog" in str(entry) for entry in proconfig
        ), f"F-03 {identity} search_path is not pinned"
        privileges = _f03_admin_query(
            postgres_harness,
            "SELECT pg_catalog.has_function_privilege("
            "'itda_photo_service', %s, 'EXECUTE'), "
            "pg_catalog.has_function_privilege('public', %s, 'EXECUTE')",
            (identity, identity),
        )
        assert privileges == (True, False), f"F-03 authority leak in {identity}"


def test_f03_authoritative_v3_reads_hold_advisory_and_exact_row_locks(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    """F-03: binding and ledger reads must serialize under the operation authority."""

    expectations = {
        "read_photo_job_filesystem_binding_v3(text,text)": (
            "pg_advisory_xact_lock",
            "FOR UPDATE",
        ),
        "list_photo_deletion_ledger_v3(text,text)": ("pg_advisory_xact_lock",),
    }
    for identity, markers in expectations.items():
        prosrc = _f03_admin_query(
            postgres_harness,
            "SELECT p.prosrc FROM pg_catalog.pg_proc p "
            "WHERE p.oid = pg_catalog.to_regprocedure(%s)",
            (f"dev_eval.{identity}",),
        )
        assert prosrc is not None, f"F-03 missing function {identity}"
        for marker in markers:
            assert marker in str(prosrc[0]), f"F-03 {identity} lacks {marker}"


def test_f03_concurrent_binding_claims_admit_exactly_one_owner(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    """F-03: two concurrent claims converge to exactly one durable owner."""

    import threading

    job_id = secrets.token_hex(32)
    profile_id = "profile-f03-claim-race"
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)", (job_id, profile_id)
        )
    outcomes: list[bool] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(2)

    def claim() -> None:
        try:
            with psycopg.connect(service_dsn) as connection:
                barrier.wait(timeout=10)
                claimed = connection.execute(
                    "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
                    (job_id, profile_id),
                ).fetchone()
                connection.commit()
            outcomes.append(bool(claimed[0]))
        except Exception as error:  # noqa: BLE001 - thread boundary capture
            errors.append(error)

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert errors == []
    assert sorted(outcomes) == [False, True]


def test_f03_binding_read_serializes_under_the_operation_advisory_lock(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    """F-03: the binding read must not bypass a held operation advisory lock."""

    import threading

    job_id = secrets.token_hex(32)
    profile_id = "profile-f03-serialized-read"
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)", (job_id, profile_id)
        )
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
    holder = psycopg.connect(service_dsn)
    try:
        holder.execute(
            "SELECT status FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'upload')",
            (job_id, profile_id),
        ).fetchone()
        results: list[tuple[object, ...]] = []
        reader_errors: list[Exception] = []

        def read_binding() -> None:
            try:
                with psycopg.connect(service_dsn, autocommit=True) as reader:
                    results.append(
                        reader.execute(
                            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s, %s)",
                            (job_id, profile_id),
                        ).fetchone()
                    )
            except Exception as error:  # noqa: BLE001 - thread boundary capture
                reader_errors.append(error)

        thread = threading.Thread(target=read_binding)
        thread.start()
        thread.join(timeout=0.8)
        assert thread.is_alive(), (
            "F-03: the binding read must serialize under the held advisory lock"
        )
        holder.rollback()
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert reader_errors == []
        assert results == [(True,)]
    finally:
        holder.close()


def test_f04_terminal_transition_records_exact_proof_pointer(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """F-04: finalize writes the exact operation key and proof digest pointer."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-f04-pointer"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
    pointer = _f03_admin_query(
        postgres_harness,
        "SELECT terminal_operation_key, terminal_proof_digest "
        "FROM dev_eval.photo_jobs WHERE job_id=%s",
        (job_id,),
    )
    operation = photo_deletion._operation_key(  # noqa: SLF001
        job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
    )
    digest = photo_deletion._proof_digest(operation, 0)  # noqa: SLF001
    assert pointer == (operation, digest)


def test_f04_fabricated_v3_ledger_row_cannot_authorize_orphan_cleanup(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """F-04: cleanup eligibility matches the exact pointer, not a cause count.

    Adversarial shape: a historical terminal job (legacy NULL-operation ledger
    row) receives one fabricated v3 zero-residue row for the same cause. The
    count-based eligibility would admit it; the exact pointer must not.
    """

    job_id = secrets.token_hex(32)
    profile_id = "profile-f04-fabricated"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET status='failed', "
            "terminal_cause='provider_error', lease_expires_at=NULL "
            "WHERE job_id=%s",
            (job_id,),
        )
        admin.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, residue_proof_digest) "
            "VALUES (%s, 'provider_error', 'PHOTO_HISTORICAL', %s)",
            (job_id, "f" * 64),
        )
    fabricated_operation = photo_deletion._operation_key(  # noqa: SLF001
        job_id, profile_id, "provider_error", "PHOTO_FABRICATED"
    )
    fabricated_digest = photo_deletion._proof_digest(fabricated_operation, 0)  # noqa: SLF001
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3"
            "(%s, %s, 'provider_error', 'PHOTO_FABRICATED', %s, 0, %s)",
            (job_id, profile_id, fabricated_operation, fabricated_digest),
        )
        projected = connection.execute(
            "SELECT cleanup_class FROM dev_eval.list_photo_cleanup_candidates_v3() WHERE job_id=%s",
            (job_id,),
        ).fetchall()
        assert projected == [], (
            "F-04: a fabricated v3 row must not classify a legacy terminal job "
            "as orphan-cleanup eligible"
        )
        denied = False
        try:
            connection.execute(
                "SELECT * FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'reconcile')",
                (job_id, profile_id),
            ).fetchone()
        except psycopg.Error:
            denied = True
        assert denied, "F-04: the reconcile lock must reject non-pointer evidence"


def test_f04_public_job_read_exposes_no_proof_pointer(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """F-04: the public job projection stays the seven historical columns."""

    job_id = secrets.token_hex(32)
    profile_id = "profile-f04-public-read"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        cursor = connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_v2(%s, %s)", (job_id, profile_id)
        )
        columns = [column.name for column in cursor.description]
    assert len(columns) == 7
    assert not any("operation" in column or "digest" in column for column in columns), (
        "F-04: pointer values must never surface in public reads"
    )


def _f05_gateway(postgres_harness: object, quarantine_root: Path, service_dsn: str) -> object:
    from pathlib import Path as FilePath

    from itda.api.routes.photo import PhotoLifecycleGateway
    from itda.db.session import create_database_engine, create_session_factory

    return PhotoLifecycleGateway(
        factory=create_session_factory(create_database_engine(service_dsn)),
        service_dsn=service_dsn,
        quarantine_root=FilePath(quarantine_root),
        runtime_role=postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
        builder_role=postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
    )


def _f05_png_bytes() -> bytes:
    from io import BytesIO

    from PIL import Image

    buffer = BytesIO()
    Image.new("RGB", (8, 8), (255, 0, 0)).save(buffer, format="PNG")
    return buffer.getvalue()


def _f05_jpeg_bytes() -> bytes:
    from io import BytesIO

    from PIL import Image

    buffer = BytesIO()
    Image.new("RGB", (8, 8), (255, 0, 0)).save(buffer, format="JPEG")
    return buffer.getvalue()


def test_f05_restart_with_empty_local_inventory_fails_validation_without_reads(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-05: a restart (empty inventory) must fail closed, never false-succeed."""

    from itda.photo.jobs import PhotoJobError

    job_id = secrets.token_hex(32)
    profile_id = "profile-f05-restart-empty"
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=2)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    provider_calls: list[str] = []

    def forbidden_provider(**_kwargs: object) -> None:
        provider_calls.append("provider")

    monkeypatch.setattr(gateway._provider, "analyze", forbidden_provider)  # noqa: SLF001
    monkeypatch.setattr(gateway, "_sanitized_bytes", forbidden_provider)  # noqa: SLF001
    with pytest.raises(PhotoJobError):
        gateway.submit_job(job_id=job_id, profile_id=profile_id)
    assert provider_calls == [], "F-05: validation failure must not reach the provider"
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        causes = [str(row[2]) for row in _ledger_rows(connection, job_id, profile_id)]
    assert state == ("failed",)
    assert causes.count("validation_failure") == 1
    assert (
        photo_deletion.inspect_job_residue_count(
            quarantine_root=quarantine_root, job_id=job_id, profile_id=profile_id
        )
        == 0
    )


def test_f05_partial_local_inventory_fails_validation_without_reads(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-05: an inventory that only partially matches the directory fails closed."""

    from itda.photo.jobs import PhotoJobError

    job_id = secrets.token_hex(32)
    profile_id = "profile-f05-partial"
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
    written = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=2)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    gateway._stored[job_id] = {1: (written[0].name, "image/png")}  # noqa: SLF001
    provider_calls: list[str] = []

    def forbidden_provider(**_kwargs: object) -> None:
        provider_calls.append("provider")

    monkeypatch.setattr(gateway._provider, "analyze", forbidden_provider)  # noqa: SLF001
    monkeypatch.setattr(gateway, "_sanitized_bytes", forbidden_provider)  # noqa: SLF001
    with pytest.raises(PhotoJobError):
        gateway.submit_job(job_id=job_id, profile_id=profile_id)
    assert provider_calls == []
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        causes = [str(row[2]) for row in _ledger_rows(connection, job_id, profile_id)]
    assert state == ("failed",)
    assert causes.count("validation_failure") == 1


def test_f05_same_gateway_complete_inventory_still_succeeds(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """F-05: the normal same-gateway flow keeps its success behavior."""

    import asyncio
    from collections.abc import AsyncIterator

    job_id = secrets.token_hex(32)
    profile_id = "profile-f05-same-gateway"
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)", (job_id, profile_id)
        )
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    payload = _f05_png_bytes()

    async def run_store() -> tuple[str, int]:
        async def body() -> AsyncIterator[bytes]:
            yield payload

        return await gateway.store_image_stream(
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )

    asyncio.run(run_store())
    result = gateway.submit_job(job_id=job_id, profile_id=profile_id)
    assert result == {"state": "succeeded"}
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
    assert state == ("succeeded",)
    assert not (quarantine_root / job_id).exists()


def test_f05_read_job_state_cleanup_pending_is_durable(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """F-05: cleanup_pending derives from durable proof, not a constant."""

    service_dsn = _service_dsn(postgres_harness)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    completed_id = secrets.token_hex(32)
    completed_profile = "profile-f05-durable-complete"
    _seed_quarantine_objects(quarantine_root, completed_id, completed_profile, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection, job_id=completed_id, profile_id=completed_profile, state="running"
        )
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=completed_id,
            profile_id=completed_profile,
            cause="success",
            reason_code="PHOTO_SUCCESS",
            from_status="running",
            to_status="succeeded",
        )
        pending = gateway.read_job_state(job_id=completed_id, profile_id=completed_profile)
        assert pending["cleanup_pending"] is True
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=completed_id,
            profile_id=completed_profile,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )
    completed = gateway.read_job_state(job_id=completed_id, profile_id=completed_profile)
    assert completed["state"] == "succeeded"
    assert completed["cleanup_pending"] is False

    fabricated_id = secrets.token_hex(32)
    fabricated_profile = "profile-f13-succeeded-without-pointer"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection, job_id=fabricated_id, profile_id=fabricated_profile, state="running"
        )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET status='succeeded', "
            "terminal_cause='success', lease_expires_at=NULL WHERE job_id=%s",
            (fabricated_id,),
        )
    fabricated = gateway.read_job_state(job_id=fabricated_id, profile_id=fabricated_profile)
    assert fabricated["cleanup_pending"] is True

    wrong_pointer_id = secrets.token_hex(32)
    wrong_pointer_profile = "profile-f13-succeeded-wrong-pointer"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection,
            job_id=wrong_pointer_id,
            profile_id=wrong_pointer_profile,
            state="running",
        )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET status='succeeded', terminal_cause='success', "
            "terminal_operation_key=%s, terminal_proof_digest=%s, lease_expires_at=NULL "
            "WHERE job_id=%s",
            ("a" * 64, "b" * 64, wrong_pointer_id),
        )
    wrong_pointer = gateway.read_job_state(
        job_id=wrong_pointer_id, profile_id=wrong_pointer_profile
    )
    assert wrong_pointer["cleanup_pending"] is True

    legacy_id = secrets.token_hex(32)
    legacy_profile = "profile-f05-durable-legacy"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection, job_id=legacy_id, profile_id=legacy_profile, state="running"
        )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET status='failed', "
            "terminal_cause='provider_error', lease_expires_at=NULL "
            "WHERE job_id=%s",
            (legacy_id,),
        )
        admin.execute(
            "INSERT INTO dev_eval.photo_deletion_ledger "
            "(job_id, cause, reason_code, residue_proof_digest) "
            "VALUES (%s, 'provider_error', 'PHOTO_HISTORICAL', %s)",
            (legacy_id, "e" * 64),
        )
    legacy = gateway.read_job_state(job_id=legacy_id, profile_id=legacy_profile)
    assert legacy["state"] == "failed"
    assert legacy["cleanup_pending"] is True, (
        "F-05: a terminal job without exact v3 proof must project cleanup pending"
    )

    restart_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    restarted = restart_gateway.read_job_state(job_id=legacy_id, profile_id=legacy_profile)
    assert restarted["cleanup_pending"] is True

    queued_id = secrets.token_hex(32)
    queued_profile = "profile-f05-durable-queued"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(
            connection, job_id=queued_id, profile_id=queued_profile, state="queued"
        )
    queued = gateway.read_job_state(job_id=queued_id, profile_id=queued_profile)
    assert queued["state"] == "queued"
    assert queued["cleanup_pending"] is False


def test_f04_downgrade_refuses_evidence_and_clean_downgrade_is_safe(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """F-04: 0021 downgrade refuses evidence and drops the pointer safely."""

    config = _migration_config(postgres_harness)
    command.upgrade(config, "head")
    job_id = secrets.token_hex(32)
    profile_id = "profile-f04-downgrade-guard"
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)", (job_id, profile_id)
        )
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
            (job_id, profile_id),
        )
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0020_phase6_exclusive_photo_mutation_authority")
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        connection.execute("TRUNCATE dev_eval.photo_deletion_ledger")
        connection.execute("TRUNCATE dev_eval.photo_jobs CASCADE")
    command.downgrade(config, "0020_phase6_exclusive_photo_mutation_authority")
    pointer_columns = _f03_admin_query(
        postgres_harness,
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_schema='dev_eval' AND table_name='photo_jobs' "
        "AND column_name IN ('terminal_operation_key','terminal_proof_digest')",
        (),
    )
    assert pointer_columns == (0,)
    command.upgrade(config, "head")


# ---------------------------------------------------------------------------
# Rev7 findings F-06..F-10: descriptor authority, exact-64 SQL boundary,
# create serialization, durable cleanup projection, and transactional removal.
# ---------------------------------------------------------------------------


def _rev9_job_counts(postgres_harness: object, job_id: str) -> tuple[int, ...]:
    with postgres_harness.connect("admin", autocommit=True) as connection:  # type: ignore[attr-defined]
        return tuple(
            int(value)
            for value in connection.execute(
                "SELECT "
                "(SELECT count(*) FROM dev_eval.photo_jobs WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_job_filesystem_bindings WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_job_dispatch_markers WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_trait_candidates WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_review_drafts WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_confirmed_traits WHERE job_id=%s), "
                "(SELECT count(*) FROM dev_eval.photo_job_image_slots WHERE job_id=%s)",
                (job_id,) * 8,
            ).fetchone()
        )


def _rev9_assert_23514(
    connection: psycopg.Connection[tuple[object, ...]],
    statement: str,
    params: tuple[object, ...],
) -> None:
    with pytest.raises(psycopg.Error) as captured:
        connection.execute(statement, params).fetchone()
    assert captured.value.sqlstate == "23514"


def test_rev9_generated_unlink_substitution_fails_before_terminal_truth(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-unlink-substitution"
    original = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)[0]
    replacement = quarantine_root / "replacement"
    replacement.write_bytes(b"replacement")
    replacement.chmod(0o600)
    swapped = False

    def substitute(boundary: str) -> None:
        nonlocal swapped
        if boundary != "before_generated_unlink" or swapped:
            return
        swapped = True
        original.rename(original.with_suffix(".held"))
        replacement.rename(original)

    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        with pytest.raises(photo_deletion.DeletionIncomplete):
            photo_deletion.remove_all_objects(
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                boundary_hook=substitute,
            )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT status,terminal_operation_key,terminal_proof_digest "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("running", None, None)
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s",
            (job_id,),
        ).fetchone() == (0,)
    assert swapped
    assert original.with_suffix(".held").exists()


@pytest.mark.parametrize("adversary", ("wrong_mode", "visible_substitution", "wrong_owner"))
def test_rev9_f06_directory_authority_rejects_before_db_mutation(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
    adversary: str,
) -> None:
    """Directory mode, visible identity, and owner drift cannot mint deletion truth."""

    from types import SimpleNamespace

    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev9-f06-{adversary}"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")

    job_dir = quarantine_root / job_id
    if adversary == "wrong_mode":
        job_dir.chmod(0o750)
    elif adversary == "visible_substitution":
        original_stat = photo_deletion.os.stat

        def substituted_stat(path: object, *args: object, **kwargs: object) -> object:
            visible = original_stat(path, *args, **kwargs)
            if path == job_id and kwargs.get("dir_fd") is not None:
                values = {
                    name: getattr(visible, name) for name in dir(visible) if name.startswith("st_")
                }
                values["st_ino"] = visible.st_ino + 1
                return SimpleNamespace(**values)
            return visible

        monkeypatch.setattr(photo_deletion.os, "stat", substituted_stat)
    else:
        original_fstat = photo_deletion.os.fstat
        target_inode = job_dir.stat().st_ino

        def foreign_fstat(fd: int) -> object:
            opened = original_fstat(fd)
            if stat.S_ISDIR(opened.st_mode) and opened.st_ino == target_inode:
                values = {
                    name: getattr(opened, name) for name in dir(opened) if name.startswith("st_")
                }
                values["st_uid"] = opened.st_uid + 1
                return SimpleNamespace(**values)
            return opened

        monkeypatch.setattr(photo_deletion.os, "fstat", foreign_fstat)

    with (
        psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection,
        pytest.raises(photo_deletion.DeletionIncomplete),
    ):
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT status, terminal_operation_key, terminal_proof_digest "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone() == ("running", None, None)
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s", (job_id,)
        ).fetchone() == (0,)


REV9_JOB_SPECIFIC_V3_CALLS: tuple[tuple[str, tuple[object, ...]], ...] = (
    ("SELECT dev_eval.create_photo_job_v3(%s,%s,%s)", ("profile", None)),
    ("SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)", ("profile",)),
    ("SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)", ("profile",)),
    ("SELECT * FROM dev_eval.lock_photo_job_operation_v3(%s,%s,%s)", ("profile", "terminal")),
    (
        "SELECT dev_eval.transition_photo_job_nonterminal_v3"
        "(%s,%s,%s,%s,now()+interval '5 minutes')",
        ("profile", "queued", "running"),
    ),
    ("SELECT dev_eval.record_photo_dispatch_marker_v3(%s,%s,%s,%s)", ("profile", 1, "a" * 64)),
    (
        "SELECT dev_eval.record_photo_candidate_batch_v3(%s,%s,%s,%s,%s,%s)",
        ("profile", [], [], [], []),
    ),
    (
        "SELECT dev_eval.annotate_photo_candidate_v3(%s,%s,%s,%s,%s)",
        ("profile", "candidate", "text", False),
    ),
    (
        "SELECT dev_eval.save_photo_review_draft_v3(%s,%s,%s,%s,%s,%s,%s)",
        ("profile", "d" * 64, [], [], [], []),
    ),
    ("SELECT dev_eval.discard_photo_review_draft_v3(%s,%s)", ("profile",)),
    (
        "SELECT dev_eval.confirm_photo_traits_v3(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        ("profile", "d" * 64, [], [], [], [], [], "receipt"),
    ),
    (
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
        ("profile", "provider_error", "PHOTO_PROVIDER_ERROR", "a" * 64, 0, "b" * 64),
    ),
    (
        "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
        (
            "profile",
            "running",
            "failed",
            "provider_error",
            "PHOTO_PROVIDER_ERROR",
            "a" * 64,
            "b" * 64,
        ),
    ),
    (
        "SELECT dev_eval.finalize_photo_job_unbound_explicit_deletion_v3(%s,%s)",
        ("profile",),
    ),
    ("SELECT * FROM dev_eval.list_photo_deletion_ledger_v3(%s,%s)", ("profile",)),
    ("SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)", ("profile",)),
    ("SELECT * FROM dev_eval.read_photo_filesystem_release_v3(%s,%s)", ("profile",)),
    (
        "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s,%s,%s,%s)",
        ("profile", "a" * 64, "b" * 64),
    ),
    (
        "SELECT dev_eval.pending_photo_filesystem_release_v3(%s,%s,%s,%s)",
        ("profile", "a" * 64, "b" * 64),
    ),
    (
        "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s,%s,%s,%s,%s)",
        ("profile", 1, "a" * 32, "image/png"),
    ),
    (
        "SELECT dev_eval.commit_photo_image_slot_v3(%s,%s,%s,%s,%s)",
        ("profile", 1, "a" * 32, 1),
    ),
    ("SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)", ("profile",)),
)


@pytest.mark.parametrize(("statement", "suffix"), REV9_JOB_SPECIFIC_V3_CALLS)
@pytest.mark.parametrize("invalid_kind", ("null", "historical-32"))
def test_rev9_f07_invalid_job_id_is_rejected_by_every_job_v3_call(
    postgres_harness: object,
    phase6_deletion_schema: None,
    statement: str,
    suffix: tuple[object, ...],
    invalid_kind: str,
) -> None:
    """Every direct service v3 call rejects NULL and historical-32 identities."""

    invalid_job_id = None if invalid_kind == "null" else secrets.token_hex(16)
    observed_job_id = invalid_job_id or secrets.token_hex(32)
    if invalid_job_id is not None:
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute(
                "INSERT INTO dev_eval.photo_jobs(job_id,profile_id,status) "
                "VALUES (%s,'profile','queued')",
                (invalid_job_id,),
            )
    before = _rev9_job_counts(postgres_harness, observed_job_id)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _rev9_assert_23514(connection, statement, (invalid_job_id, *suffix))
    assert _rev9_job_counts(postgres_harness, observed_job_id) == before


@pytest.mark.parametrize(("statement", "suffix"), REV9_JOB_SPECIFIC_V3_CALLS)
def test_rev9_f07_null_profile_is_rejected_by_every_job_v3_call(
    postgres_harness: object,
    phase6_deletion_schema: None,
    statement: str,
    suffix: tuple[object, ...],
) -> None:
    job_id = secrets.token_hex(32)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "INSERT INTO dev_eval.photo_jobs(job_id,profile_id,status) "
            "VALUES (%s,'profile','queued')",
            (job_id,),
        )
    before = _rev9_job_counts(postgres_harness, job_id)
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _rev9_assert_23514(connection, statement, (job_id, None, *suffix[1:]))
    assert _rev9_job_counts(postgres_harness, job_id) == before


def test_rev9_destructive_slot_release_function_is_absent(
    postgres_harness: object,
    phase6_deletion_schema: None,
) -> None:
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT to_regprocedure('dev_eval.release_photo_image_slot_v3"
            "(text,text,integer,boolean)')"
        ).fetchone() == (None,)


def test_rev9_startup_rejects_owner_only_execute_drift(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    service_role = "itda_photo_service"
    forbidden = (
        "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz)",
        "dev_eval.create_photo_job_v2(text,text,text)",
    )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        for identity in forbidden:
            admin.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {service_role}")
    with pytest.raises(RuntimeError, match="owner-only EXECUTE leaked"):
        gateway.verify_service_authority()  # type: ignore[attr-defined]
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        for identity in forbidden:
            admin.execute(f"REVOKE EXECUTE ON FUNCTION {identity} FROM {service_role}")
    gateway.verify_service_authority()  # type: ignore[attr-defined]


def test_rev9_startup_rejects_non_photo_namespace_execute_drift(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    from itda.api.routes.photo import verify_photo_service_execute_surface
    from itda.cli import e2e_runtime

    service_dsn = _service_dsn(postgres_harness)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    helper = "dev_eval.unexpected_helper()"
    service_role = "itda_photo_service"
    try:
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute(
                "CREATE FUNCTION dev_eval.unexpected_helper() RETURNS integer "
                "LANGUAGE sql AS 'SELECT 1'"
            )
            admin.execute(f"REVOKE ALL ON FUNCTION {helper} FROM PUBLIC")
            admin.execute(f"GRANT EXECUTE ON FUNCTION {helper} TO {service_role}")
        allowed = tuple(
            f"dev_eval.{signature}"
            for signature in gateway._REQUIRED_FUNCTIONS  # type: ignore[attr-defined]  # noqa: SLF001
        )
        for validator in (
            verify_photo_service_execute_surface,
            e2e_runtime.verify_photo_service_execute_surface,
        ):
            with (
                psycopg.connect(service_dsn, autocommit=True) as connection,
                pytest.raises(RuntimeError, match="unexpected EXECUTE grant"),
            ):
                validator(
                    connection,
                    allowed_procedures=allowed,
                    owner_only_procedures=(),
                )
        with pytest.raises(RuntimeError, match="unexpected EXECUTE grant"):
            gateway.verify_service_authority()  # type: ignore[attr-defined]
    finally:
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute(f"REVOKE EXECUTE ON FUNCTION {helper} FROM {service_role}")
            admin.execute(f"DROP FUNCTION IF EXISTS {helper}")
    gateway.verify_service_authority()  # type: ignore[attr-defined]


def test_rev9_f07_cleanup_projection_is_explicitly_64_only(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    job_id = secrets.token_hex(16)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "INSERT INTO dev_eval.photo_jobs(job_id,profile_id,status,lease_expires_at) "
            "VALUES (%s,'profile','running',now()-interval '1 minute')",
            (job_id,),
        )
        source = admin.execute(
            "SELECT p.prosrc FROM pg_catalog.pg_proc p "
            "WHERE p.oid='dev_eval.list_photo_cleanup_candidates_v3()'::regprocedure"
        ).fetchone()
    assert source is not None and "^[0-9a-f]{64}$" in str(source[0])
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        assert (
            connection.execute(
                "SELECT job_id FROM dev_eval.list_photo_cleanup_candidates_v3() WHERE job_id=%s",
                (job_id,),
            ).fetchall()
            == []
        )


def test_rev9_f08_create_row_lock_blocks_then_replays_and_rejects_mismatch(
    postgres_harness: object, phase6_deletion_schema: None
) -> None:
    import threading

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-f08"
    key = "idempotency-key-rev9-f08"
    service_dsn = _service_dsn(postgres_harness)
    source = _f03_admin_query(
        postgres_harness,
        "SELECT p.prosrc FROM pg_catalog.pg_proc p "
        "WHERE p.oid='dev_eval.create_photo_job_v3(text,text,text)'::regprocedure",
        (),
    )
    assert source is not None and "FOR UPDATE" in str(source[0])

    holder = psycopg.connect(service_dsn)
    outcomes: list[tuple[object, ...]] = []
    errors: list[Exception] = []
    try:
        assert holder.execute(
            "SELECT dev_eval.create_photo_job_v3(%s,%s,%s)", (job_id, profile_id, key)
        ).fetchone() == (True,)

        def replay() -> None:
            try:
                with psycopg.connect(service_dsn, autocommit=True) as connection:
                    outcomes.append(
                        connection.execute(
                            "SELECT dev_eval.create_photo_job_v3(%s,%s,%s)",
                            (job_id, profile_id, key),
                        ).fetchone()
                    )
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        thread = threading.Thread(target=replay)
        thread.start()
        thread.join(timeout=0.8)
        assert thread.is_alive(), "the replay must block behind the creator transaction"
        holder.commit()
        thread.join(timeout=10)
        assert not thread.is_alive() and errors == [] and outcomes == [(False,)]
    finally:
        holder.close()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _rev9_assert_23514(
            connection,
            "SELECT dev_eval.create_photo_job_v3(%s,%s,%s)",
            (job_id, profile_id, "different-key-rev9-f08"),
        )
    assert _rev9_job_counts(postgres_harness, job_id)[0] == 1


def test_rev9_f09_cleanup_projection_is_service_only_and_exact(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-f09"
    service_dsn = _service_dsn(postgres_harness)
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)", (job_id, profile_id)
        ).fetchone() == (True,)
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)", (job_id, profile_id)
        ).fetchone() == (False,)
    identity = "dev_eval.read_photo_cleanup_status_v3(text,text)"
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        assert admin.execute(
            "SELECT has_function_privilege('itda_photo_service',%s,'EXECUTE'), "
            "has_function_privilege('public',%s,'EXECUTE'), "
            "has_function_privilege(%s,%s,'EXECUTE'), "
            "has_function_privilege(%s,%s,'EXECUTE')",
            (
                identity,
                identity,
                postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
                identity,
                postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
                identity,
            ),
        ).fetchone() == (True, False, False, False)
        assert admin.execute(
            "SELECT count(*) FROM dev_eval.photo_job_filesystem_bindings WHERE job_id=%s",
            (job_id,),
        ).fetchone() == (0,)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert gateway.read_job_state(job_id=job_id, profile_id=profile_id)["cleanup_pending"] is False
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "INSERT INTO dev_eval.photo_job_filesystem_bindings(job_id,profile_id) VALUES (%s,%s)",
            (job_id, profile_id),
        )
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET terminal_proof_digest=%s WHERE job_id=%s",
            ("c" * 64, job_id),
        )
    restart_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert (
        restart_gateway.read_job_state(job_id=job_id, profile_id=profile_id)["cleanup_pending"]
        is True
    )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET terminal_proof_digest=%s WHERE job_id=%s",
            (outcome.proof_digest, job_id),
        )
        admin.execute(
            "UPDATE dev_eval.photo_deletion_ledger SET reason_code='PHOTO_DUPLICATE_PROOF'"
            " WHERE job_id=%s AND cause='provider_error'",
            (job_id,),
        )
    assert (
        restart_gateway.read_job_state(job_id=job_id, profile_id=profile_id)["cleanup_pending"]
        is True
    )


def test_rev9_f10_terminal_commit_preserves_binding_then_startup_releases(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-f10"
    service_dsn = _service_dsn(postgres_harness)
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        with pytest.raises(photo_deletion.DeletionIncomplete):
            photo_deletion.execute_terminal_deletion_with_failure_injection(
                connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                cause="provider_error",
                reason_code="PHOTO_PROVIDER_ERROR",
                injection_point="after_terminal_commit",
                from_status="running",
                to_status="failed",
            )
        assert (quarantine_root / job_id / ".itda-owner-v1").exists()
        assert _fs_residue(quarantine_root, job_id) == [".itda-owner-v1"]
        assert connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == ("failed",)
        assert len(_ledger_rows(connection, job_id, profile_id)) == 1
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
        assert report.examined >= 1
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (False,)
    assert not (quarantine_root / job_id).exists()


def test_rev9_terminal_finalizer_and_filesystem_release_are_separate_phases() -> None:
    """Rev9: irreversible release cannot run inside the terminal transaction."""

    source = Path(photo_deletion.__file__).read_text()
    terminal = source[
        source.index("def execute_terminal_deletion(") : source.index(
            "def release_filesystem_cleanup("
        )
    ]
    release = source[
        source.index("def release_filesystem_cleanup(") : source.index(
            "def execute_terminal_deletion_with_failure_injection("
        )
    ]
    assert "finalize_photo_job_terminal_v3" in terminal
    assert "_remove_bound_directory(" not in terminal
    assert "pending_photo_filesystem_release_v3" in release
    assert "_remove_bound_directory(" in release
    assert "complete_photo_filesystem_cleanup_v3" in release


def test_rev9_canonical_residue_digest_is_enforced_at_each_db_boundary(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-canonical-digest"
    service_dsn = _service_dsn(postgres_harness)
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        operation_key = photo_deletion._operation_key(  # noqa: SLF001
            job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
        )
        canonical_digest = photo_deletion._proof_digest(operation_key, 0)  # noqa: SLF001
        wrong_digest = "0" * 64 if canonical_digest != "0" * 64 else "1" * 64
        before = _rev9_job_counts(postgres_harness, job_id)
        _rev9_assert_23514(
            connection,
            "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
            (
                job_id,
                profile_id,
                "provider_error",
                "PHOTO_PROVIDER_ERROR",
                operation_key,
                0,
                wrong_digest,
            ),
        )
        assert _rev9_job_counts(postgres_harness, job_id) == before
        assert connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
            (
                job_id,
                profile_id,
                "provider_error",
                "PHOTO_PROVIDER_ERROR",
                operation_key,
                0,
                canonical_digest,
            ),
        ).fetchone() == (True,)
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            job_before = admin.execute(
                "SELECT status,terminal_operation_key,terminal_proof_digest,"
                "filesystem_cleanup_pending FROM dev_eval.photo_jobs WHERE job_id=%s",
                (job_id,),
            ).fetchone()
        _rev9_assert_23514(
            connection,
            "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                job_id,
                profile_id,
                "running",
                "failed",
                "provider_error",
                "PHOTO_PROVIDER_ERROR",
                operation_key,
                wrong_digest,
            ),
        )
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            assert (
                admin.execute(
                    "SELECT status,terminal_operation_key,terminal_proof_digest,"
                    "filesystem_cleanup_pending FROM dev_eval.photo_jobs WHERE job_id=%s",
                    (job_id,),
                ).fetchone()
                == job_before
            )
        assert connection.execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                job_id,
                profile_id,
                "running",
                "failed",
                "provider_error",
                "PHOTO_PROVIDER_ERROR",
                operation_key,
                canonical_digest,
            ),
        ).fetchone() == ("running",)
        _rev9_assert_23514(
            connection,
            "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s,%s,%s,%s)",
            (job_id, profile_id, operation_key, wrong_digest),
        )
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)


REV9_NULL_PROOF_FIELD_CALLS: tuple[tuple[str, tuple[object, ...]], ...] = (
    (
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
        (None, "PHOTO_PROVIDER_ERROR", "$operation", 0, "$digest"),
    ),
    (
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
        ("provider_error", None, "$operation", 0, "$digest"),
    ),
    (
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
        ("provider_error", "PHOTO_PROVIDER_ERROR", None, 0, "$digest"),
    ),
    (
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,%s,%s)",
        ("provider_error", "PHOTO_PROVIDER_ERROR", "$operation", 0, None),
    ),
    (
        "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
        ("running", "failed", None, "PHOTO_PROVIDER_ERROR", "$operation", "$digest"),
    ),
    (
        "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
        ("running", "failed", "provider_error", None, "$operation", "$digest"),
    ),
    (
        "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
        ("running", "failed", "provider_error", "PHOTO_PROVIDER_ERROR", None, "$digest"),
    ),
    (
        "SELECT dev_eval.finalize_photo_job_terminal_v3(%s,%s,%s,%s,%s,%s,%s,%s)",
        ("running", "failed", "provider_error", "PHOTO_PROVIDER_ERROR", "$operation", None),
    ),
    (
        "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s,%s,%s,%s)",
        (None, "$digest"),
    ),
    (
        "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s,%s,%s,%s)",
        ("$operation", None),
    ),
    (
        "SELECT dev_eval.pending_photo_filesystem_release_v3(%s,%s,%s,%s)",
        (None, "$digest"),
    ),
    (
        "SELECT dev_eval.pending_photo_filesystem_release_v3(%s,%s,%s,%s)",
        ("$operation", None),
    ),
)


@pytest.mark.parametrize(("statement", "suffix"), REV9_NULL_PROOF_FIELD_CALLS)
def test_rev9_null_terminal_proof_fields_reject_without_mutation(
    postgres_harness: object,
    phase6_deletion_schema: None,
    statement: str,
    suffix: tuple[object, ...],
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-null-proof"
    operation_key = photo_deletion._operation_key(  # noqa: SLF001
        job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
    )
    proof_digest = photo_deletion._proof_digest(operation_key, 0)  # noqa: SLF001
    arguments = tuple(
        operation_key if value == "$operation" else proof_digest if value == "$digest" else value
        for value in suffix
    )
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
        connection.execute(
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s,%s,'queued','running',now()+interval '5 minutes')",
            (job_id, profile_id),
        )
        before = _rev9_job_counts(postgres_harness, job_id)
        _rev9_assert_23514(connection, statement, (job_id, profile_id, *arguments))
    assert _rev9_job_counts(postgres_harness, job_id) == before


def test_rev9_null_lease_cleanup_requires_stale_committed_binding(
    postgres_harness: object,
    phase6_deletion_schema: None,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    stale_id = secrets.token_hex(32)
    fresh_id = secrets.token_hex(32)
    unbound_id = secrets.token_hex(32)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for job_id, profile_id in (
            (stale_id, "profile-rev9-stale-binding"),
            (fresh_id, "profile-rev9-fresh-binding"),
        ):
            connection.execute(
                "SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id)
            )
            connection.execute(
                "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)",
                (job_id, profile_id),
            )
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)",
            (unbound_id, "profile-rev9-unbound"),
        )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_job_filesystem_bindings "
            "SET claimed_at=now()-interval '6 minutes' WHERE job_id=%s",
            (stale_id,),
        )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        projected = {
            str(row[0]): str(row[3])
            for row in connection.execute(
                "SELECT * FROM dev_eval.list_photo_cleanup_candidates_v3()"
            ).fetchall()
            if str(row[0]) in {stale_id, fresh_id, unbound_id}
        }
        assert projected == {stale_id: "expiry"}
        assert connection.execute(
            "SELECT status FROM dev_eval.lock_photo_job_operation_v3(%s,%s,'reconcile')",
            (stale_id, "profile-rev9-stale-binding"),
        ).fetchone() == ("queued",)
        _rev9_assert_23514(
            connection,
            "SELECT status FROM dev_eval.lock_photo_job_operation_v3(%s,%s,'reconcile')",
            (fresh_id, "profile-rev9-fresh-binding"),
        )


def test_rev9_durable_slot_restart_replays_without_consuming_body_and_caps_three(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-slot-restart"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))

    async def upload(gateway: object, image_index: int, consumed: list[int]) -> tuple[str, int]:
        async def body() -> AsyncIterator[bytes]:
            consumed.append(image_index)
            yield payload

        return await gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=image_index,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )

    first_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    first_consumed: list[int] = []
    first = asyncio.run(upload(first_gateway, 1, first_consumed))
    restart_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    replay_consumed: list[int] = []
    replay = asyncio.run(upload(restart_gateway, 1, replay_consumed))
    assert replay == first
    assert first_consumed == [1]
    assert replay_consumed == []
    for image_index in (2, 3):
        assert asyncio.run(upload(restart_gateway, image_index, []))[1] == len(payload)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        rows = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchall()
        assert [(int(row[0]), str(row[1]), int(row[3])) for row in rows] == [
            (1, "stored", len(payload)),
            (2, "stored", len(payload)),
            (3, "stored", len(payload)),
        ]
        assert connection.execute(
            "SELECT dev_eval.commit_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, first[0], first[1]),
        ).fetchone() == (False,)
        _rev9_assert_23514(
            connection,
            "SELECT dev_eval.commit_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, first[0], first[1] + 1),
        )
        _rev9_assert_23514(
            connection,
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s,%s,4,%s,%s)",
            (job_id, profile_id, secrets.token_hex(16), "image/png"),
        )
    generated = [
        name for name in _fs_residue(quarantine_root, job_id) if re.fullmatch(r"[0-9a-f]{32}", name)
    ]
    assert len(generated) == 3


def test_rev9_reserved_partial_retry_reuses_exact_durable_slot_name(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-reserved-retry"
    service_dsn = _service_dsn(postgres_harness)
    partial = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)[0]
    payload = _f05_png_bytes()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        )
        assert connection.execute(
            "SELECT state,stored_name,newly_reserved FROM "
            "dev_eval.reserve_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, partial.name, "image/png"),
        ).fetchone() == ("reserved", partial.name, True)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    consumed = 0

    async def body() -> AsyncIterator[bytes]:
        nonlocal consumed
        consumed += 1
        yield payload

    receipt = asyncio.run(
        gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    assert receipt == (partial.name, len(payload))
    assert consumed == 1
    assert [name for name in _fs_residue(quarantine_root, job_id) if name != ".itda-owner-v1"] == [
        partial.name
    ]
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT state,stored_name,byte_length,media_type "
            "FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == ("stored", partial.name, len(payload), "image/png")


def test_rev9_new_slot_failure_retains_reserved_binding_authority(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-new-slot-failure"
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    async def failing_body() -> AsyncIterator[bytes]:
        yield b"partial"
        raise RuntimeError("synthetic iterator failure")

    with pytest.raises(RuntimeError, match="synthetic iterator failure"):
        asyncio.run(
            gateway.store_image_stream(  # type: ignore[attr-defined]
                job_id=job_id,
                job_directory=job_id,
                profile_id=profile_id,
                image_index=1,
                chunks=failing_body(),
                declared_byte_length=32,
                media_type="image/png",
            )
        )
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slot = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()
        assert slot is not None and slot[1] == "reserved"
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)


def test_rev9_pre_stream_reserved_rejection_closes_all_descriptors(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-fd-scope"
    service_dsn = _service_dsn(postgres_harness)
    partial = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)[0]
    partial.chmod(0o644)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, partial.name, "image/png"),
        )
    consumed = 0

    async def body() -> AsyncIterator[bytes]:
        nonlocal consumed
        consumed += 1
        yield b"must-not-be-read"

    baseline = len(os.listdir("/dev/fd"))
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    for _ in range(3):
        with pytest.raises(photo_quarantine.QuarantineError):
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=body(),
                    declared_byte_length=16,
                    media_type="image/png",
                )
            )
        assert len(os.listdir("/dev/fd")) == baseline
    assert consumed == 0
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slots = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchall()
        assert len(slots) == 1 and slots[0][1] == "reserved"


@pytest.mark.parametrize(
    "failure_mode",
    ("initial-job-fstat", "final-job-fstat", "final-visible-stat", "final-identity-mismatch"),
)
def test_rev9_new_directory_metadata_failure_rolls_back_and_retries_exact_slot(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    failure_mode: str,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator
    from types import SimpleNamespace

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev9-metadata-{failure_mode}"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    root_state = os.stat(quarantine_root)
    original_fstat = photo_quarantine.os.fstat
    original_stat = photo_quarantine.os.stat
    job_fstat_calls = 0
    job_stat_calls = 0

    def injected_fstat(descriptor: int) -> os.stat_result:
        nonlocal job_fstat_calls
        observed = original_fstat(descriptor)
        if stat.S_ISDIR(observed.st_mode) and (observed.st_dev, observed.st_ino) != (
            root_state.st_dev,
            root_state.st_ino,
        ):
            job_fstat_calls += 1
            if failure_mode == "initial-job-fstat" and job_fstat_calls == 1:
                raise OSError("synthetic initial job fstat failure")
            if failure_mode == "final-job-fstat" and job_fstat_calls == 3:
                raise OSError("synthetic final job fstat failure")
        return observed

    def injected_stat(path: object, *args: object, **kwargs: object) -> object:
        nonlocal job_stat_calls
        observed = original_stat(path, *args, **kwargs)
        if path == job_id and kwargs.get("dir_fd") is not None:
            job_stat_calls += 1
            if job_stat_calls == 2:
                if failure_mode == "final-visible-stat":
                    raise OSError("synthetic final visible stat failure")
                if failure_mode == "final-identity-mismatch":
                    values = {
                        name: getattr(observed, name)
                        for name in dir(observed)
                        if name.startswith("st_")
                    }
                    values["st_ino"] = observed.st_ino + 1
                    return SimpleNamespace(**values)
        return observed

    stored_name = secrets.token_hex(16)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
        assert connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
        connection.execute(
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, stored_name, "image/png"),
        )

    async def body() -> AsyncIterator[bytes]:
        yield payload

    baseline = len(os.listdir("/dev/fd"))
    root_fd = photo_quarantine.open_quarantine_root(quarantine_root)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(photo_quarantine.os, "fstat", injected_fstat)
            patch.setattr(photo_quarantine.os, "stat", injected_stat)
            with pytest.raises(photo_quarantine.QuarantineError):
                asyncio.run(
                    photo_quarantine.stream_to_quarantine(
                        root_fd=root_fd,
                        job_directory=job_id,
                        profile_id=profile_id,
                        image_index=1,
                        chunks=body(),
                        policy=photo_quarantine.QuarantinePolicy(),
                        binding_claim_created=True,
                        declared_byte_length=len(payload),
                        expected_stored_name=stored_name,
                    )
                )
    finally:
        os.close(root_fd)
    assert len(os.listdir("/dev/fd")) == baseline
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slot = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()
        assert slot is not None and slot[1] == "reserved"
        stored_name = str(slot[2])
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)

    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    ) == (stored_name, len(payload))
    assert (quarantine_root / job_id / stored_name).read_bytes() == payload


def test_rev9_uuid_failure_after_job_open_closes_and_preserves_durable_retry(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-uuid-failure"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    stored_name = secrets.token_hex(16)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
        assert connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
        connection.execute(
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, stored_name, "image/png"),
        )

    async def body() -> AsyncIterator[bytes]:
        yield payload

    baseline = len(os.listdir("/dev/fd"))
    root_fd = photo_quarantine.open_quarantine_root(quarantine_root)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                photo_quarantine.uuid,
                "uuid4",
                lambda: (_ for _ in ()).throw(RuntimeError("synthetic uuid failure")),
            )
            with pytest.raises(RuntimeError, match="synthetic uuid failure"):
                asyncio.run(
                    photo_quarantine.stream_to_quarantine(
                        root_fd=root_fd,
                        job_directory=job_id,
                        profile_id=profile_id,
                        image_index=1,
                        chunks=body(),
                        policy=photo_quarantine.QuarantinePolicy(),
                        binding_claim_created=True,
                        declared_byte_length=len(payload),
                    )
                )
    finally:
        os.close(root_fd)
    assert len(os.listdir("/dev/fd")) == baseline
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()[1:3] == ("reserved", stored_name)
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)

    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    ) == (stored_name, len(payload))


@pytest.mark.parametrize("failure_mode", ("write-zero", "write-partial-zero", "binding-fsync"))
def test_rev9_binding_initialization_failure_rolls_back_and_retries_exact_slot(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    failure_mode: str,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev9-binding-{failure_mode}"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    original_write = photo_quarantine.os.write
    original_fsync = photo_quarantine.os.fsync
    write_calls = 0
    fsync_calls = 0

    def injected_write(descriptor: int, data: object) -> int:
        nonlocal write_calls
        write_calls += 1
        if failure_mode == "write-zero":
            return 0
        if failure_mode == "write-partial-zero":
            if write_calls == 1:
                return original_write(descriptor, memoryview(data)[:5])  # type: ignore[arg-type]
            return 0
        return original_write(descriptor, data)  # type: ignore[arg-type]

    def injected_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if failure_mode == "binding-fsync" and fsync_calls == 1:
            raise OSError("synthetic binding fsync failure")
        original_fsync(descriptor)

    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))

    async def body() -> AsyncIterator[bytes]:
        yield payload

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with monkeypatch.context() as patch:
        patch.setattr(photo_quarantine.os, "write", injected_write)
        patch.setattr(photo_quarantine.os, "fsync", injected_fsync)
        with pytest.raises(photo_quarantine.QuarantineError):
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=body(),
                    declared_byte_length=len(payload),
                    media_type="image/png",
                )
            )
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slot = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()
        assert slot is not None and slot[1] == "reserved"
        stored_name = str(slot[2])
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)

    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    ) == (stored_name, len(payload))
    assert (quarantine_root / job_id / stored_name).read_bytes() == payload


@pytest.mark.parametrize("failure_mode", ("write-zero", "write-partial-zero"))
def test_rev9_generated_write_stall_rolls_back_and_retries_exact_slot(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    failure_mode: str,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev9-image-{failure_mode}"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    original_upload_write = photo_quarantine._UPLOAD_WRITE  # noqa: SLF001
    write_calls = 0

    def injected_upload_write(descriptor: int, data: object) -> int:
        nonlocal write_calls
        write_calls += 1
        if failure_mode == "write-partial-zero" and write_calls == 1:
            return original_upload_write(descriptor, memoryview(data)[:5])  # type: ignore[arg-type]
        return 0

    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))

    async def body() -> AsyncIterator[bytes]:
        yield payload

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with monkeypatch.context() as patch:
        patch.setattr(photo_quarantine, "_UPLOAD_WRITE", injected_upload_write)
        with pytest.raises(photo_quarantine.QuarantineError):
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=body(),
                    declared_byte_length=len(payload),
                    media_type="image/png",
                )
            )
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slot = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()
        assert slot is not None and slot[1] == "reserved"
        stored_name = str(slot[2])
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)

    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    ) == (stored_name, len(payload))


def test_rev9_binding_rollback_failure_retains_one_reserved_authority(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-binding-rollback-failure"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    original_fsync = photo_quarantine.os.fsync
    fsync_calls = 0

    def injected_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError("synthetic rollback fsync failure")
        original_fsync(descriptor)

    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))

    async def body() -> AsyncIterator[bytes]:
        yield payload

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with monkeypatch.context() as patch:
        patch.setattr(photo_quarantine.os, "write", lambda *_args, **_kwargs: 0)
        patch.setattr(photo_quarantine.os, "fsync", injected_fsync)
        with pytest.raises(
            photo_quarantine.QuarantineError,
            match="quarantine binding rollback did not finish",
        ):
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=body(),
                    declared_byte_length=len(payload),
                    media_type="image/png",
                )
            )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slots = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchall()
        assert len(slots) == 1 and slots[0][1] == "reserved"
        stored_name = str(slots[0][2])
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
    assert _fs_residue(quarantine_root, job_id) == []

    # Rev11 adoption contract: the empty unbound 0700 canonical directory
    # left behind by the unfinished rollback is the durable reserved intent;
    # the exact materialize retry adopts it (binding recreated, same
    # reserved stored_name) instead of failing on the collision.
    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    receipt = asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    assert receipt == (stored_name, len(payload))
    assert (quarantine_root / job_id / stored_name).read_bytes() == payload
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slots = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchall()
        assert len(slots) == 1 and str(slots[0][2]) == stored_name


def test_rev9_unlink_failure_retains_authority_and_fresh_retry_converges(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.photo import quarantine as photo_quarantine

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-unlink-failure"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))

    async def failing_body() -> AsyncIterator[bytes]:
        yield b"partial"
        raise RuntimeError("synthetic iterator failure")

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with monkeypatch.context() as patch:
        patch.setattr(
            photo_quarantine,
            "_unlink_partial_strict",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("synthetic unlink failure")),
        )
        with pytest.raises(RuntimeError, match="synthetic iterator failure") as raised:
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=failing_body(),
                    declared_byte_length=32,
                    media_type="image/png",
                )
            )
    assert raised.value.__notes__ == ["quarantine partial cleanup did not finish"]
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        slot = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()
        assert slot is not None and slot[1] == "reserved"
        stored_name = str(slot[2])
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
    assert (quarantine_root / job_id / stored_name).read_bytes() == b"partial"

    consumed = 0

    async def retry_body() -> AsyncIterator[bytes]:
        nonlocal consumed
        consumed += 1
        yield payload

    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    receipt = asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=retry_body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    assert receipt == (stored_name, len(payload))
    assert consumed == 1
    assert (quarantine_root / job_id / stored_name).read_bytes() == payload


def test_rev9_post_stream_slot_commit_failure_retains_authority_and_replays(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.api.routes import photo as photo_route

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-slot-commit-failure"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    original_connect = psycopg.connect
    with original_connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))

    class CommitFailingConnection:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._connection = original_connect(*args, **kwargs)

        def execute(self, statement: object, params: object = None) -> object:
            if "commit_photo_image_slot_v3" in str(statement):
                raise psycopg.OperationalError("synthetic slot commit failure")
            return self._connection.execute(statement, params)

        def transaction(self) -> object:
            return self._connection.transaction()

        def close(self) -> None:
            self._connection.close()

    async def body() -> AsyncIterator[bytes]:
        yield payload

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with monkeypatch.context() as patch:
        patch.setattr(photo_route.psycopg, "connect", CommitFailingConnection)
        with pytest.raises(psycopg.OperationalError, match="synthetic slot commit failure"):
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=body(),
                    declared_byte_length=len(payload),
                    media_type="image/png",
                )
            )
    with original_connect(service_dsn, autocommit=True) as connection:
        slot = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone()
        assert slot is not None and slot[1] == "reserved"
        stored_name = str(slot[2])
        assert connection.execute(
            "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
    assert (quarantine_root / job_id / stored_name).read_bytes() == payload

    consumed = 0

    async def retry_body() -> AsyncIterator[bytes]:
        nonlocal consumed
        consumed += 1
        yield payload

    retry_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    receipt = asyncio.run(
        retry_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=retry_body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    assert receipt == (stored_name, len(payload))
    assert consumed == 1
    with original_connect(service_dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT state,stored_name,byte_length FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == ("stored", stored_name, len(payload))


def test_rev9_restart_uses_durable_jpeg_media_type_for_analysis(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-jpeg-restart"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_jpeg_bytes()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
    upload_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    async def body() -> AsyncIterator[bytes]:
        yield payload

    asyncio.run(
        upload_gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/jpeg",
        )
    )
    restart_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert restart_gateway.submit_job(  # type: ignore[attr-defined]
        job_id=job_id, profile_id=profile_id
    ) == {"state": "succeeded"}
    assert not (quarantine_root / job_id).exists()


def test_rev9_concurrent_duplicate_slot_creates_one_file_and_consumes_one_body(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    import threading
    from collections.abc import AsyncIterator

    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-slot-concurrent"
    service_dsn = _service_dsn(postgres_harness)
    payload = _f05_png_bytes()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
    barrier = threading.Barrier(3)
    consumed = [0, 0]
    results: list[tuple[str, int]] = []
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

        async def body() -> AsyncIterator[bytes]:
            consumed[index] += 1
            yield payload

        async def run() -> tuple[str, int]:
            return await gateway.store_image_stream(  # type: ignore[attr-defined]
                job_id=job_id,
                job_directory=job_id,
                profile_id=profile_id,
                image_index=1,
                chunks=body(),
                declared_byte_length=len(payload),
                media_type="image/png",
            )

        try:
            barrier.wait()
            results.append(asyncio.run(run()))
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == 2 and results[0] == results[1]
    assert sum(consumed) == 1
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        assert (
            len(
                connection.execute(
                    "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s,%s)",
                    (job_id, profile_id),
                ).fetchall()
            )
            == 1
        )
    generated = [
        name for name in _fs_residue(quarantine_root, job_id) if re.fullmatch(r"[0-9a-f]{32}", name)
    ]
    assert generated == [results[0][0]]


@pytest.mark.parametrize(
    ("profile_enabled", "photo_enabled", "expected"),
    (
        (False, False, []),
        (True, False, ["profile"]),
        (False, True, ["photo"]),
        (True, True, ["profile", "photo"]),
    ),
)
def test_rev9_lifespan_uses_dedicated_startup_environment_authorities(
    monkeypatch: pytest.MonkeyPatch,
    profile_enabled: bool,
    photo_enabled: bool,
    expected: list[str],
) -> None:
    from types import SimpleNamespace

    from itda.api import main as api_main

    calls: list[str] = []
    monkeypatch.delenv("ITDA_DATABASE_URL", raising=False)
    monkeypatch.delenv("ITDA_PHOTO_SERVICE_DATABASE_URL", raising=False)
    if profile_enabled:
        monkeypatch.setenv("ITDA_DATABASE_URL", "postgresql://profile-only")
    if photo_enabled:
        monkeypatch.setenv("ITDA_PHOTO_SERVICE_DATABASE_URL", "postgresql://photo-only")
    monkeypatch.setattr(
        api_main, "validate_profile_session_startup", lambda: calls.append("profile")
    )
    monkeypatch.setattr(
        api_main,
        "get_photo_lifecycle",
        lambda: SimpleNamespace(reconcile_on_startup=lambda: calls.append("photo")),
    )
    with TestClient(api_main.create_app()) as client:
        assert client.app is not None
    assert calls == expected


def test_rev9_process_exit_after_binding_unlink_lifespan_converges(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.api.main import create_app
    from itda.api.routes import photo as photo_route

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-half-release"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="worker_crash",
            reason_code="PHOTO_WORKER_CRASH",
            from_status="running",
            to_status="failed",
        )
    child = multiprocessing.get_context("fork").Process(
        target=_exit_after_binding_unlink,
        args=(service_dsn, str(quarantine_root), job_id, profile_id),
    )
    child.start()
    child.join(timeout=15)
    assert child.exitcode == 74
    assert (quarantine_root / job_id).is_dir()
    assert _fs_residue(quarantine_root, job_id) == []
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    monkeypatch.delenv("ITDA_DATABASE_URL", raising=False)
    monkeypatch.setenv("ITDA_PHOTO_SERVICE_DATABASE_URL", service_dsn)
    monkeypatch.setattr(photo_route, "get_photo_lifecycle", lambda: gateway)
    monkeypatch.setattr("itda.api.main.get_photo_lifecycle", lambda: gateway)
    with TestClient(create_app()) as client:
        assert client.app is not None
    assert not (quarantine_root / job_id).exists()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (False,)


def test_rev9_phase_b_directory_swap_never_completes_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-release-swap"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        swapped = False

        def substitute(injection_point: str | None, boundary: str) -> None:
            nonlocal swapped
            if injection_point != boundary or boundary != "before_directory_rmdir" or swapped:
                return
            swapped = True
            (quarantine_root / job_id).rename(quarantine_root / f"{job_id}.held")
            (quarantine_root / job_id).mkdir(mode=0o700)

        monkeypatch.setattr(photo_deletion, "_inject", substitute)
        with pytest.raises(photo_deletion.DeletionIncomplete):
            photo_deletion.release_filesystem_cleanup(
                connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                operation_key=str(outcome.operation_key),
                proof_digest=str(outcome.proof_digest),
                injection_point="before_directory_rmdir",
            )
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
    assert swapped
    assert (quarantine_root / f"{job_id}.held").is_dir()


def test_rev9_phase_b_external_directory_swap_never_completes_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    tmp_path: Path,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-release-external-swap"
    external = tmp_path / f"{job_id}.external"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        swapped = False

        def substitute(injection_point: str | None, boundary: str) -> None:
            nonlocal swapped
            if injection_point != boundary or boundary != "before_directory_rmdir" or swapped:
                return
            swapped = True
            (quarantine_root / job_id).rename(external)
            (quarantine_root / job_id).mkdir(mode=0o700)

        monkeypatch.setattr(photo_deletion, "_inject", substitute)
        try:
            with pytest.raises(photo_deletion.DeletionIncomplete):
                photo_deletion.release_filesystem_cleanup(
                    connection,
                    quarantine_root=quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    operation_key=str(outcome.operation_key),
                    proof_digest=str(outcome.proof_digest),
                    injection_point="before_directory_rmdir",
                )
            assert connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
                (job_id, profile_id),
            ).fetchone() == (True,)
            assert external.is_dir()
            assert not (quarantine_root / job_id).exists()
        finally:
            if external.exists():
                external.rmdir()
    assert swapped


def test_rev9_concurrent_phase_b_callers_converge_exactly_once(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import threading

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-concurrent-release"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
    barrier = threading.Barrier(3)
    results: list[bool] = []
    errors: list[BaseException] = []

    def release() -> None:
        try:
            with psycopg.connect(service_dsn, autocommit=True) as connection:
                barrier.wait()
                results.append(
                    photo_deletion.release_filesystem_cleanup(
                        connection,
                        quarantine_root=quarantine_root,
                        job_id=job_id,
                        profile_id=profile_id,
                        operation_key=str(outcome.operation_key),
                        proof_digest=str(outcome.proof_digest),
                    )
                )
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=release) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=15)
    assert errors == [] and sorted(results) == [False, True]
    assert not (quarantine_root / job_id).exists()


def test_rev9_reserved_db_intent_rematerializes_missing_directory(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-reserve-before-mkdir"
    stored_name = secrets.token_hex(16)
    payload = _f05_png_bytes()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
        connection.execute(
            "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s,%s)",
            (job_id, profile_id),
        )
        connection.execute(
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s,%s,1,%s,%s)",
            (job_id, profile_id, stored_name, "image/png"),
        )
    assert not (quarantine_root / job_id).exists()
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    async def body() -> AsyncIterator[bytes]:
        yield payload

    receipt = asyncio.run(
        gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    assert receipt == (stored_name, len(payload))
    assert [name for name in _fs_residue(quarantine_root, job_id) if name != ".itda-owner-v1"] == [
        stored_name
    ]


def test_rev9_deleted_retry_reads_and_releases_durable_pending(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-deleted-retry"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="explicit_deletion",
            reason_code="PHOTO_EXPLICIT_DELETION",
            from_status="running",
            to_status="deleted",
        )
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert gateway.delete_job(job_id=job_id, profile_id=profile_id) == {
        "state": "deleted",
        "cleanup_pending": False,
    }
    assert not (quarantine_root / job_id).exists()

    fabricated_id = secrets.token_hex(32)
    fabricated_profile = "profile-rev9-fabricated-deleted"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)",
            (fabricated_id, fabricated_profile),
        )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET status='deleted',"
            "terminal_cause='explicit_deletion' WHERE job_id=%s",
            (fabricated_id,),
        )
    assert gateway.delete_job(job_id=fabricated_id, profile_id=fabricated_profile) == {
        "state": "deleted",
        "cleanup_pending": True,
    }


@pytest.mark.parametrize("release_state", ("binding-absent", "directory-absent"))
def test_rev9_repeated_delete_converges_half_and_fully_released_filesystem(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    release_state: str,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev9-delete-{release_state}"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="explicit_deletion",
            reason_code="PHOTO_EXPLICIT_DELETION",
            from_status="running",
            to_status="deleted",
        )
    job_path = quarantine_root / job_id
    (job_path / ".itda-owner-v1").unlink()
    if release_state == "directory-absent":
        job_path.rmdir()
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    for _ in range(2):
        assert gateway.delete_job(job_id=job_id, profile_id=profile_id) == {
            "state": "deleted",
            "cleanup_pending": False,
        }
    assert not job_path.exists()


def _rev13_job_snapshot(
    postgres_harness: object, job_id: str
) -> tuple[tuple[object, ...] | None, tuple[tuple[object, ...], ...]]:
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        job = admin.execute(
            "SELECT status,terminal_cause,terminal_operation_key,"
            "terminal_proof_digest,filesystem_cleanup_pending,lease_expires_at,"
            "reconcile_attempted_at FROM dev_eval.photo_jobs "
            "WHERE job_id=%s",
            (job_id,),
        ).fetchone()
        evidence = tuple(
            admin.execute(
                "SELECT source,count(*) FROM ("
                "SELECT 'binding'::text source FROM dev_eval.photo_job_filesystem_bindings "
                "WHERE job_id=%s UNION ALL "
                "SELECT 'slot' FROM dev_eval.photo_job_image_slots WHERE job_id=%s UNION ALL "
                "SELECT 'marker' FROM dev_eval.photo_job_dispatch_markers "
                "WHERE job_id=%s UNION ALL "
                "SELECT 'candidate' FROM dev_eval.photo_trait_candidates WHERE job_id=%s UNION ALL "
                "SELECT 'draft' FROM dev_eval.photo_review_drafts WHERE job_id=%s UNION ALL "
                "SELECT 'confirmed' FROM dev_eval.photo_confirmed_traits WHERE job_id=%s UNION ALL "
                "SELECT 'receipt' FROM dev_eval.photo_confirmation_receipts "
                "WHERE job_id=%s UNION ALL "
                "SELECT 'ledger' FROM dev_eval.photo_deletion_ledger WHERE job_id=%s"
                ") evidence GROUP BY source ORDER BY source",
                (job_id,) * 8,
            ).fetchall()
        )
    return job, evidence


def _rev13_release_terminal(
    service_dsn: str,
    quarantine_root: Path,
    job_id: str,
    profile_id: str,
    *,
    to_status: str = "succeeded",
    cause: str = "success",
    reason_code: str = "PHOTO_SUCCESS",
) -> None:
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        outcome = photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause=cause,
            reason_code=reason_code,
            from_status="running",
            to_status=to_status,
        )
        photo_deletion.release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            operation_key=str(outcome.operation_key),
            proof_digest=str(outcome.proof_digest),
        )


def test_rev13_new_queued_job_deletes_without_filesystem_authority(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev13-never-materialized"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    assert gateway.delete_job(job_id=job_id, profile_id=profile_id) == {
        "state": "deleted",
        "cleanup_pending": False,
    }
    assert not (quarantine_root / job_id).exists()
    first = _rev13_job_snapshot(postgres_harness, job_id)
    assert first[0] is not None and first[0][0:2] == ("deleted", "explicit_deletion")
    assert first[0][4] is False
    assert dict(first[1]) == {"ledger": 1}

    assert gateway.delete_job(job_id=job_id, profile_id=profile_id) == {
        "state": "deleted",
        "cleanup_pending": False,
    }
    assert _rev13_job_snapshot(postgres_harness, job_id) == first


@pytest.mark.parametrize(
    ("prior_status", "prior_cause", "prior_reason"),
    (
        ("succeeded", "success", "PHOTO_SUCCESS"),
        ("failed", "provider_error", "PHOTO_PROVIDER_ERROR"),
        ("expired", "expiry", "PHOTO_EXPIRY"),
    ),
)
def test_rev13_released_terminal_job_deletes_without_rebinding(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    prior_status: str,
    prior_cause: str,
    prior_reason: str,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev13-terminal-released"
    _rev13_release_terminal(
        service_dsn,
        quarantine_root,
        job_id,
        profile_id,
        to_status=prior_status,
        cause=prior_cause,
        reason_code=prior_reason,
    )
    assert not (quarantine_root / job_id).exists()
    before = _rev13_job_snapshot(postgres_harness, job_id)
    assert before[0] is not None and before[0][0:2] == (prior_status, prior_cause)
    assert before[0][4] is False

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    assert gateway.delete_job(job_id=job_id, profile_id=profile_id) == {
        "state": "deleted",
        "cleanup_pending": False,
    }
    after = _rev13_job_snapshot(postgres_harness, job_id)
    assert after[0] is not None and after[0][0:2] == ("deleted", "explicit_deletion")
    assert after[0][4] is False
    assert dict(after[1]) == {"ledger": 2}
    assert not (quarantine_root / job_id).exists()


@pytest.mark.parametrize(
    "poison",
    ("lease", "reconcile", "slot", "marker", "candidate", "draft", "confirmed", "receipt"),
)
def test_rev13_unbound_queued_delete_rejects_any_durable_storage_evidence(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    poison: str,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev13-queued-{poison}"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        if poison == "lease":
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()+interval '5 minutes' "
                "WHERE job_id=%s",
                (job_id,),
            )
        elif poison == "reconcile":
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET reconcile_attempted_at=now() WHERE job_id=%s",
                (job_id,),
            )
        elif poison == "slot":
            admin.execute(
                "INSERT INTO dev_eval.photo_job_image_slots "
                "(job_id,profile_id,image_index,state,stored_name,media_type) "
                "VALUES (%s,%s,1,'reserved',%s,'image/png')",
                (job_id, profile_id, secrets.token_hex(16)),
            )
        elif poison == "marker":
            admin.execute(
                "INSERT INTO dev_eval.photo_job_dispatch_markers(job_id,attempt,marker) "
                "VALUES (%s,1,'reserved')",
                (job_id,),
            )
        elif poison == "candidate":
            admin.execute(
                "INSERT INTO dev_eval.photo_trait_candidates "
                "(job_id,candidate_id,trait_id,text_ko,candidate_set_sha256) "
                "VALUES (%s,%s,'M1','증거',%s)",
                (job_id, secrets.token_hex(32), secrets.token_hex(32)),
            )
        elif poison == "draft":
            admin.execute(
                "INSERT INTO dev_eval.photo_review_drafts "
                "(job_id,profile_id,draft_digest,candidate_ids,trait_ids,"
                "edited_texts_ko,excluded_flags) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (
                    job_id,
                    profile_id,
                    secrets.token_hex(32),
                    [secrets.token_hex(32)],
                    ["M1"],
                    [None],
                    [False],
                ),
            )
        elif poison == "confirmed":
            admin.execute(
                "INSERT INTO dev_eval.photo_confirmed_traits "
                "(job_id,confirmation_seq,trait_id,text_ko,included) "
                "VALUES (%s,1,'M1','증거',true)",
                (job_id,),
            )
        else:
            admin.execute(
                "INSERT INTO dev_eval.photo_confirmation_receipts "
                "(receipt_id,job_id,profile_id,draft_digest,included_count) "
                "VALUES (%s,%s,%s,%s,0)",
                (secrets.token_hex(32), job_id, profile_id, secrets.token_hex(32)),
            )
    before = _rev13_job_snapshot(postgres_harness, job_id)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with pytest.raises(psycopg.errors.CheckViolation):
        gateway.delete_job(job_id=job_id, profile_id=profile_id)
    assert _rev13_job_snapshot(postgres_harness, job_id) == before
    assert not (quarantine_root / job_id).exists()


@pytest.mark.parametrize("poison", ("pending", "missing-ledger", "wrong-cause", "forged-digest"))
def test_rev13_released_terminal_delete_requires_exact_completed_prior_proof(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    poison: str,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev13-terminal-{poison}"
    _rev13_release_terminal(service_dsn, quarantine_root, job_id, profile_id)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        if poison == "pending":
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET filesystem_cleanup_pending=true WHERE job_id=%s",
                (job_id,),
            )
        elif poison == "missing-ledger":
            admin.execute("DELETE FROM dev_eval.photo_deletion_ledger WHERE job_id=%s", (job_id,))
        elif poison == "wrong-cause":
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET terminal_cause='provider_error' WHERE job_id=%s",
                (job_id,),
            )
        else:
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET terminal_proof_digest=%s WHERE job_id=%s",
                (secrets.token_hex(32), job_id),
            )
    before = _rev13_job_snapshot(postgres_harness, job_id)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    with pytest.raises(psycopg.errors.CheckViolation):
        gateway.delete_job(job_id=job_id, profile_id=profile_id)
    assert _rev13_job_snapshot(postgres_harness, job_id) == before
    assert not (quarantine_root / job_id).exists()


@pytest.mark.parametrize("failure", ("collision", "eio", "post_sql_eio"))
def test_rev13_unbound_delete_rejects_collision_and_non_enoent_inspection(
    monkeypatch: pytest.MonkeyPatch,
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    failure: str,
) -> None:
    from itda.photo import deletion as deletion_module

    service_dsn = _service_dsn(postgres_harness)
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    job_id = secrets.token_hex(32)
    profile_id = f"profile-rev13-path-{failure}"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute("SELECT dev_eval.create_photo_job_v3(%s,%s,NULL)", (job_id, profile_id))
    collision = quarantine_root / job_id
    if failure == "collision":
        collision.write_bytes(b"sentinel")
    before = _rev13_job_snapshot(postgres_harness, job_id)
    with monkeypatch.context() as patch:
        if failure in {"eio", "post_sql_eio"}:
            real_stat = deletion_module.os.stat
            observations = 0

            def fail_canonical(path: object, *args: object, **kwargs: object) -> os.stat_result:
                nonlocal observations
                if path == job_id and kwargs.get("follow_symlinks") is False:
                    observations += 1
                    if failure == "eio" or observations == 2:
                        raise OSError(5, "synthetic observation failure")
                return real_stat(path, *args, **kwargs)

            patch.setattr(deletion_module.os, "stat", fail_canonical)
        with pytest.raises(deletion_module.DeletionIncomplete):
            gateway.delete_job(job_id=job_id, profile_id=profile_id)
    assert _rev13_job_snapshot(postgres_harness, job_id) == before
    if failure == "collision":
        assert collision.read_bytes() == b"sentinel"


def test_rev9_connect_failure_acquires_no_budget_or_root_fd(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    from collections.abc import AsyncIterator

    from itda.api.routes import photo as photo_route

    gateway = _f05_gateway(postgres_harness, quarantine_root, _service_dsn(postgres_harness))
    opened: list[int] = []
    monkeypatch.setattr(
        photo_route.psycopg,
        "connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("connect failed")),
    )
    monkeypatch.setattr(
        photo_route,
        "open_quarantine_root",
        lambda *_args, **_kwargs: opened.append(1),
    )

    async def body() -> AsyncIterator[bytes]:
        yield b"x"

    for _ in range(2):
        job_id = secrets.token_hex(32)
        with pytest.raises(OSError, match="connect failed"):
            asyncio.run(
                gateway.store_image_stream(  # type: ignore[attr-defined]
                    job_id=job_id,
                    job_directory=job_id,
                    profile_id="profile-rev9-connect-fail",
                    image_index=1,
                    chunks=body(),
                    declared_byte_length=1,
                    media_type="image/png",
                )
            )
    assert opened == []
    assert gateway._budget._reserved_bytes == 0  # noqa: SLF001


@pytest.mark.parametrize(("statement", "suffix"), REV9_JOB_SPECIFIC_V3_CALLS)
def test_rev9_null_job_id_is_rejected_by_every_v3_call(
    postgres_harness: object,
    phase6_deletion_schema: None,
    statement: str,
    suffix: tuple[object, ...],
) -> None:
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _rev9_assert_23514(connection, statement, (None, *suffix))


@pytest.mark.parametrize("null_field", ("reason", "operation", "digest"))
def test_rev9_null_terminal_proof_fields_reject_without_writes(
    postgres_harness: object,
    phase6_deletion_schema: None,
    null_field: str,
) -> None:
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev9-null-proof"
    operation_key = photo_deletion._operation_key(  # noqa: SLF001
        job_id, profile_id, "provider_error", "PHOTO_PROVIDER_ERROR"
    )
    digest = photo_deletion._proof_digest(operation_key, 0)  # noqa: SLF001
    values: dict[str, object] = {
        "reason": "PHOTO_PROVIDER_ERROR",
        "operation": operation_key,
        "digest": digest,
    }
    values[null_field] = None
    with psycopg.connect(_service_dsn(postgres_harness), autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        before = _rev9_job_counts(postgres_harness, job_id)
        _rev9_assert_23514(
            connection,
            "SELECT dev_eval.append_photo_deletion_ledger_v3(%s,%s,%s,%s,%s,0,%s)",
            (
                job_id,
                profile_id,
                "provider_error",
                values["reason"],
                values["operation"],
                values["digest"],
            ),
        )
        assert _rev9_job_counts(postgres_harness, job_id) == before


# ---------------------------------------------------------------------------
# Rev10: durable dispatch markers, submit/provider transaction split, Phase-B
# canonical operation derivation, candidate/lock canonical derivation, and raw
# relation/schema ACL grantee closure.
# ---------------------------------------------------------------------------


def _rev10_markers(
    connection: psycopg.Connection[tuple[object, ...]], job_id: str, profile_id: str
) -> list[str]:
    return [
        str(row[0])
        for row in connection.execute(
            "SELECT marker FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
    ]


def _rev10_seed_stored_slot(
    service_dsn: str,
    quarantine_root: Path,
    job_id: str,
    profile_id: str,
) -> tuple[str, int]:
    written = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s, %s, 1, %s, %s)",
            (job_id, profile_id, written[0].name, "image/png"),
        ).fetchone()
        connection.execute(
            "SELECT dev_eval.commit_photo_image_slot_v3(%s, %s, 1, %s, %s)",
            (job_id, profile_id, written[0].name, written[0].stat().st_size),
        )
    return written[0].name, written[0].stat().st_size


class _Rev10ForbiddenProvider:
    """Provider stub whose invocation is itself the test failure."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    def analyze(self, *_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("the provider must never run in this Rev10 path")


def _rev10_exit_after_marker(
    service_dsn: str,
    quarantine_root: str,
    job_id: str,
    profile_id: str,
    boundary: str,
    runtime_role: str,
    builder_role: str,
) -> None:
    """Child worker that hard-exits right after one durable submit boundary.

    ``boundary`` selects the durable point: ``"after_stage_a_commit"`` is
    the committed reserved+prepared prefix with the row running (the
    pre-send crash), ``"after_send_boundary"`` is the uncertain send.
    """

    from itda.api.routes import photo as photo_route

    exit_code = {"after_stage_a_commit": 81, "after_send_boundary": 82}[boundary]

    def crash_hook(reached: str) -> None:
        if reached == boundary:
            os._exit(exit_code)

    gateway = _rev10_gateway_from_module(
        photo_route,
        service_dsn,
        quarantine_root,
        runtime_role=runtime_role,
        builder_role=builder_role,
    )
    gateway._provider = _Rev10ForbiddenProvider()  # noqa: SLF001
    gateway.submit_job(job_id=job_id, profile_id=profile_id, boundary_hook=crash_hook)  # type: ignore[attr-defined]


def _rev10_gateway_from_module(
    photo_route: object,
    service_dsn: str,
    quarantine_root: str,
    *,
    runtime_role: str,
    builder_role: str,
) -> object:
    from itda.db.session import create_database_engine, create_session_factory

    return photo_route.PhotoLifecycleGateway(  # type: ignore[attr-defined]
        factory=create_session_factory(create_database_engine(service_dsn)),
        service_dsn=service_dsn,
        quarantine_root=Path(quarantine_root),
        runtime_role=runtime_role,
        builder_role=builder_role,
    )


def test_rev10_send_boundary_crash_survives_markers_and_reconcile_converges_once(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash right after the durable send boundary keeps running + markers,
    proves nothing, and one real reconciliation converges worker_crash with
    uncertain_resolved and no provider re-invocation."""

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-send-crash"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
    _rev10_seed_stored_slot(service_dsn, quarantine_root, job_id, profile_id)

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_KEY", raising=False)
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    monkeypatch.delenv("BIGMODEL_API_KEY", raising=False)
    child = multiprocessing.get_context("fork").Process(
        target=_rev10_exit_after_marker,
        args=(
            service_dsn,
            str(quarantine_root),
            job_id,
            profile_id,
            "after_send_boundary",
            postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
            postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
        ),
    )
    child.start()
    child.join(timeout=20)
    assert child.exitcode == 82, "child must hard-exit right after send_boundary"

    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute' "
            "WHERE job_id=%s",
            (job_id,),
        )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        status = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        markers = _rev10_markers(connection, job_id, profile_id)
        ledger = _ledger_rows(connection, job_id, profile_id)
    assert status == ("running",)
    assert "send_boundary" in markers
    assert ledger == []

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    provider_calls: list[object] = []

    def forbidden(**_kwargs: object) -> None:
        provider_calls.append(1)
        raise AssertionError("reconciliation must never re-invoke the provider")

    monkeypatch.setattr(gateway._provider, "analyze", forbidden)  # noqa: SLF001
    monkeypatch.setattr(gateway, "_sanitized_bytes", forbidden)  # noqa: SLF001
    from itda.photo.jobs import reconcile_interrupted_jobs

    with psycopg.connect(service_dsn, autocommit=True) as connection:
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
    assert report.uncertain_resolved >= 1
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        pending = connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
    assert state == ("failed",)
    assert pending == (False,)
    assert provider_calls == []
    assert not (quarantine_root / job_id).exists()


def test_rev12_bound_marker_sets_reconcile_with_exact_metrics_and_no_provider(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute("TRUNCATE dev_eval.photo_jobs CASCADE")
    service_dsn = _service_dsn(postgres_harness)
    valid_job = secrets.token_hex(32)
    malformed_job = secrets.token_hex(32)
    valid_profile = "profile-rev12-valid-send"
    malformed_profile = "profile-rev12-malformed-send"
    _seed_quarantine_objects(quarantine_root, valid_job, valid_profile, count=1)
    _seed_quarantine_objects(quarantine_root, malformed_job, malformed_profile, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for job_id, profile_id in (
            (valid_job, valid_profile),
            (malformed_job, malformed_profile),
        ):
            _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        for marker in ("reserved", "prepared", "send_boundary"):
            connection.execute(
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, 1, %s)",
                (valid_job, valid_profile, marker),
            )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute' "
            "WHERE job_id IN (%s, %s)",
            (valid_job, malformed_job),
        )
        admin.execute(
            "INSERT INTO dev_eval.photo_job_dispatch_markers (job_id, attempt, marker) "
            "VALUES (%s, 1, 'send_boundary')",
            (malformed_job,),
        )

    provider_calls: list[object] = []

    def forbidden(**_kwargs: object) -> None:
        provider_calls.append(1)
        raise AssertionError("reconciliation must never invoke the provider")

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    monkeypatch.setattr(gateway._provider, "analyze", forbidden)  # noqa: SLF001
    monkeypatch.setattr(gateway, "_sanitized_bytes", forbidden)  # noqa: SLF001
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
    assert report.examined == 2
    assert report.uncertain_resolved == 1
    assert report.failed_closed == 1
    assert report.expired == 0
    assert provider_calls == []
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        states = admin.execute(
            "SELECT job_id, status, terminal_cause, filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id IN (%s, %s) ORDER BY job_id",
            (valid_job, malformed_job),
        ).fetchall()
    assert states == sorted(
        [
            (valid_job, "failed", "worker_crash", False),
            (malformed_job, "failed", "worker_crash", False),
        ]
    )
    assert not (quarantine_root / valid_job).exists()
    assert not (quarantine_root / malformed_job).exists()


def test_rev12_cleanup_candidate_rotation_reaches_later_valid_row(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute("TRUNCATE dev_eval.photo_jobs CASCADE")
    profile_id = "profile-rev12-fair-rotation"
    poison_ids = [f"{index:064x}" for index in range(1, 257)]
    valid_id = "f" * 64
    all_ids = poison_ids + [valid_id]
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.cursor().executemany(
            "INSERT INTO dev_eval.photo_jobs "
            "(job_id, profile_id, status, lease_expires_at, updated_at) "
            "VALUES (%s, %s, 'running', now()-interval '1 minute', "
            "now()-interval '10 minutes')",
            [(job_id, profile_id) for job_id in all_ids],
        )
        admin.cursor().executemany(
            "INSERT INTO dev_eval.photo_job_filesystem_bindings "
            "(job_id, profile_id, claimed_at) VALUES (%s, %s, now()-interval '10 minutes')",
            [(job_id, profile_id) for job_id in all_ids],
        )

    original_remove = photo_deletion.remove_all_objects

    def poison_first_batch(**kwargs: object) -> None:
        if str(kwargs["job_id"]) in poison_ids:
            raise photo_deletion.DeletionIncomplete("persistent poison cleanup")
        original_remove(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(photo_deletion, "remove_all_objects", poison_first_batch)
    service_dsn = _service_dsn(postgres_harness)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        first = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
        second = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
    assert first.examined == 0
    assert second.examined == 1, "durable rotation must reach the row after 256 poison heads"
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        valid_state = admin.execute(
            "SELECT status, terminal_cause, filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (valid_id,),
        ).fetchone()
        poison_pending = admin.execute(
            "SELECT count(*) FROM dev_eval.photo_jobs WHERE job_id=ANY(%s) AND status='running'",
            (poison_ids,),
        ).fetchone()
    assert valid_state == ("failed", "worker_crash", False)
    assert poison_pending == (256,), "poison rows must remain fail-closed and retryable"
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute("DELETE FROM dev_eval.photo_jobs WHERE job_id=ANY(%s)", (all_ids,))


def test_rev12_cleanup_candidate_claims_are_disjoint_and_rotation_is_durable(
    postgres_harness: object,
    phase6_deletion_schema: None,
) -> None:
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute("TRUNCATE dev_eval.photo_jobs CASCADE")
    profile_id = "profile-rev12-disjoint"
    job_ids = [f"{index + 4096:064x}" for index in range(300)]
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.cursor().executemany(
            "INSERT INTO dev_eval.photo_jobs "
            "(job_id, profile_id, status, lease_expires_at, updated_at) "
            "VALUES (%s, %s, 'running', now()-interval '1 minute', "
            "now()-interval '10 minutes')",
            [(job_id, profile_id) for job_id in job_ids],
        )
        admin.cursor().executemany(
            "INSERT INTO dev_eval.photo_job_filesystem_bindings "
            "(job_id, profile_id, claimed_at) VALUES (%s, %s, now()-interval '10 minutes')",
            [(job_id, profile_id) for job_id in job_ids],
        )

    service_dsn = _service_dsn(postgres_harness)
    with (
        psycopg.connect(service_dsn) as first_connection,
        psycopg.connect(service_dsn) as second_connection,
    ):
        first = {
            str(row[0])
            for row in first_connection.execute(
                "SELECT job_id FROM dev_eval.list_photo_cleanup_candidates_v3()"
            ).fetchall()
        }
        second = {
            str(row[0])
            for row in second_connection.execute(
                "SELECT job_id FROM dev_eval.list_photo_cleanup_candidates_v3()"
            ).fetchall()
        }
        assert len(first) == 256
        assert len(second) == 44
        assert first.isdisjoint(second), "concurrent sweepers must claim disjoint locked rows"
        first_connection.commit()
        second_connection.commit()
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        stamped = admin.execute(
            "SELECT count(*) FROM dev_eval.photo_jobs WHERE job_id=ANY(%s) "
            "AND reconcile_attempted_at IS NOT NULL AND status='running' "
            "AND terminal_operation_key IS NULL AND terminal_proof_digest IS NULL",
            (job_ids,),
        ).fetchone()
    assert stamped == (300,), "claim rotation may stamp time but cannot mint terminal truth"
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute("DELETE FROM dev_eval.photo_jobs WHERE job_id=ANY(%s)", (job_ids,))


def test_rev12_illegal_cause_transition_precedes_filesystem_mutation(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev12-illegal-predelete"
    paths = _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
        with pytest.raises(photo_deletion.DeletionIncomplete):
            photo_deletion.execute_terminal_deletion(
                connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                cause="provider_error",
                reason_code="PHOTO_PROVIDER_ERROR",
                from_status="queued",
                to_status="failed",
            )
        ledger = _ledger_rows(connection, job_id, profile_id)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        state = admin.execute(
            "SELECT status, terminal_cause, filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s AND profile_id=%s",
            (job_id, profile_id),
        ).fetchone()
    assert state == ("queued", None, False)
    assert ledger == []
    assert all(path.is_file() for path in paths)
    assert (quarantine_root / job_id / ".itda-owner-v1").is_file()


@pytest.mark.parametrize(
    ("cause", "from_status", "to_status"),
    (
        ("provider_error", "queued", "failed"),
        ("success", "queued", "failed"),
    ),
)
def test_rev13_illegal_terminal_replay_never_mutates_filesystem_or_proof(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    cause: str,
    from_status: str,
    to_status: str,
) -> None:
    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev13-illegal-replay-" + secrets.token_hex(4)
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        before_ledger = _ledger_rows(connection, job_id, profile_id)
    replay_file = quarantine_root / job_id / secrets.token_hex(16)
    replay_file.write_bytes(b"rev13-replay-bytes")
    replay_file.chmod(0o600)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        before_state = admin.execute(
            "SELECT status, terminal_cause, terminal_operation_key, "
            "terminal_proof_digest, filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone()
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        with pytest.raises((photo_deletion.DeletionIncomplete, psycopg.errors.CheckViolation)):
            photo_deletion.execute_terminal_deletion(
                connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                cause=cause,
                reason_code=f"PHOTO_{cause.upper()}",
                from_status=from_status,
                to_status=to_status,
            )
        after_ledger = _ledger_rows(connection, job_id, profile_id)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        after_state = admin.execute(
            "SELECT status, terminal_cause, terminal_operation_key, "
            "terminal_proof_digest, filesystem_cleanup_pending "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone()
    assert replay_file.read_bytes() == b"rev13-replay-bytes"
    assert (quarantine_root / job_id / ".itda-owner-v1").is_file()
    assert after_state == before_state
    assert after_ledger == before_ledger


def test_rev13_non_autocommit_reconciliation_rejects_before_candidate_claim(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    from itda.photo.jobs import PhotoJobError, reconcile_interrupted_jobs

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev13-non-autocommit"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute', "
            "reconcile_attempted_at=NULL WHERE job_id=%s",
            (job_id,),
        )
        before = admin.execute(
            "SELECT status, terminal_cause, terminal_operation_key, terminal_proof_digest, "
            "filesystem_cleanup_pending, reconcile_attempted_at "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone()
    with psycopg.connect(service_dsn) as connection, pytest.raises(PhotoJobError):
        reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        after = admin.execute(
            "SELECT status, terminal_cause, terminal_operation_key, terminal_proof_digest, "
            "filesystem_cleanup_pending, reconcile_attempted_at "
            "FROM dev_eval.photo_jobs WHERE job_id=%s",
            (job_id,),
        ).fetchone()
    assert after == before


def test_rev12_expected_23514_race_is_isolated_per_candidate(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.photo.jobs import reconcile_interrupted_jobs

    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute("TRUNCATE dev_eval.photo_jobs CASCADE")
    service_dsn = _service_dsn(postgres_harness)
    raced_id = "d" * 64
    valid_id = "e" * 64
    profile_id = "profile-rev12-race-isolation"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for job_id in (raced_id, valid_id):
            _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute', "
            "updated_at=CASE WHEN job_id=%s THEN now()-interval '2 minutes' "
            "ELSE now()-interval '1 minute' END WHERE job_id IN (%s,%s)",
            (raced_id, raced_id, valid_id),
        )

    original_execute = photo_deletion.execute_terminal_deletion
    raced = False

    def inject_closed_race(*args: object, **kwargs: object) -> object:
        nonlocal raced
        if kwargs.get("job_id") == raced_id and not raced:
            raced = True
            raise psycopg.errors.CheckViolation("injected concurrent state race")
        return original_execute(*args, **kwargs)

    monkeypatch.setattr(photo_deletion, "execute_terminal_deletion", inject_closed_race)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        report = reconcile_interrupted_jobs(connection, quarantine_root=quarantine_root)
    assert raced
    assert report.examined == 1 and report.failed_closed == 1
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        states = admin.execute(
            "SELECT job_id, status FROM dev_eval.photo_jobs WHERE job_id IN (%s,%s) "
            "ORDER BY job_id",
            (raced_id, valid_id),
        ).fetchall()
    assert states == [(raced_id, "running"), (valid_id, "failed")]


def test_rev10_prepared_crash_fails_closed_without_provider(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash right after the prepared marker survives the marker, and the
    real TestClient lifespan converges the running row to failed_closed with
    zero provider invocations."""

    from itda.api.main import create_app
    from itda.api.routes import photo as photo_route

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-prepared-crash"
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="queued")
    _rev10_seed_stored_slot(service_dsn, quarantine_root, job_id, profile_id)

    child = multiprocessing.get_context("fork").Process(
        target=_rev10_exit_after_marker,
        args=(
            service_dsn,
            str(quarantine_root),
            job_id,
            profile_id,
            "after_stage_a_commit",
            postgres_harness.role_names["runtime"],  # type: ignore[attr-defined]
            postgres_harness.role_names["dev"],  # type: ignore[attr-defined]
        ),
    )
    child.start()
    child.join(timeout=20)
    assert child.exitcode == 81

    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "UPDATE dev_eval.photo_jobs SET lease_expires_at=now()-interval '1 minute' "
            "WHERE job_id=%s",
            (job_id,),
        )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        status = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        markers = _rev10_markers(connection, job_id, profile_id)
    assert status == ("running",)
    assert "prepared" in markers
    assert "send_boundary" not in markers

    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    provider_calls: list[object] = []

    def forbidden(**_kwargs: object) -> None:
        provider_calls.append(1)
        raise AssertionError("reconciliation must never re-invoke the provider")

    monkeypatch.setattr(gateway._provider, "analyze", forbidden)  # noqa: SLF001
    monkeypatch.setattr(gateway, "_sanitized_bytes", forbidden)  # noqa: SLF001
    monkeypatch.delenv("ITDA_DATABASE_URL", raising=False)
    monkeypatch.setenv("ITDA_PHOTO_SERVICE_DATABASE_URL", service_dsn)
    monkeypatch.setattr("itda.api.main.get_photo_lifecycle", lambda: gateway)
    monkeypatch.setattr(photo_route, "get_photo_lifecycle", lambda: gateway)
    with TestClient(create_app()) as client:
        assert client.app is not None
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        state = connection.execute(
            "SELECT status FROM dev_eval.read_photo_job_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
        pending = connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
    assert state == ("failed",)
    assert pending == (False,)
    assert provider_calls == []
    assert not (quarantine_root / job_id).exists()


def test_rev10_golden_synthetic_submit_records_exact_create_only_markers(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """The golden synthetic submit success records exactly the clientless
    create-only marker prefix (reserved, prepared, send_boundary — never a
    fabricated client_constructed), deterministic candidates, one success
    ledger row, and cleanup completion."""

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-golden"
    import asyncio
    from collections.abc import AsyncIterator as _AsyncIterator

    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)", (job_id, profile_id)
        )
    payload = _f05_png_bytes()
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    async def upload_body() -> _AsyncIterator[bytes]:
        yield payload

    asyncio.run(
        gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=upload_body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    assert gateway.submit_job(job_id=job_id, profile_id=profile_id) == {"state": "succeeded"}  # type: ignore[attr-defined]
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        markers = _rev10_markers(connection, job_id, profile_id)
        rows = _ledger_rows(connection, job_id, profile_id)
        candidates = connection.execute(
            "SELECT count(*) FROM dev_eval.list_photo_candidates_v2(%s, %s)",
            (job_id, profile_id),
        ).fetchone()
    assert sorted(markers) == ["prepared", "reserved", "send_boundary"]
    assert [row[2] for row in rows] == ["success"]
    assert candidates is not None and int(candidates[0]) >= 1
    assert not (quarantine_root / job_id).exists()


def test_rev10_concurrent_submit_admits_exactly_one_running_dispatch(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """A second submit that observes running is rejected — no ambiguous
    retry may race the in-flight dispatch."""

    import threading

    from itda.photo.jobs import PhotoJobError

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-concurrent"
    import asyncio
    from collections.abc import AsyncIterator as _AsyncIterator

    with psycopg.connect(service_dsn, autocommit=True) as connection:
        connection.execute(
            "SELECT dev_eval.create_photo_job_v3(%s, %s, NULL)", (job_id, profile_id)
        )
    payload = _f05_png_bytes()
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)

    async def upload_body() -> _AsyncIterator[bytes]:
        yield payload

    asyncio.run(
        gateway.store_image_stream(  # type: ignore[attr-defined]
            job_id=job_id,
            job_directory=job_id,
            profile_id=profile_id,
            image_index=1,
            chunks=upload_body(),
            declared_byte_length=len(payload),
            media_type="image/png",
        )
    )
    submit_gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    errors: list[BaseException] = []
    results: list[dict[str, object]] = []
    lock = threading.Lock()

    def submit() -> None:
        try:
            outcome = submit_gateway.submit_job(job_id=job_id, profile_id=profile_id)  # type: ignore[attr-defined]
            with lock:
                results.append(outcome)  # type: ignore[arg-type]
        except BaseException as error:  # noqa: BLE001
            with lock:
                errors.append(error)

    threads = [threading.Thread(target=submit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 1, "exactly one concurrent submit must succeed"
    assert len(errors) == 1, "exactly one concurrent submit must be rejected"
    rejected = errors[0]
    assert isinstance(rejected, (PhotoJobError, psycopg.Error)), (
        f"the loser must fail closed, got {type(rejected).__name__}"
    )
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        causes = [str(row[2]) for row in _ledger_rows(connection, job_id, profile_id)]
    assert causes.count("success") == 1, "exactly one success ledger row"


def test_rev10_phase_b_fabricated_operation_inputs_are_rejected(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """BLOCKER 3: Phase-B pending/complete must derive the canonical
    operation key from job/profile/current cause/ledger reason themselves;
    arbitrary caller-supplied K and SHA(K) pairs must be rejected with
    pending/FS kept."""

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-phase-b-negative"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        assert (quarantine_root / job_id).is_dir()

    import hashlib

    def sha256_zero(operation: str) -> str:
        return hashlib.sha256(f"photo-residue-v1|{operation}|0".encode()).hexdigest()

    fabricated = secrets.token_hex(32) * 2
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for candidate_key, candidate_digest in (
            (fabricated, sha256_zero(fabricated)),
            (fabricated, "0" * 64),
            ("0" * 64, sha256_zero(fabricated)),
        ):
            _rev9_assert_23514(
                connection,
                "SELECT dev_eval.pending_photo_filesystem_release_v3(%s,%s,%s,%s)",
                (job_id, profile_id, candidate_key, candidate_digest),
            )
            _rev9_assert_23514(
                connection,
                "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s,%s,%s,%s)",
                (job_id, profile_id, candidate_key, candidate_digest),
            )
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
    assert (quarantine_root / job_id).is_dir(), "FS pending target must survive every rejection"


def test_rev10_phase_b_wrong_cause_ledger_cannot_mint_completion(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """A wrong-cause ledger row matching its own self-consistent pointers
    cannot complete cleanup: completion derives the canonical cause and
    reason from durable state, not from the caller's arguments."""

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-wrong-cause"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        decoy = photo_deletion._operation_key(  # noqa: SLF001
            job_id, profile_id, "timeout", "PHOTO_TIMEOUT"
        )
        decoy_digest = photo_deletion._proof_digest(decoy, 0)  # noqa: SLF001
        connection.execute(
            "SELECT dev_eval.append_photo_deletion_ledger_v3"
            "(%s, %s, 'timeout', 'PHOTO_TIMEOUT', %s, 0, %s)",
            (job_id, profile_id, decoy, decoy_digest),
        )
        with pytest.raises((photo_deletion.DeletionIncomplete, psycopg.errors.CheckViolation)):
            photo_deletion.release_filesystem_cleanup(
                connection,
                quarantine_root=quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                operation_key=decoy,
                proof_digest=decoy_digest,
            )
        assert connection.execute(
            "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
            (job_id, profile_id),
        ).fetchone() == (True,)
    assert (quarantine_root / job_id).is_dir()


def test_rev10_orphan_candidates_require_canonical_ledger_derivation(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """BLOCKER 4: a failed row whose terminal pointer cannot be derived
    canonically from the current cause and ledger reason never enters the
    orphan candidate projection."""

    service_dsn = _service_dsn(postgres_harness)
    job_id = secrets.token_hex(32)
    profile_id = "profile-rev10-orphan-canonical"
    _seed_quarantine_objects(quarantine_root, job_id, profile_id, count=1)
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        _seed_owned_lifecycle(connection, job_id=job_id, profile_id=profile_id, state="running")
        photo_deletion.execute_terminal_deletion(
            connection,
            quarantine_root=quarantine_root,
            job_id=job_id,
            profile_id=profile_id,
            cause="provider_error",
            reason_code="PHOTO_PROVIDER_ERROR",
            from_status="running",
            to_status="failed",
        )
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute(
                "UPDATE dev_eval.photo_deletion_ledger SET reason_code='PHOTO_TIMEOUT' "
                "WHERE job_id=%s AND ledger_seq=("
                "SELECT max(ledger_seq) FROM dev_eval.photo_deletion_ledger WHERE job_id=%s)",
                (job_id, job_id),
            )
            admin.execute(
                "UPDATE dev_eval.photo_jobs SET filesystem_cleanup_pending=false, "
                "terminal_operation_key=%s WHERE job_id=%s",
                (secrets.token_hex(32), job_id),
            )
        projected = [
            row
            for row in connection.execute(
                "SELECT job_id, cleanup_class FROM dev_eval.list_photo_cleanup_candidates_v3()"
            ).fetchall()
            if str(row[0]) == job_id
        ]
        assert projected == [], "non-canonical terminal proof must not project as a candidate"


def test_rev10_raw_relation_acl_grantee_allowlist(
    postgres_harness: object,
    phase6_deletion_schema: None,
) -> None:
    """BLOCKER 5: every protected Phase6 relation exposes raw ACL entries to
    exactly the expected grantee — the photo write authority as owner, and
    nothing else (no service/runtime/builder/PUBLIC/unexpected direct
    grants)."""

    protected = (
        "photo_jobs",
        "photo_job_dispatch_markers",
        "photo_trait_candidates",
        "photo_confirmed_traits",
        "photo_deletion_ledger",
        "photo_review_drafts",
        "photo_confirmation_receipts",
        "photo_job_filesystem_bindings",
        "photo_job_image_slots",
    )
    with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
        for relation in protected:
            rows = admin.execute(
                "SELECT a.grantee, a.privilege_type, a.is_grantable "
                "FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode("
                "COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a "
                "WHERE n.nspname='dev_eval' AND c.relname=%s "
                "AND a.grantee <> c.relowner",
                (relation,),
            ).fetchall()
            assert rows == [], (
                f"{relation} must expose no non-owner raw ACL grantee entries: {rows}"
            )
            owner = admin.execute(
                "SELECT pg_catalog.pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='dev_eval' AND c.relname=%s",
                (relation,),
            ).fetchone()
            assert owner == ("itda_photo_write_authority",), (
                f"{relation} must be owned by the photo write authority"
            )


def test_rev10_unexpected_grantee_grant_is_rejected_and_restored(
    postgres_harness: object,
    quarantine_root: Path,
    phase6_deletion_schema: None,
) -> None:
    """BLOCKER 5 (negative): granting an unexpected LOGIN role schema USAGE
    plus photo_jobs SELECT plus slot/binding privileges must make both
    startup validators reject, and revocation must restore them."""

    from itda.api.routes.photo import verify_photo_service_execute_surface
    from itda.cli import e2e_runtime

    service_dsn = _service_dsn(postgres_harness)
    unexpected_role = "itda_rev10_intruder"
    owner_only = (
        "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz)",
        "dev_eval.claim_photo_job_v1(text,timestamptz)",
        "dev_eval.record_photo_dispatch_marker_v1(text,integer,text)",
        "dev_eval.create_photo_job_v2(text,text,text)",
        "dev_eval.transition_photo_job_status_v2(text,text,text,text,text,timestamptz)",
        "dev_eval.claim_photo_job_v2(text,text,timestamptz)",
        "dev_eval.record_photo_dispatch_marker_v2(text,text,integer,text)",
        "dev_eval.record_photo_candidate_batch_v2(text,text,text[],text[],text[],text[])",
        "dev_eval.annotate_photo_candidate_v2(text,text,text,text,boolean)",
        "dev_eval.append_photo_deletion_ledger_v2(text,text,text,text,text)",
        "dev_eval.save_photo_review_draft_v2(text,text,text,text[],text[],text[],boolean[])",
        "dev_eval.discard_photo_review_draft_v2(text,text)",
        "dev_eval.confirm_photo_traits_v2(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
        "dev_eval.list_reconcile_photo_jobs_v2()",
        "dev_eval.list_photo_deletion_ledger_v2(text,text)",
    )
    gateway = _f05_gateway(postgres_harness, quarantine_root, service_dsn)
    allowed = tuple(
        f"dev_eval.{signature}"
        for signature in gateway._REQUIRED_FUNCTIONS  # type: ignore[attr-defined]  # noqa: SLF001
    )
    try:
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute(f"CREATE ROLE {unexpected_role} LOGIN PASSWORD 'x'")
            admin.execute(f"GRANT USAGE ON SCHEMA dev_eval TO {unexpected_role}")
            admin.execute(f"GRANT SELECT ON dev_eval.photo_jobs TO {unexpected_role}")
            admin.execute(f"GRANT SELECT ON dev_eval.photo_job_image_slots TO {unexpected_role}")
            admin.execute(
                f"GRANT SELECT ON dev_eval.photo_job_filesystem_bindings TO {unexpected_role}"
            )
        for validator in (
            verify_photo_service_execute_surface,
            e2e_runtime.verify_photo_service_execute_surface,
        ):
            with (
                psycopg.connect(service_dsn, autocommit=True) as connection,
                pytest.raises(RuntimeError, match="photo service authority rejected"),
            ):
                validator(
                    connection,
                    allowed_procedures=allowed,
                    owner_only_procedures=owner_only,
                )
    finally:
        with postgres_harness.connect("admin", autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute(f"REVOKE ALL ON SCHEMA dev_eval FROM {unexpected_role}")
            admin.execute(f"REVOKE ALL ON dev_eval.photo_jobs FROM {unexpected_role}")
            admin.execute(f"REVOKE ALL ON dev_eval.photo_job_image_slots FROM {unexpected_role}")
            admin.execute(
                f"REVOKE ALL ON dev_eval.photo_job_filesystem_bindings FROM {unexpected_role}"
            )
            admin.execute(f"DROP ROLE {unexpected_role}")
    with psycopg.connect(service_dsn, autocommit=True) as connection:
        for validator in (
            verify_photo_service_execute_surface,
            e2e_runtime.verify_photo_service_execute_surface,
        ):
            validator(
                connection,
                allowed_procedures=allowed,
                owner_only_procedures=owner_only,
            )
