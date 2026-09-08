"""Idempotent deletion ledger and dual filesystem+DB residue convergence.

Every one of the nine terminal causes converges through the same ordered
cleanup: unlink the original quarantine objects (filesystem truth),
fsync, append one public-safe ledger row (database truth), sweep residue,
and only then complete the terminal job transition. Terminal completion
requires BOTH subsystems; a ledger row alone or a clean directory alone
never proves deletion.

Failure or lost response at any step re-enters safely: unresolved proof
stays ``cleanup_pending`` at the projection while the no-photo baseline
remains immediately available. The cleanup phase is a projected internal
value — never a seventh persisted public state.

Public ledger rows/errors carry only opaque job IDs, cause/reason codes,
timestamps, and canonical proof digests: no names, bytes, traits,
provider bodies, paths, secrets, or internal labels.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat as stat_module
import sys
from collections.abc import Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Final

TERMINAL_CAUSES: Final[tuple[str, ...]] = (
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
_TERMINAL_TRANSITIONS: Final[dict[str, tuple[frozenset[str], str]]] = {
    "success": (frozenset({"running"}), "succeeded"),
    "rejection": (frozenset({"queued", "running"}), "failed"),
    "validation_failure": (frozenset({"queued", "running"}), "failed"),
    "provider_error": (frozenset({"running"}), "failed"),
    "timeout": (frozenset({"running"}), "failed"),
    "worker_crash": (frozenset({"running"}), "failed"),
    "explicit_deletion": (
        frozenset({"queued", "running", "succeeded", "failed", "expired"}),
        "deleted",
    ),
    "expiry": (frozenset({"queued", "running"}), "expired"),
    "orphan_cleanup": (frozenset({"failed", "expired"}), "deleted"),
}

CAUSE_KINDS: Final[dict[str, str]] = {
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
PUBLIC_LEDGER_COLUMNS: Final[tuple[str, ...]] = (
    "job_id",
    "cause",
    "reason_code",
    "recorded_at",
    "residue_proof_digest",
)
FAILURE_INJECTION_POINTS: Final[tuple[str, ...]] = (
    "after_unlink",
    "after_dir_fsync",
    "after_ledger_insert",
    "after_terminal_mutation",
    "after_terminal_commit",
    "after_binding_unlink",
    "before_directory_rmdir",
    "after_filesystem_release",
)

_JOB_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_REASON_CODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_GENERATED_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{32}$")
_OPERATION_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_BINDING_NAME: Final[str] = ".itda-owner-v1"
_MAX_GENERATED_FILES: Final[int] = 3

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_READ_DIRECTORY_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_READ_FILE_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
_PROCESS_UID = getattr(os, "geteuid", lambda: None)()
_REMOVED_DIRECTORY_NLINK = 2 if sys.platform == "darwin" else 0


class DeletionIncomplete(RuntimeError):
    """Cleanup evidence is unresolved; terminal completion stays open."""

    code = "PHOTO_DELETION_INCOMPLETE"


def cause_kind(cause: str) -> str:
    if cause not in CAUSE_KINDS:
        raise DeletionIncomplete("photo deletion cause is outside the closed vocabulary")
    return CAUSE_KINDS[cause]


def _require_job_id(job_id: object) -> str:
    if not isinstance(job_id, str) or _JOB_ID_PATTERN.fullmatch(job_id) is None:
        raise DeletionIncomplete("photo deletion requires canonical 64-hex identity")
    return job_id


def _require_profile_id(profile_id: object) -> str:
    if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 160:
        raise DeletionIncomplete("photo deletion requires an owned profile identity")
    return profile_id


def _require_cause(cause: object) -> str:
    if cause not in CAUSE_KINDS:
        raise DeletionIncomplete("photo deletion cause is outside the closed vocabulary")
    return str(cause)


def _require_reason_code(reason_code: object) -> str:
    if not isinstance(reason_code, str) or _REASON_CODE_PATTERN.fullmatch(reason_code) is None:
        raise DeletionIncomplete("photo deletion reason code is not a closed public code")
    return reason_code


@dataclass(frozen=True, slots=True)
class ResidueReport:
    entries: int
    digest: str


@dataclass(frozen=True, slots=True)
class DeletionOutcome:
    complete: bool
    residue_count: int
    proof_digest: str | None
    ledger_row_created: bool
    operation_key: str | None = None
    no_photo_available: bool = True


def _binding_bytes(job_id: str, profile_id: str) -> bytes:
    return f"{job_id}\n{profile_id}\n".encode()


def _operation_key(job_id: str, profile_id: str, cause: str, reason_code: str) -> str:
    canonical = "|".join(("photo-terminal-v1", job_id, profile_id, cause, reason_code))
    first = hashlib.md5(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()
    second = hashlib.md5(f"{canonical}|second-half".encode(), usedforsecurity=False).hexdigest()
    return first + second


def _proof_digest(operation_key: str, residue_count: int) -> str:
    canonical = f"photo-residue-v1|{operation_key}|{residue_count}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _root_fd(quarantine_root: int | os.PathLike[str]) -> int:
    if isinstance(quarantine_root, int):
        root_state = os.fstat(quarantine_root)
        if (
            not stat_module.S_ISDIR(root_state.st_mode)
            or stat_module.S_IMODE(root_state.st_mode) != 0o700
            or (_PROCESS_UID is not None and root_state.st_uid != _PROCESS_UID)
        ):
            raise DeletionIncomplete("photo deletion quarantine root authority mismatched")
        return quarantine_root
    from itda.photo.quarantine import QuarantineError, open_quarantine_root

    try:
        return open_quarantine_root(quarantine_root)
    except QuarantineError as error:
        raise DeletionIncomplete("photo deletion quarantine root is unavailable") from error


def _binding_state(job_fd: int, job_id: str, profile_id: str) -> None:
    try:
        descriptor = os.open(_BINDING_NAME, _READ_FILE_FLAGS, dir_fd=job_fd)
    except FileNotFoundError as error:
        raise DeletionIncomplete("photo deletion owner binding is absent") from error
    except OSError as error:
        raise DeletionIncomplete("photo deletion owner binding inspection failed") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat_module.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat_module.S_IMODE(opened.st_mode) != 0o600
            or (_PROCESS_UID is not None and opened.st_uid != _PROCESS_UID)
        ):
            raise DeletionIncomplete("photo deletion owner binding type is invalid")
        chunks = bytearray()
        while len(chunks) <= 512:
            piece = os.read(descriptor, 513 - len(chunks))
            if not piece:
                break
            chunks.extend(piece)
        if bytes(chunks) != _binding_bytes(job_id, profile_id):
            raise DeletionIncomplete("photo deletion owner binding mismatched")
        visible = os.stat(_BINDING_NAME, dir_fd=job_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid) != (
            visible.st_dev,
            visible.st_ino,
            visible.st_mode,
            visible.st_nlink,
            visible.st_uid,
        ):
            raise DeletionIncomplete("photo deletion owner binding changed during inspection")
    except OSError as error:
        raise DeletionIncomplete("photo deletion owner binding inspection failed") from error
    finally:
        os.close(descriptor)


def _open_bound_job(root_fd: int, job_id: str, profile_id: str) -> int | None:
    try:
        job_fd = os.open(job_id, _READ_DIRECTORY_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise DeletionIncomplete(
            "photo deletion job directory failed no-follow inspection"
        ) from error
    try:
        _binding_state(job_fd, job_id, profile_id)
        opened_directory = os.fstat(job_fd)
        visible_directory = os.stat(job_id, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat_module.S_ISDIR(opened_directory.st_mode)
            or stat_module.S_IMODE(opened_directory.st_mode) != 0o700
            or (_PROCESS_UID is not None and opened_directory.st_uid != _PROCESS_UID)
            or opened_directory.st_nlink < 2
            or (
                opened_directory.st_dev,
                opened_directory.st_ino,
                opened_directory.st_mode,
                opened_directory.st_nlink,
                opened_directory.st_uid,
            )
            != (
                visible_directory.st_dev,
                visible_directory.st_ino,
                visible_directory.st_mode,
                visible_directory.st_nlink,
                visible_directory.st_uid,
            )
        ):
            raise DeletionIncomplete("photo deletion job directory identity mismatched")
    except Exception:
        os.close(job_fd)
        raise
    return job_fd


def _bound_job_exists(
    quarantine_root: int | os.PathLike[str], job_id: str, profile_id: str
) -> bool:
    root_fd = _root_fd(quarantine_root)
    close_root = not isinstance(quarantine_root, int)
    try:
        job_fd = _open_bound_job(root_fd, job_id, profile_id)
        if job_fd is None:
            return False
        os.close(job_fd)
        return True
    finally:
        if close_root:
            os.close(root_fd)


def _generated_entries(job_fd: int) -> list[str]:
    try:
        entries = os.listdir(job_fd)
    except OSError as error:
        raise DeletionIncomplete("photo deletion directory inspection failed") from error
    allowed = [name for name in entries if name != _BINDING_NAME]
    if len(allowed) > _MAX_GENERATED_FILES:
        raise DeletionIncomplete("photo deletion residue exceeded the bounded object set")
    if any(_GENERATED_NAME_PATTERN.fullmatch(name) is None for name in allowed):
        raise DeletionIncomplete("photo deletion found an unexpected directory entry")
    return sorted(allowed)


def _open_regular(job_fd: int, entry: str) -> tuple[int, os.stat_result] | None:
    try:
        descriptor = os.open(entry, _READ_FILE_FLAGS, dir_fd=job_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise DeletionIncomplete("photo deletion object open failed") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat_module.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat_module.S_IMODE(opened.st_mode) != 0o600
            or (_PROCESS_UID is not None and opened.st_uid != _PROCESS_UID)
        ):
            raise DeletionIncomplete("photo deletion opened object type is invalid")
        visible = os.stat(entry, dir_fd=job_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid) != (
            visible.st_dev,
            visible.st_ino,
            visible.st_mode,
            visible.st_nlink,
            visible.st_uid,
        ):
            raise DeletionIncomplete("photo deletion object changed during inspection")
        return descriptor, opened
    except FileNotFoundError:
        os.close(descriptor)
        return None
    except (OSError, DeletionIncomplete):
        os.close(descriptor)
        raise


def _inspect_regular(job_fd: int, entry: str) -> os.stat_result | None:
    inspected = _open_regular(job_fd, entry)
    if inspected is None:
        return None
    descriptor, opened = inspected
    os.close(descriptor)
    return opened


def remove_all_objects(
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    boundary_hook: object = None,
) -> None:
    """Unlink the bounded generated regular files for one durably owned job.

    ``boundary_hook`` is a test seam only: called with ``"after_unlink"`` once
    the last generated unlink finished but before any fsync, and with
    ``"after_dir_fsync"`` after both durable fsyncs completed.
    """

    opaque = _require_job_id(job_id)
    owner = _require_profile_id(profile_id)
    root_fd = _root_fd(quarantine_root)
    close_root = not isinstance(quarantine_root, int)
    try:
        job_fd = _open_bound_job(root_fd, opaque, owner)
        if job_fd is None:
            return
        try:
            for entry in _generated_entries(job_fd):
                inspected = _open_regular(job_fd, entry)
                if inspected is None:
                    continue
                descriptor, opened = inspected
                try:
                    visible = os.stat(entry, dir_fd=job_fd, follow_symlinks=False)
                    if (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_nlink,
                        opened.st_uid,
                    ) != (
                        visible.st_dev,
                        visible.st_ino,
                        visible.st_mode,
                        visible.st_nlink,
                        visible.st_uid,
                    ):
                        raise DeletionIncomplete("photo deletion object changed before unlink")
                    if boundary_hook is not None:
                        boundary_hook("before_generated_unlink")  # type: ignore[operator]
                    os.unlink(entry, dir_fd=job_fd)
                    removed = os.fstat(descriptor)
                    if (
                        removed.st_dev,
                        removed.st_ino,
                        removed.st_mode,
                        removed.st_uid,
                    ) != (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_mode,
                        opened.st_uid,
                    ) or removed.st_nlink != 0:
                        raise DeletionIncomplete(
                            "photo deletion object unlink postcondition failed"
                        )
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise DeletionIncomplete("photo deletion object unlink failed") from error
                finally:
                    os.close(descriptor)
            if boundary_hook is not None:
                boundary_hook("after_unlink")  # type: ignore[operator]
            try:
                os.fsync(job_fd)
            except OSError as error:
                raise DeletionIncomplete("photo deletion directory fsync failed") from error
        finally:
            os.close(job_fd)
        # Preserve the durable owner binding and job directory until database
        # proof exists. A crash after image unlink must leave enough authority
        # for an exact retry rather than turning absence into caller proof.
        try:
            os.fsync(root_fd)
        except OSError as error:
            raise DeletionIncomplete("photo deletion root fsync failed") from error
        if boundary_hook is not None:
            boundary_hook("after_dir_fsync")  # type: ignore[operator]
    finally:
        if close_root:
            os.close(root_fd)


def _open_release_job(root_fd: int, job_id: str, profile_id: str) -> tuple[int, bool] | None:
    """Open one Phase-B target under already-verified committed pending authority."""

    try:
        job_fd = os.open(job_id, _READ_DIRECTORY_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise DeletionIncomplete(
            "photo deletion release directory failed no-follow inspection"
        ) from error
    try:
        opened = os.fstat(job_fd)
        visible = os.stat(job_id, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat_module.S_ISDIR(opened.st_mode)
            or stat_module.S_IMODE(opened.st_mode) != 0o700
            or (_PROCESS_UID is not None and opened.st_uid != _PROCESS_UID)
            or opened.st_nlink < 2
            or (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid)
            != (
                visible.st_dev,
                visible.st_ino,
                visible.st_mode,
                visible.st_nlink,
                visible.st_uid,
            )
        ):
            raise DeletionIncomplete("photo deletion release directory identity mismatched")
        entries = os.listdir(job_fd)
        if entries == [_BINDING_NAME]:
            _binding_state(job_fd, job_id, profile_id)
            return job_fd, True
        if entries:
            raise DeletionIncomplete("photo deletion release directory was not empty")
        return job_fd, False
    except Exception:
        os.close(job_fd)
        raise


def _remove_bound_directory(
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    *,
    boundary_hook: object = None,
) -> None:
    """Release a committed pending target, including a half-removed directory."""

    root_fd = _root_fd(quarantine_root)
    close_root = not isinstance(quarantine_root, int)
    try:
        opened = _open_release_job(root_fd, job_id, profile_id)
        if opened is None:
            return
        job_fd, binding_present = opened
        try:
            if binding_present:
                try:
                    os.unlink(_BINDING_NAME, dir_fd=job_fd)
                except OSError as error:
                    raise DeletionIncomplete(
                        "photo deletion owner binding unlink failed"
                    ) from error
                os.fsync(job_fd)
                if boundary_hook is not None:
                    boundary_hook("after_binding_unlink")  # type: ignore[operator]
            held = os.fstat(job_fd)
            visible = os.stat(job_id, dir_fd=root_fd, follow_symlinks=False)
            if (
                held.st_dev,
                held.st_ino,
                held.st_mode,
                held.st_nlink,
                held.st_uid,
            ) != (
                visible.st_dev,
                visible.st_ino,
                visible.st_mode,
                visible.st_nlink,
                visible.st_uid,
            ):
                raise DeletionIncomplete("photo deletion directory changed before removal")
            if boundary_hook is not None:
                boundary_hook("before_directory_rmdir")  # type: ignore[operator]
            os.rmdir(job_id, dir_fd=root_fd)
            removed = os.fstat(job_fd)
            identity_changed = (
                removed.st_dev,
                removed.st_ino,
                removed.st_mode,
                removed.st_uid,
            ) != (
                held.st_dev,
                held.st_ino,
                held.st_mode,
                held.st_uid,
            )
            removal_invariant_failed = removed.st_nlink != _REMOVED_DIRECTORY_NLINK or (
                sys.platform == "darwin" and removed.st_ctime_ns != held.st_ctime_ns
            )
            if identity_changed or removal_invariant_failed:
                raise DeletionIncomplete("photo deletion directory removal postcondition failed")
            try:
                os.stat(job_id, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise DeletionIncomplete("photo deletion directory remained visible after removal")
            for root_entry in os.listdir(root_fd):
                try:
                    remaining = os.stat(root_entry, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (remaining.st_dev, remaining.st_ino) == (held.st_dev, held.st_ino):
                    raise DeletionIncomplete(
                        "photo deletion directory remained visible under another identity"
                    )
        except FileNotFoundError as error:
            raise DeletionIncomplete("photo deletion directory changed before removal") from error
        except OSError as error:
            raise DeletionIncomplete("photo deletion directory removal failed") from error
        finally:
            os.close(job_fd)
        os.fsync(root_fd)
    except OSError as error:
        raise DeletionIncomplete("photo deletion root fsync failed") from error
    finally:
        if close_root:
            os.close(root_fd)


def sweep_residue(
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    operation_key: str | None = None,
) -> ResidueReport:
    """Fresh descriptor residue proof; only ENOENT is classified absent."""

    opaque = _require_job_id(job_id)
    owner = _require_profile_id(profile_id)
    root_fd = _root_fd(quarantine_root)
    close_root = not isinstance(quarantine_root, int)
    try:
        job_fd = _open_bound_job(root_fd, opaque, owner)
        identities: list[str] = []
        if job_fd is None:
            count = 0
        else:
            try:
                for entry in _generated_entries(job_fd):
                    inspected = _inspect_regular(job_fd, entry)
                    if inspected is not None:
                        identities.append(
                            f"{entry}:{inspected.st_dev}:{inspected.st_ino}:"
                            f"{inspected.st_mode}:{inspected.st_nlink}"
                        )
                count = len(identities)
            finally:
                os.close(job_fd)
    finally:
        if close_root:
            os.close(root_fd)
    key = operation_key or ("0" * 64)
    if _OPERATION_KEY_PATTERN.fullmatch(key) is None:
        raise DeletionIncomplete("photo residue proof operation identity is invalid")
    digest = (
        _proof_digest(key, 0)
        if count == 0
        else hashlib.sha256(
            f"photo-residue-v1|{key}|{count}|{'|'.join(sorted(identities))}".encode()
        ).hexdigest()
    )
    return ResidueReport(entries=count, digest=digest)


def _ledger_rows_for(connection: object, job_id: str, profile_id: str) -> list[tuple[object, ...]]:
    execute = getattr(connection, "execute", None)
    if execute is None:
        return []
    return list(
        execute(
            "SELECT ledger_seq, job_id, cause, reason_code, recorded_at, operation_key, "
            "residue_count, residue_proof_digest "
            "FROM dev_eval.list_photo_deletion_ledger_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
    )


def _insert_ledger_row(
    connection: object,
    *,
    job_id: str,
    profile_id: str,
    cause: str,
    reason_code: str,
    operation_key: str,
    proof_digest: str,
) -> bool:
    execute = getattr(connection, "execute", None)
    if execute is None:
        raise DeletionIncomplete("photo deletion ledger authority is unavailable")
    created = execute(
        "SELECT dev_eval.append_photo_deletion_ledger_v3(%s, %s, %s, %s, %s, 0, %s)",
        (job_id, profile_id, cause, reason_code, operation_key, proof_digest),
    ).fetchone()
    return created is not None and bool(created[0])


def _matching_ledger_rows(
    rows: Sequence[tuple[object, ...]],
    *,
    job_id: str,
    cause: str,
    reason_code: str,
    proof_digest: str,
    operation_key: str | None = None,
) -> list[tuple[object, ...]]:
    exact = [
        row
        for row in rows
        if len(row) >= 8
        and row[1] == job_id
        and row[2] == cause
        and row[3] == reason_code
        and (operation_key is None or row[5] == operation_key)
        and row[6] == 0
        and row[7] == proof_digest
    ]
    if len(exact) != 1:
        raise DeletionIncomplete("photo deletion ledger evidence mismatched the exact operation")
    return exact


def assert_terminal_complete(
    *,
    ledger_rows: Sequence[tuple[object, ...]] | tuple[object, ...] | None,
    residue_count: int,
    job_id: str | None = None,
    cause: str | None = None,
    reason_code: str | None = None,
    operation_key: str | None = None,
    proof_digest: str | None = None,
) -> None:
    rows: list[tuple[object, ...]] = []
    if ledger_rows:
        rows = [row if isinstance(row, tuple) else (row,) for row in ledger_rows]
    if not rows or residue_count != 0:
        raise DeletionIncomplete("photo deletion completion requires ledger truth and zero residue")
    exact_values = (job_id, cause, reason_code, operation_key, proof_digest)
    if any(value is not None for value in exact_values):
        if not all(value is not None for value in exact_values):
            raise DeletionIncomplete("photo deletion exact evidence identity is incomplete")
        _matching_ledger_rows(
            rows,
            job_id=str(job_id),
            cause=str(cause),
            reason_code=str(reason_code),
            operation_key=str(operation_key),
            proof_digest=str(proof_digest),
        )


def _inject(injection_point: str | None, boundary: str) -> None:
    if injection_point == boundary:
        raise DeletionIncomplete("photo deletion cleanup did not finish")


def execute_terminal_deletion(
    connection: object,
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    cause: str,
    reason_code: str,
    from_status: str | None = None,
    to_status: str | None = None,
    injection_point: str | None = None,
    operation_kind: str = "terminal",
    release_after_commit: bool = False,
) -> DeletionOutcome:
    """Phase A of the durable saga: commit terminal truth with cleanup pending.

    Inside one transaction/lock: operation lock → unlink generated files →
    job/root fsync → ledger append → fresh zero sweep → finalizer sets the
    terminal state and ``filesystem_cleanup_pending`` → COMMIT. The binding
    file and directory still exist at commit, so a rollback or crash can
    never destroy reconciliation authority.
    """

    opaque = _require_job_id(job_id)
    owner = _require_profile_id(profile_id)
    terminal_cause = _require_cause(cause)
    reason = _require_reason_code(reason_code)
    if operation_kind not in {"terminal", "reconcile"}:
        raise DeletionIncomplete("photo deletion operation authority is invalid")
    if injection_point is not None and injection_point not in FAILURE_INJECTION_POINTS:
        raise DeletionIncomplete("photo deletion injection point is unknown")
    if from_status is None or to_status is None:
        raise DeletionIncomplete("photo deletion transition contract is incomplete")
    legal_sources, legal_target = _TERMINAL_TRANSITIONS[terminal_cause]
    if from_status not in legal_sources or to_status != legal_target:
        raise DeletionIncomplete("photo deletion transition contract is illegal")
    execute = getattr(connection, "execute", None)
    transaction = getattr(connection, "transaction", None)
    if execute is None or transaction is None:
        raise DeletionIncomplete("photo deletion transaction authority is unavailable")
    transaction_status = getattr(getattr(connection, "info", None), "transaction_status", None)
    transaction_context = nullcontext() if transaction_status not in (None, 0) else transaction()
    operation_key = _operation_key(opaque, owner, terminal_cause, reason)
    proof_digest = _proof_digest(operation_key, 0)
    created = False
    with transaction_context:
        locked = execute(
            "SELECT status FROM dev_eval.lock_photo_job_operation_v3(%s, %s, %s)",
            (opaque, owner, operation_kind),
        ).fetchone()
        if locked is None or str(locked[0]) not in {from_status, to_status}:
            raise DeletionIncomplete("photo deletion source state changed before cleanup")
        existing_rows = _ledger_rows_for(connection, opaque, owner)
        exact_prior_proof = False
        try:
            _matching_ledger_rows(
                existing_rows,
                job_id=opaque,
                cause=terminal_cause,
                reason_code=reason,
                operation_key=operation_key,
                proof_digest=proof_digest,
            )
        except DeletionIncomplete:
            pass
        else:
            exact_prior_proof = True
        if (
            not _bound_job_exists(quarantine_root, opaque, owner)
            and not exact_prior_proof
            and operation_kind != "reconcile"
        ):
            raise DeletionIncomplete("photo deletion missing directory lacks exact prior proof")
        remove_all_objects(
            quarantine_root=quarantine_root,
            job_id=opaque,
            profile_id=owner,
            boundary_hook=lambda boundary: _inject(injection_point, boundary),
        )
        created = _insert_ledger_row(
            connection,
            job_id=opaque,
            profile_id=owner,
            cause=terminal_cause,
            reason_code=reason,
            operation_key=operation_key,
            proof_digest=proof_digest,
        )
        _inject(injection_point, "after_ledger_insert")
        report = sweep_residue(
            quarantine_root=quarantine_root,
            job_id=opaque,
            profile_id=owner,
            operation_key=operation_key,
        )
        if report.entries != 0 or report.digest != proof_digest:
            raise DeletionIncomplete("photo deletion fresh residue proof mismatched")
        execute(
            "SELECT dev_eval.finalize_photo_job_terminal_v3(%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                opaque,
                owner,
                from_status,
                to_status,
                terminal_cause,
                reason,
                operation_key,
                proof_digest,
            ),
        )
        _inject(injection_point, "after_terminal_mutation")
    _inject(injection_point, "after_terminal_commit")
    if release_after_commit:
        release_filesystem_cleanup(
            connection,
            quarantine_root=quarantine_root,
            job_id=opaque,
            profile_id=owner,
            operation_key=operation_key,
            proof_digest=proof_digest,
            injection_point=injection_point,
        )
    return DeletionOutcome(True, 0, proof_digest, created, operation_key)


def execute_unbound_explicit_deletion(
    connection: object,
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
) -> DeletionOutcome:
    """Finalize the narrow no-binding explicit-deletion authority."""

    opaque = _require_job_id(job_id)
    owner = _require_profile_id(profile_id)
    execute = getattr(connection, "execute", None)
    transaction = getattr(connection, "transaction", None)
    if execute is None or transaction is None:
        raise DeletionIncomplete("photo deletion transaction authority is unavailable")
    transaction_status = getattr(getattr(connection, "info", None), "transaction_status", None)
    if transaction_status not in (None, 0):
        raise DeletionIncomplete("unbound photo deletion requires a clean transaction boundary")
    operation_key = _operation_key(opaque, owner, "explicit_deletion", "PHOTO_EXPLICIT_DELETION")
    proof_digest = _proof_digest(operation_key, 0)
    execute(
        "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended('photo-fs-v1|' || %s, 0))",
        (opaque,),
    )
    try:
        root_fd = _root_fd(quarantine_root)
        close_root = not isinstance(quarantine_root, int)
        try:
            try:
                os.stat(opaque, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise DeletionIncomplete(
                    "unbound photo deletion pathname inspection failed"
                ) from error
            else:
                raise DeletionIncomplete(
                    "unbound photo deletion requires an absent canonical pathname"
                )
        finally:
            if close_root:
                os.close(root_fd)
        with transaction():
            finalized = execute(
                "SELECT dev_eval.finalize_photo_job_unbound_explicit_deletion_v3(%s, %s)",
                (opaque, owner),
            ).fetchone()
            if finalized is None:
                raise DeletionIncomplete("unbound photo deletion authority mismatched")
            root_fd = _root_fd(quarantine_root)
            close_root = not isinstance(quarantine_root, int)
            try:
                try:
                    os.stat(opaque, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise DeletionIncomplete(
                        "unbound photo deletion pathname inspection failed"
                    ) from error
                else:
                    raise DeletionIncomplete("unbound photo deletion canonical pathname appeared")
            finally:
                if close_root:
                    os.close(root_fd)
    finally:
        execute(
            "SELECT pg_catalog.pg_advisory_unlock("
            "pg_catalog.hashtextextended('photo-fs-v1|' || %s, 0))",
            (opaque,),
        )
    return DeletionOutcome(True, 0, proof_digest, str(finalized[0]) != "deleted", operation_key)


def release_filesystem_cleanup(
    connection: object,
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    operation_key: str,
    proof_digest: str,
    injection_point: str | None = None,
) -> bool:
    """Phase B: release the filesystem binding then mark cleanup complete.

    Must run only after the terminal transaction committed. Validates the
    binding and empty directory, removes binding + directory + root fsync
    (accepting an already-absent directory under pending authority), then in
    a separate transaction clears the pending marker. Returns whether this
    call performed the completion.
    """

    opaque = _require_job_id(job_id)
    owner = _require_profile_id(profile_id)
    execute = getattr(connection, "execute", None)
    transaction = getattr(connection, "transaction", None)
    if execute is None or transaction is None:
        raise DeletionIncomplete("photo deletion transaction authority is unavailable")
    transaction_status = getattr(getattr(connection, "info", None), "transaction_status", None)
    owns_transaction = transaction_status not in (None, 0)
    if owns_transaction:
        raise DeletionIncomplete(
            "photo deletion release requires a transaction boundary after commit"
        )
    execute(
        "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended('photo-fs-v1|' || %s, 0))",
        (opaque,),
    )
    try:
        with transaction():
            authority = execute(
                "SELECT dev_eval.pending_photo_filesystem_release_v3(%s, %s, %s, %s)",
                (opaque, owner, operation_key, proof_digest),
            ).fetchone()
            if authority is None:
                raise DeletionIncomplete("photo deletion release authority mismatched")
            if not bool(authority[0]):
                return False
        _remove_bound_directory(
            quarantine_root,
            opaque,
            owner,
            boundary_hook=lambda boundary: _inject(injection_point, boundary),
        )
        _inject(injection_point, "after_filesystem_release")
        with transaction():
            completed = execute(
                "SELECT dev_eval.complete_photo_filesystem_cleanup_v3(%s, %s, %s, %s)",
                (opaque, owner, operation_key, proof_digest),
            ).fetchone()
            if completed is None:
                raise DeletionIncomplete("photo deletion cleanup completion mismatched")
            if not bool(completed[0]):
                replay = execute(
                    "SELECT dev_eval.pending_photo_filesystem_release_v3(%s, %s, %s, %s)",
                    (opaque, owner, operation_key, proof_digest),
                ).fetchone()
                if replay is None or bool(replay[0]):
                    raise DeletionIncomplete("photo deletion cleanup replay mismatched")
                return False
        return True
    finally:
        execute(
            "SELECT pg_catalog.pg_advisory_unlock("
            "pg_catalog.hashtextextended('photo-fs-v1|' || %s, 0))",
            (opaque,),
        )


def execute_terminal_deletion_with_failure_injection(
    connection: object,
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    cause: str,
    reason_code: str,
    injection_point: str,
    from_status: str | None = None,
    to_status: str | None = None,
) -> DeletionOutcome:
    return execute_terminal_deletion(
        connection,
        quarantine_root=quarantine_root,
        job_id=job_id,
        profile_id=profile_id,
        cause=cause,
        reason_code=reason_code,
        from_status=from_status,
        to_status=to_status,
        injection_point=injection_point,
    )


def reconcile_after_uncertain_completion(
    connection: object,
    *,
    quarantine_root: int | os.PathLike[str],
    job_id: str,
    profile_id: str,
    cause: str,
    reason_code: str,
    from_status: str | None = None,
    to_status: str | None = None,
) -> DeletionOutcome:
    return execute_terminal_deletion(
        connection,
        quarantine_root=quarantine_root,
        job_id=job_id,
        profile_id=profile_id,
        cause=cause,
        reason_code=reason_code,
        from_status=from_status,
        to_status=to_status,
        operation_kind="reconcile",
    )


def inspect_job_residue_count(
    *, quarantine_root: int | os.PathLike[str], job_id: str, profile_id: str
) -> int:
    return sweep_residue(
        quarantine_root=quarantine_root, job_id=job_id, profile_id=profile_id
    ).entries


def list_generated_entry_names(
    *, quarantine_root: int | os.PathLike[str], job_id: str, profile_id: str
) -> list[str]:
    """Names of the bounded generated objects for one durably owned job.

    Directory-entry listing only: no image bytes are opened or read. An
    absent job directory is an empty inventory, never an authority claim.
    """

    opaque = _require_job_id(job_id)
    owner = _require_profile_id(profile_id)
    root_fd = _root_fd(quarantine_root)
    close_root = not isinstance(quarantine_root, int)
    try:
        job_fd = _open_bound_job(root_fd, opaque, owner)
        if job_fd is None:
            return []
        try:
            return _generated_entries(job_fd)
        finally:
            os.close(job_fd)
    finally:
        if close_root:
            os.close(root_fd)


__all__ = [
    "CAUSE_KINDS",
    "FAILURE_INJECTION_POINTS",
    "PUBLIC_LEDGER_COLUMNS",
    "TERMINAL_CAUSES",
    "DeletionIncomplete",
    "DeletionOutcome",
    "ResidueReport",
    "assert_terminal_complete",
    "cause_kind",
    "execute_terminal_deletion",
    "execute_terminal_deletion_with_failure_injection",
    "execute_unbound_explicit_deletion",
    "inspect_job_residue_count",
    "list_generated_entry_names",
    "reconcile_after_uncertain_completion",
    "release_filesystem_cleanup",
    "remove_all_objects",
    "sweep_residue",
]
