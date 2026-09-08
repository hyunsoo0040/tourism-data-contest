"""Controlled-RED Phase 6 quarantine substitution and resource-abuse contract.

Wave 0 (Plan 06-02): every test below freezes behavior for the planned
Phase 6 storage and resource-abuse owners (Plan 06-05) before any production
code exists.  Owners are imported inside the tests so collection always
succeeds and execution fails only because the planned Phase 6 owners are
absent:

- ``itda.photo.quarantine`` — descriptor-safe write boundary contract
  (traversal components, symlinked parent, symlink/hardlink/non-regular
  targets, owner/mode/nlink violations, post-open substitution, fsync
  ordering, idempotent partial-write cleanup, residue inspection).
- ``itda.photo.ratelimit`` — in-process fixed-window session+IP limits,
  polling frequency, concurrent upload conflict, running-job cap, and total
  quarantine-byte reservation contract.

Frozen contract (Wave 0 authority for Plan 06-05):

- Job directory names are opaque generated identities; traversal components
  ("", ".", "..", absolute, backslash, NUL) never resolve inside the root.
- Every write uses a fresh no-follow exclusive create below a 0700 job
  directory; stored files are 0600 regular files with nlink 1 owned by the
  process user; parent-chain and file identity rechecks detect post-open
  substitution; the stored file is fsynced before the parent directory
  publish fsync.
- Opening a quarantined image by name rejects symlink, hardlink, FIFO, and
  directory targets plus owner/mode/nlink drift, fact-free.
- Partial writes remove all residue; repeated hostile attempts converge to
  zero residue and ``inspect_job_residue`` reports the job clean.
- ``PhotoRateLimitPolicy`` freezes 6 job creates/min, 18 image PUTs/min,
  60 polls/min per session+IP window; ``PhotoResourceBudget`` bounds 4
  concurrent jobs and 80 MiB total quarantine reservation.  Fixed windows
  advance on an injected monotonic clock; retry-after is a deterministic
  nonnegative integer; public failures carry only closed UPPER_SNAKE
  reasons and never a counter key or client address.
- Concurrent upload of the same (job, image index) stores exactly once;
  reservation denial is atomic and release is idempotent.

No production source, dependency, lock, provider client, credential, or
network traffic is touched by this module; no BLIND path is referenced.
"""

from __future__ import annotations

import importlib
import os
import re
import secrets
import stat as stat_module
from collections.abc import AsyncIterator
from contextlib import suppress
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

QUARANTINE_MODULE = "itda.photo.quarantine"
RATELIMIT_MODULE = "itda.photo.ratelimit"
MIIB = 1024 * 1024
CHUNK_BYTES = b"phase6-abuse-synthetic-bytes-" * 2


def _phase6_owner(module_name: str) -> ModuleType:
    """Import one planned Phase 6 abuse-control owner or fail controlled RED."""

    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        pytest.fail(
            "controlled RED: planned Phase 6 quarantine/ratelimit owner is absent: "
            f"{module_name} ({error}). Implement the Plan 06-05 owners before this "
            "contract can proceed.",
            pytrace=False,
        )


def _require(condition: object, message: str) -> None:
    if not condition:
        pytest.fail(f"phase6 abuse-control contract violated: {message}", pytrace=False)


def _root_descriptor(root: Path) -> int:
    return os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )


def _job_entries(root: Path, job_directory: str) -> list[str]:
    try:
        return sorted(os.listdir(root / job_directory))
    except (FileNotFoundError, NotADirectoryError):
        return []


def _assert_closed_reason(error: BaseException, *, label: str) -> None:
    reason = getattr(error, "reason", None)
    _require(
        isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason) is not None,
        f"{label} must expose one closed UPPER_SNAKE reason, got {reason!r}",
    )
    rendered = f"{error!s} {error!r} {error.args!r}"
    _require(
        "phase6-abuse-synthetic-bytes" not in rendered,
        f"{label} must never reflect streamed bytes",
    )
    _require(len(rendered) <= 500, f"{label} text must remain bounded")


class _OneChunk:
    """Async chunk source yielding exactly one bounded synthetic chunk."""

    def __init__(self) -> None:
        self.consumed = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.consumed += 1
        yield CHUNK_BYTES


async def _expect_quarantine_rejection(
    module: ModuleType,
    *,
    root_fd: int,
    job_directory: str,
    image_index: int = 1,
) -> None:
    """One bounded attempt; rejection must be a fact-free QuarantineError."""

    stream = _OneChunk()
    with pytest.raises(module.QuarantineError) as captured:
        await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-quarantine-test",
            image_index=image_index,
            chunks=stream,
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )
    _assert_closed_reason(captured.value, label="quarantine rejection")


# ---------------------------------------------------------------------------
# Quarantine substitution matrix (Plan 06-05 Task 1 + OPS-05)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "job_directory",
    (
        "../escape",
        "sub/../../escape",
        "/absolute/escape",
        "nested/./dot",
        "double//slash",
        "trailing/",
        "back\\slash",
        "nul\x00byte",
        ".",
        "..",
    ),
)
async def test_traversal_components_never_escape_the_quarantine_root(
    tmp_path: Path, job_directory: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    _require(
        isinstance(getattr(module, "QuarantineError", None), type),
        "quarantine owner must expose a QuarantineError exception type",
    )
    root_fd = _root_descriptor(tmp_path)
    try:
        await _expect_quarantine_rejection(module, root_fd=root_fd, job_directory=job_directory)
    finally:
        os.close(root_fd)
    _require(
        sorted(os.listdir(tmp_path)) == [],
        "traversal attempts must create nothing at or beyond the quarantine root",
    )


@pytest.mark.asyncio
async def test_symlinked_parent_component_is_rejected(tmp_path: Path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    outside = tmp_path / "outside"
    outside.mkdir()
    link_parent = tmp_path / "link-parent"
    link_parent.symlink_to(outside)
    root_fd = _root_descriptor(tmp_path)
    try:
        await _expect_quarantine_rejection(
            module, root_fd=root_fd, job_directory="link-parent/job-entry"
        )
    finally:
        os.close(root_fd)
    _require(
        sorted(os.listdir(outside)) == [],
        "symlinked parent traversal must not land outside the quarantine root",
    )


@pytest.mark.asyncio
async def test_symlinked_job_directory_component_is_rejected(tmp_path: Path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    outside = tmp_path / "outside"
    outside.mkdir()
    job_directory = secrets.token_hex(32)
    (tmp_path / job_directory).symlink_to(outside)
    root_fd = _root_descriptor(tmp_path)
    try:
        await _expect_quarantine_rejection(module, root_fd=root_fd, job_directory=job_directory)
    finally:
        os.close(root_fd)
    _require(
        sorted(os.listdir(outside)) == [],
        "a symlinked job directory must never gain entries outside the root",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("decoy", ("fifo", "regular-file"))
async def test_non_directory_job_component_is_rejected(tmp_path: Path, decoy: str) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    planted = tmp_path / job_directory
    if decoy == "fifo":
        os.mkfifo(planted, 0o600)
    else:
        planted.write_bytes(b"not a directory")
    root_fd = _root_descriptor(tmp_path)
    try:
        await _expect_quarantine_rejection(module, root_fd=root_fd, job_directory=job_directory)
    finally:
        os.close(root_fd)


@pytest.mark.asyncio
async def test_stored_files_land_owner_safe_regular_and_singly_linked(
    tmp_path: Path,
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-quarantine-test",
            image_index=1,
            chunks=_OneChunk(),
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )
    finally:
        os.close(root_fd)
    stored_name = getattr(stored, "stored_name", None)
    _require(
        isinstance(stored_name, str) and re.fullmatch(r"[0-9a-f]{32}", stored_name),
        "stored_name must be an opaque generated 32-hex identity",
    )
    stored_path = tmp_path / job_directory / stored_name
    metadata = stored_path.stat()
    _require(
        stat_module.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid == os.geteuid()
        and stat_module.S_IMODE(metadata.st_mode) == 0o600,
        "stored files must be regular, singly linked, process-owned, and 0600",
    )
    job_mode = stat_module.S_IMODE((tmp_path / job_directory).stat().st_mode)
    _require(job_mode == 0o700, "job directories must exist exactly 0700")


@pytest.mark.parametrize("case", ("symlink", "hardlink", "fifo", "directory", "mode"))
def test_open_quarantined_image_rejects_linked_and_drifted_targets(
    tmp_path: Path, case: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-quarantine-test"
    job_root = tmp_path / job_directory
    job_root.mkdir(mode=0o700)
    (job_root / ".itda-owner-v1").write_text(f"{job_directory}\n{profile_id}\n")
    (job_root / ".itda-owner-v1").chmod(0o600)
    planted_name = "c" * 32
    regular = job_root / planted_name
    regular.write_bytes(CHUNK_BYTES)
    regular.chmod(0o600)
    if case == "symlink":
        (job_root / ("d" * 32)).symlink_to(planted_name)
        hostile_name = "d" * 32
    elif case == "hardlink":
        os.link(regular, job_root / ("e" * 32))
        hostile_name = "e" * 32
    elif case == "fifo":
        os.mkfifo(job_root / ("f" * 32), 0o600)
        hostile_name = "f" * 32
    elif case == "directory":
        (job_root / ("g" * 32)).mkdir()
        hostile_name = "g" * 32
    else:
        regular.chmod(0o620)
        hostile_name = planted_name

    opened: Any = None
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError) as captured:
            opened = module.open_quarantined_image(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                stored_name=hostile_name,
            )
    finally:
        os.close(root_fd)
    _assert_closed_reason(captured.value, label=f"open target:{case}")
    _require(
        opened is None,
        f"{case}: a rejected target must never yield an open handle",
    )


def test_post_open_substitution_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mid-write inode swap must fail the post-write identity recheck."""

    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    job_root = tmp_path / job_directory
    substituted = {"fired": False}

    root_fd = _root_descriptor(tmp_path)
    original_write = module._UPLOAD_WRITE

    def substituting_write(descriptor: int, data: bytes) -> int:
        result = original_write(descriptor, data)
        if not substituted["fired"]:
            entries = [entry for entry in job_root.iterdir() if entry.name != ".itda-owner-v1"]
            if entries:
                substituted["fired"] = True
                stored = entries[0]
                stored.unlink()
                stored.write_bytes(b"substituted-payload")
                stored.chmod(0o600)
        return result

    monkeypatch.setattr(module, "_UPLOAD_WRITE", substituting_write)
    try:
        with pytest.raises(module.QuarantineError) as captured:
            asyncio_run_store(module, root_fd=root_fd, job_directory=job_directory)
    finally:
        os.close(root_fd)
    _require(substituted["fired"], "the substitution fixture must fire mid-write")
    _assert_closed_reason(captured.value, label="post-open substitution")


def asyncio_run_store(module: ModuleType, *, root_fd: int, job_directory: str) -> None:
    """Drive the async store to completion inside a sync substitution test."""

    import anyio

    async def _store() -> None:
        await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-quarantine-test",
            image_index=1,
            chunks=_OneChunk(),
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )

    anyio.run(_store)


@pytest.mark.asyncio
async def test_fsync_ordering_durability_precedes_directory_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    fsync_kinds: list[str] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        kind = "dir" if stat_module.S_ISDIR(metadata.st_mode) else "file"
        fsync_kinds.append(kind)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    owner_fsync = getattr(module, "fsync", None)
    if owner_fsync is not None:
        monkeypatch.setattr(module, "fsync", recording_fsync)
    root_fd = _root_descriptor(tmp_path)
    try:
        await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-quarantine-test",
            image_index=1,
            chunks=_OneChunk(),
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )
    finally:
        os.close(root_fd)
    _require(
        "file" in fsync_kinds,
        "the stored file must be fsynced before the write completes",
    )
    _require(
        "dir" in fsync_kinds,
        "the parent job directory must be fsynced to publish the entry",
    )
    _require(
        fsync_kinds.index("file") < fsync_kinds.index("dir"),
        "file durability must be ordered before the directory publish fsync",
    )


@pytest.mark.asyncio
async def test_partial_write_rejection_is_idempotent(tmp_path: Path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    # Hostile traversal job names are rejected before creation, so repeated
    # attempts converge without relying on a shortened-identity cleanup API.
    job_directory = "../escape-idempotent"
    root_fd = _root_descriptor(tmp_path)
    try:
        await _expect_quarantine_rejection(module, root_fd=root_fd, job_directory=job_directory)
        await _expect_quarantine_rejection(module, root_fd=root_fd, job_directory=job_directory)
    finally:
        os.close(root_fd)
    _require(
        _job_entries(tmp_path, job_directory) == [],
        "repeated hostile attempts and cleanup must converge to zero residue",
    )


@pytest.mark.asyncio
async def test_quarantine_results_never_expose_private_paths(tmp_path: Path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-quarantine-test",
            image_index=1,
            chunks=_OneChunk(),
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )
        stored_name = getattr(stored, "stored_name", "")
        _require(
            "/" not in stored_name and "\\" not in stored_name and ".." not in stored_name,
            "stored_name must never carry path material",
        )
        _require(
            not hasattr(stored, "path") and not hasattr(stored, "file_path"),
            "the quarantine result must never expose a private filesystem path",
        )
        rendered = repr(stored)
        _require(
            str(tmp_path) not in rendered,
            "quarantine results must never render the private root path",
        )
        if hasattr(module, "open_quarantined_image"):
            opened = module.open_quarantined_image(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-quarantine-test",
                stored_name=stored_name,
            )
            _require(
                str(tmp_path) not in repr(opened),
                "opened quarantine handles must never render the private root path",
            )
    finally:
        os.close(root_fd)


@pytest.mark.asyncio
async def test_same_index_upload_stores_exactly_once(tmp_path: Path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    policy = module.QuarantinePolicy()
    outcomes: list[str] = []
    try:
        for _ in range(2):
            try:
                await module.stream_to_quarantine(
                    root_fd=root_fd,
                    job_directory=job_directory,
                    profile_id="profile-quarantine-test",
                    image_index=1,
                    chunks=_OneChunk(),
                    policy=policy,
                    binding_claim_created=True,
                )
                outcomes.append("stored")
            except module.QuarantineError as error:
                outcomes.append(f"rejected:{getattr(error, 'reason', '')}")
    finally:
        os.close(root_fd)
    _require(
        outcomes.count("stored") == 1,
        f"exactly one same-index upload may store; got {outcomes}",
    )


# ---------------------------------------------------------------------------
# Rate and resource abuse matrix (Plan 06-05 Task 3 + OPS-05)
# ---------------------------------------------------------------------------


class _FakeClock:
    """Injected monotonic clock with deterministic advance."""

    def __init__(self) -> None:
        self.now_seconds = 1_000_000.0
        self.reads = 0

    def monotonic(self) -> float:
        self.reads += 1
        return self.now_seconds

    def advance(self, seconds: float) -> None:
        self.now_seconds += seconds


def _identity_suffix(index: int) -> str:
    return f"session-opaque-{index}|203.0.113.{index}"


def _acquire(limiter: Any, *, action: str, identity: str, clock: _FakeClock) -> None:
    try:
        limiter.acquire(action=action, identity=identity, now=clock.monotonic())
    except Exception as error:
        reason = getattr(error, "reason", None)
        _require(
            isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason) is not None,
            "rate rejections must expose a closed UPPER_SNAKE reason",
        )
        retry_after = getattr(error, "retry_after_seconds", None)
        _require(
            isinstance(retry_after, int) and retry_after >= 0,
            "retry-after must be a deterministic nonnegative integer",
        )
        rendered = f"{error!s} {error!r} {error.args!r}"
        _require(
            identity not in rendered and "203.0.113" not in rendered,
            "rate failures must never disclose the counter key or client address",
        )
        raise


def test_rate_limit_policy_freezes_conservative_windows() -> None:
    module = _phase6_owner(RATELIMIT_MODULE)
    policy = module.PhotoRateLimitPolicy()
    _require(
        getattr(policy, "job_creates_per_minute", None) == 6,
        "job creation window must freeze at 6/minute",
    )
    _require(
        getattr(policy, "image_puts_per_minute", None) == 18,
        "image PUT window must freeze at 18/minute",
    )
    _require(
        getattr(policy, "polls_per_minute", None) == 60,
        "polling window must freeze at 60/minute",
    )
    try:
        policy.job_creates_per_minute = 1_000  # type: ignore[misc]
    except Exception:
        return
    pytest.fail(
        "phase6 abuse-control contract violated: the rate policy must be frozen",
        pytrace=False,
    )


def test_fixed_window_session_ip_limits_bound_every_action() -> None:
    module = _phase6_owner(RATELIMIT_MODULE)
    policy = module.PhotoRateLimitPolicy()
    clock = _FakeClock()
    limiter = module.PhotoRateLimiter(policy=policy, clock=clock.monotonic)
    identity = _identity_suffix(1)
    limits = {
        "job_create": policy.job_creates_per_minute,
        "image_put": policy.image_puts_per_minute,
        "poll": policy.polls_per_minute,
    }
    for action, bound in limits.items():
        for _ in range(bound):
            _acquire(limiter, action=action, identity=identity, clock=clock)
        with pytest.raises(Exception) as over_boundary:
            _acquire(limiter, action=action, identity=identity, clock=clock)
        reason = getattr(over_boundary.value, "reason", None)
        _require(
            isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason) is not None,
            f"{action}: over-bound rejection must carry a closed reason",
        )
        clock.advance(60.0)
        _acquire(limiter, action=action, identity=identity, clock=clock)


def test_identity_keys_are_independent_and_polling_is_separately_bounded() -> None:
    module = _phase6_owner(RATELIMIT_MODULE)
    policy = module.PhotoRateLimitPolicy()
    clock = _FakeClock()
    limiter = module.PhotoRateLimiter(policy=policy, clock=clock.monotonic)
    first = _identity_suffix(1)
    second = _identity_suffix(2)
    accepted = 0
    for _ in range(policy.polls_per_minute * 2):
        try:
            limiter.acquire(action="poll", identity=first, now=clock.monotonic())
            accepted += 1
        except Exception:
            break
    _require(
        accepted == policy.polls_per_minute,
        "polling beyond the frozen window bound must be rejected",
    )
    _acquire(limiter, action="poll", identity=second, clock=clock)


def test_injected_clock_drives_every_window_decision() -> None:
    module = _phase6_owner(RATELIMIT_MODULE)
    policy = module.PhotoRateLimitPolicy()
    clock = _FakeClock()
    limiter = module.PhotoRateLimiter(policy=policy, clock=clock.monotonic)
    identity = _identity_suffix(3)
    reads_before = clock.reads
    _acquire(limiter, action="poll", identity=identity, clock=clock)
    _require(
        clock.reads > reads_before,
        "the limiter must consult the injected clock for every decision",
    )


def test_resource_budget_freezes_concurrency_and_quarantine_bytes() -> None:
    module = _phase6_owner(RATELIMIT_MODULE)
    budget = module.PhotoResourceBudget()
    _require(
        getattr(budget, "max_concurrent_jobs", None) == 4,
        "the running-job cap must freeze at 4 concurrent jobs",
    )
    _require(
        getattr(budget, "max_total_quarantine_bytes", None) == 80 * MIIB,
        "total quarantine reservation must freeze at 80 MiB",
    )
    try:
        budget.max_concurrent_jobs = 100  # type: ignore[misc]
    except Exception:
        return
    pytest.fail(
        "phase6 abuse-control contract violated: the resource budget must be frozen",
        pytrace=False,
    )


def test_running_job_cap_and_quarantine_reservation_are_atomic() -> None:
    module = _phase6_owner(RATELIMIT_MODULE)
    budget = module.PhotoResourceBudget()
    clock = _FakeClock()
    reservations: list[Any] = []
    try:
        for index in range(budget.max_concurrent_jobs):
            reservations.append(
                budget.reserve_job(identity=_identity_suffix(index), now=clock.monotonic())
            )
        with pytest.raises(Exception) as denied:
            budget.reserve_job(identity=_identity_suffix(99), now=clock.monotonic())
        reason = getattr(denied.value, "reason", None)
        _require(
            isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason) is not None,
            "running-job denials must expose closed UPPER_SNAKE reasons",
        )
        for reservation in reservations:
            budget.release(reservation)
        reservations.clear()
        reservations.append(
            budget.reserve_job(identity=_identity_suffix(50), now=clock.monotonic())
        )
    finally:
        for reservation in reservations:
            with suppress(Exception):
                budget.release(reservation)

    byte_budget = budget.max_total_quarantine_bytes
    byte_reservations: list[Any] = []
    reserved_bytes = 0
    try:
        while reserved_bytes < byte_budget:
            chunk = min(MIIB, byte_budget - reserved_bytes)
            byte_reservations.append(budget.reserve_bytes(chunk))
            reserved_bytes += chunk
        with pytest.raises(Exception) as byte_denied:
            budget.reserve_bytes(1)
        byte_reason = getattr(byte_denied.value, "reason", None)
        _require(
            isinstance(byte_reason, str)
            and re.fullmatch(r"[A-Z][A-Z0-9_]*", byte_reason) is not None,
            "quarantine-byte denials must expose closed UPPER_SNAKE reasons",
        )
    finally:
        for reservation in byte_reservations:
            with suppress(Exception):
                budget.release(reservation)
    retry = budget.reserve_bytes(1)
    budget.release(retry)
    budget.release(retry)
