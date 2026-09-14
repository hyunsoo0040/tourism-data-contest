"""Process-shared local GLM session ceiling used by live provider adapters.

All workers on one host share advisory file locks. Multi-host deployments must
mount the same lock directory with flock support or partition the 40-slot budget
across instances; the local mechanism does not claim distributed coordination.
"""

from __future__ import annotations

import fcntl
import os
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

MAX_MODEL_SESSIONS = 40


class ModelSessionCapacityUnavailable(RuntimeError):
    pass


@contextmanager
def model_session(
    *, directory: Path | None = None, limit: int | None = None, timeout_seconds: float = 30.0
) -> Iterator[None]:
    ceiling = limit if limit is not None else int(os.environ.get("ITDA_MODEL_SESSION_LIMIT", "40"))
    if type(ceiling) is not int or not 1 <= ceiling <= MAX_MODEL_SESSIONS:
        raise ValueError("model session ceiling must be between 1 and 40")
    if not 0 < timeout_seconds <= 300:
        raise ValueError("model session wait must be finite and at most 300 seconds")
    root = directory or Path(
        os.environ.get(
            "ITDA_MODEL_SESSION_LOCK_DIR",
            str(Path(tempfile.gettempdir()) / f"itda-glm-sessions-{os.getuid()}"),
        )
    )
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        raise ValueError("model session lock directory must be owned by this process user")
    deadline = time.monotonic() + timeout_seconds
    handle: int | None = None
    while handle is None:
        for slot in range(ceiling):
            fd = os.open(
                root / f"session-{slot}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                continue
            handle = fd
            break
        if handle is None:
            if time.monotonic() >= deadline:
                raise ModelSessionCapacityUnavailable("MODEL_SESSION_CAPACITY_UNAVAILABLE")
            time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))
    try:
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)
