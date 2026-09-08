"""In-process fixed-window and resource-budget abuse controls for Phase 6.

The limiter bounds job creation, image uploads, and polling with per-identity
fixed windows on an injected monotonic clock; the resource budget bounds the
running-job count and the total quarantined-byte reservation atomically.
Request-rate counters are process-local and reset at restart — a documented
limitation that is scoped by single-process deployment, while durable job and
quarantine enforcement remain authoritative. Failures carry only closed
UPPER_SNAKE reasons and never disclose a counter key or client address.
"""

from __future__ import annotations

import dataclasses
import threading
from dataclasses import dataclass, field
from typing import Final

_MIB: Final[int] = 1024 * 1024


class PhotoRateLimitError(Exception):
    """One closed reason for a rejected request-rate acquisition."""

    def __init__(self, reason: str, retry_after_seconds: int) -> None:
        self.reason = reason
        self.retry_after_seconds = retry_after_seconds
        super().__init__(reason)


class PhotoResourceBudgetError(Exception):
    """One closed reason for a rejected resource reservation."""

    def __init__(self, reason: str, retry_after_seconds: int = 0) -> None:
        self.reason = reason
        self.retry_after_seconds = retry_after_seconds
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class PhotoRateLimitPolicy:
    """Frozen per-minute request-window bounds; single-process scope."""

    job_creates_per_minute: int = 6
    image_puts_per_minute: int = 18
    polls_per_minute: int = 60

    def __post_init__(self) -> None:
        for value in (
            self.job_creates_per_minute,
            self.image_puts_per_minute,
            self.polls_per_minute,
        ):
            if type(value) is not int or value <= 0:
                raise ValueError("rate window bounds must be positive integers")


@dataclass(frozen=True)
class PhotoResourceBudget:
    """Frozen process-wide concurrency and quarantine-byte ceilings.

    Reservations are atomic under the budget's lock; release is idempotent.
    The budget instance carries the live reservation state, so each photo
    process constructs exactly one shared budget.
    """

    max_concurrent_jobs: int = 4
    max_total_quarantine_bytes: int = 80 * _MIB
    _lock: threading.Lock = dataclasses.field(
        default_factory=threading.Lock, repr=False, compare=False
    )
    _running_jobs: int = dataclasses.field(default=0, repr=False, compare=False)
    _reserved_bytes: int = dataclasses.field(default=0, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.max_concurrent_jobs) is not int or self.max_concurrent_jobs <= 0:
            raise ValueError("concurrent job bound must be a positive integer")
        if (
            type(self.max_total_quarantine_bytes) is not int
            or self.max_total_quarantine_bytes <= 0
        ):
            raise ValueError("quarantine byte bound must be a positive integer")

    def reserve_job(self, *, identity: str, now: float) -> JobReservation:
        """Atomically reserve one running-job slot or fail closed."""

        del now  # the clock argument keeps the surface uniform with the limiter
        if not isinstance(identity, str):
            raise PhotoResourceBudgetError("PHOTO_RESERVATION_IDENTITY_INVALID")
        with self._lock:
            if self._running_jobs >= self.max_concurrent_jobs:
                raise PhotoResourceBudgetError("PHOTO_CONCURRENCY_LIMIT")
            object.__setattr__(self, "_running_jobs", self._running_jobs + 1)
            return JobReservation(identity_digest=str(len(identity)))

    def reserve_bytes(self, amount: int) -> BytesReservation:
        """Atomically reserve quarantine bytes or fail closed."""

        if type(amount) is not int or amount <= 0:
            raise PhotoResourceBudgetError("PHOTO_QUARANTINE_BYTES_INVALID")
        with self._lock:
            if self._reserved_bytes + amount > self.max_total_quarantine_bytes:
                raise PhotoResourceBudgetError("PHOTO_QUARANTINE_BYTES_EXHAUSTED")
            object.__setattr__(
                self, "_reserved_bytes", self._reserved_bytes + amount
            )
            return BytesReservation(reserved_bytes=amount)

    def release(self, reservation: JobReservation | BytesReservation) -> None:
        """Idempotently return one reservation to the shared budget."""

        with self._lock:
            if isinstance(reservation, JobReservation):
                if reservation.released or self._running_jobs <= 0:
                    return
                object.__setattr__(self, "_running_jobs", self._running_jobs - 1)
                object.__setattr__(reservation, "released", True)
            elif isinstance(reservation, BytesReservation):
                if (
                    reservation.released
                    or self._reserved_bytes < reservation.reserved_bytes
                ):
                    return
                object.__setattr__(
                    self,
                    "_reserved_bytes",
                    self._reserved_bytes - reservation.reserved_bytes,
                )
                object.__setattr__(reservation, "released", True)


@dataclass
class _WindowCounter:
    window_start: float
    count: int


@dataclass(frozen=True)
class JobReservation:
    """Opaque running-job reservation token; release is idempotent."""

    identity_digest: str = field(repr=False)
    released: bool = field(default=False, repr=False)


@dataclass(frozen=True)
class BytesReservation:
    """Opaque quarantine-byte reservation token; release is idempotent."""

    reserved_bytes: int = field(repr=False)
    released: bool = field(default=False, repr=False)


class PhotoRateLimiter:
    """Fixed-window per-identity request limiter on an injected monotonic clock.

    Note: counters are process-local and reset when the process restarts.
    Durable job/quarantine limits remain the authoritative boundaries.
    """

    _WINDOW_SECONDS: Final[int] = 60
    _ACTION_BOUNDS: Final[dict[str, str]] = {
        "job_create": "job_creates_per_minute",
        "image_put": "image_puts_per_minute",
        "poll": "polls_per_minute",
    }

    def __init__(self, *, policy: PhotoRateLimitPolicy, clock: object) -> None:
        if not callable(clock):
            raise ValueError("an injected monotonic clock callable is required")
        self._policy = policy
        self._clock = clock
        self._counters: dict[tuple[str, str], _WindowCounter] = {}
        self._lock = threading.Lock()

    def acquire(self, *, action: str, identity: str, now: float) -> None:
        bound_attribute = self._ACTION_BOUNDS.get(action)
        if bound_attribute is None:
            raise PhotoRateLimitError("PHOTO_RATE_ACTION_UNKNOWN", self._WINDOW_SECONDS)
        bound = getattr(self._policy, bound_attribute)
        with self._lock:
            used = now if now is not None else self._clock()
            counter = self._counters.get((action, identity))
            if counter is None or used - counter.window_start >= self._WINDOW_SECONDS:
                self._counters[(action, identity)] = _WindowCounter(
                    window_start=used, count=1
                )
                return
            if counter.count >= bound:
                retry_after = int(self._WINDOW_SECONDS - (used - counter.window_start))
                retry_after = max(0, retry_after) + 1
                raise PhotoRateLimitError(
                    "PHOTO_RATE_LIMITED",
                    min(retry_after, self._WINDOW_SECONDS),
                )
            counter.count += 1


__all__ = [
    "BytesReservation",
    "JobReservation",
    "PhotoRateLimitError",
    "PhotoRateLimitPolicy",
    "PhotoRateLimiter",
    "PhotoResourceBudget",
    "PhotoResourceBudgetError",
]
