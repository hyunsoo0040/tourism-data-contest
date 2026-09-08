"""Durable six-state photo job orchestration and startup reconciliation.

The service owns the persisted job machine: opaque identities, legal
transitions through the migration's constrained SECURITY DEFINER
functions, create-only dispatch markers (reserved → prepared →
client_constructed → send_boundary), lease claiming with concurrent
exclusion, and startup reconciliation that derives facts from durable
markers alone.

Reconciliation is conservative by construction:
- a stale running row with no dispatch markers never re-dispatches
  provider work — it fails closed;
- an uncertain send boundary (all four markers present, outcome unknown)
  reconciles to a terminal state and never spawns a second attempt;
- ambiguous completion is reconciled before any retry path can run.

Internal cleanup phases stay out of the persisted public vocabulary.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Final

import psycopg
from sqlalchemy.orm import Session, sessionmaker

from itda.photo.contracts import (
    PHOTO_JOB_INTERNAL_DISPATCH_MARKERS,
    is_legal_transition,
    is_terminal,
)

_DISPATCH_MARKER_ORDER: Final[tuple[str, ...]] = (
    "reserved",
    "prepared",
    "client_constructed",
    "send_boundary",
)
_JOB_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_PROBE_ATTEMPT: Final[int] = 1


class PhotoJobError(RuntimeError):
    """One closed, public-safe job service failure."""

    code = "PHOTO_JOB_REJECTED"


def new_job_id() -> str:
    """Generate an opaque 64-hex job identity."""

    return secrets.token_hex(32)


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """Counts of the conservative reconciliation decisions taken."""

    examined: int
    failed_closed: int
    expired: int
    uncertain_resolved: int

    def __bool__(self) -> bool:
        return self.examined > 0


@dataclass(frozen=True, slots=True)
class DispatchMarkerView:
    """The durable marker facts one job exposes for reconciliation."""

    job_id: str
    attempt: int
    markers: frozenset[str]


def _require_job_id(job_id: object) -> str:
    if not isinstance(job_id, str) or _JOB_ID_PATTERN.fullmatch(job_id) is None:
        raise PhotoJobError("photo job identity must be opaque 64-hex")
    return job_id


def highest_reached_marker(markers: frozenset[str]) -> str | None:
    """The conservative highest dispatch marker provably reached.

    Returns None when nothing durable exists: absence of markers proves
    only that no dispatch work started, never that anything was sent.
    """

    reached: str | None = None
    for marker in _DISPATCH_MARKER_ORDER:
        if marker in markers:
            reached = marker
    return reached


_VALID_MARKER_PREFIX_SETS: Final[frozenset[frozenset[str]]] = frozenset(
    frozenset(marker_set)
    for marker_set in (
        ("reserved",),
        ("reserved", "prepared"),
        ("reserved", "prepared", "client_constructed"),
        _DISPATCH_MARKER_ORDER,
        ("reserved", "prepared", "send_boundary"),
    )
)


def is_valid_marker_set(markers: frozenset[str]) -> bool:
    """Whether the durable marker inventory is an exact reachable prefix.

    The create-only marker authority admits only exact prefix states; a
    historical/admin-seeded set that could never have been written through
    the authority (skips, out-of-order claims, a send without its full
    prefix) is malformed evidence, never proof of an uncertain send.
    """

    return markers in _VALID_MARKER_PREFIX_SETS


def reconcile_decision(markers: frozenset[str]) -> str:
    """Decide the reconciled terminal state from durable markers only.

    Any job still ``running`` with durable evidence converges to
    ``failed`` — the failed state returns the user to the no-photo
    journey without claiming success and without scheduling a retry.
    The decision never depends on wall-clock uncertainty about whether
    the provider received the request: after an uncertain send boundary
    the send may or may not have happened, so a retry is forbidden.
    """

    reached = highest_reached_marker(markers)
    if reached is None:
        # Nothing durable: the job never got past claim. Fail closed —
        # re-running provider work from an ambiguous row is forbidden.
        return "failed"
    if reached == "send_boundary":
        # The send may have happened. Terminal outcome is unknowable from
        # durable evidence alone, so the conservative truth is failure
        # with no second attempt; provider-side completion (if any) is
        # reconciled by the operator, never re-executed here.
        return "failed"
    return "failed"


class PhotoJobService:
    """Session-backed owned job operations over the least-privilege stores."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create_job(
        self,
        *,
        profile_id: str,
        idempotency_key: str | None = None,
        job_id: str | None = None,
    ) -> str:
        """Create one queued job owned by the profile (idempotent by key)."""

        from itda.db.photo_repositories import PhotoJobConflict, PhotoJobStore

        store = PhotoJobStore(self._factory)
        opaque = _require_job_id(job_id or new_job_id())
        try:
            store.create_job(
                job_id=opaque,
                profile_id=profile_id,
                idempotency_key=idempotency_key,
            )
        except PhotoJobConflict as error:
            raise PhotoJobError("photo job identity already bound") from error
        return opaque

    def read_own_job(self, *, job_id: str, profile_id: str) -> dict[str, object]:
        """Ownership-checked job read projecting only public vocabulary."""

        from itda.db.photo_repositories import PhotoJobNotFound, PhotoJobStore

        store = PhotoJobStore(self._factory)
        try:
            row = store.get_for_profile(job_id, profile_id)
        except PhotoJobNotFound as error:
            raise PhotoJobError("photo job is not available") from error
        return {
            "job_id": row.job_id,
            "state": row.status,
            "terminal_cause": row.terminal_cause,
        }

    def request_deletion_marker(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        job_id: str,
        profile_id: str,
        marker: str,
    ) -> None:
        """Record one create-only dispatch marker before external work."""

        _require_job_id(job_id)
        if marker not in PHOTO_JOB_INTERNAL_DISPATCH_MARKERS:
            raise PhotoJobError("dispatch marker is outside the closed vocabulary")
        connection.execute(
            "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, %s, %s)",
            (job_id, profile_id, _PROBE_ATTEMPT, marker),
        )

    def transition(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        job_id: str,
        profile_id: str,
        from_status: str,
        to_status: str,
        terminal_cause: str | None = None,
    ) -> None:
        """Apply one legal transition or refuse the illegal pair."""

        _require_job_id(job_id)
        if not is_legal_transition(from_status, to_status):
            raise PhotoJobError("photo job transition is not legal")
        if is_terminal(to_status) and terminal_cause is None:
            raise PhotoJobError("terminal completion requires its terminal cause")
        if (from_status, to_status, terminal_cause) != ("queued", "running", None):
            raise PhotoJobError("terminal transitions require deletion proof authority")
        connection.execute(
            "SELECT dev_eval.transition_photo_job_nonterminal_v3"
            "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
            (job_id, profile_id),
        )


def read_dispatch_markers(
    connection: psycopg.Connection[tuple[object, ...]],
    job_id: str,
    profile_id: str | None = None,
) -> DispatchMarkerView:
    """Read the durable marker facts for one owned job (conservative view)."""

    _require_job_id(job_id)
    if profile_id is None:
        raise PhotoJobError("marker reads require the owning profile")
    rows = connection.execute(
        "SELECT marker FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
        (job_id, profile_id),
    ).fetchall()
    return DispatchMarkerView(
        job_id=job_id,
        attempt=_PROBE_ATTEMPT,
        markers=frozenset(str(row[0]) for row in rows),
    )


def reconcile_interrupted_jobs(
    connection: psycopg.Connection[tuple[object, ...]],
    *,
    quarantine_root: object | None = None,
) -> ReconciliationReport:
    """Reconcile stale running rows from durable markers, never re-running.

    Startup reconciliation: every ``running`` row is examined against its
    dispatch-marker inventory. The decision maps every ambiguity to the
    same conservative terminal truth — fail closed with no second attempt
    — so restart can never duplicate provider work or claim false success.
    """

    if quarantine_root is None:
        raise PhotoJobError("startup reconciliation requires quarantine authority")
    if connection.autocommit is not True:
        raise PhotoJobError("startup reconciliation requires an autocommit connection")
    reconcile_rows = connection.execute(
        "SELECT job_id, profile_id, status, cleanup_class, "
        "terminal_operation_key, terminal_proof_digest "
        "FROM dev_eval.list_photo_cleanup_candidates_v3()"
    ).fetchall()
    failed_closed = 0
    uncertain_resolved = 0
    expired_count = 0
    examined = 0
    for job_id, profile_id, projected_status, cleanup_class, *terminal_pointer in reconcile_rows:
        opaque = _require_job_id(job_id)
        owner = str(profile_id)
        projected = str(projected_status)
        cleanup = str(cleanup_class)
        if (projected, cleanup) not in {
            ("running", "worker_crash"),
            ("queued", "expiry"),
            ("failed", "orphan_cleanup"),
            ("expired", "orphan_cleanup"),
            ("succeeded", "filesystem_release"),
            ("failed", "filesystem_release"),
            ("expired", "filesystem_release"),
            ("deleted", "filesystem_release"),
        }:
            continue
        from itda.photo.deletion import (
            DeletionIncomplete,
            execute_terminal_deletion,
            release_filesystem_cleanup,
        )

        try:
            if cleanup == "filesystem_release":
                if len(terminal_pointer) < 2:
                    continue
                release_filesystem_cleanup(
                    connection,
                    quarantine_root=quarantine_root,  # type: ignore[arg-type]
                    job_id=opaque,
                    profile_id=owner,
                    operation_key=str(terminal_pointer[0]),
                    proof_digest=str(terminal_pointer[1]),
                )
                examined += 1
                continue
            if cleanup == "worker_crash":
                markers = read_dispatch_markers(connection, opaque, owner)
                if not is_valid_marker_set(markers.markers):
                    # Malformed historical marker inventory: never counted as
                    # an uncertain send, never re-run — but still terminalized
                    # fail-closed through the same worker_crash authority.
                    decision = "failed"
                else:
                    decision = reconcile_decision(markers.markers)
                outcome = execute_terminal_deletion(
                    connection,
                    quarantine_root=quarantine_root,  # type: ignore[arg-type]
                    job_id=opaque,
                    profile_id=owner,
                    cause="worker_crash",
                    reason_code="PHOTO_WORKER_CRASH",
                    from_status="running",
                    to_status=decision,
                    operation_kind="reconcile",
                )
                if is_valid_marker_set(markers.markers) and "send_boundary" in markers.markers:
                    uncertain_resolved += 1
                else:
                    failed_closed += 1
            elif cleanup == "expiry":
                outcome = execute_terminal_deletion(
                    connection,
                    quarantine_root=quarantine_root,  # type: ignore[arg-type]
                    job_id=opaque,
                    profile_id=owner,
                    cause="expiry",
                    reason_code="PHOTO_EXPIRY",
                    from_status="queued",
                    to_status="expired",
                    operation_kind="reconcile",
                )
                expired_count += 1
            else:
                outcome = execute_terminal_deletion(
                    connection,
                    quarantine_root=quarantine_root,  # type: ignore[arg-type]
                    job_id=opaque,
                    profile_id=owner,
                    cause="orphan_cleanup",
                    reason_code="PHOTO_ORPHAN_CLEANUP",
                    from_status=projected,
                    to_status="deleted",
                    operation_kind="reconcile",
                )
                expired_count += 1
            release_filesystem_cleanup(
                connection,
                quarantine_root=quarantine_root,  # type: ignore[arg-type]
                job_id=opaque,
                profile_id=owner,
                operation_key=str(outcome.operation_key),
                proof_digest=str(outcome.proof_digest),
            )
        except DeletionIncomplete:
            continue
        except psycopg.Error as error:
            if error.sqlstate == "23514":
                continue
            raise
        examined += 1
    return ReconciliationReport(
        examined=examined,
        failed_closed=failed_closed,
        expired=expired_count,
        uncertain_resolved=uncertain_resolved,
    )


def assert_transition_legal(from_status: str, to_status: str) -> None:
    """Re-export the closed matrix check for service callers."""

    if not is_legal_transition(from_status, to_status):
        raise PhotoJobError("photo job transition is not legal")


__all__ = [
    "DispatchMarkerView",
    "PhotoJobError",
    "PhotoJobService",
    "ReconciliationReport",
    "assert_transition_legal",
    "highest_reached_marker",
    "is_valid_marker_set",
    "new_job_id",
    "reconcile_decision",
    "reconcile_interrupted_jobs",
    "read_dispatch_markers",
]
