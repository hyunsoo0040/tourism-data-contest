"""Least-privilege persistence for daily GLM refreshes and release overlays."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from threading import Lock
from typing import NoReturn
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import RowMapping, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_MEMBERSHIP_SHA256,
    DailyCollectionFailure,
    DailyCollectionFailureProjection,
    DailyExcludedPlaceProjection,
    DailyGlmAttemptProjection,
    DailyIncrementalScoringPlanV2,
    DailyRecollectionCommandProjection,
    DailyRecollectionEligibility,
    DailyRefreshExecutionProjection,
    DailyRefreshRunStatus,
    DailyScoredRelease,
    DailyScoringInputSnapshotV2,
    DailySnapshot,
    MvpScoredReleaseV2,
    MvpScoredReleaseV3,
    parse_daily_scored_release,
    parse_daily_snapshot,
)
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.mvp_place_scoring import ScoringAttemptEvent


class DailyRefreshStoreError(RuntimeError):
    code = "DAILY_REFRESH_STORE_REJECTED"


class DailyReleasePayloadInvalid(DailyRefreshStoreError):
    code = "DAILY_RELEASE_PAYLOAD_INVALID"


class DailyRefreshConflict(DailyRefreshStoreError):
    code = "DAILY_REFRESH_CONFLICT"


@dataclass(frozen=True, slots=True)
class DailyRefreshStatusRecord:
    run_date: date
    status: DailyRefreshRunStatus
    changed_count: int
    failed_count: int
    call_count: int
    active_release_sha256: str | None
    safe_reason: str | None


@dataclass(frozen=True, slots=True)
class DailyOperationsOverviewRecord:
    execution: DailyRefreshExecutionProjection | None
    active_release_sha256: str | None
    recollection: DailyRecollectionEligibility
    pending_command_id: str | None


@dataclass(frozen=True, slots=True)
class DailyExecutionDetailRecord:
    execution: DailyRefreshExecutionProjection
    collection_failures: tuple[DailyCollectionFailureProjection, ...]
    attempts: tuple[DailyGlmAttemptProjection, ...]
    excluded: tuple[DailyExcludedPlaceProjection, ...] | None = None


def _raise_closed(error: SQLAlchemyError) -> NoReturn:
    sqlstate = getattr(getattr(error, "orig", None), "sqlstate", None)
    if sqlstate in {"23505", "23514", "42501"}:
        raise DailyRefreshConflict("daily refresh operation rejected") from None
    raise DailyRefreshStoreError("daily refresh store unavailable") from None


def _json_text(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _uuid4(value: str) -> UUID:
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("command ID must be canonical UUIDv4")
    return parsed


def _execution_projection(row: RowMapping) -> DailyRefreshExecutionProjection:
    try:
        values = dict(row)
        availability = values.pop("availability", None)
        if availability is not None:
            values.update(availability)
        return DailyRefreshExecutionProjection.model_validate(
            {
                "run_date": values["run_date"],
                "execution_sequence": values["execution_sequence"],
                "kind": values["kind"],
                "command_id": (
                    str(values["command_id"]) if values["command_id"] is not None else None
                ),
                "status": values["status"],
                "changed_count": values["changed_count"],
                "failed_count": values["failed_count"],
                "call_count": values["call_count"],
                "active_release_sha256": values["active_release_sha256"],
                "safe_reason": values["safe_reason"],
                "started_at": values["started_at"],
                "updated_at": values["updated_at"],
                "finished_at": values["finished_at"],
                **{
                    key: values.get(key)
                    for key in (
                        "authority_sha256",
                        "snapshot_sha256",
                        "available_count",
                        "information_unavailable_count",
                        "event_ended_count",
                    )
                },
            }
        )
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise DailyRefreshStoreError("daily execution projection invalid") from error


def _command_projection(
    row: RowMapping | None,
) -> DailyRecollectionCommandProjection | None:
    if row is None:
        return None
    try:
        values = row
        return DailyRecollectionCommandProjection.model_validate(
            {
                "command_id": str(values["command_id"]),
                "run_date": values["run_date"],
                "idempotency_key": values["idempotency_key"],
                "status": values["status"],
                "execution_sequence": values["execution_sequence"],
                "safe_reason": values["safe_reason"],
                "requested_at": values["requested_at"],
                "claimed_at": values["claimed_at"],
                "lease_expires_at": values["lease_expires_at"],
                "finished_at": values["finished_at"],
            }
        )
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        raise DailyRefreshStoreError("daily command projection invalid") from error


class DailyRefreshStore:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def claim(self, *, run_date: date, authority_sha256: str) -> bool:
        try:
            with self._factory.begin() as session:
                return bool(
                    session.execute(
                        text(
                            "SELECT dev_eval.claim_daily_glm_refresh_v2("
                            ":run_date,:authority_sha256)"
                        ),
                        {
                            "run_date": run_date,
                            "authority_sha256": authority_sha256,
                        },
                    ).scalar_one()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def store_snapshot(self, snapshot: DailyScoringInputSnapshotV2) -> None:
        validated = DailyScoringInputSnapshotV2.model_validate(snapshot.model_dump(mode="json"))
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.store_daily_glm_snapshot_v2("
                        ":run_date,:snapshot_sha256,:previous_snapshot_sha256,"
                        ":membership_sha256,CAST(:payload AS jsonb))"
                    ),
                    {
                        "run_date": validated.run_date,
                        "snapshot_sha256": validated.snapshot_sha256,
                        "previous_snapshot_sha256": validated.previous_snapshot_sha256,
                        "membership_sha256": DAILY_REFRESH_MEMBERSHIP_SHA256,
                        "payload": _json_text(validated.model_dump(mode="json")),
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def _read_snapshot(self, query: str, parameters: dict[str, str]) -> DailySnapshot | None:
        try:
            with self._factory() as session:
                payload = session.execute(text(query), parameters).scalar_one_or_none()
        except SQLAlchemyError as error:
            _raise_closed(error)
        if payload is None:
            return None
        try:
            return parse_daily_snapshot(payload)
        except (ValidationError, ValueError, TypeError) as error:
            raise DailyRefreshStoreError("daily snapshot payload invalid") from error

    def latest_snapshot(self) -> DailySnapshot | None:
        return self._read_snapshot("SELECT dev_eval.read_latest_daily_glm_snapshot_v2()", {})

    def baseline_snapshot(self) -> DailySnapshot | None:
        return self._read_snapshot("SELECT dev_eval.read_baseline_daily_glm_snapshot_v2()", {})

    def get_snapshot(self, snapshot_sha256: str) -> DailySnapshot | None:
        return self._read_snapshot(
            "SELECT dev_eval.read_daily_glm_snapshot_v2(:sha)", {"sha": snapshot_sha256}
        )

    def store_plan(self, plan: DailyIncrementalScoringPlanV2) -> None:
        validated = DailyIncrementalScoringPlanV2.model_validate(plan.model_dump(mode="json"))
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.store_daily_glm_scoring_plan_v2("
                        ":run_date,:plan_sha256,:snapshot_sha256,"
                        "CAST(:payload AS jsonb))"
                    ),
                    {
                        "run_date": validated.run_date,
                        "plan_sha256": validated.plan_sha256,
                        "snapshot_sha256": validated.snapshot_sha256,
                        "payload": _json_text(validated.model_dump(mode="json")),
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def reserve_call(
        self,
        *,
        run_date: date,
        event: ScoringAttemptEvent,
    ) -> int:
        if event.status != "STARTED" or event.reason is not None:
            raise DailyRefreshStoreError("daily reservation requires STARTED event")
        try:
            with self._factory.begin() as session:
                return int(
                    session.execute(
                        text(
                            "SELECT dev_eval.reserve_daily_glm_call_v2("
                            ":run_date,:plan_sha256,:place_id,:request_sha256,"
                            ":attempt_number)"
                        ),
                        {
                            "run_date": run_date,
                            "plan_sha256": event.run_plan_sha256,
                            "place_id": event.place_id,
                            "request_sha256": event.request_sha256,
                            "attempt_number": event.attempt_number,
                        },
                    ).scalar_one()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def finish_attempt(
        self,
        *,
        run_date: date,
        event: ScoringAttemptEvent,
        result_sha256: str | None = None,
    ) -> None:
        if event.status not in {"SUCCEEDED", "FAILED"}:
            raise DailyRefreshStoreError("daily attempt requires terminal event")
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.finish_daily_glm_attempt_v2("
                        ":run_date,:place_id,:attempt_number,:status,:reason,"
                        ":result_sha256)"
                    ),
                    {
                        "run_date": run_date,
                        "place_id": event.place_id,
                        "attempt_number": event.attempt_number,
                        "status": event.status,
                        "reason": event.reason,
                        "result_sha256": result_sha256,
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def publish(self, release: MvpScoredReleaseV3) -> None:
        validated = MvpScoredReleaseV3.model_validate(release.model_dump(mode="json"))
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.publish_daily_scored_release_v3("
                        ":run_date,:release_sha256,:previous_release_sha256,"
                        "CAST(:payload AS jsonb))"
                    ),
                    {
                        "run_date": validated.daily_run_date,
                        "release_sha256": validated.release_sha256,
                        "previous_release_sha256": validated.previous_release_sha256,
                        "payload": _json_text(validated.model_dump(mode="json")),
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def activate(
        self,
        *,
        run_date: date,
        release_sha256: str,
        expected_current: str,
    ) -> None:
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.activate_daily_scored_release_v3("
                        ":run_date,:release_sha256,:expected_current)"
                    ),
                    {
                        "run_date": run_date,
                        "release_sha256": release_sha256,
                        "expected_current": expected_current,
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def finish(
        self,
        *,
        run_date: date,
        status: DailyRefreshRunStatus,
        changed_count: int,
        failed_count: int,
        safe_reason: str | None = None,
    ) -> None:
        if status in {DailyRefreshRunStatus.RUNNING, DailyRefreshRunStatus.INTERRUPTED}:
            raise DailyRefreshStoreError("daily finish status is invalid")
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.finish_daily_glm_refresh_v2("
                        ":run_date,:status,:changed_count,:failed_count,:safe_reason)"
                    ),
                    {
                        "run_date": run_date,
                        "status": str(status),
                        "changed_count": changed_count,
                        "failed_count": failed_count,
                        "safe_reason": safe_reason,
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def interrupt(self, *, run_date: date) -> bool:
        try:
            with self._factory.begin() as session:
                return bool(
                    session.execute(
                        text("SELECT dev_eval.interrupt_daily_glm_refresh_v2(:run_date)"),
                        {"run_date": run_date},
                    ).scalar_one()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def purge(self, *, cutoff: date) -> int:
        try:
            with self._factory.begin() as session:
                return int(
                    session.execute(
                        text("SELECT dev_eval.purge_daily_glm_refresh_v2(:cutoff)"),
                        {"cutoff": cutoff},
                    ).scalar_one()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def record_collection_failure(
        self,
        *,
        run_date: date,
        failure: DailyCollectionFailure,
    ) -> None:
        validated = DailyCollectionFailure.model_validate(failure.model_dump(mode="json"))
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.record_daily_glm_collection_failure_v2("
                        ":run_date,:place_id,:operation,:category,:code)"
                    ),
                    {
                        "run_date": run_date,
                        "place_id": validated.place_id,
                        "operation": str(validated.operation),
                        "category": validated.failure_category,
                        "code": validated.failure_code,
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)

    def claim_recollection(
        self,
        *,
        lease_seconds: int = 60,
    ) -> DailyRecollectionCommandProjection | None:
        try:
            with self._factory.begin() as session:
                row = (
                    session.execute(
                        text("SELECT * FROM dev_eval.claim_daily_glm_recollection_v2(:lease)"),
                        {"lease": lease_seconds},
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        return _command_projection(row)

    def complete_recollection(
        self,
        *,
        command_id: str,
        status: str,
        safe_reason: str | None,
    ) -> None:
        try:
            parsed = _uuid4(command_id)
        except ValueError as error:
            raise DailyRefreshConflict("daily refresh operation rejected") from error
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.complete_daily_glm_recollection_v2("
                        ":command_id,:status,:safe_reason)"
                    ),
                    {
                        "command_id": parsed,
                        "status": status,
                        "safe_reason": safe_reason,
                    },
                )
        except SQLAlchemyError as error:
            _raise_closed(error)


class DailyReleaseOverlayReader:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def active_release(self) -> MvpScoredReleaseV2 | MvpScoredReleaseV3 | None:
        try:
            with self._factory() as session:
                payload = session.execute(
                    text("SELECT dev_eval.read_active_daily_scored_release_v3()")
                ).scalar_one_or_none()
        except SQLAlchemyError as error:
            _raise_closed(error)
        if payload is None:
            return None
        try:
            release = parse_daily_scored_release(payload)
            if isinstance(release, MvpScoredRelease):
                raise ValueError("bundled release is not a daily overlay")
            return release
        except (ValidationError, ValueError, TypeError) as error:
            raise DailyReleasePayloadInvalid("active daily release payload invalid") from error

    def status(self) -> DailyRefreshStatusRecord | None:
        try:
            with self._factory() as session:
                row = (
                    session.execute(
                        text("SELECT * FROM dev_eval.read_daily_glm_refresh_status_v1()")
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        if row is None:
            return None
        try:
            return DailyRefreshStatusRecord(
                run_date=row["run_date"],
                status=DailyRefreshRunStatus(row["status"]),
                changed_count=int(row["changed_count"]),
                failed_count=int(row["failed_count"]),
                call_count=int(row["call_count"]),
                active_release_sha256=row["active_release_sha256"],
                safe_reason=row["safe_reason"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise DailyRefreshStoreError("daily refresh status projection invalid") from error

    def operations_overview(self) -> DailyOperationsOverviewRecord:
        try:
            with self._factory() as session:
                row = (
                    session.execute(
                        text(
                            "SELECT e.*, dev_eval.read_daily_glm_execution_availability_v2("
                            "e.run_date,e.execution_sequence::integer) AS availability "
                            "FROM dev_eval.read_daily_glm_operations_overview_v1() e"
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        if row is None:
            return DailyOperationsOverviewRecord(
                execution=None,
                active_release_sha256=None,
                recollection=DailyRecollectionEligibility(
                    eligible=False,
                    safe_reason="NO_EXECUTION_AVAILABLE",
                ),
                pending_command_id=None,
            )
        execution = _execution_projection(row)
        try:
            return DailyOperationsOverviewRecord(
                execution=execution,
                active_release_sha256=row["active_release_sha256"],
                recollection=DailyRecollectionEligibility(
                    eligible=row["recollection_eligible"],
                    safe_reason=row["recollection_reason"],
                ),
                pending_command_id=(
                    str(row["pending_command_id"])
                    if row["pending_command_id"] is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise DailyRefreshStoreError("daily operations overview invalid") from error

    def execution_history(
        self,
        *,
        days: int,
    ) -> tuple[DailyRefreshExecutionProjection, ...]:
        try:
            with self._factory() as session:
                rows = (
                    session.execute(
                        text("SELECT * FROM dev_eval.read_daily_glm_execution_history_v1(:days)"),
                        {"days": days},
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        return tuple(_execution_projection(row) for row in rows)

    def execution_detail(
        self,
        *,
        run_date: date,
        execution_sequence: int,
    ) -> DailyExecutionDetailRecord | None:
        try:
            with self._factory() as session:
                execution_row = (
                    session.execute(
                        text(
                            "SELECT e.*, dev_eval.read_daily_glm_execution_availability_v2("
                            "e.run_date,e.execution_sequence::integer) AS availability "
                            "FROM dev_eval.read_daily_glm_execution_v1("
                            ":run_date,:execution_sequence) e"
                        ),
                        {"run_date": run_date, "execution_sequence": execution_sequence},
                    )
                    .mappings()
                    .one_or_none()
                )
                if execution_row is None:
                    return None
                failure_rows = (
                    session.execute(
                        text(
                            "SELECT * FROM dev_eval.read_daily_glm_collection_failures_v1("
                            ":run_date,:execution_sequence)"
                        ),
                        {"run_date": run_date, "execution_sequence": execution_sequence},
                    )
                    .mappings()
                    .all()
                )
                attempt_rows = (
                    session.execute(
                        text(
                            "SELECT * FROM dev_eval.read_daily_glm_attempts_v1("
                            ":run_date,:execution_sequence)"
                        ),
                        {"run_date": run_date, "execution_sequence": execution_sequence},
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        try:
            failures = tuple(
                DailyCollectionFailureProjection.model_validate(
                    {
                        "place_id": row["place_id"],
                        "operation": row["operation"],
                        "failure_category": row["failure_category"],
                        "failure_code": row["failure_code"],
                        "execution_sequence": row["execution_sequence"],
                        "occurred_at": row["occurred_at"],
                    }
                )
                for row in failure_rows
            )
            attempts = tuple(
                DailyGlmAttemptProjection.model_validate(
                    {
                        "run_date": row["run_date"],
                        "execution_sequence": row["execution_sequence"],
                        "place_id": row["place_id"],
                        "attempt_number": row["attempt_number"],
                        "status": row["status"],
                        "safe_reason": row["safe_reason"],
                        "result_sha256": row["result_sha256"],
                        "reserved_at": row["reserved_at"],
                        "finished_at": row["finished_at"],
                    }
                )
                for row in attempt_rows
            )
            return DailyExecutionDetailRecord(
                execution=_execution_projection(execution_row),
                collection_failures=failures,
                attempts=attempts,
                excluded=(
                    tuple(
                        DailyExcludedPlaceProjection.model_validate(value)
                        for value in execution_row["availability"]["excluded"]
                    )
                    if execution_row["availability"]["excluded"] is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise DailyRefreshStoreError("daily execution detail invalid") from error

    def request_recollection(
        self,
        *,
        run_date: date,
        idempotency_key: str,
    ) -> DailyRecollectionCommandProjection:
        try:
            with self._factory.begin() as session:
                row = (
                    session.execute(
                        text(
                            "SELECT * FROM dev_eval.request_daily_glm_recollection_v1("
                            ":run_date,:idempotency_key)"
                        ),
                        {"run_date": run_date, "idempotency_key": idempotency_key},
                    )
                    .mappings()
                    .one()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        projection = _command_projection(row)
        if projection is None:
            raise DailyRefreshStoreError("daily command projection missing")
        return projection

    def recollection_command(
        self,
        *,
        command_id: str,
    ) -> DailyRecollectionCommandProjection | None:
        try:
            parsed = _uuid4(command_id)
        except ValueError as error:
            raise DailyRefreshConflict("daily refresh operation rejected") from error
        try:
            with self._factory() as session:
                row = (
                    session.execute(
                        text(
                            "SELECT * FROM dev_eval.read_daily_glm_recollection_command_v1("
                            ":command_id)"
                        ),
                        {"command_id": parsed},
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            _raise_closed(error)
        return _command_projection(row)


class ActiveReleaseOverlayResolver:
    def __init__(
        self,
        *,
        overlay_reader: DailyReleaseOverlayReader,
        bundled_resolver: Callable[[], MvpScoredRelease | None],
    ) -> None:
        self._overlay_reader = overlay_reader
        self._bundled_resolver = bundled_resolver
        self._last_overlay: MvpScoredReleaseV2 | MvpScoredReleaseV3 | None = None
        self._lock = Lock()

    def __call__(self) -> DailyScoredRelease | None:
        try:
            overlay = self._overlay_reader.active_release()
        except DailyReleasePayloadInvalid:
            raise
        except DailyRefreshStoreError:
            with self._lock:
                cached = self._last_overlay
            return cached if cached is not None else self._bundled_resolver()
        if overlay is not None:
            with self._lock:
                self._last_overlay = overlay
            return overlay
        return self._bundled_resolver()
