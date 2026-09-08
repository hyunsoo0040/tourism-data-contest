"""Daily PUBLIC-100 refresh orchestration and Asia/Seoul scheduling."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Protocol
from zoneinfo import ZoneInfo

from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY_V2,
    DailyRefreshRunStatus,
    DailyScoredRelease,
    MvpScoredReleaseV3,
)
from itda.contracts.mvp_place_scoring import BoundScoringResult
from itda.contracts.mvp_public_catalog import (
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.db.mvp_release_overlay import DailyRefreshStore
from itda.pipeline.daily_incremental_scoring import (
    DailyTerminalScoringError,
    execute_incremental_scoring,
)
from itda.pipeline.daily_public_input import (
    DailyCollectionIncomplete,
    DailyTourApiProvider,
    build_daily_delta,
    build_incremental_scoring_plan,
    collect_daily_snapshot,
)
from itda.pipeline.daily_scored_release import (
    materialize_daily_scored_release,
    release_input_state,
    scoring_targets,
)
from itda.pipeline.mvp_place_scoring import ScoringAttemptEvent, ScoringTransport

SEOUL = ZoneInfo("Asia/Seoul")


class ActiveReleaseResolver(Protocol):
    def __call__(self) -> DailyScoredRelease | None: ...


@dataclass(frozen=True, slots=True)
class DailyRefreshOutcome:
    run_date: date
    status: DailyRefreshRunStatus
    changed_count: int
    failed_count: int
    call_count: int
    release_sha256: str | None = None
    safe_reason: str | None = None


def due_run_date(now: datetime) -> date | None:
    if now.utcoffset() != UTC.utcoffset(now):
        raise ValueError("daily scheduler clock must return UTC")
    local = now.astimezone(SEOUL)
    return local.date() if local.time() >= time(hour=8) else None


def next_run_at(now: datetime) -> datetime:
    if now.utcoffset() != UTC.utcoffset(now):
        raise ValueError("daily scheduler clock must return UTC")
    local = now.astimezone(SEOUL)
    target_date = local.date() if local.time() < time(hour=8) else local.date() + timedelta(days=1)
    return datetime.combine(target_date, time(hour=8), tzinfo=SEOUL).astimezone(UTC)


def run_daily_refresh(
    *,
    run_date: date,
    collected_at: datetime,
    catalog: PublicPlaceCatalog,
    evidence_inventory: PublicEvidenceInventory,
    relations: PublicPlaceRelations,
    provider: DailyTourApiProvider,
    store: DailyRefreshStore,
    active_release_resolver: ActiveReleaseResolver,
    scoring_transport_factory: Callable[[], ScoringTransport],
    preclaimed: bool = False,
) -> DailyRefreshOutcome | None:
    if not preclaimed and not store.claim(
        run_date=run_date,
        authority_sha256=DAILY_REFRESH_AUTHORITY_V2.authority_sha256,
    ):
        return None
    try:
        previous_snapshot = store.latest_snapshot()
        snapshot = collect_daily_snapshot(
            catalog=catalog,
            evidence_inventory=evidence_inventory,
            provider=provider,
            run_date=run_date,
            collected_at=collected_at,
            previous_snapshot_sha256=(
                previous_snapshot.snapshot_sha256 if previous_snapshot is not None else None
            ),
        )
        store.store_snapshot(snapshot)
    except DailyCollectionIncomplete as error:
        reason = error.safe_reason
        if error.failure is not None:
            store.record_collection_failure(run_date=run_date, failure=error.failure)
        store.finish(
            run_date=run_date,
            status=DailyRefreshRunStatus.COLLECTION_INCOMPLETE,
            changed_count=0,
            failed_count=0,
            safe_reason=reason,
        )
        return DailyRefreshOutcome(
            run_date=run_date,
            status=DailyRefreshRunStatus.COLLECTION_INCOMPLETE,
            changed_count=0,
            failed_count=0,
            call_count=0,
            safe_reason=reason,
        )

    def finish_without_scoring(
        status: DailyRefreshRunStatus,
        reason: str | None = None,
        changed: int = 0,
    ) -> DailyRefreshOutcome:
        store.finish(
            run_date=run_date,
            status=status,
            changed_count=changed,
            failed_count=0,
            safe_reason=reason,
        )
        return DailyRefreshOutcome(
            run_date=run_date,
            status=status,
            changed_count=changed,
            failed_count=0,
            call_count=0,
            safe_reason=reason,
        )

    if len(snapshot.places) < 80:
        return finish_without_scoring(
            DailyRefreshRunStatus.RELEASE_REJECTED,
            "INSUFFICIENT_AVAILABLE_PLACES",
            len(snapshot.excluded),
        )
    if previous_snapshot is None and not snapshot.excluded:
        store.finish(
            run_date=run_date,
            status=DailyRefreshRunStatus.BASELINE_RECORDED,
            changed_count=0,
            failed_count=0,
        )
        return DailyRefreshOutcome(
            run_date=run_date,
            status=DailyRefreshRunStatus.BASELINE_RECORDED,
            changed_count=0,
            failed_count=0,
            call_count=0,
        )

    prior = previous_snapshot if previous_snapshot is not None else snapshot
    delta = build_daily_delta(prior, snapshot)
    changed_count = (
        len(delta.changed_place_ids) if previous_snapshot is not None else len(snapshot.excluded)
    )
    previous_release = active_release_resolver()
    if previous_release is None:
        return finish_without_scoring(
            DailyRefreshRunStatus.RELEASE_REJECTED,
            "ACTIVE_RELEASE_MISSING",
            changed_count,
        )
    baseline = store.baseline_snapshot()
    if baseline is None:
        return finish_without_scoring(
            DailyRefreshRunStatus.RELEASE_REJECTED,
            "BASELINE_SNAPSHOT_MISSING",
            changed_count,
        )
    try:
        entries, failed = release_input_state(
            previous_release,
            baseline=baseline,
            get_snapshot=store.get_snapshot,
        )
        targets = scoring_targets(
            snapshot=snapshot,
            previous_snapshot=prior,
            entries=entries,
            failed=failed,
        )
    except (ValueError, KeyError):
        return finish_without_scoring(
            DailyRefreshRunStatus.RELEASE_REJECTED,
            "ACTIVE_INPUT_LINEAGE_MISSING",
            changed_count,
        )
    active_excluded = (
        {r.place_id: r.semantic_state for r in previous_release.excluded}
        if isinstance(previous_release, MvpScoredReleaseV3)
        else {}
    )
    current_excluded = {r.place_id: r.semantic_state for r in snapshot.excluded}
    if not targets and active_excluded == current_excluded:
        return finish_without_scoring(DailyRefreshRunStatus.NO_CHANGES, changed=changed_count)

    plan = (
        build_incremental_scoring_plan(
            snapshot=snapshot,
            delta=delta,
            scoring_place_ids=targets,
        )
        if targets
        else None
    )
    if plan is not None:
        store.store_plan(plan)
    completed_results: dict[str, BoundScoringResult] = {}
    reserved_calls = 0

    def reserve_call(event: ScoringAttemptEvent) -> None:
        nonlocal reserved_calls
        store.reserve_call(run_date=run_date, event=event)
        reserved_calls += 1

    def on_result(result: BoundScoringResult) -> None:
        completed_results[result.place_id] = result

    def on_attempt(event: ScoringAttemptEvent) -> None:
        store.finish_attempt(
            run_date=run_date,
            event=event,
            result_sha256=(
                completed_results[event.place_id].result_sha256
                if event.status == "SUCCEEDED"
                else None
            ),
        )

    scoring_failures: dict[str, str] = {}
    if plan is not None:
        transport = scoring_transport_factory()
        try:
            outcome = execute_incremental_scoring(
                snapshot=snapshot,
                plan=plan,
                transport=transport,
                catalog_sha256=catalog.catalog_sha256,
                reserve_call=reserve_call,
                on_attempt=on_attempt,
                on_result=on_result,
            )
            scoring_failures = dict(outcome.failed)
        except DailyTerminalScoringError as error:
            reason = str(error)
            store.finish(
                run_date=run_date,
                status=DailyRefreshRunStatus.SCORING_FAILED,
                changed_count=changed_count,
                failed_count=len(targets),
                safe_reason=reason,
            )
            return DailyRefreshOutcome(
                run_date=run_date,
                status=DailyRefreshRunStatus.SCORING_FAILED,
                changed_count=changed_count,
                failed_count=len(targets),
                call_count=reserved_calls,
                safe_reason=reason,
            )
        finally:
            transport.close()
    try:
        release = materialize_daily_scored_release(
            previous_release=previous_release,
            previous_snapshot=prior,
            snapshot=snapshot,
            delta=delta,
            catalog=catalog,
            relations=relations,
            results=tuple(completed_results.values()),
            failures=scoring_failures,
            created_at=collected_at,
            scoring_place_ids=targets,
            reusable_entries=entries,
            reusable_failed=failed,
        )
        store.publish(release)
        store.activate(
            run_date=run_date,
            release_sha256=release.release_sha256,
            expected_current=previous_release.release_sha256,
        )
    except ValueError:
        reason = "RELEASE_VALIDATION_REJECTED"
        store.finish(
            run_date=run_date,
            status=DailyRefreshRunStatus.RELEASE_REJECTED,
            changed_count=changed_count,
            failed_count=len(scoring_failures),
            safe_reason=reason,
        )
        return DailyRefreshOutcome(
            run_date=run_date,
            status=DailyRefreshRunStatus.RELEASE_REJECTED,
            changed_count=changed_count,
            failed_count=len(scoring_failures),
            call_count=reserved_calls,
            safe_reason=reason,
        )

    store.finish(
        run_date=run_date,
        status=DailyRefreshRunStatus.RELEASE_ACTIVATED,
        changed_count=changed_count,
        failed_count=len(scoring_failures),
    )
    return DailyRefreshOutcome(
        run_date=run_date,
        status=DailyRefreshRunStatus.RELEASE_ACTIVATED,
        changed_count=changed_count,
        failed_count=len(scoring_failures),
        call_count=reserved_calls,
        release_sha256=release.release_sha256,
    )
