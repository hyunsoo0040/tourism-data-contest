"""Bounded partial GLM execution for changed PUBLIC-100 scoring inputs."""

from __future__ import annotations

from collections.abc import Callable

from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_MAXIMUM_CALLS,
    DailyIncrementalScoringPlan,
    DailyIncrementalScoringPlanV2,
    DailySnapshot,
)
from itda.contracts.mvp_place_scoring import (
    MVP_SCORING_PROMPT_SHA256,
    BoundScoringResult,
    PublicScoringRequest,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_place_scoring import (
    MAX_INPUT_TOKENS,
    MAX_OUTPUT_TOKENS,
    REQUEST_TIMEOUT_SECONDS,
    BatchOutcome,
    MvpScoringError,
    ScoringAttemptEvent,
    ScoringTransport,
    bind_response,
    estimate_input_tokens,
    redact_error,
)

_TERMINAL_PROVIDER_REASONS = frozenset(
    {
        "GLM_CREDENTIAL_REFLECTED",
        "GLM_HTTP_AUTH_REJECTED",
        "GLM_HTTP_POLICY_REJECTED",
        "GLM_HTTP_QUOTA_REJECTED",
    }
)


class DailyTerminalScoringError(MvpScoringError):
    pass


def daily_evidence_inventory_sha256(snapshot: DailySnapshot) -> str:
    return canonical_sha256([row.evidence.model_dump(mode="json") for row in snapshot.places])


def _requests_for_plan(
    snapshot: DailySnapshot,
    plan: DailyIncrementalScoringPlan | DailyIncrementalScoringPlanV2,
) -> tuple[PublicScoringRequest, ...]:
    if (
        plan.snapshot_sha256 != snapshot.snapshot_sha256
        or plan.run_date != snapshot.run_date
        or plan.prompt_sha256 != MVP_SCORING_PROMPT_SHA256
        or plan.maximum_calls != DAILY_REFRESH_MAXIMUM_CALLS
    ):
        raise MvpScoringError("DAILY_PLAN_SNAPSHOT_BINDING_MISMATCH")
    by_id = {row.place_id: row.request for row in snapshot.places}
    try:
        targets = (
            plan.scoring_place_ids
            if isinstance(plan, DailyIncrementalScoringPlanV2)
            else plan.changed_place_ids
        )
        requests = tuple(by_id[place_id] for place_id in targets)
    except KeyError as error:
        raise MvpScoringError("DAILY_PLAN_PLACE_BINDING_MISMATCH") from error
    if tuple(row.request_sha256 for row in requests) != plan.request_sha256:
        raise MvpScoringError("DAILY_PLAN_REQUEST_BINDING_MISMATCH")
    return requests


def execute_incremental_scoring(
    *,
    snapshot: DailySnapshot,
    plan: DailyIncrementalScoringPlan | DailyIncrementalScoringPlanV2,
    transport: ScoringTransport,
    catalog_sha256: str,
    reserve_call: Callable[[ScoringAttemptEvent], None],
    on_attempt: Callable[[ScoringAttemptEvent], None] | None = None,
    on_result: Callable[[BoundScoringResult], None] | None = None,
) -> BatchOutcome:
    requests = _requests_for_plan(snapshot, plan)
    by_id = {row.place.place_id: row for row in requests}
    results: dict[str, BoundScoringResult] = {}
    failures: dict[str, str] = {}
    attempted: list[str] = []
    attempt_counts: dict[str, int] = {}
    call_count = 0
    evidence_inventory_sha256 = daily_evidence_inventory_sha256(snapshot)

    def event(
        request: PublicScoringRequest,
        *,
        attempt_number: int,
        status: str,
        reason: str | None = None,
    ) -> ScoringAttemptEvent:
        return ScoringAttemptEvent(
            run_plan_sha256=plan.plan_sha256,
            place_id=request.place.place_id,
            request_sha256=request.request_sha256,
            attempt_number=attempt_number,
            status=status,
            reason=reason,
        )

    def emit(value: ScoringAttemptEvent) -> None:
        if on_attempt is not None:
            on_attempt(value)

    def attempt(request: PublicScoringRequest) -> None:
        nonlocal call_count
        place_id = request.place.place_id
        attempt_number = attempt_counts.get(place_id, 0) + 1
        if attempt_number > plan.retry_limit_per_place + 1:
            return
        encoded_request = canonical_json_bytes(request.model_dump(mode="json"))
        if estimate_input_tokens(encoded_request) > MAX_INPUT_TOKENS:
            failures[place_id] = "REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED"
            return
        if call_count >= plan.maximum_calls:
            raise MvpScoringError("MAXIMUM_CALLS_EXCEEDED")

        started = event(
            request,
            attempt_number=attempt_number,
            status="STARTED",
        )
        reserve_call(started)
        attempt_counts[place_id] = attempt_number
        attempted.append(place_id)
        call_count += 1

        try:
            raw = transport.score(
                request,
                timeout_seconds=REQUEST_TIMEOUT_SECONDS,
                max_tokens=MAX_OUTPUT_TOKENS,
            )
            result = bind_response(
                request,
                raw,
                catalog_sha256=catalog_sha256,
                evidence_inventory_sha256=evidence_inventory_sha256,
                prompt_sha256=plan.prompt_sha256,
            )
        except Exception as error:
            reason = redact_error(error)
            failures[place_id] = reason
            emit(
                event(
                    request,
                    attempt_number=attempt_number,
                    status="FAILED",
                    reason=reason,
                )
            )
            if reason in _TERMINAL_PROVIDER_REASONS:
                raise DailyTerminalScoringError(reason) from error
            return

        results[place_id] = result
        failures.pop(place_id, None)
        if on_result is not None:
            on_result(result)
        emit(
            event(
                request,
                attempt_number=attempt_number,
                status="SUCCEEDED",
            )
        )

    for request in requests:
        attempt(request)
    for place_id in tuple(sorted(failures)):
        if attempt_counts.get(place_id, 0) == 1:
            attempt(by_id[place_id])

    if call_count > plan.maximum_calls or call_count > DAILY_REFRESH_MAXIMUM_CALLS:
        raise MvpScoringError("MAXIMUM_CALLS_EXCEEDED")
    return BatchOutcome(
        results=dict(sorted(results.items())),
        failed=dict(sorted(failures.items())),
        attempted_place_ids=tuple(attempted),
        call_count=call_count,
        attempt_counts=dict(sorted(attempt_counts.items())),
    )
