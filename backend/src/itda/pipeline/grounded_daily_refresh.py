"""Daily grounded batches stage complete pairs; only measured receipts can promote."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, Self

from pydantic import Field, model_validator

from itda.cli.analyze_grounded_places import _write_once, run_batch
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.grounded_promotion import (
    GroundedPromotionGate,
    GroundedPromotionReport,
    validate_promotion_reports,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY
from itda.contracts.grounded_source import parse_grounded_input_release
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.db.assessment_release import load_candidate_from_directory
from itda.domain.canonical import canonical_sha256
from itda.photo.provider.mood import MoodProvider
from itda.pipeline.destination_evidence import OfficialSourceCache, atomic_json, cache_lock
from itda.pipeline.grounded_place_scoring import GroundedTextProvider
from itda.pipeline.national_public_catalog import NationalProviderPaused


class DailyPairStore(Protocol):
    def load_active(self) -> GroundedReleaseCandidate | None: ...
    def load_candidate(self, candidate_sha256: str) -> GroundedReleaseCandidate | None: ...
    def stage(self, candidate: GroundedReleaseCandidate) -> str: ...
    def store_report(self, report: GroundedPromotionReport) -> str: ...
    def load_promotion(self, generation: int) -> Any: ...
    def promote(
        self,
        gate: GroundedPromotionGate,
        *,
        expected_active_sha256: str | None = None,
        expected_config_sha256: str = GROUNDED_POLICY.sha256,
    ) -> int: ...


class GroundedDailyPlan(StrictContract):
    schema_version: Literal["grounded-daily-plan.v1"] = "grounded-daily-plan.v1"
    run_date: date
    timezone: Literal["Asia/Seoul"] = "Asia/Seoul"
    scheduled_hour: Literal[8] = 8
    catalog_sha256: Sha256
    raw_release_sha256: Sha256
    baseline_candidate_sha256: Sha256 | None
    semantic_cache_version: Literal["v2"] = "v2"
    workers: int = Field(default=4, strict=True, ge=1, le=32)
    created_at: datetime
    plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.plan_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"plan_sha256"})
        ):
            raise ValueError("daily plan hash mismatch")
        return self


class GroundedDailyOutcome(StrictContract):
    schema_version: Literal["grounded-daily-outcome.v1"] = "grounded-daily-outcome.v1"
    run_date: date
    plan_sha256: Sha256
    event_number: int = Field(strict=True, ge=1)
    status: Literal["STARTED", "FAILED", "PAUSED", "STAGED", "PROMOTED"]
    candidate_sha256: Sha256 | None = None
    gate_sha256: Sha256 | None = None
    generation: int | None = Field(default=None, strict=True, ge=1)
    reason: Literal[
        "BATCH_STARTED",
        "BATCH_OR_STAGE_FAILED",
        "MEASURED_REPORTS_REQUIRED",
        "MEASURED_GATE_REJECTED",
        "PROMOTION_PASSED",
        "PROVIDER_RATE_OR_QUOTA_LIMIT",
    ]
    recorded_at: datetime
    outcome_sha256: Sha256

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        require_utc(self.recorded_at, field_name="recorded_at")
        if self.status in {"STAGED", "PROMOTED"} and self.candidate_sha256 is None:
            raise ValueError("daily outcome lacks its complete staged pair")
        if self.status == "PROMOTED" and (self.gate_sha256 is None or self.generation is None):
            raise ValueError("promotion outcome lacks actual gate authority")
        if self.outcome_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"outcome_sha256"})
        ):
            raise ValueError("daily outcome hash mismatch")
        return self


@dataclass(frozen=True)
class PromotionEvidence:
    gate: GroundedPromotionGate
    reports: tuple[GroundedPromotionReport, ...]


def read_promotion_evidence(gate_path: Path, report_directory: Path) -> PromotionEvidence | None:
    """Explicit files from a measured evaluator; absent files mean stage only."""
    if not gate_path.is_file():
        return None
    gate = GroundedPromotionGate.model_validate_json(gate_path.read_bytes())
    hashes = (
        gate.source_ablation_sha256,
        gate.axis_comparison_sha256,
        gate.api_ui_verification_sha256,
    )
    paths = tuple(report_directory / (digest + ".json") for digest in hashes)
    if not all(path.is_file() for path in paths):
        return None
    reports = tuple(
        GroundedPromotionReport.model_validate_json(path.read_bytes()) for path in paths
    )
    return PromotionEvidence(gate, reports)


def _latest(directory: Path, plan: GroundedDailyPlan) -> GroundedDailyOutcome | None:
    pointer = directory / "state.json"
    events = sorted((directory / "events").glob("[0-9][0-9][0-9][0-9][0-9].json"))
    if not events:
        if pointer.exists():
            raise ValueError("daily state has no immutable event")
        return None
    parsed = []
    for number, path in enumerate(events, 1):
        outcome = GroundedDailyOutcome.model_validate_json(path.read_bytes())
        if (
            path.name != f"{number:05d}.json"
            or outcome.run_date != plan.run_date
            or outcome.plan_sha256 != plan.plan_sha256
            or outcome.event_number != number
        ):
            raise ValueError("daily journal sequence or input identity differs")
        parsed.append(outcome)
    if pointer.exists():
        value = json.loads(pointer.read_text(encoding="utf-8"))
        number = value.get("event_number")
        if (
            type(number) is not int
            or not 1 <= number <= len(parsed)
            or value.get("outcome_sha256") != parsed[number - 1].outcome_sha256
        ):
            raise ValueError("daily state does not reference its immutable event")
    outcome = parsed[-1]
    # Recover an event committed immediately before a crash interrupted the
    # mutable pointer replacement; the validated immutable event is authority.
    atomic_json(
        pointer, {"event_number": outcome.event_number, "outcome_sha256": outcome.outcome_sha256}
    )
    return outcome


def _record(
    directory: Path,
    plan: GroundedDailyPlan,
    *,
    status: str,
    reason: str,
    clock: Callable[[], datetime],
    candidate_sha256: str | None = None,
    gate_sha256: str | None = None,
    generation: int | None = None,
) -> GroundedDailyOutcome:
    directory.joinpath("events").mkdir(parents=True, exist_ok=True)
    previous = _latest(directory, plan)
    number = previous.event_number + 1 if previous else 1
    draft = GroundedDailyOutcome.model_construct(
        run_date=plan.run_date,
        plan_sha256=plan.plan_sha256,
        event_number=number,
        status=status,
        reason=reason,
        recorded_at=clock(),
        candidate_sha256=candidate_sha256,
        gate_sha256=gate_sha256,
        generation=generation,
        outcome_sha256="0" * 64,
    )
    payload = draft.model_dump(mode="json", exclude={"outcome_sha256"})
    outcome = GroundedDailyOutcome.model_validate(
        payload | {"outcome_sha256": canonical_sha256(payload)}
    )
    _write_once(directory / "events" / f"{number:05d}.json", outcome.model_dump(mode="json"))
    atomic_json(
        directory / "state.json", {"event_number": number, "outcome_sha256": outcome.outcome_sha256}
    )
    return outcome


def run_grounded_daily(
    *,
    run_date: date,
    root: Path,
    catalog: PublicPlaceCatalog,
    store: DailyPairStore,
    cache: OfficialSourceCache,
    text_provider: GroundedTextProvider,
    mood_provider: MoodProvider | None,
    raw_release_resolver: Callable[[], Any],
    workers: int = 4,
    live: bool = True,
    evaluator: Callable[[GroundedReleaseCandidate], PromotionEvidence | None] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    batch_runner: Callable[..., dict[str, Any]] = run_batch,
) -> GroundedDailyOutcome:
    """Resume one date's immutable inputs; never call legacy raw-release activation."""
    if type(workers) is not int or not 1 <= workers <= 32:
        raise ValueError("grounded daily workers must be1..32 (default4, online capacity reserved)")
    if text_provider.cache_version != "v2":
        raise ValueError("new daily runs require semantic cache v2")
    directory = Path(root) / run_date.isoformat()
    directory.mkdir(parents=True, exist_ok=True)
    with cache_lock(directory / "operation"):
        plan_path = directory / "plan.json"
        inputs_path = directory / "inputs.json"
        if inputs_path.is_file():
            inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
            if (
                set(inputs) != {"schema_version", "plan", "raw_release", "inputs_sha256"}
                or inputs.get("schema_version") != "grounded-daily-inputs.v1"
                or inputs.get("inputs_sha256")
                != canonical_sha256({k: v for k, v in inputs.items() if k != "inputs_sha256"})
            ):
                raise ValueError("daily immutable inputs hash differs")
            plan = GroundedDailyPlan.model_validate(inputs["plan"])
            raw = parse_grounded_input_release(inputs["raw_release"])
            if (
                plan.run_date != run_date
                or plan.catalog_sha256 != catalog.catalog_sha256
                or plan.raw_release_sha256 != raw.release_sha256
            ):
                raise ValueError("daily resume input changed; use a new declared run date")
        else:
            active = store.load_active()
            raw = active.raw_release if active is not None else raw_release_resolver()
            if raw is None:
                raise ValueError("no complete raw release is available for daily analysis")
            draft = GroundedDailyPlan.model_construct(
                run_date=run_date,
                catalog_sha256=catalog.catalog_sha256,
                raw_release_sha256=raw.release_sha256,
                baseline_candidate_sha256=active.candidate_sha256 if active else None,
                workers=workers,
                created_at=clock(),
                plan_sha256="0" * 64,
            )
            payload = draft.model_dump(mode="json", exclude={"plan_sha256"})
            plan = GroundedDailyPlan.model_validate(
                payload | {"plan_sha256": canonical_sha256(payload)}
            )
            inputs = {
                "schema_version": "grounded-daily-inputs.v1",
                "plan": plan.model_dump(mode="json"),
                "raw_release": raw.model_dump(mode="json"),
            }
            _write_once(inputs_path, inputs | {"inputs_sha256": canonical_sha256(inputs)})
        _write_once(plan_path, plan.model_dump(mode="json"))
        _write_once(directory / "raw-release.json", raw.model_dump(mode="json"))
        previous = _latest(directory, plan)
        batch_directory = directory / "batch"
        if previous and previous.status == "PROMOTED":
            completed_candidate = load_candidate_from_directory(batch_directory, raw)
            stored = store.load_candidate(completed_candidate.candidate_sha256)
            if (
                stored != completed_candidate
                or previous.candidate_sha256 != completed_candidate.candidate_sha256
            ):
                raise ValueError("completed daily candidate cannot be verified")
            if previous.generation is None:
                raise ValueError("completed daily run has no database generation")
            promotion = store.load_promotion(previous.generation)
            if (
                promotion is None
                or promotion.gate.gate_sha256 != previous.gate_sha256
                or promotion.candidate != completed_candidate
            ):
                raise ValueError("daily completion has no validated database promotion")
            return previous
        candidate: GroundedReleaseCandidate | None = None
        if previous is None or previous.status not in {"STAGED"}:
            _record(directory, plan, status="STARTED", reason="BATCH_STARTED", clock=clock)
        try:
            if not (batch_directory / "run.json").is_file():
                batch_runner(
                    catalog=catalog,
                    raw_release=raw,
                    output=batch_directory,
                    cache=cache,
                    text_provider=text_provider,
                    mood_provider=mood_provider,
                    workers=plan.workers,
                    live=live,
                )
            candidate = load_candidate_from_directory(batch_directory, raw)
            _write_once(batch_directory / "candidate.json", candidate.model_dump(mode="json"))
            if store.stage(candidate) != candidate.candidate_sha256:
                raise ValueError("staged daily candidate digest differs")
        except NationalProviderPaused as error:
            atomic_json(directory / "source-paused.json", error.state)
            return _record(
                directory, plan, status="PAUSED", reason="PROVIDER_RATE_OR_QUOTA_LIMIT", clock=clock
            )
        except Exception:
            return _record(
                directory, plan, status="FAILED", reason="BATCH_OR_STAGE_FAILED", clock=clock
            )
        try:
            evidence = evaluator(candidate) if evaluator is not None else None
            if evidence is None:
                if (
                    previous is not None
                    and previous.status == "STAGED"
                    and previous.candidate_sha256 == candidate.candidate_sha256
                ):
                    return previous
                return _record(
                    directory,
                    plan,
                    status="STAGED",
                    reason="MEASURED_REPORTS_REQUIRED",
                    candidate_sha256=candidate.candidate_sha256,
                    clock=clock,
                )
            if (
                evidence.gate.candidate_sha256 != candidate.candidate_sha256
                or evidence.gate.config_sha256 != GROUNDED_POLICY.sha256
            ):
                raise ValueError("daily evaluator returned evidence for another pair/policy")
            validate_promotion_reports(
                evidence.gate, evidence.reports, candidate_created_at=candidate.created_at
            )
            for report in evidence.reports:
                store.store_report(report)
            generation = store.promote(
                evidence.gate, expected_active_sha256=plan.baseline_candidate_sha256
            )
            return _record(
                directory,
                plan,
                status="PROMOTED",
                reason="PROMOTION_PASSED",
                candidate_sha256=candidate.candidate_sha256,
                gate_sha256=evidence.gate.gate_sha256,
                generation=generation,
                clock=clock,
            )
        except Exception:
            return _record(
                directory,
                plan,
                status="FAILED",
                reason="MEASURED_GATE_REJECTED",
                candidate_sha256=candidate.candidate_sha256,
                clock=clock,
            )
