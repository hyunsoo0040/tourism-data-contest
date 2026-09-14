"""Measured, candidate-bound promotion evidence. Human relevance is not invented."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256

SOURCE_LANES = ("baseline", "detail", "odii", "images", "combined")
UI_CASES = ("happy_path", "unknown", "photo", "replay", "desktop", "mobile")
RankedFive = Annotated[tuple[StableId, ...], Field(min_length=5, max_length=5)]
Count = Annotated[int, Field(strict=True, ge=0)]


class MeasuredViolations(StrictContract):
    """Actual offending cases are retained; totals are derived from these lists."""

    constraint: tuple[str, ...] = ()
    unauthorized_claim: tuple[str, ...] = ()
    replay: tuple[str, ...] = ()
    schema_identity: tuple[str, ...] = ()
    structural_regression: tuple[str, ...] = ()

    @property
    def failure_count(self) -> int:
        return sum(len(getattr(self, key)) for key in type(self).model_fields)


class SourceAblationRow(StrictContract):
    scenario_id: StableId
    lane: Literal["baseline", "detail", "odii", "images", "combined"]
    preference_sha256: Sha256
    source_bundle_sha256: Sha256
    model_response_sha256: Sha256
    ranking: RankedFive
    eligible_count: Annotated[int, Field(strict=True, ge=5)]
    purpose_eligible_count: Count
    supported_dimensions: Count
    possible_dimensions: Annotated[int, Field(strict=True, ge=1)]
    checked_constraints: Annotated[int, Field(strict=True, ge=1)]
    checked_claims: Count
    violations: MeasuredViolations

    @model_validator(mode="after")
    def validate_measurement(self) -> Self:
        if len(set(self.ranking)) != 5:
            raise ValueError("ablation ranking must have five distinct places")
        if self.supported_dimensions > self.possible_dimensions:
            raise ValueError("invalid observed support coverage")
        if self.purpose_eligible_count > self.eligible_count:
            raise ValueError("purpose coverage exceeds eligible count")
        if len(self.violations.constraint) > self.checked_constraints:
            raise ValueError("constraint failures exceed measurements")
        if len(self.violations.unauthorized_claim) > self.checked_claims:
            raise ValueError("claim failures exceed measurements")
        return self


class SourceAblationResults(StrictContract):
    scope: Literal["DEV"] = "DEV"
    dev_manifest_sha256: Sha256
    model: Literal["glm-5.3-flash"] = "glm-5.3-flash"
    prompt_sha256: Sha256
    aggregation_policy_sha256: Sha256
    human_relevance_status: Literal["NOT_MEASURED"] = "NOT_MEASURED"
    rows: Annotated[tuple[SourceAblationRow, ...], Field(min_length=5)]

    @model_validator(mode="after")
    def comparable_lanes(self) -> Self:
        groups: dict[str, list[SourceAblationRow]] = {}
        for row in self.rows:
            groups.setdefault(row.scenario_id, []).append(row)
        for group in groups.values():
            if len(group) != 5 or {r.lane for r in group} != set(SOURCE_LANES):
                raise ValueError("each DEV scenario requires all five source lanes exactly once")
            if len({r.preference_sha256 for r in group}) != 1:
                raise ValueError("source comparison changed the user input")
        return self


class AxisComparisonRow(StrictContract):
    scenario_id: StableId
    preference_sha256: Sha256
    source_bundle_sha256: Sha256
    subordinate_judgments_sha256: Sha256
    model_response_sha256: Sha256
    raw_independent_ranking: RankedFive
    aggregated_ranking: RankedFive
    compared_places: Annotated[int, Field(strict=True, ge=5)]
    supported_axes: Count
    possible_axes: Annotated[int, Field(strict=True, ge=1)]
    raw_violations: MeasuredViolations
    aggregated_violations: MeasuredViolations

    @model_validator(mode="after")
    def comparable_axes(self) -> Self:
        if len(set(self.raw_independent_ranking)) != 5 or len(set(self.aggregated_ranking)) != 5:
            raise ValueError("axis policy rankings must have five distinct places")
        if self.supported_axes > self.possible_axes:
            raise ValueError("invalid axis coverage")
        return self


class AxisComparisonResults(StrictContract):
    scope: Literal["DEV"] = "DEV"
    dev_manifest_sha256: Sha256
    model: Literal["glm-5.3-flash"] = "glm-5.3-flash"
    prompt_sha256: Sha256
    aggregation_policy_sha256: Sha256
    comparison: Literal["FIXED_SOURCE_SUBORDINATES_MODEL_AND_USER"] = (
        "FIXED_SOURCE_SUBORDINATES_MODEL_AND_USER"
    )
    human_relevance_status: Literal["NOT_MEASURED"] = "NOT_MEASURED"
    rows: Annotated[tuple[AxisComparisonRow, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def unique_scenarios(self) -> Self:
        if len({r.scenario_id for r in self.rows}) != len(self.rows):
            raise ValueError("axis comparison repeats a scenario")
        return self


class ApiUiCase(StrictContract):
    case: Literal["happy_path", "unknown", "photo", "replay", "desktop", "mobile"]
    executed: Annotated[int, Field(strict=True, ge=1)]
    failures: tuple[str, ...]
    artifact_sha256: Annotated[tuple[Sha256, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def measured_execution(self) -> Self:
        if len(self.failures) > self.executed:
            raise ValueError("UI failures exceed executed cases")
        return self


class ApiUiVerificationResults(StrictContract):
    openapi_sha256: Sha256
    frontend_release_sha256: Sha256
    cases: Annotated[tuple[ApiUiCase, ...], Field(min_length=6, max_length=6)]

    @model_validator(mode="after")
    def required_cases(self) -> Self:
        if {case.case for case in self.cases} != set(UI_CASES):
            raise ValueError("API/UI proof requires all six executed journeys/viewports")
        return self


class GroundedPromotionReport(StrictContract):
    schema_version: Literal["grounded-promotion-report.v1"] = "grounded-promotion-report.v1"
    kind: Literal["SOURCE_ABLATION", "AXIS_COMPARISON", "API_UI"]
    candidate_sha256: Sha256
    config_sha256: Sha256
    completed_at: datetime
    result: dict[str, Any]
    outcome: Literal["PASS", "FAIL"]
    failure_count: Count
    report_sha256: Sha256

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        require_utc(self.completed_at, field_name="completed_at")
        if self.kind == "SOURCE_ABLATION":
            result = SourceAblationResults.model_validate(self.result)
            failures = sum(row.violations.failure_count for row in result.rows)
        elif self.kind == "AXIS_COMPARISON":
            paired = AxisComparisonResults.model_validate(self.result)
            # Historical raw-axis problems are comparison observations, not an
            # excuse to fail an otherwise improved candidate's new policy.
            failures = sum(row.aggregated_violations.failure_count for row in paired.rows)
        else:
            ui = ApiUiVerificationResults.model_validate(self.result)
            failures = sum(len(case.failures) for case in ui.cases)
        if self.failure_count != failures or self.outcome != ("PASS" if failures == 0 else "FAIL"):
            raise ValueError("promotion report outcome disagrees with measured violations")
        if self.report_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"report_sha256"})
        ):
            raise ValueError("promotion report hash mismatch")
        return self


class GroundedPromotionGate(StrictContract):
    schema_version: Literal["grounded-promotion-gate.v1"] = "grounded-promotion-gate.v1"
    candidate_sha256: Sha256
    config_sha256: Sha256
    source_ablation_sha256: Sha256
    axis_comparison_sha256: Sha256
    api_ui_verification_sha256: Sha256
    verified_at: datetime
    passed: Literal[True]
    gate_sha256: Sha256

    @model_validator(mode="after")
    def validate_gate(self) -> Self:
        require_utc(self.verified_at, field_name="verified_at")
        if (
            len(
                {
                    self.source_ablation_sha256,
                    self.axis_comparison_sha256,
                    self.api_ui_verification_sha256,
                }
            )
            != 3
        ):
            raise ValueError("promotion requires three distinct actual reports")
        if self.gate_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"gate_sha256"})
        ):
            raise ValueError("promotion gate hash mismatch")
        return self


def validate_promotion_reports(
    gate: GroundedPromotionGate,
    reports: tuple[GroundedPromotionReport, ...],
    *,
    candidate_created_at: datetime,
) -> None:
    expected = {
        "SOURCE_ABLATION": gate.source_ablation_sha256,
        "AXIS_COMPARISON": gate.axis_comparison_sha256,
        "API_UI": gate.api_ui_verification_sha256,
    }
    if len(reports) != 3 or {report.kind for report in reports} != set(expected):
        raise ValueError("promotion reports are missing or repeated")
    for report in reports:
        if (
            report.report_sha256 != expected[report.kind]
            or report.candidate_sha256 != gate.candidate_sha256
            or report.config_sha256 != gate.config_sha256
            or report.outcome != "PASS"
            or report.failure_count != 0
            or not candidate_created_at <= report.completed_at <= gate.verified_at
        ):
            raise ValueError("promotion report candidate, config, outcome or timing mismatch")
    source = next(r for r in reports if r.kind == "SOURCE_ABLATION")
    axis = next(r for r in reports if r.kind == "AXIS_COMPARISON")
    for field in ("dev_manifest_sha256", "model", "prompt_sha256", "aggregation_policy_sha256"):
        if source.result[field] != axis.result[field]:
            raise ValueError("source and axis comparisons use different evaluation authority")
