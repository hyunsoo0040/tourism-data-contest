"""Aggregate-only contracts for deterministic synthetic Phase 3 evaluation."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, Version, require_utc
from itda.domain.canonical import canonical_sha256

UnitMetric = Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
FailedDimension = Literal[
    "macro_mae",
    "plus_minus_one_accuracy",
    "precision_at_3",
    "recall_at_8",
    "manifest_completeness",
]


class Phase3EvaluationVersions(StrictContract):
    data_version: Version
    model_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    model_revision: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    prompt_anchor_version: Version
    preprocessing_version: Version
    scoring_version: Version
    code_git_sha: Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{40}$")]
    config_sha256: Sha256


class Phase3EvaluationThresholds(StrictContract):
    macro_mae_max: Annotated[float, Field(strict=True, ge=0.0, le=4.0)]
    plus_minus_one_accuracy_min: UnitMetric
    precision_at_3_min: UnitMetric
    recall_at_8_min: UnitMetric
    manifest_completeness_min: UnitMetric


class Phase3EvaluationMetrics(StrictContract):
    macro_mae: Annotated[float, Field(strict=True, ge=0.0, le=4.0)]
    plus_minus_one_accuracy: UnitMetric
    precision_at_3: UnitMetric
    recall_at_8: UnitMetric
    manifest_completeness: UnitMetric


class Phase3EvaluationManifest(StrictContract):
    schema_version: Literal["phase3-evaluation-manifest-v1"]
    synthetic_only: Literal[True]
    case_id: StableId
    evidence_status: Literal["EXTERNAL_EVIDENCE_PENDING"]
    approved_protected_evidence: None
    versions: Phase3EvaluationVersions
    thresholds: Phase3EvaluationThresholds
    metrics: Phase3EvaluationMetrics
    generated_at: datetime
    claim_scope: Literal["SYNTHETIC_SOFTWARE_CONTRACT_ONLY"]

    @model_validator(mode="after")
    def validate_generated_at(self) -> Self:
        require_utc(self.generated_at, field_name="generated_at")
        return self


class Phase3EvaluationReport(StrictContract):
    schema_version: Literal["phase3-evaluation-report-v1"] = "phase3-evaluation-report-v1"
    synthetic_only: Literal[True] = True
    case_id: StableId
    status: Literal["THRESHOLDS_PASSED", "THRESHOLDS_FAILED"]
    evidence_status: Literal["EXTERNAL_EVIDENCE_PENDING"]
    claim_scope: Literal["SYNTHETIC_SOFTWARE_CONTRACT_ONLY"]
    input_manifest_sha256: Sha256
    versions: Phase3EvaluationVersions
    thresholds: Phase3EvaluationThresholds
    metrics: Phase3EvaluationMetrics
    failed_dimensions: tuple[FailedDimension, ...]
    generated_at: datetime
    report_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        require_utc(self.generated_at, field_name="generated_at")
        expected_status = "THRESHOLDS_FAILED" if self.failed_dimensions else "THRESHOLDS_PASSED"
        if self.status != expected_status:
            raise ValueError("evaluation report threshold status is inconsistent")
        expected = canonical_sha256(self.model_dump(exclude={"report_sha256"}, mode="json"))
        if self.report_sha256 is None:
            object.__setattr__(self, "report_sha256", expected)
        elif self.report_sha256 != expected:
            raise ValueError("evaluation report digest is stale")
        return self


def build_evaluation_report(manifest: Phase3EvaluationManifest) -> Phase3EvaluationReport:
    thresholds = manifest.thresholds
    metrics = manifest.metrics
    failed: list[FailedDimension] = []
    if metrics.macro_mae > thresholds.macro_mae_max:
        failed.append("macro_mae")
    if metrics.plus_minus_one_accuracy < thresholds.plus_minus_one_accuracy_min:
        failed.append("plus_minus_one_accuracy")
    if metrics.precision_at_3 < thresholds.precision_at_3_min:
        failed.append("precision_at_3")
    if metrics.recall_at_8 < thresholds.recall_at_8_min:
        failed.append("recall_at_8")
    if metrics.manifest_completeness < thresholds.manifest_completeness_min:
        failed.append("manifest_completeness")
    return Phase3EvaluationReport(
        case_id=manifest.case_id,
        status="THRESHOLDS_FAILED" if failed else "THRESHOLDS_PASSED",
        evidence_status=manifest.evidence_status,
        claim_scope=manifest.claim_scope,
        input_manifest_sha256=canonical_sha256(manifest.model_dump(mode="json")),
        versions=manifest.versions,
        thresholds=thresholds,
        metrics=metrics,
        failed_dimensions=tuple(failed),
        generated_at=manifest.generated_at,
    )


__all__ = [
    "Phase3EvaluationManifest",
    "Phase3EvaluationMetrics",
    "Phase3EvaluationReport",
    "Phase3EvaluationThresholds",
    "Phase3EvaluationVersions",
    "build_evaluation_report",
]
