"""Deterministic subordinate-score aggregation with explicit unavailable axes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from itda.contracts.grounded_source import GroundedSourceProfile
from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS
from itda.contracts.mvp_scored_release import MvpScoredProfile
from itda.contracts.source_assessment import (
    AssessmentBundle,
    ClaimKind,
    SourceObservation,
    SupportState,
)
from itda.domain.canonical import canonical_sha256
from itda.pipeline.source_authority import supports_dimension

AGGREGATION_POLICY = {
    "version": "supported-axis-aggregation-v1",
    "subordinate_weights": {f"{axis}{i}": 1 for axis in "HER" for i in range(1, 5)},
    "minimum_supported_subordinates": 2,
    "rounding": "integer-half-up",
    "calibration_status": "UNCALIBRATED_DEV_COMPARISON_REQUIRED",
}
AGGREGATION_POLICY_SHA256 = canonical_sha256(AGGREGATION_POLICY)


def _score_value(observation: SourceObservation) -> int:
    value = observation.value
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("supported rubric value must be an integer")
    return value


def unknown_dimension(key: str, reason: str) -> SourceObservation:
    return SourceObservation(
        key=key,
        claim=ClaimKind.CROWD if key == "M3" else ClaimKind.EXPERIENCE,
        state=SupportState.UNKNOWN,
        value=None,
        evidence=(),
        reference_date=None,
        reason=reason,
    )


def validate_judgment(key: str, observation: SourceObservation) -> SourceObservation:
    observation = SourceObservation.model_validate_json(observation.model_dump_json())
    if key != observation.key or key not in SCORING_DIMENSIONS[3:]:
        raise ValueError("subordinate/trait judgment key mismatch")
    if observation.state == SupportState.UNKNOWN:
        return unknown_dimension(key, observation.reason)
    if any(not supports_dimension(e, key) for e in observation.evidence):
        raise ValueError("source evidence does not authorize the score dimension")
    limit = 4 if key in SCORING_DIMENSIONS[3:15] else 100
    if type(observation.value) is not int or not 0 <= observation.value <= limit:
        raise ValueError("judgment outside rubric range")
    return observation


def aggregate_axis(axis: str, dimensions: Mapping[str, SourceObservation]) -> SourceObservation:
    if axis not in "HER" or len(axis) != 1:
        raise ValueError("unknown experience axis")
    supported = [
        validate_judgment(f"{axis}{i}", dimensions[f"{axis}{i}"])
        for i in range(1, 5)
        if dimensions[f"{axis}{i}"].state != SupportState.UNKNOWN
    ]
    if len(supported) < 2:
        return unknown_dimension(
            axis, "축 계산에 필요한 세부 항목 근거가 부족합니다 (4개 중 최소 2개)."
        )
    numerator = 100 * sum(_score_value(row) for row in supported)
    denominator = 4 * len(supported)
    score = (2 * numerator + denominator) // (2 * denominator)
    evidence = {e.evidence_id: e for row in supported for e in row.evidence}
    return SourceObservation(
        key=axis,
        claim=ClaimKind.EXPERIENCE,
        state=SupportState.INFERENCE,
        value=score,
        evidence=tuple(evidence[key] for key in sorted(evidence)),
        reference_date=min(
            row.reference_date for row in supported if row.reference_date is not None
        ),
        reason=(
            f"{len(supported)}/4개 지원 항목의 동일 가중 평균을 0–100으로 변환했습니다. "
            "나머지는 미확인입니다."
        ),
    )


@dataclass(frozen=True)
class AssessmentBuildResult:
    bundle: AssessmentBundle
    raw_axes: dict[str, int | None]
    axis_deltas: dict[str, int | None]
    supported_subordinate_counts: dict[str, int]
    comparison_basis: str
    aggregation_policy_sha256: str = AGGREGATION_POLICY_SHA256


def build_assessment(
    *,
    profile: MvpScoredProfile | GroundedSourceProfile,
    judgments: Mapping[str, SourceObservation],
    facts: Mapping[str, SourceObservation],
    source_release_sha256: str,
    assessed_at: datetime,
    independent_axes: Mapping[str, int] | None = None,
) -> AssessmentBuildResult:
    if set(judgments) - set(SCORING_DIMENSIONS[3:]):
        raise ValueError("model axes cannot replace deterministic aggregation")
    dimensions = {
        key: validate_judgment(key, judgments[key])
        if key in judgments
        else unknown_dimension(key, "해당 항목의 근거가 제공되지 않았습니다.")
        for key in SCORING_DIMENSIONS[3:]
    }
    axes = {axis: aggregate_axis(axis, dimensions) for axis in "HER"}
    payload = {
        "schema_version": "place-assessment.v1",
        "policy_version": "source-assessment-v1",
        "place_id": profile.place_id,
        "raw_profile_sha256": profile.profile_sha256,
        "source_release_sha256": source_release_sha256,
        "assessed_at": assessed_at.isoformat().replace("+00:00", "Z"),
        "dimensions": {
            key: row.model_dump(mode="json") for key, row in {**axes, **dimensions}.items()
        },
        "facts": {key: row.model_dump(mode="json") for key, row in facts.items()},
    }
    bundle = AssessmentBundle.model_validate(
        {**payload, "bundle_sha256": canonical_sha256(payload)}
    )
    if independent_axes is not None and (
        set(independent_axes) != set("HER")
        or any(type(v) is not int or not 0 <= v <= 100 for v in independent_axes.values())
    ):
        raise ValueError("independent model axes must be exact H/E/R bounded integers")
    raw: dict[str, int | None] = (
        {axis: value for axis, value in independent_axes.items()}
        if independent_axes is not None
        else {
            a: None if isinstance(profile, GroundedSourceProfile) else getattr(profile.scores, a)
            for a in "HER"
        }
    )
    return AssessmentBuildResult(
        bundle=bundle,
        raw_axes=raw,
        axis_deltas={
            a: _score_value(axes[a]) - baseline
            if axes[a].value is not None and baseline is not None
            else None
            for a, baseline in raw.items()
        },
        supported_subordinate_counts={
            a: sum(dimensions[f"{a}{i}"].state != SupportState.UNKNOWN for i in range(1, 5))
            for a in "HER"
        },
        comparison_basis="SAME_ANALYSIS_RESPONSE"
        if independent_axes is not None
        else "NO_INDEPENDENT_ANALYSIS"
        if isinstance(profile, GroundedSourceProfile)
        else "HISTORICAL_RAW_PROFILE",
    )
