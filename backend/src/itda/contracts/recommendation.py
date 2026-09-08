"""Strict public contracts for the no-photo recommendation boundary."""

from __future__ import annotations

import hmac
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import (
    BasisPoints,
    DataSplit,
    ExperienceAxis,
    Score100,
    Sha256,
    StableId,
    StrictContract,
    Version,
    require_utc,
)
from itda.contracts.place_profile import MismatchTraitId, SubattributeId
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY
from itda.domain.canonical import canonical_sha256

# Kept for compatibility with callers that introspect the fusion contract.
_ = CANONICAL_FUSION_POLICY

def _recovery_policy():  # type: ignore[no-untyped-def]
    from itda.contracts.phase5_recovery_policy import CANONICAL_PHASE5_RECOVERY_POLICY

    return CANONICAL_PHASE5_RECOVERY_POLICY


def _recovery_publishability(confidence: int) -> Publishability:
    policy = _recovery_policy()
    if confidence >= policy.ordinary_information_confidence_min:
        return Publishability.PUBLISHABLE
    if confidence >= policy.candidate_confidence_min:
        return Publishability.LIMITED_INFORMATION
    return Publishability.EXCLUDED


def _recovery_recommendation_eligible(confidence: int) -> bool:
    return confidence >= _recovery_policy().candidate_confidence_min


def _half_up(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("half-up division requires nonnegative input")
    return (2 * numerator + denominator) // (2 * denominator)


class RecommendationPublicReason(StrEnum):
    """Closed, low-cardinality public recommendation failure reasons."""

    NO_ACTIVE_SCORED_RELEASE = "NO_ACTIVE_SCORED_RELEASE"
    INSUFFICIENT_ELIGIBLE_CANDIDATES = "INSUFFICIENT_ELIGIBLE_CANDIDATES"
    RECOMMENDATION_REQUEST_CONFLICT = "RECOMMENDATION_REQUEST_CONFLICT"
    INVALID_RECOMMENDATION_OUTPUT = "INVALID_RECOMMENDATION_OUTPUT"
    PREFERENCE_PROFILE_UNAVAILABLE = "PREFERENCE_PROFILE_UNAVAILABLE"
    RECOMMENDATION_RUN_NOT_FOUND = "RECOMMENDATION_RUN_NOT_FOUND"
    RECOMMENDATION_PIN_INVALID = "RECOMMENDATION_PIN_INVALID"
    RECOMMENDATION_PLACE_UNAVAILABLE = "RECOMMENDATION_PLACE_UNAVAILABLE"
    INVALID_RECOMMENDATION_REQUEST = "INVALID_RECOMMENDATION_REQUEST"


class RecommendationRequest(StrictContract):
    """Create request with optional server-owned confirmed-photo authority."""

    request_id: StableId
    preference_profile_id: StableId
    photo_job_id: Sha256 | None = None


class RecommendationErrorDetail(StrictContract):
    code: RecommendationPublicReason
    message_ko: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    request_id: StableId | None = None
    preference_profile_id: StableId | None = None
    release_id: StableId | None = None


class RecommendationErrorResponse(StrictContract):
    detail: RecommendationErrorDetail


class RecommendationRunCreated(StrictContract):
    """Opaque create result used by later release-pinned read operations."""

    schema_version: Literal["itda.recommendation-run-created.v1"] = (
        "itda.recommendation-run-created.v1"
    )
    recommendation_run_id: StableId
    request_id: StableId
    preference_profile_id: StableId
    preference_input_sha256: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9a-f]{64}$"),
    ]


RECOMMENDATION_CONTRACT_VERSION: Version = "recommendation-request-v1"


class TravelConditionId(StrEnum):
    VISIT_DATE_TIME = "VISIT_DATE_TIME"
    COMPANIONS = "COMPANIONS"
    TRANSPORT = "TRANSPORT"
    WALKING = "WALKING"
    INDOOR_OUTDOOR = "INDOOR_OUTDOOR"
    CROWD = "CROWD"


class Publishability(StrEnum):
    PUBLISHABLE = "PUBLISHABLE"
    LIMITED_INFORMATION = "LIMITED_INFORMATION"
    AUDIT_ONLY = "AUDIT_ONLY"
    EXCLUDED = "EXCLUDED"


class EvidenceConfidenceState(StrEnum):
    EVIDENCE_AUDIT_ONLY = "EVIDENCE_AUDIT_ONLY"
    EVIDENCE_LIMITED_MISMATCH_SUPPRESSED = "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED"
    EVIDENCE_LIMITED_MISMATCH_AVAILABLE = "EVIDENCE_LIMITED_MISMATCH_AVAILABLE"
    EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED"


_EVIDENCE_CONFIDENCE_REASON_BY_STATE: dict[EvidenceConfidenceState, str] = {
    EvidenceConfidenceState.EVIDENCE_AUDIT_ONLY: (
        "확인된 근거가 매우 제한되어 참고 정보로만 보여드려요."
    ),
    EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED: (
        "확인된 근거가 제한되어 기대 차이 안내를 생략했어요."
    ),
    EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_AVAILABLE: (
        "확인된 근거 범위에서 기대 차이 안내를 함께 보여드려요."
    ),
    EvidenceConfidenceState.EVIDENCE_SUPPORTED: "확인된 근거 범위에서 안내해요.",
}


def _confidence_state_for_thresholds(
    confidence: int, *, mismatch_available: int, supported: int
) -> tuple[EvidenceConfidenceState, str]:
    if type(confidence) is not int or not 0 <= confidence <= 100:
        raise ValueError("confidence must be an integer from 0 through 100")
    if confidence < 55:
        state = EvidenceConfidenceState.EVIDENCE_AUDIT_ONLY
    elif confidence < mismatch_available:
        state = EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED
    elif confidence < supported:
        state = EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_AVAILABLE
    else:
        state = EvidenceConfidenceState.EVIDENCE_SUPPORTED
    return state, _EVIDENCE_CONFIDENCE_REASON_BY_STATE[state]


def confidence_state_for(confidence: int) -> tuple[EvidenceConfidenceState, str]:
    """Derive legacy confidence copy from the frozen recovery policy."""

    policy = _recovery_policy()
    return _confidence_state_for_thresholds(
        confidence,
        mismatch_available=policy.mismatch_guidance_confidence_min,
        supported=policy.ordinary_information_confidence_min,
    )


def mvp_confidence_state_for(confidence: int) -> tuple[EvidenceConfidenceState, str]:
    return _confidence_state_for_thresholds(confidence, mismatch_available=65, supported=70)


def _validate_confidence_state_reason(
    state: EvidenceConfidenceState,
    reason: str,
) -> None:
    if reason != _EVIDENCE_CONFIDENCE_REASON_BY_STATE[state]:
        raise ValueError("evidence confidence reason does not match its closed state")


class ImageDisplayState(StrEnum):
    ABSENT = "ABSENT"
    RIGHTS_RESTRICTED = "RIGHTS_RESTRICTED"
    DISPLAY_ASSET_AVAILABLE = "DISPLAY_ASSET_AVAILABLE"


class MismatchGuidanceState(StrEnum):
    NO_GUIDANCE = "NO_GUIDANCE"
    GENTLE_DIFFERENCE = "GENTLE_DIFFERENCE"
    MATERIAL_DIFFERENCE = "MATERIAL_DIFFERENCE"
    STRONG_DIFFERENCE = "STRONG_DIFFERENCE"
    SUPPRESSED_LOW_CONFIDENCE = "SUPPRESSED_LOW_CONFIDENCE"


class CandidateExclusionReason(StrEnum):
    NOT_DEV = "NOT_DEV"
    NOT_EXACT_RELEASE_MEMBER = "NOT_EXACT_RELEASE_MEMBER"
    NOT_LOCAL_PROFILE_SCORES = "NOT_LOCAL_PROFILE_SCORES"
    NOT_DEMO_MODEL_DERIVED = "NOT_DEMO_MODEL_DERIVED"
    NOT_PUBLISHABLE = "NOT_PUBLISHABLE"
    NOT_RECOMMENDATION_ELIGIBLE = "NOT_RECOMMENDATION_ELIGIBLE"
    HARD_DUPLICATE = "HARD_DUPLICATE"
    CANNOT_COAPPEAR = "CANNOT_COAPPEAR"


class SavedPlaceState(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"


class TravelConditionWeights(StrictContract):
    visit_date_time: BasisPoints = 400
    companions: BasisPoints = 350
    transport: BasisPoints = 350
    walking: BasisPoints = 350
    indoor_outdoor: BasisPoints = 300
    crowd: BasisPoints = 250

    @model_validator(mode="after")
    def require_frozen_weights(self) -> Self:
        if self.model_dump(mode="json") != {
            "visit_date_time": 400,
            "companions": 350,
            "transport": 350,
            "walking": 350,
            "indoor_outdoor": 300,
            "crowd": 250,
        }:
            raise ValueError("travel-condition weights must match the exact frozen configuration")
        return self


class RecommendationConfig(StrictContract):
    schema_version: Literal["recommendation-config.v3"] = "recommendation-config.v3"
    kernel_version: Literal["recommendation-kernel-v3"] = "recommendation-kernel-v3"
    experience_fit_bp: BasisPoints = 8_000
    travel_condition_fit_bp: BasisPoints = 2_000
    condition_weights: TravelConditionWeights = TravelConditionWeights()
    mismatch_axis_bp: BasisPoints = 6_500
    mismatch_trait_bp: BasisPoints = 3_500
    important_trait_difference_threshold: Score100 = 70
    important_trait_floor: Score100 = 50
    mismatch_guidance_thresholds: tuple[Score100, Score100, Score100] = (30, 45, 60)
    mismatch_warning_confidence_min: Score100 = 65
    relevance_rerank_bp: BasisPoints = 8_500
    diversity_rerank_bp: BasisPoints = 1_500
    top_k: Literal[5] = 5
    config_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_frozen_policy_and_digest(self) -> Self:
        if self.experience_fit_bp + self.travel_condition_fit_bp != 10_000:
            raise ValueError("fit weights must total 10000")
        if sum(self.condition_weights.model_dump(mode="json").values()) != 2_000:
            raise ValueError("travel-condition weights must total 2000")
        if self.mismatch_axis_bp + self.mismatch_trait_bp != 10_000:
            raise ValueError("mismatch weights must total 10000")
        if self.relevance_rerank_bp + self.diversity_rerank_bp != 10_000:
            raise ValueError("rerank weights must total 10000")
        if self.mismatch_guidance_thresholds != (30, 45, 60):
            raise ValueError("mismatch guidance thresholds must be exactly 30, 45, 60")
        policy_payload = self.model_dump(mode="json", exclude={"config_sha256"})
        expected_policy = {
            "schema_version": "recommendation-config.v3",
            "kernel_version": "recommendation-kernel-v3",
            "experience_fit_bp": 8_000,
            "travel_condition_fit_bp": 2_000,
            "condition_weights": {
                "visit_date_time": 400,
                "companions": 350,
                "transport": 350,
                "walking": 350,
                "indoor_outdoor": 300,
                "crowd": 250,
            },
            "mismatch_axis_bp": 6_500,
            "mismatch_trait_bp": 3_500,
            "important_trait_difference_threshold": 70,
            "important_trait_floor": 50,
            "mismatch_guidance_thresholds": [30, 45, 60],
            "mismatch_warning_confidence_min": 65,
            "relevance_rerank_bp": 8_500,
            "diversity_rerank_bp": 1_500,
            "top_k": 5,
        }
        if policy_payload != expected_policy:
            raise ValueError("recommendation policy must match the exact frozen configuration")
        expected = canonical_sha256(policy_payload)
        if self.config_sha256 is None:
            object.__setattr__(self, "config_sha256", expected)
        elif not hmac.compare_digest(self.config_sha256, expected):
            raise ValueError("recommendation configuration digest drifted")
        return self


CANONICAL_RECOMMENDATION_CONFIG = RecommendationConfig()


class PreferenceAxisTarget(StrictContract):
    axis: ExperienceAxis
    value: Score100


class PreferenceTraitTarget(StrictContract):
    trait_id: MismatchTraitId
    value: Score100
    important: StrictBool


class TravelConditionTarget(StrictContract):
    condition_id: TravelConditionId
    value: Score100


class RecommendationPreference(StrictContract):
    profile_id: StableId
    input_sha256: Sha256
    axis_targets: tuple[PreferenceAxisTarget, PreferenceAxisTarget, PreferenceAxisTarget]
    trait_targets: tuple[
        PreferenceTraitTarget,
        PreferenceTraitTarget,
        PreferenceTraitTarget,
        PreferenceTraitTarget,
        PreferenceTraitTarget,
        PreferenceTraitTarget,
    ]
    condition_targets: tuple[
        TravelConditionTarget,
        TravelConditionTarget,
        TravelConditionTarget,
        TravelConditionTarget,
        TravelConditionTarget,
        TravelConditionTarget,
    ]

    @model_validator(mode="after")
    def require_canonical_order(self) -> Self:
        if tuple(row.axis for row in self.axis_targets) != tuple(ExperienceAxis):
            raise ValueError("preference axes must use canonical H-E-R order")
        if tuple(row.trait_id for row in self.trait_targets) != tuple(MismatchTraitId):
            raise ValueError("preference traits must use canonical M1-M6 order")
        if tuple(row.condition_id for row in self.condition_targets) != tuple(TravelConditionId):
            raise ValueError("travel conditions must use canonical Phase 1 order")
        return self


class EvidenceSnippet(StrictContract):
    evidence_id: StableId
    excerpt_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    source_label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    attribution_ko: Annotated[str, Field(strict=True, min_length=1, max_length=180)]
    contest_use_scope: Literal["noncommercial_contest_demo_evaluation"]
    contest_rights_qualified: Literal[True]
    reference_date: date


class MvpEvidenceSnippet(StrictContract):
    schema_version: Literal["mvp-evidence-snippet.v1"] = "mvp-evidence-snippet.v1"
    evidence_id: StableId
    excerpt_ko: Annotated[str, Field(strict=True, min_length=1, max_length=4_000)]
    source_label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    attribution_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    reference_date: date
    provider: Literal["TOUR_API", "ODII"]
    official_dataset_id: Literal["15101578", "15101971"]
    official_license_url: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    license_type: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    source_response_sha256: Sha256
    permission_metadata_sha256: Sha256
    evidence_sha256: Sha256
    usage_state: Literal["STRICT_PUBLIC_USAGE_ALLOWED"]


PublicEvidenceSnippet = EvidenceSnippet | MvpEvidenceSnippet


class PlaceAxisSnapshot(StrictContract):
    axis: ExperienceAxis
    value: Score100
    evidence_ids: Annotated[tuple[StableId, ...], Field(min_length=1, max_length=8)]


class PlaceSubattributeSnapshot(StrictContract):
    attribute_id: SubattributeId
    value: Annotated[int, Field(strict=True, ge=0, le=4)]
    evidence_ids: Annotated[tuple[StableId, ...], Field(min_length=1, max_length=8)]


class PlaceTraitSnapshot(StrictContract):
    trait_id: MismatchTraitId
    value: Score100
    evidence_ids: Annotated[tuple[StableId, ...], Field(min_length=1, max_length=8)]


class PlaceConditionSnapshot(StrictContract):
    condition_id: TravelConditionId
    value: Score100
    evidence_ids: Annotated[tuple[StableId, ...], Field(min_length=1, max_length=8)]


class RecommendationCandidate(StrictContract):
    place_id: StableId
    place_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    split: DataSplit
    exact_release_member: StrictBool
    profile_score_truth: StableId
    analysis_origin: StableId
    publishability: Publishability
    recommendation_eligible: StrictBool
    profile_sha256: Sha256
    duplicate_group_id: StableId | None
    overall_confidence: Score100
    axis_scores: tuple[PlaceAxisSnapshot, PlaceAxisSnapshot, PlaceAxisSnapshot]
    subattributes: tuple[
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
        PlaceSubattributeSnapshot,
    ]
    mismatch_traits: tuple[
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
    ]
    condition_scores: tuple[
        PlaceConditionSnapshot,
        PlaceConditionSnapshot,
        PlaceConditionSnapshot,
        PlaceConditionSnapshot,
        PlaceConditionSnapshot,
        PlaceConditionSnapshot,
    ]
    evidence: Annotated[tuple[PublicEvidenceSnippet, ...], Field(min_length=1, max_length=64)]
    reference_date: date
    popularity: Annotated[int, Field(strict=True, ge=0)]
    source_volume: Annotated[int, Field(strict=True, ge=0)]
    image_state: ImageDisplayState

    @model_validator(mode="after")
    def require_complete_canonical_snapshot(self) -> Self:
        if tuple(row.axis for row in self.axis_scores) != tuple(ExperienceAxis):
            raise ValueError("candidate axes must use canonical H-E-R order")
        if tuple(row.attribute_id for row in self.subattributes) != tuple(SubattributeId):
            raise ValueError("candidate subattributes must use canonical H1-R4 order")
        if tuple(row.trait_id for row in self.mismatch_traits) != tuple(MismatchTraitId):
            raise ValueError("candidate traits must use canonical M1-M6 order")
        if tuple(row.condition_id for row in self.condition_scores) != tuple(TravelConditionId):
            raise ValueError("candidate conditions must use canonical Phase 1 order")
        evidence_ids = tuple(row.evidence_id for row in self.evidence)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("candidate evidence ids must be unique")
        known = set(evidence_ids)
        referenced = {
            evidence_id
            for row in (
                *self.axis_scores,
                *self.subattributes,
                *self.mismatch_traits,
                *self.condition_scores,
            )
            for evidence_id in row.evidence_ids
        }
        unknown = referenced - known
        if unknown:
            raise ValueError(f"unknown evidence id: {sorted(unknown)[0]}")
        if self.split is DataSplit.PUBLIC:
            if self.reference_date != max(row.reference_date for row in self.evidence):
                raise ValueError("public candidate reference date must be the latest evidence date")
        elif any(row.reference_date != self.reference_date for row in self.evidence):
            raise ValueError("candidate evidence must use the exact public reference date")
        if self.split is DataSplit.PUBLIC:
            expected_publishability = (
                Publishability.AUDIT_ONLY
                if self.overall_confidence < 55
                else Publishability.LIMITED_INFORMATION
                if self.overall_confidence < 70
                else Publishability.PUBLISHABLE
            )
            expected_eligible = True
        else:
            expected_publishability = _recovery_publishability(self.overall_confidence)
            expected_eligible = _recovery_recommendation_eligible(self.overall_confidence)
        if self.publishability is not expected_publishability:
            raise ValueError("candidate publishability drifted from confidence policy")
        if self.recommendation_eligible != expected_eligible:
            raise ValueError("candidate eligibility drifted from confidence policy")
        return self


class AxisContribution(StrictContract):
    contribution_id: StableId
    axis: ExperienceAxis
    expected_value: Score100
    place_value: Score100
    absolute_difference: Score100
    fit_score: Score100


class ConditionContribution(StrictContract):
    contribution_id: StableId
    condition_id: TravelConditionId
    expected_value: Score100
    place_value: Score100
    absolute_difference: Score100
    fit_score: Score100
    total_score_weight_bp: BasisPoints
    weighted_numerator: Annotated[int, Field(strict=True, ge=0)]


class ScoreContribution(StrictContract):
    axis_components: tuple[AxisContribution, AxisContribution, AxisContribution]
    condition_components: tuple[
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
    ]
    experience_fit_score: Score100
    travel_condition_fit_score: Score100
    relevance_score: Score100
    relevance_numerator: Annotated[int, Field(strict=True, ge=0)]
    diversity_novelty_score: Score100
    rerank_score: Score100
    rerank_numerator: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def require_fixed_point_trace(self) -> Self:
        if tuple(row.axis for row in self.axis_components) != tuple(ExperienceAxis):
            raise ValueError("axis contributions must use canonical H-E-R order")
        if tuple(row.condition_id for row in self.condition_components) != tuple(TravelConditionId):
            raise ValueError("condition contributions must use canonical Phase 1 order")
        if any(
            row.absolute_difference != abs(row.expected_value - row.place_value)
            or row.fit_score != 100 - row.absolute_difference
            for row in self.axis_components
        ):
            raise ValueError("axis contribution arithmetic drifted")
        expected_weights = (400, 350, 350, 350, 300, 250)
        if any(
            row.absolute_difference != abs(row.expected_value - row.place_value)
            or row.fit_score != 100 - row.absolute_difference
            or row.total_score_weight_bp != weight
            or row.weighted_numerator != row.fit_score * weight
            for row, weight in zip(self.condition_components, expected_weights, strict=True)
        ):
            raise ValueError("condition contribution arithmetic drifted")
        if self.experience_fit_score != _half_up(
            sum(row.fit_score for row in self.axis_components), 3
        ):
            raise ValueError("experience fit trace drifted")
        expected_condition_numerator = sum(
            row.weighted_numerator for row in self.condition_components
        )
        if self.travel_condition_fit_score != _half_up(expected_condition_numerator, 2_000):
            raise ValueError("travel-condition fit trace drifted")
        expected_relevance_numerator = (
            self.experience_fit_score * 8_000 + self.travel_condition_fit_score * 2_000
        )
        if (
            self.relevance_numerator != expected_relevance_numerator
            or self.relevance_score != _half_up(expected_relevance_numerator, 10_000)
        ):
            raise ValueError("relevance contribution arithmetic drifted")
        expected_rerank_numerator = (
            self.relevance_score * 8_500 + self.diversity_novelty_score * 1_500
        )
        if self.rerank_numerator != expected_rerank_numerator or self.rerank_score != _half_up(
            expected_rerank_numerator, 10_000
        ):
            raise ValueError("rerank contribution arithmetic drifted")
        return self


class MismatchGuidance(StrictContract):
    raw_score: Score100
    effective_score: Score100
    axis_distance: Score100
    trait_distance: Score100
    important_trait_floor_applied: StrictBool
    state: MismatchGuidanceState
    template_id: StableId | None
    message_ko: Annotated[str, Field(strict=True, min_length=1, max_length=200)] | None
    suppression_reason: Literal["CONFIDENCE_BELOW_65"] | None

    @model_validator(mode="after")
    def require_state_payload(self) -> Self:
        expected_raw = _half_up(
            self.axis_distance * 6_500 + self.trait_distance * 3_500,
            10_000,
        )
        expected_effective = (
            max(expected_raw, 50) if self.important_trait_floor_applied else expected_raw
        )
        if self.raw_score != expected_raw or self.effective_score != expected_effective:
            raise ValueError("mismatch arithmetic drifted")
        if self.state is MismatchGuidanceState.SUPPRESSED_LOW_CONFIDENCE:
            if (
                self.suppression_reason != "CONFIDENCE_BELOW_65"
                or self.template_id is not None
                or self.message_ko is not None
            ):
                raise ValueError(
                    "suppressed mismatch must remain message-free with an exact reason"
                )
        else:
            if self.effective_score < 30 and self.state is not MismatchGuidanceState.NO_GUIDANCE:
                raise ValueError("mismatch below 30 cannot produce guidance")
            if self.effective_score >= 30 and self.state is MismatchGuidanceState.NO_GUIDANCE:
                raise ValueError("mismatch at or above 30 requires guidance or suppression")
            if self.suppression_reason is not None:
                raise ValueError("non-suppressed mismatch cannot carry a suppression reason")
        if self.state is MismatchGuidanceState.NO_GUIDANCE:
            if self.template_id is not None or self.message_ko is not None:
                raise ValueError("no-guidance mismatch must remain message-free")
        elif self.state is not MismatchGuidanceState.SUPPRESSED_LOW_CONFIDENCE:
            if self.template_id is None or self.message_ko is None:
                raise ValueError("visible mismatch guidance requires a bounded template")
            bounds = {
                MismatchGuidanceState.GENTLE_DIFFERENCE: range(30, 45),
                MismatchGuidanceState.MATERIAL_DIFFERENCE: range(45, 60),
                MismatchGuidanceState.STRONG_DIFFERENCE: range(60, 101),
            }
            if self.effective_score not in bounds[self.state]:
                raise ValueError("mismatch guidance state does not match its threshold")
        return self


class ExplanationLink(StrictContract):
    contribution_id: StableId
    place_attribute_id: StableId
    evidence_id: StableId
    reference_date: date
    template_id: StableId
    message_ko: Annotated[str, Field(strict=True, min_length=1, max_length=200)]


class CandidateExclusion(StrictContract):
    place_id: StableId
    reason: CandidateExclusionReason


class DuplicateDecision(StrictContract):
    duplicate_group_id: StableId
    kept_place_id: StableId
    suppressed_place_ids: Annotated[
        tuple[StableId, ...],
        Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    ]

    @model_validator(mode="after")
    def require_unique_suppressed_places(self) -> Self:
        if len(self.suppressed_place_ids) != len(set(self.suppressed_place_ids)):
            raise ValueError("suppressed_place_ids must be unique")
        return self


class CandidateScoreTrace(StrictContract):
    place_id: StableId
    relevance_score: Score100
    experience_fit_score: Score100
    travel_condition_fit_score: Score100
    contribution: ScoreContribution
    mismatch: MismatchGuidance

    @model_validator(mode="after")
    def require_complete_contribution(self) -> Self:
        if (
            self.relevance_score != self.contribution.relevance_score
            or self.experience_fit_score != self.contribution.experience_fit_score
            or self.travel_condition_fit_score != self.contribution.travel_condition_fit_score
        ):
            raise ValueError("candidate score summary must match its complete contribution")
        return self


class DiversityCandidateScore(StrictContract):
    place_id: StableId
    relevance_score: Score100
    novelty_score: Score100
    combined_score: Score100
    suppression_reason: Literal["CANNOT_COAPPEAR"] | None = None
    suppressed_by_place_id: StableId | None = None

    @model_validator(mode="after")
    def require_frozen_rerank(self) -> Self:
        expected = _half_up(self.relevance_score * 8_500 + self.novelty_score * 1_500, 10_000)
        if self.combined_score != expected:
            raise ValueError("diversity candidate score drifted")
        if self.suppression_reason is None and self.suppressed_by_place_id is not None:
            raise ValueError("unsuppressed candidate cannot carry a suppression owner")
        if self.suppression_reason is not None and self.suppressed_by_place_id is None:
            raise ValueError("suppressed candidate requires a suppression owner")
        if self.suppressed_by_place_id == self.place_id:
            raise ValueError("candidate cannot suppress itself")
        return self

    @property
    def is_suppressed(self) -> bool:
        return self.suppression_reason is not None


class RecommendationAuthorityTrace(StrictContract):
    """Legacy recovery authority retained for v1 replay."""

    recovery_policy_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    cannot_coappear_authority_sha256: Sha256
    activation_suite_sha256: Sha256
    contrast_suite_sha256: Sha256

    @model_validator(mode="after")
    def require_current_recovery_authority(self) -> Self:
        policy = _recovery_policy()
        if (
            self.recovery_policy_sha256 != policy.policy_sha256
            or self.hard_duplicate_adjudication_sha256 != policy.hard_duplicate_adjudication_sha256
            or self.activation_suite_sha256 != policy.activation_suite_sha256
            or self.contrast_suite_sha256 != policy.contrast_suite_sha256
            or len(self.cannot_coappear_authority_sha256) != 64
        ):
            raise ValueError("recommendation recovery authority drifted")
        return self


class MvpRecommendationAuthorityTrace(StrictContract):
    release_sha256: Sha256
    membership_sha256: Sha256
    relation_sha256: Sha256
    candidate_sha256: Sha256
    config_sha256: Sha256
    kernel_version: Version


def public_relation_sha256(place_ids: tuple[str, ...], pairs: tuple[tuple[str, str], ...]) -> str:
    return canonical_sha256(
        {
            "place_ids": list(place_ids),
            "pairs": [list(pair) for pair in pairs],
        }
    )


class PublicRelationAuthority(StrictContract):
    relation_sha256: Sha256
    place_ids: Annotated[tuple[StableId, ...], Field(min_length=80, max_length=100)]
    pairs: tuple[tuple[StableId, StableId], ...]

    @model_validator(mode="after")
    def validate_relations(self) -> Self:
        if self.place_ids != tuple(sorted(self.place_ids)):
            raise ValueError("public relation place IDs must use canonical order")
        known = set(self.place_ids)
        if any(
            left >= right or left not in known or right not in known for left, right in self.pairs
        ):
            raise ValueError("public relation endpoints are invalid")
        if self.pairs != tuple(sorted(self.pairs)) or len(self.pairs) != len(set(self.pairs)):
            raise ValueError("public relation pairs must use unique canonical order")
        if self.relation_sha256 != public_relation_sha256(self.place_ids, self.pairs):
            raise ValueError("public relation hash does not match canonical membership and pairs")
        return self

    def forbids(self, left: str, right: str) -> bool:
        return (min(left, right), max(left, right)) in self.pairs


class DiversityStep(StrictContract):
    rank: Annotated[int, Field(strict=True, ge=1, le=5)]
    selected_place_id: StableId
    relevance_score: Score100
    novelty_score: Score100
    combined_score: Score100
    considered: Annotated[tuple[DiversityCandidateScore, ...], Field(min_length=1)]
    suppressed_place_ids: tuple[StableId, ...] = ()

    @model_validator(mode="after")
    def require_suppression_trace(self) -> Self:
        considered_by_id = {row.place_id: row for row in self.considered}
        suppressed = tuple(self.suppressed_place_ids)
        if len(suppressed) != len(set(suppressed)):
            raise ValueError("diversity suppressed places must be unique")
        if any(place_id not in considered_by_id for place_id in suppressed):
            raise ValueError("diversity suppression must reference considered candidates")
        if self.selected_place_id in suppressed:
            raise ValueError("selected place cannot be suppressed")
        for place_id, row in considered_by_id.items():
            if row.is_suppressed != (place_id in suppressed):
                raise ValueError("diversity suppression decision drifted")
        return self

    @property
    def active_considered(self) -> tuple[DiversityCandidateScore, ...]:
        return tuple(row for row in self.considered if not row.is_suppressed)

    @property
    def suppression_decisions(self) -> tuple[DiversityCandidateScore, ...]:
        return tuple(row for row in self.considered if row.is_suppressed)

    @model_validator(mode="after")
    def require_selected_considered_score(self) -> Self:
        matches = tuple(row for row in self.considered if row.place_id == self.selected_place_id)
        if len(matches) != 1:
            raise ValueError("diversity selection must occur exactly once in considered rows")
        selected = matches[0]
        if selected.is_suppressed:
            raise ValueError("diversity selection cannot be suppressed")
        if (
            self.relevance_score,
            self.novelty_score,
            self.combined_score,
        ) != (
            selected.relevance_score,
            selected.novelty_score,
            selected.combined_score,
        ):
            raise ValueError("diversity selected score drifted")
        if len({row.place_id for row in self.considered}) != len(self.considered):
            raise ValueError("diversity considered rows must be unique")
        return self


class RecommendationItem(StrictContract):
    rank: Annotated[int, Field(strict=True, ge=1, le=5)]
    place_id: StableId
    place_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    fit_score: Score100
    evidence_confidence_state: EvidenceConfidenceState
    evidence_confidence_reason_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    mismatch: MismatchGuidance
    contribution: ScoreContribution
    axis_scores: tuple[PlaceAxisSnapshot, PlaceAxisSnapshot, PlaceAxisSnapshot]
    explanations: Annotated[tuple[ExplanationLink, ...], Field(min_length=2, max_length=6)]
    evidence: Annotated[tuple[EvidenceSnippet, ...], Field(min_length=1, max_length=6)]
    reference_date: date
    image_state: ImageDisplayState

    @model_validator(mode="after")
    def require_confidence_state_reason(self) -> Self:
        _validate_confidence_state_reason(
            self.evidence_confidence_state,
            self.evidence_confidence_reason_ko,
        )
        return self

    @model_validator(mode="after")
    def require_explanation_integrity(self) -> Self:
        contribution_ids = {row.contribution_id for row in self.contribution.axis_components} | {
            row.contribution_id for row in self.contribution.condition_components
        }
        unknown = {row.contribution_id for row in self.explanations} - contribution_ids
        if unknown:
            raise ValueError(f"unknown contribution: {sorted(unknown)[0]}")
        axis_by_id = {row.axis.value: row for row in self.axis_scores}
        evidence_by_id = {row.evidence_id: row for row in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("item evidence ids must be unique")
        for explanation in self.explanations:
            axis = axis_by_id.get(explanation.place_attribute_id)
            if axis is None or explanation.evidence_id not in axis.evidence_ids:
                raise ValueError("explanation must reference an actual place attribute evidence id")
            if explanation.reference_date != self.reference_date:
                raise ValueError("explanation reference date drifted")
            evidence = evidence_by_id.get(explanation.evidence_id)
            if evidence is None or evidence.reference_date != self.reference_date:
                raise ValueError("explanation evidence attribution is missing or stale")
        if set(evidence_by_id) != {row.evidence_id for row in self.explanations}:
            raise ValueError("item evidence must exactly resolve displayed explanations")
        explanation_keys = {(row.contribution_id, row.evidence_id) for row in self.explanations}
        if len(explanation_keys) != len(self.explanations):
            raise ValueError("explanations must be referentially unique")
        return self


class MvpRecommendationItem(StrictContract):
    rank: Annotated[int, Field(strict=True, ge=1, le=5)]
    place_id: StableId
    relevance_score: Score100
    novelty_score: Score100
    combined_score: Score100


class MvpRecommendationPublicItem(StrictContract):
    rank: Annotated[int, Field(strict=True, ge=1, le=5)]
    place_id: StableId
    place_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    fit_score: Score100
    evidence_confidence_state: EvidenceConfidenceState
    evidence_confidence_reason_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    mismatch: MismatchGuidance
    contribution: ScoreContribution
    axis_scores: tuple[PlaceAxisSnapshot, PlaceAxisSnapshot, PlaceAxisSnapshot]
    explanations: Annotated[tuple[ExplanationLink, ...], Field(min_length=2, max_length=6)]
    evidence: Annotated[tuple[MvpEvidenceSnippet, ...], Field(min_length=1, max_length=6)]
    reference_date: date
    image_state: ImageDisplayState

    @model_validator(mode="after")
    def validate_mvp_item(self) -> Self:
        _validate_confidence_state_reason(
            self.evidence_confidence_state,
            self.evidence_confidence_reason_ko,
        )
        contribution_ids = {row.contribution_id for row in self.contribution.axis_components} | {
            row.contribution_id for row in self.contribution.condition_components
        }
        if {row.contribution_id for row in self.explanations} - contribution_ids:
            raise ValueError("MVP explanation references an unknown contribution")
        axis_by_id = {row.axis.value: row for row in self.axis_scores}
        evidence_by_id = {row.evidence_id: row for row in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("MVP item evidence ids must be unique")
        for explanation in self.explanations:
            axis = axis_by_id.get(explanation.place_attribute_id)
            evidence = evidence_by_id.get(explanation.evidence_id)
            if axis is None or explanation.evidence_id not in axis.evidence_ids:
                raise ValueError("MVP explanation must reference an actual axis evidence id")
            if evidence is None or explanation.reference_date != evidence.reference_date:
                raise ValueError("MVP explanation reference date must match its evidence")
        if set(evidence_by_id) != {row.evidence_id for row in self.explanations}:
            raise ValueError("MVP item evidence must exactly resolve displayed explanations")
        if self.reference_date != max(row.reference_date for row in self.evidence):
            raise ValueError("MVP item reference date must be the latest displayed evidence date")
        return self


class PhotoTraitFitComponent(StrictContract):
    trait_id: MismatchTraitId
    expected: Score100
    actual: Score100
    fit: Score100

    @model_validator(mode="after")
    def validate_fit(self) -> Self:
        if self.fit != 100 - abs(self.expected - self.actual):
            raise ValueError("photo trait fit component drifted")
        return self


class PhotoRecommendationScoreTrace(StrictContract):
    base_relevance: Score100
    trait_components: tuple[
        PhotoTraitFitComponent,
        PhotoTraitFitComponent,
        PhotoTraitFitComponent,
        PhotoTraitFitComponent,
        PhotoTraitFitComponent,
        PhotoTraitFitComponent,
    ]
    photo_trait_fit: Score100
    effective_relevance: Score100
    explanation_ko: Annotated[str, Field(strict=True, min_length=1, max_length=160)]

    @model_validator(mode="after")
    def validate_photo_score(self) -> Self:
        if tuple(row.trait_id for row in self.trait_components) != tuple(MismatchTraitId):
            raise ValueError("photo trait components must use canonical M1-M6 order")
        expected_fit = _half_up(sum(row.fit for row in self.trait_components), 6)
        expected_relevance = _half_up(
            self.base_relevance * 6_500 + expected_fit * 3_500,
            10_000,
        )
        if self.photo_trait_fit != expected_fit or self.effective_relevance != expected_relevance:
            raise ValueError("photo recommendation score drifted")
        return self


class PhotoRecommendationAuthorityTrace(MvpRecommendationAuthorityTrace):
    photo_projection_version: Literal["photo-projection-v1"]
    photo_projection_policy_sha256: Sha256
    photo_projection_output_sha256: Sha256
    confirmation_draft_sha256: Sha256
    photo_job_reference_sha256: Sha256
    images_count: Annotated[int, Field(strict=True, ge=1, le=3)]
    included_count: Annotated[int, Field(strict=True, ge=1, le=6)]


class PhotoMvpRecommendationRun(StrictContract):
    schema_version: Literal["recommendation-run.v3"] = "recommendation-run.v3"
    run_id: StableId
    input_digest: Sha256
    preference: RecommendationPreference
    authority: PhotoRecommendationAuthorityTrace
    candidate_place_ids: Annotated[tuple[StableId, ...], Field(min_length=80, max_length=100)]
    items: tuple[
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
    ]
    photo_scores: tuple[
        PhotoRecommendationScoreTrace,
        PhotoRecommendationScoreTrace,
        PhotoRecommendationScoreTrace,
        PhotoRecommendationScoreTrace,
        PhotoRecommendationScoreTrace,
    ]
    created_at: datetime
    canonical_sha256: Sha256

    @model_validator(mode="after")
    def validate_photo_run(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.candidate_place_ids != tuple(sorted(self.candidate_place_ids)):
            raise ValueError("photo recommendation candidate IDs must use canonical order")
        if len(self.candidate_place_ids) != len(set(self.candidate_place_ids)):
            raise ValueError("photo recommendation candidate IDs must be unique")
        if tuple(row.rank for row in self.items) != (1, 2, 3, 4, 5):
            raise ValueError("photo recommendation items must use ranks 1..5")
        if len({row.place_id for row in self.items}) != 5:
            raise ValueError("photo recommendation requires five unique items")
        if any(row.place_id not in self.candidate_place_ids for row in self.items):
            raise ValueError("photo recommendation item is outside the candidate set")
        if tuple(row.fit_score for row in self.items) != tuple(
            row.effective_relevance for row in self.photo_scores
        ):
            raise ValueError("photo recommendation item scores drifted")
        if tuple(row.contribution.relevance_score for row in self.items) != tuple(
            row.base_relevance for row in self.photo_scores
        ):
            raise ValueError("photo recommendation base scores drifted")
        if self.input_digest != canonical_sha256(
            {
                "preference": self.preference.model_dump(mode="json"),
                "authority": self.authority.model_dump(mode="json"),
            }
        ):
            raise ValueError("photo recommendation input binding drifted")
        deterministic = self.model_dump(
            mode="json", exclude={"created_at", "canonical_sha256", "run_id"}
        )
        expected = canonical_sha256(deterministic)
        if self.canonical_sha256 != expected:
            raise ValueError("photo recommendation digest drifted")
        if self.run_id != f"recommendation-run:{expected[:32]}":
            raise ValueError("photo recommendation run identity drifted")
        return self


class MvpRecommendationRun(StrictContract):
    schema_version: Literal["recommendation-run.v2"] = "recommendation-run.v2"
    run_id: StableId
    input_digest: Sha256
    preference: RecommendationPreference
    authority: MvpRecommendationAuthorityTrace
    candidate_place_ids: Annotated[tuple[StableId, ...], Field(min_length=80, max_length=100)]
    items: tuple[
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
        MvpRecommendationPublicItem,
    ]
    created_at: datetime
    canonical_sha256: Sha256

    @model_validator(mode="after")
    def validate_mvp_run(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.candidate_place_ids != tuple(sorted(self.candidate_place_ids)):
            raise ValueError("MVP candidate place IDs must use canonical order")
        if len(self.candidate_place_ids) != len(set(self.candidate_place_ids)):
            raise ValueError("MVP candidate place IDs must be unique")
        if tuple(row.rank for row in self.items) != (1, 2, 3, 4, 5):
            raise ValueError("MVP recommendation items must use ranks 1..5")
        if len({row.place_id for row in self.items}) != 5:
            raise ValueError("MVP recommendation requires five unique items")
        if any(row.place_id not in self.candidate_place_ids for row in self.items):
            raise ValueError("MVP item is outside the candidate set")
        if self.input_digest != canonical_sha256(
            {
                "preference": self.preference.model_dump(mode="json"),
                "authority": self.authority.model_dump(mode="json"),
            }
        ):
            raise ValueError("MVP recommendation input binding drifted")
        deterministic = self.model_dump(
            mode="json", exclude={"created_at", "canonical_sha256", "run_id"}
        )
        expected = canonical_sha256(deterministic)
        if self.canonical_sha256 != expected:
            raise ValueError("MVP recommendation digest drifted")
        if self.run_id != f"recommendation-run:{expected[:32]}":
            raise ValueError("MVP recommendation run identity drifted")
        return self


class RecommendationRun(StrictContract):
    schema_version: Literal["recommendation-run.v1"] = "recommendation-run.v1"
    run_id: StableId
    input_digest: Sha256
    release_sha256: Sha256
    canonical_membership_sha256: Sha256
    config_sha256: Sha256
    kernel_version: Version
    candidate_set_digest: Sha256
    authority: RecommendationAuthorityTrace
    candidate_place_ids: Annotated[tuple[StableId, ...], Field(min_length=1, max_length=36)]
    exclusions: tuple[CandidateExclusion, ...]
    duplicate_decisions: tuple[DuplicateDecision, ...]
    scored_candidates: Annotated[
        tuple[CandidateScoreTrace, ...], Field(min_length=5, max_length=36)
    ]
    diversity_steps: tuple[
        DiversityStep, DiversityStep, DiversityStep, DiversityStep, DiversityStep
    ]
    items: tuple[
        RecommendationItem,
        RecommendationItem,
        RecommendationItem,
        RecommendationItem,
        RecommendationItem,
    ]
    ndcg_status: Literal["NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS"]
    ndcg_denominator: Literal[0]
    created_at: datetime
    canonical_sha256: Sha256

    @model_validator(mode="after")
    def require_complete_canonical_receipt(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if tuple(item.rank for item in self.items) != (1, 2, 3, 4, 5):
            raise ValueError("items must have canonical ranks 1..5")
        item_ids = tuple(item.place_id for item in self.items)
        if len(set(item_ids)) != 5:
            raise ValueError("items must contain five unique places")
        if tuple(step.rank for step in self.diversity_steps) != (1, 2, 3, 4, 5):
            raise ValueError("diversity steps must have canonical ranks 1..5")
        if tuple(step.selected_place_id for step in self.diversity_steps) != item_ids:
            raise ValueError("diversity steps must reconstruct final item order")
        RecommendationAuthorityTrace.model_validate(self.authority.model_dump(mode="json"))
        policy = _recovery_policy()
        if self.authority.recovery_policy_sha256 != policy.policy_sha256:
            raise ValueError("recommendation recovery policy trace drifted")
        if (
            self.authority.hard_duplicate_adjudication_sha256
            != policy.hard_duplicate_adjudication_sha256
        ):
            raise ValueError("recommendation hard-duplicate trace drifted")
        if self.authority.activation_suite_sha256 != policy.activation_suite_sha256:
            raise ValueError("recommendation activation-suite trace drifted")
        if self.authority.contrast_suite_sha256 != policy.contrast_suite_sha256:
            raise ValueError("recommendation contrast-suite trace drifted")
        if tuple(sorted(self.candidate_place_ids)) != self.candidate_place_ids:
            raise ValueError("candidate place ids must use canonical order")
        if len(set(self.candidate_place_ids)) != len(self.candidate_place_ids):
            raise ValueError("candidate place ids must be unique")
        scored_ids = {row.place_id for row in self.scored_candidates}
        excluded_ids = {row.place_id for row in self.exclusions}
        if len(scored_ids) != len(self.scored_candidates) or len(excluded_ids) != len(
            self.exclusions
        ):
            raise ValueError("candidate score and exclusion rows must be unique")
        if scored_ids & excluded_ids or scored_ids | excluded_ids != set(self.candidate_place_ids):
            raise ValueError("every candidate must be scored or explicitly excluded exactly once")
        remaining = set(scored_ids)
        for step in self.diversity_steps:
            considered_ids = {row.place_id for row in step.considered}
            if considered_ids != remaining:
                raise ValueError("diversity step must retain every remaining candidate")
            remaining.remove(step.selected_place_id)
        score_by_id = {row.place_id: row for row in self.scored_candidates}
        if any(
            item.fit_score != score_by_id[item.place_id].relevance_score
            or item.mismatch != score_by_id[item.place_id].mismatch
            or item.contribution.axis_components
            != score_by_id[item.place_id].contribution.axis_components
            or item.contribution.condition_components
            != score_by_id[item.place_id].contribution.condition_components
            for item in self.items
        ):
            raise ValueError("public items must match the scored candidate trace")
        diversity_by_id = {step.selected_place_id: step for step in self.diversity_steps}
        if any(
            item.contribution.diversity_novelty_score
            != diversity_by_id[item.place_id].novelty_score
            or item.contribution.rerank_score != diversity_by_id[item.place_id].combined_score
            or item.contribution.rerank_numerator
            != (
                diversity_by_id[item.place_id].relevance_score * 8_500
                + diversity_by_id[item.place_id].novelty_score * 1_500
            )
            for item in self.items
        ):
            raise ValueError("public item rerank contribution does not match diversity trace")
        deterministic_payload = self.model_dump(
            mode="json", exclude={"created_at", "canonical_sha256", "run_id"}
        )
        expected = canonical_sha256(deterministic_payload)
        if not hmac.compare_digest(self.canonical_sha256, expected):
            raise ValueError("recommendation receipt digest drifted")
        if self.run_id != f"recommendation-run:{expected[:32]}":
            raise ValueError("recommendation run identity drifted")
        return self


class RecommendationOperatingState(StrictContract):
    """One result-scoped operating-information state with no live claim."""

    place_id: StableId
    state: Literal["OPERATING_INFORMATION_UNVERIFIED"]


OperatingInformationKind = Literal[
    "OPENING_HOURS",
    "REST_DATES",
    "USE_SEASON",
    "EVENT_DATES",
    "CHECK_IN_OUT",
]
OperatingInformationProviderField = Literal[
    "opendate",
    "restdate",
    "usetime",
    "useseason",
    "restdateculture",
    "usetimeculture",
    "eventstartdate",
    "eventenddate",
    "playtime",
    "openperiod",
    "restdateleports",
    "usetimeleports",
    "checkintime",
    "checkouttime",
    "roomofftime",
    "opendateshopping",
    "opentime",
    "restdateshopping",
    "opendatefood",
    "opentimefood",
    "restdatefood",
]
OperatingInformationUnavailableReason = Literal[
    "ENRICHMENT_DISABLED",
    "NOT_IN_PROVIDER_SCOPE",
    "NO_OPERATING_FIELDS",
    "PROVIDER_UNAVAILABLE",
]


class OperatingInformationEntry(StrictContract):
    kind: OperatingInformationKind
    label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=40)]
    value_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    provider_field: OperatingInformationProviderField


class OperatingInformationSnapshot(StrictContract):
    provider: Literal["TOUR_API"] = "TOUR_API"
    operation: Literal["detailIntro2"] = "detailIntro2"
    content_type_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{1,2}$")]
    entries: Annotated[tuple[OperatingInformationEntry, ...], Field(min_length=1, max_length=8)]
    retrieved_at: datetime
    provider_modifiedtime: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=40)
    ] = None
    source_label_ko: Literal[
        "한국관광공사 TourAPI(KorService2 detailIntro2)"
    ] = "한국관광공사 TourAPI(KorService2 detailIntro2)"
    cached: StrictBool

    @model_validator(mode="after")
    def require_utc_retrieval_time(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        return self


class PlaceOperatingInformation(StrictContract):
    place_id: StableId
    state: Literal["AVAILABLE", "UNVERIFIED"]
    snapshot: OperatingInformationSnapshot | None = None
    unavailable_reason: OperatingInformationUnavailableReason | None = None

    @model_validator(mode="after")
    def require_state_payload_parity(self) -> Self:
        if self.state == "AVAILABLE":
            if self.snapshot is None or self.unavailable_reason is not None:
                raise ValueError("available operating information requires only a snapshot")
        elif self.snapshot is not None or self.unavailable_reason is None:
            raise ValueError("unverified operating information requires only a reason")
        return self


class OperatingInformationResponse(StrictContract):
    schema_version: Literal["operating-information.v1"] = "operating-information.v1"
    run_id: StableId
    places: Annotated[tuple[PlaceOperatingInformation, ...], Field(min_length=1, max_length=5)]

    @model_validator(mode="after")
    def require_unique_places(self) -> Self:
        ids = tuple(row.place_id for row in self.places)
        if len(ids) != len(set(ids)):
            raise ValueError("operating information places must be unique")
        return self


class RecommendationReleaseDisclosure(StrictContract):
    """Allowlisted release identity safe for the public result banner."""

    analysis_origin: Literal["DEMO_MODEL_DERIVED"]
    model: Literal["glm-5v-turbo", "minimaxai/minimax-m3"]
    prompt_schema_version: Literal[
        "phase5-demo-profile.v1",
        "phase5-demo-profile-json.v2",
        "phase5-demo-profile-sentinel-json.v4",
        "phase5-demo-profile-sentinel-json.v5",
    ]
    profile_schema_version: Literal[
        "itda.demo-model-derived-profile.v1",
        "itda.nvidia-minimax-model-derived-profile.v4",
        "itda.nvidia-minimax-model-derived-profile.v5",
    ]
    config_sha256: Sha256
    source_bundle_sha256: Sha256
    release_sha256: Sha256
    reference_date: date

    @model_validator(mode="after")
    def require_coherent_release_lineage(self) -> Self:
        lineage = (
            self.model,
            self.prompt_schema_version,
            self.profile_schema_version,
        )
        allowed = {
            (
                "glm-5v-turbo",
                "phase5-demo-profile.v1",
                "itda.demo-model-derived-profile.v1",
            ),
            (
                "glm-5v-turbo",
                "phase5-demo-profile-json.v2",
                "itda.demo-model-derived-profile.v1",
            ),
            (
                "minimaxai/minimax-m3",
                "phase5-demo-profile-sentinel-json.v4",
                "itda.nvidia-minimax-model-derived-profile.v4",
            ),
            (
                "minimaxai/minimax-m3",
                "phase5-demo-profile-sentinel-json.v5",
                "itda.nvidia-minimax-model-derived-profile.v5",
            ),
        }
        if lineage not in allowed:
            raise ValueError("release disclosure lineage tuple is invalid")
        return self


class RecommendationResultsResponse(StrictContract):
    """Pinned browser result projection with exact release disclosure."""

    schema_version: Literal["itda.recommendation-results.v1"] = "itda.recommendation-results.v1"
    preference_profile_id: StableId
    analysis_origin: Literal["DEMO_MODEL_DERIVED"]
    operating_states: tuple[
        RecommendationOperatingState,
        RecommendationOperatingState,
        RecommendationOperatingState,
        RecommendationOperatingState,
        RecommendationOperatingState,
    ]
    release_disclosure: RecommendationReleaseDisclosure
    run: RecommendationRun

    @model_validator(mode="after")
    def require_pinned_public_projection(self) -> Self:
        item_ids = tuple(item.place_id for item in self.run.items)
        if tuple(row.place_id for row in self.operating_states) != item_ids:
            raise ValueError("operating states must follow the exact result order")
        if self.analysis_origin != self.release_disclosure.analysis_origin:
            raise ValueError("result analysis origin drifted")
        if (
            self.run.release_sha256 != self.release_disclosure.release_sha256
            or self.run.config_sha256 != self.release_disclosure.config_sha256
        ):
            raise ValueError("result release disclosure drifted from the pinned run")
        if self.release_disclosure.reference_date != max(
            item.reference_date for item in self.run.items
        ):
            raise ValueError("result disclosure reference date drifted")
        return self


class MvpRecommendationReleaseDisclosure(StrictContract):
    analysis_origin: Literal["GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED"]
    model: Literal["glm-5.3-flash"]
    prompt_schema_version: Literal["mvp-place-scoring-request.v2"]
    profile_schema_version: Literal[
        "mvp-scored-release.v1", "mvp-scored-release.v2", "mvp-scored-release.v3"
    ]
    config_sha256: Sha256
    source_bundle_sha256: Sha256
    release_sha256: Sha256
    reference_date: date


class MvpRecommendationResultsResponse(StrictContract):
    schema_version: Literal["itda.recommendation-results.v2"] = "itda.recommendation-results.v2"
    preference_profile_id: StableId
    analysis_origin: Literal["GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED"]
    operating_states: tuple[
        RecommendationOperatingState,
        RecommendationOperatingState,
        RecommendationOperatingState,
        RecommendationOperatingState,
        RecommendationOperatingState,
    ]
    release_disclosure: MvpRecommendationReleaseDisclosure
    run: MvpRecommendationRun | PhotoMvpRecommendationRun

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if tuple(row.place_id for row in self.operating_states) != tuple(
            row.place_id for row in self.run.items
        ):
            raise ValueError("operating states must follow the exact result order")
        if (
            self.release_disclosure.release_sha256 != self.run.authority.release_sha256
            or self.release_disclosure.config_sha256 != self.run.authority.config_sha256
        ):
            raise ValueError("MVP result disclosure drifted from the pinned run")
        if self.release_disclosure.reference_date != max(
            row.reference_date for row in self.run.items
        ):
            raise ValueError("MVP result reference date drifted")
        return self


class RecommendationDetail(StrictContract):
    run_id: StableId
    release_sha256: Sha256
    confidence_percent: Score100
    evidence_confidence_state: EvidenceConfidenceState
    evidence_confidence_reason_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    item: RecommendationItem
    mismatch_traits: tuple[
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
    ]
    evidence: Annotated[tuple[PublicEvidenceSnippet, ...], Field(min_length=1, max_length=64)]
    operating_state: StableId
    similar_place_ids: tuple[StableId, ...]

    @model_validator(mode="after")
    def require_pinned_confidence_projection(self) -> Self:
        state, reason = confidence_state_for(self.confidence_percent)
        if (
            self.evidence_confidence_state is not state
            or self.evidence_confidence_reason_ko != reason
            or self.item.evidence_confidence_state is not state
            or self.item.evidence_confidence_reason_ko != reason
        ):
            raise ValueError("detail confidence projection does not match its item")
        return self

    @model_validator(mode="after")
    def require_pinned_evidence_inventory(self) -> Self:
        evidence_by_id = {row.evidence_id: row for row in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("detail evidence ids must be unique")
        if any(row.reference_date != self.item.reference_date for row in self.evidence):
            raise ValueError("detail evidence reference date drifted from pinned item")
        for item_evidence in self.item.evidence:
            if evidence_by_id.get(item_evidence.evidence_id) != item_evidence:
                raise ValueError("detail item evidence conflicts with pinned inventory")
        if tuple(row.trait_id for row in self.mismatch_traits) != tuple(MismatchTraitId):
            raise ValueError("detail traits must use canonical M1-M6 order")
        referenced_ids = {
            evidence_id
            for row in (*self.item.axis_scores, *self.mismatch_traits)
            for evidence_id in row.evidence_ids
        } | {row.evidence_id for row in self.item.explanations}
        unknown = referenced_ids - set(evidence_by_id)
        if unknown:
            raise ValueError(f"detail evidence reference is unresolved: {sorted(unknown)[0]}")
        return self


class MvpRecommendationDetail(StrictContract):
    run_id: StableId
    release_sha256: Sha256
    confidence_percent: Score100
    evidence_confidence_state: EvidenceConfidenceState
    evidence_confidence_reason_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    item: MvpRecommendationPublicItem
    mismatch_traits: tuple[
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
        PlaceTraitSnapshot,
    ]
    evidence: Annotated[tuple[MvpEvidenceSnippet, ...], Field(min_length=1, max_length=64)]
    operating_state: StableId
    similar_place_ids: tuple[StableId, ...]

    @model_validator(mode="after")
    def validate_mvp_detail(self) -> Self:
        state, reason = mvp_confidence_state_for(self.confidence_percent)
        if (
            self.evidence_confidence_state is not state
            or self.evidence_confidence_reason_ko != reason
            or self.item.evidence_confidence_state is not state
            or self.item.evidence_confidence_reason_ko != reason
        ):
            raise ValueError("MVP detail confidence projection drifted")
        evidence_by_id = {row.evidence_id: row for row in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("MVP detail evidence ids must be unique")
        if any(evidence_by_id.get(row.evidence_id) != row for row in self.item.evidence):
            raise ValueError("MVP detail item evidence conflicts with pinned inventory")
        if tuple(row.trait_id for row in self.mismatch_traits) != tuple(MismatchTraitId):
            raise ValueError("MVP detail traits must use canonical M1-M6 order")
        referenced_ids = {
            evidence_id
            for row in (*self.item.axis_scores, *self.mismatch_traits)
            for evidence_id in row.evidence_ids
        } | {row.evidence_id for row in self.item.explanations}
        if referenced_ids - set(evidence_by_id):
            raise ValueError("MVP detail evidence reference is unresolved")
        return self


class ComparisonRow(StrictContract):
    row_id: StableId
    label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    values_ko: Annotated[tuple[str, ...], Field(min_length=2, max_length=3)]
    missing_reasons: Annotated[tuple[StableId | None, ...], Field(min_length=2, max_length=3)]

    @model_validator(mode="after")
    def require_aligned_values(self) -> Self:
        if len(self.values_ko) != len(self.missing_reasons):
            raise ValueError("comparison values and missing reasons must align")
        return self


class RecommendationComparisonResponse(StrictContract):
    schema_version: Literal["recommendation-comparison-v1"] = "recommendation-comparison-v1"
    run_id: StableId
    release_sha256: Sha256
    place_ids: Annotated[tuple[StableId, ...], Field(min_length=2, max_length=3)]
    rows: Annotated[tuple[ComparisonRow, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def require_pinned_comparison_identity(self) -> Self:
        if len(set(self.place_ids)) != len(self.place_ids):
            raise ValueError("comparison place IDs must be unique and ordered")
        if any(len(row.values_ko) != len(self.place_ids) for row in self.rows):
            raise ValueError("comparison values must align with the requested place order")
        return self


class SavedPlaceProjection(StrictContract):
    place_id: StableId
    place_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    saved_release_sha256: Sha256
    resolved_release_sha256: Sha256 | None
    state: SavedPlaceState
    state_reason: StableId | None

    @model_validator(mode="after")
    def require_release_bound_state(self) -> Self:
        if self.state is SavedPlaceState.CURRENT:
            if (
                self.resolved_release_sha256 != self.saved_release_sha256
                or self.state_reason is not None
            ):
                raise ValueError("current saved place requires the exact saved release")
        elif self.state_reason is None:
            raise ValueError("non-current saved place requires a state reason")
        return self


__all__ = [
    "CANONICAL_RECOMMENDATION_CONFIG",
    "ComparisonRow",
    "EvidenceConfidenceState",
    "DuplicateDecision",
    "ExplanationLink",
    "MismatchGuidance",
    "OperatingInformationEntry",
    "OperatingInformationKind",
    "OperatingInformationProviderField",
    "OperatingInformationResponse",
    "OperatingInformationSnapshot",
    "OperatingInformationUnavailableReason",
    "PlaceOperatingInformation",
    "RecommendationAuthorityTrace",
    "RecommendationCandidate",
    "RecommendationConfig",
    "RecommendationDetail",
    "confidence_state_for",
    "RecommendationComparisonResponse",
    "RecommendationItem",
    "RecommendationResultsResponse",
    "RecommendationPreference",
    "RecommendationRun",
    "SavedPlaceProjection",
    "ScoreContribution",
    "TravelConditionId",
    "TravelConditionWeights",
]
