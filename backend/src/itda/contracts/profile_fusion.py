"""Immutable contracts for deterministic Phase 4 profile fusion."""

from __future__ import annotations

import hmac
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import BasisPoints, Sha256, StableId, StrictContract
from itda.contracts.place_profile import MismatchTraitAssessment, MismatchTraitId, SubattributeId
from itda.contracts.provenance import EvidenceReference
from itda.domain.canonical import canonical_sha256

AxisId = Literal["H", "E", "R"]
ScoreMilli = Annotated[int, Field(strict=True, ge=0, le=4_000)]
PositiveInteger = Annotated[int, Field(strict=True, ge=1)]


def _half_up(numerator: int, denominator: int) -> int:
    return (2 * numerator + denominator) // (2 * denominator)


def _display_percentages(weights: tuple[int, int, int]) -> tuple[int, int, int]:
    total = sum(weights)
    floors = [weight * 100 // total for weight in weights]
    remainders = [weight * 100 % total for weight in weights]
    for index in sorted(range(3), key=lambda item: (-remainders[item], item))[
        : 100 - sum(floors)
    ]:
        floors[index] += 1
    return floors[0], floors[1], floors[2]


class LaneId(StrEnum):
    DESCRIPTION = "DESCRIPTION"
    ODII = "ODII"
    IMAGE = "IMAGE"


class AgreementStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class PublicationState(StrEnum):
    PUBLISHABLE = "PUBLISHABLE"
    LIMITED_INFORMATION = "LIMITED_INFORMATION"
    EXCLUDED_MANUAL_REVIEW = "EXCLUDED_MANUAL_REVIEW"


class DisplayLabelState(StrEnum):
    SINGLE = "SINGLE"
    COMPOSITE = "COMPOSITE"
    FALLBACK = "FALLBACK"


class AxisBaseWeights(StrictContract):
    axis_id: AxisId
    description_bp: BasisPoints
    odii_bp: BasisPoints
    image_bp: BasisPoints

    @model_validator(mode="after")
    def require_complete_basis(self) -> Self:
        if self.description_bp + self.odii_bp + self.image_bp != 10_000:
            raise ValueError("axis base weights must sum to 10000 bp")
        return self


class FusionPolicyConfig(StrictContract):
    """Versioned policy; only the exact canonical values may reach release."""

    schema_version: Literal["itda.profile-fusion-policy.v1"] = "itda.profile-fusion-policy.v1"
    mode: Literal["CANONICAL_RELEASE", "SENSITIVITY_ONLY"]
    release_eligible: StrictBool
    meaningful_character_rule: Literal["UNICODE_NFKC_ALNUM_V1"]
    base_weights: tuple[AxisBaseWeights, AxisBaseWeights, AxisBaseWeights]
    description_full_min: Annotated[int, Field(strict=True, ge=1)]
    description_partial_min: Annotated[int, Field(strict=True, ge=1)]
    description_full_bp: BasisPoints
    description_partial_bp: BasisPoints
    description_low_bp: BasisPoints
    odii_full_min: Annotated[int, Field(strict=True, ge=1)]
    odii_full_bp: BasisPoints
    odii_partial_bp: BasisPoints
    image_full_min: Annotated[int, Field(strict=True, ge=1)]
    image_partial_min: Annotated[int, Field(strict=True, ge=1)]
    image_full_bp: BasisPoints
    image_partial_bp: BasisPoints
    image_low_bp: BasisPoints
    eligible_quality_bp: BasisPoints
    excluded_quality_bp: BasisPoints
    fidelity_share_bp: BasisPoints
    agreement_share_bp: BasisPoints
    agreement_min_shared_attributes: Annotated[int, Field(strict=True, ge=1, le=4)]
    agreement_rule: Literal["MEAN_NORMALIZED_ABSOLUTE_PAIR_DISTANCE_V1"]
    publishable_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    limited_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    mismatch_warning_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    axis_aggregation_rule: Literal["HALF_UP_MEAN_EXACTLY_FOUR_V1"]
    axis_tie_order: tuple[Literal["H"], Literal["E"], Literal["R"]]
    label_single_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    label_single_gap_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    label_composite_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    label_composite_gap_exclusive_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    label_rule_version: Literal["D21_LABEL_STATE_MACHINE_V1"]
    score_rounding: Literal["NONNEGATIVE_INTEGER_HALF_UP_ONCE"]
    display_weight_rule: Literal["LARGEST_REMAINDER_DESCRIPTION_ODII_IMAGE"]
    policy_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_release_policy_and_digest(self) -> Self:
        if tuple(row.axis_id for row in self.base_weights) != ("H", "E", "R"):
            raise ValueError("base weights must use canonical H-E-R order")
        canonical = self._has_canonical_release_values()
        if self.mode == "CANONICAL_RELEASE":
            if not self.release_eligible or not canonical:
                raise ValueError("release policy must preserve every canonical fusion value")
        elif self.release_eligible:
            raise ValueError("sensitivity-only policy cannot be release eligible")

        expected = canonical_sha256(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if self.policy_sha256 is None:
            object.__setattr__(self, "policy_sha256", expected)
        elif not hmac.compare_digest(self.policy_sha256, expected):
            raise ValueError("fusion policy digest drifted")
        return self

    def _has_canonical_release_values(self) -> bool:
        return (
            tuple(
                (row.axis_id, row.description_bp, row.odii_bp, row.image_bp)
                for row in self.base_weights
            )
            == (
                ("H", 3_500, 4_500, 2_000),
                ("E", 2_000, 1_000, 7_000),
                ("R", 3_500, 1_500, 5_000),
            )
            and self.meaningful_character_rule == "UNICODE_NFKC_ALNUM_V1"
            and (
                self.description_full_min,
                self.description_partial_min,
                self.description_full_bp,
                self.description_partial_bp,
                self.description_low_bp,
            )
            == (500, 200, 10_000, 7_000, 4_000)
            and (self.odii_full_min, self.odii_full_bp, self.odii_partial_bp)
            == (800, 10_000, 7_000)
            and (
                self.image_full_min,
                self.image_partial_min,
                self.image_full_bp,
                self.image_partial_bp,
                self.image_low_bp,
            )
            == (5, 2, 10_000, 7_000, 4_000)
            and (self.eligible_quality_bp, self.excluded_quality_bp) == (10_000, 0)
            and (self.fidelity_share_bp, self.agreement_share_bp) == (5_500, 4_500)
            and self.agreement_min_shared_attributes == 2
            and self.agreement_rule == "MEAN_NORMALIZED_ABSOLUTE_PAIR_DISTANCE_V1"
            and (
                self.publishable_min_percent,
                self.limited_min_percent,
                self.mismatch_warning_min_percent,
            )
            == (70, 55, 65)
            and self.axis_aggregation_rule == "HALF_UP_MEAN_EXACTLY_FOUR_V1"
            and self.axis_tie_order == ("H", "E", "R")
            and (
                self.label_single_min_percent,
                self.label_single_gap_min_percent,
                self.label_composite_min_percent,
                self.label_composite_gap_exclusive_percent,
            )
            == (65, 12, 60, 12)
            and self.label_rule_version == "D21_LABEL_STATE_MACHINE_V1"
            and self.score_rounding == "NONNEGATIVE_INTEGER_HALF_UP_ONCE"
            and self.display_weight_rule == "LARGEST_REMAINDER_DESCRIPTION_ODII_IMAGE"
        )


class LaneContributionTrace(StrictContract):
    lane_id: LaneId
    included: StrictBool
    exclusion_reason: Annotated[str, Field(strict=True, min_length=1, max_length=80)] | None
    score_milli: ScoreMilli | None
    base_weight_bp: BasisPoints
    fidelity_bp: BasisPoints
    quality_bp: BasisPoints
    effective_weight_numerator: Annotated[int, Field(strict=True, ge=0)]
    normalized_weight_numerator: Annotated[int, Field(strict=True, ge=0)]
    normalized_weight_denominator: PositiveInteger
    display_weight_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    contribution_numerator: Annotated[int, Field(strict=True, ge=0)]
    contribution_denominator: PositiveInteger
    evidence_refs: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=200)], ...]

    @model_validator(mode="after")
    def require_inclusion_shape(self) -> Self:
        if self.included:
            if self.exclusion_reason is not None or self.score_milli is None:
                raise ValueError("included lane requires a score and no exclusion")
            if self.effective_weight_numerator <= 0:
                raise ValueError("included lane requires positive effective weight")
        elif (
            self.exclusion_reason is None
            or self.score_milli is not None
            or self.effective_weight_numerator != 0
            or self.normalized_weight_numerator != 0
            or self.display_weight_percent != 0
            or self.contribution_numerator != 0
            or self.evidence_refs
        ):
            raise ValueError("excluded lane must remain score- and fact-free")
        return self


class FusedAttribute(StrictContract):
    attribute_id: SubattributeId
    axis_id: AxisId
    score_milli: ScoreMilli
    lanes: tuple[LaneContributionTrace, LaneContributionTrace, LaneContributionTrace]
    fusion_policy_sha256: Sha256
    attribute_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_canonical_trace(self) -> Self:
        if tuple(row.lane_id for row in self.lanes) != tuple(LaneId):
            raise ValueError("fusion trace must use DESCRIPTION-ODII-IMAGE order")
        included = tuple(row for row in self.lanes if row.included)
        if not included:
            raise ValueError("fused attribute requires at least one eligible lane")
        if sum(row.display_weight_percent for row in included) != 100:
            raise ValueError("included display weights must sum to 100 percent")
        weights = (
            self.lanes[0].effective_weight_numerator,
            self.lanes[1].effective_weight_numerator,
            self.lanes[2].effective_weight_numerator,
        )
        denominator = sum(weights)
        if any(
            row.normalized_weight_numerator != row.effective_weight_numerator
            or row.normalized_weight_denominator != denominator
            or row.contribution_denominator != denominator
            or row.contribution_numerator
            != ((row.score_milli or 0) * row.effective_weight_numerator)
            for row in self.lanes
        ):
            raise ValueError("fusion lane arithmetic drifted")
        if tuple(row.display_weight_percent for row in self.lanes) != _display_percentages(
            weights
        ):
            raise ValueError("fusion display weights drifted")
        expected_score = _half_up(
            sum(row.contribution_numerator for row in self.lanes),
            denominator,
        )
        if self.score_milli != expected_score:
            raise ValueError("fused score does not match lane contributions")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"attribute_sha256"}))
        if self.attribute_sha256 is None:
            object.__setattr__(self, "attribute_sha256", expected)
        elif not hmac.compare_digest(self.attribute_sha256, expected):
            raise ValueError("fused attribute digest drifted")
        return self


class ComparableLanePair(StrictContract):
    left_lane: LaneId
    right_lane: LaneId
    shared_attribute_ids: Annotated[tuple[SubattributeId, ...], Field(min_length=2)]
    absolute_distance_milli_sum: Annotated[int, Field(strict=True, ge=0)]
    agreement_numerator: Annotated[int, Field(strict=True, ge=0)]
    agreement_denominator: PositiveInteger


class AxisConfidenceTrace(StrictContract):
    axis_id: AxisId
    fidelity_effective_numerator: Annotated[int, Field(strict=True, ge=0)]
    fidelity_denominator: PositiveInteger
    fidelity_bp: BasisPoints
    comparable_lane_pairs: tuple[ComparableLanePair, ...]
    agreement_status: AgreementStatus
    agreement_bp: BasisPoints | None
    fidelity_share_bp: BasisPoints
    agreement_share_bp: BasisPoints
    fidelity_contribution_bp: BasisPoints
    agreement_contribution_bp: BasisPoints
    confidence_bp: BasisPoints
    confidence_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    publication_state: PublicationState
    mismatch_warning_authorized: StrictBool
    policy_sha256: Sha256
    confidence_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_agreement_and_digest(self) -> Self:
        if self.agreement_status is AgreementStatus.UNAVAILABLE:
            if (
                self.agreement_bp is not None
                or self.comparable_lane_pairs
                or self.agreement_contribution_bp != 0
            ):
                raise ValueError("unavailable agreement must be explicit and contribute zero")
        elif self.agreement_bp is None or not self.comparable_lane_pairs:
            raise ValueError("available agreement requires comparable lane-pair evidence")
        if self.confidence_bp != (self.fidelity_contribution_bp + self.agreement_contribution_bp):
            raise ValueError("confidence must equal its separately persisted contributions")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"confidence_sha256"}))
        if self.confidence_sha256 is None:
            object.__setattr__(self, "confidence_sha256", expected)
        elif not hmac.compare_digest(self.confidence_sha256, expected):
            raise ValueError("axis confidence digest drifted")
        return self


class ProfileConfidence(StrictContract):
    axes: tuple[AxisConfidenceTrace, AxisConfidenceTrace, AxisConfidenceTrace]
    overall_rule: Literal["MINIMUM_AXIS_CONFIDENCE_V1"]
    overall_confidence_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    publication_state: PublicationState
    mismatch_warning_authorized: StrictBool
    policy_sha256: Sha256
    profile_confidence_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_conservative_overall_and_digest(self) -> Self:
        if tuple(row.axis_id for row in self.axes) != ("H", "E", "R"):
            raise ValueError("axis confidence must use canonical H-E-R order")
        if self.overall_confidence_percent != min(row.confidence_percent for row in self.axes):
            raise ValueError("overall confidence must use the minimum axis confidence")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"profile_confidence_sha256"})
        )
        if self.profile_confidence_sha256 is None:
            object.__setattr__(self, "profile_confidence_sha256", expected)
        elif not hmac.compare_digest(self.profile_confidence_sha256, expected):
            raise ValueError("profile confidence digest drifted")
        return self


class FusedAxis(StrictContract):
    axis_id: AxisId
    member_attribute_ids: tuple[SubattributeId, SubattributeId, SubattributeId, SubattributeId]
    aggregation_rule: Literal["HALF_UP_MEAN_EXACTLY_FOUR_V1"]
    score_milli: ScoreMilli
    score_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    policy_sha256: Sha256
    axis_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_members_projection_and_digest(self) -> Self:
        expected_members = {
            "H": tuple(SubattributeId)[:4],
            "E": tuple(SubattributeId)[4:8],
            "R": tuple(SubattributeId)[8:],
        }[self.axis_id]
        if self.member_attribute_ids != expected_members:
            raise ValueError("axis members must use exact canonical four-member order")
        if self.score_percent != (self.score_milli + 20) // 40:
            raise ValueError("axis percent must be the half-up projection from score_milli")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"axis_sha256"}))
        if self.axis_sha256 is None:
            object.__setattr__(self, "axis_sha256", expected)
        elif not hmac.compare_digest(self.axis_sha256, expected):
            raise ValueError("fused axis digest drifted")
        return self


class DisplayLabelDecision(StrictContract):
    state: DisplayLabelState
    axis_ids: tuple[AxisId, ...]
    label_id: StableId
    label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    top_score_milli: ScoreMilli
    second_score_milli: ScoreMilli
    gap_milli: Annotated[int, Field(strict=True, ge=0, le=4_000)]
    label_rule_version: Literal["D21_LABEL_STATE_MACHINE_V1"]
    single_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    single_gap_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    composite_min_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    composite_gap_exclusive_percent: Annotated[int, Field(strict=True, ge=0, le=100)]
    tie_order: tuple[Literal["H"], Literal["E"], Literal["R"]]
    policy_sha256: Sha256
    label_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_state_shape_and_digest(self) -> Self:
        required_axis_count = {
            DisplayLabelState.SINGLE: 1,
            DisplayLabelState.COMPOSITE: 2,
            DisplayLabelState.FALLBACK: 0,
        }[self.state]
        if len(self.axis_ids) != required_axis_count:
            raise ValueError("label axis count does not match label state")
        if self.gap_milli != self.top_score_milli - self.second_score_milli:
            raise ValueError("label gap must match the ordered top-two inputs")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"label_sha256"}))
        if self.label_sha256 is None:
            object.__setattr__(self, "label_sha256", expected)
        elif not hmac.compare_digest(self.label_sha256, expected):
            raise ValueError("display label digest drifted")
        return self


class FusedProfileProjection(StrictContract):
    schema_version: Literal["itda.fused-profile-projection.v1"] = "itda.fused-profile-projection.v1"
    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    predecessor_profile_sha256: Sha256
    baseline_member_sha256: Sha256
    image_observation_sha256: Sha256
    attributes: Annotated[tuple[FusedAttribute, ...], Field(min_length=12, max_length=12)]
    axes: tuple[FusedAxis, FusedAxis, FusedAxis]
    mismatch_traits: Annotated[
        tuple[MismatchTraitAssessment, ...], Field(min_length=6, max_length=6)
    ]
    inherited_evidence: tuple[EvidenceReference, ...]
    mismatch_lineage_rule: Literal["EXACT_PREDECESSOR_COPY_V1"]
    confidence: ProfileConfidence
    display_label: DisplayLabelDecision
    policy_sha256: Sha256
    profile_fusion_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_canonical_profile_and_digest(self) -> Self:
        if tuple(row.attribute_id for row in self.attributes) != tuple(SubattributeId):
            raise ValueError("fused profile attributes must use canonical H1-R4 order")
        if tuple(row.axis_id for row in self.axes) != ("H", "E", "R"):
            raise ValueError("fused profile axes must use canonical H-E-R order")
        if tuple(row.trait_id for row in self.mismatch_traits) != tuple(MismatchTraitId):
            raise ValueError("fused profile traits must use canonical M1-M6 order")
        policy = CANONICAL_FUSION_POLICY
        if self.policy_sha256 != policy.policy_sha256 or any(
            attribute.fusion_policy_sha256 != policy.policy_sha256
            for attribute in self.attributes
        ):
            raise ValueError("fused profile does not bind the canonical policy")
        expected_axis_by_attribute = {
            **{attribute: "H" for attribute in tuple(SubattributeId)[:4]},
            **{attribute: "E" for attribute in tuple(SubattributeId)[4:8]},
            **{attribute: "R" for attribute in tuple(SubattributeId)[8:]},
        }
        weights_by_axis = {row.axis_id: row for row in policy.base_weights}
        for attribute in self.attributes:
            if attribute.axis_id != expected_axis_by_attribute[attribute.attribute_id]:
                raise ValueError("fused attribute axis drifted")
            weights = weights_by_axis[attribute.axis_id]
            expected_base_weights = (
                weights.description_bp,
                weights.odii_bp,
                weights.image_bp,
            )
            if tuple(row.base_weight_bp for row in attribute.lanes) != expected_base_weights:
                raise ValueError("fused lane base weights drifted")
            for lane in attribute.lanes:
                expected_quality = (
                    policy.eligible_quality_bp if lane.included else policy.excluded_quality_bp
                )
                expected_effective = (
                    lane.base_weight_bp * lane.fidelity_bp * expected_quality
                    if lane.included
                    else 0
                )
                if (
                    lane.quality_bp != expected_quality
                    or lane.effective_weight_numerator != expected_effective
                ):
                    raise ValueError("fused lane eligibility arithmetic drifted")
        from itda.domain.profile_fusion import (
            compute_profile_confidence,
            derive_display_label,
            derive_final_axes,
        )

        expected_axes = derive_final_axes(self.attributes, policy=policy)
        expected_confidence = compute_profile_confidence(self.attributes, policy=policy)
        expected_label = derive_display_label(expected_axes, policy=policy)
        if self.axes != expected_axes:
            raise ValueError("fused profile axes drifted")
        if self.confidence != expected_confidence:
            raise ValueError("fused profile confidence drifted")
        if self.display_label != expected_label:
            raise ValueError("fused profile display label drifted")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"profile_fusion_sha256"}))
        if self.profile_fusion_sha256 is None:
            object.__setattr__(self, "profile_fusion_sha256", expected)
        elif not hmac.compare_digest(self.profile_fusion_sha256, expected):
            raise ValueError("fused profile projection digest drifted")
        return self


CANONICAL_FUSION_POLICY = FusionPolicyConfig(
    mode="CANONICAL_RELEASE",
    release_eligible=True,
    meaningful_character_rule="UNICODE_NFKC_ALNUM_V1",
    base_weights=(
        AxisBaseWeights(axis_id="H", description_bp=3_500, odii_bp=4_500, image_bp=2_000),
        AxisBaseWeights(axis_id="E", description_bp=2_000, odii_bp=1_000, image_bp=7_000),
        AxisBaseWeights(axis_id="R", description_bp=3_500, odii_bp=1_500, image_bp=5_000),
    ),
    description_full_min=500,
    description_partial_min=200,
    description_full_bp=10_000,
    description_partial_bp=7_000,
    description_low_bp=4_000,
    odii_full_min=800,
    odii_full_bp=10_000,
    odii_partial_bp=7_000,
    image_full_min=5,
    image_partial_min=2,
    image_full_bp=10_000,
    image_partial_bp=7_000,
    image_low_bp=4_000,
    eligible_quality_bp=10_000,
    excluded_quality_bp=0,
    fidelity_share_bp=5_500,
    agreement_share_bp=4_500,
    agreement_min_shared_attributes=2,
    agreement_rule="MEAN_NORMALIZED_ABSOLUTE_PAIR_DISTANCE_V1",
    publishable_min_percent=70,
    limited_min_percent=55,
    mismatch_warning_min_percent=65,
    axis_aggregation_rule="HALF_UP_MEAN_EXACTLY_FOUR_V1",
    axis_tie_order=("H", "E", "R"),
    label_single_min_percent=65,
    label_single_gap_min_percent=12,
    label_composite_min_percent=60,
    label_composite_gap_exclusive_percent=12,
    label_rule_version="D21_LABEL_STATE_MACHINE_V1",
    score_rounding="NONNEGATIVE_INTEGER_HALF_UP_ONCE",
    display_weight_rule="LARGEST_REMAINDER_DESCRIPTION_ODII_IMAGE",
)


__all__ = [
    "CANONICAL_FUSION_POLICY",
    "AgreementStatus",
    "AxisBaseWeights",
    "AxisConfidenceTrace",
    "AxisId",
    "ComparableLanePair",
    "DisplayLabelDecision",
    "DisplayLabelState",
    "FusedAttribute",
    "FusedAxis",
    "FusedProfileProjection",
    "FusionPolicyConfig",
    "LaneContributionTrace",
    "LaneId",
    "ProfileConfidence",
    "PublicationState",
    "ScoreMilli",
]
