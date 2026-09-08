"""Pure integer kernel for missing-safe Phase 4 profile fusion."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from fractions import Fraction

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import ImageObservationV2
from itda.contracts.phase3_lane_baseline import (
    Phase3LaneAttributeScore,
    Phase3LaneBaselineMember,
)
from itda.contracts.place_profile import PlaceProfile, SubattributeId
from itda.contracts.profile_fusion import (
    CANONICAL_FUSION_POLICY,
    AgreementStatus,
    AxisBaseWeights,
    AxisConfidenceTrace,
    AxisId,
    ComparableLanePair,
    DisplayLabelDecision,
    DisplayLabelState,
    FusedAttribute,
    FusedAxis,
    FusedProfileProjection,
    FusionPolicyConfig,
    LaneContributionTrace,
    LaneId,
    ProfileConfidence,
    PublicationState,
)
from itda.domain.canonical import canonical_sha256

_ATTRIBUTE_AXIS: dict[SubattributeId, AxisId] = {
    **{attribute_id: "H" for attribute_id in tuple(SubattributeId)[:4]},
    **{attribute_id: "E" for attribute_id in tuple(SubattributeId)[4:8]},
    **{attribute_id: "R" for attribute_id in tuple(SubattributeId)[8:]},
}


def _half_up(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise ValueError("half-up division requires nonnegative numerator and positive denominator")
    return (2 * numerator + denominator) // (2 * denominator)


def count_meaningful_characters(value: str) -> int:
    """Count NFKC-normalized Unicode letters and numbers, excluding punctuation/spacing."""

    if type(value) is not str:
        raise TypeError("meaningful-character input must be a string")
    normalized = unicodedata.normalize("NFKC", value)
    return sum(character.isalnum() for character in normalized)


def description_fidelity_bp(
    meaningful_character_count: int,
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> int:
    if type(meaningful_character_count) is not int or meaningful_character_count < 0:
        raise ValueError("description character count must be a nonnegative integer")
    if meaningful_character_count >= policy.description_full_min:
        return policy.description_full_bp
    if meaningful_character_count >= policy.description_partial_min:
        return policy.description_partial_bp
    return policy.description_low_bp


def odii_fidelity_bp(
    meaningful_character_count: int,
    *,
    directly_linked: bool,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> int:
    if type(meaningful_character_count) is not int or meaningful_character_count < 0:
        raise ValueError("Odii character count must be a nonnegative integer")
    if type(directly_linked) is not bool:
        raise ValueError("Odii linkage must be a strict boolean")
    if not directly_linked or meaningful_character_count == 0:
        return 0
    if meaningful_character_count >= policy.odii_full_min:
        return policy.odii_full_bp
    return policy.odii_partial_bp


def image_fidelity_bp(
    representative_count: int,
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> int:
    if type(representative_count) is not int or representative_count < 0:
        raise ValueError("image representative count must be a nonnegative integer")
    if representative_count >= policy.image_full_min:
        return policy.image_full_bp
    if representative_count >= policy.image_partial_min:
        return policy.image_partial_bp
    if representative_count == 1:
        return policy.image_low_bp
    return 0


def require_release_eligible_policy(policy: FusionPolicyConfig) -> None:
    """Fail closed unless the exact D-13/D-16 release configuration is present."""

    if policy.mode != "CANONICAL_RELEASE" or not policy.release_eligible:
        raise ValueError("fusion policy is not release eligible")


def classify_publication(
    confidence_percent: int,
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> tuple[PublicationState, bool]:
    if type(confidence_percent) is not int or not 0 <= confidence_percent <= 100:
        raise ValueError("confidence must be a strict integer from 0 through 100")
    if confidence_percent >= policy.publishable_min_percent:
        state = PublicationState.PUBLISHABLE
    elif confidence_percent >= policy.limited_min_percent:
        state = PublicationState.LIMITED_INFORMATION
    else:
        state = PublicationState.EXCLUDED_MANUAL_REVIEW
    return state, confidence_percent >= policy.mismatch_warning_min_percent
    if policy.model_dump(mode="json", exclude={"policy_sha256"}) != (
        CANONICAL_FUSION_POLICY.model_dump(mode="json", exclude={"policy_sha256"})
    ):
        raise ValueError("fusion policy is not release eligible")


def _largest_remainder_percentages(
    effective_weights: tuple[int, int, int],
) -> tuple[int, int, int]:
    total = sum(effective_weights)
    if total <= 0:
        raise ValueError("at least one effective lane weight is required")
    floors = [weight * 100 // total for weight in effective_weights]
    remainders = [weight * 100 % total for weight in effective_weights]
    remaining = 100 - sum(floors)
    order = sorted(range(3), key=lambda index: (-remainders[index], index))
    for index in order[:remaining]:
        floors[index] += 1
    return floors[0], floors[1], floors[2]


def _axis_weights(policy: FusionPolicyConfig, axis_id: AxisId) -> AxisBaseWeights:
    return next(row for row in policy.base_weights if row.axis_id == axis_id)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _baseline_scores(
    rows: tuple[Phase3LaneAttributeScore, ...],
) -> dict[SubattributeId, Phase3LaneAttributeScore]:
    return {row.attribute_id: row for row in rows}


def fuse_attributes(
    baseline: Phase3LaneBaselineMember,
    image: ImageObservationV2,
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> tuple[FusedAttribute, ...]:
    """Fuse H1-R4 from eligible observed lane values only."""

    description_scores = _baseline_scores(baseline.description.attribute_scores)
    odii_scores = _baseline_scores(baseline.odii.attribute_scores)
    image_scores = {row.attribute_id: row for row in image.observations}
    description_fidelity = (
        description_fidelity_bp(baseline.description.meaningful_character_count, policy=policy)
        if baseline.description.status == "READY"
        else 0
    )
    odii_fidelity = (
        odii_fidelity_bp(
            baseline.odii.meaningful_character_count,
            directly_linked=baseline.odii.directly_linked_odii is True,
            policy=policy,
        )
        if baseline.odii.status == "READY"
        else 0
    )
    image_fidelity = (
        image_fidelity_bp(len(image.selected_image_refs), policy=policy)
        if image.media_state is ImageMediumState.QUALIFIED
        else 0
    )
    if policy.policy_sha256 is None:
        raise ValueError("fusion policy must be digest bound")

    fused: list[FusedAttribute] = []
    for attribute_id in SubattributeId:
        axis_id = _ATTRIBUTE_AXIS[attribute_id]
        weights = _axis_weights(policy, axis_id)
        description = description_scores.get(attribute_id)
        odii = odii_scores.get(attribute_id)
        image_row = image_scores.get(attribute_id)

        lane_values: list[tuple[LaneId, int | None, int, int, tuple[str, ...], str | None]] = [
            (
                LaneId.DESCRIPTION,
                description.score_milli if description is not None else None,
                weights.description_bp,
                description_fidelity,
                description.evidence_refs if description is not None else (),
                None if description is not None else baseline.description.status,
            ),
            (
                LaneId.ODII,
                odii.score_milli if odii is not None else None,
                weights.odii_bp,
                odii_fidelity,
                odii.evidence_refs if odii is not None else (),
                None if odii is not None else baseline.odii.status,
            ),
            (
                LaneId.IMAGE,
                image_row.score_milli
                if image_row is not None and image_row.status == "observed"
                else None,
                weights.image_bp,
                image_fidelity,
                _unique(evidence.image_ref for evidence in image_row.visible_evidence)
                if image_row is not None and image_row.status == "observed"
                else (),
                (
                    "NOT_OBSERVABLE"
                    if image.media_state is ImageMediumState.QUALIFIED
                    else image.media_state.value
                ),
            ),
        ]
        calculated_weights = tuple(
            base_bp * fidelity_bp * policy.eligible_quality_bp
            if score_milli is not None and fidelity_bp > 0
            else 0
            for _, score_milli, base_bp, fidelity_bp, _, _ in lane_values
        )
        effective_weights = (
            calculated_weights[0],
            calculated_weights[1],
            calculated_weights[2],
        )
        total_effective = sum(effective_weights)
        if total_effective <= 0:
            raise ValueError(f"attribute {attribute_id.value} has no eligible observed lane")
        percentages = _largest_remainder_percentages(effective_weights)
        score_numerator = sum(
            score_milli * effective
            for (_, score_milli, _, _, _, _), effective in zip(
                lane_values, effective_weights, strict=True
            )
            if score_milli is not None
        )
        score_milli = _half_up(score_numerator, total_effective)

        traces: list[LaneContributionTrace] = []
        paired_lanes = zip(lane_values, effective_weights, strict=True)
        for index, (
            (lane_id, score, base_bp, fidelity_bp, evidence, reason),
            effective,
        ) in enumerate(paired_lanes):
            included = score is not None and effective > 0
            traces.append(
                LaneContributionTrace(
                    lane_id=lane_id,
                    included=included,
                    exclusion_reason=None if included else reason or "ZERO_EFFECTIVE_WEIGHT",
                    score_milli=score if included else None,
                    base_weight_bp=base_bp,
                    fidelity_bp=fidelity_bp,
                    quality_bp=(
                        policy.eligible_quality_bp if included else policy.excluded_quality_bp
                    ),
                    effective_weight_numerator=effective,
                    normalized_weight_numerator=effective,
                    normalized_weight_denominator=total_effective,
                    display_weight_percent=percentages[index],
                    contribution_numerator=(
                        score * effective if included and score is not None else 0
                    ),
                    contribution_denominator=total_effective,
                    evidence_refs=evidence if included else (),
                )
            )
        fused.append(
            FusedAttribute(
                attribute_id=attribute_id,
                axis_id=axis_id,
                score_milli=score_milli,
                lanes=(traces[0], traces[1], traces[2]),
                fusion_policy_sha256=policy.policy_sha256,
            )
        )
    return tuple(fused)


def _axis_attributes(
    fused: tuple[FusedAttribute, ...], axis_id: AxisId
) -> tuple[FusedAttribute, ...]:
    rows = tuple(row for row in fused if row.axis_id == axis_id)
    if len(rows) != 4:
        raise ValueError(f"axis {axis_id} requires exactly four fused attributes")
    return rows


def _pair_agreement(
    axis_rows: tuple[FusedAttribute, ...],
    left_index: int,
    right_index: int,
    *,
    minimum_shared: int,
) -> ComparableLanePair | None:
    shared: list[SubattributeId] = []
    absolute_distance = 0
    for attribute in axis_rows:
        left = attribute.lanes[left_index]
        right = attribute.lanes[right_index]
        if not left.included or not right.included:
            continue
        if left.score_milli is None or right.score_milli is None:
            raise ValueError("included comparable lane is missing a score")
        shared.append(attribute.attribute_id)
        absolute_distance += abs(left.score_milli - right.score_milli)
    if len(shared) < minimum_shared:
        return None
    denominator = len(shared) * 4_000
    numerator = (denominator - absolute_distance) * 10_000
    lane_order = tuple(LaneId)
    return ComparableLanePair(
        left_lane=lane_order[left_index],
        right_lane=lane_order[right_index],
        shared_attribute_ids=tuple(shared),
        absolute_distance_milli_sum=absolute_distance,
        agreement_numerator=numerator,
        agreement_denominator=denominator,
    )


def compute_profile_confidence(
    fused: tuple[FusedAttribute, ...],
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> ProfileConfidence:
    """Compute confidence after scoring, never as an input to scoring or ranking."""

    if tuple(row.attribute_id for row in fused) != tuple(SubattributeId):
        raise ValueError("confidence requires canonical H1-R4 fused attributes")
    if policy.policy_sha256 is None:
        raise ValueError("fusion policy must be digest bound")
    pair_indexes = ((0, 1), (0, 2), (1, 2))
    axes: list[AxisConfidenceTrace] = []
    for axis_id in ("H", "E", "R"):
        axis_rows = _axis_attributes(fused, axis_id)
        fidelity_numerator = sum(
            lane.effective_weight_numerator for attribute in axis_rows for lane in attribute.lanes
        )
        fidelity_denominator = len(axis_rows) * 100_000_000
        fidelity_bp = _half_up(fidelity_numerator, fidelity_denominator)
        pairs = tuple(
            pair
            for left, right in pair_indexes
            if (
                pair := _pair_agreement(
                    axis_rows,
                    left,
                    right,
                    minimum_shared=policy.agreement_min_shared_attributes,
                )
            )
            is not None
        )
        agreement_bp: int | None = None
        if pairs:
            exact_agreement = sum(
                (Fraction(pair.agreement_numerator, pair.agreement_denominator) for pair in pairs),
                start=Fraction(0, 1),
            ) / len(pairs)
            agreement_bp = _half_up(exact_agreement.numerator, exact_agreement.denominator)
        fidelity_contribution = _half_up(policy.fidelity_share_bp * fidelity_bp, 10_000)
        agreement_contribution = (
            _half_up(policy.agreement_share_bp * agreement_bp, 10_000)
            if agreement_bp is not None
            else 0
        )
        confidence_bp = fidelity_contribution + agreement_contribution
        confidence_percent = _half_up(confidence_bp, 100)
        publication_state, mismatch_authorized = classify_publication(
            confidence_percent, policy=policy
        )
        axes.append(
            AxisConfidenceTrace(
                axis_id=axis_id,
                fidelity_effective_numerator=fidelity_numerator,
                fidelity_denominator=fidelity_denominator,
                fidelity_bp=fidelity_bp,
                comparable_lane_pairs=pairs,
                agreement_status=(
                    AgreementStatus.AVAILABLE if pairs else AgreementStatus.UNAVAILABLE
                ),
                agreement_bp=agreement_bp,
                fidelity_share_bp=policy.fidelity_share_bp,
                agreement_share_bp=policy.agreement_share_bp,
                fidelity_contribution_bp=fidelity_contribution,
                agreement_contribution_bp=agreement_contribution,
                confidence_bp=confidence_bp,
                confidence_percent=confidence_percent,
                publication_state=publication_state,
                mismatch_warning_authorized=mismatch_authorized,
                policy_sha256=policy.policy_sha256,
            )
        )
    overall = min(row.confidence_percent for row in axes)
    publication_state, mismatch_authorized = classify_publication(overall, policy=policy)
    return ProfileConfidence(
        axes=(axes[0], axes[1], axes[2]),
        overall_rule="MINIMUM_AXIS_CONFIDENCE_V1",
        overall_confidence_percent=overall,
        publication_state=publication_state,
        mismatch_warning_authorized=mismatch_authorized,
        policy_sha256=policy.policy_sha256,
    )


def derive_final_axes(
    fused: tuple[FusedAttribute, ...],
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
    claimed_axes: tuple[FusedAxis, ...] | None = None,
) -> tuple[FusedAxis, FusedAxis, FusedAxis]:
    """Derive final H-E-R axes locally and optionally reject a stored claim drift."""

    if tuple(row.attribute_id for row in fused) != tuple(SubattributeId):
        raise ValueError("final axes require canonical H1-R4 fused attributes")
    if policy.policy_sha256 is None:
        raise ValueError("fusion policy must be digest bound")
    axes: list[FusedAxis] = []
    for axis_id in policy.axis_tie_order:
        rows = _axis_attributes(fused, axis_id)
        score_milli = _half_up(sum(row.score_milli for row in rows), 4)
        axes.append(
            FusedAxis(
                axis_id=axis_id,
                member_attribute_ids=(
                    rows[0].attribute_id,
                    rows[1].attribute_id,
                    rows[2].attribute_id,
                    rows[3].attribute_id,
                ),
                aggregation_rule=policy.axis_aggregation_rule,
                score_milli=score_milli,
                score_percent=_half_up(score_milli, 40),
                policy_sha256=policy.policy_sha256,
            )
        )
    result = (axes[0], axes[1], axes[2])
    if claimed_axes is not None and (
        len(claimed_axes) != 3
        or any(
            claim.model_dump(mode="json") != actual.model_dump(mode="json")
            for claim, actual in zip(claimed_axes, result, strict=True)
        )
    ):
        raise ValueError("final axis claim drifted")
    return result


def derive_display_label(
    axes: tuple[FusedAxis, FusedAxis, FusedAxis],
    *,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> DisplayLabelDecision:
    """Apply D-21 using score_milli thresholds and the canonical H-E-R tie order."""

    if tuple(row.axis_id for row in axes) != policy.axis_tie_order:
        raise ValueError("display label requires canonical H-E-R axes")
    if policy.policy_sha256 is None:
        raise ValueError("fusion policy must be digest bound")
    order = {axis_id: index for index, axis_id in enumerate(policy.axis_tie_order)}
    ranked = sorted(axes, key=lambda row: (-row.score_milli, order[row.axis_id]))
    top, second = ranked[:2]
    gap_milli = top.score_milli - second.score_milli
    names = {"H": "역사·전통", "E": "감성·이미지", "R": "휴식·몰입"}
    ids = {"H": "history-tradition", "E": "emotion-image", "R": "rest-immersion"}
    if (
        top.score_milli >= policy.label_single_min_percent * 40
        and gap_milli >= policy.label_single_gap_min_percent * 40
    ):
        state = DisplayLabelState.SINGLE
        axis_ids: tuple[AxisId, ...] = (top.axis_id,)
        label_id = f"{ids[top.axis_id]}-type"
        label_ko = f"{names[top.axis_id]}형"
    elif (
        second.score_milli >= policy.label_composite_min_percent * 40
        and gap_milli < policy.label_composite_gap_exclusive_percent * 40
    ):
        state = DisplayLabelState.COMPOSITE
        axis_ids = (top.axis_id, second.axis_id)
        label_id = f"{ids[top.axis_id]}+{ids[second.axis_id]}"
        label_ko = f"{names[top.axis_id]}·{names[second.axis_id]} 복합형"
    else:
        state = DisplayLabelState.FALLBACK
        axis_ids = ()
        label_id = "mixed-experience"
        label_ko = "복합 경험형"
    return DisplayLabelDecision(
        state=state,
        axis_ids=axis_ids,
        label_id=label_id,
        label_ko=label_ko,
        top_score_milli=top.score_milli,
        second_score_milli=second.score_milli,
        gap_milli=gap_milli,
        label_rule_version=policy.label_rule_version,
        single_min_percent=policy.label_single_min_percent,
        single_gap_min_percent=policy.label_single_gap_min_percent,
        composite_min_percent=policy.label_composite_min_percent,
        composite_gap_exclusive_percent=policy.label_composite_gap_exclusive_percent,
        tie_order=policy.axis_tie_order,
        policy_sha256=policy.policy_sha256,
    )


def build_fused_profile(
    baseline: Phase3LaneBaselineMember,
    image: ImageObservationV2,
    *,
    predecessor_profile: PlaceProfile,
    policy: FusionPolicyConfig = CANONICAL_FUSION_POLICY,
) -> FusedProfileProjection:
    """Build the complete deterministic sidecar after proving exact predecessor lineage."""

    predecessor_sha256 = canonical_sha256(predecessor_profile.model_dump(mode="json"))
    if predecessor_sha256 != baseline.profile_sha256:
        raise ValueError("predecessor profile digest does not match baseline authority")
    if predecessor_profile.place_id != baseline.place_ref:
        raise ValueError("predecessor profile place identity does not match baseline")
    predecessor_traits = tuple(
        (row.trait_id, row.value) for row in predecessor_profile.mismatch_traits
    )
    baseline_traits = tuple((row.trait_id, row.value) for row in baseline.mismatch_traits)
    if predecessor_traits != baseline_traits:
        raise ValueError("predecessor mismatch traits do not match baseline authority")
    if baseline.member_sha256 is None:
        raise ValueError("baseline member must be digest bound")

    attributes = fuse_attributes(baseline, image, policy=policy)
    confidence = compute_profile_confidence(attributes, policy=policy)
    axes = derive_final_axes(attributes, policy=policy)
    label = derive_display_label(axes, policy=policy)
    if image.observation_sha256 is None:
        raise ValueError("image observation must be digest bound")
    if policy.policy_sha256 is None:
        raise ValueError("fusion policy must be digest bound")
    return FusedProfileProjection(
        place_ref=baseline.place_ref,
        predecessor_profile_sha256=predecessor_sha256,
        baseline_member_sha256=baseline.member_sha256,
        image_observation_sha256=image.observation_sha256,
        attributes=attributes,
        axes=axes,
        mismatch_traits=predecessor_profile.mismatch_traits,
        inherited_evidence=predecessor_profile.evidence,
        mismatch_lineage_rule="EXACT_PREDECESSOR_COPY_V1",
        confidence=confidence,
        display_label=label,
        policy_sha256=policy.policy_sha256,
    )


__all__ = [
    "count_meaningful_characters",
    "classify_publication",
    "build_fused_profile",
    "compute_profile_confidence",
    "description_fidelity_bp",
    "derive_display_label",
    "derive_final_axes",
    "fuse_attributes",
    "image_fidelity_bp",
    "odii_fidelity_bp",
    "require_release_eligible_policy",
]
