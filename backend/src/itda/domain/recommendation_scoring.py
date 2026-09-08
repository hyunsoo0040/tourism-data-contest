"""Policy-independent fixed-point scoring shared by recommendation kernels."""

from __future__ import annotations

from typing import Literal

from itda.contracts.base import ExperienceAxis
from itda.contracts.recommendation import (
    AxisContribution,
    ConditionContribution,
    ExplanationLink,
    MismatchGuidance,
    MismatchGuidanceState,
    RecommendationCandidate,
    RecommendationConfig,
    RecommendationPreference,
    ScoreContribution,
    TravelConditionId,
)


def _half_up(numerator: int, denominator: int) -> int:
    if (
        type(numerator) is not int
        or numerator < 0
        or type(denominator) is not int
        or denominator <= 0
    ):
        raise ValueError(
            "half-up division requires nonnegative integers and a positive denominator"
        )
    return (2 * numerator + denominator) // (2 * denominator)


def _condition_weight(config: RecommendationConfig, condition_id: TravelConditionId) -> int:
    return {
        TravelConditionId.VISIT_DATE_TIME: config.condition_weights.visit_date_time,
        TravelConditionId.COMPANIONS: config.condition_weights.companions,
        TravelConditionId.TRANSPORT: config.condition_weights.transport,
        TravelConditionId.WALKING: config.condition_weights.walking,
        TravelConditionId.INDOOR_OUTDOOR: config.condition_weights.indoor_outdoor,
        TravelConditionId.CROWD: config.condition_weights.crowd,
    }[condition_id]


def _mismatch_guidance(
    *,
    preference: RecommendationPreference,
    candidate: RecommendationCandidate,
    config: RecommendationConfig,
) -> MismatchGuidance:
    axis_distance = _half_up(
        sum(
            abs(expected.value - actual.value)
            for expected, actual in zip(preference.axis_targets, candidate.axis_scores, strict=True)
        ),
        3,
    )
    trait_differences = tuple(
        abs(expected.value - actual.value)
        for expected, actual in zip(
            preference.trait_targets, candidate.mismatch_traits, strict=True
        )
    )
    trait_distance = _half_up(sum(trait_differences), 6)
    raw_score = _half_up(
        axis_distance * config.mismatch_axis_bp + trait_distance * config.mismatch_trait_bp,
        10_000,
    )
    floor_applied = config.mismatch_trait_bp > 0 and any(
        expected.important and difference >= config.important_trait_difference_threshold
        for expected, difference in zip(preference.trait_targets, trait_differences, strict=True)
    )
    effective_score = max(raw_score, config.important_trait_floor) if floor_applied else raw_score
    gentle, material, strong = config.mismatch_guidance_thresholds

    suppression_reason: Literal["CONFIDENCE_BELOW_65"] | None
    if candidate.overall_confidence < config.mismatch_warning_confidence_min:
        state = MismatchGuidanceState.SUPPRESSED_LOW_CONFIDENCE
        template_id = None
        message_ko = None
        suppression_reason = "CONFIDENCE_BELOW_65"
    elif effective_score < gentle:
        state = MismatchGuidanceState.NO_GUIDANCE
        template_id = None
        message_ko = None
        suppression_reason = None
    elif effective_score < material:
        state = MismatchGuidanceState.GENTLE_DIFFERENCE
        template_id = "mismatch-gentle-v1"
        message_ko = "이번 여행에서 기대한 모습과 조금 다를 수 있어요."
        suppression_reason = None
    elif effective_score < strong:
        state = MismatchGuidanceState.MATERIAL_DIFFERENCE
        template_id = "mismatch-material-v1"
        message_ko = "이번 여행에서 기대한 모습과 다른 지점이 있어요."
        suppression_reason = None
    else:
        state = MismatchGuidanceState.STRONG_DIFFERENCE
        template_id = "mismatch-strong-v1"
        message_ko = "이번 여행의 기대와 다른 지점을 방문 전에 확인해 주세요."
        suppression_reason = None

    return MismatchGuidance(
        raw_score=raw_score,
        effective_score=effective_score,
        axis_distance=axis_distance,
        trait_distance=trait_distance,
        important_trait_floor_applied=floor_applied,
        state=state,
        template_id=template_id,
        message_ko=message_ko,
        suppression_reason=suppression_reason,
    )


def score_candidate(
    *,
    preference: RecommendationPreference,
    candidate: RecommendationCandidate,
    config: RecommendationConfig,
) -> tuple[ScoreContribution, MismatchGuidance]:
    axis_rows = tuple(
        AxisContribution(
            contribution_id=f"axis:{expected.axis.value}",
            axis=expected.axis,
            expected_value=expected.value,
            place_value=actual.value,
            absolute_difference=abs(expected.value - actual.value),
            fit_score=100 - abs(expected.value - actual.value),
        )
        for expected, actual in zip(preference.axis_targets, candidate.axis_scores, strict=True)
    )
    axis_components: tuple[AxisContribution, AxisContribution, AxisContribution] = (
        axis_rows[0],
        axis_rows[1],
        axis_rows[2],
    )
    experience_fit = _half_up(sum(row.fit_score for row in axis_components), 3)
    condition_rows = tuple(
        ConditionContribution(
            contribution_id=f"condition:{expected.condition_id.value}",
            condition_id=expected.condition_id,
            expected_value=expected.value,
            place_value=actual.value,
            absolute_difference=abs(expected.value - actual.value),
            fit_score=100 - abs(expected.value - actual.value),
            total_score_weight_bp=_condition_weight(config, expected.condition_id),
            weighted_numerator=(
                (100 - abs(expected.value - actual.value))
                * _condition_weight(config, expected.condition_id)
            ),
        )
        for expected, actual in zip(
            preference.condition_targets, candidate.condition_scores, strict=True
        )
    )
    condition_components: tuple[
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
        ConditionContribution,
    ] = (
        condition_rows[0],
        condition_rows[1],
        condition_rows[2],
        condition_rows[3],
        condition_rows[4],
        condition_rows[5],
    )
    condition_fit = (
        _half_up(
            sum(row.weighted_numerator for row in condition_components),
            config.travel_condition_fit_bp,
        )
        if config.travel_condition_fit_bp > 0
        else 0
    )
    relevance_numerator = (
        experience_fit * config.experience_fit_bp + condition_fit * config.travel_condition_fit_bp
    )
    relevance = _half_up(relevance_numerator, 10_000)
    return (
        ScoreContribution(
            axis_components=axis_components,
            condition_components=condition_components,
            experience_fit_score=experience_fit,
            travel_condition_fit_score=condition_fit,
            relevance_score=relevance,
            relevance_numerator=relevance_numerator,
            diversity_novelty_score=0,
            rerank_score=_half_up(relevance * config.relevance_rerank_bp, 10_000),
            rerank_numerator=relevance * config.relevance_rerank_bp,
        ),
        _mismatch_guidance(
            preference=preference,
            candidate=candidate,
            config=config,
        ),
    )


def explanations(
    candidate: RecommendationCandidate,
    contribution: ScoreContribution,
) -> tuple[ExplanationLink, ExplanationLink]:
    best_axes = sorted(
        contribution.axis_components,
        key=lambda row: (-row.fit_score, tuple(ExperienceAxis).index(row.axis)),
    )[:2]
    axis_by_id = {row.axis: row for row in candidate.axis_scores}
    axis_labels = {
        ExperienceAxis.HISTORY_TRADITION: "역사·전통",
        ExperienceAxis.EMOTION_IMAGE: "감성·이미지",
        ExperienceAxis.REST_IMMERSION: "휴식·몰입",
    }
    result = []
    for row in best_axes:
        snapshot = axis_by_id[row.axis]
        result.append(
            ExplanationLink(
                contribution_id=row.contribution_id,
                place_attribute_id=row.axis.value,
                evidence_id=snapshot.evidence_ids[0],
                reference_date=candidate.reference_date,
                template_id=f"reason-axis-{row.axis.value.lower()}-v1",
                message_ko=f"{axis_labels[row.axis]} 기대와 장소 특성이 가까워요.",
            )
        )
    return result[0], result[1]
