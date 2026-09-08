"""Pure fixed-point recommendation kernel for the public DEV cohort."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Literal

from itda.contracts.base import DataSplit, ExperienceAxis
from itda.contracts.phase5_recovery_policy import (
    ACTIVATION_SUITE_SHA256,
    CANONICAL_CONTRAST_PAIRS,
    CANONICAL_PHASE5_RECOVERY_POLICY,
    CANONICAL_SCENARIO_IDS,
    CONTRAST_SUITE_SHA256,
    ActivationScenarioResult,
    ActivationSuiteEvaluation,
    CannotCoappearAuthority,
    ContrastResult,
    validate_activation_scenario_results,
    validate_contrast_results,
)
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY
from itda.contracts.recommendation import (
    CANONICAL_RECOMMENDATION_CONFIG,
    AxisContribution,
    CandidateExclusion,
    CandidateExclusionReason,
    CandidateScoreTrace,
    ConditionContribution,
    DiversityCandidateScore,
    DiversityStep,
    DuplicateDecision,
    ExplanationLink,
    MismatchGuidance,
    MismatchGuidanceState,
    Publishability,
    RecommendationCandidate,
    RecommendationConfig,
    RecommendationItem,
    RecommendationPreference,
    RecommendationRun,
    ScoreContribution,
    TravelConditionId,
    confidence_state_for,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

# Kept as a compatibility import for callers that introspect the fusion contract;
# recovery candidacy itself is owned by CANONICAL_PHASE5_RECOVERY_POLICY.
_ = CANONICAL_FUSION_POLICY


class RecommendationKernelError(RuntimeError):
    """Stable fail-closed kernel outcome with no partial recommendation body."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_RECOVERY_POLICY = CANONICAL_PHASE5_RECOVERY_POLICY
_CANONICAL_CANNOT_COAPPEAR = _RECOVERY_POLICY.cannot_coappear_authority


def _target_compatible_ids(
    place_ids: tuple[str, ...], authority: CannotCoappearAuthority, *, target: int = 5
) -> tuple[str, ...] | None:
    """Find the canonical first target-sized compatible subset in O(n^target)."""

    ordered = tuple(sorted(place_ids))
    forbidden = {
        frozenset((left, right))
        for left, right in authority.pairs
        if left in ordered and right in ordered
    }
    visited = 0
    maximum_states = sum(len(ordered) ** depth for depth in range(target + 1))

    def search(start: int, selected: tuple[str, ...]) -> tuple[str, ...] | None:
        nonlocal visited
        visited += 1
        if visited > maximum_states:
            raise RecommendationKernelError("COMPATIBILITY_SEARCH_BOUND_EXCEEDED")
        if len(selected) == target:
            return selected
        needed = target - len(selected)
        if len(ordered) - start < needed:
            return None
        for index in range(start, len(ordered)):
            candidate = ordered[index]
            if any(frozenset((candidate, prior)) in forbidden for prior in selected):
                continue
            found = search(index + 1, selected + (candidate,))
            if found is not None:
                return found
        return None

    return search(0, ())


# Compatibility alias: callers need only target-k feasibility, never a maximum set.
def _maximum_compatible_ids(
    place_ids: tuple[str, ...], authority: CannotCoappearAuthority
) -> tuple[str, ...]:
    found = _target_compatible_ids(place_ids, authority)
    return found or ()


def _validate_cannot_coappear_authority(
    authority: CannotCoappearAuthority | None,
) -> CannotCoappearAuthority:
    resolved = _CANONICAL_CANNOT_COAPPEAR if authority is None else authority
    if resolved != _CANONICAL_CANNOT_COAPPEAR:
        if resolved.authority_sha256 is None:
            raise RecommendationKernelError("INVALID_CANNOT_COAPPEAR_AUTHORITY")
        if resolved.scope != _CANONICAL_CANNOT_COAPPEAR.scope:
            raise RecommendationKernelError("INVALID_CANNOT_COAPPEAR_AUTHORITY")
        if resolved.dev_place_ids != _CANONICAL_CANNOT_COAPPEAR.dev_place_ids:
            raise RecommendationKernelError("INVALID_CANNOT_COAPPEAR_AUTHORITY")
        if (
            resolved.authoritative_relationship_leaves_sha256
            != _CANONICAL_CANNOT_COAPPEAR.authoritative_relationship_leaves_sha256
        ):
            raise RecommendationKernelError("INVALID_CANNOT_COAPPEAR_AUTHORITY")
    return resolved


def _compatible_with_selected(
    place_id: str,
    selected_ids: tuple[str, ...],
    authority: CannotCoappearAuthority,
) -> bool:
    return all(not authority.forbids(place_id, selected) for selected in selected_ids)


def _recovery_candidate_eligible(candidate: RecommendationCandidate) -> bool:
    return candidate.overall_confidence >= _RECOVERY_POLICY.candidate_confidence_min


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


def _eligibility_reason(candidate: RecommendationCandidate) -> CandidateExclusionReason | None:
    if candidate.split is not DataSplit.DEV:
        return CandidateExclusionReason.NOT_DEV
    if not candidate.exact_release_member:
        return CandidateExclusionReason.NOT_EXACT_RELEASE_MEMBER
    if candidate.profile_score_truth != "LOCAL_PROFILE_SCORES":
        return CandidateExclusionReason.NOT_LOCAL_PROFILE_SCORES
    if candidate.analysis_origin != "DEMO_MODEL_DERIVED":
        return CandidateExclusionReason.NOT_DEMO_MODEL_DERIVED
    if candidate.publishability is Publishability.EXCLUDED:
        return CandidateExclusionReason.NOT_PUBLISHABLE
    if not _recovery_candidate_eligible(candidate):
        return CandidateExclusionReason.NOT_RECOMMENDATION_ELIGIBLE
    if not candidate.recommendation_eligible:
        return CandidateExclusionReason.NOT_RECOMMENDATION_ELIGIBLE
    return None


def _suppress_duplicates(
    candidates: tuple[RecommendationCandidate, ...],
) -> tuple[
    tuple[RecommendationCandidate, ...],
    tuple[DuplicateDecision, ...],
    tuple[CandidateExclusion, ...],
]:
    groups: dict[str, list[RecommendationCandidate]] = {}
    ungrouped: list[RecommendationCandidate] = []
    for candidate in candidates:
        if candidate.duplicate_group_id is None:
            ungrouped.append(candidate)
        else:
            groups.setdefault(candidate.duplicate_group_id, []).append(candidate)

    kept = list(ungrouped)
    decisions: list[DuplicateDecision] = []
    exclusions: list[CandidateExclusion] = []
    for group_id in sorted(groups):
        members = sorted(groups[group_id], key=lambda row: row.place_id)
        kept.append(members[0])
        if len(members) == 1:
            continue
        suppressed_ids = tuple(row.place_id for row in members[1:])
        decisions.append(
            DuplicateDecision(
                duplicate_group_id=group_id,
                kept_place_id=members[0].place_id,
                suppressed_place_ids=suppressed_ids,
            )
        )
        exclusions.extend(
            CandidateExclusion(
                place_id=place_id,
                reason=CandidateExclusionReason.HARD_DUPLICATE,
            )
            for place_id in suppressed_ids
        )
    return (
        tuple(sorted(kept, key=lambda row: row.place_id)),
        tuple(decisions),
        tuple(sorted(exclusions, key=lambda row: row.place_id)),
    )


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


def _score_candidate(
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


def _novelty_distance(
    candidate: RecommendationCandidate,
    selected: Iterable[RecommendationCandidate],
    *,
    config: RecommendationConfig,
) -> int:
    distances: list[int] = []
    for prior in selected:
        axis_distance = _half_up(
            sum(
                abs(left.value - right.value)
                for left, right in zip(candidate.axis_scores, prior.axis_scores, strict=True)
            ),
            3,
        )
        trait_distance = _half_up(
            sum(
                abs(left.value - right.value)
                for left, right in zip(
                    candidate.mismatch_traits, prior.mismatch_traits, strict=True
                )
            ),
            6,
        )
        distances.append(
            _half_up(
                axis_distance * config.mismatch_axis_bp + trait_distance * config.mismatch_trait_bp,
                10_000,
            )
        )
    return min(distances) if distances else 100


def _explanations(
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


def rank_recommendations(
    *,
    preference: RecommendationPreference,
    candidates: tuple[RecommendationCandidate, ...],
    release_sha256: str,
    canonical_membership_sha256: str,
    created_at: object,
    config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
    cannot_coappear_authority: CannotCoappearAuthority | None = None,
) -> RecommendationRun:
    """Return one complete immutable Top 5 receipt or a stable named failure."""

    if config != CANONICAL_RECOMMENDATION_CONFIG or config.config_sha256 is None:
        raise RecommendationKernelError("INVALID_RECOMMENDATION_CONFIG")
    ordered = tuple(sorted(candidates, key=lambda row: row.place_id))
    if not ordered or len({row.place_id for row in ordered}) != len(ordered):
        raise RecommendationKernelError("INVALID_RECOMMENDATION_INPUT")

    exclusions: list[CandidateExclusion] = []
    eligible: list[RecommendationCandidate] = []
    for candidate in ordered:
        reason = _eligibility_reason(candidate)
        if reason is None:
            eligible.append(candidate)
        else:
            exclusions.append(CandidateExclusion(place_id=candidate.place_id, reason=reason))

    deduplicated, duplicate_decisions, duplicate_exclusions = _suppress_duplicates(tuple(eligible))
    exclusions.extend(duplicate_exclusions)
    if len(deduplicated) < config.top_k:
        raise RecommendationKernelError("INSUFFICIENT_ELIGIBLE_CANDIDATES")

    score_by_place: dict[str, tuple[ScoreContribution, MismatchGuidance]] = {
        candidate.place_id: _score_candidate(
            preference=preference,
            candidate=candidate,
            config=config,
        )
        for candidate in deduplicated
    }
    authority = _validate_cannot_coappear_authority(cannot_coappear_authority)
    compatible_capacity = len(
        _maximum_compatible_ids(tuple(candidate.place_id for candidate in deduplicated), authority)
    )
    if compatible_capacity < config.top_k:
        raise RecommendationKernelError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
    candidate_by_id = {candidate.place_id: candidate for candidate in deduplicated}

    selected: list[RecommendationCandidate] = []
    steps: list[DiversityStep] = []
    remaining = list(deduplicated)
    while len(selected) < config.top_k:
        considered: list[DiversityCandidateScore] = []
        selected_ids = tuple(row.place_id for row in selected)
        for candidate in remaining:
            relevance = score_by_place[candidate.place_id][0].relevance_score
            novelty = _novelty_distance(candidate, selected, config=config)
            combined = _half_up(
                relevance * config.relevance_rerank_bp + novelty * config.diversity_rerank_bp,
                10_000,
            )
            if _compatible_with_selected(candidate.place_id, selected_ids, authority):
                considered.append(
                    DiversityCandidateScore(
                        place_id=candidate.place_id,
                        relevance_score=relevance,
                        novelty_score=novelty,
                        combined_score=combined,
                    )
                )
            else:
                owner = next(
                    previous
                    for previous in selected_ids
                    if authority.forbids(candidate.place_id, previous)
                )
                considered.append(
                    DiversityCandidateScore(
                        place_id=candidate.place_id,
                        relevance_score=relevance,
                        novelty_score=novelty,
                        combined_score=combined,
                        suppression_reason="CANNOT_COAPPEAR",
                        suppressed_by_place_id=owner,
                    )
                )
        if not considered:
            raise RecommendationKernelError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
        eligible_considered = [row for row in considered if not row.is_suppressed]
        if not eligible_considered:
            raise RecommendationKernelError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
        winner_score = min(
            eligible_considered,
            key=lambda row: (
                -row.combined_score,
                -row.relevance_score,
                -row.novelty_score,
                row.place_id,
            ),
        )
        winner = candidate_by_id[winner_score.place_id]
        selected.append(winner)
        remaining = [row for row in remaining if row.place_id != winner.place_id]
        suppressed_rows = tuple(row for row in considered if row.is_suppressed)
        exclusions.extend(
            CandidateExclusion(
                place_id=row.place_id,
                reason=CandidateExclusionReason.CANNOT_COAPPEAR,
            )
            for row in suppressed_rows
            if row.place_id not in {candidate.place_id for candidate in remaining}
        )
        steps.append(
            DiversityStep(
                rank=len(selected),
                selected_place_id=winner.place_id,
                relevance_score=winner_score.relevance_score,
                novelty_score=winner_score.novelty_score,
                combined_score=winner_score.combined_score,
                considered=tuple(sorted(considered, key=lambda row: row.place_id)),
                suppressed_place_ids=tuple(row.place_id for row in suppressed_rows),
            )
        )

    items: list[RecommendationItem] = []
    for rank, (candidate, step) in enumerate(zip(selected, steps, strict=True), start=1):
        base_contribution, mismatch = score_by_place[candidate.place_id]
        contribution_payload = base_contribution.model_dump(mode="json")
        contribution_payload.update(
            diversity_novelty_score=step.novelty_score,
            rerank_score=step.combined_score,
            rerank_numerator=(
                step.relevance_score * config.relevance_rerank_bp
                + step.novelty_score * config.diversity_rerank_bp
            ),
        )
        contribution = ScoreContribution.model_validate(contribution_payload)
        explanations = _explanations(candidate, contribution)
        explanation_evidence_ids = {row.evidence_id for row in explanations}
        item_evidence = tuple(
            row for row in candidate.evidence if row.evidence_id in explanation_evidence_ids
        )
        confidence_state, confidence_reason = confidence_state_for(candidate.overall_confidence)
        items.append(
            RecommendationItem(
                rank=rank,
                place_id=candidate.place_id,
                place_name_ko=candidate.place_name_ko,
                fit_score=base_contribution.relevance_score,
                evidence_confidence_state=confidence_state,
                evidence_confidence_reason_ko=confidence_reason,
                mismatch=mismatch,
                contribution=contribution,
                axis_scores=candidate.axis_scores,
                explanations=explanations,
                evidence=item_evidence,
                reference_date=candidate.reference_date,
                image_state=candidate.image_state,
            )
        )

    candidate_set_digest = canonical_sha256(
        [
            {
                "place_id": candidate.place_id,
                "profile_sha256": candidate.profile_sha256,
                "duplicate_group_id": candidate.duplicate_group_id,
            }
            for candidate in ordered
        ]
    )
    input_digest = canonical_sha256(
        {
            "preference": preference.model_dump(mode="json"),
            "release_sha256": release_sha256,
            "canonical_membership_sha256": canonical_membership_sha256,
            "candidate_set_digest": candidate_set_digest,
            "config_sha256": config.config_sha256,
            "kernel_version": config.kernel_version,
            "recovery_policy_sha256": _RECOVERY_POLICY.policy_sha256,
            "hard_duplicate_adjudication_sha256": (
                _RECOVERY_POLICY.hard_duplicate_adjudication_sha256
            ),
            "cannot_coappear_authority_sha256": authority.authority_sha256,
            "activation_suite_sha256": _RECOVERY_POLICY.activation_suite_sha256,
            "contrast_suite_sha256": _RECOVERY_POLICY.contrast_suite_sha256,
        }
    )
    scored_candidates = tuple(
        CandidateScoreTrace(
            place_id=candidate.place_id,
            relevance_score=score_by_place[candidate.place_id][0].relevance_score,
            experience_fit_score=score_by_place[candidate.place_id][0].experience_fit_score,
            travel_condition_fit_score=score_by_place[candidate.place_id][
                0
            ].travel_condition_fit_score,
            contribution=score_by_place[candidate.place_id][0],
            mismatch=score_by_place[candidate.place_id][1],
        )
        for candidate in deduplicated
    )
    authority_trace = {
        "recovery_policy_sha256": _RECOVERY_POLICY.policy_sha256,
        "hard_duplicate_adjudication_sha256": _RECOVERY_POLICY.hard_duplicate_adjudication_sha256,
        "cannot_coappear_authority_sha256": authority.authority_sha256,
        "activation_suite_sha256": _RECOVERY_POLICY.activation_suite_sha256,
        "contrast_suite_sha256": _RECOVERY_POLICY.contrast_suite_sha256,
    }
    deterministic_payload = {
        "schema_version": "recommendation-run.v1",
        "input_digest": input_digest,
        "release_sha256": release_sha256,
        "canonical_membership_sha256": canonical_membership_sha256,
        "config_sha256": config.config_sha256,
        "kernel_version": config.kernel_version,
        "candidate_set_digest": candidate_set_digest,
        "authority": authority_trace,
        "candidate_place_ids": [candidate.place_id for candidate in ordered],
        "exclusions": [
            row.model_dump(mode="json") for row in sorted(exclusions, key=lambda row: row.place_id)
        ],
        "duplicate_decisions": [row.model_dump(mode="json") for row in duplicate_decisions],
        "scored_candidates": [row.model_dump(mode="json") for row in scored_candidates],
        "diversity_steps": [row.model_dump(mode="json") for row in steps],
        "items": [row.model_dump(mode="json") for row in items],
        "ndcg_status": "NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS",
        "ndcg_denominator": 0,
    }
    receipt_sha256 = canonical_sha256(deterministic_payload)
    return RecommendationRun.model_validate(
        {
            **deterministic_payload,
            "run_id": f"recommendation-run:{receipt_sha256[:32]}",
            "created_at": created_at,
            "canonical_sha256": receipt_sha256,
        }
    )


def _scenario_preference(
    scenario: Mapping[str, object],
    *,
    base_preference: RecommendationPreference,
) -> RecommendationPreference:
    parameters = scenario.get("parameters")
    if not isinstance(parameters, Mapping):
        raise RecommendationKernelError("ACTIVATION_SCENARIO_INVALID")
    axis_values = parameters.get("axis_targets")
    if not isinstance(axis_values, Sequence) or isinstance(axis_values, (str, bytes)):
        raise RecommendationKernelError("ACTIVATION_SCENARIO_INVALID")
    if len(axis_values) != len(base_preference.axis_targets) or any(
        type(value) is not int or not 0 <= value <= 100 for value in axis_values
    ):
        raise RecommendationKernelError("ACTIVATION_SCENARIO_INVALID")
    variant = parameters.get("condition_variant")
    condition_values = {
        "MORNING_SOLO": (50, 0, 0, 0, 50, 0),
        "SUNSET_PARTNER": (100, 25, 50, 50, 50, 50),
        "DAYTIME_SENIORS": (50, 25, 50, 50, 50, 0),
        "FAMILY_CAR": (50, 75, 100, 50, 50, 50),
        "EVENING_WALK": (100, 0, 0, 100, 50, 50),
        "GROUP_TRANSIT": (50, 100, 0, 50, 50, 50),
        "OUTDOOR_LOW_CROWD": (50, 50, 50, 100, 100, 0),
        "UNDECIDED": (0, 0, 0, 0, 50, 50),
    }.get(variant)
    if condition_values is None:
        raise RecommendationKernelError("ACTIVATION_SCENARIO_INVALID")
    axes = tuple(
        row.model_copy(update={"value": value})
        for row, value in zip(base_preference.axis_targets, axis_values, strict=True)
    )
    conditions = tuple(
        row.model_copy(update={"value": value})
        for row, value in zip(base_preference.condition_targets, condition_values, strict=True)
    )
    return base_preference.model_copy(
        update={"axis_targets": axes, "condition_targets": conditions}
    )


def _contribution_digest(run: RecommendationRun) -> str:
    return canonical_sha256(
        [
            {"place_id": row.place_id, "contribution": row.contribution.model_dump(mode="json")}
            for row in run.scored_candidates
        ]
    )


def evaluate_activation_scenarios(
    *,
    candidates: tuple[RecommendationCandidate, ...],
    release_sha256: str,
    canonical_membership_sha256: str,
    base_preference: RecommendationPreference,
    scenario_source: object | None = None,
    config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
    cannot_coappear_authority: CannotCoappearAuthority | None = None,
    created_at: object | None = None,
) -> ActivationSuiteEvaluation:
    """Run and independently replay exactly the eight critical scenarios and seven contrasts.

    ``created_at`` is the fixed evidence timestamp injected into every run
    receipt: the SAME value flows into the original evaluation and the
    independent replay (which reuses ``original.created_at``), so the whole
    suite is deterministic for identical inputs.  When omitted, the current
    UTC time is captured ONCE for the entire evaluation — never per scenario
    — so all eight runs still share one timestamp.
    """

    source_path = scenario_source or (
        __import__("pathlib").Path(__file__).resolve().parents[3]
        / "tests/evals/phase5/recommendation_scenarios.json"
    )
    try:
        fixture = json.loads(source_path.read_text(encoding="utf-8"))
        rows = fixture["scenarios"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise RecommendationKernelError("ACTIVATION_SCENARIO_SOURCE_INVALID") from error
    if not isinstance(rows, list):
        raise RecommendationKernelError("ACTIVATION_SCENARIO_SOURCE_INVALID")
    critical_rows = {
        row.get("scenario_id"): row
        for row in rows
        if isinstance(row, Mapping) and row.get("scenario_id") in CANONICAL_SCENARIO_IDS
    }
    if tuple(critical_rows) != CANONICAL_SCENARIO_IDS:
        raise RecommendationKernelError("ACTIVATION_SCENARIO_SOURCE_INCOMPLETE")
    fixed_created_at = (
        created_at
        if created_at is not None
        else (__import__("datetime").datetime.now(__import__("datetime").UTC))
    )
    results = []
    runs: dict[str, RecommendationRun] = {}
    for scenario_id in CANONICAL_SCENARIO_IDS:
        preference = _scenario_preference(
            critical_rows[scenario_id], base_preference=base_preference
        )
        run = rank_recommendations(
            preference=preference,
            candidates=candidates,
            release_sha256=release_sha256,
            canonical_membership_sha256=canonical_membership_sha256,
            created_at=fixed_created_at,
            config=config,
            cannot_coappear_authority=cannot_coappear_authority,
        )
        replayed = replay_recommendation(
            run,
            preference=preference,
            candidates=candidates,
            release_sha256=release_sha256,
            canonical_membership_sha256=canonical_membership_sha256,
            config=config,
            cannot_coappear_authority=cannot_coappear_authority,
        )
        results.append(
            ActivationScenarioResult(
                scenario_id=scenario_id,
                status="SUCCESS",
                eligible_place_ids=tuple(item.place_id for item in run.items),
                result_sha256=canonical_sha256(run.model_dump(mode="json")),
                replay_sha256=canonical_sha256(replayed.model_dump(mode="json")),
                contribution_sha256=_contribution_digest(run),
            )
        )
        runs[scenario_id] = run
    scenario_models = tuple(results)
    contrasts = tuple(
        ContrastResult(
            left_scenario_id=left_id,
            right_scenario_id=right_id,
            left_result_sha256=next(
                row.result_sha256 for row in scenario_models if row.scenario_id == left_id
            ),
            right_result_sha256=next(
                row.result_sha256 for row in scenario_models if row.scenario_id == right_id
            ),
            left_contribution_sha256=_contribution_digest(runs[left_id]),
            right_contribution_sha256=_contribution_digest(runs[right_id]),
            left_place_ids=tuple(item.place_id for item in runs[left_id].items),
            right_place_ids=tuple(item.place_id for item in runs[right_id].items),
        )
        for left_id, right_id in CANONICAL_CONTRAST_PAIRS
    )
    validate_activation_scenario_results({row.scenario_id: row for row in scenario_models})
    validate_contrast_results({row.pair: row for row in contrasts}, scenarios=scenario_models)
    return ActivationSuiteEvaluation(
        scenario_results=scenario_models,
        contrast_results=contrasts,
        activation_suite_sha256=ACTIVATION_SUITE_SHA256,
        contrast_suite_sha256=CONTRAST_SUITE_SHA256,
    )


def replay_recommendation(
    original: RecommendationRun,
    *,
    preference: RecommendationPreference,
    candidates: tuple[RecommendationCandidate, ...],
    release_sha256: str,
    canonical_membership_sha256: str,
    config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
    cannot_coappear_authority: CannotCoappearAuthority | None = None,
) -> RecommendationRun:
    """Recompute from bound inputs and reject any byte-level receipt drift."""

    replayed = rank_recommendations(
        preference=preference,
        candidates=candidates,
        release_sha256=release_sha256,
        canonical_membership_sha256=canonical_membership_sha256,
        created_at=original.created_at,
        config=config,
        cannot_coappear_authority=cannot_coappear_authority,
    )
    if canonical_json_bytes(replayed.model_dump(mode="json")) != canonical_json_bytes(
        original.model_dump(mode="json")
    ):
        raise RecommendationKernelError("REPLAY_MISMATCH")
    return replayed


__all__ = [
    "RecommendationKernelError",
    "evaluate_activation_scenarios",
    "rank_recommendations",
    "replay_recommendation",
]
