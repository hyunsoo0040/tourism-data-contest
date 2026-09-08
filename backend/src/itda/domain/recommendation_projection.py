"""Pure, versioned projections from Phase 1 inputs to recommendation inputs."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, cast

from itda.contracts.base import ExperienceAxis
from itda.contracts.place_profile import MismatchTraitId
from itda.contracts.preference import (
    CompanionType,
    CrowdAvoidance,
    IndoorOutdoorPreference,
    PreferenceProfile,
    QuestionnaireAnswersV1,
    QuestionnaireAnswersV2,
    TransportType,
    TripConditions,
    VisitTime,
    WalkingTolerance,
)
from itda.contracts.recommendation import (
    PlaceConditionSnapshot,
    PreferenceAxisTarget,
    PreferenceTraitTarget,
    RecommendationPreference,
    TravelConditionId,
    TravelConditionTarget,
)
from itda.domain.canonical import canonical_sha256

if TYPE_CHECKING:
    from itda.contracts.demo_profile_materialization import PublicScoredProfile
else:
    PublicScoredProfile = Any

RECOMMENDATION_PROJECTION_VERSION: Final[str] = "recommendation-projection-v1"
RECOMMENDATION_PROJECTION_VERSION_V2: Final[str] = "recommendation-projection-v2"


def _half_up(numerator: int, denominator: int) -> int:
    if type(numerator) is not int or numerator < 0:
        raise ValueError("projection numerator must be a nonnegative integer")
    if type(denominator) is not int or denominator <= 0:
        raise ValueError("projection denominator must be a positive integer")
    return (2 * numerator + denominator) // (2 * denominator)


def _normalize_answer(answer: int) -> int:
    if type(answer) is not int or not 1 <= answer <= 5:
        raise ValueError("questionnaire answers must be integers from 1 through 5")
    return (answer - 1) * 25


_VISIT_TIME_VALUES: Mapping[VisitTime, int] = MappingProxyType(
    {
        VisitTime.UNDECIDED: 0,
        VisitTime.MORNING: 50,
        VisitTime.DAYTIME: 50,
        VisitTime.SUNSET: 100,
        VisitTime.EVENING: 100,
    }
)
_COMPANION_VALUES: Mapping[CompanionType, int] = MappingProxyType(
    {
        CompanionType.SOLO: 0,
        CompanionType.FRIEND_OR_PARTNER: 25,
        CompanionType.WITH_SENIORS: 25,
        CompanionType.FAMILY_WITH_CHILDREN: 75,
        CompanionType.GROUP: 100,
    }
)
_TRANSPORT_VALUES: Mapping[TransportType, int] = MappingProxyType(
    {
        TransportType.WALK_OR_TRANSIT: 0,
        TransportType.MIXED: 50,
        TransportType.CAR_OR_TAXI: 100,
    }
)
_WALKING_VALUES: Mapping[WalkingTolerance, int] = MappingProxyType(
    {
        WalkingTolerance.WITHIN_30_MINUTES: 0,
        WalkingTolerance.ABOUT_1_HOUR: 50,
        WalkingTolerance.EXTENDED_WALKING_OK: 100,
    }
)
_INDOOR_OUTDOOR_VALUES: Mapping[IndoorOutdoorPreference, int] = MappingProxyType(
    {
        IndoorOutdoorPreference.INDOOR: 0,
        IndoorOutdoorPreference.NO_PREFERENCE: 50,
        IndoorOutdoorPreference.OUTDOOR: 100,
    }
)
_CROWD_VALUES: Mapping[CrowdAvoidance, int] = MappingProxyType(
    {
        CrowdAvoidance.LOW: 0,
        CrowdAvoidance.MEDIUM: 50,
        CrowdAvoidance.HIGH: 100,
    }
)


def _condition_value_map(conditions: TripConditions) -> tuple[int, ...]:
    return (
        _VISIT_TIME_VALUES[conditions.visit_time],
        _COMPANION_VALUES[conditions.companion],
        _TRANSPORT_VALUES[conditions.transport],
        _WALKING_VALUES[conditions.walking_tolerance],
        _INDOOR_OUTDOOR_VALUES[conditions.indoor_outdoor_preference],
        _CROWD_VALUES[conditions.crowd_avoidance],
    )


def project_traveler_condition_targets(
    conditions: TripConditions,
) -> tuple[
    TravelConditionTarget,
    TravelConditionTarget,
    TravelConditionTarget,
    TravelConditionTarget,
    TravelConditionTarget,
    TravelConditionTarget,
]:
    """Project each typed trip condition in the canonical Phase 1 order."""

    values = _condition_value_map(conditions)
    result = tuple(
        TravelConditionTarget(condition_id=condition, value=value)
        for condition, value in zip(TravelConditionId, values, strict=True)
    )
    return cast(
        tuple[
            TravelConditionTarget,
            TravelConditionTarget,
            TravelConditionTarget,
            TravelConditionTarget,
            TravelConditionTarget,
            TravelConditionTarget,
        ],
        result,
    )


def project_traveler_trait_targets(
    conditions: TripConditions,
    answers: QuestionnaireAnswersV1,
) -> tuple[
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
]:
    """Project the six mismatch expectations from current-trip answers only."""

    normalized_q4 = _normalize_answer(answers.q4)
    normalized_q8 = _normalize_answer(answers.q8)
    normalized_q7 = _normalize_answer(answers.q7)
    normalized_q6 = _normalize_answer(answers.q6)
    normalized_q9 = _normalize_answer(answers.q9)
    normalized_q2 = _normalize_answer(answers.q2)
    walking = _WALKING_VALUES[conditions.walking_tolerance]
    visit_time_dependence = _VISIT_TIME_VALUES[conditions.visit_time]
    crowd_density = _CROWD_VALUES[conditions.crowd_avoidance]
    values = (
        _half_up((100 - normalized_q4) + normalized_q8, 2),
        100 - normalized_q7,
        crowd_density,
        100 - normalized_q8,
        _half_up(walking + normalized_q6 + normalized_q9, 3),
        _half_up(visit_time_dependence + normalized_q2, 2),
    )
    important = (
        answers.q4 == 5 or answers.q8 == 5,
        answers.q7 == 5,
        conditions.crowd_avoidance is CrowdAvoidance.HIGH,
        answers.q8 == 5,
        conditions.walking_tolerance
        in {
            WalkingTolerance.WITHIN_30_MINUTES,
            WalkingTolerance.EXTENDED_WALKING_OK,
        }
        or answers.q6 == 5
        or answers.q9 == 5,
        conditions.visit_time in {VisitTime.SUNSET, VisitTime.EVENING} and answers.q2 >= 4,
    )
    result = tuple(
        PreferenceTraitTarget(trait_id=trait, value=value, important=is_important)
        for trait, value, is_important in zip(MismatchTraitId, values, important, strict=True)
    )
    return cast(
        tuple[
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
        ],
        result,
    )


def _evidence_ids(profile: PublicScoredProfile, dimension: str) -> tuple[str, ...]:
    evidence_ids = tuple(profile.evidence_justifications[dimension])
    if not evidence_ids:
        raise ValueError(f"projection evidence is missing for {dimension}")
    return evidence_ids


def project_place_condition_scores(
    profile: PublicScoredProfile,
) -> tuple[
    PlaceConditionSnapshot,
    PlaceConditionSnapshot,
    PlaceConditionSnapshot,
    PlaceConditionSnapshot,
    PlaceConditionSnapshot,
    PlaceConditionSnapshot,
]:
    """Project scored place dimensions to the canonical travel-condition order."""

    mismatch = profile.mismatch_traits
    values_and_evidence = (
        (mismatch["M6"], "M6"),
        (mismatch["M4"], "M4"),
        (100 - mismatch["M5"], "M5"),
        (mismatch["M5"], "M5"),
        (profile.subattributes["R1"] * 25, "R1"),
        (100 - mismatch["M3"], "M3"),
    )
    result = tuple(
        PlaceConditionSnapshot(
            condition_id=condition,
            value=value,
            evidence_ids=_evidence_ids(profile, dimension),
        )
        for condition, (value, dimension) in zip(
            TravelConditionId, values_and_evidence, strict=True
        )
    )
    return cast(
        tuple[
            PlaceConditionSnapshot,
            PlaceConditionSnapshot,
            PlaceConditionSnapshot,
            PlaceConditionSnapshot,
            PlaceConditionSnapshot,
            PlaceConditionSnapshot,
        ],
        result,
    )


def _v2_normalized_axis_shares(answers: QuestionnaireAnswersV2) -> tuple[int, int, int]:
    """Compute canonical v2 axis shares (0..100) from the accumulated matrix.

    Each axis's accumulated weights are normalized against the same
    attainable bounds `score_axis_v2` uses, then rendered as a 0..100
    percentage with half-up integer math. No fixed denominator: a hardcoded
    total would pin never-chosen axes to a positive floor and cap most axes
    below 100.
    """

    from itda.contracts.questionnaire_v2 import AXIS_ATTAINABLE_BOUNDS, SCORING_CONFIG_V2

    matrix = cast(Mapping[str, Mapping[str, int]], SCORING_CONFIG_V2["scoring_matrix"])
    answers_by_ordinal = answers.model_dump()
    accumulated = {axis.value: 0 for axis in ExperienceAxis}
    for ordinal in range(1, 13):
        choice_id = f"q{ordinal}o{answers_by_ordinal[f'q{ordinal}']}"
        for axis_name, weight in matrix[choice_id].items():
            accumulated[axis_name] += weight

    shares: list[int] = []
    for axis in ExperienceAxis:
        lower, upper = AXIS_ATTAINABLE_BOUNDS[axis.value]
        span = upper - lower
        share = _half_up((accumulated[axis.value] - lower) * 100, span)
        shares.append(share)
    return (shares[0], shares[1], shares[2])


def project_traveler_trait_targets_v2(
    conditions: TripConditions,
    answers: QuestionnaireAnswersV2,
) -> tuple[
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
    PreferenceTraitTarget,
]:
    """Project the six mismatch expectations from v2 choices plus trip conditions.

    Deterministic v2 projection: canonical selected-option matrix rows are
    accumulated per axis, normalized against the canonical attainable bounds
    (the same semantics `score_axis_v2` uses), then mapped onto the same six
    PreferenceTraitTargets in the same order as the legacy projection.
    Integer half-up math only.
    """

    history_share, emotion_share, rest_share = _v2_normalized_axis_shares(answers)
    walking = _WALKING_VALUES[conditions.walking_tolerance]
    visit_time_dependence = _VISIT_TIME_VALUES[conditions.visit_time]
    crowd_density = _CROWD_VALUES[conditions.crowd_avoidance]
    values = (
        _half_up((100 - history_share) + emotion_share, 2),
        100 - history_share,
        crowd_density,
        100 - emotion_share,
        _half_up(walking + rest_share + rest_share, 3),
        _half_up(visit_time_dependence + emotion_share, 2),
    )
    important = (
        history_share >= 75 or emotion_share >= 75,
        history_share >= 75,
        conditions.crowd_avoidance is CrowdAvoidance.HIGH,
        emotion_share >= 75,
        conditions.walking_tolerance
        in {
            WalkingTolerance.WITHIN_30_MINUTES,
            WalkingTolerance.EXTENDED_WALKING_OK,
        }
        or rest_share >= 75,
        conditions.visit_time in {VisitTime.SUNSET, VisitTime.EVENING} and emotion_share >= 50,
    )
    result = tuple(
        PreferenceTraitTarget(trait_id=trait, value=value, important=is_important)
        for trait, value, is_important in zip(MismatchTraitId, values, important, strict=True)
    )
    return cast(
        tuple[
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
            PreferenceTraitTarget,
        ],
        result,
    )


def project_recommendation_preference(profile: PreferenceProfile) -> RecommendationPreference:
    """Build a version-bound server-owned preference trace from one profile."""

    projection_version = (
        RECOMMENDATION_PROJECTION_VERSION_V2
        if profile.questionnaire_version == "questionnaire-v2"
        else RECOMMENDATION_PROJECTION_VERSION
    )
    input_sha256 = canonical_sha256(
        {
            "projection_version": projection_version,
            "profile": profile.model_dump(mode="json"),
        }
    )
    axis_targets = tuple(
        PreferenceAxisTarget(axis=score.axis, value=score.display_score) for score in profile.scores
    )
    if isinstance(profile.answers, QuestionnaireAnswersV2):
        trait_targets = project_traveler_trait_targets_v2(profile.trip_conditions, profile.answers)
    else:
        trait_targets = project_traveler_trait_targets(
            profile.trip_conditions,
            profile.answers,
        )
    return RecommendationPreference(
        profile_id=profile.profile_id,
        input_sha256=input_sha256,
        axis_targets=cast(
            tuple[PreferenceAxisTarget, PreferenceAxisTarget, PreferenceAxisTarget],
            axis_targets,
        ),
        trait_targets=trait_targets,
        condition_targets=project_traveler_condition_targets(profile.trip_conditions),
    )


__all__ = [
    "RECOMMENDATION_PROJECTION_VERSION",
    "RECOMMENDATION_PROJECTION_VERSION_V2",
    "project_place_condition_scores",
    "project_recommendation_preference",
    "project_traveler_condition_targets",
    "project_traveler_trait_targets",
    "project_traveler_trait_targets_v2",
]
