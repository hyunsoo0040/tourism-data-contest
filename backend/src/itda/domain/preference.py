"""Pure deterministic scoring for the current-trip expectation profile."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from typing import cast

from itda.contracts.base import ExperienceAxis
from itda.contracts.preference import (
    AxisScore,
    PreferenceProfile,
    QuestionnaireAnswersV1,
    QuestionnaireAnswersV2,
    QuestionnaireSubmission,
)
from itda.contracts.questionnaire import QUESTIONNAIRE_DEFINITION, SCORING_CONFIG
from itda.contracts.questionnaire_v2 import AXIS_ATTAINABLE_BOUNDS, SCORING_CONFIG_V2

PROFILE_SCHEMA_VERSION_V1 = "preference-profile-v1"
PROFILE_SCHEMA_VERSION_V2 = "preference-profile-v2"


def _attainable_bounds(axis: ExperienceAxis) -> tuple[int, int]:
    try:
        return AXIS_ATTAINABLE_BOUNDS[axis.value]
    except KeyError as error:  # pragma: no cover - canonical axes are always present
        raise ValueError(f"no attainable bounds are configured for axis {axis}") from error


def score_axis(axis: ExperienceAxis, *answers: int) -> AxisScore:
    """Map exactly three strict 1..5 answers into integer basis points."""

    if len(answers) != 3:
        raise ValueError("each experience axis requires exactly three answers")
    if any(type(answer) is not int or not 1 <= answer <= 5 for answer in answers):
        raise ValueError("axis answers must be strict integers from 1 through 5")

    numerator = sum(answer - 1 for answer in answers) * 10_000
    basis_points = (numerator + 6) // 12
    return AxisScore(
        axis=axis,
        basis_points=basis_points,
        display_score=(basis_points + 50) // 100,
    )


def score_axis_v2(axis: ExperienceAxis, accumulated: int) -> AxisScore:
    """Map one axis's accumulated v2 matrix weights into integer basis points.

    Normalizes against the axis's attainable [min, max] accumulated weights
    (AXIS_ATTAINABLE_BOUNDS) so 0 bp and 10_000 bp are attainable on every
    axis; a fixed denominator would pin every never-chosen axis to a positive
    floor and cap most axes below 100.
    """

    lower, upper = _attainable_bounds(axis)
    if type(accumulated) is not int or not lower <= accumulated <= upper:
        raise ValueError(
            f"v2 accumulated weight for {axis.value} must be an integer "
            f"from {lower} through {upper}"
        )
    span = upper - lower
    basis_points = ((accumulated - lower) * 10_000 + span // 2) // span
    return AxisScore(
        axis=axis,
        basis_points=basis_points,
        display_score=(basis_points + 50) // 100,
    )


def _content_addressed_profile_id(
    submission: QuestionnaireSubmission,
    *,
    created_at: datetime,
    config_hash: str,
) -> str:
    payload = {
        "answers": submission.answers.model_dump(mode="json"),
        "config_hash": config_hash,
        "created_at": created_at.isoformat(),
        "request_id": submission.request_id,
        "trip_conditions": submission.trip_conditions.model_dump(mode="json"),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"profile:{hashlib.sha256(canonical).hexdigest()}"


def _score_v2_answers(
    answers: QuestionnaireAnswersV2,
) -> tuple[AxisScore, ...]:
    """Deterministically accumulate the reviewed matrix into three AxisScores."""

    matrix = cast(Mapping[str, Mapping[str, int]], SCORING_CONFIG_V2["scoring_matrix"])
    choices_by_id = cast(
        Mapping[str, object],
        SCORING_CONFIG_V2["choices_by_id"],
    )
    accumulated = {axis.value: 0 for axis in ExperienceAxis}
    answers_by_ordinal = answers.model_dump()
    for question in QUESTIONNAIRE_DEFINITION_V2_QUESTIONS:
        selected_value = answers_by_ordinal[question]
        choice_id = f"{question}o{selected_value}"
        if choice_id not in choices_by_id:
            raise ValueError(f"selected choice {choice_id} is not canonical")
        for axis_name, weight in matrix[choice_id].items():
            accumulated[axis_name] += weight

    tie_break = cast(tuple[ExperienceAxis, ...], SCORING_CONFIG_V2["axis_tie_break"])
    return tuple(score_axis_v2(axis, accumulated[axis.value]) for axis in tie_break)


QUESTIONNAIRE_DEFINITION_V2_QUESTIONS: tuple[str, ...] = tuple(
    f"q{ordinal}" for ordinal in range(1, 13)
)


def calculate_preference(
    submission: QuestionnaireSubmission,
    *,
    created_at: datetime,
) -> PreferenceProfile:
    """Calculate a byte-reproducible v2 profile from validated current-trip input."""

    scores = _score_v2_answers(submission.answers)
    if len(scores) != 3:
        raise ValueError("scoring configuration must contain exactly three axes")

    scores_by_axis = {score.axis: score for score in scores}
    tie_break = cast(tuple[ExperienceAxis, ...], SCORING_CONFIG_V2["axis_tie_break"])
    ranked = sorted(
        tie_break,
        key=lambda axis: (-scores_by_axis[axis].basis_points, tie_break.index(axis)),
    )
    labels = cast(Mapping[ExperienceAxis, str], SCORING_CONFIG_V2["axis_labels_ko"])
    connectives = cast(Mapping[ExperienceAxis, str], SCORING_CONFIG_V2["axis_connectives_ko"])
    template = cast(str, SCORING_CONFIG_V2["description_template_ko"])
    description = template.format(
        first_with_particle=connectives[ranked[0]],
        second=labels[ranked[1]],
    )
    config_hash = cast(str, SCORING_CONFIG_V2["config_hash"])

    return PreferenceProfile(
        profile_id=_content_addressed_profile_id(
            submission,
            created_at=created_at,
            config_hash=config_hash,
        ),
        request_id=submission.request_id,
        trip_conditions=submission.trip_conditions,
        answers=submission.answers,
        scores=scores,
        description_ko=description,
        schema_version=PROFILE_SCHEMA_VERSION_V2,
        questionnaire_version=cast(str, SCORING_CONFIG_V2["questionnaire_version"]),
        scoring_version=cast(str, SCORING_CONFIG_V2["scoring_version"]),
        description_template_version=cast(
            str,
            SCORING_CONFIG_V2["description_template_version"],
        ),
        config_hash=config_hash,
        created_at=created_at,
    )


def replay_legacy_v1_profile(
    profile: PreferenceProfile,
) -> tuple[AxisScore, ...]:
    """Recompute legacy v1 scores from stored answers for read/replay only."""

    if profile.questionnaire_version != "questionnaire-v1":
        raise ValueError("legacy replay requires a questionnaire-v1 profile")
    if not isinstance(profile.answers, QuestionnaireAnswersV1):
        raise ValueError("legacy replay requires nine-question 1..5 answers")
    answers = cast(Mapping[str, int], profile.answers.model_dump())
    answers_by_number = {
        question.ordinal: answers[question.question_id]
        for question in QUESTIONNAIRE_DEFINITION.questions
    }
    axis_questions = cast(
        Mapping[ExperienceAxis, tuple[int, ...]],
        SCORING_CONFIG["axis_questions"],
    )
    tie_break = cast(tuple[ExperienceAxis, ...], SCORING_CONFIG["axis_tie_break"])
    return tuple(
        score_axis(
            axis,
            *(answers_by_number[number] for number in axis_questions[axis]),
        )
        for axis in tie_break
    )
