from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.contracts.base import ExperienceAxis
from itda.contracts.preference import QuestionnaireSubmission
from itda.domain.preference import calculate_preference, score_axis

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GOLDEN = json.loads(
    (REPOSITORY_ROOT / "fixtures" / "synthetic" / "preference-golden.json").read_text()
)
CREATED_AT = datetime.fromisoformat(GOLDEN["created_at"]).astimezone(UTC)


def _submission(case: dict[str, object]) -> QuestionnaireSubmission:
    values = case["answers"]
    assert isinstance(values, list)
    return QuestionnaireSubmission.model_validate(
        {
            "request_id": f"synthetic:preference:{case['id']}",
            "trip_conditions": GOLDEN["trip_conditions"],
            "answers": {f"q{index}": value for index, value in enumerate(values, start=1)},
        }
    )


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda case: case["id"])
def test_preference_golden_vectors(case: dict[str, object]) -> None:
    submission = _submission(case)

    profile = calculate_preference(submission, created_at=CREATED_AT)

    assert [score.axis for score in profile.scores] == list(ExperienceAxis)
    assert [score.basis_points for score in profile.scores] == case["basis_points"]
    assert [score.display_score for score in profile.scores] == case["display_scores"]
    assert profile.description_ko == case["description_ko"]
    assert profile.request_id == submission.request_id
    assert profile.trip_conditions == submission.trip_conditions
    assert profile.answers == submission.answers
    assert profile.profile_id.startswith("profile:")
    assert profile.schema_version == "preference-profile-v2"
    assert profile.questionnaire_version == "questionnaire-v2"
    assert profile.scoring_version == "choice-bp-v2"
    assert profile.description_template_version == "current-trip-expectation-v1"
    assert profile.config_hash == GOLDEN["config_hash"]


@pytest.mark.parametrize(
    ("answers", "expected_basis_points", "expected_display_score"),
    [
        ((1, 1, 1), 0, 0),
        ((1, 1, 2), 833, 8),
        ((1, 1, 3), 1667, 17),
        ((1, 1, 4), 2500, 25),
        ((5, 5, 5), 10_000, 100),
    ],
)
def test_score_axis_uses_positive_integer_half_up_math(
    answers: tuple[int, int, int],
    expected_basis_points: int,
    expected_display_score: int,
) -> None:
    score = score_axis(ExperienceAxis.HISTORY_TRADITION, *answers)

    assert score.basis_points == expected_basis_points
    assert score.display_score == expected_display_score


@pytest.mark.parametrize(
    ("question_number", "expected_axis"),
    [
        (1, ExperienceAxis.REST_IMMERSION),
        (2, ExperienceAxis.HISTORY_TRADITION),
        (3, ExperienceAxis.REST_IMMERSION),
        (4, ExperienceAxis.EMOTION_IMAGE),
        (5, ExperienceAxis.EMOTION_IMAGE),
        (6, ExperienceAxis.REST_IMMERSION),
        (7, ExperienceAxis.EMOTION_IMAGE),
        (8, ExperienceAxis.REST_IMMERSION),
        (9, ExperienceAxis.EMOTION_IMAGE),
        (10, ExperienceAxis.HISTORY_TRADITION),
        (11, ExperienceAxis.HISTORY_TRADITION),
        (12, ExperienceAxis.HISTORY_TRADITION),
    ],
)
def test_each_question_changes_only_its_canonical_axis(
    question_number: int,
    expected_axis: ExperienceAxis,
) -> None:
    """Moving q{n} from value 1 to value 3 shifts exactly one matrix weight.

    Expected scores derive independently from the frozen matrix and the
    attainable bounds (the same normalization score_axis_v2 applies), so the
    test pins the semantics rather than restating its output.
    """

    from itda.contracts.questionnaire_v2 import (
        AXIS_ATTAINABLE_BOUNDS,
        QUESTIONNAIRE_DEFINITION_V2,
        SCORING_CONFIG_V2,
    )
    from itda.domain.preference import score_axis_v2

    definition = QUESTIONNAIRE_DEFINITION_V2
    matrix = SCORING_CONFIG_V2["scoring_matrix"]
    first_axis = definition.questions[question_number - 1].options[0].axis
    third_axis = definition.questions[question_number - 1].options[2].axis
    answers = [1] * 12
    case = {"id": f"axis-isolation-q{question_number}", "answers": answers}

    baseline = calculate_preference(_submission(case), created_at=CREATED_AT)
    bumped = list(answers)
    bumped[question_number - 1] = 3
    bumped_case = {"id": f"axis-isolation-q{question_number}-bumped", "answers": bumped}
    profile = calculate_preference(_submission(bumped_case), created_at=CREATED_AT)
    scores = {score.axis: score.basis_points for score in profile.scores}
    base_scores = {score.axis: score.basis_points for score in baseline.scores}

    def _expected(answers_value: int, axis: ExperienceAxis) -> int:
        accumulated = sum(
            matrix[f"q{ordinal}o{answers_value[ordinal - 1]}"][axis.value]
            for ordinal in range(1, 13)
        )
        return score_axis_v2(axis, accumulated).basis_points

    assert scores[first_axis] == _expected(bumped, first_axis)
    assert base_scores[first_axis] == _expected(answers, first_axis)
    assert scores[third_axis] == _expected(bumped, third_axis)
    assert base_scores[third_axis] == _expected(answers, third_axis)
    # The swap moves the third axis's accumulated weight up by exactly
    # (max - min) = 3 within its attainable span, and the first axis down by
    # the same absolute weight count.
    lower, upper = AXIS_ATTAINABLE_BOUNDS[third_axis.value]
    assert upper > lower and upper - lower >= 3
    others = [
        axis
        for axis in ExperienceAxis
        if axis is not first_axis and axis is not third_axis
    ]
    assert all(scores[axis] - base_scores[axis] == 0 for axis in others)


def test_all_one_axis_choices_attain_every_extreme() -> None:
    """Picking every primary option of one axis maximizes it; the never-chosen
    axes normalize to their attainable floor, not a positive offset.

    The frozen matrix cannot literally accumulate a never-chosen axis at its
    minimum in an all-one-axis input (secondary weights still accrue), so this
    test asserts the attainable extremes directly through score_axis_v2 and
    verifies the all-primary input disperses the remaining axes without a
    shared positive floor.
    """

    from itda.contracts.questionnaire_v2 import (
        AXIS_ATTAINABLE_BOUNDS,
        QUESTIONNAIRE_DEFINITION_V2,
    )
    from itda.domain.preference import score_axis_v2

    definition = QUESTIONNAIRE_DEFINITION_V2
    for target_axis in ExperienceAxis:
        lower, upper = AXIS_ATTAINABLE_BOUNDS[target_axis.value]
        min_score = score_axis_v2(target_axis, lower)
        max_score = score_axis_v2(target_axis, upper)
        assert min_score.basis_points == 0 and min_score.display_score == 0
        assert max_score.basis_points == 10_000 and max_score.display_score == 100

    # All-primary choices for HISTORY_TRADITION: axis H hits its attainable
    # max exactly (100), while E and R land strictly above their attainable
    # floors yet strictly below 100 — variance is preserved, no pinned floor.
    all_h_answers = {
        f"q{index}": next(
            option.value
            for option in definition.questions[index - 1].options
            if option.axis is ExperienceAxis.HISTORY_TRADITION
        )
        for index in range(1, 13)
    }
    profile = calculate_preference(
        _submission(
            {"id": "all-history", "answers": [all_h_answers[f"q{n}"] for n in range(1, 13)]}
        ),
        created_at=CREATED_AT,
    )
    by_axis = {score.axis: score for score in profile.scores}
    assert by_axis[ExperienceAxis.HISTORY_TRADITION].basis_points == 10_000
    # The never-chosen axes accumulate exactly their attainable minimum (one
    # secondary weight per question) and normalize to a true 0 — the fixed /48
    # denominator would have pinned them at 25 instead.
    for other in (ExperienceAxis.EMOTION_IMAGE, ExperienceAxis.REST_IMMERSION):
        other_lower, _ = AXIS_ATTAINABLE_BOUNDS[other.value]
        assert by_axis[other].basis_points == score_axis_v2(other, other_lower).basis_points
        assert by_axis[other].basis_points == 0

    # The axis-attainable bounds themselves differ (H 36, E 30, R 33 spans),
    # so the same absolute weight distance maps to different basis-point
    # distances per axis — variance is preserved, not collapsed.
    spans = {
        axis.value: AXIS_ATTAINABLE_BOUNDS[axis.value][1] - AXIS_ATTAINABLE_BOUNDS[axis.value][0]
        for axis in ExperienceAxis
    }
    assert len(set(spans.values())) == 3

    # E never appears as a primary in q6/q8 (frozen upstream set), so an
    # all-E-preferring input cannot reach E's attainable max — unlike the
    # all-H input above, which can. The bounds make that asymmetry explicit
    # and honest instead of capping silently at a fixed denominator.
    e_primary_counts = {
        axis.value: sum(
            1
            for question in definition.questions
            if any(option.axis is axis for option in question.options)
        )
        for axis in (ExperienceAxis.EMOTION_IMAGE, ExperienceAxis.HISTORY_TRADITION)
    }
    assert e_primary_counts[ExperienceAxis.EMOTION_IMAGE.value] < e_primary_counts[
        ExperienceAxis.HISTORY_TRADITION.value
    ]
