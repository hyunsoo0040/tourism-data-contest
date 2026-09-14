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
    assert profile.scoring_version == "choice-distribution-v3"
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
    """Moving A to C affects only their two primary axes (neither is Q5-B)."""

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

    def _expected(answers_value: list[int], axis: ExperienceAxis) -> int:
        accumulated = sum(
            matrix[f"q{ordinal}o{answers_value[ordinal - 1]}"][axis.value]
            for ordinal in range(1, 13)
        )
        return score_axis_v2(axis, accumulated).basis_points

    assert scores[first_axis] == _expected(bumped, first_axis)
    assert base_scores[first_axis] == _expected(answers, first_axis)
    assert scores[third_axis] == _expected(bumped, third_axis)
    assert base_scores[third_axis] == _expected(answers, third_axis)
    # A-to-C swaps one positive evidence point between two axes.
    lower, upper = AXIS_ATTAINABLE_BOUNDS[third_axis.value]
    assert upper > lower and upper - lower >= 3
    others = [axis for axis in ExperienceAxis if axis is not first_axis and axis is not third_axis]
    assert all(scores[axis] - base_scores[axis] == 0 for axis in others)


@pytest.mark.parametrize(
    ("axis", "net", "basis_points", "display"),
    [
        (ExperienceAxis.HISTORY_TRADITION, -1, 0, 0),
        (ExperienceAxis.HISTORY_TRADITION, 0, 0, 0),
        (ExperienceAxis.HISTORY_TRADITION, 1, 714, 7),
        (ExperienceAxis.HISTORY_TRADITION, 7, 5000, 50),
        (ExperienceAxis.HISTORY_TRADITION, 12, 8571, 86),
        (ExperienceAxis.EMOTION_IMAGE, 1, 909, 9),
        (ExperienceAxis.EMOTION_IMAGE, 10, 9091, 91),
        (ExperienceAxis.REST_IMMERSION, 1, 909, 9),
        (ExperienceAxis.REST_IMMERSION, 11, 10000, 100),
    ],
)
def test_inverse_option_frequency_scores_keep_the_correction(
    axis: ExperienceAxis, net: int, basis_points: int, display: int
) -> None:
    from itda.domain.preference import score_axis_v2

    score = score_axis_v2(axis, net)
    assert (score.basis_points, score.display_score) == (basis_points, display)


def test_pdf_q5b_subtracts_history_and_adds_rest_before_rounding() -> None:
    before = calculate_preference(
        _submission({"id": "q5a", "answers": [1] * 12}), created_at=CREATED_AT
    )
    answers = [1] * 12
    answers[4] = 2
    after = calculate_preference(
        _submission({"id": "q5b", "answers": answers}), created_at=CREATED_AT
    )
    # Q5 A->B changes H/E/R evidence from 4/4/4 to 3/3/5.
    assert [row.basis_points for row in before.scores] == [2857, 3636, 3636]
    assert [row.basis_points for row in after.scores] == [2143, 2727, 4545]
    assert after.description_ko == (
        "이번 여행에서는 자기•몰입형과 의미•이미지형 경험을 더 기대하고 있어요."
    )


def test_extreme_answer_patterns_remain_bounded_without_restretching() -> None:
    from itda.contracts.questionnaire_v2 import QUESTIONNAIRE_DEFINITION_V2

    definition = QUESTIONNAIRE_DEFINITION_V2
    for axis, expected in zip(ExperienceAxis, [8571, 9091, 10000], strict=True):
        answers = [
            max(q.options, key=lambda o: definition.scoring_matrix[o.choice_id][axis.value]).value
            for q in definition.questions
        ]
        profile = calculate_preference(
            _submission({"id": axis.value, "answers": answers}), created_at=CREATED_AT
        )
        assert next(row.basis_points for row in profile.scores if row.axis == axis) == expected
        assert all(0 <= row.basis_points <= 10000 for row in profile.scores)
