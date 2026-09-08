"""Contract evidence for the strict questionnaire version coupling.

Freezes: legacy v1 primitives accept only q1..q9 / ordinals 1..9 (v2-local
primitives carry q10..q12), stored profiles bind every version field to their
questionnaire generation via canonical constants, and arbitrary
schema/scoring/config combinations fail closed while legacy persisted v1 rows
keep validating and replaying byte-identically.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from itda.contracts.base import ExperienceAxis
from itda.contracts.preference import (
    VERSION_BOUND_BY_QUESTIONNAIRE_V1,
    PreferenceProfile,
    QuestionnaireAnswersV1,
    QuestionnaireAnswersV2,
    TripConditions,
)
from itda.contracts.questionnaire import (
    QUESTIONNAIRE_DEFINITION,
    SCORING_CONFIG,
    QuestionId,
    QuestionOrdinal,
)
from itda.contracts.questionnaire_v2 import QUESTIONNAIRE_DEFINITION_V2
from itda.domain.preference import replay_legacy_v1_profile, score_axis

CREATED_AT = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)

_TRIP_CONDITIONS = {
    "visit_date": None,
    "visit_time": "UNDECIDED",
    "companion": "SOLO",
    "transport": "WALK_OR_TRANSIT",
    "walking_tolerance": "ABOUT_1_HOUR",
    "indoor_outdoor_preference": "NO_PREFERENCE",
    "crowd_avoidance": "MEDIUM",
}


def _legacy_v1_answers() -> dict[str, int]:
    return {f"q{number}": 3 for number in range(1, 10)}


def _legacy_v1_profile(
    *,
    schema_version: str | None = None,
    scoring_version: str | None = None,
    description_template_version: str | None = None,
    config_hash: str | None = None,
    questionnaire_version: str = "questionnaire-v1",
    answers: QuestionnaireAnswersV1 | QuestionnaireAnswersV2 | None = None,
) -> PreferenceProfile:
    answers = answers if answers is not None else QuestionnaireAnswersV1.model_validate(
        _legacy_v1_answers()
    )
    answers_by_number = {
        question.ordinal: _legacy_v1_answers()[question.question_id]
        for question in QUESTIONNAIRE_DEFINITION.questions
    }
    axis_questions = SCORING_CONFIG["axis_questions"]
    scores = tuple(
        score_axis(
            axis,
            *(answers_by_number[number] for number in axis_questions[axis]),  # type: ignore[arg-type]
        )
        for axis in (ExperienceAxis.HISTORY_TRADITION, ExperienceAxis.EMOTION_IMAGE,
                     ExperienceAxis.REST_IMMERSION)
    )
    return PreferenceProfile(
        profile_id="profile:v1-coupling-evidence",
        request_id="anonymous:request:v1-coupling",
        trip_conditions=TripConditions.model_validate(_TRIP_CONDITIONS),
        answers=answers,
        scores=scores,  # type: ignore[arg-type]
        description_ko="v1 coupling evidence",
        schema_version=schema_version or str(VERSION_BOUND_BY_QUESTIONNAIRE_V1["schema_version"]),
        questionnaire_version=questionnaire_version,
        scoring_version=(
            scoring_version or str(VERSION_BOUND_BY_QUESTIONNAIRE_V1["scoring_version"])
        ),
        description_template_version=(
            description_template_version
            or str(VERSION_BOUND_BY_QUESTIONNAIRE_V1["description_template_version"])
        ),
        config_hash=config_hash or str(VERSION_BOUND_BY_QUESTIONNAIRE_V1["config_hash"]),
        created_at=CREATED_AT,
    )


def test_legacy_v1_primitives_reject_q10_and_ordinal_10() -> None:
    from pydantic import TypeAdapter

    from itda.contracts.questionnaire import QuestionnaireItem

    with pytest.raises(ValidationError, match="pattern"):
        TypeAdapter(QuestionId).validate_python("q10")
    with pytest.raises(ValidationError, match="less_than_equal"):
        TypeAdapter(QuestionOrdinal).validate_python(10)
    with pytest.raises(ValidationError, match="pattern"):
        TypeAdapter(QuestionId).validate_python("q12")
    assert QUESTIONNAIRE_DEFINITION.question_order == tuple(range(1, 10))
    # Authoring a v1 question item at ordinal 10 or with id q10 fails closed.
    with pytest.raises(ValidationError):
        QuestionnaireItem.model_validate(
            {
                "question_id": "q10",
                "ordinal": 10,
                "axis": ExperienceAxis.HISTORY_TRADITION,
                "prompt_ko": "leaked v2 ordinal",
            }
        )


def test_v2_definition_extends_the_twelve_question_boundary_independently() -> None:
    assert QUESTIONNAIRE_DEFINITION_V2.question_order == tuple(range(1, 13))
    v2_ids = tuple(question.question_id for question in QUESTIONNAIRE_DEFINITION_V2.questions)
    assert v2_ids == tuple(f"q{ordinal}" for ordinal in range(1, 13))


def test_legacy_persisted_v1_profile_still_validates_and_replays() -> None:
    profile = _legacy_v1_profile()
    assert profile.questionnaire_version == "questionnaire-v1"
    assert isinstance(profile.answers, QuestionnaireAnswersV1)
    replayed = replay_legacy_v1_profile(profile)
    assert [score.basis_points for score in replayed] == [
        score.basis_points for score in profile.scores
    ]


def test_v1_profile_with_v2_answers_is_rejected() -> None:
    with pytest.raises(ValidationError, match="QuestionnaireAnswersV1"):
        _legacy_v1_profile(answers=QuestionnaireAnswersV2.model_validate(
            {f"q{number}": 2 for number in range(1, 13)}
        ))


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    [
        ("schema_version", "preference-profile-v2"),
        ("schema_version", "preference-profile-v9"),
        ("scoring_version", "choice-bp-v2"),
        ("scoring_version", "scoring-v1"),
        ("description_template_version", "current-trip-expectation-v2"),
        ("config_hash", "a" * 64),
    ],
)
def test_v1_profile_with_wrong_version_coupled_field_is_rejected(
    field_name: str,
    wrong_value: str,
) -> None:
    kwargs: dict[str, str] = {field_name: wrong_value}
    with pytest.raises(ValidationError, match=field_name):
        _legacy_v1_profile(**kwargs)  # type: ignore[arg-type]


def test_unknown_questionnaire_version_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unsupported questionnaire_version"):
        _legacy_v1_profile(questionnaire_version="questionnaire-v7")


def test_canonical_v2_bounds_are_exact_and_differ_per_axis() -> None:
    from itda.contracts.questionnaire_v2 import AXIS_ATTAINABLE_BOUNDS

    assert dict(AXIS_ATTAINABLE_BOUNDS) == {
        "HISTORY_TRADITION": (12, 48),
        "EMOTION_IMAGE": (12, 42),
        "REST_IMMERSION": (12, 45),
    }
