from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from itda.contracts.preference import QuestionnaireSubmission
from itda.contracts.questionnaire import (
    QUESTIONNAIRE_DEFINITION,
    calculate_config_hash,
)
from itda.domain.preference import calculate_preference

CREATED_AT = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
SUBMISSION = QuestionnaireSubmission.model_validate(
    {
        "request_id": "synthetic:preference:determinism",
        "trip_conditions": {
            "visit_date": None,
            "visit_time": "UNDECIDED",
            "companion": "SOLO",
            "transport": "WALK_OR_TRANSIT",
            "walking_tolerance": "ABOUT_1_HOUR",
            "indoor_outdoor_preference": "NO_PREFERENCE",
            "crowd_avoidance": "MEDIUM",
        },
        "answers": {f"q{number}": 2 for number in range(1, 13)},
    }
)


def test_same_input_config_and_time_are_byte_identical_one_hundred_times() -> None:
    outputs = {
        calculate_preference(SUBMISSION, created_at=CREATED_AT).model_dump_json()
        for _ in range(100)
    }

    assert len(outputs) == 1
    profile = calculate_preference(SUBMISSION, created_at=CREATED_AT)
    assert profile.description_ko == (
        "이번 여행에서는 감성·이미지와 휴식·몰입 경험을 더 기대하고 있어요."
    )
    assert profile.description_template_version == "current-trip-expectation-v1"
    assert profile.questionnaire_version == "questionnaire-v2"
    assert profile.scoring_version == "choice-bp-v2"


def test_swapping_visible_question_order_changes_the_semantic_hash() -> None:
    payload = QUESTIONNAIRE_DEFINITION.model_dump(mode="json")
    payload["question_order"] = [2, 1, *range(3, 10)]

    assert calculate_config_hash(payload) != QUESTIONNAIRE_DEFINITION.config_hash


def test_non_utc_created_at_fails_closed_without_retry_or_coercion() -> None:
    non_utc = datetime(2026, 7, 22, 21, 0, tzinfo=timezone(timedelta(hours=9)))

    with pytest.raises(ValidationError, match="created_at must use UTC"):
        calculate_preference(SUBMISSION, created_at=non_utc)
