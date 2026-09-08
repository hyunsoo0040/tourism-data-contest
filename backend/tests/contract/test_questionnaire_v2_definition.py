"""Freeze the canonical questionnaire-v2 artifact and the reviewed scoring matrix."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.contracts.base import ExperienceAxis
from itda.contracts.preference import QuestionnaireAnswersV2
from itda.contracts.questionnaire_v2 import (
    AXIS_WEIGHT_TOTAL,
    QUESTIONNAIRE_DEFINITION_V2,
    V2_CONFIG_HASH,
    V2_QUESTIONNAIRE_VERSION,
    V2_SCORING_VERSION,
    QuestionnaireDefinitionV2,
    calculate_config_hash_v2,
)
from itda.domain.preference import calculate_preference
from itda.domain.recommendation_projection import (
    project_traveler_trait_targets_v2,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
V2_ARTIFACT = json.loads(
    (REPO_ROOT / "contracts" / "questionnaire-v2.json").read_text(encoding="utf-8")
)

EXPECTED_TITLES = (
    "기차에서 내렸는데 예상보다 30분 일찍 도착했다.",
    "길을 걷다가 계획에 없던 골목이 눈에 들어왔다.",
    '친구가 "여긴 꼭 가봐"라고 추천해줬다.',
    "갑자기 비가 내리기 시작했다.",
    "골목에서 길고양이 한 마리가 당신을 빤히 쳐다본다.",
    "식당 앞에서 20분 정도 기다려야 한다.",
    "현지인이 예상 밖의 장소를 추천해줬다.",
    "숙소 체크아웃까지 30분이 남았다.",
    "버스를 놓쳤다. 다음 버스는 25분 뒤다.",
    "숙소로 돌아가는 길, 작은 공연이 열리고 있다.",
    "집으로 돌아가기 전, 여행을 마무리하며 마지막으로 사진첩을 훑어본다.",
    "집에 돌아와 가방을 정리하다가 주머니에서 작은 영수증 한 장이 나왔다.",
)


def _artifact_questions() -> list[dict[str, object]]:
    questions = V2_ARTIFACT["questions"]
    assert isinstance(questions, list)
    return questions  # type: ignore[no-any-return]


def test_artifact_has_exactly_twelve_questions_in_upstream_order() -> None:
    questions = _artifact_questions()
    assert len(questions) == 12
    for ordinal, (question, title) in enumerate(zip(questions, EXPECTED_TITLES, strict=True), 1):
        assert question["question_id"] == f"q{ordinal}"
        assert question["ordinal"] == ordinal
        assert question["title_ko"] == title


def test_artifact_has_exactly_thirty_six_choices_with_stable_ids_and_values() -> None:
    for question in _artifact_questions():
        options = question["options"]
        assert isinstance(options, list)
        assert len(options) == 3
        for value, option in enumerate(options, start=1):
            assert option["choice_id"] == f"q{question['ordinal']}o{value}"
            assert option["value"] == value


def test_artifact_choice_texts_and_keywords_are_nonempty_korean() -> None:
    total_choices = 0
    for question in _artifact_questions():
        for option in question["options"]:  # type: ignore[union-attr]
            assert 0 < len(str(option["text_ko"])) <= 500
            keywords = option["keywords_ko"]
            assert isinstance(keywords, list) and len(keywords) == 2
            total_choices += 1
    assert total_choices == 36


def test_definition_matches_committed_artifact_texts_exactly() -> None:
    definition = QUESTIONNAIRE_DEFINITION_V2
    assert definition.questionnaire_version == V2_QUESTIONNAIRE_VERSION
    assert definition.scoring_version == V2_SCORING_VERSION
    for question, artifact_question in zip(
        definition.questions, _artifact_questions(), strict=True
    ):
        assert question.title_ko == artifact_question["title_ko"]
        assert question.description_ko == artifact_question["description_ko"]
        for option, artifact_option in zip(
            question.options, artifact_question["options"], strict=True  # type: ignore[arg-type]
        ):
            assert option.text_ko == artifact_option["text_ko"]
            assert option.keywords_ko == tuple(artifact_option["keywords_ko"])  # type: ignore[arg-type]


def test_scoring_matrix_is_frozen_deterministic_and_canonical() -> None:
    matrix = QUESTIONNAIRE_DEFINITION_V2.scoring_matrix
    assert len(matrix) == 36
    expected_q5o2 = {
        "HISTORY_TRADITION": 1,
        "EMOTION_IMAGE": 1,
        "REST_IMMERSION": 4,
    }
    assert matrix["q5o2"] == expected_q5o2
    for choice_id, row in matrix.items():
        assert sum(row.values()) == AXIS_WEIGHT_TOTAL
        primary = max(row, key=lambda axis: row[axis])
        axis_by_choice = {
            option.choice_id: option.axis
            for question in QUESTIONNAIRE_DEFINITION_V2.questions
            for option in question.options
        }
        assert ExperienceAxis(primary) is axis_by_choice[choice_id]


def test_config_hash_is_stable_sha256_of_v2_semantics() -> None:
    payload = QUESTIONNAIRE_DEFINITION_V2.model_dump(mode="json", exclude={"config_hash"})
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == V2_CONFIG_HASH
    assert QUESTIONNAIRE_DEFINITION_V2.config_hash == V2_CONFIG_HASH


def test_strict_validation_rejects_out_of_range_choice_values() -> None:
    with pytest.raises(ValidationError):
        QuestionnaireAnswersV2.model_validate({f"q{n}": 2 for n in range(1, 13)} | {"q1": 4})
    with pytest.raises(ValidationError):
        QuestionnaireAnswersV2.model_validate({f"q{n}": 2 for n in range(1, 13)} | {"q7": 0})


def test_strict_validation_rejects_missing_and_extra_questions() -> None:
    with pytest.raises(ValidationError):
        QuestionnaireAnswersV2.model_validate({f"q{n}": 1 for n in range(1, 12)})
    with pytest.raises(ValidationError):
        QuestionnaireAnswersV2.model_validate({f"q{n}": 1 for n in range(1, 13)} | {"q13": 1})


def _submission(answers: dict[str, int]) -> dict[str, object]:
    return {
        "request_id": "synthetic:v2:freeze",
        "trip_conditions": {
            "visit_date": None,
            "visit_time": "UNDECIDED",
            "companion": "SOLO",
            "transport": "WALK_OR_TRANSIT",
            "walking_tolerance": "ABOUT_1_HOUR",
            "indoor_outdoor_preference": "NO_PREFERENCE",
            "crowd_avoidance": "MEDIUM",
        },
        "answers": answers,
    }


def test_v2_scoring_is_deterministic_with_stable_her_tie_order() -> None:
    from datetime import UTC, datetime

    from itda.contracts.preference import QuestionnaireSubmission

    answers = {f"q{n}": 2 for n in range(1, 13)}
    submission = QuestionnaireSubmission.model_validate(_submission(answers))
    first = calculate_preference(submission, created_at=datetime(2026, 9, 3, tzinfo=UTC))
    second = calculate_preference(submission, created_at=datetime(2026, 9, 3, tzinfo=UTC))
    assert first == second
    assert [score.axis for score in first.scores] == list(ExperienceAxis)
    # All q{n}o3 choices are HISTORY_TRADITION primaries -> H strictly wins.
    history_answers = {f"q{n}": 3 for n in range(1, 13)}
    history_submission = QuestionnaireSubmission.model_validate(_submission(history_answers))
    history_profile = calculate_preference(
        history_submission, created_at=datetime(2026, 9, 3, tzinfo=UTC)
    )
    scores = {score.axis: score for score in history_profile.scores}
    assert (
        scores[ExperienceAxis.HISTORY_TRADITION].basis_points
        > scores[ExperienceAxis.EMOTION_IMAGE].basis_points
    )
    assert (
        scores[ExperienceAxis.HISTORY_TRADITION].basis_points
        > scores[ExperienceAxis.REST_IMMERSION].basis_points
    )


def test_v2_trait_projection_is_deterministic_six_target() -> None:
    from itda.contracts.preference import (
        CompanionType,
        CrowdAvoidance,
        IndoorOutdoorPreference,
        TransportType,
        TripConditions,
        VisitTime,
        WalkingTolerance,
    )

    conditions = TripConditions(
        visit_date=None,
        visit_time=VisitTime.SUNSET,
        companion=CompanionType.SOLO,
        transport=TransportType.MIXED,
        walking_tolerance=WalkingTolerance.WITHIN_30_MINUTES,
        indoor_outdoor_preference=IndoorOutdoorPreference.NO_PREFERENCE,
        crowd_avoidance=CrowdAvoidance.HIGH,
    )
    answers = QuestionnaireAnswersV2.model_validate({f"q{n}": 3 for n in range(1, 13)})
    first = project_traveler_trait_targets_v2(conditions, answers)
    second = project_traveler_trait_targets_v2(conditions, answers)
    assert first == second
    assert len(first) == 6
    assert all(0 <= target.value <= 100 for target in first)


def test_artifact_sort_keys_render_is_stable() -> None:
    rendered = json.dumps(V2_ARTIFACT, ensure_ascii=False, indent=2, sort_keys=True)
    on_disk = (REPO_ROOT / "contracts" / "questionnaire-v2.json").read_text(encoding="utf-8")
    assert rendered + "\n" == on_disk


def test_v2_hash_calculation_excludes_hash_field() -> None:
    payload = dict(QUESTIONNAIRE_DEFINITION_V2.model_dump(mode="json"))
    payload["config_hash"] = "0" * 64
    assert calculate_config_hash_v2(payload) == V2_CONFIG_HASH


def test_definition_rejects_matrix_not_matching_choice_axes() -> None:
    payload = QUESTIONNAIRE_DEFINITION_V2.model_dump(mode="json", exclude={"config_hash"})
    payload["scoring_matrix"]["q1o1"]["REST_IMMERSION"] = 9
    with pytest.raises(ValidationError):
        QuestionnaireDefinitionV2.model_validate(payload)
