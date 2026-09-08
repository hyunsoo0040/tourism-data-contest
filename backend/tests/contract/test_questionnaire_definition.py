from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.export_questionnaire import main as export_questionnaire
from itda.contracts.base import ExperienceAxis
from itda.contracts.questionnaire import (
    QUESTIONNAIRE_DEFINITION,
    SCORING_CONFIG,
    QuestionnaireDefinition,
    calculate_config_hash,
    questionnaire_artifact_bytes,
)

EXPECTED_QUESTIONS = (
    (
        "q1",
        1,
        ExperienceAxis.HISTORY_TRADITION,
        "오래된 터에 도착하면, 눈앞의 풍경보다 그곳에 얽힌 이야기를 먼저 알고 싶어요.",
    ),
    (
        "q2",
        2,
        ExperienceAxis.EMOTION_IMAGE,
        "해 질 무렵 한 곳을 고른다면, 빛과 색이 인상적인 장면을 만나고 싶어요.",
    ),
    (
        "q3",
        3,
        ExperienceAxis.REST_IMMERSION,
        "일정 사이 한 시간이 비면, 조용히 머물며 생각을 정리하고 싶어요.",
    ),
    (
        "q4",
        4,
        ExperienceAxis.HISTORY_TRADITION,
        "한 곳만 깊게 본다면, 유물과 건축에 남은 시대의 흔적을 따라가고 싶어요.",
    ),
    (
        "q5",
        5,
        ExperienceAxis.EMOTION_IMAGE,
        "여행에서 오래 기억할 순간은 마음을 움직이는 분위기에서 생긴다고 느껴요.",
    ),
    (
        "q6",
        6,
        ExperienceAxis.REST_IMMERSION,
        "여러 곳을 빠르게 보기보다 한 곳의 공기와 풍경에 오래 머물고 싶어요.",
    ),
    (
        "q7",
        7,
        ExperienceAxis.HISTORY_TRADITION,
        "비슷한 풍경이라면, 전통과 생활문화가 구체적으로 이어지는 곳을 고르고 싶어요.",
    ),
    (
        "q8",
        8,
        ExperienceAxis.EMOTION_IMAGE,
        "같은 시간을 보낸다면, 나만의 시선으로 사진에 담고 싶은 공간을 찾고 싶어요.",
    ),
    (
        "q9",
        9,
        ExperienceAxis.REST_IMMERSION,
        "붐비는 장면보다 천천히 걷거나 쉬며 몰입할 수 있는 시간을 원해요.",
    ),
)

EXPECTED_ANSWER_OPTIONS = (
    (1, "전혀 그렇지 않아요"),
    (2, "별로 그렇지 않아요"),
    (3, "보통이에요"),
    (4, "꽤 그래요"),
    (5, "매우 그래요"),
)

EXPECTED_CONFIG_HASH = "bc24c1ca59272397bf0dad41be34cf536b6cb6215d3148567d09fbebd749b09c"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
COMMITTED_ARTIFACT = REPOSITORY_ROOT / "contracts" / "questionnaire-v1.json"


def test_questionnaire_definition_pins_all_reviewed_copy_and_versions() -> None:
    definition = QUESTIONNAIRE_DEFINITION

    assert definition.questionnaire_version == "questionnaire-v1"
    assert definition.scoring_version == "integer-bp-v1"
    assert definition.description_template_version == "current-trip-expectation-v1"
    assert definition.question_order == tuple(range(1, 10))
    assert tuple(
        (question.question_id, question.ordinal, question.axis, question.prompt_ko)
        for question in definition.questions
    ) == EXPECTED_QUESTIONS
    assert tuple(
        (option.value, option.label_ko) for option in definition.answer_options
    ) == EXPECTED_ANSWER_OPTIONS
    assert definition.config_hash == EXPECTED_CONFIG_HASH


def test_scoring_config_is_derived_with_exact_axis_membership_and_copy() -> None:
    assert SCORING_CONFIG["question_order"] == tuple(range(1, 10))
    assert SCORING_CONFIG["axis_questions"] == {
        ExperienceAxis.HISTORY_TRADITION: (1, 4, 7),
        ExperienceAxis.EMOTION_IMAGE: (2, 5, 8),
        ExperienceAxis.REST_IMMERSION: (3, 6, 9),
    }
    assert SCORING_CONFIG["axis_tie_break"] == tuple(ExperienceAxis)
    assert SCORING_CONFIG["axis_labels_ko"] == {
        ExperienceAxis.HISTORY_TRADITION: "역사·전통",
        ExperienceAxis.EMOTION_IMAGE: "감성·이미지",
        ExperienceAxis.REST_IMMERSION: "휴식·몰입",
    }
    assert SCORING_CONFIG["axis_connectives_ko"] == {
        ExperienceAxis.HISTORY_TRADITION: "역사·전통과",
        ExperienceAxis.EMOTION_IMAGE: "감성·이미지와",
        ExperienceAxis.REST_IMMERSION: "휴식·몰입과",
    }
    assert SCORING_CONFIG["description_template_ko"] == (
        "이번 여행에서는 {first_with_particle} {second} 경험을 더 기대하고 있어요."
    )
    assert SCORING_CONFIG["config_hash"] == QUESTIONNAIRE_DEFINITION.config_hash


def test_definition_is_frozen_and_rejects_a_rehashed_drifted_order() -> None:
    with pytest.raises(ValidationError, match="frozen"):
        QUESTIONNAIRE_DEFINITION.questionnaire_version = "changed"  # type: ignore[misc]

    payload = QUESTIONNAIRE_DEFINITION.model_dump(mode="json")
    payload["question_order"] = [2, 1, *range(3, 10)]
    payload["config_hash"] = calculate_config_hash(payload)

    with pytest.raises(ValidationError, match="canonical visible order"):
        QuestionnaireDefinition.model_validate(payload)


def test_any_semantic_questionnaire_mutation_changes_the_config_hash() -> None:
    original = QUESTIONNAIRE_DEFINITION.model_dump(mode="json")
    mutations = []

    reordered = dict(original)
    reordered["question_order"] = [2, 1, *range(3, 10)]
    mutations.append(reordered)

    changed_copy = json.loads(json.dumps(original, ensure_ascii=False))
    changed_copy["questions"][2]["prompt_ko"] += " 변경"
    mutations.append(changed_copy)

    changed_label = json.loads(json.dumps(original, ensure_ascii=False))
    changed_label["answer_options"][0]["label_ko"] = "전혀 아니에요"
    mutations.append(changed_label)

    assert all(
        calculate_config_hash(mutation) != QUESTIONNAIRE_DEFINITION.config_hash
        for mutation in mutations
    )


def test_artifact_and_cli_export_are_byte_stable(tmp_path: Path) -> None:
    expected = questionnaire_artifact_bytes()

    assert COMMITTED_ARTIFACT.read_bytes() == expected
    assert json.loads(expected) == QUESTIONNAIRE_DEFINITION.model_dump(mode="json")

    exported = tmp_path / "questionnaire-v1.json"
    assert export_questionnaire(["--output", str(exported), "--version", "v1"]) == 0
    assert exported.read_bytes() == expected
