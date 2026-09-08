"""Canonical, immutable questionnaire and derived scoring configuration."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated

from pydantic import BaseModel, Field, model_validator

from itda.contracts.base import ExperienceAxis, Sha256, StrictContract, Version

QuestionId = Annotated[str, Field(strict=True, pattern=r"^q[1-9]$")]
QuestionOrdinal = Annotated[int, Field(strict=True, ge=1, le=9)]
AnswerOptionValue = Annotated[int, Field(strict=True, ge=1, le=5)]
KoreanCopy = Annotated[str, Field(strict=True, min_length=1, max_length=500)]


class QuestionnaireItem(StrictContract):
    """One reviewed scenario question in its canonical visible position."""

    question_id: QuestionId
    ordinal: QuestionOrdinal
    axis: ExperienceAxis
    prompt_ko: KoreanCopy


class QuestionnaireAnswerOption(StrictContract):
    """One strict five-point answer value and its reviewed Korean label."""

    value: AnswerOptionValue
    label_ko: KoreanCopy


class AxisDisplayCopy(StrictContract):
    """Reviewed display and Korean connective copy for one experience axis."""

    axis: ExperienceAxis
    label_ko: KoreanCopy
    connective_ko: KoreanCopy


def calculate_config_hash(payload: Mapping[str, object] | BaseModel) -> str:
    """Hash questionnaire semantics using canonical UTF-8 JSON, excluding the hash."""

    if isinstance(payload, BaseModel):
        semantic_payload = payload.model_dump(mode="json", exclude={"config_hash"})
    else:
        semantic_payload = dict(payload)
        semantic_payload.pop("config_hash", None)
    canonical = json.dumps(
        semantic_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class QuestionnaireDefinition(StrictContract):
    """The sole authored source for questionnaire, scoring, and UI projections."""

    questionnaire_version: Version
    scoring_version: Version
    description_template_version: Version
    question_order: tuple[QuestionOrdinal, ...]
    questions: tuple[QuestionnaireItem, ...]
    answer_options: tuple[QuestionnaireAnswerOption, ...]
    axis_tie_break: tuple[ExperienceAxis, ...]
    axis_display: tuple[AxisDisplayCopy, ...]
    description_template_ko: KoreanCopy
    config_hash: Sha256

    @model_validator(mode="after")
    def canonical_invariants(self) -> QuestionnaireDefinition:
        expected_order = tuple(range(1, 10))
        if self.question_order != expected_order:
            raise ValueError("question_order must use canonical visible order 1 through 9")

        if len(self.questions) != 9:
            raise ValueError("questions must contain exactly nine items")
        if tuple(question.ordinal for question in self.questions) != self.question_order:
            raise ValueError("question ordinals must match question_order")
        if tuple(question.question_id for question in self.questions) != tuple(
            f"q{ordinal}" for ordinal in self.question_order
        ):
            raise ValueError("question IDs must match q1 through q9 in order")

        expected_axis_questions = {
            ExperienceAxis.HISTORY_TRADITION: (1, 4, 7),
            ExperienceAxis.EMOTION_IMAGE: (2, 5, 8),
            ExperienceAxis.REST_IMMERSION: (3, 6, 9),
        }
        actual_axis_questions = {
            axis: tuple(
                question.ordinal for question in self.questions if question.axis is axis
            )
            for axis in ExperienceAxis
        }
        if actual_axis_questions != expected_axis_questions:
            raise ValueError("questions must use the canonical H-E-R axis membership")

        if tuple(option.value for option in self.answer_options) != tuple(range(1, 6)):
            raise ValueError("answer_options must contain strict values 1 through 5")
        if self.axis_tie_break != tuple(ExperienceAxis):
            raise ValueError("axis_tie_break must use canonical H-E-R order")
        if tuple(copy.axis for copy in self.axis_display) != tuple(ExperienceAxis):
            raise ValueError("axis_display must use canonical H-E-R order")
        if "{first_with_particle}" not in self.description_template_ko or (
            "{second}" not in self.description_template_ko
        ):
            raise ValueError("description template must expose both reviewed placeholders")
        if self.config_hash != calculate_config_hash(self):
            raise ValueError("config_hash does not match canonical questionnaire semantics")
        return self


def build_reviewed_questionnaire_definition_v1() -> QuestionnaireDefinition:
    """Build the one reviewed v1 definition without a parallel literal config table."""

    payload: dict[str, object] = {
        "questionnaire_version": "questionnaire-v1",
        "scoring_version": "integer-bp-v1",
        "description_template_version": "current-trip-expectation-v1",
        "question_order": tuple(range(1, 10)),
        "questions": (
            {
                "question_id": "q1",
                "ordinal": 1,
                "axis": ExperienceAxis.HISTORY_TRADITION,
                "prompt_ko": (
                    "오래된 터에 도착하면, 눈앞의 풍경보다 그곳에 얽힌 이야기를 먼저 알고 싶어요."
                ),
            },
            {
                "question_id": "q2",
                "ordinal": 2,
                "axis": ExperienceAxis.EMOTION_IMAGE,
                "prompt_ko": (
                    "해 질 무렵 한 곳을 고른다면, 빛과 색이 인상적인 장면을 만나고 싶어요."
                ),
            },
            {
                "question_id": "q3",
                "ordinal": 3,
                "axis": ExperienceAxis.REST_IMMERSION,
                "prompt_ko": "일정 사이 한 시간이 비면, 조용히 머물며 생각을 정리하고 싶어요.",
            },
            {
                "question_id": "q4",
                "ordinal": 4,
                "axis": ExperienceAxis.HISTORY_TRADITION,
                "prompt_ko": (
                    "한 곳만 깊게 본다면, 유물과 건축에 남은 시대의 흔적을 따라가고 싶어요."
                ),
            },
            {
                "question_id": "q5",
                "ordinal": 5,
                "axis": ExperienceAxis.EMOTION_IMAGE,
                "prompt_ko": (
                    "여행에서 오래 기억할 순간은 마음을 움직이는 분위기에서 생긴다고 느껴요."
                ),
            },
            {
                "question_id": "q6",
                "ordinal": 6,
                "axis": ExperienceAxis.REST_IMMERSION,
                "prompt_ko": (
                    "여러 곳을 빠르게 보기보다 한 곳의 공기와 풍경에 오래 머물고 싶어요."
                ),
            },
            {
                "question_id": "q7",
                "ordinal": 7,
                "axis": ExperienceAxis.HISTORY_TRADITION,
                "prompt_ko": (
                    "비슷한 풍경이라면, 전통과 생활문화가 구체적으로 이어지는 곳을 고르고 싶어요."
                ),
            },
            {
                "question_id": "q8",
                "ordinal": 8,
                "axis": ExperienceAxis.EMOTION_IMAGE,
                "prompt_ko": (
                    "같은 시간을 보낸다면, 나만의 시선으로 사진에 담고 싶은 공간을 찾고 싶어요."
                ),
            },
            {
                "question_id": "q9",
                "ordinal": 9,
                "axis": ExperienceAxis.REST_IMMERSION,
                "prompt_ko": (
                    "붐비는 장면보다 천천히 걷거나 쉬며 몰입할 수 있는 시간을 원해요."
                ),
            },
        ),
        "answer_options": (
            {"value": 1, "label_ko": "전혀 그렇지 않아요"},
            {"value": 2, "label_ko": "별로 그렇지 않아요"},
            {"value": 3, "label_ko": "보통이에요"},
            {"value": 4, "label_ko": "꽤 그래요"},
            {"value": 5, "label_ko": "매우 그래요"},
        ),
        "axis_tie_break": tuple(ExperienceAxis),
        "axis_display": (
            {
                "axis": ExperienceAxis.HISTORY_TRADITION,
                "label_ko": "역사·전통",
                "connective_ko": "역사·전통과",
            },
            {
                "axis": ExperienceAxis.EMOTION_IMAGE,
                "label_ko": "감성·이미지",
                "connective_ko": "감성·이미지와",
            },
            {
                "axis": ExperienceAxis.REST_IMMERSION,
                "label_ko": "휴식·몰입",
                "connective_ko": "휴식·몰입과",
            },
        ),
        "description_template_ko": (
            "이번 여행에서는 {first_with_particle} {second} 경험을 더 기대하고 있어요."
        ),
    }
    payload["config_hash"] = calculate_config_hash(payload)
    return QuestionnaireDefinition.model_validate(payload)


def derive_scoring_config(
    definition: QuestionnaireDefinition,
) -> Mapping[str, object]:
    """Project immutable scoring inputs from the canonical definition."""

    axis_questions = MappingProxyType(
        {
            axis: tuple(
                question.ordinal for question in definition.questions if question.axis is axis
            )
            for axis in definition.axis_tie_break
        }
    )
    axis_labels = MappingProxyType(
        {copy.axis: copy.label_ko for copy in definition.axis_display}
    )
    axis_connectives = MappingProxyType(
        {copy.axis: copy.connective_ko for copy in definition.axis_display}
    )
    return MappingProxyType(
        {
            "questionnaire_version": definition.questionnaire_version,
            "scoring_version": definition.scoring_version,
            "description_template_version": definition.description_template_version,
            "question_order": definition.question_order,
            "axis_questions": axis_questions,
            "axis_tie_break": definition.axis_tie_break,
            "axis_labels_ko": axis_labels,
            "axis_connectives_ko": axis_connectives,
            "description_template_ko": definition.description_template_ko,
            "config_hash": definition.config_hash,
        }
    )


QUESTIONNAIRE_DEFINITION = build_reviewed_questionnaire_definition_v1()
SCORING_CONFIG = derive_scoring_config(QUESTIONNAIRE_DEFINITION)


def questionnaire_artifact_bytes(
    definition: QuestionnaireDefinition = QUESTIONNAIRE_DEFINITION,
) -> bytes:
    """Render the stable generated projection committed for API and web consumers."""

    rendered = json.dumps(
        definition.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return f"{rendered}\n".encode()
