"""Canonical v2 choice questionnaire and the reviewed local scoring matrix.

The scenario copy, choice texts, and result-type metadata transcribe the
authorized upstream UI (see fixtures/upstream-ui/provenance.json), but this
module is the local backend production authority. Upstream JavaScript is never
imported or executed: the H/E/R basis-point matrix below is reviewed, local,
versioned, and frozen by tests.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Final, cast

from pydantic import BaseModel, Field, model_validator

from itda.contracts.base import ExperienceAxis, Sha256, StrictContract, Version
from itda.contracts.questionnaire import AxisDisplayCopy, KoreanCopy

# v2-local primitives: the legacy questionnaire module keeps its strict q1..q9
# boundary, so the twelve-scenario v2 identifiers are defined independently here.
V2QuestionId = Annotated[str, Field(strict=True, pattern=r"^q(?:[1-9]|1[0-2])$")]
V2QuestionOrdinal = Annotated[int, Field(strict=True, ge=1, le=12)]

ChoiceId = Annotated[str, Field(strict=True, pattern=r"^q(?:[1-9]|1[0-2])o[1-3]$")]
ChoiceValue = Annotated[int, Field(strict=True, ge=1, le=3)]

V2_QUESTIONNAIRE_VERSION: Final[str] = "questionnaire-v2"
V2_SCORING_VERSION: Final[str] = "choice-bp-v2"

AXIS_WEIGHT_H: Final[int] = 2
AXIS_WEIGHT_E: Final[int] = 2
AXIS_WEIGHT_R: Final[int] = 2
AXIS_WEIGHT_TOTAL: Final[int] = AXIS_WEIGHT_H + AXIS_WEIGHT_E + AXIS_WEIGHT_R

# Attainable per-axis accumulated-weight bounds over the canonical twelve
# questions. Each choice donates AXIS_WEIGHT_TOTAL - 2 = 4 to its primary and
# 1 to each secondary; the two non-primary axes therefore see a minimum of
# 1 per question (total 12), while each axis's attainable maximum follows from
# its per-question best case across the frozen upstream scenario set
# (H: 48, E: 42, R: 45 — verified by contract test against the matrix).
# score_axis_v2 normalizes each axis against ITS OWN bounds so 0 bp is
# attainable and 10_000 bp is attainable on every axis.
AXIS_ATTAINABLE_BOUNDS: Final[Mapping[str, tuple[int, int]]] = MappingProxyType(
    {
        ExperienceAxis.HISTORY_TRADITION.value: (12, 48),
        ExperienceAxis.EMOTION_IMAGE.value: (12, 42),
        ExperienceAxis.REST_IMMERSION.value: (12, 45),
    }
)


class QuestionnaireChoiceOption(StrictContract):
    """One strict three-point scenario choice with its upstream-frozen copy."""

    choice_id: ChoiceId
    value: ChoiceValue
    text_ko: KoreanCopy
    keywords_ko: tuple[KoreanCopy, KoreanCopy]
    axis: ExperienceAxis


class QuestionnaireScenarioItem(StrictContract):
    """One upstream-frozen scenario with its three canonical choices."""

    question_id: V2QuestionId
    ordinal: V2QuestionOrdinal
    title_ko: KoreanCopy
    description_ko: KoreanCopy
    options: tuple[QuestionnaireChoiceOption, QuestionnaireChoiceOption, QuestionnaireChoiceOption]

    @model_validator(mode="after")
    def choice_invariants(self) -> QuestionnaireScenarioItem:
        expected = tuple(f"q{self.ordinal}o{value}" for value in range(1, 4))
        if tuple(option.choice_id for option in self.options) != expected:
            raise ValueError("choice IDs must be q{i}o{1..3} in order")
        if tuple(option.value for option in self.options) != (1, 2, 3):
            raise ValueError("choice values must be strict 1 through 3")
        return self


class QuestionnaireResultType(StrictContract):
    """Reviewed result-copy metadata for one axis, transcribed from upstream."""

    axis: ExperienceAxis
    name_ko: KoreanCopy
    character_ko: KoreanCopy
    role_ko: KoreanCopy
    character_image: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    lens_ko: KoreanCopy
    description_ko: KoreanCopy
    recommend_ko: KoreanCopy


class QuestionnaireDefinitionV2(StrictContract):
    """The canonical v2 choice questionnaire with its reviewed scoring matrix."""

    questionnaire_version: Version
    scoring_version: Version
    description_template_version: Version
    question_order: tuple[V2QuestionOrdinal, ...]
    questions: tuple[QuestionnaireScenarioItem, ...]
    axis_tie_break: tuple[ExperienceAxis, ...]
    axis_display: tuple[AxisDisplayCopy, ...]
    description_template_ko: KoreanCopy
    result_types: tuple[QuestionnaireResultType, ...]
    scoring_matrix: Mapping[str, Mapping[str, int]]
    config_hash: Sha256

    @model_validator(mode="after")
    def v2_invariants(self) -> QuestionnaireDefinitionV2:
        if self.question_order != tuple(range(1, 13)):
            raise ValueError("v2 question_order must use canonical visible order 1 through 12")
        if len(self.questions) != 12:
            raise ValueError("v2 questions must contain exactly twelve scenarios")
        if tuple(question.ordinal for question in self.questions) != self.question_order:
            raise ValueError("v2 question ordinals must match question_order")
        if tuple(question.question_id for question in self.questions) != tuple(
            f"q{ordinal}" for ordinal in self.question_order
        ):
            raise ValueError("v2 question IDs must be q1 through q12 in order")
        if self.axis_tie_break != tuple(ExperienceAxis):
            raise ValueError("v2 axis_tie_break must use canonical H-E-R order")
        if tuple(copy.axis for copy in self.axis_display) != tuple(ExperienceAxis):
            raise ValueError("v2 axis_display must use canonical H-E-R order")
        if tuple(result.axis for result in self.result_types) != tuple(ExperienceAxis):
            raise ValueError("v2 result_types must use canonical H-E-R order")
        if "{first_with_particle}" not in self.description_template_ko or (
            "{second}" not in self.description_template_ko
        ):
            raise ValueError("v2 description template must expose both placeholders")

        expected_choice_axes: dict[str, ExperienceAxis] = {}
        for question in self.questions:
            for option in question.options:
                expected_choice_axes[option.choice_id] = option.axis
        for choice_id, axis_weights in self.scoring_matrix.items():
            if tuple(sorted(axis_weights)) != tuple(sorted(ExperienceAxis)):
                raise ValueError(f"scoring matrix row {choice_id} must cover H, E, and R")
            if any(type(weight) is not int or weight < 0 for weight in axis_weights.values()):
                raise ValueError(f"scoring matrix row {choice_id} must use integer weights")
            if sum(axis_weights.values()) != AXIS_WEIGHT_TOTAL:
                raise ValueError(f"scoring matrix row {choice_id} must sum to {AXIS_WEIGHT_TOTAL}")
            primary = max(axis_weights, key=lambda axis: axis_weights[axis])
            if ExperienceAxis(primary) is not expected_choice_axes.get(choice_id):
                raise ValueError(
                    f"scoring matrix row {choice_id} primary axis must match the choice axis"
                )
        if set(self.scoring_matrix) != set(expected_choice_axes):
            raise ValueError("scoring matrix must cover exactly the 36 canonical choices")
        actual_bounds = {
            axis.value: (
                sum(
                    min(self.scoring_matrix[option.choice_id][axis.value] for option in q.options)
                    for q in self.questions
                ),
                sum(
                    max(self.scoring_matrix[option.choice_id][axis.value] for option in q.options)
                    for q in self.questions
                ),
            )
            for axis in ExperienceAxis
        }
        if {key: tuple(value) for key, value in AXIS_ATTAINABLE_BOUNDS.items()} != actual_bounds:
            raise ValueError(
                "scoring matrix attainable per-axis bounds must match "
                "AXIS_ATTAINABLE_BOUNDS exactly"
            )
        if self.config_hash != calculate_config_hash_v2(self):
            raise ValueError("v2 config_hash does not match canonical semantics")
        return self


def calculate_config_hash_v2(payload: Mapping[str, object] | BaseModel) -> str:
    """Hash v2 semantics canonically, excluding the hash and the derived matrix."""

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


def _matrix_row(primary: ExperienceAxis) -> dict[str, int]:
    row = {axis.value: 0 for axis in ExperienceAxis}
    secondaries = [axis for axis in ExperienceAxis if axis is not primary]
    row[primary.value] = AXIS_WEIGHT_H + AXIS_WEIGHT_E + AXIS_WEIGHT_R - len(secondaries)
    row[secondaries[0].value] = 1
    row[secondaries[1].value] = 1
    return row


def build_reviewed_questionnaire_definition_v2() -> QuestionnaireDefinitionV2:
    """Build the one reviewed v2 definition; the matrix is the local authority."""

    payload: dict[str, object] = {
        "questionnaire_version": V2_QUESTIONNAIRE_VERSION,
        "scoring_version": V2_SCORING_VERSION,
        "description_template_version": "current-trip-expectation-v1",
        "question_order": tuple(range(1, 13)),
        "questions": (
            {
                "question_id": "q1",
                "ordinal": 1,
                "title_ko": "기차에서 내렸는데 예상보다 30분 일찍 도착했다.",
                "description_ko": (
                    "당신의 여행이 시작됩니다. 가장 자연스럽게 할 행동을 골라보세요."
                ),
                "options": (
                    {
                        "choice_id": "q1o1",
                        "value": 1,
                        "text_ko": "근처 벤치에 앉아 여행이 시작된 기분을 느껴본다.",
                        "keywords_ko": ("여유", "시작"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q1o2",
                        "value": 2,
                        "text_ko": "여행 전에 가장 기대했던 장소부터 향한다.",
                        "keywords_ko": ("기대", "장면"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q1o3",
                        "value": 3,
                        "text_ko": "역 주변을 천천히 걸으며 동네 모습을 살펴본다.",
                        "keywords_ko": ("발견", "동네"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q2",
                "ordinal": 2,
                "title_ko": "길을 걷다가 계획에 없던 골목이 눈에 들어왔다.",
                "description_ko": "예정에 없던 길 앞에서 당신은 어떻게 움직이나요?",
                "options": (
                    {
                        "choice_id": "q2o1",
                        "value": 1,
                        "text_ko": "어디로 이어지는지 궁금해 들어가 본다.",
                        "keywords_ko": ("궁금함", "탐색"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q2o2",
                        "value": 2,
                        "text_ko": "예전에 SNS에서 봤던 분위기와 비슷해 보여 들어가 본다.",
                        "keywords_ko": ("분위기", "장면"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q2o3",
                        "value": 3,
                        "text_ko": (
                            "원래 계획에는 없었지만 그냥 지나치기엔 왠지 아쉬워 들어가 본다."
                        ),
                        "keywords_ko": ("아쉬움", "우연"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                ),
            },
            {
                "question_id": "q3",
                "ordinal": 3,
                "title_ko": '친구가 "여긴 꼭 가봐"라고 추천해줬다.',
                "description_ko": "추천받은 장소를 대하는 당신의 방식은 무엇인가요?",
                "options": (
                    {
                        "choice_id": "q3o1",
                        "value": 1,
                        "text_ko": "오늘 일정과 기분을 보고 결정한다.",
                        "keywords_ko": ("기분", "여유"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q3o2",
                        "value": 2,
                        "text_ko": "왜 추천했는지 이유부터 물어본다.",
                        "keywords_ko": ("이유", "맥락"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q3o3",
                        "value": 3,
                        "text_ko": "누군가에게 특별한 곳이라니 더 궁금해진다.",
                        "keywords_ko": ("특별함", "기대"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                ),
            },
            {
                "question_id": "q4",
                "ordinal": 4,
                "title_ko": "갑자기 비가 내리기 시작했다.",
                "description_ko": "날씨가 바뀐 순간, 당신의 여행도 조금 달라집니다.",
                "options": (
                    {
                        "choice_id": "q4o1",
                        "value": 1,
                        "text_ko": "비 오는 풍경도 이번 여행만의 기억이 될 것 같다고 생각한다.",
                        "keywords_ko": ("기억", "풍경"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q4o2",
                        "value": 2,
                        "text_ko": "우산을 쓰지 않고 비를 맞으며 천천히 걸어본다.",
                        "keywords_ko": ("감각", "몰입"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q4o3",
                        "value": 3,
                        "text_ko": "근처에 들를 만한 곳이 있는지 찾아본다.",
                        "keywords_ko": ("탐색", "발견"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q5",
                "ordinal": 5,
                "title_ko": "골목에서 길고양이 한 마리가 당신을 빤히 쳐다본다.",
                "description_ko": "사소한 만남 앞에서 떠오르는 반응을 골라보세요.",
                "options": (
                    {
                        "choice_id": "q5o1",
                        "value": 1,
                        "text_ko": "괜히 웃음이 나고 한참 바라본다.",
                        "keywords_ko": ("미소", "장면"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q5o2",
                        "value": 2,
                        "text_ko": "잠시 인사만 하고 갈 길을 간다.",
                        "keywords_ko": ("순간", "흐름"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q5o3",
                        "value": 3,
                        "text_ko": "어디로 가는지 괜히 따라가 본다.",
                        "keywords_ko": ("호기심", "탐색"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q6",
                "ordinal": 6,
                "title_ko": "식당 앞에서 20분 정도 기다려야 한다.",
                "description_ko": "기다리는 시간마저 여행의 일부가 될 수 있다면요?",
                "options": (
                    {
                        "choice_id": "q6o1",
                        "value": 1,
                        "text_ko": "기다리는 시간도 괜찮다고 생각한다.",
                        "keywords_ko": ("기다림", "여유"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q6o2",
                        "value": 2,
                        "text_ko": "왜 사람들이 많이 오는지 궁금해진다.",
                        "keywords_ko": ("이유", "호기심"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q6o3",
                        "value": 3,
                        "text_ko": "다른 사람들이 뭘 먹는지 먼저 둘러본다.",
                        "keywords_ko": ("관찰", "탐색"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q7",
                "ordinal": 7,
                "title_ko": "현지인이 예상 밖의 장소를 추천해줬다.",
                "description_ko": "계획 밖 제안이 들어왔을 때의 선택입니다.",
                "options": (
                    {
                        "choice_id": "q7o1",
                        "value": 1,
                        "text_ko": "이런 우연이 여행의 묘미라고 생각한다.",
                        "keywords_ko": ("우연", "특별함"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q7o2",
                        "value": 2,
                        "text_ko": "지금 마음이 움직이지 않으면 다음 기회로 미룬다.",
                        "keywords_ko": ("마음", "흐름"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q7o3",
                        "value": 3,
                        "text_ko": "어떤 곳인지 궁금해져 가본다.",
                        "keywords_ko": ("궁금함", "탐색"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q8",
                "ordinal": 8,
                "title_ko": "숙소 체크아웃까지 30분이 남았다.",
                "description_ko": "떠나기 전 남은 시간을 어떻게 쓰고 싶나요?",
                "options": (
                    {
                        "choice_id": "q8o1",
                        "value": 1,
                        "text_ko": "짐을 정리하며 마지막 시간을 보낸다.",
                        "keywords_ko": ("마무리", "정리"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q8o2",
                        "value": 2,
                        "text_ko": "체크아웃하기 전에 숙소 구석구석을 한 번 더 둘러본다.",
                        "keywords_ko": ("관찰", "둘러보기"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q8o3",
                        "value": 3,
                        "text_ko": "숙소 주변을 한 번 더 둘러본다.",
                        "keywords_ko": ("둘러보기", "발견"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q9",
                "ordinal": 9,
                "title_ko": "버스를 놓쳤다. 다음 버스는 25분 뒤다.",
                "description_ko": "예상 밖의 빈 시간이 생겼습니다.",
                "options": (
                    {
                        "choice_id": "q9o1",
                        "value": 1,
                        "text_ko": "계획에 없던 시간이 생겨 오히려 여행다운 느낌이 든다.",
                        "keywords_ko": ("우연", "여행감"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q9o2",
                        "value": 2,
                        "text_ko": "벤치에 앉아 잠시 쉬어간다.",
                        "keywords_ko": ("쉼", "여유"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                    {
                        "choice_id": "q9o3",
                        "value": 3,
                        "text_ko": "근처에 뭐가 있는지 둘러본다.",
                        "keywords_ko": ("탐색", "발견"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                ),
            },
            {
                "question_id": "q10",
                "ordinal": 10,
                "title_ko": "숙소로 돌아가는 길, 작은 공연이 열리고 있다.",
                "description_ko": "예상치 못한 장면 앞에서 당신은 어떻게 하나요?",
                "options": (
                    {
                        "choice_id": "q10o1",
                        "value": 1,
                        "text_ko": "무슨 공연인지 궁금해서 가까이 가본다.",
                        "keywords_ko": ("궁금함", "현장"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q10o2",
                        "value": 2,
                        "text_ko": "예상치 못한 장면이라 괜히 기분이 좋아진다.",
                        "keywords_ko": ("장면", "기분"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q10o3",
                        "value": 3,
                        "text_ko": "잠시 멈춰 서서 공연을 즐긴다.",
                        "keywords_ko": ("몰입", "순간"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                ),
            },
            {
                "question_id": "q11",
                "ordinal": 11,
                "title_ko": (
                    "집으로 돌아가기 전, 여행을 마무리하며 마지막으로 사진첩을 훑어본다."
                ),
                "description_ko": "사진첩을 넘길 때 가장 먼저 하는 일은 무엇인가요?",
                "options": (
                    {
                        "choice_id": "q11o1",
                        "value": 1,
                        "text_ko": "어떤 장소를 갔는지 순서대로 다시 본다.",
                        "keywords_ko": ("장소", "정리"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q11o2",
                        "value": 2,
                        "text_ko": "가장 마음에 들었던 장면을 오래도록 바라본다.",
                        "keywords_ko": ("장면", "기억"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q11o3",
                        "value": 3,
                        "text_ko": "사진 속 모습 자체보다 그때의 기분이 먼저 떠오른다.",
                        "keywords_ko": ("기분", "여운"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                ),
            },
            {
                "question_id": "q12",
                "ordinal": 12,
                "title_ko": (
                    "집에 돌아와 가방을 정리하다가 주머니에서 작은 영수증 한 장이 나왔다."
                ),
                "description_ko": "여행이 끝난 뒤 남은 작은 흔적을 마주했습니다.",
                "options": (
                    {
                        "choice_id": "q12o1",
                        "value": 1,
                        "text_ko": "어디에서 받은 건지 기억을 더듬어 본다.",
                        "keywords_ko": ("기억", "맥락"),
                        "axis": ExperienceAxis.HISTORY_TRADITION,
                    },
                    {
                        "choice_id": "q12o2",
                        "value": 2,
                        "text_ko": "그날의 장면이 떠올라 괜히 미소가 난다.",
                        "keywords_ko": ("장면", "미소"),
                        "axis": ExperienceAxis.EMOTION_IMAGE,
                    },
                    {
                        "choice_id": "q12o3",
                        "value": 3,
                        "text_ko": "여행이 끝났다는 사실이 실감난다.",
                        "keywords_ko": ("마무리", "여운"),
                        "axis": ExperienceAxis.REST_IMMERSION,
                    },
                ),
            },
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
        "result_types": (
            {
                "axis": ExperienceAxis.HISTORY_TRADITION,
                "name_ko": "객관적 진정성",
                "character_ko": "오리지널 시커",
                "role_ko": "Original Seeker | 가치 발견가",
                "character_image": "./assets/characters/original-seeker.jpg",
                "lens_ko": "장소가 오랫동안 간직해 온 고유한 가치와 진짜 모습을 중요하게 여깁니다.",
                "description_ko": (
                    "장소 자체와 그곳의 고유한 특성, 새롭게 발견한 맥락에서 여행의 의미를 찾는 "
                    "여행자입니다."
                ),
                "recommend_ko": (
                    "지역의 이야기, 생활문화, 오래된 거리, 해설이 있는 관광지처럼 장소의 본래 "
                    "매력을 깊게 살필 수 있는 코스가 잘 맞습니다."
                ),
            },
            {
                "axis": ExperienceAxis.EMOTION_IMAGE,
                "name_ko": "구성적 진정성",
                "character_ko": "무드 위버",
                "role_ko": "Mood Weaver | 장면 수집가",
                "character_image": "./assets/characters/mood-weaver.jpg",
                "lens_ko": (
                    "기대와 이미지, 사람들이 만들어낸 의미 속에서 여행의 특별함을 발견합니다."
                ),
                "description_ko": (
                    "관광객과 사회가 부여한 의미, 기대했던 분위기, 기억하고 싶은 장면 속에서 "
                    "여행의 의미를 찾는 여행자입니다."
                ),
                "recommend_ko": (
                    "우연한 장면, 분위기 좋은 거리, 다시 보고 싶은 풍경처럼 나만의 해석과 기억을 "
                    "쌓을 수 있는 장소가 잘 맞습니다."
                ),
            },
            {
                "axis": ExperienceAxis.REST_IMMERSION,
                "name_ko": "실존적 진정성",
                "character_ko": "플로우 워커",
                "role_ko": "Flow Walker | 순간 여행가",
                "character_image": "./assets/characters/flow-walker.jpg",
                "lens_ko": "장소 자체보다 그곳에서 느끼는 감정과 경험을 더 중요하게 여깁니다.",
                "description_ko": (
                    "자신의 감정, 여유, 몰입 경험을 통해 여행이 나에게 남기는 감각을 중요하게 "
                    "보는 여행자입니다."
                ),
                "recommend_ko": (
                    "잠시 멈춰 서기 좋은 공간, 천천히 머물 수 있는 산책길, 기분의 흐름에 따라 "
                    "움직일 수 있는 여유로운 코스가 잘 맞습니다."
                ),
            },
        ),
    }

    choices_by_id: dict[str, ExperienceAxis] = {}
    questions = payload["questions"]
    assert isinstance(questions, tuple)
    for question in questions:
        options = question["options"]
        assert isinstance(options, tuple)
        for option in options:
            choices_by_id[option["choice_id"]] = option["axis"]
    scoring_matrix = {
        choice_id: _matrix_row(axis) for choice_id, axis in sorted(choices_by_id.items())
    }
    payload["scoring_matrix"] = scoring_matrix
    payload["config_hash"] = calculate_config_hash_v2(payload)
    return QuestionnaireDefinitionV2.model_validate(payload)


def derive_v2_scoring_config(
    definition: QuestionnaireDefinitionV2,
) -> Mapping[str, object]:
    """Project immutable v2 scoring inputs from the canonical definition."""

    axis_labels = MappingProxyType(
        {copy.axis: copy.label_ko for copy in definition.axis_display}
    )
    axis_connectives = MappingProxyType(
        {copy.axis: copy.connective_ko for copy in definition.axis_display}
    )
    choices_by_id = {
        option.choice_id: option
        for question in definition.questions
        for option in question.options
    }
    return MappingProxyType(
        {
            "questionnaire_version": definition.questionnaire_version,
            "scoring_version": definition.scoring_version,
            "description_template_version": definition.description_template_version,
            "question_order": definition.question_order,
            "choices_by_id": MappingProxyType(choices_by_id),
            "scoring_matrix": definition.scoring_matrix,
            "axis_tie_break": definition.axis_tie_break,
            "axis_labels_ko": axis_labels,
            "axis_connectives_ko": axis_connectives,
            "description_template_ko": definition.description_template_ko,
            "config_hash": definition.config_hash,
        }
    )


QUESTIONNAIRE_DEFINITION_V2 = build_reviewed_questionnaire_definition_v2()
SCORING_CONFIG_V2 = derive_v2_scoring_config(QUESTIONNAIRE_DEFINITION_V2)
V2_CONFIG_HASH: Final[str] = cast(str, SCORING_CONFIG_V2["config_hash"])

__all__ = [
    "AXIS_ATTAINABLE_BOUNDS",
    "AXIS_WEIGHT_TOTAL",
    "QUESTIONNAIRE_DEFINITION_V2",
    "SCORING_CONFIG_V2",
    "V2_CONFIG_HASH",
    "V2_QUESTIONNAIRE_VERSION",
    "V2_SCORING_VERSION",
    "QuestionnaireDefinitionV2",
    "calculate_config_hash_v2",
]
