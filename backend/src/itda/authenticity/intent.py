"""Independent current-trip expectations; importance is not desired low intensity."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import Field, model_validator

from itda.authenticity.contracts import Level, Score
from itda.authenticity.rubric import AXES, AXIS_LABELS, AXIS_THEORY, FACET_KEYS, Axis, FacetKey
from itda.authenticity.visual import VISUAL_FACETS
from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.preference import (
    VERSION_BOUND_BY_QUESTIONNAIRE_V2,
    QuestionnaireAnswersV2,
    TripConditions,
)
from itda.contracts.visual_mood import VisualMoodDimension
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_scoring import half_up

QUESTIONNAIRE_VERSION = "authenticity-questionnaire-v1"
QUESTIONS = (
    ("H.a", "원래 남아 있는 유적이나 실물을 직접 만나는 경험을 원해요."),
    ("H.b", "이 장소에 얽힌 실제 역사와 사람들의 이야기를 알고 싶어요."),
    ("H.c", "지금도 이어지는 지역의 전통과 생활문화를 접하고 싶어요."),
    ("H.d", "유산이나 전통의 의미를 해설·전시를 통해 깊이 이해하고 싶어요."),
    ("E.a", "낭만·레트로처럼 이 장소를 떠올리게 하는 이미지를 느껴보고 싶어요."),
    ("E.b", "작품·사진·SNS에서 접한 장소를 직접 찾아가고 싶어요."),
    ("E.c", "내 취향의 색감·경관·공간 분위기를 경험하고 싶어요."),
    ("E.d", "알고 있던 장면이나 대표 구도를 현장에서 재현해보고 싶어요."),
    ("R.a", "일정에 쫓기지 않고 내 방식으로 선택하고 둘러보고 싶어요."),
    ("R.b", "자연이나 시각적으로 편안한 환경 속에 머물고 싶어요."),
    ("R.c", "만들기·걷기·신체 활동처럼 한 활동에 집중해보고 싶어요."),
    ("R.d", "함께하는 활동이나 나를 표현할 기회를 원해요."),
)
QUESTIONNAIRE = {
    "schema_version": QUESTIONNAIRE_VERSION,
    "title": "이번 여행에서 원하는 경험",
    "description": "경험마다 원하는 정도를 골라주세요. 여러 경험을 모두 원해도 괜찮아요.",
    "choices": [
        {"value": 0, "label": "상관없어요"},
        {"value": 1, "label": "조금 원해요"},
        {"value": 2, "label": "어느 정도 원해요"},
        {"value": 3, "label": "많이 원해요"},
        {"value": 4, "label": "꼭 경험하고 싶어요"},
        {"value": None, "label": "아직 모르겠어요"},
    ],
    "questions": [{"key": key, "text": text, "axis": key[0]} for key, text in QUESTIONS],
    "axes": {axis: {"label": AXIS_LABELS[axis], "theory": AXIS_THEORY[axis]} for axis in AXES},
    "interpretation": "현재 여행의 기대이며 성격 유형·검증된 심리 척도가 아님",
}
QUESTIONNAIRE_SHA256 = canonical_sha256(QUESTIONNAIRE)


class TripRequirements(StrictContract):
    region_code: str | None = Field(default=None, pattern=r"^\d{2,5}$")
    required_facilities: tuple[RequiredFacility, ...] = ()


class IntentSubmission(StrictContract):
    request_id: StableId
    questionnaire_sha256: Sha256 = QUESTIONNAIRE_SHA256
    answers: dict[FacetKey, Level | None]
    desired_levels: dict[FacetKey, Level] = Field(default_factory=dict)
    avoid: dict[FacetKey, Level] = Field(default_factory=dict)
    visual_targets: dict[VisualMoodDimension, Level] = Field(default_factory=dict)
    visual_input_kind: Literal["NONE", "MANUAL", "CONFIRMED_PHOTO"] = "NONE"
    photo_receipt_sha256: Sha256 | None = None
    requirements: TripRequirements = Field(default_factory=TripRequirements)

    @model_validator(mode="after")
    def meaning(self) -> Self:
        if self.questionnaire_sha256 != QUESTIONNAIRE_SHA256:
            raise ValueError("QUESTIONNAIRE_MEANING_VERSION_MISMATCH")
        if set(self.answers) != set(FACET_KEYS):
            raise ValueError("EXPECTATIONS_MUST_COVER_EXACT_FACETS")
        if any((self.answers[k] or 0) == 0 for k in self.desired_levels):
            raise ValueError("DESIRED_INTENSITY_REQUIRES_IMPORTANCE")
        if any((self.answers[k] or 0) > 0 and strength > 0 for k, strength in self.avoid.items()):
            raise ValueError("CANNOT_SIMULTANEOUSLY_SEEK_AND_AVOID_FACET")
        if any(self.avoid.get(VISUAL_FACETS[k], 0) > 0 for k in self.visual_targets):
            raise ValueError("VISUAL_PREFERENCE_CONFLICTS_WITH_AVOIDANCE")
        if bool(self.visual_targets) != (self.visual_input_kind != "NONE"):
            raise ValueError("VISUAL_PREFERENCE_SOURCE_MISMATCH")
        if (self.visual_input_kind == "CONFIRMED_PHOTO") != (self.photo_receipt_sha256 is not None):
            raise ValueError("PHOTO_TARGETS_REQUIRE_CONFIRMED_RECEIPT")
        return self


class ScenarioSubmission(StrictContract):
    """Retained scenarios supply axis preferences, never invented facet answers."""

    schema_version: Literal["scenario-expectation-bridge.v1"] = "scenario-expectation-bridge.v1"
    request_id: StableId
    questionnaire_config_hash: Sha256
    answers: QuestionnaireAnswersV2
    trip_conditions: TripConditions
    exact_visit_time: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    requirements: TripRequirements = Field(default_factory=TripRequirements)
    visual_targets: dict[VisualMoodDimension, Level] = Field(default_factory=dict)
    visual_input_kind: Literal["NONE", "CONFIRMED_PHOTO"] = "NONE"
    photo_receipt_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def meaning(self) -> Self:
        if self.questionnaire_config_hash != VERSION_BOUND_BY_QUESTIONNAIRE_V2["config_hash"]:
            raise ValueError("SCENARIO_QUESTIONNAIRE_VERSION_MISMATCH")
        if bool(self.visual_targets) != (self.visual_input_kind == "CONFIRMED_PHOTO"):
            raise ValueError("VISUAL_PREFERENCE_SOURCE_MISMATCH")
        if (self.visual_input_kind == "CONFIRMED_PHOTO") != (self.photo_receipt_sha256 is not None):
            raise ValueError("PHOTO_TARGETS_REQUIRE_CONFIRMED_RECEIPT")
        return self


def scenario_weights(submission: ScenarioSubmission, total: int = 10_000) -> dict[Axis, int]:
    """Reuse the sealed scenario matrix, then apportion its axis evidence exactly."""
    from itda.domain.preference import score_choice_answers

    scores = score_choice_answers(submission.answers)
    raw = {axis: score.basis_points for axis, score in zip(AXES, scores, strict=True)}
    denominator = sum(raw.values())
    if denominator == 0:
        return {axis: 0 for axis in AXES}
    weights = {axis: raw[axis] * total // denominator for axis in AXES}
    remainder = total - sum(weights.values())
    order = sorted(AXES, key=lambda axis: (-(raw[axis] * total % denominator), AXES.index(axis)))
    for axis in order[:remainder]:
        weights[axis] += 1
    return weights


class Intent(StrictContract):
    schema_version: Literal["authenticity-intent.v1"] = "authenticity-intent.v1"
    profile_id: Sha256
    submission: IntentSubmission | ScenarioSubmission
    axis_importance: dict[Axis, Score | None]
    requested_axes: tuple[Axis, ...]
    required_axes: tuple[Axis, ...]
    created_at: datetime
    intent_sha256: Sha256

    @model_validator(mode="after")
    def identity(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.intent_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"intent_sha256"})
        ):
            raise ValueError("INTENT_DIGEST_MISMATCH")
        importance, requested, required = expectations(self.submission)
        if (
            self.axis_importance != importance
            or self.requested_axes != requested
            or self.required_axes != required
        ):
            raise ValueError("INTENT_EXPECTATION_PROJECTION_MISMATCH")
        if self.profile_id != canonical_sha256(self.submission.model_dump(mode="json")):
            raise ValueError("INTENT_PROFILE_ID_MISMATCH")
        return self


def effective_importance(submission: IntentSubmission) -> dict[FacetKey, int | None]:
    weights: dict[FacetKey, int | None] = dict(submission.answers)
    for dimension in submission.visual_targets:
        facet = VISUAL_FACETS[dimension]
        weights[facet] = max(weights[facet] or 0, 2)
    return weights


def expectations(
    submission: IntentSubmission | ScenarioSubmission,
) -> tuple[dict[Axis, int | None], tuple[Axis, ...], tuple[Axis, ...]]:
    if isinstance(submission, ScenarioSubmission):
        relative = scenario_weights(submission)
        maximum = max(relative.values())
        return (
            {axis: half_up(relative[axis], 100) for axis in AXES},
            tuple(axis for axis in AXES if relative[axis] > 0),
            tuple(axis for axis in AXES if maximum > 0 and relative[axis] == maximum),
        )
    weights = effective_importance(submission)
    importance: dict[Axis, int | None] = {}
    requested = []
    required = []
    for axis in AXES:
        known = [v for k, v in weights.items() if k.startswith(axis + ".") and v is not None]
        importance[axis] = half_up(25 * sum(known), len(known)) if known else None
        values = [
            v for k, v in weights.items() if k.startswith(axis + ".") and v is not None and v > 0
        ]
        if values:
            requested.append(axis)
        if any(v >= 3 for v in values):
            required.append(axis)
    if len(requested) == 1:
        required = list(requested)
    return importance, tuple(requested), tuple(required)


def build_intent(
    submission: IntentSubmission | ScenarioSubmission, *, created_at: datetime
) -> Intent:
    type(submission).model_validate_json(submission.model_dump_json())
    importance, requested, required = expectations(submission)
    payload = {
        "schema_version": "authenticity-intent.v1",
        "profile_id": canonical_sha256(submission.model_dump(mode="json")),
        "submission": submission.model_dump(mode="json"),
        "axis_importance": importance,
        "requested_axes": list(requested),
        "required_axes": list(required),
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    return Intent.model_validate(payload | {"intent_sha256": canonical_sha256(payload)})
