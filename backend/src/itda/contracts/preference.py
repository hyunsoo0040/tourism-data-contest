"""Preference-session and deterministic profile contracts."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import (
    BasisPoints,
    ExperienceAxis,
    Score100,
    Sha256,
    StableId,
    StrictContract,
    Version,
    require_utc,
)

AnswerValue = Annotated[int, Field(strict=True, ge=1, le=5)]
ChoiceValue = Annotated[int, Field(strict=True, ge=1, le=3)]

QUESTIONNAIRE_VERSION_V1 = "questionnaire-v1"
QUESTIONNAIRE_VERSION_V2 = "questionnaire-v2"

# Canonical version coupling: a stored profile's auxiliary version fields and
# answer type are bound to exactly one questionnaire generation. Legacy v1
# rows keep their historical exact versions/hash; current v2 profiles carry
# the bumped schema/scoring/template versions and the canonical v2 hash.
VERSION_BOUND_BY_QUESTIONNAIRE_V1: dict[str, object] = {
    "schema_version": "preference-profile-v1",
    "scoring_version": "integer-bp-v1",
    "description_template_version": "current-trip-expectation-v1",
    "config_hash": "bc24c1ca59272397bf0dad41be34cf536b6cb6215d3148567d09fbebd749b09c",
    "answers_type": "QuestionnaireAnswersV1",
}
VERSION_BOUND_BY_QUESTIONNAIRE_V2: dict[str, object] = {
    "schema_version": "preference-profile-v2",
    "scoring_version": "choice-bp-v2",
    "description_template_version": "current-trip-expectation-v1",
    "config_hash": "3531142763d74474f702a20bb4590068696b446b77391dbd2ca17d8ee5ac7563",
    "answers_type": "QuestionnaireAnswersV2",
}


class VisitTime(StrEnum):
    MORNING = "MORNING"
    DAYTIME = "DAYTIME"
    SUNSET = "SUNSET"
    EVENING = "EVENING"
    UNDECIDED = "UNDECIDED"


class CompanionType(StrEnum):
    SOLO = "SOLO"
    FRIEND_OR_PARTNER = "FRIEND_OR_PARTNER"
    FAMILY_WITH_CHILDREN = "FAMILY_WITH_CHILDREN"
    WITH_SENIORS = "WITH_SENIORS"
    GROUP = "GROUP"


class TransportType(StrEnum):
    WALK_OR_TRANSIT = "WALK_OR_TRANSIT"
    CAR_OR_TAXI = "CAR_OR_TAXI"
    MIXED = "MIXED"


class WalkingTolerance(StrEnum):
    WITHIN_30_MINUTES = "WITHIN_30_MINUTES"
    ABOUT_1_HOUR = "ABOUT_1_HOUR"
    EXTENDED_WALKING_OK = "EXTENDED_WALKING_OK"


class IndoorOutdoorPreference(StrEnum):
    INDOOR = "INDOOR"
    NO_PREFERENCE = "NO_PREFERENCE"
    OUTDOOR = "OUTDOOR"


class CrowdAvoidance(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TripConditions(StrictContract):
    visit_date: date | None
    visit_time: VisitTime
    companion: CompanionType
    transport: TransportType
    walking_tolerance: WalkingTolerance
    indoor_outdoor_preference: IndoorOutdoorPreference
    crowd_avoidance: CrowdAvoidance


class QuestionnaireAnswersV1(StrictContract):
    """Legacy nine-question Likert answers (values 1..5); retained for replay."""

    q1: AnswerValue
    q2: AnswerValue
    q3: AnswerValue
    q4: AnswerValue
    q5: AnswerValue
    q6: AnswerValue
    q7: AnswerValue
    q8: AnswerValue
    q9: AnswerValue


class QuestionnaireAnswersV2(StrictContract):
    """Current twelve-scenario choice answers (values 1..3)."""

    q1: ChoiceValue
    q2: ChoiceValue
    q3: ChoiceValue
    q4: ChoiceValue
    q5: ChoiceValue
    q6: ChoiceValue
    q7: ChoiceValue
    q8: ChoiceValue
    q9: ChoiceValue
    q10: ChoiceValue
    q11: ChoiceValue
    q12: ChoiceValue


# Historical alias retained for legacy import sites; resolves to the v1 shape.
QuestionnaireAnswers = QuestionnaireAnswersV1


class QuestionnaireSubmission(StrictContract):
    """Current-trip submission; v2-only for new profile creation."""

    request_id: StableId
    trip_conditions: TripConditions
    answers: QuestionnaireAnswersV2


class AxisScore(StrictContract):
    axis: ExperienceAxis
    basis_points: BasisPoints
    display_score: Score100

    @model_validator(mode="after")
    def display_score_matches_basis_points(self) -> AxisScore:
        if self.display_score != (self.basis_points + 50) // 100:
            raise ValueError("display_score must be basis_points rounded half-up")
        return self


class PreferenceProfile(StrictContract):
    """Stored profile; every version field is coupled to questionnaire_version."""

    profile_id: StableId
    request_id: StableId
    trip_conditions: TripConditions
    answers: QuestionnaireAnswersV1 | QuestionnaireAnswersV2
    scores: tuple[AxisScore, AxisScore, AxisScore]
    description_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    schema_version: Version
    questionnaire_version: Version
    scoring_version: Version
    description_template_version: Version
    config_hash: Sha256
    created_at: datetime
    is_current_trip_expectation: StrictBool = True

    @model_validator(mode="after")
    def profile_invariants(self) -> PreferenceProfile:
        require_utc(self.created_at, field_name="created_at")
        expected_axes = tuple(ExperienceAxis)
        if tuple(score.axis for score in self.scores) != expected_axes:
            raise ValueError("scores must use canonical H-E-R axis order")
        if not self.is_current_trip_expectation:
            raise ValueError("profile must describe the current trip expectation")
        if self.questionnaire_version == QUESTIONNAIRE_VERSION_V1:
            bound = VERSION_BOUND_BY_QUESTIONNAIRE_V1
            answers_type: type = QuestionnaireAnswersV1
        elif self.questionnaire_version == QUESTIONNAIRE_VERSION_V2:
            bound = VERSION_BOUND_BY_QUESTIONNAIRE_V2
            answers_type = QuestionnaireAnswersV2
        else:
            raise ValueError(f"unsupported questionnaire_version: {self.questionnaire_version}")
        if not isinstance(self.answers, answers_type):
            expected = bound["answers_type"]
            raise ValueError(
                f"{self.questionnaire_version} profiles require {expected} answers"
            )
        for field_name in ("schema_version", "scoring_version", "config_hash"):
            if getattr(self, field_name) != bound[field_name]:
                raise ValueError(
                    f"{field_name} {getattr(self, field_name)!r} is not the canonical "
                    f"{bound[field_name]!r} bound to {self.questionnaire_version}"
                )
        if self.description_template_version != bound["description_template_version"]:
            raise ValueError(
                f"description_template_version {self.description_template_version!r} is not "
                f"the canonical {bound['description_template_version']!r} bound to "
                f"{self.questionnaire_version}"
            )
        return self
