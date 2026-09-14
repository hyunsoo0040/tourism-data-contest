"""Independent appearance observations; no factual tourism score authority."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract
from itda.domain.canonical import canonical_sha256

VISUAL_MOOD_VERSION: Literal["visual-mood-v1"] = "visual-mood-v1"
PHOTO_MOOD_FAMILY: Literal["photo-mood-v1"] = "photo-mood-v1"


class VisualMoodDimension(StrEnum):
    GREENERY = "greenery"
    WATER = "water"
    OPEN_COMPOSITION = "open_composition"
    TRADITIONAL_APPEARANCE = "traditional_appearance"
    CONTEMPORARY_DESIGN = "contemporary_design"
    WARM_LIGHT = "warm_light"
    VIVID_COLOR = "vivid_color"
    NIGHT_LIGHTING = "night_lighting"


MOOD_LABELS = {
    VisualMoodDimension.GREENERY: "초록 식물이 보이는 풍경",
    VisualMoodDimension.WATER: "물이 보이는 풍경",
    VisualMoodDimension.OPEN_COMPOSITION: "시야가 트여 보이는 구도",
    VisualMoodDimension.TRADITIONAL_APPEARANCE: "전통적으로 보이는 외관",
    VisualMoodDimension.CONTEMPORARY_DESIGN: "현대적으로 보이는 디자인",
    VisualMoodDimension.WARM_LIGHT: "따뜻한 빛의 색감",
    VisualMoodDimension.VIVID_COLOR: "선명한 색감",
    VisualMoodDimension.NIGHT_LIGHTING: "밤 조명이 보이는 장면",
}
MOOD_RUBRIC = {
    "version": VISUAL_MOOD_VERSION,
    "levels": {
        "0": "직접 보이는 해당 시각 요소가 매우 약함",
        "1": "약함",
        "2": "보통",
        "3": "강함",
        "4": "장면을 지배함",
    },
    "unknown": "이미지에서 직접 판단할 수 없거나 확신이 낮으면 UNKNOWN/null/LOW",
    "scope": (
        "사진의 외관·빛·색·구도만 평가. 실제 혼잡, 인원 수, 복잡도, 운영, 시설, "
        "역사적 진위, 활동, 체류, OCR 금지."
    ),
    "dimensions": {dimension.value: label for dimension, label in MOOD_LABELS.items()},
}
MOOD_POLICY_SHA256 = canonical_sha256(MOOD_RUBRIC)


class MoodObservation(StrictContract):
    dimension: VisualMoodDimension
    state: Literal["OBSERVED", "UNKNOWN"]
    level: Annotated[int, Field(strict=True, ge=0, le=4)] | None
    certainty: Literal["HIGH", "LOW"]

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        if self.state == "UNKNOWN" and (self.level is not None or self.certainty != "LOW"):
            raise ValueError("unknown appearance requires null and low certainty")
        if self.state == "OBSERVED" and (self.level is None or self.certainty != "HIGH"):
            raise ValueError("observed appearance requires direct high-certainty support")
        return self


class MoodWireResponse(StrictContract):
    observations: Annotated[tuple[MoodObservation, ...], Field(min_length=8, max_length=8)]

    @model_validator(mode="after")
    def full_vocabulary(self) -> Self:
        if {row.dimension for row in self.observations} != set(VisualMoodDimension):
            raise ValueError("appearance response must cover the exact closed vocabulary")
        return self


class PhotoMoodCandidate(StrictContract):
    candidate_id: Sha256
    observation: MoodObservation


class PhotoMoodCandidateSet(StrictContract):
    schema_version: Literal["photo-mood-candidates.v1"] = "photo-mood-candidates.v1"
    family: Literal["photo-mood-v1"] = PHOTO_MOOD_FAMILY
    mood_version: Literal["visual-mood-v1"] = VISUAL_MOOD_VERSION
    authority_scope: Literal["VISUAL_MOOD_ONLY"] = "VISUAL_MOOD_ONLY"
    job_id: Sha256
    image_index: Annotated[int, Field(strict=True, ge=1, le=3)]
    payload_sha256: Sha256
    policy_sha256: Sha256
    provider_id: Annotated[str, Field(min_length=1, max_length=100)]
    analysis_kind: Literal["MODEL", "SYNTHETIC"]
    model: Literal["glm-5.3-flash"] | None
    candidates: Annotated[tuple[PhotoMoodCandidate, ...], Field(min_length=8, max_length=8)]
    candidate_set_sha256: Sha256

    @model_validator(mode="after")
    def validate_set(self) -> Self:
        if self.policy_sha256 != MOOD_POLICY_SHA256:
            raise ValueError("unknown appearance policy")
        if tuple(row.observation.dimension for row in self.candidates) != tuple(
            VisualMoodDimension
        ):
            raise ValueError("appearance candidates require canonical order")
        if self.analysis_kind == "SYNTHETIC":
            if self.model is not None or any(
                row.observation.state != "UNKNOWN" for row in self.candidates
            ):
                raise ValueError("synthetic mode has no visual inference authority")
        elif self.model != "glm-5.3-flash" or "synthetic" in self.provider_id.casefold():
            raise ValueError("appearance model provenance invalid")
        for row in self.candidates:
            expected = canonical_sha256(
                {
                    "job_id": self.job_id,
                    "image": self.payload_sha256,
                    "observation": row.observation.model_dump(mode="json"),
                    "provider_id": self.provider_id,
                    "policy_sha256": self.policy_sha256,
                }
            )
            if row.candidate_id != expected:
                raise ValueError("appearance candidate identity invalid")
        if self.candidate_set_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"candidate_set_sha256"})
        ):
            raise ValueError("appearance candidate digest invalid")
        return self


class ProjectedMood(StrictContract):
    dimension: VisualMoodDimension
    value: Annotated[int, Field(strict=True, ge=0, le=100)] | None
    distinct_images: Annotated[int, Field(strict=True, ge=0, le=3)]
    candidate_ids: tuple[Sha256, ...]

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if (self.value is None) != (self.distinct_images == 0):
            raise ValueError("unknown appearance cannot be scored")
        if self.candidate_ids != tuple(sorted(set(self.candidate_ids))):
            raise ValueError("appearance references must be canonical")
        if self.distinct_images != len(self.candidate_ids):
            raise ValueError("appearance projection needs one candidate per distinct image")
        return self


class MoodChoice(StrictContract):
    candidate_id: Sha256
    included: StrictBool


class PhotoMoodConfirmRequest(StrictContract):
    draft_sha256: Sha256
    choices: Annotated[tuple[MoodChoice, ...], Field(max_length=24)]


class ConfirmedMoodProjection(StrictContract):
    schema_version: Literal["photo-mood-projection.v1"] = "photo-mood-projection.v1"
    family: Literal["photo-mood-v1"] = PHOTO_MOOD_FAMILY
    job_id: Sha256
    preference_profile_id: StableId
    policy_sha256: Sha256
    draft_sha256: Sha256
    candidate_set_sha256: tuple[Sha256, ...]
    choices: tuple[MoodChoice, ...]
    moods: Annotated[tuple[ProjectedMood, ...], Field(min_length=8, max_length=8)]
    receipt_id: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.policy_sha256 != MOOD_POLICY_SHA256:
            raise ValueError("unknown mood projection policy")
        if tuple(row.dimension for row in self.moods) != tuple(VisualMoodDimension):
            raise ValueError("mood projection order invalid")
        if self.candidate_set_sha256 != tuple(sorted(set(self.candidate_set_sha256))):
            raise ValueError("mood batch hashes must be canonical")
        if tuple(row.candidate_id for row in self.choices) != tuple(
            sorted({row.candidate_id for row in self.choices})
        ):
            raise ValueError("mood choices must be canonical")
        if self.receipt_id != canonical_sha256(
            self.model_dump(mode="json", exclude={"receipt_id"})
        ):
            raise ValueError("mood receipt hash invalid")
        return self


class PhotoMoodReview(StrictContract):
    schema_version: Literal["photo-mood-review.v1"] = "photo-mood-review.v1"
    family: Literal["photo-mood-v1"] = PHOTO_MOOD_FAMILY
    job_id: Sha256
    preference_profile_id: StableId
    draft_sha256: Sha256
    batches: Annotated[tuple[PhotoMoodCandidateSet, ...], Field(max_length=3)]
    confirmation: ConfirmedMoodProjection | None = None
