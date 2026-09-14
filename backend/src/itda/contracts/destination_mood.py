"""Immutable destination appearance, kept outside all experience/factual scores."""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.source_assessment import ClaimKind, PlaceMatch, SourceEvidence, SourceReceipt
from itda.contracts.visual_mood import (
    MOOD_POLICY_SHA256,
    PhotoMoodCandidateSet,
    ProjectedMood,
    VisualMoodDimension,
)
from itda.domain.canonical import canonical_sha256
from itda.domain.visual_mood import aggregate_moods

Season = Literal["SPRING", "SUMMER", "AUTUMN", "WINTER", "UNKNOWN"]
LightContext = Literal["DAY", "NIGHT", "UNKNOWN"]


class DestinationImageDecision(StrictContract):
    asset_id: StableId
    original_sha256: Sha256
    license: Literal["KOGL_TYPE_1", "KOGL_TYPE_3", "UNKNOWN"]
    receipt: SourceReceipt
    match: PlaceMatch
    capture_date: date | None = None
    capture_month: Annotated[str, Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")] | None = None
    decision: Literal[
        "ANALYZED",
        "RIGHTS_EXCLUDED",
        "SOURCE_UNAVAILABLE",
        "MATCH_REJECTED",
        "TEMPORARY_EVENT_EXCLUDED",
        "PREPROCESSING_FAILED",
        "LOW_QUALITY",
        "EXACT_DUPLICATE",
        "PERCEPTUAL_DUPLICATE",
        "SCENE_ALTERNATE",
        "CAPACITY_EXCLUDED",
        "MODEL_UNAVAILABLE",
        "MODEL_REJECTED",
    ]
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    duplicate_of_asset_id: StableId | None = None
    sanitized_sha256: Sha256 | None = None
    perceptual_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")] | None = None
    quality_score_milli: Annotated[int, Field(ge=0, le=1000)] | None = None
    season: Season = "UNKNOWN"
    light_context: LightContext = "UNKNOWN"


class DestinationMoodImage(StrictContract):
    asset_id: StableId
    original_sha256: Sha256
    sanitized_sha256: Sha256
    preprocessing_policy_sha256: Sha256
    preprocessing_audit_sha256: Sha256
    capture_date: date | None = None
    capture_month: Annotated[str, Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")] | None = None
    season: Season = "UNKNOWN"
    light_context: LightContext = "UNKNOWN"
    scene_group: Annotated[str, Field(min_length=1, max_length=200)]
    attribution_ko: Annotated[str, Field(min_length=1, max_length=500)]
    evidence: SourceEvidence
    candidate_set: PhotoMoodCandidateSet

    @model_validator(mode="after")
    def validate_image(self) -> Self:
        if (
            self.evidence.modality != "IMAGE_PIXELS"
            or self.evidence.image_sha256 != self.original_sha256
            or not self.evidence.authorizes(ClaimKind.VISUAL_MOOD)
            or self.candidate_set.payload_sha256 != self.sanitized_sha256
        ):
            raise ValueError("destination image provenance differs from analyzed pixels")
        if (
            self.capture_date
            and self.capture_month
            and self.capture_date.strftime("%Y-%m") != self.capture_month
        ):
            raise ValueError("photo capture date and month disagree")
        return self


class DestinationMoodStratum(StrictContract):
    season: Season
    light_context: LightContext
    asset_ids: tuple[StableId, ...]
    moods: Annotated[tuple[ProjectedMood, ...], Field(min_length=8, max_length=8)]

    @model_validator(mode="after")
    def validate_stratum(self) -> Self:
        if self.asset_ids != tuple(sorted(set(self.asset_ids))) or not self.asset_ids:
            raise ValueError("appearance strata require canonical nonempty image members")
        if tuple(mood.dimension for mood in self.moods) != tuple(VisualMoodDimension):
            raise ValueError("appearance stratum vocabulary differs")
        return self


class DestinationMoodBundle(StrictContract):
    schema_version: Literal["destination-mood.v1"] = "destination-mood.v1"
    authority_scope: Literal["VISUAL_MOOD_ONLY"] = "VISUAL_MOOD_ONLY"
    place_id: StableId
    raw_profile_sha256: Sha256
    source_release_sha256: Sha256
    assessed_at: datetime
    mood_policy_sha256: Sha256
    selection_policy_sha256: Sha256
    images: Annotated[tuple[DestinationMoodImage, ...], Field(max_length=3)]
    decisions: tuple[DestinationImageDecision, ...]
    strata: tuple[DestinationMoodStratum, ...]
    limit_ko: Annotated[str, Field(min_length=1, max_length=600)]
    bundle_sha256: Sha256

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        require_utc(self.assessed_at, field_name="assessed_at")
        if self.mood_policy_sha256 != MOOD_POLICY_SHA256:
            raise ValueError("destination mood policy is not current")
        image_ids = tuple(image.asset_id for image in self.images)
        if image_ids != tuple(sorted(set(image_ids))):
            raise ValueError("destination images must be unique and canonical")
        if tuple(d.asset_id for d in self.decisions) != tuple(
            sorted({d.asset_id for d in self.decisions})
        ):
            raise ValueError("destination selection decisions must be canonical")
        if {d.asset_id for d in self.decisions if d.decision == "ANALYZED"} != set(image_ids):
            raise ValueError("image decisions disagree with actual model analysis")
        if len({image.original_sha256 for image in self.images}) != len(self.images):
            raise ValueError("duplicate originals cannot add mood weight")
        if len({image.scene_group for image in self.images}) != len(self.images):
            raise ValueError("each selected scene has equal one-image weight")
        expected_job = canonical_sha256(
            {
                "scope": "destination-mood.v1",
                "place_id": self.place_id,
                "raw_profile_sha256": self.raw_profile_sha256,
                "source_release_sha256": self.source_release_sha256,
                "selection_policy_sha256": self.selection_policy_sha256,
            }
        )
        decisions = {decision.asset_id: decision for decision in self.decisions}
        for image in self.images:
            if (
                image.evidence.place_match is None
                or image.evidence.place_match.place_id != self.place_id
            ):
                raise ValueError("destination pixels belong to another place")
            decision = decisions[image.asset_id]
            if (
                image.candidate_set.job_id != expected_job
                or decision.original_sha256 != image.original_sha256
                or decision.sanitized_sha256 != image.sanitized_sha256
                or decision.receipt != image.evidence.receipt
                or decision.match != image.evidence.place_match
                or decision.season != image.season
                or decision.light_context != image.light_context
            ):
                raise ValueError("destination image and decision authority differ")
        keys = tuple((row.season, row.light_context) for row in self.strata)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("appearance strata require canonical unique contexts")
        groups: dict[tuple[str, str], list[DestinationMoodImage]] = {}
        for image in self.images:
            groups.setdefault((image.season, image.light_context), []).append(image)
        if set(groups) != set(keys):
            raise ValueError("appearance strata do not cover the selected images")
        for stratum in self.strata:
            selected = groups[(stratum.season, stratum.light_context)]
            if stratum.asset_ids != tuple(sorted(image.asset_id for image in selected)):
                raise ValueError("appearance stratum members differ")
            if stratum.moods != aggregate_moods(tuple(image.candidate_set for image in selected)):
                raise ValueError("appearance aggregate differs from image observations")
        if self.bundle_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"bundle_sha256"})
        ):
            raise ValueError("destination mood bundle hash differs")
        return self
