"""Public v5 results preserve nullable evidence instead of projecting legacy scores."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_run import GroundedRecommendationItem, GroundedRecommendationRun
from itda.contracts.source_assessment import AssessmentBundle


class GroundedReleaseDisclosure(StrictContract):
    model: Literal["glm-5.3-flash"] = "glm-5.3-flash"
    raw_release_sha256: Sha256
    source_release_sha256: Sha256
    assessment_manifest_sha256: Sha256
    candidate_sha256: Sha256
    config_sha256: Sha256
    scoring_policy: Literal["SUPPORTED_SUBORDINATE_AGGREGATION"] = (
        "SUPPORTED_SUBORDINATE_AGGREGATION"
    )
    image_policy: Literal["VISUAL_MOOD_ONLY"] = "VISUAL_MOOD_ONLY"


class GroundedResultsResponse(StrictContract):
    schema_version: Literal["itda.grounded-recommendation-results.v1"] = (
        "itda.grounded-recommendation-results.v1"
    )
    preference_profile_id: StableId
    run: GroundedRecommendationRun
    release_disclosure: GroundedReleaseDisclosure

    @model_validator(mode="after")
    def validate_disclosure(self) -> Self:
        if self.preference_profile_id != self.run.preference.profile_id:
            raise ValueError("result preference ownership mismatch")
        authority = self.run.authority
        disclosure = self.release_disclosure
        if (
            disclosure.raw_release_sha256 != authority.release_sha256
            or disclosure.source_release_sha256 != authority.source_release_sha256
            or disclosure.assessment_manifest_sha256 != authority.assessment_manifest_sha256
            or disclosure.config_sha256 != authority.config_sha256
            or disclosure.candidate_sha256 != authority.candidate_sha256
        ):
            raise ValueError("public result disclosure differs from pinned authority")
        return self


class GroundedDetailResponse(StrictContract):
    schema_version: Literal["itda.grounded-recommendation-detail.v1"] = (
        "itda.grounded-recommendation-detail.v1"
    )
    recommendation_run_id: StableId
    release_sha256: Sha256
    item: GroundedRecommendationItem
    assessment: AssessmentBundle
    mood: DestinationMoodBundle

    @model_validator(mode="after")
    def validate_detail(self) -> Self:
        if (
            self.item.place_id != self.assessment.place_id
            or self.item.place_id != self.mood.place_id
            or self.item.assessment_bundle_sha256 != self.assessment.bundle_sha256
            or self.item.raw_profile_sha256 != self.assessment.raw_profile_sha256
            or self.item.raw_profile_sha256 != self.mood.raw_profile_sha256
            or self.assessment.source_release_sha256 != self.mood.source_release_sha256
        ):
            raise ValueError("detail does not match pinned place assessment/mood")
        return self


class GroundedComparisonResponse(StrictContract):
    schema_version: Literal["itda.grounded-recommendation-comparison.v1"] = (
        "itda.grounded-recommendation-comparison.v1"
    )
    recommendation_run_id: StableId
    release_sha256: Sha256
    places: Annotated[tuple[GroundedDetailResponse, ...], Field(min_length=2, max_length=3)]

    @model_validator(mode="after")
    def validate_comparison(self) -> Self:
        if len({p.item.place_id for p in self.places}) != len(self.places) or any(
            p.recommendation_run_id != self.recommendation_run_id
            or p.release_sha256 != self.release_sha256
            for p in self.places
        ):
            raise ValueError("comparison contains foreign or duplicate pinned places")
        return self


class RecommendationRegion(StrictContract):
    region_code: Annotated[str, Field(pattern=r"^\d{2}$")]
    region_name: Annotated[str, Field(min_length=1, max_length=100)]
    place_count: Annotated[int, Field(strict=True, ge=1, le=1000)]


class RecommendationRegionsResponse(StrictContract):
    candidate_sha256: Sha256 | None
    regions: tuple[RecommendationRegion, ...]

    @model_validator(mode="after")
    def validate_regions(self) -> Self:
        codes = tuple(row.region_code for row in self.regions)
        if codes != tuple(sorted(set(codes))) or (self.regions and self.candidate_sha256 is None):
            raise ValueError("regions require unique active catalog membership")
        return self
