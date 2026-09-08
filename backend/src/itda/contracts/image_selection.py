"""Canonical rights-first representative-image selection contracts."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    RightsBoundImage,
)
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.domain.canonical import canonical_sha256

IMAGE_SELECTION_SCHEMA_VERSION = "itda.image-selection-manifest.v1"
IMAGE_SELECTION_POLICY_VERSION = "phase4-image-selection-v1"
PINNED_SIGLIP2_MODEL_ID = "google/siglip2-base-patch16-224"
PINNED_SIGLIP2_REVISION = "02c35f2c035e0ed4a367fb10a892c1fe2a3f364e"
ZERO_SELECTION_REASON = "NO_SELECTION_ELIGIBLE_ASSETS"


class SelectionAuthorityScope(StrEnum):
    """Capability scope without exposing evaluation membership."""

    SYNTHETIC_LOCAL = "SYNTHETIC_LOCAL"
    AUTHORIZED_CALIBRATION = "AUTHORIZED_CALIBRATION"


class TemporaryEventRule(StrEnum):
    EXCLUDE = "EXCLUDE"
    DOWNWEIGHT = "DOWNWEIGHT"


class AssetDecisionCode(StrEnum):
    PREPROCESSING_FAILED = "PREPROCESSING_FAILED"
    LOW_QUALITY = "LOW_QUALITY"
    SEVERE_CROP = "SEVERE_CROP"
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    PERCEPTUAL_DUPLICATE = "PERCEPTUAL_DUPLICATE"
    TEMPORARY_EVENT_EXCLUDED = "TEMPORARY_EVENT_EXCLUDED"
    SCENE_ALTERNATE = "SCENE_ALTERNATE"
    REPRESENTATIVE = "REPRESENTATIVE"


class ImageSelectionPolicy(StrictContract):
    schema_version: Literal["itda.image-selection-policy.v1"]
    policy_version: Literal["phase4-image-selection-v1"]
    sensitivity_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._-]*$"),
    ]
    release_eligible: Literal[False]
    model_id: Literal["google/siglip2-base-patch16-224"]
    model_revision: Literal["02c35f2c035e0ed4a367fb10a892c1fe2a3f364e"]
    model_weight_sha256: Sha256
    preprocessing_policy_sha256: Sha256
    minimum_short_side: Annotated[int, Field(strict=True, ge=1, le=4_096)]
    minimum_aspect_ratio_milli: Annotated[int, Field(strict=True, ge=1, le=1_000)]
    maximum_aspect_ratio_milli: Annotated[int, Field(strict=True, ge=1_000, le=20_000)]
    perceptual_hash_distance: Annotated[int, Field(strict=True, ge=0, le=64)]
    scene_distance_milli: Annotated[int, Field(strict=True, ge=0, le=2_000)]
    temporary_event_rule: TemporaryEventRule
    temporary_event_quality_factor_milli: Annotated[int, Field(strict=True, ge=1, le=1_000)]
    max_representatives: Literal[5]
    policy_sha256: Sha256

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if self.minimum_aspect_ratio_milli >= self.maximum_aspect_ratio_milli:
            raise ValueError("selection aspect-ratio bounds are inverted")
        expected = canonical_sha256(self.model_dump(exclude={"policy_sha256"}, mode="json"))
        if self.policy_sha256 != expected:
            raise ValueError("image selection policy digest is stale")
        return self


def build_image_selection_policy(
    *,
    sensitivity_id: str,
    model_weight_sha256: str,
    preprocessing_policy_sha256: str,
    minimum_short_side: int,
    minimum_aspect_ratio_milli: int,
    maximum_aspect_ratio_milli: int,
    perceptual_hash_distance: int,
    scene_distance_milli: int,
    temporary_event_rule: TemporaryEventRule | str,
    temporary_event_quality_factor_milli: int = 600,
) -> ImageSelectionPolicy:
    fields = {
        "schema_version": "itda.image-selection-policy.v1",
        "policy_version": IMAGE_SELECTION_POLICY_VERSION,
        "sensitivity_id": sensitivity_id,
        "release_eligible": False,
        "model_id": PINNED_SIGLIP2_MODEL_ID,
        "model_revision": PINNED_SIGLIP2_REVISION,
        "model_weight_sha256": model_weight_sha256,
        "preprocessing_policy_sha256": preprocessing_policy_sha256,
        "minimum_short_side": minimum_short_side,
        "minimum_aspect_ratio_milli": minimum_aspect_ratio_milli,
        "maximum_aspect_ratio_milli": maximum_aspect_ratio_milli,
        "perceptual_hash_distance": perceptual_hash_distance,
        "scene_distance_milli": scene_distance_milli,
        "temporary_event_rule": TemporaryEventRule(temporary_event_rule),
        "temporary_event_quality_factor_milli": temporary_event_quality_factor_milli,
        "max_representatives": 5,
    }
    return ImageSelectionPolicy.model_validate(
        {**fields, "policy_sha256": canonical_sha256(fields)}
    )


class SelectionAssetSource(StrictContract):
    """Digest-only candidate authority; the relative path never enters outputs."""

    source_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    relative_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    rights_leaf_id: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    rights_leaf_sha256: Sha256
    content_sha256: Sha256
    materialization_sha256: Sha256
    temporary_event: Annotated[bool, Field(strict=True)]

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        path = PurePosixPath(self.relative_path)
        if (
            self.relative_path != path.as_posix()
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in self.relative_path
            or "\x00" in self.relative_path
        ):
            raise ValueError("image path must be a safe normalized relative path")
        RightsBoundImage(
            relative_path=self.relative_path,
            rights_leaf_id=self.rights_leaf_id,
            rights_leaf_sha256=self.rights_leaf_sha256,
            content_sha256=self.content_sha256,
        )
        ApprovedImageMaterialization(
            rights_leaf_id=self.rights_leaf_id,
            rights_leaf_sha256=self.rights_leaf_sha256,
            content_sha256=self.content_sha256,
            materialization_sha256=self.materialization_sha256,
        )
        return self


class PlaceImageSelectionCandidate(StrictContract):
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    authority_scope: SelectionAuthorityScope
    input_authority_sha256: Sha256
    media_state: ImageMediumState
    assets: tuple[SelectionAssetSource, ...]

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if not isinstance(self.media_state, ImageMediumState):
            raise TypeError("media state must use the exact ImageMediumState contract")
        asset_ids = tuple(asset.source_asset_id for asset in self.assets)
        if len(set(asset_ids)) != len(asset_ids):
            raise ValueError("selection source asset IDs must be unique")
        if self.media_state is not ImageMediumState.QUALIFIED and self.assets:
            raise ValueError("non-qualified selection candidate must remain fact-free")
        return self

    def recompute_input_sha256(self) -> str:
        payload = self.model_dump(mode="json")
        payload["assets"] = sorted(
            payload["assets"],
            key=lambda asset: asset["source_asset_id"],
        )
        return canonical_sha256(payload)


class AssetDecisionTrace(StrictContract):
    source_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    input_media_state: ImageMediumState
    decision_code: AssetDecisionCode
    rights_leaf_id: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    rights_leaf_sha256: Sha256
    materialization_sha256: Sha256
    preprocessing_policy_sha256: Sha256 | None = None
    asset_sha256: Sha256 | None = None
    perceptual_hash: Annotated[str | None, Field(strict=True, pattern=r"^[0-9a-f]{16}$")] = None
    quality_score_milli: Annotated[int | None, Field(strict=True, ge=0, le=1_000)] = None
    crop_quality_milli: Annotated[int | None, Field(strict=True, ge=0, le=1_000)] = None
    temporary_event: Annotated[bool, Field(strict=True)]
    duplicate_of_asset_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=160)
    ] = None
    scene_group_id: Sha256 | None = None
    representative_id: Sha256 | None = None
    decision_trace_sha256: Sha256

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        duplicate_codes = {
            AssetDecisionCode.EXACT_DUPLICATE,
            AssetDecisionCode.PERCEPTUAL_DUPLICATE,
        }
        if (self.decision_code in duplicate_codes) != (self.duplicate_of_asset_id is not None):
            raise ValueError("duplicate decision linkage does not match its reason")
        if self.decision_code is AssetDecisionCode.REPRESENTATIVE:
            if self.representative_id is None or self.scene_group_id is None:
                raise ValueError("representative decision requires representative and scene IDs")
        elif self.representative_id is not None:
            raise ValueError("rejected asset cannot carry a representative ID")
        if self.decision_code is AssetDecisionCode.SCENE_ALTERNATE:
            if self.scene_group_id is None:
                raise ValueError("scene alternate requires its exact scene group")
        elif (
            self.decision_code is not AssetDecisionCode.REPRESENTATIVE
            and self.scene_group_id is not None
        ):
            raise ValueError("pre-scene rejection cannot carry a scene group")
        expected = canonical_sha256(self.model_dump(exclude={"decision_trace_sha256"}, mode="json"))
        if self.decision_trace_sha256 != expected:
            raise ValueError("asset decision trace digest is stale")
        return self


class SceneGroup(StrictContract):
    scene_group_id: Sha256
    member_asset_ids: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...]
    representative_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]

    @model_validator(mode="after")
    def validate_group(self) -> Self:
        if (
            not self.member_asset_ids
            or self.member_asset_ids != tuple(sorted(self.member_asset_ids))
            or len(set(self.member_asset_ids)) != len(self.member_asset_ids)
            or self.representative_asset_id not in self.member_asset_ids
        ):
            raise ValueError("scene group membership is not canonical")
        return self


class SelectedRepresentative(StrictContract):
    representative_id: Sha256
    source_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    scene_group_id: Sha256
    asset_sha256: Sha256
    normalized_pixel_sha256: Sha256
    rights_leaf_id: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    rights_leaf_sha256: Sha256
    materialization_sha256: Sha256
    preprocessing_policy_sha256: Sha256
    quality_score_milli: Annotated[int, Field(strict=True, ge=0, le=1_000)]
    temporary_event: Annotated[bool, Field(strict=True)]


class ImageSelectionManifest(StrictContract):
    schema_version: Literal["itda.image-selection-manifest.v1"]
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    authority_scope: SelectionAuthorityScope
    input_authority_sha256: Sha256
    input_candidate_sha256: Sha256
    media_state: ImageMediumState
    zero_image_reason: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)] = None
    selection_policy_sha256: Sha256
    preprocessing_policy_sha256: Sha256
    model_id: Literal["google/siglip2-base-patch16-224"]
    model_revision: Literal["02c35f2c035e0ed4a367fb10a892c1fe2a3f364e"]
    model_weight_sha256: Sha256
    asset_decisions: tuple[AssetDecisionTrace, ...]
    scene_groups: tuple[SceneGroup, ...]
    representatives: tuple[SelectedRepresentative, ...] = Field(max_length=5)
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        decision_ids = tuple(decision.source_asset_id for decision in self.asset_decisions)
        if decision_ids != tuple(sorted(decision_ids)) or len(set(decision_ids)) != len(
            decision_ids
        ):
            raise ValueError("asset decisions require unique canonical order")
        representative_ids = tuple(item.source_asset_id for item in self.representatives)
        if len(set(representative_ids)) != len(representative_ids):
            raise ValueError("representatives must be unique")
        if self.media_state is not ImageMediumState.QUALIFIED:
            if self.zero_image_reason != self.media_state.value:
                raise ValueError("terminal image state must be preserved as the zero-image reason")
            if self.asset_decisions or self.scene_groups or self.representatives:
                raise ValueError("terminal image selection manifest must remain fact-free")
        elif self.representatives:
            if self.zero_image_reason is not None:
                raise ValueError("selected representatives cannot carry a zero-image reason")
        elif self.zero_image_reason != ZERO_SELECTION_REASON:
            raise ValueError("qualified zero-image manifest requires an explicit reason")
        decisions_by_id = {decision.source_asset_id: decision for decision in self.asset_decisions}
        groups_by_id = {group.scene_group_id: group for group in self.scene_groups}
        if len(groups_by_id) != len(self.scene_groups):
            raise ValueError("scene group IDs must be unique")
        grouped_ids = tuple(
            member_id for group in self.scene_groups for member_id in group.member_asset_ids
        )
        if len(set(grouped_ids)) != len(grouped_ids):
            raise ValueError("an accepted asset cannot belong to multiple scene groups")
        for group in self.scene_groups:
            for member_id in group.member_asset_ids:
                decision = decisions_by_id.get(member_id)
                if decision is None or decision.scene_group_id != group.scene_group_id:
                    raise ValueError("scene group member is not bound to one final decision")
        representatives_by_id = {
            representative.source_asset_id: representative
            for representative in self.representatives
        }
        for source_asset_id, representative in representatives_by_id.items():
            decision = decisions_by_id.get(source_asset_id)
            if (
                decision is None
                or decision.decision_code is not AssetDecisionCode.REPRESENTATIVE
                or decision.representative_id != representative.representative_id
                or decision.scene_group_id != representative.scene_group_id
                or decision.asset_sha256 != representative.asset_sha256
            ):
                raise ValueError("representative is not bound to one accepted asset decision")
        decision_representatives = {
            decision.source_asset_id
            for decision in self.asset_decisions
            if decision.decision_code is AssetDecisionCode.REPRESENTATIVE
        }
        if decision_representatives != set(representatives_by_id):
            raise ValueError("representative decision inventory does not match representatives")
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 != expected:
            raise ValueError("image selection manifest digest is stale")
        return self


class ImageSelectionBatchInput(StrictContract):
    schema_version: Literal["itda.image-selection-input.v1"]
    authority_scope: SelectionAuthorityScope
    input_authority_sha256: Sha256
    places: tuple[PlaceImageSelectionCandidate, ...] = Field(min_length=1)
    input_manifest_sha256: Sha256

    @classmethod
    def build(
        cls,
        *,
        authority_scope: SelectionAuthorityScope,
        input_authority_sha256: str,
        places: tuple[PlaceImageSelectionCandidate, ...],
    ) -> ImageSelectionBatchInput:
        ordered = tuple(sorted(places, key=lambda place: place.place_entity_id))
        fields = {
            "schema_version": "itda.image-selection-input.v1",
            "authority_scope": authority_scope,
            "input_authority_sha256": input_authority_sha256,
            "places": [place.model_dump(mode="json") for place in ordered],
        }
        return cls.model_validate({**fields, "input_manifest_sha256": canonical_sha256(fields)})

    @model_validator(mode="after")
    def validate_batch(self) -> Self:
        place_ids = tuple(place.place_entity_id for place in self.places)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != len(place_ids):
            raise ValueError("selection input places require unique canonical order")
        if any(
            place.authority_scope is not self.authority_scope
            or place.input_authority_sha256 != self.input_authority_sha256
            for place in self.places
        ):
            raise ValueError("selection input place authority does not match its batch")
        expected = canonical_sha256(self.model_dump(exclude={"input_manifest_sha256"}, mode="json"))
        if self.input_manifest_sha256 != expected:
            raise ValueError("selection input manifest digest is stale")
        return self


class ImageSelectionBatchManifest(StrictContract):
    schema_version: Literal["itda.image-selection-batch.v1"]
    input_manifest_sha256: Sha256
    selection_policy_sha256: Sha256
    manifests: tuple[ImageSelectionManifest, ...] = Field(min_length=1)
    batch_sha256: Sha256

    @classmethod
    def build(
        cls,
        *,
        input_manifest_sha256: str,
        selection_policy_sha256: str,
        manifests: tuple[ImageSelectionManifest, ...],
    ) -> ImageSelectionBatchManifest:
        ordered = tuple(sorted(manifests, key=lambda manifest: manifest.place_entity_id))
        fields = {
            "schema_version": "itda.image-selection-batch.v1",
            "input_manifest_sha256": input_manifest_sha256,
            "selection_policy_sha256": selection_policy_sha256,
            "manifests": [manifest.model_dump(mode="json") for manifest in ordered],
        }
        return cls.model_validate({**fields, "batch_sha256": canonical_sha256(fields)})

    @model_validator(mode="after")
    def validate_batch(self) -> Self:
        place_ids = tuple(manifest.place_entity_id for manifest in self.manifests)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != len(place_ids):
            raise ValueError("selection output places require unique canonical order")
        if any(
            manifest.selection_policy_sha256 != self.selection_policy_sha256
            for manifest in self.manifests
        ):
            raise ValueError("selection output mixes policy digests")
        expected = canonical_sha256(self.model_dump(exclude={"batch_sha256"}, mode="json"))
        if self.batch_sha256 != expected:
            raise ValueError("selection output batch digest is stale")
        return self


__all__ = [
    "AssetDecisionCode",
    "AssetDecisionTrace",
    "IMAGE_SELECTION_POLICY_VERSION",
    "IMAGE_SELECTION_SCHEMA_VERSION",
    "ImageSelectionManifest",
    "ImageSelectionBatchInput",
    "ImageSelectionBatchManifest",
    "ImageSelectionPolicy",
    "PINNED_SIGLIP2_MODEL_ID",
    "PINNED_SIGLIP2_REVISION",
    "PlaceImageSelectionCandidate",
    "SceneGroup",
    "SelectedRepresentative",
    "SelectionAssetSource",
    "SelectionAuthorityScope",
    "TemporaryEventRule",
    "ZERO_SELECTION_REASON",
    "build_image_selection_policy",
]
