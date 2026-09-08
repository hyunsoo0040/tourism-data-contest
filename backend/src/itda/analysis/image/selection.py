"""Deterministic rights, quality, event, and duplicate selection gates."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from io import BytesIO
from typing import Protocol

import imagehash
from PIL import Image

from itda.analysis.image.preprocessing import (
    DEFAULT_IMAGE_PREPROCESSING_POLICY,
    ImagePreprocessingCandidate,
    ImagePreprocessingPolicy,
    ImageProjection,
    preprocess_image,
)
from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    RightsBoundImage,
)
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_selection import (
    IMAGE_SELECTION_SCHEMA_VERSION,
    PINNED_SIGLIP2_MODEL_ID,
    PINNED_SIGLIP2_REVISION,
    ZERO_SELECTION_REASON,
    AssetDecisionCode,
    AssetDecisionTrace,
    ImageSelectionManifest,
    ImageSelectionPolicy,
    PlaceImageSelectionCandidate,
    SceneGroup,
    SelectedRepresentative,
    SelectionAssetSource,
    TemporaryEventRule,
)
from itda.domain.canonical import canonical_sha256


@dataclass(frozen=True, slots=True)
class GatedAsset:
    source: SelectionAssetSource
    projection: ImageProjection = field(repr=False)
    perceptual_hash: str
    quality_score_milli: int
    crop_quality_milli: int

    @property
    def source_asset_id(self) -> str:
        return self.source.source_asset_id


@dataclass(frozen=True, slots=True)
class AssetGatingResult:
    media_state: ImageMediumState
    zero_image_reason: str | None
    decisions: tuple[AssetDecisionTrace, ...]
    survivors: tuple[GatedAsset, ...]


class SceneEmbeddingEncoder(Protocol):
    model_id: str
    model_revision: str
    model_weight_sha256: str

    def encode(self, assets: tuple[GatedAsset, ...]) -> dict[str, tuple[float, ...]]:
        """Return one finite scene vector for each source asset ID."""
        ...


def _decision(
    source: SelectionAssetSource,
    code: AssetDecisionCode,
    *,
    policy: ImageSelectionPolicy,
    projection: ImageProjection | None = None,
    perceptual_hash: str | None = None,
    quality_score_milli: int | None = None,
    crop_quality_milli: int | None = None,
    duplicate_of_asset_id: str | None = None,
    scene_group_id: str | None = None,
    representative_id: str | None = None,
) -> AssetDecisionTrace:
    fields = {
        "source_asset_id": source.source_asset_id,
        "input_media_state": ImageMediumState.QUALIFIED,
        "decision_code": code,
        "rights_leaf_id": source.rights_leaf_id,
        "rights_leaf_sha256": source.rights_leaf_sha256,
        "materialization_sha256": source.materialization_sha256,
        "preprocessing_policy_sha256": (
            projection.preprocessing_policy_sha256 if projection is not None else None
        ),
        "asset_sha256": projection.asset_sha256 if projection is not None else None,
        "perceptual_hash": perceptual_hash,
        "quality_score_milli": quality_score_milli,
        "crop_quality_milli": crop_quality_milli,
        "temporary_event": source.temporary_event,
        "duplicate_of_asset_id": duplicate_of_asset_id,
        "scene_group_id": scene_group_id,
        "representative_id": representative_id,
    }
    return AssetDecisionTrace.model_validate(
        {**fields, "decision_trace_sha256": canonical_sha256(fields)}
    )


def _runtime_authority(
    source: SelectionAssetSource,
) -> tuple[RightsBoundImage, ApprovedImageMaterialization]:
    image = RightsBoundImage(
        relative_path=source.relative_path,
        rights_leaf_id=source.rights_leaf_id,
        rights_leaf_sha256=source.rights_leaf_sha256,
        content_sha256=source.content_sha256,
    )
    approved = ApprovedImageMaterialization(
        rights_leaf_id=source.rights_leaf_id,
        rights_leaf_sha256=source.rights_leaf_sha256,
        content_sha256=source.content_sha256,
        materialization_sha256=source.materialization_sha256,
    )
    return image, approved


def _quality(
    projection: ImageProjection,
    *,
    source: SelectionAssetSource,
    policy: ImageSelectionPolicy,
) -> tuple[int, int, int]:
    width, height = projection.width, projection.height
    short_side = min(width, height)
    aspect_ratio_milli = (width * 1_000 + height // 2) // height
    crop_quality_milli = (short_side * 1_000 + max(width, height) // 2) // max(width, height)
    quality_score_milli = min(
        1_000,
        (short_side * 1_000 + policy.minimum_short_side // 2) // policy.minimum_short_side,
    )
    quality_score_milli = (quality_score_milli * crop_quality_milli + 500) // 1_000
    if source.temporary_event and policy.temporary_event_rule is TemporaryEventRule.DOWNWEIGHT:
        quality_score_milli = (
            quality_score_milli * policy.temporary_event_quality_factor_milli + 500
        ) // 1_000
    return aspect_ratio_milli, crop_quality_milli, quality_score_milli


def _perceptual_hash(projection: ImageProjection) -> str:
    with Image.open(BytesIO(projection.encoded_bytes)) as image:
        return str(imagehash.phash(image.convert("RGB"), hash_size=8))


def _preferred(asset: GatedAsset) -> tuple[int, int, str, str]:
    return (
        int(asset.source.temporary_event),
        -asset.quality_score_milli,
        asset.projection.asset_sha256,
        asset.source.source_asset_id,
    )


def _components(
    assets: tuple[GatedAsset, ...],
    *,
    adjacent: Callable[[GatedAsset, GatedAsset], bool],
) -> tuple[tuple[GatedAsset, ...], ...]:
    remaining = {asset.source.source_asset_id: asset for asset in assets}
    groups: list[tuple[GatedAsset, ...]] = []
    while remaining:
        seed_id = min(remaining)
        pending = [remaining.pop(seed_id)]
        component: list[GatedAsset] = []
        while pending:
            current = pending.pop()
            component.append(current)
            linked = sorted(
                asset_id
                for asset_id, candidate in remaining.items()
                if adjacent(current, candidate)
            )
            for asset_id in linked:
                pending.append(remaining.pop(asset_id))
        groups.append(tuple(sorted(component, key=lambda item: item.source.source_asset_id)))
    return tuple(groups)


def gate_selection_assets(
    *,
    root_fd: int,
    candidate: PlaceImageSelectionCandidate,
    policy: ImageSelectionPolicy,
    preprocessing_policy: ImagePreprocessingPolicy | None = None,
) -> AssetGatingResult:
    """Apply D-01/D-02 gates without scene clustering or representative choice."""

    selected_preprocessing = preprocessing_policy or DEFAULT_IMAGE_PREPROCESSING_POLICY
    if selected_preprocessing.policy_sha256 != policy.preprocessing_policy_sha256:
        raise ValueError("selection policy does not bind the active preprocessing policy")
    if candidate.media_state is not ImageMediumState.QUALIFIED:
        return AssetGatingResult(
            media_state=candidate.media_state,
            zero_image_reason=candidate.media_state.value,
            decisions=(),
            survivors=(),
        )

    decisions: list[AssetDecisionTrace] = []
    quality_survivors: list[GatedAsset] = []
    for source in sorted(candidate.assets, key=lambda item: item.source_asset_id):
        image, approved = _runtime_authority(source)
        result = preprocess_image(
            root_fd=root_fd,
            candidate=ImagePreprocessingCandidate(
                media_state=ImageMediumState.QUALIFIED,
                image=image,
            ),
            approved=approved,
            policy=selected_preprocessing,
        )
        if result.media_state is not ImageMediumState.QUALIFIED or result.projection is None:
            decisions.append(
                _decision(source, AssetDecisionCode.PREPROCESSING_FAILED, policy=policy)
            )
            continue
        projection = result.projection
        aspect, crop, quality = _quality(projection, source=source, policy=policy)
        if min(projection.width, projection.height) < policy.minimum_short_side:
            decisions.append(
                _decision(
                    source,
                    AssetDecisionCode.LOW_QUALITY,
                    policy=policy,
                    projection=projection,
                    quality_score_milli=quality,
                    crop_quality_milli=crop,
                )
            )
            continue
        if not (policy.minimum_aspect_ratio_milli <= aspect <= policy.maximum_aspect_ratio_milli):
            decisions.append(
                _decision(
                    source,
                    AssetDecisionCode.SEVERE_CROP,
                    policy=policy,
                    projection=projection,
                    quality_score_milli=quality,
                    crop_quality_milli=crop,
                )
            )
            continue
        quality_survivors.append(
            GatedAsset(
                source=source,
                projection=projection,
                perceptual_hash=_perceptual_hash(projection),
                quality_score_milli=quality,
                crop_quality_milli=crop,
            )
        )

    exact_groups = _components(
        tuple(quality_survivors),
        adjacent=lambda left, right: (
            left.projection.source_content_sha256 == right.projection.source_content_sha256
        ),
    )
    exact_survivors: list[GatedAsset] = []
    for group in exact_groups:
        keeper = min(group, key=_preferred)
        exact_survivors.append(keeper)
        for rejected in group:
            if rejected is keeper:
                continue
            decisions.append(
                _decision(
                    rejected.source,
                    AssetDecisionCode.EXACT_DUPLICATE,
                    policy=policy,
                    projection=rejected.projection,
                    perceptual_hash=rejected.perceptual_hash,
                    quality_score_milli=rejected.quality_score_milli,
                    crop_quality_milli=rejected.crop_quality_milli,
                    duplicate_of_asset_id=keeper.source.source_asset_id,
                )
            )

    phash_groups = _components(
        tuple(exact_survivors),
        adjacent=lambda left, right: (
            (int(left.perceptual_hash, 16) ^ int(right.perceptual_hash, 16)).bit_count()
            <= policy.perceptual_hash_distance
        ),
    )
    perceptual_survivors: list[GatedAsset] = []
    for group in phash_groups:
        keeper = min(group, key=_preferred)
        perceptual_survivors.append(keeper)
        for rejected in group:
            if rejected is keeper:
                continue
            decisions.append(
                _decision(
                    rejected.source,
                    AssetDecisionCode.PERCEPTUAL_DUPLICATE,
                    policy=policy,
                    projection=rejected.projection,
                    perceptual_hash=rejected.perceptual_hash,
                    quality_score_milli=rejected.quality_score_milli,
                    crop_quality_milli=rejected.crop_quality_milli,
                    duplicate_of_asset_id=keeper.source.source_asset_id,
                )
            )

    survivors: list[GatedAsset] = []
    for asset in perceptual_survivors:
        if (
            asset.source.temporary_event
            and policy.temporary_event_rule is TemporaryEventRule.EXCLUDE
        ):
            decisions.append(
                _decision(
                    asset.source,
                    AssetDecisionCode.TEMPORARY_EVENT_EXCLUDED,
                    policy=policy,
                    projection=asset.projection,
                    perceptual_hash=asset.perceptual_hash,
                    quality_score_milli=asset.quality_score_milli,
                    crop_quality_milli=asset.crop_quality_milli,
                )
            )
        else:
            survivors.append(asset)

    ordered_survivors = tuple(sorted(survivors, key=lambda item: item.source.source_asset_id))
    return AssetGatingResult(
        media_state=ImageMediumState.QUALIFIED,
        zero_image_reason=ZERO_SELECTION_REASON if not ordered_survivors else None,
        decisions=tuple(sorted(decisions, key=lambda item: item.source_asset_id)),
        survivors=ordered_survivors,
    )


_EMBEDDING_SCALE = 1_000_000


def _quantize_embeddings(
    assets: tuple[GatedAsset, ...],
    encoder: SceneEmbeddingEncoder,
    policy: ImageSelectionPolicy,
) -> dict[str, tuple[int, ...]]:
    if (
        encoder.model_id != PINNED_SIGLIP2_MODEL_ID
        or encoder.model_revision != PINNED_SIGLIP2_REVISION
        or encoder.model_weight_sha256 != policy.model_weight_sha256
    ):
        raise ValueError("scene encoder identity does not match the selection policy")
    vectors = encoder.encode(assets)
    expected_ids = {asset.source_asset_id for asset in assets}
    if set(vectors) != expected_ids:
        raise ValueError("scene encoder output inventory does not match accepted assets")
    dimensions = {len(vector) for vector in vectors.values()}
    if len(dimensions) != 1 or not dimensions or next(iter(dimensions)) < 2:
        raise ValueError("scene embeddings require one stable dimension of at least two")
    normalized: dict[str, tuple[int, ...]] = {}
    for asset_id in sorted(vectors):
        vector = vectors[asset_id]
        if not all(math.isfinite(value) for value in vector):
            raise ValueError("scene embeddings must be finite")
        norm = math.sqrt(math.fsum(value * value for value in vector))
        if not math.isfinite(norm) or norm <= 0.0:
            raise ValueError("scene embeddings must have positive finite norm")
        quantized: list[int] = []
        for value in vector:
            scaled = (value / norm) * _EMBEDDING_SCALE
            quantized.append(
                int(math.floor(scaled + 0.5) if scaled >= 0 else math.ceil(scaled - 0.5))
            )
        normalized[asset_id] = tuple(quantized)
    return normalized


def _scene_distance_milli(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    dot = sum(left_value * right_value for left_value, right_value in zip(left, right, strict=True))
    scale_squared = _EMBEDDING_SCALE * _EMBEDDING_SCALE
    numerator = (scale_squared - dot) * 1_000
    distance = (numerator + scale_squared // 2) // scale_squared
    return max(0, min(2_000, distance))


def _final_decision(
    asset: GatedAsset,
    code: AssetDecisionCode,
    *,
    policy: ImageSelectionPolicy,
    scene_group_id: str,
    representative_id: str | None = None,
) -> AssetDecisionTrace:
    return _decision(
        asset.source,
        code,
        policy=policy,
        projection=asset.projection,
        perceptual_hash=asset.perceptual_hash,
        quality_score_milli=asset.quality_score_milli,
        crop_quality_milli=asset.crop_quality_milli,
        scene_group_id=scene_group_id,
        representative_id=representative_id,
    )


def select_representative_images(
    *,
    root_fd: int,
    candidate: PlaceImageSelectionCandidate,
    policy: ImageSelectionPolicy,
    encoder: SceneEmbeddingEncoder,
    preprocessing_policy: ImagePreprocessingPolicy | None = None,
) -> ImageSelectionManifest:
    """Return one canonical max-five manifest for a place without padding."""

    selected_preprocessing = preprocessing_policy or DEFAULT_IMAGE_PREPROCESSING_POLICY
    gated = gate_selection_assets(
        root_fd=root_fd,
        candidate=candidate,
        policy=policy,
        preprocessing_policy=selected_preprocessing,
    )
    scene_groups: tuple[SceneGroup, ...] = ()
    representatives: tuple[SelectedRepresentative, ...] = ()
    final_decisions = list(gated.decisions)

    if gated.survivors:
        embeddings = _quantize_embeddings(gated.survivors, encoder, policy)
        components = _components(
            gated.survivors,
            adjacent=lambda left, right: (
                _scene_distance_milli(
                    embeddings[left.source_asset_id], embeddings[right.source_asset_id]
                )
                <= policy.scene_distance_milli
            ),
        )
        group_rows: list[SceneGroup] = []
        winners: list[tuple[GatedAsset, str, tuple[GatedAsset, ...]]] = []
        for component in components:
            member_ids = tuple(sorted(asset.source_asset_id for asset in component))
            group_id = canonical_sha256(
                {
                    "place_entity_id": candidate.place_entity_id,
                    "member_asset_ids": member_ids,
                    "selection_policy_sha256": policy.policy_sha256,
                }
            )
            winner = min(component, key=_preferred)
            group_rows.append(
                SceneGroup(
                    scene_group_id=group_id,
                    member_asset_ids=member_ids,
                    representative_asset_id=winner.source_asset_id,
                )
            )
            winners.append((winner, group_id, component))
        scene_groups = tuple(group_rows)
        selected_winners = tuple(sorted(winners, key=lambda item: _preferred(item[0])))[:5]
        selected_ids = {winner.source_asset_id for winner, _, _ in selected_winners}
        representative_rows: list[SelectedRepresentative] = []
        for winner, group_id, _ in selected_winners:
            representative_id = canonical_sha256(
                {
                    "place_entity_id": candidate.place_entity_id,
                    "source_asset_id": winner.source_asset_id,
                    "asset_sha256": winner.projection.asset_sha256,
                    "scene_group_id": group_id,
                    "selection_policy_sha256": policy.policy_sha256,
                }
            )
            representative_rows.append(
                SelectedRepresentative(
                    representative_id=representative_id,
                    source_asset_id=winner.source_asset_id,
                    scene_group_id=group_id,
                    asset_sha256=winner.projection.asset_sha256,
                    normalized_pixel_sha256=winner.projection.normalized_pixel_sha256,
                    rights_leaf_id=winner.source.rights_leaf_id,
                    rights_leaf_sha256=winner.source.rights_leaf_sha256,
                    materialization_sha256=winner.source.materialization_sha256,
                    preprocessing_policy_sha256=winner.projection.preprocessing_policy_sha256,
                    quality_score_milli=winner.quality_score_milli,
                    temporary_event=winner.source.temporary_event,
                )
            )
            final_decisions.append(
                _final_decision(
                    winner,
                    AssetDecisionCode.REPRESENTATIVE,
                    policy=policy,
                    scene_group_id=group_id,
                    representative_id=representative_id,
                )
            )
        representatives = tuple(representative_rows)
        for _winner, group_id, component in winners:
            for asset in component:
                if asset.source_asset_id in selected_ids:
                    continue
                final_decisions.append(
                    _final_decision(
                        asset,
                        AssetDecisionCode.SCENE_ALTERNATE,
                        policy=policy,
                        scene_group_id=group_id,
                    )
                )

    fields = {
        "schema_version": IMAGE_SELECTION_SCHEMA_VERSION,
        "place_entity_id": candidate.place_entity_id,
        "authority_scope": candidate.authority_scope,
        "input_authority_sha256": candidate.input_authority_sha256,
        "input_candidate_sha256": candidate.recompute_input_sha256(),
        "media_state": gated.media_state,
        "zero_image_reason": gated.zero_image_reason,
        "selection_policy_sha256": policy.policy_sha256,
        "preprocessing_policy_sha256": selected_preprocessing.policy_sha256,
        "model_id": policy.model_id,
        "model_revision": policy.model_revision,
        "model_weight_sha256": policy.model_weight_sha256,
        "asset_decisions": [
            decision.model_dump(mode="json")
            for decision in sorted(final_decisions, key=lambda item: item.source_asset_id)
        ],
        "scene_groups": [group.model_dump(mode="json") for group in scene_groups],
        "representatives": [
            representative.model_dump(mode="json") for representative in representatives
        ],
    }
    return ImageSelectionManifest.model_validate(
        {**fields, "manifest_sha256": canonical_sha256(fields)}
    )


__all__ = [
    "AssetGatingResult",
    "GatedAsset",
    "SceneEmbeddingEncoder",
    "gate_selection_assets",
    "select_representative_images",
]
