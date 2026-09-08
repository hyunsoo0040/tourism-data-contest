from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

from itda.analysis.image.preprocessing import ImagePreprocessingPolicy
from itda.analysis.image.secure_read import ApprovedImageMaterialization, SecureReadPolicy
from itda.analysis.image.selection import (
    SceneEmbeddingEncoder,
    gate_selection_assets,
    select_representative_images,
)
from itda.cli.select_dev_images import (
    _snapshot_weight_digest,
    _verified_snapshot_stage,
    _verify_output,
)
from itda.cli.select_dev_images import main as selection_cli_main
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_selection import (
    AssetDecisionCode,
    ImageSelectionBatchInput,
    ImageSelectionBatchManifest,
    ImageSelectionManifest,
    PlaceImageSelectionCandidate,
    SelectionAssetSource,
    SelectionAuthorityScope,
    build_image_selection_policy,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _png_bytes(
    *,
    size: tuple[int, int] = (80, 60),
    color: tuple[int, int, int] = (34, 85, 136),
    optimize: bool = False,
) -> bytes:
    image = Image.new("RGB", size, color)
    for offset in range(min(size)):
        image.putpixel((offset, offset), (255, 255 - offset % 255, offset % 255))
    output = BytesIO()
    image.save(output, format="PNG", optimize=optimize)
    image.close()
    return output.getvalue()


def _source(
    root: Path,
    *,
    source_asset_id: str,
    payload: bytes,
    temporary_event: bool = False,
) -> SelectionAssetSource:
    path = root / f"{source_asset_id}.png"
    path.write_bytes(payload)
    path.chmod(0o600)
    approved = ApprovedImageMaterialization(
        rights_leaf_id=f"phase2-rights:{source_asset_id}",
        rights_leaf_sha256=_sha256(f"rights:{source_asset_id}".encode()),
        content_sha256=_sha256(payload),
    )
    assert approved.materialization_sha256 is not None
    return SelectionAssetSource(
        source_asset_id=source_asset_id,
        relative_path=path.name,
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        content_sha256=approved.content_sha256,
        materialization_sha256=approved.materialization_sha256,
        temporary_event=temporary_event,
    )


def _policies() -> tuple[ImagePreprocessingPolicy, object]:
    preprocessing = ImagePreprocessingPolicy(
        secure_read=SecureReadPolicy(max_bytes=256 * 1024),
        accepted_formats=("PNG",),
        max_source_width=2_000,
        max_source_height=2_000,
        max_source_pixels=4_000_000,
        output_max_width=256,
        output_max_height=256,
    )
    selection = build_image_selection_policy(
        sensitivity_id="synthetic-baseline",
        model_weight_sha256="7" * 64,
        preprocessing_policy_sha256=preprocessing.policy_sha256,
        minimum_short_side=40,
        minimum_aspect_ratio_milli=300,
        maximum_aspect_ratio_milli=3_333,
        perceptual_hash_distance=0,
        scene_distance_milli=200,
        temporary_event_rule="EXCLUDE",
    )
    return preprocessing, selection


def _candidate(
    assets: tuple[SelectionAssetSource, ...],
    *,
    state: ImageMediumState = ImageMediumState.QUALIFIED,
    place_index: int = 1,
) -> PlaceImageSelectionCandidate:
    return PlaceImageSelectionCandidate(
        place_entity_id=f"place:{place_index:064x}",
        authority_scope=SelectionAuthorityScope.SYNTHETIC_LOCAL,
        input_authority_sha256="2" * 64,
        media_state=state,
        assets=assets,
    )


def _root_fd(root: Path) -> int:
    return os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )


def test_standard_huggingface_cache_links_are_securely_inventory_bound(
    tmp_path: Path,
) -> None:
    model_root = tmp_path / "models--google--siglip2-base-patch16-224"
    blobs = model_root / "blobs"
    snapshot = model_root / "snapshots" / "revision"
    blobs.mkdir(parents=True)
    snapshot.mkdir(parents=True)
    payloads = {
        "model.safetensors": b"synthetic-local-weight",
        "config.json": b'{"model_type":"siglip"}',
        "preprocessor_config.json": b'{"size":224}',
    }
    for index, (name, payload) in enumerate(payloads.items()):
        blob = blobs / f"blob-{index}"
        blob.write_bytes(payload)
        (snapshot / name).symlink_to(Path("../../blobs") / blob.name)

    first = _snapshot_weight_digest(snapshot)
    (blobs / "blob-2").write_bytes(b'{"size":384}')
    second = _snapshot_weight_digest(snapshot)
    assert first != second

    outside = tmp_path / "outside.safetensors"
    outside.write_bytes(b"outside-cache")
    (snapshot / "escape.safetensors").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes its cache root"):
        _snapshot_weight_digest(snapshot)


def test_verified_model_stage_is_immutable_after_cache_mutation(tmp_path: Path) -> None:
    model_root = tmp_path / "models--google--siglip2-base-patch16-224"
    blobs = model_root / "blobs"
    snapshot = model_root / "snapshots" / "revision"
    blobs.mkdir(parents=True)
    snapshot.mkdir(parents=True)
    payloads = {
        "model.safetensors": b"approved-weight-bytes",
        "config.json": b'{"model_type":"siglip"}',
        "preprocessor_config.json": b'{"size":224}',
    }
    for index, (name, payload) in enumerate(payloads.items()):
        blob = blobs / f"blob-{index}"
        blob.write_bytes(payload)
        (snapshot / name).symlink_to(Path("../../blobs") / blob.name)
    expected = _snapshot_weight_digest(snapshot)

    with _verified_snapshot_stage(snapshot, expected_digest=expected) as staged:
        (blobs / "blob-0").write_bytes(b"mutated-after-verification")

        assert (staged / "model.safetensors").read_bytes() == b"approved-weight-bytes"
        assert staged.resolve() != snapshot.resolve()


@pytest.mark.parametrize(
    "state",
    tuple(state for state in ImageMediumState if state is not ImageMediumState.QUALIFIED),
)
def test_non_qualified_states_round_trip_fact_free_before_image_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: ImageMediumState,
) -> None:
    preprocessing, policy = _policies()

    def forbidden_preprocess(**_: object) -> object:
        raise AssertionError("terminal rights state must stop before preprocessing")

    monkeypatch.setattr(
        "itda.analysis.image.selection.preprocess_image",
        forbidden_preprocess,
    )
    result = gate_selection_assets(
        root_fd=-1,
        candidate=_candidate((), state=state),
        policy=policy,
        preprocessing_policy=preprocessing,
    )

    assert result.media_state is state
    assert result.survivors == ()
    assert result.decisions == ()
    assert result.zero_image_reason == state.value


def test_quality_crop_exact_and_perceptual_duplicate_gates_are_total_and_stable(
    tmp_path: Path,
) -> None:
    preprocessing, policy = _policies()
    persistent = _png_bytes()
    assets = (
        _source(tmp_path, source_asset_id="z-exact", payload=persistent),
        _source(tmp_path, source_asset_id="a-keeper", payload=persistent),
        _source(
            tmp_path,
            source_asset_id="b-perceptual",
            payload=_png_bytes(optimize=True),
        ),
        _source(
            tmp_path,
            source_asset_id="low-quality",
            payload=_png_bytes(size=(20, 20)),
        ),
        _source(
            tmp_path,
            source_asset_id="severe-crop",
            payload=_png_bytes(size=(500, 100)),
        ),
    )

    def run(order: tuple[SelectionAssetSource, ...]) -> object:
        descriptor = _root_fd(tmp_path)
        try:
            return gate_selection_assets(
                root_fd=descriptor,
                candidate=_candidate(order),
                policy=policy,
                preprocessing_policy=preprocessing,
            )
        finally:
            os.close(descriptor)

    first = run(assets)
    second = run(tuple(reversed(assets)))

    assert first == second
    assert tuple(asset.source_asset_id for asset in first.survivors) == ("a-keeper",)
    reasons = {decision.source_asset_id: decision.decision_code for decision in first.decisions}
    assert reasons == {
        "b-perceptual": AssetDecisionCode.PERCEPTUAL_DUPLICATE,
        "low-quality": AssetDecisionCode.LOW_QUALITY,
        "severe-crop": AssetDecisionCode.SEVERE_CROP,
        "z-exact": AssetDecisionCode.EXACT_DUPLICATE,
    }
    assert all(decision.decision_trace_sha256 for decision in first.decisions)


def test_temporary_event_never_displaces_a_persistent_duplicate(tmp_path: Path) -> None:
    preprocessing, policy = _policies()
    payload = _png_bytes()
    assets = (
        _source(
            tmp_path,
            source_asset_id="a-event",
            payload=payload,
            temporary_event=True,
        ),
        _source(tmp_path, source_asset_id="z-persistent", payload=payload),
    )
    descriptor = _root_fd(tmp_path)
    try:
        result = gate_selection_assets(
            root_fd=descriptor,
            candidate=_candidate(assets),
            policy=policy,
            preprocessing_policy=preprocessing,
        )
    finally:
        os.close(descriptor)

    assert tuple(asset.source_asset_id for asset in result.survivors) == ("z-persistent",)
    assert result.decisions[0].source_asset_id == "a-event"
    assert result.decisions[0].decision_code is AssetDecisionCode.EXACT_DUPLICATE
    assert result.decisions[0].duplicate_of_asset_id == "z-persistent"


@dataclass(frozen=True)
class _FixedEncoder(SceneEmbeddingEncoder):
    vectors: dict[str, tuple[float, ...]]
    model_id: str = "google/siglip2-base-patch16-224"
    model_revision: str = "02c35f2c035e0ed4a367fb10a892c1fe2a3f364e"
    model_weight_sha256: str = "7" * 64

    def encode(self, assets: tuple[object, ...]) -> dict[str, tuple[float, ...]]:
        return {
            asset.source_asset_id: self.vectors[asset.source_asset_id]  # type: ignore[attr-defined]
            for asset in assets
        }


def _distinct_assets(tmp_path: Path, count: int) -> tuple[SelectionAssetSource, ...]:
    def distinct_payload(index: int) -> bytes:
        image = Image.new(
            "RGB",
            (80, 60),
            ((index * 31 + 10) % 255, (index * 47 + 20) % 255, (index * 61 + 30) % 255),
        )
        for offset in range(8 + index * 3):
            image.putpixel(
                ((index * 11 + offset) % 80, (index * 7 + offset * 2) % 60),
                (255, 255, 255),
            )
        output = BytesIO()
        image.save(output, format="PNG")
        image.close()
        return output.getvalue()

    return tuple(
        _source(
            tmp_path,
            source_asset_id=f"asset-{index:02d}",
            payload=distinct_payload(index),
        )
        for index in range(count)
    )


def test_scene_selection_is_permutation_invariant_diverse_capped_and_unpadded(
    tmp_path: Path,
) -> None:
    preprocessing, policy = _policies()
    assets = _distinct_assets(tmp_path, 7)
    vectors = {
        "asset-00": (1.0, 0.0, 0.0),
        "asset-01": (0.999, 0.001, 0.0),
        "asset-02": (0.0, 1.0, 0.0),
        "asset-03": (0.0, 0.0, 1.0),
        "asset-04": (-1.0, 0.0, 0.0),
        "asset-05": (0.0, -1.0, 0.0),
        "asset-06": (0.0, 0.0, -1.0),
    }
    encoder = _FixedEncoder(vectors)

    def run(order: tuple[SelectionAssetSource, ...]) -> object:
        descriptor = _root_fd(tmp_path)
        try:
            return select_representative_images(
                root_fd=descriptor,
                candidate=_candidate(order),
                policy=policy,
                encoder=encoder,
                preprocessing_policy=preprocessing,
            )
        finally:
            os.close(descriptor)

    first = run(assets)
    second = run(tuple(reversed(assets)))

    assert first == second
    assert first.manifest_sha256 == second.manifest_sha256
    assert len(first.representatives) == 5
    assert len(first.scene_groups) == 6
    assert {"asset-00", "asset-01"}.issubset(first.scene_groups[0].member_asset_ids)
    assert len(first.asset_decisions) == len(assets)
    assert (
        sum(
            decision.decision_code is AssetDecisionCode.REPRESENTATIVE
            for decision in first.asset_decisions
        )
        == 5
    )

    smaller = run(assets[:3])
    assert len(smaller.representatives) == 2
    assert all(
        representative.source_asset_id in {asset.source_asset_id for asset in assets[:3]}
        for representative in smaller.representatives
    )


@pytest.mark.parametrize("state", tuple(ImageMediumState))
def test_all_six_states_produce_a_manifest_without_place_exclusion(
    tmp_path: Path,
    state: ImageMediumState,
) -> None:
    preprocessing, policy = _policies()
    assets = ()
    encoder = _FixedEncoder({})
    manifest = select_representative_images(
        root_fd=-1,
        candidate=_candidate(assets, state=state),
        policy=policy,
        encoder=encoder,
        preprocessing_policy=preprocessing,
    )

    assert manifest.media_state is state
    assert manifest.representatives == ()
    if state is ImageMediumState.QUALIFIED:
        assert manifest.zero_image_reason == "NO_SELECTION_ELIGIBLE_ASSETS"
    else:
        assert manifest.zero_image_reason == state.value


def test_near_ties_use_total_digest_order_and_manifest_has_no_paths_or_raw_bytes(
    tmp_path: Path,
) -> None:
    preprocessing, policy = _policies()
    assets = _distinct_assets(tmp_path, 2)
    encoder = _FixedEncoder(
        {
            assets[0].source_asset_id: (1.0, 0.0),
            assets[1].source_asset_id: (0.999999999, 0.000000001),
        }
    )
    descriptor = _root_fd(tmp_path)
    try:
        manifest = select_representative_images(
            root_fd=descriptor,
            candidate=_candidate(assets),
            policy=policy,
            encoder=encoder,
            preprocessing_policy=preprocessing,
        )
    finally:
        os.close(descriptor)

    assert len(manifest.scene_groups) == 1
    expected = min(
        assets,
        key=lambda asset: next(
            decision.asset_sha256
            for decision in manifest.asset_decisions
            if decision.source_asset_id == asset.source_asset_id
        ),
    )
    assert manifest.representatives[0].source_asset_id == expected.source_asset_id
    payload = canonical_json_bytes(manifest.model_dump(mode="json"))
    assert b"relative_path" not in payload
    assert b"encoded_bytes" not in payload
    assert b"blind" not in payload.lower()


def test_batch_contract_and_cli_verify_only_cover_every_authorized_fixture(
    tmp_path: Path,
) -> None:
    preprocessing, policy = _policies()
    places = tuple(
        _candidate((), state=state, place_index=index)
        for index, state in enumerate(
            (
                ImageMediumState.MISSING,
                ImageMediumState.EMPTY,
                ImageMediumState.RIGHTS_RESTRICTED,
            ),
            start=1,
        )
    )
    batch_input = ImageSelectionBatchInput.build(
        authority_scope=SelectionAuthorityScope.SYNTHETIC_LOCAL,
        input_authority_sha256="2" * 64,
        places=places,
    )
    manifests = tuple(
        select_representative_images(
            root_fd=-1,
            candidate=place,
            policy=policy,
            encoder=_FixedEncoder({}),
            preprocessing_policy=preprocessing,
        )
        for place in places
    )
    batch_output = ImageSelectionBatchManifest.build(
        input_manifest_sha256=batch_input.input_manifest_sha256,
        selection_policy_sha256=policy.policy_sha256,
        manifests=manifests,
    )
    input_path = tmp_path / "rights-manifest.json"
    config_path = tmp_path / "selection-config.json"
    output_path = tmp_path / "selection-output.json"
    input_path.write_bytes(canonical_json_bytes(batch_input.model_dump(mode="json")))
    config_path.write_bytes(canonical_json_bytes(policy.model_dump(mode="json")))
    output_bytes = canonical_json_bytes(batch_output.model_dump(mode="json"))
    output_path.write_bytes(output_bytes)

    assert (
        selection_cli_main(
            [
                "--rights-manifest",
                str(input_path),
                "--image-root",
                str(tmp_path),
                "--config",
                str(config_path),
                "--output",
                str(output_path),
                "--verify-only",
            ]
        )
        == 0
    )
    assert output_path.read_bytes() == output_bytes
    assert len(batch_output.manifests) == len(places)


def test_verify_only_rejects_resealed_empty_result_for_qualified_assets(
    tmp_path: Path,
) -> None:
    preprocessing, policy = _policies()
    candidate = _candidate(_distinct_assets(tmp_path, 1))
    batch_input = ImageSelectionBatchInput.build(
        authority_scope=SelectionAuthorityScope.SYNTHETIC_LOCAL,
        input_authority_sha256="2" * 64,
        places=(candidate,),
    )
    descriptor = _root_fd(tmp_path)
    try:
        valid = select_representative_images(
            root_fd=descriptor,
            candidate=candidate,
            policy=policy,
            encoder=_FixedEncoder({candidate.assets[0].source_asset_id: (1.0, 0.0)}),
            preprocessing_policy=preprocessing,
        )
    finally:
        os.close(descriptor)
    forged_fields = valid.model_dump(exclude={"manifest_sha256"}, mode="json")
    forged_fields.update(
        zero_image_reason="NO_SELECTION_ELIGIBLE_ASSETS",
        asset_decisions=[],
        scene_groups=[],
        representatives=[],
    )
    forged = ImageSelectionManifest.model_validate(
        {**forged_fields, "manifest_sha256": canonical_sha256(forged_fields)}
    )
    output = ImageSelectionBatchManifest.build(
        input_manifest_sha256=batch_input.input_manifest_sha256,
        selection_policy_sha256=policy.policy_sha256,
        manifests=(forged,),
    )

    descriptor = _root_fd(tmp_path)
    try:
        with pytest.raises(ValueError, match="deterministic protected-byte derivation"):
            _verify_output(
                batch_input,
                policy,
                output,
                root_fd=descriptor,
                encoder=_FixedEncoder({candidate.assets[0].source_asset_id: (1.0, 0.0)}),
                preprocessing_policy=preprocessing,
            )
    finally:
        os.close(descriptor)
