from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import httpx
import pytest
from PIL import Image

from itda.cli.run_dev_image_observations import (
    _image_loader,
    _open_image_root,
    _verify_output,
)
from itda.cli.run_dev_image_observations import (
    main as observation_cli_main,
)
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import (
    APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
    ImageObservationV2,
)
from itda.contracts.image_selection import (
    AssetDecisionCode,
    AssetDecisionTrace,
    ImageSelectionBatchManifest,
    ImageSelectionManifest,
    SceneGroup,
    SelectedRepresentative,
    SelectionAuthorityScope,
)
from itda.contracts.vlm_inference import (
    Glm5VProviderConfig,
    InferenceTerminalStatus,
    VlmPredictionManifest,
    seal_inference_contract,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.dev_image_observations import (
    FrozenObservationBatch,
    FrozenPlaceObservation,
    ProtectedImageCapabilityEntry,
    ProtectedImageCapabilityManifest,
    ProviderObservationCapability,
    ProviderReplayFixture,
    build_mock_replay_adapter,
    generate_dev_image_observations,
)
from itda.providers.zhipu_glm5v import Glm5VInferenceResult
from tests.contract.test_vlm_inference import _config_payload

NOW = datetime(2026, 8, 7, 9, 0, tzinfo=UTC)
FIXTURE = Path("fixtures/synthetic/phase4/provider-replay.json")


def _png_bytes() -> bytes:
    image = Image.new("RGB", (32, 24), (22, 88, 144))
    output = BytesIO()
    image.save(output, format="PNG")
    image.close()
    return output.getvalue()


def _terminal_selection(state: ImageMediumState, index: int) -> ImageSelectionManifest:
    fields: dict[str, object] = {
        "schema_version": "itda.image-selection-manifest.v1",
        "place_entity_id": f"place:{index:064x}",
        "authority_scope": SelectionAuthorityScope.SYNTHETIC_LOCAL,
        "input_authority_sha256": "2" * 64,
        "input_candidate_sha256": hashlib.sha256(f"candidate:{index}".encode()).hexdigest(),
        "media_state": state,
        "zero_image_reason": state.value,
        "selection_policy_sha256": "3" * 64,
        "preprocessing_policy_sha256": "4" * 64,
        "model_id": "google/siglip2-base-patch16-224",
        "model_revision": "02c35f2c035e0ed4a367fb10a892c1fe2a3f364e",
        "model_weight_sha256": "5" * 64,
        "asset_decisions": [],
        "scene_groups": [],
        "representatives": [],
    }
    return ImageSelectionManifest.model_validate(
        {**fields, "manifest_sha256": canonical_sha256(fields)}
    )


def _qualified_selection(payload: bytes, index: int = 9) -> ImageSelectionManifest:
    source_asset_id = "synthetic-source-a"
    representative_id = hashlib.sha256(b"representative-a").hexdigest()
    scene_group_id = hashlib.sha256(b"scene-a").hexdigest()
    asset_sha256 = hashlib.sha256(payload).hexdigest()
    decision_fields: dict[str, object] = {
        "source_asset_id": source_asset_id,
        "input_media_state": ImageMediumState.QUALIFIED,
        "decision_code": AssetDecisionCode.REPRESENTATIVE,
        "rights_leaf_id": "phase2-rights:synthetic-source-a",
        "rights_leaf_sha256": "6" * 64,
        "materialization_sha256": "7" * 64,
        "preprocessing_policy_sha256": "4" * 64,
        "asset_sha256": asset_sha256,
        "perceptual_hash": "0123456789abcdef",
        "quality_score_milli": 900,
        "crop_quality_milli": 900,
        "temporary_event": False,
        "duplicate_of_asset_id": None,
        "scene_group_id": scene_group_id,
        "representative_id": representative_id,
    }
    decision = AssetDecisionTrace.model_validate(
        {
            **decision_fields,
            "decision_trace_sha256": canonical_sha256(decision_fields),
        }
    )
    representative = SelectedRepresentative(
        representative_id=representative_id,
        source_asset_id=source_asset_id,
        scene_group_id=scene_group_id,
        asset_sha256=asset_sha256,
        normalized_pixel_sha256="8" * 64,
        rights_leaf_id="phase2-rights:synthetic-source-a",
        rights_leaf_sha256="6" * 64,
        materialization_sha256="7" * 64,
        preprocessing_policy_sha256="4" * 64,
        quality_score_milli=900,
        temporary_event=False,
    )
    fields: dict[str, object] = {
        "schema_version": "itda.image-selection-manifest.v1",
        "place_entity_id": f"place:{index:064x}",
        "authority_scope": SelectionAuthorityScope.SYNTHETIC_LOCAL,
        "input_authority_sha256": "2" * 64,
        "input_candidate_sha256": "9" * 64,
        "media_state": ImageMediumState.QUALIFIED,
        "zero_image_reason": None,
        "selection_policy_sha256": "3" * 64,
        "preprocessing_policy_sha256": "4" * 64,
        "model_id": "google/siglip2-base-patch16-224",
        "model_revision": "02c35f2c035e0ed4a367fb10a892c1fe2a3f364e",
        "model_weight_sha256": "5" * 64,
        "asset_decisions": [decision.model_dump(mode="json")],
        "scene_groups": [
            SceneGroup(
                scene_group_id=scene_group_id,
                member_asset_ids=(source_asset_id,),
                representative_asset_id=source_asset_id,
            ).model_dump(mode="json")
        ],
        "representatives": [representative.model_dump(mode="json")],
    }
    return ImageSelectionManifest.model_validate(
        {**fields, "manifest_sha256": canonical_sha256(fields)}
    )


def _batch(*manifests: ImageSelectionManifest) -> ImageSelectionBatchManifest:
    return ImageSelectionBatchManifest.build(
        input_manifest_sha256="a" * 64,
        selection_policy_sha256="3" * 64,
        manifests=tuple(manifests),
    )


def _config(selection_sha256: str) -> Glm5VProviderConfig:
    payload = _config_payload()
    payload["selection_manifest_sha256"] = selection_sha256
    return Glm5VProviderConfig.model_validate(
        seal_inference_contract(payload, digest_field="config_sha256")
    )


def _protected_capability(
    selection: ImageSelectionBatchManifest,
    payload: bytes,
) -> ProtectedImageCapabilityManifest:
    representative = selection.manifests[-1].representatives[0]
    return ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=(
            ProtectedImageCapabilityEntry(
                place_entity_id=selection.manifests[-1].place_entity_id,
                source_asset_id=representative.source_asset_id,
                relative_path="synthetic.png",
                asset_sha256=hashlib.sha256(payload).hexdigest(),
            ),
        ),
    )


def test_protected_image_loader_rejects_intermediate_symlink_escape(tmp_path: Path) -> None:
    payload = _png_bytes()
    image_root = tmp_path / "protected"
    outside = tmp_path / "outside"
    image_root.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    (outside / "image.png").write_bytes(payload)
    (outside / "image.png").chmod(0o600)
    (image_root / "alias").symlink_to(outside, target_is_directory=True)
    entry = ProtectedImageCapabilityEntry(
        place_entity_id=f"place:{1:064x}",
        source_asset_id="synthetic-source",
        relative_path="alias/image.png",
        asset_sha256=hashlib.sha256(payload).hexdigest(),
    )
    root_fd = _open_image_root(image_root)
    try:
        with pytest.raises(OSError):
            _image_loader(root_fd, entry)
    finally:
        os.close(root_fd)


def _execution_capability(
    selection: ImageSelectionBatchManifest,
    config: Glm5VProviderConfig,
    protected: ProtectedImageCapabilityManifest,
    replay: ProviderReplayFixture,
) -> ProviderObservationCapability:
    return ProviderObservationCapability.build_replay(
        selection_manifest_sha256=selection.batch_sha256,
        provider_config_sha256=config.config_sha256,
        protected_image_capability_sha256=protected.capability_sha256,
        quota_receipt_sha256="b" * 64,
        output_capability_sha256="c" * 64,
        replay_fixture_sha256=replay.fixture_sha256,
    )


@pytest.mark.asyncio
async def test_terminal_states_are_fact_free_and_bypass_every_provider_and_image_read() -> None:
    states = tuple(state for state in ImageMediumState if state is not ImageMediumState.QUALIFIED)
    selection = _batch(
        *(_terminal_selection(state, index) for index, state in enumerate(states, 1))
    )
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=(),
    )
    capability = _execution_capability(selection, config, protected, replay)

    class ForbiddenAdapter:
        def __init__(self, provider_config: Glm5VProviderConfig) -> None:
            self.config = provider_config

        async def extract(self, **_: object) -> object:
            raise AssertionError("terminal state reached the provider")

    def forbidden_loader(*_: object) -> bytes:
        raise AssertionError("terminal state read protected bytes")

    result = await generate_dev_image_observations(
        selection=selection,
        provider_config=config,
        capability=capability,
        protected_images=protected,
        image_loader=forbidden_loader,
        adapter=ForbiddenAdapter(config),
        clock=lambda: NOW,
    )

    assert tuple(row.terminal_media_state for row in result.observations) == states
    assert all(row.provider_prediction is None for row in result.observations)
    assert all(row.safe_request is None for row in result.observations)
    assert all(row.observation.selected_image_refs == () for row in result.observations)
    assert all(row.observation.observations == () for row in result.observations)


@pytest.mark.asyncio
async def test_mock_replay_is_request_bound_complete_and_byte_identical(
    tmp_path: Path,
) -> None:
    raw_image = _png_bytes()
    selection = _batch(_qualified_selection(raw_image))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = _protected_capability(selection, raw_image)
    capability = _execution_capability(selection, config, protected, replay)
    image_root = tmp_path / "protected"
    image_root.mkdir(mode=0o700)
    (image_root / "synthetic.png").write_bytes(raw_image)
    (image_root / "synthetic.png").chmod(0o600)

    outputs: list[bytes] = []
    for _ in range(2):
        adapter, client = build_mock_replay_adapter(
            config=config,
            fixture=replay,
            clock=lambda: NOW,
        )
        try:
            result = await generate_dev_image_observations(
                selection=selection,
                provider_config=config,
                capability=capability,
                protected_images=protected,
                image_loader=lambda _entry: raw_image,
                adapter=adapter,
                clock=lambda: NOW,
            )
        finally:
            await client.aclose()
        outputs.append(canonical_json_bytes(result.model_dump(mode="json")))

    assert outputs[0] == outputs[1]
    restored = FrozenObservationBatch.model_validate_json(outputs[0])
    assert len(restored.observations) == 1
    row = restored.observations[0]
    assert row.provider_prediction is not None
    assert row.provider_prediction.terminal_status is InferenceTerminalStatus.VALID
    assert row.observation.media_state is ImageMediumState.QUALIFIED
    assert row.safe_request is not None
    assert (
        row.safe_request.semantic_request_sha256 == row.provider_prediction.semantic_request_sha256
    )
    assert row.selection_manifest_sha256 == selection.manifests[0].manifest_sha256
    assert restored.selection_manifest_sha256 == selection.batch_sha256
    forged_fields = restored.model_dump(exclude={"batch_sha256"}, mode="json")
    forged_fields["replay_fixture_sha256"] = "f" * 64
    forged = FrozenObservationBatch.model_validate(
        {**forged_fields, "batch_sha256": canonical_sha256(forged_fields)}
    )
    root_fd = _open_image_root(image_root)
    try:
        _verify_output(
            output=restored,
            selection=selection,
            config=config,
            capability=capability,
            protected=protected,
            root_fd=root_fd,
        )
        with pytest.raises(ValueError, match="execution capability"):
            _verify_output(
                output=forged,
                selection=selection,
                config=config,
                capability=capability,
                protected=protected,
                root_fd=root_fd,
            )
    finally:
        os.close(root_fd)
    serialized = outputs[0].lower()
    for forbidden in (b"synthetic.png", b"image_bytes", b"relative_path", b"label", b"blind"):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_hostile_adapter_cannot_freeze_observation_for_unrequested_images() -> None:
    raw_image = _png_bytes()
    selection = _batch(_qualified_selection(raw_image))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = _protected_capability(selection, raw_image)
    capability = _execution_capability(selection, config, protected, replay)
    delegate, client = build_mock_replay_adapter(
        config=config,
        fixture=replay,
        clock=lambda: NOW,
    )

    class HostileAdapter:
        def __init__(self) -> None:
            self.config = config

        async def extract(self, **kwargs: object) -> Glm5VInferenceResult:
            result = await delegate.extract(**kwargs)  # type: ignore[arg-type]
            assert result.observation is not None
            observation_fields = result.observation.model_dump(
                mode="json", exclude={"observation_sha256"}
            )
            hostile_ref = f"selected-image:{'f' * 64}"
            observation_fields["selected_image_refs"] = [hostile_ref]
            observations = observation_fields["observations"]
            assert isinstance(observations, list)
            for attribute in observations:
                assert isinstance(attribute, dict)
                evidence_rows = attribute["visible_evidence"]
                assert isinstance(evidence_rows, list)
                for evidence in evidence_rows:
                    assert isinstance(evidence, dict)
                    evidence["image_ref"] = hostile_ref
            hostile_observation = ImageObservationV2.model_validate(
                {
                    **observation_fields,
                    "observation_sha256": canonical_sha256(observation_fields),
                }
            )
            prediction_fields = result.manifest.model_dump(
                mode="json", exclude={"prediction_manifest_sha256"}
            )
            prediction_fields["observation_sha256"] = hostile_observation.observation_sha256
            hostile_prediction = VlmPredictionManifest.model_validate(
                seal_inference_contract(
                    prediction_fields,
                    digest_field="prediction_manifest_sha256",
                )
            )
            return Glm5VInferenceResult(
                manifest=hostile_prediction,
                observation=hostile_observation,
            )

    try:
        with pytest.raises(ValueError, match="exact safe request inputs"):
            await generate_dev_image_observations(
                selection=selection,
                provider_config=config,
                capability=capability,
                protected_images=protected,
                image_loader=lambda _entry: raw_image,
                adapter=HostileAdapter(),
                clock=lambda: NOW,
            )
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_place_freeze_cannot_predate_provider_completion() -> None:
    raw_image = _png_bytes()
    selection = _batch(_qualified_selection(raw_image))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = _protected_capability(selection, raw_image)
    capability = _execution_capability(selection, config, protected, replay)
    adapter, client = build_mock_replay_adapter(
        config=config,
        fixture=replay,
        clock=lambda: NOW,
    )
    try:
        predictions = await generate_dev_image_observations(
            selection=selection,
            provider_config=config,
            capability=capability,
            protected_images=protected,
            image_loader=lambda _entry: raw_image,
            adapter=adapter,
            clock=lambda: NOW,
        )
    finally:
        await client.aclose()

    row_fields = predictions.observations[0].model_dump(
        mode="json", exclude={"record_sha256"}
    )
    row_fields["frozen_at"] = (NOW - timedelta(seconds=1)).isoformat().replace(
        "+00:00", "Z"
    )
    with pytest.raises(ValueError, match="cannot predate"):
        FrozenPlaceObservation.model_validate(
            {**row_fields, "record_sha256": canonical_sha256(row_fields)}
        )


@pytest.mark.asyncio
async def test_zero_selection_and_provider_failure_are_explicit_without_fabricated_scores() -> None:
    raw_image = _png_bytes()
    zero_fields = _terminal_selection(ImageMediumState.EMPTY, 20).model_dump(mode="json")
    zero_fields["media_state"] = ImageMediumState.QUALIFIED.value
    zero_fields["zero_image_reason"] = "NO_SELECTION_ELIGIBLE_ASSETS"
    zero_fields["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in zero_fields.items() if key != "manifest_sha256"}
    )
    zero = ImageSelectionManifest.model_validate(zero_fields)
    qualified = _qualified_selection(raw_image, 21)
    selection = _batch(zero, qualified)
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = _protected_capability(_batch(qualified), raw_image).model_copy(
        update={"selection_manifest_sha256": selection.batch_sha256}
    )
    protected = ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=protected.entries,
    )
    capability = _execution_capability(selection, config, protected, replay)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, content=b"synthetic-rejection")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    from itda.providers.zhipu_glm5v import ZhipuGlm5VAdapter

    adapter = ZhipuGlm5VAdapter(
        config=config,
        client=client,
        clock=lambda: NOW,
        request_id_factory=lambda attempt: f"replay-attempt-{attempt}",
    )
    try:
        result = await generate_dev_image_observations(
            selection=selection,
            provider_config=config,
            capability=capability,
            protected_images=protected,
            image_loader=lambda _entry: raw_image,
            adapter=adapter,
            clock=lambda: NOW,
        )
    finally:
        await client.aclose()

    assert tuple(row.terminal_media_state for row in result.observations) == (
        ImageMediumState.ANALYSIS_FAILED,
        ImageMediumState.ANALYSIS_FAILED,
    )
    assert result.observations[0].failure_code == "NO_SELECTION_ELIGIBLE_ASSETS"
    assert result.observations[0].provider_prediction is None
    assert result.observations[1].provider_prediction is not None
    assert result.observations[1].provider_prediction.terminal_status is (
        InferenceTerminalStatus.ANALYSIS_FAILED
    )
    assert all(row.observation.observations == () for row in result.observations)


def test_cli_replay_is_no_replace_verify_only_and_new_path_byte_identical(tmp_path: Path) -> None:
    raw_image = _png_bytes()
    selection = _batch(_qualified_selection(raw_image))
    config = _config(selection.batch_sha256)
    protected = _protected_capability(selection, raw_image)
    image_root = tmp_path / "images"
    image_root.mkdir(mode=0o700)
    (image_root / "synthetic.png").write_bytes(raw_image)
    (image_root / "synthetic.png").chmod(0o600)

    files = {
        "selection.json": selection,
        "config.json": config,
        "protected.json": protected,
    }
    for name, model in files.items():
        (tmp_path / name).write_bytes(canonical_json_bytes(model.model_dump(mode="json")))

    def invoke(output: Path, *extra: str) -> int:
        return observation_cli_main(
            [
                "--selection-manifest",
                str(tmp_path / "selection.json"),
                "--selection-sha256",
                selection.batch_sha256,
                "--config",
                str(tmp_path / "config.json"),
                "--config-sha256",
                config.config_sha256,
                "--schema-sha256",
                APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
                "--protected-image-capability",
                str(tmp_path / "protected.json"),
                "--protected-image-root",
                str(image_root),
                "--quota-receipt-sha256",
                "b" * 64,
                "--output-capability-sha256",
                "c" * 64,
                "--replay-fixture",
                str(FIXTURE),
                "--output",
                str(output),
                *extra,
            ]
        )

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    assert invoke(first) == 0
    assert invoke(second) == 0
    assert first.read_bytes() == second.read_bytes()
    assert invoke(first, "--verify-only") == 0
    with pytest.raises(SystemExit, match="rejected"):
        invoke(first)
