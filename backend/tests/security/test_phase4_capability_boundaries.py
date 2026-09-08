from __future__ import annotations

import inspect
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.run_dev_image_observations import main as observation_cli_main
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.dev_image_observations import (
    FrozenObservationBatch,
    LabelEvaluationCapability,
    ProtectedImageCapabilityManifest,
    ProviderObservationCapability,
    ProviderReplayFixture,
    build_label_evaluation_capability,
    build_mock_replay_adapter,
    freeze_prediction_batch,
    generate_dev_image_observations,
)
from tests.evals.phase4.test_dev_image_observations import (
    FIXTURE,
    NOW,
    _batch,
    _config,
    _execution_capability,
    _png_bytes,
    _protected_capability,
    _qualified_selection,
    _terminal_selection,
)


@pytest.mark.parametrize(
    "forbidden_key",
    (
        "label_path",
        "labels",
        "expert_labels",
        "blind_membership",
        "blind_payload",
        "complement_function",
        "evaluator_token",
        "release_authority",
    ),
)
def test_provider_capability_rejects_every_label_split_evaluator_and_release_input(
    forbidden_key: str,
) -> None:
    selection = _batch(_terminal_selection(ImageMediumState.MISSING, 1))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=(),
    )
    capability = _execution_capability(selection, config, protected, replay)
    hostile = capability.model_dump(mode="json")
    hostile[forbidden_key] = {"canary": "protected-value"}

    with pytest.raises(ValidationError, match="prohibited authority"):
        ProviderObservationCapability.model_validate(hostile)

    nested = capability.model_dump(mode="json")
    nested["unexpected"] = {forbidden_key: "protected-value"}
    with pytest.raises(ValidationError, match="prohibited authority"):
        ProviderObservationCapability.model_validate(nested)


@pytest.mark.asyncio
async def test_frozen_prediction_receipt_is_required_before_label_capability() -> None:
    selection = _batch(_terminal_selection(ImageMediumState.MISSING, 1))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=(),
    )
    provider_capability = _execution_capability(selection, config, protected, replay)

    class ForbiddenAdapter:
        def __init__(self) -> None:
            self.config = config

        async def extract(self, **_: object) -> object:
            raise AssertionError("missing image reached provider")

    predictions = await generate_dev_image_observations(
        selection=selection,
        provider_config=config,
        capability=provider_capability,
        protected_images=protected,
        image_loader=lambda _entry: b"",
        adapter=ForbiddenAdapter(),
        clock=lambda: NOW,
    )
    receipt = freeze_prediction_batch(predictions)
    evaluator = build_label_evaluation_capability(
        predictions=predictions,
        freeze_receipt=receipt,
        label_capability_sha256="d" * 64,
        label_case_inventory_sha256=receipt.dev_case_inventory_sha256,
        prediction_case_records_sha256="1" * 64,
        label_case_records_sha256="2" * 64,
        review_inventory_sha256="3" * 64,
        evaluator_authority_sha256="e" * 64,
        created_at=NOW,
    )

    assert isinstance(evaluator, LabelEvaluationCapability)
    assert evaluator.prediction_batch_sha256 == predictions.batch_sha256
    assert evaluator.prediction_freeze_receipt_sha256 == receipt.receipt_sha256
    assert receipt.dev_case_inventory == tuple(
        row.place_entity_id for row in predictions.observations
    )
    assert receipt.dev_case_inventory_sha256 == canonical_sha256(list(receipt.dev_case_inventory))
    assert evaluator.prediction_dev_case_inventory == receipt.dev_case_inventory
    assert evaluator.prediction_dev_case_inventory_sha256 == receipt.dev_case_inventory_sha256
    assert evaluator.label_case_inventory_sha256 == receipt.dev_case_inventory_sha256
    assert not hasattr(evaluator, "labels")
    assert not hasattr(evaluator, "label_path")

    with pytest.raises(ValueError, match="exact frozen predictions"):
        build_label_evaluation_capability(
            predictions=predictions,
            freeze_receipt=receipt,
            label_capability_sha256="d" * 64,
            label_case_inventory_sha256="f" * 64,
            prediction_case_records_sha256="1" * 64,
            label_case_records_sha256="2" * 64,
            review_inventory_sha256="3" * 64,
            evaluator_authority_sha256="e" * 64,
            created_at=NOW,
        )

    hostile_receipt = receipt.model_copy(update={"prediction_batch_sha256": "f" * 64})
    with pytest.raises((ValidationError, ValueError)):
        build_label_evaluation_capability(
            predictions=predictions,
            freeze_receipt=hostile_receipt,
            label_capability_sha256="d" * 64,
            label_case_inventory_sha256=receipt.dev_case_inventory_sha256,
            prediction_case_records_sha256="1" * 64,
            label_case_records_sha256="2" * 64,
            review_inventory_sha256="3" * 64,
            evaluator_authority_sha256="e" * 64,
            created_at=NOW,
        )


def test_provider_surface_has_no_label_or_complement_oracle() -> None:
    signature = inspect.signature(generate_dev_image_observations)
    assert not {
        "labels",
        "label_path",
        "blind_membership",
        "split_membership",
        "complement",
        "evaluator_token",
        "release_authority",
    } & set(signature.parameters)
    source = inspect.getsource(generate_dev_image_observations).casefold()
    assert "blind" not in source
    assert "complement" not in source
    assert "expert_label" not in source


@pytest.mark.asyncio
async def test_frozen_batch_rejects_cross_run_observation_substitution() -> None:
    raw_image = _png_bytes()
    selection = _batch(_qualified_selection(raw_image))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = _protected_capability(selection, raw_image)
    provider_capability = _execution_capability(selection, config, protected, replay)
    adapter, client = build_mock_replay_adapter(
        config=config,
        fixture=replay,
        clock=lambda: NOW,
    )
    try:
        predictions = await generate_dev_image_observations(
            selection=selection,
            provider_config=config,
            capability=provider_capability,
            protected_images=protected,
            image_loader=lambda _entry: raw_image,
            adapter=adapter,
            clock=lambda: NOW,
        )
    finally:
        await client.aclose()

    hostile = deepcopy(predictions.model_dump(mode="json"))
    row = hostile["observations"][0]
    observation = row["observation"]
    observation["representative_manifest_sha256"] = "f" * 64
    observation["observation_sha256"] = canonical_sha256(
        {key: value for key, value in observation.items() if key != "observation_sha256"}
    )
    prediction = row["provider_prediction"]
    prediction["observation_sha256"] = observation["observation_sha256"]
    prediction["prediction_manifest_sha256"] = canonical_sha256(
        {key: value for key, value in prediction.items() if key != "prediction_manifest_sha256"}
    )
    row["record_sha256"] = canonical_sha256(
        {key: value for key, value in row.items() if key != "record_sha256"}
    )
    hostile["batch_sha256"] = canonical_sha256(
        {key: value for key, value in hostile.items() if key != "batch_sha256"}
    )
    with pytest.raises(ValidationError, match="exact safe request inputs|exact selection batch"):
        FrozenObservationBatch.model_validate(hostile)


def test_offline_cli_rejects_live_path_before_client_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection = _batch(_terminal_selection(ImageMediumState.MISSING, 1))
    config = _config(selection.batch_sha256)
    protected = ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=(),
    )
    for name, model in {
        "selection.json": selection,
        "config.json": config,
        "protected.json": protected,
    }.items():
        (tmp_path / name).write_bytes(canonical_json_bytes(model.model_dump(mode="json")))

    def forbidden_client(**_: object) -> object:
        raise AssertionError("offline live-mode rejection constructed a provider client")

    monkeypatch.setattr(
        "itda.cli.run_dev_image_observations.build_glm5v_async_client",
        forbidden_client,
    )
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    with pytest.raises(SystemExit, match="rejected") as rejected:
        observation_cli_main(
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
                str(tmp_path),
                "--quota-receipt-sha256",
                "b" * 64,
                "--output-capability-sha256",
                "c" * 64,
                "--live",
                "--live-operator-approval-sha256",
                "d" * 64,
                "--api-key-env",
                "SYNTHETIC_PROVIDER_KEY",
                "--output",
                str(tmp_path / "output.json"),
            ]
        )
    assert "SYNTHETIC_PROVIDER_KEY" not in str(rejected.value)


def test_demo_input_authority_parser_exposes_no_caller_selected_input_paths() -> None:
    from itda.cli.run_phase4_demo import _parser

    parser = _parser()
    derive = parser.parse_args(["derive-authority"])
    assert vars(derive) == {"command": "derive-authority"}

    materialize = next(action for action in parser._actions if action.dest == "command").choices[
        "materialize"
    ]
    exposed = {action.dest for action in materialize._actions}
    assert exposed == {"help", "artifact_root", "receipt_output"}
    assert (
        not {
            "catalog_audit",
            "dev_sqlite",
            "snapshot_root",
            "optional_media",
            "image_root",
            "rights_manifest",
            "image_selection_manifest",
        }
        & exposed
    )


def test_demo_input_authority_derives_current_complete_zero_image_bundle() -> None:
    from itda.cli.run_phase4_demo import _derive_fixed_demo_input_authority

    authority, zero_image = _derive_fixed_demo_input_authority()

    assert authority.image_mode == "ZERO_IMAGE"
    assert zero_image is not None
    assert authority.zero_image_absence_registry_sha256 == zero_image.registry_sha256
    assert len(authority.dev_place_refs) == 24
    assert len(set(authority.dev_place_refs)) == 24
    assert len(authority.snapshot_inventory) == 33
    assert {member.status for member in zero_image.members} == {"NO_IMAGE"}
    assert tuple(member.place_ref for member in zero_image.members) == tuple(
        sorted(authority.dev_place_refs)
    )


def test_demo_input_authority_rejects_resealed_substituted_sqlite() -> None:
    from itda.cli.run_phase4_demo import (
        _derive_fixed_demo_input_authority,
        _validate_fixed_demo_input_authority,
    )
    from itda.contracts.phase4_demo import Phase4DemoInputAuthority

    authority, _ = _derive_fixed_demo_input_authority()
    hostile = authority.model_dump(mode="json", exclude={"authority_sha256"})
    hostile["dev_sqlite_sha256"] = "f" * 64
    hostile["authority_sha256"] = canonical_sha256(hostile)

    with pytest.raises(ValueError, match="fixed demo input authority"):
        _validate_fixed_demo_input_authority(Phase4DemoInputAuthority.model_validate(hostile))


def test_demo_input_authority_local_materialization_keeps_source_only_truth(
    tmp_path: Path,
) -> None:
    from itda.cli.run_phase4_demo import main

    receipt_path = tmp_path / "materialization-receipt.json"
    assert (
        main(
            [
                "materialize",
                "--artifact-root",
                str(tmp_path / "restricted"),
                "--receipt-output",
                str(receipt_path),
            ]
        )
        == 0
    )
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt["dev_row_count"] == 24
    assert receipt["source_truth"] == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert receipt["profile_truth"] == "SOURCE_EVIDENCE_ONLY"
    assert receipt["profile_score_truth"] == "NO_LOCAL_PROFILE_SCORES"
    assert receipt["image_truth"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert receipt["selected_image_count"] == 0


def test_demo_image_namespace_rejects_partial_or_unbound_inputs(tmp_path: Path) -> None:
    from itda.cli.run_phase4_demo import _derive_image_mode_authority

    image_root = tmp_path / "image-root"
    image_root.mkdir()
    (image_root / "unbound.jpg").write_bytes(b"not-an-authorized-image")

    with pytest.raises(ValueError, match="all-or-none|unbound"):
        _derive_image_mode_authority(
            authority_root=tmp_path,
            dev_place_refs=tuple(f"place:{index:064x}" for index in range(24)),
        )


@pytest.mark.asyncio
async def test_serialized_handoff_and_errors_expose_only_digests_and_status() -> None:
    selection = _batch(_terminal_selection(ImageMediumState.MISSING, 1))
    config = _config(selection.batch_sha256)
    replay = ProviderReplayFixture.model_validate_json(FIXTURE.read_bytes())
    protected = ProtectedImageCapabilityManifest.build(
        selection_manifest_sha256=selection.batch_sha256,
        entries=(),
    )
    provider_capability = _execution_capability(selection, config, protected, replay)

    class ForbiddenAdapter:
        def __init__(self) -> None:
            self.config = config

        async def extract(self, **_: object) -> object:
            raise AssertionError("missing image reached provider")

    predictions = await generate_dev_image_observations(
        selection=selection,
        provider_config=config,
        capability=provider_capability,
        protected_images=protected,
        image_loader=lambda _entry: b"",
        adapter=ForbiddenAdapter(),
        clock=lambda: NOW,
    )
    receipt = freeze_prediction_batch(predictions)
    evaluator = build_label_evaluation_capability(
        predictions=predictions,
        freeze_receipt=receipt,
        label_capability_sha256="d" * 64,
        label_case_inventory_sha256=receipt.dev_case_inventory_sha256,
        prediction_case_records_sha256="1" * 64,
        label_case_records_sha256="2" * 64,
        review_inventory_sha256="3" * 64,
        evaluator_authority_sha256="e" * 64,
        created_at=datetime(2026, 8, 7, 9, 1, tzinfo=UTC),
    )
    serialized = b"\n".join(
        canonical_json_bytes(model.model_dump(mode="json"))
        for model in (provider_capability, predictions, receipt, evaluator, replay)
    ).lower()
    for forbidden in (
        b"label_path",
        b"expert_labels",
        b"blind_membership",
        b"complement_function",
        b"evaluator_token",
        b"release_authority",
        b"relative_path",
        b"image_bytes",
        b"api_key",
        b"nonce",
    ):
        assert forbidden not in serialized
