"""Deterministic selection-to-provider-to-freeze image observation pipeline."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime
from enum import StrEnum
from io import BytesIO
from pathlib import PurePosixPath
from typing import Annotated, Literal, Protocol, Self

import httpx
from PIL import Image
from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import (
    APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
    IMAGE_OBSERVATION_V2_AXIS_MEMBERS,
    ImageObservationV2,
)
from itda.contracts.image_selection import (
    ZERO_SELECTION_REASON,
    ImageSelectionBatchManifest,
)
from itda.contracts.place_profile import SubattributeId
from itda.contracts.vlm_inference import (
    KOREAN_PROMPT_CANDIDATE,
    Glm5VProviderConfig,
    InferenceTerminalStatus,
    SafeInferenceRequest,
    VlmPredictionManifest,
    seal_inference_contract,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.providers.zhipu_glm5v import (
    Glm5VInferenceResult,
    PreparedProviderImage,
    ZhipuGlm5VAdapter,
    build_glm5v_async_client,
)

Clock = Callable[[], datetime]
ImageLoader = Callable[["ProtectedImageCapabilityEntry"], bytes]

_CAPABILITY_FORBIDDEN_KEYS = frozenset(
    {
        "blind",
        "blind_ids",
        "blind_membership",
        "blind_payload",
        "complement",
        "complement_function",
        "evaluator_token",
        "expert_label",
        "expert_labels",
        "label",
        "label_path",
        "labels",
        "release_authority",
        "release_token",
        "split",
        "split_membership",
    }
)


def _reject_capability_escalation(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in _CAPABILITY_FORBIDDEN_KEYS:
                raise ValueError("provider observation capability contains prohibited authority")
            _reject_capability_escalation(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_capability_escalation(nested)


def _require_self_digest(model: StrictContract, field_name: str) -> None:
    expected = canonical_sha256(model.model_dump(mode="json", exclude={field_name}))
    if getattr(model, field_name) != expected:
        raise ValueError(f"{field_name} does not match canonical content")


def _utc_text(value: datetime) -> str:
    return require_utc(value, field_name="timestamp").isoformat().replace("+00:00", "Z")


class ObservationExecutionMode(StrEnum):
    MOCK_REPLAY = "MOCK_REPLAY"
    LIVE_EXPLICIT = "LIVE_EXPLICIT"


class ProtectedImageCapabilityEntry(StrictContract):
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    source_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    relative_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    asset_sha256: Sha256

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        path = PurePosixPath(self.relative_path)
        if (
            self.relative_path != path.as_posix()
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in self.relative_path
            or "\x00" in self.relative_path
        ):
            raise ValueError("protected image capability path is invalid")
        return self


class ProtectedImageCapabilityManifest(StrictContract):
    schema_version: Literal["itda.phase4-protected-image-capability.v1"] = (
        "itda.phase4-protected-image-capability.v1"
    )
    selection_manifest_sha256: Sha256
    entries: tuple[ProtectedImageCapabilityEntry, ...]
    capability_sha256: Sha256

    @classmethod
    def build(
        cls,
        *,
        selection_manifest_sha256: str,
        entries: tuple[ProtectedImageCapabilityEntry, ...],
    ) -> ProtectedImageCapabilityManifest:
        ordered = tuple(sorted(entries, key=lambda row: (row.place_entity_id, row.source_asset_id)))
        fields = {
            "schema_version": "itda.phase4-protected-image-capability.v1",
            "selection_manifest_sha256": selection_manifest_sha256,
            "entries": [row.model_dump(mode="json") for row in ordered],
        }
        return cls.model_validate({**fields, "capability_sha256": canonical_sha256(fields)})

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        identities = tuple((row.place_entity_id, row.source_asset_id) for row in self.entries)
        if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
            raise ValueError("protected image capability entries are not canonical and unique")
        _require_self_digest(self, "capability_sha256")
        return self


class ProviderReplayFixture(StrictContract):
    schema_version: Literal["itda.phase4-provider-replay.v1"] = "itda.phase4-provider-replay.v1"
    fixture_id: Annotated[
        str, Field(strict=True, min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    ]
    attribute_scores_milli: Annotated[tuple[int, ...], Field(min_length=12, max_length=12)]
    uncertainty_bp: Annotated[int, Field(strict=True, ge=0, le=10_000)]
    provider_request_id: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    prompt_tokens: Annotated[int, Field(strict=True, ge=0)]
    completion_tokens: Annotated[int, Field(strict=True, ge=0)]
    frozen_at: datetime
    fixture_sha256: Sha256

    @field_validator("attribute_scores_milli")
    @classmethod
    def validate_scores(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(type(score) is not int or not 0 <= score <= 4_000 for score in value):
            raise ValueError("replay scores must be exact integers in range")
        return value

    @field_validator("frozen_at")
    @classmethod
    def validate_frozen_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="frozen_at")

    @model_validator(mode="after")
    def validate_fixture(self) -> Self:
        _require_self_digest(self, "fixture_sha256")
        return self


class ProviderObservationCapability(StrictContract):
    schema_version: Literal["itda.phase4-provider-observation-capability.v1"] = (
        "itda.phase4-provider-observation-capability.v1"
    )
    selection_manifest_sha256: Sha256
    provider_config_sha256: Sha256
    observation_schema_sha256: Sha256
    protected_image_capability_sha256: Sha256
    quota_receipt_sha256: Sha256
    output_capability_sha256: Sha256
    execution_mode: ObservationExecutionMode
    replay_fixture_sha256: Sha256 | None
    live_operator_approval_sha256: Sha256 | None
    capability_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_escalation(cls, value: object) -> object:
        _reject_capability_escalation(value)
        return value

    @classmethod
    def build_replay(
        cls,
        *,
        selection_manifest_sha256: str,
        provider_config_sha256: str,
        protected_image_capability_sha256: str,
        quota_receipt_sha256: str,
        output_capability_sha256: str,
        replay_fixture_sha256: str,
    ) -> ProviderObservationCapability:
        return cls._build(
            selection_manifest_sha256=selection_manifest_sha256,
            provider_config_sha256=provider_config_sha256,
            protected_image_capability_sha256=protected_image_capability_sha256,
            quota_receipt_sha256=quota_receipt_sha256,
            output_capability_sha256=output_capability_sha256,
            execution_mode=ObservationExecutionMode.MOCK_REPLAY,
            replay_fixture_sha256=replay_fixture_sha256,
            live_operator_approval_sha256=None,
        )

    @classmethod
    def build_live(
        cls,
        *,
        selection_manifest_sha256: str,
        provider_config_sha256: str,
        protected_image_capability_sha256: str,
        quota_receipt_sha256: str,
        output_capability_sha256: str,
        live_operator_approval_sha256: str,
    ) -> ProviderObservationCapability:
        return cls._build(
            selection_manifest_sha256=selection_manifest_sha256,
            provider_config_sha256=provider_config_sha256,
            protected_image_capability_sha256=protected_image_capability_sha256,
            quota_receipt_sha256=quota_receipt_sha256,
            output_capability_sha256=output_capability_sha256,
            execution_mode=ObservationExecutionMode.LIVE_EXPLICIT,
            replay_fixture_sha256=None,
            live_operator_approval_sha256=live_operator_approval_sha256,
        )

    @classmethod
    def _build(cls, **values: object) -> ProviderObservationCapability:
        fields = {
            "schema_version": "itda.phase4-provider-observation-capability.v1",
            "observation_schema_sha256": APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
            **values,
        }
        return cls.model_validate({**fields, "capability_sha256": canonical_sha256(fields)})

    @model_validator(mode="after")
    def validate_capability(self) -> Self:
        if self.observation_schema_sha256 != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256:
            raise ValueError("observation schema capability is not approved")
        if self.execution_mode is ObservationExecutionMode.MOCK_REPLAY:
            if self.replay_fixture_sha256 is None or self.live_operator_approval_sha256 is not None:
                raise ValueError("mock replay requires only its exact replay fixture")
        elif self.live_operator_approval_sha256 is None or self.replay_fixture_sha256 is not None:
            raise ValueError("live execution requires a separate exact operator approval")
        _require_self_digest(self, "capability_sha256")
        return self


class FrozenPlaceObservation(StrictContract):
    schema_version: Literal["itda.phase4-frozen-place-observation.v1"] = (
        "itda.phase4-frozen-place-observation.v1"
    )
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    selection_manifest_sha256: Sha256
    input_media_state: ImageMediumState
    terminal_media_state: ImageMediumState
    provider_called: bool
    safe_request: SafeInferenceRequest | None
    provider_prediction: VlmPredictionManifest | None
    observation: ImageObservationV2
    failure_code: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)]
    frozen_at: datetime
    record_sha256: Sha256

    @field_validator("frozen_at")
    @classmethod
    def validate_frozen_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="frozen_at")

    @model_validator(mode="after")
    def validate_terminal_lineage(self) -> Self:
        if self.observation.media_state is not self.terminal_media_state:
            raise ValueError("terminal media state does not match its frozen observation")
        if not self.provider_called:
            if self.safe_request is not None or self.provider_prediction is not None:
                raise ValueError("provider bypass cannot carry request or attempt lineage")
        elif self.safe_request is None or self.provider_prediction is None:
            raise ValueError("provider execution requires exact request and prediction lineage")
        else:
            if self.frozen_at < self.provider_prediction.completed_at:
                raise ValueError("frozen observation cannot predate its provider prediction")
            if (
                self.safe_request.semantic_request_sha256
                != self.provider_prediction.semantic_request_sha256
            ):
                raise ValueError("prediction does not bind the exact safe request")
            if (
                self.safe_request.place_ref != self.place_entity_id
                or self.safe_request.selection_manifest_sha256
                != self.observation.representative_manifest_sha256
                or self.safe_request.provider_config_sha256
                != self.provider_prediction.provider_config_sha256
            ):
                raise ValueError("frozen observation does not bind the exact safe request inputs")
            if self.provider_prediction.terminal_status is InferenceTerminalStatus.VALID:
                if self.safe_request.selected_image_refs != self.observation.selected_image_refs:
                    raise ValueError(
                        "frozen observation does not bind the exact safe request inputs"
                    )
                if (
                    self.terminal_media_state is not ImageMediumState.QUALIFIED
                    or self.failure_code is not None
                    or self.provider_prediction.observation_sha256
                    != self.observation.observation_sha256
                ):
                    raise ValueError("valid prediction does not bind one qualified observation")
            elif (
                self.terminal_media_state is not ImageMediumState.ANALYSIS_FAILED
                or self.failure_code is None
            ):
                raise ValueError("failed provider prediction requires an explicit failed state")
        if self.terminal_media_state is ImageMediumState.QUALIFIED:
            if self.failure_code is not None:
                raise ValueError("qualified observation cannot carry a failure code")
        elif self.failure_code is None:
            raise ValueError("fact-free observation requires an explicit terminal reason")
        _require_self_digest(self, "record_sha256")
        return self


class FrozenObservationBatch(StrictContract):
    schema_version: Literal["itda.phase4-frozen-observation-batch.v1"] = (
        "itda.phase4-frozen-observation-batch.v1"
    )
    selection_manifest_sha256: Sha256
    provider_config_sha256: Sha256
    observation_schema_sha256: Sha256
    provider_capability_sha256: Sha256
    replay_fixture_sha256: Sha256 | None
    observations: Annotated[tuple[FrozenPlaceObservation, ...], Field(min_length=1)]
    frozen_at: datetime
    batch_sha256: Sha256

    @field_validator("frozen_at")
    @classmethod
    def validate_frozen_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="frozen_at")

    @model_validator(mode="after")
    def validate_batch(self) -> Self:
        place_ids = tuple(row.place_entity_id for row in self.observations)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != len(place_ids):
            raise ValueError("frozen observations require unique canonical place order")
        if self.observation_schema_sha256 != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256:
            raise ValueError("frozen observation schema digest is not approved")
        for row in self.observations:
            if row.observation.representative_manifest_sha256 != self.selection_manifest_sha256:
                raise ValueError("frozen observation does not bind the exact selection batch")
            if row.frozen_at > self.frozen_at:
                raise ValueError("place observation cannot freeze after its containing batch")
            if row.safe_request is not None and (
                row.safe_request.selection_manifest_sha256 != self.selection_manifest_sha256
                or row.safe_request.provider_config_sha256 != self.provider_config_sha256
                or row.provider_prediction is None
                or row.provider_prediction.provider_config_sha256 != self.provider_config_sha256
            ):
                raise ValueError("provider lineage does not bind the frozen batch inputs")
        _require_self_digest(self, "batch_sha256")
        return self

    def require_exact_capability(
        self, capability: ProviderObservationCapability
    ) -> None:
        expected_fixture = (
            capability.replay_fixture_sha256
            if capability.execution_mode is ObservationExecutionMode.MOCK_REPLAY
            else None
        )
        if (
            self.provider_capability_sha256 != capability.capability_sha256
            or self.replay_fixture_sha256 != expected_fixture
        ):
            raise ValueError("frozen observation batch does not bind its execution capability")


class PredictionBatchFreezeReceipt(StrictContract):
    """Digest-only proof that the entire label-free prediction batch is immutable."""

    schema_version: Literal["itda.phase4-prediction-batch-freeze-receipt.v1"] = (
        "itda.phase4-prediction-batch-freeze-receipt.v1"
    )
    prediction_batch_sha256: Sha256
    selection_manifest_sha256: Sha256
    provider_config_sha256: Sha256
    observation_schema_sha256: Sha256
    dev_case_inventory: Annotated[tuple[StableId, ...], Field(min_length=1)] | None = None
    dev_case_inventory_sha256: Sha256 | None = None
    frozen_at: datetime
    receipt_sha256: Sha256

    @field_validator("frozen_at")
    @classmethod
    def validate_frozen_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="frozen_at")

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.observation_schema_sha256 != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256:
            raise ValueError("prediction freeze uses an unapproved observation schema")
        if self.dev_case_inventory is None and self.dev_case_inventory_sha256 is None:
            expected_legacy = canonical_sha256(
                self.model_dump(
                    mode="json",
                    exclude={"receipt_sha256"},
                    exclude_none=True,
                )
            )
            if self.receipt_sha256 != expected_legacy:
                raise ValueError("legacy prediction freeze receipt digest drifted")
            return self
        if (
            self.dev_case_inventory is None
            or self.dev_case_inventory_sha256 is None
            or self.dev_case_inventory != tuple(sorted(self.dev_case_inventory))
            or len(set(self.dev_case_inventory)) != len(self.dev_case_inventory)
            or self.dev_case_inventory_sha256
            != canonical_sha256(list(self.dev_case_inventory))
        ):
            raise ValueError("prediction freeze DEV case inventory is not canonical")
        _require_self_digest(self, "receipt_sha256")
        return self


class LabelEvaluationCapability(StrictContract):
    """Separate digest-only authority opened only after prediction freeze."""

    schema_version: Literal["itda.phase4-label-evaluation-capability.v2"] = (
        "itda.phase4-label-evaluation-capability.v2"
    )
    prediction_batch_sha256: Sha256
    prediction_freeze_receipt_sha256: Sha256
    prediction_dev_case_inventory: Annotated[tuple[StableId, ...], Field(min_length=1)]
    prediction_dev_case_inventory_sha256: Sha256
    label_case_inventory_sha256: Sha256
    prediction_case_records_sha256: Sha256
    label_case_records_sha256: Sha256
    review_inventory_sha256: Sha256
    label_capability_sha256: Sha256
    evaluator_authority_sha256: Sha256
    created_at: datetime
    capability_sha256: Sha256

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="before")
    @classmethod
    def reject_payloads_and_paths(cls, value: object) -> object:
        if isinstance(value, Mapping):
            forbidden = {
                "labels",
                "label_path",
                "label_payload",
                "blind",
                "blind_membership",
                "complement",
                "provider_credential",
                "raw_image",
                "release_authority",
            }
            for key in value:
                if isinstance(key, str) and key.casefold() in forbidden:
                    raise ValueError("label evaluation capability accepts digest authority only")
        return value

    @model_validator(mode="after")
    def validate_capability(self) -> Self:
        if (
            self.prediction_dev_case_inventory
            != tuple(sorted(self.prediction_dev_case_inventory))
            or len(set(self.prediction_dev_case_inventory))
            != len(self.prediction_dev_case_inventory)
            or self.prediction_dev_case_inventory_sha256
            != canonical_sha256(list(self.prediction_dev_case_inventory))
            or self.label_case_inventory_sha256
            != self.prediction_dev_case_inventory_sha256
        ):
            raise ValueError("label capability does not bind the exact DEV case inventory")
        _require_self_digest(self, "capability_sha256")
        return self


def freeze_prediction_batch(predictions: FrozenObservationBatch) -> PredictionBatchFreezeReceipt:
    dev_case_inventory = tuple(row.place_entity_id for row in predictions.observations)
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-prediction-batch-freeze-receipt.v1",
        "prediction_batch_sha256": predictions.batch_sha256,
        "selection_manifest_sha256": predictions.selection_manifest_sha256,
        "provider_config_sha256": predictions.provider_config_sha256,
        "observation_schema_sha256": predictions.observation_schema_sha256,
        "dev_case_inventory": list(dev_case_inventory),
        "dev_case_inventory_sha256": canonical_sha256(list(dev_case_inventory)),
        "frozen_at": _utc_text(predictions.frozen_at),
    }
    return PredictionBatchFreezeReceipt.model_validate(
        {**fields, "receipt_sha256": canonical_sha256(fields)}
    )


def build_label_evaluation_capability(
    *,
    predictions: FrozenObservationBatch,
    freeze_receipt: PredictionBatchFreezeReceipt,
    label_capability_sha256: str,
    label_case_inventory_sha256: str,
    prediction_case_records_sha256: str,
    label_case_records_sha256: str,
    review_inventory_sha256: str,
    evaluator_authority_sha256: str,
    created_at: datetime,
) -> LabelEvaluationCapability:
    inventory = freeze_receipt.dev_case_inventory
    inventory_sha256 = freeze_receipt.dev_case_inventory_sha256
    if (
        inventory is None
        or inventory_sha256 is None
        or freeze_receipt.prediction_batch_sha256 != predictions.batch_sha256
        or freeze_receipt.selection_manifest_sha256 != predictions.selection_manifest_sha256
        or freeze_receipt.provider_config_sha256 != predictions.provider_config_sha256
        or freeze_receipt.observation_schema_sha256 != predictions.observation_schema_sha256
        or freeze_receipt.frozen_at != predictions.frozen_at
        or inventory != tuple(row.place_entity_id for row in predictions.observations)
        or inventory_sha256 != canonical_sha256(list(inventory))
        or label_case_inventory_sha256 != inventory_sha256
    ):
        raise ValueError("prediction freeze receipt does not match exact frozen predictions")
    resolved_created_at = require_utc(created_at, field_name="created_at")
    if resolved_created_at < freeze_receipt.frozen_at:
        raise ValueError("label evaluation capability cannot precede prediction freeze")
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-label-evaluation-capability.v2",
        "prediction_batch_sha256": predictions.batch_sha256,
        "prediction_freeze_receipt_sha256": freeze_receipt.receipt_sha256,
        "prediction_dev_case_inventory": list(inventory),
        "prediction_dev_case_inventory_sha256": inventory_sha256,
        "label_case_inventory_sha256": label_case_inventory_sha256,
        "prediction_case_records_sha256": prediction_case_records_sha256,
        "label_case_records_sha256": label_case_records_sha256,
        "review_inventory_sha256": review_inventory_sha256,
        "label_capability_sha256": label_capability_sha256,
        "evaluator_authority_sha256": evaluator_authority_sha256,
        "created_at": _utc_text(resolved_created_at),
    }
    return LabelEvaluationCapability.model_validate(
        {**fields, "capability_sha256": canonical_sha256(fields)}
    )


class ObservationAdapter(Protocol):
    @property
    def config(self) -> Glm5VProviderConfig: ...

    async def extract(
        self,
        *,
        request: SafeInferenceRequest,
        images: tuple[PreparedProviderImage, ...],
    ) -> Glm5VInferenceResult: ...


def _fact_free_observation(
    *,
    state: ImageMediumState,
    representative_manifest_sha256: str,
) -> ImageObservationV2:
    fields: dict[str, object] = {
        "schema_version": "photo-attributes.v2",
        "media_state": state.value,
        "representative_manifest_sha256": representative_manifest_sha256,
        "selected_image_refs": [],
        "observations": [],
        "candidate_axes": [],
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    return ImageObservationV2.model_validate(
        {**fields, "observation_sha256": canonical_sha256(fields)}
    )


def _freeze_place(**fields: object) -> FrozenPlaceObservation:
    frozen_at = fields.get("frozen_at")
    if isinstance(frozen_at, datetime):
        fields["frozen_at"] = _utc_text(frozen_at)
    base = {"schema_version": "itda.phase4-frozen-place-observation.v1", **fields}
    return FrozenPlaceObservation.model_validate({**base, "record_sha256": canonical_sha256(base)})


def _provider_image_ref(representative_id: str) -> str:
    return f"selected-image:{representative_id}"


def _prepare_provider_jpeg(source_png: bytes, *, expected_sha256: str) -> bytes:
    if hashlib.sha256(source_png).hexdigest() != expected_sha256:
        raise ValueError("protected image bytes do not match selected representative")
    try:
        with Image.open(BytesIO(source_png)) as probe:
            if probe.format != "PNG":
                raise ValueError("selected projection must retain its frozen PNG encoding")
            probe.verify()
        with Image.open(BytesIO(source_png)) as decoded:
            decoded.load()
            rgb = decoded.convert("RGB")
            output = BytesIO()
            try:
                rgb.save(
                    output,
                    format="JPEG",
                    quality=95,
                    subsampling=0,
                    optimize=False,
                    progressive=False,
                )
                return output.getvalue()
            finally:
                rgb.close()
    except (OSError, ValueError) as error:
        raise ValueError("selected image preparation failed") from error


def _validate_capabilities(
    *,
    selection: ImageSelectionBatchManifest,
    provider_config: Glm5VProviderConfig,
    capability: ProviderObservationCapability,
    protected_images: ProtectedImageCapabilityManifest,
    adapter: ObservationAdapter,
) -> None:
    if (
        capability.selection_manifest_sha256 != selection.batch_sha256
        or provider_config.selection_manifest_sha256 != selection.batch_sha256
        or capability.provider_config_sha256 != provider_config.config_sha256
        or capability.protected_image_capability_sha256 != protected_images.capability_sha256
        or protected_images.selection_manifest_sha256 != selection.batch_sha256
        or adapter.config != provider_config
    ):
        raise ValueError("provider observation capability does not match exact inputs")

    expected = tuple(
        (manifest.place_entity_id, representative.source_asset_id, representative.asset_sha256)
        for manifest in selection.manifests
        for representative in manifest.representatives
    )
    supplied = tuple(
        (entry.place_entity_id, entry.source_asset_id, entry.asset_sha256)
        for entry in protected_images.entries
    )
    if supplied != tuple(sorted(expected)):
        raise ValueError(
            "protected image capability does not exactly join selected representatives"
        )


async def generate_dev_image_observations(
    *,
    selection: ImageSelectionBatchManifest,
    provider_config: Glm5VProviderConfig,
    capability: ProviderObservationCapability,
    protected_images: ProtectedImageCapabilityManifest,
    image_loader: ImageLoader,
    adapter: ObservationAdapter,
    clock: Clock,
) -> FrozenObservationBatch:
    """Produce exactly one frozen, label-free terminal observation per selected place."""

    _validate_capabilities(
        selection=selection,
        provider_config=provider_config,
        capability=capability,
        protected_images=protected_images,
        adapter=adapter,
    )
    entries = {
        (entry.place_entity_id, entry.source_asset_id): entry for entry in protected_images.entries
    }
    frozen_rows: list[FrozenPlaceObservation] = []

    for manifest in selection.manifests:
        frozen_at = require_utc(clock(), field_name="frozen_at")
        if manifest.media_state is not ImageMediumState.QUALIFIED:
            observation = _fact_free_observation(
                state=manifest.media_state,
                representative_manifest_sha256=selection.batch_sha256,
            )
            frozen_rows.append(
                _freeze_place(
                    place_entity_id=manifest.place_entity_id,
                    selection_manifest_sha256=manifest.manifest_sha256,
                    input_media_state=manifest.media_state.value,
                    terminal_media_state=manifest.media_state.value,
                    provider_called=False,
                    safe_request=None,
                    provider_prediction=None,
                    observation=observation.model_dump(mode="json"),
                    failure_code=manifest.media_state.value,
                    frozen_at=frozen_at,
                )
            )
            continue

        if not manifest.representatives:
            observation = _fact_free_observation(
                state=ImageMediumState.ANALYSIS_FAILED,
                representative_manifest_sha256=selection.batch_sha256,
            )
            frozen_rows.append(
                _freeze_place(
                    place_entity_id=manifest.place_entity_id,
                    selection_manifest_sha256=manifest.manifest_sha256,
                    input_media_state=manifest.media_state.value,
                    terminal_media_state=ImageMediumState.ANALYSIS_FAILED.value,
                    provider_called=False,
                    safe_request=None,
                    provider_prediction=None,
                    observation=observation.model_dump(mode="json"),
                    failure_code=manifest.zero_image_reason or ZERO_SELECTION_REASON,
                    frozen_at=frozen_at,
                )
            )
            continue

        prepared: list[PreparedProviderImage] = []
        try:
            for representative in manifest.representatives:
                entry = entries[(manifest.place_entity_id, representative.source_asset_id)]
                raw = image_loader(entry)
                jpeg = _prepare_provider_jpeg(raw, expected_sha256=representative.asset_sha256)
                prepared.append(
                    PreparedProviderImage(
                        image_ref=_provider_image_ref(representative.representative_id),
                        jpeg_bytes=jpeg,
                    )
                )
        except (KeyError, OSError, ValueError):
            observation = _fact_free_observation(
                state=ImageMediumState.ANALYSIS_FAILED,
                representative_manifest_sha256=selection.batch_sha256,
            )
            frozen_rows.append(
                _freeze_place(
                    place_entity_id=manifest.place_entity_id,
                    selection_manifest_sha256=manifest.manifest_sha256,
                    input_media_state=manifest.media_state.value,
                    terminal_media_state=ImageMediumState.ANALYSIS_FAILED.value,
                    provider_called=False,
                    safe_request=None,
                    provider_prediction=None,
                    observation=observation.model_dump(mode="json"),
                    failure_code="IMAGE_PREPARATION_FAILED",
                    frozen_at=frozen_at,
                )
            )
            continue

        request_fields: dict[str, object] = {
            "schema_version": "itda.vlm-safe-request.v1",
            "place_ref": manifest.place_entity_id,
            "provider_config_sha256": provider_config.config_sha256,
            "selection_manifest_sha256": selection.batch_sha256,
            "prompt_id": (
                provider_config.prompt_routing.global_prompt_id or KOREAN_PROMPT_CANDIDATE.prompt_id
            ),
            "selected_image_refs": [image.image_ref for image in prepared],
            "selected_image_sha256": [
                hashlib.sha256(image.jpeg_bytes).hexdigest() for image in prepared
            ],
            "created_at": _utc_text(frozen_at),
        }
        request = SafeInferenceRequest.model_validate(
            seal_inference_contract(request_fields, digest_field="semantic_request_sha256")
        )
        result = await adapter.extract(request=request, images=tuple(prepared))
        if result.manifest.terminal_status is InferenceTerminalStatus.VALID:
            if (
                result.observation is None
                or result.observation.media_state is not ImageMediumState.QUALIFIED
            ):
                raise ValueError("provider returned an invalid qualified terminal observation")
            observation = result.observation
            terminal_state = ImageMediumState.QUALIFIED
            failure_code = None
        else:
            observation = _fact_free_observation(
                state=ImageMediumState.ANALYSIS_FAILED,
                representative_manifest_sha256=selection.batch_sha256,
            )
            terminal_state = ImageMediumState.ANALYSIS_FAILED
            failure_code = result.manifest.attempts[-1].error_code or "ANALYSIS_FAILED"

        frozen_at = require_utc(clock(), field_name="frozen_at")

        frozen_rows.append(
            _freeze_place(
                place_entity_id=manifest.place_entity_id,
                selection_manifest_sha256=manifest.manifest_sha256,
                input_media_state=manifest.media_state.value,
                terminal_media_state=terminal_state.value,
                provider_called=True,
                safe_request=request.model_dump(mode="json"),
                provider_prediction=result.manifest.model_dump(mode="json"),
                observation=observation.model_dump(mode="json"),
                failure_code=failure_code,
                frozen_at=frozen_at,
            )
        )

    batch_fields: dict[str, object] = {
        "schema_version": "itda.phase4-frozen-observation-batch.v1",
        "selection_manifest_sha256": selection.batch_sha256,
        "provider_config_sha256": provider_config.config_sha256,
        "observation_schema_sha256": APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
        "provider_capability_sha256": capability.capability_sha256,
        "replay_fixture_sha256": capability.replay_fixture_sha256,
        "observations": [row.model_dump(mode="json") for row in frozen_rows],
        "frozen_at": _utc_text(require_utc(clock(), field_name="frozen_at")),
    }
    return FrozenObservationBatch.model_validate(
        {**batch_fields, "batch_sha256": canonical_sha256(batch_fields)}
    )


def _replay_observation(
    *,
    fixture: ProviderReplayFixture,
    selection_manifest_sha256: str,
    selected_refs: tuple[str, ...],
) -> ImageObservationV2:
    evidence_ref = selected_refs[0]
    observations: list[dict[str, object]] = []
    scores = dict(zip(tuple(SubattributeId), fixture.attribute_scores_milli, strict=True))
    for attribute_id in SubattributeId:
        observations.append(
            {
                "attribute_id": attribute_id.value,
                "status": "observed",
                "score_milli": scores[attribute_id],
                "uncertainty_bp": fixture.uncertainty_bp,
                "visible_evidence": [
                    {
                        "image_ref": evidence_ref,
                        "region": "합성 전경 중앙",
                        "caption_ko": f"합성 전경에서 {attribute_id.value}의 시각 단서가 보인다.",
                        "evidence_kind": "VISIBLE_CUE",
                    }
                ],
            }
        )
    axes = []
    for axis_id, members in IMAGE_OBSERVATION_V2_AXIS_MEMBERS.items():
        axis_score = (sum(scores[member] for member in members) + 2) // 4
        axes.append(
            {
                "axis_id": axis_id,
                "status": "observed",
                "score_milli": axis_score,
                "missing_attribute_ids": [],
                "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
            }
        )
    fields: dict[str, object] = {
        "schema_version": "photo-attributes.v2",
        "media_state": ImageMediumState.QUALIFIED.value,
        "representative_manifest_sha256": selection_manifest_sha256,
        "selected_image_refs": list(selected_refs),
        "observations": observations,
        "candidate_axes": axes,
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    return ImageObservationV2.model_validate(
        {**fields, "observation_sha256": canonical_sha256(fields)}
    )


def build_mock_replay_adapter(
    *,
    config: Glm5VProviderConfig,
    fixture: ProviderReplayFixture,
    clock: Clock,
) -> tuple[ZhipuGlm5VAdapter, httpx.AsyncClient]:
    """Build the only credential-free provider path used by tests and ordinary replay."""

    def handler(request: httpx.Request) -> httpx.Response:
        try:
            wire = json.loads(request.content)
            user_content = wire["messages"][1]["content"]
            selected_refs = tuple(
                part["text"].removeprefix("image_ref=")
                for part in user_content
                if part.get("type") == "text" and part.get("text", "").startswith("image_ref=")
            )
            if not selected_refs:
                raise ValueError("missing selected references")
            observation = _replay_observation(
                fixture=fixture,
                selection_manifest_sha256=config.selection_manifest_sha256,
                selected_refs=selected_refs,
            )
            envelope = {
                "id": "synthetic-completion-1",
                "request_id": fixture.provider_request_id,
                "model": "glm-5v-turbo",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": canonical_json_bytes(
                                observation.model_dump(mode="json")
                            ).decode("utf-8"),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": fixture.prompt_tokens,
                    "completion_tokens": fixture.completion_tokens,
                    "total_tokens": fixture.prompt_tokens + fixture.completion_tokens,
                },
            }
            return httpx.Response(200, content=canonical_json_bytes(envelope), request=request)
        except (KeyError, TypeError, ValueError):
            return httpx.Response(400, content=b"invalid synthetic replay request", request=request)

    client = build_glm5v_async_client(
        api_key="synthetic-replay-no-credential",
        config=config,
        transport=httpx.MockTransport(handler),
    )

    async def no_sleep(_seconds: float) -> None:
        return None

    adapter = ZhipuGlm5VAdapter(
        config=config,
        client=client,
        clock=clock,
        request_id_factory=lambda attempt: f"replay-attempt-{attempt}",
        sleeper=no_sleep,
    )
    return adapter, client


__all__ = [
    "FrozenObservationBatch",
    "FrozenPlaceObservation",
    "LabelEvaluationCapability",
    "ObservationExecutionMode",
    "PredictionBatchFreezeReceipt",
    "ProtectedImageCapabilityEntry",
    "ProtectedImageCapabilityManifest",
    "ProviderObservationCapability",
    "ProviderReplayFixture",
    "build_label_evaluation_capability",
    "build_mock_replay_adapter",
    "freeze_prediction_batch",
    "generate_dev_image_observations",
]
