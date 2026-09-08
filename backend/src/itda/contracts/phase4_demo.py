"""Strict, self-authenticating contracts for the local Phase 4 demo lane."""

from __future__ import annotations

import hashlib
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.provenance import (
    MAX_PROVIDER_RAW_BASE64_CHARS,
    extract_provider_modifiedtime,
    extract_upstream_rights,
    parse_provider_json_bytes,
    validate_provider_raw_bytes,
)
from itda.domain.canonical import canonical_sha256


class DemoSourceRole(StrEnum):
    TOUR_API = "TOUR_API"
    ODII = "ODII"
    TOURISM_PHOTO = "TOURISM_PHOTO"


_FROZEN_SOURCE_IDENTITIES = {
    DemoSourceRole.TOUR_API: (
        "KorService2/areaBasedList2",
        "15101578",
        None,
    ),
    DemoSourceRole.ODII: (
        "Odii/themeSearchList",
        "15101971",
        "ODII_DATASET_15101971",
    ),
    DemoSourceRole.TOURISM_PHOTO: (
        "PhotoGalleryService1/gallerySearchList1",
        "15101914",
        "KOGL_TYPE_1_ATTRIBUTION",
    ),
}
_SECRET_FRAGMENTS = (
    "servicekey",
    "api_key",
    "apikey",
    "token",
    "secret",
    "authorization",
)


class FrozenDemoSourceSnapshot(StrictContract):
    """Exact successful public-provider response accepted by the Phase 4 demo."""

    provider: DemoSourceRole
    endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    request_scope: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    retrieved_at: datetime
    http_status: Literal[200]
    raw_response_sha256: Sha256
    raw_body_base64: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=MAX_PROVIDER_RAW_BASE64_CHARS),
    ]
    modifiedtime: Annotated[str | None, Field(strict=True, min_length=1, max_length=80)] = None
    rights: tuple[dict[str, str], ...]
    payload: Any
    provider_result_code: Literal["0000"]
    provider_result_value: Literal["OK"]
    normalized_outcome: Literal["SUCCESS"]
    retry_disposition: Literal["DO_NOT_RETRY"]
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    dataset_rights_identity: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=120)
    ] = None

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @field_validator("request_scope")
    @classmethod
    def request_scope_must_be_secret_free(cls, value: dict[str, str]) -> dict[str, str]:
        if any(fragment in key.casefold() for key in value for fragment in _SECRET_FRAGMENTS):
            raise ValueError("frozen source request scope must exclude credentials")
        return value

    @model_validator(mode="after")
    def validate_exact_public_source(self) -> Self:
        endpoint, dataset_id, rights_identity = _FROZEN_SOURCE_IDENTITIES[self.provider]
        if (
            self.endpoint != endpoint
            or self.official_dataset_id != dataset_id
            or self.dataset_rights_identity != rights_identity
        ):
            raise ValueError("frozen source identity is outside the exact public demo scope")
        try:
            raw_body = b64decode(self.raw_body_base64, validate=True)
        except (Base64Error, ValueError) as exc:
            raise ValueError("raw_body_base64 must be strict base64") from exc
        validate_provider_raw_bytes(raw_body)
        if b64encode(raw_body).decode("ascii") != self.raw_body_base64:
            raise ValueError("raw_body_base64 must use canonical standard base64")
        if hashlib.sha256(raw_body).hexdigest() != self.raw_response_sha256:
            raise ValueError("raw response hash does not match exact base64 body")
        payload = parse_provider_json_bytes(raw_body)
        if payload != self.payload:
            raise ValueError("snapshot payload does not match exact raw response body")
        if extract_provider_modifiedtime(payload) != self.modifiedtime:
            raise ValueError("modifiedtime projection does not match exact raw response body")
        if extract_upstream_rights(payload) != self.rights:
            raise ValueError("rights projection does not match exact raw response body")
        return self


class DemoSourceDisposition(StrEnum):
    SUPPORTING_SOURCE_EVIDENCE = "SUPPORTING_SOURCE_EVIDENCE"
    EXACT_DEV_CLAIM_BINDING = "EXACT_DEV_CLAIM_BINDING"
    NO_EXACT_DEV_CLAIM_BINDING = "NO_EXACT_DEV_CLAIM_BINDING"


class DemoProviderMode(StrEnum):
    NO_PROVIDER_NO_IMAGE = "NO_PROVIDER_NO_IMAGE"
    PROVIDER_REPLAY = "PROVIDER_REPLAY"
    LIVE_PAID_PROVIDER = "LIVE_PAID_PROVIDER"


class DemoInputSnapshotAuthority(StrictContract):
    relative_name: Annotated[
        str,
        Field(strict=True, pattern=r"^(ODII|TOURISM_PHOTO|TOUR_API)-[A-Za-z0-9-]+\.json$"),
    ]
    byte_sha256: Sha256
    byte_count: Annotated[int, Field(strict=True, gt=0)]


class DemoZeroImageMember(StrictContract):
    place_ref: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    status: Literal["NO_IMAGE"] = "NO_IMAGE"


class Phase4DemoZeroImageAbsenceRegistry(StrictContract):
    schema_version: Literal["itda.phase4-demo-zero-image-absence-registry.v1"] = (
        "itda.phase4-demo-zero-image-absence-registry.v1"
    )
    image_namespace_state: Literal["ABSENT", "EMPTY"]
    members: Annotated[tuple[DemoZeroImageMember, ...], Field(min_length=24, max_length=24)]
    registry_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        place_refs = tuple(member.place_ref for member in self.members)
        if place_refs != tuple(sorted(place_refs)) or len(set(place_refs)) != 24:
            raise ValueError("zero-image registry requires exact ordered DEV membership")
        expected = canonical_sha256(self.model_dump(exclude={"registry_sha256"}, mode="json"))
        if self.registry_sha256 is None:
            object.__setattr__(self, "registry_sha256", expected)
        elif self.registry_sha256 != expected:
            raise ValueError("zero-image registry digest is stale")
        return self


class Phase4DemoInputAuthority(StrictContract):
    schema_version: Literal["itda.phase4-demo-input-authority.v1"] = (
        "itda.phase4-demo-input-authority.v1"
    )
    catalog_sha256: Sha256
    catalog_root_sha256: Sha256
    dev_sqlite_sha256: Sha256
    sqlite_seal_receipt_sha256: Sha256
    sqlite_logical_seal_sha256: Sha256
    dev_membership_sha256: Sha256
    dev_place_refs: Annotated[tuple[str, ...], Field(min_length=24, max_length=24)]
    collection_report_sha256: Sha256
    snapshot_inventory: Annotated[
        tuple[DemoInputSnapshotAuthority, ...], Field(min_length=33, max_length=33)
    ]
    snapshot_inventory_sha256: Sha256
    optional_media_sha256: Sha256
    optional_media_root_sha256: Sha256
    replay_fixture_sha256: Sha256
    replay_fixture_contract_sha256: Sha256
    image_mode: Literal["RIGHTS_REVIEWED_IMAGES", "ZERO_IMAGE"]
    image_namespace_sha256: Sha256 | None = None
    rights_manifest_sha256: Sha256 | None = None
    image_selection_manifest_sha256: Sha256 | None = None
    zero_image_absence_registry_sha256: Sha256 | None = None
    authority_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_complete_authority(self) -> Self:
        if (
            self.dev_place_refs != tuple(sorted(self.dev_place_refs))
            or len(set(self.dev_place_refs)) != 24
        ):
            raise ValueError("demo input authority requires exact ordered DEV membership")
        snapshot_order = tuple(row.relative_name for row in self.snapshot_inventory)
        if snapshot_order != tuple(sorted(snapshot_order)) or len(set(snapshot_order)) != 33:
            raise ValueError("demo input authority snapshot inventory is not exhaustive")
        if self.snapshot_inventory_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.snapshot_inventory]
        ):
            raise ValueError("demo input authority snapshot root is stale")
        image_values = (
            self.image_namespace_sha256,
            self.rights_manifest_sha256,
            self.image_selection_manifest_sha256,
        )
        if self.image_mode == "RIGHTS_REVIEWED_IMAGES":
            if not all(image_values) or self.zero_image_absence_registry_sha256 is not None:
                raise ValueError("image-bearing authority must be complete and exclusive")
        elif any(image_values) or self.zero_image_absence_registry_sha256 is None:
            raise ValueError("zero-image authority must bind only its absence registry")
        expected = canonical_sha256(self.model_dump(exclude={"authority_sha256"}, mode="json"))
        if self.authority_sha256 is None:
            object.__setattr__(self, "authority_sha256", expected)
        elif self.authority_sha256 != expected:
            raise ValueError("demo input authority digest is stale")
        return self


def _validate_terminal_state(
    *,
    provider_mode: DemoProviderMode,
    terminal_decision: str,
    image_review_gate: str,
    image_claim_inventory_count: int,
    human_decision_receipt_sha256: str | None,
    image_truth: str,
) -> None:
    no_image = provider_mode is DemoProviderMode.NO_PROVIDER_NO_IMAGE
    valid = (
        terminal_decision == "NO_IMAGE_TEXT_ODII_ONLY"
        and image_review_gate == "NOT_APPLICABLE"
        and image_claim_inventory_count == 0
        and human_decision_receipt_sha256 is None
        and image_truth == "NO_IMAGE_TEXT_ODII_ONLY"
        if no_image
        else provider_mode is DemoProviderMode.PROVIDER_REPLAY
        and terminal_decision == "PROVIDER_REPLAY_REVIEWED"
        and image_review_gate == "COMPLETED"
        and image_claim_inventory_count > 0
        and human_decision_receipt_sha256 is not None
        and image_truth == "REAL_LOCAL_IMAGES"
    )
    if not valid:
        raise ValueError("terminal truth fields do not form an approved exhaustive state")


class DemoSourceInventoryEntry(StrictContract):
    role: DemoSourceRole
    logical_path_sha256: Sha256
    source_sha256: Sha256
    provider_payload_sha256: Sha256 | None = None
    disposition: DemoSourceDisposition
    supporting_claim_sha256s: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.supporting_claim_sha256s != tuple(sorted(set(self.supporting_claim_sha256s))):
            raise ValueError("source claim references require unique canonical order")
        if self.role is DemoSourceRole.TOURISM_PHOTO:
            if self.disposition is DemoSourceDisposition.SUPPORTING_SOURCE_EVIDENCE:
                raise ValueError("tourism-photo source requires an exact disposition")
            if (self.disposition is DemoSourceDisposition.EXACT_DEV_CLAIM_BINDING) != bool(
                self.supporting_claim_sha256s
            ):
                raise ValueError("tourism-photo claim binding does not match its evidence")
        elif self.disposition is not DemoSourceDisposition.SUPPORTING_SOURCE_EVIDENCE:
            raise ValueError("non-photo snapshots use the supporting-source disposition")
        return self


class DemoDevPlace(StrictContract):
    place_ref: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    catalog_row_sha256: Sha256
    optional_media_row_sha256: Sha256
    image_medium_state: ImageMediumState
    selected_image_count: Annotated[int, Field(strict=True, ge=0, le=5)]
    odii_lineage: Literal["EXACT_ODII_LINEAGE", "ODII_UNAVAILABLE"]


class DemoSelectedImage(StrictContract):
    place_ref: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    source_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    representative_id: Sha256
    source_content_sha256: Sha256
    selected_asset_sha256: Sha256
    normalized_pixel_sha256: Sha256
    rights_leaf_sha256: Sha256
    materialization_sha256: Sha256
    preprocessing_policy_sha256: Sha256


class Phase4DemoManifest(StrictContract):
    schema_version: Literal["itda.phase4-demo-manifest.v2"]
    input_sha256: dict[str, Sha256]
    snapshot_inventory_sha256: Sha256
    dev_projection_sha256: Sha256
    selected_image_inventory_sha256: Sha256
    source_inventory: tuple[DemoSourceInventoryEntry, ...]
    dev_places: tuple[DemoDevPlace, ...] = Field(min_length=24, max_length=24)
    selected_images: tuple[DemoSelectedImage, ...]
    source_truth: Literal["REAL_LOCAL_DATA", "LOCAL_COLLECTION_AUTHORITY_PARTIAL"]
    profile_truth: Literal["SOURCE_EVIDENCE_ONLY"]
    profile_score_truth: Literal["NO_LOCAL_PROFILE_SCORES"]
    image_truth: Literal["NO_IMAGE_TEXT_ODII_ONLY", "REAL_LOCAL_IMAGES"]
    benchmark_truth: Literal["NO_REAL_IMAGE_BENCHMARK"]
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if tuple(self.input_sha256) != tuple(sorted(self.input_sha256)):
            raise ValueError("demo inputs require canonical key order")
        source_order = tuple(
            (row.role.value, row.logical_path_sha256) for row in self.source_inventory
        )
        if source_order != tuple(sorted(source_order)) or len(set(source_order)) != len(
            source_order
        ):
            raise ValueError("demo source inventory requires unique canonical order")
        place_ids = tuple(row.place_ref for row in self.dev_places)
        if place_ids != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
            raise ValueError("demo manifest requires 24 unique ordered DEV places")
        image_order = tuple(
            (row.place_ref, row.source_asset_id, row.representative_id)
            for row in self.selected_images
        )
        if image_order != tuple(sorted(image_order)) or len(set(image_order)) != len(image_order):
            raise ValueError("selected images require unique canonical order")
        selected_counts = {
            place_ref: sum(row.place_ref == place_ref for row in self.selected_images)
            for place_ref in place_ids
        }
        if any(
            row.selected_image_count != selected_counts[row.place_ref] for row in self.dev_places
        ):
            raise ValueError("selected image counts do not match the private inventory")
        if self.snapshot_inventory_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.source_inventory]
        ):
            raise ValueError("snapshot inventory digest is stale")
        if self.dev_projection_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.dev_places]
        ):
            raise ValueError("DEV projection digest is stale")
        if self.selected_image_inventory_sha256 != canonical_sha256(
            [row.model_dump(mode="json") for row in self.selected_images]
        ):
            raise ValueError("selected image inventory digest is stale")
        if (self.image_truth == "REAL_LOCAL_IMAGES") != bool(self.selected_images):
            raise ValueError("image truth marker does not match selected local bytes")
        all_odii_exact = all(row.odii_lineage == "EXACT_ODII_LINEAGE" for row in self.dev_places)
        if (self.source_truth == "REAL_LOCAL_DATA") != all_odii_exact:
            raise ValueError("source truth must disclose incomplete per-place Odii lineage")
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 != expected:
            raise ValueError("phase4 demo manifest digest is stale")
        return self


class Phase4DemoMaterializationReceipt(StrictContract):
    schema_version: Literal["itda.phase4-demo-materialization-receipt.v2"]
    manifest_sha256: Sha256
    input_inventory_sha256: Sha256
    snapshot_inventory_sha256: Sha256
    dev_projection_sha256: Sha256
    selected_image_inventory_sha256: Sha256
    dev_row_count: Literal[24]
    snapshot_counts: dict[str, Annotated[int, Field(strict=True, ge=0)]]
    tourism_photo_included_count: Annotated[int, Field(strict=True, ge=0)]
    tourism_photo_excluded_count: Annotated[int, Field(strict=True, ge=0)]
    selected_image_count: Annotated[int, Field(strict=True, ge=0, le=120)]
    source_truth: Literal["REAL_LOCAL_DATA", "LOCAL_COLLECTION_AUTHORITY_PARTIAL"]
    profile_truth: Literal["SOURCE_EVIDENCE_ONLY"]
    profile_score_truth: Literal["NO_LOCAL_PROFILE_SCORES"]
    image_truth: Literal["NO_IMAGE_TEXT_ODII_ONLY", "REAL_LOCAL_IMAGES"]
    benchmark_truth: Literal["NO_REAL_IMAGE_BENCHMARK"]
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        expected_roles = {role.value for role in DemoSourceRole}
        if set(self.snapshot_counts) != expected_roles or len(self.snapshot_counts) != len(
            expected_roles
        ):
            raise ValueError("snapshot counts require the closed source-role order")
        if self.snapshot_counts[DemoSourceRole.TOURISM_PHOTO.value] != (
            self.tourism_photo_included_count + self.tourism_photo_excluded_count
        ):
            raise ValueError("tourism-photo dispositions do not exhaust the inventory")
        if (self.image_truth == "REAL_LOCAL_IMAGES") != (self.selected_image_count > 0):
            raise ValueError("receipt image truth does not match selected count")
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 != expected:
            raise ValueError("materialization receipt digest is stale")
        return self


def derive_materialization_receipt(
    manifest: Phase4DemoManifest,
) -> Phase4DemoMaterializationReceipt:
    """Derive the complete public receipt from the private manifest authority."""

    snapshot_counts = {
        role.value: sum(row.role is role for row in manifest.source_inventory)
        for role in DemoSourceRole
    }
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-materialization-receipt.v2",
        "manifest_sha256": manifest.manifest_sha256,
        "input_inventory_sha256": canonical_sha256(manifest.input_sha256),
        "snapshot_inventory_sha256": manifest.snapshot_inventory_sha256,
        "dev_projection_sha256": manifest.dev_projection_sha256,
        "selected_image_inventory_sha256": manifest.selected_image_inventory_sha256,
        "dev_row_count": len(manifest.dev_places),
        "snapshot_counts": snapshot_counts,
        "tourism_photo_included_count": sum(
            row.role is DemoSourceRole.TOURISM_PHOTO
            and row.disposition is DemoSourceDisposition.EXACT_DEV_CLAIM_BINDING
            for row in manifest.source_inventory
        ),
        "tourism_photo_excluded_count": sum(
            row.role is DemoSourceRole.TOURISM_PHOTO
            and row.disposition is DemoSourceDisposition.NO_EXACT_DEV_CLAIM_BINDING
            for row in manifest.source_inventory
        ),
        "selected_image_count": len(manifest.selected_images),
        "source_truth": manifest.source_truth,
        "profile_truth": manifest.profile_truth,
        "profile_score_truth": manifest.profile_score_truth,
        "image_truth": manifest.image_truth,
        "benchmark_truth": manifest.benchmark_truth,
    }
    return Phase4DemoMaterializationReceipt.model_validate(
        {**fields, "receipt_sha256": canonical_sha256(fields)}
    )


class Phase4DemoPredictionReceipt(StrictContract):
    schema_version: Literal["itda.phase4-demo-prediction-receipt.v1"]
    materialization_receipt_sha256: Sha256
    manifest_sha256: Sha256
    observation_batch_sha256: Sha256
    freeze_receipt_sha256: Sha256
    observation_count: Literal[24]
    provider_mode: DemoProviderMode
    image_claim_inventory_count: Annotated[int, Field(strict=True, ge=0, le=120)]
    source_truth: Literal["REAL_LOCAL_DATA", "LOCAL_COLLECTION_AUTHORITY_PARTIAL"]
    profile_truth: Literal["SOURCE_EVIDENCE_ONLY"]
    profile_score_truth: Literal["NO_LOCAL_PROFILE_SCORES"]
    image_truth: Literal["NO_IMAGE_TEXT_ODII_ONLY", "REAL_LOCAL_IMAGES"]
    benchmark_truth: Literal["NO_REAL_IMAGE_BENCHMARK", "REAL_IMAGE_BENCHMARK"]
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_prediction_receipt(self) -> Self:
        if self.provider_mode is DemoProviderMode.NO_PROVIDER_NO_IMAGE and (
            self.image_claim_inventory_count != 0
            or self.image_truth != "NO_IMAGE_TEXT_ODII_ONLY"
            or self.benchmark_truth != "NO_REAL_IMAGE_BENCHMARK"
        ):
            raise ValueError("no-provider prediction receipt must remain fact-free")
        if self.provider_mode is DemoProviderMode.PROVIDER_REPLAY and (
            self.benchmark_truth != "NO_REAL_IMAGE_BENCHMARK"
        ):
            raise ValueError("provider replay cannot claim a real image benchmark")
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 != expected:
            raise ValueError("prediction receipt digest is stale")
        return self


class Phase4DemoEvaluationPreparation(StrictContract):
    schema_version: Literal["itda.phase4-demo-evaluation-preparation.v1"]
    materialization_receipt_sha256: Sha256
    prediction_receipt_sha256: Sha256
    manifest_sha256: Sha256
    observation_batch_sha256: Sha256
    freeze_receipt_sha256: Sha256
    evaluator_authority_binding_sha256: Sha256
    label_input_sha256: Sha256 | None
    evaluation_state: Literal["NOT_EVALUATED_NO_LOCAL_PROFILE_SCORES"]
    image_claim_inventory_count: Annotated[int, Field(strict=True, ge=0, le=120)]
    preparation_sha256: Sha256

    @model_validator(mode="after")
    def validate_preparation(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"preparation_sha256"}, mode="json"))
        if self.preparation_sha256 != expected:
            raise ValueError("evaluation preparation digest is stale")
        return self


class DemoImageReviewItem(StrictContract):
    stable_observation_sha256: Sha256
    attribute_id: Annotated[str, Field(strict=True, pattern=r"^(H|I|R)[1-4]$")]
    selected_image_ref: Annotated[str, Field(strict=True, pattern=r"^selected-image:[0-9a-f]{64}$")]
    region: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    caption_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    inventory_item_sha256: Sha256

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"inventory_item_sha256"}, mode="json"))
        if self.inventory_item_sha256 != expected:
            raise ValueError("review inventory item digest is stale")
        return self


class Phase4DemoReviewInventory(StrictContract):
    schema_version: Literal["itda.phase4-demo-review-inventory.v1"]
    prediction_batch_sha256: Sha256
    items: Annotated[tuple[DemoImageReviewItem, ...], Field(min_length=1)]
    inventory_sha256: Sha256

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        item_ids = tuple(item.inventory_item_sha256 for item in self.items)
        if item_ids != tuple(sorted(item_ids)) or len(set(item_ids)) != len(item_ids):
            raise ValueError("review inventory requires unique canonical item order")
        expected = canonical_sha256(self.model_dump(exclude={"inventory_sha256"}, mode="json"))
        if self.inventory_sha256 != expected:
            raise ValueError("review inventory digest is stale")
        return self


class DemoImageReviewDecision(StrictContract):
    inventory_item_sha256: Sha256
    verdict: Literal["SUPPORTED", "NON_VISIBLE", "PHANTOM_REF", "UNSUPPORTED"]


class Phase4DemoReviewDecisions(StrictContract):
    schema_version: Literal["itda.phase4-demo-review-decisions.v1"]
    inventory_sha256: Sha256
    entries: Annotated[tuple[DemoImageReviewDecision, ...], Field(min_length=1)]
    reviewer_pseudonym: Annotated[str, Field(strict=True, min_length=3, max_length=100)]
    decisions_sha256: Sha256

    @model_validator(mode="after")
    def validate_decisions(self) -> Self:
        item_ids = tuple(entry.inventory_item_sha256 for entry in self.entries)
        if item_ids != tuple(sorted(item_ids)) or len(set(item_ids)) != len(item_ids):
            raise ValueError("review decisions require unique canonical item order")
        expected = canonical_sha256(self.model_dump(exclude={"decisions_sha256"}, mode="json"))
        if self.decisions_sha256 != expected:
            raise ValueError("review decisions digest is stale")
        return self


class Phase4DemoTerminalReport(StrictContract):
    schema_version: Literal["itda.phase4-demo-terminal-report.v1"]
    manifest_sha256: Sha256
    materialization_receipt_sha256: Sha256
    prediction_receipt_sha256: Sha256
    evaluation_preparation_sha256: Sha256
    observation_batch_sha256: Sha256
    freeze_receipt_sha256: Sha256
    provider_mode: Literal[DemoProviderMode.NO_PROVIDER_NO_IMAGE, DemoProviderMode.PROVIDER_REPLAY]
    terminal_decision: Literal["NO_IMAGE_TEXT_ODII_ONLY", "PROVIDER_REPLAY_REVIEWED"]
    image_review_gate: Literal["NOT_APPLICABLE", "COMPLETED"]
    image_claim_inventory_count: Annotated[int, Field(strict=True, ge=0, le=120)]
    human_decision_receipt_sha256: Sha256 | None
    source_truth: Literal["REAL_LOCAL_DATA", "LOCAL_COLLECTION_AUTHORITY_PARTIAL"]
    profile_truth: Literal["SOURCE_EVIDENCE_ONLY"]
    profile_score_truth: Literal["NO_LOCAL_PROFILE_SCORES"]
    image_truth: Literal["NO_IMAGE_TEXT_ODII_ONLY", "REAL_LOCAL_IMAGES"]
    benchmark_truth: Literal["NO_REAL_IMAGE_BENCHMARK"]
    terminal_report_sha256: Sha256

    @model_validator(mode="after")
    def validate_terminal_report(self) -> Self:
        _validate_terminal_state(
            provider_mode=self.provider_mode,
            terminal_decision=self.terminal_decision,
            image_review_gate=self.image_review_gate,
            image_claim_inventory_count=self.image_claim_inventory_count,
            human_decision_receipt_sha256=self.human_decision_receipt_sha256,
            image_truth=self.image_truth,
        )
        expected = canonical_sha256(
            self.model_dump(exclude={"terminal_report_sha256"}, mode="json")
        )
        if self.terminal_report_sha256 != expected:
            raise ValueError("terminal report digest is stale")
        return self


class Phase4DemoTerminalReceipt(StrictContract):
    schema_version: Literal["itda.phase4-demo-terminal-receipt.v1"]
    manifest_sha256: Sha256
    materialization_receipt_sha256: Sha256
    prediction_receipt_sha256: Sha256
    evaluation_preparation_sha256: Sha256
    terminal_report_sha256: Sha256
    provider_mode: Literal[DemoProviderMode.NO_PROVIDER_NO_IMAGE, DemoProviderMode.PROVIDER_REPLAY]
    terminal_decision: Literal["NO_IMAGE_TEXT_ODII_ONLY", "PROVIDER_REPLAY_REVIEWED"]
    image_review_gate: Literal["NOT_APPLICABLE", "COMPLETED"]
    image_claim_inventory_count: Annotated[int, Field(strict=True, ge=0, le=120)]
    human_decision_receipt_sha256: Sha256 | None
    source_truth: Literal["REAL_LOCAL_DATA", "LOCAL_COLLECTION_AUTHORITY_PARTIAL"]
    profile_truth: Literal["SOURCE_EVIDENCE_ONLY"]
    profile_score_truth: Literal["NO_LOCAL_PROFILE_SCORES"]
    image_truth: Literal["NO_IMAGE_TEXT_ODII_ONLY", "REAL_LOCAL_IMAGES"]
    benchmark_truth: Literal["NO_REAL_IMAGE_BENCHMARK"]
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_terminal_receipt(self) -> Self:
        _validate_terminal_state(
            provider_mode=self.provider_mode,
            terminal_decision=self.terminal_decision,
            image_review_gate=self.image_review_gate,
            image_claim_inventory_count=self.image_claim_inventory_count,
            human_decision_receipt_sha256=self.human_decision_receipt_sha256,
            image_truth=self.image_truth,
        )
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 != expected:
            raise ValueError("terminal receipt digest is stale")
        return self


def validate_terminal_receipt_report(
    receipt: Phase4DemoTerminalReceipt,
    report: Phase4DemoTerminalReport,
) -> None:
    mirrored_fields = (
        "manifest_sha256",
        "materialization_receipt_sha256",
        "prediction_receipt_sha256",
        "evaluation_preparation_sha256",
        "provider_mode",
        "terminal_decision",
        "image_review_gate",
        "image_claim_inventory_count",
        "human_decision_receipt_sha256",
        "source_truth",
        "profile_truth",
        "profile_score_truth",
        "image_truth",
        "benchmark_truth",
    )
    if receipt.terminal_report_sha256 != report.terminal_report_sha256 or any(
        getattr(receipt, field) != getattr(report, field) for field in mirrored_fields
    ):
        raise ValueError("terminal receipt does not mirror its referenced report")


__all__ = [
    "DemoDevPlace",
    "DemoImageReviewDecision",
    "DemoImageReviewItem",
    "DemoInputSnapshotAuthority",
    "DemoProviderMode",
    "DemoSelectedImage",
    "DemoSourceDisposition",
    "DemoSourceInventoryEntry",
    "DemoSourceRole",
    "DemoZeroImageMember",
    "Phase4DemoInputAuthority",
    "Phase4DemoManifest",
    "Phase4DemoMaterializationReceipt",
    "Phase4DemoEvaluationPreparation",
    "Phase4DemoPredictionReceipt",
    "Phase4DemoReviewDecisions",
    "Phase4DemoReviewInventory",
    "Phase4DemoTerminalReceipt",
    "Phase4DemoTerminalReport",
    "Phase4DemoZeroImageAbsenceRegistry",
    "validate_terminal_receipt_report",
]
