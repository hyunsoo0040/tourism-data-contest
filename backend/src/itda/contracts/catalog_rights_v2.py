"""Hash-bound Phase 2 rights and per-place objective-evidence contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_audit import (
    CatalogAsset,
    DatasetGrantEvidence,
    RightsState,
    decide_asset_rights,
)
from itda.domain.canonical import canonical_sha256

EXPECTED_DATASET_IDS = ("15101578", "15101971", "15101914")


class GateState(StrEnum):
    PASS = "PASS"
    MISSING = "MISSING"
    BLOCKED = "BLOCKED"


class DatasetGrantRightsRow(StrictContract):
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    official_page_url: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    retrieved_at: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    response_sha256: Sha256
    page_sha256: Sha256
    dataset_grant_sha256: Sha256
    evidence_state: Literal["COMPLETE", "MISSING", "INCOMPLETE"]
    license_type: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    attribution_text: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    commercial_use_allowed: Annotated[bool, Field(strict=True)]
    transform_allowed: Annotated[bool, Field(strict=True)]
    display_allowed: Annotated[bool, Field(strict=True)]
    model_input_allowed: Annotated[bool, Field(strict=True)]
    explicit_restrictions: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=500)], ...
    ]
    allowed: Annotated[bool, Field(strict=True)]
    reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...
    ]
    evidence_refs: tuple[Sha256, ...]
    leaf_sha256: Sha256

    @model_validator(mode="after")
    def validate_grant_row(self) -> Self:
        expected_allowed = self.evidence_state == "COMPLETE" and all(
            (
                self.commercial_use_allowed,
                self.transform_allowed,
                self.display_allowed,
                self.model_input_allowed,
            )
        )
        if self.allowed != expected_allowed:
            raise ValueError("dataset grant allowed state does not match exact terms")
        if not self.reason_codes or not self.evidence_refs:
            raise ValueError("dataset grant requires reasons and exact evidence")
        expected = canonical_sha256(
            self.model_dump(exclude={"leaf_sha256"}, mode="json")
        )
        if self.leaf_sha256 != expected:
            raise ValueError("dataset grant rights leaf hash does not match")
        return self


class AssetRightsRow(StrictContract):
    source_candidate_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    dataset_record_entity_id: Annotated[
        str | None,
        Field(strict=True, pattern=r"^dataset:[0-9a-f]{64}$"),
    ] = None
    source_audit_sha256: Sha256 | None = None
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    source_asset_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    content_kind: Literal[
        "TOURAPI_DESCRIPTION",
        "ODII_SCRIPT_AUDIO_TEXT",
        "TOURISM_PHOTO_ASSET",
    ]
    source_request_sha256: Sha256 | None = None
    source_response_sha256: Sha256 | None = None
    original_url: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=2_000)
    ] = None
    creator_or_photographer: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=300)
    ] = None
    license_type: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=120)
    ] = None
    attribution_text: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    explicit_asset_restriction: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    dataset_grant_sha256: Sha256
    rights_state: RightsState
    reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...
    ]
    commercial_use_allowed: Annotated[bool, Field(strict=True)]
    transform_allowed: Annotated[bool, Field(strict=True)]
    display_allowed: Annotated[bool, Field(strict=True)]
    model_input_allowed: Annotated[bool, Field(strict=True)]
    analysis_eligible: Annotated[bool, Field(strict=True)]
    ui_eligible: Annotated[bool, Field(strict=True)]
    demo_eligible: Annotated[bool, Field(strict=True)]
    confidence_adds_score: Literal[False] = False
    evidence_refs: tuple[Sha256, ...]
    leaf_sha256: Sha256

    @model_validator(mode="after")
    def validate_asset_row(self) -> Self:
        if not self.reason_codes or not self.evidence_refs:
            raise ValueError("asset rights require reasons and exact evidence")
        lanes = (
            self.analysis_eligible,
            self.ui_eligible,
            self.demo_eligible,
        )
        if self.rights_state is RightsState.ALLOWED:
            if not all(lanes):
                raise ValueError("allowed asset rights must pass every downstream lane")
        elif any(
            lanes
            + (
                self.commercial_use_allowed,
                self.transform_allowed,
                self.display_allowed,
                self.model_input_allowed,
            )
        ):
            raise ValueError("blocked asset rights cannot authorize a downstream lane")
        expected = canonical_sha256(
            self.model_dump(exclude={"leaf_sha256"}, mode="json")
        )
        if self.leaf_sha256 != expected:
            raise ValueError("asset rights leaf hash does not match")
        return self


def project_asset_rights(
    asset: CatalogAsset,
    grant: DatasetGrantEvidence,
    *,
    source_candidate_id: str | None = None,
    dataset_record_entity_id: str | None = None,
    source_audit_sha256: str | None = None,
) -> AssetRightsRow:
    """Re-derive one asset decision from its exact dataset grant and provenance."""

    disposition = decide_asset_rights(asset, grant)
    evidence_refs = tuple(
        sorted(
            {
                grant.response_sha256,
                grant.page_sha256,
                grant.dataset_grant_sha256,
                *(
                    value
                    for value in (
                        asset.source_request_sha256,
                        asset.source_response_sha256,
                        source_audit_sha256,
                    )
                    if value is not None
                ),
            }
        )
    )
    fields = {
        "source_candidate_id": source_candidate_id,
        "dataset_record_entity_id": dataset_record_entity_id,
        "source_audit_sha256": source_audit_sha256,
        **asset.model_dump(mode="json"),
        "dataset_grant_sha256": grant.dataset_grant_sha256,
        "rights_state": disposition.rights_state.value,
        "reason_codes": disposition.reason_codes,
        "commercial_use_allowed": disposition.commercial_use_allowed,
        "transform_allowed": disposition.transform_allowed,
        "display_allowed": disposition.display_allowed,
        "model_input_allowed": disposition.model_input_allowed,
        "analysis_eligible": disposition.analysis_eligible,
        "ui_eligible": disposition.ui_eligible,
        "demo_eligible": disposition.demo_eligible,
        "confidence_adds_score": False,
        "evidence_refs": evidence_refs,
    }
    return AssetRightsRow(**fields, leaf_sha256=canonical_sha256(fields))


class AttachmentRightsRow(StrictContract):
    source_relationship_row_id: Annotated[
        str, Field(strict=True, pattern=r"^relationship:[0-9a-f]{64}$")
    ]
    source_attachment_leaf_sha256: Sha256
    source_place_candidate_id: Annotated[
        str, Field(strict=True, min_length=1, max_length=200)
    ]
    source_photo_candidate_id: Annotated[
        str, Field(strict=True, min_length=1, max_length=200)
    ]
    source_asset_id: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    place_entity_id: Annotated[
        str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")
    ]
    photo_entity_id: Annotated[
        str, Field(strict=True, pattern=r"^photo:[0-9a-f]{64}$")
    ]
    owner_dataset_entity_id: Annotated[
        str, Field(strict=True, pattern=r"^dataset:[0-9a-f]{64}$")
    ]
    attachment_rights_granting: Literal[False]
    identity_merging: Literal[False]
    asset_rights_leaf_sha256: Sha256
    rights_state: RightsState
    reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...
    ]
    evidence_refs: tuple[Sha256, ...]
    leaf_sha256: Sha256

    @model_validator(mode="after")
    def validate_attachment_rights(self) -> Self:
        if not self.reason_codes or not self.evidence_refs:
            raise ValueError("attachment rights require exact independent evidence")
        expected = canonical_sha256(
            self.model_dump(exclude={"leaf_sha256"}, mode="json")
        )
        if self.leaf_sha256 != expected:
            raise ValueError("attachment rights leaf hash does not match")
        return self


class RightsProjectionParents(StrictContract):
    entity_policy_file_sha256: Sha256
    entity_policy_report_sha256: Sha256
    formal_policy_sha256: Sha256
    immutability_manifest_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_inputs_sha256: Sha256
    entity_projection_file_sha256: Sha256
    entity_projection_sha256: Sha256
    crosswalk_dispositions_root: Sha256
    relationship_dispositions_root: Sha256
    complete_dispositions_root: Sha256
    media_attachments_root: Sha256
    phase1_rights_tree_sha256: Sha256
    cross_provider_place_auto_link_count: Literal[0]


class RightsProjection(StrictContract):
    schema_version: Literal["catalog-rights-projection-v2"]
    data_version: Literal["catalog-v2-rights-data-v1"]
    parents: RightsProjectionParents
    code_hashes: dict[str, Sha256]
    config_hashes: dict[str, Sha256]
    phase1_rights_files: dict[str, Sha256]
    dataset_grants: tuple[DatasetGrantRightsRow, ...]
    asset_rights: tuple[AssetRightsRow, ...]
    attachment_rights: tuple[AttachmentRightsRow, ...]
    counts: dict[str, Annotated[int, Field(strict=True, ge=0)]]
    roots: dict[str, Sha256]
    confidence_is_qualification_filter_only: Literal[True]
    confidence_adds_score: Literal[False]
    projection_sha256: Sha256

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if tuple(row.official_dataset_id for row in self.dataset_grants) != (
            EXPECTED_DATASET_IDS
        ):
            raise ValueError("rights projection must keep the three exact grants separate")
        candidate_ids = tuple(row.source_candidate_id for row in self.asset_rights)
        if any(item is None for item in candidate_ids):
            raise ValueError("projected asset rights require exact candidate identity")
        if candidate_ids != tuple(sorted(candidate_ids)):
            raise ValueError("asset rights must use canonical candidate order")
        attachment_ids = tuple(
            row.source_relationship_row_id for row in self.attachment_rights
        )
        if attachment_ids != tuple(sorted(attachment_ids)):
            raise ValueError("attachment rights must use canonical relationship order")
        expected_counts = {
            "dataset_grant_count": len(self.dataset_grants),
            "asset_rights_count": len(self.asset_rights),
            "attachment_rights_count": len(self.attachment_rights),
            "allowed_asset_count": sum(
                row.rights_state is RightsState.ALLOWED for row in self.asset_rights
            ),
            "blocked_asset_count": sum(
                row.rights_state is not RightsState.ALLOWED for row in self.asset_rights
            ),
        }
        if self.counts != expected_counts:
            raise ValueError("rights projection counts are not leaf-derived")
        expected_roots = {
            "dataset_grants": canonical_sha256(
                [row.model_dump(mode="json") for row in self.dataset_grants]
            ),
            "asset_rights": canonical_sha256(
                [row.model_dump(mode="json") for row in self.asset_rights]
            ),
            "attachment_rights": canonical_sha256(
                [row.model_dump(mode="json") for row in self.attachment_rights]
            ),
            "phase1_rights_files": canonical_sha256(self.phase1_rights_files),
        }
        if self.roots != expected_roots:
            raise ValueError("rights projection roots are not leaf-derived")
        expected = canonical_sha256(
            self.model_dump(exclude={"projection_sha256"}, mode="json")
        )
        if self.projection_sha256 != expected:
            raise ValueError("rights projection hash does not match")
        return self


class ObjectiveGate(StrictContract):
    state: GateState
    current_values: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=2_000)], ...
    ]
    reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...
    ]
    evidence_refs: tuple[Sha256, ...]

    @model_validator(mode="after")
    def validate_gate(self) -> Self:
        if not self.reason_codes or not self.evidence_refs:
            raise ValueError("objective gate requires explicit reasons and evidence")
        if self.state is GateState.PASS and not self.current_values:
            raise ValueError("passing objective gate requires a current value")
        return self


class CandidateObjectiveRow(StrictContract):
    place_entity_id: Annotated[
        str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")
    ]
    source_crosswalk_row_id: Annotated[
        str, Field(strict=True, pattern=r"^crosswalk:[0-9a-f]{64}$")
    ]
    source_crosswalk_row_sha256: Sha256
    source_candidate_ids: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=200)], ...
    ]
    source_dataset_entity_ids: tuple[
        Annotated[str, Field(strict=True, pattern=r"^dataset:[0-9a-f]{64}$")], ...
    ]
    coordinates: ObjectiveGate
    description: ObjectiveGate
    operating_info: ObjectiveGate
    dataset_rights: ObjectiveGate
    direct_media: ObjectiveGate
    confidence_is_qualification_filter_only: Literal[True]
    confidence_adds_score: Literal[False]
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        if len(self.source_candidate_ids) != len(self.source_dataset_entity_ids):
            raise ValueError("objective row candidate and dataset identities differ")
        if not self.source_candidate_ids:
            raise ValueError("objective row requires at least one protected candidate")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("objective evidence row hash does not match")
        return self


class ObjectiveEvidenceParents(StrictContract):
    rights_projection_sha256: Sha256
    rights_projection_file_sha256: Sha256
    entity_projection_sha256: Sha256
    entity_policy_report_sha256: Sha256
    formal_policy_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_inputs_sha256: Sha256
    complete_dispositions_root: Sha256
    media_attachments_root: Sha256


class CandidateObjectiveEvidence(StrictContract):
    schema_version: Literal["candidate-objective-evidence-v1"]
    data_version: Literal["catalog-v2-objective-evidence-data-v1"]
    parents: ObjectiveEvidenceParents
    rows: tuple[CandidateObjectiveRow, ...]
    candidate_count: Annotated[int, Field(strict=True, ge=0)]
    rows_root: Sha256
    report_sha256: Sha256

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        ids = tuple(row.place_entity_id for row in self.rows)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("objective rows must use unique canonical place order")
        if self.candidate_count != len(self.rows):
            raise ValueError("objective candidate count is not row-derived")
        expected_root = canonical_sha256(
            [row.model_dump(mode="json") for row in self.rows]
        )
        if self.rows_root != expected_root:
            raise ValueError("objective evidence root is not row-derived")
        expected = canonical_sha256(
            self.model_dump(exclude={"report_sha256"}, mode="json")
        )
        if self.report_sha256 != expected:
            raise ValueError("objective evidence report hash does not match")
        return self


__all__ = [
    "AssetRightsRow",
    "AttachmentRightsRow",
    "CandidateObjectiveEvidence",
    "CandidateObjectiveRow",
    "DatasetGrantRightsRow",
    "GateState",
    "ObjectiveEvidenceParents",
    "ObjectiveGate",
    "RightsProjection",
    "RightsProjectionParents",
    "RightsState",
    "project_asset_rights",
]
