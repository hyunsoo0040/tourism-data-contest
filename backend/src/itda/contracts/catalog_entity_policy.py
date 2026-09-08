"""Closed deterministic policy contracts for protected catalog entity evidence."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract
from itda.contracts.catalog_entity import EntityRef
from itda.domain.canonical import canonical_sha256

POLICY_VERSION = "catalog-entity-policy-v1"


class PolicyResult(StrEnum):
    AUTOMATIC_SINGLE_PROVIDER_RECORD = "AUTOMATIC_SINGLE_PROVIDER_RECORD"
    AUTOMATIC_REJECT_NON_PLACE_SOURCE_KIND = (
        "AUTOMATIC_REJECT_NON_PLACE_SOURCE_KIND"
    )
    AUTOMATIC_MEDIA_RETYPE_NO_PLACE_MERGE = (
        "AUTOMATIC_MEDIA_RETYPE_NO_PLACE_MERGE"
    )
    AUTOMATIC_REJECT_SOURCE_KIND_INCOMPATIBLE = (
        "AUTOMATIC_REJECT_SOURCE_KIND_INCOMPATIBLE"
    )
    AUTOMATIC_MEDIA_ATTACHMENT = "AUTOMATIC_MEDIA_ATTACHMENT"
    UNRESOLVED_HUMAN = "UNRESOLVED_HUMAN"


EXACT_MEDIA_RECORD_BINDINGS = (
    ("candidate:tour-api:1621391", "candidate:tourism-photo:2483380"),
    ("candidate:tour-api:129778", "candidate:tourism-photo:1136503"),
    ("candidate:tour-api:2614343", "candidate:tourism-photo:2483388"),
    ("candidate:tour-api:126134", "candidate:tourism-photo:2005377"),
    ("candidate:tour-api:990539", "candidate:tourism-photo:2005941"),
    ("candidate:tour-api:990516", "candidate:tourism-photo:1916613"),
    ("candidate:tour-api:126204", "candidate:tourism-photo:1627580"),
    ("candidate:tour-api:2002492", "candidate:tourism-photo:1907967"),
)

FORMAL_POLICY = {
    "policy_version": POLICY_VERSION,
    "result_enum": tuple(item.value for item in PolicyResult),
    "tie_order": (
        "CROSSWALK_MULTIPLE_PLACE_RECORDS_UNRESOLVED",
        "CROSSWALK_EXACT_MEDIA_RETYPE",
        "CROSSWALK_SINGLE_PLACE_RECORD_AUTOMATIC",
        "CROSSWALK_NON_PLACE_REJECT",
        "RELATIONSHIP_PLACE_PAIR_UNRESOLVED",
        "RELATIONSHIP_EXACT_MEDIA_RECORD_ATTACHMENT",
        "RELATIONSHIP_SOURCE_KIND_REJECT",
    ),
    "rules": (
        {
            "rule_id": "CROSSWALK_MULTIPLE_PLACE_RECORDS_UNRESOLVED",
            "predicate": "tour_api_record_count_gt_1",
            "result": PolicyResult.UNRESOLVED_HUMAN.value,
        },
        {
            "rule_id": "CROSSWALK_EXACT_MEDIA_RETYPE",
            "predicate": "tour_api_record_count_eq_1_and_photo_record_count_gt_0",
            "result": PolicyResult.AUTOMATIC_MEDIA_RETYPE_NO_PLACE_MERGE.value,
        },
        {
            "rule_id": "CROSSWALK_SINGLE_PLACE_RECORD_AUTOMATIC",
            "predicate": "tour_api_record_count_eq_1_and_photo_record_count_eq_0",
            "result": PolicyResult.AUTOMATIC_SINGLE_PROVIDER_RECORD.value,
        },
        {
            "rule_id": "CROSSWALK_NON_PLACE_REJECT",
            "predicate": "tour_api_record_count_eq_0",
            "result": PolicyResult.AUTOMATIC_REJECT_NON_PLACE_SOURCE_KIND.value,
        },
        {
            "rule_id": "RELATIONSHIP_PLACE_PAIR_UNRESOLVED",
            "predicate": "both_endpoints_are_tour_api_dataset_records",
            "result": PolicyResult.UNRESOLVED_HUMAN.value,
        },
        {
            "rule_id": "RELATIONSHIP_EXACT_MEDIA_RECORD_ATTACHMENT",
            "predicate": "ordered_endpoint_pair_in_exact_media_record_bindings",
            "bindings": EXACT_MEDIA_RECORD_BINDINGS,
            "result": PolicyResult.AUTOMATIC_MEDIA_ATTACHMENT.value,
        },
        {
            "rule_id": "RELATIONSHIP_SOURCE_KIND_REJECT",
            "predicate": "remaining_endpoint_pair_contains_photo_record",
            "result": PolicyResult.AUTOMATIC_REJECT_SOURCE_KIND_INCOMPATIBLE.value,
        },
    ),
}


def formal_policy_sha256() -> str:
    """Return the canonical digest of the complete closed policy vocabulary."""

    return canonical_sha256(FORMAL_POLICY)


class PolicyDisposition(StrictContract):
    source_row_id: Annotated[
        str,
        Field(strict=True, pattern=r"^(crosswalk|relationship):[0-9a-f]{64}$"),
    ]
    source_row_sha256: Sha256
    rule_id: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    result: PolicyResult
    rationale_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        ...,
    ]
    evidence_refs: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=240)],
        ...,
    ]
    leaf_sha256: Sha256

    @model_validator(mode="after")
    def validate_leaf(self) -> Self:
        if not self.rationale_codes or not self.evidence_refs:
            raise ValueError("policy disposition requires rationale and evidence")
        expected = canonical_sha256(
            self.model_dump(exclude={"leaf_sha256"}, mode="json")
        )
        if self.leaf_sha256 != expected:
            raise ValueError("derived policy leaf hash does not match")
        return self


class MediaAttachment(StrictContract):
    source_relationship_row_id: Annotated[
        str,
        Field(strict=True, pattern=r"^relationship:[0-9a-f]{64}$"),
    ]
    source_row_sha256: Sha256
    source_place_candidate_id: StableId
    source_photo_candidate_id: StableId
    source_asset_id: StableId
    place_ref: EntityRef
    photo_ref: EntityRef
    owner_dataset_ref: EntityRef
    evidence_refs: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=240)],
        ...,
    ]
    rights_granting: Literal[False]
    identity_merging: Literal[False]
    leaf_sha256: Sha256

    @model_validator(mode="after")
    def validate_attachment(self) -> Self:
        if self.place_ref.kind.value != "PLACE":
            raise ValueError("media attachment requires PLACE target")
        if self.photo_ref.kind.value != "PHOTO_ASSET":
            raise ValueError("media attachment requires PHOTO_ASSET source")
        if self.owner_dataset_ref.kind.value != "DATASET_RECORD":
            raise ValueError("media attachment requires exact dataset-record owner")
        if not self.evidence_refs:
            raise ValueError("media attachment requires exact evidence")
        expected = canonical_sha256(
            self.model_dump(exclude={"leaf_sha256"}, mode="json")
        )
        if self.leaf_sha256 != expected:
            raise ValueError("derived attachment leaf hash does not match")
        return self


class PolicyCounts(StrictContract):
    crosswalk_total: Annotated[int, Field(strict=True, ge=0)]
    crosswalk_automatic: Annotated[int, Field(strict=True, ge=0)]
    crosswalk_unresolved: Annotated[int, Field(strict=True, ge=0)]
    relationship_total: Annotated[int, Field(strict=True, ge=0)]
    relationship_automatic: Annotated[int, Field(strict=True, ge=0)]
    relationship_unresolved: Annotated[int, Field(strict=True, ge=0)]
    media_attachment_count: Annotated[int, Field(strict=True, ge=0)]
    cross_provider_place_auto_link_count: Annotated[int, Field(strict=True, ge=0)]


class ProtectedPolicyInput(StrictContract):
    relpath: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=500, pattern=r"^[A-Za-z0-9._/-]+$"),
    ]
    file_sha256: Sha256
    manifest_entry_sha256: Sha256


class PolicyParents(StrictContract):
    immutability_manifest_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_inputs: tuple[ProtectedPolicyInput, ...]
    protected_inputs_sha256: Sha256
    entity_projection_file_sha256: Sha256
    entity_projection_sha256: Sha256

    @model_validator(mode="after")
    def validate_parents(self) -> Self:
        paths = tuple(item.relpath for item in self.protected_inputs)
        if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
            raise ValueError("protected policy inputs must use canonical byte order")
        expected = canonical_sha256(
            [item.model_dump(mode="json") for item in self.protected_inputs]
        )
        if self.protected_inputs_sha256 != expected:
            raise ValueError("derived protected input root does not match")
        return self


class EntityPolicyReport(StrictContract):
    schema_version: Literal["catalog-entity-policy-report-v1"]
    data_version: Literal["catalog-v2-entity-policy-data-v1"]
    policy_version: Literal["catalog-entity-policy-v1"]
    formal_policy_sha256: Sha256
    automatic_decisions_authoritative: Literal[False]
    parents: PolicyParents
    schema_sha256: Sha256
    code_hashes: dict[str, Sha256]
    config_hashes: dict[str, Sha256]
    crosswalk_dispositions: tuple[PolicyDisposition, ...]
    relationship_dispositions: tuple[PolicyDisposition, ...]
    media_attachments: tuple[MediaAttachment, ...]
    counts: PolicyCounts
    roots: dict[str, Sha256]
    report_sha256: Sha256

    @model_validator(mode="after")
    def validate_complete_report(self) -> Self:
        if self.formal_policy_sha256 != formal_policy_sha256():
            raise ValueError("formal policy hash does not match the closed policy")
        if self.schema_sha256 != canonical_sha256(type(self).model_json_schema()):
            raise ValueError("derived policy schema hash does not match")
        expected_counts = PolicyCounts(
            crosswalk_total=len(self.crosswalk_dispositions),
            crosswalk_automatic=sum(
                item.result is not PolicyResult.UNRESOLVED_HUMAN
                for item in self.crosswalk_dispositions
            ),
            crosswalk_unresolved=sum(
                item.result is PolicyResult.UNRESOLVED_HUMAN
                for item in self.crosswalk_dispositions
            ),
            relationship_total=len(self.relationship_dispositions),
            relationship_automatic=sum(
                item.result is not PolicyResult.UNRESOLVED_HUMAN
                for item in self.relationship_dispositions
            ),
            relationship_unresolved=sum(
                item.result is PolicyResult.UNRESOLVED_HUMAN
                for item in self.relationship_dispositions
            ),
            media_attachment_count=len(self.media_attachments),
            cross_provider_place_auto_link_count=0,
        )
        if self.counts != expected_counts:
            raise ValueError("derived aggregate counts do not match complete leaves")
        if self.counts != PolicyCounts(
            crosswalk_total=718,
            crosswalk_automatic=715,
            crosswalk_unresolved=3,
            relationship_total=874,
            relationship_automatic=871,
            relationship_unresolved=3,
            media_attachment_count=8,
            cross_provider_place_auto_link_count=0,
        ):
            raise ValueError("derived aggregate counts violate the frozen policy boundary")
        expected_roots = {
            "crosswalk_dispositions": canonical_sha256(
                [item.model_dump(mode="json") for item in self.crosswalk_dispositions]
            ),
            "relationship_dispositions": canonical_sha256(
                [
                    item.model_dump(mode="json")
                    for item in self.relationship_dispositions
                ]
            ),
            "media_attachments": canonical_sha256(
                [item.model_dump(mode="json") for item in self.media_attachments]
            ),
        }
        if self.roots != expected_roots:
            raise ValueError("derived aggregate roots do not match complete leaves")
        expected_report = canonical_sha256(
            self.model_dump(exclude={"report_sha256"}, mode="json")
        )
        if self.report_sha256 != expected_report:
            raise ValueError("derived report hash does not match")
        return self


def policy_schema_sha256() -> str:
    return canonical_sha256(EntityPolicyReport.model_json_schema())


__all__ = [
    "EXACT_MEDIA_RECORD_BINDINGS",
    "EntityPolicyReport",
    "FORMAL_POLICY",
    "MediaAttachment",
    "POLICY_VERSION",
    "PolicyCounts",
    "PolicyDisposition",
    "PolicyParents",
    "PolicyResult",
    "ProtectedPolicyInput",
    "formal_policy_sha256",
    "policy_schema_sha256",
]
