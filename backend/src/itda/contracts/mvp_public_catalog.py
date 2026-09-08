"""Strict provider-free contracts for the Gyeongju PUBLIC scoring catalog."""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256

PublicPlaceId = Annotated[
    str,
    Field(strict=True, pattern=r"^public:gyeongju:[0-9a-f]{64}$"),
]
PublicEvidenceId = Annotated[
    str,
    Field(strict=True, pattern=r"^evidence:[0-9a-f]{64}$"),
]


class OfficialPermissionLane(StrictContract):
    decision: Literal["ALLOWED", "PROHIBITED", "UNKNOWN"]
    evidence_quote: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]


class OfficialDatasetPermissionMetadata(StrictContract):
    schema_version: Literal["official-dataset-permission-metadata.v2"]
    official_dataset_id: Literal["15101578", "15101971"]
    official_url: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^https://www\.data\.go\.kr/data/(15101578|15101971)/openapi\.do$",
        ),
    ]
    retrieved_at: datetime
    raw_response_sha256: Sha256
    dataset_title_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    provider_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    license_type: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    attribution_required: bool
    attribution_text_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)] | None
    no_attribution_evidence_ko: (
        Annotated[str, Field(strict=True, min_length=1, max_length=1_000)] | None
    )
    public_display: OfficialPermissionLane
    transformation_and_derived_scores: OfficialPermissionLane
    third_party_model_processing_and_retention: OfficialPermissionLane
    excerpt_and_release_redistribution: OfficialPermissionLane
    commercial_scope: OfficialPermissionLane
    restrictions_ko: Annotated[str, Field(strict=True, min_length=1, max_length=2_000)]
    metadata_sha256: Sha256

    @model_validator(mode="after")
    def validate_permission_metadata(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        if self.official_dataset_id not in self.official_url:
            raise ValueError("official permission URL does not match dataset")
        if self.attribution_required:
            if self.attribution_text_ko is None or self.no_attribution_evidence_ko is not None:
                raise ValueError("required attribution must include exact official wording")
        elif self.attribution_text_ko is not None or self.no_attribution_evidence_ko is None:
            raise ValueError("no-attribution decision requires exact official evidence")
        expected = canonical_sha256(self.model_dump(exclude={"metadata_sha256"}, mode="json"))
        if self.metadata_sha256 != expected:
            raise ValueError("official permission metadata hash does not match")
        return self

    @property
    def permits_mvp_use(self) -> bool:
        return all(
            lane.decision == "ALLOWED"
            for lane in (
                self.public_display,
                self.transformation_and_derived_scores,
                self.third_party_model_processing_and_retention,
                self.excerpt_and_release_redistribution,
                self.commercial_scope,
            )
        )

    @property
    def attribution_for_release(self) -> str:
        if self.attribution_required:
            assert self.attribution_text_ko is not None
            return self.attribution_text_ko
        return f"출처: {self.provider_name_ko} · {self.dataset_title_ko}"


class PublicEvidence(StrictContract):
    evidence_id: PublicEvidenceId
    provider: Literal["TOUR_API", "ODII"]
    official_dataset_id: Literal["15101578", "15101971"]
    provider_source_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    official_license_url: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^https://www\.data\.go\.kr/data/(15101578|15101971)/openapi\.do$",
        ),
    ]
    license_type: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    attribution_text: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    reference_date: date
    excerpt: Annotated[str, Field(strict=True, min_length=1, max_length=4_000)]
    source_response_sha256: Sha256
    permission_metadata: OfficialDatasetPermissionMetadata
    commercial_use_allowed: Literal[True]
    transform_allowed: Literal[True]
    display_allowed: Literal[True]
    model_input_allowed: Literal[True]
    release_redistribution_allowed: Literal[True]
    third_party_model_processing_allowed: Literal[True]
    evidence_sha256: Sha256

    @model_validator(mode="after")
    def validate_rights_and_hash(self) -> Self:
        expected_dataset = {"TOUR_API": "15101578", "ODII": "15101971"}[self.provider]
        if self.official_dataset_id != expected_dataset:
            raise ValueError("public evidence provider and dataset do not match")
        if self.permission_metadata.official_dataset_id != self.official_dataset_id:
            raise ValueError("public evidence permission metadata does not match dataset")
        if self.permission_metadata.official_url != self.official_license_url:
            raise ValueError("public evidence permission URL does not match")
        if self.license_type != self.permission_metadata.license_type:
            raise ValueError("public evidence license type does not match permission metadata")
        if self.attribution_text != self.permission_metadata.attribution_for_release:
            raise ValueError("public evidence attribution does not match permission metadata")
        if not self.permission_metadata.permits_mvp_use:
            raise ValueError("official permission metadata does not permit all MVP usage lanes")
        if not all(
            (
                self.commercial_use_allowed,
                self.transform_allowed,
                self.display_allowed,
                self.model_input_allowed,
                self.release_redistribution_allowed,
                self.third_party_model_processing_allowed,
            )
        ):
            raise ValueError("public evidence requires all public usage lanes")
        expected = canonical_sha256(self.model_dump(exclude={"evidence_sha256"}, mode="json"))
        if self.evidence_sha256 != expected:
            raise ValueError("public evidence hash does not match canonical fields")
        return self


class PublicEvidenceInventory(StrictContract):
    schema_version: Literal["public-evidence-inventory.v1"]
    evidence: Annotated[tuple[PublicEvidence, ...], Field(min_length=1)]
    inventory_sha256: Sha256

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        ids = tuple(row.evidence_id for row in self.evidence)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise ValueError("public evidence must use unique canonical order")
        expected = canonical_sha256(
            {
                "schema_version": self.schema_version,
                "evidence": [row.model_dump(mode="json") for row in self.evidence],
            }
        )
        if self.inventory_sha256 != expected:
            raise ValueError("public evidence inventory hash does not match")
        return self


class ProviderCrosswalk(StrictContract):
    provider: Literal["TOUR_API", "ODII"]
    source_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]


class PublicPlace(StrictContract):
    place_id: PublicPlaceId
    pool: Literal["PUBLIC"]
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    normalized_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    category: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    administrative_area: Literal["경주시"]
    address_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    latitude: Annotated[float, Field(strict=True, ge=35.0, le=36.5)]
    longitude: Annotated[float, Field(strict=True, ge=128.0, le=130.5)]
    provider_crosswalk: Annotated[tuple[ProviderCrosswalk, ...], Field(min_length=1)]
    evidence_ids: Annotated[tuple[PublicEvidenceId, ...], Field(min_length=1, max_length=8)]
    duplicate_group_id: Annotated[
        str,
        Field(strict=True, pattern=r"^duplicate:[0-9a-f]{64}$"),
    ]
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_place(self) -> Self:
        crosswalk = tuple((row.provider, row.source_id) for row in self.provider_crosswalk)
        if crosswalk != tuple(sorted(crosswalk)) or len(crosswalk) != len(set(crosswalk)):
            raise ValueError("provider crosswalk must use unique canonical order")
        if self.evidence_ids != tuple(sorted(self.evidence_ids)):
            raise ValueError("place evidence IDs must use canonical order")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("public place row hash does not match")
        return self


class PublicPlaceCatalog(StrictContract):
    schema_version: Literal["public-place-catalog.v1"]
    pool: Literal["PUBLIC"]
    region: Literal["경주시"]
    places: Annotated[tuple[PublicPlace, ...], Field(min_length=100, max_length=100)]
    evidence_inventory_sha256: Sha256
    blind_overlap_count: Literal[0]
    catalog_sha256: Sha256

    @model_validator(mode="after")
    def validate_catalog(self) -> Self:
        ids = tuple(row.place_id for row in self.places)
        if ids != tuple(sorted(ids)) or len(set(ids)) != 100:
            raise ValueError("public catalog requires exactly 100 unique sorted places")
        identity_keys = tuple(
            (row.normalized_name_ko, round(row.latitude, 5), round(row.longitude, 5))
            for row in self.places
        )
        if len(set(identity_keys)) != 100:
            raise ValueError("public catalog contains a duplicate normalized place")
        expected = canonical_sha256(self.model_dump(exclude={"catalog_sha256"}, mode="json"))
        if self.catalog_sha256 != expected:
            raise ValueError("public catalog hash does not match")
        return self


class PublicPlaceRelation(StrictContract):
    relation_type: Literal["CANNOT_COAPPEAR"]
    left_place_id: PublicPlaceId
    right_place_id: PublicPlaceId
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=500)]

    @model_validator(mode="after")
    def validate_pair(self) -> Self:
        if self.left_place_id >= self.right_place_id:
            raise ValueError("relation endpoints must use canonical order")
        return self


class PublicPlaceRelations(StrictContract):
    schema_version: Literal["public-place-relations.v1"]
    catalog_sha256: Sha256
    catalog_place_ids: Annotated[tuple[PublicPlaceId, ...], Field(min_length=100, max_length=100)]
    relations: tuple[PublicPlaceRelation, ...]
    relations_sha256: Sha256

    @model_validator(mode="after")
    def validate_relations(self) -> Self:
        if self.catalog_place_ids != tuple(sorted(self.catalog_place_ids)):
            raise ValueError("relation catalog IDs must use canonical order")
        known = set(self.catalog_place_ids)
        pairs = tuple((row.left_place_id, row.right_place_id) for row in self.relations)
        if pairs != tuple(sorted(pairs)) or len(pairs) != len(set(pairs)):
            raise ValueError("relations must use unique canonical order")
        if any(left not in known or right not in known for left, right in pairs):
            raise ValueError("relation references a non-catalog endpoint")
        expected = canonical_sha256(self.model_dump(exclude={"relations_sha256"}, mode="json"))
        if self.relations_sha256 != expected:
            raise ValueError("public relations hash does not match")
        return self


class VerifiedPermissionBinding(StrictContract):
    official_dataset_id: Literal["15101578", "15101971"]
    metadata_sha256: Sha256
    raw_response_sha256: Sha256


class CatalogGapReport(StrictContract):
    schema_version: Literal["public-place-catalog-gap.v3"]
    tracked_candidate_count: Annotated[int, Field(strict=True, ge=0)]
    description_ready_historical_count: Annotated[int, Field(strict=True, ge=0)]
    description_enrichment_candidate_count: Annotated[int, Field(strict=True, ge=0)]
    required_count: Literal[100]
    preliminary_description_gap_count: Annotated[int, Field(strict=True, ge=0, le=100)]
    strict_rights_qualified_count: None
    strict_rights_state: Literal[
        "BLOCKED_RIGHTS_METADATA",
        "PERMISSION_METADATA_VERIFIED",
    ]
    catalog_ready: Literal[False]
    permission_metadata_present: bool
    permission_bindings: tuple[VerifiedPermissionBinding, ...]
    provider_traffic: Literal[False]
    secret_access: Literal[False]
    source_file_sha256: Sha256
    report_sha256: Sha256

    @model_validator(mode="after")
    def validate_gap(self) -> Self:
        if self.preliminary_description_gap_count != max(
            0, self.required_count - self.description_ready_historical_count
        ):
            raise ValueError("preliminary description gap is not candidate-derived")
        if self.description_enrichment_candidate_count < self.preliminary_description_gap_count:
            raise ValueError("description enrichment candidates cannot cover the preliminary gap")
        dataset_ids = tuple(row.official_dataset_id for row in self.permission_bindings)
        if self.strict_rights_state == "BLOCKED_RIGHTS_METADATA":
            if self.permission_metadata_present or self.permission_bindings:
                raise ValueError("blocked rights state cannot claim verified permission metadata")
        elif (
            not self.permission_metadata_present
            or dataset_ids != ("15101578", "15101971")
            or len({row.metadata_sha256 for row in self.permission_bindings}) != 2
            or len({row.raw_response_sha256 for row in self.permission_bindings}) != 2
        ):
            raise ValueError("verified rights state requires exact dataset permission bindings")
        expected = canonical_sha256(self.model_dump(exclude={"report_sha256"}, mode="json"))
        if self.report_sha256 != expected:
            raise ValueError("catalog gap report hash does not match")
        return self


def verify_blind_overlap_count(
    public_place_ids: tuple[str, ...],
    blind_place_ids: tuple[str, ...],
) -> Literal[0]:
    if set(public_place_ids).intersection(blind_place_ids):
        raise ValueError("BLIND overlap is non-zero")
    return 0
