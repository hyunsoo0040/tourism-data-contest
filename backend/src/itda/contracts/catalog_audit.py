"""Fail-closed Phase 2 catalog rights and completeness audit contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.domain.canonical import canonical_sha256

EXPECTED_DATASET_IDS = ("15101578", "15101971", "15101914")
DATASET_LICENSES = {
    "15101578": "PUBLIC_DATA_GRANT_METADATA_ONLY",
    "15101971": "PUBLIC_DATA_GRANT",
    "15101914": "KOGL_TYPE_1_ATTRIBUTION",
}


class RightsState(StrEnum):
    ALLOWED = "ALLOWED"
    BLOCKED_EXPLICIT_ASSET_RESTRICTION = "BLOCKED_EXPLICIT_ASSET_RESTRICTION"
    BLOCKED_MISSING_PROVENANCE = "BLOCKED_MISSING_PROVENANCE"
    BLOCKED_GRANT_MISSING = "BLOCKED_GRANT_MISSING"
    BLOCKED_GRANT_INCOMPLETE = "BLOCKED_GRANT_INCOMPLETE"
    BLOCKED_DATASET_SCOPE_MISMATCH = "BLOCKED_DATASET_SCOPE_MISMATCH"


class MissingReason(StrEnum):
    DESCRIPTION_NOT_COLLECTED = "TOURAPI_DESCRIPTION_NOT_COLLECTED"
    DESCRIPTION_NOT_APPLICABLE = "DESCRIPTION_NOT_APPLICABLE_TO_SOURCE"
    PHOTO_NOT_COLLECTED = "PHOTO_ASSET_NOT_COLLECTED_FOR_CANDIDATE"
    PHOTO_NOT_APPLICABLE = "PHOTO_NOT_APPLICABLE_TO_SOURCE"
    OPERATIONAL_DETAIL_NOT_COLLECTED = "OPERATIONAL_DETAIL_NOT_COLLECTED"
    ODII_NORMALIZED_CANDIDATE_ABSENT = "ODII_NORMALIZED_CANDIDATE_ABSENT"
    COORDINATES_NOT_EXPOSED = "COORDINATES_NOT_EXPOSED_BY_COLLECTED_RESPONSE"
    CROSSWALK_REVIEW_REQUIRED = "CROSSWALK_REVIEW_REQUIRED"
    RELATIONSHIP_REVIEW_REQUIRED = "RELATIONSHIP_REVIEW_REQUIRED"
    CANONICAL_SELECTION_NOT_ADJUDICATED = "CANONICAL_SELECTION_NOT_ADJUDICATED"


CompletenessStatus = Literal["PRESENT", "MISSING", "UNKNOWN", "NOT_APPLICABLE"]


class DatasetGrantEvidence(StrictContract):
    """One exact dataset permission snapshot projected into a scoped grant."""

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
    ] = ()

    @model_validator(mode="after")
    def validate_dataset_scope(self) -> Self:
        if self.official_dataset_id not in EXPECTED_DATASET_IDS:
            raise ValueError("dataset grant is outside the exact Phase 2 dataset set")
        expected_url = (
            f"https://www.data.go.kr/data/{self.official_dataset_id}/openapi.do"
        )
        if self.official_page_url != expected_url:
            raise ValueError("dataset grant page URL does not match dataset identity")
        if self.official_dataset_id == "15101914" and (
            self.license_type != "KOGL_TYPE_1_ATTRIBUTION" or not self.attribution_text
        ):
            raise ValueError("PhotoGallery grant requires independent Type-1 attribution")
        if self.evidence_state != "COMPLETE" and any(
            (
                self.commercial_use_allowed,
                self.transform_allowed,
                self.display_allowed,
                self.model_input_allowed,
            )
        ):
            raise ValueError("missing or incomplete grant evidence cannot authorize use")
        return self


class CatalogAsset(StrictContract):
    """One provider content item, kept distinct from its dataset grant."""

    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    source_asset_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
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
    content_kind: Literal[
        "TOURAPI_DESCRIPTION",
        "ODII_SCRIPT_AUDIO_TEXT",
        "TOURISM_PHOTO_ASSET",
    ] = "TOURISM_PHOTO_ASSET"
    explicit_asset_restriction: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None


class RightsDisposition(StrictContract):
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    source_asset_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    content_kind: Literal[
        "TOURAPI_DESCRIPTION",
        "ODII_SCRIPT_AUDIO_TEXT",
        "TOURISM_PHOTO_ASSET",
    ]
    rights_state: RightsState
    reason_codes: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=120)], ...]
    audit_evidence_retained: Literal[True] = True
    commercial_use_allowed: Annotated[bool, Field(strict=True)]
    transform_allowed: Annotated[bool, Field(strict=True)]
    display_allowed: Annotated[bool, Field(strict=True)]
    model_input_allowed: Annotated[bool, Field(strict=True)]
    analysis_eligible: Annotated[bool, Field(strict=True)]
    ui_eligible: Annotated[bool, Field(strict=True)]
    demo_eligible: Annotated[bool, Field(strict=True)]

    @model_validator(mode="after")
    def blocked_lanes_must_fail_closed(self) -> Self:
        downstream = (
            self.analysis_eligible,
            self.ui_eligible,
            self.demo_eligible,
        )
        if self.rights_state is RightsState.ALLOWED:
            if not all(downstream):
                raise ValueError("allowed rights must agree across downstream lanes")
        elif any(
            downstream
            + (
                self.commercial_use_allowed,
                self.transform_allowed,
                self.display_allowed,
                self.model_input_allowed,
            )
        ):
            raise ValueError("blocked rights cannot authorize any downstream lane")
        if not self.reason_codes:
            raise ValueError("rights disposition requires an exact reason code")
        return self


def _blocked(
    asset: CatalogAsset,
    state: RightsState,
    *reason_codes: str,
) -> RightsDisposition:
    return RightsDisposition(
        official_dataset_id=asset.official_dataset_id,
        source_asset_id=asset.source_asset_id,
        content_kind=asset.content_kind,
        rights_state=state,
        reason_codes=tuple(reason_codes),
        commercial_use_allowed=False,
        transform_allowed=False,
        display_allowed=False,
        model_input_allowed=False,
        analysis_eligible=False,
        ui_eligible=False,
        demo_eligible=False,
    )


def decide_asset_rights(
    asset: CatalogAsset,
    grant: DatasetGrantEvidence,
) -> RightsDisposition:
    """Apply the one dataset-specific, asset-override, fail-closed policy."""

    if asset.official_dataset_id != grant.official_dataset_id:
        raise ValueError("asset dataset identity does not match dataset grant")
    if grant.evidence_state == "MISSING":
        return _blocked(asset, RightsState.BLOCKED_GRANT_MISSING, "GRANT_EVIDENCE_MISSING")
    if grant.evidence_state == "INCOMPLETE":
        return _blocked(
            asset,
            RightsState.BLOCKED_GRANT_INCOMPLETE,
            "GRANT_EVIDENCE_INCOMPLETE",
        )
    required_provenance = (
        asset.source_asset_id,
        asset.source_request_sha256,
        asset.source_response_sha256,
        asset.original_url,
    )
    if any(value is None for value in required_provenance):
        return _blocked(
            asset,
            RightsState.BLOCKED_MISSING_PROVENANCE,
            "ASSET_PROVENANCE_INCOMPLETE",
        )
    if asset.official_dataset_id == "15101914" and (
        asset.license_type != "KOGL_TYPE_1_ATTRIBUTION"
        or not asset.attribution_text
        or not asset.creator_or_photographer
    ):
        return _blocked(
            asset,
            RightsState.BLOCKED_MISSING_PROVENANCE,
            "PHOTO_TYPE1_ATTRIBUTION_INCOMPLETE",
        )
    if asset.explicit_asset_restriction:
        return _blocked(
            asset,
            RightsState.BLOCKED_EXPLICIT_ASSET_RESTRICTION,
            asset.explicit_asset_restriction,
        )
    grants_every_lane = all(
        (
            grant.commercial_use_allowed,
            grant.transform_allowed,
            grant.display_allowed,
            grant.model_input_allowed,
        )
    )
    if not grants_every_lane:
        return _blocked(
            asset,
            RightsState.BLOCKED_DATASET_SCOPE_MISMATCH,
            "DATASET_GRANT_DOES_NOT_AUTHORIZE_ALL_REQUIRED_LANES",
        )
    return RightsDisposition(
        official_dataset_id=asset.official_dataset_id,
        source_asset_id=asset.source_asset_id,
        content_kind=asset.content_kind,
        rights_state=RightsState.ALLOWED,
        reason_codes=("AUTHORITATIVE_DATASET_GRANT_AND_ASSET_PROVENANCE_COMPLETE",),
        commercial_use_allowed=True,
        transform_allowed=True,
        display_allowed=True,
        model_input_allowed=True,
        analysis_eligible=True,
        ui_eligible=True,
        demo_eligible=True,
    )


class SeedAuditRow(StrictContract):
    seed_id: Annotated[
        str, Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$")
    ]
    status: Literal["LINKED", "MISSING_WITH_EVIDENCE", "EXCLUDED_WITH_EVIDENCE"]
    candidate_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]
    evidence_sha256: tuple[Sha256, ...]


class CandidateAuditRow(StrictContract):
    candidate_id: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    latitude: Annotated[float | None, Field(strict=True, ge=-90, le=90)] = None
    longitude: Annotated[float | None, Field(strict=True, ge=-180, le=180)] = None
    coordinate_status: CompletenessStatus | None = None
    coordinate_missing_reason: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    description_status: CompletenessStatus
    description_missing_reason: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    photo_status: CompletenessStatus
    photo_missing_reason: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    operational_status: CompletenessStatus
    operational_missing_reason: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    odii_status: CompletenessStatus
    odii_missing_reason: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=500)
    ] = None
    provider: Annotated[str | None, Field(strict=True, min_length=1, max_length=40)] = None
    official_dataset_id: Annotated[
        str | None, Field(strict=True, pattern=r"^[0-9]{8}$")
    ] = None
    provider_content_id: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None
    request_identity: Sha256 | None = None
    raw_response_sha256: Sha256 | None = None
    permission_snapshot_sha256: Sha256 | None = None
    crosswalk_status: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=80)
    ] = None
    crosswalk_reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=120)], ...
    ] = ()
    relationship_status: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=80)
    ] = None
    relationship_reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=120)], ...
    ] = ()
    linked_seed_ids: tuple[
        Annotated[
            str,
            Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$"),
        ],
        ...,
    ] = ()
    asset: CatalogAsset | None = None
    rights_disposition: RightsDisposition | None = None
    canonical_selection_eligible: Annotated[bool, Field(strict=True)] = False
    eligibility_reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=120)], ...
    ] = (MissingReason.CANONICAL_SELECTION_NOT_ADJUDICATED.value,)
    projection_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_completeness_and_hash(self) -> Self:
        has_coordinates = self.latitude is not None and self.longitude is not None
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be present or missing together")
        if self.coordinate_status is None:
            object.__setattr__(
                self,
                "coordinate_status",
                "PRESENT" if has_coordinates else "MISSING",
            )
        if self.coordinate_missing_reason is None and not has_coordinates:
            object.__setattr__(
                self,
                "coordinate_missing_reason",
                MissingReason.COORDINATES_NOT_EXPOSED.value,
            )
        if (
            self.coordinate_status == "PRESENT"
        ) != (self.coordinate_missing_reason is None):
            raise ValueError(
                "coordinate PRESENT requires no missing reason; every other state requires one"
            )
        pairs = (
            (self.description_status, self.description_missing_reason, "description"),
            (self.photo_status, self.photo_missing_reason, "photo"),
            (self.operational_status, self.operational_missing_reason, "operational"),
            (self.odii_status, self.odii_missing_reason, "odii"),
        )
        for status, reason, label in pairs:
            if (status == "PRESENT") == (reason is not None):
                raise ValueError(
                    f"{label} PRESENT requires no missing reason; every other state requires one"
                )
        if (self.asset is None) != (self.rights_disposition is None):
            raise ValueError("asset and rights disposition must be present together")
        if self.asset is not None and (
            self.asset.official_dataset_id != self.official_dataset_id
            or self.rights_disposition is None
            or self.rights_disposition.source_asset_id != self.asset.source_asset_id
        ):
            raise ValueError("candidate asset rights are not source-bound")
        expected = canonical_sha256(
            self.model_dump(exclude={"projection_sha256"}, mode="json")
        )
        if self.projection_sha256 is None:
            object.__setattr__(self, "projection_sha256", expected)
        elif self.projection_sha256 != expected:
            raise ValueError("candidate projection_sha256 does not match row fields")
        return self


class CatalogAudit(StrictContract):
    schema_version: Literal["catalog-audit-v1"]
    data_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    source_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    grants: tuple[DatasetGrantEvidence, ...] = ()
    seed_rows: tuple[SeedAuditRow, ...] = ()
    rows: tuple[CandidateAuditRow, ...]
    source_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=120)], Sha256
    ] = Field(default_factory=dict)
    phase1_historical_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=300)], Sha256
    ] = Field(default_factory=dict)
    audit_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_order_coverage_and_hash(self) -> Self:
        candidate_ids = tuple(row.candidate_id for row in self.rows)
        if len(set(candidate_ids)) != len(candidate_ids):
            raise ValueError("catalog audit candidate IDs must be unique")
        if candidate_ids != tuple(sorted(candidate_ids)):
            raise ValueError("catalog audit rows must use candidate_id order")
        if self.grants and tuple(item.official_dataset_id for item in self.grants) != (
            EXPECTED_DATASET_IDS
        ):
            raise ValueError("catalog audit requires exact ordered dataset grants")
        if self.seed_rows:
            expected_seed_ids = tuple(
                f"proposal:gyeongju:{index:03d}" for index in range(1, 37)
            )
            if tuple(item.seed_id for item in self.seed_rows) != expected_seed_ids:
                raise ValueError("catalog audit must preserve all 36 seed rows in order")
        expected = canonical_sha256(self.model_dump(exclude={"audit_sha256"}, mode="json"))
        if self.audit_sha256 is None:
            object.__setattr__(self, "audit_sha256", expected)
        elif self.audit_sha256 != expected:
            raise ValueError("catalog audit hash does not match canonical fields")
        return self


class ProjectionManifest(StrictContract):
    schema_version: Literal["catalog-audit-projection-manifest-v1"]
    audit_schema_version: Literal["catalog-audit-v1"]
    data_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    source_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    canonical_json_sha256: Sha256
    output_hashes: dict[
        Literal[
            "catalog-audit.json",
            "catalog-audit.parquet",
            "catalog-audit.csv",
            "catalog-audit.md",
        ],
        Sha256,
    ]
    writer_metadata: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=120)],
        Annotated[str, Field(strict=True, min_length=1, max_length=500)],
    ]
    projection_manifest_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_projection_links(self) -> Self:
        expected_names = {
            "catalog-audit.json",
            "catalog-audit.parquet",
            "catalog-audit.csv",
            "catalog-audit.md",
        }
        if set(self.output_hashes) != expected_names:
            raise ValueError("projection manifest must bind all four audit outputs")
        if self.output_hashes["catalog-audit.json"] != self.canonical_json_sha256:
            raise ValueError("canonical JSON hash must match JSON output hash")
        expected = canonical_sha256(
            self.model_dump(exclude={"projection_manifest_sha256"}, mode="json")
        )
        if self.projection_manifest_sha256 is None:
            object.__setattr__(self, "projection_manifest_sha256", expected)
        elif self.projection_manifest_sha256 != expected:
            raise ValueError("projection manifest hash does not match linked outputs")
        return self


__all__ = [
    "CandidateAuditRow",
    "CatalogAsset",
    "CatalogAudit",
    "DatasetGrantEvidence",
    "MissingReason",
    "ProjectionManifest",
    "RightsDisposition",
    "RightsState",
    "SeedAuditRow",
    "decide_asset_rights",
]
