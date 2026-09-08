"""Source-neutral supplemental evidence contracts for immutable catalog salvage."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.domain.canonical import canonical_sha256

SCHEMA_VERSION = "itda.catalog-supplemental-evidence.v1"
DATA_VERSION = "catalog-v2-supplemental-evidence-data-v1"
FIELD_STATES = ("POPULATED", "MISSING", "BLOCKED", "REVIEW_REQUIRED")

SourceKind = Literal[
    "OFFICIAL_API_ROW",
    "OFFICIAL_PAGE",
    "OFFICIAL_SCRIPT",
    "OFFICIAL_ASSET",
]
FieldName = Literal[
    "coordinates",
    "korean_description",
    "provider_specific_operating_information",
    "exact_provider_direct_media",
    "odii_presence",
]
BindingState = Literal["EXACT", "REVIEW_REQUIRED"]
BindingMethod = Literal[
    "EXACT_PROVIDER_RECORD_ID",
    "EXACT_OFFICIAL_PAGE_ID",
    "IMMUTABLE_HUMAN_ADJUDICATION",
    "NAME_SIMILARITY",
    "PROXIMITY",
    "HIERARCHY",
    "MUTABLE_TITLE",
    "SOURCE_ORDER",
    "REVIEWER_PREFERENCE",
    "QUOTA_NEED",
    "EVIDENCE_VOLUME",
]

_EXACT_BINDING_METHODS = frozenset(
    {
        "EXACT_PROVIDER_RECORD_ID",
        "EXACT_OFFICIAL_PAGE_ID",
        "IMMUTABLE_HUMAN_ADJUDICATION",
    }
)
_SOURCE_FIELDS: dict[str, frozenset[str]] = {
    "OFFICIAL_API_ROW": frozenset(
        {
            "coordinates",
            "korean_description",
            "provider_specific_operating_information",
            "exact_provider_direct_media",
            "odii_presence",
        }
    ),
    "OFFICIAL_PAGE": frozenset(
        {
            "coordinates",
            "korean_description",
            "provider_specific_operating_information",
            "exact_provider_direct_media",
        }
    ),
    "OFFICIAL_SCRIPT": frozenset({"korean_description", "odii_presence"}),
    "OFFICIAL_ASSET": frozenset({"exact_provider_direct_media"}),
}


def _validate_relative_path(value: str) -> str:
    if "://" in value:
        raise ValueError("immutable evidence path must be repository-relative")
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith("/")
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
    ):
        raise ValueError("immutable evidence path escapes the repository")
    return value


def _license_is_type_3_or_4(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.upper().replace("-", "_").replace(" ", "_")
    return "TYPE_3" in normalized or "TYPE_4" in normalized


class SupplementalDatasetGrant(StrictContract):
    """One exact dataset/page grant, independent from any asset decision."""

    official_dataset_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:-]+$"),
    ]
    official_page_url: Annotated[str, Field(strict=True, min_length=1, max_length=2_000)]
    retrieved_at: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    response_sha256: Sha256
    page_sha256: Sha256
    evidence_state: Literal["COMPLETE", "MISSING", "INCOMPLETE"]
    license_type: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    commercial_use_allowed: Annotated[bool, Field(strict=True)]
    transform_allowed: Annotated[bool, Field(strict=True)]
    display_allowed: Annotated[bool, Field(strict=True)]
    model_input_allowed: Annotated[bool, Field(strict=True)]
    explicit_restrictions: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=500)],
        ...,
    ]
    dataset_grant_sha256: Sha256

    @model_validator(mode="after")
    def validate_grant_digest(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"dataset_grant_sha256"}, mode="json")
        )
        if self.dataset_grant_sha256 != expected:
            raise ValueError("dataset grant digest does not match exact grant fields")
        return self

    @property
    def allows_all_lanes(self) -> bool:
        return self.evidence_state == "COMPLETE" and all(
            (
                self.commercial_use_allowed,
                self.transform_allowed,
                self.display_allowed,
                self.model_input_allowed,
            )
        )


class SupplementalAssetProvenance(StrictContract):
    """Asset/page provenance whose restrictions may narrow the dataset grant."""

    source_asset_id: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    creator_or_photographer: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    license_type: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=160),
    ] = None
    attribution_text: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    explicit_asset_restriction: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    attachment_rights_granting: Literal[False] = False


class SupplementalEvidenceAtom(StrictContract):
    """One fixed-place, field-level evidence reference with derived disposition."""

    schema_version: Literal["itda.catalog-supplemental-evidence.v1"]
    place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    source_kind: SourceKind
    source_owner: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    official_dataset_or_page_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=500),
    ]
    operation_or_page_identity: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=500),
    ]
    provider_candidate_id: Annotated[
        str | None,
        Field(
            strict=True,
            min_length=1,
            max_length=240,
            pattern=r"^candidate:[a-z0-9-]+:[A-Za-z0-9._:-]+$",
        ),
    ] = None
    source_record_or_asset_id: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    original_url: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=2_000),
    ] = None
    retrieved_at: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    immutable_relative_path: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    raw_or_page_sha256: Sha256
    value_sha256: Sha256 | None
    parent_manifest_sha256: Sha256
    field_name: FieldName
    binding_state: BindingState
    binding_method: BindingMethod
    binding_evidence_sha256: Sha256
    dataset_grant: SupplementalDatasetGrant
    asset_provenance: SupplementalAssetProvenance
    field_state: Literal["POPULATED", "MISSING", "BLOCKED", "REVIEW_REQUIRED"]
    reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
        ...,
    ]
    analysis_eligible: Annotated[bool, Field(strict=True)]
    ui_eligible: Annotated[bool, Field(strict=True)]
    demo_eligible: Annotated[bool, Field(strict=True)]
    confidence_is_qualification_filter_only: Literal[True] = True
    confidence_adds_score: Literal[False] = False
    canonical_membership_created: Literal[False] = False
    atom_sha256: Sha256

    def _derived_disposition(self) -> tuple[str, tuple[str, ...], bool]:
        if self.binding_state == "REVIEW_REQUIRED":
            return "REVIEW_REQUIRED", ("IDENTITY_BINDING_REVIEW_REQUIRED",), False
        if self.binding_method not in _EXACT_BINDING_METHODS:
            raise ValueError("exact binding requires exact immutable evidence")
        if self.value_sha256 is None:
            return "MISSING", ("SOURCE_VALUE_MISSING",), False
        grant = self.dataset_grant
        asset = self.asset_provenance
        if grant.evidence_state == "MISSING":
            return "BLOCKED", ("DATASET_GRANT_MISSING",), False
        if grant.evidence_state == "INCOMPLETE":
            return "BLOCKED", ("DATASET_GRANT_INCOMPLETE",), False
        if _license_is_type_3_or_4(grant.license_type):
            return "BLOCKED", ("DATASET_TYPE_3_OR_4_BLOCKED",), False
        if not grant.allows_all_lanes:
            return "BLOCKED", ("DATASET_GRANT_LANES_INCOMPLETE",), False
        if (
            asset.source_asset_id is None
            or asset.creator_or_photographer is None
            or asset.license_type is None
            or self.source_record_or_asset_id is None
            or self.original_url is None
        ):
            return "BLOCKED", ("ASSET_PROVENANCE_INCOMPLETE",), False
        if _license_is_type_3_or_4(asset.license_type):
            return "BLOCKED", ("ASSET_TYPE_3_OR_4_BLOCKED",), False
        if asset.explicit_asset_restriction is not None:
            return "BLOCKED", ("EXPLICIT_ASSET_RESTRICTION",), False
        return (
            "POPULATED",
            ("EXACT_IDENTITY_AND_INDEPENDENT_RIGHTS_ALLOWED",),
            True,
        )

    @model_validator(mode="after")
    def validate_atom(self) -> Self:
        _validate_relative_path(self.immutable_relative_path)
        if self.field_name not in _SOURCE_FIELDS[self.source_kind]:
            raise ValueError("source kind cannot support the claimed field")
        if self.source_kind == "OFFICIAL_SCRIPT" and (
            self.dataset_grant.official_dataset_id != "15101971"
            or self.official_dataset_or_page_id != "15101971"
        ):
            raise ValueError("source kind confusion: script evidence must use exact Odii")
        if self.source_kind == "OFFICIAL_ASSET" and self.field_name != (
            "exact_provider_direct_media"
        ):
            raise ValueError("source kind confusion: asset evidence is media only")
        if self.source_kind == "OFFICIAL_API_ROW" and (
            self.dataset_grant.official_dataset_id
            != self.official_dataset_or_page_id
        ):
            raise ValueError("source kind confusion: API row and dataset grant differ")
        exact_method = self.binding_method in _EXACT_BINDING_METHODS
        if (self.binding_state == "EXACT") != exact_method:
            raise ValueError("binding state and exact evidence method disagree")
        expected_state, expected_reasons, allowed = self._derived_disposition()
        if self.field_state != expected_state or self.reason_codes != expected_reasons:
            raise ValueError("field state is not independently rights/binding derived")
        if (self.analysis_eligible, self.ui_eligible, self.demo_eligible) != (
            allowed,
            allowed,
            allowed,
        ):
            raise ValueError("downstream lanes are not independently rights derived")
        expected = canonical_sha256(
            self.model_dump(exclude={"atom_sha256"}, mode="json")
        )
        if self.atom_sha256 != expected:
            raise ValueError("atom digest does not match exact evidence")
        return self


class SupplementalEvidenceAtomSet(StrictContract):
    schema_version: Literal["itda.catalog-supplemental-evidence-set.v1"]
    data_version: Literal["catalog-v2-supplemental-evidence-data-v1"]
    terminal_aggregate_sha256: Sha256
    atoms: tuple[SupplementalEvidenceAtom, ...]
    atom_count: Annotated[int, Field(strict=True, ge=0)]
    field_state_counts: dict[
        Literal["POPULATED", "MISSING", "BLOCKED", "REVIEW_REQUIRED"],
        Annotated[int, Field(strict=True, ge=0)],
    ]
    atoms_root: Sha256
    confidence_is_qualification_filter_only: Literal[True]
    confidence_adds_score: Literal[False]
    canonical_membership_created: Literal[False]
    atom_set_sha256: Sha256

    @model_validator(mode="after")
    def validate_set(self) -> Self:
        identities = tuple(row.atom_sha256 for row in self.atoms)
        if len(set(identities)) != len(identities):
            raise ValueError("supplemental atom set contains a duplicate atom")
        if identities != tuple(sorted(identities)):
            raise ValueError("supplemental atoms must use canonical digest order")
        if self.atom_count != len(self.atoms):
            raise ValueError("supplemental atom count is not row-derived")
        counts = Counter(row.field_state for row in self.atoms)
        expected_counts = {state: counts[state] for state in FIELD_STATES}
        if self.field_state_counts != expected_counts:
            raise ValueError("supplemental field counts are not row-derived")
        expected_root = canonical_sha256(
            [row.model_dump(mode="json") for row in self.atoms]
        )
        if self.atoms_root != expected_root:
            raise ValueError("supplemental atom root is not row-derived")
        expected = canonical_sha256(
            self.model_dump(exclude={"atom_set_sha256"}, mode="json")
        )
        if self.atom_set_sha256 != expected:
            raise ValueError("supplemental atom-set digest does not match")
        return self


class SupplementalManifestChild(StrictContract):
    relpath: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]
    role: Literal["TARGET_LEDGER", "EVIDENCE_ATOMS", "LINEAGE_ATTESTATION"]
    entry_type: Literal["REGULAR_FILE"]
    mode: Literal["0600"]
    size: Annotated[int, Field(strict=True, ge=0)]
    file_sha256: Sha256
    row_count: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def validate_child(self) -> Self:
        _validate_relative_path(self.relpath)
        return self


class SupplementalEvidenceManifest(StrictContract):
    schema_version: Literal["itda.catalog-supplemental-evidence-manifest.v1"]
    terminal_aggregate_sha256: Sha256
    atom_set_sha256: Sha256
    children: tuple[SupplementalManifestChild, ...]
    child_count: Literal[3]
    evidence_atom_count: Annotated[int, Field(strict=True, ge=0)]
    children_root: Sha256
    confidence_adds_score: Literal[False]
    canonical_membership_created: Literal[False]
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        expected_roles = ("LINEAGE_ATTESTATION", "TARGET_LEDGER", "EVIDENCE_ATOMS")
        if tuple(row.role for row in self.children) != expected_roles:
            raise ValueError("supplemental manifest children use the wrong fixed order")
        if len({row.relpath for row in self.children}) != len(self.children):
            raise ValueError("supplemental manifest repeats a child path")
        atom_child = self.children[-1]
        if self.evidence_atom_count != atom_child.row_count:
            raise ValueError("supplemental evidence count is not child-derived")
        expected_root = canonical_sha256(
            [row.model_dump(mode="json") for row in self.children]
        )
        if self.children_root != expected_root:
            raise ValueError("supplemental manifest child root is not row-derived")
        expected = canonical_sha256(
            self.model_dump(exclude={"manifest_sha256"}, mode="json")
        )
        if self.manifest_sha256 != expected:
            raise ValueError("supplemental evidence manifest digest does not match")
        return self


def _coerce_grant(
    value: SupplementalDatasetGrant | Mapping[str, object],
) -> SupplementalDatasetGrant:
    if isinstance(value, SupplementalDatasetGrant):
        return value
    return SupplementalDatasetGrant.model_validate(dict(value))


def _coerce_asset(
    value: SupplementalAssetProvenance | Mapping[str, object],
) -> SupplementalAssetProvenance:
    if isinstance(value, SupplementalAssetProvenance):
        return value
    return SupplementalAssetProvenance.model_validate(dict(value))


def build_supplemental_evidence_atom(
    *,
    place_entity_id: str,
    source_kind: SourceKind,
    source_owner: str,
    official_dataset_or_page_id: str,
    operation_or_page_identity: str,
    provider_candidate_id: str | None,
    source_record_or_asset_id: str | None,
    original_url: str | None,
    retrieved_at: str,
    immutable_relative_path: str,
    raw_or_page_sha256: str,
    value_sha256: str | None,
    parent_manifest_sha256: str,
    field_name: FieldName,
    binding_state: BindingState,
    binding_method: BindingMethod,
    binding_evidence_sha256: str,
    dataset_grant: SupplementalDatasetGrant | Mapping[str, object],
    asset_provenance: SupplementalAssetProvenance | Mapping[str, object],
) -> SupplementalEvidenceAtom:
    """Derive one field disposition without accepting caller eligibility state."""

    grant = _coerce_grant(dataset_grant)
    asset = _coerce_asset(asset_provenance)
    provisional = {
        "schema_version": SCHEMA_VERSION,
        "place_entity_id": place_entity_id,
        "source_kind": source_kind,
        "source_owner": source_owner,
        "official_dataset_or_page_id": official_dataset_or_page_id,
        "operation_or_page_identity": operation_or_page_identity,
        "provider_candidate_id": provider_candidate_id,
        "source_record_or_asset_id": source_record_or_asset_id,
        "original_url": original_url,
        "retrieved_at": retrieved_at,
        "immutable_relative_path": _validate_relative_path(immutable_relative_path),
        "raw_or_page_sha256": raw_or_page_sha256,
        "value_sha256": value_sha256,
        "parent_manifest_sha256": parent_manifest_sha256,
        "field_name": field_name,
        "binding_state": binding_state,
        "binding_method": binding_method,
        "binding_evidence_sha256": binding_evidence_sha256,
        "dataset_grant": grant,
        "asset_provenance": asset,
        "field_state": "MISSING",
        "reason_codes": ("SOURCE_VALUE_MISSING",),
        "analysis_eligible": False,
        "ui_eligible": False,
        "demo_eligible": False,
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
        "canonical_membership_created": False,
    }
    probe = SupplementalEvidenceAtom.model_construct(**provisional, atom_sha256="0" * 64)
    state, reasons, allowed = probe._derived_disposition()
    fields = {
        **provisional,
        "field_state": state,
        "reason_codes": reasons,
        "analysis_eligible": allowed,
        "ui_eligible": allowed,
        "demo_eligible": allowed,
    }
    digest_fields = {
        **fields,
        "dataset_grant": grant.model_dump(mode="json"),
        "asset_provenance": asset.model_dump(mode="json"),
    }
    return SupplementalEvidenceAtom(
        **fields,
        atom_sha256=canonical_sha256(digest_fields),
    )


def build_supplemental_atom_set(
    *,
    terminal_aggregate_sha256: str,
    atoms: tuple[SupplementalEvidenceAtom, ...],
) -> SupplementalEvidenceAtomSet:
    ordered = tuple(sorted(atoms, key=lambda row: row.atom_sha256))
    counts = Counter(row.field_state for row in ordered)
    fields = {
        "schema_version": "itda.catalog-supplemental-evidence-set.v1",
        "data_version": DATA_VERSION,
        "terminal_aggregate_sha256": terminal_aggregate_sha256,
        "atoms": [row.model_dump(mode="json") for row in ordered],
        "atom_count": len(ordered),
        "field_state_counts": {state: counts[state] for state in FIELD_STATES},
        "atoms_root": canonical_sha256(
            [row.model_dump(mode="json") for row in ordered]
        ),
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
        "canonical_membership_created": False,
    }
    return SupplementalEvidenceAtomSet(
        **fields,
        atom_set_sha256=canonical_sha256(fields),
    )


def build_supplemental_manifest(
    *,
    terminal_aggregate_sha256: str,
    atom_set_sha256: str,
    children: tuple[SupplementalManifestChild, ...],
) -> SupplementalEvidenceManifest:
    fields = {
        "schema_version": "itda.catalog-supplemental-evidence-manifest.v1",
        "terminal_aggregate_sha256": terminal_aggregate_sha256,
        "atom_set_sha256": atom_set_sha256,
        "children": [row.model_dump(mode="json") for row in children],
        "child_count": 3,
        "evidence_atom_count": children[-1].row_count,
        "children_root": canonical_sha256(
            [row.model_dump(mode="json") for row in children]
        ),
        "confidence_adds_score": False,
        "canonical_membership_created": False,
    }
    return SupplementalEvidenceManifest(
        **fields,
        manifest_sha256=canonical_sha256(fields),
    )


__all__ = [
    "DATA_VERSION",
    "SCHEMA_VERSION",
    "SupplementalAssetProvenance",
    "SupplementalDatasetGrant",
    "SupplementalEvidenceAtom",
    "SupplementalEvidenceAtomSet",
    "SupplementalEvidenceManifest",
    "SupplementalManifestChild",
    "build_supplemental_atom_set",
    "build_supplemental_evidence_atom",
    "build_supplemental_manifest",
]
