"""Source-neutral typed entity projection contracts for protected catalog v1 rows."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract
from itda.domain.canonical import canonical_sha256

Provider = Literal["TOUR_API", "ODII", "TOURISM_PHOTO"]
EvidenceTier = Literal[
    "T0_EXACT_PROVIDER_SCOPED_ID",
    "T1_STRUCTURED_AMBIGUOUS",
    "T2_TITLE_OR_PROXIMITY_ONLY",
    "MISSING",
]

OFFICIAL_DATASET_BY_PROVIDER: dict[str, str] = {
    "TOUR_API": "15101578",
    "ODII": "15101971",
    "TOURISM_PHOTO": "15101914",
}


class EntityKind(StrEnum):
    DATASET_RECORD = "DATASET_RECORD"
    PLACE = "PLACE"
    ODII_CONTENT = "ODII_CONTENT"
    PHOTO_ASSET = "PHOTO_ASSET"


class RelationshipType(StrEnum):
    DUPLICATE_EQUIVALENT = "DUPLICATE_EQUIVALENT"
    PARENT_CHILD = "PARENT_CHILD"
    CANNOT_COAPPEAR = "CANNOT_COAPPEAR"


ENTITY_PREFIX = {
    EntityKind.DATASET_RECORD: "dataset",
    EntityKind.PLACE: "place",
    EntityKind.ODII_CONTENT: "odii",
    EntityKind.PHOTO_ASSET: "photo",
}


class EntityRef(StrictContract):
    kind: EntityKind
    entity_id: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^(dataset|place|odii|photo):[0-9a-f]{64}$",
        ),
    ]

    @model_validator(mode="after")
    def validate_kind_namespace(self) -> Self:
        expected = ENTITY_PREFIX[self.kind]
        if not self.entity_id.startswith(f"{expected}:"):
            raise ValueError("entity namespace does not match entity kind")
        return self


class EntityEvidence(StrictContract):
    evidence_tier: EvidenceTier
    provider: Provider
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    provider_record_id: StableId
    source_row_sha256: Sha256
    address: Annotated[str | None, Field(strict=True, min_length=1, max_length=500)] = None
    latitude: Annotated[float | None, Field(strict=True, ge=-90, le=90)] = None
    longitude: Annotated[float | None, Field(strict=True, ge=-180, le=180)] = None
    hierarchy: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=240)],
        ...,
    ] = ()

    @property
    def automatic_identity_eligible(self) -> bool:
        return self.evidence_tier == "T0_EXACT_PROVIDER_SCOPED_ID"

    @model_validator(mode="after")
    def validate_exact_scope(self) -> Self:
        if self.official_dataset_id != OFFICIAL_DATASET_BY_PROVIDER[self.provider]:
            raise ValueError("provider record evidence is outside its exact dataset scope")
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("identity coordinates must be present together")
        return self


def validate_automatic_identity_evidence(evidence: EntityEvidence) -> EntityEvidence:
    if not evidence.automatic_identity_eligible:
        raise ValueError("automatic identity requires T0 exact provider-scoped evidence")
    return evidence


class ProtectedFileBinding(StrictContract):
    relpath: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=500, pattern=r"^[A-Za-z0-9._/-]+$"),
    ]
    entry_type: Literal["regular_file"]
    mode: Annotated[str, Field(strict=True, pattern=r"^0o100[0-7]{3}$")]
    size_bytes: Annotated[int, Field(strict=True, ge=1)]
    file_sha256: Sha256
    no_follow_result: Literal["REGULAR_FILE_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH"]
    manifest_entry_sha256: Sha256

    @model_validator(mode="after")
    def validate_entry_hash(self) -> Self:
        entry = {
            "relpath": self.relpath,
            "entry_type": self.entry_type,
            "mode": self.mode,
            "size_bytes": self.size_bytes,
            "sha256": self.file_sha256,
            "no_follow_result": self.no_follow_result,
        }
        if self.manifest_entry_sha256 != canonical_sha256(entry):
            raise ValueError("protected file manifest entry hash does not match")
        return self


class ProjectionParents(StrictContract):
    immutability_manifest_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_files: tuple[ProtectedFileBinding, ...]
    protected_files_sha256: Sha256

    @model_validator(mode="after")
    def validate_parent_order_and_hash(self) -> Self:
        paths = tuple(item.relpath for item in self.protected_files)
        if paths != tuple(sorted(paths, key=lambda item: item.encode("utf-8"))):
            raise ValueError("protected parent paths must use canonical byte order")
        if len(set(paths)) != len(paths):
            raise ValueError("protected parent paths must be unique")
        expected = canonical_sha256(
            [item.model_dump(mode="json") for item in self.protected_files]
        )
        if self.protected_files_sha256 != expected:
            raise ValueError("protected parent root does not match file bindings")
        return self


class DatasetRecordProjection(StrictContract):
    ref: EntityRef
    candidate_ordinal: Annotated[int, Field(strict=True, ge=0)]
    audit_ordinal: Annotated[int, Field(strict=True, ge=0)]
    source_candidate_id: StableId
    source_candidate_sha256: Sha256
    source_audit_sha256: Sha256
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    evidence: EntityEvidence
    place_ref: EntityRef
    audit_latitude: Annotated[float | None, Field(strict=True, ge=-90, le=90)] = None
    audit_longitude: Annotated[float | None, Field(strict=True, ge=-180, le=180)] = None
    coordinate_missing_reason: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None

    @model_validator(mode="after")
    def validate_record_kinds_and_coordinates(self) -> Self:
        if self.ref.kind is not EntityKind.DATASET_RECORD:
            raise ValueError("dataset record projection requires DATASET_RECORD ref")
        if self.place_ref.kind is not EntityKind.PLACE:
            raise ValueError("dataset record projection requires PLACE owner ref")
        if (self.audit_latitude is None) != (self.audit_longitude is None):
            raise ValueError("audit coordinates must be present together")
        return self


class PlaceEntityProjection(StrictContract):
    ref: EntityRef
    proposal_ordinal: Annotated[int, Field(strict=True, ge=0)]
    source_row_id: Annotated[
        str,
        Field(strict=True, pattern=r"^crosswalk:[0-9a-f]{64}$"),
    ]
    source_row_sha256: Sha256
    source_proposal_id: Sha256
    source_canonical_place_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-z]{26}$"),
    ]
    member_refs: tuple[EntityRef, ...]
    source_status: Literal["EXACT_AUTO_LINK", "REVIEW_REQUIRED"]
    source_matching_rule: Literal[
        "EXACT_TITLE_ADDRESS_COORDINATE_HIERARCHY",
        "INSUFFICIENT_OR_CONFLICTING_EVIDENCE",
    ]
    review_reasons: tuple[str, ...]

    @model_validator(mode="after")
    def validate_place_projection(self) -> Self:
        if self.ref.kind is not EntityKind.PLACE:
            raise ValueError("place projection requires PLACE ref")
        if not self.member_refs:
            raise ValueError("place projection requires at least one dataset record")
        if any(item.kind is not EntityKind.DATASET_RECORD for item in self.member_refs):
            raise ValueError("place projection members must be dataset records")
        member_ids = tuple(item.entity_id for item in self.member_refs)
        if len(set(member_ids)) != len(member_ids):
            raise ValueError("place projection members must be unique")
        if self.source_status == "REVIEW_REQUIRED" and not self.review_reasons:
            raise ValueError("ambiguous place projection requires review reasons")
        return self


class ContentEntityProjection(StrictContract):
    ref: EntityRef
    owner_dataset_ref: EntityRef
    source_audit_sha256: Sha256
    official_dataset_id: Annotated[str, Field(strict=True, pattern=r"^[0-9]{8}$")]
    source_asset_id: StableId
    content_kind: Literal["ODII_SCRIPT_AUDIO_TEXT", "TOURISM_PHOTO_ASSET"]
    source_response_sha256: Sha256

    @model_validator(mode="after")
    def validate_content_kind(self) -> Self:
        if self.owner_dataset_ref.kind is not EntityKind.DATASET_RECORD:
            raise ValueError("content entity owner must be a dataset record")
        expected = {
            "ODII_SCRIPT_AUDIO_TEXT": EntityKind.ODII_CONTENT,
            "TOURISM_PHOTO_ASSET": EntityKind.PHOTO_ASSET,
        }[self.content_kind]
        if self.ref.kind is not expected:
            raise ValueError("content entity kind does not match content kind")
        return self


class TypedRelationshipProjection(StrictContract):
    source_row_id: Annotated[
        str,
        Field(strict=True, pattern=r"^relationship:[0-9a-f]{64}$"),
    ]
    source_row_sha256: Sha256
    relationship_type: RelationshipType
    left: EntityRef
    right: EntityRef
    evidence_refs: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=240)],
        ...,
    ]
    automatic_identity_merge: Annotated[bool, Field(strict=True)]
    source_status: Literal["PENDING_REVIEW", "REVIEWED"] = "PENDING_REVIEW"
    evidence_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)] = (
        "TYPED_RELATIONSHIP_EVIDENCE"
    )

    @model_validator(mode="after")
    def validate_relationship(self) -> Self:
        if self.left.entity_id == self.right.entity_id:
            raise ValueError("relationship projection cannot be a self-edge")
        if self.automatic_identity_merge:
            raise ValueError(
                f"{self.relationship_type.value} relationship cannot authorize identity merge"
            )
        if not self.evidence_refs:
            raise ValueError("relationship projection requires evidence")
        return self


class SeedLineageProjection(StrictContract):
    seed_id: Annotated[
        str,
        Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$"),
    ]
    status: Literal["LINKED", "MISSING_WITH_EVIDENCE", "EXCLUDED_WITH_EVIDENCE"]
    candidate_ref: EntityRef | None = None
    evidence_sha256: tuple[Sha256, ...]
    source_row_sha256: Sha256

    @model_validator(mode="after")
    def validate_membership_free_seed(self) -> Self:
        if (self.status == "LINKED") != (self.candidate_ref is not None):
            raise ValueError("only LINKED proposal seeds carry a dataset record ref")
        if self.candidate_ref is not None and (
            self.candidate_ref.kind is not EntityKind.DATASET_RECORD
        ):
            raise ValueError("proposal seed can reference only a dataset record")
        return self


class ProjectionCounts(StrictContract):
    dataset_record_count: Annotated[int, Field(strict=True, ge=0)]
    place_entity_count: Annotated[int, Field(strict=True, ge=0)]
    odii_content_count: Annotated[int, Field(strict=True, ge=0)]
    photo_asset_count: Annotated[int, Field(strict=True, ge=0)]
    crosswalk_proposal_count: Annotated[int, Field(strict=True, ge=0)]
    relationship_proposal_count: Annotated[int, Field(strict=True, ge=0)]
    audit_row_count: Annotated[int, Field(strict=True, ge=0)]
    proposal_seed_count: Annotated[int, Field(strict=True, ge=0)]


class EntityProjection(StrictContract):
    schema_version: Literal["catalog-entity-projection-v1"]
    data_version: Literal["catalog-v2-projection-data-v1"]
    identity_algorithm_version: Literal["typed-source-neutral-entity-v1"]
    parents: ProjectionParents
    schema_sha256: Sha256
    code_hashes: dict[str, Sha256]
    config_hashes: dict[str, Sha256]
    collection_report_sha256: Sha256
    crosswalk_artifact_sha256: Sha256
    relationship_artifact_sha256: Sha256
    catalog_audit_sha256: Sha256
    seed_manifest_sha256: Sha256
    dataset_records: tuple[DatasetRecordProjection, ...]
    place_entities: tuple[PlaceEntityProjection, ...]
    odii_contents: tuple[ContentEntityProjection, ...]
    photo_assets: tuple[ContentEntityProjection, ...]
    relationships: tuple[TypedRelationshipProjection, ...]
    seed_lineage: tuple[SeedLineageProjection, ...]
    counts: ProjectionCounts
    roots: dict[str, Sha256]
    projection_sha256: Sha256

    @model_validator(mode="after")
    def validate_full_projection(self) -> Self:
        if self.schema_sha256 != canonical_sha256(type(self).model_json_schema()):
            raise ValueError("schema_sha256 does not match the entity projection schema")
        expected_counts = ProjectionCounts(
            dataset_record_count=len(self.dataset_records),
            place_entity_count=len(self.place_entities),
            odii_content_count=len(self.odii_contents),
            photo_asset_count=len(self.photo_assets),
            crosswalk_proposal_count=len(self.place_entities),
            relationship_proposal_count=len(self.relationships),
            audit_row_count=len(self.dataset_records),
            proposal_seed_count=len(self.seed_lineage),
        )
        if self.counts != expected_counts:
            raise ValueError("projection counts must derive from complete row inventories")

        all_refs = tuple(
            record.ref
            for record in self.dataset_records
        ) + tuple(place.ref for place in self.place_entities) + tuple(
            item.ref for item in self.odii_contents
        ) + tuple(item.ref for item in self.photo_assets)
        all_ids = tuple(item.entity_id for item in all_refs)
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("typed entity IDs must be globally unique")

        dataset_ids = {item.ref.entity_id for item in self.dataset_records}
        place_ids = {item.ref.entity_id for item in self.place_entities}
        if any(item.place_ref.entity_id not in place_ids for item in self.dataset_records):
            raise ValueError("dataset record has a dangling place owner")
        projected_members = [
            member.entity_id
            for place in self.place_entities
            for member in place.member_refs
        ]
        if len(projected_members) != len(dataset_ids) or set(projected_members) != dataset_ids:
            raise ValueError("every dataset record must appear in exactly one place projection")
        if len(set(projected_members)) != len(projected_members):
            raise ValueError("dataset record cannot belong to two place projections")

        for item in (*self.odii_contents, *self.photo_assets):
            if item.owner_dataset_ref.entity_id not in dataset_ids:
                raise ValueError("content entity has a dangling dataset owner")
        for relationship in self.relationships:
            if {
                relationship.left.entity_id,
                relationship.right.entity_id,
            } - dataset_ids:
                raise ValueError("typed relationship has a dangling endpoint")

        expected_seed_ids = tuple(
            f"proposal:gyeongju:{index:03d}" for index in range(1, 37)
        )
        if tuple(item.seed_id for item in self.seed_lineage) != expected_seed_ids:
            raise ValueError("projection must preserve all 36 proposal seeds in order")
        if any(
            item.candidate_ref is not None
            and item.candidate_ref.entity_id not in dataset_ids
            for item in self.seed_lineage
        ):
            raise ValueError("proposal seed has a dangling candidate ref")

        expected_roots = {
            "dataset_records": canonical_sha256(
                [item.model_dump(mode="json") for item in self.dataset_records]
            ),
            "place_entities": canonical_sha256(
                [item.model_dump(mode="json") for item in self.place_entities]
            ),
            "odii_contents": canonical_sha256(
                [item.model_dump(mode="json") for item in self.odii_contents]
            ),
            "photo_assets": canonical_sha256(
                [item.model_dump(mode="json") for item in self.photo_assets]
            ),
            "relationships": canonical_sha256(
                [item.model_dump(mode="json") for item in self.relationships]
            ),
            "seed_lineage": canonical_sha256(
                [item.model_dump(mode="json") for item in self.seed_lineage]
            ),
        }
        if self.roots != expected_roots:
            raise ValueError("projection roots must derive from complete ordered leaves")
        expected_projection = canonical_sha256(
            self.model_dump(exclude={"projection_sha256"}, mode="json")
        )
        if self.projection_sha256 != expected_projection:
            raise ValueError("projection_sha256 does not match canonical projection fields")
        return self


def projection_schema_sha256() -> str:
    return canonical_sha256(EntityProjection.model_json_schema())


__all__ = [
    "ContentEntityProjection",
    "DatasetRecordProjection",
    "EntityEvidence",
    "EntityKind",
    "EntityProjection",
    "EntityRef",
    "PlaceEntityProjection",
    "ProjectionCounts",
    "ProjectionParents",
    "ProtectedFileBinding",
    "RelationshipType",
    "SeedLineageProjection",
    "TypedRelationshipProjection",
    "projection_schema_sha256",
    "validate_automatic_identity_evidence",
]
