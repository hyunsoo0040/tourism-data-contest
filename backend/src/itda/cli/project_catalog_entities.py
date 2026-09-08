"""Build and verify the immutable source-neutral catalog entity projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from itda.cli import fingerprint_catalog_v1
from itda.contracts.catalog_audit import CatalogAudit
from itda.contracts.catalog_collection import CollectionReport
from itda.contracts.catalog_entity import (
    ContentEntityProjection,
    DatasetRecordProjection,
    EntityEvidence,
    EntityKind,
    EntityProjection,
    EntityRef,
    PlaceEntityProjection,
    ProjectionCounts,
    ProjectionParents,
    ProtectedFileBinding,
    SeedLineageProjection,
    TypedRelationshipProjection,
    projection_schema_sha256,
)
from itda.contracts.crosswalk import CrosswalkReviewArtifact, RelationshipReviewArtifact
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

PROTECTED_PARENT_PATHS = (
    "artifacts/restricted/catalog/v1/collection/collection-report.json",
    "artifacts/restricted/catalog/v1/review/catalog-audit.json",
    "artifacts/restricted/catalog/v1/review/crosswalk-review.json",
    "artifacts/restricted/catalog/v1/review/relationship-review.json",
)
CODE_PATHS = (
    "backend/src/itda/cli/project_catalog_entities.py",
    "backend/src/itda/contracts/catalog_entity.py",
)
CONFIG_PATHS = ("backend/pyproject.toml",)


class ProjectionError(ValueError):
    """Raised when protected parents cannot produce a complete projection."""


def _entity_ref(kind: EntityKind, identity: dict[str, object]) -> EntityRef:
    prefix = {
        EntityKind.DATASET_RECORD: "dataset",
        EntityKind.PLACE: "place",
        EntityKind.ODII_CONTENT: "odii",
        EntityKind.PHOTO_ASSET: "photo",
    }[kind]
    return EntityRef(kind=kind, entity_id=f"{prefix}:{canonical_sha256(identity)}")


def _source_row_sha256(row: object) -> str:
    if hasattr(row, "model_dump"):
        return canonical_sha256(row.model_dump(mode="json"))  # type: ignore[attr-defined]
    return canonical_sha256(row)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_relative(repo_root: Path, path: Path, expected: str) -> Path:
    resolved = (path if path.is_absolute() else Path.cwd() / path).resolve()
    try:
        relpath = resolved.relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise ProjectionError("projection input escapes the repository") from exc
    if relpath != expected:
        raise ProjectionError(f"projection input must be the protected parent {expected}")
    return resolved


def _load_contract(path: Path, contract: type[Any]) -> Any:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ProjectionError("protected parent is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | fingerprint_catalog_v1.O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        fingerprint_catalog_v1._same_object(before, after)
        raw = fingerprint_catalog_v1._read_descriptor(descriptor)
        fingerprint_catalog_v1._same_state(after, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    return contract.model_validate(json.loads(raw))


def _protected_parents(
    manifest: dict[str, object],
) -> ProjectionParents:
    catalog = manifest.get("catalog_v1")
    if not isinstance(catalog, dict):
        raise ProjectionError("immutability manifest is missing catalog_v1")
    entries = catalog.get("entries")
    if not isinstance(entries, list):
        raise ProjectionError("immutability manifest is missing catalog entries")
    by_path = {
        str(entry.get("relpath")): entry
        for entry in entries
        if isinstance(entry, dict)
    }
    bindings: list[ProtectedFileBinding] = []
    for relpath in PROTECTED_PARENT_PATHS:
        entry = by_path.get(relpath)
        if entry is None:
            raise ProjectionError(f"protected parent is absent from manifest: {relpath}")
        row = {
            "relpath": entry.get("relpath"),
            "entry_type": entry.get("entry_type"),
            "mode": entry.get("mode"),
            "size_bytes": entry.get("size_bytes"),
            "sha256": entry.get("sha256"),
            "no_follow_result": entry.get("no_follow_result"),
        }
        bindings.append(
            ProtectedFileBinding(
                relpath=str(row["relpath"]),
                entry_type=row["entry_type"],
                mode=row["mode"],
                size_bytes=row["size_bytes"],
                file_sha256=row["sha256"],
                no_follow_result=row["no_follow_result"],
                manifest_entry_sha256=canonical_sha256(row),
            )
        )
    frozen = tuple(bindings)
    return ProjectionParents(
        immutability_manifest_sha256=manifest["manifest_sha256"],
        catalog_v1_tree_sha256=catalog["tree_sha256"],
        protected_files=frozen,
        protected_files_sha256=canonical_sha256(
            [item.model_dump(mode="json") for item in frozen]
        ),
    )


def _validate_complete_inputs(
    collection: CollectionReport,
    crosswalk: CrosswalkReviewArtifact,
    relationship: RelationshipReviewArtifact,
    audit: CatalogAudit,
) -> None:
    candidates = {item.candidate_id for item in collection.candidates}
    audit_ids = {item.candidate_id for item in audit.rows}
    evidence_ids = [
        item.candidate_id
        for proposal in crosswalk.proposals
        for item in proposal.evidence
    ]
    if candidates != audit_ids:
        raise ProjectionError("collection and audit candidate inventories differ")
    if len(evidence_ids) != len(candidates) or set(evidence_ids) != candidates:
        raise ProjectionError("crosswalk evidence must cover every candidate exactly once")
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ProjectionError("candidate appears in multiple crosswalk proposals")
    if {
        endpoint
        for proposal in relationship.proposals
        for endpoint in (proposal.left_subject_ref, proposal.right_subject_ref)
    } - candidates:
        raise ProjectionError("relationship proposal has an unknown candidate endpoint")
    if len(collection.seed_dispositions) != 36 or len(audit.seed_rows) != 36:
        raise ProjectionError("projection requires all 36 proposal seed rows")
    if tuple(item.seed_id for item in collection.seed_dispositions) != tuple(
        item.seed_id for item in audit.seed_rows
    ):
        raise ProjectionError("collection and audit seed inventories differ")
    if crosswalk.source_lineage.collection_report_sha256 != collection.report_sha256:
        raise ProjectionError("crosswalk does not bind the loaded collection report")
    if relationship.source_lineage.collection_report_sha256 != collection.report_sha256:
        raise ProjectionError("relationship does not bind the loaded collection report")
    if relationship.source_crosswalk_artifact_sha256 != crosswalk.artifact_sha256:
        raise ProjectionError("relationship does not bind the loaded crosswalk artifact")


def build_projection(
    *,
    repo_root: Path,
    immutability_manifest: Path,
    collection_report: Path,
    crosswalk_review: Path,
    relationship_review: Path,
    catalog_audit: Path,
) -> EntityProjection:
    """Project every protected v1 row; all aggregate totals derive internally."""

    expected_paths = dict(
        zip(
            (
                "collection",
                "audit",
                "crosswalk",
                "relationship",
            ),
            PROTECTED_PARENT_PATHS,
            strict=True,
        )
    )
    manifest_path = _repo_relative(
        repo_root,
        immutability_manifest,
        "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json",
    )
    collection_path = _repo_relative(
        repo_root, collection_report, expected_paths["collection"]
    )
    crosswalk_path = _repo_relative(
        repo_root, crosswalk_review, expected_paths["crosswalk"]
    )
    relationship_path = _repo_relative(
        repo_root, relationship_review, expected_paths["relationship"]
    )
    audit_path = _repo_relative(repo_root, catalog_audit, expected_paths["audit"])

    manifest = fingerprint_catalog_v1.verify_manifest(repo_root, manifest_path)
    parents = _protected_parents(manifest)
    collection = _load_contract(collection_path, CollectionReport)
    crosswalk = _load_contract(crosswalk_path, CrosswalkReviewArtifact)
    relationship = _load_contract(relationship_path, RelationshipReviewArtifact)
    audit = _load_contract(audit_path, CatalogAudit)
    _validate_complete_inputs(collection, crosswalk, relationship, audit)

    candidate_by_id = {item.candidate_id: item for item in collection.candidates}
    audit_by_id = {item.candidate_id: item for item in audit.rows}
    dataset_ref_by_candidate = {
        item.candidate_id: _entity_ref(
            EntityKind.DATASET_RECORD,
            {
                "kind": EntityKind.DATASET_RECORD.value,
                "provider": item.provider,
                "official_dataset_id": item.official_dataset_id,
                "provider_content_id": item.provider_content_id,
            },
        )
        for item in collection.candidates
    }
    place_ref_by_candidate: dict[str, EntityRef] = {}
    place_entities: list[PlaceEntityProjection] = []
    evidence_by_candidate: dict[str, EntityEvidence] = {}
    for proposal_ordinal, proposal in enumerate(crosswalk.proposals):
        place_ref = _entity_ref(
            EntityKind.PLACE,
            {
                "kind": EntityKind.PLACE.value,
                "canonical_place_id": proposal.canonical_place_id,
                "proposal_id": proposal.proposal_id,
            },
        )
        member_refs: list[EntityRef] = []
        for evidence in proposal.evidence:
            if evidence.candidate_id is None or evidence.official_dataset_id is None:
                raise ProjectionError("crosswalk evidence lacks exact candidate scope")
            candidate = candidate_by_id[evidence.candidate_id]
            if (
                candidate.provider != evidence.provider
                or candidate.official_dataset_id != evidence.official_dataset_id
                or candidate.provider_content_id != evidence.source_alias_id
            ):
                raise ProjectionError("crosswalk evidence does not match candidate identity")
            dataset_ref = dataset_ref_by_candidate[evidence.candidate_id]
            place_ref_by_candidate[evidence.candidate_id] = place_ref
            member_refs.append(dataset_ref)
            evidence_by_candidate[evidence.candidate_id] = EntityEvidence(
                evidence_tier="T0_EXACT_PROVIDER_SCOPED_ID",
                provider=evidence.provider,
                official_dataset_id=evidence.official_dataset_id,
                provider_record_id=evidence.source_alias_id,
                source_row_sha256=evidence.evidence_sha256,
                address=evidence.gyeongju_address,
                latitude=evidence.latitude,
                longitude=evidence.longitude,
                hierarchy=evidence.hierarchy_path,
            )
        place_entities.append(
            PlaceEntityProjection(
                ref=place_ref,
                proposal_ordinal=proposal_ordinal,
                source_row_id=f"crosswalk:{proposal.proposal_id}",
                source_row_sha256=_source_row_sha256(proposal),
                source_proposal_id=proposal.proposal_id,
                source_canonical_place_id=proposal.canonical_place_id,
                member_refs=tuple(member_refs),
                source_status=proposal.status,
                source_matching_rule=proposal.matching_rule,
                review_reasons=proposal.review_reasons,
            )
        )

    audit_ordinal_by_candidate = {
        row.candidate_id: ordinal for ordinal, row in enumerate(audit.rows)
    }
    dataset_records = tuple(
        DatasetRecordProjection(
            ref=dataset_ref_by_candidate[candidate.candidate_id],
            candidate_ordinal=ordinal,
            audit_ordinal=audit_ordinal_by_candidate[candidate.candidate_id],
            source_candidate_id=candidate.candidate_id,
            source_candidate_sha256=_source_row_sha256(candidate),
            source_audit_sha256=_source_row_sha256(
                audit_by_id[candidate.candidate_id]
            ),
            name_ko=candidate.name_ko,
            evidence=evidence_by_candidate[candidate.candidate_id],
            place_ref=place_ref_by_candidate[candidate.candidate_id],
            audit_latitude=audit_by_id[candidate.candidate_id].latitude,
            audit_longitude=audit_by_id[candidate.candidate_id].longitude,
            coordinate_missing_reason=audit_by_id[
                candidate.candidate_id
            ].coordinate_missing_reason,
        )
        for ordinal, candidate in enumerate(collection.candidates)
    )

    odii_contents: list[ContentEntityProjection] = []
    photo_assets: list[ContentEntityProjection] = []
    for audit_row in audit.rows:
        asset = audit_row.asset
        if asset is None or asset.content_kind == "TOURAPI_DESCRIPTION":
            continue
        if asset.source_asset_id is None or asset.source_response_sha256 is None:
            raise ProjectionError("content entity lacks exact source identity")
        entity_kind = (
            EntityKind.ODII_CONTENT
            if asset.content_kind == "ODII_SCRIPT_AUDIO_TEXT"
            else EntityKind.PHOTO_ASSET
        )
        content = ContentEntityProjection(
            ref=_entity_ref(
                entity_kind,
                {
                    "kind": entity_kind.value,
                    "official_dataset_id": asset.official_dataset_id,
                    "source_asset_id": asset.source_asset_id,
                    "content_kind": asset.content_kind,
                },
            ),
            owner_dataset_ref=dataset_ref_by_candidate[audit_row.candidate_id],
            source_audit_sha256=_source_row_sha256(audit_row),
            official_dataset_id=asset.official_dataset_id,
            source_asset_id=asset.source_asset_id,
            content_kind=asset.content_kind,
            source_response_sha256=asset.source_response_sha256,
        )
        if entity_kind is EntityKind.ODII_CONTENT:
            odii_contents.append(content)
        else:
            photo_assets.append(content)

    relationships = tuple(
        TypedRelationshipProjection(
            source_row_id=f"relationship:{proposal.proposal_id}",
            source_row_sha256=_source_row_sha256(proposal),
            relationship_type=proposal.relationship_type.value,
            left=dataset_ref_by_candidate[proposal.left_subject_ref],
            right=dataset_ref_by_candidate[proposal.right_subject_ref],
            evidence_refs=(
                proposal.evidence_sha256,
                proposal.source_crosswalk_proposal_sha256,
                proposal.collection_report_sha256,
            ),
            automatic_identity_merge=False,
            source_status=proposal.status,
            evidence_reason=proposal.evidence_reason,
        )
        for proposal in relationship.proposals
    )
    seed_lineage = tuple(
        SeedLineageProjection(
            seed_id=seed.seed_id,
            status=seed.status,
            candidate_ref=(
                dataset_ref_by_candidate[seed.candidate_id]
                if seed.candidate_id is not None
                else None
            ),
            evidence_sha256=seed.evidence_sha256,
            source_row_sha256=_source_row_sha256(seed),
        )
        for seed in collection.seed_dispositions
    )

    counts = ProjectionCounts(
        dataset_record_count=len(dataset_records),
        place_entity_count=len(place_entities),
        odii_content_count=len(odii_contents),
        photo_asset_count=len(photo_assets),
        crosswalk_proposal_count=len(place_entities),
        relationship_proposal_count=len(relationships),
        audit_row_count=len(dataset_records),
        proposal_seed_count=len(seed_lineage),
    )
    roots = {
        "dataset_records": canonical_sha256(
            [item.model_dump(mode="json") for item in dataset_records]
        ),
        "place_entities": canonical_sha256(
            [item.model_dump(mode="json") for item in place_entities]
        ),
        "odii_contents": canonical_sha256(
            [item.model_dump(mode="json") for item in odii_contents]
        ),
        "photo_assets": canonical_sha256(
            [item.model_dump(mode="json") for item in photo_assets]
        ),
        "relationships": canonical_sha256(
            [item.model_dump(mode="json") for item in relationships]
        ),
        "seed_lineage": canonical_sha256(
            [item.model_dump(mode="json") for item in seed_lineage]
        ),
    }
    fields: dict[str, object] = {
        "schema_version": "catalog-entity-projection-v1",
        "data_version": "catalog-v2-projection-data-v1",
        "identity_algorithm_version": "typed-source-neutral-entity-v1",
        "parents": parents.model_dump(mode="json"),
        "schema_sha256": projection_schema_sha256(),
        "code_hashes": {
            path: _file_sha256(repo_root / path) for path in CODE_PATHS
        },
        "config_hashes": {
            path: _file_sha256(repo_root / path) for path in CONFIG_PATHS
        },
        "collection_report_sha256": collection.report_sha256,
        "crosswalk_artifact_sha256": crosswalk.artifact_sha256,
        "relationship_artifact_sha256": relationship.artifact_sha256,
        "catalog_audit_sha256": audit.audit_sha256,
        "seed_manifest_sha256": collection.seed_manifest_sha256,
        "dataset_records": [
            item.model_dump(mode="json") for item in dataset_records
        ],
        "place_entities": [
            item.model_dump(mode="json") for item in place_entities
        ],
        "odii_contents": [
            item.model_dump(mode="json") for item in odii_contents
        ],
        "photo_assets": [
            item.model_dump(mode="json") for item in photo_assets
        ],
        "relationships": [
            item.model_dump(mode="json") for item in relationships
        ],
        "seed_lineage": [
            item.model_dump(mode="json") for item in seed_lineage
        ],
        "counts": counts.model_dump(mode="json"),
        "roots": roots,
    }
    projection = EntityProjection.model_validate(
        {**fields, "projection_sha256": canonical_sha256(fields)}
    )
    if (
        fingerprint_catalog_v1.scan_catalog_tree(repo_root)["tree_sha256"]
        != parents.catalog_v1_tree_sha256
    ):
        raise ProjectionError("protected parents changed while projecting")
    return projection


def _repo_root() -> Path:
    return fingerprint_catalog_v1._repo_root()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", type=Path, metavar="PROJECTION")
    modes.add_argument("--check", type=Path, metavar="PROJECTION")
    parser.add_argument("--immutability-manifest", type=Path, required=True)
    parser.add_argument("--collection-report", type=Path, required=True)
    parser.add_argument("--crosswalk-review", type=Path, required=True)
    parser.add_argument("--relationship-review", type=Path, required=True)
    parser.add_argument("--catalog-audit", type=Path, required=True)
    return parser


def _build_from_args(repo_root: Path, args: argparse.Namespace) -> EntityProjection:
    return build_projection(
        repo_root=repo_root,
        immutability_manifest=args.immutability_manifest,
        collection_report=args.collection_report,
        crosswalk_review=args.crosswalk_review,
        relationship_review=args.relationship_review,
        catalog_audit=args.catalog_audit,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = _repo_root()
    target_value = args.build if args.build is not None else args.check
    assert target_value is not None
    target = fingerprint_catalog_v1._cli_path(repo_root, target_value)
    if args.build is not None:
        first = _build_from_args(repo_root, args)
        first_bytes = canonical_json_bytes(first.model_dump(mode="json"))
        second = _build_from_args(repo_root, args)
        second_bytes = canonical_json_bytes(second.model_dump(mode="json"))
        if first_bytes != second_bytes:
            raise ProjectionError("two protected-parent builds were not byte-identical")
        fingerprint_catalog_v1._write_no_replace(target, first_bytes)
    else:
        first = _build_from_args(repo_root, args)
        first_bytes = canonical_json_bytes(first.model_dump(mode="json"))
        recorded = _load_contract(target, EntityProjection)
        if canonical_json_bytes(recorded.model_dump(mode="json")) != first_bytes:
            raise ProjectionError("recorded projection differs from protected-parent rebuild")
    print(first.projection_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
