"""Derive and verify the immutable catalog entity-policy report."""

from __future__ import annotations

import argparse
from pathlib import Path

from itda.cli import fingerprint_catalog_v1, project_catalog_entities
from itda.contracts.catalog_audit import CatalogAudit
from itda.contracts.catalog_collection import CollectionReport
from itda.contracts.catalog_entity import EntityProjection
from itda.contracts.catalog_entity_policy import (
    EXACT_MEDIA_RECORD_BINDINGS,
    POLICY_VERSION,
    EntityPolicyReport,
    MediaAttachment,
    PolicyCounts,
    PolicyDisposition,
    PolicyParents,
    PolicyResult,
    ProtectedPolicyInput,
    formal_policy_sha256,
    policy_schema_sha256,
)
from itda.contracts.crosswalk import (
    CrosswalkReviewArtifact,
    RelationshipReviewArtifact,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

CODE_PATHS = (
    "backend/src/itda/cli/evaluate_catalog_entity_policy.py",
    "backend/src/itda/contracts/catalog_entity_policy.py",
)
CONFIG_PATHS = ("backend/pyproject.toml",)
PROJECTION_PATH = (
    "artifacts/restricted/catalog/v2/projection/entity-projection.json"
)


class PolicyEvaluationError(ValueError):
    """Raised when protected evidence cannot satisfy the closed policy."""


def _disposition(
    *,
    source_row_id: str,
    source_row_sha256: str,
    rule_id: str,
    result: PolicyResult,
    rationale_codes: tuple[str, ...],
    evidence_refs: tuple[str, ...],
) -> PolicyDisposition:
    fields = {
        "source_row_id": source_row_id,
        "source_row_sha256": source_row_sha256,
        "rule_id": rule_id,
        "result": result.value,
        "rationale_codes": rationale_codes,
        "evidence_refs": evidence_refs,
    }
    return PolicyDisposition(**fields, leaf_sha256=canonical_sha256(fields))


def _attachment(
    *,
    relationship: object,
    place_candidate_id: str,
    photo_candidate_id: str,
    projection: EntityProjection,
    projection_record_by_candidate: dict[str, object],
) -> MediaAttachment:
    relationship_row_id = relationship.source_row_id  # type: ignore[attr-defined]
    relationship_row_sha256 = relationship.source_row_sha256  # type: ignore[attr-defined]
    place_record = projection_record_by_candidate[place_candidate_id]
    photo_record = projection_record_by_candidate[photo_candidate_id]
    photo_asset = next(
        (
            item
            for item in projection.photo_assets
            if item.owner_dataset_ref == photo_record.ref  # type: ignore[attr-defined]
        ),
        None,
    )
    if photo_asset is None:
        raise PolicyEvaluationError("exact media binding lacks its protected photo asset")
    fields = {
        "source_relationship_row_id": relationship_row_id,
        "source_row_sha256": relationship_row_sha256,
        "source_place_candidate_id": place_candidate_id,
        "source_photo_candidate_id": photo_candidate_id,
        "source_asset_id": photo_asset.source_asset_id,
        "place_ref": place_record.place_ref.model_dump(mode="json"),  # type: ignore[attr-defined]
        "photo_ref": photo_asset.ref.model_dump(mode="json"),
        "owner_dataset_ref": photo_asset.owner_dataset_ref.model_dump(mode="json"),
        "evidence_refs": (
            relationship_row_sha256,
            photo_asset.source_audit_sha256,
            photo_asset.source_response_sha256,
        ),
        "rights_granting": False,
        "identity_merging": False,
    }
    return MediaAttachment(**fields, leaf_sha256=canonical_sha256(fields))


def build_policy_report(
    *,
    repo_root: Path,
    entity_projection: Path,
    immutability_manifest: Path,
    collection_report: Path,
    crosswalk_review: Path,
    relationship_review: Path,
    catalog_audit: Path,
) -> EntityPolicyReport:
    """Derive every disposition from protected rows; no totals are caller inputs."""

    projection_path = project_catalog_entities._repo_relative(
        repo_root, entity_projection, PROJECTION_PATH
    )
    manifest_path = project_catalog_entities._repo_relative(
        repo_root,
        immutability_manifest,
        "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json",
    )
    expected = project_catalog_entities.PROTECTED_PARENT_PATHS
    loaded_paths = (
        project_catalog_entities._repo_relative(repo_root, collection_report, expected[0]),
        project_catalog_entities._repo_relative(repo_root, catalog_audit, expected[1]),
        project_catalog_entities._repo_relative(repo_root, crosswalk_review, expected[2]),
        project_catalog_entities._repo_relative(repo_root, relationship_review, expected[3]),
    )

    manifest = fingerprint_catalog_v1.verify_manifest(repo_root, manifest_path)
    projection_parents = project_catalog_entities._protected_parents(manifest)
    collection = project_catalog_entities._load_contract(
        loaded_paths[0], CollectionReport
    )
    audit = project_catalog_entities._load_contract(loaded_paths[1], CatalogAudit)
    crosswalk = project_catalog_entities._load_contract(
        loaded_paths[2], CrosswalkReviewArtifact
    )
    relationship = project_catalog_entities._load_contract(
        loaded_paths[3], RelationshipReviewArtifact
    )
    project_catalog_entities._validate_complete_inputs(
        collection, crosswalk, relationship, audit
    )
    projection = project_catalog_entities._load_contract(
        projection_path, EntityProjection
    )
    if projection.parents != projection_parents:
        raise PolicyEvaluationError("entity projection parent hashes drifted")

    binding_by_path = {
        item.relpath: item for item in projection_parents.protected_files
    }
    protected_inputs: list[ProtectedPolicyInput] = []
    for path, relpath in zip(loaded_paths, expected, strict=True):
        binding = binding_by_path[relpath]
        if project_catalog_entities._file_sha256(path) != binding.file_sha256:
            raise PolicyEvaluationError("protected v1 input content drifted")
        protected_inputs.append(
            ProtectedPolicyInput(
                relpath=relpath,
                file_sha256=binding.file_sha256,
                manifest_entry_sha256=binding.manifest_entry_sha256,
            )
        )
    protected_inputs.sort(key=lambda item: item.relpath.encode("utf-8"))

    projection_record_by_candidate = {
        item.source_candidate_id: item for item in projection.dataset_records
    }
    candidate_by_id = {item.candidate_id: item for item in collection.candidates}
    if set(projection_record_by_candidate) != set(candidate_by_id):
        raise PolicyEvaluationError("projection candidate inventory drifted")

    crosswalk_dispositions: list[PolicyDisposition] = []
    for ordinal, proposal in enumerate(crosswalk.proposals):
        projected = projection.place_entities[ordinal]
        source_row_sha256 = project_catalog_entities._source_row_sha256(proposal)
        if (
            projected.source_row_id != f"crosswalk:{proposal.proposal_id}"
            or projected.source_row_sha256 != source_row_sha256
        ):
            raise PolicyEvaluationError("crosswalk projection row drifted")
        providers = tuple(item.provider for item in proposal.evidence)
        tour_api_count = providers.count("TOUR_API")
        photo_count = providers.count("TOURISM_PHOTO")
        if tour_api_count > 1:
            rule_id = "CROSSWALK_MULTIPLE_PLACE_RECORDS_UNRESOLVED"
            result = PolicyResult.UNRESOLVED_HUMAN
            rationale = ("MULTIPLE_EXACT_PLACE_RECORDS_REQUIRE_HUMAN_IDENTITY",)
        elif tour_api_count == 1 and photo_count:
            rule_id = "CROSSWALK_EXACT_MEDIA_RETYPE"
            result = PolicyResult.AUTOMATIC_MEDIA_RETYPE_NO_PLACE_MERGE
            rationale = (
                "PHOTO_DATASET_RECORDS_ARE_MEDIA_NOT_PLACE_IDENTITIES",
                "CROSS_PROVIDER_PLACE_AUTO_LINK_FORBIDDEN",
            )
        elif tour_api_count == 1:
            rule_id = "CROSSWALK_SINGLE_PLACE_RECORD_AUTOMATIC"
            result = PolicyResult.AUTOMATIC_SINGLE_PROVIDER_RECORD
            rationale = ("ONE_EXACT_PROVIDER_SCOPED_PLACE_RECORD",)
        else:
            rule_id = "CROSSWALK_NON_PLACE_REJECT"
            result = PolicyResult.AUTOMATIC_REJECT_NON_PLACE_SOURCE_KIND
            rationale = ("NO_PLACE_PROVIDER_RECORD_IN_PROPOSAL",)
        crosswalk_dispositions.append(
            _disposition(
                source_row_id=projected.source_row_id,
                source_row_sha256=source_row_sha256,
                rule_id=rule_id,
                result=result,
                rationale_codes=rationale,
                evidence_refs=tuple(
                    item.evidence_sha256 for item in proposal.evidence
                ),
            )
        )

    exact_bindings = {
        frozenset(binding): binding for binding in EXACT_MEDIA_RECORD_BINDINGS
    }
    relationship_dispositions: list[PolicyDisposition] = []
    media_attachments: list[MediaAttachment] = []
    for ordinal, proposal in enumerate(relationship.proposals):
        projected = projection.relationships[ordinal]
        source_row_sha256 = project_catalog_entities._source_row_sha256(proposal)
        if (
            projected.source_row_id != f"relationship:{proposal.proposal_id}"
            or projected.source_row_sha256 != source_row_sha256
        ):
            raise PolicyEvaluationError("relationship projection row drifted")
        endpoints = (proposal.left_subject_ref, proposal.right_subject_ref)
        providers = tuple(candidate_by_id[item].provider for item in endpoints)
        binding = exact_bindings.get(frozenset(endpoints))
        if providers == ("TOUR_API", "TOUR_API"):
            rule_id = "RELATIONSHIP_PLACE_PAIR_UNRESOLVED"
            result = PolicyResult.UNRESOLVED_HUMAN
            rationale = ("TITLE_ONLY_PLACE_PAIR_REQUIRES_HUMAN_SEMANTIC_REVIEW",)
        elif binding is not None:
            rule_id = "RELATIONSHIP_EXACT_MEDIA_RECORD_ATTACHMENT"
            result = PolicyResult.AUTOMATIC_MEDIA_ATTACHMENT
            rationale = (
                "EXACT_POLICY_BOUND_ASSET_RECORD_EVIDENCE",
                "NON_RIGHTS_GRANTING_NON_IDENTITY_RELATION",
            )
            media_attachments.append(
                _attachment(
                    relationship=projected,
                    place_candidate_id=binding[0],
                    photo_candidate_id=binding[1],
                    projection=projection,
                    projection_record_by_candidate=projection_record_by_candidate,
                )
            )
        else:
            rule_id = "RELATIONSHIP_SOURCE_KIND_REJECT"
            result = PolicyResult.AUTOMATIC_REJECT_SOURCE_KIND_INCOMPATIBLE
            rationale = (
                "PHOTO_RECORD_CANNOT_BE_DUPLICATE_PLACE_IDENTITY",
                "TITLE_OR_PROXIMITY_DOES_NOT_AUTHORIZE_ATTACHMENT",
            )
        relationship_dispositions.append(
            _disposition(
                source_row_id=projected.source_row_id,
                source_row_sha256=source_row_sha256,
                rule_id=rule_id,
                result=result,
                rationale_codes=rationale,
                evidence_refs=projected.evidence_refs,
            )
        )

    counts = PolicyCounts(
        crosswalk_total=len(crosswalk_dispositions),
        crosswalk_automatic=sum(
            item.result is not PolicyResult.UNRESOLVED_HUMAN
            for item in crosswalk_dispositions
        ),
        crosswalk_unresolved=sum(
            item.result is PolicyResult.UNRESOLVED_HUMAN
            for item in crosswalk_dispositions
        ),
        relationship_total=len(relationship_dispositions),
        relationship_automatic=sum(
            item.result is not PolicyResult.UNRESOLVED_HUMAN
            for item in relationship_dispositions
        ),
        relationship_unresolved=sum(
            item.result is PolicyResult.UNRESOLVED_HUMAN
            for item in relationship_dispositions
        ),
        media_attachment_count=len(media_attachments),
        cross_provider_place_auto_link_count=0,
    )
    roots = {
        "crosswalk_dispositions": canonical_sha256(
            [item.model_dump(mode="json") for item in crosswalk_dispositions]
        ),
        "relationship_dispositions": canonical_sha256(
            [item.model_dump(mode="json") for item in relationship_dispositions]
        ),
        "media_attachments": canonical_sha256(
            [item.model_dump(mode="json") for item in media_attachments]
        ),
    }
    parents = PolicyParents(
        immutability_manifest_sha256=projection_parents.immutability_manifest_sha256,
        catalog_v1_tree_sha256=projection_parents.catalog_v1_tree_sha256,
        protected_inputs=tuple(protected_inputs),
        protected_inputs_sha256=canonical_sha256(
            [item.model_dump(mode="json") for item in protected_inputs]
        ),
        entity_projection_file_sha256=project_catalog_entities._file_sha256(
            projection_path
        ),
        entity_projection_sha256=projection.projection_sha256,
    )
    fields: dict[str, object] = {
        "schema_version": "catalog-entity-policy-report-v1",
        "data_version": "catalog-v2-entity-policy-data-v1",
        "policy_version": POLICY_VERSION,
        "formal_policy_sha256": formal_policy_sha256(),
        "automatic_decisions_authoritative": False,
        "parents": parents.model_dump(mode="json"),
        "schema_sha256": policy_schema_sha256(),
        "code_hashes": {
            path: project_catalog_entities._file_sha256(repo_root / path)
            for path in CODE_PATHS
        },
        "config_hashes": {
            path: project_catalog_entities._file_sha256(repo_root / path)
            for path in CONFIG_PATHS
        },
        "crosswalk_dispositions": [
            item.model_dump(mode="json") for item in crosswalk_dispositions
        ],
        "relationship_dispositions": [
            item.model_dump(mode="json") for item in relationship_dispositions
        ],
        "media_attachments": [
            item.model_dump(mode="json") for item in media_attachments
        ],
        "counts": counts.model_dump(mode="json"),
        "roots": roots,
    }
    report = EntityPolicyReport.model_validate(
        {**fields, "report_sha256": canonical_sha256(fields)}
    )
    if (
        fingerprint_catalog_v1.scan_catalog_tree(repo_root)["tree_sha256"]
        != projection_parents.catalog_v1_tree_sha256
    ):
        raise PolicyEvaluationError("protected v1 changed while evaluating policy")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", type=Path, metavar="REPORT")
    modes.add_argument("--check", type=Path, metavar="REPORT")
    parser.add_argument("--entity-projection", type=Path, required=True)
    parser.add_argument("--immutability-manifest", type=Path, required=True)
    parser.add_argument("--collection-report", type=Path, required=True)
    parser.add_argument("--crosswalk-review", type=Path, required=True)
    parser.add_argument("--relationship-review", type=Path, required=True)
    parser.add_argument("--catalog-audit", type=Path, required=True)
    return parser


def _from_args(repo_root: Path, args: argparse.Namespace) -> EntityPolicyReport:
    return build_policy_report(
        repo_root=repo_root,
        entity_projection=args.entity_projection,
        immutability_manifest=args.immutability_manifest,
        collection_report=args.collection_report,
        crosswalk_review=args.crosswalk_review,
        relationship_review=args.relationship_review,
        catalog_audit=args.catalog_audit,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = fingerprint_catalog_v1._repo_root()
    target_value = args.build if args.build is not None else args.check
    assert target_value is not None
    target = fingerprint_catalog_v1._cli_path(repo_root, target_value)
    first = _from_args(repo_root, args)
    first_bytes = canonical_json_bytes(first.model_dump(mode="json"))
    if args.build is not None:
        second = _from_args(repo_root, args)
        second_bytes = canonical_json_bytes(second.model_dump(mode="json"))
        if first_bytes != second_bytes:
            raise PolicyEvaluationError("independent policy builds were not identical")
        fingerprint_catalog_v1._write_no_replace(target, first_bytes)
    else:
        recorded = project_catalog_entities._load_contract(target, EntityPolicyReport)
        if canonical_json_bytes(recorded.model_dump(mode="json")) != first_bytes:
            raise PolicyEvaluationError("recorded report differs from policy replay")
    print(first.report_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
