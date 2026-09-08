"""Build deterministic canonical-catalog gate and review artifacts."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from itda.contracts.catalog_audit import CatalogAudit, ProjectionManifest
from itda.contracts.catalog_release import (
    CatalogGateReport,
    CatalogReviewRequest,
    CatalogReviewRequestRow,
    build_catalog_review_request,
    evaluate_catalog_gate_report,
)
from itda.contracts.crosswalk import (
    CrosswalkReviewArtifact,
    RelationshipReviewArtifact,
)
from itda.domain.canonical import canonical_json_bytes


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_json_object(path: Path) -> tuple[bytes, dict[str, object]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"catalog input must be a regular non-symlink file: {path}")
    payload = path.read_bytes()
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"catalog input must be valid UTF-8 JSON: {path}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"catalog input JSON root must be an object: {path}")
    return payload, parsed


def build_catalog_gate_report_from_review_artifacts(
    *,
    catalog_audit_path: Path,
    projection_manifest_path: Path,
    crosswalk_review_path: Path,
    relationship_review_path: Path,
) -> CatalogGateReport:
    """Re-derive current gate truth from exact Plan 02-07 canonical parents."""

    audit_bytes, audit_payload = _read_json_object(catalog_audit_path)
    projection_bytes, projection_payload = _read_json_object(projection_manifest_path)
    crosswalk_bytes, crosswalk_payload = _read_json_object(crosswalk_review_path)
    relationship_bytes, relationship_payload = _read_json_object(relationship_review_path)
    audit = CatalogAudit.model_validate(audit_payload)
    projection = ProjectionManifest.model_validate(projection_payload)
    crosswalk = CrosswalkReviewArtifact.model_validate(crosswalk_payload)
    relationship = RelationshipReviewArtifact.model_validate(relationship_payload)

    audit_file_sha256 = _sha256(audit_bytes)
    if audit_file_sha256 != projection.canonical_json_sha256:
        raise ValueError("projection canonical JSON hash does not match catalog audit bytes")
    if projection.output_hashes.get("catalog-audit.json") != audit_file_sha256:
        raise ValueError("projection output hash does not match canonical catalog audit")
    if audit.source_hashes.get("crosswalk_review_canonical") != crosswalk.artifact_sha256:
        raise ValueError("catalog audit crosswalk parent hash mismatch")
    if audit.source_hashes.get("relationship_review_canonical") != relationship.artifact_sha256:
        raise ValueError("catalog audit relationship parent hash mismatch")
    if relationship.source_crosswalk_artifact_sha256 != crosswalk.artifact_sha256:
        raise ValueError("relationship review crosswalk parent hash mismatch")
    if canonical_json_bytes(audit.model_dump(mode="json")) != audit_bytes:
        raise ValueError("catalog audit bytes are not canonical JSON")
    if canonical_json_bytes(projection.model_dump(mode="json")) != projection_bytes:
        raise ValueError("projection manifest bytes are not canonical JSON")

    unresolved_crosswalk = tuple(
        f"crosswalk:{item.proposal_id}"
        for item in crosswalk.proposals
        if item.status == "REVIEW_REQUIRED"
    )
    unresolved_relationship = tuple(
        f"relationship:{item.proposal_id}"
        for item in relationship.proposals
        if item.status == "PENDING_REVIEW"
    )
    eligible_rows = tuple(row for row in audit.rows if row.canonical_selection_eligible)
    candidate_to_place = {
        evidence.candidate_id: proposal.canonical_place_id
        for proposal in crosswalk.proposals
        for evidence in proposal.evidence
        if evidence.candidate_id is not None
    }
    ordered_catalog_ids = (
        tuple(
            sorted(
                candidate_to_place[row.candidate_id]
                for row in eligible_rows
                if row.candidate_id in candidate_to_place
            )
        )
        if len(eligible_rows) == 36
        else ()
    )
    candidates = tuple(
        {
            "candidate_id": row.candidate_id,
            "canonical_place_id": candidate_to_place.get(row.candidate_id),
            "name_ko": row.name_ko,
            "selection_eligible": row.canonical_selection_eligible,
            "coordinates_gate": row.coordinate_status == "PRESENT",
            "description_gate": row.description_status == "PRESENT",
            "operational_gate": row.operational_status == "PRESENT",
            "rights_gate": (
                row.rights_disposition is not None and row.rights_disposition.analysis_eligible
            ),
            "nonduplicate_gate": (
                row.candidate_id in candidate_to_place and not row.relationship_reason_codes
            ),
            "media_gate": row.photo_status == "PRESENT",
        }
        for row in audit.rows
    )
    seed_dispositions = {item.seed_id: item.status for item in audit.seed_rows}
    rights_disposition_counts = Counter(
        (
            row.rights_disposition.rights_state.value
            if row.rights_disposition is not None
            else "NO_RIGHTS_DISPOSITION"
        )
        for row in audit.rows
    )
    seed_disposition_counts = Counter(item.status for item in audit.seed_rows)
    if audit.audit_sha256 is None or projection.projection_manifest_sha256 is None:
        raise ValueError("catalog audit and projection manifest require canonical hashes")
    parent_hashes = {
        "catalog_audit_canonical_sha256": audit.audit_sha256,
        "catalog_audit_file_sha256": audit_file_sha256,
        "collection_report_sha256": audit.source_hashes["collection_report_canonical"],
        "crosswalk_review_canonical_sha256": crosswalk.artifact_sha256,
        "crosswalk_review_file_sha256": _sha256(crosswalk_bytes),
        "permission_evidence_set_sha256": audit.source_hashes["permission_evidence_set"],
        "projection_manifest_canonical_sha256": projection.projection_manifest_sha256,
        "projection_manifest_file_sha256": _sha256(projection_bytes),
        "relationship_review_canonical_sha256": relationship.artifact_sha256,
        "relationship_review_file_sha256": _sha256(relationship_bytes),
    }
    return evaluate_catalog_gate_report(
        candidates=candidates,
        ordered_catalog_ids=ordered_catalog_ids,
        proposal_seed_dispositions=seed_dispositions,
        parent_hashes=parent_hashes,
        projection_hashes={str(name): digest for name, digest in projection.output_hashes.items()},
        unresolved_review_rows=(*unresolved_crosswalk, *unresolved_relationship),
        crosswalk_review_required_count=len(unresolved_crosswalk),
        relationship_review_required_count=len(unresolved_relationship),
        rights_disposition_counts={
            str(status): count for status, count in rights_disposition_counts.items()
        },
        seed_disposition_counts={
            str(status): count for status, count in seed_disposition_counts.items()
        },
        source_version=audit.source_version,
    )


def materialize_gate_report(report: CatalogGateReport, output: Path) -> None:
    """Create canonical report bytes exactly once."""

    payload = canonical_json_bytes(report.model_dump(mode="json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = output.open("xb")
    try:
        descriptor.write(payload)
        descriptor.flush()
    finally:
        descriptor.close()


def _version_hashes(
    repository_root: Path,
    relative_paths: tuple[str, ...],
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in relative_paths:
        path = repository_root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"version-bound input must be a regular file: {relative}")
        hashes[relative] = _sha256(path.read_bytes())
    return hashes


def build_catalog_review_request_from_review_artifacts(
    *,
    gate_report: CatalogGateReport,
    gate_report_path: Path,
    crosswalk_review_path: Path,
    relationship_review_path: Path,
    repository_root: Path,
) -> CatalogReviewRequest:
    """Build the immutable pre-adjudication parent without choosing membership."""

    gate_bytes, gate_payload = _read_json_object(gate_report_path)
    if CatalogGateReport.model_validate(gate_payload) != gate_report:
        raise ValueError("gate report file does not match re-derived current gate truth")
    if gate_bytes != canonical_json_bytes(gate_report.model_dump(mode="json")):
        raise ValueError("gate report file is not canonical JSON")
    _, crosswalk_payload = _read_json_object(crosswalk_review_path)
    _, relationship_payload = _read_json_object(relationship_review_path)
    crosswalk = CrosswalkReviewArtifact.model_validate(crosswalk_payload)
    relationship = RelationshipReviewArtifact.model_validate(relationship_payload)

    rows: list[CatalogReviewRequestRow] = []
    for crosswalk_proposal in crosswalk.proposals:
        if crosswalk_proposal.status != "REVIEW_REQUIRED":
            continue
        evidence_refs = {
            crosswalk_proposal.evidence_sha256,
            *(evidence.evidence_sha256 for evidence in crosswalk_proposal.evidence),
            *(
                digest
                for evidence in crosswalk_proposal.evidence
                for digest in (
                    evidence.raw_response_sha256,
                    evidence.permission_snapshot_sha256,
                )
                if digest is not None
            ),
        }
        rows.append(
            CatalogReviewRequestRow(
                row_id=f"crosswalk:{crosswalk_proposal.proposal_id}",
                row_kind="CROSSWALK",
                source_proposal_id=crosswalk_proposal.proposal_id,
                source_revision_sha256=crosswalk.artifact_sha256,
                evidence_refs=tuple(sorted(evidence_refs)),
                parent_hashes={
                    "collection_report_sha256": (crosswalk.source_lineage.collection_report_sha256),
                    "crosswalk_review_sha256": crosswalk.artifact_sha256,
                },
            )
        )
    for relationship_proposal in relationship.proposals:
        if relationship_proposal.status != "PENDING_REVIEW":
            continue
        rows.append(
            CatalogReviewRequestRow(
                row_id=f"relationship:{relationship_proposal.proposal_id}",
                row_kind="RELATIONSHIP",
                source_proposal_id=relationship_proposal.proposal_id,
                source_revision_sha256=relationship.artifact_sha256,
                evidence_refs=tuple(
                    sorted(
                        {
                            relationship_proposal.evidence_sha256,
                            relationship_proposal.source_crosswalk_proposal_sha256,
                            relationship_proposal.collection_report_sha256,
                        }
                    )
                ),
                parent_hashes={
                    "collection_report_sha256": (
                        relationship.source_lineage.collection_report_sha256
                    ),
                    "crosswalk_review_sha256": (relationship.source_crosswalk_artifact_sha256),
                    "relationship_review_sha256": relationship.artifact_sha256,
                },
            )
        )
    code_hashes = _version_hashes(
        repository_root,
        (
            "backend/src/itda/contracts/catalog_audit.py",
            "backend/src/itda/contracts/catalog_release.py",
            "backend/src/itda/contracts/crosswalk.py",
            "backend/src/itda/pipeline/export_catalog_audit.py",
            "backend/src/itda/pipeline/publish_catalog.py",
        ),
    )
    config_hashes = _version_hashes(
        repository_root,
        (
            ".python-version",
            "backend/pyproject.toml",
            "backend/uv.lock",
            "mise.toml",
        ),
    )
    return build_catalog_review_request(
        gate_report=gate_report,
        required_rows=rows,
        code_version_hashes=code_hashes,
        config_version_hashes=config_hashes,
        gate_report_file_sha256=_sha256(gate_bytes),
    )


def materialize_review_request(
    request: CatalogReviewRequest,
    output: Path,
) -> None:
    """Create canonical pre-adjudication parent bytes exactly once."""

    payload = canonical_json_bytes(request.model_dump(mode="json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = output.open("xb")
    try:
        descriptor.write(payload)
        descriptor.flush()
    finally:
        descriptor.close()


__all__ = [
    "build_catalog_gate_report_from_review_artifacts",
    "build_catalog_review_request_from_review_artifacts",
    "materialize_gate_report",
    "materialize_review_request",
]
