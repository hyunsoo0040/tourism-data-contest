"""Build and verify the immutable v2 rights/objective-evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from collections import defaultdict
from pathlib import Path

from itda.cli import (
    fingerprint_catalog_v1,
    project_catalog_entities,
)
from itda.contracts.catalog_audit import CatalogAudit, RightsState
from itda.contracts.catalog_entity import EntityProjection
from itda.contracts.catalog_entity_policy import (
    EntityPolicyReport,
    formal_policy_sha256,
)
from itda.contracts.catalog_rights_v2 import (
    AttachmentRightsRow,
    CandidateObjectiveEvidence,
    CandidateObjectiveRow,
    DatasetGrantRightsRow,
    GateState,
    ObjectiveEvidenceParents,
    ObjectiveGate,
    RightsProjection,
    RightsProjectionParents,
    project_asset_rights,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

IMMUTABILITY_PATH = (
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json"
)
ENTITY_PROJECTION_PATH = (
    "artifacts/restricted/catalog/v2/projection/entity-projection.json"
)
ENTITY_POLICY_PATH = (
    "artifacts/restricted/catalog/v2/projection/entity-policy-report.json"
)
CATALOG_AUDIT_PATH = "artifacts/restricted/catalog/v1/review/catalog-audit.json"
RIGHTS_TARGET = "artifacts/restricted/catalog/v2/rights/rights-projection.json"
OBJECTIVE_TARGET = (
    "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
)
LINEAGE_SUCCESSOR_PATH = (
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest-v2.json"
)
CURRENT_ATTESTATION_TARGET = (
    "artifacts/restricted/catalog/v2/rights/"
    "rights-current-parent-attestation-v1.json"
)
PROTECTED_BEFORE_PATH = (
    "artifacts/restricted/catalog/v2/release/gap-closure-guards/"
    "02-60-protected-before.json"
)
CURRENT_ATTESTATION_KEYS = tuple(
    sorted(
        (
            "schema_version",
            "semantic_disposition",
            "lineage",
            "original_rights",
            "original_objective_evidence",
            "rights_semantics",
            "objective_semantics",
            "current_replay",
            "protected_before",
            "policy_assertions",
            "attestation_sha256",
        ),
        key=str.encode,
    )
)
CODE_PATHS = (
    "backend/src/itda/contracts/catalog_rights_v2.py",
    "backend/src/itda/cli/project_catalog_rights_v2.py",
)
CONFIG_PATHS = ("backend/pyproject.toml",)


class RightsProjectionError(ValueError):
    """Raised when protected evidence cannot reproduce the v2 rights bundle."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular_sha256(path: Path) -> str:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise RightsProjectionError("rights evidence is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | fingerprint_catalog_v1.O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        fingerprint_catalog_v1._same_object(before, after)
        payload = fingerprint_catalog_v1._read_descriptor(descriptor)
        fingerprint_catalog_v1._same_state(after, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    return _sha256_bytes(payload)


def _grant_row(grant: object) -> DatasetGrantRightsRow:
    grant_fields = grant.model_dump(mode="json")  # type: ignore[attr-defined]
    allowed = grant_fields["evidence_state"] == "COMPLETE" and all(
        grant_fields[field]
        for field in (
            "commercial_use_allowed",
            "transform_allowed",
            "display_allowed",
            "model_input_allowed",
        )
    )
    fields = {
        **grant_fields,
        "allowed": allowed,
        "reason_codes": (
            ("AUTHORITATIVE_DATASET_GRANT_COMPLETE",)
            if allowed
            else ("DATASET_GRANT_INCOMPLETE_OR_RESTRICTED",)
        ),
        "evidence_refs": tuple(
            sorted(
                {
                    grant_fields["response_sha256"],
                    grant_fields["page_sha256"],
                    grant_fields["dataset_grant_sha256"],
                }
            )
        ),
    }
    return DatasetGrantRightsRow(**fields, leaf_sha256=canonical_sha256(fields))


def _objective_gate(
    *,
    state: GateState,
    current_values: tuple[str, ...],
    reason_codes: tuple[str, ...],
    evidence_refs: tuple[str, ...],
) -> ObjectiveGate:
    return ObjectiveGate(
        state=state,
        current_values=tuple(sorted(set(current_values))),
        reason_codes=tuple(sorted(set(reason_codes))),
        evidence_refs=tuple(sorted(set(evidence_refs))),
    )


def _phase1_rights_files(repo_root: Path, audit: CatalogAudit) -> dict[str, str]:
    if len(audit.phase1_historical_hashes) != 6:
        raise RightsProjectionError("Phase 1 rights history must contain six exact files")
    verified: dict[str, str] = {}
    for relpath, expected in sorted(audit.phase1_historical_hashes.items()):
        path = repo_root / relpath
        actual = _read_regular_sha256(path)
        if actual != expected:
            raise RightsProjectionError(f"Phase 1 rights bytes drifted: {relpath}")
        verified[relpath] = actual
    return verified


def _build_rights(
    *,
    repo_root: Path,
    projection: EntityProjection,
    policy: EntityPolicyReport,
    audit: CatalogAudit,
    policy_file_sha256: str,
) -> RightsProjection:
    dataset_grants = tuple(_grant_row(grant) for grant in audit.grants)
    grant_by_id = {row.official_dataset_id: grant for row, grant in zip(
        dataset_grants, audit.grants, strict=True
    )}
    dataset_record_by_candidate = {
        row.source_candidate_id: row for row in projection.dataset_records
    }
    asset_rights = []
    for audit_row in audit.rows:
        asset = audit_row.asset
        recorded = audit_row.rights_disposition
        if asset is None or recorded is None:
            raise RightsProjectionError("protected audit row lacks asset rights evidence")
        dataset_record = dataset_record_by_candidate.get(audit_row.candidate_id)
        if dataset_record is None:
            raise RightsProjectionError("audit asset lacks projected dataset identity")
        decision = project_asset_rights(
            asset,
            grant_by_id[asset.official_dataset_id],
            source_candidate_id=audit_row.candidate_id,
            dataset_record_entity_id=dataset_record.ref.entity_id,
            source_audit_sha256=dataset_record.source_audit_sha256,
        )
        comparable = (
            decision.rights_state,
            decision.reason_codes,
            decision.commercial_use_allowed,
            decision.transform_allowed,
            decision.display_allowed,
            decision.model_input_allowed,
            decision.analysis_eligible,
            decision.ui_eligible,
            decision.demo_eligible,
        )
        recorded_comparable = (
            recorded.rights_state,
            recorded.reason_codes,
            recorded.commercial_use_allowed,
            recorded.transform_allowed,
            recorded.display_allowed,
            recorded.model_input_allowed,
            recorded.analysis_eligible,
            recorded.ui_eligible,
            recorded.demo_eligible,
        )
        if comparable != recorded_comparable:
            raise RightsProjectionError("v2 rights replay differs from protected v1 evidence")
        asset_rights.append(decision)
    asset_rights.sort(key=lambda row: row.source_candidate_id or "")
    asset_by_candidate = {
        row.source_candidate_id: row for row in asset_rights
    }

    attachment_rights = []
    for attachment in policy.media_attachments:
        asset_rights_row = asset_by_candidate.get(
            attachment.source_photo_candidate_id
        )
        if (
            asset_rights_row is None
            or asset_rights_row.source_asset_id != attachment.source_asset_id
            or asset_rights_row.dataset_record_entity_id
            != attachment.owner_dataset_ref.entity_id
        ):
            raise RightsProjectionError(
                "typed attachment lacks exact independently projected asset rights"
            )
        fields = {
            "source_relationship_row_id": attachment.source_relationship_row_id,
            "source_attachment_leaf_sha256": attachment.leaf_sha256,
            "source_place_candidate_id": attachment.source_place_candidate_id,
            "source_photo_candidate_id": attachment.source_photo_candidate_id,
            "source_asset_id": attachment.source_asset_id,
            "place_entity_id": attachment.place_ref.entity_id,
            "photo_entity_id": attachment.photo_ref.entity_id,
            "owner_dataset_entity_id": attachment.owner_dataset_ref.entity_id,
            "attachment_rights_granting": False,
            "identity_merging": False,
            "asset_rights_leaf_sha256": asset_rights_row.leaf_sha256,
            "rights_state": asset_rights_row.rights_state.value,
            "reason_codes": (
                ("EXACT_ASSET_RIGHTS_INDEPENDENTLY_ALLOWED",)
                if asset_rights_row.rights_state is RightsState.ALLOWED
                else (
                    "ATTACHED_ASSET_RIGHTS_BLOCKED",
                    *asset_rights_row.reason_codes,
                )
            ),
            "evidence_refs": tuple(
                sorted(
                    {
                        attachment.leaf_sha256,
                        asset_rights_row.leaf_sha256,
                        *attachment.evidence_refs,
                        *asset_rights_row.evidence_refs,
                    }
                )
            ),
        }
        attachment_rights.append(
            AttachmentRightsRow(**fields, leaf_sha256=canonical_sha256(fields))
        )
    attachment_rights.sort(key=lambda row: row.source_relationship_row_id)

    phase1_files = _phase1_rights_files(repo_root, audit)
    complete_dispositions_root = canonical_sha256(
        {
            "crosswalk_dispositions": policy.roots["crosswalk_dispositions"],
            "relationship_dispositions": policy.roots[
                "relationship_dispositions"
            ],
        }
    )
    parents = RightsProjectionParents(
        entity_policy_file_sha256=policy_file_sha256,
        entity_policy_report_sha256=policy.report_sha256,
        formal_policy_sha256=policy.formal_policy_sha256,
        immutability_manifest_sha256=policy.parents.immutability_manifest_sha256,
        catalog_v1_tree_sha256=policy.parents.catalog_v1_tree_sha256,
        protected_inputs_sha256=policy.parents.protected_inputs_sha256,
        entity_projection_file_sha256=policy.parents.entity_projection_file_sha256,
        entity_projection_sha256=policy.parents.entity_projection_sha256,
        crosswalk_dispositions_root=policy.roots["crosswalk_dispositions"],
        relationship_dispositions_root=policy.roots[
            "relationship_dispositions"
        ],
        complete_dispositions_root=complete_dispositions_root,
        media_attachments_root=policy.roots["media_attachments"],
        phase1_rights_tree_sha256=canonical_sha256(phase1_files),
        cross_provider_place_auto_link_count=policy.counts.cross_provider_place_auto_link_count,
    )
    roots = {
        "dataset_grants": canonical_sha256(
            [row.model_dump(mode="json") for row in dataset_grants]
        ),
        "asset_rights": canonical_sha256(
            [row.model_dump(mode="json") for row in asset_rights]
        ),
        "attachment_rights": canonical_sha256(
            [row.model_dump(mode="json") for row in attachment_rights]
        ),
        "phase1_rights_files": canonical_sha256(phase1_files),
    }
    counts = {
        "dataset_grant_count": len(dataset_grants),
        "asset_rights_count": len(asset_rights),
        "attachment_rights_count": len(attachment_rights),
        "allowed_asset_count": sum(
            row.rights_state is RightsState.ALLOWED for row in asset_rights
        ),
        "blocked_asset_count": sum(
            row.rights_state is not RightsState.ALLOWED for row in asset_rights
        ),
    }
    fields = {
        "schema_version": "catalog-rights-projection-v2",
        "data_version": "catalog-v2-rights-data-v1",
        "parents": parents.model_dump(mode="json"),
        "code_hashes": {
            path: project_catalog_entities._file_sha256(repo_root / path)
            for path in CODE_PATHS
        },
        "config_hashes": {
            path: project_catalog_entities._file_sha256(repo_root / path)
            for path in CONFIG_PATHS
        },
        "phase1_rights_files": phase1_files,
        "dataset_grants": [
            row.model_dump(mode="json") for row in dataset_grants
        ],
        "asset_rights": [
            row.model_dump(mode="json") for row in asset_rights
        ],
        "attachment_rights": [
            row.model_dump(mode="json") for row in attachment_rights
        ],
        "counts": counts,
        "roots": roots,
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
    }
    return RightsProjection.model_validate(
        {**fields, "projection_sha256": canonical_sha256(fields)}
    )


def _build_objective(
    *,
    projection: EntityProjection,
    policy: EntityPolicyReport,
    audit: CatalogAudit,
    rights: RightsProjection,
) -> CandidateObjectiveEvidence:
    audit_by_candidate = {row.candidate_id: row for row in audit.rows}
    dataset_by_entity = {
        row.ref.entity_id: row for row in projection.dataset_records
    }
    grant_by_id = {
        row.official_dataset_id: row for row in rights.dataset_grants
    }
    attachments_by_place: dict[str, list[AttachmentRightsRow]] = defaultdict(list)
    for row in rights.attachment_rights:
        attachments_by_place[row.place_entity_id].append(row)

    rows = []
    for place in sorted(
        projection.place_entities, key=lambda row: row.ref.entity_id
    ):
        records = [dataset_by_entity[member.entity_id] for member in place.member_refs]
        source_rows = [audit_by_candidate[row.source_candidate_id] for row in records]
        audit_refs = tuple(row.source_audit_sha256 for row in records)

        coordinate_values = tuple(
            canonical_json_bytes(
                {
                    "source_candidate_id": record.source_candidate_id,
                    "latitude": source.latitude,
                    "longitude": source.longitude,
                }
            ).decode("utf-8")
            for record, source in zip(records, source_rows, strict=True)
            if source.latitude is not None and source.longitude is not None
        )
        coordinates = _objective_gate(
            state=GateState.PASS if coordinate_values else GateState.MISSING,
            current_values=coordinate_values,
            reason_codes=(
                ("COORDINATES_PRESENT",)
                if coordinate_values
                else tuple(
                    sorted(
                        {
                            "COORDINATES_MISSING",
                            *(
                                source.coordinate_missing_reason
                                or "COORDINATES_MISSING_WITHOUT_REASON"
                                for source in source_rows
                            ),
                        }
                    )
                )
            ),
            evidence_refs=audit_refs,
        )

        description_values = tuple(
            f"{record.source_candidate_id}:PRESENT"
            for record, source in zip(records, source_rows, strict=True)
            if source.description_status == "PRESENT"
        )
        description = _objective_gate(
            state=GateState.PASS if description_values else GateState.MISSING,
            current_values=description_values,
            reason_codes=(
                ("DESCRIPTION_PRESENT",)
                if description_values
                else tuple(
                    sorted(
                        {
                            "DESCRIPTION_MISSING",
                            *(
                                source.description_missing_reason
                                or "DESCRIPTION_MISSING_WITHOUT_REASON"
                                for source in source_rows
                            ),
                        }
                    )
                )
            ),
            evidence_refs=audit_refs,
        )

        operating_values = tuple(
            f"{record.source_candidate_id}:PRESENT"
            for record, source in zip(records, source_rows, strict=True)
            if source.operational_status == "PRESENT"
        )
        operating_info = _objective_gate(
            state=GateState.PASS if operating_values else GateState.MISSING,
            current_values=operating_values,
            reason_codes=(
                ("OPERATING_INFO_PRESENT",)
                if operating_values
                else tuple(
                    sorted(
                        {
                            "OPERATING_INFO_MISSING",
                            *(
                                source.operational_missing_reason
                                or "OPERATING_INFO_MISSING_WITHOUT_REASON"
                                for source in source_rows
                            ),
                        }
                    )
                )
            ),
            evidence_refs=audit_refs,
        )

        candidate_grants = tuple(
            grant_by_id[source.official_dataset_id]
            for source in source_rows
            if source.official_dataset_id is not None
        )
        grants_allowed = bool(candidate_grants) and all(
            grant.allowed for grant in candidate_grants
        )
        dataset_rights = _objective_gate(
            state=GateState.PASS if grants_allowed else GateState.BLOCKED,
            current_values=tuple(
                f"{grant.official_dataset_id}:{'ALLOWED' if grant.allowed else 'BLOCKED'}"
                for grant in candidate_grants
            ),
            reason_codes=(
                ("EXACT_DATASET_GRANTS_ALLOWED",)
                if grants_allowed
                else ("DATASET_RIGHTS_BLOCKED_OR_MISSING",)
            ),
            evidence_refs=tuple(grant.leaf_sha256 for grant in candidate_grants)
            or audit_refs,
        )

        direct = tuple(
            sorted(
                attachments_by_place.get(place.ref.entity_id, []),
                key=lambda row: row.source_relationship_row_id,
            )
        )
        allowed_direct = tuple(
            row for row in direct if row.rights_state is RightsState.ALLOWED
        )
        direct_state = (
            GateState.PASS
            if allowed_direct
            else GateState.BLOCKED
            if direct
            else GateState.MISSING
        )
        direct_media = _objective_gate(
            state=direct_state,
            current_values=tuple(
                f"{row.source_photo_candidate_id}:{row.rights_state.value}"
                for row in direct
            ),
            reason_codes=(
                ("DIRECT_MEDIA_EXACT_ASSET_RIGHTS_ALLOWED",)
                if allowed_direct
                else ("DIRECT_MEDIA_ATTACHED_BUT_RIGHTS_BLOCKED",)
                if direct
                else ("NO_DIRECT_MEDIA_ATTACHMENT",)
            ),
            evidence_refs=tuple(row.leaf_sha256 for row in direct)
            or (place.source_row_sha256, rights.parents.media_attachments_root),
        )

        fields = {
            "place_entity_id": place.ref.entity_id,
            "source_crosswalk_row_id": place.source_row_id,
            "source_crosswalk_row_sha256": place.source_row_sha256,
            "source_candidate_ids": tuple(
                record.source_candidate_id for record in records
            ),
            "source_dataset_entity_ids": tuple(
                record.ref.entity_id for record in records
            ),
            "coordinates": coordinates.model_dump(mode="json"),
            "description": description.model_dump(mode="json"),
            "operating_info": operating_info.model_dump(mode="json"),
            "dataset_rights": dataset_rights.model_dump(mode="json"),
            "direct_media": direct_media.model_dump(mode="json"),
            "confidence_is_qualification_filter_only": True,
            "confidence_adds_score": False,
        }
        rows.append(
            CandidateObjectiveRow(**fields, row_sha256=canonical_sha256(fields))
        )

    rights_bytes = canonical_json_bytes(rights.model_dump(mode="json"))
    parents = ObjectiveEvidenceParents(
        rights_projection_sha256=rights.projection_sha256,
        rights_projection_file_sha256=_sha256_bytes(rights_bytes),
        entity_projection_sha256=projection.projection_sha256,
        entity_policy_report_sha256=policy.report_sha256,
        formal_policy_sha256=policy.formal_policy_sha256,
        catalog_v1_tree_sha256=policy.parents.catalog_v1_tree_sha256,
        protected_inputs_sha256=policy.parents.protected_inputs_sha256,
        complete_dispositions_root=rights.parents.complete_dispositions_root,
        media_attachments_root=policy.roots["media_attachments"],
    )
    rows_root = canonical_sha256(
        [row.model_dump(mode="json") for row in rows]
    )
    fields = {
        "schema_version": "candidate-objective-evidence-v1",
        "data_version": "catalog-v2-objective-evidence-data-v1",
        "parents": parents.model_dump(mode="json"),
        "rows": [row.model_dump(mode="json") for row in rows],
        "candidate_count": len(rows),
        "rows_root": rows_root,
    }
    return CandidateObjectiveEvidence.model_validate(
        {**fields, "report_sha256": canonical_sha256(fields)}
    )


def _build_bundle_from_manifest(
    repo_root: Path,
    manifest: dict[str, object],
) -> tuple[RightsProjection, CandidateObjectiveEvidence]:
    """Replay the full rights bundle from an already authenticated manifest."""

    entity_path = repo_root / ENTITY_PROJECTION_PATH
    policy_path = repo_root / ENTITY_POLICY_PATH
    audit_path = repo_root / CATALOG_AUDIT_PATH

    projection = project_catalog_entities._load_contract(
        entity_path, EntityProjection
    )
    policy = project_catalog_entities._load_contract(
        policy_path, EntityPolicyReport
    )
    audit = project_catalog_entities._load_contract(audit_path, CatalogAudit)
    if policy.formal_policy_sha256 != formal_policy_sha256():
        raise RightsProjectionError("entity policy formal hash drifted")
    if policy.parents.entity_projection_file_sha256 != _read_regular_sha256(
        entity_path
    ):
        raise RightsProjectionError("entity policy projection file parent drifted")
    if policy.parents.entity_projection_sha256 != projection.projection_sha256:
        raise RightsProjectionError("entity policy projection hash parent drifted")
    if policy.parents.immutability_manifest_sha256 != manifest["manifest_sha256"]:
        raise RightsProjectionError("entity policy immutability parent drifted")
    manifest_parents = project_catalog_entities._protected_parents(manifest)
    if (
        policy.parents.catalog_v1_tree_sha256
        != manifest_parents.catalog_v1_tree_sha256
        or {
            row.relpath for row in policy.parents.protected_inputs
        }
        != set(project_catalog_entities.PROTECTED_PARENT_PATHS)
        or policy.parents.protected_inputs_sha256
        != canonical_sha256(
            [
                row.model_dump(mode="json")
                for row in policy.parents.protected_inputs
            ]
        )
    ):
        raise RightsProjectionError("entity policy protected-parent set drifted")
    if _read_regular_sha256(audit_path) != next(
        row.file_sha256
        for row in policy.parents.protected_inputs
        if row.relpath == CATALOG_AUDIT_PATH
    ):
        raise RightsProjectionError("catalog audit protected parent drifted")
    if (
        policy.counts.media_attachment_count != 8
        or len(policy.media_attachments) != 8
        or policy.roots["media_attachments"]
        != canonical_sha256(
            [row.model_dump(mode="json") for row in policy.media_attachments]
        )
    ):
        raise RightsProjectionError("complete media-attachment root drifted")

    rights = _build_rights(
        repo_root=repo_root,
        projection=projection,
        policy=policy,
        audit=audit,
        policy_file_sha256=_read_regular_sha256(policy_path),
    )
    objective = _build_objective(
        projection=projection,
        policy=policy,
        audit=audit,
        rights=rights,
    )
    if (
        fingerprint_catalog_v1.scan_catalog_tree(repo_root)["tree_sha256"]
        != policy.parents.catalog_v1_tree_sha256
    ):
        raise RightsProjectionError("protected catalog v1 changed during projection")
    return rights, objective


def build_bundle(repo_root: Path) -> tuple[RightsProjection, CandidateObjectiveEvidence]:
    """Rebuild the historical bundle only from its exact immutable parents."""

    repo_root = repo_root.resolve()
    manifest_path = repo_root / IMMUTABILITY_PATH
    manifest = fingerprint_catalog_v1.verify_manifest(repo_root, manifest_path)
    return _build_bundle_from_manifest(repo_root, manifest)


def _load_json_object(path: Path) -> dict[str, object]:
    payload, _ = fingerprint_catalog_v1._stable_regular_payload(path)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RightsProjectionError("rights attestation parent is not canonical JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise RightsProjectionError("rights attestation parent is not a canonical object")
    return value


def _require_exact_path(repo_root: Path, path: Path, expected: str) -> Path:
    resolved = path.resolve()
    if resolved != (repo_root / expected).resolve():
        raise RightsProjectionError(f"rights attestation parent must be {expected}")
    return resolved


def _current_attestation_inputs(
    repo_root: Path,
    *,
    lineage_successor_path: Path,
    rights_path: Path,
    objective_path: Path,
    protected_before_path: Path,
) -> tuple[
    dict[str, object],
    RightsProjection,
    CandidateObjectiveEvidence,
    RightsProjection,
    CandidateObjectiveEvidence,
    dict[str, object],
]:
    repo_root = repo_root.resolve()
    predecessor_path = repo_root / IMMUTABILITY_PATH
    lineage_successor_path = _require_exact_path(
        repo_root, lineage_successor_path, LINEAGE_SUCCESSOR_PATH
    )
    rights_path = _require_exact_path(repo_root, rights_path, RIGHTS_TARGET)
    objective_path = _require_exact_path(
        repo_root, objective_path, OBJECTIVE_TARGET
    )
    protected_before_path = _require_exact_path(
        repo_root, protected_before_path, PROTECTED_BEFORE_PATH
    )

    successor = fingerprint_catalog_v1.verify_successor_manifest(
        repo_root,
        predecessor_path,
        _load_json_object(lineage_successor_path),
    )
    predecessor = _load_json_object(predecessor_path)
    replayed_rights, replayed_objective = _build_bundle_from_manifest(
        repo_root, predecessor
    )
    original_rights = project_catalog_entities._load_contract(
        rights_path, RightsProjection
    )
    original_objective = project_catalog_entities._load_contract(
        objective_path, CandidateObjectiveEvidence
    )
    if (
        replayed_rights.counts != original_rights.counts
        or replayed_rights.roots != original_rights.roots
        or replayed_rights.confidence_is_qualification_filter_only is not True
        or replayed_rights.confidence_adds_score is not False
    ):
        raise RightsProjectionError("rights semantics changed during current replay")
    if (
        replayed_objective.candidate_count != original_objective.candidate_count
        or replayed_objective.rows_root != original_objective.rows_root
    ):
        raise RightsProjectionError("objective semantics changed during current replay")

    protected_before = fingerprint_catalog_v1.validate_protected_manifest(
        repo_root,
        _load_json_object(protected_before_path),
        plan_id="02-60",
        stage="before",
    )
    return (
        successor,
        original_rights,
        original_objective,
        replayed_rights,
        replayed_objective,
        protected_before,
    )


def build_current_bundle(
    repo_root: Path,
    *,
    lineage_successor_path: Path,
    rights_path: Path,
    objective_path: Path,
    protected_before_path: Path,
) -> tuple[RightsProjection, CandidateObjectiveEvidence]:
    """Replay complete models after authenticating the current lineage bridge."""

    inputs = _current_attestation_inputs(
        repo_root,
        lineage_successor_path=lineage_successor_path,
        rights_path=rights_path,
        objective_path=objective_path,
        protected_before_path=protected_before_path,
    )
    return inputs[3], inputs[4]


def build_current_attestation(
    repo_root: Path,
    *,
    lineage_successor_path: Path,
    rights_path: Path,
    objective_path: Path,
    protected_before_path: Path,
) -> dict[str, object]:
    """Re-attest unchanged rights semantics against the current source lineage."""

    repo_root = repo_root.resolve()
    (
        successor,
        original_rights,
        original_objective,
        replayed_rights,
        replayed_objective,
        protected_before,
    ) = _current_attestation_inputs(
        repo_root,
        lineage_successor_path=lineage_successor_path,
        rights_path=rights_path,
        objective_path=objective_path,
        protected_before_path=protected_before_path,
    )
    predecessor = successor["predecessor"]
    assert isinstance(predecessor, dict)
    fields: dict[str, object] = {
        "schema_version": "rights-current-parent-attestation-v1",
        "semantic_disposition": "UNCHANGED_REATTESTED",
        "lineage": {
            "predecessor_manifest_sha256": predecessor["manifest_sha256"],
            "successor_sha256": successor["successor_sha256"],
            "recorded_inventory_sha256": successor["recorded_inventory_sha256"],
            "current_inventory_sha256": successor["current_inventory_sha256"],
            "catalog_v1_tree_sha256": successor["catalog_v1_tree_sha256"],
            "planning_history_tree_sha256": successor[
                "planning_history_tree_sha256"
            ],
        },
        "original_rights": {
            "file_sha256": _read_regular_sha256(repo_root / RIGHTS_TARGET),
            "projection_sha256": original_rights.projection_sha256,
        },
        "original_objective_evidence": {
            "file_sha256": _read_regular_sha256(repo_root / OBJECTIVE_TARGET),
            "report_sha256": original_objective.report_sha256,
        },
        "rights_semantics": {
            "counts": original_rights.counts,
            "dataset_grants_root": original_rights.roots["dataset_grants"],
            "asset_rights_root": original_rights.roots["asset_rights"],
            "attachment_rights_root": original_rights.roots["attachment_rights"],
            "phase1_rights_files_root": original_rights.roots[
                "phase1_rights_files"
            ],
        },
        "objective_semantics": {
            "candidate_count": original_objective.candidate_count,
            "rows_root": original_objective.rows_root,
        },
        "current_replay": {
            "rights_projection_sha256": replayed_rights.projection_sha256,
            "objective_report_sha256": replayed_objective.report_sha256,
            "code_hashes": replayed_rights.code_hashes,
            "config_hashes": replayed_rights.config_hashes,
        },
        "protected_before": {
            "protected_manifest_sha256": protected_before[
                "protected_manifest_sha256"
            ],
            "identity_rows_sha256": protected_before["identity_rows_sha256"],
            "protected_set_sha256": protected_before["protected_set_sha256"],
            "owner_count": protected_before["owner_count"],
        },
        "policy_assertions": {
            "confidence_is_qualification_filter_only": True,
            "confidence_adds_score": False,
            "blind_membership_disclosed": False,
        },
    }
    unordered = {**fields, "attestation_sha256": canonical_sha256(fields)}
    attestation = {key: unordered[key] for key in CURRENT_ATTESTATION_KEYS}
    if tuple(attestation) != CURRENT_ATTESTATION_KEYS:
        raise RightsProjectionError("current rights attestation schema is not closed")
    fingerprint_catalog_v1._assert_membership_free_payload(attestation)
    return attestation


def verify_current_attestation(
    repo_root: Path,
    recorded: dict[str, object],
    *,
    lineage_successor_path: Path,
    rights_path: Path,
    objective_path: Path,
    protected_before_path: Path,
) -> dict[str, object]:
    """Require an exact current-parent rights attestation replay."""

    if tuple(recorded) != CURRENT_ATTESTATION_KEYS:
        raise RightsProjectionError("current rights attestation schema is not closed")
    if recorded.get("schema_version") != "rights-current-parent-attestation-v1":
        raise RightsProjectionError("rights attestation schema version is invalid")
    fingerprint_catalog_v1._manifest_self_hash(recorded, "attestation_sha256")
    fingerprint_catalog_v1._assert_membership_free_payload(recorded)
    expected = build_current_attestation(
        repo_root,
        lineage_successor_path=lineage_successor_path,
        rights_path=rights_path,
        objective_path=objective_path,
        protected_before_path=protected_before_path,
    )
    if recorded != expected:
        raise RightsProjectionError("rights attestation differs from exact replay")
    return expected


def _publish_bundle_no_replace(
    rights_path: Path,
    objective_path: Path,
    rights_bytes: bytes,
    objective_bytes: bytes,
) -> None:
    if rights_path.exists() or objective_path.exists():
        raise FileExistsError("restricted rights bundle already exists")
    rights_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    objective_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    common = rights_path.parents[1]
    created: list[Path] = []
    with tempfile.TemporaryDirectory(prefix=".rights-bundle-", dir=common) as raw:
        stage = Path(raw)
        staged_rights = stage / rights_path.name
        staged_objective = stage / objective_path.name
        for path, payload in (
            (staged_rights, rights_bytes),
            (staged_objective, objective_bytes),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        try:
            for source, target in (
                (staged_rights, rights_path),
                (staged_objective, objective_path),
            ):
                os.link(source, target)
                created.append(target)
            for directory in {rights_path.parent, objective_path.parent}:
                descriptor = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except BaseException:
            for path in created:
                path.unlink(missing_ok=True)
            raise


def _exact_target(repo_root: Path, value: Path, expected: str) -> Path:
    target = fingerprint_catalog_v1._cli_path(repo_root, value)
    try:
        relpath = target.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise RightsProjectionError("rights bundle target escapes repository") from exc
    if relpath != expected:
        raise RightsProjectionError(f"rights bundle target must be {expected}")
    return target


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build-bundle", nargs=2, type=Path, metavar=("RIGHTS", "OBJECTIVE"))
    modes.add_argument("--check-bundle", nargs=2, type=Path, metavar=("RIGHTS", "OBJECTIVE"))
    modes.add_argument("--build-current-attestation", type=Path, metavar="TARGET")
    modes.add_argument("--check-current-bundle", type=Path, metavar="TARGET")
    parser.add_argument("--lineage-successor", type=Path)
    parser.add_argument("--rights", type=Path)
    parser.add_argument("--objective-evidence", type=Path)
    parser.add_argument("--protected-before", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = fingerprint_catalog_v1._repo_root()
    current_target = args.build_current_attestation or args.check_current_bundle
    if current_target is not None:
        if (
            args.lineage_successor is None
            or args.rights is None
            or args.objective_evidence is None
        ):
            raise RightsProjectionError(
                "current rights attestation requires lineage, rights, and objective parents"
            )
        target = _exact_target(
            repo_root, current_target, CURRENT_ATTESTATION_TARGET
        )
        protected_before = args.protected_before or (
            repo_root / PROTECTED_BEFORE_PATH
        )
        attestation = build_current_attestation(
            repo_root,
            lineage_successor_path=args.lineage_successor,
            rights_path=args.rights,
            objective_path=args.objective_evidence,
            protected_before_path=protected_before,
        )
        if args.build_current_attestation is not None:
            second = build_current_attestation(
                repo_root,
                lineage_successor_path=args.lineage_successor,
                rights_path=args.rights,
                objective_path=args.objective_evidence,
                protected_before_path=protected_before,
            )
            if canonical_json_bytes(attestation) != canonical_json_bytes(second):
                raise RightsProjectionError(
                    "independent current rights attestation builds differ"
                )
            fingerprint_catalog_v1._publish_exact_existing(
                target, canonical_json_bytes(attestation)
            )
        else:
            verify_current_attestation(
                repo_root,
                _load_json_object(target),
                lineage_successor_path=args.lineage_successor,
                rights_path=args.rights,
                objective_path=args.objective_evidence,
                protected_before_path=protected_before,
            )
        print(attestation["attestation_sha256"])
        return 0

    values = args.build_bundle or args.check_bundle
    assert values is not None
    rights_path = _exact_target(repo_root, values[0], RIGHTS_TARGET)
    objective_path = _exact_target(repo_root, values[1], OBJECTIVE_TARGET)
    first_rights, first_objective = build_bundle(repo_root)
    rights_bytes = canonical_json_bytes(first_rights.model_dump(mode="json"))
    objective_bytes = canonical_json_bytes(first_objective.model_dump(mode="json"))
    if args.build_bundle:
        second_rights, second_objective = build_bundle(repo_root)
        if (
            rights_bytes
            != canonical_json_bytes(second_rights.model_dump(mode="json"))
            or objective_bytes
            != canonical_json_bytes(second_objective.model_dump(mode="json"))
        ):
            raise RightsProjectionError("independent rights bundle builds differ")
        _publish_bundle_no_replace(
            rights_path,
            objective_path,
            rights_bytes,
            objective_bytes,
        )
    else:
        recorded_rights = project_catalog_entities._load_contract(
            rights_path, RightsProjection
        )
        recorded_objective = project_catalog_entities._load_contract(
            objective_path, CandidateObjectiveEvidence
        )
        if canonical_json_bytes(recorded_rights.model_dump(mode="json")) != rights_bytes:
            raise RightsProjectionError("recorded rights projection differs from replay")
        if (
            canonical_json_bytes(recorded_objective.model_dump(mode="json"))
            != objective_bytes
        ):
            raise RightsProjectionError("recorded objective evidence differs from replay")
    print(first_rights.projection_sha256)
    print(first_objective.report_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
