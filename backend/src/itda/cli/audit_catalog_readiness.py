"""Build and verify evidence-only catalog readiness and enrichment scope."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from itda.cli import (
    fingerprint_catalog_v1,
    project_catalog_entities,
)
from itda.cli.normalize_catalog_enrichment import (
    KTO_ELIGIBILITY_REL,
    KTO_NORMALIZATIONS_REL,
    build_kto_recovery_normalization,
)
from itda.cli.plan_catalog_kto_recovery import (
    _assert_private_directory,
    _publish_private_files,
    _read_regular_json,
)
from itda.contracts.catalog_enrichment import (
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    build_enrichment_plan,
    verify_enrichment_bundle,
)
from itda.contracts.catalog_enrichment_evidence import (
    EnrichmentEvidenceSidecar,
    build_enrichment_sidecar,
    canonical_sidecar_bytes,
)
from itda.contracts.catalog_entity import EntityProjection
from itda.contracts.catalog_entity_policy import (
    EntityPolicyReport,
    formal_policy_sha256,
)
from itda.contracts.catalog_readiness import (
    AggregateReadiness,
    CandidateRepresentationAssignments,
    CatalogReadinessReport,
    CatalogRoundManifest,
    EnrichmentCandidatePool,
    EnrichmentPoolParents,
    KtoRecoveryReadiness,
    ProviderCandidateEvidence,
    ReadinessParents,
    RemediationCandidatePool,
    RepresentationAssignmentsParents,
    RepresentationGroupRules,
    RepresentationQuotaAttestation,
    RepresentationQuotaConfig,
    RoundManifestFile,
    RoundOrderManifest,
    build_aggregate_readiness,
    build_assignment_artifact,
    build_default_representation_rules,
    build_enrichment_pool,
    build_readiness_report,
    build_remediation_candidate_pool,
    build_representation_quota_artifacts,
    build_round_order_manifest,
    classify_representation_candidate,
    derive_kto_recovery_readiness,
)
from itda.contracts.catalog_rights_v2 import (
    CandidateObjectiveEvidence,
    RightsProjection,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

ENTITY_PROJECTION_PATH = "artifacts/restricted/catalog/v2/projection/entity-projection.json"
ENTITY_POLICY_PATH = "artifacts/restricted/catalog/v2/projection/entity-policy-report.json"
RIGHTS_PATH = "artifacts/restricted/catalog/v2/rights/rights-projection.json"
OBJECTIVE_PATH = "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
SEED_PATH = "fixtures/catalog/v1/public/proposal-36-coverage-seed.json"
SOURCE_ATTACHMENT_PATH = (
    "/Users/penggin/.codex/attachments/ac3333f9-e1f2-4f9e-a614-da51d491601b/pasted-text.txt"
)
RULES_TARGET = "artifacts/restricted/catalog/v2/enrichment/representation-group-rules.json"
ASSIGNMENTS_TARGET = (
    "artifacts/restricted/catalog/v2/enrichment/candidate-representation-groups.json"
)
READINESS_TARGET = "artifacts/restricted/catalog/v2/enrichment/readiness-before-enrichment.json"
POOL_TARGET = "artifacts/restricted/catalog/v2/enrichment/enrichment-candidate-pool.json"
CATALOG_AUDIT_PATH = "artifacts/restricted/catalog/v1/review/catalog-audit.json"
ROUND_MANIFEST_NAME = "enrichment-round-manifest.json"
ROUND_ORDER_NAME = "round-order-manifest.json"
AGGREGATE_NAME = "aggregate-readiness.json"
REMEDIATION_REF_NAME = "remediation-round-ref.json"
REMEDIATION_SUPERSESSION_NAME = "remediation-round-supersession.json"
REMEDIATION_POOL_NAME = "remediation-candidate-pool.json"
REMEDIATION_REPORT_NAME = "remediation-report.json"
QUOTA_CONFIG_NAME = "representation-quota-config.json"
QUOTA_ATTESTATION_NAME = "representation-quota-attestation.json"
_ROUND_DERIVED_NAMES = frozenset(
    {
        ROUND_MANIFEST_NAME,
        ROUND_ORDER_NAME,
        AGGREGATE_NAME,
        REMEDIATION_REF_NAME,
        REMEDIATION_SUPERSESSION_NAME,
        QUOTA_CONFIG_NAME,
        QUOTA_ATTESTATION_NAME,
    }
)
KTO_DECISIONS_REL = Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/decisions")
KTO_SUBSTITUTIONS_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/substitutions"
)
KTO_REENTRIES_REL = Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/reentries")
KTO_PREFLIGHT_REL = Path(
    "artifacts/restricted/catalog/v2/supplemental/kto-recovery/preflight-readiness"
)
KTO_AGGREGATE_REL = Path(
    "artifacts/restricted/catalog/v2/enrichment/rounds/"
    "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55/"
    "aggregate-readiness.json"
)
KTO_ENTITY_PROJECTION_REL = Path(
    "artifacts/restricted/catalog/v2/projection/entity-projection.json"
)


@dataclass(frozen=True)
class PublishedKtoRecoveryReadiness:
    substitution_root: Path
    reentry_root: Path
    preflight_root: Path


@dataclass(frozen=True)
class KtoRecoveryTerminalFailure:
    terminal_root_sha256: str
    payload: dict[str, object]

    @property
    def files(self) -> dict[str, bytes]:
        return {
            "reentry-exhausted.json": canonical_json_bytes(
                {
                    "payload": self.payload,
                    "terminal_root_sha256": self.terminal_root_sha256,
                }
            )
        }


class CatalogReadinessError(ValueError):
    """Raised when immutable readiness evidence does not reproduce."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path) -> bytes:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise CatalogReadinessError("readiness parent is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | fingerprint_catalog_v1.O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        fingerprint_catalog_v1._same_object(before, after)
        raw = fingerprint_catalog_v1._read_descriptor(descriptor)
        fingerprint_catalog_v1._same_state(after, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    return raw


def _load_contract(path: Path, contract: type[object]) -> object:
    return contract.model_validate(json.loads(_read_regular(path)))  # type: ignore[attr-defined]


def _verify_parent_chain(
    *,
    entity_path: Path,
    policy_path: Path,
    rights_path: Path,
    objective_path: Path,
) -> tuple[
    EntityProjection,
    EntityPolicyReport,
    RightsProjection,
    CandidateObjectiveEvidence,
]:
    entity = _load_contract(entity_path, EntityProjection)
    policy = _load_contract(policy_path, EntityPolicyReport)
    rights = _load_contract(rights_path, RightsProjection)
    objective = _load_contract(objective_path, CandidateObjectiveEvidence)
    assert isinstance(entity, EntityProjection)
    assert isinstance(policy, EntityPolicyReport)
    assert isinstance(rights, RightsProjection)
    assert isinstance(objective, CandidateObjectiveEvidence)

    policy_file_sha256 = _sha256(_read_regular(policy_path))
    entity_file_sha256 = _sha256(_read_regular(entity_path))
    rights_file_sha256 = _sha256(_read_regular(rights_path))
    expected_protected = set(project_catalog_entities.PROTECTED_PARENT_PATHS)
    actual_protected = {row.relpath for row in policy.parents.protected_inputs}
    complete_dispositions_root = canonical_sha256(
        {
            "crosswalk_dispositions": policy.roots["crosswalk_dispositions"],
            "relationship_dispositions": policy.roots["relationship_dispositions"],
        }
    )
    if policy.formal_policy_sha256 != formal_policy_sha256():
        raise CatalogReadinessError("formal entity policy hash drifted")
    if actual_protected != expected_protected:
        raise CatalogReadinessError("complete protected-parent set drifted")
    if policy.parents.protected_inputs_sha256 != canonical_sha256(
        [row.model_dump(mode="json") for row in policy.parents.protected_inputs]
    ):
        raise CatalogReadinessError("protected-parent inventory root drifted")
    if (
        policy.parents.entity_projection_file_sha256 != entity_file_sha256
        or policy.parents.entity_projection_sha256 != entity.projection_sha256
        or rights.parents.entity_policy_file_sha256 != policy_file_sha256
        or rights.parents.entity_policy_report_sha256 != policy.report_sha256
        or rights.parents.formal_policy_sha256 != policy.formal_policy_sha256
        or rights.parents.catalog_v1_tree_sha256 != policy.parents.catalog_v1_tree_sha256
        or rights.parents.protected_inputs_sha256 != policy.parents.protected_inputs_sha256
        or rights.parents.complete_dispositions_root != complete_dispositions_root
        or rights.parents.media_attachments_root != policy.roots["media_attachments"]
        or objective.parents.rights_projection_file_sha256 != rights_file_sha256
        or objective.parents.rights_projection_sha256 != rights.projection_sha256
        or objective.parents.entity_projection_sha256 != entity.projection_sha256
        or objective.parents.entity_policy_report_sha256 != policy.report_sha256
        or objective.parents.formal_policy_sha256 != policy.formal_policy_sha256
        or objective.parents.catalog_v1_tree_sha256 != policy.parents.catalog_v1_tree_sha256
        or objective.parents.protected_inputs_sha256 != policy.parents.protected_inputs_sha256
        or objective.parents.complete_dispositions_root != complete_dispositions_root
        or objective.parents.media_attachments_root != policy.roots["media_attachments"]
    ):
        raise CatalogReadinessError("v2 policy/rights/objective parent chain drifted")
    return entity, policy, rights, objective


def _seed_hashes(seed_path: Path, source_attachment_path: Path) -> tuple[str, str]:
    seed_raw = json.loads(_read_regular(seed_path))
    if not isinstance(seed_raw, dict):
        raise CatalogReadinessError("proposal coverage seed must be an object")
    seed_sha256 = seed_raw.get("seed_manifest_sha256")
    attachment_sha256 = _sha256(_read_regular(source_attachment_path))
    if (
        not isinstance(seed_sha256, str)
        or seed_sha256
        != canonical_sha256(
            {key: value for key, value in seed_raw.items() if key != "seed_manifest_sha256"}
        )
        or seed_raw.get("source_attachment_sha256") != attachment_sha256
    ):
        raise CatalogReadinessError("proposal coverage seed or source attachment drifted")
    return seed_sha256, attachment_sha256


def _build_all(
    repo_root: Path,
) -> tuple[
    RepresentationGroupRules,
    CandidateRepresentationAssignments,
    CatalogReadinessReport,
    EnrichmentCandidatePool,
]:
    entity_path = repo_root / ENTITY_PROJECTION_PATH
    policy_path = repo_root / ENTITY_POLICY_PATH
    rights_path = repo_root / RIGHTS_PATH
    objective_path = repo_root / OBJECTIVE_PATH
    entity, policy, rights, objective = _verify_parent_chain(
        entity_path=entity_path,
        policy_path=policy_path,
        rights_path=rights_path,
        objective_path=objective_path,
    )
    seed_sha256, attachment_sha256 = _seed_hashes(
        repo_root / SEED_PATH, Path(SOURCE_ATTACHMENT_PATH)
    )
    rules = build_default_representation_rules(
        seed_manifest_sha256=seed_sha256,
        source_attachment_sha256=attachment_sha256,
    )
    rules_bytes = canonical_json_bytes(rules.model_dump(mode="json"))
    rules_file_sha256 = _sha256(rules_bytes)

    objective_by_place = {row.place_entity_id: row for row in objective.rows}
    dataset_by_entity = {row.ref.entity_id: row for row in entity.dataset_records}
    if set(objective_by_place) != {place.ref.entity_id for place in entity.place_entities}:
        raise CatalogReadinessError("objective and place inventories differ")
    assignments = []
    t0_provider_candidate_ids: set[str] = set()
    dataset_to_place: dict[str, str] = {}
    for place in entity.place_entities:
        objective_row = objective_by_place[place.ref.entity_id]
        records = tuple(dataset_by_entity[ref.entity_id] for ref in place.member_refs)
        if tuple(record.ref.entity_id for record in records) != (
            objective_row.source_dataset_entity_ids
        ):
            raise CatalogReadinessError("objective row dataset inventory drifted")
        evidence = tuple(
            ProviderCandidateEvidence(
                source_candidate_id=record.source_candidate_id,
                source_dataset_entity_id=record.ref.entity_id,
                source_row_sha256=record.source_candidate_sha256,
                provider=record.evidence.provider,
                official_dataset_id=record.evidence.official_dataset_id,
                name_ko=record.name_ko,
            )
            for record in records
        )
        assignments.append(
            classify_representation_candidate(
                place_entity_id=place.ref.entity_id,
                objective_evidence_row_sha256=objective_row.row_sha256,
                provider_evidence=evidence,
                rules=rules,
            )
        )
        for record in records:
            dataset_to_place[record.ref.entity_id] = place.ref.entity_id
            if (
                record.evidence.provider == "TOUR_API"
                and record.evidence.evidence_tier == "T0_EXACT_PROVIDER_SCOPED_ID"
            ):
                t0_provider_candidate_ids.add(record.source_candidate_id)

    common_parent_fields = {
        "entity_policy_file_sha256": _sha256(_read_regular(policy_path)),
        "entity_policy_report_sha256": policy.report_sha256,
        "formal_policy_sha256": policy.formal_policy_sha256,
        "catalog_v1_tree_sha256": policy.parents.catalog_v1_tree_sha256,
        "protected_inputs_sha256": policy.parents.protected_inputs_sha256,
        "complete_dispositions_root": rights.parents.complete_dispositions_root,
        "media_attachments_root": policy.roots["media_attachments"],
        "entity_projection_file_sha256": _sha256(_read_regular(entity_path)),
        "entity_projection_sha256": entity.projection_sha256,
        "rights_projection_file_sha256": _sha256(_read_regular(rights_path)),
        "rights_projection_sha256": rights.projection_sha256,
        "objective_evidence_file_sha256": _sha256(_read_regular(objective_path)),
        "objective_evidence_report_sha256": objective.report_sha256,
        "objective_evidence_rows_root": objective.rows_root,
    }
    assignment_parents = RepresentationAssignmentsParents(
        **common_parent_fields,
        proposal_seed_manifest_sha256=seed_sha256,
        source_attachment_sha256=attachment_sha256,
        representation_rules_file_sha256=rules_file_sha256,
        representation_rule_table_sha256=rules.rule_table_sha256,
    )
    assignment_artifact = build_assignment_artifact(
        rows=tuple(assignments), parents=assignment_parents
    )
    assignments_bytes = canonical_json_bytes(assignment_artifact.model_dump(mode="json"))
    assignments_file_sha256 = _sha256(assignments_bytes)
    readiness_parents = ReadinessParents(
        **common_parent_fields,
        representation_rules_file_sha256=rules_file_sha256,
        representation_rule_table_sha256=rules.rule_table_sha256,
        representation_assignments_file_sha256=assignments_file_sha256,
        complete_assignment_sha256=assignment_artifact.complete_assignment_sha256,
    )
    assignment_by_place = {row.place_entity_id: row for row in assignment_artifact.rows}
    readiness = build_readiness_report(
        objective_evidence=objective,
        assignments=assignment_by_place,
        assignment_hash_validity={
            row.place_entity_id: (
                row.assignment_row_sha256
                == canonical_sha256(row.model_dump(exclude={"assignment_row_sha256"}, mode="json"))
            )
            for row in assignment_artifact.rows
        },
        expected_rule_table_sha256=rules.rule_table_sha256,
        t0_provider_candidate_ids=frozenset(t0_provider_candidate_ids),
        parents=readiness_parents,
    )
    readiness_bytes = canonical_json_bytes(readiness.model_dump(mode="json"))

    linked_seed_ids_by_place: dict[str, list[str]] = {}
    for seed in entity.seed_lineage:
        if seed.status != "LINKED":
            continue
        place_id = dataset_to_place.get(seed.candidate_ref.entity_id)
        if place_id is None:
            raise CatalogReadinessError("linked seed lacks an exact place parent")
        linked_seed_ids_by_place.setdefault(place_id, []).append(seed.seed_id)
    pool_parents = EnrichmentPoolParents(
        readiness_file_sha256=_sha256(readiness_bytes),
        readiness_report_sha256=readiness.report_sha256,
        readiness_rows_root=readiness.rows_root,
        entity_policy_report_sha256=policy.report_sha256,
        formal_policy_sha256=policy.formal_policy_sha256,
        catalog_v1_tree_sha256=policy.parents.catalog_v1_tree_sha256,
        protected_inputs_sha256=policy.parents.protected_inputs_sha256,
        complete_dispositions_root=rights.parents.complete_dispositions_root,
        media_attachments_root=policy.roots["media_attachments"],
        entity_projection_file_sha256=_sha256(_read_regular(entity_path)),
        entity_projection_sha256=entity.projection_sha256,
        rights_projection_file_sha256=_sha256(_read_regular(rights_path)),
        rights_projection_sha256=rights.projection_sha256,
        objective_evidence_file_sha256=_sha256(_read_regular(objective_path)),
        objective_evidence_report_sha256=objective.report_sha256,
        representation_rules_file_sha256=rules_file_sha256,
        representation_rule_table_sha256=rules.rule_table_sha256,
        representation_assignments_file_sha256=assignments_file_sha256,
        complete_assignment_sha256=assignment_artifact.complete_assignment_sha256,
    )
    pool = build_enrichment_pool(
        readiness=readiness,
        linked_seed_ids_by_place={
            key: tuple(value) for key, value in linked_seed_ids_by_place.items()
        },
        parents=pool_parents,
    )
    return rules, assignment_artifact, readiness, pool


def _exact_target(repo_root: Path, value: Path, expected: str) -> Path:
    resolved = (value if value.is_absolute() else Path.cwd() / value).resolve()
    try:
        relpath = resolved.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise CatalogReadinessError("readiness artifact escapes repository") from exc
    if relpath != expected:
        raise CatalogReadinessError(f"readiness artifact must be {expected}")
    return resolved


def _publish_bundle(targets: tuple[Path, ...], payloads: tuple[bytes, ...]) -> None:
    if any(path.exists() for path in targets):
        raise FileExistsError("readiness bundle already exists")
    common = targets[0].parent
    common.mkdir(parents=True, exist_ok=True, mode=0o700)
    created: list[Path] = []
    with tempfile.TemporaryDirectory(prefix=".readiness-", dir=common) as raw:
        stage = Path(raw)
        staged = []
        for target, payload in zip(targets, payloads, strict=True):
            source = stage / target.name
            descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            staged.append(source)
        try:
            for source, target in zip(staged, targets, strict=True):
                os.link(source, target)
                created.append(target)
            descriptor = os.open(common, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BaseException:
            for target in created:
                target.unlink(missing_ok=True)
            raise


def _round_value(repo_root: Path, root: Path) -> str:
    try:
        return root.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise CatalogReadinessError("round root escapes repository") from exc


def _round_root(
    repo_root: Path,
    supplied: Path,
    round_id: str,
) -> Path:
    resolved = supplied.expanduser().resolve(strict=True)
    if resolved.name != round_id:
        raise CatalogReadinessError("round root basename does not match round ID")
    expected_parent = (repo_root / "artifacts/restricted/catalog/v2/enrichment/rounds").resolve(
        strict=True
    )
    if resolved.parent != expected_parent:
        raise CatalogReadinessError("round root is outside the exact rounds directory")
    return resolved


def _exclusive_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError("short write while publishing readiness artifact")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _manifest_bytes(manifest: CatalogRoundManifest) -> bytes:
    return canonical_json_bytes(manifest.model_dump(exclude={"manifest_sha256"}, mode="json"))


def _round_inventory(root: Path) -> tuple[RoundManifestFile, ...]:
    rows: list[RoundManifestFile] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in _ROUND_DERIVED_NAMES:
            continue
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise CatalogReadinessError("round inventory contains a non-regular file")
        payload = _read_regular(path)
        after = os.lstat(path)
        fingerprint_catalog_v1._same_object(before, after)
        rows.append(
            RoundManifestFile(
                relpath=relative,
                size=len(payload),
                mode=f"{stat.S_IMODE(after.st_mode):04o}",
                file_sha256=_sha256(payload),
            )
        )
    return tuple(rows)


def _build_round_manifest(
    *,
    repo_root: Path,
    root: Path,
    round_id: str,
    previous_manifest_sha256: str | None,
    ancestry_depth: int,
) -> CatalogRoundManifest:
    sidecar_path = root / "evidence-sidecars.json"
    sidecar_raw = _read_regular(sidecar_path)
    sidecar = EnrichmentEvidenceSidecar.model_validate_json(sidecar_raw)
    rebuilt = build_enrichment_sidecar(
        round_root=root,
        round_id=round_id,
        catalog_audit_path=repo_root / CATALOG_AUDIT_PATH,
    )
    if canonical_sidecar_bytes(rebuilt) != sidecar_raw:
        raise CatalogReadinessError("selected round sidecar differs from full replay")
    inventory = _round_inventory(root)
    fields = {
        "schema_version": "itda.catalog-enrichment-round-manifest.v1",
        "round_id": round_id,
        "round_root": _round_value(repo_root, root),
        "ancestry_depth": ancestry_depth,
        "previous_round_manifest_sha256": previous_manifest_sha256,
        "immutable_files": [row.model_dump(mode="json") for row in inventory],
        "immutable_files_root": canonical_sha256(
            [row.model_dump(mode="json") for row in inventory]
        ),
        "sidecar_file_sha256": _sha256(sidecar_raw),
        "sidecar_sha256": sidecar.sidecar_sha256,
    }
    return CatalogRoundManifest(
        **fields,
        manifest_sha256=canonical_sha256(fields),
    )


def _load_round_manifest(path: Path) -> CatalogRoundManifest:
    raw = _read_regular(path)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or "manifest_sha256" in parsed:
        raise CatalogReadinessError("round manifest must be an unsigned canonical object")
    if canonical_json_bytes(parsed) != raw:
        raise CatalogReadinessError("round manifest bytes are not canonical")
    return CatalogRoundManifest.model_validate({**parsed, "manifest_sha256": _sha256(raw)})


def _load_order_manifest(path: Path) -> RoundOrderManifest:
    raw = _read_regular(path)
    parsed = RoundOrderManifest.model_validate_json(raw)
    if canonical_json_bytes(parsed.model_dump(mode="json")) != raw:
        raise CatalogReadinessError("round-order manifest bytes are not canonical")
    return parsed


def _ordered_manifests(
    *,
    repo_root: Path,
    ordered: RoundOrderManifest,
) -> tuple[CatalogRoundManifest, ...]:
    manifests: list[CatalogRoundManifest] = []
    for entry in ordered.entries:
        root = (repo_root / entry.round_root).resolve(strict=True)
        if root.name != entry.round_id:
            raise CatalogReadinessError("ordered round root and ID differ")
        manifest = _load_round_manifest(root / ROUND_MANIFEST_NAME)
        if (
            manifest.manifest_sha256 != entry.round_manifest_sha256
            or manifest.round_id != entry.round_id
            or manifest.round_root != entry.round_root
        ):
            raise CatalogReadinessError("ordered round manifest hash or identity drifted")
        rebuilt = _build_round_manifest(
            repo_root=repo_root,
            root=root,
            round_id=entry.round_id,
            previous_manifest_sha256=entry.parent_round_manifest_sha256,
            ancestry_depth=entry.ancestry_depth,
        )
        if rebuilt != manifest:
            raise CatalogReadinessError("round immutable tree differs from its manifest")
        manifests.append(manifest)
    if build_round_order_manifest(tuple(manifests)) != ordered:
        raise CatalogReadinessError("round-order manifest differs from ancestry replay")
    return tuple(manifests)


def _initialize_round_order(
    *,
    repo_root: Path,
    root: Path,
    round_id: str,
    target: Path,
) -> RoundOrderManifest:
    if target.resolve(strict=False) != root / ROUND_ORDER_NAME:
        raise CatalogReadinessError("round-order target must be beneath selected round")
    sidecar = EnrichmentEvidenceSidecar.model_validate_json(
        _read_regular(root / "evidence-sidecars.json")
    )
    previous_manifests: tuple[CatalogRoundManifest, ...] = ()
    previous_sha256: str | None = None
    if sidecar.ancestry_depth > 1:
        plan = json.loads(_read_regular(root / "enrichment-plan.json"))
        remediation = plan.get("remediation")
        if not isinstance(remediation, dict):
            raise CatalogReadinessError("remediation round lacks explicit ancestry")
        previous_ref = remediation.get("previous_round_ref")
        if not isinstance(previous_ref, dict):
            raise CatalogReadinessError("remediation round lacks previous reference")
        previous_root_value = previous_ref.get("round_root")
        if not isinstance(previous_root_value, str):
            raise CatalogReadinessError("previous round root is invalid")
        previous_root = (repo_root / previous_root_value).resolve(strict=True)
        previous_order = _load_order_manifest(previous_root / ROUND_ORDER_NAME)
        previous_manifests = _ordered_manifests(
            repo_root=repo_root,
            ordered=previous_order,
        )
        previous_sha256 = previous_manifests[-1].manifest_sha256
    manifest = _build_round_manifest(
        repo_root=repo_root,
        root=root,
        round_id=round_id,
        previous_manifest_sha256=previous_sha256,
        ancestry_depth=sidecar.ancestry_depth,
    )
    ordered = build_round_order_manifest((*previous_manifests, manifest))
    manifest_payload = _manifest_bytes(manifest)
    ordered_payload = canonical_json_bytes(ordered.model_dump(mode="json"))
    second_manifest = _build_round_manifest(
        repo_root=repo_root,
        root=root,
        round_id=round_id,
        previous_manifest_sha256=previous_sha256,
        ancestry_depth=sidecar.ancestry_depth,
    )
    if manifest != second_manifest or manifest_payload != _manifest_bytes(second_manifest):
        raise CatalogReadinessError("independent round-manifest builds differ")
    _publish_bundle(
        (root / ROUND_MANIFEST_NAME, target),
        (manifest_payload, ordered_payload),
    )
    return ordered


def _actual_aggregate(
    *,
    repo_root: Path,
    root: Path,
    round_id: str,
    manifest_path: Path,
    require_objective_eligible: int,
    max_human_decisions: int,
) -> AggregateReadiness:
    ordered = _load_order_manifest(manifest_path)
    if (
        ordered.newest_round_id != round_id
        or (repo_root / ordered.newest_round_root).resolve(strict=True) != root
    ):
        raise CatalogReadinessError("explicit newest round differs from ordered manifest")
    _ordered_manifests(repo_root=repo_root, ordered=ordered)
    _, _, rebuilt_readiness, _ = _build_all(repo_root)
    recorded_readiness = CatalogReadinessReport.model_validate_json(
        _read_regular(repo_root / READINESS_TARGET)
    )
    if rebuilt_readiness != recorded_readiness:
        raise CatalogReadinessError("base readiness differs from full policy replay")
    policy_path = repo_root / ENTITY_POLICY_PATH
    policy_raw = _read_regular(policy_path)
    policy = EntityPolicyReport.model_validate_json(policy_raw)
    if (
        _sha256(policy_raw) != recorded_readiness.parents.entity_policy_file_sha256
        or policy.formal_policy_sha256 != formal_policy_sha256()
        or policy.counts.crosswalk_total != 718
        or policy.counts.crosswalk_automatic != 715
        or policy.counts.crosswalk_unresolved != 3
        or policy.counts.relationship_total != 874
        or policy.counts.relationship_automatic != 871
        or policy.counts.relationship_unresolved != 3
        or policy.counts.media_attachment_count != 8
        or policy.counts.cross_provider_place_auto_link_count != 0
    ):
        raise CatalogReadinessError("entity-policy exact counts or hashes drifted")
    sidecars: list[EnrichmentEvidenceSidecar] = []
    for entry in ordered.entries:
        sidecar_path = repo_root / entry.round_root / "evidence-sidecars.json"
        raw = _read_regular(sidecar_path)
        if _sha256(raw) != entry.sidecar_file_sha256:
            raise CatalogReadinessError("ordered sidecar file hash drifted")
        sidecars.append(EnrichmentEvidenceSidecar.model_validate_json(raw))
    return build_aggregate_readiness(
        base_readiness=recorded_readiness,
        entity_policy=policy,
        ordered_manifest=ordered,
        sidecars=tuple(sidecars),
        require_objective_eligible=require_objective_eligible,
        max_human_decisions=max_human_decisions,
    )


def _remediation_parents(
    *,
    repo_root: Path,
    aggregate: AggregateReadiness,
    aggregate_bytes: bytes,
) -> dict[str, object]:
    base = CatalogReadinessReport.model_validate_json(_read_regular(repo_root / READINESS_TARGET))
    return {
        "readiness_file_sha256": _sha256(aggregate_bytes),
        "readiness_report_sha256": aggregate.aggregate_sha256,
        "readiness_rows_root": aggregate.rows_root,
        "entity_policy_report_sha256": aggregate.entity_policy_report_sha256,
        "formal_policy_sha256": aggregate.formal_policy_sha256,
        "catalog_v1_tree_sha256": base.parents.catalog_v1_tree_sha256,
        "protected_inputs_sha256": aggregate.protected_inputs_sha256,
        "complete_dispositions_root": aggregate.complete_dispositions_root,
        "media_attachments_root": aggregate.media_attachments_root,
        "rights_projection_file_sha256": base.parents.rights_projection_file_sha256,
        "rights_projection_sha256": base.parents.rights_projection_sha256,
        "aggregate_file_sha256": _sha256(aggregate_bytes),
        "aggregate_sha256": aggregate.aggregate_sha256,
        "ordered_round_manifest_sha256": aggregate.ordered_round_manifest_sha256,
    }


def _build_remediation_bundle(
    *,
    repo_root: Path,
    root: Path,
    current_manifest: CatalogRoundManifest,
    aggregate: AggregateReadiness,
    aggregate_bytes: bytes,
) -> tuple[RemediationCandidatePool, object, dict[str, object]]:
    parents = _remediation_parents(
        repo_root=repo_root,
        aggregate=aggregate,
        aggregate_bytes=aggregate_bytes,
    )
    pool = build_remediation_candidate_pool(
        aggregate,
        parents=parents,
    )
    previous_ref = {
        "round_id": current_manifest.round_id,
        "round_root": current_manifest.round_root,
        "round_manifest_sha256": current_manifest.manifest_sha256,
        "ancestry_depth": current_manifest.ancestry_depth,
    }
    previous_ref_sha256 = canonical_sha256(previous_ref)
    remediation = {
        "schema_version": "itda.catalog-enrichment-remediation-report.v1",
        "aggregate_sha256": aggregate.aggregate_sha256,
        "aggregate_file_sha256": _sha256(aggregate_bytes),
        "previous_round_ref": previous_ref,
        "previous_round_ref_sha256": previous_ref_sha256,
        "exact_deficits_sha256": canonical_sha256(
            [row.model_dump(mode="json") for row in pool.rows]
        ),
        "attempted_provider_ids_root": aggregate.attempted_provider_ids_root,
        "frontier_count": pool.pool_count,
        "frontier_rows_root": pool.rows_root,
        "rights_refs": {
            "formal_policy_sha256": aggregate.formal_policy_sha256,
            "entity_policy_report_sha256": aggregate.entity_policy_report_sha256,
            "complete_dispositions_root": aggregate.complete_dispositions_root,
            "media_attachments_root": aggregate.media_attachments_root,
        },
        "diagnostics_policy": {
            "d13_addressable_terminal_records": True,
            "forbid_secret_or_raw_body_in_logs": True,
        },
        "resume_rules": {
            "d14_skip_only_verified_success": True,
            "partial_completion_is_not_authority": True,
        },
        "attempt_budget": {
            "d15_per_attempt_timeout_seconds": 300,
            "maximum_attempts": 3,
            "global_timeout_policy": "no-shorter-global-timeout",
        },
        "authority_policy": {
            "automatic_authorization": False,
            "inherit_prior_authority": False,
            "reuse_request": False,
            "reuse_state": False,
            "reuse_target": False,
            "reuse_binding": False,
            "reuse_nonce": False,
        },
    }
    plan = build_enrichment_plan(
        pool.model_dump(mode="json"),
        attempts=3,
        remediation=remediation,
    )
    plan_bytes = canonical_json_bytes(plan)
    round_id = _sha256(plan_bytes)
    child_root = root.parent / round_id
    now = datetime.now(UTC)
    code_hash = canonical_sha256(
        {
            "catalog_readiness.py": _sha256(
                _read_regular(repo_root / "backend/src/itda/contracts/catalog_readiness.py")
            ),
            "audit_catalog_readiness.py": _sha256(
                _read_regular(repo_root / "backend/src/itda/cli/audit_catalog_readiness.py")
            ),
            "catalog_enrichment.py": _sha256(
                _read_regular(repo_root / "backend/src/itda/contracts/catalog_enrichment.py")
            ),
        }
    )
    config_hash = _sha256(_read_regular(repo_root / ".planning/config.json"))
    frozen = FrozenEnrichmentIssuance(
        issued_at=now,
        expires_at=now + timedelta(hours=24),
        nonce=secrets.token_hex(32),
        reviewer_id="phase2-operator",
        code_sha256=code_hash,
        config_sha256=config_hash,
        permission_evidence_sha256=_sha256(canonical_json_bytes(plan["permission_evidence"])),
        previous_round_ref_sha256=previous_ref_sha256,
    )
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=child_root,
        round_id=round_id,
        frozen=frozen,
    )
    second = build_enrichment_bundle(
        plan=plan,
        round_root=child_root,
        round_id=round_id,
        frozen=frozen,
    )
    if bundle != second:
        raise CatalogReadinessError("fresh remediation authority builds differ")
    previous_request = json.loads(_read_regular(root / "enrichment-authorization-request.json"))
    request = bundle.authorization_request
    for field in (
        "request_sha256",
        "state_attestation_sha256",
        "target_sha256",
        "binding_sha256",
        "nonce",
    ):
        if request[field] == previous_request.get(field):
            raise CatalogReadinessError(f"remediation reused prior {field}")
    reference = {
        "schema_version": "itda.catalog-remediation-round-ref.v1",
        "round_id": round_id,
        "round_root": _round_value(repo_root, child_root),
        "remediation_report_sha256": round_id,
        "request_plan_sha256": round_id,
        "state_attestation_file_sha256": _sha256(bundle.state_bytes),
        "authorization_request_file_sha256": _sha256(bundle.request_bytes),
        "binding_sha256": request["binding_sha256"],
        "nonce_sha256": _sha256(str(request["nonce"]).encode("ascii")),
        "previous_round_manifest_sha256": current_manifest.manifest_sha256,
        "candidate_count": pool.pool_count,
        "request_count": plan["request_count"],
        "quota_estimate": plan["quota_estimate"],
        "overall_timeout_seconds": plan["overall_timeout_seconds"],
    }
    reference["reference_sha256"] = canonical_sha256(reference)
    return pool, bundle, reference


def _validated_remediation_reference(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CatalogReadinessError("remediation round reference must be an object")
    reference = dict(value)
    unsigned = dict(reference)
    recorded_ref_sha = unsigned.pop("reference_sha256", None)
    if recorded_ref_sha != canonical_sha256(unsigned):
        raise CatalogReadinessError("remediation round reference hash drifted")
    return reference


def _build_remediation_supersession(
    *,
    superseded_reference: dict[str, object],
    replacement_reference: dict[str, object],
) -> dict[str, object]:
    superseded = _validated_remediation_reference(superseded_reference)
    replacement = _validated_remediation_reference(replacement_reference)
    if superseded["round_id"] == replacement["round_id"]:
        raise CatalogReadinessError("replacement remediation round must be fresh")
    for field in (
        "request_plan_sha256",
        "state_attestation_file_sha256",
        "authorization_request_file_sha256",
        "binding_sha256",
        "nonce_sha256",
    ):
        if superseded[field] == replacement[field]:
            raise CatalogReadinessError(f"replacement remediation reused prior {field}")
    payload: dict[str, object] = {
        "schema_version": "itda.catalog-remediation-round-supersession.v1",
        "reason_code": "INVALID_PROVIDER_ENDPOINT_PARAMETERS",
        "rejected_endpoint_parameters": [
            {
                "operation": "detailCommon2",
                "parameter": "addrinfoYN",
            },
            {
                "operation": "detailImage2",
                "parameter": "contentTypeId",
            },
        ],
        "superseded_reference": superseded,
        "replacement_reference": replacement,
        "authority_token_issued_or_consumed": False,
        "provider_call_performed": False,
    }
    payload["supersession_sha256"] = canonical_sha256(payload)
    return payload


def _publish_remediation(
    *,
    repo_root: Path,
    root: Path,
    pool: RemediationCandidatePool,
    bundle: object,
    reference: dict[str, object],
) -> None:
    child_root = bundle.round_root  # type: ignore[attr-defined]
    if child_root.exists():
        raise FileExistsError(f"remediation round already exists: {child_root}")
    child_root.mkdir(mode=0o700, exist_ok=False)
    created: list[Path] = []
    try:
        files = dict(bundle.files)  # type: ignore[attr-defined]
        files[REMEDIATION_POOL_NAME] = canonical_json_bytes(pool.model_dump(mode="json"))
        files[REMEDIATION_REPORT_NAME] = bundle.plan_bytes  # type: ignore[attr-defined]
        for name, payload in files.items():
            target = child_root / name
            _exclusive_file(target, payload)
            created.append(target)
        _exclusive_file(
            root / REMEDIATION_REF_NAME,
            canonical_json_bytes(reference),
        )
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if child_root.exists() and not any(child_root.iterdir()):
            child_root.rmdir()
        raise


def _publish_remediation_replacement(
    *,
    root: Path,
    pool: RemediationCandidatePool,
    bundle: object,
    supersession: dict[str, object],
) -> None:
    child_root = bundle.round_root  # type: ignore[attr-defined]
    target = root / REMEDIATION_SUPERSESSION_NAME
    if child_root.exists():
        raise FileExistsError(f"remediation round already exists: {child_root}")
    if target.exists():
        raise FileExistsError(f"remediation supersession already exists: {target}")
    recorded = _validated_remediation_reference(
        json.loads(_read_regular(root / REMEDIATION_REF_NAME))
    )
    if supersession.get("superseded_reference") != recorded:
        raise CatalogReadinessError("supersession does not bind the recorded remediation")
    child_root.mkdir(mode=0o700, exist_ok=False)
    created: list[Path] = []
    try:
        files = dict(bundle.files)  # type: ignore[attr-defined]
        files[REMEDIATION_POOL_NAME] = canonical_json_bytes(pool.model_dump(mode="json"))
        files[REMEDIATION_REPORT_NAME] = bundle.plan_bytes  # type: ignore[attr-defined]
        for name, payload in files.items():
            child_target = child_root / name
            _exclusive_file(child_target, payload)
            created.append(child_target)
        _exclusive_file(target, canonical_json_bytes(supersession))
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        if child_root.exists() and not any(child_root.iterdir()):
            child_root.rmdir()
        raise


def _verify_remediation_reference(
    *,
    repo_root: Path,
    root: Path,
    current_manifest: CatalogRoundManifest,
    aggregate: AggregateReadiness,
    reference: dict[str, object],
) -> dict[str, object]:
    reference = _validated_remediation_reference(reference)
    round_id = str(reference.get("round_id", ""))
    child_root_value = reference.get("round_root")
    if not isinstance(child_root_value, str):
        raise CatalogReadinessError("remediation child root is invalid")
    child_root = (repo_root / child_root_value).resolve(strict=True)
    if child_root.name != round_id or child_root.parent != root.parent:
        raise CatalogReadinessError("remediation child escapes selected rounds")
    plan_path = child_root / "enrichment-plan.json"
    state_path = child_root / "enrichment-state-attestation.json"
    request_path = child_root / "enrichment-authorization-request.json"
    verify_enrichment_bundle(
        plan_path,
        state_path,
        request_path,
        round_root=child_root,
        round_id=round_id,
    )
    plan_raw = _read_regular(plan_path)
    if (
        _sha256(plan_raw) != round_id
        or _read_regular(child_root / REMEDIATION_REPORT_NAME) != plan_raw
        or reference.get("remediation_report_sha256") != round_id
        or reference.get("request_plan_sha256") != round_id
    ):
        raise CatalogReadinessError("remediation report and request-plan digest differ")
    plan = json.loads(plan_raw)
    remediation = plan.get("remediation")
    if not isinstance(remediation, dict):
        raise CatalogReadinessError("remediation plan lacks its canonical report")
    previous = remediation.get("previous_round_ref")
    if not isinstance(previous, dict) or previous != {
        "round_id": current_manifest.round_id,
        "round_root": current_manifest.round_root,
        "round_manifest_sha256": current_manifest.manifest_sha256,
        "ancestry_depth": current_manifest.ancestry_depth,
    }:
        raise CatalogReadinessError("remediation child ancestry drifted")
    pool = RemediationCandidatePool.model_validate_json(
        _read_regular(child_root / REMEDIATION_POOL_NAME)
    )
    expected_frontier = build_remediation_candidate_pool(
        aggregate,
        parents=pool.parents,
    )
    if pool != expected_frontier:
        raise CatalogReadinessError("remediation frontier differs from aggregate replay")
    if any(
        (child_root / name).exists()
        for name in (
            "enrichment-authorization-receipt.json",
            "enrichment-collection-report.json",
            "enrichment-collection-log.jsonl",
            "catalog-review.json",
            "catalog-approval.json",
        )
    ):
        raise CatalogReadinessError("remediation child contains unauthorized output")
    return reference


def _verify_remediation_outcome(
    *,
    repo_root: Path,
    root: Path,
    current_manifest: CatalogRoundManifest,
    aggregate: AggregateReadiness,
) -> dict[str, object]:
    recorded = _validated_remediation_reference(
        json.loads(_read_regular(root / REMEDIATION_REF_NAME))
    )
    _verify_remediation_reference(
        repo_root=repo_root,
        root=root,
        current_manifest=current_manifest,
        aggregate=aggregate,
        reference=recorded,
    )
    supersession_path = root / REMEDIATION_SUPERSESSION_NAME
    if not supersession_path.exists():
        return recorded
    supersession = json.loads(_read_regular(supersession_path))
    if not isinstance(supersession, dict):
        raise CatalogReadinessError("remediation supersession must be an object")
    unsigned = dict(supersession)
    recorded_sha256 = unsigned.pop("supersession_sha256", None)
    if recorded_sha256 != canonical_sha256(unsigned):
        raise CatalogReadinessError("remediation supersession hash drifted")
    if (
        supersession.get("schema_version") != "itda.catalog-remediation-round-supersession.v1"
        or supersession.get("reason_code") != "INVALID_PROVIDER_ENDPOINT_PARAMETERS"
        or supersession.get("superseded_reference") != recorded
        or supersession.get("authority_token_issued_or_consumed") is not False
        or supersession.get("provider_call_performed") is not False
    ):
        raise CatalogReadinessError("remediation supersession binding drifted")
    replacement = _validated_remediation_reference(supersession.get("replacement_reference"))
    return _verify_remediation_reference(
        repo_root=repo_root,
        root=root,
        current_manifest=current_manifest,
        aggregate=aggregate,
        reference=replacement,
    )


def _quota_artifacts_for_aggregate(
    *,
    repo_root: Path,
    aggregate: AggregateReadiness,
) -> tuple[RepresentationQuotaConfig, RepresentationQuotaAttestation]:
    rules = RepresentationGroupRules.model_validate_json(_read_regular(repo_root / RULES_TARGET))
    eligible_rows = tuple(row for row in aggregate.rows if row.objective_eligible)
    eligible_pool_sha256 = canonical_sha256([row.model_dump(mode="json") for row in eligible_rows])
    missing_assignments = sum(
        row.objective_eligible and row.representation_assignment_status == "MISSING"
        for row in aggregate.rows
    )
    ambiguous_assignments = sum(
        row.objective_eligible and row.representation_assignment_status == "AMBIGUOUS"
        for row in aggregate.rows
    )
    return build_representation_quota_artifacts(
        eligible_pool_sha256=eligible_pool_sha256,
        representation_rule_sha256=rules.rule_table_sha256,
        raw_eligible_group_counts=aggregate.eligible_group_counts,
        missing_assignment_count=missing_assignments,
        ambiguous_assignment_count=ambiguous_assignments,
    )


def _only_direct_kto_digest_root(base: Path, *, label: str) -> Path:
    if base.is_symlink() or not base.is_dir():
        raise CatalogReadinessError(f"{label} base must be a no-follow directory")
    entries = list(base.iterdir())
    roots = [
        entry.resolve(strict=True)
        for entry in entries
        if not entry.is_symlink()
        and entry.is_dir()
        and len(entry.name) == 64
        and all(character in "0123456789abcdef" for character in entry.name)
    ]
    if len(entries) != 1 or len(roots) != 1:
        raise CatalogReadinessError(f"expected exactly one direct {label} root")
    return roots[0]


def _kto_candidate_names(entity_projection: Mapping[str, object]) -> dict[str, str]:
    records = entity_projection.get("dataset_records")
    if not isinstance(records, list):
        raise CatalogReadinessError("entity projection lacks dataset records")
    names: dict[str, str] = {}
    for value in records:
        if not isinstance(value, Mapping):
            raise CatalogReadinessError("entity projection contains a non-object record")
        candidate_id = value.get("source_candidate_id")
        name = value.get("name_ko")
        if not isinstance(candidate_id, str) or not isinstance(name, str):
            raise CatalogReadinessError("entity projection candidate identity is invalid")
        if candidate_id in names and names[candidate_id] != name:
            raise CatalogReadinessError("candidate identity has conflicting Korean names")
        names[candidate_id] = name
    return names


def build_kto_recovery_readiness(
    repository_root: Path | str,
) -> KtoRecoveryReadiness:
    """Replay exact Plan 49 target and complete-universe readiness offline."""

    root = Path(repository_root).resolve(strict=True)
    normalization = build_kto_recovery_normalization(root)
    normalization_base = (root / KTO_NORMALIZATIONS_REL).resolve(strict=True)
    normalization_root = _only_direct_kto_digest_root(
        normalization_base,
        label="KTO normalization",
    )
    if normalization_root.name != normalization.normalization_root_sha256:
        raise CatalogReadinessError("published normalization differs from exact replay")
    _assert_private_directory(
        normalization_root,
        expected_files={"normalization.json"},
    )
    if (
        _read_regular(normalization_root / "normalization.json")
        != normalization.files["normalization.json"]
    ):
        raise CatalogReadinessError("published normalization bytes differ from replay")

    eligibility_root_value = normalization.payload.get("kto_eligibility_root")
    if not isinstance(eligibility_root_value, str):
        raise CatalogReadinessError("normalization lacks exact eligibility ancestry")
    eligibility_root = (root / KTO_ELIGIBILITY_REL / eligibility_root_value).resolve(strict=True)
    request_manifest, request_manifest_sha256 = _read_regular_json(
        eligibility_root / "request-manifest.json"
    )
    if request_manifest_sha256 != normalization.request_manifest_sha256:
        raise CatalogReadinessError("request manifest differs from normalization ancestry")

    aggregate, aggregate_file_sha256 = _read_regular_json(
        (root / KTO_AGGREGATE_REL).resolve(strict=True)
    )
    entity_projection, entity_projection_file_sha256 = _read_regular_json(
        (root / KTO_ENTITY_PROJECTION_REL).resolve(strict=True)
    )
    normalization_payload = {
        **normalization.payload,
        "kto_normalization_root": normalization.normalization_root_sha256,
    }
    aggregate_payload = {
        **aggregate,
        "aggregate_readiness_file_sha256": aggregate_file_sha256,
        "entity_projection_file_sha256": entity_projection_file_sha256,
    }
    return derive_kto_recovery_readiness(
        normalization=normalization_payload,
        aggregate=aggregate_payload,
        request_manifest=request_manifest,
        candidate_names=_kto_candidate_names(entity_projection),
    )


def _publish_or_verify_kto_root(
    *,
    destination: Path,
    filename: str,
    payload: bytes,
    temporary_prefix: str,
) -> None:
    if destination.exists():
        _assert_private_directory(destination, expected_files={filename})
        if _read_regular(destination / filename) != payload:
            raise CatalogReadinessError("existing KTO readiness root differs from replay")
        return
    _publish_private_files(
        destination=destination,
        files={filename: payload},
        temporary_prefix=temporary_prefix,
    )
    _assert_private_directory(destination, expected_files={filename})
    if _read_regular(destination / filename) != payload:
        raise CatalogReadinessError("published KTO readiness root differs from replay")


def publish_kto_recovery_readiness(
    generation: KtoRecoveryReadiness,
    *,
    repository_root: Path | str,
    substitutions_base: Path | str | None = None,
    reentries_base: Path | str | None = None,
    preflight_base: Path | str | None = None,
) -> PublishedKtoRecoveryReadiness:
    """Publish one double-replayed private KTO readiness generation."""

    root = Path(repository_root).resolve(strict=True)
    rebuilt = build_kto_recovery_readiness(root)
    if generation != rebuilt:
        raise CatalogReadinessError("caller-supplied KTO readiness was patched")
    substitutions = (
        root / KTO_SUBSTITUTIONS_REL
        if substitutions_base is None
        else Path(substitutions_base).expanduser().resolve()
    )
    preflight = (
        root / KTO_PREFLIGHT_REL
        if preflight_base is None
        else Path(preflight_base).expanduser().resolve()
    )
    if reentries_base is None and substitutions_base is not None:
        reentries = substitutions.parent / "reentries"
    else:
        reentries = (
            root / KTO_REENTRIES_REL
            if reentries_base is None
            else Path(reentries_base).expanduser().resolve()
        )
    substitution_root = substitutions / generation.substitution_root_sha256
    reentry_root = reentries / generation.reentry_root_sha256
    preflight_root = preflight / generation.preflight_root_sha256
    publications = (
        (
            substitution_root,
            "substitution-frontier.json",
            {
                "payload": generation.substitution_payload,
                "substitution_root_sha256": generation.substitution_root_sha256,
            },
            ".kto-substitution-",
        ),
        (
            reentry_root,
            "reentry-disposition.json",
            {
                "payload": generation.reentry_payload,
                "reentry_root_sha256": generation.reentry_root_sha256,
            },
            ".kto-reentry-",
        ),
        (
            preflight_root,
            "preflight-readiness.json",
            {
                "payload": generation.preflight_payload,
                "preflight_root_sha256": generation.preflight_root_sha256,
            },
            ".kto-preflight-",
        ),
    )
    for destination, filename, value, prefix in publications:
        _publish_or_verify_kto_root(
            destination=destination,
            filename=filename,
            payload=canonical_json_bytes(value),
            temporary_prefix=prefix,
        )
    return PublishedKtoRecoveryReadiness(
        substitution_root=substitution_root,
        reentry_root=reentry_root,
        preflight_root=preflight_root,
    )


def build_kto_recovery_terminal_failure(
    repository_root: Path | str,
    *,
    resume_signal: str,
) -> KtoRecoveryTerminalFailure:
    """Bind one exact rejection to the immutable exhausted KTO frontier."""

    root = Path(repository_root).resolve(strict=True)
    expected_signal = "reject-kto-substitutions:evidence-frontier-exhausted"
    if resume_signal != expected_signal:
        raise CatalogReadinessError("resume signal does not reject the exact exhausted frontier")
    readiness = build_kto_recovery_readiness(root)
    if (
        readiness.outcome != "BLOCKED"
        or readiness.outcome_reason != "EVIDENCE_FRONTIER_EXHAUSTED"
        or readiness.unresolved_count == 0
        or readiness.substitute_rows
        or readiness.reentry_ordinal != 0
        or readiness.reentry_disposition
        != {
            "required": False,
            "reentry_ordinal": 0,
            "request_packet": None,
            "reason": "EVIDENCE_FRONTIER_EXHAUSTED",
        }
        or readiness.plan50_reachable
    ):
        raise CatalogReadinessError("KTO frontier is not terminally exhausted")
    expected_publications = (
        (
            root / KTO_SUBSTITUTIONS_REL / readiness.substitution_root_sha256,
            "substitution-frontier.json",
            {
                "payload": readiness.substitution_payload,
                "substitution_root_sha256": readiness.substitution_root_sha256,
            },
        ),
        (
            root / KTO_REENTRIES_REL / readiness.reentry_root_sha256,
            "reentry-disposition.json",
            {
                "payload": readiness.reentry_payload,
                "reentry_root_sha256": readiness.reentry_root_sha256,
            },
        ),
        (
            root / KTO_PREFLIGHT_REL / readiness.preflight_root_sha256,
            "preflight-readiness.json",
            {
                "payload": readiness.preflight_payload,
                "preflight_root_sha256": readiness.preflight_root_sha256,
            },
        ),
    )
    for publication_root, filename, expected_value in expected_publications:
        _assert_private_directory(publication_root, expected_files={filename})
        if _read_regular(publication_root / filename) != canonical_json_bytes(expected_value):
            raise CatalogReadinessError("published KTO parent differs from exact replay")
    ancestry = readiness.preflight_payload.get("ancestry")
    if not isinstance(ancestry, dict):
        raise CatalogReadinessError("KTO preflight lacks immutable ancestry")
    payload: dict[str, object] = {
        "schema_version": "itda.kto-recovery-terminal-failure.v1",
        "status": "REENTRY_EXHAUSTED",
        "outcome_code": 21,
        "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
        "terminal": True,
        "decision": {
            "action": "reject-kto-substitutions",
            "reason": "evidence-frontier-exhausted",
            "resume_signal": expected_signal,
            "resume_signal_sha256": canonical_sha256({"resume_signal": expected_signal}),
        },
        "parents": {
            **ancestry,
            "substitution_root_sha256": readiness.substitution_root_sha256,
            "reentry_disposition_root_sha256": readiness.reentry_root_sha256,
            "preflight_root_sha256": readiness.preflight_root_sha256,
            "target_replay_sha256": readiness.target_replay_sha256,
            "universe_replay_sha256": readiness.universe_replay_sha256,
            "decision_accounting_sha256": readiness.decision_accounting_sha256,
            "representation_quota_attestation_sha256": (
                readiness.representation_quota_attestation_sha256
            ),
        },
        "unresolved_count": readiness.unresolved_count,
        "frontier_count": len(readiness.frontier_rows),
        "substitute_count": len(readiness.substitute_rows),
        "reentry_ordinal": 0,
        "reentry_collection_root_sha256": None,
        "summary_permitted": False,
        "plan50_reachable": False,
        "external_effects": {
            "network_performed": False,
            "credential_read": False,
            "authority_issued_or_consumed": False,
            "nonce_created_or_consumed": False,
            "provider_collection_performed": False,
        },
        "capabilities": {
            "collection": False,
            "rights_waiver": False,
            "canonical_membership": False,
            "split_membership": False,
            "schema_mutation": False,
            "seal": False,
        },
    }
    return KtoRecoveryTerminalFailure(
        terminal_root_sha256=canonical_sha256(payload),
        payload=payload,
    )


def publish_kto_recovery_terminal_failure(
    generation: KtoRecoveryTerminalFailure,
    *,
    repository_root: Path | str,
    resume_signal: str,
    output_base: Path | str | None = None,
) -> Path:
    """Publish one immutable Summary-free terminal KTO failure record."""

    root = Path(repository_root).resolve(strict=True)
    rebuilt = build_kto_recovery_terminal_failure(
        root,
        resume_signal=resume_signal,
    )
    if generation != rebuilt:
        raise CatalogReadinessError("caller-supplied KTO terminal failure was patched")
    base = (
        root / KTO_REENTRIES_REL
        if output_base is None
        else Path(output_base).expanduser().resolve()
    )
    destination = base / generation.terminal_root_sha256
    _publish_or_verify_kto_root(
        destination=destination,
        filename="reentry-exhausted.json",
        payload=generation.files["reentry-exhausted.json"],
        temporary_prefix=".kto-reentry-exhausted-",
    )
    return destination


def kto_recovery_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay exact offline KTO readiness")
    parser.add_argument("--repo-root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build-kto-recovery", action="store_true")
    mode.add_argument("--verify-kto-recovery", action="store_true")
    mode.add_argument("--apply-kto-resume-signal")
    parser.add_argument("--discover-exact-success-under", type=Path)
    parser.add_argument("--require-zero-unresolved", action="store_true")
    return parser


def _run_kto_recovery(argv: list[str]) -> int:
    args = kto_recovery_parser().parse_args(argv)
    root = args.repo_root.resolve(strict=True)
    generation = build_kto_recovery_readiness(root)
    published = publish_kto_recovery_readiness(
        generation,
        repository_root=root,
    )
    if args.apply_kto_resume_signal is not None:
        if args.discover_exact_success_under is not None or args.require_zero_unresolved:
            raise CatalogReadinessError(
                "terminal rejection does not accept readiness-success options"
            )
        terminal = build_kto_recovery_terminal_failure(
            root,
            resume_signal=args.apply_kto_resume_signal,
        )
        terminal_root = publish_kto_recovery_terminal_failure(
            terminal,
            repository_root=root,
            resume_signal=args.apply_kto_resume_signal,
        )
        print(
            canonical_json_bytes(
                {
                    "status": "REENTRY_EXHAUSTED",
                    "outcome_code": 21,
                    "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
                    "terminal_root_sha256": terminal.terminal_root_sha256,
                    "terminal_root": str(terminal_root),
                    "unresolved_count": generation.unresolved_count,
                    "reentry_ordinal": 0,
                    "summary_permitted": False,
                    "plan50_reachable": False,
                }
            ).decode("utf-8"),
            end="",
        )
        return 21
    if args.build_kto_recovery:
        if args.discover_exact_success_under is not None:
            raise CatalogReadinessError("build mode does not accept exact-success discovery")
    else:
        if args.discover_exact_success_under is None:
            raise CatalogReadinessError("verify mode requires --discover-exact-success-under")
        expected_base = (root / KTO_PREFLIGHT_REL).resolve(strict=True)
        requested_base = args.discover_exact_success_under.resolve(strict=True)
        if requested_base != expected_base:
            raise CatalogReadinessError(
                "exact-success discovery is outside the fixed preflight base"
            )
        discovered = _only_direct_kto_digest_root(
            requested_base,
            label="KTO preflight readiness",
        )
        if discovered != published.preflight_root.resolve(strict=True):
            raise CatalogReadinessError("discovered preflight differs from exact replay")
    output = {
        "verified": bool(args.verify_kto_recovery),
        "status": generation.outcome,
        "outcome_reason": generation.outcome_reason,
        "target_count": generation.target_count,
        "unresolved_count": generation.unresolved_count,
        "universe_count": generation.universe_count,
        "objective_eligible_count": generation.objective_eligible_count,
        "representation_feasible": generation.representation_feasible,
        "substitution_root_sha256": generation.substitution_root_sha256,
        "reentry_root_sha256": generation.reentry_root_sha256,
        "reentry_ordinal": generation.reentry_ordinal,
        "preflight_root_sha256": generation.preflight_root_sha256,
        "plan50_reachable": generation.plan50_reachable,
    }
    print(canonical_json_bytes(output).decode("utf-8"), end="")
    if args.require_zero_unresolved and generation.unresolved_count != 0:
        return 20
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round-root", type=Path)
    parser.add_argument("--round-id")
    parser.add_argument("--round-roots-manifest", type=Path)
    parser.add_argument("--initialize-round-order-manifest", type=Path)
    parser.add_argument("--check-after", type=Path)
    parser.add_argument("--require-objective-eligible", type=int, default=36)
    parser.add_argument("--max-human-decisions", type=int, default=6)
    parser.add_argument("--issue-remediation-round", action="store_true")
    parser.add_argument("--replace-remediation-round", action="store_true")
    parser.add_argument("--verify-outcome", type=Path)
    parser.add_argument(
        "--build-all",
        nargs=4,
        type=Path,
        metavar=("RULES", "ASSIGNMENTS", "READINESS", "POOL"),
    )
    parser.add_argument(
        "--check-groups",
        nargs=2,
        type=Path,
        metavar=("RULES", "ASSIGNMENTS"),
    )
    parser.add_argument("--check-before", type=Path)
    parser.add_argument("--check-pool", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if any(
        option in raw_argv
        for option in (
            "--build-kto-recovery",
            "--verify-kto-recovery",
            "--apply-kto-resume-signal",
        )
    ):
        return _run_kto_recovery(raw_argv)
    args = _parser().parse_args(raw_argv)
    new_modes = sum(
        (
            args.initialize_round_order_manifest is not None,
            args.check_after is not None,
            args.verify_outcome is not None,
        )
    )
    if new_modes:
        if new_modes != 1:
            raise CatalogReadinessError("select exactly one round readiness mode")
        if args.round_root is None or args.round_id is None:
            raise CatalogReadinessError(
                "round readiness requires explicit --round-root and --round-id"
            )
        repo_root = fingerprint_catalog_v1._repo_root()
        root = _round_root(repo_root, args.round_root, args.round_id)
        if args.initialize_round_order_manifest is not None:
            ordered = _initialize_round_order(
                repo_root=repo_root,
                root=root,
                round_id=args.round_id,
                target=args.initialize_round_order_manifest.resolve(strict=False),
            )
            print(
                json.dumps(
                    {
                        "round_count": ordered.round_count,
                        "newest_round_id": ordered.newest_round_id,
                        "manifest_sha256": ordered.manifest_sha256,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.round_roots_manifest is None:
            raise CatalogReadinessError(
                "aggregate readiness requires explicit --round-roots-manifest"
            )
        manifest_path = args.round_roots_manifest.resolve(strict=True)
        if manifest_path != root / ROUND_ORDER_NAME:
            raise CatalogReadinessError(
                "round-roots manifest must be the selected newest-round manifest"
            )
        aggregate = _actual_aggregate(
            repo_root=repo_root,
            root=root,
            round_id=args.round_id,
            manifest_path=manifest_path,
            require_objective_eligible=args.require_objective_eligible,
            max_human_decisions=args.max_human_decisions,
        )
        aggregate_bytes = canonical_json_bytes(aggregate.model_dump(mode="json"))
        second = _actual_aggregate(
            repo_root=repo_root,
            root=root,
            round_id=args.round_id,
            manifest_path=manifest_path,
            require_objective_eligible=args.require_objective_eligible,
            max_human_decisions=args.max_human_decisions,
        )
        if aggregate != second or aggregate_bytes != canonical_json_bytes(
            second.model_dump(mode="json")
        ):
            raise CatalogReadinessError("independent aggregate builds differ")
        aggregate_target = root / AGGREGATE_NAME
        if args.check_after is not None:
            if args.check_after.resolve(strict=False) != aggregate_target:
                raise CatalogReadinessError(
                    "aggregate target must be beneath selected newest round"
                )
            if args.replace_remediation_round and not args.issue_remediation_round:
                raise CatalogReadinessError(
                    "remediation replacement requires --issue-remediation-round"
                )
            if args.replace_remediation_round and aggregate.outcome_code != 20:
                raise CatalogReadinessError(
                    "only an addressable remediation outcome may be replaced"
                )
            if aggregate.outcome_code == 20 and not args.issue_remediation_round:
                raise CatalogReadinessError(
                    "addressable shortfall requires --issue-remediation-round"
                )
            if aggregate.outcome_code == 20:
                current_manifest = _load_round_manifest(root / ROUND_MANIFEST_NAME)
                superseded_reference: dict[str, object] | None = None
                if args.replace_remediation_round:
                    if _read_regular(aggregate_target) != aggregate_bytes:
                        raise CatalogReadinessError(
                            "recorded aggregate readiness differs from full replay"
                        )
                    superseded_reference = _validated_remediation_reference(
                        json.loads(_read_regular(root / REMEDIATION_REF_NAME))
                    )
                    _verify_remediation_reference(
                        repo_root=repo_root,
                        root=root,
                        current_manifest=current_manifest,
                        aggregate=aggregate,
                        reference=superseded_reference,
                    )
                else:
                    _exclusive_file(aggregate_target, aggregate_bytes)
                pool, bundle, reference = _build_remediation_bundle(
                    repo_root=repo_root,
                    root=root,
                    current_manifest=current_manifest,
                    aggregate=aggregate,
                    aggregate_bytes=aggregate_bytes,
                )
                supersession: dict[str, object] | None = None
                if superseded_reference is None:
                    _publish_remediation(
                        repo_root=repo_root,
                        root=root,
                        pool=pool,
                        bundle=bundle,
                        reference=reference,
                    )
                else:
                    supersession = _build_remediation_supersession(
                        superseded_reference=superseded_reference,
                        replacement_reference=reference,
                    )
                    _publish_remediation_replacement(
                        root=root,
                        pool=pool,
                        bundle=bundle,
                        supersession=supersession,
                    )
                print(
                    json.dumps(
                        {
                            "outcome_code": 20,
                            "outcome_reason": aggregate.outcome_reason,
                            "objective_eligible_count": (aggregate.objective_eligible_count),
                            "human_decisions": (aggregate.human_identity_relationship_decisions),
                            "frontier_count": pool.pool_count,
                            "new_round_id": bundle.round_id,
                            "new_round_root": _round_value(
                                repo_root,
                                bundle.round_root,
                            ),
                            "replaces_round_id": (
                                None
                                if superseded_reference is None
                                else superseded_reference["round_id"]
                            ),
                            "supersession_sha256": (
                                None
                                if supersession is None
                                else supersession["supersession_sha256"]
                            ),
                        },
                        sort_keys=True,
                    )
                )
                return 20
            if aggregate.outcome_code == 0:
                config, attestation = _quota_artifacts_for_aggregate(
                    repo_root=repo_root,
                    aggregate=aggregate,
                )
                config_bytes = canonical_json_bytes(config.model_dump(mode="json"))
                attestation_bytes = canonical_json_bytes(attestation.model_dump(mode="json"))
                repeated = _quota_artifacts_for_aggregate(
                    repo_root=repo_root,
                    aggregate=aggregate,
                )
                if (config, attestation) != repeated:
                    raise CatalogReadinessError("independent representation quotas differ")
                _publish_bundle(
                    (
                        aggregate_target,
                        root / QUOTA_CONFIG_NAME,
                        root / QUOTA_ATTESTATION_NAME,
                    ),
                    (aggregate_bytes, config_bytes, attestation_bytes),
                )
                print(
                    json.dumps(
                        {
                            "outcome_code": attestation.outcome_code,
                            "outcome_reason": (
                                aggregate.outcome_reason
                                if attestation.feasible
                                else attestation.failure_reason
                            ),
                            "objective_eligible_count": (aggregate.objective_eligible_count),
                            "human_decisions": (aggregate.human_identity_relationship_decisions),
                            "quota_sum": attestation.quota_sum,
                        },
                        sort_keys=True,
                    )
                )
                return attestation.outcome_code
            _exclusive_file(aggregate_target, aggregate_bytes)
            print(
                json.dumps(
                    {
                        "outcome_code": aggregate.outcome_code,
                        "outcome_reason": aggregate.outcome_reason,
                        "objective_eligible_count": (aggregate.objective_eligible_count),
                        "human_decisions": (aggregate.human_identity_relationship_decisions),
                        "frontier_count": aggregate.addressable_frontier_count,
                    },
                    sort_keys=True,
                )
            )
            return aggregate.outcome_code
        assert args.verify_outcome is not None
        if args.verify_outcome.resolve(strict=True) != root:
            raise CatalogReadinessError("verification target must equal selected newest round")
        if _read_regular(aggregate_target) != aggregate_bytes:
            raise CatalogReadinessError("recorded aggregate readiness differs from full replay")
        reference: dict[str, object] | None = None
        quota: RepresentationQuotaAttestation | None = None
        if aggregate.outcome_code == 20:
            reference = _verify_remediation_outcome(
                repo_root=repo_root,
                root=root,
                current_manifest=_load_round_manifest(root / ROUND_MANIFEST_NAME),
                aggregate=aggregate,
            )
        else:
            if (root / REMEDIATION_REF_NAME).exists():
                raise CatalogReadinessError(
                    "non-remediation outcome contains a remediation reference"
                )
            if aggregate.outcome_code == 0:
                config, quota = _quota_artifacts_for_aggregate(
                    repo_root=repo_root,
                    aggregate=aggregate,
                )
                expected_quota = (
                    canonical_json_bytes(config.model_dump(mode="json")),
                    canonical_json_bytes(quota.model_dump(mode="json")),
                )
                recorded_quota = (
                    _read_regular(root / QUOTA_CONFIG_NAME),
                    _read_regular(root / QUOTA_ATTESTATION_NAME),
                )
                if recorded_quota != expected_quota:
                    raise CatalogReadinessError(
                        "recorded representation quota differs from full replay"
                    )
            elif any(
                (root / name).exists() for name in (QUOTA_CONFIG_NAME, QUOTA_ATTESTATION_NAME)
            ):
                raise CatalogReadinessError("non-ready outcome contains representation quota bytes")
        if any((root / name).exists() for name in ("catalog-review.json", "catalog-approval.json")):
            raise CatalogReadinessError("non-ready outcome contains catalog review bytes")
        print(
            json.dumps(
                {
                    "verified": True,
                    "outcome_code": (
                        aggregate.outcome_code if quota is None else quota.outcome_code
                    ),
                    "outcome_reason": (
                        aggregate.outcome_reason
                        if quota is None or quota.feasible
                        else quota.failure_reason
                    ),
                    "objective_eligible_count": aggregate.objective_eligible_count,
                    "human_decisions": (aggregate.human_identity_relationship_decisions),
                    "frontier_count": aggregate.addressable_frontier_count,
                    "remediation_round_id": (None if reference is None else reference["round_id"]),
                },
                sort_keys=True,
            )
        )
        return 0

    modes = sum(
        (
            args.build_all is not None,
            args.check_groups is not None,
            args.check_before is not None or args.check_pool is not None,
        )
    )
    if modes != 1 or ((args.check_before is None) != (args.check_pool is None)):
        raise CatalogReadinessError("select exactly one complete readiness mode")
    repo_root = fingerprint_catalog_v1._repo_root()
    built = _build_all(repo_root)
    payloads = tuple(canonical_json_bytes(item.model_dump(mode="json")) for item in built)
    if args.build_all is not None:
        expected = (
            RULES_TARGET,
            ASSIGNMENTS_TARGET,
            READINESS_TARGET,
            POOL_TARGET,
        )
        targets = tuple(
            _exact_target(repo_root, value, expected_path)
            for value, expected_path in zip(args.build_all, expected, strict=True)
        )
        second = _build_all(repo_root)
        second_payloads = tuple(
            canonical_json_bytes(item.model_dump(mode="json")) for item in second
        )
        if payloads != second_payloads:
            raise CatalogReadinessError("independent readiness builds differ")
        _publish_bundle(targets, payloads)
    elif args.check_groups is not None:
        targets = (
            _exact_target(repo_root, args.check_groups[0], RULES_TARGET),
            _exact_target(repo_root, args.check_groups[1], ASSIGNMENTS_TARGET),
        )
        if tuple(_read_regular(path) for path in targets) != payloads[:2]:
            raise CatalogReadinessError("recorded group artifacts differ from replay")
    else:
        assert args.check_before is not None and args.check_pool is not None
        targets = (
            _exact_target(repo_root, args.check_before, READINESS_TARGET),
            _exact_target(repo_root, args.check_pool, POOL_TARGET),
        )
        if tuple(_read_regular(path) for path in targets) != payloads[2:]:
            raise CatalogReadinessError("recorded readiness/pool differ from replay")
    print(built[0].rule_table_sha256)
    print(built[1].complete_assignment_sha256)
    print(built[2].report_sha256)
    print(built[3].pool_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
