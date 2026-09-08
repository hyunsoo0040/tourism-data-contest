"""Build and verify one immutable, network-free supplemental evidence generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itda.cli import fingerprint_catalog_v1
from itda.cli.freeze_preview import publish_immutable_directory
from itda.contracts.catalog_readiness import AggregateReadiness, RoundOrderManifest
from itda.contracts.catalog_rights_v2 import CandidateObjectiveEvidence
from itda.contracts.catalog_supplemental_evidence import (
    SupplementalManifestChild,
    build_supplemental_atom_set,
    build_supplemental_evidence_atom,
    build_supplemental_manifest,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

EVIDENCE_FRONTIER_EXHAUSTED = 21
NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW = 22
SUCCESSOR_REENTRY_REQUIRED = 20

SALVAGE_RELPATH = "artifacts/restricted/catalog/v2/supplemental/salvage"
TERMINAL_ROUND_ID = "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55"
TERMINAL_ROUND_RELPATH = (
    "artifacts/restricted/catalog/v2/enrichment/rounds/" + TERMINAL_ROUND_ID
)
TERMINAL_AGGREGATE_RELPATH = TERMINAL_ROUND_RELPATH + "/aggregate-readiness.json"
ROUND_ORDER_RELPATH = TERMINAL_ROUND_RELPATH + "/round-order-manifest.json"
OBJECTIVE_RELPATH = (
    "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
)
RIGHTS_RELPATH = "artifacts/restricted/catalog/v2/rights/rights-projection.json"
V1_MANIFEST_RELPATH = (
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json"
)
HISTORICAL_EQUIVALENCE_RELPATH = (
    "artifacts/restricted/catalog/v2/lineage/historical-verification-equivalence.json"
)
PREVIEW_MANIFEST_RELPATH = "fixtures/preview/v1/manifest.json"
PREVIEW_BUNDLE_RELPATH = "fixtures/preview/v1/review/raw-provider-bundle.redacted.json"
ROUND_MANIFEST_NAME = "supplemental-round-manifest.json"
CHILD_ORDER = (
    "prior-lineage-attestation.json",
    "supplemental-target-ledger.json",
    "supplemental-evidence-atoms.json",
    "supplemental-evidence-manifest.json",
)
PAYLOAD_KEYS = (
    "schema_version",
    "code_policy_identity",
    "ancestry",
    "terminal_aggregate",
    "non_authorizing_identities",
    "generation_state",
    "successor_disposition",
    "children",
)
IDENTITY_KEYS = (
    "request_sha256",
    "state_attestation_sha256",
    "target_sha256",
    "binding_sha256",
    "nonce_sha256",
)
FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "root_sha256",
        "round_id",
        "round_root",
        "manifest_sha256",
        "final_path",
        "directory_basename",
        "authority_token",
        "authority_receipt",
        "credential",
        "service_key",
    }
)
APPROVED_DEFICIT_OPERATIONS: dict[str, tuple[str, ...]] = {
    "COORDINATES_MISSING": ("detailCommon2",),
    "DESCRIPTION_MISSING": ("detailCommon2",),
    "DIRECT_MEDIA_MISSING": ("detailImage2",),
    "OPERATING_INFO_MISSING": ("detailCommon2",),
}
MAX_FILE_BYTES = 64 * 1024 * 1024
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class SupplementalEvidenceError(ValueError):
    """Raised when supplemental evidence cannot be replayed safely."""


@dataclass(frozen=True)
class SalvageGeneration:
    """One frozen, twice-buildable success generation."""

    round_id: str
    destination: Path
    children: dict[str, bytes]
    envelope: dict[str, object]
    protected_snapshot: dict[str, object]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, *, limit: int = MAX_FILE_BYTES) -> bytes:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SupplementalEvidenceError("input must be one single-link regular file")
    if before.st_size > limit:
        raise SupplementalEvidenceError("input exceeds the bounded read limit")
    descriptor = os.open(path, os.O_RDONLY | fingerprint_catalog_v1.O_NOFOLLOW)
    try:
        after = os.fstat(descriptor)
        fingerprint_catalog_v1._same_object(before, after)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > limit:
            raise SupplementalEvidenceError("input exceeds the bounded read limit")
        fingerprint_catalog_v1._same_state(after, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    return payload


def _load_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path)
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise SupplementalEvidenceError(f"non-canonical JSON input: {path}")
    return value, raw


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise SupplementalEvidenceError(f"JSON input must be an object: {path}")
    return value, raw


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write while publishing supplemental evidence")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_payload_shape(payload: Mapping[str, object]) -> None:
    forbidden = FORBIDDEN_PAYLOAD_KEYS.intersection(payload)
    if forbidden:
        raise SupplementalEvidenceError(
            f"forbidden self or authority field in round payload: {sorted(forbidden)}"
        )
    if set(payload) != set(PAYLOAD_KEYS):
        raise SupplementalEvidenceError("round payload keys drifted")
    identities = payload.get("non_authorizing_identities")
    if not isinstance(identities, dict) or set(identities) != set(IDENTITY_KEYS):
        raise SupplementalEvidenceError("non-authorizing identity envelope drifted")
    if any(
        not isinstance(value, str) or HEX_64.fullmatch(value) is None
        for value in identities.values()
    ):
        raise SupplementalEvidenceError("non-authorizing identities must be SHA-256 values")


def build_round_envelope(payload: Mapping[str, object]) -> dict[str, object]:
    """Derive the only current-generation identities from a self-excluding payload."""

    _assert_payload_shape(payload)
    payload_copy = {key: payload[key] for key in PAYLOAD_KEYS}
    identities = payload_copy["non_authorizing_identities"]
    assert isinstance(identities, dict)
    payload_copy["non_authorizing_identities"] = {
        key: identities[key] for key in IDENTITY_KEYS
    }
    root = _sha256(canonical_json_bytes(payload_copy))
    return {
        "payload": payload_copy,
        "root_sha256": root,
        "round_id": root,
    }


def _ancestry_hash_values(value: object) -> set[str]:
    hashes: set[str] = set()
    if isinstance(value, dict):
        for child in value.values():
            hashes.update(_ancestry_hash_values(child))
    elif isinstance(value, list):
        for child in value:
            hashes.update(_ancestry_hash_values(child))
    elif isinstance(value, str) and HEX_64.fullmatch(value):
        hashes.add(value)
    return hashes


def build_non_authorizing_identities(
    *,
    generation_seed: str,
    ancestry: Sequence[Mapping[str, object]],
) -> dict[str, str]:
    """Derive deterministic generation-local hashes distinct from all ancestors."""

    if HEX_64.fullmatch(generation_seed) is None:
        raise SupplementalEvidenceError("generation seed must be one SHA-256")
    prior = _ancestry_hash_values(list(ancestry))
    result: dict[str, str] = {}
    for index, name in enumerate(IDENTITY_KEYS):
        counter = 0
        while True:
            candidate = canonical_sha256(
                {
                    "schema_version": "itda.non-authorizing-supplemental-envelope.v1",
                    "generation_seed": generation_seed,
                    "identity_name": name,
                    "ordinal": index,
                    "collision_counter": counter,
                }
            )
            if candidate not in prior and candidate not in result.values():
                result[name] = candidate
                break
            counter += 1
    return result


def _candidate_operations(deficits: Iterable[str]) -> tuple[str, ...] | None:
    operations: set[str] = set()
    saw_deficit = False
    for deficit in deficits:
        saw_deficit = True
        mapped = APPROVED_DEFICIT_OPERATIONS.get(deficit)
        if mapped is None:
            return None
        operations.update(mapped)
    return tuple(sorted(operations)) if saw_deficit else None


def rank_addressable_candidates(
    rows: Iterable[Mapping[str, object]],
    *,
    attempted_provider_ids_by_round: Sequence[Sequence[str]],
    representation_group_need: Mapping[str, int],
    cap: int = 60,
) -> tuple[dict[str, object], ...]:
    """Apply the locked REINF-15 filter, three-key order, and one-request cap."""

    if cap != 60:
        raise SupplementalEvidenceError("REINF-15 request cap must remain exactly 60")
    attempted = {
        provider_id
        for round_ids in attempted_provider_ids_by_round
        for provider_id in round_ids
    }
    ranked: list[dict[str, object]] = []
    for source in rows:
        provider_id = source.get("provider_place_candidate_id")
        place_id = source.get("place_entity_id")
        group = source.get("representation_primary_group")
        deficits = source.get("named_deficits")
        if (
            not isinstance(provider_id, str)
            or provider_id in attempted
            or not isinstance(place_id, str)
            or not isinstance(group, str)
            or not isinstance(deficits, list | tuple)
            or not all(isinstance(item, str) for item in deficits)
        ):
            continue
        operations = _candidate_operations(deficits)
        if operations is None:
            continue
        ranked.append(
            {
                "place_entity_id": place_id,
                "provider_place_candidate_id": provider_id,
                "named_deficits": list(deficits),
                "mandatory_deficit_count": len(deficits),
                "representation_primary_group": group,
                "representation_group_need": max(
                    0, int(representation_group_need.get(group, 0))
                ),
                "approved_operations": list(operations),
            }
        )
    ranked.sort(
        key=lambda row: (
            int(row["mandatory_deficit_count"]),
            -int(row["representation_group_need"]),
            str(row["place_entity_id"]),
        )
    )
    return tuple(ranked[:cap])


def decide_successor(
    *,
    objective_eligible_count: int,
    human_decisions: int,
    ranked_candidates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Return deterministic successor or exact terminal disposition."""

    candidates = [dict(row) for row in ranked_candidates]
    if human_decisions > 6:
        if not candidates:
            return {
                "outcome_code": NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW,
                "outcome_reason": "NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW",
                "successor_required": False,
                "successor_candidate_count": 0,
                "successor_candidates": [],
            }
        return {
            "outcome_code": SUCCESSOR_REENTRY_REQUIRED,
            "outcome_reason": "ADDRESSABLE_IDENTITY_REVIEW_SUCCESSOR_REQUIRED",
            "successor_required": True,
            "successor_candidate_count": len(candidates),
            "successor_candidates": candidates,
        }
    if objective_eligible_count < 36 and candidates:
        return {
            "outcome_code": SUCCESSOR_REENTRY_REQUIRED,
            "outcome_reason": "SUPPLEMENTAL_SUCCESSOR_REENTRY_REQUIRED",
            "successor_required": True,
            "successor_candidate_count": len(candidates),
            "successor_candidates": candidates,
        }
    return {
        "outcome_code": EVIDENCE_FRONTIER_EXHAUSTED,
        "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
        "successor_required": False,
        "successor_candidate_count": 0,
        "successor_candidates": [],
    }


def _tree(repo_root: Path, relpath: str) -> dict[str, object]:
    return fingerprint_catalog_v1.scan_catalog_tree(repo_root, relpath)


def _protected_snapshot(
    repo_root: Path,
    order: RoundOrderManifest,
) -> dict[str, object]:
    v1 = fingerprint_catalog_v1.scan_catalog_tree(repo_root)
    history = fingerprint_catalog_v1.planning_history(repo_root)
    manifest, manifest_raw = _load_canonical(repo_root / V1_MANIFEST_RELPATH)
    if (
        manifest.get("catalog_v1") != v1
        or manifest.get("planning_history") != history
        or manifest.get("manifest_sha256")
        != canonical_sha256(
            {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        )
    ):
        raise SupplementalEvidenceError("protected v1/history manifest drifted")
    rounds = [
        {
            "ordinal": entry.ordinal,
            "round_id": entry.round_id,
            "round_root": entry.round_root,
            "round_manifest_sha256": entry.round_manifest_sha256,
            "tree": _tree(repo_root, entry.round_root),
        }
        for entry in order.entries
    ]
    historical_raw = _read_regular(repo_root / HISTORICAL_EQUIVALENCE_RELPATH)
    fields = {
        "schema_version": "itda.catalog-prior-lineage-attestation.v1",
        "legacy_rounds": rounds,
        "catalog_v1": v1,
        "completed_history": history,
        "v1_immutability_manifest_file_sha256": _sha256(manifest_raw),
        "v1_immutability_manifest_sha256": manifest["manifest_sha256"],
        "historical_verification_equivalence_file_sha256": _sha256(historical_raw),
    }
    return {**fields, "protected_snapshot_sha256": canonical_sha256(fields)}


def _discover_supplemental_ancestry(
    base: Path,
    *,
    exclude: str | None = None,
) -> list[dict[str, object]]:
    if not base.exists():
        return []
    discovered: list[tuple[int, list[str], dict[str, object]]] = []
    for child in sorted(base.iterdir(), key=lambda item: item.name):
        if (
            child.name == exclude
            or child.name == "rounds"
            or not child.is_dir()
            or child.is_symlink()
            or HEX_64.fullmatch(child.name) is None
        ):
            continue
        envelope = verify_round_envelope(child)
        payload = envelope["payload"]
        assert isinstance(payload, dict)
        payload_ancestry = payload.get("ancestry")
        if not isinstance(payload_ancestry, list):
            raise SupplementalEvidenceError("supplemental ancestry must be ordered")
        prior_supplemental_ids = [
            str(row["round_id"])
            for row in payload_ancestry
            if isinstance(row, dict) and row.get("kind") == "SUPPLEMENTAL"
        ]
        discovered.append(
            (
                len(prior_supplemental_ids),
                prior_supplemental_ids,
                {
                "kind": "SUPPLEMENTAL",
                "round_id": envelope["round_id"],
                "root_sha256": envelope["root_sha256"],
                "manifest_file_sha256": _sha256(
                    _read_regular(child / ROUND_MANIFEST_NAME)
                ),
                "request_sha256": payload["non_authorizing_identities"]["request_sha256"],
                "state_attestation_sha256": payload["non_authorizing_identities"][
                    "state_attestation_sha256"
                ],
                "target_sha256": payload["non_authorizing_identities"]["target_sha256"],
                "binding_sha256": payload["non_authorizing_identities"]["binding_sha256"],
                "nonce_sha256": payload["non_authorizing_identities"]["nonce_sha256"],
                "attempted_provider_ids": [
                    row["provider_place_candidate_id"]
                    for row in payload["successor_disposition"].get(
                        "successor_candidates", []
                    )
                ],
                },
            )
        )
    discovered.sort(key=lambda item: (item[0], str(item[2]["round_id"])))
    ancestry: list[dict[str, object]] = []
    for depth, declared_prior, row in discovered:
        actual_prior = [str(value["round_id"]) for value in ancestry]
        if depth != len(ancestry) or declared_prior != actual_prior:
            raise SupplementalEvidenceError(
                "supplemental ancestry is reordered, omitted, or substituted"
            )
        ancestry.append({**row, "ordinal": 3 + len(ancestry)})
    return ancestry


def _legacy_ancestry(order: RoundOrderManifest) -> list[dict[str, object]]:
    return [
        {
            "kind": "LEGACY_ENRICHMENT",
            "ordinal": entry.ordinal,
            "round_id": entry.round_id,
            "round_root": entry.round_root,
            "round_manifest_sha256": entry.round_manifest_sha256,
            "parent_round_manifest_sha256": entry.parent_round_manifest_sha256,
            "sidecar_file_sha256": entry.sidecar_file_sha256,
            "sidecar_sha256": entry.sidecar_sha256,
        }
        for entry in order.entries
    ]


def _build_target_ledger(
    aggregate: AggregateReadiness,
    objective: CandidateObjectiveEvidence,
) -> dict[str, object]:
    objective_by_place = {row.place_entity_id: row for row in objective.rows}
    rows: list[dict[str, object]] = []
    for aggregate_row in aggregate.rows:
        objective_row = objective_by_place.get(aggregate_row.place_entity_id)
        if objective_row is None:
            raise SupplementalEvidenceError("aggregate place lacks objective evidence")
        source_ids = list(objective_row.source_candidate_ids)
        odii_ids = [value for value in source_ids if value.startswith("candidate:odii:")]
        fields = {
            "place_entity_id": aggregate_row.place_entity_id,
            "provider_place_candidate_id": aggregate_row.provider_place_candidate_id,
            "source_candidate_ids": source_ids,
            "coordinates": objective_row.coordinates.model_dump(mode="json"),
            "description": objective_row.description.model_dump(mode="json"),
            "photo": objective_row.direct_media.model_dump(mode="json"),
            "operating_status": objective_row.operating_info.model_dump(mode="json"),
            "odii_presence": {
                "state": "PASS" if odii_ids else "MISSING",
                "source_candidate_ids": odii_ids,
                "reason_codes": (
                    ["ODII_SOURCE_PRESENT"] if odii_ids else ["ODII_SOURCE_MISSING"]
                ),
            },
            "objective_gate_states": {
                key: value.value if hasattr(value, "value") else str(value)
                for key, value in aggregate_row.objective_gate_states.items()
            },
            "objective_eligible": aggregate_row.objective_eligible,
            "representation_assignment_status": (
                aggregate_row.representation_assignment_status
            ),
            "representation_primary_group": aggregate_row.representation_primary_group,
            "evidence_round_ids": list(aggregate_row.evidence_round_ids),
            "missing_reasons": list(aggregate_row.named_deficits),
            "mandatory_deficit_count": len(aggregate_row.named_deficits),
            "confidence_is_qualification_filter_only": True,
            "confidence_adds_score": False,
            "canonical_membership_created": False,
        }
        rows.append({**fields, "row_sha256": canonical_sha256(fields)})
    rows.sort(key=lambda row: str(row["place_entity_id"]))
    fields = {
        "schema_version": "itda.catalog-supplemental-target-ledger.v1",
        "terminal_aggregate_sha256": aggregate.aggregate_sha256,
        "row_count": len(rows),
        "objective_eligible_count": sum(bool(row["objective_eligible"]) for row in rows),
        "human_identity_relationship_decisions": (
            aggregate.human_identity_relationship_decisions
        ),
        "addressable_frontier_count": aggregate.addressable_frontier_count,
        "rows": rows,
        "rows_root": canonical_sha256(rows),
        "confidence_adds_score": False,
        "canonical_membership_created": False,
    }
    if (
        fields["row_count"] != 718
        or fields["objective_eligible_count"] != 13
        or fields["human_identity_relationship_decisions"] != 6
        or fields["addressable_frontier_count"] != 0
    ):
        raise SupplementalEvidenceError("terminal 718/13/6/0 facts drifted")
    return {**fields, "ledger_sha256": canonical_sha256(fields)}


def _supplemental_grant(rights: Mapping[str, object]) -> dict[str, object]:
    grants = rights.get("dataset_grants")
    if not isinstance(grants, list):
        raise SupplementalEvidenceError("rights projection lacks dataset grants")
    grant = next(
        (
            row
            for row in grants
            if isinstance(row, dict) and row.get("official_dataset_id") == "15101578"
        ),
        None,
    )
    if grant is None:
        raise SupplementalEvidenceError("TourAPI dataset grant is missing")
    fields = {
        "official_dataset_id": "15101578",
        "official_page_url": grant["official_page_url"],
        "retrieved_at": grant["retrieved_at"],
        "response_sha256": grant["response_sha256"],
        "page_sha256": grant["page_sha256"],
        "evidence_state": grant["evidence_state"],
        "license_type": grant["license_type"],
        "commercial_use_allowed": grant["commercial_use_allowed"],
        "transform_allowed": grant["transform_allowed"],
        "display_allowed": grant["display_allowed"],
        "model_input_allowed": grant["model_input_allowed"],
        "explicit_restrictions": grant["explicit_restrictions"],
    }
    return {**fields, "dataset_grant_sha256": canonical_sha256(fields)}


def _build_atoms(
    repo_root: Path,
    *,
    aggregate: AggregateReadiness,
) -> object:
    preview_manifest, preview_manifest_raw = _load_json(
        repo_root / PREVIEW_MANIFEST_RELPATH
    )
    raw_bundle, raw_bundle_bytes = _load_json(repo_root / PREVIEW_BUNDLE_RELPATH)
    if preview_manifest.get("approved_redacted_provider_bundle_sha256") != _sha256(
        raw_bundle_bytes
    ):
        raise SupplementalEvidenceError("Phase 1 preview bundle hash drifted")
    rights, _ = _load_json(repo_root / RIGHTS_RELPATH)
    grant = _supplemental_grant(rights)
    place_by_provider = {
        row.provider_place_candidate_id: row.place_entity_id
        for row in aggregate.rows
        if row.provider_place_candidate_id is not None
    }
    atoms = []
    rows = raw_bundle.get("rows")
    if not isinstance(rows, list):
        raise SupplementalEvidenceError("Phase 1 bundle lacks rows")
    for raw_row in rows:
        if not isinstance(raw_row, dict) or raw_row.get("provider") != "TOUR_API":
            continue
        source_id = raw_row.get("source_id")
        endpoint = raw_row.get("endpoint")
        response_sha256 = raw_row.get("raw_response_sha256")
        if not all(isinstance(value, str) for value in (source_id, endpoint, response_sha256)):
            continue
        provider_id = f"candidate:tour-api:{source_id}"
        place_id = place_by_provider.get(provider_id)
        if place_id is None:
            continue
        field_name = (
            "exact_provider_direct_media"
            if "Image" in endpoint
            else "korean_description"
            if "Common" in endpoint
            else "coordinates"
        )
        rights_rows = raw_row.get("rights")
        has_type_3 = isinstance(rights_rows, list) and any(
            isinstance(row, dict)
            and str(row.get("cpyrhtDivCd", "")).lower() in {"type3", "type4"}
            for row in rights_rows
        )
        atoms.append(
            build_supplemental_evidence_atom(
                place_entity_id=place_id,
                source_kind="OFFICIAL_API_ROW",
                source_owner="한국관광공사",
                official_dataset_or_page_id="15101578",
                operation_or_page_identity=endpoint,
                provider_candidate_id=provider_id,
                source_record_or_asset_id=source_id,
                original_url=f"https://apis.data.go.kr/B551011/{endpoint}",
                retrieved_at=str(raw_row.get("retrieved_at")),
                immutable_relative_path=PREVIEW_BUNDLE_RELPATH,
                raw_or_page_sha256=_sha256(raw_bundle_bytes),
                value_sha256=response_sha256,
                parent_manifest_sha256=_sha256(preview_manifest_raw),
                field_name=field_name,
                binding_state="EXACT",
                binding_method="EXACT_PROVIDER_RECORD_ID",
                binding_evidence_sha256=canonical_sha256(
                    {
                        "place_entity_id": place_id,
                        "provider_candidate_id": provider_id,
                        "source_record_id": source_id,
                    }
                ),
                dataset_grant=grant,
                asset_provenance={
                    "source_asset_id": source_id,
                    "creator_or_photographer": "UNVERIFIED_PHASE1_SOURCE",
                    "license_type": "KOGL_TYPE_3" if has_type_3 else "UNVERIFIED",
                    "attribution_text": "한국관광공사",
                    "explicit_asset_restriction": (
                        "PHASE1_ASSET_SCOPE_NOT_INDEPENDENTLY_CLEARED"
                    ),
                    "attachment_rights_granting": False,
                },
            )
        )
    return build_supplemental_atom_set(
        terminal_aggregate_sha256=aggregate.aggregate_sha256,
        atoms=tuple(atoms),
    )


def _child_row(name: str, payload: bytes, *, row_count: int) -> dict[str, object]:
    return {
        "relpath": name,
        "entry_type": "REGULAR_FILE",
        "mode": "0600",
        "size": len(payload),
        "file_sha256": _sha256(payload),
        "row_count": row_count,
    }


def _code_policy_identity(repo_root: Path) -> str:
    paths = (
        "backend/src/itda/cli/build_catalog_supplemental_evidence.py",
        "backend/src/itda/contracts/catalog_supplemental_evidence.py",
        "backend/src/itda/contracts/catalog_entity_policy.py",
        RIGHTS_RELPATH,
    )
    return canonical_sha256(
        [
            {"relpath": path, "file_sha256": _sha256(_read_regular(repo_root / path))}
            for path in paths
        ]
    )


def build_generation(repo_root: Path) -> SalvageGeneration:
    """Replay the exact terminal ledger twice from one deterministic frozen context."""

    repo_root = repo_root.resolve(strict=True)
    order_raw, _ = _load_canonical(repo_root / ROUND_ORDER_RELPATH)
    order = RoundOrderManifest.model_validate(order_raw)
    if (
        order.round_count != 3
        or order.newest_round_id != TERMINAL_ROUND_ID
        or tuple(entry.ordinal for entry in order.entries) != (0, 1, 2)
    ):
        raise SupplementalEvidenceError("exact three-round legacy prefix drifted")
    aggregate_raw, aggregate_bytes = _load_canonical(
        repo_root / TERMINAL_AGGREGATE_RELPATH
    )
    aggregate = AggregateReadiness.model_validate(aggregate_raw)
    objective_raw, _ = _load_canonical(repo_root / OBJECTIVE_RELPATH)
    objective = CandidateObjectiveEvidence.model_validate(objective_raw)
    protected = _protected_snapshot(repo_root, order)
    ledger = _build_target_ledger(aggregate, objective)
    atom_set = _build_atoms(repo_root, aggregate=aggregate)

    lineage_bytes = canonical_json_bytes(protected)
    ledger_bytes = canonical_json_bytes(ledger)
    atom_bytes = canonical_json_bytes(atom_set.model_dump(mode="json"))
    manifest_children = (
        SupplementalManifestChild(
            **_child_row(
                CHILD_ORDER[0],
                lineage_bytes,
                row_count=sum(
                    int(round_row["tree"]["entry_count"])
                    for round_row in protected["legacy_rounds"]
                )
                + int(protected["catalog_v1"]["entry_count"])
                + int(protected["completed_history"]["required_file_count"]),
            ),
            role="LINEAGE_ATTESTATION",
        ),
        SupplementalManifestChild(
            **_child_row(CHILD_ORDER[1], ledger_bytes, row_count=len(ledger["rows"])),
            role="TARGET_LEDGER",
        ),
        SupplementalManifestChild(
            **_child_row(CHILD_ORDER[2], atom_bytes, row_count=atom_set.atom_count),
            role="EVIDENCE_ATOMS",
        ),
    )
    evidence_manifest = build_supplemental_manifest(
        terminal_aggregate_sha256=aggregate.aggregate_sha256,
        atom_set_sha256=atom_set.atom_set_sha256,
        children=manifest_children,
    )
    evidence_manifest_bytes = canonical_json_bytes(
        evidence_manifest.model_dump(mode="json")
    )
    children = {
        CHILD_ORDER[0]: lineage_bytes,
        CHILD_ORDER[1]: ledger_bytes,
        CHILD_ORDER[2]: atom_bytes,
        CHILD_ORDER[3]: evidence_manifest_bytes,
    }
    child_rows = [
        _child_row(
            name,
            children[name],
            row_count=(
                int(protected["catalog_v1"]["entry_count"])
                if name == CHILD_ORDER[0]
                else len(ledger["rows"])
                if name == CHILD_ORDER[1]
                else atom_set.atom_count
                if name == CHILD_ORDER[2]
                else 3
            ),
        )
        for name in CHILD_ORDER
    ]
    base = repo_root / SALVAGE_RELPATH
    supplemental = _discover_supplemental_ancestry(base)
    ancestry = [*_legacy_ancestry(order), *supplemental]
    attempted_by_round: list[tuple[str, ...]] = [
        tuple(aggregate.attempted_provider_ids)
    ]
    attempted_by_round.extend(
        tuple(str(value) for value in row.get("attempted_provider_ids", []))
        for row in supplemental
    )
    group_need = {
        group: max(0, 12 - count)
        for group, count in aggregate.eligible_group_counts.items()
    }
    ranked = rank_addressable_candidates(
        ledger["rows"],
        attempted_provider_ids_by_round=attempted_by_round,
        representation_group_need=group_need,
    )
    disposition = decide_successor(
        objective_eligible_count=aggregate.objective_eligible_count,
        human_decisions=aggregate.human_identity_relationship_decisions,
        ranked_candidates=ranked,
    )
    disposition.update(
        {
            "attempted_provider_ids_root": aggregate.attempted_provider_ids_root,
            "complete_ancestry_round_count": len(ancestry),
            "authority_inherited": False,
            "approved_operation_policy": {
                key: list(value) for key, value in APPROVED_DEFICIT_OPERATIONS.items()
            },
        }
    )
    code_policy_identity = _code_policy_identity(repo_root)
    seed = canonical_sha256(
        {
            "terminal_aggregate_file_sha256": _sha256(aggregate_bytes),
            "terminal_aggregate_sha256": aggregate.aggregate_sha256,
            "code_policy_identity": code_policy_identity,
            "ancestry": ancestry,
            "children": child_rows,
        }
    )
    identities = build_non_authorizing_identities(
        generation_seed=seed,
        ancestry=ancestry,
    )
    payload = {
        "schema_version": "itda.catalog-supplemental-round.v1",
        "code_policy_identity": code_policy_identity,
        "ancestry": ancestry,
        "terminal_aggregate": {
            "relpath": TERMINAL_AGGREGATE_RELPATH,
            "file_sha256": _sha256(aggregate_bytes),
            "aggregate_sha256": aggregate.aggregate_sha256,
            "rows_root": aggregate.rows_root,
            "row_count": len(aggregate.rows),
            "objective_eligible_count": aggregate.objective_eligible_count,
            "human_identity_relationship_decisions": (
                aggregate.human_identity_relationship_decisions
            ),
            "addressable_frontier_count": aggregate.addressable_frontier_count,
        },
        "non_authorizing_identities": identities,
        "generation_state": "SUCCESS",
        "successor_disposition": disposition,
        "children": child_rows,
    }
    first = build_round_envelope(payload)
    second = build_round_envelope(json.loads(canonical_json_bytes(payload)))
    if canonical_json_bytes(first) != canonical_json_bytes(second):
        raise SupplementalEvidenceError("two isolated generation builds differ")
    round_id = str(first["round_id"])
    return SalvageGeneration(
        round_id=round_id,
        destination=base / round_id,
        children=children,
        envelope=first,
        protected_snapshot=protected,
    )


def publish_immutable_generation(
    *,
    destination: Path,
    round_id: str,
    children: Mapping[str, bytes],
    envelope: Mapping[str, object],
) -> None:
    """Publish one complete generation by atomic no-replace directory rename."""

    if destination.name != round_id:
        raise SupplementalEvidenceError("destination basename must equal round ID")
    if envelope.get("round_id") != round_id or envelope.get("root_sha256") != round_id:
        raise SupplementalEvidenceError("envelope root and round ID differ")
    if destination.parent.is_symlink():
        raise SupplementalEvidenceError("destination parent cannot be a symlink")
    rebuilt = build_round_envelope(envelope.get("payload", {}))
    if rebuilt != dict(envelope):
        raise SupplementalEvidenceError("round envelope does not rederive")
    if os.path.lexists(destination):
        raise FileExistsError("supplemental success generation already exists")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    prepared = Path(
        tempfile.mkdtemp(prefix=".supplemental-", dir=destination.parent)
    )
    os.chmod(prepared, 0o700)
    try:
        for name, payload in children.items():
            if name not in CHILD_ORDER:
                raise SupplementalEvidenceError("unexpected supplemental child")
            _write_exclusive(prepared / name, payload)
        _write_exclusive(
            prepared / ROUND_MANIFEST_NAME,
            canonical_json_bytes(dict(envelope)),
        )
        directory_descriptor = os.open(
            prepared,
            os.O_RDONLY | fingerprint_catalog_v1.O_DIRECTORY,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        publish_immutable_directory(prepared=prepared, output=destination)
    finally:
        if prepared.exists():
            for path in prepared.iterdir():
                path.unlink()
            prepared.rmdir()
    if verify_round_envelope(destination) != dict(envelope):
        raise SupplementalEvidenceError("live publication differs from frozen envelope")


def verify_round_envelope(root: Path) -> dict[str, object]:
    """Verify live children, exact modes, digest, basename, and outer envelope."""

    before = os.lstat(root)
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o700
        or root.is_symlink()
    ):
        raise SupplementalEvidenceError("supplemental root must be a 0700 directory")
    envelope_raw = _read_regular(root / ROUND_MANIFEST_NAME)
    envelope = json.loads(envelope_raw)
    if (
        not isinstance(envelope, dict)
        or tuple(envelope) != ("payload", "root_sha256", "round_id")
        or canonical_json_bytes(envelope) != envelope_raw
        or envelope.get("round_id") != root.name
        or envelope.get("root_sha256") != root.name
    ):
        raise SupplementalEvidenceError("round envelope or basename drifted")
    rebuilt = build_round_envelope(envelope["payload"])
    if rebuilt != envelope:
        raise SupplementalEvidenceError("round envelope payload does not rederive")
    payload = envelope["payload"]
    child_rows = payload["children"]
    if not isinstance(child_rows, list):
        raise SupplementalEvidenceError("round child inventory is invalid")
    expected_names = [row["relpath"] for row in child_rows]
    if expected_names not in ([], list(CHILD_ORDER)):
        raise SupplementalEvidenceError("round children use the wrong fixed order")
    for row in child_rows:
        path = root / row["relpath"]
        raw = _read_regular(path)
        mode = stat.S_IMODE(os.lstat(path).st_mode)
        if (
            row["entry_type"] != "REGULAR_FILE"
            or row["mode"] != "0600"
            or mode != 0o600
            or row["size"] != len(raw)
            or row["file_sha256"] != _sha256(raw)
        ):
            raise SupplementalEvidenceError("live child inventory differs")
    actual_names = sorted(path.name for path in root.iterdir())
    if actual_names != sorted([*expected_names, ROUND_MANIFEST_NAME]):
        raise SupplementalEvidenceError("supplemental root contains an untracked file")
    fingerprint_catalog_v1._same_state(before, os.lstat(root))
    return envelope


def _publish_successor_disposition(root: Path, envelope: Mapping[str, object]) -> int:
    payload = envelope["payload"]
    assert isinstance(payload, dict)
    disposition = payload["successor_disposition"]
    assert isinstance(disposition, dict)
    report_fields = {
        "schema_version": "itda.catalog-supplemental-successor-disposition.v1",
        "salvage_round_id": envelope["round_id"],
        "salvage_root_sha256": envelope["root_sha256"],
        "disposition": disposition,
        "authority_inherited": False,
        "authority_token_issued_or_consumed": False,
    }
    report_id = canonical_sha256(report_fields)
    report = {**report_fields, "report_sha256": report_id}
    rounds = root.parent / "rounds"
    rounds.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(rounds, 0o700)
    target = rounds / report_id
    if target.exists():
        raise FileExistsError("successor disposition was already emitted")
    target.mkdir(mode=0o700)
    _write_exclusive(target / "successor-disposition.json", canonical_json_bytes(report))
    return int(disposition["outcome_code"])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--derive", action="store_true")
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--emit-successor", action="store_true")
    parser.add_argument("--round-root", type=Path)
    parser.add_argument("--round-id")
    parser.add_argument("--discover-exact-success-under", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.resolve(strict=True)
    if args.check:
        if args.discover_exact_success_under is None:
            raise SupplementalEvidenceError(
                "--check requires --discover-exact-success-under"
            )
        base = args.discover_exact_success_under.resolve(strict=True)
        expected_base = (repo_root / SALVAGE_RELPATH).resolve(strict=True)
        if base != expected_base:
            raise SupplementalEvidenceError("success discovery base is not exact")
        roots = [
            child
            for child in base.iterdir()
            if child.is_dir()
            and not child.is_symlink()
            and child.name != "rounds"
            and HEX_64.fullmatch(child.name)
        ]
        if len(roots) != 1:
            raise SupplementalEvidenceError("expected exactly one salvage success root")
        envelope = verify_round_envelope(roots[0])
        print(json.dumps({"verified": True, "round_id": envelope["round_id"]}, sort_keys=True))
        return 0

    if args.emit_successor:
        if args.round_root is None or args.round_id is None:
            raise SupplementalEvidenceError(
                "successor emission requires explicit --round-root and --round-id"
            )
        root = args.round_root.resolve(strict=True)
        if root.name != args.round_id:
            raise SupplementalEvidenceError("round root and round ID differ")
        return _publish_successor_disposition(root, verify_round_envelope(root))

    generation = build_generation(repo_root)
    if args.derive:
        print(
            json.dumps(
                {
                    "round_id": generation.round_id,
                    "round_root": str(generation.destination),
                },
                sort_keys=True,
            )
        )
        return 0
    if args.round_root is None or args.round_id is None:
        raise SupplementalEvidenceError(
            "build requires explicit --round-root and --round-id"
        )
    supplied_root = args.round_root.resolve(strict=False)
    if supplied_root != generation.destination or args.round_id != generation.round_id:
        raise SupplementalEvidenceError("supplied round root or round ID differs from replay")
    publish_immutable_generation(
        destination=generation.destination,
        round_id=generation.round_id,
        children=generation.children,
        envelope=generation.envelope,
    )
    order = RoundOrderManifest.model_validate(
        _load_canonical(repo_root / ROUND_ORDER_RELPATH)[0]
    )
    if _protected_snapshot(repo_root, order) != generation.protected_snapshot:
        raise SupplementalEvidenceError("protected parents changed during publication")
    print(
        json.dumps(
            {
                "status": "success",
                "round_id": generation.round_id,
                "round_root": str(generation.destination),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
