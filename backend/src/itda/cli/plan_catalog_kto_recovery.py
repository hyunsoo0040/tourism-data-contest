"""Traffic-free Plan 02-47 KTO recovery eligibility preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from itda.cli.freeze_preview import publish_immutable_directory
from itda.contracts.catalog_enrichment import (
    KOR_SERVICE2_BASE_URL,
    KOR_SERVICE2_PARAMETER_ALLOWLISTS,
    KOR_SERVICE2_SCHEMA_SOURCE,
    KTO_OFFICIAL_CONTRACT_PINS,
    build_kto_recovery_request,
    canonical_json_bytes,
)
from itda.contracts.catalog_grammar_successor import (
    classify_typed_intro_recovery,
)

TARGET_MATRIX_REL = (
    "artifacts/restricted/catalog/v2/supplemental/preflight/rounds/"
    "0082ac8da8fe69492532b7af7b43e27d53f3b9d9ee0bfdbee1487e87ef5019d6/"
    "supplemental-target-matrix.json"
)
AGGREGATE_REL = (
    "artifacts/restricted/catalog/v2/enrichment/rounds/"
    "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55/"
    "aggregate-readiness.json"
)
SIDECARS_REL = (
    "artifacts/restricted/catalog/v2/enrichment/rounds/"
    "f53bd3a2abff43f551af1b15ad74d99f801ef1fd2b92cd0306b714139dfa2711/"
    "evidence-sidecars.json"
)
ENTITY_PROJECTION_REL = "artifacts/restricted/catalog/v2/projection/entity-projection.json"
SNAPSHOT_ROOT_REL = "artifacts/restricted/catalog/v1/collection/snapshots"
DECISION_BASE_REL = "artifacts/restricted/catalog/v2/supplemental/kto-recovery/decisions"
ELIGIBILITY_BASE_REL = "artifacts/restricted/catalog/v2/supplemental/kto-recovery/eligibility"
EXPECTED_ANCESTRY = [
    "a59fabf3371845fbacb4e32510b178b03d7a784d0becfea6edfd7f7b2e4f2c25",
    "f53bd3a2abff43f551af1b15ad74d99f801ef1fd2b92cd0306b714139dfa2711",
    "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55",
    "5e092fdff24e3b67e3098d2485f71396bec7d631a307dbfa7e8d9a5ba68f0fff",
]
EXPECTED_TYPED_TARGETS = {
    "candidate:tour-api:3486762": "14",
    "candidate:tour-api:3056660": "14",
    "candidate:tour-api:3032546": "28",
}
GROUP_NEED = {
    "history_culture": 12,
    "history_scenery_boundary": 6,
    "image_modern_content": 6,
    "rest_walk_immersion": 0,
}
PROHIBITED_KEYS = {
    "serviceKey",
    "service_key",
    "apiKey",
    "api_key",
    "authorization",
    "authority_token",
    "nonce",
    "canonical_membership",
    "split_membership",
    "seal",
}
_REVIEWER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", flags=re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_PROHIBITED_DECISION_INSTRUCTIONS = (
    "servicekey",
    "api_key",
    "credential",
    "authority",
    "nonce",
    "canonical",
    "split",
    "schema",
    "seal",
)
_DECISION_FIELDS = {
    "actual_type_evidence_root",
    "kto_allowlist_revision_sha256",
    "kto_contract_sha256",
    "kto_substitution_set_sha256",
    "policy_version",
    "rationale",
    "reviewer_id",
    "selected_policy",
    "typed_intro_predecessor_root",
    "unresolved_intro_target_root",
}
_ELIGIBILITY_FILES = {
    "contract-pins.json",
    "operation-allowlists.json",
    "eligibility.json",
    "policy-decision-ref.json",
    "request-manifest.json",
    "root-manifest.json",
}


@dataclass(frozen=True)
class KtoEligibilityGeneration:
    """One pure, self-excluding eligibility generation before publication."""

    root_sha256: str
    files: Mapping[str, bytes]

    def json_value(self, name: str) -> dict[str, object]:
        if name not in self.files:
            raise KeyError(name)
        value = json.loads(self.files[name])
        if not isinstance(value, dict):
            raise ValueError("eligibility generation child must be a JSON object")
        return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular_json(path: Path) -> tuple[dict[str, object], str]:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"protected input is not a no-follow regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("protected input identity changed during open")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size):
            raise ValueError("protected input identity changed during read")
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("protected JSON input must be an object")
    return value, _sha256_bytes(payload)


def _digest(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write while publishing KTO recovery evidence")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_prepared_directory(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ValueError("prepared KTO recovery directory contains a special entry")
        child.unlink()
    path.rmdir()


def _publish_private_files(
    *,
    destination: Path,
    files: Mapping[str, bytes],
    temporary_prefix: str,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    if os.path.lexists(destination):
        raise FileExistsError("output already exists; publication is immutable")
    prepared = Path(tempfile.mkdtemp(prefix=temporary_prefix, dir=destination.parent))
    os.chmod(prepared, 0o700)
    try:
        for name, payload in files.items():
            if Path(name).name != name:
                raise ValueError("KTO recovery output name must be one path segment")
            _write_exclusive(prepared / name, payload)
        publish_immutable_directory(prepared=prepared, output=destination)
    finally:
        _remove_prepared_directory(prepared)


def _assert_private_directory(root: Path, *, expected_files: set[str]) -> None:
    root_stat = os.lstat(root)
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise ValueError("published KTO recovery root must be a private directory")
    if {entry.name for entry in root.iterdir()} != expected_files:
        raise ValueError("published KTO recovery root has undeclared artifacts")
    for name in expected_files:
        file_stat = os.lstat(root / name)
        if (
            stat.S_ISLNK(file_stat.st_mode)
            or not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != 0o600
        ):
            raise ValueError("published KTO recovery file must be private and regular")


def _load_kto_universe(
    repository_root: Path,
) -> tuple[dict[str, dict[str, str]], str]:
    snapshot_root = repository_root / SNAPSHOT_ROOT_REL
    if snapshot_root.is_symlink() or not snapshot_root.is_dir():
        raise ValueError("KTO snapshot root must be a no-follow directory")
    rows: dict[str, dict[str, str]] = {}
    parents: list[dict[str, str]] = []
    for path in sorted(snapshot_root.glob("TOUR_API-areaBasedList2-*.json")):
        snapshot, file_sha256 = _read_regular_json(path)
        if snapshot.get("provider") != "TOUR_API":
            raise ValueError("KTO universe contains a substituted provider")
        response = snapshot.get("payload")
        if not isinstance(response, Mapping):
            raise ValueError("KTO snapshot payload is missing")
        response_envelope = response.get("response")
        body = response_envelope.get("body") if isinstance(response_envelope, Mapping) else None
        items = body.get("items") if isinstance(body, Mapping) else None
        if items in (None, ""):
            item_value: object = []
        elif isinstance(items, Mapping):
            item_value = items.get("item", [])
        else:
            raise ValueError("KTO list items projection has an unsupported shape")
        if not isinstance(item_value, list):
            raise ValueError("KTO list item projection must be an array")
        for item in item_value:
            if not isinstance(item, Mapping):
                raise ValueError("KTO list item must be an object")
            content_id = str(item.get("contentid", ""))
            candidate_id = f"candidate:tour-api:{content_id}"
            row = {
                "provider_candidate_id": candidate_id,
                "name_ko": str(item.get("title", "")),
                "actual_content_type_id": str(item.get("contenttypeid", "")),
            }
            existing = rows.get(candidate_id)
            if existing is not None and existing != row:
                raise ValueError("KTO universe contains conflicting duplicate identities")
            rows[candidate_id] = row
        parents.append({"path": path.name, "sha256": file_sha256})
    if not rows:
        raise ValueError("KTO universe is empty")
    return rows, _digest(parents)


def _entity_names(projection: Mapping[str, object]) -> dict[str, str]:
    rows = projection.get("dataset_records")
    if not isinstance(rows, list):
        raise ValueError("entity projection dataset records are missing")
    result: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("entity projection row must be an object")
        source_id = row.get("source_candidate_id")
        name = row.get("name_ko")
        if isinstance(source_id, str) and isinstance(name, str):
            result[source_id] = name
    return result


def _assert_no_prohibited_keys(value: object) -> None:
    if isinstance(value, Mapping):
        if PROHIBITED_KEYS.intersection(value):
            raise ValueError("preflight contains a prohibited capability field")
        for child in value.values():
            _assert_no_prohibited_keys(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_prohibited_keys(child)


def build_traffic_free_preflight(repository_root: Path | str) -> dict[str, object]:
    """Rebuild the exact Plan 47 decision inputs without any external effect."""

    root = Path(repository_root).resolve(strict=True)
    target_matrix, target_file_sha = _read_regular_json(root / TARGET_MATRIX_REL)
    aggregate, aggregate_file_sha = _read_regular_json(root / AGGREGATE_REL)
    sidecars, sidecars_file_sha = _read_regular_json(root / SIDECARS_REL)
    projection, projection_file_sha = _read_regular_json(root / ENTITY_PROJECTION_REL)
    universe, universe_root = _load_kto_universe(root)
    names = _entity_names(projection)

    if target_matrix.get("ordered_ancestry") != EXPECTED_ANCESTRY:
        raise ValueError("KTO recovery ancestry is stale or mixed")
    target_rows = target_matrix.get("rows")
    if (
        target_matrix.get("target_count") != 24
        or not isinstance(target_rows, list)
        or len(target_rows) != 24
    ):
        raise ValueError("KTO recovery target count drifted from 24")
    candidate_ids = [
        row.get("existing_provider_candidate_id") for row in target_rows if isinstance(row, Mapping)
    ]
    if len(candidate_ids) != 24 or len(set(candidate_ids)) != 24:
        raise ValueError("KTO recovery targets contain duplicates or invalid rows")

    response_rows = sidecars.get("responses")
    aggregate_rows = aggregate.get("rows")
    if not isinstance(response_rows, list) or not isinstance(aggregate_rows, list):
        raise ValueError("terminal evidence parents are missing")
    response_index = {
        (row.get("provider_candidate_id"), row.get("operation")): row
        for row in response_rows
        if isinstance(row, Mapping)
    }
    aggregate_index = {
        row.get("provider_place_candidate_id"): row
        for row in aggregate_rows
        if isinstance(row, Mapping)
    }

    correction_rows: list[dict[str, object]] = []
    typed_rows: list[dict[str, object]] = []
    typed_groups: set[str] = set()
    for row in target_rows:
        if not isinstance(row, Mapping):
            raise ValueError("target row must be an object")
        candidate_id = str(row["existing_provider_candidate_id"])
        deficits = row.get("mandatory_deficits")
        if deficits == ["DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING"]:
            aggregate_row = aggregate_index.get(candidate_id)
            if not isinstance(aggregate_row, Mapping):
                raise ValueError("target lacks aggregate readiness ancestry")
            for operation in ("detailCommon2", "detailImage2"):
                correction_rows.append(
                    build_kto_recovery_request(
                        operation=operation,
                        provider_candidate_id=candidate_id,
                        place_entity_id=str(row["place_entity_id"]),
                        source_candidate_row_sha256=str(aggregate_row["row_sha256"]),
                    )
                )
            continue
        if deficits != ["OPERATING_INFO_MISSING"]:
            raise ValueError("target has an unexplained mandatory deficit")
        actual = universe.get(candidate_id)
        expected_type = EXPECTED_TYPED_TARGETS.get(candidate_id)
        if actual is None or actual["actual_content_type_id"] != expected_type:
            raise ValueError("typed Intro actual KTO type evidence drifted")
        predecessor = response_index.get((candidate_id, "detailIntro2"))
        if not isinstance(predecessor, Mapping):
            raise ValueError("typed Intro predecessor evidence is missing")
        fields = predecessor.get("fields")
        if not isinstance(fields, list) or len(fields) != 1:
            raise ValueError("typed Intro predecessor fields are ambiguous")
        field = fields[0]
        if (
            predecessor.get("provider_result_code") != "0000"
            or not isinstance(field, Mapping)
            or field.get("deficit_reason") != "SUCCESS_RESPONSE_FIELD_EMPTY"
        ):
            raise ValueError("typed Intro predecessor is not successful-empty")
        policy = classify_typed_intro_recovery(
            {
                "operation": "detailIntro2",
                "provider_result_code": predecessor["provider_result_code"],
                "provider_result_value": predecessor["provider_result_value"],
                "deficit_reason": field["deficit_reason"],
                "requested_content_type_id": "12",
                "actual_content_type_id": expected_type,
            }
        )
        typed_groups.add(str(row["primary_coverage_group"]))
        typed_rows.append(
            {
                "provider_candidate_id": candidate_id,
                "place_entity_id": row["place_entity_id"],
                "name_ko": names.get(candidate_id, actual["name_ko"]),
                "actual_content_type_id": expected_type,
                "actual_type_evidence": actual,
                "predecessor": {
                    "round_id": predecessor["round_id"],
                    "request_identity": predecessor["request_identity"],
                    "raw_body_sha256": predecessor["raw_body_sha256"],
                    "provider_result_code": predecessor["provider_result_code"],
                    "provider_result_value": predecessor["provider_result_value"],
                    "deficit_reason": field["deficit_reason"],
                },
                **policy,
            }
        )
    typed_rows.sort(
        key=lambda row: (
            int(str(row["actual_content_type_id"])),
            str(row["place_entity_id"]),
        )
    )
    if len(correction_rows) != 42 or len(typed_rows) != 3:
        raise ValueError("KTO recovery pair counts drifted from 42 plus three")
    if set(EXPECTED_TYPED_TARGETS) != {str(row["provider_candidate_id"]) for row in typed_rows}:
        raise ValueError("typed Intro deficit identities drifted")

    typed_target_ids = {str(row["provider_candidate_id"]) for row in typed_rows}
    candidates: list[tuple[tuple[object, ...], Mapping[str, object]]] = []
    for row in aggregate_rows:
        if not isinstance(row, Mapping):
            continue
        candidate_value = row.get("provider_place_candidate_id")
        deficits = row.get("named_deficits")
        if (
            not isinstance(candidate_value, str)
            or candidate_value in candidate_ids
            or candidate_value in typed_target_ids
            or row.get("representation_assignment_status") != "PRIMARY"
            or deficits != ["DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING"]
            or candidate_value not in universe
        ):
            continue
        group = str(row["representation_primary_group"])
        same_group_rank = 0 if group in typed_groups else 1
        rank = (
            same_group_rank,
            -GROUP_NEED.get(group, -1),
            str(row["place_entity_id"]),
        )
        candidates.append((rank, row))
    candidates.sort(key=lambda item: item[0])
    if len(candidates) < 3:
        raise ValueError("fewer than three exact KTO substitutes remain")
    substitute_rows: list[dict[str, object]] = []
    substitute_request_count = 0
    for _rank, row in candidates[:3]:
        substitute_candidate_id = str(row["provider_place_candidate_id"])
        actual = universe[substitute_candidate_id]
        operations = ["detailCommon2", "detailImage2"]
        substitute_request_count += len(operations)
        substitute_rows.append(
            {
                "provider_candidate_id": substitute_candidate_id,
                "place_entity_id": row["place_entity_id"],
                "name_ko": names.get(substitute_candidate_id, actual["name_ko"]),
                "actual_content_type_id": actual["actual_content_type_id"],
                "primary_coverage_group": row["representation_primary_group"],
                "objective_deficit_closure_evidence": {
                    "current_deficits": row["named_deficits"],
                    "operating_information_already_passes": True,
                    "aggregate_row_sha256": row["row_sha256"],
                    "evidence_round_ids": row["evidence_round_ids"],
                },
                "operations": operations,
                "request_rows": [
                    build_kto_recovery_request(
                        operation=operation,
                        provider_candidate_id=substitute_candidate_id,
                        place_entity_id=str(row["place_entity_id"]),
                        source_candidate_row_sha256=str(row["row_sha256"]),
                    )
                    for operation in operations
                ],
            }
        )

    contract = {
        "base_url": KOR_SERVICE2_BASE_URL,
        "schema_source": KOR_SERVICE2_SCHEMA_SOURCE,
        "official_pins": dict(KTO_OFFICIAL_CONTRACT_PINS),
    }
    allowlists = {
        operation: sorted(parameters - {"serviceKey"})
        for operation, parameters in KOR_SERVICE2_PARAMETER_ALLOWLISTS.items()
    }
    packet: dict[str, object] = {
        "schema_version": "itda.kto-recovery-preflight.v1",
        "status": "AWAITING_EXACT_HUMAN_DECISION",
        "policy_version": "itda.typed-intro-substitution.v1",
        "official_contract": contract,
        "kto_contract_sha256": _digest(contract),
        "operation_allowlists": allowlists,
        "kto_allowlist_revision_sha256": _digest(allowlists),
        "ordered_ancestry": EXPECTED_ANCESTRY,
        "parent_file_sha256": {
            TARGET_MATRIX_REL: target_file_sha,
            AGGREGATE_REL: aggregate_file_sha,
            SIDECARS_REL: sidecars_file_sha,
            ENTITY_PROJECTION_REL: projection_file_sha,
        },
        "kto_universe_root": universe_root,
        "target_count": 24,
        "common_image_correction_count": len(correction_rows),
        "common_image_corrections_sha256": _digest(correction_rows),
        "common_image_corrections": correction_rows,
        "typed_intro_deficit_count": len(typed_rows),
        "typed_intro_deficits": typed_rows,
        "unresolved_intro_target_root": _digest(typed_rows),
        "proposed_substitutions": substitute_rows,
        "kto_substitution_set_sha256": _digest(substitute_rows),
        "attempted_target_exclusions": [
            {
                "provider_candidate_id": row["provider_candidate_id"],
                "reason": "SUCCESS_EMPTY_TYPED_INTRO_AND_ALL_SEMANTIC_SUCCESSORS_INELIGIBLE",
            }
            for row in typed_rows
        ],
        "request_count_if_substitution_approved": (len(correction_rows) + substitute_request_count),
        "decision_options": {
            "require-kto-substitution": (
                "Approve only the displayed substitute set; Plan 49 may still "
                "stop on empty, rights-blocked, incomplete, or representation evidence."
            ),
            "stop-kto-recovery": (
                "Stop without an eligibility root or 02-47-SUMMARY; Plans 48-50 "
                "and Plan 19 remain unreachable."
            ),
        },
        "side_effects": {
            "network": False,
            "credential_read": False,
            "authority_issued_or_consumed": False,
            "nonce_created_or_consumed": False,
            "canonical_or_split_mutation": False,
        },
    }
    _assert_no_prohibited_keys(packet)
    return packet


def build_policy_decision_receipt(
    preflight: Mapping[str, object],
    *,
    selected_policy: str,
    reviewer_id: str,
    rationale: str,
) -> dict[str, str]:
    """Bind one exact human policy selection to the replayed preflight roots."""

    decision_options = preflight.get("decision_options")
    typed_rows = preflight.get("typed_intro_deficits")
    if (
        preflight.get("status") != "AWAITING_EXACT_HUMAN_DECISION"
        or not isinstance(decision_options, Mapping)
        or selected_policy not in decision_options
        or not isinstance(typed_rows, list)
        or len(typed_rows) != 3
    ):
        raise ValueError("policy decision requires the exact traffic-free preflight")
    if _REVIEWER_ID.fullmatch(reviewer_id) is None:
        raise ValueError("reviewer_id is invalid")
    if (
        not rationale
        or len(rationale) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in rationale)
    ):
        raise ValueError("rationale must be non-empty printable text")
    normalized_rationale = rationale.casefold()
    if any(token in normalized_rationale for token in _PROHIBITED_DECISION_INSTRUCTIONS):
        raise ValueError("rationale contains a prohibited instruction")

    predecessors: list[object] = []
    actual_type_evidence: list[object] = []
    for row in typed_rows:
        if (
            not isinstance(row, Mapping)
            or row.get("reinforcement_18_eligibility") != "INELIGIBLE"
            or row.get("semantic_successor_eligibility") != "INELIGIBLE"
            or row.get("permitted_resolution") != "EXACT_KTO_TARGET_SUBSTITUTION_OR_STOP"
        ):
            raise ValueError("typed Intro policy was reclassified")
        predecessors.append(row.get("predecessor"))
        actual_type_evidence.append(row.get("actual_type_evidence"))

    required_roots = (
        "policy_version",
        "unresolved_intro_target_root",
        "kto_substitution_set_sha256",
        "kto_contract_sha256",
        "kto_allowlist_revision_sha256",
    )
    if any(not isinstance(preflight.get(field), str) for field in required_roots):
        raise ValueError("preflight decision roots are missing")

    receipt = {
        "actual_type_evidence_root": _digest(actual_type_evidence),
        "kto_allowlist_revision_sha256": str(preflight["kto_allowlist_revision_sha256"]),
        "kto_contract_sha256": str(preflight["kto_contract_sha256"]),
        "kto_substitution_set_sha256": str(preflight["kto_substitution_set_sha256"]),
        "policy_version": str(preflight["policy_version"]),
        "rationale": rationale,
        "reviewer_id": reviewer_id,
        "selected_policy": selected_policy,
        "typed_intro_predecessor_root": _digest(predecessors),
        "unresolved_intro_target_root": str(preflight["unresolved_intro_target_root"]),
    }
    if set(receipt) != _DECISION_FIELDS:
        raise AssertionError("policy decision receipt field set drifted")
    _assert_no_prohibited_keys(receipt)
    return receipt


def publish_policy_decision_receipt(
    *,
    repository_root: Path | str,
    selected_policy: str,
    reviewer_id: str,
    rationale: str,
    output_base: Path | str | None = None,
) -> Path:
    """Publish one canonical 0700/0600 digest-addressed decision receipt."""

    root = Path(repository_root).resolve(strict=True)
    preflight = build_traffic_free_preflight(root)
    receipt = build_policy_decision_receipt(
        preflight,
        selected_policy=selected_policy,
        reviewer_id=reviewer_id,
        rationale=rationale,
    )
    payload = canonical_json_bytes(receipt)
    receipt_sha256 = _sha256_bytes(payload)
    base = (
        root / DECISION_BASE_REL
        if output_base is None
        else Path(output_base).expanduser().resolve()
    )
    destination = base / receipt_sha256
    _publish_private_files(
        destination=destination,
        files={"policy-decision.json": payload},
        temporary_prefix=".kto-decision-",
    )
    verify_policy_decision_receipt(root, destination)
    return destination


def verify_policy_decision_receipt(
    repository_root: Path | str,
    receipt_root: Path | str,
) -> dict[str, str]:
    """Independently replay and verify an immutable policy decision receipt."""

    root = Path(repository_root).resolve(strict=True)
    published = Path(receipt_root).resolve(strict=True)
    _assert_private_directory(
        published,
        expected_files={"policy-decision.json"},
    )
    receipt_value, receipt_file_sha256 = _read_regular_json(published / "policy-decision.json")
    if (
        set(receipt_value) != _DECISION_FIELDS
        or published.name != receipt_file_sha256
        or receipt_file_sha256 != _sha256_bytes(canonical_json_bytes(receipt_value))
    ):
        raise ValueError("policy decision receipt is not exact canonical bytes")
    selected_policy = receipt_value.get("selected_policy")
    reviewer_id = receipt_value.get("reviewer_id")
    rationale = receipt_value.get("rationale")
    if not all(isinstance(value, str) for value in (selected_policy, reviewer_id, rationale)):
        raise ValueError("policy decision receipt text fields are invalid")
    rebuilt = build_policy_decision_receipt(
        build_traffic_free_preflight(root),
        selected_policy=str(selected_policy),
        reviewer_id=str(reviewer_id),
        rationale=str(rationale),
    )
    if receipt_value != rebuilt:
        raise ValueError("policy decision receipt differs from independent replay")
    return {key: str(value) for key, value in receipt_value.items()}


def build_kto_eligibility_generation(
    repository_root: Path | str,
    decision_receipt_root: Path | str,
) -> KtoEligibilityGeneration:
    """Build the exact decision-bound, secret-free Plan 48 request packet."""

    root = Path(repository_root).resolve(strict=True)
    receipt_root = Path(decision_receipt_root).resolve(strict=True)
    receipt = verify_policy_decision_receipt(root, receipt_root)
    if receipt["selected_policy"] != "require-kto-substitution":
        raise ValueError("stop-kto-recovery cannot produce an eligibility root")
    preflight = build_traffic_free_preflight(root)
    corrections = preflight.get("common_image_corrections")
    substitutions = preflight.get("proposed_substitutions")
    typed_rows = preflight.get("typed_intro_deficits")
    correction_count = preflight.get("common_image_correction_count")
    expected_request_count = preflight.get("request_count_if_substitution_approved")
    if (
        not isinstance(corrections, list)
        or not isinstance(substitutions, list)
        or not isinstance(typed_rows, list)
        or not isinstance(correction_count, int)
        or not isinstance(expected_request_count, int)
    ):
        raise ValueError("preflight request rows are missing")

    substitute_requests: list[object] = []
    for substitution in substitutions:
        if not isinstance(substitution, Mapping):
            raise ValueError("KTO substitution row must be an object")
        request_rows = substitution.get("request_rows")
        operations = substitution.get("operations")
        if (
            not isinstance(request_rows, list)
            or not isinstance(operations, list)
            or len(request_rows) != len(operations)
        ):
            raise ValueError("KTO substitution request rows are incomplete")
        substitute_requests.extend(request_rows)
    requests = [*corrections, *substitute_requests]
    request_count = len(requests)
    request_identities = [
        row.get("request_identity") if isinstance(row, Mapping) else None for row in requests
    ]
    if (
        request_count != expected_request_count
        or request_count != correction_count + len(substitute_requests)
        or any(not isinstance(identity, str) for identity in request_identities)
        or len(set(request_identities)) != request_count
    ):
        raise ValueError("KTO request count or identity set was caller-patched")
    typed_target_ids = {
        str(row["provider_candidate_id"]) for row in typed_rows if isinstance(row, Mapping)
    }
    if any(
        not isinstance(row, Mapping)
        or row.get("operation") not in {"detailCommon2", "detailImage2"}
        or row.get("provider_candidate_id") in typed_target_ids
        for row in requests
    ):
        raise ValueError("typed Intro predecessor or successor entered the request packet")

    typed_intro_policy = {
        "classification": "PERMANENTLY_INELIGIBLE",
        "permitted_resolution": "EXACT_KTO_TARGET_SUBSTITUTION_OR_STOP",
        "policy_version": receipt["policy_version"],
        "unresolved_intro_target_root": receipt["unresolved_intro_target_root"],
    }
    typed_intro_policy_sha256 = _digest(typed_intro_policy)
    contract_pins = preflight["official_contract"]
    operation_allowlists = preflight["operation_allowlists"]
    if (
        _digest(contract_pins) != receipt["kto_contract_sha256"]
        or _digest(operation_allowlists) != receipt["kto_allowlist_revision_sha256"]
        or preflight["kto_substitution_set_sha256"] != receipt["kto_substitution_set_sha256"]
    ):
        raise ValueError("decision receipt roots drifted from the frozen preflight")

    eligibility = {
        "schema_version": "itda.kto-recovery-eligibility.v1",
        "status": "SUCCESS",
        "target_count": preflight["target_count"],
        "common_image_correction_count": preflight["common_image_correction_count"],
        "common_image_corrections_sha256": preflight["common_image_corrections_sha256"],
        "typed_intro_deficit_count": preflight["typed_intro_deficit_count"],
        "typed_intro_policy": "PERMANENTLY_INELIGIBLE",
        "typed_intro_policy_sha256": typed_intro_policy_sha256,
        "unresolved_intro_target_root": receipt["unresolved_intro_target_root"],
        "kto_substitution_set_sha256": receipt["kto_substitution_set_sha256"],
        "substitute_target_count": len(substitutions),
        "substitute_request_count": len(substitute_requests),
        "request_count": request_count,
        "plan48_reachable": True,
    }
    policy_ref = {
        "schema_version": "itda.kto-recovery-policy-decision-ref.v1",
        "decision_receipt_sha256": receipt_root.name,
        "selected_policy": receipt["selected_policy"],
        "policy_version": receipt["policy_version"],
        "reviewer_id": receipt["reviewer_id"],
        "rationale_sha256": _sha256_bytes(receipt["rationale"].encode("utf-8")),
        "unresolved_intro_target_root": receipt["unresolved_intro_target_root"],
        "typed_intro_predecessor_root": receipt["typed_intro_predecessor_root"],
        "actual_type_evidence_root": receipt["actual_type_evidence_root"],
        "kto_substitution_set_sha256": receipt["kto_substitution_set_sha256"],
    }
    request_manifest = {
        "schema_version": "itda.kto-recovery-request-manifest.v1",
        "base_url": KOR_SERVICE2_BASE_URL,
        "kto_contract_sha256": receipt["kto_contract_sha256"],
        "kto_allowlist_revision_sha256": receipt["kto_allowlist_revision_sha256"],
        "decision_receipt_sha256": receipt_root.name,
        "request_count": request_count,
        "requests": requests,
        "attempt_policy": {
            "per_attempt_timeout_seconds": 300,
            "maximum_total_attempts": 3,
            "redirects_allowed": False,
            "retryable_outcomes": [
                "TRANSIENT_TRANSPORT",
                "HTTP_408",
                "HTTP_429",
                "HTTP_5XX",
                "TRANSIENT_PROVIDER_CODE",
            ],
        },
        "diagnostics_schema": [
            "provider",
            "operation",
            "secret_free_request_identity",
            "attempt_ordinal",
            "attempt_started_at",
            "attempt_completed_at",
            "http_status",
            "safe_response_headers",
            "provider_result_code",
            "provider_result_value",
            "raw_body_size",
            "raw_body_sha256",
            "normalized_outcome",
            "normalized_reason",
            "publication_path",
            "publication_sha256",
        ],
    }
    child_values = {
        "contract-pins.json": contract_pins,
        "operation-allowlists.json": operation_allowlists,
        "eligibility.json": eligibility,
        "policy-decision-ref.json": policy_ref,
        "request-manifest.json": request_manifest,
    }
    files = {name: canonical_json_bytes(value) for name, value in child_values.items()}
    child_inventory = [
        {
            "path": name,
            "sha256": _sha256_bytes(payload),
            "size": len(payload),
            "mode": "0600",
        }
        for name, payload in sorted(files.items())
    ]
    root_payload = {
        "schema_version": "itda.kto-recovery-root-manifest.v1",
        "status": "SUCCESS",
        "decision_receipt_sha256": receipt_root.name,
        "typed_intro_policy_sha256": typed_intro_policy_sha256,
        "kto_substitution_set_sha256": receipt["kto_substitution_set_sha256"],
        "request_manifest_sha256": _sha256_bytes(files["request-manifest.json"]),
        "request_count": request_count,
        "plan48_reachable": True,
        "files": child_inventory,
    }
    root_sha256 = _digest(root_payload)
    files["root-manifest.json"] = canonical_json_bytes(
        {
            "payload": root_payload,
            "root_sha256": root_sha256,
        }
    )
    if set(files) != _ELIGIBILITY_FILES:
        raise AssertionError("KTO eligibility child inventory drifted")
    for value in child_values.values():
        _assert_no_prohibited_keys(value)
    _assert_no_prohibited_keys(root_payload)
    return KtoEligibilityGeneration(root_sha256=root_sha256, files=files)


def verify_kto_eligibility_root(
    repository_root: Path | str,
    eligibility_root: Path | str,
    *,
    decision_receipt_root: Path | str,
) -> KtoEligibilityGeneration:
    """Rebuild and compare a published eligibility root byte for byte."""

    root = Path(repository_root).resolve(strict=True)
    published = Path(eligibility_root).resolve(strict=True)
    _assert_private_directory(published, expected_files=_ELIGIBILITY_FILES)
    actual_files: dict[str, bytes] = {}
    actual_hashes: dict[str, str] = {}
    actual_sizes: dict[str, int] = {}
    for name in sorted(_ELIGIBILITY_FILES):
        value, file_sha256 = _read_regular_json(published / name)
        canonical = canonical_json_bytes(value)
        if _sha256_bytes(canonical) != file_sha256:
            raise ValueError("published KTO eligibility child is not canonical JSON")
        actual_files[name] = canonical
        actual_hashes[name] = file_sha256
        actual_sizes[name] = len(canonical)
    root_manifest = json.loads(actual_files["root-manifest.json"])
    if (
        not isinstance(root_manifest, Mapping)
        or set(root_manifest) != {"payload", "root_sha256"}
        or not isinstance(root_manifest["payload"], Mapping)
        or root_manifest["root_sha256"] != published.name
        or _digest(root_manifest["payload"]) != published.name
    ):
        raise ValueError("KTO eligibility root manifest identity drifted")
    root_payload = root_manifest["payload"]
    inventory = root_payload.get("files")
    expected_inventory = [
        {
            "path": name,
            "sha256": actual_hashes[name],
            "size": actual_sizes[name],
            "mode": "0600",
        }
        for name in sorted(_ELIGIBILITY_FILES - {"root-manifest.json"})
    ]
    if (
        root_payload.get("status") != "SUCCESS"
        or root_payload.get("plan48_reachable") is not True
        or inventory != expected_inventory
    ):
        raise ValueError("KTO eligibility root manifest inventory drifted")
    rebuilt = build_kto_eligibility_generation(
        root,
        decision_receipt_root,
    )
    if rebuilt.root_sha256 != published.name or dict(rebuilt.files) != actual_files:
        raise ValueError("published KTO eligibility differs from independent replay")
    return rebuilt


def publish_kto_eligibility_generation(
    generation: KtoEligibilityGeneration,
    *,
    repository_root: Path | str,
    decision_receipt_root: Path | str,
    output_base: Path | str | None = None,
) -> Path:
    """Atomically publish one independently rederived eligibility generation."""

    root = Path(repository_root).resolve(strict=True)
    receipt_root = Path(decision_receipt_root).resolve(strict=True)
    rebuilt = build_kto_eligibility_generation(root, receipt_root)
    if generation != rebuilt:
        raise ValueError("caller-supplied KTO eligibility generation was patched")
    base = (
        root / ELIGIBILITY_BASE_REL
        if output_base is None
        else Path(output_base).expanduser().resolve()
    )
    destination = base / generation.root_sha256
    _publish_private_files(
        destination=destination,
        files=generation.files,
        temporary_prefix=".kto-eligibility-",
    )
    verify_kto_eligibility_root(
        root,
        destination,
        decision_receipt_root=receipt_root,
    )
    return destination


def discover_exact_kto_eligibility_success(
    repository_root: Path | str,
    eligibility_base: Path | str,
    *,
    decision_receipt_root: Path | str | None = None,
) -> Path:
    """Find and fully replay exactly one direct successful eligibility root."""

    root = Path(repository_root).resolve(strict=True)
    base = Path(eligibility_base).resolve(strict=True)
    if base.is_symlink() or not base.is_dir():
        raise ValueError("KTO eligibility base must be a no-follow directory")
    candidates = [
        entry
        for entry in base.iterdir()
        if not entry.is_symlink() and entry.is_dir() and _HEX64.fullmatch(entry.name) is not None
    ]
    if len(candidates) != 1 or len(list(base.iterdir())) != 1:
        raise ValueError("expected exactly one direct KTO eligibility success root")
    candidate = candidates[0]
    receipt_root: Path
    if decision_receipt_root is None:
        policy_ref, _ = _read_regular_json(candidate / "policy-decision-ref.json")
        receipt_sha256 = policy_ref.get("decision_receipt_sha256")
        if not isinstance(receipt_sha256, str) or _HEX64.fullmatch(receipt_sha256) is None:
            raise ValueError("eligibility policy decision reference is invalid")
        receipt_root = root / DECISION_BASE_REL / receipt_sha256
    else:
        receipt_root = Path(decision_receipt_root).resolve(strict=True)
    verify_kto_eligibility_root(
        root,
        candidate,
        decision_receipt_root=receipt_root,
    )
    return candidate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--discover-exact-success-under", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.repo_root.resolve(strict=True)
    if args.preflight:
        if args.discover_exact_success_under is not None:
            raise ValueError("--preflight does not accept exact-success discovery")
        packet = build_traffic_free_preflight(root)
        print(canonical_json_bytes(packet).decode("utf-8"), end="")
        return 0
    if args.discover_exact_success_under is None:
        raise ValueError("--check requires --discover-exact-success-under")
    expected_base = (root / ELIGIBILITY_BASE_REL).resolve(strict=True)
    requested_base = args.discover_exact_success_under.resolve(strict=True)
    if requested_base != expected_base:
        raise ValueError("exact-success discovery is outside the fixed eligibility base")
    published = discover_exact_kto_eligibility_success(root, requested_base)
    root_manifest, _ = _read_regular_json(published / "root-manifest.json")
    payload = root_manifest["payload"]
    if not isinstance(payload, Mapping):
        raise ValueError("verified root manifest payload is invalid")
    result = {
        "kto_eligibility_root": published.name,
        "plan48_reachable": payload["plan48_reachable"],
        "request_count": payload["request_count"],
        "status": payload["status"],
    }
    print(canonical_json_bytes(result).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
