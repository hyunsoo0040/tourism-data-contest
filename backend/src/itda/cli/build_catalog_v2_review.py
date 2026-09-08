"""Build and verify the success-only Plan 20 review bridge."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from itda.cli.build_catalog_contest_profile import (
    NETWORK_DENIAL_POLICY_SHA256,
    _parse_existing_result,
    load_canonical_json_nofollow,
    mode_security_roots,
    verify_historical_lineage,
)
from itda.cli.freeze_preview import (
    PublicationStateUncertainError,
    prepared_directory_snapshot,
    publish_immutable_directory,
)
from itda.contracts.authority import (
    AuthorityConsumptionReceipt,
    AuthorityIssuanceContext,
    FileNonceLedger,
    validate_authority_token,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REVIEW_FILENAMES = (
    "catalog-review-request.json",
    "catalog-review-view.json",
    "catalog-state-attestation.json",
)
ADJUDICATION_FILENAMES = (
    "catalog-adjudication-selection-target.json",
    "catalog-adjudication.json",
    "catalog-selection.json",
    "authoritative-relationship-leaves.json",
    "catalog-adjudication-bundle.json",
)
GROUP_ORDER = (
    "history_culture",
    "history_scenery_boundary",
    "image_modern_content",
    "rest_walk_immersion",
)
PLAN55_HANDOFF_ROOT_FIELDS = (
    "contest_policy_sha256",
    "contest_rights_root_sha256",
    "official_dataset_grants_root_sha256",
    "asset_exclusions_root_sha256",
    "complete_universe_root_sha256",
    "pre_handoff_content_sha256",
    "first_replay_sha256",
    "second_replay_sha256",
    "eligible_pool_sha256",
    "exact_36_sha256",
    "quota_proof_sha256",
    "missingness_state_root_sha256",
    "warning_state_root_sha256",
    "confidence_state_root_sha256",
    "commercial_review_requirement_sha256",
    "immutable_parents_root_sha256",
)
CAPTURED_MODE_SECURITY_FIELDS = (
    "execution_mode",
    "network_denial_policy_sha256",
    "null_authority_state_sha256",
    "null_credential_state_sha256",
    "provider_attempt_inventory_sha256",
)
PHASE_REL = Path(".planning/phases/02-canonical-36-rights-and-evaluation-manifest")
PLAN55_SUMMARY_REL = PHASE_REL / "02-55-SUMMARY.md"
GENERATION_BASE_REL = Path(
    "artifacts/restricted/catalog/contest-use-official-public-data-v1/generations"
)
BRIDGE_BASE_REL = Path("artifacts/restricted/catalog/v2/review/plan54-bridges")
ADJUDICATION_BASE_REL = Path("artifacts/restricted/catalog/v2/review/adjudication-bundles")
FORBIDDEN_PREDECESSOR_SUMMARIES = tuple(
    PHASE_REL / f"02-{number}-SUMMARY.md" for number in (19, 49, 50)
)
EXPECTED_GROUP_COUNTS = {
    "history_culture": 13,
    "history_scenery_boundary": 6,
    "image_modern_content": 8,
    "rest_walk_immersion": 13,
}
EXPECTED_QUOTAS = {
    "history_culture": 12,
    "history_scenery_boundary": 6,
    "image_modern_content": 7,
    "rest_walk_immersion": 11,
}
CONTEST_SCOPE = "noncommercial_contest_demo_evaluation"
POLICY_VERSION = "contest-use-official-public-data-v1"


def _without(value: Mapping[str, object], field: str) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != field}


def _require_digest(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} is not a canonical SHA-256 digest")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mode(metadata: os.stat_result) -> str:
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _repository_root(value: Path | str | None = None) -> Path:
    return (
        Path(value).resolve(strict=True)
        if value is not None
        else Path(__file__).resolve().parents[4]
    )


def assert_predecessor_summaries_absent(repository_root: Path | str) -> None:
    """Reject every stale/forged Summary that may not precede Plan 20."""

    root = Path(repository_root).resolve(strict=True)
    for relative in FORBIDDEN_PREDECESSOR_SUMMARIES:
        if os.path.lexists(root / relative):
            raise ValueError(f"forbidden predecessor Summary exists: {relative.name}")


def _stable_regular_bytes(path: Path, *, max_bytes: int) -> bytes:
    visible = path.lstat()
    if not stat.S_ISREG(visible.st_mode) or visible.st_nlink != 1 or visible.st_size > max_bytes:
        raise ValueError(f"{path.name} is not a bounded single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if _identity(visible) != _identity(before):
            raise ValueError(f"{path.name} identity changed before read")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                raise ValueError(f"{path.name} read was short")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{path.name} grew during read")
        after = os.fstat(descriptor)
        visible_after = path.lstat()
        if not (_identity(before) == _identity(after) == _identity(visible_after)):
            raise ValueError(f"{path.name} changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_canonical_file(
    path: Path,
    *,
    repository_root: Path,
    max_bytes: int = 100_000_000,
) -> dict[str, Any]:
    value = load_canonical_json_nofollow(
        path,
        max_bytes=max_bytes,
        repository_root=repository_root,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _summary_generation(repository_root: Path) -> str:
    path = repository_root / PLAN55_SUMMARY_REL
    raw = _stable_regular_bytes(path, max_bytes=2_000_000)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Plan 55 Summary is not UTF-8") from exc
    match = re.match(r"\A---\n(.*?)\n---\n", text, flags=re.DOTALL)
    if match is None:
        raise ValueError("Plan 55 Summary frontmatter is missing")
    frontmatter = match.group(1)
    generation = re.search(r"(?m)^contest_generation_sha256:\s*([0-9a-f]{64})\s*$", frontmatter)
    if generation is None:
        raise ValueError("Plan 55 Summary generation root is missing")
    if re.search(r"(?m)^status:\s*success\s*$", frontmatter) is None:
        raise ValueError("Plan 55 Summary is not an exact success")
    if re.search(r"(?m)^plan54_reachable:\s*true\s*$", frontmatter) is None:
        raise ValueError("Plan 55 Summary does not reach Plan 54")
    return generation.group(1)


def _ordered_lineage(leaves: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    order = (
        "02-49-TERMINAL-HISTORY.md",
        "02-49-FAILURE-RECORD.md",
        "reentry-exhausted.json",
        "02-49-SUMMARY.md",
        "02-53-PLAN.md",
        "02-53-SUMMARY.md",
        "closure-terminal.json",
    )
    return [{"leaf_id": name, **leaves[name]} for name in order]


def _generation_context(
    generation_path: Path | str,
    *,
    repository_root: Path,
) -> dict[str, Any]:
    assert_predecessor_summaries_absent(repository_root)
    supplied = Path(generation_path)
    if supplied.is_symlink():
        raise ValueError("Plan 55 generation path cannot be a symlink")
    generation = supplied.resolve(strict=True)
    expected_base = (repository_root / GENERATION_BASE_REL).resolve(strict=True)
    if generation.parent != expected_base:
        raise ValueError("Plan 55 generation is outside the exact restricted namespace")
    summary_generation = _summary_generation(repository_root)
    if generation.name != summary_generation:
        raise ValueError("Plan 55 Summary and generation basename differ")

    parsed_generation = _parse_existing_result(generation, repository_root=repository_root)
    if parsed_generation.publication_state != "SUCCESS" or parsed_generation.exit_code != 0:
        raise ValueError("Plan 55 generation is not a success generation")
    if parsed_generation.generation_sha256 != generation.name:
        raise ValueError("Plan 55 outer generation descriptor differs")

    manifest = _load_canonical_file(
        generation / "generation-manifest.json", repository_root=repository_root
    )
    handoff = _load_canonical_file(
        generation / "plan54-handoff.json", repository_root=repository_root
    )
    policy = _load_canonical_file(generation / "policy.json", repository_root=repository_root)
    source_grants = _load_canonical_file(
        generation / "source-grants.json", repository_root=repository_root
    )
    accounting = _load_canonical_file(
        generation / "candidate-accounting.json", repository_root=repository_root
    )
    frontier = _load_canonical_file(
        generation / "selection-frontier.json", repository_root=repository_root
    )
    first = _load_canonical_file(generation / "first-replay.json", repository_root=repository_root)
    second = _load_canonical_file(
        generation / "second-replay.json", repository_root=repository_root
    )

    if "contest_generation_sha256" in handoff:
        raise ValueError("Plan 55 handoff injected the self-referential outer root")
    if handoff.get("schema_version") != "itda.catalog-contest-use-plan54-handoff.v1":
        raise ValueError("Plan 55 handoff schema differs")
    if (
        handoff.get("scope") != CONTEST_SCOPE
        or handoff.get("commercial_production_rights_review_required") is not True
        or handoff.get("execution_mode") != "captured_replay"
        or handoff.get("authority_required") is not False
        or handoff.get("credential_required") is not False
        or handoff.get("provider_traffic_allowed") is not False
        or handoff.get("provider_attempt_inventory") != []
        or handoff.get("plan54_reachable") is not True
    ):
        raise ValueError("Plan 55 captured handoff capability or scope differs")

    expected_mode_roots = mode_security_roots(NETWORK_DENIAL_POLICY_SHA256)
    if tuple(handoff.get("mode_security_roots", {})) != CAPTURED_MODE_SECURITY_FIELDS:
        raise ValueError("captured mode-security key set differs")
    if handoff.get("mode_security_roots") != expected_mode_roots:
        raise ValueError("captured mode-security roots differ")
    handoff_mode_digest = _require_digest(
        handoff.get("mode_security_roots_sha256"), field="handoff mode-security digest"
    )
    if parsed_generation.mode_security_roots_sha256 != handoff_mode_digest:
        raise ValueError("generation receipt mode-security digest differs")

    handoff_roots = {
        field: _require_digest(handoff.get(field), field=field)
        for field in PLAN55_HANDOFF_ROOT_FIELDS
    }
    plan55_roots = {
        **handoff_roots,
        "contest_generation_sha256": generation.name,
    }
    if tuple(plan55_roots) != (
        *PLAN55_HANDOFF_ROOT_FIELDS,
        "contest_generation_sha256",
    ):
        raise ValueError("Plan 55 downstream root order differs")

    if policy.get("policy_sha256") != handoff_roots["contest_policy_sha256"]:
        raise ValueError("Plan 55 policy root binding differs")
    policy_links = {
        "contest_rights_root_sha256": "contest_rights_root_sha256",
        "official_dataset_grants_root_sha256": "official_dataset_grants_root_sha256",
        "asset_exclusions_root_sha256": "asset_exclusions_root_sha256",
        "complete_universe_root_sha256": "complete_universe_root_sha256",
        "missingness_state_root_sha256": "missingness_state_root_sha256",
        "warning_state_root_sha256": "warning_state_root_sha256",
        "confidence_state_root_sha256": "confidence_state_root_sha256",
        "commercial_review_requirement_sha256": ("commercial_review_requirement_sha256"),
        "immutable_parents_root_sha256": "immutable_parents_root_sha256",
    }
    if any(
        policy.get(policy_field) != handoff_roots[root_field]
        for policy_field, root_field in policy_links.items()
    ):
        raise ValueError("Plan 55 policy/handoff root binding differs")
    if (
        source_grants.get("official_dataset_grants_root_sha256")
        != handoff_roots["official_dataset_grants_root_sha256"]
    ):
        raise ValueError("Plan 55 official dataset grant binding differs")
    if any(
        accounting.get(field) != handoff_roots[field]
        for field in (
            "missingness_state_root_sha256",
            "warning_state_root_sha256",
            "confidence_state_root_sha256",
        )
    ):
        raise ValueError("Plan 55 missingness/warning/confidence binding differs")

    historical = _ordered_lineage(verify_historical_lineage(repository_root))
    if manifest.get("ordered_parents") != historical:
        raise ValueError("Plan 49/53 immutable parent leaves drifted")
    if canonical_sha256(historical) != handoff_roots["immutable_parents_root_sha256"]:
        raise ValueError("Plan 49/53 immutable parent root differs")

    if (
        first.get("replay_content_sha256") != second.get("replay_content_sha256")
        or first.get("replay_sha256") != handoff_roots["first_replay_sha256"]
        or second.get("replay_sha256") != handoff_roots["second_replay_sha256"]
        or handoff_roots["first_replay_sha256"] != handoff_roots["second_replay_sha256"]
    ):
        raise ValueError("Plan 55 full-universe replay roots differ")
    if (
        frontier.get("eligible_candidate_count") != 40
        or frontier.get("eligible_group_counts") != EXPECTED_GROUP_COUNTS
        or frontier.get("capped_capacity") != 38
        or frontier.get("final_quotas") != EXPECTED_QUOTAS
        or frontier.get("selectable_candidate_count") != 36
        or frontier.get("preview_is_canonical_catalog") is not False
        or frontier.get("human_choice_and_order_required") is not True
        or frontier.get("confidence_used_for_selection") is not False
        or frontier.get("popularity_used_for_selection") is not False
    ):
        raise ValueError("Plan 55 exact 40/count/capacity/quota proof differs")
    eligible_pool = frontier.get("eligible_pool")
    preview_ids = frontier.get("noncanonical_preview_ids")
    human_decision_count = frontier.get("human_decision_count")
    if (
        not isinstance(eligible_pool, list)
        or len(eligible_pool) != 40
        or canonical_sha256(eligible_pool) != handoff_roots["eligible_pool_sha256"]
        or not isinstance(preview_ids, list)
        or len(preview_ids) != 36
        or len(set(preview_ids)) != 36
        or canonical_sha256(preview_ids) != handoff_roots["exact_36_sha256"]
        or not isinstance(human_decision_count, int)
        or isinstance(human_decision_count, bool)
        or not 0 <= human_decision_count <= 6
    ):
        raise ValueError("Plan 55 eligible pool or non-canonical preview differs")

    manifest_bytes = canonical_json_bytes(manifest)
    normalized_descriptor = {
        "schema_version": "itda.catalog-contest-use-closure-evidence.v1",
        "scope": CONTEST_SCOPE,
        "execution_mode": "captured_replay",
        "plan55_roots": plan55_roots,
        "plan55_roots_sha256": canonical_sha256(plan55_roots),
        "mode_security_roots": expected_mode_roots,
        "mode_security_roots_sha256": handoff_mode_digest,
        "eligible_candidate_count": 40,
        "eligible_group_counts": EXPECTED_GROUP_COUNTS,
        "capped_capacity": 38,
        "exact_quotas": EXPECTED_QUOTAS,
        "selectable_candidate_count": 36,
        "human_decision_count": human_decision_count,
    }
    return {
        "generation": generation,
        "generation_manifest_path": (
            GENERATION_BASE_REL / generation.name / "generation-manifest.json"
        ).as_posix(),
        "generation_manifest_file_sha256": _sha256_bytes(manifest_bytes),
        "plan55_roots": plan55_roots,
        "plan55_roots_sha256": canonical_sha256(plan55_roots),
        "mode_security_roots": expected_mode_roots,
        "handoff_mode_security_roots_sha256": handoff_mode_digest,
        "mode_security_roots_sha256": handoff_mode_digest,
        "normalized_evidence_root": canonical_sha256(normalized_descriptor),
        "first_readiness_root": first["replay_content_sha256"],
        "second_readiness_root": second["replay_content_sha256"],
        "eligible_pool": eligible_pool,
        "preview_ids": preview_ids,
        "human_decision_count": human_decision_count,
    }


def _bridge_payloads(context: Mapping[str, Any]) -> dict[str, dict[str, object]]:
    common: dict[str, object] = {
        "scope": CONTEST_SCOPE,
        "commercial_production_rights_review_required": True,
        "execution_mode": "captured_replay",
        "policy_version": POLICY_VERSION,
        "normalized_evidence_schema": ("itda.catalog-contest-use-closure-evidence.v1"),
        "normalized_evidence_root": context["normalized_evidence_root"],
        "generation_manifest_path": context["generation_manifest_path"],
        "generation_manifest_file_sha256": context["generation_manifest_file_sha256"],
        "plan55_roots": context["plan55_roots"],
        "plan55_roots_sha256": context["plan55_roots_sha256"],
        "mode_security_roots": context["mode_security_roots"],
        "handoff_mode_security_roots_sha256": context["handoff_mode_security_roots_sha256"],
        "mode_security_roots_sha256": context["mode_security_roots_sha256"],
        "first_readiness_root": context["first_readiness_root"],
        "second_readiness_root": context["second_readiness_root"],
        "eligible_count": 40,
        "eligible_group_counts": EXPECTED_GROUP_COUNTS,
        "capped_capacity": 38,
        "exact_quotas": EXPECTED_QUOTAS,
        "quota_sum": 36,
        "selectable_candidate_count": 36,
        "human_decision_count": context["human_decision_count"],
        "preview_is_canonical_catalog": False,
        "human_choice_and_order_required": True,
        "plan20_reachable": True,
    }
    closure_binding = canonical_sha256(
        {
            "schema_version": "itda.catalog-contest-use-closure-binding.v1",
            **common,
        }
    )
    common["closure_binding_sha256"] = closure_binding
    request_fields: dict[str, object] = {
        "schema_version": "itda.catalog-v2-contest-review-request.v1",
        "operation": "catalog-adjudicate-select",
        **common,
        "eligible_pool": context["eligible_pool"],
        "noncanonical_preview_ids": context["preview_ids"],
        "catalog_membership_selected": False,
        "authority_issued": False,
    }
    request = {
        **request_fields,
        "request_sha256": canonical_sha256(request_fields),
    }
    state_fields: dict[str, object] = {
        "schema_version": "itda.catalog-v2-contest-review-state-attestation.v1",
        "request_sha256": request["request_sha256"],
        **common,
    }
    state = {
        **state_fields,
        "state_attestation_sha256": canonical_sha256(state_fields),
    }
    view_fields: dict[str, object] = {
        "schema_version": "itda.catalog-v2-contest-review-view.v1",
        "request_sha256": request["request_sha256"],
        "state_attestation_sha256": state["state_attestation_sha256"],
        **common,
        "eligible_place_ids": [
            row["place_entity_id"] for row in context["eligible_pool"] if isinstance(row, Mapping)
        ],
        "noncanonical_preview_ids": context["preview_ids"],
        "informational_only": True,
    }
    view = {**view_fields, "view_sha256": canonical_sha256(view_fields)}
    return {
        "catalog-review-request.json": request,
        "catalog-review-view.json": view,
        "catalog-state-attestation.json": state,
    }


def _bridge_descriptor(
    payloads: Mapping[str, Mapping[str, object]],
) -> tuple[dict[str, object], str]:
    if tuple(sorted(payloads)) != tuple(sorted(REVIEW_FILENAMES)):
        raise ValueError("Plan 20 bridge inventory is not exactly three files")
    inventory = [
        {
            "relpath": name,
            "entry_type": "regular_file",
            "mode": "0600",
            "size_bytes": len(canonical_json_bytes(payloads[name])),
            "file_sha256": _sha256_bytes(canonical_json_bytes(payloads[name])),
        }
        for name in sorted(payloads)
    ]
    descriptor: dict[str, object] = {
        "schema_version": "itda.catalog-plan54-bridge-descriptor.v1",
        "payload_inventory": inventory,
    }
    return descriptor, canonical_sha256(descriptor)


def prepare_contest_closure(
    generation_path: Path | str,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, object]:
    """Prepare every final bridge and closure byte without publishing any byte."""

    root = _repository_root(repository_root)
    context = _generation_context(generation_path, repository_root=root)
    payloads = _bridge_payloads(context)
    _, bridge_root = _bridge_descriptor(payloads)
    bridge_rel = (BRIDGE_BASE_REL / bridge_root).as_posix()
    request = payloads["catalog-review-request.json"]
    state = payloads["catalog-state-attestation.json"]
    view = payloads["catalog-review-view.json"]
    fields: dict[str, object] = {
        "schema_version": "itda.catalog-contest-use-closure-result.v1",
        "status": "success",
        "policy_version": POLICY_VERSION,
        "scope": CONTEST_SCOPE,
        "commercial_production_rights_review_required": True,
        "execution_mode": "captured_replay",
        "normalized_evidence_schema": ("itda.catalog-contest-use-closure-evidence.v1"),
        "normalized_evidence_root": context["normalized_evidence_root"],
        "contest_generation_sha256": context["generation"].name,
        "generation_directory": (GENERATION_BASE_REL / context["generation"].name).as_posix(),
        "generation_manifest_path": context["generation_manifest_path"],
        "generation_manifest_file_sha256": context["generation_manifest_file_sha256"],
        "first_readiness_root": context["first_readiness_root"],
        "second_readiness_root": context["second_readiness_root"],
        "replays_byte_identical": True,
        "eligible_count": 40,
        "eligible_group_counts": EXPECTED_GROUP_COUNTS,
        "capped_capacity": 38,
        "exact_quotas": EXPECTED_QUOTAS,
        "quota_sum": 36,
        "selectable_candidate_count": 36,
        "human_decision_count": context["human_decision_count"],
        "preview_is_canonical_catalog": False,
        "human_choice_and_order_required": True,
        "plan55_roots": context["plan55_roots"],
        "plan55_roots_sha256": context["plan55_roots_sha256"],
        "mode_security_roots": context["mode_security_roots"],
        "handoff_mode_security_roots_sha256": context["handoff_mode_security_roots_sha256"],
        "mode_security_roots_sha256": context["mode_security_roots_sha256"],
        "closure_binding_sha256": request["closure_binding_sha256"],
        "bridge_directory": bridge_rel,
        "bridge_root_sha256": bridge_root,
        "bridge_payloads": payloads,
        "catalog_review_request_sha256": request["request_sha256"],
        "catalog_state_attestation_sha256": state["state_attestation_sha256"],
        "catalog_review_view_sha256": view["view_sha256"],
        "plan20_reachable": True,
    }
    return {**fields, "closure_result_sha256": canonical_sha256(fields)}


def verify_plan54_success(
    finalization: Mapping[str, object],
    *,
    repository_root: Path | str | None = None,
) -> dict[str, object]:
    """Independently reconstruct the exact contest closure before publication."""

    root = _repository_root(repository_root)
    assert_predecessor_summaries_absent(root)
    value = dict(finalization)
    if value.get("schema_version") != "itda.catalog-contest-use-closure-result.v1":
        raise ValueError("active Plan 54 closure schema is not the contest schema")
    if value.get("status") != "success" or value.get("plan20_reachable") is not True:
        raise ValueError("Plan 20 bridge requires exact contest closure success")
    expected_digest = canonical_sha256(_without(value, "closure_result_sha256"))
    if value.get("closure_result_sha256") != expected_digest:
        raise ValueError("Plan 54 contest closure digest is stale")
    roots = value.get("plan55_roots")
    if (
        not isinstance(roots, Mapping)
        or set(roots) != {*PLAN55_HANDOFF_ROOT_FIELDS, "contest_generation_sha256"}
        or value.get("plan55_roots_sha256") != canonical_sha256(roots)
    ):
        raise ValueError("Plan 54 Plan 55 root key set or digest differs")
    mode_roots = value.get("mode_security_roots")
    if (
        not isinstance(mode_roots, Mapping)
        or set(mode_roots) != set(CAPTURED_MODE_SECURITY_FIELDS)
        or dict(mode_roots) != mode_security_roots(NETWORK_DENIAL_POLICY_SHA256)
        or value.get("handoff_mode_security_roots_sha256")
        != value.get("mode_security_roots_sha256")
    ):
        raise ValueError("Plan 54 captured mode-security key set differs")
    generation_rel = value.get("generation_directory")
    if not isinstance(generation_rel, str):
        raise ValueError("Plan 54 generation directory is missing")
    generation = root / generation_rel
    expected = prepare_contest_closure(generation, repository_root=root)
    if canonical_json_bytes(value) != canonical_json_bytes(expected):
        raise ValueError("Plan 54 closure differs from independently derived Plan 55 roots")
    return expected


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while publishing Plan 54 artifact")
        offset += written


def _create_private_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_existing_closure(path: Path, intended: bytes) -> None:
    visible = path.lstat()
    if not stat.S_ISREG(visible.st_mode) or _mode(visible) != "0600" or visible.st_nlink != 1:
        raise FileExistsError("existing closure result type, mode, or link count differs")
    actual = _stable_regular_bytes(path, max_bytes=100_000_000)
    if actual != intended:
        raise FileExistsError("existing closure result bytes differ")


def publish_closure_result(closure: Mapping[str, object], destination: Path | str) -> str:
    """Atomically install already-final closure bytes without replacement."""

    output = Path(destination)
    payload = canonical_json_bytes(dict(closure))
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise ValueError("closure result parent must be a regular directory")
    if os.path.lexists(output):
        _verify_existing_closure(output, payload)
        return "ALREADY_PRESENT_VERIFIED"
    temporary = output.parent / f".{output.name}.prepared-{os.getpid()}"
    if os.path.lexists(temporary):
        raise FileExistsError("closure result staging path already exists")
    try:
        _create_private_file(temporary, payload)
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError:
            _verify_existing_closure(output, payload)
            return "ALREADY_PRESENT_VERIFIED"
        os.unlink(temporary)
        _fsync_directory(output.parent)
        _verify_existing_closure(output, payload)
        return "PUBLISHED"
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _stable_bundle_snapshot(path: Path) -> dict[str, bytes]:
    visible = path.lstat()
    if not stat.S_ISDIR(visible.st_mode) or _mode(visible) != "0700":
        raise ValueError("Plan 20 bridge root type or mode differs")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        if _identity(visible) != _identity(opened):
            raise ValueError("Plan 20 bridge root identity changed")
        names = tuple(sorted(os.listdir(descriptor)))
        if names != tuple(sorted(REVIEW_FILENAMES)):
            raise ValueError("Plan 20 bridge inventory is not exactly three files")
        files: dict[str, bytes] = {}
        for name in names:
            child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(child.st_mode) or _mode(child) != "0600" or child.st_nlink != 1:
                raise ValueError("Plan 20 bridge child type, mode, or links differ")
            child_descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                before = os.fstat(child_descriptor)
                if _identity(child) != _identity(before):
                    raise ValueError("Plan 20 bridge child identity changed")
                chunks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    chunk = os.read(child_descriptor, min(1_048_576, remaining))
                    if not chunk:
                        raise ValueError("Plan 20 bridge child read was short")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(child_descriptor, 1):
                    raise ValueError("Plan 20 bridge child grew during read")
                after = os.fstat(child_descriptor)
                visible_after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if not (_identity(before) == _identity(after) == _identity(visible_after)):
                    raise ValueError("Plan 20 bridge child changed during read")
                files[name] = b"".join(chunks)
            finally:
                os.close(child_descriptor)
        after_root = os.fstat(descriptor)
        visible_after_root = path.lstat()
        if not (_identity(opened) == _identity(after_root) == _identity(visible_after_root)):
            raise ValueError("Plan 20 bridge root changed during verification")
        return files
    finally:
        os.close(descriptor)


def _canonical_payloads(files: Mapping[str, bytes]) -> dict[str, dict[str, Any]]:
    payloads: dict[str, dict[str, Any]] = {}
    for name in REVIEW_FILENAMES:
        raw = files[name]
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Plan 20 bridge contains invalid JSON") from exc
        if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
            raise ValueError("Plan 20 bridge contains noncanonical bytes")
        payloads[name] = value
    return payloads


def _verify_bridge_payloads(payloads: Mapping[str, Mapping[str, Any]]) -> None:
    request = payloads["catalog-review-request.json"]
    state = payloads["catalog-state-attestation.json"]
    view = payloads["catalog-review-view.json"]
    if request.get("schema_version") != "itda.catalog-v2-contest-review-request.v1":
        raise ValueError("Plan 20 request schema differs")
    if state.get("schema_version") != ("itda.catalog-v2-contest-review-state-attestation.v1"):
        raise ValueError("Plan 20 state schema differs")
    if view.get("schema_version") != "itda.catalog-v2-contest-review-view.v1":
        raise ValueError("Plan 20 view schema differs")
    if request.get("request_sha256") != canonical_sha256(_without(request, "request_sha256")):
        raise ValueError("Plan 20 request digest is stale")
    if state.get("state_attestation_sha256") != canonical_sha256(
        _without(state, "state_attestation_sha256")
    ):
        raise ValueError("Plan 20 state digest is stale")
    if view.get("view_sha256") != canonical_sha256(_without(view, "view_sha256")):
        raise ValueError("Plan 20 view digest is stale")
    if (
        state.get("request_sha256") != request.get("request_sha256")
        or view.get("request_sha256") != request.get("request_sha256")
        or view.get("state_attestation_sha256") != state.get("state_attestation_sha256")
    ):
        raise ValueError("Plan 20 bridge cross-file binding is stale")
    shared = (
        "scope",
        "commercial_production_rights_review_required",
        "execution_mode",
        "policy_version",
        "normalized_evidence_schema",
        "normalized_evidence_root",
        "generation_manifest_path",
        "generation_manifest_file_sha256",
        "plan55_roots",
        "plan55_roots_sha256",
        "mode_security_roots",
        "handoff_mode_security_roots_sha256",
        "mode_security_roots_sha256",
        "first_readiness_root",
        "second_readiness_root",
        "eligible_count",
        "eligible_group_counts",
        "capped_capacity",
        "exact_quotas",
        "quota_sum",
        "selectable_candidate_count",
        "human_decision_count",
        "preview_is_canonical_catalog",
        "human_choice_and_order_required",
        "closure_binding_sha256",
        "plan20_reachable",
    )
    if any(
        state.get(field) != request.get(field) or view.get(field) != request.get(field)
        for field in shared
    ):
        raise ValueError("Plan 20 bridge shared root or mode-security binding is mixed")
    roots = request.get("plan55_roots")
    if (
        not isinstance(roots, Mapping)
        or set(roots) != {*PLAN55_HANDOFF_ROOT_FIELDS, "contest_generation_sha256"}
        or request.get("plan55_roots_sha256") != canonical_sha256(roots)
    ):
        raise ValueError("Plan 20 bridge Plan 55 root map differs")
    mode_roots = request.get("mode_security_roots")
    if (
        not isinstance(mode_roots, Mapping)
        or set(mode_roots) != set(CAPTURED_MODE_SECURITY_FIELDS)
        or dict(mode_roots) != mode_security_roots(NETWORK_DENIAL_POLICY_SHA256)
        or request.get("handoff_mode_security_roots_sha256")
        != request.get("mode_security_roots_sha256")
    ):
        raise ValueError("Plan 20 bridge captured mode-security roots differ")
    if not all(item.get("plan20_reachable") is True for item in (request, state, view)):
        raise ValueError("Plan 20 bridge is not reachable")


def verify_materialized_bundle(
    destination: Path | str,
    *,
    closure_result: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Verify exact inventory, descriptor root, modes, and all shared bindings."""

    root = Path(destination)
    files = _stable_bundle_snapshot(root)
    payloads = _canonical_payloads(files)
    _verify_bridge_payloads(payloads)
    _, descriptor_root = _bridge_descriptor(payloads)
    if root.name != descriptor_root:
        raise ValueError("Plan 20 bridge directory basename differs from descriptor root")
    if closure_result is not None:
        expected_payloads = closure_result.get("bridge_payloads")
        if (
            closure_result.get("bridge_root_sha256") != descriptor_root
            or not isinstance(expected_payloads, Mapping)
            or canonical_json_bytes(expected_payloads) != canonical_json_bytes(payloads)
        ):
            raise ValueError("closure result and Plan 20 bridge binding differ")
    request = payloads["catalog-review-request.json"]
    state = payloads["catalog-state-attestation.json"]
    view = payloads["catalog-review-view.json"]
    return {
        "file_count": 3,
        "bridge_root_sha256": descriptor_root,
        "request_sha256": request["request_sha256"],
        "state_attestation_sha256": state["state_attestation_sha256"],
        "view_sha256": view["view_sha256"],
        "plan55_roots_sha256": request["plan55_roots_sha256"],
        "mode_security_roots_sha256": request["mode_security_roots_sha256"],
        "plan20_reachable": True,
    }


def build_catalog_v2_review_bundle(
    finalization: Mapping[str, object],
    destination: Path | str,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, str]:
    """Publish exactly the precomputed closure-carried bridge payloads once."""

    root = _repository_root(repository_root)
    success = verify_plan54_success(finalization, repository_root=root)
    payloads_value = success.get("bridge_payloads")
    if not isinstance(payloads_value, Mapping):
        raise ValueError("Plan 54 closure bridge payloads are missing")
    payloads = {
        str(name): dict(payload)
        for name, payload in payloads_value.items()
        if isinstance(name, str) and isinstance(payload, Mapping)
    }
    _, bridge_root = _bridge_descriptor(payloads)
    if success.get("bridge_root_sha256") != bridge_root:
        raise ValueError("Plan 54 closure bridge descriptor differs")
    output_base = Path(destination)
    output_base.mkdir(parents=True, exist_ok=True)
    if output_base.is_symlink() or not output_base.is_dir():
        raise ValueError("Plan 54 bridge parent must be a regular directory")
    output = output_base / bridge_root
    if os.path.lexists(output):
        verified = verify_materialized_bundle(output, closure_result=success)
        return {
            **{key: str(value) for key, value in verified.items()},
            "publication_disposition": "ALREADY_PRESENT_VERIFIED",
        }
    prepared = Path(tempfile.mkdtemp(prefix=f".{bridge_root}.prepared-", dir=output_base))
    uncertain = False
    try:
        os.chmod(prepared, 0o700)
        for filename in sorted(payloads):
            _create_private_file(prepared / filename, canonical_json_bytes(payloads[filename]))
        _fsync_directory(prepared)
        try:
            with prepared_directory_snapshot(prepared) as snapshot:
                publish_immutable_directory(
                    prepared=prepared,
                    output=output,
                    snapshot=snapshot,
                )
        except FileExistsError:
            verified = verify_materialized_bundle(output, closure_result=success)
            return {
                **{key: str(value) for key, value in verified.items()},
                "publication_disposition": "ALREADY_PRESENT_VERIFIED",
            }
        except PublicationStateUncertainError:
            uncertain = True
            raise
        verified = verify_materialized_bundle(output, closure_result=success)
        return {
            **{key: str(value) for key, value in verified.items()},
            "publication_disposition": "PUBLISHED",
        }
    finally:
        if not uncertain and prepared.exists():
            shutil.rmtree(prepared)


def _load_plan54_bridge(
    bridge_directory: Path | str,
    *,
    repository_root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, object]]:
    supplied = Path(bridge_directory)
    if supplied.is_symlink():
        raise ValueError("Plan 54 bridge path cannot be a symlink")
    bridge = supplied.resolve(strict=True)
    expected_parent = (repository_root / BRIDGE_BASE_REL).resolve(strict=True)
    if bridge.parent != expected_parent:
        raise ValueError("Plan 54 bridge is outside the exact restricted namespace")
    verified = verify_materialized_bundle(bridge)
    files = _stable_bundle_snapshot(bridge)
    payloads = _canonical_payloads(files)
    if bridge.name != verified["bridge_root_sha256"]:
        raise ValueError("Plan 54 bridge path is not the exact function of its root")
    request = payloads["catalog-review-request.json"]
    manifest_rel = request.get("generation_manifest_path")
    if not isinstance(manifest_rel, str):
        raise ValueError("Plan 54 bridge generation manifest path is missing")
    manifest_path = Path(manifest_rel)
    if (
        manifest_path.name != "generation-manifest.json"
        or manifest_path.parent.parent != GENERATION_BASE_REL
    ):
        raise ValueError("Plan 54 bridge generation manifest path differs")
    closure = prepare_contest_closure(
        repository_root / manifest_path.parent,
        repository_root=repository_root,
    )
    expected_payloads = closure.get("bridge_payloads")
    if (
        closure.get("bridge_root_sha256") != verified["bridge_root_sha256"]
        or not isinstance(expected_payloads, Mapping)
        or canonical_json_bytes(expected_payloads) != canonical_json_bytes(payloads)
    ):
        raise ValueError("Plan 54 bridge differs from independently rederived Plan 55 bytes")
    return payloads, verified


def _validated_private_draft(
    draft: Mapping[str, object],
    *,
    request: Mapping[str, Any],
) -> tuple[list[dict[str, object]], list[str], dict[str, int]]:
    if set(draft) != {"schema_version", "decisions", "ordered_place_ids"}:
        raise ValueError("private draft has unknown or missing fields")
    if draft.get("schema_version") != "itda.catalog-adjudication-private-draft.v1":
        raise ValueError("private draft schema differs")
    decisions_value = draft.get("decisions")
    ordered_value = draft.get("ordered_place_ids")
    if not isinstance(decisions_value, list) or not all(
        isinstance(item, dict) for item in decisions_value
    ):
        raise ValueError("private draft decisions must be JSON objects")
    decisions = [dict(item) for item in decisions_value]
    expected_decisions = request.get("human_decision_count")
    if (
        not isinstance(expected_decisions, int)
        or isinstance(expected_decisions, bool)
        or not 0 <= expected_decisions <= 6
        or len(decisions) != expected_decisions
    ):
        raise ValueError("private draft must contain all and only bound human decisions")
    if expected_decisions == 0 and decisions:
        raise ValueError("the bound bridge permits no human decision rows")
    if expected_decisions:
        raise ValueError(
            "the current bridge does not expose decision-row contracts for nonzero review"
        )
    if (
        not isinstance(ordered_value, list)
        or len(ordered_value) != 36
        or not all(isinstance(item, str) for item in ordered_value)
    ):
        raise ValueError("private draft requires exactly 36 ordered place IDs")
    ordered = list(ordered_value)
    if len(set(ordered)) != 36:
        raise ValueError("private draft ordered place IDs must be unique")

    eligible_value = request.get("eligible_pool")
    if not isinstance(eligible_value, list) or len(eligible_value) != request.get("eligible_count"):
        raise ValueError("bound eligible pool is incomplete")
    eligible: dict[str, dict[str, Any]] = {}
    for value in eligible_value:
        if not isinstance(value, dict):
            raise ValueError("bound eligible pool row is malformed")
        row = dict(value)
        place_id = row.get("place_entity_id")
        group = row.get("representation_primary_group")
        if (
            not isinstance(place_id, str)
            or re.fullmatch(r"place:[0-9a-f]{64}", place_id) is None
            or group not in GROUP_ORDER
            or not isinstance(row.get("candidate_row_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("candidate_row_sha256"))) is None
            or place_id in eligible
        ):
            raise ValueError("bound eligible pool row identity, group, or digest differs")
        eligible[place_id] = row
    if any(place_id not in eligible for place_id in ordered):
        raise ValueError("private draft contains an out-of-pool or ineligible place ID")
    counts = {group: 0 for group in GROUP_ORDER}
    for place_id in ordered:
        counts[str(eligible[place_id]["representation_primary_group"])] += 1
    quotas = request.get("exact_quotas")
    if counts != quotas or sum(counts.values()) != 36:
        raise ValueError("private draft violates the exact representation group quotas")
    if (
        request.get("plan20_reachable") is not True
        or request.get("selectable_candidate_count") != 36
        or request.get("quota_sum") != 36
        or request.get("preview_is_canonical_catalog") is not False
        or request.get("human_choice_and_order_required") is not True
    ):
        raise ValueError("bound D-16 reachability or selection gate differs")
    return decisions, ordered, counts


def derive_adjudication_target(
    bridge_directory: Path | str,
    draft: Mapping[str, object],
    *,
    repository_root: Path | str | None = None,
) -> dict[str, object]:
    """Derive the complete combined human target without writing any byte."""

    root = _repository_root(repository_root)
    payloads, bridge = _load_plan54_bridge(bridge_directory, repository_root=root)
    request = payloads["catalog-review-request.json"]
    state = payloads["catalog-state-attestation.json"]
    view = payloads["catalog-review-view.json"]
    decisions, ordered, selected_counts = _validated_private_draft(draft, request=request)
    fields: dict[str, object] = {
        "schema_version": "itda.catalog-adjudication-selection-target.v1",
        "bridge_directory": (BRIDGE_BASE_REL / str(bridge["bridge_root_sha256"])).as_posix(),
        "bridge_root_sha256": bridge["bridge_root_sha256"],
        "request_sha256": request["request_sha256"],
        "state_attestation_sha256": state["state_attestation_sha256"],
        "view_sha256": view["view_sha256"],
        "decisions": decisions,
        "decisions_sha256": canonical_sha256(decisions),
        "ordered_place_ids": ordered,
        "ordered_place_ids_sha256": canonical_sha256(ordered),
        "representation_policy_version": request["policy_version"],
        "representation_rule_table_sha256": request["plan55_roots"]["quota_proof_sha256"],
        "eligible_pool_sha256": request["plan55_roots"]["eligible_pool_sha256"],
        "eligible_group_counts": request["eligible_group_counts"],
        "exact_quotas": request["exact_quotas"],
        "selected_group_counts": selected_counts,
        "capped_capacity": request["capped_capacity"],
        "quota_sum": request["quota_sum"],
        "representation_state": "FEASIBLE",
        "plan55_roots": request["plan55_roots"],
        "plan55_roots_sha256": request["plan55_roots_sha256"],
        "mode_security_roots": request["mode_security_roots"],
        "handoff_mode_security_roots_sha256": request["handoff_mode_security_roots_sha256"],
        "mode_security_roots_sha256": request["mode_security_roots_sha256"],
    }
    return {**fields, "target_sha256": canonical_sha256(fields)}


def _authority_binding(target: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": "itda.catalog-adjudication-authority-binding.v1",
        "bridge_root_sha256": target["bridge_root_sha256"],
        "request_sha256": target["request_sha256"],
        "state_attestation_sha256": target["state_attestation_sha256"],
        "target_sha256": target["target_sha256"],
        "plan55_roots_sha256": target["plan55_roots_sha256"],
        "mode_security_roots_sha256": target["mode_security_roots_sha256"],
    }


def _load_authority_descriptor(
    path: Path | str,
) -> tuple[AuthorityIssuanceContext, str]:
    descriptor_path = Path(path)
    visible = descriptor_path.lstat()
    if not stat.S_ISREG(visible.st_mode) or _mode(visible) != "0600" or visible.st_nlink != 1:
        raise ValueError("authority descriptor must be a protected 0600 regular file")
    raw = _stable_regular_bytes(descriptor_path, max_bytes=2_000_000)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("authority descriptor is invalid JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("authority descriptor must use canonical JSON bytes")
    if set(value) != {"schema_version", "issuance_context", "authority_token"}:
        raise ValueError("authority descriptor has unknown or missing fields")
    if value.get("schema_version") != "itda.catalog-adjudication-authority-descriptor.v1":
        raise ValueError("authority descriptor schema differs")
    token = value.get("authority_token")
    if not isinstance(token, str):
        raise ValueError("authority descriptor token is missing")
    return AuthorityIssuanceContext.model_validate(value.get("issuance_context")), token


def _expected_authority_receipt(
    context: AuthorityIssuanceContext,
    *,
    token: str,
) -> AuthorityConsumptionReceipt:
    if context.context_sha256 is None:
        raise ValueError("authority issuance context lacks its digest")
    return AuthorityConsumptionReceipt(
        action=context.action,
        request_sha256=context.request_sha256,
        state_attestation_sha256=context.state_attestation_sha256,
        target_sha256=context.target_sha256,
        reviewer_id=context.reviewer_id,
        binding_sha256=context.binding_sha256,
        nonce_sha256=_sha256_bytes(context.nonce.encode("ascii")),
        token_sha256=_sha256_bytes(token.encode("ascii")),
        issuance_context_sha256=context.context_sha256,
        result_sha256=context.target_sha256,
        completion="MUTATION_COMMITTED",
        reviewer_channel_risk=context.reviewer_channel_risk,
    )


def _with_self_digest(fields: dict[str, object], field: str) -> dict[str, object]:
    return {**fields, field: canonical_sha256(fields)}


def _adjudication_payloads(
    target: Mapping[str, object],
    *,
    authority_receipt: AuthorityConsumptionReceipt,
    reviewed_at: datetime,
) -> tuple[dict[str, dict[str, object]], str]:
    decisions = target["decisions"]
    adjudication = _with_self_digest(
        {
            "schema_version": "itda.catalog-adjudication.v1",
            "request_sha256": target["request_sha256"],
            "state_attestation_sha256": target["state_attestation_sha256"],
            "target_sha256": target["target_sha256"],
            "reviewer_id": authority_receipt.reviewer_id,
            "reviewed_at": reviewed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "decisions": decisions,
            "decisions_sha256": canonical_sha256(decisions),
        },
        "catalog_adjudication_sha256",
    )
    selection = _with_self_digest(
        {
            "schema_version": "itda.catalog-selection.v1",
            "request_sha256": target["request_sha256"],
            "state_attestation_sha256": target["state_attestation_sha256"],
            "target_sha256": target["target_sha256"],
            "ordered_place_ids": target["ordered_place_ids"],
            "ordered_place_ids_sha256": target["ordered_place_ids_sha256"],
            "eligible_pool_sha256": target["eligible_pool_sha256"],
            "eligible_group_counts": target["eligible_group_counts"],
            "exact_quotas": target["exact_quotas"],
            "selected_group_counts": target["selected_group_counts"],
            "representation_state": target["representation_state"],
        },
        "catalog_selection_sha256",
    )
    leaves: list[object] = []
    relationships = _with_self_digest(
        {
            "schema_version": "itda.authoritative-relationship-leaves.v1",
            "request_sha256": target["request_sha256"],
            "state_attestation_sha256": target["state_attestation_sha256"],
            "target_sha256": target["target_sha256"],
            "relationship_leaf_count": 0,
            "relationship_leaves": leaves,
            "relationship_leaves_sha256": canonical_sha256(leaves),
        },
        "authoritative_relationship_leaves_sha256",
    )
    payloads: dict[str, dict[str, object]] = {
        "catalog-adjudication-selection-target.json": dict(target),
        "catalog-adjudication.json": adjudication,
        "catalog-selection.json": selection,
        "authoritative-relationship-leaves.json": relationships,
    }
    inventory = [
        {
            "filename": name,
            "mode": "0600",
            "size": len(canonical_json_bytes(payloads[name])),
            "sha256": _sha256_bytes(canonical_json_bytes(payloads[name])),
        }
        for name in sorted(payloads)
    ]
    manifest_fields: dict[str, object] = {
        "schema_version": "itda.catalog-adjudication-bundle.v1",
        "file_count": 5,
        "manifest_filename": "catalog-adjudication-bundle.json",
        "inventory": inventory,
        "inventory_sha256": canonical_sha256(inventory),
        "bridge_directory": target["bridge_directory"],
        "bridge_root_sha256": target["bridge_root_sha256"],
        "request_sha256": target["request_sha256"],
        "state_attestation_sha256": target["state_attestation_sha256"],
        "view_sha256": target["view_sha256"],
        "target_sha256": target["target_sha256"],
        "plan55_roots": target["plan55_roots"],
        "plan55_roots_sha256": target["plan55_roots_sha256"],
        "mode_security_roots": target["mode_security_roots"],
        "handoff_mode_security_roots_sha256": target["handoff_mode_security_roots_sha256"],
        "mode_security_roots_sha256": target["mode_security_roots_sha256"],
        "authority_consumption_receipt": authority_receipt.model_dump(mode="json"),
    }
    bundle_root = canonical_sha256(manifest_fields)
    payloads["catalog-adjudication-bundle.json"] = {
        **manifest_fields,
        "bundle_root_sha256": bundle_root,
    }
    return payloads, bundle_root


def _stable_adjudication_snapshot(path: Path) -> dict[str, bytes]:
    visible = path.lstat()
    if not stat.S_ISDIR(visible.st_mode) or _mode(visible) != "0700":
        raise ValueError("adjudication bundle root type or mode differs")
    names = tuple(sorted(item.name for item in path.iterdir()))
    if names != tuple(sorted(ADJUDICATION_FILENAMES)):
        raise ValueError("adjudication bundle inventory is not exactly five files")
    result: dict[str, bytes] = {}
    for name in names:
        child = path / name
        metadata = child.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or _mode(metadata) != "0600"
            or metadata.st_nlink != 1
        ):
            raise ValueError("adjudication bundle child type, mode, or links differ")
        result[name] = _stable_regular_bytes(child, max_bytes=100_000_000)
    return result


def verify_adjudication_bundle(
    bundle_manifest_path: Path | str,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, object]:
    """Verify the five-file adjudication bundle and its exact Plan 54 bridge."""

    root = _repository_root(repository_root)
    manifest_path = Path(bundle_manifest_path)
    if manifest_path.name != "catalog-adjudication-bundle.json" or manifest_path.is_symlink():
        raise ValueError("dedicated verifier requires the five-file bundle manifest")
    directory = manifest_path.parent
    files = _stable_adjudication_snapshot(directory)
    payloads: dict[str, dict[str, Any]] = {}
    for name, raw in files.items():
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("adjudication bundle contains invalid JSON") from exc
        if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
            raise ValueError("adjudication bundle contains noncanonical bytes")
        payloads[name] = value
    manifest = payloads["catalog-adjudication-bundle.json"]
    bundle_root = manifest.get("bundle_root_sha256")
    if bundle_root != canonical_sha256(_without(manifest, "bundle_root_sha256")):
        raise ValueError("adjudication bundle root is stale")
    if directory.name != bundle_root:
        raise ValueError("adjudication bundle path is not the exact function of its root")
    inventory = manifest.get("inventory")
    if not isinstance(inventory, list) or manifest.get("inventory_sha256") != canonical_sha256(
        inventory
    ):
        raise ValueError("adjudication inventory digest differs")
    expected_inventory = [
        {
            "filename": name,
            "mode": "0600",
            "size": len(files[name]),
            "sha256": _sha256_bytes(files[name]),
        }
        for name in sorted(set(ADJUDICATION_FILENAMES) - {"catalog-adjudication-bundle.json"})
    ]
    if inventory != expected_inventory or manifest.get("file_count") != 5:
        raise ValueError("adjudication inventory rows differ")
    target = payloads["catalog-adjudication-selection-target.json"]
    if target.get("target_sha256") != canonical_sha256(_without(target, "target_sha256")):
        raise ValueError("adjudication target digest is stale")
    bridge_rel = manifest.get("bridge_directory")
    if not isinstance(bridge_rel, str):
        raise ValueError("adjudication bridge path is missing")
    expected_bridge = (BRIDGE_BASE_REL / str(manifest.get("bridge_root_sha256"))).as_posix()
    if bridge_rel != expected_bridge:
        raise ValueError("adjudication bridge path is not the exact function of its root")
    bridge_payloads, bridge = _load_plan54_bridge(root / bridge_rel, repository_root=root)
    request = bridge_payloads["catalog-review-request.json"]
    state = bridge_payloads["catalog-state-attestation.json"]
    view = bridge_payloads["catalog-review-view.json"]
    if (
        bridge["bridge_root_sha256"] != manifest.get("bridge_root_sha256")
        or request["request_sha256"] != manifest.get("request_sha256")
        or state["state_attestation_sha256"] != manifest.get("state_attestation_sha256")
        or view["view_sha256"] != manifest.get("view_sha256")
        or request["plan55_roots"] != manifest.get("plan55_roots")
        or request["plan55_roots_sha256"] != manifest.get("plan55_roots_sha256")
        or request["mode_security_roots"] != manifest.get("mode_security_roots")
        or request["handoff_mode_security_roots_sha256"]
        != manifest.get("handoff_mode_security_roots_sha256")
        or request["mode_security_roots_sha256"] != manifest.get("mode_security_roots_sha256")
    ):
        raise ValueError("adjudication and Plan 54 bridge roots differ")
    draft = {
        "schema_version": "itda.catalog-adjudication-private-draft.v1",
        "decisions": target.get("decisions"),
        "ordered_place_ids": target.get("ordered_place_ids"),
    }
    expected_target = derive_adjudication_target(root / bridge_rel, draft, repository_root=root)
    if canonical_json_bytes(expected_target) != canonical_json_bytes(target):
        raise ValueError("adjudication target does not rederive from the bound pool and quotas")
    authority = AuthorityConsumptionReceipt.model_validate(
        manifest.get("authority_consumption_receipt")
    )
    if (
        authority.action != "catalog-adjudicate-select"
        or authority.request_sha256 != target["request_sha256"]
        or authority.state_attestation_sha256 != target["state_attestation_sha256"]
        or authority.target_sha256 != target["target_sha256"]
        or authority.binding_sha256 != canonical_sha256(_authority_binding(target))
        or authority.result_sha256 != target["target_sha256"]
    ):
        raise ValueError("adjudication authority or nonce receipt binding differs")

    adjudication = payloads["catalog-adjudication.json"]
    reviewed_at = adjudication.get("reviewed_at")
    if not isinstance(reviewed_at, str):
        raise ValueError("catalog adjudication review time is missing")
    try:
        parsed_reviewed_at = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("catalog adjudication review time is invalid") from exc
    if (
        not reviewed_at.endswith("Z")
        or parsed_reviewed_at.utcoffset() != timedelta(0)
        or parsed_reviewed_at.isoformat().replace("+00:00", "Z") != reviewed_at
    ):
        raise ValueError("catalog adjudication review time is not canonical UTC")
    expected_adjudication = _with_self_digest(
        {
            "schema_version": "itda.catalog-adjudication.v1",
            "request_sha256": target["request_sha256"],
            "state_attestation_sha256": target["state_attestation_sha256"],
            "target_sha256": target["target_sha256"],
            "reviewer_id": authority.reviewer_id,
            "reviewed_at": reviewed_at,
            "decisions": target["decisions"],
            "decisions_sha256": target["decisions_sha256"],
        },
        "catalog_adjudication_sha256",
    )
    expected_selection = _with_self_digest(
        {
            "schema_version": "itda.catalog-selection.v1",
            "request_sha256": target["request_sha256"],
            "state_attestation_sha256": target["state_attestation_sha256"],
            "target_sha256": target["target_sha256"],
            "ordered_place_ids": target["ordered_place_ids"],
            "ordered_place_ids_sha256": target["ordered_place_ids_sha256"],
            "eligible_pool_sha256": target["eligible_pool_sha256"],
            "eligible_group_counts": target["eligible_group_counts"],
            "exact_quotas": target["exact_quotas"],
            "selected_group_counts": target["selected_group_counts"],
            "representation_state": target["representation_state"],
        },
        "catalog_selection_sha256",
    )
    relationship_leaves: list[object] = []
    expected_relationships = _with_self_digest(
        {
            "schema_version": "itda.authoritative-relationship-leaves.v1",
            "request_sha256": target["request_sha256"],
            "state_attestation_sha256": target["state_attestation_sha256"],
            "target_sha256": target["target_sha256"],
            "relationship_leaf_count": 0,
            "relationship_leaves": relationship_leaves,
            "relationship_leaves_sha256": canonical_sha256(relationship_leaves),
        },
        "authoritative_relationship_leaves_sha256",
    )
    expected_siblings = {
        "catalog-adjudication.json": expected_adjudication,
        "catalog-selection.json": expected_selection,
        "authoritative-relationship-leaves.json": expected_relationships,
    }
    for name, expected_payload in expected_siblings.items():
        if canonical_json_bytes(payloads[name]) != canonical_json_bytes(expected_payload):
            raise ValueError(f"{name} semantics differ from the authorized target")
    return {
        "file_count": 5,
        "bundle_root_sha256": bundle_root,
        "bridge_root_sha256": bridge["bridge_root_sha256"],
        "request_sha256": target["request_sha256"],
        "state_attestation_sha256": target["state_attestation_sha256"],
        "target_sha256": target["target_sha256"],
    }


def _materialization_receipt(
    *,
    bundle_root: str,
    bridge_root: str,
    disposition: str,
) -> dict[str, str]:
    return {
        "schema_version": "itda.catalog-adjudication-materialization-receipt.v1",
        "bundle_manifest_path": (
            ADJUDICATION_BASE_REL / bundle_root / "catalog-adjudication-bundle.json"
        ).as_posix(),
        "bundle_root_sha256": bundle_root,
        "bridge_directory": (BRIDGE_BASE_REL / bridge_root).as_posix(),
        "bridge_root_sha256": bridge_root,
        "publication_disposition": disposition,
    }


def materialize_adjudication_bundle(
    bridge_directory: Path | str,
    draft: Mapping[str, object],
    authority_descriptor: Path | str,
    *,
    repository_root: Path | str | None = None,
    destination_base: Path | str | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Validate authority, consume its nonce, and publish five files once."""

    root = _repository_root(repository_root)
    target = derive_adjudication_target(bridge_directory, draft, repository_root=root)
    payloads, bridge = _load_plan54_bridge(bridge_directory, repository_root=root)
    request = payloads["catalog-review-request.json"]
    state = payloads["catalog-state-attestation.json"]
    context, token = _load_authority_descriptor(authority_descriptor)
    if context.action != "catalog-adjudicate-select":
        raise ValueError("authority action does not permit catalog adjudication")
    validated = validate_authority_token(
        token,
        issuance_context=context,
        request=_without(request, "request_sha256"),
        state_attestation=_without(state, "state_attestation_sha256"),
        target=_without(target, "target_sha256"),
        binding=_authority_binding(target),
        reviewer_id=context.reviewer_id,
        now=now or datetime.now(UTC),
        revocation_tombstones=(),
    )
    expected_receipt = _expected_authority_receipt(context, token=token)
    bundle_payloads, bundle_root = _adjudication_payloads(
        target,
        authority_receipt=expected_receipt,
        reviewed_at=context.issued_at,
    )
    output_base = (
        Path(destination_base) if destination_base is not None else root / ADJUDICATION_BASE_REL
    )
    output_base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_base.is_symlink() or not output_base.is_dir():
        raise ValueError("adjudication bundle parent must be a regular directory")
    os.chmod(output_base, 0o700)
    output = output_base / bundle_root
    if os.path.lexists(output):
        verified = verify_adjudication_bundle(
            output / "catalog-adjudication-bundle.json", repository_root=root
        )
        if verified["target_sha256"] != target["target_sha256"]:
            raise FileExistsError("existing adjudication bundle target differs")
        return _materialization_receipt(
            bundle_root=bundle_root,
            bridge_root=str(bridge["bridge_root_sha256"]),
            disposition="ALREADY_PRESENT_VERIFIED",
        )

    prepared = Path(tempfile.mkdtemp(prefix=f".{bundle_root}.prepared-", dir=output_base))
    uncertain = False
    try:
        os.chmod(prepared, 0o700)
        for filename in sorted(bundle_payloads):
            _create_private_file(
                prepared / filename,
                canonical_json_bytes(bundle_payloads[filename]),
            )
        _fsync_directory(prepared)

        def publish() -> Mapping[str, object]:
            nonlocal uncertain
            try:
                with prepared_directory_snapshot(prepared) as snapshot:
                    publish_immutable_directory(prepared=prepared, output=output, snapshot=snapshot)
            except FileExistsError:
                recovered = verify_adjudication_bundle(
                    output / "catalog-adjudication-bundle.json",
                    repository_root=root,
                )
                if recovered["target_sha256"] != target["target_sha256"]:
                    raise FileExistsError("existing adjudication bundle target differs") from None
            except PublicationStateUncertainError:
                uncertain = True
                raise
            return {"result_sha256": target["target_sha256"]}

        ledger = FileNonceLedger(output_base / ".authority-ledger")
        consumed = ledger.consume_with_mutation(validated, mutation=publish)
        if consumed.model_dump(mode="json") != expected_receipt.model_dump(mode="json"):
            raise ValueError("authority nonce receipt differs from the published bundle")
        verified = verify_adjudication_bundle(
            output / "catalog-adjudication-bundle.json", repository_root=root
        )
        if verified["bundle_root_sha256"] != bundle_root:
            raise ValueError("published adjudication bundle root differs")
        return _materialization_receipt(
            bundle_root=bundle_root,
            bridge_root=str(bridge["bridge_root_sha256"]),
            disposition="PUBLISHED",
        )
    finally:
        if not uncertain and prepared.exists():
            shutil.rmtree(prepared)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify-plan54-success", type=Path)
    modes.add_argument("--materialize-plan54-bridge", type=Path)
    modes.add_argument("--verify-materialized-bundle", type=Path)
    modes.add_argument("--derive-adjudication-target", action="store_true")
    modes.add_argument("--materialize-adjudication-bundle", action="store_true")
    modes.add_argument("--verify-adjudication-bundle", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--closure-result", type=Path)
    parser.add_argument("--bridge-dir", type=Path)
    parser.add_argument("--draft", type=Path)
    parser.add_argument("--authority-descriptor", type=Path)
    parser.add_argument("--repo-root", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = _repository_root(args.repo_root)
    result: Mapping[str, object]
    if args.verify_plan54_success:
        if any(
            value is not None
            for value in (
                args.destination,
                args.closure_result,
                args.bridge_dir,
                args.draft,
                args.authority_descriptor,
            )
        ):
            raise ValueError("success verification accepts no publication arguments")
        value = _load_canonical_file(
            args.verify_plan54_success,
            repository_root=root,
        )
        result = verify_plan54_success(value, repository_root=root)
    elif args.materialize_plan54_bridge:
        if (
            args.destination is None
            or args.closure_result is not None
            or args.bridge_dir is not None
            or args.draft is not None
            or args.authority_descriptor is not None
        ):
            raise ValueError("materialization requires only --destination")
        value = _load_canonical_file(
            args.materialize_plan54_bridge,
            repository_root=root,
        )
        result = build_catalog_v2_review_bundle(
            value,
            args.destination,
            repository_root=root,
        )
    elif args.verify_materialized_bundle:
        if (
            args.destination is not None
            or args.bridge_dir is not None
            or args.draft is not None
            or args.authority_descriptor is not None
        ):
            raise ValueError("bundle verification accepts no --destination")
        closure = (
            _load_canonical_file(args.closure_result, repository_root=root)
            if args.closure_result is not None
            else None
        )
        result = verify_materialized_bundle(
            args.verify_materialized_bundle,
            closure_result=closure,
        )
    elif args.derive_adjudication_target:
        if (
            args.bridge_dir is None
            or args.draft is None
            or args.authority_descriptor is not None
            or args.destination is not None
            or args.closure_result is not None
        ):
            raise ValueError("target derivation requires only --bridge-dir and --draft")
        draft = _load_canonical_file(args.draft, repository_root=root, max_bytes=2_000_000)
        result = derive_adjudication_target(args.bridge_dir, draft, repository_root=root)
    elif args.materialize_adjudication_bundle:
        if (
            args.bridge_dir is None
            or args.draft is None
            or args.authority_descriptor is None
            or args.destination is not None
            or args.closure_result is not None
        ):
            raise ValueError(
                "adjudication materialization requires --bridge-dir, --draft, and "
                "--authority-descriptor"
            )
        draft = _load_canonical_file(args.draft, repository_root=root, max_bytes=2_000_000)
        result = materialize_adjudication_bundle(
            args.bridge_dir,
            draft,
            args.authority_descriptor,
            repository_root=root,
        )
    else:
        if any(
            value is not None
            for value in (
                args.destination,
                args.closure_result,
                args.bridge_dir,
                args.draft,
                args.authority_descriptor,
            )
        ):
            raise ValueError("adjudication verification accepts only the bundle manifest")
        result = verify_adjudication_bundle(
            args.verify_adjudication_bundle,
            repository_root=root,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADJUDICATION_FILENAMES",
    "PLAN55_HANDOFF_ROOT_FIELDS",
    "REVIEW_FILENAMES",
    "assert_predecessor_summaries_absent",
    "build_catalog_v2_review_bundle",
    "derive_adjudication_target",
    "main",
    "materialize_adjudication_bundle",
    "prepare_contest_closure",
    "publish_closure_result",
    "verify_adjudication_bundle",
    "verify_materialized_bundle",
    "verify_plan54_success",
]
