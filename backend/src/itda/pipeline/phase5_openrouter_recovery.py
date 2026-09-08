"""Provider-free OpenRouter recovery planning, durable state, and verifier.

New disjoint ``phase5-openrouter-stealth-ox-alpha-recovery-20260823``
namespace.  Reproduces the Fresh24 security semantics (durable reserve →
dispatch → evidence → commit ordering, no-follow protected writes, exact
scheduler budgets) without refactoring or importing any NVIDIA module.  The
live seam is present but inert: production execution fails closed without
Plan 05-36 authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import threading
import urllib.parse
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import httpx

from itda.cli.freeze_preview import _rename_noreplace_at, open_directory_chain_no_follow
from itda.contracts.demo_profile_materialization import DemoSourceBundle
from itda.contracts.phase5_openrouter_recovery import (
    HISTORICAL_AUTHORITY_IDS,
    OPENROUTER_APPROVAL_STATUS_SCHEMA,
    OPENROUTER_ATTEMPT_DEADLINE_SECONDS,
    OPENROUTER_ATTEMPT_SCHEMA,
    OPENROUTER_CLAIM_SCHEMA,
    OPENROUTER_CLIENT_FACT_CONFIRMED,
    OPENROUTER_DISPATCH_CERTAINTY_PREPARED,
    OPENROUTER_DISPATCH_CERTAINTY_RESERVED,
    OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN,
    OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED,
    OPENROUTER_DISPATCH_PHASE_PREPARED,
    OPENROUTER_DISPATCH_PHASE_RESERVED,
    OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY,
    OPENROUTER_DISPATCH_SCHEMA,
    OPENROUTER_ENDPOINT,
    OPENROUTER_FIRST_PASS_COUNT,
    OPENROUTER_GENERATION_SCHEMA,
    OPENROUTER_LEDGER_ENTRY_SCHEMA,
    OPENROUTER_MAX_ATTEMPTS,
    OPENROUTER_MAX_RESPONSE_BYTES,
    OPENROUTER_MAX_RETRIES,
    OPENROUTER_MEMBER_COUNT,
    OPENROUTER_MEMBERSHIP_SHA256,
    OPENROUTER_MIN_EFFECTIVE_CANDIDATES,
    OPENROUTER_MODEL,
    OPENROUTER_PROFILE_SCHEMA_VERSION,
    OPENROUTER_PROMPT_SHA256,
    OPENROUTER_PROMPT_TEXT,
    OPENROUTER_PROVIDER_LANE,
    OPENROUTER_RECOVERY_AUTHORITY_ID,
    OPENROUTER_RESERVATION_MICRO_USD,
    OPENROUTER_RETRYABLE_HTTP_STATUSES,
    OPENROUTER_RETRYABLE_TRANSPORT_NAMES,
    OPENROUTER_SEND_MAY_HAVE_STARTED,
    OPENROUTER_SEND_NOT_STARTED,
    OPENROUTER_TERMINAL_SCHEMA,
    OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY,
    OPENROUTER_V2_PREDECESSOR_FAILURE_PATH,
    OPENROUTER_V2_PREDECESSOR_FAILURE_SHA256,
    OPENROUTER_V2_PREPROCESSING_VERSION,
    OPENROUTER_V2_PROFILE_SCHEMA,
    OPENROUTER_V2_PROMPT_SHA256,
    OPENROUTER_V2_PROMPT_TEXT,
    OPENROUTER_V2_PROMPT_VERSION,
    OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
    OPENROUTER_V2_REQUEST_SCHEMA,
    OPENROUTER_V2_SNAPSHOT_RELATIVE,
    OpenRouterApprovalBinding,
    OpenRouterClaim,
    OpenRouterExposurePolicy,
    OpenRouterExposurePolicyV2,
    OpenRouterFirstPassV2,
    OpenRouterMemberRequest,
    OpenRouterMemberRequestV2,
    OpenRouterPredecessorConsumptionV2,
    OpenRouterProfile,
    OpenRouterProtectedStateDescriptor,
    OpenRouterPublicRequestV2,
    OpenRouterRetryPolicy,
    OpenRouterRetryPolicyV2,
    OpenRouterTerminal,
    build_openrouter_exposure_policy_v2,
    build_openrouter_retry_policy_v2,
    load_openrouter_snapshot,
    load_openrouter_snapshot_v2,
    load_openrouter_v2_json_bytes,
    openrouter_request_body_fields,
    openrouter_v2_request_body_fields,
    reject_historical_openrouter_v2_coordinates,
)
from itda.contracts.phase5_recovery_policy import (
    CANONICAL_CONTRAST_PAIRS,
    CANONICAL_SCENARIO_IDS,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256


class OpenRouterSecretUnavailable(RuntimeError):
    """Raised when no credential source is bound for a production attempt."""


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
FIXED_SOURCE_ROOT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/phase5-demo-profile-materialization"
)
OPENROUTER_PUBLIC_REQUEST_RELATIVE = "artifacts/public/phase5/openrouter-recovery-request.json"
OPENROUTER_PROTECTED_ROOT_RELATIVE = "artifacts/restricted/catalog/phase5-openrouter-recovery"
OPENROUTER_TERMINAL_RELATIVE = "artifacts/reports/phase5/openrouter-recovery-terminal.json"
OPENROUTER_REQUEST_OUTPUT = REPOSITORY_ROOT / OPENROUTER_PUBLIC_REQUEST_RELATIVE
OPENROUTER_TERMINAL_OUTPUT = REPOSITORY_ROOT / OPENROUTER_TERMINAL_RELATIVE
OPENROUTER_PROTECTED_ROOT = REPOSITORY_ROOT / OPENROUTER_PROTECTED_ROOT_RELATIVE

OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE = (
    "artifacts/public/phase5/openrouter-recovery-v2-request.json"
)
OPENROUTER_V2_PROTECTED_ROOT_RELATIVE = "artifacts/restricted/catalog/phase5-openrouter-recovery-r2"
OPENROUTER_V2_TERMINAL_RELATIVE = "artifacts/reports/phase5/openrouter-recovery-v2-terminal.json"
OPENROUTER_V2_REQUEST_OUTPUT = REPOSITORY_ROOT / OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE
OPENROUTER_V2_PROTECTED_ROOT = REPOSITORY_ROOT / OPENROUTER_V2_PROTECTED_ROOT_RELATIVE
OPENROUTER_V2_TERMINAL_OUTPUT = REPOSITORY_ROOT / OPENROUTER_V2_TERMINAL_RELATIVE

OPENROUTER_SOURCE_AUTHORITY_PATHS = (
    "backend/src/itda/contracts/phase5_openrouter_recovery.py",
    "backend/src/itda/pipeline/phase5_openrouter_recovery.py",
    "backend/src/itda/cli/materialize_phase5_demo_profiles.py",
    "backend/src/itda/minimal_probe_bootstrap.py",
    "backend/tests/contract/test_phase5_openrouter_recovery.py",
)
OPENROUTER_V2_SOURCE_AUTHORITY_PATHS = (
    "backend/src/itda/providers/openrouter_ox_alpha_api_contract_v2.json",
    "backend/src/itda/contracts/phase5_openrouter_recovery.py",
    "backend/src/itda/pipeline/phase5_openrouter_recovery.py",
    "backend/src/itda/cli/materialize_phase5_demo_profiles.py",
    "backend/src/itda/minimal_probe_bootstrap.py",
    "backend/tests/contract/test_phase5_openrouter_recovery.py",
    "backend/tests/security/test_phase5_provider_boundary.py",
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class OpenRouterCapabilityError(RuntimeError):
    """Secret-safe openrouter execution rejection."""


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _lexical_absolute_path(path: Path) -> Path:
    """Normalize an absolute spelling without observing any filesystem state."""

    return Path(os.path.abspath(os.fspath(path)))


def require_fixed_openrouter_paths(
    *,
    request_output: Path | None = None,
    protected_root: Path | None = None,
    terminal_output: Path | None = None,
) -> tuple[Path, Path, Path]:
    """Resolve only the repository-owned future destinations."""

    request = OPENROUTER_REQUEST_OUTPUT if request_output is None else request_output
    protected = OPENROUTER_PROTECTED_ROOT if protected_root is None else protected_root
    terminal = OPENROUTER_TERMINAL_OUTPUT if terminal_output is None else terminal_output
    if request.resolve(strict=False) != OPENROUTER_REQUEST_OUTPUT:
        raise PermissionError("openrouter request output path is not fixed")
    if protected.resolve(strict=False) != OPENROUTER_PROTECTED_ROOT:
        raise PermissionError("openrouter protected root path is not fixed")
    if terminal.resolve(strict=False) != OPENROUTER_TERMINAL_OUTPUT:
        raise PermissionError("openrouter terminal output path is not fixed")
    return request, protected, terminal


def require_fixed_openrouter_v2_paths(
    *,
    request_output: Path | None = None,
    protected_root: Path | None = None,
    terminal_output: Path | None = None,
) -> tuple[Path, Path, Path]:
    """Accept only fixed r2/v2 coordinates without stat/open/list access."""

    request = OPENROUTER_V2_REQUEST_OUTPUT if request_output is None else request_output
    protected = OPENROUTER_V2_PROTECTED_ROOT if protected_root is None else protected_root
    terminal = OPENROUTER_V2_TERMINAL_OUTPUT if terminal_output is None else terminal_output
    if _lexical_absolute_path(request) != OPENROUTER_V2_REQUEST_OUTPUT:
        raise PermissionError("OPENROUTER_V2_REQUEST_PATH_NOT_FIXED")
    if _lexical_absolute_path(protected) != OPENROUTER_V2_PROTECTED_ROOT:
        raise PermissionError("OPENROUTER_V2_PROTECTED_PATH_NOT_FIXED")
    if _lexical_absolute_path(terminal) != OPENROUTER_V2_TERMINAL_OUTPUT:
        raise PermissionError("OPENROUTER_V2_TERMINAL_PATH_NOT_FIXED")
    return request, protected, terminal


# --------------------------------------------------------------------------
# Public file reads (component-wise no-follow, shared with fresh24 patterns).
# --------------------------------------------------------------------------


def _read_public_file_no_follow(path: Path, *, maximum: int = 8 * 1024 * 1024) -> bytes:
    from itda.pipeline.phase5_fresh24 import _read_public_file_no_follow as helper

    return helper(path, maximum=maximum)


def read_fixed_public_packet_bytes() -> bytes:
    return _read_public_file_no_follow(OPENROUTER_REQUEST_OUTPUT)


def openrouter_packet_digest_domains(payload: Mapping[str, object]) -> tuple[str, str]:
    unsigned = {key: value for key, value in payload.items() if key != "request_artifact_sha256"}
    return canonical_sha256(unsigned), hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def verify_openrouter_v2_predecessor_consumption(
    path: Path | None = None,
) -> OpenRouterPredecessorConsumptionV2:
    """Verify the exact public-safe failed-v1 record as non-authorizing context.

    The verifier reads only the fixed tracked report by default (or a caller's
    synthetic temporary copy for hostile tests).  It never derives from or
    observes either production protected root and never accepts approval/claim
    files themselves as input.
    """

    target = OPENROUTER_V2_PREDECESSOR_FAILURE_PATH if path is None else path
    if path is not None:
        candidate = _lexical_absolute_path(path)
        permitted = (
            candidate == OPENROUTER_V2_PREDECESSOR_FAILURE_PATH
            or str(candidate).startswith("/private/var/folders/")
            or str(candidate).startswith("/private/tmp/")
            or str(candidate).startswith("/tmp/")
        )
        if not permitted:
            raise PermissionError("OPENROUTER_V2_PREDECESSOR_OVERRIDE_NOT_SYNTHETIC")
        target = candidate
    raw = _read_public_file_no_follow(target, maximum=256 * 1024)
    payload = load_openrouter_v2_json_bytes(raw, label="PREDECESSOR")
    if (
        hashlib.sha256(raw).hexdigest()
        != "443c1a68a7053e672d6742e184dd1023556c93d4b6a827f238c2c2deb7faa6ba"
    ):
        raise ValueError("OPENROUTER_V2_PREDECESSOR_RAW_DIGEST_DRIFT")
    expected_keys = {
        "schema_version",
        "old_authority_id",
        "approval",
        "checkout",
        "failure",
        "history",
        "inventory",
        "packet",
        "record_sha256",
        "requirements_blocked",
        "requirements_completed",
        "rollover_required",
        "summary_exists",
        "terminal_exists",
        "traffic_boundary",
    }
    if set(payload) != expected_keys:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_SCHEMA_DRIFT")
    stored = payload.get("record_sha256")
    unsigned = {key: child for key, child in payload.items() if key != "record_sha256"}
    if stored != OPENROUTER_V2_PREDECESSOR_FAILURE_SHA256 or not hmac.compare_digest(
        str(stored), canonical_sha256(unsigned)
    ):
        raise ValueError("OPENROUTER_V2_PREDECESSOR_SELF_DIGEST_DRIFT")
    if payload.get("schema_version") != ("itda.phase5-openrouter-recovery-pre-reserve-failure.v1"):
        raise ValueError("OPENROUTER_V2_PREDECESSOR_RECORD_SCHEMA_DRIFT")
    if payload.get("old_authority_id") != OPENROUTER_RECOVERY_AUTHORITY_ID:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_AUTHORITY_DRIFT")

    approval = payload.get("approval")
    failure = payload.get("failure")
    inventory = payload.get("inventory")
    traffic = payload.get("traffic_boundary")
    if not all(isinstance(row, dict) for row in (approval, failure, inventory, traffic)):
        raise ValueError("OPENROUTER_V2_PREDECESSOR_SHAPE_DRIFT")
    approval_row = cast(dict[str, object], approval)
    failure_row = cast(dict[str, object], failure)
    inventory_row = cast(dict[str, object], inventory)
    traffic_row = cast(dict[str, object], traffic)
    if set(approval_row) != {
        "approval_self_sha256",
        "claim_self_sha256",
        "exact_human_approval_received",
        "installed",
        "one_use_claim_consumed",
        "protected_descriptor_sha256",
        "raw_approval_file_sha256",
        "raw_claim_file_sha256",
    }:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_APPROVAL_SHAPE_DRIFT")
    if approval_row.get("exact_human_approval_received") is not True or (
        approval_row.get("installed") is not True
        or approval_row.get("one_use_claim_consumed") is not True
    ):
        raise ValueError("OPENROUTER_V2_PREDECESSOR_NOT_CONSUMED")
    if failure_row != {
        "actual_repository_root_parent_index": 3,
        "code": "OPENROUTER_REPOSITORY_ROOT_BINDING_OFF_BY_ONE",
        "failed_before": "RESERVE",
        "pipeline_call": "_bind_public_entry().derive_authority()",
        "used_packet_parent_index": 4,
    }:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_FAILURE_DRIFT")
    if inventory_row != {"file_count": 2, "files": ["approval.json", "claim.json"]}:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_INVENTORY_DRIFT")
    if traffic_row != {
        "attempt_count": 0,
        "client_constructed": False,
        "lifecycle_mutated": False,
        "network_attempted": False,
        "provider_attempted": False,
        "reserve_count": 0,
        "secret_read": False,
        "send_attempted": False,
    }:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_TRAFFIC_DRIFT")
    if payload.get("terminal_exists") is not False or payload.get("summary_exists") is not False:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_TERMINAL_OR_SUMMARY_DRIFT")
    if payload.get("rollover_required") is not True:
        raise ValueError("OPENROUTER_V2_PREDECESSOR_ROLLOVER_NOT_REQUIRED")

    fields = {
        "schema_version": "itda.phase5-openrouter-predecessor-consumption.v2",
        "failure_record_relative_path": (
            "artifacts/reports/phase5/openrouter-recovery-pre-reserve-failure.json"
        ),
        "failure_record_sha256": stored,
        "predecessor_authority_id": payload["old_authority_id"],
        "failure_code": failure_row["code"],
        "failed_before": failure_row["failed_before"],
        "inventory_files": tuple(cast(list[str], inventory_row["files"])),
        "approval_self_sha256": approval_row["approval_self_sha256"],
        "claim_self_sha256": approval_row["claim_self_sha256"],
        "protected_descriptor_sha256": approval_row["protected_descriptor_sha256"],
        "raw_approval_file_sha256": approval_row["raw_approval_file_sha256"],
        "raw_claim_file_sha256": approval_row["raw_claim_file_sha256"],
        "approval_consumed": approval_row["installed"],
        "claim_consumed": approval_row["one_use_claim_consumed"],
        "reserve_count": traffic_row["reserve_count"],
        "attempt_count": traffic_row["attempt_count"],
        "secret_read": traffic_row["secret_read"],
        "client_constructed": traffic_row["client_constructed"],
        "send_attempted": traffic_row["send_attempted"],
        "provider_attempted": traffic_row["provider_attempted"],
        "network_attempted": traffic_row["network_attempted"],
        "lifecycle_mutated": traffic_row["lifecycle_mutated"],
        "terminal_exists": payload["terminal_exists"],
        "retry_authorized": False,
        "predecessor_authority_promoted": False,
        "rollover_context_only": True,
    }
    return OpenRouterPredecessorConsumptionV2.model_validate(
        {**fields, "consumption_sha256": canonical_sha256(fields)}
    )


# --------------------------------------------------------------------------
# Source authority (same four-file 05-34 inventory as fresh24).
# --------------------------------------------------------------------------


def verify_fixed_source_authority(root: Path = FIXED_SOURCE_ROOT):
    from itda.pipeline.phase5_fresh24 import verify_fixed_source_authority as helper

    return helper(root)


def checkout_manifest_sha256(repository_root: Path = REPOSITORY_ROOT) -> str:
    """Bind the packet-parent tree without either recovery lane self-reference."""

    from itda.pipeline.phase5_fresh24 import (
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_TERMINAL_RELATIVE,
    )

    root = repository_root.resolve(strict=True)
    source_commit = openrouter_checkout_commit_sha256(root)
    completed = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", source_commit],
        cwd=root,
        check=True,
        capture_output=True,
    )
    excluded = {
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_TERMINAL_RELATIVE,
        OPENROUTER_PUBLIC_REQUEST_RELATIVE,
        OPENROUTER_TERMINAL_RELATIVE,
    }
    rows: list[dict[str, str]] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        if name in excluded:
            continue
        rows.append({"path": name, "mode": mode, "type": kind, "object_id": object_id})
    if not rows:
        raise ValueError("openrouter checkout manifest is empty")
    return canonical_sha256(rows)


def _current_checkout_commit_sha256(repository_root: Path = REPOSITORY_ROOT) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD^{commit}"],
        cwd=repository_root.resolve(strict=True),
        check=True,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("openrouter checkout commit is invalid")
    return commit


def openrouter_checkout_commit_sha256(repository_root: Path = REPOSITORY_ROOT) -> str:
    """Resolve the full-tree commit immediately preceding the current packet."""

    root = repository_root.resolve(strict=True)
    head = _current_checkout_commit_sha256(root)
    packet_result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", OPENROUTER_PUBLIC_REQUEST_RELATIVE],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    packet_commit = packet_result.stdout.strip()
    if not packet_commit:
        return head
    if re.fullmatch(r"[0-9a-f]{40}", packet_commit) is None:
        raise ValueError("openrouter packet commit is invalid")
    source_result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", *OPENROUTER_SOURCE_AUTHORITY_PATHS],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    source_commit = source_result.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("openrouter source authority commit is invalid")
    source_after_packet = subprocess.run(
        ["git", "merge-base", "--is-ancestor", packet_commit, source_commit],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if source_after_packet.returncode == 0:
        return head
    if source_after_packet.returncode != 1:
        raise ValueError("openrouter source ancestry is invalid")
    parent_result = subprocess.run(
        ["git", "rev-parse", f"{packet_commit}^"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    parent = parent_result.stdout.strip()
    changed_result = subprocess.run(
        ["git", "diff", "--name-only", "-z", parent, packet_commit, "--"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    changed_paths = tuple(
        path.decode("utf-8") for path in changed_result.stdout.split(b"\0") if path
    )
    if changed_paths != (OPENROUTER_PUBLIC_REQUEST_RELATIVE,):
        raise ValueError("openrouter packet commit is not isolated")
    return parent


def _require_canonical_repository_root(
    repository_root: Path,
    _canonical_root: Path = REPOSITORY_ROOT,
) -> Path:
    """Reject caller/context roots against the import-time source authority."""

    root = _lexical_absolute_path(repository_root)
    canonical_root = _lexical_absolute_path(_canonical_root)
    if root != canonical_root:
        raise PermissionError("OPENROUTER_V2_REPOSITORY_ROOT_NOT_CANONICAL")
    return canonical_root


def openrouter_v2_checkout_commit_sha256(
    repository_root: Path = REPOSITORY_ROOT,
) -> str:
    """Bind the v2 source checkout from the canonical source root only."""

    root = _require_canonical_repository_root(repository_root)
    head = _current_checkout_commit_sha256(root)
    packet_result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    packet_commit = packet_result.stdout.strip()
    if not packet_commit:
        return head
    if re.fullmatch(r"[0-9a-f]{40}", packet_commit) is None:
        raise ValueError("OPENROUTER_V2_PACKET_COMMIT_INVALID")
    source_result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", *OPENROUTER_V2_SOURCE_AUTHORITY_PATHS],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    source_commit = source_result.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("OPENROUTER_V2_SOURCE_COMMIT_INVALID")
    if (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", packet_commit, source_commit],
            cwd=root,
            check=False,
            capture_output=True,
        ).returncode
        == 0
    ):
        return head
    parent = subprocess.run(
        ["git", "rev-parse", f"{packet_commit}^"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    changed = subprocess.run(
        ["git", "diff", "--name-only", "-z", parent, packet_commit, "--"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    changed_paths = tuple(row.decode("utf-8") for row in changed.split(b"\0") if row)
    if changed_paths != (OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE,):
        raise ValueError("OPENROUTER_V2_PACKET_COMMIT_NOT_ISOLATED")
    return parent


def openrouter_v2_checkout_manifest_sha256(
    repository_root: Path = REPOSITORY_ROOT,
) -> str:
    """Bind the canonical v2 source tree while excluding packet/terminal outputs."""

    root = _require_canonical_repository_root(repository_root)
    source_commit = openrouter_v2_checkout_commit_sha256(root)
    completed = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", source_commit],
        cwd=root,
        check=True,
        capture_output=True,
    )
    from itda.pipeline.phase5_fresh24 import (
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_TERMINAL_RELATIVE,
    )

    excluded = {
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_TERMINAL_RELATIVE,
        OPENROUTER_PUBLIC_REQUEST_RELATIVE,
        OPENROUTER_TERMINAL_RELATIVE,
        OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE,
        OPENROUTER_V2_TERMINAL_RELATIVE,
    }
    rows: list[dict[str, str]] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        if name not in excluded:
            rows.append({"path": name, "mode": mode, "type": kind, "object_id": object_id})
    if not rows:
        raise ValueError("OPENROUTER_V2_CHECKOUT_MANIFEST_EMPTY")
    return canonical_sha256(rows)


# --------------------------------------------------------------------------
# Plan building.
# --------------------------------------------------------------------------


def _evidence_inventory_sha256(bundle: DemoSourceBundle) -> str:
    return canonical_sha256(
        [
            {
                "evidence_id": source.evidence_id,
                "source_kind": source.source_kind,
                "source_sha256": source.source_sha256,
                "span_sha256": source.span_sha256,
            }
            for source in bundle.sources
        ]
    )


def openrouter_evidence_projection(bundle: DemoSourceBundle) -> list[dict[str, str]]:
    """The ordered per-source projection used in every outbound message."""

    return [
        {"evidence_id": s.evidence_id, "source_kind": s.source_kind, "text": s.text}
        for s in bundle.sources
    ]


def _openrouter_request_body(bundle: DemoSourceBundle) -> bytes:
    from itda.contracts.phase5_openrouter_recovery import (
        openrouter_user_message_content,
    )

    fields = openrouter_request_body_fields()
    user_content = openrouter_user_message_content(
        place_id=bundle.place_id,
        evidence=openrouter_evidence_projection(bundle),
    )
    payload: dict[str, object] = {
        "model": fields["model"],
        "messages": [
            {"role": "system", "content": OPENROUTER_PROMPT_TEXT},
            {"role": "user", "content": user_content},
        ],
    }
    for key, value in fields.items():
        if key != "model":
            payload[key] = value
    return canonical_json_bytes(payload)


def _openrouter_v2_request_body(bundle: DemoSourceBundle) -> bytes:
    from itda.contracts.phase5_openrouter_recovery import (
        openrouter_v2_user_message_content,
    )

    fields = openrouter_v2_request_body_fields()
    user_content = openrouter_v2_user_message_content(
        place_id=bundle.place_id,
        evidence=openrouter_evidence_projection(bundle),
    )
    payload: dict[str, object] = {
        "model": fields["model"],
        "messages": [
            {"role": "system", "content": OPENROUTER_V2_PROMPT_TEXT},
            {"role": "user", "content": user_content},
        ],
    }
    for key, value in fields.items():
        if key != "model":
            payload[key] = value
    reject_historical_openrouter_v2_coordinates(payload)
    return canonical_json_bytes(payload)


@dataclass(frozen=True, slots=True)
class OpenRouterMember:
    authority_id: str
    place_id: str
    source_bundle_sha256: str
    evidence_inventory_sha256: str
    request_body: bytes = field(repr=False)
    request: OpenRouterMemberRequest


@dataclass(frozen=True, slots=True)
class OpenRouterFirstPass:
    place_id: str
    order: int
    request_sha256: str
    request_body_sha256: str
    authority_id: str = OPENROUTER_RECOVERY_AUTHORITY_ID


@dataclass(frozen=True, slots=True)
class OpenRouterPlan:
    authority_id: str
    snapshot_sha256: str
    members: tuple[OpenRouterMember, ...]
    first_passes: tuple[OpenRouterFirstPass, ...]
    retry_policy: OpenRouterRetryPolicy
    exposure: OpenRouterExposurePolicy
    request_manifest_sha256: str
    request_sha256: str

    def authority_endpoint(self) -> str:
        """The ONE fixed endpoint bound to the verified snapshot."""

        load_openrouter_snapshot()
        return OPENROUTER_ENDPOINT

    checkout_commit_sha256: str
    checkout_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class OpenRouterMemberV2:
    """One r2/v2 member; no v1 request or lineage object is embedded."""

    authority_id: str
    place_id: str
    source_bundle_sha256: str
    evidence_inventory_sha256: str
    request_body: bytes = field(repr=False)
    request: OpenRouterMemberRequestV2


@dataclass(frozen=True, slots=True)
class OpenRouterPlanV2:
    """Closed provider-free r2 plan used only for packet construction/verify."""

    authority_id: str
    snapshot_sha256: str
    predecessor: OpenRouterPredecessorConsumptionV2
    members: tuple[OpenRouterMemberV2, ...]
    first_passes: tuple[OpenRouterFirstPassV2, ...]
    retry_policy: OpenRouterRetryPolicyV2
    exposure: OpenRouterExposurePolicyV2
    request_manifest_sha256: str
    request_sha256: str
    checkout_commit_sha256: str
    checkout_manifest_sha256: str

    def authority_endpoint(self) -> str:
        load_openrouter_snapshot_v2()
        return OPENROUTER_ENDPOINT


def _verified_source_bundles():
    """Module-level indirection over the fixed 05-34 source revalidation.

    Production always resolves the real four-file authority.  Temporary-root
    tests may patch THIS module attribute (never the production entry points)
    to inject synthetic validated bundles.
    """

    from itda.pipeline.phase5_fresh24 import verify_fixed_source_authority

    return verify_fixed_source_authority()


def fresh24_fixed_evidence_timestamp(checkout_commit_sha256: str) -> object:
    """The ONE deterministic UTC instant pinned by the checkout lineage.

    Delegates to the shared Fresh24 helper so the live run and every neutral
    replay inject the SAME timestamp and all result/replay digests reproduce
    byte-for-byte.
    """

    from itda.pipeline.phase5_fresh24 import (
        fresh24_fixed_evidence_timestamp as helper,
    )

    return helper(checkout_commit_sha256)


def _rebuild_approved_plan_for_approval(
    approval: OpenRouterApprovalBinding,
) -> OpenRouterPlan:
    """Deterministically rebuild the plan and bind it to THIS approval.

    The rebuild goes through the same fixed-source indirection as dispatch;
    the resulting member manifest must equal the APPROVED manifest digest — a
    drifted source or a foreign manifest can never masquerade as the approved
    member set during neutral verification.
    """

    rebuilt = build_openrouter_plan(
        _verified_source_bundles(),
        checkout_manifest_digest=str(approval.checkout_manifest_sha256),
    )
    if str(rebuilt.request_manifest_sha256) != str(approval.request_manifest_sha256):
        raise ValueError("openrouter rebuilt manifest drifted from approval binding")
    if str(rebuilt.checkout_commit_sha256) != str(approval.checkout_commit_sha256):
        raise ValueError("openrouter rebuilt checkout commit drifted from approval")
    return rebuilt


def build_openrouter_plan(
    source_bundles: Sequence[DemoSourceBundle],
    *,
    checkout_manifest_digest: str,
) -> OpenRouterPlan:
    validate_openrouter_namespace()
    snapshot = load_openrouter_snapshot()
    from itda.pipeline.demo_profile_materialization import (
        validate_demo_source_inventory,
    )

    bundles = _verified_source_bundles()
    supplied = validate_demo_source_inventory(tuple(source_bundles))
    if tuple(b.source_bundle_sha256 for b in supplied) != tuple(
        b.source_bundle_sha256 for b in bundles
    ):
        raise ValueError("openrouter source inventory is not the fixed four-file authority")
    members: list[OpenRouterMember] = []
    first_passes: list[OpenRouterFirstPass] = []
    member_requests: list[OpenRouterMemberRequest] = []
    config_sha = _config_sha256_for_lineage(snapshot)
    for order, bundle in enumerate(bundles, start=1):
        request_body = _openrouter_request_body(bundle)
        body_digest = hashlib.sha256(request_body).hexdigest()
        preimage = {
            "schema_version": "itda.phase5-openrouter-member-request.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "place_id": bundle.place_id,
            "split": "DEV",
            "first_pass_order": order,
            "source_bundle_sha256": bundle.source_bundle_sha256,
            "evidence_inventory_sha256": _evidence_inventory_sha256(bundle),
            "request_body_sha256": body_digest,
        }
        request = OpenRouterMemberRequest.model_validate(
            {**preimage, "request_sha256": canonical_sha256(preimage)}
        )
        members.append(
            OpenRouterMember(
                authority_id=OPENROUTER_RECOVERY_AUTHORITY_ID,
                place_id=bundle.place_id,
                source_bundle_sha256=bundle.source_bundle_sha256,
                evidence_inventory_sha256=_evidence_inventory_sha256(bundle),
                request_body=request_body,
                request=request,
            )
        )
        member_requests.append(request)
        first_passes.append(
            OpenRouterFirstPass(
                place_id=bundle.place_id,
                order=order,
                request_sha256=request.request_sha256,
                request_body_sha256=body_digest,
            )
        )
    retry_policy = OpenRouterRetryPolicy()
    exposure = OpenRouterExposurePolicy()
    manifest = canonical_sha256(
        [
            {
                "place_id": r.place_id,
                "request_sha256": r.request_sha256,
                "request_body_sha256": r.request_body_sha256,
            }
            for r in member_requests
        ]
    )
    checkout_commit = openrouter_checkout_commit_sha256(REPOSITORY_ROOT)
    request_sha = canonical_sha256(
        {
            "schema_version": "itda.phase5-openrouter-recovery-request.v1",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "snapshot_sha256": str(snapshot.snapshot_sha256),
            "request_manifest_sha256": manifest,
            "checkout_commit_sha256": checkout_commit,
            "checkout_manifest_sha256": _require_digest(
                checkout_manifest_digest, "checkout manifest"
            ),
        }
    )
    del config_sha
    return OpenRouterPlan(
        authority_id=OPENROUTER_RECOVERY_AUTHORITY_ID,
        snapshot_sha256=str(snapshot.snapshot_sha256),
        members=tuple(members),
        first_passes=tuple(first_passes),
        retry_policy=retry_policy,
        exposure=exposure,
        request_manifest_sha256=manifest,
        request_sha256=request_sha,
        checkout_commit_sha256=checkout_commit,
        checkout_manifest_sha256=_require_digest(checkout_manifest_digest, "checkout manifest"),
    )


def build_openrouter_v2_plan(
    source_bundles: Sequence[DemoSourceBundle],
    *,
    checkout_manifest_digest: str,
    repository_root: Path = REPOSITORY_ROOT,
    predecessor_path: Path | None = None,
) -> OpenRouterPlanV2:
    """Build the disjoint provider-free r2 plan from source and public history.

    ``repository_root`` defaults to the source-derived constant captured at
    function definition.  The argument exists only for hostile tests and is
    rejected unless it is lexically identical to that canonical root.
    """

    root = _require_canonical_repository_root(repository_root)
    validate_openrouter_v2_namespace()
    snapshot = load_openrouter_snapshot_v2()
    predecessor = verify_openrouter_v2_predecessor_consumption(predecessor_path)
    from itda.pipeline.demo_profile_materialization import (
        validate_demo_source_inventory,
    )

    fixed_bundles = _verified_source_bundles()
    bundles = validate_demo_source_inventory(tuple(source_bundles))
    if tuple(bundle.source_bundle_sha256 for bundle in bundles) != tuple(
        bundle.source_bundle_sha256 for bundle in fixed_bundles
    ):
        raise ValueError("OPENROUTER_V2_SOURCE_INVENTORY_NOT_FIXED")
    bundles = validate_demo_source_inventory(tuple(fixed_bundles))
    members: list[OpenRouterMemberV2] = []
    first_passes: list[OpenRouterFirstPassV2] = []
    for order, bundle in enumerate(bundles, start=1):
        request_body = _openrouter_v2_request_body(bundle)
        body_digest = hashlib.sha256(request_body).hexdigest()
        preimage = {
            "schema_version": "itda.phase5-openrouter-member-request.v2",
            "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
            "place_id": bundle.place_id,
            "split": "DEV",
            "first_pass_order": order,
            "source_bundle_sha256": bundle.source_bundle_sha256,
            "evidence_inventory_sha256": _evidence_inventory_sha256(bundle),
            "request_body_sha256": body_digest,
        }
        request_sha256 = canonical_sha256(preimage)
        lineage_sha256 = canonical_sha256(
            {
                "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
                "place_id": bundle.place_id,
                "source_bundle_sha256": bundle.source_bundle_sha256,
                "evidence_inventory_sha256": _evidence_inventory_sha256(bundle),
                "request_sha256": request_sha256,
                "prompt_sha256": OPENROUTER_V2_PROMPT_SHA256,
                "profile_schema_version": OPENROUTER_V2_PROFILE_SCHEMA,
                "config_version": "phase5-openrouter-config.v2",
                "preprocessing_version": OPENROUTER_V2_PREPROCESSING_VERSION,
                "snapshot_sha256": snapshot.snapshot_sha256,
            }
        )
        request = OpenRouterMemberRequestV2.model_validate(
            {**preimage, "request_sha256": request_sha256, "lineage_sha256": lineage_sha256}
        )
        members.append(
            OpenRouterMemberV2(
                authority_id=OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
                place_id=bundle.place_id,
                source_bundle_sha256=bundle.source_bundle_sha256,
                evidence_inventory_sha256=_evidence_inventory_sha256(bundle),
                request_body=request_body,
                request=request,
            )
        )
        first_passes.append(
            OpenRouterFirstPassV2(
                schema_version="itda.phase5-openrouter-first-pass.v2",
                authority_id=OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
                place_id=bundle.place_id,
                order=order,
                request_sha256=request.request_sha256,
                request_body_sha256=body_digest,
            )
        )
    retry_policy = build_openrouter_retry_policy_v2()
    exposure = build_openrouter_exposure_policy_v2()
    manifest = canonical_sha256(
        [
            {
                "schema_version": row.schema_version,
                "authority_id": row.authority_id,
                "place_id": row.place_id,
                "request_sha256": row.request_sha256,
                "request_body_sha256": row.request_body_sha256,
            }
            for row in first_passes
        ]
    )
    checkout_commit = openrouter_v2_checkout_commit_sha256(root)
    checkout_manifest = _require_digest(checkout_manifest_digest, "v2 checkout manifest")
    request_sha = canonical_sha256(
        {
            "schema_version": OPENROUTER_V2_REQUEST_SCHEMA,
            "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "predecessor_consumption_sha256": predecessor.consumption_sha256,
            "request_manifest_sha256": manifest,
            "checkout_commit_sha256": checkout_commit,
            "checkout_manifest_sha256": checkout_manifest,
        }
    )
    return OpenRouterPlanV2(
        authority_id=OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        snapshot_sha256=str(snapshot.snapshot_sha256),
        predecessor=predecessor,
        members=tuple(members),
        first_passes=tuple(first_passes),
        retry_policy=retry_policy,
        exposure=exposure,
        request_manifest_sha256=manifest,
        request_sha256=request_sha,
        checkout_commit_sha256=checkout_commit,
        checkout_manifest_sha256=checkout_manifest,
    )


def _config_sha256_for_lineage(snapshot: object) -> str:
    del snapshot
    from itda.contracts.phase5_openrouter_recovery import _config_sha256

    return _config_sha256()


def validate_openrouter_namespace() -> None:
    """The namespace must stay disjoint from every historical lane."""

    if OPENROUTER_RECOVERY_AUTHORITY_ID in HISTORICAL_AUTHORITY_IDS:
        raise ValueError("openrouter authority cannot reuse a historical identity")


def validate_openrouter_v2_namespace() -> None:
    """The r2 authority is disjoint from v1 and every historical provider lane."""

    if OPENROUTER_V2_RECOVERY_AUTHORITY_ID in (
        HISTORICAL_AUTHORITY_IDS | {OPENROUTER_RECOVERY_AUTHORITY_ID}
    ):
        raise ValueError("OPENROUTER_V2_AUTHORITY_NOT_DISJOINT")
    if (
        len(
            {
                OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE,
                OPENROUTER_V2_PROTECTED_ROOT_RELATIVE,
                OPENROUTER_V2_TERMINAL_RELATIVE,
                OPENROUTER_V2_SNAPSHOT_RELATIVE,
            }
        )
        != 4
    ):
        raise ValueError("OPENROUTER_V2_PATHS_NOT_DISJOINT")


# --------------------------------------------------------------------------
# Exact request-body validator used by tests and preflight.
# --------------------------------------------------------------------------


def validate_request_body_exact(body: Mapping[str, object]) -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        validate_openrouter_request_body,
    )

    validate_openrouter_request_body(body)


def reconstruct_member_body_exact(member: OpenRouterMember) -> bytes:
    """T-05R-95: rebuild ONE member's outbound body from the FIXED source.

    The stored ``member.request_body`` is never trusted on the dispatch path.
    The fixed four-file source authority is reverified, the member's approved
    place/source/inventory identity is matched against the reopened bundles,
    the canonical body bytes are reconstructed, and the reconstruction must
    hash to the approved member-manifest digest byte-exactly.  The canonical
    user content is re-parsed and its evidence rows revalidated (exact key
    set, ordered evidence IDs/text equal to the verified projection,
    forbidden-marker rescan) so no drifted, reordered, or poisoned payload
    can reach the transport.
    """

    from itda.contracts.phase5_openrouter_recovery import (
        _FORBIDDEN_CONTENT_MARKERS,
        validate_openrouter_request_body,
    )

    bundles = _verified_source_bundles()
    matched = [bundle for bundle in bundles if str(bundle.place_id) == str(member.place_id)]
    if len(matched) != 1:
        raise PermissionError("OPENROUTER_BODY_SOURCE_MEMBER_NOT_UNIQUE")
    bundle = matched[0]
    if str(bundle.source_bundle_sha256) != str(member.source_bundle_sha256) or (
        _evidence_inventory_sha256(bundle) != member.evidence_inventory_sha256
    ):
        raise PermissionError("OPENROUTER_BODY_SOURCE_IDENTITY_DRIFT")
    expected_body = _openrouter_request_body(bundle)
    if hashlib.sha256(expected_body).hexdigest() != str(member.request.request_body_sha256):
        raise PermissionError("OPENROUTER_BODY_RECONSTRUCTION_DIGEST_DRIFT")
    try:
        parsed = json.loads(expected_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PermissionError("OPENROUTER_BODY_RECONSTRUCTION_INVALID") from error
    validate_openrouter_request_body(parsed, expected_place_id=str(member.place_id))
    user_message = parsed["messages"][1]
    decoded = json.loads(str(user_message["content"]))
    projection = openrouter_evidence_projection(bundle)
    if decoded["evidence"] != projection:
        raise PermissionError("OPENROUTER_BODY_EVIDENCE_PROJECTION_DRIFT")
    if decoded["place_id"] != member.place_id:
        raise PermissionError("OPENROUTER_BODY_PLACE_LINEAGE_DRIFT")
    for row in decoded["evidence"]:
        for value in row.values():
            folded = str(value).lower()
            for marker in _FORBIDDEN_CONTENT_MARKERS:
                if marker in folded:
                    raise PermissionError("OPENROUTER_BODY_FORBIDDEN_CONTENT")
    return expected_body


# --------------------------------------------------------------------------
# Scheduler.
# --------------------------------------------------------------------------


class OpenRouterScheduler:
    """24 first passes then at most six retries; concurrency one."""

    def __init__(self, place_ids: Sequence[str]) -> None:
        self._place_ids = tuple(place_ids)
        if len(self._place_ids) != 24 or len(set(self._place_ids)) != 24:
            raise ValueError("openrouter scheduler requires 24 unique places")
        self._first_pass_done = False
        self._retry_places: tuple[str, ...] = ()
        self._dispatched = 0
        self._first_pass_dispatches = 0

    @property
    def attempt_count(self) -> int:
        return self._dispatched

    def first_pass(self) -> tuple[str, ...]:
        if self._first_pass_done:
            raise RuntimeError("openrouter first pass already consumed")
        self._first_pass_done = True
        return self._place_ids

    def record_dispatched(self, place_id: str, *, is_retry: bool) -> None:
        self._dispatched += 1
        if not is_retry:
            self._first_pass_dispatches += 1

    def retry_order(self, retryable_places: Sequence[str]) -> tuple[str, ...]:
        if not self._first_pass_done:
            raise RuntimeError("openrouter retries require all first passes")
        if self._first_pass_dispatches < OPENROUTER_FIRST_PASS_COUNT:
            raise RuntimeError("openrouter retries require all 24 first passes dispatched")
        if self._retry_places:
            raise RuntimeError("openrouter retry attempt budget already consumed")
        requested = tuple(retryable_places)
        if len(requested) > OPENROUTER_MAX_RETRIES or len(set(requested)) != len(requested):
            raise RuntimeError("openrouter retry budget exhausted")
        if requested != tuple(sorted(requested)):
            raise RuntimeError("openrouter retry order is not canonical")
        if any(place not in self._place_ids for place in requested):
            raise RuntimeError("openrouter retry place is not in first-pass inventory")
        projected = self._dispatched + len(requested)
        if projected > OPENROUTER_MAX_ATTEMPTS:
            raise RuntimeError("openrouter attempt budget exhausted")
        self._retry_places = requested
        return requested

    def classify_retry(
        self,
        *,
        error: BaseException | str | None = None,
        status_code: int | None = None,
    ) -> bool:
        if status_code is not None:
            return status_code in OPENROUTER_RETRYABLE_HTTP_STATUSES
        name = type(error).__name__ if not isinstance(error, str) else error
        return name in OPENROUTER_RETRYABLE_TRANSPORT_NAMES


# --------------------------------------------------------------------------
# Durable protected state.
# --------------------------------------------------------------------------

_OPENROUTER_TEST_ROOT_MARKERS = ("/tmp/", "/private/tmp/", "/var/folders/")


def synthetic_openrouter_claim(request_artifact_sha256: str) -> OpenRouterClaim:
    claim_fields = {
        "schema_version": OPENROUTER_CLAIM_SCHEMA,
        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
        "request_artifact_sha256": request_artifact_sha256,
        "request_file_sha256": request_artifact_sha256,
        "approval_sha256": "c" * 64,
        "protected_state_sha256": "d" * 64,
    }
    return OpenRouterClaim.model_validate(
        {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
    )


class OpenRouterProtectedState:
    """Provider-free reservation state for contract and MockTransport tests."""

    def __init__(self, root: Path) -> None:
        if root.is_symlink():
            raise PermissionError("openrouter protected root cannot be a symlink")
        self.root = root
        self.authority_id = OPENROUTER_RECOVERY_AUTHORITY_ID
        self.events: list[dict[str, object]] = []

    def append_event(self, operation: str, *, place_id: str, ordinal: int) -> None:
        predecessor = self.events[-1]["event_sha256"] if self.events else "0" * 64
        preimage = {
            "authority_id": self.authority_id,
            "sequence": len(self.events) + 1,
            "operation": operation,
            "attempt_number": ordinal,
            "amount_micro_usd": OPENROUTER_RESERVATION_MICRO_USD,
            "place_id": place_id,
            "predecessor_sha256": predecessor,
        }
        self.events.append({**preimage, "event_sha256": canonical_sha256(preimage)})


class OpenRouterDurableAuthorityState:
    """Restart-safe approval, one-use claim, zero-price ledger, and journal.

    Mirrors the Fresh24 write discipline (no-follow, create-only rename,
    fsync-before-commit, canonical JSONL) over the disjoint namespace with an
    EXACT-ZERO amount on every RESERVE/DISPATCH/COMMIT event.
    """

    _MAX_STATE_BYTES = 8 * 1024 * 1024

    def __init__(self, descriptor: OpenRouterProtectedStateDescriptor) -> None:
        self._descriptor = descriptor
        root = Path(descriptor.state_root)
        if not root.is_absolute():
            raise PermissionError("OPENROUTER_PROTECTED_ROOT_NOT_LEXICAL")
        self._root = root
        self._names = {
            "approval": "approval.json",
            "claim": "claim.json",
            "ledger": "ledger.jsonl",
            "journal": "journal",
            "raw": "raw-evidence",
            "profiles": "profiles",
            "generation": "generation.json",
            "terminal": "terminal.json",
        }
        self._lock = threading.RLock()

    @property
    def descriptor(self) -> OpenRouterProtectedStateDescriptor:
        return self._descriptor

    # ------------------------------------------------------------------ roots

    def _open_root(self, *, create: bool) -> int:
        target = self._root
        text = str(target)
        if text.startswith("/tmp/") or text == "/tmp":
            target = Path("/private/tmp") / Path(*target.parts[2:])
        elif text.startswith("/var/") or text == "/var":
            target = Path("/private/var") / Path(*target.parts[2:])
        descriptor_fd = open_directory_chain_no_follow(target, create=create)
        try:
            metadata = os.fstat(descriptor_fd)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise PermissionError("OPENROUTER_PROTECTED_ROOT_NOT_PRIVATE")
            if metadata.st_uid != os.getuid():
                raise PermissionError("OPENROUTER_PROTECTED_ROOT_OWNER_INVALID")
        except BaseException:
            os.close(descriptor_fd)
            raise
        return descriptor_fd

    def _open_private_dir(self, parent: int, name: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            child = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            with suppress(FileExistsError):
                os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
            child = os.open(name, flags, dir_fd=parent)
        metadata = os.fstat(child)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(child)
            raise PermissionError("OPENROUTER_PROTECTED_DIRECTORY_INVALID")
        return child

    def _open_existing_private_dir(self, parent: int, name: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        child = os.open(name, flags, dir_fd=parent)
        metadata = os.fstat(child)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(child)
            raise PermissionError("OPENROUTER_PROTECTED_DIRECTORY_INVALID")
        return child

    def _exists(self, directory: int, name: str) -> bool:
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        except FileNotFoundError:
            return False
        os.close(fd)
        return True

    # ------------------------------------------------------------------ files

    def _read_regular_bytes(
        self,
        directory: int,
        name: str,
        *,
        allow_empty: bool = False,
        maximum: int | None = None,
    ) -> bytes:
        limit = maximum if maximum is not None else self._MAX_STATE_BYTES
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
        try:
            before = os.fstat(fd)
            valid_size = (
                0 <= before.st_size <= limit if allow_empty else 0 < before.st_size <= limit
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or not valid_size
            ):
                raise PermissionError("OPENROUTER_PROTECTED_FILE_INVALID")
            payload = bytearray()
            while len(payload) < before.st_size:
                chunk = os.read(fd, min(65_536, before.st_size - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            after = os.fstat(fd)
            if len(payload) != before.st_size or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise PermissionError("OPENROUTER_PROTECTED_FILE_CHANGED")
            return bytes(payload)
        finally:
            os.close(fd)

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("openrouter protected JSON contains duplicate keys")
            value[key] = child
        return value

    @classmethod
    def _parse_canonical_json_object(cls, payload: bytes) -> dict[str, object]:
        value = json.loads(payload, object_pairs_hook=cls._unique_object)
        if not isinstance(value, dict):
            raise ValueError("openrouter protected JSON must be an object")
        return value

    def _read_canonical_json(self, directory: int, name: str) -> dict[str, object]:
        raw = self._read_regular_bytes(directory, name)
        try:
            value = self._parse_canonical_json_object(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise PermissionError("OPENROUTER_PROTECTED_FILE_INVALID") from error
        if canonical_json_bytes(value) != raw:
            raise PermissionError("OPENROUTER_PROTECTED_FILE_NOT_CANONICAL")
        return value

    def _publish_create_only(self, directory: int, name: str, payload: bytes) -> None:
        staging_name = f".{name}.stage-{uuid.uuid4().hex}"
        published = False
        try:
            fd = os.open(
                staging_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory,
            )
            try:
                os.fchmod(fd, 0o600)
                written = 0
                while written < len(payload):
                    count = os.write(fd, payload[written:])
                    if count <= 0:
                        raise OSError("short protected-state write")
                    written += count
                os.fsync(fd)
            finally:
                os.close(fd)
            _rename_noreplace_at(directory, staging_name, directory, name)
            published = True
            os.fsync(directory)
        finally:
            if not published:
                with suppress(FileNotFoundError):
                    os.unlink(staging_name, dir_fd=directory)

    def _publish_or_require_exact(
        self,
        directory: int,
        name: str,
        payload: bytes,
        *,
        allow_empty: bool = False,
    ) -> None:
        try:
            self._publish_create_only(directory, name, payload)
        except FileExistsError:
            existing = self._read_regular_bytes(directory, name, allow_empty=allow_empty)
            if existing != payload:
                raise PermissionError("OPENROUTER_PROTECTED_REPLACEMENT_FORBIDDEN") from None

    def _append_jsonl_line(self, directory: int, name: str, line: bytes) -> None:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise PermissionError("OPENROUTER_LEDGER_INVALID")
            written = 0
            while written < len(line):
                count = os.write(fd, line[written:])
                if count <= 0:
                    raise OSError("short protected ledger write")
                written += count
            os.fsync(fd)
        finally:
            os.close(fd)

    # ----------------------------------------------------------------- ledger

    @classmethod
    def _parse_ledger(cls, payload: bytes) -> list[dict[str, object]]:
        if not payload.endswith(b"\n") or b"\n\n" in payload:
            raise ValueError("openrouter protected ledger framing is invalid")
        entries: list[dict[str, object]] = []
        for line in payload[:-1].split(b"\n"):
            try:
                value = cls._parse_canonical_json_object(line)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise ValueError("openrouter protected ledger JSON is invalid") from error
            if canonical_json_bytes(value) != line:
                raise ValueError("openrouter protected ledger is not canonical")
            entries.append(value)
        return entries

    def read_ledger_entries(self) -> list[dict[str, object]]:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["ledger"]):
                    return []
                return self._parse_ledger(self._read_regular_bytes(root_fd, self._names["ledger"]))
            finally:
                os.close(root_fd)

    def committed_exposure_micro_usd(self) -> int:
        return sum(
            int(entry.get("amount_micro_usd", 0))
            for entry in self.read_ledger_entries()
            if entry.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        )

    def committed_attempt_counts(self) -> dict[str, int]:
        """Operation-aware counts proving zero-price event persistence."""

        entries = self.read_ledger_entries()
        return {
            "RESERVE": sum(1 for row in entries if row.get("operation") == "RESERVE"),
            "DISPATCH": sum(1 for row in entries if row.get("operation") == "DISPATCH"),
            "COMMIT": sum(1 for row in entries if row.get("operation") == "COMMIT"),
        }

    # --------------------------------------------------------------- approval

    def install_approval(
        self,
        approval: OpenRouterApprovalBinding,
        *,
        request_artifact: Mapping[str, object],
    ) -> dict[str, object]:
        self._validate_approval(approval)
        expected_artifact_digest = request_artifact.get("request_artifact_sha256")
        if (
            not isinstance(expected_artifact_digest, str)
            or not _DIGEST.fullmatch(expected_artifact_digest)
            or expected_artifact_digest != approval.request_artifact_sha256
        ):
            raise PermissionError("OPENROUTER_APPROVAL_ARTIFACT_MISMATCH")
        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                if self._exists(root_fd, self._names["claim"]):
                    raise PermissionError("OPENROUTER_ALREADY_CLAIMED")
                self._publish_or_require_exact(
                    root_fd,
                    self._names["approval"],
                    canonical_json_bytes(approval.model_dump(mode="json")),
                )
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        return {
            "schema_version": OPENROUTER_APPROVAL_STATUS_SCHEMA,
            "status": "APPROVED_UNCLAIMED",
            "authority_id": approval.authority_id,
            "approval_sha256": approval.approval_sha256,
            "claimed": False,
        }

    def read_approval(self) -> OpenRouterApprovalBinding:
        root_fd = self._open_root(create=False)
        try:
            approval = OpenRouterApprovalBinding.model_validate(
                self._read_canonical_json(root_fd, self._names["approval"])
            )
            self._validate_approval(approval)
            return approval
        finally:
            os.close(root_fd)

    def read_claim(self) -> OpenRouterClaim:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["claim"]):
                raise PermissionError("OPENROUTER_CLAIM_INVALID")
            claim = OpenRouterClaim.model_validate(
                self._read_canonical_json(root_fd, self._names["claim"])
            )
        finally:
            os.close(root_fd)
        self._require_exact_claim(claim=claim)
        return claim

    def require_approval_matches_artifact(
        self, *, request_artifact: Mapping[str, object]
    ) -> OpenRouterApprovalBinding:
        approval = self.read_approval()
        artifact_digest = request_artifact.get("request_artifact_sha256")
        if (
            not isinstance(artifact_digest, str)
            or not _DIGEST.fullmatch(artifact_digest)
            or artifact_digest != approval.request_artifact_sha256
        ):
            raise PermissionError("OPENROUTER_STALE_APPROVAL")
        return approval

    def _validate_approval(self, approval: OpenRouterApprovalBinding) -> None:
        if approval.authority_id != self._descriptor.authority_id:
            raise PermissionError("OPENROUTER_APPROVAL_AUTHORITY_MISMATCH")
        if approval.protected_state_sha256 != self._descriptor.protected_state_sha256:
            raise PermissionError("OPENROUTER_APPROVAL_PROTECTED_STATE_MISMATCH")

    # ------------------------------------------------------------------ claim

    def claim_once(self, *, request_artifact: Mapping[str, object]) -> OpenRouterClaim:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                approval = OpenRouterApprovalBinding.model_validate(
                    self._read_canonical_json(root_fd, self._names["approval"])
                )
                self._validate_approval(approval)
                artifact_digest = request_artifact.get("request_artifact_sha256")
                if (
                    not isinstance(artifact_digest, str)
                    or not _DIGEST.fullmatch(artifact_digest)
                    or artifact_digest != approval.request_artifact_sha256
                ):
                    raise PermissionError("OPENROUTER_STALE_APPROVAL")
                claim_fields = {
                    "schema_version": OPENROUTER_CLAIM_SCHEMA,
                    "authority_id": approval.authority_id,
                    "request_artifact_sha256": approval.request_artifact_sha256,
                    "request_file_sha256": approval.request_file_sha256,
                    "approval_sha256": approval.approval_sha256,
                    "protected_state_sha256": approval.protected_state_sha256,
                }
                claim = OpenRouterClaim.model_validate(
                    {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
                )
                try:
                    self._publish_create_only(
                        root_fd,
                        self._names["claim"],
                        canonical_json_bytes(claim.model_dump(mode="json")),
                    )
                except FileExistsError as error:
                    raise PermissionError("OPENROUTER_ALREADY_CLAIMED") from error
                os.fsync(root_fd)
                return claim
            finally:
                os.close(root_fd)

    def _require_exact_claim(self, *, claim: OpenRouterClaim) -> OpenRouterApprovalBinding:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["claim"]):
                raise PermissionError("OPENROUTER_CLAIM_INVALID")
            persisted = OpenRouterClaim.model_validate(
                self._read_canonical_json(root_fd, self._names["claim"])
            )
            approval = OpenRouterApprovalBinding.model_validate(
                self._read_canonical_json(root_fd, self._names["approval"])
            )
        finally:
            os.close(root_fd)
        if persisted != claim or claim.approval_sha256 != approval.approval_sha256:
            raise PermissionError("OPENROUTER_CLAIM_INVALID")
        return approval

    # ---------------------------------------------------------------- reserve

    def reserve_once(self, *, claim: OpenRouterClaim, place_id: str, request_sha256: str) -> int:
        """Durably append the zero-amount claim-bound RESERVE entry."""

        approval = self._require_exact_claim(claim=claim)
        _require_digest(request_sha256, "request digest")
        entries_snapshot = self.read_ledger_entries()
        attempt_number = sum(1 for row in entries_snapshot if row.get("operation") == "RESERVE") + 1
        if attempt_number > OPENROUTER_MAX_ATTEMPTS:
            raise RuntimeError("openrouter attempt budget exhausted")
        prior = [
            row
            for row in entries_snapshot
            if row.get("operation") == "RESERVE"
            and row.get("request_sha256") == request_sha256
            and row.get("place_id") == place_id
        ]
        if len(prior) >= 2:
            raise PermissionError("OPENROUTER_RESERVATION_DUPLICATE")
        if prior and int(prior[-1].get("attempt_number", 0)) < attempt_number:
            prior_ordinal = int(prior[-1].get("attempt_number", 0))
            prior_settled = any(
                row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
                and row.get("request_sha256") == request_sha256
                and row.get("place_id") == place_id
                and int(row.get("attempt_number", 0)) == prior_ordinal
                for row in entries_snapshot
            )
            if not prior_settled:
                raise PermissionError("OPENROUTER_RESERVATION_OUTSTANDING")
        entry = {
            "schema_version": OPENROUTER_LEDGER_ENTRY_SCHEMA,
            "authority_id": approval.authority_id,
            "operation": "RESERVE",
            "attempt_number": attempt_number,
            "amount_micro_usd": OPENROUTER_RESERVATION_MICRO_USD,
            "price_status": "EXACT_ZERO",
            # WR-A strict re-audit: the RESERVE row itself persists its phase.
            # A crash leaving ONLY this row is deterministically reconcilable:
            # nothing past reservation happened (client=false, network=false).
            "dispatch_phase": OPENROUTER_DISPATCH_PHASE_RESERVED,
            "place_id": place_id,
            "request_sha256": request_sha256,
            "claim_sha256": claim.claim_sha256,
        }
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if self._exists(root_fd, self._names["ledger"]):
                    current = self._read_regular_bytes(
                        root_fd, self._names["ledger"], allow_empty=True
                    )
                    current_entries = self._parse_ledger(current) if current else []
                else:
                    current_entries = []
                if tuple(canonical_json_bytes(row) for row in current_entries) != tuple(
                    canonical_json_bytes(row) for row in entries_snapshot
                ):
                    raise PermissionError("OPENROUTER_RESERVATION_RACE_INVALID")
                line = canonical_json_bytes(entry) + b"\n"
                if not current_entries:
                    self._publish_or_require_exact(
                        root_fd, self._names["ledger"], line, allow_empty=True
                    )
                else:
                    self._append_jsonl_line(root_fd, self._names["ledger"], line)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        return attempt_number

    # --------------------------------------------------------------- dispatch

    def record_dispatch(
        self,
        *,
        claim: OpenRouterClaim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
    ) -> int:
        """Create-only per-attempt DISPATCH marker before awaiting transport.

        Both a ledger DISPATCH row AND a journal marker are persisted; the
        credential value may only be resolved AFTER both are durable.
        """

        approval = self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                entries = self._read_ledger_from(root_fd)
                dispatch_row = {
                    "schema_version": OPENROUTER_LEDGER_ENTRY_SCHEMA,
                    "authority_id": approval.authority_id,
                    "operation": "DISPATCH",
                    "attempt_number": attempt_number,
                    "amount_micro_usd": OPENROUTER_RESERVATION_MICRO_USD,
                    "price_status": "EXACT_ZERO",
                    "place_id": place_id,
                    "request_sha256": request_sha256,
                    "claim_sha256": claim.claim_sha256,
                }
                self._append_jsonl_line(
                    root_fd,
                    self._names["ledger"],
                    canonical_json_bytes(dispatch_row) + b"\n",
                )
                journal = self._open_private_dir(root_fd, self._names["journal"])
                try:
                    dispatch = {
                        "schema_version": OPENROUTER_DISPATCH_SCHEMA,
                        "authority_id": approval.authority_id,
                        "place_id": place_id,
                        "request_sha256": request_sha256,
                        "claim_sha256": claim.claim_sha256,
                        "attempt_number": attempt_number,
                        # WR-A re-audit: this durable marker proves ONLY that
                        # the attempt was PREPARED for dispatch — it is NOT a
                        # CONFIRMED_SENT fact.  The send phase is recorded
                        # separately (record_send_started) immediately before
                        # the request operation; until then the wire state is
                        # unconfirmed by design.
                        "dispatch_phase": OPENROUTER_DISPATCH_PHASE_PREPARED,
                        "dispatch_certainty": OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN,
                        "committed_exposure_micro_usd": self._committed_exposure_from(entries),
                    }
                    self._publish_create_only(
                        journal,
                        f"dispatch-{attempt_number:02d}.json",
                        canonical_json_bytes(dispatch),
                    )
                    os.fsync(journal)
                finally:
                    os.close(journal)
                os.fsync(root_fd)
                return attempt_number
            finally:
                os.close(root_fd)

    def record_client_constructed(
        self,
        *,
        claim: OpenRouterClaim,
        place_id: str,
        attempt_number: int,
    ) -> None:
        """WR-A final semantics: durable CLIENT_CONSTRUCTED marker.

        Written IMMEDIATELY AFTER the client constructor returned.  This is a
        locally confirmable fact (the object exists in this process); the
        marker is create-only and fsynced before control returns.  It proves
        NOTHING about any send operation.
        """

        self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                journal = self._open_existing_private_dir(root_fd, self._names["journal"])
                try:
                    marker = {
                        "schema_version": OPENROUTER_DISPATCH_SCHEMA,
                        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
                        "place_id": place_id,
                        "claim_sha256": claim.claim_sha256,
                        "attempt_number": attempt_number,
                        "client_fact": OPENROUTER_CLIENT_FACT_CONFIRMED,
                    }
                    self._publish_create_only(
                        journal,
                        f"client-{attempt_number:02d}.json",
                        canonical_json_bytes(marker),
                    )
                    os.fsync(journal)
                finally:
                    os.close(journal)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)

    def record_send_boundary(
        self,
        *,
        claim: OpenRouterClaim,
        place_id: str,
        attempt_number: int,
    ) -> None:
        """WR-A final semantics: durable SEND-BOUNDARY marker.

        Written immediately BEFORE ``stream()``.  A marker persisted BEFORE an
        operation cannot prove the operation ran, let alone that anything was
        SENT — it records exactly ``SEND_ATTEMPT_MAY_HAVE_STARTED``: the send
        boundary was reached, the request MAY have started, and wire delivery
        stays UNKNOWN_AFTER_SEND_BOUNDARY forever.  Create-only and fsynced.
        """

        self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                journal = self._open_existing_private_dir(root_fd, self._names["journal"])
                try:
                    marker = {
                        "schema_version": OPENROUTER_DISPATCH_SCHEMA,
                        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
                        "place_id": place_id,
                        "claim_sha256": claim.claim_sha256,
                        "attempt_number": attempt_number,
                        "send_fact": OPENROUTER_SEND_MAY_HAVE_STARTED,
                    }
                    self._publish_create_only(
                        journal,
                        f"send-boundary-{attempt_number:02d}.json",
                        canonical_json_bytes(marker),
                    )
                    os.fsync(journal)
                finally:
                    os.close(journal)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)

    def _read_ledger_from(self, root_fd: int) -> list[dict[str, object]]:
        if self._exists(root_fd, self._names["ledger"]):
            raw = self._read_regular_bytes(root_fd, self._names["ledger"], allow_empty=True)
            return self._parse_ledger(raw) if raw else []
        return []

    @staticmethod
    def _committed_exposure_from(entries: Sequence[Mapping[str, object]]) -> int:
        return sum(
            int(row.get("amount_micro_usd", 0))
            for row in entries
            if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        )

    # ---------------------------------------------------------------- outcome

    def persist_attempt_evidence(
        self,
        *,
        claim: OpenRouterClaim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        response_body: bytes | None,
        status_code: int | None,
        credential_response_stripped: bool = False,
    ) -> str:
        """Persist one attempt's evidence (T-05R-95 secret-safe).

        When ``credential_response_stripped`` is set the provider/proxy body
        carried the credential exact bytes: the original is NEVER stored — no
        raw bin, no length, no digest of the tainted bytes.  The journal row
        records only the fixed strip marker so the inventory validator can
        distinguish a deliberately stripped ordinal from missing evidence.
        """

        if credential_response_stripped and response_body is not None:
            raise PermissionError("OPENROUTER_STRIPPED_EVIDENCE_MUST_BE_EMPTY")
        approval = self._require_exact_claim(claim=claim)
        raw_digest = (
            hashlib.sha256(response_body).hexdigest() if response_body is not None else None
        )
        attempt: dict[str, object] = {
            "schema_version": OPENROUTER_ATTEMPT_SCHEMA,
            "authority_id": approval.authority_id,
            "place_id": place_id,
            "request_sha256": request_sha256,
            "approval_sha256": approval.approval_sha256,
            "protected_state_sha256": approval.protected_state_sha256,
            "claim_sha256": claim.claim_sha256,
            "attempt_number": attempt_number,
            "status_code": status_code,
            "response_length": len(response_body) if response_body is not None else None,
            "response_sha256": raw_digest,
        }
        if credential_response_stripped:
            attempt["credential_response_stripped"] = True
        evidence_preimage = {
            "schema_version": OPENROUTER_ATTEMPT_SCHEMA,
            "attempt": attempt,
            "raw_response_sha256": raw_digest,
        }
        evidence_sha256 = canonical_sha256(evidence_preimage)
        with self._lock:
            root_fd = self._open_root(create=False)
            journal = self._open_private_dir(root_fd, self._names["journal"])
            raw_dir = self._open_private_dir(root_fd, self._names["raw"])
            try:
                if response_body is not None:
                    try:
                        self._publish_create_only(
                            raw_dir,
                            f"response-{attempt_number:02d}.bin",
                            response_body,
                        )
                    except FileExistsError:
                        existing_raw = self._read_regular_bytes(
                            raw_dir,
                            f"response-{attempt_number:02d}.bin",
                            allow_empty=True,
                        )
                        if existing_raw != response_body:
                            raise PermissionError("OPENROUTER_RAW_REPLACEMENT_FORBIDDEN") from None
                attempt_payload = canonical_json_bytes(
                    {**attempt, "evidence_sha256": evidence_sha256}
                )
                try:
                    self._publish_create_only(
                        journal, f"attempt-{attempt_number:02d}.json", attempt_payload
                    )
                except FileExistsError:
                    existing_attempt = self._read_regular_bytes(
                        journal, f"attempt-{attempt_number:02d}.json"
                    )
                    if existing_attempt != attempt_payload:
                        raise PermissionError("OPENROUTER_ATTEMPT_REPLACEMENT_FORBIDDEN") from None
                os.fsync(raw_dir)
                os.fsync(journal)
            finally:
                os.close(raw_dir)
                os.close(journal)
                os.close(root_fd)
        return evidence_sha256

    def commit_reservation(
        self,
        *,
        claim: OpenRouterClaim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        evidence_sha256: str,
    ) -> None:
        if not isinstance(evidence_sha256, str) or not _DIGEST.fullmatch(evidence_sha256):
            raise PermissionError("OPENROUTER_EVIDENCE_DIGEST_REQUIRED")
        approval = self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                attempt_record = json.loads(
                    self._read_regular_bytes(journal, f"attempt-{attempt_number:02d}.json")
                )
                if attempt_record.get("evidence_sha256") != evidence_sha256:
                    raise PermissionError("OPENROUTER_EVIDENCE_DIGEST_INVALID")
                if (
                    attempt_record.get("place_id") != place_id
                    or attempt_record.get("request_sha256") != request_sha256
                ):
                    raise PermissionError("OPENROUTER_EVIDENCE_LINEAGE_INVALID")
                commit_entry = {
                    "schema_version": OPENROUTER_LEDGER_ENTRY_SCHEMA,
                    "authority_id": approval.authority_id,
                    "operation": "COMMIT",
                    "attempt_number": attempt_number,
                    "amount_micro_usd": OPENROUTER_RESERVATION_MICRO_USD,
                    "price_status": "EXACT_ZERO",
                    "place_id": place_id,
                    "request_sha256": request_sha256,
                    "claim_sha256": claim.claim_sha256,
                    "evidence_sha256": evidence_sha256,
                }
                existing = self._read_regular_bytes(root_fd, self._names["ledger"])
                entries = self._parse_ledger(existing)
                matching = [
                    row
                    for row in entries
                    if row.get("operation") == "RESERVE"
                    and row.get("request_sha256") == request_sha256
                    and row.get("attempt_number") == attempt_number
                ]
                already_committed = any(
                    row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
                    and row.get("request_sha256") == request_sha256
                    and row.get("attempt_number") == attempt_number
                    for row in entries
                )
                if len(matching) != 1 or already_committed:
                    raise PermissionError("OPENROUTER_COMMIT_ORDER_INVALID")
                self._append_jsonl_line(
                    root_fd,
                    self._names["ledger"],
                    canonical_json_bytes(commit_entry) + b"\n",
                )
                os.fsync(root_fd)
            finally:
                os.close(journal)
                os.close(root_fd)

    # ------------------------------------------------------------ generation

    def publish_generation(self, *, generation: Mapping[str, object]) -> str:
        payload = dict(generation)
        if payload.get("schema_version") != OPENROUTER_GENERATION_SCHEMA:
            raise ValueError("openrouter generation schema drifted")
        serialized = canonical_json_bytes(payload)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                self._publish_create_only(root_fd, self._names["generation"], serialized)
            except FileExistsError as error:
                existing = self._read_regular_bytes(root_fd, self._names["generation"])
                if existing != serialized:
                    raise PermissionError("OPENROUTER_PROTECTED_REPLACEMENT_FORBIDDEN") from error
            finally:
                os.close(root_fd)
        return hashlib.sha256(serialized).hexdigest()

    def publish_terminal_raw(self, *, payload: bytes) -> None:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                self._publish_or_require_exact(root_fd, self._names["terminal"], payload)
            finally:
                os.close(root_fd)

    def publish_terminal(self, *, terminal: Mapping[str, object]) -> None:
        self.publish_terminal_raw(payload=canonical_json_bytes(terminal))

    def journal_inventory_digest(self) -> str:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["journal"]):
                return canonical_sha256({"journal": "empty"})
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                entries = []
                for name in sorted(os.listdir(journal)):
                    blob = self._read_regular_bytes(journal, name, allow_empty=True)
                    entries.append({"name": name, "sha256": hashlib.sha256(blob).hexdigest()})
                return canonical_sha256(entries)
            finally:
                os.close(journal)
        finally:
            os.close(root_fd)

    def list_profile_names(self) -> list[str]:
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["profiles"]):
                    return []
                profiles_dir = self._open_existing_private_dir(root_fd, self._names["profiles"])
                try:
                    names = []
                    for name in sorted(os.listdir(profiles_dir)):
                        metadata = os.stat(name, dir_fd=profiles_dir, follow_symlinks=False)
                        if stat.S_ISLNK(metadata.st_mode):
                            raise PermissionError("OPENROUTER_PROFILE_SYMLINK_FORBIDDEN")
                        names.append(name)
                    return names
                finally:
                    os.close(profiles_dir)
            finally:
                os.close(root_fd)

    def read_protected_terminal_bytes(self) -> bytes:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["terminal"]):
                raise PermissionError("OPENROUTER_PROTECTED_TERMINAL_MISSING")
            return self._read_regular_bytes(root_fd, self._names["terminal"])
        finally:
            os.close(root_fd)

    def validate_root_inventory(self, *, require_generation: bool = True) -> None:
        expected = set(self._names.values())
        if not require_generation:
            expected.discard(self._names["generation"])
        root_fd = self._open_root(create=False)
        try:
            names = set(os.listdir(root_fd))
            if names != expected:
                raise PermissionError("OPENROUTER_PROTECTED_ROOT_INVENTORY_INVALID")
            for name in names:
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise PermissionError("OPENROUTER_PROTECTED_ROOT_SYMLINK_FORBIDDEN")
        finally:
            os.close(root_fd)

    def ensure_profiles_dir(self) -> None:
        """Create the exact empty profiles dir as the protected schema expects."""

        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                self._open_private_dir(root_fd, self._names["profiles"])
                os.fsync(root_fd)
            finally:
                os.close(root_fd)

    def ensure_raw_evidence_dir(self) -> None:
        """Create the raw-evidence dir so the root inventory is always exact."""

        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                self._open_private_dir(root_fd, self._names["raw"])
                os.fsync(root_fd)
            finally:
                os.close(root_fd)

    # ------------------------------------------------- evidence reconstruction

    def _journal_inventory(self) -> tuple[dict[str, dict[str, object]], set[str]]:
        """Read the journal into per-name records plus its raw filename set."""

        root_fd = self._open_root(create=False)
        try:
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                names = sorted(os.listdir(journal))
                records: dict[str, dict[str, object]] = {}
                for name in names:
                    metadata = os.stat(name, dir_fd=journal, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        raise PermissionError("OPENROUTER_JOURNAL_SYMLINK_FORBIDDEN")
                    records[name] = json.loads(self._read_regular_bytes(journal, name))
                return records, set(names)
            finally:
                os.close(journal)
        finally:
            os.close(root_fd)

    def validate_journal_evidence_inventory(self) -> None:
        """Exact journal filename set derived from LEDGER operations.

        Every RESERVE ordinal N owns exactly ``dispatch-N.json``; every COMMIT
        ordinal N additionally owns ``attempt-N.json``; a RECOVER_UNRESOLVED
        ordinal N must NOT own an attempt file (evidence existed would prove
        an illegal recovery).  Each record's ordinal/place/request identity
        must match its RESERVE.
        """

        entries = self.read_ledger_entries()
        reserve_rows: dict[int, dict[str, object]] = {}
        commit_ordinals: set[int] = set()
        recovered_ordinals: set[int] = set()
        for row in entries:
            operation = row.get("operation")
            ordinal = int(row.get("attempt_number", 0))  # type: ignore[arg-type]
            if operation == "RESERVE":
                reserve_rows[ordinal] = row
            elif operation == "COMMIT":
                commit_ordinals.add(ordinal)
            elif operation == "RECOVER_UNRESOLVED":
                recovered_ordinals.add(ordinal)
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["journal"]):
                if reserve_rows:
                    raise PermissionError("OPENROUTER_JOURNAL_MISSING_FOR_RESERVES")
                return
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                names = sorted(os.listdir(journal))
                client_marker_ordinals: set[int] = set()
                boundary_marker_ordinals: set[int] = set()
                for name in names:
                    client_match = re.fullmatch(r"client-(\d{2})\.json", name)
                    if client_match:
                        client_marker_ordinals.add(int(client_match.group(1)))
                    boundary_match = re.fullmatch(r"send-boundary-(\d{2})\.json", name)
                    if boundary_match:
                        boundary_marker_ordinals.add(int(boundary_match.group(1)))
                # WR-A final semantics: only RESERVE rows whose phase advanced
                # past RESERVED own a DISPATCH marker.  A RESERVED-phase row
                # (crash before dispatch preparation) legitimately owns none.
                dispatched_ordinals = {
                    ordinal
                    for ordinal, row in reserve_rows.items()
                    if row.get("dispatch_phase") != OPENROUTER_DISPATCH_PHASE_RESERVED
                    or f"dispatch-{ordinal:02d}.json" in names
                }
                expected_names = {
                    f"dispatch-{ordinal:02d}.json" for ordinal in dispatched_ordinals
                } | {f"attempt-{ordinal:02d}.json" for ordinal in commit_ordinals}
                # WR-A final semantics: client and send-boundary markers are
                # legal ONLY for RESERVE ordinals; a boundary marker REQUIRES
                # the client marker of the same ordinal (the constructor runs
                # strictly before stream()).
                if not client_marker_ordinals <= set(reserve_rows):
                    raise PermissionError("OPENROUTER_CLIENT_MARKER_ORDINAL_INVALID")
                if not boundary_marker_ordinals <= set(reserve_rows):
                    raise PermissionError("OPENROUTER_SEND_BOUNDARY_ORDINAL_INVALID")
                if not boundary_marker_ordinals <= client_marker_ordinals:
                    raise PermissionError("OPENROUTER_SEND_BOUNDARY_WITHOUT_CLIENT_MARKER")
                expected_names |= {
                    f"client-{ordinal:02d}.json" for ordinal in client_marker_ordinals
                } | {f"send-boundary-{ordinal:02d}.json" for ordinal in boundary_marker_ordinals}
                if set(names) != expected_names:
                    raise PermissionError("OPENROUTER_JOURNAL_FILENAME_UNRECOGNIZED")
                for name in names:
                    metadata = os.stat(name, dir_fd=journal, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        raise PermissionError("OPENROUTER_JOURNAL_SYMLINK_FORBIDDEN")
                    dispatch_match = re.fullmatch(r"dispatch-(\d{2})\.json", name)
                    attempt_match = re.fullmatch(r"attempt-(\d{2})\.json", name)
                    client_marker_match = re.fullmatch(r"client-(\d{2})\.json", name)
                    boundary_marker_match = re.fullmatch(r"send-boundary-(\d{2})\.json", name)
                    record = json.loads(self._read_regular_bytes(journal, name))
                    if dispatch_match:
                        ordinal = int(dispatch_match.group(1))
                        reserve_row = reserve_rows[ordinal]
                        if (
                            int(record.get("attempt_number", -1)) != ordinal
                            or record.get("place_id") != reserve_row.get("place_id")
                            or record.get("request_sha256") != reserve_row.get("request_sha256")
                            or record.get("claim_sha256") != reserve_row.get("claim_sha256")
                        ):
                            raise PermissionError("OPENROUTER_DISPATCH_LINEAGE_INVALID")
                    elif client_marker_match:
                        ordinal = int(client_marker_match.group(1))
                        reserve_row = reserve_rows[ordinal]
                        if (
                            int(record.get("attempt_number", -1)) != ordinal
                            or record.get("place_id") != reserve_row.get("place_id")
                            or record.get("claim_sha256") != reserve_row.get("claim_sha256")
                            or record.get("client_fact") != OPENROUTER_CLIENT_FACT_CONFIRMED
                        ):
                            raise PermissionError("OPENROUTER_CLIENT_MARKER_LINEAGE_INVALID")
                    elif boundary_marker_match:
                        ordinal = int(boundary_marker_match.group(1))
                        reserve_row = reserve_rows[ordinal]
                        if (
                            int(record.get("attempt_number", -1)) != ordinal
                            or record.get("place_id") != reserve_row.get("place_id")
                            or record.get("claim_sha256") != reserve_row.get("claim_sha256")
                            or record.get("send_fact") != OPENROUTER_SEND_MAY_HAVE_STARTED
                            or ordinal not in client_marker_ordinals
                        ):
                            raise PermissionError("OPENROUTER_SEND_BOUNDARY_LINEAGE_INVALID")
                    elif attempt_match:
                        ordinal = int(attempt_match.group(1))
                        if ordinal in recovered_ordinals:
                            raise PermissionError("OPENROUTER_RECOVERY_WITH_EVIDENCE_INVALID")
                        reserve_row = reserve_rows[ordinal]
                        if (
                            int(record.get("attempt_number", -1)) != ordinal
                            or record.get("place_id") != reserve_row.get("place_id")
                            or record.get("request_sha256") != reserve_row.get("request_sha256")
                        ):
                            raise PermissionError("OPENROUTER_ATTEMPT_ORDINAL_LINEAGE_INVALID")
                    else:
                        raise PermissionError("OPENROUTER_JOURNAL_FILENAME_UNRECOGNIZED")
            finally:
                os.close(journal)
        finally:
            os.close(root_fd)

    def validate_raw_evidence_inventory(self) -> None:
        """ONLY COMMIT ordinals own raw evidence; recovered ordinals own none.

        Each ``response-N.bin`` is reopened no-follow and its digest/place/
        request lineage checked against its attempt record and RESERVE row.
        An ordinal whose attempt record carries the T-05R-95
        ``credential_response_stripped`` marker legitimately owns NO raw bin:
        its provider body carried credential bytes and the original was never
        persisted (digest-only safe evidence).
        """

        entries = self.read_ledger_entries()
        reserves: dict[int, dict[str, object]] = {
            int(row.get("attempt_number", 0)): row  # type: ignore[arg-type]
            for row in entries
            if row.get("operation") == "RESERVE"
        }
        recovered_ordinals: set[int] = {
            int(row.get("attempt_number", 0))  # type: ignore[arg-type]
            for row in entries
            if row.get("operation") == "RECOVER_UNRESOLVED"
        }
        expected_ordinals: list[int] = sorted(
            int(row.get("attempt_number", 0))  # type: ignore[arg-type]
            for row in entries
            if row.get("operation") == "COMMIT"
        )
        stripped_ordinals: set[int] = set()
        for ordinal in expected_ordinals:
            root_probe_fd = None
            try:
                root_probe_fd = self._open_root(create=False)
                if not self._exists(root_probe_fd, self._names["journal"]):
                    break
                journal_probe = self._open_existing_private_dir(
                    root_probe_fd, self._names["journal"]
                )
                try:
                    attempt_record = json.loads(
                        self._read_regular_bytes(journal_probe, f"attempt-{ordinal:02d}.json")
                    )
                finally:
                    os.close(journal_probe)
                if attempt_record.get("credential_response_stripped") is True:
                    stripped_ordinals.add(ordinal)
                    if attempt_record.get("response_sha256") is not None or (
                        attempt_record.get("response_length") is not None
                    ):
                        raise PermissionError("OPENROUTER_STRIPPED_EVIDENCE_TAINTED")
                elif attempt_record.get("response_sha256") is None and (
                    attempt_record.get("status_code") is None
                ):
                    # WR-A/CR-02: a transport failure BEFORE any response bytes
                    # existed (connect error, timeout, credential refusal)
                    # legitimately owns NO raw bin — there was never a body to
                    # persist.  The journal's null status/body pair IS the
                    # digest-only safe evidence for that ordinal.
                    stripped_ordinals.add(ordinal)
            except json.JSONDecodeError as error:
                raise PermissionError("OPENROUTER_PROTECTED_FILE_INVALID") from error
            finally:
                if root_probe_fd is not None:
                    os.close(root_probe_fd)
        expected_bin_ordinals = [
            ordinal for ordinal in expected_ordinals if ordinal not in stripped_ordinals
        ]
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["raw"]):
                if expected_bin_ordinals:
                    raise PermissionError("OPENROUTER_RAW_EVIDENCE_MISSING")
                return
            raw_dir = self._open_existing_private_dir(root_fd, self._names["raw"])
            try:
                names = set(os.listdir(raw_dir))
                expected_names = {
                    f"response-{ordinal:02d}.bin" for ordinal in expected_bin_ordinals
                }
                if names != expected_names:
                    raise PermissionError("OPENROUTER_RAW_INVENTORY_INVALID")
                for name in sorted(names):
                    metadata = os.stat(name, dir_fd=raw_dir, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        raise PermissionError("OPENROUTER_RAW_SYMLINK_FORBIDDEN")
                    match = re.fullmatch(r"response-(\d{2})\.bin", name)
                    if not match:
                        raise PermissionError("OPENROUTER_RAW_FILENAME_UNRECOGNIZED")
                    ordinal = int(match.group(1))
                    if ordinal in recovered_ordinals:
                        raise PermissionError("OPENROUTER_RECOVERY_WITH_EVIDENCE_INVALID")
                    reserve_row = reserves[ordinal]
                    blob = self._read_regular_bytes(raw_dir, name, allow_empty=True)
                    journal = self._open_existing_private_dir(root_fd, self._names["journal"])
                    try:
                        attempt_record = json.loads(
                            self._read_regular_bytes(journal, f"attempt-{ordinal:02d}.json")
                        )
                    finally:
                        os.close(journal)
                    stored_digest = hashlib.sha256(blob).hexdigest()
                    if (
                        attempt_record.get("response_sha256") != stored_digest
                        or attempt_record.get("attempt_number") != ordinal
                        or attempt_record.get("place_id") != reserve_row.get("place_id")
                        or attempt_record.get("request_sha256") != reserve_row.get("request_sha256")
                    ):
                        raise PermissionError("OPENROUTER_RAW_LINEAGE_INVALID")
            finally:
                os.close(raw_dir)
        finally:
            os.close(root_fd)

    def read_profile_bytes(self, name: str) -> bytes:
        """Reopen one durable profile through an exact no-follow descriptor."""

        if not re.fullmatch(r"profile-\d{2}-[A-Za-z0-9_-]{1,160}\.json", name):
            raise PermissionError("OPENROUTER_PROFILE_NAME_INVALID")
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                profiles_dir = self._open_existing_private_dir(root_fd, self._names["profiles"])
                try:
                    return self._read_regular_bytes(profiles_dir, name)
                finally:
                    os.close(profiles_dir)
            finally:
                os.close(root_fd)

    def publish_profile_evidence(
        self,
        *,
        claim: OpenRouterClaim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        profile_payload: Mapping[str, object],
    ) -> None:
        """No-replace publish one parsed profile bound to its attempt identity."""

        approval = self._require_exact_claim(claim=claim)
        payload_bytes = canonical_json_bytes(profile_payload)
        with self._lock:
            root_fd = self._open_root(create=False)
            profiles_dir = self._open_private_dir(root_fd, self._names["profiles"])
            try:
                place_tag = re.sub(r"[^A-Za-z0-9_-]", "_", place_id)[:160]
                name = f"profile-{attempt_number:02d}-{place_tag}.json"
                try:
                    self._publish_create_only(profiles_dir, name, payload_bytes)
                except FileExistsError:
                    existing = self._read_regular_bytes(profiles_dir, name)
                    if existing != payload_bytes:
                        raise PermissionError("OPENROUTER_PROFILE_REPLACEMENT_FORBIDDEN") from None
                os.fsync(profiles_dir)
                del approval
            finally:
                os.close(profiles_dir)
                os.close(root_fd)

    def reconstruct_positive_evidence(
        self,
        *,
        terminal: OpenRouterTerminal,
        approval: OpenRouterApprovalBinding,
        claim: OpenRouterClaim,
    ) -> None:
        """Full positive-branch reconstruction from durable bytes.

        Reopens generation.json and all 24 durable profile files through
        no-follow descriptors; requires exact key sets and self-digests;
        binds generation metadata to the terminal/approval/claim identities;
        verifies every profile's schema/self-digest/authority/member/request
        lineage; and checks counts and complete maps.
        """
        generation_bytes = _read_public_file_no_follow(Path(self._descriptor.generation_target))
        if hashlib.sha256(generation_bytes).hexdigest() != terminal.generation_sha256:
            raise ValueError("openrouter generation digest drifted")
        generation = json.loads(generation_bytes)
        expected_generation_keys = {
            "schema_version",
            "authority_id",
            "request_artifact_sha256",
            "request_file_sha256",
            "request_manifest_sha256",
            "checkout_commit_sha256",
            "claim_sha256",
            "approval_sha256",
            "profile_count",
            "profiles",
            "scenario_count",
            "contrast_count",
            "attempt_count",
            "retry_count",
            "committed_exposure_micro_usd",
            "outstanding_exposure_micro_usd",
            "profile_schema_version",
            "lifecycle_mutated",
            "generation_sha256",
        }
        if not isinstance(generation, dict) or set(generation) != expected_generation_keys:
            raise ValueError("openrouter generation manifest key set drifted")
        unsigned = {k: v for k, v in generation.items() if k != "generation_sha256"}
        if canonical_sha256(unsigned) != generation.get("generation_sha256"):
            raise ValueError("openrouter generation self-digest drifted")
        metadata_bindings = (
            ("request_artifact_sha256", str(approval.request_artifact_sha256)),
            ("request_file_sha256", str(approval.request_file_sha256)),
            # T-05R-97: the generation's member manifest must equal the
            # APPROVED manifest digest persisted in the approval binding.
            ("request_manifest_sha256", str(approval.request_manifest_sha256)),
            ("claim_sha256", claim.claim_sha256),
            ("approval_sha256", claim.approval_sha256),
            ("attempt_count", int(terminal.attempt_count)),
            ("retry_count", int(terminal.retry_count)),
            ("committed_exposure_micro_usd", 0),
            ("profile_count", int(terminal.profile_count)),
            ("scenario_count", 8),
            ("contrast_count", 7),
            ("authority_id", OPENROUTER_RECOVERY_AUTHORITY_ID),
            ("checkout_commit_sha256", str(approval.checkout_commit_sha256)),
            ("profile_schema_version", OPENROUTER_PROFILE_SCHEMA_VERSION),
            ("lifecycle_mutated", False),
        )
        for key, expected_value in metadata_bindings:
            if generation.get(key) != expected_value:
                raise ValueError(f"openrouter generation {key} does not match terminal")
        if generation.get("outstanding_exposure_micro_usd") != 0:
            raise ValueError("openrouter generation exposure did not settle")
        profile_names = sorted(state_names := self.list_profile_names())
        del state_names
        if len(profile_names) != OPENROUTER_MEMBER_COUNT:
            raise ValueError("openrouter positive terminal lacks 24 durable profiles")
        by_place: dict[str, str] = {}
        ordered_profiles: list[dict[str, object]] = []
        for name in profile_names:
            payload = json.loads(self.read_profile_bytes(name))
            validated = OpenRouterProfile.model_validate(payload)
            place_id = str(validated.place_id)
            if place_id in by_place:
                raise ValueError("openrouter duplicate durable profiles for one place")
            by_place[place_id] = str(validated.profile_sha256)
            ordered_profiles.append(payload)
        expected_profiles = {
            str(row.get("place_id")): str(row.get("profile_sha256"))
            for row in generation.get("profiles", [])  # type: ignore[union-attr]
        }
        if by_place != expected_profiles or len(expected_profiles) != OPENROUTER_MEMBER_COUNT:
            raise ValueError("openrouter durable profile digests drifted from generation")
        counts = (
            terminal.profile_count,
            terminal.candidate_count,
            terminal.post_hard_duplicate_count,
            terminal.post_cannot_coappear_count,
            terminal.effective_candidate_count,
        )
        if any(counts[i] < counts[i + 1] for i in range(len(counts) - 1)):
            raise ValueError("openrouter terminal counts are not monotonic")
        if terminal.confidence_is_ranking_input is not False:
            raise ValueError("openrouter confidence ranking drift")
        scenario_map = {row.scenario_id: row for row in terminal.scenario_results}
        contrast_map = {row.pair: row for row in terminal.contrast_results}
        if (
            tuple(scenario_map) != CANONICAL_SCENARIO_IDS
            or tuple(contrast_map) != CANONICAL_CONTRAST_PAIRS
        ):
            raise ValueError("openrouter maps are incomplete at reconstruction")
        # T-05R-97: re-run the PRODUCTION evaluators over the reopened profile
        # bytes and require field-by-field equality with the terminal's counts
        # and complete 8/7 maps.  The approved member order comes from the
        # fixed-source rebuild bound to the approval's manifest digest, so a
        # coherently re-digested forgery with stale maps/counts cannot verify.
        rebuilt_plan = _rebuild_approved_plan_for_approval(approval)
        member_order = {
            str(member.place_id): index for index, member in enumerate(rebuilt_plan.members)
        }
        if any(str(row.get("place_id")) not in member_order for row in ordered_profiles):
            raise ValueError("openrouter durable profile place is not an approved member")
        ordered = sorted(
            ordered_profiles,
            key=lambda row: member_order[str(row.get("place_id"))],
        )
        decision, evaluation = evaluate_openrouter_profiles(
            tuple(ordered),
            evidence_timestamp=fresh24_fixed_evidence_timestamp(
                str(approval.checkout_commit_sha256)
            ),
        )
        if (
            decision.candidate_count != terminal.candidate_count
            or decision.post_hard_duplicate_count != terminal.post_hard_duplicate_count
            or decision.post_cannot_coappear_count != terminal.post_cannot_coappear_count
            or decision.effective_candidate_count != terminal.effective_candidate_count
        ):
            raise ValueError("openrouter reevaluated cohort counts drifted from terminal")
        reevaluated_scenarios = [row.model_dump(mode="json") for row in evaluation.scenario_results]
        reevaluated_contrasts = [row.model_dump(mode="json") for row in evaluation.contrast_results]
        if len(reevaluated_scenarios) != 8 or len(reevaluated_contrasts) != 7:
            raise ValueError("openrouter reevaluated maps are incomplete")
        terminal_scenario_dicts = [row.model_dump(mode="json") for row in terminal.scenario_results]
        if terminal_scenario_dicts != reevaluated_scenarios:
            raise ValueError(
                "openrouter scenario maps do not reproduce exactly from durable profiles"
            )
        terminal_contrast_dicts = [row.model_dump(mode="json") for row in terminal.contrast_results]
        if terminal_contrast_dicts != reevaluated_contrasts:
            raise ValueError(
                "openrouter contrast maps do not reproduce exactly from durable profiles"
            )

    # -------------------------------------------------------------- reconcile

    def reconcile_interrupted(self, *, claim: OpenRouterClaim) -> dict[str, object] | None:
        """Close interrupted dispatched exposure conservatively (no resend)."""

        approval = self._require_exact_claim(claim=claim)
        entries = self.read_ledger_entries()
        reserves = [
            row
            for row in entries
            if row.get("operation") == "RESERVE" and row.get("claim_sha256") == claim.claim_sha256
        ]
        settled_ids = {
            (row.get("place_id"), row.get("request_sha256"), int(row.get("attempt_number", 0)))
            for row in entries
            if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        }
        pending = [
            row
            for row in reserves
            if (
                row.get("place_id"),
                row.get("request_sha256"),
                int(row.get("attempt_number", 0)),
            )
            not in settled_ids
        ]
        if not pending:
            return None
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                has_journal = self._exists(root_fd, self._names["journal"])
                journal_names: set[str] = set()
                if has_journal:
                    journal = self._open_existing_private_dir(root_fd, self._names["journal"])
                    try:
                        journal_names = set(os.listdir(journal))
                    finally:
                        os.close(journal)
                recovered: list[dict[str, object]] = []
                for row in pending:
                    place_id = str(row.get("place_id"))
                    ordinal = int(row.get("attempt_number", 0))
                    dispatched = f"dispatch-{ordinal:02d}.json" in journal_names
                    client_marker = f"client-{ordinal:02d}.json" in journal_names
                    boundary_marker = f"send-boundary-{ordinal:02d}.json" in journal_names
                    evidence_persisted = f"attempt-{ordinal:02d}.json" in journal_names
                    recover_entry = {
                        "schema_version": OPENROUTER_LEDGER_ENTRY_SCHEMA,
                        "authority_id": approval.authority_id,
                        "operation": "RECOVER_UNRESOLVED",
                        "attempt_number": ordinal,
                        "amount_micro_usd": OPENROUTER_RESERVATION_MICRO_USD,
                        "price_status": "EXACT_ZERO",
                        "place_id": place_id,
                        "request_sha256": row.get("request_sha256"),
                        "claim_sha256": claim.claim_sha256,
                        "evidence_sha256": None,
                        # WR-A final semantics: the journal marker inventory
                        # decides the phase; each phase pins its booleans and
                        # certainties exactly — never an unprovable sent fact.
                    }
                    if dispatched and not evidence_persisted:
                        if boundary_marker and client_marker:
                            # The send boundary was REACHED (client confirmed);
                            # whether any request op ran stays unknowable.
                            recover_entry["dispatch_phase"] = (
                                OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY
                            )
                            recover_entry["dispatch_certainty"] = (
                                OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY
                            )
                            recover_entry["send_certainty"] = OPENROUTER_SEND_MAY_HAVE_STARTED
                            recover_entry["client_fact"] = OPENROUTER_CLIENT_FACT_CONFIRMED
                            recover_entry["may_have_attempted"] = True
                        elif client_marker:
                            # Client constructed then crashed BEFORE the send
                            # boundary: client=true confirmed, no send fact.
                            recover_entry["dispatch_phase"] = (
                                OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED
                            )
                            recover_entry["dispatch_certainty"] = OPENROUTER_CLIENT_FACT_CONFIRMED
                            recover_entry["send_certainty"] = OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN
                            recover_entry["client_fact"] = OPENROUTER_CLIENT_FACT_CONFIRMED
                            recover_entry["may_have_attempted"] = True
                        else:
                            # DISPATCH_PREPARED only: before-secret, send
                            # provably NOT started — client=false, network=false.
                            recover_entry["dispatch_phase"] = OPENROUTER_DISPATCH_PHASE_PREPARED
                            recover_entry["dispatch_certainty"] = (
                                OPENROUTER_DISPATCH_CERTAINTY_PREPARED
                            )
                            recover_entry["send_certainty"] = OPENROUTER_SEND_NOT_STARTED
                            recover_entry["client_fact"] = OPENROUTER_SEND_NOT_STARTED
                            recover_entry["may_have_attempted"] = False
                    elif not dispatched and not evidence_persisted:
                        # RESERVE-only crash: deterministic settlement — the
                        # attempt never left reservation (client=false,
                        # network=false, RESERVED certainty).
                        recover_entry["dispatch_phase"] = OPENROUTER_DISPATCH_PHASE_RESERVED
                        recover_entry["dispatch_certainty"] = OPENROUTER_DISPATCH_CERTAINTY_RESERVED
                        recover_entry["send_certainty"] = OPENROUTER_SEND_NOT_STARTED
                        recover_entry["client_fact"] = OPENROUTER_SEND_NOT_STARTED
                        recover_entry["may_have_attempted"] = False
                    elif evidence_persisted:
                        raise PermissionError("OPENROUTER_RECONCILIATION_EVIDENCE_UNSETTLED")
                    else:
                        raise PermissionError("OPENROUTER_RECONCILIATION_DISPATCH_INVALID")
                    self._append_jsonl_line(
                        root_fd,
                        self._names["ledger"],
                        canonical_json_bytes(recover_entry) + b"\n",
                    )
                    recovered.append(recover_entry)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        # WR-A final semantics: derive summary facts from the settled rows'
        # phases — never a hardcoded boolean or blanket unknown.  Priority:
        # send-boundary > client-constructed > prepared > reserved.
        phases = {str(row.get("dispatch_phase")) for row in recovered}
        if OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY in phases:
            summary_send = OPENROUTER_SEND_MAY_HAVE_STARTED
            summary_dispatch = OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY
            summary_client_true = True
        elif OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED in phases:
            summary_send = OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN
            summary_dispatch = OPENROUTER_CLIENT_FACT_CONFIRMED
            summary_client_true = True
        elif OPENROUTER_DISPATCH_PHASE_PREPARED in phases:
            summary_send = OPENROUTER_SEND_NOT_STARTED
            summary_dispatch = OPENROUTER_DISPATCH_CERTAINTY_PREPARED
            summary_client_true = False
        else:
            summary_send = OPENROUTER_SEND_NOT_STARTED
            summary_dispatch = OPENROUTER_DISPATCH_CERTAINTY_RESERVED
            summary_client_true = False
        return {
            "status": "DESIGNED_NEGATIVE",
            "reason": "OPENROUTER_INTERRUPTED_EXPOSURE_CONSERVATIVE",
            "recovered_count": len(recovered),
            "committed_exposure_micro_usd": self.committed_exposure_micro_usd(),
            # No interrupted attempt ever persisted a response, so no wire
            # completion was ever proven locally: network_attempted stays
            # false while the certainty fields carry the exact per-phase
            # facts.  client_constructed=true ONLY when a durable client
            # marker exists (SEND_BOUNDARY/CLIENT_CONSTRUCTED phases).
            "client_constructed": summary_client_true,
            "network_attempted": False,
            "send_certainty": summary_send,
            "dispatch_certainty": summary_dispatch,
            "lifecycle_mutated": False,
        }

    def reconcile_terminal(
        self,
        *,
        claim: OpenRouterClaim,
        approval: OpenRouterApprovalBinding,
        plan: OpenRouterPlan,
        artifact: Mapping[str, object],
    ) -> dict[str, object] | None:
        if claim.approval_sha256 != approval.approval_sha256:
            raise PermissionError("OPENROUTER_RECONCILIATION_CLAIM_MISMATCH")
        if claim.request_artifact_sha256 != str(artifact.get("request_artifact_sha256")):
            raise PermissionError("OPENROUTER_RECONCILIATION_PACKET_MISMATCH")
        recovered = self.reconcile_interrupted(claim=claim)
        if recovered is None:
            return None
        entries = self.read_ledger_entries()
        reserves = [row for row in entries if row.get("operation") == "RESERVE"]
        attempt_count = len(reserves)
        recovery_rows = [row for row in entries if row.get("operation") == "RECOVER_UNRESOLVED"]
        # WR-A strict re-audit: derive the EXACT phase facts from the durable
        # ledger rows themselves — never a hardcoded boolean.  Phase priority:
        # any SEND_STARTED dominates; otherwise PREPARED; otherwise RESERVED.
        # A reserve-only crash never created the journal dir; an empty one is
        # the exact durable state for RESERVED-phase rows (no markers exist) —
        # it MUST exist before the terminal's journal digest is computed.
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["journal"]):
                    journal_fd = self._open_private_dir(root_fd, self._names["journal"])
                    os.close(journal_fd)
                    os.fsync(root_fd)
            finally:
                os.close(root_fd)
        phases = {str(row.get("dispatch_phase")) for row in recovery_rows}
        # WR-A final semantics: phase priority send-boundary > client >
        # prepared > reserved; client=true ONLY with a durable client marker.
        if OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY in phases:
            summary_send = OPENROUTER_SEND_MAY_HAVE_STARTED
            summary_dispatch = OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY
            summary_client_true = True
        elif OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED in phases:
            summary_send = OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN
            summary_dispatch = OPENROUTER_CLIENT_FACT_CONFIRMED
            summary_client_true = True
        elif OPENROUTER_DISPATCH_PHASE_PREPARED in phases:
            summary_send = OPENROUTER_SEND_NOT_STARTED
            summary_dispatch = OPENROUTER_DISPATCH_CERTAINTY_PREPARED
            summary_client_true = False
        else:
            summary_send = OPENROUTER_SEND_NOT_STARTED
            summary_dispatch = OPENROUTER_DISPATCH_CERTAINTY_RESERVED
            summary_client_true = False
        terminal = OpenRouterTerminal.model_validate(
            {
                "schema_version": OPENROUTER_TERMINAL_SCHEMA,
                "status": "DESIGNED_NEGATIVE",
                "reason": "OPENROUTER_INTERRUPTED_EXPOSURE_CONSERVATIVE",
                "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
                "request_sha256": plan.request_sha256,
                "request_file_sha256": claim.request_file_sha256,
                "checkout_manifest_sha256": plan.checkout_manifest_sha256,
                "claim_sha256": claim.claim_sha256,
                "ledger_sha256": canonical_sha256(entries),
                "journal_sha256": self.journal_inventory_digest(),
                "attempt_count": attempt_count,
                "retry_count": min(
                    max(0, attempt_count - OPENROUTER_FIRST_PASS_COUNT),
                    OPENROUTER_MAX_RETRIES,
                ),
                # No interrupted attempt ever persisted a response, so network
                # stays false; client=true ONLY from a durable client marker.
                "secret_read": False,
                "client_constructed": summary_client_true,
                "network_attempted": False,
                "send_certainty": summary_send,
                "dispatch_certainty": summary_dispatch,
                "terminal_sha256": None,
            }
        )
        payload = terminal.model_dump(mode="json")
        # CR-02: keep the root inventory EXACT before the terminal publish —
        # the reconcile-produced terminal must verify neutrally on reopen.
        self.ensure_profiles_dir()
        self.ensure_raw_evidence_dir()
        self.publish_terminal_raw(payload=canonical_json_bytes(payload))
        return payload


# --------------------------------------------------------------------------
# Neutral verification + classification.
# --------------------------------------------------------------------------


class OpenRouterTerminalDisposition(str):
    POSITIVE = "POSITIVE"
    DESIGNED_NEGATIVE = "DESIGNED_NEGATIVE"
    FAILED_UNACTIVATED = "FAILED_UNACTIVATED"


def verify_openrouter_terminal(value: Mapping[str, object]) -> str:
    try:
        terminal = OpenRouterTerminal.model_validate(value)
    except Exception as error:
        raise ValueError("openrouter terminal is malformed") from error
    if terminal.status == "COMPLETE_CANDIDATE_READY":
        return OpenRouterTerminalDisposition.POSITIVE
    if terminal.status == "DESIGNED_NEGATIVE":
        return OpenRouterTerminalDisposition.DESIGNED_NEGATIVE
    return OpenRouterTerminalDisposition.FAILED_UNACTIVATED


class OpenRouterVerifiedOutcome:
    __slots__ = ("terminal", "_provenance")

    def __init__(self, terminal: OpenRouterTerminal) -> None:
        self.terminal = terminal
        self._provenance: object = None

    @property
    def disposition(self) -> str:
        if self._provenance is not _CAPABILITY_SEAL:
            raise PermissionError("OPENROUTER_OUTCOME_PROVENANCE_INVALID")
        return verify_openrouter_terminal(self.terminal.model_dump(mode="json"))


_CAPABILITY_SEAL = object()


def classify_verified_outcome(outcome: OpenRouterVerifiedOutcome) -> str:
    return outcome.disposition


def assert_openrouter_positive_outcome(outcome: OpenRouterVerifiedOutcome) -> OpenRouterTerminal:
    terminal = outcome.terminal
    if terminal.status != "COMPLETE_CANDIDATE_READY" or terminal.reason != (
        "COMPLETE_CANDIDATE_READY"
    ):
        raise ValueError("openrouter terminal is not COMPLETE_CANDIDATE_READY")
    return terminal


def verify_openrouter_outcome(
    *,
    terminal: Mapping[str, object] | OpenRouterTerminal,
    protected_root: Path,
) -> OpenRouterVerifiedOutcome:
    """Neutral verification that independently reopens protected evidence."""

    payload = terminal if isinstance(terminal, Mapping) else terminal.model_dump(mode="json")
    verify_openrouter_terminal(payload)
    public = OpenRouterTerminal.model_validate(payload)
    descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(protected_root))
    state = OpenRouterDurableAuthorityState(descriptor)
    state.validate_root_inventory(
        require_generation=payload.get("status") == "COMPLETE_CANDIDATE_READY"
    )
    approval = state.read_approval()
    claim = state.read_claim()
    if claim.approval_sha256 != approval.approval_sha256:
        raise ValueError("openrouter protected claim does not match approval")
    if str(claim.claim_sha256) != str(public.claim_sha256):
        raise ValueError("openrouter terminal claim digest does not match persisted claim")
    if approval.checkout_manifest_sha256 != public.checkout_manifest_sha256:
        raise ValueError("openrouter approval checkout binding drifted")
    if OPENROUTER_REQUEST_OUTPUT != REPOSITORY_ROOT / OPENROUTER_PUBLIC_REQUEST_RELATIVE:
        raise PermissionError("openrouter public request path constant drifted")
    # The exact committed public packet at its fixed path is reopened when it
    # exists (the production boundary); a temporary-root verification without
    # a committed packet binds the claim/approval identity directly.
    bound_artifact = str(claim.request_artifact_sha256)
    if OPENROUTER_REQUEST_OUTPUT.exists():
        packet_bytes = _read_public_file_no_follow(OPENROUTER_REQUEST_OUTPUT)
        packet_request_file_sha256 = hashlib.sha256(packet_bytes).hexdigest()
        packet = json.loads(packet_bytes)
        if not isinstance(packet, dict):
            raise ValueError("openrouter committed public packet is malformed")
        packet_artifact = packet.get("request_artifact_sha256")
        if not isinstance(packet_artifact, str) or not _DIGEST.fullmatch(packet_artifact):
            raise ValueError("openrouter committed packet artifact digest malformed")
        unsigned_packet = {
            key: value for key, value in packet.items() if key != "request_artifact_sha256"
        }
        if canonical_sha256(unsigned_packet) != packet_artifact:
            raise ValueError("openrouter committed packet self-digest drifted")
        if str(approval.request_artifact_sha256) != bound_artifact:
            raise ValueError("openrouter approval packet identity drifted from claim")
        if packet_artifact != bound_artifact:
            raise ValueError("openrouter committed packet identity does not match this run's claim")
        if (
            str(approval.request_file_sha256) != packet_request_file_sha256
            or str(claim.request_file_sha256) != packet_request_file_sha256
        ):
            raise ValueError("openrouter committed packet raw bytes drifted from binding")
    else:
        if str(approval.request_artifact_sha256) != bound_artifact:
            raise ValueError("openrouter approval packet identity drifted from claim")
        if str(approval.request_file_sha256) != str(claim.request_file_sha256):
            raise ValueError("openrouter claim raw bytes drifted from approval binding")
    if str(public.request_file_sha256) != str(claim.request_file_sha256):
        raise ValueError("openrouter public terminal raw packet digest drifted")
    # ---- full ledger reconstruction --------------------------------------
    entries = state.read_ledger_entries()
    reserves: dict[int, dict[str, object]] = {}
    commits: set[int] = set()
    recovered: set[int] = set()
    for index, row in enumerate(entries):
        if row.get("schema_version") != OPENROUTER_LEDGER_ENTRY_SCHEMA:
            raise ValueError(f"openrouter ledger row {index} schema drifted")
        if row.get("authority_id") != OPENROUTER_RECOVERY_AUTHORITY_ID:
            raise ValueError(f"openrouter ledger row {index} authority drifted")
        if row.get("claim_sha256") != claim.claim_sha256:
            raise ValueError(f"openrouter ledger row {index} claim identity drifted")
        amount = int(row.get("amount_micro_usd", -1))
        if amount != 0 or row.get("price_status") != "EXACT_ZERO":
            raise ValueError(f"openrouter ledger row {index} price status invalid")
        operation = row.get("operation")
        ordinal = int(row.get("attempt_number", 0))
        if not 1 <= ordinal <= OPENROUTER_MAX_ATTEMPTS:
            raise ValueError(f"openrouter ledger row {index} ordinal invalid")
        if operation == "RESERVE":
            if ordinal in reserves:
                raise ValueError("openrouter duplicate RESERVE ordinal")
            # WR-A strict re-audit: the RESERVE row itself must persist its
            # RESERVED phase — a crash before dispatch preparation leaves a
            # deterministically reconcilable row.
            if row.get("dispatch_phase") != OPENROUTER_DISPATCH_PHASE_RESERVED:
                raise ValueError(f"openrouter ledger row {index} RESERVE lacks RESERVED phase")
            reserves[ordinal] = row
        elif operation == "COMMIT":
            if ordinal in commits or ordinal in recovered:
                raise ValueError("openrouter duplicate settlement ordinal")
            if ordinal not in reserves:
                raise ValueError("openrouter COMMIT precedes its RESERVE")
            if row.get("evidence_sha256") is None:
                raise ValueError("openrouter COMMIT requires an evidence digest")
            commits.add(ordinal)
        elif operation == "RECOVER_UNRESOLVED":
            if ordinal in commits or ordinal in recovered:
                raise ValueError("openrouter duplicate settlement ordinal")
            if ordinal not in reserves:
                raise ValueError("openrouter recovery precedes its RESERVE")
            # WR-A final semantics: each recovery row's phase/certainty tuple
            # must be EXACTLY consistent with its may_have_attempted fact and
            # its client_fact.
            phase = row.get("dispatch_phase")
            certainty = row.get("dispatch_certainty")
            send_certainty = row.get("send_certainty")
            client_fact = row.get("client_fact")
            may_have = row.get("may_have_attempted")
            valid_quadruples = {
                (
                    OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY,
                    OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY,
                    OPENROUTER_SEND_MAY_HAVE_STARTED,
                    True,
                ),
                (
                    OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED,
                    OPENROUTER_CLIENT_FACT_CONFIRMED,
                    OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN,
                    True,
                ),
                (
                    OPENROUTER_DISPATCH_PHASE_PREPARED,
                    OPENROUTER_DISPATCH_CERTAINTY_PREPARED,
                    OPENROUTER_SEND_NOT_STARTED,
                    False,
                ),
                (
                    OPENROUTER_DISPATCH_PHASE_RESERVED,
                    OPENROUTER_DISPATCH_CERTAINTY_RESERVED,
                    OPENROUTER_SEND_NOT_STARTED,
                    False,
                ),
            }
            if (phase, certainty, send_certainty, may_have) not in valid_quadruples:
                raise ValueError(f"openrouter ledger row {index} has inconsistent recovery facts")
            expected_client = (
                OPENROUTER_CLIENT_FACT_CONFIRMED
                if phase
                in (
                    OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY,
                    OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED,
                )
                else OPENROUTER_SEND_NOT_STARTED
            )
            if client_fact != expected_client:
                raise ValueError(f"openrouter ledger row {index} client fact contradicts phase")
            recovered.add(ordinal)
        elif operation == "DISPATCH":
            pass  # correlated against the journal inventory below.
        else:
            raise ValueError(f"openrouter ledger row {index} has unknown operation")
    settled = commits | recovered
    if any(ordinal not in settled for ordinal in reserves):
        raise ValueError("openrouter protected ledger has unresolved reservations")
    if len(settled) != len(reserves):
        raise ValueError("openrouter ledger settlements do not match reserves")
    committed = sum(
        int(row.get("amount_micro_usd", 0))
        for row in entries
        if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
    )
    if committed != 0 or int(public.committed_exposure_micro_usd) != 0:
        raise ValueError("openrouter terminal exposure must be exactly zero")
    if int(public.attempt_count) != len(reserves):
        raise ValueError("openrouter terminal attempt count does not match ledger")
    reserve_ordinals = sorted(reserves)
    if reserve_ordinals != list(range(1, int(public.attempt_count) + 1)):
        raise ValueError("openrouter ledger attempt ordinals are not exact 1..N")
    expected_retry = min(
        max(0, len(reserves) - OPENROUTER_FIRST_PASS_COUNT), OPENROUTER_MAX_RETRIES
    )
    if int(public.retry_count) != expected_retry:
        raise ValueError("openrouter terminal retry count does not match ledger shape")
    if canonical_sha256(entries) != public.ledger_sha256:
        raise ValueError("openrouter ledger digest does not match terminal")
    # ---- WR-A strict: re-derive the terminal certainty facts from the ----
    # ---- reopened ledger rows; a drifted terminal is rejected.        ----
    recovery_phases = {
        str(row.get("dispatch_phase"))
        for row in entries
        if row.get("operation") == "RECOVER_UNRESOLVED"
    }
    if recovery_phases:
        # WR-A final semantics: recompute the terminal facts from the durable
        # ledger phases; client=true ONLY for marker-proven phases, network
        # NEVER true (no interrupted attempt persisted a response).
        if OPENROUTER_DISPATCH_PHASE_SEND_BOUNDARY in recovery_phases:
            derived_send = OPENROUTER_SEND_MAY_HAVE_STARTED
            derived_dispatch = OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY
            derived_client = True
        elif OPENROUTER_DISPATCH_PHASE_CLIENT_CONSTRUCTED in recovery_phases:
            derived_send = OPENROUTER_DISPATCH_CERTAINTY_UNKNOWN
            derived_dispatch = OPENROUTER_CLIENT_FACT_CONFIRMED
            derived_client = True
        elif OPENROUTER_DISPATCH_PHASE_PREPARED in recovery_phases:
            derived_send = OPENROUTER_SEND_NOT_STARTED
            derived_dispatch = OPENROUTER_DISPATCH_CERTAINTY_PREPARED
            derived_client = False
        else:
            derived_send = OPENROUTER_SEND_NOT_STARTED
            derived_dispatch = OPENROUTER_DISPATCH_CERTAINTY_RESERVED
            derived_client = False
        if (
            public.send_certainty != derived_send
            or public.dispatch_certainty != derived_dispatch
            or public.client_constructed is not derived_client
            or public.network_attempted is True
        ):
            raise ValueError(
                "openrouter terminal certainty facts contradict durable recovery phases"
            )
    # ---- journal / raw evidence correlation ------------------------------
    state.validate_journal_evidence_inventory()
    state.validate_raw_evidence_inventory()
    if state.journal_inventory_digest() != public.journal_sha256:
        raise ValueError("openrouter journal inventory digest does not match terminal")
    # ---- protected/public terminal byte equality -------------------------
    protected_terminal_bytes = state.read_protected_terminal_bytes()
    public_bytes = canonical_json_bytes(public.model_dump(mode="json"))
    if protected_terminal_bytes != public_bytes:
        raise ValueError("openrouter protected terminal drifted from public terminal")
    positive_branch = public.status == "COMPLETE_CANDIDATE_READY"
    if not positive_branch and state.list_profile_names():
        raise ValueError("openrouter negative branch carries durable profiles")
    # ---- positive branch: full profile/generation reconstruction ----------
    if positive_branch:
        state.reconstruct_positive_evidence(
            terminal=public,
            approval=approval,
            claim=claim,
        )
    state.validate_root_inventory(require_generation=positive_branch)
    outcome = OpenRouterVerifiedOutcome(public)
    object.__setattr__(outcome, "_provenance", _CAPABILITY_SEAL)
    return outcome


def verify_openrouter_outcome_for_cli(
    *,
    terminal_path: Path | None = None,
    protected_root: Path | None = None,
) -> OpenRouterVerifiedOutcome:
    require_fixed_openrouter_paths(terminal_output=terminal_path or OPENROUTER_TERMINAL_OUTPUT)
    terminal = OpenRouterTerminal.model_validate_json(
        _read_public_file_no_follow(terminal_path or OPENROUTER_TERMINAL_OUTPUT)
    )
    root = protected_root or OPENROUTER_PROTECTED_ROOT
    return verify_openrouter_outcome(terminal=terminal, protected_root=root)


def classify_openrouter_terminal(value: Mapping[str, object]) -> str:
    return verify_openrouter_terminal(value)


def assert_openrouter_positive(value: Mapping[str, object]) -> bool:
    if verify_openrouter_terminal(value) != "POSITIVE":
        raise ValueError("openrouter terminal is not COMPLETE_CANDIDATE_READY")
    return True


# --------------------------------------------------------------------------
# Cohort evaluation + generation manifest (deterministic kernel reuse).
# --------------------------------------------------------------------------


def evaluate_openrouter_profiles(
    profiles: Sequence[Mapping[str, object]],
    *,
    evidence_timestamp: object | None = None,
) -> tuple[object, object]:
    """Recompute both relations and complete D-31/D-32 maps from fresh values.

    Delegates to the SAME production evaluator the Fresh24 lane uses, bound to
    THIS namespace's membership digest.  ``evidence_timestamp`` pins one fixed
    instant for the whole suite so live runs and every neutral replay produce
    identical result/replay digests.
    """

    from datetime import UTC, datetime

    from itda.domain.demo_profile_eligibility import evaluate_nvidia_publication_cohort
    from itda.pipeline.phase5_fresh24 import (
        _candidate_from_profile,
        _default_preference,
        fresh24_fixed_evidence_timestamp,
    )

    if evidence_timestamp is None:
        evidence_timestamp = fresh24_fixed_evidence_timestamp(
            openrouter_checkout_commit_sha256(REPOSITORY_ROOT)
        )
    del UTC, datetime
    candidates = tuple(
        _candidate_from_profile(profile, index) for index, profile in enumerate(profiles)
    )
    decision = evaluate_nvidia_publication_cohort(profiles)
    from itda.contracts.phase5_recovery_policy import CANONICAL_PHASE5_RECOVERY_POLICY
    from itda.domain.recommendation import evaluate_activation_scenarios

    evaluation = evaluate_activation_scenarios(
        candidates=candidates,  # type: ignore[arg-type]
        release_sha256=canonical_sha256([p["profile_sha256"] for p in profiles]),
        canonical_membership_sha256=OPENROUTER_MEMBERSHIP_SHA256,
        base_preference=_default_preference(),  # type: ignore[arg-type]
        cannot_coappear_authority=CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority,
        created_at=evidence_timestamp,
    )
    if tuple(row.scenario_id for row in evaluation.scenario_results) != (CANONICAL_SCENARIO_IDS):
        raise ValueError("openrouter scenario map is not canonical")
    if tuple(row.pair for row in evaluation.contrast_results) != (CANONICAL_CONTRAST_PAIRS):
        raise ValueError("openrouter contrast map is not canonical")
    return decision, evaluation


def build_openrouter_generation_manifest(
    *,
    plan: OpenRouterPlan,
    claim: OpenRouterClaim,
    profiles: Sequence[Mapping[str, object]],
    scenario_results: Sequence[Mapping[str, object]],
    contrast_results: Sequence[Mapping[str, object]],
    attempt_count: int,
    retry_count: int,
) -> dict[str, object]:
    """Build the durable candidate-ready generation manifest."""

    profile_list = [dict(profile) for profile in profiles]
    if len(profile_list) != OPENROUTER_MEMBER_COUNT:
        raise ValueError("openrouter generation requires exact 24 coherent profiles")
    unsigned = {
        "schema_version": OPENROUTER_GENERATION_SCHEMA,
        "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
        # The generation binds the CLAIM's packet identity — the same packet
        # digest the approval was minted for — plus raw-bytes lineage.
        "request_artifact_sha256": claim.request_artifact_sha256,
        "request_file_sha256": claim.request_file_sha256,
        "request_manifest_sha256": plan.request_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "claim_sha256": claim.claim_sha256,
        "approval_sha256": claim.approval_sha256,
        "profile_count": len(profile_list),
        "profiles": [
            {"place_id": row.get("place_id"), "profile_sha256": row.get("profile_sha256")}
            for row in profile_list
        ],
        "scenario_count": len(scenario_results),
        "contrast_count": len(contrast_results),
        "attempt_count": attempt_count,
        "retry_count": retry_count,
        "committed_exposure_micro_usd": 0,
        "outstanding_exposure_micro_usd": 0,
        "profile_schema_version": OPENROUTER_PROFILE_SCHEMA_VERSION,
        "lifecycle_mutated": False,
    }
    return {**unsigned, "generation_sha256": canonical_sha256(unsigned)}


# --------------------------------------------------------------------------
# Public request packet build/write/verify.
# --------------------------------------------------------------------------


def build_openrouter_public_request(
    *,
    plan: OpenRouterPlan,
    checkout_commit_sha256: str,
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", checkout_commit_sha256):
        raise ValueError("openrouter checkout commit is invalid")
    snapshot = load_openrouter_snapshot()
    payload = {
        "schema_version": "itda.phase5-openrouter-recovery-request.v1",
        "authority_id": plan.authority_id,
        "provider_lane": OPENROUTER_PROVIDER_LANE,
        "endpoint": OPENROUTER_ENDPOINT,
        "model": OPENROUTER_MODEL,
        "snapshot_relative_path": (
            "backend/src/itda/providers/openrouter_ox_alpha_api_contract.json"
        ),
        "snapshot_sha256": str(snapshot.snapshot_sha256),
        "snapshot_accessed_at": snapshot.accessed_at,
        "snapshot_provenance_urls": dict(snapshot.provenance_urls),
        "prompt_version": "phase5-openrouter-profile-sentinel-json.v1",
        "prompt_sha256": OPENROUTER_PROMPT_SHA256,
        "profile_schema_version": OPENROUTER_PROFILE_SCHEMA_VERSION,
        "preprocessing_version": "phase5-openrouter-source-preprocessing.v1",
        "source_inventory_sha256": (
            "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
        ),
        "source_authority_sha256": (
            "b4e3d1aa4c916fee8489c63e843f9cccb9ea51389adf286d14ae2acecd4bb1ad"
        ),
        "source_install_receipt_sha256": (
            "783e5815bcea6670e2942f49d1f0df2c8e88c473783d6e1104287e682b0819f6"
        ),
        "membership_sha256": OPENROUTER_MEMBERSHIP_SHA256,
        "retention_profile": (
            "public-canonical-dev24-tourism-evidence-completion-no-personal-data"
        ),
        "reasoning_effort": "high",
        "max_price": {"prompt": "0", "completion": "0"},
        "price_status": "EXACT_ZERO",
        "checkout_commit_sha256": checkout_commit_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "first_pass_count": OPENROUTER_FIRST_PASS_COUNT,
        "member_count": OPENROUTER_MEMBER_COUNT,
        "first_passes": [
            {
                "place_id": row.place_id,
                "order": row.order,
                "request_sha256": row.request_sha256,
                "request_body_sha256": row.request_body_sha256,
            }
            for row in plan.first_passes
        ],
        "request_manifest_sha256": plan.request_manifest_sha256,
        "retry_policy": plan.retry_policy.model_dump(mode="json"),
        "exposure_policy": plan.exposure.model_dump(mode="json"),
        "activation_suite_sha256": (CANONICAL_SUITE_HASHES[0]),
        "contrast_suite_sha256": CANONICAL_SUITE_HASHES[1],
        "blind_access": False,
        "secret_read": False,
        "provider_client_constructed": False,
        "network_attempted": False,
        "lifecycle_mutated": False,
        "historical_member_import": False,
    }
    payload["request_artifact_sha256"] = canonical_sha256(payload)
    return payload


CANONICAL_SUITE_HASHES = (
    "6e049343d62770b8437ce9e29220fcd31a0e7b30d9b888bc3d9a823421fc5659",
    "1f9caa8dbb010ca64acffdf1c174c383e08b4fc04ede9b7aece10af35cb4c6c9",
)


def write_openrouter_public_request(
    plan: OpenRouterPlan,
    *,
    checkout_commit_sha256: str,
    output: Path | None = None,
) -> dict[str, object]:
    request_output, _, _ = require_fixed_openrouter_paths(
        request_output=output if output is not None else None
    )
    payload = build_openrouter_public_request(
        plan=plan, checkout_commit_sha256=checkout_commit_sha256
    )
    serialized = canonical_json_bytes(payload)
    if request_output.exists():
        if request_output.is_symlink() or request_output.read_bytes() != serialized:
            raise FileExistsError("openrouter request output already differs")
    else:
        request_output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            request_output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        try:
            os.write(descriptor, serialized)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return payload


def validate_openrouter_public_request(
    payload: Mapping[str, object],
    *,
    plan: OpenRouterPlan,
    checkout_commit_sha256: str,
) -> dict[str, object]:
    expected = build_openrouter_public_request(
        plan=plan, checkout_commit_sha256=checkout_commit_sha256
    )
    if dict(payload) != expected:
        raise ValueError("openrouter public request does not match current provider-free plan")
    return dict(payload)


def build_openrouter_v2_public_request(
    *,
    plan: OpenRouterPlanV2,
    checkout_commit_sha256: str,
) -> dict[str, object]:
    """Build the exact non-authorizing r2/v2 public packet in memory."""

    validate_openrouter_v2_namespace()
    if plan.authority_id != OPENROUTER_V2_RECOVERY_AUTHORITY_ID:
        raise PermissionError("OPENROUTER_V2_PLAN_AUTHORITY_INVALID")
    if (
        checkout_commit_sha256 != plan.checkout_commit_sha256
        or re.fullmatch(r"[0-9a-f]{40}", checkout_commit_sha256) is None
    ):
        raise ValueError("OPENROUTER_V2_CHECKOUT_COMMIT_INVALID")
    snapshot = load_openrouter_snapshot_v2()
    if str(snapshot.snapshot_sha256) != plan.snapshot_sha256:
        raise ValueError("OPENROUTER_V2_PLAN_SNAPSHOT_DRIFT")
    fields = {
        "schema_version": OPENROUTER_V2_REQUEST_SCHEMA,
        "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        "provider_lane": OPENROUTER_PROVIDER_LANE,
        "endpoint": OPENROUTER_ENDPOINT,
        "model": OPENROUTER_MODEL,
        "snapshot_relative_path": OPENROUTER_V2_SNAPSHOT_RELATIVE,
        "snapshot_sha256": str(snapshot.snapshot_sha256),
        "snapshot_accessed_at": snapshot.accessed_at,
        "snapshot_provenance_urls": dict(snapshot.provenance_urls),
        "public_request_relative_path": OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE,
        "protected_root_relative_path": OPENROUTER_V2_PROTECTED_ROOT_RELATIVE,
        "terminal_relative_path": OPENROUTER_V2_TERMINAL_RELATIVE,
        "prompt_version": OPENROUTER_V2_PROMPT_VERSION,
        "prompt_sha256": OPENROUTER_V2_PROMPT_SHA256,
        "profile_schema_version": OPENROUTER_V2_PROFILE_SCHEMA,
        "preprocessing_version": OPENROUTER_V2_PREPROCESSING_VERSION,
        "source_inventory_sha256": (
            "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
        ),
        "source_authority_sha256": (
            "b4e3d1aa4c916fee8489c63e843f9cccb9ea51389adf286d14ae2acecd4bb1ad"
        ),
        "source_install_receipt_sha256": (
            "783e5815bcea6670e2942f49d1f0df2c8e88c473783d6e1104287e682b0819f6"
        ),
        "membership_sha256": OPENROUTER_MEMBERSHIP_SHA256,
        "retention_profile": (
            "public-canonical-dev24-tourism-evidence-completion-no-personal-data"
        ),
        "reasoning_effort": "high",
        "max_price": {"prompt": "0", "completion": "0"},
        "price_status": "EXACT_ZERO",
        "checkout_commit_sha256": checkout_commit_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "first_pass_count": 24,
        "member_count": 24,
        "first_passes": [row.model_dump(mode="json") for row in plan.first_passes],
        "request_manifest_sha256": plan.request_manifest_sha256,
        "retry_policy": plan.retry_policy.model_dump(mode="json"),
        "exposure_policy": plan.exposure.model_dump(mode="json"),
        "activation_suite_sha256": CANONICAL_SUITE_HASHES[0],
        "contrast_suite_sha256": CANONICAL_SUITE_HASHES[1],
        "predecessor_consumption": plan.predecessor.model_dump(mode="json"),
        "blind_access": False,
        "secret_read": False,
        "provider_client_constructed": False,
        "network_attempted": False,
        "lifecycle_mutated": False,
        "historical_member_import": False,
        "predecessor_grants_retry": False,
        "predecessor_grants_authority": False,
    }
    packet = OpenRouterPublicRequestV2.model_validate(
        {**fields, "request_artifact_sha256": canonical_sha256(fields)}
    )
    return packet.model_dump(mode="json")


def load_openrouter_v2_public_request_bytes(
    raw: bytes, *, plan: OpenRouterPlanV2, checkout_commit_sha256: str
) -> dict[str, object]:
    payload = load_openrouter_v2_json_bytes(raw, label="PUBLIC_REQUEST")
    if canonical_json_bytes(payload) != raw:
        raise ValueError("OPENROUTER_V2_PUBLIC_REQUEST_NOT_CANONICAL")
    return validate_openrouter_v2_public_request(
        payload, plan=plan, checkout_commit_sha256=checkout_commit_sha256
    )


def validate_openrouter_v2_public_request(
    payload: Mapping[str, object],
    *,
    plan: OpenRouterPlanV2,
    checkout_commit_sha256: str,
) -> dict[str, object]:
    """Closed exact verification; no v1 schema/path/digest fallback exists."""

    parsed = OpenRouterPublicRequestV2.model_validate(dict(payload))
    expected = build_openrouter_v2_public_request(
        plan=plan, checkout_commit_sha256=checkout_commit_sha256
    )
    actual = parsed.model_dump(mode="json")
    if actual != expected:
        raise ValueError("OPENROUTER_V2_PUBLIC_REQUEST_PLAN_DRIFT")
    return actual


def write_openrouter_v2_public_request(
    plan: OpenRouterPlanV2,
    *,
    checkout_commit_sha256: str,
    output: Path | None = None,
) -> dict[str, object]:
    """Task 2 writer; never invoked by Task 1 execution or tests."""

    request_output, _, _ = require_fixed_openrouter_v2_paths(request_output=output)
    payload = build_openrouter_v2_public_request(
        plan=plan, checkout_commit_sha256=checkout_commit_sha256
    )
    serialized = canonical_json_bytes(payload)
    if request_output.exists():
        if request_output.is_symlink() or request_output.read_bytes() != serialized:
            raise FileExistsError("OPENROUTER_V2_REQUEST_OUTPUT_ALREADY_DIFFERS")
        return payload
    request_output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        request_output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        os.write(descriptor, serialized)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return payload


# --------------------------------------------------------------------------
# Sealed production transport.
#
# The public production entry points are import-time frozen closures over the
# fixed httpx constructor and the sealed executor (Fresh24 runner pattern).
# Post-import monkeypatching or deletion of any module symbol cannot redirect
# an already-bound entry point.  The caller-injected client seam exists ONLY
# inside the strictly-private ``_execute_with_test_transport`` namespace used
# by temporary-root tests; no production reference can be monkeypatched into it.
# --------------------------------------------------------------------------

_USE_BOOTSTRAP_MESSAGE = "USE_OPENROUTER_BOOTSTRAP_ENTRYPOINT"

OPENROUTER_ALLOWED_HEADER_NAMES = (
    "Authorization",
    "Content-Type",
    "Accept",
)


def _openrouter_open_client_blocking(**kwargs: object) -> httpx.AsyncClient:
    """Fixed production constructor; runs off the event loop via to_thread."""

    return httpx.AsyncClient(**kwargs)


def _percent_encode_exact(value_bytes: bytes) -> str:
    """Uppercase-hex percent encoding of EVERY byte (no unreserved pass-through)."""

    return "".join(f"%{byte:02X}" for byte in value_bytes)


def _lowercase_percent_escapes(text: str) -> str:
    """Lower ONLY the two hex digits of each ``%HH`` escape.

    A plain ``str.lower()`` would also lowercase literal characters that were
    never escaped (e.g. ``D`` or ``E`` inside ``A%2fB%2bC%20D%3dE%25``),
    corrupting the probe.  This walks the string and rewrites exactly the
    ``%HH`` sequences, leaving every other character untouched.
    """

    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if (
            char == "%"
            and index + 2 < length
            and text[index + 1] in "0123456789abcdefABCDEF"
            and text[index + 2] in "0123456789abcdefABCDEF"
        ):
            out.append("%")
            out.append(text[index + 1].lower())
            out.append(text[index + 2].lower())
            index += 3
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _body_is_credential_tainted(body: bytes | None, secret_value: str) -> bool:
    """T-05R-95 taint probe over an EXPLICIT fixed encoding inventory.

    Checks the response body for every value-derived encoding in the audit's
    fixed set: raw secret bytes; SHA-256 hex digest (lower AND upper);
    base64 of the raw credential / of the UTF-8 hex-digest text / of the
    BINARY 32-byte digest — each standard AND urlsafe, padded AND unpadded;
    and percent-encoded credentials with UPPERCASE and lowercase hex escapes
    (the lowercase form derived by rewriting ONLY the ``%HH`` hex digits, so
    unescaped literals survive verbatim).  Probes are derived IN MEMORY from
    the credential value and are NEVER returned, printed, journaled, or
    stored — no raw byte, digest, or length escapes; only a boolean verdict.
    """

    if not body or not secret_value:
        return False
    import base64

    value_bytes = secret_value.encode("utf-8")
    digest_binary = hashlib.sha256(value_bytes).digest()
    digest_hex_lower = digest_binary.hex()  # lowercase hex digest
    digest_hex_upper = digest_hex_lower.upper()  # uppercase hex digest

    def _b64_variants(raw: bytes) -> list[bytes]:
        """Standard AND urlsafe, padded AND unpadded base64 of ``raw``."""

        variants: list[bytes] = []
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encoder(raw)
            variants.append(encoded)
            variants.append(encoded.rstrip(b"="))
        return variants

    def _percent_forms() -> list[bytes]:
        """Every percent-encoding family in the fixed set:

        - exact all-bytes escapes: uppercase AND lowercase hex digits;
        - stdlib-quote family (unreserved literals pass through unescaped):
          the quote() output itself plus its exact-lowercase-escape rewrite.
        """

        forms: list[bytes] = []
        upper_exact = _percent_encode_exact(value_bytes)
        lower_exact = _lowercase_percent_escapes(upper_exact)
        for form in (upper_exact, lower_exact):
            if form != secret_value:
                forms.append(form.encode("utf-8"))
        quoted = urllib.parse.quote(secret_value, safe="")
        if quoted != secret_value:
            forms.append(quoted.encode("utf-8"))
            quoted_lower = _lowercase_percent_escapes(quoted)
            if quoted_lower != quoted and quoted_lower != secret_value:
                forms.append(quoted_lower.encode("utf-8"))
        return forms

    candidates: list[bytes] = [
        # 1. raw credential bytes.
        value_bytes,
        # 2. SHA-256 hex digest (lower + upper).
        digest_hex_lower.encode("ascii"),
        digest_hex_upper.encode("ascii"),
        # 3. base64 of the raw credential (std/urlsafe x padded/unpadded).
        *_b64_variants(value_bytes),
        # 4. base64 of the UTF-8 hex-digest text (all four forms).
        *_b64_variants(digest_hex_lower.encode("ascii")),
        *_b64_variants(digest_hex_upper.encode("ascii")),
        # 5. base64 of the BINARY digest (32 raw bytes; all four forms).
        *_b64_variants(digest_binary),
        # 6. percent-encoded credential: uppercase AND exact-lowercase hex
        #    escapes (every byte escaped; literals preserved by the walker).
        *_percent_forms(),
    ]
    return any(probe and probe in body for probe in candidates)


async def _openrouter_live_attempt(
    *,
    endpoint: str,
    request_body: bytes,
    secret: str | None,
    open_client: Callable[..., object],
    deadline_seconds: int,
    on_client_constructed: Callable[[], None] | None = None,
    on_send_started: Callable[[], None] | None = None,
) -> tuple[int | None, bytes]:
    """One bounded whole-attempt request.

    The absolute monotonic deadline covers client construction, the streaming
    request, and the bounded read.  ``open_client`` is a closure cell owned by
    this module's two executors only.  ``on_client_constructed`` fires exactly
    when the constructor returned (WR-A locally confirmed client fact).
    ``on_send_started`` fires IMMEDIATELY BEFORE the request operation — the
    durable SEND_STARTED marker is written there (WR-A re-audit phase
    separation), independent of how the attempt completes.
    """

    import asyncio

    started = asyncio.get_running_loop().time()
    try:
        async with asyncio.timeout(deadline_seconds):
            client = await open_client(
                headers={
                    "Authorization": f"Bearer {secret or ''}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(float(deadline_seconds)),
                follow_redirects=False,
                trust_env=False,
            )
            if on_client_constructed is not None:
                on_client_constructed()
            if on_send_started is not None:
                on_send_started()
            typed_client = cast(httpx.AsyncClient, client)
            try:
                async with typed_client.stream("POST", endpoint, content=request_body) as response:
                    elapsed = asyncio.get_running_loop().time() - started
                    if elapsed > deadline_seconds:
                        raise TimeoutError("OPENROUTER_ATTEMPT_DEADLINE_EXCEEDED")
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared, 10)
                        except ValueError as error:
                            raise ValueError("OPENROUTER_CONTENT_LENGTH_INVALID") from error
                        if not 0 <= declared_size <= OPENROUTER_MAX_RESPONSE_BYTES:
                            raise ValueError("OPENROUTER_RESPONSE_TOO_LARGE")
                    chunks: list[bytes] = []
                    received = 0
                    async for chunk in response.aiter_bytes():
                        received += len(chunk)
                        if received > OPENROUTER_MAX_RESPONSE_BYTES:
                            raise ValueError("OPENROUTER_RESPONSE_TOO_LARGE")
                        chunks.append(chunk)
                    return response.status_code, b"".join(chunks)
            finally:
                await typed_client.aclose()
    except TimeoutError as error:
        raise TimeoutError("OPENROUTER_ATTEMPT_DEADLINE_EXCEEDED") from error


@dataclass(frozen=True, slots=True)
class _OpenRouterRunnerBinding:
    """Immutable definition-time bundle of the sealed production runner.

    The bundle carries ONLY frozen transport cells — no module-global lookups
    happen through it at call time, so post-import mutation of any runner
    factory/executor/opener symbol cannot redirect an in-flight entry.
    """

    open_client: Callable[..., object]
    invoke_sync: Callable[..., dict[str, object]]
    invoke_async: Callable[..., object]


async def _execute_openrouter_transport(
    *,
    plan: OpenRouterPlan,
    claim: OpenRouterClaim,
    state: OpenRouterDurableAuthorityState,
    credential_reader: Callable[[OpenRouterApprovalBinding], str],
    open_client: Callable[..., object],
    deadline_seconds: int = OPENROUTER_ATTEMPT_DEADLINE_SECONDS,
) -> dict[str, object]:
    """State-owned attempt loop: reserve → dispatch → read → attempt → COMMIT.

    Ordering guarantees enforced here:
    - approval/claim are verified before anything else;
    - every attempt RESERVEs and DISPATCHes durably before the credential
      value is read or a client/socket exists (reserve-before-secret);
    - the whole attempt (client construction included) is under one timeout;
    - first-pass retryable failures enter the retry queue; retries run only
      after all 24 first passes, at most one retry per place;
    - COMMIT requires reopened digest-verified evidence and never accepts None.
    """

    approval = state.read_approval()
    state._require_exact_claim(claim=claim)
    # T-05R-95: bind the supplied plan/member manifest to the PERSISTED
    # approval identity before any attempt may run.  A plan rebuilt from
    # drifted source, a foreign manifest, or a non-member membership digest
    # can never dispatch.
    if str(approval.request_manifest_sha256) != str(plan.request_manifest_sha256):
        raise PermissionError("OPENROUTER_PLAN_APPROVAL_MANIFEST_MISMATCH")
    if str(approval.membership_sha256) != OPENROUTER_MEMBERSHIP_SHA256:
        raise PermissionError("OPENROUTER_PLAN_APPROVAL_MEMBERSHIP_MISMATCH")
    scheduler = OpenRouterScheduler(tuple(member.place_id for member in plan.members))
    members_by_place = {member.place_id: member for member in plan.members}
    retry_queue: list[str] = []
    retried_once: set[str] = set()
    responses: dict[str, Mapping[str, object]] = {}
    successful_ordinals: dict[str, int] = {}
    secret_read = False
    client_constructed = False
    network_attempted = False

    def finalize_terminal(
        *,
        status: str,
        reason: str,
        extra: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        fields: dict[str, object] = {
            "status": status,
            "reason": reason,
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "request_sha256": plan.request_sha256,
            "request_file_sha256": claim.request_file_sha256,
            "checkout_manifest_sha256": plan.checkout_manifest_sha256,
            "claim_sha256": claim.claim_sha256,
            "ledger_sha256": canonical_sha256(state.read_ledger_entries()),
            "journal_sha256": state.journal_inventory_digest(),
            "attempt_count": scheduler.attempt_count,
            "retry_count": min(
                max(0, scheduler.attempt_count - OPENROUTER_FIRST_PASS_COUNT),
                OPENROUTER_MAX_RETRIES,
            ),
            "committed_exposure_micro_usd": state.committed_exposure_micro_usd(),
            "secret_read": secret_read,
            # WR-A final semantics: derived from ACTUAL attempt facts.
            # network_attempted=true only with response/transport evidence;
            # client_constructed=true only after the durable client marker.
            # A reached send boundary without evidence stays MAY_HAVE/
            # UNKNOWN_AFTER_SEND_BOUNDARY — never a confirmed sent fact.
            "client_constructed": client_constructed,
            "network_attempted": network_attempted,
            "send_certainty": (
                OPENROUTER_SEND_MAY_HAVE_STARTED
                if network_attempted
                else (
                    OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY
                    if client_constructed or secret_read
                    else OPENROUTER_SEND_NOT_STARTED
                )
            ),
            "dispatch_certainty": (
                OPENROUTER_SEND_MAY_HAVE_STARTED
                if network_attempted and client_constructed
                else (
                    OPENROUTER_UNKNOWN_AFTER_SEND_BOUNDARY
                    if secret_read
                    else OPENROUTER_SEND_NOT_STARTED
                )
            ),
        }
        if extra:
            fields.update(extra)
        # CR-02 (security re-audit): EVERY terminal publish must leave the
        # protected root at the EXACT schema inventory.  A negative branch
        # that never succeeded an attempt would otherwise lack the empty
        # ``profiles/``/``raw-evidence/`` dirs and fail its own neutral
        # verification.  Both are created deterministically (idempotent,
        # no-follow, mode 0o700) before the terminal bytes are published.
        state.ensure_profiles_dir()
        state.ensure_raw_evidence_dir()
        terminal = OpenRouterTerminal.model_validate({**fields, "terminal_sha256": None})
        state.publish_terminal(terminal=terminal.model_dump(mode="json"))
        return terminal.model_dump(mode="json")

    async def finalize_success_terminal() -> dict[str, object]:
        """Parse, validate, evaluate — and publish ONLY on positive (CR-02).

        Every 200 response body must carry the exact profile JSON contract
        bound to its member lineage.  ALL 24 profiles are parsed, lineage-
        validated, and evaluated IN MEMORY first; durable profile evidence is
        published only after the cohort is positively eligible.  A late
        malformed or ineligible response therefore leaves the profiles dir
        EXACTLY empty and the run ends DESIGNED_NEGATIVE with nothing but
        journal/terminal bytes on disk.
        """

        from itda.contracts.phase5_openrouter_recovery import OpenRouterProfile

        profiles_by_place: dict[str, Mapping[str, object]] = {}
        ordinals_by_place: dict[str, int] = {}
        for place_id in sorted(responses):
            response = responses[place_id]
            member = members_by_place[place_id]
            request_digest = member.request.request_sha256  # type: ignore[union-attr]
            if not isinstance(response.get("body"), bytes) or not response["body"]:
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason="OPENROUTER_RESPONSE_EMPTY"
                )
            try:
                parsed = json.loads(bytes(response["body"]).decode("utf-8"))  # type: ignore[arg-type]
            except (UnicodeDecodeError, json.JSONDecodeError):
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason="OPENROUTER_RESPONSE_INVALID_JSON"
                )
            if not isinstance(parsed, Mapping):
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason="OPENROUTER_RESPONSE_SHAPE_INVALID"
                )
            profile_value = parsed.get("profile", parsed)
            try:
                profile = OpenRouterProfile.model_validate(profile_value)
            except Exception:
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE",
                    reason="OPENROUTER_PROFILE_LINEAGE_INVALID",
                )
            if (
                profile.place_id != place_id
                or profile.authority_id != member.authority_id
                or profile.source_bundle_sha256 != member.source_bundle_sha256
                or profile.evidence_inventory_sha256 != member.evidence_inventory_sha256
                or profile.request_sha256 != request_digest
            ):
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE",
                    reason="OPENROUTER_PROFILE_LINEAGE_INVALID",
                )
            profiles_by_place[place_id] = profile.model_dump(mode="json")
            ordinals_by_place[place_id] = successful_ordinals[place_id]
        if len(profiles_by_place) != OPENROUTER_MEMBER_COUNT:
            return finalize_terminal(
                status="DESIGNED_NEGATIVE", reason="OPENROUTER_EXACT_24_REQUIRED"
            )
        ordered_profiles = [profiles_by_place[member.place_id] for member in plan.members]
        decision, evaluation = evaluate_openrouter_profiles(tuple(ordered_profiles))
        if (
            not decision.recommendation_eligible
            or decision.effective_candidate_count < OPENROUTER_MIN_EFFECTIVE_CANDIDATES
        ):
            # CR-02: negative BEFORE any durable profile publish — the
            # profiles directory stays exactly empty.
            return finalize_terminal(
                status="DESIGNED_NEGATIVE",
                reason=decision.reason or "OPENROUTER_COHORT_INELIGIBLE",
            )
        # Positive verdict reached: NOW atomically publish each validated
        # profile bound to its attempt identity (no-replace per file).
        for place_id in sorted(profiles_by_place):
            state.publish_profile_evidence(
                claim=claim,
                place_id=place_id,
                request_sha256=str(members_by_place[place_id].request.request_sha256),
                attempt_number=ordinals_by_place[place_id],
                profile_payload=profiles_by_place[place_id],
            )
        generation = build_openrouter_generation_manifest(
            plan=plan,
            claim=claim,
            profiles=ordered_profiles,
            scenario_results=[row.model_dump(mode="json") for row in evaluation.scenario_results],
            contrast_results=[row.model_dump(mode="json") for row in evaluation.contrast_results],
            attempt_count=scheduler.attempt_count,
            retry_count=min(
                max(0, scheduler.attempt_count - OPENROUTER_FIRST_PASS_COUNT),
                OPENROUTER_MAX_RETRIES,
            ),
        )
        generation_bytes = canonical_json_bytes(generation)
        generation_sha256 = hashlib.sha256(generation_bytes).hexdigest()
        state.publish_generation(generation=generation)
        fields = {
            "status": "COMPLETE_CANDIDATE_READY",
            "reason": "COMPLETE_CANDIDATE_READY",
            "authority_id": OPENROUTER_RECOVERY_AUTHORITY_ID,
            "request_sha256": plan.request_sha256,
            "request_file_sha256": claim.request_file_sha256,
            "checkout_manifest_sha256": plan.checkout_manifest_sha256,
            "claim_sha256": claim.claim_sha256,
            "ledger_sha256": canonical_sha256(state.read_ledger_entries()),
            "journal_sha256": state.journal_inventory_digest(),
            "generation_sha256": generation_sha256,
            "profile_count": len(ordered_profiles),
            "candidate_count": decision.candidate_count,
            "post_hard_duplicate_count": decision.post_hard_duplicate_count,
            "post_cannot_coappear_count": decision.post_cannot_coappear_count,
            "effective_candidate_count": decision.effective_candidate_count,
            "attempt_count": scheduler.attempt_count,
            "retry_count": min(
                max(0, scheduler.attempt_count - OPENROUTER_FIRST_PASS_COUNT),
                OPENROUTER_MAX_RETRIES,
            ),
            "scenario_results": list(evaluation.scenario_results),
            "contrast_results": list(evaluation.contrast_results),
            "secret_read": secret_read,
            # WR-A final semantics: the positive branch required 24 successful
            # attempts WITH responses — response evidence proves the ops ran.
            "client_constructed": client_constructed,
            "network_attempted": network_attempted,
            "send_certainty": OPENROUTER_SEND_MAY_HAVE_STARTED,
            "dispatch_certainty": OPENROUTER_SEND_MAY_HAVE_STARTED,
        }
        terminal = OpenRouterTerminal.model_validate({**fields, "terminal_sha256": None})
        # CR-02: keep the root inventory exact before the terminal publish.
        state.ensure_profiles_dir()
        state.ensure_raw_evidence_dir()
        # Publish protected first; the CLI exports exactly the same canonical bytes.
        state.publish_terminal_raw(payload=canonical_json_bytes(terminal.model_dump(mode="json")))
        return terminal.model_dump(mode="json")

    async def run_attempt(place_id: str, *, is_retry: bool) -> dict[str, object] | None:
        nonlocal secret_read, client_constructed, network_attempted
        member = members_by_place[place_id]
        request_digest = member.request.request_sha256
        # T-05R-95: reconstruct this attempt's outbound body from the FIXED
        # source authority immediately before dispatch — byte-exact against
        # the approved member manifest (keys/order/IDs/text/forbidden
        # markers).  The plan's stored body bytes are never trusted here.
        expected_body = reconstruct_member_body_exact(member)
        # Reserve and dispatch BEFORE reading the credential value.
        attempt_number = state.reserve_once(
            claim=claim, place_id=place_id, request_sha256=request_digest
        )
        state.record_dispatch(
            claim=claim,
            place_id=place_id,
            request_sha256=request_digest,
            attempt_number=attempt_number,
        )
        scheduler.record_dispatched(place_id, is_retry=is_retry)

        def _mark_client_constructed() -> None:
            # WR-A final semantics: the constructor RETURNED — persist the
            # durable CLIENT_CONSTRUCTED marker (locally confirmable fact)
            # and record the in-memory boolean.
            nonlocal client_constructed
            state.record_client_constructed(
                claim=claim,
                place_id=place_id,
                attempt_number=attempt_number,
            )
            client_constructed = True

        def _record_send_boundary() -> None:
            # WR-A final semantics: durable send-boundary marker written
            # immediately BEFORE stream().  A pre-operation marker proves the
            # boundary was REACHED, never that a request was SENT — the
            # in-memory network_attempted flag is NOT set here; only actual
            # response/transport evidence may set it.
            state.record_send_boundary(
                claim=claim,
                place_id=place_id,
                attempt_number=attempt_number,
            )

        secret: str | None = None
        status_code: int | None = None
        body: bytes | None = None
        failure_reason: str | None = None
        try:
            secret = credential_reader(approval)
            secret_read = True
            if not isinstance(secret, str) or not secret.strip():
                raise ValueError("OPENROUTER_SECRET_UNAVAILABLE")
            status_code, body = await _openrouter_live_attempt(
                endpoint=plan.authority_endpoint(),
                request_body=expected_body,
                secret=secret,
                open_client=open_client,
                deadline_seconds=deadline_seconds,
                on_client_constructed=_mark_client_constructed,
                on_send_started=_record_send_boundary,
            )
            # WR-A final semantics: a returned response IS transport-level
            # proof the request operation ran — only NOW does the in-memory
            # network_attempted fact become true.
            if status_code is not None:
                network_attempted = True
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadError,
            httpx.ReadTimeout,
            httpx.WriteError,
            httpx.WriteTimeout,
            httpx.HTTPError,
            httpx.InvalidURL,
            httpx.StreamError,
        ):
            # T-05R-95 scrub: exception strings can carry proxy URLs, header
            # fragments, or body echoes.  Only the FIXED transport class code
            # survives — never str(error).
            failure_reason = "OPENROUTER_TRANSPORT_ERROR"
            # A transport exception with a received response/status proves the
            # request operation RAN; without one the boundary marker alone
            # never upgrades network_attempted.
            if status_code is not None:
                network_attempted = True
        except TimeoutError as error:
            fixed = {"OPENROUTER_ATTEMPT_DEADLINE_EXCEEDED"}
            message = str(error)
            failure_reason = message if message in fixed else "OPENROUTER_ATTEMPT_DEADLINE_EXCEEDED"
        except ValueError as error:
            fixed_codes = {
                "OPENROUTER_SECRET_UNAVAILABLE",
                "OPENROUTER_CONTENT_LENGTH_INVALID",
                "OPENROUTER_RESPONSE_TOO_LARGE",
                "OPENROUTER_RESPONSE_INVALID",
                "OPENROUTER_ATTEMPT_DEADLINE_EXCEEDED",
            }
            message = str(error)
            failure_reason = message if message in fixed_codes else "OPENROUTER_RESPONSE_INVALID"
        finally:
            # The credential value never outlives this attempt scope.  The
            # taint probes below are derived from the value IN MEMORY and are
            # themselves never printed, stored, or journaled.
            secret_value = secret if isinstance(secret, str) else ""
            del secret
        # T-05R-95: if the provider/proxy echoed the credential — exact bytes
        # OR a common value-derived encoding (lower/upper hex of the SHA-256
        # digest, base64 of the exact bytes, base64 of the UTF-8 digest hex) —
        # DO NOT store the original.  The journal keeps a digest-only safe
        # record (no raw bin, no length) and the run ends DESIGNED_NEGATIVE.
        credential_echo = bool(body) and _body_is_credential_tainted(body, secret_value)
        del secret_value
        safe_body = None if credential_echo else body
        evidence = state.persist_attempt_evidence(
            claim=claim,
            place_id=place_id,
            request_sha256=request_digest,
            attempt_number=attempt_number,
            response_body=safe_body,
            status_code=status_code,
            credential_response_stripped=credential_echo,
        )
        state.commit_reservation(
            claim=claim,
            place_id=place_id,
            request_sha256=request_digest,
            attempt_number=attempt_number,
            evidence_sha256=evidence,
        )
        if credential_echo:
            return finalize_terminal(
                status="DESIGNED_NEGATIVE",
                reason="OPENROUTER_CREDENTIAL_ECHO_REJECTED",
            )
        if failure_reason is None:
            if isinstance(status_code, int) and scheduler.classify_retry(status_code=status_code):
                if is_retry:
                    return finalize_terminal(
                        status="DESIGNED_NEGATIVE", reason=f"HTTP_{status_code}"
                    )
                retry_queue.append(place_id)
                return None
            if status_code != 200:
                return finalize_terminal(status="DESIGNED_NEGATIVE", reason=f"HTTP_{status_code}")
            responses[place_id] = {"status_code": status_code, "body": body}
            successful_ordinals[place_id] = attempt_number
            return None
        if scheduler.classify_retry(error=failure_reason):
            if is_retry or place_id in retried_once:
                return finalize_terminal(status="DESIGNED_NEGATIVE", reason=failure_reason)
            retry_queue.append(place_id)
            retried_once.add(place_id)
            return None
        return finalize_terminal(status="DESIGNED_NEGATIVE", reason=failure_reason)

    for place_id in scheduler.first_pass():
        failure = await run_attempt(place_id, is_retry=False)
        if failure is not None:
            return failure
    try:
        retry_plan = scheduler.retry_order(retry_queue)
    except RuntimeError as error:
        return finalize_terminal(status="DESIGNED_NEGATIVE", reason=str(error))
    for place_id in retry_plan:
        failure = await run_attempt(place_id, is_retry=True)
        if failure is not None:
            return failure
    return await finalize_success_terminal()


# --------------------------- T-05R-98 fixed internal credential path -------

OPENROUTER_SECRET_FILE_RELATIVE = ".secrets/itda-openrouter.env"
OPENROUTER_SECRET_ENV_KEY = "OPENROUTER_API_KEY"


def _openrouter_fixed_secret_file(
    _root: Path = REPOSITORY_ROOT / OPENROUTER_SECRET_FILE_RELATIVE,
) -> Path:
    """The FIXED ignored secret env file inside THIS repository root.

    T-05R-98 strict form: the path is bound as a DEFAULT argument — resolved
    ONCE at import time — so a post-import monkeypatch of the module-global
    ``REPOSITORY_ROOT`` can never redirect the frozen reader's file.  macOS
    tmp spelling is canonicalized exactly like
    ``OpenRouterDurableAuthorityState._open_root``: ``/tmp`` and ``/var``
    prefixes resolve to their ``/private``-prefixed real directories so the
    no-follow ancestor chain never traverses the ``/var`` or ``/tmp``
    symlinks.
    """

    target = _root
    text = str(target)
    if text.startswith("/tmp/") or text == "/tmp":
        target = Path("/private/tmp") / Path(*target.parts[2:])
    elif text.startswith("/var/") or text == "/var":
        target = Path("/private/var") / Path(*target.parts[2:])
    return target


def _openrouter_secret_metadata_identity(path: Path) -> str:
    """Non-value continuity identity of the FIXED secret file.

    One lexical no-follow ancestor-chain open; fstat before AND after with an
    identity over stat fields ONLY (device/inode/size/timestamps/owner/nlink/
    mode).  Never reads a byte of content, never derives any content digest,
    and never returns value-derived material.
    """

    target = _openrouter_fixed_secret_file()
    if path != target or not path.is_absolute():
        raise PermissionError("OPENROUTER_SECRET_FILE_FORBIDDEN")
    parent_fd = open_directory_chain_no_follow(path.parent, create=False)
    try:
        parent_metadata = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise PermissionError("OPENROUTER_SECRET_DIRECTORY_IDENTITY_UNSAFE")
        fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        before = os.fstat(fd)
        after = os.fstat(fd)
    finally:
        os.close(fd)

    def _identity(metadata: os.stat_result) -> str:
        return canonical_sha256(
            {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
                "uid": metadata.st_uid,
                "nlink": metadata.st_nlink,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        )

    if _identity(before) != _identity(after):
        raise PermissionError("OPENROUTER_SECRET_FILE_CHANGED_DURING_IDENTITY")
    return _identity(before)


def _read_fixed_openrouter_secret_value(*, expected_identity_sha256: str) -> str:
    """Read the credential VALUE from the FIXED file after identity re-check.

    Called ONLY by the frozen runner's internal ``build_credential_reader`` after each
    attempt's RESERVE+DISPATCH are durable.  One pinned descriptor; the stable
    stat tuple must match ``expected_identity_sha256`` across the read.  The
    value is returned to the transport scope only — never echoed, digested,
    length-recorded, journaled, or printed.
    """

    path = _openrouter_fixed_secret_file()
    if not path.is_absolute() or path.parent.name != ".secrets":
        raise PermissionError("OPENROUTER_SECRET_FILE_FORBIDDEN")
    parent_fd = open_directory_chain_no_follow(path.parent, create=False)
    try:
        fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)

    def _identity(metadata: os.stat_result) -> str:
        return canonical_sha256(
            {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
                "uid": metadata.st_uid,
                "nlink": metadata.st_nlink,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        )

    if len(raw) != before.st_size or _identity(before) != _identity(after):
        raise PermissionError("OPENROUTER_SECRET_FILE_CHANGED_DURING_READ")
    if _identity(before) != expected_identity_sha256:
        raise PermissionError("OPENROUTER_SECRET_CONTINUITY_CHANGED")
    try:
        text = raw.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError as error:
        raise PermissionError("OPENROUTER_SECRET_ENCODING_INVALID") from error
    if "\n" in text or "\r" in text or "=" not in text:
        raise PermissionError("OPENROUTER_SECRET_RECORD_INVALID")
    key, value = text.split("=", 1)
    if key != OPENROUTER_SECRET_ENV_KEY or not value.strip():
        raise PermissionError("OPENROUTER_SECRET_RECORD_INVALID")
    return value


def _make_openrouter_runner() -> _OpenRouterRunnerBinding:
    """Build the production runner bundle as immutable import-time closures.

    T-05R-98 strict form: the credential-reader CONSTRUCTION LOGIC lives
    INSIDE this factory body — every helper it needs (the fixed-file resolver,
    the non-value metadata identity, the keyword-only value reader) is
    captured in closure cells at CREATION time, so a post-import poison or
    deletion of any module-global helper cannot redirect an already-bound
    entry point, and there is no mutable ``LOAD_GLOBAL`` lookup of a
    production-capable reader factory at invocation time.
    """

    constructor_cell = _openrouter_open_client_blocking
    executor_cell = _execute_openrouter_transport
    fixed_file_cell = _openrouter_fixed_secret_file
    identity_cell = _openrouter_secret_metadata_identity
    value_reader_cell = _read_fixed_openrouter_secret_value

    def build_credential_reader(
        state: OpenRouterDurableAuthorityState,
    ):
        """THE internal credential reader bound to ONE state instance.

        Created inside this frozen factory; not exported, recoverable, or
        injectable — no parameter, factory, module global, or private-import
        path can substitute another reader.  On each call it re-verifies the
        approval/claim/root identity of THIS state, re-derives the FIXED
        file's non-value metadata identity, and only then opens the value.
        The value never escapes one attempt scope.
        """

        def read(approval: OpenRouterApprovalBinding) -> str:
            state._validate_approval(approval)
            persisted = state.read_claim()
            if persisted.approval_sha256 != approval.approval_sha256:
                raise PermissionError("OPENROUTER_CLAIM_INVALID")
            identity = identity_cell(fixed_file_cell())
            if identity != str(approval.secret_identity_sha256):
                raise PermissionError("OPENROUTER_SECRET_IDENTITY_MISMATCH")
            return value_reader_cell(expected_identity_sha256=identity)

        return read

    def open_client(**kwargs: object) -> object:
        import asyncio

        loop = asyncio.get_running_loop()

        async def construct_transfer_on_take() -> httpx.AsyncClient:
            client: httpx.AsyncClient | None = None

            def build() -> httpx.AsyncClient:
                nonlocal client
                client = constructor_cell(**kwargs)
                return client

            future = loop.run_in_executor(None, build)
            taken = False
            try:
                produced = await asyncio.shield(future)
                taken = True
                return produced
            finally:
                if not taken:

                    async def _drain_and_close():
                        try:
                            late = await future
                        except BaseException:
                            return
                        if late is not None and not getattr(late, "is_closed", True):
                            await late.aclose()

                    closing = loop.create_task(_drain_and_close())

                    def _detach(_: asyncio.Future) -> None:  # type: ignore[type-arg]
                        closing.done()

                    closing.add_done_callback(_detach)

        return construct_transfer_on_take()

    def runner(
        *,
        plan: OpenRouterPlan,
        state: OpenRouterDurableAuthorityState,
        claim: OpenRouterClaim,
        request_artifact: Mapping[str, object],
        run_sync: bool,
    ) -> dict[str, object]:
        approval_binding = state.require_approval_matches_artifact(
            request_artifact=request_artifact
        )
        coroutine = executor_cell(
            plan=plan,
            claim=claim,
            state=state,
            credential_reader=build_credential_reader(state),
            open_client=open_client,
        )
        del approval_binding
        if run_sync:
            import asyncio

            return asyncio.run(coroutine)
        return coroutine

    def invoke_sync(**kwargs: object) -> dict[str, object]:
        result = runner(**kwargs, run_sync=True)
        assert isinstance(result, dict)
        return result

    def invoke_async(**kwargs: object) -> object:
        return runner(**kwargs, run_sync=False)

    return _OpenRouterRunnerBinding(
        open_client=open_client,
        invoke_sync=invoke_sync,
        invoke_async=invoke_async,
    )


_SYNC_BINDING = _make_openrouter_runner()
_ASYNC_BINDING = _make_openrouter_runner()


# --------------------------- T-05R-98 strict: complete import-time sealing --
#
# The public entries and their authority derivation are built INSIDE one
# import-time factory.  Every production path constant is resolved ONCE here
# (exact Path objects) and every helper is captured as a closure cell — a
# post-import monkeypatch/deletion of ``_SYNC_BINDING``, ``_ASYNC_BINDING``,
# any derivation helper, ``REPOSITORY_ROOT``, or the secret-path helpers can
# never redirect an already-bound entry, and disassembly of the bound
# functions shows ZERO forbidden LOAD_GLOBALs.


def _bind_public_entry(*, binding, run_sync: bool):
    """Build ONE zero-arg public production entry over frozen cells.

    Captured at import time:
      - ``binding.invoke_sync`` / ``binding.invoke_async`` (the sealed runner);
      - the EXACT resolved production paths (request packet, protected root);
      - every authority helper callable.
    The returned function consults NO mutable module global at call time.
    """

    invoke_cell = binding.invoke_sync if run_sync else binding.invoke_async
    repository_root_cell = REPOSITORY_ROOT
    request_path_cell = OPENROUTER_REQUEST_OUTPUT
    protected_root_cell = OPENROUTER_PROTECTED_ROOT
    read_public_cell = _read_public_file_no_follow
    digest_domains_cell = openrouter_packet_digest_domains
    source_bundles_cell = _verified_source_bundles
    manifest_cell = checkout_manifest_sha256
    commit_cell = openrouter_checkout_commit_sha256
    build_plan_cell = build_openrouter_plan
    validate_request_cell = validate_openrouter_public_request
    descriptor_cell = OpenRouterProtectedStateDescriptor.from_root
    durable_state_cell = OpenRouterDurableAuthorityState

    def derive_authority():
        """Re-derive the ENTIRE authority chain from frozen cells ONLY.

        Order (every step before any client/credential/durable mutation):
          1. sanitized-entrypoint capability gate;
          2. offline / network-capability gates;
          3. committed packet at the FIXED captured path — both digests;
          4. fixed-source plan rebuild validated against that packet;
          5. persisted approval + one-use claim at the FIXED protected root.
        """

        from itda.minimal_probe_bootstrap import validate_capability_process

        validate_capability_process()
        if os.environ.get("ITDA_OFFLINE") == "1" or os.environ.get("ITDA_NO_NETWORK") == "1":
            raise PermissionError("LIVE_MODE_DISABLED")
        if os.environ.get("CI") or os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
            raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        packet_raw_bytes = read_public_cell(request_path_cell)
        try:
            packet_payload = json.loads(packet_raw_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PermissionError("OPENROUTER_PUBLIC_PACKET_MALFORMED") from error
        if not isinstance(packet_payload, dict):
            raise PermissionError("OPENROUTER_PUBLIC_PACKET_MALFORMED")
        semantic_digest, raw_file_digest = digest_domains_cell(packet_payload)
        stored_artifact = packet_payload.get("request_artifact_sha256")
        if not isinstance(stored_artifact, str) or stored_artifact != semantic_digest:
            raise PermissionError("OPENROUTER_PACKET_SEMANTIC_DIGEST_DRIFT")
        if hashlib.sha256(packet_raw_bytes).hexdigest() != raw_file_digest:
            raise PermissionError("OPENROUTER_PACKET_RAW_DIGEST_DRIFT")
        rebuilt_plan = build_plan_cell(
            source_bundles_cell(),
            checkout_manifest_digest=manifest_cell(repository_root=repository_root_cell),
        )
        validate_request_cell(
            packet_payload,
            plan=rebuilt_plan,
            checkout_commit_sha256=commit_cell(repository_root=repository_root_cell),
        )
        descriptor = descriptor_cell(state_root=str(protected_root_cell))
        state = durable_state_cell(descriptor)
        claim = state.read_claim()
        approval_binding = state.require_approval_matches_artifact(
            request_artifact={"request_artifact_sha256": stored_artifact}
        )
        if str(approval_binding.request_file_sha256) != raw_file_digest:
            raise PermissionError("OPENROUTER_APPROVAL_RAW_BYTES_DRIFT")
        if str(approval_binding.request_manifest_sha256) != str(
            rebuilt_plan.request_manifest_sha256
        ):
            raise PermissionError("OPENROUTER_PLAN_APPROVAL_MANIFEST_MISMATCH")
        return rebuilt_plan, state, claim, dict(packet_payload)

    def derive_only_for_tests():
        """Private test-only alias so tests may exercise the frozen
        derivation without the transport; NOT exported, never used by any
        production path."""

        return derive_authority()

    if run_sync:

        def execute_entry() -> dict[str, object]:
            plan, state, claim, artifact = derive_authority()
            result = invoke_cell(
                plan=plan,
                state=state,
                claim=claim,
                request_artifact=artifact,
            )
            assert isinstance(result, dict)
            return result

    else:

        async def execute_entry() -> dict[str, object]:
            plan, state, claim, artifact = derive_authority()
            result = await invoke_cell(
                plan=plan,
                state=state,
                claim=claim,
                request_artifact=artifact,
            )
            assert isinstance(result, dict)
            return result

    execute_entry.__name__ = (
        "execute_openrouter_production" if run_sync else "execute_openrouter_production_async"
    )
    return execute_entry


execute_openrouter_production = _bind_public_entry(binding=_SYNC_BINDING, run_sync=True)
execute_openrouter_production_async = _bind_public_entry(binding=_ASYNC_BINDING, run_sync=False)


# T-05R-98 re-audit: ``run_production_with_credential_reader`` and the whole
# bindable-reader seam are REMOVED.  The only production surface is the
# zero-argument ``execute_openrouter_production`` / ``..._async`` pair, which
# internally re-derives the fixed packet/source/root/approval/claim chain AND
# builds THE fixed internal credential reader from repository-owned constants
# (see the frozen factory's ``build_credential_reader``).  No factory, private import,
# or attribute can inject a reader: there is no parameter to receive one.


# --------------------------- strictly private test transport ---------------

_OPENROUTER_TEST_ROOT_MARKERS = ("/tmp/", "/private/tmp/", "/var/folders/")


def _reject_production_root_alias(candidate: Path) -> None:
    """Reject production aliases without observing the production root itself."""

    production = _lexical_absolute_path(OPENROUTER_PROTECTED_ROOT)
    candidate_absolute = _lexical_absolute_path(candidate)
    if candidate_absolute == production:
        raise PermissionError("OPENROUTER_MOCK_FORBIDS_PRODUCTION_ROOT")
    if production in candidate_absolute.parents:
        raise PermissionError("OPENROUTER_MOCK_FORBIDS_PRODUCTION_ROOT_DESCENDANT")

    # Inspect only existing candidate-side components (synthetic temp state in
    # tests).  Never call resolve/stat/list on the production coordinate.  A
    # symlink component whose lexical target is production or its descendant is
    # rejected before the state constructor can open anything.
    probe = Path(candidate_absolute.anchor)
    for component in candidate_absolute.parts[1:]:
        probe = probe / component
        if probe == production or production in probe.parents:
            raise PermissionError("OPENROUTER_MOCK_FORBIDS_PRODUCTION_ROOT_ALIAS")
        try:
            metadata = os.lstat(probe)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            target = Path(os.readlink(probe))
            if not target.is_absolute():
                target = probe.parent / target
            target = _lexical_absolute_path(target)
            if target == production or production in target.parents:
                raise PermissionError("OPENROUTER_MOCK_FORBIDS_PRODUCTION_ROOT_ALIAS")


async def execute_openrouter_mock_transport(
    *,
    plan: OpenRouterPlan,
    claim: OpenRouterClaim,
    protected_state_root: Path,
    response_handler: Callable[[httpx.Request], httpx.Response],
) -> dict[str, object]:
    """Provider-free MockTransport helper bound to a disjoint test-only root.

    The production root — every descendant, symlink alias, and ``..``-
    normalized spelling — is refused component-wise.  This function is the
    ONLY caller-injected transport seam and lives in a strictly private test
    namespace; production entry points above never consult it.
    """

    root_str = str(protected_state_root)
    _reject_production_root_alias(Path(root_str))
    resolved = str(Path(root_str).resolve(strict=False))
    if not any(marker in resolved for marker in _OPENROUTER_TEST_ROOT_MARKERS):
        raise PermissionError("OPENROUTER_MOCK_REQUIRES_ISOLATED_TEST_ROOT")
    descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=root_str)
    if claim.protected_state_sha256 != descriptor.protected_state_sha256:
        raise PermissionError("OPENROUTER_MOCK_CLAIM_ROOT_MISMATCH")
    state = OpenRouterDurableAuthorityState(descriptor)

    async def open_client(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(response_handler), **kwargs)

    # The test-only credential reader is built INSIDE this strictly-private
    # namespace (never a caller parameter) and participates in the SAME
    # reserve-before-secret ordering, so the run's terminal legitimately
    # records a resolved (synthetic) credential — exactly like the fixed
    # production reader would.
    def test_credential_reader(_approval: OpenRouterApprovalBinding) -> str:
        return "provider-free-test-secret"

    return await _execute_openrouter_transport(
        plan=plan,
        claim=claim,
        state=state,
        credential_reader=test_credential_reader,
        open_client=open_client,
    )


__all__ = [
    "OPENROUTER_ALLOWED_HEADER_NAMES",
    "OPENROUTER_PROTECTED_ROOT",
    "OPENROUTER_PROTECTED_ROOT_RELATIVE",
    "OPENROUTER_PUBLIC_REQUEST_RELATIVE",
    "OPENROUTER_TERMINAL_OUTPUT",
    "OpenRouterCapabilityError",
    "OpenRouterDurableAuthorityState",
    "OpenRouterFirstPass",
    "OpenRouterMember",
    "OpenRouterPlan",
    "OpenRouterProtectedState",
    "OpenRouterScheduler",
    "OpenRouterSecretUnavailable",
    "OpenRouterVerifiedOutcome",
    "assert_openrouter_positive",
    "assert_openrouter_positive_outcome",
    "build_openrouter_plan",
    "build_openrouter_public_request",
    "classify_openrouter_terminal",
    "classify_verified_outcome",
    "execute_openrouter_production_async",
    "execute_openrouter_mock_transport",
    "execute_openrouter_production",
    "openrouter_checkout_commit_sha256",
    "openrouter_evidence_projection",
    "openrouter_packet_digest_domains",
    "require_fixed_openrouter_paths",
    "synthetic_openrouter_claim",
    "validate_openrouter_public_request",
    "verify_fixed_source_authority",
    "verify_openrouter_outcome",
    "verify_openrouter_outcome_for_cli",
    "verify_openrouter_terminal",
    "write_openrouter_public_request",
    "OPENROUTER_V2_PROTECTED_ROOT",
    "OPENROUTER_V2_PROTECTED_ROOT_RELATIVE",
    "OPENROUTER_V2_PUBLIC_REQUEST_RELATIVE",
    "OPENROUTER_V2_REQUEST_OUTPUT",
    "OPENROUTER_V2_TERMINAL_OUTPUT",
    "OPENROUTER_V2_TERMINAL_RELATIVE",
    "OpenRouterMemberV2",
    "OpenRouterPlanV2",
    "build_openrouter_v2_plan",
    "build_openrouter_v2_public_request",
    "openrouter_v2_checkout_commit_sha256",
    "openrouter_v2_checkout_manifest_sha256",
    "require_fixed_openrouter_v2_paths",
    "validate_openrouter_v2_namespace",
    "validate_openrouter_v2_public_request",
    "verify_openrouter_v2_predecessor_consumption",
    "write_openrouter_v2_public_request",
]
