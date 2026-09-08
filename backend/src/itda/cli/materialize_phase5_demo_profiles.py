"""Explicit replay, preflight, live, and verify commands for Phase 5 profiles."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

# ---------------------------------------------------------------------------
# Direct-invocation capability gate.
#
# Capability commands whose only production entrypoint is the stdlib-only
# bootstrap (see below).
# ---------------------------------------------------------------------------

_FRESH24_CAPABILITY_COMMANDS = frozenset(
    {
        "nvidia-fresh24-install-approval",
        "nvidia-fresh24-live",
        "nvidia-fresh24-reconcile",
    }
)

_OPENROUTER_CAPABILITY_COMMANDS = frozenset(
    {
        "openrouter-recovery-install-approval",
        "openrouter-recovery-live",
        "openrouter-recovery-reconcile",
    }
)
_OPENROUTER_V2_CAPABILITY_COMMANDS = frozenset(
    {
        "openrouter-recovery-v2-install-approval",
        "openrouter-recovery-v2-live",
        "openrouter-recovery-v2-reconcile",
    }
)
# Plan 05-38 registers the disjoint r3/v3 capability names.  The PUBLIC main
# still rejects every one of them fail-closed; they are listed here so the
# pre-import gate and the direct-invocation guard can name the correct
# sanitized bootstrap entrypoint.  Actual dispatch lives ONLY behind
# ``minimal_probe_bootstrap`` (see _openrouter_v3_capability_dispatch below).
_OPENROUTER_V3_CAPABILITY_COMMANDS = frozenset(
    {
        "openrouter-recovery-v3-install-approval",
        "openrouter-recovery-v3-live",
        "openrouter-recovery-v3-reconcile",
    }
)
_OPENROUTER_V4_CAPABILITY_COMMANDS = frozenset(
    {
        "openrouter-recovery-v4-install-approval",
        "openrouter-recovery-v4-live",
        "openrouter-recovery-v4-reconcile",
    }
)

_ALL_CAPABILITY_COMMANDS = (
    _FRESH24_CAPABILITY_COMMANDS
    | _OPENROUTER_CAPABILITY_COMMANDS
    | _OPENROUTER_V2_CAPABILITY_COMMANDS
    | _OPENROUTER_V3_CAPABILITY_COMMANDS
    | _OPENROUTER_V4_CAPABILITY_COMMANDS
)

# ---------------------------------------------------------------------------
# Direct-invocation fail-closed gate.
#
# ``python -m itda.cli.materialize_phase5_demo_profiles`` can never be a
# production entrypoint for a fresh24 capability command: by the time this
# module executes at all the interpreter has already run site startup
# (sitecustomize/usercustomize from a hostile PYTHONPATH), so no in-module
# check can restore a pre-import guarantee.  The only production entrypoint
# for capability commands is the stdlib-only bootstrap executed with
# ``python -I backend/src/itda/minimal_probe_bootstrap.py`` (see
# ``minimal_probe_bootstrap.py``), which validates origin, environment, and
# checkout before importing and dispatching this application module.
#
# A direct invocation with a capability command therefore fails closed here,
# before any approval install, protected-root mutation, claim, dispatch, or
# other side effect.  Provider-free commands (verify/classify/preflight/…)
# still dispatch normally through ``main`` below.
# ---------------------------------------------------------------------------

_FRESH24_BOOTSTRAP_ENTRYPOINT = (
    "python -I backend/src/itda/minimal_probe_bootstrap.py"
)

if __name__ == "__main__" and len(sys.argv) > 1 and (
    sys.argv[1] in _ALL_CAPABILITY_COMMANDS
):
    _entrypoint_hint = (
        "USE_FRESH24_BOOTSTRAP_ENTRYPOINT"
        if sys.argv[1] in _FRESH24_CAPABILITY_COMMANDS
        else (
            "OPENROUTER_V2_CAPABILITY_INERT"
            if sys.argv[1] in _OPENROUTER_V2_CAPABILITY_COMMANDS
            else (
                "USE_OPENROUTER_V3_BOOTSTRAP_ENTRYPOINT"
                if sys.argv[1] in _OPENROUTER_V3_CAPABILITY_COMMANDS
                else (
                    "USE_OPENROUTER_V4_BOOTSTRAP_ENTRYPOINT"
                    if sys.argv[1] in _OPENROUTER_V4_CAPABILITY_COMMANDS
                    else "USE_OPENROUTER_BOOTSTRAP_ENTRYPOINT"
                )
            )
        )
    )
    print(
        f"{_entrypoint_hint} "
        f"run: env -u PYTHONPATH -u PYTHONHOME {_FRESH24_BOOTSTRAP_ENTRYPOINT} "
        f"{sys.argv[1]} ...",
        file=sys.stderr,
    )
    raise SystemExit(2)

from pydantic import ValidationError  # noqa: E402 — after the pre-import gate

from itda.contracts.demo_profile_materialization import (  # noqa: E402
    ATTEMPT_RESERVATION_MICRO_USD,
    CODING_PLAN_AUTHORITY_SHA256,
    CODING_PLAN_AUTHORITY_TEXT,
    CODING_PLAN_BASE_URL,
    CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    CUMULATIVE_RERUN_CAP_MICRO_USD,
    MAX_HTTP_ATTEMPTS,
    MAX_RUN_COST_MICRO_USD,
    NVIDIA_AUTHORITY_SHA256,
    NVIDIA_AUTHORITY_TEXT,
    NVIDIA_INITIAL_AUTHORITY_SHA256,
    NVIDIA_PROFILE_ENDPOINT,
    NVIDIA_PROFILE_MODEL,
    NVIDIA_PROVIDER_LANE,
    NVIDIA_RESUME_AUTHORITY_SHA256,
    NVIDIA_RESUME_AUTHORITY_TEXT,
    NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256,
    NVIDIA_SECOND_RESUME_AUTHORITY_SHA256,
    NVIDIA_SECOND_RESUME_AUTHORITY_TEXT,
    NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256,
    NVIDIA_TOOL_AUTHORITY_SHA256,
    NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
    NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT,
    NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256,
    NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256,
    NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_TEXT,
    NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS,
    NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_TEXT,
    NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS,
    NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_TEXT,
    PRIOR_COMMITTED_LOWER_MICRO_USD,
    PRIOR_COMMITTED_UPPER_MICRO_USD,
    PROFILE_ENDPOINT,
    PROFILE_MODEL,
    RERUN_AUTHORITY_SHA256,
    RERUN_AUTHORITY_TEXT,
    RERUN_COST_CAP_MICRO_USD,
    CodingPlanProfileMaterializationConfig,
    CodingPlanProfileMaterializationReceipt,
    DemoProfileMaterializationConfig,
    DemoSourceBundle,
    NvidiaMinimaxProfileMaterializationConfig,
    NvidiaMinimaxProfileMaterializationReceipt,
    PricingSnapshot,
)
from itda.contracts.phase5_fresh_cohort import (  # noqa: E402 — after the pre-import gate
    FRESH_ATTEMPT_DEADLINE_SECONDS,
    FRESH_AUTHORITY_ID,
    FRESH_CONFIDENCE_THRESHOLD,
    FRESH_EXPOSURE_CAP_MICRO_USD,
    FRESH_MAX_HTTP_ATTEMPTS,
    FRESH_MIN_ELIGIBLE_PROFILES,
    FRESH_MODEL,
    FRESH_PROVIDER_LANE,
    FRESH_RESERVATION_MICRO_USD,
)
from itda.contracts.phase5_nvidia_recovery import (  # noqa: E402 — after the pre-import gate
    MINIMAL_PROBE_ACTIVATION_CAPABILITY,
    MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS,
    MINIMAL_PROBE_AUTHORITY_ID,
    MINIMAL_PROBE_COHORT_CAPABILITY,
    MINIMAL_PROBE_CONCURRENCY,
    MINIMAL_PROBE_CONFIG_SHA256,
    MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD,
    MINIMAL_PROBE_ENDPOINT,
    MINIMAL_PROBE_MAX_ATTEMPTS,
    MINIMAL_PROBE_MAX_RESPONSE_BYTES,
    MINIMAL_PROBE_MODEL,
    MINIMAL_PROBE_PROFILE_SCHEMA_SHA256,
    MINIMAL_PROBE_PROMPT_SHA256,
    MINIMAL_PROBE_PROMPT_VERSION,
    MINIMAL_PROBE_PROVIDER_LANE,
    MINIMAL_PROBE_RECEIPT_EMITTED,
    MINIMAL_PROBE_RELEASE_CAPABILITY,
    MINIMAL_PROBE_RESERVATION_MICRO_USD,
    MINIMAL_PROBE_SECRET_FILE_FORMAT,
    MINIMAL_PROBE_SECRET_FILE_MODE,
    MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES,
    MINIMAL_PROBE_SMOKE_CAPABILITY,
    NvidiaMinimalProbePublicArtifact,
    NvidiaMinimalProbeTerminal,
)
from itda.domain.canonical import (  # noqa: E402 — after the pre-import gate
    canonical_json_bytes,
    canonical_sha256,
)
from itda.pipeline import (  # noqa: E402 — after the pre-import gate
    phase5_fresh24,  # noqa: E402 — after the pre-import gate
    phase5_openrouter_recovery,
)
from itda.pipeline.demo_profile_materialization import (  # noqa: E402 — after the pre-import gate
    DemoProfileMaterializationError,
    DemoProfileMaterializationFailure,
    DurableCodingPlanJournal,
    DurableNvidiaJournal,
    DurableRerunJournal,
    build_nvidia_resume_authority,
    build_nvidia_resume_plan,
    build_nvidia_second_resume_authority,
    build_nvidia_second_resume_plan,
    build_nvidia_v4_probe_resume_authority,
    build_nvidia_v4_probe_resume_plan,
    build_nvidia_v5_attempt8_resume_authority,
    build_nvidia_v5_attempt8_resume_plan,
    build_nvidia_v5_three_validated_resume_authority,
    build_nvidia_v5_three_validated_resume_plan,
    build_nvidia_v5_two_probe_resume_authority,
    build_nvidia_v5_two_probe_resume_plan,
    build_synthetic_replay_sources,
    materialization_binding_payload,
    materialize_demo_profiles,
    materialize_live_demo_profiles,
    materialize_live_nvidia_profiles,
    materialize_live_nvidia_resume_profiles,
    materialize_live_nvidia_second_resume_profiles,
    materialize_live_nvidia_v4_probe_resume_profiles,
    materialize_live_nvidia_v5_attempt8_resume_profiles,
    materialize_live_nvidia_v5_three_validated_resume_profiles,
    materialize_live_nvidia_v5_two_probe_resume_profiles,
    publish_demo_profile_failure,
    publish_demo_profile_generation,
    verify_demo_profile_generation,
)
from itda.pipeline.phase5_attempt5_retaining import (  # noqa: E402 — after the pre-import gate
    Attempt5RetainingAuthority,
    Attempt5RetainingPlan,
    build_attempt5_retaining_plan,
    derive_attempt5_retaining_authority,
    execute_attempt5_retaining_materialization,
    preflight_attempt5_retaining_authority,
    preflight_attempt5_retaining_execution_approval,
    publish_attempt5_retaining_generation,
)
from itda.pipeline.phase5_fresh_cohort import (  # noqa: E402 — after the pre-import gate
    FreshCohortPlan,
    FreshDurableAuthorityState,
    FreshProtectedStateResolver,
    build_fresh_cohort_plan,
    checkout_manifest_sha256,
    install_fresh_approval_from_public_artifact,
    safe_public_request_payload,
    validate_fresh_public_approval_artifact,
)
from itda.pipeline.phase5_fresh_live import (  # noqa: E402 — after the pre-import gate
    execute_fresh_live_cohort,
    reconcile_fresh_claimed_run,
)
from itda.providers.nvidia_minimax_profile import (  # noqa: E402 — after the pre-import gate
    NvidiaAttemptLedger,
    NvidiaMinimaxProfileAdapter,
    NvidiaRateLimitPolicy,
)
from itda.providers.zhipu_glm5v_profile import (  # noqa: E402 — after the pre-import gate
    AttemptCostLedger,
    CodingPlanAttemptLedger,
    ZhipuGlm5vProfileAdapter,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
REPLAY_FIXTURE = REPOSITORY_ROOT / "fixtures/synthetic/phase5/provider-profile-replay.json"
FIXED_DEV_AUTHORITY = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/phase4-demo-authority/input-authority.json"
)
FIXED_LIVE_SOURCE_BUNDLES = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/phase5-demo-profile-materialization/source-bundles.json"
)
SECRET_FILE = REPOSITORY_ROOT / ".secrets/itda-api.env"
FRESH_PUBLIC_REQUEST_OUTPUT = (
    REPOSITORY_ROOT / "artifacts/public/phase5/fresh-provider-materialization-request.json"
)
FRESH_PROTECTED_STATE_ROOT = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/phase5-demo-profile-materialization/fresh"
)
FRESH_TERMINAL_OUTPUT = (
    REPOSITORY_ROOT / "artifacts/reports/phase5/fresh-provider-terminal.json"
)
OUTPUT_ROOT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/phase5-demo-profile-materialization/generations"
)
_SAFE_OUTPUT_ROOT = "artifacts/restricted/catalog/phase5-demo-profile-materialization"
PRIOR_BLOCKER = OUTPUT_ROOT.parent / "live-budget-exhaustion-blocker.json"
PRIOR_RERUN_AUTHORITY = (
    OUTPUT_ROOT.parent
    / "reruns/fef0add1196d86930fb6dfb47736f36d4d10a43a496c029ccb668046894f56cf/authority.json"
)
PRIOR_RERUN_TERMINAL = PRIOR_RERUN_AUTHORITY.parent / "terminal/terminal.json"
PRIOR_FAILURE = (
    OUTPUT_ROOT.parent
    / "failures/d43e36b66d660a60e9d7b88f10985d3d1f0804d8adefb4a64d77252471614013/failure.json"
)
PRIOR_FAILURE_ATTEMPTS = PRIOR_FAILURE.parent / "attempts.json"
CODING_PLAN_EVIDENCE_REF = "debug-session:phase5-coding-endpoint#user-account-plan-screenshot"
PRIOR_PAYGO_CUMULATIVE_UPPER_MICRO_USD = 12_445_760
_PRIOR_PAYGO_HASHES = {
    PRIOR_BLOCKER: "3834d0de4c60a760a15971ec4d2694e2f09d158549b94b18634fe87cd40c4cd7",
    PRIOR_RERUN_AUTHORITY: "c1f4e1b6a290e27c9846b5536c90080575f669301b4e8abe98356428abc114af",
    PRIOR_RERUN_TERMINAL: "ac26e91e47401a6f875318cbe7071d9fb9dfd151a21444bbd75c506308d349de",
    PRIOR_FAILURE: "1e500f59bb40f99094f3c8511e44ab43a1a694c204132b9f97d07b55aad75901",
    PRIOR_FAILURE_ATTEMPTS: "c56a056b424195a1e3351ace818c49b4d3c664e3b4b8d1df2bd37ad4c8123af0",
}
PRIOR_CODING_PLAN_ROOT = OUTPUT_ROOT.parent / "coding-plan" / CODING_PLAN_AUTHORITY_SHA256
PRIOR_CODING_PLAN_AUTHORITY = PRIOR_CODING_PLAN_ROOT / "authority.json"
PRIOR_CODING_PLAN_TERMINAL = PRIOR_CODING_PLAN_ROOT / "terminal/terminal.json"
PRIOR_CODING_PLAN_ATTEMPT = (
    PRIOR_CODING_PLAN_ROOT
    / "attempts/01-52a245728c17e8fa72237003d9268221ff1579927166e675387300392484e053/attempt.json"
)
PRIOR_CODING_PLAN_RAW = PRIOR_CODING_PLAN_ATTEMPT.with_name("raw-response.bin")
_PRIOR_CODING_PLAN_HASHES = {
    PRIOR_CODING_PLAN_AUTHORITY: "6f7e30de1975c02fb6c1c74fc80728d256ab151f38983f597e5671bc63a0b9fb",
    PRIOR_CODING_PLAN_TERMINAL: "9c33f65a5a95c3ac94b83d00e52b5da7747348d8b57dde5e762257a345c80541",
    PRIOR_CODING_PLAN_ATTEMPT: "7f011dd3cb264dbcb1adf89081dc24d24295a2537789017b6a51d04b1dfcdb94",
    PRIOR_CODING_PLAN_RAW: "80136df3594d7bf7d602f6e4f07bb7efd1f27fef21ae6af23e6b194a89829b1c",
}
PRIOR_NVIDIA_ROOT = OUTPUT_ROOT.parent / "nvidia" / NVIDIA_INITIAL_AUTHORITY_SHA256
PRIOR_NVIDIA_AUTHORITY = PRIOR_NVIDIA_ROOT / "authority.json"
PRIOR_NVIDIA_TERMINAL = PRIOR_NVIDIA_ROOT / "terminal/terminal.json"
PRIOR_NVIDIA_ATTEMPT = (
    PRIOR_NVIDIA_ROOT
    / "attempts/01-ec8f27bd440ac8c990fc4b57a48c365d8bc102313c721fabea642d537c5cee30/attempt.json"
)
PRIOR_NVIDIA_RAW = PRIOR_NVIDIA_ATTEMPT.with_name("raw-response.bin")
PRIOR_NVIDIA_TOOL_ROOT = OUTPUT_ROOT.parent / "nvidia" / NVIDIA_TOOL_AUTHORITY_SHA256
PRIOR_NVIDIA_TOOL_AUTHORITY = PRIOR_NVIDIA_TOOL_ROOT / "authority.json"
PRIOR_NVIDIA_TOOL_TERMINAL = PRIOR_NVIDIA_TOOL_ROOT / "terminal/terminal.json"
PRIOR_NVIDIA_TOOL_ATTEMPT = (
    PRIOR_NVIDIA_TOOL_ROOT
    / "attempts/01-ae15639ee5667957db76bd37dbe96250123de87b40866940b7039ecb8c0ed7c1/attempt.json"
)
PRIOR_NVIDIA_TOOL_RAW = PRIOR_NVIDIA_TOOL_ATTEMPT.with_name("raw-response.bin")
PRIOR_NVIDIA_SENTINEL_ROOT = OUTPUT_ROOT.parent / "nvidia" / NVIDIA_AUTHORITY_SHA256
_PRIOR_NVIDIA_HASHES = {
    PRIOR_NVIDIA_AUTHORITY: "354a01ae994ae0854958aa696637ea83ca6dc76b61b0692489bc46ceb7f8e2ce",
    PRIOR_NVIDIA_TERMINAL: "e9c6acd9b542068610ebf93ffc77af8bf241bd93599f7f900bf73effadc15a73",
    PRIOR_NVIDIA_ATTEMPT: "dfa400c9a97efd20d1a262decee5290365879a976d55a479903c3c55241ce6a2",
    PRIOR_NVIDIA_RAW: "b6c8d1291e7d3afff60e2a4283559af30a5d1fefc7303c0f9555244acfc175e5",
    PRIOR_NVIDIA_TOOL_AUTHORITY: "c57583e71c2957182a9ebe0b16b5f5b5d10b700c57f031cd163493669872a42a",
    PRIOR_NVIDIA_TOOL_TERMINAL: "202358c375e821b2055584dfd16bc2813e452a43401fa0389252721e7f736acd",
    PRIOR_NVIDIA_TOOL_ATTEMPT: "7c95eda15a1dbdfc18c8ea3dfebaad770d5743fa442bccb3bde14db60e83daf2",
    PRIOR_NVIDIA_TOOL_RAW: "e6fdd1ddc6c5f83fb19bec22b7f3ba7b468138335631c4313ce04036301c6b6d",
}
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _read_bounded_regular(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ValueError("fixed input is not a bounded single-link regular file")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise OSError("fixed input ended before its stated size")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OSError("fixed input changed during read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _load_json(path: Path, *, maximum_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    value = json.loads(_read_bounded_regular(path, maximum_bytes=maximum_bytes))
    if not isinstance(value, dict):
        raise ValueError("fixed JSON input must be an object")
    return cast(dict[str, Any], value)


def _fixed_dev_place_ids() -> tuple[str, ...]:
    authority = _load_json(FIXED_DEV_AUTHORITY, maximum_bytes=4 * 1024 * 1024)
    supplied_digest = authority.get("authority_sha256")
    if supplied_digest != canonical_sha256(
        {key: value for key, value in authority.items() if key != "authority_sha256"}
    ):
        raise ValueError("fixed DEV authority digest drifted")
    ids = authority.get("dev_place_refs")
    if (
        not isinstance(ids, list)
        or len(ids) != 24
        or len(set(ids)) != 24
        or tuple(ids) != tuple(sorted(ids))
        or any(not isinstance(value, str) or not value.startswith("place:") for value in ids)
    ):
        raise ValueError("fixed DEV authority is not an exact canonical cohort")
    folded = canonical_json_bytes(ids).lower()
    if b"blind" in folded:
        raise ValueError("fixed DEV authority contains evaluation material")
    return tuple(cast(list[str], ids))


def _load_replay_fixture() -> dict[str, Any]:
    fixture = _load_json(REPLAY_FIXTURE, maximum_bytes=512 * 1024)
    if fixture.get("fixture_scope") != "SYNTHETIC_REPLAY_ONLY":
        raise ValueError("replay fixture scope is invalid")
    return fixture


def _load_live_source_bundles(path: Path) -> tuple[DemoSourceBundle, ...]:
    if path != FIXED_LIVE_SOURCE_BUNDLES:
        raise ValueError("live source bundle path differs from fixed authority")
    from itda.cli.collect_phase5_demo_sources import verify_source_collection

    validated = verify_source_collection(path.parent)
    if tuple(bundle.place_id for bundle in validated) != _fixed_dev_place_ids():
        raise ValueError("live source bundle membership differs from fixed DEV authority")
    return validated


def _read_local_secret(path: Path, *, allow_missing: bool) -> tuple[bool, str | None]:
    if not path.exists():
        if allow_missing:
            return False, None
        raise PermissionError("provider secret file is unavailable")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PermissionError("provider secret file permissions are unsafe")
    raw = _read_bounded_regular(path, maximum_bytes=64 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PermissionError("provider secret file encoding is invalid") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PermissionError("provider secret file record is invalid")
        key, value = line.split("=", 1)
        if not _ENV_NAME.fullmatch(key) or not value or key in values:
            raise PermissionError("provider secret file record is invalid")
        values[key] = value
    selected = values.get("ZHIPUAI_API_KEY") or values.get("BIGMODEL_API_KEY")
    if selected is None:
        if allow_missing:
            return False, None
        raise PermissionError("provider secret is unavailable")
    return True, selected


def _read_nvidia_secret(path: Path, *, allow_missing: bool) -> tuple[bool, str | None]:
    """Read only the exact local NVIDIA_KEY; ambient/fallback keys are forbidden."""

    if not path.exists():
        if allow_missing:
            return False, None
        raise PermissionError("local NVIDIA_KEY secret file is unavailable")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PermissionError("NVIDIA_KEY secret file permissions are unsafe")
    raw = _read_bounded_regular(path, maximum_bytes=64 * 1024)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PermissionError("NVIDIA_KEY secret file encoding is invalid") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PermissionError("NVIDIA_KEY secret file record is invalid")
        key, value = line.split("=", 1)
        if not _ENV_NAME.fullmatch(key) or not value or key in values:
            raise PermissionError("NVIDIA_KEY secret file record is invalid")
        values[key] = value
    selected = values.get("NVIDIA_KEY")
    if selected is None:
        if allow_missing:
            return False, None
        raise PermissionError("exact local NVIDIA_KEY is unavailable")
    return True, selected


def _minimal_probe_open_secret(path: Path) -> tuple[int, os.stat_result]:
    """Open the fixed secret through a lexical, no-follow ancestor chain."""

    from itda.cli.freeze_preview import open_directory_chain_no_follow

    if path != SECRET_FILE or not path.is_absolute():
        raise PermissionError("caller-selected minimal probe secret file is forbidden")
    parent = open_directory_chain_no_follow(path.parent, create=False)
    try:
        parent_metadata = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise PermissionError("NVIDIA_KEY secret directory identity is unsafe")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 0 < metadata.st_size <= 64 * 1024
    ):
        os.close(descriptor)
        raise PermissionError("NVIDIA_KEY secret file identity or permissions are unsafe")
    return descriptor, metadata


def _minimal_probe_secret_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_uid,
        metadata.st_nlink,
        stat.S_IMODE(metadata.st_mode),
    )


def _fresh24_secret_metadata_identity(path: Path) -> str:
    """Non-value continuity identity: inode/device/owner/mode/timestamps only.

    Never reads the key value, never derives any digest from its content, and
    never prints or returns value-derived material.
    """

    descriptor, before = _minimal_probe_open_secret(path)
    try:
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _minimal_probe_secret_signature(before) != _minimal_probe_secret_signature(after):
        raise PermissionError("FRESH24_SECRET_FILE_CHANGED_DURING_IDENTITY")
    return canonical_sha256(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "uid": before.st_uid,
            "nlink": before.st_nlink,
            "mode": stat.S_IMODE(before.st_mode),
        }
    )


def _minimal_probe_validate_secret_bytes(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError as error:
        raise PermissionError("NVIDIA_KEY secret file encoding is invalid") from error
    if "\n" in text or "\r" in text or "=" not in text:
        raise PermissionError("NVIDIA_KEY secret file must contain exactly one record")
    key, value = text.split("=", 1)
    if key != "NVIDIA_KEY" or not value:
        raise PermissionError("NVIDIA_KEY secret file record is invalid")
    return value


def _minimal_probe_secret_binding(path: Path) -> tuple[str, str]:
    """Return protected metadata and content continuity digests without disclosure."""

    descriptor, before = _minimal_probe_open_secret(path)
    try:
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != before.st_size or _minimal_probe_secret_signature(before) != (
        _minimal_probe_secret_signature(after)
    ):
        raise PermissionError("NVIDIA_KEY secret file changed during validation")
    value = _minimal_probe_validate_secret_bytes(raw)
    identity = canonical_sha256(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "uid": before.st_uid,
            "mode": stat.S_IMODE(before.st_mode),
        }
    )
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return identity, fingerprint


def _minimal_probe_secret_identity(path: Path) -> str:
    return _minimal_probe_secret_binding(path)[0]


def _read_minimal_probe_secret(
    path: Path,
    *,
    expected_identity_sha256: str,
    expected_content_fingerprint: str,
) -> str:
    """Verify and read through one pinned descriptor without a reopen window."""

    descriptor, before = _minimal_probe_open_secret(path)
    try:
        raw = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != before.st_size or _minimal_probe_secret_signature(before) != (
        _minimal_probe_secret_signature(after)
    ):
        raise PermissionError("NVIDIA_KEY secret file changed during read")
    value = _minimal_probe_validate_secret_bytes(raw)
    identity = canonical_sha256(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "uid": before.st_uid,
            "mode": stat.S_IMODE(before.st_mode),
        }
    )
    fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()
    if identity != expected_identity_sha256 or fingerprint != expected_content_fingerprint:
        raise PermissionError("NVIDIA_KEY secret continuity changed after approval")
    return value


def _validate_nvidia_secret_shape(path: Path) -> bool:
    _minimal_probe_secret_identity(path)
    return True


def _preflight_payload(
    *,
    allow_missing_secret: bool,
    secret_file: Path,
    artifact_root: Path,
) -> dict[str, object]:
    config = DemoProfileMaterializationConfig()
    pricing = PricingSnapshot()
    secret_present, _ = _read_local_secret(
        secret_file,
        allow_missing=allow_missing_secret,
    )
    live_sources = artifact_root / "source-bundles.json"
    live_sources_valid = False
    if live_sources.is_file():
        try:
            _load_live_source_bundles(live_sources)
            live_sources_valid = True
        except (OSError, ValidationError, ValueError):
            live_sources_valid = False
    return {
        "schema_version": "itda.phase5-profile-preflight.v1",
        "secret_present": secret_present,
        "model": PROFILE_MODEL,
        "endpoint": PROFILE_ENDPOINT,
        "source_count": len(_fixed_dev_place_ids()),
        "live_source_bundles_present": live_sources.is_file(),
        "live_source_bundles_valid": live_sources_valid,
        "split": "DEV_ONLY",
        "blind_excluded": True,
        "pricing_version": pricing.version,
        "pricing_source_sha256": pricing.pricing_snapshot_sha256,
        "uncached_input_rate_numerator": pricing.uncached_input_rate_numerator,
        "cached_input_rate_numerator": pricing.cached_input_rate_numerator,
        "output_rate_numerator": pricing.output_rate_numerator,
        "worst_case_input_tokens": pricing.worst_case_input_tokens,
        "max_tokens": config.max_tokens,
        "attempt_reservation_micro_usd": ATTEMPT_RESERVATION_MICRO_USD,
        "max_http_attempts": MAX_HTTP_ATTEMPTS,
        "max_run_cost_micro_usd": MAX_RUN_COST_MICRO_USD,
        "committed_cost_micro_usd": 0,
        "outstanding_cost_micro_usd": 0,
        "connect_seconds": config.connect_seconds,
        "pool_seconds": config.pool_seconds,
        "write_seconds": config.write_seconds,
        "read_seconds": config.read_seconds,
        "attempt_deadline_seconds": config.attempt_deadline_seconds,
        "rights_qualified_image_count": 0,
        "restricted_output_root": _SAFE_OUTPUT_ROOT,
        "network_attempted": False,
    }


def _rerun_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
) -> tuple[dict[str, object], DurableRerunJournal]:
    if authority_text != RERUN_AUTHORITY_TEXT:
        raise PermissionError("RERUN_AUTHORITY_TEXT_MISMATCH")
    if hashlib.sha256(authority_text.encode("utf-8")).hexdigest() != RERUN_AUTHORITY_SHA256:
        raise PermissionError("RERUN_AUTHORITY_DIGEST_MISMATCH")
    secret_present, _ = _read_local_secret(secret_file, allow_missing=False)
    if not secret_present:
        raise PermissionError("PROVIDER_SECRET_UNAVAILABLE")
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    blocker_bytes = _read_bounded_regular(PRIOR_BLOCKER, maximum_bytes=64 * 1024)
    blocker = json.loads(blocker_bytes)
    if (
        not isinstance(blocker, dict)
        or blocker.get("terminal_error") != "COST_BUDGET_EXHAUSTED"
        or blocker.get("committed_cost_micro_usd_lower_bound") != PRIOR_COMMITTED_LOWER_MICRO_USD
        or blocker.get("committed_cost_micro_usd_upper_bound") != PRIOR_COMMITTED_UPPER_MICRO_USD
        or blocker.get("retry_performed") is not False
    ):
        raise PermissionError("PRIOR_COST_AUTHORITY_DRIFT")
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    status = Phase5DemoReleaseStore().status()
    if status.get("state") != "NO_ACTIVE_SCORED_RELEASE":
        raise PermissionError("ACTIVE_RELEASE_ALREADY_EXISTS")
    worst_new_reservation = MAX_HTTP_ATTEMPTS * ATTEMPT_RESERVATION_MICRO_USD
    if (
        PRIOR_COMMITTED_UPPER_MICRO_USD + RERUN_COST_CAP_MICRO_USD != CUMULATIVE_RERUN_CAP_MICRO_USD
        or worst_new_reservation > RERUN_COST_CAP_MICRO_USD
    ):
        raise PermissionError("CUMULATIVE_BUDGET_ARITHMETIC_INVALID")
    fields: dict[str, object] = {
        "schema_version": "itda.phase5-zai-rerun-authority.v1",
        "authority_text": authority_text,
        "authority_sha256": RERUN_AUTHORITY_SHA256,
        "prior_blocker_sha256": hashlib.sha256(blocker_bytes).hexdigest(),
        "prior_committed_cost_lower_micro_usd": PRIOR_COMMITTED_LOWER_MICRO_USD,
        "prior_committed_cost_upper_micro_usd": PRIOR_COMMITTED_UPPER_MICRO_USD,
        "conservative_prior_carry_micro_usd": PRIOR_COMMITTED_UPPER_MICRO_USD,
        "new_run_cost_cap_micro_usd": RERUN_COST_CAP_MICRO_USD,
        "cumulative_reservation_cap_micro_usd": CUMULATIVE_RERUN_CAP_MICRO_USD,
        "new_http_attempt_cap": MAX_HTTP_ATTEMPTS,
        "worst_case_new_reservation_micro_usd": worst_new_reservation,
        "reservation_headroom_micro_usd": RERUN_COST_CAP_MICRO_USD - worst_new_reservation,
        "source_bundle_sha256": [bundle.source_bundle_sha256 for bundle in bundles],
        "source_inventory_sha256": canonical_sha256(
            [bundle.source_bundle_sha256 for bundle in bundles]
        ),
        "source_count": 24,
        "split": "DEV_ONLY",
        "blind_excluded": True,
        "active_release_state": "NO_ACTIVE_SCORED_RELEASE",
        **materialization_binding_payload(),
    }
    fields["receipt_sha256"] = canonical_sha256(fields)
    journal = DurableRerunJournal(
        root=artifact_root / "reruns" / RERUN_AUTHORITY_SHA256,
        authority_receipt=fields,
    )
    return fields, journal


def _coding_plan_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    if authority_text != CODING_PLAN_AUTHORITY_TEXT:
        raise PermissionError("CODING_PLAN_AUTHORITY_TEXT_MISMATCH")
    if hashlib.sha256(authority_text.encode("utf-8")).hexdigest() != (CODING_PLAN_AUTHORITY_SHA256):
        raise PermissionError("CODING_PLAN_AUTHORITY_DIGEST_MISMATCH")
    secret_present, _ = _read_local_secret(
        secret_file,
        allow_missing=allow_missing_secret,
    )
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    prior_hashes: dict[str, str] = {}
    for path, expected_sha256 in _PRIOR_PAYGO_HASHES.items():
        payload = _read_bounded_regular(path, maximum_bytes=64 * 1024 * 1024)
        observed_sha256 = hashlib.sha256(payload).hexdigest()
        if observed_sha256 != expected_sha256:
            raise PermissionError("PRIOR_PAYGO_EVIDENCE_DRIFT")
        prior_hashes[path.name] = observed_sha256
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    status = Phase5DemoReleaseStore().status()
    if status.get("state") != "NO_ACTIVE_SCORED_RELEASE":
        raise PermissionError("ACTIVE_RELEASE_ALREADY_EXISTS")
    config = CodingPlanProfileMaterializationConfig.for_authorized_base(
        base_url=CODING_PLAN_BASE_URL,
        entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )
    fields: dict[str, object] = {
        "schema_version": "itda.phase5-coding-plan-authority.v1",
        "authority_text": authority_text,
        "authority_sha256": CODING_PLAN_AUTHORITY_SHA256,
        "secret_present": secret_present,
        "provider_lane": config.provider_lane,
        "base_url": config.base_url,
        "endpoint": config.endpoint,
        "model": config.model,
        "accounting_mode": config.accounting_mode,
        "entitlement_evidence_sha256": config.entitlement_evidence_sha256,
        "entitlement_evidence_ref": CODING_PLAN_EVIDENCE_REF,
        "model_weight": config.model_weight,
        "new_http_attempt_cap": MAX_HTTP_ATTEMPTS,
        "subscription_attempt_count": 0,
        "subscription_total_weight": 0,
        "prior_paygo_cumulative_upper_micro_usd": (PRIOR_PAYGO_CUMULATIVE_UPPER_MICRO_USD),
        "prior_paygo_blocker_sha256": prior_hashes[PRIOR_BLOCKER.name],
        "prior_paygo_rerun_authority_sha256": prior_hashes[PRIOR_RERUN_AUTHORITY.name],
        "prior_paygo_rerun_terminal_sha256": prior_hashes[PRIOR_RERUN_TERMINAL.name],
        "prior_paygo_failure_sha256": prior_hashes[PRIOR_FAILURE.name],
        "prior_paygo_failure_attempts_sha256": prior_hashes[PRIOR_FAILURE_ATTEMPTS.name],
        "source_bundle_sha256": [bundle.source_bundle_sha256 for bundle in bundles],
        "source_inventory_sha256": canonical_sha256(
            [bundle.source_bundle_sha256 for bundle in bundles]
        ),
        "source_count": 24,
        "split": "DEV_ONLY",
        "blind_excluded": True,
        "active_release_state": "NO_ACTIVE_SCORED_RELEASE",
        "network_attempted": False,
        "config_sha256": canonical_sha256(config.model_dump(mode="json")),
    }
    fields["receipt_sha256"] = canonical_sha256(fields)
    return fields


def _nvidia_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    if authority_text != NVIDIA_AUTHORITY_TEXT:
        raise PermissionError("NVIDIA_AUTHORITY_TEXT_MISMATCH")
    if hashlib.sha256(authority_text.encode("utf-8")).hexdigest() != (NVIDIA_AUTHORITY_SHA256):
        raise PermissionError("NVIDIA_AUTHORITY_DIGEST_MISMATCH")
    secret_present, _ = _read_nvidia_secret(
        secret_file,
        allow_missing=allow_missing_secret,
    )
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    prior_hashes: dict[str, str] = {}
    for path, expected_sha256 in {
        **_PRIOR_PAYGO_HASHES,
        **_PRIOR_CODING_PLAN_HASHES,
    }.items():
        payload = _read_bounded_regular(path, maximum_bytes=64 * 1024 * 1024)
        observed_sha256 = hashlib.sha256(payload).hexdigest()
        if observed_sha256 != expected_sha256:
            raise PermissionError("PRIOR_ZAI_EVIDENCE_DRIFT")
        prior_hashes[path.relative_to(OUTPUT_ROOT.parent).as_posix()] = observed_sha256
    prior_nvidia_hashes: dict[str, str] = {}
    for path, expected_sha256 in _PRIOR_NVIDIA_HASHES.items():
        payload = _read_bounded_regular(path, maximum_bytes=64 * 1024 * 1024)
        observed_sha256 = hashlib.sha256(payload).hexdigest()
        if observed_sha256 != expected_sha256:
            raise PermissionError("PRIOR_NVIDIA_EVIDENCE_DRIFT")
        prior_nvidia_hashes[path.relative_to(OUTPUT_ROOT.parent).as_posix()] = observed_sha256
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    store = Phase5DemoReleaseStore()
    legacy_predecessor: dict[str, str] = {}
    try:
        status = store.status()
    except Phase5DemoReleaseError as error:
        if str(error) != "ACTIVE_POINTER_INVALID":
            raise
        legacy_predecessor = store.require_invalidated_legacy_predecessor()
        status = {"state": "INVALIDATED_LEGACY_PREDECESSOR"}
    if status.get("state") not in {
        "NO_ACTIVE_SCORED_RELEASE",
        "INVALIDATED_LEGACY_PREDECESSOR",
    }:
        raise PermissionError("ACTIVE_RELEASE_ALREADY_EXISTS")
    config = NvidiaMinimaxProfileMaterializationConfig()
    fields: dict[str, object] = {
        "schema_version": "itda.phase5-nvidia-authority.v3",
        "authority_text": authority_text,
        "authority_sha256": NVIDIA_AUTHORITY_SHA256,
        "secret_present": secret_present,
        "provider_lane": NVIDIA_PROVIDER_LANE,
        "endpoint": NVIDIA_PROFILE_ENDPOINT,
        "model": NVIDIA_PROFILE_MODEL,
        "temperature": config.temperature,
        "top_p": config.top_p,
        "top_p_policy": config.top_p_policy,
        "max_tokens": config.max_tokens,
        "stream": config.stream,
        "seed": config.seed,
        "thinking_mode": config.thinking_mode,
        "output_contract": config.output_contract,
        "json_start_sentinel": config.json_start_sentinel,
        "json_end_sentinel": config.json_end_sentinel,
        "bounded_json_max_bytes": config.bounded_json_max_bytes,
        "sentinel_policy": config.sentinel_policy,
        "prompt_injection_policy": config.prompt_injection_policy,
        "response_format_policy": config.response_format_policy,
        "temperature_rationale": config.temperature_rationale,
        "thinking_mode_rationale": config.thinking_mode_rationale,
        "output_contract_rationale": config.output_contract_rationale,
        "new_http_attempt_cap": config.max_http_attempts,
        "attempt_deadline_seconds": config.attempt_deadline_seconds,
        "source_bundle_sha256": [bundle.source_bundle_sha256 for bundle in bundles],
        "source_inventory_sha256": canonical_sha256(
            [bundle.source_bundle_sha256 for bundle in bundles]
        ),
        "source_count": 24,
        "split": "DEV_ONLY",
        "blind_excluded": True,
        "active_release_state": status["state"],
        **legacy_predecessor,
        "prior_zai_evidence_sha256": prior_hashes,
        "initial_nvidia_authority_sha256": NVIDIA_INITIAL_AUTHORITY_SHA256,
        "tool_nvidia_authority_sha256": NVIDIA_TOOL_AUTHORITY_SHA256,
        "prior_nvidia_evidence_sha256": prior_nvidia_hashes,
        "network_attempted": False,
        **materialization_binding_payload(config),
    }
    fields["receipt_sha256"] = canonical_sha256(fields)
    return fields


def _nvidia_resume_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    if (
        artifact_root
        / "nvidia-resume"
        / NVIDIA_RESUME_AUTHORITY_SHA256
        / "reconciliations"
        / NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256
    ).is_dir():
        raise PermissionError("NVIDIA_RESUME_AUTHORITY_SUPERSEDED")
    secret_present, _ = _read_nvidia_secret(
        secret_file,
        allow_missing=allow_missing_secret,
    )
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_nvidia_resume_plan(
        source_bundles=bundles,
        predecessor_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
        expected_predecessor_manifest_sha256=NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256,
    )
    fields = build_nvidia_resume_authority(
        authority_text=authority_text,
        source_bundles=bundles,
        plan=plan,
    )
    terminal = json.loads(
        _read_bounded_regular(
            artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256 / "terminal/terminal.json",
            maximum_bytes=1_048_576,
        )
    )
    recorded_at = datetime.fromisoformat(str(terminal["recorded_at"]).replace("Z", "+00:00"))
    cooldown_seconds = fields["default_cooldown_seconds"]
    if not isinstance(cooldown_seconds, int) or isinstance(cooldown_seconds, bool):
        raise PermissionError("NVIDIA_RESUME_COOLDOWN_POLICY_INVALID")
    cooldown_not_before = recorded_at + timedelta(seconds=cooldown_seconds)
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    status = Phase5DemoReleaseStore().status()
    if status.get("state") != "NO_ACTIVE_SCORED_RELEASE":
        raise PermissionError("ACTIVE_RELEASE_ALREADY_EXISTS")
    fields.update(
        {
            "secret_present": secret_present,
            "cooldown_not_before_utc": cooldown_not_before.astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "cooldown_satisfied": datetime.now(UTC) >= cooldown_not_before,
            "requires_explicit_future_authority": True,
            "future_live_command": (
                "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                "backend/.venv/bin/python -m itda.cli.materialize_phase5_demo_profiles "
                "nvidia-resume-live --json --authority-text "
                f"'{NVIDIA_RESUME_AUTHORITY_TEXT}'"
            ),
            "network_attempted": False,
        }
    )
    fields.pop("receipt_sha256", None)
    fields["receipt_sha256"] = canonical_sha256(fields)
    return fields


def _nvidia_second_resume_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    secret_present, _ = _read_nvidia_secret(secret_file, allow_missing=allow_missing_secret)
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_nvidia_second_resume_plan(
        source_bundles=bundles,
        predecessor_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
        resume_root=artifact_root / "nvidia-resume" / NVIDIA_RESUME_AUTHORITY_SHA256,
        expected_reconciliation_sha256=NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256,
    )
    fields = build_nvidia_second_resume_authority(
        authority_text=authority_text,
        source_bundles=bundles,
        plan=plan,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    status = Phase5DemoReleaseStore().status()
    if status.get("state") != "NO_ACTIVE_SCORED_RELEASE":
        raise PermissionError("ACTIVE_RELEASE_ALREADY_EXISTS")
    fields.update(
        {
            "secret_present": secret_present,
            "requires_explicit_future_authority": True,
            "future_live_command": (
                "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                "backend/.venv/bin/python -m itda.cli.materialize_phase5_demo_profiles "
                "nvidia-second-resume-live --json --authority-text "
                f"'{NVIDIA_SECOND_RESUME_AUTHORITY_TEXT}'"
            ),
            "network_attempted": False,
        }
    )
    fields.pop("receipt_sha256", None)
    fields["receipt_sha256"] = canonical_sha256(fields)
    return fields


def _nvidia_v4_probe_resume_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    secret_present, _ = _read_nvidia_secret(secret_file, allow_missing=allow_missing_secret)
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_nvidia_v4_probe_resume_plan(
        source_bundles=bundles,
        predecessor_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
        failure_root=artifact_root / "failures" / NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256,
        expected_predecessor_manifest_sha256=(NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256),
    )
    fields = build_nvidia_v4_probe_resume_authority(
        authority_text=authority_text,
        source_bundles=bundles,
        plan=plan,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    legacy = Phase5DemoReleaseStore().require_invalidated_legacy_predecessor()
    if (
        legacy.get("legacy_predecessor_release_sha256")
        != "59c3a6379e1e3de6ef67d95947d80f39d97c21bdcbf368d0080e5d8aa7224c50"
        or legacy.get("legacy_predecessor_receipt_sha256")
        != "ad7edaa8cb97569385f2601d52374565a683df4f84e1c8dd47e23ad72b901f00"
    ):
        raise PermissionError("NVIDIA_V4_PROBE_RESUME_LEGACY_PREDECESSOR_DRIFT")
    fields.update(
        {
            **legacy,
            "secret_present": secret_present,
            "requires_explicit_future_authority": True,
            "future_live_command": (
                "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                "backend/.venv/bin/python -m itda.cli.materialize_phase5_demo_profiles "
                "nvidia-v4-probe-resume-live --json --authority-text "
                f"'{NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT}' "
                "--secret-env-file .secrets/itda-api.env --artifact-root "
                "artifacts/restricted/catalog/phase5-demo-profile-materialization"
            ),
            "network_attempted": False,
        }
    )
    fields.pop("receipt_sha256", None)
    fields["receipt_sha256"] = canonical_sha256(fields)
    return fields


def _nvidia_v5_two_probe_resume_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    """Reconcile both consumed invalid probes without opening the network."""

    secret_present, _ = _read_nvidia_secret(secret_file, allow_missing=allow_missing_secret)
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_nvidia_v5_two_probe_resume_plan(
        source_bundles=bundles,
        attempt1_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
        attempt1_failure_root=(artifact_root / "failures" / NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256),
        attempt2_root=(artifact_root / "nvidia-resume" / NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256),
        attempt2_failure_root=(
            artifact_root
            / "failures"
            / "555d8aaccbaa0dcb49e506cf7f20d5d8608999cde2e37ae4fe118dc3db312e66"
        ),
    )
    fields = build_nvidia_v5_two_probe_resume_authority(
        authority_text=authority_text,
        source_bundles=bundles,
        plan=plan,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    legacy = Phase5DemoReleaseStore().require_invalidated_legacy_predecessor()
    if (
        legacy.get("legacy_predecessor_release_sha256")
        != "59c3a6379e1e3de6ef67d95947d80f39d97c21bdcbf368d0080e5d8aa7224c50"
        or legacy.get("legacy_predecessor_receipt_sha256")
        != "ad7edaa8cb97569385f2601d52374565a683df4f84e1c8dd47e23ad72b901f00"
    ):
        raise PermissionError("NVIDIA_V5_TWO_PROBE_RESUME_LEGACY_PREDECESSOR_DRIFT")
    fields.update(
        {
            **legacy,
            "secret_present": secret_present,
            "requires_explicit_future_authority": False,
            "future_live_command": (
                "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                "backend/.venv/bin/python -m itda.cli.materialize_phase5_demo_profiles "
                "nvidia-v5-two-probe-resume-live --json --authority-text "
                f"'{NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_TEXT}' "
                "--secret-env-file .secrets/itda-api.env --artifact-root "
                "artifacts/restricted/catalog/phase5-demo-profile-materialization"
            ),
            "network_attempted": False,
        }
    )
    fields.pop("receipt_sha256", None)
    fields["receipt_sha256"] = canonical_sha256(fields)
    if fields["authority_sha256"] != NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256:
        raise PermissionError("NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_DRIFT")
    return fields


def _nvidia_v5_three_validated_resume_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    """Reconcile exact attempts 1-6 and retained v5 profiles without network."""

    secret_present, _ = _read_nvidia_secret(secret_file, allow_missing=allow_missing_secret)
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_nvidia_v5_three_validated_resume_plan(
        source_bundles=bundles,
        predecessor_root=(
            artifact_root / "nvidia-resume" / NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256
        ),
        failure_root=(
            artifact_root
            / "failures"
            / cast(str, NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["failure_sha256"])
        ),
    )
    fields = build_nvidia_v5_three_validated_resume_authority(
        authority_text=authority_text,
        source_bundles=bundles,
        plan=plan,
    )
    active_pointer = artifact_root / "active/current.json"
    if hashlib.sha256(active_pointer.read_bytes()).hexdigest() != cast(
        str, NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["active_pointer_file_sha256"]
    ):
        raise PermissionError("NVIDIA_V5_THREE_VALIDATED_ACTIVE_POINTER_DRIFT")
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    legacy = Phase5DemoReleaseStore().require_invalidated_legacy_predecessor()
    fields.update(
        {
            **legacy,
            "secret_present": secret_present,
            "requires_explicit_future_authority": False,
            "future_live_command": (
                "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                "backend/.venv/bin/python -m itda.cli.materialize_phase5_demo_profiles "
                "nvidia-v5-three-validated-resume-live --json --authority-text "
                f"'{NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_TEXT}' "
                "--secret-env-file .secrets/itda-api.env --artifact-root "
                "artifacts/restricted/catalog/phase5-demo-profile-materialization"
            ),
            "network_attempted": False,
        }
    )
    fields.pop("receipt_sha256", None)
    fields["receipt_sha256"] = canonical_sha256(fields)
    if fields["authority_sha256"] != NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256:
        raise PermissionError("NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_DRIFT")
    return fields


def _nvidia_v5_attempt8_resume_authority_receipt(
    *,
    authority_text: str,
    secret_file: Path,
    artifact_root: Path,
    allow_missing_secret: bool,
) -> dict[str, object]:
    """Reconcile exact attempts 1-7 and retained v5 profiles without network."""

    secret_present, _ = _read_nvidia_secret(secret_file, allow_missing=allow_missing_secret)
    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_nvidia_v5_attempt8_resume_plan(
        source_bundles=bundles,
        base_predecessor_root=(
            artifact_root / "nvidia-resume" / NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256
        ),
        base_failure_root=(
            artifact_root
            / "failures"
            / cast(str, NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["failure_sha256"])
        ),
        predecessor_root=(
            artifact_root / "nvidia-resume" / NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256
        ),
        failure_root=(
            artifact_root
            / "failures"
            / cast(str, NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["failure_sha256"])
        ),
    )
    fields = build_nvidia_v5_attempt8_resume_authority(
        authority_text=authority_text,
        source_bundles=bundles,
        plan=plan,
    )
    active_pointer = artifact_root / "active/current.json"
    if hashlib.sha256(active_pointer.read_bytes()).hexdigest() != cast(
        str, NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["active_pointer_file_sha256"]
    ):
        raise PermissionError("NVIDIA_V5_ATTEMPT8_ACTIVE_POINTER_DRIFT")
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    legacy = Phase5DemoReleaseStore().require_invalidated_legacy_predecessor()
    fields.update(
        {
            **legacy,
            "secret_present": secret_present,
            "requires_explicit_future_authority": False,
            "future_live_command": (
                "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                "backend/.venv/bin/python -m itda.cli.materialize_phase5_demo_profiles "
                "nvidia-v5-attempt8-resume-live --json --authority-text "
                f"'{NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_TEXT}' "
                "--secret-env-file .secrets/itda-api.env --artifact-root "
                "artifacts/restricted/catalog/phase5-demo-profile-materialization"
            ),
            "network_attempted": False,
        }
    )
    fields.pop("receipt_sha256", None)
    fields["receipt_sha256"] = canonical_sha256(fields)
    if fields["authority_sha256"] != NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256:
        raise PermissionError("NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_DRIFT")
    return fields


_ATTEMPT5_RETAINING_IMPLEMENTATION_PATHS = (
    "backend/src/itda",
    "backend/migrations",
    "backend/schema",
    "backend/pyproject.toml",
    "backend/uv.lock",
    "contracts/openapi.json",
    ".python-version",
    "mise.toml",
)


def _repository_identity() -> tuple[str, str]:
    """Return the exact committed implementation identity without network access."""

    def rev_parse(revision: str) -> str:
        completed = subprocess.run(
            ["git", "rev-parse", revision],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        value = completed.stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40,64}", value) is None:
            raise PermissionError("repository identity is invalid")
        return value

    implementation_status = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            *_ATTEMPT5_RETAINING_IMPLEMENTATION_PATHS,
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if implementation_status.returncode != 0 or implementation_status.stdout:
        raise PermissionError("attempt-5-retaining implementation scope is dirty")
    return rev_parse("HEAD"), rev_parse("HEAD^{tree}")


def _attempt5_retaining_cli_context(
    *,
    authority_text: str,
    authority_sha256: str,
    artifact_root: Path,
) -> tuple[
    tuple[DemoSourceBundle, ...],
    Attempt5RetainingPlan,
    Attempt5RetainingAuthority,
]:
    """Build the official local preflight context without reading a secret."""

    bundles = _load_live_source_bundles(artifact_root / "source-bundles.json")
    plan = build_attempt5_retaining_plan(
        source_bundles=bundles,
        predecessor_root=(
            artifact_root / "nvidia-resume" / NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256
        ),
        failure_root=(
            artifact_root
            / "failures"
            / "d7f373f45036728e02f1f16526b893b2e8bf1d02daf27b835500a0f928fc0db7"
        ),
        active_pointer_path=artifact_root / "active/current.json",
    )
    implementation_commit, implementation_tree = _repository_identity()
    authority = derive_attempt5_retaining_authority(
        source_bundles=bundles,
        plan=plan,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
    )
    preflight_attempt5_retaining_authority(
        authority_text=authority_text,
        authority_sha256=authority_sha256,
        source_bundles=bundles,
        plan=plan,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
    )
    return bundles, plan, authority


def _installed_attempt5_execution_approval(
    *,
    authority: Attempt5RetainingAuthority,
    approval_text: str,
    approval_sha256: str,
    artifact_root: Path,
) -> tuple[Mapping[str, object], str]:
    """Require the post-checkpoint private decision-root install; absent means deny."""

    decision_path = (
        artifact_root
        / "execution-approvals"
        / authority.authority_sha256
        / "trusted-decision-record.sha256"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            decision_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size != 64
        ):
            raise PermissionError("trusted execution decision root is not private and exact")
        trusted_decision_record_sha256 = os.read(descriptor, 65).decode("ascii")
    except (OSError, UnicodeError) as error:
        raise PermissionError("trusted execution decision root is not installed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if re.fullmatch(r"[0-9a-f]{64}", trusted_decision_record_sha256) is None:
        raise PermissionError("trusted execution decision root is invalid")
    receipt = preflight_attempt5_retaining_execution_approval(
        authority=authority,
        approval_text=approval_text,
        approval_sha256=approval_sha256,
        trusted_decision_record_sha256=trusted_decision_record_sha256,
    )
    return receipt, trusted_decision_record_sha256


def _safe_receipt_payload(receipt: object) -> dict[str, object]:
    dumped = cast(Any, receipt).model_dump(mode="json")
    if isinstance(receipt, NvidiaMinimaxProfileMaterializationReceipt):
        return {
            "schema_version": dumped["schema_version"],
            "status": dumped["status"],
            "analysis_origin": dumped["analysis_origin"],
            "profile_count": dumped["profile_count"],
            "profile_inventory_sha256": canonical_sha256(dumped["profile_sha256"]),
            "attempt_inventory_sha256": canonical_sha256(dumped["attempt_sha256"]),
            "provider_lane": dumped["provider_lane"],
            "endpoint": dumped["endpoint"],
            "model": dumped["model"],
            "config_sha256": dumped["config_sha256"],
            "authority_sha256": dumped["authority_sha256"],
            "resume_authority_sha256": dumped["resume_authority_sha256"],
            "predecessor_manifest_sha256": dumped["predecessor_manifest_sha256"],
            "validated_predecessor_count": dumped["validated_predecessor_count"],
            "remaining_member_count": dumped["remaining_member_count"],
            "validated_membership_sha256": dumped["validated_membership_sha256"],
            "remaining_membership_sha256": dumped["remaining_membership_sha256"],
            "http_attempt_count": dumped["http_attempt_count"],
            "generation_sha256": dumped["generation_sha256"],
            "receipt_sha256": dumped["receipt_sha256"],
            "release_eligible": False,
            "network_attempted": False,
        }
    if isinstance(receipt, CodingPlanProfileMaterializationReceipt):
        return {
            "schema_version": dumped["schema_version"],
            "status": dumped["status"],
            "analysis_origin": dumped["analysis_origin"],
            "profile_count": dumped["profile_count"],
            "profile_inventory_sha256": canonical_sha256(dumped["profile_sha256"]),
            "attempt_inventory_sha256": canonical_sha256(dumped["attempt_sha256"]),
            "provider_lane": dumped["provider_lane"],
            "endpoint": dumped["endpoint"],
            "model": dumped["model"],
            "accounting_mode": dumped["accounting_mode"],
            "model_weight": dumped["model_weight"],
            "subscription_attempt_count": dumped["subscription_attempt_count"],
            "subscription_total_weight": dumped["subscription_total_weight"],
            "generation_sha256": dumped["generation_sha256"],
            "receipt_sha256": dumped["receipt_sha256"],
            "release_eligible": False,
            "network_attempted": False,
        }
    return {
        "schema_version": dumped["schema_version"],
        "status": dumped["status"],
        "analysis_origin": dumped["analysis_origin"],
        "profile_count": dumped["profile_count"],
        "profile_inventory_sha256": canonical_sha256(dumped["profile_sha256"]),
        "attempt_inventory_sha256": canonical_sha256(dumped["attempt_sha256"]),
        "pricing_snapshot_sha256": dumped["pricing_snapshot_sha256"],
        "committed_cost_micro_usd": dumped["committed_cost_micro_usd"],
        "outstanding_cost_micro_usd": dumped["outstanding_cost_micro_usd"],
        "generation_sha256": dumped["generation_sha256"],
        "receipt_sha256": dumped["receipt_sha256"],
        "release_eligible": False,
        "network_attempted": False,
    }


def _terminalize_attempt8_local_rejection(
    *,
    journal: DurableRerunJournal | DurableCodingPlanJournal | DurableNvidiaJournal | None,
    adapter: ZhipuGlm5vProfileAdapter | NvidiaMinimaxProfileAdapter | None,
) -> None:
    """Persist terminal evidence when exact attempt-8 authority was already claimed."""

    if not isinstance(journal, DurableNvidiaJournal):
        return
    try:
        journal.require_live_started()
    except (DemoProfileMaterializationError, OSError, PermissionError, ValueError):
        return
    if (journal.root / "terminal").exists():
        return
    attempt_count = (
        adapter.ledger.attempt_count if isinstance(adapter, NvidiaMinimaxProfileAdapter) else 7
    )
    journal.record_terminal(
        failure_code="LOCAL_STATE_REJECTED",
        failed_place_id="PRE_SOCKET_OR_UNKNOWN",
        attempt_count=attempt_count,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--json", action="store_true")
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--json", action="store_true")
    preflight.add_argument("--allow-missing-secret", action="store_true")
    preflight.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    preflight.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    live = commands.add_parser("live")
    live.add_argument("--json", action="store_true")
    live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    live.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    for name in ("rerun-preflight", "rerun-live"):
        rerun = commands.add_parser(name)
        rerun.add_argument("--json", action="store_true")
        rerun.add_argument("--authority-text", required=True)
        rerun.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
        rerun.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    coding_preflight = commands.add_parser("coding-plan-preflight")
    coding_preflight.add_argument("--json", action="store_true")
    coding_preflight.add_argument("--allow-missing-secret", action="store_true")
    coding_preflight.add_argument("--authority-text", required=True)
    coding_preflight.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    coding_preflight.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    coding_live = commands.add_parser("coding-plan-live")
    coding_live.add_argument("--json", action="store_true")
    coding_live.add_argument("--authority-text", required=True)
    coding_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    coding_live.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    nvidia_preflight = commands.add_parser("nvidia-preflight")
    nvidia_preflight.add_argument("--json", action="store_true")
    nvidia_preflight.add_argument("--allow-missing-secret", action="store_true")
    nvidia_preflight.add_argument("--authority-text", required=True)
    nvidia_preflight.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_preflight.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    nvidia_live = commands.add_parser("nvidia-live")
    nvidia_live.add_argument("--json", action="store_true")
    nvidia_live.add_argument("--authority-text", required=True)
    nvidia_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_live.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    nvidia_resume_preflight = commands.add_parser("nvidia-resume-preflight")
    nvidia_resume_preflight.add_argument("--json", action="store_true")
    nvidia_resume_preflight.add_argument("--allow-missing-secret", action="store_true")
    nvidia_resume_preflight.add_argument("--authority-text", required=True)
    nvidia_resume_preflight.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_resume_preflight.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    nvidia_resume_live = commands.add_parser("nvidia-resume-live")
    nvidia_resume_live.add_argument("--json", action="store_true")
    nvidia_resume_live.add_argument("--authority-text", required=True)
    nvidia_resume_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_resume_live.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    nvidia_second_resume_preflight = commands.add_parser("nvidia-second-resume-preflight")
    nvidia_second_resume_preflight.add_argument("--json", action="store_true")
    nvidia_second_resume_preflight.add_argument("--allow-missing-secret", action="store_true")
    nvidia_second_resume_preflight.add_argument("--authority-text", required=True)
    nvidia_second_resume_preflight.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_second_resume_preflight.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_second_resume_live = commands.add_parser("nvidia-second-resume-live")
    nvidia_second_resume_live.add_argument("--json", action="store_true")
    nvidia_second_resume_live.add_argument("--authority-text", required=True)
    nvidia_second_resume_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_second_resume_live.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    nvidia_v4_probe_resume_preflight = commands.add_parser("nvidia-v4-probe-resume-preflight")
    nvidia_v4_probe_resume_preflight.add_argument("--json", action="store_true")
    nvidia_v4_probe_resume_preflight.add_argument("--allow-missing-secret", action="store_true")
    nvidia_v4_probe_resume_preflight.add_argument("--authority-text", required=True)
    nvidia_v4_probe_resume_preflight.add_argument(
        "--secret-env-file", type=Path, default=SECRET_FILE
    )
    nvidia_v4_probe_resume_preflight.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v4_probe_resume_live = commands.add_parser("nvidia-v4-probe-resume-live")
    nvidia_v4_probe_resume_live.add_argument("--json", action="store_true")
    nvidia_v4_probe_resume_live.add_argument("--authority-text", required=True)
    nvidia_v4_probe_resume_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_v4_probe_resume_live.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v5_two_probe_resume_preflight = commands.add_parser(
        "nvidia-v5-two-probe-resume-preflight"
    )
    nvidia_v5_two_probe_resume_preflight.add_argument("--json", action="store_true")
    nvidia_v5_two_probe_resume_preflight.add_argument("--allow-missing-secret", action="store_true")
    nvidia_v5_two_probe_resume_preflight.add_argument("--authority-text", required=True)
    nvidia_v5_two_probe_resume_preflight.add_argument(
        "--secret-env-file", type=Path, default=SECRET_FILE
    )
    nvidia_v5_two_probe_resume_preflight.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v5_two_probe_resume_live = commands.add_parser("nvidia-v5-two-probe-resume-live")
    nvidia_v5_two_probe_resume_live.add_argument("--json", action="store_true")
    nvidia_v5_two_probe_resume_live.add_argument("--authority-text", required=True)
    nvidia_v5_two_probe_resume_live.add_argument(
        "--secret-env-file", type=Path, default=SECRET_FILE
    )
    nvidia_v5_two_probe_resume_live.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v5_three_validated_resume_preflight = commands.add_parser(
        "nvidia-v5-three-validated-resume-preflight"
    )
    nvidia_v5_three_validated_resume_preflight.add_argument("--json", action="store_true")
    nvidia_v5_three_validated_resume_preflight.add_argument(
        "--allow-missing-secret", action="store_true"
    )
    nvidia_v5_three_validated_resume_preflight.add_argument("--authority-text", required=True)
    nvidia_v5_three_validated_resume_preflight.add_argument(
        "--secret-env-file", type=Path, default=SECRET_FILE
    )
    nvidia_v5_three_validated_resume_preflight.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v5_three_validated_resume_live = commands.add_parser(
        "nvidia-v5-three-validated-resume-live"
    )
    nvidia_v5_three_validated_resume_live.add_argument("--json", action="store_true")
    nvidia_v5_three_validated_resume_live.add_argument("--authority-text", required=True)
    nvidia_v5_three_validated_resume_live.add_argument(
        "--secret-env-file", type=Path, default=SECRET_FILE
    )
    nvidia_v5_three_validated_resume_live.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v5_attempt8_resume_preflight = commands.add_parser("nvidia-v5-attempt8-resume-preflight")
    nvidia_v5_attempt8_resume_preflight.add_argument("--json", action="store_true")
    nvidia_v5_attempt8_resume_preflight.add_argument("--allow-missing-secret", action="store_true")
    nvidia_v5_attempt8_resume_preflight.add_argument("--authority-text", required=True)
    nvidia_v5_attempt8_resume_preflight.add_argument(
        "--secret-env-file", type=Path, default=SECRET_FILE
    )
    nvidia_v5_attempt8_resume_preflight.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    nvidia_v5_attempt8_resume_live = commands.add_parser("nvidia-v5-attempt8-resume-live")
    nvidia_v5_attempt8_resume_live.add_argument("--json", action="store_true")
    nvidia_v5_attempt8_resume_live.add_argument("--authority-text", required=True)
    nvidia_v5_attempt8_resume_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    nvidia_v5_attempt8_resume_live.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    attempt5_retaining_preflight = commands.add_parser("nvidia-v5-attempt5-retaining-preflight")
    attempt5_retaining_preflight.add_argument("--json", action="store_true")
    attempt5_retaining_preflight.add_argument("--authority-text", required=True)
    attempt5_retaining_preflight.add_argument("--authority-sha256", required=True)
    attempt5_retaining_preflight.add_argument(
        "--artifact-root", type=Path, default=OUTPUT_ROOT.parent
    )
    attempt5_retaining_live = commands.add_parser("nvidia-v5-attempt5-retaining-live")
    attempt5_retaining_live.add_argument("--json", action="store_true")
    attempt5_retaining_live.add_argument("--authority-text", required=True)
    attempt5_retaining_live.add_argument("--authority-sha256", required=True)
    attempt5_retaining_live.add_argument("--execution-approval-text", required=True)
    attempt5_retaining_live.add_argument("--execution-approval-sha256", required=True)
    attempt5_retaining_live.add_argument("--secret-env-file", type=Path, default=SECRET_FILE)
    attempt5_retaining_live.add_argument("--artifact-root", type=Path, default=OUTPUT_ROOT.parent)
    fresh_preflight = commands.add_parser("nvidia-fresh-cohort-preflight")
    fresh_preflight.add_argument("--json", action="store_true")
    fresh_preflight.add_argument("--authority-id", required=True)
    fresh_preflight.add_argument("--request-output", type=Path, required=True)
    fresh_install = commands.add_parser("nvidia-fresh-cohort-install-approval")
    fresh_install.add_argument("--json", action="store_true")
    fresh_install.add_argument("--request", type=Path, required=True)
    fresh_install.add_argument("--authority-id", required=True)
    fresh_install.add_argument("--protected-state-root", type=Path, required=True)
    fresh_install.add_argument("--approval-payload-sha256", required=True)
    fresh_live = commands.add_parser("nvidia-fresh-cohort-live")
    fresh_live.add_argument("--json", action="store_true")
    fresh_live.add_argument("--request", type=Path, required=True)
    fresh_live.add_argument("--authority-id", required=True)
    fresh_live.add_argument("--protected-state-root", type=Path, required=True)
    fresh_live.add_argument("--secret-env-file", type=Path, required=True)
    fresh_live.add_argument("--terminal-output", type=Path, required=True)
    fresh_smoke = commands.add_parser("nvidia-fresh-cohort-activate-and-smoke")
    fresh_smoke.add_argument("--json", action="store_true")
    fresh_smoke.add_argument("--authority-id", required=True)
    fresh_smoke.add_argument("--terminal", type=Path, required=True)
    fresh_smoke.add_argument("--require-active-member-count", type=int, required=True)
    fresh_smoke.add_argument("--require-minimum-eligible", type=int, required=True)
    fresh_smoke.add_argument("--require-two-preference-rank-change", action="store_true")
    recovery_preflight = commands.add_parser("nvidia-recovery-preflight")
    recovery_preflight.add_argument("--request-output", type=Path, required=True)
    recovery_preflight.add_argument("--require-committed-clean-source", action="store_true")
    recovery_preflight.add_argument("--regenerate", action="store_true")
    recovery_preflight.add_argument("--json", action="store_true")
    probe_install = commands.add_parser("nvidia-minimal-probe-install-approval")
    probe_install.add_argument("--request", type=Path, required=True)
    probe_install.add_argument("--protected-state-root", type=Path, required=True)
    probe_install.add_argument("--secret-env-file", type=Path, required=True)
    probe_install.add_argument("--approval-payload-sha256", required=True)
    probe_install.add_argument("--json", action="store_true")
    probe_reconcile = commands.add_parser("nvidia-minimal-probe-reconcile")
    probe_reconcile.add_argument("--request", type=Path, required=True)
    probe_reconcile.add_argument("--protected-state-root", type=Path, required=True)
    probe_reconcile.add_argument("--terminal-output", type=Path, required=True)
    probe_reconcile.add_argument("--json", action="store_true")
    probe_verify = commands.add_parser("nvidia-minimal-probe-verify")
    probe_verify.add_argument("--terminal", type=Path, required=True)
    probe_verify.add_argument("--request", type=Path)
    probe_verify.add_argument("--raw-response", type=Path)
    probe_verify.add_argument("--require-positive", action="store_true")
    probe_verify.add_argument("--json", action="store_true")
    probe_classify = commands.add_parser("nvidia-minimal-probe-classify")
    probe_classify.add_argument("--terminal", type=Path, required=True)
    probe_classify.add_argument("--request", type=Path)
    probe_classify.add_argument("--raw-response", type=Path)
    probe_classify.add_argument("--value-only", action="store_true")
    probe_classify.add_argument("--json", action="store_true")
    probe_live = commands.add_parser("nvidia-minimal-probe-live")
    probe_live.add_argument("--request", type=Path, required=True)
    probe_live.add_argument("--protected-state-root", type=Path, required=True)
    probe_live.add_argument("--secret-env-file", type=Path, required=True)
    probe_live.add_argument("--terminal-output", type=Path, required=True)
    probe_live.add_argument("--json", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--generation", type=Path, required=True)
    verify.add_argument("--json", action="store_true")
    fresh24_preflight = commands.add_parser("nvidia-fresh24-preflight")
    fresh24_preflight.add_argument("--probe-terminal", type=Path, required=True)
    fresh24_preflight.add_argument("--request-output", type=Path, required=True)
    fresh24_preflight.add_argument("--require-committed-clean-source", action="store_true")
    fresh24_preflight.add_argument("--json", action="store_true")
    # NOTE: the fresh24 capability subcommands (install-approval / live /
    # reconcile) are deliberately NOT registered here.  The public parser and
    # ``main`` can never dispatch them; only the bootstrap's internal
    # dispatcher (see ``_fresh24_capability_dispatch``) parses and runs them,
    # and that dispatcher is reachable exclusively through the validated
    # stdlib bootstrap entrypoint.
    fresh24_verify = commands.add_parser("nvidia-fresh24-verify")
    fresh24_verify.add_argument("--terminal", type=Path, required=True)
    fresh24_verify.add_argument(
        "--protected-state-root",
        type=Path,
        default=phase5_fresh24.FRESH24_PROTECTED_ROOT_RELATIVE,
    )
    fresh24_verify.add_argument("--require-positive", action="store_true")
    fresh24_verify.add_argument("--json", action="store_true")
    fresh24_classify = commands.add_parser("nvidia-fresh24-classify")
    fresh24_classify.add_argument("--terminal", type=Path, required=True)
    fresh24_classify.add_argument("--value-only", action="store_true")
    fresh24_classify.add_argument("--json", action="store_true")
    # OpenRouter recovery provider-free commands.  The capability subcommands
    # (install-approval / live / reconcile) are NOT registered here — only the
    # sanitized bootstrap dispatcher (``_openrouter_recovery_capability_dispatch``)
    # can reach them.
    openrouter_preflight = commands.add_parser("openrouter-recovery-preflight")
    openrouter_preflight.add_argument("--request", type=Path, required=True)
    openrouter_preflight.add_argument(
        "--require-committed-clean-source", action="store_true"
    )
    openrouter_preflight.add_argument("--verify-only", action="store_true")
    openrouter_preflight.add_argument("--json", action="store_true")
    openrouter_verify = commands.add_parser("openrouter-recovery-verify")
    openrouter_verify.add_argument("--terminal", type=Path, required=True)
    openrouter_verify.add_argument(
        "--protected-state-root",
        type=Path,
        default=phase5_openrouter_recovery.OPENROUTER_PROTECTED_ROOT_RELATIVE,
    )
    openrouter_verify.add_argument("--require-positive", action="store_true")
    openrouter_verify.add_argument("--json", action="store_true")
    openrouter_classify = commands.add_parser("openrouter-recovery-classify")
    openrouter_classify.add_argument("--terminal", type=Path, required=True)
    openrouter_classify.add_argument("--value-only", action="store_true")
    openrouter_classify.add_argument("--json", action="store_true")
    openrouter_v2_preflight = commands.add_parser("openrouter-recovery-v2-preflight")
    openrouter_v2_preflight.add_argument("--request", type=Path, required=True)
    openrouter_v2_preflight.add_argument(
        "--require-committed-clean-source", action="store_true"
    )
    openrouter_v2_preflight.add_argument("--verify-only", action="store_true")
    openrouter_v2_preflight.add_argument("--json", action="store_true")
    return parser


def _print_payload(payload: dict[str, object], *, json_output: bool) -> None:
    if json_output:
        sys.stdout.buffer.write(canonical_json_bytes(payload) + b"\n")
    else:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))


def _require_fixed_cli_paths(*, secret_file: Path, artifact_root: Path) -> tuple[Path, Path]:
    resolved_secret = (REPOSITORY_ROOT / secret_file).resolve(strict=False)
    resolved_artifact = (REPOSITORY_ROOT / artifact_root).resolve(strict=False)
    if resolved_secret != SECRET_FILE or resolved_artifact != OUTPUT_ROOT.parent:
        raise PermissionError("caller-selected secret or artifact root is forbidden")
    return resolved_secret, resolved_artifact


def _require_fixed_artifact_root(artifact_root: Path) -> Path:
    resolved_artifact = (REPOSITORY_ROOT / artifact_root).resolve(strict=False)
    if resolved_artifact != OUTPUT_ROOT.parent:
        raise PermissionError("caller-selected artifact root is forbidden")
    return resolved_artifact


def _require_fresh_public_request_output(path: Path) -> Path:
    resolved = (REPOSITORY_ROOT / path).resolve(strict=False)
    if resolved != FRESH_PUBLIC_REQUEST_OUTPUT:
        raise PermissionError("caller-selected fresh public request output is forbidden")
    return resolved


def _require_fresh_protected_state_root(path: Path) -> Path:
    resolved = (REPOSITORY_ROOT / path).resolve(strict=False)
    if resolved != FRESH_PROTECTED_STATE_ROOT:
        raise PermissionError("caller-selected fresh protected state root is forbidden")
    return resolved


def _require_fresh_terminal_output(path: Path) -> Path:
    resolved = (REPOSITORY_ROOT / path).resolve(strict=False)
    if resolved != FRESH_TERMINAL_OUTPUT:
        raise PermissionError("caller-selected fresh terminal output is forbidden")
    return resolved


def _require_fresh_secret_file(path: Path) -> Path:
    resolved = (REPOSITORY_ROOT / path).resolve(strict=False)
    if resolved != SECRET_FILE:
        raise PermissionError("caller-selected fresh secret file is forbidden")
    return resolved


def _fresh_cli_context(
    *,
    request: Path,
    authority_id: str,
    protected_state_root: Path,
) -> tuple[
    FreshCohortPlan,
    FreshProtectedStateResolver,
    dict[str, Any],
    str,
    str,
]:
    request_path = _require_fresh_public_request_output(request)
    state_root = _require_fresh_protected_state_root(protected_state_root)
    if authority_id != FRESH_AUTHORITY_ID:
        raise PermissionError("FRESH_AUTHORITY_ID_MISMATCH")
    source_bundles = _load_live_source_bundles(FIXED_LIVE_SOURCE_BUNDLES)
    plan = build_fresh_cohort_plan(
        source_bundles,
        checkout_manifest=checkout_manifest_sha256(REPOSITORY_ROOT),
    )
    artifact = _load_json(request_path, maximum_bytes=2 * 1024 * 1024)
    request_digest, approval_digest, active_state = (
        validate_fresh_public_approval_artifact(
            plan=plan,
            artifact=artifact,
            approved_payload_sha256=artifact.get("approval_payload_sha256"),
        )
    )
    if active_state != _fresh_active_release_state():
        raise PermissionError("FRESH_ACTIVE_RELEASE_STATE_MISMATCH")
    resolver = FreshProtectedStateResolver(protected_state_root=state_root)
    return plan, resolver, artifact, request_digest, approval_digest


def _fresh_live_preflight_context(
    *,
    request: Path,
    authority_id: str,
    protected_state_root: Path,
    terminal_output: Path,
) -> tuple[FreshCohortPlan, FreshDurableAuthorityState, dict[str, object]]:
    _require_fresh_terminal_output(terminal_output)
    try:
        plan, resolver, _artifact, request_digest, approval_digest = _fresh_cli_context(
            request=request,
            authority_id=authority_id,
            protected_state_root=protected_state_root,
        )
        state = FreshDurableAuthorityState(
            plan=plan,
            descriptor=resolver.resolve(authority_id),
        )
        try:
            status = state.preflight(
                expected_request_artifact_sha256=request_digest,
                expected_approval_payload_sha256=approval_digest,
            )
        except PermissionError as error:
            if str(error) != "FRESH_AUTHORITY_ALREADY_CLAIMED":
                raise
            status, _claim = state.claimed_preflight(
                expected_request_artifact_sha256=request_digest,
                expected_approval_payload_sha256=approval_digest,
            )
            status["reconciliation_required"] = True
    except (FileExistsError, OSError, PermissionError, ValidationError, ValueError) as error:
        raise PermissionError("FRESH_PROVIDER_EXECUTION_APPROVAL_REQUIRED") from error
    return plan, state, status


def _fresh_active_release_state() -> str:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    try:
        state = Phase5DemoReleaseStore().status().get("state")
    except Phase5DemoReleaseError as error:
        if str(error) != "ACTIVE_POINTER_INVALID":
            raise
        state = "INVALIDATED_LEGACY_PREDECESSOR"
    if state not in {"NO_ACTIVE_SCORED_RELEASE", "INVALIDATED_LEGACY_PREDECESSOR"}:
        raise PermissionError("ACTIVE_RELEASE_ALREADY_EXISTS")
    return str(state)


def _fresh_preflight_payload(*, authority_id: str, request_output: Path) -> dict[str, object]:
    if authority_id != FRESH_AUTHORITY_ID:
        raise PermissionError("FRESH_AUTHORITY_ID_MISMATCH")
    source_bundles = _load_live_source_bundles(FIXED_LIVE_SOURCE_BUNDLES)
    plan = build_fresh_cohort_plan(
        source_bundles,
        checkout_manifest=checkout_manifest_sha256(REPOSITORY_ROOT),
    )
    active_state = _fresh_active_release_state()
    approval_payload = {
        "authority_id": plan.authority_id,
        "public_request_sha256": plan.public_request.public_request_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "endpoint": plan.public_request.endpoint,
        "model": FRESH_MODEL,
        "provider_lane": FRESH_PROVIDER_LANE,
        "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
        "reservation_micro_usd": FRESH_RESERVATION_MICRO_USD,
        "max_new_http_attempts": FRESH_MAX_HTTP_ATTEMPTS,
        "attempt_deadline_seconds": FRESH_ATTEMPT_DEADLINE_SECONDS,
        "price_status": "UNKNOWN",
        "invocation_policy": "SINGLE_INVOCATION",
        "confidence_threshold": FRESH_CONFIDENCE_THRESHOLD,
        "minimum_eligible_profiles": FRESH_MIN_ELIGIBLE_PROFILES,
        "active_release_state": active_state,
        "blind_access": False,
    }
    payload: dict[str, object] = {
        "schema_version": "itda.phase5-fresh-provider-materialization-request.v1",
        **safe_public_request_payload(plan),
        "source_count": len(plan.source_bundles),
        "dev_member_count": len(plan.source_bundles),
        "dev_membership_order_sha256": plan.membership_sha256,
        "active_release_state": active_state,
        "active_release_state_sha256": canonical_sha256({"state": active_state}),
        "implementation_commit": _git_head_sha256(),
        "approval_payload_sha256": canonical_sha256(approval_payload),
        "approval_sentence": (
            "Approve one fresh NVIDIA MiniMax-M3 DEV-24 invocation with at most "
            "30 new attempts and a cumulative exposure cap of 15,000,000 micro-USD "
            "(500,000 micro-USD reserved per attempt); price status remains UNKNOWN."
        ),
        "secret_read": False,
        "provider_client_constructed": False,
        "network_attempted": False,
    }
    artifact_digest = canonical_sha256(payload)
    payload["request_artifact_sha256"] = artifact_digest
    request_output.parent.mkdir(parents=True, exist_ok=True)
    serialized = canonical_json_bytes(payload)
    if request_output.exists():
        if request_output.read_bytes() != serialized:
            raise FileExistsError("fresh public request output already contains different bytes")
    else:
        request_output.write_bytes(serialized)
    return payload


def _fixed_lexical_path(path: Path, *, expected: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if candidate != expected or any(part in {"", ".", ".."} for part in candidate.parts[1:]):
        raise PermissionError(f"caller-selected minimal probe {label} is forbidden")
    return candidate


def _minimal_probe_request_output(path: Path) -> Path:
    return _fixed_lexical_path(
        path,
        expected=REPOSITORY_ROOT / "artifacts/public/phase5/nvidia-minimal-probe-request.json",
        label="request output",
    )


def _minimal_probe_terminal_output(path: Path) -> Path:
    return _fixed_lexical_path(
        path,
        expected=REPOSITORY_ROOT / "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json",
        label="terminal output",
    )


def _minimal_probe_protected_state_root(path: Path) -> Path:
    return _fixed_lexical_path(
        path,
        expected=(
            REPOSITORY_ROOT / "artifacts/restricted/catalog/phase5-nvidia-minimal-probe"
        ),
        label="protected root",
    )


def _minimal_probe_secret_file(path: Path) -> Path:
    return _fixed_lexical_path(path, expected=SECRET_FILE, label="secret file")


FRESH24_PROTECTED_ROOT = REPOSITORY_ROOT / phase5_fresh24.FRESH24_PROTECTED_ROOT_RELATIVE


def _fresh24_request_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if (
        candidate != phase5_fresh24.FRESH24_REQUEST_OUTPUT
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise PermissionError("caller-selected fresh24 request is forbidden")
    return candidate


def _fresh24_protected_root(path: Path) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if (
        candidate != FRESH24_PROTECTED_ROOT
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise PermissionError("caller-selected fresh24 protected root is forbidden")
    return candidate


def _fresh24_terminal_output(path: Path) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if (
        candidate != phase5_fresh24.FRESH24_TERMINAL_OUTPUT
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise PermissionError("caller-selected fresh24 terminal output is forbidden")
    return candidate


def _fresh24_secret_file(path: Path) -> Path:
    return _fixed_lexical_path(path, expected=SECRET_FILE, label="fresh24 secret file")


def _fresh24_load_public_artifact() -> dict[str, Any]:
    """Load and structurally revalidate the committed second-decision packet.

    The packet must carry the exact schema/key set of the current
    ``build_fresh24_public_request`` output and its self-digest must verify.
    """

    artifact = _load_json(
        phase5_fresh24.FRESH24_REQUEST_OUTPUT, maximum_bytes=2 * 1024 * 1024
    )
    required_keys = {
        "schema_version",
        "authority_id",
        "provider_lane",
        "endpoint",
        "model",
        "prompt_version",
        "prompt_sha256",
        "profile_schema_version",
        "profile_schema_sha256",
        "config_version",
        "config_sha256",
        "preprocessing_version",
        "preprocessing_sha256",
        "source_inventory_sha256",
        "source_authority_sha256",
        "source_install_receipt_sha256",
        "membership_sha256",
        "probe_terminal_sha256",
        "probe_request_sha256",
        "checkout_commit_sha256",
        "checkout_manifest_sha256",
        "first_pass_count",
        "member_count",
        "first_passes",
        "request_manifest_sha256",
        "retry_policy",
        "exposure_policy",
        "activation_source_file_sha256",
        "activation_dataset_sha256",
        "activation_suite_sha256",
        "activation_scenario_ids",
        "contrast_suite_sha256",
        "contrast_pairs",
        "hard_duplicate_adjudication_sha256",
        "cannot_coappear_authority_sha256",
        "cannot_coappear_pairs",
        "active_release_states",
        "blind_access",
        "live_invocation_count",
        "receipt_emitted",
        "secret_read",
        "provider_client_constructed",
        "network_attempted",
        "lifecycle_mutated",
        "historical_member_import",
        "probe_invocation_only",
        "request_artifact_sha256",
    }
    keys = set(artifact)
    missing = required_keys - keys
    extra = keys - required_keys
    if missing or extra:
        raise ValueError(
            f"fresh24 public packet schema drifted (missing={sorted(missing)}, "
            f"extra={sorted(extra)})"
        )
    stored_digest = artifact.get("request_artifact_sha256")
    computed_digest = canonical_sha256(
        {key: value for key, value in artifact.items() if key != "request_artifact_sha256"}
    )
    if stored_digest != computed_digest:
        raise PermissionError("FRESH24_PUBLIC_PACKET_DIGEST_INVALID")
    return artifact


def _fresh24_rebuild_and_validate_plan(artifact: dict[str, Any]):
    """Rebuild the provider-free plan from current source and require exact
    equality with the committed packet before any capability runs."""

    source = phase5_fresh24.verify_fixed_source_authority()
    plan = phase5_fresh24.build_fresh24_plan(
        source,
        checkout_manifest_sha256=phase5_fresh24.checkout_manifest_sha256(
            REPOSITORY_ROOT
        ),
        probe_terminal=json.loads(
            (
                REPOSITORY_ROOT
                / "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json"
            ).read_bytes()
        ),
    )
    phase5_fresh24.validate_fresh24_public_request(
        artifact,
        plan=plan,
        checkout_commit_sha256=plan.checkout_commit_sha256,
    )
    return plan, plan.checkout_commit_sha256


def _fresh24_descriptor(root: Path):
    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor

    return Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))


def _write_fresh24_terminal(path: Path, terminal: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(terminal)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PermissionError("fresh24 terminal output cannot be a symlink")
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("fresh24 terminal output already differs")
        return
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _minimal_probe_read_terminal(path: Path) -> NvidiaMinimalProbeTerminal:
    terminal_path = _minimal_probe_terminal_output(path)
    return NvidiaMinimalProbeTerminal.model_validate_json(
        _read_bounded_regular(terminal_path, maximum_bytes=2 * 1024 * 1024)
    )


def _write_minimal_probe_terminal(
    path: Path,
    terminal: NvidiaMinimalProbeTerminal,
) -> None:
    payload = canonical_json_bytes(terminal.model_dump(mode="json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PermissionError("minimal probe terminal output cannot be a symlink")
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("minimal probe terminal output already differs")
        return
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_minimal_probe_committed_clean_source(
    repository_root: Path = REPOSITORY_ROOT,
) -> None:
    """Reuse the stdlib bootstrap's authoritative checkout policy exactly."""

    from itda.minimal_probe_bootstrap import _validate_checkout
    from itda.pipeline.phase5_nvidia_recovery import (
        checkout_commit_sha256,
        checkout_manifest_sha256,
    )

    try:
        _validate_checkout(repository_root)
        checkout_commit_sha256(repository_root)
        checkout_manifest_sha256(repository_root)
    except (OSError, PermissionError, subprocess.CalledProcessError, UnicodeError) as error:
        raise RuntimeError("minimal probe source checkout is not committed and clean") from error


def _minimal_probe_preflight_payload(
    request_output: Path,
    *,
    regenerate: bool = False,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, object]:
    from itda.pipeline.phase5_nvidia_recovery import (
        checkout_commit_sha256,
        checkout_manifest_sha256,
        preflight_nvidia_invocation,
    )

    output = _minimal_probe_request_output(request_output)
    result = preflight_nvidia_invocation(
        source_root=FIXED_LIVE_SOURCE_BUNDLES.parent,
        checkout_manifest_sha256=checkout_manifest_sha256(repository_root),
    )
    request = result.request
    preimage = {
        "schema_version": "itda.phase5-nvidia-minimal-probe-approval-request.v1",
        "authority_id": MINIMAL_PROBE_AUTHORITY_ID,
        "provider_lane": MINIMAL_PROBE_PROVIDER_LANE,
        "endpoint": MINIMAL_PROBE_ENDPOINT,
        "model": MINIMAL_PROBE_MODEL,
        "prompt_version": MINIMAL_PROBE_PROMPT_VERSION,
        "prompt_sha256": MINIMAL_PROBE_PROMPT_SHA256,
        "profile_schema_sha256": MINIMAL_PROBE_PROFILE_SCHEMA_SHA256,
        "config_sha256": MINIMAL_PROBE_CONFIG_SHA256,
        "source_inventory_sha256": result.source_inventory_sha256,
        "source_bundle_sha256": request.source_bundle_sha256,
        "evidence_inventory_sha256": request.evidence_inventory_sha256,
        "place_id": request.place_id,
        "request_sha256": request.request_sha256,
        "request_body_sha256": request.request_body_sha256,
        "checkout_manifest_sha256": result.checkout_manifest_sha256,
        "checkout_commit_sha256": checkout_commit_sha256(repository_root),
        "attempt_deadline_seconds": MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS,
        "max_response_bytes": MINIMAL_PROBE_MAX_RESPONSE_BYTES,
        "sentinel_payload_bytes": MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES,
        "max_attempts": MINIMAL_PROBE_MAX_ATTEMPTS,
        "concurrency": MINIMAL_PROBE_CONCURRENCY,
        "cumulative_exposure_micro_usd": MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD,
        "reservation_micro_usd": MINIMAL_PROBE_RESERVATION_MICRO_USD,
        "secret_file_mode": MINIMAL_PROBE_SECRET_FILE_MODE,
        "secret_file_format": MINIMAL_PROBE_SECRET_FILE_FORMAT,
        "receipt_emitted": MINIMAL_PROBE_RECEIPT_EMITTED,
        "cohort_capability": MINIMAL_PROBE_COHORT_CAPABILITY,
        "candidate_capability": False,
        "smoke_capability": MINIMAL_PROBE_SMOKE_CAPABILITY,
        "activation_capability": MINIMAL_PROBE_ACTIVATION_CAPABILITY,
        "release_capability": MINIMAL_PROBE_RELEASE_CAPABILITY,
        "secret_read": False,
        "client_constructed": False,
        "network_attempted": False,
        "lifecycle_mutated": False,
    }
    approval_payload_sha256 = canonical_sha256(preimage)
    artifact_preimage = {**preimage, "approval_payload_sha256": approval_payload_sha256}
    payload = NvidiaMinimalProbePublicArtifact.model_validate(
        {
            **artifact_preimage,
            "request_artifact_sha256": canonical_sha256(artifact_preimage),
        }
    ).model_dump(mode="json")
    serialized = canonical_json_bytes(payload)
    if output.is_symlink():
        raise PermissionError("minimal probe request output cannot be a symlink")
    if output.exists() and output.read_bytes() != serialized:
        if not regenerate:
            raise FileExistsError(
                "minimal probe request artifact differs; regeneration is explicit"
            )
        output.write_bytes(serialized)
        output.chmod(0o644)
    elif not output.exists():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(serialized)
        output.chmod(0o644)
    return payload


def _git_head_sha256() -> str:
    try:
        completed = subprocess.run(
            [
                "git",
                "log",
                "-1",
                "--format=%H",
                "--",
                "backend/src/itda/contracts/phase5_fresh_cohort.py",
                "backend/src/itda/pipeline/phase5_fresh_cohort.py",
                "backend/src/itda/providers/nvidia_minimax_profile.py",
                "backend/src/itda/cli/materialize_phase5_demo_profiles.py",
            ],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise PermissionError("CURRENT_CHECKOUT_COMMIT_UNAVAILABLE") from error
    value = completed.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise PermissionError("CURRENT_CHECKOUT_COMMIT_INVALID")
    return value


def main(argv: list[str] | None = None) -> int:
    # The disjoint r3/v3 provider-free commands live in their own module
    # parser; delegate BEFORE this module's parser can reject the name.  The
    # v3 capability names are NOT delegated — they fall through to the parser
    # rejection / capability hint below (fail closed).
    _arguments = list(sys.argv[1:] if argv is None else argv)
    if _arguments:
        from itda.cli.phase5_openrouter_recovery_v3 import (
            V3_PUBLIC_COMMANDS as _V3_PUBLIC_COMMANDS,
        )
        from itda.cli.phase5_openrouter_recovery_v4 import (
            V4_PUBLIC_COMMANDS as _V4_PUBLIC_COMMANDS,
        )

        if _arguments[0] in _V3_PUBLIC_COMMANDS:
            from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

            return v3_main(_arguments)
        if _arguments[0] in _V4_PUBLIC_COMMANDS:
            from itda.cli.phase5_openrouter_recovery_v4 import main as v4_main

            return v4_main(_arguments)
    args = _parser().parse_args(argv)
    # The fresh24 capability commands are unreachable through this public
    # surface: they are not registered in ``_parser`` and any forged Namespace
    # carrying one is rejected unconditionally here.  Only the bootstrap's
    # internal dispatcher (built after origin/environment/checkout validation)
    # can reach the capability handlers.
    if getattr(args, "command", None) in _ALL_CAPABILITY_COMMANDS:
        hint = (
            "OPENROUTER_V2_CAPABILITY_INERT"
            if args.command in _OPENROUTER_V2_CAPABILITY_COMMANDS
            else (
                "USE_OPENROUTER_BOOTSTRAP_ENTRYPOINT"
                if args.command in _OPENROUTER_CAPABILITY_COMMANDS
                else (
                    "USE_OPENROUTER_V3_BOOTSTRAP_ENTRYPOINT"
                    if args.command in _OPENROUTER_V3_CAPABILITY_COMMANDS
                    else (
                        "USE_OPENROUTER_V4_BOOTSTRAP_ENTRYPOINT"
                        if args.command in _OPENROUTER_V4_CAPABILITY_COMMANDS
                        else "USE_FRESH24_BOOTSTRAP_ENTRYPOINT"
                    )
                )
            )
        )
        print(hint, file=sys.stderr)
        return 2
    journal: DurableRerunJournal | DurableCodingPlanJournal | DurableNvidiaJournal | None = None
    adapter: ZhipuGlm5vProfileAdapter | NvidiaMinimaxProfileAdapter | None = None
    try:
        if args.command == "replay":
            fixture = _load_replay_fixture()
            result = materialize_demo_profiles(
                source_bundles=build_synthetic_replay_sources(fixture),
                mode="replay",
                replay_fixture=fixture,
            )
            _print_payload(_safe_receipt_payload(result.receipt), json_output=args.json)
            return 0
        if args.command == "preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            _print_payload(
                _preflight_payload(
                    allow_missing_secret=args.allow_missing_secret,
                    secret_file=secret_file,
                    artifact_root=artifact_root,
                ),
                json_output=args.json,
            )
            return 0
        if args.command == "nvidia-recovery-preflight":
            _require_minimal_probe_committed_clean_source()
            payload = _minimal_probe_preflight_payload(
                args.request_output,
                regenerate=args.regenerate,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-fresh24-preflight":
            if args.require_committed_clean_source:
                _require_minimal_probe_committed_clean_source()
            probe_path = (REPOSITORY_ROOT / args.probe_terminal).resolve(strict=False)
            output_path = (REPOSITORY_ROOT / args.request_output).resolve(strict=False)
            expected_probe_path = (
                REPOSITORY_ROOT
                / "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json"
            )
            if probe_path != expected_probe_path:
                raise PermissionError("caller-selected fresh24 probe terminal is forbidden")
            if output_path != phase5_fresh24.FRESH24_REQUEST_OUTPUT:
                raise PermissionError("caller-selected fresh24 request output is forbidden")
            source = phase5_fresh24.verify_fixed_source_authority()
            terminal = json.loads(probe_path.read_bytes())
            plan = phase5_fresh24.build_fresh24_plan(
                source,
                checkout_manifest_sha256=phase5_fresh24.checkout_manifest_sha256(
                    REPOSITORY_ROOT
                ),
                probe_terminal=terminal,
            )
            payload = phase5_fresh24.write_fresh24_public_request(
                plan,
                checkout_commit_sha256=phase5_fresh24.fresh24_checkout_commit_sha256(
                    REPOSITORY_ROOT
                ),
                output=output_path,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-fresh24-verify":
            terminal_path = (REPOSITORY_ROOT / args.terminal).resolve(strict=False)
            if terminal_path != phase5_fresh24.FRESH24_TERMINAL_OUTPUT:
                raise PermissionError("caller-selected fresh24 terminal is forbidden")
            terminal = phase5_fresh24.verify_fresh24_terminal_file(terminal_path)
            protected_root = _fresh24_protected_root(args.protected_state_root)
            outcome = phase5_fresh24.verify_fresh24_outcome(
                terminal=terminal.model_dump(mode="json"),
                protected_root=protected_root,
            )
            positive_assertion = False
            if args.require_positive:
                phase5_fresh24.assert_fresh24_positive_outcome(outcome)
                positive_assertion = True
            _print_payload(
                {
                    "status": outcome.terminal.status,
                    "reason": outcome.terminal.reason,
                    "terminal_sha256": outcome.terminal.terminal_sha256,
                    "neutral_verified": True,
                    "protected_verified": True,
                    "positive_assertion": positive_assertion,
                    "network_attempted": outcome.terminal.network_attempted,
                    "lifecycle_mutated": outcome.terminal.lifecycle_mutated,
                },
                json_output=args.json,
            )
            return 0

        if args.command == "nvidia-fresh24-classify":
            terminal_path = (REPOSITORY_ROOT / args.terminal).resolve(strict=False)
            if terminal_path != phase5_fresh24.FRESH24_TERMINAL_OUTPUT:
                raise PermissionError("caller-selected fresh24 terminal is forbidden")
            outcome = phase5_fresh24.verify_fresh24_outcome_for_cli()
            disposition = phase5_fresh24.classify_verified_outcome(outcome)
            if args.value_only:
                print(disposition)
            else:
                _print_payload({"disposition": disposition}, json_output=args.json)
            return 0

        # The fresh24 capability commands (install-approval/live/reconcile) are
        # NOT dispatched here at all — see ``_fresh24_capability_dispatch``,
        # reachable only through the bootstrap's validated internal entry.
        # OpenRouter recovery capability commands follow the same rule via
        # ``_openrouter_recovery_capability_dispatch``.

        if args.command == "openrouter-recovery-preflight":
            from itda.pipeline.phase5_openrouter_recovery import (
                OPENROUTER_REQUEST_OUTPUT,
                openrouter_checkout_commit_sha256,
                validate_openrouter_public_request,
            )
            from itda.pipeline.phase5_openrouter_recovery import (
                verify_fixed_source_authority as _verify_source,
            )

            if args.require_committed_clean_source:
                _require_minimal_probe_committed_clean_source()
            request_path = (REPOSITORY_ROOT / args.request).resolve(strict=False)
            if request_path != OPENROUTER_REQUEST_OUTPUT:
                raise PermissionError(
                    "caller-selected openrouter request output is forbidden"
                )
            source = _verify_source()
            plan = phase5_openrouter_recovery.build_openrouter_plan(
                source,
                checkout_manifest_digest=phase5_openrouter_recovery.checkout_manifest_sha256(
                    REPOSITORY_ROOT
                ),
            )
            checkout_commit = openrouter_checkout_commit_sha256(REPOSITORY_ROOT)
            if args.verify_only:
                payload = json.loads(request_path.read_bytes())
                validate_openrouter_public_request(
                    payload, plan=plan, checkout_commit_sha256=checkout_commit
                )
            else:
                payload = phase5_openrouter_recovery.write_openrouter_public_request(
                    plan, checkout_commit_sha256=checkout_commit
                )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "openrouter-recovery-v2-preflight":
            from itda.pipeline.phase5_openrouter_recovery import (
                OPENROUTER_V2_REQUEST_OUTPUT,
                build_openrouter_v2_plan,
                load_openrouter_v2_public_request_bytes,
                openrouter_v2_checkout_commit_sha256,
                openrouter_v2_checkout_manifest_sha256,
                write_openrouter_v2_public_request,
            )

            if args.require_committed_clean_source:
                _require_minimal_probe_committed_clean_source()
            request_path = (
                args.request
                if args.request.is_absolute()
                else REPOSITORY_ROOT / args.request
            )
            if request_path != OPENROUTER_V2_REQUEST_OUTPUT:
                raise PermissionError("OPENROUTER_V2_REQUEST_PATH_NOT_FIXED")
            source = phase5_openrouter_recovery.verify_fixed_source_authority()
            plan = build_openrouter_v2_plan(
                source,
                checkout_manifest_digest=openrouter_v2_checkout_manifest_sha256(
                    REPOSITORY_ROOT
                ),
                repository_root=REPOSITORY_ROOT,
            )
            checkout_commit = openrouter_v2_checkout_commit_sha256(REPOSITORY_ROOT)
            if args.verify_only:
                payload = load_openrouter_v2_public_request_bytes(
                    phase5_openrouter_recovery._read_public_file_no_follow(request_path),
                    plan=plan,
                    checkout_commit_sha256=checkout_commit,
                )
            else:
                payload = write_openrouter_v2_public_request(
                    plan,
                    checkout_commit_sha256=checkout_commit,
                    output=request_path,
                )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "openrouter-recovery-verify":
            from itda.pipeline.phase5_openrouter_recovery import (
                OPENROUTER_TERMINAL_OUTPUT,
                assert_openrouter_positive_outcome,
                require_fixed_openrouter_paths,
                verify_openrouter_outcome,
            )

            terminal_path = (REPOSITORY_ROOT / args.terminal).resolve(strict=False)
            if terminal_path != OPENROUTER_TERMINAL_OUTPUT:
                raise PermissionError("caller-selected openrouter terminal is forbidden")
            require_fixed_openrouter_paths(terminal_output=terminal_path)
            terminal = phase5_openrouter_recovery.OpenRouterTerminal.model_validate_json(
                phase5_openrouter_recovery._read_public_file_no_follow(terminal_path)
            )
            protected_root = (
                REPOSITORY_ROOT / args.protected_state_root
            ).resolve(strict=False)
            outcome = verify_openrouter_outcome(
                terminal=terminal.model_dump(mode="json"),
                protected_root=protected_root,
            )
            positive_assertion = False
            if args.require_positive:
                assert_openrouter_positive_outcome(outcome)
                positive_assertion = True
            _print_payload(
                {
                    "status": outcome.terminal.status,
                    "reason": outcome.terminal.reason,
                    "terminal_sha256": outcome.terminal.terminal_sha256,
                    "neutral_verified": True,
                    "protected_verified": True,
                    "positive_assertion": positive_assertion,
                    "network_attempted": outcome.terminal.network_attempted,
                    "lifecycle_mutated": outcome.terminal.lifecycle_mutated,
                    "committed_exposure_micro_usd": (
                        outcome.terminal.committed_exposure_micro_usd
                    ),
                },
                json_output=args.json,
            )
            return 0

        if args.command == "openrouter-recovery-classify":
            from itda.pipeline.phase5_openrouter_recovery import (
                OPENROUTER_TERMINAL_OUTPUT,
            )

            terminal_path = (REPOSITORY_ROOT / args.terminal).resolve(strict=False)
            if terminal_path != OPENROUTER_TERMINAL_OUTPUT:
                raise PermissionError("caller-selected openrouter terminal is forbidden")
            outcome = phase5_openrouter_recovery.verify_openrouter_outcome_for_cli()
            disposition = phase5_openrouter_recovery.classify_verified_outcome(outcome)
            if args.value_only:
                print(disposition)
            else:
                _print_payload({"disposition": disposition}, json_output=args.json)
            return 0

        if args.command == "nvidia-minimal-probe-install-approval":
            from itda.pipeline.phase5_nvidia_recovery import (
                MinimalProbeDurableAuthorityState,
                MinimalProbeProtectedStateResolver,
                build_minimal_probe_approval_binding,
                build_minimal_probe_request,
                checkout_commit_sha256,
                checkout_manifest_sha256,
                load_minimal_probe_bundle,
                validate_minimal_probe_public_artifact,
            )

            _require_minimal_probe_committed_clean_source()
            request_path = _minimal_probe_request_output(args.request)
            state_root = _minimal_probe_protected_state_root(args.protected_state_root)
            secret_file = _minimal_probe_secret_file(args.secret_env_file)
            artifact = _load_json(request_path, maximum_bytes=2 * 1024 * 1024)
            request = build_minimal_probe_request(
                load_minimal_probe_bundle()
            )
            public = validate_minimal_probe_public_artifact(
                request=request,
                artifact=artifact,
                checkout_manifest_sha256=checkout_manifest_sha256(REPOSITORY_ROOT),
                checkout_commit_sha256=checkout_commit_sha256(REPOSITORY_ROOT),
            )
            if public.approval_payload_sha256 != args.approval_payload_sha256:
                raise PermissionError("MINIMAL_PROBE_APPROVAL_MISMATCH")
            secret_identity, secret_fingerprint = _minimal_probe_secret_binding(secret_file)
            descriptor = MinimalProbeProtectedStateResolver(
                protected_state_root=state_root
            ).resolve(MINIMAL_PROBE_AUTHORITY_ID)
            approval = build_minimal_probe_approval_binding(
                request=request,
                artifact=public.model_dump(mode="json"),
                protected_state_sha256=descriptor.protected_state_sha256,
                secret_identity_sha256=secret_identity,
                secret_content_fingerprint=secret_fingerprint,
            )
            status = MinimalProbeDurableAuthorityState(
                descriptor=descriptor
            ).install_approval(approval)
            _print_payload(status, json_output=args.json)
            return 0

        if args.command == "nvidia-minimal-probe-reconcile":
            from itda.pipeline.phase5_nvidia_recovery import (
                MinimalProbeDurableAuthorityState,
                MinimalProbeProtectedStateResolver,
                build_minimal_probe_request,
                checkout_commit_sha256,
                checkout_manifest_sha256,
                load_minimal_probe_bundle,
                validate_minimal_probe_public_artifact,
            )

            _require_minimal_probe_committed_clean_source()
            request_path = _minimal_probe_request_output(args.request)
            state_root = _minimal_probe_protected_state_root(args.protected_state_root)
            terminal_path = _minimal_probe_terminal_output(args.terminal_output)
            artifact = _load_json(request_path, maximum_bytes=2 * 1024 * 1024)
            request = build_minimal_probe_request(
                load_minimal_probe_bundle()
            )
            public = validate_minimal_probe_public_artifact(
                request=request,
                artifact=artifact,
                checkout_manifest_sha256=checkout_manifest_sha256(REPOSITORY_ROOT),
                checkout_commit_sha256=checkout_commit_sha256(REPOSITORY_ROOT),
            )
            descriptor = MinimalProbeProtectedStateResolver(
                protected_state_root=state_root
            ).resolve(MINIMAL_PROBE_AUTHORITY_ID)
            result = MinimalProbeDurableAuthorityState(
                descriptor=descriptor
            ).reconcile_interrupted(
                request=request,
                expected_artifact=public,
            )
            if result is None:
                raise PermissionError("MINIMAL_PROBE_RECONCILIATION_NOT_REQUIRED")
            _write_minimal_probe_terminal(terminal_path, result.terminal)
            _print_payload(
                {
                    "status": result.terminal.status,
                    "reason": result.terminal.reason,
                    "terminal_sha256": result.terminal.terminal_sha256,
                    "network_attempted": result.terminal.network_attempted,
                },
                json_output=args.json,
            )
            return 2

        if args.command in {"nvidia-minimal-probe-verify", "nvidia-minimal-probe-classify"}:
            terminal_path = _minimal_probe_terminal_output(args.terminal)
            terminal = NvidiaMinimalProbeTerminal.model_validate_json(
                _read_bounded_regular(terminal_path, maximum_bytes=2 * 1024 * 1024)
            )
            from itda.pipeline.phase5_nvidia_recovery import (
                MinimalProbeDurableAuthorityState,
                MinimalProbeProtectedStateResolver,
                assert_nvidia_probe_positive,
                build_minimal_probe_request,
                checkout_manifest_sha256,
                classify_nvidia_probe_terminal,
                load_minimal_probe_bundle,
                validate_minimal_probe_public_artifact,
                verify_nvidia_probe_terminal,
            )

            request_path = _minimal_probe_request_output(
                args.request
                or Path("artifacts/public/phase5/nvidia-minimal-probe-request.json")
            )
            artifact = _load_json(request_path, maximum_bytes=2 * 1024 * 1024)
            request = build_minimal_probe_request(
                load_minimal_probe_bundle()
            )
            public = validate_minimal_probe_public_artifact(
                request=request,
                artifact=artifact,
                checkout_manifest_sha256=checkout_manifest_sha256(REPOSITORY_ROOT),
                checkout_commit_sha256=checkout_commit_sha256(REPOSITORY_ROOT),
            )
            descriptor = MinimalProbeProtectedStateResolver(
                protected_state_root=_minimal_probe_protected_state_root(
                    Path("artifacts/restricted/catalog/phase5-nvidia-minimal-probe")
                )
            ).descriptor
            durable = MinimalProbeDurableAuthorityState(descriptor=descriptor)
            durable.require_approval_matches(public)
            outcome = durable.verify_outcome(
                request=request,
                terminal=terminal,
            )
            verified = verify_nvidia_probe_terminal(outcome)
            protected_verified = True
            if args.command == "nvidia-minimal-probe-verify":
                if args.require_positive:
                    assert_nvidia_probe_positive(outcome)
                _print_payload(
                    {
                        "status": verified.status,
                        "reason": verified.reason,
                        "terminal_sha256": verified.terminal_sha256,
                        "neutral_verified": True,
                        "protected_verified": protected_verified,
                        "positive_assertion": bool(args.require_positive),
                    },
                    json_output=args.json,
                )
            else:
                disposition = classify_nvidia_probe_terminal(outcome)
                if args.value_only:
                    print(disposition)
                else:
                    _print_payload(
                        {"disposition": disposition, "terminal_sha256": verified.terminal_sha256},
                        json_output=args.json,
                    )
            return 0

        if args.command == "nvidia-minimal-probe-live":
            from itda.pipeline.phase5_nvidia_recovery import (
                MinimalProbeDurableAuthorityState,
                MinimalProbeProtectedStateResolver,
                build_minimal_probe_request,
                checkout_manifest_sha256,
                execute_nvidia_minimal_probe,
                load_minimal_probe_bundle,
                validate_minimal_probe_public_artifact,
            )

            _require_minimal_probe_committed_clean_source()
            request_path = _minimal_probe_request_output(args.request)
            state_root = _minimal_probe_protected_state_root(args.protected_state_root)
            secret_file = _minimal_probe_secret_file(args.secret_env_file)
            terminal_path = _minimal_probe_terminal_output(args.terminal_output)
            if os.environ.get("ITDA_OFFLINE") == "1" or os.environ.get("ITDA_NO_NETWORK") == "1":
                raise PermissionError("LIVE_MODE_DISABLED")
            if os.environ.get("CI") or os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
                raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
            request_artifact = _load_json(request_path, maximum_bytes=2 * 1024 * 1024)
            bundle = load_minimal_probe_bundle()
            request = build_minimal_probe_request(bundle)
            public = validate_minimal_probe_public_artifact(
                request=request,
                artifact=request_artifact,
                checkout_manifest_sha256=checkout_manifest_sha256(REPOSITORY_ROOT),
                checkout_commit_sha256=checkout_commit_sha256(REPOSITORY_ROOT),
            )
            descriptor = MinimalProbeProtectedStateResolver(
                protected_state_root=state_root
            ).resolve(MINIMAL_PROBE_AUTHORITY_ID)
            durable = MinimalProbeDurableAuthorityState(descriptor=descriptor)
            approval = durable.require_approval_matches(public)
            current_identity, current_fingerprint = _minimal_probe_secret_binding(secret_file)
            if (
                current_identity != approval.secret_identity_sha256
                or current_fingerprint != approval.secret_content_fingerprint
            ):
                raise PermissionError("MINIMAL_PROBE_SECRET_IDENTITY_MISMATCH")

            def read_secret() -> str:
                return _read_minimal_probe_secret(
                    secret_file,
                    expected_identity_sha256=approval.secret_identity_sha256,
                    expected_content_fingerprint=approval.secret_content_fingerprint,
                )

            def publish_terminal(result: object) -> None:
                _write_minimal_probe_terminal(
                    terminal_path,
                    cast(Any, result).terminal,
                )

            result = asyncio.run(
                execute_nvidia_minimal_probe(
                    state=durable,
                    artifact=public,
                    bundle=bundle,
                    credential_reader=read_secret,
                    terminal_sink=publish_terminal,
                )
            )
            durable.verify_outcome(request=request, terminal=result.terminal)
            _print_payload(
                {
                    "status": result.terminal.status,
                    "reason": result.terminal.reason,
                    "terminal_sha256": result.terminal.terminal_sha256,
                    "attempt_count": result.terminal.attempt_count,
                    "network_attempted": result.terminal.network_attempted,
                },
                json_output=args.json,
            )
            return 0 if result.terminal.status == "POSITIVE" else 2

        if args.command == "verify":
            receipt = verify_demo_profile_generation(args.generation.resolve(strict=True))
            _print_payload(_safe_receipt_payload(receipt), json_output=args.json)
            return 0

        if args.command == "rerun-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            authority, _ = _rerun_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
            )
            payload = dict(authority)
            payload["network_attempted"] = False
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "coding-plan-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _coding_plan_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-resume-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-second-resume-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_second_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-v4-probe-resume-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_v4_probe_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-v5-two-probe-resume-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_v5_two_probe_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-v5-three-validated-resume-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_v5_three_validated_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-v5-attempt8-resume-preflight":
            secret_file, artifact_root = _require_fixed_cli_paths(
                secret_file=args.secret_env_file,
                artifact_root=args.artifact_root,
            )
            payload = _nvidia_v5_attempt8_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=args.allow_missing_secret,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-v5-attempt5-retaining-preflight":
            artifact_root = _require_fixed_artifact_root(args.artifact_root)
            _bundles, _plan, attempt5_preflight_authority = _attempt5_retaining_cli_context(
                authority_text=args.authority_text,
                authority_sha256=args.authority_sha256,
                artifact_root=artifact_root,
            )
            _print_payload(dict(attempt5_preflight_authority.receipt), json_output=args.json)
            return 0

        if args.command == "nvidia-fresh-cohort-preflight":
            request_output = _require_fresh_public_request_output(args.request_output)
            payload = _fresh_preflight_payload(
                authority_id=args.authority_id,
                request_output=request_output,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-fresh-cohort-install-approval":
            plan, resolver, artifact, _request_digest, _approval_digest = (
                _fresh_cli_context(
                    request=args.request,
                    authority_id=args.authority_id,
                    protected_state_root=args.protected_state_root,
                )
            )
            payload = install_fresh_approval_from_public_artifact(
                plan=plan,
                descriptor=resolver.resolve(args.authority_id),
                artifact=artifact,
                approved_payload_sha256=args.approval_payload_sha256,
            )
            _print_payload(payload, json_output=args.json)
            return 0

        if args.command == "nvidia-fresh-cohort-live":
            plan, state, fresh_status = _fresh_live_preflight_context(
                request=args.request,
                authority_id=args.authority_id,
                protected_state_root=args.protected_state_root,
                terminal_output=args.terminal_output,
            )
            terminal_output = _require_fresh_terminal_output(args.terminal_output)
            if fresh_status.get("reconciliation_required") is True:
                payload = reconcile_fresh_claimed_run(
                    plan=plan,
                    authority=state,
                    descriptor=state.descriptor,
                    terminal_output=terminal_output,
                )
                _print_payload(payload, json_output=args.json)
                return 0 if payload.get("status") == "COMPLETE_ELIGIBLE_UNACTIVATED" else 2
            secret_file = _require_fresh_secret_file(args.secret_env_file)
            if (
                os.environ.get("ITDA_OFFLINE") == "1"
                or os.environ.get("ITDA_NO_NETWORK") == "1"
                or os.environ.get("CI")
            ):
                raise PermissionError("LIVE_MODE_DISABLED")
            if os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
                raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")

            def read_fresh_secret() -> str:
                present, value = _read_nvidia_secret(secret_file, allow_missing=False)
                if not present or value is None:
                    raise PermissionError("exact local NVIDIA_KEY is unavailable")
                return value

            payload = asyncio.run(
                execute_fresh_live_cohort(
                    plan=plan,
                    authority=state,
                    descriptor=state.descriptor,
                    terminal_output=terminal_output,
                    credential_reader=read_fresh_secret,
                )
            )
            _print_payload(payload, json_output=args.json)
            return 0 if payload.get("status") == "COMPLETE_ELIGIBLE_UNACTIVATED" else 2

        if args.command == "nvidia-fresh-cohort-activate-and-smoke":
            if args.authority_id != FRESH_AUTHORITY_ID:
                raise PermissionError("FRESH_AUTHORITY_ID_MISMATCH")
            terminal = (REPOSITORY_ROOT / args.terminal).resolve(strict=False)
            expected_terminal = (
                REPOSITORY_ROOT / "artifacts/reports/phase5/fresh-provider-terminal.json"
            )
            if terminal != expected_terminal:
                raise PermissionError("caller-selected fresh terminal path is forbidden")
            if not terminal.is_file():
                raise PermissionError("FRESH_PROVIDER_TERMINAL_UNAVAILABLE")
            terminal_payload = json.loads(
                _read_bounded_regular(terminal, maximum_bytes=2 * 1024 * 1024)
            )
            if not isinstance(terminal_payload, dict):
                raise PermissionError("FRESH_PROVIDER_TERMINAL_INVALID")
            active_count = terminal_payload.get("active_member_count")
            eligible_count = terminal_payload.get("eligible_count")
            if active_count != args.require_active_member_count:
                raise PermissionError("FRESH_ACTIVE_MEMBER_COUNT_MISMATCH")
            if not isinstance(eligible_count, int) or eligible_count < (
                args.require_minimum_eligible
            ):
                raise PermissionError("FRESH_MINIMUM_ELIGIBLE_COUNT_NOT_MET")
            if args.require_two_preference_rank_change and terminal_payload.get(
                "two_preference_rank_change"
            ) is not True:
                raise PermissionError("FRESH_TWO_PREFERENCE_RANK_INSENSITIVE")
            payload = {
                "schema_version": "itda.phase5-fresh-cohort-smoke.v1",
                "authority_id": args.authority_id,
                "active_member_count": active_count,
                "eligible_count": eligible_count,
                "two_preference_rank_change": terminal_payload.get(
                    "two_preference_rank_change", False
                ),
                "activation_capability": True,
                "network_attempted": False,
            }
            _print_payload(payload, json_output=args.json)
            return 0

        if os.environ.get("ITDA_OFFLINE") == "1" or os.environ.get("CI"):
            raise PermissionError("LIVE_MODE_DISABLED")
        if os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
            raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        secret_file, artifact_root = _require_fixed_cli_paths(
            secret_file=args.secret_env_file,
            artifact_root=args.artifact_root,
        )
        attempt5_live_context: (
            tuple[
                tuple[DemoSourceBundle, ...],
                Attempt5RetainingPlan,
                Attempt5RetainingAuthority,
            ]
            | None
        ) = None
        attempt5_execution_approval: Mapping[str, object] | None = None
        attempt5_trusted_decision_record_sha256: str | None = None
        if args.command == "nvidia-v5-attempt5-retaining-live":
            attempt5_live_context = _attempt5_retaining_cli_context(
                authority_text=args.authority_text,
                authority_sha256=args.authority_sha256,
                artifact_root=artifact_root,
            )
            (
                attempt5_execution_approval,
                attempt5_trusted_decision_record_sha256,
            ) = _installed_attempt5_execution_approval(
                authority=attempt5_live_context[2],
                approval_text=args.execution_approval_text,
                approval_sha256=args.execution_approval_sha256,
                artifact_root=artifact_root,
            )
        if args.command in {
            "nvidia-live",
            "nvidia-resume-live",
            "nvidia-second-resume-live",
            "nvidia-v4-probe-resume-live",
            "nvidia-v5-two-probe-resume-live",
            "nvidia-v5-three-validated-resume-live",
            "nvidia-v5-attempt8-resume-live",
            "nvidia-v5-attempt5-retaining-live",
        }:
            _, credential = _read_nvidia_secret(secret_file, allow_missing=False)
        else:
            _, credential = _read_local_secret(secret_file, allow_missing=False)
        if credential is None:
            raise PermissionError("PROVIDER_SECRET_UNAVAILABLE")
        credential_bytes = credential.encode("utf-8")
        source_bundles = (
            attempt5_live_context[0]
            if attempt5_live_context is not None
            else _load_live_source_bundles(artifact_root / "source-bundles.json")
        )
        rerun_authority_sha256: str | None = None
        coding_plan_authority_sha256: str | None = None
        ledger = None
        coding_plan_ledger = None
        config: (
            DemoProfileMaterializationConfig
            | CodingPlanProfileMaterializationConfig
            | NvidiaMinimaxProfileMaterializationConfig
        ) = DemoProfileMaterializationConfig()
        if args.command == "nvidia-live":
            authority = _nvidia_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            journal = DurableNvidiaJournal(
                root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
                authority_receipt=authority,
            )
            journal.require_pristine()
            nvidia_config = NvidiaMinimaxProfileMaterializationConfig()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                config=nvidia_config,
                ledger=NvidiaAttemptLedger(),
            )
            result = asyncio.run(
                materialize_live_nvidia_profiles(
                    source_bundles=source_bundles,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    nvidia_authority_sha256=NVIDIA_AUTHORITY_SHA256,
                    require_first_probe_valid=True,
                )
            )
        elif args.command == "nvidia-resume-live":
            authority = _nvidia_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            if authority.get("cooldown_satisfied") is not True:
                raise PermissionError("NVIDIA_RESUME_COOLDOWN_ACTIVE")
            resume_plan = build_nvidia_resume_plan(
                source_bundles=source_bundles,
                predecessor_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
                expected_predecessor_manifest_sha256=(NVIDIA_RESUME_PREDECESSOR_MANIFEST_SHA256),
            )
            journal = DurableNvidiaJournal(
                root=artifact_root / "nvidia-resume" / NVIDIA_RESUME_AUTHORITY_SHA256,
                authority_receipt=authority,
                resume_authority_sha256=NVIDIA_RESUME_AUTHORITY_SHA256,
            )
            journal.require_pristine()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_resume(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
            )
            result = asyncio.run(
                materialize_live_nvidia_resume_profiles(
                    source_bundles=source_bundles,
                    plan=resume_plan,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    resume_authority_sha256=NVIDIA_RESUME_AUTHORITY_SHA256,
                )
            )
        elif args.command == "nvidia-second-resume-live":
            authority = _nvidia_second_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            second_resume_plan = build_nvidia_second_resume_plan(
                source_bundles=source_bundles,
                predecessor_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
                resume_root=artifact_root / "nvidia-resume" / NVIDIA_RESUME_AUTHORITY_SHA256,
                expected_reconciliation_sha256=NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256,
            )
            journal = DurableNvidiaJournal(
                root=(artifact_root / "nvidia-resume" / NVIDIA_SECOND_RESUME_AUTHORITY_SHA256),
                authority_receipt=authority,
                resume_authority_sha256=NVIDIA_SECOND_RESUME_AUTHORITY_SHA256,
            )
            journal.require_pristine()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_second_resume(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
            )
            result = asyncio.run(
                materialize_live_nvidia_second_resume_profiles(
                    source_bundles=source_bundles,
                    plan=second_resume_plan,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    resume_authority_sha256=NVIDIA_SECOND_RESUME_AUTHORITY_SHA256,
                )
            )
        elif args.command == "nvidia-v4-probe-resume-live":
            authority = _nvidia_v4_probe_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            v4_probe_resume_plan = build_nvidia_v4_probe_resume_plan(
                source_bundles=source_bundles,
                predecessor_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
                failure_root=artifact_root / "failures" / NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256,
                expected_predecessor_manifest_sha256=(
                    NVIDIA_V4_PROBE_RESUME_PREDECESSOR_MANIFEST_SHA256
                ),
            )
            journal = DurableNvidiaJournal(
                root=(artifact_root / "nvidia-resume" / NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256),
                authority_receipt=authority,
                resume_authority_sha256=NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
            )
            journal.require_pristine()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_v4_probe_resume(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
            )
            result = asyncio.run(
                materialize_live_nvidia_v4_probe_resume_profiles(
                    source_bundles=source_bundles,
                    plan=v4_probe_resume_plan,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    resume_authority_sha256=NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
                )
            )
        elif args.command == "nvidia-v5-two-probe-resume-live":
            authority = _nvidia_v5_two_probe_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            v5_two_probe_resume_plan = build_nvidia_v5_two_probe_resume_plan(
                source_bundles=source_bundles,
                attempt1_root=artifact_root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
                attempt1_failure_root=(
                    artifact_root / "failures" / NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256
                ),
                attempt2_root=(
                    artifact_root / "nvidia-resume" / NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256
                ),
                attempt2_failure_root=(
                    artifact_root
                    / "failures"
                    / "555d8aaccbaa0dcb49e506cf7f20d5d8608999cde2e37ae4fe118dc3db312e66"
                ),
            )
            journal = DurableNvidiaJournal(
                root=(
                    artifact_root / "nvidia-resume" / NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256
                ),
                authority_receipt=authority,
                resume_authority_sha256=NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
            )
            journal.require_pristine()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_v5_two_probe_resume(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
            )
            result = asyncio.run(
                materialize_live_nvidia_v5_two_probe_resume_profiles(
                    source_bundles=source_bundles,
                    plan=v5_two_probe_resume_plan,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    resume_authority_sha256=NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
                )
            )
        elif args.command == "nvidia-v5-three-validated-resume-live":
            authority = _nvidia_v5_three_validated_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            v5_three_validated_resume_plan = build_nvidia_v5_three_validated_resume_plan(
                source_bundles=source_bundles,
                predecessor_root=(
                    artifact_root / "nvidia-resume" / NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256
                ),
                failure_root=(
                    artifact_root
                    / "failures"
                    / cast(
                        str,
                        NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["failure_sha256"],
                    )
                ),
            )
            journal = DurableNvidiaJournal(
                root=(
                    artifact_root
                    / "nvidia-resume"
                    / NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256
                ),
                authority_receipt=authority,
                resume_authority_sha256=NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
            )
            journal.require_pristine()
            journal.record_live_start()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_v5_three_validated_resume(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
            )
            result = asyncio.run(
                materialize_live_nvidia_v5_three_validated_resume_profiles(
                    source_bundles=source_bundles,
                    plan=v5_three_validated_resume_plan,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    resume_authority_sha256=(NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256),
                )
            )
        elif args.command == "nvidia-v5-attempt8-resume-live":
            _nvidia_v5_attempt8_resume_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            v5_attempt8_resume_plan = build_nvidia_v5_attempt8_resume_plan(
                source_bundles=source_bundles,
                base_predecessor_root=(
                    artifact_root / "nvidia-resume" / NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256
                ),
                base_failure_root=(
                    artifact_root
                    / "failures"
                    / cast(
                        str,
                        NVIDIA_V5_THREE_VALIDATED_RESUME_BINDINGS["failure_sha256"],
                    )
                ),
                predecessor_root=(
                    artifact_root
                    / "nvidia-resume"
                    / NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256
                ),
                failure_root=(
                    artifact_root
                    / "failures"
                    / cast(str, NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["failure_sha256"])
                ),
            )
            live_authority = build_nvidia_v5_attempt8_resume_authority(
                authority_text=args.authority_text,
                source_bundles=source_bundles,
                plan=v5_attempt8_resume_plan,
            )
            journal = DurableNvidiaJournal(
                root=(artifact_root / "nvidia-resume" / NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256),
                authority_receipt=live_authority,
                resume_authority_sha256=NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
            )
            journal.require_pristine()
            journal.record_live_start()
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_v5_attempt8_resume(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
            )
            result = asyncio.run(
                materialize_live_nvidia_v5_attempt8_resume_profiles(
                    source_bundles=source_bundles,
                    plan=v5_attempt8_resume_plan,
                    adapter=adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    resume_authority_sha256=NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
                    predecessor_root=(
                        artifact_root
                        / "nvidia-resume"
                        / NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256
                    ),
                    failure_root=(
                        artifact_root
                        / "failures"
                        / cast(str, NVIDIA_V5_ATTEMPT8_RESUME_BINDINGS["failure_sha256"])
                    ),
                    active_pointer_path=artifact_root / "active/current.json",
                )
            )
        elif args.command == "nvidia-v5-attempt5-retaining-live":
            if (
                attempt5_live_context is None
                or attempt5_execution_approval is None
                or attempt5_trusted_decision_record_sha256 is None
            ):
                raise PermissionError("attempt-5-retaining live context is absent")
            source_bundles, attempt5_plan, attempt5_authority = attempt5_live_context
            journal = DurableNvidiaJournal(
                root=artifact_root / "nvidia-resume" / attempt5_authority.authority_sha256,
                authority_receipt=attempt5_authority.receipt,
                resume_authority_sha256=attempt5_authority.authority_sha256,
            )
            journal.require_pristine()
            journal.record_live_start(
                execution_approval_receipt=attempt5_execution_approval,
            )
            adapter = NvidiaMinimaxProfileAdapter(
                secret=credential,
                ledger=NvidiaAttemptLedger.for_v5_attempt5_retaining(),
                rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
                unknown_price_request_exposure=True,
            )

            def current_attempt5_state() -> str:
                return build_attempt5_retaining_plan(
                    source_bundles=source_bundles,
                    predecessor_root=(
                        artifact_root / "nvidia-resume" / NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256
                    ),
                    failure_root=(
                        artifact_root
                        / "failures"
                        / "d7f373f45036728e02f1f16526b893b2e8bf1d02daf27b835500a0f928fc0db7"
                    ),
                    active_pointer_path=artifact_root / "active/current.json",
                ).state_sha256

            attempt5_result = asyncio.run(
                execute_attempt5_retaining_materialization(
                    source_bundles=source_bundles,
                    plan=attempt5_plan,
                    authority=attempt5_authority,
                    adapter=adapter,
                    journal=journal,
                    execution_approval_text=args.execution_approval_text,
                    execution_approval_sha256=args.execution_approval_sha256,
                    trusted_decision_record_sha256=(attempt5_trusted_decision_record_sha256),
                    state_guard=current_attempt5_state,
                    redaction_token=credential.encode("utf-8"),
                )
            )
            generation_path = publish_attempt5_retaining_generation(
                attempt5_result,
                output_root=artifact_root / "generations",
            )
            journal.record_attempt5_retaining_complete(
                attempt5_result.receipt,
                generation_path=generation_path,
            )
            _print_payload(dict(attempt5_result.receipt), json_output=args.json)
            return 0
        elif args.command == "rerun-live":
            _, journal = _rerun_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
            )
            journal.require_pristine()
            rerun_authority_sha256 = RERUN_AUTHORITY_SHA256
            ledger = AttemptCostLedger(max_cost_micro_usd=RERUN_COST_CAP_MICRO_USD)
        elif args.command == "coding-plan-live":
            authority = _coding_plan_authority_receipt(
                authority_text=args.authority_text,
                secret_file=secret_file,
                artifact_root=artifact_root,
                allow_missing_secret=False,
            )
            journal = DurableCodingPlanJournal(
                root=artifact_root / "coding-plan" / CODING_PLAN_AUTHORITY_SHA256,
                authority_receipt=authority,
            )
            journal.require_pristine()
            coding_plan_authority_sha256 = CODING_PLAN_AUTHORITY_SHA256
            coding_plan_ledger = CodingPlanAttemptLedger()
            config = CodingPlanProfileMaterializationConfig.for_authorized_base(
                base_url=CODING_PLAN_BASE_URL,
                entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
            )
        if args.command not in {
            "nvidia-live",
            "nvidia-resume-live",
            "nvidia-second-resume-live",
            "nvidia-v4-probe-resume-live",
            "nvidia-v5-two-probe-resume-live",
            "nvidia-v5-three-validated-resume-live",
            "nvidia-v5-attempt8-resume-live",
            "nvidia-v5-attempt5-retaining-live",
        }:
            assert not isinstance(config, NvidiaMinimaxProfileMaterializationConfig)
            assert not isinstance(journal, DurableNvidiaJournal)
            zhipu_adapter = ZhipuGlm5vProfileAdapter(
                secret=credential,
                ledger=ledger,
                config=config,
                coding_plan_ledger=coding_plan_ledger,
            )
            adapter = zhipu_adapter
            result = asyncio.run(
                materialize_live_demo_profiles(
                    source_bundles=source_bundles,
                    adapter=zhipu_adapter,
                    journal=journal,
                    redaction_token=credential.encode("utf-8"),
                    rerun_authority_sha256=rerun_authority_sha256,
                    coding_plan_authority_sha256=coding_plan_authority_sha256,
                    require_first_probe_valid=args.command == "coding-plan-live",
                )
            )
        if any(credential_bytes in raw for _, raw in result.raw_responses):
            raise PermissionError("PROVIDER_RESPONSE_CONTAINED_SECRET")
        publish_demo_profile_generation(result, output_root=artifact_root / "generations")
        if journal is not None:
            journal.record_complete(result)
        payload = _safe_receipt_payload(result.receipt)
        payload["network_attempted"] = True
        _print_payload(payload, json_output=args.json)
        return 0
    except DemoProfileMaterializationFailure as error:
        try:
            for attempt_result in error.results:
                raw_response = attempt_result.raw_response
                if raw_response is not None and credential_bytes in raw_response:
                    raise PermissionError("PROVIDER_RESPONSE_CONTAINED_SECRET")
            if journal is not None and not (journal.root / "terminal").exists():
                if isinstance(journal, DurableNvidiaJournal):
                    journal.record_terminal(
                        failure_code=error.failure_code,
                        failed_place_id=error.failed_place_id,
                        attempt_count=len(error.results),
                    )
                else:
                    journal.record_terminal(
                        failure_code=error.failure_code,
                        failed_place_id=error.failed_place_id,
                        attempt_count=len(error.results),
                        committed_cost_micro_usd=error.committed_cost_micro_usd,
                        outstanding_cost_micro_usd=error.outstanding_cost_micro_usd,
                    )
            failure_path = publish_demo_profile_failure(
                error,
                output_root=OUTPUT_ROOT.parent / "failures",
            )
            relative_path = failure_path.relative_to(REPOSITORY_ROOT).as_posix()
        except (FileExistsError, OSError, ValueError):
            print("PHASE5_PROFILE_FAILURE_PERSISTENCE_REJECTED", file=sys.stderr)
            return 2
        print(
            f"PHASE5_PROFILE_MATERIALIZATION_REJECTED failure_artifact={relative_path}",
            file=sys.stderr,
        )
        return 2
    except RuntimeError as error:
        if journal is not None:
            if isinstance(journal, DurableNvidiaJournal):
                journal.record_terminal(
                    failure_code="RUNTIME_REJECTED",
                    failed_place_id="PRE_SOCKET_OR_UNKNOWN",
                    attempt_count=(
                        adapter.ledger.attempt_count
                        if isinstance(adapter, NvidiaMinimaxProfileAdapter)
                        else 0
                    ),
                )
                print("PHASE5_PROFILE_MATERIALIZATION_REJECTED", file=sys.stderr)
                return 2
            is_coding_plan = (
                isinstance(adapter, ZhipuGlm5vProfileAdapter) and adapter.is_coding_plan
            )
            committed = (
                0
                if not isinstance(adapter, ZhipuGlm5vProfileAdapter) or is_coding_plan
                else adapter.ledger.committed_micro_usd
            )
            outstanding = (
                0
                if not isinstance(adapter, ZhipuGlm5vProfileAdapter) or is_coding_plan
                else adapter.ledger.outstanding_micro_usd
            )
            if isinstance(adapter, ZhipuGlm5vProfileAdapter) and adapter.is_coding_plan:
                subscription_attempt_count = adapter.coding_plan_ledger.attempt_count
                subscription_total_weight = adapter.coding_plan_ledger.total_weight
            else:
                subscription_attempt_count = 0
                subscription_total_weight = 0
            journal.record_terminal(
                failure_code=(
                    str(error)
                    if str(error) in {"COST_BUDGET_EXHAUSTED", "PROVIDER_USAGE_EXCEEDS_RESERVATION"}
                    else "RUNTIME_REJECTED"
                ),
                failed_place_id="PRE_SOCKET_OR_UNKNOWN",
                attempt_count=0,
                committed_cost_micro_usd=committed,
                outstanding_cost_micro_usd=outstanding,
                subscription_attempt_count=subscription_attempt_count,
                subscription_total_weight=subscription_total_weight,
                coding_plan_authority_sha256=(
                    CODING_PLAN_AUTHORITY_SHA256 if is_coding_plan else None
                ),
            )
        print("PHASE5_PROFILE_MATERIALIZATION_REJECTED", file=sys.stderr)
        return 2
    except (
        DemoProfileMaterializationError,
        FileExistsError,
        json.JSONDecodeError,
        OSError,
        PermissionError,
        ValidationError,
        ValueError,
    ):
        if args.command in {
            "nvidia-v5-attempt8-resume-live",
            "nvidia-v5-attempt5-retaining-live",
        }:
            _terminalize_attempt8_local_rejection(journal=journal, adapter=adapter)
        print("PHASE5_PROFILE_MATERIALIZATION_REJECTED", file=sys.stderr)
        return 2


def _fresh24_capability_parser() -> argparse.ArgumentParser:
    """Private parser for the fresh24 capability commands.

    Deliberately separate from the public ``_parser``: the public surface has
    no capability subcommands at all, so neither the CLI argv of a direct
    ``python -m`` run nor an imported ``main()`` call can reach the capability
    handlers.  Only :func:`_fresh24_capability_dispatch` uses this parser, and
    that dispatcher is invoked exclusively by the stdlib bootstrap after its
    origin/environment/checkout validation has passed.
    """

    parser = argparse.ArgumentParser(description="fresh24 capability commands")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("nvidia-fresh24-install-approval")
    install.add_argument("--request", type=Path, required=True)
    install.add_argument("--protected-state-root", type=Path, required=True)
    install.add_argument("--secret-env-file", type=Path, required=True)
    install.add_argument("--approval-payload-sha256", required=True)
    install.add_argument("--json", action="store_true")
    live = commands.add_parser("nvidia-fresh24-live")
    live.add_argument("--request", type=Path, required=True)
    live.add_argument("--protected-state-root", type=Path, required=True)
    live.add_argument("--secret-env-file", type=Path, required=True)
    live.add_argument("--terminal-output", type=Path, required=True)
    live.add_argument("--json", action="store_true")
    reconcile = commands.add_parser("nvidia-fresh24-reconcile")
    reconcile.add_argument("--request", type=Path, required=True)
    reconcile.add_argument("--protected-state-root", type=Path, required=True)
    reconcile.add_argument("--terminal-output", type=Path, required=True)
    reconcile.add_argument("--json", action="store_true")
    return parser


def _fresh24_capability_dispatch(argv: list[str]) -> int:
    """Internal dispatcher for capability runs — self-validating on every call.

    Private naming is not the boundary: every entry re-runs the SAME stdlib
    validation as the production bootstrap (environment, import origin and
    shadowing, committed checkout) via
    ``itda.minimal_probe_bootstrap.validate_capability_process``.  A hostile
    environment, dirty checkout, or poisoned import surface fails closed here
    before any handler sentinel.  On the clean production path this double
    validation is safe (both passes are read-only).
    """

    from itda.minimal_probe_bootstrap import validate_capability_process

    args = _fresh24_capability_parser().parse_args(argv)
    try:
        validate_capability_process()
        return _fresh24_capability_run(args)
    except (
        DemoProfileMaterializationError,
        FileExistsError,
        json.JSONDecodeError,
        OSError,
        PermissionError,
        RuntimeError,
        subprocess.CalledProcessError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        print("PHASE5_PROFILE_MATERIALIZATION_REJECTED", file=sys.stderr)
        return 2


def _fresh24_capability_run(args: argparse.Namespace) -> int:
    if args.command == "nvidia-fresh24-install-approval":
        from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
        from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

        _require_minimal_probe_committed_clean_source()
        request_path = _fresh24_request_path(args.request)
        state_root = _fresh24_protected_root(args.protected_state_root)
        secret_file = _fresh24_secret_file(args.secret_env_file)
        del request_path
        # The approval binds the committed packet's EXACT raw bytes: reopen
        # the fixed path component-wise no-follow and record BOTH digest
        # domains through the ONE shared helper (semantic self-digest +
        # exact raw file bytes).
        from itda.pipeline.phase5_fresh24 import (
            _read_fixed_public_packet_bytes,
            fresh24_packet_digest_domains,
        )

        packet_raw_bytes = _read_fixed_public_packet_bytes()
        artifact = _fresh24_load_public_artifact()
        semantic_digest, raw_file_digest = fresh24_packet_digest_domains(
            json.loads(packet_raw_bytes)
        )
        if semantic_digest != str(artifact.get("request_artifact_sha256")):
            raise PermissionError("FRESH24_PACKET_SEMANTIC_DIGEST_DRIFT")
        if hashlib.sha256(packet_raw_bytes).hexdigest() != raw_file_digest:
            raise PermissionError("FRESH24_PACKET_RAW_DIGEST_DRIFT")
        if artifact.get("request_artifact_sha256") != args.approval_payload_sha256:
            raise PermissionError("FRESH24_APPROVAL_MISMATCH")
        # Non-value continuity identity only; no value/prefix/length/digest
        # derivation ever happens at approval time.
        _fresh24_rebuild_and_validate_plan(artifact)
        secret_identity = _fresh24_secret_metadata_identity(secret_file)
        descriptor = _fresh24_descriptor(state_root)
        approval_fields = {
            "schema_version": "itda.phase5-fresh24-approval.v1",
            "authority_id": artifact["authority_id"],
            "decision": "APPROVED",
            "request_artifact_sha256": artifact["request_artifact_sha256"],
            "request_file_sha256": raw_file_digest,
            "request_manifest_sha256": artifact["request_manifest_sha256"],
            "membership_sha256": artifact["membership_sha256"],
            "checkout_manifest_sha256": artifact["checkout_manifest_sha256"],
            "checkout_commit_sha256": artifact["checkout_commit_sha256"],
            "probe_terminal_sha256": artifact["probe_terminal_sha256"],
            "protected_state_sha256": descriptor.protected_state_sha256,
            "secret_identity_sha256": secret_identity,
            "provider_lane": artifact["provider_lane"],
            "endpoint": artifact["endpoint"],
            "model": artifact["model"],
            "member_count": artifact["member_count"],
            "first_pass_count": artifact["first_pass_count"],
            "max_retries": artifact["retry_policy"]["max_retries"],
            "max_attempts": artifact["retry_policy"]["max_attempts"],
            "concurrency": artifact["exposure_policy"]["concurrency"],
            "attempt_deadline_seconds": artifact["exposure_policy"][
                "attempt_deadline_seconds"
            ],
            "max_response_bytes": artifact["exposure_policy"]["max_response_bytes"],
            "reservation_micro_usd": artifact["exposure_policy"]["reservation_micro_usd"],
            "cumulative_exposure_micro_usd": artifact["exposure_policy"][
                "cumulative_cap_micro_usd"
            ],
        }
        approval = Fresh24ApprovalBinding.model_validate(
            {**approval_fields, "approval_sha256": canonical_sha256(approval_fields)}
        )
        status = Fresh24DurableAuthorityState(descriptor).install_approval(
            approval, request_artifact=artifact
        )
        _print_payload(status, json_output=args.json)
        return 0

    if args.command == "nvidia-fresh24-live":
        from itda.pipeline.phase5_fresh24 import (
            Fresh24DurableAuthorityState,
            execute_fresh24_production,
        )

        _require_minimal_probe_committed_clean_source()
        state_root = _fresh24_protected_root(args.protected_state_root)
        secret_file = _fresh24_secret_file(args.secret_env_file)
        terminal_path = _fresh24_terminal_output(args.terminal_output)
        if os.environ.get("ITDA_OFFLINE") == "1" or os.environ.get("ITDA_NO_NETWORK") == "1":
            raise PermissionError("LIVE_MODE_DISABLED")
        if os.environ.get("CI") or os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
            raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        artifact = _fresh24_load_public_artifact()
        plan, _checkout_commit = _fresh24_rebuild_and_validate_plan(artifact)
        descriptor = _fresh24_descriptor(state_root)
        durable = Fresh24DurableAuthorityState(descriptor)
        approval = durable.require_approval_matches_artifact(request_artifact=artifact)
        # Metadata/shape continuity only; the value is never read here.
        current_identity = _fresh24_secret_metadata_identity(secret_file)
        if current_identity != approval.secret_identity_sha256:
            raise PermissionError("FRESH24_SECRET_IDENTITY_MISMATCH")

        def read_secret(approval_binding: Fresh24ApprovalBinding) -> str:
            # Called only after RESERVE/DISPATCH are durable.  Verifies the
            # non-value metadata identity against the REOPENED approval
            # binding handed over by the sealed executor (never a caller's
            # copy), through one pinned descriptor; then returns the value
            # without echoing or digesting it.
            identity = _fresh24_secret_metadata_identity(secret_file)
            if identity != approval_binding.secret_identity_sha256:
                raise PermissionError("FRESH24_SECRET_IDENTITY_MISMATCH")
            descriptor_fd, before = _minimal_probe_open_secret(secret_file)
            try:
                raw = os.read(descriptor_fd, before.st_size + 1)
                after = os.fstat(descriptor_fd)
            finally:
                os.close(descriptor_fd)
            if len(raw) != before.st_size or _minimal_probe_secret_signature(
                before
            ) != _minimal_probe_secret_signature(after):
                raise PermissionError("FRESH24_SECRET_FILE_CHANGED_DURING_READ")
            return _minimal_probe_validate_secret_bytes(raw)

        claim = durable.claim_once(request_artifact=artifact)
        # No credential seam: the production entry point carries its own
        # import-time-bound fixed descriptor reader; the CLI-pinned lexical
        # reader is registered on the durable state so the executor hands the
        # reopened approval to it at reserve-before-secret time.
        result = execute_fresh24_production(
            plan=plan,
            state=durable.bind_credential_reader(read_secret),
            claim=claim,
            request_artifact=artifact,
        )
        _write_fresh24_terminal(terminal_path, result)
        _print_payload(
            {
                "status": result.get("status"),
                "reason": result.get("reason"),
                "attempt_count": result.get("attempt_count"),
                "network_attempted": result.get("network_attempted"),
            },
            json_output=args.json,
        )
        return 0

    if args.command == "nvidia-fresh24-reconcile":
        from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor
        from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

        state_root = _fresh24_protected_root(args.protected_state_root)
        terminal_path = _fresh24_terminal_output(args.terminal_output)
        artifact = _fresh24_load_public_artifact()
        plan, _checkout_commit = _fresh24_rebuild_and_validate_plan(artifact)
        descriptor = Fresh24ProtectedStateDescriptor.from_root(
            state_root=str(state_root)
        )
        durable = Fresh24DurableAuthorityState(descriptor)
        approval = durable.require_approval_matches_artifact(request_artifact=artifact)
        claim = durable.read_claim()
        terminal_payload = durable.reconcile_terminal(
            claim=claim,
            approval=approval,
            plan=plan,
            artifact=artifact,
        )
        if terminal_payload is None:
            raise PermissionError("FRESH24_RECONCILIATION_NOT_REQUIRED")
        _write_fresh24_terminal(terminal_path, terminal_payload)
        _print_payload(
            {
                "status": terminal_payload["status"],
                "reason": terminal_payload["reason"],
                "attempt_count": terminal_payload.get("attempt_count"),
                "committed_exposure_micro_usd": terminal_payload.get(
                    "committed_exposure_micro_usd"
                ),
                "network_attempted": False,
                "lifecycle_mutated": False,
            },
            json_output=args.json,
        )
        return 2

    print("USE_FRESH24_BOOTSTRAP_ENTRYPOINT", file=sys.stderr)
    return 2


def _openrouter_v2_capability_parser() -> argparse.ArgumentParser:
    """Parse distinct r2 names while Task 1 keeps every capability inert."""

    parser = argparse.ArgumentParser(description="openrouter r2 capability commands")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in sorted(_OPENROUTER_V2_CAPABILITY_COMMANDS):
        commands.add_parser(name)
    return parser


def _openrouter_v2_capability_run(args: argparse.Namespace) -> int:
    """Task 1 bootstrap target: unconditional pre-capability rejection."""

    if args.command not in _OPENROUTER_V2_CAPABILITY_COMMANDS:
        raise PermissionError("OPENROUTER_V2_CAPABILITY_NAME_INVALID")
    raise PermissionError("OPENROUTER_V2_CAPABILITY_INERT")


# ---------------------------------------------------------------------------
# OpenRouter r3/v3 capability dispatch (Plan 05-38).
#
# The public main NEVER reaches these handlers: the v3 capability names are
# rejected fail-closed with USE_OPENROUTER_V3_BOOTSTRAP_ENTRYPOINT.  Only the
# sanitized stdlib bootstrap entrypoint routes them here, and every mutating
# handler re-runs validate_capability_process() before its first state change.
# The v3 capability surface itself (install/live/reconcile execution) is
# activated by Plan 05-39's separate human gate; until then each handler is a
# sealed fail-closed boundary that performs NO secret, client, socket, or
# protected-root work — matching this plan's provider-free contract.
# ---------------------------------------------------------------------------


def _openrouter_v3_capability_run(args: argparse.Namespace) -> int:
    """Bootstrap target for the disjoint r3/v3 capability names."""

    from itda.cli.phase5_openrouter_recovery_v3 import V3_CAPABILITY_COMMANDS

    if args.command not in V3_CAPABILITY_COMMANDS:
        raise PermissionError("OPENROUTER_V3_CAPABILITY_NAME_INVALID")
    # Plan 05-38 keeps every r3/v3 capability sealed: no approval install,
    # claim, key-value read, client construction, socket, send, provider
    # attempt, protected-root creation, terminal, or lifecycle mutation.
    raise PermissionError("OPENROUTER_V3_CAPABILITY_SEALED_UNTIL_PLAN_05_39")


def _openrouter_v3_capability_dispatch(argv: list[str]) -> int:
    """Sanitized bootstrap dispatch for the disjoint r3/v3 names.

    Re-validates the process on every entry (same stdlib gate as production)
    before parsing any path or touching any state; fails closed before any
    capability effect while Plan 05-39 owns activation.
    """

    from itda.minimal_probe_bootstrap import validate_capability_process

    args = _openrouter_v3_capability_parser().parse_args(argv)
    try:
        validate_capability_process()
        return _openrouter_v3_capability_run(args)
    except (
        DemoProfileMaterializationError,
        FileExistsError,
        json.JSONDecodeError,
        OSError,
        PermissionError,
        RuntimeError,
        subprocess.CalledProcessError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        print("PHASE5_PROFILE_MATERIALIZATION_REJECTED", file=sys.stderr)
        return 2


def _openrouter_v3_capability_run_from_cli_module(argv: list[str]) -> int:
    """Delegation target for phase5_openrouter_recovery_v3.v3_capability_dispatch."""

    return _openrouter_v3_capability_dispatch(argv)


def _openrouter_v3_capability_parser() -> argparse.ArgumentParser:
    """Private parser for the disjoint r3/v3 capability commands."""

    parser = argparse.ArgumentParser(description="openrouter r3/v3 capability commands")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("openrouter-recovery-v3-install-approval")
    install.add_argument("--request", type=Path, required=True)
    install.add_argument("--protected-state-root", type=Path, required=True)
    install.add_argument("--secret-env-file", type=Path, required=True)
    install.add_argument("--approval-payload-sha256", required=True)
    install.add_argument("--json", action="store_true")
    live = commands.add_parser("openrouter-recovery-v3-live")
    live.add_argument("--request", type=Path, required=True)
    live.add_argument("--protected-state-root", type=Path, required=True)
    live.add_argument("--secret-env-file", type=Path, required=True)
    live.add_argument("--terminal-output", type=Path, required=True)
    live.add_argument("--json", action="store_true")
    reconcile = commands.add_parser("openrouter-recovery-v3-reconcile")
    reconcile.add_argument("--request", type=Path, required=True)
    reconcile.add_argument("--protected-state-root", type=Path, required=True)
    reconcile.add_argument("--terminal-output", type=Path, required=True)
    reconcile.add_argument("--json", action="store_true")
    return parser


def _openrouter_v2_capability_dispatch(argv: list[str]) -> int:
    """Distinct bootstrap dispatch that remains inert until Plan 05-38."""

    args = _openrouter_v2_capability_parser().parse_args(argv)
    return _openrouter_v2_capability_run(args)


def _openrouter_recovery_capability_parser() -> argparse.ArgumentParser:
    """Private parser for the OpenRouter recovery capability commands."""

    parser = argparse.ArgumentParser(description="openrouter recovery capability commands")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("openrouter-recovery-install-approval")
    install.add_argument("--request", type=Path, required=True)
    install.add_argument("--protected-state-root", type=Path, required=True)
    install.add_argument("--secret-env-file", type=Path, required=True)
    install.add_argument("--approval-payload-sha256", required=True)
    install.add_argument("--json", action="store_true")
    live = commands.add_parser("openrouter-recovery-live")
    live.add_argument("--request", type=Path, required=True)
    live.add_argument("--protected-state-root", type=Path, required=True)
    live.add_argument("--secret-env-file", type=Path, required=True)
    live.add_argument("--terminal-output", type=Path, required=True)
    live.add_argument("--json", action="store_true")
    reconcile = commands.add_parser("openrouter-recovery-reconcile")
    reconcile.add_argument("--request", type=Path, required=True)
    reconcile.add_argument("--protected-state-root", type=Path, required=True)
    reconcile.add_argument("--terminal-output", type=Path, required=True)
    reconcile.add_argument("--json", action="store_true")
    return parser


def _openrouter_request_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if (
        candidate != phase5_openrouter_recovery.OPENROUTER_REQUEST_OUTPUT
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise PermissionError("caller-selected openrouter request is forbidden")
    return candidate


def _openrouter_protected_root(path: Path) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if (
        candidate != phase5_openrouter_recovery.OPENROUTER_PROTECTED_ROOT
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise PermissionError("caller-selected openrouter protected root is forbidden")
    return candidate


def _openrouter_terminal_output(path: Path) -> Path:
    candidate = path if path.is_absolute() else REPOSITORY_ROOT / path
    if (
        candidate != phase5_openrouter_recovery.OPENROUTER_TERMINAL_OUTPUT
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise PermissionError("caller-selected openrouter terminal output is forbidden")
    return candidate


def _openrouter_secret_env_file(path: Path) -> Path:
    """Pin the OpenRouter secret to its fixed ignored env-file path.

    The file itself is created only during Plan 05-36 Task 1; this resolver
    validates the lexical path identity only and never reads a value.
    """

    expected = REPOSITORY_ROOT / ".secrets" / "itda-openrouter.env"
    resolved = (path if path.is_absolute() else REPOSITORY_ROOT / path).resolve(
        strict=False
    )
    if resolved != expected or any(
        part in {"", ".", ".."} for part in resolved.parts[1:]
    ):
        raise PermissionError("caller-selected openrouter secret file is forbidden")
    return resolved


def _openrouter_open_secret(path: Path) -> tuple[int, os.stat_result]:
    """Open the fixed OpenRouter secret via a lexical, no-follow ancestor chain."""

    from itda.cli.freeze_preview import open_directory_chain_no_follow

    expected = REPOSITORY_ROOT / ".secrets" / "itda-openrouter.env"
    if path != expected or not path.is_absolute():
        raise PermissionError("caller-selected openrouter secret file is forbidden")
    parent = open_directory_chain_no_follow(path.parent, create=False)
    try:
        parent_metadata = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise PermissionError("OPENROUTER_SECRET_DIRECTORY_IDENTITY_UNSAFE")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 0 < metadata.st_size <= 64 * 1024
    ):
        os.close(descriptor)
        raise PermissionError("OPENROUTER_SECRET_FILE_IDENTITY_UNSAFE")
    return descriptor, metadata


def _openrouter_secret_metadata_identity(path: Path) -> str:
    """Non-value continuity identity: inode/device/owner/mode/timestamps only.

    Never reads the key value, never derives any digest from its content, and
    never prints or returns value-derived material.
    """

    descriptor, before = _openrouter_open_secret(path)
    try:
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _minimal_probe_secret_signature(before) != _minimal_probe_secret_signature(after):
        raise PermissionError("OPENROUTER_SECRET_FILE_CHANGED_DURING_IDENTITY")
    return canonical_sha256(
        {
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "uid": before.st_uid,
            "nlink": before.st_nlink,
            "mode": stat.S_IMODE(before.st_mode),
        }
    )


def _openrouter_load_public_artifact() -> dict[str, Any]:
    """Load + revalidate the committed OpenRouter recovery packet."""

    artifact = _load_json(
        phase5_openrouter_recovery.OPENROUTER_REQUEST_OUTPUT,
        maximum_bytes=2 * 1024 * 1024,
    )
    required_keys = {
        "schema_version",
        "authority_id",
        "provider_lane",
        "endpoint",
        "model",
        "snapshot_relative_path",
        "snapshot_sha256",
        "snapshot_accessed_at",
        "snapshot_provenance_urls",
        "prompt_version",
        "prompt_sha256",
        "profile_schema_version",
        "preprocessing_version",
        "source_inventory_sha256",
        "source_authority_sha256",
        "source_install_receipt_sha256",
        "membership_sha256",
        "retention_profile",
        "reasoning_effort",
        "max_price",
        "price_status",
        "checkout_commit_sha256",
        "checkout_manifest_sha256",
        "first_pass_count",
        "member_count",
        "first_passes",
        "request_manifest_sha256",
        "retry_policy",
        "exposure_policy",
        "activation_suite_sha256",
        "contrast_suite_sha256",
        "blind_access",
        "secret_read",
        "provider_client_constructed",
        "network_attempted",
        "lifecycle_mutated",
        "historical_member_import",
        "request_artifact_sha256",
    }
    keys = set(artifact)
    missing = required_keys - keys
    extra = keys - required_keys
    if missing or extra:
        raise ValueError(
            f"openrouter public packet schema drifted (missing={sorted(missing)}, "
            f"extra={sorted(extra)})"
        )
    stored_digest = artifact.get("request_artifact_sha256")
    computed_digest = canonical_sha256(
        {key: value for key, value in artifact.items() if key != "request_artifact_sha256"}
    )
    if stored_digest != computed_digest:
        raise PermissionError("OPENROUTER_PUBLIC_PACKET_DIGEST_INVALID")
    return artifact


def _openrouter_rebuild_and_validate_plan(artifact: dict[str, Any]):
    from itda.pipeline.phase5_openrouter_recovery import (
        openrouter_checkout_commit_sha256,
        validate_openrouter_public_request,
    )

    source = phase5_openrouter_recovery.verify_fixed_source_authority()
    plan = phase5_openrouter_recovery.build_openrouter_plan(
        source,
        checkout_manifest_digest=(
            phase5_openrouter_recovery.checkout_manifest_sha256(REPOSITORY_ROOT)
        ),
    )
    validate_openrouter_public_request(
        artifact,
        plan=plan,
        checkout_commit_sha256=openrouter_checkout_commit_sha256(REPOSITORY_ROOT),
    )
    return plan


def _write_openrouter_terminal(path: Path, terminal: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(terminal)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PermissionError("openrouter terminal output cannot be a symlink")
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("openrouter terminal output already differs")
        return
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class _OpenRouterCapabilitySeal:
    """Capability token minted ONLY inside the dispatcher's closure (T-05R-98).

    There is deliberately NO recoverable module-global seal instance: every
    :func:`_openrouter_capability_dispatch` entry mints a fresh token inside a
    ``_make_openrouter_seal`` closure cell that no other code path can reach.
    A stolen or forged token is additionally worthless — each mutating
    handler re-runs the full stdlib ``validate_capability_process`` gate
    before ANY state change, so direct invocation fails closed even with a
    structurally valid token in hand.
    """

    __slots__ = ()


def _make_openrouter_seal() -> _OpenRouterCapabilitySeal:
    """The ONLY producer of a valid seal token (dispatcher-local)."""

    return _OpenRouterCapabilitySeal()


def _openrouter_capability_dispatch(argv: list[str]) -> int:
    """Internal dispatcher for OpenRouter recovery capability runs.

    Self-validating on every call via ``validate_capability_process`` — the
    same stdlib gate as the production bootstrap — then hands a FRESHLY
    MINTED dispatcher-local sealed token to the handler.
    """

    from itda.minimal_probe_bootstrap import validate_capability_process

    args = _openrouter_recovery_capability_parser().parse_args(argv)
    try:
        validate_capability_process()
        return _openrouter_capability_run(args, _seal=_make_openrouter_seal())
    except (
        DemoProfileMaterializationError,
        FileExistsError,
        json.JSONDecodeError,
        OSError,
        PermissionError,
        RuntimeError,
        subprocess.CalledProcessError,
        UnicodeError,
        ValidationError,
        ValueError,
    ):
        print("PHASE5_PROFILE_MATERIALIZATION_REJECTED", file=sys.stderr)
        return 2


def _openrouter_capability_run(
    args: argparse.Namespace, *, _seal: _OpenRouterCapabilitySeal
) -> int:
    """Mutating OpenRouter capability handlers behind the dispatcher seal.

    T-05R-98: the seal identity check runs first so a forged Namespace fails
    with the stable entrypoint hint; then EVERY mutating handler re-validates
    the full process (environment/import origin/checkout) BEFORE its first
    state change — a recovered or forged-but-well-typed token cannot reach
    install/claim/dispatch without passing the stdlib gate again.
    """

    if not isinstance(_seal, _OpenRouterCapabilitySeal):
        raise PermissionError("USE_OPENROUTER_BOOTSTRAP_ENTRYPOINT")

    def _revalidate_capability_process() -> None:
        from itda.minimal_probe_bootstrap import validate_capability_process

        validate_capability_process()

    if args.command == "openrouter-recovery-install-approval":
        from itda.contracts.phase5_openrouter_recovery import (
            OpenRouterApprovalBinding,
            OpenRouterProtectedStateDescriptor,
            load_openrouter_snapshot,
        )

        _revalidate_capability_process()
        _require_minimal_probe_committed_clean_source()
        request_path = _openrouter_request_path(args.request)
        state_root = _openrouter_protected_root(args.protected_state_root)
        secret_env_file = _openrouter_secret_env_file(args.secret_env_file)
        del request_path
        packet_raw_bytes = phase5_openrouter_recovery.read_fixed_public_packet_bytes()
        artifact = _openrouter_load_public_artifact()
        semantic_digest, raw_file_digest = (
            phase5_openrouter_recovery.openrouter_packet_digest_domains(
                json.loads(packet_raw_bytes)
            )
        )
        if semantic_digest != str(artifact.get("request_artifact_sha256")):
            raise PermissionError("OPENROUTER_PACKET_SEMANTIC_DIGEST_DRIFT")
        if hashlib.sha256(packet_raw_bytes).hexdigest() != raw_file_digest:
            raise PermissionError("OPENROUTER_PACKET_RAW_DIGEST_DRIFT")
        if artifact.get("request_artifact_sha256") != args.approval_payload_sha256:
            raise PermissionError("OPENROUTER_APPROVAL_MISMATCH")
        _openrouter_rebuild_and_validate_plan(artifact)
        # Non-value metadata continuity identity of the FIXED ignored secret
        # file: no-follow open/fstat stable tuple only.  Never a value, length
        # prefix, or content digest; never the packet digest.
        secret_identity = _openrouter_secret_metadata_identity(secret_env_file)
        descriptor = OpenRouterProtectedStateDescriptor.from_root(
            state_root=str(state_root)
        )
        approval_fields = {
            "schema_version": "itda.phase5-openrouter-approval.v1",
            "authority_id": artifact["authority_id"],
            "decision": "APPROVED",
            "request_artifact_sha256": artifact["request_artifact_sha256"],
            "request_file_sha256": raw_file_digest,
            "request_manifest_sha256": artifact["request_manifest_sha256"],
            "membership_sha256": artifact["membership_sha256"],
            "checkout_manifest_sha256": artifact["checkout_manifest_sha256"],
            "checkout_commit_sha256": artifact["checkout_commit_sha256"],
            "protected_state_sha256": str(descriptor.protected_state_sha256),
            "secret_identity_sha256": secret_identity,
            "snapshot_sha256": str(load_openrouter_snapshot().snapshot_sha256),
        }
        # T-05R-98: the approval digest MUST be computed over the COMPLETE
        # final payload including schema defaults.  Build the full field map
        # first, derive the contract's own dump (every default materialized),
        # and hash exactly that — a digest over a partial preimage can never
        # validate against the contract's self-digest recomputation.
        complete_fields: dict[str, object] = {
            **approval_fields,
            "provider_lane": artifact["provider_lane"],
            "endpoint": artifact["endpoint"],
            "model": artifact["model"],
            **{
                key: artifact[key]
                for key in (
                    "member_count",
                    "first_pass_count",
                )
            },
            "max_retries": artifact["retry_policy"]["max_retries"],
            "max_attempts": artifact["retry_policy"]["max_attempts"],
            "concurrency": artifact["exposure_policy"]["concurrency"],
            "attempt_deadline_seconds": artifact["exposure_policy"][
                "attempt_deadline_seconds"
            ],
            "max_response_bytes": artifact["exposure_policy"]["max_response_bytes"],
            "reservation_micro_usd": artifact["exposure_policy"][
                "reservation_micro_usd"
            ],
            "cumulative_exposure_micro_usd": artifact["exposure_policy"][
                "cumulative_cap_micro_usd"
            ],
        }
        probe = OpenRouterApprovalBinding.model_construct(**complete_fields)  # type: ignore[arg-type]
        final_payload = probe.model_dump(mode="json", exclude={"approval_sha256"})
        approval = OpenRouterApprovalBinding.model_validate(
            {**final_payload, "approval_sha256": canonical_sha256(final_payload)}
        )
        state = phase5_openrouter_recovery.OpenRouterDurableAuthorityState(descriptor)
        status = state.install_approval(
            approval, request_artifact=artifact
        )
        _print_payload(status, json_output=args.json)
        return 0

    if args.command == "openrouter-recovery-live":
        from itda.contracts.phase5_openrouter_recovery import (
            OpenRouterProtectedStateDescriptor,
        )

        _revalidate_capability_process()
        # The single live invocation belongs to Plan 05-36 with its own secret
        # checkpoint and explicit human traffic decision; the offline/network
        # gates below keep every test and CI environment fail-closed.
        if os.environ.get("ITDA_OFFLINE") == "1" or os.environ.get("ITDA_NO_NETWORK") == "1":
            raise PermissionError("LIVE_MODE_DISABLED")
        if os.environ.get("CI") or os.environ.get("ITDA_PROVIDER_NETWORK") != "1":
            raise PermissionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        _require_minimal_probe_committed_clean_source()
        state_root = _openrouter_protected_root(args.protected_state_root)
        secret_env_file = _openrouter_secret_env_file(args.secret_env_file)
        terminal_path = _openrouter_terminal_output(args.terminal_output)
        artifact = _openrouter_load_public_artifact()
        plan = _openrouter_rebuild_and_validate_plan(artifact)
        descriptor = OpenRouterProtectedStateDescriptor.from_root(
            state_root=str(state_root)
        )
        durable = phase5_openrouter_recovery.OpenRouterDurableAuthorityState(descriptor)
        approval = durable.require_approval_matches_artifact(request_artifact=artifact)
        # Metadata/shape continuity only; the value is never read here.  The
        # CLI creates and passes NO credential reader (T-05R-98): the zero-arg
        # production entry internally re-derives the FIXED reader from the
        # repository-owned fixed env-file constants.
        current_identity = _openrouter_secret_metadata_identity(secret_env_file)
        if current_identity != str(approval.secret_identity_sha256):
            raise PermissionError("OPENROUTER_SECRET_IDENTITY_MISMATCH")

        durable.claim_once(request_artifact=artifact)
        result = phase5_openrouter_recovery.execute_openrouter_production()
        _write_openrouter_terminal(terminal_path, result)
        _print_payload(
            {
                "status": result.get("status"),
                "reason": result.get("reason"),
                "attempt_count": result.get("attempt_count"),
                "network_attempted": result.get("network_attempted"),
            },
            json_output=args.json,
        )
        return 0

    if args.command == "openrouter-recovery-reconcile":
        from itda.contracts.phase5_openrouter_recovery import (
            OpenRouterProtectedStateDescriptor,
        )

        _revalidate_capability_process()
        state_root = _openrouter_protected_root(args.protected_state_root)
        terminal_path = _openrouter_terminal_output(args.terminal_output)
        artifact = _openrouter_load_public_artifact()
        plan = _openrouter_rebuild_and_validate_plan(artifact)
        descriptor = OpenRouterProtectedStateDescriptor.from_root(
            state_root=str(state_root)
        )
        durable = phase5_openrouter_recovery.OpenRouterDurableAuthorityState(descriptor)
        approval = durable.require_approval_matches_artifact(request_artifact=artifact)
        claim = durable.read_claim()
        terminal_payload = durable.reconcile_terminal(
            claim=claim,
            approval=approval,
            plan=plan,
            artifact=artifact,
        )
        if terminal_payload is None:
            raise PermissionError("OPENROUTER_RECONCILIATION_NOT_REQUIRED")
        _write_openrouter_terminal(terminal_path, terminal_payload)
        _print_payload(
            {
                "status": terminal_payload["status"],
                "reason": terminal_payload["reason"],
                "attempt_count": terminal_payload.get("attempt_count"),
                "committed_exposure_micro_usd": terminal_payload.get(
                    "committed_exposure_micro_usd"
                ),
                "network_attempted": bool(terminal_payload.get("network_attempted")),
                "lifecycle_mutated": bool(terminal_payload.get("lifecycle_mutated")),
            },
            json_output=args.json,
        )
        return 2

    print("USE_OPENROUTER_BOOTSTRAP_ENTRYPOINT", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
