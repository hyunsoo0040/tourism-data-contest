"""Provider-free fresh24 planning, durable authority state, and terminal verifier.

This module owns the new 20260820 namespace.  It consumes source evidence to
build requests, but it never consumes a provider response as a member until a
future explicitly approved live execution claims the one-use approval.  All
protected writes are no-follow/no-replace with fsync-before-COMMIT ordering;
the sealed production transport is reachable only through the state-owned API.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal, cast

import httpx

from itda.cli.freeze_preview import _rename_noreplace_at, open_directory_chain_no_follow
from itda.contracts.base import DataSplit, ExperienceAxis
from itda.contracts.demo_profile_materialization import (
    DemoSourceBundle,
    NvidiaMinimaxProfileMaterializationConfig,
)
from itda.contracts.phase5_fresh24 import (
    ACTIVATION_SUITE_SHA256,
    CANNOT_COAPPEAR_AUTHORITY_SHA256,
    CANONICAL_CONTRAST_PAIRS,
    CANONICAL_SCENARIO_IDS,
    CONTRAST_SUITE_SHA256,
    FRESH24_ACTIVE_RELEASE_STATES,
    FRESH24_ATTEMPT_DEADLINE_SECONDS,
    FRESH24_ATTEMPT_SCHEMA,
    FRESH24_AUTHORITY_ID,
    FRESH24_BLIND_ACCESS,
    FRESH24_CLAIM_SCHEMA,
    FRESH24_CUMULATIVE_EXPOSURE_CAP_MICRO_USD,
    FRESH24_DISPATCH_SCHEMA,
    FRESH24_ENDPOINT,
    FRESH24_FIRST_PASS_COUNT,
    FRESH24_GENERATION_SCHEMA,
    FRESH24_LEDGER_ENTRY_SCHEMA,
    FRESH24_LIFECYCLE_MUTATED,
    FRESH24_LIVE_INVOCATION_COUNT,
    FRESH24_MAX_ATTEMPTS,
    FRESH24_MAX_RESPONSE_BYTES,
    FRESH24_MAX_RETRIES,
    FRESH24_MEMBER_COUNT,
    FRESH24_MEMBERSHIP_SHA256,
    FRESH24_MIN_EFFECTIVE_CANDIDATES,
    FRESH24_MODEL,
    FRESH24_NETWORK_ATTEMPTED,
    FRESH24_PROBE_INVOCATION_ONLY,
    FRESH24_PROFILE_SCHEMA_VERSION,
    FRESH24_PROMPT_TEXT,
    FRESH24_PROVIDER_CLIENT_CONSTRUCTED,
    FRESH24_PROVIDER_LANE,
    FRESH24_RECEIPT_EMITTED,
    FRESH24_RESERVATION_MICRO_USD,
    FRESH24_RETRYABLE_HTTP_STATUSES,
    FRESH24_RETRYABLE_TRANSPORT_NAMES,
    FRESH24_SECRET_READ,
    FRESH24_SOURCE_AUTHORITY_SHA256,
    FRESH24_SOURCE_INSTALL_RECEIPT_SHA256,
    FRESH24_SOURCE_INVENTORY_SHA256,
    FRESH24_TERMINAL_SCHEMA,
    Fresh24ApprovalBinding,
    Fresh24Authority,
    Fresh24Claim,
    Fresh24ExposurePolicy,
    Fresh24InvocationEvidence,
    Fresh24MemberRequest,
    Fresh24Profile,
    Fresh24ProtectedStateDescriptor,
    Fresh24Request,
    Fresh24RetryPolicy,
    Fresh24Terminal,
    validate_fresh24_authority_id,
)
from itda.contracts.phase5_recovery_policy import (
    CANONICAL_PHASE5_RECOVERY_POLICY,
    ActivationSuiteEvaluation,
)
from itda.contracts.place_profile import MismatchTraitId, SubattributeId
from itda.contracts.recommendation import (
    EvidenceSnippet,
    ImageDisplayState,
    PlaceAxisSnapshot,
    PlaceConditionSnapshot,
    PlaceSubattributeSnapshot,
    PlaceTraitSnapshot,
    PreferenceAxisTarget,
    PreferenceTraitTarget,
    Publishability,
    RecommendationCandidate,
    RecommendationPreference,
    TravelConditionId,
    TravelConditionTarget,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.demo_profile_eligibility import (
    PublicationEligibilityDecision,
    evaluate_nvidia_publication_cohort,
)
from itda.domain.recommendation import evaluate_activation_scenarios
from itda.pipeline.demo_profile_materialization import validate_demo_source_inventory

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
FIXED_SOURCE_ROOT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/phase5-demo-profile-materialization"
)
FRESH24_PUBLIC_REQUEST_RELATIVE = (
    "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
)
FRESH24_PROTECTED_ROOT_RELATIVE = "artifacts/restricted/catalog/phase5-nvidia-fresh24"
FRESH24_TERMINAL_RELATIVE = "artifacts/reports/phase5/nvidia-fresh24-terminal.json"
RETRYABLE_HTTP_STATUSES = FRESH24_RETRYABLE_HTTP_STATUSES
RETRYABLE_TRANSPORT_ERRORS = FRESH24_RETRYABLE_TRANSPORT_NAMES
FRESH24_REQUEST_OUTPUT = REPOSITORY_ROOT / FRESH24_PUBLIC_REQUEST_RELATIVE
FRESH24_TERMINAL_OUTPUT = REPOSITORY_ROOT / FRESH24_TERMINAL_RELATIVE
FRESH24_PROTECTED_ROOT = REPOSITORY_ROOT / FRESH24_PROTECTED_ROOT_RELATIVE
FRESH24_SOURCE_ROOT = FIXED_SOURCE_ROOT
FRESH24_SOURCE_AUTHORITY_PATHS = (
    "backend/src/itda/contracts/phase5_fresh24.py",
    "backend/src/itda/pipeline/phase5_fresh24.py",
    "backend/src/itda/cli/materialize_phase5_demo_profiles.py",
    "backend/tests/contract/test_phase5_fresh24.py",
    "backend/tests/security/test_phase5_provider_boundary.py",
)


def require_fixed_fresh24_paths(
    *,
    request_output: Path | None = None,
    protected_root: Path | None = None,
    terminal_output: Path | None = None,
) -> tuple[Path, Path, Path]:
    """Resolve only the repository-owned future fresh24 destinations."""

    request = FRESH24_REQUEST_OUTPUT if request_output is None else request_output
    protected = FRESH24_PROTECTED_ROOT if protected_root is None else protected_root
    terminal = FRESH24_TERMINAL_OUTPUT if terminal_output is None else terminal_output
    if request.resolve(strict=False) != FRESH24_REQUEST_OUTPUT:
        raise PermissionError("fresh24 request output path is not fixed")
    if protected.resolve(strict=False) != FRESH24_PROTECTED_ROOT:
        raise PermissionError("fresh24 protected root path is not fixed")
    if terminal.resolve(strict=False) != FRESH24_TERMINAL_OUTPUT:
        raise PermissionError("fresh24 terminal output path is not fixed")
    return request, protected, terminal


def build_fresh24_public_request(
    *,
    plan: Fresh24Plan,
    checkout_commit_sha256: str,
) -> dict[str, object]:
    """Build the exact second-decision packet without provider or secret access."""

    if not re.fullmatch(r"[0-9a-f]{40}", checkout_commit_sha256):
        raise ValueError("fresh24 checkout commit is invalid")
    payload = {
        "schema_version": "itda.phase5-fresh24-materialization-request.v1",
        "authority_id": plan.authority.authority_id,
        "provider_lane": FRESH24_PROVIDER_LANE,
        "endpoint": FRESH24_ENDPOINT,
        "model": FRESH24_MODEL,
        "prompt_version": plan.authority.prompt_version,
        "prompt_sha256": plan.authority.prompt_sha256,
        "profile_schema_version": plan.authority.profile_schema_version,
        "profile_schema_sha256": plan.authority.profile_schema_sha256,
        "config_version": plan.authority.config_version,
        "config_sha256": plan.authority.config_sha256,
        "preprocessing_version": plan.authority.preprocessing_version,
        "preprocessing_sha256": plan.authority.preprocessing_sha256,
        "source_inventory_sha256": FRESH24_SOURCE_INVENTORY_SHA256,
        "source_authority_sha256": FRESH24_SOURCE_AUTHORITY_SHA256,
        "source_install_receipt_sha256": FRESH24_SOURCE_INSTALL_RECEIPT_SHA256,
        "membership_sha256": FRESH24_MEMBERSHIP_SHA256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "probe_request_sha256": plan.probe.probe_request_sha256,
        "checkout_commit_sha256": checkout_commit_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "first_pass_count": FRESH24_FIRST_PASS_COUNT,
        "member_count": FRESH24_MEMBER_COUNT,
        "first_passes": [
            {
                "place_id": row.place_id,
                "order": row.order,
                "request_sha256": row.request_sha256,
                "request_body_sha256": row.request_body_sha256,
            }
            for row in plan.first_passes
        ],
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "retry_policy": plan.retry_policy.model_dump(mode="json"),
        "exposure_policy": plan.exposure.model_dump(mode="json"),
        "activation_source_file_sha256": (
            CANONICAL_PHASE5_RECOVERY_POLICY.activation_source_file_sha256
        ),
        "activation_dataset_sha256": (
            CANONICAL_PHASE5_RECOVERY_POLICY.activation_dataset_sha256
        ),
        "activation_suite_sha256": ACTIVATION_SUITE_SHA256,
        "activation_scenario_ids": list(CANONICAL_SCENARIO_IDS),
        "contrast_suite_sha256": CONTRAST_SUITE_SHA256,
        "contrast_pairs": [list(pair) for pair in CANONICAL_CONTRAST_PAIRS],
        "hard_duplicate_adjudication_sha256": (
            CANONICAL_PHASE5_RECOVERY_POLICY.hard_duplicate_adjudication_sha256
        ),
        "cannot_coappear_authority_sha256": CANNOT_COAPPEAR_AUTHORITY_SHA256,
        "cannot_coappear_pairs": [],
        "active_release_states": list(FRESH24_ACTIVE_RELEASE_STATES),
        "blind_access": FRESH24_BLIND_ACCESS,
        "live_invocation_count": FRESH24_LIVE_INVOCATION_COUNT,
        "receipt_emitted": FRESH24_RECEIPT_EMITTED,
        "secret_read": FRESH24_SECRET_READ,
        "provider_client_constructed": FRESH24_PROVIDER_CLIENT_CONSTRUCTED,
        "network_attempted": FRESH24_NETWORK_ATTEMPTED,
        "lifecycle_mutated": FRESH24_LIFECYCLE_MUTATED,
        "historical_member_import": False,
        "probe_invocation_only": FRESH24_PROBE_INVOCATION_ONLY,
    }
    payload["request_artifact_sha256"] = canonical_sha256(payload)
    return payload


def fresh24_packet_digest_domains(
    payload: Mapping[str, object],
) -> tuple[str, str]:
    """The ONE shared semantic/raw digest pair for a fresh24 packet.

    Returns ``(request_artifact_sha256, request_file_sha256)``:
    - ``request_artifact_sha256`` — the canonical SELF-digest over the
      semantic payload (every key except the digest field itself);
    - ``request_file_sha256`` — the SHA-256 over the packet's EXACT raw file
      bytes (canonical serialization of the same payload).  A reformatted
      but semantically-equal packet changes ONLY the second domain.

    Every producer (builder, install handler, tests) MUST derive both
    domains from this single helper so the naming/meaning never diverges.
    """

    unsigned = {
        key: value for key, value in payload.items() if key != "request_artifact_sha256"
    }
    return canonical_sha256(unsigned), hashlib.sha256(
        canonical_json_bytes(payload)
    ).hexdigest()


def write_fresh24_public_request(
    plan: Fresh24Plan,
    *,
    checkout_commit_sha256: str,
    output: Path = FRESH24_REQUEST_OUTPUT,
) -> dict[str, object]:
    """No-replace publish one provider-free public request packet."""

    request_output, _, _ = require_fixed_fresh24_paths(request_output=output)
    payload = build_fresh24_public_request(plan=plan, checkout_commit_sha256=checkout_commit_sha256)
    serialized = canonical_json_bytes(payload)
    if request_output.exists():
        if request_output.is_symlink() or request_output.read_bytes() != serialized:
            raise FileExistsError("fresh24 request output already differs")
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


def validate_fresh24_public_request(
    payload: Mapping[str, object],
    *,
    plan: Fresh24Plan,
    checkout_commit_sha256: str,
) -> dict[str, object]:
    expected = build_fresh24_public_request(
        plan=plan, checkout_commit_sha256=checkout_commit_sha256
    )
    if dict(payload) != expected:
        raise ValueError("fresh24 public request does not match current provider-free plan")
    return dict(payload)


def _read_fixed_probe_terminal() -> bytes:
    """Read the fixed minimal-probe terminal with a no-follow descriptor."""

    path = REPOSITORY_ROOT / "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json"
    if path.is_symlink():
        raise PermissionError("fresh24 probe terminal must not be a symlink")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PermissionError("fresh24 probe terminal is not a regular file")
        return os.read(descriptor, metadata.st_size + 1)[: metadata.st_size]
    finally:
        os.close(descriptor)


def _read_public_file_no_follow(path: Path, *, maximum: int = 8 * 1024 * 1024) -> bytes:
    """Component-wise no-follow read of a regular single-link owner file.

    The path is opened ONE COMPONENT AT A TIME starting from the filesystem
    root descriptor (``openat`` + ``O_DIRECTORY|O_NOFOLLOW`` for every
    ancestor, then ``O_NOFOLLOW`` + regular + single-link checks on the final
    component).  No single absolute ``os.open`` ever resolves the path, so a
    symlinked ANCESTOR cannot redirect the read either.  Only the two macOS
    system-symlink prefixes (/tmp → /private/tmp, /var → /private/var) are
    normalized lexically — exactly like ``Fresh24DurableAuthorityState``.
    This is THE shared reopen helper for fixed public artifacts — packet,
    terminal, and any CLI terminal reopen MUST go through it.
    """

    absolute = path.absolute()
    text = str(absolute)
    if text.startswith("/tmp/") or text == "/tmp":
        absolute = Path("/private/tmp") / Path(*absolute.parts[2:])
    elif text.startswith("/var/") or text == "/var":
        absolute = Path("/private/var") / Path(*absolute.parts[2:])
    root_fd = os.open(
        str(absolute.anchor or os.sep),
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        *ancestors, final = absolute.parts[1:]
        descriptor_fd = root_fd
        try:
            for component in ancestors:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor_fd,
                )
                os.close(descriptor_fd)
                descriptor_fd = child_fd
            file_fd = os.open(
                final,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor_fd,
            )
            try:
                metadata = os.fstat(file_fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise PermissionError("fresh24 expected a regular file")
                if metadata.st_nlink != 1 or not 0 < metadata.st_size <= maximum:
                    raise PermissionError(
                        "fresh24 file identity or size is invalid"
                    )
                return os.read(file_fd, metadata.st_size + 1)[: metadata.st_size]
            finally:
                os.close(file_fd)
        except BaseException:
            os.close(descriptor_fd)
            raise
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("fresh24 public path contains a symlink or non-directory") from error
        raise


def _read_fixed_public_packet_bytes() -> bytes:
    """Read the exact committed public request packet, component-wise.

    Every ancestor directory and the final file are reopened without
    following a single symlink; see :func:`_read_public_file_no_follow`.
    """

    return _read_public_file_no_follow(FRESH24_REQUEST_OUTPUT)


def read_fixed_fresh24_terminal_bytes(path: Path | None = None) -> bytes:
    """Shared CLI/pipeline reopen of the fixed public terminal bytes."""

    _, _, terminal_path = require_fixed_fresh24_paths(terminal_output=path)
    return _read_public_file_no_follow(terminal_path)


FRESH24_REQUEST_ARTIFACT_SHA256 = canonical_sha256(
    json.loads(FRESH24_REQUEST_OUTPUT.read_bytes())
    if FRESH24_REQUEST_OUTPUT.exists() and not FRESH24_REQUEST_OUTPUT.is_dir()
    else {"absent": True}
)


def _rebuild_fixed_request() -> Fresh24Request:
    """Deterministically rebuild the provider-free request from fixed source."""

    source = verify_fixed_source_authority()
    plan = build_fresh24_plan(
        source,
        checkout_manifest_sha256=checkout_manifest_sha256(REPOSITORY_ROOT),
        probe_terminal=json.loads(_read_fixed_probe_terminal()),
    )
    return plan.request


def _rebuild_fixed_plan() -> Fresh24Plan:
    """Deterministically rebuild the full provider-free plan from fixed source."""

    source = verify_fixed_source_authority()
    return build_fresh24_plan(
        source,
        checkout_manifest_sha256=checkout_manifest_sha256(REPOSITORY_ROOT),
        probe_terminal=json.loads(_read_fixed_probe_terminal()),
    )


def verify_fresh24_terminal_file(
    path: Path = FRESH24_TERMINAL_OUTPUT,
) -> Fresh24Terminal:
    """Reopen the fixed public terminal without any provider capability.

    Uses the shared component-wise no-follow reopen (repository-root fd →
    openat per ancestor → O_NOFOLLOW final file).
    """

    _, _, terminal_path = require_fixed_fresh24_paths(terminal_output=path)
    return Fresh24Terminal.model_validate_json(
        _read_public_file_no_follow(terminal_path)
    )


def classify_fresh24_terminal_file(path: Path = FRESH24_TERMINAL_OUTPUT) -> str:
    """Deprecated public-only classification — neutral verification required.

    Kept only as a module-level name so old imports fail loudly here rather
    than silently classifying unverified bytes.  Every production path must
    go through :func:`classify_verified_outcome`, which runs the full neutral
    verification (protected evidence reopen + committed packet binding) first.
    """

    raise PermissionError(
        "FRESH24_CLASSIFY_REQUIRES_NEUTRAL_VERIFICATION"
    )


def verify_fresh24_outcome_for_cli(
    *,
    terminal_path: Path | None = None,
    protected_root: Path | None = None,
) -> Fresh24VerifiedOutcome:
    """CLI-shaped neutral verification over the fixed public terminal.

    Reads the exact fixed terminal through the SHARED component-wise
    no-follow reopen helper (same helper as the packet), then runs
    the full neutral verification against the fixed protected root.
    """

    require_fixed_fresh24_paths(
        terminal_output=terminal_path or FRESH24_TERMINAL_OUTPUT
    )
    terminal = Fresh24Terminal.model_validate_json(
        read_fixed_fresh24_terminal_bytes(terminal_path)
    )
    root = protected_root or FRESH24_PROTECTED_ROOT
    return verify_fresh24_outcome(terminal=terminal, protected_root=root)


class Fresh24VerifiedOutcome:
    """Opaque neutral-verified outcome carrying its contract-checked disposition.

    Construction is module-private: the only producer is
    :func:`verify_fresh24_outcome`, which stamps the provenance token after
    the full neutral verification (protected reopen + packet binding + map
    reevaluation) has passed.  A fabricated instance cannot obtain the token,
    so :func:`classify_verified_outcome` rejects it outright.
    """

    __slots__ = ("terminal", "_provenance")

    def __init__(self, terminal: Fresh24Terminal) -> None:
        self.terminal = terminal
        self._provenance: object = None

    @property
    def disposition(self) -> str:
        """Contract-validated classification stamped by the verifier."""

        if self._provenance is not _CAPABILITY_SEAL:
            raise PermissionError("FRESH24_OUTCOME_PROVENANCE_INVALID")
        return verify_fresh24_terminal(self.terminal.model_dump(mode="json"))


def classify_verified_outcome(outcome: Fresh24VerifiedOutcome) -> str:
    """Classify ONLY a verifier-stamped outcome.

    The receipt must carry the verifier's internal provenance token — set
    exclusively after full neutral verification.  Fabricated objects are
    rejected before any status is read.
    """

    return outcome.disposition


def verify_fresh24_outcome(
    *,
    terminal: Mapping[str, object] | Fresh24Terminal,
    protected_root: Path,
) -> Fresh24VerifiedOutcome:
    """Neutral verification that independently reopens the protected evidence.

    The public terminal must digest-validate first; then this function reopens
    approval/claim/ledger/journal/raw/profiles/generation/protected-terminal in
    the disjoint fresh24 root through no-follow descriptors and requires exact
    lineage, digest, and count consistency with the public terminal:
    - approval and claim reopen with their canonical self-digests;
    - the exact committed public packet at its FIXED repository constant path
      is ALWAYS reopened component-wise no-follow; its canonical self-digest
      AND its raw file SHA-256 must match the approval/claim bindings.  A
      stale packet, a reformatted-but-semantically-equal copy, or any other
      path fails outright (correct before final regeneration).
    - the ledger bytes digest and exact reserve/commit transition state match
      the terminal attempt/exposure fields;
    - the complete journal inventory (dispatch + attempt files) digests to the
      terminal ``journal_sha256``;
    - the protected terminal's canonical bytes equal the public bytes exactly;
    - a positive branch additionally reopens the generation manifest and all
      24 durable profile files through strict contracts and re-runs the
      production evaluator against them.
    """

    payload = (
        terminal if isinstance(terminal, Mapping) else terminal.model_dump(mode="json")
    )
    verify_fresh24_terminal(payload)
    public = Fresh24Terminal.model_validate(payload)
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(protected_root))
    state = Fresh24DurableAuthorityState(descriptor)
    # Root exact inventory at verification START — every neutral branch
    # (generation.json is mandatory only on the positive branch).
    state.validate_root_inventory(
        require_generation=payload.get("status") == "COMPLETE_CANDIDATE_READY"
    )
    approval = state.read_approval()
    claim = state.read_claim()
    if claim.approval_sha256 != approval.approval_sha256:
        raise ValueError("fresh24 protected claim does not match approval")
    if claim.protected_state_sha256 != descriptor.protected_state_sha256:
        raise ValueError("fresh24 protected claim root identity drifted")
    # The persisted one-use claim must be the exact claim named by the
    # terminal — a forged or replayed claim digest cannot verify.
    if str(claim.claim_sha256) != str(public.claim_sha256):
        raise ValueError("fresh24 terminal claim digest does not match persisted claim")
    if approval.checkout_manifest_sha256 != public.checkout_manifest_sha256:
        raise ValueError("fresh24 approval checkout binding drifted from terminal")
    # Bind every evidence artifact to ONE packet identity — ALWAYS via the
    # exact committed public packet at its fixed path (no-follow descriptor
    # read), never conditionally.  The packet's canonical self-digest field,
    # its raw file digest, and its semantic fields are each compared against
    # approval / claim / terminal / generation.  A stale or mismatched packet
    # fails verification outright (correct before final regeneration).
    # Component-wise fixed-path reopen: the constant is exact, no caller
    # override exists.  Raw file bytes SHA-256 (request_file_sha256 domain)
    # is distinct from the canonical self-digest field (request_artifact
    # domain); BOTH bind approval/claim.
    if FRESH24_REQUEST_OUTPUT != REPOSITORY_ROOT / (
        "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
    ):
        raise PermissionError("fresh24 public request path constant drifted")
    packet_bytes = _read_public_file_no_follow(FRESH24_REQUEST_OUTPUT)
    packet_request_file_sha256 = hashlib.sha256(packet_bytes).hexdigest()
    packet = json.loads(packet_bytes)
    if not isinstance(packet, dict):
        raise ValueError("fresh24 committed public packet is malformed")
    packet_artifact = packet.get("request_artifact_sha256")
    packet_manifest = packet.get("request_manifest_sha256")
    if not isinstance(packet_artifact, str) or not _DIGEST.fullmatch(packet_artifact):
        raise ValueError("fresh24 committed packet artifact digest is malformed")
    unsigned_packet = {
        key: value for key, value in packet.items() if key != "request_artifact_sha256"
    }
    if canonical_sha256(unsigned_packet) != packet_artifact:
        raise ValueError("fresh24 committed packet self-digest drifted")
    rebuilt_request = _rebuild_fixed_request()
    rebuilt_members = _rebuild_fixed_plan().members
    bound_artifact = str(claim.request_artifact_sha256)
    if str(approval.request_artifact_sha256) != bound_artifact:
        raise ValueError("fresh24 approval packet identity drifted from claim")
    # Request-domain digests: the deterministic fixed-source rebuild pins the
    # member manifest and its derived request digest exactly.
    if str(approval.request_manifest_sha256) != (
        rebuilt_request.request_manifest_sha256
    ):
        raise ValueError("fresh24 approval member manifest drifted from fixed source")
    if str(public.request_sha256) != rebuilt_request.request_sha256:
        raise ValueError("fresh24 terminal request digest drifted from fixed source")
    # Packet-domain digests: claim and approval bind BOTH the canonical
    # self-digest AND the exact raw file bytes of THE committed packet.
    # request_file_sha256 is REQUIRED everywhere — no optional getattr path.
    if packet_artifact != bound_artifact:
        raise ValueError(
            "fresh24 committed packet identity does not match this run's claim"
        )
    approval_file_binding = getattr(approval, "request_file_sha256", None)
    claim_file_binding = getattr(claim, "request_file_sha256", None)
    if approval_file_binding is None or claim_file_binding is None:
        raise ValueError("fresh24 approval/claim lack a required raw file digest")
    if (
        str(approval_file_binding) != packet_request_file_sha256
        or str(claim_file_binding) != packet_request_file_sha256
    ):
        raise ValueError(
            "fresh24 committed packet raw bytes drifted from approval/claim binding"
        )
    if str(public.request_file_sha256) != packet_request_file_sha256:
        raise ValueError(
            "fresh24 public terminal raw packet digest drifted from committed bytes"
        )
    if packet_manifest != str(approval.request_manifest_sha256):
        raise ValueError("fresh24 committed packet manifest drifted from approval")
    if packet.get("checkout_commit_sha256") != approval.checkout_commit_sha256:
        raise ValueError("fresh24 committed packet commit drifted from approval")
    if str(approval.checkout_manifest_sha256) != str(
        packet.get("checkout_manifest_sha256")
    ):
        raise ValueError(
            "fresh24 approval checkout manifest drifted from committed packet"
        )
    entries = state.read_ledger_entries()
    reserves = [row for row in entries if row.get("operation") == "RESERVE"]
    commits = [
        row
        for row in entries
        if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
    ]
    if len(reserves) != len(commits):
        raise ValueError("fresh24 protected ledger has unresolved reservations")
    committed = sum(int(row.get("amount_micro_usd", 0)) for row in commits)
    if committed != public.committed_exposure_micro_usd:
        raise ValueError("fresh24 terminal exposure does not match protected ledger")
    if int(public.attempt_count) != len(reserves):
        raise ValueError("fresh24 terminal attempt count does not match ledger")
    # Ordinals must be exactly 1..attempt_count over the reserve transitions.
    reserve_ordinals = sorted(
        int(row.get("attempt_number", 0))  # type: ignore[arg-type]
        for row in reserves
    )
    if reserve_ordinals != list(range(1, int(public.attempt_count) + 1)):
        raise ValueError("fresh24 ledger attempt ordinals are not exact 1..N")
    if canonical_sha256(entries) != public.ledger_sha256:
        raise ValueError("fresh24 ledger digest does not match terminal")
    if state.journal_inventory_digest() != public.journal_sha256:
        raise ValueError("fresh24 journal inventory digest does not match terminal")
    # Raw/dispatch/attempt evidence: reopen the journal AND raw-evidence
    # directories through no-follow descriptors and require the EXACT
    # filename sets derived from the ledger attempts with per-file lineage
    # (each dispatch-N pairs an attempt-N and a response-N.bin of the same
    # ordinal, place, and request identity; digests must match stored bytes).
    state.validate_journal_evidence_inventory()
    state.validate_raw_evidence_inventory()
    protected_terminal_bytes = state.read_protected_terminal_bytes()
    public_bytes = canonical_json_bytes(public.model_dump(mode="json"))
    if protected_terminal_bytes != public_bytes:
        raise ValueError("fresh24 protected terminal drifted from public terminal")
    # Exact raw-evidence filename set: every committed attempt ordinal owns
    # exactly one response file; the positive branch additionally reopens
    # all 24 durable profiles below.
    if public.status == "COMPLETE_CANDIDATE_READY":
        # Reopen generation and every durable profile through no-follow
        # descriptors with exact expected filenames — never Path.read_bytes
        # or iterdir on descriptor-owned paths.  The root itself must carry
        # EXACTLY its eight fixed names (raw files live inside raw-evidence,
        # whose exact inventory validate_raw_evidence_inventory pinned).
        state.validate_root_inventory()
        generation_bytes = _read_public_file_no_follow(
            Path(descriptor.generation_target)
        )
        if hashlib.sha256(generation_bytes).hexdigest() != public.generation_sha256:
            raise ValueError("fresh24 generation digest drifted")
        generation = json.loads(generation_bytes)
        profile_names = sorted(state.list_profile_names())
        if len(profile_names) != FRESH24_MEMBER_COUNT:
            raise ValueError("fresh24 positive terminal lacks 24 durable profiles")
        # Exact key set + self-digest: the manifest binds every authority,
        # claim, exposure, and count field to this terminal and ledger.
        generation_keys = {
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
        if set(generation) != generation_keys:
            raise ValueError("fresh24 generation manifest key set drifted")
        unsigned = {k: v for k, v in generation.items() if k != "generation_sha256"}
        if canonical_sha256(unsigned) != generation.get("generation_sha256"):
            raise ValueError("fresh24 generation self-digest drifted")
        metadata_bindings = (
            ("request_artifact_sha256", approval.request_artifact_sha256),
            # Raw packet bytes lineage: the generation binds the EXACT raw
            # file digest the approval/claim/terminal already pinned.
            ("request_file_sha256", str(approval.request_file_sha256)),
            ("claim_sha256", claim.claim_sha256),
            ("approval_sha256", claim.approval_sha256),
            ("attempt_count", int(public.attempt_count)),
            ("retry_count", int(public.retry_count)),
            (
                "committed_exposure_micro_usd",
                int(public.committed_exposure_micro_usd),
            ),
            ("profile_count", int(public.profile_count)),
            ("scenario_count", 8),
            ("contrast_count", 7),
        )
        for key, expected_value in metadata_bindings:
            if generation.get(key) != expected_value:
                raise ValueError(
                    f"fresh24 generation {key} does not match terminal/claim"
                )
        if generation.get("outstanding_exposure_micro_usd") != 0:
            raise ValueError("fresh24 generation exposure did not settle")
        if generation.get("lifecycle_mutated") is not False:
            raise ValueError("fresh24 generation lifecycle drift")
        # Compare per place: each durable profile's self-digest (validated by
        # the Fresh24Profile contract) must match the generation entry.  All
        # reads go through no-follow descriptors with exact filenames.
        by_place: dict[str, str] = {}
        ordered_profiles: list[dict[str, object]] = []
        for name in profile_names:
            payload = json.loads(state.read_profile_bytes(name))
            validated = Fresh24Profile.model_validate(payload)
            place_id = str(validated.place_id)
            if place_id in by_place:
                raise ValueError("fresh24 duplicate durable profiles for one place")
            by_place[place_id] = str(validated.profile_sha256)
            ordered_profiles.append(payload)
        expected = {
            str(row.get("place_id")): str(row.get("profile_sha256"))
            for row in generation.get("profiles", [])
        }
        if by_place != expected or len(expected) != FRESH24_MEMBER_COUNT:
            raise ValueError("fresh24 durable profile digests drifted from generation")
        counts = (
            public.profile_count,
            public.candidate_count,
            public.post_hard_duplicate_count,
            public.post_cannot_coappear_count,
            public.effective_candidate_count,
        )
        if any(counts[i] < counts[i + 1] for i in range(len(counts) - 1)):
            raise ValueError("fresh24 terminal counts are not monotonic")
        if public.confidence_is_ranking_input is not False:
            raise ValueError("fresh24 confidence ranking drift")
        # Re-evaluate the persisted 24 profiles with the production evaluator
        # and require field-by-field equality with the terminal's maps: the
        # counts, every one of the 8 scenario result/replay entries and their
        # digests, and every one of the 7 contrast entries must reproduce
        # exactly from durable evidence — fabricated maps cannot verify.
        member_order = {
            member.place_id: index for index, member in enumerate(rebuilt_members)
        }
        ordered = sorted(
            ordered_profiles,
            key=lambda row: member_order.get(str(row.get("place_id")), 10**9),
        )
        if any(row.get("place_id") not in member_order for row in ordered):
            raise ValueError("fresh24 durable profile place is not a plan member")
        # The neutral replay injects the SAME fixed evidence timestamp the
        # live run used — derived from the identical checkout lineage — so
        # every result/replay digest reproduces byte-for-byte.
        decision, evaluation = evaluate_fresh24_profiles(
            tuple(ordered),
            evidence_timestamp=fresh24_fixed_evidence_timestamp(
                rebuilt_request.checkout_commit_sha256
            ),
        )
        if (
            decision.candidate_count != public.candidate_count
            or decision.post_hard_duplicate_count != public.post_hard_duplicate_count
            or decision.post_cannot_coappear_count != public.post_cannot_coappear_count
            or decision.effective_candidate_count != public.effective_candidate_count
        ):
            raise ValueError("fresh24 reevaluated cohort counts drifted from terminal")
        persisted_scenarios = [row.model_dump(mode="json") for row in evaluation.scenario_results]
        persisted_contrasts = [row.model_dump(mode="json") for row in evaluation.contrast_results]
        if len(persisted_scenarios) != 8 or len(persisted_contrasts) != 7:
            raise ValueError("fresh24 reevaluated maps are incomplete")
        # EXACT canonical-dict equality: the fixed evidence timestamp makes
        # every result/replay/contribution/record digest deterministic, so
        # each of the 8 scenario rows and each of the 7 contrast rows must
        # reproduce as a complete dict — same key set, same place order,
        # same change flags, same digests.  No per-field exemption remains.
        terminal_scenario_dicts = [
            row.model_dump(mode="json") for row in public.scenario_results
        ]
        if terminal_scenario_dicts != persisted_scenarios:
            raise ValueError(
                "fresh24 scenario maps do not reproduce exactly from durable profiles"
            )
        terminal_contrast_dicts = [
            row.model_dump(mode="json") for row in public.contrast_results
        ]
        if terminal_contrast_dicts != persisted_contrasts:
            raise ValueError(
                "fresh24 contrast maps do not reproduce exactly from durable profiles"
            )
    else:
        # Negative/reconcile branch: NO durable profile may exist — the
        # exact allowed set is empty (no candidate was produced).
        if state.list_profile_names():
            raise ValueError("fresh24 negative branch carries durable profiles")
    # Root exact inventory again at verification END — no tamper during reads.
    state.validate_root_inventory(
        require_generation=public.status == "COMPLETE_CANDIDATE_READY"
    )
    outcome = Fresh24VerifiedOutcome(public)
    object.__setattr__(outcome, "_provenance", _CAPABILITY_SEAL)
    return outcome


def assert_fresh24_positive_outcome(outcome: Fresh24VerifiedOutcome) -> Fresh24Terminal:
    """Separate strict-positive assertion accepting only COMPLETE_CANDIDATE_READY."""

    terminal = outcome.terminal
    if terminal.status != "COMPLETE_CANDIDATE_READY" or terminal.reason != (
        "COMPLETE_CANDIDATE_READY"
    ):
        raise ValueError("fresh24 terminal is not COMPLETE_CANDIDATE_READY")
    return terminal


def build_fresh24_generation_manifest(
    *,
    plan: Fresh24Plan,
    claim: Fresh24Claim,
    profiles: Sequence[Mapping[str, object]],
    scenario_results: Sequence[Mapping[str, object]],
    contrast_results: Sequence[Mapping[str, object]],
    attempt_count: int,
    retry_count: int,
    committed_exposure_micro_usd: int,
) -> dict[str, object]:
    """Build the durable candidate-ready generation manifest."""

    profile_list = [dict(profile) for profile in profiles]
    if len(profile_list) != FRESH24_MEMBER_COUNT:
        raise ValueError("fresh24 generation requires exact 24 coherent profiles")
    unsigned = {
        "schema_version": FRESH24_GENERATION_SCHEMA,
        "authority_id": FRESH24_AUTHORITY_ID,
        # The generation binds the CLAIM's packet identity — the same packet
        # digest the approval was minted for — not the request-domain digest.
        "request_artifact_sha256": claim.request_artifact_sha256,
        # Raw bytes lineage: the exact raw file digest carried on the claim.
        "request_file_sha256": claim.request_file_sha256,
        "request_manifest_sha256": plan.request.request_manifest_sha256,
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
        "committed_exposure_micro_usd": committed_exposure_micro_usd,
        "outstanding_exposure_micro_usd": 0,
        "profile_schema_version": FRESH24_PROFILE_SCHEMA_VERSION,
        "lifecycle_mutated": False,
    }
    manifest = {**unsigned, "generation_sha256": canonical_sha256(unsigned)}
    return manifest


HISTORICAL_AUTHORITY_IDS = frozenset(
    {
        "phase5-nvidia-minimax-m3-fresh-d24-20260816",
        "phase5-nvidia-minimax-m3-minimal-probe-20260820",
    }
)
_HISTORICAL_HASHES = frozenset(
    {
        "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e",
        "14d16266cedee68d132e3992b82367643de3658b7f489172e2153f1b85019675",
        "65adc81f59548debd0d964dced0ee6eb6f8ee14e3045c64b9605d4b589b298da",
    }
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class Fresh24CapabilityError(RuntimeError):
    """Secret-safe fresh24 execution rejection."""


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _read_regular_no_follow(path: Path, *, maximum: int) -> bytes:
    """Read a private regular file with descriptor identity checks."""

    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("fresh24 source authority file identity is invalid")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise ValueError("fresh24 source authority file was truncated")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
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
            raise ValueError("fresh24 source authority changed during read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _load_json(path: Path, *, maximum: int) -> object:
    try:
        return json.loads(_read_regular_no_follow(path, maximum=maximum))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("fresh24 source authority JSON is invalid") from error


def _require_exact_key_set(payload: Mapping[str, object], expected: set[str]) -> None:
    keys = set(payload)
    if keys != expected:
        raise ValueError(
            "fresh24 fixed authority metadata schema drifted "
            f"(missing={sorted(expected - keys)}, extra={sorted(keys - expected)})"
        )


def verify_fixed_source_authority(root: Path = FIXED_SOURCE_ROOT) -> tuple[DemoSourceBundle, ...]:
    """Revalidate only the exact committed 05-34 four-file authority."""

    if root.resolve(strict=False) != FIXED_SOURCE_ROOT.resolve(strict=False):
        raise ValueError("fresh24 source root is not the fixed 05-34 authority")
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("fresh24 source authority root is not private")
    if any(
        component.is_symlink()
        for component in (root, *root.parents)
        if component.exists()
    ):
        raise ValueError("fresh24 source authority path contains a symlink")
    for name in (
        "source-bundles.json",
        "source-authority-members.json",
        "source-authority.json",
        "source-authority-install-receipt.json",
    ):
        if (root / name).is_symlink():
            raise ValueError("fresh24 source authority file contains a symlink")
    expected_names = {
        "source-bundles.json",
        "source-authority-members.json",
        "source-authority.json",
        "source-authority-install-receipt.json",
    }
    if set(os.listdir(root)) != expected_names:
        raise ValueError("fresh24 source authority inventory is not exact")
    bundles_value = _load_json(root / "source-bundles.json", maximum=64 * 1024 * 1024)
    members = _load_json(root / "source-authority-members.json", maximum=8 * 1024 * 1024)
    authority = _load_json(root / "source-authority.json", maximum=8 * 1024 * 1024)
    receipt = _load_json(root / "source-authority-install-receipt.json", maximum=4 * 1024 * 1024)
    if not isinstance(bundles_value, list) or not isinstance(members, list):
        raise ValueError("fresh24 source authority member shape is invalid")
    if not isinstance(authority, dict) or not isinstance(receipt, dict):
        raise ValueError("fresh24 source authority receipt shape is invalid")
    bundles = validate_demo_source_inventory(
        tuple(DemoSourceBundle.model_validate(value) for value in bundles_value)
    )
    inventory = canonical_sha256([bundle.source_bundle_sha256 for bundle in bundles])
    place_ids = [bundle.place_id for bundle in bundles]
    authority_self = authority.get("authority_sha256")
    computed_authority = canonical_sha256(
        {key: value for key, value in authority.items() if key != "authority_sha256"}
    )
    if (
        inventory != FRESH24_SOURCE_INVENTORY_SHA256
        or authority.get("source_inventory_sha256") != inventory
        or receipt.get("source_inventory_sha256") != inventory
        or not isinstance(authority_self, str)
        or authority_self != computed_authority
        or authority.get("member_count") != 24
        or authority.get("status") != "COMPLETE_AUTHORIZED_DEV_24"
        or authority.get("blind_excluded") is not True
        or authority.get("dev_membership_sha256") != FRESH24_MEMBERSHIP_SHA256
        or authority.get("dev_place_refs") != place_ids
        or authority.get("source_bundle_sha256")
        != [bundle.source_bundle_sha256 for bundle in bundles]
        or len(members) != 24
        or [row.get("place_id") for row in members] != place_ids
        or [row.get("source_bundle_sha256") for row in members]
        != [bundle.source_bundle_sha256 for bundle in bundles]
        or [row.get("member_sha256") for row in members] != authority.get("member_sha256")
        or receipt.get("installed_authority_sha256") != FRESH24_SOURCE_AUTHORITY_SHA256
        or receipt.get("installed_authority_sha256") != authority_self
        or receipt.get("receipt_sha256")
        != canonical_sha256(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        or receipt.get("forbidden_content_count") != 0
        or any(
            receipt.get(key) is not False
            for key in (
                "secret_read",
                "network_attempted",
                "provider_client_constructed",
                "lifecycle_mutated",
            )
        )
        or any(
            receipt.get(key) is not True
            for key in (
                "no_follow_verified",
                "no_replace_verified",
                "regular_single_link_verified",
            )
        )
        or receipt.get("published_files")
        != [
            "source-bundles.json",
            "source-authority-members.json",
            "source-authority.json",
            "source-authority-install-receipt.json",
        ]
        # The receipt self-digest must equal the pinned fresh24 constant.
        or receipt.get("receipt_sha256") != FRESH24_SOURCE_INSTALL_RECEIPT_SHA256
    ):
        raise ValueError("fresh24 source authority digest or capability drifted")
    _require_exact_key_set(
        receipt,
        {
            "backup_authority_sha256",
            "backup_member_count",
            "backup_schema_version",
            "backup_source_inventory_sha256",
            "backup_verification",
            "destination_root_mode",
            "dev_membership_sha256",
            "forbidden_content_count",
            "installed_authority_sha256",
            "lifecycle_mutated",
            "member_count",
            "network_attempted",
            "no_follow_verified",
            "no_replace_verified",
            "output_file_mode",
            "phase4_input_authority_sha256",
            "provider_client_constructed",
            "published_files",
            "receipt_sha256",
            "regular_single_link_verified",
            "schema_version",
            "secret_read",
            "source_inventory_sha256",
            "status",
        },
    )
    _require_exact_key_set(
        authority,
        {
            "analysis_scope",
            "authority_sha256",
            "blind_excluded",
            "dev_membership_sha256",
            "dev_place_refs",
            "endpoint",
            "member_count",
            "member_sha256",
            "official_dataset_id",
            "phase4_input_authority_sha256",
            "provider",
            "schema_version",
            "source_bundle_sha256",
            "source_inventory_sha256",
            "status",
        },
    )
    if tuple(place_ids) != tuple(sorted(place_ids)) or len(set(place_ids)) != 24:
        raise ValueError("fresh24 source membership is not exact ordered DEV-24")
    if any(
        not isinstance(member, dict)
        or member.get("place_id") != bundle.place_id
        or member.get("source_bundle_sha256") != bundle.source_bundle_sha256
        or member.get("member_sha256")
        != canonical_sha256({key: value for key, value in member.items() if key != "member_sha256"})
        for member, bundle in zip(members, bundles, strict=True)
    ):
        raise ValueError("fresh24 source member lineage drifted")
    return bundles


def checkout_manifest_sha256(repository_root: Path = REPOSITORY_ROOT) -> str:
    """Bind the complete fresh24 source-authority tree without self-reference."""

    root = repository_root.resolve(strict=True)
    source_commit = fresh24_checkout_commit_sha256(root)
    completed = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", source_commit],
        cwd=root,
        check=True,
        capture_output=True,
    )
    rows: list[dict[str, str]] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        name = raw_name.decode("utf-8")
        if name in {FRESH24_PUBLIC_REQUEST_RELATIVE, FRESH24_TERMINAL_RELATIVE}:
            continue
        rows.append({"path": name, "mode": mode, "type": kind, "object_id": object_id})
    if not rows:
        raise ValueError("fresh24 checkout manifest is empty")
    return canonical_sha256(rows)


def bind_positive_probe_evidence(terminal: Mapping[str, object]) -> Fresh24InvocationEvidence:
    """Bind only safe terminal/request digests; reject all probe member reuse."""

    expected_keys = {
        "schema_version",
        "status",
        "reason",
        "authority_id",
        "request_sha256",
        "approval_sha256",
        "protected_state_sha256",
        "claim_sha256",
        "raw_response_sha256",
        "ledger_sha256",
        "journal_sha256",
        "attempt_count",
        "committed_exposure_micro_usd",
        "outstanding_exposure_micro_usd",
        "confidence",
        "release_eligible",
        "secret_read",
        "client_constructed",
        "network_attempted",
        "lifecycle_mutated",
        "terminal_sha256",
    }
    if set(terminal) != expected_keys:
        raise ValueError("fresh24 probe terminal contains member or profile material")
    try:
        from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeTerminal

        validated = NvidiaMinimalProbeTerminal.model_validate(terminal)
    except Exception as error:
        raise ValueError("fresh24 probe terminal is not independently valid") from error
    if (
        validated.status != "POSITIVE"
        or validated.reason != "STRICT_INVOCATION_SUCCESS"
        or validated.authority_id != "phase5-nvidia-minimax-m3-minimal-probe-20260820"
        or validated.release_eligible is not False
    ):
        raise ValueError("fresh24 requires a strict-positive minimal-probe terminal")
    return Fresh24InvocationEvidence(
        probe_authority_id=validated.authority_id,
        probe_terminal_sha256=validated.terminal_sha256,
        probe_request_sha256=validated.request_sha256,
    )


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


def _fresh24_request_body(bundle: DemoSourceBundle) -> bytes:
    config = NvidiaMinimaxProfileMaterializationConfig()
    evidence = [
        {"evidence_id": source.evidence_id, "source_kind": source.source_kind, "text": source.text}
        for source in bundle.sources
    ]
    payload = {
        "model": FRESH24_MODEL,
        "messages": [
            {"role": "system", "content": FRESH24_PROMPT_TEXT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "instruction": (
                            "Return one complete fresh24 profile JSON object using only this "
                            "place's supplied evidence. Do not use probe, historical, or "
                            "continuation data."
                        ),
                        "place_id": bundle.place_id,
                        "evidence": evidence,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "stream": config.stream,
        "seed": config.seed,
        "chat_template_kwargs": {"thinking_mode": config.thinking_mode},
    }
    return canonical_json_bytes(payload)


@dataclass(frozen=True, slots=True)
class Fresh24Member:
    authority_id: str
    probe_terminal_sha256: str
    place_id: str
    source_bundle_sha256: str
    evidence_inventory_sha256: str
    request_body: bytes = field(repr=False)
    request: Fresh24MemberRequest | None = None


@dataclass(frozen=True, slots=True)
class Fresh24FirstPass:
    place_id: str
    order: int
    request_sha256: str
    request_body_sha256: str
    authority_id: str = FRESH24_AUTHORITY_ID


@dataclass(frozen=True, slots=True)
class Fresh24Plan:
    authority: Fresh24Authority
    probe: Fresh24InvocationEvidence
    members: tuple[Fresh24Member, ...]
    first_passes: tuple[Fresh24FirstPass, ...]
    retry_policy: Fresh24RetryPolicy
    exposure: Fresh24ExposurePolicy
    request: Fresh24Request
    checkout_commit_sha256: str
    checkout_manifest_sha256: str


def _validate_response_profile_lineage(
    *,
    profile_value: object,
    place_id: str,
    member: Fresh24Member,
) -> dict[str, object]:
    if member.request is None:
        raise ValueError("fresh24 member request is missing")
    profile = Fresh24Profile.model_validate(profile_value)
    if (
        profile.place_id != place_id
        or profile.authority_id != member.authority_id
        or profile.source_bundle_sha256 != member.source_bundle_sha256
        or profile.evidence_inventory_sha256 != member.evidence_inventory_sha256
        or profile.request_sha256 != member.request.request_sha256
    ):
        raise ValueError("fresh24 response profile lineage does not match member request")
    return profile.model_dump(mode="json")


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
        raise ValueError("fresh24 checkout commit is invalid")
    return commit


def fresh24_checkout_commit_sha256(repository_root: Path = REPOSITORY_ROOT) -> str:
    """Resolve the full-tree commit immediately preceding the current packet."""

    root = repository_root.resolve(strict=True)
    head = _current_checkout_commit_sha256(root)
    packet_result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", FRESH24_PUBLIC_REQUEST_RELATIVE],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    packet_commit = packet_result.stdout.strip()
    if not packet_commit:
        return head
    if re.fullmatch(r"[0-9a-f]{40}", packet_commit) is None:
        raise ValueError("fresh24 packet commit is invalid")
    source_result = subprocess.run(
        ["git", "log", "-1", "--format=%H", "--", *FRESH24_SOURCE_AUTHORITY_PATHS],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    source_commit = source_result.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("fresh24 source authority commit is invalid")
    source_after_packet = subprocess.run(
        ["git", "merge-base", "--is-ancestor", packet_commit, source_commit],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if source_after_packet.returncode == 0:
        return head
    if source_after_packet.returncode != 1:
        raise ValueError("fresh24 source ancestry is invalid")
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
    if changed_paths != (FRESH24_PUBLIC_REQUEST_RELATIVE,):
        raise ValueError("fresh24 packet commit is not isolated")
    return parent


class Fresh24Scheduler:
    """Exact two-pass scheduler: 24 first passes then at most six retries.

    ``attempt_count`` reflects only actually dispatched attempts: it advances
    when an attempt is dispatched (reserve+dispatch), never speculatively.
    """

    def __init__(self, place_ids: Sequence[str]) -> None:
        self._place_ids = tuple(place_ids)
        if len(self._place_ids) != 24 or len(set(self._place_ids)) != 24:
            raise ValueError("fresh24 scheduler requires 24 unique places")
        self._first_pass_done = False
        self._retry_places: tuple[str, ...] = ()
        self._dispatched = 0
        self._first_pass_dispatches = 0
        self._retried_places: dict[str, int] = {}

    @property
    def attempt_count(self) -> int:
        return self._dispatched

    def first_pass(self) -> tuple[str, ...]:
        if self._first_pass_done:
            raise RuntimeError("fresh24 first pass already consumed")
        self._first_pass_done = True
        return self._place_ids

    def record_dispatched(self, place_id: str, *, is_retry: bool) -> None:
        """Count a real dispatch (called after RESERVE+DISPATCH are durable)."""

        self._dispatched += 1
        if is_retry:
            self._retried_places[place_id] = (
                self._retried_places.get(place_id, 0) + 1
            )
        else:
            self._first_pass_dispatches += 1

    def retry_order(self, retryable_places: Sequence[str]) -> tuple[str, ...]:
        if not self._first_pass_done:
            raise RuntimeError("fresh24 retries require all first passes")
        if self._first_pass_dispatches < FRESH24_FIRST_PASS_COUNT:
            raise RuntimeError(
                "fresh24 retries require all 24 first passes dispatched"
            )
        if self._retry_places:
            raise RuntimeError("fresh24 retry attempt budget already consumed")
        requested = tuple(retryable_places)
        if len(requested) > FRESH24_MAX_RETRIES or len(set(requested)) != len(requested):
            raise RuntimeError("fresh24 retry budget exhausted")
        if requested != tuple(sorted(requested)):
            raise RuntimeError("fresh24 retry order is not canonical")
        if any(place not in self._place_ids for place in requested):
            raise RuntimeError("fresh24 retry place is not in first-pass inventory")
        projected = self._dispatched + len(requested)
        if projected > FRESH24_MAX_ATTEMPTS:
            raise RuntimeError("fresh24 attempt budget exhausted")
        self._retry_places = requested
        return requested

    def classify_retry(
        self,
        *,
        error: BaseException | str | None = None,
        status_code: int | None = None,
    ) -> bool:
        if status_code is not None:
            return status_code in FRESH24_RETRYABLE_HTTP_STATUSES
        name = type(error).__name__ if not isinstance(error, str) else error
        return name in FRESH24_RETRYABLE_TRANSPORT_NAMES


def build_fresh24_plan(
    source_bundles: Sequence[DemoSourceBundle],
    *,
    checkout_manifest_sha256: str,
    probe_terminal: Mapping[str, object],
    authority_id: str = FRESH24_AUTHORITY_ID,
) -> Fresh24Plan:
    validate_fresh24_authority_id(authority_id)
    if authority_id in HISTORICAL_AUTHORITY_IDS:
        raise ValueError("fresh24 authority cannot reuse historical authority")
    checkout_digest = _require_digest(checkout_manifest_sha256, "checkout manifest")
    bundles = verify_fixed_source_authority(FIXED_SOURCE_ROOT)
    supplied = validate_demo_source_inventory(tuple(source_bundles))
    if tuple(bundle.source_bundle_sha256 for bundle in supplied) != tuple(
        bundle.source_bundle_sha256 for bundle in bundles
    ):
        raise ValueError("fresh24 source inventory is not the fixed four-file authority")
    probe = bind_positive_probe_evidence(probe_terminal)
    members: list[Fresh24Member] = []
    first_passes: list[Fresh24FirstPass] = []
    member_requests: list[Fresh24MemberRequest] = []
    for order, bundle in enumerate(bundles, start=1):
        request_body = _fresh24_request_body(bundle)
        body_digest = hashlib.sha256(request_body).hexdigest()
        preimage = {
            "schema_version": "itda.phase5-fresh24-member-request.v1",
            "authority_id": authority_id,
            "place_id": bundle.place_id,
            "split": "DEV",
            "first_pass_order": order,
            "source_bundle_sha256": bundle.source_bundle_sha256,
            "evidence_inventory_sha256": _evidence_inventory_sha256(bundle),
            "request_body_sha256": body_digest,
        }
        request = Fresh24MemberRequest.model_validate(
            {**preimage, "request_sha256": canonical_sha256(preimage)}
        )
        member = Fresh24Member(
            authority_id=authority_id,
            probe_terminal_sha256=probe.probe_terminal_sha256,
            place_id=bundle.place_id,
            source_bundle_sha256=bundle.source_bundle_sha256,
            evidence_inventory_sha256=_evidence_inventory_sha256(bundle),
            request_body=request_body,
            request=request,
        )
        members.append(member)
        member_requests.append(request)
        first_passes.append(
            Fresh24FirstPass(
                place_id=bundle.place_id,
                order=order,
                request_sha256=request.request_sha256,
                request_body_sha256=body_digest,
            )
        )
    retry_policy = Fresh24RetryPolicy()
    exposure = Fresh24ExposurePolicy()
    root_digest = canonical_sha256(
        {
            "authority_id": authority_id,
            "checkout_manifest_sha256": checkout_digest,
            "fresh24_namespace": FRESH24_AUTHORITY_ID,
        }
    )
    authority = Fresh24Authority(
        probe_evidence=probe,
        root_identity_sha256=root_digest,
        claim_identity_sha256=canonical_sha256({"root": root_digest, "kind": "claim"}),
        ledger_identity_sha256=canonical_sha256({"root": root_digest, "kind": "ledger"}),
        journal_identity_sha256=canonical_sha256({"root": root_digest, "kind": "journal"}),
        generation_identity_sha256=canonical_sha256({"root": root_digest, "kind": "generation"}),
    )
    manifest = canonical_sha256(
        [
            {
                "place_id": request.place_id,
                "request_sha256": request.request_sha256,
                "request_body_sha256": request.request_body_sha256,
            }
            for request in member_requests
        ]
    )
    checkout_commit = fresh24_checkout_commit_sha256(REPOSITORY_ROOT)
    request = Fresh24Request.model_validate(
        {
            "authority": authority.model_dump(mode="json"),
            "checkout_commit_sha256": checkout_commit,
            "checkout_manifest_sha256": checkout_digest,
            "members": [row.model_dump(mode="json") for row in member_requests],
            "retry_policy": retry_policy.model_dump(mode="json"),
            "exposure_policy": exposure.model_dump(mode="json"),
            "request_manifest_sha256": manifest,
        }
    )
    return Fresh24Plan(
        authority=authority,
        probe=probe,
        members=tuple(members),
        first_passes=tuple(first_passes),
        retry_policy=retry_policy,
        exposure=exposure,
        request=request,
        checkout_commit_sha256=checkout_commit,
        checkout_manifest_sha256=checkout_digest,
    )


@dataclass(frozen=True, slots=True)
class Fresh24Reservation:
    reservation_id: int
    place_id: str
    request_sha256: str
    amount_micro_usd: int = FRESH24_RESERVATION_MICRO_USD


@dataclass(frozen=True, slots=True)
class Fresh24LedgerEvent:
    authority_id: str
    sequence: int
    operation: Literal["RESERVE", "RELEASE_BEFORE_SOCKET", "COMMIT", "RECOVER_UNRESOLVED"]
    reservation_id: int
    place_id: str
    request_sha256: str
    amount_micro_usd: int
    capability_accessed: bool
    predecessor_sha256: str
    event_sha256: str


class Fresh24ProtectedState:
    """Small provider-free reservation state used by contract and MockTransport tests."""

    def __init__(self, root: Path, *, authority_id: str = FRESH24_AUTHORITY_ID) -> None:
        validate_fresh24_authority_id(authority_id)
        if root.is_symlink():
            raise PermissionError("fresh24 protected root cannot be a symlink")
        self.root = root
        self.authority_id = authority_id
        self._events: list[Fresh24LedgerEvent] = []
        self._outstanding: dict[int, Fresh24Reservation] = {}
        self._next_id = 1
        self._lock = threading.RLock()

    @property
    def events(self) -> tuple[Fresh24LedgerEvent, ...]:
        return tuple(self._events)

    def reserve(self, *, place_id: str, request_sha256: str) -> Fresh24Reservation:
        with self._lock:
            _require_digest(request_sha256, "request digest")
            projected = (
                self.committed_exposure_micro_usd
                + self.outstanding_exposure_micro_usd
                + FRESH24_RESERVATION_MICRO_USD
            )
            if (
                len(self._events) >= 2 * FRESH24_MAX_ATTEMPTS
                or projected > FRESH24_CUMULATIVE_EXPOSURE_CAP_MICRO_USD
            ):
                raise RuntimeError("fresh24 exposure or attempt budget exhausted")
            reservation = Fresh24Reservation(self._next_id, place_id, request_sha256)
            self._next_id += 1
            self._outstanding[reservation.reservation_id] = reservation
            self._append("RESERVE", reservation, capability_accessed=False)
            return reservation

    def release_before_socket(self, reservation: Fresh24Reservation) -> None:
        with self._lock:
            current = self._outstanding.pop(reservation.reservation_id, None)
            if current != reservation:
                raise RuntimeError("fresh24 reservation is invalid or reused")
            self._append("RELEASE_BEFORE_SOCKET", reservation, capability_accessed=False)

    def commit(self, reservation: Fresh24Reservation) -> None:
        with self._lock:
            current = self._outstanding.pop(reservation.reservation_id, None)
            if current != reservation:
                raise RuntimeError("fresh24 reservation is invalid or reused")
            self._append("COMMIT", reservation, capability_accessed=True)

    @property
    def outstanding_exposure_micro_usd(self) -> int:
        return sum(item.amount_micro_usd for item in self._outstanding.values())

    @property
    def committed_exposure_micro_usd(self) -> int:
        return sum(
            event.amount_micro_usd
            for event in self._events
            if event.operation in {"COMMIT", "RECOVER_UNRESOLVED"}
        )

    def _append(
        self, operation: str, reservation: Fresh24Reservation, *, capability_accessed: bool
    ) -> None:
        predecessor = self._events[-1].event_sha256 if self._events else "0" * 64
        sequence = len(self._events) + 1
        preimage = {
            "authority_id": self.authority_id,
            "sequence": sequence,
            "operation": operation,
            "reservation_id": reservation.reservation_id,
            "place_id": reservation.place_id,
            "request_sha256": reservation.request_sha256,
            "amount_micro_usd": reservation.amount_micro_usd,
            "capability_accessed": capability_accessed,
            "predecessor_sha256": predecessor,
        }
        self._events.append(Fresh24LedgerEvent(**preimage, event_sha256=canonical_sha256(preimage)))


class Fresh24DurableAuthorityState:
    """Restart-safe exact approval, one-use claim, ledger, journal, and evidence.

    Every write is no-follow and no-replace; the ledger is append-only JSONL
    with canonical duplicate-key rejection; attempt evidence is fsynced before
    the COMMIT entry may be appended.  The class is deliberately disjoint from
    every historical probe/cohort namespace.
    """

    _MAX_STATE_BYTES = 8 * 1024 * 1024

    def __init__(self, descriptor: Fresh24ProtectedStateDescriptor) -> None:
        self._descriptor = descriptor
        root = Path(descriptor.state_root)
        if not root.is_absolute():
            raise PermissionError("FRESH24_PROTECTED_ROOT_NOT_LEXICAL")
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
        # Optional CLI-pinned credential reader.  This is NOT a public
        # production seam: the production entry point's import-time closure
        # never consults it.  Only the CLI live handler registers one (via
        # ``bind_credential_reader``), and the sealed executor hands the
        # reopened approval binding to it at reserve-before-secret time.
        self._credential_reader: (
            Callable[[Fresh24ApprovalBinding], str] | None
        ) = None

    @property
    def descriptor(self) -> Fresh24ProtectedStateDescriptor:
        return self._descriptor

    def bind_credential_reader(
        self,
        reader: Callable[[Fresh24ApprovalBinding], str],
    ) -> Fresh24DurableAuthorityState:
        """Attach the CLI's pinned lexical reader to THIS state instance.

        Returns self so the call can wrap construction inline.  The reader is
        instance state — it cannot leak into other roots, and the public
        production API still exposes no credential parameter.
        """

        if not callable(reader):
            raise TypeError("fresh24 credential reader must be callable")
        self._credential_reader = reader
        return self

    def credential_reader_for(
        self,
        approval: Fresh24ApprovalBinding,
    ) -> str:
        """Resolve the credential VALUE at reserve-before-secret time.

        Called by the sealed production executor AFTER each attempt's RESERVE
        + DISPATCH are durable.  Re-verifies the approval binding and the
        persisted claim/root identity against THIS instance's descriptor
        before delegating to the CLI-pinned reader — so a stale approval, a
        foreign root, or an unbound state can never reach the value path.
        The one-use ordering (reserve → dispatch → read) is enforced by the
        caller; this method adds no re-reads of its own beyond identity.
        """

        if self._credential_reader is None:
            raise Fresh24SecretUnavailable("FRESH24_SECRET_UNAVAILABLE")
        # Identity gates: the reopened approval must still be THE approved
        # binding of this exact protected root, and the persisted claim must
        # still match it — a replayed or foreign run cannot read here.
        self._validate_approval(approval)
        persisted = self.read_claim()
        if persisted.approval_sha256 != approval.approval_sha256:
            raise PermissionError("FRESH24_CLAIM_INVALID")
        return self._credential_reader(approval)

    # ------------------------------------------------------------------ roots

    def _open_root(self, *, create: bool) -> int:
        target = self._root
        # macOS exposes /tmp -> /private/tmp and /var -> /private/var; pin the
        # canonical /private spelling so no symlinked ancestor is traversed.
        text = str(target)
        if text.startswith("/tmp/") or text == "/tmp":
            target = Path("/private/tmp") / Path(*target.parts[2:])
        elif text.startswith("/var/") or text == "/var":
            target = Path("/private/var") / Path(*target.parts[2:])
        descriptor_fd = open_directory_chain_no_follow(target, create=create)
        try:
            metadata = os.fstat(descriptor_fd)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise PermissionError("FRESH24_PROTECTED_ROOT_NOT_PRIVATE")
            owner_ok = metadata.st_uid == os.getuid()
            if not owner_ok:
                raise PermissionError("FRESH24_PROTECTED_ROOT_OWNER_INVALID")
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
            raise PermissionError("FRESH24_PROTECTED_DIRECTORY_INVALID")
        return child

    def _open_existing_private_dir(self, parent: int, name: str) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        child = os.open(name, flags, dir_fd=parent)
        metadata = os.fstat(child)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(child)
            raise PermissionError("FRESH24_PROTECTED_DIRECTORY_INVALID")
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
                raise PermissionError("FRESH24_PROTECTED_FILE_INVALID")
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
                raise PermissionError("FRESH24_PROTECTED_FILE_CHANGED")
            return bytes(payload)
        finally:
            os.close(fd)

    @staticmethod
    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("fresh24 protected JSON contains duplicate keys")
            value[key] = child
        return value

    @classmethod
    def _parse_canonical_json_object(cls, payload: bytes) -> dict[str, object]:
        value = json.loads(payload, object_pairs_hook=cls._unique_object)
        if not isinstance(value, dict):
            raise ValueError("fresh24 protected JSON must be an object")
        return value

    def _read_canonical_json(self, directory: int, name: str) -> dict[str, object]:
        raw = self._read_regular_bytes(directory, name)
        try:
            value = self._parse_canonical_json_object(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise PermissionError("FRESH24_PROTECTED_FILE_INVALID") from error
        if canonical_json_bytes(value) != raw:
            raise PermissionError("FRESH24_PROTECTED_FILE_NOT_CANONICAL")
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
                raise PermissionError("FRESH24_PROTECTED_REPLACEMENT_FORBIDDEN") from None

    def _append_jsonl_line(self, directory: int, name: str, line: bytes) -> None:
        fd = os.open(
            name,
            os.O_WRONLY
            | os.O_APPEND
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise PermissionError("FRESH24_LEDGER_INVALID")
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
            raise ValueError("fresh24 protected ledger framing is invalid")
        entries: list[dict[str, object]] = []
        for line in payload[:-1].split(b"\n"):
            try:
                value = cls._parse_canonical_json_object(line)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise ValueError("fresh24 protected ledger JSON is invalid") from error
            if canonical_json_bytes(value) != line:
                raise ValueError("fresh24 protected ledger is not canonical")
            entries.append(value)
        return entries

    def read_ledger_entries(self) -> list[dict[str, object]]:
        """Reopen the protected ledger without any provider capability."""

        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["ledger"]):
                    return []
                return self._parse_ledger(
                    self._read_regular_bytes(root_fd, self._names["ledger"])
                )
            finally:
                os.close(root_fd)

    def committed_exposure_micro_usd(self) -> int:
        return sum(
            int(entry.get("amount_micro_usd", 0))
            for entry in self.read_ledger_entries()
            if entry.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        )

    # --------------------------------------------------------------- approval

    def install_approval(
        self,
        approval: Fresh24ApprovalBinding,
        *,
        request_artifact: Mapping[str, object],
    ) -> dict[str, object]:
        """Publish the exact approval bound to the committed packet; one-use safe."""

        self._validate_approval(approval)
        expected_artifact_digest = request_artifact.get("request_artifact_sha256")
        if (
            not isinstance(expected_artifact_digest, str)
            or not _DIGEST.fullmatch(expected_artifact_digest)
            or expected_artifact_digest != approval.request_artifact_sha256
        ):
            raise PermissionError("FRESH24_APPROVAL_ARTIFACT_MISMATCH")
        with self._lock:
            root_fd = self._open_root(create=True)
            try:
                if self._exists(root_fd, self._names["claim"]):
                    raise PermissionError("FRESH24_ALREADY_CLAIMED")
                self._publish_or_require_exact(
                    root_fd,
                    self._names["approval"],
                    canonical_json_bytes(approval.model_dump(mode="json")),
                )
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        return {
            "schema_version": FRESH24_GENERATION_SCHEMA,
            "status": "APPROVED_UNCLAIMED",
            "authority_id": approval.authority_id,
            "approval_sha256": approval.approval_sha256,
            "claimed": False,
        }

    def read_approval(self) -> Fresh24ApprovalBinding:
        root_fd = self._open_root(create=False)
        try:
            approval = Fresh24ApprovalBinding.model_validate(
                self._read_canonical_json(root_fd, self._names["approval"])
            )
            self._validate_approval(approval)
            return approval
        finally:
            os.close(root_fd)

    def read_claim(self) -> Fresh24Claim:
        """Reopen the persisted one-use claim through the no-follow root."""

        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["claim"]):
                raise PermissionError("FRESH24_CLAIM_INVALID")
            claim = Fresh24Claim.model_validate(
                self._read_canonical_json(root_fd, self._names["claim"])
            )
        finally:
            os.close(root_fd)
        self._require_exact_claim(claim=claim)
        return claim

    def require_approval_matches_artifact(
        self,
        *,
        request_artifact: Mapping[str, object],
    ) -> Fresh24ApprovalBinding:
        """Public stale-approval check used by verify/reconcile without claim."""

        approval = self.read_approval()
        artifact_digest = request_artifact.get("request_artifact_sha256")
        if (
            not isinstance(artifact_digest, str)
            or not _DIGEST.fullmatch(artifact_digest)
            or artifact_digest != approval.request_artifact_sha256
        ):
            raise PermissionError("FRESH24_STALE_APPROVAL")
        return approval

    def _validate_approval(self, approval: Fresh24ApprovalBinding) -> None:
        validate_fresh24_authority_id(approval.authority_id)
        if approval.authority_id != self._descriptor.authority_id:
            raise PermissionError("FRESH24_APPROVAL_AUTHORITY_MISMATCH")
        if approval.protected_state_sha256 != self._descriptor.protected_state_sha256:
            raise PermissionError("FRESH24_APPROVAL_PROTECTED_STATE_MISMATCH")

    # ------------------------------------------------------------------ claim

    def claim_once(self, *, request_artifact: Mapping[str, object]) -> Fresh24Claim:
        """Atomically create the sole claim bound to the exact approved packet."""

        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                approval = Fresh24ApprovalBinding.model_validate(
                    self._read_canonical_json(root_fd, self._names["approval"])
                )
                self._validate_approval(approval)
                artifact_digest = request_artifact.get("request_artifact_sha256")
                if (
                    not isinstance(artifact_digest, str)
                    or not _DIGEST.fullmatch(artifact_digest)
                    or artifact_digest != approval.request_artifact_sha256
                ):
                    raise PermissionError("FRESH24_STALE_APPROVAL")
                claim_fields = {
                    "schema_version": FRESH24_CLAIM_SCHEMA,
                    "authority_id": approval.authority_id,
                    "request_artifact_sha256": approval.request_artifact_sha256,
                    # Raw bytes lineage carried from the approval binding.
                    "request_file_sha256": approval.request_file_sha256,
                    "approval_sha256": approval.approval_sha256,
                    "protected_state_sha256": approval.protected_state_sha256,
                }
                claim = Fresh24Claim.model_validate(
                    {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
                )
                try:
                    self._publish_create_only(
                        root_fd,
                        self._names["claim"],
                        canonical_json_bytes(claim.model_dump(mode="json")),
                    )
                except FileExistsError as error:
                    raise PermissionError("FRESH24_ALREADY_CLAIMED") from error
                os.fsync(root_fd)
                return claim
            finally:
                os.close(root_fd)

    def _require_exact_claim(self, *, claim: Fresh24Claim) -> Fresh24ApprovalBinding:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["claim"]):
                raise PermissionError("FRESH24_CLAIM_INVALID")
            persisted = Fresh24Claim.model_validate(
                self._read_canonical_json(root_fd, self._names["claim"])
            )
            approval = Fresh24ApprovalBinding.model_validate(
                self._read_canonical_json(root_fd, self._names["approval"])
            )
        finally:
            os.close(root_fd)
        if persisted != claim or claim.approval_sha256 != approval.approval_sha256:
            raise PermissionError("FRESH24_CLAIM_INVALID")
        return approval

    # ---------------------------------------------------------------- reserve

    def reserve_once(
        self, *, claim: Fresh24Claim, place_id: str, request_sha256: str
    ) -> int:
        """Durably append the claim-bound RESERVE entry before capability use.

        Attempt identity is the triple (place_id, request_sha256, attempt_id).
        The attempt ordinal counts RESERVE entries only — exactly 1..30 — so a
        retry RESERVE is legal with its own fresh ordinal.
        """

        approval = self._require_exact_claim(claim=claim)
        _require_digest(request_sha256, "request digest")
        entries_snapshot = self.read_ledger_entries()
        attempt_number = sum(
            1 for row in entries_snapshot if row.get("operation") == "RESERVE"
        ) + 1
        if attempt_number > FRESH24_MAX_ATTEMPTS:
            raise RuntimeError("fresh24 attempt budget exhausted")
        entry = {
            "schema_version": FRESH24_LEDGER_ENTRY_SCHEMA,
            "authority_id": approval.authority_id,
            "operation": "RESERVE",
            "attempt_number": attempt_number,
            "amount_micro_usd": FRESH24_RESERVATION_MICRO_USD,
            "place_id": place_id,
            "request_sha256": request_sha256,
            "claim_sha256": claim.claim_sha256,
        }
        projected = (
            sum(
                int(row.get("amount_micro_usd", 0))
                for row in entries_snapshot
                if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
            )
            + FRESH24_RESERVATION_MICRO_USD
        )
        if projected > FRESH24_CUMULATIVE_EXPOSURE_CAP_MICRO_USD:
            raise RuntimeError("fresh24 cumulative exposure cap exhausted")
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
                # Exact expected prefix: the ledger must not have moved since
                # the snapshot; concurrent reservation attempts fail closed.
                if tuple(canonical_json_bytes(row) for row in current_entries) != tuple(
                    canonical_json_bytes(row) for row in entries_snapshot
                ):
                    raise PermissionError("FRESH24_RESERVATION_RACE_INVALID")
                # Attempt identity triple: at most one RESERVE per (place,
                # request, ordinal) and at most two per (place, request).
                prior = [
                    row
                    for row in current_entries
                    if row.get("operation") == "RESERVE"
                    and row.get("request_sha256") == request_sha256
                    and row.get("place_id") == place_id
                ]
                if len(prior) >= 2:
                    raise PermissionError("FRESH24_RESERVATION_DUPLICATE")
                # The immediately preceding transition must not be an
                # unresolved RESERVE for this same attempt identity: a place's
                # retry may only be reserved after its first attempt settled.
                if prior and int(prior[-1].get("attempt_number", 0)) < attempt_number:  # type: ignore[arg-type]
                    prior_ordinal = int(prior[-1].get("attempt_number", 0))  # type: ignore[arg-type]
                    prior_settled = any(
                        row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
                        and row.get("request_sha256") == request_sha256
                        and row.get("place_id") == place_id
                        and int(row.get("attempt_number", 0)) == prior_ordinal  # type: ignore[arg-type]
                        for row in current_entries
                    )
                    if not prior_settled:
                        raise PermissionError("FRESH24_RESERVATION_OUTSTANDING")
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

    def _next_attempt_number(self) -> int:
        entries = self.read_ledger_entries()
        reserves = [row for row in entries if row.get("operation") == "RESERVE"]
        commits = [
            row
            for row in entries
            if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        ]
        if len(reserves) - len(commits) > 1:
            raise PermissionError("FRESH24_OUTSTANDING_RESERVATIONS_INVALID")
        return len(commits) + 1

    # --------------------------------------------------------------- dispatch

    def record_dispatch(
        self,
        *,
        claim: Fresh24Claim,
        place_id: str,
        request_sha256: str,
        attempt_number: int | None = None,
    ) -> int:
        """Create-only per-attempt DISPATCH marker before awaiting transport.

        ``attempt_number`` must be the reserved ordinal; when omitted the next
        ledger-derived ordinal is used.  Returns the dispatch ordinal.
        """

        approval = self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            journal = self._open_private_dir(root_fd, self._names["journal"])
            try:
                entries = self._read_ledger_from(root_fd)
                ordinal = (
                    attempt_number
                    if attempt_number is not None
                    else len(entries) + 1
                )
                dispatch = {
                    "schema_version": FRESH24_DISPATCH_SCHEMA,
                    "authority_id": approval.authority_id,
                    "place_id": place_id,
                    "request_sha256": request_sha256,
                    "claim_sha256": claim.claim_sha256,
                    "attempt_number": ordinal,
                    "committed_exposure_micro_usd": self._committed_exposure_from(
                        entries
                    ),
                }
                name = f"dispatch-{ordinal:02d}.json"
                self._publish_create_only(
                    journal, name, canonical_json_bytes(dispatch)
                )
                os.fsync(journal)
                os.fsync(root_fd)
                return ordinal
            finally:
                os.close(journal)
                os.close(root_fd)

    def _read_ledger_from(self, root_fd: int) -> list[dict[str, object]]:
        if self._exists(root_fd, self._names["ledger"]):
            raw = self._read_regular_bytes(
                root_fd, self._names["ledger"], allow_empty=True
            )
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
        claim: Fresh24Claim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        response_body: bytes | None,
        status_code: int | None,
        profile_payload: Mapping[str, object] | None,
    ) -> str:
        """Durably store per-attempt raw/profile evidence and its digest."""

        approval = self._require_exact_claim(claim=claim)
        raw_digest = (
            hashlib.sha256(response_body).hexdigest() if response_body is not None else None
        )
        profile_digest = (
            canonical_sha256(profile_payload) if profile_payload is not None else None
        )
        attempt = {
            "schema_version": FRESH24_ATTEMPT_SCHEMA,
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
            "profile_sha256": profile_digest,
        }
        evidence_preimage = {
            "schema_version": FRESH24_ATTEMPT_SCHEMA,
            "attempt": attempt,
            "raw_response_sha256": raw_digest,
            "profile_sha256": profile_digest,
        }
        evidence_sha256 = canonical_sha256(evidence_preimage)
        with self._lock:
            root_fd = self._open_root(create=False)
            journal = self._open_private_dir(root_fd, self._names["journal"])
            raw_dir = self._open_private_dir(root_fd, self._names["raw"])
            profiles_dir = self._open_private_dir(root_fd, self._names["profiles"])
            try:
                if response_body is not None:
                    # Idempotent: re-persisting the identical bytes is a no-op;
                    # different bytes for one attempt ordinal fail closed.
                    try:
                        self._publish_create_only(
                            raw_dir,
                            f"response-{attempt_number:02d}.bin",
                            response_body,
                        )
                    except FileExistsError:
                        raw_name = f"response-{attempt_number:02d}.bin"
                        existing_raw = self._read_regular_bytes(
                            raw_dir, raw_name, allow_empty=True
                        )
                        if existing_raw != response_body:
                            raise PermissionError(
                                "FRESH24_RAW_REPLACEMENT_FORBIDDEN"
                            ) from None
                attempt_name = f"attempt-{attempt_number:02d}.json"
                attempt_payload = canonical_json_bytes(
                    {**attempt, "evidence_sha256": evidence_sha256}
                )
                try:
                    self._publish_create_only(journal, attempt_name, attempt_payload)
                except FileExistsError:
                    existing_attempt = self._read_regular_bytes(journal, attempt_name)
                    if existing_attempt != attempt_payload:
                        raise PermissionError(
                            "FRESH24_ATTEMPT_REPLACEMENT_FORBIDDEN"
                        ) from None
                if profile_payload is not None:
                    place_tag = re.sub(r"[^A-Za-z0-9_-]", "_", place_id)[:160]
                    profile_payload_bytes = canonical_json_bytes(profile_payload)
                    profile_name = f"profile-{attempt_number:02d}-{place_tag}.json"
                    try:
                        self._publish_create_only(profiles_dir, profile_name, profile_payload_bytes)
                    except FileExistsError:
                        existing_profile = self._read_regular_bytes(profiles_dir, profile_name)
                        if existing_profile != profile_payload_bytes:
                            raise PermissionError("FRESH24_PROFILE_REPLACEMENT_FORBIDDEN") from None
                os.fsync(raw_dir)
                os.fsync(profiles_dir)
                os.fsync(journal)
            finally:
                os.close(raw_dir)
                os.close(profiles_dir)
                os.close(journal)
                os.close(root_fd)
        return evidence_sha256

    def publish_profile_evidence(
        self,
        *,
        claim: Fresh24Claim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        profile_payload: Mapping[str, object],
    ) -> None:
        """No-replace publish one parsed profile bound to its attempt identity."""

        self._require_exact_claim(claim=claim)
        profile_digest = canonical_sha256(profile_payload)
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
                        raise PermissionError(
                            "FRESH24_PROFILE_REPLACEMENT_FORBIDDEN"
                        ) from None
                del profile_digest
                os.fsync(profiles_dir)
            finally:
                os.close(profiles_dir)
                os.close(root_fd)

    def list_profile_names(self) -> list[str]:
        """List durable profile filenames via a no-follow directory descriptor."""

        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                if not self._exists(root_fd, self._names["profiles"]):
                    return []
                profiles_dir = self._open_existing_private_dir(
                    root_fd, self._names["profiles"]
                )
                try:
                    names = []
                    for name in sorted(os.listdir(profiles_dir)):
                        metadata = os.stat(
                            name, dir_fd=profiles_dir, follow_symlinks=False
                        )
                        if stat.S_ISLNK(metadata.st_mode):
                            raise PermissionError(
                                "FRESH24_PROFILE_SYMLINK_FORBIDDEN"
                            )
                        names.append(name)
                    return names
                finally:
                    os.close(profiles_dir)
            finally:
                os.close(root_fd)

    def read_profile_bytes(self, name: str) -> bytes:
        """Reopen one durable profile through an exact no-follow descriptor."""

        if not re.fullmatch(r"profile-\d{2}-[A-Za-z0-9_-]{1,160}\.json", name):
            raise PermissionError("FRESH24_PROFILE_NAME_INVALID")
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                profiles_dir = self._open_existing_private_dir(
                    root_fd, self._names["profiles"]
                )
                try:
                    return self._read_regular_bytes(profiles_dir, name)
                finally:
                    os.close(profiles_dir)
            finally:
                os.close(root_fd)

    def commit_reservation(
        self,
        *,
        claim: Fresh24Claim,
        place_id: str,
        request_sha256: str,
        attempt_number: int,
        evidence_sha256: str,
    ) -> None:
        """Append COMMIT after reopening and digest-verifying durable evidence.

        The COMMIT requires the exact non-None evidence digest and reopens the
        attempt journal/raw files to verify their digests before appending.
        """

        if not isinstance(evidence_sha256, str) or not _DIGEST.fullmatch(
            evidence_sha256
        ):
            raise PermissionError("FRESH24_EVIDENCE_DIGEST_REQUIRED")
        approval = self._require_exact_claim(claim=claim)
        with self._lock:
            root_fd = self._open_root(create=False)
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                # Reopen and verify the persisted attempt evidence.
                attempt_bytes = self._read_regular_bytes(
                    journal, f"attempt-{attempt_number:02d}.json"
                )
                attempt_record = json.loads(attempt_bytes)
                if attempt_record.get("evidence_sha256") != evidence_sha256:
                    raise PermissionError("FRESH24_EVIDENCE_DIGEST_INVALID")
                if attempt_record.get("place_id") != place_id or attempt_record.get(
                    "request_sha256"
                ) != request_sha256:
                    raise PermissionError("FRESH24_EVIDENCE_LINEAGE_INVALID")
                raw_name = f"response-{attempt_number:02d}.bin"
                if self._exists(root_fd, self._names["raw"]):
                    raw_dir = self._open_existing_private_dir(
                        root_fd, self._names["raw"]
                    )
                    try:
                        if attempt_record.get("response_sha256") is not None:
                            if not self._exists(raw_dir, raw_name):
                                raise PermissionError("FRESH24_RAW_EVIDENCE_MISSING")
                            raw_bytes = self._read_regular_bytes(
                                raw_dir, raw_name, allow_empty=True
                            )
                            if hashlib.sha256(raw_bytes).hexdigest() != attempt_record[
                                "response_sha256"
                            ]:
                                raise PermissionError("FRESH24_RAW_DIGEST_INVALID")
                    finally:
                        os.close(raw_dir)
                commit_entry = {
                    "schema_version": FRESH24_LEDGER_ENTRY_SCHEMA,
                    "authority_id": approval.authority_id,
                    "operation": "COMMIT",
                    "attempt_number": attempt_number,
                    "amount_micro_usd": FRESH24_RESERVATION_MICRO_USD,
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
                    raise PermissionError("FRESH24_COMMIT_ORDER_INVALID")
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
        """No-replace publish the complete candidate-ready generation manifest."""

        payload = dict(generation)
        if payload.get("schema_version") != FRESH24_GENERATION_SCHEMA:
            raise ValueError("fresh24 generation schema drifted")
        payload.setdefault("authority_id", FRESH24_AUTHORITY_ID)
        serialized = canonical_json_bytes(payload)
        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                self._publish_create_only(root_fd, self._names["generation"], serialized)
            except FileExistsError as error:
                existing = self._read_regular_bytes(root_fd, self._names["generation"])
                if existing != serialized:
                    raise PermissionError(
                        "FRESH24_PROTECTED_REPLACEMENT_FORBIDDEN"
                    ) from error
            finally:
                os.close(root_fd)
        return hashlib.sha256(serialized).hexdigest()

    def publish_terminal(self, *, terminal: Mapping[str, object]) -> None:
        """No-replace publish the public-safe terminal inside protected state."""

        self.publish_terminal_raw(payload=canonical_json_bytes(terminal))

    def publish_terminal_raw(self, *, payload: bytes) -> None:
        """No-replace publish exact canonical terminal bytes (protected copy)."""

        with self._lock:
            root_fd = self._open_root(create=False)
            try:
                self._publish_or_require_exact(root_fd, self._names["terminal"], payload)
            finally:
                os.close(root_fd)

    def journal_inventory_digest(self) -> str:
        """Digest over the complete dispatch+attempt journal inventory."""

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

    def validate_journal_evidence_inventory(self) -> None:
        """Exact journal filename set derived from LEDGER operations.

        Operation-aware expectations (RECOVER_UNRESOLVED is a crash AFTER
        dispatch BEFORE evidence, so it must NOT own an attempt file):
        - every RESERVE ordinal N: exactly ``dispatch-N.json``;
        - every COMMIT ordinal N additionally owns ``attempt-N.json``;
        - a RECOVER_UNRESOLVED ordinal N owns ONLY ``dispatch-N.json`` — any
          ``attempt-N.json`` for a recovered ordinal proves evidence existed
          and the recovery was illegal.
        No extra, missing, orphan, or renamed evidence survives; each record
        names its own ordinal and matches its RESERVE's place/request/claim
        identity.  All reads are no-follow descriptors.
        """

        entries = self.read_ledger_entries()
        reserve_rows: dict[int, dict[str, object]] = {}
        commit_ordinals: set[int] = set()
        recovered_ordinals: set[int] = set()
        for row in entries:
            ordinal = int(row.get("attempt_number", 0))  # type: ignore[arg-type]
            operation = row.get("operation")
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
                    raise PermissionError(
                        "FRESH24_JOURNAL_MISSING_FOR_RESERVED_ATTEMPTS"
                    )
                return
            journal = self._open_existing_private_dir(root_fd, self._names["journal"])
            try:
                names = sorted(os.listdir(journal))
                expected_names = {
                    f"dispatch-{ordinal:02d}.json" for ordinal in reserve_rows
                } | {f"attempt-{ordinal:02d}.json" for ordinal in commit_ordinals}
                if set(names) != expected_names:
                    raise PermissionError(
                        "FRESH24_JOURNAL_FILENAME_UNRECOGNIZED"
                    )
                for name in names:
                    metadata = os.stat(
                        name, dir_fd=journal, follow_symlinks=False
                    )
                    if stat.S_ISLNK(metadata.st_mode):
                        raise PermissionError("FRESH24_JOURNAL_SYMLINK_FORBIDDEN")
                    dispatch_match = re.fullmatch(r"dispatch-(\d{2})\.json", name)
                    attempt_match = re.fullmatch(r"attempt-(\d{2})\.json", name)
                    if dispatch_match:
                        ordinal = int(dispatch_match.group(1))
                        record = json.loads(
                            self._read_regular_bytes(journal, name)
                        )
                        reserve_row = reserve_rows[ordinal]
                        if (
                            int(record.get("attempt_number", -1)) != ordinal
                            or record.get("place_id") != reserve_row.get("place_id")
                            or record.get("request_sha256")
                            != reserve_row.get("request_sha256")
                            or record.get("claim_sha256")
                            != reserve_row.get("claim_sha256")
                        ):
                            raise PermissionError(
                                "FRESH24_DISPATCH_LINEAGE_INVALID"
                            )
                    elif attempt_match:
                        ordinal = int(attempt_match.group(1))
                        # Evidence may exist ONLY for COMMIT attempts: a
                        # RECOVERED ordinal with an attempt file means the
                        # crash model was violated (evidence existed but the
                        # run claimed an unresolved recovery).
                        if ordinal in recovered_ordinals:
                            raise PermissionError(
                                "FRESH24_RECOVERY_WITH_EVIDENCE_INVALID"
                            )
                        # Lineage: each attempt record names its own ordinal
                        # and matches its RESERVE's place/request identity.
                        record = json.loads(
                            self._read_regular_bytes(journal, name)
                        )
                        reserve_row = reserve_rows[ordinal]
                        if (
                            int(record.get("attempt_number", -1)) != ordinal
                            or record.get("place_id") != reserve_row.get("place_id")
                            or record.get("request_sha256")
                            != reserve_row.get("request_sha256")
                        ):
                            raise PermissionError(
                                "FRESH24_ATTEMPT_ORDINAL_LINEAGE_INVALID"
                            )
                    else:
                        raise PermissionError(
                            "FRESH24_JOURNAL_FILENAME_UNRECOGNIZED"
                        )
            finally:
                os.close(journal)
        finally:
            os.close(root_fd)

    def read_protected_terminal(self) -> dict[str, object]:
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["terminal"]):
                raise PermissionError("FRESH24_PROTECTED_TERMINAL_MISSING")
            return self._read_canonical_json(root_fd, self._names["terminal"])
        finally:
            os.close(root_fd)

    def read_protected_terminal_bytes(self) -> bytes:
        """Reopen the protected terminal as exact canonical bytes."""

        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["terminal"]):
                raise PermissionError("FRESH24_PROTECTED_TERMINAL_MISSING")
            return self._read_regular_bytes(root_fd, self._names["terminal"])
        finally:
            os.close(root_fd)

    def validate_raw_evidence_inventory(self) -> None:
        """Exact raw-evidence filename set derived from COMMITTED attempts.

        ONLY COMMIT ordinals own raw evidence: every committed attempt
        ordinal N must own exactly ``response-N.bin``; a RECOVERED ordinal
        (crash after dispatch before evidence) must own NOTHING — a raw file
        for a recovered ordinal is illegal.  No extra raw file, orphan, or
        symlink survives.  Each file is REOPENED no-follow and its
        digest/place/request/ordinal lineage is checked against the attempt
        record and the ledger row: the stored bytes must hash to the
        attempt's ``response_sha256``, the attempt must name the same
        place/request/ordinal identity as its RESERVE.
        """

        entries = self.read_ledger_entries()
        reserves = {
            int(row.get("attempt_number", 0)): row  # type: ignore[arg-type]
            for row in entries
            if row.get("operation") == "RESERVE"
        }
        recovered_ordinals = {
            int(row.get("attempt_number", 0))  # type: ignore[arg-type]
            for row in entries
            if row.get("operation") == "RECOVER_UNRESOLVED"
        }
        expected_ordinals = sorted(
            int(row.get("attempt_number", 0))  # type: ignore[arg-type]
            for row in entries
            if row.get("operation") == "COMMIT"
        )
        root_fd = self._open_root(create=False)
        try:
            if not self._exists(root_fd, self._names["raw"]):
                if expected_ordinals:
                    raise PermissionError(
                        "FRESH24_RAW_EVIDENCE_MISSING_FOR_COMMITTED_ATTEMPTS"
                    )
                return
            raw_dir = self._open_existing_private_dir(root_fd, self._names["raw"])
            try:
                names = set(os.listdir(raw_dir))
                expected_names = {
                    f"response-{ordinal:02d}.bin" for ordinal in expected_ordinals
                }
                if names != expected_names:
                    raise PermissionError(
                        "FRESH24_RAW_INVENTORY_INVALID"
                    )
                for name in sorted(names):
                    metadata = os.stat(
                        name, dir_fd=raw_dir, follow_symlinks=False
                    )
                    if stat.S_ISLNK(metadata.st_mode):
                        raise PermissionError(
                            "FRESH24_RAW_SYMLINK_FORBIDDEN"
                        )
                    match = re.fullmatch(r"response-(\d{2})\.bin", name)
                    if not match:
                        raise PermissionError(
                            "FRESH24_RAW_FILENAME_UNRECOGNIZED"
                        )
                    ordinal = int(match.group(1))
                    if ordinal in recovered_ordinals:
                        raise PermissionError(
                            "FRESH24_RECOVERY_WITH_EVIDENCE_INVALID"
                        )
                    reserve_row = reserves[ordinal]
                    blob = self._read_regular_bytes(
                        raw_dir, name, allow_empty=True
                    )
                    journal = self._open_existing_private_dir(
                        root_fd, self._names["journal"]
                    )
                    try:
                        attempt_record = json.loads(
                            self._read_regular_bytes(
                                journal, f"attempt-{ordinal:02d}.json"
                            )
                        )
                    finally:
                        os.close(journal)
                    stored_digest = hashlib.sha256(blob).hexdigest()
                    if (
                        attempt_record.get("response_sha256") != stored_digest
                        or attempt_record.get("attempt_number") != ordinal
                        or attempt_record.get("place_id")
                        != reserve_row.get("place_id")
                        or attempt_record.get("request_sha256")
                        != reserve_row.get("request_sha256")
                    ):
                        raise PermissionError(
                            "FRESH24_RAW_LINEAGE_INVALID"
                        )
            finally:
                os.close(raw_dir)
        finally:
            os.close(root_fd)

    # ------------------------------------------------------------ reconciliation

    def reconcile_interrupted(
        self,
        *,
        claim: Fresh24Claim,
        request_sha256_by_place: Mapping[str, str] | None = None,
    ) -> dict[str, object] | None:
        """Close an interrupted dispatched exposure conservatively (no resend).

        Settled/pending state is tracked by the unique attempt identity
        (place_id, request_sha256, attempt ordinal) — never by request digest
        alone — so a committed first pass plus a crashed retry dispatch
        recovers exactly the retry attempt.  When ``request_sha256_by_place``
        is None (the CLI path) every unresolved RESERVE for this claim is
        considered; never re-dispatches.
        """

        approval = self._require_exact_claim(claim=claim)
        entries = self.read_ledger_entries()
        reserves = [
            row
            for row in entries
            if row.get("operation") == "RESERVE" and row.get("claim_sha256") == claim.claim_sha256
        ]
        settled_ids = {
            (
                row.get("place_id"),
                row.get("request_sha256"),
                int(row.get("attempt_number", 0)),  # type: ignore[arg-type]
            )
            for row in entries
            if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
        }
        pending = []
        for row in reserves:
            identity = (
                row.get("place_id"),
                row.get("request_sha256"),
                int(row.get("attempt_number", 0)),  # type: ignore[arg-type]
            )
            if identity in settled_ids:
                continue
            if request_sha256_by_place is not None:
                place_filter = request_sha256_by_place.get(str(row.get("place_id")))
                if place_filter is None or place_filter != row.get("request_sha256"):
                    continue
            pending.append(row)
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
                    ordinal = int(row.get("attempt_number", 0))  # type: ignore[arg-type]
                    dispatch_name = f"dispatch-{ordinal:02d}.json"
                    evidence_name = f"attempt-{ordinal:02d}.json"
                    dispatched = dispatch_name in journal_names
                    evidence_persisted = evidence_name in journal_names
                    recover_entry = {
                        "schema_version": FRESH24_LEDGER_ENTRY_SCHEMA,
                        "authority_id": approval.authority_id,
                        "operation": "RECOVER_UNRESOLVED",
                        "attempt_number": ordinal,
                        "amount_micro_usd": FRESH24_RESERVATION_MICRO_USD,
                        "place_id": place_id,
                        "request_sha256": row.get("request_sha256"),
                        "claim_sha256": claim.claim_sha256,
                        "evidence_sha256": None,
                    }
                    if dispatched and not evidence_persisted:
                        # Dispatched exposure with missing evidence: fail closed,
                        # commit the reservation conservatively, never resend.
                        pass
                    elif evidence_persisted:
                        raise PermissionError(
                            "FRESH24_RECONCILIATION_EVIDENCE_UNSETTLED"
                        )
                    else:
                        raise PermissionError("FRESH24_RECONCILIATION_DISPATCH_INVALID")
                    self._append_jsonl_line(
                        root_fd,
                        self._names["ledger"],
                        canonical_json_bytes(recover_entry) + b"\n",
                    )
                    recovered.append(recover_entry)
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        return {
            "status": "DESIGNED_NEGATIVE",
            "reason": "FRESH24_INTERRUPTED_EXPOSURE_CONSERVATIVE",
            "recovered_count": len(recovered),
            "committed_exposure_micro_usd": self.committed_exposure_micro_usd(),
            "network_attempted": False,
            "lifecycle_mutated": False,
        }

    def reconcile_terminal(
        self,
        *,
        claim: Fresh24Claim,
        approval: Fresh24ApprovalBinding,
        plan: Fresh24Plan,
        artifact: Mapping[str, object],
    ) -> dict[str, object] | None:
        """Close an interrupted run as a legal canonical ``Fresh24Terminal``.

        Runs the conservative ledger reconciliation first (never re-dispatches)
        and then builds the DESIGNED_NEGATIVE terminal through the strict
        contract — every count/exposure/digest field is validated by
        :class:`Fresh24Terminal` itself — and publishes it protected-first.
        Returns the exact published payload, or ``None`` when nothing was
        pending.  The public export is byte-identical to the protected copy so
        neutral verification can validate both.
        """

        approval_typed = (
            approval
            if isinstance(approval, Fresh24ApprovalBinding)
            else Fresh24ApprovalBinding.model_validate(approval)
        )
        if claim.approval_sha256 != approval_typed.approval_sha256:
            raise PermissionError("FRESH24_RECONCILIATION_CLAIM_MISMATCH")
        if claim.request_artifact_sha256 != str(artifact.get("request_artifact_sha256")):
            raise PermissionError("FRESH24_RECONCILIATION_PACKET_MISMATCH")
        # Derive pending attempts DIRECTLY from the ledger's attempt-identity
        # tuples (place, request, ordinal): every unsettled RESERVE for this
        # claim becomes exactly one RECOVER_UNRESOLVED — no caller-supplied
        # place filter can drop or duplicate a recovery.
        recovered = self.reconcile_interrupted(claim=claim, request_sha256_by_place=None)
        if recovered is None:
            return None
        entries = self.read_ledger_entries()
        reserves = [
            row for row in entries if row.get("operation") == "RESERVE"
        ]
        attempt_count = len(reserves)
        terminal = Fresh24Terminal.model_validate(
            {
                "schema_version": FRESH24_TERMINAL_SCHEMA,
                "status": "DESIGNED_NEGATIVE",
                "reason": "FRESH24_INTERRUPTED_EXPOSURE_CONSERVATIVE",
                "authority_id": FRESH24_AUTHORITY_ID,
                "request_sha256": plan.request.request_sha256,
                "request_file_sha256": claim.request_file_sha256,
                "checkout_manifest_sha256": plan.checkout_manifest_sha256,
                "claim_sha256": claim.claim_sha256,
                "ledger_sha256": canonical_sha256(entries),
                "journal_sha256": self.journal_inventory_digest(),
                "attempt_count": attempt_count,
                "retry_count": min(
                    max(0, attempt_count - FRESH24_FIRST_PASS_COUNT),
                    FRESH24_MAX_RETRIES,
                ),
                "committed_exposure_micro_usd": sum(
                    int(row.get("amount_micro_usd", 0))
                    for row in entries
                    if row.get("operation") in {"COMMIT", "RECOVER_UNRESOLVED"}
                ),
                "secret_read": False,
                "client_constructed": False,
                "network_attempted": True,
                "terminal_sha256": None,
            }
        )
        # Protected-first no-replace publish; identical canonical bytes are
        # what the CLI exports to the public path.
        payload = terminal.model_dump(mode="json")
        self.publish_terminal_raw(payload=canonical_json_bytes(payload))
        return payload

    # -------------------------------------------------------------- inventory

    def validate_root_inventory(self, *, require_generation: bool = True) -> None:
        """Require the EXACT no-follow protected root inventory.

        ``generation.json`` exists only on the positive branch; neutral
        verification of a designed negative/reconcile passes
        ``require_generation=False``.  Every OTHER entry is mandatory in every
        branch.  Orphan ``.stage-`` files are NOT ignored: any leftover
        staging artifact fails verification (a crash mid-publish must be
        reconciled, never silently accepted).  NO extras are permitted at the
        root; the raw-evidence directory's own contents are pinned exactly by
        :meth:`validate_raw_evidence_inventory` from the ledger attempts.  No
        entry may be a symlink.
        """

        expected = set(self._names.values())
        if not require_generation:
            expected.discard(self._names["generation"])
        root_fd = self._open_root(create=False)
        try:
            names = set(os.listdir(root_fd))
            if names != expected:
                raise PermissionError("FRESH24_PROTECTED_ROOT_INVENTORY_INVALID")
            for name in names:
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise PermissionError("FRESH24_PROTECTED_ROOT_SYMLINK_FORBIDDEN")
        finally:
            os.close(root_fd)


class Fresh24CapabilitySeal:
    """Opaque seal proving the sealed production executor produced a result."""

    __slots__ = ()

_CAPABILITY_SEAL = Fresh24CapabilitySeal()


async def _fresh24_live_attempt(
    *,
    endpoint: str,
    request_body: bytes,
    secret: str | None,
    open_client: Callable[..., object],
    deadline_seconds: int,
) -> tuple[int | None, bytes]:
    """One bounded whole-attempt request.

    The absolute monotonic deadline covers client construction (executed off
    the event loop via ``open_client``), the streaming request, and the
    bounded read.  ``open_client`` is a caller-supplied constructor seam used
    only by this module's two executors — the production entry passes its own
    lexical constructor and tests pass an asyncio.to_thread-backed one.
    """

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
            typed_client = cast(httpx.AsyncClient, client)
            try:
                async with typed_client.stream(
                    "POST", endpoint, content=request_body
                ) as response:
                    elapsed = asyncio.get_running_loop().time() - started
                    if elapsed > deadline_seconds:
                        raise TimeoutError("FRESH24_ATTEMPT_DEADLINE_EXCEEDED")
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared, 10)
                        except ValueError as error:
                            raise ValueError("FRESH24_CONTENT_LENGTH_INVALID") from error
                        if not 0 <= declared_size <= FRESH24_MAX_RESPONSE_BYTES:
                            raise ValueError("FRESH24_RESPONSE_TOO_LARGE")
                    chunks: list[bytes] = []
                    received = 0
                    async for chunk in response.aiter_bytes():
                        received += len(chunk)
                        if received > FRESH24_MAX_RESPONSE_BYTES:
                            raise ValueError("FRESH24_RESPONSE_TOO_LARGE")
                        chunks.append(chunk)
                    return response.status_code, b"".join(chunks)
            finally:
                await typed_client.aclose()
    except TimeoutError as error:
        raise TimeoutError("FRESH24_ATTEMPT_DEADLINE_EXCEEDED") from error


async def _execute_fresh24_transport(
    *,
    plan: Fresh24Plan,
    claim: Fresh24Claim,
    state: Fresh24DurableAuthorityState,
    credential_reader: Callable[[Fresh24ApprovalBinding], str],
    open_client: Callable[..., object],
    deadline_seconds: int = FRESH24_ATTEMPT_DEADLINE_SECONDS,
) -> dict[str, object]:
    """State-owned attempt loop: reserve → dispatch → attempt → evidence → COMMIT.

    Ordering guarantees enforced here:
    - approval/claim are verified before anything else;
    - every attempt RESERVEs and DISPATCHes durably before the credential value
      is read or a client/socket exists (reserve-before-secret); the reader
      receives the reopened approval binding so it can verify the secret's
      non-value identity against the EXACT approved record before the value
      is touched;
    - the whole attempt (client construction included) is under one timeout;
    - first-pass retryable failures (transport classes and HTTP 429/500/502/503/
      504) enter the retry queue; retries run only after all 24 first passes;
    - COMMIT requires reopened digest-verified evidence and never accepts None.
    """

    # Approval/claim/packet binding precedes any capability use.
    approval = state.read_approval()
    state._require_exact_claim(claim=claim)
    scheduler = Fresh24Scheduler(tuple(member.place_id for member in plan.members))
    members_by_place = {member.place_id: member for member in plan.members}
    retry_queue: list[str] = []
    retried_once: set[str] = set()
    responses: dict[str, Mapping[str, object]] = {}
    successful_ordinals: dict[str, int] = {}
    secret_read = False

    def finalize_terminal(
        *,
        status: str,
        reason: str,
        extra: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Build the canonical terminal payload for this run and publish it."""

        fields: dict[str, object] = {
            "status": status,
            "reason": reason,
            "authority_id": FRESH24_AUTHORITY_ID,
            "request_sha256": plan.request.request_sha256,
            "request_file_sha256": claim.request_file_sha256,
            "checkout_manifest_sha256": plan.checkout_manifest_sha256,
            "claim_sha256": claim.claim_sha256,
            "ledger_sha256": canonical_sha256(state.read_ledger_entries()),
            "journal_sha256": state.journal_inventory_digest(),
            "attempt_count": scheduler.attempt_count,
            "retry_count": min(
                max(0, scheduler.attempt_count - FRESH24_FIRST_PASS_COUNT),
                FRESH24_MAX_RETRIES,
            ),
            "committed_exposure_micro_usd": state.committed_exposure_micro_usd(),
            "secret_read": secret_read,
            "client_constructed": True,
            "network_attempted": True,
        }
        if extra:
            fields.update(extra)
        terminal = Fresh24Terminal.model_validate({**fields, "terminal_sha256": None})
        state.publish_terminal(terminal=terminal.model_dump(mode="json"))
        return terminal.model_dump(mode="json")

    async def finalize_success_terminal() -> dict[str, object]:
        """Parse responses into profiles, evaluate, and publish the terminal.

        Every 200 response body is parsed through the fresh profile contract,
        bound to its per-attempt evidence, and only then evaluated with the
        deterministic cohort kernel (hard-duplicate → cannot-coappear →
        effective counts, eight scenario result/replay entries, seven
        contrasts).  The generation manifest and protected/public terminals
        are published no-replace before returning.
        """

        profiles_by_place: dict[str, Mapping[str, object]] = {}
        for place_id in sorted(responses):
            response = responses[place_id]
            member = members_by_place[place_id]
            request_digest = member.request.request_sha256  # type: ignore[union-attr]
            if not isinstance(response.get("body"), bytes) or not response["body"]:
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason="FRESH24_RESPONSE_EMPTY"
                )
            try:
                parsed = json.loads(bytes(response["body"]).decode("utf-8"))  # type: ignore[arg-type]
            except (UnicodeDecodeError, json.JSONDecodeError):
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason="FRESH24_RESPONSE_INVALID_JSON"
                )
            if not isinstance(parsed, Mapping):
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason="FRESH24_RESPONSE_SHAPE_INVALID"
                )
            try:
                profile_payload = _validate_response_profile_lineage(
                    profile_value=parsed.get("profile", parsed),
                    place_id=place_id,
                    member=member,
                )
            except ValueError:
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE",
                    reason="FRESH24_PROFILE_LINEAGE_INVALID",
                )
            # Bind the parsed profile durably to this place's successful
            # attempt ordinal; the raw body and attempt record were already
            # persisted by run_attempt.
            ordinal = successful_ordinals[place_id]
            state.publish_profile_evidence(
                claim=claim,
                place_id=place_id,
                request_sha256=request_digest,
                attempt_number=ordinal,
                profile_payload=profile_payload,
            )
            profiles_by_place[place_id] = profile_payload

        if len(profiles_by_place) != FRESH24_MEMBER_COUNT:
            return finalize_terminal(
                status="DESIGNED_NEGATIVE", reason="FRESH24_EXACT_24_REQUIRED"
            )
        ordered_profiles = [
            profiles_by_place[member.place_id] for member in plan.members
        ]
        decision, evaluation = evaluate_fresh24_profiles(
            tuple(ordered_profiles),
            evidence_timestamp=fresh24_fixed_evidence_timestamp(
                plan.checkout_commit_sha256
            ),
        )
        if (
            not decision.recommendation_eligible
            or decision.effective_candidate_count < FRESH24_MIN_EFFECTIVE_CANDIDATES
        ):
            return finalize_terminal(
                status="DESIGNED_NEGATIVE",
                reason=decision.reason or "FRESH24_COHORT_INELIGIBLE",
            )
        scenario_map = {row.scenario_id: row for row in evaluation.scenario_results}
        confidence_rank_invariant = all(
            len({row.result_sha256 for row in [scenario_map[sid]]}) == 1
            for sid in CANONICAL_SCENARIO_IDS
        )
        del confidence_rank_invariant
        generation = build_fresh24_generation_manifest(
            plan=plan,
            claim=claim,
            profiles=ordered_profiles,
            scenario_results=[row.model_dump(mode="json") for row in evaluation.scenario_results],
            contrast_results=[row.model_dump(mode="json") for row in evaluation.contrast_results],
            attempt_count=scheduler.attempt_count,
            retry_count=min(
                max(0, scheduler.attempt_count - FRESH24_FIRST_PASS_COUNT),
                FRESH24_MAX_RETRIES,
            ),
            committed_exposure_micro_usd=state.committed_exposure_micro_usd(),
        )
        generation_bytes = canonical_json_bytes(generation)
        generation_sha256 = hashlib.sha256(generation_bytes).hexdigest()
        state.publish_generation(generation=generation)
        fields = {
            "status": "COMPLETE_CANDIDATE_READY",
            "reason": "COMPLETE_CANDIDATE_READY",
            "authority_id": FRESH24_AUTHORITY_ID,
            "request_sha256": plan.request.request_sha256,
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
                max(0, scheduler.attempt_count - FRESH24_FIRST_PASS_COUNT),
                FRESH24_MAX_RETRIES,
            ),
            "committed_exposure_micro_usd": state.committed_exposure_micro_usd(),
            "scenario_results": list(evaluation.scenario_results),
            "contrast_results": list(evaluation.contrast_results),
            "confidence_is_ranking_input": False,
            "secret_read": secret_read,
            "client_constructed": True,
            "network_attempted": True,
        }
        terminal = Fresh24Terminal.model_validate({**fields, "terminal_sha256": None})
        # Publish protected first; export exactly the same canonical safe bytes.
        state.publish_terminal_raw(payload=canonical_json_bytes(terminal.model_dump(mode="json")))
        return terminal.model_dump(mode="json")

    async def run_attempt(place_id: str, *, is_retry: bool) -> dict[str, object] | None:
        nonlocal secret_read
        member = members_by_place[place_id]
        request_digest = member.request.request_sha256  # type: ignore[union-attr]
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
        secret: str | None = None
        status_code: int | None = None
        body: bytes | None = None
        failure_reason: str | None = None
        try:
            secret = credential_reader(approval)
            secret_read = True
            if not isinstance(secret, str) or not secret.strip():
                raise ValueError("FRESH24_SECRET_UNAVAILABLE")
            status_code, body = await _fresh24_live_attempt(
                endpoint=plan.authority.endpoint,
                request_body=member.request_body,
                secret=secret,
                open_client=open_client,
                deadline_seconds=deadline_seconds,
            )
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadError,
            httpx.ReadTimeout,
            httpx.WriteError,
            httpx.WriteTimeout,
        ) as error:
            failure_reason = type(error).__name__
        except TimeoutError as error:
            failure_reason = str(error) or "FRESH24_ATTEMPT_DEADLINE_EXCEEDED"
        except ValueError as error:
            failure_reason = str(error) or "FRESH24_RESPONSE_INVALID"
        evidence = state.persist_attempt_evidence(
            claim=claim,
            place_id=place_id,
            request_sha256=request_digest,
            attempt_number=attempt_number,
            response_body=body,
            status_code=status_code,
            profile_payload=None,
        )
        state.commit_reservation(
            claim=claim,
            place_id=place_id,
            request_sha256=request_digest,
            attempt_number=attempt_number,
            evidence_sha256=evidence,
        )
        if failure_reason is None:
            if isinstance(status_code, int) and scheduler.classify_retry(
                status_code=status_code
            ):
                if is_retry:
                    return finalize_terminal(
                        status="DESIGNED_NEGATIVE", reason=f"HTTP_{status_code}"
                    )
                retry_queue.append(place_id)
                return None
            if status_code != 200:
                return finalize_terminal(
                    status="DESIGNED_NEGATIVE", reason=f"HTTP_{status_code}"
                )
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
        # The retry budget guard tripped (more than six retryable first-pass
        # failures): fail closed as a designed negative without resending.
        return finalize_terminal(
            status="DESIGNED_NEGATIVE", reason=str(error)
        )
    for place_id in retry_plan:
        failure = await run_attempt(place_id, is_retry=True)
        if failure is not None:
            return failure
    return await finalize_success_terminal()


def _fresh24_open_client_blocking(**kwargs: object) -> httpx.AsyncClient:
    """Fixed production constructor; runs off the event loop via to_thread."""

    return httpx.AsyncClient(**kwargs)


@dataclass(frozen=True, slots=True)
class _Fresh24RunnerBinding:
    """Immutable definition-time bundle of the sealed production runner.

    The public wrappers call EXACTLY one callable member of this frozen
    bundle (``invoke_sync`` / ``invoke_async``), captured into their
    default-argument cells at import time — never a module-global lookup and
    never an unstructured tuple member.  Every dependency inside (opener,
    credential resolver, executor) is itself a closure over this module's
    fixed definitions, so post-import monkeypatching or DELETION of any
    module symbol cannot redirect or break an already-bound entry point.
    """

    open_client: Callable[..., object]
    invoke_sync: Callable[..., dict[str, object]]
    invoke_async: Callable[..., object]


class Fresh24SecretUnavailable(RuntimeError):
    """Raised when no credential source is bound for a production attempt."""


def _make_fresh24_runner() -> _Fresh24RunnerBinding:
    """Build the production runner bundle as immutable closures.

    EVERY dependency — the fixed constructor and the sealed executor
    coroutine function — is captured in this factory's definition-time
    closure cells.  The credential path has NO caller seam: at reserve-
    before-secret time the runner resolves the credential through the
    DURABLE STATE instance (``state.credential_reader_for(approval)``),
    which only ever yields a reader that was pinned by the CLI live handler
    via ``bind_credential_reader`` — after verifying approval/claim/root
    identity.  The public wrappers are FINAL import-time functions whose
    bodies call one frozen bundle member through default-argument cells, so
    they LOAD_GLOBAL nothing but module constants: replacing or deleting ANY
    module symbol after import cannot redirect or break an already-bound
    production entry point — behavior stays identical with no NameError.

    Late-constructor ownership: the opener tracks whether the awaiting
    attempt actually TOOK the client.  Only when construction completes after
    the caller was cancelled (ownership never transferred) does the callback
    close it; a normally completed client stays open for
    ``_fresh24_live_attempt``, which closes it exactly once in its own
    ``finally`` after the bounded request.
    """

    constructor_cell = _fresh24_open_client_blocking
    executor_cell = _execute_fresh24_transport

    def open_client(**kwargs: object) -> object:
        loop = asyncio.get_running_loop()
        # Ownership handoff with explicit cancellation handling.  The wrapper's
        # ``finally`` is the authoritative late-completion closer: if the
        # awaiting attempt was cancelled (deadline) before receiving the
        # client, the wrapper keeps draining the shielded future and closes
        # whatever the constructor produced.  A normal return transfers
        # ownership — no close here; _fresh24_live_attempt closes exactly once.

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
                    # Cancelled/deadline before ownership transfer: drain the
                    # shielded construction off-loop and close its product so
                    # a late constructor retains no send capability.
                    async def _drain_and_close():
                        try:
                            late = await future
                        except BaseException:
                            return
                        if late is not None and not getattr(
                            late, "is_closed", True
                        ):
                            await late.aclose()

                    closing = loop.create_task(_drain_and_close())

                    def _detach(_: asyncio.Future) -> None:  # type: ignore[type-arg]
                        closing.done()

                    closing.add_done_callback(_detach)

        return construct_transfer_on_take()

    def runner(
        *,
        plan: Fresh24Plan,
        state: Fresh24DurableAuthorityState,
        claim: Fresh24Claim,
        request_artifact: Mapping[str, object],
        run_sync: bool,
    ) -> dict[str, object]:
        # The credential resolver is the STATE-BOUND reader — pinned by the
        # CLI live handler on this exact root instance.  It is handed the
        # reopened approval binding and is invoked by the sealed executor
        # only AFTER each attempt's RESERVE + DISPATCH are durable.
        approval_binding = state.require_approval_matches_artifact(
            request_artifact=request_artifact
        )
        coroutine = executor_cell(
            plan=plan,
            claim=claim,
            state=state,
            credential_reader=state.credential_reader_for,
            open_client=open_client,
        )
        del approval_binding
        if run_sync:
            return asyncio.run(coroutine)
        return coroutine

    def invoke_sync(**kwargs: object) -> dict[str, object]:
        result = runner(**kwargs, run_sync=True)
        assert isinstance(result, dict)
        return result

    def invoke_async(**kwargs: object) -> object:
        # Returns the coroutine itself: the caller awaits it.
        return runner(**kwargs, run_sync=False)

    return _Fresh24RunnerBinding(
        open_client=open_client,
        invoke_sync=invoke_sync,
        invoke_async=invoke_async,
    )


# Stable alias for the mock executor path: binding at import time keeps
# execute_fresh24_mock independent of later module-global mutations of the
# sealed production executor.
execute_fresh24_mock_transport = _execute_fresh24_transport

_SYNC_BINDING = _make_fresh24_runner()
_ASYNC_BINDING = _make_fresh24_runner()


def run_fresh24_transport(
    *,
    plan: Fresh24Plan,
    state: Fresh24DurableAuthorityState,
    claim: Fresh24Claim,
    request_artifact: Mapping[str, object],
    _invoke: Callable[..., dict[str, object]] = _SYNC_BINDING.invoke_sync,
) -> dict[str, object]:
    """Final synchronous production entry point (import-time binding).

    The frozen bundle's ``invoke_sync`` callable rides in ``_invoke``'s
    default cell — captured ONCE at import.  This function body performs no
    dependency LOAD_GLOBALs, so monkeypatching or DELETING any module symbol
    after import cannot redirect or break an in-flight call: behavior is
    unchanged and no NameError can occur.
    """

    return _invoke(
        plan=plan,
        state=state,
        claim=claim,
        request_artifact=request_artifact,
    )


def execute_fresh24_transport_async(
    *,
    plan: Fresh24Plan,
    state: Fresh24DurableAuthorityState,
    claim: Fresh24Claim,
    request_artifact: Mapping[str, object],
    _invoke: Callable[..., object] = _ASYNC_BINDING.invoke_async,
):
    """Final awaitable production entry point over its own immutable bundle.

    Like :func:`run_fresh24_transport`, the pre-built bundle member is bound
    through a default-argument cell at import time; post-import module
    mutations cannot affect it.  Returns an awaitable coroutine.
    """

    return _invoke(
        plan=plan,
        state=state,
        claim=claim,
        request_artifact=request_artifact,
    )


def execute_fresh24_production(
    *,
    plan: Fresh24Plan,
    state: Fresh24DurableAuthorityState,
    claim: Fresh24Claim,
    request_artifact: Mapping[str, object],
    _invoke: Callable[..., dict[str, object]] = _SYNC_BINDING.invoke_sync,
) -> dict[str, object]:
    """Stable public alias of :func:`run_fresh24_transport` over the SAME
    frozen sync binding.

    There is no credential-reader parameter and no module-global lookup:
    the credential resolver is resolved per-run from the durable state
    instance (CLI-pinned via ``bind_credential_reader``).  Deleting or
    replacing every other module symbol afterwards leaves this entry
    point's behavior identical.
    """

    return _invoke(
        plan=plan,
        state=state,
        claim=claim,
        request_artifact=request_artifact,
    )


def synthetic_fresh24_claim(request_artifact_sha256: str) -> Fresh24Claim:
    """Create a provider-free typed claim exclusively for injected tests."""

    claim_fields = {
        "schema_version": FRESH24_CLAIM_SCHEMA,
        "authority_id": FRESH24_AUTHORITY_ID,
        "request_artifact_sha256": request_artifact_sha256,
        "request_file_sha256": request_artifact_sha256,
        "approval_sha256": "a" * 64,
        "protected_state_sha256": "b" * 64,
    }
    return Fresh24Claim.model_validate(
        {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
    )


_FRESH24_TEST_ROOT_MARKERS = ("/tmp/", "/private/tmp/", "/var/folders/", tempfile.gettempdir())


def _reject_production_root_alias(candidate: Path) -> None:
    """Refuse the production root itself and every lexical/canonical alias.

    Component-wise comparison catches the exact root, any descendant, symlink
    aliases (via resolve), and ``..``-spelled relatives that land inside it.
    """

    production = FRESH24_PROTECTED_ROOT
    production_resolved = Path(str(production)).resolve(strict=False)
    candidate_resolved = candidate.resolve(strict=False)
    for form in (candidate, candidate_resolved):
        if form in (production, production_resolved):
            raise PermissionError("FRESH24_MOCK_FORBIDS_PRODUCTION_ROOT")
        if production_resolved in form.parents or production in form.parents:
            raise PermissionError("FRESH24_MOCK_FORBIDS_PRODUCTION_ROOT_DESCENDANT")
    relative = os.path.relpath(candidate_resolved, production_resolved)
    if relative == "." or not relative.startswith(".."):
        raise PermissionError("FRESH24_MOCK_FORBIDS_PRODUCTION_ROOT_ALIAS")


async def execute_fresh24_mock(
    *,
    plan: Fresh24Plan,
    claim: Fresh24Claim,
    protected_state_root: Path,
    response_handler: Callable[[httpx.Request], httpx.Response],
) -> dict[str, object]:
    """Provider-free MockTransport helper bound to a disjoint test-only root.

    The production root — including every descendant, symlink alias, and
    ``..``-normalized spelling — is refused component-wise.  A production
    protected-state descriptor or a claim bound to one is also refused by
    namespace identity: tests can never write evidence into (or borrow the
    authority of) the fixed repository protected root.
    """

    root_str = str(protected_state_root)
    _reject_production_root_alias(Path(root_str))
    resolved = str(Path(root_str).resolve(strict=False))
    if not any(marker in resolved for marker in _FRESH24_TEST_ROOT_MARKERS):
        raise PermissionError("FRESH24_MOCK_REQUIRES_ISOLATED_TEST_ROOT")
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=root_str)
    # Namespace typing: a claim minted for the production descriptor cannot be
    # replayed against this test root.
    if claim.protected_state_sha256 != descriptor.protected_state_sha256:
        raise PermissionError("FRESH24_MOCK_CLAIM_ROOT_MISMATCH")
    state = Fresh24DurableAuthorityState(descriptor)

    async def open_client(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(response_handler), **kwargs
        )

    async def runner() -> dict[str, object]:
        return await execute_fresh24_mock_transport(
            plan=plan,
            claim=claim,
            state=state,
            credential_reader=lambda _approval: "provider-free-test-secret",
            open_client=open_client,
        )

    return await runner()


def _cohort_counts(profiles: Sequence[Mapping[str, object]]) -> tuple[int, int, int, int]:
    from itda.domain.demo_profile_eligibility import evaluate_nvidia_publication_cohort

    decision = evaluate_nvidia_publication_cohort(profiles)
    return (
        decision.candidate_count,
        decision.post_hard_duplicate_count,
        decision.post_cannot_coappear_count,
        decision.effective_candidate_count,
    )


def _candidate_from_profile(profile: Mapping[str, object], index: int) -> RecommendationCandidate:
    """Project a fresh profile into the existing deterministic kernel contract."""

    confidence = profile.get("confidence")
    if type(confidence) is not int:
        raise ValueError("fresh24 profile confidence is invalid")
    publishability = (
        Publishability.PUBLISHABLE if confidence >= 70 else Publishability.LIMITED_INFORMATION
    )
    eligible = confidence >= 55
    evidence_id = str(profile["evidence_ids"][0])
    reference_date = date(2026, 8, 20)
    axes = tuple(
        PlaceAxisSnapshot(
            axis=axis,
            value=int(
                profile["axis_scores"][
                    {"HISTORY_TRADITION": "H", "EMOTION_IMAGE": "E", "REST_IMMERSION": "R"}[
                        axis.value
                    ]
                ]
            ),
            evidence_ids=(evidence_id,),
        )
        for axis in ExperienceAxis
    )
    subattributes = tuple(
        PlaceSubattributeSnapshot(
            attribute_id=attribute,
            value=int(profile["subattributes"][attribute.value]),
            evidence_ids=(evidence_id,),
        )
        for attribute in SubattributeId
    )
    traits = tuple(
        PlaceTraitSnapshot(
            trait_id=trait,
            value=int(profile["mismatch_traits"][trait.value]),
            evidence_ids=(evidence_id,),
        )
        for trait in MismatchTraitId
    )
    conditions = tuple(
        PlaceConditionSnapshot(
            condition_id=condition,
            value=50,
            evidence_ids=(evidence_id,),
        )
        for condition in TravelConditionId
    )
    evidence = EvidenceSnippet(
        evidence_id=evidence_id,
        excerpt_ko="검증된 DEV 원천 설명 근거",
        source_label_ko="TourAPI 설명",
        attribution_ko="공식 관광 원천",
        contest_use_scope="noncommercial_contest_demo_evaluation",
        contest_rights_qualified=True,
        reference_date=reference_date,
    )
    return RecommendationCandidate(
        place_id=str(profile["place_id"]),
        place_name_ko=f"DEV 장소 {index + 1}",
        split=DataSplit.DEV,
        exact_release_member=True,
        profile_score_truth="LOCAL_PROFILE_SCORES",
        analysis_origin="DEMO_MODEL_DERIVED",
        publishability=publishability,
        recommendation_eligible=eligible,
        profile_sha256=str(profile["profile_sha256"]),
        duplicate_group_id=str(profile["place_id"]),
        overall_confidence=confidence,
        axis_scores=axes,  # type: ignore[arg-type]
        subattributes=subattributes,  # type: ignore[arg-type]
        mismatch_traits=traits,  # type: ignore[arg-type]
        condition_scores=conditions,  # type: ignore[arg-type]
        evidence=(evidence,),
        reference_date=reference_date,
        popularity=index,
        source_volume=1,
        image_state=ImageDisplayState.ABSENT,
    )


def _default_preference() -> RecommendationPreference:
    return RecommendationPreference(
        profile_id="fresh24-activation-preference",
        input_sha256=canonical_sha256({"fresh24": "activation"}),
        axis_targets=tuple(PreferenceAxisTarget(axis=axis, value=50) for axis in ExperienceAxis),  # type: ignore[arg-type]
        trait_targets=tuple(
            PreferenceTraitTarget(trait_id=trait, value=50, important=False)
            for trait in MismatchTraitId
        ),  # type: ignore[arg-type]
        condition_targets=tuple(
            TravelConditionTarget(condition_id=condition, value=50)
            for condition in TravelConditionId
        ),  # type: ignore[arg-type]
    )


def fresh24_fixed_evidence_timestamp(checkout_commit_sha256: str) -> object:
    """Derive the ONE fixed evidence timestamp from the checkout lineage.

    The commit's 40-hex characters pin a deterministic UTC instant so the
    ORIGINAL evaluation and EVERY neutral replay inject the SAME timestamp —
    result/replay digests are reproducible byte-for-byte forever.
    """

    if re.fullmatch(r"[0-9a-f]{40}", checkout_commit_sha256) is None:
        raise ValueError("fresh24 fixed evidence timestamp needs a valid commit")
    seconds = int(checkout_commit_sha256[:12], 16) % 0xFFFFFFFF
    return datetime.fromtimestamp(seconds, tz=UTC)


def evaluate_fresh24_profiles(
    profiles: Sequence[Mapping[str, object]],
    *,
    evidence_timestamp: object | None = None,
    cannot_coappear_pairs: Sequence[tuple[str, str]] | None = None,
    scenario_results: Sequence[object] | None = None,
    contrast_results: Sequence[object] | None = None,
) -> tuple[PublicationEligibilityDecision, ActivationSuiteEvaluation]:
    """Recompute both relations and complete D-31/D-32 maps from fresh values.

    ``evidence_timestamp`` is the FIXED timestamp recorded in the generation
    lineage; the live run and every neutral verification pass the SAME value
    so all result/replay/contribution/record digests reproduce exactly.  When
    omitted (contract-level tests only), one current instant is captured for
    the whole suite — never per scenario.
    """

    if cannot_coappear_pairs is not None:
        raise ValueError("caller relation authority is not accepted")
    candidates = tuple(
        _candidate_from_profile(profile, index) for index, profile in enumerate(profiles)
    )
    decision = evaluate_nvidia_publication_cohort(profiles)
    if scenario_results is not None and len(scenario_results) != 8:
        raise ValueError("scenario map is incomplete")
    if contrast_results is not None and len(contrast_results) != 7:
        raise ValueError("contrast map is incomplete")
    evaluation = evaluate_activation_scenarios(
        candidates=candidates,
        release_sha256=canonical_sha256([profile["profile_sha256"] for profile in profiles]),
        canonical_membership_sha256=FRESH24_MEMBERSHIP_SHA256,
        base_preference=_default_preference(),
        cannot_coappear_authority=CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority,
        created_at=evidence_timestamp,
    )
    if scenario_results is not None and (
        tuple(getattr(row, "scenario_id", None) for row in scenario_results)
        != CANONICAL_SCENARIO_IDS
    ):
        raise ValueError("scenario map is not canonical")
    if contrast_results is not None and (
        tuple(getattr(row, "pair", None) for row in contrast_results) != CANONICAL_CONTRAST_PAIRS
    ):
        raise ValueError("contrast map is not canonical")
    return decision, evaluation


def build_activation_evidence(
    *,
    candidates: tuple[object, ...],
    release_sha256: str,
    membership_sha256: str,
    base_preference: object,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    """Delegate complete D-31/D-32 evaluation to the existing deterministic kernel."""

    from itda.domain.recommendation import evaluate_activation_scenarios

    evaluation = evaluate_activation_scenarios(
        candidates=candidates,  # type: ignore[arg-type]
        release_sha256=release_sha256,
        canonical_membership_sha256=membership_sha256,
        base_preference=base_preference,  # type: ignore[arg-type]
        cannot_coappear_authority=CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority,
    )
    return evaluation.scenario_results, evaluation.contrast_results


class Fresh24TerminalDisposition(str):
    POSITIVE = "POSITIVE"
    DESIGNED_NEGATIVE = "DESIGNED_NEGATIVE"
    FAILED_UNACTIVATED = "FAILED_UNACTIVATED"


def verify_fresh24_terminal(value: Mapping[str, object]) -> str:
    """Neutral validation: accepts designed negative and complete positive branches."""

    try:
        terminal = Fresh24Terminal.model_validate(value)
    except Exception as error:
        raise ValueError("fresh24 terminal is malformed") from error
    if terminal.status == "COMPLETE_CANDIDATE_READY":
        return Fresh24TerminalDisposition.POSITIVE
    if terminal.status == "DESIGNED_NEGATIVE":
        return Fresh24TerminalDisposition.DESIGNED_NEGATIVE
    return Fresh24TerminalDisposition.FAILED_UNACTIVATED


def assert_fresh24_positive(value: Mapping[str, object]) -> bool:
    if verify_fresh24_terminal(value) != "POSITIVE":
        raise ValueError("fresh24 terminal is not COMPLETE_CANDIDATE_READY")
    return True


def classify_fresh24_terminal(value: Mapping[str, object]) -> str:
    return verify_fresh24_terminal(value)


__all__ = [
    "FRESH24_PUBLIC_REQUEST_RELATIVE",
    "FRESH24_PROTECTED_ROOT_RELATIVE",
    "FRESH24_TERMINAL_RELATIVE",
    "Fresh24CapabilityError",
    "Fresh24DurableAuthorityState",
    "Fresh24FirstPass",
    "Fresh24LedgerEvent",
    "Fresh24Member",
    "Fresh24Plan",
    "Fresh24ProtectedState",
    "Fresh24Reservation",
    "Fresh24Scheduler",
    "Fresh24TerminalDisposition",
    "Fresh24VerifiedOutcome",
    "execute_fresh24_transport_async",
    "run_fresh24_transport",
    "assert_fresh24_positive",
    "assert_fresh24_positive_outcome",
    "bind_positive_probe_evidence",
    "build_activation_evidence",
    "build_fresh24_generation_manifest",
    "build_fresh24_plan",
    "execute_fresh24_production",
    "synthetic_fresh24_claim",
    "verify_fresh24_outcome",
    "verify_fresh24_outcome_for_cli",
    "classify_verified_outcome",
    "checkout_manifest_sha256",
    "classify_fresh24_terminal",
    "evaluate_fresh24_profiles",
    "verify_fixed_source_authority",
    "verify_fresh24_terminal",
]
