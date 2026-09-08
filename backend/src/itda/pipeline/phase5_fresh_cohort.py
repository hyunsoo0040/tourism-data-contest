"""Provider-free planning and fail-closed execution for Phase 5 fresh NVIDIA work.

The executor in this module accepts a transport callback only so contract tests
can use a MockTransport.  The CLI preflight uses the planning half exclusively;
it never creates an HTTP client or reads ``NVIDIA_KEY``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import subprocess
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from itda.cli.freeze_preview import _rename_noreplace_at, open_directory_chain_no_follow
from itda.contracts.demo_profile_materialization import (
    NVIDIA_AUTHORITY_SHA256,
    NVIDIA_JSON_END_SENTINEL,
    NVIDIA_JSON_START_SENTINEL,
    DemoSourceBundle,
    NvidiaMinimaxProfileMaterializationConfig,
)
from itda.contracts.phase5_fresh_cohort import (
    FRESH_ATTEMPT_DEADLINE_SECONDS,
    FRESH_AUTHORITY_ID,
    FRESH_CONFIDENCE_THRESHOLD,
    FRESH_ENDPOINT,
    FRESH_EXPOSURE_CAP_MICRO_USD,
    FRESH_MAX_HTTP_ATTEMPTS,
    FRESH_MIN_ELIGIBLE_PROFILES,
    FRESH_MODEL,
    FRESH_PROVIDER_LANE,
    FRESH_RESERVATION_MICRO_USD,
    FreshApprovalBinding,
    FreshApprovalDecisionRecord,
    FreshAuthorityClaim,
    FreshNvidiaExposureLedger,
    FreshProtectedStateDescriptor,
    FreshPublicRequest,
    validate_fresh_authority_id,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.demo_profile_eligibility import (
    PublicationEligibilityDecision,
    evaluate_nvidia_profile_publication,
    evaluate_nvidia_publication_cohort,
)
from itda.pipeline.demo_profile_materialization import (
    NVIDIA_V5_PROFILE_SCHEMA_SHA256,
    NVIDIA_V5_PROMPT_SHA256,
    NVIDIA_V5_PROMPT_VERSION,
    build_nvidia_v5_request_bytes,
    validate_demo_source_bundle,
    validate_demo_source_inventory,
)

FRESH_PROMPT_VERSION = NVIDIA_V5_PROMPT_VERSION
FRESH_PROFILE_SCHEMA_VERSION = "itda.nvidia-minimax-model-derived-profile.v5"
FRESH_PROMPT_SHA256 = NVIDIA_V5_PROMPT_SHA256
FRESH_PROFILE_SCHEMA_SHA256 = NVIDIA_V5_PROFILE_SCHEMA_SHA256
FRESH_CONFIG_SHA256 = canonical_sha256(
    NvidiaMinimaxProfileMaterializationConfig.model_validate(
        {"authority_sha256": NVIDIA_AUTHORITY_SHA256}
    ).model_dump(mode="json")
)
FRESH_PUBLIC_REQUEST_RELATIVE = (
    "artifacts/public/phase5/fresh-provider-materialization-request.json"
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest") from error
    return value


def build_fresh_request_body(
    bundle: DemoSourceBundle,
    *,
    prompt_sha256: str = FRESH_PROMPT_SHA256,
    profile_schema_sha256: str = FRESH_PROFILE_SCHEMA_SHA256,
    config_sha256: str = FRESH_CONFIG_SHA256,
) -> bytes:
    """Build one deterministic restricted request body from one DEV bundle."""

    validated = validate_demo_source_bundle(bundle)
    if validated.split != "DEV" or not validated.sources:
        raise ValueError("fresh request requires one validated DEV source bundle")
    if (
        _strict_digest(prompt_sha256, "prompt_sha256") != FRESH_PROMPT_SHA256
        or _strict_digest(profile_schema_sha256, "profile_schema_sha256")
        != FRESH_PROFILE_SCHEMA_SHA256
        or _strict_digest(config_sha256, "config_sha256") != FRESH_CONFIG_SHA256
    ):
        raise ValueError("fresh NVIDIA request contract drifted")
    return build_nvidia_v5_request_bytes(
        validated,
        NvidiaMinimaxProfileMaterializationConfig.model_validate(
            {"authority_sha256": NVIDIA_AUTHORITY_SHA256}
        ),
    )


def checkout_manifest_sha256(repository_root: Path) -> str:
    """Hash tracked, non-evidence source files for the current checkout.

    ``.planning`` and restricted evidence are deliberately excluded.  The
    function is read-only and falls back to a bounded local walk for test
    directories that are not Git repositories.
    """

    root = repository_root.resolve(strict=False)
    paths: list[Path] = []
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=root,
            check=True,
            capture_output=True,
        )
        names = completed.stdout.decode("utf-8").split("\0")
        paths = [root / name for name in names if name]
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        paths = [path for path in root.rglob("*") if path.is_file()]
    rows: dict[str, str] = {}
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        if (
            relative.startswith(".planning/")
            or relative.startswith("artifacts/restricted/")
            or relative.startswith(".git/")
            or relative == FRESH_PUBLIC_REQUEST_RELATIVE
        ):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        rows[relative] = _sha256(path.read_bytes())
    return canonical_sha256(rows)


@dataclass(frozen=True, slots=True)
class FreshCohortPlan:
    authority_id: str
    source_bundles: tuple[DemoSourceBundle, ...]
    request_bodies: tuple[tuple[str, bytes], ...]
    source_inventory_sha256: str
    membership_sha256: str
    request_manifest_sha256: str
    checkout_manifest_sha256: str
    prompt_sha256: str
    profile_schema_sha256: str
    config_sha256: str
    public_request: FreshPublicRequest


def build_fresh_cohort_plan(
    source_bundles: Sequence[DemoSourceBundle],
    *,
    checkout_manifest: str = "0" * 64,
    prompt_sha256: str = FRESH_PROMPT_SHA256,
    profile_schema_sha256: str = FRESH_PROFILE_SCHEMA_SHA256,
    config_sha256: str = FRESH_CONFIG_SHA256,
    authority_id: str = FRESH_AUTHORITY_ID,
) -> FreshCohortPlan:
    validate_fresh_authority_id(authority_id)
    bundles = validate_demo_source_inventory(tuple(source_bundles))
    checkout_digest = _strict_digest(checkout_manifest, "checkout_manifest")
    prompt_digest = _strict_digest(prompt_sha256, "prompt_sha256")
    schema_digest = _strict_digest(profile_schema_sha256, "profile_schema_sha256")
    config_digest = _strict_digest(config_sha256, "config_sha256")
    request_bodies = tuple(
        (
            bundle.place_id,
            build_fresh_request_body(
                bundle,
                prompt_sha256=prompt_digest,
                profile_schema_sha256=schema_digest,
                config_sha256=config_digest,
            ),
        )
        for bundle in bundles
    )
    source_inventory = canonical_sha256([bundle.source_bundle_sha256 for bundle in bundles])
    membership = canonical_sha256([bundle.place_id for bundle in bundles])
    request_manifest = canonical_sha256(
        {place_id: _sha256(body) for place_id, body in request_bodies}
    )
    public_seed = {
        "schema_version": "itda.phase5-fresh-provider-request.v1",
        "authority_id": authority_id,
        "provider_lane": FRESH_PROVIDER_LANE,
        "endpoint": FRESH_ENDPOINT,
        "model": FRESH_MODEL,
        "source_inventory_sha256": source_inventory,
        "membership_sha256": membership,
        "prompt_sha256": prompt_digest,
        "profile_schema_sha256": schema_digest,
        "config_sha256": config_digest,
        "request_manifest_sha256": request_manifest,
        "checkout_manifest_sha256": checkout_digest,
        "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
        "reservation_micro_usd": FRESH_RESERVATION_MICRO_USD,
        "max_new_http_attempts": FRESH_MAX_HTTP_ATTEMPTS,
        "attempt_deadline_seconds": FRESH_ATTEMPT_DEADLINE_SECONDS,
        "concurrency": 1,
        "price_status": "UNKNOWN",
        "invocation_policy": "SINGLE_INVOCATION",
        "confidence_threshold": FRESH_CONFIDENCE_THRESHOLD,
        "minimum_eligible_profiles": FRESH_MIN_ELIGIBLE_PROFILES,
        "blind_access": False,
        "network_attempted": False,
    }
    public_request = FreshPublicRequest.model_validate(
        {**public_seed, "public_request_sha256": canonical_sha256(public_seed)}
    )
    return FreshCohortPlan(
        authority_id=authority_id,
        source_bundles=bundles,
        request_bodies=request_bodies,
        source_inventory_sha256=source_inventory,
        membership_sha256=membership,
        request_manifest_sha256=request_manifest,
        checkout_manifest_sha256=checkout_digest,
        prompt_sha256=prompt_digest,
        profile_schema_sha256=schema_digest,
        config_sha256=config_digest,
        public_request=public_request,
    )


class FreshProtectedStateResolver:
    """Resolve one fixed logical authority ID to protected-only destinations."""

    def __init__(self, *, protected_state_root: Path) -> None:
        root = protected_state_root.absolute()
        if protected_state_root.is_symlink():
            raise ValueError("fresh protected state root cannot be a symlink")
        self._descriptor = FreshProtectedStateDescriptor.from_root(
            authority_id=FRESH_AUTHORITY_ID,
            state_root=root,
        )

    @property
    def descriptor(self) -> FreshProtectedStateDescriptor:
        return self._descriptor

    def resolve(self, authority_id: str) -> FreshProtectedStateDescriptor:
        validate_fresh_authority_id(authority_id)
        if authority_id != self._descriptor.authority_id:
            raise PermissionError("FRESH_AUTHORITY_ID_NOT_FOUND")
        return self._descriptor


class FreshAuthorityState:
    """In-memory one-use claim state used by provider-free tests and runners."""

    def __init__(self, *, plan: FreshCohortPlan, descriptor: FreshProtectedStateDescriptor) -> None:
        if plan.authority_id != descriptor.authority_id:
            raise PermissionError("FRESH_AUTHORITY_STATE_ID_MISMATCH")
        self._plan = plan
        self._descriptor = descriptor
        self._approval: FreshApprovalBinding | None = None
        self._claim: FreshAuthorityClaim | None = None
        self._lock = threading.Lock()

    @property
    def claim(self) -> FreshAuthorityClaim | None:
        with self._lock:
            return self._claim

    def install_approval(self, approval: FreshApprovalBinding) -> None:
        with self._lock:
            if approval.authority_id != self._plan.authority_id:
                raise PermissionError("FRESH_APPROVAL_AUTHORITY_MISMATCH")
            if approval.public_request_sha256 != self._plan.public_request.public_request_sha256:
                raise PermissionError("FRESH_APPROVAL_REQUEST_MISMATCH")
            if approval.checkout_manifest_sha256 != self._plan.checkout_manifest_sha256:
                raise PermissionError("FRESH_APPROVAL_CHECKOUT_MISMATCH")
            if approval.protected_state_sha256 != self._descriptor.protected_state_sha256:
                raise PermissionError("FRESH_APPROVAL_PROTECTED_STATE_MISMATCH")
            if self._claim is not None:
                raise PermissionError("FRESH_APPROVAL_ALREADY_CLAIMED")
            self._approval = approval

    def claim_once(self) -> FreshAuthorityClaim:
        with self._lock:
            if self._approval is None:
                raise PermissionError("FRESH_APPROVAL_REQUIRED")
            if self._claim is not None:
                raise PermissionError("FRESH_AUTHORITY_ALREADY_CLAIMED")
            claim_digest = canonical_sha256(
                {
                    "authority_id": self._approval.authority_id,
                    "request_sha256": self._approval.public_request_sha256,
                    "approval_sha256": self._approval.approval_sha256,
                    "protected_state_sha256": self._approval.protected_state_sha256,
                }
            )
            self._claim = FreshAuthorityClaim(
                authority_id=self._approval.authority_id,
                request_sha256=self._approval.public_request_sha256,
                claim_sha256=claim_digest,
            )
            return self._claim


class FreshDurableAuthorityState:
    """Private restart-safe approval and atomic one-use claim state.

    The descriptor resolves one fixed container root to a private ``state``
    directory.  Every file operation is relative to a pinned directory
    descriptor, rejects links/non-regular files, and publishes create-only.
    """

    _MAX_STATE_BYTES = 128 * 1024

    def __init__(
        self,
        *,
        plan: FreshCohortPlan,
        descriptor: FreshProtectedStateDescriptor,
    ) -> None:
        if plan.authority_id != descriptor.authority_id:
            raise PermissionError("FRESH_AUTHORITY_STATE_ID_MISMATCH")
        self._plan = plan
        self._descriptor = descriptor
        self._root = Path(descriptor.state_root)
        self._decision_name = self._target_name(
            descriptor.decision_target,
            expected="trusted-decision.json",
        )
        self._approval_name = self._target_name(
            descriptor.approval_target,
            expected="approval.json",
        )
        self._claim_name = self._target_name(
            descriptor.claim_target,
            expected="claim.json",
        )

    @property
    def descriptor(self) -> FreshProtectedStateDescriptor:
        return self._descriptor

    def install_approval(
        self,
        approval: FreshApprovalBinding,
        *,
        decision: FreshApprovalDecisionRecord | None = None,
    ) -> dict[str, object]:
        """Install one exact approval without replacing prior protected bytes."""

        self._validate_approval(approval)
        if decision is None:
            raise PermissionError("FRESH_APPROVAL_DECISION_REQUIRED")
        self._validate_decision(decision, approval)
        directory = self._open_root(create=True)
        try:
            if self._exists(directory, self._claim_name):
                raise PermissionError("FRESH_AUTHORITY_ALREADY_CLAIMED")
            self._publish_or_require_exact(
                directory,
                self._decision_name,
                canonical_json_bytes(decision.model_dump(mode="json")),
            )
            self._publish_or_require_exact(
                directory,
                self._approval_name,
                canonical_json_bytes(approval.model_dump(mode="json")),
            )
            os.fsync(directory)
        finally:
            os.close(directory)
        return self._status(approval, claimed=False)

    def claimed_preflight(
        self,
        *,
        expected_request_artifact_sha256: str | None = None,
        expected_approval_payload_sha256: str | None = None,
    ) -> tuple[dict[str, object], FreshAuthorityClaim]:
        """Validate and project an already-consumed claim for local reconciliation only."""

        try:
            directory = self._open_root(create=False)
        except FileNotFoundError as error:
            raise PermissionError("FRESH_APPROVAL_REQUIRED") from error
        try:
            approval = FreshApprovalBinding.model_validate_json(
                self._read_regular(directory, self._approval_name)
            )
            self._validate_approval(approval)
            if (
                expected_request_artifact_sha256 is not None
                and approval.request_artifact_sha256
                != _strict_digest(
                    expected_request_artifact_sha256,
                    "expected_request_artifact_sha256",
                )
            ):
                raise PermissionError("FRESH_REQUEST_ARTIFACT_MISMATCH")
            if (
                expected_approval_payload_sha256 is not None
                and approval.approval_payload_sha256
                != _strict_digest(
                    expected_approval_payload_sha256,
                    "expected_approval_payload_sha256",
                )
            ):
                raise PermissionError("FRESH_APPROVAL_PAYLOAD_MISMATCH")
            decision = FreshApprovalDecisionRecord.model_validate_json(
                self._read_regular(directory, self._decision_name)
            )
            self._validate_decision(decision, approval)
            if not self._exists(directory, self._claim_name):
                raise PermissionError("FRESH_AUTHORITY_NOT_CLAIMED")
            claim = self._read_and_validate_claim(directory, approval)
            return self._status(approval, claimed=True), claim
        finally:
            os.close(directory)

    def preflight(
        self,
        *,
        expected_request_artifact_sha256: str | None = None,
        expected_approval_payload_sha256: str | None = None,
    ) -> dict[str, object]:
        """Verify the exact unclaimed approval without exposing protected paths."""

        try:
            directory = self._open_root(create=False)
        except FileNotFoundError as error:
            raise PermissionError("FRESH_APPROVAL_REQUIRED") from error
        try:
            approval = self._load_unclaimed(
                directory,
                expected_request_artifact_sha256=expected_request_artifact_sha256,
                expected_approval_payload_sha256=expected_approval_payload_sha256,
            )
        except FileNotFoundError as error:
            raise PermissionError("FRESH_APPROVAL_REQUIRED") from error
        finally:
            os.close(directory)
        return self._status(approval, claimed=False)

    def claim_once(self) -> FreshAuthorityClaim:
        """Atomically consume the installed approval across processes/restarts."""

        try:
            directory = self._open_root(create=False)
        except FileNotFoundError as error:
            raise PermissionError("FRESH_APPROVAL_REQUIRED") from error
        try:
            approval = self._load_unclaimed(
                directory,
                expected_request_artifact_sha256=None,
                expected_approval_payload_sha256=None,
            )
            claim_digest = canonical_sha256(
                {
                    "authority_id": approval.authority_id,
                    "request_sha256": approval.public_request_sha256,
                    "approval_sha256": approval.approval_sha256,
                    "protected_state_sha256": approval.protected_state_sha256,
                }
            )
            claim = FreshAuthorityClaim(
                authority_id=approval.authority_id,
                request_sha256=approval.public_request_sha256,
                claim_sha256=claim_digest,
            )
            payload = canonical_json_bytes(
                {
                    "schema_version": "itda.phase5-fresh-authority-claim.v1",
                    "authority_id": claim.authority_id,
                    "request_sha256": claim.request_sha256,
                    "approval_sha256": approval.approval_sha256,
                    "protected_state_sha256": approval.protected_state_sha256,
                    "claim_sha256": claim.claim_sha256,
                }
            )
            try:
                self._publish_create_only(directory, self._claim_name, payload)
            except FileExistsError as error:
                raise PermissionError("FRESH_AUTHORITY_ALREADY_CLAIMED") from error
            os.fsync(directory)
            return claim
        finally:
            os.close(directory)

    def _load_unclaimed(
        self,
        directory: int,
        *,
        expected_request_artifact_sha256: str | None,
        expected_approval_payload_sha256: str | None,
    ) -> FreshApprovalBinding:
        approval = FreshApprovalBinding.model_validate_json(
            self._read_regular(directory, self._approval_name)
        )
        self._validate_approval(approval)
        if (
            expected_request_artifact_sha256 is not None
            and approval.request_artifact_sha256
            != _strict_digest(
                expected_request_artifact_sha256,
                "expected_request_artifact_sha256",
            )
        ):
            raise PermissionError("FRESH_REQUEST_ARTIFACT_MISMATCH")
        if (
            expected_approval_payload_sha256 is not None
            and approval.approval_payload_sha256
            != _strict_digest(
                expected_approval_payload_sha256,
                "expected_approval_payload_sha256",
            )
        ):
            raise PermissionError("FRESH_APPROVAL_PAYLOAD_MISMATCH")
        if not self._exists(directory, self._decision_name):
            raise PermissionError("FRESH_APPROVAL_DECISION_REQUIRED")
        decision = FreshApprovalDecisionRecord.model_validate_json(
            self._read_regular(directory, self._decision_name)
        )
        self._validate_decision(decision, approval)
        if self._exists(directory, self._claim_name):
            self._read_and_validate_claim(directory, approval)
            raise PermissionError("FRESH_AUTHORITY_ALREADY_CLAIMED")
        return approval

    def _validate_approval(self, approval: FreshApprovalBinding) -> None:
        if approval.authority_id != self._plan.authority_id:
            raise PermissionError("FRESH_APPROVAL_AUTHORITY_MISMATCH")
        if approval.checkout_manifest_sha256 != self._plan.checkout_manifest_sha256:
            raise PermissionError("FRESH_APPROVAL_CHECKOUT_MISMATCH")
        if approval.public_request_sha256 != self._plan.public_request.public_request_sha256:
            raise PermissionError("FRESH_APPROVAL_REQUEST_MISMATCH")
        if approval.protected_state_sha256 != self._descriptor.protected_state_sha256:
            raise PermissionError("FRESH_APPROVAL_PROTECTED_STATE_MISMATCH")

    def _validate_decision(
        self,
        decision: FreshApprovalDecisionRecord,
        approval: FreshApprovalBinding,
    ) -> None:
        if (
            decision.authority_id != approval.authority_id
            or decision.public_request_sha256 != approval.public_request_sha256
            or decision.checkout_manifest_sha256 != approval.checkout_manifest_sha256
            or decision.request_artifact_sha256 != approval.request_artifact_sha256
            or decision.approval_payload_sha256 != approval.approval_payload_sha256
            or decision.decision_sha256 != approval.trusted_decision_sha256
        ):
            raise PermissionError("FRESH_APPROVAL_DECISION_MISMATCH")

    def _read_and_validate_claim(
        self,
        directory: int,
        approval: FreshApprovalBinding,
    ) -> FreshAuthorityClaim:
        try:
            value = json.loads(self._read_regular(directory, self._claim_name))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PermissionError("FRESH_AUTHORITY_CLAIM_INVALID") from error
        expected = canonical_sha256(
            {
                "authority_id": approval.authority_id,
                "request_sha256": approval.public_request_sha256,
                "approval_sha256": approval.approval_sha256,
                "protected_state_sha256": approval.protected_state_sha256,
            }
        )
        if not isinstance(value, dict) or value != {
            "schema_version": "itda.phase5-fresh-authority-claim.v1",
            "authority_id": approval.authority_id,
            "request_sha256": approval.public_request_sha256,
            "approval_sha256": approval.approval_sha256,
            "protected_state_sha256": approval.protected_state_sha256,
            "claim_sha256": expected,
        }:
            raise PermissionError("FRESH_AUTHORITY_CLAIM_INVALID")
        return FreshAuthorityClaim(
            authority_id=approval.authority_id,
            request_sha256=approval.public_request_sha256,
            claim_sha256=expected,
        )

    def _status(
        self,
        approval: FreshApprovalBinding,
        *,
        claimed: bool,
    ) -> dict[str, object]:
        return {
            "schema_version": "itda.phase5-fresh-authority-status.v1",
            "status": "CLAIMED" if claimed else "APPROVED_UNCLAIMED",
            "authority_id": approval.authority_id,
            "public_request_sha256": approval.public_request_sha256,
            "approval_sha256": approval.approval_sha256,
            "claimed": claimed,
        }

    def _target_name(self, target: str, *, expected: str) -> str:
        path = Path(target)
        if path.parent != self._root or path.name != expected:
            raise PermissionError("FRESH_PROTECTED_STATE_TARGET_MISMATCH")
        return expected

    def _open_root(self, *, create: bool) -> int:
        descriptor = open_directory_chain_no_follow(self._root, create=create)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise PermissionError("FRESH_PROTECTED_STATE_ROOT_NOT_PRIVATE")
        return descriptor

    def _exists(self, directory: int, name: str) -> bool:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except FileNotFoundError:
            return False
        else:
            os.close(descriptor)
            return True

    def _read_regular(self, directory: int, name: str) -> bytes:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= self._MAX_STATE_BYTES
            ):
                raise PermissionError("FRESH_PROTECTED_STATE_FILE_INVALID")
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    raise PermissionError("FRESH_PROTECTED_STATE_FILE_TRUNCATED")
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if canonical_json_bytes(json.loads(payload)) != payload:
                raise PermissionError("FRESH_PROTECTED_STATE_FILE_NOT_CANONICAL")
            return payload
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PermissionError("FRESH_PROTECTED_STATE_FILE_INVALID") from error
        finally:
            os.close(descriptor)

    def _publish_or_require_exact(self, directory: int, name: str, payload: bytes) -> None:
        try:
            self._publish_create_only(directory, name, payload)
        except FileExistsError:
            if self._read_regular(directory, name) != payload:
                raise PermissionError(
                    "FRESH_PROTECTED_STATE_REPLACEMENT_FORBIDDEN"
                ) from None

    def _publish_create_only(self, directory: int, name: str, payload: bytes) -> None:
        staging_name = f".{name}.stage-{uuid.uuid4().hex}"
        published = False
        try:
            descriptor = os.open(
                staging_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory,
            )
            try:
                os.fchmod(descriptor, 0o600)
                written = 0
                while written < len(payload):
                    chunk = os.write(descriptor, payload[written:])
                    if chunk <= 0:
                        raise OSError("short fresh protected-state write")
                    written += chunk
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _rename_noreplace_at(directory, staging_name, directory, name)
            published = True
            os.fsync(directory)
        finally:
            if not published:
                with suppress(FileNotFoundError):
                    os.unlink(staging_name, dir_fd=directory)


class FreshTransport(Protocol):
    def __call__(self, place_id: str, request_body: bytes) -> object: ...


@dataclass(frozen=True, slots=True)
class FreshProfileObservation:
    place_id: str
    profile: Mapping[str, object] | None
    decision: PublicationEligibilityDecision
    response_sha256: str | None
    raw_response: bytes | None = field(default=None, repr=False)
    error: str | None = None


@dataclass(frozen=True, slots=True)
class FreshCohortExecutionResult:
    authority_id: str
    observations: tuple[FreshProfileObservation, ...]
    attempts: int
    ledger_snapshot: Mapping[str, object]
    terminal_reason: str | None
    release_build_eligible: bool
    activation_capability: bool

    @property
    def profiles(self) -> tuple[Mapping[str, object], ...]:
        return tuple(
            observation.profile
            for observation in self.observations
            if observation.profile is not None
        )

    @property
    def eligible_profiles(self) -> tuple[Mapping[str, object], ...]:
        return tuple(
            profile
            for profile in self.profiles
            if evaluate_nvidia_profile_publication(profile).recommendation_eligible
        )


def _unwrap_provider_profile(
    value: object,
) -> tuple[dict[str, object] | None, bytes | None, str | None]:
    if isinstance(value, bytes):
        raw = value
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, raw, "MALFORMED_PROVIDER_RESPONSE"
    if not isinstance(value, Mapping):
        return None, None, "MALFORMED_PROVIDER_RESPONSE"
    if isinstance(value.get("profile"), Mapping):
        return dict(value["profile"]), canonical_json_bytes(value), None
    if "axis_scores" in value:
        return dict(value), canonical_json_bytes(value), None
    choices = value.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        return None, canonical_json_bytes(value), "MALFORMED_PROVIDER_RESPONSE"
    message = choices[0].get("message")
    content = message.get("content") if isinstance(message, Mapping) else None
    if not isinstance(content, str):
        return None, canonical_json_bytes(value), "MALFORMED_PROVIDER_RESPONSE"
    if NVIDIA_JSON_START_SENTINEL not in content or NVIDIA_JSON_END_SENTINEL not in content:
        return None, canonical_json_bytes(value), "MALFORMED_PROVIDER_RESPONSE"
    start = content.index(NVIDIA_JSON_START_SENTINEL) + len(NVIDIA_JSON_START_SENTINEL)
    end = content.index(NVIDIA_JSON_END_SENTINEL, start)
    try:
        parsed = json.loads(content[start:end])
    except json.JSONDecodeError:
        return None, canonical_json_bytes(value), "MALFORMED_PROVIDER_RESPONSE"
    if not isinstance(parsed, Mapping):
        return None, canonical_json_bytes(value), "MALFORMED_PROVIDER_RESPONSE"
    return dict(parsed), canonical_json_bytes(value), None


def _call_transport(transport: FreshTransport, place_id: str, request_body: bytes) -> object:
    return transport(place_id, request_body)


def execute_fresh_cohort(
    *,
    plan: FreshCohortPlan,
    authority: FreshAuthorityState,
    transport: FreshTransport,
    ledger: FreshNvidiaExposureLedger | None = None,
    credential_reader: Callable[[], str] | None = None,
    reservation_sink: Callable[[Mapping[str, object]], object] | None = None,
) -> FreshCohortExecutionResult:
    """Execute a fresh cohort through an injected, normally MockTransport."""

    if (
        authority._plan.public_request.public_request_sha256
        != plan.public_request.public_request_sha256
    ):
        raise PermissionError("FRESH_PLAN_REQUEST_DRIFT")
    authority.claim_once()  # claim precedes optional secret access
    exposure = ledger or FreshNvidiaExposureLedger(authority_id=plan.authority_id)
    observations: list[FreshProfileObservation] = []
    terminal: str | None = None
    for place_id, request_body in plan.request_bodies:
        try:
            reservation = exposure.reserve()
        except RuntimeError:
            terminal = "NVIDIA_FRESH_EXPOSURE_BUDGET_EXHAUSTED"
            break
        if reservation_sink is not None:
            try:
                reservation_sink(
                    {
                        "authority_id": plan.authority_id,
                        "place_id": place_id,
                        "attempt_number": reservation.attempt_number,
                        "reservation_sha256": reservation.reservation_sha256,
                    }
                )
            except BaseException:
                exposure.release_before_socket(reservation)
                raise
        if credential_reader is not None:
            try:
                credential = credential_reader()
            except BaseException:
                exposure.release_before_socket(reservation)
                raise
            if not isinstance(credential, str) or not credential.strip():
                exposure.release_before_socket(reservation)
                terminal = "FRESH_NVIDIA_SECRET_UNAVAILABLE"
                break
        try:
            returned = _call_transport(transport, place_id, request_body)
        except FreshPreSocketFailure:
            exposure.release_before_socket(reservation)
            observations.append(
                FreshProfileObservation(
                    place_id=place_id,
                    profile=None,
                    decision=PublicationEligibilityDecision(False, False, "PRE_SOCKET_FAILURE"),
                    response_sha256=None,
                    error="PRE_SOCKET_FAILURE",
                )
            )
            continue
        except BaseException:
            exposure.commit(reservation)
            terminal = "PROVIDER_TRANSPORT_ERROR"
            break
        exposure.commit(reservation)
        profile, raw, error = _unwrap_provider_profile(returned)
        if error is not None or profile is None:
            observations.append(
                FreshProfileObservation(
                    place_id=place_id,
                    profile=None,
                    decision=PublicationEligibilityDecision(
                        False,
                        False,
                        error or "MALFORMED_PROVIDER_RESPONSE",
                    ),
                    response_sha256=_sha256(raw) if raw is not None else None,
                    raw_response=raw,
                    error=error or "MALFORMED_PROVIDER_RESPONSE",
                )
            )
            terminal = error or "MALFORMED_PROVIDER_RESPONSE"
            break
        # The place ID is part of returned-value validation; a provider cannot
        # borrow another place's profile or inherit an old cohort member.
        if profile.get("place_id") not in (None, place_id):
            terminal = "PROFILE_PLACE_ID_MISMATCH"
            observations.append(
                FreshProfileObservation(
                    place_id=place_id,
                    profile=None,
                    decision=PublicationEligibilityDecision(False, False, terminal),
                    response_sha256=_sha256(raw) if raw is not None else None,
                    raw_response=raw,
                    error=terminal,
                )
            )
            break
        profile["place_id"] = place_id
        decision = evaluate_nvidia_profile_publication(profile)
        observations.append(
            FreshProfileObservation(
                place_id=place_id,
                profile=profile,
                decision=decision,
                response_sha256=_sha256(raw) if raw is not None else None,
                raw_response=raw,
                error=None if decision.eligible else decision.reason,
            )
        )
        if not decision.eligible:
            terminal = decision.reason
            break
    profiles = tuple(
        observation.profile
        for observation in observations
        if observation.profile is not None
    )
    release_eligible = False
    if terminal is None:
        if len(profiles) != 24:
            terminal = "FRESH_COHORT_EXACT_24_REQUIRED"
        else:
            cohort = evaluate_nvidia_publication_cohort(profiles)
            if not cohort.eligible or not cohort.recommendation_eligible:
                terminal = cohort.reason
            else:
                release_eligible = True
    return FreshCohortExecutionResult(
        authority_id=plan.authority_id,
        observations=tuple(observations),
        attempts=exposure.attempt_count,
        ledger_snapshot=exposure.snapshot(),
        terminal_reason=terminal,
        release_build_eligible=release_eligible,
        activation_capability=release_eligible,
    )


class FreshPreSocketFailure(RuntimeError):
    """Injected transport failure proven to occur before socket exposure."""


def build_fresh_approval_binding(
    *,
    plan: FreshCohortPlan,
    descriptor: FreshProtectedStateDescriptor,
    trusted_decision_sha256: str,
    request_artifact_sha256: str | None = None,
    approval_payload_sha256: str | None = None,
    active_release_state: str = "NO_ACTIVE_SCORED_RELEASE",
) -> FreshApprovalBinding:
    decision_digest = _strict_digest(trusted_decision_sha256, "trusted_decision_sha256")
    artifact_digest = _strict_digest(
        request_artifact_sha256
        or canonical_sha256(plan.public_request.model_dump(mode="json")),
        "request_artifact_sha256",
    )
    approval_payload_digest = _strict_digest(
        approval_payload_sha256 or decision_digest,
        "approval_payload_sha256",
    )
    if active_release_state not in {
        "NO_ACTIVE_SCORED_RELEASE",
        "INVALIDATED_LEGACY_PREDECESSOR",
    }:
        raise ValueError("fresh approval active release state is invalid")
    payload = {
        "schema_version": "itda.phase5-fresh-approval-binding.v1",
        "authority_id": plan.authority_id,
        "public_request_sha256": plan.public_request.public_request_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "request_artifact_sha256": artifact_digest,
        "approval_payload_sha256": approval_payload_digest,
        "endpoint": FRESH_ENDPOINT,
        "model": FRESH_MODEL,
        "provider_lane": FRESH_PROVIDER_LANE,
        "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
        "reservation_micro_usd": FRESH_RESERVATION_MICRO_USD,
        "max_new_http_attempts": FRESH_MAX_HTTP_ATTEMPTS,
        "attempt_deadline_seconds": FRESH_ATTEMPT_DEADLINE_SECONDS,
        "concurrency": 1,
        "price_status": "UNKNOWN",
        "invocation_policy": "SINGLE_INVOCATION",
        "single_live_invocation": True,
        "confidence_threshold": FRESH_CONFIDENCE_THRESHOLD,
        "minimum_eligible_profiles": FRESH_MIN_ELIGIBLE_PROFILES,
        "active_release_state": active_release_state,
        "active_release_state_sha256": canonical_sha256(
            {"state": active_release_state}
        ),
        "trusted_decision_sha256": decision_digest,
        "protected_state_sha256": descriptor.protected_state_sha256,
    }
    return FreshApprovalBinding.model_validate(
        {**payload, "approval_sha256": canonical_sha256(payload)}
    )


def build_fresh_approval_decision(
    *,
    plan: FreshCohortPlan,
    request_artifact_sha256: str,
    approval_payload_sha256: str,
) -> FreshApprovalDecisionRecord:
    payload = {
        "schema_version": "itda.phase5-fresh-approval-decision.v1",
        "authority_id": plan.authority_id,
        "decision": "APPROVED",
        "public_request_sha256": plan.public_request.public_request_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "request_artifact_sha256": _strict_digest(
            request_artifact_sha256,
            "request_artifact_sha256",
        ),
        "approval_payload_sha256": _strict_digest(
            approval_payload_sha256,
            "approval_payload_sha256",
        ),
    }
    return FreshApprovalDecisionRecord.model_validate(
        {**payload, "decision_sha256": canonical_sha256(payload)}
    )


def validate_fresh_public_approval_artifact(
    *,
    plan: FreshCohortPlan,
    artifact: Mapping[str, object],
    approved_payload_sha256: object,
) -> tuple[str, str, str]:
    payload = dict(artifact)
    request_artifact_sha256 = _strict_digest(
        payload.pop("request_artifact_sha256", None),
        "request_artifact_sha256",
    )
    if canonical_sha256(payload) != request_artifact_sha256:
        raise PermissionError("FRESH_REQUEST_ARTIFACT_MISMATCH")
    approved_digest = _strict_digest(
        approved_payload_sha256,
        "approved_payload_sha256",
    )
    recorded_digest = _strict_digest(
        artifact.get("approval_payload_sha256"),
        "approval_payload_sha256",
    )
    if not hmac.compare_digest(approved_digest, recorded_digest):
        raise PermissionError("FRESH_APPROVAL_PAYLOAD_MISMATCH")

    expected_public = plan.public_request.model_dump(mode="json")
    if any(artifact.get(key) != value for key, value in expected_public.items()):
        raise PermissionError("FRESH_PUBLIC_REQUEST_MISMATCH")
    if (
        artifact.get("source_count") != 24
        or artifact.get("dev_member_count") != 24
        or artifact.get("dev_membership_order_sha256") != plan.membership_sha256
        or artifact.get("secret_read") is not False
        or artifact.get("provider_client_constructed") is not False
        or artifact.get("network_attempted") is not False
    ):
        raise PermissionError("FRESH_PUBLIC_REQUEST_MISMATCH")
    implementation_commit = artifact.get("implementation_commit")
    if not isinstance(implementation_commit, str) or len(implementation_commit) != 40:
        raise PermissionError("FRESH_IMPLEMENTATION_COMMIT_INVALID")
    try:
        int(implementation_commit, 16)
    except ValueError as error:
        raise PermissionError("FRESH_IMPLEMENTATION_COMMIT_INVALID") from error

    active_release_state = artifact.get("active_release_state")
    if active_release_state not in {
        "NO_ACTIVE_SCORED_RELEASE",
        "INVALIDATED_LEGACY_PREDECESSOR",
    }:
        raise PermissionError("FRESH_ACTIVE_RELEASE_STATE_MISMATCH")
    if artifact.get("active_release_state_sha256") != canonical_sha256(
        {"state": active_release_state}
    ):
        raise PermissionError("FRESH_ACTIVE_RELEASE_STATE_MISMATCH")
    approval_payload = {
        "authority_id": plan.authority_id,
        "public_request_sha256": plan.public_request.public_request_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "endpoint": plan.public_request.endpoint,
        "model": plan.public_request.model,
        "provider_lane": plan.public_request.provider_lane,
        "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
        "reservation_micro_usd": FRESH_RESERVATION_MICRO_USD,
        "max_new_http_attempts": FRESH_MAX_HTTP_ATTEMPTS,
        "attempt_deadline_seconds": FRESH_ATTEMPT_DEADLINE_SECONDS,
        "price_status": "UNKNOWN",
        "invocation_policy": "SINGLE_INVOCATION",
        "confidence_threshold": FRESH_CONFIDENCE_THRESHOLD,
        "minimum_eligible_profiles": FRESH_MIN_ELIGIBLE_PROFILES,
        "active_release_state": active_release_state,
        "blind_access": False,
    }
    if canonical_sha256(approval_payload) != recorded_digest:
        raise PermissionError("FRESH_APPROVAL_PAYLOAD_MISMATCH")
    return request_artifact_sha256, recorded_digest, str(active_release_state)


def install_fresh_approval_from_public_artifact(
    *,
    plan: FreshCohortPlan,
    descriptor: FreshProtectedStateDescriptor,
    artifact: Mapping[str, object],
    approved_payload_sha256: object,
) -> dict[str, object]:
    """Install only the exact current canonical public approval artifact."""

    request_artifact_sha256, approval_payload_sha256, active_release_state = (
        validate_fresh_public_approval_artifact(
            plan=plan,
            artifact=artifact,
            approved_payload_sha256=approved_payload_sha256,
        )
    )
    decision = build_fresh_approval_decision(
        plan=plan,
        request_artifact_sha256=request_artifact_sha256,
        approval_payload_sha256=approval_payload_sha256,
    )
    approval = build_fresh_approval_binding(
        plan=plan,
        descriptor=descriptor,
        trusted_decision_sha256=decision.decision_sha256,
        request_artifact_sha256=request_artifact_sha256,
        approval_payload_sha256=approval_payload_sha256,
        active_release_state=active_release_state,
    )
    return FreshDurableAuthorityState(
        plan=plan,
        descriptor=descriptor,
    ).install_approval(approval, decision=decision)


def safe_public_request_payload(plan: FreshCohortPlan) -> dict[str, object]:
    """Return the allowlisted public projection, never the request bodies."""

    return plan.public_request.model_dump(mode="json")


__all__ = [
    "FRESH_CONFIG_SHA256",
    "FRESH_PROFILE_SCHEMA_SHA256",
    "FRESH_PROMPT_SHA256",
    "FreshAuthorityState",
    "FreshCohortExecutionResult",
    "FreshCohortPlan",
    "FreshDurableAuthorityState",
    "FreshPreSocketFailure",
    "FreshProfileObservation",
    "FreshProtectedStateResolver",
    "build_fresh_approval_binding",
    "build_fresh_approval_decision",
    "build_fresh_cohort_plan",
    "build_fresh_request_body",
    "checkout_manifest_sha256",
    "execute_fresh_cohort",
    "install_fresh_approval_from_public_artifact",
    "safe_public_request_payload",
    "validate_fresh_public_approval_artifact",
]
