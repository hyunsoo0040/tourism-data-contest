"""Fail-closed DEV profile release lifecycle and immutable publication helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
import threading
from copy import deepcopy
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.profile_release_candidate_validation import (
    validate_profile_release_candidate_payload_v1,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_PRINCIPAL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_RELEASE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_NONCE_PATTERN = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)


class ProfileReleaseState(StrEnum):
    """The only legal externally observable release states."""

    BUILT_UNAPPROVED = "BUILT_UNAPPROVED"
    APPROVED_INACTIVE = "APPROVED_INACTIVE"
    ACTIVE = "ACTIVE"


class ProfileReleaseCompletion(StrEnum):
    """Observable completion semantics for uncertain mutation reconciliation."""

    MUTATION_COMMITTED = "MUTATION_COMMITTED"
    RELOOKUP_CONFIRMED = "RELOOKUP_CONFIRMED"


_ALLOWED_TRANSITIONS: frozenset[tuple[ProfileReleaseState, ProfileReleaseState]] = frozenset(
    {
        (ProfileReleaseState.BUILT_UNAPPROVED, ProfileReleaseState.APPROVED_INACTIVE),
        (ProfileReleaseState.APPROVED_INACTIVE, ProfileReleaseState.ACTIVE),
        (ProfileReleaseState.ACTIVE, ProfileReleaseState.APPROVED_INACTIVE),
    }
)


class ProfileReleaseReplayError(RuntimeError):
    """A nonce was reused or a compare-and-swap lost its race."""


class ProfileReleaseUnknownOutcomeError(RuntimeError):
    """A transport/commit failure has no authoritative committed row yet."""

    def __init__(self, *, action: str, lookup_path: str) -> None:
        super().__init__(f"{action} outcome is unknown; reconcile through the lookup endpoint")
        self.action = action
        self.lookup_path = lookup_path


class ProfileReleaseRetryableAbortError(RuntimeError):
    """A serializable transaction exhausted bounded safe retries before commit."""

    def __init__(self, *, action: str) -> None:
        super().__init__(f"{action} was safely aborted after serialization retries")
        self.action = action


class ProfileReleaseBuildUnavailableError(RuntimeError):
    """The draft could not be read before any BUILD mutation began."""

    def __init__(self, *, retry_path: str) -> None:
        super().__init__("BUILD is temporarily unavailable before mutation")
        self.action = "BUILD"
        self.retry_path = retry_path


class ProfileReleaseDraftCleanupUnknownError(RuntimeError):
    """BUILD is proven, but protected draft scrubbing cannot yet be proven."""

    def __init__(self, *, lookup_path: str, retry_path: str) -> None:
        super().__init__("BUILD draft cleanup outcome is unknown")
        self.action = "BUILD"
        self.lookup_path = lookup_path
        self.retry_path = retry_path


class ProfileReleaseBuildDraftReference(StrictContract):
    """Opaque, expiring handle; protected cohort bytes remain server-side."""

    draft_ref: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9_-]{43}$"),
    ]
    expires_at: datetime
    nonce_sha256: Sha256

    @model_validator(mode="after")
    def expiry_is_utc(self) -> Self:
        require_utc(self.expires_at, field_name="expires_at")
        return self


class ProfileReleaseDraftPurgeResult(StrictContract):
    """Payload-free retention job status suitable for logs and metrics."""

    event: Literal["profile_release_build_draft_purge"] = (
        "profile_release_build_draft_purge"
    )
    status: Literal["SUCCEEDED"] = "SUCCEEDED"
    deleted_count: Annotated[int, Field(strict=True, ge=0)]
    remaining_expired_count: Annotated[int, Field(strict=True, ge=0)]


class ProfileReleaseBuildReceipt(StrictContract):
    """Immutable internal proof for one builder-bound BUILD response."""

    schema_version: Literal["itda.profile-release-build-receipt.v1"] = (
        "itda.profile-release-build-receipt.v1"
    )
    release_sha256: Sha256
    builder_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    nonce_sha256: Sha256
    binding_sha256: Sha256
    receipt_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif not hmac.compare_digest(self.receipt_sha256, expected):
            raise ValueError("profile release build receipt digest drifted")
        return self


class ProfileReleaseBuildOutcome(StrictContract):
    """Public hash-only reconciliation projection for one committed BUILD."""

    outcome: Literal["COMMITTED"] = "COMMITTED"
    release_sha256: Sha256
    state: Literal[ProfileReleaseState.BUILT_UNAPPROVED] = ProfileReleaseState.BUILT_UNAPPROVED
    receipt_sha256: Sha256
    nonce_sha256: Sha256
    binding_sha256: Sha256
    completion: ProfileReleaseCompletion


class ProfileReleaseActivePointerProjection(StrictContract):
    """Current DEV pointer, or an explicit all-null no-active state."""

    active_release_sha256: Sha256 | None
    state: Literal[ProfileReleaseState.ACTIVE] | None
    receipt_sha256: Sha256 | None

    @model_validator(mode="after")
    def require_all_null_or_active(self) -> Self:
        populated = (
            self.active_release_sha256 is not None,
            self.state is not None,
            self.receipt_sha256 is not None,
        )
        if any(populated) and not all(populated):
            raise ValueError("profile release active pointer projection is partial")
        return self


class ProfileReleaseStateProjection(StrictContract):
    """Exact lifecycle head plus its independently validated provenance."""

    release_sha256: Sha256
    state: ProfileReleaseState
    lifecycle_head_receipt_sha256: Sha256 | None
    provenance_kind: Literal["BUILD", "APPROVAL", "TRANSITION"]
    provenance_receipt_sha256: Sha256

    @model_validator(mode="after")
    def require_state_provenance_shape(self) -> Self:
        if self.state == ProfileReleaseState.BUILT_UNAPPROVED:
            if (
                self.lifecycle_head_receipt_sha256 is not None
                or self.provenance_kind != "BUILD"
            ):
                raise ValueError("BUILT lifecycle provenance is inconsistent")
            return self
        if (
            self.lifecycle_head_receipt_sha256 is None
            or self.lifecycle_head_receipt_sha256 != self.provenance_receipt_sha256
        ):
            raise ValueError("approved lifecycle state requires its exact provenance head")
        if self.state == ProfileReleaseState.ACTIVE and self.provenance_kind != "TRANSITION":
            raise ValueError("ACTIVE lifecycle requires transition provenance")
        if (
            self.state == ProfileReleaseState.APPROVED_INACTIVE
            and self.provenance_kind not in {"APPROVAL", "TRANSITION"}
        ):
            raise ValueError("inactive approved lifecycle provenance is inconsistent")
        return self


class ProfileReleaseTransitionOutcome(StrictContract):
    """Public action-specific reconciliation projection with no actor or reason."""

    outcome: Literal["COMMITTED"] = "COMMITTED"
    action: Literal["ACTIVATE", "ROLLBACK"]
    release_sha256: Sha256
    previous_release_sha256: Sha256 | None
    expected_current_sha256: Sha256 | None
    receipt_sha256: Sha256
    nonce_sha256: Sha256
    binding_sha256: Sha256
    completion: ProfileReleaseCompletion

    @model_validator(mode="after")
    def require_exact_compare_and_swap_relationship(self) -> Self:
        if self.previous_release_sha256 != self.expected_current_sha256:
            raise ValueError("transition previous release differs from expected current")
        if self.action == "ROLLBACK" and self.previous_release_sha256 is None:
            raise ValueError("rollback transition requires a previous release")
        return self


def profile_release_build_binding_sha256_v1(*, builder_principal: str, release_sha256: str) -> str:
    """Bind BUILD to the server actor and already-canonical candidate hash."""

    return canonical_sha256(
        {
            "action": "BUILD",
            "builder": builder_principal,
            "release_sha256": release_sha256,
        }
    )


def profile_release_activate_binding_sha256_v1(
    *, target_sha256: str, expected_current_sha256: str | None
) -> str:
    """Reproduce the shipped 0008 ACTIVATE binding byte-for-byte."""

    return canonical_sha256(
        {
            "action": "ACTIVATE",
            "target": target_sha256,
            "expected": expected_current_sha256,
        }
    )


def profile_release_rollback_binding_sha256_v1(
    *,
    target_sha256: str,
    expected_current_sha256: str,
    reason_sha256: str,
    approver_principal: str,
) -> str:
    """Reproduce the shipped 0008 ROLLBACK binding byte-for-byte."""

    return canonical_sha256(
        {
            "action": "ROLLBACK",
            "target": target_sha256,
            "expected": expected_current_sha256,
            "reason_sha256": reason_sha256,
            "approver": approver_principal,
        }
    )


class ProfileReleaseCohortMember(StrictContract):
    """One complete DEV member; MISSING is an explicit lane state, not absent evidence."""

    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    label_ready: StrictBool
    rights_ready: StrictBool
    evidence_ready: StrictBool
    description_lane: Literal["READY", "MISSING"]
    odii_lane: Literal["READY", "MISSING"]
    profile_sha256: Sha256
    label_export_sha256: Sha256
    candidate_manifest_sha256: Sha256
    reviewed_evidence_manifest_sha256: Sha256
    accepted_review_set_sha256: Sha256
    rights_sha256: Sha256
    source_sha256: Sha256

    @model_validator(mode="after")
    def require_gate_clean_member(self) -> Self:
        if not self.label_ready:
            raise ValueError("profile release member has unresolved label state")
        if not self.rights_ready:
            raise ValueError("profile release member has invalid rights state")
        if not self.evidence_ready:
            raise ValueError("profile release member is source-less or unreviewed")
        return self


class ProfileReleaseCandidate(StrictContract):
    """One content-addressed, full DEV cohort before independent approval."""

    schema_version: Literal["itda.profile-release-candidate.v1"] = (
        "itda.profile-release-candidate.v1"
    )
    release_id: Annotated[str, Field(strict=True, pattern=_RELEASE_ID_PATTERN)]
    state: Literal[ProfileReleaseState.BUILT_UNAPPROVED] = ProfileReleaseState.BUILT_UNAPPROVED
    builder_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    label_freeze_sha256: Sha256
    candidate_run_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    rights_manifest_sha256: Sha256
    source_manifest_sha256: Sha256
    code_sha256: Sha256
    config_sha256: Sha256
    cohort: tuple[ProfileReleaseCohortMember, ...]
    release_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_complete_release(self) -> Self:
        validated = validate_profile_release_candidate_payload_v1(
            self.model_dump(mode="json")
        )
        object.__setattr__(self, "release_sha256", validated["release_sha256"])
        return self


class ProfileReleasePublication(StrictContract):
    schema_version: Literal["itda.profile-release-publication.v1"] = (
        "itda.profile-release-publication.v1"
    )
    release_sha256: Sha256
    release_id: Annotated[str, Field(strict=True, pattern=_RELEASE_ID_PATTERN)]
    state: Literal[ProfileReleaseState.BUILT_UNAPPROVED] = ProfileReleaseState.BUILT_UNAPPROVED
    cohort_count: Literal[24] = 24
    publication_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_publication(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"publication_sha256"}, mode="json"))
        if self.publication_sha256 is None:
            object.__setattr__(self, "publication_sha256", expected)
        elif not hmac.compare_digest(self.publication_sha256, expected):
            raise ValueError("profile release publication digest drifted")
        return self


class ProfileReleaseApproval(StrictContract):
    schema_version: Literal["itda.profile-release-approval.v1"] = "itda.profile-release-approval.v1"
    release_sha256: Sha256
    builder_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    approver_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    state: Literal[ProfileReleaseState.APPROVED_INACTIVE] = ProfileReleaseState.APPROVED_INACTIVE
    approval_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        if hmac.compare_digest(self.builder_principal, self.approver_principal):
            raise ValueError("builder and independent approver must be distinct")
        expected = canonical_sha256(self.model_dump(exclude={"approval_sha256"}, mode="json"))
        if self.approval_sha256 is None:
            object.__setattr__(self, "approval_sha256", expected)
        elif not hmac.compare_digest(self.approval_sha256, expected):
            raise ValueError("profile release approval digest drifted")
        return self


class ProfileReleaseTransitionReceipt(StrictContract):
    schema_version: Literal["itda.profile-release-transition.v1"] = (
        "itda.profile-release-transition.v1"
    )
    action: Literal["ACTIVATE", "ROLLBACK"]
    release_sha256: Sha256
    previous_release_sha256: Sha256 | None
    expected_current_sha256: Sha256 | None
    approver_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    nonce_sha256: Sha256
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)] | None = None
    completion: ProfileReleaseCompletion
    receipt_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if (self.action == "ROLLBACK") != (self.reason is not None):
            raise ValueError("rollback receipt alone must bind a normalized reason")
        if self.previous_release_sha256 != self.expected_current_sha256:
            raise ValueError("transition previous release differs from expected current")
        if self.action == "ROLLBACK" and self.previous_release_sha256 is None:
            raise ValueError("rollback transition requires a previous release")
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif not hmac.compare_digest(self.receipt_sha256, expected):
            raise ValueError("profile release transition receipt digest drifted")
        return self


class ProfileReleaseTransitionMutationResult(StrictContract):
    """Unsigned reconciliation metadata wrapped around one immutable signed receipt."""

    receipt: ProfileReleaseTransitionReceipt
    completion: ProfileReleaseCompletion

    @model_validator(mode="after")
    def keep_persisted_receipt_completion_immutable(self) -> Self:
        if self.receipt.completion is not ProfileReleaseCompletion.MUTATION_COMMITTED:
            raise ValueError("persisted transition receipt completion must remain immutable")
        return self

    @property
    def release_sha256(self) -> str:
        return self.receipt.release_sha256

    @property
    def receipt_sha256(self) -> str | None:
        return self.receipt.receipt_sha256


class ProfileReleasePin(StrictContract):
    schema_version: Literal["itda.profile-release-pin.v1"] = "itda.profile-release-pin.v1"
    pin_kind: Literal["SESSION", "RESULT"]
    owner_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    release_sha256: Sha256
    pin_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_pin(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"pin_sha256"}, mode="json"))
        if self.pin_sha256 is None:
            object.__setattr__(self, "pin_sha256", expected)
        elif not hmac.compare_digest(self.pin_sha256, expected):
            raise ValueError("profile release pin digest drifted")
        return self


class ProfileReleaseSessionPinProjection(StrictContract):
    """Read-only observation of one immutable session pin and its server clock."""

    session_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    release_sha256: Sha256
    pin_sha256: Sha256
    pinned_at: datetime

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        require_utc(self.pinned_at, field_name="pinned_at")
        expected = ProfileReleasePin(
            pin_kind="SESSION",
            owner_ref=self.session_ref,
            release_sha256=self.release_sha256,
        )
        if not hmac.compare_digest(cast(str, expected.pin_sha256), self.pin_sha256):
            raise ValueError("profile release session pin projection drifted")
        return self


def authorize_profile_release_action(
    *,
    action: Literal["BUILD", "APPROVE", "ACTIVATE", "ROLLBACK"],
    authenticated_principal: str,
    builder_principal: str,
    client_actor_id: str | None,
) -> str:
    """Use only the server-derived principal and enforce builder separation."""

    validate_profile_release_action_identity(
        authenticated_principal=authenticated_principal,
        client_actor_id=client_actor_id,
    )
    if action == "BUILD":
        if not hmac.compare_digest(authenticated_principal, builder_principal):
            raise ValueError("builder principal differs from authenticated principal")
    elif hmac.compare_digest(authenticated_principal, builder_principal):
        raise ValueError("builder cannot approve or activate; independent principal required")
    return authenticated_principal


def validate_profile_release_action_identity(
    *,
    authenticated_principal: str,
    client_actor_id: str | None,
) -> str:
    """Reject client identity before any history-dependent mutation replay."""

    if client_actor_id is not None:
        raise ValueError("client actor or principal fields are forbidden")
    if not re.fullmatch(_PRINCIPAL_PATTERN, authenticated_principal):
        raise ValueError("authenticated server principal is invalid")
    return authenticated_principal


def validate_rollback_authority(
    *,
    authenticated_principal: str,
    builder_principal: str,
    client_approver_id: str | None,
    reason: str,
) -> tuple[str, str]:
    """Return the server approver and canonical trimmed rollback reason."""

    principal = authorize_profile_release_action(
        action="ROLLBACK",
        authenticated_principal=authenticated_principal,
        builder_principal=builder_principal,
        client_actor_id=client_approver_id,
    )
    normalized = reason.strip()
    if not 1 <= len(normalized) <= 300:
        raise ValueError("rollback reason must contain 1..300 trimmed characters")
    return principal, normalized


def redact_profile_release_channels(payload: dict[str, object]) -> dict[str, object]:
    """Project only aggregate/hash-safe fields to every observable channel."""

    safe = {
        key: value
        for key, value in payload.items()
        if key in {"release_sha256", "status", "action", "completion"}
        and isinstance(value, str)
        and (key != "release_sha256" or _NONCE_PATTERN.fullmatch(value) is not None)
    }
    return {
        channel: dict(safe)
        for channel in ("artifact", "stdout", "stderr", "error", "log", "trace", "report")
    }


def _require_stable_regular_file(path: Path) -> bytes:
    visible = path.lstat()
    if not stat.S_ISREG(visible.st_mode) or visible.st_nlink != 1:
        raise ValueError("source path must be one unlinked regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("source path identity changed")
        raw = os.read(descriptor, 8_000_001)
        if len(raw) > 8_000_000:
            raise ValueError("source path exceeds the bounded read limit")
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("source path changed during stable read")
        return raw
    finally:
        os.close(descriptor)


def snapshot_release_directory(path: Path | str) -> dict[str, str]:
    """Return a hash-only snapshot while rejecting substituted directory entries."""

    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("profile release path is not a regular directory")
    snapshot: dict[str, str] = {}
    for entry in sorted(root.iterdir(), key=lambda item: item.name):
        raw = _require_stable_regular_file(entry)
        snapshot[entry.name] = hashlib.sha256(raw).hexdigest()
    return snapshot


def _load_published_candidate(path: Path) -> ProfileReleaseCandidate:
    raw = _require_stable_regular_file(path / "release.json")
    candidate = ProfileReleaseCandidate.model_validate(json.loads(raw))
    if raw != canonical_json_bytes(candidate.model_dump(mode="json")):
        raise ValueError("existing profile release bytes are not canonical")
    return candidate


def publish_profile_release(
    candidate: ProfileReleaseCandidate,
    *,
    output: Path | str,
    inject_fault: Literal["incomplete-set", "interrupted", "path-swap"] | None = None,
    injected_source: Path | str | None = None,
) -> ProfileReleasePublication:
    """Publish a complete release directory in one no-replace rename."""

    destination = Path(output)
    if destination.exists() or os.path.lexists(destination):
        existing = _load_published_candidate(destination)
        if existing != candidate:
            raise FileExistsError("immutable profile release collision with existing bytes")
        return ProfileReleasePublication(
            release_sha256=cast(str, candidate.release_sha256),
            release_id=candidate.release_id,
        )
    if injected_source is not None:
        _require_stable_regular_file(Path(injected_source))
    if inject_fault is not None:
        raise ValueError(f"profile release publication fault: {inject_fault}")
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("profile release parent path is invalid")
    prepared = Path(tempfile.mkdtemp(prefix=".profile-release-", dir=parent))
    try:
        release_path = prepared / "release.json"
        publication = ProfileReleasePublication(
            release_sha256=cast(str, candidate.release_sha256),
            release_id=candidate.release_id,
        )
        publication_path = prepared / "publication.json"
        release_path.write_bytes(canonical_json_bytes(candidate.model_dump(mode="json")))
        publication_path.write_bytes(canonical_json_bytes(publication.model_dump(mode="json")))
        for path in (release_path, publication_path):
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.rename(prepared, destination)
        return publication
    except BaseException:
        if prepared.exists():
            shutil.rmtree(prepared)
        raise


def _validate_transition(before: ProfileReleaseState, after: ProfileReleaseState) -> None:
    if (before, after) not in _ALLOWED_TRANSITIONS:
        raise ValueError(f"profile release state transition {before}->{after} is closed")


class ProfileReleaseStore:
    """Small deterministic file store used by CLI/tests; PostgreSQL is the deployment store."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("profile release store root is invalid")
        self._state_path = self.root / "profile-release-state.json"
        self._lock = threading.RLock()
        self._state = self._read_state()

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {
            "releases": {},
            "states": {},
            "approvals": {},
            "active_release_sha256": None,
            "active_history": [],
            "transition_receipts": [],
            "consumed_nonce_sha256s": [],
            "session_pins": {},
            "result_pins": {},
        }

    def _read_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return self._empty_state()
        raw = _require_stable_regular_file(self._state_path)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict) or raw != canonical_json_bytes(parsed):
            raise ValueError("profile release store state is invalid")
        return cast(dict[str, Any], parsed)

    def _write_state(self, state: dict[str, Any]) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".profile-state-", dir=self.root)
        temporary = Path(temporary_name)
        try:
            payload = canonical_json_bytes(state)
            written = os.write(descriptor, payload)
            if written != len(payload):
                raise OSError("short write while persisting profile release state")
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            temporary.chmod(0o600)
            os.replace(temporary, self._state_path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _commit(self, next_state: dict[str, Any]) -> None:
        self._write_state(next_state)
        self._state = next_state

    @property
    def active_release_sha256(self) -> str | None:
        with self._lock:
            return cast(str | None, self._state["active_release_sha256"])

    @property
    def transition_receipts(self) -> tuple[ProfileReleaseTransitionReceipt, ...]:
        with self._lock:
            return tuple(
                ProfileReleaseTransitionReceipt.model_validate(item)
                for item in self._state["transition_receipts"]
            )

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return cast(dict[str, object], deepcopy(self._state))

    def _candidate(self, release_sha256: str) -> ProfileReleaseCandidate:
        raw = self._state["releases"].get(release_sha256)
        if raw is None:
            raise ValueError("profile release target does not exist")
        candidate = ProfileReleaseCandidate.model_validate(raw)
        if not hmac.compare_digest(cast(str, candidate.release_sha256), release_sha256):
            raise ValueError("profile release integrity or hash drift detected")
        return candidate

    def build(
        self,
        candidate: ProfileReleaseCandidate,
        *,
        authenticated_principal: str | None = None,
        client_actor_id: str | None = None,
        inject_fault: Literal["incomplete-set", "interrupted", "path-swap"] | None = None,
    ) -> ProfileReleasePublication:
        principal = authenticated_principal or candidate.builder_principal
        authorize_profile_release_action(
            action="BUILD",
            authenticated_principal=principal,
            builder_principal=candidate.builder_principal,
            client_actor_id=client_actor_id,
        )
        release_sha256 = cast(str, candidate.release_sha256)
        with self._lock:
            before = deepcopy(self._state)
            existing = before["releases"].get(release_sha256)
            if existing is not None:
                if ProfileReleaseCandidate.model_validate(existing) != candidate:
                    raise FileExistsError("profile release hash collision")
                return ProfileReleasePublication(
                    release_sha256=release_sha256,
                    release_id=candidate.release_id,
                )
            publication = publish_profile_release(
                candidate,
                output=self.root / "releases" / release_sha256,
                inject_fault=inject_fault,
            )
            before["releases"][release_sha256] = candidate.model_dump(mode="json")
            before["states"][release_sha256] = ProfileReleaseState.BUILT_UNAPPROVED.value
            self._commit(before)
            return publication

    def approve(
        self,
        release_sha256: str,
        *,
        authenticated_principal: str,
        client_approver_id: str | None,
    ) -> ProfileReleaseApproval:
        with self._lock:
            candidate = self._candidate(release_sha256)
            principal = authorize_profile_release_action(
                action="APPROVE",
                authenticated_principal=authenticated_principal,
                builder_principal=candidate.builder_principal,
                client_actor_id=client_approver_id,
            )
            if self._state["states"].get(release_sha256) != (
                ProfileReleaseState.BUILT_UNAPPROVED.value
            ):
                raise ValueError("only exact BUILT_UNAPPROVED release can be approved")
            _validate_transition(
                ProfileReleaseState.BUILT_UNAPPROVED,
                ProfileReleaseState.APPROVED_INACTIVE,
            )
            approval = ProfileReleaseApproval(
                release_sha256=release_sha256,
                builder_principal=candidate.builder_principal,
                approver_principal=principal,
            )
            next_state = deepcopy(self._state)
            next_state["approvals"][release_sha256] = approval.model_dump(mode="json")
            next_state["states"][release_sha256] = ProfileReleaseState.APPROVED_INACTIVE.value
            self._commit(next_state)
            return approval

    @staticmethod
    def _nonce_sha256(nonce: str) -> str:
        if _NONCE_PATTERN.fullmatch(nonce) is None:
            raise ValueError("profile release nonce must be 64 lowercase hex characters")
        return hashlib.sha256(nonce.encode("ascii")).hexdigest()

    def _require_unused_nonce(self, state: dict[str, Any], nonce_sha256: str) -> None:
        if nonce_sha256 in state["consumed_nonce_sha256s"]:
            raise ProfileReleaseReplayError("profile release nonce already consumed")

    def activate(
        self,
        release_sha256: str,
        *,
        expected_current: str | None,
        authenticated_principal: str,
        nonce: str,
        client_actor_id: str | None = None,
        inject_fault: Literal["uncertain-after-commit"] | None = None,
    ) -> ProfileReleaseTransitionMutationResult:
        nonce_sha256 = self._nonce_sha256(nonce)
        with self._lock:
            candidate = self._candidate(release_sha256)
            principal = authorize_profile_release_action(
                action="ACTIVATE",
                authenticated_principal=authenticated_principal,
                builder_principal=candidate.builder_principal,
                client_actor_id=client_actor_id,
            )
            self._require_unused_nonce(self._state, nonce_sha256)
            approval_raw = self._state["approvals"].get(release_sha256)
            if approval_raw is None:
                raise ValueError("activation target lacks exact independent approval")
            approval = ProfileReleaseApproval.model_validate(approval_raw)
            if not hmac.compare_digest(approval.approver_principal, principal):
                raise ValueError("activation principal differs from exact approval")
            if self._state["states"].get(release_sha256) != (
                ProfileReleaseState.APPROVED_INACTIVE.value
            ):
                raise ValueError("activation target is not APPROVED_INACTIVE")
            if self._state["active_release_sha256"] != expected_current:
                raise ProfileReleaseReplayError("stale expected-current activation CAS")
            previous = cast(str | None, self._state["active_release_sha256"])
            next_state = deepcopy(self._state)
            if previous is not None:
                _validate_transition(
                    ProfileReleaseState.ACTIVE,
                    ProfileReleaseState.APPROVED_INACTIVE,
                )
                next_state["states"][previous] = ProfileReleaseState.APPROVED_INACTIVE.value
            _validate_transition(
                ProfileReleaseState.APPROVED_INACTIVE,
                ProfileReleaseState.ACTIVE,
            )
            next_state["states"][release_sha256] = ProfileReleaseState.ACTIVE.value
            next_state["active_release_sha256"] = release_sha256
            next_state["active_history"].append(release_sha256)
            next_state["consumed_nonce_sha256s"].append(nonce_sha256)
            receipt = ProfileReleaseTransitionReceipt(
                action="ACTIVATE",
                release_sha256=release_sha256,
                previous_release_sha256=previous,
                expected_current_sha256=expected_current,
                approver_principal=principal,
                nonce_sha256=nonce_sha256,
                completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
            )
            next_state["transition_receipts"].append(receipt.model_dump(mode="json"))
            self._commit(next_state)
            return ProfileReleaseTransitionMutationResult(
                receipt=receipt,
                completion=(
                    ProfileReleaseCompletion.RELOOKUP_CONFIRMED
                    if inject_fault == "uncertain-after-commit"
                    else ProfileReleaseCompletion.MUTATION_COMMITTED
                ),
            )

    @staticmethod
    def _compatible(first: ProfileReleaseCandidate, second: ProfileReleaseCandidate) -> bool:
        return (
            first.canonical_lineage_sha256 == second.canonical_lineage_sha256
            and first.dev_lineage_sha256 == second.dev_lineage_sha256
            and first.profile_schema_sha256 == second.profile_schema_sha256
        )

    def rollback(
        self,
        release_sha256: str,
        *,
        expected_current: str,
        authenticated_principal: str,
        client_approver_id: str | None,
        reason: str,
        nonce: str,
    ) -> ProfileReleaseTransitionMutationResult:
        nonce_sha256 = self._nonce_sha256(nonce)
        with self._lock:
            if self._state["active_release_sha256"] != expected_current:
                raise ProfileReleaseReplayError("stale expected-current rollback CAS")
            current = self._candidate(expected_current)
            principal, normalized_reason = validate_rollback_authority(
                authenticated_principal=authenticated_principal,
                builder_principal=current.builder_principal,
                client_approver_id=client_approver_id,
                reason=reason,
            )
            self._require_unused_nonce(self._state, nonce_sha256)
            prior = self._state["active_history"][:-1]
            if release_sha256 not in prior:
                raise ValueError("rollback target is not a recorded prior-active release")
            target = self._candidate(release_sha256)
            if not self._compatible(target, current):
                raise ValueError("rollback target has incompatible lineage")
            if self._state["states"].get(release_sha256) != (
                ProfileReleaseState.APPROVED_INACTIVE.value
            ):
                raise ValueError("rollback target is not an inactive prior release")
            next_state = deepcopy(self._state)
            next_state["states"][expected_current] = ProfileReleaseState.APPROVED_INACTIVE.value
            next_state["states"][release_sha256] = ProfileReleaseState.ACTIVE.value
            next_state["active_release_sha256"] = release_sha256
            next_state["active_history"].append(release_sha256)
            next_state["consumed_nonce_sha256s"].append(nonce_sha256)
            receipt = ProfileReleaseTransitionReceipt(
                action="ROLLBACK",
                release_sha256=release_sha256,
                previous_release_sha256=expected_current,
                expected_current_sha256=expected_current,
                approver_principal=principal,
                nonce_sha256=nonce_sha256,
                reason=normalized_reason,
                completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
            )
            next_state["transition_receipts"].append(receipt.model_dump(mode="json"))
            self._commit(next_state)
            return ProfileReleaseTransitionMutationResult(
                receipt=receipt,
                completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
            )

    def seed_approved(
        self,
        candidate: ProfileReleaseCandidate,
        *,
        approver_principal: str = "synthetic-approver",
    ) -> None:
        with self._lock:
            next_state = deepcopy(self._state)
            release_sha256 = cast(str, candidate.release_sha256)
            approval = ProfileReleaseApproval(
                release_sha256=release_sha256,
                builder_principal=candidate.builder_principal,
                approver_principal=approver_principal,
            )
            next_state["releases"][release_sha256] = candidate.model_dump(mode="json")
            next_state["states"][release_sha256] = ProfileReleaseState.APPROVED_INACTIVE.value
            next_state["approvals"][release_sha256] = approval.model_dump(mode="json")
            self._commit(next_state)

    def seed_active_history(
        self,
        candidates: tuple[ProfileReleaseCandidate, ...],
        *,
        current: str,
        approver_principal: str = "synthetic-approver",
    ) -> None:
        if not candidates:
            raise ValueError("active history requires at least one release")
        with self._lock:
            next_state = deepcopy(self._state)
            digests = [cast(str, candidate.release_sha256) for candidate in candidates]
            if current != digests[-1]:
                raise ValueError("active history current must be the final recorded release")
            for candidate, release_sha256 in zip(candidates, digests, strict=True):
                approval = ProfileReleaseApproval(
                    release_sha256=release_sha256,
                    builder_principal=candidate.builder_principal,
                    approver_principal=approver_principal,
                )
                next_state["releases"][release_sha256] = candidate.model_dump(mode="json")
                next_state["states"][release_sha256] = (
                    ProfileReleaseState.ACTIVE.value
                    if release_sha256 == current
                    else ProfileReleaseState.APPROVED_INACTIVE.value
                )
                next_state["approvals"][release_sha256] = approval.model_dump(mode="json")
            next_state["active_release_sha256"] = current
            next_state["active_history"] = digests
            self._commit(next_state)

    def pin_session(self, session_ref: str) -> str:
        return self._pin("session_pins", "SESSION", session_ref)

    def pin_result(self, result_ref: str) -> str:
        return self._pin("result_pins", "RESULT", result_ref)

    def _pin(self, collection: str, kind: Literal["SESSION", "RESULT"], owner_ref: str) -> str:
        with self._lock:
            existing = self._state[collection].get(owner_ref)
            if existing is not None:
                return cast(str, existing["release_sha256"])
            active = cast(str | None, self._state["active_release_sha256"])
            if active is None:
                raise ValueError("cannot pin without an active profile release")
            pin = ProfileReleasePin(pin_kind=kind, owner_ref=owner_ref, release_sha256=active)
            next_state = deepcopy(self._state)
            next_state[collection][owner_ref] = pin.model_dump(mode="json")
            self._commit(next_state)
            return active

    def session_release_sha256(self, session_ref: str) -> str:
        with self._lock:
            pin = self._state["session_pins"].get(session_ref)
            if pin is None:
                raise KeyError("profile release session pin does not exist")
            return cast(str, pin["release_sha256"])

    def result_release_sha256(self, result_ref: str) -> str:
        with self._lock:
            pin = self._state["result_pins"].get(result_ref)
            if pin is None:
                raise KeyError("profile release result pin does not exist")
            return cast(str, pin["release_sha256"])


__all__ = [
    "ProfileReleaseActivePointerProjection",
    "ProfileReleaseApproval",
    "ProfileReleaseBuildDraftReference",
    "ProfileReleaseBuildUnavailableError",
    "ProfileReleaseBuildOutcome",
    "ProfileReleaseBuildReceipt",
    "ProfileReleaseCandidate",
    "ProfileReleaseCohortMember",
    "ProfileReleaseCompletion",
    "ProfileReleaseDraftCleanupUnknownError",
    "ProfileReleaseDraftPurgeResult",
    "ProfileReleasePin",
    "ProfileReleaseSessionPinProjection",
    "ProfileReleasePublication",
    "ProfileReleaseReplayError",
    "ProfileReleaseRetryableAbortError",
    "ProfileReleaseState",
    "ProfileReleaseStateProjection",
    "ProfileReleaseStore",
    "ProfileReleaseTransitionOutcome",
    "ProfileReleaseTransitionMutationResult",
    "ProfileReleaseTransitionReceipt",
    "ProfileReleaseUnknownOutcomeError",
    "authorize_profile_release_action",
    "profile_release_activate_binding_sha256_v1",
    "profile_release_build_binding_sha256_v1",
    "profile_release_rollback_binding_sha256_v1",
    "publish_profile_release",
    "redact_profile_release_channels",
    "snapshot_release_directory",
    "validate_rollback_authority",
]
