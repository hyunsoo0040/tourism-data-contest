"""Fail-closed catalog-v2 activation and append-only rollback lifecycle."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import Field, field_validator, model_validator

from itda.contracts.authority import (
    AuthorityIssuanceContext,
    FileNonceLedger,
    freeze_issuance_context,
    validate_authority_token,
)
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.catalog_release import (
    CatalogApprovalV2,
    CatalogRevisionV2,
    verify_catalog_v2_approval,
    verify_catalog_v2_revision,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

CatalogAction = Literal["catalog-activate", "catalog-rollback"]

_CODE_PATHS = (
    "backend/src/itda/contracts/catalog_activation.py",
    "backend/src/itda/contracts/authority.py",
    "backend/src/itda/cli/activate_catalog.py",
)
_CONFIG_PATHS = ("backend/pyproject.toml", "backend/uv.lock")
_ROLLBACK_PROOF_PATHS = (*_CODE_PATHS, "backend/tests/security/test_catalog_activation.py")
_EVENT_NAME = re.compile(
    r"^catalog-(?:activation|rollback)-event(?:-[0-9]{6}-[0-9a-f]{64})?\.json$"
)


class CatalogActivationStateV2(StrictContract):
    """Exact append-only chain head and approved revision before one action."""

    schema_version: Literal["itda.catalog-activation-state-attestation.v2"] = (
        "itda.catalog-activation-state-attestation.v2"
    )
    action: CatalogAction
    approval_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    approval_file_sha256: Sha256
    catalog_approval_sha256: Sha256
    catalog_revision_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    revision_file_sha256: Sha256
    catalog_revision_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    current_sequence: Annotated[int, Field(strict=True, ge=0)]
    current_event_sha256: Sha256 | None = None
    active_revision_sha256: Sha256 | None = None
    rollback_target_revision_sha256: Sha256 | None = None
    rollback_capability_sha256: Sha256
    code_version_hashes: dict[Annotated[str, Field(strict=True, min_length=1)], Sha256]
    config_version_hashes: dict[Annotated[str, Field(strict=True, min_length=1)], Sha256]
    state_attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if (self.current_sequence == 0) != (self.current_event_sha256 is None):
            raise ValueError("catalog activation state sequence and event head differ")
        if self.action == "catalog-rollback" and self.current_sequence == 0:
            raise ValueError("catalog rollback requires an existing activation event")
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif not hmac.compare_digest(self.state_attestation_sha256, expected):
            raise ValueError("catalog activation state sha256 drifted")
        return self


class CatalogActivationRequestV2(StrictContract):
    """Fresh authority request for one exact chain transition."""

    schema_version: Literal["itda.catalog-activation-request.v2"] = (
        "itda.catalog-activation-request.v2"
    )
    action: CatalogAction
    catalog_approval_sha256: Sha256
    catalog_revision_sha256: Sha256
    state_attestation_sha256: Sha256
    current_event_sha256: Sha256 | None = None
    current_revision_sha256: Sha256 | None = None
    target_revision_sha256: Sha256 | None = None
    target_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    rollback_capability_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    binding_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    expires_at: datetime
    replaces_request_sha256: Sha256 | None = None
    reviewer_channel_risk: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    request_sha256: Sha256 | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="catalog_activation_request_timestamp")

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("catalog activation request expiry must follow issuance")
        if self.action == "catalog-activate" and self.target_revision_sha256 is None:
            raise ValueError("catalog activation requires an exact target revision")
        expected = canonical_sha256(self.model_dump(exclude={"request_sha256"}, mode="json"))
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif not hmac.compare_digest(self.request_sha256, expected):
            raise ValueError("catalog activation request sha256 drifted")
        return self


class CatalogActivationEventV2(StrictContract):
    """One immutable, hash-chained activation or rollback event."""

    schema_version: Literal["itda.catalog-activation-event.v2"] = (
        "itda.catalog-activation-event.v2"
    )
    sequence: Annotated[int, Field(strict=True, ge=1)]
    action: CatalogAction
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    catalog_approval_sha256: Sha256
    catalog_revision_sha256: Sha256
    from_revision_sha256: Sha256 | None = None
    to_revision_sha256: Sha256 | None = None
    previous_event_sha256: Sha256 | None = None
    authoritative_relationship_leaves_sha256: Sha256
    rollback_capability_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    occurred_at: datetime
    token_sha256: Sha256
    nonce_sha256: Sha256
    issuance_context_sha256: Sha256
    event_sha256: Sha256 | None = None

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="occurred_at")

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        if self.from_revision_sha256 == self.to_revision_sha256:
            raise ValueError("catalog activation event must change the active revision")
        if (self.sequence == 1) != (self.previous_event_sha256 is None):
            raise ValueError("catalog activation event predecessor differs from sequence")
        if self.action == "catalog-activate" and (
            self.to_revision_sha256 != self.catalog_revision_sha256
        ):
            raise ValueError("catalog activation event target is not the approved revision")
        expected = canonical_sha256(self.model_dump(exclude={"event_sha256"}, mode="json"))
        if self.event_sha256 is None:
            object.__setattr__(self, "event_sha256", expected)
        elif not hmac.compare_digest(self.event_sha256, expected):
            raise ValueError("catalog activation event sha256 drifted")
        return self


class CatalogActivationChain(StrictContract):
    """Replay result for the complete append-only event chain."""

    events: tuple[CatalogActivationEventV2, ...]
    active_revision_sha256: Sha256 | None = None
    current_event_sha256: Sha256 | None = None
    current_sequence: Annotated[int, Field(strict=True, ge=0)]


def _stable_bytes(path: Path, *, max_bytes: int = 8_000_000) -> bytes:
    if path.is_symlink():
        raise ValueError("catalog activation input cannot be a symlink")
    before = path.stat()
    if not path.is_file() or before.st_size > max_bytes:
        raise ValueError("catalog activation input must be a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise ValueError("catalog activation input identity changed before open")
        raw = b""
        while len(raw) <= max_bytes:
            chunk = os.read(descriptor, min(1_048_576, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        if len(raw) > max_bytes or (opened.st_dev, opened.st_ino, opened.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ValueError("catalog activation input changed during stable read")
        return raw
    finally:
        os.close(descriptor)


def _load_model[ModelT: StrictContract](path: Path, model: type[ModelT]) -> ModelT:
    raw = _stable_bytes(path)
    try:
        parsed = model.model_validate(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("catalog activation artifact fields are invalid") from exc
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("catalog activation artifact is not canonical JSON")
    return parsed


def _relative(path: Path, root: Path) -> str:
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return resolved.as_posix()


def _hash_paths(root: Path, paths: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"catalog activation version input is invalid: {relative}")
        result[relative] = hashlib.sha256(_stable_bytes(path)).hexdigest()
    return result


def rollback_capability_fingerprint(repository_root: Path | str) -> str:
    """Hash the exact consumer and hostile-test bytes that prove rollback readiness."""

    root = Path(repository_root).resolve(strict=True)
    return canonical_sha256(
        {
            "schema_version": "itda.catalog-rollback-capability.v2",
            "capabilities": [
                "append-only-hash-chain",
                "first-activation-rollback-to-none",
                "distinct-activate-and-rollback-authority",
                "atomic-nonce-and-event-recovery",
                "exclusive-lock-full-chain-replay",
                "verify-event-require-current",
            ],
            "proof_file_hashes": _hash_paths(root, _ROLLBACK_PROOF_PATHS),
        }
    )


def _event_paths(events_root: Path) -> tuple[Path, ...]:
    if not events_root.exists():
        return ()
    if events_root.is_symlink() or not events_root.is_dir():
        raise ValueError("catalog activation events root must be a regular directory")
    return tuple(
        path
        for path in events_root.iterdir()
        if path.is_file() and not path.is_symlink() and _EVENT_NAME.fullmatch(path.name)
    )


def replay_catalog_activation_chain(events_root: Path | str) -> CatalogActivationChain:
    """Replay every canonical event and derive the sole current active revision."""

    root = Path(events_root)
    events = tuple(
        sorted(
            (_load_model(path, CatalogActivationEventV2) for path in _event_paths(root)),
            key=lambda event: event.sequence,
        )
    )
    if tuple(event.sequence for event in events) != tuple(range(1, len(events) + 1)):
        raise ValueError("catalog activation event sequence is not append-only")
    active: str | None = None
    head: str | None = None
    for event in events:
        if event.previous_event_sha256 != head or event.from_revision_sha256 != active:
            raise ValueError("catalog activation event chain head or active state is broken")
        if event.action == "catalog-rollback":
            previous = events[event.sequence - 2]
            if event.to_revision_sha256 != previous.from_revision_sha256:
                raise ValueError("catalog rollback is not the exact inverse transition")
        active = event.to_revision_sha256
        head = event.event_sha256
    return CatalogActivationChain(
        events=events,
        active_revision_sha256=active,
        current_event_sha256=head,
        current_sequence=len(events),
    )


def _approval_and_revision(
    approval_path: Path,
    root: Path,
) -> tuple[CatalogApprovalV2, CatalogRevisionV2, Path]:
    approval = verify_catalog_v2_approval(
        approval_path,
        repository_root=root,
        require_inactive=True,
    )
    revision_path = root / approval.catalog_revision_path
    revision = verify_catalog_v2_revision(
        revision_path,
        repository_root=root,
        require_inactive=True,
    )
    if (
        approval.catalog_approval_sha256 is None
        or revision.catalog_revision_sha256 is None
        or approval.catalog_revision_sha256 != revision.catalog_revision_sha256
    ):
        raise ValueError("catalog activation approval and revision differ")
    return approval, revision, revision_path


def _transition_target(
    *,
    action: CatalogAction,
    state: CatalogActivationStateV2,
    target_revision_sha256: str | None,
) -> dict[str, object]:
    return {
        "schema_version": "itda.catalog-activation-transition-target.v2",
        "action": action,
        "from_revision_sha256": state.active_revision_sha256,
        "to_revision_sha256": target_revision_sha256,
        "previous_event_sha256": state.current_event_sha256,
        "catalog_approval_sha256": state.catalog_approval_sha256,
        "catalog_revision_sha256": state.catalog_revision_sha256,
        "authoritative_relationship_leaves_sha256": (
            state.authoritative_relationship_leaves_sha256
        ),
        "rollback_capability_sha256": state.rollback_capability_sha256,
    }


def _activation_binding(
    state: CatalogActivationStateV2,
    target: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "itda.catalog-activation-authority-binding.v2",
        "action": state.action,
        "state_attestation_sha256": state.state_attestation_sha256,
        "target_sha256": canonical_sha256(target),
        "catalog_approval_sha256": state.catalog_approval_sha256,
        "catalog_revision_sha256": state.catalog_revision_sha256,
        "current_event_sha256": state.current_event_sha256,
        "active_revision_sha256": state.active_revision_sha256,
        "authoritative_relationship_leaves_sha256": (
            state.authoritative_relationship_leaves_sha256
        ),
        "rollback_capability_sha256": state.rollback_capability_sha256,
    }


def build_catalog_activation_request(
    approval_path: Path | str,
    *,
    repository_root: Path | str,
    events_root: Path | str,
    action: CatalogAction,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    replaces_request_sha256: str | None = None,
    reviewer_channel_risk: str = (
        "Local-channel reviewer identity is accepted metadata and is not cryptographic."
    ),
) -> tuple[CatalogActivationStateV2, CatalogActivationRequestV2]:
    """Replay approval, revision, and chain twice before freezing one request."""

    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("catalog activation nonce must be 64 lowercase hex characters")
    root = Path(repository_root).resolve(strict=True)
    approval_file = Path(approval_path)
    approval, revision, revision_path = _approval_and_revision(approval_file, root)
    second_approval, second_revision, _ = _approval_and_revision(approval_file, root)
    if canonical_json_bytes(approval.model_dump(mode="json")) != canonical_json_bytes(
        second_approval.model_dump(mode="json")
    ) or canonical_json_bytes(revision.model_dump(mode="json")) != canonical_json_bytes(
        second_revision.model_dump(mode="json")
    ):
        raise ValueError("catalog activation parents changed between replays")
    chain = replay_catalog_activation_chain(events_root)
    again = replay_catalog_activation_chain(events_root)
    if chain.model_dump(mode="json") != again.model_dump(mode="json"):
        raise ValueError("catalog activation chain changed between replays")
    if action == "catalog-activate":
        target_revision = revision.catalog_revision_sha256
        if chain.active_revision_sha256 == target_revision:
            raise ValueError("approved catalog revision is already active")
        rollback_target = chain.active_revision_sha256
    else:
        if not chain.events:
            raise ValueError("catalog rollback requires an existing activation event")
        if chain.active_revision_sha256 != revision.catalog_revision_sha256:
            raise ValueError("catalog rollback current revision is not the approved revision")
        target_revision = chain.events[-1].from_revision_sha256
        rollback_target = target_revision
    state = CatalogActivationStateV2(
        action=action,
        approval_path=_relative(approval_file, root),
        approval_file_sha256=hashlib.sha256(_stable_bytes(approval_file)).hexdigest(),
        catalog_approval_sha256=cast(str, approval.catalog_approval_sha256),
        catalog_revision_path=_relative(revision_path, root),
        revision_file_sha256=hashlib.sha256(_stable_bytes(revision_path)).hexdigest(),
        catalog_revision_sha256=cast(str, revision.catalog_revision_sha256),
        authoritative_relationship_leaves_sha256=(
            revision.authoritative_relationship_leaves_sha256
        ),
        current_sequence=chain.current_sequence,
        current_event_sha256=chain.current_event_sha256,
        active_revision_sha256=chain.active_revision_sha256,
        rollback_target_revision_sha256=rollback_target,
        rollback_capability_sha256=rollback_capability_fingerprint(root),
        code_version_hashes=_hash_paths(root, _CODE_PATHS),
        config_version_hashes=_hash_paths(root, _CONFIG_PATHS),
    )
    if state.state_attestation_sha256 is None:
        raise ValueError("catalog activation state lacks its digest")
    target = _transition_target(
        action=action,
        state=state,
        target_revision_sha256=target_revision,
    )
    request = CatalogActivationRequestV2(
        action=action,
        catalog_approval_sha256=state.catalog_approval_sha256,
        catalog_revision_sha256=state.catalog_revision_sha256,
        state_attestation_sha256=state.state_attestation_sha256,
        current_event_sha256=state.current_event_sha256,
        current_revision_sha256=state.active_revision_sha256,
        target_revision_sha256=target_revision,
        target_sha256=canonical_sha256(target),
        authoritative_relationship_leaves_sha256=(
            state.authoritative_relationship_leaves_sha256
        ),
        rollback_capability_sha256=state.rollback_capability_sha256,
        reviewer_id=reviewer_id,
        binding_sha256=canonical_sha256(_activation_binding(state, target)),
        nonce=nonce,
        issued_at=require_utc(issued_at, field_name="issued_at"),
        expires_at=require_utc(expires_at, field_name="expires_at"),
        replaces_request_sha256=replaces_request_sha256,
        reviewer_channel_risk=reviewer_channel_risk,
    )
    return state, request


def publish_catalog_activation_request(
    state: CatalogActivationStateV2,
    request: CatalogActivationRequestV2,
    *,
    state_path: Path | str,
    request_path: Path | str,
) -> None:
    """Install the state/request pair through no-replace hard links."""

    state_destination = Path(state_path)
    request_destination = Path(request_path)
    if state_destination.parent != request_destination.parent:
        raise ValueError("catalog activation request files require one atomic parent")
    if os.path.lexists(state_destination) or os.path.lexists(request_destination):
        raise FileExistsError("catalog activation request bundle is no-replace")
    if request.state_attestation_sha256 != state.state_attestation_sha256:
        raise ValueError("catalog activation request and state digests differ")
    parent = state_destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    prepared = Path(tempfile.mkdtemp(prefix=".activation-request-prepared-", dir=parent))
    state_temp = prepared / state_destination.name
    request_temp = prepared / request_destination.name
    state_temp.write_bytes(canonical_json_bytes(state.model_dump(mode="json")))
    request_temp.write_bytes(canonical_json_bytes(request.model_dump(mode="json")))
    state_temp.chmod(0o600)
    request_temp.chmod(0o600)
    installed_state = False
    try:
        for path in (state_temp, request_temp):
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.link(state_temp, state_destination, follow_symlinks=False)
        installed_state = True
        os.link(request_temp, request_destination, follow_symlinks=False)
        directory_descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        if installed_state:
            state_destination.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(prepared)


def check_catalog_activation_request(
    request_path: Path | str,
    state_path: Path | str,
    *,
    approval_path: Path | str,
    events_root: Path | str,
    repository_root: Path | str,
) -> CatalogActivationRequestV2:
    """Compare the actual request/state bytes with a fresh full replay."""

    state = _load_model(Path(state_path), CatalogActivationStateV2)
    request = _load_model(Path(request_path), CatalogActivationRequestV2)
    expected_state, expected_request = build_catalog_activation_request(
        approval_path,
        repository_root=repository_root,
        events_root=events_root,
        action=request.action,
        reviewer_id=request.reviewer_id,
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
        replaces_request_sha256=request.replaces_request_sha256,
        reviewer_channel_risk=request.reviewer_channel_risk,
    )
    if canonical_json_bytes(state.model_dump(mode="json")) != canonical_json_bytes(
        expected_state.model_dump(mode="json")
    ) or canonical_json_bytes(request.model_dump(mode="json")) != canonical_json_bytes(
        expected_request.model_dump(mode="json")
    ):
        raise ValueError("catalog activation request or state is stale or has a wrong target")
    return request


def catalog_activation_issuance_context(
    request_path: Path | str,
    state_path: Path | str,
    *,
    approval_path: Path | str,
    events_root: Path | str,
    repository_root: Path | str,
) -> AuthorityIssuanceContext:
    """Rederive the strict authority-v2 context for activation or rollback."""

    request = check_catalog_activation_request(
        request_path,
        state_path,
        approval_path=approval_path,
        events_root=events_root,
        repository_root=repository_root,
    )
    state = _load_model(Path(state_path), CatalogActivationStateV2)
    target = _transition_target(
        action=request.action,
        state=state,
        target_revision_sha256=request.target_revision_sha256,
    )
    binding = _activation_binding(state, target)
    return freeze_issuance_context(
        action=request.action,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        reviewer_id=request.reviewer_id,
        binding=binding,
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
        replaces_request_sha256=request.replaces_request_sha256,
        reviewer_channel_risk=request.reviewer_channel_risk,
    )


def _load_authority_descriptor(path: Path) -> tuple[AuthorityIssuanceContext, str]:
    visible = path.lstat()
    if (
        not stat.S_ISREG(visible.st_mode)
        or stat.S_IMODE(visible.st_mode) != 0o600
        or visible.st_nlink != 1
    ):
        raise ValueError("catalog activation authority descriptor must be protected 0600")
    raw = _stable_bytes(path, max_bytes=2_000_000)
    value = json.loads(raw)
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        raise ValueError("catalog activation authority descriptor is not canonical JSON")
    if set(value) != {"schema_version", "issuance_context", "authority_token"} or (
        value.get("schema_version") != "itda.catalog-activation-authority-descriptor.v2"
    ):
        raise ValueError("catalog activation authority descriptor fields differ")
    token = value.get("authority_token")
    if not isinstance(token, str):
        raise ValueError("catalog activation authority token is missing")
    return AuthorityIssuanceContext.model_validate(value.get("issuance_context")), token


def _append_event_locked(
    events_root: Path,
    event: CatalogActivationEventV2,
) -> CatalogActivationEventV2:
    if event.event_sha256 is None:
        raise ValueError("catalog activation event lacks its digest")
    destination = (
        events_root / "catalog-activation-event.json"
        if event.sequence == 1
        else events_root
        / f"catalog-{'rollback' if event.action == 'catalog-rollback' else 'activation'}-event-"
        f"{event.sequence:06d}-{event.event_sha256}.json"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        payload = canonical_json_bytes(event.model_dump(mode="json"))
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(
        events_root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return event


def catalog_activation_event_path(
    events_root: Path | str,
    event: CatalogActivationEventV2,
) -> Path:
    """Find the one immutable file carrying an event digest."""

    matches = [
        path
        for path in _event_paths(Path(events_root))
        if _load_model(path, CatalogActivationEventV2).event_sha256 == event.event_sha256
    ]
    if len(matches) != 1:
        raise ValueError("catalog activation event does not have exactly one file")
    return matches[0]


def consume_catalog_activation(
    *,
    authority_descriptor_path: Path | str,
    request_path: Path | str,
    state_path: Path | str,
    approval_path: Path | str,
    events_root: Path | str,
    nonce_ledger_root: Path | str,
    repository_root: Path | str,
    occurred_at: datetime,
) -> CatalogActivationEventV2:
    """Consume one action under ledger + event locks with deterministic recovery."""

    root = Path(repository_root).resolve(strict=True)
    event_root = Path(events_root)
    request = check_catalog_activation_request(
        request_path,
        state_path,
        approval_path=approval_path,
        events_root=event_root,
        repository_root=root,
    )
    state = _load_model(Path(state_path), CatalogActivationStateV2)
    approval, revision, _ = _approval_and_revision(Path(approval_path), root)
    expected_context = catalog_activation_issuance_context(
        request_path,
        state_path,
        approval_path=approval_path,
        events_root=event_root,
        repository_root=root,
    )
    supplied_context, raw_token = _load_authority_descriptor(Path(authority_descriptor_path))
    if supplied_context.model_dump(mode="json") != expected_context.model_dump(mode="json"):
        raise ValueError("catalog activation authority context differs from live parents")
    target = _transition_target(
        action=request.action,
        state=state,
        target_revision_sha256=request.target_revision_sha256,
    )
    binding = _activation_binding(state, target)
    canonical_time = require_utc(occurred_at, field_name="occurred_at")
    validated = validate_authority_token(
        raw_token,
        issuance_context=expected_context,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        binding=binding,
        reviewer_id=request.reviewer_id,
        now=canonical_time,
        revocation_tombstones=(),
    )
    if (
        request.request_sha256 is None
        or state.state_attestation_sha256 is None
        or expected_context.context_sha256 is None
        or approval.catalog_approval_sha256 is None
        or revision.catalog_revision_sha256 is None
    ):
        raise ValueError("catalog activation parent digest is missing")
    nonce_sha256 = hashlib.sha256(request.nonce.encode("ascii")).hexdigest()

    def expected_event(chain: CatalogActivationChain) -> CatalogActivationEventV2:
        return CatalogActivationEventV2(
            sequence=chain.current_sequence + 1,
            action=request.action,
            request_sha256=request.request_sha256,
            state_attestation_sha256=state.state_attestation_sha256,
            target_sha256=request.target_sha256,
            binding_sha256=request.binding_sha256,
            catalog_approval_sha256=approval.catalog_approval_sha256,
            catalog_revision_sha256=revision.catalog_revision_sha256,
            from_revision_sha256=state.active_revision_sha256,
            to_revision_sha256=request.target_revision_sha256,
            previous_event_sha256=state.current_event_sha256,
            authoritative_relationship_leaves_sha256=(
                state.authoritative_relationship_leaves_sha256
            ),
            rollback_capability_sha256=state.rollback_capability_sha256,
            reviewer_id=request.reviewer_id,
            occurred_at=canonical_time,
            token_sha256=validated.token_sha256,
            nonce_sha256=nonce_sha256,
            issuance_context_sha256=expected_context.context_sha256,
        )

    def relookup() -> Mapping[str, object] | None:
        matches = [
            event
            for event in replay_catalog_activation_chain(event_root).events
            if event.request_sha256 == request.request_sha256
            and event.target_sha256 == request.target_sha256
            and event.token_sha256 == validated.token_sha256
            and event.nonce_sha256 == nonce_sha256
        ]
        if len(matches) > 1:
            raise ValueError("catalog activation recovery found duplicate events")
        return {"result_sha256": cast(str, matches[0].event_sha256)} if matches else None

    def mutation() -> Mapping[str, object]:
        event_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if event_root.is_symlink() or not event_root.is_dir():
            raise ValueError("catalog activation events root is invalid")
        lock_path = event_root / ".catalog-activation-events.lock"
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            chain = replay_catalog_activation_chain(event_root)
            if (
                chain.current_sequence != state.current_sequence
                or chain.current_event_sha256 != state.current_event_sha256
                or chain.active_revision_sha256 != state.active_revision_sha256
            ):
                raise ValueError("catalog activation request has a stale chain head")
            event = _append_event_locked(event_root, expected_event(chain))
            return {"result_sha256": cast(str, event.event_sha256)}
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    receipt = FileNonceLedger(Path(nonce_ledger_root)).consume_with_mutation(
        validated,
        mutation=mutation,
        relookup=relookup,
    )
    for event in replay_catalog_activation_chain(event_root).events:
        if event.event_sha256 == receipt.result_sha256:
            return event
    raise ValueError("catalog activation receipt result is absent from the event chain")


def verify_catalog_activation_event(
    event_path: Path | str,
    *,
    events_root: Path | str,
    approval_path: Path | str,
    repository_root: Path | str,
    require_current: bool = False,
) -> CatalogActivationEventV2:
    """Verify one event against the full chain, approval, revision, and rollback proof."""

    root = Path(repository_root).resolve(strict=True)
    path = Path(event_path)
    event = _load_model(path, CatalogActivationEventV2)
    approval, revision, _ = _approval_and_revision(Path(approval_path), root)
    chain = replay_catalog_activation_chain(events_root)
    matching = [item for item in chain.events if item.event_sha256 == event.event_sha256]
    if len(matching) != 1 or matching[0].model_dump(mode="json") != event.model_dump(mode="json"):
        raise ValueError("catalog activation event is absent from the full chain")
    if (
        event.catalog_approval_sha256 != approval.catalog_approval_sha256
        or event.catalog_revision_sha256 != revision.catalog_revision_sha256
        or event.authoritative_relationship_leaves_sha256
        != revision.authoritative_relationship_leaves_sha256
        or event.rollback_capability_sha256 != rollback_capability_fingerprint(root)
    ):
        raise ValueError("catalog activation event differs from current verified parents")
    if require_current and (
        event.event_sha256 != chain.current_event_sha256
        or event.to_revision_sha256 != chain.active_revision_sha256
    ):
        raise ValueError("catalog activation event is not the current chain head")
    return event


__all__ = [
    "CatalogActivationChain",
    "CatalogActivationEventV2",
    "CatalogActivationRequestV2",
    "CatalogActivationStateV2",
    "build_catalog_activation_request",
    "catalog_activation_event_path",
    "catalog_activation_issuance_context",
    "check_catalog_activation_request",
    "consume_catalog_activation",
    "publish_catalog_activation_request",
    "replay_catalog_activation_chain",
    "rollback_capability_fingerprint",
    "verify_catalog_activation_event",
]
