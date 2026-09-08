"""Versioned, read-only activation rollback-parent migration proof."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.cli.fingerprint_catalog_v1 import (
    PROTECTED_MANIFEST_KEYS,
    FingerprintError,
    build_protected_manifest,
    compare_protected_manifests,
    validate_protected_manifest,
)
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_activation import (
    CatalogActivationEventV2,
    replay_catalog_activation_chain,
    rollback_capability_fingerprint,
)
from itda.contracts.catalog_release import (
    verify_catalog_v2_approval,
    verify_catalog_v2_revision,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

HISTORICAL_PROOF_COMMIT = "788d79a"
AUTHORITY_PATH = "backend/src/itda/contracts/authority.py"
ROLLBACK_PROOF_PATHS = (
    "backend/src/itda/contracts/catalog_activation.py",
    AUTHORITY_PATH,
    "backend/src/itda/cli/activate_catalog.py",
    "backend/tests/security/test_catalog_activation.py",
)
ROLLBACK_CAPABILITIES = (
    "append-only-hash-chain",
    "first-activation-rollback-to-none",
    "distinct-activate-and-rollback-authority",
    "atomic-nonce-and-event-recovery",
    "exclusive-lock-full-chain-replay",
    "verify-event-require-current",
)
ADDED_AUTHORITY_ACTIONS = (
    "sqlite-manifest-initialize",
    "sqlite-real-manifest-seal",
)
AUTHORITY_ACTION_OWNER_COMMITS: Mapping[str, str] = {
    "sqlite-manifest-initialize": "74b8a3e",
    "sqlite-real-manifest-seal": "4279cfb",
}
PROTECTED_FORBIDDEN_TERMS = (
    "authority_token",
    "blind_ids",
    "database_path",
    "database_uri",
    "dev_ids",
    "member_ids",
    "raw_nonce",
    "raw_token",
)
_GUARD_ROOT = "artifacts/restricted/catalog/v2/release/gap-closure-guards"
EVENT_RELPATH = "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"
LEDGER_RELPATH = (
    "artifacts/restricted/catalog/v2/activation/.authority-ledger/"
    "authority-consumption-ledger.jsonl"
)
APPROVAL_RELPATH = "artifacts/restricted/catalog/v2/approval/catalog-approval.json"
REVISION_RELPATH = "artifacts/restricted/catalog/v2/revisions/catalog-revision.json"
ATTESTATION_RELPATH = (
    "artifacts/restricted/catalog/v2/activation/"
    "catalog-activation-current-parent-attestation-v1.json"
)


class CatalogActivationCurrentParentError(ValueError):
    """The historical-to-current activation parent cannot be proven exactly."""


class ProofMigration(StrictContract):
    """Exact byte-level relationship between historical and current proof files."""

    historical_proof_file_hashes: dict[str, Sha256]
    current_proof_file_hashes: dict[str, Sha256]
    changed_proof_paths: tuple[str, ...]
    added_authority_actions: tuple[str, ...]
    migration_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_migration(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"migration_sha256"}, mode="json"))
        if self.migration_sha256 is None:
            object.__setattr__(self, "migration_sha256", expected)
        elif self.migration_sha256 != expected:
            raise ValueError("proof migration sha256 drifted")
        return self


class CurrentParentDiagnosis(StrictContract):
    """Membership-free diagnosis of the one accepted rollback-parent migration."""

    schema_version: Literal["itda.catalog-activation-current-parent-diagnosis.v1"] = (
        "itda.catalog-activation-current-parent-diagnosis.v1"
    )
    event_sha256: Sha256
    historical_proof_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{7,40}$")]
    historical_rollback_capability_sha256: Sha256
    current_rollback_capability_sha256: Sha256
    historical_proof_file_hashes: dict[str, Sha256]
    current_proof_file_hashes: dict[str, Sha256]
    changed_proof_paths: tuple[str, ...]
    added_authority_actions: tuple[str, ...]
    owner_commits: dict[str, Annotated[str, Field(pattern=r"^[0-9a-f]{7,40}$")]]
    migration_sha256: Sha256
    diagnosis_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_diagnosis(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"diagnosis_sha256"}, mode="json"))
        if self.diagnosis_sha256 is None:
            object.__setattr__(self, "diagnosis_sha256", expected)
        elif self.diagnosis_sha256 != expected:
            raise ValueError("current-parent diagnosis sha256 drifted")
        return self


class StableFileIdentity(StrictContract):
    """Stable, membership-free identity for one protected authority file."""

    relpath: Annotated[str, Field(strict=True, min_length=1)]
    device: Annotated[int, Field(strict=True, ge=0)]
    inode: Annotated[int, Field(strict=True, ge=0)]
    mode: Literal[384]
    uid: Annotated[int, Field(strict=True, ge=0)]
    gid: Annotated[int, Field(strict=True, ge=0)]
    link_count: Literal[1]
    size_bytes: Annotated[int, Field(strict=True, ge=0)]
    mtime_ns: Annotated[int, Field(strict=True, ge=0)]
    file_sha256: Sha256


class AuthorityStateSnapshot(StrictContract):
    """Event and nonce-ledger identity captured around a read-only operation."""

    schema_version: Literal["itda.catalog-activation-authority-snapshot.v1"] = (
        "itda.catalog-activation-authority-snapshot.v1"
    )
    event_identity: StableFileIdentity
    ledger_identity: StableFileIdentity
    event_count: Literal[1]
    current_sequence: Literal[1]
    current_event_sha256: Sha256
    active_revision_sha256: Sha256
    snapshot_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"snapshot_sha256"}, mode="json"))
        if self.snapshot_sha256 is None:
            object.__setattr__(self, "snapshot_sha256", expected)
        elif self.snapshot_sha256 != expected:
            raise ValueError("authority state snapshot sha256 drifted")
        return self


class HostileTestResult(StrictContract):
    """Deterministic proof that the unchanged historical hostile suite passed."""

    schema_version: Literal["itda.catalog-activation-hostile-test-result.v1"] = (
        "itda.catalog-activation-hostile-test-result.v1"
    )
    command: tuple[Annotated[str, Field(strict=True, min_length=1)], ...]
    test_file_sha256: Sha256
    exit_code: Literal[0]
    status: Literal["PASS"]
    result_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"result_sha256"}, mode="json"))
        if self.result_sha256 is None:
            object.__setattr__(self, "result_sha256", expected)
        elif self.result_sha256 != expected:
            raise ValueError("hostile test result sha256 drifted")
        return self


class CatalogActivationCurrentParentAttestation(StrictContract):
    """Explicit compatibility link for one unchanged current activation event."""

    schema_version: Literal["itda.catalog-activation-current-parent-attestation.v1"] = (
        "itda.catalog-activation-current-parent-attestation.v1"
    )
    event_path: Literal["artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"]
    event_file_sha256: Sha256
    event_sha256: Sha256
    event_sequence: Literal[1]
    current_event_sha256: Sha256
    active_revision_sha256: Sha256
    approval_path: Literal["artifacts/restricted/catalog/v2/approval/catalog-approval.json"]
    approval_file_sha256: Sha256
    catalog_approval_sha256: Sha256
    revision_path: Literal["artifacts/restricted/catalog/v2/revisions/catalog-revision.json"]
    revision_file_sha256: Sha256
    catalog_revision_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    historical_proof_commit: Literal["788d79a"]
    historical_rollback_capability_sha256: Sha256
    current_rollback_capability_sha256: Sha256
    historical_proof_file_hashes: dict[str, Sha256]
    current_proof_file_hashes: dict[str, Sha256]
    changed_proof_paths: tuple[Literal["backend/src/itda/contracts/authority.py"], ...]
    added_authority_actions: tuple[str, ...]
    owner_commits: dict[str, str]
    migration_sha256: Sha256
    protected_before_path: Annotated[str, Field(strict=True, min_length=1)]
    protected_before_file_sha256: Sha256
    protected_before_manifest_sha256: Sha256
    protected_set_sha256: Sha256
    authority_state_snapshot: AuthorityStateSnapshot
    hostile_test_result: HostileTestResult
    attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        if self.event_sha256 != self.current_event_sha256:
            raise ValueError("attested event is not the current head")
        if self.catalog_revision_sha256 != self.active_revision_sha256:
            raise ValueError("attested revision is not currently active")
        if self.changed_proof_paths != (AUTHORITY_PATH,):
            raise ValueError("attested proof migration is not authority-only")
        if self.added_authority_actions != ADDED_AUTHORITY_ACTIONS:
            raise ValueError("attested authority action migration differs")
        if self.owner_commits != dict(AUTHORITY_ACTION_OWNER_COMMITS):
            raise ValueError("attested authority owner commits differ")
        expected = canonical_sha256(self.model_dump(exclude={"attestation_sha256"}, mode="json"))
        if self.attestation_sha256 is None:
            object.__setattr__(self, "attestation_sha256", expected)
        elif self.attestation_sha256 != expected:
            raise ValueError("current-parent attestation sha256 drifted")
        return self


def _run_git(root: Path, *args: str, check: bool = True) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise CatalogActivationCurrentParentError(f"git evidence command failed: {' '.join(args)}")
    return result.stdout


def _git_show(root: Path, revision: str, relpath: str) -> bytes:
    return _run_git(root, "show", f"{revision}:{relpath}")


def _git_is_ancestor(root: Path, revision: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def _stable_bytes(path: Path, *, max_bytes: int = 8_000_000) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CatalogActivationCurrentParentError("required proof file is missing") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > max_bytes
    ):
        raise CatalogActivationCurrentParentError(
            "required proof file is not a bounded regular single-link file"
        )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise CatalogActivationCurrentParentError(
                "proof file identity changed before stable open"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1_048_576, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise CatalogActivationCurrentParentError("proof file exceeds size bound")
        after = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CatalogActivationCurrentParentError("proof file changed during stable read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _stable_worktree_proof_files(root: Path) -> dict[str, bytes]:
    return {path: _stable_bytes(root / path) for path in ROLLBACK_PROOF_PATHS}


def _stage0_proof_files(root: Path) -> dict[str, bytes]:
    stage_rows = _run_git(root, "ls-files", "-s", "--", *ROLLBACK_PROOF_PATHS).decode()
    parsed: dict[str, tuple[str, str]] = {}
    for line in stage_rows.splitlines():
        metadata, relpath = line.split("\t", 1)
        mode, blob, stage = metadata.split()
        if stage != "0" or mode != "100644":
            raise CatalogActivationCurrentParentError(
                "rollback proof stage-0 mode or stage is invalid"
            )
        parsed[relpath] = (mode, blob)
    if tuple(sorted(parsed, key=str.encode)) != tuple(sorted(ROLLBACK_PROOF_PATHS, key=str.encode)):
        raise CatalogActivationCurrentParentError("rollback proof stage-0 inventory is incomplete")
    return {path: _git_show(root, "", path) for path in ROLLBACK_PROOF_PATHS}


def _proof_hashes(payloads: Mapping[str, bytes]) -> dict[str, str]:
    return {path: hashlib.sha256(payloads[path]).hexdigest() for path in ROLLBACK_PROOF_PATHS}


def _rollback_fingerprint(payloads: Mapping[str, bytes]) -> str:
    return canonical_sha256(
        {
            "schema_version": "itda.catalog-rollback-capability.v2",
            "capabilities": list(ROLLBACK_CAPABILITIES),
            "proof_file_hashes": _proof_hashes(payloads),
        }
    )


def _remove_exact_action_lines(payload: bytes, actions: tuple[str, ...]) -> bytes:
    lines = payload.splitlines(keepends=True)
    for action in actions:
        type_line = f'    "{action}",\n'.encode("ascii")
        allowlist_line = f'        "{action}",\n'.encode("ascii")
        if lines.count(type_line) != 1 or lines.count(allowlist_line) != 1:
            raise CatalogActivationCurrentParentError(
                "authority action migration is not exactly one type and one allowlist line"
            )
        lines.remove(type_line)
        lines.remove(allowlist_line)
    return b"".join(lines)


def validate_proof_file_migration(
    historical: Mapping[str, bytes],
    current: Mapping[str, bytes],
) -> ProofMigration:
    """Accept only the four-line additive SQLite authority migration."""

    expected = set(ROLLBACK_PROOF_PATHS)
    if set(historical) != expected or set(current) != expected:
        raise CatalogActivationCurrentParentError("rollback proof path inventory differs")
    changed = tuple(path for path in ROLLBACK_PROOF_PATHS if historical[path] != current[path])
    if changed != (AUTHORITY_PATH,):
        raise CatalogActivationCurrentParentError(
            "rollback proof path migration is not authority-only"
        )
    reconstructed = _remove_exact_action_lines(current[AUTHORITY_PATH], ADDED_AUTHORITY_ACTIONS)
    if reconstructed != historical[AUTHORITY_PATH]:
        raise CatalogActivationCurrentParentError(
            "authority migration contains an extra, removed, or reordered byte"
        )
    migration = ProofMigration(
        historical_proof_file_hashes=_proof_hashes(historical),
        current_proof_file_hashes=_proof_hashes(current),
        changed_proof_paths=changed,
        added_authority_actions=ADDED_AUTHORITY_ACTIONS,
    )
    if migration.migration_sha256 is None:
        raise CatalogActivationCurrentParentError("migration digest was not derived")
    return migration


def _verify_owner_commits(root: Path) -> dict[str, str]:
    owners = dict(AUTHORITY_ACTION_OWNER_COMMITS)
    if owners != {
        "sqlite-manifest-initialize": "74b8a3e",
        "sqlite-real-manifest-seal": "4279cfb",
    }:
        raise CatalogActivationCurrentParentError("authority owner commit registry drifted")
    for action, commit in owners.items():
        if not _git_is_ancestor(root, commit):
            raise CatalogActivationCurrentParentError("authority owner commit is not in HEAD")
        parent = _git_show(root, f"{commit}^", AUTHORITY_PATH)
        owned = _git_show(root, commit, AUTHORITY_PATH)
        if _remove_exact_action_lines(owned, (action,)) != parent:
            raise CatalogActivationCurrentParentError(
                "authority owner commit contains an unowned change"
            )
    return owners


def _load_event(path: Path) -> CatalogActivationEventV2:
    raw = _stable_bytes(path)
    try:
        event = CatalogActivationEventV2.model_validate(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CatalogActivationCurrentParentError("activation event is invalid") from exc
    if raw != canonical_json_bytes(event.model_dump(mode="json")):
        raise CatalogActivationCurrentParentError("activation event is not canonical")
    return event


def diagnose_current_parent(
    repository_root: Path | str,
    event_path: Path | str,
    *,
    historical_proof_commit: str = HISTORICAL_PROOF_COMMIT,
) -> CurrentParentDiagnosis:
    """Diagnose the exact historical-to-current rollback fingerprint migration."""

    root = Path(repository_root).resolve(strict=True)
    if historical_proof_commit != HISTORICAL_PROOF_COMMIT:
        raise CatalogActivationCurrentParentError("historical proof commit is not allowlisted")
    if not _git_is_ancestor(root, historical_proof_commit):
        raise CatalogActivationCurrentParentError("historical proof commit is not in HEAD")
    event = _load_event(Path(event_path))
    historical = {
        path: _git_show(root, historical_proof_commit, path) for path in ROLLBACK_PROOF_PATHS
    }
    worktree = _stable_worktree_proof_files(root)
    stage0 = _stage0_proof_files(root)
    head = {path: _git_show(root, "HEAD", path) for path in ROLLBACK_PROOF_PATHS}
    if worktree != stage0 or stage0 != head:
        raise CatalogActivationCurrentParentError(
            "rollback proof worktree or stage-0 bytes are dirty"
        )
    migration = validate_proof_file_migration(historical, stage0)
    historical_fingerprint = _rollback_fingerprint(historical)
    if event.rollback_capability_sha256 != historical_fingerprint:
        raise CatalogActivationCurrentParentError(
            "activation event historical rollback fingerprint differs"
        )
    current_fingerprint = _rollback_fingerprint(stage0)
    if current_fingerprint != rollback_capability_fingerprint(root):
        raise CatalogActivationCurrentParentError(
            "current rollback fingerprint differs from the live implementation"
        )
    events_root = root / "artifacts/restricted/catalog/v2/activation"
    chain = replay_catalog_activation_chain(events_root)
    matching = [item for item in chain.events if item.event_sha256 == event.event_sha256]
    if len(matching) != 1 or matching[0] != event:
        raise CatalogActivationCurrentParentError(
            "activation event is absent from the immutable event chain"
        )
    owners = _verify_owner_commits(root)
    assert event.event_sha256 is not None
    assert migration.migration_sha256 is not None
    return CurrentParentDiagnosis(
        event_sha256=event.event_sha256,
        historical_proof_commit=historical_proof_commit,
        historical_rollback_capability_sha256=historical_fingerprint,
        current_rollback_capability_sha256=current_fingerprint,
        historical_proof_file_hashes=migration.historical_proof_file_hashes,
        current_proof_file_hashes=migration.current_proof_file_hashes,
        changed_proof_paths=migration.changed_proof_paths,
        added_authority_actions=migration.added_authority_actions,
        owner_commits=owners,
        migration_sha256=migration.migration_sha256,
    )


def _guard_relpath(plan_id: str, stage: str) -> str:
    if plan_id != "02-61" or stage not in {"before", "after"}:
        raise CatalogActivationCurrentParentError("protected guard coordinates are not Plan 61")
    return f"{_GUARD_ROOT}/{plan_id}-protected-{stage}.json"


def _require_guard_target(root: Path, path: Path, *, plan_id: str, stage: str) -> Path:
    resolved = path.resolve()
    try:
        relpath = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise CatalogActivationCurrentParentError("protected guard escapes repository") from exc
    if relpath != _guard_relpath(plan_id, stage):
        raise CatalogActivationCurrentParentError("protected guard target is not exact")
    return resolved


def _assert_membership_free(value: object) -> None:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
    if any(term in rendered for term in PROTECTED_FORBIDDEN_TERMS):
        raise CatalogActivationCurrentParentError(
            "protected manifest contains a forbidden capability or membership field"
        )


def _publish_exact_existing(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise CatalogActivationCurrentParentError("protected output parent is invalid")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        if _stable_bytes(path) != payload:
            raise CatalogActivationCurrentParentError(
                "existing protected output differs from exact expected bytes"
            ) from exc
        metadata = path.lstat()
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise CatalogActivationCurrentParentError(
                "existing protected output mode or link count differs"
            ) from exc
        return
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("short write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600, follow_symlinks=False)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def validate_protected_manifest_payload(
    repository_root: Path | str,
    payload: dict[str, object],
    *,
    plan_id: str,
    stage: str,
) -> dict[str, object]:
    root = Path(repository_root).resolve(strict=True)
    _assert_membership_free(payload)
    try:
        return validate_protected_manifest(
            root,
            payload,
            plan_id=plan_id,
            stage=stage,
        )
    except FingerprintError as exc:
        raise CatalogActivationCurrentParentError(
            "protected manifest schema or live identity is invalid"
        ) from exc


def capture_protected_manifest_file(
    repository_root: Path | str,
    path: Path | str,
    *,
    plan_id: str,
    stage: str,
) -> dict[str, object]:
    root = Path(repository_root).resolve(strict=True)
    target = _require_guard_target(root, Path(path), plan_id=plan_id, stage=stage)
    try:
        manifest = build_protected_manifest(root, plan_id=plan_id, stage=stage)
    except FingerprintError as exc:
        raise CatalogActivationCurrentParentError("protected manifest build failed") from exc
    _assert_membership_free(manifest)
    _publish_exact_existing(target, canonical_json_bytes(manifest))
    return verify_protected_manifest_file(
        root,
        target,
        plan_id=plan_id,
        stage=stage,
    )


def verify_protected_manifest_file(
    repository_root: Path | str,
    path: Path | str,
    *,
    plan_id: str,
    stage: str,
) -> dict[str, object]:
    root = Path(repository_root).resolve(strict=True)
    target = _require_guard_target(root, Path(path), plan_id=plan_id, stage=stage)
    metadata = target.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
    ):
        raise CatalogActivationCurrentParentError(
            "protected guard permission or identity is invalid"
        )
    ignored = subprocess.run(["git", "check-ignore", "-q", str(target)], cwd=root, check=False)
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(target)],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if ignored.returncode != 0 or tracked.returncode == 0:
        raise CatalogActivationCurrentParentError(
            "protected guard must remain ignored and untracked"
        )
    try:
        payload = json.loads(_stable_bytes(target))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogActivationCurrentParentError("protected guard is invalid JSON") from exc
    if not isinstance(payload, dict) or tuple(payload) != PROTECTED_MANIFEST_KEYS:
        raise CatalogActivationCurrentParentError("protected guard schema is not closed")
    if _stable_bytes(target) != canonical_json_bytes(payload):
        raise CatalogActivationCurrentParentError("protected guard is not canonical JSON")
    return validate_protected_manifest_payload(
        root,
        payload,
        plan_id=plan_id,
        stage=stage,
    )


def compare_protected_manifest_files(
    repository_root: Path | str,
    before_path: Path | str,
    after_path: Path | str,
) -> str:
    root = Path(repository_root).resolve(strict=True)
    before = verify_protected_manifest_file(root, before_path, plan_id="02-61", stage="before")
    after = verify_protected_manifest_file(root, after_path, plan_id="02-61", stage="after")
    try:
        return compare_protected_manifests(before, after)
    except FingerprintError as exc:
        raise CatalogActivationCurrentParentError(
            "protected manifest owner sets are not exactly equal"
        ) from exc


def hash_file(path: Path | str) -> str:
    """Return the SHA-256 of one stable regular file."""

    return hashlib.sha256(_stable_bytes(Path(path))).hexdigest()


def _relative_exact(root: Path, path: Path, expected: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        relpath = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise CatalogActivationCurrentParentError("protected path escapes repository") from exc
    if relpath != expected:
        raise CatalogActivationCurrentParentError(
            f"protected path must be the exact {expected} owner"
        )
    return resolved


def _stable_identity(root: Path, relpath: str) -> StableFileIdentity:
    path = root / relpath
    payload = _stable_bytes(path)
    metadata = path.lstat()
    if (
        stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
    ):
        raise CatalogActivationCurrentParentError(
            "protected authority file mode, link count, or owner differs"
        )
    return StableFileIdentity(
        relpath=relpath,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=0o600,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        link_count=1,
        size_bytes=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        file_sha256=hashlib.sha256(payload).hexdigest(),
    )


def snapshot_authority_state(
    repository_root: Path | str,
    event_path: Path | str,
) -> AuthorityStateSnapshot:
    """Snapshot the immutable event, ledger, and derived current chain."""

    root = Path(repository_root).resolve(strict=True)
    _relative_exact(root, Path(event_path), EVENT_RELPATH)
    event = _load_event(root / EVENT_RELPATH)
    chain = replay_catalog_activation_chain(root / Path(EVENT_RELPATH).parent)
    if (
        len(chain.events) != 1
        or chain.current_sequence != 1
        or chain.current_event_sha256 != event.event_sha256
        or chain.active_revision_sha256 != event.to_revision_sha256
        or event.to_revision_sha256 is None
        or event.event_sha256 is None
    ):
        raise CatalogActivationCurrentParentError(
            "activation event is not the sole current sequence-1 head"
        )
    return AuthorityStateSnapshot(
        event_identity=_stable_identity(root, EVENT_RELPATH),
        ledger_identity=_stable_identity(root, LEDGER_RELPATH),
        event_count=1,
        current_sequence=1,
        current_event_sha256=event.event_sha256,
        active_revision_sha256=event.to_revision_sha256,
    )


def _require_unchanged_authority_state(
    before: AuthorityStateSnapshot,
    after: AuthorityStateSnapshot,
) -> None:
    if before.model_dump(mode="json") != after.model_dump(mode="json"):
        raise CatalogActivationCurrentParentError(
            "activation event or ledger identity changed during verification"
        )


def run_hostile_activation_tests(repository_root: Path | str) -> HostileTestResult:
    """Run the unchanged historical hostile suite without exposing its output."""

    root = Path(repository_root).resolve(strict=True)
    command = (
        "python",
        "-m",
        "pytest",
        "tests/security/test_catalog_activation.py",
        "-q",
    )
    result = subprocess.run(
        [sys.executable, *command[1:]],
        cwd=root / "backend",
        check=False,
        capture_output=True,
        timeout=420,
    )
    if result.returncode != 0:
        raise CatalogActivationCurrentParentError(
            "unchanged historical hostile activation suite failed"
        )
    return HostileTestResult(
        command=command,
        test_file_sha256=hash_file(root / "backend/tests/security/test_catalog_activation.py"),
        exit_code=0,
        status="PASS",
    )


HostileTestRunner = Callable[[Path], HostileTestResult]


def build_current_parent_attestation_payload(
    repository_root: Path | str,
    event_path: Path | str,
    protected_before_path: Path | str,
    *,
    historical_proof_commit: str = HISTORICAL_PROOF_COMMIT,
    hostile_test_result: HostileTestResult,
) -> CatalogActivationCurrentParentAttestation:
    """Build canonical attestation data from independently replayed current parents."""

    root = Path(repository_root).resolve(strict=True)
    event_target = _relative_exact(root, Path(event_path), EVENT_RELPATH)
    before_target = _require_guard_target(
        root,
        Path(protected_before_path),
        plan_id="02-61",
        stage="before",
    )
    before_manifest = verify_protected_manifest_file(
        root,
        before_target,
        plan_id="02-61",
        stage="before",
    )
    diagnosis = diagnose_current_parent(
        root,
        event_target,
        historical_proof_commit=historical_proof_commit,
    )
    event = _load_event(event_target)
    snapshot = snapshot_authority_state(root, event_target)
    approval_path = root / APPROVAL_RELPATH
    approval = verify_catalog_v2_approval(
        approval_path,
        repository_root=root,
        require_inactive=True,
    )
    revision_path = root / REVISION_RELPATH
    revision = verify_catalog_v2_revision(
        revision_path,
        repository_root=root,
        require_inactive=True,
    )
    if (
        event.catalog_approval_sha256 != approval.catalog_approval_sha256
        or event.catalog_revision_sha256 != revision.catalog_revision_sha256
        or event.authoritative_relationship_leaves_sha256
        != revision.authoritative_relationship_leaves_sha256
        or snapshot.current_event_sha256 != event.event_sha256
        or snapshot.active_revision_sha256 != event.to_revision_sha256
    ):
        raise CatalogActivationCurrentParentError(
            "activation event differs from a non-fingerprint verified parent"
        )
    if hostile_test_result.status != "PASS" or hostile_test_result.exit_code != 0:
        raise CatalogActivationCurrentParentError("hostile activation tests did not pass")
    if (
        hostile_test_result.test_file_sha256
        != diagnosis.current_proof_file_hashes["backend/tests/security/test_catalog_activation.py"]
    ):
        raise CatalogActivationCurrentParentError(
            "hostile test result is not bound to the current proof bytes"
        )
    assert event.event_sha256 is not None
    assert event.to_revision_sha256 is not None
    assert diagnosis.diagnosis_sha256 is not None
    protected_manifest_sha = before_manifest.get("protected_manifest_sha256")
    protected_set_sha = before_manifest.get("protected_set_sha256")
    if not isinstance(protected_manifest_sha, str) or not isinstance(protected_set_sha, str):
        raise CatalogActivationCurrentParentError("protected before manifest digests are invalid")
    return CatalogActivationCurrentParentAttestation(
        event_path=("artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"),
        event_file_sha256=hash_file(event_target),
        event_sha256=event.event_sha256,
        event_sequence=1,
        current_event_sha256=snapshot.current_event_sha256,
        active_revision_sha256=snapshot.active_revision_sha256,
        approval_path="artifacts/restricted/catalog/v2/approval/catalog-approval.json",
        approval_file_sha256=hash_file(approval_path),
        catalog_approval_sha256=approval.catalog_approval_sha256,
        revision_path="artifacts/restricted/catalog/v2/revisions/catalog-revision.json",
        revision_file_sha256=hash_file(revision_path),
        catalog_revision_sha256=revision.catalog_revision_sha256,
        authoritative_relationship_leaves_sha256=(
            revision.authoritative_relationship_leaves_sha256
        ),
        historical_proof_commit="788d79a",
        historical_rollback_capability_sha256=(diagnosis.historical_rollback_capability_sha256),
        current_rollback_capability_sha256=(diagnosis.current_rollback_capability_sha256),
        historical_proof_file_hashes=diagnosis.historical_proof_file_hashes,
        current_proof_file_hashes=diagnosis.current_proof_file_hashes,
        changed_proof_paths=("backend/src/itda/contracts/authority.py",),
        added_authority_actions=diagnosis.added_authority_actions,
        owner_commits=diagnosis.owner_commits,
        migration_sha256=diagnosis.migration_sha256,
        protected_before_path=before_target.relative_to(root).as_posix(),
        protected_before_file_sha256=hash_file(before_target),
        protected_before_manifest_sha256=protected_manifest_sha,
        protected_set_sha256=protected_set_sha,
        authority_state_snapshot=snapshot,
        hostile_test_result=hostile_test_result,
    )


def validate_current_parent_attestation_payload(
    repository_root: Path | str,
    payload: dict[str, object],
    event_path: Path | str,
    *,
    require_current: bool,
    hostile_test_result: HostileTestResult,
) -> CatalogActivationCurrentParentAttestation:
    """Independently rebuild and compare every attested current parent."""

    try:
        recorded = CatalogActivationCurrentParentAttestation.model_validate(payload)
    except ValueError as exc:
        raise CatalogActivationCurrentParentError(
            "current-parent attestation schema or self hash is invalid"
        ) from exc
    if not require_current:
        raise CatalogActivationCurrentParentError(
            "current-parent attestation verification requires the current head"
        )
    root = Path(repository_root).resolve(strict=True)
    expected = build_current_parent_attestation_payload(
        root,
        event_path,
        root / recorded.protected_before_path,
        historical_proof_commit=recorded.historical_proof_commit,
        hostile_test_result=hostile_test_result,
    )
    if recorded.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise CatalogActivationCurrentParentError(
            "current-parent attestation differs from exact live replay"
        )
    return expected


def publish_attestation_no_replace(path: Path | str, payload: bytes) -> str:
    """Publish one 0600 attestation or verify exact-existing state read-only."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise CatalogActivationCurrentParentError("attestation parent is invalid")
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        existing = _stable_bytes(target)
        metadata = target.lstat()
        if existing != payload:
            raise CatalogActivationCurrentParentError(
                "existing attestation differs from exact expected bytes"
            ) from exc
        if (
            stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
        ):
            raise CatalogActivationCurrentParentError(
                "existing attestation mode, link count, or owner differs"
            ) from exc
        return "ALREADY_PRESENT_VERIFIED"
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("short attestation write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(target, 0o600, follow_symlinks=False)
    parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return "PUBLISHED"


def _attestation_target(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    try:
        relpath = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise CatalogActivationCurrentParentError("attestation path escapes repository") from exc
    if relpath != ATTESTATION_RELPATH:
        raise CatalogActivationCurrentParentError("attestation target path is not exact")
    return resolved


def build_current_parent_attestation(
    repository_root: Path | str,
    attestation_path: Path | str,
    event_path: Path | str,
    protected_before_path: Path | str,
    *,
    historical_proof_commit: str = HISTORICAL_PROOF_COMMIT,
    hostile_test_runner: HostileTestRunner = run_hostile_activation_tests,
) -> CatalogActivationCurrentParentAttestation:
    """Double-diagnose, publish no-replace, and prove authority state unchanged."""

    root = Path(repository_root).resolve(strict=True)
    target = _attestation_target(root, Path(attestation_path))
    before_state = snapshot_authority_state(root, Path(event_path))
    hostile_result = hostile_test_runner(root)
    first = build_current_parent_attestation_payload(
        root,
        event_path,
        protected_before_path,
        historical_proof_commit=historical_proof_commit,
        hostile_test_result=hostile_result,
    )
    second = build_current_parent_attestation_payload(
        root,
        event_path,
        protected_before_path,
        historical_proof_commit=historical_proof_commit,
        hostile_test_result=hostile_result,
    )
    first_bytes = canonical_json_bytes(first.model_dump(mode="json"))
    if first_bytes != canonical_json_bytes(second.model_dump(mode="json")):
        raise CatalogActivationCurrentParentError(
            "two current-parent diagnoses were not byte-identical; event or ledger changed"
        )
    _require_unchanged_authority_state(
        before_state,
        snapshot_authority_state(root, Path(event_path)),
    )
    publish_attestation_no_replace(target, first_bytes)
    _require_unchanged_authority_state(
        before_state,
        snapshot_authority_state(root, Path(event_path)),
    )
    return first


def verify_current_parent_attestation_file(
    repository_root: Path | str,
    attestation_path: Path | str,
    event_path: Path | str,
    *,
    require_current: bool,
    protected_before_path: Path | str | None = None,
    protected_after_path: Path | str | None = None,
    hostile_test_runner: HostileTestRunner = run_hostile_activation_tests,
) -> CatalogActivationCurrentParentAttestation:
    """Verify the attestation, current parents, guards, and unchanged authority state."""

    root = Path(repository_root).resolve(strict=True)
    target = _attestation_target(root, Path(attestation_path))
    metadata = target.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
    ):
        raise CatalogActivationCurrentParentError(
            "attestation mode, link count, type, or owner differs"
        )
    before_state = snapshot_authority_state(root, Path(event_path))
    raw = _stable_bytes(target)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogActivationCurrentParentError("attestation is invalid JSON") from exc
    hostile_result = hostile_test_runner(root)
    verified = validate_current_parent_attestation_payload(
        root,
        payload,
        event_path,
        require_current=require_current,
        hostile_test_result=hostile_result,
    )
    if raw != canonical_json_bytes(verified.model_dump(mode="json")):
        raise CatalogActivationCurrentParentError("attestation bytes are not canonical")
    if (protected_before_path is None) != (protected_after_path is None):
        raise CatalogActivationCurrentParentError(
            "protected guard verification requires both before and after"
        )
    if (
        protected_before_path is not None
        and protected_after_path is not None
        and compare_protected_manifest_files(
            root,
            protected_before_path,
            protected_after_path,
        )
        != "EXACT_EQUAL"
    ):
        raise CatalogActivationCurrentParentError(
            "protected before and after guards are not exactly equal"
        )
    _require_unchanged_authority_state(
        before_state,
        snapshot_authority_state(root, Path(event_path)),
    )
    return verified


__all__ = [
    "ADDED_AUTHORITY_ACTIONS",
    "ATTESTATION_RELPATH",
    "AUTHORITY_ACTION_OWNER_COMMITS",
    "AuthorityStateSnapshot",
    "CatalogActivationCurrentParentAttestation",
    "CatalogActivationCurrentParentError",
    "CurrentParentDiagnosis",
    "HISTORICAL_PROOF_COMMIT",
    "HostileTestResult",
    "PROTECTED_FORBIDDEN_TERMS",
    "ProofMigration",
    "ROLLBACK_PROOF_PATHS",
    "build_current_parent_attestation",
    "build_current_parent_attestation_payload",
    "capture_protected_manifest_file",
    "compare_protected_manifest_files",
    "diagnose_current_parent",
    "hash_file",
    "publish_attestation_no_replace",
    "run_hostile_activation_tests",
    "snapshot_authority_state",
    "validate_current_parent_attestation_payload",
    "validate_proof_file_migration",
    "validate_protected_manifest_payload",
    "verify_current_parent_attestation_file",
    "verify_protected_manifest_file",
]
