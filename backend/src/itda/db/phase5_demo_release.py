"""Fail-closed local authority for the Phase 5 contest-demo scored release."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from itda.cli.freeze_preview import (
    PublicationStateUncertainError,
    prepared_directory_snapshot,
    publish_immutable_directory,
)
from itda.contracts.demo_profile_materialization import (
    ATTEMPT_RESERVATION_MICRO_USD,
    CANONICAL_CONTRAST_PAIRS,
    CANONICAL_PHASE5_RECOVERY_POLICY,
    CANONICAL_SCENARIO_IDS,
    CODING_PLAN_AUTHORITY_SHA256,
    CODING_PLAN_ENDPOINT,
    CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    CODING_PLAN_MODEL_WEIGHT,
    MAX_HTTP_ATTEMPTS,
    NVIDIA_AUTHORITY_SHA256,
    NVIDIA_PROFILE_ENDPOINT,
    NVIDIA_PROFILE_MODEL,
    NVIDIA_RESUME_AUTHORITY_SHA256,
    NVIDIA_SECOND_RESUME_AUTHORITY_SHA256,
    NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256,
    NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256,
    NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256,
    NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256,
    NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
    NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT,
    NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256,
    NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256,
    NVIDIA_V4_PROBE_RESUME_RESPONSE_SHA256,
    NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS,
    PRICING_SNAPSHOT_SHA256,
    RERUN_AUTHORITY_SHA256,
    CodingPlanProfileAttempt,
    CodingPlanProfileMaterializationConfig,
    CodingPlanProfileMaterializationReceipt,
    DemoModelDerivedProfile,
    DemoProfileAttempt,
    DemoProfileMaterializationConfig,
    DemoProfileMaterializationReceipt,
    DemoSourceBundle,
    NvidiaMinimaxModelDerivedProfile,
    NvidiaMinimaxProfileAttempt,
    NvidiaMinimaxProfileMaterializationConfig,
    NvidiaMinimaxProfileMaterializationReceipt,
    Phase5ActivationAttestation,
    Phase5ActivationIntent,
    Phase5CandidateSmokeAttestation,
    Phase5CodingPlanReleaseCandidate,
    Phase5DemoReleaseCandidate,
    Phase5DemoReleaseReceipt,
    Phase5InvalidationReceipt,
    Phase5NvidiaMinimaxReleaseCandidate,
    Phase5PromotionReceipt,
    Phase5RecoveryActivePointer,
    Phase5RecoveryReleaseCandidate,
    Phase5ReleaseLifecycle,
    Phase5RollbackReceipt,
    PricingSnapshot,
    PublicScoredReleaseSnapshot,
    _validate_recovery_maps,
    seal_demo_contract,
)
from itda.contracts.hard_duplicate_adjudication import (
    HardDuplicateAdjudication,
    load_hard_duplicate_adjudication,
)
from itda.contracts.phase5_recovery_policy import ActivationScenarioResult
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.demo_profile_eligibility import evaluate_nvidia_publication_cohort
from itda.domain.profile_fusion import classify_publication
from itda.pipeline.demo_profile_materialization import (
    DemoProfileMaterializationError,
    _lineage_for,
    _nvidia_lineage_for,
    _nvidia_v5_lineage_for,
    build_nvidia_v4_probe_resume_authority,
    build_nvidia_v4_probe_resume_plan,
    validate_demo_source_inventory,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
PRODUCTION_ROOT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/phase5-demo-profile-materialization"
)
FIXED_DEV_AUTHORITY = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/phase4-demo-authority/input-authority.json"
)
FIXED_CANONICAL_CATALOG = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json"
)
FIXED_CONTEST_RIGHTS_CLOSURE = (
    REPOSITORY_ROOT / "artifacts/catalog/contest-use-official-public-data-v1/closure-result.json"
)
_CONTEST_RIGHTS_ROOT_SHA256 = "863a064bbd83d945e82b4f19729aa62bd53e1ea4d260f3373877d6ba18188be2"
_GENERATION_BASE_FILES = frozenset({"attempts.json", "profiles.json", "receipt.json"})
_CODING_PLAN_EVIDENCE_REF = "debug-session:phase5-coding-endpoint#user-account-plan-screenshot"
_PRIOR_PAYGO_CUMULATIVE_UPPER_MICRO_USD = 12_445_760
_PRIOR_PAYGO_BLOCKER_SHA256 = "3834d0de4c60a760a15971ec4d2694e2f09d158549b94b18634fe87cd40c4cd7"
_INVALIDATED_LEGACY_POINTER_FILE_SHA256 = (
    "9c3d28fb770b3c8b53acee419abdefe1fed21fb14d2854c9f2f5fd685566d0fc"
)
_INVALIDATED_LEGACY_RECEIPT_SHA256 = (
    "ad7edaa8cb97569385f2601d52374565a683df4f84e1c8dd47e23ad72b901f00"
)
_INVALIDATED_LEGACY_RELEASE_SHA256 = (
    "59c3a6379e1e3de6ef67d95947d80f39d97c21bdcbf368d0080e5d8aa7224c50"
)
_INVALIDATED_LEGACY_CANDIDATE_FILE_SHA256 = (
    "6138959ce11516f2308fbc2b019b33938c6c22a523fc5901aff83259b123d200"
)
_INVALIDATED_LEGACY_GENERATION_SHA256 = (
    "4354deace22c92a821f7ada3ff307dff775736fa7a9618a2eab3b2a29bc96581"
)
_INVALIDATED_LEGACY_GENERATION_RECEIPT_FILE_SHA256 = (
    "070d90842d189f1e2be581c544b433411eaa384d52b3f19c14e60a42b444929f"
)


class Phase5DemoReleaseError(ValueError):
    """Bounded failure that never includes protected content or paths."""


def _require_no_symlink_ancestors(path: Path) -> None:
    """Reject a path reached through any symlinked directory component."""

    cursor = path.absolute()
    while True:
        try:
            if cursor.is_symlink():
                raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK")
        except OSError as error:
            raise Phase5DemoReleaseError("RESTRICTED_PATH_UNAVAILABLE") from error
        if cursor.parent == cursor:
            return
        cursor = cursor.parent


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    _require_no_symlink_ancestors(path)
    absolute = path.absolute()
    components = absolute.parts
    if len(components) < 2 or not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    parent_descriptor: int | None = None
    try:
        parent_descriptor = os.open(components[0], directory_flags)
        for component in components[1:-1]:
            child_descriptor = os.open(component, directory_flags, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = child_descriptor
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK") from error
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise Phase5DemoReleaseError("RESTRICTED_INPUT_INVALID")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise Phase5DemoReleaseError("RESTRICTED_INPUT_TRUNCATED")
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
            raise Phase5DemoReleaseError("RESTRICTED_INPUT_CHANGED")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _read_json(path: Path, *, maximum_bytes: int = 64 * 1024 * 1024) -> object:
    try:
        return json.loads(_read_regular(path, maximum_bytes=maximum_bytes))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Phase5DemoReleaseError("RESTRICTED_JSON_INVALID") from error


@lru_cache(maxsize=1)
def _verified_contest_rights_root() -> str:
    value = _read_json(FIXED_CONTEST_RIGHTS_CLOSURE)
    if not isinstance(value, dict):
        raise Phase5DemoReleaseError("CONTEST_RIGHTS_CLOSURE_INVALID")
    supplied = value.get("closure_result_sha256")
    roots = value.get("plan55_roots")
    if (
        supplied
        != canonical_sha256(
            {key: item for key, item in value.items() if key != "closure_result_sha256"}
        )
        or value.get("schema_version") != "itda.catalog-contest-use-closure-result.v1"
        or value.get("status") != "success"
        or value.get("scope") != "noncommercial_contest_demo_evaluation"
        or value.get("policy_version") != "contest-use-official-public-data-v1"
        or value.get("commercial_production_rights_review_required") is not True
        or not isinstance(roots, dict)
        or roots.get("contest_rights_root_sha256") != _CONTEST_RIGHTS_ROOT_SHA256
    ):
        raise Phase5DemoReleaseError("CONTEST_RIGHTS_CLOSURE_DRIFT")
    return _CONTEST_RIGHTS_ROOT_SHA256


def _bounded_public_excerpt(text: str) -> str:
    normalized = " ".join(text.split())
    if not normalized:
        raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_TEXT_EMPTY")
    if len(normalized) <= 240:
        return normalized
    prefix = normalized[:239]
    boundary = max(prefix.rfind(mark) for mark in (". ", "! ", "? ", "다. ", "요. "))
    if boundary >= 80:
        return prefix[: boundary + 1].rstrip()
    return f"{prefix}…"


@lru_cache(maxsize=1)
def _canonical_place_names() -> dict[str, str]:
    """Return only verified public-safe names from the immutable canonical catalog."""

    value = _read_json(FIXED_CANONICAL_CATALOG)
    if not isinstance(value, dict):
        raise Phase5DemoReleaseError("CANONICAL_CATALOG_INVALID")
    rows = value.get("rows")
    revision = value.get("catalog_revision_sha256")
    if (
        value.get("schema_version") != "itda.catalog-v2-final-audit.v1"
        or value.get("row_count") != 36
        or not isinstance(revision, str)
        or not isinstance(rows, list)
        or len(rows) != 36
    ):
        raise Phase5DemoReleaseError("CANONICAL_CATALOG_INVALID")
    names: dict[str, str] = {}
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            raise Phase5DemoReleaseError("CANONICAL_CATALOG_INVALID")
        place_id = raw_row.get("canonical_place_id")
        name_ko = raw_row.get("name_ko")
        row_sha256 = raw_row.get("canonical_row_sha256")
        if (
            not isinstance(place_id, str)
            or not isinstance(name_ko, str)
            or not 0 < len(name_ko) <= 120
            or raw_row.get("catalog_revision_sha256") != revision
            or row_sha256
            != canonical_sha256(
                {key: item for key, item in raw_row.items() if key != "canonical_row_sha256"}
            )
            or place_id in names
        ):
            raise Phase5DemoReleaseError("CANONICAL_CATALOG_INVALID")
        names[place_id] = name_ko
    if tuple(names) != tuple(sorted(names)):
        raise Phase5DemoReleaseError("CANONICAL_CATALOG_ORDER_INVALID")
    return names


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short private write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_directory_chain(path: Path) -> int:
    """Open every path component with no-follow semantics and keep the final fd pinned."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE")
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor or os.sep, directory_flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        os.close(descriptor)
        if error.errno == errno.ELOOP:
            raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK") from error
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error


def _open_or_create_directory(parent_descriptor: int, name: str) -> int:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        with suppress(FileExistsError):
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        try:
            descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK") from error
            raise
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK") from error
        raise
    try:
        os.fsync(parent_descriptor)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _require_canonical_directory(
    path: Path,
    pinned_descriptor: int,
    *,
    error_code: str,
) -> None:
    """Ensure a canonical pathname still resolves to its pinned directory fd."""

    expected = os.fstat(pinned_descriptor)
    try:
        current_descriptor = _open_directory_chain(path)
    except (OSError, Phase5DemoReleaseError) as error:
        raise Phase5DemoReleaseError(error_code) from error
    try:
        current = os.fstat(current_descriptor)
        if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
            raise Phase5DemoReleaseError(error_code)
    finally:
        os.close(current_descriptor)


def _read_regular_at(directory_descriptor: int, name: str, *, maximum_bytes: int) -> bytes:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        raise
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK") from error
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise Phase5DemoReleaseError("RESTRICTED_INPUT_INVALID")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise Phase5DemoReleaseError("RESTRICTED_INPUT_TRUNCATED")
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
            raise Phase5DemoReleaseError("RESTRICTED_INPUT_CHANGED")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _open_directory_beneath(root_descriptor: int, components: Sequence[str]) -> int:
    """Open a descendant directory without resolving through the mutable root path."""

    descriptor = os.dup(root_descriptor)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        for component in components:
            if component in {"", ".", ".."} or "/" in component:
                raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise Phase5DemoReleaseError("RESTRICTED_PATH_SYMLINK") from error
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_beneath(
    root_descriptor: int,
    components: Sequence[str],
    *,
    maximum_bytes: int,
) -> bytes:
    if not components:
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE")
    parent = _open_directory_beneath(root_descriptor, components[:-1])
    try:
        return _read_regular_at(parent, components[-1], maximum_bytes=maximum_bytes)
    finally:
        os.close(parent)


def _read_json_beneath(
    root_descriptor: int,
    components: Sequence[str],
    *,
    maximum_bytes: int = 64 * 1024 * 1024,
) -> object:
    try:
        return json.loads(
            _read_regular_beneath(
                root_descriptor,
                components,
                maximum_bytes=maximum_bytes,
            )
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Phase5DemoReleaseError("RESTRICTED_JSON_INVALID") from error


def _read_exact_tree_beneath(
    root_descriptor: int,
    prefix: Sequence[str],
    expected_files: set[str],
    *,
    maximum_bytes: int,
) -> dict[str, bytes]:
    """Snapshot an exact regular-file tree below one pinned root descriptor."""

    expected_directories = {
        "/".join(parts[:index])
        for relative in expected_files
        for parts in (relative.split("/"),)
        for index in range(1, len(parts))
    }
    observed_files: set[str] = set()
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    def walk(directory_descriptor: int, relative_directory: str = "") -> None:
        try:
            names = os.listdir(directory_descriptor)
        except OSError as error:
            raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error
        for name in names:
            if not name or name in {".", ".."} or "/" in name:
                raise Phase5DemoReleaseError("RESTRICTED_INPUT_INVALID")
            relative = f"{relative_directory}/{name}" if relative_directory else name
            try:
                metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            except OSError as error:
                raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error
            if stat.S_ISDIR(metadata.st_mode):
                if relative not in expected_directories:
                    raise Phase5DemoReleaseError("RESTRICTED_INPUT_INVALID")
                try:
                    child = os.open(name, directory_flags, dir_fd=directory_descriptor)
                except OSError as error:
                    raise Phase5DemoReleaseError("RESTRICTED_INPUT_UNAVAILABLE") from error
                try:
                    walk(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(relative)
            else:
                raise Phase5DemoReleaseError("RESTRICTED_INPUT_INVALID")

    tree_descriptor = _open_directory_beneath(root_descriptor, prefix)
    try:
        walk(tree_descriptor)
    finally:
        os.close(tree_descriptor)
    if observed_files != expected_files:
        raise Phase5DemoReleaseError("RESTRICTED_INPUT_INVALID")
    snapshot = {
        relative: _read_regular_beneath(
            root_descriptor,
            (*prefix, *relative.split("/")),
            maximum_bytes=maximum_bytes,
        )
        for relative in sorted(expected_files)
    }
    for relative, payload in snapshot.items():
        if (
            _read_regular_beneath(
                root_descriptor,
                (*prefix, *relative.split("/")),
                maximum_bytes=maximum_bytes,
            )
            != payload
        ):
            raise Phase5DemoReleaseError("RESTRICTED_INPUT_CHANGED")
    return snapshot


def _write_private_at(directory_descriptor: int, name: str, payload: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory_descriptor,
    )
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short private write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_private_temporary_at(directory_descriptor: int, payload: bytes) -> str:
    for _ in range(8):
        name = f".current-{uuid.uuid4().hex}"
        try:
            _write_private_at(directory_descriptor, name, payload)
            return name
        except FileExistsError:
            continue
    raise Phase5DemoReleaseError("ACTIVATION_TEMPORARY_UNAVAILABLE")


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_expected_ids(expected_place_ids: Sequence[str]) -> tuple[str, ...]:
    expected = tuple(expected_place_ids)
    if (
        len(expected) != 24
        or len(set(expected)) != 24
        or expected != tuple(sorted(expected))
        or any(not value or "blind" in value.casefold() for value in expected)
    ):
        raise Phase5DemoReleaseError("DEV_MEMBERSHIP_INVALID")
    return expected


def _production_expected_ids() -> tuple[str, ...]:
    value = _read_json(FIXED_DEV_AUTHORITY, maximum_bytes=4 * 1024 * 1024)
    if not isinstance(value, dict):
        raise Phase5DemoReleaseError("DEV_AUTHORITY_INVALID")
    authority = cast(dict[str, object], value)
    supplied = authority.get("authority_sha256")
    if supplied != canonical_sha256(
        {key: nested for key, nested in authority.items() if key != "authority_sha256"}
    ):
        raise Phase5DemoReleaseError("DEV_AUTHORITY_DIGEST_DRIFT")
    ids = authority.get("dev_place_refs")
    if not isinstance(ids, list) or any(not isinstance(item, str) for item in ids):
        raise Phase5DemoReleaseError("DEV_AUTHORITY_MEMBERSHIP_INVALID")
    return _validate_expected_ids(cast(list[str], ids))


def _attempts_from_values(
    values: Sequence[object],
) -> tuple[DemoProfileAttempt | CodingPlanProfileAttempt | NvidiaMinimaxProfileAttempt, ...]:
    try:
        return tuple(
            (
                CodingPlanProfileAttempt.model_validate(value)
                if value.get("schema_version") == "itda.coding-plan-profile-attempt.v1"
                else NvidiaMinimaxProfileAttempt.model_validate(value)
                if value.get("schema_version") == "itda.nvidia-minimax-profile-attempt.v3"
                else DemoProfileAttempt.model_validate(value)
            )
            if isinstance(value, Mapping)
            else DemoProfileAttempt.model_validate(value)
            for value in values
        )
    except ValidationError as error:
        raise Phase5DemoReleaseError("ATTEMPT_CONTRACT_INVALID") from error


def _require_nondegenerate_profiles(
    profiles: Sequence[DemoModelDerivedProfile | NvidiaMinimaxModelDerivedProfile],
) -> None:
    if not profiles:
        return
    nvidia_profiles = tuple(
        profile for profile in profiles if isinstance(profile, NvidiaMinimaxModelDerivedProfile)
    )
    if nvidia_profiles:
        if len(nvidia_profiles) != len(profiles):
            raise Phase5DemoReleaseError("PROFILE_CONTRACT_MIXED")
        eligibility = evaluate_nvidia_publication_cohort(
            tuple(profile.model_dump(mode="json") for profile in nvidia_profiles)
        )
        if not eligibility.eligible or not eligibility.recommendation_eligible:
            raise Phase5DemoReleaseError(eligibility.reason)
        try:
            tuple(
                NvidiaMinimaxModelDerivedProfile.model_validate(profile.model_dump(mode="json"))
                for profile in nvidia_profiles
            )
        except ValidationError as error:
            raise Phase5DemoReleaseError("PROFILE_CONTRACT_INVALID") from error
        return
    vectors = tuple(
        tuple(profile.axis_scores[key] for key in ("H", "E", "R")) for profile in profiles
    )
    if any(all(value == 0 for value in vector) for vector in vectors):
        raise Phase5DemoReleaseError("PROFILE_SCHEMA_ECHO_DETECTED")
    if len(vectors) > 1 and len(set(vectors)) == 1:
        raise Phase5DemoReleaseError("PROFILE_COHORT_DEGENERATE")
    if len(vectors) > 1:
        axis_probes = (
            (100, 0, 0),
            (0, 100, 0),
            (0, 0, 100),
        )
        top_count = min(5, len(profiles))
        probe_top_fives = tuple(
            tuple(
                profile.place_id
                for profile, vector in sorted(
                    zip(profiles, vectors, strict=True),
                    key=lambda item: (
                        -sum(value * weight for value, weight in zip(item[1], probe, strict=True)),
                        item[0].place_id,
                    ),
                )[:top_count]
            )
            for probe in axis_probes
        )
        if len(set(probe_top_fives)) != len(axis_probes):
            raise Phase5DemoReleaseError("PROFILE_RANK_INSENSITIVE")


def validate_demo_scored_release(
    *,
    profiles: Sequence[DemoModelDerivedProfile | NvidiaMinimaxModelDerivedProfile],
    attempts: Sequence[object],
    receipt: (
        DemoProfileMaterializationReceipt
        | CodingPlanProfileMaterializationReceipt
        | NvidiaMinimaxProfileMaterializationReceipt
    ),
    source_bundles: Sequence[DemoSourceBundle],
    raw_responses: Mapping[str, bytes],
    expected_place_ids: Sequence[str],
    _adjudication: HardDuplicateAdjudication | None = None,
) -> (
    Phase5DemoReleaseCandidate
    | Phase5CodingPlanReleaseCandidate
    | Phase5NvidiaMinimaxReleaseCandidate
):
    """Independently reconstruct one exact live release from private evidence."""

    expected = _validate_expected_ids(expected_place_ids)
    adjudication = _adjudication or load_hard_duplicate_adjudication()
    if tuple(adjudication.group_id_by_place) != expected:
        raise Phase5DemoReleaseError("HARD_DUPLICATE_MEMBERSHIP_MISMATCH")
    if receipt.status != "COMPLETE_UNACTIVATED":
        raise Phase5DemoReleaseError("LIVE_GENERATION_REQUIRED")
    try:
        sources = validate_demo_source_inventory(source_bundles)
    except (ValidationError, ValueError) as error:
        raise Phase5DemoReleaseError("SOURCE_INVENTORY_INVALID") from error
    if tuple(bundle.place_id for bundle in sources) != expected:
        raise Phase5DemoReleaseError("SOURCE_MEMBERSHIP_MISMATCH")
    if any(bundle.optional_image is not None for bundle in sources):
        raise Phase5DemoReleaseError("OPTIONAL_IMAGE_AUTHORITY_UNAVAILABLE")

    restored_profiles = tuple(profiles)
    profile_ids = tuple(profile.place_id for profile in restored_profiles)
    if profile_ids != expected or len(restored_profiles) != 24:
        raise Phase5DemoReleaseError("PROFILE_MEMBERSHIP_MISMATCH")
    if tuple(profile.profile_sha256 for profile in restored_profiles) != tuple(
        receipt.profile_sha256
    ):
        raise Phase5DemoReleaseError("PROFILE_RECEIPT_MISMATCH")
    _require_nondegenerate_profiles(restored_profiles)

    restored_attempts = _attempts_from_values(attempts)
    if not 24 <= len(restored_attempts) <= MAX_HTTP_ATTEMPTS:
        raise Phase5DemoReleaseError("ATTEMPT_COUNT_INVALID")
    if tuple(attempt.attempt_sha256 for attempt in restored_attempts) != tuple(
        receipt.attempt_sha256
    ):
        raise Phase5DemoReleaseError("ATTEMPT_RECEIPT_MISMATCH")
    expected_attempt_numbers = (
        tuple(range(1, 14)) + tuple(range(15, 26))
        if isinstance(receipt, NvidiaMinimaxProfileMaterializationReceipt)
        and receipt.resume_authority_sha256 == NVIDIA_SECOND_RESUME_AUTHORITY_SHA256
        else tuple(range(1, len(restored_attempts) + 1))
    )
    if tuple(attempt.attempt_number for attempt in restored_attempts) != expected_attempt_numbers:
        raise Phase5DemoReleaseError("ATTEMPT_ORDER_INVALID")
    if any(attempt.place_id not in expected for attempt in restored_attempts):
        raise Phase5DemoReleaseError("ATTEMPT_MEMBERSHIP_INVALID")

    response_attempts = {
        attempt.attempt_sha256: attempt
        for attempt in restored_attempts
        if attempt.response_sha256 is not None
    }
    if set(raw_responses) != set(response_attempts):
        raise Phase5DemoReleaseError("RAW_INVENTORY_MISMATCH")
    for digest, attempt in response_attempts.items():
        if hashlib.sha256(raw_responses[digest]).hexdigest() != attempt.response_sha256:
            raise Phase5DemoReleaseError("RAW_RESPONSE_DIGEST_MISMATCH")

    coding_receipt = (
        receipt if isinstance(receipt, CodingPlanProfileMaterializationReceipt) else None
    )
    nvidia_receipt = (
        receipt if isinstance(receipt, NvidiaMinimaxProfileMaterializationReceipt) else None
    )
    is_coding_plan = coding_receipt is not None
    is_nvidia = nvidia_receipt is not None
    if (
        nvidia_receipt is not None
        and nvidia_receipt.resume_authority_sha256 == NVIDIA_RESUME_AUTHORITY_SHA256
    ):
        raise Phase5DemoReleaseError("NVIDIA_RESUME_AUTHORITY_SUPERSEDED")
    if nvidia_receipt is not None and nvidia_receipt.resume_authority_sha256 in {
        NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
        NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
    }:
        raise Phase5DemoReleaseError("NVIDIA_V5_RETAINED_AUTHORITY_SUPERSEDED")
    committed = 0
    if is_coding_plan:
        assert coding_receipt is not None
        if not all(isinstance(attempt, CodingPlanProfileAttempt) for attempt in restored_attempts):
            raise Phase5DemoReleaseError("CODING_PLAN_ATTEMPT_CONTRACT_MISMATCH")
        for index, attempt in enumerate(restored_attempts, start=1):
            assert isinstance(attempt, CodingPlanProfileAttempt)
            if (
                attempt.endpoint != coding_receipt.endpoint
                or attempt.model != coding_receipt.model
                or attempt.entitlement_evidence_sha256 != coding_receipt.entitlement_evidence_sha256
                or attempt.model_weight != coding_receipt.model_weight
                or attempt.subscription_cumulative_weight != index * coding_receipt.model_weight
            ):
                raise Phase5DemoReleaseError("CODING_PLAN_ATTEMPT_ACCOUNTING_DRIFT")
        if (
            coding_receipt.subscription_attempt_count != len(restored_attempts)
            or coding_receipt.subscription_total_weight
            != len(restored_attempts) * CODING_PLAN_MODEL_WEIGHT
        ):
            raise Phase5DemoReleaseError("CODING_PLAN_RECEIPT_ACCOUNTING_DRIFT")
    elif is_nvidia:
        assert nvidia_receipt is not None
        if not all(
            isinstance(attempt, NvidiaMinimaxProfileAttempt) for attempt in restored_attempts
        ):
            raise Phase5DemoReleaseError("NVIDIA_ATTEMPT_CONTRACT_MISMATCH")
        for attempt in restored_attempts:
            assert isinstance(attempt, NvidiaMinimaxProfileAttempt)
            if (
                attempt.endpoint != nvidia_receipt.endpoint
                or attempt.model != nvidia_receipt.model
                or attempt.config_sha256 != nvidia_receipt.config_sha256
                or attempt.authority_sha256 != nvidia_receipt.authority_sha256
            ):
                raise Phase5DemoReleaseError("NVIDIA_ATTEMPT_AUTHORITY_DRIFT")
        if nvidia_receipt.http_attempt_count != len(restored_attempts):
            raise Phase5DemoReleaseError("NVIDIA_RECEIPT_ATTEMPT_DRIFT")
        if nvidia_receipt.resume_authority_sha256 == NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256:
            first = restored_attempts[0]
            assert isinstance(first, NvidiaMinimaxProfileAttempt)
            if (
                len(restored_attempts) != 25
                or first.attempt_number != 1
                or first.attempt_sha256 != NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256
                or first.place_id != expected[0]
                or first.outcome != "RESPONSE_INVALID"
                or first.retry
                or first.http_status != 200
                or first.request_sha256 != NVIDIA_V4_PROBE_RESUME_REQUEST_SHA256
                or first.response_sha256 != NVIDIA_V4_PROBE_RESUME_RESPONSE_SHA256
                or tuple(attempt.attempt_number for attempt in restored_attempts[1:])
                != tuple(range(2, 26))
                or tuple(attempt.place_id for attempt in restored_attempts[1:]) != expected
                or any(attempt.outcome != "VALIDATED" for attempt in restored_attempts[1:])
            ):
                raise Phase5DemoReleaseError("NVIDIA_V4_PROBE_RESUME_ATTEMPT_DRIFT")
        if nvidia_receipt.resume_authority_sha256 == NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256:
            first, second = restored_attempts[:2]
            assert isinstance(first, NvidiaMinimaxProfileAttempt)
            assert isinstance(second, NvidiaMinimaxProfileAttempt)
            if (
                len(restored_attempts) != 26
                or first.attempt_number != 1
                or first.attempt_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt1_attempt_sha256"]
                or first.place_id != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["probe_place_id"]
                or first.outcome != "RESPONSE_INVALID"
                or first.retry
                or first.http_status != 200
                or first.request_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt1_contract_request_sha256"]
                or first.response_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt1_response_sha256"]
                or second.attempt_number != 2
                or second.attempt_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt2_attempt_sha256"]
                or second.place_id != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["probe_place_id"]
                or second.outcome != "RESPONSE_INVALID"
                or second.retry
                or second.http_status != 200
                or second.request_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt2_contract_request_sha256"]
                or second.response_sha256
                != NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt2_response_sha256"]
                or tuple(attempt.attempt_number for attempt in restored_attempts[2:])
                != tuple(range(3, 27))
                or tuple(attempt.place_id for attempt in restored_attempts[2:]) != expected
                or any(attempt.outcome != "VALIDATED" for attempt in restored_attempts[2:])
            ):
                raise Phase5DemoReleaseError("NVIDIA_V5_TWO_PROBE_ATTEMPT_DRIFT")
    else:
        assert isinstance(receipt, DemoProfileMaterializationReceipt)
        if not all(isinstance(attempt, DemoProfileAttempt) for attempt in restored_attempts):
            raise Phase5DemoReleaseError("PAY_GO_ATTEMPT_CONTRACT_MISMATCH")
        pricing = PricingSnapshot()
        for attempt in restored_attempts:
            assert isinstance(attempt, DemoProfileAttempt)
            if attempt.reservation_micro_usd != ATTEMPT_RESERVATION_MICRO_USD:
                raise Phase5DemoReleaseError("RESERVATION_DRIFT")
            if attempt.outcome == "VALIDATED":
                if attempt.usage is None:
                    raise Phase5DemoReleaseError("VALID_USAGE_MISSING")
                expected_charge = pricing.charge(attempt.usage).total_micro_usd
                if (
                    attempt.committed_micro_usd != expected_charge
                    or attempt.refund_micro_usd != ATTEMPT_RESERVATION_MICRO_USD - expected_charge
                ):
                    raise Phase5DemoReleaseError("PRICING_RECONCILIATION_DRIFT")
            elif (
                attempt.committed_micro_usd != ATTEMPT_RESERVATION_MICRO_USD
                or attempt.refund_micro_usd != 0
            ):
                raise Phase5DemoReleaseError("CONSERVATIVE_CHARGE_DRIFT")
            committed += attempt.committed_micro_usd
            if committed > receipt.run_cost_cap_micro_usd:
                raise Phase5DemoReleaseError("COST_CAP_EXCEEDED")
            if attempt.remaining_cap_micro_usd != receipt.run_cost_cap_micro_usd - committed:
                raise Phase5DemoReleaseError("REMAINING_CAP_DRIFT")
        if committed != receipt.committed_cost_micro_usd:
            raise Phase5DemoReleaseError("RECEIPT_COST_DRIFT")

    latest: dict[
        str, DemoProfileAttempt | CodingPlanProfileAttempt | NvidiaMinimaxProfileAttempt
    ] = {}
    for attempt in restored_attempts:
        latest[attempt.place_id] = attempt
    if tuple(sorted(latest)) != expected or any(
        attempt.outcome != "VALIDATED" for attempt in latest.values()
    ):
        raise Phase5DemoReleaseError("TERMINAL_PROFILE_SET_INCOMPLETE")

    by_source = {bundle.place_id: bundle for bundle in sources}
    lineage_config: (
        DemoProfileMaterializationConfig
        | CodingPlanProfileMaterializationConfig
        | NvidiaMinimaxProfileMaterializationConfig
    )
    if is_coding_plan:
        lineage_config = CodingPlanProfileMaterializationConfig.for_authorized_base(
            base_url="https://api.z.ai/api/coding/paas/v4",
            entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        )
    elif is_nvidia:
        lineage_config = NvidiaMinimaxProfileMaterializationConfig()
    else:
        lineage_config = DemoProfileMaterializationConfig()
    for profile in restored_profiles:
        bundle = by_source[profile.place_id]
        known_evidence = tuple(source.evidence_id for source in bundle.sources)
        if is_nvidia:
            assert isinstance(lineage_config, NvidiaMinimaxProfileMaterializationConfig)
            assert nvidia_receipt is not None
            if nvidia_receipt.prompt_version == "phase5-demo-profile-sentinel-json.v5":
                if nvidia_receipt.resume_authority_sha256 is None:
                    raise Phase5DemoReleaseError("PROFILE_LINEAGE_DRIFT")
                lineage = _nvidia_v5_lineage_for(
                    bundle,
                    lineage_config,
                    resume_authority_sha256=nvidia_receipt.resume_authority_sha256,
                )
            else:
                lineage = _nvidia_lineage_for(bundle, lineage_config)
            try:
                restored_nvidia = NvidiaMinimaxModelDerivedProfile.model_validate(
                    profile.model_dump(mode="json"),
                    context={"known_evidence_ids": set(known_evidence)},
                )
            except ValidationError as error:
                raise Phase5DemoReleaseError("PROFILE_EVIDENCE_INVALID") from error
            latest_attempt = latest[profile.place_id]
            assert isinstance(latest_attempt, NvidiaMinimaxProfileAttempt)
            if (
                restored_nvidia.authority_sha256 != NVIDIA_AUTHORITY_SHA256
                or restored_nvidia.endpoint != NVIDIA_PROFILE_ENDPOINT
                or restored_nvidia.model != NVIDIA_PROFILE_MODEL
                or nvidia_receipt.prompt_sha256 != lineage["prompt_sha256"]
                or nvidia_receipt.profile_schema_sha256 != lineage["profile_schema_sha256"]
                or nvidia_receipt.config_sha256 != lineage["config_sha256"]
                or restored_nvidia.source_bundle_sha256 != lineage["source_bundle_sha256"]
                or restored_nvidia.evidence_inventory_sha256 != lineage["evidence_inventory_sha256"]
                or restored_nvidia.request_sha256 != lineage["request_sha256"]
                or restored_nvidia.prompt_sha256 != lineage["prompt_sha256"]
                or restored_nvidia.profile_schema_sha256 != lineage["profile_schema_sha256"]
                or restored_nvidia.config_sha256 != lineage["config_sha256"]
                or latest_attempt.request_sha256 != lineage["request_sha256"]
                or restored_nvidia.response_sha256 != latest_attempt.response_sha256
            ):
                raise Phase5DemoReleaseError("PROFILE_LINEAGE_DRIFT")
        else:
            assert isinstance(
                lineage_config,
                DemoProfileMaterializationConfig | CodingPlanProfileMaterializationConfig,
            )
            lineage = _lineage_for(bundle, lineage_config)
            try:
                restored_zai = DemoModelDerivedProfile.model_validate(
                    profile.model_dump(mode="json"),
                    context={"known_evidence_ids": set(known_evidence)},
                )
            except ValidationError as error:
                raise Phase5DemoReleaseError("PROFILE_EVIDENCE_INVALID") from error
            if (
                restored_zai.source_bundle_sha256 != lineage["source_bundle_sha256"]
                or restored_zai.evidence_inventory_sha256 != lineage["evidence_inventory_sha256"]
                or restored_zai.request_sha256 != lineage["request_sha256"]
                or restored_zai.prompt_sha256 != lineage["prompt_sha256"]
                or restored_zai.profile_schema_sha256 != lineage["profile_schema_sha256"]
                or restored_zai.config_sha256 != lineage["config_sha256"]
                or restored_zai.pricing_snapshot_sha256 != PRICING_SNAPSHOT_SHA256
                or restored_zai.response_sha256 != latest[profile.place_id].response_sha256
            ):
                raise Phase5DemoReleaseError("PROFILE_LINEAGE_DRIFT")

    if is_coding_plan:
        assert isinstance(receipt, CodingPlanProfileMaterializationReceipt)
        generation_fields = {
            "mode": "live",
            "profile_sha256": [profile.profile_sha256 for profile in restored_profiles],
            "attempt_sha256": [attempt.attempt_sha256 for attempt in restored_attempts],
            "provider_lane": receipt.provider_lane,
            "base_url": receipt.base_url,
            "endpoint": receipt.endpoint,
            "model": receipt.model,
            "accounting_mode": receipt.accounting_mode,
            "entitlement_evidence_sha256": receipt.entitlement_evidence_sha256,
            "model_weight": receipt.model_weight,
            "coding_plan_authority_sha256": receipt.coding_plan_authority_sha256,
        }
    elif is_nvidia:
        assert isinstance(receipt, NvidiaMinimaxProfileMaterializationReceipt)
        generation_fields = {
            "mode": "live",
            "profile_sha256": [profile.profile_sha256 for profile in restored_profiles],
            "attempt_sha256": [attempt.attempt_sha256 for attempt in restored_attempts],
            "provider_lane": receipt.provider_lane,
            "endpoint": receipt.endpoint,
            "model": receipt.model,
            "temperature": receipt.temperature,
            "top_p": receipt.top_p,
            "top_p_policy": receipt.top_p_policy,
            "max_tokens": receipt.max_tokens,
            "stream": receipt.stream,
            "seed": receipt.seed,
            "thinking_mode": receipt.thinking_mode,
            "output_contract": receipt.output_contract,
            "json_start_sentinel": receipt.json_start_sentinel,
            "json_end_sentinel": receipt.json_end_sentinel,
            "bounded_json_max_bytes": receipt.bounded_json_max_bytes,
            "sentinel_policy": receipt.sentinel_policy,
            "prompt_injection_policy": receipt.prompt_injection_policy,
            "response_format_policy": receipt.response_format_policy,
            "temperature_rationale": receipt.temperature_rationale,
            "thinking_mode_rationale": receipt.thinking_mode_rationale,
            "output_contract_rationale": receipt.output_contract_rationale,
            "config_sha256": receipt.config_sha256,
            "authority_sha256": receipt.authority_sha256,
            "prompt_version": receipt.prompt_version,
            "prompt_sha256": receipt.prompt_sha256,
            "profile_schema_sha256": receipt.profile_schema_sha256,
            "source_inventory_sha256": receipt.source_inventory_sha256,
            "resume_authority_sha256": receipt.resume_authority_sha256,
            "predecessor_manifest_sha256": receipt.predecessor_manifest_sha256,
            "validated_predecessor_count": receipt.validated_predecessor_count,
            "remaining_member_count": receipt.remaining_member_count,
            "validated_membership_sha256": receipt.validated_membership_sha256,
            "remaining_membership_sha256": receipt.remaining_membership_sha256,
        }
    else:
        assert isinstance(receipt, DemoProfileMaterializationReceipt)
        generation_fields = {
            "mode": "live",
            "profile_sha256": [profile.profile_sha256 for profile in restored_profiles],
            "attempt_sha256": [attempt.attempt_sha256 for attempt in restored_attempts],
            "pricing_snapshot_sha256": PRICING_SNAPSHOT_SHA256,
        }
        if receipt.rerun_authority_sha256 is not None:
            generation_fields["rerun_authority_sha256"] = receipt.rerun_authority_sha256
    if receipt.generation_sha256 != canonical_sha256(generation_fields):
        raise Phase5DemoReleaseError("GENERATION_DIGEST_DRIFT")
    membership_sha256 = canonical_sha256(list(expected))
    candidate_fields: dict[str, object] = {
        "schema_version": "itda.phase5-demo-release-candidate.v2",
        "state": "BUILT_UNACTIVATED",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "model": NVIDIA_PROFILE_MODEL if is_nvidia else "glm-5v-turbo",
        "prompt_version": (
            nvidia_receipt.prompt_version
            if nvidia_receipt is not None
            else "phase5-demo-profile.v1"
        ),
        "generation_sha256": receipt.generation_sha256,
        "generation_receipt_sha256": receipt.receipt_sha256,
        "membership_sha256": membership_sha256,
        "hard_duplicate_adjudication_sha256": adjudication.adjudication_sha256,
        "source_inventory_sha256": canonical_sha256(
            [bundle.source_bundle_sha256 for bundle in sources]
        ),
        "attempt_count": len(restored_attempts),
        "retry_count": len(restored_attempts) - 24,
        "profiles": [profile.model_dump(mode="json") for profile in restored_profiles],
    }
    if is_coding_plan:
        assert isinstance(receipt, CodingPlanProfileMaterializationReceipt)
        candidate_fields.update(
            {
                "schema_version": "itda.phase5-coding-plan-release-candidate.v2",
                "provider_lane": receipt.provider_lane,
                "endpoint": receipt.endpoint,
                "entitlement_evidence_sha256": receipt.entitlement_evidence_sha256,
                "coding_plan_authority_sha256": receipt.coding_plan_authority_sha256,
                "model_weight": receipt.model_weight,
                "subscription_total_weight": receipt.subscription_total_weight,
            }
        )
        return Phase5CodingPlanReleaseCandidate.model_validate(
            seal_demo_contract(candidate_fields, digest_field="release_sha256")
        )
    if is_nvidia:
        assert isinstance(receipt, NvidiaMinimaxProfileMaterializationReceipt)
        candidate_fields.update(
            {
                "schema_version": (
                    "itda.phase5-nvidia-minimax-release-candidate.v5"
                    if receipt.prompt_version == "phase5-demo-profile-sentinel-json.v5"
                    else "itda.phase5-nvidia-minimax-release-candidate.v4"
                ),
                "provider_lane": receipt.provider_lane,
                "endpoint": receipt.endpoint,
                "authority_sha256": receipt.authority_sha256,
                "config_sha256": receipt.config_sha256,
                "resume_authority_sha256": receipt.resume_authority_sha256,
                "predecessor_manifest_sha256": receipt.predecessor_manifest_sha256,
                "validated_membership_sha256": receipt.validated_membership_sha256,
                "remaining_membership_sha256": receipt.remaining_membership_sha256,
            }
        )
        return Phase5NvidiaMinimaxReleaseCandidate.model_validate(
            seal_demo_contract(candidate_fields, digest_field="release_sha256")
        )
    assert isinstance(receipt, DemoProfileMaterializationReceipt)
    candidate_fields.update(
        {
            "pricing_snapshot_sha256": PRICING_SNAPSHOT_SHA256,
            "committed_cost_micro_usd": committed,
            "rerun_authority_sha256": receipt.rerun_authority_sha256,
        }
    )
    return Phase5DemoReleaseCandidate.model_validate(
        seal_demo_contract(candidate_fields, digest_field="release_sha256")
    )


class Phase5DemoReleaseStore:
    """Private no-replace build store and atomic active pointer."""

    def __init__(
        self,
        *,
        root: Path = PRODUCTION_ROOT,
        expected_place_ids: Sequence[str] | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self._root = root.absolute()
        self._production_authority = expected_place_ids is None
        self._expected = _validate_expected_ids(
            _production_expected_ids() if expected_place_ids is None else expected_place_ids
        )
        self._test_place_names = (
            None
            if self._production_authority
            else {
                place_id: f"테스트 장소 {index:02d}"
                for index, place_id in enumerate(self._expected, start=1)
            }
        )
        self._fault_injector: Callable[[str], None] | None = fault_injector

    def _fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)

    def _generation_path(self, generation_sha256: str) -> Path:
        if len(generation_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in generation_sha256
        ):
            raise Phase5DemoReleaseError("GENERATION_ID_INVALID")
        return self._root / "generations" / generation_sha256

    def _recovery_candidate_path(self, release_sha256: str) -> Path:
        if len(release_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in release_sha256
        ):
            raise Phase5DemoReleaseError("CANDIDATE_ID_INVALID")
        return self._root / "candidates" / release_sha256 / "candidate.json"

    def _recovery_lifecycle_path(self) -> Path:
        return self._root / "lifecycle.json"

    def _recovery_parts(self, path: Path) -> tuple[str, ...]:
        try:
            relative = path.absolute().relative_to(self._root)
        except ValueError as error:
            raise Phase5DemoReleaseError("RECOVERY_PATH_FORBIDDEN") from error
        parts = relative.parts
        if not parts or any(not part or part in {".", ".."} or "/" in part for part in parts):
            raise Phase5DemoReleaseError("RECOVERY_PATH_INVALID")
        return parts

    def _write_recovery_record(self, path: Path, payload: bytes) -> None:
        """Publish an immutable record through pinned no-follow directory descriptors."""

        parts = self._recovery_parts(path)
        root_descriptor = _open_directory_chain(self._root)
        parent_descriptor = root_descriptor
        opened: list[int] = []
        try:
            for component in parts[:-1]:
                child = _open_or_create_directory(parent_descriptor, component)
                opened.append(child)
                parent_descriptor = child
            try:
                existing = _read_regular_at(
                    parent_descriptor,
                    parts[-1],
                    maximum_bytes=8 * 1024 * 1024,
                )
            except FileNotFoundError:
                _write_private_at(parent_descriptor, parts[-1], payload)
                os.fsync(parent_descriptor)
            else:
                if existing != payload:
                    raise Phase5DemoReleaseError("LIFECYCLE_NO_REPLACE_CONFLICT")
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)
            os.close(root_descriptor)

    def _recovery_candidate_from_generation(
        self,
        generation_sha256: str,
        *,
        scenario_results: Mapping[str, ActivationScenarioResult | Mapping[str, object]],
        contrast_results: object,
    ) -> Phase5RecoveryReleaseCandidate:
        legacy = self._load_generation(generation_sha256)
        if not isinstance(legacy, Phase5NvidiaMinimaxReleaseCandidate):
            raise Phase5DemoReleaseError("RECOVERY_NVIDIA_CANDIDATE_REQUIRED")
        scenarios, contrasts = _validate_recovery_maps(scenario_results, contrast_results)
        policy = CANONICAL_PHASE5_RECOVERY_POLICY
        candidate_ids = tuple(
            profile.place_id
            for profile in legacy.profiles
            if profile.confidence >= policy.candidate_confidence_min
        )
        adjudication = load_hard_duplicate_adjudication()
        groups = {adjudication.group_id_by_place[place_id] for place_id in candidate_ids}
        hard_representatives = tuple(
            next(
                place_id
                for place_id in candidate_ids
                if adjudication.group_id_by_place[place_id] == group_id
            )
            for group_id in sorted(groups)
        )
        from itda.domain.demo_profile_eligibility import _maximum_pairwise_compatible_capacity

        selected = list(
            _maximum_pairwise_compatible_capacity(
                hard_representatives,
                policy.cannot_coappear_authority,
            )
        )
        if len(selected) < policy.minimum_effective_candidate_count:
            raise Phase5DemoReleaseError("INSUFFICIENT_EFFECTIVE_CANDIDATES")
        post_hard_duplicate_count = len(hard_representatives)
        post_cannot_coappear_count = len(selected)
        fields: dict[str, object] = {
            "schema_version": "itda.phase5-recovery-release-candidate.v1",
            "state": "DRAFT_QUARANTINED",
            "analysis_origin": legacy.analysis_origin,
            "model": legacy.model,
            "prompt_version": legacy.prompt_version,
            "generation_sha256": legacy.generation_sha256,
            "generation_receipt_sha256": legacy.generation_receipt_sha256,
            "membership_sha256": legacy.membership_sha256,
            "hard_duplicate_adjudication_sha256": policy.hard_duplicate_adjudication_sha256,
            "cannot_coappear_authority_sha256": policy.cannot_coappear_authority.authority_sha256,
            "policy_sha256": policy.policy_sha256,
            "structural_profile_count": len(legacy.profiles),
            "candidate_profile_count": len(candidate_ids),
            "post_hard_duplicate_count": post_hard_duplicate_count,
            "post_cannot_coappear_count": post_cannot_coappear_count,
            "effective_candidate_count": len(selected),
            "confidence_is_ranking_input": False,
            "source_inventory_sha256": legacy.source_inventory_sha256,
            "config_sha256": legacy.config_sha256,
            "checkout_sha256": canonical_sha256({"generation_sha256": legacy.generation_sha256}),
            "kernel_sha256": canonical_sha256({"schema_version": "itda.phase5-recovery-kernel.v1"}),
            "activation_source_file_sha256": policy.activation_source_file_sha256,
            "activation_dataset_sha256": policy.activation_dataset_sha256,
            "activation_suite_sha256": policy.activation_suite_sha256,
            "scenario_results": {
                key: value.model_dump(mode="json") for key, value in scenarios.items()
            },
            "contrast_suite_sha256": policy.contrast_suite_sha256,
            "contrast_results": [value.model_dump(mode="json") for value in contrasts],
            "profiles": [profile.model_dump(mode="json") for profile in legacy.profiles],
        }
        candidate = Phase5RecoveryReleaseCandidate.model_validate(
            seal_demo_contract(fields, digest_field="release_sha256")
        )
        return candidate

    def build_recovery_candidate(
        self,
        generation_sha256: str,
        *,
        scenario_results: Mapping[str, ActivationScenarioResult | Mapping[str, object]],
        contrast_results: object,
    ) -> Phase5RecoveryReleaseCandidate:
        """Build one no-replace DRAFT_QUARANTINED candidate without promotion."""

        candidate = self._recovery_candidate_from_generation(
            generation_sha256,
            scenario_results=scenario_results,
            contrast_results=contrast_results,
        )
        existing_lifecycle = self._read_recovery_lifecycle()
        if existing_lifecycle is not None and (
            existing_lifecycle.candidate_sha256 != candidate.release_sha256
            or existing_lifecycle.state != "DRAFT_QUARANTINED"
        ):
            raise Phase5DemoReleaseError("CANDIDATE_LIFECYCLE_CONFLICT")
        destination = self._recovery_candidate_path(candidate.release_sha256)
        self._write_recovery_record(
            destination, canonical_json_bytes(candidate.model_dump(mode="json"))
        )
        lifecycle = Phase5ReleaseLifecycle.model_validate(
            seal_demo_contract(
                {
                    "schema_version": "itda.phase5-release-lifecycle.v1",
                    "candidate_sha256": candidate.release_sha256,
                    "state": "DRAFT_QUARANTINED",
                    "generation_sha256": candidate.generation_sha256,
                    "smoke_attestation_sha256": None,
                    "activation_intent_sha256": None,
                    "promotion_sha256": None,
                    "activation_attestation_sha256": None,
                    "invalidation_sha256": None,
                    "rollback_sha256": None,
                    "previous_release_sha256": None,
                    "expected_current_sha256": None,
                },
                digest_field="lifecycle_sha256",
            )
        )
        self._write_recovery_lifecycle(lifecycle)
        return candidate

    def resolve_candidate_private(self, release_sha256: str) -> Phase5RecoveryReleaseCandidate:
        """Resolve a quarantined candidate only after lifecycle identity checks."""

        lifecycle = self._read_recovery_lifecycle()
        if lifecycle is None or lifecycle.candidate_sha256 != release_sha256:
            raise Phase5DemoReleaseError("CANDIDATE_LIFECYCLE_UNAVAILABLE")
        try:
            candidate = self._read_recovery_candidate(release_sha256)
        except ValidationError as error:
            raise Phase5DemoReleaseError("CANDIDATE_CONTRACT_INVALID") from error
        if candidate.release_sha256 != release_sha256 or candidate.state != "DRAFT_QUARANTINED":
            raise Phase5DemoReleaseError("CANDIDATE_LIFECYCLE_INVALID")
        return candidate

    def read_recovery_lifecycle(self) -> Phase5ReleaseLifecycle:
        lifecycle = self._read_recovery_lifecycle()
        if lifecycle is None:
            raise Phase5DemoReleaseError("LIFECYCLE_UNAVAILABLE")
        return lifecycle

    def validate_candidate_smoke(
        self,
        release_sha256: str,
        smoke: Phase5CandidateSmokeAttestation,
    ) -> Phase5CandidateSmokeAttestation:
        candidate = self.resolve_candidate_private(release_sha256)
        if (
            smoke.candidate_sha256 != candidate.release_sha256
            or smoke.release_sha256 != candidate.release_sha256
        ):
            raise Phase5DemoReleaseError("SMOKE_CANDIDATE_MISMATCH")
        if (
            smoke.generation_sha256 != candidate.generation_sha256
            or smoke.policy_sha256 != candidate.policy_sha256
        ):
            raise Phase5DemoReleaseError("SMOKE_LINEAGE_MISMATCH")
        if smoke.membership_sha256 != candidate.membership_sha256:
            raise Phase5DemoReleaseError("SMOKE_MEMBERSHIP_MISMATCH")
        if (
            tuple(smoke.scenario_results) != CANONICAL_SCENARIO_IDS
            or tuple(row.pair for row in smoke.contrast_results) != CANONICAL_CONTRAST_PAIRS
        ):
            raise Phase5DemoReleaseError("SMOKE_MAP_INCOMPLETE")
        if (
            smoke.source_inventory_sha256 != candidate.source_inventory_sha256
            or smoke.config_sha256 != candidate.config_sha256
            or smoke.checkout_sha256 != candidate.checkout_sha256
            or smoke.kernel_sha256 != candidate.kernel_sha256
            or smoke.activation_source_file_sha256 != candidate.activation_source_file_sha256
            or smoke.activation_dataset_sha256 != candidate.activation_dataset_sha256
            or smoke.activation_suite_sha256 != candidate.activation_suite_sha256
            or smoke.contrast_suite_sha256 != candidate.contrast_suite_sha256
            or smoke.hard_duplicate_adjudication_sha256
            != candidate.hard_duplicate_adjudication_sha256
            or smoke.cannot_coappear_authority_sha256 != candidate.cannot_coappear_authority_sha256
        ):
            raise Phase5DemoReleaseError("SMOKE_PARENT_MISMATCH")
        for scenario_id, scenario in smoke.scenario_results.items():
            if candidate.scenario_results.get(scenario_id) != scenario:
                raise Phase5DemoReleaseError("SMOKE_SCENARIO_MISMATCH")
        if tuple(smoke.contrast_results) != tuple(candidate.contrast_results):
            raise Phase5DemoReleaseError("SMOKE_CONTRAST_MISMATCH")
        self._write_recovery_record(
            self._root / "smoke" / f"{smoke.smoke_attestation_sha256}.json",
            canonical_json_bytes(smoke.model_dump(mode="json")),
        )
        lifecycle_fields = {
            "schema_version": "itda.phase5-release-lifecycle.v1",
            "candidate_sha256": candidate.release_sha256,
            "state": "SMOKE_COMPLETE",
            "generation_sha256": candidate.generation_sha256,
            "smoke_attestation_sha256": smoke.smoke_attestation_sha256,
            "activation_intent_sha256": None,
            "promotion_sha256": None,
            "activation_attestation_sha256": None,
            "invalidation_sha256": None,
            "rollback_sha256": None,
            "previous_release_sha256": None,
            "expected_current_sha256": None,
        }
        lifecycle = Phase5ReleaseLifecycle.model_validate(
            seal_demo_contract(lifecycle_fields, digest_field="lifecycle_sha256")
        )
        self._write_recovery_lifecycle(lifecycle)
        return smoke

    def prepare_activation_intent(
        self,
        release_sha256: str,
        smoke: Phase5CandidateSmokeAttestation,
        *,
        expected_current_sha256: str | None,
    ) -> Phase5ActivationIntent:
        lifecycle = self.read_recovery_lifecycle()
        if (
            lifecycle.state != "SMOKE_COMPLETE"
            or lifecycle.smoke_attestation_sha256 != smoke.smoke_attestation_sha256
        ):
            raise Phase5DemoReleaseError("SMOKE_REQUIRED_BEFORE_INTENT")
        candidate = self.resolve_candidate_private(release_sha256)
        fields = {
            "schema_version": "itda.phase5-activation-intent.v1",
            "state": "PREPARED",
            "candidate_sha256": candidate.release_sha256,
            "smoke_attestation_sha256": smoke.smoke_attestation_sha256,
            "expected_current_sha256": expected_current_sha256,
            "policy_sha256": candidate.policy_sha256,
            "hard_duplicate_adjudication_sha256": candidate.hard_duplicate_adjudication_sha256,
            "cannot_coappear_authority_sha256": candidate.cannot_coappear_authority_sha256,
            "activation_suite_sha256": candidate.activation_suite_sha256,
            "contrast_suite_sha256": candidate.contrast_suite_sha256,
        }
        intent = Phase5ActivationIntent.model_validate(
            seal_demo_contract(fields, digest_field="intent_sha256")
        )
        self._write_recovery_record(
            self._root / "intents" / f"{intent.intent_sha256}.json",
            canonical_json_bytes(intent.model_dump(mode="json")),
        )
        lifecycle_fields = {
            "schema_version": "itda.phase5-release-lifecycle.v1",
            "candidate_sha256": candidate.release_sha256,
            "state": "PREPARED",
            "generation_sha256": candidate.generation_sha256,
            "smoke_attestation_sha256": smoke.smoke_attestation_sha256,
            "activation_intent_sha256": intent.intent_sha256,
            "promotion_sha256": None,
            "activation_attestation_sha256": None,
            "invalidation_sha256": None,
            "rollback_sha256": None,
            "previous_release_sha256": None,
            "expected_current_sha256": expected_current_sha256,
        }
        lifecycle = Phase5ReleaseLifecycle.model_validate(
            seal_demo_contract(lifecycle_fields, digest_field="lifecycle_sha256")
        )
        self._write_recovery_lifecycle(lifecycle)
        return intent

    def _write_recovery_lifecycle(self, lifecycle: Phase5ReleaseLifecycle) -> None:
        path = self._recovery_lifecycle_path()
        payload = canonical_json_bytes(lifecycle.model_dump(mode="json"))
        try:
            existing = self._read_recovery_record(path, maximum_bytes=256 * 1024)
        except FileNotFoundError:
            existing = None
        if existing == payload:
            return
        root_descriptor = _open_directory_chain(self._root)
        temporary_name: str | None = None
        try:
            temporary_name = _create_private_temporary_at(root_descriptor, payload)
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
            )
            temporary_name = None
            os.fsync(root_descriptor)
            reopened = Phase5ReleaseLifecycle.model_validate(
                json.loads(_read_regular_at(root_descriptor, path.name, maximum_bytes=256 * 1024))
            )
            if reopened != lifecycle:
                raise Phase5DemoReleaseError("LIFECYCLE_REOPEN_MISMATCH")
        finally:
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=root_descriptor)
            os.close(root_descriptor)
        self._fault("lifecycle_reopened")

    def _read_recovery_record(self, path: Path, *, maximum_bytes: int) -> bytes:
        parts = self._recovery_parts(path)
        root_descriptor = _open_directory_chain(self._root)
        parent_descriptor = root_descriptor
        opened: list[int] = []
        try:
            for component in parts[:-1]:
                child = _open_directory_beneath(parent_descriptor, (component,))
                opened.append(child)
                parent_descriptor = child
            return _read_regular_at(parent_descriptor, parts[-1], maximum_bytes=maximum_bytes)
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)
            os.close(root_descriptor)

    def _read_recovery_lifecycle(self) -> Phase5ReleaseLifecycle | None:
        try:
            return Phase5ReleaseLifecycle.model_validate_json(
                self._read_recovery_record(
                    self._recovery_lifecycle_path(),
                    maximum_bytes=256 * 1024,
                )
            )
        except FileNotFoundError:
            return None
        except ValidationError as error:
            raise Phase5DemoReleaseError("LIFECYCLE_INVALID") from error

    def _read_recovery_candidate(self, release_sha256: str) -> Phase5RecoveryReleaseCandidate:
        try:
            return Phase5RecoveryReleaseCandidate.model_validate_json(
                self._read_recovery_record(
                    self._recovery_candidate_path(release_sha256),
                    maximum_bytes=64 * 1024 * 1024,
                )
            )
        except FileNotFoundError:
            raise
        except ValidationError as error:
            raise Phase5DemoReleaseError("CANDIDATE_CONTRACT_INVALID") from error

    def _read_recovery_attestation(self, attestation_sha256: str) -> Phase5ActivationAttestation:
        try:
            return Phase5ActivationAttestation.model_validate_json(
                self._read_recovery_record(
                    self._root / "attestations" / f"{attestation_sha256}.json",
                    maximum_bytes=8 * 1024 * 1024,
                )
            )
        except FileNotFoundError:
            raise
        except ValidationError as error:
            raise Phase5DemoReleaseError("ATTESTATION_INVALID") from error

    def _write_recovery_pointer(self, pointer: Phase5RecoveryActivePointer) -> None:
        path = self._root / "recovery-active.json"
        payload = canonical_json_bytes(pointer.model_dump(mode="json"))
        root_descriptor = _open_directory_chain(self._root)
        temporary_name: str | None = None
        try:
            temporary_name = _create_private_temporary_at(root_descriptor, payload)
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
            )
            temporary_name = None
            os.fsync(root_descriptor)
            reopened = Phase5RecoveryActivePointer.model_validate_json(
                _read_regular_at(root_descriptor, path.name, maximum_bytes=256 * 1024)
            )
            if reopened != pointer:
                raise Phase5DemoReleaseError("RECOVERY_POINTER_REOPEN_MISMATCH")
        finally:
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=root_descriptor)
            os.close(root_descriptor)
        self._fault("pointer_reopened")

    def _read_recovery_pointer(self) -> Phase5RecoveryActivePointer | None:
        try:
            return Phase5RecoveryActivePointer.model_validate_json(
                self._read_recovery_record(
                    self._root / "recovery-active.json",
                    maximum_bytes=256 * 1024,
                )
            )
        except FileNotFoundError:
            return None
        except ValidationError as error:
            raise Phase5DemoReleaseError("RECOVERY_POINTER_INVALID") from error

    def _recovery_lifecycle_matches_pointer(self, lifecycle: Phase5ReleaseLifecycle) -> bool:
        pointer = self._read_recovery_pointer()
        if pointer is None:
            return False
        if pointer.active_release_sha256 != lifecycle.candidate_sha256:
            return False
        if pointer.promotion_sha256 != lifecycle.promotion_sha256:
            return False
        return pointer.activation_attestation_sha256 == lifecycle.activation_attestation_sha256

    def _invalidate_before_rollback(
        self,
        candidate: Phase5RecoveryReleaseCandidate,
        *,
        promotion_sha256: str | None,
        reason_code: str,
    ) -> Phase5InvalidationReceipt:
        invalidation = Phase5InvalidationReceipt.model_validate(
            seal_demo_contract(
                {
                    "schema_version": "itda.phase5-invalidation-receipt.v1",
                    "state": "INVALIDATED",
                    "candidate_sha256": candidate.release_sha256,
                    "promotion_sha256": promotion_sha256,
                    "reason_code": reason_code,
                },
                digest_field="invalidation_sha256",
            )
        )
        self._write_recovery_record(
            self._root / "invalidations" / f"{invalidation.invalidation_sha256}.json",
            canonical_json_bytes(invalidation.model_dump(mode="json")),
        )
        lifecycle = self.read_recovery_lifecycle()
        self._write_recovery_lifecycle(
            Phase5ReleaseLifecycle.model_validate(
                seal_demo_contract(
                    {
                        "schema_version": "itda.phase5-release-lifecycle.v1",
                        "candidate_sha256": candidate.release_sha256,
                        "state": "INVALIDATED",
                        "generation_sha256": candidate.generation_sha256,
                        "smoke_attestation_sha256": lifecycle.smoke_attestation_sha256,
                        "activation_intent_sha256": lifecycle.activation_intent_sha256,
                        "promotion_sha256": promotion_sha256,
                        "activation_attestation_sha256": None,
                        "invalidation_sha256": invalidation.invalidation_sha256,
                        "rollback_sha256": None,
                        "previous_release_sha256": lifecycle.previous_release_sha256,
                        "expected_current_sha256": lifecycle.expected_current_sha256,
                    },
                    digest_field="lifecycle_sha256",
                )
            )
        )
        self._fault("after_invalidation")
        return invalidation

    def promote(
        self,
        release_sha256: str,
        *,
        smoke_attestation_sha256: Phase5CandidateSmokeAttestation | str,
        activation_intent: Phase5ActivationIntent,
        expected_current_sha256: str | None,
        activation_attestation: Phase5ActivationAttestation | None = None,
    ) -> Phase5PromotionReceipt:
        candidate = self.resolve_candidate_private(release_sha256)
        lifecycle = self.read_recovery_lifecycle()
        smoke_digest = (
            smoke_attestation_sha256.smoke_attestation_sha256
            if isinstance(smoke_attestation_sha256, Phase5CandidateSmokeAttestation)
            else smoke_attestation_sha256
        )
        if (
            lifecycle.state != "PREPARED"
            or lifecycle.activation_intent_sha256 != activation_intent.intent_sha256
        ):
            raise Phase5DemoReleaseError("PREPARED_INTENT_REQUIRED")
        if lifecycle.smoke_attestation_sha256 != smoke_digest:
            raise Phase5DemoReleaseError("SMOKE_PROMOTION_MISMATCH")
        if expected_current_sha256 != activation_intent.expected_current_sha256:
            raise Phase5DemoReleaseError("EXPECTED_CURRENT_MISMATCH")
        self._fault("before_pointer")
        promotion = Phase5PromotionReceipt.model_validate(
            seal_demo_contract(
                {
                    "schema_version": "itda.phase5-promotion-receipt.v1",
                    "state": "PROMOTED",
                    "candidate_sha256": candidate.release_sha256,
                    "smoke_attestation_sha256": smoke_digest,
                    "activation_intent_sha256": activation_intent.intent_sha256,
                    "expected_current_sha256": expected_current_sha256,
                    "previous_release_sha256": expected_current_sha256,
                    "active_release_sha256": candidate.release_sha256,
                },
                digest_field="promotion_sha256",
            )
        )
        self._write_recovery_record(
            self._root / "promotions" / f"{promotion.promotion_sha256}.json",
            canonical_json_bytes(promotion.model_dump(mode="json")),
        )
        self._write_recovery_pointer(
            Phase5RecoveryActivePointer.model_validate(
                seal_demo_contract(
                    {
                        "schema_version": "itda.phase5-recovery-active-pointer.v1",
                        "state": "PROMOTED",
                        "active_release_sha256": candidate.release_sha256,
                        "previous_release_sha256": expected_current_sha256,
                        "expected_current_sha256": expected_current_sha256,
                        "promotion_sha256": promotion.promotion_sha256,
                        "activation_attestation_sha256": None,
                    },
                    digest_field="pointer_sha256",
                )
            )
        )
        try:
            self._fault("after_pointer")
            if activation_attestation is None:
                self._write_recovery_lifecycle(
                    Phase5ReleaseLifecycle.model_validate(
                        seal_demo_contract(
                            {
                                "schema_version": "itda.phase5-release-lifecycle.v1",
                                "candidate_sha256": candidate.release_sha256,
                                "state": "PROMOTED",
                                "generation_sha256": candidate.generation_sha256,
                                "smoke_attestation_sha256": smoke_digest,
                                "activation_intent_sha256": activation_intent.intent_sha256,
                                "promotion_sha256": promotion.promotion_sha256,
                                "activation_attestation_sha256": None,
                                "invalidation_sha256": None,
                                "rollback_sha256": None,
                                "previous_release_sha256": expected_current_sha256,
                                "expected_current_sha256": expected_current_sha256,
                            },
                            digest_field="lifecycle_sha256",
                        )
                    )
                )
                return promotion
            self._write_recovery_record(
                self._root / "attestations" / f"{activation_attestation.attestation_sha256}.json",
                canonical_json_bytes(activation_attestation.model_dump(mode="json")),
            )
            self._write_recovery_lifecycle(
                Phase5ReleaseLifecycle.model_validate(
                    seal_demo_contract(
                        {
                            "schema_version": "itda.phase5-release-lifecycle.v1",
                            "candidate_sha256": candidate.release_sha256,
                            "state": "ACTIVE",
                            "generation_sha256": candidate.generation_sha256,
                            "smoke_attestation_sha256": smoke_digest,
                            "activation_intent_sha256": activation_intent.intent_sha256,
                            "promotion_sha256": promotion.promotion_sha256,
                            "activation_attestation_sha256": (
                                activation_attestation.attestation_sha256
                            ),
                            "invalidation_sha256": None,
                            "rollback_sha256": None,
                            "previous_release_sha256": expected_current_sha256,
                            "expected_current_sha256": expected_current_sha256,
                        },
                        digest_field="lifecycle_sha256",
                    )
                )
            )
            self._write_recovery_pointer(
                Phase5RecoveryActivePointer.model_validate(
                    seal_demo_contract(
                        {
                            "schema_version": "itda.phase5-recovery-active-pointer.v1",
                            "state": "ACTIVE",
                            "active_release_sha256": candidate.release_sha256,
                            "previous_release_sha256": expected_current_sha256,
                            "expected_current_sha256": expected_current_sha256,
                            "promotion_sha256": promotion.promotion_sha256,
                            "activation_attestation_sha256": (
                                activation_attestation.attestation_sha256
                            ),
                        },
                        digest_field="pointer_sha256",
                    )
                )
            )
            self._fault("after_attestation")

            return promotion
        except BaseException as error:
            with suppress(BaseException):
                self._invalidate_before_rollback(
                    candidate,
                    promotion_sha256=promotion.promotion_sha256,
                    reason_code="POST_PROMOTION_FAILURE",
                )
            try:
                self._fault("before_rollback")
                rollback = Phase5RollbackReceipt.model_validate(
                    seal_demo_contract(
                        {
                            "schema_version": "itda.phase5-rollback-receipt.v1",
                            "state": "ROLLBACK_SUCCEEDED",
                            "candidate_sha256": candidate.release_sha256,
                            "previous_release_sha256": expected_current_sha256,
                            "active_release_sha256_before": candidate.release_sha256,
                            "error_code": None,
                        },
                        digest_field="rollback_sha256",
                    )
                )
            except BaseException as rollback_error:
                rollback = Phase5RollbackReceipt.model_validate(
                    seal_demo_contract(
                        {
                            "schema_version": "itda.phase5-rollback-receipt.v1",
                            "state": "ROLLBACK_FAILED",
                            "candidate_sha256": candidate.release_sha256,
                            "previous_release_sha256": expected_current_sha256,
                            "active_release_sha256_before": candidate.release_sha256,
                            "error_code": "ROLLBACK_FAILED",
                        },
                        digest_field="rollback_sha256",
                    )
                )
                del rollback_error
            self._write_recovery_record(
                self._root / "rollbacks" / f"{rollback.rollback_sha256}.json",
                canonical_json_bytes(rollback.model_dump(mode="json")),
            )
            raise Phase5DemoReleaseError("POST_PROMOTION_FAILURE") from error

    def require_invalidated_legacy_predecessor(self) -> dict[str, str]:
        """Verify the one revoked predecessor without treating it as an active release."""

        if not self._production_authority or self._root != PRODUCTION_ROOT:
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_ROOT_FORBIDDEN")

        pointer_payload = _read_regular(
            self._root / "active" / "current.json",
            maximum_bytes=64 * 1024,
        )
        if hashlib.sha256(pointer_payload).hexdigest() != (_INVALIDATED_LEGACY_POINTER_FILE_SHA256):
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_POINTER_DRIFT")
        try:
            pointer = json.loads(pointer_payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_POINTER_INVALID") from error
        if (
            not isinstance(pointer, dict)
            or pointer.get("schema_version") != "itda.phase5-demo-release-activation.v1"
            or pointer.get("state") != "ACTIVE"
            or pointer.get("active_release_sha256") != _INVALIDATED_LEGACY_RELEASE_SHA256
            or pointer.get("previous_release_sha256") is not None
            or pointer.get("expected_current_sha256") is not None
            or pointer.get("analysis_origin") != "DEMO_MODEL_DERIVED"
            or pointer.get("member_count") != 24
            or pointer.get("receipt_sha256") != _INVALIDATED_LEGACY_RECEIPT_SHA256
            or pointer.get("receipt_sha256")
            != canonical_sha256(
                {key: value for key, value in pointer.items() if key != "receipt_sha256"}
            )
        ):
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_POINTER_DRIFT")

        candidate_payload = _read_regular(
            self._root / "releases" / _INVALIDATED_LEGACY_RELEASE_SHA256 / "candidate.json",
            maximum_bytes=64 * 1024 * 1024,
        )
        if hashlib.sha256(candidate_payload).hexdigest() != (
            _INVALIDATED_LEGACY_CANDIDATE_FILE_SHA256
        ):
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_RELEASE_DRIFT")
        try:
            candidate = json.loads(candidate_payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_RELEASE_INVALID") from error
        if (
            not isinstance(candidate, dict)
            or candidate.get("schema_version") != "itda.phase5-nvidia-minimax-release-candidate.v3"
            or candidate.get("release_sha256") != _INVALIDATED_LEGACY_RELEASE_SHA256
            or candidate.get("generation_sha256") != _INVALIDATED_LEGACY_GENERATION_SHA256
            or candidate.get("analysis_origin") != "DEMO_MODEL_DERIVED"
            or candidate.get("membership_sha256")
            != "979127c3cfd457fa0a9354acf7fd984c8d8b4d753a97c7c176ac531e0808af7a"
            or candidate.get("prompt_version") != "phase5-demo-profile-sentinel-json.v3"
            or not isinstance(candidate.get("profiles"), list)
            or len(candidate["profiles"]) != 24
            or candidate.get("release_sha256")
            != canonical_sha256(
                {key: value for key, value in candidate.items() if key != "release_sha256"}
            )
        ):
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_RELEASE_DRIFT")

        generation_receipt_payload = _read_regular(
            self._root / "generations" / _INVALIDATED_LEGACY_GENERATION_SHA256 / "receipt.json",
            maximum_bytes=4 * 1024 * 1024,
        )
        if hashlib.sha256(generation_receipt_payload).hexdigest() != (
            _INVALIDATED_LEGACY_GENERATION_RECEIPT_FILE_SHA256
        ):
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_GENERATION_DRIFT")
        try:
            generation_receipt = json.loads(generation_receipt_payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_GENERATION_INVALID") from error
        if (
            not isinstance(generation_receipt, dict)
            or generation_receipt.get("schema_version")
            != "itda.nvidia-minimax-profile-materialization-receipt.v3"
            or generation_receipt.get("generation_sha256") != _INVALIDATED_LEGACY_GENERATION_SHA256
            or generation_receipt.get("prompt_version") != "phase5-demo-profile-sentinel-json.v3"
        ):
            raise Phase5DemoReleaseError("LEGACY_PREDECESSOR_GENERATION_DRIFT")

        return {
            "legacy_predecessor_release_sha256": _INVALIDATED_LEGACY_RELEASE_SHA256,
            "legacy_predecessor_receipt_sha256": _INVALIDATED_LEGACY_RECEIPT_SHA256,
            "legacy_predecessor_generation_sha256": _INVALIDATED_LEGACY_GENERATION_SHA256,
        }

    def _load_generation(
        self,
        generation_sha256: str,
        *,
        _adjudication: HardDuplicateAdjudication | None = None,
        _root_descriptor: int | None = None,
    ) -> (
        Phase5DemoReleaseCandidate
        | Phase5CodingPlanReleaseCandidate
        | Phase5NvidiaMinimaxReleaseCandidate
    ):
        generation = self._generation_path(generation_sha256)
        descriptor_raw_files: dict[str, bytes] | None = None
        if _root_descriptor is None:
            try:
                metadata = generation.lstat()
            except OSError as error:
                raise Phase5DemoReleaseError("GENERATION_UNAVAILABLE") from error
            if not stat.S_ISDIR(metadata.st_mode) or generation.is_symlink():
                raise Phase5DemoReleaseError("GENERATION_INVALID")
            receipt_value = _read_json(generation / "receipt.json")
        else:
            generation_descriptor = _open_directory_beneath(
                _root_descriptor,
                ("generations", generation_sha256),
            )
            try:
                receipt_value = json.loads(
                    _read_regular_at(
                        generation_descriptor,
                        "receipt.json",
                        maximum_bytes=64 * 1024 * 1024,
                    )
                )
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise Phase5DemoReleaseError("RESTRICTED_JSON_INVALID") from error
            finally:
                os.close(generation_descriptor)
        if (
            self._production_authority
            and isinstance(receipt_value, Mapping)
            and receipt_value.get("resume_authority_sha256")
            in {
                NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
                NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
                NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
            }
        ):
            raise Phase5DemoReleaseError("NVIDIA_V5_AUTHORITY_SUPERSEDED")
        if _root_descriptor is None:
            profiles_value = _read_json(generation / "profiles.json")
            attempts_value = _read_json(generation / "attempts.json")
            sources_value = _read_json(self._root / "source-bundles.json")
        else:
            generation_descriptor = _open_directory_beneath(
                _root_descriptor,
                ("generations", generation_sha256),
            )
            try:
                profiles_value = json.loads(
                    _read_regular_at(
                        generation_descriptor,
                        "profiles.json",
                        maximum_bytes=64 * 1024 * 1024,
                    )
                )
                attempts_value = json.loads(
                    _read_regular_at(
                        generation_descriptor,
                        "attempts.json",
                        maximum_bytes=64 * 1024 * 1024,
                    )
                )
                actual_names = set(os.listdir(generation_descriptor))
                descriptor_raw_files = {
                    name: _read_regular_at(
                        generation_descriptor,
                        name,
                        maximum_bytes=4 * 1024 * 1024,
                    )
                    for name in actual_names - _GENERATION_BASE_FILES
                }
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise Phase5DemoReleaseError("RESTRICTED_JSON_INVALID") from error
            finally:
                os.close(generation_descriptor)
            sources_value = _read_json_beneath(
                _root_descriptor,
                ("source-bundles.json",),
            )
        if not all(
            isinstance(value, list) for value in (profiles_value, attempts_value, sources_value)
        ):
            raise Phase5DemoReleaseError("GENERATION_INVENTORY_INVALID")

        def read_root_json(*components: str, maximum_bytes: int = 64 * 1024 * 1024) -> object:
            if _root_descriptor is None:
                return _read_json(
                    self._root.joinpath(*components),
                    maximum_bytes=maximum_bytes,
                )
            return _read_json_beneath(
                _root_descriptor,
                components,
                maximum_bytes=maximum_bytes,
            )

        try:
            receipt_schema = (
                receipt_value.get("schema_version") if isinstance(receipt_value, Mapping) else None
            )
            if receipt_schema == "itda.coding-plan-profile-materialization-receipt.v1":
                receipt: (
                    DemoProfileMaterializationReceipt
                    | CodingPlanProfileMaterializationReceipt
                    | NvidiaMinimaxProfileMaterializationReceipt
                ) = CodingPlanProfileMaterializationReceipt.model_validate(receipt_value)
            elif receipt_schema in {
                "itda.nvidia-minimax-profile-materialization-receipt.v3",
                "itda.nvidia-minimax-profile-materialization-receipt.v4",
            }:
                receipt = NvidiaMinimaxProfileMaterializationReceipt.model_validate(receipt_value)
            else:
                receipt = DemoProfileMaterializationReceipt.model_validate(receipt_value)
            source_rows = cast(list[object], sources_value)
            sources = tuple(DemoSourceBundle.model_validate(row) for row in source_rows)
            if self._production_authority:
                from itda.cli.collect_phase5_demo_sources import verify_source_collection

                sources = verify_source_collection(
                    self._root,
                    root_descriptor=_root_descriptor,
                )
                if isinstance(receipt, CodingPlanProfileMaterializationReceipt):
                    authority = read_root_json(
                        "coding-plan",
                        receipt.coding_plan_authority_sha256,
                        "authority.json",
                        maximum_bytes=2 * 1024 * 1024,
                    )
                    if not isinstance(authority, dict):
                        raise Phase5DemoReleaseError("CODING_PLAN_AUTHORITY_INVALID")
                    authority_fields = cast(dict[str, object], authority)
                    if (
                        receipt.coding_plan_authority_sha256 != CODING_PLAN_AUTHORITY_SHA256
                        or authority_fields.get("authority_sha256")
                        != receipt.coding_plan_authority_sha256
                        or authority_fields.get("receipt_sha256")
                        != canonical_sha256(
                            {
                                key: value
                                for key, value in authority_fields.items()
                                if key != "receipt_sha256"
                            }
                        )
                        or authority_fields.get("source_inventory_sha256")
                        != canonical_sha256([bundle.source_bundle_sha256 for bundle in sources])
                        or authority_fields.get("endpoint") != CODING_PLAN_ENDPOINT
                        or authority_fields.get("model") != "glm-5v-turbo"
                        or authority_fields.get("entitlement_evidence_sha256")
                        != CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
                        or authority_fields.get("entitlement_evidence_ref")
                        != _CODING_PLAN_EVIDENCE_REF
                        or authority_fields.get("model_weight") != CODING_PLAN_MODEL_WEIGHT
                        or authority_fields.get("prior_paygo_cumulative_upper_micro_usd")
                        != _PRIOR_PAYGO_CUMULATIVE_UPPER_MICRO_USD
                        or authority_fields.get("prior_paygo_blocker_sha256")
                        != _PRIOR_PAYGO_BLOCKER_SHA256
                    ):
                        raise Phase5DemoReleaseError("CODING_PLAN_AUTHORITY_DRIFT")
                elif isinstance(receipt, NvidiaMinimaxProfileMaterializationReceipt):
                    if receipt.resume_authority_sha256 == NVIDIA_RESUME_AUTHORITY_SHA256:
                        raise Phase5DemoReleaseError("NVIDIA_RESUME_AUTHORITY_SUPERSEDED")
                    authority = (
                        read_root_json(
                            "nvidia-resume",
                            receipt.resume_authority_sha256,
                            "authority.json",
                            maximum_bytes=2 * 1024 * 1024,
                        )
                        if receipt.resume_authority_sha256 is not None
                        else read_root_json(
                            "nvidia",
                            receipt.authority_sha256,
                            "authority.json",
                            maximum_bytes=2 * 1024 * 1024,
                        )
                    )
                    if not isinstance(authority, dict):
                        raise Phase5DemoReleaseError("NVIDIA_AUTHORITY_INVALID")
                    authority_fields = cast(dict[str, object], authority)
                    expected_v4_probe_authority: dict[str, object] | None = None
                    if receipt.resume_authority_sha256 == NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256:
                        try:
                            predecessor_attempt_root = (
                                f"attempts/01-{NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256}"
                            )
                            predecessor_files = (
                                _read_exact_tree_beneath(
                                    _root_descriptor,
                                    ("nvidia", NVIDIA_AUTHORITY_SHA256),
                                    {
                                        "authority.json",
                                        (
                                            "reservations/01-e705cd32db494530b4f66c0c1033f19a"
                                            "518fca99b2c49cb3e51533e76b305dfd/"
                                            "reservation.json"
                                        ),
                                        f"{predecessor_attempt_root}/attempt.json",
                                        f"{predecessor_attempt_root}/raw-response.bin",
                                        "terminal/terminal.json",
                                    },
                                    maximum_bytes=2 * 1024 * 1024,
                                )
                                if _root_descriptor is not None
                                else None
                            )
                            failure_files = (
                                _read_exact_tree_beneath(
                                    _root_descriptor,
                                    ("failures", NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256),
                                    {
                                        "attempts.json",
                                        "failure.json",
                                        (f"raw-{NVIDIA_V4_PROBE_RESUME_ATTEMPT_SHA256}.bin"),
                                    },
                                    maximum_bytes=1_048_576,
                                )
                                if _root_descriptor is not None
                                else None
                            )
                            v4_probe_plan = build_nvidia_v4_probe_resume_plan(
                                source_bundles=sources,
                                predecessor_root=self._root / "nvidia" / NVIDIA_AUTHORITY_SHA256,
                                failure_root=(
                                    self._root / "failures" / NVIDIA_V4_PROBE_RESUME_FAILURE_SHA256
                                ),
                                predecessor_files=predecessor_files,
                                failure_files=failure_files,
                            )
                            expected_v4_probe_authority = build_nvidia_v4_probe_resume_authority(
                                authority_text=NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT,
                                source_bundles=sources,
                                plan=v4_probe_plan,
                            )
                            expected_v4_probe_authority.update(
                                {
                                    "legacy_predecessor_release_sha256": (
                                        _INVALIDATED_LEGACY_RELEASE_SHA256
                                    ),
                                    "legacy_predecessor_receipt_sha256": (
                                        _INVALIDATED_LEGACY_RECEIPT_SHA256
                                    ),
                                    "legacy_predecessor_generation_sha256": (
                                        _INVALIDATED_LEGACY_GENERATION_SHA256
                                    ),
                                    "secret_present": True,
                                    "requires_explicit_future_authority": True,
                                    "future_live_command": (
                                        "ITDA_PROVIDER_NETWORK=1 PYTHONPATH=backend/src "
                                        "backend/.venv/bin/python -m "
                                        "itda.cli.materialize_phase5_demo_profiles "
                                        "nvidia-v4-probe-resume-live --json --authority-text "
                                        f"'{NVIDIA_V4_PROBE_RESUME_AUTHORITY_TEXT}' "
                                        "--secret-env-file .secrets/itda-api.env --artifact-root "
                                        "artifacts/restricted/catalog/"
                                        "phase5-demo-profile-materialization"
                                    ),
                                    "network_attempted": False,
                                }
                            )
                            expected_v4_probe_authority.pop("receipt_sha256", None)
                            expected_v4_probe_authority["receipt_sha256"] = canonical_sha256(
                                expected_v4_probe_authority
                            )
                        except (
                            DemoProfileMaterializationError,
                            PermissionError,
                            ValueError,
                        ) as error:
                            raise Phase5DemoReleaseError(
                                "NVIDIA_V4_PROBE_RESUME_EVIDENCE_INVALID"
                            ) from error
                    if (
                        receipt.authority_sha256 != NVIDIA_AUTHORITY_SHA256
                        or authority_fields.get("authority_sha256")
                        != (
                            receipt.resume_authority_sha256
                            if receipt.resume_authority_sha256 is not None
                            else receipt.authority_sha256
                        )
                        or authority_fields.get("receipt_sha256")
                        != canonical_sha256(
                            {
                                key: value
                                for key, value in authority_fields.items()
                                if key != "receipt_sha256"
                            }
                        )
                        or authority_fields.get("source_inventory_sha256")
                        != canonical_sha256([bundle.source_bundle_sha256 for bundle in sources])
                        or (
                            receipt.resume_authority_sha256 is None
                            and (
                                authority_fields.get("endpoint") != NVIDIA_PROFILE_ENDPOINT
                                or authority_fields.get("model") != NVIDIA_PROFILE_MODEL
                                or authority_fields.get("config_sha256") != receipt.config_sha256
                            )
                        )
                        or (
                            receipt.resume_authority_sha256 == NVIDIA_SECOND_RESUME_AUTHORITY_SHA256
                            and (
                                authority_fields.get("predecessor_authority_sha256")
                                != NVIDIA_RESUME_AUTHORITY_SHA256
                                or authority_fields.get("corrective_reconciliation_sha256")
                                != NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256
                                or receipt.predecessor_manifest_sha256
                                != NVIDIA_SECOND_RESUME_RECONCILIATION_SHA256
                                or authority_fields.get("validated_membership_sha256")
                                != NVIDIA_SECOND_RESUME_VALIDATED_MEMBERSHIP_SHA256
                                or authority_fields.get("validated_membership_sha256")
                                != receipt.validated_membership_sha256
                                or authority_fields.get("remaining_membership_sha256")
                                != NVIDIA_SECOND_RESUME_REMAINING_MEMBERSHIP_SHA256
                                or authority_fields.get("remaining_membership_sha256")
                                != receipt.remaining_membership_sha256
                                or authority_fields.get("consumed_predecessor_attempt_count") != 14
                                or authority_fields.get(
                                    "superseded_terminal_activation_authorizing"
                                )
                                is not False
                            )
                        )
                        or (
                            receipt.resume_authority_sha256
                            == NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256
                            and authority_fields != expected_v4_probe_authority
                        )
                        or (
                            receipt.resume_authority_sha256 is not None
                            and receipt.resume_authority_sha256
                            not in {
                                NVIDIA_SECOND_RESUME_AUTHORITY_SHA256,
                                NVIDIA_V4_PROBE_RESUME_AUTHORITY_SHA256,
                            }
                        )
                    ):
                        raise Phase5DemoReleaseError("NVIDIA_AUTHORITY_DRIFT")
                elif receipt.rerun_authority_sha256 is not None:
                    authority = read_root_json(
                        "reruns",
                        receipt.rerun_authority_sha256,
                        "authority.json",
                        maximum_bytes=2 * 1024 * 1024,
                    )
                    if not isinstance(authority, dict):
                        raise Phase5DemoReleaseError("RERUN_AUTHORITY_INVALID")
                    authority_fields = cast(dict[str, object], authority)
                    if (
                        receipt.rerun_authority_sha256 != RERUN_AUTHORITY_SHA256
                        or authority_fields.get("authority_sha256")
                        != receipt.rerun_authority_sha256
                        or authority_fields.get("receipt_sha256")
                        != canonical_sha256(
                            {
                                key: value
                                for key, value in authority_fields.items()
                                if key != "receipt_sha256"
                            }
                        )
                        or authority_fields.get("source_inventory_sha256")
                        != canonical_sha256([bundle.source_bundle_sha256 for bundle in sources])
                        or authority_fields.get("model") != "glm-5v-turbo"
                    ):
                        raise Phase5DemoReleaseError("RERUN_AUTHORITY_DRIFT")
            profile_rows = cast(list[object], profiles_value)
            source_by_id = {bundle.place_id: bundle for bundle in sources}
            profiles = tuple(
                (
                    NvidiaMinimaxModelDerivedProfile.model_validate(
                        row,
                        context={
                            "known_evidence_ids": {
                                source.evidence_id
                                for source in source_by_id[
                                    cast(dict[str, Any], row)["place_id"]
                                ].sources
                            }
                        },
                    )
                    if cast(dict[str, Any], row).get("schema_version")
                    in {
                        "itda.nvidia-minimax-model-derived-profile.v4",
                        "itda.nvidia-minimax-model-derived-profile.v5",
                    }
                    else DemoModelDerivedProfile.model_validate(
                        row,
                        context={
                            "known_evidence_ids": {
                                source.evidence_id
                                for source in source_by_id[
                                    cast(dict[str, Any], row)["place_id"]
                                ].sources
                            }
                        },
                    )
                )
                for row in profile_rows
            )
        except (KeyError, TypeError, ValidationError, ValueError) as error:
            raise Phase5DemoReleaseError("GENERATION_CONTRACT_INVALID") from error
        attempts_rows = cast(list[object], attempts_value)
        response_attempt_ids = {
            cast(dict[str, Any], row).get("attempt_sha256")
            for row in attempts_rows
            if cast(dict[str, Any], row).get("response_sha256") is not None
        }
        if descriptor_raw_files is None:
            actual_names = {child.name for child in generation.iterdir()}
        expected_names = _GENERATION_BASE_FILES | {
            f"raw-{attempt_sha256}.json" for attempt_sha256 in response_attempt_ids
        }
        if actual_names != expected_names:
            raise Phase5DemoReleaseError("RAW_INVENTORY_MISMATCH")
        raw_responses = (
            {
                str(attempt_sha256): _read_regular(
                    generation / f"raw-{attempt_sha256}.json",
                    maximum_bytes=4 * 1024 * 1024,
                )
                for attempt_sha256 in response_attempt_ids
            }
            if descriptor_raw_files is None
            else {
                str(attempt_sha256): descriptor_raw_files[f"raw-{attempt_sha256}.json"]
                for attempt_sha256 in response_attempt_ids
            }
        )
        if receipt.generation_sha256 != generation_sha256:
            raise Phase5DemoReleaseError("GENERATION_DIRECTORY_DRIFT")
        return validate_demo_scored_release(
            profiles=profiles,
            attempts=attempts_rows,
            receipt=receipt,
            source_bundles=sources,
            raw_responses=raw_responses,
            expected_place_ids=self._expected,
            _adjudication=_adjudication,
        )

    def build(
        self, generation_sha256: str
    ) -> (
        Phase5DemoReleaseCandidate
        | Phase5CodingPlanReleaseCandidate
        | Phase5NvidiaMinimaxReleaseCandidate
    ):
        _require_no_symlink_ancestors(self._root)
        candidate = self._load_generation(generation_sha256)
        intended = canonical_json_bytes(candidate.model_dump(mode="json"))
        releases = self._root / "releases"
        destination = releases / candidate.release_sha256
        root_descriptor = _open_directory_chain(self._root)
        try:
            releases_descriptor = _open_or_create_directory(root_descriptor, "releases")
            os.fchmod(releases_descriptor, 0o700)
        except BaseException:
            os.close(root_descriptor)
            raise
        staging_name = f".phase5-release-{uuid.uuid4().hex}"
        staging: Path | None = None
        staging_descriptor: int | None = None
        preserve_uncertain = False
        published = False
        try:
            try:
                existing_descriptor = os.open(
                    candidate.release_sha256,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=releases_descriptor,
                )
            except FileNotFoundError:
                existing_descriptor = None
            except OSError as error:
                raise Phase5DemoReleaseError("RELEASE_NO_REPLACE_CONFLICT") from error
            if existing_descriptor is not None:
                try:
                    if (
                        _read_regular_at(
                            existing_descriptor,
                            "candidate.json",
                            maximum_bytes=32 * 1024 * 1024,
                        )
                        != intended
                    ):
                        raise Phase5DemoReleaseError("RELEASE_NO_REPLACE_CONFLICT")
                finally:
                    os.close(existing_descriptor)
                _require_canonical_directory(
                    releases,
                    releases_descriptor,
                    error_code="RELEASE_PUBLICATION_UNCERTAIN",
                )
                verified = self.verify(candidate.release_sha256)
                _require_canonical_directory(
                    releases,
                    releases_descriptor,
                    error_code="RELEASE_PUBLICATION_UNCERTAIN",
                )
                return verified

            os.mkdir(staging_name, mode=0o700, dir_fd=releases_descriptor)
            staging = releases / staging_name
            staging_descriptor = os.open(
                staging_name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=releases_descriptor,
            )
            _write_private_at(staging_descriptor, "candidate.json", intended)
            os.fsync(staging_descriptor)
            try:
                with prepared_directory_snapshot(
                    staging,
                    parent_descriptor=releases_descriptor,
                ) as snapshot:
                    publish_immutable_directory(
                        prepared=staging,
                        output=destination,
                        snapshot=snapshot,
                        output_parent_descriptor=releases_descriptor,
                    )
                    published = True
            except FileExistsError:
                existing_descriptor = os.open(
                    candidate.release_sha256,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=releases_descriptor,
                )
                try:
                    if (
                        _read_regular_at(
                            existing_descriptor,
                            "candidate.json",
                            maximum_bytes=32 * 1024 * 1024,
                        )
                        != intended
                    ):
                        raise Phase5DemoReleaseError("RELEASE_NO_REPLACE_CONFLICT")
                finally:
                    os.close(existing_descriptor)
            except PublicationStateUncertainError as error:
                preserve_uncertain = True
                raise Phase5DemoReleaseError("RELEASE_PUBLICATION_UNCERTAIN") from error
            _require_canonical_directory(
                releases,
                releases_descriptor,
                error_code="RELEASE_PUBLICATION_UNCERTAIN",
            )
            destination_descriptor = os.open(
                candidate.release_sha256,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=releases_descriptor,
            )
            try:
                if (
                    _read_regular_at(
                        destination_descriptor,
                        "candidate.json",
                        maximum_bytes=32 * 1024 * 1024,
                    )
                    != intended
                ):
                    raise Phase5DemoReleaseError("RELEASE_NO_REPLACE_CONFLICT")
            finally:
                os.close(destination_descriptor)
            verified = self.verify(candidate.release_sha256)
            _require_canonical_directory(
                releases,
                releases_descriptor,
                error_code="RELEASE_PUBLICATION_UNCERTAIN",
            )
            return verified
        finally:
            if not preserve_uncertain and not published:
                if staging_descriptor is not None:
                    with suppress(FileNotFoundError):
                        os.unlink("candidate.json", dir_fd=staging_descriptor)
                with suppress(FileNotFoundError):
                    os.rmdir(staging_name, dir_fd=releases_descriptor)
            if staging_descriptor is not None:
                os.close(staging_descriptor)
            os.close(releases_descriptor)
            os.close(root_descriptor)

    def verify(
        self, release_sha256: str
    ) -> (
        Phase5DemoReleaseCandidate
        | Phase5CodingPlanReleaseCandidate
        | Phase5NvidiaMinimaxReleaseCandidate
    ):
        return self._verify(release_sha256, _adjudication=None)

    def _verify(
        self,
        release_sha256: str,
        *,
        _adjudication: HardDuplicateAdjudication | None = None,
        _root_descriptor: int | None = None,
    ) -> (
        Phase5DemoReleaseCandidate
        | Phase5CodingPlanReleaseCandidate
        | Phase5NvidiaMinimaxReleaseCandidate
    ):
        path = self._root / "releases" / release_sha256 / "candidate.json"
        try:
            raw_candidate = (
                _read_regular(path, maximum_bytes=32 * 1024 * 1024)
                if _root_descriptor is None
                else _read_regular_beneath(
                    _root_descriptor,
                    ("releases", release_sha256, "candidate.json"),
                    maximum_bytes=32 * 1024 * 1024,
                )
            )
            candidate_value = json.loads(raw_candidate)
            candidate_schema = (
                candidate_value.get("schema_version")
                if isinstance(candidate_value, Mapping)
                else None
            )
            if candidate_schema == "itda.phase5-coding-plan-release-candidate.v2":
                candidate: (
                    Phase5DemoReleaseCandidate
                    | Phase5CodingPlanReleaseCandidate
                    | Phase5NvidiaMinimaxReleaseCandidate
                ) = Phase5CodingPlanReleaseCandidate.model_validate(candidate_value)
            elif candidate_schema in {
                "itda.phase5-nvidia-minimax-release-candidate.v4",
                "itda.phase5-nvidia-minimax-release-candidate.v5",
            }:
                candidate = Phase5NvidiaMinimaxReleaseCandidate.model_validate(candidate_value)
            else:
                candidate = Phase5DemoReleaseCandidate.model_validate(candidate_value)
        except (json.JSONDecodeError, ValidationError) as error:
            raise Phase5DemoReleaseError("RELEASE_CANDIDATE_INVALID") from error
        if candidate.release_sha256 != release_sha256:
            raise Phase5DemoReleaseError("RELEASE_DIRECTORY_DRIFT")
        reconstructed = self._load_generation(
            candidate.generation_sha256,
            _adjudication=_adjudication,
            _root_descriptor=_root_descriptor,
        )
        if canonical_json_bytes(reconstructed.model_dump(mode="json")) != canonical_json_bytes(
            candidate.model_dump(mode="json")
        ):
            raise Phase5DemoReleaseError("RELEASE_REPLAY_DRIFT")
        replay = canonical_json_bytes(candidate.model_dump(mode="json"))
        if any(
            canonical_json_bytes(
                (
                    Phase5CodingPlanReleaseCandidate.model_validate_json(replay)
                    if isinstance(candidate, Phase5CodingPlanReleaseCandidate)
                    else Phase5NvidiaMinimaxReleaseCandidate.model_validate_json(replay)
                    if isinstance(candidate, Phase5NvidiaMinimaxReleaseCandidate)
                    else Phase5DemoReleaseCandidate.model_validate_json(replay)
                ).model_dump(mode="json")
            )
            != replay
            for _ in range(100)
        ):
            raise Phase5DemoReleaseError("RELEASE_REPLAY_UNSTABLE")
        return candidate

    def _read_active(self) -> Phase5DemoReleaseReceipt | None:
        pointer = self._root / "active" / "current.json"
        if not os.path.lexists(pointer):
            return None
        try:
            return Phase5DemoReleaseReceipt.model_validate_json(
                _read_regular(pointer, maximum_bytes=64 * 1024)
            )
        except ValidationError as error:
            raise Phase5DemoReleaseError("ACTIVE_POINTER_INVALID") from error

    def activate(
        self,
        release_sha256: str,
        *,
        expected_current_sha256: str | None,
    ) -> Phase5DemoReleaseReceipt:
        _require_no_symlink_ancestors(self._root)
        root_descriptor = _open_directory_chain(self._root)
        try:
            candidate = self._verify(
                release_sha256,
                _root_descriptor=root_descriptor,
            )
            _require_canonical_directory(
                self._root,
                root_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            if not isinstance(candidate, Phase5NvidiaMinimaxReleaseCandidate):
                raise Phase5DemoReleaseError("PROFILE_DIMENSION_EVIDENCE_UNSEALED")
            adjudication = load_hard_duplicate_adjudication()
            _require_canonical_directory(
                self._root,
                root_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            if (
                candidate.hard_duplicate_adjudication_sha256 != adjudication.adjudication_sha256
                or candidate.membership_sha256 != adjudication.dev_membership_sha256
                or tuple(profile.place_id for profile in candidate.profiles)
                != tuple(adjudication.group_id_by_place)
            ):
                raise Phase5DemoReleaseError("ACTIVE_HARD_DUPLICATE_ADJUDICATION_DRIFT")
        except BaseException:
            os.close(root_descriptor)
            raise
        try:
            active_descriptor = _open_or_create_directory(root_descriptor, "active")
        except BaseException:
            os.close(root_descriptor)
            raise
        try:
            receipts_descriptor = _open_or_create_directory(active_descriptor, "receipts")
        except BaseException:
            os.close(active_descriptor)
            os.close(root_descriptor)
            raise
        try:
            os.fchmod(active_descriptor, 0o700)
            os.fchmod(receipts_descriptor, 0o700)
            _require_canonical_directory(
                self._root,
                root_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            _require_canonical_directory(
                self._root / "active",
                active_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            _require_canonical_directory(
                self._root / "active" / "receipts",
                receipts_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
        except BaseException:
            os.close(receipts_descriptor)
            os.close(active_descriptor)
            os.close(root_descriptor)
            raise
        try:
            lock_descriptor = os.open(
                ".activation.lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=active_descriptor,
            )
            lock_metadata = os.fstat(lock_descriptor)
            if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_nlink != 1:
                raise Phase5DemoReleaseError("ACTIVATION_LOCK_INVALID")
            os.fchmod(lock_descriptor, 0o600)
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(active_descriptor)
        except BlockingIOError as error:
            os.close(lock_descriptor)
            os.close(receipts_descriptor)
            os.close(active_descriptor)
            os.close(root_descriptor)
            raise Phase5DemoReleaseError("ACTIVATION_BUSY") from error
        except BaseException:
            if "lock_descriptor" in locals():
                os.close(lock_descriptor)
            os.close(receipts_descriptor)
            os.close(active_descriptor)
            os.close(root_descriptor)
            raise
        try:
            try:
                current_raw = _read_regular_at(
                    active_descriptor,
                    "current.json",
                    maximum_bytes=64 * 1024,
                )
            except FileNotFoundError:
                current = None
            else:
                try:
                    current = Phase5DemoReleaseReceipt.model_validate_json(current_raw)
                except ValidationError as error:
                    raise Phase5DemoReleaseError("ACTIVE_POINTER_INVALID") from error
            current_sha256 = current.active_release_sha256 if current is not None else None
            if current_sha256 != expected_current_sha256:
                raise Phase5DemoReleaseError("EXPECTED_CURRENT_MISMATCH")
            fields: dict[str, object] = {
                "schema_version": "itda.phase5-demo-release-activation.v3",
                "state": "ACTIVE",
                "active_release_sha256": candidate.release_sha256,
                "previous_release_sha256": current_sha256,
                "expected_current_sha256": expected_current_sha256,
                "membership_sha256": candidate.membership_sha256,
                "hard_duplicate_adjudication_sha256": (
                    candidate.hard_duplicate_adjudication_sha256
                ),
                "hard_duplicate_adjudication": adjudication.model_dump(mode="json"),
                "analysis_origin": "DEMO_MODEL_DERIVED",
                "member_count": 24,
            }
            receipt = Phase5DemoReleaseReceipt.model_validate(
                seal_demo_contract(fields, digest_field="receipt_sha256")
            )
            receipt_bytes = canonical_json_bytes(receipt.model_dump(mode="json"))
            receipt_name = f"{receipt.receipt_sha256}.json"
            _require_canonical_directory(
                self._root,
                root_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            _require_canonical_directory(
                self._root / "active",
                active_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            _require_canonical_directory(
                self._root / "active" / "receipts",
                receipts_descriptor,
                error_code="ACTIVATION_PATH_DRIFT",
            )
            try:
                existing_receipt = _read_regular_at(
                    receipts_descriptor,
                    receipt_name,
                    maximum_bytes=64 * 1024,
                )
            except FileNotFoundError:
                _write_private_at(receipts_descriptor, receipt_name, receipt_bytes)
            else:
                if existing_receipt != receipt_bytes:
                    raise Phase5DemoReleaseError("ACTIVATION_RECEIPT_CONFLICT")
            os.fsync(receipts_descriptor)
            temporary_name = _create_private_temporary_at(active_descriptor, receipt_bytes)
            try:
                os.replace(
                    temporary_name,
                    "current.json",
                    src_dir_fd=active_descriptor,
                    dst_dir_fd=active_descriptor,
                )
                try:
                    os.fsync(active_descriptor)
                    try:
                        _require_canonical_directory(
                            self._root,
                            root_descriptor,
                            error_code="ACTIVATION_COMMIT_UNCERTAIN",
                        )
                        _require_canonical_directory(
                            self._root / "active",
                            active_descriptor,
                            error_code="ACTIVATION_COMMIT_UNCERTAIN",
                        )
                        _require_canonical_directory(
                            self._root / "active" / "receipts",
                            receipts_descriptor,
                            error_code="ACTIVATION_COMMIT_UNCERTAIN",
                        )
                    except Phase5DemoReleaseError as drift_error:
                        raise drift_error
                    verified_raw = _read_regular_at(
                        active_descriptor,
                        "current.json",
                        maximum_bytes=64 * 1024,
                    )
                    try:
                        verified = Phase5DemoReleaseReceipt.model_validate_json(verified_raw)
                    except ValidationError as error:
                        raise Phase5DemoReleaseError(
                            "ACTIVE_POINTER_RECONCILIATION_FAILED"
                        ) from error
                    if verified != receipt:
                        raise Phase5DemoReleaseError("ACTIVE_POINTER_RECONCILIATION_FAILED")
                except Exception as error:
                    if (
                        isinstance(error, Phase5DemoReleaseError)
                        and str(error) == "ACTIVATION_COMMIT_UNCERTAIN"
                    ):
                        raise
                    raise Phase5DemoReleaseError("ACTIVATION_COMMIT_UNCERTAIN") from error
            finally:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=active_descriptor)
            return receipt
        finally:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)
            os.close(receipts_descriptor)
            os.close(active_descriptor)
            os.close(root_descriptor)

    def resolve_active(self) -> PublicScoredReleaseSnapshot | None:
        lifecycle = self._read_recovery_lifecycle()
        if lifecycle is not None and lifecycle.state != "ACTIVE":
            return None
        active = self._read_active()
        if active is None:
            return None
        if lifecycle is not None and lifecycle.candidate_sha256 != active.active_release_sha256:
            return None
        if lifecycle is not None and lifecycle.activation_attestation_sha256 is None:
            return None
        if lifecycle is not None:
            try:
                Phase5ActivationAttestation.model_validate_json(
                    self._read_recovery_record(
                        self._root
                        / "attestations"
                        / f"{lifecycle.activation_attestation_sha256}.json",
                        maximum_bytes=8 * 1024 * 1024,
                    )
                )
            except (FileNotFoundError, ValidationError, Phase5DemoReleaseError):
                return None
        candidate = self._verify(
            active.active_release_sha256,
            _adjudication=active.hard_duplicate_adjudication,
        )
        _require_nondegenerate_profiles(candidate.profiles)
        if candidate.membership_sha256 != active.membership_sha256:
            raise Phase5DemoReleaseError("ACTIVE_MEMBERSHIP_DRIFT")
        adjudication = active.hard_duplicate_adjudication
        if (
            candidate.hard_duplicate_adjudication_sha256
            != active.hard_duplicate_adjudication_sha256
            or active.hard_duplicate_adjudication_sha256 != adjudication.adjudication_sha256
            or tuple(adjudication.group_id_by_place)
            != tuple(profile.place_id for profile in candidate.profiles)
        ):
            raise Phase5DemoReleaseError("ACTIVE_HARD_DUPLICATE_ADJUDICATION_DRIFT")
        sources_value = _read_json(self._root / "source-bundles.json")
        if not isinstance(sources_value, list):
            raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_INVENTORY_INVALID")
        try:
            sources = validate_demo_source_inventory(
                tuple(DemoSourceBundle.model_validate(item) for item in sources_value)
            )
        except (ValidationError, ValueError) as error:
            raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_INVENTORY_INVALID") from error
        if self._production_authority:
            from itda.cli.collect_phase5_demo_sources import verify_source_collection

            sources = verify_source_collection(self._root)
            authority_value = _read_json(self._root / "source-authority.json")
            if not isinstance(authority_value, dict):
                raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_AUTHORITY_INVALID")
            source_authority_sha256 = authority_value.get("authority_sha256")
            if not isinstance(source_authority_sha256, str):
                raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_AUTHORITY_INVALID")
        else:
            source_authority_sha256 = canonical_sha256(
                {
                    "schema_version": "itda.synthetic-public-evidence-authority.v1",
                    "source_inventory_sha256": candidate.source_inventory_sha256,
                }
            )
        if canonical_sha256(
            [bundle.source_bundle_sha256 for bundle in sources]
        ) != candidate.source_inventory_sha256 or tuple(
            bundle.place_id for bundle in sources
        ) != tuple(profile.place_id for profile in candidate.profiles):
            raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_RELEASE_DRIFT")
        contest_rights_root_sha256 = _verified_contest_rights_root()
        sources_by_place = {bundle.place_id: bundle for bundle in sources}
        names = (
            _canonical_place_names() if self._test_place_names is None else self._test_place_names
        )
        projections: list[dict[str, object]] = []
        for profile in candidate.profiles:
            try:
                place_name_ko = names[profile.place_id]
            except KeyError as error:
                raise Phase5DemoReleaseError("ACTIVE_PLACE_NAME_MISSING") from error
            source_bundle = sources_by_place[profile.place_id]
            if tuple(source.evidence_id for source in source_bundle.sources) != tuple(
                profile.evidence_ids
            ):
                raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_PROFILE_DRIFT")
            evidence_excerpts: list[dict[str, object]] = []
            for source in source_bundle.sources:
                if hashlib.sha256(
                    source.text.encode("utf-8")
                ).hexdigest() != source.span_sha256 or (
                    self._production_authority and source.source_kind != "TOUR_API_DESCRIPTION"
                ):
                    raise Phase5DemoReleaseError("PUBLIC_EVIDENCE_SOURCE_UNQUALIFIED")
                excerpt_ko = _bounded_public_excerpt(source.text)
                is_tour_api = source.source_kind == "TOUR_API_DESCRIPTION"
                evidence_excerpts.append(
                    {
                        "evidence_id": source.evidence_id,
                        "source_kind": source.source_kind,
                        "source_label_ko": (
                            "한국관광공사 TourAPI 공식 관광정보"
                            if is_tour_api
                            else "합성 검증용 Odii 해설 근거"
                        ),
                        "attribution_ko": (
                            "출처: 한국관광공사 TourAPI (공공데이터포털 데이터셋 15101578)"
                            if is_tour_api
                            else "출처: 합성 검증 픽스처"
                        ),
                        "provider": "TOUR_API" if is_tour_api else "SYNTHETIC_TEST_ONLY",
                        "official_dataset_id": (
                            "15101578" if is_tour_api else "SYNTHETIC_TEST_ONLY"
                        ),
                        "endpoint": (
                            "KorService2/detailCommon2" if is_tour_api else "SYNTHETIC_TEST_ONLY"
                        ),
                        "contest_use_scope": "noncommercial_contest_demo_evaluation",
                        "contest_rights_qualified": True,
                        "commercial_production_rights_review_required": True,
                        "excerpt_ko": excerpt_ko,
                        "excerpt_sha256": hashlib.sha256(excerpt_ko.encode("utf-8")).hexdigest(),
                        "source_sha256": source.source_sha256,
                        "span_sha256": source.span_sha256,
                        "source_authority_sha256": source_authority_sha256,
                        "contest_rights_root_sha256": contest_rights_root_sha256,
                    }
                )
            publication_state, _ = classify_publication(profile.confidence)
            fields: dict[str, object] = {
                "place_id": profile.place_id,
                "place_name_ko": place_name_ko,
                "duplicate_group_id": adjudication.group_id_by_place[profile.place_id],
                "axis_scores": profile.axis_scores,
                "subattributes": profile.subattributes,
                "mismatch_traits": profile.mismatch_traits,
                "evidence_ids": list(profile.evidence_ids),
                "evidence_justifications": (
                    profile.evidence_justifications
                    if isinstance(profile, NvidiaMinimaxModelDerivedProfile)
                    else None
                ),
                "evidence_excerpts": evidence_excerpts,
                "confidence": profile.confidence,
                "publishable": True,
                "publication_state": publication_state,
                "recommendation_eligible": publication_state.value == "PUBLISHABLE",
                "analysis_origin": "DEMO_MODEL_DERIVED",
                "model": profile.model,
                "prompt_version": profile.prompt_version,
                "profile_sha256": profile.profile_sha256,
                "source_bundle_sha256": profile.source_bundle_sha256,
                "evidence_inventory_sha256": profile.evidence_inventory_sha256,
                "response_sha256": profile.response_sha256,
                "created_at": profile.created_at.isoformat().replace("+00:00", "Z"),
            }
            projections.append(seal_demo_contract(fields, digest_field="projection_sha256"))
        snapshot_fields: dict[str, object] = {
            "schema_version": (
                "itda.public-scored-release-snapshot.v5"
                if candidate.prompt_version == "phase5-demo-profile-sentinel-json.v5"
                else "itda.public-scored-release-snapshot.v4"
            ),
            "state": "ACTIVE",
            "analysis_origin": "DEMO_MODEL_DERIVED",
            "model": candidate.model,
            "prompt_version": candidate.prompt_version,
            "release_sha256": candidate.release_sha256,
            "membership_sha256": candidate.membership_sha256,
            "hard_duplicate_adjudication_sha256": adjudication.adjudication_sha256,
            "hard_duplicate_adjudication": adjudication.model_dump(mode="json"),
            "profiles": projections,
        }
        return PublicScoredReleaseSnapshot.model_validate(
            seal_demo_contract(snapshot_fields, digest_field="snapshot_sha256")
        )

    def status(self) -> dict[str, object]:
        active = self._read_active()
        if active is None:
            return {
                "state": "NO_ACTIVE_SCORED_RELEASE",
                "member_count": 0,
                "analysis_origin": None,
                "active_release_sha256": None,
            }
        candidate = self.verify(active.active_release_sha256)
        payload: dict[str, object] = {
            "state": "ACTIVE",
            "member_count": 24,
            "analysis_origin": candidate.analysis_origin,
            "active_release_sha256": candidate.release_sha256,
            "membership_sha256": candidate.membership_sha256,
            "hard_duplicate_adjudication_sha256": (candidate.hard_duplicate_adjudication_sha256),
            "generation_sha256": candidate.generation_sha256,
            "generation_receipt_sha256": candidate.generation_receipt_sha256,
            "attempt_count": candidate.attempt_count,
            "retry_count": candidate.retry_count,
            "model": candidate.model,
            "prompt_version": candidate.prompt_version,
        }
        if isinstance(candidate, Phase5CodingPlanReleaseCandidate):
            payload.update(
                {
                    "provider_lane": candidate.provider_lane,
                    "accounting_mode": "CODING_PLAN_WEIGHT",
                    "model_weight": candidate.model_weight,
                    "subscription_total_weight": candidate.subscription_total_weight,
                }
            )
        elif isinstance(candidate, Phase5NvidiaMinimaxReleaseCandidate):
            payload.update(
                {
                    "provider_lane": candidate.provider_lane,
                    "endpoint": candidate.endpoint,
                    "authority_sha256": candidate.authority_sha256,
                    "config_sha256": candidate.config_sha256,
                }
            )
        else:
            payload.update(
                {
                    "pricing_snapshot_sha256": candidate.pricing_snapshot_sha256,
                    "committed_cost_micro_usd": candidate.committed_cost_micro_usd,
                }
            )
        return payload


def resolve_active_public_scored_release() -> PublicScoredReleaseSnapshot | None:
    """Resolve only the repository-fixed release; any drift is unavailable publicly."""

    try:
        return Phase5DemoReleaseStore().resolve_active()
    except (OSError, Phase5DemoReleaseError, ValidationError, ValueError):
        return None


__all__ = [
    "Phase5DemoReleaseError",
    "Phase5DemoReleaseStore",
    "resolve_active_public_scored_release",
    "validate_demo_scored_release",
]
