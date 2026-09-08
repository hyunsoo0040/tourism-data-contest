"""Rights-bound, descriptor-stable reads for approved image materializations."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from itda.domain.canonical import canonical_sha256

O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

_SAFE_ERROR = "approved image read failed"
_DEFAULT_FORBIDDEN_MODE_BITS = 0o022 | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


class SecureImageReadError(ValueError):
    """One externally safe failure for every rejected image read."""


def _current_owner_uids() -> tuple[int, ...]:
    getter = getattr(os, "geteuid", None)
    if getter is None:
        return ()
    return (getter(),)


def _require_sha256(value: str, *, field_name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _normalized_parts(relative_path: str) -> tuple[str, ...]:
    path = PurePosixPath(relative_path)
    normalized = path.as_posix()
    if (
        not relative_path
        or relative_path != normalized
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in relative_path
        or "\x00" in relative_path
    ):
        raise ValueError("image path must be a safe normalized relative path")
    return path.parts


@dataclass(frozen=True, slots=True)
class ApprovedImageMaterialization:
    """Independent authority binding one Phase 2 rights leaf to exact local bytes.

    Phase 2's provider-response digest is deliberately not accepted as an image
    content digest. The caller must supply a separately approved materialization
    whose self-digest covers the rights-leaf identity and the actual image bytes.
    """

    rights_leaf_id: str
    rights_leaf_sha256: str
    content_sha256: str
    materialization_sha256: str | None = None

    def __post_init__(self) -> None:
        if not 0 < len(self.rights_leaf_id) <= 300:
            raise ValueError("rights leaf ID is invalid")
        _require_sha256(self.rights_leaf_sha256, field_name="rights leaf digest")
        _require_sha256(self.content_sha256, field_name="content digest")
        expected = canonical_sha256(
            {
                "rights_leaf_id": self.rights_leaf_id,
                "rights_leaf_sha256": self.rights_leaf_sha256,
                "content_sha256": self.content_sha256,
            }
        )
        if self.materialization_sha256 is None:
            object.__setattr__(self, "materialization_sha256", expected)
        elif not hmac.compare_digest(self.materialization_sha256, expected):
            raise ValueError("approved image materialization digest is stale")


@dataclass(frozen=True, slots=True)
class RightsBoundImage:
    """Candidate-local copy of the exact authority triple plus a safe path."""

    relative_path: str
    rights_leaf_id: str
    rights_leaf_sha256: str
    content_sha256: str

    def __post_init__(self) -> None:
        _normalized_parts(self.relative_path)
        if not 0 < len(self.rights_leaf_id) <= 300:
            raise ValueError("rights leaf ID is invalid")
        _require_sha256(self.rights_leaf_sha256, field_name="rights leaf digest")
        _require_sha256(self.content_sha256, field_name="content digest")


@dataclass(frozen=True, slots=True)
class SecureReadPolicy:
    """Bounded regular-file owner/mode policy for one descriptor read."""

    max_bytes: int = 16 * 1024 * 1024
    chunk_size: int = 64 * 1024
    allowed_owner_uids: tuple[int, ...] = field(default_factory=_current_owner_uids)
    forbidden_mode_bits: int = _DEFAULT_FORBIDDEN_MODE_BITS

    def __post_init__(self) -> None:
        if self.max_bytes <= 0 or self.chunk_size <= 0:
            raise ValueError("secure read byte bounds are invalid")
        if not self.allowed_owner_uids:
            raise ValueError("secure read requires an explicit allowed owner")
        if (
            any(owner < 0 for owner in self.allowed_owner_uids)
            or len(set(self.allowed_owner_uids)) != len(self.allowed_owner_uids)
            or tuple(sorted(self.allowed_owner_uids)) != self.allowed_owner_uids
        ):
            raise ValueError("secure read owners must be unique and sorted")
        if self.forbidden_mode_bits < 0:
            raise ValueError("forbidden mode bits are invalid")


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """The exact before/after descriptor tuple required by the plan."""

    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> FileIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
        )

    def as_payload(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
        }


@dataclass(frozen=True, slots=True)
class VerifiedImageRead:
    """Short-lived verified raw buffer; callers must wipe it after projection."""

    payload: bytearray = field(repr=False)
    content_sha256: str
    identity: FileIdentity

    def close(self) -> None:
        """Destroy the protected source buffer immediately."""

        _wipe(self.payload)

    def __enter__(self) -> VerifiedImageRead:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _require_secure_capabilities() -> None:
    if not O_DIRECTORY or not O_NONBLOCK or not O_NOFOLLOW or not O_CLOEXEC:
        raise OSError("secure file flags unavailable")
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise OSError("descriptor-relative file operations unavailable")


def _bind_authority(
    candidate: RightsBoundImage,
    approved: ApprovedImageMaterialization,
) -> None:
    matches = (
        hmac.compare_digest(candidate.rights_leaf_id, approved.rights_leaf_id),
        hmac.compare_digest(candidate.rights_leaf_sha256, approved.rights_leaf_sha256),
        hmac.compare_digest(candidate.content_sha256, approved.content_sha256),
    )
    if not all(matches):
        raise ValueError("image materialization authority mismatch")


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(value.st_mode):
        raise OSError("path component is not a directory")
    return (value.st_dev, value.st_ino)


def _open_parent_chain(
    root_fd: int,
    directory_parts: tuple[str, ...],
) -> tuple[int, tuple[tuple[int, int], ...]]:
    current = os.dup(root_fd)
    identities: list[tuple[int, int]] = []
    try:
        identities.append(_directory_identity(os.fstat(current)))
        flags = os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        for part in directory_parts:
            following = os.open(part, flags, dir_fd=current)
            try:
                identities.append(_directory_identity(os.fstat(following)))
            except Exception:
                os.close(following)
                raise
            os.close(current)
            current = following
        return current, tuple(identities)
    except Exception:
        os.close(current)
        raise


def _full_file_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _validate_file_state(value: os.stat_result, policy: SecureReadPolicy) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or not 0 < value.st_size <= policy.max_bytes
        or value.st_uid not in policy.allowed_owner_uids
        or stat.S_IMODE(value.st_mode) & policy.forbidden_mode_bits
    ):
        raise OSError("image file does not satisfy the approved file policy")


def _verify_resolved_path(
    *,
    root_fd: int,
    parts: tuple[str, ...],
    expected_directories: tuple[tuple[int, int], ...],
    expected_file: os.stat_result,
    policy: SecureReadPolicy,
) -> None:
    parent, directories = _open_parent_chain(root_fd, parts[:-1])
    try:
        if directories != expected_directories:
            raise OSError("image parent path changed during read")
        visible = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        _validate_file_state(visible, policy)
        if _full_file_state(visible) != _full_file_state(expected_file):
            raise OSError("image path changed during read")
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            reopened = os.fstat(descriptor)
            _validate_file_state(reopened, policy)
            if _full_file_state(reopened) != _full_file_state(expected_file):
                raise OSError("image inode changed during read")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _wipe(payload: bytearray) -> None:
    payload[:] = b"\x00" * len(payload)


def read_approved_image(
    *,
    root_fd: int,
    candidate: RightsBoundImage,
    approved: ApprovedImageMaterialization,
    policy: SecureReadPolicy | None = None,
) -> VerifiedImageRead:
    """Read one exact approved image from a stable descriptor or fail generically."""

    selected_policy = policy or SecureReadPolicy()
    payload = bytearray()
    descriptor: int | None = None
    parent: int | None = None
    try:
        # This complete join intentionally precedes every filesystem operation.
        _bind_authority(candidate, approved)
        parts = _normalized_parts(candidate.relative_path)
        _require_secure_capabilities()
        parent, directory_identities = _open_parent_chain(root_fd, parts[:-1])
        visible = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        _validate_file_state(visible, selected_policy)
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        _validate_file_state(opened, selected_policy)
        if _full_file_state(opened) != _full_file_state(visible):
            raise OSError("image changed before descriptor open")

        digest = hashlib.sha256()
        while True:
            remaining_with_sentinel = selected_policy.max_bytes + 1 - len(payload)
            if remaining_with_sentinel <= 0:
                raise OSError("image exceeds the approved byte ceiling")
            chunk = os.read(
                descriptor,
                min(selected_policy.chunk_size, remaining_with_sentinel),
            )
            if not chunk:
                break
            payload.extend(chunk)
            digest.update(chunk)
            if len(payload) > selected_policy.max_bytes:
                raise OSError("image exceeds the approved byte ceiling")

        after = os.fstat(descriptor)
        _validate_file_state(after, selected_policy)
        if len(payload) != opened.st_size or _full_file_state(after) != _full_file_state(opened):
            raise OSError("image changed during descriptor read")
        _verify_resolved_path(
            root_fd=root_fd,
            parts=parts,
            expected_directories=directory_identities,
            expected_file=opened,
            policy=selected_policy,
        )
        observed_sha256 = digest.hexdigest()
        if not hmac.compare_digest(observed_sha256, approved.content_sha256):
            raise OSError("image content differs from approved materialization")
        return VerifiedImageRead(
            payload=payload,
            content_sha256=observed_sha256,
            identity=FileIdentity.from_stat(after),
        )
    except SecureImageReadError:
        _wipe(payload)
        raise
    except Exception:
        _wipe(payload)
        raise SecureImageReadError(_SAFE_ERROR) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


__all__ = [
    "ApprovedImageMaterialization",
    "FileIdentity",
    "O_CLOEXEC",
    "O_DIRECTORY",
    "O_NONBLOCK",
    "O_NOFOLLOW",
    "RightsBoundImage",
    "SecureImageReadError",
    "SecureReadPolicy",
    "VerifiedImageRead",
    "read_approved_image",
]
