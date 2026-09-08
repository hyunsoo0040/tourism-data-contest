"""Descriptor-safe write-side quarantine for Phase 6 photo upload bytes.

One job directory per photo job holds generated-name regular files written
exclusively below the caller-provided quarantine root descriptor. The module
never follows symbolic links, never reuses caller-supplied file names, and
removes partial residue from every failed attempt so hostile streams converge
to zero residue.

Policy instances are per photo job: the seen-index guard enforces exactly-once
storage per image index for the lifetime of one ``QuarantinePolicy``.
"""

from __future__ import annotations

import os
import re
import stat as stat_module
import sys
import uuid
from collections.abc import AsyncIterable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Final

_GENERATED_NAME_LENGTH: Final[int] = 32
_GENERATED_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{32}\Z")
_JOB_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_BINDING_NAME: Final[str] = ".itda-owner-v1"
_MIB: Final[int] = 1024 * 1024
_STORED_FILE_MODE: Final[int] = 0o600
_JOB_DIRECTORY_MODE: Final[int] = 0o700
_BINDING_FILE_MODE: Final[int] = 0o600
_REMOVED_DIRECTORY_NLINK: Final[int] = 2 if sys.platform == "darwin" else 0

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_READ_DIRECTORY_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_WRITE_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
_OPEN_FILE_FLAGS = os.O_RDONLY | _O_NONBLOCK | _O_NOFOLLOW | _O_CLOEXEC
_UPLOAD_WRITE = os.write


class QuarantineError(Exception):
    """One closed, public-safe failure for every rejected quarantine write."""

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class QuarantinePolicy:
    """Frozen bounded-byte policy for one photo job's quarantine writes.

    ``used_image_indexes`` is deliberate per-instance state: exactly one store
    is accepted per image index for the lifetime of this policy instance, so a
    duplicate or replayed upload is rejected before stream iteration.
    """

    max_image_bytes: int = 10 * _MIB
    max_job_total_bytes: int = 30 * _MIB
    used_image_indexes: set[int] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        if type(self.max_image_bytes) is not int or self.max_image_bytes <= 0:
            raise ValueError("quarantine image byte bound must be a positive integer")
        if type(self.max_job_total_bytes) is not int or self.max_job_total_bytes <= 0:
            raise ValueError("quarantine job byte bound must be a positive integer")
        if self.max_job_total_bytes < self.max_image_bytes:
            raise ValueError("job byte bound must cover at least one image")


@dataclass(frozen=True, slots=True)
class QuarantinedImage:
    """Generated-identity handoff for one stored quarantined image."""

    stored_name: str
    image_index: int
    byte_length: int

    def __post_init__(self) -> None:
        if _GENERATED_NAME_PATTERN.fullmatch(self.stored_name) is None:
            raise ValueError("stored name must be a generated 32-hex identity")
        if type(self.image_index) is not int or not 1 <= self.image_index <= 3:
            raise ValueError("image index must be an integer within 1..3")
        if type(self.byte_length) is not int or self.byte_length <= 0:
            raise ValueError("byte length must be a positive integer")


@dataclass(frozen=True, slots=True)
class QuarantinedImageHandle:
    """Open descriptor for one verified quarantined image; close after use."""

    descriptor: int
    stored_name: str

    def close(self) -> None:
        os.close(self.descriptor)

    def __enter__(self) -> QuarantinedImageHandle:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _require_capabilities() -> None:
    if not _O_DIRECTORY or not _O_NOFOLLOW or not _O_CLOEXEC:
        raise QuarantineError(
            "QUARANTINE_PLATFORM_UNSUPPORTED",
            "quarantine requires secure descriptor operations",
        )
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
    ):
        raise QuarantineError(
            "QUARANTINE_PLATFORM_UNSUPPORTED",
            "quarantine requires descriptor-relative filesystem operations",
        )


def open_quarantine_root(path: os.PathLike[str] | str) -> int:
    """Open one exact process-owned 0700 quarantine root, no-follow."""

    _require_capabilities()
    try:
        descriptor = os.open(path, _READ_DIRECTORY_FLAGS)
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine root failed the no-follow directory check",
        ) from error
    try:
        opened = os.fstat(descriptor)
        visible = os.stat(path, follow_symlinks=False)
        owner_uid = _process_owner_uid()
        if (
            not stat_module.S_ISDIR(opened.st_mode)
            or stat_module.S_IMODE(opened.st_mode) != _JOB_DIRECTORY_MODE
            or (owner_uid is not None and opened.st_uid != owner_uid)
            or _identity_tuple(opened) != _identity_tuple(visible)
        ):
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine root ownership, mode, or identity mismatched",
            )
    except (OSError, QuarantineError):
        os.close(descriptor)
        raise
    return descriptor


def _require_generated_name(value: str, reason: str) -> None:
    if (
        type(value) is not str
        or len(value) != _GENERATED_NAME_LENGTH
        or _GENERATED_NAME_PATTERN.fullmatch(value) is None
    ):
        raise QuarantineError(reason, "quarantine names must be opaque generated identities")


def _require_job_identity(job_id: str, profile_id: str) -> None:
    if type(job_id) is not str or _JOB_ID_PATTERN.fullmatch(job_id) is None:
        raise QuarantineError(
            "QUARANTINE_PATH_REJECTED",
            "quarantine jobs require canonical full identities",
        )
    if type(profile_id) is not str or not profile_id or len(profile_id) > 160:
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine jobs require an owning profile",
        )


def _binding_bytes(job_id: str, profile_id: str) -> bytes:
    return f"{job_id}\n{profile_id}\n".encode()


def _write_binding(descriptor: int, data: bytes) -> None:
    """Write the small durable binding without using the upload write helper."""

    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("quarantine binding write made no progress")
        view = view[written:]


def _process_owner_uid() -> int | None:
    getter = getattr(os, "geteuid", None)
    return None if getter is None else getter()


def _identity_tuple(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid)


def _rollback_created_entry(
    root_fd: int,
    job_fd: int,
    job_directory: str,
) -> None:
    """Remove a just-created empty directory only after exact held/visible proof."""

    owner_uid = _process_owner_uid()
    created_state = os.fstat(job_fd)
    if (
        not stat_module.S_ISDIR(created_state.st_mode)
        or stat_module.S_IMODE(created_state.st_mode) != _JOB_DIRECTORY_MODE
        or (owner_uid is not None and created_state.st_uid != owner_uid)
    ):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine new directory rollback identity mismatched",
        )
    if os.listdir(job_fd):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine new directory rollback found unexpected entries",
        )
    visible = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat_module.S_ISDIR(visible.st_mode)
        or stat_module.S_IMODE(visible.st_mode) != _JOB_DIRECTORY_MODE
        or _identity_tuple(visible) != _identity_tuple(created_state)
        or (owner_uid is not None and visible.st_uid != owner_uid)
    ):
        # A different entry holds the name: never blind-rmdir a substitute.
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine new directory rollback identity mismatched",
        )
    os.rmdir(job_directory, dir_fd=root_fd)
    removed = os.fstat(job_fd)
    if removed.st_nlink != _REMOVED_DIRECTORY_NLINK or (
        removed.st_dev,
        removed.st_ino,
        removed.st_mode,
        removed.st_uid,
    ) != (
        created_state.st_dev,
        created_state.st_ino,
        created_state.st_mode,
        created_state.st_uid,
    ):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine new directory rollback removal postcondition failed",
        )
    os.fsync(root_fd)


def _rollback_adoption_binding(
    root_fd: int,
    job_fd: int,
    job_directory: str,
    binding_identity: os.stat_result,
) -> None:
    owner_uid = _process_owner_uid()
    opened_directory = os.fstat(job_fd)
    visible_directory = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat_module.S_ISDIR(opened_directory.st_mode)
        or stat_module.S_IMODE(opened_directory.st_mode) != _JOB_DIRECTORY_MODE
        or (owner_uid is not None and opened_directory.st_uid != owner_uid)
        or _identity_tuple(opened_directory) != _identity_tuple(visible_directory)
        or os.listdir(job_fd) != [_BINDING_NAME]
    ):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine adoption rollback directory identity mismatched",
        )
    visible_binding = os.stat(_BINDING_NAME, dir_fd=job_fd, follow_symlinks=False)
    binding_fd = os.open(_BINDING_NAME, _OPEN_FILE_FLAGS, dir_fd=job_fd)
    try:
        opened_binding = os.fstat(binding_fd)
        if (
            not stat_module.S_ISREG(opened_binding.st_mode)
            or opened_binding.st_nlink != 1
            or (owner_uid is not None and opened_binding.st_uid != owner_uid)
            or _identity_tuple(opened_binding) != _identity_tuple(visible_binding)
            or _identity_tuple(opened_binding) != _identity_tuple(binding_identity)
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine adoption rollback binding identity mismatched",
            )
        os.unlink(_BINDING_NAME, dir_fd=job_fd)
        removed_binding = os.fstat(binding_fd)
        if removed_binding.st_nlink != 0 or (
            removed_binding.st_dev,
            removed_binding.st_ino,
            removed_binding.st_mode,
            removed_binding.st_uid,
        ) != (
            opened_binding.st_dev,
            opened_binding.st_ino,
            opened_binding.st_mode,
            opened_binding.st_uid,
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine adoption rollback binding removal failed",
            )
    finally:
        os.close(binding_fd)
    os.fsync(job_fd)
    os.fsync(root_fd)


def _rollback_binding_initialization(
    root_fd: int,
    job_fd: int,
    job_directory: str,
) -> None:
    """Undo a failed new-directory binding init, then remove the directory.

    Closes ``job_fd`` on every path: the caller must not reuse it after a
    rollback attempt.
    """

    try:
        owner_uid = _process_owner_uid()
        opened = os.fstat(job_fd)
        visible = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat_module.S_ISDIR(opened.st_mode)
            or stat_module.S_IMODE(opened.st_mode) != _JOB_DIRECTORY_MODE
            or not stat_module.S_ISDIR(visible.st_mode)
            or stat_module.S_IMODE(visible.st_mode) != _JOB_DIRECTORY_MODE
            or (owner_uid is not None and opened.st_uid != owner_uid)
            or _identity_tuple(opened) != _identity_tuple(visible)
            or any(entry != _BINDING_NAME for entry in os.listdir(job_fd))
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine new directory rollback identity mismatched",
            )
        with suppress(FileNotFoundError):
            os.unlink(_BINDING_NAME, dir_fd=job_fd)
        os.fsync(job_fd)
        _rollback_created_entry(root_fd, job_fd, job_directory)
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine new directory rollback could not be proven",
        ) from error
    finally:
        os.close(job_fd)


def _open_job_directory(
    root_fd: int,
    job_directory: str,
    profile_id: str,
    *,
    binding_claim_created: bool,
    materialize_reserved_missing: bool,
) -> tuple[int, bool]:
    """Materialize only a DB-authorized first claim or exact durable retry.

    The creation identity comes from the held descriptor's fstat — never
    from a pre-open visible stat of the just-created name, which an
    attacker could race or fail to leave a rollback-able empty directory.
    """

    _require_job_identity(job_directory, profile_id)
    owner_uid = _process_owner_uid()
    root_state = os.fstat(root_fd)
    if (
        not stat_module.S_ISDIR(root_state.st_mode)
        or stat_module.S_IMODE(root_state.st_mode) != _JOB_DIRECTORY_MODE
        or (owner_uid is not None and root_state.st_uid != owner_uid)
    ):
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine root ownership or mode mismatched",
        )
    created = False
    try:
        os.mkdir(job_directory, _JOB_DIRECTORY_MODE, dir_fd=root_fd)
        created = True
        try:
            os.chmod(
                job_directory,
                _JOB_DIRECTORY_MODE,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            rollback_fd: int | None = None
            try:
                rollback_fd = os.open(job_directory, _READ_DIRECTORY_FLAGS, dir_fd=root_fd)
                os.fchmod(rollback_fd, _JOB_DIRECTORY_MODE)
                _rollback_provisioned_directory(root_fd, rollback_fd, job_directory)
            except OSError as rollback_error:
                raise QuarantineError(
                    "QUARANTINE_STORE_FAILED",
                    "quarantine directory mode normalization could not be rolled back",
                ) from rollback_error
            finally:
                if rollback_fd is not None:
                    os.close(rollback_fd)
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine job directory mode could not be normalized",
            ) from error
    except FileExistsError as error:
        if binding_claim_created and not materialize_reserved_missing:
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "new database binding claim collided with a pre-existing directory",
            ) from error
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine job directory could not be provisioned",
        ) from error

    normalized_path: tuple[os.stat_result, int] | None = None
    if materialize_reserved_missing and not created:
        try:
            normalized_path = _normalize_restrictive_path_before_open(root_fd, job_directory)
        except OSError as error:
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine restrictive intent could not be normalized",
            ) from error

    descriptor: int | None = None
    adoption_binding: os.stat_result | None = None
    try:
        try:
            descriptor = os.open(job_directory, _READ_DIRECTORY_FLAGS, dir_fd=root_fd)
        except OSError as error:
            if not created:
                raise QuarantineError(
                    "QUARANTINE_JOB_DIRECTORY_REJECTED",
                    "quarantine job directory failed the no-follow directory check",
                ) from error
            # The just-created directory could not be opened no-follow.
            # Retry the open strictly for rollback: a transient failure lets
            # the held descriptor prove 0700/UID/empty identity before the
            # held-inode removal, while a persistent failure keeps the
            # durable reserved intent for the exact materialize retry
            # instead of discarding DB-authorized authority unproven.
            open_failure_rollback_fd: int | None = None
            try:
                open_failure_rollback_fd = os.open(
                    job_directory, _READ_DIRECTORY_FLAGS, dir_fd=root_fd
                )
            except OSError:
                open_failure_rollback_fd = None
            if open_failure_rollback_fd is not None:
                try:
                    _rollback_provisioned_directory(
                        root_fd, open_failure_rollback_fd, job_directory
                    )
                finally:
                    os.close(open_failure_rollback_fd)
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine job directory failed the no-follow directory check",
            ) from error
        if normalized_path is not None:
            opened_normalized = os.fstat(descriptor)
            visible_normalized = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat_module.S_ISDIR(opened_normalized.st_mode)
                or stat_module.S_IMODE(opened_normalized.st_mode) != _JOB_DIRECTORY_MODE
                or _identity_tuple(opened_normalized) != _identity_tuple(visible_normalized)
                or (
                    opened_normalized.st_dev,
                    opened_normalized.st_ino,
                    opened_normalized.st_uid,
                )
                != (
                    normalized_path[0].st_dev,
                    normalized_path[0].st_ino,
                    normalized_path[0].st_uid,
                )
            ):
                raise QuarantineError(
                    "QUARANTINE_JOB_DIRECTORY_REJECTED",
                    "quarantine normalized intent descriptor mismatched",
                )
            os.fsync(descriptor)
            os.fsync(root_fd)
        if created and not (binding_claim_created or materialize_reserved_missing):
            try:
                _rollback_created_entry(root_fd, descriptor, job_directory)
            finally:
                os.close(descriptor)
            descriptor = None
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "database and filesystem binding claim states mismatched",
            )
        if created:
            os.fchmod(descriptor, _JOB_DIRECTORY_MODE)
            initialized = os.fstat(descriptor)
            if (
                not stat_module.S_ISDIR(initialized.st_mode)
                or stat_module.S_IMODE(initialized.st_mode) != _JOB_DIRECTORY_MODE
                or (owner_uid is not None and initialized.st_uid != owner_uid)
            ):
                raise QuarantineError(
                    "QUARANTINE_JOB_DIRECTORY_REJECTED",
                    "quarantine job directory initialization mismatched",
                )
            binding_fd = os.open(
                _BINDING_NAME,
                _WRITE_FILE_FLAGS,
                _BINDING_FILE_MODE,
                dir_fd=descriptor,
            )
            try:
                _write_binding(binding_fd, _binding_bytes(job_directory, profile_id))
                os.fchmod(binding_fd, _BINDING_FILE_MODE)
                os.fsync(binding_fd)
            finally:
                os.close(binding_fd)
            os.fsync(descriptor)
            os.fsync(root_fd)
        else:
            if materialize_reserved_missing:
                _normalize_restrictive_provisioned(root_fd, descriptor, job_directory)
                _remove_partial_adoption_binding(root_fd, descriptor, job_directory)
            if materialize_reserved_missing and _is_unbound_provisioned(descriptor):
                # Adoption: a previously provisioned directory stranded by a
                # persistent open failure is exactly an empty unbound 0700
                # process-owned dir. Under the committed materialize intent
                # the binding is created now; anything else falls through to
                # the strict binding verification and rejects.
                binding_fd = os.open(
                    _BINDING_NAME,
                    _WRITE_FILE_FLAGS,
                    _BINDING_FILE_MODE,
                    dir_fd=descriptor,
                )
                try:
                    try:
                        adoption_binding = os.fstat(binding_fd)
                    except OSError:
                        adoption_binding = os.fstat(binding_fd)
                        raise
                    _write_binding(binding_fd, _binding_bytes(job_directory, profile_id))
                    os.fchmod(binding_fd, _BINDING_FILE_MODE)
                    os.fsync(binding_fd)
                finally:
                    os.close(binding_fd)
                os.fsync(descriptor)
                os.fsync(root_fd)
                created = True
                return descriptor, created
            binding_fd = os.open(_BINDING_NAME, _OPEN_FILE_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(binding_fd)
                content = bytearray()
                while len(content) <= 512:
                    piece = os.read(binding_fd, 513 - len(content))
                    if not piece:
                        break
                    content.extend(piece)
                visible = os.stat(_BINDING_NAME, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat_module.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or stat_module.S_IMODE(opened.st_mode) != _BINDING_FILE_MODE
                    or (owner_uid is not None and opened.st_uid != owner_uid)
                    or bytes(content) != _binding_bytes(job_directory, profile_id)
                    or _identity_tuple(opened) != _identity_tuple(visible)
                ):
                    raise QuarantineError(
                        "QUARANTINE_JOB_DIRECTORY_REJECTED",
                        "quarantine job directory binding mismatched",
                    )
            finally:
                os.close(binding_fd)
        opened_directory = os.fstat(descriptor)
        visible_directory = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat_module.S_ISDIR(opened_directory.st_mode)
            or stat_module.S_IMODE(opened_directory.st_mode) != _JOB_DIRECTORY_MODE
            or (owner_uid is not None and opened_directory.st_uid != owner_uid)
            or _identity_tuple(opened_directory) != _identity_tuple(visible_directory)
        ):
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine job directory identity changed",
            )
    except (OSError, QuarantineError) as error:
        if adoption_binding is not None and descriptor is not None:
            adoption_directory_fd = descriptor
            try:
                _rollback_adoption_binding(
                    root_fd,
                    adoption_directory_fd,
                    job_directory,
                    adoption_binding,
                )
                os.close(adoption_directory_fd)
                descriptor = None
            except (OSError, QuarantineError) as rollback_error:
                with suppress(OSError):
                    os.close(adoption_directory_fd)
                raise QuarantineError(
                    "QUARANTINE_STORE_FAILED",
                    "quarantine adoption binding rollback did not finish",
                ) from rollback_error
        elif created and descriptor is not None:
            try:
                _rollback_binding_initialization(root_fd, descriptor, job_directory)
            except (OSError, QuarantineError) as rollback_error:
                with suppress(OSError):
                    os.close(descriptor)
                raise QuarantineError(
                    "QUARANTINE_STORE_FAILED",
                    "quarantine binding rollback did not finish",
                ) from rollback_error
        elif descriptor is not None:
            try:
                _restore_restrictive_path_mode(
                    root_fd,
                    descriptor,
                    job_directory,
                    normalized_path,
                )
            except (OSError, QuarantineError) as restore_error:
                with suppress(OSError):
                    os.close(descriptor)
                raise QuarantineError(
                    "QUARANTINE_STORE_FAILED",
                    "quarantine restrictive intent mode restore did not finish",
                ) from restore_error
            with suppress(OSError):
                os.close(descriptor)
        if isinstance(error, QuarantineError):
            raise
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine job directory binding could not be verified",
        ) from error
    assert descriptor is not None
    return descriptor, created


def _existing_job_bytes(job_fd: int, policy: QuarantinePolicy) -> int:
    """Sum at most three generated regular files, no-follow.

    Every existing child is opened descriptor-relatively and its open
    descriptor identity is compared to the visible no-follow stat before
    the byte total is trusted; a child that cannot be opened or whose
    identity drifts is a substitution, not an accounting fact.
    """

    total = 0
    owner_uid = _process_owner_uid()
    try:
        entries = [entry for entry in os.listdir(job_fd) if entry != _BINDING_NAME]
        if len(entries) > 3 or any(
            _GENERATED_NAME_PATTERN.fullmatch(entry) is None for entry in entries
        ):
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine directory contains unexpected entries",
            )
        for entry in entries:
            visible = os.stat(entry, dir_fd=job_fd, follow_symlinks=False)
            if not stat_module.S_ISREG(visible.st_mode) or visible.st_nlink != 1:
                raise QuarantineError(
                    "QUARANTINE_JOB_DIRECTORY_REJECTED",
                    "quarantine directory contains a substituted object",
                )
            descriptor = os.open(entry, _OPEN_FILE_FLAGS, dir_fd=job_fd)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat_module.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or stat_module.S_IMODE(opened.st_mode) != _STORED_FILE_MODE
                    or (owner_uid is not None and opened.st_uid != owner_uid)
                    or _identity_tuple(opened) != _identity_tuple(visible)
                ):
                    raise QuarantineError(
                        "QUARANTINE_SUBSTITUTION_DETECTED",
                        "quarantine existing child identity could not be proven",
                    )
                if opened.st_size > policy.max_image_bytes:
                    raise QuarantineError(
                        "QUARANTINE_JOB_BYTES_EXCEEDED",
                        "quarantine existing child exceeded the image byte reservation",
                    )
                total += opened.st_size
                if total > policy.max_job_total_bytes:
                    raise QuarantineError(
                        "QUARANTINE_JOB_BYTES_EXCEEDED",
                        "quarantine existing children exceeded the aggregate byte reservation",
                    )
            finally:
                os.close(descriptor)
    except QuarantineError:
        raise
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_JOB_BYTES_EXCEEDED",
            "quarantine job bytes could not be accounted safely",
        ) from error
    return total


def _write_complete(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = _UPLOAD_WRITE(descriptor, view)
        if written <= 0:
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine write could not make progress",
            )
        view = view[written:]


def _validate_declared_length(
    declared_byte_length: int | None,
    policy: QuarantinePolicy,
) -> int | None:
    if declared_byte_length is None:
        return None
    if (
        type(declared_byte_length) is not int
        or declared_byte_length <= 0
        or declared_byte_length > policy.max_image_bytes
    ):
        raise QuarantineError(
            "QUARANTINE_DECLARED_LENGTH_REJECTED",
            "declared byte length is not a bounded positive integer",
        )
    return declared_byte_length


async def stream_to_quarantine(
    *,
    root_fd: int,
    job_directory: str,
    profile_id: str,
    image_index: int,
    chunks: AsyncIterable[bytes],
    policy: QuarantinePolicy,
    binding_claim_created: bool,
    declared_byte_length: int | None = None,
    expected_stored_name: str | None = None,
    resume_reserved: bool = False,
    materialize_reserved_missing: bool = False,
) -> QuarantinedImage:
    """Write one bounded chunk stream into the quarantine or fail closed.

    ``expected_stored_name`` binds the durable DB slot reservation to the
    generated file identity before any body byte is consumed, so DB/FS
    reconciliation has one exact name to reconcile. When omitted a fresh
    server-generated name is used. Every failure removes partial residue
    before returning.
    """

    owner = profile_id
    _require_job_identity(job_directory, owner)
    if type(image_index) is not int or not 1 <= image_index <= 3:
        raise QuarantineError(
            "QUARANTINE_IMAGE_INDEX_OUT_OF_RANGE",
            "image index must be within the bounded 1..3 range",
        )
    if image_index in policy.used_image_indexes:
        raise QuarantineError(
            "QUARANTINE_IMAGE_INDEX_REUSED",
            "each image index may be stored exactly once per job policy",
        )
    declared = _validate_declared_length(declared_byte_length, policy)
    _require_capabilities()

    job_fd, directory_created = _open_job_directory(
        root_fd,
        job_directory,
        owner,
        binding_claim_created=binding_claim_created,
        materialize_reserved_missing=materialize_reserved_missing,
    )
    file_fd: int | None = None
    stored_name = expected_stored_name or ""
    try:
        if expected_stored_name is None:
            stored_name = uuid.uuid4().hex
        if _GENERATED_NAME_PATTERN.fullmatch(stored_name) is None:
            raise QuarantineError(
                "QUARANTINE_PATH_REJECTED",
                "quarantine slot reservation names must be generated 32-hex identities",
            )
        if resume_reserved:
            _remove_reserved_partial(job_fd, stored_name)
        existing_bytes = _existing_job_bytes(job_fd, policy)
        iterator = aiter(chunks)
        try:
            first_chunk = await anext(iterator)
        except StopAsyncIteration as error:
            raise QuarantineError(
                "QUARANTINE_EMPTY_STREAM",
                "quarantine requires at least one nonempty byte chunk",
            ) from error
        if not first_chunk:
            raise QuarantineError(
                "QUARANTINE_EMPTY_STREAM",
                "quarantine requires at least one nonempty byte chunk",
            )
        cumulative = len(first_chunk)
        if cumulative > policy.max_image_bytes:
            raise QuarantineError(
                "QUARANTINE_SIZE_OVERFLOW",
                "quarantine stream exceeds the bounded image byte cap",
            )
        if declared is not None and cumulative > declared:
            raise QuarantineError(
                "QUARANTINE_DECLARED_LENGTH_MISMATCH",
                "quarantine stream crossed the declared length",
            )
        if existing_bytes + cumulative > policy.max_job_total_bytes:
            raise QuarantineError(
                "QUARANTINE_JOB_BYTES_EXCEEDED",
                "quarantine job exceeded the aggregate byte reservation",
            )
        try:
            file_fd = os.open(
                stored_name,
                _WRITE_FILE_FLAGS,
                _STORED_FILE_MODE,
                dir_fd=job_fd,
            )
        except OSError as error:
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine could not create the exclusive generated-name file",
            ) from error
        os.fchmod(file_fd, _STORED_FILE_MODE)
        opened_state = os.fstat(file_fd)
        _write_complete(file_fd, first_chunk)

        async for chunk in iterator:
            next_total = cumulative + len(chunk)
            if next_total > policy.max_image_bytes:
                raise QuarantineError(
                    "QUARANTINE_SIZE_OVERFLOW",
                    "quarantine stream exceeds the bounded image byte cap",
                )
            if declared is not None and next_total > declared:
                raise QuarantineError(
                    "QUARANTINE_DECLARED_LENGTH_MISMATCH",
                    "quarantine stream crossed the declared length",
                )
            if existing_bytes + next_total > policy.max_job_total_bytes:
                raise QuarantineError(
                    "QUARANTINE_JOB_BYTES_EXCEEDED",
                    "quarantine job exceeded the aggregate byte reservation",
                )
            cumulative = next_total
            _write_complete(file_fd, chunk)
        if declared is not None and cumulative != declared:
            raise QuarantineError(
                "QUARANTINE_DECLARED_LENGTH_MISMATCH",
                "quarantine stream delivered a different length than declared",
            )

        final_state = os.fstat(file_fd)
        owner_uid = _process_owner_uid()
        substitution = (
            not stat_module.S_ISREG(final_state.st_mode)
            or final_state.st_nlink != 1
            or stat_module.S_IMODE(final_state.st_mode) != _STORED_FILE_MODE
            or (owner_uid is not None and final_state.st_uid != owner_uid)
            or _identity_tuple(final_state) != _identity_tuple(opened_state)
        )
        if substitution:
            raise QuarantineError(
                "QUARANTINE_SUBSTITUTION_DETECTED",
                "quarantine file identity drifted during the bounded write",
            )
        visible = os.stat(stored_name, dir_fd=job_fd, follow_symlinks=False)
        if _identity_tuple(visible) != _identity_tuple(final_state):
            raise QuarantineError(
                "QUARANTINE_SUBSTITUTION_DETECTED",
                "quarantine file name no longer matches the written inode",
            )
        os.fsync(file_fd)
        os.fsync(job_fd)
    except QuarantineError as original:
        try:
            if file_fd is not None:
                _unlink_partial_strict(job_fd, stored_name)
            if directory_created:
                _rollback_new_job_directory(root_fd, job_fd, job_directory, profile_id)
        except (OSError, QuarantineError) as cleanup_error:
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine partial cleanup did not finish",
            ) from cleanup_error
        raise original
    except OSError as error:
        try:
            if file_fd is not None:
                _unlink_partial_strict(job_fd, stored_name)
            if directory_created:
                _rollback_new_job_directory(root_fd, job_fd, job_directory, profile_id)
        except (OSError, QuarantineError) as cleanup_error:
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine partial cleanup did not finish",
            ) from cleanup_error
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine write failed a descriptor-safe filesystem check",
        ) from error
    except BaseException as original:
        # Cancellation/SystemExit/async-iterator failure after the partial
        # file exists: remove the residue durably, then re-raise the original.
        try:
            if file_fd is not None:
                _unlink_partial_strict(job_fd, stored_name)
            if directory_created:
                _rollback_new_job_directory(root_fd, job_fd, job_directory, profile_id)
        except BaseException:
            original.add_note("quarantine partial cleanup did not finish")
        raise
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(job_fd)

    policy.used_image_indexes.add(image_index)
    return QuarantinedImage(
        stored_name=stored_name,
        image_index=image_index,
        byte_length=cumulative,
    )


def _unlink_partial(job_fd: int, stored_name: str) -> None:
    with suppress(OSError):
        os.unlink(stored_name, dir_fd=job_fd)


def _unlink_partial_strict(job_fd: int, stored_name: str) -> None:
    """Durable partial removal for the BaseException boundary: unlink + fsync."""

    with suppress(FileNotFoundError):
        os.unlink(stored_name, dir_fd=job_fd)
    os.fsync(job_fd)


def _remove_reserved_partial(job_fd: int, stored_name: str) -> None:
    """Remove only the exact durable reserved name after no-follow proof."""

    try:
        visible = os.stat(stored_name, dir_fd=job_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine reserved partial could not be inspected",
        ) from error
    owner_uid = _process_owner_uid()
    if (
        not stat_module.S_ISREG(visible.st_mode)
        or visible.st_nlink != 1
        or stat_module.S_IMODE(visible.st_mode) != _STORED_FILE_MODE
        or (owner_uid is not None and visible.st_uid != owner_uid)
    ):
        raise QuarantineError(
            "QUARANTINE_SUBSTITUTION_DETECTED",
            "quarantine reserved partial identity mismatched",
        )
    descriptor = os.open(stored_name, _OPEN_FILE_FLAGS, dir_fd=job_fd)
    try:
        opened = os.fstat(descriptor)
        if _identity_tuple(opened) != _identity_tuple(visible):
            raise QuarantineError(
                "QUARANTINE_SUBSTITUTION_DETECTED",
                "quarantine reserved partial changed during inspection",
            )
    finally:
        os.close(descriptor)
    _unlink_partial_strict(job_fd, stored_name)


def _normalize_restrictive_path_before_open(
    root_fd: int,
    job_directory: str,
) -> tuple[os.stat_result, int] | None:
    owner_uid = _process_owner_uid()
    visible = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    mode = stat_module.S_IMODE(visible.st_mode)
    if mode == _JOB_DIRECTORY_MODE:
        return None
    if (
        not stat_module.S_ISDIR(visible.st_mode)
        or mode & ~_JOB_DIRECTORY_MODE
        or (owner_uid is not None and visible.st_uid != owner_uid)
    ):
        return None
    os.chmod(
        job_directory,
        _JOB_DIRECTORY_MODE,
        dir_fd=root_fd,
        follow_symlinks=False,
    )
    normalized = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat_module.S_ISDIR(normalized.st_mode)
        or stat_module.S_IMODE(normalized.st_mode) != _JOB_DIRECTORY_MODE
        or (normalized.st_dev, normalized.st_ino, normalized.st_uid)
        != (visible.st_dev, visible.st_ino, visible.st_uid)
    ):
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine restrictive intent pathname changed",
        )
    os.fsync(root_fd)
    return normalized, mode


def _restore_restrictive_path_mode(
    root_fd: int,
    job_fd: int,
    job_directory: str,
    normalized_path: tuple[os.stat_result, int] | None,
) -> None:
    if normalized_path is None:
        return
    normalized, prior_mode = normalized_path
    held = os.fstat(job_fd)
    visible = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if _identity_tuple(held) != _identity_tuple(visible) or (
        held.st_dev,
        held.st_ino,
        held.st_uid,
    ) != (normalized.st_dev, normalized.st_ino, normalized.st_uid):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine restrictive intent restore identity mismatched",
        )
    os.fchmod(job_fd, prior_mode)
    restored = os.fstat(job_fd)
    visible_restored = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        stat_module.S_IMODE(restored.st_mode) != prior_mode
        or _identity_tuple(restored) != _identity_tuple(visible_restored)
        or (restored.st_dev, restored.st_ino, restored.st_uid)
        != (normalized.st_dev, normalized.st_ino, normalized.st_uid)
    ):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine restrictive intent restore postcondition failed",
        )
    os.fsync(job_fd)
    os.fsync(root_fd)


def _normalize_restrictive_provisioned(
    root_fd: int,
    job_fd: int,
    job_directory: str,
) -> None:
    owner_uid = _process_owner_uid()
    held = os.fstat(job_fd)
    mode = stat_module.S_IMODE(held.st_mode)
    if mode == _JOB_DIRECTORY_MODE:
        return
    visible = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat_module.S_ISDIR(held.st_mode)
        or mode & ~_JOB_DIRECTORY_MODE
        or (owner_uid is not None and held.st_uid != owner_uid)
        or _identity_tuple(held) != _identity_tuple(visible)
        or os.listdir(job_fd)
    ):
        return
    os.fchmod(job_fd, _JOB_DIRECTORY_MODE)
    normalized = os.fstat(job_fd)
    visible_normalized = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        stat_module.S_IMODE(normalized.st_mode) != _JOB_DIRECTORY_MODE
        or _identity_tuple(normalized) != _identity_tuple(visible_normalized)
        or (normalized.st_dev, normalized.st_ino, normalized.st_uid)
        != (held.st_dev, held.st_ino, held.st_uid)
    ):
        raise QuarantineError(
            "QUARANTINE_JOB_DIRECTORY_REJECTED",
            "quarantine restrictive intent normalization mismatched",
        )
    os.fsync(job_fd)
    os.fsync(root_fd)


def _remove_partial_adoption_binding(
    root_fd: int,
    job_fd: int,
    job_directory: str,
) -> None:
    if os.listdir(job_fd) != [_BINDING_NAME]:
        return
    owner_uid = _process_owner_uid()
    held_directory = os.fstat(job_fd)
    visible_directory = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat_module.S_ISDIR(held_directory.st_mode)
        or stat_module.S_IMODE(held_directory.st_mode) != _JOB_DIRECTORY_MODE
        or (owner_uid is not None and held_directory.st_uid != owner_uid)
        or _identity_tuple(held_directory) != _identity_tuple(visible_directory)
    ):
        return
    visible_binding = os.stat(_BINDING_NAME, dir_fd=job_fd, follow_symlinks=False)
    binding_mode = stat_module.S_IMODE(visible_binding.st_mode)
    if (
        not stat_module.S_ISREG(visible_binding.st_mode)
        or visible_binding.st_nlink != 1
        or binding_mode & ~_BINDING_FILE_MODE
        or (owner_uid is not None and visible_binding.st_uid != owner_uid)
        or visible_binding.st_size != 0
    ):
        return
    if binding_mode != _BINDING_FILE_MODE:
        os.chmod(
            _BINDING_NAME,
            _BINDING_FILE_MODE,
            dir_fd=job_fd,
            follow_symlinks=False,
        )
        normalized_binding = os.stat(_BINDING_NAME, dir_fd=job_fd, follow_symlinks=False)
        if stat_module.S_IMODE(normalized_binding.st_mode) != _BINDING_FILE_MODE or (
            normalized_binding.st_dev,
            normalized_binding.st_ino,
            normalized_binding.st_uid,
            normalized_binding.st_nlink,
            normalized_binding.st_size,
        ) != (
            visible_binding.st_dev,
            visible_binding.st_ino,
            visible_binding.st_uid,
            visible_binding.st_nlink,
            visible_binding.st_size,
        ):
            raise QuarantineError(
                "QUARANTINE_JOB_DIRECTORY_REJECTED",
                "quarantine partial binding pathname changed",
            )
        visible_binding = normalized_binding
        os.fsync(job_fd)
        os.fsync(root_fd)
    binding_fd = os.open(_BINDING_NAME, _OPEN_FILE_FLAGS, dir_fd=job_fd)
    try:
        opened_binding = os.fstat(binding_fd)
        if (
            not stat_module.S_ISREG(opened_binding.st_mode)
            or opened_binding.st_nlink != 1
            or stat_module.S_IMODE(opened_binding.st_mode) != _BINDING_FILE_MODE
            or (owner_uid is not None and opened_binding.st_uid != owner_uid)
            or opened_binding.st_size != 0
            or _identity_tuple(opened_binding) != _identity_tuple(visible_binding)
        ):
            return
        os.unlink(_BINDING_NAME, dir_fd=job_fd)
        removed_binding = os.fstat(binding_fd)
        if removed_binding.st_nlink != 0 or (
            removed_binding.st_dev,
            removed_binding.st_ino,
            removed_binding.st_mode,
            removed_binding.st_uid,
        ) != (
            opened_binding.st_dev,
            opened_binding.st_ino,
            opened_binding.st_mode,
            opened_binding.st_uid,
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine partial adoption binding removal failed",
            )
    finally:
        os.close(binding_fd)
    os.fsync(job_fd)
    os.fsync(root_fd)


def _is_unbound_provisioned(job_fd: int) -> bool:
    """Whether the held directory is exactly an empty bindingless 0700 dir."""

    owner_uid = _process_owner_uid()
    held = os.fstat(job_fd)
    return (
        stat_module.S_ISDIR(held.st_mode)
        and stat_module.S_IMODE(held.st_mode) == _JOB_DIRECTORY_MODE
        and (owner_uid is None or held.st_uid == owner_uid)
        and os.listdir(job_fd) == []
    )


def _rollback_provisioned_directory(
    root_fd: int,
    job_fd: int,
    job_directory: str,
) -> None:
    """Strictly remove a just-provisioned (bindingless) new directory.

    The held descriptor must prove the exact freshly created shape —
    directory, 0700, process UID, empty — before ``_rollback_created_entry``
    removes it through its held identity with the post-rmdir nlink proof.
    Any other shape is a substitution: the name is left untouched and the
    caller fails closed.
    """

    owner_uid = _process_owner_uid()
    provisioned = os.fstat(job_fd)
    if (
        not stat_module.S_ISDIR(provisioned.st_mode)
        or stat_module.S_IMODE(provisioned.st_mode) != _JOB_DIRECTORY_MODE
        or (owner_uid is not None and provisioned.st_uid != owner_uid)
        or os.listdir(job_fd)
    ):
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine new directory rollback identity mismatched",
        )
    _rollback_created_entry(root_fd, job_fd, job_directory)


def _rollback_new_job_directory(
    root_fd: int, job_fd: int, job_directory: str, profile_id: str
) -> None:
    owner_uid = _process_owner_uid()
    try:
        opened_directory = os.fstat(job_fd)
        visible_directory = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat_module.S_ISDIR(opened_directory.st_mode)
            or stat_module.S_IMODE(opened_directory.st_mode) != _JOB_DIRECTORY_MODE
            or (owner_uid is not None and opened_directory.st_uid != owner_uid)
            or _identity_tuple(opened_directory) != _identity_tuple(visible_directory)
            or os.listdir(job_fd) != [_BINDING_NAME]
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine rollback directory identity mismatched",
            )
        binding_fd = os.open(_BINDING_NAME, _OPEN_FILE_FLAGS, dir_fd=job_fd)
        try:
            opened_binding = os.fstat(binding_fd)
            content = bytearray()
            while len(content) <= 512:
                piece = os.read(binding_fd, 513 - len(content))
                if not piece:
                    break
                content.extend(piece)
            visible_binding = os.stat(_BINDING_NAME, dir_fd=job_fd, follow_symlinks=False)
            if (
                not stat_module.S_ISREG(opened_binding.st_mode)
                or opened_binding.st_nlink != 1
                or stat_module.S_IMODE(opened_binding.st_mode) != _BINDING_FILE_MODE
                or (owner_uid is not None and opened_binding.st_uid != owner_uid)
                or bytes(content) != _binding_bytes(job_directory, profile_id)
                or _identity_tuple(opened_binding) != _identity_tuple(visible_binding)
            ):
                raise QuarantineError(
                    "QUARANTINE_STORE_FAILED",
                    "quarantine rollback binding identity mismatched",
                )
            os.unlink(_BINDING_NAME, dir_fd=job_fd)
            removed_binding = os.fstat(binding_fd)
            if removed_binding.st_nlink != 0 or (
                removed_binding.st_dev,
                removed_binding.st_ino,
                removed_binding.st_mode,
                removed_binding.st_uid,
            ) != (
                opened_binding.st_dev,
                opened_binding.st_ino,
                opened_binding.st_mode,
                opened_binding.st_uid,
            ):
                raise QuarantineError(
                    "QUARANTINE_STORE_FAILED",
                    "quarantine rollback binding removal failed",
                )
        finally:
            os.close(binding_fd)
        os.fsync(job_fd)
        visible_before_rmdir = os.stat(job_directory, dir_fd=root_fd, follow_symlinks=False)
        held_before_rmdir = os.fstat(job_fd)
        if (
            not stat_module.S_ISDIR(held_before_rmdir.st_mode)
            or stat_module.S_IMODE(held_before_rmdir.st_mode) != _JOB_DIRECTORY_MODE
            or (owner_uid is not None and held_before_rmdir.st_uid != owner_uid)
            or (
                held_before_rmdir.st_dev,
                held_before_rmdir.st_ino,
                held_before_rmdir.st_mode,
                held_before_rmdir.st_uid,
            )
            != (
                opened_directory.st_dev,
                opened_directory.st_ino,
                opened_directory.st_mode,
                opened_directory.st_uid,
            )
            or (
                visible_before_rmdir.st_dev,
                visible_before_rmdir.st_ino,
                visible_before_rmdir.st_mode,
                visible_before_rmdir.st_uid,
            )
            != (
                opened_directory.st_dev,
                opened_directory.st_ino,
                opened_directory.st_mode,
                opened_directory.st_uid,
            )
            or os.listdir(job_fd)
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine rollback directory changed before removal",
            )
        os.rmdir(job_directory, dir_fd=root_fd)
        removed_directory = os.fstat(job_fd)
        if removed_directory.st_nlink != _REMOVED_DIRECTORY_NLINK or (
            removed_directory.st_dev,
            removed_directory.st_ino,
            removed_directory.st_mode,
            removed_directory.st_uid,
        ) != (
            opened_directory.st_dev,
            opened_directory.st_ino,
            opened_directory.st_mode,
            opened_directory.st_uid,
        ):
            raise QuarantineError(
                "QUARANTINE_STORE_FAILED",
                "quarantine rollback directory removal failed",
            )
        os.fsync(root_fd)
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_STORE_FAILED",
            "quarantine failed to rollback a new job directory",
        ) from error


def _verify_binding(job_fd: int, job_directory: str, profile_id: str) -> None:
    owner_uid = _process_owner_uid()
    try:
        binding_fd = os.open(_BINDING_NAME, _OPEN_FILE_FLAGS, dir_fd=job_fd)
        try:
            opened = os.fstat(binding_fd)
            content = bytearray()
            while len(content) <= 512:
                piece = os.read(binding_fd, 513 - len(content))
                if not piece:
                    break
                content.extend(piece)
            visible = os.stat(_BINDING_NAME, dir_fd=job_fd, follow_symlinks=False)
            if (
                not stat_module.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or stat_module.S_IMODE(opened.st_mode) != _BINDING_FILE_MODE
                or (owner_uid is not None and opened.st_uid != owner_uid)
                or bytes(content) != _binding_bytes(job_directory, profile_id)
                or _identity_tuple(opened) != _identity_tuple(visible)
            ):
                raise QuarantineError("QUARANTINE_OPEN_REJECTED", "quarantine binding mismatched")
        finally:
            os.close(binding_fd)
    except OSError as error:
        raise QuarantineError(
            "QUARANTINE_OPEN_REJECTED", "quarantine binding could not be verified"
        ) from error


def open_quarantined_image(
    *,
    root_fd: int,
    job_directory: str,
    profile_id: str,
    stored_name: str,
) -> QuarantinedImageHandle:
    """Open one stored quarantine file or reject linked/drifted targets fact-free."""

    _require_job_identity(job_directory, profile_id)
    _require_generated_name(stored_name, "QUARANTINE_PATH_REJECTED")
    job_fd: int | None = None
    descriptor: int | None = None
    try:
        job_fd = os.open(job_directory, _READ_DIRECTORY_FLAGS, dir_fd=root_fd)
        _verify_binding(job_fd, job_directory, profile_id)
        descriptor = os.open(stored_name, _OPEN_FILE_FLAGS, dir_fd=job_fd)
        opened = os.fstat(descriptor)
        owner_uid = _process_owner_uid()
        rejected = (
            not stat_module.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat_module.S_IMODE(opened.st_mode) != _STORED_FILE_MODE
            or (owner_uid is not None and opened.st_uid != owner_uid)
        )
        if rejected:
            raise QuarantineError(
                "QUARANTINE_OPEN_REJECTED",
                "quarantine target failed the regular-file owner policy",
            )
        visible = os.stat(stored_name, dir_fd=job_fd, follow_symlinks=False)
        if _identity_tuple(visible) != _identity_tuple(opened):
            raise QuarantineError(
                "QUARANTINE_SUBSTITUTION_DETECTED",
                "quarantine target changed while being opened",
            )
        return QuarantinedImageHandle(descriptor=descriptor, stored_name=stored_name)
    except QuarantineError:
        _close_quietly(descriptor)
        raise
    except OSError as error:
        _close_quietly(descriptor)
        raise QuarantineError(
            "QUARANTINE_OPEN_REJECTED",
            "quarantine open failed the no-follow descriptor checks",
        ) from error
    finally:
        _close_quietly(job_fd)


def _close_quietly(descriptor: int | None) -> None:
    if descriptor is not None:
        with suppress(OSError):
            os.close(descriptor)


__all__ = [
    "QuarantinedImage",
    "QuarantinedImageHandle",
    "QuarantineError",
    "QuarantinePolicy",
    "open_quarantine_root",
    "open_quarantined_image",
    "stream_to_quarantine",
]
