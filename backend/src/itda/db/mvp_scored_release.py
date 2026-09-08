"""Atomic immutable store for public MVP scored releases."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from itda.contracts.mvp_scored_release import MvpActivePointer, MvpScoredRelease
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
PRODUCTION_ROOT = REPOSITORY_ROOT / "artifacts/public/catalog/mvp-scored-releases"
_MAX_RELEASE_BYTES = 16 * 1024 * 1024
_MAX_POINTER_BYTES = 4 * 1024


class MvpScoredReleaseError(RuntimeError):
    pass


def _reject_symlinks(path: Path) -> None:
    cursor = path.absolute()
    while True:
        if cursor.is_symlink():
            raise MvpScoredReleaseError("MVP_RELEASE_PATH_SYMLINK")
        if cursor.parent == cursor:
            return
        cursor = cursor.parent


def _open_directory_chain(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor or os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise MvpScoredReleaseError("MVP_RELEASE_PATH_SYMLINK") from error


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    parent_descriptor = _open_directory_chain(path.parent)
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise MvpScoredReleaseError("MVP_RELEASE_FILE_INVALID") from error
    finally:
        os.close(parent_descriptor)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum_bytes:
            raise MvpScoredReleaseError("MVP_RELEASE_FILE_INVALID")
        payload = os.read(descriptor, metadata.st_size + 1)
        if len(payload) != metadata.st_size:
            raise MvpScoredReleaseError("MVP_RELEASE_FILE_CHANGED")
        return payload
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_atomic(path: Path, payload: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class MvpScoredReleaseStore:
    def __init__(self, root: Path = PRODUCTION_ROOT) -> None:
        self._root = root

    @property
    def root(self) -> Path:
        return self._root

    @contextmanager
    def _locked(self) -> Iterator[None]:
        _reject_symlinks(self._root)
        self._root.mkdir(parents=True, exist_ok=True)
        lock = self._root / ".lock"
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def publish(self, release: MvpScoredRelease) -> Path:
        validated = MvpScoredRelease.model_validate(release.model_dump(mode="json"))
        payload = canonical_json_bytes(validated.model_dump(mode="json")) + b"\n"
        if len(payload) > _MAX_RELEASE_BYTES:
            raise MvpScoredReleaseError("MVP_RELEASE_TOO_LARGE")
        with self._locked():
            releases = self._root / "releases"
            _reject_symlinks(releases)
            releases.mkdir(exist_ok=True)
            destination = releases / validated.release_sha256
            if destination.exists():
                existing = self.resolve_release(validated.release_sha256)
                if existing != validated:
                    raise MvpScoredReleaseError("MVP_RELEASE_DIGEST_COLLISION")
                return destination
            temporary = Path(tempfile.mkdtemp(prefix=".release.", dir=releases))
            try:
                _write_atomic(temporary / "release.json", payload)
                os.rename(temporary, destination)
                _fsync_directory(releases)
            finally:
                if temporary.exists():
                    for child in temporary.iterdir():
                        child.unlink()
                    temporary.rmdir()
        return destination

    def resolve_release(self, release_sha256: str) -> MvpScoredRelease:
        if len(release_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in release_sha256
        ):
            raise MvpScoredReleaseError("MVP_RELEASE_ID_INVALID")
        path = self._root / "releases" / release_sha256 / "release.json"
        try:
            release = MvpScoredRelease.model_validate_json(
                _read_regular(path, maximum_bytes=_MAX_RELEASE_BYTES)
            )
        except (FileNotFoundError, OSError, ValidationError, ValueError) as error:
            raise MvpScoredReleaseError("MVP_RELEASE_INVALID") from error
        if release.release_sha256 != release_sha256:
            raise MvpScoredReleaseError("MVP_RELEASE_PATH_DIGEST_MISMATCH")
        return release

    def active_pointer(self) -> MvpActivePointer | None:
        path = self._root / "active.json"
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            raise MvpScoredReleaseError("MVP_ACTIVE_POINTER_INVALID")
        try:
            return MvpActivePointer.model_validate_json(
                _read_regular(path, maximum_bytes=_MAX_POINTER_BYTES)
            )
        except (OSError, ValidationError, ValueError) as error:
            raise MvpScoredReleaseError("MVP_ACTIVE_POINTER_INVALID") from error

    def activate(self, release_sha256: str, *, expected_current: str | None) -> MvpActivePointer:
        with self._locked():
            current = self.active_pointer()
            current_sha = current.release_sha256 if current else None
            if current_sha != expected_current:
                raise MvpScoredReleaseError("MVP_ACTIVE_POINTER_CAS_MISMATCH")
            self.resolve_release(release_sha256)
            fields = {
                "schema_version": "mvp-scored-release-active.v1",
                "release_sha256": release_sha256,
                "previous_release_sha256": current_sha,
            }
            pointer = MvpActivePointer(
                **fields,
                pointer_sha256=canonical_sha256(fields),
            )
            _write_atomic(
                self._root / "active.json",
                canonical_json_bytes(pointer.model_dump(mode="json")) + b"\n",
            )
            return pointer

    def resolve_active(self) -> MvpScoredRelease:
        pointer = self.active_pointer()
        if pointer is None:
            raise MvpScoredReleaseError("NO_ACTIVE_MVP_SCORED_RELEASE")
        return self.resolve_release(pointer.release_sha256)

    def rollback(self, *, expected_current: str) -> MvpActivePointer:
        current = self.active_pointer()
        if current is None or current.release_sha256 != expected_current:
            raise MvpScoredReleaseError("MVP_ACTIVE_POINTER_CAS_MISMATCH")
        previous = current.previous_release_sha256
        if previous is None:
            raise MvpScoredReleaseError("MVP_ROLLBACK_TARGET_MISSING")
        return self.activate(previous, expected_current=expected_current)


def resolve_active_mvp_scored_release() -> MvpScoredRelease | None:
    try:
        return MvpScoredReleaseStore().resolve_active()
    except (OSError, MvpScoredReleaseError, ValidationError, ValueError):
        return None
