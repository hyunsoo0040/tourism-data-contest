"""Derive a new append-only rights review from an existing exact-four review offline."""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import sys
import tempfile
from collections.abc import Container
from pathlib import Path
from stat import S_ISDIR, S_ISREG

from pydantic import ValidationError

from itda.cli.freeze_preview import (
    PublicationStateUncertainError,
    prepared_directory_snapshot,
)
from itda.contracts.candidate_review import (
    CHECK_RESOLVED,
    RawProviderBundle,
    _legacy_v1_review,
    _reconstructed_source_review_manifest_bytes,
    build_review_manifest_from_bytes,
    build_rights_review,
    canonical_json_bytes,
    check_review_manifest,
    load_preview_source_lock,
    render_candidate_review_markdown,
    sha256_bytes,
)

_REVIEW_ARTIFACT_NAMES = (
    "raw-provider-bundle.redacted.json",
    "candidate-review.json",
    "candidate-review.md",
    "review-manifest.json",
)

# Module-local seam for source-open race tests. Capability detection must keep
# consulting the real ``os.open`` member recorded by ``os.supports_dir_fd``.
_open = os.open


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-review-manifest", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _require_secure_source_read_capabilities() -> tuple[int, int]:
    """Return required flags only when pinned source reads are fully supported."""

    missing: list[str] = []
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(directory_flag, int) or directory_flag == 0:
        missing.append("O_DIRECTORY")
    if not isinstance(nofollow_flag, int) or nofollow_flag == 0:
        missing.append("O_NOFOLLOW")

    supports_dir_fd: Container[object] = getattr(os, "supports_dir_fd", ())
    supports_follow_symlinks: Container[object] = getattr(os, "supports_follow_symlinks", ())
    supports_fd: Container[object] = getattr(os, "supports_fd", ())
    if os.open not in supports_dir_fd:
        missing.append("os.open(dir_fd)")
    if os.stat not in supports_dir_fd:
        missing.append("os.stat(dir_fd)")
    if os.stat not in supports_follow_symlinks:
        missing.append("os.stat(follow_symlinks=False)")
    if os.listdir not in supports_fd:
        missing.append("os.listdir(fd)")
    if missing:
        raise ValueError(
            "platform lacks required secure source read capabilities: " + ", ".join(missing)
        )
    assert isinstance(directory_flag, int)
    assert isinstance(nofollow_flag, int)
    return directory_flag, nofollow_flag


def _read_regular_bytes_once(directory_descriptor: int, name: str) -> bytes:
    """Read one non-symlink regular file through its validated descriptor."""

    _, nofollow_flag = _require_secure_source_read_capabilities()
    try:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not S_ISREG(metadata.st_mode):
            raise ValueError(f"{name} must be a regular non-symlink file")
    except FileNotFoundError:
        raise ValueError(f"{name} must be a regular non-symlink file") from None
    flags = os.O_RDONLY | nofollow_flag
    descriptor = _open(name, flags, dir_fd=directory_descriptor)
    try:
        opened = os.fstat(descriptor)
        if (
            not S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or opened.st_size != metadata.st_size
        ):
            raise ValueError(f"{name} changed between stat and open")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read()
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) or len(payload) != opened.st_size:
            raise ValueError(f"{name} changed while being read")
        if not S_ISREG(after.st_mode):
            raise ValueError(f"{name} must be a regular non-symlink file")
        return payload
    finally:
        os.close(descriptor)


def _read_source_snapshot(source_manifest: Path) -> dict[str, bytes]:
    directory_flag, nofollow_flag = _require_secure_source_read_capabilities()
    if source_manifest.name != "review-manifest.json":
        raise ValueError("source review manifest must use the exact artifact name")
    source_root = source_manifest.parent
    flags = os.O_RDONLY | directory_flag | nofollow_flag
    directory_descriptor = _open(source_root, flags)
    try:
        if not S_ISDIR(os.fstat(directory_descriptor).st_mode):
            raise ValueError("source review root must be a regular non-symlink directory")
        entries = tuple(sorted(os.listdir(directory_descriptor)))
        if entries != tuple(sorted(_REVIEW_ARTIFACT_NAMES)):
            raise ValueError("source review must contain the exact four review artifacts")
        return {
            name: _read_regular_bytes_once(directory_descriptor, name)
            for name in _REVIEW_ARTIFACT_NAMES
        }
    finally:
        os.close(directory_descriptor)


def _write_durable_file(path: Path, payload: bytes) -> None:
    _, nofollow_flag = _require_secure_source_read_capabilities()
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | nofollow_flag,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(source: Path, target: Path) -> None:
    """Publish with a kernel no-replace primitive or fail closed.

    Linux uses ``renameat2(RENAME_NOREPLACE)`` and Darwin uses
    ``renameatx_np(RENAME_EXCL)``. Both names are resolved relative to one
    pinned parent descriptor, so a concurrent winner is never overwritten.
    """

    if source.parent.resolve(strict=True) != target.parent.resolve(strict=True):
        raise ValueError("atomic publication paths must share the same parent")
    library = ctypes.CDLL(None, use_errno=True)
    directory_flag, nofollow_flag = _require_secure_source_read_capabilities()
    parent_descriptor = os.open(
        source.parent,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    source_bytes = os.fsencode(source.name)
    target_bytes = os.fsencode(target.name)
    try:
        if hasattr(library, "renameat2"):
            renameat2 = library.renameat2
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                parent_descriptor,
                source_bytes,
                parent_descriptor,
                target_bytes,
                1,
            )
        elif hasattr(library, "renameatx_np"):
            renameatx_np = library.renameatx_np
            renameatx_np.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameatx_np.restype = ctypes.c_int
            result = renameatx_np(
                parent_descriptor,
                source_bytes,
                parent_descriptor,
                target_bytes,
                0x00000004,
            )
        else:
            raise OSError(
                "platform does not provide atomic no-replace directory rename; publication refused"
            )
    finally:
        os.close(parent_descriptor)
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == 0:
            raise OSError("atomic no-replace directory rename failed")
        raise OSError(error_number, os.strerror(error_number))


def derive_rights_review(
    *,
    source_manifest: Path,
    source_lock_path: Path,
    output: Path,
) -> None:
    source_lock = load_preview_source_lock(source_lock_path)
    requested_parent = output.parent
    requested_parent.mkdir(parents=True, exist_ok=True)
    if requested_parent.is_symlink() or not S_ISDIR(requested_parent.lstat().st_mode):
        raise ValueError("output parent must be a regular non-symlink directory")
    output_parent = requested_parent.resolve(strict=True)
    output = output_parent / output.name
    if os.path.lexists(output):
        raise FileExistsError("output already exists; rights review publication is immutable")

    source_bytes = _read_source_snapshot(source_manifest)
    source_snapshot = Path(tempfile.mkdtemp(prefix=f".{output.name}.source-", dir=output_parent))
    prepared = Path(tempfile.mkdtemp(prefix=f".{output.name}.publish-", dir=output_parent))
    os.chmod(source_snapshot, 0o700)
    os.chmod(prepared, 0o700)
    published = False
    preserve_uncertain_state = False
    try:
        for name in _REVIEW_ARTIFACT_NAMES:
            _write_durable_file(source_snapshot / name, source_bytes[name])
        checked = check_review_manifest(
            source_snapshot / "review-manifest.json",
            source_lock=source_lock,
        )
        if (
            checked.exit_code != CHECK_RESOLVED
            or checked.review is None
            or checked.bundle_path is None
        ):
            raise ValueError(f"source review is not exact-four and resolved: {checked.reason}")
        bundle_bytes = source_bytes["raw-provider-bundle.redacted.json"]
        bundle = RawProviderBundle.model_validate_json(bundle_bytes)
        if checked.review.rights_review is None:
            legacy_review = checked.review
            canonical_candidate_bytes = canonical_json_bytes(
                legacy_review.model_dump(mode="json", exclude={"rights_review"})
            )
            canonical_markdown_bytes = render_candidate_review_markdown(
                legacy_review,
                bundle,
            )
            canonical_manifest_bytes = build_review_manifest_from_bytes(
                bundle_bytes=bundle_bytes,
                candidate_bytes=canonical_candidate_bytes,
                markdown_bytes=canonical_markdown_bytes,
            )
            if (
                source_bytes["candidate-review.json"] != canonical_candidate_bytes
                or source_bytes["candidate-review.md"] != canonical_markdown_bytes
                or source_bytes["review-manifest.json"] != canonical_manifest_bytes
            ):
                raise ValueError("source v1 review is not the canonical exact-four snapshot")
            source_review_manifest_sha256 = sha256_bytes(canonical_manifest_bytes)
        elif checked.review.rights_review.policy_version == "official-public-data-contest-v1":
            legacy_review = _legacy_v1_review(checked.review)
            reconstructed_manifest = _reconstructed_source_review_manifest_bytes(
                review=checked.review,
                bundle=bundle,
                bundle_bytes=bundle_bytes,
            )
            source_review_manifest_sha256 = sha256_bytes(reconstructed_manifest)
            if (
                checked.review.rights_review.source_review_manifest_sha256
                != source_review_manifest_sha256
            ):
                raise ValueError("legacy rights review source binding is invalid")
        else:
            raise ValueError("source review already contains the current rights decision")
        reviewed = build_rights_review(
            legacy_review,
            bundle,
            source_review_manifest_sha256=source_review_manifest_sha256,
        )
        review_bytes = canonical_json_bytes(reviewed.model_dump(mode="json"))
        markdown_bytes = render_candidate_review_markdown(reviewed, bundle)
        _write_durable_file(
            prepared / "raw-provider-bundle.redacted.json",
            bundle_bytes,
        )
        _write_durable_file(prepared / "candidate-review.json", review_bytes)
        _write_durable_file(prepared / "candidate-review.md", markdown_bytes)
        manifest_bytes = build_review_manifest_from_bytes(
            bundle_bytes=bundle_bytes,
            candidate_bytes=review_bytes,
            markdown_bytes=markdown_bytes,
        )
        _write_durable_file(prepared / "review-manifest.json", manifest_bytes)
        _fsync_directory(prepared)
        directory_flag, nofollow_flag = _require_secure_source_read_capabilities()
        parent_descriptor = os.open(
            output_parent,
            os.O_RDONLY | directory_flag | nofollow_flag,
        )
        try:
            with prepared_directory_snapshot(prepared) as prepared_snapshot:
                with tempfile.TemporaryDirectory(prefix=".rights-validation-") as validation_parent:
                    validation_root = Path(validation_parent) / "review"
                    prepared_snapshot.materialize(validation_root)
                    verified = check_review_manifest(
                        validation_root / "review-manifest.json",
                        source_lock=source_lock,
                    )
                if verified.exit_code != CHECK_RESOLVED:
                    raise ValueError(
                        f"derived rights review failed canonical verification: {verified.reason}"
                    )
                try:
                    prepared_snapshot.verify_visible(parent_descriptor, prepared.name)
                except OSError as identity_error:
                    preserve_uncertain_state = True
                    raise PublicationStateUncertainError(
                        "rights review publication state is uncertain before rename"
                    ) from identity_error
                try:
                    _rename_directory_noreplace(prepared, output)
                except OSError as rename_error:
                    try:
                        prepared_snapshot.verify_visible(parent_descriptor, prepared.name)
                    except OSError as identity_error:
                        preserve_uncertain_state = True
                        raise PublicationStateUncertainError(
                            "rights review publication state is uncertain after rename failure"
                        ) from identity_error
                    raise rename_error
                try:
                    prepared_snapshot.verify_visible(parent_descriptor, output.name)
                    os.fsync(parent_descriptor)
                except OSError as commit_error:
                    preserve_uncertain_state = True
                    raise PublicationStateUncertainError(
                        "rights review publication state is uncertain after identity "
                        "or durability failure"
                    ) from commit_error
        finally:
            os.close(parent_descriptor)
        published = True
    finally:
        shutil.rmtree(source_snapshot, ignore_errors=True)
        if not published and not preserve_uncertain_state:
            shutil.rmtree(prepared, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        derive_rights_review(
            source_manifest=args.source_review_manifest,
            source_lock_path=args.source_lock,
            output=args.output,
        )
    except (OSError, ValueError, ValidationError) as exc:
        print(f"offline rights review refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["derive_rights_review", "main"]
