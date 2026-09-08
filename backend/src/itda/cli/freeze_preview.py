"""Fail-closed approval validator and atomic PREVIEW artifact publisher."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from stat import S_ISDIR, S_ISREG
from typing import Any

from pydantic import ValidationError

from itda.contracts.candidate_review import (
    CHECK_RESOLVED,
    LOCKED_PREVIEW_CANDIDATES,
    ApprovedPreviewIdentity,
    CandidateReview,
    FreezeApproval,
    PreviewSourceLockSnapshot,
    RawProviderBundle,
    check_approved_review_manifest,
    load_preview_source_lock_snapshot,
    sha256_bytes,
)

_PIPELINE_STAGE_ORDER = (
    "collect",
    "normalize",
    "analyze",
    "fuse",
    "publish",
    "recommend",
    "evaluate",
)


class PublicationStateUncertainError(OSError):
    """Raised after publication when ownership-safe cleanup is no longer possible."""


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
    )


def open_directory_chain_no_follow(path: Path, *, create: bool = False) -> int:
    """Open a directory path component-by-component without following ancestors."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise ValueError("platform lacks secure directory descriptor capabilities")
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor or os.sep, directory_flags)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, directory_flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("directory path contains a symlink or non-directory") from error
        raise


def _read_descriptor_bytes(descriptor: int, expected_size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = expected_size + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 65_536))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _close_descriptors_preserving_error(descriptors: Iterable[int]) -> None:
    """Attempt every close without replacing an exception already in flight."""

    active_error = sys.exception()
    close_errors: list[BaseException] = []
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except BaseException as close_error:
            close_errors.append(close_error)
    if not close_errors:
        return
    if active_error is not None:
        for teardown_error in close_errors:
            active_error.add_note(f"descriptor close failed during teardown: {teardown_error}")
        return
    raise close_errors[0]


@dataclass(frozen=True)
class PreparedDirectorySnapshot:
    """Descriptor-pinned bytes and metadata retained through publication."""

    root_descriptor: int
    directory_descriptors: dict[str, int]
    directory_entries: dict[str, tuple[str, ...]]
    directory_identities: dict[str, tuple[int, ...]]
    directory_locations: dict[str, tuple[str, str]]
    directory_signatures: dict[str, tuple[int, ...]]
    file_descriptors: dict[str, int]
    file_locations: dict[str, tuple[str, str]]
    file_signatures: dict[str, tuple[int, ...]]
    files: dict[str, bytes]

    @property
    def root_identity(self) -> tuple[int, ...]:
        return self.directory_identities[""]

    def materialize(self, root: Path) -> None:
        root.mkdir()
        for relative in sorted(
            (name for name in self.directory_descriptors if name),
            key=lambda name: (name.count("/"), name),
        ):
            (root / relative).mkdir()
        for relative, payload in self.files.items():
            (root / relative).write_bytes(payload)

    def verify_contents(self) -> None:
        for relative, descriptor in self.directory_descriptors.items():
            if _directory_identity(os.fstat(descriptor)) != self.directory_identities[relative]:
                raise OSError("prepared directory identity changed during validation")
            if tuple(sorted(os.listdir(descriptor))) != self.directory_entries[relative]:
                raise OSError("prepared directory entries changed during validation")
            if relative:
                parent_relative, name = self.directory_locations[relative]
                parent_descriptor = self.directory_descriptors[parent_relative]
                visible = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                if (
                    _metadata_signature(os.fstat(descriptor)) != self.directory_signatures[relative]
                    or _metadata_signature(visible) != self.directory_signatures[relative]
                ):
                    raise OSError("prepared child directory changed during validation")
        for relative, descriptor in self.file_descriptors.items():
            parent_relative, name = self.file_locations[relative]
            parent_descriptor = self.directory_descriptors[parent_relative]
            visible = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                _metadata_signature(os.fstat(descriptor)) != self.file_signatures[relative]
                or _metadata_signature(visible) != self.file_signatures[relative]
                or _read_descriptor_bytes(descriptor, visible.st_size) != self.files[relative]
            ):
                raise OSError("prepared artifact changed during validation")

    def verify_visible(self, parent_descriptor: int, name: str) -> None:
        visible_root = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if _directory_identity(visible_root) != self.root_identity:
            raise OSError("visible publication root does not match the validated directory")
        self.verify_contents()


@contextmanager
def prepared_directory_snapshot(
    root: Path,
    *,
    parent_descriptor: int | None = None,
) -> Iterator[PreparedDirectorySnapshot]:
    """Pin a bounded regular tree until its publisher has verified the final name."""

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise ValueError("platform lacks secure prepared-directory snapshot capabilities")
    root_descriptor = (
        os.open(
            root.name,
            os.O_RDONLY | directory_flag | nofollow_flag,
            dir_fd=parent_descriptor,
        )
        if parent_descriptor is not None
        else os.open(root, os.O_RDONLY | directory_flag | nofollow_flag)
    )
    directory_descriptors: dict[str, int] = {"": root_descriptor}
    directory_entries: dict[str, tuple[str, ...]] = {}
    directory_identities: dict[str, tuple[int, ...]] = {}
    directory_locations: dict[str, tuple[str, str]] = {}
    directory_signatures: dict[str, tuple[int, ...]] = {}
    file_descriptors: dict[str, int] = {}
    file_locations: dict[str, tuple[str, str]] = {}
    file_signatures: dict[str, tuple[int, ...]] = {}
    files: dict[str, bytes] = {}

    def visit(relative: str, descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if not S_ISDIR(metadata.st_mode):
            raise ValueError("prepared publication root must be a regular directory")
        directory_identities[relative] = _directory_identity(metadata)
        names = tuple(sorted(os.listdir(descriptor)))
        directory_entries[relative] = names
        for name in names:
            child_relative = f"{relative}/{name}" if relative else name
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if S_ISDIR(before.st_mode):
                child_descriptor = os.open(
                    name,
                    os.O_RDONLY | directory_flag | nofollow_flag,
                    dir_fd=descriptor,
                )
                try:
                    directory_descriptors[child_relative] = child_descriptor
                    opened = os.fstat(child_descriptor)
                    if _directory_identity(opened) != _directory_identity(before):
                        raise ValueError("prepared directory changed before snapshot")
                    directory_locations[child_relative] = (relative, name)
                    directory_signatures[child_relative] = _metadata_signature(opened)
                    visit(child_relative, child_descriptor)
                except BaseException:
                    if child_relative not in directory_descriptors:
                        _close_descriptors_preserving_error((child_descriptor,))
                    raise
            elif S_ISREG(before.st_mode) and before.st_nlink == 1:
                file_descriptor = os.open(
                    name,
                    os.O_RDONLY | nofollow_flag,
                    dir_fd=descriptor,
                )
                try:
                    file_descriptors[child_relative] = file_descriptor
                    opened = os.fstat(file_descriptor)
                    if (
                        _metadata_signature(opened) != _metadata_signature(before)
                        or opened.st_size > _MAX_FROZEN_ARTIFACT_BYTES
                    ):
                        raise ValueError("prepared artifact changed before snapshot")
                    payload = _read_descriptor_bytes(file_descriptor, opened.st_size)
                    after = os.fstat(file_descriptor)
                    if len(payload) != opened.st_size or _metadata_signature(
                        after
                    ) != _metadata_signature(opened):
                        raise ValueError("prepared artifact changed during snapshot")
                except BaseException:
                    if child_relative not in file_descriptors:
                        _close_descriptors_preserving_error((file_descriptor,))
                    raise
                file_locations[child_relative] = (relative, name)
                file_signatures[child_relative] = _metadata_signature(opened)
                files[child_relative] = payload
            else:
                raise ValueError("prepared publication rejects symlinks and special entries")

    try:
        visit("", root_descriptor)
        snapshot = PreparedDirectorySnapshot(
            root_descriptor=root_descriptor,
            directory_descriptors=directory_descriptors,
            directory_entries=directory_entries,
            directory_identities=directory_identities,
            directory_locations=directory_locations,
            directory_signatures=directory_signatures,
            file_descriptors=file_descriptors,
            file_locations=file_locations,
            file_signatures=file_signatures,
            files=files,
        )
        yield snapshot
    finally:
        _close_descriptors_preserving_error(
            (
                *file_descriptors.values(),
                *(descriptor for relative, descriptor in directory_descriptors.items() if relative),
                root_descriptor,
            )
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-approved", action="store_true", required=True)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--review-manifest", required=True, type=Path)
    parser.add_argument("--source-lock", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )


def _update_directory_digest_record(
    digest: Any,
    *,
    kind: bytes,
    relative: str,
    payload: bytes | None = None,
) -> None:
    encoded = relative.encode("utf-8")
    digest.update(kind)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    if payload is not None:
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)


def _directory_digest(directory: Path) -> str:
    """Hash a descriptor-pinned regular tree, including empty dirs and every filename."""

    digest = hashlib.sha256()
    digest.update(b"itda-directory-digest-v2\0")
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise ValueError("platform lacks secure directory digest capabilities")
    root_descriptor = os.open(
        directory,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    try:
        if not S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise ValueError("immutable publication root must be a regular directory")

        def visit(directory_descriptor: int, prefix: str) -> None:
            opened_directory = os.fstat(directory_descriptor)
            names = sorted(os.listdir(directory_descriptor))
            for name in names:
                relative = f"{prefix}/{name}" if prefix else name
                before = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if S_ISDIR(before.st_mode):
                    _update_directory_digest_record(
                        digest,
                        kind=b"D",
                        relative=relative,
                    )
                    child = os.open(
                        name,
                        os.O_RDONLY | directory_flag | nofollow_flag,
                        dir_fd=directory_descriptor,
                    )
                    try:
                        child_opened = os.fstat(child)
                        if (child_opened.st_dev, child_opened.st_ino) != (
                            before.st_dev,
                            before.st_ino,
                        ):
                            raise ValueError("immutable directory changed before traversal")
                        visit(child, relative)
                    finally:
                        os.close(child)
                elif S_ISREG(before.st_mode):
                    if before.st_nlink != 1:
                        raise ValueError("immutable files must not have external hard links")
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | nofollow_flag,
                        dir_fd=directory_descriptor,
                    )
                    try:
                        opened = os.fstat(descriptor)
                        if (
                            not S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or (opened.st_dev, opened.st_ino, opened.st_size)
                            != (before.st_dev, before.st_ino, before.st_size)
                        ):
                            raise ValueError("immutable file changed before read")
                        with os.fdopen(descriptor, "rb", closefd=False) as handle:
                            payload = handle.read()
                        after = os.fstat(descriptor)
                        if (
                            after.st_dev,
                            after.st_ino,
                            after.st_size,
                            after.st_mtime_ns,
                        ) != (
                            opened.st_dev,
                            opened.st_ino,
                            opened.st_size,
                            opened.st_mtime_ns,
                        ) or len(payload) != opened.st_size:
                            raise ValueError("immutable file changed while being read")
                    finally:
                        os.close(descriptor)
                    _update_directory_digest_record(
                        digest,
                        kind=b"F",
                        relative=relative,
                        payload=payload,
                    )
                else:
                    raise ValueError("immutable publication rejects symlink and special entries")
            after_directory = os.fstat(directory_descriptor)
            if (
                after_directory.st_dev,
                after_directory.st_ino,
                after_directory.st_mtime_ns,
                after_directory.st_ctime_ns,
            ) != (
                opened_directory.st_dev,
                opened_directory.st_ino,
                opened_directory.st_mtime_ns,
                opened_directory.st_ctime_ns,
            ):
                raise ValueError("immutable directory changed during traversal")

        visit(root_descriptor, "")
    finally:
        os.close(root_descriptor)
    return digest.hexdigest()


def _rename_noreplace_at(
    source_parent_descriptor: int,
    source_name: str,
    destination_parent_descriptor: int,
    destination_name: str,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
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
            source_parent_descriptor,
            source_bytes,
            destination_parent_descriptor,
            destination_bytes,
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
            source_parent_descriptor,
            source_bytes,
            destination_parent_descriptor,
            destination_bytes,
            0x00000004,
        )
    else:
        raise OSError("platform does not provide atomic no-replace publication")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def publish_immutable_directory(
    *,
    prepared: Path,
    output: Path,
    snapshot: PreparedDirectorySnapshot | None = None,
    output_parent_descriptor: int | None = None,
) -> None:
    """Publish one validated directory directly with an atomic no-replace rename."""

    if output_parent_descriptor is None:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.parent.is_symlink() or not output.parent.is_dir():
            raise ValueError("output parent must be a regular non-symlink directory")
        if prepared.is_symlink() or not prepared.is_dir():
            raise ValueError("prepared output must be a regular non-symlink directory")
        if prepared.parent.resolve(strict=True) != output.parent.resolve(strict=True):
            raise ValueError("prepared and output directories must share one pinned parent")
        if os.path.lexists(output):
            raise FileExistsError("output already exists; publication is immutable")
    elif snapshot is None:
        raise ValueError("a pinned snapshot is required with a pinned output parent")

    if snapshot is None:
        _fsync_tree(prepared)
        with prepared_directory_snapshot(prepared) as captured:
            publish_immutable_directory(
                prepared=prepared,
                output=output,
                snapshot=captured,
            )
        return

    parent_descriptor = (
        os.dup(output_parent_descriptor)
        if output_parent_descriptor is not None
        else os.open(
            output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
        )
    )
    try:
        try:
            snapshot.verify_visible(parent_descriptor, prepared.name)
            _rename_noreplace_at(
                parent_descriptor,
                prepared.name,
                parent_descriptor,
                output.name,
            )
            snapshot.verify_visible(parent_descriptor, output.name)
            os.fsync(parent_descriptor)
        except FileExistsError:
            raise
        except OSError as commit_error:
            raise PublicationStateUncertainError(
                "pipeline publication state is uncertain after identity or durability failure"
            ) from commit_error
    finally:
        os.close(parent_descriptor)


_APPROVAL_FIELDS = (
    "schema_version",
    "approval_signal",
    "status",
    "canonical_candidate_review_sha256",
    "canonical_candidate_review_markdown_sha256",
    "canonical_source_lock_sha256",
    "approved_redacted_provider_bundle_sha256",
    "approved_review_manifest_sha256",
    "approved_candidate_identities",
    "rights_acknowledgement_version",
    "reviewer",
    "approved_at",
)
_FINAL_DIRECTORIES = ("raw", "sanitized", "normalized")
_FINAL_FILES = ("manifest.json", "stage-manifest.json")


def _parse_approval_bytes(payload: bytes) -> FreezeApproval:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise ValueError("APPROVAL.md must be valid UTF-8") from None
    values: dict[str, object] = {}
    for line in lines:
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", maxsplit=1))
        if key not in _APPROVAL_FIELDS or key in values or not value:
            raise ValueError("APPROVAL.md contains unknown, duplicate, or empty fields")
        if key == "approved_candidate_identities":
            try:
                values[key] = json.loads(value)
            except json.JSONDecodeError:
                raise ValueError("approved candidate identities must be canonical JSON") from None
        else:
            values[key] = value
    if tuple(values) != _APPROVAL_FIELDS:
        raise ValueError("APPROVAL.md fields must appear once in the exact contract order")
    return FreezeApproval.model_validate(values)


def parse_approval_markdown(path: Path) -> FreezeApproval:
    return _parse_approval_bytes(path.read_bytes())


def _lineage_hash(stage: str, output_hash: str) -> str:
    return sha256_bytes(_canonical_json_bytes([{"output_hash": output_hash, "stage": stage}]))


def _stage_manifest(*, source_hash: str, raw_hash: str, normalized_hash: str) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    previous_stage: str | None = None
    previous_hash: str | None = None
    for stage in _PIPELINE_STAGE_ORDER:
        if previous_stage is None or previous_hash is None:
            input_hash = source_hash
            lineage: list[dict[str, str]] = []
        else:
            input_hash = _lineage_hash(previous_stage, previous_hash)
            lineage = [{"stage": previous_stage, "output_hash": previous_hash}]
        if stage == "collect":
            status = "MATERIALIZED"
            artifact_path: str | None = "raw/six-places.json"
            output_hash = raw_hash
            proof: dict[str, object] | None = None
        elif stage == "normalize":
            status = "MATERIALIZED"
            artifact_path = "normalized/six-places.json"
            output_hash = normalized_hash
            proof = None
        else:
            status = "NOT_SCORED"
            artifact_path = None
            proof = {
                "executed": True,
                "reason": "DEFERRED_PHASE_1_CONTRACT_ONLY",
                "result_emitted": False,
            }
            output_hash = sha256_bytes(
                _canonical_json_bytes(
                    {
                        "input_hash": input_hash,
                        "procedure_proof": proof,
                        "stage": stage,
                        "status": status,
                    }
                )
            )
        rows.append(
            {
                "artifact_path": artifact_path,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "procedure_proof": proof,
                "stage": stage,
                "status": status,
                "upstream_lineage": lineage,
            }
        )
        previous_stage = stage
        previous_hash = output_hash
    return {
        "schema_version": "frozen-preview-stage-manifest-v1",
        "source_input_hash": source_hash,
        "stages": rows,
    }


def _prepare_final_boundary(
    *,
    approval: FreezeApproval,
    approval_bytes: bytes,
    review_manifest_bytes: bytes,
    review: CandidateReview,
    bundle_bytes: bytes,
    bundle: RawProviderBundle,
    temporary: Path,
) -> None:
    if (
        review.schema_version != "candidate-review-v2"
        or review.rights_review is None
        or review.rights_review.policy_version != "official-public-data-contest-v2"
    ):
        raise ValueError("current validated candidate-review-v2 rights decision is required")
    grouped: dict[str, list[dict[str, object]]] = {
        candidate.place_id: [] for candidate in review.candidates
    }
    for row in bundle.rows:
        grouped[row.candidate_place_id].append(row.model_dump(mode="json"))
    rights_by_place = {
        disposition.place_id: disposition for disposition in review.rights_review.candidates
    }

    def permitted_sources(place_id: str) -> list[dict[str, object]]:
        rights = rights_by_place.get(place_id)
        if rights is None:
            return []
        return [
            {
                "attribution_required": disposition.attribution_required,
                "commercial_use_allowed": disposition.commercial_use_allowed,
                "dataset_id": disposition.dataset_id,
                "derivatives_allowed": disposition.derivatives_allowed,
                "license_code": disposition.license_code,
                "provider": disposition.provider.value,
                "provenance_retained": disposition.provenance_retained,
                "scope": disposition.scope.value,
                "source_id": disposition.source_id,
            }
            for disposition in (rights.tour_metadata_text, rights.odii_content)
        ]

    def disposition_assets(
        place_id: str,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        rights = rights_by_place.get(place_id)
        if rights is None:
            return [], []
        allowed: list[dict[str, object]] = []
        excluded: list[dict[str, object]] = []
        for image in (rights.representative_image, *rights.detail_images):
            common = {
                "asset_id": image.asset_id,
                "attribution_required": image.attribution_required,
                "commercial_use_allowed": image.commercial_use_allowed,
                "cpyrht_div_cd": image.cpyrht_div_cd,
                "derivatives_allowed": image.derivatives_allowed,
                "model_input_allowed": image.model_input_allowed,
                "normalized_asset_allowed": image.normalized_asset_allowed,
                "scope": image.scope.value,
                "source_id": image.source_id,
                "status": image.status.value,
                "transform_allowed": image.transform_allowed,
            }
            if image.cpyrht_div_cd == "Type1":
                if not (
                    image.derivatives_allowed
                    and image.transform_allowed
                    and image.model_input_allowed
                    and image.normalized_asset_allowed
                ):
                    raise ValueError("Type1 rights disposition must permit derivative use")
                allowed.append({**common, "source_url": image.source_url})
            else:
                if any(
                    (
                        image.derivatives_allowed,
                        image.transform_allowed,
                        image.model_input_allowed,
                        image.normalized_asset_allowed,
                    )
                ):
                    raise ValueError("Type3 rights disposition must block derivative use")
                excluded.append(
                    {
                        **common,
                        "reason": "TYPE3_ORIGINAL_DISPLAY_ONLY_NO_DERIVATIVES",
                    }
                )
        return allowed, excluded

    rights_assets = {
        candidate.place_id: disposition_assets(candidate.place_id)
        for candidate in review.candidates
    }
    raw_payload = {
        "assessment_status": "NOT_SCORED",
        "places": [
            {
                "name_ko": candidate.name_ko,
                "place_id": candidate.place_id,
                "provider_rows": grouped[candidate.place_id],
            }
            for candidate in review.candidates
        ],
        "schema_version": "preview-raw-v1",
        "split": "PREVIEW",
    }
    sanitized_payload = {
        "assessment_status": "NOT_SCORED",
        "places": [
            {
                "address_ko": candidate.address_ko,
                **(
                    {
                        "allowed_assets": rights_assets[candidate.place_id][0],
                        "allowed_sources": permitted_sources(candidate.place_id),
                        "excluded_assets": rights_assets[candidate.place_id][1],
                        "rights_policy_version": review.rights_review.policy_version,
                    }
                    if review.rights_review is not None
                    else {
                        "excluded_assets": [
                            {
                                "asset_usage_status": evidence.asset_usage_status.value,
                                "provider": evidence.provider.value,
                                "reason": "PHASE2_RIGHTS_REVIEW_REQUIRED",
                            }
                            for evidence in candidate.evidence
                        ]
                    }
                ),
                "latitude": candidate.latitude,
                "longitude": candidate.longitude,
                "name_ko": candidate.name_ko,
                "place_id": candidate.place_id,
                "provider_evidence": [
                    {
                        "endpoint": evidence.endpoint,
                        "http_status": evidence.http_status,
                        "modifiedtime": evidence.modifiedtime,
                        "provider": evidence.provider.value,
                        "raw_response_sha256": evidence.raw_response_sha256,
                        "retrieved_at": evidence.retrieved_at.isoformat().replace("+00:00", "Z"),
                        "source_id": evidence.source_id,
                    }
                    for evidence in candidate.evidence
                ],
            }
            for candidate in review.candidates
        ],
        "schema_version": "preview-sanitized-v1",
        "split": "PREVIEW",
    }
    normalized_payload = {
        "assessment_status": "NOT_SCORED",
        "places": [
            {
                "address_ko": candidate.address_ko,
                "assessment_status": candidate.assessment_status.value,
                "latitude": candidate.latitude,
                "longitude": candidate.longitude,
                "name_ko": candidate.name_ko,
                "place_id": candidate.place_id,
                "provider_ids": {
                    evidence.provider.value: evidence.source_id for evidence in candidate.evidence
                },
                **(
                    {
                        "allowed_asset_ids": [
                            asset["asset_id"] for asset in rights_assets[candidate.place_id][0]
                        ],
                        "allowed_source_scopes": [
                            source["scope"] for source in permitted_sources(candidate.place_id)
                        ],
                        "blocked_asset_ids": [
                            asset["asset_id"] for asset in rights_assets[candidate.place_id][1]
                        ],
                        "rights_policy_version": review.rights_review.policy_version,
                    }
                    if review.rights_review is not None
                    else {}
                ),
                "split": candidate.split.value,
            }
            for candidate in review.candidates
        ],
        "schema_version": "preview-normalized-v1",
        "split": "PREVIEW",
    }
    (temporary / "raw").mkdir()
    (temporary / "sanitized").mkdir()
    (temporary / "normalized").mkdir()
    raw_bytes = _canonical_json_bytes(raw_payload)
    sanitized_bytes = _canonical_json_bytes(sanitized_payload)
    normalized_bytes = _canonical_json_bytes(normalized_payload)
    (temporary / "raw" / "six-places.json").write_bytes(raw_bytes)
    (temporary / "sanitized" / "six-places.json").write_bytes(sanitized_bytes)
    (temporary / "normalized" / "six-places.json").write_bytes(normalized_bytes)
    raw_hash = sha256_bytes(raw_bytes)
    sanitized_hash = sha256_bytes(sanitized_bytes)
    normalized_hash = sha256_bytes(normalized_bytes)
    review_manifest_hash = sha256_bytes(review_manifest_bytes)
    bundle_hash = sha256_bytes(bundle_bytes)
    manifest_payload = {
        "approval_sha256": sha256_bytes(approval_bytes),
        "approved_redacted_provider_bundle_sha256": bundle_hash,
        "approved_review_manifest_sha256": review_manifest_hash,
        "approved_at": approval.approved_at.isoformat().replace("+00:00", "Z"),
        "assessment_status": "NOT_SCORED",
        "candidate_names": list(LOCKED_PREVIEW_CANDIDATES),
        "files": [
            {
                "derived_from_sha256": bundle_hash,
                "path": "raw/six-places.json",
                "sha256": raw_hash,
            },
            {
                "derived_from_sha256": raw_hash,
                "path": "sanitized/six-places.json",
                "sha256": sanitized_hash,
            },
            {
                "derived_from_sha256": sanitized_hash,
                "path": "normalized/six-places.json",
                "sha256": normalized_hash,
            },
        ],
        "reviewer": approval.reviewer,
        "schema_version": "frozen-preview-manifest-v1",
        "split": "PREVIEW",
        "status": "FROZEN_PREVIEW",
    }
    (temporary / "manifest.json").write_bytes(_canonical_json_bytes(manifest_payload))
    (temporary / "stage-manifest.json").write_bytes(
        _canonical_json_bytes(
            _stage_manifest(
                source_hash=bundle_hash,
                raw_hash=raw_hash,
                normalized_hash=normalized_hash,
            )
        )
    )


_APPROVED_REVIEW_NAMES = frozenset(
    {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
        "APPROVAL.md",
    }
)
_FROZEN_ROOT_NAMES = frozenset(
    {
        "review",
        "raw",
        "sanitized",
        "normalized",
        "manifest.json",
        "stage-manifest.json",
    }
)
_FROZEN_STAGE_DIRECTORY_NAMES = frozenset({"six-places.json"})
_FROZEN_MANIFEST_KEYS = frozenset(
    {
        "approval_sha256",
        "approved_redacted_provider_bundle_sha256",
        "approved_review_manifest_sha256",
        "approved_at",
        "assessment_status",
        "candidate_names",
        "files",
        "reviewer",
        "schema_version",
        "split",
        "status",
    }
)
_FROZEN_FILE_DESCRIPTOR_KEYS = frozenset({"derived_from_sha256", "path", "sha256"})
_STAGE_MANIFEST_KEYS = frozenset({"schema_version", "source_input_hash", "stages"})
_STAGE_ROW_KEYS = frozenset(
    {
        "artifact_path",
        "input_hash",
        "output_hash",
        "procedure_proof",
        "stage",
        "status",
        "upstream_lineage",
    }
)
_STAGE_LINEAGE_KEYS = frozenset({"output_hash", "stage"})
_PROCEDURE_PROOF_KEYS = frozenset({"executed", "reason", "result_emitted"})
_MAX_FROZEN_ARTIFACT_BYTES = 16_000_000


def _read_approved_review_snapshot(review_root: Path) -> dict[str, bytes]:
    """Read the exact approved-five boundary through one pinned directory descriptor."""

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise ValueError("platform lacks secure approved-review read capabilities")
    directory_descriptor = os.open(
        review_root,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    try:
        if not S_ISDIR(os.fstat(directory_descriptor).st_mode):
            raise ValueError("approved review root must be a regular directory")
        names = frozenset(os.listdir(directory_descriptor))
        if names != _APPROVED_REVIEW_NAMES:
            raise ValueError("approved review boundary must contain the exact five artifacts")
        snapshot: dict[str, bytes] = {}
        for name in sorted(names):
            before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if not S_ISREG(before.st_mode) or not 0 < before.st_size <= 16_000_000:
                raise ValueError("approved review artifacts must be bounded regular files")
            descriptor = os.open(
                name,
                os.O_RDONLY | nofollow_flag,
                dir_fd=directory_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if not S_ISREG(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                ) != (before.st_dev, before.st_ino, before.st_size):
                    raise ValueError("approved review artifact changed before read")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    payload = handle.read()
                after = os.fstat(descriptor)
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                ) != (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                ) or len(payload) != opened.st_size:
                    raise ValueError("approved review artifact changed while being read")
                snapshot[name] = payload
            finally:
                _close_descriptors_preserving_error((descriptor,))
        return snapshot
    finally:
        _close_descriptors_preserving_error((directory_descriptor,))


@contextmanager
def _frozen_boundary_snapshot(output_root: Path) -> Iterator[dict[str, bytes]]:
    """Yield one descriptor-pinned boundary and reject namespace changes before return."""

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        raise ValueError("platform lacks secure frozen-boundary read capabilities")
    root_descriptor = os.open(
        output_root,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    directory_descriptors: dict[str, int] = {"": root_descriptor}
    directory_signatures: dict[str, tuple[int, ...]] = {
        "": _metadata_signature(os.fstat(root_descriptor))
    }
    file_descriptors: dict[str, int] = {}
    file_signatures: dict[str, tuple[int, ...]] = {}
    file_locations: dict[str, tuple[int, str]] = {}
    snapshot: dict[str, bytes] = {}
    try:
        if not S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise ValueError("frozen output root must be a regular directory")
        if frozenset(os.listdir(root_descriptor)) != _FROZEN_ROOT_NAMES:
            raise ValueError("frozen output root has missing or extra entries")

        for directory_name, expected_names in (
            ("review", _APPROVED_REVIEW_NAMES),
            ("raw", _FROZEN_STAGE_DIRECTORY_NAMES),
            ("sanitized", _FROZEN_STAGE_DIRECTORY_NAMES),
            ("normalized", _FROZEN_STAGE_DIRECTORY_NAMES),
        ):
            before = os.stat(
                directory_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if not S_ISDIR(before.st_mode):
                raise ValueError("frozen boundary directories must not be symlinks")
            descriptor = os.open(
                directory_name,
                os.O_RDONLY | directory_flag | nofollow_flag,
                dir_fd=root_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if _metadata_signature(opened) != _metadata_signature(before):
                    raise ValueError("frozen boundary directory changed before snapshot")
                if frozenset(os.listdir(descriptor)) != expected_names:
                    raise ValueError("frozen boundary directory has missing or extra artifacts")
            except BaseException:
                _close_descriptors_preserving_error((descriptor,))
                raise
            directory_descriptors[directory_name] = descriptor
            directory_signatures[directory_name] = _metadata_signature(opened)

        locations = {
            "manifest.json": (root_descriptor, "manifest.json"),
            "stage-manifest.json": (root_descriptor, "stage-manifest.json"),
            **{
                f"review/{name}": (directory_descriptors["review"], name)
                for name in _APPROVED_REVIEW_NAMES
            },
            **{
                f"{directory}/six-places.json": (
                    directory_descriptors[directory],
                    "six-places.json",
                )
                for directory in _FINAL_DIRECTORIES
            },
        }
        for relative, (parent_descriptor, name) in locations.items():
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or not 0 < before.st_size <= _MAX_FROZEN_ARTIFACT_BYTES
            ):
                raise ValueError("frozen artifacts must be bounded unlinked regular files")
            descriptor = os.open(
                name,
                os.O_RDONLY | nofollow_flag,
                dir_fd=parent_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if _metadata_signature(opened) != _metadata_signature(before):
                    raise ValueError("frozen artifact changed before snapshot")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    payload = handle.read()
                after = os.fstat(descriptor)
                if (
                    _metadata_signature(after) != _metadata_signature(opened)
                    or len(payload) != opened.st_size
                ):
                    raise ValueError("frozen artifact changed while being read")
            except BaseException:
                _close_descriptors_preserving_error((descriptor,))
                raise
            snapshot[relative] = payload
            file_descriptors[relative] = descriptor
            file_signatures[relative] = _metadata_signature(opened)
            file_locations[relative] = (parent_descriptor, name)

        yield snapshot

        if frozenset(os.listdir(root_descriptor)) != _FROZEN_ROOT_NAMES:
            raise ValueError("frozen output root changed during validation")
        for directory_name, descriptor in directory_descriptors.items():
            if _metadata_signature(os.fstat(descriptor)) != directory_signatures[directory_name]:
                raise ValueError("frozen boundary directory changed during validation")
        for relative, descriptor in file_descriptors.items():
            parent_descriptor, name = file_locations[relative]
            visible = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                _metadata_signature(os.fstat(descriptor)) != file_signatures[relative]
                or _metadata_signature(visible) != file_signatures[relative]
                or _read_descriptor_bytes(descriptor, visible.st_size) != snapshot[relative]
            ):
                raise ValueError("frozen artifact changed during validation")
    except OSError:
        raise ValueError("frozen boundary could not be read as one stable snapshot") from None
    finally:
        _close_descriptors_preserving_error(
            (
                *file_descriptors.values(),
                *(descriptor for name, descriptor in directory_descriptors.items() if name),
                root_descriptor,
            )
        )


def _atomic_rename_directory_noreplace_at(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Publish one sibling directory without replacing any racing destination."""

    if any(
        not name or name in {".", ".."} or "/" in name or os.sep in name
        for name in (source_name, destination_name)
    ):
        raise ValueError("unsafe final publication name")
    _rename_noreplace_at(
        parent_descriptor,
        source_name,
        parent_descriptor,
        destination_name,
    )


def _fsync_tree(root: Path) -> None:
    directories = [root]
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if not S_ISDIR(current_path.lstat().st_mode):
            raise ValueError("durable tree directories must not be symlinks or special files")
        for name in sorted(directory_names):
            path = current_path / name
            if not S_ISDIR(path.lstat().st_mode):
                raise ValueError("durable tree directories must not be symlinks or special files")
            directories.append(path)
        for name in sorted(file_names):
            path = current_path / name
            if not S_ISREG(path.lstat().st_mode):
                raise ValueError("durable tree files must be regular non-symlink files")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _publish_final_boundary(
    *,
    prepared: Path,
    output_root: Path,
    snapshot: PreparedDirectorySnapshot,
) -> None:
    if prepared.is_symlink() or not prepared.is_dir():
        raise ValueError("prepared boundary must be a regular directory")
    if os.path.lexists(output_root):
        raise FileExistsError("frozen output already exists; publication is immutable")
    if prepared.parent.resolve(strict=True) != output_root.parent.resolve(strict=True):
        raise ValueError("prepared and final boundaries must share one pinned parent")
    parent_descriptor = os.open(
        output_root.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW,
    )
    try:
        try:
            snapshot.verify_visible(parent_descriptor, prepared.name)
            _atomic_rename_directory_noreplace_at(
                parent_descriptor,
                prepared.name,
                output_root.name,
            )
            snapshot.verify_visible(parent_descriptor, output_root.name)
            os.fsync(parent_descriptor)
        except OSError as commit_error:
            raise PublicationStateUncertainError(
                "frozen boundary publication state is uncertain after identity "
                "or durability failure"
            ) from commit_error
    finally:
        os.close(parent_descriptor)


def _approved_identities(review: CandidateReview) -> tuple[ApprovedPreviewIdentity, ...]:
    if review.rights_review is None:
        raise ValueError("approved identities require a current rights review")
    identities: list[ApprovedPreviewIdentity] = []
    for candidate, rights in zip(
        review.candidates,
        review.rights_review.candidates,
        strict=True,
    ):
        tour_source_id = candidate.evidence[0].source_id
        story = rights.selected_odii_story
        if tour_source_id is None or story is None:
            raise ValueError("approved identity is missing TourAPI or Odii story identity")
        identities.append(
            ApprovedPreviewIdentity(
                place_id=candidate.place_id,
                name_ko=candidate.name_ko,
                tour_source_id=tour_source_id,
                selected_odii_story=story,
            )
        )
    return tuple(identities)


def publish_approved_preview(
    *,
    approval_path: Path,
    review_manifest_path: Path,
    source_lock_path: Path,
    output_root: Path,
) -> None:
    source_lock_snapshot = load_preview_source_lock_snapshot(source_lock_path)
    if approval_path.name != "APPROVAL.md":
        raise ValueError("approval artifact must be named APPROVAL.md")
    if review_manifest_path.name != "review-manifest.json":
        raise ValueError("review manifest must use the exact artifact name")
    if approval_path.parent.resolve(strict=True) != review_manifest_path.parent.resolve(
        strict=True
    ):
        raise ValueError("approval must be inside the approved review directory")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(output_root):
        raise FileExistsError("frozen output already exists; publication is immutable")
    review_snapshot = _read_approved_review_snapshot(review_manifest_path.parent)
    temporary = Path(tempfile.mkdtemp(prefix=".preview-freeze-", dir=output_root.parent))
    preserve_uncertain_state = False
    try:
        review_copy = temporary / "review"
        review_copy.mkdir()
        for name, payload in review_snapshot.items():
            (review_copy / name).write_bytes(payload)
        review_result = check_approved_review_manifest(
            review_copy / "review-manifest.json",
            source_lock=source_lock_snapshot.lock,
        )
        if review_result.exit_code != CHECK_RESOLVED:
            raise ValueError(
                f"review manifest is not fully resolved and bundle-matched: {review_result.reason}"
            )
        assert review_result.review is not None
        assert review_result.bundle_path is not None
        if (
            review_result.review.schema_version != "candidate-review-v2"
            or review_result.review.rights_review is None
            or review_result.review.rights_review.policy_version
            != "official-public-data-contest-v2"
        ):
            raise ValueError("freeze requires the current validated candidate-review-v2")
        approval_bytes = review_snapshot["APPROVAL.md"]
        approval = _parse_approval_bytes(approval_bytes)
        review_manifest_bytes = review_snapshot["review-manifest.json"]
        candidate_bytes = review_snapshot["candidate-review.json"]
        markdown_bytes = review_snapshot["candidate-review.md"]
        bundle_bytes = review_snapshot["raw-provider-bundle.redacted.json"]
        if sha256_bytes(review_manifest_bytes) != approval.approved_review_manifest_sha256:
            raise ValueError("approved review manifest SHA-256 mismatch")
        if sha256_bytes(bundle_bytes) != approval.approved_redacted_provider_bundle_sha256:
            raise ValueError("approved redacted provider bundle SHA-256 mismatch")
        if sha256_bytes(candidate_bytes) != approval.canonical_candidate_review_sha256:
            raise ValueError("approved candidate review SHA-256 mismatch")
        if sha256_bytes(markdown_bytes) != approval.canonical_candidate_review_markdown_sha256:
            raise ValueError("approved candidate review markdown SHA-256 mismatch")
        if sha256_bytes(source_lock_snapshot.payload) != approval.canonical_source_lock_sha256:
            raise ValueError("approved source lock SHA-256 mismatch")
        if approval.approved_candidate_identities != _approved_identities(review_result.review):
            raise ValueError("approved candidate identities do not match the current review")
        if (
            review_result.review.rights_review.policy_version
            != approval.rights_acknowledgement_version
        ):
            raise ValueError("approved rights acknowledgement version mismatch")
        bundle = RawProviderBundle.model_validate_json(bundle_bytes)
        _prepare_final_boundary(
            approval=approval,
            approval_bytes=approval_bytes,
            review_manifest_bytes=review_manifest_bytes,
            review=review_result.review,
            bundle_bytes=bundle_bytes,
            bundle=bundle,
            temporary=temporary,
        )
        _fsync_tree(temporary)
        try:
            with prepared_directory_snapshot(temporary) as prepared_snapshot:
                with tempfile.TemporaryDirectory(
                    prefix=".preview-freeze-validation-"
                ) as validation_parent:
                    validation_root = Path(validation_parent) / "boundary"
                    prepared_snapshot.materialize(validation_root)
                    validate_frozen_preview_boundary(
                        validation_root / "stage-manifest.json",
                        source_lock_snapshot=source_lock_snapshot,
                    )
                _publish_final_boundary(
                    prepared=temporary,
                    output_root=output_root,
                    snapshot=prepared_snapshot,
                )
        except PublicationStateUncertainError:
            preserve_uncertain_state = True
            raise
    finally:
        if not preserve_uncertain_state:
            shutil.rmtree(temporary, ignore_errors=True)


def _regular_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path.name} must be a regular local file")
    return path.read_bytes()


def validate_frozen_preview_boundary(
    stage_manifest_path: Path,
    *,
    source_lock_path: Path | None = None,
    source_lock_snapshot: PreviewSourceLockSnapshot | None = None,
) -> None:
    """Recompute the immutable five-artifact boundary and seven-stage proof."""

    if source_lock_path is not None and source_lock_snapshot is not None:
        raise ValueError("inject source lock by path or pinned snapshot, not both")
    if source_lock_snapshot is None:
        if source_lock_path is None:
            raise ValueError("frozen validation requires a preview source lock")
        source_lock_snapshot = load_preview_source_lock_snapshot(source_lock_path)
    if stage_manifest_path.name != "stage-manifest.json":
        raise ValueError("stage manifest must use the exact artifact name")
    output_root = stage_manifest_path.parent
    with _frozen_boundary_snapshot(output_root) as snapshot:
        paths = (
            "raw/six-places.json",
            "sanitized/six-places.json",
            "normalized/six-places.json",
        )
        file_bytes = {relative: snapshot[relative] for relative in paths}
        manifest = json.loads(snapshot["manifest.json"])
        if not isinstance(manifest, dict) or frozenset(manifest) != _FROZEN_MANIFEST_KEYS:
            raise ValueError("frozen manifest must contain the exact object fields")
        if (
            manifest["schema_version"] != "frozen-preview-manifest-v1"
            or manifest["status"] != "FROZEN_PREVIEW"
            or manifest["split"] != "PREVIEW"
            or manifest["assessment_status"] != "NOT_SCORED"
            or manifest["candidate_names"] != list(LOCKED_PREVIEW_CANDIDATES)
        ):
            raise ValueError("frozen manifest lifecycle or identities are invalid")

        review_bytes = {name: snapshot[f"review/{name}"] for name in _APPROVED_REVIEW_NAMES}
        expected_root = Path(tempfile.mkdtemp(prefix=".preview-rederive-", dir=output_root.parent))
        try:
            review_copy = expected_root / "review"
            review_copy.mkdir()
            for name, payload in review_bytes.items():
                (review_copy / name).write_bytes(payload)
            checked_review = check_approved_review_manifest(
                review_copy / "review-manifest.json",
                source_lock=source_lock_snapshot.lock,
            )
            if (
                checked_review.exit_code != CHECK_RESOLVED
                or checked_review.bundle_path is None
                or checked_review.review is None
            ):
                raise ValueError("frozen review boundary is no longer resolved and bundle-matched")
            approval_bytes = review_bytes["APPROVAL.md"]
            approval = _parse_approval_bytes(approval_bytes)
            review_manifest_bytes = review_bytes["review-manifest.json"]
            bundle_bytes = review_bytes["raw-provider-bundle.redacted.json"]
            candidate_bytes = review_bytes["candidate-review.json"]
            markdown_bytes = review_bytes["candidate-review.md"]
            if (
                approval.approved_review_manifest_sha256 != sha256_bytes(review_manifest_bytes)
                or approval.approved_redacted_provider_bundle_sha256 != sha256_bytes(bundle_bytes)
                or manifest["approved_review_manifest_sha256"]
                != approval.approved_review_manifest_sha256
                or manifest["approved_redacted_provider_bundle_sha256"]
                != approval.approved_redacted_provider_bundle_sha256
                or manifest["approval_sha256"] != sha256_bytes(approval_bytes)
                or approval.canonical_source_lock_sha256
                != sha256_bytes(source_lock_snapshot.payload)
                or approval.canonical_candidate_review_sha256 != sha256_bytes(candidate_bytes)
                or approval.canonical_candidate_review_markdown_sha256
                != sha256_bytes(markdown_bytes)
                or approval.approved_candidate_identities
                != _approved_identities(checked_review.review)
                or checked_review.review.rights_review is None
                or approval.rights_acknowledgement_version
                != checked_review.review.rights_review.policy_version
            ):
                raise ValueError("approval, review manifest, and provider bundle hashes diverged")
            _prepare_final_boundary(
                approval=approval,
                approval_bytes=approval_bytes,
                review_manifest_bytes=review_manifest_bytes,
                review=checked_review.review,
                bundle_bytes=bundle_bytes,
                bundle=RawProviderBundle.model_validate_json(bundle_bytes),
                temporary=expected_root,
            )
            for relative in (*paths, "manifest.json", "stage-manifest.json"):
                if snapshot[relative] != _regular_file(expected_root / relative):
                    raise ValueError("frozen artifact bytes do not match exact approved derivation")
        finally:
            shutil.rmtree(expected_root, ignore_errors=True)

        descriptors = manifest["files"]
        if not isinstance(descriptors, list):
            raise ValueError("frozen manifest files must be a list")
        for descriptor in descriptors:
            if (
                not isinstance(descriptor, dict)
                or frozenset(descriptor) != _FROZEN_FILE_DESCRIPTOR_KEYS
            ):
                raise ValueError("frozen file descriptor must contain exact fields")
        if [descriptor["path"] for descriptor in descriptors] != list(paths):
            raise ValueError("frozen manifest file order is invalid")
        previous_hash = manifest["approved_redacted_provider_bundle_sha256"]
        for descriptor in descriptors:
            relative = descriptor["path"]
            digest = sha256_bytes(file_bytes[relative])
            if descriptor["sha256"] != digest:
                raise ValueError("frozen file SHA-256 mismatch")
            if descriptor["derived_from_sha256"] != previous_hash:
                raise ValueError("raw-to-sanitized-to-normalized lineage is broken")
            previous_hash = digest

        normalized = json.loads(file_bytes["normalized/six-places.json"])
        if not isinstance(normalized, dict) or not isinstance(normalized.get("places"), list):
            raise ValueError("normalized artifact must contain a place list")
        places = normalized["places"]
        if any(not isinstance(place, dict) for place in places):
            raise ValueError("normalized places must be objects")
        if [place.get("name_ko") for place in places] != list(LOCKED_PREVIEW_CANDIDATES):
            raise ValueError("normalized identities are invalid")
        if any(
            place.get("split") != "PREVIEW" or place.get("assessment_status") != "NOT_SCORED"
            for place in places
        ):
            raise ValueError("normalized rows must remain PREVIEW and NOT_SCORED")

        stage_manifest = json.loads(snapshot["stage-manifest.json"])
        if (
            not isinstance(stage_manifest, dict)
            or frozenset(stage_manifest) != _STAGE_MANIFEST_KEYS
        ):
            raise ValueError("stage manifest must contain the exact object fields")
        if (
            stage_manifest["schema_version"] != "frozen-preview-stage-manifest-v1"
            or stage_manifest["source_input_hash"]
            != manifest["approved_redacted_provider_bundle_sha256"]
        ):
            raise ValueError("stage manifest source binding is invalid")
        rows = stage_manifest["stages"]
        if not isinstance(rows, list):
            raise ValueError("stage manifest stages must be a list")
        for row in rows:
            if not isinstance(row, dict) or frozenset(row) != _STAGE_ROW_KEYS:
                raise ValueError("stage row must contain the exact fields")
            lineage = row["upstream_lineage"]
            if not isinstance(lineage, list) or any(
                not isinstance(item, dict) or frozenset(item) != _STAGE_LINEAGE_KEYS
                for item in lineage
            ):
                raise ValueError("stage lineage must contain exact objects")
            proof = row["procedure_proof"]
            if proof is not None and (
                not isinstance(proof, dict) or frozenset(proof) != _PROCEDURE_PROOF_KEYS
            ):
                raise ValueError("stage procedure proof must contain exact fields")
        if [row["stage"] for row in rows] != list(_PIPELINE_STAGE_ORDER):
            raise ValueError("stage manifest must contain the exact ordered seven stages")

        previous_stage: str | None = None
        previous_output: str | None = None
        for row in rows:
            stage = row["stage"]
            if previous_stage is None or previous_output is None:
                expected_input = stage_manifest["source_input_hash"]
                expected_lineage: list[dict[str, str]] = []
            else:
                expected_input = _lineage_hash(previous_stage, previous_output)
                expected_lineage = [{"stage": previous_stage, "output_hash": previous_output}]
            if row["input_hash"] != expected_input or row["upstream_lineage"] != expected_lineage:
                raise ValueError("stage input hash or immediate lineage is broken")
            if stage == "collect":
                expected_status = "MATERIALIZED"
                expected_path = "raw/six-places.json"
                expected_output = sha256_bytes(file_bytes[expected_path])
                expected_proof = None
            elif stage == "normalize":
                expected_status = "MATERIALIZED"
                expected_path = "normalized/six-places.json"
                expected_output = sha256_bytes(file_bytes[expected_path])
                expected_proof = None
            else:
                expected_status = "NOT_SCORED"
                expected_path = None
                expected_proof = {
                    "executed": True,
                    "reason": "DEFERRED_PHASE_1_CONTRACT_ONLY",
                    "result_emitted": False,
                }
                expected_output = sha256_bytes(
                    _canonical_json_bytes(
                        {
                            "input_hash": expected_input,
                            "procedure_proof": expected_proof,
                            "stage": stage,
                            "status": expected_status,
                        }
                    )
                )
            if (
                row["status"] != expected_status
                or row["artifact_path"] != expected_path
                or row["procedure_proof"] != expected_proof
                or row["output_hash"] != expected_output
            ):
                raise ValueError("stage output or procedure proof is invalid")
            previous_stage = stage
            previous_output = expected_output


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source_lock_path = (
        args.source_lock
        if args.source_lock is not None
        else args.output_root.parent / "source-locks" / "preview-v1-source-lock.json"
    )
    try:
        publish_approved_preview(
            approval_path=args.approval,
            review_manifest_path=args.review_manifest,
            source_lock_path=source_lock_path,
            output_root=args.output_root,
        )
    except (OSError, ValueError, ValidationError) as exc:
        print(f"freeze refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
