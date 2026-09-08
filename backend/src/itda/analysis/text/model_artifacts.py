"""Freeze-gated preparation and offline verification for the approved Phase 3 encoder."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import math
import os
import socket
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

APPROVED_MODEL_ID = "BAAI/bge-m3"
APPROVED_MODEL_REVISION = "b28ce2a6fcc9c75ef1c0619575d0ec19af760082"
APPROVED_PACKAGES: Mapping[str, str] = {
    "torch": "2.13.0",
    "transformers": "5.14.1",
    "sentence-transformers": "5.6.0",
    "numpy": "2.5.1",
    "huggingface-hub": "1.26.0",
    "krippendorff": "0.8.2",
    "arize-phoenix": "19.13.0",
    "opentelemetry-sdk": "1.44.0",
}
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_WEIGHT_SUFFIXES = frozenset({".bin", ".pt", ".pth", ".safetensors"})
_REMOTE_CODE_SUFFIXES = frozenset({".py", ".pyc", ".so", ".dll", ".dylib"})


class ModelArtifactFile(StrictContract):
    """One immutable regular file in the approved local snapshot."""

    relative_path: Annotated[str, Field(strict=True, min_length=1, max_length=512)]
    size_bytes: Annotated[int, Field(strict=True, ge=0)]
    sha256: Sha256

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        path = PurePosixPath(self.relative_path)
        hidden_allowed = path.parts == (".gitattributes",)
        if (
            path.is_absolute()
            or ".." in path.parts
            or (self.relative_path.startswith(".") and not hidden_allowed)
        ):
            raise ValueError("model artifact path must be safe and relative")
        if path.suffix.casefold() in _REMOTE_CODE_SUFFIXES:
            raise ValueError("remote executable code is forbidden in the model snapshot")
        return self


class ModelArtifactManifest(StrictContract):
    """Self-authenticating inventory for one exact local-only encoder snapshot."""

    schema_version: Literal["phase3-model-artifact-manifest-v1"] = (
        "phase3-model-artifact-manifest-v1"
    )
    model_id: Literal["BAAI/bge-m3"] = "BAAI/bge-m3"
    model_revision: Literal[
        "b28ce2a6fcc9c75ef1c0619575d0ec19af760082"
    ] = "b28ce2a6fcc9c75ef1c0619575d0ec19af760082"
    snapshot_directory: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    freeze_receipt_sha256: Sha256
    package_set_sha256: Sha256
    model_config_sha256: Sha256
    tokenizer_sha256: Sha256
    weight_sha256: Sha256
    snapshot_sha256: Sha256
    files: tuple[ModelArtifactFile, ...]
    trust_remote_code: Literal[False] = False
    local_files_only: Literal[True] = True
    manifest_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        directory = PurePosixPath(self.snapshot_directory)
        if directory.is_absolute() or len(directory.parts) != 1 or directory.name.startswith("."):
            raise ValueError("snapshot directory must be one safe manifest-relative name")
        if not self.files:
            raise ValueError("model artifact manifest requires an inventory")
        paths = tuple(item.relative_path for item in self.files)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            raise ValueError("model artifact inventory must be unique and sorted")
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 is None:
            object.__setattr__(self, "manifest_sha256", expected)
        elif self.manifest_sha256 != expected:
            raise ValueError("model artifact manifest digest is stale")
        return self


def _safe_json_bytes(path: Path, *, maximum_bytes: int = _MAX_MANIFEST_BYTES) -> bytes:
    """Read a bounded single-link regular file without following symlinks."""

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("platform lacks no-follow file reads")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("manifest input must be a single-link regular file")
        if not 0 < before.st_size <= maximum_bytes:
            raise ValueError("manifest input is empty or exceeds the bounded size")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError("manifest input changed during verification")
        return payload
    finally:
        os.close(descriptor)


def _canonical_self_digest(payload: Mapping[str, object], field: str) -> str:
    material = dict(payload)
    digest = material.pop(field, None)
    if not isinstance(digest, str) or digest != canonical_sha256(material):
        raise ValueError("freeze receipt digest is invalid")
    return digest


class VerifiedFreezeGuard:
    """Validate D-11 entirely before callers resolve any model/cache location."""

    @staticmethod
    def verify(
        receipt: Mapping[str, object] | None,
        *,
        expected_source_manifest_sha256: str | None = None,
        expected_authority_sha256: str | None = None,
        now: str | datetime | None = None,
    ) -> str:
        if receipt is None:
            raise ValueError("freeze receipt is required")
        try:
            schema = receipt.get("schema_version")
            if schema != "phase3-label-freeze-receipt-v1":
                raise ValueError("freeze receipt schema is invalid")

            # The controlled synthetic receipt binds a synthetic authority and source manifest.
            if "freeze" in receipt:
                if receipt.get("synthetic_only") is not True:
                    raise ValueError("synthetic freeze receipt scope is invalid")
                authority = receipt.get("authority")
                freeze = receipt.get("freeze")
                if not isinstance(authority, Mapping) or not isinstance(freeze, Mapping):
                    raise ValueError("freeze receipt structure is invalid")
                authority_digest = _canonical_self_digest(authority, "authority_sha256")
                if authority.get("scope") != "SYNTHETIC_ONLY":
                    raise ValueError("synthetic freeze authority scope is invalid")
                if (
                    expected_authority_sha256 is not None
                    and authority_digest != expected_authority_sha256
                ):
                    raise ValueError("freeze authority digest has drifted")
                if freeze.get("status") != "APPROVED_FROZEN":
                    raise ValueError("freeze receipt is not approved")
                if (
                    expected_source_manifest_sha256 is not None
                    and freeze.get("source_manifest_sha256") != expected_source_manifest_sha256
                ):
                    raise ValueError("freeze receipt source digest has drifted")
                if now is not None:
                    moment = _parse_utc(now)
                    issued_at = _parse_utc(authority.get("issued_at"))
                    expires_at = _parse_utc(authority.get("expires_at"))
                    if not issued_at <= moment <= expires_at:
                        raise ValueError("freeze receipt authority is expired")
                return _canonical_self_digest(receipt, "receipt_sha256")

            # Production D-11 receipts are authority-free and self-authenticating.
            if receipt.get("status") != "APPROVED_FROZEN":
                raise ValueError("freeze receipt is not approved")
            if receipt.get("authority_grants") not in ([], ()):
                raise ValueError("freeze receipt cannot grant downstream authority")
            return _canonical_self_digest(receipt, "receipt_sha256")
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError) and "freeze" in str(exc).casefold():
                raise
            raise ValueError("freeze receipt validation failed") from exc

    @classmethod
    def from_path(cls, path: Path) -> tuple[dict[str, object], str]:
        raw = _safe_json_bytes(path)
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("freeze receipt is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("freeze receipt must be an object")
        digest = cls.verify(parsed)
        return parsed, digest


def _parse_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("freeze receipt time is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("freeze receipt time must be UTC")
    return parsed


def verify_approved_packages(*, include_dev: bool = False) -> str:
    """Verify exact human-approved direct coordinates without importing them."""

    names = tuple(APPROVED_PACKAGES) if include_dev else tuple(APPROVED_PACKAGES)[:5]
    resolved: dict[str, str] = {}
    for name in names:
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ValueError("approved package set is incomplete") from exc
        if installed != APPROVED_PACKAGES[name]:
            raise ValueError("approved package version has drifted")
        resolved[name] = installed
    return canonical_sha256(resolved)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("model artifact must be a single-link regular file")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OSError("model artifact changed while being hashed")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def inventory_snapshot(root: Path) -> tuple[ModelArtifactFile, ...]:
    """Inventory regular, non-executable snapshot files in deterministic order."""

    if root.is_symlink() or not root.is_dir():
        raise ValueError("model snapshot root must be a regular directory")
    items: list[ModelArtifactFile] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError("model snapshot cannot contain symlinks")
        if path.is_dir():
            continue
        file_stat = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
            raise ValueError("model snapshot contains an unsafe file")
        if file_stat.st_mode & 0o111 or path.suffix.casefold() in _REMOTE_CODE_SUFFIXES:
            raise ValueError("model snapshot contains executable remote code")
        items.append(
            ModelArtifactFile(
                relative_path=relative,
                size_bytes=file_stat.st_size,
                sha256=_file_sha256(path),
            )
        )
    if not items:
        raise ValueError("model snapshot is empty")
    return tuple(items)


def _category_digest(files: Sequence[ModelArtifactFile], category: str) -> str:
    def selected(item: ModelArtifactFile) -> bool:
        path = PurePosixPath(item.relative_path)
        name = path.name.casefold()
        if category == "weight":
            return path.suffix.casefold() in _WEIGHT_SUFFIXES
        if category == "tokenizer":
            return any(
                part in name
                for part in ("tokenizer", "vocab", "sentencepiece", "special_tokens")
            )
        return path.suffix.casefold() == ".json" and not any(
            part in name for part in ("tokenizer", "vocab", "special_tokens")
        )

    rows = [item.model_dump(mode="json") for item in files if selected(item)]
    if not rows:
        raise ValueError(f"model snapshot lacks required {category} artifacts")
    return canonical_sha256(rows)


def build_model_manifest(
    *,
    snapshot_root: Path,
    snapshot_directory: str,
    freeze_receipt_sha256: str,
    package_set_sha256: str,
) -> ModelArtifactManifest:
    files = inventory_snapshot(snapshot_root)
    return ModelArtifactManifest(
        snapshot_directory=snapshot_directory,
        freeze_receipt_sha256=freeze_receipt_sha256,
        package_set_sha256=package_set_sha256,
        model_config_sha256=_category_digest(files, "config"),
        tokenizer_sha256=_category_digest(files, "tokenizer"),
        weight_sha256=_category_digest(files, "weight"),
        snapshot_sha256=canonical_sha256([item.model_dump(mode="json") for item in files]),
        files=files,
    )


def load_model_manifest(path: Path) -> tuple[ModelArtifactManifest, bytes]:
    raw = _safe_json_bytes(path)
    manifest = ModelArtifactManifest.model_validate_json(raw)
    if raw != canonical_json_bytes(manifest.model_dump(mode="json")):
        raise ValueError("model artifact manifest is not canonical JSON")
    return manifest, raw


def verify_local_snapshot(manifest_path: Path) -> tuple[ModelArtifactManifest, Path]:
    manifest, _ = load_model_manifest(manifest_path)
    root = manifest_path.parent / manifest.snapshot_directory
    files = inventory_snapshot(root)
    if files != manifest.files:
        raise ValueError("local model snapshot inventory or digest has drifted")
    rebuilt = build_model_manifest(
        snapshot_root=root,
        snapshot_directory=manifest.snapshot_directory,
        freeze_receipt_sha256=manifest.freeze_receipt_sha256,
        package_set_sha256=manifest.package_set_sha256,
    )
    if rebuilt.model_dump(exclude={"manifest_sha256"}) != manifest.model_dump(
        exclude={"manifest_sha256"}
    ):
        raise ValueError("local model snapshot provenance has drifted")
    return manifest, root


def write_canonical_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class _Encoder(Protocol):
    def encode(self, sentences: list[str], **kwargs: object) -> Any: ...


@contextmanager
def deny_network() -> Iterator[None]:
    """Fail closed if an offline smoke attempts any socket connection."""

    original_connect = socket.socket.connect
    original_create_connection = socket.create_connection

    def blocked(*_: object, **__: object) -> None:
        raise RuntimeError("offline model smoke attempted network access")

    socket.socket.connect = blocked  # type: ignore[method-assign]
    socket.create_connection = blocked  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.socket.connect = original_connect  # type: ignore[method-assign]
        socket.create_connection = original_create_connection


def smoke_local_model(
    manifest_path: Path,
    *,
    encoder_factory: Callable[..., _Encoder] | None = None,
) -> dict[str, object]:
    if os.environ.get("HF_HUB_OFFLINE") != "1" or os.environ.get("TRANSFORMERS_OFFLINE") != "1":
        raise ValueError("offline model smoke requires strict offline environment flags")
    manifest, root = verify_local_snapshot(manifest_path)
    verify_approved_packages()
    if encoder_factory is None:
        encoder_factory = cast(
            Callable[..., _Encoder],
            importlib.import_module("sentence_transformers").SentenceTransformer,
        )
    with deny_network():
        encoder = encoder_factory(
            str(root),
            device="cpu",
            trust_remote_code=False,
            local_files_only=True,
        )
        vectors = encoder.encode(
            ["경주의 역사와 전통을 차분히 이해하는 여행", "조용히 쉬며 풍경에 몰입하는 여행"],
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
    shape = getattr(vectors, "shape", None)
    if not isinstance(shape, tuple) or len(shape) != 2 or shape[0] != 2 or shape[1] <= 0:
        raise ValueError("offline model smoke produced an invalid embedding shape")
    flat = vectors.ravel().tolist()
    if not flat or any(not math.isfinite(float(value)) for value in flat):
        raise ValueError("offline model smoke produced non-finite embeddings")
    return {
        "status": "OFFLINE_LOCAL_ONLY_VERIFIED",
        "model_revision": manifest.model_revision,
        "manifest_sha256": manifest.manifest_sha256,
        "embedding_count": shape[0],
        "embedding_dimensions": shape[1],
        "trust_remote_code": False,
        "local_files_only": True,
    }


__all__ = [
    "APPROVED_MODEL_ID",
    "APPROVED_MODEL_REVISION",
    "APPROVED_PACKAGES",
    "ModelArtifactFile",
    "ModelArtifactManifest",
    "VerifiedFreezeGuard",
    "build_model_manifest",
    "deny_network",
    "inventory_snapshot",
    "load_model_manifest",
    "smoke_local_model",
    "verify_approved_packages",
    "verify_local_snapshot",
    "write_canonical_no_replace",
]
