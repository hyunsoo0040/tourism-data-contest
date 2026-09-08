"""Select deterministic rights-qualified representatives from an authorized calibration fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from itda.analysis.image.preprocessing import (
    DEFAULT_IMAGE_PREPROCESSING_POLICY,
    ImagePreprocessingPolicy,
)
from itda.analysis.image.selection import (
    GatedAsset,
    SceneEmbeddingEncoder,
    select_representative_images,
)
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_selection import (
    PINNED_SIGLIP2_MODEL_ID,
    PINNED_SIGLIP2_REVISION,
    ImageSelectionBatchInput,
    ImageSelectionBatchManifest,
    ImageSelectionPolicy,
    SelectionAuthorityScope,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_MAX_INPUT_BYTES = 8 * 1024 * 1024
_PROHIBITED_KEY_PARTS = ("blind", "split", "membership", "complement")


def _safe_read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_INPUT_BYTES
        ):
            raise ValueError("selection artifact must be a bounded single-link regular file")
        payload = bytearray()
        while len(payload) <= before.st_size:
            chunk = os.read(descriptor, min(64 * 1024, before.st_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError("selection artifact changed during verification")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _reject_prohibited_keys(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, nested in current.items():
                if any(part in str(key).casefold() for part in _PROHIBITED_KEY_PARTS):
                    raise ValueError("selection input contains prohibited evaluation authority")
                stack.append(nested)
        elif isinstance(current, list):
            stack.extend(current)


def _load_canonical[ContractT: BaseModel](path: Path, contract: type[ContractT]) -> ContractT:
    raw = _safe_read(path)
    parsed = json.loads(raw)
    _reject_prohibited_keys(parsed)
    model = contract.model_validate(parsed)
    if raw != canonical_json_bytes(model.model_dump(mode="json")):
        raise ValueError("selection artifact is not canonical JSON")
    return model


def _write_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _snapshot_weight_digest(
    snapshot: Path,
    *,
    materialization_root: Path | None = None,
) -> str:
    snapshot_root = snapshot.resolve(strict=True)
    if snapshot_root.parent.name != "snapshots":
        raise ValueError("model snapshot is not in a standard cache layout")
    cache_root = snapshot_root.parent.parent.resolve(strict=True)
    candidates = sorted(
        {
            *snapshot_root.rglob("*.safetensors"),
            *snapshot_root.rglob("*.json"),
        }
    )
    rows: list[dict[str, str]] = []
    names: set[str] = set()
    weight_count = 0
    for path in candidates:
        relative_path = path.relative_to(snapshot_root).as_posix()
        link_before = path.lstat()
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(cache_root):
            raise ValueError("model snapshot entry escapes its cache root")
        if path.is_symlink() and resolved.parent != cache_root / "blobs":
            raise ValueError("model snapshot link does not target the canonical blob store")
        digest = hashlib.sha256()
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        staged_descriptor: int | None = None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
                raise ValueError("model snapshot entry is not an immutable regular file")
            if materialization_root is not None:
                staged_path = materialization_root / relative_path
                staged_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                staged_descriptor = os.open(
                    staged_path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                if staged_descriptor is not None:
                    view = memoryview(chunk)
                    while view:
                        written = os.write(staged_descriptor, view)
                        if written <= 0:
                            raise OSError("verified model staging write did not complete")
                        view = view[written:]
            if staged_descriptor is not None:
                os.fsync(staged_descriptor)
            after = os.fstat(descriptor)
        finally:
            if staged_descriptor is not None:
                os.close(staged_descriptor)
            os.close(descriptor)
        link_after = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (link_before.st_dev, link_before.st_ino, link_before.st_mtime_ns)
            != (link_after.st_dev, link_after.st_ino, link_after.st_mtime_ns)
            or path.resolve(strict=True) != resolved
        ):
            raise OSError("model snapshot entry changed while hashing")
        kind = "WEIGHT" if path.suffix == ".safetensors" else "CONFIG"
        weight_count += kind == "WEIGHT"
        names.add(path.name)
        rows.append({"path": relative_path, "kind": kind, "sha256": digest.hexdigest()})
    if weight_count == 0:
        raise ValueError("model snapshot contains no safetensors weights")
    if "config.json" not in names or not names & {
        "preprocessor_config.json",
        "processor_config.json",
    }:
        raise ValueError("model snapshot is missing bound model or processor configuration")
    return canonical_sha256(rows)


@contextmanager
def _verified_snapshot_stage(
    snapshot: Path,
    *,
    expected_digest: str,
) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="itda-siglip2-verified-") as temporary:
        staged = Path(temporary)
        actual_digest = _snapshot_weight_digest(
            snapshot,
            materialization_root=staged,
        )
        if actual_digest != expected_digest:
            raise ValueError("local SigLIP2 weight inventory does not match selection policy")
        yield staged


class LocalSiglip2SceneEncoder:
    """Local-only pinned SigLIP2 image encoder with weight-inventory binding."""

    model_id = PINNED_SIGLIP2_MODEL_ID
    model_revision = PINNED_SIGLIP2_REVISION

    def __init__(self, *, model_weight_sha256: str) -> None:
        self.model_weight_sha256 = model_weight_sha256
        self._processor: Any | None = None
        self._model: Any | None = None

    def _ensure_loaded(self) -> None:
        if self._processor is not None and self._model is not None:
            return
        import torch
        from huggingface_hub import snapshot_download
        from transformers import AutoModel, AutoProcessor

        snapshot = Path(
            snapshot_download(
                repo_id=self.model_id,
                revision=self.model_revision,
                local_files_only=True,
            )
        ).resolve()
        with _verified_snapshot_stage(
            snapshot,
            expected_digest=self.model_weight_sha256,
        ) as verified_snapshot:
            torch.use_deterministic_algorithms(True)
            self._processor = AutoProcessor.from_pretrained(  # type: ignore[no-untyped-call]
                verified_snapshot,
                local_files_only=True,
                trust_remote_code=False,
            )
            self._model = AutoModel.from_pretrained(
                verified_snapshot,
                local_files_only=True,
                trust_remote_code=False,
            )
        self._model.eval()

    def encode(self, assets: tuple[GatedAsset, ...]) -> dict[str, tuple[float, ...]]:
        self._ensure_loaded()
        if self._processor is None or self._model is None:
            raise RuntimeError("local SigLIP2 encoder failed to initialize")
        import torch
        from PIL import Image

        images: list[Image.Image] = []
        try:
            for asset in assets:
                with Image.open(BytesIO(asset.projection.encoded_bytes)) as decoded:
                    images.append(decoded.convert("RGB"))
            inputs = self._processor(images=images, return_tensors="pt")
            with torch.no_grad():
                output = self._model.get_image_features(**inputs)
            features = getattr(output, "pooler_output", output)
            rows = features.detach().cpu().tolist()
            return {
                asset.source_asset_id: tuple(float(value) for value in row)
                for asset, row in zip(assets, rows, strict=True)
            }
        finally:
            for image in images:
                image.close()


def _open_image_root(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("protected image root must be absolute")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    identity = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != os.geteuid()
        or identity.st_mode & 0o022
    ):
        os.close(descriptor)
        raise ValueError("protected image root ownership or mode is unsafe")
    return descriptor


def _verify_output(
    batch_input: ImageSelectionBatchInput,
    policy: ImageSelectionPolicy,
    output: ImageSelectionBatchManifest,
    *,
    root_fd: int,
    encoder: SceneEmbeddingEncoder,
    preprocessing_policy: ImagePreprocessingPolicy | None = None,
) -> None:
    if (
        output.input_manifest_sha256 != batch_input.input_manifest_sha256
        or output.selection_policy_sha256 != policy.policy_sha256
        or tuple(manifest.place_entity_id for manifest in output.manifests)
        != tuple(place.place_entity_id for place in batch_input.places)
    ):
        raise ValueError("selection output does not bind the requested input and policy")
    if all(
        not place.assets and place.media_state is not ImageMediumState.QUALIFIED
        for place in batch_input.places
    ):
        return
    if (
        preprocessing_policy is None
        and policy.preprocessing_policy_sha256
        != DEFAULT_IMAGE_PREPROCESSING_POLICY.policy_sha256
    ):
        raise ValueError("verification requires the exact preprocessing policy authority")
    expected = ImageSelectionBatchManifest.build(
        input_manifest_sha256=batch_input.input_manifest_sha256,
        selection_policy_sha256=policy.policy_sha256,
        manifests=tuple(
            select_representative_images(
                root_fd=root_fd,
                candidate=place,
                policy=policy,
                encoder=encoder,
                preprocessing_policy=preprocessing_policy,
            )
            for place in batch_input.places
        ),
    )
    if output != expected:
        raise ValueError("selection output differs from deterministic protected-byte derivation")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rights-manifest", required=True, type=Path)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        batch_input = _load_canonical(args.rights_manifest, ImageSelectionBatchInput)
        policy = _load_canonical(args.config, ImageSelectionPolicy)
        assert isinstance(batch_input, ImageSelectionBatchInput)
        assert isinstance(policy, ImageSelectionPolicy)
        if args.verify_only:
            output = _load_canonical(args.output, ImageSelectionBatchManifest)
            assert isinstance(output, ImageSelectionBatchManifest)
            root_fd = _open_image_root(args.image_root)
            try:
                _verify_output(
                    batch_input,
                    policy,
                    output,
                    root_fd=root_fd,
                    encoder=LocalSiglip2SceneEncoder(
                        model_weight_sha256=policy.model_weight_sha256
                    ),
                )
            finally:
                os.close(root_fd)
            return 0
        if batch_input.authority_scope is not SelectionAuthorityScope.AUTHORIZED_CALIBRATION:
            raise ValueError("production selection requires exact calibration authority")
        root_fd = _open_image_root(args.image_root)
        try:
            encoder = LocalSiglip2SceneEncoder(model_weight_sha256=policy.model_weight_sha256)
            manifests = tuple(
                select_representative_images(
                    root_fd=root_fd,
                    candidate=place,
                    policy=policy,
                    encoder=encoder,
                )
                for place in batch_input.places
            )
        finally:
            os.close(root_fd)
        output = ImageSelectionBatchManifest.build(
            input_manifest_sha256=batch_input.input_manifest_sha256,
            selection_policy_sha256=policy.policy_sha256,
            manifests=manifests,
        )
        _write_no_replace(args.output, canonical_json_bytes(output.model_dump(mode="json")))
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        raise SystemExit("image selection rejected invalid or unauthorized input") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
