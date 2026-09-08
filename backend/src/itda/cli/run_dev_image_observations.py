"""Freeze label-free DEV image observations from an exact selected-image manifest."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ValidationError

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256
from itda.contracts.image_selection import ImageSelectionBatchManifest
from itda.contracts.vlm_inference import Glm5VProviderConfig
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.dev_image_observations import (
    FrozenObservationBatch,
    ProtectedImageCapabilityEntry,
    ProtectedImageCapabilityManifest,
    ProviderObservationCapability,
    ProviderReplayFixture,
    _prepare_provider_jpeg,
    _provider_image_ref,
    build_mock_replay_adapter,
    generate_dev_image_observations,
)
from itda.providers.zhipu_glm5v import (
    LiveProviderApprovalReceipt,
    ZhipuGlm5VAdapter,
    build_glm5v_async_client,
)

_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_IMAGE_BYTES = 32 * 1024 * 1024
_LIVE_APPROVAL_RECEIPT_PATH = Path(
    "/run/secrets/itda/phase4-live-provider-approval.json"
)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _safe_read(path: Path, *, maximum_bytes: int = _MAX_ARTIFACT_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ValueError("observation input must be a bounded single-link regular file")
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
            raise OSError("observation input changed during verification")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _load_canonical[ContractT: BaseModel](
    path: Path,
    contract: type[ContractT],
) -> ContractT:
    raw = _safe_read(path)
    model = contract.model_validate(json.loads(raw))
    canonical = canonical_json_bytes(model.model_dump(mode="json"))
    if raw not in {canonical, canonical + b"\n"}:
        raise ValueError("observation input is not canonical JSON")
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


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise OSError("protected image directory is unsafe")
    return (value.st_dev, value.st_ino)


def _open_image_parent_chain(
    root_fd: int,
    directory_parts: tuple[str, ...],
) -> tuple[int, tuple[tuple[int, int], ...]]:
    if not _O_DIRECTORY or not _O_NOFOLLOW or not _O_CLOEXEC:
        raise OSError("secure descriptor-relative flags are unavailable")
    current = os.dup(root_fd)
    identities: list[tuple[int, int]] = []
    try:
        identities.append(_directory_identity(os.fstat(current)))
        flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
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


def _image_file_state(value: os.stat_result) -> tuple[int, ...]:
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


def _validate_image_file(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) & 0o022
        or not 0 < value.st_size <= _MAX_IMAGE_BYTES
    ):
        raise ValueError("protected image must be a bounded single-link regular file")


def _image_loader(root_fd: int, entry: ProtectedImageCapabilityEntry) -> bytes:
    parts = PurePosixPath(entry.relative_path).parts
    parent, directory_identities = _open_image_parent_chain(root_fd, parts[:-1])
    descriptor: int | None = None
    try:
        visible = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        _validate_image_file(visible)
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        _validate_image_file(before)
        if _image_file_state(before) != _image_file_state(visible):
            raise OSError("protected image changed before descriptor open")
        payload = bytearray()
        while len(payload) <= before.st_size:
            chunk = os.read(descriptor, min(64 * 1024, before.st_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        _validate_image_file(after)
        if len(payload) != before.st_size or _image_file_state(before) != _image_file_state(after):
            raise OSError("protected image changed during verification")
        reopened_parent, reopened_identities = _open_image_parent_chain(root_fd, parts[:-1])
        try:
            if reopened_identities != directory_identities:
                raise OSError("protected image parent path changed during verification")
            reopened_visible = os.stat(
                parts[-1],
                dir_fd=reopened_parent,
                follow_symlinks=False,
            )
            _validate_image_file(reopened_visible)
            if _image_file_state(reopened_visible) != _image_file_state(before):
                raise OSError("protected image path changed during verification")
        finally:
            os.close(reopened_parent)
        result = bytes(payload)
        if hashlib.sha256(result).hexdigest() != entry.asset_sha256:
            raise ValueError("protected image digest does not match its capability")
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _verify_output(
    *,
    output: FrozenObservationBatch,
    selection: ImageSelectionBatchManifest,
    config: Glm5VProviderConfig,
    capability: ProviderObservationCapability,
    protected: ProtectedImageCapabilityManifest,
    root_fd: int,
) -> None:
    output.require_exact_capability(capability)
    if (
        output.selection_manifest_sha256 != selection.batch_sha256
        or output.provider_config_sha256 != config.config_sha256
        or output.provider_capability_sha256 != capability.capability_sha256
        or output.observation_schema_sha256 != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256
        or tuple(row.place_entity_id for row in output.observations)
        != tuple(row.place_entity_id for row in selection.manifests)
    ):
        raise ValueError("frozen observation output does not bind exact inputs")
    expected_entries = tuple(
        (row.place_entity_id, image.source_asset_id, image.asset_sha256)
        for row in selection.manifests
        for image in row.representatives
    )
    supplied_entries = tuple(
        (entry.place_entity_id, entry.source_asset_id, entry.asset_sha256)
        for entry in protected.entries
    )
    if (
        protected.selection_manifest_sha256 != selection.batch_sha256
        or capability.protected_image_capability_sha256 != protected.capability_sha256
        or supplied_entries != tuple(sorted(expected_entries))
    ):
        raise ValueError("protected image capability does not exactly join the selection")
    entries = {
        (entry.place_entity_id, entry.source_asset_id): entry
        for entry in protected.entries
    }
    for frozen, selected in zip(output.observations, selection.manifests, strict=True):
        if (
            frozen.selection_manifest_sha256 != selected.manifest_sha256
            or frozen.input_media_state is not selected.media_state
        ):
            raise ValueError("frozen place observation does not bind its selection")
        has_representatives = bool(selected.representatives)
        if selected.media_state is not ImageMediumState.QUALIFIED:
            expected = (
                frozen.provider_called is False
                and frozen.terminal_media_state is selected.media_state
            )
        elif not has_representatives:
            expected = (
                frozen.provider_called is False
                and frozen.terminal_media_state is ImageMediumState.ANALYSIS_FAILED
            )
        else:
            prepared_refs: list[str] = []
            prepared_sha256: list[str] = []
            preparation_failed = False
            try:
                for representative in selected.representatives:
                    entry = entries[
                        (selected.place_entity_id, representative.source_asset_id)
                    ]
                    raw = _image_loader(root_fd, entry)
                    jpeg = _prepare_provider_jpeg(
                        raw,
                        expected_sha256=representative.asset_sha256,
                    )
                    prepared_refs.append(
                        _provider_image_ref(representative.representative_id)
                    )
                    prepared_sha256.append(hashlib.sha256(jpeg).hexdigest())
            except (KeyError, OSError, ValueError):
                preparation_failed = True

            if preparation_failed:
                expected = (
                    frozen.provider_called is False
                    and frozen.safe_request is None
                    and frozen.terminal_media_state is ImageMediumState.ANALYSIS_FAILED
                    and frozen.failure_code == "IMAGE_PREPARATION_FAILED"
                )
            else:
                expected = (
                    frozen.provider_called is True
                    and frozen.safe_request is not None
                    and tuple(frozen.safe_request.selected_image_refs)
                    == tuple(prepared_refs)
                    and tuple(frozen.safe_request.selected_image_sha256)
                    == tuple(prepared_sha256)
                    and frozen.terminal_media_state
                    in {
                        ImageMediumState.QUALIFIED,
                        ImageMediumState.ANALYSIS_FAILED,
                    }
                )
        if not expected:
            raise ValueError("frozen provider execution state differs from selected images")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection-manifest", required=True, type=Path)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--schema-sha256", required=True)
    parser.add_argument("--protected-image-capability", required=True, type=Path)
    parser.add_argument("--protected-image-root", required=True, type=Path)
    parser.add_argument("--quota-receipt-sha256", required=True)
    parser.add_argument("--output-capability-sha256", required=True)
    parser.add_argument("--replay-fixture", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--live-operator-approval-sha256")
    parser.add_argument("--api-key-env")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify-only", action="store_true")
    return parser


async def _run(
    *,
    selection: ImageSelectionBatchManifest,
    config: Glm5VProviderConfig,
    protected: ProtectedImageCapabilityManifest,
    capability: ProviderObservationCapability,
    replay: ProviderReplayFixture | None,
    image_root: Path,
    live_api_key: str | None,
    live_approval: LiveProviderApprovalReceipt | None,
) -> FrozenObservationBatch:
    clock: Callable[[], datetime] = (
        (lambda: replay.frozen_at)
        if replay is not None
        else (lambda: datetime.now(UTC))
    )
    if replay is not None:
        adapter, client = build_mock_replay_adapter(config=config, fixture=replay, clock=clock)
    else:
        if (
            live_api_key is None
            or live_approval is None
            or capability.live_operator_approval_sha256 != live_approval.approval_sha256
        ):
            raise PermissionError("live provider authority is incomplete")
        client = build_glm5v_async_client(
            api_key=live_api_key,
            config=config,
            live_approval=live_approval,
            approval_time=clock(),
        )
        adapter = ZhipuGlm5VAdapter(config=config, client=client, clock=clock)
    root_fd = _open_image_root(image_root)
    try:
        return await generate_dev_image_observations(
            selection=selection,
            provider_config=config,
            capability=capability,
            protected_images=protected,
            image_loader=lambda entry: _image_loader(root_fd, entry),
            adapter=adapter,
            clock=clock,
        )
    finally:
        os.close(root_fd)
        await client.aclose()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        selection = _load_canonical(args.selection_manifest, ImageSelectionBatchManifest)
        config = _load_canonical(args.config, Glm5VProviderConfig)
        protected = _load_canonical(
            args.protected_image_capability,
            ProtectedImageCapabilityManifest,
        )
        if (
            args.selection_sha256 != selection.batch_sha256
            or args.config_sha256 != config.config_sha256
            or args.schema_sha256 != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256
        ):
            raise ValueError("explicit observation digest does not match exact artifact")

        replay: ProviderReplayFixture | None = None
        live_approval: LiveProviderApprovalReceipt | None = None
        if args.live:
            if (
                args.replay_fixture is not None
                or args.live_operator_approval_sha256 is None
                or args.api_key_env is None
                or os.environ.get("ITDA_OFFLINE") == "1"
                or os.environ.get("CI")
            ):
                raise PermissionError("live provider execution is not independently authorized")
            live_api_key = os.environ.get(args.api_key_env)
            if not live_api_key:
                raise PermissionError("live provider credential is unavailable")
            live_approval = _load_canonical(
                _LIVE_APPROVAL_RECEIPT_PATH,
                LiveProviderApprovalReceipt,
            )
            qualified_count = sum(
                manifest.media_state.value == "qualified" and bool(manifest.representatives)
                for manifest in selection.manifests
            )
            if (
                args.live_operator_approval_sha256 != live_approval.approval_sha256
                or live_approval.selection_manifest_sha256 != selection.batch_sha256
                or live_approval.provider_config_sha256 != config.config_sha256
                or live_approval.protected_image_capability_sha256 != protected.capability_sha256
                or live_approval.quota_receipt_sha256 != args.quota_receipt_sha256
                or live_approval.output_capability_sha256 != args.output_capability_sha256
                or live_approval.maximum_requests < qualified_count
            ):
                raise PermissionError("live provider approval does not bind the exact run")
            capability = ProviderObservationCapability.build_live(
                selection_manifest_sha256=selection.batch_sha256,
                provider_config_sha256=config.config_sha256,
                protected_image_capability_sha256=protected.capability_sha256,
                quota_receipt_sha256=args.quota_receipt_sha256,
                output_capability_sha256=args.output_capability_sha256,
                live_operator_approval_sha256=live_approval.approval_sha256,
            )
        else:
            if (
                args.replay_fixture is None
                or args.live_operator_approval_sha256
                or args.api_key_env
            ):
                raise ValueError("offline replay requires only one exact replay fixture")
            replay = _load_canonical(args.replay_fixture, ProviderReplayFixture)
            live_api_key = None
            capability = ProviderObservationCapability.build_replay(
                selection_manifest_sha256=selection.batch_sha256,
                provider_config_sha256=config.config_sha256,
                protected_image_capability_sha256=protected.capability_sha256,
                quota_receipt_sha256=args.quota_receipt_sha256,
                output_capability_sha256=args.output_capability_sha256,
                replay_fixture_sha256=replay.fixture_sha256,
            )

        if args.verify_only:
            output = _load_canonical(args.output, FrozenObservationBatch)
            root_fd = _open_image_root(args.protected_image_root)
            try:
                _verify_output(
                    output=output,
                    selection=selection,
                    config=config,
                    capability=capability,
                    protected=protected,
                    root_fd=root_fd,
                )
            finally:
                os.close(root_fd)
            return 0

        output = asyncio.run(
            _run(
                selection=selection,
                config=config,
                protected=protected,
                capability=capability,
                replay=replay,
                image_root=args.protected_image_root,
                live_api_key=live_api_key,
                live_approval=live_approval,
            )
        )
        _write_no_replace(args.output, canonical_json_bytes(output.model_dump(mode="json")))
    except (
        OSError,
        PermissionError,
        ValueError,
        ValidationError,
        json.JSONDecodeError,
    ) as error:
        raise SystemExit(
            "image observation pipeline rejected invalid or unauthorized input"
        ) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
