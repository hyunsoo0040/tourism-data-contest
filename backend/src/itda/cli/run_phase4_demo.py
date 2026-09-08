"""Materialize and finalize truthful local Phase 4 contest-demo evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

from pydantic import ValidationError

from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    RightsBoundImage,
    read_approved_image,
)
from itda.contracts.catalog_collection import CollectionAttempt, CollectionReport
from itda.contracts.catalog_optional_media import ImageMediumState, OptionalMediaCandidateSet
from itda.contracts.image_observation import (
    APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
    ImageObservationV2,
)
from itda.contracts.image_selection import (
    ImageSelectionBatchInput,
    ImageSelectionBatchManifest,
    PlaceImageSelectionCandidate,
    SelectionAssetSource,
)
from itda.contracts.phase4_benchmark import bind_evaluator_authority
from itda.contracts.phase4_demo import (
    DemoDevPlace,
    DemoImageReviewItem,
    DemoInputSnapshotAuthority,
    DemoProviderMode,
    DemoSelectedImage,
    DemoSourceDisposition,
    DemoSourceInventoryEntry,
    DemoSourceRole,
    DemoZeroImageMember,
    FrozenDemoSourceSnapshot,
    Phase4DemoEvaluationPreparation,
    Phase4DemoInputAuthority,
    Phase4DemoManifest,
    Phase4DemoMaterializationReceipt,
    Phase4DemoPredictionReceipt,
    Phase4DemoReviewDecisions,
    Phase4DemoReviewInventory,
    Phase4DemoTerminalReceipt,
    Phase4DemoTerminalReport,
    Phase4DemoZeroImageAbsenceRegistry,
    derive_materialization_receipt,
    validate_terminal_receipt_report,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.dev_image_observations import (
    FrozenObservationBatch,
    FrozenPlaceObservation,
    PredictionBatchFreezeReceipt,
    ProviderReplayFixture,
    _replay_observation,
    build_label_evaluation_capability,
    freeze_prediction_batch,
)

_MAX_JSON_BYTES = 64_000_000
_MAX_SQLITE_BYTES = 64_000_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png", ".webp", ".gif", ".tif", ".tiff", ".bmp"})
_SAFE_FAILURE = "phase4 demo rejected invalid or unauthorized input"
_DETERMINISTIC_FREEZE_TIME = datetime(2026, 8, 7, tzinfo=UTC)
_TRUSTED_COLLECTION_REPORT_SHA256 = (
    "89097d9619c23099cbf3224cd3f76efc395a83cb3fbe35db7855fa87a55a09cd"
)
_TRUSTED_COLLECTION_PLAN_SHA256 = "cd59461fb2c20c9dc45cfb2611a83974dc7a064b9082db82120a0661d434caf2"
_TRUSTED_COLLECTION_SEED_SHA256 = "d2e22d3231575dd57c96176e2e735458ee885324866d94ba1d8114fe02ca096b"
_TRUSTED_SNAPSHOT_RESPONSE_INVENTORY_SHA256 = (
    "b2fb3b72c7bb4c768b3b73957713bed74aff38afcfadb508b68fd6f2eefe825d"
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_CATALOG_RELATIVE = Path("artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json")
_SQLITE_SEAL_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/sqlite/real-manifest-seal-receipt.json"
)
_DEV_SQLITE_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/sqlite/releases/"
    "e45fae2e591542c1ecd8cc041ce4d2af863944f57be593ad38bfc196cf289ed0/"
    "evaluation-authority.sqlite3"
)
_COLLECTION_REPORT_RELATIVE = Path(
    "artifacts/restricted/catalog/v1/collection/collection-report.json"
)
_SNAPSHOT_ROOT_RELATIVE = Path("artifacts/restricted/catalog/v1/collection/snapshots")
_OPTIONAL_MEDIA_RELATIVE = Path(
    "artifacts/catalog/optional-media-v2/policy/"
    "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243/"
    "projected-candidates.json"
)
_REPLAY_FIXTURE_RELATIVE = Path("fixtures/synthetic/phase4/provider-replay.json")
_DEMO_AUTHORITY_RELATIVE = Path("artifacts/restricted/catalog/v2/phase4-demo-authority")
_INPUT_AUTHORITY_RELATIVE = _DEMO_AUTHORITY_RELATIVE / "input-authority.json"
_ZERO_IMAGE_REGISTRY_RELATIVE = _DEMO_AUTHORITY_RELATIVE / "zero-image-absence-registry.json"


def _file_signature(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_read(path: Path, *, max_bytes: int = _MAX_JSON_BYTES) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow:
        raise OSError("stable no-follow reads are unavailable")
    descriptor = os.open(path, os.O_RDONLY | nofollow | cloexec)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= max_bytes
        ):
            raise ValueError("demo input must be a bounded single-link regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("demo input ended before its pinned size")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if _file_signature(before) != _file_signature(after):
            raise ValueError("demo input changed during stable read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_at(directory_fd: int, name: str, *, max_bytes: int) -> bytes:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= max_bytes
    ):
        raise ValueError("fixed demo input must be a bounded single-link regular file")
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        opened = os.fstat(descriptor)
        if _file_signature(before) != _file_signature(opened):
            raise ValueError("fixed demo input changed before open")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("fixed demo input ended before its pinned size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if _file_signature(opened) != _file_signature(os.fstat(descriptor)):
            raise ValueError("fixed demo input changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _open_directory_at(directory_fd: int, name: str) -> int:
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise ValueError("fixed demo directory component is invalid")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("fixed demo directory component is invalid")
    return descriptor


def _secure_read_under(root: Path, relative: Path, *, max_bytes: int) -> bytes:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("fixed demo relative path is invalid")
    descriptor = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for component in relative.parts[:-1]:
            child = _open_directory_at(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return _read_at(descriptor, relative.parts[-1], max_bytes=max_bytes)
    finally:
        os.close(descriptor)


def _secure_direct_inventory(root: Path) -> dict[str, bytes]:
    descriptor = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        names = sorted(os.listdir(descriptor))
        if any(name.startswith(".") or not name.endswith(".json") for name in names):
            raise ValueError("fixed demo namespace contains a hidden or extraneous entry")
        return {name: _read_at(descriptor, name, max_bytes=_MAX_JSON_BYTES) for name in names}
    finally:
        os.close(descriptor)


def _load_canonical_mapping(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _stable_read(path)
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("demo input is not valid JSON") from exc
    if not isinstance(parsed, dict) or raw != canonical_json_bytes(parsed):
        raise ValueError("demo input must be a canonical JSON object")
    return raw, parsed


def _write_exact_no_replace(path: Path, payload: bytes, *, directory_mode: int = 0o700) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=directory_mode)
    if path.exists() or path.is_symlink():
        if _stable_read(path, max_bytes=max(len(payload), 1)) == payload:
            return
        raise FileExistsError("demo output already exists with different bytes")
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("demo publication made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _collect_sha256_strings(value: object) -> set[str]:
    found: set[str] = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            stack.extend(current.values())
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            stack.extend(current)
        elif isinstance(current, str) and _SHA256_RE.fullmatch(current):
            found.add(current)
    return found


def _read_dev_place_refs(database_path: Path) -> tuple[tuple[str, ...], bytes]:
    database_bytes = _stable_read(database_path, max_bytes=_MAX_SQLITE_BYTES)
    return _read_dev_place_refs_from_bytes(database_bytes), database_bytes


def _read_dev_place_refs_from_bytes(database_bytes: bytes) -> tuple[str, ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(database_bytes)
        connection.execute("PRAGMA query_only = ON")
        rows = connection.execute(
            "SELECT canonical_place_id FROM manifest_members "
            "WHERE split = ? ORDER BY manifest_version, member_ordinal",
            ("DEV",),
        ).fetchall()
    finally:
        connection.close()
    place_refs = tuple(str(row[0]) for row in rows)
    if len(place_refs) != 24 or len(set(place_refs)) != 24:
        raise ValueError("DEV authority must yield exactly 24 unique rows")
    return place_refs


def _load_collector_mapping(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _stable_read(path)
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("collector artifact is not valid JSON") from exc
    if not isinstance(parsed, dict) or raw != canonical_json_bytes(parsed) + b"\n":
        raise ValueError("collector artifact must be a canonical newline-terminated JSON object")
    return raw, parsed


def _validate_permission_evidence(report: CollectionReport) -> None:
    expected = {
        "15101578": False,
        "15101971": False,
        "15101914": True,
    }
    for snapshot in report.permission_evidence.snapshots:
        attribution_required = expected[snapshot.official_dataset_id]
        terms = snapshot.terms_projection
        if (
            terms.availability != "AVAILABLE"
            or not terms.commercial_use
            or not terms.derivative_use
            or terms.attribution_required is not attribution_required
        ):
            raise ValueError("collection report permission projection is not demo-eligible")


def _validated_snapshot_sources(
    snapshot_root: Path,
) -> tuple[tuple[tuple[Path, bytes, FrozenDemoSourceSnapshot], ...], bytes]:
    if not snapshot_root.is_dir() or snapshot_root.is_symlink():
        raise ValueError("snapshot root must be a real directory")
    report_raw, report_payload = _load_collector_mapping(
        snapshot_root.parent / "collection-report.json"
    )
    report = CollectionReport.model_validate(report_payload)
    _validate_permission_evidence(report)

    identities = {item.request_identity: item for item in report.request_identities}
    if len(identities) != 33:
        raise ValueError("collection report must contain the exact 33 request identities")
    successful_attempts = [item for item in report.attempts if item.terminal_state == "SUCCESS"]
    successful_by_hash: dict[str, CollectionAttempt] = {}
    for attempt in successful_attempts:
        if attempt.raw_body_sha256 in successful_by_hash:
            raise ValueError("successful collection response hashes must be unique")
        successful_by_hash[attempt.raw_body_sha256] = attempt
    if len(successful_by_hash) != 33 or {
        item.request_identity for item in successful_attempts
    } != set(identities):
        raise ValueError("collection report must bind exactly 33 successful requests")

    operation_by_role = {
        DemoSourceRole.TOUR_API: "areaBasedList2",
        DemoSourceRole.ODII: "themeSearchList",
        DemoSourceRole.TOURISM_PHOTO: "search",
    }
    rows: list[tuple[Path, bytes, FrozenDemoSourceSnapshot]] = []
    inventory_hashes: set[str] = set()
    files = sorted(snapshot_root.glob("*.json"), key=lambda item: item.name)
    if not files:
        raise ValueError("snapshot root contains no frozen JSON snapshots")
    for path in files:
        raw, parsed = _load_collector_mapping(path)
        snapshot = FrozenDemoSourceSnapshot.model_validate(parsed)
        bound_attempt = successful_by_hash.get(snapshot.raw_response_sha256)
        if bound_attempt is None:
            raise ValueError("snapshot does not bind a successful collection attempt")
        identity = identities.get(bound_attempt.request_identity)
        if identity is None or (
            identity.provider != snapshot.provider.value
            or identity.official_dataset_id != snapshot.official_dataset_id
            or identity.operation != operation_by_role[snapshot.provider]
            or identity.secret_free_parameters != snapshot.request_scope
            or bound_attempt.http_status != snapshot.http_status
            or bound_attempt.provider_result_code != snapshot.provider_result_code
            or bound_attempt.provider_result_value != snapshot.provider_result_value
            or bound_attempt.retry_classification != snapshot.retry_disposition
        ):
            raise ValueError("snapshot metadata does not match its exact collection request")
        if snapshot.raw_response_sha256 in inventory_hashes:
            raise ValueError("snapshot inventory contains a duplicate provider response")
        inventory_hashes.add(snapshot.raw_response_sha256)
        rows.append((path, raw, snapshot))
    if inventory_hashes != set(successful_by_hash):
        raise ValueError("snapshot inventory does not exhaust successful collection responses")
    counts = {
        role: sum(snapshot.provider is role for _, _, snapshot in rows) for role in DemoSourceRole
    }
    if any(count != 11 for count in counts.values()):
        raise ValueError("snapshot inventory requires exactly 11 responses per provider")
    return tuple(rows), report_raw


def _snapshot_inventory(
    *,
    validated_sources: tuple[tuple[Path, bytes, FrozenDemoSourceSnapshot], ...],
    supporting_claims: set[str],
) -> tuple[DemoSourceInventoryEntry, ...]:
    rows: list[DemoSourceInventoryEntry] = []
    for path, raw, snapshot in validated_sources:
        role = snapshot.provider
        source_sha256 = hashlib.sha256(raw).hexdigest()
        provider_payload_sha256 = snapshot.raw_response_sha256
        matched_claims = tuple(
            sorted(
                claim
                for claim in (source_sha256, provider_payload_sha256)
                if claim in supporting_claims
            )
        )
        if role is DemoSourceRole.TOURISM_PHOTO:
            disposition = (
                DemoSourceDisposition.EXACT_DEV_CLAIM_BINDING
                if matched_claims
                else DemoSourceDisposition.NO_EXACT_DEV_CLAIM_BINDING
            )
        else:
            disposition = DemoSourceDisposition.SUPPORTING_SOURCE_EVIDENCE
            matched_claims = ()
        rows.append(
            DemoSourceInventoryEntry(
                role=role,
                logical_path_sha256=canonical_sha256(
                    {"role": role.value, "snapshot_name": path.name}
                ),
                source_sha256=source_sha256,
                provider_payload_sha256=provider_payload_sha256,
                disposition=disposition,
                supporting_claim_sha256s=matched_claims,
            )
        )
    return tuple(sorted(rows, key=lambda row: (row.role.value, row.logical_path_sha256)))


def _require_trusted_collection_authority(
    report_raw: bytes,
    validated_sources: tuple[tuple[Path, bytes, FrozenDemoSourceSnapshot], ...],
) -> None:
    _, report_payload = _load_collector_mapping(
        validated_sources[0][0].parent.parent / "collection-report.json"
    )
    response_root = canonical_sha256(
        sorted(snapshot.raw_response_sha256 for _, _, snapshot in validated_sources)
    )
    if (
        hashlib.sha256(report_raw).hexdigest() != _TRUSTED_COLLECTION_REPORT_SHA256
        or report_payload.get("collection_plan_sha256") != _TRUSTED_COLLECTION_PLAN_SHA256
        or report_payload.get("seed_manifest_sha256") != _TRUSTED_COLLECTION_SEED_SHA256
        or response_root != _TRUSTED_SNAPSHOT_RESPONSE_INVENTORY_SHA256
    ):
        raise ValueError("collection inputs do not match the trusted local authority receipt")


def _count_local_image_files(snapshot_root: Path) -> int:
    count = 0
    for path in snapshot_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("snapshot tree contains a symbolic link")
        if path.is_file() and path.suffix.casefold() in _IMAGE_SUFFIXES:
            count += 1
    return count


def _load_catalog_dev_rows(
    payload: Mapping[str, object],
    place_refs: tuple[str, ...],
    tour_api_snapshot_hashes: set[str],
    odii_snapshot_hashes: set[str],
) -> tuple[
    dict[str, Mapping[str, object]],
    dict[str, Literal["EXACT_ODII_LINEAGE", "ODII_UNAVAILABLE"]],
]:
    if payload.get("schema_version") != "itda.catalog-v2-final-audit.v1":
        raise ValueError("catalog audit schema is invalid")
    rows = payload.get("rows")
    if not isinstance(rows, list) or payload.get("row_count") != 36 or len(rows) != 36:
        raise ValueError("catalog audit must contain exactly 36 rows")
    by_id: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("catalog audit row is invalid")
        place_ref = row.get("canonical_place_id")
        row_sha256 = row.get("canonical_row_sha256")
        if (
            not isinstance(place_ref, str)
            or not isinstance(row_sha256, str)
            or not _SHA256_RE.fullmatch(row_sha256)
            or place_ref in by_id
        ):
            raise ValueError("catalog audit row identity is invalid")
        if (
            canonical_sha256(
                {key: value for key, value in row.items() if key != "canonical_row_sha256"}
            )
            != row_sha256
        ):
            raise ValueError("catalog audit row digest is stale")
        by_id[place_ref] = row
    selected = {place_ref: by_id[place_ref] for place_ref in place_refs if place_ref in by_id}
    if len(selected) != 24:
        raise ValueError("DEV authority does not join exactly to the canonical audit")
    odii_lineage: dict[str, Literal["EXACT_ODII_LINEAGE", "ODII_UNAVAILABLE"]] = {}
    for place_ref, row in selected.items():
        rights_provenance = row.get("rights_provenance")
        if not isinstance(rights_provenance, Mapping):
            raise ValueError("DEV catalog row lacks rights provenance")
        assets = rights_provenance.get("assets")
        if not isinstance(assets, list):
            raise ValueError("DEV catalog row asset provenance is invalid")
        tour_hashes: set[str] = set()
        for asset in assets:
            if not isinstance(asset, Mapping) or asset.get("official_dataset_id") != "15101578":
                continue
            source_hash = asset.get("source_response_sha256")
            if not isinstance(source_hash, str) or not _SHA256_RE.fullmatch(source_hash):
                raise ValueError("DEV TourAPI asset lacks exact response lineage")
            tour_hashes.add(source_hash)
        if not tour_hashes or not tour_hashes.issubset(tour_api_snapshot_hashes):
            raise ValueError("DEV TourAPI lineage is outside the validated snapshot inventory")
        odii_hashes = {
            str(asset.get("source_response_sha256"))
            for asset in assets
            if isinstance(asset, Mapping)
            and asset.get("official_dataset_id") == "15101971"
            and isinstance(asset.get("source_response_sha256"), str)
        }
        if odii_hashes and not odii_hashes.issubset(odii_snapshot_hashes):
            raise ValueError("DEV Odii lineage is outside the validated snapshot inventory")
        odii_lineage[place_ref] = "EXACT_ODII_LINEAGE" if odii_hashes else "ODII_UNAVAILABLE"
    return selected, odii_lineage


def _load_optional_dev_rows(
    payload: Mapping[str, object],
    place_refs: tuple[str, ...],
) -> dict[str, Mapping[str, object]]:
    candidate_set = OptionalMediaCandidateSet.model_validate(payload)
    wanted = set(place_refs)
    selected = {
        row.place_entity_id: cast(Mapping[str, object], row.model_dump(mode="json"))
        for row in candidate_set.candidates
        if row.place_entity_id in wanted
    }
    if len(selected) != 24:
        raise ValueError("DEV authority does not join exactly to optional-media rows")
    return selected


def _open_image_root(path: Path) -> int:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("image root must be an absolute real directory")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    identity = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != os.geteuid()
        or stat.S_IMODE(identity.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise ValueError("image root ownership or mode is unsafe")
    return descriptor


def _source_by_id(
    candidate: PlaceImageSelectionCandidate,
) -> dict[str, SelectionAssetSource]:
    return {source.source_asset_id: source for source in candidate.assets}


def _materialize_selected_images(
    *,
    image_root: Path,
    rights_manifest: Path,
    selection_manifest: Path,
    dev_place_refs: tuple[str, ...],
) -> tuple[tuple[DemoSelectedImage, ...], dict[str, str]]:
    rights_raw, rights_payload = _load_canonical_mapping(rights_manifest)
    selection_raw, selection_payload = _load_canonical_mapping(selection_manifest)
    rights = ImageSelectionBatchInput.model_validate(rights_payload)
    selection = ImageSelectionBatchManifest.model_validate(selection_payload)
    if selection.input_manifest_sha256 != rights.input_manifest_sha256:
        raise ValueError("selection output does not bind the exact rights input")
    rights_by_place = {place.place_entity_id: place for place in rights.places}
    selection_places = tuple(manifest.place_entity_id for manifest in selection.manifests)
    if set(selection_places) != set(rights_by_place) or not set(selection_places).issubset(
        dev_place_refs
    ):
        raise ValueError("selection place inventory is not an exact DEV rights join")
    rows: list[DemoSelectedImage] = []
    root_fd = _open_image_root(image_root)
    try:
        for manifest in selection.manifests:
            candidate = rights_by_place[manifest.place_entity_id]
            if (
                manifest.input_authority_sha256 != candidate.input_authority_sha256
                or manifest.input_candidate_sha256 != candidate.recompute_input_sha256()
                or manifest.media_state is not candidate.media_state
            ):
                raise ValueError("selection manifest place lineage is stale")
            sources = _source_by_id(candidate)
            for representative in manifest.representatives:
                source = sources.get(representative.source_asset_id)
                if source is None or (
                    representative.rights_leaf_id != source.rights_leaf_id
                    or representative.rights_leaf_sha256 != source.rights_leaf_sha256
                    or representative.materialization_sha256 != source.materialization_sha256
                    or representative.preprocessing_policy_sha256
                    != manifest.preprocessing_policy_sha256
                ):
                    raise ValueError("representative does not join its exact source authority")
                approved = ApprovedImageMaterialization(
                    rights_leaf_id=source.rights_leaf_id,
                    rights_leaf_sha256=source.rights_leaf_sha256,
                    content_sha256=source.content_sha256,
                    materialization_sha256=source.materialization_sha256,
                )
                candidate_image = RightsBoundImage(
                    relative_path=source.relative_path,
                    rights_leaf_id=source.rights_leaf_id,
                    rights_leaf_sha256=source.rights_leaf_sha256,
                    content_sha256=source.content_sha256,
                )
                with read_approved_image(
                    root_fd=root_fd,
                    candidate=candidate_image,
                    approved=approved,
                ) as verified:
                    rows.append(
                        DemoSelectedImage(
                            place_ref=manifest.place_entity_id,
                            source_asset_id=source.source_asset_id,
                            representative_id=representative.representative_id,
                            source_content_sha256=verified.content_sha256,
                            selected_asset_sha256=representative.asset_sha256,
                            normalized_pixel_sha256=representative.normalized_pixel_sha256,
                            rights_leaf_sha256=source.rights_leaf_sha256,
                            materialization_sha256=source.materialization_sha256,
                            preprocessing_policy_sha256=(
                                representative.preprocessing_policy_sha256
                            ),
                        )
                    )
    finally:
        os.close(root_fd)
    ordered = tuple(
        sorted(rows, key=lambda row: (row.place_ref, row.source_asset_id, row.representative_id))
    )
    if not ordered:
        raise ValueError("image-present branch requires at least one selected representative")
    return ordered, {
        "rights_manifest": hashlib.sha256(rights_raw).hexdigest(),
        "selection_manifest": hashlib.sha256(selection_raw).hexdigest(),
    }


def _directory_entry_exists(path: Path) -> bool:
    try:
        state = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(state.st_mode):
        raise ValueError("fixed demo authority cannot contain symbolic links")
    return True


def _secure_image_inventory(root: Path) -> dict[str, bytes]:
    root_fd = _open_image_root(root.resolve(strict=True))
    rows: dict[str, bytes] = {}

    def walk(directory_fd: int, prefix: tuple[str, ...]) -> None:
        for name in sorted(os.listdir(directory_fd)):
            if name.startswith("."):
                raise ValueError("image namespace contains a hidden entry")
            state = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            relative = "/".join((*prefix, name))
            if stat.S_ISDIR(state.st_mode):
                child = _open_directory_at(directory_fd, name)
                try:
                    walk(child, (*prefix, name))
                finally:
                    os.close(child)
            elif stat.S_ISREG(state.st_mode) and state.st_nlink == 1:
                rows[relative] = _read_at(
                    directory_fd,
                    name,
                    max_bytes=_MAX_JSON_BYTES,
                )
            else:
                raise ValueError("image namespace contains an unsafe entry")

    try:
        walk(root_fd, ())
    finally:
        os.close(root_fd)
    return rows


def _derive_image_mode_authority(
    *,
    authority_root: Path,
    dev_place_refs: tuple[str, ...],
) -> tuple[dict[str, str | None], Phase4DemoZeroImageAbsenceRegistry | None]:
    image_root = authority_root / "image-root"
    rights_path = authority_root / "rights-manifest.json"
    selection_path = authority_root / "image-selection-manifest.json"
    exists = tuple(
        _directory_entry_exists(path) for path in (image_root, rights_path, selection_path)
    )
    if not any(exists):
        registry = Phase4DemoZeroImageAbsenceRegistry(
            image_namespace_state="ABSENT",
            members=tuple(
                DemoZeroImageMember(place_ref=place_ref) for place_ref in sorted(dev_place_refs)
            ),
        )
        return {
            "image_mode": "ZERO_IMAGE",
            "image_namespace_sha256": None,
            "rights_manifest_sha256": None,
            "image_selection_manifest_sha256": None,
            "zero_image_absence_registry_sha256": registry.registry_sha256,
        }, registry
    if exists == (True, False, False):
        inventory = _secure_image_inventory(image_root)
        if inventory:
            raise ValueError("image namespace contains unbound bytes")
        registry = Phase4DemoZeroImageAbsenceRegistry(
            image_namespace_state="EMPTY",
            members=tuple(
                DemoZeroImageMember(place_ref=place_ref) for place_ref in sorted(dev_place_refs)
            ),
        )
        return {
            "image_mode": "ZERO_IMAGE",
            "image_namespace_sha256": None,
            "rights_manifest_sha256": None,
            "image_selection_manifest_sha256": None,
            "zero_image_absence_registry_sha256": registry.registry_sha256,
        }, registry
    if not all(exists):
        raise ValueError("phase4 demo image inputs must be all-or-none")

    inventory = _secure_image_inventory(image_root)
    if not inventory:
        raise ValueError("image-bearing authority requires image bytes")
    rights_raw = _secure_read_under(
        authority_root,
        Path("rights-manifest.json"),
        max_bytes=_MAX_JSON_BYTES,
    )
    selection_raw = _secure_read_under(
        authority_root,
        Path("image-selection-manifest.json"),
        max_bytes=_MAX_JSON_BYTES,
    )
    rights = ImageSelectionBatchInput.model_validate_json(rights_raw)
    selection = ImageSelectionBatchManifest.model_validate_json(selection_raw)
    rights_by_place = {row.place_entity_id: row for row in rights.places}
    selection_by_place = {row.place_entity_id: row for row in selection.manifests}
    if (
        set(rights_by_place) != set(selection_by_place)
        or not set(rights_by_place).issubset(dev_place_refs)
        or selection.input_manifest_sha256 != rights.input_manifest_sha256
    ):
        raise ValueError("image authority cohort is not an exact DEV join")
    bound_paths: dict[str, str] = {}
    for place_ref, candidate in rights_by_place.items():
        manifest = selection_by_place[place_ref]
        asset_ids = tuple(asset.source_asset_id for asset in candidate.assets)
        decision_ids = tuple(decision.source_asset_id for decision in manifest.asset_decisions)
        if (
            set(asset_ids) != set(decision_ids)
            or len(asset_ids) != len(set(asset_ids))
            or manifest.input_candidate_sha256 != candidate.recompute_input_sha256()
            or manifest.input_authority_sha256 != candidate.input_authority_sha256
        ):
            raise ValueError("selection manifest does not exhaust its rights authority")
        for asset in candidate.assets:
            if asset.relative_path in bound_paths:
                raise ValueError("image bytes are bound more than once")
            raw = inventory.get(asset.relative_path)
            if raw is None or hashlib.sha256(raw).hexdigest() != asset.content_sha256:
                raise ValueError("image rights authority does not bind the exact byte")
            bound_paths[asset.relative_path] = asset.source_asset_id
    if set(bound_paths) != set(inventory):
        raise ValueError("image namespace contains unbound bytes")
    image_inventory = [
        {
            "relative_path": relative,
            "byte_sha256": hashlib.sha256(raw).hexdigest(),
            "byte_count": len(raw),
        }
        for relative, raw in sorted(inventory.items())
    ]
    return {
        "image_mode": "RIGHTS_REVIEWED_IMAGES",
        "image_namespace_sha256": canonical_sha256(image_inventory),
        "rights_manifest_sha256": hashlib.sha256(rights_raw).hexdigest(),
        "image_selection_manifest_sha256": hashlib.sha256(selection_raw).hexdigest(),
        "zero_image_absence_registry_sha256": None,
    }, None


def _derive_fixed_demo_input_authority() -> tuple[
    Phase4DemoInputAuthority,
    Phase4DemoZeroImageAbsenceRegistry | None,
]:
    catalog_raw = _secure_read_under(_REPOSITORY_ROOT, _CATALOG_RELATIVE, max_bytes=_MAX_JSON_BYTES)
    sqlite_seal_raw = _secure_read_under(
        _REPOSITORY_ROOT, _SQLITE_SEAL_RELATIVE, max_bytes=_MAX_JSON_BYTES
    )
    sqlite_raw = _secure_read_under(
        _REPOSITORY_ROOT, _DEV_SQLITE_RELATIVE, max_bytes=_MAX_SQLITE_BYTES
    )
    collection_report_raw = _secure_read_under(
        _REPOSITORY_ROOT, _COLLECTION_REPORT_RELATIVE, max_bytes=_MAX_JSON_BYTES
    )
    optional_raw = _secure_read_under(
        _REPOSITORY_ROOT, _OPTIONAL_MEDIA_RELATIVE, max_bytes=_MAX_JSON_BYTES
    )
    replay_raw = _secure_read_under(
        _REPOSITORY_ROOT, _REPLAY_FIXTURE_RELATIVE, max_bytes=_MAX_JSON_BYTES
    )
    catalog_payload = json.loads(catalog_raw)
    sqlite_seal_payload = json.loads(sqlite_seal_raw)
    optional_payload = json.loads(optional_raw)
    if (
        catalog_raw != canonical_json_bytes(catalog_payload)
        or sqlite_seal_raw != canonical_json_bytes(sqlite_seal_payload)
        or optional_raw != canonical_json_bytes(optional_payload)
    ):
        raise ValueError("fixed demo JSON authority is not canonical")
    dev_place_refs = _read_dev_place_refs_from_bytes(sqlite_raw)
    if (
        sqlite_seal_payload.get("database_sha256") != hashlib.sha256(sqlite_raw).hexdigest()
        or sqlite_seal_payload.get("database_size_bytes") != len(sqlite_raw)
        or sqlite_seal_payload.get("counts") != {"blind": 12, "dev": 24, "total": 36}
        or sqlite_seal_payload.get("catalog_revision_sha256")
        != catalog_payload.get("catalog_revision_sha256")
    ):
        raise ValueError("fixed demo SQLite seal does not bind the active database")
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(sqlite_raw)
        connection.execute("PRAGMA query_only = ON")
        seal_rows = connection.execute(
            "SELECT catalog_sha256, membership_sha256, logical_seal_sha256, "
            "dev_count, blind_count, total_count FROM manifest_seals"
        ).fetchall()
    finally:
        connection.close()
    expected_seal = (
        sqlite_seal_payload.get("catalog_revision_sha256"),
        sqlite_seal_payload.get("membership_sha256"),
        sqlite_seal_payload.get("logical_seal_sha256"),
        24,
        12,
        36,
    )
    if seal_rows != [expected_seal]:
        raise ValueError("fixed demo SQLite logical seal is stale")

    snapshot_root = _REPOSITORY_ROOT / _SNAPSHOT_ROOT_RELATIVE
    secure_snapshots = _secure_direct_inventory(snapshot_root)
    validated_sources, validated_report = _validated_snapshot_sources(snapshot_root)
    if (
        validated_report != collection_report_raw
        or {path.name: raw for path, raw, _ in validated_sources} != secure_snapshots
    ):
        raise ValueError("fixed demo snapshot namespace changed during derivation")
    _require_trusted_collection_authority(collection_report_raw, validated_sources)
    snapshot_inventory = tuple(
        DemoInputSnapshotAuthority(
            relative_name=name,
            byte_sha256=hashlib.sha256(raw).hexdigest(),
            byte_count=len(raw),
        )
        for name, raw in sorted(secure_snapshots.items())
    )
    replay_fixture = ProviderReplayFixture.model_validate_json(replay_raw)
    image_fields, zero_image = _derive_image_mode_authority(
        authority_root=_REPOSITORY_ROOT / _DEMO_AUTHORITY_RELATIVE,
        dev_place_refs=dev_place_refs,
    )
    authority_fields: dict[str, object] = {
        "catalog_sha256": hashlib.sha256(catalog_raw).hexdigest(),
        "catalog_root_sha256": str(catalog_payload["catalog_revision_sha256"]),
        "dev_sqlite_sha256": hashlib.sha256(sqlite_raw).hexdigest(),
        "sqlite_seal_receipt_sha256": hashlib.sha256(sqlite_seal_raw).hexdigest(),
        "sqlite_logical_seal_sha256": str(sqlite_seal_payload["logical_seal_sha256"]),
        "dev_membership_sha256": canonical_sha256(list(sorted(dev_place_refs))),
        "dev_place_refs": tuple(sorted(dev_place_refs)),
        "collection_report_sha256": hashlib.sha256(collection_report_raw).hexdigest(),
        "snapshot_inventory": snapshot_inventory,
        "snapshot_inventory_sha256": canonical_sha256(
            [row.model_dump(mode="json") for row in snapshot_inventory]
        ),
        "optional_media_sha256": hashlib.sha256(optional_raw).hexdigest(),
        "optional_media_root_sha256": str(optional_payload["candidate_set_sha256"]),
        "replay_fixture_sha256": hashlib.sha256(replay_raw).hexdigest(),
        "replay_fixture_contract_sha256": replay_fixture.fixture_sha256,
        **image_fields,
    }
    authority = Phase4DemoInputAuthority.model_validate(authority_fields)
    return authority, zero_image


def _validate_fixed_demo_input_authority(authority: Phase4DemoInputAuthority) -> None:
    current, _ = _derive_fixed_demo_input_authority()
    if canonical_json_bytes(current.model_dump(mode="json")) != canonical_json_bytes(
        authority.model_dump(mode="json")
    ):
        raise ValueError("fixed demo input authority differs from current bytes")


def _derive_authority() -> int:
    authority, zero_image = _derive_fixed_demo_input_authority()
    zero_image_path = _REPOSITORY_ROOT / _ZERO_IMAGE_REGISTRY_RELATIVE
    if zero_image is not None:
        _write_exact_no_replace(
            zero_image_path,
            canonical_json_bytes(zero_image.model_dump(mode="json")),
        )
    elif _directory_entry_exists(zero_image_path):
        raise ValueError("image authority conflicts with a zero-image registry")
    _write_exact_no_replace(
        _REPOSITORY_ROOT / _INPUT_AUTHORITY_RELATIVE,
        canonical_json_bytes(authority.model_dump(mode="json")),
    )
    print(
        json.dumps(
            {
                "authority_sha256": authority.authority_sha256,
                "image_mode": authority.image_mode,
                "status": "AUTHORITY_DERIVED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _load_fixed_demo_input_authority() -> Phase4DemoInputAuthority:
    raw = _secure_read_under(_REPOSITORY_ROOT, _INPUT_AUTHORITY_RELATIVE, max_bytes=_MAX_JSON_BYTES)
    authority = Phase4DemoInputAuthority.model_validate_json(raw)
    if raw != canonical_json_bytes(authority.model_dump(mode="json")):
        raise ValueError("fixed demo input authority is not canonical")
    registry_path = _REPOSITORY_ROOT / _ZERO_IMAGE_REGISTRY_RELATIVE
    if authority.image_mode == "ZERO_IMAGE":
        registry_raw = _secure_read_under(
            _REPOSITORY_ROOT, _ZERO_IMAGE_REGISTRY_RELATIVE, max_bytes=_MAX_JSON_BYTES
        )
        registry = Phase4DemoZeroImageAbsenceRegistry.model_validate_json(registry_raw)
        if (
            registry_raw != canonical_json_bytes(registry.model_dump(mode="json"))
            or authority.zero_image_absence_registry_sha256 != registry.registry_sha256
        ):
            raise ValueError("fixed demo zero-image authority is stale")
    elif _directory_entry_exists(registry_path):
        raise ValueError("image authority conflicts with a zero-image registry")
    _validate_fixed_demo_input_authority(authority)
    return authority


def _materialize_from_explicit_inputs(
    args: argparse.Namespace,
    *,
    authority: Phase4DemoInputAuthority | None = None,
    allow_synthetic_test_inputs: bool = False,
) -> int:
    if authority is None and not allow_synthetic_test_inputs:
        raise PermissionError(
            "explicit phase4 demo inputs are synthetic-test-only and require an explicit opt-in"
        )
    image_values = (args.image_root, args.rights_manifest, args.image_selection_manifest)
    if any(value is not None for value in image_values) and not all(
        value is not None for value in image_values
    ):
        raise ValueError("phase4 demo image inputs must be all-or-none")

    catalog_raw, catalog_payload = _load_canonical_mapping(args.catalog_audit)
    optional_raw, optional_payload = _load_canonical_mapping(args.optional_media)
    dev_place_refs, sqlite_raw = _read_dev_place_refs(args.dev_sqlite)
    validated_sources, collection_report_raw = _validated_snapshot_sources(args.snapshot_root)
    if authority is not None:
        current_snapshots = tuple(
            DemoInputSnapshotAuthority(
                relative_name=path.name,
                byte_sha256=hashlib.sha256(raw).hexdigest(),
                byte_count=len(raw),
            )
            for path, raw, _ in validated_sources
        )
        if not (
            hashlib.sha256(catalog_raw).hexdigest() == authority.catalog_sha256
            and hashlib.sha256(optional_raw).hexdigest() == authority.optional_media_sha256
            and hashlib.sha256(sqlite_raw).hexdigest() == authority.dev_sqlite_sha256
            and hashlib.sha256(collection_report_raw).hexdigest()
            == authority.collection_report_sha256
            and tuple(sorted(dev_place_refs)) == authority.dev_place_refs
            and current_snapshots == authority.snapshot_inventory
        ):
            raise ValueError("fixed demo input authority changed before materialization")
    _require_trusted_collection_authority(collection_report_raw, validated_sources)
    tour_api_snapshot_hashes = {
        snapshot.raw_response_sha256
        for _, _, snapshot in validated_sources
        if snapshot.provider is DemoSourceRole.TOUR_API
    }
    odii_snapshot_hashes = {
        snapshot.raw_response_sha256
        for _, _, snapshot in validated_sources
        if snapshot.provider is DemoSourceRole.ODII
    }
    catalog_rows, odii_lineage = _load_catalog_dev_rows(
        catalog_payload,
        dev_place_refs,
        tour_api_snapshot_hashes,
        odii_snapshot_hashes,
    )
    optional_rows = _load_optional_dev_rows(optional_payload, dev_place_refs)

    claim_source: list[object] = []
    claim_source.extend(catalog_rows[place_ref] for place_ref in dev_place_refs)
    claim_source.extend(optional_rows[place_ref] for place_ref in dev_place_refs)
    supporting_claims = _collect_sha256_strings(claim_source)

    selected_images: tuple[DemoSelectedImage, ...] = ()
    image_input_hashes: dict[str, str] = {}
    if all(value is not None for value in image_values):
        selected_images, image_input_hashes = _materialize_selected_images(
            image_root=cast(Path, args.image_root),
            rights_manifest=cast(Path, args.rights_manifest),
            selection_manifest=cast(Path, args.image_selection_manifest),
            dev_place_refs=dev_place_refs,
        )
        supporting_claims.update(image_input_hashes.values())
    elif _count_local_image_files(args.snapshot_root) != 0:
        raise ValueError("image inputs cannot be omitted while local image bytes exist")

    source_inventory = _snapshot_inventory(
        validated_sources=validated_sources,
        supporting_claims=supporting_claims,
    )
    selected_count_by_place = {
        place_ref: sum(image.place_ref == place_ref for image in selected_images)
        for place_ref in dev_place_refs
    }
    dev_places = tuple(
        sorted(
            (
                DemoDevPlace(
                    place_ref=place_ref,
                    catalog_row_sha256=str(catalog_rows[place_ref]["canonical_row_sha256"]),
                    optional_media_row_sha256=str(optional_rows[place_ref]["row_sha256"]),
                    image_medium_state=ImageMediumState(
                        str(
                            cast(Mapping[str, object], optional_rows[place_ref]["image_medium"])[
                                "state"
                            ]
                        )
                    ),
                    selected_image_count=selected_count_by_place[place_ref],
                    odii_lineage=odii_lineage[place_ref],
                )
                for place_ref in dev_place_refs
            ),
            key=lambda row: row.place_ref,
        )
    )
    input_sha256 = {
        "catalog_audit": hashlib.sha256(catalog_raw).hexdigest(),
        "collection_report": hashlib.sha256(collection_report_raw).hexdigest(),
        "dev_sqlite": hashlib.sha256(sqlite_raw).hexdigest(),
        **image_input_hashes,
        "optional_media": hashlib.sha256(optional_raw).hexdigest(),
    }
    if authority is not None:
        input_sha256["input_authority"] = cast(str, authority.authority_sha256)
    else:
        input_sha256["synthetic_test_authority"] = canonical_sha256(
            {"mode": "SYNTHETIC_TEST_ONLY", "input_sha256": input_sha256}
        )
    input_sha256 = dict(sorted(input_sha256.items()))
    source_payload = [row.model_dump(mode="json") for row in source_inventory]
    place_payload = [row.model_dump(mode="json") for row in dev_places]
    image_payload = [row.model_dump(mode="json") for row in selected_images]
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-manifest.v2",
        "input_sha256": input_sha256,
        "snapshot_inventory_sha256": canonical_sha256(source_payload),
        "dev_projection_sha256": canonical_sha256(place_payload),
        "selected_image_inventory_sha256": canonical_sha256(image_payload),
        "source_inventory": source_payload,
        "dev_places": place_payload,
        "selected_images": image_payload,
        "source_truth": (
            "REAL_LOCAL_DATA"
            if all(value == "EXACT_ODII_LINEAGE" for value in odii_lineage.values())
            else "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
        ),
        "profile_truth": "SOURCE_EVIDENCE_ONLY",
        "profile_score_truth": "NO_LOCAL_PROFILE_SCORES",
        "image_truth": "REAL_LOCAL_IMAGES" if selected_images else "NO_IMAGE_TEXT_ODII_ONLY",
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    manifest = Phase4DemoManifest.model_validate(
        {**fields, "manifest_sha256": canonical_sha256(fields)}
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json"))
    private_output = args.artifact_root / manifest.manifest_sha256 / "phase4-demo-manifest.json"
    _write_exact_no_replace(private_output, manifest_bytes)

    receipt = derive_materialization_receipt(manifest)
    _write_exact_no_replace(
        args.receipt_output,
        canonical_json_bytes(receipt.model_dump(mode="json")),
    )
    print(
        json.dumps(
            {
                "manifest_sha256": manifest.manifest_sha256,
                "receipt_sha256": receipt.receipt_sha256,
                "status": "MATERIALIZED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _materialize(args: argparse.Namespace) -> int:
    authority = _load_fixed_demo_input_authority()
    image_root: Path | None = None
    rights_manifest: Path | None = None
    image_selection_manifest: Path | None = None
    if authority.image_mode == "RIGHTS_REVIEWED_IMAGES":
        authority_root = _REPOSITORY_ROOT / _DEMO_AUTHORITY_RELATIVE
        image_root = authority_root / "image-root"
        rights_manifest = authority_root / "rights-manifest.json"
        image_selection_manifest = authority_root / "image-selection-manifest.json"
    fixed_args = argparse.Namespace(
        catalog_audit=_REPOSITORY_ROOT / _CATALOG_RELATIVE,
        dev_sqlite=_REPOSITORY_ROOT / _DEV_SQLITE_RELATIVE,
        snapshot_root=_REPOSITORY_ROOT / _SNAPSHOT_ROOT_RELATIVE,
        optional_media=_REPOSITORY_ROOT / _OPTIONAL_MEDIA_RELATIVE,
        artifact_root=args.artifact_root,
        receipt_output=args.receipt_output,
        image_root=image_root,
        rights_manifest=rights_manifest,
        image_selection_manifest=image_selection_manifest,
    )
    return _materialize_from_explicit_inputs(fixed_args, authority=authority)


def _load_materialized_run(
    *, receipt_path: Path, artifact_root: Path
) -> tuple[Phase4DemoMaterializationReceipt, Phase4DemoManifest]:
    _, receipt_payload = _load_canonical_mapping(receipt_path)
    receipt = Phase4DemoMaterializationReceipt.model_validate(receipt_payload)
    manifest_path = artifact_root / receipt.manifest_sha256 / "phase4-demo-manifest.json"
    _, manifest_payload = _load_canonical_mapping(manifest_path)
    manifest = Phase4DemoManifest.model_validate(manifest_payload)
    if receipt != derive_materialization_receipt(manifest):
        raise ValueError("materialization receipt does not match its private manifest authority")
    require_fixed_materialization_authority(manifest)
    return receipt, manifest


def require_fixed_materialization_authority(
    manifest: Phase4DemoManifest,
) -> Phase4DemoInputAuthority:
    """Reject coherent receipts unless they bind the current fixed input authority."""

    authority = _load_fixed_demo_input_authority()
    expected_inputs = {
        "catalog_audit": authority.catalog_sha256,
        "collection_report": authority.collection_report_sha256,
        "dev_sqlite": authority.dev_sqlite_sha256,
        "input_authority": cast(str, authority.authority_sha256),
        "optional_media": authority.optional_media_sha256,
    }
    if authority.image_mode == "RIGHTS_REVIEWED_IMAGES":
        expected_inputs.update(
            {
                "rights_manifest": cast(str, authority.rights_manifest_sha256),
                "selection_manifest": cast(str, authority.image_selection_manifest_sha256),
            }
        )
    if manifest.input_sha256 != dict(sorted(expected_inputs.items())):
        raise ValueError("materialization does not bind the fixed demo input authority")

    if tuple(place.place_ref for place in manifest.dev_places) != authority.dev_place_refs:
        raise ValueError("materialization DEV membership differs from fixed authority")

    snapshot_root = _REPOSITORY_ROOT / _SNAPSHOT_ROOT_RELATIVE
    validated_sources, _ = _validated_snapshot_sources(snapshot_root)
    expected_sources = tuple(
        sorted(
            (
                snapshot.provider.value,
                canonical_sha256({"role": snapshot.provider.value, "snapshot_name": path.name}),
                hashlib.sha256(raw).hexdigest(),
                snapshot.raw_response_sha256,
            )
            for path, raw, snapshot in validated_sources
        )
    )
    actual_sources = tuple(
        sorted(
            (
                row.role.value,
                row.logical_path_sha256,
                row.source_sha256,
                row.provider_payload_sha256,
            )
            for row in manifest.source_inventory
        )
    )
    if actual_sources != expected_sources:
        raise ValueError("materialization snapshot inventory differs from fixed authority")

    if authority.image_mode == "ZERO_IMAGE":
        if manifest.selected_images or manifest.image_truth != "NO_IMAGE_TEXT_ODII_ONLY":
            raise ValueError("zero-image authority cannot accept selected image evidence")
    elif not manifest.selected_images or manifest.image_truth != "REAL_LOCAL_IMAGES":
        raise ValueError("image authority requires its bound selected image evidence")
    return authority


def _fact_free_observation(*, state: ImageMediumState, selection_sha256: str) -> ImageObservationV2:
    fields: dict[str, object] = {
        "schema_version": "photo-attributes.v2",
        "media_state": state.value,
        "representative_manifest_sha256": selection_sha256,
        "selected_image_refs": [],
        "observations": [],
        "candidate_axes": [],
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    return ImageObservationV2.model_validate(
        {**fields, "observation_sha256": canonical_sha256(fields)}
    )


def _freeze_fact_free_batch(manifest: Phase4DemoManifest) -> FrozenObservationBatch:
    selection_sha256 = manifest.selected_image_inventory_sha256
    timestamp = _DETERMINISTIC_FREEZE_TIME.isoformat().replace("+00:00", "Z")
    rows: list[FrozenPlaceObservation] = []
    for place in manifest.dev_places:
        terminal_state = (
            ImageMediumState.ANALYSIS_FAILED
            if place.image_medium_state is ImageMediumState.QUALIFIED
            else place.image_medium_state
        )
        failure_code = (
            "NO_LOCAL_IMAGE_BYTES"
            if place.image_medium_state is ImageMediumState.QUALIFIED
            else place.image_medium_state.value
        )
        observation = _fact_free_observation(
            state=terminal_state,
            selection_sha256=selection_sha256,
        )
        fields: dict[str, object] = {
            "schema_version": "itda.phase4-frozen-place-observation.v1",
            "place_entity_id": place.place_ref,
            "selection_manifest_sha256": selection_sha256,
            "input_media_state": place.image_medium_state.value,
            "terminal_media_state": terminal_state.value,
            "provider_called": False,
            "safe_request": None,
            "provider_prediction": None,
            "observation": observation.model_dump(mode="json"),
            "failure_code": failure_code,
            "frozen_at": timestamp,
        }
        rows.append(
            FrozenPlaceObservation.model_validate(
                {**fields, "record_sha256": canonical_sha256(fields)}
            )
        )
    provider_config_sha256 = canonical_sha256(
        {"provider_mode": DemoProviderMode.NO_PROVIDER_NO_IMAGE.value}
    )
    provider_capability_sha256 = canonical_sha256(
        {"authority": "NO_PROVIDER_CAPABILITY", "selected_image_count": 0}
    )
    fields = {
        "schema_version": "itda.phase4-frozen-observation-batch.v1",
        "selection_manifest_sha256": selection_sha256,
        "provider_config_sha256": provider_config_sha256,
        "observation_schema_sha256": APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
        "provider_capability_sha256": provider_capability_sha256,
        "replay_fixture_sha256": None,
        "observations": [row.model_dump(mode="json") for row in rows],
        "frozen_at": timestamp,
    }
    return FrozenObservationBatch.model_validate(
        {**fields, "batch_sha256": canonical_sha256(fields)}
    )


def _freeze_replay_batch(
    *, manifest: Phase4DemoManifest, fixture_path: Path
) -> FrozenObservationBatch:
    fixture_raw = _stable_read(fixture_path)
    try:
        fixture_payload = json.loads(fixture_raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("provider replay fixture is not valid JSON") from exc
    fixture = ProviderReplayFixture.model_validate(fixture_payload)
    selection_sha256 = manifest.selected_image_inventory_sha256
    timestamp = fixture.frozen_at.isoformat().replace("+00:00", "Z")
    images_by_place: dict[str, list[DemoSelectedImage]] = {}
    for image in manifest.selected_images:
        images_by_place.setdefault(image.place_ref, []).append(image)
    rows: list[FrozenPlaceObservation] = []
    for place in manifest.dev_places:
        selected = tuple(
            sorted(images_by_place.get(place.place_ref, ()), key=lambda row: row.representative_id)
        )
        if selected:
            observation = _replay_observation(
                fixture=fixture,
                selection_manifest_sha256=selection_sha256,
                selected_refs=tuple(
                    f"selected-image:{image.representative_id}" for image in selected
                ),
            )
            terminal_state = ImageMediumState.QUALIFIED
            failure_code = None
        else:
            terminal_state = (
                ImageMediumState.ANALYSIS_FAILED
                if place.image_medium_state is ImageMediumState.QUALIFIED
                else place.image_medium_state
            )
            failure_code = (
                "NO_SELECTED_REPRESENTATIVE"
                if place.image_medium_state is ImageMediumState.QUALIFIED
                else place.image_medium_state.value
            )
            observation = _fact_free_observation(
                state=terminal_state,
                selection_sha256=selection_sha256,
            )
        fields: dict[str, object] = {
            "schema_version": "itda.phase4-frozen-place-observation.v1",
            "place_entity_id": place.place_ref,
            "selection_manifest_sha256": selection_sha256,
            "input_media_state": place.image_medium_state.value,
            "terminal_media_state": terminal_state.value,
            "provider_called": False,
            "safe_request": None,
            "provider_prediction": None,
            "observation": observation.model_dump(mode="json"),
            "failure_code": failure_code,
            "frozen_at": timestamp,
        }
        rows.append(
            FrozenPlaceObservation.model_validate(
                {**fields, "record_sha256": canonical_sha256(fields)}
            )
        )
    provider_config_sha256 = canonical_sha256(
        {
            "provider_mode": DemoProviderMode.PROVIDER_REPLAY.value,
            "fixture_sha256": fixture.fixture_sha256,
        }
    )
    provider_capability_sha256 = canonical_sha256(
        {
            "authority": "CREDENTIAL_FREE_MOCK_REPLAY",
            "fixture_sha256": fixture.fixture_sha256,
        }
    )
    batch_fields: dict[str, object] = {
        "schema_version": "itda.phase4-frozen-observation-batch.v1",
        "selection_manifest_sha256": selection_sha256,
        "provider_config_sha256": provider_config_sha256,
        "observation_schema_sha256": APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
        "provider_capability_sha256": provider_capability_sha256,
        "replay_fixture_sha256": fixture.fixture_sha256,
        "observations": [row.model_dump(mode="json") for row in rows],
        "frozen_at": timestamp,
    }
    return FrozenObservationBatch.model_validate(
        {**batch_fields, "batch_sha256": canonical_sha256(batch_fields)}
    )


def _observe(args: argparse.Namespace) -> int:
    materialization, manifest = _load_materialized_run(
        receipt_path=args.materialization_receipt,
        artifact_root=args.artifact_root,
    )
    if not manifest.selected_images:
        if args.provider_mode == "live":
            raise ValueError("live provider mode requires eligible actual image bytes")
        provider_mode = DemoProviderMode.NO_PROVIDER_NO_IMAGE
        predictions = _freeze_fact_free_batch(manifest)
    else:
        if args.provider_mode == "live":
            raise ValueError("LIVE_PAID_PROVIDER requires a separate bounded human cost approval")
        authority = _load_fixed_demo_input_authority()
        replay_raw = _stable_read(args.replay_fixture)
        replay = ProviderReplayFixture.model_validate_json(replay_raw)
        if not (
            hashlib.sha256(replay_raw).hexdigest() == authority.replay_fixture_sha256
            and replay.fixture_sha256 == authority.replay_fixture_contract_sha256
        ):
            raise ValueError("provider replay fixture differs from fixed demo authority")
        provider_mode = DemoProviderMode.PROVIDER_REPLAY
        predictions = _freeze_replay_batch(
            manifest=manifest,
            fixture_path=args.replay_fixture,
        )

    freeze_receipt = freeze_prediction_batch(predictions)
    run_root = args.artifact_root / manifest.manifest_sha256
    _write_exact_no_replace(
        run_root / "frozen-observations.json",
        canonical_json_bytes(predictions.model_dump(mode="json")),
    )
    _write_exact_no_replace(
        run_root / "prediction-freeze-receipt.json",
        canonical_json_bytes(freeze_receipt.model_dump(mode="json")),
    )
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-prediction-receipt.v1",
        "materialization_receipt_sha256": materialization.receipt_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "observation_batch_sha256": predictions.batch_sha256,
        "freeze_receipt_sha256": freeze_receipt.receipt_sha256,
        "observation_count": len(predictions.observations),
        "provider_mode": provider_mode.value,
        "image_claim_inventory_count": sum(
            len(observation.visible_evidence)
            for row in predictions.observations
            for observation in row.observation.observations
        ),
        "source_truth": manifest.source_truth,
        "profile_truth": manifest.profile_truth,
        "profile_score_truth": manifest.profile_score_truth,
        "image_truth": manifest.image_truth,
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    receipt = Phase4DemoPredictionReceipt.model_validate(
        {**fields, "receipt_sha256": canonical_sha256(fields)}
    )
    _write_exact_no_replace(
        args.receipt_output,
        canonical_json_bytes(receipt.model_dump(mode="json")),
    )
    print(
        json.dumps(
            {
                "observation_batch_sha256": predictions.batch_sha256,
                "provider_mode": provider_mode.value,
                "receipt_sha256": receipt.receipt_sha256,
                "status": "PREDICTIONS_FROZEN",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _load_prediction_run(
    *,
    prediction_receipt_path: Path,
    artifact_root: Path,
    materialization: Phase4DemoMaterializationReceipt,
    manifest: Phase4DemoManifest,
) -> tuple[Phase4DemoPredictionReceipt, FrozenObservationBatch, PredictionBatchFreezeReceipt]:
    _, receipt_payload = _load_canonical_mapping(prediction_receipt_path)
    receipt = Phase4DemoPredictionReceipt.model_validate(receipt_payload)
    if (
        receipt.manifest_sha256 != manifest.manifest_sha256
        or receipt.materialization_receipt_sha256 != materialization.receipt_sha256
        or receipt.source_truth != manifest.source_truth
        or receipt.profile_truth != manifest.profile_truth
        or receipt.profile_score_truth != manifest.profile_score_truth
        or receipt.image_truth != manifest.image_truth
        or receipt.benchmark_truth != manifest.benchmark_truth
    ):
        raise ValueError("prediction receipt crosses materialized runs")
    run_root = artifact_root / manifest.manifest_sha256
    _, predictions_payload = _load_canonical_mapping(run_root / "frozen-observations.json")
    predictions = FrozenObservationBatch.model_validate(predictions_payload)
    _, freeze_payload = _load_canonical_mapping(run_root / "prediction-freeze-receipt.json")
    freeze_receipt = PredictionBatchFreezeReceipt.model_validate(freeze_payload)
    expected_freeze = freeze_prediction_batch(predictions)
    expected_selected_refs = {
        place.place_ref: tuple(
            sorted(
                f"selected-image:{image.representative_id}"
                for image in manifest.selected_images
                if image.place_ref == place.place_ref
            )
        )
        for place in manifest.dev_places
    }
    actual_claim_count = 0
    for row in predictions.observations:
        selected_refs = expected_selected_refs.get(row.place_entity_id)
        if selected_refs is None or row.observation.selected_image_refs != selected_refs:
            raise ValueError("frozen predictions do not bind selected image inventory")
        for observation in row.observation.observations:
            for evidence in observation.visible_evidence:
                if evidence.image_ref not in selected_refs:
                    raise ValueError("visible evidence does not bind a selected image")
                actual_claim_count += 1
    expected_provider_mode = (
        DemoProviderMode.PROVIDER_REPLAY
        if predictions.replay_fixture_sha256 is not None
        else DemoProviderMode.NO_PROVIDER_NO_IMAGE
    )
    expected_image_truth = (
        "REAL_LOCAL_IMAGES" if manifest.selected_images else "NO_IMAGE_TEXT_ODII_ONLY"
    )
    if (
        receipt.observation_batch_sha256 != predictions.batch_sha256
        or receipt.freeze_receipt_sha256 != freeze_receipt.receipt_sha256
        or freeze_receipt != expected_freeze
        or receipt.observation_count != len(predictions.observations)
        or receipt.provider_mode is not expected_provider_mode
        or receipt.image_claim_inventory_count != actual_claim_count
        or receipt.image_truth != expected_image_truth
        or receipt.benchmark_truth != "NO_REAL_IMAGE_BENCHMARK"
    ):
        raise ValueError("prediction receipt does not bind the exact frozen batch")
    return receipt, predictions, freeze_receipt


def _derive_review_inventory(predictions: FrozenObservationBatch) -> Phase4DemoReviewInventory:
    items: list[DemoImageReviewItem] = []
    for row in predictions.observations:
        for observation in row.observation.observations:
            for evidence in observation.visible_evidence:
                item_fields: dict[str, object] = {
                    "stable_observation_sha256": row.record_sha256,
                    "attribute_id": observation.attribute_id.value,
                    "selected_image_ref": evidence.image_ref,
                    "region": evidence.region,
                    "caption_ko": evidence.caption_ko,
                }
                items.append(
                    DemoImageReviewItem.model_validate(
                        {
                            **item_fields,
                            "inventory_item_sha256": canonical_sha256(item_fields),
                        }
                    )
                )
    ordered_items = tuple(sorted(items, key=lambda item: item.inventory_item_sha256))
    if not ordered_items:
        raise ValueError("image review inventory requires actual visible evidence")
    inventory_fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-review-inventory.v1",
        "prediction_batch_sha256": predictions.batch_sha256,
        "items": [item.model_dump(mode="json") for item in ordered_items],
    }
    return Phase4DemoReviewInventory.model_validate(
        {**inventory_fields, "inventory_sha256": canonical_sha256(inventory_fields)}
    )


_FORBIDDEN_EVALUATION_KEYS = frozenset(
    {
        "blind",
        "blind_membership",
        "complement",
        "credentials",
        "provider_credential",
        "raw_image",
        "split_membership",
    }
)


def _reject_evaluation_payload_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_EVALUATION_KEYS:
                raise ValueError("evaluation payload contains prohibited authority")
            _reject_evaluation_payload_keys(nested)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            _reject_evaluation_payload_keys(nested)


def _prepare_evaluation(args: argparse.Namespace) -> int:
    materialization, manifest = _load_materialized_run(
        receipt_path=args.materialization_receipt,
        artifact_root=args.artifact_root,
    )
    prediction, predictions, freeze_receipt = _load_prediction_run(
        prediction_receipt_path=args.prediction_receipt,
        artifact_root=args.artifact_root,
        materialization=materialization,
        manifest=manifest,
    )

    label_input_sha256: str | None = None
    if args.dev_labels is not None:
        label_raw, label_payload = _load_canonical_mapping(args.dev_labels)
        _reject_evaluation_payload_keys(label_payload)
        label_input_sha256 = hashlib.sha256(label_raw).hexdigest()
    label_capability_sha256 = label_input_sha256 or canonical_sha256(
        {"label_authority": "NO_LOCAL_DEV_LABELS"}
    )
    evaluator_authority_sha256 = canonical_sha256(
        {"scope": "DEV_ONLY_DIGEST_EVALUATOR", "manifest": manifest.manifest_sha256}
    )
    inventory_sha256 = freeze_receipt.dev_case_inventory_sha256
    if inventory_sha256 is None:
        raise ValueError("prediction freeze receipt lacks a protected DEV case inventory")
    capability = build_label_evaluation_capability(
        predictions=predictions,
        freeze_receipt=freeze_receipt,
        label_capability_sha256=label_capability_sha256,
        label_case_inventory_sha256=inventory_sha256,
        prediction_case_records_sha256=canonical_sha256(
            [row.model_dump(mode="json") for row in predictions.observations]
        ),
        label_case_records_sha256=label_input_sha256
        or canonical_sha256({"label_authority": "NO_LOCAL_DEV_LABELS"}),
        review_inventory_sha256=canonical_sha256([]),
        evaluator_authority_sha256=evaluator_authority_sha256,
        created_at=freeze_receipt.frozen_at + timedelta(seconds=1),
    )
    authority = bind_evaluator_authority(
        dev_authority_sha256=manifest.dev_projection_sha256,
        selection=SimpleNamespace(batch_sha256=predictions.selection_manifest_sha256),
        predictions=predictions,
        freeze_receipt=freeze_receipt,
        label_capability=capability,
    )
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-evaluation-preparation.v1",
        "materialization_receipt_sha256": materialization.receipt_sha256,
        "prediction_receipt_sha256": prediction.receipt_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "observation_batch_sha256": predictions.batch_sha256,
        "freeze_receipt_sha256": freeze_receipt.receipt_sha256,
        "evaluator_authority_binding_sha256": authority.authority_binding_sha256,
        "label_input_sha256": label_input_sha256,
        "evaluation_state": "NOT_EVALUATED_NO_LOCAL_PROFILE_SCORES",
        "image_claim_inventory_count": prediction.image_claim_inventory_count,
    }
    preparation = Phase4DemoEvaluationPreparation.model_validate(
        {**fields, "preparation_sha256": canonical_sha256(fields)}
    )
    _write_exact_no_replace(
        args.artifact_root / manifest.manifest_sha256 / "evaluation-preparation.json",
        canonical_json_bytes(preparation.model_dump(mode="json")),
    )
    if prediction.image_claim_inventory_count:
        inventory = _derive_review_inventory(predictions)
        if len(inventory.items) != prediction.image_claim_inventory_count:
            raise ValueError("review inventory does not exhaust image claims")
        _write_exact_no_replace(
            args.artifact_root / manifest.manifest_sha256 / "image-review-inventory.json",
            canonical_json_bytes(inventory.model_dump(mode="json")),
        )
    print(
        json.dumps(
            {
                "preparation_sha256": preparation.preparation_sha256,
                "status": preparation.evaluation_state,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _finalize(args: argparse.Namespace) -> int:
    materialization, manifest = _load_materialized_run(
        receipt_path=args.materialization_receipt,
        artifact_root=args.artifact_root,
    )
    prediction, predictions, freeze_receipt = _load_prediction_run(
        prediction_receipt_path=args.prediction_receipt,
        artifact_root=args.artifact_root,
        materialization=materialization,
        manifest=manifest,
    )
    run_root = args.artifact_root / manifest.manifest_sha256
    _, preparation_payload = _load_canonical_mapping(run_root / "evaluation-preparation.json")
    preparation = Phase4DemoEvaluationPreparation.model_validate(preparation_payload)
    if (
        preparation.materialization_receipt_sha256 != materialization.receipt_sha256
        or preparation.prediction_receipt_sha256 != prediction.receipt_sha256
        or preparation.observation_batch_sha256 != predictions.batch_sha256
        or preparation.freeze_receipt_sha256 != freeze_receipt.receipt_sha256
    ):
        raise ValueError("evaluation preparation crosses frozen run boundaries")
    human_decision_sha256: str | None = None
    if prediction.image_claim_inventory_count == 0:
        if args.review_decisions is not None:
            raise ValueError("zero-image finalization cannot accept human review input")
        if prediction.provider_mode is not DemoProviderMode.NO_PROVIDER_NO_IMAGE:
            raise ValueError("fact-free terminal branch has an invalid provider mode")
        terminal_decision = "NO_IMAGE_TEXT_ODII_ONLY"
        image_review_gate = "NOT_APPLICABLE"
    else:
        if prediction.provider_mode is not DemoProviderMode.PROVIDER_REPLAY:
            raise ValueError("image-bearing demo finalization requires a closed provider mode")
        if args.review_decisions is None:
            raise ValueError("image-bearing finalization requires complete review decisions")
        _, inventory_payload = _load_canonical_mapping(run_root / "image-review-inventory.json")
        inventory = Phase4DemoReviewInventory.model_validate(inventory_payload)
        expected_inventory = _derive_review_inventory(predictions)
        _, decisions_payload = _load_canonical_mapping(args.review_decisions)
        decisions = Phase4DemoReviewDecisions.model_validate(decisions_payload)
        inventory_ids = tuple(item.inventory_item_sha256 for item in inventory.items)
        decision_ids = tuple(entry.inventory_item_sha256 for entry in decisions.entries)
        if (
            inventory.prediction_batch_sha256 != predictions.batch_sha256
            or inventory != expected_inventory
            or inventory.inventory_sha256 != decisions.inventory_sha256
            or inventory_ids != decision_ids
            or len(inventory_ids) != prediction.image_claim_inventory_count
        ):
            raise ValueError("review decisions do not completely bind the image inventory")
        human_decision_sha256 = decisions.decisions_sha256
        terminal_decision = "PROVIDER_REPLAY_REVIEWED"
        image_review_gate = "COMPLETED"

    report_fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-terminal-report.v1",
        "manifest_sha256": manifest.manifest_sha256,
        "materialization_receipt_sha256": materialization.receipt_sha256,
        "prediction_receipt_sha256": prediction.receipt_sha256,
        "evaluation_preparation_sha256": preparation.preparation_sha256,
        "observation_batch_sha256": predictions.batch_sha256,
        "freeze_receipt_sha256": freeze_receipt.receipt_sha256,
        "provider_mode": prediction.provider_mode.value,
        "terminal_decision": terminal_decision,
        "image_review_gate": image_review_gate,
        "image_claim_inventory_count": prediction.image_claim_inventory_count,
        "human_decision_receipt_sha256": human_decision_sha256,
        "source_truth": manifest.source_truth,
        "profile_truth": manifest.profile_truth,
        "profile_score_truth": manifest.profile_score_truth,
        "image_truth": manifest.image_truth,
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    report = Phase4DemoTerminalReport.model_validate(
        {**report_fields, "terminal_report_sha256": canonical_sha256(report_fields)}
    )
    _write_exact_no_replace(
        run_root / "phase4-demo-terminal-report.json",
        canonical_json_bytes(report.model_dump(mode="json")),
    )
    receipt_fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-terminal-receipt.v1",
        "manifest_sha256": manifest.manifest_sha256,
        "materialization_receipt_sha256": materialization.receipt_sha256,
        "prediction_receipt_sha256": prediction.receipt_sha256,
        "evaluation_preparation_sha256": preparation.preparation_sha256,
        "terminal_report_sha256": report.terminal_report_sha256,
        "provider_mode": prediction.provider_mode.value,
        "terminal_decision": terminal_decision,
        "image_review_gate": image_review_gate,
        "image_claim_inventory_count": prediction.image_claim_inventory_count,
        "human_decision_receipt_sha256": human_decision_sha256,
        "source_truth": manifest.source_truth,
        "profile_truth": manifest.profile_truth,
        "profile_score_truth": manifest.profile_score_truth,
        "image_truth": manifest.image_truth,
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    receipt = Phase4DemoTerminalReceipt.model_validate(
        {**receipt_fields, "receipt_sha256": canonical_sha256(receipt_fields)}
    )
    validate_terminal_receipt_report(receipt, report)
    _write_exact_no_replace(
        args.receipt_output,
        canonical_json_bytes(receipt.model_dump(mode="json")),
    )
    print(
        json.dumps(
            {
                "receipt_sha256": receipt.receipt_sha256,
                "status": receipt.terminal_decision,
                "terminal_report_sha256": report.terminal_report_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("derive-authority")
    materialize = subcommands.add_parser("materialize")
    materialize.add_argument("--artifact-root", required=True, type=Path)
    materialize.add_argument("--receipt-output", required=True, type=Path)
    observe = subcommands.add_parser("observe")
    observe.add_argument("--materialization-receipt", required=True, type=Path)
    observe.add_argument("--artifact-root", required=True, type=Path)
    observe.add_argument("--provider-mode", choices=("auto", "live"), default="auto")
    observe.add_argument("--replay-fixture", required=True, type=Path)
    observe.add_argument("--receipt-output", required=True, type=Path)
    prepare = subcommands.add_parser("prepare-evaluation")
    prepare.add_argument("--materialization-receipt", required=True, type=Path)
    prepare.add_argument("--prediction-receipt", required=True, type=Path)
    prepare.add_argument("--artifact-root", required=True, type=Path)
    prepare.add_argument("--dev-labels", type=Path)
    finalize = subcommands.add_parser("finalize")
    finalize.add_argument("--materialization-receipt", required=True, type=Path)
    finalize.add_argument("--prediction-receipt", required=True, type=Path)
    finalize.add_argument("--artifact-root", required=True, type=Path)
    finalize.add_argument("--review-decisions", type=Path)
    finalize.add_argument("--receipt-output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "derive-authority":
            return _derive_authority()
        if args.command == "materialize":
            return _materialize(args)
        if args.command == "observe":
            return _observe(args)
        if args.command == "prepare-evaluation":
            return _prepare_evaluation(args)
        if args.command == "finalize":
            return _finalize(args)
    except ValueError as exc:
        if "all-or-none" in str(exc):
            raise SystemExit(str(exc)) from None
        raise SystemExit(_SAFE_FAILURE) from exc
    except (FileExistsError, OSError, ValidationError, sqlite3.Error) as exc:
        raise SystemExit(_SAFE_FAILURE) from exc
    raise SystemExit(_SAFE_FAILURE)


if __name__ == "__main__":
    raise SystemExit(main())
