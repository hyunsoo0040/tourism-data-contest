"""Collect exact DEV-24 TourAPI description bodies for Phase 5 materialization."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from itda.collectors.base import CollectedResponse, CollectionError, RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnostics, ProviderDiagnosticsError
from itda.collectors.kto import KorService2Client
from itda.collectors.snapshots import write_snapshot
from itda.contracts.demo_profile_materialization import (
    DemoSourceBundle,
    seal_demo_contract,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.demo_profile_materialization import validate_demo_source_inventory

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
ARTIFACT_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/phase5-demo-profile-materialization"
FIXED_DEV_AUTHORITY = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/phase4-demo-authority/input-authority.json"
)
FIXED_CANONICAL_CATALOG = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json"
)
SECRET_FILE = REPOSITORY_ROOT / ".secrets/itda-api.env"
_SAFE_ROOT = "artifacts/restricted/catalog/phase5-demo-profile-materialization"
_DATASET_ID = "15101578"
_ENDPOINT = "KorService2/detailCommon2"
_SCHEMA = "itda.phase5-demo-source-authority.v1"
_RECEIPT_SCHEMA = "itda.phase5-demo-source-collection-receipt.v1"


class Phase5DemoSourceCollectionError(ValueError):
    """Secret-safe source collection or authority failure."""


@dataclass(frozen=True, slots=True)
class AuthorizedDevRow:
    place_id: str
    name_ko: str
    content_id: str
    canonical_row_sha256: str
    dataset_grant_sha256: str
    dataset_grant_leaf_sha256: str
    dataset_grant_page_sha256: str
    dataset_grant_response_sha256: str


def _read_regular(path: Path, *, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise Phase5DemoSourceCollectionError("FIXED_INPUT_INVALID")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise Phase5DemoSourceCollectionError("FIXED_INPUT_TRUNCATED")
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
            raise Phase5DemoSourceCollectionError("FIXED_INPUT_CHANGED")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _read_regular_beneath(
    root_descriptor: int,
    components: Sequence[str],
    *,
    maximum: int,
) -> bytes:
    """Read one regular file relative to a caller-pinned root descriptor."""

    if not components or any(
        not component or component in {".", ".."} or "/" in component for component in components
    ):
        raise Phase5DemoSourceCollectionError("FIXED_INPUT_INVALID")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_descriptor = os.dup(root_descriptor)
    descriptor: int | None = None
    try:
        for component in components[:-1]:
            child_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
        descriptor = os.open(
            components[-1],
            file_flags,
            dir_fd=directory_descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise Phase5DemoSourceCollectionError("FIXED_INPUT_INVALID")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise Phase5DemoSourceCollectionError("FIXED_INPUT_TRUNCATED")
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
            raise Phase5DemoSourceCollectionError("FIXED_INPUT_CHANGED")
        return bytes(payload)
    except OSError as error:
        raise Phase5DemoSourceCollectionError("FIXED_INPUT_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)


def _object(path: Path, *, maximum: int = 64 * 1024 * 1024) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular(path, maximum=maximum))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Phase5DemoSourceCollectionError("FIXED_JSON_INVALID") from error
    if not isinstance(value, dict):
        raise Phase5DemoSourceCollectionError("FIXED_JSON_NOT_OBJECT")
    return cast(dict[str, Any], value)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fixed_dev_rows() -> tuple[AuthorizedDevRow, ...]:
    authority = _object(FIXED_DEV_AUTHORITY, maximum=4 * 1024 * 1024)
    if authority.get("authority_sha256") != canonical_sha256(
        {key: value for key, value in authority.items() if key != "authority_sha256"}
    ):
        raise Phase5DemoSourceCollectionError("DEV_AUTHORITY_DIGEST_DRIFT")
    ids = authority.get("dev_place_refs")
    if (
        not isinstance(ids, list)
        or len(ids) != 24
        or len(set(ids)) != 24
        or tuple(ids) != tuple(sorted(ids))
        or any(not isinstance(value, str) or not value.startswith("place:") for value in ids)
    ):
        raise Phase5DemoSourceCollectionError("DEV_AUTHORITY_MEMBERSHIP_INVALID")
    catalog = _object(FIXED_CANONICAL_CATALOG)
    rows = catalog.get("rows")
    if not isinstance(rows, list) or len(rows) != 36:
        raise Phase5DemoSourceCollectionError("CANONICAL_CATALOG_INVALID")
    by_id = {
        row.get("canonical_place_id"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("canonical_place_id"), str)
    }
    result: list[AuthorizedDevRow] = []
    for place_id in cast(list[str], ids):
        row = by_id.get(place_id)
        if not isinstance(row, dict):
            raise Phase5DemoSourceCollectionError("DEV_ROW_MISSING")
        provenance = row.get("dataset_provenance")
        if not isinstance(provenance, list) or len(provenance) != 1:
            raise Phase5DemoSourceCollectionError("TOURAPI_IDENTITY_NOT_EXACT")
        evidence = provenance[0].get("evidence") if isinstance(provenance[0], dict) else None
        if (
            not isinstance(evidence, dict)
            or evidence.get("provider") != "TOUR_API"
            or evidence.get("official_dataset_id") != _DATASET_ID
            or not isinstance(evidence.get("provider_record_id"), str)
            or not str(evidence["provider_record_id"]).isdigit()
        ):
            raise Phase5DemoSourceCollectionError("TOURAPI_IDENTITY_NOT_EXACT")
        rights = row.get("rights_provenance")
        grants = rights.get("dataset_grants") if isinstance(rights, dict) else None
        matching = [
            grant
            for grant in grants or []
            if isinstance(grant, dict) and grant.get("official_dataset_id") == _DATASET_ID
        ]
        if len(matching) != 1:
            raise Phase5DemoSourceCollectionError("TOURAPI_GRANT_NOT_EXACT")
        grant = matching[0]
        if not all(
            (
                grant.get("allowed") is True,
                grant.get("model_input_allowed") is True,
                grant.get("transform_allowed") is True,
                grant.get("evidence_state") == "COMPLETE",
            )
        ):
            raise Phase5DemoSourceCollectionError("TOURAPI_GRANT_NOT_AUTHORIZED")
        required_hashes = {
            key: grant.get(key)
            for key in (
                "dataset_grant_sha256",
                "leaf_sha256",
                "page_sha256",
                "response_sha256",
            )
        }
        if any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in required_hashes.values()
        ):
            raise Phase5DemoSourceCollectionError("TOURAPI_GRANT_DIGEST_INVALID")
        result.append(
            AuthorizedDevRow(
                place_id=place_id,
                name_ko=str(row.get("name_ko", "")),
                content_id=str(evidence["provider_record_id"]),
                canonical_row_sha256=str(row.get("canonical_row_sha256", "")),
                dataset_grant_sha256=cast(str, required_hashes["dataset_grant_sha256"]),
                dataset_grant_leaf_sha256=cast(str, required_hashes["leaf_sha256"]),
                dataset_grant_page_sha256=cast(str, required_hashes["page_sha256"]),
                dataset_grant_response_sha256=cast(str, required_hashes["response_sha256"]),
            )
        )
    if tuple(row.place_id for row in result) != tuple(cast(list[str], ids)):
        raise Phase5DemoSourceCollectionError("DEV_ROW_ORDER_DRIFT")
    return tuple(result)


def _read_secret() -> str:
    metadata = SECRET_FILE.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise Phase5DemoSourceCollectionError("SECRET_FILE_INVALID")
    raw = _read_regular(SECRET_FILE, maximum=64 * 1024)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise Phase5DemoSourceCollectionError("SECRET_FILE_ENCODING_INVALID") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise Phase5DemoSourceCollectionError("SECRET_FILE_RECORD_INVALID")
        name, value = line.split("=", 1)
        if not name or not value or name in values:
            raise Phase5DemoSourceCollectionError("SECRET_FILE_RECORD_INVALID")
        values[name] = value
    try:
        return values["TOUR_API_SERVICE_KEY"]
    except KeyError as error:
        raise Phase5DemoSourceCollectionError("TOURAPI_SECRET_UNAVAILABLE") from error


def _items(payload: object) -> tuple[Mapping[str, object], ...]:
    try:
        response = cast(Mapping[str, object], payload)["response"]
        body = cast(Mapping[str, object], response)["body"]
        items = cast(Mapping[str, object], body)["items"]
        item = cast(Mapping[str, object], items)["item"]
    except (KeyError, TypeError) as error:
        raise Phase5DemoSourceCollectionError("TOURAPI_BODY_SHAPE_INVALID") from error
    values = item if isinstance(item, list) else [item]
    if len(values) != 1 or not isinstance(values[0], Mapping):
        raise Phase5DemoSourceCollectionError("TOURAPI_EXACT_ITEM_REQUIRED")
    return (cast(Mapping[str, object], values[0]),)


def _bundle_and_authority(
    row: AuthorizedDevRow,
    collected: CollectedResponse,
    *,
    snapshot_sha256: str,
) -> tuple[DemoSourceBundle, dict[str, object]]:
    if collected.provider != "TOUR_API" or collected.endpoint != _ENDPOINT:
        raise Phase5DemoSourceCollectionError("TOURAPI_ENDPOINT_DRIFT")
    expected_scope = {
        "MobileApp": "IT-DA",
        "MobileOS": "ETC",
        "_type": "json",
        "contentId": row.content_id,
        "numOfRows": "1",
        "pageNo": "1",
    }
    if collected.request_scope != expected_scope or collected.http_status != 200:
        raise Phase5DemoSourceCollectionError("TOURAPI_REQUEST_SCOPE_DRIFT")
    item = _items(collected.payload)[0]
    if str(item.get("contentid", item.get("contentId", ""))) != row.content_id:
        raise Phase5DemoSourceCollectionError("TOURAPI_CONTENT_ID_MISMATCH")
    overview = item.get("overview")
    if not isinstance(overview, str) or not overview.strip():
        raise Phase5DemoSourceCollectionError("TOURAPI_OVERVIEW_MISSING")
    text_sha256 = _sha256(overview.encode("utf-8"))
    evidence_id = f"tourapi-description:{row.content_id}:{text_sha256[:16]}"
    evidence = {
        "evidence_id": evidence_id,
        "source_kind": "TOUR_API_DESCRIPTION",
        "source_sha256": text_sha256,
        "span_sha256": text_sha256,
        "text": overview,
    }
    fields: dict[str, object] = {
        "schema_version": "itda.demo-source-bundle.v1",
        "place_id": row.place_id,
        "split": "DEV",
        "sources": [evidence],
        "optional_image": None,
        "source_inventory_sha256": canonical_sha256(
            [{key: value for key, value in evidence.items() if key != "text"}]
        ),
    }
    bundle = DemoSourceBundle.model_validate(
        seal_demo_contract(fields, digest_field="source_bundle_sha256")
    )
    authority_fields: dict[str, object] = {
        "place_id": row.place_id,
        "canonical_row_sha256": row.canonical_row_sha256,
        "provider": "TOUR_API",
        "official_dataset_id": _DATASET_ID,
        "endpoint": _ENDPOINT,
        "content_id": row.content_id,
        "request_scope": expected_scope,
        "request_scope_sha256": canonical_sha256(expected_scope),
        "retrieved_at": collected.retrieved_at.isoformat().replace("+00:00", "Z"),
        "http_status": collected.http_status,
        "provider_result_code": collected.provider_result_code,
        "provider_result_value": collected.provider_result_value,
        "raw_response_sha256": collected.raw_response_sha256,
        "snapshot_sha256": snapshot_sha256,
        "evidence_id": evidence_id,
        "overview_sha256": text_sha256,
        "source_bundle_sha256": bundle.source_bundle_sha256,
        "dataset_grant_sha256": row.dataset_grant_sha256,
        "dataset_grant_leaf_sha256": row.dataset_grant_leaf_sha256,
        "dataset_grant_page_sha256": row.dataset_grant_page_sha256,
        "dataset_grant_response_sha256": row.dataset_grant_response_sha256,
        "model_input_allowed": True,
        "transform_allowed": True,
    }
    authority_fields["member_sha256"] = canonical_sha256(authority_fields)
    return bundle, authority_fields


def collect_authorized_dev_sources(
    *,
    rows: Sequence[AuthorizedDevRow],
    client: KorService2Client,
    run_root: Path,
    diagnostics: ProviderDiagnostics,
) -> tuple[tuple[DemoSourceBundle, ...], tuple[dict[str, object], ...]]:
    bundles: list[DemoSourceBundle] = []
    authority: list[dict[str, object]] = []
    snapshots = run_root / "snapshots"
    snapshots.mkdir(parents=True, exist_ok=True, mode=0o700)
    snapshots.chmod(0o700)
    diagnostics.run_started()
    for row in rows:
        operation = diagnostics.operation(
            candidate_place_id=row.place_id,
            candidate_name=row.name_ko,
            provider="TOUR_API",
            operation="detailCommon2",
        )
        collected = client.request(
            "detailCommon2",
            {"contentId": row.content_id, "numOfRows": 1, "pageNo": 1},
            explicit_opt_in=True,
            diagnostics=diagnostics,
            diagnostic_operation=operation,
        )
        snapshot = write_snapshot(collected, snapshots)
        snapshot.chmod(0o600)
        bundle, member = _bundle_and_authority(
            row,
            collected,
            snapshot_sha256=_sha256(snapshot.read_bytes()),
        )
        bundles.append(bundle)
        authority.append(member)
        diagnostics.complete_operation(operation)
    diagnostics.terminal_success()
    validated = validate_demo_source_inventory(bundles)
    return validated, tuple(authority)


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short private write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _authority_payload(
    bundles: Sequence[DemoSourceBundle],
    members: Sequence[Mapping[str, object]],
    *,
    collection_run_id: str,
    diagnostics_file: str,
) -> dict[str, object]:
    fields: dict[str, object] = {
        "schema_version": _SCHEMA,
        "status": "COMPLETE_AUTHORIZED_DEV_24",
        "analysis_scope": "DEV_ONLY",
        "blind_excluded": True,
        "provider": "TOUR_API",
        "official_dataset_id": _DATASET_ID,
        "endpoint": _ENDPOINT,
        "member_count": 24,
        "member_sha256": [member["member_sha256"] for member in members],
        "source_bundle_sha256": [bundle.source_bundle_sha256 for bundle in bundles],
        "collection_run_id": collection_run_id,
        "diagnostics_file": diagnostics_file,
    }
    fields["authority_sha256"] = canonical_sha256(fields)
    return fields


def verify_source_collection(
    root: Path = ARTIFACT_ROOT,
    *,
    expected_rows: Sequence[AuthorizedDevRow] | None = None,
    root_descriptor: int | None = None,
) -> tuple[DemoSourceBundle, ...]:
    rows = tuple(_fixed_dev_rows() if expected_rows is None else expected_rows)

    def read_root(*components: str, maximum: int) -> bytes:
        if root_descriptor is None:
            return _read_regular(root.joinpath(*components), maximum=maximum)
        return _read_regular_beneath(root_descriptor, components, maximum=maximum)

    try:
        bundles_value = json.loads(read_root("source-bundles.json", maximum=64 * 1024 * 1024))
        authority_value = json.loads(read_root("source-authority.json", maximum=64 * 1024 * 1024))
        members = json.loads(read_root("source-authority-members.json", maximum=8 * 1024 * 1024))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Phase5DemoSourceCollectionError("SOURCE_COLLECTION_JSON_INVALID") from error
    if (
        not isinstance(bundles_value, list)
        or not isinstance(authority_value, dict)
        or not isinstance(members, list)
    ):
        raise Phase5DemoSourceCollectionError("SOURCE_COLLECTION_INVENTORY_INVALID")
    authority = cast(dict[str, Any], authority_value)
    try:
        bundles = validate_demo_source_inventory(
            tuple(DemoSourceBundle.model_validate(value) for value in bundles_value)
        )
    except (ValidationError, ValueError) as error:
        raise Phase5DemoSourceCollectionError("SOURCE_BUNDLE_INVALID") from error
    if tuple(bundle.place_id for bundle in bundles) != tuple(row.place_id for row in rows):
        raise Phase5DemoSourceCollectionError("SOURCE_MEMBERSHIP_DRIFT")
    if authority.get("authority_sha256") != canonical_sha256(
        {key: value for key, value in authority.items() if key != "authority_sha256"}
    ):
        raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_DIGEST_DRIFT")
    if (
        authority.get("schema_version") != _SCHEMA
        or authority.get("status") != "COMPLETE_AUTHORIZED_DEV_24"
        or authority.get("member_count") != 24
        or authority.get("blind_excluded") is not True
        or authority.get("provider") != "TOUR_API"
        or authority.get("official_dataset_id") != _DATASET_ID
        or authority.get("endpoint") != _ENDPOINT
        or authority.get("source_bundle_sha256")
        != [bundle.source_bundle_sha256 for bundle in bundles]
    ):
        raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_CONTRACT_DRIFT")
    if len(members) != 24:
        raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_MEMBER_COUNT_INVALID")
    collection_run_id = authority.get("collection_run_id")
    diagnostics_file = authority.get("diagnostics_file")
    if (
        not isinstance(collection_run_id, str)
        or not collection_run_id.startswith("run-")
        or not isinstance(diagnostics_file, str)
        or not diagnostics_file.startswith("provider-collection-")
        or not diagnostics_file.endswith(".jsonl")
    ):
        raise Phase5DemoSourceCollectionError("SOURCE_COLLECTION_IDENTITY_INVALID")
    run_components = ("source-collection", collection_run_id)
    read_root(*run_components, "diagnostics", diagnostics_file, maximum=8 * 1024 * 1024)
    by_row = {row.place_id: row for row in rows}
    for bundle, value in zip(bundles, members, strict=True):
        if not isinstance(value, dict):
            raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_MEMBER_INVALID")
        supplied = value.get("member_sha256")
        if supplied != canonical_sha256(
            {key: nested for key, nested in value.items() if key != "member_sha256"}
        ):
            raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_MEMBER_DIGEST_DRIFT")
        row = by_row[bundle.place_id]
        source = bundle.sources[0]
        raw_response_sha256 = value.get("raw_response_sha256")
        snapshot_sha256 = value.get("snapshot_sha256")
        if not isinstance(raw_response_sha256, str) or not isinstance(snapshot_sha256, str):
            raise Phase5DemoSourceCollectionError("SOURCE_SNAPSHOT_DIGEST_MISSING")
        snapshot_bytes = read_root(
            *run_components,
            "snapshots",
            f"TOUR_API-detailCommon2-{raw_response_sha256}.json",
            maximum=4 * 1024 * 1024,
        )
        if _sha256(snapshot_bytes) != snapshot_sha256:
            raise Phase5DemoSourceCollectionError("SOURCE_SNAPSHOT_DIGEST_DRIFT")
        try:
            snapshot = json.loads(snapshot_bytes)
            encoded_raw = snapshot["raw_body_base64"]
            raw_body = base64.b64decode(encoded_raw, validate=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise Phase5DemoSourceCollectionError("SOURCE_SNAPSHOT_INVALID") from error
        if (
            snapshot.get("provider") != "TOUR_API"
            or snapshot.get("endpoint") != _ENDPOINT
            or snapshot.get("official_dataset_id") != _DATASET_ID
            or snapshot.get("http_status") != 200
            or snapshot.get("request_scope") != value.get("request_scope")
            or snapshot.get("retrieved_at") != value.get("retrieved_at")
            or snapshot.get("raw_response_sha256") != raw_response_sha256
            or _sha256(raw_body) != raw_response_sha256
        ):
            raise Phase5DemoSourceCollectionError("SOURCE_SNAPSHOT_LINEAGE_DRIFT")
        try:
            raw_payload = json.loads(raw_body)
        except json.JSONDecodeError as error:
            raise Phase5DemoSourceCollectionError("SOURCE_RAW_RESPONSE_INVALID") from error
        if raw_payload != snapshot.get("payload"):
            raise Phase5DemoSourceCollectionError("SOURCE_RAW_PAYLOAD_DRIFT")
        raw_item = _items(raw_payload)[0]
        raw_overview = raw_item.get("overview")
        if (
            value.get("place_id") != row.place_id
            or value.get("content_id") != row.content_id
            or value.get("canonical_row_sha256") != row.canonical_row_sha256
            or value.get("source_bundle_sha256") != bundle.source_bundle_sha256
            or value.get("evidence_id") != source.evidence_id
            or value.get("overview_sha256") != source.source_sha256
            or value.get("dataset_grant_sha256") != row.dataset_grant_sha256
            or value.get("dataset_grant_leaf_sha256") != row.dataset_grant_leaf_sha256
            or value.get("model_input_allowed") is not True
            or value.get("transform_allowed") is not True
            or value.get("http_status") != 200
            or str(raw_item.get("contentid", raw_item.get("contentId", ""))) != row.content_id
            or raw_overview != source.text
            or _sha256(source.text.encode("utf-8")) != source.source_sha256
        ):
            raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_MEMBER_DRIFT")
    if authority.get("member_sha256") != [member["member_sha256"] for member in members]:
        raise Phase5DemoSourceCollectionError("SOURCE_AUTHORITY_INVENTORY_DRIFT")
    return bundles


def _safe_preflight() -> dict[str, object]:
    rows = _fixed_dev_rows()
    credential_present = bool(_read_secret())
    return {
        "schema_version": "itda.phase5-demo-source-preflight.v1",
        "status": "READY" if credential_present else "BLOCKED",
        "secret_present": credential_present,
        "provider": "TOUR_API",
        "official_dataset_id": _DATASET_ID,
        "endpoint": _ENDPOINT,
        "source_count": len(rows),
        "split": "DEV_ONLY",
        "blind_excluded": True,
        "per_attempt_timeout_seconds": 300,
        "maximum_attempts_per_request": 3,
        "request_count": 24,
        "artifact_root": _SAFE_ROOT,
        "network_attempted": False,
    }


def _publish_complete(
    *,
    run_root: Path,
    bundles: Sequence[DemoSourceBundle],
    members: Sequence[Mapping[str, object]],
    diagnostics_file: str,
) -> dict[str, object]:
    authority = _authority_payload(
        bundles,
        members,
        collection_run_id=run_root.name,
        diagnostics_file=diagnostics_file,
    )
    payloads = {
        ARTIFACT_ROOT / "source-bundles.json": canonical_json_bytes(
            [bundle.model_dump(mode="json") for bundle in bundles]
        ),
        ARTIFACT_ROOT / "source-authority-members.json": canonical_json_bytes(list(members)),
        ARTIFACT_ROOT / "source-authority.json": canonical_json_bytes(authority),
    }
    for path, payload in payloads.items():
        if path.exists():
            if _read_regular(path, maximum=64 * 1024 * 1024) != payload:
                raise Phase5DemoSourceCollectionError("SOURCE_PUBLICATION_NO_REPLACE_CONFLICT")
        else:
            _write_private(path, payload)
    verified = verify_source_collection()
    receipt_fields: dict[str, object] = {
        "schema_version": _RECEIPT_SCHEMA,
        "status": "COMPLETE_AUTHORIZED_DEV_24",
        "member_count": len(verified),
        "authority_sha256": authority["authority_sha256"],
        "source_inventory_sha256": canonical_sha256(
            [bundle.source_bundle_sha256 for bundle in verified]
        ),
        "collection_run_id": run_root.name,
        "network_attempted": True,
    }
    receipt_fields["receipt_sha256"] = canonical_sha256(receipt_fields)
    _write_private(
        run_root / "source-collection-receipt.json",
        canonical_json_bytes(receipt_fields),
    )
    return receipt_fields


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("preflight")
    commands.add_parser("verify")
    commands.add_parser("live")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            print(canonical_json_bytes(_safe_preflight()).decode("utf-8"))
            return 0
        if args.command == "verify":
            bundles = verify_source_collection()
            print(
                canonical_json_bytes(
                    {
                        "status": "COMPLETE_AUTHORIZED_DEV_24",
                        "member_count": len(bundles),
                        "source_inventory_sha256": canonical_sha256(
                            [bundle.source_bundle_sha256 for bundle in bundles]
                        ),
                        "network_attempted": False,
                    }
                ).decode("utf-8")
            )
            return 0
        if (
            os.environ.get("ITDA_OFFLINE") == "1"
            or os.environ.get("CI")
            or os.environ.get("ITDA_PROVIDER_NETWORK") != "1"
        ):
            raise Phase5DemoSourceCollectionError("LIVE_NETWORK_CAPABILITY_REQUIRED")
        rows = _fixed_dev_rows()
        credential = _read_secret()
        ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        ARTIFACT_ROOT.chmod(0o700)
        runs = ARTIFACT_ROOT / "source-collection"
        runs.mkdir(parents=True, exist_ok=True, mode=0o700)
        runs.chmod(0o700)
        run_root = Path(tempfile.mkdtemp(prefix="run-", dir=runs))
        run_root.chmod(0o700)
        diagnostics_dir = run_root / "diagnostics"
        diagnostics = ProviderDiagnostics.create(diagnostics_dir)
        diagnostics.bind_credentials(credential)
        try:
            client = KorService2Client(
                service_key=credential,
                policy=RequestPolicy(
                    timeout_seconds=300,
                    max_attempts=3,
                    initial_backoff_seconds=0.25,
                    max_backoff_seconds=300,
                ),
            )
            try:
                bundles, members = collect_authorized_dev_sources(
                    rows=rows,
                    client=client,
                    run_root=run_root,
                    diagnostics=diagnostics,
                )
            finally:
                client.close()
            receipt = _publish_complete(
                run_root=run_root,
                bundles=bundles,
                members=members,
                diagnostics_file=diagnostics.file_name,
            )
        except (CollectionError, Phase5DemoSourceCollectionError) as error:
            diagnostics.terminal_failure(
                outcome="collection_failed",
                category="collection",
                http_status=(error.http_status if isinstance(error, CollectionError) else None),
                exception_class=type(error).__name__,
            )
            failure = {
                "schema_version": "itda.phase5-demo-source-collection-failure.v1",
                "status": "BLOCKED_PARTIAL_SOURCE_COLLECTION",
                "completed_count": sum(1 for _ in (run_root / "snapshots").glob("*.json")),
                "failed_count": 24 - sum(1 for _ in (run_root / "snapshots").glob("*.json")),
                "reason": (
                    error.normalized_failure_reason
                    if isinstance(error, CollectionError)
                    else str(error)
                ),
                "http_status": error.http_status if isinstance(error, CollectionError) else None,
                "provider_result_code": (
                    error.provider_result_code if isinstance(error, CollectionError) else None
                ),
                "provider_result_value": (
                    error.provider_result_value if isinstance(error, CollectionError) else None
                ),
                "retry_disposition": (
                    error.retry_disposition
                    if isinstance(error, CollectionError)
                    else "DO_NOT_RETRY"
                ),
                "diagnostics_file": diagnostics.file_name,
                "network_attempted": True,
            }
            _write_private(run_root / "failure-report.json", canonical_json_bytes(failure))
            print(canonical_json_bytes(failure).decode("utf-8"))
            return 2
        finally:
            diagnostics.close()
        print(canonical_json_bytes(receipt).decode("utf-8"))
        return 0
    except (
        FileExistsError,
        OSError,
        Phase5DemoSourceCollectionError,
        ProviderDiagnosticsError,
        ValidationError,
        ValueError,
    ):
        print("PHASE5_DEMO_SOURCE_COLLECTION_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AuthorizedDevRow",
    "Phase5DemoSourceCollectionError",
    "collect_authorized_dev_sources",
    "main",
    "verify_source_collection",
]
