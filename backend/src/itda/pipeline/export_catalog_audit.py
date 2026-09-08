"""Deterministic machine and human projections for the canonical catalog audit."""

from __future__ import annotations

import base64
import csv
import hashlib
import html
import io
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.parquet as pq  # type: ignore[import-untyped]

from itda.contracts.catalog_audit import (
    CandidateAuditRow,
    CatalogAsset,
    CatalogAudit,
    CompletenessStatus,
    DatasetGrantEvidence,
    MissingReason,
    ProjectionManifest,
    SeedAuditRow,
    decide_asset_rights,
)
from itda.contracts.catalog_collection import (
    CollectionReport,
    LiveReportValidation,
    NormalizedCandidate,
    PermissionPageSnapshot,
)
from itda.contracts.crosswalk import (
    CrosswalkProposal,
    CrosswalkReviewArtifact,
    RelationshipProposal,
    RelationshipReviewArtifact,
)
from itda.contracts.provenance import parse_provider_json_bytes
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

EXPECTED_COLUMNS: Final = (
    "candidate_id",
    "name_ko",
    "latitude",
    "longitude",
    "description_status",
    "description_missing_reason",
    "photo_status",
    "photo_missing_reason",
    "operational_status",
    "operational_missing_reason",
    "odii_status",
    "odii_missing_reason",
    "projection_sha256",
)
_FORMULA_PREFIXES: Final = ("=", "+", "-", "@")
_CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_OUTPUT_NAMES: Final = (
    "catalog-audit.json",
    "catalog-audit.parquet",
    "catalog-audit.csv",
    "catalog-audit.md",
)
_PHASE1_RIGHTS_HASHES: Final = {
    "fixtures/preview/v1/review/candidate-review.json": (
        "12875e60d591e8824b32642df204ea2ce626bada22000e75ca1dd16e37a6d89d"
    ),
    "fixtures/preview/v1/review/candidate-review.md": (
        "1308a2544fdff7eb2c662644a4e3b0b473be62e479f51e0a03529243004fa39c"
    ),
    "fixtures/preview/v1/review/raw-provider-bundle.redacted.json": (
        "f0fc68aa465015611219e6a233f91f8f133d9cee323eb84a3b7d288a5689114f"
    ),
    "fixtures/preview/v1/review/review-manifest.json": (
        "172ef4a7ce940c052384861aef907f917971d2e762311d303361af2112260bb6"
    ),
    "fixtures/preview/v1/review/APPROVAL.md": (
        "8ea915e8a2f975d4612e81bd139d142b48a9159cfcc768cd02ab847b6af2b6d2"
    ),
    "fixtures/preview/source-locks/preview-v1-source-lock.json": (
        "5e4f29f9495a7d4561d0c334a36ed06f155789520af8760961989314cfbb2d6b"
    ),
}


@dataclass(frozen=True)
class ExportedCatalogAudit:
    canonical_json_bytes: bytes
    parquet_bytes: bytes
    csv_bytes: bytes
    markdown_bytes: bytes
    projection_manifest_bytes: bytes
    projection_manifest: ProjectionManifest
    column_order: tuple[str, ...] = EXPECTED_COLUMNS


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required audit input must be a regular non-symlink file: {path}")
    return path.read_bytes()


def _read_json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(_read_regular_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"audit input must be valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"audit input JSON root must be an object: {path}")
    return payload


def _walk_objects(value: object) -> list[Mapping[str, object]]:
    found: list[Mapping[str, object]] = []
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            found.append(current)
            stack.extend(reversed(tuple(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))
    return found


def _provider_item(
    payload: object,
    *,
    provider: str,
    content_id: str,
) -> Mapping[str, object] | None:
    keys = {
        "TOUR_API": ("contentid", "contentId"),
        "ODII": ("tid", "tlid", "stid", "stlid"),
        "TOURISM_PHOTO": ("galContentId",),
    }[provider]
    for item in _walk_objects(payload):
        if any(str(item.get(key, "")) == content_id for key in keys):
            return item
    return None


def _optional_text(item: Mapping[str, object], *keys: str) -> str | None:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            rendered = str(value).strip()
            if rendered:
                return rendered
    return None


def _optional_float(item: Mapping[str, object], *keys: str) -> float | None:
    rendered = _optional_text(item, *keys)
    if rendered is None:
        return None
    try:
        return float(rendered)
    except ValueError:
        return None


def _snapshot_index(snapshot_root: Path) -> dict[tuple[str, str], dict[str, object]]:
    indexed: dict[tuple[str, str], dict[str, object]] = {}
    for path in sorted(snapshot_root.glob("*.json")):
        snapshot = _read_json_object(path)
        provider = snapshot.get("provider")
        raw_sha256 = snapshot.get("raw_response_sha256")
        raw_base64 = snapshot.get("raw_body_base64")
        if not all(isinstance(value, str) for value in (provider, raw_sha256, raw_base64)):
            raise ValueError(f"provider snapshot lacks exact identity fields: {path.name}")
        assert isinstance(provider, str)
        assert isinstance(raw_sha256, str)
        assert isinstance(raw_base64, str)
        try:
            raw_bytes = base64.b64decode(raw_base64, validate=True)
        except ValueError as exc:
            raise ValueError(
                f"provider snapshot raw body is not valid base64: {path.name}"
            ) from exc
        if _sha256(raw_bytes) != raw_sha256:
            raise ValueError(f"provider snapshot raw response hash mismatch: {path.name}")
        parsed = parse_provider_json_bytes(raw_bytes)
        if parsed != snapshot.get("payload"):
            raise ValueError(f"provider snapshot payload is not exact raw-body JSON: {path.name}")
        key = (provider, raw_sha256)
        previous = indexed.get(key)
        if previous is not None and previous != snapshot:
            raise ValueError("duplicate provider response hash has conflicting snapshot metadata")
        indexed[key] = snapshot
    return indexed


def _dataset_grants(
    report: CollectionReport,
    permission_root: Path,
) -> tuple[DatasetGrantEvidence, ...]:
    paths = sorted(permission_root.glob("*.json"))
    if tuple(path.name for path in paths) != (
        "15101578.json",
        "15101914.json",
        "15101971.json",
    ):
        raise ValueError("permission directory must contain exactly the three dataset snapshots")
    parsed = {
        path.stem: PermissionPageSnapshot.model_validate(_read_json_object(path))
        for path in paths
    }
    report_snapshots = {
        snapshot.official_dataset_id: snapshot for snapshot in report.permission_evidence.snapshots
    }
    if parsed != report_snapshots:
        raise ValueError("permission files do not match collection report evidence bytes")
    grants: list[DatasetGrantEvidence] = []
    for dataset_id in ("15101578", "15101971", "15101914"):
        snapshot = parsed[dataset_id]
        terms = snapshot.terms_projection
        license_type = {
            "15101578": "PUBLIC_DATA_GRANT_METADATA_ONLY",
            "15101971": "PUBLIC_DATA_GRANT",
            "15101914": "KOGL_TYPE_1_ATTRIBUTION",
        }[dataset_id]
        attribution = "한국관광공사 포토코리아" if dataset_id == "15101914" else None
        grant_hash = canonical_sha256(
            {
                "official_dataset_id": dataset_id,
                "snapshot_sha256": snapshot.snapshot_sha256,
                "terms_projection": terms.model_dump(mode="json"),
            }
        )
        grants.append(
            DatasetGrantEvidence(
                official_dataset_id=dataset_id,
                official_page_url=snapshot.official_url,
                retrieved_at=snapshot.retrieved_at.isoformat().replace("+00:00", "Z"),
                response_sha256=snapshot.page_response_sha256,
                page_sha256=snapshot.snapshot_sha256,
                dataset_grant_sha256=grant_hash,
                evidence_state="COMPLETE",
                license_type=license_type,
                attribution_text=attribution,
                commercial_use_allowed=terms.commercial_use,
                transform_allowed=terms.derivative_use,
                display_allowed=terms.commercial_use,
                model_input_allowed=terms.derivative_use,
                explicit_restrictions=terms.explicit_restrictions,
            )
        )
    return tuple(grants)


def _candidate_asset(
    candidate: NormalizedCandidate,
    snapshot: Mapping[str, object],
    item: Mapping[str, object],
) -> CatalogAsset:
    provider = candidate.provider
    dataset_id = candidate.official_dataset_id
    content_id = candidate.provider_content_id
    request_identity = candidate.request_identity
    raw_response_sha256 = candidate.raw_response_sha256
    endpoint = str(snapshot.get("endpoint", ""))
    if provider == "TOURISM_PHOTO":
        creator = _optional_text(item, "galPhotographer")
        original_url = _optional_text(
            item,
            "galWebImageUrl",
            "galWebImageUrl2",
            "galOriginalImageUrl",
        )
        restriction = None
        explicit_rights = _optional_text(
            item,
            "cpyrhtDivCd",
            "copyrightCode",
            "licenseCode",
        )
        if explicit_rights not in (None, "Type1", "1", "KOGL_TYPE_1_ATTRIBUTION"):
            restriction = "ASSET_LEVEL_RIGHTS_NOT_TYPE1"
        elif creator is not None and not creator.startswith("한국관광공사"):
            restriction = "THIRD_PARTY_CREATOR_RIGHTS_UNCONFIRMED"
        return CatalogAsset(
            official_dataset_id=dataset_id,
            source_asset_id=content_id,
            source_request_sha256=request_identity,
            source_response_sha256=raw_response_sha256,
            original_url=original_url,
            creator_or_photographer=creator,
            license_type="KOGL_TYPE_1_ATTRIBUTION",
            attribution_text=f"한국관광공사 포토코리아-{creator}" if creator else None,
            content_kind="TOURISM_PHOTO_ASSET",
            explicit_asset_restriction=restriction,
        )
    if provider == "ODII":
        original_url = (
            f"https://apis.data.go.kr/B551011/Odii/{endpoint.rsplit('/', maxsplit=1)[-1]}"
            if endpoint
            else None
        )
        return CatalogAsset(
            official_dataset_id=dataset_id,
            source_asset_id=content_id,
            source_request_sha256=request_identity,
            source_response_sha256=raw_response_sha256,
            original_url=original_url,
            license_type="PUBLIC_DATA_GRANT",
            content_kind="ODII_SCRIPT_AUDIO_TEXT",
        )
    overview = _optional_text(item, "overview", "description")
    original_url = None
    if overview and endpoint:
        operation = endpoint.rsplit("/", maxsplit=1)[-1]
        original_url = (
            f"https://apis.data.go.kr/B551011/KorService2/{operation}"
            f"?contentId={content_id}"
        )
    return CatalogAsset(
        official_dataset_id=dataset_id,
        source_asset_id=content_id,
        source_request_sha256=request_identity,
        source_response_sha256=raw_response_sha256,
        original_url=original_url,
        license_type="PUBLIC_DATA_GRANT_METADATA_ONLY",
        content_kind="TOURAPI_DESCRIPTION",
        explicit_asset_restriction=(
            None if overview else "TOURAPI_DESCRIPTION_BODY_NOT_COLLECTED"
        ),
    )


def build_catalog_audit_from_review_artifacts(repository_root: Path) -> CatalogAudit:
    """Build the audit from the actual immutable Plan 02-05/06 restricted inputs."""

    restricted = repository_root / "artifacts/restricted/catalog/v1"
    collection_path = restricted / "collection/collection-report.json"
    validation_path = restricted / "collection/live-report-validation.json"
    crosswalk_path = restricted / "review/crosswalk-review.json"
    relationship_path = restricted / "review/relationship-review.json"
    collection_bytes = _read_regular_bytes(collection_path)
    validation_bytes = _read_regular_bytes(validation_path)
    crosswalk_bytes = _read_regular_bytes(crosswalk_path)
    relationship_bytes = _read_regular_bytes(relationship_path)
    report = CollectionReport.model_validate_json(collection_bytes)
    validation = LiveReportValidation.model_validate_json(validation_bytes)
    crosswalk = CrosswalkReviewArtifact.model_validate_json(crosswalk_bytes)
    relationships = RelationshipReviewArtifact.model_validate_json(relationship_bytes)
    collection_file_sha256 = _sha256(collection_bytes)
    crosswalk_file_sha256 = _sha256(crosswalk_bytes)
    relationship_file_sha256 = _sha256(relationship_bytes)
    if (
        not validation.valid
        or validation.report_sha256 != report.report_sha256
        or validation.collection_plan_sha256 != report.collection_plan_sha256
    ):
        raise ValueError("live report validation does not authorize this collection report")
    if (
        crosswalk.source_lineage.collection_report_file_sha256
        != collection_file_sha256
        or crosswalk.source_lineage.collection_report_sha256 != report.report_sha256
        or relationships.source_lineage != crosswalk.source_lineage
        or relationships.source_crosswalk_artifact_sha256 != crosswalk.artifact_sha256
    ):
        raise ValueError("crosswalk or relationship review lineage is not exact")
    grants = _dataset_grants(report, restricted / "collection/permission-pages")
    grant_by_dataset = {grant.official_dataset_id: grant for grant in grants}
    snapshots = _snapshot_index(restricted / "collection/snapshots")
    requests = {request.request_identity: request for request in report.request_identities}
    latest_attempts = {
        attempt.request_identity: attempt
        for attempt in report.attempts
    }
    seed_ids_by_candidate: dict[str, list[str]] = {}
    seed_rows: list[SeedAuditRow] = []
    for disposition in report.seed_dispositions:
        seed_rows.append(SeedAuditRow.model_validate(disposition.model_dump(mode="json")))
        if disposition.candidate_id is not None:
            seed_ids_by_candidate.setdefault(disposition.candidate_id, []).append(
                disposition.seed_id
            )
    crosswalk_by_candidate: dict[str, CrosswalkProposal] = {}
    for proposal_entry in crosswalk.proposals:
        for evidence in proposal_entry.evidence:
            if evidence.candidate_id is None:
                raise ValueError("crosswalk evidence is missing collected candidate identity")
            crosswalk_by_candidate[evidence.candidate_id] = proposal_entry
    relationship_by_candidate: dict[str, list[RelationshipProposal]] = {}
    for relationship_proposal in relationships.proposals:
        relationship_by_candidate.setdefault(
            relationship_proposal.left_subject_ref, []
        ).append(relationship_proposal)
        relationship_by_candidate.setdefault(
            relationship_proposal.right_subject_ref, []
        ).append(relationship_proposal)
    rows: list[CandidateAuditRow] = []
    for candidate in sorted(report.candidates, key=lambda item: item.candidate_id):
        request = requests.get(candidate.request_identity)
        attempt = latest_attempts.get(candidate.request_identity)
        if (
            request is None
            or request.provider != candidate.provider
            or request.official_dataset_id != candidate.official_dataset_id
            or attempt is None
            or attempt.terminal_state != "SUCCESS"
            or attempt.raw_body_sha256 != candidate.raw_response_sha256
        ):
            raise ValueError(
                f"candidate provenance is not response-bound: {candidate.candidate_id}"
            )
        snapshot = snapshots.get((candidate.provider, candidate.raw_response_sha256))
        if snapshot is None:
            raise ValueError(f"candidate response snapshot is missing: {candidate.candidate_id}")
        if (
            snapshot.get("official_dataset_id") != candidate.official_dataset_id
            or candidate.permission_snapshot_sha256
            != grant_by_dataset[candidate.official_dataset_id].page_sha256
        ):
            raise ValueError(
                f"candidate dataset permission binding failed: {candidate.candidate_id}"
            )
        item = _provider_item(
            snapshot.get("payload"),
            provider=candidate.provider,
            content_id=candidate.provider_content_id,
        )
        if item is None:
            raise ValueError(
                f"candidate content ID is absent from response: {candidate.candidate_id}"
            )
        asset = _candidate_asset(candidate, snapshot, item)
        rights = decide_asset_rights(asset, grant_by_dataset[candidate.official_dataset_id])
        latitude = _optional_float(item, "mapy", "latitude", "lat")
        longitude = _optional_float(item, "mapx", "longitude", "lng", "lon")
        if (latitude is None) != (longitude is None):
            latitude = None
            longitude = None
        overview = _optional_text(item, "overview", "description")
        photo_url = _optional_text(
            item,
            "galWebImageUrl",
            "firstimage",
            "firstImage",
        )
        description_status: CompletenessStatus
        description_reason: str | None
        photo_status: CompletenessStatus
        photo_reason: str | None
        if candidate.provider == "TOUR_API":
            description_status = "PRESENT" if overview else "MISSING"
            description_reason = None if overview else MissingReason.DESCRIPTION_NOT_COLLECTED.value
            photo_status = "UNKNOWN"
            photo_reason = "TOURAPI_IMAGE_ASSET_RIGHTS_NOT_AUDITED"
        elif candidate.provider == "TOURISM_PHOTO":
            description_status = "NOT_APPLICABLE"
            description_reason = MissingReason.DESCRIPTION_NOT_APPLICABLE.value
            photo_status = "PRESENT" if photo_url else "MISSING"
            photo_reason = None if photo_url else MissingReason.PHOTO_NOT_COLLECTED.value
        else:
            description_status = "NOT_APPLICABLE"
            description_reason = MissingReason.DESCRIPTION_NOT_APPLICABLE.value
            photo_status = "NOT_APPLICABLE"
            photo_reason = MissingReason.PHOTO_NOT_APPLICABLE.value
        candidate_crosswalk = crosswalk_by_candidate.get(candidate.candidate_id)
        if candidate_crosswalk is None:
            raise ValueError(f"candidate is absent from crosswalk review: {candidate.candidate_id}")
        crosswalk_status = candidate_crosswalk.status
        crosswalk_reasons = candidate_crosswalk.review_reasons
        relationship_proposals = relationship_by_candidate.get(candidate.candidate_id, [])
        relationship_status = (
            "PENDING_REVIEW" if relationship_proposals else "NO_RELATIONSHIP_PROPOSAL"
        )
        relationship_reasons = tuple(
            sorted(
                {
                    proposal.evidence_reason
                    for proposal in relationship_proposals
                }
            )
        )
        eligibility_reasons = [
            MissingReason.CANONICAL_SELECTION_NOT_ADJUDICATED.value,
            *crosswalk_reasons,
            description_reason,
            photo_reason,
            MissingReason.OPERATIONAL_DETAIL_NOT_COLLECTED.value,
            MissingReason.ODII_NORMALIZED_CANDIDATE_ABSENT.value,
        ]
        if latitude is None:
            eligibility_reasons.append(MissingReason.COORDINATES_NOT_EXPOSED.value)
        if rights.rights_state != "ALLOWED":
            eligibility_reasons.extend(rights.reason_codes)
        rows.append(
            CandidateAuditRow(
                candidate_id=candidate.candidate_id,
                name_ko=candidate.name_ko,
                latitude=latitude,
                longitude=longitude,
                description_status=description_status,
                description_missing_reason=description_reason,
                photo_status=photo_status,
                photo_missing_reason=photo_reason,
                operational_status="UNKNOWN",
                operational_missing_reason=(
                    MissingReason.OPERATIONAL_DETAIL_NOT_COLLECTED.value
                ),
                odii_status="MISSING",
                odii_missing_reason=MissingReason.ODII_NORMALIZED_CANDIDATE_ABSENT.value,
                provider=candidate.provider,
                official_dataset_id=candidate.official_dataset_id,
                provider_content_id=candidate.provider_content_id,
                request_identity=candidate.request_identity,
                raw_response_sha256=candidate.raw_response_sha256,
                permission_snapshot_sha256=candidate.permission_snapshot_sha256,
                crosswalk_status=crosswalk_status,
                crosswalk_reason_codes=crosswalk_reasons,
                relationship_status=relationship_status,
                relationship_reason_codes=relationship_reasons,
                linked_seed_ids=tuple(
                    sorted(seed_ids_by_candidate.get(candidate.candidate_id, ()))
                ),
                asset=asset,
                rights_disposition=rights,
                canonical_selection_eligible=False,
                eligibility_reason_codes=tuple(
                    dict.fromkeys(
                        str(reason) for reason in eligibility_reasons if reason is not None
                    )
                ),
            )
        )
    phase1_hashes: dict[str, str] = {}
    for relative_path, expected_sha256 in _PHASE1_RIGHTS_HASHES.items():
        actual = _sha256(_read_regular_bytes(repository_root / relative_path))
        if actual != expected_sha256:
            raise ValueError(f"Phase 1 rights history changed: {relative_path}")
        phase1_hashes[relative_path] = actual
    source_hashes = {
        "collection_report_file": collection_file_sha256,
        "collection_report_canonical": report.report_sha256,
        "live_validation_file": _sha256(validation_bytes),
        "crosswalk_review_file": crosswalk_file_sha256,
        "crosswalk_review_canonical": crosswalk.artifact_sha256,
        "relationship_review_file": relationship_file_sha256,
        "relationship_review_canonical": relationships.artifact_sha256,
        "permission_evidence_set": report.permission_evidence.permission_evidence_sha256,
    }
    return CatalogAudit(
        schema_version="catalog-audit-v1",
        data_version="catalog-audit-data-v1",
        source_version="catalog-collection-v1",
        grants=grants,
        seed_rows=tuple(seed_rows),
        rows=tuple(rows),
        source_hashes=source_hashes,
        phase1_historical_hashes=phase1_hashes,
    )


def validate_catalog_audit(payload: object) -> CatalogAudit:
    """Validate a Python payload as canonical JSON truth, never as a projection."""

    if isinstance(payload, CatalogAudit):
        return payload
    return CatalogAudit.model_validate(payload)


def load_catalog_audit(path: Path) -> CatalogAudit:
    """Load only canonical audit JSON; Parquet/CSV/Markdown are never truth inputs."""

    if path.name != "catalog-audit.json" or path.suffix.casefold() != ".json":
        raise ValueError("input must be canonical audit JSON named catalog-audit.json")
    if path.is_symlink() or not path.is_file():
        raise ValueError("canonical audit JSON must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("canonical audit JSON is malformed") from exc
    return validate_catalog_audit(payload)


def _projection_rows(audit: CatalogAudit) -> list[dict[str, object]]:
    return [
        {
            "candidate_id": row.candidate_id,
            "name_ko": row.name_ko,
            "latitude": row.latitude,
            "longitude": row.longitude,
            "description_status": row.description_status,
            "description_missing_reason": row.description_missing_reason,
            "photo_status": row.photo_status,
            "photo_missing_reason": row.photo_missing_reason,
            "operational_status": row.operational_status,
            "operational_missing_reason": row.operational_missing_reason,
            "odii_status": row.odii_status,
            "odii_missing_reason": row.odii_missing_reason,
            "projection_sha256": row.projection_sha256,
        }
        for row in audit.rows
    ]


def _parquet_schema(audit: CatalogAudit) -> pa.Schema:
    metadata = {
        b"audit_schema_version": audit.schema_version.encode("utf-8"),
        b"data_version": audit.data_version.encode("utf-8"),
        b"pyarrow_version": pa.__version__.encode("ascii"),
        b"source_version": audit.source_version.encode("utf-8"),
        b"writer_contract": b"itda-catalog-audit-parquet-v1",
    }
    return pa.schema(
        [
            pa.field("candidate_id", pa.string(), nullable=False),
            pa.field("name_ko", pa.string(), nullable=False),
            pa.field("latitude", pa.float64(), nullable=True),
            pa.field("longitude", pa.float64(), nullable=True),
            pa.field("description_status", pa.string(), nullable=False),
            pa.field("description_missing_reason", pa.string(), nullable=True),
            pa.field("photo_status", pa.string(), nullable=False),
            pa.field("photo_missing_reason", pa.string(), nullable=True),
            pa.field("operational_status", pa.string(), nullable=False),
            pa.field("operational_missing_reason", pa.string(), nullable=True),
            pa.field("odii_status", pa.string(), nullable=False),
            pa.field("odii_missing_reason", pa.string(), nullable=True),
            pa.field("projection_sha256", pa.string(), nullable=False),
        ],
        metadata=metadata,
    )


def _render_parquet(audit: CatalogAudit) -> bytes:
    rows = _projection_rows(audit)
    table = pa.Table.from_pylist(rows, schema=_parquet_schema(audit))
    sink = pa.BufferOutputStream()
    pq.write_table(
        table,
        sink,
        version="2.6",
        compression="NONE",
        use_dictionary=False,
        write_statistics=False,
        data_page_version="1.0",
        row_group_size=max(1, len(rows)),
        use_compliant_nested_type=True,
        write_page_index=False,
        store_schema=True,
    )
    return bytes(sink.getvalue())


def _escape_controls(value: str) -> str:
    return _CONTROL_RE.sub(lambda match: f"\\u{ord(match.group()):04x}", value)


def _csv_safe(value: object, *, missing: str) -> str:
    if value is None:
        return missing
    rendered = _escape_controls(str(value))
    stripped = rendered.lstrip()
    if stripped.startswith(_FORMULA_PREFIXES):
        rendered = "'" + rendered
    return rendered


def _csv_value(column: str, value: object) -> str:
    if column in {"latitude", "longitude"} and isinstance(value, float):
        return format(value, ".6f")
    missing = {
        "latitude": "COORDINATES_NOT_AVAILABLE",
        "longitude": "COORDINATES_NOT_AVAILABLE",
        "description_missing_reason": "DESCRIPTION_NOT_MISSING",
        "photo_missing_reason": "PHOTO_NOT_MISSING",
        "operational_missing_reason": "OPERATIONAL_NOT_MISSING",
        "odii_missing_reason": "ODII_NOT_MISSING",
    }.get(column, "VALUE_NOT_AVAILABLE")
    return _csv_safe(value, missing=missing)


def _render_csv(audit: CatalogAudit) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(
        stream,
        delimiter=",",
        quotechar='"',
        quoting=csv.QUOTE_ALL,
        lineterminator="\n",
        doublequote=True,
    )
    writer.writerow(EXPECTED_COLUMNS)
    for row in _projection_rows(audit):
        writer.writerow([_csv_value(column, row[column]) for column in EXPECTED_COLUMNS])
    return stream.getvalue().encode("utf-8")


def _markdown_safe(value: object, *, missing: str = "해당 없음") -> str:
    if value is None:
        return missing
    rendered = _escape_controls(str(value))
    rendered = html.escape(rendered, quote=True)
    return (
        rendered.replace("\\", "&#92;")
        .replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("*", "&#42;")
        .replace("_", "&#95;")
    )


def _status_counts(audit: CatalogAudit, field: str) -> str:
    counts: dict[str, int] = {}
    for row in audit.rows:
        value = str(getattr(row, field))
        counts[value] = counts.get(value, 0) + 1
    return ", ".join(f"{key} {counts[key]}" for key in sorted(counts))


def _render_markdown(
    audit: CatalogAudit,
    *,
    canonical_json_sha256: str,
    parquet_sha256: str,
    csv_sha256: str,
) -> bytes:
    lines = [
        "# IT-DA Catalog Audit",
        "",
        "## Artifact identity",
        "",
        f"- Schema version: `{_markdown_safe(audit.schema_version)}`",
        f"- Data version: `{_markdown_safe(audit.data_version)}`",
        f"- Source version: `{_markdown_safe(audit.source_version)}`",
        f"- Canonical JSON SHA-256: `{canonical_json_sha256}`",
        f"- Parquet SHA-256: `{parquet_sha256}`",
        f"- CSV SHA-256: `{csv_sha256}`",
        "- Markdown SHA-256: `projection-manifest.json에서 검증`",
        "",
        "## Collection status",
        "",
        f"- 후보 수: {len(audit.rows)}",
        f"- Seed coverage 수: {len(audit.seed_rows)}",
        f"- Dataset grant 수: {len(audit.grants)}",
    ]
    for name in sorted(audit.source_hashes):
        lines.append(f"- {_markdown_safe(name)}: `{audit.source_hashes[name]}`")
    lines.extend(
        [
            "",
            "## Candidate coverage",
            "",
            f"- Description: {_status_counts(audit, 'description_status')}",
            f"- Photo: {_status_counts(audit, 'photo_status')}",
            f"- Operational: {_status_counts(audit, 'operational_status')}",
            f"- Odii: {_status_counts(audit, 'odii_status')}",
            "",
            "| Candidate ID | 이름 | 설명 | 사진 | 운영 | Odii | 누락 및 차단 사유 |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for row in audit.rows:
        reasons = tuple(
            reason
            for reason in (
                row.description_missing_reason,
                row.photo_missing_reason,
                row.operational_missing_reason,
                row.odii_missing_reason,
                *row.eligibility_reason_codes,
            )
            if reason is not None
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown_safe(row.candidate_id),
                    _markdown_safe(row.name_ko),
                    _markdown_safe(row.description_status),
                    _markdown_safe(row.photo_status),
                    _markdown_safe(row.operational_status),
                    _markdown_safe(row.odii_status),
                    _markdown_safe(", ".join(dict.fromkeys(reasons))),
                )
            )
            + " |"
        )
    blocked = sum(
        row.rights_disposition is not None
        and row.rights_disposition.rights_state != "ALLOWED"
        for row in audit.rows
    )
    allowed = sum(
        row.rights_disposition is not None
        and row.rights_disposition.rights_state == "ALLOWED"
        for row in audit.rows
    )
    lines.extend(
        [
            "",
            "## Crosswalk review",
            "",
            "- 검토 상태는 canonical JSON의 각 candidate row에 보존됩니다.",
            "- 검토 전 제안은 canonical identity 승인으로 취급하지 않습니다.",
            "",
            "## Rights review",
            "",
            f"- 권리·출처 완전 asset: {allowed}",
            f"- 분석·UI·데모 사용 차단 asset: {blocked}",
            (
                "- Dataset grant와 asset provenance는 별도 증거이며 "
                "다른 dataset으로 이전되지 않습니다."
            ),
            "",
            "## Relationship review",
            "",
            "- 관계 제안은 별도 typed review 상태로 유지되며 identity merge를 의미하지 않습니다.",
            "",
            "## Canonical-36 gate",
            "",
            "- 상태: 승인 전",
            (
                "- 이 감사표는 718개 review-required group을 판정하거나 "
                "canonical 36을 승인하지 않습니다."
            ),
            "",
            "## Split gate",
            "",
            "- 상태: 실행 전",
            "- Canonical catalog 승인 전에는 DEV/BLIND membership을 생성하지 않습니다.",
            "",
            "## Approvals and seal",
            "",
            "- Catalog approval: 없음",
            "- Manifest approval: 없음",
            "- Seal record: 없음",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _writer_metadata() -> dict[str, str]:
    return {
        "canonical_json": "UTF-8; sorted keys; compact separators; no newline",
        "csv": "UTF-8; LF; fixed columns; QUOTE_ALL; formula/control neutralized",
        "markdown": "UTF-8; LF; HTML/Markdown escaped; fixed section order",
        "parquet": (
            f"pyarrow={pa.__version__}; parquet=2.6; compression=NONE; "
            "dictionary=false; statistics=false; data_page=1.0"
        ),
        "runtime": "python-3.13",
    }


def _write_verified(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"projection path must be a regular file: {path.name}")
        if path.read_bytes() != payload:
            raise ValueError(
                f"existing projection differs from canonical re-derivation: {path.name}"
            )
        return
    path.write_bytes(payload)


def export_catalog_audit(
    payload: object,
    output_root: Path,
) -> ExportedCatalogAudit:
    """Derive all projections from canonical audit values and verify immutable outputs."""

    audit = validate_catalog_audit(payload)
    canonical_bytes = canonical_json_bytes(audit.model_dump(mode="json"))
    parquet_bytes = _render_parquet(audit)
    csv_bytes = _render_csv(audit)
    canonical_hash = _sha256(canonical_bytes)
    parquet_hash = _sha256(parquet_bytes)
    csv_hash = _sha256(csv_bytes)
    markdown_bytes = _render_markdown(
        audit,
        canonical_json_sha256=canonical_hash,
        parquet_sha256=parquet_hash,
        csv_sha256=csv_hash,
    )
    manifest = ProjectionManifest.model_validate(
        {
            "schema_version": "catalog-audit-projection-manifest-v1",
            "audit_schema_version": audit.schema_version,
            "data_version": audit.data_version,
            "source_version": audit.source_version,
            "canonical_json_sha256": canonical_hash,
            "output_hashes": {
                "catalog-audit.json": canonical_hash,
                "catalog-audit.parquet": parquet_hash,
                "catalog-audit.csv": csv_hash,
                "catalog-audit.md": _sha256(markdown_bytes),
            },
            "writer_metadata": _writer_metadata(),
        }
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json"))
    output_root.mkdir(parents=True, exist_ok=True)
    for name, rendered in zip(
        _OUTPUT_NAMES,
        (canonical_bytes, parquet_bytes, csv_bytes, markdown_bytes),
        strict=True,
    ):
        _write_verified(output_root / name, rendered)
    _write_verified(output_root / "projection-manifest.json", manifest_bytes)
    return ExportedCatalogAudit(
        canonical_json_bytes=canonical_bytes,
        parquet_bytes=parquet_bytes,
        csv_bytes=csv_bytes,
        markdown_bytes=markdown_bytes,
        projection_manifest_bytes=manifest_bytes,
        projection_manifest=manifest,
    )


__all__ = [
    "EXPECTED_COLUMNS",
    "ExportedCatalogAudit",
    "build_catalog_audit_from_review_artifacts",
    "export_catalog_audit",
    "load_catalog_audit",
    "validate_catalog_audit",
]
