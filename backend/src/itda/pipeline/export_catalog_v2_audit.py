"""Deterministic, membership-free final audit projections for catalog v2.

This module deliberately has no database dependency.  Its only seal input is the
sanitized, self-hashed receipt produced by the protected SQLite sealing step.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

import pyarrow as pa  # type: ignore[import-untyped]
import pyarrow.parquet as pq  # type: ignore[import-untyped]

from itda.cli.freeze_preview import publish_immutable_directory
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_activation import CatalogActivationEventV2
from itda.contracts.catalog_release import CatalogApprovalV2, CatalogRevisionV2
from itda.contracts.sqlite_manifest_authority import SQLiteSealReceipt
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

OUTPUT_NAMES: Final = (
    "canonical-36.csv",
    "canonical-36.json",
    "canonical-36.md",
    "canonical-36.parquet",
    "projection-manifest.json",
)
_PROJECTION_NAMES: Final = OUTPUT_NAMES[:-1]
_DATA_VERSION: Final = "catalog-v2-final-audit-data-v1"
_ROW_SCHEMA_VERSION: Final = "itda.catalog-v2-final-audit-row.v1"
_DOCUMENT_SCHEMA_VERSION: Final = "itda.catalog-v2-final-audit.v1"
_MANIFEST_SCHEMA_VERSION: Final = "itda.catalog-v2-final-audit-manifest.v1"
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN: Final = (
    ".sqlite3",
    "database_path",
    "database_uri",
    "dev_members",
    "blind_members",
    "membership_sha256",
    "ordered_place_ids",
    "per_member",
    "complement",
    "-journal",
    "-wal",
    "-shm",
)


@dataclass(frozen=True)
class CatalogV2AuditResult:
    """Hashes of one verified five-file publication."""

    file_hashes: dict[str, str]
    manifest_sha256: str
    row_count: int


class SanitizedSQLiteSealParent(StrictContract):
    """Exact membership-free subset allowed to cross the SQLite boundary."""

    database_sha256: Sha256
    development_count: Literal[24]
    held_out_count: Literal[12]
    logical_seal_sha256: Sha256
    sqlite_seal_receipt_sha256: Sha256
    total_count: Literal[36]


@dataclass(frozen=True)
class _BuiltBundle:
    files: dict[str, bytes]
    manifest_sha256: str
    row_count: int


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_bounded(path: Path, *, max_bytes: int = 64_000_000) -> bytes:
    """Read a stable regular file without following a final symlink."""

    if path.is_symlink():
        raise ValueError("audit input cannot be a symlink")
    before = path.stat()
    if not path.is_file() or before.st_size > max_bytes:
        raise ValueError("audit input must be a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise ValueError("audit input identity changed before open")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) > max_bytes or (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size):
            raise ValueError("audit input changed during read")
        return payload
    finally:
        os.close(descriptor)


def _load_canonical_mapping(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _read_bounded(path)
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("audit input is not valid JSON") from exc
    if not isinstance(parsed, dict) or raw != canonical_json_bytes(parsed):
        raise ValueError("audit input is not canonical JSON")
    return raw, parsed


def _self_hash(payload: Mapping[str, Any], field: str) -> str:
    stored = payload.get(field)
    expected = canonical_sha256({key: value for key, value in payload.items() if key != field})
    if not isinstance(stored, str) or stored != expected:
        raise ValueError(f"audit source {field} is stale")
    return stored


def _as_hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} is not a sha256")
    return value


def _safe_relative(root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise ValueError("audit source path must be repository-relative")
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / relative).resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("audit source escaped repository root") from exc
    return resolved


def _sanitize_text(value: object) -> str:
    rendered = str(value)
    return "".join(character for character in rendered if character >= " " or character == "\t")


def human_csv_safe(value: object) -> str:
    """Neutralize spreadsheet formulas and control characters."""

    rendered = _sanitize_text(value)
    if rendered[:1] in ("=", "+", "-", "@"):
        rendered = "'" + rendered
    return rendered


def human_markdown_safe(value: object) -> str:
    """Render untrusted text as inert single-line Markdown content."""

    rendered = _sanitize_text(value)
    rendered = re.sub(r"<[^>]*>", "", rendered)
    for token in ("|", "`", "[", "]", "*", "_", "<", ">"):
        rendered = rendered.replace(token, "")
    return rendered.replace("\n", " ").replace("\r", " ")


def _load_sources(repository_root: Path, receipt_path: Path) -> dict[str, Any]:
    root = repository_root.resolve(strict=True)
    _, receipt_raw = _load_canonical_mapping(receipt_path)
    try:
        receipt = SQLiteSealReceipt.model_validate(receipt_raw)
    except ValueError as exc:
        raise ValueError("sanitized seal receipt is invalid") from exc
    if receipt.receipt_sha256 is None:
        raise ValueError("sanitized seal receipt is missing its self hash")

    source_paths = {
        "revision": root / "artifacts/restricted/catalog/v2/revisions/catalog-revision.json",
        "approval": root / "artifacts/restricted/catalog/v2/approval/catalog-approval.json",
        "activation": root
        / "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json",
        "entity": root / "artifacts/restricted/catalog/v2/projection/entity-projection.json",
        "policy": root / "artifacts/restricted/catalog/v2/projection/entity-policy-report.json",
        "rights": root / "artifacts/restricted/catalog/v2/rights/rights-projection.json",
        "evidence": root
        / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json",
    }
    loaded = {name: _load_canonical_mapping(path) for name, path in source_paths.items()}
    raw_bytes = {name: item[0] for name, item in loaded.items()}
    raw = {name: item[1] for name, item in loaded.items()}

    try:
        revision = CatalogRevisionV2.model_validate(raw["revision"])
        approval = CatalogApprovalV2.model_validate(raw["approval"])
        activation = CatalogActivationEventV2.model_validate(raw["activation"])
    except ValueError as exc:
        raise ValueError("catalog parent artifacts are invalid") from exc
    revision_hash = _as_hash(revision.catalog_revision_sha256, label="catalog revision")
    approval_hash = _as_hash(approval.catalog_approval_sha256, label="catalog approval")
    activation_hash = _as_hash(activation.event_sha256, label="activation event")
    if receipt.catalog_revision_sha256 != revision_hash:
        raise ValueError("sanitized seal receipt catalog parent differs from live revision")
    if receipt.catalog_activation_sha256 != activation_hash:
        raise ValueError("sanitized seal receipt activation parent differs from live event")
    if approval.catalog_revision_sha256 != revision_hash:
        raise ValueError("catalog approval parent differs from live revision")
    if (
        activation.catalog_revision_sha256 != revision_hash
        or activation.catalog_approval_sha256 != approval_hash
    ):
        raise ValueError("catalog activation parent chain is stale")
    if activation.action != "catalog-activate" or activation.to_revision_sha256 != revision_hash:
        raise ValueError("catalog activation is not the live approved revision")

    entity_hash = _self_hash(raw["entity"], "projection_sha256")
    policy_hash = _self_hash(raw["policy"], "report_sha256")
    rights_hash = _self_hash(raw["rights"], "projection_sha256")
    evidence_hash = _self_hash(raw["evidence"], "report_sha256")
    if raw["evidence"].get("rows_root") != canonical_sha256(raw["evidence"].get("rows")):
        raise ValueError("objective evidence row root is stale")
    if raw["evidence"].get("parents", {}).get("entity_projection_sha256") != entity_hash:
        raise ValueError("objective evidence entity parent is stale")
    if raw["evidence"].get("parents", {}).get("entity_policy_report_sha256") != policy_hash:
        raise ValueError("objective evidence policy parent is stale")
    if raw["evidence"].get("parents", {}).get("rights_projection_sha256") != rights_hash:
        raise ValueError("objective evidence rights parent is stale")

    relationship_path = (
        _safe_relative(root, str(revision.adjudication_bundle_path)).parent
        / "authoritative-relationship-leaves.json"
    )
    _, reviewed_relationships = _load_canonical_mapping(relationship_path)
    reviewed_hash = _self_hash(reviewed_relationships, "authoritative_relationship_leaves_sha256")
    reviewed_leaves = reviewed_relationships.get("relationship_leaves")
    if not isinstance(reviewed_leaves, list):
        raise ValueError("reviewed relationship leaves are invalid")
    if reviewed_relationships.get("relationship_leaves_sha256") != canonical_sha256(
        reviewed_leaves
    ):
        raise ValueError("reviewed relationship leaf root is stale")
    if reviewed_hash != revision.authoritative_relationship_leaves_sha256:
        raise ValueError("reviewed relationship parent differs from live revision")

    return {
        "receipt": receipt,
        "raw": raw,
        "raw_bytes": raw_bytes,
        "revision": revision,
        "approval": approval,
        "activation": activation,
        "revision_hash": revision_hash,
        "approval_hash": approval_hash,
        "activation_hash": activation_hash,
        "entity_hash": entity_hash,
        "policy_hash": policy_hash,
        "rights_hash": rights_hash,
        "evidence_hash": evidence_hash,
        "reviewed_relationships": reviewed_relationships,
        "reviewed_hash": reviewed_hash,
    }


def _leaf_root(rows: list[dict[str, Any]], *, predicate: Any) -> str:
    hashes = sorted(
        (_as_hash(row.get("leaf_sha256"), label="policy leaf") for row in rows if predicate(row)),
        key=lambda value: value.encode("utf-8"),
    )
    return canonical_sha256(hashes)


def _safe_seal_parent(receipt: SQLiteSealReceipt) -> dict[str, object]:
    assert receipt.receipt_sha256 is not None
    counts = receipt.counts
    if counts != {"dev": 24, "blind": 12, "total": 36}:
        raise ValueError("sanitized seal receipt aggregate counts are invalid")
    return SanitizedSQLiteSealParent(
        database_sha256=receipt.database_sha256,
        development_count=24,
        held_out_count=12,
        logical_seal_sha256=receipt.logical_seal_sha256,
        sqlite_seal_receipt_sha256=receipt.receipt_sha256,
        total_count=36,
    ).model_dump(mode="json")


def _assertions(policy: dict[str, Any], reviewed: dict[str, Any]) -> dict[str, int]:
    counts = policy.get("counts")
    if not isinstance(counts, dict):
        raise ValueError("entity policy counts are invalid")
    values = {
        "cross_provider_place_auto_link_count": counts.get("cross_provider_place_auto_link_count"),
        "crosswalk_automatic_count": counts.get("crosswalk_automatic"),
        "crosswalk_total_count": counts.get("crosswalk_total"),
        "crosswalk_unresolved_count": counts.get("crosswalk_unresolved"),
        "media_attachment_count": counts.get("media_attachment_count"),
        "relationship_automatic_count": counts.get("relationship_automatic"),
        "relationship_total_count": counts.get("relationship_total"),
        "relationship_unresolved_count": counts.get("relationship_unresolved"),
        "reviewed_relationship_leaf_count": reviewed.get("relationship_leaf_count"),
    }
    expected = {
        "cross_provider_place_auto_link_count": 0,
        "crosswalk_automatic_count": 715,
        "crosswalk_total_count": 718,
        "crosswalk_unresolved_count": 3,
        "media_attachment_count": 8,
        "relationship_automatic_count": 871,
        "relationship_total_count": 874,
        "relationship_unresolved_count": 3,
        "reviewed_relationship_leaf_count": 0,
    }
    if values != expected:
        raise ValueError("entity policy source assertions drifted")
    return expected


def _evidence_parents(sources: dict[str, Any]) -> dict[str, str]:
    raw = sources["raw"]
    policy = raw["policy"]
    rights = raw["rights"]
    evidence = raw["evidence"]
    receipt: SQLiteSealReceipt = sources["receipt"]
    crosswalk = policy.get("crosswalk_dispositions")
    relationships = policy.get("relationship_dispositions")
    media = policy.get("media_attachments")
    if not all(isinstance(value, list) for value in (crosswalk, relationships, media)):
        raise ValueError("policy leaves are invalid")
    evidence_source_parents = evidence.get("parents")
    rights_roots = rights.get("roots")
    if not isinstance(evidence_source_parents, dict) or not isinstance(rights_roots, dict):
        raise ValueError("evidence parent roots are invalid")
    assert receipt.receipt_sha256 is not None
    parents = {
        "activation_event_sha256": sources["activation_hash"],
        "asset_rights_root_sha256": rights_roots.get("asset_rights"),
        "catalog_approval_sha256": sources["approval_hash"],
        "catalog_revision_sha256": sources["revision_hash"],
        "crosswalk_automatic_leaves_root_sha256": _leaf_root(
            crosswalk, predicate=lambda row: str(row.get("result", "")).startswith("AUTOMATIC_")
        ),
        "crosswalk_unresolved_leaves_root_sha256": _leaf_root(
            crosswalk, predicate=lambda row: row.get("result") == "UNRESOLVED_HUMAN"
        ),
        "database_sha256": receipt.database_sha256,
        "formal_policy_sha256": evidence_source_parents.get("formal_policy_sha256"),
        "logical_seal_sha256": receipt.logical_seal_sha256,
        "media_attachment_leaves_root_sha256": _leaf_root(media, predicate=lambda _row: True),
        "objective_evidence_rows_root_sha256": evidence.get("rows_root"),
        "protected_catalog_v1_tree_sha256": evidence_source_parents.get("catalog_v1_tree_sha256"),
        "protected_inputs_root_sha256": evidence_source_parents.get("protected_inputs_sha256"),
        "relationship_automatic_leaves_root_sha256": _leaf_root(
            relationships, predicate=lambda row: str(row.get("result", "")).startswith("AUTOMATIC_")
        ),
        "relationship_unresolved_leaves_root_sha256": _leaf_root(
            relationships, predicate=lambda row: row.get("result") == "UNRESOLVED_HUMAN"
        ),
        "reviewed_relationship_leaves_root_sha256": sources["reviewed_relationships"].get(
            "relationship_leaves_sha256"
        ),
        "sqlite_seal_receipt_sha256": receipt.receipt_sha256,
    }
    return {key: _as_hash(value, label=key) for key, value in parents.items()}


def _build_rows(sources: dict[str, Any]) -> list[dict[str, Any]]:
    raw = sources["raw"]
    entity = raw["entity"]
    policy = raw["policy"]
    rights = raw["rights"]
    evidence = raw["evidence"]
    revision: CatalogRevisionV2 = sources["revision"]
    active_ids = set(revision.ordered_place_ids)

    places = {item["ref"]["entity_id"]: item for item in entity["place_entities"]}
    records = {item["ref"]["entity_id"]: item for item in entity["dataset_records"]}
    evidence_rows = {item["place_entity_id"]: item for item in evidence["rows"]}
    crosswalk = {item["source_row_id"]: item for item in policy["crosswalk_dispositions"]}
    asset_rights: dict[str, list[dict[str, Any]]] = {}
    for item in rights["asset_rights"]:
        asset_rights.setdefault(item["dataset_record_entity_id"], []).append(item)
    attachments: dict[str, list[dict[str, Any]]] = {}
    for item in rights["attachment_rights"]:
        attachments.setdefault(item["place_entity_id"], []).append(item)
    grants = sorted(
        rights["dataset_grants"], key=lambda item: item["official_dataset_id"].encode("utf-8")
    )

    rows: list[dict[str, Any]] = []
    for place_id in sorted(active_ids, key=lambda value: value.encode("utf-8")):
        place = places.get(place_id)
        objective = evidence_rows.get(place_id)
        if place is None or objective is None:
            raise ValueError("active catalog place lacks complete objective evidence")
        refs = place.get("member_refs")
        if not isinstance(refs, list):
            raise ValueError("entity provenance is invalid")
        selected_records = [
            records[ref["entity_id"]] for ref in refs if ref.get("kind") == "DATASET_RECORD"
        ]
        if not selected_records:
            raise ValueError("active catalog place lacks dataset provenance")
        selected_records.sort(
            key=lambda item: (
                item["audit_ordinal"],
                item["candidate_ordinal"],
                item["ref"]["entity_id"].encode("utf-8"),
            )
        )
        primary = selected_records[0]
        source_crosswalk = crosswalk.get(place["source_row_id"])
        if source_crosswalk is None:
            raise ValueError("active catalog place lacks identity policy provenance")
        selected_assets = [
            item
            for record in selected_records
            for item in asset_rights.get(record["ref"]["entity_id"], [])
        ]
        selected_assets.sort(key=lambda item: item["leaf_sha256"].encode("utf-8"))
        selected_attachments = sorted(
            attachments.get(place_id, []), key=lambda item: item["leaf_sha256"].encode("utf-8")
        )
        row: dict[str, Any] = {
            "schema_version": _ROW_SCHEMA_VERSION,
            "data_version": _DATA_VERSION,
            "catalog_revision_sha256": sources["revision_hash"],
            "canonical_place_id": place_id,
            "name_ko": primary["name_ko"],
            "latitude": primary["audit_latitude"],
            "longitude": primary["audit_longitude"],
            "evidence_states": {
                key: objective[key]["state"]
                for key in (
                    "coordinates",
                    "dataset_rights",
                    "description",
                    "direct_media",
                    "operating_info",
                )
            },
            "entity_provenance": {
                "entity_ref": place["ref"],
                "proposal_ordinal": place["proposal_ordinal"],
                "review_reasons": place["review_reasons"],
                "source_matching_rule": place["source_matching_rule"],
                "source_proposal_id": place["source_proposal_id"],
                "source_row_id": place["source_row_id"],
                "source_row_sha256": place["source_row_sha256"],
                "source_status": place["source_status"],
            },
            "dataset_provenance": selected_records,
            "objective_evidence": objective,
            "identity_policy_provenance": source_crosswalk,
            "rights_provenance": {
                "dataset_grants": grants,
                "assets": selected_assets,
                "attachments": selected_attachments,
            },
            "reviewed_relationship_provenance": sources["reviewed_relationships"][
                "relationship_leaves"
            ],
        }
        row["canonical_row_sha256"] = canonical_sha256(row)
        rows.append(row)
    if len(rows) != 36:
        raise ValueError("active catalog audit requires exactly 36 rows")
    return rows


def _json_document(
    rows: list[dict[str, Any]],
    *,
    sources: dict[str, Any],
    parents: dict[str, str],
    assertions: dict[str, int],
) -> dict[str, Any]:
    receipt: SQLiteSealReceipt = sources["receipt"]
    return {
        "schema_version": _DOCUMENT_SCHEMA_VERSION,
        "data_version": _DATA_VERSION,
        "catalog_revision_sha256": sources["revision_hash"],
        "seal_parent": _safe_seal_parent(receipt),
        "evidence_parents": parents,
        "evidence_parents_sha256": canonical_sha256(parents),
        "source_assertions": assertions,
        "row_count": len(rows),
        "sort_contract": "canonical_place_id_utf8_bytes_ascending",
        "rows": rows,
    }


def _parquet_bytes(rows: list[dict[str, Any]], *, document: dict[str, Any]) -> bytes:
    semantic = [canonical_json_bytes(row).decode("utf-8") for row in rows]
    schema = pa.schema(
        [
            pa.field("canonical_place_id", pa.string(), nullable=False),
            pa.field("canonical_row_sha256", pa.string(), nullable=False),
            pa.field("name_ko", pa.string(), nullable=False),
            pa.field("latitude", pa.float64()),
            pa.field("longitude", pa.float64()),
            pa.field("canonical_row_json", pa.string(), nullable=False),
        ],
        metadata={
            b"schema_version": _DOCUMENT_SCHEMA_VERSION.encode(),
            b"data_version": _DATA_VERSION.encode(),
            b"catalog_revision_sha256": str(document["catalog_revision_sha256"]).encode(),
            b"seal_parent": canonical_json_bytes(document["seal_parent"]),
            b"evidence_parents": canonical_json_bytes(document["evidence_parents"]),
            b"evidence_parents_sha256": str(document["evidence_parents_sha256"]).encode(),
        },
    )
    table = pa.Table.from_arrays(
        [
            pa.array([row["canonical_place_id"] for row in rows], type=pa.string()),
            pa.array([row["canonical_row_sha256"] for row in rows], type=pa.string()),
            pa.array([row["name_ko"] for row in rows], type=pa.string()),
            pa.array([row["latitude"] for row in rows], type=pa.float64()),
            pa.array([row["longitude"] for row in rows], type=pa.float64()),
            pa.array(semantic, type=pa.string()),
        ],
        schema=schema,
    )
    sink = pa.BufferOutputStream()
    pq.write_table(
        table,
        sink,
        compression="zstd",
        compression_level=9,
        use_dictionary=False,
        write_statistics=False,
        data_page_version="1.0",
        version="2.6",
    )
    return bytes(sink.getvalue())


def _csv_bytes(rows: list[dict[str, Any]], *, document: dict[str, Any]) -> bytes:
    fields = (
        "schema_version",
        "data_version",
        "catalog_revision_sha256",
        "sqlite_seal_receipt_sha256",
        "logical_seal_sha256",
        "database_sha256",
        "evidence_parents_sha256",
        "evidence_parents_json",
        "canonical_place_id",
        "canonical_row_sha256",
        "name_ko",
        "latitude",
        "longitude",
        "evidence_states_json",
    )
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    seal = document["seal_parent"]
    parents_json = canonical_json_bytes(document["evidence_parents"]).decode()
    for row in rows:
        writer.writerow(
            {
                "schema_version": _DOCUMENT_SCHEMA_VERSION,
                "data_version": _DATA_VERSION,
                "catalog_revision_sha256": document["catalog_revision_sha256"],
                "sqlite_seal_receipt_sha256": seal["sqlite_seal_receipt_sha256"],
                "logical_seal_sha256": seal["logical_seal_sha256"],
                "database_sha256": seal["database_sha256"],
                "evidence_parents_sha256": document["evidence_parents_sha256"],
                "evidence_parents_json": parents_json,
                "canonical_place_id": row["canonical_place_id"],
                "canonical_row_sha256": row["canonical_row_sha256"],
                "name_ko": human_csv_safe(row["name_ko"]),
                "latitude": row["latitude"],
                "longitude": row["longitude"],
                "evidence_states_json": canonical_json_bytes(row["evidence_states"]).decode(),
            }
        )
    return stream.getvalue().encode("utf-8")


def _markdown_bytes(rows: list[dict[str, Any]], *, document: dict[str, Any]) -> bytes:
    seal = document["seal_parent"]
    lines = [
        "# Canonical 36 Final Audit",
        "",
        f"- Schema: `{_DOCUMENT_SCHEMA_VERSION}`",
        f"- Data version: `{_DATA_VERSION}`",
        f"- Catalog revision: `{document['catalog_revision_sha256']}`",
        f"- SQLite seal receipt: `{seal['sqlite_seal_receipt_sha256']}`",
        f"- Logical seal: `{seal['logical_seal_sha256']}`",
        f"- Database content hash: `{seal['database_sha256']}`",
        "- Aggregate counts: development={development}, held-out={held_out}, total={total}".format(
            development=seal["development_count"],
            held_out=seal["held_out_count"],
            total=seal["total_count"],
        ),
        f"- Evidence parent map hash: `{document['evidence_parents_sha256']}`",
        "",
        "## Evidence parents",
        "",
    ]
    lines.extend(
        f"- {key}: `{value}`" for key, value in sorted(document["evidence_parents"].items())
    )
    lines.extend(
        [
            "",
            "## Rows",
            "",
            "| Canonical place | Row hash | Korean name | Latitude | Longitude | Evidence states |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| {place} | {digest} | {name} | {lat} | {lon} | {states} |".format(
                place=human_markdown_safe(row["canonical_place_id"]),
                digest=row["canonical_row_sha256"],
                name=human_markdown_safe(row["name_ko"]),
                lat=row["latitude"],
                lon=row["longitude"],
                states=human_markdown_safe(canonical_json_bytes(row["evidence_states"]).decode()),
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _forbidden_scan(name: str, payload: bytes) -> None:
    if name.endswith(".parquet"):
        text = canonical_json_bytes(parquet_semantic_rows_bytes(payload)).decode().casefold()
    else:
        text = payload.decode("utf-8").casefold()
    for fragment in _FORBIDDEN:
        if fragment in text:
            raise ValueError("audit projection contains a forbidden capability or membership field")


def _assemble_bundle(repository_root: Path, receipt_path: Path) -> _BuiltBundle:
    sources = _load_sources(repository_root, receipt_path)
    policy = sources["raw"]["policy"]
    assertions = _assertions(policy, sources["reviewed_relationships"])
    parents = _evidence_parents(sources)
    rows = _build_rows(sources)
    document = _json_document(rows, sources=sources, parents=parents, assertions=assertions)
    files = {
        "canonical-36.csv": _csv_bytes(rows, document=document),
        "canonical-36.json": canonical_json_bytes(document),
        "canonical-36.md": _markdown_bytes(rows, document=document),
        "canonical-36.parquet": _parquet_bytes(rows, document=document),
    }
    manifest: dict[str, Any] = {
        "schema_version": _MANIFEST_SCHEMA_VERSION,
        "data_version": _DATA_VERSION,
        "catalog_revision_sha256": sources["revision_hash"],
        "seal_parent": document["seal_parent"],
        "evidence_parents": parents,
        "evidence_parents_sha256": document["evidence_parents_sha256"],
        "source_assertions": assertions,
        "counts": {
            "development_count": 24,
            "held_out_count": 12,
            "total_count": 36,
        },
        "row_count": 36,
        "files": {
            name: {
                "sha256": _sha256(files[name]),
                "row_count": 36,
                "role": "authoritative" if name.endswith((".json", ".parquet")) else "human-review",
            }
            for name in _PROJECTION_NAMES
        },
    }
    manifest["projection_manifest_sha256"] = canonical_sha256(manifest)
    files["projection-manifest.json"] = canonical_json_bytes(manifest)
    for name, payload in files.items():
        _forbidden_scan(name, payload)
    return _BuiltBundle(
        files=files, manifest_sha256=manifest["projection_manifest_sha256"], row_count=36
    )


def parquet_semantic_rows_bytes(payload: bytes) -> list[dict[str, Any]]:
    table = pq.read_table(pa.BufferReader(payload))
    values = table.column("canonical_row_json").to_pylist()
    return [json.loads(value) for value in values]


def parquet_semantic_rows(path: Path) -> list[dict[str, Any]]:
    """Return the canonical semantic rows without exposing Parquet metadata."""

    return parquet_semantic_rows_bytes(_read_bounded(path))


def _validate_cross_view(files: Mapping[str, bytes]) -> None:
    document = json.loads(files["canonical-36.json"])
    rows = document["rows"]
    if rows != parquet_semantic_rows_bytes(files["canonical-36.parquet"]):
        raise ValueError("JSON and Parquet projections differ")
    expected = [(row["canonical_place_id"], row["canonical_row_sha256"]) for row in rows]
    csv_rows = list(csv.DictReader(io.StringIO(files["canonical-36.csv"].decode())))
    if [(row["canonical_place_id"], row["canonical_row_sha256"]) for row in csv_rows] != expected:
        raise ValueError("CSV projection differs from authoritative rows")
    markdown = files["canonical-36.md"].decode()
    markdown_rows = [line for line in markdown.splitlines() if line.startswith("| place:")]
    if len(markdown_rows) != len(expected) or any(
        not any(place in line and digest in line for line in markdown_rows)
        for place, digest in expected
    ):
        raise ValueError("Markdown projection differs from authoritative rows")


def _write_prepared(prepared: Path, files: Mapping[str, bytes]) -> None:
    prepared.mkdir(mode=0o700)
    for name in OUTPUT_NAMES:
        target = prepared / name
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        try:
            os.write(descriptor, files[name])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def build_catalog_v2_audit(
    *, repository_root: Path, sqlite_seal_receipt: Path, output_root: Path | None = None
) -> CatalogV2AuditResult:
    """Build twice, compare bytes, and optionally publish with no replacement."""

    if output_root is not None and os.path.lexists(output_root):
        raise FileExistsError("output already exists; publication is immutable")
    first = _assemble_bundle(repository_root, sqlite_seal_receipt)
    second = _assemble_bundle(repository_root, sqlite_seal_receipt)
    if first.files != second.files or first.manifest_sha256 != second.manifest_sha256:
        raise ValueError("audit projections are not byte deterministic")
    _validate_cross_view(first.files)
    if output_root is not None:
        output_root = output_root.absolute()
        output_root.parent.mkdir(parents=True, exist_ok=True)
        prepared = Path(tempfile.mkdtemp(prefix=".catalog-v2-audit-", dir=output_root.parent))
        prepared.rmdir()
        try:
            _write_prepared(prepared, first.files)
            publish_immutable_directory(prepared=prepared, output=output_root)
        except BaseException:
            if prepared.exists():
                shutil.rmtree(prepared)
            raise
    return CatalogV2AuditResult(
        file_hashes={name: _sha256(payload) for name, payload in first.files.items()},
        manifest_sha256=first.manifest_sha256,
        row_count=first.row_count,
    )


def verify_catalog_v2_audit(
    output_root: Path, *, repository_root: Path, sqlite_seal_receipt: Path
) -> CatalogV2AuditResult:
    """Verify inventory, live parents, exact bytes, and cross-view equality."""

    if output_root.is_symlink() or not output_root.is_dir():
        raise ValueError("projection output must be a regular directory")
    actual_names = tuple(sorted(path.name for path in output_root.iterdir()))
    if actual_names != OUTPUT_NAMES:
        raise ValueError("projection inventory is not exact")
    actual = {name: _read_bounded(output_root / name) for name in OUTPUT_NAMES}
    expected = _assemble_bundle(repository_root, sqlite_seal_receipt)
    for name in OUTPUT_NAMES:
        if actual[name] != expected.files[name]:
            raise ValueError(f"projection {name} differs from deterministic source replay")
        _forbidden_scan(name, actual[name])
    _validate_cross_view(actual)
    manifest = json.loads(actual["projection-manifest.json"])
    if manifest.get("projection_manifest_sha256") != expected.manifest_sha256:
        raise ValueError("projection manifest self hash is stale")
    return CatalogV2AuditResult(
        file_hashes={name: _sha256(payload) for name, payload in actual.items()},
        manifest_sha256=expected.manifest_sha256,
        row_count=36,
    )
