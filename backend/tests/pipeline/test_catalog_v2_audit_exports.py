"""Final canonical-v2 audit export contract (Plan 02-33)."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pyarrow.parquet as pq  # type: ignore[import-untyped]
import pytest

from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.export_catalog_v2_audit import (
    OUTPUT_NAMES,
    build_catalog_v2_audit,
    verify_catalog_v2_audit,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SEAL_RECEIPT = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/sqlite/real-manifest-seal-receipt.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _published_hashes(root: Path) -> dict[str, str]:
    return {name: _sha256(root / name) for name in OUTPUT_NAMES}


def _json_rows(root: Path) -> list[dict[str, object]]:
    payload = json.loads((root / "canonical-36.json").read_bytes())
    assert isinstance(payload, dict)
    rows = payload["rows"]
    assert isinstance(rows, list)
    return rows


def _parquet_rows(root: Path) -> list[dict[str, object]]:
    table = pq.read_table(root / "canonical-36.parquet")
    return [json.loads(value) for value in table.column("canonical_row_json").to_pylist()]


def test_builds_two_byte_identical_cross_view_bundles_from_sanitized_receipt(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    first = build_catalog_v2_audit(
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
        output_root=first_root,
    )
    second = build_catalog_v2_audit(
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
        output_root=second_root,
    )

    assert tuple(sorted(path.name for path in first_root.iterdir())) == OUTPUT_NAMES
    assert _published_hashes(first_root) == _published_hashes(second_root)
    assert first.file_hashes == second.file_hashes
    assert first.manifest_sha256 == second.manifest_sha256

    json_rows = _json_rows(first_root)
    parquet_rows = _parquet_rows(first_root)
    assert len(json_rows) == len(parquet_rows) == 36
    assert json_rows == parquet_rows
    assert [row["canonical_place_id"] for row in json_rows] == sorted(
        (row["canonical_place_id"] for row in json_rows),
        key=lambda value: str(value).encode("utf-8"),
    )

    with (first_root / "canonical-36.csv").open(
        encoding="utf-8", newline=""
    ) as stream:
        csv_rows = list(csv.DictReader(stream))
    markdown_rows = [
        line
        for line in (first_root / "canonical-36.md").read_text(encoding="utf-8").splitlines()
        if line.startswith("| place:")
    ]
    expected_identity = [
        (str(row["canonical_place_id"]), str(row["canonical_row_sha256"]))
        for row in json_rows
    ]
    assert [
        (row["canonical_place_id"], row["canonical_row_sha256"]) for row in csv_rows
    ] == expected_identity
    assert len(markdown_rows) == 36
    for place_id, row_sha256 in expected_identity:
        assert any(place_id in line and row_sha256 in line for line in markdown_rows)

    manifest = json.loads((first_root / "projection-manifest.json").read_bytes())
    assert manifest["row_count"] == 36
    assert manifest["counts"] == {
        "development_count": 24,
        "held_out_count": 12,
        "total_count": 36,
    }
    assert set(manifest["files"]) == set(OUTPUT_NAMES[:-1])
    assert manifest["projection_manifest_sha256"] == canonical_sha256(
        {key: value for key, value in manifest.items() if key != "projection_manifest_sha256"}
    )
    verified = verify_catalog_v2_audit(
        first_root,
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
    )
    assert verified.manifest_sha256 == first.manifest_sha256


def test_build_is_no_replace_and_verify_rejects_tampered_projection(tmp_path: Path) -> None:
    output_root = tmp_path / "published"
    build_catalog_v2_audit(
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
        output_root=output_root,
    )
    before = _published_hashes(output_root)

    with pytest.raises(FileExistsError, match="already exists"):
        build_catalog_v2_audit(
            repository_root=REPOSITORY_ROOT,
            sqlite_seal_receipt=SEAL_RECEIPT,
            output_root=output_root,
        )
    assert _published_hashes(output_root) == before

    target = output_root / "canonical-36.csv"
    target.write_bytes(target.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="projection"):
        verify_catalog_v2_audit(
            output_root,
            repository_root=REPOSITORY_ROOT,
            sqlite_seal_receipt=SEAL_RECEIPT,
        )


def test_receipt_schema_self_hash_and_live_parent_mismatch_fail_closed(
    tmp_path: Path,
) -> None:
    original = json.loads(SEAL_RECEIPT.read_bytes())

    extra = dict(original)
    extra["dev_members"] = ["forbidden"]
    extra_path = tmp_path / "extra.json"
    extra_path.write_bytes(canonical_json_bytes(extra))
    with pytest.raises(ValueError, match="sanitized seal receipt"):
        build_catalog_v2_audit(
            repository_root=REPOSITORY_ROOT,
            sqlite_seal_receipt=extra_path,
        )

    stale = dict(original)
    stale["catalog_revision_sha256"] = "0" * 64
    stale["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in stale.items() if key != "receipt_sha256"}
    )
    stale_path = tmp_path / "stale.json"
    stale_path.write_bytes(canonical_json_bytes(stale))
    with pytest.raises(ValueError, match="catalog parent"):
        build_catalog_v2_audit(
            repository_root=REPOSITORY_ROOT,
            sqlite_seal_receipt=stale_path,
        )


def test_manifest_binds_complete_leaf_and_nonmembership_parent_roots(tmp_path: Path) -> None:
    output_root = tmp_path / "audit"
    build_catalog_v2_audit(
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
        output_root=output_root,
    )
    manifest = json.loads((output_root / "projection-manifest.json").read_bytes())
    parents = manifest["evidence_parents"]
    assert manifest["source_assertions"] == {
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
    assert set(parents) >= {
        "activation_event_sha256",
        "asset_rights_root_sha256",
        "catalog_approval_sha256",
        "catalog_revision_sha256",
        "crosswalk_automatic_leaves_root_sha256",
        "crosswalk_unresolved_leaves_root_sha256",
        "database_sha256",
        "formal_policy_sha256",
        "logical_seal_sha256",
        "media_attachment_leaves_root_sha256",
        "objective_evidence_rows_root_sha256",
        "protected_catalog_v1_tree_sha256",
        "protected_inputs_root_sha256",
        "relationship_automatic_leaves_root_sha256",
        "relationship_unresolved_leaves_root_sha256",
        "sqlite_seal_receipt_sha256",
    }
    for value in parents.values():
        assert isinstance(value, str) and len(value) == 64
