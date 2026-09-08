"""Wave 0 contract for DATA-03 (02-W0-DATA03; T-02-04)."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

CAPABILITY_MODULE = "itda.pipeline.export_catalog_audit"
EXPECTED_COLUMNS = (
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


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("candidate audit export capability is implemented in Plan 02-07")
    return importlib.import_module(CAPABILITY_MODULE)


def _audit_payload() -> dict[str, object]:
    return {
        "schema_version": "catalog-audit-v1",
        "data_version": "catalog-audit-data-v1",
        "source_version": "catalog-collection-v1",
        "rows": [
            {
                "candidate_id": "candidate:001",
                "name_ko": '=HYPERLINK("https://invalid.example")',
                "latitude": 35.790000,
                "longitude": 129.331000,
                "description_status": "MISSING",
                "description_missing_reason": "DESCRIPTION_TOO_SHORT",
                "photo_status": "PRESENT",
                "photo_missing_reason": None,
                "operational_status": "UNKNOWN",
                "operational_missing_reason": "PROVIDER_FIELD_ABSENT",
                "odii_status": "MISSING",
                "odii_missing_reason": "NO_MATCHED_STORY",
            }
        ],
    }


def test_audit_requires_explicit_completeness_and_missing_reasons() -> None:
    capability = _capability_or_skip()
    audit = capability.validate_catalog_audit(_audit_payload())
    row = audit.rows[0]
    assert row.latitude == 35.790000
    assert row.longitude == 129.331000
    assert row.description_missing_reason == "DESCRIPTION_TOO_SHORT"
    assert row.photo_missing_reason is None
    assert row.operational_missing_reason == "PROVIDER_FIELD_ABSENT"
    assert row.odii_missing_reason == "NO_MATCHED_STORY"


def test_all_projection_bytes_are_deterministic_hash_linked_and_not_truth_inputs(
    tmp_path: Path,
) -> None:
    capability = _capability_or_skip()
    first = capability.export_catalog_audit(_audit_payload(), tmp_path / "first")
    second = capability.export_catalog_audit(_audit_payload(), tmp_path / "second")
    assert first.canonical_json_bytes == second.canonical_json_bytes
    assert first.parquet_bytes == second.parquet_bytes
    assert first.csv_bytes == second.csv_bytes
    assert first.markdown_bytes == second.markdown_bytes
    assert first.column_order == EXPECTED_COLUMNS
    assert first.projection_manifest.output_hashes == second.projection_manifest.output_hashes
    assert set(first.projection_manifest.output_hashes) == {
        "catalog-audit.json",
        "catalog-audit.parquet",
        "catalog-audit.csv",
        "catalog-audit.md",
    }
    with pytest.raises(ValueError, match="canonical audit JSON"):
        capability.load_catalog_audit(tmp_path / "first" / "catalog-audit.csv")


def test_human_projections_neutralize_formula_control_and_markup_injection(
    tmp_path: Path,
) -> None:
    capability = _capability_or_skip()
    exported = capability.export_catalog_audit(_audit_payload(), tmp_path)
    csv_text = exported.csv_bytes.decode("utf-8")
    markdown_text = exported.markdown_bytes.decode("utf-8")
    assert "\"'=HYPERLINK" in csv_text
    assert "=HYPERLINK(" not in csv_text.replace("'=HYPERLINK(", "")
    assert "<script" not in markdown_text.casefold()
    assert "<" not in markdown_text or "&lt;" in markdown_text


def test_missing_candidate_audit_exports_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:candidate-audit-exports", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)
