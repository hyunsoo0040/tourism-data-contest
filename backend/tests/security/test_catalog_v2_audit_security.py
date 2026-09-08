"""Security boundary for the membership-free final canonical-v2 audit."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from itda.pipeline import export_catalog_v2_audit as exporter

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SEAL_RECEIPT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/sqlite/real-manifest-seal-receipt.json"
)

_FORBIDDEN_OUTPUT_FRAGMENTS = (
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


def test_exporter_never_opens_database_or_sidecars(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_open = os.open
    opened: list[str] = []

    def guarded_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *args: object,
        **kwargs: object,
    ) -> int:
        rendered = os.fsdecode(path)
        folded = rendered.casefold()
        if any(
            fragment in folded for fragment in (".sqlite3", "-journal", "-wal", "-shm", "file:")
        ):
            raise AssertionError("database capability was opened")
        opened.append(rendered)
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", guarded_open)
    exporter.build_catalog_v2_audit(
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
        output_root=tmp_path / "audit",
    )
    assert opened
    assert not any(path.casefold().endswith(".sqlite3") for path in opened)


def test_human_renderers_neutralize_formula_control_and_markup() -> None:
    hostile = '=HYPERLINK("https://invalid.example")\x00<script>|`[_]*'
    csv_value = exporter.human_csv_safe(hostile)
    markdown_value = exporter.human_markdown_safe(hostile)
    assert csv_value.startswith("'")
    assert "\x00" not in csv_value
    assert "<script" not in markdown_value.casefold()
    assert "|" not in markdown_value
    assert "`" not in markdown_value
    assert "[" not in markdown_value


def test_published_bundle_contains_no_membership_or_database_capability(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "audit"
    exporter.build_catalog_v2_audit(
        repository_root=REPOSITORY_ROOT,
        sqlite_seal_receipt=SEAL_RECEIPT,
        output_root=output_root,
    )
    for path in output_root.iterdir():
        assert path.name in exporter.OUTPUT_NAMES
        if path.suffix == ".parquet":
            payload = " ".join(
                str(value) for value in exporter.parquet_semantic_rows(path)
            ).casefold()
        else:
            payload = path.read_text(encoding="utf-8").casefold()
        for forbidden in _FORBIDDEN_OUTPUT_FRAGMENTS:
            assert forbidden not in payload

    manifest = json.loads((output_root / "projection-manifest.json").read_bytes())
    seal_parent = manifest["seal_parent"]
    assert set(seal_parent) == {
        "database_sha256",
        "development_count",
        "held_out_count",
        "logical_seal_sha256",
        "sqlite_seal_receipt_sha256",
        "total_count",
    }


def test_cli_has_only_build_verify_and_sanitized_receipt_inputs() -> None:
    from itda.cli.export_catalog_v2_audit import parser

    help_text = parser().format_help().casefold()
    assert "--build" in help_text
    assert "--verify" in help_text
    assert "--sqlite-seal-receipt" in help_text
    assert "--database" not in help_text
    assert "--dsn" not in help_text
    assert "--uri" not in help_text
    assert "--member" not in help_text
    assert "--split" not in help_text


def test_sanitized_seal_parent_rejects_extra_fields() -> None:
    safe = {
        "database_sha256": "1" * 64,
        "development_count": 24,
        "held_out_count": 12,
        "logical_seal_sha256": "2" * 64,
        "sqlite_seal_receipt_sha256": "3" * 64,
        "total_count": 36,
    }
    exporter.SanitizedSQLiteSealParent.model_validate(safe)
    with pytest.raises(ValueError):
        exporter.SanitizedSQLiteSealParent.model_validate({**safe, "dev_members": []})
