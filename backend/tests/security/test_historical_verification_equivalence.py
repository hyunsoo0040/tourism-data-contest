"""Security contract for the Phase 2 historical verification lineage."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from itda.cli.fingerprint_catalog_v1 import FingerprintError, verify_manifest
from itda.cli.verify_historical_phase2 import (
    HistoricalVerificationError,
    _assert_replay_equivalent,
    _verify_evidence,
    _verify_historical_parent,
    build_mapping,
    extract_sources,
    obligations,
)


def test_missing_historical_equivalence_is_controlled_red() -> None:
    assert len(extract_sources(_repository_root())) == 19


def test_current_checkout_uses_explicit_successor_for_historical_parent() -> None:
    root = _repository_root()
    with pytest.raises(FingerprintError, match="live recomputation"):
        verify_manifest(
            root,
            root / "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json",
        )

    _verify_historical_parent(root)


def test_historical_parent_falls_back_to_strict_when_successor_is_absent(
    tmp_path: Path,
) -> None:
    with pytest.raises(FingerprintError, match="live recomputation"):
        _verify_historical_parent(_repository_root(), successor_path=tmp_path / "absent.json")


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_exact_cardinality_bijection_and_non_weaker_obligations() -> None:
    mapping = build_mapping(_repository_root())
    rows = mapping["rows"]
    assert mapping["source_count"] == 19
    assert len(rows) == 19
    assert len({row["replacement_id"] for row in rows}) == 19
    assert len(
        {
            (
                row["source"]["plan_id"],
                row["source"]["task_ordinal"],
                row["source"]["task_name"],
                row["source"]["original_command_sha256"],
            )
            for row in rows
        }
    ) == 19
    for source, row in zip(extract_sources(_repository_root()), rows, strict=True):
        assert row["replacement_command"].startswith(
            "set -eu; repo_root=$(rtk git rev-parse --show-toplevel)"
        )
        assert row["cwd_kind"] == "repository_root"
        assert row["obligations"] == obligations(source["original_command"])


def test_altered_original_and_missing_or_shared_mapping_fail_closed(
    tmp_path: Path,
) -> None:
    plan_root = tmp_path / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
    plan_root.mkdir(parents=True)
    real_root = (
        _repository_root()
        / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
    )
    for ordinal in range(1, 9):
        source = real_root / f"02-{ordinal:02d}-PLAN.md"
        text = source.read_text(encoding="utf-8")
        if ordinal == 1:
            text = text.replace("python -m json.tool", "python -m json.tool ")
        (plan_root / source.name).write_text(text, encoding="utf-8")
    altered = extract_sources(tmp_path)
    current = extract_sources(_repository_root())
    assert altered[0]["original_command_sha256"] != current[0]["original_command_sha256"]

    mapping = build_mapping(_repository_root())
    rows = copy.deepcopy(mapping["rows"])
    rows.pop()
    assert len(rows) != mapping["source_count"]
    rows = copy.deepcopy(mapping["rows"])
    rows[1]["replacement_id"] = rows[0]["replacement_id"]
    assert len({row["replacement_id"] for row in rows}) != len(rows)


def test_obligation_extractor_detects_removed_and_duplicated_nodes() -> None:
    command = (
        "rtk pytest tests/example.py::test_named -q && "
        "rtk git check-ignore artifacts/restricted/catalog/v1/example.json"
    )
    expected = obligations(command)
    assert obligations(command.replace("::test_named", "")) != expected
    assert obligations(f"{command} && {command}") != expected


def test_evidence_hash_status_and_named_hash_tampering_fail() -> None:
    mapping = build_mapping(_repository_root())
    rows = []
    for mapping_row in mapping["rows"]:
        fields = {
            "source": mapping_row["source"],
            "replacement_id": mapping_row["replacement_id"],
            "replacement_command_sha256": mapping_row["replacement_command_sha256"],
            "cwd": ".",
            "exit_code": 0,
            "status": "PASS",
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64,
            "named_evidence_sha256": {
                name: __import__("itda.domain.canonical", fromlist=["canonical_sha256"])
                .canonical_sha256(values)
                for name, values in mapping_row["obligations"].items()
            },
        }
        rows.append(
            {
                **fields,
                "row_sha256": __import__(
                    "itda.domain.canonical", fromlist=["canonical_sha256"]
                ).canonical_sha256(fields),
            }
        )
    fields = {
        "schema_version": "historical-verification-evidence-v1",
        "mapping_sha256": mapping["mapping_sha256"],
        "evidence_count": 19,
        "rows": rows,
    }
    evidence = {
        **fields,
        "evidence_sha256": __import__(
            "itda.domain.canonical", fromlist=["canonical_sha256"]
        ).canonical_sha256(fields),
    }
    _verify_evidence(mapping, evidence)
    for key, value in (
        ("status", "FAIL"),
        ("exit_code", 1),
        ("named_evidence_sha256", {}),
    ):
        tampered = json.loads(json.dumps(evidence))
        tampered["rows"][0][key] = value
        with pytest.raises(HistoricalVerificationError):
            _verify_evidence(mapping, tampered)


def test_replay_equivalence_allows_only_sanitized_output_digest_drift() -> None:
    recorded = {
        "schema_version": "historical-verification-evidence-v1",
        "mapping_sha256": "a" * 64,
        "evidence_count": 1,
        "rows": [
            {
                "replacement_id": "replacement-01",
                "exit_code": 0,
                "status": "PASS",
                "stdout_sha256": "b" * 64,
                "stderr_sha256": "c" * 64,
                "named_evidence_sha256": {"tests": "d" * 64},
                "row_sha256": "e" * 64,
            }
        ],
        "evidence_sha256": "f" * 64,
    }
    fresh = copy.deepcopy(recorded)
    fresh["rows"][0]["stdout_sha256"] = "1" * 64
    fresh["rows"][0]["stderr_sha256"] = "2" * 64
    fresh["rows"][0]["row_sha256"] = "3" * 64
    fresh["evidence_sha256"] = "4" * 64
    _assert_replay_equivalent(recorded, fresh)

    fresh["rows"][0]["status"] = "FAIL"
    with pytest.raises(HistoricalVerificationError, match="semantic evidence"):
        _assert_replay_equivalent(recorded, fresh)
