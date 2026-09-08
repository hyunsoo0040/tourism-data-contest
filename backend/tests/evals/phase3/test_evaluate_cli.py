"""Wave 0 RED contracts for canonical synthetic Phase 3 evaluation reports."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

CLI_MODULE = "itda.cli.evaluate_phase3"
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
FIXTURE_PATH = REPOSITORY_ROOT / "fixtures/synthetic/phase3/evaluate-manifest.json"
EXPECTED_REPORT_PATH = (
    REPOSITORY_ROOT / "fixtures/synthetic/phase3/evaluate-expected-report.json"
)


def _require_cli() -> None:
    try:
        available = importlib.util.find_spec(CLI_MODULE) is not None
    except ModuleNotFoundError:
        available = False
    if not available:
        pytest.fail("PHASE3-MISSING:evaluate-cli", pytrace=False)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture() -> dict[str, Any]:
    return _load(FIXTURE_PATH)


def _expected_report() -> dict[str, Any]:
    return _load(EXPECTED_REPORT_PATH)


def _deep_merge(target: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def _set_path(payload: dict[str, Any], path: str, value: object) -> None:
    parts = path.split(".")
    current = payload
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


def _remove_path(payload: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    current = payload
    for part in parts[:-1]:
        current = current[part]
    current.pop(parts[-1])


def _projection(name: str) -> dict[str, Any]:
    fixture = _fixture()
    payload = copy.deepcopy(fixture["base_manifest"])
    override = copy.deepcopy(fixture["projections"][name])
    remove_paths = override.pop("remove_paths", [])
    replace_paths = override.pop("replace_paths", {})
    _deep_merge(payload, override)
    for path in remove_paths:
        _remove_path(payload, path)
    for path, value in replace_paths.items():
        _set_path(payload, path, value)
    if name == "malformed_non_finite":
        payload["metrics"]["macro_mae"] = float("nan")
    return payload


def _forbidden_markers() -> tuple[str, ...]:
    return tuple(_fixture()["forbidden_canaries"])


def _assert_redacted(surfaces: dict[str, object]) -> None:
    for surface, payload in surfaces.items():
        if isinstance(payload, bytes):
            rendered = payload.decode("utf-8", errors="replace")
        else:
            rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        if any(marker in rendered for marker in _forbidden_markers()):
            pytest.fail(f"PHASE3-LEAK:{surface}", pytrace=False)


def _write_projection(
    path: Path,
    payload: dict[str, Any],
    *,
    noncanonical_nan: bool = False,
) -> None:
    if noncanonical_nan:
        path.write_text(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=True,
            ),
            encoding="utf-8",
        )
        return
    path.write_bytes(canonical_json_bytes(payload))


def _safe_environment() -> dict[str, str]:
    allowed = ("PATH", "PYTHONPATH", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
        }
    )
    return environment


def _run_cli(manifest_path: Path, report_path: Path) -> subprocess.CompletedProcess[bytes]:
    _require_cli()
    return subprocess.run(
        (
            sys.executable,
            "-m",
            CLI_MODULE,
            "--manifest",
            str(manifest_path),
            "--assert-thresholds",
            "--report",
            str(report_path),
        ),
        cwd=REPOSITORY_ROOT / "backend",
        env=_safe_environment(),
        capture_output=True,
        check=False,
    )


def test_expected_report_is_canonical_aggregate_only_and_self_authenticating() -> None:
    fixture = _fixture()
    passing = _projection("passing")
    report = _expected_report()

    assert fixture["synthetic_only"] is True
    assert passing["synthetic_only"] is True
    assert passing["approved_protected_evidence"] is None
    assert report["evidence_status"] == "EXTERNAL_EVIDENCE_PENDING"
    assert report["claim_scope"] == "SYNTHETIC_SOFTWARE_CONTRACT_ONLY"
    assert report["input_manifest_sha256"] == canonical_sha256(passing)

    report_payload = copy.deepcopy(report)
    report_sha256 = report_payload.pop("report_sha256")
    assert report_sha256 == canonical_sha256(report_payload)
    assert all(
        isinstance(value, (int, float)) and not isinstance(value, bool)
        for value in report["metrics"].values()
    )

    forbidden_report_keys = {
        "individual_labels",
        "evaluator_identities",
        "membership",
        "source_text",
        "restricted_locations",
        "expert_agreement_claim",
        "retrieval_quality_claim",
    }
    assert set(report).isdisjoint(forbidden_report_keys)
    _assert_redacted({"expected_report": report})


def test_evaluate_cli_pass_writes_exact_canonical_pending_report(tmp_path: Path) -> None:
    manifest_path = tmp_path / "passing.json"
    report_path = tmp_path / "report.json"
    _write_projection(manifest_path, _projection("passing"))

    completed = _run_cli(manifest_path, report_path)

    assert completed.returncode == 0
    assert report_path.read_bytes() == canonical_json_bytes(_expected_report())
    _assert_redacted(
        {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "report": report_path.read_bytes(),
        }
    )


def test_evaluate_cli_threshold_failure_is_nonzero_and_names_only_aggregate_dimension(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "failing.json"
    report_path = tmp_path / "report.json"
    _write_projection(manifest_path, _projection("failing"))

    completed = _run_cli(manifest_path, report_path)

    assert completed.returncode != 0
    report = json.loads(report_path.read_bytes())
    assert report["status"] == "THRESHOLDS_FAILED"
    assert report["failed_dimensions"] == ["macro_mae"]
    assert report["evidence_status"] == "EXTERNAL_EVIDENCE_PENDING"
    assert b"THRESHOLDS_PASSED" not in completed.stdout + completed.stderr
    assert b"THRESHOLDS_PASSED" not in report_path.read_bytes()
    _assert_redacted(
        {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "report": report_path.read_bytes(),
        }
    )


def test_absent_protected_evidence_never_becomes_a_real_quality_claim(tmp_path: Path) -> None:
    manifest_path = tmp_path / "pending.json"
    report_path = tmp_path / "report.json"
    _write_projection(manifest_path, _projection("pending"))

    completed = _run_cli(manifest_path, report_path)

    assert completed.returncode == 0
    report = json.loads(report_path.read_bytes())
    assert report["evidence_status"] == "EXTERNAL_EVIDENCE_PENDING"
    assert report["claim_scope"] == "SYNTHETIC_SOFTWARE_CONTRACT_ONLY"
    assert "expert_agreement" not in report
    assert "retrieval_quality" not in report


@pytest.mark.parametrize(
    "projection_name",
    (
        "malformed_missing_version",
        "malformed_non_finite",
        "malformed_out_of_contract",
    ),
)
def test_malformed_provenance_and_metrics_fail_closed(
    tmp_path: Path,
    projection_name: str,
) -> None:
    manifest_path = tmp_path / "malformed.json"
    report_path = tmp_path / "report.json"
    _write_projection(
        manifest_path,
        _projection(projection_name),
        noncanonical_nan=projection_name == "malformed_non_finite",
    )

    completed = _run_cli(manifest_path, report_path)

    assert completed.returncode != 0
    assert not report_path.exists()
    _assert_redacted({"stdout": completed.stdout, "stderr": completed.stderr})


def test_identical_input_produces_byte_identical_report_and_hash(tmp_path: Path) -> None:
    payload = _projection("passing")
    reports: list[bytes] = []

    for index in range(3):
        root = tmp_path / f"run-{index}"
        root.mkdir()
        manifest_path = root / "manifest.json"
        report_path = root / "report.json"
        _write_projection(manifest_path, payload)
        completed = _run_cli(manifest_path, report_path)
        assert completed.returncode == 0
        reports.append(report_path.read_bytes())

    hashes = [hashlib.sha256(report).hexdigest() for report in reports]
    assert reports[0] == reports[1] == reports[2]
    assert hashes[0] == hashes[1] == hashes[2]


def test_prohibited_input_is_rejected_without_echoing_the_matched_value(tmp_path: Path) -> None:
    manifest = _projection("passing")
    manifest["individual_label"] = _forbidden_markers()[0]
    manifest_path = tmp_path / "prohibited.json"
    report_path = tmp_path / "report.json"
    _write_projection(manifest_path, manifest)

    completed = _run_cli(manifest_path, report_path)

    assert completed.returncode != 0
    assert not report_path.exists()
    _assert_redacted({"stdout": completed.stdout, "stderr": completed.stderr})


def test_redaction_scanner_failure_names_only_the_surface() -> None:
    with pytest.raises(pytest.fail.Exception) as failure:
        _assert_redacted({"stderr": _forbidden_markers()[0]})

    assert str(failure.value) == "PHASE3-LEAK:stderr"
