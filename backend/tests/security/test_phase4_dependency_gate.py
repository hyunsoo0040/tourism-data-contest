"""Fail-closed regression coverage for the retired Phase 4 dependency gate."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from itda.cli.verify_phase4_dependency_gate import LEGACY_GATE_EXHAUSTED_MESSAGE

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "arguments",
    (
        (),
        ("--output", "alternate.json"),
        ("--gsd-tools", "caller-selected-tool.cjs", "--uv-version-output", "uv 0.11.28"),
    ),
)
def test_retired_gate_rejects_every_invocation_without_publishing(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    output = tmp_path / "alternate.json"
    result = subprocess.run(
        [sys.executable, "-m", "itda.cli.verify_phase4_dependency_gate", *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert LEGACY_GATE_EXHAUSTED_MESSAGE in result.stderr
    assert not output.exists()


def test_retired_gate_contains_no_dormant_measurement_or_execution_surface() -> None:
    source = (REPOSITORY_ROOT / "backend/src/itda/cli/verify_phase4_dependency_gate.py").read_text(
        encoding="utf-8"
    )

    for forbidden in (
        "subprocess",
        "tomllib",
        "os.open",
        "verify_and_write",
        "_fresh_legitimacy",
        "_verify_toolchain",
    ):
        assert forbidden not in source


PHASE_ROOT = REPOSITORY_ROOT / ".planning/phases/04-dev-24-image-benchmark-and-multimodal-fusion"
PACKAGE_RECEIPT = PHASE_ROOT / "04-PACKAGE-COORDINATE-RECEIPT.json"
LOCK_RECEIPT = PHASE_ROOT / "04-LOCK-DIFF-APPROVAL.json"
LOCK_PROPOSAL = PHASE_ROOT / "04-LOCK-PROPOSAL.json"
PACKAGE_SUMMARY = PHASE_ROOT / "04-03-SUMMARY.md"
LOCK_SUMMARY = PHASE_ROOT / "04-15-SUMMARY.md"
EXPECTED_COORDINATES = (
    "Pillow==12.3.0",
    "ImageHash==4.3.2",
    "scikit-learn==1.9.0",
    "scipy==1.18.0",
    "dvc==3.67.1",
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    canonical = json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert raw == f"{canonical}\n".encode()
    return parsed, raw


def _self_digest(receipt: dict[str, Any]) -> str:
    unsigned = dict(receipt)
    digest = unsigned.pop("receipt_sha256")
    assert isinstance(digest, str)
    canonical_unsigned = json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    assert hashlib.sha256(canonical_unsigned).hexdigest() == digest
    return digest


def _summary_receipt_digest(path: Path, receipt_sha256: str) -> None:
    assert re.search(rf"receipt_sha256[=:]\s*{re.escape(receipt_sha256)}", path.read_text())


def test_package_approval_receipt_is_exact_and_bound_to_summary() -> None:
    receipt, _ = _load_canonical(PACKAGE_RECEIPT)
    receipt_sha256 = _self_digest(receipt)

    assert receipt["schema_version"] == "phase4-package-coordinate-approval.v1"
    assert receipt["decision"] == "APPROVED"
    assert receipt["approver_pseudonym"]
    assert tuple(item["coordinate"] for item in receipt["packages"]) == EXPECTED_COORDINATES
    assert all(item["registry"] == "pypi" for item in receipt["packages"])
    assert all(
        item["registry_json_sha256"] and item["registry_page_sha256"]
        for item in receipt["packages"]
    )
    assert "dependency-installation" in receipt["excluded_authorizations"]
    assert "protected-dataset-access" in receipt["excluded_authorizations"]
    _summary_receipt_digest(PACKAGE_SUMMARY, receipt_sha256)


def test_lock_approval_receipt_binds_current_proposal_and_dependency_bytes() -> None:
    receipt, _ = _load_canonical(LOCK_RECEIPT)
    proposal, _ = _load_canonical(LOCK_PROPOSAL)
    package, package_raw = _load_canonical(PACKAGE_RECEIPT)
    receipt_sha256 = _self_digest(receipt)

    assert receipt["schema_version"] == "phase4-lock-diff-approval.v1"
    assert receipt["decision"] == "APPROVED"
    assert receipt["coordinate_approval"]["receipt_sha256"] == package["receipt_sha256"]
    assert (
        receipt["coordinate_approval"]["receipt_file_sha256"]
        == hashlib.sha256(package_raw).hexdigest()
    )
    assert receipt["proposal_sha256"] == proposal["proposal_sha256"]
    assert (
        tuple(item["coordinate"] for item in receipt["direct_coordinates"]) == EXPECTED_COORDINATES
    )
    assert receipt["plan_04_16_sync_authorization"]["authorized"] is True
    assert receipt["plan_04_16_sync_authorization"]["maximum_syncs"] == 1
    assert receipt["proposal_installation_authorized"] is False

    for item in receipt["files"]:
        actual_sha256 = hashlib.sha256((REPOSITORY_ROOT / item["path"]).read_bytes()).hexdigest()
        assert item["after_sha256"] == actual_sha256
    assert receipt["diff"]["paths"] == ["backend/pyproject.toml", "backend/uv.lock"]
    _summary_receipt_digest(LOCK_SUMMARY, receipt_sha256)


def test_dependency_approval_receipts_cannot_authorize_provider_or_release_actions() -> None:
    package, _ = _load_canonical(PACKAGE_RECEIPT)
    lock, _ = _load_canonical(LOCK_RECEIPT)
    proposal, _ = _load_canonical(LOCK_PROPOSAL)

    forbidden = {
        "external-provider-call",
        "protected-dataset-access",
        "release-activation",
        "production-or-release-activation",
    }
    assert forbidden.intersection(package["authorized_actions"]) == set()
    assert forbidden.intersection(lock["authorized_actions"]) == set()
    assert forbidden.intersection(package["excluded_authorizations"]) == forbidden - {
        "production-or-release-activation"
    }
    assert forbidden.intersection(lock["excluded_authorizations"]) == {
        "external-provider-call",
        "protected-dataset-access",
        "production-or-release-activation",
    }
    assert proposal["installation_authorized"] is False
