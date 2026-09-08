"""Exact approved-target PyArrow supply-chain contract for Phase 02 Plan 02."""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from urllib.parse import urlparse

import pyarrow
import pytest
from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
APPROVAL_PATH = (
    REPOSITORY_ROOT
    / ".planning"
    / "phases"
    / "02-canonical-36-rights-and-evaluation-manifest"
    / "02-PYARROW-APPROVAL.json"
)
EVIDENCE_PATH = APPROVAL_PATH.with_name("02-PYARROW-TARGET-EVIDENCE.json")
PYPROJECT_PATH = REPOSITORY_ROOT / "backend" / "pyproject.toml"
LOCK_PATH = REPOSITORY_ROOT / "backend" / "uv.lock"
APPROVED_PACKAGE = "pyarrow==25.0.0"
APPROVED_FILENAME = "pyarrow-25.0.0-cp313-cp313-macosx_12_0_arm64.whl"
APPROVED_SHA256 = "8831a3ba52fa7cdb78d368d968b1dcd06171e6dff5461e16d90de91d371e47bc"
APPROVAL_SHA256 = "7641f86e6ef24bbcfc49f32cb3ad33253b581ab49b47aa0658f5b77faeaa7b85"


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _lock() -> dict[str, object]:
    return tomllib.loads(LOCK_PATH.read_text(encoding="utf-8"))


def _lock_tuple_inventory(lock: dict[str, object]) -> list[dict[str, object]]:
    inventory = []
    for package in lock["package"]:
        artifacts = []
        if "sdist" in package:
            artifacts.append(package["sdist"])
        artifacts.extend(package.get("wheels", []))
        inventory.append(
            {
                "name": package["name"],
                "version": package["version"],
                "source": package.get("source"),
                "artifact_hashes": sorted(artifact["hash"] for artifact in artifacts),
            }
        )
    return inventory


def _pyarrow_lock_package() -> dict[str, object]:
    matches = [package for package in _lock()["package"] if package["name"] == "pyarrow"]
    assert len(matches) == 1
    return matches[0]


def test_approval_and_evidence_are_current_canonical_repository_contracts() -> None:
    approval = _json(APPROVAL_PATH)
    evidence = _json(EVIDENCE_PATH)
    digest_payload = dict(approval)
    recorded_digest = digest_payload.pop("approval_sha256")

    assert recorded_digest == _canonical_sha256(digest_payload) == APPROVAL_SHA256
    assert approval["status"] == "APPROVED"
    assert approval["package_spec"] == APPROVED_PACKAGE
    assert approval["selected_artifact_filename"] == APPROVED_FILENAME
    assert approval["selected_artifact_sha256"] == APPROVED_SHA256
    assert approval["dataset_membership_included"] is False
    assert evidence["approval"]["approval_sha256"] == APPROVAL_SHA256
    assert (
        evidence["approval"]["approval_contract_file_sha256"]
        == hashlib.sha256(APPROVAL_PATH.read_bytes()).hexdigest()
    )
    assert evidence["approval"]["reviewer_id"] == approval["reviewer_id"] == "penggin"


def test_current_target_selects_only_the_exact_approved_compatible_lock_wheel() -> None:
    approval = _json(APPROVAL_PATH)
    evidence = _json(EVIDENCE_PATH)
    package = _pyarrow_lock_package()
    supported = frozenset(sys_tags())
    compatible_wheels = []
    for wheel in package["wheels"]:
        filename = Path(urlparse(wheel["url"]).path).name
        _, version, _, wheel_tags = parse_wheel_filename(filename)
        if wheel_tags & supported:
            compatible_wheels.append((filename, str(version), wheel))

    assert str(next(iter(sys_tags()))) == "cp313-cp313-macosx_26_0_arm64"
    assert approval["target_environment"] == evidence["target_environment"]
    assert approval["target_environment_sha256"] == _canonical_sha256(
        approval["target_environment"]
    )
    assert package["version"] == "25.0.0"
    assert package["source"] == {"registry": "https://pypi.org/simple"}
    assert len(compatible_wheels) == 1
    filename, version, selected = compatible_wheels[0]
    assert filename == APPROVED_FILENAME
    assert version == "25.0.0"
    assert selected["hash"] == f"sha256:{APPROVED_SHA256}"
    assert selected["url"] == approval["selected_artifact_url"]
    assert evidence["selected_lock_artifact"] == {
        "filename": filename,
        "sha256": APPROVED_SHA256,
        "size": selected["size"],
        "url": selected["url"],
        "wheel_tags": ["cp313-cp313-macosx_12_0_arm64"],
    }


def test_download_explicit_install_frozen_resolution_and_import_match_approval() -> None:
    evidence = _json(EVIDENCE_PATH)
    downloaded = evidence["downloaded_artifact"]
    installed = evidence["explicit_install"]
    frozen = evidence["frozen_resolution"]

    assert downloaded["filename"] == APPROVED_FILENAME
    assert downloaded["sha256"] == APPROVED_SHA256
    assert downloaded["redirects_followed"] == 0
    assert downloaded["verified_before_use"] is True
    assert installed["source_filename"] == APPROVED_FILENAME
    assert installed["source_sha256"] == APPROVED_SHA256
    assert installed["dependencies_installed"] is False
    assert installed["result"] == "INSTALLED"
    assert frozen == {
        "lock_check": "PASS",
        "offline_no_sync_import": "PASS",
        "sync_frozen_no_python_downloads": "PASS",
    }
    assert evidence["imported_version"] == pyarrow.__version__ == "25.0.0"


def test_only_pyarrow_direct_and_lock_tuple_were_added() -> None:
    evidence = _json(EVIDENCE_PATH)
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    current_direct = sorted(pyproject["project"]["dependencies"])
    inventory = _lock_tuple_inventory(_lock())
    preexisting = [item for item in inventory if item["name"] != "pyarrow"]
    pyarrow_items = [item for item in inventory if item["name"] == "pyarrow"]

    assert evidence["direct_dependencies"]["after"] == current_direct
    assert evidence["direct_dependencies"]["added"] == [APPROVED_PACKAGE]
    assert evidence["direct_dependencies"]["removed"] == []
    assert evidence["direct_dependencies"]["before_sha256"] == _canonical_sha256(
        evidence["direct_dependencies"]["before"]
    )
    assert evidence["direct_dependencies"]["after_sha256"] == _canonical_sha256(current_direct)
    assert evidence["lock"]["before_package_count"] == 42
    assert evidence["lock"]["after_package_count"] == 43
    assert evidence["lock"]["removed"] == []
    assert evidence["lock"]["changed"] == []
    assert evidence["lock"]["added"] == pyarrow_items
    assert evidence["lock"]["before_tuples_sha256"] == _canonical_sha256(preexisting)
    assert evidence["lock"]["after_preexisting_tuples_sha256"] == _canonical_sha256(preexisting)
    assert evidence["lock"]["after_tuples_sha256"] == _canonical_sha256(inventory)
    assert (
        evidence["files"]["pyproject_after_sha256"]
        == hashlib.sha256(PYPROJECT_PATH.read_bytes()).hexdigest()
    )
    assert (
        evidence["files"]["lock_after_sha256"] == hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()
    )
    assert not {
        "fastparquet",
        "pandas",
        "polars",
        "duckdb",
    } & {dependency.split("=", maxsplit=1)[0] for dependency in current_direct}


def test_phase_02_check_consumes_both_repository_owned_supply_chain_contracts() -> None:
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    if "phase-02-check:" not in makefile:
        pytest.skip("Plan 02-03 owns the phase-02-check target")
    assert "02-PYARROW-APPROVAL.json" in makefile
    assert "02-PYARROW-TARGET-EVIDENCE.json" in makefile
