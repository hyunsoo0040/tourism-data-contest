"""Hostile verification for the immutable Plan 38 preflight failure."""

from __future__ import annotations

import builtins
import hashlib
import http.client
import json
import os
import shutil
import socket
import stat
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from itda.cli import collect_catalog_enrichment
from itda.cli.build_catalog_supplemental_evidence import _read_regular
from itda.cli.plan_catalog_remediation import (
    INSUFFICIENT_CONFIRMED_COVERAGE,
    derive_preflight_generation,
    publish_preflight_generation,
)
from itda.contracts import authority
from itda.contracts.catalog_remediation_preflight import (
    ConfirmedCoverageBound,
    TargetMatrix,
    build_confirmed_coverage_bound,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPO_ROOT = Path(__file__).parents[3]
PHASE_DIR = (
    REPO_ROOT
    / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
)
FAILURE_RECORD = PHASE_DIR / "02-38-FAILURE-RECORD.md"
FAILURE_SUMMARY = PHASE_DIR / "02-38-SUMMARY.md"
FAILURE_PLAN = PHASE_DIR / "02-38-PLAN.md"
FAILURE_ROOT_SHA256 = (
    "0082ac8da8fe69492532b7af7b43e27d53f3b9d9ee0bfdbee1487e87ef5019d6"
)
FAILURE_ROUND_ID = (
    "650efdc9364094e3d9bdd7d888d4bd05c462f6fcec4a72b5a64f12cb125da63f"
)
FAILURE_ROOT = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/preflight/rounds"
    / FAILURE_ROOT_SHA256
)
EXPECTED_CHILD_HASHES = {
    "coverage-upper-bound.json": (
        "452df6de6fe0d010b67bd004366f25b4bc28b26afa114cd2164ba177f0c13a10"
    ),
    "official-source-metadata-manifest.json": (
        "0ef6c98bc2716095f979f3c427a2e9dc739293e9931f3120f8aef35263d8a954"
    ),
    "packet-manifest.json": (
        "0e421544cdf387145aaefc8222bbe52a7d1e9d2ac3a0155858ae3a39d8bbabe4"
    ),
    "preflight-state-attestation.json": (
        "711c5d44b23cb3a76f644c241621b8e7e8eceb3b0541139c5e85286cf8d10c8d"
    ),
    "supplemental-round-manifest.json": (
        "6f1e6a63ca41fcdfb312f45768378f503bea3a196aa213e07aef97753aa874ea"
    ),
    "supplemental-target-matrix.json": (
        "5a0d7a9a26f56541f11201780ccf0aec69f2448af61e3dc6c6c54ee09c876371"
    ),
}
EXPECTED_GROUP_COUNTS = {
    "history_culture": 0,
    "history_scenery_boundary": 0,
    "image_modern_content": 0,
    "rest_walk_immersion": 13,
}
FORBIDDEN_GENERATION_CHILDREN = {
    "supplemental-source-plan.json",
    "authority-request.json",
    "authority-token",
    "authority-consumption-receipt.jsonl",
    "catalog.json",
    "split-manifest.json",
    "schema.json",
    "seal.json",
}
FORBIDDEN_DOWNSTREAM_RELPATHS = (
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/"
    "02-38-SUMMARY.md",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/"
    "02-38-PLAN.md",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "supplemental-source-plan.json",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "authority-request.json",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "authority-consumption-receipt.jsonl",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "plan-19-review.json",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "canonical-catalog.json",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "split-manifest.json",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "schema.json",
    "artifacts/restricted/catalog/v2/supplemental/preflight/"
    "seal.json",
)


@dataclass(frozen=True)
class VerifiedFailure:
    """Independently replayed public facts from the exact failure generation."""

    root_sha256: str
    round_id: str
    outcome: str
    exit_code: int
    confirmed_total: int
    confirmed_group_counts: dict[str, int]
    confirmed_capped_sum: int
    unconfirmed_target_count: int


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stable_stat(path: Path) -> tuple[int, int, int, int, int, int]:
    value = os.lstat(path)
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path)
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError(f"non-canonical child: {path.name}")
    return value, raw


def _assert_false(payload: dict[str, Any], *keys: str) -> None:
    for key in keys:
        if payload.get(key) is not False:
            raise ValueError(f"{key} must remain false")


def verify_failure_generation(root: Path) -> VerifiedFailure:
    """Verify the exact immutable failure without trusting caller totals."""

    root_before = _stable_stat(root)
    root_mode = root_before[2]
    if (
        root.name != FAILURE_ROOT_SHA256
        or not stat.S_ISDIR(root_mode)
        or stat.S_IMODE(root_mode) != 0o700
        or root.is_symlink()
    ):
        raise ValueError("failure root identity or mode drifted")

    children = sorted(path.name for path in root.iterdir())
    if children != sorted(EXPECTED_CHILD_HASHES):
        raise ValueError("failure child inventory drifted")
    if FORBIDDEN_GENERATION_CHILDREN.intersection(children):
        raise ValueError("failure generation contains downstream or authority bytes")

    child_before = {name: _stable_stat(root / name) for name in children}
    loaded: dict[str, dict[str, Any]] = {}
    for name in children:
        path = root / name
        mode = child_before[name][2]
        if (
            not stat.S_ISREG(mode)
            or stat.S_IMODE(mode) != 0o600
            or child_before[name][3] != 1
            or path.is_symlink()
        ):
            raise ValueError("failure child type, link count, or mode drifted")
        value, raw = _canonical_object(path)
        if _sha256(raw) != EXPECTED_CHILD_HASHES[name]:
            raise ValueError("failure child digest drifted")
        loaded[name] = value

    packet = loaded["packet-manifest.json"]
    if tuple(packet) != ("payload", "root_sha256"):
        raise ValueError("packet outer shape drifted")
    packet_payload = packet["payload"]
    if not isinstance(packet_payload, dict):
        raise ValueError("packet payload is not an object")
    if (
        packet["root_sha256"] != FAILURE_ROOT_SHA256
        or canonical_sha256(packet_payload) != FAILURE_ROOT_SHA256
        or packet_payload.get("round_id") != FAILURE_ROUND_ID
        or packet_payload.get("publication_state") != "FAILURE"
    ):
        raise ValueError("packet root, round, or failure state drifted")
    packet_children = packet_payload.get("children")
    if not isinstance(packet_children, list):
        raise ValueError("packet child inventory is not a list")
    expected_packet_children = [
        {
            "relpath": name,
            "file_sha256": EXPECTED_CHILD_HASHES[name],
        }
        for name in (
            "official-source-metadata-manifest.json",
            "supplemental-target-matrix.json",
            "coverage-upper-bound.json",
            "preflight-state-attestation.json",
            "supplemental-round-manifest.json",
        )
    ]
    if packet_children != expected_packet_children:
        raise ValueError("packet child inventory or digest order drifted")

    round_manifest = loaded["supplemental-round-manifest.json"]
    if tuple(round_manifest) != ("payload", "root_sha256"):
        raise ValueError("round manifest outer shape drifted")
    round_payload = round_manifest["payload"]
    if not isinstance(round_payload, dict):
        raise ValueError("round payload is not an object")
    if (
        canonical_sha256(round_payload) != round_manifest["root_sha256"]
        or round_payload.get("round_id") != FAILURE_ROUND_ID
        or round_payload.get("outcome") != "INSUFFICIENT_CONFIRMED_COVERAGE"
    ):
        raise ValueError("round digest, ID, or outcome drifted")
    _assert_false(
        round_payload,
        "authorizes_provider_execution",
        "authorizes_import",
        "authority_inherited",
    )

    matrix = TargetMatrix.model_validate(
        loaded["supplemental-target-matrix.json"]
    )
    stored_coverage = ConfirmedCoverageBound.model_validate(
        loaded["coverage-upper-bound.json"]
    )
    replayed_coverage = build_confirmed_coverage_bound(
        matrix=matrix,
        repo_root=REPO_ROOT,
    )
    if replayed_coverage != stored_coverage:
        raise ValueError("coverage facts do not replay from exact target rows")
    if (
        len(matrix.rows) != 24
        or stored_coverage.confirmed_target_count != 0
        or stored_coverage.confirmed_projected_total != 13
        or stored_coverage.confirmed_group_counts != EXPECTED_GROUP_COUNTS
        or stored_coverage.confirmed_capped_sum != 12
        or stored_coverage.outcome != "INSUFFICIENT_CONFIRMED_COVERAGE"
        or stored_coverage.representation_feasible
        or any(stored_coverage.target_serviceability)
    ):
        raise ValueError("row-derived failure facts drifted")

    state = loaded["preflight-state-attestation.json"]
    if (
        state.get("outcome") != "INSUFFICIENT_CONFIRMED_COVERAGE"
        or state.get("network_state") != "NETWORK_DISABLED"
        or state.get("external_data_bytes_obtained") != 0
        or state.get("confirmed_total") != stored_coverage.confirmed_projected_total
        or state.get("confirmed_group_counts")
        != stored_coverage.confirmed_group_counts
        or state.get("confirmed_capped_sum")
        != stored_coverage.confirmed_capped_sum
        or state.get("target_deficit_serviceability")
        != list(stored_coverage.target_serviceability)
        or state.get("source_plan_published") is not False
    ):
        raise ValueError("state attestation does not match replayed failure")
    _assert_false(
        state,
        "authority_issued_or_consumed",
        "authority_inherited",
        "authorizes_provider_execution",
        "authorizes_import",
        "plan39_reachable",
        "canonical_membership_created",
        "split_membership_created",
        "schema_artifact_created",
        "seal_artifact_created",
    )

    if _stable_stat(root) != root_before:
        raise ValueError("failure root changed during verification")
    if any(_stable_stat(root / name) != child_before[name] for name in children):
        raise ValueError("failure child changed during verification")

    return VerifiedFailure(
        root_sha256=FAILURE_ROOT_SHA256,
        round_id=FAILURE_ROUND_ID,
        outcome=stored_coverage.outcome,
        exit_code=INSUFFICIENT_CONFIRMED_COVERAGE,
        confirmed_total=stored_coverage.confirmed_projected_total,
        confirmed_group_counts=dict(stored_coverage.confirmed_group_counts),
        confirmed_capped_sum=stored_coverage.confirmed_capped_sum,
        unconfirmed_target_count=sum(
            not value for value in stored_coverage.target_serviceability
        ),
    )


def assert_no_failure_successor_bytes(repo_root: Path) -> None:
    """Reject a synthetic Summary/PLAN or any Plan 38 downstream output."""

    for relpath in FORBIDDEN_DOWNSTREAM_RELPATHS:
        if (repo_root / relpath).exists() or (repo_root / relpath).is_symlink():
            raise ValueError(f"forbidden Plan 38 successor byte exists: {relpath}")


def _copy_generation(tmp_path: Path, *, basename: str = FAILURE_ROOT_SHA256) -> Path:
    destination = tmp_path / basename
    shutil.copytree(FAILURE_ROOT, destination)
    os.chmod(destination, 0o700)
    for child in destination.iterdir():
        os.chmod(child, 0o600)
    return destination


def test_exact_historical_failure_is_replayed_from_immutable_children() -> None:
    result = verify_failure_generation(FAILURE_ROOT)

    assert result == VerifiedFailure(
        root_sha256=FAILURE_ROOT_SHA256,
        round_id=FAILURE_ROUND_ID,
        outcome="INSUFFICIENT_CONFIRMED_COVERAGE",
        exit_code=24,
        confirmed_total=13,
        confirmed_group_counts=EXPECTED_GROUP_COUNTS,
        confirmed_capped_sum=12,
        unconfirmed_target_count=24,
    )
    assert FAILURE_RECORD.is_file()
    assert_no_failure_successor_bytes(REPO_ROOT)


def test_derivation_traps_network_credentials_authority_and_nonce_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network, credential, authority, or nonce use attempted")

    real_os_open = os.open
    real_builtin_open = builtins.open

    def guarded_os_open(path: object, *args: object, **kwargs: object) -> int:
        lowered = os.fspath(path).lower()
        if any(token in lowered for token in ("credential", "service-key", "api-key")):
            raise AssertionError("credential-file open attempted")
        return real_os_open(path, *args, **kwargs)

    def guarded_builtin_open(
        path: object, *args: object, **kwargs: object
    ) -> Any:
        lowered = os.fspath(path).lower()
        if any(token in lowered for token in ("credential", "service-key", "api-key")):
            raise AssertionError("credential-file open attempted")
        return real_builtin_open(path, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(http.client, "HTTPConnection", blocked)
    monkeypatch.setattr(http.client, "HTTPSConnection", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(httpx, "request", blocked)
    monkeypatch.setattr(httpx, "Client", blocked)
    monkeypatch.setattr(httpx, "AsyncClient", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(subprocess, "check_output", blocked)
    monkeypatch.setattr(authority, "validate_authority_token", blocked)
    monkeypatch.setattr(
        authority.FileNonceLedger,
        "consume_with_mutation",
        blocked,
    )
    monkeypatch.setattr(collect_catalog_enrichment, "_consume_authority", blocked)
    monkeypatch.setattr(os, "open", guarded_os_open)
    monkeypatch.setattr(builtins, "open", guarded_builtin_open)

    first = derive_preflight_generation(REPO_ROOT)
    second = derive_preflight_generation(REPO_ROOT)

    assert first.exit_code == second.exit_code == 24
    assert first.packet_root == second.packet_root == FAILURE_ROOT_SHA256
    assert first.children == second.children
    assert first.state["external_data_bytes_obtained"] == 0
    assert first.state["authority_issued_or_consumed"] is False


@pytest.mark.parametrize("mode", (0o755, 0o750, 0o777))
def test_root_mode_drift_is_rejected(tmp_path: Path, mode: int) -> None:
    copied = _copy_generation(tmp_path)
    os.chmod(copied, mode)
    with pytest.raises(ValueError, match="root identity or mode"):
        verify_failure_generation(copied)


@pytest.mark.parametrize("mode", (0o644, 0o640, 0o400))
def test_child_mode_drift_is_rejected(tmp_path: Path, mode: int) -> None:
    copied = _copy_generation(tmp_path)
    os.chmod(copied / "coverage-upper-bound.json", mode)
    with pytest.raises(ValueError, match="type, link count, or mode"):
        verify_failure_generation(copied)


def test_symlink_and_hardlink_substitution_are_rejected(tmp_path: Path) -> None:
    linked = _copy_generation(tmp_path / "symlink")
    target = linked / "coverage-upper-bound.json"
    target.unlink()
    target.symlink_to(FAILURE_ROOT / target.name)
    with pytest.raises(ValueError, match="type, link count, or mode"):
        verify_failure_generation(linked)

    hardlinked = _copy_generation(tmp_path / "hardlink")
    target = hardlinked / "coverage-upper-bound.json"
    target.unlink()
    os.link(hardlinked / "packet-manifest.json", target)
    with pytest.raises(ValueError, match="type, link count, or mode"):
        verify_failure_generation(hardlinked)


def test_missing_extra_and_source_plan_children_are_rejected(tmp_path: Path) -> None:
    missing = _copy_generation(tmp_path / "missing")
    (missing / "coverage-upper-bound.json").unlink()
    with pytest.raises(ValueError, match="child inventory"):
        verify_failure_generation(missing)

    extra = _copy_generation(tmp_path / "extra")
    injected = extra / "supplemental-source-plan.json"
    injected.write_bytes(b"{}")
    os.chmod(injected, 0o600)
    with pytest.raises(ValueError, match="child inventory"):
        verify_failure_generation(extra)


def test_root_basename_and_canonical_child_tampering_are_rejected(
    tmp_path: Path,
) -> None:
    renamed = _copy_generation(tmp_path / "renamed", basename="f" * 64)
    with pytest.raises(ValueError, match="root identity or mode"):
        verify_failure_generation(renamed)

    tampered = _copy_generation(tmp_path / "tampered")
    path = tampered / "preflight-state-attestation.json"
    value = json.loads(path.read_bytes())
    value["plan39_reachable"] = True
    path.write_bytes(canonical_json_bytes(value))
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="child digest"):
        verify_failure_generation(tampered)


def test_summary_plan_authority_and_downstream_injection_are_rejected(
    tmp_path: Path,
) -> None:
    assert_no_failure_successor_bytes(tmp_path)
    for relpath in FORBIDDEN_DOWNSTREAM_RELPATHS:
        injected = tmp_path / relpath
        injected.parent.mkdir(parents=True, exist_ok=True)
        injected.write_bytes(b"forbidden")
        with pytest.raises(ValueError, match="forbidden Plan 38 successor"):
            assert_no_failure_successor_bytes(tmp_path)
        injected.unlink()


def test_failure_publication_is_no_replace_and_creates_no_downstream_bytes(
    tmp_path: Path,
) -> None:
    generation = derive_preflight_generation(REPO_ROOT)
    output_base = tmp_path / "preflight"
    published = publish_preflight_generation(
        generation,
        output_base=output_base,
    )

    assert published == output_base / "rounds" / FAILURE_ROOT_SHA256
    assert verify_failure_generation(published).exit_code == 24
    with pytest.raises(FileExistsError):
        publish_preflight_generation(generation, output_base=output_base)
    assert sorted(
        path.name for path in (output_base / "rounds").iterdir()
    ) == [FAILURE_ROOT_SHA256]
    assert not any(
        (output_base / name).exists() for name in FORBIDDEN_GENERATION_CHILDREN
    )
