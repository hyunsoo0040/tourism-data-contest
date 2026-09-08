"""Clean-checkout verification for the promoted Phase 4 demo chain."""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import stat
from pathlib import Path
from typing import Any, cast

import pytest

from itda.cli.manage_phase4_staged_chain import runtime_versions
from itda.contracts.phase4_demo import (
    Phase4DemoMaterializationReceipt,
    Phase4DemoPredictionReceipt,
    Phase4DemoTerminalReceipt,
)
from itda.db.phase4_demo_release import Phase4DemoReleaseRepository
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PUBLIC_ROOT = REPOSITORY_ROOT / "artifacts/public/catalog/v2"
EXPECTED_RED_MARKER = "CR-10_STALE_INVALID_CHAIN"
RECEIPT_MODELS: dict[str, type[Any] | None] = {
    "phase4-demo-materialization-receipt.json": Phase4DemoMaterializationReceipt,
    "phase4-demo-prediction-receipt.json": Phase4DemoPredictionReceipt,
    "phase4-demo-terminal-receipt.json": Phase4DemoTerminalReceipt,
    "phase4-demo-release-receipt.json": None,
}
PROOF_NAME = "phase4-demo-chain-proof.json"
TRUTH_FIELDS = (
    "source_truth",
    "profile_truth",
    "profile_score_truth",
    "image_truth",
)
EXPECTED_TOOLCHAIN_PATHS = (
    "backend/src/itda/cli/manage_phase4_staged_chain.py",
    "backend/src/itda/cli/run_phase4_demo.py",
    "backend/src/itda/contracts/phase4_demo.py",
    "backend/src/itda/db/phase4_demo_release.py",
    "backend/tests/security/test_phase4_checked_artifact_chain.py",
    "backend/uv.lock",
    "mise.toml",
)
EXPECTED_SCHEMA_VERSIONS = {
    "chain_proof": "itda.phase4-demo-chain-proof.v1",
    "materialization": "itda.phase4-demo-materialization-receipt.v2",
    "prediction": "itda.phase4-demo-prediction-receipt.v1",
    "release": "itda.phase4-demo-release-final-receipt.v1",
    "terminal": "itda.phase4-demo-terminal-receipt.v1",
}
MAX_TOOLCHAIN_BYTES = 32 * 1024 * 1024
EXPECTED_AUTHORITY_SHA256 = "0dfa371289ba55ca14d99632915c3948269d7811645a759b618fed1957bfd3cc"
EXPECTED_DEV_MEMBERSHIP_SHA256 = "979127c3cfd457fa0a9354acf7fd984c8d8b4d753a97c7c176ac531e0808af7a"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _guard_restricted_opens(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    observed: list[str] = []

    def reject(value: object) -> None:
        text = os.fspath(value) if isinstance(value, (str, os.PathLike)) else ""
        if "artifacts/restricted" in text.replace("\\", "/"):
            observed.append(text)
            raise AssertionError("tracked-safe verification opened restricted evidence")

    original_builtin_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open

    def guarded_builtin_open(file: object, *args: object, **kwargs: object) -> Any:
        reject(file)
        return original_builtin_open(file, *args, **kwargs)

    def guarded_io_open(file: object, *args: object, **kwargs: object) -> Any:
        reject(file)
        return original_io_open(file, *args, **kwargs)

    def guarded_os_open(path: object, *args: object, **kwargs: object) -> int:
        reject(path)
        return original_os_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_builtin_open)
    monkeypatch.setattr(io, "open", guarded_io_open)
    monkeypatch.setattr(os, "open", guarded_os_open)
    return observed


def _canonical_mapping(raw: bytes) -> dict[str, object]:
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    assert raw == canonical_json_bytes(parsed)
    return cast(dict[str, object], parsed)


def _read_tracked_regular_nofollow(root: Path, logical_path: str) -> bytes:
    components = Path(logical_path).parts
    if (
        not components
        or Path(logical_path).is_absolute()
        or any(component in {"", ".", ".."} for component in components)
    ):
        raise ValueError("proof toolchain path is not a safe repository-relative path")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("no-follow reads are unavailable")
    descriptors = [
        os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | nofollow | getattr(os, "O_CLOEXEC", 0),
        )
    ]
    try:
        for component in components[:-1]:
            descriptors.append(
                os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | nofollow | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=descriptors[-1],
                )
            )
        descriptor = os.open(
            components[-1],
            os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=descriptors[-1],
        )
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("proof toolchain entry is not a single-link regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_TOOLCHAIN_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_TOOLCHAIN_BYTES:
                raise ValueError("proof toolchain entry exceeds its byte limit")
        after = os.fstat(descriptor)
        signature = lambda value: (  # noqa: E731
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if signature(before) != signature(after):
            raise ValueError("proof toolchain entry changed during verification")
        return b"".join(chunks)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _verify_proof_toolchain(proof: dict[str, object], root: Path) -> None:
    rows = cast(list[dict[str, object]], proof["toolchain"])
    assert [row.get("logical_path") for row in rows] == list(EXPECTED_TOOLCHAIN_PATHS)
    assert all(set(row) == {"logical_path", "byte_sha256"} for row in rows)
    for row, logical_path in zip(rows, EXPECTED_TOOLCHAIN_PATHS, strict=True):
        try:
            raw = _read_tracked_regular_nofollow(root, logical_path)
        except OSError as exc:
            raise OSError(f"toolchain path rejected: {logical_path}") from exc
        assert row["byte_sha256"] == _sha256(raw), f"toolchain digest mismatch: {logical_path}"
    assert proof["schema_versions"] == EXPECTED_SCHEMA_VERSIONS
    runtime = runtime_versions()
    assert proof["runtime"] == runtime
    assert proof["runtime_sha256"] == canonical_sha256(runtime)


def test_tracked_safe_phase4_demo_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    observed = _guard_restricted_opens(monkeypatch)
    paths = [PUBLIC_ROOT / name for name in (*RECEIPT_MODELS, PROOF_NAME)]
    if any(not path.is_file() or path.is_symlink() for path in paths):
        print(EXPECTED_RED_MARKER)
        pytest.fail("current public chain is incomplete or stale", pytrace=False)

    raw_by_name = {path.name: path.read_bytes() for path in paths}
    try:
        materialization = Phase4DemoMaterializationReceipt.model_validate_json(
            raw_by_name["phase4-demo-materialization-receipt.json"]
        )
    except ValueError:
        print(EXPECTED_RED_MARKER)
        pytest.fail("current public materialization receipt is stale", pytrace=False)

    receipts: dict[str, dict[str, object]] = {}
    for name, model in RECEIPT_MODELS.items():
        raw = raw_by_name[name]
        if model is None:
            payload = _canonical_mapping(raw)
            Phase4DemoReleaseRepository.validate_local_receipt(payload)
        else:
            value = model.model_validate_json(raw)
            payload = cast(dict[str, object], value.model_dump(mode="json"))
            assert raw == canonical_json_bytes(payload)
        receipts[name] = payload

    proof = _canonical_mapping(raw_by_name[PROOF_NAME])
    assert proof["schema_version"] == "itda.phase4-demo-chain-proof.v1"
    assert proof["proof_sha256"] == canonical_sha256(
        {key: value for key, value in proof.items() if key != "proof_sha256"}
    )
    assert proof["manifest_sha256"] == materialization.manifest_sha256
    assert proof["authority_sha256"] == EXPECTED_AUTHORITY_SHA256
    assert proof["dev_membership_sha256"] == EXPECTED_DEV_MEMBERSHIP_SHA256
    promotion_binding = cast(dict[str, object], proof["promotion_binding"])
    assert proof["promotion_binding_sha256"] == canonical_sha256(promotion_binding)
    for field in (
        "authority_sha256",
        "dev_membership_sha256",
        "manifest_sha256",
        "manifest_input_inventory_sha256",
        "manifest_snapshot_inventory_sha256",
        "manifest_dev_projection_sha256",
        "manifest_selected_image_inventory_sha256",
        "private_parent_inventory_sha256",
        "database_sha256",
    ):
        assert proof[field] == promotion_binding[field]
    expected_truth = {
        "source_truth": "LOCAL_COLLECTION_AUTHORITY_PARTIAL",
        "profile_truth": "SOURCE_EVIDENCE_ONLY",
        "profile_score_truth": "NO_LOCAL_PROFILE_SCORES",
        "provider_mode": "NO_PROVIDER_NO_IMAGE",
        "image_truth": "NO_IMAGE_TEXT_ODII_ONLY",
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    assert proof["truth"] == expected_truth
    _verify_proof_toolchain(proof, REPOSITORY_ROOT)

    proof_receipts = cast(list[dict[str, object]], proof["receipts"])
    assert [row["logical_path"] for row in proof_receipts] == [
        f"artifacts/public/catalog/v2/{name}" for name in RECEIPT_MODELS
    ]
    assert len(proof_receipts) == 4
    for row in proof_receipts:
        name = Path(cast(str, row["logical_path"])).name
        payload = receipts[name]
        assert row["byte_sha256"] == _sha256(raw_by_name[name])
        assert row["receipt_sha256"] == payload["receipt_sha256"]
        assert payload["manifest_sha256"] == materialization.manifest_sha256
        for field in TRUTH_FIELDS:
            assert payload[field] == expected_truth[field]

    prediction = receipts["phase4-demo-prediction-receipt.json"]
    terminal = receipts["phase4-demo-terminal-receipt.json"]
    release = receipts["phase4-demo-release-receipt.json"]
    assert (
        prediction["provider_mode"] == terminal["provider_mode"] == expected_truth["provider_mode"]
    )
    assert (
        prediction["benchmark_truth"]
        == terminal["benchmark_truth"]
        == expected_truth["benchmark_truth"]
    )
    assert release["provider_mode"] == expected_truth["provider_mode"]
    assert release["terminal_decision"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert release["production_mutation"] == "NO_PRODUCTION_MUTATION"

    serialized = raw_by_name[PROOF_NAME].lower()
    for forbidden in (
        b"artifacts/restricted",
        b"database_path",
        b"raw_image",
        b"service_key",
        b"postgresql://",
        b"zhipu",
        b"label_input",
    ):
        assert forbidden not in serialized
    assert observed == []


@pytest.mark.parametrize("logical_path", EXPECTED_TOOLCHAIN_PATHS)
@pytest.mark.parametrize("attack", ["byte-mutation", "symlink-substitution"])
def test_proof_toolchain_rejects_current_file_substitution(
    tmp_path: Path, attack: str, logical_path: str
) -> None:
    proof = _canonical_mapping((PUBLIC_ROOT / PROOF_NAME).read_bytes())
    for setup_logical_path in EXPECTED_TOOLCHAIN_PATHS:
        target = tmp_path / setup_logical_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY_ROOT / setup_logical_path).read_bytes())
    _verify_proof_toolchain(proof, tmp_path)

    attacked = tmp_path / logical_path
    assert attacked.relative_to(tmp_path).as_posix() == logical_path
    if attack == "byte-mutation":
        attacked.write_bytes(attacked.read_bytes() + b"\n")
        with pytest.raises(AssertionError) as caught:
            _verify_proof_toolchain(proof, tmp_path)
        assert logical_path in str(caught.value)
    else:
        replacement = tmp_path / "replacement.py"
        replacement.write_bytes(attacked.read_bytes())
        attacked.unlink()
        attacked.symlink_to(replacement)
        with pytest.raises(OSError) as caught:
            _verify_proof_toolchain(proof, tmp_path)
        assert logical_path in str(caught.value)


@pytest.mark.parametrize("runtime_field", ["mise", "pydantic", "python", "sqlalchemy", "uv"])
def test_proof_toolchain_rejects_runtime_substitution(tmp_path: Path, runtime_field: str) -> None:
    proof = _canonical_mapping((PUBLIC_ROOT / PROOF_NAME).read_bytes())
    for logical_path in EXPECTED_TOOLCHAIN_PATHS:
        target = tmp_path / logical_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY_ROOT / logical_path).read_bytes())
    runtime = cast(dict[str, str], proof["runtime"])
    proof["runtime"] = {**runtime, runtime_field: "0.0.0-hostile"}
    proof["runtime_sha256"] = canonical_sha256(proof["runtime"])
    with pytest.raises(AssertionError):
        _verify_proof_toolchain(proof, tmp_path)


def test_proof_toolchain_rejects_runtime_digest_substitution(tmp_path: Path) -> None:
    proof = _canonical_mapping((PUBLIC_ROOT / PROOF_NAME).read_bytes())
    for logical_path in EXPECTED_TOOLCHAIN_PATHS:
        target = tmp_path / logical_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY_ROOT / logical_path).read_bytes())
    proof["runtime_sha256"] = "0" * 64
    with pytest.raises(AssertionError):
        _verify_proof_toolchain(proof, tmp_path)
