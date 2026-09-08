"""Opt-in verification of the repository-fixed private Phase 4 parents."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import cast

import pytest

from itda.cli import manage_phase4_staged_chain as staged

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PUBLIC_PROOF = REPOSITORY_ROOT / "artifacts/public/catalog/v2/phase4-demo-chain-proof.json"
PRIVATE_OUTPUTS = (
    staged.PRIVATE_DATABASE_COPY,
    staged.PRIVATE_PARENT_INVENTORY,
    staged.PRIVATE_HANDOFF,
)
EXPECTED_FIXED_PATHS = (
    "artifacts/restricted/catalog/v2/phase4-demo-regeneration/"
    "04-20-review-fix-v2-20260808/release/"
    "phase4-demo-release.sqlite3",
    "artifacts/restricted/catalog/v2/phase4-demo-regeneration/"
    "04-20-review-fix-v2-20260808/private-parent-inventory.json",
    "artifacts/restricted/catalog/v2/phase4-demo-regeneration/"
    "04-20-review-fix-v2-20260808/regeneration-handoff.json",
)


def _relative(path: Path) -> str:
    return path.relative_to(REPOSITORY_ROOT).as_posix()


def _facts(path: Path) -> tuple[int, int, int, int, int, int, int, str]:
    value = path.lstat()
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        staged._sha256(staged._stable_read(path, max_bytes=staged.MAX_SQLITE_BYTES)),
    )


def _directory_facts(root: Path) -> tuple[tuple[str, int, int, int, int, int, int, int], ...]:
    rows = []
    for path in sorted((root, *root.rglob("*")), key=lambda value: value.as_posix()):
        value = path.lstat()
        rows.append(
            (
                path.relative_to(root).as_posix(),
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
        )
    return tuple(rows)


@pytest.fixture(autouse=True)
def require_explicit_private_evidence() -> None:
    if os.environ.get("ITDA_PHASE4_PRIVATE_EVIDENCE") != "1":
        pytest.fail("PRIVATE_EVIDENCE_NOT_PROVISIONED: opt-in flag is absent", pytrace=False)
    required = (
        staged.AUTHORITY_RECEIPT,
        staged.ZERO_IMAGE_REGISTRY,
        staged.STAGED_RECEIPT_ROOT,
        staged.PRIVATE_DATABASE_COPY,
        staged.PRIVATE_PARENT_INVENTORY,
        staged.PRIVATE_HANDOFF,
    )
    if any(not path.exists() or path.is_symlink() for path in required):
        pytest.fail("PRIVATE_EVIDENCE_NOT_PROVISIONED: fixed parent is absent", pytrace=False)


def _read_cli_result(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    assert staged.main(["verify-private"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert isinstance(result, dict)
    return cast(dict[str, object], result)


def test_fixed_private_chain_is_repeatable_and_read_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert tuple(_relative(path) for path in PRIVATE_OUTPUTS) == EXPECTED_FIXED_PATHS
    assert all(path.is_file() and not path.is_symlink() for path in PRIVATE_OUTPUTS)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in PRIVATE_OUTPUTS)

    public_proof = staged._canonical_mapping(PUBLIC_PROOF.read_bytes())
    private_handoff = staged._canonical_mapping(staged.PRIVATE_HANDOFF.read_bytes())
    private_inventory = staged._canonical_mapping(staged.PRIVATE_PARENT_INVENTORY.read_bytes())
    authority_raw = staged._stable_read(staged.AUTHORITY_RECEIPT)
    assert private_handoff["authority_receipt_sha256"] == staged._sha256(authority_raw)
    assert private_inventory["authority_receipt_sha256"] == staged._sha256(authority_raw)
    assert private_handoff["private_parent_inventory_sha256"] == staged._sha256(
        staged.PRIVATE_PARENT_INVENTORY.read_bytes()
    )

    before_outputs = tuple(_facts(path) for path in PRIVATE_OUTPUTS)
    before_tree = _directory_facts(staged.STAGE_ROOT)
    first = _read_cli_result(capsys)
    middle_outputs = tuple(_facts(path) for path in PRIVATE_OUTPUTS)
    middle_tree = _directory_facts(staged.STAGE_ROOT)
    second = _read_cli_result(capsys)
    after_outputs = tuple(_facts(path) for path in PRIVATE_OUTPUTS)
    after_tree = _directory_facts(staged.STAGE_ROOT)

    assert (
        first
        == second
        == {
            "disposition": "ALREADY_VERIFIED",
            "handoff_sha256": public_proof["handoff_sha256"],
        }
    )
    assert private_handoff["handoff_sha256"] == public_proof["handoff_sha256"]
    assert before_outputs == middle_outputs == after_outputs
    assert before_tree == middle_tree == after_tree


def _redirect_outputs(monkeypatch: pytest.MonkeyPatch, root: Path) -> tuple[Path, ...]:
    outputs = (
        root / "release/phase4-demo-release.sqlite3",
        root / "private-parent-inventory.json",
        root / "regeneration-handoff.json",
    )
    monkeypatch.setattr(staged, "PRIVATE_DATABASE_COPY", outputs[0])
    monkeypatch.setattr(staged, "PRIVATE_PARENT_INVENTORY", outputs[1])
    monkeypatch.setattr(staged, "PRIVATE_HANDOFF", outputs[2])
    return outputs


def test_partial_private_outputs_fail_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixed_handoff_raw = PRIVATE_OUTPUTS[2].read_bytes()
    outputs = _redirect_outputs(monkeypatch, tmp_path / "partial")
    outputs[2].parent.mkdir(parents=True)
    outputs[2].write_bytes(fixed_handoff_raw)
    before = _facts(outputs[2])

    with pytest.raises(staged.StagedChainError, match="partial"):
        staged.verify_private()

    assert _facts(outputs[2]) == before
    assert sum(path.exists() for path in outputs) == 1


def test_conflicting_private_outputs_fail_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    outputs = _redirect_outputs(monkeypatch, tmp_path / "conflict")
    assert staged.verify_private()["disposition"] == "CREATED"
    payload = bytearray(outputs[1].read_bytes())
    payload[-2] ^= 1
    outputs[1].write_bytes(payload)
    before = tuple(_facts(path) for path in outputs)

    with pytest.raises(staged.StagedChainError, match="conflict"):
        staged.verify_private()

    assert tuple(_facts(path) for path in outputs) == before
