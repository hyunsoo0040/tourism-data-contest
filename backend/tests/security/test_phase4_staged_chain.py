"""Private verification and atomic promotion contracts for Phase 4."""

from __future__ import annotations

import fcntl
import inspect
import json
import multiprocessing
import os
from pathlib import Path
from typing import Any

import pytest

from itda.cli import manage_phase4_staged_chain as staged
from itda.contracts.phase4_demo import (
    Phase4DemoInputAuthority,
    Phase4DemoZeroImageAbsenceRegistry,
)


def _private_outputs(root: Path) -> tuple[Path, Path, Path]:
    return (
        root / "release/phase4-demo-release.sqlite3",
        root / "private-parent-inventory.json",
        root / "regeneration-handoff.json",
    )


def _redirect_private_outputs(monkeypatch: pytest.MonkeyPatch, root: Path) -> tuple[Path, ...]:
    outputs = _private_outputs(root)
    monkeypatch.setattr(staged, "PRIVATE_DATABASE_COPY", outputs[0])
    monkeypatch.setattr(staged, "PRIVATE_PARENT_INVENTORY", outputs[1])
    monkeypatch.setattr(staged, "PRIVATE_HANDOFF", outputs[2])
    return outputs


def _facts(path: Path) -> tuple[int, int, int, int, int, str]:
    value = path.stat()
    return (
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        staged._sha256(path.read_bytes()),
    )


def test_fixed_inputs_are_caller_path_free() -> None:
    assert tuple(inspect.signature(staged.verify_private).parameters) == ()
    assert tuple(inspect.signature(staged.promote).parameters) == ()
    with pytest.raises(SystemExit):
        staged.build_parser().parse_args(["verify-private", "--stage", "/tmp/alternate"])
    with pytest.raises(SystemExit):
        staged.build_parser().parse_args(["promote", "--handoff", "0" * 64])


def test_private_stage_first_creation_and_regeneration_handoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    outputs = _redirect_private_outputs(monkeypatch, tmp_path / "private")
    result = staged.verify_private()
    assert result["disposition"] == "CREATED"
    assert all(path.is_file() and not path.is_symlink() for path in outputs)
    assert outputs[0].stat().st_mode & 0o777 == 0o600
    assert outputs[1].stat().st_mode & 0o777 == 0o600
    assert outputs[2].stat().st_mode & 0o777 == 0o600
    handoff = staged._canonical_mapping(outputs[2].read_bytes())
    assert handoff["schema_version"] == "itda.phase4-demo-regeneration-handoff.v1"
    assert handoff["database_sha256"] == staged._sha256(outputs[0].read_bytes())
    assert handoff["promotion_binding_sha256"] == staged.canonical_sha256(
        handoff["promotion_binding"]
    )
    assert len(handoff["candidate_public_receipts"]) == 4
    assert len(handoff["intended_public_paths"]) == 5
    assert "checkout_head" not in handoff
    assert "created_at" not in handoff


def test_private_stage_exact_rerun_is_read_only_after_unrelated_head_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    outputs = _redirect_private_outputs(monkeypatch, tmp_path / "private")
    staged.verify_private()
    before = tuple(_facts(path) for path in outputs)
    result = staged.verify_private()
    after = tuple(_facts(path) for path in outputs)
    assert result["disposition"] == "ALREADY_VERIFIED"
    assert after == before


@pytest.mark.parametrize("existing_index", [0, 1, 2])
def test_private_stage_rejects_partial_output_without_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, existing_index: int
) -> None:
    outputs = _redirect_private_outputs(monkeypatch, tmp_path / "private")
    outputs[existing_index].parent.mkdir(parents=True, exist_ok=True)
    outputs[existing_index].write_bytes(b"partial")
    before = outputs[existing_index].read_bytes()
    with pytest.raises(staged.StagedChainError, match="partial"):
        staged.verify_private()
    assert outputs[existing_index].read_bytes() == before
    assert sum(path.exists() for path in outputs) == 1


def test_private_stage_rejects_one_byte_conflict_without_rewriting_siblings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    outputs = _redirect_private_outputs(monkeypatch, tmp_path / "private")
    staged.verify_private()
    inventory = bytearray(outputs[1].read_bytes())
    inventory[-2] ^= 1
    outputs[1].write_bytes(inventory)
    before = tuple(path.read_bytes() for path in outputs)
    with pytest.raises(staged.StagedChainError, match="conflict"):
        staged.verify_private()
    assert tuple(path.read_bytes() for path in outputs) == before


def test_private_stage_rejects_symlink_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    outputs = _redirect_private_outputs(monkeypatch, tmp_path / "private")
    outputs[0].parent.mkdir(parents=True)
    outputs[0].symlink_to(Path(os.devnull))
    with pytest.raises(staged.StagedChainError, match="partial|unsafe"):
        staged.verify_private()


def test_coherent_alternate_dev_authority_cannot_derive_or_promote(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    authority_payload = json.loads(staged.AUTHORITY_RECEIPT.read_bytes())
    registry_payload = json.loads(staged.ZERO_IMAGE_REGISTRY.read_bytes())
    alternate_ref = f"place:{'f' * 64}"
    alternate_refs = sorted([*authority_payload["dev_place_refs"][1:], alternate_ref])
    authority_payload["dev_place_refs"] = alternate_refs
    authority_payload["dev_membership_sha256"] = staged.canonical_sha256(alternate_refs)
    authority_payload["authority_sha256"] = None
    registry_payload["members"] = [
        {"place_ref": place_ref, "status": "NO_IMAGE"} for place_ref in alternate_refs
    ]
    registry_payload["registry_sha256"] = None
    registry = Phase4DemoZeroImageAbsenceRegistry.model_validate(registry_payload)
    authority_payload["zero_image_absence_registry_sha256"] = registry.registry_sha256
    authority = Phase4DemoInputAuthority.model_validate(authority_payload)

    authority_path = tmp_path / "input-authority.json"
    registry_path = tmp_path / "zero-image-absence-registry.json"
    authority_path.write_bytes(staged.canonical_json_bytes(authority.model_dump(mode="json")))
    registry_path.write_bytes(staged.canonical_json_bytes(registry.model_dump(mode="json")))
    monkeypatch.setattr(staged, "AUTHORITY_RECEIPT", authority_path)
    monkeypatch.setattr(staged, "ZERO_IMAGE_REGISTRY", registry_path)
    private_outputs = _redirect_private_outputs(monkeypatch, tmp_path / "private")
    public_root = _redirect_public_root(monkeypatch, tmp_path / "public")
    old_public = _seed_old_public(public_root)

    with pytest.raises(staged.StagedChainError, match="repository-fixed authority"):
        staged.verify_private()
    with pytest.raises(staged.StagedChainError, match="repository-fixed authority"):
        staged.promote()

    assert not any(path.exists() or path.is_symlink() for path in private_outputs)
    assert tuple((public_root / name).read_bytes() for name in staged.PUBLIC_RECEIPT_NAMES) == (
        old_public
    )
    assert not (public_root / staged.PUBLIC_PROOF_NAME).exists()


def _redirect_public_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    monkeypatch.setattr(staged, "PUBLIC_ROOT", root)
    return root


def _prepare_promotion_roots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    _redirect_private_outputs(monkeypatch, tmp_path / "private")
    staged.verify_private()
    return _redirect_public_root(monkeypatch, tmp_path / "public")


def _seed_old_public(root: Path) -> tuple[bytes, ...]:
    root.mkdir(parents=True)
    source = staged.REPOSITORY_ROOT / "artifacts/public/catalog/v2"
    old = []
    for name in staged.PUBLIC_RECEIPT_NAMES:
        raw = (source / name).read_bytes()
        (root / name).write_bytes(raw)
        old.append(raw)
    return tuple(old)


def _hold_promotion_lock(lock_path: str, ready: Any, release: Any) -> None:
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        ready.set()
        release.wait(timeout=10)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _attempt_promotion(result: Any) -> None:
    try:
        promoted = staged.promote()
    except staged.StagedChainError as exc:
        result.put(("rejected", str(exc)))
    else:
        result.put(("promoted", promoted["disposition"]))


def _hard_exit_at_promotion_boundary(public_root: str, boundary: str) -> None:
    staged.PUBLIC_ROOT = Path(public_root)
    original_write = staged._write_exclusive
    original_fsync_directory = staged._fsync_directory
    original_replace = staged._replace_for_promotion

    def write_and_maybe_exit(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
        original_write(path, payload, mode=mode)
        if "-journal.tmp" in path.name:
            journal = json.loads(payload)
            if boundary == "after-preparing-journal-write" and journal.get("state") == "PREPARING":
                os._exit(77)
        for index in range(5):
            if boundary == f"after-temp-{index}" and path.name.endswith(f"-staged-{index:02d}.tmp"):
                os._exit(77)
            if boundary == f"after-backup-{index}" and path.name.endswith(
                f"-backup-{index:02d}.bak"
            ):
                os._exit(77)

    def fsync_and_maybe_exit(path: Path) -> None:
        original_fsync_directory(path)
        journal_path = path / staged.PROMOTION_JOURNAL_NAME
        if boundary == "after-committing-journal-durable" and journal_path.is_file():
            journal = json.loads(journal_path.read_bytes())
            if journal.get("state") == "COMMITTING":
                os._exit(77)

    def replace_and_maybe_exit(source: Path, destination: Path) -> None:
        original_replace(source, destination)
        target_names = (*staged.PUBLIC_RECEIPT_NAMES, staged.PUBLIC_PROOF_NAME)
        if destination.name in target_names:
            index = target_names.index(destination.name)
            if boundary == f"after-replace-{index}":
                os._exit(77)

    staged._write_exclusive = write_and_maybe_exit
    staged._fsync_directory = fsync_and_maybe_exit
    staged._replace_for_promotion = replace_and_maybe_exit
    staged.promote()
    os._exit(0)


def test_promotion_publishes_exact_candidate_and_tracked_safe_proof(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    _seed_old_public(public_root)
    result = staged.promote()
    assert result["disposition"] == "PROMOTED"
    for name in staged.PUBLIC_RECEIPT_NAMES:
        assert (public_root / name).read_bytes() == (staged.STAGED_RECEIPT_ROOT / name).read_bytes()
    proof_raw = (public_root / staged.PUBLIC_PROOF_NAME).read_bytes()
    proof = staged._canonical_mapping(proof_raw)
    assert proof["schema_version"] == "itda.phase4-demo-chain-proof.v1"
    assert proof["proof_sha256"] == staged.canonical_sha256(
        {key: value for key, value in proof.items() if key != "proof_sha256"}
    )
    assert proof["handoff_sha256"] == result["handoff_sha256"]
    assert b"artifacts/restricted" not in proof_raw.lower()
    assert (public_root / staged.PROMOTION_LOCK_NAME).is_file()
    assert not (public_root / staged.PROMOTION_JOURNAL_NAME).exists()


def test_promotion_exact_rerun_is_read_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    _seed_old_public(public_root)
    staged.promote()
    output_names = (*staged.PUBLIC_RECEIPT_NAMES, staged.PUBLIC_PROOF_NAME)
    outputs = tuple(public_root / name for name in output_names)
    before = tuple(_facts(path) for path in outputs)
    result = staged.promote()
    after = tuple(_facts(path) for path in outputs)
    assert result["disposition"] == "ALREADY_PROMOTED"
    assert before == after


def test_failed_contender_cannot_unlink_winner_lock_for_third_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    _seed_old_public(public_root)
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    result = context.Queue()
    holder = context.Process(
        target=_hold_promotion_lock,
        args=(str(public_root / staged.PROMOTION_LOCK_NAME), ready, release),
    )
    holder.start()
    try:
        assert ready.wait(timeout=5)
        contenders = [context.Process(target=_attempt_promotion, args=(result,)) for _ in range(2)]
        for contender in contenders:
            contender.start()
            contender.join(timeout=5)
            assert contender.exitcode == 0
            disposition, message = result.get(timeout=2)
            assert disposition == "rejected"
            assert "already held" in message
            assert (public_root / staged.PROMOTION_LOCK_NAME).is_file()
    finally:
        release.set()
        holder.join(timeout=5)
        if holder.is_alive():
            holder.terminate()
            holder.join(timeout=5)
    assert holder.exitcode == 0


def test_promotion_rejects_tampered_handoff_before_public_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    old = _seed_old_public(public_root)
    handoff_path = tmp_path / "regeneration-handoff.json"
    handoff = json.loads(staged.PRIVATE_HANDOFF.read_bytes())
    handoff["database_sha256"] = "0" * 64
    handoff_path.write_bytes(staged.canonical_json_bytes(handoff))
    monkeypatch.setattr(staged, "PRIVATE_HANDOFF", handoff_path)
    with pytest.raises(staged.StagedChainError, match="handoff"):
        staged.promote()
    assert tuple((public_root / name).read_bytes() for name in staged.PUBLIC_RECEIPT_NAMES) == old
    assert not (public_root / staged.PUBLIC_PROOF_NAME).exists()


def test_crash_recovery_restores_complete_old_public_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    old = _seed_old_public(public_root)
    original = staged._replace_for_promotion
    calls = 0

    def fail_once(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("simulated interruption")
        original(source, destination)

    monkeypatch.setattr(staged, "_replace_for_promotion", fail_once)
    with pytest.raises(staged.StagedChainError, match="recovered"):
        staged.promote()
    assert tuple((public_root / name).read_bytes() for name in staged.PUBLIC_RECEIPT_NAMES) == old
    assert not (public_root / staged.PUBLIC_PROOF_NAME).exists()
    assert (public_root / staged.PROMOTION_LOCK_NAME).is_file()
    assert not (public_root / staged.PROMOTION_JOURNAL_NAME).exists()


def test_unjournaled_legacy_artifacts_never_overwrite_valid_winner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    _seed_old_public(public_root)
    staged.promote()
    outputs = tuple(
        public_root / name for name in (*staged.PUBLIC_RECEIPT_NAMES, staged.PUBLIC_PROOF_NAME)
    )
    winner_before = tuple(_facts(path) for path in outputs)
    (public_root / ".phase4-demo-promotion-backup-00").write_bytes(b"stale-old-bytes")
    stale_temp = public_root / ".phase4-demo-promotion-00-stale.tmp"
    stale_temp.symlink_to(outputs[0])

    result = staged.promote()

    assert result["disposition"] == "ALREADY_PROMOTED"
    assert tuple(_facts(path) for path in outputs) == winner_before
    assert not (public_root / ".phase4-demo-promotion-backup-00").exists()
    assert not stale_temp.exists() and not stale_temp.is_symlink()


@pytest.mark.parametrize(
    "boundary",
    [
        "after-preparing-journal-write",
        *(f"after-temp-{index}" for index in range(5)),
        *(f"after-backup-{index}" for index in range(4)),
        "after-committing-journal-durable",
        *(f"after-replace-{index}" for index in range(5)),
    ],
)
def test_hard_exit_recovery_reaches_complete_winner_and_remains_retryable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
) -> None:
    public_root = _prepare_promotion_roots(monkeypatch, tmp_path)
    _seed_old_public(public_root)
    intended = staged._derive_public_outputs(staged._validated_private_handoff())
    context = multiprocessing.get_context("fork")
    crashed = context.Process(
        target=_hard_exit_at_promotion_boundary,
        args=(str(public_root), boundary),
    )
    crashed.start()
    crashed.join(timeout=10)
    if crashed.is_alive():
        crashed.terminate()
        crashed.join(timeout=5)
        pytest.fail(f"promotion crash probe hung at {boundary}")
    assert crashed.exitcode == 77

    result = context.Queue()
    recovered = context.Process(target=_attempt_promotion, args=(result,))
    recovered.start()
    recovered.join(timeout=10)
    if recovered.is_alive():
        recovered.terminate()
        recovered.join(timeout=5)
        pytest.fail(f"promotion recovery hung after {boundary}")
    assert recovered.exitcode == 0
    assert result.get(timeout=2) in {
        ("promoted", "PROMOTED"),
        ("promoted", "ALREADY_PROMOTED"),
    }
    targets = tuple(
        public_root / name for name in (*staged.PUBLIC_RECEIPT_NAMES, staged.PUBLIC_PROOF_NAME)
    )
    assert tuple(path.read_bytes() for path in targets) == intended
    assert not (public_root / staged.PROMOTION_JOURNAL_NAME).exists()
    assert not any(
        path.name != staged.PROMOTION_LOCK_NAME and path.name.startswith(".phase4-demo-promotion-")
        for path in public_root.iterdir()
    )
