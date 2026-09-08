"""Verify and promote the repository-fixed Phase 4 regenerated demo chain."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

from itda.cli.run_phase4_demo import require_fixed_materialization_authority
from itda.contracts.phase4_demo import (
    Phase4DemoInputAuthority,
    Phase4DemoManifest,
    Phase4DemoMaterializationReceipt,
    Phase4DemoPredictionReceipt,
    Phase4DemoTerminalReceipt,
    Phase4DemoZeroImageAbsenceRegistry,
    derive_materialization_receipt,
)
from itda.db.phase4_demo_release import (
    DATABASE_NAME,
    Phase4DemoReleaseError,
    Phase4DemoReleaseRepository,
    _validate_exact_terminal_parents,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
AUTHORITY_RECEIPT = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/phase4-demo-authority/input-authority.json"
)
ZERO_IMAGE_REGISTRY = AUTHORITY_RECEIPT.with_name("zero-image-absence-registry.json")
STAGE_ROOT = REPOSITORY_ROOT / (
    "artifacts/restricted/catalog/v2/phase4-demo-regeneration/04-20-review-fix-v2-20260808"
)
STAGED_RECEIPT_ROOT = STAGE_ROOT / "receipts"
PRIVATE_DATABASE_COPY = STAGE_ROOT / "release" / DATABASE_NAME
PRIVATE_PARENT_INVENTORY = STAGE_ROOT / "private-parent-inventory.json"
PRIVATE_HANDOFF = STAGE_ROOT / "regeneration-handoff.json"
PUBLIC_ROOT = REPOSITORY_ROOT / "artifacts/public/catalog/v2"

PUBLIC_RECEIPT_NAMES = (
    "phase4-demo-materialization-receipt.json",
    "phase4-demo-prediction-receipt.json",
    "phase4-demo-terminal-receipt.json",
    "phase4-demo-release-receipt.json",
)
PUBLIC_PROOF_NAME = "phase4-demo-chain-proof.json"
PROMOTION_LOCK_NAME = ".phase4-demo-promotion.lock"
PROMOTION_JOURNAL_NAME = ".phase4-demo-promotion-journal.json"
EXPECTED_TRUTH = {
    "source_truth": "LOCAL_COLLECTION_AUTHORITY_PARTIAL",
    "profile_truth": "SOURCE_EVIDENCE_ONLY",
    "profile_score_truth": "NO_LOCAL_PROFILE_SCORES",
    "provider_mode": "NO_PROVIDER_NO_IMAGE",
    "image_truth": "NO_IMAGE_TEXT_ODII_ONLY",
    "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
}
MAX_JSON_BYTES = 64_000_000
MAX_SQLITE_BYTES = 64 * 1024 * 1024

AUTHORITY_PARENT_PATHS = {
    "catalog": REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json",
    "sqlite_seal": REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/sqlite/real-manifest-seal-receipt.json",
    "dev_sqlite": REPOSITORY_ROOT
    / (
        "artifacts/restricted/catalog/v2/sqlite/releases/"
        "e45fae2e591542c1ecd8cc041ce4d2af863944f57be593ad38bfc196cf289ed0/"
        "evaluation-authority.sqlite3"
    ),
    "collection_report": REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v1/collection/collection-report.json",
    "optional_media": REPOSITORY_ROOT
    / (
        "artifacts/catalog/optional-media-v2/policy/"
        "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243/"
        "projected-candidates.json"
    ),
    "replay_fixture": REPOSITORY_ROOT / "fixtures/synthetic/phase4/provider-replay.json",
}
SNAPSHOT_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v1/collection/snapshots"
IMMUTABLE_TOOLCHAIN_PATHS = (
    REPOSITORY_ROOT / "backend/src/itda/cli/manage_phase4_staged_chain.py",
    REPOSITORY_ROOT / "backend/src/itda/cli/run_phase4_demo.py",
    REPOSITORY_ROOT / "backend/src/itda/contracts/phase4_demo.py",
    REPOSITORY_ROOT / "backend/src/itda/db/phase4_demo_release.py",
    REPOSITORY_ROOT / "backend/tests/security/test_phase4_checked_artifact_chain.py",
    REPOSITORY_ROOT / "backend/uv.lock",
    REPOSITORY_ROOT / "mise.toml",
)


class StagedChainError(ValueError):
    """The fixed regenerated candidate is absent, stale, or unsafe."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _local_command_version(command: str, *, prefixed: bool) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "MISE_OFFLINE": "1",
            "MISE_NOT_FOUND_AUTO_INSTALL": "0",
            "NO_COLOR": "1",
            "UV_OFFLINE": "1",
        }
    )
    try:
        completed = subprocess.run(
            [command, "--version"],
            check=True,
            capture_output=True,
            env=environment,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise StagedChainError(f"required local runtime {command} is unavailable") from exc
    tokens = completed.stdout.strip().split()
    index = 1 if prefixed else 0
    if len(tokens) <= index:
        raise StagedChainError(f"required local runtime {command} has invalid self-description")
    return tokens[index]


def runtime_versions() -> dict[str, str]:
    """Return the exact local execution environment bound into the public proof."""

    return {
        "mise": _local_command_version("mise", prefixed=False),
        "pydantic": importlib.metadata.version("pydantic"),
        "python": platform.python_version(),
        "sqlalchemy": importlib.metadata.version("sqlalchemy"),
        "uv": _local_command_version("uv", prefixed=True),
    }


def _signature(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_read(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    try:
        visible = path.lstat()
    except OSError as exc:
        raise StagedChainError("fixed private parent is absent") from exc
    if stat.S_ISLNK(visible.st_mode) or not stat.S_ISREG(visible.st_mode):
        raise StagedChainError("fixed private parent is unsafe")
    if visible.st_nlink != 1 or not 0 < visible.st_size <= max_bytes:
        raise StagedChainError("fixed private parent has unsafe file facts")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _signature(visible) != _signature(opened):
            raise StagedChainError("fixed private parent changed before open")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise StagedChainError("fixed private parent ended during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    replay = path.lstat()
    if _signature(opened) != _signature(after) or _signature(after) != _signature(replay):
        raise StagedChainError("fixed private parent changed during read")
    return b"".join(chunks)


def _canonical_mapping(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise StagedChainError("fixed JSON parent is invalid") from exc
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        raise StagedChainError("fixed JSON parent is not canonical")
    return cast(dict[str, object], value)


def _canonical_contract(path: Path, model: type[Any]) -> tuple[bytes, Any]:
    raw = _stable_read(path)
    try:
        value = model.model_validate_json(raw)
    except ValueError as exc:
        raise StagedChainError("fixed contract parent is invalid") from exc
    if raw != canonical_json_bytes(value.model_dump(mode="json")):
        raise StagedChainError("fixed contract parent is not canonical")
    return raw, value


def _relative(path: Path) -> str:
    try:
        return path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _inventory_row(path: Path, raw: bytes) -> dict[str, object]:
    return {
        "logical_path": _relative(path),
        "byte_count": len(raw),
        "byte_sha256": _sha256(raw),
    }


def _require_directory(path: Path) -> None:
    try:
        facts = path.lstat()
    except OSError as exc:
        raise StagedChainError("fixed private directory is absent") from exc
    if stat.S_ISLNK(facts.st_mode) or not stat.S_ISDIR(facts.st_mode):
        raise StagedChainError("fixed private directory is unsafe")


def _verify_authority_parents() -> tuple[Phase4DemoInputAuthority, list[dict[str, object]]]:
    authority_raw, authority = _canonical_contract(AUTHORITY_RECEIPT, Phase4DemoInputAuthority)
    registry_raw, registry = _canonical_contract(
        ZERO_IMAGE_REGISTRY, Phase4DemoZeroImageAbsenceRegistry
    )
    if authority.image_mode != "ZERO_IMAGE" or (
        authority.zero_image_absence_registry_sha256 != registry.registry_sha256
    ):
        raise StagedChainError("fixed zero-image authority is stale")

    parents = [_inventory_row(AUTHORITY_RECEIPT, authority_raw)]
    parents.append(_inventory_row(ZERO_IMAGE_REGISTRY, registry_raw))
    expected_digests = {
        "catalog": authority.catalog_sha256,
        "sqlite_seal": authority.sqlite_seal_receipt_sha256,
        "dev_sqlite": authority.dev_sqlite_sha256,
        "collection_report": authority.collection_report_sha256,
        "optional_media": authority.optional_media_sha256,
        "replay_fixture": authority.replay_fixture_sha256,
    }
    for name, path in AUTHORITY_PARENT_PATHS.items():
        raw = _stable_read(
            path,
            max_bytes=MAX_SQLITE_BYTES if name == "dev_sqlite" else MAX_JSON_BYTES,
        )
        if _sha256(raw) != expected_digests[name]:
            raise StagedChainError("fixed authority parent digest is stale")
        parents.append(_inventory_row(path, raw))

    _require_directory(SNAPSHOT_ROOT)
    names = sorted(path.name for path in SNAPSHOT_ROOT.iterdir())
    expected_names = [row.relative_name for row in authority.snapshot_inventory]
    if names != expected_names:
        raise StagedChainError("fixed snapshot namespace is not exhaustive")
    for expected in authority.snapshot_inventory:
        path = SNAPSHOT_ROOT / expected.relative_name
        raw = _stable_read(path)
        if len(raw) != expected.byte_count or _sha256(raw) != expected.byte_sha256:
            raise StagedChainError("fixed snapshot parent digest is stale")
        parents.append(_inventory_row(path, raw))
    return authority, parents


def _verify_release_candidate(
    *,
    run_root: Path,
    database_raw: bytes,
    receipt_file_rows: list[tuple[Path, bytes]],
    release_receipt: dict[str, object],
) -> None:
    terminal_path = STAGED_RECEIPT_ROOT / "phase4-demo-terminal-receipt.json"
    inputs = _validate_exact_terminal_parents(
        terminal_receipt_path=terminal_path,
        artifact_root=STAGE_ROOT,
    )
    with tempfile.TemporaryDirectory(prefix="itda-phase4-verify-") as temporary:
        release_root = Path(temporary) / "release"
        receipt_root = release_root / "receipts"
        pending_root = release_root / ".receipt-pending"
        receipt_root.mkdir(parents=True, mode=0o700)
        pending_root.mkdir(mode=0o700)
        database_path = release_root / DATABASE_NAME
        database_path.write_bytes(database_raw)
        database_path.chmod(0o600)
        for source, raw in receipt_file_rows:
            target = receipt_root / source.name
            target.write_bytes(raw)
            target.chmod(0o600)
        repository = Phase4DemoReleaseRepository(
            database_path=database_path,
            run_root=release_root.parent,
        )
        try:
            verified = repository.verify_complete_lifecycle(inputs)
        except Phase4DemoReleaseError as exc:
            raise StagedChainError("fixed SQLite lifecycle verifier rejected candidate") from exc
    compared_keys = (
        "upstream_terminal_receipt_sha256",
        "terminal_report_sha256",
        "manifest_sha256",
        "predecessor_sha256",
        "successor_sha256",
        "active_release_sha256",
        "generation",
        "database_sha256",
        "integrity_check",
        "foreign_key_check_count",
        "receipt_count",
        "receipt_type_counts",
        "receipt_inventory_sha256",
        "session_pin_count",
        "result_pin_count",
        "pin_inventory_sha256",
        "source_truth",
        "profile_truth",
        "profile_score_truth",
        "image_truth",
        "provider_mode",
        "terminal_decision",
    )
    if any(release_receipt.get(key) != verified.get(key) for key in compared_keys):
        raise StagedChainError("fixed release receipt differs from verified SQLite lifecycle")


def _derive_private_outputs() -> tuple[bytes, bytes, bytes]:
    authority, parent_rows = _verify_authority_parents()
    materialization_raw, materialization = _canonical_contract(
        STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[0],
        Phase4DemoMaterializationReceipt,
    )
    prediction_raw, prediction = _canonical_contract(
        STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[1],
        Phase4DemoPredictionReceipt,
    )
    terminal_raw, terminal = _canonical_contract(
        STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[2],
        Phase4DemoTerminalReceipt,
    )
    release_raw = _stable_read(STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[3])
    release = _canonical_mapping(release_raw)
    try:
        Phase4DemoReleaseRepository.validate_local_receipt(release)
    except Phase4DemoReleaseError as exc:
        raise StagedChainError("fixed release receipt is invalid") from exc

    run_root = STAGE_ROOT / materialization.manifest_sha256
    if run_root.parent != STAGE_ROOT or run_root.name != materialization.manifest_sha256:
        raise StagedChainError("fixed manifest root escaped its stage")
    _require_directory(run_root)
    manifest_raw, manifest = _canonical_contract(
        run_root / "phase4-demo-manifest.json", Phase4DemoManifest
    )
    if materialization != derive_materialization_receipt(manifest):
        raise StagedChainError("fixed materialization receipt differs from manifest")
    try:
        fixed_authority = require_fixed_materialization_authority(manifest)
    except ValueError as exc:
        raise StagedChainError(
            "fixed materialization authority does not authorize the staged manifest"
        ) from exc
    if fixed_authority != authority:
        raise StagedChainError("staged authority differs from the repository-fixed authority")

    content_paths = (
        run_root / "frozen-observations.json",
        run_root / "prediction-freeze-receipt.json",
        run_root / "evaluation-preparation.json",
        run_root / "phase4-demo-terminal-report.json",
    )
    content_rows = [(path, _stable_read(path)) for path in content_paths]
    release_root = run_root / "release"
    _require_directory(release_root)
    source_database = release_root / DATABASE_NAME
    database_raw = _stable_read(source_database, max_bytes=MAX_SQLITE_BYTES)
    receipt_root = release_root / "receipts"
    pending_root = release_root / ".receipt-pending"
    _require_directory(receipt_root)
    _require_directory(pending_root)
    if tuple(pending_root.iterdir()):
        raise StagedChainError("fixed SQLite pending directory is not empty")
    receipt_paths = sorted(receipt_root.iterdir(), key=lambda path: path.name)
    receipt_file_rows = [(path, _stable_read(path)) for path in receipt_paths]
    if len(receipt_file_rows) != 21:
        raise StagedChainError("fixed SQLite receipt inventory is incomplete")

    receipt_values = {
        "materialization": (materialization_raw, materialization.model_dump(mode="json")),
        "prediction": (prediction_raw, prediction.model_dump(mode="json")),
        "terminal": (terminal_raw, terminal.model_dump(mode="json")),
        "release": (release_raw, release),
    }
    common_truth = (
        manifest.source_truth,
        manifest.profile_truth,
        manifest.profile_score_truth,
        manifest.image_truth,
    )
    if common_truth != (
        EXPECTED_TRUTH["source_truth"],
        EXPECTED_TRUTH["profile_truth"],
        EXPECTED_TRUTH["profile_score_truth"],
        EXPECTED_TRUTH["image_truth"],
    ):
        raise StagedChainError("fixed manifest truth is not the authorized zero-image state")
    for _, payload in receipt_values.values():
        if payload["manifest_sha256"] != manifest.manifest_sha256 or any(
            payload[field] != EXPECTED_TRUTH[field]
            for field in ("source_truth", "profile_truth", "profile_score_truth", "image_truth")
        ):
            raise StagedChainError("fixed candidate receipts have mixed truth")
    if not (
        prediction.provider_mode.value == EXPECTED_TRUTH["provider_mode"]
        and terminal.provider_mode.value == EXPECTED_TRUTH["provider_mode"]
        and release["provider_mode"] == EXPECTED_TRUTH["provider_mode"]
        and prediction.benchmark_truth == EXPECTED_TRUTH["benchmark_truth"]
        and terminal.benchmark_truth == EXPECTED_TRUTH["benchmark_truth"]
        and manifest.benchmark_truth == EXPECTED_TRUTH["benchmark_truth"]
        and terminal.image_claim_inventory_count == 0
        and terminal.human_decision_receipt_sha256 is None
        and release["database_sha256"] == _sha256(database_raw)
    ):
        raise StagedChainError("fixed candidate overclaims image, provider, or label evidence")

    _verify_release_candidate(
        run_root=run_root,
        database_raw=database_raw,
        receipt_file_rows=receipt_file_rows,
        release_receipt=release,
    )

    for path, raw in (
        (STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[0], materialization_raw),
        (STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[1], prediction_raw),
        (STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[2], terminal_raw),
        (STAGED_RECEIPT_ROOT / PUBLIC_RECEIPT_NAMES[3], release_raw),
        (run_root / "phase4-demo-manifest.json", manifest_raw),
        *content_rows,
        (source_database, database_raw),
        *receipt_file_rows,
    ):
        parent_rows.append(_inventory_row(path, raw))
    parent_rows.sort(key=lambda row: cast(str, row["logical_path"]))

    toolchain = []
    for path in IMMUTABLE_TOOLCHAIN_PATHS:
        raw = _stable_read(path, max_bytes=MAX_SQLITE_BYTES)
        toolchain.append(_inventory_row(path, raw))
    toolchain.sort(key=lambda row: cast(str, row["logical_path"]))

    inventory_fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-private-parent-inventory.v1",
        "authority_receipt_sha256": _sha256(_stable_read(AUTHORITY_RECEIPT)),
        "authority_sha256": authority.authority_sha256,
        "dev_membership_sha256": authority.dev_membership_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "manifest_input_inventory_sha256": canonical_sha256(manifest.input_sha256),
        "manifest_snapshot_inventory_sha256": manifest.snapshot_inventory_sha256,
        "manifest_dev_projection_sha256": manifest.dev_projection_sha256,
        "manifest_selected_image_inventory_sha256": manifest.selected_image_inventory_sha256,
        "database_sha256": _sha256(database_raw),
        "parents": parent_rows,
        "immutable_toolchain": toolchain,
    }
    inventory_fields["inventory_sha256"] = canonical_sha256(inventory_fields)
    inventory_raw = canonical_json_bytes(inventory_fields)

    candidate_receipts = []
    for name, (raw, payload) in zip(PUBLIC_RECEIPT_NAMES, receipt_values.values(), strict=True):
        candidate_receipts.append(
            {
                "logical_path": f"artifacts/public/catalog/v2/{name}",
                "schema_version": payload["schema_version"],
                "byte_sha256": _sha256(raw),
                "receipt_sha256": payload["receipt_sha256"],
            }
        )
    intended_paths = [row["logical_path"] for row in candidate_receipts]
    intended_paths.append(f"artifacts/public/catalog/v2/{PUBLIC_PROOF_NAME}")
    promotion_binding = {
        "authority_receipt_sha256": inventory_fields["authority_receipt_sha256"],
        "authority_sha256": authority.authority_sha256,
        "dev_membership_sha256": authority.dev_membership_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "manifest_input_inventory_sha256": inventory_fields["manifest_input_inventory_sha256"],
        "manifest_snapshot_inventory_sha256": manifest.snapshot_inventory_sha256,
        "manifest_dev_projection_sha256": manifest.dev_projection_sha256,
        "manifest_selected_image_inventory_sha256": (manifest.selected_image_inventory_sha256),
        "private_parent_inventory_sha256": _sha256(inventory_raw),
        "private_parent_inventory_self_sha256": inventory_fields["inventory_sha256"],
        "database_sha256": _sha256(database_raw),
        "candidate_public_receipts_sha256": canonical_sha256(candidate_receipts),
    }
    handoff_fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-regeneration-handoff.v1",
        "authority_receipt_sha256": inventory_fields["authority_receipt_sha256"],
        "authority_sha256": authority.authority_sha256,
        "manifest_sha256": manifest.manifest_sha256,
        "private_parent_inventory_sha256": _sha256(inventory_raw),
        "private_parent_inventory_self_sha256": inventory_fields["inventory_sha256"],
        "database_sha256": _sha256(database_raw),
        "promotion_binding": promotion_binding,
        "promotion_binding_sha256": canonical_sha256(promotion_binding),
        "candidate_public_receipts": candidate_receipts,
        "truth": EXPECTED_TRUTH,
        "intended_public_paths": intended_paths,
        "immutable_toolchain": toolchain,
    }
    handoff_fields["handoff_sha256"] = canonical_sha256(handoff_fields)
    handoff_raw = canonical_json_bytes(handoff_fields)
    return database_raw, inventory_raw, handoff_raw


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StagedChainError("private output write did not complete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode, follow_symlinks=False)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_private() -> dict[str, object]:
    """Verify fixed parents and create or read-only confirm one exact handoff triple."""

    expected = _derive_private_outputs()
    outputs = (PRIVATE_DATABASE_COPY, PRIVATE_PARENT_INVENTORY, PRIVATE_HANDOFF)
    existence = tuple(path.exists() or path.is_symlink() for path in outputs)
    if any(existence) and not all(existence):
        raise StagedChainError("private output triple is partial")
    if all(existence):
        before = tuple(_signature(path.lstat()) for path in outputs)
        observed = tuple(_stable_read(path, max_bytes=MAX_SQLITE_BYTES) for path in outputs)
        after = tuple(_signature(path.lstat()) for path in outputs)
        if before != after:
            raise StagedChainError("private output triple changed during verification")
        if observed != expected:
            raise StagedChainError("private output triple conflicts with fixed parents")
        if any(path.stat().st_mode & 0o777 != 0o600 for path in outputs):
            raise StagedChainError("private output triple has unsafe mode")
        return {
            "disposition": "ALREADY_VERIFIED",
            "handoff_sha256": _canonical_mapping(expected[2])["handoff_sha256"],
        }

    for path, payload in zip(outputs, expected, strict=True):
        _write_exclusive(path, payload)
    for path, payload in zip(outputs, expected, strict=True):
        if _stable_read(path, max_bytes=MAX_SQLITE_BYTES) != payload:
            raise StagedChainError("private output verification failed")
    _fsync_directory(STAGE_ROOT)
    return {
        "disposition": "CREATED",
        "handoff_sha256": _canonical_mapping(expected[2])["handoff_sha256"],
    }


def _derive_public_outputs(handoff: dict[str, object]) -> tuple[bytes, ...]:
    expected_paths = [
        f"artifacts/public/catalog/v2/{name}" for name in (*PUBLIC_RECEIPT_NAMES, PUBLIC_PROOF_NAME)
    ]
    if handoff.get("schema_version") != "itda.phase4-demo-regeneration-handoff.v1":
        raise StagedChainError("candidate handoff schema is invalid")
    if handoff.get("handoff_sha256") != canonical_sha256(
        {key: value for key, value in handoff.items() if key != "handoff_sha256"}
    ):
        raise StagedChainError("candidate handoff digest is stale")
    if handoff.get("truth") != EXPECTED_TRUTH:
        raise StagedChainError("candidate handoff truth is unauthorized")
    if handoff.get("intended_public_paths") != expected_paths:
        raise StagedChainError("candidate handoff public paths are stale")
    promotion_binding = handoff.get("promotion_binding")
    if not isinstance(promotion_binding, dict) or handoff.get(
        "promotion_binding_sha256"
    ) != canonical_sha256(promotion_binding):
        raise StagedChainError("candidate handoff promotion binding is stale")
    if any(
        promotion_binding.get(key) != handoff.get(key)
        for key in (
            "authority_receipt_sha256",
            "authority_sha256",
            "manifest_sha256",
            "private_parent_inventory_sha256",
            "private_parent_inventory_self_sha256",
            "database_sha256",
        )
    ):
        raise StagedChainError("candidate handoff promotion binding differs from handoff")

    rows = handoff.get("candidate_public_receipts")
    if not isinstance(rows, list) or len(rows) != len(PUBLIC_RECEIPT_NAMES):
        raise StagedChainError("candidate handoff receipt inventory is invalid")
    if promotion_binding.get("candidate_public_receipts_sha256") != canonical_sha256(rows):
        raise StagedChainError("candidate handoff receipt promotion binding is stale")
    candidate: list[bytes] = []
    for name, row in zip(PUBLIC_RECEIPT_NAMES, rows, strict=True):
        if not isinstance(row, dict):
            raise StagedChainError("candidate handoff receipt row is invalid")
        raw = _stable_read(STAGED_RECEIPT_ROOT / name)
        payload = _canonical_mapping(raw)
        if not (
            row.get("logical_path") == f"artifacts/public/catalog/v2/{name}"
            and row.get("byte_sha256") == _sha256(raw)
            and row.get("schema_version") == payload.get("schema_version")
            and row.get("receipt_sha256") == payload.get("receipt_sha256")
            and payload.get("manifest_sha256") == handoff.get("manifest_sha256")
        ):
            raise StagedChainError("candidate handoff receipt binding is stale")
        candidate.append(raw)

    toolchain_rows = handoff.get("immutable_toolchain")
    if not isinstance(toolchain_rows, list):
        raise StagedChainError("candidate handoff toolchain binding is invalid")
    safe_toolchain = []
    for row in toolchain_rows:
        if not isinstance(row, dict):
            raise StagedChainError("candidate handoff toolchain row is invalid")
        logical_path = row.get("logical_path")
        byte_sha256 = row.get("byte_sha256")
        if not isinstance(logical_path, str) or not isinstance(byte_sha256, str):
            raise StagedChainError("candidate handoff toolchain row is invalid")
        if logical_path.startswith("artifacts/restricted"):
            raise StagedChainError("candidate handoff toolchain path is private")
        path = REPOSITORY_ROOT / logical_path
        if _sha256(_stable_read(path, max_bytes=MAX_SQLITE_BYTES)) != byte_sha256:
            raise StagedChainError("candidate handoff toolchain changed after verification")
        safe_toolchain.append({"logical_path": logical_path, "byte_sha256": byte_sha256})

    proof_fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-chain-proof.v1",
        "handoff_sha256": handoff["handoff_sha256"],
        "manifest_sha256": handoff["manifest_sha256"],
        "authority_sha256": handoff["authority_sha256"],
        "dev_membership_sha256": promotion_binding["dev_membership_sha256"],
        "manifest_input_inventory_sha256": promotion_binding["manifest_input_inventory_sha256"],
        "manifest_snapshot_inventory_sha256": promotion_binding[
            "manifest_snapshot_inventory_sha256"
        ],
        "manifest_dev_projection_sha256": promotion_binding["manifest_dev_projection_sha256"],
        "manifest_selected_image_inventory_sha256": promotion_binding[
            "manifest_selected_image_inventory_sha256"
        ],
        "private_parent_inventory_sha256": handoff["private_parent_inventory_sha256"],
        "database_sha256": handoff["database_sha256"],
        "promotion_binding_sha256": handoff["promotion_binding_sha256"],
        "promotion_binding": promotion_binding,
        "truth": EXPECTED_TRUTH,
        "receipts": rows,
        "schema_versions": {
            "materialization": cast(dict[str, object], rows[0])["schema_version"],
            "prediction": cast(dict[str, object], rows[1])["schema_version"],
            "terminal": cast(dict[str, object], rows[2])["schema_version"],
            "release": cast(dict[str, object], rows[3])["schema_version"],
            "chain_proof": "itda.phase4-demo-chain-proof.v1",
        },
        "toolchain": safe_toolchain,
    }
    runtime = runtime_versions()
    proof_fields["runtime"] = runtime
    proof_fields["runtime_sha256"] = canonical_sha256(runtime)
    proof_fields["proof_sha256"] = canonical_sha256(proof_fields)
    proof_raw = canonical_json_bytes(proof_fields)
    forbidden = (
        b"artifacts/restricted",
        b"database_path",
        b"raw_image",
        b"service_key",
        b"postgresql://",
        b"label_input",
        b"nonce",
    )
    if any(token in proof_raw.lower() for token in forbidden):
        raise StagedChainError("tracked chain proof contains a private field")
    candidate.append(proof_raw)
    return tuple(candidate)


def _replace_for_promotion(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _write_public_temp(
    root: Path,
    *,
    transaction_id: str,
    index: int,
    payload: bytes,
) -> Path:
    path = root / f".phase4-demo-promotion-{transaction_id}-staged-{index:02d}.tmp"
    _write_exclusive(path, payload, mode=0o644)
    if _stable_read(path) != payload:
        raise StagedChainError("promotion staging verification failed")
    return path


def _seal_promotion_journal(fields: dict[str, object]) -> dict[str, object]:
    sealed = {key: value for key, value in fields.items() if key != "journal_sha256"}
    sealed["journal_sha256"] = canonical_sha256(sealed)
    return sealed


def _journal_rows(journal: dict[str, object]) -> list[dict[str, object]]:
    rows = journal.get("targets")
    schema_version = journal.get("schema_version")
    if (
        schema_version
        not in {
            "itda.phase4-demo-promotion-journal.v1",
            "itda.phase4-demo-promotion-journal.v2",
        }
        or journal.get("journal_sha256")
        != canonical_sha256(
            {key: value for key, value in journal.items() if key != "journal_sha256"}
        )
        or not isinstance(rows, list)
        or len(rows) != 5
    ):
        raise StagedChainError("promotion journal is invalid")
    expected_names = [*PUBLIC_RECEIPT_NAMES, PUBLIC_PROOF_NAME]
    if [row.get("name") if isinstance(row, dict) else None for row in rows] != expected_names:
        raise StagedChainError("promotion journal target order is invalid")
    typed_rows = cast(list[dict[str, object]], rows)
    if schema_version == "itda.phase4-demo-promotion-journal.v1":
        for index, row in enumerate(typed_rows):
            staged_name = row.get("staged_name")
            backup_name = row.get("backup_name")
            if (
                not isinstance(staged_name, str)
                or Path(staged_name).name != staged_name
                or not staged_name.startswith(f".phase4-demo-promotion-{index:02d}-")
                or not staged_name.endswith(".tmp")
                or (
                    backup_name is not None
                    and backup_name != f".phase4-demo-promotion-backup-{index:02d}"
                )
            ):
                raise StagedChainError("legacy promotion journal namespace is invalid")
        return typed_rows

    transaction_id = journal.get("transaction_id")
    state = journal.get("state")
    transition_name = journal.get("transition_name")
    if (
        not isinstance(transaction_id, str)
        or len(transaction_id) != 32
        or any(character not in "0123456789abcdef" for character in transaction_id)
        or state not in {"PREPARING", "COMMITTING"}
        or transition_name != f".phase4-demo-promotion-{transaction_id}-journal.tmp"
    ):
        raise StagedChainError("promotion journal ownership is invalid")
    for index, row in enumerate(typed_rows):
        expected_staged = f".phase4-demo-promotion-{transaction_id}-staged-{index:02d}.tmp"
        expected_backup = (
            f".phase4-demo-promotion-{transaction_id}-backup-{index:02d}.bak"
            if row.get("old_present") is True
            else None
        )
        if row.get("staged_name") != expected_staged or row.get("backup_name") != expected_backup:
            raise StagedChainError("promotion journal artifact ownership is invalid")
    return typed_rows


def _journal_state(journal: dict[str, object]) -> str:
    _journal_rows(journal)
    if journal["schema_version"] == "itda.phase4-demo-promotion-journal.v1":
        return "COMMITTING"
    return cast(str, journal["state"])


def _journal_target_set_matches(
    root: Path,
    rows: list[dict[str, object]],
    *,
    target_set: str,
) -> bool:
    for row in rows:
        target = root / cast(str, row["name"])
        if target_set == "new":
            expected_present = True
            expected_sha256 = row.get("new_sha256")
        else:
            expected_present = row.get("old_present") is True
            expected_sha256 = row.get("old_sha256")
        present = target.exists() or target.is_symlink()
        if present != expected_present:
            return False
        if present and (
            not isinstance(expected_sha256, str)
            or target.is_symlink()
            or not target.is_file()
            or _sha256(_stable_read(target)) != expected_sha256
        ):
            return False
    return True


def _recover_old_public_set(root: Path, journal: dict[str, object]) -> None:
    rows = _journal_rows(journal)
    for row in rows:
        name = cast(str, row["name"])
        target = root / name
        backup_name = row.get("backup_name")
        old_sha256 = row.get("old_sha256")
        old_present = row.get("old_present")
        if old_present is True:
            if not isinstance(backup_name, str) or not isinstance(old_sha256, str):
                raise StagedChainError("promotion journal old binding is invalid")
            backup = root / backup_name
            if backup.exists() or backup.is_symlink():
                if _sha256(_stable_read(backup)) != old_sha256:
                    raise StagedChainError("promotion backup digest is stale")
                os.replace(backup, target)
            elif (
                not target.is_file()
                or target.is_symlink()
                or (_sha256(_stable_read(target)) != old_sha256)
            ):
                raise StagedChainError("promotion old set cannot be recovered")
        elif old_present is False:
            if target.exists() or target.is_symlink():
                target.unlink()
        else:
            raise StagedChainError("promotion journal old presence is invalid")
        staged_name = row.get("staged_name")
        if isinstance(staged_name, str):
            staged_path = root / staged_name
            if staged_path.exists() or staged_path.is_symlink():
                staged_path.unlink()

    for row in rows:
        backup_name = row.get("backup_name")
        if isinstance(backup_name, str):
            backup = root / backup_name
            if backup.exists() or backup.is_symlink():
                backup.unlink()
    journal_path = root / PROMOTION_JOURNAL_NAME
    if journal_path.exists() or journal_path.is_symlink():
        journal_path.unlink()
    _fsync_directory(root)


def _remove_success_artifacts(root: Path, journal: dict[str, object]) -> None:
    for row in _journal_rows(journal):
        for key in ("backup_name", "staged_name"):
            name = row.get(key)
            if isinstance(name, str):
                path = root / name
                if path.exists() or path.is_symlink():
                    path.unlink()
    transition_name = journal.get("transition_name")
    if isinstance(transition_name, str):
        transition_path = root / transition_name
        if transition_path.exists() or transition_path.is_symlink():
            transition_path.unlink()
    journal_path = root / PROMOTION_JOURNAL_NAME
    if journal_path.exists() or journal_path.is_symlink():
        journal_path.unlink()
    _fsync_directory(root)


def _recover_promotion(root: Path, journal: dict[str, object]) -> None:
    rows = _journal_rows(journal)
    if _journal_target_set_matches(root, rows, target_set="new"):
        _remove_success_artifacts(root, journal)
        return
    if _journal_state(journal) == "PREPARING":
        if not _journal_target_set_matches(root, rows, target_set="old"):
            raise StagedChainError("preparing promotion changed the public target set")
        _remove_success_artifacts(root, journal)
        return
    _recover_old_public_set(root, journal)


def _reconcile_unjournaled_legacy_artifacts(root: Path) -> None:
    legacy_paths = [root / f".phase4-demo-promotion-backup-{index:02d}" for index in range(5)]
    for child in root.iterdir():
        legacy_temp = any(
            child.name.startswith(f".phase4-demo-promotion-{index:02d}-")
            and child.name.endswith(".tmp")
            for index in range(5)
        )
        owned_v2_artifact = re.fullmatch(
            r"\.phase4-demo-promotion-[0-9a-f]{32}-(?:journal\.tmp|"
            r"staged-[0-9]{2}\.tmp|backup-[0-9]{2}\.bak)",
            child.name,
        )
        if legacy_temp or owned_v2_artifact is not None:
            legacy_paths.append(child)
    changed = False
    for path in dict.fromkeys(legacy_paths):
        if not (path.exists() or path.is_symlink()):
            continue
        if path.is_dir() and not path.is_symlink():
            raise StagedChainError("legacy promotion artifact is not a removable file")
        path.unlink()
        changed = True
    if changed:
        _fsync_directory(root)


def _replace_promotion_journal(root: Path, journal: dict[str, object]) -> None:
    transition_name = journal.get("transition_name")
    if not isinstance(transition_name, str):
        raise StagedChainError("promotion journal transition is invalid")
    transition_path = root / transition_name
    _write_exclusive(transition_path, canonical_json_bytes(journal))
    os.replace(transition_path, root / PROMOTION_JOURNAL_NAME)
    _fsync_directory(root)


def _validated_private_handoff() -> dict[str, object]:
    expected = _derive_private_outputs()
    paths = (PRIVATE_DATABASE_COPY, PRIVATE_PARENT_INVENTORY, PRIVATE_HANDOFF)
    if not all(path.exists() and path.is_file() and not path.is_symlink() for path in paths):
        raise StagedChainError("candidate handoff private triple is absent or partial")
    observed = tuple(_stable_read(path, max_bytes=MAX_SQLITE_BYTES) for path in paths)
    if observed != expected:
        raise StagedChainError("candidate handoff differs from current fixed parents")
    handoff = _canonical_mapping(observed[2])
    if handoff.get("private_parent_inventory_sha256") != _sha256(observed[1]):
        raise StagedChainError("candidate handoff inventory binding is stale")
    if handoff.get("database_sha256") != _sha256(observed[0]):
        raise StagedChainError("candidate handoff database binding is stale")
    return handoff


def promote() -> dict[str, object]:
    """Atomically promote one verified fixed handoff into the public namespace."""

    handoff = _validated_private_handoff()
    intended = _derive_public_outputs(handoff)
    PUBLIC_ROOT.mkdir(parents=True, exist_ok=True)
    _require_directory(PUBLIC_ROOT)
    targets = tuple(PUBLIC_ROOT / name for name in (*PUBLIC_RECEIPT_NAMES, PUBLIC_PROOF_NAME))
    lock_path = PUBLIC_ROOT / PROMOTION_LOCK_NAME
    lock_descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    lock_acquired = False
    try:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock_acquired = True
        except BlockingIOError as exc:
            raise StagedChainError("public promotion lock is already held") from exc
        journal_path = PUBLIC_ROOT / PROMOTION_JOURNAL_NAME
        if journal_path.exists() or journal_path.is_symlink():
            journal = _canonical_mapping(_stable_read(journal_path))
            _recover_promotion(PUBLIC_ROOT, journal)
        else:
            _reconcile_unjournaled_legacy_artifacts(PUBLIC_ROOT)

        current: list[bytes | None] = []
        for target in targets:
            if target.exists() or target.is_symlink():
                current.append(_stable_read(target))
            else:
                current.append(None)
        if tuple(current) == intended:
            return {
                "disposition": "ALREADY_PROMOTED",
                "handoff_sha256": handoff["handoff_sha256"],
            }
        if current[-1] is not None:
            current_proof = _canonical_mapping(current[-1])
            if current_proof.get("handoff_sha256") == handoff["handoff_sha256"]:
                raise StagedChainError("candidate handoff was reused with mixed public bytes")
        if any(raw is None for raw in current[:4]):
            raise StagedChainError("prior public receipt set is incomplete")

        transaction_id = secrets.token_hex(16)
        rows: list[dict[str, object]] = []
        for index, (target, old_raw, new_raw) in enumerate(
            zip(targets, current, intended, strict=True)
        ):
            rows.append(
                {
                    "name": target.name,
                    "old_present": old_raw is not None,
                    "old_sha256": _sha256(old_raw) if old_raw is not None else None,
                    "new_sha256": _sha256(new_raw),
                    "backup_name": (
                        f".phase4-demo-promotion-{transaction_id}-backup-{index:02d}.bak"
                        if old_raw is not None
                        else None
                    ),
                    "staged_name": (
                        f".phase4-demo-promotion-{transaction_id}-staged-{index:02d}.tmp"
                    ),
                }
            )
        preparing_journal = _seal_promotion_journal(
            {
                "schema_version": "itda.phase4-demo-promotion-journal.v2",
                "state": "PREPARING",
                "transaction_id": transaction_id,
                "transition_name": f".phase4-demo-promotion-{transaction_id}-journal.tmp",
                "handoff_sha256": handoff["handoff_sha256"],
                "targets": rows,
            }
        )
        _replace_promotion_journal(PUBLIC_ROOT, preparing_journal)
        try:
            for index, payload in enumerate(intended):
                _write_public_temp(
                    PUBLIC_ROOT,
                    transaction_id=transaction_id,
                    index=index,
                    payload=payload,
                )
            for index, old_raw in enumerate(current):
                if old_raw is not None:
                    backup = PUBLIC_ROOT / cast(str, rows[index]["backup_name"])
                    _write_exclusive(backup, old_raw)
                    if _stable_read(backup) != old_raw:
                        raise StagedChainError("promotion backup verification failed")
            _fsync_directory(PUBLIC_ROOT)
            journal = _seal_promotion_journal({**preparing_journal, "state": "COMMITTING"})
            _replace_promotion_journal(PUBLIC_ROOT, journal)
        except BaseException:
            if journal_path.exists() or journal_path.is_symlink():
                _recover_promotion(
                    PUBLIC_ROOT,
                    _canonical_mapping(_stable_read(journal_path)),
                )
            raise
        try:
            staged_paths = tuple(PUBLIC_ROOT / cast(str, row["staged_name"]) for row in rows)
            for target, staged_path in zip(targets, staged_paths, strict=True):
                _replace_for_promotion(staged_path, target)
                _fsync_directory(PUBLIC_ROOT)
            if tuple(_stable_read(target) for target in targets) != intended:
                raise StagedChainError("promoted public set failed final verification")
        except BaseException as exc:
            _recover_promotion(PUBLIC_ROOT, journal)
            raise StagedChainError(
                "promotion failed and recovered the complete prior public set"
            ) from exc
        _remove_success_artifacts(PUBLIC_ROOT, journal)
        return {
            "disposition": "PROMOTED",
            "handoff_sha256": handoff["handoff_sha256"],
            "proof_sha256": _canonical_mapping(intended[-1])["proof_sha256"],
        }
    finally:
        try:
            if lock_acquired:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("verify-private")
    subparsers.add_parser("promote")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = verify_private() if args.command == "verify-private" else promote()
    except (OSError, ValueError, Phase4DemoReleaseError, StagedChainError) as exc:
        raise SystemExit(f"phase4 staged chain failed closed: {exc}") from None
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
