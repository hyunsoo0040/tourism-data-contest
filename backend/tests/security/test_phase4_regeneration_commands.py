"""Validate the fixed Phase 4 regeneration stage and its local lifecycle."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from collections import Counter
from pathlib import Path
from typing import cast

import pytest
from pydantic import BaseModel

from itda.contracts.phase4_demo import (
    DemoProviderMode,
    Phase4DemoEvaluationPreparation,
    Phase4DemoManifest,
    Phase4DemoMaterializationReceipt,
    Phase4DemoPredictionReceipt,
    Phase4DemoTerminalReceipt,
    Phase4DemoTerminalReport,
    derive_materialization_receipt,
    validate_terminal_receipt_report,
)
from itda.db.phase4_demo_release import (
    DATABASE_NAME,
    LOCAL_APPROVAL_MARKER,
    LOCAL_SQLITE_MARKER,
    Phase4DemoReleaseRepository,
    verify_demo_release,
)
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.dev_image_observations import (
    FrozenObservationBatch,
    PredictionBatchFreezeReceipt,
    freeze_prediction_batch,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
STAGE_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/phase4-demo-regeneration/04-20"
RECEIPT_ROOT = STAGE_ROOT / "receipts"
MATERIALIZATION_RECEIPT_PATH = RECEIPT_ROOT / "phase4-demo-materialization-receipt.json"
PREDICTION_RECEIPT_PATH = RECEIPT_ROOT / "phase4-demo-prediction-receipt.json"
TERMINAL_RECEIPT_PATH = RECEIPT_ROOT / "phase4-demo-terminal-receipt.json"
RELEASE_RECEIPT_PATH = RECEIPT_ROOT / "phase4-demo-release-receipt.json"
EXPECTED_RED_MARKER = "CR-10_REGENERATION_NOT_STARTED"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_stage_started() -> None:
    if not STAGE_ROOT.exists() and not STAGE_ROOT.is_symlink():
        print(EXPECTED_RED_MARKER)
        pytest.fail("fixed regeneration stage is absent", pytrace=False)
    assert STAGE_ROOT.is_dir()
    assert not STAGE_ROOT.is_symlink()


def _canonical_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> tuple[bytes, ModelT]:
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1
    raw = path.read_bytes()
    parsed = model.model_validate_json(raw)
    assert raw == canonical_json_bytes(parsed.model_dump(mode="json"))
    return raw, parsed


def _canonical_mapping(path: Path) -> tuple[bytes, dict[str, object]]:
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1
    raw = path.read_bytes()
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    assert raw == canonical_json_bytes(parsed)
    return raw, cast(dict[str, object], parsed)


def _run_root_from_receipt() -> tuple[Phase4DemoMaterializationReceipt, Phase4DemoManifest, Path]:
    _, receipt = _canonical_model(
        MATERIALIZATION_RECEIPT_PATH,
        Phase4DemoMaterializationReceipt,
    )
    assert SHA256_RE.fullmatch(receipt.manifest_sha256)
    run_root = STAGE_ROOT / receipt.manifest_sha256
    assert run_root.parent == STAGE_ROOT
    assert run_root.name == receipt.manifest_sha256
    assert run_root.is_dir()
    assert not run_root.is_symlink()
    _, manifest = _canonical_model(
        run_root / "phase4-demo-manifest.json",
        Phase4DemoManifest,
    )
    assert receipt == derive_materialization_receipt(manifest)
    return receipt, manifest, run_root


def _validate_materialization_stage() -> None:
    receipt, manifest, _ = _run_root_from_receipt()
    assert receipt.manifest_sha256 == manifest.manifest_sha256
    assert receipt.source_truth == manifest.source_truth == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert receipt.profile_truth == manifest.profile_truth == "SOURCE_EVIDENCE_ONLY"
    assert receipt.profile_score_truth == manifest.profile_score_truth == "NO_LOCAL_PROFILE_SCORES"
    assert receipt.image_truth == manifest.image_truth == "NO_IMAGE_TEXT_ODII_ONLY"
    assert receipt.benchmark_truth == manifest.benchmark_truth == "NO_REAL_IMAGE_BENCHMARK"
    assert receipt.dev_row_count == len(manifest.dev_places) == 24
    assert receipt.selected_image_count == len(manifest.selected_images) == 0


def _validate_observation_stage() -> None:
    materialization, manifest, run_root = _run_root_from_receipt()
    _, prediction = _canonical_model(
        PREDICTION_RECEIPT_PATH,
        Phase4DemoPredictionReceipt,
    )
    _, observations = _canonical_model(
        run_root / "frozen-observations.json",
        FrozenObservationBatch,
    )
    _, freeze_receipt = _canonical_model(
        run_root / "prediction-freeze-receipt.json",
        PredictionBatchFreezeReceipt,
    )
    assert freeze_receipt == freeze_prediction_batch(observations)
    assert prediction.materialization_receipt_sha256 == materialization.receipt_sha256
    assert prediction.manifest_sha256 == manifest.manifest_sha256
    assert prediction.observation_batch_sha256 == observations.batch_sha256
    assert prediction.freeze_receipt_sha256 == freeze_receipt.receipt_sha256
    assert prediction.observation_count == len(observations.observations) == 24
    assert prediction.provider_mode is DemoProviderMode.NO_PROVIDER_NO_IMAGE
    assert prediction.image_claim_inventory_count == 0
    assert prediction.source_truth == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert prediction.profile_truth == "SOURCE_EVIDENCE_ONLY"
    assert prediction.profile_score_truth == "NO_LOCAL_PROFILE_SCORES"
    assert prediction.image_truth == "NO_IMAGE_TEXT_ODII_ONLY"
    assert prediction.benchmark_truth == "NO_REAL_IMAGE_BENCHMARK"
    assert observations.replay_fixture_sha256 is None
    assert all(not row.provider_called for row in observations.observations)
    assert all(row.safe_request is None for row in observations.observations)
    assert all(row.provider_prediction is None for row in observations.observations)
    assert all(not row.observation.selected_image_refs for row in observations.observations)
    assert all(not row.observation.observations for row in observations.observations)
    assert all(not row.observation.candidate_axes for row in observations.observations)


def _validate_terminal_stage() -> None:
    materialization, manifest, run_root = _run_root_from_receipt()
    _, prediction = _canonical_model(
        PREDICTION_RECEIPT_PATH,
        Phase4DemoPredictionReceipt,
    )
    _, preparation = _canonical_model(
        run_root / "evaluation-preparation.json",
        Phase4DemoEvaluationPreparation,
    )
    _, report = _canonical_model(
        run_root / "phase4-demo-terminal-report.json",
        Phase4DemoTerminalReport,
    )
    _, terminal = _canonical_model(
        TERMINAL_RECEIPT_PATH,
        Phase4DemoTerminalReceipt,
    )
    validate_terminal_receipt_report(terminal, report)
    assert preparation.materialization_receipt_sha256 == materialization.receipt_sha256
    assert preparation.prediction_receipt_sha256 == prediction.receipt_sha256
    assert preparation.manifest_sha256 == manifest.manifest_sha256
    assert preparation.observation_batch_sha256 == prediction.observation_batch_sha256
    assert preparation.freeze_receipt_sha256 == prediction.freeze_receipt_sha256
    assert preparation.label_input_sha256 is None
    assert preparation.evaluation_state == "NOT_EVALUATED_NO_LOCAL_PROFILE_SCORES"
    assert preparation.image_claim_inventory_count == 0
    assert terminal.evaluation_preparation_sha256 == preparation.preparation_sha256
    assert terminal.provider_mode is DemoProviderMode.NO_PROVIDER_NO_IMAGE
    assert terminal.terminal_decision == "NO_IMAGE_TEXT_ODII_ONLY"
    assert terminal.image_review_gate == "NOT_APPLICABLE"
    assert terminal.image_claim_inventory_count == 0
    assert terminal.human_decision_receipt_sha256 is None
    assert terminal.source_truth == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert terminal.profile_truth == "SOURCE_EVIDENCE_ONLY"
    assert terminal.profile_score_truth == "NO_LOCAL_PROFILE_SCORES"
    assert terminal.image_truth == "NO_IMAGE_TEXT_ODII_ONLY"
    assert terminal.benchmark_truth == "NO_REAL_IMAGE_BENCHMARK"


def _validate_release_stage() -> None:
    _, manifest, run_root = _run_root_from_receipt()
    release_root = run_root / "release"
    database_path = release_root / DATABASE_NAME
    receipts_path = release_root / "receipts"
    pending_path = release_root / ".receipt-pending"
    assert release_root.is_dir() and not release_root.is_symlink()
    assert {entry.name for entry in os.scandir(release_root)} == {
        DATABASE_NAME,
        "receipts",
        ".receipt-pending",
    }
    assert database_path.is_file() and not database_path.is_symlink()
    assert receipts_path.is_dir() and not receipts_path.is_symlink()
    assert pending_path.is_dir() and not pending_path.is_symlink()
    assert not tuple(pending_path.iterdir())
    assert database_path.stat().st_mode & 0o777 == 0o600
    assert release_root.stat().st_mode & 0o777 == 0o700
    assert receipts_path.stat().st_mode & 0o777 == 0o700
    assert pending_path.stat().st_mode & 0o777 == 0o700
    assert not any(
        database_path.with_name(database_path.name + suffix).exists()
        for suffix in ("-journal", "-wal", "-shm")
    )

    with sqlite3.connect(database_path) as connection:
        rows = connection.execute(
            "SELECT receipt_ordinal, receipt_sha256, receipt_type, receipt_json "
            "FROM receipts ORDER BY receipt_ordinal"
        ).fetchall()
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert len(rows) == 21
    assert tuple(row[0] for row in rows) == tuple(range(1, 22))
    expected_counts = {
        "BUILD": 1,
        "APPROVAL": 1,
        "ACTIVATION": 1,
        "ROLLBACK": 1,
        "REACTIVATION": 1,
        "PIN": 8,
        "STATUS": 8,
    }
    assert Counter(row[2] for row in rows) == Counter(expected_counts)
    expected_names: set[str] = set()
    for ordinal, digest, receipt_type, raw in rows:
        receipt = json.loads(raw)
        Phase4DemoReleaseRepository.validate_local_receipt(receipt)
        assert raw == canonical_json_bytes(receipt)
        assert receipt["receipt_ordinal"] == ordinal
        assert receipt["receipt_sha256"] == digest
        assert receipt["receipt_type"] == receipt_type
        assert receipt["local_storage_scope"] == LOCAL_SQLITE_MARKER
        assert receipt["approval_authority"] == LOCAL_APPROVAL_MARKER
        name = f"{ordinal:03d}-{receipt_type.casefold()}-{digest}.json"
        expected_names.add(name)
        path = receipts_path / name
        assert path.is_file() and not path.is_symlink()
        assert path.read_bytes() == raw
    assert {entry.name for entry in os.scandir(receipts_path)} == expected_names

    _, release_receipt = _canonical_mapping(RELEASE_RECEIPT_PATH)
    Phase4DemoReleaseRepository.validate_local_receipt(release_receipt)
    verified = verify_demo_release(
        terminal_receipt_path=TERMINAL_RECEIPT_PATH,
        artifact_root=STAGE_ROOT,
        receipt_output=RELEASE_RECEIPT_PATH,
    )
    assert verified == release_receipt
    assert release_receipt["manifest_sha256"] == manifest.manifest_sha256
    assert release_receipt["active_release_sha256"] == release_receipt["successor_sha256"]
    assert release_receipt["generation"] == 3
    assert release_receipt["receipt_count"] == 21
    assert release_receipt["receipt_type_counts"] == expected_counts
    assert release_receipt["session_pin_count"] == 4
    assert release_receipt["result_pin_count"] == 4
    assert release_receipt["sqlite_sidecar_count"] == 0
    assert release_receipt["local_storage_scope"] == LOCAL_SQLITE_MARKER
    assert release_receipt["approval_authority"] == LOCAL_APPROVAL_MARKER
    assert release_receipt["production_mutation"] == "NO_PRODUCTION_MUTATION"
    assert release_receipt["source_truth"] == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert release_receipt["profile_truth"] == "SOURCE_EVIDENCE_ONLY"
    assert release_receipt["profile_score_truth"] == "NO_LOCAL_PROFILE_SCORES"
    assert release_receipt["provider_mode"] == "NO_PROVIDER_NO_IMAGE"
    assert release_receipt["terminal_decision"] == "NO_IMAGE_TEXT_ODII_ONLY"


def test_regeneration_complete() -> None:
    _require_stage_started()
    _validate_materialization_stage()
    _validate_observation_stage()
    _validate_terminal_stage()
    _validate_release_stage()


def test_materialization_stage() -> None:
    if not STAGE_ROOT.exists() and not STAGE_ROOT.is_symlink():
        pytest.skip("fixed regeneration stage not materialized yet")
    _validate_materialization_stage()


def test_observation_stage() -> None:
    if not STAGE_ROOT.exists() and not STAGE_ROOT.is_symlink():
        pytest.skip("fixed regeneration stage not materialized yet")
    _validate_observation_stage()
