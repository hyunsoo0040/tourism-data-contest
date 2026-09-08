"""Isolated SQLite lifecycle for Phase 4 contest-demo evidence.

This module deliberately models evidence releases, not production profile
releases.  Its database and receipts are valid only for the local contest demo.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from itda.contracts.phase4_demo import (
    Phase4DemoEvaluationPreparation,
    Phase4DemoManifest,
    Phase4DemoMaterializationReceipt,
    Phase4DemoPredictionReceipt,
    Phase4DemoTerminalReceipt,
    Phase4DemoTerminalReport,
    derive_materialization_receipt,
    validate_terminal_receipt_report,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.dev_image_observations import (
    FrozenObservationBatch,
    PredictionBatchFreezeReceipt,
)

LOCAL_SQLITE_MARKER = "LOCAL_SQLITE_DEMO_ONLY"
LOCAL_APPROVAL_MARKER = "LOCAL_AUTOMATED_APPROVAL"
DATABASE_NAME = "phase4-demo-release.sqlite3"
SCHEMA_VERSION = "itda.phase4-demo-release-sqlite.v1"
USER_VERSION = 1
SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
PRODUCTION_CAPABILITY_ENV = (
    "ITDA_PHASE3_DATABASE_URL",
    "ITDA_PHASE3_BUILDER_DATABASE_URL",
    "ITDA_PHASE3_APPROVER_DATABASE_URL",
)


class Phase4DemoReleaseError(ValueError):
    """A local evidence-release boundary failed closed."""


@dataclass(frozen=True)
class ValidatedTerminalInputs:
    terminal_receipt_path: Path
    artifact_root: Path
    run_root: Path
    terminal_receipt_bytes_sha256: str
    materialization_receipt_bytes_sha256: str
    prediction_receipt_bytes_sha256: str
    manifest_bytes_sha256: str
    observations_bytes_sha256: str
    freeze_receipt_bytes_sha256: str
    evaluation_preparation_bytes_sha256: str
    terminal_report_bytes_sha256: str
    terminal_receipt: Phase4DemoTerminalReceipt
    materialization_receipt: Phase4DemoMaterializationReceipt
    prediction_receipt: Phase4DemoPredictionReceipt
    manifest: Phase4DemoManifest
    observations: FrozenObservationBatch
    freeze_receipt: PredictionBatchFreezeReceipt
    evaluation_preparation: Phase4DemoEvaluationPreparation
    terminal_report: Phase4DemoTerminalReport
    predecessor_payload: dict[str, object]
    successor_payload: dict[str, object]
    predecessor_sha256: str
    successor_sha256: str


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stable_read(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    try:
        visible = path.lstat()
    except OSError as exc:
        raise Phase4DemoReleaseError("local evidence parent could not be inspected") from exc
    if stat.S_ISLNK(visible.st_mode) or not stat.S_ISREG(visible.st_mode):
        raise Phase4DemoReleaseError("local evidence parent must be a regular file")
    if visible.st_nlink != 1 or not 0 < visible.st_size <= max_bytes:
        raise Phase4DemoReleaseError("local evidence parent has unsafe file facts")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise Phase4DemoReleaseError("local evidence parent ended during stable read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    replay = path.lstat()

    def signature(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
        )

    if signature(visible) != signature(opened) or signature(opened) != signature(after):
        raise Phase4DemoReleaseError("local evidence parent changed during stable read")
    if signature(after) != signature(replay):
        raise Phase4DemoReleaseError("local evidence parent path changed during stable read")
    return b"".join(chunks)


def _load_contract(path: Path, model: type[Any]) -> tuple[bytes, Any]:
    raw = _stable_read(path)
    try:
        parsed = json.loads(raw)
        value = model.model_validate(parsed)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise Phase4DemoReleaseError("upstream terminal contract is invalid") from exc
    canonical_value = value.model_dump(
        mode="json",
        exclude_none=(
            isinstance(value, PredictionBatchFreezeReceipt)
            and value.dev_case_inventory is None
        ),
    )
    if raw != canonical_json_bytes(canonical_value):
        raise Phase4DemoReleaseError("upstream terminal parent is not canonical JSON")
    return raw, value


def _require_no_production_capability() -> None:
    if any(os.environ.get(name) for name in PRODUCTION_CAPABILITY_ENV):
        raise Phase4DemoReleaseError("production capability is forbidden for the local demo")


def _require_local_path(path: Path, *, label: str) -> Path:
    text = str(path)
    folded = text.casefold()
    if "://" in text or folded.startswith(("postgres", "http", "s3", "gs:")):
        raise Phase4DemoReleaseError(f"{label} rejects production, network, or DSN paths")
    candidate = Path(os.path.abspath(path))
    if any(part.casefold() in {"production", "prod"} for part in candidate.parts):
        raise Phase4DemoReleaseError(f"{label} rejects production, network, or DSN paths")
    return candidate


def _require_no_sidecars(database_path: Path) -> None:
    for suffix in SIDECAR_SUFFIXES:
        sidecar = database_path.with_name(database_path.name + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise Phase4DemoReleaseError("SQLite sidecar exists and will not be removed")


def _validate_exact_terminal_parents(
    *, terminal_receipt_path: Path, artifact_root: Path
) -> ValidatedTerminalInputs:
    receipt_path = _require_local_path(terminal_receipt_path, label="terminal receipt")
    root = _require_local_path(artifact_root, label="artifact root")
    terminal_raw, terminal = _load_contract(receipt_path, Phase4DemoTerminalReceipt)
    if terminal.source_truth not in {
        "REAL_LOCAL_DATA",
        "LOCAL_COLLECTION_AUTHORITY_PARTIAL",
    }:
        raise Phase4DemoReleaseError("upstream terminal source truth is unsupported")
    if terminal.profile_truth != "SOURCE_EVIDENCE_ONLY":
        raise Phase4DemoReleaseError("upstream terminal profile truth is not source evidence")
    if terminal.profile_score_truth != "NO_LOCAL_PROFILE_SCORES":
        raise Phase4DemoReleaseError("upstream terminal profile score truth is not absent")
    if (
        terminal.provider_mode.value != "NO_PROVIDER_NO_IMAGE"
        or terminal.image_truth != "NO_IMAGE_TEXT_ODII_ONLY"
        or terminal.terminal_decision != "NO_IMAGE_TEXT_ODII_ONLY"
    ):
        raise Phase4DemoReleaseError("upstream terminal mode is not the supported local result")

    public_root = receipt_path.parent
    materialization_raw, materialization = _load_contract(
        public_root / "phase4-demo-materialization-receipt.json",
        Phase4DemoMaterializationReceipt,
    )
    prediction_raw, prediction = _load_contract(
        public_root / "phase4-demo-prediction-receipt.json",
        Phase4DemoPredictionReceipt,
    )
    run_root = root / terminal.manifest_sha256
    manifest_raw, manifest = _load_contract(
        run_root / "phase4-demo-manifest.json", Phase4DemoManifest
    )
    observations_raw, observations = _load_contract(
        run_root / "frozen-observations.json", FrozenObservationBatch
    )
    freeze_raw, freeze_receipt = _load_contract(
        run_root / "prediction-freeze-receipt.json", PredictionBatchFreezeReceipt
    )
    preparation_raw, preparation = _load_contract(
        run_root / "evaluation-preparation.json", Phase4DemoEvaluationPreparation
    )
    report_raw, report = _load_contract(
        run_root / "phase4-demo-terminal-report.json", Phase4DemoTerminalReport
    )
    try:
        validate_terminal_receipt_report(terminal, report)
    except ValueError as exc:
        raise Phase4DemoReleaseError(
            "upstream terminal receipt and report truth fields differ"
        ) from exc
    truth_tuple = (
        manifest.source_truth,
        manifest.profile_truth,
        manifest.profile_score_truth,
        manifest.image_truth,
        manifest.benchmark_truth,
    )
    if materialization != derive_materialization_receipt(manifest):
        raise Phase4DemoReleaseError("materialization receipt differs from manifest authority")
    if any(
        candidate != truth_tuple
        for candidate in (
            (
                prediction.source_truth,
                prediction.profile_truth,
                prediction.profile_score_truth,
                prediction.image_truth,
                prediction.benchmark_truth,
            ),
            (
                report.source_truth,
                report.profile_truth,
                report.profile_score_truth,
                report.image_truth,
                report.benchmark_truth,
            ),
            (
                terminal.source_truth,
                terminal.profile_truth,
                terminal.profile_score_truth,
                terminal.image_truth,
                terminal.benchmark_truth,
            ),
        )
    ):
        raise Phase4DemoReleaseError("public truth fields differ from manifest authority")
    if not (
        materialization.receipt_sha256 == terminal.materialization_receipt_sha256
        and prediction.receipt_sha256 == terminal.prediction_receipt_sha256
        and manifest.manifest_sha256 == terminal.manifest_sha256
        and observations.batch_sha256 == report.observation_batch_sha256
        and freeze_receipt.receipt_sha256 == report.freeze_receipt_sha256
        and preparation.preparation_sha256 == terminal.evaluation_preparation_sha256
        and report.terminal_report_sha256 == terminal.terminal_report_sha256
        and report.manifest_sha256 == manifest.manifest_sha256
        and report.materialization_receipt_sha256 == materialization.receipt_sha256
        and report.prediction_receipt_sha256 == prediction.receipt_sha256
        and report.evaluation_preparation_sha256 == preparation.preparation_sha256
        and preparation.observation_batch_sha256 == observations.batch_sha256
        and preparation.freeze_receipt_sha256 == freeze_receipt.receipt_sha256
    ):
        raise Phase4DemoReleaseError("upstream terminal parent digests are mixed or stale")

    predecessor_payload: dict[str, object] = {
        "schema_version": "itda.phase4-demo-evidence-release.v1",
        "release_role": "SOURCE_EVIDENCE_PREDECESSOR",
        "manifest_sha256": manifest.manifest_sha256,
        "materialization_receipt_sha256": materialization.receipt_sha256,
        "snapshot_inventory_sha256": manifest.snapshot_inventory_sha256,
        "dev_projection_sha256": manifest.dev_projection_sha256,
        "selected_image_inventory_sha256": manifest.selected_image_inventory_sha256,
        "source_truth": manifest.source_truth,
        "profile_truth": manifest.profile_truth,
        "profile_score_truth": manifest.profile_score_truth,
        "image_truth": manifest.image_truth,
        "benchmark_truth": manifest.benchmark_truth,
    }
    predecessor_sha256 = canonical_sha256(predecessor_payload)
    successor_payload: dict[str, object] = {
        "schema_version": "itda.phase4-demo-evidence-release.v1",
        "release_role": "TERMINAL_EVIDENCE_SUCCESSOR",
        "predecessor_sha256": predecessor_sha256,
        "manifest_sha256": terminal.manifest_sha256,
        "prediction_receipt_sha256": terminal.prediction_receipt_sha256,
        "evaluation_preparation_sha256": terminal.evaluation_preparation_sha256,
        "terminal_report_sha256": terminal.terminal_report_sha256,
        "upstream_terminal_receipt_sha256": terminal.receipt_sha256,
        "provider_mode": terminal.provider_mode.value,
        "terminal_decision": terminal.terminal_decision,
        "source_truth": manifest.source_truth,
        "profile_truth": manifest.profile_truth,
        "profile_score_truth": manifest.profile_score_truth,
        "image_truth": manifest.image_truth,
        "benchmark_truth": manifest.benchmark_truth,
    }
    successor_sha256 = canonical_sha256(successor_payload)
    return ValidatedTerminalInputs(
        terminal_receipt_path=receipt_path,
        artifact_root=root,
        run_root=run_root,
        terminal_receipt_bytes_sha256=_sha256(terminal_raw),
        materialization_receipt_bytes_sha256=_sha256(materialization_raw),
        prediction_receipt_bytes_sha256=_sha256(prediction_raw),
        manifest_bytes_sha256=_sha256(manifest_raw),
        observations_bytes_sha256=_sha256(observations_raw),
        freeze_receipt_bytes_sha256=_sha256(freeze_raw),
        evaluation_preparation_bytes_sha256=_sha256(preparation_raw),
        terminal_report_bytes_sha256=_sha256(report_raw),
        terminal_receipt=terminal,
        materialization_receipt=materialization,
        prediction_receipt=prediction,
        manifest=manifest,
        observations=observations,
        freeze_receipt=freeze_receipt,
        evaluation_preparation=preparation,
        terminal_report=report,
        predecessor_payload=predecessor_payload,
        successor_payload=successor_payload,
        predecessor_sha256=predecessor_sha256,
        successor_sha256=successor_sha256,
    )


_DDL = """
PRAGMA user_version = 1;
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version TEXT NOT NULL CHECK (schema_version = 'itda.phase4-demo-release-sqlite.v1'),
    upstream_terminal_receipt_file_sha256 TEXT NOT NULL,
    upstream_terminal_receipt_sha256 TEXT NOT NULL,
    terminal_report_sha256 TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    predecessor_sha256 TEXT NOT NULL,
    successor_sha256 TEXT NOT NULL,
    source_truth TEXT NOT NULL CHECK (
        source_truth IN ('REAL_LOCAL_DATA', 'LOCAL_COLLECTION_AUTHORITY_PARTIAL')
    ),
    profile_truth TEXT NOT NULL CHECK (profile_truth = 'SOURCE_EVIDENCE_ONLY'),
    profile_score_truth TEXT NOT NULL CHECK (profile_score_truth = 'NO_LOCAL_PROFILE_SCORES'),
    image_truth TEXT NOT NULL CHECK (image_truth = 'NO_IMAGE_TEXT_ODII_ONLY'),
    provider_mode TEXT NOT NULL CHECK (provider_mode = 'NO_PROVIDER_NO_IMAGE'),
    terminal_decision TEXT NOT NULL CHECK (terminal_decision = 'NO_IMAGE_TEXT_ODII_ONLY')
);
CREATE TABLE releases (
    release_sha256 TEXT PRIMARY KEY,
    release_role TEXT NOT NULL UNIQUE CHECK (
        release_role IN (
            'SOURCE_EVIDENCE_PREDECESSOR',
            'TERMINAL_EVIDENCE_SUCCESSOR'
        )
    ),
    initial_state TEXT NOT NULL CHECK (initial_state IN ('ACTIVE', 'BUILT_UNAPPROVED')),
    predecessor_sha256 TEXT REFERENCES releases(release_sha256),
    payload_json BLOB NOT NULL
);
CREATE TABLE approvals (
    approval_sha256 TEXT PRIMARY KEY,
    release_sha256 TEXT NOT NULL UNIQUE REFERENCES releases(release_sha256),
    receipt_sha256 TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state = 'APPROVED_INACTIVE')
);
CREATE TABLE transition_history (
    transition_sha256 TEXT PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('ACTIVATE', 'ROLLBACK', 'REACTIVATE')),
    target_release_sha256 TEXT NOT NULL REFERENCES releases(release_sha256),
    previous_release_sha256 TEXT NOT NULL REFERENCES releases(release_sha256),
    expected_current_sha256 TEXT NOT NULL REFERENCES releases(release_sha256),
    expected_generation INTEGER NOT NULL,
    new_generation INTEGER NOT NULL UNIQUE,
    reason_sha256 TEXT,
    receipt_sha256 TEXT NOT NULL UNIQUE
);
CREATE TABLE active_pointer (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    release_sha256 TEXT NOT NULL REFERENCES releases(release_sha256),
    generation INTEGER NOT NULL CHECK (generation >= 0)
);
CREATE TABLE receipts (
    receipt_ordinal INTEGER PRIMARY KEY,
    receipt_sha256 TEXT NOT NULL UNIQUE,
    receipt_type TEXT NOT NULL CHECK (
        receipt_type IN (
            'BUILD', 'APPROVAL', 'ACTIVATION', 'ROLLBACK',
            'REACTIVATION', 'PIN', 'STATUS'
        )
    ),
    local_storage_scope TEXT NOT NULL CHECK (local_storage_scope = 'LOCAL_SQLITE_DEMO_ONLY'),
    approval_authority TEXT NOT NULL CHECK (approval_authority = 'LOCAL_AUTOMATED_APPROVAL'),
    receipt_json BLOB NOT NULL
);
CREATE TABLE session_pins (
    owner_ref_sha256 TEXT PRIMARY KEY,
    release_sha256 TEXT NOT NULL REFERENCES releases(release_sha256),
    generation INTEGER NOT NULL,
    pin_sha256 TEXT NOT NULL UNIQUE,
    receipt_sha256 TEXT NOT NULL UNIQUE REFERENCES receipts(receipt_sha256)
);
CREATE TABLE result_pins (
    owner_ref_sha256 TEXT PRIMARY KEY,
    release_sha256 TEXT NOT NULL REFERENCES releases(release_sha256),
    generation INTEGER NOT NULL,
    pin_sha256 TEXT NOT NULL UNIQUE,
    receipt_sha256 TEXT NOT NULL UNIQUE REFERENCES receipts(receipt_sha256)
);
CREATE TRIGGER releases_no_update BEFORE UPDATE ON releases BEGIN
    SELECT RAISE(ABORT, 'immutable releases');
END;
CREATE TRIGGER releases_no_delete BEFORE DELETE ON releases BEGIN
    SELECT RAISE(ABORT, 'immutable releases');
END;
CREATE TRIGGER metadata_no_update BEFORE UPDATE ON metadata BEGIN
    SELECT RAISE(ABORT, 'immutable metadata');
END;
CREATE TRIGGER metadata_no_delete BEFORE DELETE ON metadata BEGIN
    SELECT RAISE(ABORT, 'immutable metadata');
END;
CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals BEGIN
    SELECT RAISE(ABORT, 'immutable approvals');
END;
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals BEGIN
    SELECT RAISE(ABORT, 'immutable approvals');
END;
CREATE TRIGGER transitions_no_update BEFORE UPDATE ON transition_history BEGIN
    SELECT RAISE(ABORT, 'immutable transitions');
END;
CREATE TRIGGER transitions_no_delete BEFORE DELETE ON transition_history BEGIN
    SELECT RAISE(ABORT, 'immutable transitions');
END;
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON receipts BEGIN
    SELECT RAISE(ABORT, 'immutable receipts');
END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON receipts BEGIN
    SELECT RAISE(ABORT, 'immutable receipts');
END;
CREATE TRIGGER session_pins_no_update BEFORE UPDATE ON session_pins BEGIN
    SELECT RAISE(ABORT, 'immutable session pins');
END;
CREATE TRIGGER session_pins_no_delete BEFORE DELETE ON session_pins BEGIN
    SELECT RAISE(ABORT, 'immutable session pins');
END;
CREATE TRIGGER result_pins_no_update BEFORE UPDATE ON result_pins BEGIN
    SELECT RAISE(ABORT, 'immutable result pins');
END;
CREATE TRIGGER result_pins_no_delete BEFORE DELETE ON result_pins BEGIN
    SELECT RAISE(ABORT, 'immutable result pins');
END;
CREATE TRIGGER pointer_guard_update BEFORE UPDATE ON active_pointer
WHEN itda_pointer_mutation_allowed() != 1 BEGIN
    SELECT RAISE(ABORT, 'pointer mutation forbidden');
END;
CREATE TRIGGER pointer_no_delete BEFORE DELETE ON active_pointer BEGIN
    SELECT RAISE(ABORT, 'pointer deletion forbidden');
END;
"""


class Phase4DemoReleaseRepository:
    """One local SQLite evidence-release repository."""

    def __init__(self, *, database_path: Path, run_root: Path) -> None:
        self.database_path = _require_local_path(database_path, label="database path")
        self.run_root = _require_local_path(run_root, label="run root")
        try:
            self.database_path.relative_to(self.run_root)
        except ValueError as exc:
            raise Phase4DemoReleaseError("database path is outside the local demo run") from exc
        if self.database_path.name != DATABASE_NAME:
            raise Phase4DemoReleaseError("database path is not the local demo database")
        self._pointer_mutation_allowed = False

    @classmethod
    def from_terminal_receipt(
        cls, *, terminal_receipt_path: Path, artifact_root: Path
    ) -> Phase4DemoReleaseRepository:
        inputs = _validate_exact_terminal_parents(
            terminal_receipt_path=terminal_receipt_path,
            artifact_root=artifact_root,
        )
        return cls(
            database_path=inputs.run_root / "release" / DATABASE_NAME,
            run_root=inputs.run_root,
        )

    def _connect_write(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, isolation_level=None, timeout=1.0)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.create_function(
            "itda_pointer_mutation_allowed",
            0,
            lambda: int(self._pointer_mutation_allowed),
        )
        return connection

    def _connect_read_only(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"{self.database_path.as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=1.0,
        )
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA query_only=ON")
        return connection

    def _database_identity(self) -> tuple[int, int, int, int, str]:
        facts = self.database_path.stat()
        raw = _stable_read(self.database_path, max_bytes=64 * 1024 * 1024)
        return (
            facts.st_dev,
            facts.st_ino,
            facts.st_size,
            facts.st_mtime_ns,
            _sha256(raw),
        )

    @contextmanager
    def _transaction(self, connection: sqlite3.Connection) -> Iterator[None]:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def validate_local_receipt(receipt: dict[str, object]) -> None:
        if (
            receipt.get("local_storage_scope") != LOCAL_SQLITE_MARKER
            or receipt.get("approval_authority") != LOCAL_APPROVAL_MARKER
        ):
            raise Phase4DemoReleaseError("local marker is absent or mutated")
        digest = receipt.get("receipt_sha256")
        if not isinstance(digest, str) or not hmac.compare_digest(
            digest,
            canonical_sha256({k: v for k, v in receipt.items() if k != "receipt_sha256"}),
        ):
            raise Phase4DemoReleaseError("local receipt digest is stale")

    @staticmethod
    def _receipt(
        *, receipt_type: str, receipt_ordinal: int, facts: dict[str, object]
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": f"itda.phase4-demo-release-{receipt_type.casefold()}-receipt.v1",
            "receipt_type": receipt_type,
            "receipt_ordinal": receipt_ordinal,
            "local_storage_scope": LOCAL_SQLITE_MARKER,
            "approval_authority": LOCAL_APPROVAL_MARKER,
            **facts,
        }
        value["receipt_sha256"] = canonical_sha256(value)
        Phase4DemoReleaseRepository.validate_local_receipt(value)
        return value

    def _insert_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        receipt_type: str,
        facts: dict[str, object],
    ) -> dict[str, object]:
        ordinal = cast(
            int,
            connection.execute(
                "SELECT coalesce(max(receipt_ordinal), 0) + 1 FROM receipts"
            ).fetchone()[0],
        )
        receipt = self._receipt(receipt_type=receipt_type, receipt_ordinal=ordinal, facts=facts)
        connection.execute(
            "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
            (
                ordinal,
                receipt["receipt_sha256"],
                receipt_type,
                LOCAL_SQLITE_MARKER,
                LOCAL_APPROVAL_MARKER,
                canonical_json_bytes(receipt),
            ),
        )
        return receipt

    def _publish_receipts(self, receipts: list[dict[str, object]]) -> None:
        receipt_root = self.database_path.parent / "receipts"
        receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        receipt_root.chmod(0o700)
        pending_root = self.database_path.parent / ".receipt-pending"
        pending_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        pending_root.chmod(0o700)
        for receipt in receipts:
            path = receipt_root / (
                f"{cast(int, receipt['receipt_ordinal']):03d}-"
                f"{cast(str, receipt['receipt_type']).casefold()}-"
                f"{cast(str, receipt['receipt_sha256'])}.json"
            )
            payload = canonical_json_bytes(receipt)
            if path.exists() or path.is_symlink():
                if path.is_symlink() or _stable_read(path) != payload:
                    raise Phase4DemoReleaseError(
                        "private receipt conflicts with stored receipt"
                    )
                continue
            descriptor, pending_name = tempfile.mkstemp(
                prefix=f"{cast(str, receipt['receipt_sha256'])}-",
                suffix=".tmp",
                dir=pending_root,
            )
            pending_path = Path(pending_name)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise Phase4DemoReleaseError("private receipt write did not complete")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.link(pending_path, path, follow_symlinks=False)
            except FileExistsError:
                if path.is_symlink() or _stable_read(path) != payload:
                    raise Phase4DemoReleaseError(
                        "private receipt conflicts with stored receipt"
                    ) from None
            finally:
                pending_path.unlink(missing_ok=True)
            directory_descriptor = os.open(
                receipt_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)

    def reconcile_private_receipts(self) -> None:
        """Regenerate only missing files from digest-verified committed rows."""

        if not self.database_path.exists():
            return
        connection = self._connect_read_only()
        try:
            connection.execute("BEGIN")
            receipts: list[dict[str, object]] = []
            for (raw,) in connection.execute(
                "SELECT receipt_json FROM receipts ORDER BY receipt_ordinal"
            ):
                receipt = json.loads(raw)
                self.validate_local_receipt(receipt)
                if raw != canonical_json_bytes(receipt):
                    raise Phase4DemoReleaseError("local demo receipt row drifted")
                receipts.append(cast(dict[str, object], receipt))
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        self._publish_receipts(receipts)

    def _pin(
        self,
        connection: sqlite3.Connection,
        *,
        kind: Literal["SESSION", "RESULT"],
        owner_ref: str,
        release_sha256: str,
        generation: int,
        era: str,
    ) -> dict[str, object]:
        owner_ref_sha256 = _sha256(owner_ref.encode("utf-8"))
        pin_facts = {
            "pin_kind": kind,
            "owner_ref_sha256": owner_ref_sha256,
            "release_sha256": release_sha256,
            "generation": generation,
            "era": era,
        }
        pin_sha256 = canonical_sha256(pin_facts)
        receipt = self._insert_receipt(
            connection,
            receipt_type="PIN",
            facts={**pin_facts, "pin_sha256": pin_sha256},
        )
        table = "session_pins" if kind == "SESSION" else "result_pins"
        try:
            connection.execute(
                f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?)",
                (
                    owner_ref_sha256,
                    release_sha256,
                    generation,
                    pin_sha256,
                    receipt["receipt_sha256"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            existing = connection.execute(
                f"SELECT release_sha256, generation, pin_sha256 FROM {table} "
                "WHERE owner_ref_sha256 = ?",
                (owner_ref_sha256,),
            ).fetchone()
            if existing != (release_sha256, generation, pin_sha256):
                raise Phase4DemoReleaseError("copy-once pin cannot be repinned") from exc
            raise Phase4DemoReleaseError("copy-once pin receipt replay is forbidden") from exc
        return receipt

    @staticmethod
    def _status_from_connection(connection: sqlite3.Connection) -> dict[str, object]:
        metadata = connection.execute(
            "SELECT upstream_terminal_receipt_sha256, terminal_report_sha256, "
            "manifest_sha256, predecessor_sha256, successor_sha256, source_truth, "
            "profile_truth, profile_score_truth, image_truth, provider_mode, terminal_decision "
            "FROM metadata WHERE singleton = 1"
        ).fetchone()
        if metadata is None:
            raise Phase4DemoReleaseError("local demo metadata is absent")
        pointer = connection.execute(
            "SELECT release_sha256, generation FROM active_pointer WHERE singleton = 1"
        ).fetchone()
        approval = connection.execute(
            "SELECT 1 FROM approvals WHERE release_sha256 = ?", (metadata[4],)
        ).fetchone()
        successor_state = (
            "ACTIVE"
            if pointer[0] == metadata[4]
            else "APPROVED_INACTIVE"
            if approval is not None
            else "BUILT_UNAPPROVED"
        )
        return {
            "upstream_terminal_receipt_sha256": metadata[0],
            "terminal_report_sha256": metadata[1],
            "manifest_sha256": metadata[2],
            "predecessor_sha256": metadata[3],
            "successor_sha256": metadata[4],
            "source_truth": metadata[5],
            "profile_truth": metadata[6],
            "profile_score_truth": metadata[7],
            "image_truth": metadata[8],
            "provider_mode": metadata[9],
            "terminal_decision": metadata[10],
            "active_release_sha256": pointer[0],
            "generation": pointer[1],
            "successor_state": successor_state,
            "session_pin_count": connection.execute("SELECT count(*) FROM session_pins").fetchone()[
                0
            ],
            "result_pin_count": connection.execute("SELECT count(*) FROM result_pins").fetchone()[
                0
            ],
            "transition_count": connection.execute(
                "SELECT count(*) FROM transition_history"
            ).fetchone()[0],
        }

    def status(self, *, create_receipt: bool = False) -> dict[str, object]:
        _require_no_sidecars(self.database_path)
        self.reconcile_private_receipts()
        if not create_receipt:
            connection = self._connect_read_only()
            try:
                return self._status_from_connection(connection)
            finally:
                connection.close()
        connection = self._connect_write()
        receipts: list[dict[str, object]] = []
        try:
            with self._transaction(connection):
                status = self._status_from_connection(connection)
                receipts.append(
                    self._insert_receipt(connection, receipt_type="STATUS", facts=status)
                )
        finally:
            connection.close()
        _require_no_sidecars(self.database_path)
        self._publish_receipts(receipts)
        return {**status, "status_receipt_sha256": receipts[0]["receipt_sha256"]}

    @staticmethod
    def _verify_release_payload(
        connection: sqlite3.Connection, release_sha256: str
    ) -> dict[str, object]:
        row = connection.execute(
            "SELECT payload_json FROM releases WHERE release_sha256 = ?",
            (release_sha256,),
        ).fetchone()
        if row is None:
            raise Phase4DemoReleaseError("local demo release target does not exist")
        try:
            payload = json.loads(row[0])
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise Phase4DemoReleaseError("local demo release payload is invalid") from exc
        if row[0] != canonical_json_bytes(payload) or canonical_sha256(payload) != release_sha256:
            raise Phase4DemoReleaseError("local demo release payload drifted")
        return cast(dict[str, object], payload)

    def approve_release(self, release_sha256: str) -> dict[str, object]:
        """Approve only the exact local successor without moving the pointer."""

        _require_no_production_capability()
        _require_no_sidecars(self.database_path)
        self.reconcile_private_receipts()
        connection = self._connect_write()
        receipts: list[dict[str, object]] = []
        try:
            with self._transaction(connection):
                status = self._status_from_connection(connection)
                if release_sha256 != status["successor_sha256"]:
                    raise Phase4DemoReleaseError("approval requires the exact successor")
                if connection.execute(
                    "SELECT 1 FROM approvals WHERE release_sha256 = ?", (release_sha256,)
                ).fetchone():
                    raise Phase4DemoReleaseError("approval receipt replay is forbidden")
                self._verify_release_payload(connection, release_sha256)
                approval_facts = {
                    "release_sha256": release_sha256,
                    "predecessor_sha256": status["predecessor_sha256"],
                    "state": "APPROVED_INACTIVE",
                    "active_release_sha256": status["active_release_sha256"],
                    "generation": status["generation"],
                }
                approval_sha256 = canonical_sha256(approval_facts)
                approval_receipt = self._insert_receipt(
                    connection,
                    receipt_type="APPROVAL",
                    facts={**approval_facts, "approval_sha256": approval_sha256},
                )
                connection.execute(
                    "INSERT INTO approvals VALUES (?, ?, ?, 'APPROVED_INACTIVE')",
                    (approval_sha256, release_sha256, approval_receipt["receipt_sha256"]),
                )
                receipts.append(approval_receipt)
                receipts.append(
                    self._insert_receipt(
                        connection,
                        receipt_type="STATUS",
                        facts=self._status_from_connection(connection),
                    )
                )
        finally:
            connection.close()
        _require_no_sidecars(self.database_path)
        self._publish_receipts(receipts)
        return receipts[0]

    def _transition_release(
        self,
        *,
        action: Literal["ACTIVATE", "ROLLBACK", "REACTIVATE"],
        target_release_sha256: str,
        expected_current: str,
        expected_generation: int,
        reason: str | None = None,
    ) -> dict[str, object]:
        _require_no_production_capability()
        _require_no_sidecars(self.database_path)
        self.reconcile_private_receipts()
        if expected_generation < 0:
            raise Phase4DemoReleaseError("stale expected generation")
        connection = self._connect_write()
        receipts: list[dict[str, object]] = []
        try:
            with self._transaction(connection):
                status = self._status_from_connection(connection)
                current = cast(str, status["active_release_sha256"])
                generation = cast(int, status["generation"])
                predecessor = cast(str, status["predecessor_sha256"])
                successor = cast(str, status["successor_sha256"])
                if current != expected_current or generation != expected_generation:
                    raise Phase4DemoReleaseError("stale expected-current or generation CAS")

                reason_sha256: str | None = None
                receipt_type: str
                if action == "ACTIVATE":
                    receipt_type = "ACTIVATION"
                    if target_release_sha256 != successor:
                        raise Phase4DemoReleaseError("activation requires the exact successor")
                    if current != predecessor:
                        raise Phase4DemoReleaseError("activation requires the exact predecessor")
                    if connection.execute(
                        "SELECT 1 FROM transition_history WHERE action = 'ACTIVATE'"
                    ).fetchone():
                        raise Phase4DemoReleaseError("activation replay is forbidden")
                elif action == "ROLLBACK":
                    receipt_type = "ROLLBACK"
                    if target_release_sha256 != predecessor or current != successor:
                        raise Phase4DemoReleaseError(
                            "rollback requires the exact predecessor and successor"
                        )
                    normalized_reason = (reason or "").strip()
                    if not 1 <= len(normalized_reason) <= 300:
                        raise Phase4DemoReleaseError(
                            "rollback reason must contain 1..300 trimmed characters"
                        )
                    reason_sha256 = _sha256(normalized_reason.encode("utf-8"))
                    if not connection.execute(
                        "SELECT 1 FROM transition_history WHERE action = 'ACTIVATE'"
                    ).fetchone():
                        raise Phase4DemoReleaseError("rollback requires prior activation")
                    if connection.execute(
                        "SELECT 1 FROM transition_history WHERE action = 'ROLLBACK'"
                    ).fetchone():
                        raise Phase4DemoReleaseError("rollback replay is forbidden")
                else:
                    receipt_type = "REACTIVATION"
                    if target_release_sha256 != successor or current != predecessor:
                        raise Phase4DemoReleaseError(
                            "reactivation requires the exact successor and predecessor"
                        )
                    if not connection.execute(
                        "SELECT 1 FROM transition_history WHERE action = 'ROLLBACK'"
                    ).fetchone():
                        raise Phase4DemoReleaseError("reactivation requires prior rollback")
                    if connection.execute(
                        "SELECT 1 FROM transition_history WHERE action = 'REACTIVATE'"
                    ).fetchone():
                        raise Phase4DemoReleaseError("reactivation replay is forbidden")

                if (
                    target_release_sha256 == successor
                    and not connection.execute(
                        "SELECT 1 FROM approvals WHERE release_sha256 = ?", (successor,)
                    ).fetchone()
                ):
                    raise Phase4DemoReleaseError("successor transition requires exact approval")
                self._verify_release_payload(connection, current)
                self._verify_release_payload(connection, target_release_sha256)
                new_generation = generation + 1
                transition_facts: dict[str, object] = {
                    "action": action,
                    "target_release_sha256": target_release_sha256,
                    "previous_release_sha256": current,
                    "expected_current_sha256": expected_current,
                    "expected_generation": expected_generation,
                    "new_generation": new_generation,
                    "reason_sha256": reason_sha256,
                }
                transition_sha256 = canonical_sha256(transition_facts)
                transition_receipt = self._insert_receipt(
                    connection,
                    receipt_type=receipt_type,
                    facts={**transition_facts, "transition_sha256": transition_sha256},
                )
                connection.execute(
                    "INSERT INTO transition_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        transition_sha256,
                        action,
                        target_release_sha256,
                        current,
                        expected_current,
                        expected_generation,
                        new_generation,
                        reason_sha256,
                        transition_receipt["receipt_sha256"],
                    ),
                )
                self._pointer_mutation_allowed = True
                try:
                    changed = connection.execute(
                        "UPDATE active_pointer SET release_sha256 = ?, generation = ? "
                        "WHERE singleton = 1 AND release_sha256 = ? AND generation = ?",
                        (
                            target_release_sha256,
                            new_generation,
                            expected_current,
                            expected_generation,
                        ),
                    ).rowcount
                finally:
                    self._pointer_mutation_allowed = False
                if changed != 1:
                    raise Phase4DemoReleaseError("stale pointer compare-and-swap")
                receipts.append(transition_receipt)
                receipts.append(
                    self._insert_receipt(
                        connection,
                        receipt_type="STATUS",
                        facts=self._status_from_connection(connection),
                    )
                )
        finally:
            self._pointer_mutation_allowed = False
            connection.close()
        _require_no_sidecars(self.database_path)
        self._publish_receipts(receipts)
        return receipts[0]

    def activate_release(
        self,
        release_sha256: str,
        *,
        expected_current: str,
        expected_generation: int,
    ) -> dict[str, object]:
        return self._transition_release(
            action="ACTIVATE",
            target_release_sha256=release_sha256,
            expected_current=expected_current,
            expected_generation=expected_generation,
        )

    def rollback_release(
        self,
        release_sha256: str,
        *,
        expected_current: str,
        expected_generation: int,
        reason: str,
    ) -> dict[str, object]:
        return self._transition_release(
            action="ROLLBACK",
            target_release_sha256=release_sha256,
            expected_current=expected_current,
            expected_generation=expected_generation,
            reason=reason,
        )

    def reactivate_release(
        self,
        release_sha256: str,
        *,
        expected_current: str,
        expected_generation: int,
    ) -> dict[str, object]:
        return self._transition_release(
            action="REACTIVATE",
            target_release_sha256=release_sha256,
            expected_current=expected_current,
            expected_generation=expected_generation,
        )

    def _committed_receipt(self, receipt_type: str) -> dict[str, object]:
        connection = self._connect_read_only()
        try:
            rows = connection.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_type = ? "
                "ORDER BY receipt_ordinal",
                (receipt_type,),
            ).fetchall()
        finally:
            connection.close()
        if len(rows) != 1:
            raise Phase4DemoReleaseError(
                f"local lifecycle requires exactly one {receipt_type} receipt"
            )
        receipt = json.loads(rows[0][0])
        self.validate_local_receipt(receipt)
        if rows[0][0] != canonical_json_bytes(receipt):
            raise Phase4DemoReleaseError("local lifecycle receipt row drifted")
        return cast(dict[str, object], receipt)

    def exercise_lifecycle(self, *, final_state: Literal["successor"]) -> dict[str, object]:
        """Resume the exact local lifecycle through final reactivation."""

        if final_state != "successor":
            raise Phase4DemoReleaseError("local demo lifecycle must finish on successor")
        status = self.status(create_receipt=False)
        predecessor = cast(str, status["predecessor_sha256"])
        successor = cast(str, status["successor_sha256"])

        if (
            status["generation"] == 0
            and status["active_release_sha256"] == predecessor
            and status["transition_count"] == 0
            and status["successor_state"] == "BUILT_UNAPPROVED"
        ):
            approval = self.approve_release(successor)
            status = self.status(create_receipt=False)
        elif (
            status["generation"] == 0
            and status["active_release_sha256"] == predecessor
            and status["transition_count"] == 0
            and status["successor_state"] == "APPROVED_INACTIVE"
        ):
            approval = self._committed_receipt("APPROVAL")
        else:
            approval = self._committed_receipt("APPROVAL")

        if status["generation"] == 0 and status["active_release_sha256"] == predecessor:
            activation = self.activate_release(
                successor,
                expected_current=predecessor,
                expected_generation=0,
            )
            status = self.status(create_receipt=False)
        else:
            activation = self._committed_receipt("ACTIVATION")

        if status["generation"] == 1 and status["active_release_sha256"] == successor:
            rollback = self.rollback_release(
                predecessor,
                expected_current=successor,
                expected_generation=1,
                reason="contest demo rollback verification",
            )
            status = self.status(create_receipt=False)
        else:
            rollback = self._committed_receipt("ROLLBACK")

        if status["generation"] == 2 and status["active_release_sha256"] == predecessor:
            reactivation = self.reactivate_release(
                successor,
                expected_current=predecessor,
                expected_generation=2,
            )
        else:
            reactivation = self._committed_receipt("REACTIVATION")

        final_status = self.status(create_receipt=False)
        if (
            final_status["generation"] != 3
            or final_status["active_release_sha256"] != successor
            or final_status["transition_count"] != 3
            or final_status["successor_state"] != "ACTIVE"
        ):
            raise Phase4DemoReleaseError("local lifecycle state is not resumable")
        return {
            **final_status,
            "approval_receipt_sha256": approval["receipt_sha256"],
            "activation_receipt_sha256": activation["receipt_sha256"],
            "rollback_receipt_sha256": rollback["receipt_sha256"],
            "reactivation_receipt_sha256": reactivation["receipt_sha256"],
        }

    def pin_active(
        self,
        *,
        kind: Literal["SESSION", "RESULT"],
        owner_ref: str,
        era: str,
    ) -> dict[str, object]:
        """Copy-once pin the current local evidence release for a probe owner."""

        _require_no_production_capability()
        _require_no_sidecars(self.database_path)
        self.reconcile_private_receipts()
        if kind not in {"SESSION", "RESULT"}:
            raise Phase4DemoReleaseError("unsupported local pin kind")
        if not owner_ref or not era:
            raise Phase4DemoReleaseError("local pin owner and era are required")
        connection = self._connect_write()
        receipts: list[dict[str, object]] = []
        try:
            with self._transaction(connection):
                status = self._status_from_connection(connection)
                receipts.append(
                    self._pin(
                        connection,
                        kind=kind,
                        owner_ref=owner_ref,
                        release_sha256=cast(str, status["active_release_sha256"]),
                        generation=cast(int, status["generation"]),
                        era=era,
                    )
                )
                receipts.append(
                    self._insert_receipt(
                        connection,
                        receipt_type="STATUS",
                        facts=self._status_from_connection(connection),
                    )
                )
        finally:
            connection.close()
        _require_no_sidecars(self.database_path)
        self._publish_receipts(receipts)
        return receipts[0]

    @staticmethod
    def _require_final_transition_history(
        connection: sqlite3.Connection,
    ) -> tuple[dict[str, object], tuple[tuple[str, str, int], ...]]:
        status = Phase4DemoReleaseRepository._status_from_connection(connection)
        predecessor = cast(str, status["predecessor_sha256"])
        successor = cast(str, status["successor_sha256"])
        if not (
            status["active_release_sha256"] == successor
            and status["generation"] == 3
            and status["successor_state"] == "ACTIVE"
        ):
            raise Phase4DemoReleaseError("local lifecycle final pointer or generation drifted")
        approval = connection.execute(
            "SELECT approval_sha256, release_sha256, receipt_sha256, state FROM approvals"
        ).fetchall()
        if len(approval) != 1 or approval[0][1:] != (
            successor,
            approval[0][2],
            "APPROVED_INACTIVE",
        ):
            raise Phase4DemoReleaseError("local lifecycle exact approval drifted")
        approval_facts = {
            "release_sha256": successor,
            "predecessor_sha256": predecessor,
            "state": "APPROVED_INACTIVE",
            "active_release_sha256": predecessor,
            "generation": 0,
        }
        if approval[0][0] != canonical_sha256(approval_facts):
            raise Phase4DemoReleaseError("local lifecycle approval digest drifted")
        approval_receipt = connection.execute(
            "SELECT receipt_json FROM receipts WHERE receipt_sha256 = ? "
            "AND receipt_type = 'APPROVAL'",
            (approval[0][2],),
        ).fetchone()
        if approval_receipt is None:
            raise Phase4DemoReleaseError("local lifecycle approval receipt is absent")
        parsed_approval = json.loads(approval_receipt[0])
        if any(parsed_approval.get(key) != value for key, value in approval_facts.items()):
            raise Phase4DemoReleaseError("local lifecycle approval receipt drifted")
        if parsed_approval.get("approval_sha256") != approval[0][0]:
            raise Phase4DemoReleaseError("local lifecycle approval receipt digest drifted")

        rows = connection.execute(
            "SELECT transition_sha256, action, target_release_sha256, "
            "previous_release_sha256, expected_current_sha256, expected_generation, "
            "new_generation, reason_sha256, receipt_sha256 "
            "FROM transition_history ORDER BY new_generation"
        ).fetchall()
        expected_shape = (
            ("ACTIVATE", successor, predecessor, 0, 1, None, "ACTIVATION"),
            ("ROLLBACK", predecessor, successor, 1, 2, "REASON", "ROLLBACK"),
            ("REACTIVATE", successor, predecessor, 2, 3, None, "REACTIVATION"),
        )
        if len(rows) != len(expected_shape):
            raise Phase4DemoReleaseError("local lifecycle transition count drifted")
        for row, expected in zip(rows, expected_shape, strict=True):
            (
                transition_sha256,
                action,
                target,
                previous,
                expected_current,
                expected_generation,
                new_generation,
                reason_sha256,
                receipt_sha256,
            ) = row
            expected_action, expected_target, expected_previous, old_gen, new_gen, reason, kind = (
                expected
            )
            if not (
                action == expected_action
                and target == expected_target
                and previous == expected_previous
                and expected_current == expected_previous
                and expected_generation == old_gen
                and new_generation == new_gen
                and (
                    (reason == "REASON" and isinstance(reason_sha256, str))
                    or reason_sha256 == reason
                )
            ):
                raise Phase4DemoReleaseError("local lifecycle transition relationship drifted")
            facts = {
                "action": action,
                "target_release_sha256": target,
                "previous_release_sha256": previous,
                "expected_current_sha256": expected_current,
                "expected_generation": expected_generation,
                "new_generation": new_generation,
                "reason_sha256": reason_sha256,
            }
            if transition_sha256 != canonical_sha256(facts):
                raise Phase4DemoReleaseError("local lifecycle transition digest drifted")
            receipt_row = connection.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_sha256 = ? AND receipt_type = ?",
                (receipt_sha256, kind),
            ).fetchone()
            if receipt_row is None:
                raise Phase4DemoReleaseError("local lifecycle transition receipt is absent")
            receipt = json.loads(receipt_row[0])
            if any(receipt.get(key) != value for key, value in facts.items()):
                raise Phase4DemoReleaseError("local lifecycle transition receipt drifted")
            if receipt.get("transition_sha256") != transition_sha256:
                raise Phase4DemoReleaseError("local lifecycle transition receipt digest drifted")

        eras = (
            ("PREDECESSOR", predecessor, 0),
            ("SUCCESSOR", successor, 1),
            ("POST_ROLLBACK", predecessor, 2),
            ("FINAL", successor, 3),
        )
        return status, eras

    def ensure_lifecycle_pins(self) -> dict[str, object]:
        """Create the three post-initialization historical probe pin pairs once."""

        _require_no_production_capability()
        _require_no_sidecars(self.database_path)
        self.reconcile_private_receipts()
        connection = self._connect_write()
        published: list[dict[str, object]] = []
        try:
            _, eras = self._require_final_transition_history(connection)
            seed = cast(
                str,
                connection.execute(
                    "SELECT upstream_terminal_receipt_sha256 FROM metadata WHERE singleton = 1"
                ).fetchone()[0],
            )
            for era, release_sha256, generation in eras[1:]:
                owners = (
                    ("SESSION", f"{era.casefold()}-session:{seed}"),
                    ("RESULT", f"{era.casefold()}-result:{seed}"),
                )
                observed: list[tuple[str, tuple[object, ...] | None]] = []
                for kind, owner_ref in owners:
                    table = "session_pins" if kind == "SESSION" else "result_pins"
                    owner_sha256 = _sha256(owner_ref.encode("utf-8"))
                    row = connection.execute(
                        f"SELECT release_sha256, generation FROM {table} "
                        "WHERE owner_ref_sha256 = ?",
                        (owner_sha256,),
                    ).fetchone()
                    observed.append((kind, row))
                if all(row is not None for _, row in observed):
                    if any(row != (release_sha256, generation) for _, row in observed):
                        raise Phase4DemoReleaseError("copy-once lifecycle pin drifted")
                    continue
                if any(row is not None for _, row in observed):
                    raise Phase4DemoReleaseError("copy-once lifecycle pin pair is partial")
                receipts: list[dict[str, object]] = []
                with self._transaction(connection):
                    for kind, owner_ref in owners:
                        receipts.append(
                            self._pin(
                                connection,
                                kind=cast(Literal["SESSION", "RESULT"], kind),
                                owner_ref=owner_ref,
                                release_sha256=release_sha256,
                                generation=generation,
                                era=era,
                            )
                        )
                    receipts.append(
                        self._insert_receipt(
                            connection,
                            receipt_type="STATUS",
                            facts=self._status_from_connection(connection),
                        )
                    )
                published.extend(receipts)
        finally:
            connection.close()
        _require_no_sidecars(self.database_path)
        self._publish_receipts(published)
        return self.status(create_receipt=False)

    def verify_complete_lifecycle(self, inputs: ValidatedTerminalInputs) -> dict[str, object]:
        """Independently verify the exact final lifecycle and every pin parent."""

        database_identity_before = self._database_identity()
        initialized = self.verify_initialized(inputs)
        connection = self._connect_read_only()
        try:
            connection.execute("BEGIN")
            status, eras = self._require_final_transition_history(connection)
            expected_eras = {era: (release, generation) for era, release, generation in eras}
            receipt_rows = connection.execute(
                "SELECT receipt_sha256, receipt_type, receipt_json FROM receipts "
                "ORDER BY receipt_ordinal"
            ).fetchall()
            type_counts: dict[str, int] = {}
            receipt_inventory: list[dict[str, str]] = []
            for receipt_sha256, receipt_type, receipt_json in receipt_rows:
                receipt = json.loads(receipt_json)
                self.validate_local_receipt(receipt)
                type_counts[receipt_type] = type_counts.get(receipt_type, 0) + 1
                receipt_inventory.append(
                    {"receipt_sha256": receipt_sha256, "receipt_type": receipt_type}
                )
                if receipt_type == "STATUS":
                    generation = receipt.get("generation")
                    active = receipt.get("active_release_sha256")
                    if (generation, active) not in {
                        (0, status["predecessor_sha256"]),
                        (1, status["successor_sha256"]),
                        (2, status["predecessor_sha256"]),
                        (3, status["successor_sha256"]),
                    }:
                        raise Phase4DemoReleaseError("local lifecycle status receipt drifted")
                    for key in (
                        "upstream_terminal_receipt_sha256",
                        "terminal_report_sha256",
                        "manifest_sha256",
                        "source_truth",
                        "profile_truth",
                        "profile_score_truth",
                        "image_truth",
                        "provider_mode",
                        "terminal_decision",
                    ):
                        if receipt.get(key) != status[key]:
                            raise Phase4DemoReleaseError("local lifecycle status parent drifted")
            required_counts = {
                "BUILD": 1,
                "APPROVAL": 1,
                "ACTIVATION": 1,
                "ROLLBACK": 1,
                "REACTIVATION": 1,
                "PIN": 8,
                "STATUS": 8,
            }
            if type_counts != required_counts:
                raise Phase4DemoReleaseError("local lifecycle receipt inventory drifted")

            pin_inventory: list[dict[str, object]] = []
            for kind, table in (("SESSION", "session_pins"), ("RESULT", "result_pins")):
                rows = connection.execute(
                    f"SELECT pins.owner_ref_sha256, pins.release_sha256, pins.generation, "
                    f"pins.pin_sha256, receipts.receipt_json FROM {table} pins "
                    "JOIN receipts ON receipts.receipt_sha256 = pins.receipt_sha256 "
                    "ORDER BY pins.generation"
                ).fetchall()
                if len(rows) != 4:
                    raise Phase4DemoReleaseError("copy-once lifecycle pin count drifted")
                for owner_sha256, release_sha256, generation, pin_sha256, raw in rows:
                    receipt = json.loads(raw)
                    era = receipt.get("era")
                    if era not in expected_eras or expected_eras[era] != (
                        release_sha256,
                        generation,
                    ):
                        raise Phase4DemoReleaseError("copy-once lifecycle pin binding drifted")
                    pin_facts = {
                        "pin_kind": kind,
                        "owner_ref_sha256": owner_sha256,
                        "release_sha256": release_sha256,
                        "generation": generation,
                        "era": era,
                    }
                    if pin_sha256 != canonical_sha256(pin_facts) or any(
                        receipt.get(key) != value for key, value in pin_facts.items()
                    ):
                        raise Phase4DemoReleaseError("copy-once lifecycle pin digest drifted")
                    pin_inventory.append(
                        {
                            "pin_kind": kind,
                            "release_sha256": release_sha256,
                            "generation": generation,
                            "pin_sha256": pin_sha256,
                        }
                    )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        _require_no_sidecars(self.database_path)
        database_identity_after = self._database_identity()
        if (
            database_identity_before != database_identity_after
            or initialized["database_sha256"] != database_identity_after[-1]
        ):
            raise Phase4DemoReleaseError("local demo database changed during verification")
        return {
            **initialized,
            "receipt_count": len(receipt_inventory),
            "receipt_type_counts": dict(sorted(type_counts.items())),
            "receipt_inventory_sha256": canonical_sha256(receipt_inventory),
            "pin_inventory_sha256": canonical_sha256(
                sorted(
                    pin_inventory,
                    key=lambda row: (
                        cast(str, row["pin_kind"]),
                        cast(int, row["generation"]),
                    ),
                )
            ),
        }

    def verify_initialized(self, inputs: ValidatedTerminalInputs) -> dict[str, object]:
        _require_no_sidecars(self.database_path)
        self.reconcile_private_receipts()
        database_identity_before = self._database_identity()
        if self.database_path.stat().st_mode & 0o777 != 0o600:
            raise Phase4DemoReleaseError("local demo database mode is not 0600")
        connection = self._connect_read_only()
        try:
            connection.execute("BEGIN")
            if connection.execute("PRAGMA user_version").fetchone() != (USER_VERSION,):
                raise Phase4DemoReleaseError("local demo schema version drifted")
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise Phase4DemoReleaseError("local demo integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise Phase4DemoReleaseError("local demo foreign-key check failed")
            status = self._status_from_connection(connection)
            if not (
                status["upstream_terminal_receipt_sha256"] == inputs.terminal_receipt.receipt_sha256
                and status["terminal_report_sha256"]
                == inputs.terminal_report.terminal_report_sha256
                and status["manifest_sha256"] == inputs.manifest.manifest_sha256
                and status["predecessor_sha256"] == inputs.predecessor_sha256
                and status["successor_sha256"] == inputs.successor_sha256
            ):
                raise Phase4DemoReleaseError("local demo database parents are stale")
            for release_sha256, payload_raw in connection.execute(
                "SELECT release_sha256, payload_json FROM releases"
            ):
                payload = json.loads(payload_raw)
                if (
                    payload_raw != canonical_json_bytes(payload)
                    or canonical_sha256(payload) != release_sha256
                ):
                    raise Phase4DemoReleaseError("local demo release payload drifted")
            receipt_rows = connection.execute(
                "SELECT receipt_sha256, receipt_type, local_storage_scope, "
                "approval_authority, receipt_json FROM receipts ORDER BY receipt_ordinal"
            ).fetchall()
            for digest, receipt_type, local_scope, approval_mode, raw in receipt_rows:
                receipt = json.loads(raw)
                self.validate_local_receipt(receipt)
                if (
                    raw != canonical_json_bytes(receipt)
                    or receipt["receipt_sha256"] != digest
                    or receipt["receipt_type"] != receipt_type
                    or local_scope != LOCAL_SQLITE_MARKER
                    or approval_mode != LOCAL_APPROVAL_MARKER
                ):
                    raise Phase4DemoReleaseError("local demo receipt row drifted")
            self._verify_private_receipts()
            database_sha256 = _sha256(
                _stable_read(self.database_path, max_bytes=64 * 1024 * 1024)
            )
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        database_identity_after = self._database_identity()
        if (
            database_identity_before != database_identity_after
            or database_sha256 != database_identity_after[-1]
        ):
            raise Phase4DemoReleaseError("local demo database changed during verification")
        return {
            **status,
            "database_sha256": database_sha256,
            "integrity_check": "ok",
            "foreign_key_check_count": 0,
        }

    def _verify_private_receipts(self) -> None:
        receipt_root = self.database_path.parent / "receipts"
        if not receipt_root.is_dir() or receipt_root.is_symlink():
            raise Phase4DemoReleaseError("private receipt directory is absent")
        connection = self._connect_read_only()
        try:
            expected = {
                cast(str, digest): cast(bytes, raw)
                for digest, raw in connection.execute(
                    "SELECT receipt_sha256, receipt_json FROM receipts"
                )
            }
        finally:
            connection.close()
        observed: dict[str, bytes] = {}
        for path in receipt_root.iterdir():
            raw = _stable_read(path)
            receipt = json.loads(raw)
            self.validate_local_receipt(receipt)
            observed[cast(str, receipt["receipt_sha256"])] = raw
        if observed != expected:
            raise Phase4DemoReleaseError("private receipt files differ from SQLite receipts")


def _create_database(
    inputs: ValidatedTerminalInputs, repository: Phase4DemoReleaseRepository
) -> None:
    release_root = repository.database_path.parent
    release_root.mkdir(parents=True, exist_ok=False, mode=0o700)
    release_root.chmod(0o700)
    descriptor = os.open(
        repository.database_path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    os.close(descriptor)
    receipts: list[dict[str, object]] = []
    connection: sqlite3.Connection | None = None
    try:
        connection = repository._connect_write()
        connection.executescript(_DDL)
        with repository._transaction(connection):
            connection.execute(
                "INSERT INTO metadata VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    SCHEMA_VERSION,
                    inputs.terminal_receipt_bytes_sha256,
                    inputs.terminal_receipt.receipt_sha256,
                    inputs.terminal_report.terminal_report_sha256,
                    inputs.manifest.manifest_sha256,
                    inputs.predecessor_sha256,
                    inputs.successor_sha256,
                    inputs.manifest.source_truth,
                    inputs.manifest.profile_truth,
                    inputs.manifest.profile_score_truth,
                    inputs.manifest.image_truth,
                    inputs.terminal_receipt.provider_mode.value,
                    inputs.terminal_receipt.terminal_decision,
                ),
            )
            connection.execute(
                "INSERT INTO releases VALUES (?, 'SOURCE_EVIDENCE_PREDECESSOR', 'ACTIVE', NULL, ?)",
                (inputs.predecessor_sha256, canonical_json_bytes(inputs.predecessor_payload)),
            )
            connection.execute(
                "INSERT INTO releases VALUES (?, 'TERMINAL_EVIDENCE_SUCCESSOR', "
                "'BUILT_UNAPPROVED', ?, ?)",
                (
                    inputs.successor_sha256,
                    inputs.predecessor_sha256,
                    canonical_json_bytes(inputs.successor_payload),
                ),
            )
            connection.execute(
                "INSERT INTO active_pointer VALUES (1, ?, 0)",
                (inputs.predecessor_sha256,),
            )
            receipts.append(
                repository._insert_receipt(
                    connection,
                    receipt_type="BUILD",
                    facts={
                        "upstream_terminal_receipt_file_sha256": (
                            inputs.terminal_receipt_bytes_sha256
                        ),
                        "upstream_terminal_receipt_sha256": inputs.terminal_receipt.receipt_sha256,
                        "terminal_report_sha256": inputs.terminal_report.terminal_report_sha256,
                        "manifest_sha256": inputs.manifest.manifest_sha256,
                        "predecessor_sha256": inputs.predecessor_sha256,
                        "predecessor_state": "ACTIVE",
                        "successor_sha256": inputs.successor_sha256,
                        "successor_state": "BUILT_UNAPPROVED",
                        "source_truth": inputs.terminal_receipt.source_truth,
                        "profile_truth": inputs.terminal_receipt.profile_truth,
                        "profile_score_truth": inputs.terminal_receipt.profile_score_truth,
                        "image_truth": inputs.terminal_receipt.image_truth,
                        "provider_mode": inputs.terminal_receipt.provider_mode.value,
                        "terminal_decision": inputs.terminal_receipt.terminal_decision,
                    },
                )
            )
            seed = inputs.terminal_receipt.receipt_sha256
            receipts.append(
                repository._pin(
                    connection,
                    kind="SESSION",
                    owner_ref=f"predecessor-session:{seed}",
                    release_sha256=inputs.predecessor_sha256,
                    generation=0,
                    era="PREDECESSOR",
                )
            )
            receipts.append(
                repository._pin(
                    connection,
                    kind="RESULT",
                    owner_ref=f"predecessor-result:{seed}",
                    release_sha256=inputs.predecessor_sha256,
                    generation=0,
                    era="PREDECESSOR",
                )
            )
            status = repository._status_from_connection(connection)
            receipts.append(
                repository._insert_receipt(connection, receipt_type="STATUS", facts=status)
            )
    except BaseException:
        if connection is not None:
            connection.close()
        repository.database_path.unlink(missing_ok=True)
        for suffix in SIDECAR_SUFFIXES:
            repository.database_path.with_name(repository.database_path.name + suffix).unlink(
                missing_ok=True
            )
        raise
    else:
        assert connection is not None
        connection.close()
    repository.database_path.chmod(0o600)
    _require_no_sidecars(repository.database_path)
    repository._publish_receipts(receipts)


def initialize_demo_release(
    *, terminal_receipt_path: Path, artifact_root: Path
) -> dict[str, object]:
    """Create once or independently verify one exact local evidence lifecycle."""

    _require_no_production_capability()
    inputs = _validate_exact_terminal_parents(
        terminal_receipt_path=terminal_receipt_path,
        artifact_root=artifact_root,
    )
    repository = Phase4DemoReleaseRepository(
        database_path=inputs.run_root / "release" / DATABASE_NAME,
        run_root=inputs.run_root,
    )
    if repository.database_path.exists() or repository.database_path.is_symlink():
        if repository.database_path.is_symlink() or not repository.database_path.is_file():
            raise Phase4DemoReleaseError("local demo database path is not a regular file")
        result = repository.verify_initialized(inputs)
        return {**result, "disposition": "ALREADY_INITIALIZED_VERIFIED"}
    if repository.database_path.parent.exists() or repository.database_path.parent.is_symlink():
        raise Phase4DemoReleaseError("local demo release directory exists without its database")
    _create_database(inputs, repository)
    result = repository.verify_initialized(inputs)
    return {**result, "disposition": "CREATED"}


_FINAL_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "upstream_terminal_receipt_sha256",
        "terminal_report_sha256",
        "manifest_sha256",
        "predecessor_sha256",
        "successor_sha256",
        "active_release_sha256",
        "generation",
        "database_sha256",
        "sqlite_schema_version",
        "sqlite_user_version",
        "integrity_check",
        "foreign_key_check_count",
        "sqlite_sidecar_count",
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
        "local_storage_scope",
        "approval_authority",
        "production_mutation",
        "receipt_sha256",
    }
)


def _is_digest_valid_final_receipt(payload: bytes) -> bool:
    try:
        decoded = json.loads(payload)
        if not isinstance(decoded, dict) or set(decoded) != _FINAL_RECEIPT_KEYS:
            return False
        if canonical_json_bytes(decoded) != payload:
            return False
        Phase4DemoReleaseRepository.validate_local_receipt(decoded)
    except (json.JSONDecodeError, TypeError, ValueError, Phase4DemoReleaseError):
        return False
    return True


def _preserve_expected_conflict(*, output: Path, pending_path: Path, payload: bytes) -> None:
    conflict = output.with_name(f".{output.name}.conflict-{hashlib.sha256(payload).hexdigest()}")
    try:
        os.link(pending_path, conflict, follow_symlinks=False)
    except FileExistsError:
        if conflict.is_symlink() or _stable_read(conflict) != payload:
            raise Phase4DemoReleaseError("final receipt conflict evidence differs") from None


def _publish_final_receipt(path: Path, receipt: dict[str, object]) -> None:
    output = _require_local_path(path, label="final receipt output")
    if set(receipt) != _FINAL_RECEIPT_KEYS:
        raise Phase4DemoReleaseError("final receipt allowlist drifted")
    payload = canonical_json_bytes(receipt)
    forbidden = (
        b"artifact_root",
        b"database_path",
        b"owner_ref",
        b"payload_json",
        b"place_ref",
        b"raw_image",
        b"service_key",
        b"postgresql://",
    )
    if any(token in payload.lower() for token in forbidden):
        raise Phase4DemoReleaseError("final receipt contains a private or production field")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, pending_name = tempfile.mkstemp(
        prefix=f".{output.name}.pending-",
        suffix=".tmp",
        dir=output.parent,
    )
    pending_path = Path(pending_name)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise Phase4DemoReleaseError("final receipt write did not complete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if output.exists() or output.is_symlink():
            if output.is_symlink():
                raise Phase4DemoReleaseError(
                    "final receipt output conflicts with prior evidence"
                )
            existing = _stable_read(output)
            if existing == payload:
                return
            if _is_digest_valid_final_receipt(existing) or not payload.startswith(existing):
                _preserve_expected_conflict(
                    output=output,
                    pending_path=pending_path,
                    payload=payload,
                )
                raise Phase4DemoReleaseError(
                    "final receipt output conflicts with prior evidence"
                )
            quarantine = output.with_name(
                f".{output.name}.incomplete-{hashlib.sha256(existing).hexdigest()}"
            )
            try:
                os.link(output, quarantine, follow_symlinks=False)
            except FileExistsError:
                if quarantine.is_symlink() or _stable_read(quarantine) != existing:
                    raise Phase4DemoReleaseError(
                        "final receipt recovery evidence conflicts"
                    ) from None
            output.unlink()
        try:
            os.link(pending_path, output, follow_symlinks=False)
        except FileExistsError:
            if output.is_symlink() or _stable_read(output) != payload:
                raise Phase4DemoReleaseError(
                    "final receipt output conflicts with prior evidence"
                ) from None
        directory_descriptor = os.open(
            output.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        pending_path.unlink(missing_ok=True)


def verify_demo_release(
    *, terminal_receipt_path: Path, artifact_root: Path, receipt_output: Path
) -> dict[str, object]:
    """Verify and publish the digest-only local SQLite demo release receipt."""

    _require_no_production_capability()
    inputs = _validate_exact_terminal_parents(
        terminal_receipt_path=terminal_receipt_path,
        artifact_root=artifact_root,
    )
    repository = Phase4DemoReleaseRepository(
        database_path=inputs.run_root / "release" / DATABASE_NAME,
        run_root=inputs.run_root,
    )
    repository.ensure_lifecycle_pins()
    verified = repository.verify_complete_lifecycle(inputs)
    receipt: dict[str, object] = {
        "schema_version": "itda.phase4-demo-release-final-receipt.v1",
        "upstream_terminal_receipt_sha256": verified["upstream_terminal_receipt_sha256"],
        "terminal_report_sha256": verified["terminal_report_sha256"],
        "manifest_sha256": verified["manifest_sha256"],
        "predecessor_sha256": verified["predecessor_sha256"],
        "successor_sha256": verified["successor_sha256"],
        "active_release_sha256": verified["active_release_sha256"],
        "generation": verified["generation"],
        "database_sha256": verified["database_sha256"],
        "sqlite_schema_version": SCHEMA_VERSION,
        "sqlite_user_version": USER_VERSION,
        "integrity_check": verified["integrity_check"],
        "foreign_key_check_count": verified["foreign_key_check_count"],
        "sqlite_sidecar_count": 0,
        "receipt_count": verified["receipt_count"],
        "receipt_type_counts": verified["receipt_type_counts"],
        "receipt_inventory_sha256": verified["receipt_inventory_sha256"],
        "session_pin_count": verified["session_pin_count"],
        "result_pin_count": verified["result_pin_count"],
        "pin_inventory_sha256": verified["pin_inventory_sha256"],
        "source_truth": verified["source_truth"],
        "profile_truth": verified["profile_truth"],
        "profile_score_truth": verified["profile_score_truth"],
        "image_truth": verified["image_truth"],
        "provider_mode": verified["provider_mode"],
        "terminal_decision": verified["terminal_decision"],
        "local_storage_scope": LOCAL_SQLITE_MARKER,
        "approval_authority": LOCAL_APPROVAL_MARKER,
        "production_mutation": "NO_PRODUCTION_MUTATION",
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    repository.validate_local_receipt(receipt)
    _publish_final_receipt(receipt_output, receipt)
    return receipt


__all__ = [
    "DATABASE_NAME",
    "LOCAL_APPROVAL_MARKER",
    "LOCAL_SQLITE_MARKER",
    "Phase4DemoReleaseError",
    "Phase4DemoReleaseRepository",
    "initialize_demo_release",
    "verify_demo_release",
]
