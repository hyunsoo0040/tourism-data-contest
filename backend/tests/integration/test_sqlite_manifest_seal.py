"""Plan 58 SQLite seal serialization and exact-existing recovery contracts."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import itda.contracts.sqlite_manifest_authority as sqlite_authority
from itda.contracts.sqlite_manifest_authority import (
    SQLiteRestrictedFileIdentity,
    SQLiteSealReadiness,
    classify_sqlite_seal_state,
    derive_logical_seal_sha256,
)


def _schema_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "schema/evaluation_manifest_v1"


def _new_database(tmp_path: Path) -> Path:
    path = tmp_path / "race.sqlite3"
    path.write_bytes((_schema_dir() / "empty.sqlite3").read_bytes())
    path.chmod(0o600)
    return path


def _seal_inputs() -> tuple[dict[str, object], tuple[dict[str, object], ...], str]:
    members = tuple(
        {
            "member_ordinal": ordinal,
            "canonical_place_id": f"synthetic-place-{ordinal:02d}",
            "split": "DEV" if ordinal <= 24 else "BLIND",
        }
        for ordinal in range(1, 37)
    )
    seal = {
        "manifest_version": "real-v1",
        "catalog_sha256": "4" * 64,
        "split_sha256": "5" * 64,
        "membership_sha256": "6" * 64,
        "canonicalization_version": "itda-canonical-json-v1",
        "dev_count": 24,
        "blind_count": 12,
        "total_count": 36,
        "sealed_at_utc": "2026-08-02T14:00:00Z",
    }
    request_sha256 = "1" * 64
    logical = derive_logical_seal_sha256(
        logical_schema_sha256="7" * 64,
        seal=seal,
        ordered_members=members,
        authority_request_sha256=request_sha256,
    )
    return seal, members, logical


def _insert_exact_seal(
    connection: sqlite3.Connection,
    *,
    request_sha256: str,
    nonce_sha256: str,
) -> None:
    seal, members, logical = _seal_inputs()
    connection.execute(
        "INSERT INTO manifest_seals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            seal["manifest_version"],
            seal["catalog_sha256"],
            seal["split_sha256"],
            seal["membership_sha256"],
            request_sha256,
            "7" * 64,
            logical,
            seal["canonicalization_version"],
            seal["dev_count"],
            seal["blind_count"],
            seal["total_count"],
            seal["sealed_at_utc"],
        ),
    )
    connection.executemany(
        "INSERT INTO manifest_members VALUES (?, ?, ?, ?)",
        [
            (
                seal["manifest_version"],
                member["member_ordinal"],
                member["canonical_place_id"],
                member["split"],
            )
            for member in members
        ],
    )
    connection.execute(
        "INSERT INTO authority_consumptions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            seal["manifest_version"],
            "8" * 64,
            nonce_sha256,
            "9" * 64,
            request_sha256,
            "a" * 64,
            "b" * 64,
            "c" * 64,
            logical,
            "phase2-sqlite-sealer",
            seal["sealed_at_utc"],
        ),
    )


def test_begin_immediate_allows_one_writer_and_never_consumes_competing_nonce(
    tmp_path: Path,
) -> None:
    database = _new_database(tmp_path)
    request_a, nonce_a, nonce_b = "1" * 64, "2" * 64, "3" * 64
    acquired = threading.Event()
    release = threading.Event()
    competitor: dict[str, object] = {}

    def writer_a() -> None:
        connection = sqlite3.connect(database, timeout=0.25, autocommit=True)
        connection.execute("PRAGMA busy_timeout=250")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN IMMEDIATE")
        acquired.set()
        release.wait(timeout=2)
        _insert_exact_seal(
            connection,
            request_sha256=request_a,
            nonce_sha256=nonce_a,
        )
        connection.execute("COMMIT")
        connection.close()

    def writer_b() -> None:
        assert acquired.wait(timeout=2)
        connection = sqlite3.connect(database, timeout=0.10, autocommit=True)
        connection.execute("PRAGMA busy_timeout=100")
        started = time.monotonic()
        try:
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            competitor["error"] = exc.sqlite_errorname
            competitor["elapsed"] = time.monotonic() - started
        else:
            competitor["error"] = "UNEXPECTED_SUCCESS"
            connection.execute("ROLLBACK")
        finally:
            connection.close()

    first = threading.Thread(target=writer_a)
    second = threading.Thread(target=writer_b)
    first.start()
    assert acquired.wait(timeout=2)
    second.start()
    second.join(timeout=2)
    release.set()
    first.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert competitor["error"] == "SQLITE_BUSY"
    assert float(competitor["elapsed"]) < 0.5

    connection = sqlite3.connect(database, autocommit=True)
    try:
        counts = {
            "seals": connection.execute("SELECT count(*) FROM manifest_seals").fetchone()[0],
            "members": connection.execute("SELECT count(*) FROM manifest_members").fetchone()[0],
            "consumptions": connection.execute(
                "SELECT count(*) FROM authority_consumptions"
            ).fetchone()[0],
        }
        consumed = {
            row[0]
            for row in connection.execute(
                "SELECT nonce_sha256 FROM authority_consumptions"
            ).fetchall()
        }
    finally:
        connection.close()
    assert counts == {"seals": 1, "members": 36, "consumptions": 1}
    assert consumed == {nonce_a}
    assert nonce_b not in consumed


def test_exact_committed_recovery_is_zero_write_and_conflicts_stay_closed(
    tmp_path: Path,
) -> None:
    database = _new_database(tmp_path)
    request_sha256, nonce_sha256 = "1" * 64, "2" * 64
    connection = sqlite3.connect(database, autocommit=True)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("BEGIN IMMEDIATE")
    _insert_exact_seal(
        connection,
        request_sha256=request_sha256,
        nonce_sha256=nonce_sha256,
    )
    connection.execute("COMMIT")
    connection.close()
    before = (database.read_bytes(), database.stat().st_mtime_ns, database.stat().st_size)
    _, _, logical = _seal_inputs()

    ro = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True, autocommit=True)
    try:
        exact = classify_sqlite_seal_state(
            ro,
            manifest_version="real-v1",
            expected_request_sha256=request_sha256,
            expected_nonce_sha256=nonce_sha256,
            expected_logical_seal_sha256=logical,
        )
        replayed = classify_sqlite_seal_state(
            ro,
            manifest_version="real-v1",
            expected_request_sha256=request_sha256,
            expected_nonce_sha256="3" * 64,
            expected_logical_seal_sha256=logical,
        )
        different = classify_sqlite_seal_state(
            ro,
            manifest_version="real-v1",
            expected_request_sha256="4" * 64,
            expected_nonce_sha256=nonce_sha256,
            expected_logical_seal_sha256=logical,
        )
    finally:
        ro.close()

    after = (database.read_bytes(), database.stat().st_mtime_ns, database.stat().st_size)
    assert exact.classification == "EXACT_COMMITTED"
    assert replayed.classification == "CONFLICTING"
    assert different.classification == "CONFLICTING"
    assert exact.counts == {
        "authority_consumptions": 1,
        "manifest_members": 36,
        "manifest_seals": 1,
    }
    assert before == after


def test_live_database_is_exact_committed_and_read_only_replay_is_unmodified() -> None:
    root = Path(__file__).resolve().parents[3]
    receipt = json.loads(
        (root / "artifacts/restricted/catalog/v2/sqlite/initialization-receipt.json").read_bytes()
    )
    database = root / receipt["file_identity"]["relative_path"]
    before = (
        database.read_bytes(),
        database.stat().st_ino,
        database.stat().st_mtime_ns,
        database.stat().st_size,
    )

    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True, autocommit=True)
    try:
        counts = {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("authority_consumptions", "manifest_members", "manifest_seals")
        }
    finally:
        connection.close()

    assert counts == {
        "authority_consumptions": 1,
        "manifest_members": 36,
        "manifest_seals": 1,
    }
    assert before == (
        database.read_bytes(),
        database.stat().st_ino,
        database.stat().st_mtime_ns,
        database.stat().st_size,
    )


def _consumer_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Any, datetime]:
    root = tmp_path / "repo"
    release = root / "artifacts/restricted/catalog/v2/sqlite/releases" / ("a" * 64)
    release.mkdir(parents=True, mode=0o700)
    for parent in (
        root / "artifacts/restricted/catalog/v2/sqlite",
        root / "artifacts/restricted/catalog/v2/sqlite/releases",
        release,
    ):
        parent.chmod(0o700)
    database = release / "evaluation-authority.sqlite3"
    database.write_bytes((_schema_dir() / "empty.sqlite3").read_bytes())
    database.chmod(0o600)
    identity = sqlite_authority.verify_sqlite_file_identity(
        repo_root=root,
        database_path=database,
    )
    readiness = SQLiteSealReadiness(
        initialization_receipt_sha256="1" * 64,
        initialization_receipt_receipt_sha256="2" * 64,
        initialized_file_sha256=identity.sha256,
        ddl_sha256="3" * 64,
        logical_schema_manifest_sha256="4" * 64,
        logical_schema_sha256="5" * 64,
        split_approval_sha256="6" * 64,
        split_approval_receipt_sha256="7" * 64,
        empty_counts={
            "authority_consumptions": 0,
            "manifest_members": 0,
            "manifest_seals": 0,
        },
        effective_pragmas={
            "foreign_keys": 1,
            "journal_mode": "delete",
            "query_only": 1,
            "trusted_schema": 0,
        },
        sidecars={"journal": False, "shm": False, "wal": False},
        file_identity=SQLiteRestrictedFileIdentity.model_validate(identity.model_dump()),
    )
    members = tuple(
        {
            "member_ordinal": ordinal,
            "canonical_place_id": f"synthetic-place-{ordinal:02d}",
            "split": "DEV" if ordinal <= 24 else "BLIND",
        }
        for ordinal in range(1, 37)
    )
    issued_at = datetime(2026, 8, 2, 15, 0, tzinfo=UTC)
    state, request, issuance = sqlite_authority._derive_seal_authority(
        readiness=readiness,
        active_bindings_sha256="8" * 64,
        active_parents={
            "catalog_revision_sha256": "9" * 64,
            "catalog_activation_event_sha256": "a" * 64,
        },
        split_approval_sha256="6" * 64,
        split_approval_receipt_sha256="7" * 64,
        split_manifest_sha256="b" * 64,
        determinism_report_sha256="c" * 64,
        split_replay_sha256="d" * 64,
        membership_sha256="e" * 64,
        logical_seal_input_sha256=sqlite_authority.derive_logical_seal_input_sha256(
            logical_schema_sha256="5" * 64,
            catalog_revision_sha256="9" * 64,
            split_manifest_sha256="b" * 64,
            membership_sha256="e" * 64,
            ordered_members=members,
        ),
        reviewer_id="phase2-sqlite-sealer",
        nonce="f" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=2),
    )
    monkeypatch.setattr(
        sqlite_authority,
        "_load_persisted_seal_inputs",
        lambda **_: (state, request, issuance, None, members, database),
    )
    receipt = root / "artifacts/restricted/catalog/v2/sqlite/real-manifest-seal-receipt.json"
    return root, receipt, issuance, issued_at


def test_full_consumer_seals_once_and_recovers_exact_commit_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, receipt_path, issuance, issued_at = _consumer_fixture(tmp_path, monkeypatch)
    token = issuance.expected_token().serialize()
    kwargs = {
        "raw_token": token,
        "repo_root": root,
        "schema_dir": _schema_dir(),
        "receipt_path": tmp_path / "ignored-initialization-receipt.json",
        "materialized_bundle_path": tmp_path / "ignored-bundle.json",
        "split_approval_path": tmp_path / "ignored-approval.json",
        "state_path": tmp_path / "ignored-state.json",
        "issuance_context_path": tmp_path / "ignored-issuance.json",
        "request_path": tmp_path / "ignored-request.json",
        "seal_receipt_output": receipt_path,
        "now": issued_at + timedelta(minutes=1),
    }
    first = sqlite_authority.seal_restricted_manifest(**kwargs)
    assert first.publication_disposition == "PUBLISHED"
    database = next((root / "artifacts/restricted/catalog/v2/sqlite/releases").glob("*/*.sqlite3"))
    before = database.read_bytes()
    before_stat = database.stat()
    existing_verified = sqlite_authority.seal_restricted_manifest(**kwargs)
    assert existing_verified == first
    assert database.read_bytes() == before
    receipt_path.unlink()

    recovered = sqlite_authority.seal_restricted_manifest(**kwargs)
    after_stat = database.stat()
    assert recovered.publication_disposition == "ALREADY_COMMITTED_VERIFIED"
    assert database.read_bytes() == before
    assert (after_stat.st_size, after_stat.st_mtime_ns) == (
        before_stat.st_size,
        before_stat.st_mtime_ns,
    )


def test_full_consumer_rejects_partial_relation_without_receipt_or_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, receipt_path, issuance, issued_at = _consumer_fixture(tmp_path, monkeypatch)
    database = next((root / "artifacts/restricted/catalog/v2/sqlite/releases").glob("*/*.sqlite3"))
    connection = sqlite3.connect(database, autocommit=True)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO manifest_seals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "catalog-v2-real-split-v1",
                "9" * 64,
                "b" * 64,
                "e" * 64,
                "1" * 64,
                "5" * 64,
                "2" * 64,
                "itda-canonical-json-v1",
                24,
                12,
                36,
                "2026-08-02T15:01:00Z",
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    before = database.read_bytes()

    with pytest.raises(
        sqlite_authority.SQLiteManifestAuthorityError,
        match="repair is forbidden",
    ):
        sqlite_authority.seal_restricted_manifest(
            raw_token=issuance.expected_token().serialize(),
            repo_root=root,
            schema_dir=_schema_dir(),
            receipt_path=tmp_path / "ignored-initialization-receipt.json",
            materialized_bundle_path=tmp_path / "ignored-bundle.json",
            split_approval_path=tmp_path / "ignored-approval.json",
            state_path=tmp_path / "ignored-state.json",
            issuance_context_path=tmp_path / "ignored-issuance.json",
            request_path=tmp_path / "ignored-request.json",
            seal_receipt_output=receipt_path,
            now=issued_at + timedelta(minutes=1),
        )
    assert not receipt_path.exists()
    assert database.read_bytes() == before
