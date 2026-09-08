"""Plan 58 restricted SQLite file-identity and empty-readiness contracts."""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from itda.contracts.sqlite_manifest_authority import (
    SQLiteManifestAuthorityError,
    verify_seal_receipt,
    verify_sqlite_file_identity,
)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _schema_dir() -> Path:
    return _repository_root() / "backend/schema/evaluation_manifest_v1"


def _receipt_path() -> Path:
    return _repository_root() / "artifacts/restricted/catalog/v2/sqlite/initialization-receipt.json"


def _database_path() -> Path:
    import json

    receipt = json.loads(_receipt_path().read_bytes())
    return _repository_root() / receipt["file_identity"]["relative_path"]


def _copy_private_database(tmp_path: Path) -> tuple[Path, Path]:
    repo_root = tmp_path / "repo"
    release = repo_root / "artifacts/restricted/catalog/v2/sqlite/releases" / ("a" * 64)
    release.mkdir(parents=True, mode=0o700)
    for parent in (
        repo_root / "artifacts/restricted/catalog/v2/sqlite",
        repo_root / "artifacts/restricted/catalog/v2/sqlite/releases",
        release,
    ):
        parent.chmod(0o700)
    database = release / "evaluation-authority.sqlite3"
    shutil.copyfile(_schema_dir() / "empty.sqlite3", database)
    database.chmod(0o600)
    return repo_root, database


def test_live_sealed_database_reverifies_without_mutation() -> None:
    database = _database_path()
    before = (
        hashlib.sha256(database.read_bytes()).hexdigest(),
        database.stat().st_dev,
        database.stat().st_ino,
        database.stat().st_size,
        database.stat().st_mtime_ns,
    )

    root = _repository_root()
    restricted = root / "artifacts/restricted/catalog/v2/sqlite"
    receipt = verify_seal_receipt(
        repo_root=_repository_root(),
        schema_dir=_schema_dir(),
        receipt_path=_receipt_path(),
        materialized_bundle_path=root
        / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
        split_approval_path=root / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
        state_path=restricted / "seal-state-attestation.json",
        issuance_context_path=restricted / "seal-issuance-context.json",
        request_path=root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
        seal_receipt_path=restricted / "real-manifest-seal-receipt.json",
    )

    after = (
        hashlib.sha256(database.read_bytes()).hexdigest(),
        database.stat().st_dev,
        database.stat().st_ino,
        database.stat().st_size,
        database.stat().st_mtime_ns,
    )
    assert receipt.counts == {"blind": 12, "dev": 24, "total": 36}
    assert receipt.integrity_check == "ok"
    assert receipt.foreign_key_check_count == 0
    assert receipt.sidecars == {"journal": False, "shm": False, "wal": False}
    assert before == after


def test_file_identity_rejects_hardlink_mode_replacement_and_path_escape(
    tmp_path: Path,
) -> None:
    repo_root, database = _copy_private_database(tmp_path)
    identity = verify_sqlite_file_identity(repo_root=repo_root, database_path=database)

    hardlink = database.with_name("second-link.sqlite3")
    os.link(database, hardlink)
    try:
        with pytest.raises(SQLiteManifestAuthorityError, match="link|identity"):
            verify_sqlite_file_identity(
                repo_root=repo_root,
                database_path=database,
                expected_identity=identity,
            )
    finally:
        hardlink.unlink()

    database.chmod(0o640)
    with pytest.raises(SQLiteManifestAuthorityError, match="0600|mode"):
        verify_sqlite_file_identity(repo_root=repo_root, database_path=database)
    database.chmod(0o600)

    original = database.read_bytes()
    database.unlink()
    database.write_bytes(original)
    database.chmod(0o600)
    with pytest.raises(SQLiteManifestAuthorityError, match="identity|inode"):
        verify_sqlite_file_identity(
            repo_root=repo_root,
            database_path=database,
            expected_identity=identity,
        )

    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(original)
    outside.chmod(0o600)
    with pytest.raises(SQLiteManifestAuthorityError, match="repository|restricted|path"):
        verify_sqlite_file_identity(repo_root=repo_root, database_path=outside)


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_unexpected_sidecars_fail_closed_and_are_never_deleted(tmp_path: Path, suffix: str) -> None:
    repo_root, database = _copy_private_database(tmp_path)
    sidecar = database.with_name(database.name + suffix)
    sidecar.write_bytes(b"preserve-recovery-evidence")
    sidecar.chmod(0o600)

    with pytest.raises(SQLiteManifestAuthorityError, match="sidecar"):
        verify_sqlite_file_identity(repo_root=repo_root, database_path=database)

    assert sidecar.read_bytes() == b"preserve-recovery-evidence"
