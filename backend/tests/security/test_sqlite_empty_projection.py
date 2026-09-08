"""Security and behavior contract for the tracked empty SQLite projection."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import sqlite3
import subprocess
import urllib.request
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.contracts.sqlite_manifest_authority import (
    APPLICATION_ID,
    APPLICATION_ID_HEX,
    APPLICATION_ID_REGISTRY_SHA256,
    RESEARCH_ATTESTATION_SHA256,
    ApplicationIdCollisionProof,
    SQLiteEmptyProof,
    SQLiteLogicalSchemaManifest,
    SQLiteManifestAuthorityError,
    build_tracked_empty_projection,
    verify_application_id_collision,
    verify_empty_projection,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PHASE_DIR = (
    REPOSITORY_ROOT
    / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
)
PLANNING_REGISTRY = PHASE_DIR / "02-SQLITE-APPLICATION-IDS-2026-08-02.txt"
RESEARCH = PHASE_DIR / "02-SQLITE-TRANSITION-RESEARCH.md"
SCHEMA_DIR = REPOSITORY_ROOT / "backend/schema/evaluation_manifest_v1"
SCHEMA_FILE_ALLOWLIST = {
    "empty-proof.json",
    "empty.sqlite3",
    "logical-schema-manifest.json",
    "schema.sql",
    "sqlite-application-ids-2026-08-02.txt",
}
EXPECTED_TABLES = {
    "artifact_metadata",
    "authority_consumptions",
    "manifest_members",
    "manifest_seals",
}
EXPECTED_INDEXES = {
    "idx_authority_consumptions_request",
    "idx_manifest_members_split",
    "ux_manifest_members_version_place",
    "ux_manifest_seals_logical_seal",
}
EXPECTED_TRIGGERS = {
    f"trg_{table}_{operation}_immutable"
    for table in EXPECTED_TABLES
    for operation in ("delete", "update")
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_registry(tmp_path: Path, payload: bytes) -> Path:
    path = tmp_path / "magic.txt"
    path.write_bytes(payload)
    return path


def _verify_fixture(path: Path, *, expected_sha256: str) -> ApplicationIdCollisionProof:
    return verify_application_id_collision(
        path,
        research_path=RESEARCH,
        expected_registry_sha256=expected_sha256,
        expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
        as_of=date(2026, 8, 2),
    )


def test_audited_registry_proves_fixed_application_id_absent_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def deny_network(*_args: object, **_kwargs: object) -> None:
        calls.append("network")
        raise AssertionError("application-id verification attempted network access")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    monkeypatch.setattr(urllib.request, "urlopen", deny_network)

    proof = verify_application_id_collision(
        PLANNING_REGISTRY,
        research_path=RESEARCH,
        expected_registry_sha256=APPLICATION_ID_REGISTRY_SHA256,
        expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
        as_of=date(2026, 8, 2),
    )

    assert calls == []
    assert proof.application_id == APPLICATION_ID
    assert proof.application_id_hex == APPLICATION_ID_HEX
    assert proof.application_id_collision is False
    assert proof.status == "ABSENT"
    assert proof.application_id_registry_sha256 == APPLICATION_ID_REGISTRY_SHA256
    assert proof.research_attestation_sha256 == RESEARCH_ATTESTATION_SHA256
    assert proof.valid_through == date(2026, 9, 1)


def test_collision_malformed_duplicate_digest_drift_and_expiry_fail_closed(
    tmp_path: Path,
) -> None:
    root = b"0 string =SQLite\\ format\\ 3\n"
    fallback = b">0 string =SQLite SQLite3 database\n"
    collision = root + b">68 belong =0x49544441 Conflicting application\n" + fallback
    with pytest.raises(SQLiteManifestAuthorityError, match="collision"):
        _verify_fixture(_write_registry(tmp_path, collision), expected_sha256=_sha256(collision))

    malformed = root + b">68 belong not-a-hex-row\n" + fallback
    with pytest.raises(SQLiteManifestAuthorityError, match="malformed"):
        _verify_fixture(_write_registry(tmp_path, malformed), expected_sha256=_sha256(malformed))

    duplicated = (
        root
        + b">68 belong =0x0f055112 First\n"
        + b">68 belong =0x0f055112 Duplicate\n"
        + fallback
    )
    with pytest.raises(SQLiteManifestAuthorityError, match="duplicate"):
        _verify_fixture(_write_registry(tmp_path, duplicated), expected_sha256=_sha256(duplicated))

    with pytest.raises(SQLiteManifestAuthorityError, match="digest"):
        verify_application_id_collision(
            PLANNING_REGISTRY,
            research_path=RESEARCH,
            expected_registry_sha256="0" * 64,
            expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
            as_of=date(2026, 8, 2),
        )
    with pytest.raises(SQLiteManifestAuthorityError, match="expired"):
        verify_application_id_collision(
            PLANNING_REGISTRY,
            research_path=RESEARCH,
            expected_registry_sha256=APPLICATION_ID_REGISTRY_SHA256,
            expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
            as_of=date(2026, 9, 2),
        )


def test_research_digest_drift_and_network_capability_are_rejected(tmp_path: Path) -> None:
    drifted_research = tmp_path / "research.md"
    drifted_research.write_bytes(RESEARCH.read_bytes() + b"\n")
    with pytest.raises(SQLiteManifestAuthorityError, match="research attestation digest"):
        verify_application_id_collision(
            PLANNING_REGISTRY,
            research_path=drifted_research,
            expected_registry_sha256=APPLICATION_ID_REGISTRY_SHA256,
            expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
            as_of=date(2026, 8, 2),
        )
    with pytest.raises(SQLiteManifestAuthorityError, match="network"):
        verify_application_id_collision(
            PLANNING_REGISTRY,
            research_path=RESEARCH,
            expected_registry_sha256=APPLICATION_ID_REGISTRY_SHA256,
            expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
            as_of=date(2026, 8, 2),
            network_capability=object(),
        )


def test_collision_proof_is_strict_and_membership_free() -> None:
    proof = verify_application_id_collision(
        PLANNING_REGISTRY,
        research_path=RESEARCH,
        expected_registry_sha256=APPLICATION_ID_REGISTRY_SHA256,
        expected_research_sha256=RESEARCH_ATTESTATION_SHA256,
        as_of=date(2026, 8, 2),
    )
    payload = proof.model_dump(mode="json")
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()
    assert not {"dev_members", "blind_members", "members", "ordered_ids"}.intersection(payload)
    assert "canonical_place_id" not in serialized
    assert "dev_members" not in serialized
    assert "blind_members" not in serialized

    with pytest.raises(ValidationError):
        ApplicationIdCollisionProof.model_validate(
            {**payload, "dev_members": ["synthetic-forbidden-member"]}
        )


def _load_manifest() -> SQLiteLogicalSchemaManifest:
    return SQLiteLogicalSchemaManifest.model_validate_json(
        (SCHEMA_DIR / "logical-schema-manifest.json").read_bytes()
    )


def _load_proof() -> SQLiteEmptyProof:
    return SQLiteEmptyProof.model_validate_json((SCHEMA_DIR / "empty-proof.json").read_bytes())


def _schema_names(kind: str) -> set[str]:
    return {
        row.name
        for row in _load_manifest().ordered_schema_objects
        if row.object_type == kind
    }


def test_canonical_ddl_and_logical_manifest_have_exact_closed_inventory() -> None:
    ddl = (SCHEMA_DIR / "schema.sql").read_text(encoding="utf-8")
    assert "\r" not in ddl
    assert not ddl.startswith("\ufeff")
    assert _schema_names("table") == EXPECTED_TABLES
    assert _schema_names("index") == EXPECTED_INDEXES
    assert _schema_names("trigger") == EXPECTED_TRIGGERS
    assert _schema_names("view") == set()
    assert "AUTOINCREMENT" not in ddl.upper()
    assert "SQLALCHEMY" not in ddl.upper()
    assert "ALEMBIC" not in ddl.upper()
    assert "SECURITY DEFINER" not in ddl.upper()
    assert "ON DELETE RESTRICT" in ddl
    assert "CHECK (split IN ('DEV', 'BLIND'))" in ddl
    assert "member_ordinal BETWEEN 1 AND 24" in ddl
    assert "member_ordinal BETWEEN 25 AND 36" in ddl
    assert "PRIMARY KEY (manifest_version, member_ordinal)" in ddl


def test_tracked_projection_is_schema_exact_empty_clean_and_sidecar_free() -> None:
    proof = verify_empty_projection(SCHEMA_DIR)
    recorded = _load_proof()
    manifest = _load_manifest()
    assert proof == recorded
    assert proof.logical_schema_sha256 == manifest.logical_schema_sha256
    assert proof.ddl_sha256 == manifest.ddl_sha256
    assert proof.application_id == APPLICATION_ID
    assert proof.user_version == 1
    assert proof.effective_pragmas == {
        "foreign_keys": 1,
        "journal_mode": "delete",
        "query_only": 1,
        "trusted_schema": 0,
    }
    assert proof.row_counts == {table: 0 for table in sorted(EXPECTED_TABLES)}
    assert proof.freelist_count == 0
    assert proof.integrity_check == "ok"
    assert proof.foreign_key_check_count == 0
    assert proof.sqlite_sequence_present is False
    assert proof.unexpected_schema_objects == ()
    assert proof.sidecars == {"journal": False, "shm": False, "wal": False}

    database = SCHEMA_DIR / "empty.sqlite3"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, autocommit=True)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        assert connection.execute("PRAGMA application_id").fetchone() == (APPLICATION_ID,)
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
        assert connection.execute("PRAGMA trusted_schema").fetchone() == (0,)
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for table in sorted(EXPECTED_TABLES):
            assert connection.execute(f'SELECT count(*) FROM "{table}"').fetchone() == (0,)
    finally:
        connection.close()


def test_logical_schema_is_authoritative_and_binary_hash_is_projection_only() -> None:
    manifest = _load_manifest()
    proof = _load_proof()
    database_bytes = (SCHEMA_DIR / "empty.sqlite3").read_bytes()
    assert proof.empty_file_identity.sha256 == hashlib.sha256(database_bytes).hexdigest()
    assert proof.empty_file_identity.size_bytes == len(database_bytes)
    assert proof.logical_schema_sha256 == manifest.logical_schema_sha256
    assert proof.empty_file_identity.sha256 != proof.logical_schema_sha256
    assert proof.binary_authoritative is False
    assert manifest.logical_schema_authoritative is True


def test_projection_rebuild_uses_new_exclusive_file_and_same_logical_schema(
    tmp_path: Path,
) -> None:
    schema_dir = tmp_path / "schema"
    schema_dir.mkdir()
    shutil.copyfile(SCHEMA_DIR / "schema.sql", schema_dir / "schema.sql")
    shutil.copyfile(
        SCHEMA_DIR / "sqlite-application-ids-2026-08-02.txt",
        schema_dir / "sqlite-application-ids-2026-08-02.txt",
    )
    manifest, proof = build_tracked_empty_projection(
        schema_dir,
        research_path=RESEARCH,
        as_of=date(2026, 8, 2),
    )
    assert manifest.logical_schema_sha256 == _load_manifest().logical_schema_sha256
    assert verify_empty_projection(schema_dir) == proof
    assert proof.row_counts == {table: 0 for table in sorted(EXPECTED_TABLES)}
    with pytest.raises(SQLiteManifestAuthorityError, match="already exists"):
        build_tracked_empty_projection(
            schema_dir,
            research_path=RESEARCH,
            as_of=date(2026, 8, 2),
        )


def test_empty_verifier_rejects_rows_schema_drift_sidecars_and_binary_tamper(
    tmp_path: Path,
) -> None:
    def copy_schema(name: str) -> Path:
        destination = tmp_path / name
        shutil.copytree(SCHEMA_DIR, destination)
        return destination

    row_dir = copy_schema("row")
    with sqlite3.connect(row_dir / "empty.sqlite3", autocommit=True) as connection:
        connection.execute(
            "INSERT INTO artifact_metadata(metadata_key, metadata_value) VALUES (?, ?)",
            ("synthetic-key", "synthetic-value"),
        )
    with pytest.raises(SQLiteManifestAuthorityError, match="row count|file digest"):
        verify_empty_projection(row_dir)

    schema_drift_dir = copy_schema("schema-drift")
    with sqlite3.connect(schema_drift_dir / "empty.sqlite3", autocommit=True) as connection:
        connection.execute("CREATE VIEW unexpected_view AS SELECT 1 AS value")
    with pytest.raises(SQLiteManifestAuthorityError, match="schema|file digest"):
        verify_empty_projection(schema_drift_dir)

    sidecar_dir = copy_schema("sidecar")
    (sidecar_dir / "empty.sqlite3-wal").write_bytes(b"synthetic-sidecar")
    with pytest.raises(SQLiteManifestAuthorityError, match="sidecar"):
        verify_empty_projection(sidecar_dir)

    tamper_dir = copy_schema("tamper")
    with (tamper_dir / "empty.sqlite3").open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(SQLiteManifestAuthorityError, match="file digest"):
        verify_empty_projection(tamper_dir)


def test_manifest_and_proof_contracts_reject_membership_fields() -> None:
    manifest_payload = json.loads((SCHEMA_DIR / "logical-schema-manifest.json").read_bytes())
    proof_payload = json.loads((SCHEMA_DIR / "empty-proof.json").read_bytes())
    for model, payload in (
        (SQLiteLogicalSchemaManifest, manifest_payload),
        (SQLiteEmptyProof, proof_payload),
    ):
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()
        assert "dev_members" not in serialized
        assert "blind_members" not in serialized
        with pytest.raises(ValidationError):
            model.model_validate({**payload, "blind_members": ["synthetic-forbidden-member"]})


def test_schema_directory_and_git_candidates_are_strictly_allowlisted() -> None:
    assert {path.name for path in SCHEMA_DIR.iterdir()} == SCHEMA_FILE_ALLOWLIST
    assert not any(
        path.name.endswith(("-journal", "-wal", "-shm"))
        for path in SCHEMA_DIR.iterdir()
    )
    completed = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "backend/schema/evaluation_manifest_v1",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    candidates = {Path(line).name for line in completed.stdout.splitlines() if line}
    assert candidates == SCHEMA_FILE_ALLOWLIST

    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    sqlite_signatures: list[str] = []
    for raw_path in tracked:
        if not raw_path:
            continue
        path = REPOSITORY_ROOT / raw_path.decode("utf-8")
        if path.is_file() and path.read_bytes()[:16] == b"SQLite format 3\x00":
            sqlite_signatures.append(path.relative_to(REPOSITORY_ROOT).as_posix())
    if (SCHEMA_DIR / "empty.sqlite3").is_file() and (
        "backend/schema/evaluation_manifest_v1/empty.sqlite3" not in sqlite_signatures
    ):
        sqlite_signatures.append("backend/schema/evaluation_manifest_v1/empty.sqlite3")
    assert sqlite_signatures == ["backend/schema/evaluation_manifest_v1/empty.sqlite3"]
