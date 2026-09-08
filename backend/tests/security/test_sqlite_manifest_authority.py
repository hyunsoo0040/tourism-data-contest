"""Plan 58 seal-readiness and closed state-classifier contracts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.contracts.authority import AuthorityIssuanceContext
from itda.contracts.sqlite_manifest_authority import (
    SQLiteSealReadiness,
    SQLiteSealReceipt,
    SQLiteSealRequest,
    SQLiteSealState,
    check_seal_request,
    classify_sqlite_seal_state,
    verify_seal_receipt,
)
from itda.domain.canonical import canonical_json_bytes


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _schema_dir() -> Path:
    return _repository_root() / "backend/schema/evaluation_manifest_v1"


def _receipt_path() -> Path:
    return _repository_root() / "artifacts/restricted/catalog/v2/sqlite/initialization-receipt.json"


def _database_path() -> Path:
    receipt = json.loads(_receipt_path().read_bytes())
    return _repository_root() / receipt["file_identity"]["relative_path"]


def _empty_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, autocommit=True)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def test_live_seal_receipt_binds_file_schema_and_approved_parent() -> None:
    root = _repository_root()
    restricted = root / "artifacts/restricted/catalog/v2/sqlite"
    receipt = verify_seal_receipt(
        repo_root=root,
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
    receipt_bytes = _receipt_path().read_bytes()
    approval_bytes = (
        _repository_root() / "artifacts/restricted/catalog/v2/split/real-split-approval.json"
    ).read_bytes()

    import hashlib

    assert isinstance(receipt, SQLiteSealReceipt)
    assert receipt.initialization_receipt_sha256 == hashlib.sha256(receipt_bytes).hexdigest()
    assert receipt.split_approval_sha256 == hashlib.sha256(approval_bytes).hexdigest()
    assert receipt.initialized_file_sha256 == json.loads(receipt_bytes)["file_identity"]["sha256"]
    assert receipt.logical_schema_sha256 == (
        "08248cb4637fd51e748af86b5112676efdeda573afd199c546ccb6d1905dfdf7"
    )


def test_empty_database_classifies_exact_unsealed_and_partial_is_closed(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    database.write_bytes((_schema_dir() / "empty.sqlite3").read_bytes())
    connection = _empty_connection(database)
    try:
        state = classify_sqlite_seal_state(
            connection,
            manifest_version="real-v1",
            expected_request_sha256="1" * 64,
            expected_nonce_sha256="2" * 64,
            expected_logical_seal_sha256="3" * 64,
        )
        assert isinstance(state, SQLiteSealState)
        assert state.classification == "EXACT_UNSEALED"

        connection.execute(
            "INSERT INTO manifest_seals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "real-v1",
                "4" * 64,
                "5" * 64,
                "6" * 64,
                "1" * 64,
                "7" * 64,
                "3" * 64,
                "itda-canonical-json-v1",
                24,
                12,
                36,
                "2026-08-02T14:00:00Z",
            ),
        )
        partial = classify_sqlite_seal_state(
            connection,
            manifest_version="real-v1",
            expected_request_sha256="1" * 64,
            expected_nonce_sha256="2" * 64,
            expected_logical_seal_sha256="3" * 64,
        )
        assert partial.classification == "PARTIAL"
        assert partial.counts == {
            "authority_consumptions": 0,
            "manifest_members": 0,
            "manifest_seals": 1,
        }
    finally:
        connection.close()


@pytest.mark.parametrize(
    "contract",
    [SQLiteSealReadiness, SQLiteSealState, SQLiteSealRequest, SQLiteSealReceipt],
)
def test_seal_contracts_are_strict_and_reject_unknown_fields(contract: type) -> None:
    schema = contract.model_json_schema()
    assert schema.get("additionalProperties") is False
    with pytest.raises(ValidationError):
        contract.model_validate({"unexpected": True})


def test_persisted_seal_authority_replay_is_exact_and_nonce_is_protected() -> None:
    root = _repository_root()
    restricted = root / "artifacts/restricted/catalog/v2/sqlite"
    before = (_database_path().read_bytes(), _database_path().stat().st_mtime_ns)

    first = check_seal_request(
        repo_root=root,
        schema_dir=_schema_dir(),
        receipt_path=_receipt_path(),
        materialized_bundle_path=root
        / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
        split_approval_path=root / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
        state_path=restricted / "seal-state-attestation.json",
        issuance_context_path=restricted / "seal-issuance-context.json",
        request_path=root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
    )
    second = check_seal_request(
        repo_root=root,
        schema_dir=_schema_dir(),
        receipt_path=_receipt_path(),
        materialized_bundle_path=root
        / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
        split_approval_path=root / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
        state_path=restricted / "seal-state-attestation.json",
        issuance_context_path=restricted / "seal-issuance-context.json",
        request_path=root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
    )

    assert first == second
    assert first.counts == {"blind": 12, "dev": 24, "total": 36}
    issuance_payload = json.loads((restricted / "seal-issuance-context.json").read_bytes())
    assert (
        first.nonce_sha256 == hashlib.sha256(issuance_payload["nonce"].encode("ascii")).hexdigest()
    )
    assert issuance_payload["nonce"] not in json.dumps(
        first.model_dump(mode="json"), sort_keys=True
    )
    assert before == (_database_path().read_bytes(), _database_path().stat().st_mtime_ns)


def test_published_seal_request_replays_from_live_protected_parents() -> None:
    root = _repository_root()
    restricted = root / "artifacts/restricted/catalog/v2/sqlite"
    request = check_seal_request(
        repo_root=root,
        schema_dir=_schema_dir(),
        receipt_path=_receipt_path(),
        materialized_bundle_path=root
        / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
        split_approval_path=root / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
        state_path=restricted / "seal-state-attestation.json",
        issuance_context_path=restricted / "seal-issuance-context.json",
        request_path=root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
    )

    assert request.action == "sqlite-real-manifest-seal"
    assert request.counts == {"blind": 12, "dev": 24, "total": 36}


def _write_canonical(path: Path, value: object, *, mode: int) -> None:
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(mode)


def test_mixed_parent_and_request_replay_fail_closed(tmp_path: Path) -> None:
    root = _repository_root()
    restricted = root / "artifacts/restricted/catalog/v2/sqlite"
    state_path = restricted / "seal-state-attestation.json"
    issuance_path = restricted / "seal-issuance-context.json"
    request_path = root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json"
    state_copy = tmp_path / "state.json"
    issuance_copy = tmp_path / "issuance.json"
    request_copy = tmp_path / "request.json"
    _write_canonical(state_copy, json.loads(state_path.read_bytes()), mode=0o600)
    _write_canonical(issuance_copy, json.loads(issuance_path.read_bytes()), mode=0o600)

    mixed_request = json.loads(request_path.read_bytes())
    mixed_request["catalog_revision_sha256"] = "f" * 64
    mixed_request["request_sha256"] = None
    mixed = SQLiteSealRequest.model_validate(mixed_request)
    _write_canonical(request_copy, mixed.model_dump(mode="json"), mode=0o644)
    with pytest.raises(ValueError, match="stale"):
        check_seal_request(
            repo_root=root,
            schema_dir=_schema_dir(),
            receipt_path=_receipt_path(),
            materialized_bundle_path=root
            / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
            split_approval_path=root
            / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
            state_path=state_copy,
            issuance_context_path=issuance_copy,
            request_path=request_copy,
        )

    original_request = json.loads(request_path.read_bytes())
    _write_canonical(request_copy, original_request, mode=0o644)
    replayed_issuance = json.loads(issuance_path.read_bytes())
    replayed_issuance["nonce"] = "8" * 64
    replayed_issuance["context_sha256"] = None
    replayed = AuthorityIssuanceContext.model_validate(replayed_issuance)
    _write_canonical(issuance_copy, replayed.model_dump(mode="json"), mode=0o600)
    with pytest.raises(ValueError, match="stale"):
        check_seal_request(
            repo_root=root,
            schema_dir=_schema_dir(),
            receipt_path=_receipt_path(),
            materialized_bundle_path=root
            / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
            split_approval_path=root
            / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
            state_path=state_copy,
            issuance_context_path=issuance_copy,
            request_path=request_copy,
        )


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "database_path",
        "database_uri",
        "dev_members",
        "blind_members",
        "complement",
        "member_order",
        "per_member_digests",
    ],
)
def test_request_contract_rejects_membership_and_capability_fields(
    forbidden_field: str,
) -> None:
    root = _repository_root()
    payload = json.loads(
        (root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json").read_bytes()
    )
    payload[forbidden_field] = []

    with pytest.raises(ValidationError):
        SQLiteSealRequest.model_validate(payload)
