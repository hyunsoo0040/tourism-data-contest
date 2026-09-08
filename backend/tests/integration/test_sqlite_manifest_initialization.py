"""Plan 57 initialization authority, filesystem, and leakage contracts."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.contracts.authority import AuthorityTokenV2
from itda.contracts.sqlite_manifest_authority import (
    SQLiteInitializationReceipt,
    SQLiteInitializationRequest,
    SQLiteInitializationState,
    SQLiteManifestAuthorityError,
    build_initialization_authority,
    check_initialization_request,
    initialize_restricted_empty_database,
    verify_initialization_receipt,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

NOW = datetime(2026, 8, 2, 13, 0, tzinfo=UTC)
NONCE = "9" * 64
REVIEWER = "phase2-sqlite-initializer"


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _schema_dir() -> Path:
    return _repository_root() / "backend/schema/evaluation_manifest_v1"


def _canonical_write(path: Path, payload: object, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload))
    path.chmod(mode)


def _synthetic_split_approval(path: Path) -> None:
    payload: dict[str, object] = {
        "schema_version": "itda.real-split-approval.v2",
        "status": "APPROVED_UNSEALED",
        "seal_sha256": None,
        "request_sha256": "1" * 64,
        "state_attestation_sha256": "2" * 64,
        "target_sha256": "3" * 64,
        "binding_sha256": "4" * 64,
    }
    payload["approval_sha256"] = canonical_sha256(payload)
    _canonical_write(path, payload, mode=0o600)


@pytest.fixture
def authority_fixture(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir(mode=0o700)
    (repo_root / ".gitignore").write_text(
        "/artifacts/restricted/catalog/**\n",
        encoding="utf-8",
    )
    split_approval_path = (
        repo_root / "artifacts/restricted/catalog/v2/split/real-split-approval.json"
    )
    split_approval_path.parent.mkdir(parents=True, mode=0o700)
    split_approval_path.parent.chmod(0o700)
    _synthetic_split_approval(split_approval_path)

    restricted_root = repo_root / "artifacts/restricted/catalog/v2/sqlite"
    state_path = restricted_root / "initialization-state-attestation.json"
    issuance_path = restricted_root / "initialization-issuance-context.json"
    request_path = repo_root / "artifacts/public/catalog/v2/sqlite-initialization-request.json"
    receipt_path = restricted_root / "initialization-receipt.json"
    state, request, issuance = build_initialization_authority(
        repo_root=repo_root,
        schema_dir=_schema_dir(),
        split_approval_path=split_approval_path,
        restricted_root=restricted_root,
        state_output=state_path,
        issuance_output=issuance_path,
        request_output=request_path,
        reviewer_id=REVIEWER,
        nonce=NONCE,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=2),
    )
    return {
        "repo_root": repo_root,
        "restricted_root": restricted_root,
        "state_path": state_path,
        "issuance_path": issuance_path,
        "request_path": request_path,
        "receipt_path": receipt_path,
        "state": state,
        "request": request,
        "issuance": issuance,
        "token": issuance.expected_token().serialize(),
    }


def _initialize(fixture: dict[str, object]) -> SQLiteInitializationReceipt:
    return initialize_restricted_empty_database(
        raw_token=str(fixture["token"]),
        repo_root=Path(fixture["repo_root"]),
        schema_dir=_schema_dir(),
        state_path=Path(fixture["state_path"]),
        issuance_context_path=Path(fixture["issuance_path"]),
        request_path=Path(fixture["request_path"]),
        receipt_output=Path(fixture["receipt_path"]),
        initialized_at=NOW + timedelta(minutes=5),
    )


def _target_path(fixture: dict[str, object]) -> Path:
    request = fixture["request"]
    assert isinstance(request, SQLiteInitializationRequest)
    return (
        Path(fixture["restricted_root"])
        / "releases"
        / request.target_sha256
        / "evaluation-authority.sqlite3"
    )


def test_prepare_is_membership_free_and_keeps_real_target_absent(
    authority_fixture: dict[str, object],
) -> None:
    state = authority_fixture["state"]
    request = authority_fixture["request"]
    assert isinstance(state, SQLiteInitializationState)
    assert isinstance(request, SQLiteInitializationRequest)
    assert state.split_approval_status == "APPROVED_UNSEALED"
    assert request.action == "sqlite-manifest-initialize"
    assert request.empty_counts == {
        "authority_consumptions": 0,
        "manifest_members": 0,
        "manifest_seals": 0,
    }
    assert request.restricted_root == "artifacts/restricted/catalog/v2/sqlite"
    assert request.directory_mode == "0700"
    assert request.database_mode == "0600"
    assert not (Path(authority_fixture["restricted_root"]) / "releases").exists()
    assert not Path(authority_fixture["receipt_path"]).exists()

    assert (
        check_initialization_request(
            repo_root=Path(authority_fixture["repo_root"]),
            schema_dir=_schema_dir(),
            state_path=Path(authority_fixture["state_path"]),
            issuance_context_path=Path(authority_fixture["issuance_path"]),
            request_path=Path(authority_fixture["request_path"]),
        )
        == request
    )


def test_exact_authority_creates_only_empty_schema_and_sanitized_receipt(
    authority_fixture: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    receipt = _initialize(authority_fixture)
    target = _target_path(authority_fixture)

    assert target.is_file()
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700
    assert target.stat().st_nlink == 1
    assert receipt.empty_counts == {
        "authority_consumptions": 0,
        "manifest_members": 0,
        "manifest_seals": 0,
    }
    assert receipt.integrity_check == "ok"
    assert receipt.foreign_key_check_count == 0
    assert receipt.sidecars == {"journal": False, "shm": False, "wal": False}
    assert receipt == verify_initialization_receipt(
        repo_root=Path(authority_fixture["repo_root"]),
        schema_dir=_schema_dir(),
        state_path=Path(authority_fixture["state_path"]),
        issuance_context_path=Path(authority_fixture["issuance_path"]),
        request_path=Path(authority_fixture["request_path"]),
        receipt_path=Path(authority_fixture["receipt_path"]),
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


@pytest.mark.parametrize(
    "field",
    [
        "request_sha256",
        "state_attestation_sha256",
        "target_sha256",
        "binding_sha256",
    ],
)
def test_wrong_authority_coordinate_is_rejected_before_creation(
    authority_fixture: dict[str, object], field: str
) -> None:
    token = AuthorityTokenV2.parse(str(authority_fixture["token"]))
    raw = token.model_copy(update={field: "b" * 64}).serialize()

    with pytest.raises(ValueError, match="authority|stale|digest"):
        initialize_restricted_empty_database(
            raw_token=raw,
            repo_root=Path(authority_fixture["repo_root"]),
            schema_dir=_schema_dir(),
            state_path=Path(authority_fixture["state_path"]),
            issuance_context_path=Path(authority_fixture["issuance_path"]),
            request_path=Path(authority_fixture["request_path"]),
            receipt_output=Path(authority_fixture["receipt_path"]),
            initialized_at=NOW + timedelta(minutes=5),
        )
    assert not _target_path(authority_fixture).exists()


def test_replay_and_preexisting_target_fail_closed(
    authority_fixture: dict[str, object],
) -> None:
    _initialize(authority_fixture)
    before = _target_path(authority_fixture).read_bytes()

    with pytest.raises(SQLiteManifestAuthorityError, match="exists|replay|receipt"):
        _initialize(authority_fixture)
    assert _target_path(authority_fixture).read_bytes() == before


@pytest.mark.parametrize("sidecar", ["-journal", "-wal", "-shm"])
def test_preexisting_sidecar_is_never_unlinked(
    authority_fixture: dict[str, object], sidecar: str
) -> None:
    request = authority_fixture["request"]
    assert isinstance(request, SQLiteInitializationRequest)
    release = Path(authority_fixture["restricted_root"]) / "releases" / request.target_sha256
    release.mkdir(parents=True, mode=0o700)
    sidecar_path = release / f"evaluation-authority.sqlite3{sidecar}"
    sidecar_path.write_bytes(b"do-not-delete")
    sidecar_path.chmod(0o600)

    with pytest.raises(SQLiteManifestAuthorityError, match="sidecar|exists|target"):
        _initialize(authority_fixture)
    assert sidecar_path.read_bytes() == b"do-not-delete"


def test_symlink_path_escape_and_wrong_mode_are_rejected(tmp_path: Path) -> None:
    fixture_root = tmp_path / "repo"
    fixture_root.mkdir(mode=0o700)
    (fixture_root / ".gitignore").write_text("/artifacts/restricted/catalog/**\n", encoding="utf-8")
    split = fixture_root / "artifacts/restricted/catalog/v2/split/approval.json"
    split.parent.mkdir(parents=True, mode=0o700)
    split.parent.chmod(0o700)
    _synthetic_split_approval(split)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    restricted = fixture_root / "artifacts/restricted/catalog/v2/sqlite"
    restricted.parent.mkdir(parents=True, exist_ok=True)
    restricted.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SQLiteManifestAuthorityError, match="symlink|restricted"):
        build_initialization_authority(
            repo_root=fixture_root,
            schema_dir=_schema_dir(),
            split_approval_path=split,
            restricted_root=restricted,
            state_output=restricted / "state.json",
            issuance_output=restricted / "issuance.json",
            request_output=fixture_root / "artifacts/public/request.json",
            reviewer_id=REVIEWER,
            nonce=NONCE,
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )

    restricted.unlink()
    restricted.mkdir(mode=0o755)
    with pytest.raises(SQLiteManifestAuthorityError, match="0700|mode"):
        build_initialization_authority(
            repo_root=fixture_root,
            schema_dir=_schema_dir(),
            split_approval_path=split,
            restricted_root=restricted,
            state_output=restricted / "state.json",
            issuance_output=restricted / "issuance.json",
            request_output=fixture_root / "artifacts/public/request.json",
            reviewer_id=REVIEWER,
            nonce=NONCE,
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )


def test_hardlink_and_file_replacement_break_receipt_verification(
    authority_fixture: dict[str, object],
) -> None:
    _initialize(authority_fixture)
    target = _target_path(authority_fixture)
    link = target.with_name("unexpected-hardlink.sqlite3")
    os.link(target, link)
    try:
        with pytest.raises(SQLiteManifestAuthorityError, match="link|identity"):
            verify_initialization_receipt(
                repo_root=Path(authority_fixture["repo_root"]),
                schema_dir=_schema_dir(),
                state_path=Path(authority_fixture["state_path"]),
                issuance_context_path=Path(authority_fixture["issuance_path"]),
                request_path=Path(authority_fixture["request_path"]),
                receipt_path=Path(authority_fixture["receipt_path"]),
            )
    finally:
        link.unlink()

    original = target.read_bytes()
    target.unlink()
    target.write_bytes(original)
    target.chmod(0o600)
    with pytest.raises(SQLiteManifestAuthorityError, match="identity|inode|receipt"):
        verify_initialization_receipt(
            repo_root=Path(authority_fixture["repo_root"]),
            schema_dir=_schema_dir(),
            state_path=Path(authority_fixture["state_path"]),
            issuance_context_path=Path(authority_fixture["issuance_path"]),
            request_path=Path(authority_fixture["request_path"]),
            receipt_path=Path(authority_fixture["receipt_path"]),
        )


def test_request_state_and_receipt_have_no_secret_path_or_membership_leakage(
    authority_fixture: dict[str, object],
) -> None:
    receipt = _initialize(authority_fixture)
    request = authority_fixture["request"]
    state = authority_fixture["state"]
    assert isinstance(request, SQLiteInitializationRequest)
    assert isinstance(state, SQLiteInitializationState)

    surfaces = (
        canonical_json_bytes(request.model_dump(mode="json")),
        canonical_json_bytes(state.model_dump(mode="json")),
        canonical_json_bytes(receipt.model_dump(mode="json")),
    )
    forbidden = (
        str(authority_fixture["token"]).encode(),
        NONCE.encode(),
        str(authority_fixture["repo_root"]).encode(),
        b"file:",
        b"private-dev-id",
        b"private-blind-id",
        b"complement",
        b"member_order",
        b"per_member",
    )
    for surface in surfaces:
        assert not any(value in surface for value in forbidden)

    assert hashlib.sha256(NONCE.encode("ascii")).hexdigest() == receipt.nonce_sha256
    assert Path(authority_fixture["issuance_path"]).stat().st_mode & 0o777 == 0o600
    assert Path(authority_fixture["state_path"]).stat().st_mode & 0o777 == 0o600
    assert Path(authority_fixture["receipt_path"]).stat().st_mode & 0o777 == 0o600
