"""Plan 58 membership and capability isolation for SQLite seal authority."""

from __future__ import annotations

import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RESTRICTED_SPLIT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/split"
RESTRICTED_SQLITE = REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/sqlite"
PUBLIC_REQUEST = (
    REPOSITORY_ROOT / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json"
)

FORBIDDEN_KEYS = {
    "blind_members",
    "canonical_place_id",
    "complement",
    "database_path",
    "database_uri",
    "dev_members",
    "device",
    "inode",
    "member_ids",
    "member_order",
    "members",
    "nonce",
    "ordered_members",
    "ordered_place_ids",
    "path",
    "per_member",
    "per_member_digests",
    "raw_token",
    "uri",
}


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {str(key).casefold() for key in value} | {
            key for child in value.values() for key in _keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _keys(child)}
    return set()


def _membership_values() -> tuple[str, ...]:
    payload = json.loads((RESTRICTED_SPLIT / "real-split-manifest.json").read_bytes())
    return tuple(payload["dev_members"]) + tuple(payload["blind_members"])


def test_public_request_and_protected_state_are_membership_and_path_free() -> None:
    public_bytes = PUBLIC_REQUEST.read_bytes()
    state_bytes = (RESTRICTED_SQLITE / "seal-state-attestation.json").read_bytes()
    public = json.loads(public_bytes)
    state = json.loads(state_bytes)

    assert _keys(public).isdisjoint(FORBIDDEN_KEYS)
    assert _keys(state).isdisjoint(FORBIDDEN_KEYS)
    assert public["counts"] == {"blind": 12, "dev": 24, "total": 36}
    assert state["counts"] == {"blind": 12, "dev": 24, "total": 36}
    for value in _membership_values():
        assert value.encode("utf-8") not in public_bytes, "public request leaked membership"
        assert value.encode("utf-8") not in state_bytes, "protected state leaked membership"


def test_raw_nonce_exists_only_in_restricted_issuance_context() -> None:
    issuance = json.loads((RESTRICTED_SQLITE / "seal-issuance-context.json").read_bytes())
    raw_nonce = issuance["nonce"].encode("ascii")
    public_bytes = PUBLIC_REQUEST.read_bytes()
    state_bytes = (RESTRICTED_SQLITE / "seal-state-attestation.json").read_bytes()

    assert len(raw_nonce) == 64
    assert raw_nonce not in public_bytes
    assert raw_nonce not in state_bytes
    assert "nonce_sha256" in json.loads(public_bytes)


def test_seal_authority_artifact_modes_are_exact() -> None:
    assert (RESTRICTED_SQLITE / "seal-state-attestation.json").stat().st_mode & 0o777 == 0o600
    assert (RESTRICTED_SQLITE / "seal-issuance-context.json").stat().st_mode & 0o777 == 0o600
    assert PUBLIC_REQUEST.stat().st_mode & 0o777 == 0o644
