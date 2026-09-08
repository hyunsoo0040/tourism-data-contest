from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.seal_manifest import ManifestAlreadySealedError, create_manifest_seal
from itda.contracts.manifest import SplitManifest
from itda.domain.canonical import canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_FIXTURE = REPOSITORY_ROOT / "fixtures" / "synthetic" / "synthetic-split-manifest.json"
EXPECTED_MANIFEST_SHA256 = "c88fbe3ebbd1874b130ce6985600eaa635c3d4a06f7062c2febbf42174f9dd11"


def _fixture_payload() -> dict[str, object]:
    return json.loads(MANIFEST_FIXTURE.read_text(encoding="utf-8"))


def _valid_manifest() -> SplitManifest:
    return SplitManifest.model_validate(_fixture_payload())


def test_synthetic_fixture_has_exact_split_and_stable_canonical_hash() -> None:
    manifest = _valid_manifest()

    assert len(manifest.members) == 36
    assert sum(member.split == "DEV" for member in manifest.members) == 24
    assert sum(member.split == "BLIND" for member in manifest.members) == 12
    assert canonical_sha256(manifest.canonical_payload()) == EXPECTED_MANIFEST_SHA256


def test_member_and_object_key_order_do_not_change_canonical_hash() -> None:
    payload = _fixture_payload()
    reordered = {
        "members": [
            {"split": member["split"], "synthetic_place_id": member["synthetic_place_id"]}
            for member in reversed(payload["members"])
        ],
        "canonicalization_version": payload["canonicalization_version"],
        "manifest_version": payload["manifest_version"],
    }

    assert canonical_sha256(
        SplitManifest.model_validate(reordered).canonical_payload()
    ) == canonical_sha256(_valid_manifest().canonical_payload())


def test_canonical_member_order_is_locale_independent_for_contract_valid_ids() -> None:
    payload = _fixture_payload()
    mixed_ids = (
        "synthetic:dev:Alpha",
        "synthetic:dev:alpha",
        "synthetic:dev:Éclair",
        "synthetic:dev:한글",
    )
    for member, synthetic_place_id in zip(payload["members"], mixed_ids, strict=False):
        member["synthetic_place_id"] = synthetic_place_id

    manifest = SplitManifest.model_validate(payload)
    canonical_dev_ids = [
        member.synthetic_place_id
        for member in manifest.canonical_members()
        if member.split == "DEV"
    ]

    assert canonical_dev_ids == sorted(canonical_dev_ids)
    assert [identifier for identifier in canonical_dev_ids if identifier in mixed_ids] == list(
        mixed_ids
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload["members"].pop(), "exactly 24 DEV and 12 BLIND"),
        (
            lambda payload: payload["members"].__setitem__(35, dict(payload["members"][0])),
            "synthetic_place_id values must be unique",
        ),
        (
            lambda payload: payload["members"][0].__setitem__(
                "synthetic_place_id", "real:gyeongju:126166"
            ),
            "synthetic_place_id must start with synthetic:",
        ),
        (
            lambda payload: payload.__setitem__("canonicalization_version", "canonical-json-v2"),
            "canonicalization_version must be canonical-json-v1",
        ),
    ],
)
def test_invalid_manifest_membership_is_rejected(mutate: object, message: str) -> None:
    payload = _fixture_payload()
    mutate(payload)

    with pytest.raises(ValidationError, match=message):
        SplitManifest.model_validate(payload)


def test_seal_metadata_is_utc_immutable_and_single_use() -> None:
    manifest = _valid_manifest()
    sealed_at = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
    seal = create_manifest_seal(manifest, sealed_at=sealed_at)

    assert seal.manifest_sha256 == EXPECTED_MANIFEST_SHA256
    assert seal.sealed_at == sealed_at
    assert seal.member_count == 36
    assert seal.dev_count == 24
    assert seal.blind_count == 12
    with pytest.raises(ValidationError, match="frozen"):
        seal.manifest_sha256 = "0" * 64
    with pytest.raises(ManifestAlreadySealedError, match="already sealed"):
        create_manifest_seal(manifest, sealed_at=sealed_at, existing_seal=seal)


def test_seal_rejects_non_utc_timestamp() -> None:
    with pytest.raises(ValidationError, match="sealed_at must use UTC"):
        create_manifest_seal(
            _valid_manifest(),
            sealed_at=datetime(2026, 7, 22, 12, 0),
        )
