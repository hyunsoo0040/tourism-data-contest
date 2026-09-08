"""Security contract for the current-parent v1 lineage successor."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from itda.cli import fingerprint_catalog_v1 as capability
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PREDECESSOR = (
    REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json"
)

EXPECTED_DELTA_PATHS = (
    "backend/src/itda/cli/approve_catalog.py",
    "backend/src/itda/contracts/catalog_manifest.py",
    "backend/src/itda/contracts/catalog_release.py",
    "backend/tests/pipeline/test_catalog_relationships.py",
)


def test_live_successor_diagnostic_is_exact_and_membership_free() -> None:
    diagnostic = capability.diagnose_successor(REPOSITORY_ROOT, PREDECESSOR)

    assert diagnostic["recorded_inventory_sha256"] == (
        "ac09f3a884b4b2e2c8b51d875346bb46ece5b3fc138973e38d6d7dad3fd91483"
    )
    assert diagnostic["current_inventory_sha256"] == (
        "e7011e47b22a6e0886ce8cd6e95e4c52f2448153e4fb94cccaacab204d039a32"
    )
    assert tuple(row["relpath"] for row in diagnostic["delta_rows"]) == (EXPECTED_DELTA_PATHS)
    assert diagnostic["catalog_v1_tree_sha256"] == (
        "907eb790d3eb187763742f492a4fc63541ebb18308262a5acef23adc31c0d24e"
    )
    assert diagnostic["planning_history_tree_sha256"] == (
        "05adbd4d3db076f95c3649c5592e9d581d89aad2a0c753d5e5a5ed2b9c41414b"
    )
    capability._assert_membership_free_payload(diagnostic)


def test_successor_schema_binds_predecessor_delta_and_owner_commits() -> None:
    successor = capability.build_successor_manifest(REPOSITORY_ROOT, PREDECESSOR)

    assert tuple(successor) == capability.SUCCESSOR_KEYS
    assert successor["schema_version"] == capability.SUCCESSOR_SCHEMA_VERSION
    assert successor["migration_reason"] == "LATER_COMPLETED_SOURCE_EVOLUTION"
    assert successor["exceptional_delta_allowlist"] == []
    assert tuple(row["relpath"] for row in successor["tracked_source_delta"]) == (
        EXPECTED_DELTA_PATHS
    )
    assert {row["owner_plan_id"] for row in successor["tracked_source_delta"]} == {"02-21", "02-25"}
    assert successor["successor_sha256"] == canonical_sha256(
        {key: value for key, value in successor.items() if key != "successor_sha256"}
    )
    assert (
        capability.verify_successor_manifest(REPOSITORY_ROOT, PREDECESSOR, successor) == successor
    )


def test_successor_rejects_unknown_fifth_path_and_reordered_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = capability._load_manifest(PREDECESSOR)
    current = capability.build_manifest(REPOSITORY_ROOT)
    extra = copy.deepcopy(current["tracked_source_config"]["entries"][0])
    extra["worktree"]["relpath"] = "backend/src/itda/unowned.py"
    current["tracked_source_config"]["entries"].append(extra)
    current["tracked_source_config"]["entry_count"] += 1
    current["tracked_source_config"]["inventory_sha256"] = canonical_sha256(
        current["tracked_source_config"]["entries"]
    )
    current["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in current.items() if key != "manifest_sha256"}
    )
    with pytest.raises(capability.FingerprintError, match="exact four-path"):
        capability.classify_successor_delta(REPOSITORY_ROOT, recorded, current)

    valid = capability.build_successor_manifest(REPOSITORY_ROOT, PREDECESSOR)
    reordered = copy.deepcopy(valid)
    reordered["tracked_source_delta"].reverse()
    reordered["successor_sha256"] = canonical_sha256(
        {key: value for key, value in reordered.items() if key != "successor_sha256"}
    )
    with pytest.raises(capability.FingerprintError, match="ordered|canonical"):
        capability.verify_successor_manifest(REPOSITORY_ROOT, PREDECESSOR, reordered)


def test_successor_rejects_dirty_path_wrong_owner_and_protected_tree_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        capability,
        "_worktree_status_rows",
        lambda *_: ((EXPECTED_DELTA_PATHS[0], "modified"),),
    )
    with pytest.raises(capability.FingerprintError, match="clean"):
        capability.diagnose_successor(REPOSITORY_ROOT, PREDECESSOR)

    monkeypatch.undo()
    monkeypatch.setitem(
        capability.DELTA_OWNER_COMMITS,
        EXPECTED_DELTA_PATHS[0],
        ("02-21", "0" * 40),
    )
    with pytest.raises(capability.FingerprintError, match="owner commit"):
        capability.diagnose_successor(REPOSITORY_ROOT, PREDECESSOR)

    monkeypatch.undo()
    recorded = capability._load_manifest(PREDECESSOR)
    current = capability.build_manifest(REPOSITORY_ROOT)
    current["catalog_v1"]["tree_sha256"] = "0" * 64
    current["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in current.items() if key != "manifest_sha256"}
    )
    with pytest.raises(capability.FingerprintError, match="catalog_v1"):
        capability.classify_successor_delta(REPOSITORY_ROOT, recorded, current)
    current = capability.build_manifest(REPOSITORY_ROOT)
    current["planning_history"]["tree_sha256"] = "0" * 64
    current["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in current.items() if key != "manifest_sha256"}
    )
    with pytest.raises(capability.FingerprintError, match="planning_history"):
        capability.classify_successor_delta(REPOSITORY_ROOT, recorded, current)


def test_protected_manifest_is_closed_private_and_exact_comparable() -> None:
    before = capability.build_protected_manifest(REPOSITORY_ROOT, plan_id="02-60", stage="before")
    after = capability.build_protected_manifest(REPOSITORY_ROOT, plan_id="02-60", stage="after")

    assert tuple(before) == capability.PROTECTED_MANIFEST_KEYS
    assert before["schema_version"] == capability.PROTECTED_MANIFEST_SCHEMA_VERSION
    assert before["plan_id"] == "02-60"
    assert before["stage"] == "before"
    assert before["owner_count"] == len(before["owners"])
    assert before["identity_rows_sha256"] == canonical_sha256(before["owners"])
    assert before["protected_set_sha256"] == after["protected_set_sha256"]
    assert capability.compare_protected_manifests(before, after) == "EXACT_EQUAL"
    capability._assert_membership_free_payload(before)

    missing = copy.deepcopy(after)
    missing["owners"].pop()
    missing["owner_count"] -= 1
    missing["identity_rows_sha256"] = canonical_sha256(missing["owners"])
    with pytest.raises(capability.FingerprintError, match="owner|protected"):
        capability.compare_protected_manifests(before, missing)


@pytest.mark.parametrize(
    "forbidden",
    [
        {"members": ["restricted-value"]},
        {"ordered_catalog_ids": ["restricted-value"]},
        {"database_uri": "sqlite:///restricted"},
        {"populated_database_path": "/restricted/location"},
        {"raw_nonce": "secret"},
    ],
)
def test_protected_manifest_rejects_capability_or_membership_fields(
    forbidden: dict[str, object],
) -> None:
    with pytest.raises(capability.FingerprintError, match="forbidden"):
        capability._assert_membership_free_payload(forbidden)


def test_successor_and_guard_publication_are_no_replace_exact_recoverable(
    tmp_path: Path,
) -> None:
    successor = capability.build_successor_manifest(REPOSITORY_ROOT, PREDECESSOR)
    payload = canonical_json_bytes(successor)
    target = tmp_path / "successor.json"

    assert capability._publish_exact_existing(target, payload) == "PUBLISHED"
    identity = target.stat()
    assert capability._publish_exact_existing(target, payload) == ("ALREADY_PRESENT_VERIFIED")
    assert target.stat().st_ino == identity.st_ino
    assert target.read_bytes() == payload
    assert target.stat().st_mode & 0o777 == 0o600

    target.write_bytes(canonical_json_bytes({"collision": True}))
    with pytest.raises(capability.FingerprintError, match="collision"):
        capability._publish_exact_existing(target, payload)


def test_protected_manifest_rejects_noncanonical_or_self_hash_tamper() -> None:
    payload = capability.build_protected_manifest(REPOSITORY_ROOT, plan_id="02-60", stage="before")
    tampered = json.loads(json.dumps(payload))
    tampered["protected_manifest_sha256"] = "0" * 64
    with pytest.raises(capability.FingerprintError, match="self|hash"):
        capability.validate_protected_manifest(
            REPOSITORY_ROOT,
            tampered,
            plan_id="02-60",
            stage="before",
        )
