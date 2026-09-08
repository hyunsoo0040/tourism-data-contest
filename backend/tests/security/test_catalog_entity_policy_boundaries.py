from __future__ import annotations

import importlib
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

from itda.cli import fingerprint_catalog_v1 as capability
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

ENTITY_CONTRACT_MODULE = "itda.contracts.catalog_entity"
POLICY_CONTRACT_MODULE = "itda.contracts.catalog_entity_policy"


def _entity_contract_or_skip() -> ModuleType:
    if importlib.util.find_spec(ENTITY_CONTRACT_MODULE) is None:
        pytest.skip("catalog entity contract is implemented in Plan 02-10")
    return importlib.import_module(ENTITY_CONTRACT_MODULE)


def _write(path: Path, payload: bytes = b"payload", mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def test_descriptor_tree_inventory_binds_every_six_field_row(tmp_path: Path) -> None:
    root = tmp_path / "artifacts/restricted/catalog/v1"
    _write(root / "nested/evidence.json", b'{"ok":true}')
    _write(root / "top.bin", b"\x00\xff", 0o640)

    first = capability.scan_catalog_tree(tmp_path)
    second = capability.scan_catalog_tree(tmp_path)

    assert first == second
    assert first["entry_count"] == 4
    rows = first["entries"]
    assert all(tuple(row) == capability.ROW_KEYS for row in rows)
    assert [row["relpath"] for row in rows] == sorted(
        (row["relpath"] for row in rows),
        key=lambda item: item.encode("utf-8"),
    )
    assert {
        row["no_follow_result"] for row in rows
    } == capability.ALLOWED_NO_FOLLOW_RESULTS
    root_row = next(row for row in rows if row["relpath"] == capability.CATALOG_ROOT)
    assert first["tree_sha256"] == root_row["sha256"]


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_exceptional_entries_fail_closed(tmp_path: Path, kind: str) -> None:
    root = tmp_path / capability.CATALOG_ROOT
    root.mkdir(parents=True)
    if kind == "symlink":
        (root / "escape").symlink_to(tmp_path)
    else:
        os.mkfifo(root / "pipe")
    with pytest.raises(capability.FingerprintError, match="exceptional"):
        capability.scan_catalog_tree(tmp_path)


def test_no_follow_result_is_live_derived_and_merkle_bound(tmp_path: Path) -> None:
    root = tmp_path / capability.CATALOG_ROOT
    _write(root / "evidence.json", b"immutable")
    tree = capability.scan_catalog_tree(tmp_path)
    tampered = json.loads(json.dumps(tree))
    tampered["entries"][1]["no_follow_result"] = (
        "DIRECTORY_LSTAT_OPEN_NOFOLLOW_FSTAT_MATCH"
    )
    assert canonical_sha256(tampered["entries"]) != canonical_sha256(tree["entries"])
    assert tampered != capability.scan_catalog_tree(tmp_path)


def test_content_mode_size_type_and_inventory_changes_change_tree(tmp_path: Path) -> None:
    root = tmp_path / capability.CATALOG_ROOT
    target = root / "evidence.json"
    _write(target, b"first")
    baseline = capability.scan_catalog_tree(tmp_path)

    target.write_bytes(b"second")
    assert capability.scan_catalog_tree(tmp_path)["tree_sha256"] != baseline["tree_sha256"]
    target.write_bytes(b"first")
    target.chmod(0o640)
    assert capability.scan_catalog_tree(tmp_path)["tree_sha256"] != baseline["tree_sha256"]
    _write(root / "additional.json", b"extra")
    assert capability.scan_catalog_tree(tmp_path)["entry_count"] != baseline["entry_count"]


def test_manifest_loader_rejects_noncanonical_and_symlink_paths(tmp_path: Path) -> None:
    payload = {"schema_version": capability.SCHEMA_VERSION}
    target = tmp_path / "manifest.json"
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    with pytest.raises(capability.FingerprintError, match="canonical"):
        capability._load_manifest(target)
    target.write_bytes(canonical_json_bytes(payload))
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(capability.FingerprintError, match="regular"):
        capability._load_manifest(alias)


def test_no_replace_writer_refuses_existing_target(tmp_path: Path) -> None:
    target = tmp_path / "lineage/manifest.json"
    capability._write_no_replace(target, b"first")
    with pytest.raises(FileExistsError):
        capability._write_no_replace(target, b"second")
    assert target.read_bytes() == b"first"
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("kind", "entity_id"),
    [
        ("DATASET_RECORD", "place:" + "1" * 64),
        ("PLACE", "dataset:TOUR_API:15101578:content-123"),
        ("ODII_CONTENT", "photo:15101914:image-123"),
        ("PHOTO_ASSET", "odii:15101971:story-123"),
    ],
)
def test_entity_kind_and_identifier_namespace_cannot_alias(
    kind: str,
    entity_id: str,
) -> None:
    capability = _entity_contract_or_skip()
    with pytest.raises(ValueError, match="namespace|kind"):
        capability.EntityRef(kind=kind, entity_id=entity_id)


def test_title_or_proximity_evidence_cannot_authorize_identity_merge() -> None:
    capability = _entity_contract_or_skip()
    weak = capability.EntityEvidence(
        evidence_tier="T2_TITLE_OR_PROXIMITY_ONLY",
        provider="TOUR_API",
        official_dataset_id="15101578",
        provider_record_id="content:123",
        source_row_sha256="1" * 64,
        address="경주시 동일 제목",
        latitude=35.0,
        longitude=129.0,
        hierarchy=("경주시",),
    )
    assert weak.automatic_identity_eligible is False
    with pytest.raises(ValueError, match="automatic|T0"):
        capability.validate_automatic_identity_evidence(weak)


def test_unknown_fourth_relationship_type_is_rejected() -> None:
    capability = _entity_contract_or_skip()
    left = capability.EntityRef(kind="PLACE", entity_id="place:" + "1" * 64)
    right = capability.EntityRef(kind="PLACE", entity_id="place:" + "2" * 64)
    with pytest.raises(ValueError, match="relationship"):
        capability.TypedRelationshipProjection(
            source_row_id="relationship:" + "3" * 64,
            source_row_sha256="4" * 64,
            relationship_type="SAME_COMPLEX",
            left=left,
            right=right,
            evidence_refs=("evidence:" + "5" * 64,),
            automatic_identity_merge=False,
        )


def test_parent_child_cannot_be_marked_as_identity_merge() -> None:
    capability = _entity_contract_or_skip()
    with pytest.raises(ValueError, match="PARENT_CHILD|identity"):
        capability.TypedRelationshipProjection(
            source_row_id="relationship:" + "3" * 64,
            source_row_sha256="4" * 64,
            relationship_type="PARENT_CHILD",
            left=capability.EntityRef(
                kind="PLACE",
                entity_id="place:" + "1" * 64,
            ),
            right=capability.EntityRef(
                kind="PLACE",
                entity_id="place:" + "2" * 64,
            ),
            evidence_refs=("evidence:" + "5" * 64,),
            automatic_identity_merge=True,
        )


def test_policy_report_rejects_forged_aggregate_and_policy_hash() -> None:
    if importlib.util.find_spec(POLICY_CONTRACT_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-entity-policy", pytrace=False)
    policy = importlib.import_module(POLICY_CONTRACT_MODULE)
    assert policy.formal_policy_sha256() == policy.formal_policy_sha256()
    with pytest.raises(ValueError, match="derived|formal policy"):
        policy.EntityPolicyReport.model_validate(
            {
                "schema_version": "catalog-entity-policy-report-v1",
                "formal_policy_sha256": "0" * 64,
                "counts": {"crosswalk_total": 718},
            }
        )
