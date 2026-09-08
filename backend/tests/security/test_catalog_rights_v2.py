"""Security contract for the immutable v2 rights and objective-evidence bundle."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from itda.cli import fingerprint_catalog_v1
from itda.cli.project_catalog_rights_v2 import (
    build_bundle,
    build_current_attestation,
    build_current_bundle,
    verify_current_attestation,
)
from itda.contracts.catalog_audit import CatalogAsset, DatasetGrantEvidence
from itda.contracts.catalog_rights_v2 import (
    AttachmentRightsRow,
    RightsState,
    project_asset_rights,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
LINEAGE_SUCCESSOR = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest-v2.json"
)
RIGHTS_PROJECTION = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/rights/rights-projection.json"
)
OBJECTIVE_EVIDENCE = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
)
PROTECTED_BEFORE = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-60-protected-before.json"
)


def _grant(dataset_id: str, *, attribution: str | None = None) -> DatasetGrantEvidence:
    return DatasetGrantEvidence(
        official_dataset_id=dataset_id,
        official_page_url=f"https://www.data.go.kr/data/{dataset_id}/openapi.do",
        retrieved_at="2026-07-27T09:07:55.580018Z",
        response_sha256="1" * 64,
        page_sha256="2" * 64,
        dataset_grant_sha256="3" * 64,
        evidence_state="COMPLETE",
        license_type=(
            "KOGL_TYPE_1_ATTRIBUTION"
            if dataset_id == "15101914"
            else "PUBLIC_DATA_GRANT"
        ),
        attribution_text=attribution,
        commercial_use_allowed=True,
        transform_allowed=True,
        display_allowed=True,
        model_input_allowed=True,
    )


def _photo(*, restriction: str | None = None) -> CatalogAsset:
    return CatalogAsset(
        official_dataset_id="15101914",
        source_asset_id="photo-001",
        source_request_sha256="4" * 64,
        source_response_sha256="5" * 64,
        original_url="https://tong.visitkorea.or.kr/photo-001.jpg",
        creator_or_photographer="한국관광공사 홍길동",
        license_type="KOGL_TYPE_1_ATTRIBUTION",
        attribution_text="한국관광공사 포토코리아-홍길동",
        explicit_asset_restriction=restriction,
    )


def test_asset_rights_are_dataset_scoped_and_asset_restrictions_win() -> None:
    allowed = project_asset_rights(
        _photo(),
        _grant("15101914", attribution="한국관광공사 포토코리아"),
    )
    assert allowed.rights_state is RightsState.ALLOWED

    blocked = project_asset_rights(
        _photo(restriction="NO_DERIVATIVES_OR_MODEL_INPUT"),
        _grant("15101914", attribution="한국관광공사 포토코리아"),
    )
    assert blocked.rights_state is RightsState.BLOCKED_EXPLICIT_ASSET_RESTRICTION
    assert blocked.analysis_eligible is False
    assert blocked.ui_eligible is False
    assert blocked.demo_eligible is False

    with pytest.raises(ValueError, match="dataset"):
        project_asset_rights(_photo(), _grant("15101971"))


def test_attachment_is_evidence_only_and_cannot_confer_rights() -> None:
    with pytest.raises(ValueError, match="rights"):
        AttachmentRightsRow.model_validate(
            {
                "source_relationship_row_id": f"relationship:{'a' * 64}",
                "source_attachment_leaf_sha256": "b" * 64,
                "source_place_candidate_id": "candidate:tour-api:1",
                "source_photo_candidate_id": "candidate:tourism-photo:2",
                "source_asset_id": "2",
                "place_entity_id": f"place:{'c' * 64}",
                "photo_entity_id": f"photo:{'d' * 64}",
                "owner_dataset_entity_id": f"dataset:{'e' * 64}",
                "attachment_rights_granting": True,
                "identity_merging": False,
                "asset_rights_leaf_sha256": "f" * 64,
                "rights_state": "ALLOWED",
                "reason_codes": ["EXACT_ASSET_RIGHTS_INDEPENDENTLY_ALLOWED"],
                "evidence_refs": ["1" * 64],
                "leaf_sha256": "2" * 64,
            }
        )


def test_live_bundle_covers_every_place_and_exact_attachment() -> None:
    rights, evidence = build_current_bundle(
        REPOSITORY_ROOT,
        lineage_successor_path=LINEAGE_SUCCESSOR,
        rights_path=RIGHTS_PROJECTION,
        objective_path=OBJECTIVE_EVIDENCE,
        protected_before_path=PROTECTED_BEFORE,
    )

    assert rights.parents.formal_policy_sha256 == (
        "0a8d264c356822f60391976de78eaba4378c562a04400e41962213e5f9cdbcc5"
    )
    assert rights.parents.media_attachments_root == (
        "1943ce379106fb04e26f73cb21fe83b0f7cfd865eca5d3929449f874cbbca7b2"
    )
    assert len(rights.dataset_grants) == 3
    assert tuple(row.official_dataset_id for row in rights.dataset_grants) == (
        "15101578",
        "15101971",
        "15101914",
    )
    assert len(rights.asset_rights) == 1_592
    assert len(rights.attachment_rights) == 8
    assert all(not row.attachment_rights_granting for row in rights.attachment_rights)
    assert all(not row.identity_merging for row in rights.attachment_rights)

    assert len(evidence.rows) == 718
    assert {row.place_entity_id for row in evidence.rows} == {
        row.place_entity_id for row in evidence.rows
    }
    assert evidence.parents.rights_projection_sha256 == rights.projection_sha256
    assert all(
        (
            row.coordinates.reason_codes
            and row.description.reason_codes
            and row.operating_info.reason_codes
            and row.dataset_rights.reason_codes
            and row.direct_media.reason_codes
        )
        for row in evidence.rows
    )


def test_current_rights_bundle_replays_through_versioned_lineage_successor() -> None:
    attestation = build_current_attestation(
        REPOSITORY_ROOT,
        lineage_successor_path=LINEAGE_SUCCESSOR,
        rights_path=RIGHTS_PROJECTION,
        objective_path=OBJECTIVE_EVIDENCE,
        protected_before_path=PROTECTED_BEFORE,
    )

    assert attestation["schema_version"] == "rights-current-parent-attestation-v1"
    assert attestation["semantic_disposition"] == "UNCHANGED_REATTESTED"
    assert attestation["rights_semantics"]["counts"] == {
        "dataset_grant_count": 3,
        "asset_rights_count": 1_592,
        "allowed_asset_count": 920,
        "blocked_asset_count": 672,
        "attachment_rights_count": 8,
    }
    assert attestation["objective_semantics"]["candidate_count"] == 718
    assert attestation["lineage"]["current_inventory_sha256"] == (
        "e7011e47b22a6e0886ce8cd6e95e4c52f2448153e4fb94cccaacab204d039a32"
    )
    fingerprint_catalog_v1._assert_membership_free_payload(attestation)
    assert (
        verify_current_attestation(
            REPOSITORY_ROOT,
            attestation,
            lineage_successor_path=LINEAGE_SUCCESSOR,
            rights_path=RIGHTS_PROJECTION,
            objective_path=OBJECTIVE_EVIDENCE,
            protected_before_path=PROTECTED_BEFORE,
        )
        == attestation
    )


def test_current_rights_attestation_rejects_semantic_or_parent_drift() -> None:
    attestation = build_current_attestation(
        REPOSITORY_ROOT,
        lineage_successor_path=LINEAGE_SUCCESSOR,
        rights_path=RIGHTS_PROJECTION,
        objective_path=OBJECTIVE_EVIDENCE,
        protected_before_path=PROTECTED_BEFORE,
    )
    mutations = (
        ("lineage", "predecessor_manifest_sha256"),
        ("lineage", "successor_sha256"),
        ("lineage", "current_inventory_sha256"),
        ("original_rights", "file_sha256"),
        ("original_rights", "projection_sha256"),
        ("original_objective_evidence", "file_sha256"),
        ("original_objective_evidence", "report_sha256"),
        ("rights_semantics", "dataset_grants_root"),
        ("rights_semantics", "asset_rights_root"),
        ("rights_semantics", "attachment_rights_root"),
        ("objective_semantics", "rows_root"),
    )
    for section, field in mutations:
        tampered = copy.deepcopy(attestation)
        tampered[section][field] = "0" * 64
        tampered["attestation_sha256"] = fingerprint_catalog_v1.canonical_sha256(
            {
                key: value
                for key, value in tampered.items()
                if key != "attestation_sha256"
            }
        )
        with pytest.raises(ValueError, match="rights|objective|lineage|attestation"):
            verify_current_attestation(
                REPOSITORY_ROOT,
                tampered,
                lineage_successor_path=LINEAGE_SUCCESSOR,
                rights_path=RIGHTS_PROJECTION,
                objective_path=OBJECTIVE_EVIDENCE,
                protected_before_path=PROTECTED_BEFORE,
            )

    count_tamper = copy.deepcopy(attestation)
    count_tamper["rights_semantics"]["counts"]["allowed_asset_count"] += 1
    count_tamper["attestation_sha256"] = fingerprint_catalog_v1.canonical_sha256(
        {
            key: value
            for key, value in count_tamper.items()
            if key != "attestation_sha256"
        }
    )
    with pytest.raises(ValueError, match="rights|attestation"):
        verify_current_attestation(
            REPOSITORY_ROOT,
            count_tamper,
            lineage_successor_path=LINEAGE_SUCCESSOR,
            rights_path=RIGHTS_PROJECTION,
            objective_path=OBJECTIVE_EVIDENCE,
            protected_before_path=PROTECTED_BEFORE,
        )


def test_historical_rights_bundle_verifier_remains_strict() -> None:
    with pytest.raises(fingerprint_catalog_v1.FingerprintError):
        build_bundle(REPOSITORY_ROOT)
