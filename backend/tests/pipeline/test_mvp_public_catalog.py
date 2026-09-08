from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli import prepare_mvp_public_catalog
from itda.contracts.mvp_public_catalog import (
    OfficialDatasetPermissionMetadata,
    OfficialPermissionLane,
    PublicEvidence,
    PublicEvidenceInventory,
    PublicPlace,
    PublicPlaceCatalog,
    PublicPlaceRelation,
    PublicPlaceRelations,
    verify_blind_overlap_count,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_public_catalog import (
    build_catalog_gap_report,
    build_public_catalog,
    materialize_public_catalog,
    verify_permission_snapshot,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_UNIVERSE = (
    REPO_ROOT
    / "artifacts/catalog/optional-media-v2/policy"
    / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
    / "projected-candidates.json"
)
OFFICIAL_PERMISSION_ROOT = (
    REPO_ROOT / "artifacts/public/catalog/official-permission-snapshots"
)
V5_RESULT_PATH = (
    REPO_ROOT
    / "artifacts/public/catalog/mvp-public-enrichment-runs"
    / "7a70a63b472980b12afa17250be87aab7cefc1d26204ffb65ddb858f8c6aaeb9"
    / "result.json"
)
V6_RESULT_PATH = (
    REPO_ROOT
    / "artifacts/public/catalog/mvp-public-enrichment-runs"
    / "adad3f9b0b308aac2827258c9a9275f7fc01b9d20a6ebf4e43e4fb38a2fa414e"
    / "result.json"
)


PERMISSION_QUOTE = "합성 테스트 전용 공식 허용 문구"
PERMISSION_RAW = (
    "합성 테스트 관광정보 합성 테스트 제공기관 SYNTHETIC_TEST_GRANT "
    "합성 테스트 제공기관 · 합성 테스트 관광정보 "
    f"{PERMISSION_QUOTE} 합성 테스트에서만 사용"
).encode()


def _permission_metadata() -> OfficialDatasetPermissionMetadata:
    allowed = OfficialPermissionLane(
        decision="ALLOWED",
        evidence_quote=PERMISSION_QUOTE,
    )
    fields = {
        "schema_version": "official-dataset-permission-metadata.v2",
        "official_dataset_id": "15101578",
        "official_url": "https://www.data.go.kr/data/15101578/openapi.do",
        "retrieved_at": "2026-08-25T00:00:00Z",
        "raw_response_sha256": hashlib.sha256(PERMISSION_RAW).hexdigest(),
        "dataset_title_ko": "합성 테스트 관광정보",
        "provider_name_ko": "합성 테스트 제공기관",
        "license_type": "SYNTHETIC_TEST_GRANT",
        "attribution_required": True,
        "attribution_text_ko": "합성 테스트 제공기관 · 합성 테스트 관광정보",
        "no_attribution_evidence_ko": None,
        "public_display": allowed,
        "transformation_and_derived_scores": allowed,
        "third_party_model_processing_and_retention": allowed,
        "excerpt_and_release_redistribution": allowed,
        "commercial_scope": allowed,
        "restrictions_ko": "합성 테스트에서만 사용",
    }
    return OfficialDatasetPermissionMetadata(
        **fields,
        metadata_sha256=canonical_sha256(
            {
                **fields,
                "public_display": allowed.model_dump(mode="json"),
                "transformation_and_derived_scores": allowed.model_dump(mode="json"),
                "third_party_model_processing_and_retention": allowed.model_dump(mode="json"),
                "excerpt_and_release_redistribution": allowed.model_dump(mode="json"),
                "commercial_scope": allowed.model_dump(mode="json"),
            }
        ),
    )


def _evidence(ordinal: int) -> PublicEvidence:
    permission = _permission_metadata()
    fields = {
        "evidence_id": f"evidence:{ordinal:064x}",
        "provider": "TOUR_API",
        "official_dataset_id": "15101578",
        "provider_source_id": str(ordinal),
        "official_license_url": "https://www.data.go.kr/data/15101578/openapi.do",
        "license_type": permission.license_type,
        "attribution_text": permission.attribution_for_release,
        "reference_date": "2026-08-25",
        "excerpt": f"경주시 공개 관광 설명 {ordinal}",
        "source_response_sha256": f"{ordinal:064x}",
        "permission_metadata": permission,
        "commercial_use_allowed": True,
        "transform_allowed": True,
        "display_allowed": True,
        "model_input_allowed": True,
        "release_redistribution_allowed": True,
        "third_party_model_processing_allowed": True,
    }
    return PublicEvidence(
        **fields,
        evidence_sha256=canonical_sha256(
            {**fields, "permission_metadata": permission.model_dump(mode="json")}
        ),
    )


def _place(ordinal: int, evidence_id: str) -> PublicPlace:
    provider_crosswalk = ({"provider": "TOUR_API", "source_id": str(ordinal)},)
    fields = {
        "place_id": f"public:gyeongju:{ordinal:064x}",
        "pool": "PUBLIC",
        "name_ko": f"경주 관광지 {ordinal:03d}",
        "normalized_name_ko": f"경주관광지{ordinal:03d}",
        "category": "HISTORY_CULTURE" if ordinal % 2 else "REST_NATURE",
        "administrative_area": "경주시",
        "address_ko": f"경상북도 경주시 시험로 {ordinal}",
        "latitude": 35.0 + ordinal / 10_000,
        "longitude": 129.0 + ordinal / 10_000,
        "provider_crosswalk": provider_crosswalk,
        "evidence_ids": (evidence_id,),
        "duplicate_group_id": f"duplicate:{ordinal:064x}",
    }
    return PublicPlace(**fields, row_sha256=canonical_sha256(fields))


def _inventory(count: int = 100) -> PublicEvidenceInventory:
    rows = tuple(_evidence(index) for index in range(1, count + 1))
    fields = {"schema_version": "public-evidence-inventory.v1", "evidence": rows}
    return PublicEvidenceInventory(
        **fields,
        inventory_sha256=canonical_sha256(
            {
                "schema_version": fields["schema_version"],
                "evidence": [row.model_dump(mode="json") for row in rows],
            }
        ),
    )


def _permission_snapshots(inventory: PublicEvidenceInventory) -> dict[str, bytes]:
    return {row.permission_metadata.metadata_sha256: PERMISSION_RAW for row in inventory.evidence}


def _official_permission_inputs() -> tuple[
    tuple[OfficialDatasetPermissionMetadata, ...],
    dict[str, bytes],
]:
    permissions = tuple(
        OfficialDatasetPermissionMetadata.model_validate_json(
            (OFFICIAL_PERMISSION_ROOT / f"{dataset}.metadata.json").read_bytes()
        )
        for dataset in ("15101578", "15101971")
    )
    snapshots = {
        permission.metadata_sha256: (
            OFFICIAL_PERMISSION_ROOT / f"{permission.official_dataset_id}.raw"
        ).read_bytes()
        for permission in permissions
    }
    return permissions, snapshots


def test_tracked_source_reports_exact_public_safe_gap() -> None:
    report = build_catalog_gap_report(SOURCE_UNIVERSE)

    assert report.tracked_candidate_count == 718
    assert report.description_ready_historical_count == 40
    assert report.description_enrichment_candidate_count == 620
    assert report.preliminary_description_gap_count == 60
    assert report.strict_rights_qualified_count is None
    assert report.strict_rights_state == "BLOCKED_RIGHTS_METADATA"
    assert report.catalog_ready is False
    assert report.permission_metadata_present is False
    assert report.permission_bindings == ()
    assert report.provider_traffic is False
    assert report.secret_access is False


def test_tracked_source_reports_verified_permission_without_claiming_catalog_ready() -> None:
    permissions, snapshots = _official_permission_inputs()

    report = build_catalog_gap_report(
        SOURCE_UNIVERSE,
        permissions=permissions,
        permission_snapshots=snapshots,
    )

    assert report.strict_rights_state == "PERMISSION_METADATA_VERIFIED"
    assert report.permission_metadata_present is True
    assert tuple(row.official_dataset_id for row in report.permission_bindings) == (
        "15101578",
        "15101971",
    )
    assert report.preliminary_description_gap_count == 60
    assert report.strict_rights_qualified_count is None
    assert report.catalog_ready is False
    assert report.provider_traffic is False
    assert report.secret_access is False


def test_tracked_source_rejects_partial_or_drifted_permission_inputs() -> None:
    permissions, snapshots = _official_permission_inputs()
    with pytest.raises(ValueError, match="exact official dataset"):
        build_catalog_gap_report(
            SOURCE_UNIVERSE,
            permissions=permissions[:1],
            permission_snapshots={
                permissions[0].metadata_sha256: snapshots[permissions[0].metadata_sha256]
            },
        )

    drifted = dict(snapshots)
    drifted[permissions[0].metadata_sha256] += b" drift"
    with pytest.raises(ValueError, match="hash does not match"):
        build_catalog_gap_report(
            SOURCE_UNIVERSE,
            permissions=permissions,
            permission_snapshots=drifted,
        )


def test_real_enrichment_materializes_exact_byte_stable_public_100() -> None:
    permissions, snapshots = _official_permission_inputs()
    tourapi = next(row for row in permissions if row.official_dataset_id == "15101578")

    first = materialize_public_catalog(
        V5_RESULT_PATH,
        V6_RESULT_PATH,
        permission=tourapi,
        permission_snapshots=snapshots,
        reference_date=date(2026, 8, 26),
    )
    second = materialize_public_catalog(
        V5_RESULT_PATH,
        V6_RESULT_PATH,
        permission=tourapi,
        permission_snapshots=snapshots,
        reference_date=date(2026, 8, 26),
    )

    catalog, inventory, relations = first
    assert first == second
    assert len(catalog.places) == len(inventory.evidence) == 100
    assert len(relations.relations) == 0
    assert catalog.evidence_inventory_sha256 == inventory.inventory_sha256
    assert relations.catalog_sha256 == catalog.catalog_sha256
    source_ids = {
        crosswalk.source_id
        for place in catalog.places
        for crosswalk in place.provider_crosswalk
    }
    assert len(source_ids) == 100
    assert all(place.pool == "PUBLIC" for place in catalog.places)
    assert all(evidence.model_input_allowed for evidence in inventory.evidence)
    serialized = canonical_json_bytes(
        {
            "catalog": catalog.model_dump(mode="json"),
            "inventory": inventory.model_dump(mode="json"),
            "relations": relations.model_dump(mode="json"),
        }
    ).lower()
    for forbidden in (b"secret", b"authorization", b"openrouter"):
        assert forbidden not in serialized


def test_exact_100_catalog_is_sorted_rights_bound_and_byte_stable() -> None:
    inventory = _inventory()
    candidates = tuple(
        _place(index, inventory.evidence[index - 1].evidence_id) for index in range(100, 0, -1)
    )

    first, relations = build_public_catalog(
        candidates,
        inventory,
        permission_snapshots=_permission_snapshots(inventory),
        cannot_coappear=(),
    )
    second, second_relations = build_public_catalog(
        candidates,
        inventory,
        permission_snapshots=_permission_snapshots(inventory),
        cannot_coappear=(),
    )

    assert len(first.places) == 100
    assert tuple(row.place_id for row in first.places) == tuple(
        sorted(row.place_id for row in first.places)
    )
    assert first == second
    assert relations == second_relations
    assert first.blind_overlap_count == 0


def test_catalog_rejects_fewer_than_100_without_synthesizing() -> None:
    inventory = _inventory(99)
    candidates = tuple(
        _place(index, inventory.evidence[index - 1].evidence_id) for index in range(1, 100)
    )

    with pytest.raises(ValueError, match="exactly 100"):
        build_public_catalog(
            candidates,
            inventory,
            permission_snapshots=_permission_snapshots(inventory),
            cannot_coappear=(),
        )


def test_catalog_rejects_duplicate_name_and_coordinates() -> None:
    inventory = _inventory()
    candidates = [
        _place(index, inventory.evidence[index - 1].evidence_id) for index in range(1, 101)
    ]
    duplicate = candidates[-1].model_dump(mode="json")
    duplicate["normalized_name_ko"] = candidates[0].normalized_name_ko
    duplicate["latitude"] = candidates[0].latitude
    duplicate["longitude"] = candidates[0].longitude
    duplicate["row_sha256"] = canonical_sha256(
        {key: value for key, value in duplicate.items() if key != "row_sha256"}
    )
    candidates[-1] = PublicPlace.model_validate(duplicate)

    with pytest.raises(ValueError, match="duplicate normalized place"):
        build_public_catalog(
            candidates,
            inventory,
            permission_snapshots=_permission_snapshots(inventory),
            cannot_coappear=(),
        )


def test_evidence_rights_are_fail_closed() -> None:
    payload = _evidence(1).model_dump(mode="json")
    payload["model_input_allowed"] = False
    payload["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )

    with pytest.raises(ValidationError, match="Input should be True"):
        PublicEvidence.model_validate(payload)


def test_historical_rights_flags_cannot_construct_strict_public_evidence() -> None:
    payload = _evidence(1).model_dump(mode="json")
    payload.pop("permission_metadata")
    payload["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )

    with pytest.raises(ValidationError, match="permission_metadata"):
        PublicEvidence.model_validate(payload)


def _unknown_model_lane_permission() -> OfficialDatasetPermissionMetadata:
    payload = _permission_metadata().model_dump(mode="json")
    payload["third_party_model_processing_and_retention"] = {
        "decision": "UNKNOWN",
        "evidence_quote": PERMISSION_QUOTE,
    }
    payload["metadata_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "metadata_sha256"}
    )
    return OfficialDatasetPermissionMetadata.model_validate(payload)


def test_unknown_official_permission_lane_blocks_mvp_projection() -> None:
    permission = _unknown_model_lane_permission()
    assert permission.permits_mvp_use is False

    evidence = _evidence(1).model_dump(mode="json")
    evidence["permission_metadata"] = permission.model_dump(mode="json")
    evidence["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    )
    with pytest.raises(ValidationError, match="does not permit all MVP usage lanes"):
        PublicEvidence.model_validate(evidence)


def test_permission_checkpoint_is_provider_free_and_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    allowed = tmp_path / "allowed.json"
    blocked = tmp_path / "blocked.json"
    raw = tmp_path / "permission.html"
    raw.write_bytes(PERMISSION_RAW)
    allowed.write_bytes(canonical_json_bytes(_permission_metadata().model_dump(mode="json")))
    blocked.write_bytes(
        canonical_json_bytes(_unknown_model_lane_permission().model_dump(mode="json"))
    )

    assert (
        prepare_mvp_public_catalog.main(
            ["verify-permission", str(allowed), "--raw-snapshot", str(raw)]
        )
        == 0
    )
    allowed_output = capsys.readouterr().out
    assert "mvp_usage=allowed" in allowed_output
    assert "provider_traffic=false" in allowed_output

    assert (
        prepare_mvp_public_catalog.main(
            ["verify-permission", str(blocked), "--raw-snapshot", str(raw)]
        )
        == 2
    )
    blocked_output = capsys.readouterr().out
    assert "mvp_usage=blocked" in blocked_output
    assert "provider_traffic=false" in blocked_output


def test_permission_snapshot_rejects_hash_and_quote_mismatch() -> None:
    permission = _permission_metadata()
    with pytest.raises(ValueError, match="hash does not match"):
        verify_permission_snapshot(permission, PERMISSION_RAW + b" drift")

    payload = permission.model_dump(mode="json")
    payload["public_display"]["evidence_quote"] = "원문에 없는 문구"
    payload["metadata_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "metadata_sha256"}
    )
    changed = OfficialDatasetPermissionMetadata.model_validate(payload)
    with pytest.raises(ValueError, match="quote is absent"):
        verify_permission_snapshot(changed, PERMISSION_RAW)


@pytest.mark.parametrize(
    "field",
    [
        "dataset_title_ko",
        "provider_name_ko",
        "license_type",
        "attribution_text_ko",
        "restrictions_ko",
        "public_display",
        "transformation_and_derived_scores",
        "third_party_model_processing_and_retention",
        "excerpt_and_release_redistribution",
        "commercial_scope",
    ],
)
def test_every_permission_quote_must_exist_in_snapshot(field: str) -> None:
    payload = _permission_metadata().model_dump(mode="json")
    if isinstance(payload[field], dict):
        payload[field]["evidence_quote"] = f"원문에 없는 {field} 문구"
    else:
        payload[field] = f"원문에 없는 {field} 문구"
    payload["metadata_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "metadata_sha256"}
    )
    changed = OfficialDatasetPermissionMetadata.model_validate(payload)
    with pytest.raises(ValueError, match="quote is absent"):
        verify_permission_snapshot(changed, PERMISSION_RAW)


def test_inspect_tracked_binds_exact_official_permissions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "gap.json"
    argv = [
        "inspect-tracked",
        "--source",
        str(SOURCE_UNIVERSE),
        "--output",
        str(output),
    ]
    for dataset in ("15101578", "15101971"):
        argv.extend(
            [
                "--permission",
                str(OFFICIAL_PERMISSION_ROOT / f"{dataset}.metadata.json")
                + "="
                + str(OFFICIAL_PERMISSION_ROOT / f"{dataset}.raw"),
            ]
        )

    assert prepare_mvp_public_catalog.main(argv) == 2
    report = prepare_mvp_public_catalog.CatalogGapReport.model_validate_json(
        output.read_bytes()
    )
    assert report.strict_rights_state == "PERMISSION_METADATA_VERIFIED"
    assert report.permission_metadata_present is True
    assert "strict_rights_state=permission_metadata_verified" in capsys.readouterr().out


def test_permission_checkpoint_requires_raw_snapshot_argument() -> None:
    with pytest.raises(SystemExit):
        prepare_mvp_public_catalog.build_parser().parse_args(["verify-permission", "metadata.json"])


def test_catalog_requires_exact_permission_snapshot() -> None:
    inventory = _inventory()
    candidates = tuple(
        _place(index, inventory.evidence[index - 1].evidence_id) for index in range(1, 101)
    )
    with pytest.raises(ValueError, match="must cover"):
        build_public_catalog(
            candidates,
            inventory,
            permission_snapshots={},
            cannot_coappear=(),
        )


def test_permission_checkpoint_rejects_invalid_snapshot_files(tmp_path: Path) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(canonical_json_bytes(_permission_metadata().model_dump(mode="json")))
    empty = tmp_path / "empty.html"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="file is invalid"):
        prepare_mvp_public_catalog.main(
            ["verify-permission", str(metadata), "--raw-snapshot", str(empty)]
        )

    target = tmp_path / "target.html"
    target.write_bytes(PERMISSION_RAW)
    link = tmp_path / "link.html"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="file is invalid"):
        prepare_mvp_public_catalog.main(
            ["verify-permission", str(metadata), "--raw-snapshot", str(link)]
        )

    oversized = tmp_path / "oversized.html"
    oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="file is invalid"):
        prepare_mvp_public_catalog.main(
            ["verify-permission", str(metadata), "--raw-snapshot", str(oversized)]
        )


def test_relations_are_internal_sorted_and_hash_bound() -> None:
    inventory = _inventory()
    candidates = tuple(
        _place(index, inventory.evidence[index - 1].evidence_id) for index in range(1, 101)
    )
    left = candidates[0].place_id
    right = candidates[1].place_id

    catalog, relations = build_public_catalog(
        candidates,
        inventory,
        permission_snapshots=_permission_snapshots(inventory),
        cannot_coappear=((right, left, "동일 방문 단위"),),
    )

    assert relations.relations[0].left_place_id == min(left, right)
    assert relations.catalog_sha256 == catalog.catalog_sha256

    invalid_fields = {
        "schema_version": "public-place-relations.v1",
        "catalog_sha256": catalog.catalog_sha256,
        "relations": (
            PublicPlaceRelation(
                relation_type="CANNOT_COAPPEAR",
                left_place_id=left,
                right_place_id=f"public:gyeongju:{999:064x}",
                reason="catalog 밖 endpoint",
            ),
        ),
    }
    with pytest.raises(ValidationError, match="catalog endpoint"):
        PublicPlaceRelations(
            **invalid_fields,
            catalog_place_ids=tuple(row.place_id for row in catalog.places),
            relations_sha256=canonical_sha256(
                {
                    **invalid_fields,
                    "relations": [
                        row.model_dump(mode="json") for row in invalid_fields["relations"]
                    ],
                    "catalog_place_ids": [row.place_id for row in catalog.places],
                }
            ),
        )


def test_blind_overlap_verifier_returns_only_zero_count() -> None:
    public_ids = tuple(f"public:gyeongju:{index:064x}" for index in range(1, 101))
    blind_ids = tuple(f"blind:{index:064x}" for index in range(1, 13))

    assert verify_blind_overlap_count(public_ids, blind_ids) == 0

    overlapping = deepcopy(list(blind_ids))
    overlapping[0] = public_ids[0]
    with pytest.raises(ValueError, match="BLIND overlap is non-zero"):
        verify_blind_overlap_count(public_ids, overlapping)


def test_catalog_contract_rejects_blind_shaped_fields() -> None:
    inventory = _inventory()
    candidates = tuple(
        _place(index, inventory.evidence[index - 1].evidence_id) for index in range(1, 101)
    )
    catalog, _ = build_public_catalog(
        candidates,
        inventory,
        permission_snapshots=_permission_snapshots(inventory),
        cannot_coappear=(),
    )
    payload = catalog.model_dump(mode="json")
    payload["blind_membership"] = []

    with pytest.raises(ValidationError, match="Extra inputs"):
        PublicPlaceCatalog.model_validate(payload)
