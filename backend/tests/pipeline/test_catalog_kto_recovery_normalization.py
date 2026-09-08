from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from itda.cli.audit_catalog_readiness import (
    build_kto_recovery_readiness,
    build_kto_recovery_terminal_failure,
    publish_kto_recovery_readiness,
    publish_kto_recovery_terminal_failure,
)
from itda.cli.normalize_catalog_enrichment import (
    build_kto_recovery_normalization,
    publish_kto_recovery_normalization,
)
from itda.contracts.catalog_audit import CatalogAudit
from itda.contracts.catalog_enrichment_evidence import (
    KTO_MAX_JSON_DEPTH,
    KTO_MAX_RAW_BYTES,
    normalize_kto_recovery_response,
)
from itda.domain.canonical import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).parents[3]
COLLECTION_ROOT = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/collections"
    / "f122ae1c67359ec4f855d57159921cc41be6879df62eb85f0515c46b4bf78612"
)
AUDIT_PATH = REPOSITORY_ROOT / "artifacts/restricted/catalog/v1/review/catalog-audit.json"
EMPTY_IMAGE_IDENTITIES = {
    "975047e072f7561642f5c226ad4b1bf31b6e500651e3492d75a84b5e0c888463",
    "d8746cdf8500083a739f44d19d73f53397cbad52fb6e3838ada2ef44f757d3f7",
}


def _grant():
    audit = CatalogAudit.model_validate_json(AUDIT_PATH.read_bytes())
    return next(row for row in audit.grants if row.official_dataset_id == "15101578")


def _request(
    operation: str,
    *,
    content_id: str = "12345",
    content_type_id: str | None = None,
    num_of_rows: int = 100,
) -> dict[str, object]:
    parameters = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
        "contentId": content_id,
        "numOfRows": str(num_of_rows),
        "pageNo": "1",
    }
    if content_type_id is not None:
        parameters["contentTypeId"] = content_type_id
    if operation == "detailImage2":
        parameters["imageYN"] = "Y"
    return {
        "provider": "TourAPI",
        "operation": operation,
        "provider_candidate_id": f"candidate:tour-api:{content_id}",
        "place_entity_id": f"place:{'1' * 64}",
        "parameters": parameters,
        "request_identity": "2" * 64,
    }


def _terminal(raw: bytes) -> dict[str, object]:
    return {
        "request_identity": "2" * 64,
        "terminal_status": "SUCCESS_WITH_ITEMS",
        "provider_result_code": "0000",
        "provider_result_value": "OK",
        "normalized_reason": None,
        "raw_body_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_relative_path": "raw/2/attempt-001.response",
        "completed_at": "2026-07-30T15:00:00+00:00",
    }


def _body(item: object, *, num_of_rows: int = 100) -> bytes:
    return canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {
                    "items": {"item": item},
                    "numOfRows": num_of_rows,
                    "pageNo": 1,
                    "totalCount": 1,
                },
            }
        }
    )


@pytest.mark.parametrize(
    ("content_type_id", "field_name"),
    [
        ("12", "usetime"),
        ("14", "usetimeculture"),
        ("15", "playtime"),
        ("28", "usetimeleports"),
        ("32", "checkintime"),
        ("38", "opentime"),
        ("39", "opentimefood"),
    ],
)
def test_operating_information_uses_only_actual_type_fields(
    content_type_id: str,
    field_name: str,
) -> None:
    item = {
        "contentid": "12345",
        "contenttypeid": content_type_id,
        field_name: "09:00~18:00",
        "addr1": "주소는 운영정보가 아니다",
        "modifiedtime": "20260730000000",
        "showflag": "1",
        "overview": "일반 설명은 운영정보가 아니다",
    }
    raw = _body(item)

    normalized = normalize_kto_recovery_response(
        planned_request=_request(
            "detailIntro2",
            content_type_id=content_type_id,
        ),
        terminal_record=_terminal(raw),
        raw_body=raw,
        grant=_grant(),
    )

    assert normalized["actual_content_type_id"] == content_type_id
    assert normalized["operating_information"] == {field_name: "09:00~18:00"}
    assert normalized["operating_state"] == "PASS"


def test_type_25_and_generic_metadata_never_pass_operating_information() -> None:
    raw = _body(
        {
            "contentid": "12345",
            "contenttypeid": "25",
            "taketime": "약 3시간",
            "overview": "일반 설명",
            "addr1": "경주시",
            "modifiedtime": "20260730000000",
            "showflag": "1",
        }
    )

    normalized = normalize_kto_recovery_response(
        planned_request=_request("detailIntro2", content_type_id="25"),
        terminal_record=_terminal(raw),
        raw_body=raw,
        grant=_grant(),
    )

    assert normalized["operating_information"] == {}
    assert normalized["operating_state"] == "TYPE_INAPPLICABLE"
    assert normalized["operating_reason"] == "CONTENT_TYPE_25_POLICY_REQUIRED"


def test_array_singleton_and_empty_items_are_distinct_and_deterministic() -> None:
    item = {
        "contentid": "12345",
        "contenttypeid": "12",
        "mapx": "129.1",
        "mapy": "35.8",
        "overview": "실제 설명",
    }
    array_raw = _body([item], num_of_rows=1)
    singleton_raw = _body(item, num_of_rows=1)
    empty_raw = canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {"items": "", "numOfRows": 1, "pageNo": 1, "totalCount": 0},
            }
        }
    )

    array = normalize_kto_recovery_response(
        planned_request=_request("detailCommon2", num_of_rows=1),
        terminal_record=_terminal(array_raw),
        raw_body=array_raw,
        grant=_grant(),
    )
    singleton = normalize_kto_recovery_response(
        planned_request=_request("detailCommon2", num_of_rows=1),
        terminal_record=_terminal(singleton_raw),
        raw_body=singleton_raw,
        grant=_grant(),
    )
    empty = normalize_kto_recovery_response(
        planned_request=_request("detailCommon2", num_of_rows=1),
        terminal_record=_terminal(empty_raw),
        raw_body=empty_raw,
        grant=_grant(),
    )

    assert array["normalized_items"] == singleton["normalized_items"]
    assert array["item_shape"] == "ARRAY"
    assert singleton["item_shape"] == "SINGLETON"
    assert empty["item_shape"] == "EMPTY"
    assert empty["description_state"] == "MISSING"
    assert empty["transport_state"] == "SUCCESS_EMPTY"


def test_raw_depth_and_item_limits_fail_before_partial_materialization() -> None:
    item = {"contentid": "12345", "contenttypeid": "12", "overview": "설명"}
    oversized = b" " * (KTO_MAX_RAW_BYTES + 1)
    with pytest.raises(ValueError, match="8 MiB"):
        normalize_kto_recovery_response(
            planned_request=_request("detailCommon2", num_of_rows=1),
            terminal_record=_terminal(oversized),
            raw_body=oversized,
            grant=_grant(),
        )

    nested: object = "leaf"
    for _ in range(KTO_MAX_JSON_DEPTH + 1):
        nested = {"x": nested}
    deep_raw = json.dumps(nested).encode()
    with pytest.raises(ValueError, match="depth"):
        normalize_kto_recovery_response(
            planned_request=_request("detailCommon2", num_of_rows=1),
            terminal_record=_terminal(deep_raw),
            raw_body=deep_raw,
            grant=_grant(),
        )

    excess_raw = _body([item, item], num_of_rows=1)
    with pytest.raises(ValueError, match="declared numOfRows"):
        normalize_kto_recovery_response(
            planned_request=_request("detailCommon2", num_of_rows=1),
            terminal_record=_terminal(excess_raw),
            raw_body=excess_raw,
            grant=_grant(),
        )


def test_dataset_and_asset_rights_are_separate_and_type3_vetoes_all_lanes() -> None:
    raw = _body(
        [
            {
                "contentid": "12345",
                "originimgurl": "https://tong.visitkorea.or.kr/a.jpg",
                "smallimageurl": "https://tong.visitkorea.or.kr/a-small.jpg",
                "serialnum": "asset-1",
                "imgname": "대표 사진",
                "cpyrhtDivCd": "Type1",
            },
            {
                "contentid": "12345",
                "originimgurl": "https://tong.visitkorea.or.kr/b.jpg",
                "smallimageurl": "https://tong.visitkorea.or.kr/b-small.jpg",
                "serialnum": "asset-2",
                "imgname": "제3자 사진",
                "cpyrhtDivCd": "Type3",
            },
        ],
        num_of_rows=100,
    )

    normalized = normalize_kto_recovery_response(
        planned_request=_request("detailImage2"),
        terminal_record=_terminal(raw),
        raw_body=raw,
        grant=_grant(),
    )

    assert normalized["dataset_rights"]["state"] == "PASS"
    assert normalized["asset_rights"]["state"] == "BLOCKED"
    assert normalized["asset_rights"]["reason"] == "NARROWER_TYPE3_ASSET_RESTRICTION"
    assert normalized["asset_rights"]["analysis_eligible"] is False
    assert normalized["asset_rights"]["ui_eligible"] is False
    assert normalized["asset_rights"]["demo_eligible"] is False
    assert normalized["direct_media_state"] == "RIGHTS_BLOCKED"


def test_exact_plan48_collection_builds_twice_and_preserves_success_empty_rows(
    tmp_path: Path,
) -> None:
    first = build_kto_recovery_normalization(REPOSITORY_ROOT)
    second = build_kto_recovery_normalization(REPOSITORY_ROOT)

    assert first == second
    assert first.collection_base == COLLECTION_ROOT.name
    assert first.response_count == 48
    assert first.request_count == 48
    assert first.success_empty_count == 2
    assert {
        row["request_identity"]
        for row in first.responses
        if row["transport_state"] == "SUCCESS_EMPTY"
    } == EMPTY_IMAGE_IDENTITIES
    assert {
        row["provider_content_id"]
        for row in first.responses
        if row["transport_state"] == "SUCCESS_EMPTY"
    } == {"1621764", "1959067"}

    published = publish_kto_recovery_normalization(
        first,
        repository_root=REPOSITORY_ROOT,
        output_base=tmp_path / "normalizations",
    )
    assert published.name == first.normalization_root_sha256
    assert stat.S_IMODE(os.lstat(published).st_mode) == 0o700
    assert {stat.S_IMODE(os.lstat(path).st_mode) for path in published.iterdir()} == {0o600}


def test_readiness_replays_exact_targets_and_leaf_derived_full_universe(
    tmp_path: Path,
) -> None:
    first = build_kto_recovery_readiness(REPOSITORY_ROOT)
    second = build_kto_recovery_readiness(REPOSITORY_ROOT)

    assert first == second
    assert first.target_count == 24
    assert first.universe_count == 718
    assert first.unresolved_count == 15
    assert first.objective_eligible_count == 22
    assert first.human_identity_relationship_decisions == 6
    assert first.maximum_human_decisions == 6
    assert first.representation_feasible is False
    assert sum(first.group_counts.values()) == first.objective_eligible_count
    assert first.capped_capacity < 36
    assert {
        row["provider_content_id"]
        for row in first.frontier_rows
        if row["deficit_reason"] == "SUCCESS_EMPTY_DIRECT_MEDIA"
    } == {"1621764", "1959067"}
    assert all(
        row["substitute_provider_candidate_id"] is None
        and row["required_next_action"] == "STOP_EVIDENCE_FRONTIER_EXHAUSTED"
        for row in first.frontier_rows
    )
    assert first.reentry_disposition == {
        "required": False,
        "reentry_ordinal": 0,
        "request_packet": None,
        "reason": "EVIDENCE_FRONTIER_EXHAUSTED",
    }

    published = publish_kto_recovery_readiness(
        first,
        repository_root=REPOSITORY_ROOT,
        substitutions_base=tmp_path / "substitutions",
        preflight_base=tmp_path / "preflight-readiness",
    )
    assert published.substitution_root.name == first.substitution_root_sha256
    assert published.preflight_root.name == first.preflight_root_sha256
    assert {
        stat.S_IMODE(os.lstat(path).st_mode)
        for root in (published.substitution_root, published.preflight_root)
        for path in root.iterdir()
    } == {0o600}


def test_readiness_frontier_excludes_every_attempted_provider_identity() -> None:
    readiness = build_kto_recovery_readiness(REPOSITORY_ROOT)

    assert readiness.reentry_ordinal == 0
    assert readiness.reentry_root_sha256
    assert readiness.attempted_provider_count == 100
    assert not readiness.substitute_rows
    assert readiness.outcome == "BLOCKED"
    assert readiness.outcome_reason == "EVIDENCE_FRONTIER_EXHAUSTED"
    assert readiness.plan50_reachable is False


def test_rejected_exhausted_frontier_publishes_summary_free_terminal_record(
    tmp_path: Path,
) -> None:
    signal = "reject-kto-substitutions:evidence-frontier-exhausted"
    first = build_kto_recovery_terminal_failure(
        REPOSITORY_ROOT,
        resume_signal=signal,
    )
    second = build_kto_recovery_terminal_failure(
        REPOSITORY_ROOT,
        resume_signal=signal,
    )

    assert first == second
    assert first.payload["status"] == "REENTRY_EXHAUSTED"
    assert first.payload["outcome_code"] == 21
    assert first.payload["unresolved_count"] == 15
    assert first.payload["substitute_count"] == 0
    assert first.payload["reentry_ordinal"] == 0
    assert first.payload["reentry_collection_root_sha256"] is None
    assert first.payload["summary_permitted"] is False
    assert first.payload["plan50_reachable"] is False
    assert first.payload["external_effects"] == {
        "network_performed": False,
        "credential_read": False,
        "authority_issued_or_consumed": False,
        "nonce_created_or_consumed": False,
        "provider_collection_performed": False,
    }
    published = publish_kto_recovery_terminal_failure(
        first,
        repository_root=REPOSITORY_ROOT,
        resume_signal=signal,
        output_base=tmp_path / "reentries",
    )
    assert published.name == first.terminal_root_sha256
    assert stat.S_IMODE(os.lstat(published).st_mode) == 0o700
    assert {stat.S_IMODE(os.lstat(path).st_mode) for path in published.iterdir()} == {0o600}


@pytest.mark.parametrize(
    "signal",
    [
        "approve-kto-substitutions:92944124:reviewer",
        "authorize-kto-substitution-reentry:6022bf44:reviewer",
        "no-substitution-required:821b0551",
        "reject-kto-substitutions:any-other-reason",
    ],
)
def test_terminal_failure_rejects_every_nonmatching_resume_signal(signal: str) -> None:
    with pytest.raises(ValueError, match="exact exhausted frontier"):
        build_kto_recovery_terminal_failure(
            REPOSITORY_ROOT,
            resume_signal=signal,
        )
