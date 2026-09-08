from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.cli.normalize_catalog_enrichment import (
    _parser,
    load_round_context,
    publish_bytes_no_replace,
)
from itda.contracts.catalog_audit import CatalogAudit, DatasetGrantEvidence
from itda.contracts.catalog_enrichment import (
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    build_enrichment_plan,
    publish_enrichment_bundle,
)
from itda.contracts.catalog_enrichment_evidence import (
    build_enrichment_sidecar,
    canonical_sidecar_bytes,
    normalize_terminal_response,
)
from itda.domain.canonical import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).parents[3]
ROUND_ID = "a59fabf3371845fbacb4e32510b178b03d7a784d0becfea6edfd7f7b2e4f2c25"
ROUND_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog/v2/enrichment/rounds" / ROUND_ID
POOL_PATH = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/enrichment/enrichment-candidate-pool.json"
)
CATALOG_AUDIT_PATH = REPOSITORY_ROOT / "artifacts/restricted/catalog/v1/review/catalog-audit.json"
HEX_B = "b" * 64
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def _tourapi_grant() -> DatasetGrantEvidence:
    audit = CatalogAudit.model_validate_json(CATALOG_AUDIT_PATH.read_bytes())
    return next(grant for grant in audit.grants if grant.official_dataset_id == "15101578")


def _planned_request(
    *,
    operation: str,
    mapped_fields: list[str],
) -> dict[str, object]:
    return {
        "provider": "TourAPI",
        "service": "KorService2",
        "operation": operation,
        "provider_candidate_id": "candidate:tour-api:12345",
        "place_entity_id": f"place:{'1' * 64}",
        "parameters": {
            "MobileOS": "ETC",
            "MobileApp": "IT-DA",
            "_type": "json",
            "contentId": "12345",
            "contentTypeId": "12",
        },
        "mapped_mandatory_fields": mapped_fields,
        "source_candidate_row_sha256": "2" * 64,
        "request_identity": "3" * 64,
    }


def _report(
    request: dict[str, object],
    raw_body: bytes,
    *,
    terminal_status: str = "SUCCESS",
) -> dict[str, object]:
    raw_sha256 = hashlib.sha256(raw_body).hexdigest()
    attempt = {
        "attempt_number": 1,
        "completed_at": "2026-07-29T00:00:01+00:00",
        "elapsed_ms": 1000,
        "http_status": 200,
        "normalized_reason": (
            None
            if terminal_status == "SUCCESS"
            else "provider response is not a valid result envelope"
        ),
        "provider_result_code": "0000" if terminal_status == "SUCCESS" else None,
        "provider_result_value": "OK" if terminal_status == "SUCCESS" else None,
        "raw_body_retention": "IMMUTABLE_ATTEMPT_SNAPSHOT",
        "raw_body_sha256": raw_sha256,
        "raw_relative_path": (f"raw/{request['request_identity']}/attempt-001.response"),
        "retryable": False,
        "safe_headers": {"content-type": "application/json"},
        "started_at": "2026-07-29T00:00:00+00:00",
        "terminal": True,
        "timeout_seconds": 300,
    }
    return {
        "ancestry_depth": 1,
        "attempt_count": 1,
        "attempts": [attempt],
        "attempts_per_request": 3,
        "http_status": 200,
        "invocation_id": "4" * 64,
        "mapped_mandatory_fields": request["mapped_mandatory_fields"],
        "normalized_reason": attempt["normalized_reason"],
        "operation": request["operation"],
        "overall_timeout_seconds": 162000,
        "per_attempt_timeout_seconds": 300,
        "provider": "TourAPI",
        "provider_result_code": attempt["provider_result_code"],
        "provider_result_value": attempt["provider_result_value"],
        "raw_body_retention": "IMMUTABLE_ATTEMPT_SNAPSHOT",
        "raw_body_sha256": raw_sha256,
        "raw_relative_path": attempt["raw_relative_path"],
        "request_identity": request["request_identity"],
        "round_id": ROUND_ID,
        "round_root": ("artifacts/restricted/catalog/v2/enrichment/rounds/" + ROUND_ID),
        "safe_headers": {"content-type": "application/json"},
        "schema_version": "itda.catalog-enrichment-collection-report-record.v1",
        "terminal_status": terminal_status,
        "token_sha256": "5" * 64,
    }


def _collection_log_event(
    request: dict[str, object],
    report: dict[str, object],
) -> dict[str, object]:
    attempt = dict(report["attempts"][0])
    return {
        "schema_version": "itda.catalog-enrichment-collection-log.v1",
        "round_id": report["round_id"],
        "invocation_id": report["invocation_id"],
        "request_identity": request["request_identity"],
        "provider": request["provider"],
        "operation": request["operation"],
        **attempt,
    }


def _current_plan() -> dict[str, object]:
    pool = json.loads(POOL_PATH.read_bytes())
    return build_enrichment_plan(pool, attempts=3)


def _build_test_initial_round(tmp_path: Path) -> tuple[Path, str]:
    plan = _current_plan()
    round_id = hashlib.sha256(canonical_json_bytes(plan)).hexdigest()
    root = tmp_path / "enrichment" / "rounds" / round_id
    frozen = FrozenEnrichmentIssuance(
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        nonce="1" * 64,
        reviewer_id="phase2-operator",
        code_sha256="2" * 64,
        config_sha256="3" * 64,
        permission_evidence_sha256=hashlib.sha256(
            canonical_json_bytes(plan["permission_evidence"])
        ).hexdigest(),
        previous_round_ref_sha256=None,
    )
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=frozen,
    )
    publish_enrichment_bundle(
        bundle,
        initial_reference_path=root.parents[1] / "initial-round-ref.json",
    )
    return root, round_id


def _build_test_remediation_round(
    previous_root: Path,
    previous_round_id: str,
    *,
    nonce: str,
    ancestry_depth: int,
) -> tuple[Path, str]:
    manifest_path = previous_root / "enrichment-round-manifest.json"
    manifest_bytes = canonical_json_bytes(
        {
            "schema_version": "test-round-manifest-v1",
            "round_id": previous_round_id,
            "ancestry_depth": ancestry_depth,
        }
    )
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o600)
    previous_ref = {
        "round_id": previous_round_id,
        "round_root": previous_root.as_posix(),
        "round_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "ancestry_depth": ancestry_depth,
    }
    previous_ref_sha256 = hashlib.sha256(canonical_json_bytes(previous_ref)).hexdigest()
    plan = _current_plan()
    plan["remediation"] = {
        "failed_request_identity": str(plan["requests"][0]["request_identity"]),
        "previous_round_ref": previous_ref,
    }
    round_id = hashlib.sha256(canonical_json_bytes(plan)).hexdigest()
    root = previous_root.parent / round_id
    frozen = FrozenEnrichmentIssuance(
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        nonce=nonce,
        reviewer_id="phase2-operator",
        code_sha256="2" * 64,
        config_sha256="3" * 64,
        permission_evidence_sha256=hashlib.sha256(
            canonical_json_bytes(plan["permission_evidence"])
        ).hexdigest(),
        previous_round_ref_sha256=previous_ref_sha256,
    )
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=frozen,
    )
    root.mkdir(mode=0o700)
    for name, payload in bundle.files.items():
        path = root / name
        path.write_bytes(payload)
        path.chmod(0o600)
    return root, round_id


def _success_body(operation: str) -> bytes:
    if operation == "detailCommon2":
        item = {
            "contentid": "12345",
            "contenttypeid": "12",
            "mapx": "129.1234",
            "mapy": "35.7890",
            "overview": "경주의 역사와 풍경을 설명하는 한국어 본문",
        }
    elif operation == "detailIntro2":
        item = {
            "contentid": "12345",
            "contenttypeid": "12",
            "infocenter": "054-000-0000",
            "restdate": "연중무휴",
            "usetime": "09:00~18:00",
            "parking": "주차 가능",
        }
    elif operation == "detailImage2":
        item = {
            "contentid": "12345",
            "originimgurl": "https://tong.visitkorea.or.kr/provider/12345.jpg",
            "smallimageurl": "https://tong.visitkorea.or.kr/provider/12345-thumb.jpg",
            "imgname": "대표 전경",
            "serialnum": "12345_1",
        }
    else:
        raise AssertionError(operation)
    return canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {
                    "items": {"item": [item]},
                    "numOfRows": 1,
                    "pageNo": 1,
                    "totalCount": 1,
                },
            }
        }
    )


def test_actual_selected_round_normalizes_every_terminal_response_once() -> None:
    sidecar = build_enrichment_sidecar(
        round_root=ROUND_ROOT,
        round_id=ROUND_ID,
        catalog_audit_path=CATALOG_AUDIT_PATH,
    )

    assert sidecar.schema_version == "itda.catalog-enrichment-evidence-sidecars.v1"
    assert sidecar.round_id == ROUND_ID
    assert sidecar.ancestry_depth == 1
    assert sidecar.response_count == 180
    assert len({row.request_identity for row in sidecar.responses}) == 180
    assert sidecar.terminal_status_counts == {
        "SUCCESS": 60,
        "TERMINAL_PROVIDER_FAILURE": 120,
        "RETRYABLE_FOR_RESUME": 0,
    }
    assert sidecar.operation_status_counts == {
        "detailCommon2": {
            "SUCCESS": 0,
            "TERMINAL_PROVIDER_FAILURE": 60,
            "RETRYABLE_FOR_RESUME": 0,
        },
        "detailIntro2": {
            "SUCCESS": 60,
            "TERMINAL_PROVIDER_FAILURE": 0,
            "RETRYABLE_FOR_RESUME": 0,
        },
        "detailImage2": {
            "SUCCESS": 0,
            "TERMINAL_PROVIDER_FAILURE": 60,
            "RETRYABLE_FOR_RESUME": 0,
        },
    }
    assert sidecar.field_state_counts == {
        "POPULATED": 51,
        "MISSING": 189,
        "BLOCKED": 0,
        "REVIEW_REQUIRED": 0,
    }
    assert all(
        field.raw_body_sha256 == row.raw_body_sha256
        and field.request_identity == row.request_identity
        and field.round_id == ROUND_ID
        and field.rights.dataset_grant_sha256
        for row in sidecar.responses
        for field in row.fields
    )
    assert canonical_sidecar_bytes(sidecar) == canonical_sidecar_bytes(
        build_enrichment_sidecar(
            round_root=ROUND_ROOT,
            round_id=ROUND_ID,
            catalog_audit_path=CATALOG_AUDIT_PATH,
        )
    )


@pytest.mark.parametrize(
    ("operation", "mapped_fields", "expected_names"),
    [
        (
            "detailCommon2",
            ["coordinates", "korean_description"],
            {"coordinates", "korean_description"},
        ),
        (
            "detailIntro2",
            ["provider_specific_operating_information"],
            {"provider_specific_operating_information"},
        ),
        (
            "detailImage2",
            ["exact_provider_direct_media"],
            {"exact_provider_direct_media"},
        ),
    ],
)
def test_populated_fields_bind_exact_content_raw_attempt_and_rights_evidence(
    operation: str,
    mapped_fields: list[str],
    expected_names: set[str],
) -> None:
    request = _planned_request(operation=operation, mapped_fields=mapped_fields)
    raw_body = _success_body(operation)

    row = normalize_terminal_response(
        planned_request=request,
        report_record=_report(request, raw_body),
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    assert {field.field_name for field in row.fields} == expected_names
    assert all(field.state == "POPULATED" for field in row.fields)
    assert all(field.content_identity.provider == "TOUR_API" for field in row.fields)
    assert all(
        field.content_identity.official_dataset_id == "15101578"
        and field.content_identity.provider_candidate_id == request["provider_candidate_id"]
        and field.rights.rights_state == "ALLOWED"
        and field.rights.source_request_sha256 == request["request_identity"]
        and field.rights.source_response_sha256 == hashlib.sha256(raw_body).hexdigest()
        and field.attempt_history_sha256
        == hashlib.sha256(canonical_json_bytes(_report(request, raw_body)["attempts"])).hexdigest()
        for field in row.fields
    )


def test_rights_block_suppresses_media_readiness_value() -> None:
    request = _planned_request(
        operation="detailImage2",
        mapped_fields=["exact_provider_direct_media"],
    )
    raw_body = _success_body("detailImage2")
    grant = _tourapi_grant().model_copy(
        update={
            "evidence_state": "INCOMPLETE",
            "commercial_use_allowed": False,
            "transform_allowed": False,
            "display_allowed": False,
            "model_input_allowed": False,
        }
    )

    row = normalize_terminal_response(
        planned_request=request,
        report_record=_report(request, raw_body),
        raw_body=raw_body,
        grant=grant,
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    field = row.fields[0]
    assert field.state == "BLOCKED"
    assert field.value is None
    assert field.deficit_reason == "GRANT_EVIDENCE_INCOMPLETE"
    assert field.rights.rights_state == "BLOCKED_GRANT_INCOMPLETE"


def test_cross_provider_media_is_review_only_and_cannot_pass_direct_media() -> None:
    request = _planned_request(
        operation="detailImage2",
        mapped_fields=["exact_provider_direct_media"],
    )
    body = json.loads(_success_body("detailImage2"))
    body["response"]["body"]["items"]["item"][0].update(
        {
            "provider": "TOURISM_PHOTO",
            "official_dataset_id": "15101914",
        }
    )
    raw_body = canonical_json_bytes(body)

    row = normalize_terminal_response(
        planned_request=request,
        report_record=_report(request, raw_body),
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    field = row.fields[0]
    assert field.state == "REVIEW_REQUIRED"
    assert field.value is None
    assert field.deficit_reason == "CROSS_PROVIDER_MEDIA_REQUIRES_HUMAN_REVIEW"
    assert field.rights.rights_state == "BLOCKED_DATASET_SCOPE_MISMATCH"


@pytest.mark.parametrize("empty_items", [{}, "", None])
def test_success_with_empty_provider_items_emits_named_missing_evidence(
    empty_items: object,
) -> None:
    request = _planned_request(
        operation="detailIntro2",
        mapped_fields=["provider_specific_operating_information"],
    )
    raw_body = canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {
                    "items": empty_items,
                    "numOfRows": 0,
                    "pageNo": 1,
                    "totalCount": 0,
                },
            }
        }
    )

    row = normalize_terminal_response(
        planned_request=request,
        report_record=_report(request, raw_body),
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    field = row.fields[0]
    assert field.state == "MISSING"
    assert field.value is None
    assert field.deficit_reason == "SUCCESS_RESPONSE_FIELD_EMPTY"
    assert field.raw_body_sha256 == hashlib.sha256(raw_body).hexdigest()


def test_narrower_media_restriction_overrides_authoritative_dataset_grant() -> None:
    request = _planned_request(
        operation="detailImage2",
        mapped_fields=["exact_provider_direct_media"],
    )
    body = json.loads(_success_body("detailImage2"))
    body["response"]["body"]["items"]["item"][0]["explicit_asset_restriction"] = (
        "ASSET_OWNER_PROHIBITS_DERIVATIVES"
    )
    raw_body = canonical_json_bytes(body)

    row = normalize_terminal_response(
        planned_request=request,
        report_record=_report(request, raw_body),
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    field = row.fields[0]
    assert field.state == "BLOCKED"
    assert field.value is None
    assert field.deficit_reason == "ASSET_OWNER_PROHIBITS_DERIVATIVES"
    assert field.rights.rights_state == "BLOCKED_EXPLICIT_ASSET_RESTRICTION"


def test_later_media_asset_restriction_vetoes_entire_aggregate_field() -> None:
    request = _planned_request(
        operation="detailImage2",
        mapped_fields=["exact_provider_direct_media"],
    )
    body = json.loads(_success_body("detailImage2"))
    body["response"]["body"]["items"]["item"].append(
        {
            "contentid": "12345",
            "originimgurl": "https://tong.visitkorea.or.kr/provider/12345-2.jpg",
            "smallimageurl": "https://tong.visitkorea.or.kr/provider/12345-2-thumb.jpg",
            "imgname": "제한된 전경",
            "serialnum": "12345_2",
            "explicit_asset_restriction": "SECOND_ASSET_DISPLAY_PROHIBITED",
        }
    )
    raw_body = canonical_json_bytes(body)

    row = normalize_terminal_response(
        planned_request=request,
        report_record=_report(request, raw_body),
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    field = row.fields[0]
    assert field.state == "BLOCKED"
    assert field.deficit_reason == "SECOND_ASSET_DISPLAY_PROHIBITED"
    assert field.rights.explicit_asset_restriction == ("SECOND_ASSET_DISPLAY_PROHIBITED")
    assert field.content_identity.source_asset_id is not None
    assert field.content_identity.source_asset_id.startswith("media-set:")


def test_provider_failure_remains_named_deficit_with_complete_attempt_history() -> None:
    request = _planned_request(
        operation="detailCommon2",
        mapped_fields=["coordinates", "korean_description"],
    )
    raw_body = canonical_json_bytes(
        {
            "responseTime": "2026-07-29T00:00:00+09:00",
            "resultCode": "10",
            "resultMsg": "INVALID_REQUEST_PARAMETER_ERROR",
        }
    )
    report = _report(request, raw_body, terminal_status="TERMINAL_PROVIDER_FAILURE")

    row = normalize_terminal_response(
        planned_request=request,
        report_record=report,
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
    )

    assert {field.state for field in row.fields} == {"MISSING"}
    assert {field.deficit_reason for field in row.fields} == {"TERMINAL_PROVIDER_FAILURE"}
    assert row.attempts == tuple(report["attempts"])
    assert row.normalized_reason == report["normalized_reason"]


def test_final_attempt_and_complete_collection_log_lineage_are_exact() -> None:
    request = _planned_request(
        operation="detailIntro2",
        mapped_fields=["provider_specific_operating_information"],
    )
    raw_body = _success_body("detailIntro2")
    report = _report(request, raw_body)
    log_event = _collection_log_event(request, report)

    row = normalize_terminal_response(
        planned_request=request,
        report_record=report,
        raw_body=raw_body,
        grant=_tourapi_grant(),
        round_id=ROUND_ID,
        round_root=ROUND_ROOT,
        collection_log_records=(log_event,),
    )
    assert (
        row.collection_log_history_sha256
        == hashlib.sha256(canonical_json_bytes([log_event])).hexdigest()
    )

    detached_report = _report(request, raw_body)
    detached_report["attempts"][0]["raw_relative_path"] = "raw/detached.response"
    with pytest.raises(ValueError, match="final attempt"):
        normalize_terminal_response(
            planned_request=request,
            report_record=detached_report,
            raw_body=raw_body,
            grant=_tourapi_grant(),
            round_id=ROUND_ID,
            round_root=ROUND_ROOT,
        )

    detached_log = _collection_log_event(request, report)
    detached_log["safe_headers"] = {"content-type": "text/plain"}
    with pytest.raises(ValueError, match="report attempts"):
        normalize_terminal_response(
            planned_request=request,
            report_record=report,
            raw_body=raw_body,
            grant=_tourapi_grant(),
            round_id=ROUND_ID,
            round_root=ROUND_ROOT,
            collection_log_records=(detached_log,),
        )


def test_source_kind_confusion_and_cross_round_mixing_fail_closed() -> None:
    request = _planned_request(
        operation="detailIntro2",
        mapped_fields=["provider_specific_operating_information"],
    )
    raw_body = _success_body("detailIntro2")
    report = _report(request, raw_body)
    report["round_id"] = HEX_B
    with pytest.raises(ValueError, match="selected round"):
        normalize_terminal_response(
            planned_request=request,
            report_record=report,
            raw_body=raw_body,
            grant=_tourapi_grant(),
            round_id=ROUND_ID,
            round_root=ROUND_ROOT,
        )

    report = _report(request, raw_body)
    report["operation"] = "detailImage2"
    with pytest.raises(ValueError, match="operation"):
        normalize_terminal_response(
            planned_request=request,
            report_record=report,
            raw_body=raw_body,
            grant=_tourapi_grant(),
            round_id=ROUND_ID,
            round_root=ROUND_ROOT,
        )


def test_round_loader_rejects_wrong_id_and_broken_ancestry() -> None:
    context = load_round_context(ROUND_ROOT, ROUND_ID)
    assert context.ancestry_depth == 1

    with pytest.raises(ValueError, match="basename|selected round|digest"):
        load_round_context(ROUND_ROOT, HEX_B)


def test_initial_depth_two_depth_three_and_broken_ancestry(
    tmp_path: Path,
) -> None:
    first_root, first_id = _build_test_initial_round(tmp_path)
    second_root, second_id = _build_test_remediation_round(
        first_root,
        first_id,
        nonce="4" * 64,
        ancestry_depth=1,
    )
    third_root, third_id = _build_test_remediation_round(
        second_root,
        second_id,
        nonce="5" * 64,
        ancestry_depth=2,
    )

    assert load_round_context(first_root, first_id).ancestry_depth == 1
    assert load_round_context(second_root, second_id).ancestry_depth == 2
    assert load_round_context(third_root, third_id).ancestry_depth == 3

    (second_root / "enrichment-round-manifest.json").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="manifest digest"):
        load_round_context(third_root, third_id)


def test_cli_requires_explicit_round_pair_for_build_publish_and_check() -> None:
    parser = _parser()
    for action in ("--build", "--publish", "--check"):
        argv = [action]
        if action == "--check":
            argv.append("evidence-sidecars.json")
        with pytest.raises(SystemExit):
            parser.parse_args(argv)
        with pytest.raises(SystemExit):
            parser.parse_args(["--round-root", str(ROUND_ROOT), *argv])
        with pytest.raises(SystemExit):
            parser.parse_args(["--round-id", ROUND_ID, *argv])


def test_atomic_publish_is_no_replace_and_preserves_existing_bytes(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "evidence-sidecars.json"
    first = b'{"complete":true}'
    publish_bytes_no_replace(destination, first)
    before = destination.stat()

    with pytest.raises(FileExistsError):
        publish_bytes_no_replace(destination, b'{"replacement":true}')

    after = destination.stat()
    assert destination.read_bytes() == first
    assert (after.st_dev, after.st_ino, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
    )
    assert after.st_mode & 0o777 == 0o600
    assert not tuple(tmp_path.glob(".evidence-sidecars.json.*.tmp"))


def test_atomic_publish_never_replaces_symlink_and_cleans_partial_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = tmp_path / "protected.json"
    protected.write_bytes(b"protected")
    destination = tmp_path / "evidence-sidecars.json"
    destination.symlink_to(protected)
    with pytest.raises(FileExistsError):
        publish_bytes_no_replace(destination, b"sidecar")
    assert destination.is_symlink()
    assert protected.read_bytes() == b"protected"

    destination.unlink()
    real_write = os.write
    calls = 0

    def partial_then_fail(descriptor: int, value: memoryview[bytes]) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, value[:3])
        raise OSError("simulated interrupted write")

    monkeypatch.setattr(os, "write", partial_then_fail)
    with pytest.raises(OSError, match="interrupted"):
        publish_bytes_no_replace(destination, b"complete-sidecar")
    assert not destination.exists()
    assert not tuple(tmp_path.glob(".evidence-sidecars.json.*.tmp"))
