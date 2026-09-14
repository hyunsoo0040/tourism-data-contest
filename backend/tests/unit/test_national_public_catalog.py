"""Provider-free verification of nationwide inventory and source sampling."""

from __future__ import annotations

import hashlib
import math
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from itda.contracts.mvp_public_catalog import OfficialDatasetPermissionMetadata
from itda.contracts.source_assessment import ClaimKind, SourceEvidence, SourceReceipt, SourceService
from itda.pipeline import national_public_catalog as national


def _listing(
    cid: int, province: str = "11", district: str = "110", category: str = "12"
) -> dict[str, Any]:
    return {
        "contentid": str(cid),
        "contenttypeid": category,
        "title": f"공식 관광지 {cid}",
        "addr1": "서울특별시 종로구 공식주소",
        "mapy": str(37.0 + cid / 1_000_000),
        "mapx": str(127.0 + cid / 1_000_000),
        "lDongRegnCd": province,
        "lDongSignguCd": district,
    }


def test_administrative_lookup_receipt_cannot_be_score_evidence() -> None:
    receipt = SourceReceipt(
        service=SourceService.TOUR,
        operation="ldongCode2",
        dataset_id="15101578",
        request_scope={"lDongListYn": "N"},
        retrieved_at=datetime.now(UTC),
        status="AVAILABLE",
        http_status=200,
        response_sha256="a" * 64,
        reason="official administrative lookup",
    )
    evidence = SourceEvidence(
        evidence_id="administrative-fixture",
        receipt=receipt,
        scope="REGION",
        modality="STRUCTURED",
        source_field="name",
        excerpt="서울특별시",
        quote="서울특별시",
    )
    assert all(not evidence.authorizes(claim) for claim in ClaimKind)


@pytest.mark.parametrize(
    ("length", "intro", "accepted"),
    [
        (399, {"usetime": "09:00~18:00"}, False),
        (400, {"usetime": "09:00~18:00"}, True),
        (649, {}, False),
        (650, {}, True),
        (500, {"parking": "없음", "heritage1": "0"}, True),
        (500, {"parking": None, "usetime": "미제공"}, False),
    ],
)
def test_sufficiency_is_explicit_source_coverage(
    length: int, intro: dict[str, str | None], accepted: bool
) -> None:
    result = national.source_sufficiency({"overview": "가" * length, "rating": 100}, intro)
    assert result["accepted"] is accepted
    assert result["overview_characters"] == length
    assert result["model_score_used"] is False


def test_coordinates_identity_region_and_type_are_required() -> None:
    row = _listing(1)
    assert national.identity_is_usable(row, "11")
    assert not national.identity_is_usable(row, "26")
    for replacement in (
        {"mapy": "nan"},
        {"mapx": "1299"},
        {"contenttypeid": "38"},
        {"lDongSignguCd": ""},
        {"title": ""},
    ):
        assert not national.identity_is_usable(row | replacement, "11")


def test_official_administrative_shapes_include_2026_sejong_and_merged_region() -> None:
    assert national.official_region_code("12", "870") == "12870"
    assert national.official_region_code("36110", "36110") == "36110"
    assert national.official_region_code("36110", "110") is None
    assert national.identity_is_usable(_listing(1, province="36110", district="36110"), "36110")


def test_candidates_balance_district_and_type_without_provider_order() -> None:
    rows = [
        _listing(i, district="110" if i < 10 else "140", category="12" if i % 2 else "14")
        for i in range(1, 20)
    ]
    first = national.balanced_candidates(rows, "11")
    assert first == national.balanced_candidates(list(reversed(rows)), "11")
    assert len({(r["lDongSignguCd"], r["contenttypeid"]) for r in first[:4]}) == 4


def test_paging_rejects_incomplete_and_changed_totals(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = iter([{"rows": [{"id": 1}], "total_count": 2}, {"rows": [], "total_count": 2}])
    monkeypatch.setattr(national, "_page", lambda *_args: next(pages))
    with pytest.raises(ValueError, match="before complete coverage"):
        national._all_pages(None, "areaBasedList2", {}, page_size=1)  # type: ignore[arg-type]
    pages = iter([{"rows": [{"id": 1}], "total_count": 2}, {"rows": [{"id": 2}], "total_count": 3}])
    with pytest.raises(ValueError, match="total changed"):
        national._all_pages(None, "areaBasedList2", {}, page_size=1)  # type: ignore[arg-type]


def test_frozen_artifact_rejects_mutation(tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    artifact = national._stamped({"provider_count": 17})
    national._write_once(path, artifact)
    assert national.read_artifact(path) == artifact
    path.write_text(path.read_text().replace("17", "16"))
    with pytest.raises(ValueError, match="integrity"):
        national.read_artifact(path)


def test_transient_failure_is_bounded_and_preserved_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real_inspect = national._inspect_candidate

    def unavailable(*_args: Any) -> dict[str, Any]:
        calls.append(1)
        raise national.NationalSourceUnavailable(
            "detailCommon2", "bounded HTTP attempts exhausted", 503
        )

    monkeypatch.setattr(national, "_inspect_candidate", unavailable)
    row, province = _listing(1), {"code": "11", "name": "서울특별시"}
    result = national._inspect_with_retries(None, tmp_path, row, province)  # type: ignore[arg-type]
    assert len(calls) == 3
    assert result["sufficiency"]["reason"] == "API_UNAVAILABLE"
    assert result["common"] is None
    assert len(national.read_artifact(tmp_path / "collection-failures/1.json")["attempts"]) == 3
    monkeypatch.setattr(national, "_inspect_candidate", real_inspect)
    assert national._inspect_with_retries(None, tmp_path, row, province) == result  # type: ignore[arg-type]


def test_http_attempt_accounting_never_records_credentials(tmp_path: Path) -> None:
    path = tmp_path / "http-attempts.jsonl"
    transport = national.NationalAttemptTransport(
        path,
        httpx.MockTransport(lambda _request: httpx.Response(503)),
    )
    with httpx.Client(transport=transport) as client:
        response = client.get(
            "https://apis.data.go.kr/B551011/KorService2/detailCommon2",
            params={"serviceKey": "SYNTHETIC_ONLY_SECRET", "contentId": "123"},
        )
    assert response.status_code == 503
    text = path.read_text()
    assert "SYNTHETIC_ONLY_SECRET" not in text and "serviceKey" not in text
    assert '"contentId": "123"' in text
    assert '"transport_retries": 0' in text


def test_429_closes_provider_circuit_and_obeys_retry_after(tmp_path: Path) -> None:
    calls: list[int] = []

    def limited(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "120"}, content=b"rate limited")

    transport = national.NationalAttemptTransport(
        tmp_path / "attempts.jsonl", httpx.MockTransport(limited)
    )
    with httpx.Client(transport=transport) as client, ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(client.get, "https://apis.data.go.kr/detailCommon2") for _ in range(6)
        ]
        for future in futures:
            with pytest.raises(national.NationalProviderPaused):
                future.result()
    assert len(calls) == 1
    state = national.read_artifact(tmp_path / "provider-state.json")
    assert state["status"] == "PAUSED" and state["retry_after_seconds"] == 120
    assert len((tmp_path / "attempts.jsonl").read_text().splitlines()) == 1
    # Even an explicit new-process resume cannot bypass the provider's Retry-After.
    resumed = national.NationalAttemptTransport(
        tmp_path / "attempts.jsonl", httpx.MockTransport(limited), resume_provider=True
    )
    with httpx.Client(transport=resumed) as client, pytest.raises(national.NationalProviderPaused):
        client.get("https://apis.data.go.kr/detailIntro2")
    assert len(calls) == 1


def test_daily_quota_requires_manual_resume_and_cannot_become_place_rejection(
    tmp_path: Path,
) -> None:
    body = (
        b"<OpenAPI_ServiceResponse><cmmMsgHeader><returnReasonCode>22</returnReasonCode>"
        b"<returnAuthMsg>LIMITED_NUMBER_OF_SERVICE_REQUESTS_EXCEEDS_ERROR</returnAuthMsg>"
        b"</cmmMsgHeader></OpenAPI_ServiceResponse>"
    )
    transport = national.NationalAttemptTransport(
        tmp_path / "attempts.jsonl",
        httpx.MockTransport(
            lambda _request: httpx.Response(
                429,
                headers={"x-ratelimit-limit": "1000", "x-ratelimit-remaining": "0"},
                content=body,
            )
        ),
    )
    with (
        httpx.Client(transport=transport) as client,
        pytest.raises(national.NationalProviderPaused),
    ):
        client.get("https://apis.data.go.kr/detailCommon2")
    state = national.read_artifact(tmp_path / "provider-state.json")
    assert state["provider_result_code"] == "22"
    assert state["manual_resume_required"] is True and state["resume_not_before"] is None
    assert state["daily_limit"] == 1000 and state["remaining"] == 0
    calls: list[int] = []

    def available(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200)

    with (
        httpx.Client(
            transport=national.NationalAttemptTransport(
                tmp_path / "attempts.jsonl", httpx.MockTransport(available)
            )
        ) as client,
        pytest.raises(national.NationalProviderPaused),
    ):
        client.get("https://apis.data.go.kr/detailCommon2")
    assert not calls
    with httpx.Client(
        transport=national.NationalAttemptTransport(
            tmp_path / "attempts.jsonl", httpx.MockTransport(available), resume_provider=True
        )
    ) as client:
        assert client.get("https://apis.data.go.kr/detailCommon2").status_code == 200
    assert len(calls) == 1


def test_request_pacing_is_shared_across_transports(tmp_path: Path) -> None:
    starts: list[float] = []

    def request(_request: httpx.Request) -> httpx.Response:
        starts.append(time.monotonic())
        return httpx.Response(200)

    clients = [
        httpx.Client(
            transport=national.NationalAttemptTransport(
                tmp_path / f"attempts-{i}.jsonl", httpx.MockTransport(request)
            )
        )
        for i in range(2)
    ]
    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(clients[i % 2].get, "https://apis.data.go.kr/detailCommon2")
                for i in range(5)
            ]
            assert all(f.result().status_code == 200 for f in futures)
    finally:
        for client in clients:
            client.close()
    assert len(starts) == 5
    ordered = sorted(starts)
    assert all(right - left >= 0.32 for left, right in zip(ordered, ordered[1:], strict=False))


def test_rate_limit_repair_preserves_normal_decisions_and_quarantines_only_429(
    tmp_path: Path,
) -> None:
    normal = national._stamped(
        {"content_id": "1", "sufficiency": {"accepted": True, "reason": "SUFFICIENT_OFFICIAL_TEXT"}}
    )
    failed = national._stamped(
        {"content_id": "2", "sufficiency": {"accepted": False, "reason": "API_UNAVAILABLE"}}
    )
    failure = national._stamped({"content_id": "2", "attempts": [{"http_status": 429}] * 3})
    national.atomic_json(tmp_path / "decisions/1.json", normal)
    national.atomic_json(tmp_path / "decisions/2.json", failed)
    national.atomic_json(tmp_path / "collection-failures/2.json", failure)
    result = national.quarantine_rate_limited_decisions(tmp_path)
    assert result["retained_normal_decisions"] == result["retained_selected_count"] == 1
    assert result["quarantined_decision_count"] == 1
    assert national.read_artifact(tmp_path / "decisions/1.json") == normal
    assert not (tmp_path / "decisions/2.json").exists()
    assert national.read_artifact(tmp_path / "old-partial-http-errors/decisions/2.json") == failed
    assert national.quarantine_rate_limited_decisions(tmp_path) == result


def test_source_client_factory_owns_resources_and_separates_service_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[Path] = []

    def transport(path: Path, **_options: Any) -> httpx.MockTransport:
        paths.append(path)
        return httpx.MockTransport(lambda _request: httpx.Response(200))

    monkeypatch.setattr(national, "NationalAttemptTransport", transport)
    with national.national_source_clients("synthetic-key", None, tmp_path) as clients:
        assert set(clients) == {SourceService.TOUR, SourceService.ODII, SourceService.GALLERY}
        http_clients = [client._http_client for client in clients.values()]
        assert not any(client.is_closed for client in http_clients)
    assert all(client.is_closed for client in http_clients)
    assert set(paths) == {
        tmp_path / "http-attempts.jsonl",
        tmp_path / "provider-controls/odii/http-attempts.jsonl",
        tmp_path / "provider-controls/gallery/http-attempts.jsonl",
    }


def test_source_batch_stops_other_providers_after_one_quota(tmp_path: Path) -> None:
    control = national.NationalBatchControl()
    calls: list[str] = []

    def limited(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(429)

    def available(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200)

    with (
        httpx.Client(
            transport=national.NationalAttemptTransport(
                tmp_path / "odii/http-attempts.jsonl",
                httpx.MockTransport(limited),
                batch_control=control,
            )
        ) as odii,
        httpx.Client(
            transport=national.NationalAttemptTransport(
                tmp_path / "tour/http-attempts.jsonl",
                httpx.MockTransport(available),
                batch_control=control,
            )
        ) as tour,
    ):
        with pytest.raises(national.NationalProviderPaused):
            odii.get("https://apis.data.go.kr/themeSearchList")
        with pytest.raises(national.NationalProviderPaused):
            tour.get("https://apis.data.go.kr/detailCommon2")
    assert calls == ["/themeSearchList"]


@pytest.mark.parametrize("status", [401, 403])
def test_source_transport_stops_repeated_authentication_failures(
    tmp_path: Path, status: int
) -> None:
    calls: list[int] = []

    def denied(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(status)

    with httpx.Client(
        transport=national.NationalAttemptTransport(
            tmp_path / "http-attempts.jsonl", httpx.MockTransport(denied)
        )
    ) as client:
        for _ in range(2):
            with pytest.raises(national.NationalProviderPaused):
                client.get("https://apis.data.go.kr/themeSearchList")
    assert calls == [1]
    state = national.read_artifact(tmp_path / "provider-state.json")
    assert state["reason"] == "PROVIDER_AUTHORIZATION_REJECTED"
    assert state["http_status"] == status and state["manual_resume_required"] is True


def test_source_batch_refuses_all_calls_when_another_service_is_already_paused(
    tmp_path: Path,
) -> None:
    national.atomic_json(
        tmp_path / "provider-controls/odii/provider-state.json",
        national._stamped(
            {
                "status": "PAUSED",
                "manual_resume_required": True,
            }
        ),
    )
    with (
        pytest.raises(national.NationalProviderPaused),
        national.national_source_clients("synthetic-key", None, tmp_path),
    ):
        pytest.fail("a paused source provider must prevent batch startup")


@pytest.mark.parametrize(
    ("status", "reason"),
    [(403, "HTTP status requires operator review"), (200, "the service key is expired")],
)
def test_authentication_failure_stops_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    reason: str,
) -> None:
    calls: list[int] = []

    def denied(*_args: Any) -> dict[str, Any]:
        calls.append(1)
        raise national.NationalSourceUnavailable("detailCommon2", reason, status)

    monkeypatch.setattr(national, "_inspect_candidate", denied)
    with pytest.raises(national.NationalSourceUnavailable):
        national._inspect_with_retries(None, tmp_path, _listing(1), {"code": "11"})  # type: ignore[arg-type]
    assert len(calls) == 1
    assert not (tmp_path / "decisions/1.json").exists()


@pytest.mark.parametrize(
    "exclude_prior,target_count,evaluation_sample",
    [(False, 800, False), (True, 800, False), (True, 60, True)],
)
def test_selection_balances_and_reuses_national_or_evaluation_sample(
    exclude_prior: bool,
    target_count: int,
    evaluation_sample: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provinces = [str(n) for n in range(11, 28)]
    regions = [
        {
            "province": {"code": p, "name": "테스트 시도 " + p},
            "listing": {
                "rows": [
                    _listing(
                        int(p) * 100 + i,
                        province=p,
                        category="39" if 50 <= i < 65 else "32" if i >= 65 else "12",
                    )
                    for i in range(90)
                ]
            },
        }
        for p in provinces
    ]
    discovery = national._stamped({"complete": True, "regions": regions})
    calls = []

    def inspect(
        _cache: Any, _output: Path, row: dict[str, Any], province: dict[str, str]
    ) -> dict[str, Any]:
        calls.append(row["contentid"])
        return {
            "content_id": row["contentid"],
            "common": {"rows": [row]},
            "province": province,
            "sufficiency": {"accepted": True, "reason": "SUFFICIENT_OFFICIAL_TEXT"},
        }

    monkeypatch.setattr(national, "_inspect_candidate", inspect)
    exclusions = None
    if exclude_prior:
        exclusions = national._stamped(
            {
                "content_ids": [str(int(p) * 100) for p in provinces],
                "place_identities": [
                    list(national._place_identity(_listing(int(p) * 100 + 1, province=p)))
                    for p in provinces
                ],
            }
        )
    result = national.select_nationwide(
        None,
        tmp_path,
        discovery,
        target_count=target_count,
        evaluation_sample=evaluation_sample,
        exclusions=exclusions,  # type: ignore[arg-type]
    )
    if exclude_prior:
        assert not set(calls) & {str(int(p) * 100 + i) for p in provinces for i in (0, 1)}
        assert result["exclusion_sha256"] == exclusions["artifact_sha256"]
        with pytest.raises(ValueError, match="selection identity changed|national sample target"):
            national.select_nationwide(None, tmp_path, discovery, target_count=target_count)  # type: ignore[arg-type]
    assert result["selected_count"] == len(calls) == target_count
    assert len({r["content_id"] for r in result["selected"]}) == target_count
    assert all(
        (1 if evaluation_sample else 40) <= row["selected"] <= math.ceil(target_count * 0.125)
        for row in result["distribution"]
    )
    assert result["model_calls"] == 0 and not result["popularity_used"]
    assert result["purpose_selected"] == {"SIGHTSEEING": target_count}
    assert result["purpose_targets"] == {"SIGHTSEEING": target_count}
    assert result["excluded_purposes"] == ["FOOD", "LODGING"]
    assert all(r["common"]["rows"][0]["contenttypeid"] == "12" for r in result["selected"])
    assert (
        national.select_nationwide(
            None,
            tmp_path,
            discovery,
            target_count=target_count,
            evaluation_sample=evaluation_sample,
            exclusions=exclusions,  # type: ignore[arg-type]
        )
        == result
    )
    assert len(calls) == target_count


def test_materialization_preserves_national_identity_and_exact_source_hash() -> None:
    raw = "테스트 관광정보 테스트 기관 테스트 이용허락 테스트 허용 테스트 제한".encode()
    allowed = {"decision": "ALLOWED", "evidence_quote": "테스트 허용"}
    permission_fields = {
        "schema_version": "official-dataset-permission-metadata.v2",
        "official_dataset_id": "15101578",
        "official_url": "https://www.data.go.kr/data/15101578/openapi.do",
        "retrieved_at": "2026-09-09T00:00:00Z",
        "raw_response_sha256": hashlib.sha256(raw).hexdigest(),
        "dataset_title_ko": "테스트 관광정보",
        "provider_name_ko": "테스트 기관",
        "license_type": "테스트 이용허락",
        "attribution_required": True,
        "attribution_text_ko": "테스트 기관",
        "no_attribution_evidence_ko": None,
        "public_display": allowed,
        "transformation_and_derived_scores": allowed,
        "third_party_model_processing_and_retention": allowed,
        "excerpt_and_release_redistribution": allowed,
        "commercial_scope": allowed,
        "restrictions_ko": "테스트 제한",
    }
    permission = OfficialDatasetPermissionMetadata.model_validate(
        {**permission_fields, "metadata_sha256": national.canonical_sha256(permission_fields)}
    )
    row = _listing(123, province="36110", district="36110")
    discovery = national._stamped(
        {"regions": [{"province": {"code": "36110"}, "district_codes": {"rows": []}}]}
    )
    selection = {
        "discovery_sha256": discovery["artifact_sha256"],
        "selected": [
            {
                "content_id": "123",
                "province": {"name": "세종특별자치시"},
                "common": {
                    "rows": [row],
                    "receipt": {"response_sha256": "c" * 64, "reference_date": "2026-09-09"},
                },
                "sufficiency": {"overview": "공식 설명 " * 100},
            }
        ],
    }
    catalog, inventory, relations = national.materialize_national_catalog(
        selection,
        discovery,
        permission=permission,
        permission_snapshot=raw,
    )
    assert catalog.region == "전국"
    assert catalog.blind_overlap_count is None
    assert catalog.places[0].region_code == "36110"
    assert catalog.places[0].administrative_area == "세종특별자치시"
    assert catalog.places[0].place_id.startswith("public:korea:")
    assert inventory.evidence[0].source_response_sha256 == "c" * 64
    assert catalog.places[0].evidence_ids == (inventory.evidence[0].evidence_id,)
    assert relations.catalog_sha256 == catalog.catalog_sha256
    for excluded in ("32", "39"):
        selection["selected"][0]["common"]["rows"][0] = row | {"contenttypeid": excluded}
        with pytest.raises(ValueError, match="only sightseeing"):
            national.materialize_national_catalog(
                selection, discovery, permission=permission, permission_snapshot=raw
            )


def test_prior_collection_excludes_insufficient_as_well_as_accepted(tmp_path: Path) -> None:
    for cid in (1, 2):
        national._write_once(
            tmp_path / "decisions" / f"{cid}.json",
            national._stamped(
                {
                    "content_id": str(cid),
                    "province": {"code": "11"},
                    "common": {"rows": [_listing(cid)]},
                    "sufficiency": {"accepted": cid == 1},
                }
            ),
        )
    result = national.prior_collection_exclusions([tmp_path])
    assert result["content_ids"] == ["1", "2"]
    assert len(result["place_identities"]) == 2
    assert result == national.prior_collection_exclusions([tmp_path])
    with pytest.raises(ValueError, match="no source decisions"):
        national.prior_collection_exclusions([tmp_path / "missing"])
