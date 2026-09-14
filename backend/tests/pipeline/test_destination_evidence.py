from __future__ import annotations

from datetime import UTC, datetime

import pytest

from itda.contracts.source_assessment import SourceReceipt, SourceService
from itda.pipeline.destination_evidence import (
    aliases_for,
    evidence_from_fields,
    match_gallery,
    match_odii,
)
from itda.tourism.accessibility import CanonicalTourismPlace


def place():
    return CanonicalTourismPlace(
        place_id="public:gyeongju:" + "a" * 64,
        name_ko="경주 나정",
        latitude=35.8,
        longitude=129.2,
        provider_content_id="123",
    )


def test_name_and_region_or_coordinates_do_not_match_unrelated_place():
    p = place()
    assert (
        match_odii(p, {"title": "경주 나정", "tid": "1", "mapY": "37.8", "mapX": "129.2"}).state
        == "NOT_MATCHED"
    )
    assert (
        match_gallery(
            p, {"galTitle": "나정", "galContentId": "1", "galPhotographyLocation": "강릉시"}
        ).state
        == "NOT_MATCHED"
    )
    assert (
        match_gallery(
            p,
            {"galTitle": "나정", "galContentId": "1", "galPhotographyLocation": "경상북도 경주시"},
        ).state
        == "MATCHED"
    )
    assert "나정" in aliases_for(p.name_ko)


def test_national_alias_uses_own_official_region_and_preserves_location_checks():
    assert "화성" in aliases_for("수원 화성", "경기도 수원시 팔달구")
    assert "숲" not in aliases_for("서울숲", "서울특별시 성동구")
    assert "흥무로" not in aliases_for("흥무로벚꽃길", "경상북도 경주시")
    assert "나정" not in aliases_for("경주 나정", "강원특별자치도 강릉시")
    p = CanonicalTourismPlace(
        place_id="public:korea:" + "a" * 64,
        name_ko="수원 화성",
        region_code="41115",
        region_name="경기도 수원시 팔달구",
        latitude=37.28,
        longitude=127.01,
    )
    row = {"title": "화성", "tid": "1", "mapY": "37.28", "mapX": "127.01"}
    assert match_odii(p, row).state == "MATCHED"
    assert match_odii(p, row | {"mapY": "38.0"}).state == "NOT_MATCHED"


def test_source_text_preserves_book_titles_and_field_lineage():
    p = place()
    receipt = SourceReceipt(
        service=SourceService.TOUR,
        operation="detailCommon2",
        dataset_id="15101578",
        request_scope={"contentId": "123"},
        retrieved_at=datetime.now(UTC),
        status="AVAILABLE",
        http_status=200,
        response_sha256="b" * 64,
        reason="OK",
    )
    match = match_odii(
        p, {"title": "경주 나정", "tid": "1", "mapY": "35.8", "mapX": "129.2"}
    ).model_copy(update={"service": SourceService.TOUR, "provider_entity_id": "123"})
    rows, lineage = evidence_from_fields(
        receipt, match, {"overview": "<p><삼국사기>에 기록된 신라 유적.</p>"}, ("overview",)
    )
    assert rows[0].excerpt == "<삼국사기>에 기록된 신라 유적."
    assert lineage[0]["original_chars"] > lineage[0]["used_chars"]
    assert rows[0].quote in rows[0].excerpt


def test_evidence_empty_fields_are_not_invented():
    p = place()
    receipt = SourceReceipt(
        service=SourceService.ODII,
        operation="storyBasedList",
        dataset_id="15101971",
        request_scope={},
        retrieved_at=datetime.now(UTC),
        status="EMPTY",
        http_status=200,
        response_sha256="c" * 64,
        reason="EMPTY",
    )
    match = match_odii(p, {})
    assert evidence_from_fields(receipt, match, {}, ("script",)) == ((), ())


def test_cache_preserves_source_identity_and_rejects_cross_request_rebinding(tmp_path):
    import base64
    import hashlib
    import json

    from itda.collectors.base import CollectedResponse
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.destination_evidence import OfficialSourceCache

    class Client:
        common_parameters = {"_type": "json"}
        calls = 0

        def request(self, operation, params, explicit_opt_in):
            self.calls += 1
            payload = {
                "response": {
                    "body": {"items": {"item": [{"contentid": "123", "overview": "관광지 소개"}]}}
                }
            }
            raw = json.dumps(payload).encode()
            return CollectedResponse(
                provider="TOUR_API",
                endpoint="https://apis.data.go.kr/B551011/KorService2/" + operation,
                request_scope=self.common_parameters | params,
                retrieved_at=datetime.now(UTC),
                http_status=200,
                raw_response_sha256=hashlib.sha256(raw).hexdigest(),
                raw_body_base64=base64.b64encode(raw).decode(),
                modifiedtime=None,
                rights=(),
                payload=payload,
            )

    client = Client()
    cache = OfficialSourceCache(tmp_path, clients={SourceService.TOUR: client}, live=True)
    first, raw1 = cache.fetch(SourceService.TOUR, "detailCommon2", {"contentId": "123"})
    second, raw2 = cache.fetch(SourceService.TOUR, "detailCommon2", {"contentId": "123"})
    assert first == second and client.calls == 1
    assert raw1["cache_reused"] is False and raw2["cache_reused"] is True
    path = next(tmp_path.glob("*.json"))
    stored = json.loads(path.read_text())
    stored["scope"]["contentId"] = "999"
    stored["cache_sha256"] = canonical_sha256(
        {k: v for k, v in stored.items() if k != "cache_sha256"}
    )
    path.write_text(json.dumps(stored))
    with pytest.raises(ValueError):
        cache.fetch(SourceService.TOUR, "detailCommon2", {"contentId": "123"})
