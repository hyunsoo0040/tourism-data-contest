from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_accessibility import KorWithService2Client
from itda.contracts.source_assessment import SupportState
from itda.tourism.accessibility import AccessibilityService, CanonicalTourismPlace
from itda.tourism.settings import TourismSettings


def _place() -> CanonicalTourismPlace:
    return CanonicalTourismPlace(
        place_id="place:bulguksa",
        name_ko="불국사",
        address="경상북도 경주시 불국로 385",
        latitude=35.7897,
        longitude=129.3319,
        provider_content_id="126166",
    )


def _discovery(**changes: str) -> dict[str, str]:
    return {
        "contentid": "126166",
        "title": "불국사",
        "addr1": "경상북도 경주시 불국로 385",
        "mapy": "35.7897",
        "mapx": "129.3319",
        "lDongRegnCd": "47",
        "lDongSignguCd": "130",
        **changes,
    }


# Exact field text from the official 2026-09-09 live response. No external calls.
DETAIL = {
    "contentid": "126166",
    "parking": "장애인 주차구역이 있음(주출입구 근처)_무장애 편의시설",
    "publictransport": "",
    "route": (
        "주출입구에서 대웅전까지 경사로가 설치되어 있음"
        "장애인 탑승차량은 매표소 앞까지 차량접근 가능함"
    ),
    "wheelchair": "휠체어 무료 대여 가능함(8대)",
    "exit": "원활한 이동 가능함",
    "restroom": "장애인 화장실 있음(주차장과 불국사 내에 각 1곳씩(1.8mx1.8m))",
    "stroller": "유모차 대여 가능함",
}


@pytest.fixture(autouse=True)
def _no_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def _service(
    rows: list[dict[str, str]], detail: dict[str, str] | None = None, *, status: int = 200
) -> tuple[AccessibilityService, list[str], list[datetime]]:
    requests: list[str] = []
    now = [datetime(2026, 9, 9, tzinfo=UTC)]

    def transport(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path.rsplit("/", 1)[-1])
        items = rows if requests[-1] == "searchKeyword2" else [detail or DETAIL]
        return httpx.Response(
            status,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {"items": {"item": items}, "totalCount": len(items)},
                }
            },
        )

    client = KorWithService2Client(
        service_key="fixture-key-not-in-receipts",
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
        policy=RequestPolicy(max_attempts=1),
        clock=lambda: now[0],
    )
    return (
        AccessibilityService(
            client=client,
            places=(_place(),),
            clock=lambda: now[0],
            settings=TourismSettings(
                enabled=True, positive_ttl_seconds=60, negative_ttl_seconds=10
            ),
        ),
        requests,
        now,
    )


def test_verified_fixture_supports_only_narrow_facility_claims() -> None:
    service, requests, _ = _service([_discovery()])
    snapshot = service.fetch("place:bulguksa")
    assert snapshot.match.state == "MATCHED"
    assert requests == ["searchKeyword2", "detailWithTour2"]
    for key in ("accessible_parking", "accessible_toilet", "wheelchair_rental", "stroller_rental"):
        assert snapshot.facts[key].value is True
        assert snapshot.facts[key].state == SupportState.FACT
        assert snapshot.facts[key].evidence[0].receipt.operation == "detailWithTour2"
    assert snapshot.facts["step_free_entry"].state == SupportState.UNKNOWN
    assert snapshot.facts["accessible_route"].value is None
    assert snapshot.facts["accessible_route_segment"].value == DETAIL["route"]
    assert "fixture-key" not in snapshot.model_dump_json()


@pytest.mark.parametrize(
    "row",
    [_discovery(title="다른 장소"), _discovery(mapx="127.0"), _discovery(lDongSignguCd="110")],
)
def test_content_id_does_not_authorize_wrong_place(row: dict[str, str]) -> None:
    service, requests, _ = _service([row])
    result = service.fetch("place:bulguksa")
    assert result.match.state == "NOT_MATCHED"
    assert requests == ["searchKeyword2"]
    assert all(row.state == SupportState.UNKNOWN for row in result.facts.values())


def test_duplicate_exact_matches_fail_closed() -> None:
    service, requests, _ = _service([_discovery(), _discovery(contentid="different-id")])
    assert service.fetch("place:bulguksa").match.state == "AMBIGUOUS"
    assert requests == ["searchKeyword2"]


def test_blank_rental_and_swapped_labels_are_not_access_claims() -> None:
    service, _, _ = _service(
        [_discovery()],
        {
            "contentid": "126166",
            "wheelchair": "",
            "route": "대중교통 이용 가능 : 감은사지 정류장저상버스 없음.",
            "publictransport": "주출입구 경사로 설치",
            "restroom": "장애인 화장실 없음",
        },
    )
    facts = service.fetch("place:bulguksa").facts
    assert facts["wheelchair_rental"].value is None
    assert facts["accessible_toilet"].value is False
    assert facts["accessible_route"].value is None
    assert facts["accessible_route_segment"].value == "주출입구 경사로 설치"
    assert facts["step_free_entry"].value is None


def test_cache_ttl_and_negative_cache_use_injected_clock() -> None:
    service, requests, now = _service([_discovery()])
    first = service.fetch("place:bulguksa")
    assert service.fetch("place:bulguksa") == first
    assert len(requests) == 2
    now[0] += timedelta(seconds=61)
    assert service.fetch("place:bulguksa").snapshot_sha256 != first.snapshot_sha256
    assert len(requests) == 4
    service, requests, now = _service([])
    first = service.fetch("place:bulguksa")
    assert service.fetch("place:bulguksa") == first
    assert len(requests) == 1
    now[0] += timedelta(seconds=11)
    service.fetch("place:bulguksa")
    assert len(requests) == 2


def test_foreign_detail_id_and_unavailable_source_remain_unknown() -> None:
    service, _, _ = _service(
        [_discovery()], {"contentid": "foreign", "restroom": "장애인 화장실 있음"}
    )
    assert service.fetch("place:bulguksa").facts["accessible_toilet"].value is None
    service, requests, _ = _service([], status=403)
    result = service.fetch("place:bulguksa")
    assert result.receipts[0].status == "UNAVAILABLE"
    assert service.fetch("place:bulguksa") == result
    assert len(requests) == 1


def test_noncanonical_place_cannot_trigger_provider_call() -> None:
    service, requests, _ = _service([_discovery()])
    with pytest.raises(KeyError):
        service.fetch("place:untrusted")
    assert requests == []


@pytest.mark.parametrize(
    "text",
    [
        "휠체어 대여 문의 필요",
        "휠체어 대여 미확인",
        "휠체어 대여",
        "휠체어 대여 가능 여부 문의",
        "휠체어 대여 가능함, 대여 불가",
        "휠체어 대여 가능함, 휠체어 대여 불가",
    ],
)
def test_uncertain_or_conflicting_rental_is_unknown(text: str) -> None:
    service, _, _ = _service([_discovery()], {"contentid": "126166", "wheelchair": text})
    assert service.fetch("place:bulguksa").facts["wheelchair_rental"].value is None


def test_unrelated_absence_does_not_negate_accessible_parking() -> None:
    service, _, _ = _service(
        [_discovery()],
        {
            "contentid": "126166",
            "parking": "장애인 주차구역 있음, 일반주차 없음",
            "restroom": "장애인화장실 위치 : 경주감은사지동서삼층석탑주차장 아래.",
        },
    )
    facts = service.fetch("place:bulguksa").facts
    assert facts["accessible_parking"].value is True
    assert facts["accessible_toilet"].value is True


def test_explicit_impossible_rental_is_false() -> None:
    service, _, _ = _service(
        [_discovery()], {"contentid": "126166", "wheelchair": "휠체어 대여 불가능"}
    )
    assert service.fetch("place:bulguksa").facts["wheelchair_rental"].value is False


@pytest.mark.parametrize(
    "text",
    [
        "휠체어 접근 불가. 유모차 대여 가능함",
        "휠체어 이용 가능함. 유모차 대여 불가",
        "휠체어 이동 가능함, 유모차 대여 가능함",
    ],
)
def test_another_facility_rental_does_not_establish_wheelchair_rental(text: str) -> None:
    service, _, _ = _service([_discovery()], {"contentid": "126166", "wheelchair": text})
    fact = service.fetch("place:bulguksa").facts["wheelchair_rental"]
    assert fact.state == SupportState.UNKNOWN
    assert fact.value is None


@pytest.mark.parametrize(
    "text",
    [
        "출입구 문턱 없음 여부 문의 필요",
        "주출입구 문턱 없음으로 안내되었으나 현재 계단만 이용 가능",
        "주출입구 계단만 이용 가능, 별관 입구 문턱 없음 여부 미확인",
        "주출입구 문턱 없지 않음",
        "출입구 무단차 설치 예정",
        "주출입구 문턱 없음, 휠체어 이용 불가",
        "주출입구 문턱 없애는 공사 진행 중",
    ],
)
def test_uncertain_or_conflicting_step_free_entry_cannot_establish_access(text: str) -> None:
    service, _, _ = _service([_discovery()], {"contentid": "126166", "exit": text})
    fact = service.fetch("place:bulguksa").facts["step_free_entry"]
    assert fact.state == SupportState.UNKNOWN
    assert fact.value is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("주출입구 문턱 없음", True),
        ("출입구 무단차", True),
        ("주출입구 계단만 있음", False),
        ("주출입구 휠체어 진입 불가", False),
    ],
)
def test_unambiguous_step_free_entry_preserves_presence_and_absence(
    text: str, expected: bool
) -> None:
    service, _, _ = _service([_discovery()], {"contentid": "126166", "exit": text})
    fact = service.fetch("place:bulguksa").facts["step_free_entry"]
    assert fact.state == SupportState.FACT
    assert fact.value is expected
