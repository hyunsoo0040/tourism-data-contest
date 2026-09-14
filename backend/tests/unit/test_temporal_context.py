"""Official response shapes with explicit synthetic dates for contract testing."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from threading import Lock

import httpx
import pytest

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_concentration import ConcentrationClient
from itda.collectors.kto_demand import RegionalDemandClient
from itda.collectors.kto_visitors import RegionalVisitorsClient
from itda.tourism.accessibility import CanonicalTourismPlace
from itda.tourism.temporal import TemporalContextService, TemporalPolicy


def forecast_rows(name: str = "감포항", value: str = "24.16") -> list[dict[str, str]]:
    # Shape and first-row values from the 2026-09-09 research capture. Other
    # dates/values are explicit test counterfactuals, not new measured forecasts.
    return [
        {
            "baseYmd": (date(2026, 9, 8) + timedelta(days=offset)).strftime("%Y%m%d"),
            "areaCd": "47",
            "areaNm": "경상북도",
            "signguCd": "47130",
            "signguNm": "경주시",
            "tAtsNm": name,
            "cnctrRate": value if offset else "10.00",
        }
        for offset in range(30)
    ]


VISITORS = [
    {
        "signguCode": "47130",
        "signguNm": "경주시",
        "daywkDivCd": "3",
        "daywkDivNm": "수요일",
        "touDivCd": category,
        "touDivNm": label,
        "touNum": amount,
        "baseYmd": "20260701",
    }
    for category, label, amount in (
        ("1", "현지인(a)", "186735.5"),
        ("2", "외지인(b)", "83716.5"),
        ("3", "외국인(c)", "3570.8999999999996"),
    )
]


@pytest.fixture(autouse=True)
def no_network_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def make_service(*, forecasts=None, visitors=None, demand_status=403, page_size=1000, attempts=1):
    state = {
        "forecasts": forecasts if forecasts is not None else forecast_rows(),
        "visitors": visitors if visitors is not None else VISITORS,
        "calls": [],
        "fail": False,
    }
    now = [datetime(2026, 9, 9, tzinfo=UTC)]
    lock = Lock()

    def transport(request: httpx.Request) -> httpx.Response:
        operation = request.url.path.rsplit("/", 1)[-1]
        with lock:
            state["calls"].append(operation)
        if state["fail"]:
            raise httpx.ConnectError("injected outage", request=request)
        if operation.startswith("areaTar"):
            if demand_status == 403:
                return httpx.Response(
                    403,
                    json={
                        "OpenAPI_ServiceResponse": {
                            "cmmMsgHeader": {
                                "errMsg": "등록되지 않은 서비스키",
                                "returnAuthMsg": "SERVICE_KEY_IS_NOT_REGISTERED_ERROR",
                                "returnReasonCode": "30",
                            }
                        }
                    },
                )
            prefix = "tarSjrnDsIx" if operation == "areaTarSjrnDsList" else "tarExpDsIx"
            rows = [
                {
                    "areaCd": "47",
                    "signguCd": "47130",
                    "baseYm": "202607",
                    prefix + "Cd": "2101" if prefix == "tarSjrnDsIx" else "2201",
                    prefix + "Nm": "합성 테스트 지표",
                    prefix + "Val": "12.5",
                }
            ]
        else:
            rows = state["forecasts"] if operation == "tatsCnctrRatedList" else state["visitors"]
        page = int(request.url.params.get("pageNo", "1"))
        size = int(request.url.params["numOfRows"])
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {
                        "items": {"item": rows[(page - 1) * size : page * size]},
                        "totalCount": len(rows),
                    },
                }
            },
        )

    http = httpx.Client(transport=httpx.MockTransport(transport))
    arguments = dict(
        service_key="fixture-temporal-key-not-saved",
        http_client=http,
        clock=lambda: now[0],
        policy=RequestPolicy(max_attempts=attempts, initial_backoff_seconds=0, jitter_fraction=0),
    )
    places = (
        CanonicalTourismPlace(place_id="place:gampo", name_ko="감포항", address="경주시 감포읍"),
    )
    service = TemporalContextService(
        places=places,
        concentration=ConcentrationClient(**arguments),
        visitors=RegionalVisitorsClient(**arguments),
        demand=RegionalDemandClient(**arguments),
        clock=lambda: now[0],
        policy=TemporalPolicy(
            enabled=True, page_size=page_size, positive_ttl_seconds=60, negative_ttl_seconds=10
        ),
    )
    return service, state, now


def test_forecast_preserves_actual_window_and_intraplace_alternatives() -> None:
    service, state, _ = make_service()
    result = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    forecast = result.forecasts[0]
    assert forecast.state == "AVAILABLE"
    assert forecast.value == Decimal("24.16")
    assert forecast.unit == "WITHIN_PLACE_RELATIVE_INDEX_0_100"
    assert (forecast.window_start, forecast.window_end) == (date(2026, 9, 8), date(2026, 10, 7))
    assert forecast.provider_issue_date is None
    assert forecast.target_date == date(2026, 9, 10)
    assert forecast.alternatives == ()  # Lower 9/8 value is already in the past.
    assert state["calls"] == ["tatsCnctrRatedList"]
    assert "fixture-temporal-key" not in result.model_dump_json()
    assert "M3" not in result.model_dump_json()


def test_lower_future_date_alternative_never_crosses_place() -> None:
    rows = forecast_rows()
    rows[3]["cnctrRate"] = "9.5"
    service, _, _ = make_service(forecasts=rows + forecast_rows("다른장소", "0"))
    result = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    assert [(row.target_date, row.value) for row in result.forecasts[0].alternatives] == [
        (date(2026, 9, 11), Decimal("9.5"))
    ]


@pytest.mark.parametrize(
    "rows,reason",
    [
        (forecast_rows()[:-1], "PARTIAL_SERIES"),
        (forecast_rows() + [forecast_rows()[0]], "AMBIGUOUS_MATCH"),
        ([], "EMPTY"),
        (forecast_rows("다른 장소"), "PLACE_NOT_MATCHED"),
    ],
)
def test_incomplete_or_unmatched_forecast_is_unknown(rows, reason) -> None:
    service, _, _ = make_service(forecasts=rows)
    result = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10)).forecasts[
        0
    ]
    assert result.state == "UNKNOWN" and result.value is None and result.reason == reason


def test_out_of_window_and_changed_target_have_distinct_snapshot_identity() -> None:
    service, state, _ = make_service()
    first = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    second = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 10, 8))
    assert second.forecasts[0].reason == "OUT_OF_WINDOW"
    assert first.context_sha256 != second.context_sha256
    assert state["calls"] == ["tatsCnctrRatedList"]  # Regional batch shared across target dates.


def test_visitors_keep_decimal_categories_and_regional_scope() -> None:
    service, _, _ = make_service(visitors=VISITORS + [{**VISITORS[0], "signguCode": "11110"}])
    result = service.get_context(
        place_ids=(),
        trip_date=date(2026, 9, 10),
        visitor_start=date(2026, 7, 1),
        visitor_end=date(2026, 7, 1),
    )
    assert result.visitors.state == "AVAILABLE"
    assert len(result.visitors.points) == 3
    assert result.visitors.points[0].value == Decimal("186735.5")
    assert result.visitors.points[2].value == Decimal("3570.8999999999996")
    assert result.visitors.scope == "REGION"
    assert result.visitors.unit == "ESTIMATED_VISITOR_COUNT"


def test_partial_visitors_preserve_missing_null_and_do_not_sum_categories() -> None:
    service, _, _ = make_service(visitors=VISITORS[:2])
    visitors = service.get_context(
        place_ids=(),
        trip_date=date(2026, 9, 10),
        visitor_start=date(2026, 7, 1),
        visitor_end=date(2026, 7, 2),
    ).visitors
    assert visitors.state == "PARTIAL"
    assert len(visitors.points) == 6
    assert sum(point.value is None for point in visitors.points) == 4


def test_demand_authorization_is_unavailable_not_empty_and_units_never_invented() -> None:
    service, state, _ = make_service()
    context = service.get_context(place_ids=(), trip_date=date(2026, 9, 10), demand_month="202607")
    assert all(
        row.reason == "AUTHORIZATION_UNAVAILABLE" and row.provider_result_code == "30"
        for row in context.demand
    )
    assert len(state["calls"]) == 2
    service, _, _ = make_service(demand_status=200)
    context = service.get_context(place_ids=(), trip_date=date(2026, 9, 10), demand_month="202607")
    assert all(
        row.measures[0].raw_value == "12.5"
        and row.measures[0].value is None
        and row.measures[0].unit == "UNVERIFIED_PROVIDER_UNIT"
        for row in context.demand
    )


def test_singleflight_ttl_and_replay_never_refetch_stored_context() -> None:
    service, state, now = make_service()

    def get():
        return service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: get(), range(8)))
    assert len(state["calls"]) == 1
    now[0] += timedelta(seconds=61)
    state["fail"] = True
    refreshed = get()
    assert refreshed.forecasts[0].value is None
    assert refreshed.forecasts[0].reason == "SOURCE_UNAVAILABLE"
    calls = len(state["calls"])
    assert service.replay(results[0].model_dump(mode="json")) == results[0]
    assert len(state["calls"]) == calls
    get()
    assert len(state["calls"]) == calls


def test_future_observations_and_untrusted_place_rejected_before_http() -> None:
    service, state, _ = make_service()
    result = service.get_context(
        place_ids=(),
        trip_date=date(2026, 9, 10),
        visitor_start=date(2026, 10, 1),
        visitor_end=date(2026, 10, 1),
        demand_month="202610",
    )
    assert result.visitors.reason == "FUTURE_OBSERVATION"
    assert all(row.reason == "FUTURE_OBSERVATION" for row in result.demand)
    assert state["calls"] == []
    with pytest.raises(ValueError, match="canonical"):
        service.get_context(place_ids=("place:untrusted",), trip_date=date(2026, 9, 10))
    assert state["calls"] == []


def test_full_69_place_30_day_batch_is_bounded_paginated_and_preserved() -> None:
    rows = forecast_rows() + [
        row for index in range(68) for row in forecast_rows(f"합성장소{index}")
    ]
    service, state, _ = make_service(forecasts=rows)
    result, sources = service.get_context_with_sources(
        place_ids=("place:gampo",), trip_date=date(2026, 9, 10)
    )
    assert result.forecasts[0].state == "AVAILABLE"
    assert len(sources[0].rows) == 69 * 30
    assert len(sources[0].raw_responses) == 3
    assert state["calls"] == ["tatsCnctrRatedList"] * 3


def test_pagination_limit_keeps_partial_unknown_instead_of_selective_success() -> None:
    service, state, _ = make_service(page_size=10)
    service.policy = service.policy.model_copy(update={"max_pages": 2})
    result = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    assert result.forecasts[0].reason == "PARTIAL_SERIES"
    assert result.forecasts[0].value is None
    assert len(state["calls"]) == 2


@pytest.mark.parametrize("value", ["", "NaN", "-1", "101", "24%"])
def test_bad_forecast_values_never_default_to_zero(value: str) -> None:
    rows = forecast_rows()
    rows[1]["cnctrRate"] = value
    service, _, _ = make_service(forecasts=rows)
    forecast = service.get_context(
        place_ids=("place:gampo",), trip_date=date(2026, 9, 10)
    ).forecasts[0]
    assert forecast.value is None and forecast.reason == "INVALID_VALUE"


def test_business_day_uses_korean_calendar_and_old_window_is_stale() -> None:
    service, _, now = make_service()
    now[0] = datetime(2026, 9, 8, 16, tzinfo=UTC)  # Already September 9 in Korea.
    assert (
        service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 8))
        .forecasts[0]
        .reason
        == "OUT_OF_WINDOW"
    )
    now[0] = datetime(2026, 9, 15, tzinfo=UTC)
    assert (
        service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 16))
        .forecasts[0]
        .reason
        == "STALE"
    )


def test_source_and_context_tampering_fail_closed() -> None:
    from itda.domain.canonical import canonical_sha256
    from itda.tourism.temporal_cache import TemporalSourceSnapshot

    service, _, _ = make_service()
    result, sources = service.get_context_with_sources(
        place_ids=("place:gampo",), trip_date=date(2026, 9, 10)
    )
    changed = result.model_dump(mode="json")
    changed["forecasts"][0]["value"] = "99"
    with pytest.raises(ValueError, match="hash"):
        service.replay(changed)
    changed = sources[0].model_dump(mode="json")
    changed["rows"][0]["cnctrRate"] = "99"
    changed["snapshot_sha256"] = canonical_sha256(
        {k: v for k, v in changed.items() if k != "snapshot_sha256"}
    )
    with pytest.raises(ValueError, match="raw payload"):
        TemporalSourceSnapshot.model_validate(changed)
    changed["raw_responses"][0]["payload"]["response"]["body"]["items"]["item"][0]["cnctrRate"] = (
        "99"
    )
    changed["snapshot_sha256"] = canonical_sha256(
        {k: v for k, v in changed.items() if k != "snapshot_sha256"}
    )
    with pytest.raises(ValueError, match="raw bytes"):
        TemporalSourceSnapshot.model_validate(changed)


def test_transport_attempts_are_bounded_then_negatively_cached() -> None:
    service, state, now = make_service(attempts=2)
    state["fail"] = True
    first = service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    assert first.forecasts[0].value is None and len(state["calls"]) == 2
    service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    assert len(state["calls"]) == 2
    now[0] += timedelta(seconds=11)
    service.get_context(place_ids=("place:gampo",), trip_date=date(2026, 9, 10))
    assert len(state["calls"]) == 4


def test_duplicate_canonical_names_or_visitor_categories_never_merge_measurements() -> None:
    service, _, _ = make_service()
    service.places["place:duplicate"] = CanonicalTourismPlace(
        place_id="place:duplicate", name_ko="감포항"
    )
    forecast = service.get_context(
        place_ids=("place:gampo",), trip_date=date(2026, 9, 10)
    ).forecasts[0]
    assert forecast.reason == "AMBIGUOUS_MATCH"
    service, _, _ = make_service(visitors=VISITORS + [VISITORS[0]])
    context = service.get_context(
        place_ids=(),
        trip_date=date(2026, 9, 10),
        visitor_start=date(2026, 7, 1),
        visitor_end=date(2026, 7, 1),
    )
    assert context.visitors.state == "PARTIAL"
    assert context.visitors.points[0].value is None
    assert context.visitors.points[0].reason == "AMBIGUOUS_MATCH"
