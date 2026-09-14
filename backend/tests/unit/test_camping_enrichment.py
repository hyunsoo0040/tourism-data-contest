from datetime import UTC, datetime

import httpx
import pytest

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_camping import CampingClient
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.place_enrichment import confirmed_facility_exclusions
from itda.tourism.accessibility import CanonicalTourismPlace
from itda.tourism.camping import CampingEnrichmentService
from itda.tourism.temporal import TemporalPolicy

NOW = datetime(2026, 9, 9, tzinfo=UTC)


@pytest.mark.parametrize(
    "text",
    [
        "출입구 문턱 없음 여부 문의 필요",
        "주출입구 문턱 없음으로 안내되었으나 현재 계단만 이용 가능",
    ],
)
def test_uncertain_or_conflicting_step_free_claims_stay_unknown(text):
    service, _ = service_for([row(sbrsEtc=text)])
    assert service.get_context("place:camp").facts["step_free_entry"].value is None


def test_provider_numeric_zero_is_preserved_without_inventing_accessible_toilet_absence():
    raw = row()
    raw["toiletCo"] = 0
    service, _ = service_for([raw])
    facts = service.get_context("place:camp").facts
    assert facts["toilet_count"].value == 0
    assert facts["accessible_toilet"].value is None


def row(**updates: str) -> dict[str, str]:
    # Recorded official field values, copied into a clearly synthetic identity.
    return {
        "contentId": "101352",
        "facltNm": "합성 캠프",
        "doNm": "경상북도",
        "sigunguNm": "경주시",
        "addr1": "경상북도 경주시 시험로 1",
        "mapX": "129.2840582",
        "mapY": "35.7726922",
        "manageSttus": "운영",
        "operPdCl": "봄,여름,가을,겨울",
        "operDeCl": "평일+주말",
        "toiletCo": "0",
        "swrmCo": "0",
        "wtrplCo": "0",
        "modifiedtime": "2026-07-14",
        **updates,
    }


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def service_for(rows: list[dict[str, str]], *, page_size=1000):
    calls = []

    def transport(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path.rsplit("/", 1)[-1])
        assert "keyword" not in request.url.params
        page = int(request.url.params["pageNo"])
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

    client = CampingClient(
        service_key="fixture-camp-key",
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
        policy=RequestPolicy(max_attempts=1),
        clock=lambda: NOW,
    )
    place = CanonicalTourismPlace(
        place_id="place:camp",
        name_ko="합성 캠프",
        address="경상북도 경주시 시험로 1",
        latitude=35.7726922,
        longitude=129.2840582,
        provider_content_id="101352",
    )
    return CampingEnrichmentService(
        places=(place,),
        client=client,
        clock=lambda: NOW,
        policy=TemporalPolicy(enabled=True, page_size=page_size),
    ), calls


def test_explicit_camping_facility_absence_only_reaches_shared_suitability() -> None:
    service, calls = service_for([row(sbrsEtc="장애인 화장실 없음")])
    context = service.get_context("place:camp")
    assert context.match.state == "MATCHED"
    assert confirmed_facility_exclusions(
        (context,), (RequiredFacility.ACCESSIBLE_TOILET,)
    ) == frozenset({"place:camp"})
    assert service.excluded_place_ids(
        ("place:camp",), (RequiredFacility.ACCESSIBLE_TOILET,)
    ) == frozenset({"place:camp"})
    assert calls == ["basedList"]
    assert context.facts["accessible_toilet"].evidence[0].receipt.service == "GoCamping"
    assert "fixture-camp-key" not in context.model_dump_json()


def test_national_camping_pages_stay_small_and_find_a_later_city_record() -> None:
    # The first national page can contain no Gyeongju entry; keep paging rather
    # than substituting a name-keyword query or increasing the2MB byte ceiling.
    rows = [row(contentId=f"outside-{i}", sigunguNm="포항시") for i in range(200)]
    service, calls = service_for([*rows, row()])
    context, snapshots = service.get_context_with_sources("place:camp")
    assert context.match.state == "MATCHED"
    assert calls == ["basedList", "basedList"]
    assert snapshots[0].complete
    assert all(r.request_scope["numOfRows"] == "200" for r in snapshots[0].receipts)


def test_zero_and_blank_counts_preserve_distinct_states_without_absence() -> None:
    service, _ = service_for([row(swrmCo="", caravInnerFclty="침대,화장실")])
    facts = service.get_context("place:camp").facts
    assert facts["toilet_count"].value == 0 and facts["toilet_count"].state == "SUPPORTED_FACT"
    assert facts["shower_count"].value is None
    assert facts["toilet_available"].value is None
    assert facts["caravan_toilet"].value is True
    assert facts["accessible_toilet"].value is None
    assert facts["published_operating_days"].value == "평일+주말"
    assert (
        service.excluded_place_ids(("place:camp",), (RequiredFacility.ACCESSIBLE_TOILET,))
        == frozenset()
    )


def test_full_national_discovery_filters_city_and_preserves_duplicate_ambiguity() -> None:
    service, calls = service_for([row(contentId="outside", sigunguNm="포항시"), row()], page_size=1)
    assert service.get_context("place:camp").match.state == "MATCHED"
    assert calls == ["basedList", "basedList"]
    service, _ = service_for([row(), row(contentId="other-id")])
    context = service.get_context("place:camp")
    assert context.reason == "AMBIGUOUS_MATCH"
    assert all(fact.value is None for fact in context.facts.values())


@pytest.mark.parametrize(
    "updates,reason",
    [
        ({"mapX": "127.0"}, "PLACE_NOT_MATCHED"),
        ({"facltNm": "다른 캠프"}, "PLACE_NOT_MATCHED"),
        ({"modifiedtime": "2020-01-01"}, "STALE"),
    ],
)
def test_wrong_identity_or_stale_camp_cannot_qualify(updates, reason) -> None:
    service, _ = service_for([row(**updates)])
    context = service.get_context("place:camp")
    assert context.reason == reason
    assert all(fact.value is None for fact in context.facts.values())


def test_no_requirement_does_not_collect_or_infer_one() -> None:
    service, calls = service_for([row()])
    assert service.excluded_place_ids(("place:camp",), ()) == frozenset()
    assert calls == []


def test_conflicting_camp_fields_do_not_recover_a_convenient_positive() -> None:
    service, _ = service_for(
        [
            row(
                sbrsEtc="장애인 화장실 있음",
                posblFcltyEtc="장애인 화장실 없음",
                eqpmnLendCl="장애인 화장실 있음",
            )
        ]
    )
    assert service.get_context("place:camp").facts["accessible_toilet"].state == "UNKNOWN"


def test_explicit_step_free_entry_is_supported_without_rental_projection() -> None:
    service, _ = service_for([row(sbrsEtc="주출입구 단차 없음")])
    context = service.get_context("place:camp")
    assert context.facts["step_free_entry"].value is True
    assert context.facts["wheelchair_rental"].value is None
