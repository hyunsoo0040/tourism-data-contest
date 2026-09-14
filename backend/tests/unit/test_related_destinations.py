from datetime import UTC, datetime

import httpx
import pytest

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_related import RelatedDestinationsClient
from itda.contracts.place_enrichment import RelatedCanonicalPlace
from itda.tourism.related import RelatedDestinationsService
from itda.tourism.temporal import TemporalPolicy

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def row(index: int, **updates: str) -> dict[str, str]:
    # Documented official successful shape; synthetic because actual service is403.
    return {
        "baseYm": "202504",
        "areaCd": "47",
        "signguCd": "47130",
        "tAtsCd": "NAV-source",
        "tAtsNm": "합성 장소 0",
        "rlteTatsCd": f"NAV-{index}",
        "rlteTatsNm": f"합성 장소 {index}",
        "rlteRank": str(index),
        "rlteRegnCd": "47",
        "rlteSignguCd": "47130",
        **updates,
    }


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def service_for(rows=None, status=200):
    calls = []

    def transport(request):
        calls.append(request.url.path)
        if status != 200:
            return httpx.Response(
                status,
                json={
                    "OpenAPI_ServiceResponse": {
                        "cmmMsgHeader": {
                            "returnReasonCode": "30",
                            "errMsg": "SERVICE_KEY_IS_NOT_REGISTERED_ERROR",
                            "returnAuthMsg": "등록되지 않은 서비스키",
                        }
                    }
                },
            )
        items = rows if rows is not None else [row(i) for i in range(1, 7)]
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {"items": {"item": items}, "totalCount": len(items)},
                }
            },
        )

    client = RelatedDestinationsClient(
        service_key="related-fixture-key",
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
        policy=RequestPolicy(max_attempts=1),
        clock=lambda: NOW,
    )
    places = tuple(
        RelatedCanonicalPlace(
            place_id=f"place:{i}",
            name_ko=f"합성 장소 {i}",
            category="음식점" if i == 1 else "관광지",
            duplicate_group_id=f"group:{2 if i == 3 else i}",
        )
        for i in range(7)
    )
    return RelatedDestinationsService(
        places=places, client=client, clock=lambda: NOW, policy=TemporalPolicy(enabled=True)
    ), calls


def test_navigation_candidates_obey_purpose_conditions_and_duplicate_pair_constraints() -> None:
    service, calls = service_for()
    result = service.get_context(
        place_id="place:0",
        base_month="202504",
        eligible_place_ids=tuple(f"place:{i}" for i in range(7)),
        condition_excluded_place_ids=("place:4",),
        cannot_coappear_pairs=(("place:0", "place:5"),),
    )
    assert [row.place_id for row in result.suggestions] == ["place:2", "place:6"]
    assert all(
        row.affinity_effect == "NONE" and row.relation_kind == "NAVIGATION_ASSOCIATION"
        for row in result.suggestions
    )
    assert result.filtered_count == 4
    assert len(calls) == 1
    assert "related-fixture-key" not in result.model_dump_json()


def test_changed_eligibility_has_new_context_identity_without_refetching_raw_month() -> None:
    service, calls = service_for()
    first = service.get_context(
        place_id="place:0",
        base_month="202504",
        eligible_place_ids=("place:1", "place:2"),
        purpose="MIXED",
    )
    second = service.get_context(
        place_id="place:0", base_month="202504", eligible_place_ids=("place:2",), purpose="MIXED"
    )
    assert first.context_sha256 != second.context_sha256 and len(calls) == 1
    assert [row.place_id for row in second.suggestions] == ["place:2"]


def test_actual_authorization_error_stays_unavailable_and_negatively_cached() -> None:
    service, calls = service_for(status=403)
    result = service.get_context(
        place_id="place:0", base_month="202504", eligible_place_ids=("place:2",)
    )
    assert result.state == "UNKNOWN" and result.reason == "AUTHORIZATION_UNAVAILABLE"
    assert result.provider_result_code == "30" and result.suggestions == ()
    service.get_context(place_id="place:0", base_month="202504", eligible_place_ids=("place:2",))
    assert len(calls) == 1


@pytest.mark.parametrize(
    "rows",
    [
        [row(2, tAtsCd="NAV-a"), row(3, tAtsCd="NAV-b")],
        [row(2, rlteSignguCd="11110")],
        [row(2, rlteTatsNm="존재하지 않는 장소")],
        [row(2), row(2, rlteTatsCd="different-provider-place")],
    ],
)
def test_ambiguous_or_foreign_related_ids_never_borrow_facts(rows) -> None:
    service, _ = service_for(rows=rows)
    result = service.get_context(
        place_id="place:0", base_month="202504", eligible_place_ids=("place:2", "place:3")
    )
    assert result.suggestions == ()


def test_noncanonical_filters_and_future_period_rejected_before_provider() -> None:
    service, calls = service_for()
    for kwargs in (
        {"eligible_place_ids": ("place:unknown",)},
        {"base_month": "202610"},
        {"cannot_coappear_pairs": (("place:0", "place:unknown"),)},
    ):
        with pytest.raises(ValueError):
            service.get_context(
                **{
                    "place_id": "place:0",
                    "base_month": "202504",
                    "eligible_place_ids": ("place:2",),
                    **kwargs,
                }
            )
    assert calls == []
