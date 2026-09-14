"""All-seven production registry consumers with only HTTP transport mocked."""

from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest

from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.source_assessment import SourceService
from itda.contracts.tourism_context import TOURISM_CONSUMERS
from itda.domain.canonical import canonical_sha256
from itda.tourism.registry import ProductionTourismRegistry
from itda.tourism.settings import TourismSettings
from tests.integration.test_source_grounding_tracer import _synthetic_catalog
from tests.unit.test_accessibility_source import DETAIL
from tests.unit.test_temporal_context import VISITORS, forecast_rows
from tests.unit.test_walking_enrichment import course

NOW = datetime(2026, 9, 9, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def registry_for(
    *,
    key="fixture-registry-key",
    related_denied=False,
    settings=None,
    observer=None,
    echo_key=False,
):
    catalog = _synthetic_catalog()
    calls = []
    environment = {"TOUR_API_SERVICE_KEY": key}

    def transport(request: httpx.Request) -> httpx.Response:
        service, operation = request.url.path.split("/")[-2:]
        calls.append((service, operation))
        if echo_key:
            return httpx.Response(200, json={"echo": request.url.params["serviceKey"]})
        if service == "AreaTarDemDsService" or service == "TarRlteTarService1" and related_denied:
            return httpx.Response(
                403,
                json={
                    "OpenAPI_ServiceResponse": {
                        "cmmMsgHeader": {
                            "returnReasonCode": "30",
                            "returnAuthMsg": "등록되지 않은 서비스키",
                            "errMsg": "SERVICE_KEY_IS_NOT_REGISTERED_ERROR",
                        }
                    }
                },
            )
        if service == "KorWithService2":
            if operation == "searchKeyword2":
                place = next(
                    row for row in catalog.places if row.name_ko == request.url.params["keyword"]
                )
                index = int(place.place_id.rsplit(":", 1)[-1], 16)
                rows = [
                    {
                        "contentid": str(index),
                        "title": place.name_ko,
                        "addr1": place.address_ko,
                        "mapx": str(place.longitude),
                        "mapy": str(place.latitude),
                        "lDongRegnCd": "47",
                        "lDongSignguCd": "130",
                    }
                ]
            else:
                rows = [{**DETAIL, "contentid": request.url.params["contentId"]}]
        elif service == "TatsCnctrRateService":
            rows = forecast_rows(catalog.places[0].name_ko) + forecast_rows(
                catalog.places[1].name_ko
            )
        elif service == "DataLabService":
            rows = VISITORS
        elif service == "GoCamping":
            place = catalog.places[0]
            rows = [
                {
                    "contentId": "0",
                    "facltNm": place.name_ko,
                    "addr1": place.address_ko,
                    "mapX": str(place.longitude),
                    "mapY": str(place.latitude),
                    "doNm": "경상북도",
                    "sigunguNm": "경주시",
                    "modifiedtime": "2026-07-14",
                    "toiletCo": "0",
                    "swrmCo": "",
                    "wtrplCo": "0",
                    "operDeCl": "평일+주말",
                }
            ]
        elif service == "Durunubi":
            rows = (
                [course(crsIdx=f"course:{i}") for i in range(7)]
                if operation == "courseList"
                else [
                    {"routeIdx": "T_THEME_MNG0000011235", "themeNm": "해파랑길", "brdDiv": "DNWW"}
                ]
            )
        elif service == "TarRlteTarService1":
            rows = [
                {
                    "baseYm": request.url.params["baseYm"],
                    "areaCd": "47",
                    "signguCd": "47130",
                    "tAtsNm": catalog.places[0].name_ko,
                    "tAtsCd": "NAV-0",
                    "rlteTatsNm": catalog.places[2].name_ko,
                    "rlteTatsCd": "NAV-2",
                    "rlteRegnCd": "47",
                    "rlteSignguCd": "47130",
                    "rlteRank": "1",
                }
            ]
        else:
            raise AssertionError(service)
        page = int(request.url.params.get("pageNo", "1"))
        size = int(request.url.params.get("numOfRows", "1000"))
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

    client = httpx.Client(transport=httpx.MockTransport(transport))
    registry = ProductionTourismRegistry.from_catalog(
        catalog,
        settings=settings or TourismSettings(enabled=True),
        environ=environment,
        http_client=client,
        clock=lambda: NOW,
        observer=observer,
    )
    return registry, calls, environment, catalog


def arguments(catalog):
    return {
        "run_id": "run:registry",
        "place_ids": tuple(row.place_id for row in catalog.places[:2]),
        "trip_input": GroundedTripInput(
            visit_date=date(2026, 9, 10), required_facilities=("accessible_toilet",)
        ),
        "eligible_place_ids": tuple(row.place_id for row in catalog.places[:4]),
    }


def test_registry_invokes_all_seven_real_consumers_and_returns_bounded_context() -> None:
    registry, calls, _, catalog = registry_for(settings=TourismSettings.from_environment({}))
    context, sources = registry.context_with_sources(**arguments(catalog))
    assert {source for source, _ in calls} == {service.value for service in TOURISM_CONSUMERS}
    assert len(context.source_health) == 7 and len(context.places) == 2
    assert all(len(place.walking.courses) <= 5 for place in context.places)
    assert context.temporal.forecasts[0].value is not None
    assert context.temporal.visitors.points[0].value is not None
    assert context.places[0].camping.facts["toilet_count"].value == 0
    assert context.places[0].accessibility.facts[0].key
    assert context.places[0].related.suggestions[0].place_id == catalog.places[2].place_id
    health = {row.service: row for row in context.source_health}
    assert health[SourceService.DEMAND].reason == "AUTHORIZATION_UNAVAILABLE"
    assert health[SourceService.DEMAND].provider_result_codes == ("30",)
    assert health[SourceService.WALKING].http_attempt_count == 2
    assert context.reference_periods.visitor_start == date(2026, 7, 1)
    assert context.reference_periods.related_month == "202504"
    assert context.source_snapshot_sha256 == tuple(
        sorted(canonical_sha256(source) for source in sources)
    )
    assert "fixture-registry-key" not in context.model_dump_json()


def test_cached_and_stored_reads_make_no_http_and_key_rotation_invalidates_private_cache() -> None:
    registry, calls, environment, catalog = registry_for(related_denied=True)
    context = registry.context(**arguments(catalog))
    count = len(calls)
    cached = registry.context(**arguments(catalog))
    assert len(calls) == count and sum(row.http_attempt_count for row in cached.source_health) == 0
    assert registry.replay(context.model_dump(mode="json")) == context and len(calls) == count
    environment["TOUR_API_SERVICE_KEY"] = "different-registry-key"
    changed = registry.context(**arguments(catalog))
    assert len(calls) > count
    assert "different-registry-key" not in changed.model_dump_json()


def test_missing_configuration_is_explicitly_unavailable_without_requests() -> None:
    registry, calls, _, catalog = registry_for(key="")
    context = registry.context(**arguments(catalog))
    assert calls == []
    assert all(
        row.state == "UNAVAILABLE" and row.http_attempt_count == 0 for row in context.source_health
    )


def test_bad_membership_rejected_before_any_provider_call() -> None:
    registry, calls, _, catalog = registry_for()
    for update in (
        {"place_ids": ("place:untrusted",)},
        {"eligible_place_ids": ()},
        {"selected_place_ids": ("place:untrusted",)},
        {"condition_excluded_place_ids": ("place:untrusted",)},
    ):
        with pytest.raises(ValueError, match="membership"):
            registry.context(**{**arguments(catalog), **update})
    assert calls == []


@pytest.mark.parametrize(
    "values",
    [
        {"http_concurrency": 40},
        {"batch_model_sessions": 33},
        {"model_session_limit": 50},
        {"negative_ttl_seconds": 0},
        {"model": "glm-4.6v"},
        {"visitor_reference_start": "2026-07-01"},
    ],
)
def test_settings_reject_unbounded_or_conflicting_configuration(values) -> None:
    with pytest.raises(ValueError):
        TourismSettings(**values)


def test_settings_period_overrides_do_not_claim_latest_and_files_are_secret_only(
    tmp_path: Path,
) -> None:
    settings = TourismSettings.from_environment(
        {
            "ITDA_TOURISM_ENABLED": "1",
            "ITDA_TOURISM_RELATED_MONTH": "202504",
            "ITDA_TOURISM_VISITOR_START": "2026-07-01",
            "ITDA_TOURISM_VISITOR_END": "2026-07-02",
        }
    )
    assert settings.related_reference_month == "202504"
    assert settings.batch_model_sessions + settings.photo_model_sessions == 40
    from itda.tourism.registry import tourism_credentials

    path = tmp_path / "key"
    path.write_text("private%2Bkey")
    credentials = tourism_credentials({"ITDA_TOUR_API_SERVICE_KEY_FILE": str(path)})
    assert set(credentials.values()) == {"private+key"}


def test_diagnostic_observer_gets_safe_per_attempt_bytes_and_never_echoed_keys() -> None:
    observed = []
    registry, _, _, catalog = registry_for(
        observer=lambda event, body: observed.append((event, body))
    )
    context = registry.context(**arguments(catalog))
    assert len(observed) == sum(row.http_attempt_count for row in context.source_health)
    assert all("serviceKey" not in event["request_scope"] for event, _ in observed)
    assert all(body is not None for _, body in observed)
    observed = []
    registry, _, _, catalog = registry_for(
        observer=lambda event, body: observed.append((event, body)), echo_key=True
    )
    context = registry.context(**arguments(catalog))
    assert all(body is None for _, body in observed)
    assert all(row.state == "UNAVAILABLE" for row in context.source_health)
    assert (
        "fixture-registry-key" not in str(observed)
        and "fixture-registry-key" not in context.model_dump_json()
    )


def test_diagnostic_cli_dry_run_has_zero_requests_and_explicit_periods(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    from itda.cli.verify_tourism_sources import main

    catalog = _synthetic_catalog()
    path = tmp_path / "catalog.json"
    path.write_text(catalog.model_dump_json())

    def no_factory(*args, **kwargs):
        raise AssertionError("dry-run constructed a live registry")

    monkeypatch.setattr(ProductionTourismRegistry, "from_catalog", no_factory)
    assert main(["--catalog", str(path), "--related-month", "202504"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "DRY_RUN" and result["provider_requests"] == 0
    assert len(result["source_consumers"]) == 7
    assert result["reference_periods"]["related_month"] == "202504"


def test_combined_context_hash_and_membership_cannot_be_tampered() -> None:
    registry, _, _, catalog = registry_for()
    context = registry.context(**arguments(catalog))
    payload = context.model_dump(mode="json")
    payload["places"][0]["place_id"] = "place:foreign"
    with pytest.raises(ValueError):
        registry.replay(payload)
    payload = context.model_dump(mode="json")
    payload["source_health"].pop()
    with pytest.raises(ValueError, match="seven"):
        registry.replay(payload)
