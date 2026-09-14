"""National recommendations retain exact regional source and preference boundaries."""

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from pydantic import ValidationError

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_concentration import ConcentrationClient
from itda.collectors.kto_demand import RegionalDemandClient
from itda.collectors.kto_visitors import RegionalVisitorsClient
from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.grounded_run import GroundedRecommendationRun
from itda.contracts.grounded_source import GroundedSourceProfile
from itda.contracts.source_assessment import AssessmentBundle
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import match_gallery
from itda.tourism.accessibility import CanonicalTourismPlace, region_location_matches
from itda.tourism.temporal import TemporalContextService, TemporalPolicy
from tests.unit.test_grounded_recommendation import candidate, preference, run

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def test_region_input_is_bound_without_rewriting_legacy_empty_payload():
    legacy = GroundedTripInput(visit_date=date(2026, 9, 10))
    assert "region_code" not in legacy.model_dump(mode="json")
    assert GroundedTripInput(region_code="12").region_code == "12"
    selected = GroundedTripInput(visit_date=date(2026, 9, 10), region_code="11")
    assert selected.input_sha256 != legacy.input_sha256
    with pytest.raises(ValidationError):
        GroundedTripInput(
            region_code="36110"
        )  # The selector uses a province prefix, not a five-digit municipality.


def test_region_filter_precedes_scoring_and_never_backfills_another_province():
    rows = [
        replace(
            candidate(i),
            region_code="11110" if i < 5 else "26110",
            region_name="서울특별시 종로구" if i < 5 else "부산광역시 중구",
        )
        for i in range(9)
    ]
    result = run(rows, pref=preference(trip_input=GroundedTripInput(region_code="11")))
    assert all(item.region_code == "11110" for item in result.items)
    assert {row.reason for row in result.exclusions} == {"REGION"}
    from itda.domain.grounded_recommendation import GroundedRecommendationError

    with pytest.raises(GroundedRecommendationError, match="INSUFFICIENT"):
        run(rows, pref=preference(trip_input=GroundedTripInput(region_code="26")))
    assert GroundedRecommendationRun.model_validate_json(result.model_dump_json()) == result


def test_fresh_source_profiles_rank_without_inventing_legacy_scores_or_confidence():
    rows = []
    for i in range(6):
        row = candidate(i, level=1)
        payload = {
            "schema_version": "grounded-source-profile.v1",
            "place_id": row.place_id,
            "place_name_ko": row.profile.place_name_ko,
            "duplicate_group_id": row.profile.duplicate_group_id,
            "catalog_row_sha256": "4" * 64,
            "source_evidence_ids": row.profile.source_evidence_ids,
            "recommendation_eligible": True,
        }
        profile = GroundedSourceProfile.model_validate(
            payload | {"profile_sha256": canonical_sha256(payload)}
        )
        assessment = row.assessment.model_dump(mode="json", exclude={"bundle_sha256"})
        assessment["raw_profile_sha256"] = profile.profile_sha256
        bound = AssessmentBundle.model_validate(
            assessment | {"bundle_sha256": canonical_sha256(assessment)}
        )
        rows.append(replace(row, profile=profile, assessment=bound))
    result = run(rows)
    assert all(item.overall_confidence is None for item in result.items)
    assert all(item.contribution.experience.score == 75 for item in result.items)
    assert all(item.mismatch.state == "SUPPRESSED_LOW_CONFIDENCE" for item in result.items)
    assert GroundedRecommendationRun.model_validate_json(result.model_dump_json()) == result


def test_gallery_requires_actual_province_and_municipality_even_for_equal_names():
    place = CanonicalTourismPlace(
        place_id="place:seoul",
        name_ko="중앙공원",
        region_code="11110",
        region_name="서울특별시 종로구",
        address="서울특별시 종로구 공원로 1",
    )
    row = {"galContentId": "1", "galTitle": "중앙공원", "galPhotographyLocation": "서울 종로구"}
    assert match_gallery(place, row).state == "MATCHED"
    assert (
        match_gallery(place, row | {"galPhotographyLocation": "부산광역시 중구"}).state
        == "NOT_MATCHED"
    )
    assert not region_location_matches(place, "경상북도 경주시")


def test_multiple_regions_use_distinct_forecasts_demand_and_visitor_series(monkeypatch):
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    calls = []
    regions = {"11110": "서울특별시 종로구", "26110": "부산광역시 중구"}

    def respond(request):
        params = dict(request.url.params)
        operation = request.url.path.rsplit("/", 1)[-1]
        calls.append((operation, params.get("signguCd")))
        code = params.get("signguCd", "")
        if operation == "tatsCnctrRatedList":
            rows = [
                {
                    "areaCd": code[:2],
                    "signguCd": code,
                    "tAtsNm": "중앙공원",
                    "baseYmd": (NOW.date() + timedelta(days=i)).strftime("%Y%m%d"),
                    "cnctrRate": "10" if code == "11110" else "80",
                }
                for i in range(30)
            ]
        elif operation.startswith("areaTar"):
            prefix, number, label = (
                ("tarSjrnDsIx", "21", "관광체류강도")
                if operation == "areaTarSjrnDsList"
                else ("tarExpDsIx", "22", "관광소비강도")
            )
            rows = [
                {
                    "baseYm": "202607",
                    "areaCd": code[:2],
                    "signguCd": code,
                    prefix + "Cd": number,
                    prefix + "Nm": label,
                    prefix + "Val": "102.99" if code == "11110" else "77.92",
                }
            ]
        else:
            rows = [
                {
                    "baseYmd": "20260701",
                    "signguCode": region,
                    "touDivCd": category,
                    "touDivNm": label,
                    "touNum": "1.5" if region == "11110" else "9.5",
                }
                for region in regions
                for category, label in (("1", "현지인(a)"), ("2", "외지인(b)"), ("3", "외국인(c)"))
            ]
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {"items": {"item": rows}, "totalCount": len(rows)},
                }
            },
        )

    args = dict(
        service_key="synthetic-national-key",
        clock=lambda: NOW,
        http_client=httpx.Client(transport=httpx.MockTransport(respond)),
        policy=RequestPolicy(max_attempts=1),
    )
    service = TemporalContextService(
        places=tuple(
            CanonicalTourismPlace(
                place_id=code, name_ko="중앙공원", region_code=code, region_name=name
            )
            for code, name in regions.items()
        ),
        concentration=ConcentrationClient(**args),
        visitors=RegionalVisitorsClient(**args),
        demand=RegionalDemandClient(**args),
        policy=TemporalPolicy(enabled=True),
        clock=lambda: NOW,
    )
    result = service.get_context(
        place_ids=tuple(regions),
        trip_date=date(2026, 9, 10),
        visitor_start=date(2026, 7, 1),
        visitor_end=date(2026, 7, 1),
        demand_month="202607",
    )
    assert [row.value for row in result.forecasts] == [Decimal("10"), Decimal("80")]
    assert [row.region_code for row in result.forecasts] == list(regions)
    assert [row.points[0].value for row in result.regional_visitors] == [
        Decimal("1.5"),
        Decimal("9.5"),
    ]
    assert [row.measures[0].value for row in result.regional_demand] == [Decimal("102.99")] * 2 + [
        Decimal("77.92")
    ] * 2
    assert result.visitors == result.regional_visitors[0]
    assert result.demand == result.regional_demand[:2]
    assert len(calls) == 7 and all(code != "47130" for _, code in calls)
    assert service.replay(result.model_dump(mode="json")) == result
    with pytest.raises(ValueError, match="unambiguous"):
        service.get_context(place_ids=(), trip_date=date(2026, 9, 10))


def test_sejong_tourapi_codes_preserve_official_unsplit_municipality():
    from itda.tourism.accessibility import match_place

    place = CanonicalTourismPlace(
        place_id="place:sejong",
        name_ko="세종공원",
        region_code="36110",
        region_name="세종특별자치시",
        address="세종특별자치시 공원로 1",
        latitude=36.5,
        longitude=127.3,
    )
    assert place.tour_region_code == "36110" and place.tour_district_code == "36110"
    row = {
        "contentid": "1",
        "title": "세종공원",
        "addr1": place.address,
        "mapy": "36.5",
        "mapx": "127.3",
        "lDongRegnCd": "36110",
        "lDongSignguCd": "36110",
    }
    assert match_place(place, (row,)).state == "MATCHED"
    assert match_place(place, ({**row, "lDongRegnCd": "47"},)).state == "NOT_MATCHED"


def test_regions_endpoint_uses_active_supported_official_regions():
    from types import SimpleNamespace

    from itda.application.grounded_recommendations import GroundedRecommendationService

    sources = [
        {
            "place": {
                "place_id": "sejong",
                "region_code": "36110",
                "region_name": "세종특별자치시",
            },
            "category": "관광지",
        },
        {
            "place": {
                "place_id": "merged",
                "region_code": "12110",
                "region_name": "전남광주통합특별시 동구",
            },
            "category": "문화시설",
        },
        {
            "place": {
                "place_id": "no-evidence",
                "region_code": "11110",
                "region_name": "서울특별시 종로구",
            },
            "category": "관광지",
        },
    ]
    assessments = [
        SimpleNamespace(
            place_id=source["place"]["place_id"],
            dimensions={
                key: SimpleNamespace(
                    value=50 if source["place"]["place_id"] != "no-evidence" else None
                )
                for key in "HER"
            },
        )
        for source in sources
    ]
    active = SimpleNamespace(
        source_snapshots=sources, assessments=assessments, candidate_sha256="a" * 64
    )
    service = object.__new__(GroundedRecommendationService)
    service.enabled = True
    service.candidate_resolver = lambda: active
    result = service.get_regions()
    assert [(row.region_code, row.region_name) for row in result.regions] == [
        ("12", "전남광주통합특별시"),
        ("36", "세종특별자치시"),
    ]
    service.enabled = False
    assert service.get_regions().regions == ()


def test_national_places_cannot_inherit_legacy_default_region():
    with pytest.raises(ValidationError, match="explicit official region"):
        CanonicalTourismPlace(place_id="public:korea:" + "a" * 64, name_ko="새로운 장소")
