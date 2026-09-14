from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest

from itda.collectors.base import RequestPolicy
from itda.collectors.kto_walking import WalkingClient
from itda.tourism.accessibility import CanonicalTourismPlace
from itda.tourism.temporal import TemporalPolicy
from itda.tourism.walking import WalkingEnrichmentService, official_gpx_url, parse_official_gpx

NOW = datetime(2026, 9, 9, tzinfo=UTC)
GPX_URL = "https://www.durunubi.kr/editImgUp.do?filePath=/data/koreamobility/file/2025/09/37d0bec1fe844a7cbe650c432b7c49e6.gpx"


def course(**updates: str) -> dict[str, str]:
    # Exact published fields from 해파랑길10코스; shortened text is test-only.
    return {
        "routeIdx": "T_THEME_MNG0000011235",
        "crsIdx": "T_CRS_MNG0000004238",
        "crsKorNm": "해파랑길 10코스",
        "crsDstnc": "13",
        "crsTotlRqrmHour": "270",
        "crsLevel": "2",
        "sigun": "경북 경주시",
        "brdDiv": "DNWW",
        "crsContents": "경주 감포항을 언급하는 합성 코스 설명",
        "gpxpath": GPX_URL,
        "modifiedtime": "20250916124850",
        **updates,
    }


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def service_for(rows=None, **options):
    calls = []

    def transport(request: httpx.Request) -> httpx.Response:
        operation = request.url.path.rsplit("/", 1)[-1]
        calls.append(operation)
        items = (
            (rows if rows is not None else [course()])
            if operation == "courseList"
            else [{"routeIdx": "T_THEME_MNG0000011235", "themeNm": "해파랑길", "brdDiv": "DNWW"}]
        )
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {"items": {"item": items}, "totalCount": len(items)},
                }
            },
        )

    client = WalkingClient(
        service_key="walking-fixture-key",
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
        policy=RequestPolicy(max_attempts=1),
        clock=lambda: NOW,
    )
    place = CanonicalTourismPlace(
        place_id="place:gampo", name_ko="감포항", latitude=35.8, longitude=129.5
    )
    return WalkingEnrichmentService(
        places=(place,),
        client=client,
        clock=lambda: NOW,
        policy=TemporalPolicy(enabled=True),
        **options,
    ), calls


def test_actual_course_minutes_km_and_landmark_scope_are_preserved() -> None:
    service, calls = service_for()
    result = service.get_context("place:gampo")
    item = result.courses[0]
    assert calls == ["courseList", "routeList"]
    assert item.duration_minutes == 270 and item.distance_km == Decimal("13")
    assert item.difficulty_code == "2" and item.difficulty_label_ko == "보통"
    assert item.link_kind == "MENTIONED_ON_COURSE"
    assert item.scope == "COURSE" and not item.applies_to_place_walking_score
    assert item.unit_authority == "DURUNUBI_MANUAL_4_1"
    assert "walking-fixture-key" not in result.model_dump_json()


def test_substring_car_racing_elsewhere_and_unverified_parent_are_rejected() -> None:
    service, _ = service_for(
        [course(sigun="전남 영암군", crsContents="자동차 경주를 볼 수 있습니다")]
    )
    assert service.get_context("place:gampo").courses == ()
    service, _ = service_for([course(routeIdx="unknown-route")])
    result = service.get_context("place:gampo")
    assert result.courses == () and result.reason == "PARTIAL_SERIES"


@pytest.mark.parametrize(
    "updates,reason",
    [
        ({"crsTotlRqrmHour": ""}, "INVALID_VALUE"),
        ({"crsLevel": "4"}, "INVALID_VALUE"),
        ({"modifiedtime": "20200101000000"}, "STALE"),
    ],
)
def test_bad_or_stale_course_estimates_are_unknown(updates, reason) -> None:
    service, _ = service_for([course(**updates)])
    item = service.get_context("place:gampo").courses[0]
    assert item.state == "UNKNOWN" and item.reason == reason
    assert item.duration_minutes is None and item.distance_km is None


def test_validated_official_geometry_supports_nearby_label_only() -> None:
    raw = (
        b'<gpx><trk><trkseg><trkpt lat="35.799" lon="129.5"/>'
        b'<trkpt lat="35.801" lon="129.5"/></trkseg></trk></gpx>'
    )
    geometry = parse_official_gpx(
        raw,
        course_id="T_CRS_MNG0000004238",
        route_id="T_THEME_MNG0000011235",
        source_url=GPX_URL,
        retrieved_at=NOW,
    )
    service, _ = service_for(geometries=(geometry,))
    context, sources = service.get_context_with_sources("place:gampo")
    item = context.courses[0]
    assert item.link_kind == "VERIFIED_NEARBY_COURSE" and item.distance_from_place_meters == 0
    assert item.geometry_sha256 == geometry.geometry_sha256 and len(sources) == 3
    assert not item.applies_to_place_walking_score


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/route.gpx",
        GPX_URL + "&next=http://localhost",
        GPX_URL.replace("www.durunubi.kr", "user@www.durunubi.kr"),
        GPX_URL.replace("37d0bec1fe844a7cbe650c432b7c49e6.gpx", "../../secret"),
    ],
)
def test_gpx_only_allows_official_path(url) -> None:
    assert official_gpx_url(url) is None


def test_gpx_entities_and_invalid_geometry_fail_before_use() -> None:
    for raw in (
        b'<!DOCTYPE gpx [<!ENTITY x SYSTEM "file:///etc/passwd">]><gpx>&x;</gpx>',
        b'<gpx><trkpt lat="999" lon="129"/><trkpt lat="35" lon="129"/></gpx>',
    ):
        with pytest.raises(ValueError):
            parse_official_gpx(
                raw,
                course_id="course:one",
                route_id="route:one",
                source_url=GPX_URL,
                retrieved_at=NOW,
            )


def test_optional_gpx_http_fetch_is_bounded_and_rejects_redirects() -> None:
    service, _ = service_for()
    item = service.get_context("place:gampo").courses[0]
    calls = []

    def transport(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://example.com/private"})

    with (
        httpx.Client(transport=httpx.MockTransport(transport)) as client,
        pytest.raises(ValueError, match="unavailable"),
    ):
        service.fetch_geometry(item, http_client=client)
    assert len(calls) == 1 and calls[0] == GPX_URL


def test_exact_course_requires_matching_curated_review_and_keeps_course_scope() -> None:
    from itda.contracts.place_enrichment import CuratedCourseCrosswalk

    reviewed = CuratedCourseCrosswalk(
        place_id="place:gampo",
        course_id="T_CRS_MNG0000004238",
        route_id="T_THEME_MNG0000011235",
        review_sha256="a" * 64,
        evidence_ko="합성 검수: 이 관광지 식별자는 전체 걷기 코스 식별자임",
    )
    service, _ = service_for(exact_course_crosswalk=(reviewed,))
    course = service.get_context("place:gampo").courses[0]
    assert (
        course.link_kind == "EXACT_CANONICAL_COURSE"
        and course.exact_match_review_sha256 == "a" * 64
    )
    assert not course.applies_to_place_walking_score


def test_geometry_for_different_source_url_cannot_claim_nearby_route() -> None:
    raw = b'<gpx><trkpt lat="35.799" lon="129.5"/><trkpt lat="35.801" lon="129.5"/></gpx>'
    geometry = parse_official_gpx(
        raw,
        course_id="T_CRS_MNG0000004238",
        route_id="T_THEME_MNG0000011235",
        source_url=GPX_URL.replace(
            "37d0bec1fe844a7cbe650c432b7c49e6", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        retrieved_at=NOW,
    )
    service, _ = service_for(geometries=(geometry,))
    course = service.get_context("place:gampo").courses[0]
    assert course.link_kind == "MENTIONED_ON_COURSE" and course.geometry_sha256 is None
