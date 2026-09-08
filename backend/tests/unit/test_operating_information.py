from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.collectors.base import CollectedResponse
from itda.operating.service import (
    OperatingInformationService,
    ProviderPlace,
    PublicCatalogLookup,
    parse_operating_snapshot,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
RETRIEVED_AT = datetime(2026, 9, 5, 4, 30, tzinfo=UTC)
PLACE_A = "public:gyeongju:test-a"
PLACE_B = "public:gyeongju:test-b"


class SyntheticCatalog:
    catalog_sha256 = "a" * 64

    def __init__(self) -> None:
        self.places = {
            PLACE_A: ProviderPlace(content_id="100", content_type_id="12"),
            PLACE_B: ProviderPlace(content_id="200", content_type_id="39"),
        }

    def lookup(self, place_id: str) -> ProviderPlace | None:
        return self.places.get(place_id)


class SyntheticProvider:
    def __init__(self, payloads: dict[str, object]) -> None:
        self.payloads = payloads
        self.calls: list[ProviderPlace] = []
        self.closed = False

    def fetch(self, place: ProviderPlace) -> CollectedResponse:
        self.calls.append(place)
        payload = self.payloads[place.content_id]
        if isinstance(payload, Exception):
            raise payload
        return response(payload)

    def close(self) -> None:
        self.closed = True


def response(payload: object) -> CollectedResponse:
    return CollectedResponse(
        provider="TOUR_API",
        endpoint="detailIntro2",
        request_scope={},
        retrieved_at=RETRIEVED_AT,
        http_status=200,
        raw_response_sha256="b" * 64,
        raw_body_base64="",
        modifiedtime="20260905043000",
        rights=(),
        payload=payload,
    )


def test_parser_projects_only_matching_allowlisted_operating_fields() -> None:
    snapshot = parse_operating_snapshot(
        response(
            {
                "response": {
                    "body": {
                        "items": {
                            "item": [
                                {"contentid": "other", "usetime": "잘못된 장소"},
                                {
                                    "contentid": "100",
                                    "usetime": "<b>09:00</b> &amp; 18:00",
                                    "restdate": "  매주   월요일  ",
                                    "parking": "실시간 주차 가능",
                                },
                            ]
                        }
                    }
                }
            }
        ),
        place=ProviderPlace(content_id="100", content_type_id="12"),
        cached=False,
    )

    assert snapshot is not None
    assert snapshot.model_dump(mode="json") == {
        "provider": "TOUR_API",
        "operation": "detailIntro2",
        "content_type_id": "12",
        "entries": [
            {
                "kind": "REST_DATES",
                "label_ko": "휴무일",
                "value_ko": "매주 월요일",
                "provider_field": "restdate",
            },
            {
                "kind": "OPENING_HOURS",
                "label_ko": "이용시간",
                "value_ko": "09:00 & 18:00",
                "provider_field": "usetime",
            },
        ],
        "retrieved_at": "2026-09-05T04:30:00Z",
        "provider_modifiedtime": "20260905043000",
        "source_label_ko": "한국관광공사 TourAPI(KorService2 detailIntro2)",
        "cached": False,
    }
    assert "parking" not in snapshot.model_dump_json()


def test_public_catalog_lookup_uses_verified_crosswalk_and_category_mapping() -> None:
    catalog = PublicCatalogLookup(
        catalog_path=REPO_ROOT / "artifacts/public/catalog/public-place-catalog-v1.json"
    )

    assert catalog.catalog_sha256 == (
        "e8957b1648ab72e593ed5c9b91f53d84f1c28bc1961a62e5acc7b3a04ea021f0"
    )
    assert catalog.lookup(
        "public:gyeongju:6a693878aae5efa3a97b5872e50ab1ec7ef46516a3325d1c2f835a907c327c88"
    ) == ProviderPlace(content_id="126207", content_type_id="12")
    assert catalog.lookup("public:gyeongju:missing") is None


def test_service_preserves_order_and_caches_available_snapshots() -> None:
    now = [10.0]
    provider = SyntheticProvider(
        {
            "100": {"item": {"contentid": "100", "usetime": "09:00~18:00"}},
            "200": {"item": {"contentid": "200", "opentimefood": "11:00~20:00"}},
        }
    )
    service = OperatingInformationService(
        catalog=SyntheticCatalog(),
        provider=provider,
        ttl_seconds=15,
        negative_ttl_seconds=2,
        monotonic=lambda: now[0],
    )

    first = service.load(run_id="recommendation-run:test", place_ids=(PLACE_B, PLACE_A))
    second = service.load(run_id="recommendation-run:test", place_ids=(PLACE_B, PLACE_A))

    assert [row.place_id for row in first.places] == [PLACE_B, PLACE_A]
    assert all(row.state == "AVAILABLE" for row in first.places)
    assert all(row.snapshot is not None and not row.snapshot.cached for row in first.places)
    assert all(row.snapshot is not None and row.snapshot.cached for row in second.places)
    assert len(provider.calls) == 2

    now[0] = 26.0
    service.load(run_id="recommendation-run:test", place_ids=(PLACE_A,))
    assert len(provider.calls) == 3


def test_service_negative_caches_failures_and_isolates_disabled_places() -> None:
    now = [10.0]
    provider = SyntheticProvider({"100": RuntimeError("synthetic failure")})
    service = OperatingInformationService(
        catalog=SyntheticCatalog(),
        provider=provider,
        negative_ttl_seconds=2,
        monotonic=lambda: now[0],
    )

    first = service.load(
        run_id="recommendation-run:test",
        place_ids=(PLACE_A, "public:gyeongju:outside"),
    )
    service.load(run_id="recommendation-run:test", place_ids=(PLACE_A,))

    assert [row.unavailable_reason for row in first.places] == [
        "PROVIDER_UNAVAILABLE",
        "NOT_IN_PROVIDER_SCOPE",
    ]
    assert len(provider.calls) == 1

    now[0] = 13.0
    service.load(run_id="recommendation-run:test", place_ids=(PLACE_A,))
    assert len(provider.calls) == 2

    disabled = OperatingInformationService(catalog=SyntheticCatalog(), provider=None)
    result = disabled.load(run_id="recommendation-run:test", place_ids=(PLACE_A,))
    assert result.places[0].unavailable_reason == "ENRICHMENT_DISABLED"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"ttl_seconds": 0}, "ttl_seconds must be finite and positive"),
        ({"negative_ttl_seconds": float("inf")}, "negative_ttl_seconds must be finite"),
        ({"cache_size": 0}, "cache_size must be a positive integer"),
    ],
)
def test_service_rejects_invalid_cache_configuration(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        OperatingInformationService(
            catalog=SyntheticCatalog(),
            provider=None,
            **kwargs,
        )
