"""Actual FastAPI → official transport → kernel → PostgreSQL source tracer.

The catalog and scored profiles below are explicitly synthetic. Facility text is
copied from the recorded official 불국사 response; the negative and missing cases
are deliberate test counterfactuals, never evidence about real destinations.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from itda.api.dependencies import get_recommendation_service
from itda.api.main import create_app
from itda.application.recommendations import RecommendationService
from itda.application.source_grounding import SourceGroundingService
from itda.collectors.base import RequestPolicy
from itda.collectors.kto_accessibility import KorWithService2Client
from itda.contracts.mvp_public_catalog import PublicPlace, PublicPlaceCatalog
from itda.contracts.recommendation import QUALITY_RECOMMENDATION_CONFIG
from itda.db.recommendation_repositories import RecommendationRunRepository
from itda.db.repositories import ProfileRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.db.source_snapshot_repositories import SourceSnapshotRepository
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import AccessibilityService, CanonicalTourismPlace
from itda.tourism.settings import TourismSettings
from tests.contract.test_mvp_scored_release import _release_inventory_sha256, release
from tests.integration.test_recommendation_runs import _migrate, _persist_profile
from tests.pipeline.test_mvp_public_catalog import _place
from tests.unit.test_accessibility_source import DETAIL

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def _synthetic_catalog() -> PublicPlaceCatalog:
    places = []
    for index in range(100):
        payload = _place(index, "evidence:" + "1" * 64).model_dump(
            mode="json", exclude={"row_sha256"}
        )
        payload.update(
            category="관광지",
            name_ko=f"합성 공개 장소 {index}",
            normalized_name_ko=f"합성공개장소{index}",
        )
        places.append(
            PublicPlace.model_validate({**payload, "row_sha256": canonical_sha256(payload)})
        )
    payload = dict(
        schema_version="public-place-catalog.v1",
        pool="PUBLIC",
        region="경주시",
        places=[row.model_dump(mode="json") for row in places],
        evidence_inventory_sha256=_release_inventory_sha256(),
        blind_overlap_count=0,
    )
    return PublicPlaceCatalog.model_validate(
        {**payload, "catalog_sha256": canonical_sha256(payload)}
    )


@dataclass
class TransportState:
    catalog: PublicPlaceCatalog
    absent: set[str] = field(default_factory=set)
    unknown: set[str] = field(default_factory=set)
    fail: bool = False
    calls: list[str] = field(default_factory=list)
    lock: Lock = field(default_factory=Lock)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.calls.append(request.url.path)
        if self.fail:
            raise httpx.ConnectError("injected provider outage", request=request)
        if request.url.path.endswith("searchKeyword2"):
            place = next(
                row for row in self.catalog.places if row.name_ko == request.url.params["keyword"]
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
            index = int(request.url.params["contentId"])
            place_id = f"public:gyeongju:{index:064x}"
            rows = [{**DETAIL, "contentid": str(index)}]
            if place_id in self.absent:
                rows[0]["restroom"] = "장애인 화장실 없음"
            elif place_id in self.unknown:
                rows[0]["restroom"] = ""
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {"items": {"item": rows}, "totalCount": len(rows)},
                }
            },
        )


@dataclass
class Stack:
    client: TestClient
    engine: Engine
    service: RecommendationService
    source_store: SourceSnapshotRepository
    state: TransportState
    clock: list[datetime]
    profile_id: str

    def request(self, request_id: str, facilities: list[str] | None = None, **trip: object) -> dict:
        payload = {"request_id": request_id, "preference_profile_id": self.profile_id}
        if facilities is not None:
            payload["grounded_input"] = {"required_facilities": facilities, **trip}
        return payload

    def create(self, payload: dict) -> str:
        response = self.client.post("/v1/recommendation-runs", json=payload)
        assert response.status_code == 201, response.text
        return response.json()["recommendation_run_id"]

    def counts(self) -> tuple[int, ...]:
        with self.engine.connect() as connection:
            return tuple(
                connection.execute(text(f"SELECT count(*) FROM app.{table}")).scalar_one()
                for table in (
                    "recommendation_runs",
                    "recommendation_request_bindings",
                    "recommendation_result_pins",
                    "grounded_run_bindings",
                )
            )


@pytest.fixture
def stack(postgres_harness: object, monkeypatch: pytest.MonkeyPatch) -> Iterator[Stack]:
    _migrate(postgres_harness)
    for key in ("CI", "ITDA_NO_NETWORK", "ITDA_DATABASE_URL", "ITDA_PHOTO_SERVICE_DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    engine = create_database_engine(postgres_harness.dsns["runtime"])
    sessions = create_session_factory(engine)
    catalog = _synthetic_catalog()
    snapshot = release(80, catalog_sha256=catalog.catalog_sha256)
    profile = _persist_profile(engine, "source-tracer:" + uuid4().hex)
    state = TransportState(catalog)
    now = [NOW]
    with httpx.Client(transport=httpx.MockTransport(state)) as transport:
        collector = KorWithService2Client(
            service_key="synthetic-key-must-not-persist",
            http_client=transport,
            policy=RequestPolicy(max_attempts=1),
            clock=lambda: now[0],
        )
        places = tuple(
            CanonicalTourismPlace(
                place_id=row.place_id,
                name_ko=row.name_ko,
                address=row.address_ko,
                latitude=row.latitude,
                longitude=row.longitude,
                provider_content_id=row.provider_crosswalk[0].source_id,
            )
            for row in catalog.places
        )
        accessibility = AccessibilityService(
            client=collector,
            places=places,
            clock=lambda: now[0],
            settings=TourismSettings(
                enabled=True, positive_ttl_seconds=60, negative_ttl_seconds=10
            ),
        )
        source_store = SourceSnapshotRepository(sessions)
        service = RecommendationService(
            profile_repository=ProfileRepository(sessions),
            recommendation_repository=RecommendationRunRepository(sessions),
            release_resolver=lambda: snapshot,
            catalog=catalog,
            config=QUALITY_RECOMMENDATION_CONFIG,
            clock=lambda: now[0],
            source_grounding_service=SourceGroundingService(
                accessibility=accessibility, store=source_store
            ),
            event_sink=lambda event: None,
        )
        application = create_app()
        application.dependency_overrides[get_recommendation_service] = lambda: service
        with TestClient(application, raise_server_exceptions=False) as client:
            yield Stack(client, engine, service, source_store, state, now, profile.profile_id)
    engine.dispose()


def test_actual_api_filters_only_explicit_absence_and_pins_source_context(stack: Stack) -> None:
    baseline_id = stack.create(stack.request("baseline:" + uuid4().hex))
    baseline = stack.service.get_run(baseline_id)
    absent_id, unknown_id = (item.place_id for item in baseline.items[:2])
    assert stack.state.calls == []  # Companion alone does not infer an accessibility need.
    stack.state.absent.add(absent_id)
    stack.state.unknown.add(unknown_id)
    payload = stack.request(
        "facility:" + uuid4().hex, ["accessible_toilet"], visit_date="2026-09-15"
    )
    run_id = stack.create(payload)
    run = stack.service.get_run(run_id)
    ids = {item.place_id for item in run.items}
    assert absent_id not in ids
    assert unknown_id in ids
    assert run_id != baseline_id
    assert run.preference.quality_context.grounding is not None
    response = stack.client.get(f"/v1/recommendation-runs/{run_id}/trip-context")
    assert response.status_code == 200, response.text
    context = response.json()
    assert context["mode"] == "PINNED"
    assert response.headers["cache-control"] == "no-store"
    facts = {
        row["place_id"]: {fact["key"]: fact for fact in row["facts"]} for row in context["places"]
    }
    assert facts[unknown_id]["accessible_toilet"]["state"] == "UNKNOWN"
    assert facts[unknown_id]["accessible_toilet"]["value"] is None
    supported = next(
        row["accessible_toilet"] for place_id, row in facts.items() if place_id != unknown_id
    )
    assert supported["value"] is True
    assert supported["reference_date"] == NOW.date().isoformat()
    assert supported["evidence"][0]["receipt"]["service"] == "KorWithService2"
    assert supported["evidence"][0]["receipt"]["operation"] == "detailWithTour2"
    binding = stack.source_store.get_request_binding(payload["request_id"])
    assert binding.run_id == run_id
    assert (
        binding.source_snapshot_sha256
        == run.preference.quality_context.grounding.source_snapshot_sha256
    )
    assert len(binding.source_snapshot_sha256) == 80
    assert "synthetic-key-must-not-persist" not in str(context)

    before = run.model_dump_json()
    calls = len(stack.state.calls)
    stack.clock[0] += timedelta(days=10)
    stack.state.fail = True
    stack.state.absent.clear()
    assert stack.create(payload) == run_id
    assert stack.service.get_run(run_id).model_dump_json() == before
    refreshed_view = stack.client.get(f"/v1/recommendation-runs/{run_id}/trip-context").json()
    assert refreshed_view["places"] == context["places"]
    assert len(stack.state.calls) == calls
    for changes in ({"visit_date": "2026-09-16"}, {"required_facilities": ["wheelchair_rental"]}):
        changed = {**payload, "grounded_input": {**payload["grounded_input"], **changes}}
        rejected = stack.client.post("/v1/recommendation-runs", json=changed)
        assert rejected.status_code == 409, rejected.text
    assert len(stack.state.calls) == calls


def test_identical_request_alias_replays_same_grounding(stack: Stack) -> None:
    first = stack.request("alias-first:" + uuid4().hex, ["accessible_toilet"])
    run_id = stack.create(first)
    second = {**first, "request_id": "alias-second:" + uuid4().hex}
    assert stack.create(second) == run_id
    assert stack.source_store.get_request_binding(second["request_id"]).run_id == run_id
    stack.state.fail = True
    stack.clock[0] += timedelta(days=10)
    calls = len(stack.state.calls)
    assert stack.create(second) == run_id
    assert len(stack.state.calls) == calls


def test_provider_outage_still_produces_unknown_context_without_filtering(stack: Stack) -> None:
    baseline_id = stack.create(stack.request("outage-baseline:" + uuid4().hex))
    baseline = stack.service.get_run(baseline_id)
    stack.state.fail = True
    run_id = stack.create(stack.request("outage-facility:" + uuid4().hex, ["accessible_toilet"]))
    run = stack.service.get_run(run_id)
    assert [item.place_id for item in run.items] == [item.place_id for item in baseline.items]
    response = stack.client.get(f"/v1/recommendation-runs/{run_id}/trip-context")
    assert response.status_code == 200, response.text
    assert response.json()["mode"] == "PINNED"
    assert all(place["state"] == "UNAVAILABLE" for place in response.json()["places"])
    assert all(
        fact["state"] == "UNKNOWN" and fact["value"] is None
        for place in response.json()["places"]
        for fact in place["facts"]
    )
    calls = len(stack.state.calls)
    stack.client.get(f"/v1/recommendation-runs/{run_id}/trip-context")
    assert len(stack.state.calls) == calls


def test_failed_atomic_binding_leaves_no_run_pin_or_request_alias(
    stack: Stack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline_counts = stack.counts()
    original = SourceSnapshotRepository.bind_run_in_session

    def fail_after_write(self, session, binding):
        original(self, session, binding)
        raise RuntimeError("injected failure after source binding insert")

    monkeypatch.setattr(SourceSnapshotRepository, "bind_run_in_session", fail_after_write)
    response = stack.client.post(
        "/v1/recommendation-runs", json=stack.request("abort:" + uuid4().hex, ["accessible_toilet"])
    )
    assert response.status_code == 500
    assert stack.counts() == baseline_counts
