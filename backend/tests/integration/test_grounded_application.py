"""Real FastAPI routes and PostgreSQL run pins with only provider transport mocked."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from threading import Lock
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from itda.api.dependencies import (
    ProfileSessionPrincipal,
    get_optional_profile_session,
    get_recommendation_service,
)
from itda.api.main import create_app
from itda.application.grounded_recommendations import GroundedRecommendationService
from itda.application.recommendations import RecommendationService
from itda.contracts.recommendation import QUALITY_RECOMMENDATION_CONFIG
from itda.contracts.tourism_context import TOURISM_CONSUMERS
from itda.contracts.visual_mood import MoodObservation, VisualMoodDimension
from itda.db.recommendation_repositories import RecommendationRunRepository
from itda.db.repositories import ProfileRepository
from itda.domain.visual_mood import build_candidate_set, confirm_moods, mood_draft_sha256
from itda.tourism.registry import ProductionTourismRegistry
from itda.tourism.settings import TourismSettings
from tests.integration.test_grounded_recommendation_runs import database as _database
from tests.integration.test_grounded_release_pairs import NOW
from tests.integration.test_recommendation_runs import _persist_profile
from tests.integration.test_source_grounding_tracer import _synthetic_catalog
from tests.unit.test_accessibility_source import DETAIL

database = _database
ORIGIN = "http://testserver"


@dataclass
class OfficialTransport:
    catalog: object
    calls: list[tuple[str, str]] = field(default_factory=list)
    absent: set[str] = field(default_factory=set)
    unknown: set[str] = field(default_factory=set)
    denied: bool = False
    fail_if_called: bool = False
    lock: Lock = field(default_factory=Lock)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        service, operation = request.url.path.split("/")[-2:]
        with self.lock:
            self.calls.append((service, operation))
        if self.fail_if_called:
            raise AssertionError("saved replay attempted external source I/O")
        if self.denied:
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
        rows = []
        if service == "KorWithService2":
            if operation == "searchKeyword2":
                p = next(
                    p for p in self.catalog.places if p.name_ko == request.url.params["keyword"]
                )
                index = int(p.place_id.rsplit(":", 1)[-1], 16)
                rows = [
                    dict(
                        contentid=str(index),
                        title=p.name_ko,
                        addr1=p.address_ko,
                        mapx=str(p.longitude),
                        mapy=str(p.latitude),
                        lDongRegnCd="47",
                        lDongSignguCd="130",
                    )
                ]
            else:
                cid = request.url.params["contentId"]
                pid = next(
                    p.place_id
                    for p in self.catalog.places
                    if str(int(p.place_id.rsplit(":", 1)[-1], 16)) == cid
                )
                rows = [
                    dict(
                        DETAIL,
                        contentid=cid,
                        restroom="장애인 화장실 없음"
                        if pid in self.absent
                        else ""
                        if pid in self.unknown
                        else DETAIL["restroom"],
                    )
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


@pytest.fixture
def app_stack(database, monkeypatch):
    # No process environment credential is consulted: every provider is attached
    # to an in-memory transport with an explicit non-secret test key.
    for key in ("ITDA_DATABASE_URL", "ITDA_PHOTO_SERVICE_DATABASE_URL", "ITDA_NO_NETWORK", "CI"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", ORIGIN)
    engine, factory, runs, sources, (candidate, _) = database
    profile = _persist_profile(engine, "app-profile:" + uuid4().hex)
    catalog = _synthetic_catalog()
    transport = OfficialTransport(catalog)
    registry = ProductionTourismRegistry.from_catalog(
        catalog,
        settings=TourismSettings(enabled=True, max_attempts=1),
        environ={"TOUR_API_SERVICE_KEY": "fixture-key-never-in-public-payload"},
        http_client=httpx.Client(transport=httpx.MockTransport(transport)),
        clock=lambda: NOW,
    )
    profiles = ProfileRepository(factory)
    legacy = RecommendationService(
        profile_repository=profiles,
        recommendation_repository=RecommendationRunRepository(factory),
        release_resolver=lambda: candidate.raw_release,
        config=QUALITY_RECOMMENDATION_CONFIG,
        catalog=catalog,
        tourism_registry=registry,
        clock=lambda: NOW + timedelta(minutes=5),
    )
    facade = GroundedRecommendationService(
        legacy=legacy,
        profiles=profiles,
        runs=runs,
        sources=sources,
        candidate_resolver=lambda: candidate,
        registry=registry,
        enabled=True,
        clock=lambda: NOW + timedelta(minutes=5),
    )
    app = create_app()
    app.dependency_overrides[get_recommendation_service] = lambda: facade
    app.dependency_overrides[get_optional_profile_session] = lambda: ProfileSessionPrincipal(
        profile_id=profile.profile_id, session_digest="a" * 64, raw_reference="synthetic-session"
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, facade, profile, candidate, transport, registry
    registry.close()


def payload(profile, **updates):
    return dict(
        request_id="http-grounded:" + uuid4().hex,
        preference_profile_id=profile.profile_id,
        purpose="MIXED",
        grounded_input={"visit_date": "2026-09-10"},
        **updates,
    )


def create(client, request):
    response = client.post(
        "/v1/recommendation-runs",
        json=request,
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_real_api_v5_response_flow_and_all_seven_unavailable_sources(app_stack):
    client, facade, profile, candidate, transport, _ = app_stack
    transport.denied = True
    created = create(client, payload(profile))
    run_id = created["recommendation_run_id"]
    result = client.get(f"/v1/recommendation-runs/{run_id}")
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["schema_version"] == "itda.grounded-recommendation-results.v1"
    assert data["release_disclosure"]["candidate_sha256"] == candidate.candidate_sha256
    ids = [item["place_id"] for item in data["run"]["items"]]
    detail = client.get(f"/v1/recommendation-runs/{run_id}/places/{ids[0]}")
    compare = client.get(
        f"/v1/recommendation-runs/{run_id}/comparison",
        params=[("place_id", pid) for pid in ids[:2]],
    )
    context = client.get(f"/v1/recommendation-runs/{run_id}/tourism-context")
    for response in (detail, compare, context):
        assert response.status_code == 200, response.text
    assert detail.json()["item"] == data["run"]["items"][0]
    assert compare.json()["places"][0] == detail.json()
    tourism = context.json()
    assert {r["service"] for r in tourism["source_health"]} == {s.value for s in TOURISM_CONSUMERS}
    assert all(r["state"] == "UNAVAILABLE" for r in tourism["source_health"])
    assert all(r["value"] is None for r in tourism["temporal"]["forecasts"])
    assert tourism["temporal"]["ranking_effect"] == "NONE"
    assert {service for service, _ in transport.calls} == {s.value for s in TOURISM_CONSUMERS}
    assert facade.get_run(run_id).canonical_sha256 == data["run"]["canonical_sha256"]
    fixture = {
        "fixture_kind": "SYNTHETIC_POSTGRES_FASTAPI_RESPONSES",
        "note": "HTTP paths and PostgreSQL persistence were executed; "
        "place/source values are synthetic policy cases.",
        "created": created,
        "results": data,
        "detail": detail.json(),
        "comparison": compare.json(),
        "tourism_context": tourism,
    }
    assert "fixture-key-never-in-public-payload" not in json.dumps(fixture)
    destination = (
        Path(__file__).resolve().parents[3]
        / "artifacts/reports/grounded-api-pg-fixtures-20260909.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(fixture, ensure_ascii=False, indent=2))


def test_required_facility_absence_filters_unknown_remains_and_replay_does_no_io(app_stack):
    client, facade, profile, _, transport, _ = app_stack
    baseline = create(client, payload(profile))["recommendation_run_id"]
    baseline_run = client.get(f"/v1/recommendation-runs/{baseline}").json()["run"]
    absent = baseline_run["items"][0]["place_id"]
    unknown = baseline_run["items"][1]["place_id"]
    transport.absent.add(absent)
    transport.unknown.add(unknown)
    req = payload(profile)
    req["grounded_input"]["required_facilities"] = ["accessible_toilet"]
    created = create(client, req)
    run_id = created["recommendation_run_id"]
    result = client.get(f"/v1/recommendation-runs/{run_id}").json()
    ids = {item["place_id"] for item in result["run"]["items"]}
    assert absent not in ids and unknown in ids
    assert {
        e["place_id"]
        for e in result["run"]["exclusions"]
        if e["reason"] == "EXPLICIT_FACILITY_ABSENT"
    } == {absent}
    pinned = client.get(f"/v1/recommendation-runs/{run_id}/trip-context")
    assert pinned.status_code == 200, pinned.text
    assert pinned.json()["mode"] == "PINNED"
    unknown_row = next(p for p in pinned.json()["places"] if p["place_id"] == unknown)
    assert next(f for f in unknown_row["facts"] if f["key"] == "accessible_toilet")["value"] is None
    transport.fail_if_called = True
    facade.candidate_resolver = lambda: (_ for _ in ()).throw(
        AssertionError("replay consulted active candidate")
    )
    calls = len(transport.calls)
    assert create(client, req) == created
    assert client.get(f"/v1/recommendation-runs/{run_id}").json() == result
    assert client.get(f"/v1/recommendation-runs/{run_id}/trip-context").json() == pinned.json()
    assert len(transport.calls) == calls
    changed = json.loads(json.dumps(req))
    changed["grounded_input"]["visit_date"] = "2026-09-11"
    response = client.post("/v1/recommendation-runs", json=changed)
    assert response.status_code == 409, response.text


def test_confirmed_unknown_mood_api_keeps_baseline_and_replays_without_private_reader(app_stack):
    client, facade, profile, _, transport, _ = app_stack
    baseline_id = create(client, payload(profile))["recommendation_run_id"]
    baseline = client.get(f"/v1/recommendation-runs/{baseline_id}").json()["run"]
    job = "d" * 64
    batch = build_candidate_set(
        job_id=job,
        image_index=1,
        image_sha256="e" * 64,
        provider_id="synthetic-app-mood",
        analysis_kind="SYNTHETIC",
        model=None,
        observations=tuple(
            MoodObservation(dimension=d, state="UNKNOWN", level=None, certainty="LOW")
            for d in VisualMoodDimension
        ),
    )
    photo = confirm_moods(
        job_id=job,
        profile_id=profile.profile_id,
        batches=(batch,),
        choices=(),
        draft_sha256=mood_draft_sha256(job_id=job, profile_id=profile.profile_id, batches=(batch,)),
    )

    class Reader:
        calls = 0
        failed = False

        def read_projection(self, *, job_id, profile_id):
            self.calls += 1
            assert not self.failed and job_id == job and profile_id == profile.profile_id
            return photo

    reader = Reader()
    facade.mood_reader = reader
    req = payload(profile, photo_job_id=job)
    created = create(client, req)
    run_id = created["recommendation_run_id"]
    result = client.get(f"/v1/recommendation-runs/{run_id}").json()["run"]
    assert [(i["place_id"], i["fit_score"]) for i in result["items"]] == [
        (i["place_id"], i["fit_score"]) for i in baseline["items"]
    ]
    assert result["preference"]["axis_targets"] == baseline["preference"]["axis_targets"]
    assert result["preference"]["trait_targets"] == baseline["preference"]["trait_targets"]
    assert result["authority"]["photo_input_sha256"] == photo.receipt_id
    assert reader.calls == 1
    reader.failed = True
    transport.fail_if_called = True
    facade.enabled = False
    facade.candidate_resolver = lambda: (_ for _ in ()).throw(
        AssertionError("saved photo consulted current pair")
    )
    assert create(client, req) == created
    assert reader.calls == 1


def test_disabled_facade_replays_archives_but_does_not_create_new_legacy_runs(app_stack):
    from itda.contracts.recommendation import RecommendationRequest

    client, facade, profile, _, transport, _ = app_stack
    facade.enabled = False
    req = payload(profile)
    req.pop("grounded_input")
    paused = client.post("/v1/recommendation-runs", json=req)
    assert paused.status_code == 503, paused.text
    assert facade.runs.lookup_schema_for_request(req["request_id"]) is None
    assert transport.calls == []
    # Seed an explicitly historical record via the legacy test fixture. Normal
    # production HTTP may only replay it, never create this old scoring family.
    created = facade.legacy.create_run_response(
        RecommendationRequest.model_validate(req)
    ).model_dump(mode="json")
    run_id = created["recommendation_run_id"]
    result = client.get(f"/v1/recommendation-runs/{run_id}")
    assert result.status_code == 200, result.text
    assert result.json()["schema_version"] == "itda.recommendation-results.v2"
    assert result.json()["run"]["schema_version"] == "recommendation-run.v2"
    facade.enabled = True
    transport.fail_if_called = True
    facade.candidate_resolver = lambda: (_ for _ in ()).throw(
        AssertionError("legacy replay consulted v5")
    )
    facade.legacy._release_resolver = lambda: (_ for _ in ()).throw(
        AssertionError("legacy replay consulted active release")
    )
    assert create(client, req) == created
    assert client.get(f"/v1/recommendation-runs/{run_id}").json() == result.json()


def test_normal_production_factory_rejects_retired_catalog_even_with_an_active_gate(
    app_stack, database, postgres_harness, monkeypatch, tmp_path
):
    from itda.api import dependencies
    from itda.db.assessment_release import AssessmentReleaseRepository
    from itda.db.session import create_database_engine, create_session_factory
    from tests.integration.test_grounded_release_pairs import gate_fixture, report_fixtures

    client, _, profile, candidate, transport, registry = app_stack
    engine, _, _, _, _ = database
    catalog_file = tmp_path / "public-catalog.json"
    catalog_file.write_text(registry.catalog.model_dump_json())
    monkeypatch.setenv("ITDA_DATABASE_URL", engine.url.render_as_string(hide_password=False))
    monkeypatch.setenv("ITDA_PUBLIC_PLACE_CATALOG_PATH", str(catalog_file))
    monkeypatch.delenv("ITDA_GROUNDED_CANDIDATE_SHA256", raising=False)
    monkeypatch.delenv("ITDA_GROUNDED_RECOMMENDATIONS_ENABLED", raising=False)
    monkeypatch.setattr(dependencies, "_operating_information_service", lambda: None)
    monkeypatch.setattr(dependencies, "_source_grounding_service", lambda *args: None)
    monkeypatch.setattr(ProductionTourismRegistry, "from_catalog", lambda *args, **kwargs: registry)
    dependencies._recommendation_service_for_dsn.cache_clear()
    client.app.dependency_overrides.pop(get_recommendation_service)
    factory_service = None
    admin = create_database_engine(postgres_harness.dsns["admin"])
    try:
        # The candidate is already STAGED in database. An environment override
        # cannot bypass its measured promotion gate.
        monkeypatch.setenv("ITDA_GROUNDED_CANDIDATE_SHA256", candidate.candidate_sha256)
        with pytest.raises(ValueError, match="activate a measured"):
            dependencies.get_recommendation_service()
        monkeypatch.delenv("ITDA_GROUNDED_CANDIDATE_SHA256")
        before = client.post("/v1/recommendation-runs", json=payload(profile))
        assert before.status_code == 503, before.text
        store = AssessmentReleaseRepository(create_session_factory(admin))
        reports = report_fixtures(candidate)
        for report in reports:
            store.store_report(report)
        store.promote(gate_fixture(candidate, reports))
        # A valid historical promotion is readable history, not authority for
        # new national recommendations after the operational catalog is retired.
        after = client.post("/v1/recommendation-runs", json=payload(profile))
        assert after.status_code == 503, after.text
        assert store.load_active().candidate_sha256 == candidate.candidate_sha256
        assert transport.calls == []
    finally:
        admin.dispose()
        dependencies._recommendation_service_for_dsn.cache_clear()
        if factory_service is not None:
            factory_service.runs._factory.kw["bind"].dispose()
