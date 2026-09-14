"""Opt-in live demand through normal API/PG reads, with no photo/model or promotion.

Only the demand source is configured for this verification. Other families are
explicitly unconfigured, not mocked and not evidence of present provider health.
The actual PUBLIC100 candidate is staged and a scripted v5 run is pinned through
the real domain/repository; this does not claim normal new-run creation.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from itda.api import dependencies
from itda.api.main import create_app
from itda.application.grounded_recommendations import GroundedRecommendationService
from itda.collectors.base import credential_material_present
from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.recommendation import RecommendationRequest
from itda.contracts.source_assessment import SourceService
from itda.contracts.tourism_context import TourismContextResponse
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.grounded_run_repositories import GroundedRunRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.domain.canonical import canonical_sha256
from itda.pipeline.offline_guard import require_live_collection_allowed
from tests.integration.test_grounded_recommendation_runs import insert, run
from tests.integration.test_recommendation_runs import _migrate, _persist_profile

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "artifacts/reports/grounded-demand-live-20260909"
pytestmark = pytest.mark.skipif(
    os.environ.get("ITDA_REGIONAL_DEMAND_LIVE_VERIFY") != "1",
    reason="explicit live demand verification opt-in required",
)


@pytest.fixture
def live_demand(monkeypatch):
    if os.environ.get("ITDA_REGIONAL_DEMAND_LIVE_VERIFY") != "1":
        pytest.skip("explicit live demand verification opt-in required")
    require_live_collection_allowed(explicit_opt_in=True)
    if (OUTPUT / "dispatch-attempt.json").exists():
        pytest.skip("the bounded live demand attempt is already recorded")
    credential = ""
    for line in (ROOT / ".secrets/itda-api-all.env").read_text().splitlines():
        key, separator, value = line.strip().removeprefix("export ").partition("=")
        if separator and key == "TOUR_API_SERVICE_KEY":
            credential = value.strip().strip("\"'")
    if not credential:
        pytest.fail("live demand credential is not configured")
    for name in tuple(os.environ):
        if name in {"TOUR_API_SERVICE_KEY", "ITDA_TOUR_API_SERVICE_KEY_FILE"} or (
            name.startswith("ITDA_TOURISM_") and "KEY" in name
        ):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ITDA_TOURISM_DEMAND_SERVICE_KEY", credential)
    monkeypatch.setenv("ITDA_TOURISM_DEMAND_MONTH", "202607")
    monkeypatch.setenv("ITDA_TOURISM_MAX_ATTEMPTS", "1")
    for name in (
        "ITDA_TOURISM_ENABLED",
        "ITDA_GROUNDED_RECOMMENDATIONS_ENABLED",
        "ITDA_GROUNDED_CANDIDATE_SHA256",
        "ITDA_PHOTO_SERVICE_DATABASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(logging.getLogger("httpx"), "level", logging.WARNING)
    monkeypatch.setattr(logging.getLogger("httpcore"), "level", logging.WARNING)
    return credential


def test_actual_aggregate_demand_serialization_and_unchanged_pinned_v5_run(
    live_demand, postgres_harness, monkeypatch
):
    started = datetime.now(UTC)
    candidate = GroundedReleaseCandidate.model_validate_json(
        (
            ROOT / "fixtures/historical-gyeongju/catalog/grounded-bootstrap/candidate.json"
        ).read_bytes()
    )
    assert candidate.candidate_sha256 == (
        "b84378d12a31c87107f55ed671dd09025ef8b841a8c7227995233662191a7ff5"
    )
    _migrate(postgres_harness)
    admin = create_database_engine(postgres_harness.dsns["admin"])
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    store = AssessmentReleaseRepository(create_session_factory(admin))
    store.stage(candidate)
    assert store.load_active_record() is None
    profile = _persist_profile(
        runtime,
        "scripted-demand-verifier:" + uuid4().hex,
        condition_updates={"visit_date": "2026-09-10"},
    )
    request = RecommendationRequest(
        request_id="demand-api-verifier:" + uuid4().hex,
        preference_profile_id=profile.profile_id,
        purpose="SIGHTSEEING",
        grounded_input=GroundedTripInput(visit_date=profile.trip_conditions.visit_date),
    )
    repo = GroundedRunRepository(create_session_factory(runtime))
    receipt = run(candidate, profile, request)
    insert(repo, candidate, profile, request, receipt)
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("ITDA_DATABASE_URL", postgres_harness.dsns["runtime"])
    dependencies._recommendation_service_for_dsn.cache_clear()
    service = dependencies.get_recommendation_service()
    assert isinstance(service, GroundedRecommendationService) and service.enabled
    assert service.mood_reader is None
    assert service.registry.clients[SourceService.DEMAND] is not None
    assert all(
        client is None
        for source, client in service.registry.clients.items()
        if source != SourceService.DEMAND
    )
    application = create_app()
    client = TestClient(application, raise_server_exceptions=False)
    report = {
        "schema_version": "grounded-demand-live-api-verification.v1",
        "fixture_kind": "REAL_PUBLIC100_PG_PIN_AND_TWO_LIVE_DEMAND_OPERATIONS",
        "scope": "API_POSTGRES_ONLY",
        "source_context_mode": "LIVE_DEMAND_ONLY_OTHER_SOURCES_UNCONFIGURED_FOR_VERIFICATION",
        "run_setup": "DIRECT_DOMAIN_AND_PIN_REPOSITORY_WITH_STAGE_ONLY_CANDIDATE",
        "normal_api_factory": True,
        "normal_new_run_creation_verified": False,
        "active_promotion_performed": False,
        "session_authentication_verified": False,
        "model_calls": 0,
        "browser_executed": False,
        "candidate_sha256": candidate.candidate_sha256,
        "started_at": started.isoformat(),
        "outcome": "INCOMPLETE",
    }
    try:
        path = f"/v1/recommendation-runs/{receipt.run_id}"
        before = client.get(path)
        assert before.status_code == 200
        report["results"] = before.json()
        places = [item.place_id for item in receipt.items[:2]]
        details = []
        for place in places:
            response = client.get(path + "/places/" + place)
            assert response.status_code == 200
            details.append(response.json())
        comparison = client.get(path + "/comparison", params=[("place_id", p) for p in places])
        assert comparison.status_code == 200
        assert comparison.json()["places"] == details
        report["details"] = details
        report["detail"] = details[0]
        report["comparison"] = comparison.json()
        saved = client.get(f"/v1/saved-place-references/{candidate.candidate_sha256}/{places[0]}")
        assert saved.status_code == 200
        assert saved.json()["place_id"] == places[0]
        assert saved.json()["state"] == "STALE"  # Staged fixture is deliberately not ACTIVE.
        report["saved_reference"] = saved.json()
        OUTPUT.mkdir(parents=True, exist_ok=True)
        with (OUTPUT / "dispatch-attempt.json").open("x") as marker:
            json.dump(
                {"started_at": datetime.now(UTC).isoformat(), "maximum_http_calls": 2}, marker
            )
        context_response = client.get(path + "/tourism-context")
        report["tourism_context"] = context_response.json()
        assert context_response.status_code == 200
        assert context_response.headers["cache-control"] == "no-store"
        context = TourismContextResponse.model_validate(context_response.json())
        demand = context_response.json()["temporal"]["demand"]
        assert [row["state"] for row in demand] == ["AVAILABLE", "AVAILABLE"]
        assert [row["reason"] for row in demand] == ["NONE", "NONE"]
        assert [row["measures"][0]["value"] for row in demand] == ["102.99", "77.92"]
        assert [row["measures"][0]["raw_value"] for row in demand] == ["102.99", "77.92"]
        assert [row["measures"][0]["indicator_code"] for row in demand] == ["21", "22"]
        assert all(row["measures"][0]["unit"] == "TOURISM_DEMAND_INDEX" for row in demand)
        assert context.temporal.ranking_effect == "NONE"
        events = service.registry._http.events
        assert len(events) == 2 and all(row["service"] == "AreaTarDemDsService" for row in events)
        by_operation = {event["operation"]: event for event in events}
        assert by_operation["areaTarSjrnDsList"]["request_scope"]["tarSjrnDsIxCd"] == "21"
        assert by_operation["areaTarExpDsList"]["request_scope"]["tarExpDsIxCd"] == "22"
        assert all(event["http_status"] == 200 for event in events)
        assert all(
            row.http_attempt_count == 0
            for row in context.source_health
            if row.service != SourceService.DEMAND
        )
        refreshed = client.get(path + "/tourism-context")
        assert refreshed.status_code == 200
        assert refreshed.json()["temporal"]["demand"] == demand
        assert len(events) == 2  # The second local API read uses the normal source cache.
        after = client.get(path)
        assert after.status_code == 200 and after.content == before.content
        assert repo.load_pinned(receipt.run_id).run == receipt
        assert store.load_active_record() is None
        report["checks"] = [
            "actual_GET_serializes_exact_aggregate_decimal_indices",
            "two_live_demand_operations_use_explicit_21_and_22_parameters",
            "normal_context_cache_avoids_additional_live_requests_on_refresh",
            "pinned_v5_results_core_and_order_byte_identical_after_refresh",
            "actual_detail_comparison_and_stale_saved_reference_captured",
            "no_model_photo_or_active_promotion",
        ]
        report["http_attempts"] = [
            {
                key: event[key]
                for key in (
                    "service",
                    "operation",
                    "request_scope",
                    "http_status",
                    "response_sha256",
                    "latency_ms",
                )
            }
            for event in events
        ]
        report["external_http_calls"] = len(events)
        report["outcome"] = "PASS"
    except Exception:
        report["outcome"] = "FAIL"
        raise
    finally:
        report["completed_at"] = datetime.now(UTC).isoformat()
        report["artifact_sha256"] = canonical_sha256(report)
        encoded = json.dumps(report, ensure_ascii=False, indent=2).encode()
        assert not any(
            credential_material_present(encoded, value)
            for value in (live_demand, unquote(live_demand))
        ), "credential material cannot enter the public API fixture"
        OUTPUT.mkdir(parents=True, exist_ok=True)
        (OUTPUT / "api-fixture.json").write_bytes(encoded)
        client.close()
        service.registry.close()
        dependencies._recommendation_service_for_dsn.cache_clear()
        runtime.dispose()
        admin.dispose()
