"""Opt-in actual-candidate API/PG verification. No external API/model requests.

Set ITDA_GROUNDED_VERIFY_CANDIDATE to an explicitly selected immutable candidate.
The questionnaire is scripted; these checks do not constitute human relevance/UI tests.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
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
from itda.api.routes.photo import (
    CURRENT_PHOTO_CONSENT_NOTICE,
    PhotoLifecycleGateway,
    get_photo_lifecycle,
)
from itda.application.grounded_recommendations import GroundedRecommendationService
from itda.application.recommendations import RecommendationService
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.recommendation import QUALITY_RECOMMENDATION_CONFIG
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.grounded_run_repositories import GroundedRunRepository
from itda.db.photo_mood_repositories import PhotoMoodRepository
from itda.db.recommendation_repositories import RecommendationRunRepository
from itda.db.repositories import ProfileRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.db.source_snapshot_repositories import SourceSnapshotRepository
from itda.domain.canonical import canonical_sha256
from itda.tourism.registry import ProductionTourismRegistry
from itda.tourism.settings import TourismSettings
from PIL import Image
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles
from tests.integration.test_recommendation_runs import _migrate, _persist_profile

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def selected_candidate():
    configured = os.environ.get("ITDA_GROUNDED_VERIFY_CANDIDATE")
    if not configured:
        pytest.skip("explicit immutable candidate path is required for real-candidate verification")
    path = Path(configured).resolve()
    candidate = GroundedReleaseCandidate.model_validate_json(path.read_bytes())
    assert len(candidate.raw_release.profiles) == 100, (
        "real verification requires complete current PUBLIC100"
    )
    catalog_path = Path(
        os.environ.get(
            "ITDA_GROUNDED_VERIFY_CATALOG",
            str(ROOT / "fixtures/historical-gyeongju/catalog/public-place-catalog-v1.json"),
        )
    )
    catalog = PublicPlaceCatalog.model_validate_json(catalog_path.read_bytes())
    assert {p.place_id for p in candidate.raw_release.profiles} <= {
        p.place_id for p in catalog.places
    }
    return candidate, catalog


def test_actual_candidate_api_postgres_and_unknown_photo_baseline(
    selected_candidate, postgres_harness, tmp_path, monkeypatch
):
    started = datetime.now(UTC)
    candidate, catalog = selected_candidate
    _migrate(postgres_harness)
    photo_roles = ensure_photo_lifecycle_roles(postgres_harness)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    photo_dsn = make_conninfo(
        **(
            admin_info
            | {"user": photo_roles["service_role"], "password": photo_roles["service_password"]}
        )
    )
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    admin = create_database_engine(postgres_harness.dsns["admin"])
    photo_engine = create_database_engine(photo_dsn)
    factory = create_session_factory(runtime)
    pair_store = AssessmentReleaseRepository(create_session_factory(admin))
    assert pair_store.stage(candidate) == candidate.candidate_sha256
    assert pair_store.load_active() is None  # This is an isolated staged verifier, never promotion.
    profile = _persist_profile(
        runtime,
        "real-candidate-api-profile:" + uuid4().hex,
        condition_updates={
            "visit_date": (datetime.now(UTC).date() + timedelta(days=1)).isoformat()
        },
    )
    requests = []

    def forbidden(request):
        requests.append(str(request.url))
        raise AssertionError("real-candidate static verification must not make external requests")

    http = httpx.Client(transport=httpx.MockTransport(forbidden))
    registry = ProductionTourismRegistry.from_catalog(
        catalog, settings=TourismSettings(enabled=False), environ={}, http_client=http
    )
    profiles = ProfileRepository(factory)
    runs = GroundedRunRepository(factory)
    legacy = RecommendationService(
        profile_repository=profiles,
        recommendation_repository=RecommendationRunRepository(factory),
        release_resolver=lambda: candidate.raw_release,
        config=QUALITY_RECOMMENDATION_CONFIG,
        catalog=catalog,
        tourism_registry=registry,
    )
    facade = GroundedRecommendationService(
        legacy=legacy,
        profiles=profiles,
        runs=runs,
        sources=SourceSnapshotRepository(factory),
        candidate_resolver=lambda: candidate,
        registry=registry,
        mood_reader=PhotoMoodRepository(create_session_factory(photo_engine)),
        enabled=True,
    )
    quarantine = tmp_path / "photo-quarantine"
    quarantine.mkdir(mode=0o700)
    gateway = PhotoLifecycleGateway(
        factory=create_session_factory(photo_engine),
        service_dsn=photo_dsn,
        quarantine_root=quarantine,
        runtime_role=postgres_harness.role_names["runtime"],
        builder_role=postgres_harness.role_names["dev"],
        mood_enabled=True,
        synthetic_test_mode=True,
    )
    gateway.verify_service_authority()
    for name in ("ITDA_DATABASE_URL", "ITDA_PHOTO_SERVICE_DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    origin = "http://testserver"
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", origin)
    app = create_app()
    principal = ProfileSessionPrincipal(
        profile_id=profile.profile_id,
        session_digest="a" * 64,
        raw_reference="verifier-owned-session",
    )
    app.dependency_overrides[get_recommendation_service] = lambda: facade
    app.dependency_overrides[get_optional_profile_session] = lambda: principal
    app.dependency_overrides[get_photo_lifecycle] = lambda: gateway
    headers = {"Origin": origin, "Sec-Fetch-Site": "same-origin"}
    checks = []

    def check(name):
        checks.append({"case": name, "executed": 1, "failures": []})

    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            payload = {
                "request_id": "real-api:" + uuid4().hex,
                "preference_profile_id": profile.profile_id,
                "purpose": "SIGHTSEEING",
                "grounded_input": {"visit_date": profile.trip_conditions.visit_date.isoformat()},
            }
            created = client.post("/v1/recommendation-runs", json=payload, headers=headers)
            assert created.status_code == 201, created.text
            run_id = created.json()["recommendation_run_id"]
            results = client.get(f"/v1/recommendation-runs/{run_id}")
            assert results.status_code == 200, results.text
            body = results.json()
            run = body["run"]
            assert run["authority"]["candidate_sha256"] == candidate.candidate_sha256
            assert (
                body["release_disclosure"]["scoring_policy"] == "SUPPORTED_SUBORDINATE_AGGREGATION"
            )
            ids = [i["place_id"] for i in run["items"]]
            details = []
            for pid in ids[:3]:
                detail = client.get(f"/v1/recommendation-runs/{run_id}/places/{pid}")
                assert detail.status_code == 200, detail.text
                details.append(detail.json())
            comparison = client.get(
                f"/v1/recommendation-runs/{run_id}/comparison",
                params=[("place_id", pid) for pid in ids[:3]],
            )
            assert comparison.status_code == 200, comparison.text
            assert comparison.json()["places"] == details
            check("api_happy_detail_compare")
            saved = client.get(f"/v1/saved-place-references/{candidate.candidate_sha256}/{ids[0]}")
            assert saved.status_code == 200, saved.text
            assert (
                saved.json()["state"] == "CURRENT"
                and saved.json()["saved_release_sha256"] == candidate.candidate_sha256
            )
            check("api_saved_candidate_reference")
            context = client.get(f"/v1/recommendation-runs/{run_id}/tourism-context")
            assert context.status_code == 200, context.text
            assert len(context.json()["source_health"]) == 7
            assert all(
                s["state"] == "UNAVAILABLE" and s["http_attempt_count"] == 0
                for s in context.json()["source_health"]
            )
            assert context.json()["temporal"]["ranking_effect"] == "NONE"
            assert all(
                next(t for t in item["mismatch_traits"] if t["key"] == "M3")["value"] is None
                for item in run["items"]
            )
            check("api_unknown_and_disabled_sources")
            original_resolver = facade.candidate_resolver
            facade.candidate_resolver = lambda: (_ for _ in ()).throw(
                AssertionError("saved replay looked up current candidate")
            )
            assert (
                client.post("/v1/recommendation-runs", json=payload, headers=headers).json()
                == created.json()
            )
            assert client.get(f"/v1/recommendation-runs/{run_id}").json() == body
            facade.candidate_resolver = original_resolver
            check("api_saved_replay")

            # A real sanitized upload/SQL mood confirmation uses an explicit
            # synthetic all-UNKNOWN provider, not a paid or claimed real inference.
            photo_created = client.post(
                "/v1/photo-jobs",
                json={
                    "consent_version": CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
                    "consent_accepted": True,
                },
                headers=headers,
            )
            assert photo_created.status_code == 201, photo_created.text
            job = photo_created.json()["job_id"]
            picture = Image.new("RGB", (96, 96), (25, 95, 60))
            buffer = BytesIO()
            exif = Image.Exif()
            exif[0x010E] = "synthetic verifier private metadata"
            picture.save(buffer, format="JPEG", exif=exif)
            pixels = buffer.getvalue()

            async def chunks():
                yield pixels

            asyncio.run(
                gateway.store_image_stream(
                    job_id=job,
                    job_directory=job,
                    profile_id=profile.profile_id,
                    image_index=1,
                    chunks=chunks(),
                    declared_byte_length=len(pixels),
                    media_type="image/jpeg",
                )
            )
            gateway.submit_job(job_id=job, profile_id=profile.profile_id)
            review = client.get(f"/v1/photo-jobs/{job}/moods")
            assert review.status_code == 200, review.text
            confirmed = client.post(
                f"/v1/photo-jobs/{job}/moods/confirm",
                json={"draft_sha256": review.json()["draft_sha256"], "choices": []},
                headers=headers,
            )
            assert confirmed.status_code == 200, confirmed.text
            assert all(m["value"] is None for m in confirmed.json()["moods"])
            photo_request = payload | {
                "request_id": "real-photo-api:" + uuid4().hex,
                "photo_job_id": job,
            }
            photo_run_created = client.post(
                "/v1/recommendation-runs", json=photo_request, headers=headers
            )
            assert photo_run_created.status_code == 201, photo_run_created.text
            photo_run_id = photo_run_created.json()["recommendation_run_id"]
            photo_results = client.get(f"/v1/recommendation-runs/{photo_run_id}")
            assert photo_results.status_code == 200, photo_results.text
            photo_run = photo_results.json()["run"]
            assert [(i["place_id"], i["fit_score"]) for i in photo_run["items"]] == [
                (i["place_id"], i["fit_score"]) for i in run["items"]
            ]
            for key in ("axis_targets", "trait_targets", "condition_targets"):
                assert photo_run["preference"][key] == run["preference"][key]
            assert photo_run["authority"]["photo_input_sha256"] == confirmed.json()["receipt_id"]
            assert not (quarantine / job).exists()
            gateway.delete_job(job_id=job, profile_id=profile.profile_id)
            facade.mood_reader = None
            assert (
                client.post("/v1/recommendation-runs", json=photo_request, headers=headers).json()
                == photo_run_created.json()
            )
            assert (
                client.get(f"/v1/recommendation-runs/{photo_run_id}").json() == photo_results.json()
            )
            check("api_confirmed_unknown_photo_pg_and_deleted_replay")
            assert requests == []
            artifact = {
                "schema_version": "grounded-real-candidate-api-verification.v1",
                "scope": "API_POSTGRES_ONLY",
                "browser_executed": False,
                "candidate_sha256": candidate.candidate_sha256,
                "config_sha256": run["authority"]["config_sha256"],
                "started_at": started.isoformat(),
                "completed_at": datetime.now(UTC).isoformat(),
                "source_context_mode": "EXPLICITLY_DISABLED",
                "external_api_calls": 0,
                "paid_model_calls": 0,
                "profile_origin": "SCRIPTED_QUESTIONNAIRE_PERSISTED_BY_REAL_DOMAIN_SERVICE",
                "photo_mode": "SYNTHETIC_UNKNOWN_PROVIDER_WITH_REAL_PG_CONFIRMATION",
                "checks": checks,
                "executed_cases": len(checks),
                "failure_count": 0,
                "created": created.json(),
                "results": body,
                "details": details,
                "detail": details[0],
                "comparison": comparison.json(),
                "saved_reference": saved.json(),
                "tourism_context": context.json(),
                "photo": {
                    "created": photo_created.json(),
                    "review": review.json(),
                    "confirmation": confirmed.json(),
                    "run_created": photo_run_created.json(),
                    "results": photo_results.json(),
                },
            }
            artifact["artifact_sha256"] = canonical_sha256(artifact)
            destination = Path(
                os.environ.get(
                    "ITDA_GROUNDED_VERIFY_REPORT",
                    str(ROOT / "artifacts/reports/grounded-real-candidate-api-fixture.json"),
                )
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(artifact, ensure_ascii=False, indent=2))
            assert pair_store.load_active() is None
    finally:
        registry.close()
        http.close()
        runtime.dispose()
        admin.dispose()
        photo_engine.dispose()
