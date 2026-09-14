"""Historical Gyeongju live API/PG verification; not the current national release.

Requires ITDA_GROUNDED_PRODUCTION_LIVE_VERIFY=1 and honors every offline guard.
One licensed cached public image is submitted once; no provider is mocked.
Authentication alone uses an explicitly synthetic principal in an isolated DB.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from itda.api import dependencies
from itda.api.dependencies import ProfileSessionPrincipal, get_optional_profile_session
from itda.api.main import create_app
from itda.api.routes import photo as photo_routes
from itda.application.grounded_context import build_candidates
from itda.application.grounded_recommendations import GroundedRecommendationService
from itda.cli.initialize_grounded_release import ensure_initial_grounded_release
from itda.collectors.base import credential_material_present
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.tourism_context import TourismContextResponse
from itda.db.session import create_database_engine
from itda.domain.canonical import canonical_sha256
from itda.photo.provider.mood import GlmMoodProvider
from itda.pipeline.offline_guard import require_live_collection_allowed
from tests.integration.profile_release_test_support import ensure_photo_lifecycle_roles
from tests.integration.test_recommendation_runs import _migrate, _persist_profile

ROOT = Path(__file__).resolve().parents[3]
REPORT_DIRECTORY = ROOT / "artifacts/reports/grounded-production-live-20260909"
BUNDLE = ROOT / "fixtures/historical-gyeongju/catalog/grounded-bootstrap"
KEY_NAMES = ("TOUR_API_SERVICE_KEY", "ODII_SERVICE_KEY", "ZHIPUAI_API_KEY")


@pytest.fixture
def live_inputs(monkeypatch):
    if os.environ.get("ITDA_GROUNDED_PRODUCTION_LIVE_VERIFY") != "1":
        pytest.skip("explicit live production verification opt-in required")
    require_live_collection_allowed(explicit_opt_in=True)
    if (REPORT_DIRECTORY / "photo-attempt.json").exists():
        pytest.skip("one live photo attempt already recorded; inspect the saved report")
    assert (BUNDLE / "candidate.json").is_file(), "validated production bundle is required"
    candidate = GroundedReleaseCandidate.model_validate_json(
        (BUNDLE / "candidate.json").read_bytes()
    )
    assert candidate.candidate_sha256 == (
        "b84378d12a31c87107f55ed671dd09025ef8b841a8c7227995233662191a7ff5"
    )
    secrets_file = ROOT / ".secrets/itda-api-all.env"
    secrets = {}
    for line in secrets_file.read_text().splitlines():
        name, separator, value = line.strip().removeprefix("export ").partition("=")
        if separator and name in KEY_NAMES:
            secrets[name] = value.strip().strip("\"'")
    if any(not secrets.get(name) for name in KEY_NAMES):
        pytest.fail("required live credentials are not configured")
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)
    for name in (
        "ITDA_GROUNDED_CANDIDATE_SHA256",
        "ITDA_GROUNDED_RECOMMENDATIONS_ENABLED",
        "ITDA_PHOTO_MOOD_ENABLED",
        "ITDA_PHOTO_VLM_ENABLED",
        "ITDA_TOURISM_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)
    # Suppress transport URL logging; provider receipts already redact credentials.
    monkeypatch.setattr(logging.getLogger("httpx"), "level", logging.WARNING)
    monkeypatch.setattr(logging.getLogger("httpcore"), "level", logging.WARNING)
    for source in candidate.source_snapshots:
        for asset in source["images"]:
            if (
                asset.get("license") == "KOGL_TYPE_1"
                and asset.get("match", {}).get("state") == "MATCHED"
                and asset.get("download_status") == "DOWNLOADED"
            ):
                path = (
                    ROOT / "fixtures/historical-gyeongju/catalog/photos" / asset["original_sha256"]
                )
                if path.is_file():
                    pixels = path.read_bytes()
                    if hashlib.sha256(pixels).hexdigest() == asset["original_sha256"]:
                        return (
                            candidate,
                            pixels,
                            {
                                "asset_id": asset["asset_id"],
                                "license": asset["license"],
                                "attribution_ko": asset["attribution_ko"],
                                "source_url": asset["url"],
                                "original_sha256": asset["original_sha256"],
                            },
                            tuple(secrets.values()),
                        )
    pytest.fail("no licensed cached tourism image was found")


def _checked(response, expected):
    assert response.status_code == expected, "public API response status differed"
    return response.json()


def _save_report(report, secrets):
    report["completed_at"] = datetime.now(UTC).isoformat()
    report["artifact_sha256"] = canonical_sha256(report)
    encoded = json.dumps(report, ensure_ascii=False, indent=2).encode()
    if any(credential_material_present(encoded, value) for value in secrets):
        pytest.fail("credential material rejected before writing verification report")
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    (REPORT_DIRECTORY / "verification.json").write_bytes(encoded)


def test_normal_production_seed_sources_and_live_photo_then_deleted_replay(
    live_inputs, postgres_harness, tmp_path, monkeypatch
):
    candidate, pixels, image_origin, secrets = live_inputs
    started = datetime.now(UTC)
    _migrate(postgres_harness)
    roles = ensure_photo_lifecycle_roles(postgres_harness)
    admin_info = conninfo_to_dict(postgres_harness.dsns["admin"])
    photo_dsn = make_conninfo(
        **(admin_info | {"user": roles["service_role"], "password": roles["service_password"]})
    )
    monkeypatch.chdir(ROOT)
    initialized = ensure_initial_grounded_release({}, admin_dsn=postgres_harness.dsns["admin"])
    assert (
        initialized.state == "initialized"
        and initialized.candidate_sha256 == candidate.candidate_sha256
    )
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir(mode=0o700)
    for name, value in {
        "ITDA_DATABASE_URL": postgres_harness.dsns["runtime"],
        "ITDA_PHOTO_SERVICE_DATABASE_URL": photo_dsn,
        "ITDA_PHOTO_QUARANTINE_ROOT": str(quarantine),
        "ITDA_RUNTIME_ROLE": postgres_harness.role_names["runtime"],
        "ITDA_LABEL_BUILDER_ROLE": postgres_harness.role_names["dev"],
        "ITDA_CANONICAL_APP_ORIGIN": "http://testserver",
    }.items():
        monkeypatch.setenv(name, value)
    assert int(os.environ.get("ITDA_MODEL_SESSION_LIMIT", "40")) <= 40
    dependencies._recommendation_service_for_dsn.cache_clear()
    photo_routes._lifecycle_for.cache_clear()
    engine = create_database_engine(postgres_harness.dsns["runtime"])
    profile = _persist_profile(
        engine,
        "live-scripted-profile:" + uuid4().hex,
        condition_updates={
            "visit_date": (datetime.now(UTC).date() + timedelta(days=1)).isoformat()
        },
    )
    principal = ProfileSessionPrincipal(
        profile_id=profile.profile_id,
        session_digest="a" * 64,
        raw_reference="explicitly-synthetic-live-verification-principal",
    )
    app = create_app()
    app.dependency_overrides[get_optional_profile_session] = lambda: principal
    # The raw-stream route calls this auth helper directly rather than through DI.
    monkeypatch.setattr(photo_routes, "get_optional_profile_session", lambda *_a: principal)
    client = TestClient(app, raise_server_exceptions=False)
    service = dependencies.get_recommendation_service()
    gateway = photo_routes.get_photo_lifecycle()
    assert isinstance(service, GroundedRecommendationService) and service.enabled
    assert isinstance(gateway._mood_provider, GlmMoodProvider)
    assert gateway._mood_provider._transport is None and gateway._mood_provider._audit_sink is None
    assert gateway._provider is None and not gateway._synthetic_test_mode
    assert service.registry.settings.enabled and service.registry.settings.model == "glm-5.3-flash"
    headers = {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}
    checks = []
    report = {
        "schema_version": "grounded-production-live-verification.v1",
        "scope": "REAL_API_AND_POSTGRES_WITH_SYNTHETIC_AUTH_PRINCIPAL",
        "browser_executed": False,
        "session_authentication_verified": False,
        "normal_production_factories": True,
        "default_flags_used": True,
        "candidate_sha256": candidate.candidate_sha256,
        "gate_sha256": initialized.gate_sha256,
        "initial_gate_provenance": "PREVIOUSLY_MEASURED_PAIR_CURRENT_CODE_UNDER_VERIFICATION",
        "current_openapi_sha256": canonical_sha256(app.openapi()),
        "started_at": started.isoformat(),
        "checks": checks,
        "paid_model_calls": 0,
        "model_dispatch_attempts": 0,
        "image_origin": image_origin,
        "outcome": "INCOMPLETE",
    }
    job = None
    try:
        request = {
            "request_id": "live-default-api:" + uuid4().hex,
            "preference_profile_id": profile.profile_id,
            "purpose": "SIGHTSEEING",
            "grounded_input": {"visit_date": profile.trip_conditions.visit_date.isoformat()},
        }
        created = _checked(
            client.post("/v1/recommendation-runs", json=request, headers=headers), 201
        )
        run_id = created["recommendation_run_id"]
        baseline = _checked(client.get(f"/v1/recommendation-runs/{run_id}"), 200)
        assert baseline["run"]["authority"]["candidate_sha256"] == candidate.candidate_sha256
        checks.append("default_factory_v5_from_initialized_measured_active_pair")
        report["baseline"] = baseline
        pinned = service.runs.load_pinned(run_id)
        # The normal endpoint asks for five places. Call its actual production
        # registry once with three authorized places to obey this live-call budget.
        prior_stage = REPORT_DIRECTORY / "source-context-stage.json"
        if prior_stage.exists():
            # Resume after a local assertion repair without repeating external
            # source calls. Preserve the original run identity and provenance.
            prior = json.loads(prior_stage.read_text())
            assert prior["artifact_sha256"] == canonical_sha256(
                {key: value for key, value in prior.items() if key != "artifact_sha256"}
            )
            assert prior["candidate_sha256"] == candidate.candidate_sha256
            assert prior["source_context_calls"] == 1 and prior["model_dispatch_attempts"] == 0
            context = TourismContextResponse.model_validate(prior["tourism_context"])
            report["source_context_origin"] = "EARLIER_LIVE_STAGE_PRESERVED_WITHOUT_REQUERY"
            report["source_context_stage_sha256"] = prior["artifact_sha256"]
            report["source_http_attempts"] = prior["source_http_attempts"]
        else:
            context = service.registry.context(
                run_id=run_id,
                place_ids=tuple(item.place_id for item in pinned.run.items[:3]),
                trip_input=pinned.run.preference.trip_input,
                eligible_place_ids=pinned.run.eligible_place_ids,
                purpose=pinned.run.preference.purpose,
                selected_place_ids=tuple(item.place_id for item in pinned.run.items),
                cannot_coappear_pairs=candidate.raw_release.relation_pairs,
            )
            report["source_context_origin"] = "LIVE_CURRENT_STAGE"
            report["source_http_attempts"] = len(service.registry._http.events)
        assert len(context.source_health) == 7 and len(context.places) == 3
        assert all(row.http_attempt_count > 0 for row in context.source_health)
        assert context.temporal.ranking_effect == "NONE"
        report["tourism_context"] = context.model_dump(mode="json")
        report["source_context_calls"] = 1
        checks.append("seven_actual_source_families_over_three_places_with_truthful_health")

        photo_created = _checked(
            client.post(
                "/v1/photo-jobs",
                json={
                    "consent_version": photo_routes.CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
                    "consent_accepted": True,
                },
                headers=headers,
            ),
            201,
        )
        assert photo_created["analysis_family"] == "photo-mood-v1"
        job = photo_created["job_id"]
        media_type = "image/png" if pixels.startswith(b"\x89PNG") else "image/jpeg"
        _checked(
            client.put(
                f"/v1/photo-jobs/{job}/images/1",
                content=pixels,
                headers=headers | {"Content-Type": media_type},
            ),
            200,
        )
        REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
        with (REPORT_DIRECTORY / "photo-attempt.json").open("x") as marker:
            json.dump(
                {"started_at": datetime.now(UTC).isoformat(), "model": "glm-5.3-flash"}, marker
            )
        report["model_dispatch_attempts"] = 1
        _checked(client.post(f"/v1/photo-jobs/{job}/submit", headers=headers), 200)
        report["paid_model_calls"] = 1
        state = _checked(client.get(f"/v1/photo-jobs/{job}"), 200)
        assert state["state"] == "succeeded" and state["cleanup_pending"] is False
        review = _checked(client.get(f"/v1/photo-jobs/{job}/moods"), 200)
        assert len(review["batches"]) == 1
        batch = review["batches"][0]
        assert batch["model"] == "glm-5.3-flash" and batch["analysis_kind"] == "MODEL"
        choices = [
            {"candidate_id": row["candidate_id"], "included": True}
            for row in batch["candidates"]
            if row["observation"]["state"] == "OBSERVED"
        ]
        confirmed = _checked(
            client.post(
                f"/v1/photo-jobs/{job}/moods/confirm",
                json={"draft_sha256": review["draft_sha256"], "choices": choices},
                headers=headers,
            ),
            200,
        )
        assert not (quarantine / job).exists()
        report["photo"] = {
            "created": photo_created,
            "state": state,
            "review": review,
            "confirmed": confirmed,
        }
        checks.append("one_actual_glm53_photo_mood_upload_review_confirmation_and_cleanup")
        photo_request = request | {
            "request_id": "live-photo-api:" + uuid4().hex,
            "photo_job_id": job,
        }
        photo_created_run = _checked(
            client.post("/v1/recommendation-runs", json=photo_request, headers=headers), 201
        )
        photo_run_id = photo_created_run["recommendation_run_id"]
        photo_results = _checked(client.get(f"/v1/recommendation-runs/{photo_run_id}"), 200)
        photo_pinned = service.runs.load_pinned(photo_run_id)
        for key in ("axis_targets", "trait_targets", "condition_targets", "important_traits"):
            assert getattr(photo_pinned.run.preference, key) == getattr(pinned.run.preference, key)
        assert photo_pinned.run.authority.photo_input_sha256 == confirmed["receipt_id"]
        before_candidates = build_candidates(candidate, (), pinned.run.preference, profile)
        after_candidates = build_candidates(candidate, (), photo_pinned.run.preference, profile)
        for before, after in zip(before_candidates, after_candidates, strict=True):
            for key in ("profile", "assessment", "conditions", "contextual_facts"):
                assert getattr(before, key) == getattr(after, key)
        assert all(item.contribution.mood_weight <= 1500 for item in photo_pinned.run.items)
        report["photo_results"] = photo_results
        report["core_comparison_places"] = len(before_candidates)
        checks.append(
            "photo_only_changes_visual_mood_input_not_H_E_R_M_or_operating_facility_truth"
        )
        _checked(client.delete(f"/v1/photo-jobs/{job}", headers=headers), 200)
        deleted = _checked(client.get(f"/v1/photo-jobs/{job}"), 200)
        assert deleted["state"] == "deleted" and deleted["cleanup_pending"] is False
        assert not (quarantine / job).exists()
        attempts = len(service.registry._http.events)
        replay_created = _checked(
            client.post("/v1/recommendation-runs", json=photo_request, headers=headers), 201
        )
        assert replay_created == photo_created_run
        assert _checked(client.get(f"/v1/recommendation-runs/{photo_run_id}"), 200) == photo_results
        assert len(service.registry._http.events) == attempts
        report["photo_deleted"] = deleted
        checks.append("deleted_photo_retains_identical_pinned_replay_without_external_source_calls")
        report["outcome"] = "PASS"
    except Exception:
        report["outcome"] = "FAIL"
        raise
    finally:
        if job is not None:
            try:
                gateway.delete_job(job_id=job, profile_id=profile.profile_id)
            except Exception:
                report["cleanup_retry"] = "FAILED"
        _save_report(report, (*secrets, *(unquote(value) for value in secrets)))
        client.close()
        service.registry.close()
        engine.dispose()
        dependencies._recommendation_service_for_dsn.cache_clear()
        photo_routes._lifecycle_for.cache_clear()
