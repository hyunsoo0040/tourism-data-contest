"""API + PostgreSQL happy path, identity boundaries and private photo confirmation."""

from datetime import UTC, datetime

from alembic import command
from fastapi.testclient import TestClient

from itda.api.main import create_app
from itda.api.routes.authenticity import get_service, provider
from itda.authenticity.intent import QUESTIONNAIRE_SHA256
from itda.authenticity.release import build_release
from itda.authenticity.repository import Repository, install_release
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.service import Service
from itda.db.session import create_database_engine
from tests.authenticity.test_intent_and_ranking import assessment
from tests.authenticity.test_private_photo import TestMoodProvider, photo_bytes
from tests.integration.test_daily_glm_refresh_migration import _config


def test_complete_api_journey_and_private_photos(postgres_harness, tmp_path, monkeypatch):
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", "http://testserver")
    monkeypatch.setenv("ITDA_E2E_ALLOW_INSECURE_COOKIE", "1")
    command.upgrade(_config(postgres_harness), "head")
    admin = create_database_engine(postgres_harness.dsns["admin"])
    runtime = create_database_engine(postgres_harness.dsns["runtime"])
    repository = Repository(runtime)
    try:
        rows = tuple(assessment(i) for i in range(1, 7))
        directory = tmp_path / "release"
        build_release(
            assessments=rows,
            directory=directory,
            expected_ids=tuple(a.source.place.place_id for a in rows),
            parent_manifest_sha256="a" * 64,
            scope="DEVELOPMENT",
            created_at=datetime.now(UTC),
        )
        install_release(admin, directory, expected_previous=None, activate=True)
        service = Service(repository, allow_development=True, photo_enabled=True)
        app = create_app()
        app.dependency_overrides[get_service] = lambda: service
        app.dependency_overrides[provider] = lambda: TestMoodProvider()
        with TestClient(app) as client:
            base = "/v1/authenticity"
            headers = {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}
            definition = client.get(base + "/definition")
            assert definition.status_code == 200
            assert len(definition.json()["questions"]) == 12
            assert client.post(base + "/sessions").status_code == 403
            session = client.post(base + "/sessions", headers=headers).json()
            headers["Authorization"] = "Bearer " + session["token"]
            body = {
                "request_id": "api-profile",
                "questionnaire_sha256": QUESTIONNAIRE_SHA256,
                "answers": {k: 4 if k == "H.a" else 0 for k in FACET_KEYS},
            }
            response = client.post(base + "/profiles", json=body, headers=headers)
            assert response.status_code == 200, response.text
            profile = response.json()
            run = client.post(
                base + "/runs",
                json={"profile_id": profile["profile_id"], "request_id": "api-run"},
                headers=headers,
            )
            assert run.status_code == 200, run.text
            r = run.json()
            assert r["result_count"] == 5
            assert client.get(base + "/runs/" + r["run_sha256"], headers=headers).json() == r
            pid = r["items"][0]["place_id"]
            path = base + "/runs/" + r["run_sha256"]
            detail = client.get(path + "/places/" + pid, headers=headers)
            assert detail.status_code == 200, detail.text
            assert detail.json()["evidence"]
            comparison = client.get(
                path + "/compare",
                params={"place_ids": ",".join(p["place_id"] for p in r["items"][:2])},
                headers=headers,
            )
            assert len(comparison.json()["places"]) == 2
            assert (
                client.put(
                    path + "/places/" + pid + "/saved", json={"saved": True}, headers=headers
                ).status_code
                == 200
            )
            assert len(client.get(base + "/saved", headers=headers).json()) == 1
            feedback = client.post(
                path + "/places/" + pid + "/feedback",
                json={
                    "request_id": "test-feedback",
                    "visited": False,
                    "note": "기술 검증용 합성 응답",
                },
                headers=headers,
            )
            assert feedback.status_code == 200 and feedback.json()["research_use"] is False
            uploaded = client.post(
                base + "/photos",
                files=[("files", ("test.jpg", bytes(photo_bytes()), "image/jpeg"))],
                headers=headers,
            )
            assert uploaded.status_code == 200, uploaded.text
            photo = uploaded.json()
            assert photo["original_retained"] is False
            cid = photo["batches"][0]["candidates"][0]["candidate_id"]
            confirmed = client.post(
                base + "/photos/" + photo["photo_id"] + "/confirm",
                json={"candidate_ids": [cid]},
                headers=headers,
            )
            assert confirmed.status_code == 200, confirmed.text
            assert confirmed.json()["receipt_sha256"]
            deleted = client.delete(base + "/photos/" + photo["photo_id"], headers=headers)
            assert deleted.json()["state"] == "DELETED" and deleted.json()["batches"] == []
            # A new anonymous session cannot read another session's run.
            other = client.post(base + "/sessions", headers={"Origin": "http://testserver"}).json()
            assert (
                client.get(path, headers={"Authorization": "Bearer " + other["token"]}).status_code
                == 404
            )
            assert client.delete(base + "/session", headers=headers).status_code == 200
            assert client.get(path, headers=headers).status_code == 401
    finally:
        runtime.dispose()
        admin.dispose()
