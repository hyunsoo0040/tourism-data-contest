"""Production photo factory configuration without a database or paid requests."""

import json
import os

import httpx
import pytest

from itda.api.routes import photo as route
from itda.contracts.visual_mood import VisualMoodDimension
from itda.photo.provider.live import PhotoLiveAnalysisUnavailable
from itda.photo.provider.mood import GlmMoodProvider
from itda.photo.provider.vlm import SemanticVlmPhotoAnalysisProvider

KEY_NAMES = (
    "ITDA_PHOTO_MOOD_ENABLED",
    "ITDA_PHOTO_VLM_ENABLED",
    "ITDA_PHOTO_VLM_API_KEY",
    "ITDA_PHOTO_VLM_API_KEY_FILE",
    "ZHIPUAI_API_KEY",
    "ITDA_ZHIPUAI_API_KEY_FILE",
    "ITDA_PHOTO_VLM_ENDPOINT",
    "ITDA_PHOTO_VLM_MODEL",
)


@pytest.fixture(autouse=True)
def isolated_factory(monkeypatch, tmp_path):
    for name in KEY_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ITDA_MODEL_SESSION_LOCK_DIR", str(tmp_path / "model-sessions"))
    monkeypatch.setattr(route, "create_database_engine", lambda _dsn: object())
    monkeypatch.setattr(route, "create_session_factory", lambda _engine: None)
    monkeypatch.setattr(route.PhotoLifecycleGateway, "verify_service_authority", lambda _self: None)
    route._lifecycle_for.cache_clear()
    yield
    route._lifecycle_for.cache_clear()


def factory(tmp_path):
    return route._lifecycle_for("mock-photo-dsn", str(tmp_path), "runtime", "builder")


@pytest.mark.parametrize("mood_flag", [None, "1"])
def test_mood_factory_reads_deployment_key_file_and_sends_only_53_pixels(
    monkeypatch, tmp_path, capsys, mood_flag
):
    key_file = tmp_path / "key"
    key_file.write_text("mock-secret-from-file\n")
    if mood_flag is not None:
        monkeypatch.setenv("ITDA_PHOTO_MOOD_ENABLED", mood_flag)
    monkeypatch.setenv("ITDA_ZHIPUAI_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("ZHIPUAI_API_KEY", "ignored-direct-key")
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer mock-secret-from-file"
        body = json.loads(request.content)
        assert str(request.url) == "https://api.z.ai/api/coding/paas/v4/chat/completions"
        assert body["model"] == "glm-5.3-flash"
        assert body["messages"][1]["content"][0]["type"] == "image_url"
        assert "mock-secret" not in request.content.decode()
        wire = {
            "observations": [
                {"dimension": d.value, "state": "UNKNOWN", "level": None, "certainty": "LOW"}
                for d in VisualMoodDimension
            ]
        }
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(wire)},
                    }
                ],
            },
        )

    monkeypatch.setattr(
        route,
        "GlmMoodProvider",
        lambda **kwargs: GlmMoodProvider(
            **kwargs,
            transport=httpx.MockTransport(handler),
        ),
    )
    gateway = factory(tmp_path)
    assert gateway._mood_enabled and gateway._provider is None
    assert requests == []
    batch = gateway._mood_provider.analyze(
        image_png=b"\x89PNG\r\n\x1a\nmock-sanitized",
        job_id="a" * 64,
        image_index=1,
    )
    assert batch.family == "photo-mood-v1" and batch.model == "glm-5.3-flash"
    assert len(requests) == 1
    assert "mock-secret" not in str(capsys.readouterr())


@pytest.mark.parametrize("mood_flag", [None, "0", "1"])
@pytest.mark.parametrize("legacy_flag", ["0", "1"])
@pytest.mark.parametrize("configured_key", [False, True])
def test_every_production_configuration_creates_only_mood_jobs(
    monkeypatch, tmp_path, mood_flag, legacy_flag, configured_key
):
    if mood_flag is not None:
        monkeypatch.setenv("ITDA_PHOTO_MOOD_ENABLED", mood_flag)
    monkeypatch.setenv("ITDA_PHOTO_VLM_ENABLED", legacy_flag)
    monkeypatch.setenv("ITDA_PHOTO_VLM_ENDPOINT", "https://example.invalid/legacy")
    monkeypatch.setenv("ITDA_PHOTO_VLM_MODEL", "glm-4.6v")
    if configured_key:
        monkeypatch.setenv("ZHIPUAI_API_KEY", "mock-secret")
    monkeypatch.setattr(
        SemanticVlmPhotoAnalysisProvider,
        "__init__",
        lambda *_a, **_k: pytest.fail("legacy provider constructed"),
    )
    monkeypatch.setattr(
        SemanticVlmPhotoAnalysisProvider,
        "analyze",
        lambda *_a, **_k: pytest.fail("legacy provider called"),
    )
    gateway = factory(tmp_path)
    assert gateway._provider is None
    assert (gateway._mood_provider is not None) == (configured_key and mood_flag != "0")
    monkeypatch.setattr(gateway._mood_store, "create_job", lambda **_kwargs: "a" * 64)
    monkeypatch.setattr(
        gateway._job_service, "create_job", lambda **_kwargs: pytest.fail("legacy job created")
    )
    created = gateway.create_job(
        profile_id="profile:test",
        consent_version=route.CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
        consent_accepted=True,
    )
    assert created["analysis_family"] == "photo-mood-v1"
    monkeypatch.setattr(gateway._mood_store, "family", lambda **_kwargs: "photo-mood-v1")
    if gateway._mood_provider is None:
        with pytest.raises(PhotoLiveAnalysisUnavailable):
            gateway._analyze_stored_images(job_id="a" * 64, profile_id="profile:test")


def test_pending_legacy_job_cannot_invoke_either_provider_in_production(monkeypatch, tmp_path):
    gateway = factory(tmp_path)

    class ForbiddenProvider:
        def analyze(self, **_kwargs):
            pytest.fail("historical job dispatched new inference")

    gateway._provider = ForbiddenProvider()
    gateway._mood_provider = ForbiddenProvider()
    monkeypatch.setattr(gateway._mood_store, "family", lambda **_kwargs: None)
    monkeypatch.setattr(
        route.psycopg, "connect", lambda *_a, **_kw: pytest.fail("read pixels for legacy job")
    )
    with pytest.raises(PhotoLiveAnalysisUnavailable):
        gateway._analyze_stored_images(job_id="a" * 64, profile_id="profile:test")


def test_production_gateway_preserves_completed_historical_trait_reads(monkeypatch, tmp_path):
    gateway = factory(tmp_path)
    candidates, confirmed = [object()], [object()]
    monkeypatch.setattr(gateway._mood_store, "family", lambda **_kwargs: None)
    monkeypatch.setattr(gateway, "_read_owned", lambda **_kwargs: {"state": "succeeded"})
    monkeypatch.setattr(gateway._candidate_store, "list_for_job", lambda *_args: candidates)
    monkeypatch.setattr(gateway._confirmed_store, "list_for_job", lambda *_args: confirmed)
    assert gateway.read_traits(job_id="a" * 64, profile_id="profile:test") == {
        "state": "succeeded",
        "candidates": candidates,
        "confirmed": confirmed,
    }


@pytest.mark.parametrize(
    "problem", ["missing", "empty", "oversized", "binary", "multiline", "directory", "fifo"]
)
def test_invalid_file_keeps_mood_family_unavailable_without_legacy_fallback(
    monkeypatch, tmp_path, problem
):
    path = tmp_path / "configured-key"
    if problem == "empty":
        path.write_text(" \n")
    elif problem == "oversized":
        path.write_bytes(b"x" * 4099)
    elif problem == "binary":
        path.write_bytes(b"\xff")
    elif problem == "multiline":
        path.write_text("key\nsecond-record")
    elif problem == "directory":
        path.mkdir()
    elif problem == "fifo":
        os.mkfifo(path)
    monkeypatch.setenv("ITDA_PHOTO_MOOD_ENABLED", "1")
    monkeypatch.setenv("ITDA_PHOTO_VLM_ENABLED", "1")
    monkeypatch.setenv("ITDA_ZHIPUAI_API_KEY_FILE", str(path))
    monkeypatch.setenv("ZHIPUAI_API_KEY", "must-not-fall-back")
    monkeypatch.setattr(
        SemanticVlmPhotoAnalysisProvider,
        "__init__",
        lambda *_a, **_k: pytest.fail("legacy fallback constructed"),
    )
    gateway = factory(tmp_path)
    assert gateway._mood_enabled and gateway._mood_provider is None and gateway._provider is None
    monkeypatch.setattr(gateway._mood_store, "create_job", lambda **_kwargs: "a" * 64)
    monkeypatch.setattr(
        gateway._job_service, "create_job", lambda **_kwargs: pytest.fail("legacy job created")
    )
    created = gateway.create_job(
        profile_id="profile:test",
        consent_version=route.CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
        consent_accepted=True,
    )
    assert created["analysis_family"] == "photo-mood-v1"
    monkeypatch.setattr(gateway._mood_store, "family", lambda **_kwargs: "photo-mood-v1")
    with pytest.raises(PhotoLiveAnalysisUnavailable):
        gateway._analyze_stored_images(job_id="a" * 64, profile_id="profile:test")


def test_photo_override_precedes_common_key_and_disabled_factory_never_reads_key(
    monkeypatch, tmp_path
):
    configured = tmp_path / "key"
    configured.write_text("common-file-key")
    monkeypatch.setenv("ITDA_ZHIPUAI_API_KEY_FILE", str(configured))
    monkeypatch.setenv("ITDA_PHOTO_VLM_API_KEY", "photo-override")
    monkeypatch.setenv("ITDA_PHOTO_MOOD_ENABLED", "1")
    values = []
    monkeypatch.setattr(
        route, "GlmMoodProvider", lambda **kwargs: values.append(kwargs["api_key"]) or object()
    )
    assert factory(tmp_path)._mood_provider is not None
    assert values == ["photo-override"]
    route._lifecycle_for.cache_clear()
    monkeypatch.setenv("ITDA_PHOTO_MOOD_ENABLED", "0")
    monkeypatch.setattr(
        route, "_photo_provider_api_key", lambda: pytest.fail("disabled feature read key")
    )
    assert factory(tmp_path)._mood_provider is None


def test_photo_specific_file_is_authoritative_over_direct_value(monkeypatch, tmp_path):
    configured = tmp_path / "photo-key"
    configured.write_text("specific-file-key\r\n")
    monkeypatch.setenv("ITDA_PHOTO_VLM_API_KEY_FILE", str(configured))
    monkeypatch.setenv("ITDA_PHOTO_VLM_API_KEY", "ignored-direct")
    monkeypatch.setenv("ITDA_PHOTO_MOOD_ENABLED", "1")
    values = []
    monkeypatch.setattr(
        route, "GlmMoodProvider", lambda **kwargs: values.append(kwargs["api_key"]) or object()
    )
    factory(tmp_path)
    assert values == ["specific-file-key"]
