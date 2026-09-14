from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from threading import Event

import httpx
import pytest
from PIL import Image

from itda.photo.model_control import ModelBatchControl, ModelBatchPaused
from itda.photo.provider.mood import GlmMoodProvider
from itda.pipeline.grounded_place_scoring import GroundedTextProvider


@pytest.mark.parametrize("first", ["text", "mood"])
def test_text_and_mood_share_quota_stop_without_validation_fallback(first, tmp_path, monkeypatch):
    from itda.pipeline import grounded_place_scoring

    monkeypatch.setattr(
        grounded_place_scoring,
        "build_text_request",
        lambda _: ({"model": "glm-5.3-flash", "messages": []}, (), {"inventory": []}),
    )
    control = ModelBatchControl()
    calls = []

    def limited(request):
        calls.append(request.method)
        return httpx.Response(429, json={"error": "limited"})

    text = GroundedTextProvider(
        api_key="fixture-key", transport=httpx.MockTransport(limited), batch_control=control
    )
    mood = GlmMoodProvider(
        api_key="fixture-key",
        explicit_opt_in=True,
        transport=httpx.MockTransport(limited),
        batch_control=control,
    )
    image = BytesIO()
    Image.new("RGB", (20, 20), "green").save(image, format="PNG")
    invoke = {
        "text": lambda: text.analyze(None, cache_directory=tmp_path),
        "mood": lambda: mood.analyze(image_png=image.getvalue(), job_id="a" * 64, image_index=1),
    }
    with pytest.raises(ModelBatchPaused) as caught:
        invoke[first]()
    for run in invoke.values():
        with pytest.raises(ModelBatchPaused):
            run()
    assert calls == ["POST"]
    assert caught.value.state["automatic_retry"] is False
    assert caught.value.state["requests_started_before_pause"] == 1
    assert not list(tmp_path.glob("*.json"))


def test_inflight_request_can_finish_but_later_requests_are_not_dispatched():
    control = ModelBatchControl()
    entered, finish = Event(), Event()
    calls = []

    def delayed(request):
        calls.append(request.url.path)
        entered.set()
        assert finish.wait(5)
        return httpx.Response(200)

    def limited(request):
        calls.append(request.url.path)
        return httpx.Response(429)

    def issue(path, handler):
        with httpx.Client(transport=control.transport(httpx.MockTransport(handler))) as client:
            return client.post("https://example.invalid/" + path).status_code

    with ThreadPoolExecutor(max_workers=1) as pool:
        inflight = pool.submit(issue, "inflight", delayed)
        try:
            assert entered.wait(5)
            with pytest.raises(ModelBatchPaused):
                issue("limited", limited)
            with pytest.raises(ModelBatchPaused):
                issue("later", limited)
        finally:
            finish.set()
        assert inflight.result() == 200
    assert calls == ["/inflight", "/limited"]


def test_non_quota_http_error_does_not_close_batch():
    control = ModelBatchControl()
    with httpx.Client(
        transport=control.transport(httpx.MockTransport(lambda _: httpx.Response(503)))
    ) as client:
        assert client.post("https://example.invalid/").status_code == 503
    control.check()


def test_retry_limit_preserves_body_closes_response_and_honors_retry_after(monkeypatch):
    from types import SimpleNamespace

    from itda.photo import model_control

    now = [100.0]
    monkeypatch.setattr(
        model_control,
        "time",
        SimpleNamespace(monotonic=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0] + n)),
    )
    records, calls, responses = [], [], []
    control = ModelBatchControl(retry_limits=True, on_retry=records.append)

    def handle(request):
        calls.append((now[0], request.content))
        response = httpx.Response(
            429 if len(calls) < 3 else 200,
            headers={"Retry-After": "90"} if len(calls) == 1 else {},
        )
        responses.append(response)
        return response

    with httpx.Client(transport=control.transport(httpx.MockTransport(handle))) as client:
        assert (
            client.post("https://example.invalid/", content=b"same-image-json").status_code == 200
        )
    assert calls == [
        (100.0, b"same-image-json"),
        (190.0, b"same-image-json"),
        (310.0, b"same-image-json"),
    ]
    assert all(r.is_closed for r in responses)
    assert [r["limited_responses"] for r in records] == [1, 2]
    assert all(r["automatic_retry"] for r in records)
    control.check()


def test_shared_cooldown_cohort_and_recovery_spacing(monkeypatch):
    from types import SimpleNamespace

    from itda.photo import model_control

    now = [100.0]
    monkeypatch.setattr(
        model_control,
        "time",
        SimpleNamespace(monotonic=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0] + n)),
    )
    records, starts = [], []
    control = ModelBatchControl(retry_limits=True, on_retry=records.append)
    for _ in range(40):
        control.retry(httpx.Response(429, headers={"Retry-After": "invalid"}))
    assert control._retry_until == 160
    assert control._backoff == 60
    for _ in range(3):
        with httpx.Client(
            transport=control.transport(
                httpx.MockTransport(lambda _: (starts.append(now[0]), httpx.Response(200))[1])
            )
        ) as client:
            assert client.post("https://example.invalid/").status_code == 200
    assert starts == [160, 162, 164]
    assert records[-1]["limited_responses"] == 40


def test_retry_mode_does_not_retry_authentication_errors():
    calls = []
    control = ModelBatchControl(retry_limits=True)
    with httpx.Client(
        transport=control.transport(
            httpx.MockTransport(lambda _: (calls.append(1), httpx.Response(403))[1])
        )
    ) as client:
        assert client.post("https://example.invalid/").status_code == 403
    assert calls == [1]


@pytest.mark.parametrize("recovers", [False, True])
def test_connection_failure_retries_with_shared_delay_and_pauses_before_other_places(
    monkeypatch, recovers
):
    from types import SimpleNamespace

    from itda.photo import model_control

    now = [100.0]
    monkeypatch.setattr(
        model_control,
        "time",
        SimpleNamespace(monotonic=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0] + n)),
    )
    starts, records = [], []
    control = ModelBatchControl(retry_connections=True, on_retry=records.append)

    def handle(request):
        starts.append(now[0])
        if recovers and len(starts) == 2:
            return httpx.Response(200)
        raise httpx.ConnectError("fixture-only connection error", request=request)

    with httpx.Client(transport=control.transport(httpx.MockTransport(handle))) as client:
        if recovers:
            assert client.post("https://example.invalid/").status_code == 200
            assert starts == [100, 160]
        else:
            with pytest.raises(ModelBatchPaused) as caught:
                client.post("https://example.invalid/")
            assert caught.value.state["reason"] == "MODEL_CONNECTION_UNAVAILABLE"
            assert starts == [100, 160, 280, 520, 1000]
            with pytest.raises(ModelBatchPaused):
                client.post("https://example.invalid/next-place")
            assert len(starts) == 5
    assert all(
        r["reason"] == "MODEL_CONNECTION_ERROR" and r["http_status"] is None for r in records
    )
