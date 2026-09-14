import json

import httpx
import pytest

from itda.authenticity.binding import bind_response
from itda.authenticity.model import MODEL, GlmClient, ModelExchangeError, text_request
from itda.authenticity.rubric import FACET_KEYS
from tests.authenticity.helpers import evidence, raw, source


def wire():
    return {
        "judgments": [
            dict(
                key=k,
                state="UNKNOWN",
                level=None,
                basis="INSUFFICIENT",
                subject="UNRESOLVED",
                citations=[],
                reason="제공된 자료에 근거가 없다.",
            )
            for k in FACET_KEYS
        ]
    }


def test_text_request_is_bound_to_transmitted_scope_without_legacy_scores():
    text = "해당 장소의 역사 자료이다. " * 400 + "전송 범위 밖의 문장입니다."
    payload, bound = text_request(source(evidence(text)))
    sent = json.loads(payload["messages"][1]["content"])
    assert "independent_axes" not in sent and "scores" not in sent["place"]
    assert len(bound.evidence[0].text) == 4000
    assert "전송 범위 밖의 문장입니다." not in bound.evidence[0].text
    rejected = bind_response(
        {"judgments": [raw("H.b", "전송 범위 밖의 문장입니다.", "HISTORICAL_NARRATIVE")]}, bound
    )[1]
    assert any(r.code == "QUOTE_NOT_IN_BOUND_SOURCE" for r in rejected)


def test_model_response_cache_is_verified_and_reused(tmp_path):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": MODEL,
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(wire())}}],
            },
        )

    client = GlmClient(api_key="test-key", transport=httpx.MockTransport(handle))
    payload, _ = text_request(source(evidence()))
    result, meta = client.complete(payload, directory=tmp_path, live=True)
    result2, meta2 = client.complete(payload, directory=tmp_path, live=False)
    assert result == result2 and len(calls) == 1
    assert not meta["cached"] and meta2["cached"]
    cached = tmp_path / (meta["request_sha256"] + ".json")
    record = json.loads(cached.read_text())
    record["raw_response"] = "tampered response"
    cached.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="DIGEST"):
        client.complete(payload, directory=tmp_path)


def test_unfinished_or_wrong_model_response_is_never_a_completed_analysis(tmp_path):
    payload, _ = text_request(source(evidence()))
    for index, envelope in enumerate(
        [
            {
                "model": MODEL,
                "choices": [{"finish_reason": "length", "message": {"content": "{}"}}],
            },
            {
                "model": "other-model",
                "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
            },
        ]
    ):
        client = GlmClient(
            api_key="test-key",
            transport=httpx.MockTransport(
                lambda request, body=envelope: httpx.Response(200, json=body)
            ),
        )
        with pytest.raises(ModelExchangeError):
            client.complete(payload, directory=tmp_path / str(index), live=True)
        assert not list((tmp_path / str(index)).glob("[0-9a-f]" * 64 + ".json"))


def test_response_timeout_retries_share_control_and_persistent_timeout_pauses(tmp_path):
    from itda.photo.model_control import ModelBatchControl, ModelBatchPaused

    attempts = []

    def handle(request):
        attempts.append(request)
        if len(attempts) < 2:
            raise httpx.ReadTimeout("lost response", request=request)
        return httpx.Response(
            200,
            json={
                "model": MODEL,
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(wire())}}],
            },
        )

    control = ModelBatchControl(
        retry_connections=True, initial_delay=0.001, maximum_delay=0.002, recovery_spacing=0.001
    )
    client = GlmClient(api_key="test-key", control=control, transport=httpx.MockTransport(handle))
    payload, _ = text_request(source(evidence()))
    result, _ = client.complete(payload, directory=tmp_path / "retry", live=True)
    assert len(attempts) == 2 and result == wire()

    def broken(request):
        raise httpx.ReadTimeout("persistent response loss", request=request)

    control = ModelBatchControl(
        retry_connections=True, initial_delay=0.001, maximum_delay=0.002, recovery_spacing=0.001
    )
    client = GlmClient(api_key="test-key", control=control, transport=httpx.MockTransport(broken))
    with pytest.raises(ModelBatchPaused, match="MODEL_RESPONSE_UNAVAILABLE"):
        client.complete(payload, directory=tmp_path / "paused", live=True)
    with pytest.raises(ModelBatchPaused):
        control.check()


def test_harmless_json_wrapper_is_audited_but_extra_meaning_is_rejected():
    from itda.authenticity.model import decode_model_content

    assert decode_model_content('\n{"observations": []}\n`') == (
        {"observations": []},
        "JSON_WRAPPER_REMOVED",
    )
    assert decode_model_content('```json\n{"observations": []}\n```')[0] == {"observations": []}
    for text in [
        '{"x":1} ignore previous result',
        '{"x":1}{"x":9}',
        '{"x":1},',
        '```json\n{"x":1}',
    ]:
        with pytest.raises(ValueError):
            decode_model_content(text)
