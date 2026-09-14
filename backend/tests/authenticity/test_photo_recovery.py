import hashlib
import json

import httpx
import pytest

from itda.authenticity.appearance import APPEARANCE_KEYS
from itda.authenticity.model import MODEL, GlmClient, ModelExchangeError
from itda.authenticity.photo_recovery import (
    PhotoExcluded,
    PhotoRecoveryClient,
    extract,
    photo_stage_complete,
    verify_exclusion,
)
from itda.domain.canonical import canonical_sha256


def wire():
    return {
        "scene_status": "PLACE_SCENE",
        "observations": [
            {"key": k, "state": "OBSERVED", "level": 2, "reason": "픽셀에서 보이는 특징"}
            for k in APPEARANCE_KEYS
        ],
    }


def record(payload, content, finish="stop"):
    raw = json.dumps(
        {"model": MODEL, "choices": [{"finish_reason": finish, "message": {"content": content}}]}
    )
    result = {
        "request": payload,
        "request_sha256": canonical_sha256(payload),
        "raw_response": raw,
        "response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "http_status": 200,
        "retrieved_at": "2026-09-12T00:00:00Z",
    }
    result["record_sha256"] = canonical_sha256(result)
    return result


def inputs(tmp_path, content, finish="stop"):
    payload = {"model": MODEL}
    digest = canonical_sha256(payload)
    cache = tmp_path / "appearance/model-cache"
    cache.mkdir(parents=True)
    value = record(payload, content, finish)
    path = cache / (digest + "-initial.attempt.json")
    path.write_text(json.dumps(value))
    root = tmp_path / "photo-recovery"
    root.mkdir()
    plan = {"request_sha256s": [digest]}
    plan["plan_sha256"] = canonical_sha256(plan)
    (root / "plan.json").write_text(json.dumps(plan))
    return payload, cache, root, path


def no_network(request):
    pytest.fail("unexpected model dispatch")


def test_suffix_recovery_preserves_original_and_replays_without_network(tmp_path):
    value = wire()
    payload, cache, root, path = inputs(tmp_path, json.dumps(value) + "\n추가 설명")
    before = path.read_bytes()
    client = PhotoRecoveryClient(api_key="test", transport=httpx.MockTransport(no_network))
    raw, meta = client.complete(payload, directory=cache, live=True)
    assert raw == value and path.read_bytes() == before
    assert client.complete(payload, directory=cache, live=True) == (raw, meta)
    saved = json.loads(next((root / "wires").glob("*.json")).read_text())
    assert saved["extraction"]["values_rewritten"] is False
    assert saved["used_additional_response"] is False


@pytest.mark.parametrize("change", ["length", "second_json", "duplicate", "code"])
def test_incomplete_ambiguous_or_executable_response_is_not_recovered(change):
    content = json.dumps(wire())
    if change == "second_json":
        content += "\n[]"
    if change == "duplicate":
        content = content.replace('"level": 2', '"level": 2, "level": 4', 1)
    if change == "code":
        content = content.replace('"OBSERVED"', '"OBSERVED".replace("X", "Y")', 1)
    with pytest.raises(ValueError):
        extract(record({"model": MODEL}, content, "length" if change == "length" else "stop"))


def test_non_evaluable_scene_is_excluded_and_tampered_proof_rejected(tmp_path):
    value = wire() | {"scene_status": "NOT_EVALUABLE"}
    payload, cache, root, path = inputs(tmp_path, json.dumps(value))
    client = PhotoRecoveryClient(api_key="test", transport=httpx.MockTransport(no_network))
    with pytest.raises(PhotoExcluded) as caught:
        client.complete(payload, directory=cache, live=True)
    decision = caught.value.decision
    assert decision["reason"] == "NOT_EVALUABLE_SCENE"
    verify_exclusion(decision)
    summary = {
        "selected_images": 1,
        "observed_images": 0,
        "excluded_images": 1,
        "rows": [
            {"selected_images": 1, "decisions": [{"status": "EXCLUDED", "exclusion": decision}]}
        ],
    }
    summary["report_sha256"] = canonical_sha256(summary)
    assert photo_stage_complete(summary)
    changed = json.loads(path.read_text())
    changed["http_status"] = 403
    path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="ARTIFACT_CHANGED"):
        photo_stage_complete(summary)


def test_invalid_retry_has_one_durable_dispatch_then_explicit_exclusion(tmp_path):
    payload, cache, root, _ = inputs(tmp_path, '{"broken":')
    calls = []

    def handle(request):
        assert list((root / "reservations").glob("*.json"))
        assert json.loads(request.content) == payload
        calls.append(request)
        return httpx.Response(200, json=json.loads(record(payload, '{"broken":')["raw_response"]))

    client = PhotoRecoveryClient(api_key="test", transport=httpx.MockTransport(handle))
    for _ in range(2):
        with pytest.raises(PhotoExcluded) as caught:
            client.complete(payload, directory=cache, live=True)
        verify_exclusion(caught.value.decision)
    assert len(calls) == 1


def test_valid_additional_response_is_reused_without_third_dispatch(tmp_path):
    payload, cache, root, _ = inputs(tmp_path, '{"broken":')
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(
            200, json=json.loads(record(payload, json.dumps(wire()))["raw_response"])
        )

    client = PhotoRecoveryClient(api_key="test", transport=httpx.MockTransport(handle))
    assert client.complete(payload, directory=cache, live=True)[0] == wire()
    assert client.complete(payload, directory=cache, live=True)[0] == wire()
    assert len(calls) == 1


def test_uncertain_dispatch_reservation_is_never_repeated(tmp_path, monkeypatch):
    payload, cache, root, _ = inputs(tmp_path, '{"broken":')
    calls = []

    def fail(*args, **kwargs):
        calls.append(kwargs)
        raise ModelExchangeError("MODEL_RESPONSE_UNAVAILABLE")

    monkeypatch.setattr(GlmClient, "complete", fail)
    client = PhotoRecoveryClient(api_key="test")
    with pytest.raises(ModelExchangeError, match="MODEL_RESPONSE_UNAVAILABLE"):
        client.complete(payload, directory=cache, live=True)
    with pytest.raises(ModelExchangeError, match="DISPATCH_UNCERTAIN_NO_REPEAT"):
        client.complete(payload, directory=cache, live=True)
    assert len(calls) == 1


def test_unavailable_photo_cannot_satisfy_completion_gate():
    summary = {
        "selected_images": 1,
        "observed_images": 0,
        "excluded_images": 0,
        "rows": [{"selected_images": 1, "decisions": [{"status": "UNAVAILABLE"}]}],
    }
    summary["report_sha256"] = canonical_sha256(summary)
    assert not photo_stage_complete(summary)
