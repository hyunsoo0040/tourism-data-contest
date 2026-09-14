import hashlib
import json

import pytest

from itda.authenticity.model import MODEL
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.wire_recovery import extract
from itda.domain.canonical import canonical_sha256


def record(content):
    request = {"model": MODEL}
    raw = json.dumps(
        {"model": MODEL, "choices": [{"finish_reason": "stop", "message": {"content": content}}]}
    )
    value = {
        "http_status": 200,
        "request": request,
        "request_sha256": canonical_sha256(request),
        "raw_response": raw,
        "response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
    }
    value["record_sha256"] = canonical_sha256(value)
    return value


def wire():
    return {
        "judgments": [
            {
                "key": k,
                "state": "UNKNOWN",
                "level": None,
                "basis": "INSUFFICIENT",
                "subject": "UNRESOLVED",
                "citations": [],
                "reason": "기술 검사",
            }
            for k in FACET_KEYS
        ]
    }


def test_complete_prefix_is_exact_and_suffix_has_a_separate_hash():
    value = wire()
    encoded = json.dumps(value, ensure_ascii=False)
    suffix = "\n추가 설명문입니다."
    parsed, meta = extract(record("\n" + encoded + suffix))
    assert parsed == value and meta["values_rewritten"] is False
    assert meta["json_char_start"] == 1 and meta["json_char_end"] == len(encoded) + 1
    assert meta["suffix_sha256"] == hashlib.sha256(suffix.encode()).hexdigest()


@pytest.mark.parametrize(
    "change", ["second_object", "duplicate_key", "truncated", "missing_facet", "prefix"]
)
def test_ambiguous_or_incomplete_answer_is_not_extracted(change):
    value = wire()
    text = json.dumps(value)
    if change == "second_object":
        text += '\n{"judgments": []}'
    elif change == "duplicate_key":
        text = text.replace('"level": null', '"level": null, "level": 4', 1) + "\n설명"
    elif change == "truncated":
        text = text[:-15] + "\n설명"
    elif change == "missing_facet":
        value["judgments"].pop()
        text = json.dumps(value) + "\n설명"
    else:
        text = "먼저 생각해보면 " + text + "\n설명"
    with pytest.raises(ValueError):
        extract(record(text))
    with pytest.raises(ValueError):
        extract(record(text), allow_facet_rejections=True)


def test_v2_preserves_invalid_facet_and_frozen_binder_rejects_it():
    from itda.authenticity.binding import bind_response
    from tests.authenticity.helpers import evidence, source

    value = wire()
    value["judgments"][0].update(state="SUPPORTED", level=3, basis="DIRECT_SUPPORT")
    value["judgments"][0]["citations"] = [
        {"evidence_id": "evidence:test", "claim": "PARTICIPATORY_ACTIVITY", "quote": "전망대"}
    ]
    response = record(json.dumps(value, ensure_ascii=False) + "\n추가 설명")
    with pytest.raises(ValueError):
        extract(response)
    extracted, meta = extract(response, allow_facet_rejections=True)
    assert extracted == value and meta["values_rewritten"] is False
    judgments, rejections = bind_response(extracted, source(evidence()))
    rejected = next(j for j in judgments if j.key == value["judgments"][0]["key"])
    assert rejected.state == "REJECTED" and rejected.level is None
    assert rejections[0].code == "FACET_SCHEMA_REJECTED"
    assert rejections[0].proposed == value["judgments"][0]


def test_v2_saved_wire_replays_and_rejects_tampering(tmp_path):
    from itda.authenticity.wire_recovery import from_attempts, load

    value = wire()
    value["judgments"][0]["reason"] = ""
    response = record(json.dumps(value) + "\n추가 설명")
    response["retrieved_at"] = "2026-09-12T00:00:00Z"
    response["record_sha256"] = canonical_sha256(
        {k: v for k, v in response.items() if k != "record_sha256"}
    )
    digest = response["request_sha256"]
    folder = tmp_path / "model-cache/attempt-2"
    folder.mkdir(parents=True)
    (folder / (digest + "-record.attempt.json")).write_text(json.dumps(response))
    result = from_attempts(tmp_path, digest)
    assert result is not None
    extracted, _, path = result
    assert extracted == value and load(path, digest) == value
    saved = json.loads(path.read_text())
    assert saved["version"] == "authenticity-lossless-wire-recovery-v2"
    saved["wire"]["judgments"][0]["level"] = 4
    path.write_text(json.dumps(saved))
    with pytest.raises(ValueError, match="WIRE_RECOVERY_ARTIFACT_CHANGED"):
        load(path, digest)
