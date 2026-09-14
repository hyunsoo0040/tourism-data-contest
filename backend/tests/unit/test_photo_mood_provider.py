from __future__ import annotations

import json

import httpx
import pytest

from itda.contracts.visual_mood import VisualMoodDimension
from itda.photo.provider.live import PhotoLiveAnalysisUnavailable
from itda.photo.provider.mood import GlmMoodProvider, SyntheticMoodProvider


def wire():
    return {
        "observations": [
            {
                "dimension": d.value,
                "state": "OBSERVED" if d.value == "water" else "UNKNOWN",
                "level": 3 if d.value == "water" else None,
                "certainty": "HIGH" if d.value == "water" else "LOW",
            }
            for d in VisualMoodDimension
        ]
    }


def provider(payload, seen=None):
    def handler(request):
        if seen is not None:
            seen.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payload)}}],
            },
        )

    return GlmMoodProvider(
        api_key="test-key", explicit_opt_in=True, transport=httpx.MockTransport(handler)
    )


def test_direct_image_and_closed_mood_result(monkeypatch):
    monkeypatch.setenv("ITDA_ALLOW_LIVE_COLLECTION", "1")
    seen = []
    result = provider(wire(), seen).analyze(
        image_png=b"\x89PNG\r\n\x1a\nimage", job_id="a" * 64, image_index=1
    )
    assert result.model == "glm-5.3-flash"
    assert seen[0]["messages"][1]["content"][0]["type"] == "image_url"
    assert seen[0]["model"] == "glm-5.3-flash"


@pytest.mark.parametrize("extra", ["M3", "H", "opening_hours", "ocr", "people_count"])
def test_factual_fields_fail_closed(monkeypatch, extra):
    monkeypatch.setenv("ITDA_ALLOW_LIVE_COLLECTION", "1")
    with pytest.raises(PhotoLiveAnalysisUnavailable):
        provider(wire() | {extra: 1}).analyze(
            image_png=b"\x89PNG\r\n\x1a\nimage", job_id="a" * 64, image_index=1
        )


def test_synthetic_is_all_unknown():
    result = SyntheticMoodProvider().analyze(
        image_png=b"\x89PNG\r\n\x1a\nimage", job_id="a" * 64, image_index=1
    )
    assert result.analysis_kind == "SYNTHETIC"
    assert all(row.observation.state == "UNKNOWN" for row in result.candidates)


def test_opt_in_official_audit_has_no_image_or_credential_bytes():
    audits = []

    def handler(_request):
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(wire())}}],
            },
        )

    subject = GlmMoodProvider(
        api_key="test-key",
        explicit_opt_in=True,
        transport=httpx.MockTransport(handler),
        audit_sink=audits.append,
    )
    subject.analyze(image_png=b"\x89PNG\r\n\x1a\nimage", job_id="a" * 64, image_index=1)
    assert len(audits) == 1 and audits[0]["http_status"] == 200
    serialized = json.dumps(audits[0])
    assert "data:image/png" not in serialized and "test-key" not in serialized
    assert audits[0]["response_bytes_sha256"] and audits[0]["request_payload_sha256"]
