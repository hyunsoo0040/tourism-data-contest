import hashlib
import json

import httpx
import pytest
from PIL import Image
from pydantic import ValidationError

from itda.authenticity.appearance import AppearanceWire, analyze_asset
from itda.authenticity.model import MODEL, GlmClient
from itda.contracts.source_assessment import PlaceMatch, SourceReceipt
from tests.authenticity.helpers import NOW, PID


def test_unreadable_scene_cannot_claim_observed_scores():
    observations = [
        dict(key=k, state="OBSERVED", level=2, reason="보임")
        for k in ("visual_character", "natural_setting", "traditional_appearance")
    ]
    with pytest.raises(ValidationError, match="NON_EVALUABLE"):
        AppearanceWire(scene_status="NOT_EVALUABLE", observations=observations)


def test_licensed_pixels_are_bound_to_original_and_sanitized_model_input(tmp_path):
    path = tmp_path / "artifacts/national/test/photo.png"
    path.parent.mkdir(parents=True)
    Image.new("RGB", (640, 480), (30, 80, 40)).save(path)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt = SourceReceipt(
        service="KorService2",
        operation="detailImage2",
        dataset_id="15101578",
        request_scope={"contentId": "1"},
        retrieved_at=NOW,
        status="AVAILABLE",
        http_status=200,
        response_sha256="a" * 64,
        reason="test response",
    )
    match = PlaceMatch(
        place_id=PID,
        service="KorService2",
        provider_entity_id="1",
        state="MATCHED",
        method="EXACT_ID_AND_LOCATION",
        region_code="11",
        evidence=("matched fixture",),
    )
    asset = {
        "asset_id": "image:1",
        "place_id": PID,
        "path": str(path.relative_to(tmp_path)),
        "original_sha256": sha,
        "receipt": receipt.model_dump(mode="json"),
        "match": match.model_dump(mode="json"),
        "license": "KOGL_TYPE_1",
        "attribution_ko": "공식 테스트 이미지",
        "download_status": "DOWNLOADED",
        "url": "https://example.test/photo.png",
    }

    def handle(request):
        payload = json.loads(request.content)
        user = payload["messages"][1]["content"]
        assert user[0]["image_url"]["url"].startswith("data:image/png;base64,")
        assert "name_ko" not in payload
        wire = {
            "scene_status": "PLACE_SCENE",
            "observations": [
                dict(key=k, state="OBSERVED", level=2, reason="사진에서 직접 보이는 특징")
                for k in ("visual_character", "natural_setting", "traditional_appearance")
            ],
        }
        return httpx.Response(
            200,
            json={
                "model": MODEL,
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(wire)}}],
            },
        )

    client = GlmClient(api_key="test-key", transport=httpx.MockTransport(handle))
    records, packet = analyze_asset(
        raw_asset=asset,
        repository=tmp_path,
        directory=tmp_path / "output",
        client=client,
        place_id=PID,
        live=True,
    )
    assert len(records) == 3
    assert all(r.image_sha256 == sha for r in records)
    assert packet["original_image_sha256"] == sha
    assert packet["materialization_sha256"] == records[0].receipt.source_record_sha256
    from itda.authenticity.photo_review import request as review_request

    review, keys = review_request(packet)
    assert keys == {"visual_character", "natural_setting", "traditional_appearance"}
    assert review["messages"][1]["content"][0]["image_url"]["url"].startswith(
        "data:image/png;base64,"
    )
    with pytest.raises(ValueError, match="PIXELS_CHANGED"):
        review_request(packet | {"sanitized_image_sha256": "f" * 64})
    with pytest.raises(ValueError, match="RIGHTS"):
        analyze_asset(
            raw_asset=asset | {"license": "UNKNOWN"},
            repository=tmp_path,
            directory=tmp_path / "output",
            client=client,
            place_id=PID,
            live=True,
        )


def test_exact_digit_strings_are_repaired_with_an_audit_but_not_arbitrary_coercion():
    from itda.authenticity.appearance import normalize_appearance

    raw = {
        "scene_status": "PLACE_SCENE",
        "observations": [
            dict(key=k, state="OBSERVED", level="2", reason="보이는 특징")
            for k in ("visual_character", "natural_setting", "traditional_appearance")
        ],
    }
    normalized, changes = normalize_appearance(raw)
    assert all(o.level == 2 for o in normalized.observations) and len(changes) == 3
    assert raw["observations"][0]["level"] == "2"
    for invalid in ["2.0", "-1", "five", True]:
        broken = {
            "scene_status": "PLACE_SCENE",
            "observations": [
                dict(key=k, state="OBSERVED", level=invalid, reason="보이는 특징")
                for k in ("visual_character", "natural_setting", "traditional_appearance")
            ],
        }
        with pytest.raises(ValidationError):
            normalize_appearance(broken)


def test_photo_review_missing_duplicate_and_invalid_rows_remain_uncertain():
    from itda.authenticity.photo_review import normalize

    rows = [{"key": "natural_setting", "decision": "SUPPORTED", "reason": "보이는 자연"}]
    result = normalize({"reviews": rows + rows}, {"natural_setting", "visual_character"})
    assert all(r.decision == "UNCERTAIN" for r in result)
    result = normalize({"reviews": rows}, {"natural_setting"})
    assert len(result) == 1 and result[0].decision == "SUPPORTED"
