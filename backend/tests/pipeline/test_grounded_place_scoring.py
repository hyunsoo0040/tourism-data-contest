from __future__ import annotations

import pytest

from itda.pipeline.grounded_place_scoring import (
    GroundedTextWire,
    bind_text_judgments,
    normalize_text_wire,
)


def empty_wire():
    from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS

    return {
        "independent_axes": {"H": 0, "E": 0, "R": 0},
        "judgments": [
            {
                "dimension": key,
                "state": "UNKNOWN",
                "value": None,
                "citations": [],
                "reason": "자료 미확인",
            }
            for key in SCORING_DIMENSIONS[3:]
        ],
    }


def test_missing_model_judgments_explicitly_unknown():
    wire = GroundedTextWire.model_validate(empty_wire())
    judgments = bind_text_judgments(wire, ())
    assert len(judgments) == 18
    assert all(row.value is None for row in judgments.values())


def test_m3_cannot_acquire_model_authority_or_fabricated_citation():
    raw = empty_wire()
    raw["judgments"][14].update(
        state="SUPPORTED",
        value=20,
        citations=[{"evidence_id": "evidence:missing", "quote": "실측 자료"}],
    )
    with pytest.raises(ValueError):
        bind_text_judgments(GroundedTextWire.model_validate(raw), ())


def test_closed_model_contract_rejects_operating_or_photo_fields():
    with pytest.raises(ValueError):
        GroundedTextWire.model_validate(empty_wire() | {"opening_hours": "24시간"})
    with pytest.raises(ValueError):
        GroundedTextWire.model_validate(empty_wire() | {"image_url": "https://example.org"})


def test_partial_discard_keeps_valid_dimensions_without_repairing_invalid_citations():
    from tests.unit.test_grounded_axis_aggregation import judgment

    source = judgment("H1", 4).evidence[0]
    raw = empty_wire()
    raw["judgments"][0].update(
        state="SUPPORTED",
        value=4,
        citations=[{"evidence_id": source.evidence_id, "quote": source.quote}],
    )
    raw["judgments"][1].update(
        state="SUPPORTED",
        value=3,
        citations=[{"evidence_id": source.evidence_id, "quote": "원문에 없는 문장"}],
    )
    raw["judgments"][2].update(
        state="SUPPORTED", value=2, citations=[{"evidence_id": source.evidence_id, "quote": "무료"}]
    )
    wire, rejections = normalize_text_wire(raw)
    actual = bind_text_judgments(wire, (source,), rejections=rejections)
    assert actual["H1"].value == 4
    assert actual["H2"].value is None and actual["H3"].value is None
    assert {r["code"] for r in rejections} == {
        "DIMENSION_SCHEMA_REJECTED",
        "QUOTE_NOT_IN_BOUND_SOURCE",
    }


def test_duplicate_dimension_does_not_let_last_value_win():
    raw = empty_wire()
    raw["judgments"].append(raw["judgments"][0].copy())
    wire, rejections = normalize_text_wire(raw)
    assert wire.judgments[0].state == "UNKNOWN"
    assert rejections == [{"dimension": "H1", "code": "DIMENSION_DUPLICATED"}]


def test_m6_requires_the_actual_citation_not_an_uncited_time_sentence():
    from tests.unit.test_grounded_axis_aggregation import judgment

    source = (
        judgment("E4", 3)
        .evidence[0]
        .model_copy(
            update={
                "excerpt": "사계절 물놀이를 즐길 수 있다. 식당도 있다.",
                "quote": "사계절 물놀이를 즐길 수 있다. 식당도 있다.",
            }
        )
    )
    raw = empty_wire()
    for row in raw["judgments"]:
        if row["dimension"] == "E4":
            row.update(
                state="SUPPORTED",
                value=3,
                citations=[
                    {"evidence_id": source.evidence_id, "quote": "사계절 물놀이를 즐길 수 있다"}
                ],
            )
        if row["dimension"] == "M6":
            row.update(
                state="SUPPORTED",
                value=20,
                citations=[{"evidence_id": source.evidence_id, "quote": "식당도 있다"}],
            )
    wire, rejections = normalize_text_wire(raw)
    bound = bind_text_judgments(wire, (source,), rejections=rejections)
    assert bound["E4"].value == 3 and bound["M6"].value is None
    assert rejections == [{"dimension": "M6", "code": "SOURCE_DIMENSION_NOT_AUTHORIZED"}]


def test_invalid_response_is_audited_without_poisoning_success_cache(monkeypatch, tmp_path):
    import json

    import httpx

    from itda.pipeline import grounded_place_scoring as module
    from itda.pipeline.grounded_place_scoring import GroundedTextProvider

    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [
                    {
                        "finish_reason": "length" if len(calls) == 1 else "stop",
                        "message": {"content": json.dumps(empty_wire())},
                    }
                ],
            },
        )

    monkeypatch.setattr(
        module,
        "build_text_request",
        lambda _: ({"model": "glm-5.3-flash", "messages": []}, (), {"inventory": []}),
    )
    provider = GroundedTextProvider(api_key="test-key", transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError):
        provider.analyze(None, cache_directory=tmp_path)
    assert len(list(tmp_path.glob("*.attempt.json"))) == 1
    wire, judgments, metadata = provider.analyze(None, cache_directory=tmp_path)
    assert metadata["validation_status"] == "VALIDATED"
    assert all(row.value is None for row in judgments.values())
    assert provider.analyze(None, cache_directory=tmp_path, live=False)[2]["cached"] is True
    assert len(calls) == 2


def test_http_failure_preserves_safe_response_and_retry_metadata(monkeypatch, tmp_path):
    import json

    import httpx

    from itda.pipeline import grounded_place_scoring as module
    from itda.pipeline.grounded_place_scoring import GroundedModelHTTPError, GroundedTextProvider

    monkeypatch.setattr(
        module,
        "build_text_request",
        lambda _: ({"model": "glm-5.3-flash", "messages": []}, (), {"inventory": []}),
    )
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            429,
            headers={"Retry-After": "7"},
            json={"error": {"code": "RATE_LIMIT", "message": "try later"}},
        )
    )
    provider = GroundedTextProvider(api_key="test-key", transport=transport)
    with pytest.raises(GroundedModelHTTPError) as caught:
        provider.analyze(None, cache_directory=tmp_path)
    assert caught.value.http_status == 429 and caught.value.retry_after == 7
    record = json.loads(__import__("pathlib").Path(caught.value.record_path).read_text())
    assert (
        record["http_status"] == 429
        and json.loads(record["raw_response"])["error"]["code"] == "RATE_LIMIT"
    )
    assert "test-key" not in json.dumps(record)
    assert not any(
        p.suffix == ".json" and not p.name.endswith(".attempt.json") for p in tmp_path.iterdir()
    )


def test_v2_unchanged_refresh_reuses_one_model_call_and_rebinds_current_receipt(tmp_path):
    import base64
    import hashlib
    import json
    from datetime import UTC, datetime, timedelta

    import httpx

    from itda.contracts.source_assessment import PlaceMatch, SourceReceipt, SourceService
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot, evidence_from_fields
    from itda.pipeline.grounded_place_scoring import GroundedTextProvider, build_text_request
    from tests.pipeline.test_destination_evidence import place

    canonical = place()
    row = {"contentid": "123", "overview": "공식 장소 설명"}
    body = {"response": {"body": {"items": {"item": [row]}}}}
    raw = json.dumps(body).encode()

    def snapshot(day):
        stamp = datetime(2026, 9, 9, tzinfo=UTC) + timedelta(days=day)
        receipt = SourceReceipt(
            service=SourceService.TOUR,
            operation="detailCommon2",
            dataset_id="15101578",
            request_scope={"contentId": "123"},
            retrieved_at=stamp,
            reference_date=stamp.date(),
            source_modified_at=datetime(2025, 1, 1, tzinfo=UTC),
            status="AVAILABLE",
            http_status=200,
            response_sha256=hashlib.sha256(raw).hexdigest(),
            reason="OFFICIAL_RESPONSE",
        )
        match = PlaceMatch(
            place_id=canonical.place_id,
            service=SourceService.TOUR,
            provider_entity_id="123",
            state="MATCHED",
            method="EXACT_ID_AND_LOCATION",
            region_code="47130",
            evidence=("exact content ID and coordinates",),
        )
        evidence, lineage = evidence_from_fields(
            receipt, match, row, ("overview",), identity_version="v2"
        )
        fields = {
            "schema_version": "destination-evidence.v1",
            "place": canonical.model_dump(mode="json"),
            "category": "관광지",
            "catalog_row_sha256": "b" * 64,
            "collected_at": stamp.isoformat().replace("+00:00", "Z"),
            "receipts": [receipt.model_dump(mode="json")],
            "raw_responses": [
                {
                    "raw_response_sha256": receipt.response_sha256,
                    "raw_body_base64": base64.b64encode(raw).decode(),
                    "payload": body,
                }
            ],
            "evidence": [e.model_dump(mode="json") for e in evidence],
            "text_lineage": list(lineage),
            "images": [],
            "coverage": {"semantic_evidence_version": "v2"},
        }
        return DestinationEvidenceSnapshot.model_validate(
            fields | {"snapshot_sha256": canonical_sha256(fields)}
        )

    old, fresh = snapshot(0), snapshot(1)
    assert old.evidence[0].evidence_id == fresh.evidence[0].evidence_id
    assert (
        build_text_request(old, cache_version="v2")[0]
        == build_text_request(fresh, cache_version="v2")[0]
    )
    assert (
        build_text_request(old)[0] != build_text_request(fresh)[0]
    )  # historical v1 remains distinct
    calls = []

    def handler(request):
        calls.append(request)
        wire = empty_wire()
        wire["judgments"][0].update(
            state="SUPPORTED",
            value=4,
            citations=[{"evidence_id": old.evidence[0].evidence_id, "quote": "공식 장소 설명"}],
        )
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(wire)}}],
            },
        )

    provider = GroundedTextProvider(
        api_key="test-key", transport=httpx.MockTransport(handler), cache_version="v2"
    )
    first = provider.analyze(old, cache_directory=tmp_path)
    second = provider.analyze(fresh, cache_directory=tmp_path)
    assert len(calls) == 1 and second[2]["cached"] is True
    assert first[1]["H1"].value == second[1]["H1"].value == 4
    assert second[1]["H1"].evidence[0].receipt.retrieved_at == fresh.receipts[0].retrieved_at
    assert (
        first[1]["H1"].evidence[0].receipt.retrieved_at
        != second[1]["H1"].evidence[0].receipt.retrieved_at
    )
