from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.contracts.mvp_place_scoring import (
    MVP_SCORING_PROMPT_SHA256,
    PUBLIC_SCORING_RUBRIC,
    SCORING_DIMENSIONS,
    ProviderScoringResponse,
    PublicScoringRequest,
    reject_forbidden_fields,
)
from itda.contracts.mvp_public_catalog import PublicEvidenceInventory, PublicPlaceCatalog
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_place_scoring import (
    MAX_INPUT_TOKENS,
    build_scoring_requests,
    estimate_input_tokens,
)

SHA = "0" * 64
EVIDENCE_ID = f"evidence:{'1' * 64}"
PLACE_ID = f"public:gyeongju:{'2' * 64}"
REPO_ROOT = Path(__file__).resolve().parents[3]
PUBLIC_CATALOG_PATH = REPO_ROOT / "artifacts/public/catalog/public-place-catalog-v1.json"
PUBLIC_EVIDENCE_PATH = REPO_ROOT / "artifacts/public/catalog/public-evidence-inventory-v1.json"


def request_payload() -> dict[str, object]:
    fields: dict[str, object] = {
        "schema_version": "mvp-place-scoring-request.v2",
        "model": "glm-5.3-flash",
        "place": {
            "place_id": PLACE_ID,
            "name_ko": "합성 공개 장소",
            "category": "관광지",
            "administrative_area": "경주시",
            "address_ko": "경주시 합성로 1",
            "latitude": 35.8,
            "longitude": 129.2,
        },
        "evidence": [{"evidence_id": EVIDENCE_ID, "excerpt": "합성 공개 근거"}],
        "rubric": {dimension: f"{dimension} 공개 평가 기준" for dimension in SCORING_DIMENSIONS},
    }
    return {**fields, "request_sha256": canonical_sha256(fields)}


def response_payload() -> dict[str, object]:
    return {
        "H": 50,
        "E": 51,
        "R": 52,
        **{dimension: 2 for dimension in SCORING_DIMENSIONS[3:15]},
        **{dimension: 50 for dimension in SCORING_DIMENSIONS[15:]},
        "confidence": 40,
        "justifications": [
            {
                "dimension": dimension,
                "evidence_ids": [EVIDENCE_ID],
                "justification_ko": f"{dimension} 합성 근거",
            }
            for dimension in SCORING_DIMENSIONS
        ],
    }


def test_real_public_100_builds_byte_stable_bounded_request_corpus() -> None:
    catalog = PublicPlaceCatalog.model_validate_json(PUBLIC_CATALOG_PATH.read_bytes())
    evidence = PublicEvidenceInventory.model_validate_json(PUBLIC_EVIDENCE_PATH.read_bytes())

    first = build_scoring_requests(catalog, evidence)
    second = build_scoring_requests(catalog, evidence)

    assert first == second
    assert len(first) == 100
    assert tuple(row.place.place_id for row in first) == tuple(
        sorted(row.place.place_id for row in first)
    )
    assert all(tuple(row.rubric) == SCORING_DIMENSIONS for row in first)
    assert all(dict(row.rubric) == PUBLIC_SCORING_RUBRIC for row in first)
    assert all(
        estimate_input_tokens(canonical_json_bytes(row.model_dump(mode="json")))
        <= MAX_INPUT_TOKENS
        for row in first
    )
    encoded = canonical_json_bytes([row.model_dump(mode="json") for row in first]).lower()
    for forbidden in (b"authorization", b"api_key", b"servicekey", b"openrouter_api"):
        assert forbidden not in encoded
    assert len(MVP_SCORING_PROMPT_SHA256) == 64


def test_request_exact_allowlist_and_hash() -> None:
    request = PublicScoringRequest.model_validate(request_payload())
    assert request.place.place_id == PLACE_ID
    with pytest.raises(ValidationError):
        PublicScoringRequest.model_validate({**request_payload(), "confidence": 90})


@pytest.mark.parametrize(
    "forbidden",
    [
        "blind_membership",
        "split",
        "user_id",
        "session",
        "photo_url",
        "secret",
        "authorization",
        "api_key",
        "existing_score",
        "internal_scores",
        "confidence",
        "labels",
        "reviewer_notes",
        "private_path",
    ],
)
def test_recursive_forbidden_field_matrix(forbidden: str) -> None:
    with pytest.raises(ValueError, match="forbidden provider field"):
        reject_forbidden_fields({"public": {"nested": [{forbidden: "forbidden"}]}})


def test_response_requires_exact_shape_ranges_and_evidence_order() -> None:
    response = ProviderScoringResponse.model_validate(response_payload())
    assert len(response.justifications) == 21
    malformed = response_payload()
    malformed["H1"] = 5
    with pytest.raises(ValidationError):
        ProviderScoringResponse.model_validate(malformed)
    missing = response_payload()
    missing["justifications"] = missing["justifications"][:-1]  # type: ignore[index]
    with pytest.raises(ValidationError):
        ProviderScoringResponse.model_validate(missing)
    extra = {**response_payload(), "place_id": PLACE_ID}
    with pytest.raises(ValidationError):
        ProviderScoringResponse.model_validate(extra)


def test_payload_contains_no_forbidden_field_names() -> None:
    encoded = json.dumps(
        PublicScoringRequest.model_validate(request_payload()).model_dump(mode="json")
    )
    for forbidden in ("BLIND", "api_key", "authorization", "confidence", "reviewer"):
        assert forbidden.lower() not in encoded.lower()
