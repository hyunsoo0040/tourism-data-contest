from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.contracts.image_observation import (
    APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
)
from itda.contracts.place_profile import SubattributeId
from itda.contracts.vlm_inference import (
    BILINGUAL_PROMPT_CANDIDATE,
    GLM5V_API_CONTRACT_PATH,
    GLM5V_ENDPOINT,
    GLM5V_MODEL,
    KOREAN_PROMPT_CANDIDATE,
    AttributePromptRoute,
    FrozenPromptRouting,
    Glm5VApiContract,
    Glm5VProviderConfig,
    InferenceAttempt,
    InferenceTerminalStatus,
    PredictionFreezeReceipt,
    SafeInferenceRequest,
    VlmPredictionManifest,
    load_glm5v_api_contract,
    seal_inference_contract,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
REFS = tuple(f"selected-image:{digit * 64}" for digit in ("1", "2", "3", "4", "5"))
NOW = datetime(2026, 8, 7, tzinfo=UTC)


def _utc_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _routing() -> FrozenPromptRouting:
    return FrozenPromptRouting(
        strategy="GLOBAL",
        global_prompt_id=KOREAN_PROMPT_CANDIDATE.prompt_id,
        attribute_routes=(),
    )


def _config_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "itda.vlm-provider-config.v1",
        "provider": "ZHIPU_BIGMODEL",
        "endpoint": GLM5V_ENDPOINT,
        "requested_model": GLM5V_MODEL,
        "model_revision": "UNKNOWN_PROVIDER_ALIAS_MUTABILITY",
        "api_contract_sha256": load_glm5v_api_contract().contract_sha256,
        "prompt_candidates": [
            KOREAN_PROMPT_CANDIDATE.model_dump(mode="json"),
            BILINGUAL_PROMPT_CANDIDATE.model_dump(mode="json"),
        ],
        "prompt_routing": _routing().model_dump(mode="json"),
        "observation_schema_version": "photo-attributes.v2",
        "observation_schema_sha256": APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
        "generation": {
            "stream": False,
            "thinking_type": "disabled",
            "do_sample": False,
            "max_tokens": 2048,
            "tools": None,
            "response_format": None,
        },
        "timeouts": {
            "connect_seconds": 10,
            "read_seconds": 180,
            "write_seconds": 60,
            "pool_seconds": 10,
        },
        "retry_policy": {
            "max_total_attempts": 3,
            "retryable_http_statuses": [429, 500, 502, 503, 504],
            "retryable_transport_errors": [
                "CONNECT_ERROR",
                "CONNECT_TIMEOUT",
                "READ_ERROR",
                "READ_TIMEOUT",
                "WRITE_ERROR",
                "WRITE_TIMEOUT",
            ],
            "semantic_repair_attempts": 0,
        },
        "preprocessing_manifest_sha256": SHA_A,
        "selection_manifest_sha256": SHA_B,
        "code_sha256": "c" * 64,
        "config_source_sha256": "d" * 64,
        "created_at": _utc_text(NOW),
    }
    return seal_inference_contract(payload, digest_field="config_sha256")


def _request_payload(*, refs: tuple[str, ...] = REFS[:2]) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "itda.vlm-safe-request.v1",
        "place_ref": f"place:{'e' * 64}",
        "provider_config_sha256": "f" * 64,
        "selection_manifest_sha256": SHA_B,
        "prompt_id": KOREAN_PROMPT_CANDIDATE.prompt_id,
        "selected_image_refs": list(refs),
        "selected_image_sha256": [str(index) * 64 for index in range(1, len(refs) + 1)],
        "created_at": _utc_text(NOW),
    }
    return seal_inference_contract(payload, digest_field="semantic_request_sha256")


def test_official_api_snapshot_is_safe_hash_bound_and_explicit_about_unknowns() -> None:
    snapshot = load_glm5v_api_contract()
    raw = json.loads(Path(GLM5V_API_CONTRACT_PATH).read_text(encoding="utf-8"))

    assert snapshot.endpoint == GLM5V_ENDPOINT
    assert snapshot.model == GLM5V_MODEL
    assert snapshot.multimodal_content_shape == (
        "messages[].content[{type:image_url,image_url:{url}}]"
    )
    assert snapshot.strict_vision_json_mode == "UNKNOWN"
    assert snapshot.documented_max_image_count == "UNKNOWN"
    assert snapshot.retention_terms == "UNKNOWN"
    assert snapshot.numeric_pricing == "UNKNOWN"
    assert len(snapshot.sources) >= 3
    assert all(source.url.startswith("https://docs.bigmodel.cn/") for source in snapshot.sources)
    assert all(len(source.safe_facts_sha256) == 64 for source in snapshot.sources)
    assert snapshot.contract_sha256 == raw["contract_sha256"]

    raw["numeric_pricing"] = "invented-price"
    with pytest.raises(ValidationError):
        Glm5VApiContract.model_validate(raw)


def test_provider_config_freezes_prompts_schema_generation_timeout_and_retry_policy() -> None:
    restored = Glm5VProviderConfig.model_validate(_config_payload())

    assert restored.prompt_candidates == (
        KOREAN_PROMPT_CANDIDATE,
        BILINGUAL_PROMPT_CANDIDATE,
    )
    assert restored.observation_schema_sha256 == APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256
    assert restored.generation.stream is False
    assert restored.generation.do_sample is False
    assert restored.generation.tools is None
    assert restored.generation.response_format is None
    assert restored.generation.max_tokens == 2048
    assert restored.retry_policy.max_total_attempts == 3
    assert restored.retry_policy.semantic_repair_attempts == 0

    hostile = _config_payload()
    hostile["observation_schema_sha256"] = "0" * 64
    hostile = seal_inference_contract(hostile, digest_field="config_sha256")
    with pytest.raises(ValidationError):
        Glm5VProviderConfig.model_validate(hostile)


def test_prompt_routing_is_global_or_complete_predeclared_attribute_routing() -> None:
    global_route = _routing()
    assert global_route.global_prompt_id == KOREAN_PROMPT_CANDIDATE.prompt_id

    attribute_route = FrozenPromptRouting(
        strategy="ATTRIBUTE_PREDECLARED",
        global_prompt_id=None,
        attribute_routes=tuple(
            AttributePromptRoute(
                attribute_id=attribute,
                prompt_id=(
                    KOREAN_PROMPT_CANDIDATE.prompt_id
                    if attribute.value.startswith("H")
                    else BILINGUAL_PROMPT_CANDIDATE.prompt_id
                ),
            )
            for attribute in SubattributeId
        ),
    )
    assert tuple(row.attribute_id for row in attribute_route.attribute_routes) == tuple(
        SubattributeId
    )

    with pytest.raises(ValidationError):
        FrozenPromptRouting(
            strategy="ATTRIBUTE_PREDECLARED",
            global_prompt_id=None,
            attribute_routes=attribute_route.attribute_routes[:-1],
        )


def test_safe_request_is_one_place_one_to_five_representatives_and_self_hashed() -> None:
    restored = SafeInferenceRequest.model_validate(_request_payload())
    assert len(restored.selected_image_refs) == 2
    assert restored.place_ref.startswith("place:")

    for refs in ((), REFS + (f"selected-image:{'6' * 64}",)):
        with pytest.raises(ValidationError):
            SafeInferenceRequest.model_validate(_request_payload(refs=refs))

    hostile = _request_payload()
    hostile["selected_image_refs"] = [REFS[0], REFS[0]]
    hostile = seal_inference_contract(hostile, digest_field="semantic_request_sha256")
    with pytest.raises(ValidationError):
        SafeInferenceRequest.model_validate(hostile)


def test_prediction_manifest_requires_complete_terminal_lineage() -> None:
    attempt = InferenceAttempt(
        attempt_number=1,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        outcome="VALIDATED",
        retry_disposition="DO_NOT_RETRY",
        http_status=200,
        error_code=None,
        provider_request_id="provider-request-1",
        returned_model=GLM5V_MODEL,
        finish_reason="stop",
        safe_response_sha256=SHA_A,
        usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    )
    payload: dict[str, object] = {
        "schema_version": "itda.vlm-prediction-manifest.v1",
        "semantic_request_sha256": SHA_B,
        "provider_config_sha256": "c" * 64,
        "attempts": [attempt.model_dump(mode="json")],
        "terminal_status": InferenceTerminalStatus.VALID.value,
        "observation_sha256": "d" * 64,
        "completed_at": _utc_text(NOW + timedelta(seconds=1)),
    }
    restored = VlmPredictionManifest.model_validate(
        seal_inference_contract(payload, digest_field="prediction_manifest_sha256")
    )
    assert restored.terminal_status is InferenceTerminalStatus.VALID

    hostile = deepcopy(payload)
    hostile["terminal_status"] = InferenceTerminalStatus.ANALYSIS_FAILED.value
    hostile["observation_sha256"] = None
    with pytest.raises(ValidationError):
        VlmPredictionManifest.model_validate(
            seal_inference_contract(hostile, digest_field="prediction_manifest_sha256")
        )


@pytest.mark.parametrize(
    "mutation",
    ("early_terminal", "overlap", "failed_response_lineage"),
)
def test_prediction_manifest_rejects_impossible_retry_histories(mutation: str) -> None:
    first = {
        "attempt_number": 1,
        "started_at": _utc_text(NOW),
        "completed_at": _utc_text(NOW + timedelta(seconds=2)),
        "outcome": "HTTP_ERROR",
        "retry_disposition": "RETRY",
        "http_status": 503,
        "error_code": "HTTP_503",
        "provider_request_id": None,
        "returned_model": None,
        "finish_reason": None,
        "safe_response_sha256": SHA_A,
        "usage": None,
    }
    second = {
        "attempt_number": 2,
        "started_at": _utc_text(NOW + timedelta(seconds=3)),
        "completed_at": _utc_text(NOW + timedelta(seconds=4)),
        "outcome": "HTTP_ERROR",
        "retry_disposition": "DO_NOT_RETRY",
        "http_status": 400,
        "error_code": "HTTP_400",
        "provider_request_id": None,
        "returned_model": None,
        "finish_reason": None,
        "safe_response_sha256": SHA_B,
        "usage": None,
    }
    if mutation == "early_terminal":
        first["retry_disposition"] = "DO_NOT_RETRY"
    elif mutation == "overlap":
        second["started_at"] = _utc_text(NOW + timedelta(seconds=1))
    else:
        first["provider_request_id"] = "impossible-response-lineage"
    payload: dict[str, object] = {
        "schema_version": "itda.vlm-prediction-manifest.v1",
        "semantic_request_sha256": SHA_B,
        "provider_config_sha256": "c" * 64,
        "attempts": [first, second],
        "terminal_status": InferenceTerminalStatus.ANALYSIS_FAILED.value,
        "observation_sha256": None,
        "completed_at": second["completed_at"],
    }
    with pytest.raises(ValidationError):
        VlmPredictionManifest.model_validate(
            seal_inference_contract(payload, digest_field="prediction_manifest_sha256")
        )


@pytest.mark.parametrize(
    ("outcome", "updates", "message"),
    [
        (
            "SEMANTIC_INVALID",
            {"http_status": None},
            "exact terminal response lineage",
        ),
        (
            "AUTHORITY_INVALID",
            {"http_status": 418, "safe_response_sha256": SHA_A},
            "exact terminal response lineage",
        ),
        (
            "RESPONSE_ENVELOPE_INVALID",
            {"retry_disposition": "RETRY"},
            "exact terminal response lineage",
        ),
        (
            "HTTP_ERROR",
            {"http_status": 418, "retry_disposition": "RETRY"},
            "retry authority",
        ),
    ],
)
def test_failed_attempt_outcome_matrix_rejects_one_field_drift(
    outcome: str,
    updates: dict[str, object],
    message: str,
) -> None:
    baseline_payload: dict[str, object] = {
        "attempt_number": 1,
        "started_at": NOW,
        "completed_at": NOW + timedelta(seconds=1),
        "outcome": outcome,
        "retry_disposition": "DO_NOT_RETRY",
        "http_status": 200 if outcome != "HTTP_ERROR" else 400,
        "error_code": "SAFE_FAILURE",
        "provider_request_id": None,
        "returned_model": None,
        "finish_reason": None,
        "safe_response_sha256": SHA_B,
        "usage": None,
    }
    baseline = InferenceAttempt.model_validate(baseline_payload)
    hostile = baseline.model_dump(mode="json")
    hostile.update(updates)
    with pytest.raises(ValidationError, match=message):
        InferenceAttempt.model_validate(hostile)


def test_prediction_freeze_receipt_is_schema_bound_and_self_hashed() -> None:
    payload: dict[str, object] = {
        "schema_version": "itda.vlm-prediction-freeze-receipt.v1",
        "semantic_request_sha256": SHA_A,
        "prediction_manifest_sha256": SHA_B,
        "observation_schema_sha256": APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
        "frozen_at": _utc_text(NOW),
    }
    receipt = PredictionFreezeReceipt.model_validate(
        seal_inference_contract(payload, digest_field="freeze_receipt_sha256")
    )
    assert receipt.observation_schema_sha256 == APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256

    hostile = receipt.model_dump(mode="json")
    hostile["prediction_manifest_sha256"] = "9" * 64
    with pytest.raises(ValidationError, match="freeze_receipt_sha256"):
        PredictionFreezeReceipt.model_validate(hostile)
