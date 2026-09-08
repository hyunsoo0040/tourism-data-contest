"""Provider-free planning and bounded execution for MVP place scoring."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Protocol, cast

import httpx
from pydantic import ValidationError

from itda.contracts.mvp_place_scoring import (
    GLM_CODING_ENDPOINT,
    GLM_MODEL,
    LEGACY_OPENROUTER_MODEL,
    MVP_SCORING_PROMPT_V2,
    PUBLIC_SCORING_RUBRIC,
    SCORING_DIMENSIONS,
    BoundScoringResult,
    LocalConditionScores,
    OpenRouterPricingSnapshot,
    ProviderScoringResponse,
    ProviderWireScoringResponse,
    PublicScoringRequest,
    reject_forbidden_fields,
)
from itda.contracts.mvp_public_catalog import PublicEvidenceInventory, PublicPlaceCatalog
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REQUEST_TIMEOUT_SECONDS = 300
MAX_INPUT_TOKENS = 8_192
MAX_OUTPUT_TOKENS = 16_384
REASONING_EFFORT = "max"
MAX_RESPONSE_BYTES = 256 * 1024
MAX_CALLS = 200
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
OPENROUTER_DATA_POLICY_URL = "https://openrouter.ai/docs/policies/data-policies"
PREFLIGHT_TIMEOUT_SECONDS = 15
PREFLIGHT_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
SAFE_PROVIDER_ERROR_CODES = frozenset(
    {
        "GLM_REQUEST_FAILED",
        "GLM_TIMEOUT",
        "GLM_ENVELOPE_INVALID",
        "GLM_CONTENT_INVALID",
        "GLM_MODEL_MISMATCH",
        "GLM_FINISH_REASON_INVALID",
        "GLM_CREDENTIAL_REFLECTED",
        "GLM_HTTP_AUTH_REJECTED",
        "GLM_HTTP_QUOTA_REJECTED",
        "GLM_HTTP_POLICY_REJECTED",
        "GLM_HTTP_REQUEST_REJECTED",
        "GLM_HTTP_SERVER_ERROR",
        "RESPONSE_BODY_LIMIT_EXCEEDED",
        "PROVIDER_RESPONSE_JSON_INVALID",
        "PROVIDER_RESPONSE_SCORE_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_COUNT_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_DIMENSION_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_EVIDENCE_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_TEXT_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_SHAPE_INVALID",
        "PROVIDER_RESPONSE_SHAPE_INVALID",
        "PROVIDER_EVIDENCE_REFERENCE_INVALID",
        "PROCESS_INTERRUPTED_UNKNOWN_OUTCOME",
    }
)
CONSUMED_V1_RUN_PLAN_SHA256 = (
    "f031bd15b6e07c3b4523a81667b824600f4012b2d53941a4a591805da1e7f069"
)
CONSUMED_V2_RUN_PLAN_SHA256 = (
    "b493e3b86ed0835210ccacb7a6bd4ee90a724f50ce8fc63eff91a83d0bae3564"
)
CONSUMED_GLM_RUN_PLAN_SHA256 = (
    "1ee70778bb098b63bb7368bfe3aea26ef5c93f8ff6f1609608db2b3487011874"
)
CONSUMED_INTERRUPTED_RUN_PLAN_SHA256S = frozenset(
    {
        CONSUMED_V1_RUN_PLAN_SHA256,
        CONSUMED_V2_RUN_PLAN_SHA256,
        CONSUMED_GLM_RUN_PLAN_SHA256,
    }
)


class MvpScoringError(RuntimeError):
    pass


class ScoringTransport(Protocol):
    def score(
        self,
        request: PublicScoringRequest,
        *,
        timeout_seconds: int,
        max_tokens: int,
    ) -> bytes: ...

    def close(self) -> None: ...


class GlmCodingScoringTransport:
    def __init__(self, api_key: str, *, http_client: httpx.Client | None = None) -> None:
        if not api_key:
            raise MvpScoringError("GLM_CREDENTIAL_ABSENT")
        self._api_key = api_key
        self._client = http_client or httpx.Client(follow_redirects=False, trust_env=False)

    def close(self) -> None:
        self._client.close()

    def score(
        self,
        request: PublicScoringRequest,
        *,
        timeout_seconds: int,
        max_tokens: int,
    ) -> bytes:
        payload = _scoring_payload(request, max_tokens=max_tokens)
        encoded_payload = canonical_json_bytes(payload)
        if estimate_input_tokens(encoded_payload) > MAX_INPUT_TOKENS:
            raise MvpScoringError("REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED")
        try:
            with self._client.stream(
                "POST",
                GLM_CODING_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                content=encoded_payload,
                timeout=timeout_seconds,
                follow_redirects=False,
            ) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise MvpScoringError("RESPONSE_BODY_LIMIT_EXCEEDED")
        except MvpScoringError:
            raise
        except httpx.TimeoutException as error:
            raise MvpScoringError("GLM_TIMEOUT") from error
        except httpx.HTTPStatusError as error:
            raise MvpScoringError(_glm_http_error_code(error.response.status_code)) from error
        except httpx.HTTPError as error:
            raise MvpScoringError("GLM_REQUEST_FAILED") from error
        raw = bytes(body)
        if self._api_key.encode() in raw:
            raise MvpScoringError("GLM_CREDENTIAL_REFLECTED")
        try:
            envelope = json.loads(raw)
            choice = envelope["choices"][0]
            message = choice["message"]
            content = message["content"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            raise MvpScoringError("GLM_ENVELOPE_INVALID") from error
        if envelope.get("model") != GLM_MODEL:
            raise MvpScoringError("GLM_MODEL_MISMATCH")
        if choice.get("finish_reason") != "stop":
            raise MvpScoringError("GLM_FINISH_REASON_INVALID")
        if not isinstance(content, str):
            raise MvpScoringError("GLM_CONTENT_INVALID")
        return content.encode("utf-8")


def _glm_http_error_code(status_code: int) -> str:
    if status_code in {401, 403}:
        return "GLM_HTTP_AUTH_REJECTED"
    if status_code == 429:
        return "GLM_HTTP_QUOTA_REJECTED"
    if status_code == 451:
        return "GLM_HTTP_POLICY_REJECTED"
    if 400 <= status_code <= 499:
        return "GLM_HTTP_REQUEST_REJECTED"
    if 500 <= status_code <= 599:
        return "GLM_HTTP_SERVER_ERROR"
    return "GLM_REQUEST_FAILED"


@dataclass(frozen=True)
class ScoringAttemptEvent:
    run_plan_sha256: str
    place_id: str
    request_sha256: str
    attempt_number: int
    status: str
    reason: str | None = None


@dataclass(frozen=True)
class BatchOutcome:
    results: Mapping[str, BoundScoringResult]
    failed: Mapping[str, str]
    attempted_place_ids: tuple[str, ...]
    call_count: int
    attempt_counts: Mapping[str, int]


@dataclass(frozen=True)
class DiagnosticOutcome:
    result: BoundScoringResult | None
    failure: str | None


def _mvp_prompt_text() -> str:
    return (MVP_SCORING_PROMPT_V2)


def _scoring_payload(
    request: PublicScoringRequest,
    *,
    max_tokens: int,
) -> dict[str, object]:
    return {
        "model": GLM_MODEL,
        "messages": [
            {"role": "system", "content": _mvp_prompt_text()},
            {
                "role": "user",
                "content": canonical_json_bytes(request.model_dump(mode="json")).decode(),
            },
        ],
        "max_tokens": max_tokens,
        "thinking": {"type": "enabled"},
        "reasoning_effort": REASONING_EFFORT,
        "response_format": {"type": "json_object"},
    }


def build_scoring_requests(
    catalog: PublicPlaceCatalog,
    evidence_inventory: PublicEvidenceInventory,
) -> tuple[PublicScoringRequest, ...]:
    if catalog.evidence_inventory_sha256 != evidence_inventory.inventory_sha256:
        raise MvpScoringError("CATALOG_EVIDENCE_BINDING_MISMATCH")
    evidence_by_id = {row.evidence_id: row for row in evidence_inventory.evidence}
    rows: list[PublicScoringRequest] = []
    for place in catalog.places:
        if not set(place.evidence_ids).issubset(evidence_by_id):
            raise MvpScoringError("CATALOG_EVIDENCE_REFERENCE_INVALID")
        fields = {
            "schema_version": "mvp-place-scoring-request.v2",
            "model": GLM_MODEL,
            "place": {
                "place_id": place.place_id,
                "name_ko": place.name_ko,
                "category": place.category,
                "administrative_area": place.administrative_area,
                "address_ko": place.address_ko,
                "latitude": place.latitude,
                "longitude": place.longitude,
            },
            "evidence": tuple(
                {
                    "evidence_id": evidence_id,
                    "excerpt": evidence_by_id[evidence_id].excerpt,
                }
                for evidence_id in place.evidence_ids
            ),
            "rubric": PUBLIC_SCORING_RUBRIC,
        }
        reject_forbidden_fields(fields)
        rows.append(
            PublicScoringRequest.model_validate(
                {**fields, "request_sha256": canonical_sha256(fields)}
            )
        )
    ordered = tuple(sorted(rows, key=lambda row: row.place.place_id))
    if len(ordered) != 100:
        raise MvpScoringError("REQUEST_CORPUS_REQUIRES_EXACTLY_100_PLACES")
    return ordered


def fetch_openrouter_pricing_snapshot(
    *,
    retrieved_at: datetime,
    corpus_file_sha256: str,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
    response_schema_sha256: str,
) -> OpenRouterPricingSnapshot:
    require_live_network_allowed()
    import httpx

    with (
        httpx.Client(follow_redirects=False, trust_env=False) as client,
        client.stream(
            "GET",
            OPENROUTER_MODELS_URL,
            timeout=PREFLIGHT_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={"Accept": "application/json"},
        ) as response,
    ):
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > PREFLIGHT_RESPONSE_MAX_BYTES:
                raise MvpScoringError("PREFLIGHT_RESPONSE_BODY_LIMIT_EXCEEDED")
    return parse_openrouter_pricing_snapshot(
        bytes(body),
        retrieved_at=retrieved_at,
        corpus_file_sha256=corpus_file_sha256,
        catalog_sha256=catalog_sha256,
        evidence_inventory_sha256=evidence_inventory_sha256,
        prompt_sha256=prompt_sha256,
        response_schema_sha256=response_schema_sha256,
    )


def parse_openrouter_pricing_snapshot(
    raw: bytes,
    *,
    retrieved_at: datetime,
    corpus_file_sha256: str,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
    response_schema_sha256: str,
) -> OpenRouterPricingSnapshot:
    if not raw or len(raw) > PREFLIGHT_RESPONSE_MAX_BYTES:
        raise MvpScoringError("PREFLIGHT_RESPONSE_BODY_INVALID")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise MvpScoringError("PREFLIGHT_RESPONSE_INVALID") from error
    data = payload.get("data") if isinstance(payload, Mapping) else None
    if not isinstance(data, list):
        raise MvpScoringError("PREFLIGHT_MODELS_MISSING")
    matches = [
        row
        for row in data
        if isinstance(row, Mapping) and row.get("id") == LEGACY_OPENROUTER_MODEL
    ]
    if len(matches) != 1:
        raise MvpScoringError("PREFLIGHT_MODEL_NOT_UNIQUE")
    model = matches[0]
    pricing = model.get("pricing")
    parameters = model.get("supported_parameters")
    context_length = model.get("context_length")
    if not isinstance(pricing, Mapping) or not isinstance(parameters, list):
        raise MvpScoringError("PREFLIGHT_MODEL_METADATA_INVALID")
    if not isinstance(context_length, int) or isinstance(context_length, bool):
        raise MvpScoringError("PREFLIGHT_CONTEXT_LENGTH_INVALID")
    prompt_rate = _decimal_string(pricing.get("prompt"), "PREFLIGHT_PROMPT_PRICE_INVALID")
    completion_rate = _decimal_string(
        pricing.get("completion"), "PREFLIGHT_COMPLETION_PRICE_INVALID"
    )
    internal_reasoning = pricing.get("internal_reasoning")
    if internal_reasoning is None:
        reasoning_rate = completion_rate
        reasoning_basis = "COMPLETION_RATE"
    else:
        reasoning_rate = _decimal_string(
            internal_reasoning, "PREFLIGHT_REASONING_PRICE_INVALID"
        )
        reasoning_basis = "INTERNAL_REASONING"
    request_fee = _decimal_string(pricing.get("request", "0"), "PREFLIGHT_REQUEST_FEE_INVALID")
    fields = {
        "schema_version": "openrouter-public-pricing-snapshot.v1",
        "source_url": OPENROUTER_MODELS_URL,
        "retrieved_at": retrieved_at,
        "model": LEGACY_OPENROUTER_MODEL,
        "context_length": context_length,
        "supported_parameters": tuple(sorted(set(_string_list(parameters)))),
        "prompt_per_token_usd": prompt_rate,
        "completion_per_token_usd": completion_rate,
        "reasoning_per_token_usd": reasoning_rate,
        "reasoning_pricing_basis": reasoning_basis,
        "request_fee_usd": request_fee,
        "data_policy_url": OPENROUTER_DATA_POLICY_URL,
        "raw_response_sha256": hashlib.sha256(raw).hexdigest(),
        "corpus_file_sha256": corpus_file_sha256,
        "catalog_sha256": catalog_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "prompt_sha256": prompt_sha256,
        "response_schema_sha256": response_schema_sha256,
    }
    canonical_fields = {
        **fields,
        "retrieved_at": retrieved_at.isoformat().replace("+00:00", "Z"),
    }
    return OpenRouterPricingSnapshot.model_validate(
        {**fields, "snapshot_sha256": canonical_sha256(canonical_fields)}
    )


def _decimal_string(value: object, error_code: str) -> str:
    if not isinstance(value, str):
        raise MvpScoringError(error_code)
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise MvpScoringError(error_code) from error
    if not parsed.is_finite() or parsed < 0:
        raise MvpScoringError(error_code)
    return format(parsed, "f")


def _string_list(values: list[object]) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value for value in values):
        raise MvpScoringError("PREFLIGHT_SUPPORTED_PARAMETERS_INVALID")
    return tuple(cast(str, value) for value in values)


def estimate_input_tokens(payload: bytes) -> int:
    return (len(payload) + 3) // 4


def _is_safe_provider_error_code(value: object) -> bool:
    return isinstance(value, str) and (
        value in SAFE_PROVIDER_ERROR_CODES
        or (
            value.startswith("OPENROUTER_HTTP_")
            and value.removeprefix("OPENROUTER_HTTP_").isdigit()
            and 100 <= int(value.removeprefix("OPENROUTER_HTTP_")) <= 599
        )
    )


def redact_error(error: BaseException) -> str:
    if isinstance(error, MvpScoringError) and _is_safe_provider_error_code(str(error)):
        return str(error)
    return "PROVIDER_ATTEMPT_FAILED"


def project_local_conditions(response: ProviderScoringResponse) -> LocalConditionScores:
    def bounded(value: int) -> int:
        return max(0, min(100, value))

    return LocalConditionScores(
        visit_date_time=bounded((response.M6 + response.E) // 2),
        companions=bounded(100 - abs(response.M2 - 50) * 2),
        transport=bounded(100 - response.M5 // 2),
        walking=bounded(response.M5),
        indoor_outdoor=bounded((response.R + (100 - response.M1)) // 2),
        crowd=bounded(100 - response.M3),
    )


def _strip_json_fence(raw_response: bytes) -> bytes:
    for prefix in (b"```json\n", b"```\n"):
        if raw_response.startswith(prefix) and raw_response.endswith(b"\n```"):
            content = raw_response[len(prefix) : -4]
            if content.startswith(b"{") and content.endswith(b"}"):
                return content
    return raw_response


def bind_response(
    request: PublicScoringRequest,
    raw_response: bytes,
    *,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
) -> BoundScoringResult:
    if len(raw_response) > MAX_RESPONSE_BYTES:
        raise MvpScoringError("RESPONSE_BODY_LIMIT_EXCEEDED")
    try:
        parsed = json.loads(raw_response)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise MvpScoringError("PROVIDER_RESPONSE_JSON_INVALID") from error
    try:
        wire = ProviderWireScoringResponse.model_validate(parsed)
    except ValidationError as error:
        issues = error.errors(include_input=False)
        locations = tuple(issue["loc"] for issue in issues)
        if any(location and str(location[0]) == "justifications" for location in locations):
            if any("evidence_ids" in tuple(map(str, location)) for location in locations):
                code = "PROVIDER_RESPONSE_JUSTIFICATION_EVIDENCE_INVALID"
            elif any("justification_ko" in tuple(map(str, location)) for location in locations):
                code = "PROVIDER_RESPONSE_JUSTIFICATION_TEXT_INVALID"
            else:
                code = "PROVIDER_RESPONSE_JUSTIFICATION_SHAPE_INVALID"
        elif any(location and str(location[0]) in SCORING_DIMENSIONS for location in locations):
            code = "PROVIDER_RESPONSE_SCORE_INVALID"
        else:
            code = "PROVIDER_RESPONSE_SHAPE_INVALID"
        raise MvpScoringError(code) from error
    score_fields = {
        dimension: getattr(wire, dimension) for dimension in SCORING_DIMENSIONS
    }
    response = ProviderScoringResponse.model_validate(
        {
            **score_fields,
            "confidence": wire.confidence,
            "justifications": tuple(
                {
                    "dimension": dimension,
                    "evidence_ids": tuple(
                        sorted(getattr(wire.justifications, dimension).evidence_ids)
                    ),
                    "justification_ko": getattr(
                        wire.justifications, dimension
                    ).justification_ko,
                }
                for dimension in SCORING_DIMENSIONS
            ),
        }
    )
    parsed = response.model_dump(mode="json")
    allowed = {row.evidence_id for row in request.evidence}
    if any(not set(row.evidence_ids).issubset(allowed) for row in response.justifications):
        raise MvpScoringError("PROVIDER_EVIDENCE_REFERENCE_INVALID")
    condition_scores = project_local_conditions(response)
    fields = {
        "schema_version": "mvp-place-scoring-result.v2",
        "place_id": request.place.place_id,
        "request_sha256": request.request_sha256,
        "catalog_sha256": catalog_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "model": GLM_MODEL,
        "prompt_sha256": prompt_sha256,
        "response_sha256": canonical_sha256(parsed),
        "scores": response,
        "condition_scores": condition_scores,
    }
    return BoundScoringResult.model_validate(
        {
            **fields,
            "result_sha256": canonical_sha256(
                {
                    **fields,
                    "scores": response.model_dump(mode="json"),
                    "condition_scores": condition_scores.model_dump(mode="json"),
                }
            ),
        }
    )


def verify_requests_match_run_plan(
    requests: Sequence[PublicScoringRequest],
    plan: Mapping[str, object],
) -> None:
    verify_run_plan(plan)
    ordered = tuple(sorted(requests, key=lambda row: row.place.place_id))
    if [row.place.place_id for row in ordered] != plan.get("place_ids"):
        raise MvpScoringError("RUN_PLAN_PLACE_BINDING_MISMATCH")
    if [row.request_sha256 for row in ordered] != plan.get("place_request_sha256"):
        raise MvpScoringError("RUN_PLAN_REQUEST_BINDING_MISMATCH")


def build_run_plan(
    requests: Sequence[PublicScoringRequest],
    *,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
    corpus_file_sha256: str,
    entitlement_snapshot_sha256: str,
    canary_plan_sha256: str,
    canary_outcome_sha256: str,
) -> dict[str, object]:
    ordered = tuple(sorted(requests, key=lambda row: row.place.place_id))
    if len(ordered) != 100 or len({row.place.place_id for row in ordered}) != 100:
        raise MvpScoringError("RUN_PLAN_REQUIRES_EXACTLY_100_PLACES")
    if any(
        estimate_input_tokens(
            canonical_json_bytes(_scoring_payload(row, max_tokens=MAX_OUTPUT_TOKENS))
        )
        > MAX_INPUT_TOKENS
        for row in ordered
    ):
        raise MvpScoringError("REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED")
    payload: dict[str, object] = {
        "schema_version": "mvp-place-scoring-run-plan.v3",
        "endpoint": GLM_CODING_ENDPOINT,
        "model": GLM_MODEL,
        "catalog_sha256": catalog_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "prompt_sha256": prompt_sha256,
        "corpus_file_sha256": corpus_file_sha256,
        "entitlement_snapshot_sha256": entitlement_snapshot_sha256,
        "canary_plan_sha256": canary_plan_sha256,
        "canary_outcome_sha256": canary_outcome_sha256,
        "place_request_sha256": [row.request_sha256 for row in ordered],
        "place_ids": [row.place.place_id for row in ordered],
        "first_pass_count": 100,
        "retry_limit_per_place": 1,
        "maximum_calls": MAX_CALLS,
        "concurrency": 1,
        "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "maximum_input_tokens": MAX_INPUT_TOKENS,
        "maximum_output_tokens": MAX_OUTPUT_TOKENS,
        "thinking_type": "enabled",
        "reasoning_effort": REASONING_EFFORT,
        "response_format": "json_object",
        "maximum_response_bytes": MAX_RESPONSE_BYTES,
        "pre_attempt_persistence": True,
        "fallback": False,
        "model_discovery": False,
        "pay_as_you_go_fallback": False,
    }
    payload["run_plan_sha256"] = canonical_sha256(payload)
    return payload


def build_continuation_plan(
    requests: Sequence[PublicScoringRequest],
    *,
    predecessor_plan: Mapping[str, object],
    predecessor_attempt_state_sha256: str,
    predecessor_result_manifest: Sequence[Mapping[str, str]],
    consumed_completion_calls: int,
    completed_first_passes: int,
    carried_result_count: int,
    retry_candidate_count: int,
    remaining_first_pass_count: int,
    maximum_new_calls: int,
) -> dict[str, object]:
    predecessor_sha256 = verify_run_plan(predecessor_plan)
    if predecessor_sha256 not in CONSUMED_INTERRUPTED_RUN_PLAN_SHA256S:
        raise MvpScoringError("CONTINUATION_PREDECESSOR_NOT_CONSUMED")
    ordered = tuple(sorted(requests, key=lambda row: row.place.place_id))
    if len(ordered) != 100 or [row.place.place_id for row in ordered] != predecessor_plan.get(
        "place_ids"
    ):
        raise MvpScoringError("CONTINUATION_REQUEST_MEMBERSHIP_INVALID")
    manifest = [dict(row) for row in predecessor_result_manifest]
    payload: dict[str, object] = {
        "schema_version": "mvp-place-scoring-continuation-plan.v1",
        "endpoint": GLM_CODING_ENDPOINT,
        "model": GLM_MODEL,
        "catalog_sha256": predecessor_plan["catalog_sha256"],
        "evidence_inventory_sha256": predecessor_plan["evidence_inventory_sha256"],
        "prompt_sha256": predecessor_plan["prompt_sha256"],
        "corpus_file_sha256": predecessor_plan["corpus_file_sha256"],
        "entitlement_snapshot_sha256": predecessor_plan[
            "entitlement_snapshot_sha256"
        ],
        "canary_plan_sha256": predecessor_plan["canary_plan_sha256"],
        "canary_outcome_sha256": predecessor_plan["canary_outcome_sha256"],
        "place_request_sha256": [row.request_sha256 for row in ordered],
        "place_ids": [row.place.place_id for row in ordered],
        "predecessor_run_plan_sha256": predecessor_sha256,
        "predecessor_attempt_state_sha256": predecessor_attempt_state_sha256,
        "predecessor_result_manifest": manifest,
        "predecessor_result_manifest_sha256": canonical_sha256(manifest),
        "consumed_completion_calls": consumed_completion_calls,
        "completed_first_passes": completed_first_passes,
        "carried_result_count": carried_result_count,
        "retry_candidate_count": retry_candidate_count,
        "remaining_first_pass_count": remaining_first_pass_count,
        "maximum_new_calls": maximum_new_calls,
        "maximum_aggregate_calls": consumed_completion_calls + maximum_new_calls,
        "first_pass_count": 100,
        "retry_limit_per_place": 1,
        "maximum_calls": MAX_CALLS,
        "concurrency": 1,
        "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "maximum_input_tokens": MAX_INPUT_TOKENS,
        "maximum_output_tokens": MAX_OUTPUT_TOKENS,
        "thinking_type": "enabled",
        "reasoning_effort": REASONING_EFFORT,
        "response_format": "json_object",
        "maximum_response_bytes": MAX_RESPONSE_BYTES,
        "pre_attempt_persistence": True,
        "fallback": False,
        "model_discovery": False,
        "pay_as_you_go_fallback": False,
    }
    payload["run_plan_sha256"] = canonical_sha256(payload)
    verify_continuation_plan(payload)
    return payload


def verify_continuation_plan(plan: Mapping[str, object]) -> str:
    expected_fields = {
        "schema_version",
        "endpoint",
        "model",
        "catalog_sha256",
        "evidence_inventory_sha256",
        "prompt_sha256",
        "corpus_file_sha256",
        "entitlement_snapshot_sha256",
        "canary_plan_sha256",
        "canary_outcome_sha256",
        "place_request_sha256",
        "place_ids",
        "predecessor_run_plan_sha256",
        "predecessor_attempt_state_sha256",
        "predecessor_result_manifest",
        "predecessor_result_manifest_sha256",
        "consumed_completion_calls",
        "completed_first_passes",
        "carried_result_count",
        "retry_candidate_count",
        "remaining_first_pass_count",
        "maximum_new_calls",
        "maximum_aggregate_calls",
        "first_pass_count",
        "retry_limit_per_place",
        "maximum_calls",
        "concurrency",
        "timeout_seconds",
        "maximum_input_tokens",
        "maximum_output_tokens",
        "thinking_type",
        "reasoning_effort",
        "response_format",
        "maximum_response_bytes",
        "pre_attempt_persistence",
        "fallback",
        "model_discovery",
        "pay_as_you_go_fallback",
        "run_plan_sha256",
    }
    if set(plan) != expected_fields:
        raise MvpScoringError("CONTINUATION_PLAN_FIELDS_INVALID")
    supplied = plan.get("run_plan_sha256")
    expected = canonical_sha256(
        {key: value for key, value in plan.items() if key != "run_plan_sha256"}
    )
    if supplied != expected:
        raise MvpScoringError("CONTINUATION_PLAN_HASH_INVALID")
    sha_fields = (
        "catalog_sha256",
        "evidence_inventory_sha256",
        "prompt_sha256",
        "corpus_file_sha256",
        "entitlement_snapshot_sha256",
        "canary_plan_sha256",
        "canary_outcome_sha256",
        "predecessor_run_plan_sha256",
        "predecessor_attempt_state_sha256",
        "predecessor_result_manifest_sha256",
        "run_plan_sha256",
    )
    manifest = plan.get("predecessor_result_manifest")
    place_ids = plan.get("place_ids")
    request_hashes = plan.get("place_request_sha256")
    integer_field_names = (
        "consumed_completion_calls",
        "completed_first_passes",
        "carried_result_count",
        "retry_candidate_count",
        "remaining_first_pass_count",
        "maximum_new_calls",
        "maximum_aggregate_calls",
    )
    integer_fields = {field: plan.get(field) for field in integer_field_names}
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in integer_fields.values()
    ):
        raise MvpScoringError("CONTINUATION_PLAN_INVALID")
    integers = cast(dict[str, int], integer_fields)
    if (
        any(not _is_sha256(plan.get(field)) for field in sha_fields)
        or plan.get("schema_version")
        != "mvp-place-scoring-continuation-plan.v1"
        or plan.get("endpoint") != GLM_CODING_ENDPOINT
        or plan.get("model") != GLM_MODEL
        or not isinstance(place_ids, list)
        or len(place_ids) != 100
        or any(not isinstance(value, str) for value in place_ids)
        or place_ids != sorted(place_ids)
        or len(set(cast(list[str], place_ids))) != 100
        or not isinstance(request_hashes, list)
        or len(request_hashes) != 100
        or any(not _is_sha256(value) for value in request_hashes)
        or not isinstance(manifest, list)
        or canonical_sha256(manifest) != plan.get("predecessor_result_manifest_sha256")
        or any(
            not isinstance(row, dict)
            or set(row)
            != {
                "file_name",
                "file_sha256",
                "place_id",
                "request_sha256",
                "result_sha256",
            }
            or not isinstance(row.get("file_name"), str)
            or not isinstance(row.get("place_id"), str)
            or any(
                not _is_sha256(row.get(field))
                for field in ("file_sha256", "request_sha256", "result_sha256")
            )
            for row in manifest
        )
        or integers["completed_first_passes"]
        + integers["remaining_first_pass_count"]
        != 100
        or integers["consumed_completion_calls"]
        != integers["completed_first_passes"]
        or integers["carried_result_count"]
        + integers["retry_candidate_count"]
        != integers["completed_first_passes"]
        or integers["carried_result_count"] != len(manifest)
        or len({row.get("file_name") for row in manifest}) != len(manifest)
        or len({row.get("place_id") for row in manifest}) != len(manifest)
        or any(row.get("place_id") not in place_ids for row in manifest)
        or any(
            row.get("request_sha256")
            != request_hashes[place_ids.index(row.get("place_id"))]
            for row in manifest
        )
        or integers["maximum_new_calls"]
        != 2 * integers["remaining_first_pass_count"]
        + integers["retry_candidate_count"]
        or integers["maximum_aggregate_calls"]
        != integers["consumed_completion_calls"] + integers["maximum_new_calls"]
        or integers["maximum_aggregate_calls"] > MAX_CALLS
        or plan.get("first_pass_count") != 100
        or plan.get("retry_limit_per_place") != 1
        or plan.get("maximum_calls") != MAX_CALLS
        or plan.get("concurrency") != 1
        or plan.get("timeout_seconds") != REQUEST_TIMEOUT_SECONDS
        or plan.get("maximum_input_tokens") != MAX_INPUT_TOKENS
        or plan.get("maximum_output_tokens") != MAX_OUTPUT_TOKENS
        or plan.get("thinking_type") != "enabled"
        or plan.get("reasoning_effort") != REASONING_EFFORT
        or plan.get("response_format") != "json_object"
        or plan.get("maximum_response_bytes") != MAX_RESPONSE_BYTES
        or plan.get("pre_attempt_persistence") is not True
        or plan.get("fallback") is not False
        or plan.get("model_discovery") is not False
        or plan.get("pay_as_you_go_fallback") is not False
    ):
        raise MvpScoringError("CONTINUATION_PLAN_INVALID")
    return (expected)


def verify_run_plan(plan: Mapping[str, object]) -> str:
    if plan.get("schema_version") == "mvp-place-scoring-continuation-plan.v1":
        return verify_continuation_plan(plan)
    supplied = plan.get("run_plan_sha256")
    expected = canonical_sha256(
        {key: value for key, value in plan.items() if key != "run_plan_sha256"}
    )
    if supplied in CONSUMED_INTERRUPTED_RUN_PLAN_SHA256S:
        if supplied != expected:
            raise MvpScoringError("RUN_PLAN_HASH_INVALID")
        return (expected)
    expected_fields = {
        "schema_version",
        "endpoint",
        "model",
        "catalog_sha256",
        "evidence_inventory_sha256",
        "prompt_sha256",
        "corpus_file_sha256",
        "entitlement_snapshot_sha256",
        "canary_plan_sha256",
        "canary_outcome_sha256",
        "place_request_sha256",
        "place_ids",
        "first_pass_count",
        "retry_limit_per_place",
        "maximum_calls",
        "concurrency",
        "timeout_seconds",
        "maximum_input_tokens",
        "maximum_output_tokens",
        "thinking_type",
        "reasoning_effort",
        "response_format",
        "maximum_response_bytes",
        "pre_attempt_persistence",
        "fallback",
        "model_discovery",
        "pay_as_you_go_fallback",
        "run_plan_sha256",
    }
    if set(plan) != expected_fields:
        raise MvpScoringError("RUN_PLAN_FIELDS_INVALID")
    if supplied != expected:
        raise MvpScoringError("RUN_PLAN_HASH_INVALID")
    sha_fields = (
        "catalog_sha256",
        "evidence_inventory_sha256",
        "prompt_sha256",
        "corpus_file_sha256",
        "entitlement_snapshot_sha256",
        "canary_plan_sha256",
        "canary_outcome_sha256",
        "run_plan_sha256",
    )
    if any(not _is_sha256(plan.get(field)) for field in sha_fields):
        raise MvpScoringError("RUN_PLAN_SHA256_INVALID")
    if (
        plan.get("schema_version") != "mvp-place-scoring-run-plan.v3"
        or plan.get("endpoint") != GLM_CODING_ENDPOINT
        or plan.get("model") != GLM_MODEL
        or plan.get("first_pass_count") != 100
        or plan.get("retry_limit_per_place") != 1
        or plan.get("maximum_calls") != MAX_CALLS
        or plan.get("concurrency") != 1
        or plan.get("timeout_seconds") != REQUEST_TIMEOUT_SECONDS
        or plan.get("maximum_input_tokens") != MAX_INPUT_TOKENS
        or plan.get("maximum_output_tokens") != MAX_OUTPUT_TOKENS
        or plan.get("thinking_type") != "enabled"
        or plan.get("reasoning_effort") != REASONING_EFFORT
        or plan.get("response_format") != "json_object"
        or plan.get("maximum_response_bytes") != MAX_RESPONSE_BYTES
        or plan.get("pre_attempt_persistence") is not True
        or plan.get("fallback") is not False
        or plan.get("model_discovery") is not False
        or plan.get("pay_as_you_go_fallback") is not False
    ):
        raise MvpScoringError("RUN_PLAN_BOUNDS_INVALID")
    place_ids = plan.get("place_ids")
    request_hashes = plan.get("place_request_sha256")
    if (
        not isinstance(place_ids, list)
        or place_ids != sorted(place_ids)
        or len(place_ids) != 100
        or len(set(place_ids)) != 100
        or not isinstance(request_hashes, list)
        or len(request_hashes) != 100
        or len(set(request_hashes)) != 100
        or any(not _is_sha256(value) for value in request_hashes)
    ):
        raise MvpScoringError("RUN_PLAN_MEMBERSHIP_INVALID")
    return (expected)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def build_canary_plan(
    request: PublicScoringRequest,
    *,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
    response_schema_sha256: str,
    entitlement_snapshot_sha256: str,
    canary_selection_sha256: str,
) -> dict[str, object]:
    if estimate_input_tokens(
        canonical_json_bytes(_scoring_payload(request, max_tokens=MAX_OUTPUT_TOKENS))
    ) > MAX_INPUT_TOKENS:
        raise MvpScoringError("REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED")
    fields: dict[str, object] = {
        "schema_version": "mvp-place-scoring-canary-plan.v3",
        "endpoint": GLM_CODING_ENDPOINT,
        "model": GLM_MODEL,
        "probe_kind": "PUBLIC_CATALOG_MEMBER_NON_RELEASE_COMPATIBILITY_PROBE",
        "place_id": request.place.place_id,
        "request_sha256": request.request_sha256,
        "catalog_sha256": catalog_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "prompt_sha256": prompt_sha256,
        "response_schema_sha256": response_schema_sha256,
        "entitlement_snapshot_sha256": entitlement_snapshot_sha256,
        "canary_selection_sha256": canary_selection_sha256,
        "maximum_calls": 1,
        "concurrency": 1,
        "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "maximum_input_tokens": MAX_INPUT_TOKENS,
        "maximum_output_tokens": MAX_OUTPUT_TOKENS,
        "thinking_type": "enabled",
        "reasoning_effort": REASONING_EFFORT,
        "response_format": "json_object",
        "maximum_response_bytes": MAX_RESPONSE_BYTES,
        "pre_attempt_persistence": True,
        "fallback": False,
        "model_discovery": False,
        "pay_as_you_go_fallback": False,
    }
    fields["canary_plan_sha256"] = canonical_sha256(fields)
    return fields


def verify_canary_plan(plan: Mapping[str, object]) -> str:
    expected_fields = {
        "schema_version",
        "endpoint",
        "model",
        "probe_kind",
        "place_id",
        "request_sha256",
        "catalog_sha256",
        "evidence_inventory_sha256",
        "prompt_sha256",
        "response_schema_sha256",
        "entitlement_snapshot_sha256",
        "canary_selection_sha256",
        "maximum_calls",
        "concurrency",
        "timeout_seconds",
        "maximum_input_tokens",
        "maximum_output_tokens",
        "thinking_type",
        "reasoning_effort",
        "response_format",
        "maximum_response_bytes",
        "pre_attempt_persistence",
        "fallback",
        "model_discovery",
        "pay_as_you_go_fallback",
        "canary_plan_sha256",
    }
    if set(plan) != expected_fields:
        raise MvpScoringError("CANARY_PLAN_FIELDS_INVALID")
    supplied = plan["canary_plan_sha256"]
    expected = canonical_sha256(
        {key: value for key, value in plan.items() if key != "canary_plan_sha256"}
    )
    if supplied != expected:
        raise MvpScoringError("CANARY_PLAN_HASH_INVALID")
    sha_fields = {
        "request_sha256",
        "catalog_sha256",
        "evidence_inventory_sha256",
        "prompt_sha256",
        "response_schema_sha256",
        "entitlement_snapshot_sha256",
        "canary_selection_sha256",
        "canary_plan_sha256",
    }
    if any(not _is_sha256(plan[field]) for field in sha_fields):
        raise MvpScoringError("CANARY_PLAN_SHA256_INVALID")
    if (
        plan["schema_version"] != "mvp-place-scoring-canary-plan.v3"
        or plan["endpoint"] != GLM_CODING_ENDPOINT
        or plan["model"] != GLM_MODEL
        or plan["probe_kind"]
        != "PUBLIC_CATALOG_MEMBER_NON_RELEASE_COMPATIBILITY_PROBE"
        or plan["maximum_calls"] != 1
        or plan["concurrency"] != 1
        or plan["timeout_seconds"] != REQUEST_TIMEOUT_SECONDS
        or plan["maximum_input_tokens"] != MAX_INPUT_TOKENS
        or plan["maximum_output_tokens"] != MAX_OUTPUT_TOKENS
        or plan["thinking_type"] != "enabled"
        or plan["reasoning_effort"] != REASONING_EFFORT
        or plan["response_format"] != "json_object"
        or plan["maximum_response_bytes"] != MAX_RESPONSE_BYTES
        or plan["pre_attempt_persistence"] is not True
        or plan["fallback"] is not False
        or plan["model_discovery"] is not False
        or plan["pay_as_you_go_fallback"] is not False
    ):
        raise MvpScoringError("CANARY_PLAN_BOUNDS_INVALID")
    return (expected)


def execute_diagnostic(
    request: PublicScoringRequest,
    *,
    transport: ScoringTransport,
    diagnostic_plan_sha256: str,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
    on_attempt: Callable[[ScoringAttemptEvent], None],
    on_result: Callable[[BoundScoringResult], None],
) -> DiagnosticOutcome:
    event = ScoringAttemptEvent(
        run_plan_sha256=diagnostic_plan_sha256,
        place_id=request.place.place_id,
        request_sha256=request.request_sha256,
        attempt_number=1,
        status="STARTED",
    )
    on_attempt(event)
    try:
        raw = transport.score(
            request,
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            max_tokens=MAX_OUTPUT_TOKENS,
        )
        result = bind_response(
            request,
            raw,
            catalog_sha256=catalog_sha256,
            evidence_inventory_sha256=evidence_inventory_sha256,
            prompt_sha256=prompt_sha256,
        )
    except Exception as error:
        reason = redact_error(error)
        on_attempt(
            ScoringAttemptEvent(
                run_plan_sha256=diagnostic_plan_sha256,
                place_id=request.place.place_id,
                request_sha256=request.request_sha256,
                attempt_number=1,
                status="FAILED",
                reason=reason,
            )
        )
        return DiagnosticOutcome(result=None, failure=reason)
    on_result(result)
    on_attempt(
        ScoringAttemptEvent(
            run_plan_sha256=diagnostic_plan_sha256,
            place_id=request.place.place_id,
            request_sha256=request.request_sha256,
            attempt_number=1,
            status="SUCCEEDED",
        )
    )
    return DiagnosticOutcome(result=result, failure=None)


def execute_batch(
    requests: Sequence[PublicScoringRequest],
    *,
    transport: ScoringTransport,
    run_plan_sha256: str,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
    prompt_sha256: str,
    resumed_results: Mapping[str, BoundScoringResult] | None = None,
    resumed_attempt_counts: Mapping[str, int] | None = None,
    on_attempt: Callable[[ScoringAttemptEvent], None] | None = None,
    on_result: Callable[[BoundScoringResult], None] | None = None,
    maximum_new_calls: int = MAX_CALLS,
) -> BatchOutcome:
    ordered = tuple(sorted(requests, key=lambda row: row.place.place_id))
    if len(ordered) != 100 or len({row.place.place_id for row in ordered}) != 100:
        raise MvpScoringError("BATCH_REQUIRES_EXACTLY_100_PLACES")
    results = dict(resumed_results or {})
    by_id = {row.place.place_id: row for row in ordered}
    if not set(results).issubset(by_id):
        raise MvpScoringError("RESUME_RESULT_NOT_IN_PLAN")
    for place_id, result in results.items():
        request = by_id[place_id]
        try:
            validated_result = BoundScoringResult.model_validate(result.model_dump(mode="json"))
        except (ValidationError, ValueError) as error:
            raise MvpScoringError("RESUME_RESULT_BINDING_MISMATCH") from error
        if (
            validated_result.place_id != place_id
            or validated_result.request_sha256 != request.request_sha256
            or validated_result.catalog_sha256 != catalog_sha256
            or validated_result.evidence_inventory_sha256 != evidence_inventory_sha256
            or validated_result.prompt_sha256 != prompt_sha256
            or validated_result.model != GLM_MODEL
        ):
            raise MvpScoringError("RESUME_RESULT_BINDING_MISMATCH")
    failures: dict[str, str] = {}
    attempted: list[str] = []
    attempt_counts = dict(resumed_attempt_counts or {})
    if any(
        place_id not in by_id
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not 0 <= count <= 2
        for place_id, count in attempt_counts.items()
    ):
        raise MvpScoringError("RESUME_ATTEMPT_COUNT_INVALID")
    if any(attempt_counts.get(place_id, 0) == 0 for place_id in results):
        raise MvpScoringError("RESUME_RESULT_ATTEMPT_STATE_MISMATCH")
    if (
        not isinstance(maximum_new_calls, int)
        or isinstance(maximum_new_calls, bool)
        or not 0 <= maximum_new_calls <= MAX_CALLS
    ):
        raise MvpScoringError("MAXIMUM_NEW_CALLS_INVALID")
    call_count = 0

    def emit(place_id: str, status: str, reason: str | None = None) -> None:
        if on_attempt is not None:
            on_attempt(
                ScoringAttemptEvent(
                    run_plan_sha256=run_plan_sha256,
                    place_id=place_id,
                    request_sha256=by_id[place_id].request_sha256,
                    attempt_number=attempt_counts[place_id],
                    status=status,
                    reason=reason,
                )
            )

    def attempt(request: PublicScoringRequest) -> None:
        nonlocal call_count
        place_id = request.place.place_id
        if attempt_counts.get(place_id, 0) >= 2:
            failures[place_id] = "PROVIDER_ATTEMPT_FAILED"
            return
        if call_count >= maximum_new_calls:
            raise MvpScoringError("MAXIMUM_NEW_CALLS_EXCEEDED")
        if (
            estimate_input_tokens(canonical_json_bytes(request.model_dump(mode="json")))
            > MAX_INPUT_TOKENS
        ):
            failures[place_id] = "REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED"
            return
        attempt_counts[place_id] = attempt_counts.get(place_id, 0) + 1
        emit(place_id, "STARTED")
        attempted.append(place_id)
        call_count += 1
        try:
            raw = transport.score(
                request,
                timeout_seconds=REQUEST_TIMEOUT_SECONDS,
                max_tokens=MAX_OUTPUT_TOKENS,
            )
            result = bind_response(
                request,
                raw,
                catalog_sha256=catalog_sha256,
                evidence_inventory_sha256=evidence_inventory_sha256,
                prompt_sha256=prompt_sha256,
            )
        except Exception as error:
            reason = redact_error(error)
            failures[place_id] = reason
            emit(place_id, "FAILED", reason)
            return
        results[place_id] = result
        failures.pop(place_id, None)
        if on_result is not None:
            on_result(result)
        emit(place_id, "SUCCEEDED")

    pending = tuple(row for row in ordered if row.place.place_id not in results)
    for request in pending:
        if attempt_counts.get(request.place.place_id, 0) < 1:
            attempt(request)
        else:
            failures[request.place.place_id] = "PROVIDER_ATTEMPT_FAILED"
    retry_ids = tuple(sorted(failures))
    for place_id in retry_ids:
        if attempt_counts.get(place_id, 0) < 2:
            attempt(by_id[place_id])
    if call_count > MAX_CALLS:
        raise MvpScoringError("MAXIMUM_CALLS_EXCEEDED")
    return BatchOutcome(
        results=dict(sorted(results.items())),
        failed=dict(sorted(failures.items())),
        attempted_place_ids=tuple(attempted),
        call_count=call_count,
        attempt_counts=dict(sorted(attempt_counts.items())),
    )


def result_manifest(
    output_root: Path,
    requests: Sequence[PublicScoringRequest],
) -> tuple[dict[str, str], ...]:
    results = load_resumed_results(output_root, requests)
    rows = []
    for place_id, result in sorted(results.items()):
        file_name = f"{place_id.removeprefix('public:gyeongju:')}.json"
        path = output_root / "results" / file_name
        rows.append(
            {
                "file_name": file_name,
                "file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "place_id": place_id,
                "request_sha256": result.request_sha256,
                "result_sha256": result.result_sha256,
            }
        )
    return tuple(rows)


def prepare_continuation_state(
    *,
    plan: Mapping[str, object],
    predecessor_root: Path,
    output_root: Path,
    requests: Sequence[PublicScoringRequest],
) -> None:
    plan_sha256 = verify_continuation_plan(plan)
    if output_root.exists():
        raise MvpScoringError("CONTINUATION_OUTPUT_ALREADY_EXISTS")
    attempt_path = predecessor_root / "attempt-state.json"
    if hashlib.sha256(attempt_path.read_bytes()).hexdigest() != plan.get(
        "predecessor_attempt_state_sha256"
    ):
        raise MvpScoringError("CONTINUATION_ATTEMPT_STATE_DRIFT")
    if list(result_manifest(predecessor_root, requests)) != plan.get(
        "predecessor_result_manifest"
    ):
        raise MvpScoringError("CONTINUATION_RESULT_MANIFEST_DRIFT")
    state = _read_attempt_state(attempt_path)
    if state is None or state["run_plan_sha256"] != plan.get(
        "predecessor_run_plan_sha256"
    ):
        raise MvpScoringError("CONTINUATION_PREDECESSOR_STATE_INVALID")
    attempts = state["attempts"]
    if not isinstance(attempts, list):
        raise MvpScoringError("CONTINUATION_PREDECESSOR_STATE_INVALID")
    carried_attempts = []
    for value in attempts:
        if not isinstance(value, dict):
            raise MvpScoringError("CONTINUATION_PREDECESSOR_STATE_INVALID")
        row = dict(value)
        if row.get("status") == "STARTED":
            row["status"] = "FAILED"
            row["reason"] = "PROCESS_INTERRUPTED_UNKNOWN_OUTCOME"
        carried_attempts.append(row)
    if (
        len(carried_attempts) != plan.get("consumed_completion_calls")
        or sum(row.get("attempt_number") == 1 for row in carried_attempts)
        != plan.get("completed_first_passes")
    ):
        raise MvpScoringError("CONTINUATION_PREDECESSOR_COUNTS_INVALID")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=output_root.parent)
    )
    try:
        _write_atomic(
            temporary / "attempt-state.json",
            canonical_json_bytes(
                {
                    "schema_version": "mvp-scoring-attempt-state.v1",
                    "run_plan_sha256": plan_sha256,
                    "attempts": carried_attempts,
                }
            )
            + b"\n",
        )
        for row in cast(list[dict[str, str]], plan["predecessor_result_manifest"]):
            source = predecessor_root / "results" / row["file_name"]
            _write_atomic(temporary / "results" / row["file_name"], source.read_bytes())
        os.rename(temporary, output_root)
        directory = os.open(output_root.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            for child in sorted(temporary.rglob("*"), reverse=True):
                if child.is_file():
                    child.unlink()
                elif child.is_dir():
                    child.rmdir()
            temporary.rmdir()


def load_resumed_results(
    output_root: Path,
    requests: Sequence[PublicScoringRequest],
) -> dict[str, BoundScoringResult]:
    if not output_root.exists():
        return {}
    by_id = {row.place.place_id: row for row in requests}
    results: dict[str, BoundScoringResult] = {}
    for path in sorted((output_root / "results").glob("*.json")):
        result = BoundScoringResult.model_validate_json(path.read_bytes())
        request = by_id.get(result.place_id)
        if request is None or result.request_sha256 != request.request_sha256:
            raise MvpScoringError("RESUME_RESULT_BINDING_MISMATCH")
        if path.name != f"{result.place_id.removeprefix('public:gyeongju:')}.json":
            raise MvpScoringError("RESUME_RESULT_FILENAME_INVALID")
        results[result.place_id] = result
    return results


def _read_attempt_state(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise MvpScoringError("ATTEMPT_STATE_INVALID") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "run_plan_sha256", "attempts"}
        or payload.get("schema_version") != "mvp-scoring-attempt-state.v1"
        or not isinstance(payload.get("run_plan_sha256"), str)
        or not isinstance(payload.get("attempts"), list)
    ):
        raise MvpScoringError("ATTEMPT_STATE_INVALID")
    return payload


def load_attempt_counts(
    output_root: Path,
    *,
    run_plan_sha256: str,
    requests: Sequence[PublicScoringRequest],
) -> dict[str, int]:
    payload = _read_attempt_state(output_root / "attempt-state.json")
    if payload is None:
        return {}
    if payload["run_plan_sha256"] != run_plan_sha256:
        raise MvpScoringError("ATTEMPT_STATE_PLAN_MISMATCH")
    request_hashes = {row.place.place_id: row.request_sha256 for row in requests}
    counts: dict[str, int] = {}
    attempts = payload["attempts"]
    if not isinstance(attempts, list):
        raise MvpScoringError("ATTEMPT_STATE_INVALID")
    for value in attempts:
        if not isinstance(value, dict) or set(value) != {
            "place_id",
            "request_sha256",
            "attempt_number",
            "status",
            "reason",
        }:
            raise MvpScoringError("ATTEMPT_STATE_INVALID")
        place_id = value["place_id"]
        attempt_number = value["attempt_number"]
        status = value["status"]
        if (
            not isinstance(place_id, str)
            or request_hashes.get(place_id) != value["request_sha256"]
            or not isinstance(attempt_number, int)
            or isinstance(attempt_number, bool)
            or attempt_number not in {1, 2}
            or status not in {"STARTED", "FAILED", "SUCCEEDED"}
            or (
                status == "FAILED"
                and value["reason"] != "PROVIDER_ATTEMPT_FAILED"
                and not _is_safe_provider_error_code(value["reason"])
            )
            or (status != "FAILED" and value["reason"] is not None)
            or attempt_number != counts.get(place_id, 0) + 1
        ):
            raise MvpScoringError("ATTEMPT_STATE_INVALID")
        counts[place_id] = attempt_number
    return dict(sorted(counts.items()))


def persist_attempt_event(output_root: Path, event: ScoringAttemptEvent) -> None:
    path = output_root / "attempt-state.json"
    payload = _read_attempt_state(path)
    if payload is None:
        payload = {
            "schema_version": "mvp-scoring-attempt-state.v1",
            "run_plan_sha256": event.run_plan_sha256,
            "attempts": [],
        }
    if payload["run_plan_sha256"] != event.run_plan_sha256:
        raise MvpScoringError("ATTEMPT_STATE_PLAN_MISMATCH")
    attempts = payload["attempts"]
    if not isinstance(attempts, list):
        raise MvpScoringError("ATTEMPT_STATE_INVALID")
    matching = [row for row in attempts if row.get("place_id") == event.place_id]
    if event.status == "STARTED":
        if event.reason is not None or event.attempt_number != len(matching) + 1:
            raise MvpScoringError("ATTEMPT_STATE_TRANSITION_INVALID")
        attempts.append(
            {
                "place_id": event.place_id,
                "request_sha256": event.request_sha256,
                "attempt_number": event.attempt_number,
                "status": event.status,
                "reason": None,
            }
        )
    else:
        if (
            not matching
            or matching[-1].get("request_sha256") != event.request_sha256
            or matching[-1].get("attempt_number") != event.attempt_number
            or matching[-1].get("status") != "STARTED"
            or event.status not in {"FAILED", "SUCCEEDED"}
            or (
                event.status == "FAILED"
                and event.reason != "PROVIDER_ATTEMPT_FAILED"
                and not _is_safe_provider_error_code(event.reason)
            )
            or (event.status == "SUCCEEDED" and event.reason is not None)
        ):
            raise MvpScoringError("ATTEMPT_STATE_TRANSITION_INVALID")
        matching[-1]["status"] = event.status
        matching[-1]["reason"] = event.reason
    _write_atomic(path, canonical_json_bytes(payload) + b"\n")


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def consume_execution_authority(output_root: Path, run_plan_sha256: str) -> None:
    path = output_root / "execution-started.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(
        {
            "schema_version": "mvp-scoring-execution-started.v1",
            "run_plan_sha256": run_plan_sha256,
        }
    ) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise MvpScoringError("SCORING_EXECUTION_ALREADY_STARTED") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def persist_scoring_result(output_root: Path, result: BoundScoringResult) -> None:
    path = output_root / "results" / f"{result.place_id.removeprefix('public:gyeongju:')}.json"
    payload = canonical_json_bytes(result.model_dump(mode="json")) + b"\n"
    if path.exists():
        if path.read_bytes() != payload:
            raise MvpScoringError("RESULT_FILE_CONFLICT")
        return
    _write_atomic(path, payload)


def require_live_network_allowed() -> None:
    if os.getenv("ITDA_OFFLINE") == "1" or os.getenv("ITDA_NO_NETWORK") == "1":
        raise MvpScoringError("NETWORK_DISABLED_BEFORE_CLIENT_CONSTRUCTION")


def build_http_client() -> object:
    require_live_network_allowed()
    import httpx

    return httpx.Client(
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
    )
