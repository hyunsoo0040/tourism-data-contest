"""Immutable, label-free contracts for bounded Phase 4 VLM inference."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.image_observation import (
    APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
    FORBIDDEN_PROVIDER_AUTHORITY_FIELDS,
)
from itda.contracts.place_profile import SubattributeId
from itda.domain.canonical import canonical_sha256

GLM5V_ENDPOINT = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
GLM5V_MODEL = "glm-5v-turbo"
GLM5V_API_CONTRACT_PATH = (
    Path(__file__).resolve().parent.parent / "providers" / "glm5v_api_contract.json"
)

PromptId = Annotated[
    str,
    Field(strict=True, pattern=r"^glm5v-(?:ko|ko-en)-visible-v1$"),
]
PlaceRef = Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
SelectedImageRef = Annotated[
    str,
    Field(strict=True, pattern=r"^selected-image:[0-9a-f]{64}$"),
]
SafeProviderId = Annotated[str, Field(strict=True, min_length=1, max_length=200)]


FORBIDDEN_PROVIDER_INPUT_KEYS = tuple(
    sorted(
        {
            *FORBIDDEN_PROVIDER_AUTHORITY_FIELDS,
            "api_key",
            "authorization",
            "bearer_token",
            "blind",
            "blind_ids",
            "blind_membership",
            "blind_payload",
            "credential",
            "credentials",
            "expert_label",
            "expert_labels",
            "image_bytes",
            "label",
            "labels",
            "raw_image",
            "raw_images",
            "raw_request_body",
            "raw_response_body",
            "response_body",
            "split",
            "split_membership",
        }
    )
)


def _reject_forbidden_provider_inputs(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in FORBIDDEN_PROVIDER_INPUT_KEYS:
                raise ValueError(f"forbidden provider input field: {key.casefold()}")
            _reject_forbidden_provider_inputs(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_forbidden_provider_inputs(nested)


def seal_inference_contract(
    payload: Mapping[str, object], *, digest_field: str
) -> dict[str, object]:
    """Return a copy with a canonical self-digest over every other field."""

    sealed = dict(payload)
    sealed.pop(digest_field, None)
    sealed[digest_field] = canonical_sha256(sealed)
    return sealed


def _require_self_digest(model: StrictContract, *, digest_field: str) -> None:
    payload = model.model_dump(mode="json", exclude={digest_field})
    if getattr(model, digest_field) != canonical_sha256(payload):
        raise ValueError(f"{digest_field} does not match canonical content")


class OfficialApiSource(StrictContract):
    url: Annotated[
        str,
        Field(strict=True, pattern=r"^https://docs\.bigmodel\.cn/[^\s]+$"),
    ]
    safe_facts_sha256: Sha256
    digest_scope: Literal["CANONICAL_EXTRACTED_SAFE_FACTS"]


class Glm5VApiContract(StrictContract):
    schema_version: Literal["itda.glm5v-official-api-snapshot.v1"]
    retrieved_at: datetime
    endpoint: Literal["https://open.bigmodel.cn/api/paas/v4/chat/completions"]
    model: Literal["glm-5v-turbo"]
    authorization_scheme: Literal["Bearer"]
    multimodal_content_shape: Literal["messages[].content[{type:image_url,image_url:{url}}]"]
    supports_multiple_image_parts: Literal[True]
    supports_non_streaming: Literal[True]
    strict_vision_json_mode: Literal["UNKNOWN"]
    documented_max_image_count: Literal["UNKNOWN"]
    immutable_model_revision: Literal["UNKNOWN"]
    retention_terms: Literal["UNKNOWN"]
    numeric_pricing: Literal["UNKNOWN"]
    sources: Annotated[tuple[OfficialApiSource, ...], Field(min_length=3)]
    contract_sha256: Sha256

    @field_validator("retrieved_at")
    @classmethod
    def validate_retrieved_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        _require_self_digest(self, digest_field="contract_sha256")
        return self


class PromptCandidate(StrictContract):
    prompt_id: PromptId
    language: Literal["ko", "ko-en"]
    version: Literal["visible-evidence.v1"]
    system_instructions_sha256: Sha256
    user_template_sha256: Sha256


KOREAN_PROMPT_CANDIDATE = PromptCandidate(
    prompt_id="glm5v-ko-visible-v1",
    language="ko",
    version="visible-evidence.v1",
    system_instructions_sha256=("4921d1face70ee5913d8e6d7bc9043477d46df181ac6baa114231cba53d3a703"),
    user_template_sha256=("95b564e5834961ca237ad383d8a778ab69ebf6e81694f9a39ff457623bd31aa2"),
)
BILINGUAL_PROMPT_CANDIDATE = PromptCandidate(
    prompt_id="glm5v-ko-en-visible-v1",
    language="ko-en",
    version="visible-evidence.v1",
    system_instructions_sha256=("b3d469af8950b8de9ef84ef31de2775cdaa1964b89f477d36d009cbe93922ee7"),
    user_template_sha256=("8c5f49e594b5d2d7d3fcc266db6f5dc25d6bc0e53128de92e61435af24137bbe"),
)


class AttributePromptRoute(StrictContract):
    attribute_id: SubattributeId
    prompt_id: PromptId


class FrozenPromptRouting(StrictContract):
    strategy: Literal["GLOBAL", "ATTRIBUTE_PREDECLARED"]
    global_prompt_id: PromptId | None
    attribute_routes: tuple[AttributePromptRoute, ...]

    @model_validator(mode="after")
    def validate_routing(self) -> Self:
        if self.strategy == "GLOBAL":
            if self.global_prompt_id is None or self.attribute_routes:
                raise ValueError("global prompt routing requires one global prompt only")
            return self
        if self.global_prompt_id is not None:
            raise ValueError("attribute routing cannot carry a global prompt")
        if tuple(row.attribute_id for row in self.attribute_routes) != tuple(SubattributeId):
            raise ValueError("attribute routing requires exact H1-H4, I1-I4, R1-R4 order")
        return self


class DeterministicGeneration(StrictContract):
    stream: Literal[False]
    thinking_type: Literal["disabled"]
    do_sample: Literal[False]
    max_tokens: Literal[2048]
    tools: Literal[None]
    response_format: Literal[None]


class ProviderTimeouts(StrictContract):
    connect_seconds: Literal[10]
    read_seconds: Literal[180]
    write_seconds: Literal[60]
    pool_seconds: Literal[10]


class ProviderRetryPolicy(StrictContract):
    max_total_attempts: Literal[3]
    retryable_http_statuses: tuple[Literal[429, 500, 502, 503, 504], ...]
    retryable_transport_errors: tuple[
        Literal[
            "CONNECT_ERROR",
            "CONNECT_TIMEOUT",
            "READ_ERROR",
            "READ_TIMEOUT",
            "WRITE_ERROR",
            "WRITE_TIMEOUT",
        ],
        ...,
    ]
    semantic_repair_attempts: Literal[0]

    @model_validator(mode="after")
    def validate_closed_retry_allowlist(self) -> Self:
        if self.retryable_http_statuses != (429, 500, 502, 503, 504):
            raise ValueError("retryable HTTP statuses must match the closed allowlist")
        if self.retryable_transport_errors != (
            "CONNECT_ERROR",
            "CONNECT_TIMEOUT",
            "READ_ERROR",
            "READ_TIMEOUT",
            "WRITE_ERROR",
            "WRITE_TIMEOUT",
        ):
            raise ValueError("retryable transport errors must match the closed allowlist")
        return self


class Glm5VProviderConfig(StrictContract):
    schema_version: Literal["itda.vlm-provider-config.v1"]
    provider: Literal["ZHIPU_BIGMODEL"]
    endpoint: Literal["https://open.bigmodel.cn/api/paas/v4/chat/completions"]
    requested_model: Literal["glm-5v-turbo"]
    model_revision: Literal["UNKNOWN_PROVIDER_ALIAS_MUTABILITY"]
    api_contract_sha256: Sha256
    prompt_candidates: tuple[PromptCandidate, ...]
    prompt_routing: FrozenPromptRouting
    observation_schema_version: Literal["photo-attributes.v2"]
    observation_schema_sha256: Sha256
    generation: DeterministicGeneration
    timeouts: ProviderTimeouts
    retry_policy: ProviderRetryPolicy
    preprocessing_manifest_sha256: Sha256
    selection_manifest_sha256: Sha256
    code_sha256: Sha256
    config_source_sha256: Sha256
    created_at: datetime
    config_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_protected_inputs(cls, value: object) -> object:
        _reject_forbidden_provider_inputs(value)
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_frozen_config(self) -> Self:
        if self.api_contract_sha256 != load_glm5v_api_contract().contract_sha256:
            raise ValueError("provider API contract hash is not approved")
        if self.prompt_candidates != (
            KOREAN_PROMPT_CANDIDATE,
            BILINGUAL_PROMPT_CANDIDATE,
        ):
            raise ValueError("prompt candidates drifted from the frozen pair")
        known_prompts = {candidate.prompt_id for candidate in self.prompt_candidates}
        routed_prompts = (
            {self.prompt_routing.global_prompt_id}
            if self.prompt_routing.strategy == "GLOBAL"
            else {route.prompt_id for route in self.prompt_routing.attribute_routes}
        )
        if None in routed_prompts or not routed_prompts <= known_prompts:
            raise ValueError("prompt routing references an unknown candidate")
        if self.observation_schema_sha256 != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256:
            raise ValueError("image observation schema hash is not approved")
        _require_self_digest(self, digest_field="config_sha256")
        return self


class SafeInferenceRequest(StrictContract):
    schema_version: Literal["itda.vlm-safe-request.v1"]
    place_ref: PlaceRef
    provider_config_sha256: Sha256
    selection_manifest_sha256: Sha256
    prompt_id: PromptId
    selected_image_refs: Annotated[tuple[SelectedImageRef, ...], Field(min_length=1, max_length=5)]
    selected_image_sha256: Annotated[tuple[Sha256, ...], Field(min_length=1, max_length=5)]
    created_at: datetime
    semantic_request_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_protected_inputs(cls, value: object) -> object:
        _reject_forbidden_provider_inputs(value)
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if len(set(self.selected_image_refs)) != len(self.selected_image_refs):
            raise ValueError("selected image references must be unique")
        if len(set(self.selected_image_sha256)) != len(self.selected_image_sha256):
            raise ValueError("selected image digests must be unique")
        if len(self.selected_image_refs) != len(self.selected_image_sha256):
            raise ValueError("selected image refs and digests must align")
        _require_self_digest(self, digest_field="semantic_request_sha256")
        return self


class InferenceTerminalStatus(StrEnum):
    VALID = "VALID"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"


class AttemptOutcome(StrEnum):
    VALIDATED = "VALIDATED"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    RESPONSE_ENVELOPE_INVALID = "RESPONSE_ENVELOPE_INVALID"
    SEMANTIC_INVALID = "SEMANTIC_INVALID"
    AUTHORITY_INVALID = "AUTHORITY_INVALID"


class RetryDisposition(StrEnum):
    RETRY = "RETRY"
    DO_NOT_RETRY = "DO_NOT_RETRY"


class ProviderUsage(StrictContract):
    prompt_tokens: Annotated[int, Field(strict=True, ge=0)]
    completion_tokens: Annotated[int, Field(strict=True, ge=0)]
    total_tokens: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def validate_total(self) -> Self:
        if self.total_tokens < self.prompt_tokens + self.completion_tokens:
            raise ValueError("total token usage cannot be smaller than its parts")
        return self


class InferenceAttempt(StrictContract):
    attempt_number: Annotated[int, Field(strict=True, ge=1, le=3)]
    started_at: datetime
    completed_at: datetime
    outcome: AttemptOutcome
    retry_disposition: RetryDisposition
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)] | None
    error_code: Annotated[str, Field(strict=True, min_length=1, max_length=80)] | None
    provider_request_id: SafeProviderId | None
    returned_model: SafeProviderId | None
    finish_reason: Annotated[str, Field(strict=True, min_length=1, max_length=40)] | None
    safe_response_sha256: Sha256 | None
    usage: ProviderUsage | None

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: object) -> datetime:
        return require_utc(value, field_name=getattr(info, "field_name", "timestamp"))

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("attempt completion cannot precede start")
        if self.outcome is AttemptOutcome.VALIDATED:
            if (
                self.http_status != 200
                or self.retry_disposition is not RetryDisposition.DO_NOT_RETRY
                or self.error_code is not None
                or self.provider_request_id is None
                or self.returned_model is None
                or self.finish_reason is None
                or self.safe_response_sha256 is None
                or self.usage is None
            ):
                raise ValueError("validated attempt requires complete safe success lineage")
        else:
            if self.error_code is None:
                raise ValueError("failed attempt requires a safe error code")
            if any(
                value is not None
                for value in (
                    self.provider_request_id,
                    self.returned_model,
                    self.finish_reason,
                    self.usage,
                )
            ):
                raise ValueError("failed attempt cannot carry validated response lineage")
            if self.outcome is AttemptOutcome.TRANSPORT_ERROR:
                if self.http_status is not None or self.safe_response_sha256 is not None:
                    raise ValueError("transport failure cannot carry an HTTP response")
            elif self.outcome is AttemptOutcome.HTTP_ERROR:
                if self.http_status in {None, 200} or self.safe_response_sha256 is None:
                    raise ValueError("HTTP failure requires its exact safe response digest")
                if (
                    self.retry_disposition is RetryDisposition.RETRY
                    and self.http_status not in {408, 429, 500, 502, 503, 504}
                ):
                    raise ValueError("non-retryable HTTP status cannot carry retry authority")
            elif self.outcome is AttemptOutcome.RESPONSE_TOO_LARGE:
                if (
                    self.http_status is None
                    or self.safe_response_sha256 is not None
                    or self.retry_disposition is not RetryDisposition.DO_NOT_RETRY
                ):
                    raise ValueError("oversized response requires exact terminal HTTP lineage")
            elif (
                self.http_status != 200
                or self.safe_response_sha256 is None
                or self.retry_disposition is not RetryDisposition.DO_NOT_RETRY
            ):
                raise ValueError(
                    "semantic, authority, and envelope failures require "
                    "exact terminal response lineage"
                )
        return self


class VlmPredictionManifest(StrictContract):
    schema_version: Literal["itda.vlm-prediction-manifest.v1"]
    semantic_request_sha256: Sha256
    provider_config_sha256: Sha256
    attempts: Annotated[tuple[InferenceAttempt, ...], Field(min_length=1, max_length=3)]
    terminal_status: InferenceTerminalStatus
    observation_sha256: Sha256 | None
    completed_at: datetime
    prediction_manifest_sha256: Sha256

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="completed_at")

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if tuple(attempt.attempt_number for attempt in self.attempts) != tuple(
            range(1, len(self.attempts) + 1)
        ):
            raise ValueError("attempt numbers must be complete and ordered")
        if self.attempts[-1].retry_disposition is not RetryDisposition.DO_NOT_RETRY:
            raise ValueError("terminal attempt cannot remain retryable")
        if any(
            attempt.retry_disposition is not RetryDisposition.RETRY
            for attempt in self.attempts[:-1]
        ):
            raise ValueError("every nonterminal attempt must be retryable")
        if any(
            current.started_at < previous.completed_at
            for previous, current in zip(self.attempts, self.attempts[1:], strict=False)
        ):
            raise ValueError("attempt timestamps must be chronologically non-overlapping")
        if self.completed_at != self.attempts[-1].completed_at:
            raise ValueError("manifest completion must match its terminal attempt")
        if self.terminal_status is InferenceTerminalStatus.VALID:
            if (
                self.observation_sha256 is None
                or self.attempts[-1].outcome is not AttemptOutcome.VALIDATED
            ):
                raise ValueError("VALID manifest requires one validated observation")
        elif (
            self.observation_sha256 is not None
            or self.attempts[-1].outcome is AttemptOutcome.VALIDATED
        ):
            raise ValueError("ANALYSIS_FAILED cannot carry a validated observation")
        _require_self_digest(self, digest_field="prediction_manifest_sha256")
        return self


class PredictionFreezeReceipt(StrictContract):
    schema_version: Literal["itda.vlm-prediction-freeze-receipt.v1"]
    semantic_request_sha256: Sha256
    prediction_manifest_sha256: Sha256
    observation_schema_sha256: Literal[
        "1551c1966f4239323423b69906a7ffe7ffa4daebc0920f8b9ab2a02bb80e0fe0"
    ]
    frozen_at: datetime
    freeze_receipt_sha256: Sha256

    @field_validator("frozen_at")
    @classmethod
    def validate_frozen_at(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="frozen_at")

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        _require_self_digest(self, digest_field="freeze_receipt_sha256")
        return self


def load_glm5v_api_contract() -> Glm5VApiContract:
    return Glm5VApiContract.model_validate_json(GLM5V_API_CONTRACT_PATH.read_bytes())


__all__ = [
    "BILINGUAL_PROMPT_CANDIDATE",
    "FORBIDDEN_PROVIDER_INPUT_KEYS",
    "GLM5V_API_CONTRACT_PATH",
    "GLM5V_ENDPOINT",
    "GLM5V_MODEL",
    "KOREAN_PROMPT_CANDIDATE",
    "AttributePromptRoute",
    "AttemptOutcome",
    "FrozenPromptRouting",
    "Glm5VApiContract",
    "Glm5VProviderConfig",
    "InferenceAttempt",
    "InferenceTerminalStatus",
    "PredictionFreezeReceipt",
    "ProviderRetryPolicy",
    "ProviderTimeouts",
    "ProviderUsage",
    "RetryDisposition",
    "SafeInferenceRequest",
    "VlmPredictionManifest",
    "load_glm5v_api_contract",
    "seal_inference_contract",
]
