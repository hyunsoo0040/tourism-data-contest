"""Provider-free contracts for the one-use Phase 5 NVIDIA minimal probe."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.demo_profile_materialization import (
    NVIDIA_JSON_END_SENTINEL,
    NVIDIA_JSON_START_SENTINEL,
    NVIDIA_PROFILE_ENDPOINT,
    NVIDIA_PROFILE_MODEL,
    NVIDIA_PROVIDER_LANE,
)
from itda.domain.canonical import canonical_sha256

MINIMAL_PROBE_AUTHORITY_ID = "phase5-nvidia-minimax-m3-minimal-probe-20260820"
MINIMAL_PROBE_ENDPOINT = NVIDIA_PROFILE_ENDPOINT
MINIMAL_PROBE_MODEL = NVIDIA_PROFILE_MODEL
MINIMAL_PROBE_PROVIDER_LANE = NVIDIA_PROVIDER_LANE
MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS = 300
MINIMAL_PROBE_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES = 65_536
MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD = 500_000
MINIMAL_PROBE_RESERVATION_MICRO_USD = 500_000
MINIMAL_PROBE_MAX_ATTEMPTS = 1
MINIMAL_PROBE_CONCURRENCY = 1
MINIMAL_PROBE_CONFIDENCE_THRESHOLD = 0
MINIMAL_PROBE_PROMPT_VERSION = "phase5-demo-profile-sentinel-json.v5"
MINIMAL_PROBE_PROMPT_SHA256 = "aaa0328deaae58999b96eb9a43f176e589eb95319c3a80e9cd2978b23b925b3a"
MINIMAL_PROBE_PROFILE_SCHEMA_SHA256 = (
    "85fec5e62a23e949c10e1ff6f9fceb8f27f1aaa8d766f3b86cc443f028844a3c"
)
MINIMAL_PROBE_CONFIG_SHA256 = "9c6061bac4c411f108f2328862a8439024928ba52ffdd64bf176a454cd78f90c"
MINIMAL_PROBE_SCHEMA_VERSION = "itda.phase5-nvidia-minimal-probe.v1"
MINIMAL_PROBE_TERMINAL_SCHEMA = "itda.phase5-nvidia-minimal-probe-terminal.v1"
MINIMAL_PROBE_SOURCE_INVENTORY_SHA256 = (
    "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
)
MINIMAL_PROBE_SECRET_FILE_MODE = "0600"
MINIMAL_PROBE_SECRET_FILE_FORMAT = "UTF8_SINGLE_NVIDIA_KEY_RECORD"
MINIMAL_PROBE_RECEIPT_EMITTED = False
MINIMAL_PROBE_COHORT_CAPABILITY = False
MINIMAL_PROBE_RELEASE_CAPABILITY = False
MINIMAL_PROBE_SMOKE_CAPABILITY = False
MINIMAL_PROBE_ACTIVATION_CAPABILITY = False
_MINIMAL_AUTHORITY_RE = re.compile(r"^phase5-nvidia-minimax-m3-minimal-probe-20260820$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def minimal_probe_public_facts() -> dict[str, object]:
    return {
        "authority_id": MINIMAL_PROBE_AUTHORITY_ID,
        "endpoint": MINIMAL_PROBE_ENDPOINT,
        "model": MINIMAL_PROBE_MODEL,
        "provider_lane": MINIMAL_PROBE_PROVIDER_LANE,
        "prompt_version": MINIMAL_PROBE_PROMPT_VERSION,
        "prompt_sha256": MINIMAL_PROBE_PROMPT_SHA256,
        "profile_schema_sha256": MINIMAL_PROBE_PROFILE_SCHEMA_SHA256,
        "config_sha256": MINIMAL_PROBE_CONFIG_SHA256,
        "source_inventory_sha256": MINIMAL_PROBE_SOURCE_INVENTORY_SHA256,
        "attempt_deadline_seconds": MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS,
        "max_response_bytes": MINIMAL_PROBE_MAX_RESPONSE_BYTES,
        "sentinel_payload_bytes": MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES,
        "max_attempts": MINIMAL_PROBE_MAX_ATTEMPTS,
        "concurrency": MINIMAL_PROBE_CONCURRENCY,
        "cumulative_exposure_micro_usd": MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD,
        "reservation_micro_usd": MINIMAL_PROBE_RESERVATION_MICRO_USD,
        "secret_file_mode": MINIMAL_PROBE_SECRET_FILE_MODE,
        "secret_file_format": MINIMAL_PROBE_SECRET_FILE_FORMAT,
        "receipt_emitted": MINIMAL_PROBE_RECEIPT_EMITTED,
        "cohort_capability": MINIMAL_PROBE_COHORT_CAPABILITY,
        "candidate_capability": False,
        "smoke_capability": MINIMAL_PROBE_SMOKE_CAPABILITY,
        "activation_capability": MINIMAL_PROBE_ACTIVATION_CAPABILITY,
        "release_capability": MINIMAL_PROBE_RELEASE_CAPABILITY,
    }


def require_minimal_probe_digest(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def validate_minimal_probe_authority_id(value: object) -> str:
    if not isinstance(value, str) or _MINIMAL_AUTHORITY_RE.fullmatch(value) is None:
        raise ValueError("minimal probe authority ID is invalid")
    return value


def _reject_path_material(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("minimal probe keys must be strings")
            if re.search(
                r"(?:^|_)(?:path|file|dir|root|secret|raw|journal|approval|claim)(?:_|$)", key, re.I
            ):
                raise ValueError("minimal probe public contract contains protected path material")
            _reject_path_material(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_path_material(child)


class NvidiaInvocationContract(StrictContract):
    """Exact one-request provider envelope and bounded response policy."""

    schema_version: Literal["itda.nvidia-invocation-contract.v1"] = (
        "itda.nvidia-invocation-contract.v1"
    )
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    provider_lane: Literal["NVIDIA_NIM_API"] = MINIMAL_PROBE_PROVIDER_LANE
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        MINIMAL_PROBE_ENDPOINT
    )
    model: Literal["minimaxai/minimax-m3"] = MINIMAL_PROBE_MODEL
    authorization_scheme: Literal["Bearer"] = "Bearer"
    temperature: Literal[0.0] = 0.0
    max_tokens: Literal[8192] = 8192
    stream: Literal[False] = False
    seed: Literal[0] = 0
    thinking_mode: Literal["disabled"] = "disabled"
    top_p_omitted: Literal[True] = True
    response_format_omitted: Literal[True] = True
    tools_omitted: Literal[True] = True
    attempt_deadline_seconds: Literal[300] = MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS
    max_response_bytes: Literal[4_194_304] = MINIMAL_PROBE_MAX_RESPONSE_BYTES
    sentinel_payload_bytes: Literal[65_536] = MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES
    concurrency: Literal[1] = MINIMAL_PROBE_CONCURRENCY
    max_attempts: Literal[1] = MINIMAL_PROBE_MAX_ATTEMPTS
    cumulative_exposure_micro_usd: Literal[500_000] = MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD
    reservation_micro_usd: Literal[500_000] = MINIMAL_PROBE_RESERVATION_MICRO_USD
    json_start_sentinel: Literal["<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"] = (
        NVIDIA_JSON_START_SENTINEL
    )
    json_end_sentinel: Literal["<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"] = NVIDIA_JSON_END_SENTINEL
    response_contract: Literal["STRICT_INVOCATION_ONLY"] = "STRICT_INVOCATION_ONLY"
    cohort_capability: Literal[False] = False
    release_capability: Literal[False] = False
    network_attempted: Literal[False] = False

    @model_validator(mode="before")
    @classmethod
    def reject_protected_inputs(cls, value: object) -> object:
        _reject_path_material(value)
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        if (
            self.max_attempts != 1
            or self.cumulative_exposure_micro_usd != self.reservation_micro_usd
        ):
            raise ValueError("minimal probe must have exactly one bounded attempt")
        return self


class NvidiaMinimalProbeRequest(StrictContract):
    """Path-free request packet for one exact provider invocation."""

    schema_version: Literal["itda.nvidia-minimal-probe-request.v1"] = (
        "itda.nvidia-minimal-probe-request.v1"
    )
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    invocation: NvidiaInvocationContract
    source_inventory_sha256: Sha256
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    request_sha256: Sha256
    request_body: Annotated[bytes, Field(repr=False)]
    request_body_sha256: Sha256

    @property
    def cumulative_exposure_micro_usd(self) -> int:
        return self.invocation.cumulative_exposure_micro_usd

    @property
    def max_response_bytes(self) -> int:
        return self.invocation.max_response_bytes

    @property
    def sentinel_payload_bytes(self) -> int:
        return self.invocation.sentinel_payload_bytes

    @property
    def attempt_deadline_seconds(self) -> int:
        return self.invocation.attempt_deadline_seconds

    @property
    def max_attempts(self) -> int:
        return self.invocation.max_attempts

    @property
    def concurrency(self) -> int:
        return self.invocation.concurrency

    def public_payload(self) -> dict[str, object]:
        """Return the digest-only projection safe for a public approval packet."""

        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "invocation": self.invocation.model_dump(mode="json"),
            "source_inventory_sha256": self.source_inventory_sha256,
            "source_bundle_sha256": self.source_bundle_sha256,
            "evidence_inventory_sha256": self.evidence_inventory_sha256,
            "place_id": self.place_id,
            "request_sha256": self.request_sha256,
            "request_body_sha256": self.request_body_sha256,
        }

    @model_validator(mode="before")
    @classmethod
    def reject_protected_inputs(cls, value: object) -> object:
        _reject_path_material(value)
        return value

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        if self.invocation.authority_id != self.authority_id:
            raise ValueError("minimal probe request authority drifted")
        if self.request_body_sha256 != hashlib.sha256(self.request_body).hexdigest():
            raise ValueError("minimal probe HTTP body digest drifted")
        if self.request_sha256 != canonical_sha256(
            {
                "authority_id": self.authority_id,
                "invocation": self.invocation.model_dump(mode="json"),
                "source_inventory_sha256": self.source_inventory_sha256,
                "source_bundle_sha256": self.source_bundle_sha256,
                "evidence_inventory_sha256": self.evidence_inventory_sha256,
                "place_id": self.place_id,
                "request_body_sha256": self.request_body_sha256,
            }
        ):
            raise ValueError("minimal probe request digest drifted")
        return self


class NvidiaMinimalProbePublicArtifact(StrictContract):
    """Closed public packet whose self digest covers every other field."""

    schema_version: Literal["itda.phase5-nvidia-minimal-probe-approval-request.v1"] = (
        "itda.phase5-nvidia-minimal-probe-approval-request.v1"
    )
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    provider_lane: Literal["NVIDIA_NIM_API"] = MINIMAL_PROBE_PROVIDER_LANE
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        MINIMAL_PROBE_ENDPOINT
    )
    model: Literal["minimaxai/minimax-m3"] = MINIMAL_PROBE_MODEL
    prompt_version: Literal["phase5-demo-profile-sentinel-json.v5"] = (
        MINIMAL_PROBE_PROMPT_VERSION
    )
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    config_sha256: Sha256
    source_inventory_sha256: Sha256
    source_bundle_sha256: Sha256
    evidence_inventory_sha256: Sha256
    place_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    request_sha256: Sha256
    request_body_sha256: Sha256
    checkout_manifest_sha256: Sha256
    checkout_commit_sha256: Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{40}$")]
    attempt_deadline_seconds: Literal[300] = MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS
    max_response_bytes: Literal[4_194_304] = MINIMAL_PROBE_MAX_RESPONSE_BYTES
    sentinel_payload_bytes: Literal[65_536] = MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES
    max_attempts: Literal[1] = MINIMAL_PROBE_MAX_ATTEMPTS
    concurrency: Literal[1] = MINIMAL_PROBE_CONCURRENCY
    cumulative_exposure_micro_usd: Literal[500_000] = MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD
    reservation_micro_usd: Literal[500_000] = MINIMAL_PROBE_RESERVATION_MICRO_USD
    secret_file_mode: Literal["0600"] = MINIMAL_PROBE_SECRET_FILE_MODE
    secret_file_format: Literal["UTF8_SINGLE_NVIDIA_KEY_RECORD"] = (
        MINIMAL_PROBE_SECRET_FILE_FORMAT
    )
    receipt_emitted: Literal[False] = False
    cohort_capability: Literal[False] = False
    candidate_capability: Literal[False] = False
    smoke_capability: Literal[False] = False
    activation_capability: Literal[False] = False
    release_capability: Literal[False] = False
    secret_read: Literal[False] = False
    client_constructed: Literal[False] = False
    network_attempted: Literal[False] = False
    lifecycle_mutated: Literal[False] = False
    approval_payload_sha256: Sha256
    request_artifact_sha256: Sha256

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        if (
            self.prompt_sha256 != MINIMAL_PROBE_PROMPT_SHA256
            or self.profile_schema_sha256 != MINIMAL_PROBE_PROFILE_SCHEMA_SHA256
            or self.config_sha256 != MINIMAL_PROBE_CONFIG_SHA256
            or self.source_inventory_sha256 != MINIMAL_PROBE_SOURCE_INVENTORY_SHA256
        ):
            raise ValueError("minimal probe public authority facts drifted")
        dumped = self.model_dump(mode="json")
        approval_preimage = {
            key: value
            for key, value in dumped.items()
            if key not in {"approval_payload_sha256", "request_artifact_sha256"}
        }
        if not hmac.compare_digest(
            self.approval_payload_sha256,
            canonical_sha256(approval_preimage),
        ):
            raise ValueError("minimal probe public approval payload digest drifted")
        artifact_preimage = {
            key: value for key, value in dumped.items() if key != "request_artifact_sha256"
        }
        if not hmac.compare_digest(
            self.request_artifact_sha256,
            canonical_sha256(artifact_preimage),
        ):
            raise ValueError("minimal probe full public artifact digest drifted")
        return self


class NvidiaMinimalProbeApprovalBinding(StrictContract):
    """Exact approved public packet and secret identity persisted in protected state."""

    schema_version: Literal["itda.nvidia-minimal-probe-approval.v1"] = (
        "itda.nvidia-minimal-probe-approval.v1"
    )
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    decision: Literal["APPROVED"] = "APPROVED"
    request_sha256: Sha256
    checkout_manifest_sha256: Sha256
    checkout_commit_sha256: Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{40}$")]
    request_artifact_sha256: Sha256
    approval_payload_sha256: Sha256
    protected_state_sha256: Sha256
    secret_identity_sha256: Sha256
    secret_content_fingerprint: Sha256
    provider_lane: Literal["NVIDIA_NIM_API"] = MINIMAL_PROBE_PROVIDER_LANE
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        MINIMAL_PROBE_ENDPOINT
    )
    model: Literal["minimaxai/minimax-m3"] = MINIMAL_PROBE_MODEL
    attempt_deadline_seconds: Literal[300] = MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS
    max_response_bytes: Literal[4_194_304] = MINIMAL_PROBE_MAX_RESPONSE_BYTES
    max_attempts: Literal[1] = MINIMAL_PROBE_MAX_ATTEMPTS
    concurrency: Literal[1] = MINIMAL_PROBE_CONCURRENCY
    cumulative_exposure_micro_usd: Literal[500_000] = MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD
    reservation_micro_usd: Literal[500_000] = MINIMAL_PROBE_RESERVATION_MICRO_USD
    approval_sha256: Sha256

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        unsigned = self.model_dump(mode="json", exclude={"approval_sha256"})
        if not hmac.compare_digest(self.approval_sha256, canonical_sha256(unsigned)):
            raise ValueError("minimal probe approval binding digest drifted")
        return self


class NvidiaProbeClaim(StrictContract):
    """Typed one-use claim bound to the exact approval and protected root."""

    schema_version: Literal["itda.nvidia-minimal-probe-claim.v1"] = (
        "itda.nvidia-minimal-probe-claim.v1"
    )
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    request_sha256: Sha256
    approval_sha256: Sha256
    protected_state_sha256: Sha256
    claim_sha256: Sha256

    @model_validator(mode="after")
    def validate_claim(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        unsigned = self.model_dump(mode="json", exclude={"claim_sha256"})
        if not hmac.compare_digest(self.claim_sha256, canonical_sha256(unsigned)):
            raise ValueError("minimal probe claim digest drifted")
        return self


class NvidiaMinimalProbeProtectedStateDescriptor(StrictContract):
    """Logical-authority resolver for protected approval and one-use evidence."""

    schema_version: Literal["itda.nvidia-minimal-probe-protected-state.v1"] = (
        "itda.nvidia-minimal-probe-protected-state.v1"
    )
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    state_root: str
    approval_target: str
    claim_target: str
    ledger_target: str
    journal_target: str
    raw_evidence_target: str
    protected_state_sha256: Sha256

    @model_validator(mode="after")
    def validate_descriptor(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        values = (
            self.state_root,
            self.approval_target,
            self.claim_target,
            self.ledger_target,
            self.journal_target,
            self.raw_evidence_target,
        )
        if any(not value.startswith("/") for value in values):
            raise ValueError("minimal probe protected targets must be absolute")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"protected_state_sha256"})
        )
        if not hmac.compare_digest(expected, self.protected_state_sha256):
            raise ValueError("minimal probe protected state digest drifted")
        return self

    @classmethod
    def from_root(
        cls,
        *,
        state_root: str,
        authority_id: str = MINIMAL_PROBE_AUTHORITY_ID,
    ) -> Self:
        validate_minimal_probe_authority_id(authority_id)
        root_path = Path(state_root)
        if not root_path.is_absolute() or any(
            part in {"", ".", ".."} for part in root_path.parts[1:]
        ):
            raise ValueError("minimal probe protected root must be absolute and lexical")
        root = str(root_path).rstrip("/")
        payload = {
            "schema_version": "itda.nvidia-minimal-probe-protected-state.v1",
            "authority_id": authority_id,
            "state_root": root,
            "approval_target": f"{root}/approval.json",
            "claim_target": f"{root}/claim.json",
            "ledger_target": f"{root}/ledger.jsonl",
            "journal_target": f"{root}/journal",
            "raw_evidence_target": f"{root}/raw-evidence",
        }
        return cls.model_validate(
            {**payload, "protected_state_sha256": canonical_sha256(payload)}
        )


class NvidiaMinimalProbeTerminal(StrictContract):
    """Self-digested safe terminal; profile eligibility is not release authority."""

    schema_version: Literal["itda.phase5-nvidia-minimal-probe-terminal.v1"] = (
        MINIMAL_PROBE_TERMINAL_SCHEMA
    )
    status: Literal["POSITIVE", "DESIGNED_NEGATIVE", "MALFORMED"]
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    authority_id: str = MINIMAL_PROBE_AUTHORITY_ID
    request_sha256: Sha256
    approval_sha256: Sha256
    protected_state_sha256: Sha256
    claim_sha256: Sha256
    raw_response_sha256: Sha256 | None
    ledger_sha256: Sha256
    journal_sha256: Sha256
    attempt_count: Literal[0, 1]
    committed_exposure_micro_usd: Literal[0, 500_000]
    outstanding_exposure_micro_usd: Literal[0] = 0
    confidence: Annotated[int, Field(strict=True, ge=0, le=100)] | None = None
    release_eligible: Literal[False] = False
    secret_read: StrictBool = False
    client_constructed: StrictBool = False
    network_attempted: StrictBool = False
    lifecycle_mutated: StrictBool = False
    terminal_sha256: Sha256

    @model_validator(mode="after")
    def validate_terminal(self) -> Self:
        validate_minimal_probe_authority_id(self.authority_id)
        if (
            self.attempt_count != 1
            or self.committed_exposure_micro_usd != 500_000
            or not self.secret_read
            or not self.client_constructed
            or not self.network_attempted
        ):
            raise ValueError("attempted minimal probe terminal exposure is invalid")
        if self.status == "POSITIVE":
            if self.reason != "STRICT_INVOCATION_SUCCESS" or self.confidence is None:
                raise ValueError("positive minimal probe terminal is incomplete")
        elif self.status == "DESIGNED_NEGATIVE":
            if self.confidence is not None or self.reason == "STRICT_INVOCATION_SUCCESS":
                raise ValueError("designed-negative terminal contains positive evidence")
        elif self.confidence is not None or self.reason == "STRICT_INVOCATION_SUCCESS":
            raise ValueError("malformed minimal probe terminal contains positive evidence")
        if self.status == "MALFORMED" and self.reason not in {
            "PROBE_RESPONSE_INVALID",
            "PROBE_RESPONSE_TOO_LARGE",
            "PROBE_SECRET_ECHO",
            "PROBE_CONTENT_LENGTH_INVALID",
            "PROBE_CLEANUP_FAILED",
            "PROBE_INTERRUPTED",
        }:
            raise ValueError("malformed minimal probe reason is not canonical")
        unsigned = self.model_dump(mode="json", exclude={"terminal_sha256"})
        if not hmac.compare_digest(self.terminal_sha256, canonical_sha256(unsigned)):
            raise ValueError("minimal probe terminal digest drifted")
        return self


__all__ = [
    "MINIMAL_PROBE_ATTEMPT_DEADLINE_SECONDS",
    "MINIMAL_PROBE_AUTHORITY_ID",
    "MINIMAL_PROBE_CONCURRENCY",
    "MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD",
    "MINIMAL_PROBE_ENDPOINT",
    "MINIMAL_PROBE_MAX_ATTEMPTS",
    "MINIMAL_PROBE_MAX_RESPONSE_BYTES",
    "MINIMAL_PROBE_MODEL",
    "MINIMAL_PROBE_PROVIDER_LANE",
    "MINIMAL_PROBE_RESERVATION_MICRO_USD",
    "MINIMAL_PROBE_SCHEMA_VERSION",
    "MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES",
    "MINIMAL_PROBE_TERMINAL_SCHEMA",
    "NvidiaInvocationContract",
    "NvidiaMinimalProbeApprovalBinding",
    "NvidiaMinimalProbeProtectedStateDescriptor",
    "NvidiaMinimalProbePublicArtifact",
    "NvidiaMinimalProbeRequest",
    "NvidiaMinimalProbeTerminal",
    "NvidiaProbeClaim",
    "minimal_probe_public_facts",
    "validate_minimal_probe_authority_id",
]
