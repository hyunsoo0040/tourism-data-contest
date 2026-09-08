"""Isolated, bounded NVIDIA NIM adapter for Phase 5 DEV materialization."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Final

import httpx
from pydantic import Field, ValidationError

from itda.contracts.demo_profile_materialization import (
    MAX_HTTP_ATTEMPTS,
    MAX_PROVIDER_RESPONSE_BYTES,
    NVIDIA_AUTHORITY_SHA256,
    NvidiaLocalProfileLineage,
    NvidiaMinimaxModelDerivedProfile,
    NvidiaMinimaxProfileAttempt,
    NvidiaMinimaxProfileMaterializationConfig,
    NvidiaProfileRecommendationClassification,
    NvidiaProviderTokenUsage,
    seal_demo_contract,
)
from itda.contracts.phase5_fresh_cohort import (
    FRESH_AUTHORITY_ID,
    FRESH_ENDPOINT,
    FRESH_MODEL,
    FreshExposureReservation,
    FreshNvidiaExposureLedger,
)
from itda.domain.canonical import canonical_sha256
from itda.domain.demo_profile_eligibility import evaluate_nvidia_profile_publication

_RETRYABLE_HTTP = frozenset({429, 500, 502, 503, 504})
_RATE_LIMIT_HEADER_ALLOWLIST = frozenset(
    {
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
)
_RETRYABLE_TRANSPORT = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.WriteTimeout,
)


@dataclass(frozen=True, slots=True)
class NvidiaAttemptReservation:
    attempt_number: int


@dataclass(frozen=True, slots=True)
class NvidiaRateLimitPolicy:
    minimum_interval_seconds: int = 0
    minimum_cooldown_seconds: int = 60
    default_cooldown_seconds: int = 300
    maximum_cooldown_seconds: int = 3_600

    def __post_init__(self) -> None:
        if not (
            0
            <= self.minimum_interval_seconds
            <= self.minimum_cooldown_seconds
            <= self.default_cooldown_seconds
            <= self.maximum_cooldown_seconds
            <= 3_600
        ):
            raise ValueError("NVIDIA rate-limit policy is outside fixed safety bounds")


class NvidiaAttemptLedger:
    """NVIDIA-only attempt counter; never aliases either historical Z.ai ledger."""

    def __init__(
        self,
        *,
        max_attempts: int = MAX_HTTP_ATTEMPTS,
        initial_attempt_count: int = 0,
    ) -> None:
        if (max_attempts, initial_attempt_count) not in {
            (MAX_HTTP_ATTEMPTS, 0),
            (MAX_HTTP_ATTEMPTS, 1),
            (MAX_HTTP_ATTEMPTS, 2),
            (MAX_HTTP_ATTEMPTS, 6),
            (MAX_HTTP_ATTEMPTS, 7),
            (24, 3),
            (25, 14),
            (34, 8),
        }:
            raise ValueError("NVIDIA attempt policy is not the authorized fixed bound")
        self._max_attempts = max_attempts
        self._attempt_count = initial_attempt_count
        self._lock = threading.Lock()

    @classmethod
    def for_resume(cls) -> NvidiaAttemptLedger:
        return cls(max_attempts=24, initial_attempt_count=3)

    @classmethod
    def for_second_resume(cls) -> NvidiaAttemptLedger:
        return cls(max_attempts=25, initial_attempt_count=14)

    @classmethod
    def for_v4_probe_resume(cls) -> NvidiaAttemptLedger:
        return cls(max_attempts=MAX_HTTP_ATTEMPTS, initial_attempt_count=1)

    @classmethod
    def for_v5_two_probe_resume(cls) -> NvidiaAttemptLedger:
        return cls(max_attempts=MAX_HTTP_ATTEMPTS, initial_attempt_count=2)

    @classmethod
    def for_v5_three_validated_resume(cls) -> NvidiaAttemptLedger:
        return cls(max_attempts=MAX_HTTP_ATTEMPTS, initial_attempt_count=6)

    @classmethod
    def for_v5_attempt8_resume(cls) -> NvidiaAttemptLedger:
        return cls(max_attempts=MAX_HTTP_ATTEMPTS, initial_attempt_count=7)

    @classmethod
    def for_v5_attempt5_retaining(cls) -> NvidiaAttemptLedger:
        """Authorize 23 first passes plus three connect-only retry reservations."""

        return cls(max_attempts=34, initial_attempt_count=8)

    @property
    def attempt_count(self) -> int:
        with self._lock:
            return self._attempt_count

    @property
    def remaining_attempts(self) -> int:
        with self._lock:
            return self._max_attempts - self._attempt_count

    def reserve(self) -> NvidiaAttemptReservation:
        with self._lock:
            if self._attempt_count >= self._max_attempts:
                raise RuntimeError("NVIDIA_ATTEMPT_BUDGET_EXHAUSTED")
            self._attempt_count += 1
            return NvidiaAttemptReservation(attempt_number=self._attempt_count)


@dataclass(frozen=True, slots=True)
class NvidiaProfileAdapterResult:
    attempt: NvidiaMinimaxProfileAttempt
    candidate: NvidiaMinimaxModelDerivedProfile | None
    retry: bool
    raw_response: bytes | None = field(default=None, repr=False)
    rate_limit_headers: Mapping[str, str] = field(default_factory=dict)
    cooldown_seconds: int | None = None
    cooldown_source: str | None = None
    provider_publishable: bool | None = None
    request_body_sha256: str | None = None
    live_transport: bool = False


@dataclass(frozen=True, slots=True)
class NvidiaLocalProfileClassificationResult:
    """Local-only result shape that release materialization never accepts."""

    profile: NvidiaMinimaxModelDerivedProfile
    classification: NvidiaProfileRecommendationClassification


@dataclass(frozen=True, slots=True)
class NvidiaInvocationValidationResult:
    """Strict provider envelope validation independent of publication eligibility."""

    model: str
    finish_reason: str
    usage: NvidiaProviderTokenUsage
    content: Mapping[str, object]
    response_sha256: str


ClientFactory = Callable[..., httpx.AsyncClient]
CredentialReader = Callable[[], str]


def _new_httpx_async_client(
    *,
    headers: Mapping[str, str],
    timeout: httpx.Timeout,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        follow_redirects=False,
        trust_env=False,
    )


def _production_client_factory(
    *,
    headers: Mapping[str, str],
    timeout: httpx.Timeout,
) -> httpx.AsyncClient:
    return _new_httpx_async_client(headers=headers, timeout=timeout)


_PRODUCTION_CLIENT_FACTORY: Final[ClientFactory] = _production_client_factory


class NvidiaMinimaxProfileAdapter:
    """Concurrency-one NVIDIA adapter with one immutable endpoint/configuration."""

    def __init__(
        self,
        *,
        secret: str | None,
        config: NvidiaMinimaxProfileMaterializationConfig | None = None,
        ledger: NvidiaAttemptLedger | None = None,
        fresh_ledger: FreshNvidiaExposureLedger | None = None,
        credential_reader: CredentialReader | None = None,
        client_factory: ClientFactory | None = None,
        monotonic: Callable[[], float] | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        rate_limit_policy: NvidiaRateLimitPolicy | None = None,
        unknown_price_request_exposure: bool = False,
    ) -> None:
        if fresh_ledger is None and (not secret or secret.isspace()):
            raise ValueError("explicit NVIDIA credential is required")
        if fresh_ledger is not None and ledger is not None:
            raise ValueError("fresh NVIDIA lane cannot share the historical attempt ledger")
        if fresh_ledger is not None:
            if fresh_ledger.authority_id != FRESH_AUTHORITY_ID:
                raise ValueError("fresh NVIDIA exposure authority drifted")
            if config is not None and (
                config.endpoint != FRESH_ENDPOINT or config.model != FRESH_MODEL
            ):
                raise ValueError("fresh NVIDIA configuration drifted")
            if credential_reader is None and (not secret or secret.isspace()):
                raise ValueError("fresh NVIDIA lane requires a lazy credential reader")
        self._credential = secret or ""
        self._fresh_ledger = fresh_ledger
        self._credential_reader = credential_reader
        self._config = config or NvidiaMinimaxProfileMaterializationConfig()
        self._ledger = ledger or NvidiaAttemptLedger()
        self._client_factory = (
            client_factory if client_factory is not None else _PRODUCTION_CLIENT_FACTORY
        )
        self._monotonic = monotonic or time.monotonic
        self._sleeper = sleeper or asyncio.sleep
        self._rate_limit_policy = rate_limit_policy or NvidiaRateLimitPolicy()
        if unknown_price_request_exposure and (
            self._ledger.attempt_count != 8 or self._ledger.remaining_attempts != 26
        ):
            raise ValueError("unknown-price exposure requires the attempt-5-retaining ledger")
        self._unknown_price_request_exposure = unknown_price_request_exposure
        self._next_allowed_monotonic = 0.0
        self._semaphore = asyncio.Semaphore(1)

    @classmethod
    def for_fresh_authority(
        cls,
        *,
        ledger: FreshNvidiaExposureLedger,
        credential_reader: CredentialReader,
        config: NvidiaMinimaxProfileMaterializationConfig | None = None,
        client_factory: ClientFactory | None = None,
        monotonic: Callable[[], float] | None = None,
        sleeper: Callable[[float], Awaitable[None]] | None = None,
        rate_limit_policy: NvidiaRateLimitPolicy | None = None,
    ) -> NvidiaMinimaxProfileAdapter:
        """Construct a fresh adapter without reading the credential.

        The reader is invoked only after a durable exposure reservation has
        been created.  Existing callers continue using the historical
        constructor and ledger unchanged.
        """

        return cls(
            secret=None,
            config=config,
            fresh_ledger=ledger,
            credential_reader=credential_reader,
            client_factory=client_factory,
            monotonic=monotonic,
            sleeper=sleeper,
            rate_limit_policy=rate_limit_policy,
        )

    @property
    def config(self) -> NvidiaMinimaxProfileMaterializationConfig:
        return self._config

    @property
    def ledger(self) -> NvidiaAttemptLedger:
        return self._ledger

    @property
    def fresh_ledger(self) -> FreshNvidiaExposureLedger | None:
        return self._fresh_ledger

    @property
    def next_allowed_monotonic(self) -> float:
        return self._next_allowed_monotonic

    @property
    def unknown_price_request_exposure(self) -> bool:
        return self._unknown_price_request_exposure

    @property
    def release_authorizing_transport(self) -> bool:
        """Whether the exact callable used for transport is the sealed production factory."""

        return self._client_factory is _PRODUCTION_CLIENT_FACTORY

    async def attempt(
        self,
        *,
        place_id: str,
        request_body: bytes,
        lineage: Mapping[str, object],
        reservation_sink: Callable[[Mapping[str, object]], object] | None,
    ) -> NvidiaProfileAdapterResult:
        if reservation_sink is None:
            raise RuntimeError("DURABLE_PROVIDER_RESERVATION_REQUIRED")
        client_factory = self._client_factory
        live_transport = client_factory is _PRODUCTION_CLIENT_FACTORY
        await self._wait_until_allowed()
        fresh_reservation: FreshExposureReservation | None = None
        if self._fresh_ledger is not None:
            # This is deliberately the first capability-bearing operation in
            # the fresh lane.  Credential access and client construction come
            # only after the durable sink has accepted this entry.
            fresh_reservation = self._fresh_ledger.reserve()
            try:
                reservation_sink(
                    {
                        "schema_version": "itda.phase5-fresh-exposure-reservation.v1",
                        "authority_id": self._fresh_ledger.authority_id,
                        "provider_lane": self._config.provider_lane,
                        "endpoint": self._config.endpoint,
                        "model": self._config.model,
                        "attempt_number": fresh_reservation.attempt_number,
                        "reservation_id": fresh_reservation.reservation_id,
                        "reservation_micro_usd": fresh_reservation.amount_micro_usd,
                        "predecessor_sha256": fresh_reservation.predecessor_sha256,
                        "reservation_sha256": fresh_reservation.reservation_sha256,
                        "place_id": place_id,
                        "request_sha256": hashlib.sha256(request_body).hexdigest(),
                        "provider_price_status": "UNKNOWN",
                    }
                )
            except BaseException:
                self._fresh_ledger.release_before_socket(fresh_reservation)
                raise
            reservation_number = fresh_reservation.attempt_number
        else:
            reservation = self._ledger.reserve()
            reservation_number = reservation.attempt_number
            reservation_sink(
                {
                    "provider_lane": self._config.provider_lane,
                    "authority_sha256": self._config.authority_sha256,
                    "endpoint": self._config.endpoint,
                    "model": self._config.model,
                    "config_sha256": canonical_sha256(self._config.model_dump(mode="json")),
                    "attempt_number": reservation.attempt_number,
                    "place_id": place_id,
                    "lineage_request_sha256": lineage.get("request_sha256"),
                    "request_sha256": hashlib.sha256(request_body).hexdigest(),
                    "worst_case_charge_micro_usd": (
                        None if self._unknown_price_request_exposure else 0
                    ),
                    "provider_price_status": (
                        "UNKNOWN" if self._unknown_price_request_exposure else "ZERO_RECORDED"
                    ),
                    "cost_exposure_request_equivalents": (
                        1 if self._unknown_price_request_exposure else 0
                    ),
                }
            )
        request_body_sha256 = hashlib.sha256(request_body).hexdigest()
        started_at = datetime.now(UTC)
        started = self._monotonic()
        timeout = httpx.Timeout(
            connect=float(self._config.connect_seconds),
            pool=float(self._config.pool_seconds),
            write=float(self._config.write_seconds),
            read=float(self._config.read_seconds),
        )
        credential = self._credential
        if self._fresh_ledger is not None and self._credential_reader is not None:
            try:
                credential = self._credential_reader()
            except BaseException:
                assert fresh_reservation is not None
                self._fresh_ledger.release_before_socket(fresh_reservation)
                raise
            if not isinstance(credential, str) or not credential.strip():
                assert fresh_reservation is not None
                self._fresh_ledger.release_before_socket(fresh_reservation)
                raise RuntimeError("FRESH_NVIDIA_SECRET_UNAVAILABLE")
        transport_exposed = False
        try:
            client = client_factory(
                headers={
                    "Authorization": f"Bearer {credential}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if self._fresh_ledger is not None:
                assert fresh_reservation is not None
                self._fresh_ledger.release_before_socket(fresh_reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=reservation_number,
                lineage=lineage,
                outcome="TRANSPORT_ERROR",
                error_code="CLIENT_FACTORY_ERROR",
                error_reason=(
                    "NVIDIA client factory failed: "
                    + _safe_reason(str(error).replace(credential, "[REDACTED]"))
                ),
                retry=False,
                started=started,
                started_at=started_at,
                request_body_sha256=request_body_sha256,
                live_transport=live_transport,
            )
        try:
            async with asyncio.timeout(self._config.attempt_deadline_seconds):
                try:
                    async with (
                        self._semaphore,
                        client.stream(
                            "POST",
                            self._config.endpoint,
                            content=request_body,
                        ) as response,
                    ):
                        transport_exposed = True
                        raw = await self._read_bounded(response, started=started)
                finally:
                    await client.aclose()
        except asyncio.CancelledError:
            if self._fresh_ledger is not None and transport_exposed:
                assert fresh_reservation is not None
                self._fresh_ledger.commit(fresh_reservation)
            raise
        except TimeoutError:
            if self._fresh_ledger is not None:
                assert fresh_reservation is not None
                self._fresh_ledger.commit(fresh_reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=reservation_number,
                lineage=lineage,
                outcome="ATTEMPT_DEADLINE_EXCEEDED",
                error_code="ATTEMPT_DEADLINE_EXCEEDED",
                error_reason="whole attempt exceeded 300 seconds",
                retry=False,
                started=started,
                started_at=started_at,
                request_body_sha256=request_body_sha256,
                live_transport=live_transport,
            )
        except httpx.DecodingError as error:
            if self._fresh_ledger is not None:
                assert fresh_reservation is not None
                self._fresh_ledger.commit(fresh_reservation)
            message = str(error)
            return self._failure(
                place_id=place_id,
                attempt_number=reservation_number,
                lineage=lineage,
                outcome="RESPONSE_INVALID",
                error_code=(
                    "RESPONSE_BYTE_LIMIT_EXCEEDED"
                    if "byte limit" in message
                    else "RESPONSE_BODY_INVALID"
                ),
                error_reason=message,
                retry=False,
                started=started,
                started_at=started_at,
                request_body_sha256=request_body_sha256,
                live_transport=live_transport,
            )
        except httpx.TransportError as error:
            if self._fresh_ledger is not None:
                assert fresh_reservation is not None
                self._fresh_ledger.commit(fresh_reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=reservation_number,
                lineage=lineage,
                outcome="TRANSPORT_ERROR",
                error_code=type(error).__name__.upper(),
                error_reason=_safe_reason(str(error)),
                retry=isinstance(error, _RETRYABLE_TRANSPORT),
                started=started,
                started_at=started_at,
                request_body_sha256=request_body_sha256,
                live_transport=live_transport,
            )
        if self._fresh_ledger is not None:
            assert fresh_reservation is not None
            self._fresh_ledger.commit(fresh_reservation)
        stored_raw = raw.replace(credential.encode("utf-8"), b"[REDACTED]")
        response_sha256 = hashlib.sha256(stored_raw).hexdigest()
        if response.status_code != 200:
            provider_code, provider_reason = _safe_provider_error(stored_raw)
            rate_limit_headers = (
                _safe_rate_limit_headers(response.headers, credential=credential)
                if response.status_code == 429
                else {}
            )
            cooldown_seconds: int | None = None
            cooldown_source: str | None = None
            if response.status_code == 429:
                cooldown_seconds, cooldown_source = self._rate_limit_cooldown(rate_limit_headers)
                self._next_allowed_monotonic = max(
                    self._next_allowed_monotonic,
                    self._monotonic() + cooldown_seconds,
                )
            error_code = f"HTTP_{response.status_code}"
            if provider_code is not None:
                error_code += f"_PROVIDER_{provider_code}"
            return self._failure(
                place_id=place_id,
                attempt_number=reservation_number,
                lineage=lineage,
                outcome="HTTP_ERROR",
                error_code=error_code,
                error_reason=provider_reason or f"HTTP {response.status_code}",
                retry=response.status_code in _RETRYABLE_HTTP,
                started=started,
                started_at=started_at,
                request_body_sha256=request_body_sha256,
                http_status=response.status_code,
                response_sha256=response_sha256,
                raw_response=stored_raw,
                rate_limit_headers=rate_limit_headers,
                cooldown_seconds=cooldown_seconds,
                cooldown_source=cooldown_source,
                live_transport=live_transport,
            )
        try:
            payload = json.loads(stored_raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._failure(
                place_id=place_id,
                attempt_number=reservation_number,
                lineage=lineage,
                outcome="RESPONSE_INVALID",
                error_code="RESPONSE_JSON_INVALID",
                error_reason="provider response is not valid JSON",
                retry=False,
                started=started,
                started_at=started_at,
                http_status=200,
                response_sha256=response_sha256,
                raw_response=stored_raw,
                request_body_sha256=request_body_sha256,
                live_transport=live_transport,
            )
        result = self._validate_payload(
            place_id=place_id,
            payload=payload,
            lineage=lineage,
            attempt_number=reservation_number,
            started=started,
            started_at=started_at,
            raw_response=stored_raw,
            request_body_sha256=request_body_sha256,
            live_transport=live_transport,
        )
        if result.candidate is not None:
            self._next_allowed_monotonic = max(
                self._next_allowed_monotonic,
                self._monotonic() + self._rate_limit_policy.minimum_interval_seconds,
            )
        return result

    async def _wait_until_allowed(self) -> None:
        delay = max(0.0, self._next_allowed_monotonic - self._monotonic())
        if delay > 0:
            await self._sleeper(delay)

    async def pace_retry(self, minimum_seconds: int) -> None:
        """Apply explicit connect-retry pacing through the injected safe sleeper."""

        if minimum_seconds < 60:
            raise ValueError("NVIDIA retry pacing cannot be below 60 seconds")
        await self._sleeper(float(minimum_seconds))

    def _rate_limit_cooldown(self, headers: Mapping[str, str]) -> tuple[int, str]:
        raw_retry_after = headers.get("retry-after")
        if raw_retry_after is not None:
            try:
                parsed = int(raw_retry_after, 10)
            except ValueError:
                parsed = self._rate_limit_policy.default_cooldown_seconds
            else:
                return (
                    max(
                        self._rate_limit_policy.minimum_cooldown_seconds,
                        min(parsed, self._rate_limit_policy.maximum_cooldown_seconds),
                    ),
                    "RETRY_AFTER",
                )
        return self._rate_limit_policy.default_cooldown_seconds, "DEFAULT"

    async def _read_bounded(self, response: httpx.Response, *, started: float) -> bytes:
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError as error:
                raise httpx.DecodingError("invalid content length") from error
            if not 0 <= declared_size <= MAX_PROVIDER_RESPONSE_BYTES:
                raise httpx.DecodingError("provider response byte limit exceeded")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            if self._monotonic() - started > self._config.attempt_deadline_seconds:
                raise TimeoutError
            if len(body) + len(chunk) > MAX_PROVIDER_RESPONSE_BYTES:
                raise httpx.DecodingError("provider response byte limit exceeded")
            body.extend(chunk)
        return bytes(body)

    def validate_invocation_response(
        self,
        *,
        payload: Mapping[str, object],
        approved_evidence_ids: set[str] | frozenset[str] | None = None,
    ) -> NvidiaInvocationValidationResult:
        """Validate only invocation viability, without constructing a profile."""

        response_sha256 = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
        normalized = _normalize_response_payload(
            payload,
            lineage={},
            start_sentinel=self._config.json_start_sentinel,
            end_sentinel=self._config.json_end_sentinel,
            maximum_json_bytes=self._config.bounded_json_max_bytes,
        )
        model = normalized.get("model")
        finish_reason = normalized.get("finish_reason")
        usage = NvidiaProviderTokenUsage.model_validate(normalized["usage"])
        content = normalized.get("content")
        if (
            model != self._config.model
            or finish_reason != "stop"
            or not isinstance(content, Mapping)
        ):
            raise ValueError("strict invocation response envelope is invalid")
        _validate_invocation_profile_shape(
            content,
            approved_evidence_ids=approved_evidence_ids,
        )
        if not isinstance(content.get("confidence"), int) or isinstance(
            content.get("confidence"), bool
        ):
            raise ValueError("strict invocation confidence is invalid")
        if not 0 <= content["confidence"] <= 100:
            raise ValueError("strict invocation confidence is invalid")
        if type(content.get("publishable")) is not bool:
            raise ValueError("strict invocation publishable flag is invalid")
        return NvidiaInvocationValidationResult(
            model=model,
            finish_reason=finish_reason,
            usage=usage,
            content=dict(content),
            response_sha256=response_sha256,
        )

    def validate_replay_response(
        self,
        *,
        place_id: str,
        payload: Mapping[str, object],
        lineage: Mapping[str, object],
    ) -> NvidiaProfileAdapterResult:
        reservation = self._ledger.reserve()
        started_at = datetime.now(UTC)
        return self._validate_payload(
            place_id=place_id,
            payload=payload,
            lineage=lineage,
            attempt_number=reservation.attempt_number,
            started=self._monotonic(),
            started_at=started_at,
            raw_response=None,
        )

    def validate_replay_raw_response(
        self,
        *,
        place_id: str,
        raw_response: bytes,
        lineage: Mapping[str, object],
    ) -> NvidiaProfileAdapterResult:
        try:
            payload = json.loads(raw_response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("predecessor raw response is not valid JSON") from error
        if not isinstance(payload, Mapping):
            raise ValueError("predecessor raw response is not a JSON object")
        reservation = self._ledger.reserve()
        started_at = datetime.now(UTC)
        return self._validate_payload(
            place_id=place_id,
            payload=payload,
            lineage=lineage,
            attempt_number=reservation.attempt_number,
            started=self._monotonic(),
            started_at=started_at,
            raw_response=raw_response,
        )

    def classify_digest_bound_raw_response(
        self,
        *,
        place_id: str,
        raw_response: bytes,
        lineage: Mapping[str, object],
        expected_response_sha256: str,
        expected_lineage_sha256: str,
    ) -> NvidiaLocalProfileClassificationResult:
        """Locally classify exact immutable bytes without granting release authority."""

        actual_response_sha256 = hashlib.sha256(raw_response).hexdigest()
        actual_lineage_sha256 = canonical_sha256(lineage)
        if (
            re.fullmatch(r"[0-9a-f]{64}", expected_response_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_lineage_sha256) is None
            or not hmac.compare_digest(actual_response_sha256, expected_response_sha256)
            or not hmac.compare_digest(actual_lineage_sha256, expected_lineage_sha256)
        ):
            raise ValueError("digest-bound NVIDIA replay evidence mismatch")
        try:
            payload = json.loads(raw_response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("predecessor raw response is not valid JSON") from error
        if not isinstance(payload, Mapping):
            raise ValueError("predecessor raw response is not a JSON object")
        local_lineage = NvidiaLocalProfileLineage.model_validate(lineage)
        if (
            canonical_sha256(local_lineage.model_dump(mode="json", exclude_none=True))
            != actual_lineage_sha256
        ):
            raise ValueError("digest-bound NVIDIA replay lineage normalization drifted")
        started_at = datetime.now(UTC)
        validated = self._validate_payload(
            place_id=place_id,
            payload=payload,
            lineage=lineage,
            attempt_number=1,
            started=self._monotonic(),
            started_at=started_at,
            raw_response=raw_response,
            allow_low_confidence_local_replay=True,
        )
        if validated.candidate is None:
            raise ValueError("digest-bound NVIDIA replay profile is structurally invalid")
        eligibility = evaluate_nvidia_profile_publication(
            validated.candidate.model_dump(mode="json")
        )
        if not eligibility.eligible:
            raise ValueError("digest-bound NVIDIA replay profile is structurally invalid")
        classification = NvidiaProfileRecommendationClassification.model_validate(
            seal_demo_contract(
                {
                    "schema_version": ("itda.nvidia-profile-recommendation-classification.v1"),
                    "profile_sha256": validated.candidate.profile_sha256,
                    "response_sha256": actual_response_sha256,
                    "lineage": local_lineage.model_dump(mode="json"),
                    "lineage_sha256": actual_lineage_sha256,
                    "confidence": validated.candidate.confidence,
                    "recommendation_eligible": eligibility.recommendation_eligible,
                    "recommendation_eligibility_reason": eligibility.reason,
                    "release_eligible": False,
                },
                digest_field="classification_sha256",
            )
        )
        return NvidiaLocalProfileClassificationResult(
            profile=validated.candidate,
            classification=classification,
        )

    def _validate_payload(
        self,
        *,
        place_id: str,
        payload: Mapping[str, object],
        lineage: Mapping[str, object],
        attempt_number: int,
        started: float,
        started_at: datetime,
        raw_response: bytes | None,
        allow_low_confidence_local_replay: bool = False,
        request_body_sha256: str | None = None,
        live_transport: bool = False,
    ) -> NvidiaProfileAdapterResult:
        response_sha256 = hashlib.sha256(
            raw_response if raw_response is not None else _canonical_bytes(payload)
        ).hexdigest()
        try:
            prompt_version = lineage.get("prompt_version")
            if not isinstance(prompt_version, str):
                raise ValueError("NVIDIA profile prompt lineage is absent")
            profile_schema_version = {
                "phase5-demo-profile-sentinel-json.v4": (
                    "itda.nvidia-minimax-model-derived-profile.v4"
                ),
                "phase5-demo-profile-sentinel-json.v5": (
                    "itda.nvidia-minimax-model-derived-profile.v5"
                ),
            }.get(prompt_version)
            if profile_schema_version is None:
                raise ValueError("NVIDIA profile prompt lineage is unsupported")
            normalized = _normalize_response_payload(
                payload,
                lineage=lineage,
                start_sentinel=self._config.json_start_sentinel,
                end_sentinel=self._config.json_end_sentinel,
                maximum_json_bytes=self._config.bounded_json_max_bytes,
            )
            usage = NvidiaProviderTokenUsage.model_validate(normalized["usage"])
            if normalized["model"] != self._config.model:
                raise ValueError("returned model mismatch")
            if normalized["finish_reason"] != "stop":
                raise ValueError("non-stop finish")
            content = normalized["content"]
            if not isinstance(content, Mapping):
                raise ValueError("profile content is absent")
            provider_publishable = content.get("publishable")
            if type(provider_publishable) is not bool:
                raise ValueError("provider publishable diagnostic must be a strict boolean")
            eligibility = evaluate_nvidia_profile_publication(content)
            if not eligibility.eligible:
                raise ValueError(eligibility.reason)
            if not eligibility.recommendation_eligible and not (
                allow_low_confidence_local_replay or self._fresh_ledger is not None
            ):
                raise ValueError("PROFILE_CONFIDENCE_INELIGIBLE")
            profile_payload: dict[str, object] = {
                "schema_version": profile_schema_version,
                "analysis_origin": "DEMO_MODEL_DERIVED",
                "place_id": place_id,
                "split": "DEV",
                "axis_scores": content.get("axis_scores"),
                "subattributes": content.get("subattributes"),
                "mismatch_traits": content.get("mismatch_traits"),
                "evidence_justifications": content.get("evidence_justifications"),
                "evidence_ids": content.get("evidence_ids"),
                "confidence": content.get("confidence"),
                "publishable": True,
                "model": self._config.model,
                "provider_lane": self._config.provider_lane,
                "endpoint": self._config.endpoint,
                "prompt_version": lineage.get("prompt_version"),
                "prompt_sha256": lineage.get("prompt_sha256"),
                "profile_schema_sha256": lineage.get("profile_schema_sha256"),
                "config_sha256": lineage.get("config_sha256"),
                "authority_sha256": NVIDIA_AUTHORITY_SHA256,
                "source_bundle_sha256": lineage.get("source_bundle_sha256"),
                "evidence_inventory_sha256": lineage.get("evidence_inventory_sha256"),
                "request_sha256": lineage.get("request_sha256"),
                "response_sha256": response_sha256,
                "created_at": lineage.get("created_at"),
            }
            known_evidence_ids = lineage.get("evidence_ids")
            if not isinstance(known_evidence_ids, (list, tuple)):
                raise ValueError("profile evidence lineage is absent")
            candidate = NvidiaMinimaxModelDerivedProfile.model_validate(
                seal_demo_contract(profile_payload, digest_field="profile_sha256"),
                context={"known_evidence_ids": set(known_evidence_ids)},
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            ValidationError,
            json.JSONDecodeError,
            RecursionError,
        ):
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                lineage=lineage,
                outcome="RESPONSE_INVALID",
                error_code="PROVIDER_RESPONSE_TERMINAL_INVALID",
                error_reason="response envelope or profile schema validation failed",
                retry=False,
                started=started,
                started_at=started_at,
                http_status=200 if payload else None,
                response_sha256=response_sha256 if payload else None,
                raw_response=raw_response,
                request_body_sha256=request_body_sha256,
                live_transport=live_transport,
            )
        attempt = self._attempt_contract(
            place_id=place_id,
            attempt_number=attempt_number,
            lineage=lineage,
            outcome="VALIDATED",
            retry=False,
            http_status=200,
            error_code=None,
            error_reason=None,
            returned_model=self._config.model,
            finish_reason="stop",
            response_sha256=response_sha256,
            usage=usage,
            started=started,
            started_at=started_at,
        )
        result = NvidiaProfileAdapterResult(
            attempt=attempt,
            candidate=candidate,
            retry=False,
            raw_response=raw_response,
            provider_publishable=provider_publishable,
            request_body_sha256=request_body_sha256,
            live_transport=live_transport,
        )
        return result

    def _failure(
        self,
        *,
        place_id: str,
        attempt_number: int,
        lineage: Mapping[str, object],
        outcome: str,
        error_code: str,
        error_reason: str,
        retry: bool,
        started: float,
        started_at: datetime,
        http_status: int | None = None,
        response_sha256: str | None = None,
        raw_response: bytes | None = None,
        rate_limit_headers: Mapping[str, str] | None = None,
        cooldown_seconds: int | None = None,
        cooldown_source: str | None = None,
        request_body_sha256: str | None = None,
        live_transport: bool = False,
    ) -> NvidiaProfileAdapterResult:
        attempt = self._attempt_contract(
            place_id=place_id,
            attempt_number=attempt_number,
            lineage=lineage,
            outcome=outcome,
            retry=retry,
            http_status=http_status,
            error_code=error_code,
            error_reason=_safe_reason(error_reason, credential=self._credential),
            returned_model=None,
            finish_reason=None,
            response_sha256=response_sha256,
            usage=None,
            started=started,
            started_at=started_at,
        )
        result = NvidiaProfileAdapterResult(
            attempt=attempt,
            candidate=None,
            retry=retry,
            raw_response=raw_response,
            rate_limit_headers=dict(rate_limit_headers or {}),
            cooldown_seconds=cooldown_seconds,
            cooldown_source=cooldown_source,
            request_body_sha256=request_body_sha256,
            live_transport=live_transport,
        )
        return result

    def _attempt_contract(
        self,
        *,
        place_id: str,
        attempt_number: int,
        lineage: Mapping[str, object],
        outcome: str,
        retry: bool,
        http_status: int | None,
        error_code: str | None,
        error_reason: str | None,
        returned_model: str | None,
        finish_reason: str | None,
        response_sha256: str | None,
        usage: NvidiaProviderTokenUsage | None,
        started: float,
        started_at: datetime,
    ) -> NvidiaMinimaxProfileAttempt:
        completed_at = datetime.now(UTC)
        duration_ms = max(0, min(300_000, int((self._monotonic() - started) * 1000)))
        fields: dict[str, object] = {
            "schema_version": "itda.nvidia-minimax-profile-attempt.v3",
            "place_id": place_id,
            "attempt_number": attempt_number,
            "outcome": outcome,
            "retry": retry,
            "http_status": http_status,
            "error_code": error_code,
            "error_reason": error_reason,
            "returned_model": returned_model,
            "finish_reason": finish_reason,
            "request_sha256": lineage.get("request_sha256"),
            "response_sha256": response_sha256,
            "usage": usage.model_dump(mode="json") if usage is not None else None,
            "provider_lane": self._config.provider_lane,
            "endpoint": self._config.endpoint,
            "model": self._config.model,
            "config_sha256": canonical_sha256(self._config.model_dump(mode="json")),
            "authority_sha256": NVIDIA_AUTHORITY_SHA256,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
        }
        return NvidiaMinimaxProfileAttempt.model_validate(
            seal_demo_contract(fields, digest_field="attempt_sha256")
        )


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _safe_reason(value: str, *, credential: str | None = None) -> str:
    redacted = value.replace(credential, "[REDACTED]") if credential else value
    redacted = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", redacted)
    compact = " ".join(redacted.split())
    safe = "".join(character for character in compact if character.isprintable())
    return safe[:300] or "provider returned no safe reason"


def _safe_provider_error(raw_response: bytes) -> tuple[str | None, str | None]:
    try:
        payload = json.loads(raw_response)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None
    if not isinstance(payload, Mapping):
        return None, None
    error = payload.get("error")
    if not isinstance(error, Mapping):
        return None, None
    raw_code = error.get("code")
    code: str | None = None
    if isinstance(raw_code, (str, int)) and not isinstance(raw_code, bool):
        normalized = re.sub(r"[^A-Z0-9]+", "_", str(raw_code).upper()).strip("_")
        code = normalized if 0 < len(normalized) <= 48 else None
    message = error.get("message")
    reason = _safe_reason(message) if isinstance(message, str) else None
    return code, reason


def _safe_rate_limit_headers(
    headers: httpx.Headers,
    *,
    credential: str,
) -> dict[str, str]:
    safe: dict[str, str] = {}
    for name, raw_value in headers.multi_items():
        normalized_name = name.lower()
        if normalized_name not in _RATE_LIMIT_HEADER_ALLOWLIST:
            continue
        redacted = raw_value.replace(credential, "[REDACTED]")
        normalized_value = _safe_reason(redacted)[:128]
        if normalized_name in safe:
            safe[normalized_name] = f"{safe[normalized_name]}, {normalized_value}"[:128]
        else:
            safe[normalized_name] = normalized_value
    return dict(sorted(safe.items()))


def _normalize_response_payload(
    payload: Mapping[str, object],
    *,
    lineage: Mapping[str, object],
    start_sentinel: str,
    end_sentinel: str,
    maximum_json_bytes: int,
) -> dict[str, object]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("provider response requires exactly one choice")
    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise ValueError("provider choice is invalid")
    message = choice.get("message")
    if not isinstance(message, Mapping) or message.get("role") != "assistant":
        raise ValueError("provider assistant message is invalid")
    if message.get("tool_calls") not in (None, []):
        raise ValueError("provider emitted prohibited tool calls")
    assistant_content = message.get("content")
    if not isinstance(assistant_content, str):
        raise ValueError("provider sentinel content is absent")
    content = _extract_sentinel_bounded_json(
        assistant_content,
        start_sentinel=start_sentinel,
        end_sentinel=end_sentinel,
        maximum_json_bytes=maximum_json_bytes,
    )
    _require_exact_profile_shape(content)
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        raise ValueError("provider usage is absent")
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")
    details = usage.get("prompt_tokens_details")
    cached_tokens = details.get("cached_tokens", 0) if isinstance(details, Mapping) else 0
    return {
        "model": payload.get("model"),
        "finish_reason": choice.get("finish_reason"),
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cached_tokens": cached_tokens,
            "total_tokens": total_tokens,
        },
        "content": dict(content),
        "lineage": dict(lineage),
    }


def _extract_sentinel_bounded_json(
    content: str,
    *,
    start_sentinel: str,
    end_sentinel: str,
    maximum_json_bytes: int,
) -> Mapping[str, object]:
    if (
        not start_sentinel
        or not end_sentinel
        or start_sentinel == end_sentinel
        or content.count(start_sentinel) != 1
        or content.count(end_sentinel) != 1
    ):
        raise ValueError("provider sentinel cardinality is invalid")
    start = content.index(start_sentinel)
    json_start = start + len(start_sentinel)
    end = content.index(end_sentinel)
    if end <= json_start:
        raise ValueError("provider sentinels are reversed or empty")
    if content[:start].strip() or content[end + len(end_sentinel) :].strip():
        raise ValueError("provider emitted content outside sentinels")
    bounded = content[json_start:end]
    encoded = bounded.encode("utf-8")
    if not 0 < len(encoded) <= maximum_json_bytes:
        raise ValueError("provider bounded JSON byte limit exceeded")
    decoded = json.loads(bounded)
    if not isinstance(decoded, Mapping):
        raise ValueError("provider profile content must be one object")
    return decoded


def _require_exact_profile_shape(content: Mapping[str, object]) -> None:
    if set(content) != {
        "axis_scores",
        "subattributes",
        "mismatch_traits",
        "evidence_justifications",
        "evidence_ids",
        "confidence",
        "publishable",
    }:
        raise ValueError("provider profile top-level schema drifted")
    axis_scores = content.get("axis_scores")
    subattributes = content.get("subattributes")
    mismatch_traits = content.get("mismatch_traits")
    if not isinstance(axis_scores, Mapping) or set(axis_scores) != {"H", "E", "R"}:
        raise ValueError("provider profile axis schema drifted")
    expected_subattributes = {
        f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)
    }
    if not isinstance(subattributes, Mapping) or set(subattributes) != expected_subattributes:
        raise ValueError("provider profile subattribute schema drifted")
    expected_mismatches = {f"M{index}" for index in range(1, 7)}
    if not isinstance(mismatch_traits, Mapping) or set(mismatch_traits) != expected_mismatches:
        raise ValueError("provider profile mismatch schema drifted")
    justifications = content.get("evidence_justifications")
    expected_justifications = {"H", "E", "R"} | expected_subattributes | expected_mismatches
    if not isinstance(justifications, Mapping) or set(justifications) != expected_justifications:
        raise ValueError("provider profile evidence-justification schema drifted")


def _validate_invocation_profile_shape(
    content: Mapping[str, object],
    *,
    approved_evidence_ids: set[str] | frozenset[str] | None,
) -> None:
    from pydantic import TypeAdapter

    _require_exact_profile_shape(content)
    TypeAdapter(dict[str, Annotated[int, Field(strict=True, ge=0, le=100)]]).validate_python(
        content["axis_scores"]
    )
    TypeAdapter(dict[str, Annotated[int, Field(strict=True, ge=0, le=4)]]).validate_python(
        content["subattributes"]
    )
    TypeAdapter(dict[str, Annotated[int, Field(strict=True, ge=0, le=100)]]).validate_python(
        content["mismatch_traits"]
    )
    evidence_ids = content.get("evidence_ids")
    justifications = content.get("evidence_justifications")
    if (
        not isinstance(evidence_ids, list)
        or not evidence_ids
        or len(evidence_ids) != len(set(evidence_ids))
        or any(not isinstance(item, str) or not item for item in evidence_ids)
        or (
            approved_evidence_ids is not None
            and set(evidence_ids) != set(approved_evidence_ids)
        )
        or not isinstance(justifications, Mapping)
        or any(
            not isinstance(values, list)
            or not values
            or any(item not in evidence_ids for item in values)
            or (
                approved_evidence_ids is not None
                and not set(values) <= set(approved_evidence_ids)
            )
            for values in justifications.values()
        )
    ):
        raise ValueError("strict invocation evidence inventory is invalid")




__all__ = [
    "NvidiaAttemptLedger",
    "NvidiaInvocationValidationResult",
    "NvidiaMinimaxProfileAdapter",
    "NvidiaProfileAdapterResult",
]
