"""Bounded direct-HTTP adapter for Phase 5 DEV profile materialization.

This module has no ambient credential or proxy access.  The explicit offline
CLI is the only caller allowed to pass a credential into the constructor.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field

import httpx
from pydantic import ValidationError

from itda.contracts.demo_profile_materialization import (
    ATTEMPT_RESERVATION_MICRO_USD,
    CODING_PLAN_MODEL_WEIGHT,
    MAX_HTTP_ATTEMPTS,
    MAX_PROVIDER_RESPONSE_BYTES,
    MAX_RUN_COST_MICRO_USD,
    PRICING_SNAPSHOT_SHA256,
    RERUN_COST_CAP_MICRO_USD,
    CodingPlanProfileAttempt,
    CodingPlanProfileMaterializationConfig,
    DemoModelDerivedProfile,
    DemoProfileAttempt,
    DemoProfileMaterializationConfig,
    PricingSnapshot,
    ProviderTokenUsage,
    ProviderUsageCharge,
    seal_demo_contract,
)

_RETRYABLE_HTTP = frozenset({429, 500, 502, 503, 504})
_RETRYABLE_TRANSPORT = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.WriteTimeout,
)


@dataclass(frozen=True, slots=True)
class CostReservation:
    reservation_id: int
    amount_micro_usd: int = ATTEMPT_RESERVATION_MICRO_USD


@dataclass(frozen=True, slots=True)
class CodingPlanAttemptReservation:
    attempt_number: int
    model_weight: int = CODING_PLAN_MODEL_WEIGHT


class CodingPlanAttemptLedger:
    """Separate subscription accounting; never mutates the pay-go cost ledger."""

    def __init__(self, *, max_attempts: int = MAX_HTTP_ATTEMPTS, model_weight: int = 1) -> None:
        if max_attempts != MAX_HTTP_ATTEMPTS or model_weight != CODING_PLAN_MODEL_WEIGHT:
            raise ValueError("Coding Plan attempt policy is not the authorized fixed bound")
        self._max_attempts = max_attempts
        self._model_weight = model_weight
        self._attempt_count = 0
        self._total_weight = 0
        self._lock = threading.Lock()

    @property
    def attempt_count(self) -> int:
        with self._lock:
            return self._attempt_count

    @property
    def total_weight(self) -> int:
        with self._lock:
            return self._total_weight

    @property
    def remaining_attempts(self) -> int:
        with self._lock:
            return self._max_attempts - self._attempt_count

    def reserve(self) -> CodingPlanAttemptReservation:
        with self._lock:
            if self._attempt_count >= self._max_attempts:
                raise RuntimeError("ATTEMPT_BUDGET_EXHAUSTED")
            self._attempt_count += 1
            self._total_weight += self._model_weight
            return CodingPlanAttemptReservation(
                attempt_number=self._attempt_count,
                model_weight=self._model_weight,
            )


class AttemptCostLedger:
    """Thread-safe conservative run-cost ledger.

    Every socket opportunity is funded before a client can be constructed.
    Unknown billing consumes the whole reservation; only valid final usage can
    refund the unused portion.
    """

    def __init__(
        self,
        *,
        committed_micro_usd: int = 0,
        max_cost_micro_usd: int = MAX_RUN_COST_MICRO_USD,
    ) -> None:
        if max_cost_micro_usd not in (MAX_RUN_COST_MICRO_USD, RERUN_COST_CAP_MICRO_USD):
            raise ValueError("cost cap is not an authorized fixed bound")
        if not 0 <= committed_micro_usd <= max_cost_micro_usd:
            raise ValueError("initial committed cost is outside the frozen cap")
        self._max_cost = max_cost_micro_usd
        self._committed = committed_micro_usd
        self._reservations: dict[int, int] = {}
        self._next_id = 1
        self._lock = threading.Lock()
        self._pricing = PricingSnapshot()

    @property
    def committed_micro_usd(self) -> int:
        with self._lock:
            return self._committed

    @property
    def outstanding_micro_usd(self) -> int:
        with self._lock:
            return sum(self._reservations.values())

    @property
    def remaining_cap_micro_usd(self) -> int:
        with self._lock:
            return self._max_cost - self._committed - sum(self._reservations.values())

    def reserve(self) -> CostReservation:
        with self._lock:
            outstanding = sum(self._reservations.values())
            projected = self._committed + outstanding + ATTEMPT_RESERVATION_MICRO_USD
            if projected > self._max_cost:
                raise RuntimeError("COST_BUDGET_EXHAUSTED")
            reservation = CostReservation(self._next_id)
            self._next_id += 1
            self._reservations[reservation.reservation_id] = reservation.amount_micro_usd
            return reservation

    def reconcile(
        self,
        reservation: CostReservation,
        usage: ProviderTokenUsage,
    ) -> ProviderUsageCharge:
        charge = self._pricing.charge(usage)
        with self._lock:
            reserved = self._pop_exact(reservation)
            if charge.total_micro_usd > reserved:
                self._committed += reserved
                raise RuntimeError("PROVIDER_USAGE_EXCEEDS_RESERVATION")
            self._committed += charge.total_micro_usd
        return charge

    def commit_unknown(self, reservation: CostReservation) -> int:
        with self._lock:
            reserved = self._pop_exact(reservation)
            self._committed += reserved
            return reserved

    def _pop_exact(self, reservation: CostReservation) -> int:
        reserved = self._reservations.pop(reservation.reservation_id, None)
        if reserved is None or reserved != reservation.amount_micro_usd:
            raise RuntimeError("INVALID_OR_REUSED_COST_RESERVATION")
        return reserved


class TwoPassAttemptBudget:
    """One canonical first pass, then at most six canonical-order retries."""

    def __init__(self, place_ids: Sequence[str]) -> None:
        canonical = tuple(place_ids)
        if len(canonical) != 24 or len(set(canonical)) != 24:
            raise ValueError("two-pass budget requires exactly 24 unique DEV places")
        if canonical != tuple(sorted(canonical)):
            raise ValueError("DEV place inventory must be in canonical ID order")
        self._place_ids = canonical
        self._first_completed: set[str] = set()
        self._attempt_count = 0

    @property
    def attempt_count(self) -> int:
        return self._attempt_count

    def first_pass(self) -> Iterable[str]:
        for place_id in self._place_ids:
            self.consume(place_id)
            self._first_completed.add(place_id)
            yield place_id

    def retry_pass(self, retryable_place_ids: Sequence[str]) -> Iterable[str]:
        if self._first_completed != set(self._place_ids):
            raise RuntimeError("RETRIES_FORBIDDEN_BEFORE_COMPLETE_FIRST_PASS")
        unknown = set(retryable_place_ids) - set(self._place_ids)
        if unknown:
            raise ValueError("retry inventory contains a non-DEV place")
        for place_id in tuple(sorted(set(retryable_place_ids)))[:6]:
            self.consume(place_id)
            yield place_id

    def consume(self, place_id: str) -> None:
        if place_id not in self._place_ids:
            raise ValueError("attempt place is outside the fixed DEV inventory")
        if self._attempt_count >= MAX_HTTP_ATTEMPTS:
            raise RuntimeError("ATTEMPT_BUDGET_EXHAUSTED")
        self._attempt_count += 1


def _safe_provider_error_code(raw_response: bytes) -> str | None:
    try:
        payload = json.loads(raw_response)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    error = payload.get("error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("code")
    if not isinstance(code, (str, int)) or isinstance(code, bool):
        return None
    normalized = re.sub(r"[^A-Z0-9]+", "_", str(code).upper()).strip("_")
    return normalized if 0 < len(normalized) <= 48 else None


def classify_retry(
    *,
    error: BaseException | None,
    status_code: int | None,
    provider_code: str | None = None,
) -> bool:
    if error is not None:
        return isinstance(error, _RETRYABLE_TRANSPORT)
    if status_code == 429 and provider_code == "1113":
        return False
    return status_code in _RETRYABLE_HTTP


@dataclass(frozen=True, slots=True)
class ProfileAdapterResult:
    attempt: DemoProfileAttempt | CodingPlanProfileAttempt
    candidate: DemoModelDerivedProfile | None
    retry: bool
    raw_response: bytes | None = field(default=None, repr=False)


ClientFactory = Callable[..., httpx.AsyncClient]


class ZhipuGlm5vProfileAdapter:
    """Concurrency-one profile adapter with frozen cost and transport policy."""

    def __init__(
        self,
        *,
        secret: str,
        ledger: AttemptCostLedger | None = None,
        config: DemoProfileMaterializationConfig
        | CodingPlanProfileMaterializationConfig
        | None = None,
        coding_plan_ledger: CodingPlanAttemptLedger | None = None,
        client_factory: ClientFactory | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if not secret or secret.isspace():
            raise ValueError("explicit provider credential is required")
        self._credential = secret
        self._config = config or DemoProfileMaterializationConfig()
        self._ledger: AttemptCostLedger | None
        self._coding_plan_ledger: CodingPlanAttemptLedger | None
        if isinstance(self._config, CodingPlanProfileMaterializationConfig):
            if ledger is not None:
                raise ValueError("Coding Plan cannot reuse the pay-go cost ledger")
            self._ledger = None
            self._coding_plan_ledger = coding_plan_ledger or CodingPlanAttemptLedger()
        else:
            if coding_plan_ledger is not None:
                raise ValueError("general API cannot use Coding Plan accounting")
            self._ledger = ledger or AttemptCostLedger()
            self._coding_plan_ledger = None
        self._client_factory = client_factory or self._default_client
        self._monotonic = monotonic or time.monotonic
        self._semaphore = asyncio.Semaphore(1)
        self._attempt_number = 0

    @property
    def ledger(self) -> AttemptCostLedger:
        if self._ledger is None:
            raise RuntimeError("PAY_GO_LEDGER_UNAVAILABLE_FOR_CODING_PLAN")
        return self._ledger

    @property
    def coding_plan_ledger(self) -> CodingPlanAttemptLedger:
        if self._coding_plan_ledger is None:
            raise RuntimeError("CODING_PLAN_LEDGER_UNAVAILABLE_FOR_GENERAL_API")
        return self._coding_plan_ledger

    @property
    def is_coding_plan(self) -> bool:
        return isinstance(self._config, CodingPlanProfileMaterializationConfig)

    @property
    def config(
        self,
    ) -> DemoProfileMaterializationConfig | CodingPlanProfileMaterializationConfig:
        return self._config

    @staticmethod
    def _default_client(
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

    async def attempt(
        self,
        *,
        place_id: str,
        request_body: bytes,
        lineage: Mapping[str, object] | None = None,
        reservation_sink: Callable[[Mapping[str, object]], None] | None,
    ) -> ProfileAdapterResult:
        """Execute one paid attempt; callers cannot override any policy value."""

        if reservation_sink is None:
            raise RuntimeError("DURABLE_PROVIDER_RESERVATION_REQUIRED")
        reservation = self._ledger.reserve() if self._ledger is not None else None
        if self._coding_plan_ledger is not None:
            self._coding_plan_ledger.reserve()
        self._attempt_number += 1
        attempt_number = self._attempt_number
        provider_lane = (
            self._config.provider_lane
            if isinstance(self._config, CodingPlanProfileMaterializationConfig)
            else "ZHIPU_PAY_GO"
        )
        reservation_sink(
            {
                "provider_lane": provider_lane,
                "attempt_number": attempt_number,
                "place_id": place_id,
                "request_sha256": hashlib.sha256(request_body).hexdigest(),
                "worst_case_charge_micro_usd": (
                    reservation.amount_micro_usd if reservation is not None else 0
                ),
            }
        )
        started = self._monotonic()
        try:
            timeout = httpx.Timeout(connect=10.0, pool=10.0, write=30.0, read=180.0)
            client = self._client_factory(
                headers={
                    "Authorization": f"Bearer {self._credential}",
                    "Content-Type": "application/json",
                },
                timeout=timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code="CLIENT_FACTORY_ERROR",
                outcome="TRANSPORT_ERROR",
                reservation=reservation,
                started=started,
            )

        try:
            async with self._semaphore:
                async with asyncio.timeout(self._config.attempt_deadline_seconds):
                    async with client.stream(
                        "POST",
                        self._config.endpoint,
                        content=request_body,
                    ) as response:
                        raw = await self._read_bounded(response, started=started)
        except asyncio.CancelledError:
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            raise
        except TimeoutError:
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code="ATTEMPT_DEADLINE_EXCEEDED",
                outcome="ATTEMPT_DEADLINE_EXCEEDED",
                reservation=reservation,
                started=started,
            )
        except httpx.DecodingError as error:
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            message = str(error)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code=(
                    "RESPONSE_BYTE_LIMIT_EXCEEDED"
                    if "byte limit" in message
                    else "RESPONSE_BODY_INVALID"
                ),
                outcome="RESPONSE_INVALID",
                retry=False,
                reservation=reservation,
                started=started,
            )
        except httpx.TransportError as error:
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code=type(error).__name__.upper(),
                outcome="TRANSPORT_ERROR",
                retry=classify_retry(error=error, status_code=None),
                reservation=reservation,
                started=started,
            )
        finally:
            await client.aclose()

        response_sha256 = hashlib.sha256(raw).hexdigest()
        if response.status_code != 200:
            provider_code = _safe_provider_error_code(raw)
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code=(
                    f"HTTP_{response.status_code}_PROVIDER_{provider_code}"
                    if provider_code is not None
                    else f"HTTP_{response.status_code}"
                ),
                outcome="HTTP_ERROR",
                retry=classify_retry(
                    error=None,
                    status_code=response.status_code,
                    provider_code=provider_code,
                ),
                http_status=response.status_code,
                response_sha256=response_sha256,
                reservation=reservation,
                started=started,
                raw_response=raw,
            )
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code="RESPONSE_JSON_INVALID",
                outcome="RESPONSE_INVALID",
                http_status=200,
                response_sha256=response_sha256,
                reservation=reservation,
                started=started,
                raw_response=raw,
            )
        return self._validate_payload(
            place_id=place_id,
            payload=payload,
            reservation=reservation,
            attempt_number=attempt_number,
            started=started,
            raw_response=raw,
            supplied_lineage=lineage,
        )

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

    def _safe_raw_response(self, raw_response: bytes | None) -> bytes | None:
        """Keep the digestable response only when it cannot contain the credential."""

        if raw_response is None:
            return None
        if self._credential.encode("utf-8") in raw_response:
            return None
        return raw_response

    def validate_replay_response(
        self,
        *,
        place_id: str,
        payload: Mapping[str, object],
        lineage: Mapping[str, object] | None = None,
    ) -> ProfileAdapterResult:
        reservation = self._ledger.reserve() if self._ledger is not None else None
        if self._coding_plan_ledger is not None:
            self._coding_plan_ledger.reserve()
        self._attempt_number += 1
        return self._validate_payload(
            place_id=place_id,
            payload=payload,
            reservation=reservation,
            attempt_number=self._attempt_number,
            started=self._monotonic(),
            raw_response=None,
            supplied_lineage=lineage,
        )

    def _validate_payload(
        self,
        *,
        place_id: str,
        payload: Mapping[str, object],
        reservation: CostReservation | None,
        attempt_number: int,
        started: float,
        raw_response: bytes | None,
        supplied_lineage: Mapping[str, object] | None,
        sanitize_raw_response: bool = True,
    ) -> ProfileAdapterResult:
        response_sha256 = hashlib.sha256(
            raw_response if raw_response is not None else _canonical_bytes(payload)
        ).hexdigest()
        try:
            normalized = _normalize_response_payload(payload, supplied_lineage=supplied_lineage)
        except (ValueError, TypeError, json.JSONDecodeError):
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code="PROVIDER_RESPONSE_TERMINAL_INVALID",
                outcome="RESPONSE_INVALID",
                http_status=200 if payload else None,
                response_sha256=response_sha256 if payload else None,
                reservation=reservation,
                started=started,
                raw_response=raw_response,
                sanitize_raw_response=sanitize_raw_response,
            )
        usage_payload = normalized.get("usage")
        usage: ProviderTokenUsage | None = None
        try:
            usage = ProviderTokenUsage.model_validate(usage_payload)
            if normalized.get("model") != self._config.model:
                raise ValueError("returned model mismatch")
            if normalized.get("finish_reason") != "stop":
                raise ValueError("non-stop finish")
            content = normalized.get("content")
            if not isinstance(content, Mapping):
                raise ValueError("profile content is absent")
            lineage = normalized.get("lineage")
            if not isinstance(lineage, Mapping):
                raise ValueError("profile lineage is absent")
            profile_payload: dict[str, object] = {
                "schema_version": "itda.demo-model-derived-profile.v1",
                "analysis_origin": "DEMO_MODEL_DERIVED",
                "place_id": place_id,
                "split": "DEV",
                "axis_scores": content.get("axis_scores"),
                "subattributes": content.get("subattributes"),
                "mismatch_traits": content.get("mismatch_traits"),
                "evidence_ids": content.get("evidence_ids"),
                "confidence": content.get("confidence"),
                "publishable": content.get("publishable"),
                "model": self._config.model,
                "prompt_version": lineage.get("prompt_version"),
                "prompt_sha256": lineage.get("prompt_sha256"),
                "profile_schema_sha256": lineage.get("profile_schema_sha256"),
                "config_sha256": lineage.get("config_sha256"),
                "source_bundle_sha256": lineage.get("source_bundle_sha256"),
                "evidence_inventory_sha256": lineage.get("evidence_inventory_sha256"),
                "request_sha256": lineage.get("request_sha256"),
                "response_sha256": response_sha256,
                "pricing_snapshot_sha256": PRICING_SNAPSHOT_SHA256,
                "created_at": lineage.get("created_at"),
            }
            candidate = DemoModelDerivedProfile.model_validate(
                seal_demo_contract(profile_payload, digest_field="profile_sha256"),
                context={"known_evidence_ids": set(lineage.get("evidence_ids", ()))},
            )
        except (ValidationError, ValueError, TypeError):
            if reservation is not None:
                self.ledger.commit_unknown(reservation)
            return self._failure(
                place_id=place_id,
                attempt_number=attempt_number,
                error_code="PROVIDER_RESPONSE_TERMINAL_INVALID",
                outcome="RESPONSE_INVALID",
                http_status=200 if payload else None,
                response_sha256=response_sha256 if payload else None,
                reservation=reservation,
                started=started,
                raw_response=raw_response,
                sanitize_raw_response=sanitize_raw_response,
            )

        charge = self.ledger.reconcile(reservation, usage) if reservation is not None else None
        attempt = self._attempt_contract(
            place_id=place_id,
            attempt_number=attempt_number,
            outcome="VALIDATED",
            retry=False,
            http_status=200,
            error_code=None,
            returned_model=self._config.model,
            finish_reason="stop",
            response_sha256=response_sha256,
            usage=usage,
            committed=charge.total_micro_usd if charge is not None else 0,
            refund=(
                ATTEMPT_RESERVATION_MICRO_USD - charge.total_micro_usd if charge is not None else 0
            ),
            started=started,
        )
        return ProfileAdapterResult(
            attempt=attempt,
            candidate=candidate,
            retry=False,
            raw_response=(
                self._safe_raw_response(raw_response) if sanitize_raw_response else raw_response
            ),
        )

    def consume_replay_chunks(
        self,
        *,
        place_id: str,
        chunks: Sequence[bytes],
    ) -> ProfileAdapterResult:
        reservation = self._ledger.reserve() if self._ledger is not None else None
        if self._coding_plan_ledger is not None:
            self._coding_plan_ledger.reserve()
        self._attempt_number += 1
        started = self._monotonic()
        body = bytearray()
        for chunk in chunks:
            elapsed = self._monotonic() - started
            if elapsed > self._config.attempt_deadline_seconds:
                if reservation is not None:
                    self.ledger.commit_unknown(reservation)
                return self._failure(
                    place_id=place_id,
                    attempt_number=self._attempt_number,
                    error_code="ATTEMPT_DEADLINE_EXCEEDED",
                    outcome="ATTEMPT_DEADLINE_EXCEEDED",
                    reservation=reservation,
                    started=started,
                )
            if len(body) + len(chunk) > MAX_PROVIDER_RESPONSE_BYTES:
                if reservation is not None:
                    self.ledger.commit_unknown(reservation)
                return self._failure(
                    place_id=place_id,
                    attempt_number=self._attempt_number,
                    error_code="RESPONSE_BYTE_LIMIT_EXCEEDED",
                    outcome="RESPONSE_INVALID",
                    reservation=reservation,
                    started=started,
                )
            body.extend(chunk)
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        return self._validate_payload(
            place_id=place_id,
            payload=payload,
            reservation=reservation,
            attempt_number=self._attempt_number,
            started=started,
            raw_response=bytes(body),
            supplied_lineage=None,
            sanitize_raw_response=False,
        )

    def _failure(
        self,
        *,
        place_id: str,
        attempt_number: int,
        error_code: str,
        outcome: str,
        reservation: CostReservation | None,
        started: float,
        retry: bool = False,
        http_status: int | None = None,
        response_sha256: str | None = None,
        raw_response: bytes | None = None,
        sanitize_raw_response: bool = True,
    ) -> ProfileAdapterResult:
        duration_ms = max(0, min(300_000, int((self._monotonic() - started) * 1000)))
        attempt = self._attempt_contract(
            place_id=place_id,
            attempt_number=attempt_number,
            outcome=outcome,
            retry=retry,
            http_status=http_status,
            error_code=error_code,
            returned_model=None,
            finish_reason=None,
            response_sha256=response_sha256,
            usage=None,
            committed=reservation.amount_micro_usd if reservation is not None else 0,
            refund=0,
            started=started,
            duration_ms=duration_ms,
        )
        return ProfileAdapterResult(
            attempt=attempt,
            candidate=None,
            retry=retry,
            raw_response=(
                self._safe_raw_response(raw_response) if sanitize_raw_response else raw_response
            ),
        )

    def _attempt_contract(
        self,
        *,
        place_id: str,
        attempt_number: int,
        outcome: str,
        retry: bool,
        http_status: int | None,
        error_code: str | None,
        returned_model: str | None,
        finish_reason: str | None,
        response_sha256: str | None,
        usage: ProviderTokenUsage | None,
        committed: int,
        refund: int,
        started: float,
        duration_ms: int | None = None,
    ) -> DemoProfileAttempt | CodingPlanProfileAttempt:
        if duration_ms is None:
            duration_ms = max(0, min(300_000, int((self._monotonic() - started) * 1000)))
        if isinstance(self._config, CodingPlanProfileMaterializationConfig):
            coding_payload: dict[str, object] = {
                "schema_version": "itda.coding-plan-profile-attempt.v1",
                "place_id": place_id,
                "attempt_number": attempt_number,
                "outcome": outcome,
                "retry": retry,
                "http_status": http_status,
                "error_code": error_code,
                "returned_model": returned_model,
                "finish_reason": finish_reason,
                "response_sha256": response_sha256,
                "usage": usage.model_dump(mode="json") if usage is not None else None,
                "provider_lane": self._config.provider_lane,
                "endpoint": self._config.endpoint,
                "model": self._config.model,
                "accounting_mode": self._config.accounting_mode,
                "entitlement_evidence_sha256": self._config.entitlement_evidence_sha256,
                "model_weight": self._config.model_weight,
                "subscription_attempt_weight": self._config.model_weight,
                "subscription_cumulative_weight": self.coding_plan_ledger.total_weight,
                "duration_ms": duration_ms,
            }
            return CodingPlanProfileAttempt.model_validate(
                seal_demo_contract(coding_payload, digest_field="attempt_sha256")
            )
        payload: dict[str, object] = {
            "schema_version": "itda.demo-profile-attempt.v1",
            "place_id": place_id,
            "attempt_number": attempt_number,
            "outcome": outcome,
            "retry": retry,
            "http_status": http_status,
            "error_code": error_code,
            "returned_model": returned_model,
            "finish_reason": finish_reason,
            "response_sha256": response_sha256,
            "usage": usage.model_dump(mode="json") if usage is not None else None,
            "reservation_micro_usd": ATTEMPT_RESERVATION_MICRO_USD,
            "committed_micro_usd": committed,
            "refund_micro_usd": refund,
            "remaining_cap_micro_usd": self.ledger.remaining_cap_micro_usd,
            "duration_ms": duration_ms,
            "pricing_snapshot_sha256": PRICING_SNAPSHOT_SHA256,
        }
        return DemoProfileAttempt.model_validate(
            seal_demo_contract(payload, digest_field="attempt_sha256")
        )


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _normalize_response_payload(
    payload: Mapping[str, object],
    *,
    supplied_lineage: Mapping[str, object] | None,
) -> dict[str, object]:
    """Normalize a provider chat envelope or an already-sanitized replay row."""

    if "choices" not in payload:
        normalized = dict(payload)
        if supplied_lineage is not None:
            normalized["lineage"] = dict(supplied_lineage)
        return normalized

    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("provider response requires exactly one choice")
    choice = choices[0]
    if not isinstance(choice, Mapping):
        raise ValueError("provider choice is invalid")
    message = choice.get("message")
    if not isinstance(message, Mapping) or message.get("role") != "assistant":
        raise ValueError("provider assistant message is invalid")
    content_text = message.get("content")
    if not isinstance(content_text, str):
        raise ValueError("provider profile content is invalid")
    content = json.loads(content_text)
    if not isinstance(content, Mapping):
        raise ValueError("provider profile content must be an object")
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        raise ValueError("provider usage is absent")
    details = usage.get("prompt_tokens_details")
    if not isinstance(details, Mapping) or "cached_tokens" not in details:
        raise ValueError("provider cached-token usage is absent")
    if supplied_lineage is None:
        raise ValueError("provider response lacks server-held request lineage")
    return {
        "model": payload.get("model"),
        "finish_reason": choice.get("finish_reason"),
        "usage": {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "cached_tokens": details.get("cached_tokens"),
        },
        "content": dict(content),
        "lineage": dict(supplied_lineage),
    }


__all__ = [
    "AttemptCostLedger",
    "CodingPlanAttemptLedger",
    "ProfileAdapterResult",
    "TwoPassAttemptBudget",
    "ZhipuGlm5vProfileAdapter",
    "classify_retry",
]
