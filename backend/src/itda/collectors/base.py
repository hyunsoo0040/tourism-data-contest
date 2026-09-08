"""Shared official-API collection boundary with fail-closed live policy."""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
import time
import xml.etree.ElementTree as ET
from base64 import b64encode
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import unquote, unquote_plus

import httpx

from itda.contracts.catalog_collection import (
    classify_provider_result,
    provider_failure_rationale,
)
from itda.contracts.provenance import (
    MAX_PROVIDER_JSON_DEPTH,
    MAX_PROVIDER_JSON_NODES,
    MAX_PROVIDER_RAW_BYTES,
    extract_provider_modifiedtime,
    extract_upstream_rights,
    parse_provider_json_bytes,
    validate_provider_raw_bytes,
)
from itda.domain.canonical import canonical_sha256
from itda.pipeline.offline_guard import require_live_collection_allowed

if TYPE_CHECKING:
    from itda.collectors.diagnostics import DiagnosticOperation, ProviderDiagnostics

QueryParamValue = str | int | float | bool | None

_SECRET_FRAGMENTS = (
    "servicekey",
    "api_key",
    "apikey",
    "token",
    "secret",
    "authorization",
)
_RETRYABLE_STATUSES = frozenset({408, 429})
_JSON_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
_MAX_CREDENTIAL_NORMALIZATION_ROUNDS = 16
_SAFE_RESPONSE_HEADERS = frozenset(
    {"content-type", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"}
)


class CollectionError(RuntimeError):
    """Raised when an official provider cannot be collected within policy."""

    def __init__(
        self,
        message: str,
        *,
        outcome: str = "collection_failed",
        category: str = "collection",
        http_status: int | None = None,
        exception_class: str | None = None,
        provider_result_code: str | None = None,
        provider_result_value: str | None = None,
        retry_disposition: str = "DO_NOT_RETRY",
        normalized_failure_reason: str | None = None,
        raw_body_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.outcome = outcome
        self.category = category
        self.http_status = http_status
        self.exception_class = exception_class
        self.provider_result_code = provider_result_code
        self.provider_result_value = provider_result_value
        self.retry_disposition = retry_disposition
        self.normalized_failure_reason = normalized_failure_reason
        self.raw_body_sha256 = raw_body_sha256


@dataclass(frozen=True, slots=True)
class RequestPolicy:
    """Finite HTTP policy; timeouts and attempts may never be disabled."""

    timeout_seconds: float = 5.0
    max_attempts: int = 3
    initial_backoff_seconds: float = 0.25
    max_backoff_seconds: float = 300.0
    jitter_fraction: float = 0.2

    def __post_init__(self) -> None:
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 300
        ):
            raise ValueError("timeout_seconds must be positive and at most 300")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 5:
            raise ValueError("max_attempts must be between 1 and 5")
        for field_name, value in (
            ("initial_backoff_seconds", self.initial_backoff_seconds),
            ("max_backoff_seconds", self.max_backoff_seconds),
            ("jitter_fraction", self.jitter_fraction),
        ):
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError(f"{field_name} must be finite")
        if self.initial_backoff_seconds < 0:
            raise ValueError("initial_backoff_seconds must not be negative")
        if not 0 < self.max_backoff_seconds <= 300:
            raise ValueError("max_backoff_seconds must be positive and at most 300")
        if self.initial_backoff_seconds > self.max_backoff_seconds:
            raise ValueError("initial_backoff_seconds must not exceed max_backoff_seconds")
        if not 0 <= self.jitter_fraction <= 1:
            raise ValueError("jitter_fraction must be between zero and one")


@dataclass(frozen=True, slots=True)
class CollectedResponse:
    """Sanitized provider response plus exact retrieval provenance."""

    provider: str
    endpoint: str
    request_scope: dict[str, str]
    retrieved_at: datetime
    http_status: int
    raw_response_sha256: str
    raw_body_base64: str
    modifiedtime: str | None
    rights: tuple[dict[str, str], ...]
    payload: object
    provider_result_code: str | None = None
    provider_result_value: str | None = None
    normalized_outcome: str = "SUCCESS"
    retry_disposition: str = "DO_NOT_RETRY"
    official_dataset_id: str | None = None
    dataset_rights_identity: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "http_status": self.http_status,
            "modifiedtime": self.modifiedtime,
            "payload": self.payload,
            "provider": self.provider,
            "provider_result_code": self.provider_result_code,
            "provider_result_value": self.provider_result_value,
            "raw_response_sha256": self.raw_response_sha256,
            "raw_body_base64": self.raw_body_base64,
            "request_scope": self.request_scope,
            "retrieved_at": self.retrieved_at.isoformat().replace("+00:00", "Z"),
            "retry_disposition": self.retry_disposition,
            "rights": list(self.rights),
            "normalized_outcome": self.normalized_outcome,
            "official_dataset_id": self.official_dataset_id,
            "dataset_rights_identity": self.dataset_rights_identity,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_dict(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _validate_utc(value: datetime) -> datetime:
    if value.utcoffset() != UTC.utcoffset(value):
        raise CollectionError("collector clock must return a UTC datetime")
    return value


def _contains_secret_name(name: str) -> bool:
    folded = name.casefold()
    return any(fragment in folded for fragment in _SECRET_FRAGMENTS)


def _validate_query_params(params: Mapping[str, QueryParamValue]) -> None:
    for key, value in params.items():
        if not isinstance(key, str) or _contains_secret_name(key):
            raise CollectionError("caller parameters must not contain credentials")
        if type(value) not in (str, int, float, bool, type(None)):
            raise CollectionError("query parameter values must be scalar")
        if type(value) is float and not math.isfinite(value):
            raise CollectionError("query parameter values must be finite")


def _transmitted_scope(request: httpx.Request) -> dict[str, str]:
    return {
        key: value
        for key, value in sorted(request.url.params.multi_items())
        if not _contains_secret_name(key)
    }


def _decode_json_unicode_escapes(value: str) -> str:
    decoded = _JSON_UNICODE_ESCAPE.sub(
        lambda match: chr(int(match.group(1), 16)),
        value,
    )
    if decoded == value:
        return value
    try:
        return decoded.encode("utf-16", errors="surrogatepass").decode("utf-16")
    except UnicodeError:
        return decoded


def credential_material_present(raw_body: bytes, secret: str) -> bool:
    """Reject credentials after bounded, case-independent transport decoding."""

    text = raw_body.decode("utf-8", errors="replace")
    frontier = {text}
    seen: set[str] = set()
    for _round in range(_MAX_CREDENTIAL_NORMALIZATION_ROUNDS):
        next_frontier: set[str] = set()
        for value in frontier:
            if secret in value:
                return True
            normalized_values = {_decode_json_unicode_escapes(value)}
            normalized_values.add(value.replace("\\\\u", "\\u"))
            for decoder in (unquote, unquote_plus):
                try:
                    normalized_values.add(decoder(value, errors="strict"))
                except UnicodeDecodeError:
                    continue
            next_frontier.update(
                normalized
                for normalized in normalized_values
                if normalized != value and normalized not in seen
            )
        seen.update(frontier)
        if not next_frontier:
            return False
        frontier = next_frontier
    # Excessive nesting is credential-obfuscation-shaped input; reject fail-closed.
    return bool(frontier)


def _provider_result_fields(payload: object) -> tuple[object | None, object | None]:
    stack = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            if "resultCode" in current or "resultMsg" in current:
                return current.get("resultCode"), current.get("resultMsg")
            stack.extend(reversed(tuple(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))
    return None, None


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1]


def _parse_provider_xml_bytes(raw_body: bytes) -> tuple[object, object | None, object | None]:
    if b"<!DOCTYPE" in raw_body.upper() or b"<!ENTITY" in raw_body.upper():
        raise ValueError("provider XML declarations are not allowed")
    try:
        root = ET.fromstring(raw_body)
    except (ET.ParseError, RecursionError) as exc:
        raise ValueError("provider raw body must be valid XML") from exc

    stack: list[tuple[ET.Element, int]] = [(root, 0)]
    node_count = 0
    while stack:
        element, depth = stack.pop()
        node_count += 1
        if node_count > MAX_PROVIDER_JSON_NODES:
            raise ValueError("provider XML exceeds total node limit")
        if depth > MAX_PROVIDER_JSON_DEPTH:
            raise ValueError("provider XML exceeds maximum depth")
        children = list(element)
        stack.extend((child, depth + 1) for child in reversed(children))

    def project(element: ET.Element, depth: int = 0) -> object:
        if depth > MAX_PROVIDER_JSON_DEPTH:
            raise ValueError("provider XML exceeds maximum depth")
        children = list(element)
        if not children:
            return (element.text or "").strip()
        projected: dict[str, object] = {}
        for child in children:
            key = _xml_local_name(child.tag)
            value = project(child, depth + 1)
            existing = projected.get(key)
            if existing is None:
                projected[key] = value
            elif isinstance(existing, list):
                existing.append(value)
            else:
                projected[key] = [existing, value]
        return projected

    payload = {_xml_local_name(root.tag): project(root)}
    values = {
        _xml_local_name(element.tag): (element.text or "").strip()
        for element in root.iter()
        if not list(element)
    }
    code = values.get("returnReasonCode") or values.get("resultCode")
    message = (
        values.get("returnAuthMsg")
        or values.get("errMsg")
        or values.get("resultMsg")
    )
    return payload, code, message


def parse_provider_envelope(
    raw_body: bytes,
    *,
    content_type: str,
) -> tuple[object, str | None, str | None]:
    stripped = raw_body.lstrip()
    if "xml" in content_type.casefold() or stripped.startswith(b"<"):
        payload, raw_code, raw_value = _parse_provider_xml_bytes(raw_body)
    else:
        payload = parse_provider_json_bytes(raw_body)
        raw_code, raw_value = _provider_result_fields(payload)
    code = None if raw_code is None else str(raw_code)[:80]
    value = None if raw_value is None else str(raw_value)[:200]
    return payload, code, value


def _safe_response_headers(headers: httpx.Headers) -> dict[str, str]:
    safe: dict[str, str] = {}
    for name in _SAFE_RESPONSE_HEADERS:
        value = headers.get(name)
        if value is None:
            continue
        rendered = " ".join(value.split())
        if (
            rendered
            and len(rendered) <= 500
            and all(ord(character) >= 32 and ord(character) != 127 for character in rendered)
        ):
            safe[name] = rendered
    return dict(sorted(safe.items()))


def _is_retryable_http_status(status: int) -> bool:
    return status in _RETRYABLE_STATUSES or 500 <= status <= 599


def _retry_after_seconds(
    value: str | None,
    *,
    now: datetime,
    maximum: float,
) -> float | None:
    if value is None:
        return None
    rendered = value.strip()
    try:
        seconds = float(rendered)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(rendered)
        except (TypeError, ValueError, OverflowError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        seconds = (retry_at.astimezone(UTC) - now).total_seconds()
    if not math.isfinite(seconds):
        return None
    return min(max(0.0, seconds), maximum)


class OfficialApiClient:
    """Base client that admits only fixed HTTPS hosts and allowlisted operations."""

    provider: ClassVar[str]
    service_name: ClassVar[str]
    base_url: ClassVar[str]
    allowed_operations: ClassVar[frozenset[str]]
    common_parameters: ClassVar[Mapping[str, str]]
    official_dataset_id: ClassVar[str]
    dataset_rights_identity: ClassVar[str | None] = None
    provenance_fields: ClassVar[tuple[str, ...]] = ()
    forbidden_parameter_names: ClassVar[frozenset[str]] = frozenset()

    def __init__(
        self,
        *,
        service_key: str,
        http_client: httpx.Client | None = None,
        policy: RequestPolicy | None = None,
        clock: Callable[[], datetime] = _utc_now,
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if not service_key:
            raise ValueError("service_key must not be empty")
        self._service_key = service_key
        self._policy = policy or RequestPolicy()
        self._clock = clock
        self._sleeper = sleeper
        self._jitter = jitter
        self._owned_client = http_client is None
        self._http_client = http_client or httpx.Client(
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        if self._owned_client:
            self._http_client.close()

    def __enter__(self) -> OfficialApiClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def request(
        self,
        operation: str,
        params: Mapping[str, QueryParamValue],
        *,
        explicit_opt_in: bool,
        diagnostics: ProviderDiagnostics | None = None,
        diagnostic_operation: DiagnosticOperation | None = None,
    ) -> CollectedResponse:
        require_live_collection_allowed(explicit_opt_in=explicit_opt_in)
        if operation not in self.allowed_operations:
            raise CollectionError(f"operation is not allowlisted: {operation}")
        obsolete_parameters = set(params).intersection(self.forbidden_parameter_names)
        if obsolete_parameters:
            raise CollectionError(
                "caller supplied obsolete provider parameter: "
                + sorted(obsolete_parameters)[0]
            )
        reserved_parameters = set(params).intersection(self.common_parameters)
        if reserved_parameters:
            raise CollectionError(
                "caller supplied reserved parameter: " + sorted(reserved_parameters)[0]
            )

        _validate_query_params(params)
        actual_params: dict[str, QueryParamValue] = {
            **self.common_parameters,
            **params,
            "serviceKey": self._service_key,
        }
        secret_free_query = dict(
            sorted(
                httpx.QueryParams({**self.common_parameters, **params}).multi_items()
            )
        )
        url = f"{self.base_url}/{operation}"
        if (diagnostics is None) != (diagnostic_operation is None):
            raise CollectionError("diagnostics context must be complete")

        request_sha256 = canonical_sha256(
            {
                "provider": self.provider,
                "service": self.service_name,
                "operation": operation,
                "request_scope": secret_free_query,
            }
        )

        def wait_before_retry(
            attempt: int,
            *,
            retry_after: str | None = None,
        ) -> None:
            retry_after_delay = _retry_after_seconds(
                retry_after,
                now=_validate_utc(self._clock()),
                maximum=self._policy.max_backoff_seconds,
            )
            if retry_after_delay is not None:
                delay = retry_after_delay
            else:
                base_delay = min(
                    self._policy.initial_backoff_seconds * (2 ** (attempt - 1)),
                    self._policy.max_backoff_seconds,
                )
                jitter_sample = self._jitter()
                if (
                    type(jitter_sample) not in (int, float)
                    or not math.isfinite(jitter_sample)
                    or not 0 <= jitter_sample <= 1
                ):
                    raise CollectionError("retry jitter source returned an invalid value")
                multiplier = 1 + ((2 * jitter_sample - 1) * self._policy.jitter_fraction)
                delay = min(
                    max(0.0, base_delay * multiplier),
                    self._policy.max_backoff_seconds,
                )
            if delay > 0:
                self._sleeper(delay)

        for attempt in range(1, self._policy.max_attempts + 1):
            attempt_started_ns = time.monotonic_ns()
            if diagnostics is not None and diagnostic_operation is not None:
                diagnostics.request_attempt_started(
                    diagnostic_operation,
                    attempt=attempt,
                    max_attempts=self._policy.max_attempts,
                    timeout_seconds=self._policy.timeout_seconds,
                    request_sha256=request_sha256,
                )
            try:
                response = self._http_client.get(
                    url,
                    params=actual_params,
                    timeout=self._policy.timeout_seconds,
                    follow_redirects=False,
                )
            except httpx.RequestError as exc:
                terminal_failure = attempt == self._policy.max_attempts
                elapsed_ms = max(0, (time.monotonic_ns() - attempt_started_ns) // 1_000_000)
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_attempt(
                        diagnostic_operation,
                        attempt=attempt,
                        max_attempts=self._policy.max_attempts,
                        timeout_seconds=self._policy.timeout_seconds,
                        outcome="transport_error",
                        category="network",
                        retryable=True,
                        terminal_failure=terminal_failure,
                        exception_class=type(exc).__name__,
                        normalized_outcome="RETRYABLE_FOR_RESUME",
                        retry_disposition="RETRY",
                        elapsed_ms=elapsed_ms,
                        request_sha256=request_sha256,
                    )
                if terminal_failure:
                    if diagnostics is not None and diagnostic_operation is not None:
                        diagnostics.request_failed(
                            diagnostic_operation,
                            outcome="transport_error",
                            category="network",
                            attempt=attempt,
                            exception_class=type(exc).__name__,
                            normalized_outcome="RETRYABLE_FOR_RESUME",
                            retry_disposition="RETRYABLE_FOR_RESUME",
                        )
                    raise CollectionError(
                        f"request failed after {self._policy.max_attempts} attempts",
                        outcome="retryable_for_resume",
                        category="network",
                        exception_class=type(exc).__name__,
                        retry_disposition="RETRYABLE_FOR_RESUME",
                        normalized_failure_reason="bounded transport attempts exhausted",
                    ) from exc
                wait_before_retry(attempt)
                continue

            raw_body = response.content
            safe_headers = _safe_response_headers(response.headers)
            raw_body_sha256 = hashlib.sha256(raw_body).hexdigest()
            try:
                validate_provider_raw_bytes(raw_body)
            except ValueError as exc:
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_failed(
                        diagnostic_operation,
                        outcome="collection_failed",
                        category="provider_response",
                        attempt=attempt,
                        http_status=response.status_code,
                        normalized_outcome="TERMINAL_PROVIDER_RESPONSE",
                        retry_disposition="DO_NOT_RETRY",
                    )
                raise CollectionError(
                    f"provider response exceeded the {MAX_PROVIDER_RAW_BYTES}-byte limit",
                    category="provider_response",
                    http_status=response.status_code,
                    raw_body_sha256=raw_body_sha256,
                ) from exc
            if credential_material_present(raw_body, self._service_key):
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_failed(
                        diagnostic_operation,
                        outcome="collection_failed",
                        category="provider_response",
                        attempt=attempt,
                        http_status=response.status_code,
                        normalized_outcome="REDACTED_CREDENTIAL",
                        retry_disposition="DO_NOT_RETRY",
                    )
                raise CollectionError(
                    "provider response contained sensitive credential material",
                    category="provider_response",
                    http_status=response.status_code,
                    raw_body_sha256=raw_body_sha256,
                )

            raw_body_file: str | None = None
            if diagnostics is not None and diagnostic_operation is not None:
                raw_body_file = diagnostics.retain_attempt_body(
                    diagnostic_operation,
                    attempt=attempt,
                    raw_body=raw_body,
                    raw_body_sha256=raw_body_sha256,
                )

            payload: object | None = None
            provider_code: str | None = None
            provider_value: str | None = None
            parse_error: ValueError | None = None
            try:
                payload, provider_code, provider_value = parse_provider_envelope(
                    raw_body,
                    content_type=response.headers.get("content-type", ""),
                )
            except ValueError as exc:
                parse_error = exc

            elapsed_ms = max(0, (time.monotonic_ns() - attempt_started_ns) // 1_000_000)
            retryable_http = _is_retryable_http_status(response.status_code)
            successful_http = 200 <= response.status_code < 300
            if not successful_http:
                normalized_outcome = (
                    "RETRYABLE_FOR_RESUME" if retryable_http else "TERMINAL_HTTP_ERROR"
                )
                terminal_failure = not retryable_http or attempt == self._policy.max_attempts
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_attempt(
                        diagnostic_operation,
                        attempt=attempt,
                        max_attempts=self._policy.max_attempts,
                        timeout_seconds=self._policy.timeout_seconds,
                        outcome="response",
                        category="http",
                        retryable=retryable_http,
                        terminal_failure=terminal_failure,
                        http_status=response.status_code,
                        provider_result_code=provider_code,
                        provider_result_value=provider_value,
                        normalized_outcome=normalized_outcome,
                        retry_disposition="RETRY" if retryable_http else "DO_NOT_RETRY",
                        raw_body_sha256=raw_body_sha256,
                        raw_body_retention="IMMUTABLE_ATTEMPT_SNAPSHOT",
                        raw_body_file=raw_body_file,
                        safe_headers=safe_headers,
                        elapsed_ms=elapsed_ms,
                        request_sha256=request_sha256,
                    )
                if retryable_http and attempt < self._policy.max_attempts:
                    wait_before_retry(attempt, retry_after=response.headers.get("retry-after"))
                    continue
                outcome = "retryable_for_resume" if retryable_http else "http_error"
                retry_disposition = (
                    "RETRYABLE_FOR_RESUME" if retryable_http else "DO_NOT_RETRY"
                )
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_failed(
                        diagnostic_operation,
                        outcome=outcome,
                        category="http",
                        attempt=attempt,
                        http_status=response.status_code,
                        normalized_outcome=normalized_outcome,
                        retry_disposition=retry_disposition,
                        provider_result_code=provider_code,
                        provider_result_value=provider_value,
                    )
                raise CollectionError(
                    (
                        f"provider returned {response.status_code} after "
                        f"{self._policy.max_attempts} attempts"
                        if retryable_http
                        else f"provider returned non-success status {response.status_code}"
                    ),
                    outcome=outcome,
                    category="http",
                    http_status=response.status_code,
                    provider_result_code=provider_code,
                    provider_result_value=provider_value,
                    retry_disposition=retry_disposition,
                    normalized_failure_reason=(
                        "bounded HTTP attempts exhausted"
                        if retryable_http
                        else "HTTP status requires operator review"
                    ),
                    raw_body_sha256=raw_body_sha256,
                )

            if parse_error is not None or payload is None:
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_attempt(
                        diagnostic_operation,
                        attempt=attempt,
                        max_attempts=self._policy.max_attempts,
                        timeout_seconds=self._policy.timeout_seconds,
                        outcome="collection_failed",
                        category="provider_response",
                        retryable=False,
                        terminal_failure=True,
                        http_status=response.status_code,
                        normalized_outcome="TERMINAL_PROVIDER_RESPONSE",
                        retry_disposition="DO_NOT_RETRY",
                        raw_body_sha256=raw_body_sha256,
                        raw_body_retention="IMMUTABLE_ATTEMPT_SNAPSHOT",
                        raw_body_file=raw_body_file,
                        safe_headers=safe_headers,
                        elapsed_ms=elapsed_ms,
                        request_sha256=request_sha256,
                    )
                    diagnostics.request_failed(
                        diagnostic_operation,
                        outcome="collection_failed",
                        category="provider_response",
                        attempt=attempt,
                        http_status=response.status_code,
                        normalized_outcome="TERMINAL_PROVIDER_RESPONSE",
                        retry_disposition="DO_NOT_RETRY",
                    )
                raise CollectionError(
                    "provider response was not valid container JSON or a bounded XML envelope",
                    category="provider_response",
                    http_status=response.status_code,
                    raw_body_sha256=raw_body_sha256,
                ) from parse_error

            provider_outcome = (
                "SUCCESS"
                if provider_code is None
                else classify_provider_result(provider_code)
            )
            retryable_provider = provider_outcome == "RETRYABLE_FOR_RESUME"
            terminal_provider = provider_outcome == "TERMINAL_OPERATOR_ACTION"
            terminal_failure = terminal_provider or (
                retryable_provider and attempt == self._policy.max_attempts
            )
            if diagnostics is not None and diagnostic_operation is not None:
                diagnostics.request_attempt(
                    diagnostic_operation,
                    attempt=attempt,
                    max_attempts=self._policy.max_attempts,
                    timeout_seconds=self._policy.timeout_seconds,
                    outcome="response",
                    category="provider_response",
                    retryable=retryable_provider,
                    terminal_failure=terminal_failure,
                    http_status=response.status_code,
                    provider_result_code=provider_code,
                    provider_result_value=provider_value,
                    normalized_outcome=provider_outcome,
                    retry_disposition="RETRY" if retryable_provider else "DO_NOT_RETRY",
                    raw_body_sha256=raw_body_sha256,
                    raw_body_retention="IMMUTABLE_ATTEMPT_SNAPSHOT",
                    raw_body_file=raw_body_file,
                    safe_headers=safe_headers,
                    elapsed_ms=elapsed_ms,
                    request_sha256=request_sha256,
                )

            if retryable_provider:
                if attempt < self._policy.max_attempts:
                    wait_before_retry(attempt, retry_after=response.headers.get("retry-after"))
                    continue
                rationale = provider_failure_rationale(provider_code)
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_failed(
                        diagnostic_operation,
                        outcome="retryable_for_resume",
                        category="provider_response",
                        attempt=attempt,
                        http_status=response.status_code,
                        normalized_outcome=provider_outcome,
                        retry_disposition="RETRYABLE_FOR_RESUME",
                        provider_result_code=provider_code,
                        provider_result_value=provider_value,
                    )
                raise CollectionError(
                    f"provider result remained retryable after {attempt} attempts",
                    outcome="retryable_for_resume",
                    category="provider_response",
                    http_status=response.status_code,
                    provider_result_code=provider_code,
                    provider_result_value=provider_value,
                    retry_disposition="RETRYABLE_FOR_RESUME",
                    normalized_failure_reason=rationale,
                    raw_body_sha256=raw_body_sha256,
                )

            if terminal_provider:
                rationale = provider_failure_rationale(provider_code)
                if diagnostics is not None and diagnostic_operation is not None:
                    diagnostics.request_failed(
                        diagnostic_operation,
                        outcome="terminal_operator_action",
                        category="provider_response",
                        attempt=attempt,
                        http_status=response.status_code,
                        normalized_outcome=provider_outcome,
                        retry_disposition="DO_NOT_RETRY",
                        provider_result_code=provider_code,
                        provider_result_value=provider_value,
                    )
                raise CollectionError(
                    "provider result requires operator intervention",
                    outcome="terminal_operator_action",
                    category="provider_response",
                    http_status=response.status_code,
                    provider_result_code=provider_code,
                    provider_result_value=provider_value,
                    retry_disposition="DO_NOT_RETRY",
                    normalized_failure_reason=rationale,
                    raw_body_sha256=raw_body_sha256,
                )

            if diagnostics is not None and diagnostic_operation is not None:
                from itda.collectors.diagnostics import (
                    sanitize_upstream_result_code,
                    sanitize_upstream_result_message,
                )

                diagnostics.request_succeeded(
                    diagnostic_operation,
                    attempt=attempt,
                    http_status=response.status_code,
                    upstream_result_code=sanitize_upstream_result_code(provider_code),
                    upstream_result_message=sanitize_upstream_result_message(provider_value),
                    normalized_outcome=provider_outcome,
                    raw_body_sha256=raw_body_sha256,
                    raw_body_retention="IMMUTABLE_ATTEMPT_SNAPSHOT",
                    raw_body_file=raw_body_file,
                    safe_headers=safe_headers,
                    elapsed_ms=elapsed_ms,
                    request_sha256=request_sha256,
                )

            return CollectedResponse(
                provider=self.provider,
                endpoint=f"{self.service_name}/{operation}",
                request_scope=_transmitted_scope(response.request),
                retrieved_at=_validate_utc(self._clock()),
                http_status=response.status_code,
                raw_response_sha256=raw_body_sha256,
                raw_body_base64=b64encode(raw_body).decode("ascii"),
                modifiedtime=extract_provider_modifiedtime(payload),
                rights=extract_upstream_rights(payload),
                payload=payload,
                provider_result_code=provider_code,
                provider_result_value=provider_value,
                normalized_outcome=provider_outcome,
                retry_disposition="DO_NOT_RETRY",
                official_dataset_id=self.official_dataset_id,
                dataset_rights_identity=self.dataset_rights_identity,
            )

        raise CollectionError(
            "bounded request loop ended without a terminal state",
            outcome="retryable_for_resume",
            retry_disposition="RETRYABLE_FOR_RESUME",
        )
