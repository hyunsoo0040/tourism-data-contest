"""Shared offline model quota control, with explicitly enabled delayed retries."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import httpx


class ModelBatchPaused(RuntimeError):
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state
        super().__init__(str(state.get("reason", "MODEL_BATCH_PAUSED")))


class ModelBatchControl:
    """Shared by the text and mood providers of a single explicitly started batch.

    Default mode stops at a quota response. Explicit retry mode shares an
    exponential cooldown and spaces subsequent starts across both providers.
    This does not replace the host-wide 40-session semaphore.
    """

    def __init__(
        self,
        *,
        retry_limits: bool = False,
        retry_connections: bool = False,
        initial_delay: float = 60,
        maximum_delay: float = 900,
        recovery_spacing: float = 2,
        on_retry: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if initial_delay <= 0 or maximum_delay < initial_delay or recovery_spacing <= 0:
            raise ValueError("invalid model retry timing")
        self.retry_limits = retry_limits
        self.retry_connections = retry_connections
        self._connection_failures = 0
        self._response_failures = 0
        self._initial_delay = initial_delay
        self._maximum_delay = maximum_delay
        self._recovery_spacing = recovery_spacing
        self._on_retry = on_retry
        self._retry_until = 0.0
        self._next_start = 0.0
        self._backoff = 0.0
        self._limited_responses = 0
        self._lock = threading.Lock()
        self._paused: dict[str, Any] | None = None
        self._started = 0

    def check(self) -> None:
        with self._lock:
            if self._paused is not None:
                raise ModelBatchPaused(dict(self._paused))

    def _begin(self) -> None:
        while True:
            with self._lock:
                if self._paused is not None:
                    raise ModelBatchPaused(dict(self._paused))
                now = time.monotonic()
                remaining = max(self._retry_until, self._next_start) - now
                if remaining <= 0:
                    self._started += 1
                    if (
                        self._limited_responses
                        or self._connection_failures
                        or self._response_failures
                    ):
                        self._next_start = now + self._recovery_spacing
                    return
            # Short waits keep Ctrl-C responsive during a long provider cooldown.
            time.sleep(min(remaining, 1))

    def retry(self, response: httpx.Response) -> None:
        if not self.retry_limits:
            self._pause()
        retry_after = 0.0
        value = response.headers.get("retry-after", "")
        try:
            retry_after = max(0, float(value))
        except ValueError:
            try:
                deadline = parsedate_to_datetime(value)
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=UTC)
                retry_after = max(0, (deadline - datetime.now(UTC)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
        if not math.isfinite(retry_after):
            retry_after = 0.0
        self._schedule_retry("MODEL_REQUEST_LIMIT", 429, retry_after)

    def retry_connection(self, error: httpx.TransportError, attempt: int) -> None:
        if not self.retry_connections:
            raise error
        if attempt >= 5:
            self._pause("MODEL_CONNECTION_UNAVAILABLE", None, type(error).__name__)
        with self._lock:
            self._connection_failures += 1
        self._schedule_retry("MODEL_CONNECTION_ERROR", None, 0)

    def retry_response(self, error: httpx.TransportError, attempt: int) -> None:
        """A lost/timeout response is not missing evidence; bound retries then pause."""
        if not self.retry_connections:
            raise error
        if attempt >= 3:
            self._pause("MODEL_RESPONSE_UNAVAILABLE", None, type(error).__name__)
        with self._lock:
            self._response_failures += 1
        self._schedule_retry("MODEL_RESPONSE_ERROR", None, 0)

    def _schedule_retry(self, reason: str, status: int | None, retry_after: float) -> None:
        with self._lock:
            now = time.monotonic()
            # Failures from the same in-flight cohort share one backoff step.
            if now >= self._retry_until:
                self._backoff = min(
                    self._maximum_delay,
                    max(self._initial_delay, self._backoff * 2),
                )
                self._retry_until = now + self._backoff
            self._retry_until = max(self._retry_until, now + retry_after)
            if status == 429:
                self._limited_responses += 1
            if self._on_retry is not None:
                self._on_retry(
                    {
                        "status": "WAITING_RETRY",
                        "reason": reason,
                        "model": "glm-5.3-flash",
                        "http_status": status,
                        "observed_at": datetime.now(UTC).isoformat(),
                        "retry_not_before": (
                            datetime.now(UTC) + timedelta(seconds=self._retry_until - now)
                        ).isoformat(),
                        "limited_responses": self._limited_responses,
                        "connection_failures": self._connection_failures,
                        "response_failures": self._response_failures,
                        "requests_started": self._started,
                        "automatic_retry": True,
                        "recovery_spacing_seconds": self._recovery_spacing,
                    }
                )

    def _pause(
        self,
        reason: str = "MODEL_REQUEST_LIMIT",
        status: int | None = 429,
        error_type: str | None = None,
    ) -> None:
        with self._lock:
            if self._paused is None:
                self._paused = {
                    "status": "PAUSED",
                    "reason": reason,
                    "model": "glm-5.3-flash",
                    "http_status": status,
                    "error_type": error_type,
                    "observed_at": datetime.now(UTC).isoformat(),
                    "requests_started_before_pause": self._started,
                    "automatic_retry": False,
                }
            raise ModelBatchPaused(dict(self._paused))

    def transport(self, underlying: httpx.BaseTransport | None) -> httpx.BaseTransport:
        return _ControlledTransport(self, underlying or httpx.HTTPTransport(retries=0))


class _ControlledTransport(httpx.BaseTransport):
    def __init__(self, control: ModelBatchControl, underlying: httpx.BaseTransport) -> None:
        self.control = control
        self.underlying = underlying

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.read()  # Preserve the JSON/image body across transport retries.
        connection_attempts = 0
        while True:
            self.control._begin()
            try:
                response = self.underlying.handle_request(request)
            except (httpx.ConnectError, httpx.ConnectTimeout) as error:
                connection_attempts += 1
                self.control.retry_connection(error, connection_attempts)
                continue
            if response.status_code != 429:
                return response
            try:
                self.control.retry(response)
            finally:
                response.close()

    def close(self) -> None:
        self.underlying.close()
