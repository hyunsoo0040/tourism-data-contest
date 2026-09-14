"""Bounded single-flight cache of immutable source batches, with injected time."""

from __future__ import annotations

import hashlib
from base64 import b64decode
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from threading import Lock
from typing import Literal, Self

from pydantic import model_validator

from itda.collectors.base import parse_provider_envelope
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.source_assessment import SourceReceipt, SourceService
from itda.contracts.trip_context import TemporalReason
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import provider_items


class TemporalSourceSnapshot(StrictContract):
    schema_version: Literal["temporal-source-snapshot.v1"] = "temporal-source-snapshot.v1"
    service: SourceService
    operation: str
    cache_key_sha256: Sha256
    retrieved_at: datetime
    expires_at: datetime
    complete: bool
    reason: TemporalReason
    provider_result_code: str | None
    rows: tuple[dict[str, object], ...]
    receipts: tuple[SourceReceipt, ...]
    raw_responses: tuple[dict[str, object], ...]
    snapshot_sha256: Sha256

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        require_utc(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.retrieved_at:
            raise ValueError("source expiry must follow retrieval")
        raw_rows: list[dict[str, object]] = []
        raw_hashes = set()
        for response in self.raw_responses:
            raw_bytes = b64decode(str(response.get("raw_body_base64", "")), validate=True)
            if hashlib.sha256(raw_bytes).hexdigest() != response.get("raw_response_sha256"):
                raise ValueError("temporal raw source hash mismatch")
            parsed, _, _ = parse_provider_envelope(raw_bytes, content_type="application/json")
            if parsed != response.get("payload"):
                raise ValueError("temporal raw bytes and parsed payload disagree")
            raw_hashes.add(response["raw_response_sha256"])
            raw_rows.extend(provider_items(response.get("payload")))
        if tuple(raw_rows) != self.rows:
            raise ValueError("temporal normalized rows differ from collected raw payloads")
        if any(
            receipt.status != "UNAVAILABLE" and receipt.response_sha256 not in raw_hashes
            for receipt in self.receipts
        ):
            raise ValueError("temporal receipt missing raw response")
        if any(
            row.service != self.service or row.operation != self.operation for row in self.receipts
        ):
            raise ValueError("temporal receipt source mismatch")
        if self.snapshot_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"snapshot_sha256"})
        ):
            raise ValueError("temporal source snapshot hash mismatch")
        return self


class TemporalCache:
    def __init__(self, *, clock: Callable[[], datetime], max_entries: int = 128) -> None:
        if not 1 <= max_entries <= 1024:
            raise ValueError("temporal cache size must be bounded")
        self.clock = clock
        self.max_entries = max_entries
        self._entries: OrderedDict[str, TemporalSourceSnapshot] = OrderedDict()
        self._lock = Lock()
        # Fixed lock stripes avoid an unbounded lock per arbitrary requested date.
        self._flights = tuple(Lock() for _ in range(32))

    def get_or_load(
        self, key: str, loader: Callable[[], TemporalSourceSnapshot]
    ) -> TemporalSourceSnapshot:
        with self._flights[int(key[:8], 16) % len(self._flights)]:
            with self._lock:
                found = self._entries.get(key)
                if (
                    found is not None
                    and require_utc(self.clock(), field_name="clock") < found.expires_at
                ):
                    self._entries.move_to_end(key)
                    return found.model_copy(deep=True)
            value = loader()
            if value.cache_key_sha256 != key:
                raise ValueError("loaded source cache identity mismatch")
            with self._lock:
                self._entries[key] = value.model_copy(deep=True)
                self._entries.move_to_end(key)
                while len(self._entries) > self.max_entries:
                    self._entries.popitem(last=False)
            return value
