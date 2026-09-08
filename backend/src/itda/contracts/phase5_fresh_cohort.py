"""Fail-closed contracts for the fresh Phase 5 NVIDIA materialization lane.

This module is intentionally independent from the historical Z.ai and NVIDIA
resume ledgers.  The public request contains a logical authority identifier,
while the protected state descriptor is the only object that may resolve the
approval, claim, journal, and raw-evidence destinations.
"""

from __future__ import annotations

import hmac
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from pydantic import model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.domain.canonical import canonical_sha256

FRESH_AUTHORITY_ID = "phase5-nvidia-minimax-m3-fresh-d24-20260816"
FRESH_PROVIDER_LANE = "NVIDIA_NIM_API"
FRESH_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
FRESH_MODEL = "minimaxai/minimax-m3"
FRESH_SECRET_ENV = "NVIDIA_KEY"
FRESH_EXPOSURE_CAP_MICRO_USD = 15_000_000
FRESH_CUMULATIVE_EXPOSURE_CAP_MICRO_USD = FRESH_EXPOSURE_CAP_MICRO_USD
FRESH_RESERVATION_MICRO_USD = 500_000
FRESH_MAX_HTTP_ATTEMPTS = 30
FRESH_ATTEMPT_DEADLINE_SECONDS = 300
FRESH_CONCURRENCY = 1
FRESH_PRICE_STATUS = "UNKNOWN"
FRESH_MIN_ELIGIBLE_PROFILES = 5
FRESH_CONFIDENCE_THRESHOLD = 70
FRESH_SCHEMA_VERSION = "itda.phase5-fresh-cohort.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY_RE = re.compile(r"^phase5-nvidia-minimax-m3-fresh-d24-20260816$")
_PATH_KEY_RE = re.compile(
    r"(?:^|_)(?:path|file|dir|root|secret|raw|journal|approval|claim)(?:_|$)",
    re.I,
)


def _require_sha256(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def validate_fresh_authority_id(value: str) -> str:
    if not isinstance(value, str) or _AUTHORITY_RE.fullmatch(value) is None:
        raise ValueError("fresh NVIDIA logical authority ID is invalid")
    return value


def _reject_path_material(value: object, *, key: str = "") -> None:
    """Reject path-like public material, including nested string values."""

    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                raise ValueError("public authority keys must be strings")
            if _PATH_KEY_RE.search(child_key):
                raise ValueError("public fresh authority request contains protected path material")
            _reject_path_material(child_value, key=child_key)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_path_material(child, key=key)
    elif isinstance(value, str) and key and (
        value.startswith(("/", "~/", "file://")) or "\\" in value
    ):
        raise ValueError("public fresh authority request contains a path-like value")


class FreshPublicRequest(StrictContract):
    """Allowlisted, secret-free request facts shown to an approver."""

    schema_version: Literal["itda.phase5-fresh-provider-request.v1"] = (
        "itda.phase5-fresh-provider-request.v1"
    )
    authority_id: str
    provider_lane: Literal["NVIDIA_NIM_API"] = "NVIDIA_NIM_API"
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    model: Literal["minimaxai/minimax-m3"] = "minimaxai/minimax-m3"
    source_inventory_sha256: Sha256
    membership_sha256: Sha256
    prompt_sha256: Sha256
    profile_schema_sha256: Sha256
    config_sha256: Sha256
    request_manifest_sha256: Sha256
    checkout_manifest_sha256: Sha256
    cumulative_exposure_cap_micro_usd: Literal[15_000_000] = 15_000_000
    reservation_micro_usd: Literal[500_000] = 500_000
    max_new_http_attempts: Literal[30] = 30
    attempt_deadline_seconds: Literal[300] = 300
    concurrency: Literal[1] = 1
    price_status: Literal["UNKNOWN"] = "UNKNOWN"
    invocation_policy: Literal["SINGLE_INVOCATION"] = "SINGLE_INVOCATION"
    confidence_threshold: Literal[70] = 70
    minimum_eligible_profiles: Literal[5] = 5
    blind_access: Literal[False] = False
    network_attempted: Literal[False] = False
    public_request_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_protected_inputs(cls, value: object) -> object:
        _reject_path_material(value)
        return value

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        validate_fresh_authority_id(self.authority_id)
        _require_sha256(self.public_request_sha256, field_name="public_request_sha256")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"public_request_sha256"})
        )
        if not hmac.compare_digest(expected, self.public_request_sha256):
            raise ValueError("fresh public request digest drifted")
        return self


class FreshApprovalBinding(StrictContract):
    """One-use approval payload bound to the exact public request and state."""

    schema_version: Literal["itda.phase5-fresh-approval-binding.v1"] = (
        "itda.phase5-fresh-approval-binding.v1"
    )
    authority_id: str
    public_request_sha256: Sha256
    checkout_manifest_sha256: Sha256
    request_artifact_sha256: Sha256
    approval_payload_sha256: Sha256
    endpoint: Literal["https://integrate.api.nvidia.com/v1/chat/completions"] = (
        "https://integrate.api.nvidia.com/v1/chat/completions"
    )
    model: Literal["minimaxai/minimax-m3"] = "minimaxai/minimax-m3"
    provider_lane: Literal["NVIDIA_NIM_API"] = "NVIDIA_NIM_API"
    cumulative_exposure_cap_micro_usd: Literal[15_000_000] = 15_000_000
    reservation_micro_usd: Literal[500_000] = 500_000
    max_new_http_attempts: Literal[30] = 30
    attempt_deadline_seconds: Literal[300] = 300
    concurrency: Literal[1] = 1
    price_status: Literal["UNKNOWN"] = "UNKNOWN"
    invocation_policy: Literal["SINGLE_INVOCATION"] = "SINGLE_INVOCATION"
    single_live_invocation: Literal[True] = True
    confidence_threshold: Literal[70] = 70
    minimum_eligible_profiles: Literal[5] = 5
    active_release_state: Literal[
        "NO_ACTIVE_SCORED_RELEASE", "INVALIDATED_LEGACY_PREDECESSOR"
    ]
    active_release_state_sha256: Sha256
    trusted_decision_sha256: Sha256
    protected_state_sha256: Sha256
    approval_sha256: Sha256

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        validate_fresh_authority_id(self.authority_id)
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"approval_sha256"}))
        if not hmac.compare_digest(expected, self.approval_sha256):
            raise ValueError("fresh approval binding digest drifted")
        return self


class FreshApprovalDecisionRecord(StrictContract):
    """Canonical local record of the exact public approval payload."""

    schema_version: Literal["itda.phase5-fresh-approval-decision.v1"] = (
        "itda.phase5-fresh-approval-decision.v1"
    )
    authority_id: str
    decision: Literal["APPROVED"] = "APPROVED"
    public_request_sha256: Sha256
    checkout_manifest_sha256: Sha256
    request_artifact_sha256: Sha256
    approval_payload_sha256: Sha256
    decision_sha256: Sha256

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        validate_fresh_authority_id(self.authority_id)
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"decision_sha256"})
        )
        if not hmac.compare_digest(expected, self.decision_sha256):
            raise ValueError("fresh approval decision digest drifted")
        return self


@dataclass(frozen=True, slots=True)
class FreshExposureReservation:
    """A one-use reservation returned before any provider capability exists."""

    reservation_id: int
    attempt_number: int
    amount_micro_usd: int = FRESH_RESERVATION_MICRO_USD
    predecessor_sha256: str = "0" * 64
    reservation_sha256: str = ""


@dataclass(frozen=True, slots=True)
class FreshLedgerEntry:
    sequence: int
    operation: Literal["RESERVE", "RELEASE_BEFORE_SOCKET", "COMMIT", "RECOVER_UNRESOLVED"]
    reservation_id: int
    amount_micro_usd: int
    predecessor_sha256: str
    entry_sha256: str


class FreshNvidiaExposureLedger:
    """Thread-safe append-only conservative exposure ledger.

    A reservation is created before a secret reader, client factory, or socket
    can be called.  Only a proven pre-socket failure can release it.  Once
    transport may have been exposed, the full reservation is committed.
    """

    def __init__(
        self,
        *,
        authority_id: str = FRESH_AUTHORITY_ID,
        committed_micro_usd: int = 0,
        max_attempts: int = FRESH_MAX_HTTP_ATTEMPTS,
    ) -> None:
        validate_fresh_authority_id(authority_id)
        if max_attempts != FRESH_MAX_HTTP_ATTEMPTS:
            raise ValueError("fresh NVIDIA attempt limit is fixed at 30")
        if (
            type(committed_micro_usd) is not int
            or not 0 <= committed_micro_usd <= FRESH_EXPOSURE_CAP_MICRO_USD
        ):
            raise ValueError("fresh NVIDIA committed exposure is outside the fixed cap")
        self._authority_id = authority_id
        self._max_attempts = max_attempts
        self._committed = committed_micro_usd
        self._next_reservation_id = 1
        self._attempt_count = 0
        self._outstanding: dict[int, FreshExposureReservation] = {}
        self._entries: list[FreshLedgerEntry] = []
        self._lock = threading.RLock()

    @property
    def authority_id(self) -> str:
        return self._authority_id

    @property
    def cap_micro_usd(self) -> int:
        return FRESH_EXPOSURE_CAP_MICRO_USD

    @property
    def reservation_micro_usd(self) -> int:
        return FRESH_RESERVATION_MICRO_USD

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    @property
    def attempt_count(self) -> int:
        with self._lock:
            return self._attempt_count

    @property
    def committed_micro_usd(self) -> int:
        with self._lock:
            return self._committed

    @property
    def outstanding_micro_usd(self) -> int:
        with self._lock:
            return sum(item.amount_micro_usd for item in self._outstanding.values())

    @property
    def remaining_cap_micro_usd(self) -> int:
        with self._lock:
            return FRESH_EXPOSURE_CAP_MICRO_USD - self._committed - self.outstanding_micro_usd

    @property
    def entries(self) -> tuple[FreshLedgerEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    @property
    def head_sha256(self) -> str:
        with self._lock:
            return self._entries[-1].entry_sha256 if self._entries else "0" * 64

    def reserve(self) -> FreshExposureReservation:
        with self._lock:
            projected = (
                self._committed
                + self.outstanding_micro_usd
                + FRESH_RESERVATION_MICRO_USD
            )
            if (
                self._attempt_count >= self._max_attempts
                or projected > FRESH_EXPOSURE_CAP_MICRO_USD
            ):
                raise RuntimeError("NVIDIA_FRESH_EXPOSURE_BUDGET_EXHAUSTED")
            reservation = FreshExposureReservation(
                reservation_id=self._next_reservation_id,
                attempt_number=self._attempt_count + 1,
                predecessor_sha256=self.head_sha256,
            )
            self._next_reservation_id += 1
            self._attempt_count += 1
            reservation_hash = canonical_sha256(
                {
                    "authority_id": self._authority_id,
                    "reservation_id": reservation.reservation_id,
                    "attempt_number": reservation.attempt_number,
                    "amount_micro_usd": reservation.amount_micro_usd,
                    "predecessor_sha256": reservation.predecessor_sha256,
                }
            )
            reservation = FreshExposureReservation(
                reservation_id=reservation.reservation_id,
                attempt_number=reservation.attempt_number,
                amount_micro_usd=reservation.amount_micro_usd,
                predecessor_sha256=reservation.predecessor_sha256,
                reservation_sha256=reservation_hash,
            )
            self._outstanding[reservation.reservation_id] = reservation
            self._append("RESERVE", reservation)
            return reservation

    def release_before_socket(self, reservation: FreshExposureReservation) -> None:
        with self._lock:
            self._pop(reservation)
            self._append("RELEASE_BEFORE_SOCKET", reservation)

    def release(self, reservation: FreshExposureReservation) -> None:
        self.release_before_socket(reservation)

    def commit(self, reservation: FreshExposureReservation) -> int:
        with self._lock:
            self._pop(reservation)
            self._committed += reservation.amount_micro_usd
            if self._committed > FRESH_EXPOSURE_CAP_MICRO_USD:
                raise RuntimeError("NVIDIA_FRESH_EXPOSURE_BUDGET_EXHAUSTED")
            self._append("COMMIT", reservation)
            return reservation.amount_micro_usd

    def commit_unknown(self, reservation: FreshExposureReservation) -> int:
        return self.commit(reservation)

    def recover_unresolved(self) -> int:
        with self._lock:
            pending = tuple(self._outstanding.values())
            for reservation in pending:
                self._pop(reservation)
                self._committed += reservation.amount_micro_usd
                self._append("RECOVER_UNRESOLVED", reservation)
            return len(pending)

    def verify_hash_chain(self) -> bool:
        with self._lock:
            predecessor = "0" * 64
            for entry in self._entries:
                if entry.predecessor_sha256 != predecessor:
                    return False
                expected = canonical_sha256(
                    {
                        "authority_id": self._authority_id,
                        "sequence": entry.sequence,
                        "operation": entry.operation,
                        "reservation_id": entry.reservation_id,
                        "amount_micro_usd": entry.amount_micro_usd,
                        "predecessor_sha256": entry.predecessor_sha256,
                    }
                )
                if not hmac.compare_digest(expected, entry.entry_sha256):
                    return False
                predecessor = entry.entry_sha256
            return True

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "schema_version": FRESH_SCHEMA_VERSION,
                "authority_id": self._authority_id,
                "cumulative_exposure_cap_micro_usd": FRESH_EXPOSURE_CAP_MICRO_USD,
                "reservation_micro_usd": FRESH_RESERVATION_MICRO_USD,
                "max_new_http_attempts": self._max_attempts,
                "attempt_count": self._attempt_count,
                "committed_micro_usd": self._committed,
                "outstanding_micro_usd": self.outstanding_micro_usd,
                "head_sha256": self.head_sha256,
                "hash_chain_valid": self.verify_hash_chain(),
            }

    def _pop(self, reservation: FreshExposureReservation) -> FreshExposureReservation:
        current = self._outstanding.pop(reservation.reservation_id, None)
        if current is None or current != reservation:
            raise RuntimeError("INVALID_OR_REUSED_FRESH_RESERVATION")
        return current

    def _append(
        self,
        operation: Literal[
            "RESERVE",
            "RELEASE_BEFORE_SOCKET",
            "COMMIT",
            "RECOVER_UNRESOLVED",
        ],
        reservation: FreshExposureReservation,
    ) -> None:
        predecessor = self.head_sha256
        sequence = len(self._entries) + 1
        entry_hash = canonical_sha256(
            {
                "authority_id": self._authority_id,
                "sequence": sequence,
                "operation": operation,
                "reservation_id": reservation.reservation_id,
                "amount_micro_usd": reservation.amount_micro_usd,
                "predecessor_sha256": predecessor,
            }
        )
        self._entries.append(
            FreshLedgerEntry(
                sequence=sequence,
                operation=operation,
                reservation_id=reservation.reservation_id,
                amount_micro_usd=reservation.amount_micro_usd,
                predecessor_sha256=predecessor,
                entry_sha256=entry_hash,
            )
        )


NvidiaFreshExposureLedger = FreshNvidiaExposureLedger
FreshExposureLedger = FreshNvidiaExposureLedger


class FreshProtectedStateDescriptor(StrictContract):
    """Private resolver descriptor; never serialize this as public request data."""

    schema_version: Literal["itda.phase5-fresh-protected-state.v1"] = (
        "itda.phase5-fresh-protected-state.v1"
    )
    authority_id: str
    state_root: str
    decision_target: str
    approval_target: str
    claim_target: str
    ledger_target: str
    journal_target: str
    raw_evidence_target: str
    protected_state_sha256: Sha256

    @model_validator(mode="after")
    def validate_descriptor(self) -> Self:
        validate_fresh_authority_id(self.authority_id)
        values = (
            self.state_root,
            self.decision_target,
            self.approval_target,
            self.claim_target,
            self.ledger_target,
            self.journal_target,
            self.raw_evidence_target,
        )
        if any(not value or not value.startswith("/") for value in values):
            raise ValueError("protected fresh state targets must be absolute")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"protected_state_sha256"})
        )
        if not hmac.compare_digest(expected, self.protected_state_sha256):
            raise ValueError("protected fresh state descriptor digest drifted")
        return self

    @classmethod
    def from_root(cls, *, authority_id: str = FRESH_AUTHORITY_ID, state_root: Path) -> Self:
        validate_fresh_authority_id(authority_id)
        container_root = state_root.absolute()
        root = str(container_root / "state")
        payload = {
            "schema_version": "itda.phase5-fresh-protected-state.v1",
            "authority_id": authority_id,
            "state_root": root,
            "decision_target": f"{root}/trusted-decision.json",
            "approval_target": f"{root}/approval.json",
            "claim_target": f"{root}/claim.json",
            "ledger_target": f"{root}/exposure-ledger.jsonl",
            "journal_target": str(container_root / "journal"),
            "raw_evidence_target": str(container_root / "raw-evidence"),
        }
        return cls.model_validate({**payload, "protected_state_sha256": canonical_sha256(payload)})


@dataclass(frozen=True, slots=True)
class FreshAuthorityClaim:
    authority_id: str
    request_sha256: str
    claim_sha256: str


FRESH_ATTEMPT_RESERVATION_MICRO_USD = FRESH_RESERVATION_MICRO_USD
FRESH_AUTHORITY_SHA256 = canonical_sha256({"authority_id": FRESH_AUTHORITY_ID})


__all__ = [
    "FRESH_ATTEMPT_DEADLINE_SECONDS",
    "FRESH_AUTHORITY_ID",
    "FRESH_CONCURRENCY",
    "FRESH_CONFIDENCE_THRESHOLD",
    "FRESH_CUMULATIVE_EXPOSURE_CAP_MICRO_USD",
    "FRESH_ENDPOINT",
    "FRESH_EXPOSURE_CAP_MICRO_USD",
    "FRESH_MAX_HTTP_ATTEMPTS",
    "FRESH_MIN_ELIGIBLE_PROFILES",
    "FRESH_MODEL",
    "FRESH_PRICE_STATUS",
    "FRESH_PROVIDER_LANE",
    "FRESH_RESERVATION_MICRO_USD",
    "FreshApprovalBinding",
    "FreshApprovalDecisionRecord",
    "FreshAuthorityClaim",
    "FreshExposureLedger",
    "FreshExposureReservation",
    "FreshLedgerEntry",
    "FreshNvidiaExposureLedger",
    "FreshProtectedStateDescriptor",
    "FreshPublicRequest",
    "NvidiaFreshExposureLedger",
    "validate_fresh_authority_id",
]
