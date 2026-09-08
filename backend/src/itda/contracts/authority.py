"""Shared fail-closed authority-v2 contract for Phase 2 human actions."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import Field, ValidationInfo, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

AuthorityAction = Literal[
    "enrichment-collect",
    "catalog-optional-media-close",
    "catalog-adjudicate-select",
    "catalog-approve",
    "catalog-activate",
    "catalog-rollback",
    "real-split-materialize",
    "split-approve",
    "sqlite-manifest-initialize",
    "sqlite-real-manifest-seal",
    "schema-apply-0003",
    "schema-verify-0003",
    "real-manifest-seal",
    "real-manifest-verify-existing",
]

ALLOWED_AUTHORITY_ACTIONS: frozenset[str] = frozenset(
    (
        "enrichment-collect",
        "catalog-optional-media-close",
        "catalog-adjudicate-select",
        "catalog-approve",
        "catalog-activate",
        "catalog-rollback",
        "real-split-materialize",
        "split-approve",
        "sqlite-manifest-initialize",
        "sqlite-real-manifest-seal",
        "schema-apply-0003",
        "schema-verify-0003",
        "real-manifest-seal",
        "real-manifest-verify-existing",
    )
)

_TOKEN_PATTERN = re.compile(
    r"^itda-auth-v2:"
    r"(?P<action>[a-z0-9-]+):"
    r"(?P<request>[0-9a-f]{64}):"
    r"(?P<state>[0-9a-f]{64}):"
    r"(?P<target>[0-9a-f]{64}):"
    r"(?P<reviewer>[A-Za-z0-9][A-Za-z0-9._-]{0,63}):"
    r"(?P<binding>[0-9a-f]{64}):"
    r"(?P<nonce>[0-9a-f]{64})$",
    flags=re.ASCII,
)


class AuthorityReplayError(RuntimeError):
    """The binding-global nonce was already consumed."""


class AuthorityMutationUncertain(RuntimeError):
    """A mutation may have committed and must be relooked up before retry."""


class AuthorityTokenV2(StrictContract):
    """The exact seven-field authority token, excluding its fixed prefix."""

    action: AuthorityAction
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    reviewer_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]
    binding_sha256: Sha256
    nonce: Sha256

    def serialize(self) -> str:
        """Return the only accepted ASCII wire representation."""

        return (
            f"itda-auth-v2:{self.action}:{self.request_sha256}:"
            f"{self.state_attestation_sha256}:{self.target_sha256}:"
            f"{self.reviewer_id}:{self.binding_sha256}:{self.nonce}"
        )

    @classmethod
    def parse(cls, raw: str) -> AuthorityTokenV2:
        """Parse without trimming, normalization, aliases, or partial matching."""

        if not isinstance(raw, str):
            raise TypeError("authority token must be text")
        if unicodedata.normalize("NFKC", raw) != raw or not raw.isascii():
            raise ValueError("authority token must be canonical ASCII")
        match = _TOKEN_PATTERN.fullmatch(raw)
        if match is None:
            raise ValueError("authority token does not match strict itda-auth-v2 grammar")
        action = match.group("action")
        if action not in ALLOWED_AUTHORITY_ACTIONS:
            raise ValueError("authority action is not allowlisted")
        token = cls(
            action=cast(AuthorityAction, action),
            request_sha256=match.group("request"),
            state_attestation_sha256=match.group("state"),
            target_sha256=match.group("target"),
            reviewer_id=match.group("reviewer"),
            binding_sha256=match.group("binding"),
            nonce=match.group("nonce"),
        )
        if token.serialize() != raw:
            raise ValueError("authority token is not in canonical wire form")
        return token


def derive_request_sha256(request: object) -> str:
    """Derive the complete canonical request digest."""

    return canonical_sha256(request)


def derive_state_attestation_sha256(state_attestation: object) -> str:
    """Derive the complete current-state attestation digest."""

    return canonical_sha256(state_attestation)


def derive_target_sha256(target: object) -> str:
    """Derive the exact mutation/result target digest."""

    return canonical_sha256(target)


def derive_binding_sha256(binding: object) -> str:
    """Derive the consumer-global authority binding digest."""

    return canonical_sha256(binding)


class AuthorityIssuanceContext(StrictContract):
    """Frozen issuance facts from which every consumer rederives authority."""

    schema_version: Literal["itda-authority-issuance-context-v2"] = (
        "itda-authority-issuance-context-v2"
    )
    action: AuthorityAction
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    reviewer_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]
    binding_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    expires_at: datetime
    replaces_request_sha256: Sha256 | None = None
    reviewer_channel_risk: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    context_sha256: Sha256 | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime, info: ValidationInfo) -> datetime:
        return require_utc(value, field_name=info.field_name or "authority_timestamp")

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("authority expiry must be later than issuance")
        expected = canonical_sha256(self.model_dump(exclude={"context_sha256"}, mode="json"))
        if self.context_sha256 is None:
            object.__setattr__(self, "context_sha256", expected)
        elif not hmac.compare_digest(self.context_sha256, expected):
            raise ValueError("authority issuance context sha256 is stale")
        return self

    def expected_token(self) -> AuthorityTokenV2:
        """Project the strict token without persisting a raw wire value."""

        return AuthorityTokenV2(
            action=self.action,
            request_sha256=self.request_sha256,
            state_attestation_sha256=self.state_attestation_sha256,
            target_sha256=self.target_sha256,
            reviewer_id=self.reviewer_id,
            binding_sha256=self.binding_sha256,
            nonce=self.nonce,
        )


def freeze_issuance_context(
    *,
    action: AuthorityAction,
    request: object,
    state_attestation: object,
    target: object,
    reviewer_id: str,
    binding: object,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    reviewer_channel_risk: str,
    replaces_request_sha256: str | None = None,
) -> AuthorityIssuanceContext:
    """Freeze one deterministic issuance context from complete canonical parents."""

    return AuthorityIssuanceContext(
        action=action,
        request_sha256=derive_request_sha256(request),
        state_attestation_sha256=derive_state_attestation_sha256(state_attestation),
        target_sha256=derive_target_sha256(target),
        reviewer_id=reviewer_id,
        binding_sha256=derive_binding_sha256(binding),
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        replaces_request_sha256=replaces_request_sha256,
        reviewer_channel_risk=reviewer_channel_risk,
    )


class AuthorityRevocationTombstone(StrictContract):
    """Immutable revocation/replacement evidence for a frozen issuance context."""

    schema_version: Literal["itda-authority-revocation-v2"] = "itda-authority-revocation-v2"
    issuance_context_sha256: Sha256
    binding_sha256: Sha256
    nonce_sha256: Sha256
    revoked_at: datetime
    reason_code: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Z][A-Z0-9_]{0,63}$"),
    ]
    replacement_request_sha256: Sha256 | None = None
    tombstone_sha256: Sha256 | None = None

    @field_validator("revoked_at")
    @classmethod
    def revoked_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="revoked_at")

    @model_validator(mode="after")
    def validate_tombstone(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"tombstone_sha256"}, mode="json"))
        if self.tombstone_sha256 is None:
            object.__setattr__(self, "tombstone_sha256", expected)
        elif not hmac.compare_digest(self.tombstone_sha256, expected):
            raise ValueError("authority revocation tombstone sha256 is stale")
        return self

    @classmethod
    def for_context(
        cls,
        context: AuthorityIssuanceContext,
        *,
        revoked_at: datetime,
        reason_code: str,
        replacement_request_sha256: str | None = None,
    ) -> AuthorityRevocationTombstone:
        if context.context_sha256 is None:
            raise ValueError("authority issuance context lacks a canonical digest")
        return cls(
            issuance_context_sha256=context.context_sha256,
            binding_sha256=context.binding_sha256,
            nonce_sha256=hashlib.sha256(context.nonce.encode("ascii")).hexdigest(),
            revoked_at=revoked_at,
            reason_code=reason_code,
            replacement_request_sha256=replacement_request_sha256,
        )


class ValidatedAuthority(StrictContract):
    """Internal proof produced by validation without consuming authority."""

    issuance_context: AuthorityIssuanceContext
    token_sha256: Sha256


def _require_same(label: str, actual: str, expected: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise ValueError(f"authority {label} digest or field is stale")


def validate_authority_token(
    raw_token: str,
    *,
    issuance_context: AuthorityIssuanceContext,
    request: object,
    state_attestation: object,
    target: object,
    binding: object,
    reviewer_id: str,
    now: datetime,
    revocation_tombstones: Iterable[AuthorityRevocationTombstone],
) -> ValidatedAuthority:
    """Independently rederive every field without consuming the nonce."""

    canonical_now = require_utc(now, field_name="now")
    if canonical_now < issuance_context.issued_at:
        raise ValueError("authority token is not yet valid")
    if canonical_now >= issuance_context.expires_at:
        raise ValueError("authority token is expired")
    if issuance_context.context_sha256 is None:
        raise ValueError("authority issuance context lacks a canonical digest")
    for tombstone in revocation_tombstones:
        if hmac.compare_digest(
            tombstone.issuance_context_sha256,
            issuance_context.context_sha256,
        ):
            raise ValueError("authority issuance context is revoked by tombstone")

    token = AuthorityTokenV2.parse(raw_token)
    expected = issuance_context.expected_token()
    _require_same("action", token.action, expected.action)
    _require_same(
        "request",
        token.request_sha256,
        derive_request_sha256(request),
    )
    _require_same("request context", token.request_sha256, issuance_context.request_sha256)
    _require_same(
        "state",
        token.state_attestation_sha256,
        derive_state_attestation_sha256(state_attestation),
    )
    _require_same(
        "state context",
        token.state_attestation_sha256,
        issuance_context.state_attestation_sha256,
    )
    _require_same("target", token.target_sha256, derive_target_sha256(target))
    _require_same("target context", token.target_sha256, issuance_context.target_sha256)
    _require_same("reviewer", token.reviewer_id, reviewer_id)
    _require_same("reviewer context", token.reviewer_id, issuance_context.reviewer_id)
    _require_same("binding", token.binding_sha256, derive_binding_sha256(binding))
    _require_same("binding context", token.binding_sha256, issuance_context.binding_sha256)
    _require_same("nonce", token.nonce, issuance_context.nonce)
    return ValidatedAuthority(
        issuance_context=issuance_context,
        token_sha256=hashlib.sha256(raw_token.encode("ascii")).hexdigest(),
    )


class AuthorityConsumptionReceipt(StrictContract):
    """Secret-safe proof that one nonce and its mutation completed together."""

    schema_version: Literal["itda-authority-consumption-receipt-v2"] = (
        "itda-authority-consumption-receipt-v2"
    )
    action: AuthorityAction
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    reviewer_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]
    binding_sha256: Sha256
    nonce_sha256: Sha256
    token_sha256: Sha256
    issuance_context_sha256: Sha256
    result_sha256: Sha256
    completion: Literal["MUTATION_COMMITTED", "RELOOKUP_CONFIRMED"]
    reviewer_channel_risk: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    receipt_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif not hmac.compare_digest(self.receipt_sha256, expected):
            raise ValueError("authority receipt sha256 is stale")
        return self


Mutation = Callable[[], Mapping[str, object]]
Relookup = Callable[[], Mapping[str, object] | None]


class FileNonceLedger:
    """Cross-process binding-global nonce ledger with uncertain-result recovery."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.ledger_path = root / "authority-consumption-ledger.jsonl"
        self.lock_path = root / "authority-consumption-ledger.lock"

    @staticmethod
    def _nonce_sha256(context: AuthorityIssuanceContext) -> str:
        return hashlib.sha256(context.nonce.encode("ascii")).hexdigest()

    @staticmethod
    def _result_sha256(result: Mapping[str, object]) -> str:
        value = result.get("result_sha256")
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("authority mutation result requires result_sha256")
        return value

    def _read_receipts(self) -> tuple[AuthorityConsumptionReceipt, ...]:
        if not self.ledger_path.exists():
            return ()
        if self.ledger_path.is_symlink() or not self.ledger_path.is_file():
            raise ValueError("authority nonce ledger is not a regular file")
        receipts: list[AuthorityConsumptionReceipt] = []
        for line in self.ledger_path.read_bytes().splitlines():
            if not line:
                raise ValueError("authority nonce ledger contains a blank record")
            parsed = AuthorityConsumptionReceipt.model_validate(json.loads(line))
            if line != canonical_json_bytes(parsed.model_dump(mode="json")):
                raise ValueError("authority nonce ledger contains noncanonical bytes")
            receipts.append(parsed)
        return tuple(receipts)

    def _append_receipt(self, receipt: AuthorityConsumptionReceipt) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.ledger_path, flags, 0o600)
        try:
            payload = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
            written = os.write(descriptor, payload)
            if written != len(payload):
                raise OSError("short write while recording authority consumption")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def consume_with_mutation(
        self,
        validated: ValidatedAuthority,
        *,
        mutation: Mutation,
        relookup: Relookup | None = None,
    ) -> AuthorityConsumptionReceipt:
        """Consume once while serialized with mutation and deterministic relookup."""

        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("authority nonce ledger root is not a regular directory")
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        lock_descriptor = os.open(self.lock_path, lock_flags, 0o600)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            context = validated.issuance_context
            nonce_sha256 = self._nonce_sha256(context)
            for receipt in self._read_receipts():
                if hmac.compare_digest(
                    receipt.binding_sha256, context.binding_sha256
                ) and hmac.compare_digest(receipt.nonce_sha256, nonce_sha256):
                    raise AuthorityReplayError("binding-global authority nonce already consumed")

            completion: Literal["MUTATION_COMMITTED", "RELOOKUP_CONFIRMED"]
            preexisting = relookup() if relookup is not None else None
            if preexisting is not None:
                result_sha256 = self._result_sha256(preexisting)
                completion = "RELOOKUP_CONFIRMED"
            else:
                try:
                    result_sha256 = self._result_sha256(mutation())
                    completion = "MUTATION_COMMITTED"
                except AuthorityMutationUncertain:
                    recovered = relookup() if relookup is not None else None
                    if recovered is None:
                        raise
                    result_sha256 = self._result_sha256(recovered)
                    completion = "RELOOKUP_CONFIRMED"

            if context.context_sha256 is None:
                raise ValueError("authority issuance context lacks a canonical digest")
            receipt = AuthorityConsumptionReceipt(
                action=context.action,
                request_sha256=context.request_sha256,
                state_attestation_sha256=context.state_attestation_sha256,
                target_sha256=context.target_sha256,
                reviewer_id=context.reviewer_id,
                binding_sha256=context.binding_sha256,
                nonce_sha256=nonce_sha256,
                token_sha256=validated.token_sha256,
                issuance_context_sha256=context.context_sha256,
                result_sha256=result_sha256,
                completion=completion,
                reviewer_channel_risk=context.reviewer_channel_risk,
            )
            self._append_receipt(receipt)
            return receipt
        finally:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)


__all__ = [
    "ALLOWED_AUTHORITY_ACTIONS",
    "AuthorityAction",
    "AuthorityConsumptionReceipt",
    "AuthorityIssuanceContext",
    "AuthorityMutationUncertain",
    "AuthorityReplayError",
    "AuthorityRevocationTombstone",
    "AuthorityTokenV2",
    "FileNonceLedger",
    "ValidatedAuthority",
    "derive_binding_sha256",
    "derive_request_sha256",
    "derive_state_attestation_sha256",
    "derive_target_sha256",
    "freeze_issuance_context",
    "validate_authority_token",
]
