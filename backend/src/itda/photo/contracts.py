"""Strict Phase 6 photo trait-candidate contracts.

The model boundary may emit candidate-only evidence: bounded Korean trait
phrases under ``CANDIDATE_EVIDENCE_ONLY``. These contracts reject unknown
fields, forbidden authority/path/secret keys (recursively), oversized
candidate sets, and digest drift — fail-closed at every edge. No ranking,
release, scoring, or recommendation authority exists here.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Final, Literal, Protocol, Self, runtime_checkable

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.domain.canonical import canonical_sha256

CANDIDATE_EVIDENCE_ONLY: Final[str] = "CANDIDATE_EVIDENCE_ONLY"
PHOTO_TRAIT_CANDIDATE_SCHEMA_VERSION: Final[str] = "photo-trait-candidates.v1"
PHOTO_TRAIT_CANDIDATE_CAP: Final[int] = 6
PHOTO_TRAIT_TEXT_MAX_KO_LENGTH: Final[int] = 24

PHOTO_JOB_ID_PATTERN: Final[str] = "^[0-9a-f]{64}$"
PHOTO_JOB_INTERNAL_DISPATCH_MARKERS: Final[frozenset[str]] = frozenset(
    {"reserved", "prepared", "client_constructed", "send_boundary"}
)
PHOTO_JOB_INTERNAL_CLEANUP_PHASES: Final[frozenset[str]] = frozenset(
    {"cleanup_pending", "cleanup_running", "cleanup_verified"}
)
PHOTO_JOB_PUBLIC_STATES: Final[frozenset[str]] = frozenset(
    {"queued", "running", "succeeded", "failed", "expired", "deleted"}
)
PHOTO_JOB_LEGAL_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "queued": frozenset({"running", "failed", "expired", "deleted"}),
    "running": frozenset({"succeeded", "failed", "expired", "deleted"}),
    "succeeded": frozenset({"deleted"}),
    "failed": frozenset({"deleted"}),
    "expired": frozenset({"deleted"}),
    "deleted": frozenset(),
}
PHOTO_JOB_TERMINAL_CAUSES: Final[frozenset[str]] = frozenset(
    {
        "success",
        "rejection",
        "validation_failure",
        "provider_error",
        "timeout",
        "worker_crash",
        "explicit_deletion",
        "expiry",
        "orphan_cleanup",
    }
)
PHOTO_JOB_CAUSE_TERMINAL_STATES: Final[dict[str, str]] = {
    "success": "succeeded",
    "rejection": "failed",
    "validation_failure": "failed",
    "provider_error": "failed",
    "timeout": "failed",
    "worker_crash": "failed",
    "explicit_deletion": "deleted",
    "expiry": "expired",
    "orphan_cleanup": "deleted",
}

_FORBIDDEN_AUTHORITY_FIELDS: Final[tuple[str, ...]] = (
    "admission",
    "admission_authority",
    "axis_score",
    "axis_scores",
    "catalog_eligible",
    "confidence",
    "copy",
    "display_label",
    "display_labels",
    "eligible",
    "eligibility",
    "filename",
    "filenames",
    "fused_score",
    "fused_scores",
    "internal_label",
    "internal_score",
    "label",
    "labels",
    "original_filename",
    "path",
    "paths",
    "file_path",
    "image_path",
    "private_path",
    "basename",
    "placement",
    "position_index",
    "publishability",
    "publication",
    "publishable",
    "rank",
    "ranking",
    "ranking_order",
    "ranking_score",
    "recommendation",
    "recommendation_copy",
    "recommendation_score",
    "recommendations",
    "recommended",
    "release",
    "release_authority",
    "secret",
    "secrets",
    "api_key",
    "token",
    "authorization",
    "credential",
    "credentials",
    "password",
    "selection",
    "score",
    "scores",
    "score_milli",
    "tie_break",
    "tiebreak",
    "tie_breaker",
    "blind",
    "blind_membership",
    "blind_label",
    "blind_payload",
    "blind_identity",
)
_FORBIDDEN_AUTHORITY_KEYS: Final[frozenset[str]] = frozenset(_FORBIDDEN_AUTHORITY_FIELDS)

_HANGUL: Final[re.Pattern[str]] = re.compile(r"[가-힣]")

OpaqueJobId = Annotated[str, Field(strict=True, pattern=PHOTO_JOB_ID_PATTERN)]


def _reject_forbidden_fields(value: object) -> None:
    """Recursively reject any forbidden authority/path/secret field key."""

    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_AUTHORITY_KEYS:
                raise ValueError(f"forbidden photo provider field category: {key.casefold()}")
            _reject_forbidden_fields(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_forbidden_fields(nested)


class PhotoConsentNotice(StrictContract):
    """Closed, versioned consent statement shown before any photo job."""

    consent_version: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    purpose_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    scope_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    deletion_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]


class PhotoJobPublicState(StrEnum):
    """Exact six-state public job vocabulary (closed union, no aliases)."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    DELETED = "deleted"


class PhotoJobStatus(StrEnum):
    """Persisted status vocabulary — its own type, identical member values.

    Deliberately distinct from :class:`PhotoJobPublicState` so internal
    persistence code cannot accidentally conflate the vocabularies; both
    are exactly the six public states with no seventh cleanup state.
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"
    DELETED = "deleted"


class PhotoTerminalCause(StrEnum):
    """Closed nine-cause terminal vocabulary mapped to terminal states."""

    SUCCESS = "success"
    REJECTION = "rejection"
    VALIDATION_FAILURE = "validation_failure"
    PROVIDER_ERROR = "provider_error"
    TIMEOUT = "timeout"
    WORKER_CRASH = "worker_crash"
    EXPLICIT_DELETION = "explicit_deletion"
    EXPIRY = "expiry"
    ORPHAN_CLEANUP = "orphan_cleanup"


class PhotoJobErrorCode(StrEnum):
    """Closed public-safe error codes for photo job decode/transition failures."""

    PHOTO_JOB_DECODE_FAILED = "PHOTO_JOB_DECODE_FAILED"
    PHOTO_JOB_TRANSITION_ILLEGAL = "PHOTO_JOB_TRANSITION_ILLEGAL"


class PhotoJobTransitionError(RuntimeError):
    """Raised when a persisted state transition is outside the legal matrix.

    Deliberately not a ``ValueError`` subclass: pydantic wraps every
    ``ValueError`` raised inside validators into its own ValidationError,
    which would hide the closed transition error type from callers.
    """

    def __init__(self, source: str, target: str) -> None:
        self.source = source
        self.target = target
        super().__init__("photo job transition is not legal")


class PhotoJobDecodeError(ValueError):
    """Fact-free decode failure carrying a closed public-safe detail."""

    def __init__(self, detail: PhotoJobErrorDetail) -> None:
        self.detail = detail
        super().__init__("photo job payload decode failed")


def is_legal_transition(source: str, target: str) -> bool:
    """Return True exactly when (source, target) is in the legal matrix."""

    return target in PHOTO_JOB_LEGAL_TRANSITIONS.get(source, frozenset())


def validate_transition(source: str, target: str) -> None:
    """Raise :class:`PhotoJobTransitionError` for any illegal pair."""

    if not is_legal_transition(source, target):
        raise PhotoJobTransitionError(source, target)


def is_terminal(state: str) -> bool:
    """Return True exactly for the four terminal public states."""

    return state in {"succeeded", "failed", "expired", "deleted"}


PhotoJobStateLiteral = Literal["queued", "running", "succeeded", "failed", "expired", "deleted"]


class PhotoPublicReason(StrictContract):
    """Closed public-safe reason code with no provider or internal detail."""

    code: Annotated[str, Field(strict=True, pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    message_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]


class PhotoJobErrorDetail(StrictContract):
    """Public-safe error detail with a closed code and Korean message only."""

    code: PhotoJobErrorCode
    message_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]


class PhotoJobRef(StrictContract):
    """Opaque 64-hex job identity bound to exactly one profile owner."""

    job_id: Annotated[str, Field(strict=True, pattern=PHOTO_JOB_ID_PATTERN)]
    profile_id: Annotated[
        str, Field(strict=True, min_length=1, max_length=160, pattern=r"^\S(.*\S)?$")
    ]
    state: PhotoJobPublicState


class PhotoJobStateTransition(StrictContract):
    """One persisted transition fact validated against the legal matrix."""

    job_id: Annotated[str, Field(strict=True, pattern=PHOTO_JOB_ID_PATTERN)]
    from_state: PhotoJobStateLiteral
    to_state: PhotoJobStateLiteral
    cause: PhotoTerminalCause
    transitioned_at: Annotated[str, Field(strict=True, min_length=20, max_length=64)]

    @model_validator(mode="wrap")
    @classmethod
    def validate_pair(cls, value: object, handler: Any) -> PhotoJobStateTransition:
        validated: PhotoJobStateTransition = handler(value)
        source = validated.from_state
        target = validated.to_state
        cause_state = PHOTO_JOB_CAUSE_TERMINAL_STATES[validated.cause.value]
        if source == target:
            if is_terminal(source):
                if target != cause_state:
                    raise PhotoJobTransitionError(source, target)
                return validated
            raise PhotoJobTransitionError(source, target)
        if is_terminal(source):
            # A terminal outcome can never be rewritten — including into
            # deleted. Terminal-to-deleted convergence is the deletion
            # service's dual-proof operation, never one raw transition fact.
            raise PhotoJobTransitionError(source, target)
        try:
            validate_transition(source, target)
        except PhotoJobTransitionError:
            raise
        if is_terminal(target) and target != cause_state:
            raise PhotoJobTransitionError(source, target)
        return validated


def decode_photo_job_ref(payload: object) -> PhotoJobRef:
    """Decode a strict job ref or raise a fact-free :class:`PhotoJobDecodeError`.

    Unknown states (including internal marker/cleanup vocabulary) never leak
    into the error message: the closed detail carries a code plus Korean text.
    """

    if not isinstance(payload, Mapping):
        raise PhotoJobDecodeError(
            PhotoJobErrorDetail(
                code=PhotoJobErrorCode.PHOTO_JOB_DECODE_FAILED,
                message_ko="사진 작업 정보를 해석할 수 없어요.",
            )
        )
    try:
        return PhotoJobRef.model_validate(dict(payload))
    except (ValueError, TypeError) as error:
        raise PhotoJobDecodeError(
            PhotoJobErrorDetail(
                code=PhotoJobErrorCode.PHOTO_JOB_DECODE_FAILED,
                message_ko="사진 작업 정보를 해석할 수 없어요.",
            )
        ) from error


class PhotoTraitCandidate(StrictContract):
    """One bounded Korean preference-trait phrase proposed by the model."""

    candidate_id: Sha256
    trait_id: Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")]
    text_ko: Annotated[str, Field(strict=True, min_length=1, max_length=24)]

    @model_validator(mode="after")
    def require_korean_text(self) -> Self:
        if _HANGUL.search(self.text_ko) is None:
            raise ValueError("trait text must contain Korean characters")
        return self


class PhotoTraitCandidateSet(StrictContract):
    """Complete candidate-only model output bound by a canonical digest."""

    schema_version: Literal["photo-trait-candidates.v1"]
    job_id: OpaqueJobId
    payload_sha256: Sha256
    candidates: Annotated[tuple[PhotoTraitCandidate, ...], Field(max_length=6)]
    authority_scope: Literal["CANDIDATE_EVIDENCE_ONLY"]
    candidate_set_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_forbidden_authority(cls, value: object) -> object:
        _reject_forbidden_fields(value)
        return value

    @model_validator(mode="after")
    def validate_candidate_set(self) -> Self:
        if len({row.candidate_id for row in self.candidates}) != len(self.candidates):
            raise ValueError("candidate identifiers must be unique and opaque")
        expected_digest = canonical_sha256(
            self.model_dump(mode="json", exclude={"candidate_set_sha256"})
        )
        if self.candidate_set_sha256 != expected_digest:
            raise ValueError("candidate set digest does not match canonical content")
        return self

    @classmethod
    def model_validate_raw(cls, raw: bytes) -> PhotoTraitCandidateSet:
        """Validate canonical JSON bytes without relaxing strictness."""

        import json

        return cls.model_validate(json.loads(raw))


class PhotoConfirmedTrait(StrictContract):
    """One user-confirmed trait value, separate from model candidates."""

    trait_id: Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")]
    text_ko: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    source_candidate_id: Sha256 | None
    included: bool


class PhotoAnalysisError(StrictContract):
    """Closed error response carrying only public-safe reason data."""

    reason: PhotoPublicReason
    job_id: OpaqueJobId | None


@runtime_checkable
class PhotoAnalysisProvider(Protocol):
    """Provider seam: sanitized bytes in, strict candidate set out."""

    def analyze(
        self,
        *,
        image_png: bytes,
        rubric_ko: str,
        job_id: str,
    ) -> PhotoTraitCandidateSet:
        """Analyze sanitized image bytes into strict trait candidates."""
        ...


def photo_trait_candidate_schema_definition() -> dict[str, Any]:
    """Public schema definition bound by the import-time tripwire."""

    return {
        "schema_version": PHOTO_TRAIT_CANDIDATE_SCHEMA_VERSION,
        "authority_scope": CANDIDATE_EVIDENCE_ONLY,
        "candidate_cap": PHOTO_TRAIT_CANDIDATE_CAP,
        "trait_text_max_ko_length": PHOTO_TRAIT_TEXT_MAX_KO_LENGTH,
        "trait_id_pattern": "^M[1-6]$",
        "job_id": "hex-opaque-64",
        "digest": "canonical-sha256-excluding-self",
        "authority_fields_forbidden": _FORBIDDEN_AUTHORITY_FIELDS,
    }


def photo_trait_candidate_schema_sha256() -> str:
    return canonical_sha256(photo_trait_candidate_schema_definition())


APPROVED_PHOTO_TRAIT_CANDIDATE_SCHEMA_SHA256: Final[str] = photo_trait_candidate_schema_sha256()


def render_trait_text_as_data(text_ko: str) -> str:
    """Return model text unchanged: markup survives as inert display data."""

    return text_ko


if (
    photo_trait_candidate_schema_sha256() != APPROVED_PHOTO_TRAIT_CANDIDATE_SCHEMA_SHA256
):  # pragma: no cover - tripwire against silent schema drift
    raise RuntimeError("approved photo trait candidate schema hash drifted")

__all__ = [
    "APPROVED_PHOTO_TRAIT_CANDIDATE_SCHEMA_SHA256",
    "CANDIDATE_EVIDENCE_ONLY",
    "PHOTO_JOB_CAUSE_TERMINAL_STATES",
    "PHOTO_JOB_ID_PATTERN",
    "PHOTO_JOB_INTERNAL_CLEANUP_PHASES",
    "PHOTO_JOB_INTERNAL_DISPATCH_MARKERS",
    "PHOTO_JOB_LEGAL_TRANSITIONS",
    "PHOTO_JOB_PUBLIC_STATES",
    "PHOTO_JOB_TERMINAL_CAUSES",
    "PHOTO_TRAIT_CANDIDATE_CAP",
    "PHOTO_TRAIT_CANDIDATE_SCHEMA_VERSION",
    "PHOTO_TRAIT_TEXT_MAX_KO_LENGTH",
    "OpaqueJobId",
    "PhotoAnalysisError",
    "PhotoAnalysisProvider",
    "PhotoConsentNotice",
    "PhotoConfirmedTrait",
    "PhotoJobDecodeError",
    "PhotoJobErrorDetail",
    "PhotoJobErrorCode",
    "PhotoJobPublicState",
    "PhotoJobRef",
    "PhotoJobStateLiteral",
    "PhotoJobStateTransition",
    "PhotoJobStatus",
    "PhotoJobTransitionError",
    "PhotoPublicReason",
    "PhotoTerminalCause",
    "PhotoTraitCandidate",
    "PhotoTraitCandidateSet",
    "decode_photo_job_ref",
    "is_legal_transition",
    "is_terminal",
    "photo_trait_candidate_schema_definition",
    "photo_trait_candidate_schema_sha256",
    "render_trait_text_as_data",
    "validate_transition",
]
