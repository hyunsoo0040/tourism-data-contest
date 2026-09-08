"""Versioned photo-preference lifecycle routes (Phase 6, Plan 06-08).

Seven owned routes expose the photo vertical: consent-gated job creation,
raw streamed image uploads into bounded quarantine, synthetic-only analysis
submission, rate-limited polling, trait review/confirmation, and dual-truth
deletion. Every route binds the server-derived preference-profile principal
and maps every failure to one closed Korean reason code.

The upload boundary consumes ``request.stream()`` chunks only — multipart
materialization is structurally absent, and Content-Length is an early
rejection advisory only: the accumulated quarantine cap remains the sole
memory authority. Public rejections never reflect input markers, header
values, paths, stored names, provider payloads, or internal labels.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from collections.abc import Sequence
from contextlib import suppress
from functools import lru_cache
from pathlib import Path as FilePath
from typing import Annotated, Any, Final, NoReturn

import psycopg
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import Field

from itda.api.dependencies import (
    PROFILE_SESSION_COOKIE_NAME,
    ProfileSessionPrincipal,
    get_optional_profile_session,
    get_profile_session,
    require_same_origin_mutation,
)
from itda.contracts.base import Sha256, StableId, StrictContract
from itda.db.photo_repositories import (
    PhotoConfirmedTraitStore,
    PhotoJobConflict,
    PhotoJobNotFound,
    PhotoJobStore,
    PhotoJobStoreError,
    PhotoReviewDraftStore,
    PhotoTraitCandidateStore,
    ReviewDraftEntry,
)
from itda.db.session import create_database_engine, create_session_factory
from itda.photo.contracts import (
    PHOTO_JOB_ID_PATTERN,
    PhotoConsentNotice,
    PhotoJobPublicState,
    PhotoTerminalCause,
)
from itda.photo.deletion import (
    DeletionIncomplete,
    execute_terminal_deletion,
    execute_unbound_explicit_deletion,
    list_generated_entry_names,
    release_filesystem_cleanup,
)
from itda.photo.jobs import PhotoJobError, PhotoJobService, reconcile_interrupted_jobs
from itda.photo.preprocessing import (
    PhotoUploadPreprocessingError,
    preprocess_quarantined_image,
)
from itda.photo.provider import SyntheticPhotoAnalysisProvider
from itda.photo.quarantine import (
    QuarantineError,
    QuarantinePolicy,
    open_quarantine_root,
    open_quarantined_image,
    stream_to_quarantine,
)
from itda.photo.ratelimit import (
    PhotoRateLimiter,
    PhotoRateLimitError,
    PhotoRateLimitPolicy,
    PhotoResourceBudget,
    PhotoResourceBudgetError,
)

router = APIRouter(prefix="/v1", tags=["photo-preference"])

PHOTO_SERVICE_DSN_ENVIRONMENT_VARIABLE: Final[str] = "ITDA_PHOTO_SERVICE_DATABASE_URL"
PHOTO_QUARANTINE_ROOT_ENVIRONMENT_VARIABLE: Final[str] = "ITDA_PHOTO_QUARANTINE_ROOT"
RUNTIME_ROLE_ENVIRONMENT_VARIABLE: Final[str] = "ITDA_RUNTIME_ROLE"
LABEL_BUILDER_ROLE_ENVIRONMENT_VARIABLE: Final[str] = "ITDA_LABEL_BUILDER_ROLE"
PHOTO_AUTHORITY_SERVICE_ROLE: Final[str] = "itda_photo_service"
PHOTO_WRITE_AUTHORITY_ROLE: Final[str] = "itda_photo_write_authority"

_MAX_IMAGE_BYTES: Final[int] = 10 * 1024 * 1024
_READ_CHUNK_BYTES: Final[int] = 1024 * 1024
_HEX_JOB_ID: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_ACCEPTED_MEDIA_TYPES: Final[frozenset[str]] = frozenset({"image/jpeg", "image/png", "image/webp"})
_PUBLIC_RUBRIC_KO: Final[str] = "사진에서 나타나는 여행 선호를 공개 기준으로 분석합니다"

CURRENT_PHOTO_CONSENT_NOTICE: Final[PhotoConsentNotice] = PhotoConsentNotice(
    consent_version="photo-consent-2026-08-v1",
    purpose_ko="회원님이 올린 사진에서 여행 취향 후보를 공개 기준으로 분석하기 위해서예요.",
    scope_ko="사진은 분석용으로만 쓰이며, 원본은 즉시 안전하게 정리됩니다.",
    deletion_ko="사진 작업을 지우면 원본과 분석 기록이 모두 안전하게 제거돼요.",
)

# ---------------------------------------------------------------------------
# Public API contracts (closed, bounded, opaque)
# ---------------------------------------------------------------------------


class PhotoErrorDetail(StrictContract):
    """Closed public-safe photo error detail."""

    code: Annotated[str, Field(strict=True, pattern=r"^[A-Z][A-Z0-9_]{2,63}$")]
    message_ko: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    request_id: StableId | None = None
    job_id: Annotated[str, Field(strict=True, pattern=PHOTO_JOB_ID_PATTERN)] | None = None
    preference_profile_id: StableId | None = None


class PhotoErrorResponse(StrictContract):
    """Bounded error response body shared by every photo failure."""

    detail: PhotoErrorDetail


class PhotoJobCreateRequest(StrictContract):
    """Consent-gated job creation request."""

    consent_version: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    consent_accepted: bool


class PhotoJobCreatedResponse(StrictContract):
    """One owned queued job bound to the requesting principal."""

    job_id: Sha256
    preference_profile_id: StableId
    state: PhotoJobPublicState
    consent_version: Annotated[str, Field(strict=True, min_length=1, max_length=64)]


class PhotoJobImageStoredResponse(StrictContract):
    """Bounded storage receipt for one streamed image."""

    job_id: Sha256
    image_index: Annotated[int, Field(strict=True, ge=1, le=3)]
    byte_length: Annotated[int, Field(strict=True, ge=1)]


class PhotoJobStateResponse(StrictContract):
    """Owned six-state job projection with separately derived cleanup truth."""

    job_id: Sha256
    preference_profile_id: StableId
    state: PhotoJobPublicState
    terminal_cause: PhotoTerminalCause | None
    cleanup_pending: bool


class PhotoTraitCandidateView(StrictContract):
    """One immutable model candidate proposed for review."""

    candidate_id: Sha256
    trait_id: Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")]
    text_ko: Annotated[str, Field(strict=True, min_length=1, max_length=24)]
    edited_text_ko: Annotated[str, Field(strict=True, min_length=1, max_length=64)] | None
    excluded: bool


class PhotoConfirmedTraitView(StrictContract):
    """One explicit user-confirmed value, separate from model candidates."""

    trait_id: Annotated[str, Field(strict=True, pattern=r"^M[1-6]$")]
    text_ko: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    source_candidate_id: Sha256 | None
    included: bool


class PhotoJobTraitsResponse(StrictContract):
    """Review surface: model candidates and confirmed values, separated."""

    job_id: Sha256
    preference_profile_id: StableId
    state: PhotoJobPublicState
    candidates: Annotated[tuple[PhotoTraitCandidateView, ...], Field(max_length=6)]
    confirmed: Annotated[tuple[PhotoConfirmedTraitView, ...], Field(max_length=6)]


class PhotoJobConfirmRequest(StrictContract):
    """Explicit batch confirmation of reviewed trait values."""

    confirmations: Annotated[
        tuple[PhotoConfirmedTraitView, ...],
        Field(min_length=0, max_length=6),
    ]


class PhotoConfirmationReceiptView(StrictContract):
    """Minimized opaque receipt: identity plus bounded batch facts only."""

    receipt_id: Sha256
    batch_digest: Sha256
    included_count: Annotated[int, Field(strict=True, ge=0, le=6)]
    version: Annotated[int, Field(strict=True, ge=1, le=1)]


class PhotoJobConfirmedResponse(StrictContract):
    """Confirmation receipt returning the projected profile identity."""

    job_id: Sha256
    preference_profile_id: StableId
    state: PhotoJobPublicState
    confirmed: Annotated[tuple[PhotoConfirmedTraitView, ...], Field(max_length=6)]
    included_count: Annotated[int, Field(strict=True, ge=0)]
    receipt: PhotoConfirmationReceiptView | None = None


class PhotoJobDeletedResponse(StrictContract):
    """Deletion receipt carrying cleanup truth separately from state."""

    job_id: Sha256
    preference_profile_id: StableId
    state: PhotoJobPublicState
    cleanup_pending: bool


# ---------------------------------------------------------------------------
# Closed error mapping (no exception chaining, no sensitive reflection)
# ---------------------------------------------------------------------------

_PHOTO_ERROR_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    status.HTTP_400_BAD_REQUEST: {"model": PhotoErrorResponse},
    status.HTTP_401_UNAUTHORIZED: {"model": PhotoErrorResponse},
    status.HTTP_403_FORBIDDEN: {"model": PhotoErrorResponse},
    status.HTTP_404_NOT_FOUND: {"model": PhotoErrorResponse},
    status.HTTP_409_CONFLICT: {"model": PhotoErrorResponse},
    status.HTTP_412_PRECONDITION_FAILED: {"model": PhotoErrorResponse},
    status.HTTP_413_CONTENT_TOO_LARGE: {"model": PhotoErrorResponse},
    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {"model": PhotoErrorResponse},
    status.HTTP_422_UNPROCESSABLE_CONTENT: {"model": PhotoErrorResponse},
    status.HTTP_429_TOO_MANY_REQUESTS: {"model": PhotoErrorResponse},
    status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": PhotoErrorResponse},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"model": PhotoErrorResponse},
}


def _safe_public_job_id(job_id: object) -> str | None:
    if isinstance(job_id, str) and _HEX_JOB_ID.fullmatch(job_id) is not None:
        return job_id
    return None


def _raise_photo_error(
    *,
    status_code: int,
    code: str,
    message_ko: str,
    job_id: object = None,
    preference_profile_id: object = None,
    headers: dict[str, str] | None = None,
) -> NoReturn:
    principal = (
        preference_profile_id
        if isinstance(preference_profile_id, str) and preference_profile_id
        else None
    )
    detail = PhotoErrorDetail(
        code=code,
        message_ko=message_ko,
        job_id=_safe_public_job_id(job_id),
        preference_profile_id=principal,
    )
    raise HTTPException(
        status_code=status_code,
        detail=detail.model_dump(mode="json"),
        headers=headers,
    ) from None


def _photo_rejection_response(
    *,
    status_code: int,
    code: str,
    message_ko: str,
    job_id: object = None,
    preference_profile_id: object = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """One bounded flat rejection body for the raw streaming boundary.

    The upload handler returns rejections directly (never raises) so the
    closed public body — never an exception chain — crosses the boundary.
    """

    principal = (
        preference_profile_id
        if isinstance(preference_profile_id, str) and preference_profile_id
        else None
    )
    detail = PhotoErrorDetail(
        code=code,
        message_ko=message_ko,
        job_id=_safe_public_job_id(job_id),
        preference_profile_id=principal,
    )
    return JSONResponse(
        status_code=status_code,
        content=detail.model_dump(mode="json"),
        headers=headers or None,
    )


def _map_lifecycle_failure(
    error: Exception,
    *,
    job_id: object = None,
    preference_profile_id: object = None,
) -> NoReturn:
    """Map every lifecycle failure onto one closed public rejection."""

    if isinstance(error, PhotoRateLimitError):
        _raise_photo_error(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="PHOTO_RATE_LIMITED",
            message_ko="요청이 너무 많아요. 잠시 후 다시 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
            headers={"Retry-After": str(max(1, error.retry_after_seconds))},
        )
    if isinstance(error, PermissionError):
        _raise_photo_error(
            status_code=status.HTTP_403_FORBIDDEN,
            code="PHOTO_ACCESS_DENIED",
            message_ko="이 사진 작업에 접근할 수 없어요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoJobNotFound):
        _raise_photo_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="PHOTO_JOB_UNAVAILABLE",
            message_ko="사진 작업을 찾을 수 없거나 사용할 수 없어요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, QuarantineError):
        _map_quarantine_rejection(
            error,
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoUploadPreprocessingError):
        _raise_photo_error(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code="PHOTO_UPLOAD_PREPROCESSING_FAILED",
            message_ko="사진을 안전하게 정리하지 못했어요. 다른 사진으로 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, DeletionIncomplete):
        _raise_photo_error(
            status_code=status.HTTP_409_CONFLICT,
            code="PHOTO_CLEANUP_PENDING",
            message_ko="사진 정리가 아직 진행 중이에요. 잠시 후 상태를 확인해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoResourceBudgetError):
        _raise_photo_error(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="PHOTO_CAPACITY_UNAVAILABLE",
            message_ko="지금은 사진 분석 요청이 많아요. 잠시 후 다시 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
            headers={"Retry-After": str(max(1, error.retry_after_seconds))},
        )
    if isinstance(error, PhotoJobConflict):
        _raise_photo_error(
            status_code=status.HTTP_409_CONFLICT,
            code="PHOTO_JOB_CONFLICT",
            message_ko="사진 작업 요청이 충돌했어요. 잠시 후 다시 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoJobError):
        _raise_photo_error(
            status_code=status.HTTP_404_NOT_FOUND,
            code="PHOTO_JOB_UNAVAILABLE",
            message_ko="사진 작업을 찾을 수 없거나 사용할 수 없어요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoJobStoreError):
        _raise_photo_error(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="PHOTO_STORAGE_UNAVAILABLE",
            message_ko="사진 저장소에 일시적인 문제가 있어요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    _raise_photo_error(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="PHOTO_REQUEST_FAILED",
        message_ko="사진 요청을 처리하지 못했어요. 잠시 후 다시 시도해 주세요.",
        job_id=job_id,
        preference_profile_id=preference_profile_id,
    )


def _map_quarantine_rejection(
    error: QuarantineError,
    *,
    job_id: object = None,
    preference_profile_id: object = None,
) -> NoReturn:
    mapping: dict[str, tuple[int, str, str]] = {
        "QUARANTINE_SIZE_OVERFLOW": (
            status.HTTP_413_CONTENT_TOO_LARGE,
            "PHOTO_IMAGE_TOO_LARGE",
            "사진 파일이 너무 커요. 각 사진은 10MB 이하로 준비해 주세요.",
        ),
        "QUARANTINE_IMAGE_INDEX_REUSED": (
            status.HTTP_409_CONFLICT,
            "PHOTO_IMAGE_ALREADY_STORED",
            "이 번호의 사진은 이미 저장되었어요.",
        ),
        "QUARANTINE_JOB_BYTES_EXCEEDED": (
            status.HTTP_413_CONTENT_TOO_LARGE,
            "PHOTO_JOB_BYTES_EXHAUSTED",
            "사진 용량 한도를 초과했어요.",
        ),
        "QUARANTINE_DECLARED_LENGTH_MISMATCH": (
            status.HTTP_400_BAD_REQUEST,
            "PHOTO_UPLOAD_LENGTH_MISMATCH",
            "사진 전송이 완전하지 않아요. 다시 시도해 주세요.",
        ),
        "QUARANTINE_EMPTY_STREAM": (
            status.HTTP_400_BAD_REQUEST,
            "PHOTO_UPLOAD_LENGTH_MISMATCH",
            "사진 전송이 완전하지 않아요. 다시 시도해 주세요.",
        ),
        "QUARANTINE_DECLARED_LENGTH_REJECTED": (
            status.HTTP_400_BAD_REQUEST,
            "PHOTO_UPLOAD_LENGTH_INVALID",
            "사진 파일 크기 정보를 확인해 주세요.",
        ),
        "QUARANTINE_IMAGE_INDEX_OUT_OF_RANGE": (
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "PHOTO_IMAGE_INDEX_INVALID",
            "사진은 한 장에서 세 장까지만 추가할 수 있어요.",
        ),
    }
    status_code, code, message_ko = mapping.get(
        error.reason,
        (
            status.HTTP_400_BAD_REQUEST,
            "PHOTO_UPLOAD_REJECTED",
            "사진을 안전하게 저장하지 못했어요. 다시 시도해 주세요.",
        ),
    )
    _raise_photo_error(
        status_code=status_code,
        code=code,
        message_ko=message_ko,
        job_id=job_id,
        preference_profile_id=preference_profile_id,
    )


def _declared_content_length(request: Request) -> int:
    """Parse Content-Length as an early-rejection advisory (headers only)."""

    raw = request.headers.get("content-length")
    if raw is None:
        _raise_photo_error(
            status_code=status.HTTP_411_LENGTH_REQUIRED,
            code="PHOTO_UPLOAD_LENGTH_REQUIRED",
            message_ko="사진 파일 크기 정보가 필요해요.",
        )
    stripped = raw.strip()
    if not stripped.isdigit():
        _raise_photo_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PHOTO_UPLOAD_LENGTH_INVALID",
            message_ko="사진 파일 크기 정보를 확인해 주세요.",
        )
    value = int(stripped)
    if value <= 0:
        _raise_photo_error(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PHOTO_UPLOAD_LENGTH_INVALID",
            message_ko="사진 파일 크기 정보를 확인해 주세요.",
        )
    if value > _MAX_IMAGE_BYTES:
        _raise_photo_error(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            code="PHOTO_UPLOAD_TOO_LARGE",
            message_ko="사진 파일이 너무 커요. 각 사진은 10MB 이하로 준비해 주세요.",
        )
    return value


def _declared_length_or_reject(request: Request, job_id: str) -> int | JSONResponse:
    """Return-mode Content-Length advisory for the raw streaming boundary."""

    raw = request.headers.get("content-length")
    if raw is None:
        return _photo_rejection_response(
            status_code=status.HTTP_411_LENGTH_REQUIRED,
            code="PHOTO_UPLOAD_LENGTH_REQUIRED",
            message_ko="사진 파일 크기 정보가 필요해요.",
            job_id=job_id,
        )
    stripped = raw.strip()
    if not stripped.isdigit():
        return _photo_rejection_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PHOTO_UPLOAD_LENGTH_INVALID",
            message_ko="사진 파일 크기 정보를 확인해 주세요.",
            job_id=job_id,
        )
    value = int(stripped)
    if value <= 0:
        return _photo_rejection_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            code="PHOTO_UPLOAD_LENGTH_INVALID",
            message_ko="사진 파일 크기 정보를 확인해 주세요.",
            job_id=job_id,
        )
    if value > _MAX_IMAGE_BYTES:
        return _photo_rejection_response(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            code="PHOTO_UPLOAD_TOO_LARGE",
            message_ko="사진 파일이 너무 커요. 각 사진은 10MB 이하로 준비해 주세요.",
            job_id=job_id,
        )
    return value


def _declared_media_type(request: Request) -> str:
    raw = request.headers.get("content-type")
    if raw is None:
        _raise_photo_error(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            code="PHOTO_MEDIA_TYPE_REQUIRED",
            message_ko="사진 파일 형식 정보가 필요해요.",
        )
    media = raw.split(";")[0].strip().casefold()
    if media not in _ACCEPTED_MEDIA_TYPES:
        _raise_photo_error(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            code="PHOTO_MEDIA_TYPE_REJECTED",
            message_ko="JPEG, PNG, WEBP 사진만 추가할 수 있어요.",
        )
    return media


def _media_type_or_reject(request: Request, job_id: str) -> str | JSONResponse:
    """Return-mode media-type gate for the raw streaming boundary."""

    raw = request.headers.get("content-type")
    if raw is None:
        return _photo_rejection_response(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            code="PHOTO_MEDIA_TYPE_REQUIRED",
            message_ko="사진 파일 형식 정보가 필요해요.",
            job_id=job_id,
        )
    media = raw.split(";")[0].strip().casefold()
    if media not in _ACCEPTED_MEDIA_TYPES:
        return _photo_rejection_response(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            code="PHOTO_MEDIA_TYPE_REJECTED",
            message_ko="JPEG, PNG, WEBP 사진만 추가할 수 있어요.",
            job_id=job_id,
        )
    return media


def _upload_failure_response(
    error: Exception,
    *,
    job_id: object = None,
    preference_profile_id: object = None,
) -> JSONResponse:
    """Map one lifecycle failure to a bounded closed upload rejection."""

    if isinstance(error, PhotoRateLimitError):
        return _photo_rejection_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="PHOTO_RATE_LIMITED",
            message_ko="요청이 너무 많아요. 잠시 후 다시 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
            headers={"Retry-After": str(max(1, error.retry_after_seconds))},
        )
    if isinstance(error, PermissionError):
        return _photo_rejection_response(
            status_code=status.HTTP_403_FORBIDDEN,
            code="PHOTO_ACCESS_DENIED",
            message_ko="이 사진 작업에 접근할 수 없어요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoJobNotFound):
        return _photo_rejection_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="PHOTO_JOB_UNAVAILABLE",
            message_ko="사진 작업을 찾을 수 없거나 사용할 수 없어요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, QuarantineError):
        quarantine_mapping: dict[str, tuple[int, str, str]] = {
            "QUARANTINE_SIZE_OVERFLOW": (
                status.HTTP_413_CONTENT_TOO_LARGE,
                "PHOTO_IMAGE_TOO_LARGE",
                "사진 파일이 너무 커요. 각 사진은 10MB 이하로 준비해 주세요.",
            ),
            "QUARANTINE_IMAGE_INDEX_REUSED": (
                status.HTTP_409_CONFLICT,
                "PHOTO_IMAGE_ALREADY_STORED",
                "이 번호의 사진은 이미 저장되었어요.",
            ),
            "QUARANTINE_JOB_BYTES_EXCEEDED": (
                status.HTTP_413_CONTENT_TOO_LARGE,
                "PHOTO_JOB_BYTES_EXHAUSTED",
                "사진 용량 한도를 초과했어요.",
            ),
            "QUARANTINE_DECLARED_LENGTH_MISMATCH": (
                status.HTTP_400_BAD_REQUEST,
                "PHOTO_UPLOAD_LENGTH_MISMATCH",
                "사진 전송이 완전하지 않아요. 다시 시도해 주세요.",
            ),
            "QUARANTINE_EMPTY_STREAM": (
                status.HTTP_400_BAD_REQUEST,
                "PHOTO_UPLOAD_LENGTH_MISMATCH",
                "사진 전송이 완전하지 않아요. 다시 시도해 주세요.",
            ),
        }
        status_code, code, message_ko = quarantine_mapping.get(
            error.reason,
            (
                status.HTTP_400_BAD_REQUEST,
                "PHOTO_UPLOAD_REJECTED",
                "사진을 안전하게 저장하지 못했어요. 다시 시도해 주세요.",
            ),
        )
        return _photo_rejection_response(
            status_code=status_code,
            code=code,
            message_ko=message_ko,
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoUploadPreprocessingError):
        return _photo_rejection_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code="PHOTO_UPLOAD_PREPROCESSING_FAILED",
            message_ko="사진을 안전하게 정리하지 못했어요. 다른 사진으로 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
        )
    if isinstance(error, PhotoResourceBudgetError):
        return _photo_rejection_response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="PHOTO_CAPACITY_UNAVAILABLE",
            message_ko="지금은 사진 분석 요청이 많아요. 잠시 후 다시 시도해 주세요.",
            job_id=job_id,
            preference_profile_id=preference_profile_id,
            headers={"Retry-After": str(max(1, error.retry_after_seconds))},
        )
    return _photo_rejection_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="PHOTO_REQUEST_FAILED",
        message_ko="사진 요청을 처리하지 못했어요. 잠시 후 다시 시도해 주세요.",
        job_id=job_id,
        preference_profile_id=preference_profile_id,
    )


# ---------------------------------------------------------------------------
# Lifecycle gateway: ownership, consent, budgets, quarantine, synthetic only
# ---------------------------------------------------------------------------


PHOTO_PROTECTED_RELATIONS: Final[tuple[str, ...]] = (
    "photo_jobs",
    "photo_job_dispatch_markers",
    "photo_trait_candidates",
    "photo_confirmed_traits",
    "photo_deletion_ledger",
    "photo_review_drafts",
    "photo_confirmation_receipts",
    "photo_job_filesystem_bindings",
    "photo_job_image_slots",
)


def verify_photo_relation_acl_closure(connection: object) -> None:
    """Every protected Phase6 relation exposes raw ACL entries to exactly
    its owner — no service/runtime/builder/PUBLIC/unexpected grantee."""

    execute = connection.execute  # type: ignore[attr-defined]
    leaked = execute(
        "SELECT c.relname, pg_catalog.pg_get_userbyid(a.grantee), a.privilege_type "
        "FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "CROSS JOIN LATERAL pg_catalog.aclexplode("
        "COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a "
        "WHERE n.nspname='dev_eval' AND c.relname=ANY(%s) "
        "AND a.grantee <> c.relowner "
        "AND (a.grantee, a.privilege_type) NOT IN ("
        "SELECT c2.relowner, 'REFERENCES' FROM pg_catalog.pg_class c2 "
        "WHERE false)",
        (list(PHOTO_PROTECTED_RELATIONS),),
    ).fetchone()
    if leaked is not None:
        raise RuntimeError("photo service authority rejected: raw relation ACL grantee leak")
    owners = execute(
        "SELECT count(*) FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_catalog.pg_roles r ON r.oid=c.relowner "
        "WHERE n.nspname='dev_eval' AND c.relname=ANY(%s) "
        "AND r.rolname=%s",
        (list(PHOTO_PROTECTED_RELATIONS), PHOTO_WRITE_AUTHORITY_ROLE),
    ).fetchone()
    if owners != (len(PHOTO_PROTECTED_RELATIONS),):
        raise RuntimeError("photo service authority rejected: protected relation ownership broken")
    unexpected_usage = execute(
        "SELECT a.grantee FROM pg_catalog.pg_namespace n "
        "CROSS JOIN LATERAL pg_catalog.aclexplode("
        "COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))) a "
        "WHERE n.nspname='dev_eval' "
        "AND a.privilege_type='USAGE' "
        "AND a.grantee <> (SELECT oid FROM pg_catalog.pg_roles "
        "WHERE rolname=%s) "
        "AND a.grantee <> (SELECT oid FROM pg_catalog.pg_roles "
        "WHERE rolname=%s) "
        "AND a.grantee <> (SELECT oid FROM pg_catalog.pg_roles "
        "WHERE rolname=%s) "
        "AND a.grantee <> (SELECT oid FROM pg_catalog.pg_roles "
        "WHERE rolname=%s) "
        "AND a.grantee <> 0",
        (
            PHOTO_WRITE_AUTHORITY_ROLE,
            PHOTO_AUTHORITY_SERVICE_ROLE,
            "itda_migrator",
            "postgres",
        ),
    ).fetchall()
    if unexpected_usage:
        raise RuntimeError("photo service authority rejected: unexpected schema USAGE grantee")


def verify_photo_service_execute_surface(
    connection: object,
    *,
    allowed_procedures: tuple[str, ...],
    owner_only_procedures: tuple[str, ...],
) -> None:
    execute = connection.execute  # type: ignore[attr-defined]
    forbidden_execute = execute(
        "SELECT count(*) FROM unnest(CAST(%s AS pg_catalog.regprocedure[])) p(oid) "
        "WHERE has_function_privilege(current_user, p.oid, 'EXECUTE')",
        (list(owner_only_procedures),),
    ).fetchone()
    if forbidden_execute != (0,):
        raise RuntimeError("photo service authority rejected: owner-only EXECUTE leaked")
    unexpected = execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='dev_eval' "
        "AND has_function_privilege(current_user, p.oid, 'EXECUTE') "
        "AND p.oid <> ALL(CAST(%s AS pg_catalog.regprocedure[]))",
        (list(allowed_procedures),),
    ).fetchone()
    if unexpected != (0,):
        raise RuntimeError("photo service authority rejected: unexpected EXECUTE grant")
    unexpected_catalog = execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='dev_eval' AND p.proname ~ '(^|_)photo_' "
        "AND p.oid <> ALL(CAST(%s AS pg_catalog.regprocedure[]))",
        (list((*allowed_procedures, *owner_only_procedures)),),
    ).fetchone()
    if unexpected_catalog != (0,):
        raise RuntimeError("photo service authority rejected: unexpected photo function")
    verify_photo_relation_acl_closure(connection)


class PhotoLifecycleGateway:
    """Server-owned composition of the photo lifecycle services.

    One instance per process (cached per DSN + quarantine root): request
    windows and resource budgets are process-local by design, while durable
    job truth stays in PostgreSQL and streamed bytes land only in quarantine.
    """

    def __init__(
        self,
        *,
        factory: Any,
        service_dsn: str,
        quarantine_root: FilePath,
        runtime_role: str,
        builder_role: str,
    ) -> None:
        self._factory = factory
        self._service_dsn = service_dsn
        self._quarantine_root = quarantine_root
        self._runtime_role = runtime_role
        self._builder_role = builder_role
        self._limiter = PhotoRateLimiter(policy=PhotoRateLimitPolicy(), clock=time.monotonic)
        self._budget = PhotoResourceBudget()
        self._provider = SyntheticPhotoAnalysisProvider()
        self._job_store = PhotoJobStore(factory)
        self._candidate_store = PhotoTraitCandidateStore(factory)
        self._confirmed_store = PhotoConfirmedTraitStore(factory)
        self._draft_store = PhotoReviewDraftStore(factory)
        self._job_service = PhotoJobService(factory)
        self._policies: dict[str, QuarantinePolicy] = {}
        self._stored: dict[str, dict[int, tuple[str, str]]] = {}
        self._reservations: dict[str, Any] = {}
        self._authority_verified = False

    # -- startup authority verification ----------------------------------

    _REQUIRED_FUNCTIONS: Final[tuple[str, ...]] = (
        "create_photo_job_v3(text,text,text)",
        "claim_photo_job_filesystem_binding_v3(text,text)",
        "read_photo_job_filesystem_binding_v3(text,text)",
        "lock_photo_job_operation_v3(text,text,text)",
        "list_photo_cleanup_candidates_v3()",
        "transition_photo_job_nonterminal_v3(text,text,text,text,timestamptz)",
        "append_photo_deletion_ledger_v3(text,text,text,text,text,integer,text)",
        "finalize_photo_job_terminal_v3(text,text,text,text,text,text,text,text)",
        "finalize_photo_job_unbound_explicit_deletion_v3(text,text)",
        "record_photo_dispatch_marker_v3(text,text,integer,text)",
        "record_photo_candidate_batch_v3(text,text,text[],text[],text[],text[])",
        "annotate_photo_candidate_v3(text,text,text,text,boolean)",
        "save_photo_review_draft_v3(text,text,text,text[],text[],text[],boolean[])",
        "discard_photo_review_draft_v3(text,text)",
        "confirm_photo_traits_v3(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
        "list_photo_deletion_ledger_v3(text,text)",
        "read_photo_cleanup_status_v3(text,text)",
        "complete_photo_filesystem_cleanup_v3(text,text,text,text)",
        "pending_photo_filesystem_release_v3(text,text,text,text)",
        "read_photo_filesystem_release_v3(text,text)",
        "reserve_photo_image_slot_v3(text,text,integer,text,text)",
        "commit_photo_image_slot_v3(text,text,integer,text,integer)",
        "read_photo_image_slots_v3(text,text)",
        "read_photo_job_v2(text,text)",
        "list_photo_candidates_v2(text,text)",
        "list_photo_confirmed_traits_v2(text,text)",
        "list_photo_dispatch_markers_v2(text,text)",
        "read_photo_review_draft_v2(text,text)",
        "read_photo_confirmation_receipt_v2(text,text,text)",
        "read_photo_recommendation_projection_v1(text,text)",
    )

    def verify_service_authority(self) -> None:
        """Connect once and prove the exact photo service authority.

        Fail closed before serving when the DSN's session identity, role
        flags, membership closure, schema/default privileges, or the v2
        EXECUTE allowlist do not match the exclusive authority topology
        migration 0020 froze.
        """

        if self._authority_verified:
            return
        import psycopg

        with psycopg.connect(self._service_dsn, connect_timeout=10) as connection:
            identity = connection.execute("SELECT session_user, current_user").fetchone()
            if identity != (PHOTO_AUTHORITY_SERVICE_ROLE, PHOTO_AUTHORITY_SERVICE_ROLE):
                raise RuntimeError(
                    "photo service authority rejected: DSN identity is not the "
                    "fixed photo service principal"
                )
            topology = connection.execute(
                "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
                "rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_catalog.pg_roles WHERE rolname = %s",
                (PHOTO_AUTHORITY_SERVICE_ROLE,),
            ).fetchone()
            if topology != (True, False, False, False, False, False, False):
                raise RuntimeError("photo service authority rejected: unsafe role flags")
            owner_topology = connection.execute(
                "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
                "rolcreaterole, rolreplication, rolbypassrls "
                "FROM pg_catalog.pg_roles WHERE rolname = %s",
                (PHOTO_WRITE_AUTHORITY_ROLE,),
            ).fetchone()
            if owner_topology != (False, False, False, False, False, False, False):
                raise RuntimeError("photo service authority rejected: unsafe owner flags")
            roles = (
                PHOTO_WRITE_AUTHORITY_ROLE,
                PHOTO_AUTHORITY_SERVICE_ROLE,
                self._runtime_role,
                self._builder_role,
            )
            pairs = tuple(
                (member, granted) for member in roles for granted in roles if member != granted
            )
            related = connection.execute(
                "SELECT count(*) FROM unnest(%s::text[], %s::text[]) "
                "AS pair(member, granted) "
                "WHERE pg_catalog.pg_has_role(pair.member, pair.granted, 'MEMBER')",
                (
                    [member for member, _granted in pairs],
                    [granted for _member, granted in pairs],
                ),
            ).fetchone()
            if related != (0,):
                raise RuntimeError("photo service authority rejected: membership closure violated")
            required_relations = (
                "photo_jobs",
                "photo_job_dispatch_markers",
                "photo_trait_candidates",
                "photo_confirmed_traits",
                "photo_deletion_ledger",
                "photo_review_drafts",
                "photo_confirmation_receipts",
                "photo_job_filesystem_bindings",
                "photo_job_image_slots",
            )
            owner = connection.execute(
                "SELECT count(*) FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_catalog.pg_roles r ON r.oid=c.relowner "
                "WHERE n.nspname='dev_eval' AND c.relname=ANY(%s) "
                "AND r.rolname=%s",
                (list(required_relations), PHOTO_WRITE_AUTHORITY_ROLE),
            ).fetchone()
            if owner != (len(required_relations),):
                raise RuntimeError("photo service authority rejected: lifecycle ownership broken")
            if not connection.execute(
                "SELECT has_schema_privilege(current_user, 'dev_eval', 'USAGE'), "
                "NOT has_schema_privilege(current_user, 'dev_eval', 'CREATE')"
            ).fetchone() == (True, True):
                raise RuntimeError("photo service authority rejected: schema authority mismatch")
            allowed_procedures = tuple(
                f"dev_eval.{signature}" for signature in self._REQUIRED_FUNCTIONS
            )
            for signature in self._REQUIRED_FUNCTIONS:
                granted = connection.execute(
                    "SELECT has_function_privilege(current_user, %s, 'EXECUTE')",
                    (f"dev_eval.{signature}",),
                ).fetchone()
                if granted != (True,):
                    raise RuntimeError("photo service authority rejected: EXECUTE allowlist broken")
            allowed_acl = connection.execute(
                "SELECT count(*) FILTER (WHERE a.grantee=(SELECT oid FROM "
                "pg_catalog.pg_roles WHERE rolname=%s) "
                "AND a.privilege_type='EXECUTE' AND a.grantor=p.proowner "
                "AND NOT a.is_grantable), "
                "count(*) FILTER (WHERE NOT (a.grantee=(SELECT oid FROM "
                "pg_catalog.pg_roles WHERE rolname=%s) "
                "AND a.privilege_type='EXECUTE' AND a.grantor=p.proowner "
                "AND NOT a.is_grantable)) "
                "FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode("
                "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a "
                "WHERE n.nspname='dev_eval' "
                "AND p.oid=ANY(CAST(%s AS pg_catalog.regprocedure[]))",
                (
                    PHOTO_AUTHORITY_SERVICE_ROLE,
                    PHOTO_AUTHORITY_SERVICE_ROLE,
                    list(allowed_procedures),
                ),
            ).fetchone()
            if allowed_acl != (len(allowed_procedures), 0):
                raise RuntimeError("photo service authority rejected: EXECUTE ACL mismatch")
            owner_only_procedures = (
                "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz)",
                "dev_eval.claim_photo_job_v1(text,timestamptz)",
                "dev_eval.record_photo_dispatch_marker_v1(text,integer,text)",
                "dev_eval.create_photo_job_v2(text,text,text)",
                "dev_eval.transition_photo_job_status_v2(text,text,text,text,text,timestamptz)",
                "dev_eval.claim_photo_job_v2(text,text,timestamptz)",
                "dev_eval.record_photo_dispatch_marker_v2(text,text,integer,text)",
                "dev_eval.record_photo_candidate_batch_v2(text,text,text[],text[],text[],text[])",
                "dev_eval.annotate_photo_candidate_v2(text,text,text,text,boolean)",
                "dev_eval.append_photo_deletion_ledger_v2(text,text,text,text,text)",
                "dev_eval.save_photo_review_draft_v2(text,text,text,text[],text[],text[],boolean[])",
                "dev_eval.discard_photo_review_draft_v2(text,text)",
                "dev_eval.confirm_photo_traits_v2(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
                "dev_eval.list_reconcile_photo_jobs_v2()",
                "dev_eval.list_photo_deletion_ledger_v2(text,text)",
            )
            verify_photo_service_execute_surface(
                connection,
                allowed_procedures=allowed_procedures,
                owner_only_procedures=owner_only_procedures,
            )
            for forbidden_table in (
                "dev_eval.photo_jobs",
                "dev_eval.photo_job_dispatch_markers",
                "dev_eval.photo_trait_candidates",
                "dev_eval.photo_confirmed_traits",
                "dev_eval.photo_deletion_ledger",
                "dev_eval.photo_review_drafts",
                "dev_eval.photo_confirmation_receipts",
                "dev_eval.photo_job_filesystem_bindings",
                "dev_eval.photo_job_image_slots",
            ):
                leaked = connection.execute(
                    "SELECT has_table_privilege(current_user, %s, 'SELECT'), "
                    "has_table_privilege(current_user, %s, 'INSERT'), "
                    "has_table_privilege(current_user, %s, 'UPDATE'), "
                    "has_table_privilege(current_user, %s, 'DELETE'), "
                    "has_table_privilege(current_user, %s, 'TRUNCATE')",
                    (
                        forbidden_table,
                        forbidden_table,
                        forbidden_table,
                        forbidden_table,
                        forbidden_table,
                    ),
                ).fetchone()
                if leaked is None or any(bool(value) for value in leaked):
                    raise RuntimeError(
                        "photo service authority rejected: direct table access survives"
                    )
        self._authority_verified = True

    # -- shared helpers -----------------------------------------------------

    def _acquire(self, action: str, profile_id: str) -> None:
        self._limiter.acquire(action=action, identity=profile_id, now=time.monotonic())

    @staticmethod
    def _require_hex_job_id(job_id: str) -> str:
        if _HEX_JOB_ID.fullmatch(job_id) is None:
            raise PhotoJobError("photo job is not available")
        return job_id

    def _read_owned(self, *, job_id: str, profile_id: str) -> dict[str, object]:
        self._require_hex_job_id(job_id)
        return self._job_service.read_own_job(job_id=job_id, profile_id=profile_id)

    # -- lifecycle operations -----------------------------------------------

    def create_job(
        self, *, profile_id: str, consent_version: str, consent_accepted: bool
    ) -> dict[str, object]:
        self._acquire("job_create", profile_id)
        if not consent_accepted:
            _raise_photo_error(
                status_code=status.HTTP_403_FORBIDDEN,
                code="PHOTO_CONSENT_REQUIRED",
                message_ko="사진 분석 안내에 동의한 뒤에 시작할 수 있어요.",
                preference_profile_id=profile_id,
            )
        if consent_version != CURRENT_PHOTO_CONSENT_NOTICE.consent_version:
            _raise_photo_error(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                code="PHOTO_CONSENT_VERSION_MISMATCH",
                message_ko="최신 사진 분석 안내에 다시 동의해 주세요.",
                preference_profile_id=profile_id,
            )
        reservation = self._budget.reserve_job(identity=profile_id, now=time.monotonic())
        try:
            job_id = self._job_service.create_job(profile_id=profile_id)
        except Exception:
            self._budget.release(reservation)
            raise
        self._reservations[job_id] = reservation
        return {
            "job_id": job_id,
            "state": "queued",
            "consent_version": CURRENT_PHOTO_CONSENT_NOTICE.consent_version,
        }

    def authorize_image_upload(self, *, job_id: str, profile_id: str, image_index: int) -> str:
        """Ownership and state gate that precedes any stream iteration."""

        row = self._read_owned(job_id=job_id, profile_id=profile_id)
        if row["state"] != "queued":
            raise PhotoJobError("photo job no longer accepts image uploads")
        return job_id

    async def store_image_stream(
        self,
        *,
        job_id: str,
        job_directory: str,
        profile_id: str,
        image_index: int,
        chunks: Any,
        declared_byte_length: int,
        media_type: str,
    ) -> tuple[str, int]:
        """Rate-limited, budget-bounded streamed store into quarantine.

        The exactly-once image-index authority is the durable slot row: the
        reservation is committed before the first body byte is consumed, so a
        crash, cancellation, or lost response can never produce a second
        generated file for the same index. A ``stored`` slot replays its
        durable receipt instead of consuming the stream again.
        """

        self._require_hex_job_id(job_id)
        if job_directory != job_id:
            raise PhotoJobError("photo job directory identity mismatched")
        self._acquire("image_put", profile_id)
        policy = self._policies.setdefault(job_id, QuarantinePolicy())
        connection = psycopg.connect(self._service_dsn, autocommit=True)
        reservation: Any = None
        root_fd: int | None = None
        advisory_locked = False
        try:
            reservation = self._budget.reserve_bytes(declared_byte_length)
            root_fd = open_quarantine_root(self._quarantine_root)
            connection.execute(
                "SELECT pg_catalog.pg_advisory_lock("
                "pg_catalog.hashtextextended('photo-fs-v1|' || %s, 0))",
                (job_id,),
            )
            advisory_locked = True
            with connection.transaction():
                connection.execute(
                    "SELECT * FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'upload')",
                    (job_id, profile_id),
                ).fetchone()
                claimed = connection.execute(
                    "SELECT dev_eval.claim_photo_job_filesystem_binding_v3(%s, %s)",
                    (job_id, profile_id),
                ).fetchone()
                if claimed is None:
                    raise QuarantineError(
                        "QUARANTINE_JOB_DIRECTORY_REJECTED",
                        "quarantine database binding claim failed",
                    )
                claimed_created = bool(claimed[0])
                slot = connection.execute(
                    "SELECT * FROM dev_eval.reserve_photo_image_slot_v3(%s, %s, %s, %s, %s)",
                    (job_id, profile_id, image_index, uuid.uuid4().hex, media_type),
                ).fetchone()
                if slot is None:
                    raise QuarantineError(
                        "QUARANTINE_IMAGE_INDEX_REUSED",
                        "quarantine slot authority rejected the reservation",
                    )
                slot_state = str(slot[0])
                stored_name = str(slot[1])
                newly_reserved = bool(slot[4])
                if slot_state == "stored":
                    stored_map = self._stored.setdefault(job_id, {})
                    stored_map[image_index] = (stored_name, media_type)
                    return stored_name, int(slot[2])
            policy.used_image_indexes.discard(image_index)
            stored = await stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=image_index,
                chunks=chunks,
                policy=policy,
                binding_claim_created=claimed_created,
                declared_byte_length=declared_byte_length,
                expected_stored_name=stored_name,
                resume_reserved=not newly_reserved,
                materialize_reserved_missing=(slot_state == "reserved" and not newly_reserved),
            )
            connection.execute(
                "SELECT dev_eval.commit_photo_image_slot_v3(%s, %s, %s, %s, %s)",
                (
                    job_id,
                    profile_id,
                    image_index,
                    stored.stored_name,
                    stored.byte_length,
                ),
            )
        finally:
            if advisory_locked:
                with suppress(psycopg.Error):
                    connection.execute(
                        "SELECT pg_catalog.pg_advisory_unlock("
                        "pg_catalog.hashtextextended('photo-fs-v1|' || %s, 0))",
                        (job_id,),
                    )
            connection.close()
            if root_fd is not None:
                os.close(root_fd)
            if reservation is not None:
                self._budget.release(reservation)
        stored_map = self._stored.setdefault(job_id, {})
        stored_map[image_index] = (stored.stored_name, media_type)
        return stored.stored_name, stored.byte_length

    def read_job_state(self, *, job_id: str, profile_id: str) -> dict[str, object]:
        """Project the durable job row plus durable cleanup evidence.

        ``cleanup_pending`` is derived per read from exact v3 proof truth:
        a terminal job is cleanup-complete only when exactly one current-cause
        v3 zero-residue ledger row exists. No process memory participates.
        """

        self._acquire("poll", profile_id)
        row = self._read_owned(job_id=job_id, profile_id=profile_id)
        state = str(row["state"])
        cause = row["terminal_cause"]
        with psycopg.connect(self._service_dsn, autocommit=True) as connection:
            cleanup = connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s, %s)",
                (job_id, profile_id),
            ).fetchone()
            cleanup_pending = cleanup is None or bool(cleanup[0])
        return {
            "state": state,
            "terminal_cause": cause,
            "cleanup_pending": cleanup_pending,
        }

    def _durable_slot_inventory(
        self, connection: Any, *, job_id: str, profile_id: str
    ) -> dict[int, tuple[str, int, str]]:
        """The durable slot truth for one job."""

        rows = connection.execute(
            "SELECT * FROM dev_eval.read_photo_image_slots_v3(%s, %s)",
            (job_id, profile_id),
        ).fetchall()
        inventory: dict[int, tuple[str, int, str]] = {}
        for row in rows:
            if str(row[1]) != "stored":
                return {}
            inventory[int(row[0])] = (str(row[2]), int(row[3]), str(row[4]))
        return inventory

    def _durable_inventory_drift(self, connection: Any, *, job_id: str, profile_id: str) -> bool:
        """Fail closed when durable slots and quarantine contents disagree."""

        inventory = self._durable_slot_inventory(connection, job_id=job_id, profile_id=profile_id)
        if not inventory:
            return True
        on_disk = set(
            list_generated_entry_names(
                quarantine_root=self._quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
            )
        )
        return on_disk != {name for name, _length, _media_type in inventory.values()}

    def _record_dispatch_marker(
        self,
        job_id: str,
        profile_id: str,
        marker: str,
        *,
        connection: Any = None,
    ) -> None:
        """Record one create-only dispatch marker on the given connection.

        With ``connection`` the marker joins the caller's open transaction
        (stage A); without it the marker is durably committed on a fresh
        autocommit connection (stage B send boundary).
        """

        if connection is not None:
            connection.execute(
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, %s, %s)",
                (job_id, profile_id, 1, marker),
            )
            return
        with psycopg.connect(self._service_dsn, autocommit=True) as marker_connection:
            marker_connection.execute(
                "SELECT dev_eval.record_photo_dispatch_marker_v3(%s, %s, %s, %s)",
                (job_id, profile_id, 1, marker),
            )

    def submit_job(
        self,
        *,
        job_id: str,
        profile_id: str,
        boundary_hook: Any = None,
    ) -> dict[str, object]:
        """Three-stage durable submit: markers commit, send boundary commits,
        provider runs transaction-free, then a fresh locked saga finalizes.

        Stage A (one transaction): operation lock → durable slot inventory
        validation → queued→running → ``reserved``/``prepared`` markers →
        COMMIT. A crash here rolls the whole saga back to queued with no
        marker truth, so restart treats the row as never dispatched.
        Stage B (autocommit): ``send_boundary`` marker durably committed
        immediately before the provider call. A crash after this point
        leaves running+markers as the durable fact of an uncertain send.
        Stage C: the provider runs OUTSIDE any database transaction; a new
        transaction then re-takes the advisory+row lock, requires running
        plus the exact marker prefix, records candidate batches, and runs
        the terminal saga for every outcome.

        ``boundary_hook`` is a test seam mirroring the deletion module's
        injection points: called with ``"after_stage_a_commit"`` and
        ``"after_send_boundary"`` so crash regressions can hard-exit at the
        exact durable boundaries.
        """

        def _hook(boundary: str) -> None:
            if boundary_hook is not None:
                boundary_hook(boundary)

        self._acquire("poll", profile_id)
        self._require_hex_job_id(job_id)
        from_status = "queued"
        with psycopg.connect(self._service_dsn, autocommit=True) as connection:
            validation_outcome: Any = None
            with connection.transaction():
                locked = connection.execute(
                    "SELECT status FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'analysis')",
                    (job_id, profile_id),
                ).fetchone()
                if locked is None or locked[0] != "queued":
                    raise PhotoJobError("photo job is not available")
                if self._durable_inventory_drift(connection, job_id=job_id, profile_id=profile_id):
                    validation_outcome = execute_terminal_deletion(
                        connection,
                        quarantine_root=self._quarantine_root,
                        job_id=job_id,
                        profile_id=profile_id,
                        cause="validation_failure",
                        reason_code="PHOTO_VALIDATION_FAILURE",
                        from_status="queued",
                        to_status="failed",
                    )
            if validation_outcome is not None:
                release_filesystem_cleanup(
                    connection,
                    quarantine_root=self._quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    operation_key=str(validation_outcome.operation_key),
                    proof_digest=str(validation_outcome.proof_digest),
                )
                raise PhotoJobError("photo analysis failed closed")
            with connection.transaction():
                connection.execute(
                    "SELECT dev_eval.transition_photo_job_nonterminal_v3"
                    "(%s, %s, 'queued', 'running', now() + interval '5 minutes')",
                    (job_id, profile_id),
                )
                for marker in ("reserved", "prepared"):
                    self._record_dispatch_marker(job_id, profile_id, marker, connection=connection)
            _hook("after_stage_a_commit")
            # Stage B: the durable send boundary. The synthetic provider
            # constructs no client, so client_constructed is never claimed.
            self._record_dispatch_marker(job_id, profile_id, "send_boundary")
            _hook("after_send_boundary")
            # Stage C: provider work runs outside the transaction.
            candidate_batches: list[list[dict[str, object]]]
            failure: tuple[str, str] | None
            try:
                candidate_batches = self._analyze_stored_images(
                    job_id=job_id, profile_id=profile_id
                )
            except TimeoutError:
                failure = ("timeout", "PHOTO_TIMEOUT")
            except PhotoUploadPreprocessingError:
                failure = ("validation_failure", "PHOTO_VALIDATION_FAILURE")
            except (QuarantineError, ValueError, TypeError):
                failure = ("rejection", "PHOTO_REJECTION")
            except Exception:  # noqa: BLE001 - closed provider failure category
                failure = ("provider_error", "PHOTO_PROVIDER_ERROR")
            else:
                failure = None
            from_status = "running"
            cause, reason = failure or ("success", "PHOTO_SUCCESS")
            with connection.transaction():
                locked = connection.execute(
                    "SELECT status FROM dev_eval.lock_photo_job_operation_v3(%s, %s, 'analysis')",
                    (job_id, profile_id),
                ).fetchone()
                if locked is None or locked[0] != "running":
                    raise PhotoJobError("photo job is not available")
                markers = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT marker FROM dev_eval.list_photo_dispatch_markers_v2(%s, %s)",
                        (job_id, profile_id),
                    ).fetchall()
                }
                if not {"reserved", "prepared", "send_boundary"} <= markers:
                    raise PhotoJobError("photo job is not available")
                if failure is None:
                    for candidate_batch in candidate_batches:
                        connection.execute(
                            "SELECT dev_eval.record_photo_candidate_batch_v3"
                            "(%s, %s, %s, %s, %s, %s)",
                            (
                                job_id,
                                profile_id,
                                [str(row["candidate_id"]) for row in candidate_batch],
                                [str(row["trait_id"]) for row in candidate_batch],
                                [str(row["text_ko"]) for row in candidate_batch],
                                [str(row["candidate_set_sha256"]) for row in candidate_batch],
                            ),
                        )
                outcome = execute_terminal_deletion(
                    connection,
                    quarantine_root=self._quarantine_root,
                    job_id=job_id,
                    profile_id=profile_id,
                    cause=cause,
                    reason_code=reason,
                    from_status=from_status,
                    to_status="succeeded" if failure is None else "failed",
                )
            release_filesystem_cleanup(
                connection,
                quarantine_root=self._quarantine_root,
                job_id=job_id,
                profile_id=profile_id,
                operation_key=str(outcome.operation_key),
                proof_digest=str(outcome.proof_digest),
            )
        self._release_job_bookkeeping(job_id)
        if failure is not None:
            raise PhotoJobError("photo analysis failed closed")
        return {"state": "succeeded"}

    def _analyze_stored_images(
        self, *, job_id: str, profile_id: str
    ) -> list[list[dict[str, object]]]:
        """One bounded 1..6 candidate batch per analyzed image.

        Runs outside any database transaction: the durable slot inventory is
        read on a separate short-lived connection, provider calls hold no
        locks, and every outcome re-enters through the locked stage-C saga.
        """

        with psycopg.connect(self._service_dsn, autocommit=True) as inventory_connection:
            inventory = self._durable_slot_inventory(
                inventory_connection, job_id=job_id, profile_id=profile_id
            )
        job_directory = job_id
        batches: list[list[dict[str, object]]] = []
        root_fd = open_quarantine_root(self._quarantine_root)
        try:
            for image_index in sorted(inventory):
                stored_name, _slot_length, media_type = inventory[image_index]
                sanitized = self._sanitized_bytes(
                    root_fd=root_fd,
                    job_directory=job_directory,
                    stored_name=stored_name,
                    profile_id=profile_id,
                    media_type=media_type,
                )
                candidate_set = self._provider.analyze(
                    image_png=sanitized,
                    rubric_ko=_PUBLIC_RUBRIC_KO,
                    job_id=job_id,
                )
                batches.append(
                    [
                        {
                            "candidate_id": candidate.candidate_id,
                            "trait_id": candidate.trait_id,
                            "text_ko": candidate.text_ko,
                            "candidate_set_sha256": candidate_set.candidate_set_sha256,
                        }
                        for candidate in candidate_set.candidates
                    ]
                )
        finally:
            os.close(root_fd)
        return batches

    def _sanitized_bytes(
        self,
        *,
        root_fd: int,
        job_directory: str,
        profile_id: str,
        stored_name: str,
        media_type: str,
    ) -> bytes:
        with open_quarantined_image(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            stored_name=stored_name,
        ) as handle:
            payload = bytearray()
            while True:
                piece = os.read(handle.descriptor, _READ_CHUNK_BYTES)
                if not piece:
                    break
                if len(payload) + len(piece) > _MAX_IMAGE_BYTES:
                    raise QuarantineError(
                        "QUARANTINE_SIZE_OVERFLOW",
                        "stored bytes exceeded the bounded image cap",
                    )
                payload.extend(piece)
        result = preprocess_quarantined_image(
            payload=payload,
            stored_name=stored_name,
            declared_media_type=media_type,
        )
        return result.encoded_bytes

    def _release_job_bookkeeping(self, job_id: str) -> None:
        """Release process-local reservations after coordinator proof succeeds."""

        self._stored.pop(job_id, None)
        self._policies.pop(job_id, None)
        reservation = self._reservations.pop(job_id, None)
        if reservation is not None:
            self._budget.release(reservation)

    def read_traits(self, *, job_id: str, profile_id: str) -> dict[str, object]:
        self._acquire("poll", profile_id)
        row = self._read_owned(job_id=job_id, profile_id=profile_id)
        candidates = self._candidate_store.list_for_job(job_id, profile_id)
        confirmed = self._confirmed_store.list_for_job(job_id, profile_id)
        return {
            "state": row["state"],
            "candidates": candidates,
            "confirmed": confirmed,
        }

    def confirm_traits(
        self, *, job_id: str, profile_id: str, confirmations: tuple[PhotoConfirmedTraitView, ...]
    ) -> dict[str, object]:
        """Server draft save → atomic confirm, both under exact ownership.

        The submitted batch first persists as the owned review draft, then
        the database confirm function verifies that draft row-by-row against
        the real candidates before any confirmation exists.
        """

        self._acquire("poll", profile_id)
        row = self._read_owned(job_id=job_id, profile_id=profile_id)
        if row["state"] != "succeeded":
            raise PhotoJobError("photo job is not available")
        candidate_rows = self._candidate_store.list_for_job(job_id, profile_id)
        candidates_by_id = {candidate.candidate_id: candidate for candidate in candidate_rows}
        batch: list[dict[str, object]] = []
        entries: list[ReviewDraftEntry] = []
        for entry in confirmations:
            # Product inputs are candidate-derived: every submitted row must
            # name its real source candidate of this exact owned job. NULL
            # provenance cannot be verified against the candidate rows and
            # is rejected before any write.
            if entry.source_candidate_id is None:
                raise PhotoJobError("photo job is not available")
            candidate = candidates_by_id.get(entry.source_candidate_id)
            if candidate is None:
                raise PhotoJobError("photo job is not available")
            batch.append(
                {
                    "trait_id": entry.trait_id,
                    "text_ko": entry.text_ko,
                    "source_candidate_id": entry.source_candidate_id,
                    "included": entry.included,
                }
            )
            entries.append(
                ReviewDraftEntry(
                    candidate_id=entry.source_candidate_id,
                    edited_text_ko=None,
                    excluded=not entry.included,
                )
            )
        if not batch:
            raise PhotoJobError("photo job is not available")
        draft_digest = hashlib.sha256(
            "\n".join(
                f"{entry['trait_id']}:{entry['text_ko']}:{entry['source_candidate_id']}:"
                f"{entry['included']}"
                for entry in batch
            ).encode("utf-8")
        ).hexdigest()
        self._draft_store.save(
            job_id,
            profile_id,
            draft_digest=draft_digest,
            entries=entries,
        )
        receipt = self._confirmed_store.confirm_batch(
            job_id,
            batch,
            profile_id=profile_id,
            draft_digest=draft_digest,
        )
        self._draft_store.discard(job_id, profile_id)
        return {
            "state": row["state"],
            "confirmed": confirmations,
            "included_count": receipt.included_count,
            "receipt_view": PhotoConfirmationReceiptView(
                receipt_id=receipt.receipt_id,
                batch_digest=receipt.draft_digest,
                included_count=receipt.included_count,
                version=1,
            ),
        }

    def delete_job(self, *, job_id: str, profile_id: str) -> dict[str, object]:
        """Converge dual deletion truth; cleanup evidence is returned separately."""

        self._acquire("poll", profile_id)
        row = self._read_owned(job_id=job_id, profile_id=profile_id)
        current_state = str(row["state"])
        with psycopg.connect(self._service_dsn, autocommit=True) as connection:
            if current_state != "deleted":
                binding = connection.execute(
                    "SELECT * FROM dev_eval.read_photo_job_filesystem_binding_v3(%s,%s)",
                    (job_id, profile_id),
                ).fetchone()
                if binding is None:
                    execute_unbound_explicit_deletion(
                        connection,
                        quarantine_root=self._quarantine_root,
                        job_id=job_id,
                        profile_id=profile_id,
                    )
                else:
                    execute_terminal_deletion(
                        connection,
                        quarantine_root=self._quarantine_root,
                        job_id=job_id,
                        profile_id=profile_id,
                        cause="explicit_deletion",
                        reason_code="PHOTO_EXPLICIT_DELETION",
                        from_status=current_state,
                        to_status="deleted",
                        release_after_commit=True,
                    )
                self._release_job_bookkeeping(job_id)
            else:
                pending = connection.execute(
                    "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
                    (job_id, profile_id),
                ).fetchone()
                if pending is None or bool(pending[0]):
                    candidate = connection.execute(
                        "SELECT * FROM dev_eval.read_photo_filesystem_release_v3(%s,%s)",
                        (job_id, profile_id),
                    ).fetchone()
                    if candidate is not None:
                        release_filesystem_cleanup(
                            connection,
                            quarantine_root=self._quarantine_root,
                            job_id=job_id,
                            profile_id=profile_id,
                            operation_key=str(candidate[0]),
                            proof_digest=str(candidate[1]),
                        )
            cleanup = connection.execute(
                "SELECT dev_eval.read_photo_cleanup_status_v3(%s,%s)",
                (job_id, profile_id),
            ).fetchone()
        return {
            "state": "deleted",
            "cleanup_pending": cleanup is None or bool(cleanup[0]),
        }

    def reconcile_on_startup(self) -> object:
        """Conservative startup reconciliation over durable dispatch markers."""

        with psycopg.connect(self._service_dsn, autocommit=True) as connection:
            return reconcile_interrupted_jobs(connection, quarantine_root=self._quarantine_root)


@lru_cache(maxsize=2)
def _lifecycle_for(
    dsn: str, quarantine_root: str, runtime_role: str, builder_role: str
) -> PhotoLifecycleGateway:
    engine = create_database_engine(dsn)
    factory = create_session_factory(engine)
    gateway = PhotoLifecycleGateway(
        factory=factory,
        service_dsn=dsn,
        quarantine_root=FilePath(quarantine_root),
        runtime_role=runtime_role,
        builder_role=builder_role,
    )
    gateway.verify_service_authority()
    return gateway


def get_photo_lifecycle() -> PhotoLifecycleGateway:
    """Resolve the photo service graph lazily so schema export needs no database."""

    dsn = os.environ.get(PHOTO_SERVICE_DSN_ENVIRONMENT_VARIABLE)
    quarantine_root = os.environ.get(PHOTO_QUARANTINE_ROOT_ENVIRONMENT_VARIABLE)
    runtime_role = os.environ.get(RUNTIME_ROLE_ENVIRONMENT_VARIABLE)
    builder_role = os.environ.get(LABEL_BUILDER_ROLE_ENVIRONMENT_VARIABLE)
    if not dsn or not quarantine_root or not runtime_role or not builder_role:
        raise RuntimeError("photo lifecycle storage is not configured")
    return _lifecycle_for(dsn, quarantine_root, runtime_role, builder_role)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/photo-jobs",
    response_model=PhotoJobCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_photo_job",
    responses=_PHOTO_ERROR_RESPONSES,
)
def create_photo_job(
    payload: PhotoJobCreateRequest,
    request: Request,
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoJobCreatedResponse:
    require_same_origin_mutation(request)
    profile_id = principal.profile_id
    try:
        created = lifecycle.create_job(
            profile_id=profile_id,
            consent_version=payload.consent_version,
            consent_accepted=payload.consent_accepted,
        )
    except Exception as error:  # noqa: BLE001 - closed public mapping
        _map_lifecycle_failure(error, preference_profile_id=profile_id)
    return PhotoJobCreatedResponse(
        job_id=str(created["job_id"]),
        preference_profile_id=profile_id,
        state=PhotoJobPublicState.QUEUED,
        consent_version=str(created["consent_version"]),
    )


@router.put(
    "/photo-jobs/{job_id}/images/{image_index}",
    response_model=PhotoJobImageStoredResponse,
    status_code=status.HTTP_200_OK,
    operation_id="put_photo_job_image",
    responses=_PHOTO_ERROR_RESPONSES,
)
async def put_photo_job_image(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    image_index: Annotated[int, Path(ge=1, le=3)],
    request: Request,
) -> PhotoJobImageStoredResponse | JSONResponse:
    """Raw streamed image store composed only from path values and the request.

    Gates run strictly before stream iteration: index bounds, derived
    principal, declared-length advisory, media type, and server ownership.
    Every rejection is returned as one bounded closed body; the request
    body is consumed as raw streamed chunks only.
    """

    try:
        require_same_origin_mutation(request)
    except HTTPException:
        return _photo_rejection_response(
            status_code=status.HTTP_403_FORBIDDEN,
            code="PHOTO_SAME_ORIGIN_REQUIRED",
            message_ko="같은 화면에서 다시 요청해 주세요.",
            job_id=job_id,
        )
    if not 1 <= image_index <= 3:
        return _photo_rejection_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code="PHOTO_IMAGE_INDEX_INVALID",
            message_ko="사진은 한 장에서 세 장까지만 추가할 수 있어요.",
            job_id=job_id,
        )
    try:
        principal = get_profile_session(
            get_optional_profile_session(request.cookies.get(PROFILE_SESSION_COOKIE_NAME))
        )
    except HTTPException:
        return _photo_rejection_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="PHOTO_PRINCIPAL_REQUIRED",
            message_ko="사진 기능을 사용하려면 취향 프로필 확인이 필요해요.",
        )
    profile_id = principal.profile_id
    declared = _declared_length_or_reject(request, job_id)
    if isinstance(declared, JSONResponse):
        return declared
    media_type = _media_type_or_reject(request, job_id)
    if isinstance(media_type, JSONResponse):
        return media_type
    lifecycle = get_photo_lifecycle()
    try:
        job_directory = lifecycle.authorize_image_upload(
            job_id=job_id,
            profile_id=profile_id,
            image_index=image_index,
        )
    except Exception as error:  # noqa: BLE001 - closed public mapping
        return _upload_failure_response(error, job_id=job_id, preference_profile_id=profile_id)
    try:
        _stored_name, byte_length = await lifecycle.store_image_stream(
            job_id=job_id,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=image_index,
            chunks=request.stream(),
            declared_byte_length=declared,
            media_type=media_type,
        )
    except Exception as error:  # noqa: BLE001 - closed public mapping
        return _upload_failure_response(error, job_id=job_id, preference_profile_id=profile_id)
    return PhotoJobImageStoredResponse(
        job_id=job_id, image_index=image_index, byte_length=byte_length
    )


@router.post(
    "/photo-jobs/{job_id}/submit",
    response_model=PhotoJobTraitsResponse,
    status_code=status.HTTP_200_OK,
    operation_id="submit_photo_job",
    responses=_PHOTO_ERROR_RESPONSES,
)
def submit_photo_job(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    request: Request,
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoJobTraitsResponse:
    require_same_origin_mutation(request)
    profile_id = principal.profile_id
    try:
        submitted = lifecycle.submit_job(job_id=job_id, profile_id=profile_id)
    except Exception as error:  # noqa: BLE001 - closed public mapping
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=profile_id)
    return _traits_response(job_id, profile_id, submitted)


def _traits_response(
    job_id: str, profile_id: str, projected: dict[str, object]
) -> PhotoJobTraitsResponse:
    state = PhotoJobPublicState(str(projected["state"]))
    candidate_rows: Sequence[Any] = projected.get("candidates", ())  # type: ignore[assignment]
    confirmed_rows: Sequence[Any] = projected.get("confirmed", ())  # type: ignore[assignment]
    candidates = tuple(
        PhotoTraitCandidateView(
            candidate_id=str(row.candidate_id),
            trait_id=str(row.trait_id),
            text_ko=str(row.text_ko),
            edited_text_ko=row.edited_text_ko,
            excluded=bool(row.excluded),
        )
        for row in candidate_rows
    )
    confirmed = tuple(
        PhotoConfirmedTraitView(
            trait_id=str(row.trait_id),
            text_ko=str(row.text_ko),
            source_candidate_id=row.source_candidate_id,
            included=bool(row.included),
        )
        for row in confirmed_rows
    )
    return PhotoJobTraitsResponse(
        job_id=job_id,
        preference_profile_id=profile_id,
        state=state,
        candidates=candidates,
        confirmed=confirmed,
    )


@router.get(
    "/photo-jobs/{job_id}",
    response_model=PhotoJobStateResponse,
    status_code=status.HTTP_200_OK,
    operation_id="get_photo_job",
    responses=_PHOTO_ERROR_RESPONSES,
)
def get_photo_job(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoJobStateResponse:
    profile_id = principal.profile_id
    try:
        state = lifecycle.read_job_state(job_id=job_id, profile_id=profile_id)
    except Exception as error:  # noqa: BLE001 - closed public mapping
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=profile_id)
    return PhotoJobStateResponse(
        job_id=job_id,
        preference_profile_id=profile_id,
        state=PhotoJobPublicState(str(state["state"])),
        terminal_cause=(
            PhotoTerminalCause(str(state["terminal_cause"]))
            if state["terminal_cause"] is not None
            else None
        ),
        cleanup_pending=bool(state["cleanup_pending"]),
    )


@router.delete(
    "/photo-jobs/{job_id}",
    response_model=PhotoJobDeletedResponse,
    status_code=status.HTTP_200_OK,
    operation_id="delete_photo_job",
    responses=_PHOTO_ERROR_RESPONSES,
)
def delete_photo_job(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    request: Request,
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoJobDeletedResponse:
    require_same_origin_mutation(request)
    profile_id = principal.profile_id
    try:
        deleted = lifecycle.delete_job(job_id=job_id, profile_id=profile_id)
    except Exception as error:  # noqa: BLE001 - closed public mapping
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=profile_id)
    return PhotoJobDeletedResponse(
        job_id=job_id,
        preference_profile_id=profile_id,
        state=PhotoJobPublicState.DELETED,
        cleanup_pending=bool(deleted["cleanup_pending"]),
    )


@router.get(
    "/photo-jobs/{job_id}/traits",
    response_model=PhotoJobTraitsResponse,
    status_code=status.HTTP_200_OK,
    operation_id="get_photo_job_traits",
    responses=_PHOTO_ERROR_RESPONSES,
)
def get_photo_job_traits(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoJobTraitsResponse:
    profile_id = principal.profile_id
    try:
        projected = lifecycle.read_traits(job_id=job_id, profile_id=profile_id)
    except Exception as error:  # noqa: BLE001 - closed public mapping
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=profile_id)
    return _traits_response(job_id, profile_id, projected)


@router.post(
    "/photo-jobs/{job_id}/traits/confirm",
    response_model=PhotoJobConfirmedResponse,
    status_code=status.HTTP_200_OK,
    operation_id="confirm_photo_job_traits",
    responses=_PHOTO_ERROR_RESPONSES,
)
def confirm_photo_job_traits(
    job_id: Annotated[str, Path(pattern=PHOTO_JOB_ID_PATTERN)],
    payload: PhotoJobConfirmRequest,
    request: Request,
    principal: Annotated[ProfileSessionPrincipal, Depends(get_profile_session)],
    lifecycle: Annotated[PhotoLifecycleGateway, Depends(get_photo_lifecycle)],
) -> PhotoJobConfirmedResponse:
    require_same_origin_mutation(request)
    profile_id = principal.profile_id
    try:
        confirmed = lifecycle.confirm_traits(
            job_id=job_id,
            profile_id=profile_id,
            confirmations=payload.confirmations,
        )
    except Exception as error:  # noqa: BLE001 - closed public mapping
        _map_lifecycle_failure(error, job_id=job_id, preference_profile_id=profile_id)
    confirmed_rows = confirmed.get("confirmed", ())
    included_count = confirmed.get("included_count", 0)
    receipt_view = confirmed.get("receipt_view")
    return PhotoJobConfirmedResponse(
        job_id=job_id,
        preference_profile_id=profile_id,
        state=PhotoJobPublicState(str(confirmed["state"])),
        confirmed=confirmed_rows if isinstance(confirmed_rows, tuple) else (),
        included_count=included_count if isinstance(included_count, int) else 0,
        receipt=receipt_view if isinstance(receipt_view, PhotoConfirmationReceiptView) else None,
    )
