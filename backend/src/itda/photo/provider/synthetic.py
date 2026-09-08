"""Deterministic offline photo analysis provider.

Emits strict candidate-only trait candidates from sanitized bytes using pure
integer digest arithmetic. Performs no I/O of any kind: no files, sockets,
clients, environment, or clocks. Identity is the stable
``synthetic-photo-analyzer`` id; output is a byte-reproducible function of
(sanitized bytes, rubric, job id) alone.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final, Literal, cast

from itda.domain.canonical import canonical_sha256
from itda.photo.contracts import (
    CANDIDATE_EVIDENCE_ONLY,
    PHOTO_TRAIT_CANDIDATE_CAP,
    PHOTO_TRAIT_CANDIDATE_SCHEMA_VERSION,
    PhotoTraitCandidate,
    PhotoTraitCandidateSet,
)

SYNTHETIC_PHOTO_ANALYZER_ID: Final[str] = "synthetic-photo-analyzer"

_MIN_IMAGE_BYTES: Final[int] = 8
_MAX_IMAGE_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_RUBRIC_KO_LENGTH: Final[int] = 300
_JOB_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

_TRAIT_VOCABULARY: Final[tuple[tuple[str, str], ...]] = (
    ("M5", "조용한 자연 산책"),
    ("M2", "역사와 이야기가 있는 곳"),
    ("M3", "사람이 적은 한적한 곳"),
    ("M1", "편안한 저녁 산책"),
    ("M4", "넓게 걷기 좋은 길"),
    ("M6", "노을이 보이는 자리"),
)


def _require_korean(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{field} must be a nonempty string")
    if re.search(r"[가-힣]", value) is None:
        raise ValueError(f"{field} must contain Korean text")
    if len(value) > _MAX_RUBRIC_KO_LENGTH:
        raise ValueError(f"{field} exceeds its bounded length")
    return value


def _require_job_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("job_id must be a string")
    if _JOB_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("job_id must be an opaque 64-character hex identifier")
    return value


class SyntheticPhotoAnalysisProvider:
    """Deterministic, capability-free stand-in for a photo analysis provider."""

    provider_id: Final[str] = SYNTHETIC_PHOTO_ANALYZER_ID

    def analyze(
        self,
        *,
        image_png: bytes,
        rubric_ko: str,
        job_id: str,
    ) -> PhotoTraitCandidateSet:
        _require_korean(rubric_ko, field="rubric_ko")
        _require_job_id(job_id)
        if not isinstance(image_png, bytes):
            raise TypeError("image_png must be sanitized bytes")
        if not _MIN_IMAGE_BYTES <= len(image_png) <= _MAX_IMAGE_BYTES:
            raise ValueError("sanitized image bytes are outside the bounded size")

        payload_sha256 = hashlib.sha256(image_png).hexdigest()
        selection_digest = hashlib.sha256(
            f"{payload_sha256}:{rubric_ko}:{job_id}".encode()
        ).digest()
        count = 1 + (selection_digest[0] % PHOTO_TRAIT_CANDIDATE_CAP)
        ordered = _ordered_vocabulary(selection_digest)

        candidates = tuple(
            PhotoTraitCandidate(
                candidate_id=hashlib.sha256(
                    f"{job_id}:{payload_sha256}:{trait_id}".encode()
                ).hexdigest(),
                trait_id=trait_id,
                text_ko=text_ko,
            )
            for trait_id, text_ko in ordered[:count]
        )
        return PhotoTraitCandidateSet(
            schema_version=cast(
                Literal["photo-trait-candidates.v1"], PHOTO_TRAIT_CANDIDATE_SCHEMA_VERSION
            ),
            job_id=job_id,
            payload_sha256=payload_sha256,
            candidates=candidates,
            authority_scope=cast(Literal["CANDIDATE_EVIDENCE_ONLY"], CANDIDATE_EVIDENCE_ONLY),
            candidate_set_sha256=_seal(
                schema_version=PHOTO_TRAIT_CANDIDATE_SCHEMA_VERSION,
                job_id=job_id,
                payload_sha256=payload_sha256,
                candidates=[row.model_dump(mode="json") for row in candidates],
                authority_scope=CANDIDATE_EVIDENCE_ONLY,
            ),
        )


def _ordered_vocabulary(
    selection_digest: bytes,
) -> tuple[tuple[str, str], ...]:
    """Order the closed vocabulary deterministically from digest bytes."""

    indexes = list(range(len(_TRAIT_VOCABULARY)))
    ordered: list[tuple[str, str]] = []
    for position in range(len(_TRAIT_VOCABULARY)):
        remaining = len(indexes)
        pick = selection_digest[position] % remaining
        ordered.append(_TRAIT_VOCABULARY[indexes.pop(pick)])
    return tuple(ordered)


def _seal(**payload: object) -> str:
    return canonical_sha256(payload)
