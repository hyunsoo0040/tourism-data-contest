"""Typed least-privilege repositories for the Phase 6 photo lifecycle.

One store per authority surface, all consuming the same session factory:

- :class:`PhotoJobStore` — opaque job rows, create/read/claim/transition
  through the migration's constrained SECURITY DEFINER functions.
- :class:`PhotoTraitCandidateStore` — immutable model candidate evidence
  with provenance-preserving edit/exclusion annotations.
- :class:`PhotoConfirmedTraitStore` — separate explicit user confirmations
  and the projection query that consumes included nonempty values only.
- :class:`PhotoDeletionLedgerStore` — append-only deletion truth reads.

Every error is a closed typed exception; no store method leaks paths,
provider data, or internal labels.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn

from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError as SQLAlchemyProgrammingError
from sqlalchemy.orm import Session, sessionmaker

_JOB_ID_PATTERN: re.Pattern[str] = re.compile(r"^[0-9a-f]{64}$")
_TRAIT_ID_PATTERN: re.Pattern[str] = re.compile(r"^M[1-6]$")
_CAUSE_PATTERN: re.Pattern[str] = re.compile(
    r"^(success|rejection|validation_failure|provider_error|timeout|"
    r"worker_crash|explicit_deletion|expiry|orphan_cleanup)$"
)
_REASON_CODE_PATTERN: re.Pattern[str] = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_STATE_PATTERN: re.Pattern[str] = re.compile(r"^(queued|running|succeeded|failed|expired|deleted)$")


class PhotoJobNotFound(RuntimeError):
    """The opaque job id does not exist or belongs to another profile."""

    code = "PHOTO_JOB_NOT_FOUND"


class PhotoJobConflict(RuntimeError):
    """A create/transition collided with existing durable state."""

    code = "PHOTO_JOB_CONFLICT"


class PhotoJobStoreError(RuntimeError):
    """The store refused an operation that would violate its authority."""

    code = "PHOTO_JOB_STORE_REJECTED"


def _require_job_id(value: object) -> str:
    if not isinstance(value, str) or _JOB_ID_PATTERN.fullmatch(value) is None:
        raise PhotoJobStoreError("photo job identity must be opaque 64-hex")
    return value


def _require_state(value: object) -> str:
    if not isinstance(value, str) or _STATE_PATTERN.fullmatch(value) is None:
        raise PhotoJobStoreError("photo job state is outside the closed vocabulary")
    return value


def _require_cause(value: object) -> str:
    if not isinstance(value, str) or _CAUSE_PATTERN.fullmatch(value) is None:
        raise PhotoJobStoreError("photo terminal cause is outside the closed vocabulary")
    return value


def _require_reason_code(value: object) -> str:
    if not isinstance(value, str) or _REASON_CODE_PATTERN.fullmatch(value) is None:
        raise PhotoJobStoreError("photo reason code is not a closed public code")
    return value


def _require_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PhotoJobStoreError("photo proof digest must be a lowercase sha-256")
    return value


@dataclass(frozen=True, slots=True)
class PhotoJobRecord:
    """One durable job row projection (no paths, no provider data)."""

    job_id: str
    profile_id: str
    status: str
    terminal_cause: str | None
    lease_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CandidateRow:
    """One immutable model candidate row with its review annotations."""

    job_id: str
    candidate_id: str
    trait_id: str
    text_ko: str
    candidate_set_sha256: str
    edited_text_ko: str | None
    excluded: bool
    provenance: str

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        if mode not in ("python", "json"):
            raise ValueError(f"unsupported dump mode: {mode}")
        return {
            "job_id": self.job_id,
            "candidate_id": self.candidate_id,
            "trait_id": self.trait_id,
            "text_ko": self.text_ko,
            "candidate_set_sha256": self.candidate_set_sha256,
            "edited_text_ko": self.edited_text_ko,
            "excluded": self.excluded,
            "provenance": self.provenance,
        }


@dataclass(frozen=True, slots=True)
class ConfirmedTraitRow:
    """One explicit user-confirmed trait value, separate from model text."""

    job_id: str
    confirmation_seq: int
    trait_id: str
    text_ko: str
    source_candidate_id: str | None
    included: bool
    provenance: str
    text_ko_is_blank: bool = False

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        if mode not in ("python", "json"):
            raise ValueError(f"unsupported dump mode: {mode}")
        return {
            "job_id": self.job_id,
            "confirmation_seq": self.confirmation_seq,
            "trait_id": self.trait_id,
            "text_ko": self.text_ko,
            "source_candidate_id": self.source_candidate_id,
            "included": self.included,
            "provenance": self.provenance,
            "text_ko_is_blank": self.text_ko_is_blank,
        }


@dataclass(frozen=True, slots=True)
class ProjectionTraitRow:
    """The projection-facing row: trait id plus the effective integer value.

    The confirmed store derives each value deterministically from the
    confirmed text (canonical Korean-text digest projection), so the
    integer-only projection authority keeps consuming typed rows.
    """

    trait_id: str
    text_ko: str
    value: int
    included: bool


@dataclass(frozen=True, slots=True)
class PhotoRecommendationProjectionRecord:
    draft_digest: str
    included_count: int
    images_count: int
    traits: tuple[ProjectionTraitRow, ...]


@dataclass(frozen=True, slots=True)
class LedgerRow:
    """One public-safe append-only ledger evidence row."""

    ledger_seq: int
    job_id: str
    cause: str
    reason_code: str
    recorded_at: datetime
    residue_proof_digest: str


def _effective_text(candidate: CandidateRow) -> str:
    """Edited text replaces model text for confirmation without rewriting it."""

    return candidate.edited_text_ko if candidate.edited_text_ko is not None else candidate.text_ko


def _raise_closed_candidate_error(error: SQLAlchemyProgrammingError) -> NoReturn:
    """Map a database annotation rejection onto one closed typed failure."""

    code = getattr(getattr(error, "orig", None), "sqlstate", None)
    if code in {"23514", "42501"}:
        raise PhotoJobNotFound("photo candidate annotation rejected") from None
    raise PhotoJobStoreError("photo candidate annotation was rejected") from None


def _trait_value_from_text(text_ko: str) -> int:
    """Deterministic integer projection of confirmed Korean text.

    The value space is 0-100; the mapping is a stable function of the text
    bytes so identical confirmations aggregate identically across reloads.
    A fully neutral anchor maps to the scale midpoint.
    """

    digest = hashlib.sha256(text_ko.encode("utf-8")).digest()
    return int.from_bytes(digest[:2], "big") % 101


class PhotoJobStore:
    """Create/read owned jobs and mutate status only via definer functions."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create_job(
        self,
        *,
        job_id: str,
        profile_id: str,
        idempotency_key: str | None = None,
    ) -> PhotoJobRecord:
        _require_job_id(job_id)
        if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 160:
            raise PhotoJobStoreError("photo job requires one bounded profile owner")
        if idempotency_key is not None and not 16 <= len(idempotency_key) <= 160:
            raise PhotoJobStoreError("photo job idempotency key is out of bounds")
        with self._factory.begin() as session:
            created = session.execute(
                text("SELECT dev_eval.create_photo_job_v3(:job_id, :profile_id, :idempotency_key)"),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "idempotency_key": idempotency_key,
                },
            ).scalar_one()
            existing = self._read_row(session, job_id, profile_id)
            if not bool(created):
                if existing is None:
                    raise PhotoJobConflict("photo job identity already bound")
                return existing
            assert existing is not None
            return existing

    def find_for_profile(self, job_id: str, profile_id: str) -> PhotoJobRecord | None:
        """Return the job only when it belongs to the requesting profile."""

        _require_job_id(job_id)
        with self._factory() as session:
            row = self._read_row(session, job_id, profile_id)
        return row

    def get_for_profile(self, job_id: str, profile_id: str) -> PhotoJobRecord:
        row = self.find_for_profile(job_id, profile_id)
        if row is None:
            raise PhotoJobNotFound(job_id)
        return row

    def claim(self, *, job_id: str, profile_id: str, lease_seconds: int) -> bool:
        """Claim a queued job with a fresh lease; False when already claimed."""

        _require_job_id(job_id)
        self.get_for_profile(job_id, profile_id)
        with self._factory.begin() as session:
            previous = session.execute(
                text(
                    "SELECT dev_eval.transition_photo_job_nonterminal_v3"
                    "(:job_id, :profile_id, 'queued', 'running', now() + :lease)"
                ),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "lease": _lease_interval(lease_seconds),
                },
            ).scalar_one()
        return str(previous) == "queued"

    def transition(
        self,
        *,
        job_id: str,
        profile_id: str,
        from_status: str,
        to_status: str,
        terminal_cause: str | None,
    ) -> None:
        _require_job_id(job_id)
        if (from_status, to_status, terminal_cause) != ("queued", "running", None):
            raise PhotoJobStoreError("terminal transitions require deletion proof authority")
        with self._factory.begin() as session:
            session.execute(
                text(
                    "SELECT dev_eval.transition_photo_job_nonterminal_v3"
                    "(:job_id, :profile_id, 'queued', 'running', "
                    "now() + interval '5 minutes')"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            )

    @staticmethod
    def _read_row(session: Session, job_id: str, profile_id: str) -> PhotoJobRecord | None:
        row = session.execute(
            text(
                "SELECT job_id, profile_id, status, terminal_cause, "
                "lease_expires_at, created_at, updated_at "
                "FROM dev_eval.read_photo_job_v2(:job_id, :profile_id)"
            ),
            {"job_id": job_id, "profile_id": profile_id},
        ).first()
        if row is None:
            return None
        return PhotoJobRecord(
            job_id=str(row[0]),
            profile_id=str(row[1]),
            status=str(row[2]),
            terminal_cause=None if row[3] is None else str(row[3]),
            lease_expires_at=None if row[4] is None else _as_datetime(row[4]),
            created_at=_as_datetime(row[5]),
            updated_at=_as_datetime(row[6]),
        )


class PhotoTraitCandidateStore:
    """Immutable model-candidate evidence with provenance annotations."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def append_batch(
        self, job_id: str, batch: list[dict[str, Any]], *, profile_id: str | None = None
    ) -> None:
        """Append one typed candidate batch (1..6) through the exact function.

        The batch is one provider candidate set: equal-length parallel arrays
        of opaque candidate IDs, closed trait IDs, bounded Korean text, and
        the canonical set digest. Cardinality, NULL elements, and duplicate
        identities are rejected here and again inside the database function.
        """

        _require_job_id(job_id)
        if profile_id is None:
            raise PhotoJobStoreError("candidate writes require the owning profile")
        rows: list[dict[str, Any]] = []
        seen_candidates: set[str] = set()
        for entry in batch:
            candidate_id = _require_digest(entry.get("candidate_id"))
            trait_id = entry.get("trait_id")
            text_ko = entry.get("text_ko")
            candidate_set = _require_digest(entry.get("candidate_set_sha256"))
            if not isinstance(trait_id, str) or _TRAIT_ID_PATTERN.fullmatch(trait_id) is None:
                raise PhotoJobStoreError("candidate trait id must be M1-M6")
            if not isinstance(text_ko, str) or not 1 <= len(text_ko) <= 24:
                raise PhotoJobStoreError("candidate Korean text exceeds its bound")
            if candidate_id in seen_candidates:
                raise PhotoJobStoreError("candidate identifiers must be unique per batch")
            seen_candidates.add(candidate_id)
            rows.append(
                {
                    "candidate_id": candidate_id,
                    "trait_id": trait_id,
                    "text_ko": text_ko,
                    "candidate_set_sha256": candidate_set,
                }
            )
        if not 1 <= len(rows) <= 6:
            raise PhotoJobStoreError("candidate batch cardinality must be 1..6")
        with self._factory.begin() as session:
            session.execute(
                text(
                    "SELECT dev_eval.record_photo_candidate_batch_v3"
                    "(:job_id, :profile_id, :candidate_ids, :trait_ids, "
                    ":texts_ko, :candidate_set_sha256s)"
                ),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "candidate_ids": [row["candidate_id"] for row in rows],
                    "trait_ids": [row["trait_id"] for row in rows],
                    "texts_ko": [row["text_ko"] for row in rows],
                    "candidate_set_sha256s": [row["candidate_set_sha256"] for row in rows],
                },
            )

    def annotate(
        self,
        job_id: str,
        profile_id: str,
        candidate_id: str,
        *,
        edited_text_ko: str | None,
        excluded: bool | None,
    ) -> None:
        """Apply one provenance annotation without rewriting model text."""

        _require_job_id(job_id)
        _require_digest(candidate_id)
        if edited_text_ko is not None and (
            not isinstance(edited_text_ko, str) or not 1 <= len(edited_text_ko) <= 64
        ):
            raise PhotoJobStoreError("edited Korean text exceeds its bound")
        if edited_text_ko is None and excluded is None:
            raise PhotoJobStoreError("one annotation must be provided")
        try:
            with self._factory.begin() as session:
                session.execute(
                    text(
                        "SELECT dev_eval.annotate_photo_candidate_v3"
                        "(:job_id, :profile_id, :candidate_id, "
                        ":edited_text_ko, :excluded)"
                    ),
                    {
                        "job_id": job_id,
                        "profile_id": profile_id,
                        "candidate_id": candidate_id,
                        "edited_text_ko": edited_text_ko,
                        "excluded": excluded,
                    },
                )
        except SQLAlchemyProgrammingError as error:
            _raise_closed_candidate_error(error)

    def record_edit(
        self,
        job_id: str,
        profile_id: str,
        candidate_id: str,
        *,
        edited_text_ko: str,
    ) -> None:
        """Edit annotation through the exact function for the owned job."""

        self.annotate(
            job_id,
            profile_id,
            candidate_id,
            edited_text_ko=edited_text_ko,
            excluded=None,
        )

    def record_exclusion(self, job_id: str, profile_id: str, candidate_id: str) -> None:
        """Exclusion annotation through the exact function for the owned job."""

        self.annotate(
            job_id,
            profile_id,
            candidate_id,
            edited_text_ko=None,
            excluded=True,
        )

    def list_for_job(self, job_id: str, profile_id: str | None = None) -> list[CandidateRow]:
        """List candidates only for the job owned by the given profile."""

        _require_job_id(job_id)
        if profile_id is None:
            raise PhotoJobStoreError("candidate reads require the owning profile")
        with self._factory() as session:
            rows = session.execute(
                text(
                    "SELECT job_id, candidate_id, trait_id, text_ko, "
                    "candidate_set_sha256, edited_text_ko, excluded, provenance "
                    "FROM dev_eval.list_photo_candidates_v2(:job_id, :profile_id)"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            ).all()
        return [
            CandidateRow(
                job_id=str(row[0]),
                candidate_id=str(row[1]),
                trait_id=str(row[2]),
                text_ko=str(row[3]),
                candidate_set_sha256=str(row[4]),
                edited_text_ko=None if row[5] is None else str(row[5]),
                excluded=bool(row[6]),
                provenance=str(row[7]),
            )
            for row in rows
        ]

    def effective_text_for(self, job_id: str, profile_id: str, candidate_id: str) -> str:
        """The confirmation-time text (edited when present, model otherwise)."""

        for row in self.list_for_job(job_id, profile_id):
            if hmac.compare_digest(row.candidate_id, candidate_id):
                return _effective_text(row)
        raise PhotoJobNotFound(candidate_id)


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    """One minimized confirmation receipt: opaque identity plus bounds only."""

    receipt_id: str
    job_id: str
    included_count: int
    draft_digest: str
    created_at: datetime

    def public_view(self) -> dict[str, object]:
        """Opaque API projection: no job/profile ownership internals."""

        return {
            "receipt_id": self.receipt_id,
            "included_count": self.included_count,
            "batch_digest": self.draft_digest,
            "version": 1,
        }


@dataclass(frozen=True, slots=True)
class ReviewDraftEntry:
    """One candidate annotation inside an owned review draft."""

    candidate_id: str
    edited_text_ko: str | None
    excluded: bool


@dataclass(frozen=True, slots=True)
class ReviewDraftRecord:
    """One owned review draft projection (bounded annotations only)."""

    job_id: str
    draft_digest: str
    entries: tuple[ReviewDraftEntry, ...]


class ReviewDraftNotFound(RuntimeError):
    """The review draft does not exist or belongs to another profile."""

    code = "PHOTO_REVIEW_DRAFT_NOT_FOUND"


class PhotoReviewDraftStore:
    """Owned review-draft persistence through the exact definer functions."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def save(
        self,
        job_id: str,
        profile_id: str,
        *,
        draft_digest: str,
        entries: tuple[ReviewDraftEntry, ...] | list[ReviewDraftEntry],
    ) -> bool:
        """CAS-save one bounded draft (1..6 typed entries)."""

        _require_job_id(job_id)
        _require_digest(draft_digest)
        if not 1 <= len(entries) <= 6:
            raise PhotoJobStoreError("review draft cardinality must be 1..6")
        candidate_ids: list[str] = []
        trait_ids: list[str] = []
        edited_texts: list[str | None] = []
        excluded_flags: list[bool] = []
        seen: set[str] = set()
        annotations: list[tuple[str, str | None, bool | None]] = []
        for projected in self._candidate_projection(job_id, profile_id):
            candidate_id = projected[0]
            if candidate_id in seen:
                raise PhotoJobStoreError("review draft candidates must be unique")
            seen.add(candidate_id)
            candidate_ids.append(candidate_id)
            trait_ids.append(projected[1])
            edited_texts.append(projected[2])
            excluded_flags.append(projected[4])
        for entry in entries:
            candidate_id = _require_digest(entry.candidate_id)
            if candidate_id not in seen:
                raise PhotoJobNotFound(candidate_id)
            position = candidate_ids.index(candidate_id)
            edited = entry.edited_text_ko
            if edited is None:
                edited = edited_texts[position]
            elif not 1 <= len(edited) <= 64:
                raise PhotoJobStoreError("edited Korean text exceeds its bound")
            excluded = entry.excluded or excluded_flags[position]
            if edited != edited_texts[position] or excluded != excluded_flags[position]:
                annotations.append(
                    (
                        candidate_id,
                        edited if edited != edited_texts[position] else None,
                        excluded if excluded != excluded_flags[position] else None,
                    )
                )
            edited_texts[position] = edited
            excluded_flags[position] = excluded
        with self._factory.begin() as session:
            for candidate_id, annotation_edit, annotation_excluded in annotations:
                session.execute(
                    text(
                        "SELECT dev_eval.annotate_photo_candidate_v3"
                        "(:job_id, :profile_id, :candidate_id, "
                        ":edited_text_ko, :excluded)"
                    ),
                    {
                        "job_id": job_id,
                        "profile_id": profile_id,
                        "candidate_id": candidate_id,
                        "edited_text_ko": annotation_edit,
                        "excluded": annotation_excluded,
                    },
                )
            saved = session.execute(
                text(
                    "SELECT dev_eval.save_photo_review_draft_v3"
                    "(:job_id, :profile_id, :draft_digest, :candidate_ids, "
                    ":trait_ids, :edited_texts_ko, :excluded_flags)"
                ),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "draft_digest": draft_digest,
                    "candidate_ids": candidate_ids,
                    "trait_ids": trait_ids,
                    "edited_texts_ko": edited_texts,
                    "excluded_flags": excluded_flags,
                },
            ).scalar_one()
        return bool(saved)

    def read_owned(self, job_id: str, profile_id: str) -> ReviewDraftRecord:
        _require_job_id(job_id)
        with self._factory() as session:
            row = session.execute(
                text(
                    "SELECT candidate_ids, trait_ids, edited_texts_ko, "
                    "excluded_flags, draft_digest "
                    "FROM dev_eval.read_photo_review_draft_v2(:job_id, :profile_id)"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            ).first()
        if row is None:
            raise ReviewDraftNotFound(job_id)
        entries = tuple(
            ReviewDraftEntry(
                candidate_id=str(candidate_id),
                edited_text_ko=None if edited is None else str(edited),
                excluded=bool(excluded),
            )
            for candidate_id, edited, excluded in zip(row[0], row[2], row[3], strict=True)
        )
        return ReviewDraftRecord(
            job_id=job_id,
            draft_digest=str(row[4]),
            entries=entries,
        )

    def discard(self, job_id: str, profile_id: str) -> bool:
        _require_job_id(job_id)
        with self._factory.begin() as session:
            discarded = session.execute(
                text("SELECT dev_eval.discard_photo_review_draft_v3(:job_id, :profile_id)"),
                {"job_id": job_id, "profile_id": profile_id},
            ).scalar_one()
        return bool(discarded)

    def _candidate_projection(
        self, job_id: str, profile_id: str
    ) -> list[tuple[str, str, str | None, str, bool]]:
        """Owned candidate rows through the read projection (no table scan)."""

        with self._factory() as session:
            rows = session.execute(
                text(
                    "SELECT candidate_id, trait_id, edited_text_ko, "
                    "candidate_set_sha256, excluded "
                    "FROM dev_eval.list_photo_candidates_v2(:job_id, :profile_id)"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            ).all()
        return [
            (
                str(row[0]),
                str(row[1]),
                None if row[2] is None else str(row[2]),
                str(row[3]),
                bool(row[4]),
            )
            for row in rows
        ]


class PhotoConfirmedTraitStore:
    """Explicit batch confirmations, separate from model candidate rows."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def confirm_batch(
        self,
        job_id: str,
        batch: list[dict[str, Any]],
        *,
        profile_id: str | None = None,
        draft_digest: str | None = None,
    ) -> ReceiptRecord:
        """Atomically confirm one batch (1..6) and return the opaque receipt.

        All-excluded input is valid: it confirms the exclusion decision with
        zero included rows and one durable receipt. Repeating an identical
        batch is idempotent — the existing receipt is returned unchanged.
        """

        _require_job_id(job_id)
        if profile_id is None:
            raise PhotoJobStoreError("confirmation requires the owning profile")
        trait_ids: list[str] = []
        texts: list[str] = []
        sources: list[str | None] = []
        included_flags: list[bool] = []
        blank_flags: list[bool] = []
        for entry in batch:
            trait_id = entry.get("trait_id")
            text_ko = entry.get("text_ko")
            source = entry.get("source_candidate_id")
            included = entry.get("included")
            if not isinstance(trait_id, str) or _TRAIT_ID_PATTERN.fullmatch(trait_id) is None:
                raise PhotoJobStoreError("confirmed trait id must be M1-M6")
            if not isinstance(text_ko, str) or not 1 <= len(text_ko) <= 64:
                raise PhotoJobStoreError("confirmed Korean text exceeds its bound")
            if not isinstance(included, bool):
                raise PhotoJobStoreError("confirmed inclusion must be an explicit boolean")
            if source is not None:
                source = _require_digest(source)
            trait_ids.append(trait_id)
            texts.append(text_ko)
            sources.append(source)
            included_flags.append(included)
            blank_flags.append(bool(entry.get("text_ko_is_blank", False)))
        if not 1 <= len(trait_ids) <= 6:
            raise PhotoJobStoreError("confirmation batch cardinality must be 1..6")
        if draft_digest is None:
            # Deterministic batch digest: identical confirmations map to the
            # same receipt identity, making repeats naturally idempotent.
            draft_digest = hashlib.sha256(
                "\n".join(
                    f"{trait_id}:{text_ko}:{source}:{included}"
                    for trait_id, text_ko, source, included in zip(
                        trait_ids, texts, sources, included_flags, strict=True
                    )
                ).encode("utf-8")
            ).hexdigest()
        _require_digest(draft_digest)
        # Persist the review draft first: the database confirm function
        # requires the exact (job, profile, digest) draft and verifies every
        # submitted row against it plus the real candidate rows.
        _CandidateProjection = tuple[str, str, str, str | None, str, bool]
        candidate_rows: list[_CandidateProjection] = []
        with self._factory() as session:
            projected = session.execute(
                text(
                    "SELECT candidate_id, trait_id, text_ko, edited_text_ko, "
                    "candidate_set_sha256, excluded "
                    "FROM dev_eval.list_photo_candidates_v2(:job_id, :profile_id)"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            ).all()
            candidate_rows = [
                (
                    str(row[0]),
                    str(row[1]),
                    str(row[2]),
                    None if row[3] is None else str(row[3]),
                    str(row[4]),
                    bool(row[5]),
                )
                for row in projected
            ]
        candidates_by_id: dict[str, _CandidateProjection] = {row[0]: row for row in candidate_rows}
        draft_candidate_ids: list[str] = []
        draft_trait_ids: list[str] = []
        draft_edited: list[str | None] = []
        draft_original_excluded: list[bool] = []
        draft_excluded: list[bool] = []
        for _trait_id, text_ko, source, included in zip(
            trait_ids, texts, sources, included_flags, strict=True
        ):
            # Product inputs are candidate-derived: every confirmed row must
            # carry its real source candidate id. NULL provenance would
            # bypass the database-side candidate binding and is rejected
            # before any write (mirroring the 0020 confirm function).
            if source is None:
                raise PhotoJobStoreError("confirmation requires the persisted candidate identity")
            selected = candidates_by_id.get(source)
            if selected is None:
                raise PhotoJobStoreError("confirmation requires a persisted candidate for each row")
            candidate_id, cand_trait, model_text, stored_edit, _digest, excluded = selected
            effective = stored_edit
            if effective is None and text_ko != model_text:
                # The user confirmed edited text: persist the edit annotation
                # first so the draft the database verifies carries it.
                with self._factory.begin() as session:
                    session.execute(
                        text(
                            "SELECT dev_eval.annotate_photo_candidate_v3"
                            "(:job_id, :profile_id, :candidate_id, "
                            ":edited_text_ko, NULL)"
                        ),
                        {
                            "job_id": job_id,
                            "profile_id": profile_id,
                            "candidate_id": candidate_id,
                            "edited_text_ko": text_ko,
                        },
                    )
                effective = text_ko
            draft_candidate_ids.append(candidate_id)
            draft_trait_ids.append(cand_trait)
            draft_edited.append(effective)
            draft_original_excluded.append(excluded)
            draft_excluded.append(excluded or not included)
        with self._factory.begin() as session:
            for candidate_id, excluded, draft_value in zip(
                draft_candidate_ids,
                draft_original_excluded,
                draft_excluded,
                strict=True,
            ):
                if draft_value != excluded:
                    session.execute(
                        text(
                            "SELECT dev_eval.annotate_photo_candidate_v3"
                            "(:job_id, :profile_id, :candidate_id, NULL, "
                            ":excluded)"
                        ),
                        {
                            "job_id": job_id,
                            "profile_id": profile_id,
                            "candidate_id": candidate_id,
                            "excluded": draft_value,
                        },
                    )
            session.execute(
                text(
                    "SELECT dev_eval.save_photo_review_draft_v3"
                    "(:job_id, :profile_id, :draft_digest, :candidate_ids, "
                    ":trait_ids, :edited_texts_ko, :excluded_flags)"
                ),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "draft_digest": draft_digest,
                    "candidate_ids": draft_candidate_ids,
                    "trait_ids": draft_trait_ids,
                    "edited_texts_ko": draft_edited,
                    "excluded_flags": draft_excluded,
                },
            )
        receipt_id = secrets.token_hex(32)
        with self._factory.begin() as session:
            returned = session.execute(
                text(
                    "SELECT dev_eval.confirm_photo_traits_v3"
                    "(:job_id, :profile_id, :draft_digest, :trait_ids, :texts_ko, "
                    ":source_candidate_ids, :included_flags, :blank_flags, "
                    ":receipt_id)"
                ),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "draft_digest": draft_digest,
                    "trait_ids": trait_ids,
                    "texts_ko": texts,
                    "source_candidate_ids": sources,
                    "included_flags": included_flags,
                    "blank_flags": blank_flags,
                    "receipt_id": receipt_id,
                },
            ).scalar_one()
            receipt_row = session.execute(
                text(
                    "SELECT receipt_id, job_id, profile_id, draft_digest, "
                    "included_count, created_at "
                    "FROM dev_eval.read_photo_confirmation_receipt_v2"
                    "(:job_id, :profile_id, :receipt_id)"
                ),
                {
                    "job_id": job_id,
                    "profile_id": profile_id,
                    "receipt_id": str(returned),
                },
            ).first()
        assert receipt_row is not None
        return ReceiptRecord(
            receipt_id=str(receipt_row[0]),
            job_id=str(receipt_row[1]),
            included_count=int(receipt_row[4]),
            draft_digest=str(receipt_row[3]),
            created_at=_as_datetime(receipt_row[5]),
        )

    def list_for_job(self, job_id: str, profile_id: str | None = None) -> list[ConfirmedTraitRow]:
        _require_job_id(job_id)
        if profile_id is None:
            raise PhotoJobStoreError("confirmed reads require the owning profile")
        with self._factory() as session:
            rows = session.execute(
                text(
                    "SELECT job_id, confirmation_seq, trait_id, text_ko, "
                    "source_candidate_id, included, provenance, text_ko_is_blank "
                    "FROM dev_eval.list_photo_confirmed_traits_v2"
                    "(:job_id, :profile_id)"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            ).all()
        return [
            ConfirmedTraitRow(
                job_id=str(row[0]),
                confirmation_seq=int(row[1]),
                trait_id=str(row[2]),
                text_ko=str(row[3]),
                source_candidate_id=None if row[4] is None else str(row[4]),
                included=bool(row[5]),
                provenance=str(row[6]),
                text_ko_is_blank=bool(row[7]),
            )
            for row in rows
        ]

    def list_included_for_projection(
        self, job_id: str, profile_id: str | None = None
    ) -> list[ProjectionTraitRow]:
        """Included, nonempty-value confirmed rows for projection only.

        Rows explicitly flagged ``text_ko_is_blank`` (or with whitespace-only
        text) never reach the projection: an empty preference contributes
        nothing to the blended profile.
        """

        included_rows = [
            row
            for row in self.list_for_job(job_id, profile_id)
            if row.included and not row.text_ko_is_blank and row.text_ko.strip() != ""
        ]
        return [
            ProjectionTraitRow(
                trait_id=row.trait_id,
                text_ko=row.text_ko,
                value=_trait_value_from_text(row.text_ko),
                included=True,
            )
            for row in included_rows
        ]


class PhotoRecommendationProjectionReader:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def read(self, job_id: str, profile_id: str) -> PhotoRecommendationProjectionRecord:
        _require_job_id(job_id)
        if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 160:
            raise PhotoJobStoreError("photo recommendation projection requires an owner")
        try:
            with self._factory() as session:
                rows = session.execute(
                    text(
                        "SELECT draft_digest, included_count, images_count, "
                        "confirmation_seq, trait_id, text_ko "
                        "FROM dev_eval.read_photo_recommendation_projection_v1"
                        "(:job_id, :profile_id)"
                    ),
                    {"job_id": job_id, "profile_id": profile_id},
                ).all()
        except SQLAlchemyProgrammingError:
            raise PhotoJobNotFound("photo recommendation projection unavailable") from None
        if not rows:
            raise PhotoJobNotFound("photo recommendation projection unavailable")
        draft_digest = _require_digest(rows[0][0])
        included_count = int(rows[0][1])
        images_count = int(rows[0][2])
        if len(rows) != included_count or not 1 <= included_count <= 6:
            raise PhotoJobStoreError("photo recommendation projection cardinality drifted")
        traits = tuple(
            ProjectionTraitRow(
                trait_id=str(row[4]),
                text_ko=str(row[5]),
                value=_trait_value_from_text(str(row[5])),
                included=True,
            )
            for row in rows
        )
        if any(_TRAIT_ID_PATTERN.fullmatch(row.trait_id) is None for row in traits):
            raise PhotoJobStoreError("photo recommendation projection trait drifted")
        return PhotoRecommendationProjectionRecord(
            draft_digest=draft_digest,
            included_count=included_count,
            images_count=images_count,
            traits=traits,
        )


class PhotoDeletionLedgerStore:
    """Append-only deletion evidence reads; writes live in photo.deletion."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def rows_for_job(self, job_id: str, profile_id: str) -> list[LedgerRow]:
        """Ledger rows only for the job owned by the given profile."""

        _require_job_id(job_id)
        with self._factory() as session:
            rows = session.execute(
                text(
                    "SELECT ledger_seq, job_id, cause, reason_code, recorded_at, "
                    "residue_proof_digest "
                    "FROM dev_eval.list_photo_deletion_ledger_v3"
                    "(:job_id, :profile_id)"
                ),
                {"job_id": job_id, "profile_id": profile_id},
            ).all()
        return [
            LedgerRow(
                ledger_seq=int(row[0]),
                job_id=str(row[1]),
                cause=str(row[2]),
                reason_code=str(row[3]),
                recorded_at=_as_datetime(row[4]),
                residue_proof_digest=str(row[5]),
            )
            for row in rows
        ]

    def has_ledger_row(
        self, job_id: str, profile_id: str, cause: str, residue_proof_digest: str
    ) -> bool:
        _require_job_id(job_id)
        _require_cause(cause)
        _require_digest(residue_proof_digest)
        return any(
            row.cause == cause and row.residue_proof_digest == residue_proof_digest
            for row in self.rows_for_job(job_id, profile_id)
        )


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    raise PhotoJobStoreError("stored timestamp column did not parse as a datetime")


def _rowcount(result: Any) -> int:
    count = getattr(result, "rowcount", None)
    return count if isinstance(count, int) else 0


def _lease_interval(lease_seconds: int) -> str:
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
        raise PhotoJobStoreError("photo job lease must be a bounded positive integer")
    return f"{lease_seconds} seconds"


__all__ = [
    "CandidateRow",
    "ConfirmedTraitRow",
    "LedgerRow",
    "PhotoJobConflict",
    "PhotoJobNotFound",
    "PhotoJobRecord",
    "PhotoJobStore",
    "PhotoJobStoreError",
    "PhotoConfirmedTraitStore",
    "PhotoRecommendationProjectionReader",
    "PhotoRecommendationProjectionRecord",
    "PhotoDeletionLedgerStore",
    "PhotoReviewDraftStore",
    "PhotoTraitCandidateStore",
    "ProjectionTraitRow",
    "ReceiptRecord",
    "ReviewDraftEntry",
    "ReviewDraftNotFound",
    "ReviewDraftRecord",
]
