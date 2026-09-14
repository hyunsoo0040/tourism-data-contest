"""Server-owned review and confirmation over immutable appearance candidates."""

from __future__ import annotations

from typing import Protocol

from itda.contracts.visual_mood import (
    PHOTO_MOOD_FAMILY,
    ConfirmedMoodProjection,
    MoodChoice,
    PhotoMoodCandidateSet,
    PhotoMoodReview,
)
from itda.db.photo_repositories import PhotoJobConflict
from itda.domain.visual_mood import mood_draft_sha256


class MoodStore(Protocol):
    def family(self, *, job_id: str, profile_id: str) -> str | None: ...
    def read_batches(
        self, *, job_id: str, profile_id: str
    ) -> tuple[PhotoMoodCandidateSet, ...]: ...
    def read_confirmation(
        self, *, job_id: str, profile_id: str
    ) -> ConfirmedMoodProjection | None: ...
    def confirm(
        self, *, job_id: str, profile_id: str, choices: tuple[MoodChoice, ...], draft_sha256: str
    ) -> ConfirmedMoodProjection: ...


class PhotoMoodService:
    def __init__(self, store: MoodStore) -> None:
        self._store = store

    def review(self, *, job_id: str, profile_id: str) -> PhotoMoodReview:
        if self._store.family(job_id=job_id, profile_id=profile_id) != PHOTO_MOOD_FAMILY:
            raise PhotoJobConflict("photo job has a different analysis family")
        batches = self._store.read_batches(job_id=job_id, profile_id=profile_id)
        return PhotoMoodReview(
            job_id=job_id,
            preference_profile_id=profile_id,
            batches=batches,
            draft_sha256=mood_draft_sha256(job_id=job_id, profile_id=profile_id, batches=batches),
            confirmation=self._store.read_confirmation(job_id=job_id, profile_id=profile_id),
        )

    def confirm(
        self, *, job_id: str, profile_id: str, choices: tuple[MoodChoice, ...], draft_sha256: str
    ) -> ConfirmedMoodProjection:
        if self._store.family(job_id=job_id, profile_id=profile_id) != PHOTO_MOOD_FAMILY:
            raise PhotoJobConflict("photo job has a different analysis family")
        batches = self._store.read_batches(job_id=job_id, profile_id=profile_id)
        if draft_sha256 != mood_draft_sha256(job_id=job_id, profile_id=profile_id, batches=batches):
            raise PhotoJobConflict("photo mood draft changed")
        candidates = {row.candidate_id: row for batch in batches for row in batch.candidates}
        if len({row.candidate_id for row in choices}) != len(choices) or any(
            row.candidate_id not in candidates
            or (row.included and candidates[row.candidate_id].observation.state != "OBSERVED")
            for row in choices
        ):
            raise PhotoJobConflict("photo mood selection is not supported")
        return self._store.confirm(
            job_id=job_id, profile_id=profile_id, choices=choices, draft_sha256=draft_sha256
        )
