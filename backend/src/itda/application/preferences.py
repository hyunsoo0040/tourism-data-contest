"""Application orchestration for current-trip preference profiles."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from itda.contracts.preference import PreferenceProfile, QuestionnaireSubmission
from itda.db.repositories import ProfileRepository
from itda.domain.preference import calculate_preference

Clock = Callable[[], datetime]
REQUEST_INPUT_CONFLICT_DETAIL = "request_id already belongs to different preference input"


class PreferenceInputConflict(Exception):
    """Raised when an idempotency key is reused for materially different input."""


def utc_now() -> datetime:
    """Return an aware UTC timestamp for production profile creation."""

    return datetime.now(UTC)


class PreferenceService:
    """Coordinate the pure scorer and app-owned profile repository."""

    def __init__(
        self,
        repository: ProfileRepository,
        *,
        clock: Clock = utc_now,
    ) -> None:
        self._repository = repository
        self._clock = clock

    def build_profile(self, submission: QuestionnaireSubmission) -> PreferenceProfile:
        """Build a validated profile without crossing a persistence boundary."""

        return calculate_preference(submission, created_at=self._clock())

    def create_profile(self, submission: QuestionnaireSubmission) -> PreferenceProfile:
        candidate = self.build_profile(submission)
        persisted = self._repository.insert_or_get_by_request_id(candidate)
        if (
            persisted.trip_conditions != submission.trip_conditions
            or persisted.answers != submission.answers
        ):
            raise PreferenceInputConflict(REQUEST_INPUT_CONFLICT_DETAIL)
        return persisted

    def get_profile(self, profile_id: str) -> PreferenceProfile | None:
        return self._repository.get(profile_id)

    def get_profile_by_request_id(self, request_id: str) -> PreferenceProfile | None:
        return self._repository.get_by_request_id(request_id)
