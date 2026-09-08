"""Narrow transactional repositories for anonymous journey state."""

from __future__ import annotations

from datetime import datetime

from pydantic import model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.base import ExperienceAxis, StableId, StrictContract, Version, require_utc
from itda.contracts.preference import (
    AxisScore,
    PreferenceProfile,
    QuestionnaireAnswersV1,
    QuestionnaireAnswersV2,
    TripConditions,
)
from itda.db.models import JourneyDraftRow, PreferenceProfileRow


def decode_stored_answers(
    raw: object,
    questionnaire_version: str,
) -> QuestionnaireAnswersV1 | QuestionnaireAnswersV2:
    """Decode stored answers strictly per the questionnaire_version coupling."""

    if questionnaire_version == "questionnaire-v1":
        return QuestionnaireAnswersV1.model_validate(raw)
    if questionnaire_version == "questionnaire-v2":
        return QuestionnaireAnswersV2.model_validate(raw)
    raise ValueError(f"unsupported stored questionnaire_version: {questionnaire_version}")


class JourneyDraft(StrictContract):
    """Validated account-free state that can be edited before profile submission."""

    session_id: StableId
    trip_conditions: TripConditions
    answers: QuestionnaireAnswersV1 | QuestionnaireAnswersV2
    questionnaire_version: Version
    updated_at: datetime

    @model_validator(mode="after")
    def updated_at_is_utc(self) -> JourneyDraft:
        require_utc(self.updated_at, field_name="updated_at")
        return self


def _profile_to_row(profile: PreferenceProfile) -> PreferenceProfileRow:
    scores = {score.axis: score for score in profile.scores}
    history = scores[ExperienceAxis.HISTORY_TRADITION]
    emotion = scores[ExperienceAxis.EMOTION_IMAGE]
    rest = scores[ExperienceAxis.REST_IMMERSION]
    return PreferenceProfileRow(
        profile_id=profile.profile_id,
        request_id=profile.request_id,
        trip_conditions=profile.trip_conditions.model_dump(mode="json"),
        answers=profile.answers.model_dump(mode="json"),
        history_basis_points=history.basis_points,
        history_display_score=history.display_score,
        emotion_basis_points=emotion.basis_points,
        emotion_display_score=emotion.display_score,
        rest_basis_points=rest.basis_points,
        rest_display_score=rest.display_score,
        description_ko=profile.description_ko,
        schema_version=profile.schema_version,
        questionnaire_version=profile.questionnaire_version,
        scoring_version=profile.scoring_version,
        description_template_version=profile.description_template_version,
        config_hash=profile.config_hash,
        created_at=profile.created_at,
        is_current_trip_expectation=profile.is_current_trip_expectation,
    )


def _row_to_profile(row: PreferenceProfileRow) -> PreferenceProfile:
    return PreferenceProfile(
        profile_id=row.profile_id,
        request_id=row.request_id,
        trip_conditions=TripConditions.model_validate(row.trip_conditions),
        answers=decode_stored_answers(row.answers, row.questionnaire_version),
        scores=(
            AxisScore(
                axis=ExperienceAxis.HISTORY_TRADITION,
                basis_points=row.history_basis_points,
                display_score=row.history_display_score,
            ),
            AxisScore(
                axis=ExperienceAxis.EMOTION_IMAGE,
                basis_points=row.emotion_basis_points,
                display_score=row.emotion_display_score,
            ),
            AxisScore(
                axis=ExperienceAxis.REST_IMMERSION,
                basis_points=row.rest_basis_points,
                display_score=row.rest_display_score,
            ),
        ),
        description_ko=row.description_ko,
        schema_version=row.schema_version,
        questionnaire_version=row.questionnaire_version,
        scoring_version=row.scoring_version,
        description_template_version=row.description_template_version,
        config_hash=row.config_hash,
        created_at=row.created_at,
        is_current_trip_expectation=row.is_current_trip_expectation,
    )


class ProfileRepository:
    """Create and fetch validated profiles in one app-owned transaction boundary."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create(self, profile: PreferenceProfile) -> PreferenceProfile:
        with self._factory.begin() as session:
            session.add(_profile_to_row(profile))
            session.flush()
        return profile

    def insert_or_get_by_request_id(self, profile: PreferenceProfile) -> PreferenceProfile:
        """Insert once or recover the request winner without aborting the transaction."""

        with self._factory.begin() as session:
            try:
                with session.begin_nested():
                    session.add(_profile_to_row(profile))
                    session.flush()
                return profile
            except IntegrityError:
                row = session.scalar(
                    select(PreferenceProfileRow).where(
                        PreferenceProfileRow.request_id == profile.request_id
                    )
                )
                if row is None:
                    raise
                return _row_to_profile(row)

    def get(self, profile_id: str) -> PreferenceProfile | None:
        with self._factory() as session:
            row = session.get(PreferenceProfileRow, profile_id)
            return _row_to_profile(row) if row is not None else None

    def get_by_request_id(self, request_id: str) -> PreferenceProfile | None:
        with self._factory() as session:
            row = session.scalar(
                select(PreferenceProfileRow).where(PreferenceProfileRow.request_id == request_id)
            )
            return _row_to_profile(row) if row is not None else None


class JourneyDraftRepository:
    """Upsert and recover a validated anonymous journey draft."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def save(self, draft: JourneyDraft) -> JourneyDraft:
        row = JourneyDraftRow(
            session_id=draft.session_id,
            trip_conditions=draft.trip_conditions.model_dump(mode="json"),
            answers=draft.answers.model_dump(mode="json"),
            questionnaire_version=draft.questionnaire_version,
            updated_at=draft.updated_at,
        )
        with self._factory.begin() as session:
            session.merge(row)
            session.flush()
        return draft

    def get(self, session_id: str) -> JourneyDraft | None:
        with self._factory() as session:
            row = session.get(JourneyDraftRow, session_id)
            if row is None:
                return None
            return JourneyDraft(
                session_id=row.session_id,
                trip_conditions=TripConditions.model_validate(row.trip_conditions),
                answers=decode_stored_answers(row.answers, row.questionnaire_version),
                questionnaire_version=row.questionnaire_version,
                updated_at=row.updated_at,
            )
