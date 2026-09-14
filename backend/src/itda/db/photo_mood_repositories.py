"""Service-only mood persistence with independently recomputed confirmations."""

from __future__ import annotations

import json
from typing import Any

from psycopg import Connection
from psycopg.types.json import Jsonb
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.visual_mood import (
    PHOTO_MOOD_FAMILY,
    ConfirmedMoodProjection,
    MoodChoice,
    PhotoMoodCandidateSet,
)
from itda.db.photo_repositories import PhotoJobConflict, PhotoJobNotFound, PhotoJobStoreError
from itda.domain.visual_mood import confirm_moods


class PhotoMoodRepository:
    """No table DML/SELECT authority is required by the service role."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def create_job(self, *, job_id: str, profile_id: str) -> str:
        with self._factory.begin() as session:
            session.execute(
                text("SELECT dev_eval.create_photo_mood_job_v1(:job,:profile)"),
                {"job": job_id, "profile": profile_id},
            ).scalar_one()
        return job_id

    def family(self, *, job_id: str, profile_id: str) -> str | None:
        with self._factory.begin() as session:
            family = session.execute(
                text("SELECT dev_eval.read_photo_mood_family_v1(:job,:profile)"),
                {"job": job_id, "profile": profile_id},
            ).scalar_one()
        if family not in (None, PHOTO_MOOD_FAMILY):
            raise PhotoJobStoreError("invalid stored photo analysis family")
        return family

    def record_batch(
        self,
        connection: Connection[Any] | Session,
        *,
        batch: PhotoMoodCandidateSet,
        profile_id: str,
    ) -> int:
        """Participate in the existing Stage-C transaction; never commit here."""
        validated = PhotoMoodCandidateSet.model_validate_json(batch.model_dump_json())
        payload = validated.model_dump(mode="json")
        if isinstance(connection, Session):
            count = connection.execute(
                text(
                    "SELECT dev_eval.record_photo_mood_batch_v1"
                    "(:job,:profile,CAST(:payload AS jsonb))"
                ),
                {"job": validated.job_id, "profile": profile_id, "payload": json.dumps(payload)},
            ).scalar_one()
        else:
            row = connection.execute(
                "SELECT dev_eval.record_photo_mood_batch_v1(%s,%s,%s)",
                (validated.job_id, profile_id, Jsonb(payload)),
            ).fetchone()
            if row is None:
                raise PhotoJobStoreError("photo mood batch was not stored")
            count = row[0]
        return int(count)

    @staticmethod
    def _batches(
        session: Session, job_id: str, profile_id: str
    ) -> tuple[PhotoMoodCandidateSet, ...]:
        values = session.execute(
            text("SELECT * FROM dev_eval.read_photo_mood_batches_v1(:job,:profile)"),
            {"job": job_id, "profile": profile_id},
        ).scalars()
        batches = tuple(PhotoMoodCandidateSet.model_validate(value) for value in values)
        if any(batch.job_id != job_id for batch in batches) or len(
            {b.image_index for b in batches}
        ) != len(batches):
            raise PhotoJobStoreError("stored photo mood batches have invalid ownership")
        return batches

    def read_batches(self, *, job_id: str, profile_id: str) -> tuple[PhotoMoodCandidateSet, ...]:
        with self._factory.begin() as session:
            return self._batches(session, job_id, profile_id)

    @staticmethod
    def _confirmed(
        session: Session, job_id: str, profile_id: str, payload: object
    ) -> ConfirmedMoodProjection | None:
        if payload is None:
            return None
        stored = ConfirmedMoodProjection.model_validate(payload)
        if stored.job_id != job_id or stored.preference_profile_id != profile_id:
            raise PhotoJobNotFound("photo mood confirmation belongs to another owner")
        expected = confirm_moods(
            job_id=job_id,
            profile_id=profile_id,
            batches=PhotoMoodRepository._batches(session, job_id, profile_id),
            choices=stored.choices,
            draft_sha256=stored.draft_sha256,
        )
        if expected != stored:
            raise PhotoJobStoreError("photo mood confirmation differs from stored evidence")
        return stored

    def read_confirmation(self, *, job_id: str, profile_id: str) -> ConfirmedMoodProjection | None:
        with self._factory.begin() as session:
            payload = session.execute(
                text("SELECT dev_eval.read_photo_mood_confirmation_v1(:job,:profile)"),
                {"job": job_id, "profile": profile_id},
            ).scalar_one()
            return self._confirmed(session, job_id, profile_id, payload)

    def confirm(
        self,
        *,
        job_id: str,
        profile_id: str,
        choices: tuple[MoodChoice, ...],
        draft_sha256: str,
    ) -> ConfirmedMoodProjection:
        with self._factory.begin() as session:
            batches = self._batches(session, job_id, profile_id)
            expected = confirm_moods(
                job_id=job_id,
                profile_id=profile_id,
                batches=batches,
                choices=choices,
                draft_sha256=draft_sha256,
            )
            payload = session.execute(
                text(
                    "SELECT dev_eval.confirm_photo_moods_v1"
                    "(:job,:profile,CAST(:choices AS jsonb),:draft)"
                ),
                {
                    "job": job_id,
                    "profile": profile_id,
                    "draft": draft_sha256,
                    "choices": json.dumps([choice.model_dump(mode="json") for choice in choices]),
                },
            ).scalar_one()
            stored = self._confirmed(session, job_id, profile_id, payload)
            if stored != expected:
                raise PhotoJobConflict("photo mood confirmation changed during persistence")
            return expected

    def read_projection(self, *, job_id: str, profile_id: str) -> ConfirmedMoodProjection:
        projection = self.read_confirmation(job_id=job_id, profile_id=profile_id)
        if projection is None:
            raise PhotoJobNotFound("photo mood confirmation is unavailable")
        return projection
