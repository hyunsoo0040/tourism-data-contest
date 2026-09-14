"""PostgreSQL persistence with session ownership and immutable replayable runs."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from itda.authenticity.auxiliary import Auxiliary
from itda.authenticity.contracts import Assessment
from itda.authenticity.intent import Intent
from itda.authenticity.release import Release, load_release
from itda.authenticity.scoring import verify_assessment
from itda.domain.canonical import canonical_sha256


class OwnershipError(ValueError):
    pass


class RequestConflict(ValueError):
    pass


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Repository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def create_session(self) -> dict[str, Any]:
        token = secrets.token_urlsafe(32)
        session_id = secrets.token_urlsafe(24)
        created = datetime.now(UTC)
        expires = created + timedelta(days=7)
        with self.engine.begin() as connection:
            connection.execute(
                text("""INSERT INTO app.authenticity_sessions
                (session_id,token_sha256,created_at,expires_at)
                VALUES (:id,:digest,:created,:expires)"""),
                {
                    "id": session_id,
                    "digest": token_digest(token),
                    "created": created,
                    "expires": expires,
                },
            )
        return {"session_id": session_id, "token": token, "expires_at": expires}

    def session(self, token: str) -> str:
        if not token or len(token) > 100:
            raise OwnershipError("SESSION_REQUIRED")
        with self.engine.connect() as connection:
            value = connection.execute(
                text("""SELECT session_id FROM app.authenticity_sessions
                WHERE token_sha256=:digest AND expires_at>now()"""),
                {"digest": token_digest(token)},
            ).scalar_one_or_none()
        if not isinstance(value, str):
            raise OwnershipError("SESSION_EXPIRED_OR_UNKNOWN")
        return value

    def delete_session(self, session_id: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM app.authenticity_sessions WHERE session_id=:sid"),
                {"sid": session_id},
            )

    def put_intent(self, session_id: str, intent: Intent) -> Intent:
        payload = intent.model_dump(mode="json")
        try:
            with self.engine.begin() as connection:
                connection.execute(
                    text("""INSERT INTO app.authenticity_intents
                    (profile_id,session_id,request_id,payload)
                    VALUES (:pid,:sid,:rid,CAST(:payload AS jsonb))
                    ON CONFLICT (session_id,request_id) DO NOTHING"""),
                    {
                        "pid": intent.profile_id,
                        "sid": session_id,
                        "rid": intent.submission.request_id,
                        "payload": json.dumps(payload, ensure_ascii=False),
                    },
                )
                stored = connection.execute(
                    text("""SELECT payload FROM app.authenticity_intents
                    WHERE session_id=:sid AND request_id=:rid"""),
                    {"sid": session_id, "rid": intent.submission.request_id},
                ).scalar_one()
        except IntegrityError as error:
            raise RequestConflict("INTENT_REQUEST_CONFLICT") from error
        result = Intent.model_validate(stored)
        if result.submission != intent.submission:
            raise RequestConflict("INTENT_REQUEST_CONFLICT")
        return result

    def get_intent(self, session_id: str, profile_id: str) -> Intent:
        with self.engine.connect() as connection:
            value = connection.execute(
                text("""SELECT payload FROM app.authenticity_intents
                WHERE session_id=:sid AND profile_id=:pid"""),
                {"sid": session_id, "pid": profile_id},
            ).scalar_one_or_none()
        if value is None:
            raise OwnershipError("PROFILE_NOT_FOUND")
        return Intent.model_validate(value)

    def active_release(self) -> Release | None:
        with self.engine.connect() as connection:
            value = connection.execute(
                text("""SELECT r.payload FROM app.authenticity_active a
                JOIN app.authenticity_releases r USING (release_sha256) WHERE a.singleton""")
            ).scalar_one_or_none()
        return Release.model_validate(value) if value is not None else None

    def get_release(self, release_sha256: str) -> tuple[Release, tuple[Assessment, ...]]:
        with self.engine.connect() as connection:
            raw = connection.execute(
                text("SELECT payload FROM app.authenticity_releases WHERE release_sha256=:sha"),
                {"sha": release_sha256},
            ).scalar_one_or_none()
            if raw is None:
                raise ValueError("PINNED_RELEASE_NOT_FOUND")
            release = Release.model_validate(raw)
            hashes = [m.assessment_sha256 for m in release.members]
            rows = connection.execute(
                text("""SELECT assessment_sha256,payload FROM app.authenticity_assessments
                WHERE assessment_sha256 = ANY(:hashes)"""),
                {"hashes": hashes},
            ).all()
        by_hash = {r[0]: Assessment.model_validate(r[1]) for r in rows}
        if set(by_hash) != set(hashes):
            raise ValueError("PINNED_RELEASE_ASSESSMENTS_MISSING")
        assessments = []
        for member in release.members:
            item = by_hash[member.assessment_sha256]
            verify_assessment(item)
            if (
                item.source.place.place_id != member.place_id
                or item.policy.policy_sha256 != release.policy_sha256
            ):
                raise ValueError("PINNED_RELEASE_ASSESSMENT_MISMATCH")
            assessments.append(item)
        return release, tuple(assessments)

    def auxiliary(self, release: Release) -> Auxiliary:
        with self.engine.connect() as connection:
            payload = connection.execute(
                text("SELECT auxiliary FROM app.authenticity_releases WHERE release_sha256=:sha"),
                {"sha": release.release_sha256},
            ).scalar_one()
        result = Auxiliary.model_validate(payload)
        if result.digest != release.auxiliary_sha256:
            raise ValueError("STORED_AUXILIARY_DIGEST_MISMATCH")
        return result

    def find_run(self, session_id: str, request_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    text("""SELECT profile_id,release_sha256,payload FROM app.authenticity_runs
                WHERE session_id=:sid AND request_id=:rid"""),
                    {"sid": session_id, "rid": request_id},
                )
                .mappings()
                .one_or_none()
            )
        return dict(row) if row else None

    def put_run(
        self, session_id: str, request_id: str, release: Release, run: dict[str, Any]
    ) -> dict[str, Any]:
        if run["run_sha256"] != canonical_sha256(
            {k: v for k, v in run.items() if k != "run_sha256"}
        ):
            raise ValueError("RUN_DIGEST_MISMATCH")
        with self.engine.begin() as connection:
            connection.execute(
                text("""INSERT INTO app.authenticity_runs
                (run_sha256,session_id,profile_id,request_id,release_sha256,payload)
                VALUES (:sha,:sid,:pid,:rid,:release,CAST(:payload AS jsonb))
                ON CONFLICT (session_id,request_id) DO NOTHING"""),
                {
                    "sha": run["run_sha256"],
                    "sid": session_id,
                    "pid": run["profile_id"],
                    "rid": request_id,
                    "release": release.release_sha256,
                    "payload": json.dumps(run, ensure_ascii=False),
                },
            )
        stored = self.find_run(session_id, request_id)
        if stored is None or stored["profile_id"] != run["profile_id"]:
            raise RequestConflict("RUN_REQUEST_CONFLICT")
        return dict(stored["payload"])

    def get_run(self, session_id: str, run_id: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    text("""SELECT profile_id,release_sha256,payload FROM app.authenticity_runs
                WHERE session_id=:sid AND run_sha256=:sha"""),
                    {"sid": session_id, "sha": run_id},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise OwnershipError("RUN_NOT_FOUND")
        result = dict(row)
        payload = result["payload"]
        if payload.get("run_sha256") != canonical_sha256(
            {k: v for k, v in payload.items() if k != "run_sha256"}
        ):
            raise ValueError("STORED_RUN_DIGEST_MISMATCH")
        return result

    def put_photo(self, session_id: str, review: object) -> None:
        from itda.authenticity.photo import PhotoReview

        value = PhotoReview.model_validate(review)
        with self.engine.begin() as connection:
            connection.execute(
                text("""INSERT INTO app.authenticity_photo_receipts
                (photo_id,session_id,state,payload) VALUES (:id,:sid,:state,CAST(:payload AS jsonb))
                ON CONFLICT (photo_id) DO UPDATE
                SET state=excluded.state,payload=excluded.payload,updated_at=now()
                WHERE app.authenticity_photo_receipts.session_id=excluded.session_id"""),
                {
                    "id": value.photo_id,
                    "sid": session_id,
                    "state": value.state,
                    "payload": value.model_dump_json(),
                },
            )

    def get_photo(self, session_id: str, photo_id: str) -> object:
        from itda.authenticity.photo import PhotoReview

        with self.engine.connect() as connection:
            raw = connection.execute(
                text(
                    "SELECT payload FROM app.authenticity_photo_receipts "
                    "WHERE session_id=:sid AND photo_id=:id"
                ),
                {"sid": session_id, "id": photo_id},
            ).scalar_one_or_none()
        if raw is None:
            raise OwnershipError("PHOTO_NOT_FOUND")
        return PhotoReview.model_validate(raw)

    def confirmed_photo(self, session_id: str, receipt_sha256: str) -> object:
        from itda.authenticity.photo import PhotoReview

        with self.engine.connect() as connection:
            raw = connection.execute(
                text("""SELECT payload FROM app.authenticity_photo_receipts
                WHERE session_id=:sid AND state='CONFIRMED' AND payload->>'receipt_sha256'=:sha"""),
                {"sid": session_id, "sha": receipt_sha256},
            ).scalar_one_or_none()
        if raw is None:
            raise OwnershipError("CONFIRMED_PHOTO_NOT_FOUND")
        return PhotoReview.model_validate(raw)

    def save(self, session_id: str, run_id: str, place_id: str, *, saved: bool) -> None:
        run = self.get_run(session_id, run_id)["payload"]
        if place_id not in {p["place_id"] for p in run["items"]}:
            raise ValueError("PLACE_NOT_IN_PINNED_RESULTS")
        with self.engine.begin() as connection:
            if saved:
                connection.execute(
                    text("""INSERT INTO app.authenticity_saved(session_id,run_sha256,place_id)
                    VALUES (:sid,:run,:place) ON CONFLICT DO NOTHING"""),
                    {"sid": session_id, "run": run_id, "place": place_id},
                )
            else:
                connection.execute(
                    text("""DELETE FROM app.authenticity_saved
                    WHERE session_id=:sid AND run_sha256=:run AND place_id=:place"""),
                    {"sid": session_id, "run": run_id, "place": place_id},
                )

    def saved(self, session_id: str) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = (
                connection.execute(
                    text("""SELECT run_sha256,place_id,saved_at FROM app.authenticity_saved
                WHERE session_id=:sid ORDER BY saved_at DESC"""),
                    {"sid": session_id},
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def feedback(self, session_id: str, run_id: str, place_id: str, payload: dict[str, Any]) -> str:
        run = self.get_run(session_id, run_id)["payload"]
        if place_id not in {p["place_id"] for p in run["items"]}:
            raise ValueError("FEEDBACK_PLACE_NOT_IN_RESULTS")
        identifier = canonical_sha256(
            {"session": session_id, "run": run_id, "place": place_id, "payload": payload}
        )
        with self.engine.begin() as connection:
            connection.execute(
                text("""INSERT INTO app.authenticity_feedback
                (feedback_id,session_id,run_sha256,place_id,payload)
                VALUES (:id,:sid,:run,:place,CAST(:payload AS jsonb)) ON CONFLICT DO NOTHING"""),
                {
                    "id": identifier,
                    "sid": session_id,
                    "run": run_id,
                    "place": place_id,
                    "payload": json.dumps(payload, ensure_ascii=False),
                },
            )
        return identifier


def install_release(
    engine: Engine, directory: Path, *, expected_previous: str | None, activate: bool
) -> Release:
    release, assessments = load_release(directory)
    validation = json.loads((directory / "validation.json").read_text())
    auxiliary = Auxiliary.model_validate_json((directory / "auxiliary.json").read_bytes())
    with engine.begin() as connection:
        for assessment in assessments:
            connection.execute(
                text("""INSERT INTO app.authenticity_assessments(assessment_sha256,place_id,payload)
                VALUES (:sha,:pid,CAST(:payload AS jsonb)) ON CONFLICT DO NOTHING"""),
                {
                    "sha": assessment.assessment_sha256,
                    "pid": assessment.source.place.place_id,
                    "payload": assessment.model_dump_json(),
                },
            )
        connection.execute(
            text("""INSERT INTO app.authenticity_releases
            (release_sha256,scope,payload,validation,auxiliary)
            VALUES (:sha,:scope,CAST(:payload AS jsonb),
                    CAST(:validation AS jsonb),CAST(:auxiliary AS jsonb))
            ON CONFLICT DO NOTHING"""),
            {
                "sha": release.release_sha256,
                "scope": release.scope,
                "payload": release.model_dump_json(),
                "validation": json.dumps(validation, ensure_ascii=False),
                "auxiliary": auxiliary.model_dump_json(),
            },
        )
        if activate:
            connection.execute(
                text("SELECT pg_advisory_xact_lock(hashtext('itda-authenticity-active'))")
            )
            row = connection.execute(
                text(
                    "SELECT release_sha256,generation FROM app.authenticity_active "
                    "WHERE singleton FOR UPDATE"
                )
            ).one_or_none()
            previous = row[0] if row else None
            if previous != expected_previous:
                raise RequestConflict("ACTIVE_RELEASE_CHANGED")
            connection.execute(
                text("""INSERT INTO app.authenticity_active(singleton,release_sha256,generation)
                VALUES (true,:sha,1) ON CONFLICT (singleton) DO UPDATE
                SET release_sha256=excluded.release_sha256,
                    generation=app.authenticity_active.generation+1,activated_at=now()"""),
                {"sha": release.release_sha256},
            )
    return release
