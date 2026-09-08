"""Real-PostgreSQL evidence for migration 0022 version-coupled answer checks.

Covers: upgrade to 0022 from a v1-seeded 0021 database, constraint names and
explicit key/type/range check form, v2 row insertion and rejection at head,
legacy v1 persistence/replay at head, and the fail-closed downgrade that
restores the exact legacy constraint only when zero v2 rows exist.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from itda.contracts.base import ExperienceAxis
from itda.contracts.preference import PreferenceProfile, QuestionnaireAnswersV1, TripConditions
from itda.contracts.questionnaire import QUESTIONNAIRE_DEFINITION, SCORING_CONFIG
from itda.db.session import sqlalchemy_url_from_dsn
from itda.domain.preference import replay_legacy_v1_profile, score_axis
from tests.integration.test_migrations import _config

CREATED_AT = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)

_V1_ANSWERS = {f"q{number}": 3 for number in range(1, 10)}
_V2_ANSWERS = {f"q{number}": 2 for number in range(1, 13)}


def _legacy_v1_profile(profile_id: str, request_id: str) -> PreferenceProfile:
    answers_by_number = {
        question.ordinal: _V1_ANSWERS[question.question_id]
        for question in QUESTIONNAIRE_DEFINITION.questions
    }
    axis_questions = SCORING_CONFIG["axis_questions"]
    scores = tuple(
        score_axis(
            axis,
            *(answers_by_number[number] for number in axis_questions[axis]),  # type: ignore[arg-type]
        )
        for axis in (ExperienceAxis.HISTORY_TRADITION, ExperienceAxis.EMOTION_IMAGE,
                     ExperienceAxis.REST_IMMERSION)
    )
    return PreferenceProfile(
        profile_id=profile_id,
        request_id=request_id,
        trip_conditions=TripConditions.model_validate(
            {
                "visit_date": None,
                "visit_time": "UNDECIDED",
                "companion": "SOLO",
                "transport": "WALK_OR_TRANSIT",
                "walking_tolerance": "ABOUT_1_HOUR",
                "indoor_outdoor_preference": "NO_PREFERENCE",
                "crowd_avoidance": "MEDIUM",
            }
        ),
        answers=QuestionnaireAnswersV1.model_validate(_V1_ANSWERS),
        scores=scores,  # type: ignore[arg-type]
        description_ko="migration evidence profile",
        schema_version="preference-profile-v1",
        questionnaire_version="questionnaire-v1",
        scoring_version="integer-bp-v1",
        description_template_version="current-trip-expectation-v1",
        config_hash="bc24c1ca59272397bf0dad41be34cf536b6cb6215d3148567d09fbebd749b09c",
        created_at=CREATED_AT,
    )


def _insert_v1_profile(engine: object, profile_id: str, request_id: str) -> None:
    profile = _legacy_v1_profile(profile_id, request_id)
    scores = {score.axis: score for score in profile.scores}
    history = scores[ExperienceAxis.HISTORY_TRADITION]
    emotion = scores[ExperienceAxis.EMOTION_IMAGE]
    rest = scores[ExperienceAxis.REST_IMMERSION]
    with engine.begin() as connection:  # type: ignore[attr-defined]
        connection.execute(
            text(
                """
                INSERT INTO app.preference_profiles (
                    profile_id, request_id, trip_conditions, answers,
                    history_basis_points, history_display_score,
                    emotion_basis_points, emotion_display_score,
                    rest_basis_points, rest_display_score, description_ko,
                    schema_version, questionnaire_version, scoring_version,
                    description_template_version, config_hash, created_at,
                    is_current_trip_expectation
                ) VALUES (
                    :profile_id, :request_id, '{}'::jsonb, CAST(:answers AS jsonb),
                    :h_bp, :h_display, :e_bp, :e_display, :r_bp, :r_display,
                    :description_ko, :schema_version, :questionnaire_version,
                    :scoring_version, :description_template_version, :config_hash,
                    :created_at, TRUE
                )
                """
            ),
            {
                "profile_id": profile.profile_id,
                "request_id": profile.request_id,
                "answers": profile.answers.model_dump_json(),
                "h_bp": history.basis_points,
                "h_display": history.display_score,
                "e_bp": emotion.basis_points,
                "e_display": emotion.display_score,
                "r_bp": rest.basis_points,
                "r_display": rest.display_score,
                "description_ko": profile.description_ko,
                "schema_version": profile.schema_version,
                "questionnaire_version": profile.questionnaire_version,
                "scoring_version": profile.scoring_version,
                "description_template_version": profile.description_template_version,
                "config_hash": profile.config_hash,
                "created_at": profile.created_at,
            },
        )


def _answers_constraint_definitions(engine: object) -> dict[str, str]:
    rows: dict[str, str] = {}
    with engine.connect() as connection:  # type: ignore[attr-defined]
        for table, name in (
            ("journey_drafts", "ck_journey_drafts_ck_draft_answers"),
            ("preference_profiles", "ck_preference_profiles_ck_profile_answers"),
        ):
            definition = connection.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = :name "
                    "AND conrelid = CAST('app.' || CAST(:table AS text) AS regclass)"
                ),
                {"name": name, "table": table},
            ).scalar_one()
            rows[name] = str(definition)
    return rows


def test_0022_version_coupled_checks_survive_upgrade_and_fail_closed_downgrade(
    postgres_harness: object,
) -> None:
    config = _config(postgres_harness)
    command.downgrade(config, "base")
    command.upgrade(config, "0021_phase6_proof_bound_photo_terminal_authority")
    engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))

    # Seed a legacy v1 profile at 0021, exactly as production holds it.
    _insert_v1_profile(engine, "migration-profile-v1-0022", "migration-request-v1-0022")

    # Upgrade to 0022: the exact 0001 constraint names are version-coupled now.
    command.upgrade(config, "0022_questionnaire_v2_choice_answers")
    definitions = _answers_constraint_definitions(engine)
    assert all("questionnaire-v2" in definition for definition in definitions.values())
    assert all("jsonb_each_text" not in definition for definition in definitions.values())
    assert all("NOT EXISTS" not in definition for definition in definitions.values())
    # The explicit 0001 key/type/range form includes a per-key JSON number
    # type predicate; string-typed answers cannot satisfy it. PostgreSQL
    # normalizes the rendered SQL (spacing and explicit ::text casts), so
    # match with a whitespace-tolerant pattern per checked key.
    for definition in definitions.values():
        for number in (1, 5, 9, 12):
            pattern = (
                rf"jsonb_typeof\(\(?answers -> 'q{number}'(::text)?\)\) = 'number'(::text)?"
            )
            assert re.search(pattern, definition) is not None, definition[:400]

    # The seeded legacy v1 row still validates under the version-coupled check.
    v1_count = 0
    with engine.connect() as connection:
        v1_count = connection.execute(
            text(
                "SELECT count(*) FROM app.preference_profiles "
                "WHERE profile_id = 'migration-profile-v1-0022'"
            )
        ).scalar_one()
    assert v1_count == 1

    # Legacy v1 read/replay through the strict contract round-trips exactly.
    stored = None
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT answers FROM app.preference_profiles "
                "WHERE profile_id = 'migration-profile-v1-0022'"
            )
        ).one()
    stored = QuestionnaireAnswersV1.model_validate(row[0])
    replayed_profile = _legacy_v1_profile(
        "migration-profile-v1-0022", "migration-request-v1-0022"
    )
    assert stored == replayed_profile.answers
    scores = replay_legacy_v1_profile(replayed_profile)
    assert [score.basis_points for score in scores] == [
        score.basis_points for score in replayed_profile.scores
    ]

    # New v2 rows are accepted at head.
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-v2-0022', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v2', :updated_at
                )
                """
            ),
            {"answers": json.dumps(_V2_ANSWERS), "updated_at": CREATED_AT},
        )

    # v2 out-of-range values are rejected by the version-coupled check.
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-v2-bad', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v2', :updated_at
                )
                """
            ),
            {"answers": json.dumps(_V2_ANSWERS | {"q1": 4}), "updated_at": CREATED_AT},
        )

    # JSON numeric strings are not numbers: the per-key jsonb_typeof
    # predicate rejects {"q1":"1",...} for both generations.
    v1_string_answers = {f"q{number}": "3" for number in range(1, 10)}
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-v1-strings', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v1', :updated_at
                )
                """
            ),
            {"answers": json.dumps(v1_string_answers), "updated_at": CREATED_AT},
        )
    v2_string_answers = {f"q{number}": "2" for number in range(1, 13)}
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-v2-strings', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v2', :updated_at
                )
                """
            ),
            {"answers": json.dumps(v2_string_answers), "updated_at": CREATED_AT},
        )

    # v2 answers on a v1 row are rejected; v1 answers on a v2 row are rejected.
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-mismatched-1', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v1', :updated_at
                )
                """
            ),
            {"answers": json.dumps(_V2_ANSWERS), "updated_at": CREATED_AT},
        )
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-mismatched-2', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v2', :updated_at
                )
                """
            ),
            {"answers": json.dumps(_V1_ANSWERS), "updated_at": CREATED_AT},
        )

    # Downgrade is fail-closed while v2 rows exist.
    with pytest.raises(RuntimeError, match="requires zero questionnaire-v2 rows"):
        command.downgrade(config, "0021_phase6_proof_bound_photo_terminal_authority")

    # Removing the v2 rows unblocks the downgrade, which restores exactly the
    # legacy v1 constraint form under the same 0001 names.
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM app.journey_drafts WHERE questionnaire_version = 'questionnaire-v2'")
        )
    command.downgrade(config, "0021_phase6_proof_bound_photo_terminal_authority")
    legacy_definitions = _answers_constraint_definitions(engine)
    for definition in legacy_definitions.values():
        assert "questionnaire-v2" not in definition
        assert "jsonb_each_text" not in definition
        assert "NOT EXISTS" not in definition
        assert "q10" not in definition
        # The restored legacy check keeps 0001's per-key JSON number predicate.
        assert (
            re.search(
                r"jsonb_typeof\(\(?answers -> 'q1'(::text)?\)\) = 'number'(::text)?",
                definition,
            )
            is not None
        )
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.journey_drafts (
                    session_id, trip_conditions, answers, questionnaire_version, updated_at
                ) VALUES (
                    'migration-draft-v2-post-downgrade', '{}'::jsonb,
                    CAST(:answers AS jsonb), 'questionnaire-v2', :updated_at
                )
                """
            ),
            {"answers": json.dumps(_V2_ANSWERS), "updated_at": CREATED_AT},
        )

    # The legacy v1 profile row survived the entire upgrade/downgrade cycle.
    with engine.connect() as connection:
        surviving = connection.execute(
            text(
                "SELECT count(*) FROM app.preference_profiles "
                "WHERE profile_id = 'migration-profile-v1-0022'"
            )
        ).scalar_one()
    assert surviving == 1
    engine.dispose()
