from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError

from itda.contracts.preference import QuestionnaireSubmission
from itda.contracts.questionnaire import QUESTIONNAIRE_DEFINITION
from itda.db.repositories import JourneyDraft, JourneyDraftRepository, ProfileRepository
from itda.db.session import create_database_engine, create_session_factory, sqlalchemy_url_from_dsn
from itda.domain.preference import calculate_preference

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"
CREATED_AT = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def _submission(request_id: str, *, answer: int = 3) -> QuestionnaireSubmission:
    return QuestionnaireSubmission.model_validate(
        {
            "request_id": request_id,
            "trip_conditions": {
                "visit_date": "2026-10-09",
                "visit_time": "SUNSET",
                "companion": "FRIEND_OR_PARTNER",
                "transport": "MIXED",
                "walking_tolerance": "ABOUT_1_HOUR",
                "indoor_outdoor_preference": "NO_PREFERENCE",
                "crowd_avoidance": "HIGH",
            },
            "answers": {f"q{number}": answer for number in range(1, 10)},
        }
    )


def _migrate(postgres_harness: object) -> None:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["runtime_role"] = postgres_harness.role_names["runtime"]
    config.attributes["database_name"] = postgres_harness.database_name
    command.upgrade(config, "head")


@pytest.fixture
def repositories(
    postgres_harness: object,
) -> Iterator[tuple[ProfileRepository, JourneyDraftRepository, Engine]]:
    _migrate(postgres_harness)
    admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    with admin_engine.begin() as connection:
        connection.execute(text("TRUNCATE app.preference_profiles, app.journey_drafts"))
    admin_engine.dispose()

    runtime_engine = create_database_engine(postgres_harness.dsns["runtime"])
    factory = create_session_factory(runtime_engine)
    yield ProfileRepository(factory), JourneyDraftRepository(factory), runtime_engine
    runtime_engine.dispose()


def test_profile_round_trip_preserves_every_version_and_value(
    repositories: tuple[ProfileRepository, JourneyDraftRepository, Engine],
) -> None:
    profiles, _, _ = repositories
    expected = calculate_preference(
        _submission("anonymous:request:round-trip"),
        created_at=CREATED_AT,
    )

    created = profiles.create(expected)

    assert created == expected
    assert profiles.get(expected.profile_id) == expected
    assert profiles.get_by_request_id(expected.request_id) == expected


def test_anonymous_draft_round_trip_supports_edits(
    repositories: tuple[ProfileRepository, JourneyDraftRepository, Engine],
) -> None:
    _, drafts, _ = repositories
    first_submission = _submission("anonymous:session:draft", answer=2)
    first = JourneyDraft(
        session_id=first_submission.request_id,
        trip_conditions=first_submission.trip_conditions,
        answers=first_submission.answers,
        questionnaire_version=QUESTIONNAIRE_DEFINITION.questionnaire_version,
        updated_at=CREATED_AT,
    )
    edited_submission = _submission("anonymous:session:draft", answer=4)
    edited = JourneyDraft(
        session_id=edited_submission.request_id,
        trip_conditions=edited_submission.trip_conditions,
        answers=edited_submission.answers,
        questionnaire_version=QUESTIONNAIRE_DEFINITION.questionnaire_version,
        updated_at=CREATED_AT + timedelta(minutes=2),
    )

    drafts.save(first)
    drafts.save(edited)

    assert drafts.get(first.session_id) == edited


def test_failed_profile_write_rolls_back_without_poisoning_next_transaction(
    repositories: tuple[ProfileRepository, JourneyDraftRepository, Engine],
) -> None:
    profiles, _, engine = repositories
    original = calculate_preference(
        _submission("anonymous:request:rollback"),
        created_at=CREATED_AT,
    )
    duplicate_request = original.model_copy(update={"profile_id": "profile:duplicate-request"})
    following = calculate_preference(
        _submission("anonymous:request:after-rollback", answer=4),
        created_at=CREATED_AT + timedelta(seconds=1),
    )

    profiles.create(original)
    with pytest.raises(IntegrityError):
        profiles.create(duplicate_request)
    profiles.create(following)

    assert profiles.get(original.profile_id) == original
    assert profiles.get(following.profile_id) == following
    with engine.connect() as connection:
        count = connection.execute(text("SELECT count(*) FROM preference_profiles")).scalar_one()
    assert count == 2


def test_missing_ids_return_none(
    repositories: tuple[ProfileRepository, JourneyDraftRepository, Engine],
) -> None:
    profiles, drafts, _ = repositories

    assert profiles.get("profile:missing") is None
    assert profiles.get_by_request_id("request:missing") is None
    assert drafts.get("session:missing") is None


def test_repository_source_has_no_evaluation_schema_access() -> None:
    source = (REPOSITORY_ROOT / "backend" / "src" / "itda" / "db" / "repositories.py")
    repository_source = source.read_text()

    assert "dev_eval" not in repository_source
    assert "blind_eval" not in repository_source
