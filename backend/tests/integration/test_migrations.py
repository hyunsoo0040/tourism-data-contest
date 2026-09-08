from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError, ProgrammingError

from itda.db.session import sqlalchemy_url_from_dsn
from tests.integration.profile_release_test_support import (
    ensure_photo_lifecycle_roles,
    ensure_profile_release_authority_roles,
    ensure_profile_session_roles,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALEMBIC_CONFIG = REPOSITORY_ROOT / "backend" / "alembic.ini"


def _config(postgres_harness: object) -> Config:
    # Provision the fixed authority roles migrations 0014/0018/0019 require
    # before building the config so every upgrade reaches head.
    ensure_profile_release_authority_roles(postgres_harness)  # type: ignore[arg-type]
    ensure_profile_session_roles(postgres_harness)  # type: ignore[arg-type]
    ensure_photo_lifecycle_roles(postgres_harness)  # type: ignore[arg-type]
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option(
        "sqlalchemy.url",
        sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]).render_as_string(
            hide_password=False
        ),
    )
    config.attributes["runtime_role"] = postgres_harness.role_names["runtime"]
    config.attributes["database_name"] = postgres_harness.database_name
    config.attributes["profile_release_authorization_hmac_key"] = "41" * 32
    for capability in ("dev", "sealer", "evaluator"):
        config.attributes[f"{capability}_role"] = postgres_harness.role_names[capability]
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    ensure_profile_release_authority_roles(postgres_harness)
    ensure_photo_lifecycle_roles(postgres_harness)
    return config


def test_blank_postgres_migrates_downgrades_and_reupgrades(postgres_harness: object) -> None:
    config = _config(postgres_harness)
    engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))

    command.upgrade(config, "head")
    command.check(config)
    inspector = inspect(engine)
    assert set(inspector.get_table_names(schema="app")) == {
        "journey_drafts",
        "preference_profiles",
    }
    assert {"dev_eval", "blind_eval"}.issubset(inspector.get_schema_names())
    assert inspector.get_table_names(schema="dev_eval") == [
        "daily_glm_attempts",
        "daily_glm_input_snapshots",
        "daily_glm_refresh_runs",
        "daily_glm_scoring_plans",
        "daily_scored_release_active",
        "daily_scored_release_activations",
        "daily_scored_releases",
        "manifest_members",
        "photo_confirmation_receipts",
        "photo_confirmed_traits",
        "photo_deletion_ledger",
        "photo_job_dispatch_markers",
        "photo_job_filesystem_bindings",
        "photo_jobs",
        "photo_review_drafts",
        "photo_trait_candidates",
    ]
    assert set(inspector.get_table_names(schema="blind_eval")) == {
        "manifest_members",
        "manifest_seals",
    }
    assert set(inspector.get_view_names(schema="blind_eval")) == {
        "evaluator_manifest_v1",
        "internal_manifest_v1",
    }
    assert all(
        forbidden not in column["name"].lower()
        for table in ("journey_drafts", "preference_profiles")
        for column in inspector.get_columns(table, schema="app")
        for forbidden in ("photo", "image", "blob", "exif")
    )

    for invalid_value in (6, "3"):
        invalid_answers = {f"q{number}": 3 for number in range(1, 10)}
        invalid_answers["q9"] = invalid_value
        with engine.connect() as connection, pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO app.journey_drafts (
                        session_id, trip_conditions, answers, questionnaire_version, updated_at
                    ) VALUES (
                        :session_id, CAST(:trip_conditions AS jsonb), CAST(:answers AS jsonb),
                        :questionnaire_version, '2026-07-22T12:00:00+00:00'
                    )
                    """
                ),
                {
                    "session_id": f"synthetic:invalid-draft:{invalid_value}",
                    "trip_conditions": json.dumps({"visit_time": "UNDECIDED"}),
                    "answers": json.dumps(invalid_answers),
                    "questionnaire_version": "questionnaire-v1",
                },
            )

    command.downgrade(config, "base")
    assert not {"app", "dev_eval", "blind_eval"}.intersection(inspect(engine).get_schema_names())
    for capability in ("runtime", "dev", "sealer", "evaluator"):
        capability_engine = create_engine(
            sqlalchemy_url_from_dsn(postgres_harness.dsns[capability])
        )
        with capability_engine.connect() as connection:
            search_path = connection.execute(
                text("SELECT current_setting('search_path')")
            ).scalar_one()
            assert not {"app", "dev_eval", "blind_eval"}.intersection(search_path.split(", "))
        capability_engine.dispose()

    command.upgrade(config, "head")
    assert set(inspect(engine).get_table_names(schema="app")) == {
        "journey_drafts",
        "preference_profiles",
    }
    assert inspector.get_table_names(schema="dev_eval") == [
        "daily_glm_attempts",
        "daily_glm_input_snapshots",
        "daily_glm_refresh_runs",
        "daily_glm_scoring_plans",
        "daily_scored_release_active",
        "daily_scored_release_activations",
        "daily_scored_releases",
        "manifest_members",
        "photo_confirmation_receipts",
        "photo_confirmed_traits",
        "photo_deletion_ledger",
        "photo_job_dispatch_markers",
        "photo_job_filesystem_bindings",
        "photo_jobs",
        "photo_review_drafts",
        "photo_trait_candidates",
    ]
    assert set(inspect(engine).get_table_names(schema="blind_eval")) == {
        "manifest_members",
        "manifest_seals",
    }
    engine.dispose()


def test_0023_photo_projection_migration_upgrades_downgrades_and_reupgrades(
    postgres_harness: object,
) -> None:
    config = _config(postgres_harness)
    engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    signature = "dev_eval.read_photo_recommendation_projection_v1(text,text)"
    try:
        command.downgrade(config, "base")
        command.upgrade(config, "0022_questionnaire_v2_choice_answers")
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT to_regprocedure(:signature)"), {"signature": signature}
            ).scalar_one_or_none() is None

        command.upgrade(config, "0023_photo_recommendation_projection_authority")
        with engine.connect() as connection:
            assert str(
                connection.execute(
                    text("SELECT to_regprocedure(:signature)"), {"signature": signature}
                ).scalar_one()
            ) == signature

        command.downgrade(config, "0022_questionnaire_v2_choice_answers")
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT to_regprocedure(:signature)"), {"signature": signature}
            ).scalar_one_or_none() is None
    finally:
        command.upgrade(config, "head")
        engine.dispose()


def test_runtime_role_is_limited_to_app_schema(postgres_harness: object) -> None:
    config = _config(postgres_harness)
    command.upgrade(config, "head")
    runtime_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["runtime"]))
    admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    with admin_engine.begin() as connection:
        connection.execute(text("CREATE SCHEMA runtime_forbidden"))
        connection.execute(text("CREATE TABLE runtime_forbidden.private_rows (id integer)"))

    with runtime_engine.connect() as connection:
        current = connection.execute(
            text("SELECT current_user, current_setting('search_path')")
        ).one()
        assert current[0] == postgres_harness.role_names["runtime"]
        assert current[1] == "app, pg_catalog"
        count = connection.execute(text("SELECT count(*) FROM preference_profiles")).scalar_one()
        assert count == 0

    for forbidden_sql in (
        "SELECT * FROM runtime_forbidden.private_rows",
        "CREATE TABLE app.runtime_must_not_create (id integer)",
    ):
        with runtime_engine.connect() as connection, pytest.raises(ProgrammingError):
            connection.execute(text(forbidden_sql))

    with admin_engine.begin() as connection:
        connection.execute(text("DROP SCHEMA runtime_forbidden CASCADE"))
    admin_engine.dispose()
    runtime_engine.dispose()


def test_split_migration_rejects_colliding_capability_roles(
    postgres_harness: object,
) -> None:
    valid_config = _config(postgres_harness)
    command.downgrade(valid_config, "base")
    colliding_config = _config(postgres_harness)
    colliding_config.attributes["evaluator_role"] = postgres_harness.role_names["sealer"]

    try:
        with pytest.raises(ValueError, match="capability role identifiers must be distinct"):
            command.upgrade(colliding_config, "head")
        admin_engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
        try:
            assert not {"dev_eval", "blind_eval"}.intersection(
                inspect(admin_engine).get_schema_names()
            )
        finally:
            admin_engine.dispose()
    finally:
        command.upgrade(valid_config, "head")


def test_libpq_security_and_routing_options_survive_url_conversion() -> None:
    url = sqlalchemy_url_from_dsn(
        "host=db.example dbname=itda user=app password=secret "
        "sslmode=require connect_timeout=9 application_name=itda "
        "target_session_attrs=read-write"
    )

    assert url.query == {
        "sslmode": "require",
        "connect_timeout": "9",
        "application_name": "itda",
        "target_session_attrs": "read-write",
    }


def test_offline_migration_emits_runtime_grants_without_connecting(
    postgres_harness: object,
) -> None:
    config = _config(postgres_harness)
    output = StringIO()
    config.output_buffer = output

    command.upgrade(config, "head", sql=True)

    sql = output.getvalue()
    assert f"GRANT USAGE ON SCHEMA app TO {postgres_harness.role_names['runtime']}" in sql
    assert "SET search_path TO app, pg_catalog" in sql


def test_initial_migration_freezes_its_answer_constraint() -> None:
    migration = (
        REPOSITORY_ROOT / "backend" / "migrations" / "versions" / "0001_app_profiles.py"
    ).read_text()

    assert "itda.db.models" not in migration


def test_recommendation_binding_successor_migration_hardens_existing_0016(
    postgres_harness: object,
) -> None:
    """A database stamped at 0016 receives the complete composite invariant at head."""

    config = _config(postgres_harness)
    config.attributes["label_builder_role"] = postgres_harness.role_names["dev"]
    ensure_profile_release_authority_roles(postgres_harness)
    command.downgrade(config, "base")
    command.upgrade(config, "0016_recommendation_request_bindings")
    engine = create_engine(sqlalchemy_url_from_dsn(postgres_harness.dsns["admin"]))
    answers = json.dumps({f"q{number}": 3 for number in range(1, 10)})
    with engine.begin() as connection:
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
                    'migration-profile-001', 'migration-request-001',
                    '{}'::jsonb, CAST(:answers AS jsonb),
                    5000, 50, 5000, 50, 5000, 50, 'migration test',
                    'preference-profile-v1', 'questionnaire-v1', 'scoring-v1',
                    'description-v1', :config_hash, '2026-08-16T00:00:00+00:00', TRUE
                )
                """
            ),
            {"answers": answers, "config_hash": "a" * 64},
        )
        connection.execute(
            text(
                """
                INSERT INTO app.recommendation_runs (
                    run_id, request_id, preference_profile_id, input_digest,
                    release_sha256, canonical_membership_sha256, config_sha256,
                    kernel_version, receipt_sha256, receipt, created_at
                ) VALUES (
                    'migration-run-001', 'migration-run-request-001',
                    'migration-profile-001', :input_digest,
                    :release_sha256, :membership_sha256, :config_sha256,
                    'kernel-v1', :receipt_sha256, '{}'::jsonb,
                    '2026-08-16T00:00:00+00:00'
                )
                """
            ),
            {
                "input_digest": "b" * 64,
                "release_sha256": "c" * 64,
                "membership_sha256": "d" * 64,
                "config_sha256": "e" * 64,
                "receipt_sha256": "f" * 64,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO app.recommendation_request_bindings (
                    request_id, run_id, preference_profile_id, input_digest, created_at
                ) VALUES (
                    'migration-alias-001', 'migration-run-001',
                    'migration-profile-001', :input_digest,
                    '2026-08-16T00:00:00+00:00'
                )
                """
            ),
            {"input_digest": "b" * 64},
        )

    command.upgrade(config, "head")
    with engine.connect() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                """
                INSERT INTO app.recommendation_request_bindings (
                    request_id, run_id, preference_profile_id, input_digest, created_at
                ) VALUES (
                    'migration-alias-cross-generation', 'migration-run-001',
                    'migration-profile-001', :input_digest,
                    '2026-08-16T00:00:00+00:00'
                )
                """
            ),
            {"input_digest": "0" * 64},
        )
    engine.dispose()
