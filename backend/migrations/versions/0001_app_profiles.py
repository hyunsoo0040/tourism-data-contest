"""Create the application-owned anonymous journey and profile store."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_app_profiles"
down_revision = None
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _frozen_answers_check_sql(column: str = "answers") -> str:
    required_keys = ", ".join(f"'q{number}'" for number in range(1, 10))
    value_checks = " AND ".join(
        (
            f"jsonb_typeof({column}->'q{number}') = 'number' "
            f"AND ({column}->>'q{number}') ~ '^[1-5]$'"
        )
        for number in range(1, 10)
    )
    return (
        f"jsonb_typeof({column}) = 'object' "
        f"AND {column} ?& ARRAY[{required_keys}] "
        f"AND ({column} - ARRAY[{required_keys}]) = '{{}}'::jsonb "
        f"AND {value_checks}"
    )


def _configured_identifier(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid PostgreSQL identifier for {name}")
    return value


def _grant_runtime_access() -> None:
    runtime_role = _configured_identifier("runtime_role")
    if runtime_role is None:
        return
    bind = op.get_bind()
    quote = bind.dialect.identifier_preparer.quote
    quoted_role = quote(runtime_role)
    op.execute(sa.text(f"GRANT USAGE ON SCHEMA app TO {quoted_role}"))
    op.execute(
        sa.text(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app "
            f"TO {quoted_role}"
        )
    )

    database_name = _configured_identifier("database_name")
    if database_name is not None:
        op.execute(
            sa.text(
                f"ALTER ROLE {quoted_role} IN DATABASE {quote(database_name)} "
                "SET search_path TO app, pg_catalog"
            )
        )


def _reset_runtime_search_path() -> None:
    runtime_role = _configured_identifier("runtime_role")
    database_name = _configured_identifier("database_name")
    if runtime_role is None or database_name is None:
        return
    bind = op.get_bind()
    quote = bind.dialect.identifier_preparer.quote
    op.execute(
        sa.text(
            f"ALTER ROLE {quote(runtime_role)} IN DATABASE {quote(database_name)} "
            "RESET search_path"
        )
    )


def upgrade() -> None:
    op.execute("CREATE SCHEMA app")
    op.create_table(
        "journey_drafts",
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("trip_conditions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("answers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("questionnaire_version", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("char_length(session_id) BETWEEN 1 AND 160", name="ck_draft_session"),
        sa.CheckConstraint(
            "jsonb_typeof(trip_conditions) = 'object'", name="ck_draft_trip_conditions"
        ),
        sa.CheckConstraint(_frozen_answers_check_sql(), name="ck_draft_answers"),
        sa.CheckConstraint(
            "char_length(questionnaire_version) BETWEEN 1 AND 128",
            name="ck_draft_questionnaire_version",
        ),
        sa.PrimaryKeyConstraint("session_id", name="pk_journey_drafts"),
        schema="app",
    )
    op.create_table(
        "preference_profiles",
        sa.Column("profile_id", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("trip_conditions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("answers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("history_basis_points", sa.Integer(), nullable=False),
        sa.Column("history_display_score", sa.Integer(), nullable=False),
        sa.Column("emotion_basis_points", sa.Integer(), nullable=False),
        sa.Column("emotion_display_score", sa.Integer(), nullable=False),
        sa.Column("rest_basis_points", sa.Integer(), nullable=False),
        sa.Column("rest_display_score", sa.Integer(), nullable=False),
        sa.Column("description_ko", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("questionnaire_version", sa.Text(), nullable=False),
        sa.Column("scoring_version", sa.Text(), nullable=False),
        sa.Column("description_template_version", sa.Text(), nullable=False),
        sa.Column("config_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_current_trip_expectation", sa.Boolean(), nullable=False),
        sa.CheckConstraint("char_length(profile_id) BETWEEN 1 AND 160", name="ck_profile_id"),
        sa.CheckConstraint("char_length(request_id) BETWEEN 1 AND 160", name="ck_request_id"),
        sa.CheckConstraint(
            "jsonb_typeof(trip_conditions) = 'object'", name="ck_profile_trip_conditions"
        ),
        sa.CheckConstraint(_frozen_answers_check_sql(), name="ck_profile_answers"),
        sa.CheckConstraint(
            "history_basis_points BETWEEN 0 AND 10000", name="ck_profile_history_bp"
        ),
        sa.CheckConstraint(
            "emotion_basis_points BETWEEN 0 AND 10000", name="ck_profile_emotion_bp"
        ),
        sa.CheckConstraint("rest_basis_points BETWEEN 0 AND 10000", name="ck_profile_rest_bp"),
        sa.CheckConstraint(
            "history_display_score BETWEEN 0 AND 100", name="ck_profile_history_display"
        ),
        sa.CheckConstraint(
            "emotion_display_score BETWEEN 0 AND 100", name="ck_profile_emotion_display"
        ),
        sa.CheckConstraint(
            "rest_display_score BETWEEN 0 AND 100", name="ck_profile_rest_display"
        ),
        sa.CheckConstraint(
            "history_display_score = (history_basis_points + 50) / 100",
            name="ck_profile_history_rounding",
        ),
        sa.CheckConstraint(
            "emotion_display_score = (emotion_basis_points + 50) / 100",
            name="ck_profile_emotion_rounding",
        ),
        sa.CheckConstraint(
            "rest_display_score = (rest_basis_points + 50) / 100",
            name="ck_profile_rest_rounding",
        ),
        sa.CheckConstraint(
            "char_length(description_ko) BETWEEN 1 AND 500", name="ck_profile_description"
        ),
        sa.CheckConstraint(
            "char_length(schema_version) BETWEEN 1 AND 128", name="ck_profile_schema_version"
        ),
        sa.CheckConstraint(
            "char_length(questionnaire_version) BETWEEN 1 AND 128",
            name="ck_profile_questionnaire_version",
        ),
        sa.CheckConstraint(
            "char_length(scoring_version) BETWEEN 1 AND 128", name="ck_profile_scoring_version"
        ),
        sa.CheckConstraint(
            "char_length(description_template_version) BETWEEN 1 AND 128",
            name="ck_profile_template_version",
        ),
        sa.CheckConstraint("config_hash ~ '^[0-9a-f]{64}$'", name="ck_profile_config_hash"),
        sa.CheckConstraint("is_current_trip_expectation", name="ck_profile_current_trip"),
        sa.PrimaryKeyConstraint("profile_id", name="pk_preference_profiles"),
        sa.UniqueConstraint("request_id", name="uq_preference_profiles_request_id"),
        schema="app",
    )
    _grant_runtime_access()


def downgrade() -> None:
    _reset_runtime_search_path()
    op.drop_table("preference_profiles", schema="app")
    op.drop_table("journey_drafts", schema="app")
    op.execute("DROP SCHEMA app")
