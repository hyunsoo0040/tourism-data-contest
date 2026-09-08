"""Add immutable recommendation run receipts and release/result pins."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015_phase5_recommendations"
down_revision = "0014_phase4_profile_release_write_boundary"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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
    quoted = op.get_bind().dialect.identifier_preparer.quote(runtime_role)
    op.execute(
        sa.text(
            "GRANT SELECT, INSERT ON app.recommendation_runs, "
            f"app.recommendation_result_pins TO {quoted}"
        )
    )


def upgrade() -> None:
    op.create_table(
        "recommendation_runs",
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("preference_profile_id", sa.Text(), nullable=False),
        sa.Column("input_digest", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("canonical_membership_sha256", sa.Text(), nullable=False),
        sa.Column("config_sha256", sa.Text(), nullable=False),
        sa.Column("kernel_version", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("receipt", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("char_length(run_id) BETWEEN 1 AND 160", name="ck_run_id"),
        sa.CheckConstraint("char_length(request_id) BETWEEN 1 AND 160", name="ck_run_request_id"),
        sa.CheckConstraint(
            "char_length(preference_profile_id) BETWEEN 1 AND 160",
            name="ck_run_preference_profile_id",
        ),
        sa.CheckConstraint("input_digest ~ '^[0-9a-f]{64}$'", name="ck_run_input_digest"),
        sa.CheckConstraint("release_sha256 ~ '^[0-9a-f]{64}$'", name="ck_run_release"),
        sa.CheckConstraint(
            "canonical_membership_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_run_membership",
        ),
        sa.CheckConstraint("config_sha256 ~ '^[0-9a-f]{64}$'", name="ck_run_config"),
        sa.CheckConstraint("receipt_sha256 ~ '^[0-9a-f]{64}$'", name="ck_run_receipt"),
        sa.CheckConstraint("jsonb_typeof(receipt) = 'object'", name="ck_run_receipt_json"),
        sa.ForeignKeyConstraint(
            ["preference_profile_id"],
            ["app.preference_profiles.profile_id"],
            name="fk_recommendation_runs_preference_profile",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("run_id", name="pk_recommendation_runs"),
        sa.UniqueConstraint("request_id", name="uq_recommendation_runs_request_id"),
        sa.UniqueConstraint("receipt_sha256", name="uq_recommendation_runs_receipt_sha256"),
        schema="app",
    )
    op.create_index(
        "ix_recommendation_runs_release_sha256",
        "recommendation_runs",
        ["release_sha256"],
        schema="app",
    )
    op.create_table(
        "recommendation_result_pins",
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("canonical_membership_sha256", sa.Text(), nullable=False),
        sa.Column("config_sha256", sa.Text(), nullable=False),
        sa.Column("kernel_version", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("snapshot_sha256", sa.Text(), nullable=False),
        sa.Column(
            "release_snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("release_sha256 ~ '^[0-9a-f]{64}$'", name="ck_pin_release"),
        sa.CheckConstraint(
            "canonical_membership_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_pin_membership",
        ),
        sa.CheckConstraint("config_sha256 ~ '^[0-9a-f]{64}$'", name="ck_pin_config"),
        sa.CheckConstraint("receipt_sha256 ~ '^[0-9a-f]{64}$'", name="ck_pin_receipt"),
        sa.CheckConstraint("snapshot_sha256 ~ '^[0-9a-f]{64}$'", name="ck_pin_snapshot"),
        sa.CheckConstraint(
            "jsonb_typeof(release_snapshot) = 'object'",
            name="ck_pin_snapshot_json",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["app.recommendation_runs.run_id"],
            name="fk_recommendation_result_pins_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("run_id", name="pk_recommendation_result_pins"),
        schema="app",
    )
    op.create_index(
        "ix_recommendation_result_pins_release_sha256",
        "recommendation_result_pins",
        ["release_sha256"],
        schema="app",
    )
    _grant_runtime_access()


def downgrade() -> None:
    op.drop_index(
        "ix_recommendation_result_pins_release_sha256",
        table_name="recommendation_result_pins",
        schema="app",
    )
    op.drop_table("recommendation_result_pins", schema="app")
    op.drop_index(
        "ix_recommendation_runs_release_sha256",
        table_name="recommendation_runs",
        schema="app",
    )
    op.drop_table("recommendation_runs", schema="app")
