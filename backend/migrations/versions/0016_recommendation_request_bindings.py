"""Add immutable aliases from request IDs to deterministic recommendation runs."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0016_recommendation_request_bindings"
down_revision = "0015_phase5_recommendations"
branch_labels = None
depends_on = None
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def upgrade() -> None:
    op.create_table(
        "recommendation_request_bindings",
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("preference_profile_id", sa.Text(), nullable=False),
        sa.Column("input_digest", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "char_length(request_id) BETWEEN 1 AND 160", name="ck_request_binding_id"
        ),
        sa.CheckConstraint(
            "char_length(preference_profile_id) BETWEEN 1 AND 160",
            name="ck_request_binding_profile_id",
        ),
        sa.CheckConstraint(
            "input_digest ~ '^[0-9a-f]{64}$'", name="ck_request_binding_input_digest"
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["app.recommendation_runs.run_id"],
            name="fk_request_binding_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("request_id", name="pk_recommendation_request_bindings"),
        schema="app",
    )
    op.execute(
        sa.text(
            "INSERT INTO app.recommendation_request_bindings "
            "(request_id, run_id, preference_profile_id, input_digest, created_at) "
            "SELECT request_id, run_id, preference_profile_id, input_digest, created_at "
            "FROM app.recommendation_runs"
        )
    )
    config = op.get_context().config
    runtime_role = config.attributes.get("runtime_role") if config is not None else None
    if runtime_role is None:
        runtime_role = os.environ.get("ITDA_RUNTIME_ROLE")
    if runtime_role is not None:
        if not isinstance(runtime_role, str) or _IDENTIFIER.fullmatch(runtime_role) is None:
            raise ValueError("invalid PostgreSQL runtime role")
        quoted = op.get_bind().dialect.identifier_preparer.quote(runtime_role)
        op.execute(
            sa.text(f"GRANT SELECT, INSERT ON app.recommendation_request_bindings TO {quoted}")
        )


def downgrade() -> None:
    op.drop_table("recommendation_request_bindings", schema="app")
