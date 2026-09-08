"""Bind request aliases to the complete recommendation run identity."""

from __future__ import annotations

from alembic import op

revision = "0017_recommendation_request_binding_metadata"
down_revision = "0016_recommendation_request_bindings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_recommendation_runs_binding_metadata",
        "recommendation_runs",
        ["run_id", "preference_profile_id", "input_digest"],
        schema="app",
    )
    op.drop_constraint(
        "fk_request_binding_run",
        "recommendation_request_bindings",
        schema="app",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_request_binding_run_metadata",
        "recommendation_request_bindings",
        "recommendation_runs",
        ["run_id", "preference_profile_id", "input_digest"],
        ["run_id", "preference_profile_id", "input_digest"],
        source_schema="app",
        referent_schema="app",
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_request_binding_run_metadata",
        "recommendation_request_bindings",
        schema="app",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_request_binding_run",
        "recommendation_request_bindings",
        "recommendation_runs",
        ["run_id"],
        ["run_id"],
        source_schema="app",
        referent_schema="app",
        ondelete="RESTRICT",
    )
    op.drop_constraint(
        "uq_recommendation_runs_binding_metadata",
        "recommendation_runs",
        schema="app",
        type_="unique",
    )
