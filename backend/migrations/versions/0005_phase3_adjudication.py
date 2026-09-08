"""Add immutable Phase 3 accepted-head, adjudication, aggregate, and freeze inputs."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005_phase3_adjudication"
down_revision = "0004_phase3_labels"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
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


def _quoted_identifier(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _configured_roles() -> dict[str, str]:
    return {
        capability: role
        for capability in _CAPABILITIES
        if (role := _configured_identifier(f"label_{capability}_role")) is not None
    }


def _grant(statement: str, *roles: str) -> None:
    if not roles:
        return
    quoted = ", ".join(_quoted_identifier(role) for role in roles)
    op.execute(sa.text(f"{statement} TO {quoted}"))


def _pseudonym(expression: str) -> str:
    return (
        "'phase3-' || substr(encode(sha256(convert_to('phase3-pseudonym-v1' || "
        f"E'\\n' || {expression}, 'UTF8')), 'hex'), 1, 24)"
    )


def upgrade() -> None:
    roles = _configured_roles()

    op.create_table(
        "label_review_triggers",
        sa.Column("trigger_sha256", sa.Text(), nullable=False),
        sa.Column("assignment_id", sa.Text(), nullable=False),
        sa.Column("accepted_revision_set_sha256", sa.Text(), nullable=False),
        sa.Column("trigger_kind", sa.Text(), nullable=False),
        sa.Column("attribute_id", sa.Text(), nullable=True),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "trigger_sha256 ~ '^[0-9a-f]{64}$' AND accepted_revision_set_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_review_trigger_hashes",
        ),
        sa.CheckConstraint(
            "trigger_kind IN ('ATTRIBUTE_RANGE_AT_LEAST_TWO', "
            "'ALL_PRIMARY_AXES_DIFFER', 'REQUIRED_EVIDENCE_MISSING', "
            "'PRIMARY_AXIS_MISSING')",
            name="ck_phase3_review_trigger_kind",
        ),
        sa.PrimaryKeyConstraint(
            "accepted_revision_set_sha256",
            "trigger_sha256",
            name="pk_phase3_review_triggers",
        ),
        schema="dev_eval",
    )
    op.create_table(
        "label_trigger_resolutions",
        sa.Column("resolution_sha256", sa.Text(), nullable=False),
        sa.Column("accepted_revision_set_sha256", sa.Text(), nullable=False),
        sa.Column("trigger_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("adjudicated_by", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["accepted_revision_set_sha256", "trigger_sha256"],
            [
                "dev_eval.label_review_triggers.accepted_revision_set_sha256",
                "dev_eval.label_review_triggers.trigger_sha256",
            ],
            name="fk_phase3_trigger_resolution",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("resolution_sha256", name="pk_phase3_trigger_resolutions"),
        sa.UniqueConstraint(
            "accepted_revision_set_sha256",
            "trigger_sha256",
            name="uq_phase3_trigger_resolution",
        ),
        schema="dev_eval",
    )
    op.create_table(
        "label_aggregates",
        sa.Column("aggregate_sha256", sa.Text(), nullable=False),
        sa.Column("assignment_id", sa.Text(), nullable=False),
        sa.Column("accepted_revision_set_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.PrimaryKeyConstraint("aggregate_sha256", name="pk_phase3_label_aggregates"),
        schema="dev_eval",
    )
    op.add_column(
        "adjudicated_label_exports",
        sa.Column("assignment_id", sa.Text(), nullable=True),
        schema="dev_eval",
    )
    op.add_column(
        "adjudicated_label_exports",
        sa.Column("accepted_revision_set_sha256", sa.Text(), nullable=True),
        schema="dev_eval",
    )
    op.add_column(
        "adjudicated_label_exports",
        sa.Column("payload", JSONB(), nullable=True),
        schema="dev_eval",
    )
    op.add_column(
        "adjudicated_label_exports",
        sa.Column("created_by", sa.Text(), nullable=True),
        schema="dev_eval",
    )

    for relation in (
        "label_review_triggers",
        "label_trigger_resolutions",
        "label_aggregates",
        "adjudicated_label_exports",
    ):
        op.execute(
            f"CREATE TRIGGER reject_{relation}_mutation_v1 "
            f"BEFORE UPDATE OR DELETE ON dev_eval.{relation} "
            "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
        )

    op.execute("DROP VIEW dev_eval.label_submission_status_v1")
    status_readers = tuple(roles[name] for name in ("builder", "adjudicator") if name in roles)
    status_reader_sql = ", ".join(f"'{role}'" for role in status_readers) or "NULL"
    evaluator_pseudonym = _pseudonym("evaluator_principal")
    op.execute(
        f"""
        CREATE VIEW dev_eval.label_submission_status_v1
        WITH (security_barrier = true) AS
        SELECT {evaluator_pseudonym} AS evaluator_pseudonym,
               'SUBMITTED'::text AS submission_status,
               max(created_at) AS latest_server_event_at,
               (SELECT count(DISTINCT evaluator_principal) >= 3
                  FROM dev_eval.label_revisions)
                   AS all_required_submissions_exist
          FROM dev_eval.label_revisions
         WHERE session_user IN ({status_reader_sql})
         GROUP BY evaluator_principal
        """
    )

    operator_pseudonym = _pseudonym("selected.selected_by")
    accepted_evaluator_pseudonym = _pseudonym("selected.evaluator_principal")
    op.execute(
        f"""
        CREATE VIEW dev_eval.accepted_label_heads_v1
        WITH (security_barrier = true) AS
        SELECT selected.event_sha256,
               selected.assignment_id,
               {accepted_evaluator_pseudonym} AS evaluator_pseudonym,
               selected.revision_sha256,
               {operator_pseudonym} AS operator_pseudonym,
               selected.selection_reason,
               selected.selected_at,
               revisions.payload
          FROM (
                SELECT DISTINCT ON (assignment_id, evaluator_principal)
                       event_sha256, assignment_id, evaluator_principal,
                       revision_sha256, selected_by, selection_reason, selected_at
                  FROM dev_eval.accepted_label_revisions
                 ORDER BY assignment_id, evaluator_principal,
                          selected_at DESC, event_sha256 DESC
               ) AS selected
          JOIN dev_eval.label_revisions AS revisions
            ON revisions.revision_sha256 = selected.revision_sha256
         WHERE NOT EXISTS (
               SELECT 1
                 FROM dev_eval.label_revisions AS successor
                WHERE successor.parent_revision_sha256 = selected.revision_sha256
                  AND successor.assignment_id = selected.assignment_id
                  AND successor.evaluator_principal = selected.evaluator_principal
         )
        """
    )
    op.execute(
        """
        CREATE VIEW dev_eval.label_freeze_exports_v1
        WITH (security_barrier = true) AS
        SELECT export_sha256, assignment_id, accepted_revision_set_sha256,
               payload, created_at
          FROM dev_eval.adjudicated_label_exports
         WHERE payload IS NOT NULL
        """
    )

    # This projection contains only pseudonymous submission status and must remain
    # discoverable by dynamically provisioned operator roles.
    op.execute("GRANT SELECT ON dev_eval.label_submission_status_v1 TO PUBLIC")
    op.execute("REVOKE ALL ON dev_eval.accepted_label_heads_v1 FROM PUBLIC")
    op.execute("REVOKE ALL ON dev_eval.label_freeze_exports_v1 FROM PUBLIC")
    adjudicator = roles.get("adjudicator")
    if adjudicator is not None:
        _grant("GRANT USAGE ON SCHEMA dev_eval", adjudicator)
        _grant("GRANT SELECT ON dev_eval.label_submission_status_v1", adjudicator)
        _grant("GRANT SELECT ON dev_eval.accepted_label_heads_v1", adjudicator)
        _grant(
            "GRANT SELECT, INSERT ON dev_eval.label_review_triggers, "
            "dev_eval.label_trigger_resolutions, dev_eval.label_aggregates, "
            "dev_eval.adjudicated_label_exports",
            adjudicator,
        )
        _grant("GRANT SELECT ON dev_eval.label_freeze_exports_v1", adjudicator)
    builder = roles.get("builder")
    if builder is not None:
        _grant("GRANT USAGE ON SCHEMA dev_eval", builder)
        _grant("GRANT SELECT ON dev_eval.label_submission_status_v1", builder)
        _grant("GRANT SELECT ON dev_eval.label_freeze_exports_v1", builder)


def downgrade() -> None:
    op.execute("DROP VIEW dev_eval.label_freeze_exports_v1")
    op.execute("DROP VIEW dev_eval.accepted_label_heads_v1")
    op.execute("DROP VIEW dev_eval.label_submission_status_v1")
    op.execute(
        """
        CREATE VIEW dev_eval.label_submission_status_v1 AS
        SELECT evaluator_principal AS evaluator_pseudonym,
               'SUBMITTED'::text AS submission_status,
               max(created_at) AS latest_server_event_at,
               (SELECT count(DISTINCT evaluator_principal) >= 3
                  FROM dev_eval.label_revisions)
                   AS all_required_submissions_exist
          FROM dev_eval.label_revisions
         GROUP BY evaluator_principal
        """
    )
    op.execute("GRANT SELECT ON dev_eval.label_submission_status_v1 TO PUBLIC")
    for relation in (
        "adjudicated_label_exports",
        "label_aggregates",
        "label_trigger_resolutions",
        "label_review_triggers",
    ):
        op.execute(f"DROP TRIGGER reject_{relation}_mutation_v1 ON dev_eval.{relation}")
    for column in ("created_by", "payload", "accepted_revision_set_sha256", "assignment_id"):
        op.drop_column("adjudicated_label_exports", column, schema="dev_eval")
    op.drop_table("label_aggregates", schema="dev_eval")
    op.drop_table("label_trigger_resolutions", schema="dev_eval")
    op.drop_table("label_review_triggers", schema="dev_eval")
