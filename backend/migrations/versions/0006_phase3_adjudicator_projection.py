"""Add the adjudicator-only pseudonymous revision-chain projection."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0006_phase3_adjudicator_projection"
down_revision = "0005_phase3_adjudication"
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
    # The mandated revision identifier exceeds Alembic's historical VARCHAR(32)
    # default. Widen only Alembic's own metadata before it records this revision.
    op.alter_column(
        "alembic_version",
        "version_num",
        existing_type=sa.String(length=32),
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    evaluator_pseudonym = _pseudonym("revisions.evaluator_principal")
    operator_pseudonym = _pseudonym("accepted.selected_by")
    op.execute(
        f"""
        CREATE VIEW dev_eval.adjudicator_label_revisions_v1
        WITH (security_barrier = true) AS
        SELECT revisions.assignment_id,
               {evaluator_pseudonym} AS evaluator_pseudonym,
               revisions.revision_sha256,
               revisions.receipt_sha256,
               revisions.parent_revision_sha256,
               revisions.correction_reason,
               revisions.payload,
               revisions.submitted_at,
               revisions.created_at,
               accepted.event_sha256 AS accepted_event_sha256,
               accepted.revision_sha256 AS accepted_revision_sha256,
               CASE WHEN accepted.event_sha256 IS NULL
                    THEN NULL ELSE {operator_pseudonym} END AS operator_pseudonym,
               accepted.selection_reason,
               accepted.selected_at
          FROM dev_eval.label_revisions AS revisions
          LEFT JOIN LATERAL (
                SELECT event_sha256, revision_sha256, selected_by,
                       selection_reason, selected_at
                  FROM dev_eval.accepted_label_revisions
                 WHERE assignment_id = revisions.assignment_id
                   AND evaluator_principal = revisions.evaluator_principal
                 ORDER BY selected_at DESC, event_sha256 DESC
                 LIMIT 1
          ) AS accepted ON true
        """
    )
    op.execute("REVOKE ALL ON dev_eval.adjudicator_label_revisions_v1 FROM PUBLIC")
    adjudicator = roles.get("adjudicator")
    if adjudicator is not None:
        _grant("GRANT USAGE ON SCHEMA dev_eval", adjudicator)
        _grant("GRANT SELECT ON dev_eval.adjudicator_label_revisions_v1", adjudicator)


def downgrade() -> None:
    op.execute("DROP VIEW dev_eval.adjudicator_label_revisions_v1")
