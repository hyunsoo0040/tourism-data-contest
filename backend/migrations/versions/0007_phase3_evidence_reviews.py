"""Add immutable candidate references and append-only evidence review lineage."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007_phase3_evidence_reviews"
down_revision = "0006_phase3_adjudicator_projection"
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


def _quoted_identifier(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _grant(statement: str, role: str | None) -> None:
    if role is not None:
        op.execute(sa.text(f"{statement} TO {_quoted_identifier(role)}"))


def upgrade() -> None:
    reviewer = _configured_identifier("label_builder_role")

    op.create_table(
        "evidence_candidate_manifests",
        sa.Column("candidate_manifest_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("registered_by", sa.Text(), nullable=False),
        sa.Column(
            "registered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "candidate_manifest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_candidate_manifest_sha256",
        ),
        sa.PrimaryKeyConstraint("candidate_manifest_sha256", name="pk_phase3_candidate_manifests"),
        schema="dev_eval",
    )
    op.create_table(
        "evidence_candidate_references",
        sa.Column("candidate_manifest_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_id", sa.Text(), nullable=False),
        sa.Column("candidate_sha256", sa.Text(), nullable=False),
        sa.Column("lane", sa.Text(), nullable=False),
        sa.Column("source_id", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_manifest_sha256"],
            ["dev_eval.evidence_candidate_manifests.candidate_manifest_sha256"],
            name="fk_phase3_evidence_candidate_manifest",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "candidate_id ~ '^[0-9a-f]{64}$' AND candidate_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_evidence_candidate_hashes",
        ),
        sa.CheckConstraint(
            "lane IN ('DESCRIPTION', 'ODII')", name="ck_phase3_evidence_candidate_lane"
        ),
        sa.PrimaryKeyConstraint(
            "candidate_manifest_sha256",
            "candidate_id",
            name="pk_phase3_evidence_candidate_references",
        ),
        sa.UniqueConstraint(
            "candidate_manifest_sha256",
            "candidate_id",
            "candidate_sha256",
            "lane",
            name="uq_phase3_evidence_candidate_identity",
        ),
        schema="dev_eval",
    )
    op.create_table(
        "evidence_review_revisions",
        sa.Column("review_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_manifest_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_id", sa.Text(), nullable=False),
        sa.Column("candidate_sha256", sa.Text(), nullable=False),
        sa.Column("lane", sa.Text(), nullable=False),
        sa.Column("parent_review_sha256", sa.Text(), nullable=True),
        sa.Column("correction_reason", sa.Text(), nullable=True),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("reviewed_by", sa.Text(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["candidate_manifest_sha256", "candidate_id", "candidate_sha256", "lane"],
            [
                "dev_eval.evidence_candidate_references.candidate_manifest_sha256",
                "dev_eval.evidence_candidate_references.candidate_id",
                "dev_eval.evidence_candidate_references.candidate_sha256",
                "dev_eval.evidence_candidate_references.lane",
            ],
            name="fk_phase3_evidence_review_candidate",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["parent_review_sha256"],
            ["dev_eval.evidence_review_revisions.review_sha256"],
            name="fk_phase3_evidence_review_parent",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "review_sha256 ~ '^[0-9a-f]{64}$' AND receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_evidence_review_hashes",
        ),
        sa.CheckConstraint(
            "decision IN ('ACCEPT', 'REJECT', 'NOT_CURRENT_SITE')",
            name="ck_phase3_evidence_review_decision",
        ),
        sa.CheckConstraint(
            "lane IN ('DESCRIPTION', 'ODII')", name="ck_phase3_evidence_review_lane"
        ),
        sa.CheckConstraint(
            "(parent_review_sha256 IS NULL) = (correction_reason IS NULL)",
            name="ck_phase3_evidence_review_correction_pair",
        ),
        sa.PrimaryKeyConstraint("review_sha256", name="pk_phase3_evidence_reviews"),
        sa.UniqueConstraint(
            "candidate_manifest_sha256",
            "candidate_id",
            "reviewed_by",
            "parent_review_sha256",
            name="uq_phase3_evidence_review_successor",
        ),
        schema="dev_eval",
    )
    op.create_index(
        "uq_phase3_evidence_review_root",
        "evidence_review_revisions",
        ["candidate_manifest_sha256", "candidate_id", "reviewed_by"],
        unique=True,
        schema="dev_eval",
        postgresql_where=sa.text("parent_review_sha256 IS NULL"),
    )
    op.create_table(
        "accepted_evidence_review_heads",
        sa.Column("event_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_manifest_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_id", sa.Text(), nullable=False),
        sa.Column("candidate_sha256", sa.Text(), nullable=False),
        sa.Column("lane", sa.Text(), nullable=False),
        sa.Column("review_sha256", sa.Text(), nullable=False),
        sa.Column("expected_chain_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("selected_by", sa.Text(), nullable=False),
        sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["review_sha256"],
            ["dev_eval.evidence_review_revisions.review_sha256"],
            name="fk_phase3_accepted_evidence_review",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "event_sha256 ~ '^[0-9a-f]{64}$' AND expected_chain_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_accepted_evidence_review_hashes",
        ),
        sa.PrimaryKeyConstraint("event_sha256", name="pk_phase3_accepted_evidence_heads"),
        schema="dev_eval",
    )
    op.create_table(
        "reviewed_evidence_manifests",
        sa.Column("manifest_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_manifest_sha256", sa.Text(), nullable=False),
        sa.Column("accepted_review_set_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["candidate_manifest_sha256"],
            ["dev_eval.evidence_candidate_manifests.candidate_manifest_sha256"],
            name="fk_phase3_reviewed_manifest_candidate",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "manifest_sha256 ~ '^[0-9a-f]{64}$' AND accepted_review_set_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_reviewed_manifest_hashes",
        ),
        sa.PrimaryKeyConstraint("manifest_sha256", name="pk_phase3_reviewed_manifests"),
        sa.UniqueConstraint(
            "candidate_manifest_sha256",
            "accepted_review_set_sha256",
            name="uq_phase3_reviewed_manifest_input",
        ),
        schema="dev_eval",
    )

    for relation in (
        "evidence_candidate_manifests",
        "evidence_candidate_references",
        "evidence_review_revisions",
        "accepted_evidence_review_heads",
        "reviewed_evidence_manifests",
    ):
        op.execute(
            f"CREATE TRIGGER reject_{relation}_mutation_v1 "
            f"BEFORE UPDATE OR DELETE ON dev_eval.{relation} "
            "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
        )
        op.execute(f"REVOKE ALL ON dev_eval.{relation} FROM PUBLIC")

    _grant("GRANT USAGE ON SCHEMA dev_eval", reviewer)
    _grant(
        "GRANT SELECT, INSERT ON dev_eval.evidence_candidate_manifests, "
        "dev_eval.evidence_candidate_references, dev_eval.evidence_review_revisions, "
        "dev_eval.accepted_evidence_review_heads, dev_eval.reviewed_evidence_manifests",
        reviewer,
    )


def downgrade() -> None:
    for relation in (
        "reviewed_evidence_manifests",
        "accepted_evidence_review_heads",
        "evidence_review_revisions",
        "evidence_candidate_references",
        "evidence_candidate_manifests",
    ):
        op.execute(f"DROP TRIGGER reject_{relation}_mutation_v1 ON dev_eval.{relation}")
    op.drop_table("reviewed_evidence_manifests", schema="dev_eval")
    op.drop_table("accepted_evidence_review_heads", schema="dev_eval")
    op.drop_index(
        "uq_phase3_evidence_review_root",
        table_name="evidence_review_revisions",
        schema="dev_eval",
    )
    op.drop_table("evidence_review_revisions", schema="dev_eval")
    op.drop_table("evidence_candidate_references", schema="dev_eval")
    op.drop_table("evidence_candidate_manifests", schema="dev_eval")
