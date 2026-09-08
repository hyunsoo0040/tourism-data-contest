"""Add immutable DEV profile releases, CAS transitions, and copied release pins."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008_phase3_profile_releases"
down_revision = "0007_phase3_evidence_reviews"
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


def _immutable(relation: str) -> None:
    op.execute(
        f"CREATE TRIGGER reject_{relation}_mutation_v1 "
        f"BEFORE UPDATE OR DELETE ON dev_eval.{relation} "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
    )
    op.execute(f"REVOKE ALL ON dev_eval.{relation} FROM PUBLIC")


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    approver = _configured_identifier("label_approver_role")

    op.create_table(
        "profile_releases",
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("release_id", sa.Text(), nullable=False),
        sa.Column("builder_principal", sa.Text(), nullable=False),
        sa.Column("canonical_lineage_sha256", sa.Text(), nullable=False),
        sa.Column("dev_lineage_sha256", sa.Text(), nullable=False),
        sa.Column("profile_schema_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column(
            "built_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "release_sha256 ~ '^[0-9a-f]{64}$' AND "
            "canonical_lineage_sha256 ~ '^[0-9a-f]{64}$' AND "
            "dev_lineage_sha256 ~ '^[0-9a-f]{64}$' AND "
            "profile_schema_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_hashes",
        ),
        sa.PrimaryKeyConstraint("release_sha256", name="pk_phase3_profile_releases"),
        sa.UniqueConstraint("release_id", name="uq_phase3_profile_release_id"),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_lifecycle_heads",
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("head_receipt_sha256", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["release_sha256"],
            ["dev_eval.profile_releases.release_sha256"],
            name="fk_phase3_profile_release_head",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "state IN ('BUILT_UNAPPROVED', 'APPROVED_INACTIVE', 'ACTIVE')",
            name="ck_phase3_profile_release_state",
        ),
        sa.CheckConstraint(
            "head_receipt_sha256 IS NULL OR head_receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_head_hash",
        ),
        sa.PrimaryKeyConstraint("release_sha256", name="pk_phase3_profile_release_heads"),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_approvals",
        sa.Column("approval_sha256", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("builder_principal", sa.Text(), nullable=False),
        sa.Column("approver_principal", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column(
            "approved_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["release_sha256"],
            ["dev_eval.profile_releases.release_sha256"],
            name="fk_phase3_profile_release_approval",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "approval_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_approval_hash",
        ),
        sa.CheckConstraint(
            "builder_principal <> approver_principal",
            name="ck_phase3_profile_release_independent_approval",
        ),
        sa.PrimaryKeyConstraint("approval_sha256", name="pk_phase3_profile_release_approvals"),
        sa.UniqueConstraint("release_sha256", name="uq_phase3_profile_release_approval_target"),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_transition_events",
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("previous_release_sha256", sa.Text(), nullable=True),
        sa.Column("expected_current_sha256", sa.Text(), nullable=True),
        sa.Column("approver_principal", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["release_sha256"],
            ["dev_eval.profile_releases.release_sha256"],
            name="fk_phase3_profile_release_transition_target",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "action IN ('ACTIVATE', 'ROLLBACK')", name="ck_phase3_profile_release_action"
        ),
        sa.CheckConstraint(
            "receipt_sha256 ~ '^[0-9a-f]{64}$' AND nonce_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_transition_hashes",
        ),
        sa.PrimaryKeyConstraint("receipt_sha256", name="pk_phase3_profile_release_events"),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_rollback_receipts",
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("transition_receipt_sha256", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("approver_principal", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("reason_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["transition_receipt_sha256"],
            ["dev_eval.profile_release_transition_events.receipt_sha256"],
            name="fk_phase3_profile_release_rollback_transition",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "char_length(reason) BETWEEN 1 AND 300 AND reason = btrim(reason)",
            name="ck_phase3_profile_release_rollback_reason",
        ),
        sa.CheckConstraint(
            "receipt_sha256 ~ '^[0-9a-f]{64}$' AND reason_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_rollback_hashes",
        ),
        sa.PrimaryKeyConstraint("receipt_sha256", name="pk_phase3_profile_release_rollbacks"),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_active_pointer",
        sa.Column("slot", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["release_sha256"],
            ["dev_eval.profile_releases.release_sha256"],
            name="fk_phase3_profile_release_active_target",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("slot = 'DEV'", name="ck_phase3_profile_release_active_slot"),
        sa.PrimaryKeyConstraint("slot", name="pk_phase3_profile_release_active_pointer"),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_nonce_ledger",
        sa.Column("binding_sha256", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.CheckConstraint(
            "binding_sha256 ~ '^[0-9a-f]{64}$' AND "
            "nonce_sha256 ~ '^[0-9a-f]{64}$' AND receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_nonce_hashes",
        ),
        sa.PrimaryKeyConstraint(
            "binding_sha256", "nonce_sha256", name="pk_phase3_profile_release_nonce_ledger"
        ),
        schema="dev_eval",
    )
    for relation, owner_column in (
        ("profile_release_session_pins", "session_ref"),
        ("profile_release_result_pins", "result_ref"),
    ):
        op.create_table(
            relation,
            sa.Column(owner_column, sa.Text(), nullable=False),
            sa.Column("release_sha256", sa.Text(), nullable=False),
            sa.Column("pin_sha256", sa.Text(), nullable=False),
            sa.Column(
                "pinned_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.ForeignKeyConstraint(
                ["release_sha256"],
                ["dev_eval.profile_releases.release_sha256"],
                name=f"fk_phase3_{relation}_release",
                ondelete="RESTRICT",
            ),
            sa.CheckConstraint("pin_sha256 ~ '^[0-9a-f]{64}$'", name=f"ck_phase3_{relation}_hash"),
            sa.PrimaryKeyConstraint(owner_column, name=f"pk_phase3_{relation}"),
            schema="dev_eval",
        )

    immutable_relations = (
        "profile_releases",
        "profile_release_approvals",
        "profile_release_transition_events",
        "profile_release_rollback_receipts",
        "profile_release_nonce_ledger",
        "profile_release_session_pins",
        "profile_release_result_pins",
    )
    for relation in immutable_relations:
        _immutable(relation)
    for relation in ("profile_release_lifecycle_heads", "profile_release_active_pointer"):
        op.execute(f"REVOKE ALL ON dev_eval.{relation} FROM PUBLIC")

    for role in (builder, approver):
        _grant("GRANT USAGE ON SCHEMA dev_eval", role)
        _grant(
            "GRANT SELECT ON dev_eval.profile_releases, "
            "dev_eval.profile_release_lifecycle_heads, "
            "dev_eval.profile_release_approvals, "
            "dev_eval.profile_release_transition_events, "
            "dev_eval.profile_release_rollback_receipts, "
            "dev_eval.profile_release_active_pointer, "
            "dev_eval.profile_release_nonce_ledger, "
            "dev_eval.profile_release_session_pins, "
            "dev_eval.profile_release_result_pins",
            role,
        )
    _grant(
        "GRANT INSERT ON dev_eval.profile_releases, dev_eval.profile_release_lifecycle_heads",
        builder,
    )
    _grant(
        "GRANT INSERT, UPDATE ON dev_eval.profile_release_lifecycle_heads, "
        "dev_eval.profile_release_active_pointer",
        approver,
    )
    _grant(
        "GRANT INSERT ON dev_eval.profile_release_approvals, "
        "dev_eval.profile_release_transition_events, "
        "dev_eval.profile_release_rollback_receipts, "
        "dev_eval.profile_release_nonce_ledger, "
        "dev_eval.profile_release_session_pins, "
        "dev_eval.profile_release_result_pins",
        approver,
    )


def downgrade() -> None:
    for relation in (
        "profile_release_result_pins",
        "profile_release_session_pins",
        "profile_release_nonce_ledger",
        "profile_release_rollback_receipts",
        "profile_release_transition_events",
        "profile_release_approvals",
        "profile_releases",
    ):
        op.execute(f"DROP TRIGGER reject_{relation}_mutation_v1 ON dev_eval.{relation}")
    for relation in (
        "profile_release_result_pins",
        "profile_release_session_pins",
        "profile_release_nonce_ledger",
        "profile_release_active_pointer",
        "profile_release_rollback_receipts",
        "profile_release_transition_events",
        "profile_release_approvals",
        "profile_release_lifecycle_heads",
        "profile_releases",
    ):
        op.drop_table(relation, schema="dev_eval")
