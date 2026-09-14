"""Add immutable tourism source, assessment and recommendation context sidecars.

Downgrade drops only these new sidecars and their guards. It is intentionally
costly (source context is lost); historical recommendation tables stay intact.
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0028_source_grounding_snapshots"
down_revision = "0027_photo_semantic_authority"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("tourism_source_snapshots", "place_assessment_snapshots"):
        op.create_table(
            name,
            sa.Column("snapshot_sha256", sa.Text(), primary_key=True),
            sa.Column("payload", postgresql.JSONB(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint("snapshot_sha256 ~ '^[0-9a-f]{64}$'", name=f"ck_{name}_sha"),
            sa.CheckConstraint("jsonb_typeof(payload) = 'object'", name=f"ck_{name}_payload"),
            schema="app",
        )
    op.create_table(
        "grounded_run_bindings",
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), primary_key=True),
        sa.Column("preference_profile_id", sa.Text(), nullable=False),
        sa.Column("binding_sha256", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["app.recommendation_runs.run_id"],
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.CheckConstraint("binding_sha256 ~ '^[0-9a-f]{64}$'", name="ck_grounded_binding_sha"),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object' AND "
            "payload->>'run_id' = run_id AND payload->>'request_id' = request_id AND "
            "payload->>'preference_profile_id' = preference_profile_id AND "
            "payload->>'binding_sha256' = binding_sha256",
            name="ck_grounded_binding_metadata",
        ),
        schema="app",
    )
    op.create_index(
        "ix_grounded_run_bindings_run_id", "grounded_run_bindings", ["run_id"], schema="app"
    )
    op.execute("""
        CREATE FUNCTION app.reject_source_snapshot_mutation() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            RAISE EXCEPTION 'source snapshots and bindings are immutable'
                USING ERRCODE = '23514';
        END
        $function$;
        CREATE FUNCTION app.validate_grounded_run_binding() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_run app.recommendation_runs%ROWTYPE; v_digest text;
        BEGIN
            SELECT * INTO v_run FROM app.recommendation_runs WHERE run_id = NEW.run_id;
            IF NOT FOUND OR v_run.preference_profile_id <> NEW.preference_profile_id
                OR v_run.release_sha256 <> NEW.payload->>'raw_release_sha256' THEN
                RAISE EXCEPTION 'grounded binding owner or release mismatch'
                    USING ERRCODE = '23514';
            END IF;
            IF v_run.request_id <> NEW.request_id AND NOT EXISTS (
                SELECT 1 FROM app.recommendation_request_bindings
                WHERE request_id = NEW.request_id AND run_id = NEW.run_id
                AND preference_profile_id = NEW.preference_profile_id
            ) THEN
                RAISE EXCEPTION 'grounded request alias mismatch' USING ERRCODE = '23514';
            END IF;
            IF EXISTS (SELECT 1 FROM app.grounded_run_bindings
                WHERE run_id = NEW.run_id AND request_id <> NEW.request_id
                AND (payload - 'request_id' - 'created_at' - 'binding_sha256')
                    <> (NEW.payload - 'request_id' - 'created_at' - 'binding_sha256')) THEN
                RAISE EXCEPTION 'grounded run alias source mismatch' USING ERRCODE = '23514';
            END IF;
            FOR v_digest IN SELECT jsonb_array_elements_text(
                NEW.payload->'source_snapshot_sha256') LOOP
                IF NOT EXISTS (SELECT 1 FROM app.tourism_source_snapshots
                    WHERE snapshot_sha256 = v_digest) THEN
                    RAISE EXCEPTION 'missing source snapshot' USING ERRCODE = '23503';
                END IF;
            END LOOP;
            FOR v_digest IN SELECT jsonb_array_elements_text(
                NEW.payload->'assessment_bundle_sha256') LOOP
                IF NOT EXISTS (SELECT 1 FROM app.place_assessment_snapshots
                    WHERE snapshot_sha256 = v_digest
                    AND payload->>'source_release_sha256' =
                        NEW.payload->>'source_release_sha256') THEN
                    RAISE EXCEPTION 'missing or foreign assessment snapshot'
                        USING ERRCODE = '23503';
                END IF;
            END LOOP;
            RETURN NEW;
        END $function$;
        CREATE CONSTRAINT TRIGGER grounded_run_binding_membership
        AFTER INSERT ON app.grounded_run_bindings DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION app.validate_grounded_run_binding();
    """)
    for name in ("tourism_source_snapshots", "place_assessment_snapshots", "grounded_run_bindings"):
        op.execute(
            f"CREATE TRIGGER immutable_{name} BEFORE UPDATE OR DELETE ON app.{name} "
            "FOR EACH ROW EXECUTE FUNCTION app.reject_source_snapshot_mutation()"
        )
    config = op.get_context().config
    runtime_role = config.attributes.get("runtime_role") if config is not None else None
    runtime_role = runtime_role or os.environ.get("ITDA_RUNTIME_ROLE")
    if runtime_role is not None:
        if (
            not isinstance(runtime_role, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", runtime_role) is None
        ):
            raise ValueError("invalid PostgreSQL runtime role")
        quoted = op.get_bind().dialect.identifier_preparer.quote(runtime_role)
        op.execute(
            "GRANT SELECT, INSERT ON app.tourism_source_snapshots, "
            f"app.place_assessment_snapshots, app.grounded_run_bindings TO {quoted}"
        )


def downgrade() -> None:
    op.drop_table("grounded_run_bindings", schema="app")
    op.execute("DROP FUNCTION app.validate_grounded_run_binding()")
    op.drop_table("place_assessment_snapshots", schema="app")
    op.drop_table("tourism_source_snapshots", schema="app")
    op.execute("DROP FUNCTION app.reject_source_snapshot_mutation()")
