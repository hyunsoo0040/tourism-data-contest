"""Versioned authenticity releases and anonymous experience journeys."""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0032_authenticity_experience"
down_revision = "0031_national_grounded_catalog"
branch_labels = None
depends_on = None

_TABLES = (
    "authenticity_assessments",
    "authenticity_releases",
    "authenticity_active",
    "authenticity_sessions",
    "authenticity_intents",
    "authenticity_runs",
    "authenticity_saved",
    "authenticity_feedback",
    "authenticity_photo_receipts",
)


def upgrade() -> None:
    cfg = op.get_context().config.attributes
    runtime = (
        cfg.get("authenticity_runtime_role")
        or os.environ.get("ITDA_AUTHENTICITY_RUNTIME_ROLE")
        or cfg.get("runtime_role")
        or os.environ.get("ITDA_RUNTIME_ROLE")
    )
    if not isinstance(runtime, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", runtime) is None:
        raise ValueError("authenticity runtime role invalid")
    op.execute("""
        CREATE TABLE app.authenticity_assessments (
            assessment_sha256 text PRIMARY KEY CHECK (assessment_sha256 ~ '^[0-9a-f]{64}$'),
            place_id text NOT NULL,
            payload jsonb NOT NULL CHECK (payload->>'assessment_sha256' = assessment_sha256),
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE app.authenticity_releases (
            release_sha256 text PRIMARY KEY CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
            scope text NOT NULL CHECK (scope IN ('DEVELOPMENT','PUBLIC')),
            payload jsonb NOT NULL CHECK (payload->>'release_sha256' = release_sha256),
            validation jsonb NOT NULL,
            auxiliary jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE app.authenticity_active (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            release_sha256 text NOT NULL REFERENCES app.authenticity_releases,
            generation bigint NOT NULL CHECK (generation > 0),
            activated_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE app.authenticity_sessions (
            session_id text PRIMARY KEY,
            token_sha256 text UNIQUE NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
            created_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            CHECK (expires_at > created_at)
        );
        CREATE TABLE app.authenticity_intents (
            profile_id text PRIMARY KEY,
            session_id text NOT NULL REFERENCES app.authenticity_sessions ON DELETE CASCADE,
            request_id text NOT NULL,
            payload jsonb NOT NULL CHECK (payload->>'profile_id' = profile_id),
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (session_id,request_id),
            UNIQUE (profile_id,session_id)
        );
        CREATE TABLE app.authenticity_runs (
            run_sha256 text PRIMARY KEY CHECK (run_sha256 ~ '^[0-9a-f]{64}$'),
            session_id text NOT NULL REFERENCES app.authenticity_sessions ON DELETE CASCADE,
            profile_id text NOT NULL,
            request_id text NOT NULL,
            release_sha256 text NOT NULL REFERENCES app.authenticity_releases,
            payload jsonb NOT NULL CHECK (payload->>'run_sha256' = run_sha256),
            created_at timestamptz NOT NULL DEFAULT now(),
            FOREIGN KEY (profile_id,session_id)
                REFERENCES app.authenticity_intents(profile_id,session_id) ON DELETE CASCADE,
            UNIQUE (session_id,request_id),
            UNIQUE (run_sha256,session_id)
        );
        CREATE TABLE app.authenticity_saved (
            session_id text NOT NULL,
            run_sha256 text NOT NULL,
            place_id text NOT NULL,
            saved_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (session_id,run_sha256,place_id),
            FOREIGN KEY (run_sha256,session_id)
                REFERENCES app.authenticity_runs(run_sha256,session_id) ON DELETE CASCADE
        );
        CREATE TABLE app.authenticity_feedback (
            feedback_id text PRIMARY KEY,
            session_id text NOT NULL,
            run_sha256 text NOT NULL,
            place_id text NOT NULL,
            payload jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            FOREIGN KEY (run_sha256,session_id)
                REFERENCES app.authenticity_runs(run_sha256,session_id) ON DELETE CASCADE
        );
        CREATE TABLE app.authenticity_photo_receipts (
            photo_id text PRIMARY KEY,
            session_id text NOT NULL REFERENCES app.authenticity_sessions ON DELETE CASCADE,
            state text NOT NULL CHECK (state IN ('REVIEW','CONFIRMED','DELETED','FAILED')),
            payload jsonb NOT NULL,
            original_retained boolean NOT NULL DEFAULT false CHECK (NOT original_retained),
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX authenticity_run_owner_idx ON app.authenticity_runs(session_id,created_at);
        CREATE INDEX authenticity_intent_owner_idx
            ON app.authenticity_intents(session_id,created_at);
        CREATE FUNCTION app.authenticity_immutable_snapshot() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            RAISE EXCEPTION 'authenticity snapshot is immutable' USING ERRCODE='23514';
        END $$;
        CREATE TRIGGER authenticity_assessment_immutable
            BEFORE UPDATE OR DELETE ON app.authenticity_assessments
            FOR EACH ROW EXECUTE FUNCTION app.authenticity_immutable_snapshot();
        CREATE TRIGGER authenticity_release_immutable
            BEFORE UPDATE OR DELETE ON app.authenticity_releases
            FOR EACH ROW EXECUTE FUNCTION app.authenticity_immutable_snapshot();
    """)
    for table in _TABLES:
        op.execute(f'REVOKE ALL ON app.{table} FROM PUBLIC,"{runtime}"')
    op.execute(f'GRANT USAGE ON SCHEMA app TO "{runtime}"')
    for table in _TABLES:
        op.execute(f'GRANT SELECT ON app.{table} TO "{runtime}"')
    for table in (
        "authenticity_sessions",
        "authenticity_intents",
        "authenticity_runs",
        "authenticity_saved",
        "authenticity_feedback",
        "authenticity_photo_receipts",
    ):
        op.execute(f'GRANT INSERT,DELETE ON app.{table} TO "{runtime}"')
    op.execute(f'GRANT UPDATE ON app.authenticity_photo_receipts TO "{runtime}"')


def downgrade() -> None:
    # Explicit downgrade is refused once a release has been archived. Destructive
    # retirement needs its own deliberate data-export/migration procedure.
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM app.authenticity_releases) THEN
            RAISE EXCEPTION 'cannot remove archived authenticity releases';
        END IF;
    END $$;""")
    for table in reversed(_TABLES):
        op.execute(f"DROP TABLE app.{table}")
    op.execute("DROP FUNCTION app.authenticity_immutable_snapshot()")
