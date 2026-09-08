"""Add the Phase 6 photo lifecycle and deletion ledger storage.

Creates the least-privilege Phase 6 topology: a no-login
``itda_photo_write_authority`` owner, a login ``itda_photo_service``
principal, and the five ``dev_eval`` tables the durable lifecycle needs —
``photo_jobs`` (six-state machine), ``photo_job_dispatch_markers``
(durable dispatch evidence), ``photo_trait_candidates`` (immutable model
output), ``photo_confirmed_traits`` (separate user authority), and
``photo_deletion_ledger`` (append-only deletion truth).

Mutation authority is narrow: the service role may INSERT candidates and
confirmed rows, UPDATE job rows only through constrained SECURITY DEFINER
functions with ``session_user`` checks, and never DELETE/TRUNCATE anything.
The ledger is INSERT-only for the service role; runtime mutation of ledger
rows does not exist at any privilege level. Every table grants nothing to
PUBLIC, carries exact state/cause/provenance checks, opaque hex identity,
canonical digest shapes, and unique idempotency keys. Downgrade refuses to
run once lifecycle state exists.
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0018_phase6_photo_jobs_and_deletion_ledger"
down_revision = "0017_recommendation_request_binding_metadata"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WRITE_AUTHORITY = "itda_photo_write_authority"
_AUTHORITY_SERVICE = "itda_photo_service"


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


def _require_role_topology(builder: str) -> None:
    """Assert the fixed photo role topology exists with production-safe flags."""

    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (:owner, :service, :builder)"
        ),
        {"owner": _WRITE_AUTHORITY, "service": _AUTHORITY_SERVICE, "builder": builder},
    ).mappings()
    roles = {str(row["rolname"]): row for row in rows}
    if set(roles) != {_WRITE_AUTHORITY, _AUTHORITY_SERVICE, builder}:
        raise RuntimeError("photo lifecycle roles must be provisioned exactly")
    owner = roles[_WRITE_AUTHORITY]
    service = roles[_AUTHORITY_SERVICE]
    if tuple(
        owner[key]
        for key in (
            "rolcanlogin",
            "rolinherit",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        )
    ) != (False, False, False, False, False, False, False):
        raise RuntimeError("photo write authority role flags are unsafe")
    if tuple(
        service[key]
        for key in (
            "rolcanlogin",
            "rolinherit",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        )
    ) != (True, False, False, False, False, False, False):
        raise RuntimeError("photo service role flags are unsafe")
    if builder in {_WRITE_AUTHORITY, _AUTHORITY_SERVICE}:
        raise RuntimeError("photo builder must be distinct from authority roles")
    related = connection.execute(
        sa.text(
            "SELECT pg_catalog.pg_has_role(:builder, :owner, 'MEMBER'), "
            "pg_catalog.pg_has_role(:owner, :builder, 'MEMBER'), "
            "pg_catalog.pg_has_role(:builder, :service, 'MEMBER'), "
            "pg_catalog.pg_has_role(:service, :builder, 'MEMBER')"
        ),
        {"builder": builder, "owner": _WRITE_AUTHORITY, "service": _AUTHORITY_SERVICE},
    ).one()
    if any(bool(value) for value in related):
        raise RuntimeError("photo lifecycle roles must not be member-related")


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    if builder is None:
        raise RuntimeError("photo lifecycle builder role is required")
    _require_role_topology(builder)

    # ------------------------------------------------------------------
    # photo_jobs: the durable six-state machine.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE dev_eval.photo_jobs (
            job_id text PRIMARY KEY CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            profile_id text NOT NULL CHECK (
                char_length(profile_id) BETWEEN 1 AND 160
                AND profile_id ~ '^\\S(.*\\S)?$'
            ),
            status text NOT NULL CHECK (
                status IN ('queued','running','succeeded','failed','expired','deleted')
            ),
            lease_expires_at timestamptz NULL,
            idempotency_key text NULL UNIQUE CHECK (
                idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 16 AND 160
            ),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            terminal_cause text NULL CHECK (
                terminal_cause IS NULL OR terminal_cause IN (
                    'success','rejection','validation_failure','provider_error',
                    'timeout','worker_crash','explicit_deletion','expiry','orphan_cleanup'
                )
            )
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX photo_jobs_profile_idempotency_uidx "
        "ON dev_eval.photo_jobs (profile_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL"
    )
    op.execute("CREATE INDEX photo_jobs_status_idx ON dev_eval.photo_jobs (status)")
    op.execute("ALTER TABLE dev_eval.photo_jobs OWNER TO itda_photo_write_authority")
    op.execute("REVOKE ALL ON dev_eval.photo_jobs FROM PUBLIC")

    # ------------------------------------------------------------------
    # photo_job_dispatch_markers: create-only durable dispatch evidence.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE dev_eval.photo_job_dispatch_markers (
            job_id text NOT NULL REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE RESTRICT CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            attempt integer NOT NULL CHECK (attempt >= 1),
            marker text NOT NULL CHECK (
                marker IN ('reserved','prepared','client_constructed','send_boundary')
            ),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (job_id, attempt, marker)
        )
        """
    )
    op.execute(
        "ALTER TABLE dev_eval.photo_job_dispatch_markers "
        "OWNER TO itda_photo_write_authority"
    )
    op.execute("REVOKE ALL ON dev_eval.photo_job_dispatch_markers FROM PUBLIC")

    # ------------------------------------------------------------------
    # photo_trait_candidates: immutable model candidate evidence.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE dev_eval.photo_trait_candidates (
            job_id text NOT NULL REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE RESTRICT CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            candidate_id text NOT NULL CHECK (candidate_id ~ '^[0-9a-f]{64}$'),
            trait_id text NOT NULL CHECK (trait_id ~ '^M[1-6]$'),
            text_ko text NOT NULL CHECK (
                char_length(text_ko) BETWEEN 1 AND 24 AND text_ko ~ '[가-힣]'
            ),
            candidate_set_sha256 text NOT NULL CHECK (
                candidate_set_sha256 ~ '^[0-9a-f]{64}$'
            ),
            edited_text_ko text NULL CHECK (
                edited_text_ko IS NULL OR (
                    char_length(edited_text_ko) BETWEEN 1 AND 64
                    AND edited_text_ko ~ '[가-힣]'
                )
            ),
            excluded boolean NOT NULL DEFAULT FALSE,
            provenance text NOT NULL DEFAULT 'MODEL_CANDIDATE' CHECK (
                provenance = 'MODEL_CANDIDATE'
            ),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (job_id, candidate_id)
        )
        """
    )
    op.execute(
        "ALTER TABLE dev_eval.photo_trait_candidates "
        "OWNER TO itda_photo_write_authority"
    )
    op.execute("REVOKE ALL ON dev_eval.photo_trait_candidates FROM PUBLIC")

    # ------------------------------------------------------------------
    # photo_confirmed_traits: separate explicit user authority.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE dev_eval.photo_confirmed_traits (
            job_id text NOT NULL REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE RESTRICT CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            confirmation_seq integer NOT NULL CHECK (confirmation_seq >= 1),
            trait_id text NOT NULL CHECK (trait_id ~ '^M[1-6]$'),
            text_ko text NOT NULL CHECK (
                char_length(text_ko) BETWEEN 1 AND 64 AND text_ko ~ '[가-힣]'
            ),
            source_candidate_id text NULL CHECK (
                source_candidate_id IS NULL OR source_candidate_id ~ '^[0-9a-f]{64}$'
            ),
            included boolean NOT NULL,
            text_ko_is_blank boolean NOT NULL DEFAULT FALSE,
            provenance text NOT NULL DEFAULT 'USER_CONFIRMED' CHECK (
                provenance = 'USER_CONFIRMED'
            ),
            confirmed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (job_id, confirmation_seq)
        )
        """
    )
    op.execute(
        "ALTER TABLE dev_eval.photo_confirmed_traits "
        "OWNER TO itda_photo_write_authority"
    )
    op.execute("REVOKE ALL ON dev_eval.photo_confirmed_traits FROM PUBLIC")

    # ------------------------------------------------------------------
    # photo_deletion_ledger: append-only deletion truth.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE TABLE dev_eval.photo_deletion_ledger (
            ledger_seq bigserial PRIMARY KEY,
            job_id text NOT NULL CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            cause text NOT NULL CHECK (cause IN (
                'success','rejection','validation_failure','provider_error',
                'timeout','worker_crash','explicit_deletion','expiry','orphan_cleanup'
            )),
            reason_code text NOT NULL CHECK (
                reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
            ),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            residue_proof_digest text NOT NULL CHECK (
                residue_proof_digest ~ '^[0-9a-f]{64}$'
            )
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX photo_deletion_ledger_job_cause_digest_uidx "
        "ON dev_eval.photo_deletion_ledger "
        "(job_id, cause, residue_proof_digest)"
    )
    op.execute(
        "ALTER TABLE dev_eval.photo_deletion_ledger OWNER TO itda_photo_write_authority"
    )
    op.execute("REVOKE ALL ON dev_eval.photo_deletion_ledger FROM PUBLIC")

    # ------------------------------------------------------------------
    # SECURITY DEFINER transition function: the only status mutation path.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE FUNCTION dev_eval.transition_photo_job_status_v1(
            p_job_id text,
            p_from_status text,
            p_to_status text,
            p_terminal_cause text,
            p_lease_expires_at timestamptz
        ) RETURNS text
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            current_status text;
            legal boolean;
        BEGIN
            IF session_user <> 'itda_photo_service' THEN
                RAISE EXCEPTION 'photo job transition rejected'
                    USING ERRCODE = '42501';
            END IF;
            SELECT stored.status INTO current_status
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'photo job transition rejected'
                    USING ERRCODE = '23514';
            END IF;
            IF current_status IS DISTINCT FROM p_from_status THEN
                RAISE EXCEPTION 'photo job transition rejected'
                    USING ERRCODE = '23514';
            END IF;
            legal := CASE
                WHEN p_from_status = p_to_status THEN TRUE
                WHEN p_from_status = 'queued' THEN
                    p_to_status IN ('running','failed','expired','deleted')
                WHEN p_from_status = 'running' THEN
                    p_to_status IN ('succeeded','failed','expired','deleted')
                WHEN p_from_status = 'succeeded' THEN p_to_status = 'deleted'
                WHEN p_from_status = 'failed' THEN p_to_status = 'deleted'
                WHEN p_from_status = 'expired' THEN p_to_status = 'deleted'
                ELSE FALSE
            END;
            IF NOT legal THEN
                RAISE EXCEPTION 'photo job transition rejected'
                    USING ERRCODE = '23514';
            END IF;
            IF p_to_status IN ('succeeded','failed','expired','deleted')
               AND p_terminal_cause IS NULL THEN
                RAISE EXCEPTION 'photo job transition rejected'
                    USING ERRCODE = '23514';
            END IF;
            UPDATE dev_eval.photo_jobs stored
            SET status = p_to_status,
                lease_expires_at = p_lease_expires_at,
                terminal_cause = COALESCE(p_terminal_cause, stored.terminal_cause),
                updated_at = CURRENT_TIMESTAMP
            WHERE stored.job_id = p_job_id;
            RETURN current_status;
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.transition_photo_job_status_v1"
        "(text,text,text,text,timestamptz) OWNER TO itda_photo_write_authority"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.transition_photo_job_status_v1"
        "(text,text,text,text,timestamptz) FROM PUBLIC"
    )

    # ------------------------------------------------------------------
    # SECURITY DEFINER claim function: exactly one concurrent worker.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE FUNCTION dev_eval.claim_photo_job_v1(
            p_job_id text,
            p_lease_expires_at timestamptz
        ) RETURNS integer
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            claimed integer;
        BEGIN
            IF session_user <> 'itda_photo_service' THEN
                RAISE EXCEPTION 'photo job claim rejected'
                    USING ERRCODE = '42501';
            END IF;
            UPDATE dev_eval.photo_jobs stored
            SET status = 'running',
                lease_expires_at = p_lease_expires_at,
                updated_at = CURRENT_TIMESTAMP
            WHERE stored.job_id = p_job_id
              AND stored.status = 'queued'
              AND (stored.lease_expires_at IS NULL OR stored.lease_expires_at < CURRENT_TIMESTAMP);
            GET DIAGNOSTICS claimed = ROW_COUNT;
            RETURN claimed;
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.claim_photo_job_v1(text,timestamptz) "
        "OWNER TO itda_photo_write_authority"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.claim_photo_job_v1(text,timestamptz) FROM PUBLIC"
    )

    # ------------------------------------------------------------------
    # SECURITY DEFINER marker recording: create-only dispatch evidence.
    # ------------------------------------------------------------------
    op.execute(
        """
        CREATE FUNCTION dev_eval.record_photo_dispatch_marker_v1(
            p_job_id text,
            p_attempt integer,
            p_marker text
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            IF session_user <> 'itda_photo_service' THEN
                RAISE EXCEPTION 'photo dispatch marker rejected'
                    USING ERRCODE = '42501';
            END IF;
            BEGIN
                INSERT INTO dev_eval.photo_job_dispatch_markers (
                    job_id, attempt, marker
                ) VALUES (p_job_id, p_attempt, p_marker);
            EXCEPTION
                WHEN unique_violation THEN
                    RETURN;
            END;
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.record_photo_dispatch_marker_v1(text,integer,text) "
        "OWNER TO itda_photo_write_authority"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.record_photo_dispatch_marker_v1"
        "(text,integer,text) FROM PUBLIC"
    )

    # ------------------------------------------------------------------
    # Grants: schema usage, narrow table privileges, function execution.
    # ------------------------------------------------------------------
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO itda_photo_service")
    # The RI triggers on the owned tables run as the table owner; the owner
    # needs schema usage for their internal key-share validation queries.
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO itda_photo_write_authority")
    # Dispatch-marker inventory is public-projectable: any database role may
    # count markers, but only the service mutates them. Table grants remain
    # revoked from PUBLIC for the other four relations.
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO PUBLIC")
    op.execute("GRANT SELECT ON dev_eval.photo_job_dispatch_markers TO PUBLIC")

    # The application runtime role owns the candidate/confirmed review
    # flow (upload -> review -> confirm). It never touches the ledger.
    runtime_role = _configured_identifier("runtime_role")
    if runtime_role is not None:
        quoted_runtime = _quoted_identifier(runtime_role)
        op.execute(
            "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_trait_candidates "
            f"TO {quoted_runtime}"
        )
        op.execute(
            "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_confirmed_traits "
            f"TO {quoted_runtime}"
        )
        op.execute(
            "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_jobs "
            f"TO {quoted_runtime}"
        )
        op.execute(
            "GRANT SELECT, INSERT ON dev_eval.photo_job_dispatch_markers "
            f"TO {quoted_runtime}"
        )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_jobs TO itda_photo_service"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_job_dispatch_markers "
        "TO itda_photo_service"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_trait_candidates "
        "TO itda_photo_service"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_confirmed_traits "
        "TO itda_photo_service"
    )
    op.execute(
        "GRANT SELECT, INSERT ON dev_eval.photo_deletion_ledger TO itda_photo_service"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz), "
        "dev_eval.claim_photo_job_v1(text,timestamptz), "
        "dev_eval.record_photo_dispatch_marker_v1(text,integer,text) "
        "TO itda_photo_service"
    )

    # Explicit denial reinforcement: the label builder loses nothing it had,
    # and no migration role gains photo mutation beyond the service grant.
    quoted_builder = _quoted_identifier(builder)
    op.execute(
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON "
        "dev_eval.photo_jobs, dev_eval.photo_job_dispatch_markers, "
        "dev_eval.photo_trait_candidates, dev_eval.photo_confirmed_traits, "
        "dev_eval.photo_deletion_ledger "
        f"FROM {quoted_builder}"
    )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "LOCK TABLE dev_eval.photo_jobs, "
            "dev_eval.photo_job_dispatch_markers, "
            "dev_eval.photo_trait_candidates, "
            "dev_eval.photo_confirmed_traits, "
            "dev_eval.photo_deletion_ledger IN ACCESS EXCLUSIVE MODE"
        )
    )
    if connection.execute(
        sa.text(
            "SELECT (SELECT count(*) FROM dev_eval.photo_jobs) + "
            "(SELECT count(*) FROM dev_eval.photo_job_dispatch_markers) + "
            "(SELECT count(*) FROM dev_eval.photo_trait_candidates) + "
            "(SELECT count(*) FROM dev_eval.photo_confirmed_traits) + "
            "(SELECT count(*) FROM dev_eval.photo_deletion_ledger)"
        )
    ).scalar_one():
        raise RuntimeError(
            "0018 downgrade is intentionally irreversible after lifecycle state exists"
        )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION "
        "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz), "
        "dev_eval.claim_photo_job_v1(text,timestamptz), "
        "dev_eval.record_photo_dispatch_marker_v1(text,integer,text) "
        "FROM itda_photo_service"
    )
    op.execute("REVOKE USAGE ON SCHEMA dev_eval FROM itda_photo_service")
    op.execute(
        "REVOKE ALL ON dev_eval.photo_jobs, "
        "dev_eval.photo_job_dispatch_markers, "
        "dev_eval.photo_trait_candidates, "
        "dev_eval.photo_confirmed_traits, "
        "dev_eval.photo_deletion_ledger FROM itda_photo_service"
    )
    op.execute("DROP FUNCTION dev_eval.record_photo_dispatch_marker_v1(text,integer,text)")
    op.execute("DROP FUNCTION dev_eval.claim_photo_job_v1(text,timestamptz)")
    op.execute(
        "DROP FUNCTION dev_eval.transition_photo_job_status_v1"
        "(text,text,text,text,timestamptz)"
    )
    op.execute("DROP TABLE dev_eval.photo_deletion_ledger")
    op.execute("DROP TABLE dev_eval.photo_confirmed_traits")
    op.execute("DROP TABLE dev_eval.photo_trait_candidates")
    op.execute("DROP TABLE dev_eval.photo_job_dispatch_markers")
    op.execute("DROP TABLE dev_eval.photo_jobs")
