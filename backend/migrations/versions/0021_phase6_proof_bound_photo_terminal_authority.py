"""Bind photo filesystem ownership and terminal state to exact durable proof.

Revision 0021 removes the photo service's generic terminal mutation authority.
Service callers may claim one durable filesystem binding, serialize an exact
operation, perform the sole queued-to-running transition, append typed deletion
proof, and finalize only when that exact proof exists. Legacy ledger rows remain
unaltered and carry a NULL operation key; they cannot authorize v3 finalization.

Rev9 durable saga: the finalizer marks ``filesystem_cleanup_pending`` so the
terminal commit never depends on irreversible filesystem removal; a separate
service-only completion function clears the marker only after the binding
directory is released. Durable per-image slot authority replaces the
process-local exactly-once registry.
"""

# ruff: noqa: E501

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0021_phase6_proof_bound_photo_terminal_authority"
down_revision = "0020_phase6_exclusive_photo_mutation_authority"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OWNER = "itda_photo_write_authority"
_SERVICE = "itda_photo_service"
_SERVICE_GUARD = (
    "IF session_user <> 'itda_photo_service' THEN "
    "RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '42501'; END IF;"
)
_V3_JOB_GUARD = (
    "IF p_job_id IS NULL OR p_job_id !~ '^[0-9a-f]{64}$' "
    "OR p_profile_id IS NULL OR char_length(p_profile_id) NOT BETWEEN 1 AND 160 THEN "
    "RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;"
)

_V3_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("create_photo_job_v3", "(text,text,text)"),
    ("claim_photo_job_filesystem_binding_v3", "(text,text)"),
    ("read_photo_job_filesystem_binding_v3", "(text,text)"),
    ("lock_photo_job_operation_v3", "(text,text,text)"),
    ("list_photo_cleanup_candidates_v3", "()"),
    ("transition_photo_job_nonterminal_v3", "(text,text,text,text,timestamptz)"),
    ("record_photo_dispatch_marker_v3", "(text,text,integer,text)"),
    ("record_photo_candidate_batch_v3", "(text,text,text[],text[],text[],text[])"),
    ("annotate_photo_candidate_v3", "(text,text,text,text,boolean)"),
    ("save_photo_review_draft_v3", "(text,text,text,text[],text[],text[],boolean[])"),
    ("discard_photo_review_draft_v3", "(text,text)"),
    ("confirm_photo_traits_v3", "(text,text,text,text[],text[],text[],boolean[],boolean[],text)"),
    ("append_photo_deletion_ledger_v3", "(text,text,text,text,text,integer,text)"),
    ("finalize_photo_job_terminal_v3", "(text,text,text,text,text,text,text,text)"),
    ("finalize_photo_job_unbound_explicit_deletion_v3", "(text,text)"),
    ("list_photo_deletion_ledger_v3", "(text,text)"),
    ("read_photo_cleanup_status_v3", "(text,text)"),
    ("complete_photo_filesystem_cleanup_v3", "(text,text,text,text)"),
    ("pending_photo_filesystem_release_v3", "(text,text,text,text)"),
    ("read_photo_filesystem_release_v3", "(text,text)"),
    ("reserve_photo_image_slot_v3", "(text,text,integer,text,text)"),
    ("commit_photo_image_slot_v3", "(text,text,integer,text,integer)"),
    ("read_photo_image_slots_v3", "(text,text)"),
)
_REVOKED_V2: tuple[tuple[str, str], ...] = (
    ("create_photo_job_v2", "(text,text,text)"),
    ("transition_photo_job_status_v2", "(text,text,text,text,text,timestamptz)"),
    ("claim_photo_job_v2", "(text,text,timestamptz)"),
    ("record_photo_dispatch_marker_v2", "(text,text,integer,text)"),
    ("record_photo_candidate_batch_v2", "(text,text,text[],text[],text[],text[])"),
    ("annotate_photo_candidate_v2", "(text,text,text,text,boolean)"),
    ("append_photo_deletion_ledger_v2", "(text,text,text,text,text)"),
    ("save_photo_review_draft_v2", "(text,text,text,text[],text[],text[],boolean[])"),
    ("discard_photo_review_draft_v2", "(text,text)"),
    ("confirm_photo_traits_v2", "(text,text,text,text[],text[],text[],boolean[],boolean[],text)"),
    ("list_reconcile_photo_jobs_v2", "()"),
    ("list_photo_deletion_ledger_v2", "(text,text)"),
)

# Canonical terminal-proof derivation, expressed once and reused by every
# projection/lock/Phase-B authority: the operation key is the two-MD5 pair
# over job/profile/cause/ledger reason_code, the digest is the built-in
# SHA256 over the residue frame with count 0. Every consumer derives the
# pair from the stored columns itself — caller-supplied hex is only ever
# compared against the derivation, never trusted as the truth.
_CANONICAL_KEY_SUFFIX = (
    "pg_catalog.md5('photo-terminal-v1|' || {job} || '|' || {profile} || '|' "
    "|| {cause} || '|' || {reason}) "
    "|| pg_catalog.md5('photo-terminal-v1|' || {job} || '|' || {profile} "
    "|| '|' || {cause} || '|' || {reason} || '|second-half')"
)


def _canonical_key_sql(job: str, profile: str, cause: str, reason: str) -> str:
    return _CANONICAL_KEY_SUFFIX.format(job=job, profile=profile, cause=cause, reason=reason)


def _configured_identifier(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError("proof-bound photo authority migration configuration rejected")
    return value


def _quote(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _create_relation() -> None:
    op.execute(
        """
        ALTER TABLE dev_eval.photo_deletion_ledger
        ADD COLUMN operation_key text NULL
            CHECK (operation_key IS NULL OR operation_key ~ '^[0-9a-f]{64}$'),
        ADD COLUMN residue_count integer NULL
            CHECK (residue_count IS NULL OR residue_count = 0)
        """
    )
    op.execute(
        """
        ALTER TABLE dev_eval.photo_jobs
        ADD COLUMN terminal_operation_key text NULL
            CHECK (terminal_operation_key IS NULL
                   OR terminal_operation_key ~ '^[0-9a-f]{64}$'),
        ADD COLUMN terminal_proof_digest text NULL
            CHECK (terminal_proof_digest IS NULL
                   OR terminal_proof_digest ~ '^[0-9a-f]{64}$'),
        ADD COLUMN filesystem_cleanup_pending boolean NOT NULL DEFAULT false,
        ADD COLUMN reconcile_attempted_at timestamptz NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX photo_deletion_ledger_v3_exact_uidx
        ON dev_eval.photo_deletion_ledger
            (job_id, cause, reason_code, operation_key)
        WHERE operation_key IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.photo_job_filesystem_bindings (
            job_id text PRIMARY KEY REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE CASCADE CHECK (job_id ~ '^[0-9a-f]{64}$'),
            profile_id text NOT NULL CHECK (
                char_length(profile_id) BETWEEN 1 AND 160
                AND profile_id ~ '^\\S(.*\\S)?$'
            ),
            claimed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute(f"ALTER TABLE dev_eval.photo_job_filesystem_bindings OWNER TO {_OWNER}")
    op.execute(
        """
        CREATE TABLE dev_eval.photo_job_image_slots (
            job_id text NOT NULL REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE CASCADE CHECK (job_id ~ '^[0-9a-f]{64}$'),
            profile_id text NOT NULL CHECK (
                char_length(profile_id) BETWEEN 1 AND 160
                AND profile_id ~ '^\\S(.*\\S)?$'
            ),
            image_index integer NOT NULL CHECK (image_index BETWEEN 1 AND 3),
            state text NOT NULL CHECK (state IN ('reserved','stored')),
            stored_name text NULL CHECK (stored_name ~ '^[0-9a-f]{32}$'),
            media_type text NOT NULL CHECK (
                media_type IN ('image/jpeg','image/png','image/webp')),
            byte_length integer NULL CHECK (
                byte_length IS NULL OR byte_length BETWEEN 1 AND 10485760),
            reserved_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            stored_at timestamptz NULL,
            PRIMARY KEY (job_id, image_index)
        )
        """
    )
    op.execute(f"ALTER TABLE dev_eval.photo_job_image_slots OWNER TO {_OWNER}")


def _create_functions() -> None:
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.create_photo_job_v3(
            p_job_id text, p_profile_id text, p_idempotency_key text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_inserted integer;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_job_id !~ '^[0-9a-f]{{64}}$'
               OR char_length(p_profile_id) NOT BETWEEN 1 AND 160
               OR (p_idempotency_key IS NOT NULL
                   AND char_length(p_idempotency_key) NOT BETWEEN 16 AND 160) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            INSERT INTO dev_eval.photo_jobs (job_id, profile_id, status, idempotency_key)
            VALUES (p_job_id, p_profile_id, 'queued', p_idempotency_key)
            ON CONFLICT DO NOTHING;
            GET DIAGNOSTICS v_inserted = ROW_COUNT;
            PERFORM 1 FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
              AND stored.idempotency_key IS NOT DISTINCT FROM p_idempotency_key
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            RETURN v_inserted=1;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_photo_cleanup_candidates_v3()
        RETURNS TABLE (
            job_id text, profile_id text, status text, cleanup_class text,
            terminal_operation_key text, terminal_proof_digest text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            RETURN QUERY
            WITH selected AS (
                SELECT stored.job_id
                FROM dev_eval.photo_jobs stored
                JOIN dev_eval.photo_job_filesystem_bindings binding
                  ON binding.job_id=stored.job_id AND binding.profile_id=stored.profile_id
                WHERE stored.job_id ~ '^[0-9a-f]{{64}}$'
                  AND ((stored.status='running' AND (
                          stored.lease_expires_at IS NULL
                          OR stored.lease_expires_at < CURRENT_TIMESTAMP))
                   OR (stored.status='queued' AND (
                          (stored.lease_expires_at IS NOT NULL
                           AND stored.lease_expires_at < CURRENT_TIMESTAMP)
                       OR (stored.lease_expires_at IS NULL
                           AND binding.claimed_at
                               < CURRENT_TIMESTAMP - interval '5 minutes')))
                   OR (stored.status IN ('failed','expired')
                       AND stored.terminal_operation_key IS NOT NULL
                       AND stored.terminal_proof_digest IS NOT NULL
                       AND stored.terminal_cause IS NOT NULL
                       AND EXISTS (
                        SELECT 1 FROM dev_eval.photo_deletion_ledger ledger
                        WHERE ledger.job_id=stored.job_id
                          AND ledger.cause=stored.terminal_cause
                          AND ledger.reason_code IS NOT NULL
                          AND ledger.operation_key={
            _canonical_key_sql(
                "stored.job_id", "stored.profile_id", "stored.terminal_cause", "ledger.reason_code"
            )
        }
                          AND ledger.operation_key=stored.terminal_operation_key
                          AND ledger.residue_proof_digest=stored.terminal_proof_digest
                          AND ledger.residue_count=0
                          AND ledger.operation_key ~ '^[0-9a-f]{{64}}$'
                          AND ledger.residue_proof_digest ~ '^[0-9a-f]{{64}}$')
                       AND stored.terminal_proof_digest=encode(pg_catalog.sha256(
                          pg_catalog.convert_to('photo-residue-v1|'
                              || stored.terminal_operation_key || '|0', 'UTF8')), 'hex'))
                   OR (stored.filesystem_cleanup_pending AND stored.status IN (
                          'succeeded','failed','expired','deleted')
                       AND stored.terminal_operation_key IS NOT NULL
                       AND stored.terminal_proof_digest IS NOT NULL
                       AND stored.terminal_cause IS NOT NULL
                       AND EXISTS (
                        SELECT 1 FROM dev_eval.photo_deletion_ledger ledger
                        WHERE ledger.job_id=stored.job_id
                          AND ledger.cause=stored.terminal_cause
                          AND ledger.reason_code IS NOT NULL
                          AND ledger.operation_key={
            _canonical_key_sql(
                "stored.job_id", "stored.profile_id", "stored.terminal_cause", "ledger.reason_code"
            )
        }
                          AND ledger.operation_key=stored.terminal_operation_key
                          AND ledger.residue_proof_digest=stored.terminal_proof_digest
                          AND ledger.residue_count=0)
                       AND stored.terminal_proof_digest=encode(pg_catalog.sha256(
                          pg_catalog.convert_to('photo-residue-v1|'
                              || stored.terminal_operation_key || '|0', 'UTF8')), 'hex')))
                ORDER BY stored.reconcile_attempted_at NULLS FIRST,
                    stored.reconcile_attempted_at, stored.updated_at, stored.job_id
                LIMIT 256
                FOR UPDATE OF stored SKIP LOCKED
            ), claimed AS (
                UPDATE dev_eval.photo_jobs stored
                SET reconcile_attempted_at=CURRENT_TIMESTAMP
                FROM selected
                WHERE stored.job_id=selected.job_id
                RETURNING stored.job_id, stored.profile_id, stored.status,
                    stored.filesystem_cleanup_pending,
                    stored.terminal_operation_key, stored.terminal_proof_digest
            )
            SELECT claimed.job_id, claimed.profile_id, claimed.status,
                CASE
                    WHEN claimed.status='running' THEN 'worker_crash'::text
                    WHEN claimed.status='queued' THEN 'expiry'::text
                    WHEN claimed.filesystem_cleanup_pending THEN 'filesystem_release'::text
                    ELSE 'orphan_cleanup'::text
                END,
                claimed.terminal_operation_key, claimed.terminal_proof_digest
            FROM claimed;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.claim_photo_job_filesystem_binding_v3(
            p_job_id text, p_profile_id text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_inserted integer;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF char_length(p_profile_id) NOT BETWEEN 1 AND 160 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status INTO v_status FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_status NOT IN ('queued','running') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF EXISTS (SELECT 1 FROM dev_eval.photo_job_filesystem_bindings stored
                       WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id) THEN
                RETURN false;
            END IF;
            INSERT INTO dev_eval.photo_job_filesystem_bindings (job_id, profile_id)
            VALUES (p_job_id, p_profile_id);
            GET DIAGNOSTICS v_inserted = ROW_COUNT;
            RETURN v_inserted = 1;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_job_filesystem_binding_v3(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (binding_claimed boolean)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            RETURN QUERY SELECT true
            FROM dev_eval.photo_job_filesystem_bindings binding
            JOIN dev_eval.photo_jobs job ON job.job_id=binding.job_id
            WHERE binding.job_id=p_job_id AND binding.profile_id=p_profile_id
              AND job.profile_id=p_profile_id
            FOR UPDATE OF binding;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.lock_photo_job_operation_v3(
            p_job_id text, p_profile_id text, p_operation_kind text
        ) RETURNS TABLE (status text, lease_expires_at timestamptz, binding_claimed boolean)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_lease timestamptz; v_binding boolean;
                v_ptr_operation text; v_ptr_digest text; v_claimed_at timestamptz;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_operation_kind IS NULL
               OR p_operation_kind NOT IN ('upload','analysis','terminal','reconcile') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT job.status, job.lease_expires_at, binding.job_id IS NOT NULL,
                job.terminal_operation_key, job.terminal_proof_digest,
                binding.claimed_at
            INTO v_status, v_lease, v_binding, v_ptr_operation, v_ptr_digest,
                v_claimed_at
            FROM dev_eval.photo_jobs job
            LEFT JOIN dev_eval.photo_job_filesystem_bindings binding
              ON binding.job_id=job.job_id AND binding.profile_id=job.profile_id
            WHERE job.job_id=p_job_id AND job.profile_id=p_profile_id
            FOR UPDATE OF job;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF (p_operation_kind='upload' AND v_status <> 'queued')
               OR (p_operation_kind='analysis' AND (
                    v_status NOT IN ('queued','running') OR NOT v_binding))
               OR (p_operation_kind IN ('terminal','reconcile') AND NOT v_binding)
               OR (p_operation_kind='reconcile' AND NOT (
                    (v_status='running' AND (v_lease IS NULL OR v_lease < CURRENT_TIMESTAMP))
                    OR (v_status='queued' AND (
                        (v_lease IS NOT NULL AND v_lease < CURRENT_TIMESTAMP)
                        OR (v_lease IS NULL AND v_claimed_at IS NOT NULL
                            AND v_claimed_at
                                < CURRENT_TIMESTAMP - interval '5 minutes')))
                    OR (v_status IN ('failed','expired')
                        AND v_ptr_operation IS NOT NULL AND v_ptr_digest IS NOT NULL
                        AND EXISTS (
                        SELECT 1 FROM dev_eval.photo_deletion_ledger ledger
                        JOIN dev_eval.photo_jobs job
                          ON job.job_id=ledger.job_id
                         AND job.job_id=p_job_id AND job.profile_id=p_profile_id
                        WHERE ledger.job_id=p_job_id
                          AND ledger.cause=job.terminal_cause
                          AND ledger.reason_code IS NOT NULL
                          AND ledger.operation_key={
            _canonical_key_sql(
                "p_job_id", "p_profile_id", "job.terminal_cause", "ledger.reason_code"
            )
        }
                          AND ledger.operation_key=v_ptr_operation
                          AND ledger.residue_proof_digest=v_ptr_digest
                          AND ledger.residue_count=0)
                        AND v_ptr_digest=encode(pg_catalog.sha256(
                            pg_catalog.convert_to('photo-residue-v1|'
                                || v_ptr_operation || '|0', 'UTF8')), 'hex')))) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            RETURN QUERY SELECT v_status, v_lease, v_binding;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.transition_photo_job_nonterminal_v3(
            p_job_id text, p_profile_id text, p_from_status text,
            p_to_status text, p_lease_expires_at timestamptz
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status INTO v_status FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_status IS DISTINCT FROM p_from_status
               OR p_from_status <> 'queued' OR p_to_status <> 'running'
               OR p_lease_expires_at IS NULL
               OR p_lease_expires_at <= CURRENT_TIMESTAMP THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            UPDATE dev_eval.photo_jobs stored
            SET status='running', lease_expires_at=p_lease_expires_at,
                updated_at=CURRENT_TIMESTAMP
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id;
            RETURN v_status;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.record_photo_dispatch_marker_v3(
            p_job_id text, p_profile_id text, p_attempt integer, p_marker text
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_existing record;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_attempt IS DISTINCT FROM 1
               OR p_marker NOT IN
                    ('reserved','prepared','client_constructed','send_boundary') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status INTO v_status
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_status <> 'running' OR NOT EXISTS (
                SELECT 1 FROM dev_eval.photo_job_filesystem_bindings binding
                WHERE binding.job_id=p_job_id AND binding.profile_id=p_profile_id
            ) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            SELECT marker INTO v_existing
              FROM dev_eval.photo_job_dispatch_markers stored
             WHERE stored.job_id=p_job_id AND stored.attempt=1
               AND stored.marker=p_marker;
            IF FOUND THEN
                RETURN;  -- exact duplicate is idempotent
            END IF;
            -- Create-only prefix state machine: reserved requires the empty
            -- set; prepared requires reserved with no later marker; the
            -- optional client_constructed requires reserved+prepared with no
            -- send; send_boundary requires reserved+prepared (the synthetic
            -- provider path never claims client_constructed).
            IF (p_marker='reserved' AND EXISTS (
                    SELECT 1 FROM dev_eval.photo_job_dispatch_markers later
                    WHERE later.job_id=p_job_id AND later.attempt=1))
               OR (p_marker='prepared' AND NOT EXISTS (
                    SELECT 1 FROM dev_eval.photo_job_dispatch_markers prior
                    WHERE prior.job_id=p_job_id AND prior.attempt=1
                      AND prior.marker='reserved'))
               OR (p_marker='prepared' AND EXISTS (
                    SELECT 1 FROM dev_eval.photo_job_dispatch_markers later
                    WHERE later.job_id=p_job_id AND later.attempt=1
                      AND later.marker IN ('client_constructed','send_boundary')))
               OR (p_marker='client_constructed' AND (
                    NOT EXISTS (SELECT 1 FROM dev_eval.photo_job_dispatch_markers prior
                        WHERE prior.job_id=p_job_id AND prior.attempt=1
                          AND prior.marker='reserved')
                    OR NOT EXISTS (SELECT 1 FROM dev_eval.photo_job_dispatch_markers prior
                        WHERE prior.job_id=p_job_id AND prior.attempt=1
                          AND prior.marker='prepared')
                    OR EXISTS (SELECT 1 FROM dev_eval.photo_job_dispatch_markers later
                        WHERE later.job_id=p_job_id AND later.attempt=1
                          AND later.marker='send_boundary')))
               OR (p_marker='send_boundary' AND (
                    NOT EXISTS (SELECT 1 FROM dev_eval.photo_job_dispatch_markers prior
                        WHERE prior.job_id=p_job_id AND prior.attempt=1
                          AND prior.marker='reserved')
                    OR NOT EXISTS (SELECT 1 FROM dev_eval.photo_job_dispatch_markers prior
                        WHERE prior.job_id=p_job_id AND prior.attempt=1
                          AND prior.marker='prepared'))) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            INSERT INTO dev_eval.photo_job_dispatch_markers (job_id, attempt, marker)
            VALUES (p_job_id, p_attempt, p_marker);
        END $function$;
        """
    )
    wrappers = (
        (
            "record_photo_candidate_batch_v3",
            "p_job_id text, p_profile_id text, p_candidate_ids text[], p_trait_ids text[], p_texts_ko text[], p_candidate_set_sha256s text[]",
            "integer",
            "running,succeeded",
            "RETURN dev_eval.record_photo_candidate_batch_v2(p_job_id, p_profile_id, p_candidate_ids, p_trait_ids, p_texts_ko, p_candidate_set_sha256s);",
        ),
        (
            "annotate_photo_candidate_v3",
            "p_job_id text, p_profile_id text, p_candidate_id text, p_edited_text_ko text, p_excluded boolean",
            "void",
            "succeeded",
            "PERFORM dev_eval.annotate_photo_candidate_v2(p_job_id, p_profile_id, p_candidate_id, p_edited_text_ko, p_excluded); RETURN;",
        ),
        (
            "save_photo_review_draft_v3",
            "p_job_id text, p_profile_id text, p_draft_digest text, p_candidate_ids text[], p_trait_ids text[], p_edited_texts_ko text[], p_excluded_flags boolean[]",
            "boolean",
            "succeeded",
            "RETURN dev_eval.save_photo_review_draft_v2(p_job_id, p_profile_id, p_draft_digest, p_candidate_ids, p_trait_ids, p_edited_texts_ko, p_excluded_flags);",
        ),
        (
            "discard_photo_review_draft_v3",
            "p_job_id text, p_profile_id text",
            "boolean",
            "succeeded",
            "RETURN dev_eval.discard_photo_review_draft_v2(p_job_id, p_profile_id);",
        ),
        (
            "confirm_photo_traits_v3",
            "p_job_id text, p_profile_id text, p_draft_digest text, p_trait_ids text[], p_texts_ko text[], p_source_candidate_ids text[], p_included_flags boolean[], p_blank_flags boolean[], p_receipt_id text",
            "text",
            "succeeded",
            "RETURN dev_eval.confirm_photo_traits_v2(p_job_id, p_profile_id, p_draft_digest, p_trait_ids, p_texts_ko, p_source_candidate_ids, p_included_flags, p_blank_flags, p_receipt_id);",
        ),
    )
    for name, arguments, returns, states, invocation in wrappers:
        allowed = ",".join(f"'{state}'" for state in states.split(","))
        op.execute(
            f"""
            CREATE FUNCTION dev_eval.{name}({arguments})
            RETURNS {returns} LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            DECLARE v_status text;
            BEGIN
                {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
                PERFORM pg_catalog.pg_advisory_xact_lock(
                    pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
                SELECT status INTO v_status FROM dev_eval.photo_jobs
                WHERE job_id=p_job_id AND profile_id=p_profile_id FOR UPDATE;
                IF NOT FOUND OR v_status NOT IN ({allowed}) THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
                {invocation}
            END $function$;
            """
        )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.append_photo_deletion_ledger_v3(
            p_job_id text, p_profile_id text, p_cause text,
            p_reason_code text, p_operation_key text, p_residue_count integer,
            p_residue_digest text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_inserted integer;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_cause IS NULL
               OR p_cause NOT IN ('success','rejection','validation_failure','provider_error','timeout','worker_crash','explicit_deletion','expiry','orphan_cleanup')
               OR p_reason_code IS NULL
               OR p_reason_code !~ '^[A-Z][A-Z0-9_]{{2,63}}$'
               OR p_operation_key IS NULL
               OR p_residue_digest IS NULL
               OR p_operation_key IS DISTINCT FROM {
            _canonical_key_sql("p_job_id", "p_profile_id", "p_cause", "p_reason_code")
        }
               OR p_residue_count IS DISTINCT FROM 0
               OR p_residue_digest !~ '^[0-9a-f]{{64}}$'
               OR p_residue_digest IS DISTINCT FROM encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        'photo-residue-v1|' || p_operation_key || '|0', 'UTF8')),
                    'hex') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status INTO v_status FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF v_status='deleted' AND EXISTS (
                SELECT 1 FROM dev_eval.photo_deletion_ledger ledger
                WHERE ledger.job_id=p_job_id AND ledger.cause=p_cause
                  AND ledger.reason_code=p_reason_code
                  AND ledger.operation_key=p_operation_key
                  AND ledger.residue_count=0
                  AND ledger.residue_proof_digest=p_residue_digest
            ) THEN RETURN false; END IF;
            IF v_status NOT IN ('queued','running','succeeded','failed','expired') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            BEGIN
                INSERT INTO dev_eval.photo_deletion_ledger
                    (job_id, cause, reason_code, operation_key, residue_count,
                     residue_proof_digest)
                VALUES (p_job_id, p_cause, p_reason_code, p_operation_key,
                        p_residue_count, p_residue_digest);
                GET DIAGNOSTICS v_inserted = ROW_COUNT;
                RETURN v_inserted=1;
            EXCEPTION WHEN unique_violation THEN
                IF EXISTS (
                    SELECT 1 FROM dev_eval.photo_deletion_ledger ledger
                    WHERE ledger.job_id=p_job_id AND ledger.cause=p_cause
                      AND ledger.reason_code=p_reason_code
                      AND ledger.operation_key=p_operation_key
                      AND ledger.residue_count=0
                      AND ledger.residue_proof_digest=p_residue_digest
                ) THEN RETURN false; END IF;
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_photo_deletion_ledger_v3(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            ledger_seq bigint, job_id text, cause text, reason_code text,
            recorded_at timestamptz, operation_key text, residue_count integer,
            residue_proof_digest text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            IF NOT EXISTS (SELECT 1 FROM dev_eval.photo_jobs stored
                WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id) THEN
                RETURN;
            END IF;
            RETURN QUERY SELECT ledger.ledger_seq, ledger.job_id, ledger.cause,
                ledger.reason_code, ledger.recorded_at, ledger.operation_key,
                ledger.residue_count, ledger.residue_proof_digest
            FROM dev_eval.photo_deletion_ledger ledger
            WHERE ledger.job_id=p_job_id ORDER BY ledger.ledger_seq;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_cleanup_status_v3(
            p_job_id text, p_profile_id text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_cause text; v_ptr_operation text; v_ptr_digest text;
                v_binding boolean; v_count integer; v_pending boolean;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            SELECT job.status, job.terminal_cause,
                job.terminal_operation_key, job.terminal_proof_digest,
                binding.job_id IS NOT NULL, job.filesystem_cleanup_pending
            INTO v_status, v_cause, v_ptr_operation, v_ptr_digest, v_binding, v_pending
            FROM dev_eval.photo_jobs job
            LEFT JOIN dev_eval.photo_job_filesystem_bindings binding
              ON binding.job_id=job.job_id AND binding.profile_id=job.profile_id
            WHERE job.job_id=p_job_id AND job.profile_id=p_profile_id
            FOR UPDATE OF job;
            IF NOT FOUND THEN
                RETURN true;
            END IF;
            IF v_status NOT IN ('failed','expired','deleted','succeeded') THEN
                RETURN false;
            END IF;
            IF v_ptr_operation IS NULL OR v_ptr_digest IS NULL THEN
                RETURN true;
            END IF;
            SELECT count(*) INTO v_count FROM dev_eval.photo_deletion_ledger ledger
            WHERE ledger.job_id=p_job_id
              AND ledger.cause=v_cause
              AND ledger.operation_key=v_ptr_operation
              AND ledger.operation_key={
            _canonical_key_sql("p_job_id", "p_profile_id", "v_cause", "ledger.reason_code")
        }
              AND ledger.residue_proof_digest=v_ptr_digest
              AND ledger.residue_proof_digest = encode(pg_catalog.sha256(
                    pg_catalog.convert_to('photo-residue-v1|' || v_ptr_operation || '|0',
                        'UTF8')), 'hex')
              AND ledger.operation_key ~ '^[0-9a-f]{{64}}$'
              AND ledger.residue_proof_digest ~ '^[0-9a-f]{{64}}$'
              AND ledger.residue_count=0;
            RETURN v_count IS DISTINCT FROM 1 OR v_pending OR v_binding;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.finalize_photo_job_terminal_v3(
            p_job_id text, p_profile_id text, p_from_status text,
            p_to_status text, p_cause text, p_reason_code text,
            p_operation_key text, p_residue_digest text
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_terminal_cause text; v_count integer; v_legal boolean;
                v_ptr_operation text; v_ptr_digest text;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status, stored.terminal_cause,
                stored.terminal_operation_key, stored.terminal_proof_digest
            INTO v_status, v_terminal_cause, v_ptr_operation, v_ptr_digest
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR NOT EXISTS (
                SELECT 1 FROM dev_eval.photo_job_filesystem_bindings binding
                WHERE binding.job_id=p_job_id AND binding.profile_id=p_profile_id
            ) THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            v_legal := CASE
                WHEN p_cause='success' THEN p_to_status='succeeded' AND p_from_status='running'
                WHEN p_cause IN ('rejection','validation_failure') THEN p_to_status='failed' AND p_from_status IN ('queued','running')
                WHEN p_cause IN ('provider_error','timeout','worker_crash') THEN p_to_status='failed' AND p_from_status='running'
                WHEN p_cause='expiry' THEN p_to_status='expired' AND p_from_status IN ('queued','running')
                WHEN p_cause='explicit_deletion' THEN p_to_status='deleted' AND p_from_status IN ('queued','running','succeeded','failed','expired')
                WHEN p_cause='orphan_cleanup' THEN p_to_status='deleted' AND p_from_status IN ('failed','expired')
                ELSE false END;
            IF NOT v_legal OR p_reason_code IS NULL
               OR p_reason_code !~ '^[A-Z][A-Z0-9_]{{2,63}}$'
               OR p_operation_key IS NULL
               OR p_residue_digest IS NULL
               OR p_operation_key IS DISTINCT FROM {
            _canonical_key_sql("p_job_id", "p_profile_id", "p_cause", "p_reason_code")
        }
               OR p_residue_digest !~ '^[0-9a-f]{{64}}$'
               OR p_residue_digest IS DISTINCT FROM encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        'photo-residue-v1|' || p_operation_key || '|0', 'UTF8')),
                    'hex') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF v_status=p_to_status AND v_terminal_cause=p_cause THEN
                IF v_ptr_operation IS DISTINCT FROM p_operation_key
                   OR v_ptr_digest IS DISTINCT FROM p_residue_digest THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
                SELECT count(*) INTO v_count FROM dev_eval.photo_deletion_ledger ledger
                WHERE ledger.job_id=p_job_id AND ledger.cause=p_cause
                  AND ledger.reason_code=p_reason_code
                  AND ledger.operation_key=p_operation_key
                  AND ledger.residue_count=0
                  AND ledger.residue_proof_digest=p_residue_digest;
                IF v_count=1 THEN RETURN v_status; END IF;
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF v_status IS DISTINCT FROM p_from_status THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            SELECT count(*) INTO v_count FROM dev_eval.photo_deletion_ledger ledger
            WHERE ledger.job_id=p_job_id AND ledger.cause=p_cause
              AND ledger.reason_code=p_reason_code
              AND ledger.operation_key=p_operation_key
              AND ledger.residue_count=0
              AND ledger.residue_proof_digest=p_residue_digest;
            IF v_count <> 1 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            UPDATE dev_eval.photo_jobs stored SET status=p_to_status,
                lease_expires_at=NULL, terminal_cause=p_cause,
                terminal_operation_key=p_operation_key,
                terminal_proof_digest=p_residue_digest,
                filesystem_cleanup_pending=true,
                updated_at=CURRENT_TIMESTAMP
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id;
            RETURN v_status;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.finalize_photo_job_unbound_explicit_deletion_v3(
            p_job_id text, p_profile_id text
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_cause text; v_ptr_operation text;
                v_ptr_digest text; v_pending boolean; v_lease timestamptz;
                v_reconcile_attempted timestamptz; v_prior_count integer;
                v_ledger_count integer; v_explicit_count integer;
                v_explicit_total integer; v_operation text; v_digest text;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status, stored.terminal_cause,
                stored.terminal_operation_key, stored.terminal_proof_digest,
                stored.filesystem_cleanup_pending, stored.lease_expires_at,
                stored.reconcile_attempted_at
            INTO v_status, v_cause, v_ptr_operation, v_ptr_digest, v_pending,
                v_lease, v_reconcile_attempted
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR EXISTS (
                SELECT 1 FROM dev_eval.photo_job_filesystem_bindings binding
                WHERE binding.job_id=p_job_id
            ) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            v_operation := {
            _canonical_key_sql(
                "p_job_id",
                "p_profile_id",
                "'explicit_deletion'",
                "'PHOTO_EXPLICIT_DELETION'",
            )
        };
            v_digest := encode(pg_catalog.sha256(pg_catalog.convert_to(
                'photo-residue-v1|' || v_operation || '|0', 'UTF8')), 'hex');
            IF v_status='deleted' THEN
                SELECT count(*), count(*) FILTER (
                    WHERE ledger.reason_code='PHOTO_EXPLICIT_DELETION'
                      AND ledger.operation_key=v_operation
                      AND ledger.residue_count=0
                      AND ledger.residue_proof_digest=v_digest)
                INTO v_explicit_total, v_explicit_count
                FROM dev_eval.photo_deletion_ledger ledger
                WHERE ledger.job_id=p_job_id
                  AND ledger.cause='explicit_deletion';
                IF v_cause='explicit_deletion'
                   AND v_ptr_operation=v_operation AND v_ptr_digest=v_digest
                   AND NOT v_pending AND v_explicit_total=1
                   AND v_explicit_count=1 THEN
                    RETURN v_status;
                END IF;
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF v_status='queued' THEN
                IF v_cause IS NOT NULL OR v_ptr_operation IS NOT NULL
                   OR v_ptr_digest IS NOT NULL OR v_pending
                   OR v_lease IS NOT NULL OR v_reconcile_attempted IS NOT NULL
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_job_image_slots stored
                              WHERE stored.job_id=p_job_id)
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_job_dispatch_markers stored
                              WHERE stored.job_id=p_job_id)
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_trait_candidates stored
                              WHERE stored.job_id=p_job_id)
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_review_drafts stored
                              WHERE stored.job_id=p_job_id)
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_confirmed_traits stored
                              WHERE stored.job_id=p_job_id)
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_confirmation_receipts stored
                              WHERE stored.job_id=p_job_id)
                   OR EXISTS (SELECT 1 FROM dev_eval.photo_deletion_ledger stored
                              WHERE stored.job_id=p_job_id) THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
            ELSIF v_status IN ('succeeded','failed','expired') THEN
                IF v_pending OR v_cause IS NULL OR v_ptr_operation IS NULL
                   OR v_ptr_digest IS NULL
                   OR NOT (CASE
                        WHEN v_status='succeeded' THEN v_cause='success'
                        WHEN v_status='failed' THEN v_cause IN (
                            'rejection','validation_failure','provider_error',
                            'timeout','worker_crash')
                        WHEN v_status='expired' THEN v_cause='expiry'
                        ELSE false END) THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
                SELECT count(*) INTO v_ledger_count
                FROM dev_eval.photo_deletion_ledger ledger
                WHERE ledger.job_id=p_job_id;
                SELECT count(*) INTO v_prior_count
                FROM dev_eval.photo_deletion_ledger ledger
                WHERE ledger.job_id=p_job_id AND ledger.cause=v_cause
                  AND ledger.reason_code IS NOT NULL
                  AND ledger.operation_key={
            _canonical_key_sql("p_job_id", "p_profile_id", "v_cause", "ledger.reason_code")
        }
                  AND ledger.operation_key=v_ptr_operation
                  AND ledger.residue_count=0
                  AND ledger.residue_proof_digest=v_ptr_digest
                  AND v_ptr_digest=encode(pg_catalog.sha256(pg_catalog.convert_to(
                      'photo-residue-v1|' || v_ptr_operation || '|0', 'UTF8')), 'hex');
                IF v_ledger_count <> 1 OR v_prior_count <> 1 THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
            ELSE
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            INSERT INTO dev_eval.photo_deletion_ledger
                (job_id, cause, reason_code, operation_key, residue_count,
                 residue_proof_digest)
            VALUES (p_job_id, 'explicit_deletion', 'PHOTO_EXPLICIT_DELETION',
                    v_operation, 0, v_digest)
            ON CONFLICT (job_id, cause, reason_code, operation_key)
                WHERE operation_key IS NOT NULL DO NOTHING;
            SELECT count(*), count(*) FILTER (
                WHERE ledger.reason_code='PHOTO_EXPLICIT_DELETION'
                  AND ledger.operation_key=v_operation
                  AND ledger.residue_count=0
                  AND ledger.residue_proof_digest=v_digest)
            INTO v_explicit_total, v_explicit_count
            FROM dev_eval.photo_deletion_ledger ledger
            WHERE ledger.job_id=p_job_id
              AND ledger.cause='explicit_deletion';
            IF v_explicit_total <> 1 OR v_explicit_count <> 1 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            UPDATE dev_eval.photo_jobs stored
            SET status='deleted', lease_expires_at=NULL,
                terminal_cause='explicit_deletion',
                terminal_operation_key=v_operation,
                terminal_proof_digest=v_digest,
                filesystem_cleanup_pending=false,
                updated_at=CURRENT_TIMESTAMP
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id;
            RETURN v_status;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.complete_photo_filesystem_cleanup_v3(
            p_job_id text, p_profile_id text, p_operation_key text, p_residue_digest text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_pending boolean; v_cause text;
                v_ptr_operation text; v_ptr_digest text; v_count integer;
                v_reason text;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_operation_key IS NULL
               OR p_operation_key !~ '^[0-9a-f]{{64}}$'
               OR p_residue_digest IS NULL
               OR p_residue_digest !~ '^[0-9a-f]{{64}}$' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status, stored.filesystem_cleanup_pending,
                stored.terminal_cause, stored.terminal_operation_key,
                stored.terminal_proof_digest
            INTO v_status, v_pending, v_cause, v_ptr_operation, v_ptr_digest
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_status NOT IN ('succeeded','failed','expired','deleted')
               OR v_cause IS NULL
               OR v_ptr_operation IS NULL OR v_ptr_digest IS NULL
               OR v_ptr_operation <> p_operation_key
               OR v_ptr_digest <> p_residue_digest
               OR v_ptr_digest <> encode(pg_catalog.sha256(
                    pg_catalog.convert_to('photo-residue-v1|' || p_operation_key || '|0',
                        'UTF8')), 'hex') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            SELECT count(*), max(ledger.reason_code) INTO v_count, v_reason
            FROM dev_eval.photo_deletion_ledger ledger
            WHERE ledger.job_id=p_job_id
              AND ledger.cause=v_cause
              AND ledger.reason_code IS NOT NULL
              AND ledger.operation_key={
            _canonical_key_sql("p_job_id", "p_profile_id", "v_cause", "ledger.reason_code")
        }
              AND ledger.operation_key=v_ptr_operation
              AND ledger.residue_proof_digest=v_ptr_digest
              AND ledger.residue_count=0
              AND ledger.operation_key ~ '^[0-9a-f]{{64}}$'
              AND ledger.residue_proof_digest ~ '^[0-9a-f]{{64}}$';
            IF v_count <> 1 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF NOT v_pending THEN
                RETURN false;
            END IF;
            DELETE FROM dev_eval.photo_job_filesystem_bindings binding
            WHERE binding.job_id=p_job_id AND binding.profile_id=p_profile_id;
            UPDATE dev_eval.photo_jobs stored
            SET filesystem_cleanup_pending=false, updated_at=CURRENT_TIMESTAMP
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id;
            RETURN true;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.pending_photo_filesystem_release_v3(
            p_job_id text, p_profile_id text, p_operation_key text, p_residue_digest text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_pending boolean; v_cause text;
                v_ptr_operation text; v_ptr_digest text;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_operation_key IS NULL
               OR p_operation_key !~ '^[0-9a-f]{{64}}$'
               OR p_residue_digest IS NULL
               OR p_residue_digest !~ '^[0-9a-f]{{64}}$' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status, stored.filesystem_cleanup_pending,
                stored.terminal_cause, stored.terminal_operation_key,
                stored.terminal_proof_digest
            INTO v_status, v_pending, v_cause, v_ptr_operation, v_ptr_digest
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_status NOT IN ('succeeded','failed','expired','deleted')
               OR v_cause IS NULL
               OR v_ptr_operation IS DISTINCT FROM p_operation_key
               OR v_ptr_digest IS DISTINCT FROM p_residue_digest
               OR v_ptr_digest <> encode(pg_catalog.sha256(
                    pg_catalog.convert_to('photo-residue-v1|' || p_operation_key || '|0',
                        'UTF8')), 'hex')
               OR NOT EXISTS (
                    SELECT 1 FROM dev_eval.photo_deletion_ledger ledger
                    WHERE ledger.job_id=p_job_id
                      AND ledger.cause=v_cause
                      AND ledger.reason_code IS NOT NULL
                      AND ledger.operation_key={
            _canonical_key_sql("p_job_id", "p_profile_id", "v_cause", "ledger.reason_code")
        }
                      AND ledger.operation_key=v_ptr_operation
                      AND ledger.residue_proof_digest=v_ptr_digest
                      AND ledger.residue_count=0
                      AND ledger.operation_key ~ '^[0-9a-f]{{64}}$'
                      AND ledger.residue_proof_digest ~ '^[0-9a-f]{{64}}$') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            RETURN v_pending;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_filesystem_release_v3(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (operation_key text, proof_digest text)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            RETURN QUERY SELECT stored.terminal_operation_key,
                stored.terminal_proof_digest
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
              AND stored.status IN ('succeeded','failed','expired','deleted')
              AND stored.filesystem_cleanup_pending
              AND stored.terminal_cause IS NOT NULL
              AND stored.terminal_operation_key IS NOT NULL
              AND stored.terminal_proof_digest IS NOT NULL
              AND stored.terminal_proof_digest=encode(pg_catalog.sha256(
                    pg_catalog.convert_to('photo-residue-v1|'
                        || stored.terminal_operation_key || '|0', 'UTF8')), 'hex')
              AND (SELECT count(*) FROM dev_eval.photo_deletion_ledger ledger
                   WHERE ledger.job_id=stored.job_id
                     AND ledger.cause=stored.terminal_cause
                     AND ledger.reason_code IS NOT NULL
                     AND ledger.operation_key={
            _canonical_key_sql(
                "stored.job_id", "stored.profile_id", "stored.terminal_cause", "ledger.reason_code"
            )
        }
                     AND ledger.operation_key=stored.terminal_operation_key
                     AND ledger.residue_proof_digest=stored.terminal_proof_digest
                     AND ledger.residue_count=0)=1
            FOR UPDATE;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.reserve_photo_image_slot_v3(
            p_job_id text, p_profile_id text, p_image_index integer,
            p_stored_name text, p_media_type text
        ) RETURNS TABLE (
            state text, stored_name text, byte_length integer,
            media_type text, newly_reserved boolean
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_slot_state text; v_slot_name text;
                v_slot_length integer; v_slot_media_type text;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_image_index IS NULL OR p_image_index NOT BETWEEN 1 AND 3
               OR p_stored_name IS NULL OR p_stored_name !~ '^[0-9a-f]{{32}}$'
               OR p_media_type IS NULL
               OR p_media_type NOT IN ('image/jpeg','image/png','image/webp') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT stored.status INTO v_status FROM dev_eval.photo_jobs stored
            WHERE stored.job_id=p_job_id AND stored.profile_id=p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_status <> 'queued' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            SELECT slot.state, slot.stored_name, slot.byte_length, slot.media_type
            INTO v_slot_state, v_slot_name, v_slot_length, v_slot_media_type
            FROM dev_eval.photo_job_image_slots slot
            WHERE slot.job_id=p_job_id AND slot.profile_id=p_profile_id
              AND slot.image_index=p_image_index
            FOR UPDATE;
            IF v_slot_state IN ('reserved','stored') THEN
                IF v_slot_media_type IS DISTINCT FROM p_media_type THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
                RETURN QUERY SELECT v_slot_state, v_slot_name, v_slot_length,
                    v_slot_media_type, false;
                RETURN;
            END IF;
            INSERT INTO dev_eval.photo_job_image_slots
                (job_id, profile_id, image_index, state, stored_name, media_type)
            VALUES (p_job_id, p_profile_id, p_image_index, 'reserved',
                    p_stored_name, p_media_type);
            RETURN QUERY SELECT 'reserved'::text, p_stored_name, NULL::integer,
                p_media_type, true;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.commit_photo_image_slot_v3(
            p_job_id text, p_profile_id text, p_image_index integer,
            p_stored_name text, p_byte_length integer
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_slot_state text; v_slot_name text; v_slot_length integer;
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            IF p_image_index IS NULL OR p_image_index NOT BETWEEN 1 AND 3
               OR p_stored_name IS NULL OR p_stored_name !~ '^[0-9a-f]{{32}}$'
               OR p_byte_length IS NULL OR p_byte_length NOT BETWEEN 1 AND 10485760 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT slot.state, slot.stored_name, slot.byte_length
            INTO v_slot_state, v_slot_name, v_slot_length
            FROM dev_eval.photo_job_image_slots slot
            WHERE slot.job_id=p_job_id AND slot.profile_id=p_profile_id
              AND slot.image_index=p_image_index
            FOR UPDATE;
            IF NOT FOUND OR v_slot_name IS DISTINCT FROM p_stored_name THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            IF v_slot_state='stored' THEN
                IF v_slot_length IS DISTINCT FROM p_byte_length THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
                END IF;
                RETURN false;
            END IF;
            IF v_slot_state IS DISTINCT FROM 'reserved' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            UPDATE dev_eval.photo_job_image_slots slot
            SET state='stored', stored_name=p_stored_name,
                byte_length=p_byte_length, stored_at=CURRENT_TIMESTAMP
            WHERE slot.job_id=p_job_id AND slot.profile_id=p_profile_id
              AND slot.image_index=p_image_index;
            RETURN true;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_image_slots_v3(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            image_index integer, state text, stored_name text, byte_length integer,
            media_type text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            {_V3_JOB_GUARD}
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            RETURN QUERY SELECT slot.image_index, slot.state, slot.stored_name,
                slot.byte_length, slot.media_type
            FROM dev_eval.photo_job_image_slots slot
            WHERE slot.job_id=p_job_id AND slot.profile_id=p_profile_id
            ORDER BY slot.image_index;
        END $function$;
        """
    )


def _close_acls(runtime: str, builder: str) -> None:
    quoted_runtime = _quote(runtime)
    quoted_builder = _quote(builder)
    op.execute("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA dev_eval FROM PUBLIC")
    op.execute("REVOKE ALL ON dev_eval.photo_job_filesystem_bindings FROM PUBLIC")
    for role in (_SERVICE, quoted_runtime, quoted_builder, "CURRENT_USER"):
        op.execute(f"REVOKE ALL ON dev_eval.photo_job_filesystem_bindings FROM {role}")
    op.execute("REVOKE ALL ON dev_eval.photo_job_image_slots FROM PUBLIC")
    for role in (_SERVICE, quoted_runtime, quoted_builder, "CURRENT_USER"):
        op.execute(f"REVOKE ALL ON dev_eval.photo_job_image_slots FROM {role}")
    for name, signature in _REVOKED_V2:
        op.execute(f"REVOKE EXECUTE ON FUNCTION dev_eval.{name}{signature} FROM {_SERVICE}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{name}{signature} TO {_OWNER}")
    for name, signature in _V3_FUNCTIONS:
        identity = f"dev_eval.{name}{signature}"
        op.execute(f"ALTER FUNCTION {identity} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM {quoted_runtime}")
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM {quoted_builder}")
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM {_OWNER}")
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM CURRENT_USER")
        op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_SERVICE}")


def upgrade() -> None:
    runtime = _configured_identifier("runtime_role")
    builder = _configured_identifier("label_builder_role")
    if runtime is None or builder is None:
        raise RuntimeError("proof-bound photo authority migration roles are required")
    _create_relation()
    _create_functions()
    _close_acls(runtime, builder)


def downgrade() -> None:
    connection = op.get_bind()
    evidence = connection.execute(
        sa.text(
            "SELECT (SELECT count(*) FROM dev_eval.photo_job_filesystem_bindings) + "
            "(SELECT count(*) FROM dev_eval.photo_deletion_ledger "
            " WHERE operation_key IS NOT NULL) + "
            "(SELECT count(*) FROM dev_eval.photo_jobs "
            " WHERE terminal_operation_key IS NOT NULL) + "
            "(SELECT count(*) FROM dev_eval.photo_job_image_slots) + "
            "(SELECT count(*) FROM dev_eval.photo_jobs "
            " WHERE filesystem_cleanup_pending)"
        )
    ).scalar_one()
    if int(evidence) != 0:
        raise RuntimeError(
            "0021 downgrade is intentionally irreversible after proof-bound photo evidence exists"
        )
    for name, signature in reversed(_V3_FUNCTIONS):
        op.execute(f"DROP FUNCTION dev_eval.{name}{signature}")
    op.execute("DROP TABLE dev_eval.photo_job_image_slots")
    op.execute("DROP TABLE dev_eval.photo_job_filesystem_bindings")
    op.execute("DROP INDEX dev_eval.photo_deletion_ledger_v3_exact_uidx")
    op.execute(
        "ALTER TABLE dev_eval.photo_deletion_ledger "
        "DROP COLUMN residue_count, DROP COLUMN operation_key"
    )
    op.execute(
        "ALTER TABLE dev_eval.photo_jobs "
        "DROP COLUMN filesystem_cleanup_pending, DROP COLUMN reconcile_attempted_at,"
        "DROP COLUMN terminal_proof_digest, DROP COLUMN terminal_operation_key"
    )
    for name, signature in _REVOKED_V2:
        identity = f"dev_eval.{name}{signature}"
        op.execute(f"REVOKE EXECUTE ON FUNCTION {identity} FROM {_OWNER}")
        op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_SERVICE}")
