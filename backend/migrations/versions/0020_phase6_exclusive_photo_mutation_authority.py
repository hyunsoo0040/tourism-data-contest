"""Make exact SECURITY DEFINER functions the exclusive photo write path.

Closes the direct-table bypass that migration 0018's broad application
grants left open. After this migration no application role — runtime,
photo service, label builder, ledger, or PUBLIC — holds INSERT, UPDATE,
DELETE, or TRUNCATE on any of the seven photo lifecycle relations, and
nobody but the owner can create objects in ``dev_eval``. The legacy 0018
functions lose their service EXECUTE grant; ten exact-purpose v2
functions with locked ``(job_id, profile_id)`` ownership checks become
the only mutation authority.

Every function revokes PUBLIC immediately after creation, pins
``search_path = pg_catalog, pg_temp``, schema-qualifies app relations,
uses no dynamic SQL, binds values only, checks the exact service
``session_user``, and validates migration-configured role identifiers
before quoting. Candidate/review/confirm batches accept only concrete
parallel typed arrays with equal cardinality 1..6, no NULL elements or
duplicates, and ``unnest(...) WITH ORDINALITY`` order preservation.
"""

# ruff: noqa: E501

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0020_phase6_exclusive_photo_mutation_authority"
down_revision = "0019_phase6_current_profile_sessions"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WRITE_AUTHORITY = "itda_photo_write_authority"
_AUTHORITY_SERVICE = "itda_photo_service"

# Exact mutation authority: the only functions that may write.
_FUNCTIONS: tuple[tuple[str, str], ...] = (
    (
        "create_photo_job_v2",
        "(text,text,text)",
    ),
    (
        "transition_photo_job_status_v2",
        "(text,text,text,text,text,timestamptz)",
    ),
    (
        "claim_photo_job_v2",
        "(text,text,timestamptz)",
    ),
    (
        "record_photo_dispatch_marker_v2",
        "(text,text,integer,text)",
    ),
    (
        "record_photo_candidate_batch_v2",
        "(text,text,text[],text[],text[],text[])",
    ),
    (
        "annotate_photo_candidate_v2",
        "(text,text,text,text,boolean)",
    ),
    (
        "append_photo_deletion_ledger_v2",
        "(text,text,text,text,text)",
    ),
    (
        "save_photo_review_draft_v2",
        "(text,text,text,text[],text[],text[],boolean[])",
    ),
    (
        "discard_photo_review_draft_v2",
        "(text,text)",
    ),
    (
        "confirm_photo_traits_v2",
        "(text,text,text,text[],text[],text[],boolean[],boolean[],text)",
    ),
)

# Exact read projections: owner-scoped replacements for every lifecycle
# read. No table SELECT grant remains — reads only happen through these.
_READ_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("read_photo_job_v2", "(text,text)"),
    ("list_photo_candidates_v2", "(text,text)"),
    ("list_photo_confirmed_traits_v2", "(text,text)"),
    ("list_photo_dispatch_markers_v2", "(text,text)"),
    ("list_reconcile_photo_jobs_v2", "()"),
    ("read_photo_review_draft_v2", "(text,text)"),
    ("read_photo_confirmation_receipt_v2", "(text,text,text)"),
    ("list_photo_deletion_ledger_v2", "(text,text)"),
)


def _configured_identifier(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError("exclusive photo authority migration configuration rejected")
    return value


def _quote(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _require_role_topology(builder: str, runtime: str) -> None:
    """Assert the fixed photo role topology with production-safe flags."""

    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (:owner, :service, :builder, :runtime)"
        ),
        {
            "owner": _WRITE_AUTHORITY,
            "service": _AUTHORITY_SERVICE,
            "builder": builder,
            "runtime": runtime,
        },
    ).mappings()
    roles = {str(row["rolname"]): row for row in rows}
    if set(roles) != {_WRITE_AUTHORITY, _AUTHORITY_SERVICE, builder, runtime}:
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
    related = connection.execute(
        sa.text(
            "SELECT pg_catalog.pg_has_role(:runtime, :owner, 'MEMBER'), "
            "pg_catalog.pg_has_role(:owner, :runtime, 'MEMBER'), "
            "pg_catalog.pg_has_role(:runtime, :service, 'MEMBER'), "
            "pg_catalog.pg_has_role(:service, :runtime, 'MEMBER'), "
            "pg_catalog.pg_has_role(:builder, :owner, 'MEMBER'), "
            "pg_catalog.pg_has_role(:owner, :builder, 'MEMBER'), "
            "pg_catalog.pg_has_role(:builder, :service, 'MEMBER'), "
            "pg_catalog.pg_has_role(:service, :builder, 'MEMBER'), "
            "pg_catalog.pg_has_role(:builder, :runtime, 'MEMBER'), "
            "pg_catalog.pg_has_role(:runtime, :builder, 'MEMBER'), "
            "pg_catalog.pg_has_role(:owner, :service, 'MEMBER'), "
            "pg_catalog.pg_has_role(:service, :owner, 'MEMBER')"
        ),
        {
            "runtime": runtime,
            "owner": _WRITE_AUTHORITY,
            "service": _AUTHORITY_SERVICE,
            "builder": builder,
        },
    ).one()
    if any(bool(value) for value in related):
        raise RuntimeError("photo lifecycle roles must not be member-related")


def _assert_default_acl_closed(runtime: str, builder: str) -> None:
    """No creator/owner default ACL may grant photo authority to anyone."""

    leaked = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM pg_catalog.pg_default_acl d "
                "JOIN pg_catalog.pg_roles r ON r.oid=d.defaclrole "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a "
                "WHERE r.rolname IN (CURRENT_USER, :owner, :service, :runtime, :builder) "
                "AND (d.defaclnamespace=0 OR d.defaclnamespace=("
                "  SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='dev_eval')) "
                "AND NOT (a.grantee=d.defaclrole)"
            ),
            {
                "owner": _WRITE_AUTHORITY,
                "service": _AUTHORITY_SERVICE,
                "runtime": runtime,
                "builder": builder,
            },
        )
        .scalar_one()
    )
    if int(leaked) != 0:
        raise RuntimeError("exclusive photo authority default privileges rejected")


# Exact identity-argument allowlist as regprocedure literals. Comparing
# function oids against these casts matches the exact function identity —
# name AND argument types — so an unauthorized overload of an allowed name
# can never satisfy the allowlist side, and every grant on a non-allowlisted
# photo function is rejected regardless of grantee.
_ALLOWED_FUNCTIONS: tuple[str, ...] = tuple(
    f"dev_eval.{name}{signature}" for name, signature in (*_FUNCTIONS, *_READ_FUNCTIONS)
)
_OWNER_ONLY_FUNCTIONS: tuple[str, ...] = (
    "dev_eval.transition_photo_job_status_v1(text,text,text,text,timestamptz)",
    "dev_eval.claim_photo_job_v1(text,timestamptz)",
    "dev_eval.record_photo_dispatch_marker_v1(text,integer,text)",
)


def _assert_acl_closed() -> None:
    """Every lifecycle table and function carries exactly the intended ACL."""

    connection = op.get_bind()
    # No table privilege may exist for anyone but the owner: reads happen
    # only through the owner-scoped read projections.
    leaked_table = connection.execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(c.relacl, pg_catalog.acldefault('r',c.relowner))) a "
            "WHERE n.nspname='dev_eval' "
            "AND c.relname IN ('photo_jobs','photo_job_dispatch_markers',"
            "'photo_trait_candidates','photo_confirmed_traits',"
            "'photo_deletion_ledger','photo_review_drafts',"
            "'photo_confirmation_receipts') "
            "AND a.grantee <> c.relowner"
        ),
    ).scalar_one()
    leaked_sequence = connection.execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(c.relacl, pg_catalog.acldefault('S',c.relowner))) a "
            "WHERE n.nspname='dev_eval' AND c.relkind='S' "
            "AND c.relname IN ('photo_deletion_ledger_ledger_seq_seq') "
            "AND a.grantee <> c.relowner"
        ),
    ).scalar_one()
    leaked_legacy_function = connection.execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a "
            "WHERE n.nspname='dev_eval' "
            "AND p.proname IN ('transition_photo_job_status_v1',"
            "'claim_photo_job_v1','record_photo_dispatch_marker_v1') "
            "AND a.grantee <> p.proowner"
        ),
    ).scalar_one()
    # Exactly one service-only, non-grantable, owner-granted EXECUTE entry
    # per allowlisted function — nothing more, nothing less. The allowlist
    # is matched on exact regprocedure identity (name + argument types), so
    # an overload of an allowed name with different arguments carries a
    # different identity and is treated as an unexpected function.
    leaked_v2_function = connection.execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a "
            "WHERE n.nspname='dev_eval' "
            "AND p.oid = ANY(CAST(:allowed_procedures AS pg_catalog.regprocedure[])) "
            "AND NOT (a.grantee=(SELECT oid FROM pg_catalog.pg_roles "
            "                           WHERE rolname=:service) "
            "AND a.privilege_type='EXECUTE' AND a.grantor=p.proowner "
            "AND NOT a.is_grantable)"
        ),
        {
            "allowed_procedures": list(_ALLOWED_FUNCTIONS),
            "service": _AUTHORITY_SERVICE,
        },
    ).scalar_one()
    allowed_acl_entries = connection.execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))) a "
            "WHERE n.nspname='dev_eval' "
            "AND p.oid = ANY(CAST(:allowed_procedures AS pg_catalog.regprocedure[])) "
            "AND a.grantee=(SELECT oid FROM pg_catalog.pg_roles "
            "               WHERE rolname=:service) "
            "AND a.privilege_type='EXECUTE' AND a.grantor=p.proowner "
            "AND NOT a.is_grantable"
        ),
        {
            "allowed_procedures": list(_ALLOWED_FUNCTIONS),
            "service": _AUTHORITY_SERVICE,
        },
    ).scalar_one()
    # The function universe itself is closed. The only photo functions that
    # may exist are the exact v2 allowlist and three legacy owner-only v1
    # procedures retained for downgrade compatibility. Any additional overload
    # is rejected even when it carries only its owner's implicit EXECUTE.
    unexpected_function = connection.execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='dev_eval' AND p.proname ~ '(^|_)photo_' "
            "AND p.oid <> ALL(CAST(:known_procedures AS pg_catalog.regprocedure[]))"
        ),
        {"known_procedures": list((*_ALLOWED_FUNCTIONS, *_OWNER_ONLY_FUNCTIONS))},
    ).scalar_one()
    if int(allowed_acl_entries) != len(_ALLOWED_FUNCTIONS) or any(
        int(value) != 0
        for value in (
            leaked_table,
            leaked_sequence,
            leaked_legacy_function,
            leaked_v2_function,
            unexpected_function,
        )
    ):
        raise RuntimeError("exclusive photo authority privileges rejected")


_LEGACY_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("transition_photo_job_status_v1", "(text,text,text,text,timestamptz)"),
    ("claim_photo_job_v1", "(text,timestamptz)"),
    ("record_photo_dispatch_marker_v1", "(text,integer,text)"),
)

_LIFECYCLE_TABLES: tuple[str, ...] = (
    "dev_eval.photo_jobs",
    "dev_eval.photo_job_dispatch_markers",
    "dev_eval.photo_trait_candidates",
    "dev_eval.photo_confirmed_traits",
    "dev_eval.photo_deletion_ledger",
)


def _create_review_tables() -> None:
    op.execute(
        """
        CREATE TABLE dev_eval.photo_review_drafts (
            job_id text NOT NULL REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE CASCADE CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            profile_id text NOT NULL CHECK (
                char_length(profile_id) BETWEEN 1 AND 160
                AND profile_id ~ '^\\S(.*\\S)?$'
            ),
            draft_digest text NOT NULL CHECK (draft_digest ~ '^[0-9a-f]{64}$'),
            candidate_ids text[] NOT NULL CHECK (cardinality(candidate_ids) BETWEEN 1 AND 6)
                CHECK (array_position(candidate_ids, NULL) IS NULL),
            trait_ids text[] NOT NULL CHECK (cardinality(trait_ids) BETWEEN 1 AND 6)
                CHECK (array_position(trait_ids, NULL) IS NULL),
            edited_texts_ko text[] NOT NULL CHECK (
                cardinality(edited_texts_ko) BETWEEN 1 AND 6),
            excluded_flags boolean[] NOT NULL CHECK (
                cardinality(excluded_flags) BETWEEN 1 AND 6),
            updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (job_id),
            CHECK (cardinality(candidate_ids) = cardinality(trait_ids)
                AND cardinality(trait_ids) = cardinality(edited_texts_ko)
                AND cardinality(edited_texts_ko) = cardinality(excluded_flags))
        )
        """
    )
    op.execute("ALTER TABLE dev_eval.photo_review_drafts OWNER TO itda_photo_write_authority")
    op.execute("REVOKE ALL ON dev_eval.photo_review_drafts FROM PUBLIC")
    op.execute(
        """
        CREATE TABLE dev_eval.photo_confirmation_receipts (
            receipt_id text PRIMARY KEY CHECK (receipt_id ~ '^[0-9a-f]{32,64}$'),
            job_id text NOT NULL REFERENCES dev_eval.photo_jobs(job_id)
                ON DELETE CASCADE CHECK (job_id ~ '^[0-9a-f]{32,64}$'),
            profile_id text NOT NULL CHECK (
                char_length(profile_id) BETWEEN 1 AND 160
                AND profile_id ~ '^\\S(.*\\S)?$'
            ),
            draft_digest text NOT NULL CHECK (draft_digest ~ '^[0-9a-f]{64}$'),
            included_count integer NOT NULL CHECK (
                included_count >= 0 AND included_count <= 6),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (job_id, profile_id, draft_digest)
        )
        """
    )
    op.execute(
        "ALTER TABLE dev_eval.photo_confirmation_receipts OWNER TO itda_photo_write_authority"
    )
    op.execute("REVOKE ALL ON dev_eval.photo_confirmation_receipts FROM PUBLIC")


_SERVICE_GUARD = (
    "IF session_user <> 'itda_photo_service' THEN "
    "RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '42501'; END IF;"
)


def _lock_owned_job(p_job_id: str, p_profile_id: str, states: str) -> str:
    return (
        f"SELECT stored.status INTO v_status FROM dev_eval.photo_jobs stored "
        f"WHERE stored.job_id = {p_job_id} AND stored.profile_id = {p_profile_id} "
        f"FOR UPDATE; "
        f"IF NOT FOUND THEN RAISE EXCEPTION 'photo operation rejected' "
        f"USING ERRCODE = '23514'; END IF; "
        f"IF v_status NOT IN ({states}) THEN RAISE EXCEPTION 'photo operation rejected' "
        f"USING ERRCODE = '23514'; END IF;"
    )


def _create_functions() -> None:
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.create_photo_job_v2(
            p_job_id text, p_profile_id text, p_idempotency_key text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE inserted integer;
        BEGIN
            {_SERVICE_GUARD}
            IF p_job_id !~ '^[0-9a-f]{{32,64}}$' THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF char_length(p_profile_id) NOT BETWEEN 1 AND 160 OR p_profile_id !~ '^\\S(.*\\S)?$' THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_idempotency_key IS NOT NULL AND char_length(p_idempotency_key) NOT BETWEEN 16 AND 160 THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            INSERT INTO dev_eval.photo_jobs (job_id, profile_id, status, idempotency_key)
            VALUES (p_job_id, p_profile_id, 'queued', p_idempotency_key)
            ON CONFLICT (job_id) DO NOTHING;
            GET DIAGNOSTICS inserted = ROW_COUNT;
            RETURN inserted = 1;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.transition_photo_job_status_v2(
            p_job_id text, p_profile_id text, p_from_status text,
            p_to_status text, p_terminal_cause text, p_lease_expires_at timestamptz
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_legal boolean;
        BEGIN
            {_SERVICE_GUARD}
            {_lock_owned_job("p_job_id", "p_profile_id", "'queued','running','succeeded','failed','expired','deleted'")}
            IF v_status IS DISTINCT FROM p_from_status THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            v_legal := CASE
                WHEN p_from_status = p_to_status THEN TRUE
                WHEN p_from_status = 'queued' THEN p_to_status IN ('running','failed','expired','deleted')
                WHEN p_from_status = 'running' THEN p_to_status IN ('succeeded','failed','expired','deleted')
                WHEN p_from_status = 'succeeded' THEN p_to_status = 'deleted'
                WHEN p_from_status = 'failed' THEN p_to_status = 'deleted'
                WHEN p_from_status = 'expired' THEN p_to_status = 'deleted'
                ELSE FALSE
            END;
            IF NOT v_legal THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_to_status IN ('succeeded','failed','expired','deleted') AND p_terminal_cause IS NULL THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            UPDATE dev_eval.photo_jobs stored
            SET status = p_to_status, lease_expires_at = p_lease_expires_at,
                terminal_cause = COALESCE(p_terminal_cause, stored.terminal_cause),
                updated_at = CURRENT_TIMESTAMP
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            RETURN v_status;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.claim_photo_job_v2(
            p_job_id text, p_profile_id text, p_lease_expires_at timestamptz
        ) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_claimed integer;
        BEGIN
            {_SERVICE_GUARD}
            UPDATE dev_eval.photo_jobs stored
            SET status = 'running', lease_expires_at = p_lease_expires_at,
                updated_at = CURRENT_TIMESTAMP
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id
              AND stored.status = 'queued'
              AND (stored.lease_expires_at IS NULL OR stored.lease_expires_at < CURRENT_TIMESTAMP);
            GET DIAGNOSTICS v_claimed = ROW_COUNT;
            RETURN v_claimed;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.record_photo_dispatch_marker_v2(
            p_job_id text, p_profile_id text, p_attempt integer, p_marker text
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text;
        BEGIN
            {_SERVICE_GUARD}
            {_lock_owned_job("p_job_id", "p_profile_id", "'queued','running','failed','expired'")}
            IF p_attempt < 1 OR p_marker NOT IN ('reserved','prepared','client_constructed','send_boundary') THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            BEGIN
                INSERT INTO dev_eval.photo_job_dispatch_markers (job_id, attempt, marker)
                VALUES (p_job_id, p_attempt, p_marker);
            EXCEPTION
                WHEN unique_violation THEN RETURN;
            END;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.record_photo_candidate_batch_v2(
            p_job_id text, p_profile_id text, p_candidate_ids text[],
            p_trait_ids text[], p_texts_ko text[], p_candidate_set_sha256s text[]
        ) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_count integer;
        BEGIN
            {_SERVICE_GUARD}
            {_lock_owned_job("p_job_id", "p_profile_id", "'running','succeeded'")}
            SELECT cardinality(p_candidate_ids), cardinality(p_trait_ids),
                   cardinality(p_texts_ko), cardinality(p_candidate_set_sha256s)
            INTO v_count, v_count, v_count, v_count;
            IF v_count < 1 OR v_count > 6 THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023'; END IF;
            IF p_candidate_ids IS NULL OR p_trait_ids IS NULL OR p_texts_ko IS NULL OR p_candidate_set_sha256s IS NULL
               OR cardinality(p_candidate_ids) <> cardinality(p_trait_ids)
               OR cardinality(p_trait_ids) <> cardinality(p_texts_ko)
               OR cardinality(p_texts_ko) <> cardinality(p_candidate_set_sha256s) THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF array_position(p_candidate_ids, NULL) IS NOT NULL
               OR array_position(p_trait_ids, NULL) IS NOT NULL
               OR array_position(p_texts_ko, NULL) IS NOT NULL
               OR array_position(p_candidate_set_sha256s, NULL) IS NOT NULL THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF (SELECT count(DISTINCT u) FROM unnest(p_candidate_ids) u)
               <> cardinality(p_candidate_ids) THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF EXISTS (SELECT 1 FROM unnest(p_candidate_ids) u WHERE u !~ '^[0-9a-f]{{64}}$')
               OR EXISTS (SELECT 1 FROM unnest(p_trait_ids) u WHERE u !~ '^M[1-6]$')
               OR EXISTS (SELECT 1 FROM unnest(p_texts_ko) u WHERE char_length(u) NOT BETWEEN 1 AND 24)
               OR EXISTS (SELECT 1 FROM unnest(p_candidate_set_sha256s) u WHERE u !~ '^[0-9a-f]{{64}}$') THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            INSERT INTO dev_eval.photo_trait_candidates
                (job_id, candidate_id, trait_id, text_ko, candidate_set_sha256)
            SELECT p_job_id, u.candidate_id, u.trait_id, u.text_ko, u.digest
            FROM unnest(p_candidate_ids, p_trait_ids, p_texts_ko, p_candidate_set_sha256s)
                WITH ORDINALITY AS u(candidate_id, trait_id, text_ko, digest, ord);
            RETURN cardinality(p_candidate_ids);
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.annotate_photo_candidate_v2(
            p_job_id text, p_profile_id text, p_candidate_id text,
            p_edited_text_ko text, p_excluded boolean
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_updated integer;
        BEGIN
            {_SERVICE_GUARD}
            {_lock_owned_job("p_job_id", "p_profile_id", "'succeeded'")}
            IF p_candidate_id !~ '^[0-9a-f]{{64}}$' THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_edited_text_ko IS NOT NULL AND char_length(p_edited_text_ko) NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_edited_text_ko IS NULL AND p_excluded IS NULL THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            UPDATE dev_eval.photo_trait_candidates stored
            SET edited_text_ko = COALESCE(p_edited_text_ko, stored.edited_text_ko),
                excluded = COALESCE(p_excluded, stored.excluded)
            WHERE stored.job_id = p_job_id AND stored.candidate_id = p_candidate_id;
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            IF v_updated <> 1 THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.append_photo_deletion_ledger_v2(
            p_job_id text, p_profile_id text, p_cause text,
            p_reason_code text, p_residue_proof_digest text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_inserted integer;
        BEGIN
            {_SERVICE_GUARD}
            IF p_cause NOT IN ('success','rejection','validation_failure','provider_error','timeout','worker_crash','explicit_deletion','expiry','orphan_cleanup') THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_reason_code !~ '^[A-Z][A-Z0-9_]{{2,63}}$' OR p_residue_proof_digest !~ '^[0-9a-f]{{64}}$' THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            -- The ledger row may only exist for a real job owned by the exact
            -- profile in a legal lifecycle state, locked for update: an
            -- arbitrary hex id, foreign profile, or absent job appends nothing.
            {_lock_owned_job("p_job_id", "p_profile_id", "'queued','running','succeeded','failed','expired'")}
            BEGIN
                INSERT INTO dev_eval.photo_deletion_ledger
                    (job_id, cause, reason_code, residue_proof_digest)
                VALUES (p_job_id, p_cause, p_reason_code, p_residue_proof_digest);
                GET DIAGNOSTICS v_inserted = ROW_COUNT;
                RETURN v_inserted = 1;
            EXCEPTION
                WHEN unique_violation THEN RETURN false;
            END;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.save_photo_review_draft_v2(
            p_job_id text, p_profile_id text, p_draft_digest text,
            p_candidate_ids text[], p_trait_ids text[],
            p_edited_texts_ko text[], p_excluded_flags boolean[]
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_unbound integer;
        BEGIN
            {_SERVICE_GUARD}
            {_lock_owned_job("p_job_id", "p_profile_id", "'succeeded'")}
            IF p_draft_digest !~ '^[0-9a-f]{{64}}$' THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_candidate_ids IS NULL OR cardinality(p_candidate_ids) NOT BETWEEN 1 AND 6
               OR cardinality(p_candidate_ids) <> cardinality(p_trait_ids)
               OR cardinality(p_trait_ids) <> cardinality(p_edited_texts_ko)
               OR cardinality(p_edited_texts_ko) <> cardinality(p_excluded_flags) THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF array_position(p_candidate_ids, NULL) IS NOT NULL
               OR array_position(p_trait_ids, NULL) IS NOT NULL
               OR array_position(p_excluded_flags, NULL) IS NOT NULL THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF (SELECT count(DISTINCT u) FROM unnest(p_candidate_ids) u)
               <> cardinality(p_candidate_ids)
               OR EXISTS (SELECT 1 FROM unnest(p_candidate_ids) u WHERE u !~ '^[0-9a-f]{{64}}$')
               OR EXISTS (SELECT 1 FROM unnest(p_trait_ids) u WHERE u !~ '^M[1-6]$')
               OR EXISTS (SELECT 1 FROM unnest(p_edited_texts_ko) u
                          WHERE u IS NOT NULL AND char_length(u) > 64) THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            -- Every ordinal entry must bind to a real candidate row of the
            -- exact owned job with the same trait id and exclusion
            -- provenance: fake candidates, foreign-job ids, and trait or
            -- exclusion drift from the stored candidate all fail closed.
            SELECT count(*) INTO v_unbound
            FROM unnest(p_candidate_ids, p_trait_ids, p_edited_texts_ko,
                        p_excluded_flags)
                WITH ORDINALITY AS b(candidate_id, trait_id, edited_text_ko,
                                     excluded, ord)
            LEFT JOIN dev_eval.photo_trait_candidates c
                ON c.job_id = p_job_id AND c.candidate_id = b.candidate_id
            WHERE c.candidate_id IS NULL
               OR c.trait_id IS DISTINCT FROM b.trait_id
               OR b.edited_text_ko IS DISTINCT FROM c.edited_text_ko
               OR b.excluded IS DISTINCT FROM c.excluded;
            IF v_unbound <> 0 THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            INSERT INTO dev_eval.photo_review_drafts
                (job_id, profile_id, draft_digest, candidate_ids, trait_ids,
                 edited_texts_ko, excluded_flags)
            VALUES (p_job_id, p_profile_id, p_draft_digest, p_candidate_ids,
                    p_trait_ids, p_edited_texts_ko, p_excluded_flags)
            ON CONFLICT (job_id) DO UPDATE
            SET draft_digest = EXCLUDED.draft_digest,
                candidate_ids = EXCLUDED.candidate_ids,
                trait_ids = EXCLUDED.trait_ids,
                edited_texts_ko = EXCLUDED.edited_texts_ko,
                excluded_flags = EXCLUDED.excluded_flags,
                updated_at = CURRENT_TIMESTAMP;
            RETURN true;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.discard_photo_review_draft_v2(
            p_job_id text, p_profile_id text
        ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_removed integer;
        BEGIN
            {_SERVICE_GUARD}
            DELETE FROM dev_eval.photo_review_drafts stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            GET DIAGNOSTICS v_removed = ROW_COUNT;
            RETURN v_removed = 1;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.confirm_photo_traits_v2(
            p_job_id text, p_profile_id text, p_draft_digest text,
            p_trait_ids text[], p_texts_ko text[], p_source_candidate_ids text[],
            p_included_flags boolean[], p_text_ko_is_blank_flags boolean[],
            p_receipt_id text
        ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_status text; v_included integer; v_existing text;
                v_digest text; v_mismatch integer; v_draft_cardinality integer;
        BEGIN
            {_SERVICE_GUARD}
            {_lock_owned_job("p_job_id", "p_profile_id", "'succeeded'")}
            IF p_receipt_id !~ '^[0-9a-f]{{32,64}}$' OR p_draft_digest !~ '^[0-9a-f]{{64}}$' THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514'; END IF;
            IF p_trait_ids IS NULL OR cardinality(p_trait_ids) NOT BETWEEN 1 AND 6
               OR cardinality(p_trait_ids) <> cardinality(p_texts_ko)
               OR cardinality(p_texts_ko) <> cardinality(p_source_candidate_ids)
               OR cardinality(p_source_candidate_ids) <> cardinality(p_included_flags)
               OR cardinality(p_included_flags) <> cardinality(p_text_ko_is_blank_flags) THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF array_position(p_trait_ids, NULL) IS NOT NULL
               OR array_position(p_texts_ko, NULL) IS NOT NULL
               OR array_position(p_included_flags, NULL) IS NOT NULL
               OR array_position(p_text_ko_is_blank_flags, NULL) IS NOT NULL THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            IF EXISTS (SELECT 1 FROM unnest(p_trait_ids) u WHERE u !~ '^M[1-6]$')
               OR EXISTS (SELECT 1 FROM unnest(p_texts_ko) u WHERE char_length(u) NOT BETWEEN 1 AND 64)
               OR EXISTS (SELECT 1 FROM unnest(p_source_candidate_ids) u
                          WHERE u IS NULL OR u !~ '^[0-9a-f]{{64}}$') THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '22023';
            END IF;
            -- Require the exact persisted review draft, locked for update.
            -- An absent, stale, or foreign draft fails closed before any write.
            SELECT d.draft_digest INTO v_digest FROM dev_eval.photo_review_drafts d
            WHERE d.job_id = p_job_id AND d.profile_id = p_profile_id
            FOR UPDATE;
            IF NOT FOUND OR v_digest IS DISTINCT FROM p_draft_digest THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            -- The submission must cover the ENTIRE persisted draft with the
            -- same cardinality: partial batches (shorter or longer) and
            -- reordered drafts fail closed before any write. Every parallel
            -- draft array carries the same cardinality by construction.
            SELECT cardinality(d.candidate_ids) INTO v_draft_cardinality
            FROM dev_eval.photo_review_drafts d
            WHERE d.job_id = p_job_id AND d.profile_id = p_profile_id;
            IF v_draft_cardinality IS DISTINCT FROM cardinality(p_trait_ids) THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            -- Every submitted row must match the draft's ordinality AND the
            -- real candidate row: the draft position binds the candidate id,
            -- and the submitted row must carry that exact candidate id, its
            -- trait id, and the effective text (draft edit when present,
            -- model text otherwise). Product inputs are candidate-derived,
            -- so a NULL source id can never satisfy the binding. Fake or
            -- NULL sources, foreign trait/text, reordered drafts, and
            -- partial batches all fail closed with zero rows written.
            SELECT count(*) INTO v_mismatch
            FROM unnest(p_source_candidate_ids, p_trait_ids, p_texts_ko,
                        p_included_flags)
                WITH ORDINALITY AS b(candidate_id, trait_id, text_ko, included, ord)
            JOIN dev_eval.photo_review_drafts d
                ON d.job_id = p_job_id AND d.profile_id = p_profile_id
            JOIN LATERAL unnest(d.candidate_ids, d.trait_ids, d.edited_texts_ko,
                                d.excluded_flags)
                WITH ORDINALITY AS dr(candidate_id, trait_id, edited_text_ko,
                                      excluded, ord)
                ON dr.ord = b.ord
            JOIN dev_eval.photo_trait_candidates c
                ON c.job_id = p_job_id AND c.candidate_id = dr.candidate_id
            WHERE b.candidate_id IS DISTINCT FROM dr.candidate_id
               OR dr.trait_id IS DISTINCT FROM c.trait_id
               OR b.trait_id IS DISTINCT FROM c.trait_id
               OR b.text_ko IS DISTINCT FROM COALESCE(dr.edited_text_ko, c.text_ko)
               OR b.included IS DISTINCT FROM NOT dr.excluded;
            IF v_mismatch <> 0 THEN
               RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            -- Idempotency is evaluated only after the repeated request passes
            -- the same complete semantic validation as the first request.
            SELECT stored.receipt_id INTO v_existing FROM dev_eval.photo_confirmation_receipts stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id
              AND stored.draft_digest = p_draft_digest;
            IF v_existing IS NOT NULL THEN RETURN v_existing; END IF;
            SELECT count(*) INTO v_included FROM unnest(p_included_flags) u WHERE u;
            INSERT INTO dev_eval.photo_confirmed_traits
                (job_id, confirmation_seq, trait_id, text_ko,
                 source_candidate_id, included, text_ko_is_blank)
            SELECT p_job_id, u.ord, u.trait_id, u.text_ko,
                   u.source_candidate_id, u.included, u.is_blank
            FROM unnest(p_trait_ids, p_texts_ko, p_source_candidate_ids,
                        p_included_flags, p_text_ko_is_blank_flags)
                WITH ORDINALITY AS u(trait_id, text_ko, source_candidate_id,
                                     included, is_blank, ord);
            INSERT INTO dev_eval.photo_confirmation_receipts
                (receipt_id, job_id, profile_id, draft_digest, included_count)
            VALUES (p_receipt_id, p_job_id, p_profile_id, p_draft_digest, v_included);
            RETURN p_receipt_id;
        END $function$;
        """
    )


def _create_read_functions() -> None:
    """Owner-scoped read projections replacing every table SELECT grant."""

    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_job_v2(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            job_id text, profile_id text, status text, terminal_cause text,
            lease_expires_at timestamptz, created_at timestamptz,
            updated_at timestamptz
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            RETURN QUERY SELECT stored.job_id, stored.profile_id, stored.status,
                stored.terminal_cause, stored.lease_expires_at,
                stored.created_at, stored.updated_at
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_photo_candidates_v2(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            job_id text, candidate_id text, trait_id text, text_ko text,
            candidate_set_sha256 text, edited_text_ko text, excluded boolean,
            provenance text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_count integer;
        BEGIN
            {_SERVICE_GUARD}
            SELECT count(*) INTO v_count FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            IF v_count <> 1 THEN RETURN; END IF;
            RETURN QUERY SELECT stored.job_id, stored.candidate_id,
                stored.trait_id, stored.text_ko, stored.candidate_set_sha256,
                stored.edited_text_ko, stored.excluded, stored.provenance
            FROM dev_eval.photo_trait_candidates stored
            WHERE stored.job_id = p_job_id
            ORDER BY stored.recorded_at, stored.candidate_id;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_photo_confirmed_traits_v2(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            job_id text, confirmation_seq integer, trait_id text, text_ko text,
            source_candidate_id text, included boolean, provenance text,
            text_ko_is_blank boolean
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_count integer;
        BEGIN
            {_SERVICE_GUARD}
            SELECT count(*) INTO v_count FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            IF v_count <> 1 THEN RETURN; END IF;
            RETURN QUERY SELECT stored.job_id, stored.confirmation_seq,
                stored.trait_id, stored.text_ko, stored.source_candidate_id,
                stored.included, stored.provenance, stored.text_ko_is_blank
            FROM dev_eval.photo_confirmed_traits stored
            WHERE stored.job_id = p_job_id ORDER BY stored.confirmation_seq;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_photo_dispatch_markers_v2(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (marker text, attempt_count bigint)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_count integer;
        BEGIN
            {_SERVICE_GUARD}
            SELECT count(*) INTO v_count FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            IF v_count <> 1 THEN RETURN; END IF;
            RETURN QUERY SELECT stored.marker,
                (SELECT count(*) FROM dev_eval.photo_job_dispatch_markers later
                 WHERE later.job_id = stored.job_id
                   AND later.marker = stored.marker)
            FROM dev_eval.photo_job_dispatch_markers stored
            WHERE stored.job_id = p_job_id AND stored.attempt = 1;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_reconcile_photo_jobs_v2()
        RETURNS TABLE (job_id text, profile_id text, stale_running boolean)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            RETURN QUERY SELECT stored.job_id, stored.profile_id,
                stored.status = 'running' AND (
                    stored.lease_expires_at IS NULL
                    OR stored.lease_expires_at < CURRENT_TIMESTAMP)
            FROM dev_eval.photo_jobs stored
            WHERE (stored.status = 'running'
                   AND (stored.lease_expires_at IS NULL
                        OR stored.lease_expires_at < CURRENT_TIMESTAMP))
               OR (stored.status = 'queued'
                   AND stored.lease_expires_at IS NOT NULL
                   AND stored.lease_expires_at < CURRENT_TIMESTAMP);
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_review_draft_v2(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            candidate_ids text[], trait_ids text[], edited_texts_ko text[],
            excluded_flags boolean[], draft_digest text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            RETURN QUERY SELECT stored.candidate_ids, stored.trait_ids,
                stored.edited_texts_ko, stored.excluded_flags,
                stored.draft_digest
            FROM dev_eval.photo_review_drafts stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_photo_confirmation_receipt_v2(
            p_job_id text, p_profile_id text, p_receipt_id text
        ) RETURNS TABLE (
            receipt_id text, job_id text, profile_id text, draft_digest text,
            included_count integer, created_at timestamptz
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            {_SERVICE_GUARD}
            RETURN QUERY SELECT stored.receipt_id, stored.job_id,
                stored.profile_id, stored.draft_digest, stored.included_count,
                stored.created_at
            FROM dev_eval.photo_confirmation_receipts stored
            WHERE stored.receipt_id = p_receipt_id
              AND stored.job_id = p_job_id
              AND stored.profile_id = p_profile_id;
        END $function$;
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.list_photo_deletion_ledger_v2(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            ledger_seq bigint, job_id text, cause text, reason_code text,
            recorded_at timestamptz, residue_proof_digest text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_count integer;
        BEGIN
            {_SERVICE_GUARD}
            SELECT count(*) INTO v_count FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            IF v_count <> 1 THEN RETURN; END IF;
            RETURN QUERY SELECT stored.ledger_seq, stored.job_id, stored.cause,
                stored.reason_code, stored.recorded_at,
                stored.residue_proof_digest
            FROM dev_eval.photo_deletion_ledger stored
            WHERE stored.job_id = p_job_id ORDER BY stored.ledger_seq;
        END $function$;
        """
    )


def upgrade() -> None:
    runtime = _configured_identifier("runtime_role")
    builder = _configured_identifier("label_builder_role")
    if runtime is None or builder is None:
        raise RuntimeError("exclusive photo authority migration roles are required")
    quoted_runtime = _quote(runtime)
    quoted_builder = _quote(builder)

    _require_role_topology(builder, runtime)
    _assert_default_acl_closed(runtime, builder)

    _create_review_tables()
    _create_functions()
    _create_read_functions()

    # Fail-closed function ACLs: revoke everything from everyone first,
    # then grant EXECUTE only to the exact service principal. Mutation and
    # read-projection functions share one exact allowlist.
    for name, signature in (*_FUNCTIONS, *_READ_FUNCTIONS):
        op.execute(f"ALTER FUNCTION dev_eval.{name}{signature} OWNER TO {_WRITE_AUTHORITY}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM {quoted_runtime}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM {quoted_builder}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM {_WRITE_AUTHORITY}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM CURRENT_USER")
        op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{name}{signature} TO {_AUTHORITY_SERVICE}")
    for name, signature in _LEGACY_FUNCTIONS:
        op.execute(
            f"REVOKE EXECUTE ON FUNCTION dev_eval.{name}{signature} FROM {_AUTHORITY_SERVICE}"
        )
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{name}{signature} FROM PUBLIC")

    # Remove every direct mutation path migration 0018 granted, and every
    # direct read: lifecycle rows are reachable only through the read
    # projections above.
    for table in _LIFECYCLE_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM {_AUTHORITY_SERVICE}")
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON {table} FROM {quoted_runtime}")
        op.execute(f"REVOKE ALL ON {table} FROM {quoted_builder}")
        op.execute(f"REVOKE ALL ON {table} FROM CURRENT_USER")
    op.execute("REVOKE ALL ON dev_eval.photo_review_drafts FROM PUBLIC")
    op.execute("REVOKE ALL ON dev_eval.photo_confirmation_receipts FROM PUBLIC")
    op.execute(f"REVOKE ALL ON dev_eval.photo_review_drafts FROM {quoted_runtime}")
    op.execute(f"REVOKE ALL ON dev_eval.photo_confirmation_receipts FROM {quoted_runtime}")
    op.execute(f"REVOKE ALL ON dev_eval.photo_review_drafts FROM {quoted_builder}")
    op.execute(f"REVOKE ALL ON dev_eval.photo_confirmation_receipts FROM {quoted_builder}")
    op.execute(f"REVOKE ALL ON dev_eval.photo_review_drafts FROM {_AUTHORITY_SERVICE}")
    op.execute(f"REVOKE ALL ON dev_eval.photo_confirmation_receipts FROM {_AUTHORITY_SERVICE}")
    # The sequence grant from 0019 was needed for direct ledger INSERTs;
    # functions now own that write, so the sequence access goes away.
    op.execute(
        "REVOKE USAGE, SELECT ON SEQUENCE "
        "dev_eval.photo_deletion_ledger_ledger_seq_seq FROM itda_photo_service"
    )

    # Schema authority: only the owner may create objects in dev_eval.
    op.execute("REVOKE CREATE ON SCHEMA dev_eval FROM PUBLIC")
    op.execute(f"REVOKE CREATE ON SCHEMA dev_eval FROM {quoted_runtime}")
    op.execute(f"REVOKE CREATE ON SCHEMA dev_eval FROM {quoted_builder}")
    op.execute("REVOKE CREATE ON SCHEMA dev_eval FROM CURRENT_USER")
    op.execute("REVOKE CREATE ON SCHEMA dev_eval FROM itda_photo_service")

    # Hostile-default-privilege closure for every authority role.
    for role in (_WRITE_AUTHORITY, _AUTHORITY_SERVICE):
        quoted_role = _quote(role)
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_role} REVOKE ALL ON TABLES FROM PUBLIC"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_role} "
            f"REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_role} REVOKE ALL ON SEQUENCES FROM PUBLIC"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_role} IN SCHEMA dev_eval "
            f"REVOKE ALL ON TABLES FROM PUBLIC"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_role} IN SCHEMA dev_eval "
            f"REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_role} IN SCHEMA dev_eval "
            f"REVOKE ALL ON SEQUENCES FROM PUBLIC"
        )

    _assert_acl_closed()


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
            "0020 downgrade is intentionally irreversible after lifecycle "
            "state exists: removing the exclusive photo mutation authority "
            "would reopen direct-table bypass over durable user data"
        )

    runtime = _configured_identifier("runtime_role")
    builder = _configured_identifier("label_builder_role")
    if runtime is None or builder is None:
        raise RuntimeError("exclusive photo authority migration roles are required")
    quoted_runtime = _quote(runtime)

    # Drop the exclusive-authority functions first.
    for name, signature in (*_FUNCTIONS, *_READ_FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS dev_eval.{name}{signature}")

    # Restore the 0018-era default-privilege posture is unnecessary (0018
    # created no default ACLs); simply drop our hostile-default closure by
    # leaving the REVOKEs in place is also acceptable — but the authoritative
    # downgrade restores the exact 0019 schema state below.
    op.execute("DROP TABLE dev_eval.photo_confirmation_receipts")
    op.execute("DROP TABLE dev_eval.photo_review_drafts")

    # Restore the 0019-era grants so the schema matches revision 0019.
    for name, signature in _LEGACY_FUNCTIONS:
        op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{name}{signature} TO {_AUTHORITY_SERVICE}")
    for table in _LIFECYCLE_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM {_AUTHORITY_SERVICE}")
        op.execute(f"GRANT SELECT ON {table} TO {_AUTHORITY_SERVICE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_jobs TO {_AUTHORITY_SERVICE}")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_job_dispatch_markers "
        f"TO {_AUTHORITY_SERVICE}"
    )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_trait_candidates TO {_AUTHORITY_SERVICE}"
    )
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_confirmed_traits TO {_AUTHORITY_SERVICE}"
    )
    op.execute(f"GRANT SELECT, INSERT ON dev_eval.photo_deletion_ledger TO {_AUTHORITY_SERVICE}")
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE "
        f"dev_eval.photo_deletion_ledger_ledger_seq_seq TO {_AUTHORITY_SERVICE}"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.photo_trait_candidates, "
        f"dev_eval.photo_confirmed_traits, dev_eval.photo_jobs "
        f"TO {quoted_runtime}"
    )
    op.execute(f"GRANT SELECT, INSERT ON dev_eval.photo_job_dispatch_markers TO {quoted_runtime}")
    op.execute("GRANT SELECT ON dev_eval.photo_job_dispatch_markers TO PUBLIC")
    op.execute("REVOKE ALL ON SCHEMA dev_eval FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO PUBLIC")
