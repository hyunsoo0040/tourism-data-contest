# ruff: noqa: E501
"""Add function-only digest-backed current-profile sessions.

The application role can execute five exact-purpose SECURITY DEFINER functions but
cannot inspect or mutate session rows.  The owner is a dedicated NOLOGIN role.
Raw opaque references never cross this migration boundary: callers provide only
a SHA-256 digest.
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0019_phase6_current_profile_sessions"
down_revision = "0018_phase6_photo_jobs_and_deletion_ledger"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OWNER = "itda_current_profile_session_owner"
_SERVICE = "itda_current_profile_session_service"


def _configured_identifier(name: str) -> str:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError("current profile session migration configuration rejected")
    return value


def _quote(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _assert_default_acl_closed() -> None:
    leaked = op.get_bind().execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_default_acl d "
            "JOIN pg_catalog.pg_roles r ON r.oid=d.defaclrole "
            "LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a "
            "WHERE r.rolname IN (CURRENT_USER, :owner) "
            "AND d.defaclobjtype IN ('r','S','f') "
            "AND (d.defaclnamespace=0 OR n.nspname='app') "
            "AND NOT (a.grantee=d.defaclrole OR (d.defaclnamespace=0 "
            "AND d.defaclobjtype='f' AND a.grantee=0 "
            "AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))"
        ),
        {"owner": _OWNER},
    ).scalar_one()
    if int(leaked) != 0:
        raise RuntimeError("current profile session default privileges rejected")


def _assert_session_acl_closed() -> None:
    leaked_table = op.get_bind().execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(c.relacl, pg_catalog.acldefault('r',c.relowner))) a "
            "JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=c.relowner "
            "WHERE n.nspname='app' AND c.relname='current_profile_sessions' "
            "AND a.grantee <> c.relowner"
        )
    ).scalar_one()
    leaked_function = op.get_bind().execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='app' AND (p.proname LIKE '%current_profile_session%' "
            "OR p.proname='create_preference_profile_and_issue_session_v1') "
            "AND (SELECT count(*) FROM pg_catalog.aclexplode(p.proacl) a) <> 1 "
            "OR n.nspname='app' AND (p.proname LIKE '%current_profile_session%' "
            "OR p.proname='create_preference_profile_and_issue_session_v1') "
            "AND (SELECT count(*) FROM pg_catalog.aclexplode(p.proacl) a "
            "JOIN pg_catalog.pg_roles grantee ON grantee.oid=a.grantee "
            "WHERE grantee.rolname=:service AND a.grantor=p.proowner "
            "AND a.privilege_type='EXECUTE' AND NOT a.is_grantable) <> 1"
        ),
        {"service": _SERVICE},
    ).scalar_one()
    leaked_sequence = op.get_bind().execute(
        sa.text(
            "SELECT count(*) FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_roles owner_role ON owner_role.oid=c.relowner "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "COALESCE(c.relacl, pg_catalog.acldefault('S',c.relowner))) a "
            "WHERE n.nspname='app' AND c.relkind='S' AND owner_role.rolname=:owner "
            "AND a.grantee <> c.relowner"
        ),
        {"owner": _OWNER},
    ).scalar_one()
    if any(int(value) != 0 for value in (leaked_table, leaked_function, leaked_sequence)):
        raise RuntimeError("current profile session privileges rejected")


def upgrade() -> None:
    runtime = _configured_identifier("runtime_role")
    quoted_runtime = _quote(runtime)
    role_rows = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
                "WHERE rolname IN (:owner, :service)"
            ),
            {"owner": _OWNER, "service": _SERVICE},
        )
        .all()
    )
    role_flags = {str(row[0]): tuple(bool(value) for value in row[1:]) for row in role_rows}
    if role_flags != {
        _OWNER: (False, False, False, False, False, False, False),
        _SERVICE: (True, False, False, False, False, False, False),
    }:
        raise RuntimeError("current profile session role topology rejected")
    memberships = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT pg_catalog.pg_has_role(:runtime, :owner, 'MEMBER'), "
                "pg_catalog.pg_has_role(:runtime, :service, 'MEMBER'), "
                "pg_catalog.pg_has_role(:owner, :runtime, 'MEMBER'), "
                "pg_catalog.pg_has_role(:owner, :service, 'MEMBER'), "
                "pg_catalog.pg_has_role(:service, :runtime, 'MEMBER'), "
                "pg_catalog.pg_has_role(:service, :owner, 'MEMBER')"
            ),
            {"runtime": runtime, "owner": _OWNER, "service": _SERVICE},
        )
        .one()
    )
    if any(bool(value) for value in memberships):
        raise RuntimeError("current profile session role topology rejected")
    _assert_default_acl_closed()

    op.execute("REVOKE CREATE ON SCHEMA app FROM PUBLIC")
    op.execute(f"REVOKE CREATE ON SCHEMA app FROM {quoted_runtime}")
    op.execute(f"GRANT USAGE ON SCHEMA app TO {_OWNER}")
    op.execute(f"GRANT USAGE ON SCHEMA app TO {_SERVICE}")
    op.execute(
        "CREATE TABLE app.current_profile_sessions ("
        "session_digest text PRIMARY KEY CHECK (session_digest ~ '^[0-9a-f]{64}$'),"
        "profile_id text NOT NULL REFERENCES app.preference_profiles(profile_id) ON DELETE CASCADE,"
        "issued_at timestamptz NOT NULL,"
        "expires_at timestamptz NOT NULL CHECK (expires_at = issued_at + interval '30 minutes'),"
        "revoked_at timestamptz NULL CHECK (revoked_at IS NULL OR revoked_at >= issued_at),"
        "revocation_version integer NOT NULL DEFAULT 1 CHECK (revocation_version >= 1),"
        "peer_digest text NOT NULL CHECK (peer_digest ~ '^[0-9a-f]{64}$'),"
        "origin_digest text NOT NULL CHECK (origin_digest ~ '^[0-9a-f]{64}$')"
        ")"
    )
    op.execute(
        "CREATE UNIQUE INDEX current_profile_sessions_one_active_profile_uidx "
        "ON app.current_profile_sessions(profile_id) WHERE revoked_at IS NULL"
    )
    op.execute(
        "CREATE INDEX current_profile_sessions_expiry_idx "
        "ON app.current_profile_sessions(expires_at)"
    )
    op.execute(
        "CREATE INDEX current_profile_sessions_revoked_idx "
        "ON app.current_profile_sessions(revoked_at) WHERE revoked_at IS NOT NULL"
    )
    op.execute(
        "ALTER TABLE app.current_profile_sessions OWNER TO itda_current_profile_session_owner"
    )
    op.execute("REVOKE ALL ON app.current_profile_sessions FROM PUBLIC")
    op.execute(f"REVOKE ALL ON app.current_profile_sessions FROM {quoted_runtime}")
    op.execute(f"REVOKE ALL ON app.current_profile_sessions FROM {_SERVICE}")
    op.execute("REVOKE ALL ON app.current_profile_sessions FROM CURRENT_USER")

    # Migration 0018 grants the photo service append-only ledger INSERT but its
    # bigserial sequence also needs explicit access for real DELETE requests.
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE "
        "dev_eval.photo_deletion_ledger_ledger_seq_seq TO itda_photo_service"
    )

    op.execute(
        "GRANT INSERT (profile_id,request_id,trip_conditions,answers,"
        "history_basis_points,history_display_score,emotion_basis_points,"
        "emotion_display_score,rest_basis_points,rest_display_score,description_ko,"
        "schema_version,questionnaire_version,scoring_version,"
        "description_template_version,config_hash,created_at,is_current_trip_expectation) "
        "ON app.preference_profiles TO itda_current_profile_session_owner"
    )

    session_check = _SERVICE
    functions = {
        "create_preference_profile_and_issue_session_v1": f"""
            CREATE FUNCTION app.create_preference_profile_and_issue_session_v1(
                p_profile_id text, p_request_id text, p_trip_conditions jsonb, p_answers jsonb,
                p_history_bp integer, p_history_display integer, p_emotion_bp integer,
                p_emotion_display integer, p_rest_bp integer, p_rest_display integer,
                p_description text, p_schema_version text, p_questionnaire_version text,
                p_scoring_version text, p_template_version text, p_config_hash text,
                p_created_at timestamptz, p_is_current boolean, p_digest text,
                p_issued_at timestamptz, p_expires_at timestamptz, p_peer_digest text,
                p_origin_digest text, p_predecessor_digest text DEFAULT NULL
            ) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            DECLARE inserted integer;
            BEGIN
                IF session_user <> '{session_check}' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='42501'; END IF;
                INSERT INTO app.preference_profiles(
                    profile_id,request_id,trip_conditions,answers,history_basis_points,
                    history_display_score,emotion_basis_points,emotion_display_score,
                    rest_basis_points,rest_display_score,description_ko,schema_version,
                    questionnaire_version,scoring_version,description_template_version,
                    config_hash,created_at,is_current_trip_expectation
                ) VALUES (
                    p_profile_id,p_request_id,p_trip_conditions,p_answers,p_history_bp,
                    p_history_display,p_emotion_bp,p_emotion_display,p_rest_bp,p_rest_display,
                    p_description,p_schema_version,p_questionnaire_version,p_scoring_version,
                    p_template_version,p_config_hash,p_created_at,p_is_current
                ) ON CONFLICT DO NOTHING;
                GET DIAGNOSTICS inserted=ROW_COUNT;
                IF inserted=0 THEN RETURN false; END IF;
                IF p_expires_at <> p_issued_at + interval '30 minutes' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='23514'; END IF;
                PERFORM pg_catalog.pg_advisory_xact_lock(9040614);
                WITH victims AS (
                    SELECT s.session_digest FROM app.current_profile_sessions s
                    WHERE s.expires_at < CURRENT_TIMESTAMP - interval '1 day'
                       OR (s.revoked_at IS NOT NULL AND s.revoked_at < CURRENT_TIMESTAMP - interval '1 day')
                    ORDER BY s.expires_at, s.session_digest
                    FOR UPDATE SKIP LOCKED LIMIT 256
                ) DELETE FROM app.current_profile_sessions s USING victims v
                  WHERE s.session_digest=v.session_digest;
                IF (SELECT count(*) FROM app.current_profile_sessions) >= 10000 THEN RAISE EXCEPTION 'session capacity rejected' USING ERRCODE='54000'; END IF;
                IF p_predecessor_digest IS NOT NULL THEN
                    UPDATE app.current_profile_sessions s SET revoked_at=CURRENT_TIMESTAMP,
                        revocation_version=s.revocation_version+1
                    WHERE s.session_digest=p_predecessor_digest AND s.revoked_at IS NULL;
                END IF;
                UPDATE app.current_profile_sessions s SET revoked_at=CURRENT_TIMESTAMP,
                    revocation_version=s.revocation_version+1
                WHERE s.profile_id=p_profile_id AND s.revoked_at IS NULL;
                INSERT INTO app.current_profile_sessions(session_digest,profile_id,issued_at,expires_at,peer_digest,origin_digest)
                VALUES(p_digest,p_profile_id,p_issued_at,p_expires_at,p_peer_digest,p_origin_digest);
                RETURN true;
            END $function$;
        """,
        "issue_current_profile_session_v1": f"""
            CREATE FUNCTION app.issue_current_profile_session_v1(
                p_digest text, p_profile_id text, p_issued_at timestamptz,
                p_expires_at timestamptz, p_peer_digest text, p_origin_digest text,
                p_predecessor_digest text DEFAULT NULL
            ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            BEGIN
                IF session_user <> '{session_check}' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='42501'; END IF;
                IF p_expires_at <> p_issued_at + interval '30 minutes' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='23514'; END IF;
                PERFORM pg_catalog.pg_advisory_xact_lock(9040614);
                WITH victims AS (
                    SELECT s.session_digest FROM app.current_profile_sessions s
                    WHERE s.expires_at < CURRENT_TIMESTAMP - interval '1 day'
                       OR (s.revoked_at IS NOT NULL AND s.revoked_at < CURRENT_TIMESTAMP - interval '1 day')
                    ORDER BY s.expires_at, s.session_digest
                    FOR UPDATE SKIP LOCKED LIMIT 256
                ) DELETE FROM app.current_profile_sessions s USING victims v
                  WHERE s.session_digest=v.session_digest;
                IF (SELECT count(*) FROM app.current_profile_sessions) >= 10000 THEN RAISE EXCEPTION 'session capacity rejected' USING ERRCODE='54000'; END IF;
                IF p_predecessor_digest IS NOT NULL THEN
                    UPDATE app.current_profile_sessions s SET revoked_at=CURRENT_TIMESTAMP,
                        revocation_version=s.revocation_version+1
                    WHERE s.session_digest=p_predecessor_digest AND s.revoked_at IS NULL;
                END IF;
                UPDATE app.current_profile_sessions s SET revoked_at=CURRENT_TIMESTAMP,
                    revocation_version=s.revocation_version+1
                WHERE s.profile_id=p_profile_id AND s.revoked_at IS NULL;
                INSERT INTO app.current_profile_sessions(session_digest,profile_id,issued_at,expires_at,peer_digest,origin_digest)
                VALUES(p_digest,p_profile_id,p_issued_at,p_expires_at,p_peer_digest,p_origin_digest);
            END $function$;
        """,
        "resolve_current_profile_session_v1": f"""
            CREATE FUNCTION app.resolve_current_profile_session_v1(p_digest text)
            RETURNS text LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            DECLARE resolved text;
            BEGIN
                IF session_user <> '{session_check}' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='42501'; END IF;
                SELECT s.profile_id INTO resolved FROM app.current_profile_sessions s
                WHERE s.session_digest=p_digest AND s.revoked_at IS NULL
                  AND s.issued_at <= CURRENT_TIMESTAMP AND s.expires_at > CURRENT_TIMESTAMP;
                RETURN resolved;
            END $function$;
        """,
        "revoke_current_profile_session_v1": f"""
            CREATE FUNCTION app.revoke_current_profile_session_v1(p_digest text)
            RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            DECLARE changed integer;
            BEGIN
                IF session_user <> '{session_check}' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='42501'; END IF;
                UPDATE app.current_profile_sessions s SET revoked_at=CURRENT_TIMESTAMP,
                    revocation_version=s.revocation_version+1
                WHERE s.session_digest=p_digest AND s.revoked_at IS NULL;
                GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
            END $function$;
        """,
        "rotate_current_profile_session_v1": f"""
            CREATE FUNCTION app.rotate_current_profile_session_v1(
                p_old_digest text, p_new_digest text, p_issued_at timestamptz,
                p_expires_at timestamptz, p_peer_digest text, p_origin_digest text
            ) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            DECLARE resolved text;
            BEGIN
                IF session_user <> '{session_check}' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='42501'; END IF;
                IF p_expires_at <> p_issued_at + interval '30 minutes' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='23514'; END IF;
                SELECT s.profile_id INTO resolved FROM app.current_profile_sessions s
                WHERE s.session_digest=p_old_digest AND s.revoked_at IS NULL AND s.expires_at>CURRENT_TIMESTAMP FOR UPDATE;
                IF resolved IS NULL THEN RETURN NULL; END IF;
                UPDATE app.current_profile_sessions s SET revoked_at=p_issued_at,
                    revocation_version=s.revocation_version+1 WHERE s.session_digest=p_old_digest;
                INSERT INTO app.current_profile_sessions(session_digest,profile_id,issued_at,expires_at,peer_digest,origin_digest)
                VALUES(p_new_digest,resolved,p_issued_at,p_expires_at,p_peer_digest,p_origin_digest);
                RETURN resolved;
            END $function$;
        """,
        "purge_current_profile_sessions_v1": f"""
            CREATE FUNCTION app.purge_current_profile_sessions_v1(p_limit integer DEFAULT 256)
            RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $function$
            DECLARE purged integer;
            BEGIN
                IF session_user <> '{session_check}' THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='42501'; END IF;
                IF p_limit < 1 OR p_limit > 1024 THEN RAISE EXCEPTION 'session operation rejected' USING ERRCODE='22023'; END IF;
                WITH victims AS (
                    SELECT s.session_digest FROM app.current_profile_sessions s
                    WHERE s.expires_at < CURRENT_TIMESTAMP - interval '1 day'
                       OR (s.revoked_at IS NOT NULL AND s.revoked_at < CURRENT_TIMESTAMP - interval '1 day')
                    ORDER BY s.expires_at, s.session_digest FOR UPDATE SKIP LOCKED LIMIT p_limit
                ) DELETE FROM app.current_profile_sessions s USING victims v
                  WHERE s.session_digest=v.session_digest;
                GET DIAGNOSTICS purged=ROW_COUNT; RETURN purged;
            END $function$;
        """,
    }
    signatures = {
        "create_preference_profile_and_issue_session_v1": "(text,text,jsonb,jsonb,integer,integer,integer,integer,integer,integer,text,text,text,text,text,text,timestamptz,boolean,text,timestamptz,timestamptz,text,text,text)",
        "issue_current_profile_session_v1": "(text,text,timestamptz,timestamptz,text,text,text)",
        "resolve_current_profile_session_v1": "(text)",
        "revoke_current_profile_session_v1": "(text)",
        "rotate_current_profile_session_v1": "(text,text,timestamptz,timestamptz,text,text)",
        "purge_current_profile_sessions_v1": "(integer)",
    }
    for name, statement in functions.items():
        op.execute(statement)
        signature = signatures[name]
        op.execute(f"ALTER FUNCTION app.{name}{signature} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON FUNCTION app.{name}{signature} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON FUNCTION app.{name}{signature} FROM {quoted_runtime}")
        op.execute(f"REVOKE ALL ON FUNCTION app.{name}{signature} FROM CURRENT_USER")
        op.execute(f"REVOKE EXECUTE ON FUNCTION app.{name}{signature} FROM {_OWNER}")
        op.execute(f"GRANT EXECUTE ON FUNCTION app.{name}{signature} TO {_SERVICE}")

    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_OWNER} REVOKE ALL ON TABLES FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_OWNER} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_OWNER} REVOKE ALL ON SEQUENCES FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_OWNER} IN SCHEMA app REVOKE ALL ON TABLES FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_OWNER} IN SCHEMA app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_OWNER} IN SCHEMA app REVOKE ALL ON SEQUENCES FROM PUBLIC"
    )
    _assert_session_acl_closed()


def downgrade() -> None:
    if (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM app.current_profile_sessions"))
        .scalar_one()
    ):
        raise RuntimeError(
            "0019 downgrade is intentionally irreversible after session state exists"
        )
    for signature in (
        "purge_current_profile_sessions_v1(integer)",
        "create_preference_profile_and_issue_session_v1(text,text,jsonb,jsonb,integer,integer,integer,integer,integer,integer,text,text,text,text,text,text,timestamptz,boolean,text,timestamptz,timestamptz,text,text,text)",
        "rotate_current_profile_session_v1(text,text,timestamptz,timestamptz,text,text)",
        "revoke_current_profile_session_v1(text)",
        "resolve_current_profile_session_v1(text)",
        "issue_current_profile_session_v1(text,text,timestamptz,timestamptz,text,text,text)",
    ):
        op.execute(f"DROP FUNCTION app.{signature}")
    op.execute("DROP TABLE app.current_profile_sessions")
