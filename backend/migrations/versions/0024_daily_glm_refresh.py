"""Add bounded daily GLM refresh authority and release overlay."""

# ruff: noqa: E501

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0024_daily_glm_refresh"
down_revision = "0023_photo_recommendation_projection_authority"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OWNER = "itda_daily_glm_refresh_write_authority"
_SERVICE = "itda_daily_glm_refresh_service"
_AUTHORITY_SHA256 = "e4f8d78e763617697ed926764d44c14e7672bc48bb91eb4a6513cc70adb41f6f"
_MEMBERSHIP_SHA256 = "cdd573f635259b4ac35becdcecdc72f00795cb768d21a003ca0e30fbb9b501f9"
_WRITE_FUNCTIONS = (
    "dev_eval.claim_daily_glm_refresh_v1(date,text)",
    "dev_eval.store_daily_glm_snapshot_v1(date,text,text,text,jsonb)",
    "dev_eval.store_daily_glm_scoring_plan_v1(date,text,text,jsonb)",
    "dev_eval.reserve_daily_glm_call_v1(date,text,text,text,integer)",
    "dev_eval.finish_daily_glm_attempt_v1(date,text,integer,text,text,text)",
    "dev_eval.publish_daily_scored_release_v2(date,text,text,jsonb)",
    "dev_eval.activate_daily_scored_release_v2(date,text,text)",
    "dev_eval.finish_daily_glm_refresh_v1(date,text,integer,integer,text)",
    "dev_eval.interrupt_daily_glm_refresh_v1(date)",
    "dev_eval.purge_daily_glm_refresh_v1(date)",
)
_READ_FUNCTIONS = (
    "dev_eval.read_latest_daily_glm_snapshot_v1()",
    "dev_eval.read_active_daily_scored_release_v2()",
    "dev_eval.read_daily_glm_refresh_status_v1()",
)


def _configured_identifier(name: str) -> str:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError("daily GLM authority configuration rejected")
    return value


def _quote(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _require_role_topology(runtime: str) -> None:
    rows = op.get_bind().execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (:owner, :service, :runtime)"
        ),
        {"owner": _OWNER, "service": _SERVICE, "runtime": runtime},
    ).mappings()
    roles = {str(row["rolname"]): row for row in rows}
    if set(roles) != {_OWNER, _SERVICE, runtime}:
        raise RuntimeError("daily GLM roles must be provisioned exactly")
    flags = (
        "rolcanlogin",
        "rolinherit",
        "rolsuper",
        "rolcreatedb",
        "rolcreaterole",
        "rolreplication",
        "rolbypassrls",
    )
    if tuple(roles[_OWNER][key] for key in flags) != (
        False,
        False,
        False,
        False,
        False,
        False,
        False,
    ):
        raise RuntimeError("daily GLM owner role flags are unsafe")
    if tuple(roles[_SERVICE][key] for key in flags) != (
        True,
        False,
        False,
        False,
        False,
        False,
        False,
    ):
        raise RuntimeError("daily GLM service role flags are unsafe")
    related = op.get_bind().execute(
        sa.text(
            "SELECT pg_catalog.pg_has_role(:runtime,:owner,'MEMBER'), "
            "pg_catalog.pg_has_role(:owner,:runtime,'MEMBER'), "
            "pg_catalog.pg_has_role(:runtime,:service,'MEMBER'), "
            "pg_catalog.pg_has_role(:service,:runtime,'MEMBER'), "
            "pg_catalog.pg_has_role(:owner,:service,'MEMBER'), "
            "pg_catalog.pg_has_role(:service,:owner,'MEMBER')"
        ),
        {"runtime": runtime, "owner": _OWNER, "service": _SERVICE},
    ).one()
    if any(bool(value) for value in related):
        raise RuntimeError("daily GLM roles must not have memberships")


def _secure_function(identity: str, *, runtime: str, runtime_read: bool) -> None:
    op.execute(f"ALTER FUNCTION {identity} OWNER TO {_OWNER}")
    for role in ("PUBLIC", _OWNER, "CURRENT_USER", _quote(runtime)):
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_SERVICE}")
    if runtime_read:
        op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_quote(runtime)}")


def upgrade() -> None:
    runtime_name = _configured_identifier("runtime_role")
    runtime = _quote(runtime_name)
    _require_role_topology(runtime_name)

    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_refresh_runs (
            run_date date PRIMARY KEY,
            status text NOT NULL CHECK (status IN (
                'RUNNING','BASELINE_RECORDED','NO_CHANGES','COLLECTION_INCOMPLETE',
                'SCORING_FAILED','RELEASE_REJECTED','RELEASE_ACTIVATED','INTERRUPTED'
            )),
            authority_sha256 text NOT NULL CHECK (authority_sha256 ~ '^[0-9a-f]{64}$'),
            snapshot_sha256 text NULL CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
            changed_count integer NOT NULL DEFAULT 0 CHECK (changed_count BETWEEN 0 AND 100),
            failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count BETWEEN 0 AND 100),
            call_count integer NOT NULL DEFAULT 0 CHECK (call_count BETWEEN 0 AND 200),
            active_release_sha256 text NULL CHECK (active_release_sha256 ~ '^[0-9a-f]{64}$'),
            safe_reason text NULL CHECK (safe_reason ~ '^[A-Z0-9_]{1,80}$'),
            started_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at timestamptz NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_input_snapshots (
            snapshot_sha256 text PRIMARY KEY CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
            run_date date NOT NULL UNIQUE REFERENCES dev_eval.daily_glm_refresh_runs(run_date),
            previous_snapshot_sha256 text NULL CHECK (previous_snapshot_sha256 ~ '^[0-9a-f]{64}$'),
            authority_sha256 text NOT NULL CHECK (authority_sha256 ~ '^[0-9a-f]{64}$'),
            membership_sha256 text NOT NULL CHECK (membership_sha256 ~ '^[0-9a-f]{64}$'),
            payload jsonb NOT NULL CHECK (octet_length(payload::text) BETWEEN 2 AND 8388608),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_scoring_plans (
            plan_sha256 text PRIMARY KEY CHECK (plan_sha256 ~ '^[0-9a-f]{64}$'),
            run_date date NOT NULL UNIQUE REFERENCES dev_eval.daily_glm_refresh_runs(run_date),
            snapshot_sha256 text NOT NULL REFERENCES dev_eval.daily_glm_input_snapshots(snapshot_sha256),
            payload jsonb NOT NULL CHECK (octet_length(payload::text) BETWEEN 2 AND 1048576),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_attempts (
            run_date date NOT NULL REFERENCES dev_eval.daily_glm_refresh_runs(run_date),
            place_id text NOT NULL CHECK (place_id ~ '^public:gyeongju:[0-9a-f]{64}$'),
            request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
            plan_sha256 text NOT NULL CHECK (plan_sha256 ~ '^[0-9a-f]{64}$'),
            attempt_number integer NOT NULL CHECK (attempt_number IN (1,2)),
            status text NOT NULL CHECK (status IN ('STARTED','SUCCEEDED','FAILED')),
            safe_reason text NULL CHECK (safe_reason ~ '^[A-Z0-9_]{1,80}$'),
            result_sha256 text NULL CHECK (result_sha256 ~ '^[0-9a-f]{64}$'),
            reserved_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at timestamptz NULL,
            PRIMARY KEY (run_date, place_id, attempt_number),
            CHECK ((status='STARTED' AND finished_at IS NULL AND safe_reason IS NULL AND result_sha256 IS NULL)
                OR (status='SUCCEEDED' AND finished_at IS NOT NULL AND safe_reason IS NULL AND result_sha256 IS NOT NULL)
                OR (status='FAILED' AND finished_at IS NOT NULL AND safe_reason IS NOT NULL AND result_sha256 IS NULL))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_scored_releases (
            release_sha256 text PRIMARY KEY CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
            previous_release_sha256 text NOT NULL CHECK (previous_release_sha256 ~ '^[0-9a-f]{64}$'),
            run_date date NOT NULL UNIQUE REFERENCES dev_eval.daily_glm_refresh_runs(run_date),
            payload jsonb NOT NULL CHECK (octet_length(payload::text) BETWEEN 2 AND 16777216),
            published_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_scored_release_active (
            singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
            release_sha256 text NOT NULL REFERENCES dev_eval.daily_scored_releases(release_sha256),
            updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_scored_release_activations (
            activation_seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            release_sha256 text NOT NULL REFERENCES dev_eval.daily_scored_releases(release_sha256),
            previous_release_sha256 text NULL CHECK (previous_release_sha256 ~ '^[0-9a-f]{64}$'),
            run_date date NOT NULL REFERENCES dev_eval.daily_glm_refresh_runs(run_date),
            activated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    for table in (
        "daily_glm_refresh_runs",
        "daily_glm_input_snapshots",
        "daily_glm_scoring_plans",
        "daily_glm_attempts",
        "daily_scored_releases",
        "daily_scored_release_active",
        "daily_scored_release_activations",
    ):
        op.execute(f"ALTER TABLE dev_eval.{table} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON TABLE dev_eval.{table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON TABLE dev_eval.{table} FROM {_SERVICE}")
        op.execute(f"REVOKE ALL ON TABLE dev_eval.{table} FROM {runtime}")
    op.execute("ALTER SEQUENCE dev_eval.daily_scored_release_activations_activation_seq_seq OWNER TO itda_daily_glm_refresh_write_authority")
    op.execute("REVOKE ALL ON SEQUENCE dev_eval.daily_scored_release_activations_activation_seq_seq FROM PUBLIC")
    op.execute(f"REVOKE ALL ON SEQUENCE dev_eval.daily_scored_release_activations_activation_seq_seq FROM {runtime}")
    op.execute("REVOKE ALL ON SEQUENCE dev_eval.daily_scored_release_activations_activation_seq_seq FROM itda_daily_glm_refresh_service")
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO itda_daily_glm_refresh_service")
    op.execute(f"GRANT USAGE ON SCHEMA dev_eval TO {runtime}")

    op.execute(
        f"""
        CREATE FUNCTION dev_eval.claim_daily_glm_refresh_v1(p_run_date date, p_authority text)
        RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_inserted integer;
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_run_date IS NULL OR p_authority <> '{_AUTHORITY_SHA256}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514'; END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('daily-glm-refresh-v1|' || p_run_date::text, 0));
            INSERT INTO dev_eval.daily_glm_refresh_runs(run_date,status,authority_sha256)
            VALUES (p_run_date,'RUNNING',p_authority) ON CONFLICT (run_date) DO NOTHING;
            GET DIAGNOSTICS v_inserted = ROW_COUNT;
            RETURN v_inserted = 1;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.store_daily_glm_snapshot_v1(p_run_date date, p_snapshot text, p_previous text, p_membership text, p_payload jsonb)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_snapshot IS NULL OR p_snapshot !~ '^[0-9a-f]{{64}}$' OR (p_previous IS NOT NULL AND p_previous !~ '^[0-9a-f]{{64}}$')
               OR p_membership IS DISTINCT FROM '{_MEMBERSHIP_SHA256}' OR p_payload IS NULL
               OR p_payload->>'schema_version' IS DISTINCT FROM 'mvp-daily-scoring-input-snapshot.v1'
               OR p_payload->>'snapshot_sha256' IS DISTINCT FROM p_snapshot OR p_payload->>'run_date' IS DISTINCT FROM p_run_date::text
               OR p_payload->>'authority_sha256' IS DISTINCT FROM '{_AUTHORITY_SHA256}' OR p_payload->>'membership_sha256' IS DISTINCT FROM p_membership
               OR jsonb_typeof(p_payload->'places') IS DISTINCT FROM 'array' OR jsonb_array_length(p_payload->'places') <> 100 THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=p_run_date AND r.status='RUNNING') THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            INSERT INTO dev_eval.daily_glm_input_snapshots(snapshot_sha256,run_date,previous_snapshot_sha256,authority_sha256,membership_sha256,payload)
            VALUES (p_snapshot,p_run_date,p_previous,'{_AUTHORITY_SHA256}',p_membership,p_payload);
            UPDATE dev_eval.daily_glm_refresh_runs SET snapshot_sha256=p_snapshot,updated_at=CURRENT_TIMESTAMP WHERE run_date=p_run_date;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.store_daily_glm_scoring_plan_v1(p_run_date date, p_plan text, p_snapshot text, p_payload jsonb)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_plan IS NULL OR p_plan !~ '^[0-9a-f]{{64}}$' OR p_snapshot IS NULL OR p_snapshot !~ '^[0-9a-f]{{64}}$' OR p_payload IS NULL
               OR p_payload->>'schema_version' IS DISTINCT FROM 'mvp-daily-incremental-scoring-plan.v1'
               OR p_payload->>'plan_sha256' IS DISTINCT FROM p_plan OR p_payload->>'snapshot_sha256' IS DISTINCT FROM p_snapshot
               OR p_payload->>'run_date' IS DISTINCT FROM p_run_date::text OR p_payload->>'authority_sha256' IS DISTINCT FROM '{_AUTHORITY_SHA256}'
               OR p_payload->>'model' IS DISTINCT FROM 'glm-5.3-flash' OR p_payload->>'endpoint' IS DISTINCT FROM 'https://api.z.ai/api/coding/paas/v4/chat/completions'
               OR p_payload->>'prompt_sha256' IS DISTINCT FROM '483fd6088036eaeb34a4598c3e856eca9429cd1bac182bb144a31c6517fce87b'
               OR p_payload->>'maximum_calls' IS DISTINCT FROM '200' OR p_payload->>'concurrency' IS DISTINCT FROM '1'
               OR p_payload->>'retry_limit_per_place' IS DISTINCT FROM '1' OR p_payload->>'fallback' IS DISTINCT FROM 'false'
               OR p_payload->>'pay_as_you_go_fallback' IS DISTINCT FROM 'false'
               OR jsonb_typeof(p_payload->'changed_place_ids') IS DISTINCT FROM 'array'
               OR jsonb_typeof(p_payload->'request_sha256') IS DISTINCT FROM 'array'
               OR jsonb_array_length(p_payload->'changed_place_ids') NOT BETWEEN 1 AND 100
               OR jsonb_array_length(p_payload->'changed_place_ids') <> jsonb_array_length(p_payload->'request_sha256')
               OR (p_payload->>'first_pass_count')::integer <> jsonb_array_length(p_payload->'changed_place_ids')
               OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_payload->'changed_place_ids') AS item(value) WHERE item.value !~ '^public:gyeongju:[0-9a-f]{{64}}$')
               OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_payload->'request_sha256') AS item(value) WHERE item.value !~ '^[0-9a-f]{{64}}$')
               OR (SELECT count(*) FROM jsonb_array_elements_text(p_payload->'changed_place_ids'))
                  <> (SELECT count(DISTINCT item.value) FROM jsonb_array_elements_text(p_payload->'changed_place_ids') AS item(value))
               OR (SELECT array_agg(item.value ORDER BY item.value) FROM jsonb_array_elements_text(p_payload->'changed_place_ids') AS item(value))
                  <> (SELECT array_agg(item.value) FROM jsonb_array_elements_text(p_payload->'changed_place_ids') AS item(value)) THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=p_run_date AND s.snapshot_sha256=p_snapshot) THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            INSERT INTO dev_eval.daily_glm_scoring_plans(plan_sha256,run_date,snapshot_sha256,payload)
            VALUES(p_plan,p_run_date,p_snapshot,p_payload);
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.reserve_daily_glm_call_v1(p_run_date date, p_plan text, p_place text, p_request text, p_attempt integer)
        RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_count integer;
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_plan !~ '^[0-9a-f]{{64}}$' OR p_place !~ '^public:gyeongju:[0-9a-f]{{64}}$'
               OR p_request !~ '^[0-9a-f]{{64}}$' OR p_attempt NOT IN (1,2) THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM dev_eval.daily_glm_refresh_runs r
                JOIN dev_eval.daily_glm_scoring_plans p ON p.run_date=r.run_date AND p.plan_sha256=p_plan
                WHERE r.run_date=p_run_date AND r.status='RUNNING'
                  AND EXISTS (
                    SELECT 1 FROM jsonb_array_elements_text(p.payload->'changed_place_ids') WITH ORDINALITY AS ids(value, ordinal)
                    JOIN jsonb_array_elements_text(p.payload->'request_sha256') WITH ORDINALITY AS hashes(value, ordinal) USING (ordinal)
                    WHERE ids.value=p_place AND hashes.value=p_request
                  )
            ) THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            IF p_attempt=2 AND NOT EXISTS (SELECT 1 FROM dev_eval.daily_glm_attempts a WHERE a.run_date=p_run_date AND a.place_id=p_place AND a.attempt_number=1 AND a.status='FAILED') THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            INSERT INTO dev_eval.daily_glm_attempts(run_date,place_id,request_sha256,plan_sha256,attempt_number,status)
            VALUES (p_run_date,p_place,p_request,p_plan,p_attempt,'STARTED');
            UPDATE dev_eval.daily_glm_refresh_runs SET call_count=call_count+1,updated_at=CURRENT_TIMESTAMP
            WHERE run_date=p_run_date AND status='RUNNING' AND call_count < 200 RETURNING call_count INTO v_count;
            IF v_count IS NULL THEN RAISE EXCEPTION 'daily GLM call budget exhausted' USING ERRCODE='23514'; END IF;
            RETURN v_count;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.finish_daily_glm_attempt_v1(p_run_date date, p_place text, p_attempt integer, p_status text, p_reason text, p_result text)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_updated integer;
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_status NOT IN ('SUCCEEDED','FAILED') OR (p_status='SUCCEEDED' AND (p_reason IS NOT NULL OR p_result !~ '^[0-9a-f]{{64}}$'))
               OR (p_status='FAILED' AND (p_reason !~ '^[A-Z0-9_]{{1,80}}$' OR p_result IS NOT NULL)) THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            UPDATE dev_eval.daily_glm_attempts SET status=p_status,safe_reason=p_reason,result_sha256=p_result,finished_at=CURRENT_TIMESTAMP
            WHERE run_date=p_run_date AND place_id=p_place AND attempt_number=p_attempt AND status='STARTED';
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            IF v_updated <> 1 THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514'; END IF;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.publish_daily_scored_release_v2(p_run_date date, p_release text, p_previous text, p_payload jsonb)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_release IS NULL OR p_release !~ '^[0-9a-f]{{64}}$' OR p_previous IS NULL OR p_previous !~ '^[0-9a-f]{{64}}$' OR p_payload IS NULL
               OR p_payload->>'schema_version' IS DISTINCT FROM 'mvp-scored-release.v2' OR p_payload->>'release_sha256' IS DISTINCT FROM p_release
               OR p_payload->>'previous_release_sha256' IS DISTINCT FROM p_previous OR p_payload->>'daily_run_date' IS DISTINCT FROM p_run_date::text
               OR p_payload->>'authority_sha256' IS DISTINCT FROM '{_AUTHORITY_SHA256}'
               OR p_payload->>'authority_membership_sha256' IS DISTINCT FROM '{_MEMBERSHIP_SHA256}'
               OR COALESCE((p_payload->>'published_count') ~ '^[0-9]+$', FALSE) IS FALSE
               OR (p_payload->>'published_count')::integer NOT BETWEEN 80 AND 100 THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=p_run_date AND r.status='RUNNING' AND r.snapshot_sha256=p_payload->>'snapshot_sha256') THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            INSERT INTO dev_eval.daily_scored_releases(release_sha256,previous_release_sha256,run_date,payload)
            VALUES (p_release,p_previous,p_run_date,p_payload);
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.activate_daily_scored_release_v2(p_run_date date, p_release text, p_expected text)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_current text;
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            SELECT a.release_sha256 INTO v_current FROM dev_eval.daily_scored_release_active a WHERE a.singleton FOR UPDATE;
            IF NOT EXISTS (SELECT 1 FROM dev_eval.daily_scored_release_active a WHERE a.singleton)
               AND EXISTS (SELECT 1 FROM dev_eval.daily_scored_release_activations) THEN
                RAISE EXCEPTION 'daily GLM activation rejected' USING ERRCODE='23514';
            END IF;
            IF (v_current IS NOT NULL AND v_current IS DISTINCT FROM p_expected) OR NOT EXISTS (
                SELECT 1 FROM dev_eval.daily_scored_releases r WHERE r.release_sha256=p_release AND r.run_date=p_run_date AND r.previous_release_sha256=p_expected
            ) THEN RAISE EXCEPTION 'daily GLM activation rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_scored_release_active(singleton,release_sha256) VALUES(TRUE,p_release)
            ON CONFLICT(singleton) DO UPDATE SET release_sha256=EXCLUDED.release_sha256,updated_at=CURRENT_TIMESTAMP;
            INSERT INTO dev_eval.daily_scored_release_activations(release_sha256,previous_release_sha256,run_date)
            VALUES(p_release,v_current,p_run_date);
            UPDATE dev_eval.daily_glm_refresh_runs SET active_release_sha256=p_release,updated_at=CURRENT_TIMESTAMP WHERE run_date=p_run_date AND status='RUNNING';
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.finish_daily_glm_refresh_v1(p_run_date date, p_status text, p_changed integer, p_failed integer, p_reason text)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_updated integer;
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            IF p_status NOT IN ('BASELINE_RECORDED','NO_CHANGES','COLLECTION_INCOMPLETE','SCORING_FAILED','RELEASE_REJECTED','RELEASE_ACTIVATED')
               OR p_changed NOT BETWEEN 0 AND 100 OR p_failed NOT BETWEEN 0 AND 100
               OR (p_reason IS NOT NULL AND p_reason !~ '^[A-Z0-9_]{{1,80}}$') THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            UPDATE dev_eval.daily_glm_refresh_runs SET status=p_status,changed_count=p_changed,failed_count=p_failed,
                safe_reason=p_reason,updated_at=CURRENT_TIMESTAMP,finished_at=CURRENT_TIMESTAMP
            WHERE run_date=p_run_date AND status='RUNNING';
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            IF v_updated <> 1 THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514'; END IF;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.interrupt_daily_glm_refresh_v1(p_run_date date)
        RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_updated integer;
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            UPDATE dev_eval.daily_glm_refresh_runs SET status='INTERRUPTED',safe_reason='PROCESS_INTERRUPTED_UNKNOWN_OUTCOME',updated_at=CURRENT_TIMESTAMP,finished_at=CURRENT_TIMESTAMP
            WHERE run_date=p_run_date AND status='RUNNING';
            GET DIAGNOSTICS v_updated = ROW_COUNT;
            RETURN v_updated = 1;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.purge_daily_glm_refresh_v1(p_cutoff date)
        RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_deleted integer;
        BEGIN
            IF session_user <> '{_SERVICE}' OR p_cutoff IS NULL OR p_cutoff >= CURRENT_DATE THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            DELETE FROM dev_eval.daily_glm_attempts a WHERE a.run_date < p_cutoff;
            DELETE FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date < p_cutoff;
            DELETE FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date < p_cutoff
              AND s.run_date <> (SELECT max(y.run_date) FROM dev_eval.daily_glm_input_snapshots y)
              AND NOT EXISTS (
                SELECT 1 FROM dev_eval.daily_scored_releases r
                WHERE r.payload->>'snapshot_sha256'=s.snapshot_sha256
                   OR EXISTS (
                     SELECT 1 FROM jsonb_array_elements(r.payload->'profile_entries') entry
                     WHERE entry->'lineage'->>'source_snapshot_sha256'=s.snapshot_sha256
                   )
              );
            DELETE FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date < p_cutoff
              AND NOT EXISTS (SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=r.run_date)
              AND NOT EXISTS (SELECT 1 FROM dev_eval.daily_scored_releases d WHERE d.run_date=r.run_date);
            GET DIAGNOSTICS v_deleted = ROW_COUNT;
            RETURN v_deleted;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_latest_daily_glm_snapshot_v1()
        RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user <> '{_SERVICE}' THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN (SELECT s.payload FROM dev_eval.daily_glm_input_snapshots s ORDER BY s.run_date DESC LIMIT 1);
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_active_daily_scored_release_v2()
        RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}', '{runtime_name}') THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN (SELECT r.payload FROM dev_eval.daily_scored_release_active a JOIN dev_eval.daily_scored_releases r ON r.release_sha256=a.release_sha256 WHERE a.singleton);
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_refresh_status_v1()
        RETURNS TABLE(run_date date,status text,changed_count integer,failed_count integer,call_count integer,active_release_sha256 text,safe_reason text)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}', '{runtime_name}') THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY SELECT r.run_date,r.status,r.changed_count,r.failed_count,r.call_count,
                COALESCE(r.active_release_sha256,(SELECT a.release_sha256 FROM dev_eval.daily_scored_release_active a WHERE a.singleton)),r.safe_reason
            FROM dev_eval.daily_glm_refresh_runs r ORDER BY r.run_date DESC LIMIT 1;
        END $function$
        """
    )
    for identity in _WRITE_FUNCTIONS:
        _secure_function(identity, runtime=runtime_name, runtime_read=False)
    for identity in _READ_FUNCTIONS:
        _secure_function(identity, runtime=runtime_name, runtime_read=identity != _READ_FUNCTIONS[0])


def downgrade() -> None:
    for identity in reversed((*_WRITE_FUNCTIONS, *_READ_FUNCTIONS)):
        op.execute(f"DROP FUNCTION {identity}")
    for table in (
        "daily_scored_release_activations",
        "daily_scored_release_active",
        "daily_scored_releases",
        "daily_glm_attempts",
        "daily_glm_scoring_plans",
        "daily_glm_input_snapshots",
        "daily_glm_refresh_runs",
    ):
        op.execute(f"DROP TABLE dev_eval.{table}")
