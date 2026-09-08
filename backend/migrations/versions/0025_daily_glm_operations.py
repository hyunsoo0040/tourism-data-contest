"""Add daily GLM operations history and recollection commands."""

# ruff: noqa: E501

from __future__ import annotations

import os
import re

from alembic import op

revision = "0025_daily_glm_operations"
down_revision = "0024_daily_glm_refresh"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OWNER = "itda_daily_glm_refresh_write_authority"
_SERVICE = "itda_daily_glm_refresh_service"
_AUTHORITY_SHA256 = "e4f8d78e763617697ed926764d44c14e7672bc48bb91eb4a6513cc70adb41f6f"

_NEW_FUNCTIONS = (
    "dev_eval.read_daily_glm_operations_overview_v1()",
    "dev_eval.read_daily_glm_execution_history_v1(integer)",
    "dev_eval.read_daily_glm_execution_v1(date,integer)",
    "dev_eval.read_daily_glm_collection_failures_v1(date,integer)",
    "dev_eval.read_daily_glm_attempts_v1(date,integer)",
    "dev_eval.request_daily_glm_recollection_v1(date,text)",
    "dev_eval.read_daily_glm_recollection_command_v1(uuid)",
    "dev_eval.claim_daily_glm_recollection_v1(integer)",
    "dev_eval.record_daily_glm_collection_failure_v1(date,text,text,text,text)",
    "dev_eval.complete_daily_glm_recollection_v1(uuid,text,text)",
)


def _configured_identifier(name: str) -> str:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError("daily GLM operations authority configuration rejected")
    return value


def _quote(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _secure(identity: str, *, runtime: str, runtime_access: bool) -> None:
    op.execute(f"ALTER FUNCTION {identity} OWNER TO {_OWNER}")
    for role in ("PUBLIC", _OWNER, "CURRENT_USER", _quote(runtime)):
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_SERVICE}")
    if runtime_access:
        op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_quote(runtime)}")


def upgrade() -> None:
    runtime_name = _configured_identifier("runtime_role")
    runtime = _quote(runtime_name)

    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_refresh_commands (
            command_id uuid PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
            command_type text NOT NULL DEFAULT 'RECOLLECT_INCOMPLETE_DAY'
                CHECK (command_type='RECOLLECT_INCOMPLETE_DAY'),
            run_date date NOT NULL REFERENCES dev_eval.daily_glm_refresh_runs(run_date)
                ON DELETE CASCADE,
            idempotency_key text NOT NULL UNIQUE
                CHECK (idempotency_key ~ '^[A-Za-z0-9_-]{16,128}$'),
            status text NOT NULL CHECK (status IN (
                'REQUESTED','CLAIMED','SUCCEEDED','FAILED','REJECTED'
            )),
            execution_sequence smallint NULL CHECK (execution_sequence BETWEEN 1 AND 3),
            safe_reason text NULL CHECK (safe_reason ~ '^[A-Z0-9_]{1,80}$'),
            requested_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            claimed_at timestamptz NULL,
            lease_expires_at timestamptz NULL,
            finished_at timestamptz NULL,
            CHECK (
                (status='REQUESTED' AND execution_sequence IS NULL AND claimed_at IS NULL
                    AND lease_expires_at IS NULL AND finished_at IS NULL)
                OR (status='CLAIMED' AND execution_sequence IS NOT NULL AND claimed_at IS NOT NULL
                    AND lease_expires_at IS NOT NULL AND finished_at IS NULL)
                OR (status IN ('SUCCEEDED','FAILED') AND execution_sequence IS NOT NULL
                    AND claimed_at IS NOT NULL AND lease_expires_at IS NULL
                    AND finished_at IS NOT NULL)
                OR (status='REJECTED' AND lease_expires_at IS NULL AND finished_at IS NOT NULL)
            )
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX daily_glm_refresh_commands_one_pending_per_day "
        "ON dev_eval.daily_glm_refresh_commands(run_date) "
        "WHERE status IN ('REQUESTED','CLAIMED')"
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_refresh_executions (
            run_date date NOT NULL REFERENCES dev_eval.daily_glm_refresh_runs(run_date)
                ON DELETE CASCADE,
            execution_sequence smallint NOT NULL CHECK (execution_sequence BETWEEN 0 AND 3),
            kind text NOT NULL CHECK (kind IN ('SCHEDULED','MANUAL_RECOLLECTION')),
            command_id uuid NULL REFERENCES dev_eval.daily_glm_refresh_commands(command_id)
                ON DELETE CASCADE,
            status text NOT NULL CHECK (status IN (
                'RUNNING','BASELINE_RECORDED','NO_CHANGES','COLLECTION_INCOMPLETE',
                'SCORING_FAILED','RELEASE_REJECTED','RELEASE_ACTIVATED','INTERRUPTED'
            )),
            changed_count integer NOT NULL DEFAULT 0 CHECK (changed_count BETWEEN 0 AND 100),
            failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count BETWEEN 0 AND 100),
            call_count integer NOT NULL DEFAULT 0 CHECK (call_count BETWEEN 0 AND 200),
            active_release_sha256 text NULL CHECK (active_release_sha256 ~ '^[0-9a-f]{64}$'),
            safe_reason text NULL CHECK (safe_reason ~ '^[A-Z0-9_]{1,80}$'),
            started_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL,
            finished_at timestamptz NULL,
            PRIMARY KEY (run_date, execution_sequence),
            UNIQUE (command_id),
            CHECK ((kind='SCHEDULED' AND execution_sequence=0 AND command_id IS NULL)
                OR (kind='MANUAL_RECOLLECTION' AND execution_sequence BETWEEN 1 AND 3
                    AND command_id IS NOT NULL))
        )
        """
    )
    op.execute(
        """
        INSERT INTO dev_eval.daily_glm_refresh_executions(
            run_date,execution_sequence,kind,status,changed_count,failed_count,call_count,
            active_release_sha256,safe_reason,started_at,updated_at,finished_at
        )
        SELECT run_date,0,'SCHEDULED',status,changed_count,failed_count,call_count,
            active_release_sha256,safe_reason,started_at,updated_at,finished_at
        FROM dev_eval.daily_glm_refresh_runs
        """
    )
    op.execute(
        "ALTER TABLE dev_eval.daily_glm_attempts ADD COLUMN execution_sequence smallint "
        "NOT NULL DEFAULT 0 CHECK (execution_sequence BETWEEN 0 AND 3)"
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_collection_failures (
            failure_seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            run_date date NOT NULL,
            execution_sequence smallint NOT NULL,
            place_id text NOT NULL CHECK (place_id ~ '^public:gyeongju:[0-9a-f]{64}$'),
            operation text NOT NULL CHECK (operation IN ('detailCommon2','detailIntro2')),
            failure_category text NOT NULL CHECK (failure_category ~ '^[A-Z0-9_]{1,80}$'),
            failure_code text NOT NULL CHECK (failure_code ~ '^[A-Z0-9_]{1,80}$'),
            occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (run_date,execution_sequence)
                REFERENCES dev_eval.daily_glm_refresh_executions(run_date,execution_sequence)
                ON DELETE CASCADE,
            CHECK (execution_sequence BETWEEN 0 AND 3)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE dev_eval.daily_glm_refresh_command_events (
            event_seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            command_id uuid NOT NULL REFERENCES dev_eval.daily_glm_refresh_commands(command_id)
                ON DELETE CASCADE,
            status text NOT NULL CHECK (status IN (
                'REQUESTED','CLAIMED','SUCCEEDED','FAILED','REJECTED'
            )),
            safe_reason text NULL CHECK (safe_reason ~ '^[A-Z0-9_]{1,80}$'),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    for table in (
        "daily_glm_refresh_commands",
        "daily_glm_refresh_executions",
        "daily_glm_collection_failures",
        "daily_glm_refresh_command_events",
    ):
        op.execute(f"ALTER TABLE dev_eval.{table} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON TABLE dev_eval.{table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON TABLE dev_eval.{table} FROM {_SERVICE}")
        op.execute(f"REVOKE ALL ON TABLE dev_eval.{table} FROM {runtime}")
    for sequence in (
        "daily_glm_collection_failures_failure_seq_seq",
        "daily_glm_refresh_command_events_event_seq_seq",
    ):
        op.execute(f"ALTER SEQUENCE dev_eval.{sequence} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON SEQUENCE dev_eval.{sequence} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON SEQUENCE dev_eval.{sequence} FROM {_SERVICE}")
        op.execute(f"REVOKE ALL ON SEQUENCE dev_eval.{sequence} FROM {runtime}")

    op.execute(
        """
        CREATE FUNCTION dev_eval.sync_daily_glm_execution_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF TG_OP='INSERT' THEN
                INSERT INTO dev_eval.daily_glm_refresh_executions(
                    run_date,execution_sequence,kind,status,started_at,updated_at
                ) VALUES(NEW.run_date,0,'SCHEDULED',NEW.status,NEW.started_at,NEW.updated_at);
            ELSE
                UPDATE dev_eval.daily_glm_refresh_executions SET status=NEW.status,
                    changed_count=NEW.changed_count,failed_count=NEW.failed_count,
                    call_count=NEW.call_count,active_release_sha256=NEW.active_release_sha256,
                    safe_reason=NEW.safe_reason,updated_at=NEW.updated_at,finished_at=NEW.finished_at
                WHERE run_date=NEW.run_date AND execution_sequence=(
                    SELECT max(e.execution_sequence)
                    FROM dev_eval.daily_glm_refresh_executions e
                    WHERE e.run_date=NEW.run_date AND e.status='RUNNING'
                );
            END IF;
            RETURN NEW;
        END $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.sync_daily_glm_execution_v1() OWNER TO " + _OWNER
    )
    op.execute("REVOKE ALL ON FUNCTION dev_eval.sync_daily_glm_execution_v1() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER sync_daily_glm_execution_v1 AFTER INSERT OR UPDATE "
        "ON dev_eval.daily_glm_refresh_runs FOR EACH ROW "
        "EXECUTE FUNCTION dev_eval.sync_daily_glm_execution_v1()"
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.bind_daily_glm_attempt_execution_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            SELECT max(e.execution_sequence) INTO NEW.execution_sequence
            FROM dev_eval.daily_glm_refresh_executions e
            WHERE e.run_date=NEW.run_date AND e.status='RUNNING';
            IF NEW.execution_sequence IS NULL THEN
                RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514';
            END IF;
            RETURN NEW;
        END $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.bind_daily_glm_attempt_execution_v1() OWNER TO " + _OWNER
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.bind_daily_glm_attempt_execution_v1() FROM PUBLIC"
    )
    op.execute(
        "CREATE TRIGGER bind_daily_glm_attempt_execution_v1 BEFORE INSERT "
        "ON dev_eval.daily_glm_attempts FOR EACH ROW "
        "EXECUTE FUNCTION dev_eval.bind_daily_glm_attempt_execution_v1()"
    )

    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_operations_overview_v1()
        RETURNS TABLE(run_date date,execution_sequence smallint,kind text,command_id uuid,status text,
            changed_count integer,failed_count integer,call_count integer,active_release_sha256 text,
            safe_reason text,started_at timestamptz,updated_at timestamptz,finished_at timestamptz,
            recollection_eligible boolean,recollection_reason text,pending_command_id uuid)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}','{runtime_name}') THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY
            WITH latest AS (
                SELECT e.* FROM dev_eval.daily_glm_refresh_executions e
                ORDER BY e.run_date DESC,e.execution_sequence DESC LIMIT 1
            )
            SELECT e.run_date,e.execution_sequence,e.kind,e.command_id,e.status,e.changed_count,
                e.failed_count,e.call_count,
                COALESCE(e.active_release_sha256,(SELECT a.release_sha256 FROM dev_eval.daily_scored_release_active a WHERE a.singleton)),
                e.safe_reason,e.started_at,e.updated_at,e.finished_at,
                CASE WHEN e.status='COLLECTION_INCOMPLETE' AND e.call_count=0
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=e.run_date)
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date=e.run_date)
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts t WHERE t.run_date=e.run_date)
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases r WHERE r.run_date=e.run_date)
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_commands c WHERE c.run_date=e.run_date AND c.status IN ('REQUESTED','CLAIMED'))
                    AND (SELECT count(*) FROM dev_eval.daily_glm_refresh_executions x WHERE x.run_date=e.run_date AND x.kind='MANUAL_RECOLLECTION')<3
                    THEN TRUE ELSE FALSE END,
                CASE
                    WHEN e.status IS DISTINCT FROM 'COLLECTION_INCOMPLETE' THEN 'STATUS_NOT_COLLECTION_INCOMPLETE'
                    WHEN e.call_count<>0 THEN 'GLM_CALLS_ALREADY_RESERVED'
                    WHEN EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=e.run_date) THEN 'SNAPSHOT_ALREADY_EXISTS'
                    WHEN EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date=e.run_date) THEN 'SCORING_PLAN_ALREADY_EXISTS'
                    WHEN EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts t WHERE t.run_date=e.run_date) THEN 'GLM_ATTEMPT_ALREADY_EXISTS'
                    WHEN EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases r WHERE r.run_date=e.run_date) THEN 'RELEASE_ALREADY_EXISTS'
                    WHEN EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_commands c WHERE c.run_date=e.run_date AND c.status IN ('REQUESTED','CLAIMED')) THEN 'COMMAND_ALREADY_PENDING'
                    WHEN (SELECT count(*) FROM dev_eval.daily_glm_refresh_executions x WHERE x.run_date=e.run_date AND x.kind='MANUAL_RECOLLECTION')>=3 THEN 'MANUAL_RECOLLECTION_LIMIT_REACHED'
                    ELSE 'RECOLLECTION_ALLOWED' END,
                (SELECT c.command_id FROM dev_eval.daily_glm_refresh_commands c
                    WHERE c.run_date=e.run_date AND c.status IN ('REQUESTED','CLAIMED')
                    ORDER BY c.requested_at LIMIT 1)
            FROM latest e;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_execution_history_v1(p_days integer)
        RETURNS SETOF dev_eval.daily_glm_refresh_executions LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}','{runtime_name}') OR p_days NOT BETWEEN 1 AND 30
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY SELECT e.* FROM dev_eval.daily_glm_refresh_executions e
            WHERE e.run_date>=CURRENT_DATE-(p_days-1) ORDER BY e.run_date DESC,e.execution_sequence DESC;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_execution_v1(p_run_date date,p_execution integer)
        RETURNS SETOF dev_eval.daily_glm_refresh_executions LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}','{runtime_name}') OR p_run_date IS NULL OR p_execution NOT BETWEEN 0 AND 3
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY SELECT e.* FROM dev_eval.daily_glm_refresh_executions e
            WHERE e.run_date=p_run_date AND e.execution_sequence=p_execution;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_collection_failures_v1(p_run_date date,p_execution integer)
        RETURNS SETOF dev_eval.daily_glm_collection_failures LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}','{runtime_name}') OR p_run_date IS NULL OR p_execution NOT BETWEEN 0 AND 3
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY SELECT f.* FROM dev_eval.daily_glm_collection_failures f
            WHERE f.run_date=p_run_date AND f.execution_sequence=p_execution ORDER BY f.failure_seq;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_attempts_v1(p_run_date date,p_execution integer)
        RETURNS TABLE(run_date date,execution_sequence smallint,place_id text,attempt_number integer,
            status text,safe_reason text,result_sha256 text,reserved_at timestamptz,finished_at timestamptz)
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}','{runtime_name}') OR p_run_date IS NULL OR p_execution NOT BETWEEN 0 AND 3
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY SELECT a.run_date,a.execution_sequence,a.place_id,a.attempt_number,
                a.status,a.safe_reason,a.result_sha256,a.reserved_at,a.finished_at
            FROM dev_eval.daily_glm_attempts a WHERE a.run_date=p_run_date
                AND a.execution_sequence=p_execution ORDER BY a.place_id,a.attempt_number;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.request_daily_glm_recollection_v1(p_run_date date,p_idempotency text)
        RETURNS SETOF dev_eval.daily_glm_refresh_commands LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_command uuid;
        BEGIN
            IF session_user <> '{runtime_name}' OR p_run_date IS NULL OR p_idempotency !~ '^[A-Za-z0-9_-]{{16,128}}$'
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            SELECT c.command_id INTO v_command FROM dev_eval.daily_glm_refresh_commands c
            WHERE c.idempotency_key=p_idempotency;
            IF v_command IS NOT NULL THEN
                IF NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_commands c WHERE c.command_id=v_command AND c.run_date=p_run_date)
                THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514'; END IF;
                RETURN QUERY SELECT c.* FROM dev_eval.daily_glm_refresh_commands c WHERE c.command_id=v_command;
                RETURN;
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('daily-glm-recollect-v1|' || p_run_date::text,0));
            IF NOT EXISTS(
                SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=p_run_date
                AND r.status='COLLECTION_INCOMPLETE' AND r.call_count=0
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=r.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date=r.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts a WHERE a.run_date=r.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases d WHERE d.run_date=r.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_commands c WHERE c.run_date=r.run_date AND c.status IN ('REQUESTED','CLAIMED'))
                AND (SELECT count(*) FROM dev_eval.daily_glm_refresh_executions e WHERE e.run_date=r.run_date AND e.kind='MANUAL_RECOLLECTION')<3
            ) THEN RAISE EXCEPTION 'daily GLM recollection rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_refresh_commands(run_date,idempotency_key,status)
            VALUES(p_run_date,p_idempotency,'REQUESTED') RETURNING command_id INTO v_command;
            INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status)
            VALUES(v_command,'REQUESTED');
            RETURN QUERY SELECT c.* FROM dev_eval.daily_glm_refresh_commands c WHERE c.command_id=v_command;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.read_daily_glm_recollection_command_v1(p_command uuid)
        RETURNS SETOF dev_eval.daily_glm_refresh_commands LANGUAGE plpgsql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user NOT IN ('{_SERVICE}','{runtime_name}') OR p_command IS NULL
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            RETURN QUERY SELECT c.* FROM dev_eval.daily_glm_refresh_commands c WHERE c.command_id=p_command;
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.claim_daily_glm_recollection_v1(p_lease_seconds integer)
        RETURNS SETOF dev_eval.daily_glm_refresh_commands LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_command dev_eval.daily_glm_refresh_commands%ROWTYPE; v_sequence smallint;
        BEGIN
            IF session_user <> '{_SERVICE}' OR p_lease_seconds NOT BETWEEN 15 AND 300
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            SELECT c.* INTO v_command FROM dev_eval.daily_glm_refresh_commands c
            WHERE c.status='REQUESTED' OR (c.status='CLAIMED' AND c.lease_expires_at<=CURRENT_TIMESTAMP)
            ORDER BY c.requested_at FOR UPDATE SKIP LOCKED LIMIT 1;
            IF NOT FOUND THEN RETURN; END IF;
            IF v_command.status='CLAIMED' THEN
                IF EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=v_command.run_date
                    AND r.status='RUNNING' AND r.call_count=0)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=v_command.run_date)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date=v_command.run_date)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts a WHERE a.run_date=v_command.run_date)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases d WHERE d.run_date=v_command.run_date) THEN
                    UPDATE dev_eval.daily_glm_refresh_commands SET claimed_at=CURRENT_TIMESTAMP,
                        lease_expires_at=CURRENT_TIMESTAMP+pg_catalog.make_interval(secs=>p_lease_seconds)
                    WHERE command_id=v_command.command_id;
                    INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status,safe_reason)
                    VALUES(v_command.command_id,'CLAIMED','LEASE_RECLAIMED');
                    RETURN QUERY SELECT c.* FROM dev_eval.daily_glm_refresh_commands c WHERE c.command_id=v_command.command_id;
                    RETURN;
                END IF;
            ELSE
                SELECT count(*)::smallint+1 INTO v_sequence FROM dev_eval.daily_glm_refresh_executions e
                WHERE e.run_date=v_command.run_date AND e.kind='MANUAL_RECOLLECTION';
                IF v_sequence<=3 AND EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs r
                    WHERE r.run_date=v_command.run_date AND r.status='COLLECTION_INCOMPLETE' AND r.call_count=0)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=v_command.run_date)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date=v_command.run_date)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts a WHERE a.run_date=v_command.run_date)
                   AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases d WHERE d.run_date=v_command.run_date) THEN
                    UPDATE dev_eval.daily_glm_refresh_commands SET status='CLAIMED',execution_sequence=v_sequence,
                        claimed_at=CURRENT_TIMESTAMP,
                        lease_expires_at=CURRENT_TIMESTAMP+pg_catalog.make_interval(secs=>p_lease_seconds)
                    WHERE command_id=v_command.command_id;
                    UPDATE dev_eval.daily_glm_refresh_runs SET status='RUNNING',snapshot_sha256=NULL,
                        changed_count=0,failed_count=0,call_count=0,active_release_sha256=NULL,
                        safe_reason=NULL,started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,finished_at=NULL
                    WHERE run_date=v_command.run_date;
                    INSERT INTO dev_eval.daily_glm_refresh_executions(
                        run_date,execution_sequence,kind,command_id,status,started_at,updated_at
                    ) VALUES(v_command.run_date,v_sequence,'MANUAL_RECOLLECTION',v_command.command_id,
                        'RUNNING',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
                    INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status)
                    VALUES(v_command.command_id,'CLAIMED');
                    RETURN QUERY SELECT c.* FROM dev_eval.daily_glm_refresh_commands c WHERE c.command_id=v_command.command_id;
                    RETURN;
                END IF;
            END IF;
            IF v_command.status='CLAIMED' THEN
                UPDATE dev_eval.daily_glm_refresh_runs SET status='INTERRUPTED',
                    safe_reason='PROCESS_INTERRUPTED_UNKNOWN_OUTCOME',updated_at=CURRENT_TIMESTAMP,
                    finished_at=CURRENT_TIMESTAMP WHERE run_date=v_command.run_date AND status='RUNNING';
            END IF;
            UPDATE dev_eval.daily_glm_refresh_commands SET status='REJECTED',safe_reason='RECOLLECTION_STATE_CHANGED',
                lease_expires_at=NULL,finished_at=CURRENT_TIMESTAMP WHERE command_id=v_command.command_id;
            INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status,safe_reason)
            VALUES(v_command.command_id,'REJECTED','RECOLLECTION_STATE_CHANGED');
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.record_daily_glm_collection_failure_v1(
            p_run_date date,p_place text,p_operation text,p_category text,p_code text
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_execution smallint;
        BEGIN
            IF session_user <> '{_SERVICE}' OR p_place !~ '^public:gyeongju:[0-9a-f]{{64}}$'
               OR p_operation NOT IN ('detailCommon2','detailIntro2')
               OR p_category !~ '^[A-Z0-9_]{{1,80}}$' OR p_code !~ '^[A-Z0-9_]{{1,80}}$'
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            SELECT max(e.execution_sequence) INTO v_execution FROM dev_eval.daily_glm_refresh_executions e
            WHERE e.run_date=p_run_date AND e.status='RUNNING';
            IF v_execution IS NULL THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_collection_failures(
                run_date,execution_sequence,place_id,operation,failure_category,failure_code
            ) VALUES(p_run_date,v_execution,p_place,p_operation,p_category,p_code);
        END $function$
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.complete_daily_glm_recollection_v1(
            p_command uuid,p_status text,p_reason text
        ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_updated integer;
        BEGIN
            IF session_user <> '{_SERVICE}' OR p_status NOT IN ('SUCCEEDED','FAILED','REJECTED')
               OR (p_reason IS NOT NULL AND p_reason !~ '^[A-Z0-9_]{{1,80}}$')
            THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='42501'; END IF;
            UPDATE dev_eval.daily_glm_refresh_commands c SET status=p_status,safe_reason=p_reason,
                lease_expires_at=NULL,finished_at=CURRENT_TIMESTAMP
            WHERE c.command_id=p_command AND c.status='CLAIMED'
              AND EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_executions e
                WHERE e.command_id=c.command_id AND e.status<>'RUNNING');
            GET DIAGNOSTICS v_updated=ROW_COUNT;
            IF v_updated<>1 THEN RAISE EXCEPTION 'daily GLM operation rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status,safe_reason)
            VALUES(p_command,p_status,p_reason);
        END $function$
        """
    )

    runtime_functions = {
        "dev_eval.read_daily_glm_operations_overview_v1()",
        "dev_eval.read_daily_glm_execution_history_v1(integer)",
        "dev_eval.read_daily_glm_execution_v1(date,integer)",
        "dev_eval.read_daily_glm_collection_failures_v1(date,integer)",
        "dev_eval.read_daily_glm_attempts_v1(date,integer)",
        "dev_eval.request_daily_glm_recollection_v1(date,text)",
        "dev_eval.read_daily_glm_recollection_command_v1(uuid)",
    }
    for identity in _NEW_FUNCTIONS:
        _secure(identity, runtime=runtime_name, runtime_access=identity in runtime_functions)


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER bind_daily_glm_attempt_execution_v1 "
        "ON dev_eval.daily_glm_attempts"
    )
    op.execute(
        "DROP TRIGGER sync_daily_glm_execution_v1 "
        "ON dev_eval.daily_glm_refresh_runs"
    )
    op.execute("DROP FUNCTION dev_eval.bind_daily_glm_attempt_execution_v1()")
    op.execute("DROP FUNCTION dev_eval.sync_daily_glm_execution_v1()")
    for identity in reversed(_NEW_FUNCTIONS):
        op.execute(f"DROP FUNCTION {identity}")
    op.execute("ALTER TABLE dev_eval.daily_glm_attempts DROP COLUMN execution_sequence")
    for table in (
        "daily_glm_refresh_command_events",
        "daily_glm_collection_failures",
        "daily_glm_refresh_executions",
        "daily_glm_refresh_commands",
    ):
        op.execute(f"DROP TABLE dev_eval.{table}")
