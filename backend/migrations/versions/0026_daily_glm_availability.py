"""Fence daily availability writers and preserve historical execution lineage."""

# ruff: noqa: E501

from __future__ import annotations

import os
import re

from alembic import op

revision = "0026_daily_glm_availability"
down_revision = "0025_daily_glm_operations"
branch_labels = None
depends_on = None

_OWNER = "itda_daily_glm_refresh_write_authority"
_SERVICE = "itda_daily_glm_refresh_service"
_AUTHORITY = "060c06e8aac3f786413b6298e58b6fcf43638fa5e351d5aabab064069ec7959c"
_V1_AUTHORITY = "e4f8d78e763617697ed926764d44c14e7672bc48bb91eb4a6513cc70adb41f6f"
_MEMBERSHIP = "cdd573f635259b4ac35becdcecdc72f00795cb768d21a003ca0e30fbb9b501f9"
_PROMPT = "483fd6088036eaeb34a4598c3e856eca9429cd1bac182bb144a31c6517fce87b"
_OLD_WRITERS = (
    "claim_daily_glm_refresh_v1(date,text)",
    "store_daily_glm_snapshot_v1(date,text,text,text,jsonb)",
    "store_daily_glm_scoring_plan_v1(date,text,text,jsonb)",
    "reserve_daily_glm_call_v1(date,text,text,text,integer)",
    "finish_daily_glm_attempt_v1(date,text,integer,text,text,text)",
    "publish_daily_scored_release_v2(date,text,text,jsonb)",
    "activate_daily_scored_release_v2(date,text,text)",
    "finish_daily_glm_refresh_v1(date,text,integer,integer,text)",
    "interrupt_daily_glm_refresh_v1(date)",
    "purge_daily_glm_refresh_v1(date)",
    "claim_daily_glm_recollection_v1(integer)",
    "record_daily_glm_collection_failure_v1(date,text,text,text,text)",
    "complete_daily_glm_recollection_v1(uuid,text,text)",
)


def _runtime() -> str:
    value = op.get_context().config.attributes.get("runtime_role")
    if value is None:
        value = os.environ.get("ITDA_RUNTIME_ROLE")
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        raise RuntimeError("daily availability runtime role rejected")
    return value


def _function(
    name: str,
    args: str,
    returns: str,
    body: str,
    *,
    runtime: str,
    read: bool = False,
    helper: bool = False,
    stable: bool = False,
) -> None:
    guard = (
        f"IF session_user NOT IN ('{_SERVICE}','{runtime}') THEN"
        if read
        else f"IF session_user <> '{_SERVICE}' THEN"
    )
    # 모든 외부 진입점은 원래 로그인 역할을 검증한다.
    if not helper:
        body = body.replace(
            "BEGIN",
            "BEGIN\n"
            + guard
            + " RAISE EXCEPTION 'daily availability rejected' USING ERRCODE='42501'; END IF;",
            1,
        )
    op.execute(
        f"CREATE FUNCTION dev_eval.{name}({args}) RETURNS {returns} LANGUAGE plpgsql "
        f"{'STABLE ' if stable else ''}SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn${body}$fn$"
    )
    argtypes = ",".join(arg.strip().split()[-1] for arg in args.split(",") if arg.strip())
    identity = f"dev_eval.{name}({argtypes})"
    op.execute(f"ALTER FUNCTION {identity} OWNER TO {_OWNER}")
    for role in ("PUBLIC", _SERVICE, f'"{runtime}"'):
        op.execute(f"REVOKE ALL ON FUNCTION {identity} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_OWNER}")
    if not helper:
        op.execute(f"GRANT EXECUTE ON FUNCTION {identity} TO {_SERVICE}")
        if read:
            op.execute(f'GRANT EXECUTE ON FUNCTION {identity} TO "{runtime}"')


def upgrade() -> None:
    runtime = _runtime()
    for identity in _OLD_WRITERS:
        op.execute(f'REVOKE ALL ON FUNCTION dev_eval.{identity} FROM PUBLIC,{_SERVICE},"{runtime}"')
    op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb) TO {_OWNER}")
    for table in ("daily_glm_refresh_runs", "daily_glm_refresh_executions"):
        op.execute(
            f"ALTER TABLE dev_eval.{table} ADD COLUMN available_count integer CHECK(available_count BETWEEN 0 AND 100), ADD COLUMN information_unavailable_count integer CHECK(information_unavailable_count BETWEEN 0 AND 100), ADD COLUMN event_ended_count integer CHECK(event_ended_count BETWEEN 0 AND 100)"
        )
        op.execute(
            f"ALTER TABLE dev_eval.{table} ADD CONSTRAINT {table}_availability_complete CHECK ((available_count IS NULL AND information_unavailable_count IS NULL AND event_ended_count IS NULL) OR (available_count IS NOT NULL AND information_unavailable_count IS NOT NULL AND event_ended_count IS NOT NULL AND available_count+information_unavailable_count+event_ended_count=100))"
        )
    op.execute(
        "ALTER TABLE dev_eval.daily_glm_refresh_executions ADD COLUMN authority_sha256 text CHECK(authority_sha256 ~ '^[0-9a-f]{64}$'), ADD COLUMN snapshot_sha256 text CHECK(snapshot_sha256 ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        f"UPDATE dev_eval.daily_glm_refresh_executions SET authority_sha256='{_V1_AUTHORITY}'"
    )
    # 과거 완료 snapshot이 실제 속한 마지막 실행에만 확인 가능한 집계를 채운다.
    op.execute("""
        UPDATE dev_eval.daily_glm_refresh_runs r SET available_count=100,
            information_unavailable_count=0,event_ended_count=0
        FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=r.run_date
            AND s.snapshot_sha256=r.snapshot_sha256
            AND s.payload->>'schema_version'='mvp-daily-scoring-input-snapshot.v1'
            AND jsonb_array_length(s.payload->'places')=100;
        UPDATE dev_eval.daily_glm_refresh_executions e SET snapshot_sha256=r.snapshot_sha256,
            available_count=r.available_count,information_unavailable_count=r.information_unavailable_count,
            event_ended_count=r.event_ended_count
        FROM dev_eval.daily_glm_refresh_runs r WHERE e.run_date=r.run_date AND r.available_count=100
            AND e.execution_sequence=(SELECT max(x.execution_sequence) FROM dev_eval.daily_glm_refresh_executions x WHERE x.run_date=e.run_date);
    """)
    op.execute(f"""
        CREATE OR REPLACE FUNCTION dev_eval.sync_daily_glm_execution_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN
            IF TG_OP='INSERT' THEN
                INSERT INTO dev_eval.daily_glm_refresh_executions(run_date,execution_sequence,kind,status,started_at,updated_at,authority_sha256)
                VALUES(NEW.run_date,0,'SCHEDULED',NEW.status,NEW.started_at,NEW.updated_at,NEW.authority_sha256);
            ELSE
                UPDATE dev_eval.daily_glm_refresh_executions SET status=NEW.status,
                    changed_count=NEW.changed_count,failed_count=NEW.failed_count,call_count=NEW.call_count,
                    active_release_sha256=NEW.active_release_sha256,safe_reason=NEW.safe_reason,
                    updated_at=NEW.updated_at,finished_at=NEW.finished_at,
                    snapshot_sha256=NEW.snapshot_sha256,available_count=NEW.available_count,
                    information_unavailable_count=NEW.information_unavailable_count,event_ended_count=NEW.event_ended_count
                WHERE run_date=NEW.run_date AND authority_sha256=NEW.authority_sha256 AND status='RUNNING'
                    AND execution_sequence=(SELECT max(e.execution_sequence) FROM dev_eval.daily_glm_refresh_executions e WHERE e.run_date=NEW.run_date AND e.status='RUNNING');
            END IF;
            RETURN NEW;
        END $fn$;
        ALTER FUNCTION dev_eval.sync_daily_glm_execution_v1() OWNER TO {_OWNER};
        REVOKE ALL ON FUNCTION dev_eval.sync_daily_glm_execution_v1() FROM PUBLIC,{_SERVICE},"{runtime}";
    """)
    _function(
        "daily_availability_hash_v2",
        "p_value jsonb",
        "text",
        """
        BEGIN RETURN encode(sha256(convert_to(dev_eval.canonical_jsonb_compact_v2(p_value),'UTF8')),'hex'); END
    """,
        runtime=runtime,
        helper=True,
        stable=True,
    )
    _function(
        "require_daily_availability_run_v2",
        "p_date date",
        "void",
        f"""
        BEGIN
            PERFORM 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=p_date
                AND r.authority_sha256='{_AUTHORITY}' AND r.status='RUNNING' FOR UPDATE;
            IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_executions e
                WHERE e.run_date=p_date AND e.status='RUNNING' AND e.authority_sha256='{_AUTHORITY}')
            THEN RAISE EXCEPTION 'daily availability run rejected' USING ERRCODE='23514'; END IF;
        END
    """,
        runtime=runtime,
        helper=True,
    )
    _function(
        "claim_daily_glm_refresh_v2",
        "p_date date,p_authority text",
        "boolean",
        f"""
        DECLARE n integer;
        BEGIN
            IF p_date IS NULL OR p_authority IS DISTINCT FROM '{_AUTHORITY}' THEN RAISE EXCEPTION 'daily authority rejected' USING ERRCODE='23514'; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended('daily-glm-refresh-v1|'||p_date::text,0));
            INSERT INTO dev_eval.daily_glm_refresh_runs(run_date,status,authority_sha256)
                VALUES(p_date,'RUNNING',p_authority) ON CONFLICT(run_date) DO NOTHING;
            GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
        END
    """,
        runtime=runtime,
    )
    _function(
        "store_daily_glm_snapshot_v2",
        "p_date date,p_sha text,p_previous text,p_membership text,p_payload jsonb",
        "void",
        f"""
        DECLARE ids jsonb; n integer; latest text;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            IF p_payload IS NULL OR p_payload->>'schema_version' IS DISTINCT FROM 'mvp-daily-scoring-input-snapshot.v2'
                OR p_payload->>'authority_sha256' IS DISTINCT FROM '{_AUTHORITY}'
                OR p_payload->>'run_date' IS DISTINCT FROM p_date::text
                OR p_membership IS DISTINCT FROM '{_MEMBERSHIP}' OR p_payload->>'membership_sha256' IS DISTINCT FROM p_membership
                OR p_payload->>'snapshot_sha256' IS DISTINCT FROM p_sha
                OR p_payload->>'previous_snapshot_sha256' IS DISTINCT FROM p_previous
                OR dev_eval.daily_availability_hash_v2(p_payload-'snapshot_sha256') IS DISTINCT FROM p_sha
                OR jsonb_typeof(p_payload->'places') IS DISTINCT FROM 'array'
                OR jsonb_typeof(p_payload->'excluded') IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'daily snapshot rejected' USING ERRCODE='23514'; END IF;
            SELECT jsonb_agg(x.id ORDER BY x.id COLLATE "C"),count(DISTINCT x.id) INTO ids,n FROM (
                SELECT value->>'place_id' id FROM jsonb_array_elements(p_payload->'places')
                UNION ALL SELECT value->>'place_id' FROM jsonb_array_elements(p_payload->'excluded')
            ) x;
            IF n<>100 OR jsonb_array_length(ids)<>100 OR dev_eval.daily_availability_hash_v2(ids) IS DISTINCT FROM '{_MEMBERSHIP}'
                OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'places') r WHERE
                    r->>'place_id' IS DISTINCT FROM r->'request'->'place'->>'place_id'
                    OR r->>'content_id' IS DISTINCT FROM r->'evidence'->>'provider_source_id'
                    OR r->'evidence'->>'provider' IS DISTINCT FROM 'TOUR_API'
                    OR dev_eval.daily_availability_hash_v2(r-'row_sha256') IS DISTINCT FROM r->>'row_sha256'
                    OR dev_eval.daily_availability_hash_v2((r->'request')-'request_sha256') IS DISTINCT FROM r->'request'->>'request_sha256')
                OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'excluded') r WHERE
                    dev_eval.daily_availability_hash_v2(r-'row_sha256') IS DISTINCT FROM r->>'row_sha256'
                    OR r->>'state' IS NULL OR r->>'state' NOT IN ('INFORMATION_UNAVAILABLE','EVENT_ENDED')
                    OR (r->>'state'='INFORMATION_UNAVAILABLE' AND (r->>'safe_reason' IS DISTINCT FROM 'COMMON_INFORMATION_UNAVAILABLE' OR r->>'event_end_date' IS NOT NULL OR r->>'intro' IS NOT NULL))
                    OR (r->>'state'='EVENT_ENDED' AND (r->>'safe_reason' IS DISTINCT FROM 'OFFICIAL_EVENT_END_DATE_PASSED' OR r->>'content_type_id' IS DISTINCT FROM '15' OR r->>'event_end_date' IS NULL OR (r->>'event_end_date')::date>=p_date OR r->'intro'->>'operation' IS DISTINCT FROM 'detailIntro2'))
                    OR r->'common'->>'operation' IS DISTINCT FROM 'detailCommon2')
            THEN RAISE EXCEPTION 'daily snapshot partition rejected' USING ERRCODE='23514'; END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended('daily-availability-snapshot-chain',0));
            SELECT s.snapshot_sha256 INTO latest FROM dev_eval.daily_glm_input_snapshots s ORDER BY s.run_date DESC LIMIT 1;
            IF latest IS DISTINCT FROM p_previous OR EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date>=p_date)
            THEN RAISE EXCEPTION 'daily snapshot chain rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_input_snapshots(snapshot_sha256,run_date,previous_snapshot_sha256,authority_sha256,membership_sha256,payload)
                VALUES(p_sha,p_date,p_previous,'{_AUTHORITY}',p_membership,p_payload);
            UPDATE dev_eval.daily_glm_refresh_runs SET snapshot_sha256=p_sha,updated_at=CURRENT_TIMESTAMP,
                available_count=jsonb_array_length(p_payload->'places'),
                information_unavailable_count=(SELECT count(*) FROM jsonb_array_elements(p_payload->'excluded') e WHERE e->>'state'='INFORMATION_UNAVAILABLE'),
                event_ended_count=(SELECT count(*) FROM jsonb_array_elements(p_payload->'excluded') e WHERE e->>'state'='EVENT_ENDED') WHERE run_date=p_date;
        END
    """,
        runtime=runtime,
    )
    _function(
        "store_daily_glm_scoring_plan_v2",
        "p_date date,p_sha text,p_snapshot text,p_payload jsonb",
        "void",
        f"""
        DECLARE s jsonb; n integer;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            SELECT payload INTO s FROM dev_eval.daily_glm_input_snapshots WHERE run_date=p_date AND snapshot_sha256=p_snapshot;
            IF s IS NULL OR jsonb_array_length(s->'places')<80 OR p_payload IS NULL
                OR p_payload->>'schema_version' IS DISTINCT FROM 'mvp-daily-incremental-scoring-plan.v2'
                OR p_payload->>'authority_sha256' IS DISTINCT FROM '{_AUTHORITY}'
                OR p_payload->>'snapshot_sha256' IS DISTINCT FROM p_snapshot OR p_payload->>'run_date' IS DISTINCT FROM p_date::text
                OR p_payload->>'plan_sha256' IS DISTINCT FROM p_sha OR dev_eval.daily_availability_hash_v2(p_payload-'plan_sha256') IS DISTINCT FROM p_sha
                OR p_payload->>'endpoint' IS DISTINCT FROM 'https://api.z.ai/api/coding/paas/v4/chat/completions'
                OR p_payload->>'model' IS DISTINCT FROM 'glm-5.3-flash' OR p_payload->>'prompt_sha256' IS DISTINCT FROM '{_PROMPT}'
                OR p_payload->>'maximum_calls' IS DISTINCT FROM '200' OR p_payload->>'concurrency' IS DISTINCT FROM '1'
                OR p_payload->>'retry_limit_per_place' IS DISTINCT FROM '1' OR p_payload->>'fallback' IS DISTINCT FROM 'false'
                OR p_payload->>'pay_as_you_go_fallback' IS DISTINCT FROM 'false'
                OR jsonb_typeof(p_payload->'scoring_place_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(p_payload->'request_sha256') IS DISTINCT FROM 'array'
            THEN RAISE EXCEPTION 'daily plan rejected' USING ERRCODE='23514'; END IF;
            n:=jsonb_array_length(p_payload->'scoring_place_ids');
            IF n NOT BETWEEN 1 AND 100 OR n<>jsonb_array_length(p_payload->'request_sha256')
                OR p_payload->>'first_pass_count' IS DISTINCT FROM n::text
                OR n<>(SELECT count(DISTINCT value) FROM jsonb_array_elements_text(p_payload->'scoring_place_ids'))
                OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(p_payload->'scoring_place_ids') WITH ORDINALITY i(id,num)
                    JOIN jsonb_array_elements_text(p_payload->'request_sha256') WITH ORDINALITY h(sha,num) USING(num)
                    WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s->'places') r WHERE r->>'place_id'=i.id AND r->'request'->>'request_sha256'=h.sha))
            THEN RAISE EXCEPTION 'daily plan targets rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_scoring_plans(plan_sha256,run_date,snapshot_sha256,payload) VALUES(p_sha,p_date,p_snapshot,p_payload);
        END
    """,
        runtime=runtime,
    )
    _function(
        "reserve_daily_glm_call_v2",
        "p_date date,p_plan text,p_place text,p_request text,p_attempt integer",
        "integer",
        """
        DECLARE n integer;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            IF p_attempt IS NULL OR p_attempt NOT IN (1,2) OR p_place IS NULL OR p_request IS NULL OR NOT EXISTS(
                SELECT 1 FROM dev_eval.daily_glm_scoring_plans p,
                    jsonb_array_elements_text(p.payload->'scoring_place_ids') WITH ORDINALITY i(id,num),
                    jsonb_array_elements_text(p.payload->'request_sha256') WITH ORDINALITY h(sha,num)
                WHERE p.run_date=p_date AND p.plan_sha256=p_plan AND i.num=h.num AND i.id=p_place AND h.sha=p_request)
                OR EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts WHERE run_date=p_date AND status='STARTED')
                OR (p_attempt=2 AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts WHERE run_date=p_date AND place_id=p_place AND request_sha256=p_request AND plan_sha256=p_plan AND attempt_number=1 AND status='FAILED'))
            THEN RAISE EXCEPTION 'daily reservation rejected' USING ERRCODE='23514'; END IF;
            UPDATE dev_eval.daily_glm_refresh_runs SET call_count=call_count+1,updated_at=CURRENT_TIMESTAMP WHERE run_date=p_date AND call_count<200 RETURNING call_count INTO n;
            IF n IS NULL THEN RAISE EXCEPTION 'daily budget exhausted' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_attempts(run_date,place_id,request_sha256,plan_sha256,attempt_number,status) VALUES(p_date,p_place,p_request,p_plan,p_attempt,'STARTED');
            RETURN n;
        END
    """,
        runtime=runtime,
    )
    _function(
        "finish_daily_glm_attempt_v2",
        "p_date date,p_place text,p_attempt integer,p_status text,p_reason text,p_result text",
        "void",
        """
        DECLARE n integer;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            IF p_status IS NULL OR p_status NOT IN ('SUCCEEDED','FAILED') OR
                (p_status='SUCCEEDED' AND (p_reason IS NOT NULL OR p_result IS NULL OR p_result !~ '^[0-9a-f]{64}$')) OR
                (p_status='FAILED' AND (p_result IS NOT NULL OR p_reason IS NULL OR p_reason !~ '^[A-Z0-9_]{1,80}$'))
            THEN RAISE EXCEPTION 'daily attempt rejected' USING ERRCODE='23514'; END IF;
            UPDATE dev_eval.daily_glm_attempts SET status=p_status,safe_reason=p_reason,result_sha256=p_result,finished_at=CURRENT_TIMESTAMP WHERE run_date=p_date AND place_id=p_place AND attempt_number=p_attempt AND status='STARTED';
            GET DIAGNOSTICS n=ROW_COUNT;
            IF n<>1 THEN RAISE EXCEPTION 'daily attempt rejected' USING ERRCODE='23514'; END IF;
        END
    """,
        runtime=runtime,
    )
    _publish_functions(runtime)
    _lifecycle_functions(runtime)
    _reader_functions(runtime)


def _publish_functions(runtime: str) -> None:
    _function(
        "publish_daily_scored_release_v3",
        "p_date date,p_sha text,p_previous text,p_payload jsonb",
        "void",
        f"""
        DECLARE s jsonb; ids jsonb; n integer;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            SELECT payload INTO s FROM dev_eval.daily_glm_input_snapshots WHERE run_date=p_date AND snapshot_sha256=p_payload->>'snapshot_sha256';
            IF s IS NULL OR p_payload IS NULL OR p_payload->>'schema_version' IS DISTINCT FROM 'mvp-scored-release.v3'
                OR p_payload->>'authority_sha256' IS DISTINCT FROM '{_AUTHORITY}' OR p_payload->>'authority_membership_sha256' IS DISTINCT FROM '{_MEMBERSHIP}'
                OR p_payload->>'daily_run_date' IS DISTINCT FROM p_date::text OR p_payload->>'previous_release_sha256' IS DISTINCT FROM p_previous
                OR p_payload->>'release_sha256' IS DISTINCT FROM p_sha OR dev_eval.daily_availability_hash_v2(p_payload-'release_sha256') IS DISTINCT FROM p_sha
                OR p_payload->'excluded' IS DISTINCT FROM s->'excluded'
                OR jsonb_typeof(p_payload->'profile_entries') IS DISTINCT FROM 'array' OR jsonb_typeof(p_payload->'failed') IS DISTINCT FROM 'array'
                OR EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts WHERE run_date=p_date AND status='STARTED')
            THEN RAISE EXCEPTION 'daily publication rejected' USING ERRCODE='23514'; END IF;
            n:=jsonb_array_length(p_payload->'profile_entries');
            IF n NOT BETWEEN 80 AND 100 OR p_payload->>'published_count' IS DISTINCT FROM n::text
            THEN RAISE EXCEPTION 'daily profile gate rejected' USING ERRCODE='23514'; END IF;
            SELECT jsonb_agg(x.id ORDER BY x.id COLLATE "C"),count(DISTINCT x.id) INTO ids,n FROM (
                SELECT r->'profile'->>'place_id' id FROM jsonb_array_elements(p_payload->'profile_entries') r
                UNION ALL SELECT r->>'place_id' FROM jsonb_array_elements(p_payload->'failed') r
                UNION ALL SELECT r->>'place_id' FROM jsonb_array_elements(p_payload->'excluded') r
            ) x;
            IF n<>100 OR jsonb_array_length(ids)<>100 OR dev_eval.daily_availability_hash_v2(ids) IS DISTINCT FROM '{_MEMBERSHIP}'
            THEN RAISE EXCEPTION 'daily publication partition rejected' USING ERRCODE='23514'; END IF;
            IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'profile_entries') e WHERE
                dev_eval.daily_availability_hash_v2(e-'entry_sha256') IS DISTINCT FROM e->>'entry_sha256'
                OR e->'lineage'->>'result_sha256' IS DISTINCT FROM e->'profile'->'scoring_result'->>'result_sha256'
                OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s->'places') r WHERE r->>'place_id'=e->'profile'->>'place_id'
                    AND r->'request'->>'request_sha256'=COALESCE(e->'baseline_observation'->>'request_sha256',e->'lineage'->>'input_request_sha256'))
                OR (e->'lineage'->>'origin'='DAILY_GLM' AND e->'lineage'->>'input_request_sha256' IS DISTINCT FROM e->'profile'->'scoring_result'->>'request_sha256')
                OR NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots z,
                    jsonb_array_elements(z.payload->'places') r
                    WHERE z.snapshot_sha256=e->'lineage'->>'source_snapshot_sha256'
                        AND z.run_date::text=e->'lineage'->>'source_run_date'
                        AND r->>'place_id'=e->'profile'->>'place_id'
                        AND r->'request'->>'request_sha256'=COALESCE(e->'baseline_observation'->>'request_sha256',e->'lineage'->>'input_request_sha256'))
                OR (e->'baseline_observation' IS NOT NULL AND e->'baseline_observation'<>'null'::jsonb AND (
                    e->'baseline_observation'->>'snapshot_sha256' IS DISTINCT FROM e->'lineage'->>'source_snapshot_sha256'
                    OR e->'baseline_observation'->>'run_date' IS DISTINCT FROM e->'lineage'->>'source_run_date'))
                OR (e->'lineage'->>'origin'='DAILY_GLM'
                    AND e->'lineage'->>'source_snapshot_sha256'=p_payload->>'snapshot_sha256'
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts a
                        WHERE a.run_date=p_date AND a.place_id=e->'profile'->>'place_id'
                            AND a.request_sha256=e->'lineage'->>'input_request_sha256'
                            AND a.status='SUCCEEDED' AND a.result_sha256=e->'lineage'->>'result_sha256'))
                OR (e->'lineage'->>'source_snapshot_sha256' IS DISTINCT FROM p_payload->>'snapshot_sha256'
                    AND EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases WHERE release_sha256=p_previous)
                    AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases old,
                        jsonb_array_elements(old.payload->'profile_entries') prior
                        WHERE old.release_sha256=p_previous AND prior=e))
            ) OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'failed') f WHERE
                NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s->'places') r WHERE r->>'place_id'=f->>'place_id' AND r->'request'->>'request_sha256'=f->>'input_request_sha256')
                OR NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots z,
                    jsonb_array_elements(z.payload->'places') r WHERE z.snapshot_sha256=f->>'source_snapshot_sha256'
                        AND z.run_date::text=f->>'source_run_date' AND r->>'place_id'=f->>'place_id'
                        AND r->'request'->>'request_sha256'=f->>'input_request_sha256')
                OR (f->>'origin'='DAILY_GLM' AND f->>'source_snapshot_sha256'=p_payload->>'snapshot_sha256'
                    AND (EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts a WHERE a.run_date=p_date AND a.place_id=f->>'place_id' AND a.status='SUCCEEDED')
                        OR (f->>'reason' IS DISTINCT FROM 'REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED' AND NOT EXISTS(
                            SELECT 1 FROM dev_eval.daily_glm_attempts a WHERE a.run_date=p_date AND a.place_id=f->>'place_id'
                                AND a.request_sha256=f->>'input_request_sha256' AND a.status='FAILED')))))
            THEN RAISE EXCEPTION 'daily publication lineage rejected' USING ERRCODE='23514'; END IF;
            IF EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans plan,
                jsonb_array_elements_text(plan.payload->'scoring_place_ids') target
                WHERE plan.run_date=p_date AND NOT (
                    EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'profile_entries') e
                        WHERE e->'profile'->>'place_id'=target AND e->'lineage'->>'origin'='DAILY_GLM'
                            AND e->'lineage'->>'source_snapshot_sha256'=p_payload->>'snapshot_sha256')
                    OR EXISTS(SELECT 1 FROM jsonb_array_elements(p_payload->'failed') f
                        WHERE f->>'place_id'=target AND f->>'origin'='DAILY_GLM'
                            AND f->>'source_snapshot_sha256'=p_payload->>'snapshot_sha256')))
            THEN RAISE EXCEPTION 'daily publication targets rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_scored_releases(release_sha256,previous_release_sha256,run_date,payload) VALUES(p_sha,p_previous,p_date,p_payload);
        END
    """,
        runtime=runtime,
    )
    _function(
        "activate_daily_scored_release_v3",
        "p_date date,p_sha text,p_expected text",
        "void",
        f"""
        DECLARE current_sha text;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            PERFORM pg_advisory_xact_lock(hashtextextended('daily-scored-release-activation',0));
            SELECT release_sha256 INTO current_sha FROM dev_eval.daily_scored_release_active WHERE singleton FOR UPDATE;
            IF (current_sha IS NOT NULL AND current_sha IS DISTINCT FROM p_expected)
                OR (current_sha IS NULL AND EXISTS(SELECT 1 FROM dev_eval.daily_scored_release_activations))
                OR NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases r WHERE r.run_date=p_date AND r.release_sha256=p_sha AND r.previous_release_sha256=p_expected AND r.payload->>'authority_sha256'='{_AUTHORITY}')
            THEN RAISE EXCEPTION 'daily activation rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_scored_release_active(singleton,release_sha256) VALUES(TRUE,p_sha)
                ON CONFLICT(singleton) DO UPDATE SET release_sha256=EXCLUDED.release_sha256,updated_at=CURRENT_TIMESTAMP;
            INSERT INTO dev_eval.daily_scored_release_activations(release_sha256,previous_release_sha256,run_date) VALUES(p_sha,current_sha,p_date);
            UPDATE dev_eval.daily_glm_refresh_runs SET active_release_sha256=p_sha,updated_at=CURRENT_TIMESTAMP WHERE run_date=p_date;
        END
    """,
        runtime=runtime,
    )


def _lifecycle_functions(runtime: str) -> None:
    _function(
        "finish_daily_glm_refresh_v2",
        "p_date date,p_status text,p_changed integer,p_failed integer,p_reason text",
        "void",
        """
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            IF p_status IS NULL OR p_status NOT IN ('BASELINE_RECORDED','NO_CHANGES','COLLECTION_INCOMPLETE','SCORING_FAILED','RELEASE_REJECTED','RELEASE_ACTIVATED')
                OR p_changed IS NULL OR p_changed NOT BETWEEN 0 AND 100 OR p_failed IS NULL OR p_failed NOT BETWEEN 0 AND 100
                OR (p_reason IS NOT NULL AND p_reason !~ '^[A-Z0-9_]{1,80}$')
                OR (p_status='RELEASE_ACTIVATED' AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs WHERE run_date=p_date AND active_release_sha256 IS NOT NULL))
            THEN RAISE EXCEPTION 'daily finish rejected' USING ERRCODE='23514'; END IF;
            UPDATE dev_eval.daily_glm_refresh_runs SET status=p_status,changed_count=p_changed,failed_count=p_failed,safe_reason=p_reason,updated_at=CURRENT_TIMESTAMP,finished_at=CURRENT_TIMESTAMP WHERE run_date=p_date;
        END
    """,
        runtime=runtime,
    )
    _function(
        "interrupt_daily_glm_refresh_v2",
        "p_date date",
        "boolean",
        f"""
        BEGIN
            IF NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs WHERE run_date=p_date AND status='RUNNING' AND authority_sha256='{_AUTHORITY}') THEN RETURN FALSE; END IF;
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            UPDATE dev_eval.daily_glm_refresh_runs SET status='INTERRUPTED',safe_reason='PROCESS_INTERRUPTED_UNKNOWN_OUTCOME',updated_at=CURRENT_TIMESTAMP,finished_at=CURRENT_TIMESTAMP WHERE run_date=p_date;
            RETURN TRUE;
        END
    """,
        runtime=runtime,
    )
    _function(
        "record_daily_glm_collection_failure_v2",
        "p_date date,p_place text,p_operation text,p_category text,p_code text",
        "void",
        """
        DECLARE seq smallint;
        BEGIN
            PERFORM dev_eval.require_daily_availability_run_v2(p_date);
            IF p_place IS NULL OR p_place !~ '^public:gyeongju:[0-9a-f]{64}$' OR p_operation IS NULL OR p_operation NOT IN ('detailCommon2','detailIntro2')
                OR p_category IS NULL OR p_category !~ '^[A-Z0-9_]{1,80}$' OR p_code IS NULL OR p_code !~ '^[A-Z0-9_]{1,80}$'
            THEN RAISE EXCEPTION 'daily failure rejected' USING ERRCODE='23514'; END IF;
            SELECT max(execution_sequence) INTO seq FROM dev_eval.daily_glm_refresh_executions WHERE run_date=p_date AND status='RUNNING';
            INSERT INTO dev_eval.daily_glm_collection_failures(run_date,execution_sequence,place_id,operation,failure_category,failure_code) VALUES(p_date,seq,p_place,p_operation,p_category,p_code);
        END
    """,
        runtime=runtime,
    )
    _function(
        "claim_daily_glm_recollection_v2",
        "p_lease integer",
        "SETOF dev_eval.daily_glm_refresh_commands",
        f"""
        DECLARE c dev_eval.daily_glm_refresh_commands%ROWTYPE; r dev_eval.daily_glm_refresh_runs%ROWTYPE; seq smallint; clean boolean;
        BEGIN
            IF p_lease IS NULL OR p_lease NOT BETWEEN 15 AND 300 THEN RAISE EXCEPTION 'daily lease rejected' USING ERRCODE='23514'; END IF;
            SELECT * INTO c FROM dev_eval.daily_glm_refresh_commands x WHERE x.status='REQUESTED' OR (x.status='CLAIMED' AND x.lease_expires_at<=CURRENT_TIMESTAMP) ORDER BY x.requested_at FOR UPDATE SKIP LOCKED LIMIT 1;
            IF NOT FOUND THEN RETURN; END IF;
            SELECT * INTO r FROM dev_eval.daily_glm_refresh_runs WHERE run_date=c.run_date FOR UPDATE;
            clean:=r.call_count=0 AND r.snapshot_sha256 IS NULL AND r.active_release_sha256 IS NULL
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots WHERE run_date=c.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_scoring_plans WHERE run_date=c.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_attempts WHERE run_date=c.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases WHERE run_date=c.run_date);
            IF c.status='CLAIMED' AND clean AND r.status='RUNNING' AND r.authority_sha256='{_AUTHORITY}'
                AND EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_executions e WHERE e.run_date=c.run_date AND e.execution_sequence=c.execution_sequence AND e.command_id=c.command_id AND e.status='RUNNING' AND e.authority_sha256='{_AUTHORITY}') THEN
                UPDATE dev_eval.daily_glm_refresh_commands SET claimed_at=CURRENT_TIMESTAMP,lease_expires_at=CURRENT_TIMESTAMP+make_interval(secs=>p_lease) WHERE command_id=c.command_id;
                INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status,safe_reason) VALUES(c.command_id,'CLAIMED','LEASE_RECLAIMED');
                RETURN QUERY SELECT x.* FROM dev_eval.daily_glm_refresh_commands x WHERE x.command_id=c.command_id; RETURN;
            ELSIF c.status='REQUESTED' AND clean AND r.status='COLLECTION_INCOMPLETE' AND r.authority_sha256 IN ('{_V1_AUTHORITY}','{_AUTHORITY}') THEN
                SELECT COALESCE(max(execution_sequence),0)+1 INTO seq FROM dev_eval.daily_glm_refresh_executions WHERE run_date=c.run_date;
                IF seq<=3 THEN
                    UPDATE dev_eval.daily_glm_refresh_commands SET status='CLAIMED',execution_sequence=seq,claimed_at=CURRENT_TIMESTAMP,lease_expires_at=CURRENT_TIMESTAMP+make_interval(secs=>p_lease) WHERE command_id=c.command_id;
                    UPDATE dev_eval.daily_glm_refresh_runs SET status='RUNNING',authority_sha256='{_AUTHORITY}',available_count=NULL,information_unavailable_count=NULL,event_ended_count=NULL,
                        changed_count=0,failed_count=0,safe_reason=NULL,started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,finished_at=NULL WHERE run_date=c.run_date;
                    INSERT INTO dev_eval.daily_glm_refresh_executions(run_date,execution_sequence,kind,command_id,status,authority_sha256,started_at,updated_at)
                        VALUES(c.run_date,seq,'MANUAL_RECOLLECTION',c.command_id,'RUNNING','{_AUTHORITY}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
                    INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status) VALUES(c.command_id,'CLAIMED');
                    RETURN QUERY SELECT x.* FROM dev_eval.daily_glm_refresh_commands x WHERE x.command_id=c.command_id; RETURN;
                END IF;
            END IF;
            IF c.status='CLAIMED' THEN
                UPDATE dev_eval.daily_glm_refresh_runs SET status='INTERRUPTED',safe_reason='RECOLLECTION_STATE_CHANGED',updated_at=CURRENT_TIMESTAMP,finished_at=CURRENT_TIMESTAMP WHERE run_date=c.run_date AND status='RUNNING';
            END IF;
            UPDATE dev_eval.daily_glm_refresh_commands SET status='REJECTED',safe_reason='RECOLLECTION_STATE_CHANGED',lease_expires_at=NULL,finished_at=CURRENT_TIMESTAMP WHERE command_id=c.command_id;
            INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status,safe_reason) VALUES(c.command_id,'REJECTED','RECOLLECTION_STATE_CHANGED');
        END
    """,
        runtime=runtime,
    )
    _function(
        "complete_daily_glm_recollection_v2",
        "p_command uuid,p_status text,p_reason text",
        "void",
        f"""
        DECLARE n integer;
        BEGIN
            IF p_command IS NULL OR p_status IS NULL OR p_status NOT IN ('SUCCEEDED','FAILED','REJECTED') OR (p_reason IS NOT NULL AND p_reason !~ '^[A-Z0-9_]{{1,80}}$') THEN RAISE EXCEPTION 'daily command rejected' USING ERRCODE='23514'; END IF;
            UPDATE dev_eval.daily_glm_refresh_commands c SET status=p_status,safe_reason=p_reason,lease_expires_at=NULL,finished_at=CURRENT_TIMESTAMP
                WHERE c.command_id=p_command AND c.status='CLAIMED' AND EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_executions e WHERE e.command_id=c.command_id AND e.status<>'RUNNING' AND e.authority_sha256='{_AUTHORITY}');
            GET DIAGNOSTICS n=ROW_COUNT;
            IF n<>1 THEN RAISE EXCEPTION 'daily command rejected' USING ERRCODE='23514'; END IF;
            INSERT INTO dev_eval.daily_glm_refresh_command_events(command_id,status,safe_reason) VALUES(p_command,p_status,p_reason);
        END
    """,
        runtime=runtime,
    )
    _function(
        "purge_daily_glm_refresh_v2",
        "p_cutoff date",
        "integer",
        """
        DECLARE n integer;
        BEGIN
            IF p_cutoff IS NULL OR p_cutoff>=CURRENT_DATE THEN RAISE EXCEPTION 'daily retention rejected' USING ERRCODE='23514'; END IF;
            DELETE FROM dev_eval.daily_glm_attempts a WHERE a.run_date<p_cutoff AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=a.run_date AND r.status='RUNNING');
            DELETE FROM dev_eval.daily_glm_scoring_plans p WHERE p.run_date<p_cutoff AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=p.run_date AND r.status='RUNNING');
            DELETE FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date<p_cutoff
                AND s.run_date NOT IN (SELECT min(run_date) FROM dev_eval.daily_glm_input_snapshots UNION SELECT max(run_date) FROM dev_eval.daily_glm_input_snapshots)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date=s.run_date AND r.status='RUNNING')
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases r WHERE r.payload->>'snapshot_sha256'=s.snapshot_sha256
                    OR EXISTS(SELECT 1 FROM jsonb_array_elements(r.payload->'profile_entries') e WHERE e->'lineage'->>'source_snapshot_sha256'=s.snapshot_sha256 OR e->'baseline_observation'->>'snapshot_sha256'=s.snapshot_sha256)
                    OR EXISTS(SELECT 1 FROM jsonb_array_elements(r.payload->'failed') f WHERE f->>'source_snapshot_sha256'=s.snapshot_sha256));
            DELETE FROM dev_eval.daily_glm_refresh_runs r WHERE r.run_date<p_cutoff AND r.status<>'RUNNING'
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_input_snapshots s WHERE s.run_date=r.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_scored_releases d WHERE d.run_date=r.run_date)
                AND NOT EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_commands c WHERE c.run_date=r.run_date AND c.status IN ('REQUESTED','CLAIMED'));
            GET DIAGNOSTICS n=ROW_COUNT; RETURN n;
        END
    """,
        runtime=runtime,
    )


def _reader_functions(runtime: str) -> None:
    for name, query in (
        (
            "read_latest_daily_glm_snapshot_v2",
            "SELECT payload FROM dev_eval.daily_glm_input_snapshots ORDER BY run_date DESC LIMIT 1",
        ),
        (
            "read_baseline_daily_glm_snapshot_v2",
            "SELECT payload FROM dev_eval.daily_glm_input_snapshots ORDER BY run_date LIMIT 1",
        ),
    ):
        _function(name, "", "jsonb", f"BEGIN RETURN ({query}); END", runtime=runtime, stable=True)
    _function(
        "read_daily_glm_snapshot_v2",
        "p_sha text",
        "jsonb",
        "BEGIN RETURN (SELECT payload FROM dev_eval.daily_glm_input_snapshots WHERE snapshot_sha256=p_sha); END",
        runtime=runtime,
        stable=True,
    )
    _function(
        "read_active_daily_scored_release_v3",
        "",
        "jsonb",
        "BEGIN RETURN (SELECT r.payload FROM dev_eval.daily_scored_release_active a JOIN dev_eval.daily_scored_releases r USING(release_sha256) WHERE a.singleton); END",
        runtime=runtime,
        read=True,
        stable=True,
    )
    # 과거 reader에는 과거 schema만 반환한다. 새 scheduler보다 먼저 모든 backend를 교체해야 한다.
    op.execute(f"""
        CREATE OR REPLACE FUNCTION dev_eval.read_latest_daily_glm_snapshot_v1() RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN IF session_user<>'{_SERVICE}' THEN RAISE EXCEPTION 'daily read rejected' USING ERRCODE='42501'; END IF;
        RETURN (SELECT payload FROM dev_eval.daily_glm_input_snapshots WHERE payload->>'schema_version'='mvp-daily-scoring-input-snapshot.v1' ORDER BY run_date DESC LIMIT 1); END $fn$;
        CREATE OR REPLACE FUNCTION dev_eval.read_active_daily_scored_release_v2() RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN IF session_user NOT IN ('{_SERVICE}','{runtime}') THEN RAISE EXCEPTION 'daily read rejected' USING ERRCODE='42501'; END IF;
        RETURN (SELECT r.payload FROM dev_eval.daily_scored_release_active a JOIN dev_eval.daily_scored_releases r USING(release_sha256) WHERE a.singleton AND r.payload->>'schema_version'='mvp-scored-release.v2'); END $fn$;
    """)
    _function(
        "read_daily_glm_execution_availability_v2",
        "p_date date,p_sequence integer",
        "jsonb",
        """
        DECLARE result jsonb; s jsonb;
        BEGIN
            SELECT jsonb_build_object('authority_sha256',e.authority_sha256,'snapshot_sha256',e.snapshot_sha256,
                'available_count',e.available_count,'information_unavailable_count',e.information_unavailable_count,'event_ended_count',e.event_ended_count),snapshot.payload
                INTO result,s FROM dev_eval.daily_glm_refresh_executions e LEFT JOIN dev_eval.daily_glm_input_snapshots snapshot ON snapshot.snapshot_sha256=e.snapshot_sha256
                WHERE e.run_date=p_date AND e.execution_sequence=p_sequence;
            IF result IS NULL THEN RETURN NULL; END IF;
            RETURN result||jsonb_build_object('excluded', CASE WHEN s IS NULL THEN NULL
                WHEN s->>'schema_version'='mvp-daily-scoring-input-snapshot.v1' THEN '[]'::jsonb
                WHEN s->>'schema_version'='mvp-daily-scoring-input-snapshot.v2' THEN COALESCE((SELECT jsonb_agg(jsonb_build_object(
                    'place_id',e->>'place_id','content_id',e->>'content_id','state',e->>'state','safe_reason',e->>'safe_reason','event_end_date',e->>'event_end_date') ORDER BY e->>'place_id') FROM jsonb_array_elements(s->'excluded') e),'[]'::jsonb)
                ELSE NULL END);
        END
    """,
        runtime=runtime,
        read=True,
        stable=True,
    )


def downgrade() -> None:
    runtime = _runtime()
    # 새 정책을 사용한 이력은 구 writer에 넘기거나 지우지 않는다.
    op.execute(f"""
        DO $guard$ BEGIN
            IF EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_runs WHERE authority_sha256='{_AUTHORITY}')
                OR EXISTS(SELECT 1 FROM dev_eval.daily_glm_refresh_executions WHERE authority_sha256='{_AUTHORITY}')
            THEN RAISE EXCEPTION 'daily availability policy downgrade requires an explicit data migration'; END IF;
        END $guard$;
    """)
    for identity in (
        "read_daily_glm_execution_availability_v2(date,integer)",
        "read_active_daily_scored_release_v3()",
        "read_daily_glm_snapshot_v2(text)",
        "read_baseline_daily_glm_snapshot_v2()",
        "read_latest_daily_glm_snapshot_v2()",
        "purge_daily_glm_refresh_v2(date)",
        "complete_daily_glm_recollection_v2(uuid,text,text)",
        "claim_daily_glm_recollection_v2(integer)",
        "record_daily_glm_collection_failure_v2(date,text,text,text,text)",
        "interrupt_daily_glm_refresh_v2(date)",
        "finish_daily_glm_refresh_v2(date,text,integer,integer,text)",
        "activate_daily_scored_release_v3(date,text,text)",
        "publish_daily_scored_release_v3(date,text,text,jsonb)",
        "finish_daily_glm_attempt_v2(date,text,integer,text,text,text)",
        "reserve_daily_glm_call_v2(date,text,text,text,integer)",
        "store_daily_glm_scoring_plan_v2(date,text,text,jsonb)",
        "store_daily_glm_snapshot_v2(date,text,text,text,jsonb)",
        "claim_daily_glm_refresh_v2(date,text)",
        "require_daily_availability_run_v2(date)",
        "daily_availability_hash_v2(jsonb)",
    ):
        op.execute(f"DROP FUNCTION dev_eval.{identity}")
    op.execute(f"""
        CREATE OR REPLACE FUNCTION dev_eval.sync_daily_glm_execution_v1()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN
            IF TG_OP='INSERT' THEN
                INSERT INTO dev_eval.daily_glm_refresh_executions(run_date,execution_sequence,kind,status,started_at,updated_at)
                VALUES(NEW.run_date,0,'SCHEDULED',NEW.status,NEW.started_at,NEW.updated_at);
            ELSE
                UPDATE dev_eval.daily_glm_refresh_executions SET status=NEW.status,
                    changed_count=NEW.changed_count,failed_count=NEW.failed_count,call_count=NEW.call_count,
                    active_release_sha256=NEW.active_release_sha256,safe_reason=NEW.safe_reason,
                    updated_at=NEW.updated_at,finished_at=NEW.finished_at
                WHERE run_date=NEW.run_date AND execution_sequence=(SELECT max(e.execution_sequence)
                    FROM dev_eval.daily_glm_refresh_executions e WHERE e.run_date=NEW.run_date AND e.status='RUNNING');
            END IF;
            RETURN NEW;
        END $fn$;
        CREATE OR REPLACE FUNCTION dev_eval.read_latest_daily_glm_snapshot_v1() RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN IF session_user<>'{_SERVICE}' THEN RAISE EXCEPTION 'daily read rejected' USING ERRCODE='42501'; END IF;
        RETURN (SELECT payload FROM dev_eval.daily_glm_input_snapshots ORDER BY run_date DESC LIMIT 1); END $fn$;
        CREATE OR REPLACE FUNCTION dev_eval.read_active_daily_scored_release_v2() RETURNS jsonb
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN IF session_user NOT IN ('{_SERVICE}','{runtime}') THEN RAISE EXCEPTION 'daily read rejected' USING ERRCODE='42501'; END IF;
        RETURN (SELECT r.payload FROM dev_eval.daily_scored_release_active a JOIN dev_eval.daily_scored_releases r USING(release_sha256) WHERE a.singleton); END $fn$;
    """)
    for table in ("daily_glm_refresh_runs", "daily_glm_refresh_executions"):
        op.execute(
            f"ALTER TABLE dev_eval.{table} DROP COLUMN available_count, DROP COLUMN information_unavailable_count, DROP COLUMN event_ended_count"
        )
    op.execute(
        "ALTER TABLE dev_eval.daily_glm_refresh_executions DROP COLUMN authority_sha256, DROP COLUMN snapshot_sha256"
    )
    for identity in _OLD_WRITERS:
        op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{identity} TO {_SERVICE}")
    op.execute(
        f"REVOKE EXECUTE ON FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb) FROM {_OWNER}"
    )
