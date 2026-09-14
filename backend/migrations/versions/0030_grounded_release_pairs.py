"""Stage complete grounded pairs and atomically promote only measured gate evidence."""

# SQL authority statements are kept together for review.
# ruff: noqa: E501

from __future__ import annotations

import os
import re

from alembic import op
from sqlalchemy import text

revision = "0030_grounded_release_pairs"
down_revision = "0029_photo_mood_authority"
branch_labels = None
depends_on = None

_OWNER = "itda_daily_glm_refresh_write_authority"
_SERVICE = "itda_daily_glm_refresh_service"
_TABLES = (
    "grounded_release_candidates",
    "grounded_promotion_reports",
    "grounded_promotion_gates",
    "grounded_release_active",
    "grounded_release_promotions",
)
_FUNCTIONS = (
    "stage_grounded_release_candidate_v1(jsonb)",
    "store_grounded_promotion_report_v1(jsonb)",
    "promote_grounded_release_pair_v1(jsonb,text)",
)


def _hash(value: str) -> str:
    return f"encode(sha256(convert_to(dev_eval.canonical_jsonb_compact_v2({value}),'UTF8')),'hex')"


def upgrade() -> None:
    cfg = op.get_context().config.attributes
    runtime = cfg.get("runtime_role") or os.environ.get("ITDA_RUNTIME_ROLE")
    if not isinstance(runtime, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", runtime) is None:
        raise ValueError("grounded runtime role invalid")
    migrator = op.get_bind().execute(text("SELECT current_user")).scalar_one()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", migrator) is None:
        raise ValueError("grounded migration role invalid")
    guard = f"""
        IF session_user NOT IN ('{_SERVICE}','{migrator}') THEN
            RAISE EXCEPTION 'grounded mutation rejected' USING ERRCODE='42501';
        END IF;
    """
    op.execute("""
        CREATE TABLE app.grounded_release_candidates(
            candidate_sha256 text PRIMARY KEY CHECK(candidate_sha256 ~ '^[0-9a-f]{64}$'),
            raw_release_sha256 text NOT NULL CHECK(raw_release_sha256 ~ '^[0-9a-f]{64}$'),
            source_release_sha256 text NOT NULL CHECK(source_release_sha256 ~ '^[0-9a-f]{64}$'),
            payload jsonb NOT NULL,
            created_at timestamptz NOT NULL,
            staged_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE app.grounded_promotion_reports(
            report_sha256 text PRIMARY KEY CHECK(report_sha256 ~ '^[0-9a-f]{64}$'),
            candidate_sha256 text NOT NULL REFERENCES app.grounded_release_candidates(candidate_sha256),
            kind text NOT NULL CHECK(kind IN ('SOURCE_ABLATION','AXIS_COMPARISON','API_UI')),
            config_sha256 text NOT NULL CHECK(config_sha256 ~ '^[0-9a-f]{64}$'),
            payload jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE app.grounded_promotion_gates(
            gate_sha256 text PRIMARY KEY CHECK(gate_sha256 ~ '^[0-9a-f]{64}$'),
            candidate_sha256 text NOT NULL REFERENCES app.grounded_release_candidates(candidate_sha256),
            config_sha256 text NOT NULL CHECK(config_sha256 ~ '^[0-9a-f]{64}$'),
            payload jsonb NOT NULL,
            verified_at timestamptz NOT NULL
        );
        CREATE TABLE app.grounded_release_active(
            singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
            candidate_sha256 text NOT NULL REFERENCES app.grounded_release_candidates(candidate_sha256),
            gate_sha256 text NOT NULL REFERENCES app.grounded_promotion_gates(gate_sha256),
            generation bigint NOT NULL CHECK(generation>0),
            activated_at timestamptz NOT NULL
        );
        CREATE TABLE app.grounded_release_promotions(
            generation bigint PRIMARY KEY,
            candidate_sha256 text NOT NULL REFERENCES app.grounded_release_candidates(candidate_sha256),
            gate_sha256 text NOT NULL REFERENCES app.grounded_promotion_gates(gate_sha256),
            previous_candidate_sha256 text REFERENCES app.grounded_release_candidates(candidate_sha256),
            activated_at timestamptz NOT NULL
        );
    """)
    for table in _TABLES:
        op.execute(f"ALTER TABLE app.{table} OWNER TO {_OWNER}")
        op.execute(f'REVOKE ALL ON app.{table} FROM PUBLIC,"{runtime}",{_SERVICE}')
        op.execute(f'GRANT SELECT ON app.{table} TO "{runtime}",{_SERVICE}')
    op.execute(f"GRANT USAGE ON SCHEMA app TO {_OWNER},{_SERVICE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb) TO {_OWNER}")
    op.execute("""
        CREATE FUNCTION app.reject_grounded_pair_mutation_v1() RETURNS trigger LANGUAGE plpgsql
        SET search_path=pg_catalog,pg_temp AS $fn$
        BEGIN RAISE EXCEPTION 'grounded artifacts are immutable' USING ERRCODE='23514'; END $fn$;
    """)
    for table in _TABLES:
        if table != "grounded_release_active":
            op.execute(
                f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON app.{table} "
                "FOR EACH ROW EXECUTE FUNCTION app.reject_grounded_pair_mutation_v1()"
            )
    op.execute(f"""
        CREATE FUNCTION app.validate_grounded_report_v1(p jsonb) RETURNS void
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $fn$
        DECLARE row jsonb; body jsonb; v jsonb; n integer:=0; failures integer:=0; key text;
        BEGIN
            IF p IS NULL OR jsonb_typeof(p) IS DISTINCT FROM 'object'
                OR (SELECT array_agg(k ORDER BY k COLLATE "C") FROM jsonb_object_keys(p) k)
                    IS DISTINCT FROM ARRAY['candidate_sha256','completed_at','config_sha256','failure_count',
                        'kind','outcome','report_sha256','result','schema_version']
                OR p->>'schema_version' IS DISTINCT FROM 'grounded-promotion-report.v1'
                OR p->>'kind' IS NULL OR p->>'kind' NOT IN ('SOURCE_ABLATION','AXIS_COMPARISON','API_UI')
                OR COALESCE(p->>'candidate_sha256','') !~ '^[0-9a-f]{{64}}$'
                OR COALESCE(p->>'config_sha256','') !~ '^[0-9a-f]{{64}}$'
                OR jsonb_typeof(p->'completed_at') IS DISTINCT FROM 'string'
                OR p->>'report_sha256' IS DISTINCT FROM {_hash("p-'report_sha256'")}
                OR jsonb_typeof(p->'result') IS DISTINCT FROM 'object' THEN
                RAISE EXCEPTION 'invalid grounded report' USING ERRCODE='23514';
            END IF;
            PERFORM (p->>'completed_at')::timestamptz;
            body:=p->'result';
            IF p->>'kind'='API_UI' THEN
                IF COALESCE(body->>'openapi_sha256','') !~ '^[0-9a-f]{{64}}$'
                    OR COALESCE(body->>'frontend_release_sha256','') !~ '^[0-9a-f]{{64}}$'
                    OR jsonb_typeof(body->'cases') IS DISTINCT FROM 'array'
                    OR jsonb_array_length(body->'cases')<>6
                    OR (SELECT array_agg(value->>'case' ORDER BY value->>'case') FROM jsonb_array_elements(body->'cases'))
                        IS DISTINCT FROM ARRAY['desktop','happy_path','mobile','photo','replay','unknown'] THEN
                    RAISE EXCEPTION 'incomplete API UI report' USING ERRCODE='23514';
                END IF;
                FOR row IN SELECT value FROM jsonb_array_elements(body->'cases') LOOP
                    IF jsonb_typeof(row->'executed') IS DISTINCT FROM 'number' OR row->>'executed' !~ '^[1-9][0-9]*$'
                        OR jsonb_typeof(row->'failures') IS DISTINCT FROM 'array'
                        OR jsonb_typeof(row->'artifact_sha256') IS DISTINCT FROM 'array'
                        OR jsonb_array_length(row->'artifact_sha256')<1
                        OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(row->'artifact_sha256') a WHERE COALESCE(a,'') !~ '^[0-9a-f]{{64}}$')
                        OR jsonb_array_length(row->'failures')>(row->>'executed')::integer THEN
                        RAISE EXCEPTION 'unexecuted API UI case' USING ERRCODE='23514';
                    END IF;
                    failures:=failures+jsonb_array_length(row->'failures');
                END LOOP;
            ELSE
                IF body->>'scope' IS DISTINCT FROM 'DEV' OR body->>'model' IS DISTINCT FROM 'glm-5.3-flash'
                    OR body->>'human_relevance_status' IS DISTINCT FROM 'NOT_MEASURED'
                    OR COALESCE(body->>'dev_manifest_sha256','') !~ '^[0-9a-f]{{64}}$'
                    OR COALESCE(body->>'prompt_sha256','') !~ '^[0-9a-f]{{64}}$'
                    OR COALESCE(body->>'aggregation_policy_sha256','') !~ '^[0-9a-f]{{64}}$'
                    OR jsonb_typeof(body->'rows') IS DISTINCT FROM 'array'
                    OR jsonb_array_length(body->'rows')<1 THEN
                    RAISE EXCEPTION 'invalid DEV comparison' USING ERRCODE='23514';
                END IF;
                IF p->>'kind'='SOURCE_ABLATION' THEN
                    IF EXISTS(SELECT 1 FROM jsonb_array_elements(body->'rows') r GROUP BY r->>'scenario_id'
                        HAVING count(*)<>5 OR count(DISTINCT r->>'preference_sha256')<>1
                        OR array_agg(r->>'lane' ORDER BY r->>'lane')<>
                            ARRAY['baseline','combined','detail','images','odii']) THEN
                        RAISE EXCEPTION 'incomparable source lanes' USING ERRCODE='23514';
                    END IF;
                ELSIF body->>'comparison' IS DISTINCT FROM 'FIXED_SOURCE_SUBORDINATES_MODEL_AND_USER' THEN
                    RAISE EXCEPTION 'incomparable axis policies' USING ERRCODE='23514';
                END IF;
                FOR row IN SELECT value FROM jsonb_array_elements(body->'rows') LOOP
                    IF COALESCE(row->>'preference_sha256','') !~ '^[0-9a-f]{{64}}$'
                        OR COALESCE(row->>'source_bundle_sha256','') !~ '^[0-9a-f]{{64}}$'
                        OR COALESCE(row->>'model_response_sha256','') !~ '^[0-9a-f]{{64}}$'
                        OR jsonb_typeof(row->'scenario_id') IS DISTINCT FROM 'string'
                        OR char_length(row->>'scenario_id') NOT BETWEEN 1 AND 160 THEN
                        RAISE EXCEPTION 'comparison input not bound' USING ERRCODE='23514';
                    END IF;
                    IF p->>'kind'='SOURCE_ABLATION' THEN
                        FOREACH key IN ARRAY ARRAY['eligible_count','purpose_eligible_count','supported_dimensions',
                            'possible_dimensions','checked_constraints','checked_claims'] LOOP
                            IF jsonb_typeof(row->key) IS DISTINCT FROM 'number'
                                OR COALESCE(row->>key,'') !~ '^[0-9]+$' THEN
                                RAISE EXCEPTION 'unmeasured source coverage' USING ERRCODE='23514';
                            END IF;
                        END LOOP;
                        IF jsonb_typeof(row->'ranking') IS DISTINCT FROM 'array' OR jsonb_array_length(row->'ranking')<>5
                            OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(row->'ranking'))<>5
                            OR (row->>'eligible_count')::integer<5
                            OR (row->>'purpose_eligible_count')::integer<0
                            OR (row->>'purpose_eligible_count')::integer>(row->>'eligible_count')::integer
                            OR (row->>'supported_dimensions')::integer<0
                            OR (row->>'supported_dimensions')::integer>(row->>'possible_dimensions')::integer
                            OR (row->>'possible_dimensions')::integer<1
                            OR (row->>'checked_constraints')::integer<1 THEN
                            RAISE EXCEPTION 'invalid source measurements' USING ERRCODE='23514';
                        END IF;
                        v:=row->'violations';
                    ELSE
                        FOREACH key IN ARRAY ARRAY['compared_places','supported_axes','possible_axes'] LOOP
                            IF jsonb_typeof(row->key) IS DISTINCT FROM 'number'
                                OR COALESCE(row->>key,'') !~ '^[0-9]+$' THEN
                                RAISE EXCEPTION 'unmeasured axis coverage' USING ERRCODE='23514';
                            END IF;
                        END LOOP;
                        IF jsonb_array_length(row->'raw_independent_ranking') IS DISTINCT FROM 5
                            OR jsonb_array_length(row->'aggregated_ranking') IS DISTINCT FROM 5
                            OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(row->'raw_independent_ranking'))<>5
                            OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(row->'aggregated_ranking'))<>5
                            OR COALESCE(row->>'subordinate_judgments_sha256','') !~ '^[0-9a-f]{{64}}$'
                            OR (row->>'compared_places')::integer<5
                            OR (row->>'supported_axes')::integer<0
                            OR (row->>'possible_axes')::integer<1
                            OR (row->>'supported_axes')::integer>(row->>'possible_axes')::integer THEN
                            RAISE EXCEPTION 'invalid axis measurements' USING ERRCODE='23514';
                        END IF;
                        v:=row->'aggregated_violations';
                    END IF;
                    IF v IS NULL OR jsonb_typeof(v) IS DISTINCT FROM 'object'
                        OR v-ARRAY['constraint','unauthorized_claim','replay','schema_identity','structural_regression']<>'{{}}'::jsonb THEN
                        RAISE EXCEPTION 'invalid measured violations' USING ERRCODE='23514';
                    END IF;
                    FOREACH key IN ARRAY ARRAY['constraint','unauthorized_claim','replay','schema_identity','structural_regression'] LOOP
                        IF v ? key AND jsonb_typeof(v->key) IS DISTINCT FROM 'array' THEN
                            RAISE EXCEPTION 'invalid measured violations' USING ERRCODE='23514';
                        END IF;
                        failures:=failures+COALESCE(jsonb_array_length(v->key),0);
                    END LOOP;
                END LOOP;
            END IF;
            IF jsonb_typeof(p->'failure_count') IS DISTINCT FROM 'number' OR (p->>'failure_count')::integer IS DISTINCT FROM failures
                OR p->>'outcome' IS DISTINCT FROM (CASE WHEN failures=0 THEN 'PASS' ELSE 'FAIL' END) THEN
                RAISE EXCEPTION 'report verdict is not measured' USING ERRCODE='23514';
            END IF;
        END $fn$;
    """)
    op.execute(f"""
        CREATE FUNCTION app.stage_grounded_release_candidate_v1(p jsonb) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        DECLARE v_prior jsonb; v_sha text; i integer; profile jsonb; assessment jsonb; mood jsonb;
        BEGIN {guard}
            v_sha:=p->>'candidate_sha256';
            IF p IS NULL OR p->>'schema_version' IS DISTINCT FROM 'grounded-release-candidate.v1'
                OR v_sha IS DISTINCT FROM {_hash("p-'candidate_sha256'")}
                OR p->'raw_release'->>'release_sha256' IS DISTINCT FROM p->'manifest'->>'raw_release_sha256'
                OR p->'analysis_run'->>'scope' IS DISTINCT FROM 'PUBLIC_COMPLETE'
                OR p->'analysis_run'->>'run_sha256' IS DISTINCT FROM {_hash("(p->'analysis_run')-'run_sha256'")}
                OR jsonb_typeof(p->'raw_release'->'profiles') IS DISTINCT FROM 'array'
                OR jsonb_typeof(p->'assessments') IS DISTINCT FROM 'array'
                OR jsonb_typeof(p->'moods') IS DISTINCT FROM 'array'
                OR jsonb_typeof(p->'source_snapshots') IS DISTINCT FROM 'array'
                OR jsonb_array_length(p->'raw_release'->'profiles') NOT BETWEEN 80 AND 100
                OR jsonb_array_length(p->'assessments') IS DISTINCT FROM jsonb_array_length(p->'raw_release'->'profiles')
                OR jsonb_array_length(p->'moods') IS DISTINCT FROM jsonb_array_length(p->'assessments')
                OR jsonb_array_length(p->'source_snapshots') IS DISTINCT FROM jsonb_array_length(p->'assessments') THEN
                RAISE EXCEPTION 'invalid complete grounded candidate' USING ERRCODE='23514';
            END IF;
            FOR i IN 0..jsonb_array_length(p->'assessments')-1 LOOP
                profile:=p->'raw_release'->'profiles'->i;
                assessment:=p->'assessments'->i; mood:=p->'moods'->i;
                IF assessment->>'bundle_sha256' IS DISTINCT FROM {_hash("assessment-'bundle_sha256'")}
                    OR mood->>'bundle_sha256' IS DISTINCT FROM {_hash("mood-'bundle_sha256'")}
                    OR assessment->>'place_id' IS DISTINCT FROM profile->>'place_id'
                    OR mood->>'place_id' IS DISTINCT FROM profile->>'place_id'
                    OR assessment->>'raw_profile_sha256' IS DISTINCT FROM profile->>'profile_sha256'
                    OR mood->>'raw_profile_sha256' IS DISTINCT FROM profile->>'profile_sha256'
                    OR assessment->>'source_release_sha256' IS DISTINCT FROM p->'manifest'->>'source_release_sha256'
                    OR mood->>'source_release_sha256' IS DISTINCT FROM p->'manifest'->>'source_release_sha256' THEN
                    RAISE EXCEPTION 'grounded candidate member binding differs' USING ERRCODE='23514';
                END IF;
            END LOOP;
            INSERT INTO app.grounded_release_candidates(candidate_sha256,raw_release_sha256,source_release_sha256,payload,created_at)
                VALUES(v_sha,p->'raw_release'->>'release_sha256',p->'manifest'->>'source_release_sha256',p,(p->>'created_at')::timestamptz)
                ON CONFLICT DO NOTHING;
            SELECT payload INTO v_prior FROM app.grounded_release_candidates WHERE candidate_sha256=v_sha;
            IF v_prior IS DISTINCT FROM p THEN RAISE EXCEPTION 'grounded candidate conflict' USING ERRCODE='23514'; END IF;
            RETURN v_sha;
        END $fn$;
        CREATE FUNCTION app.store_grounded_promotion_report_v1(p jsonb) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        DECLARE v_prior jsonb;
        BEGIN {guard}
            PERFORM app.validate_grounded_report_v1(p);
            INSERT INTO app.grounded_promotion_reports(report_sha256,candidate_sha256,kind,config_sha256,payload)
                VALUES(p->>'report_sha256',p->>'candidate_sha256',p->>'kind',p->>'config_sha256',p)
                ON CONFLICT DO NOTHING;
            SELECT payload INTO v_prior FROM app.grounded_promotion_reports WHERE report_sha256=p->>'report_sha256';
            IF v_prior IS DISTINCT FROM p THEN RAISE EXCEPTION 'grounded report conflict' USING ERRCODE='23514'; END IF;
            RETURN p->>'report_sha256';
        END $fn$;
    """)
    op.execute(f"""
        CREATE FUNCTION app.promote_grounded_release_pair_v1(p jsonb,p_expected_active text) RETURNS bigint
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
        DECLARE v_candidate jsonb; v_report jsonb; v_reports jsonb:='{{}}'::jsonb;
            v_field text; v_kind text; v_previous text; v_old_gate text; v_generation bigint;
        BEGIN {guard}
            PERFORM pg_advisory_xact_lock(hashtextextended('grounded-active-pair-v1',0));
            IF p IS NULL OR p->>'schema_version' IS DISTINCT FROM 'grounded-promotion-gate.v1'
                OR (SELECT array_agg(k ORDER BY k COLLATE "C") FROM jsonb_object_keys(p) k)
                    IS DISTINCT FROM ARRAY['api_ui_verification_sha256','axis_comparison_sha256','candidate_sha256',
                        'config_sha256','gate_sha256','passed','schema_version','source_ablation_sha256','verified_at']
                OR p->'passed' IS DISTINCT FROM 'true'::jsonb
                OR jsonb_typeof(p->'verified_at') IS DISTINCT FROM 'string'
                OR p->>'gate_sha256' IS DISTINCT FROM {_hash("p-'gate_sha256'")} THEN
                RAISE EXCEPTION 'invalid promotion gate' USING ERRCODE='23514';
            END IF;
            SELECT payload INTO v_candidate FROM app.grounded_release_candidates WHERE candidate_sha256=p->>'candidate_sha256';
            IF NOT FOUND OR v_candidate->>'candidate_sha256' IS DISTINCT FROM {_hash("v_candidate-'candidate_sha256'")} THEN
                RAISE EXCEPTION 'missing grounded candidate' USING ERRCODE='23514';
            END IF;
            FOREACH v_field IN ARRAY ARRAY['source_ablation_sha256','axis_comparison_sha256','api_ui_verification_sha256'] LOOP
                v_kind:=CASE v_field WHEN 'source_ablation_sha256' THEN 'SOURCE_ABLATION'
                    WHEN 'axis_comparison_sha256' THEN 'AXIS_COMPARISON' ELSE 'API_UI' END;
                SELECT payload INTO v_report FROM app.grounded_promotion_reports WHERE report_sha256=p->>v_field;
                IF NOT FOUND THEN RAISE EXCEPTION 'missing actual promotion report' USING ERRCODE='23514'; END IF;
                PERFORM app.validate_grounded_report_v1(v_report);
                IF v_report->>'kind' IS DISTINCT FROM v_kind
                    OR v_report->>'candidate_sha256' IS DISTINCT FROM p->>'candidate_sha256'
                    OR v_report->>'config_sha256' IS DISTINCT FROM p->>'config_sha256'
                    OR v_report->>'outcome' IS DISTINCT FROM 'PASS'
                    OR (v_report->>'failure_count')::integer<>0
                    OR (v_report->>'completed_at')::timestamptz<(v_candidate->>'created_at')::timestamptz
                    OR (v_report->>'completed_at')::timestamptz>(p->>'verified_at')::timestamptz THEN
                    RAISE EXCEPTION 'promotion report authority differs' USING ERRCODE='23514';
                END IF;
                v_reports:=v_reports||jsonb_build_object(v_kind,v_report);
            END LOOP;
            FOREACH v_field IN ARRAY ARRAY['dev_manifest_sha256','model','prompt_sha256','aggregation_policy_sha256'] LOOP
                IF v_reports->'SOURCE_ABLATION'->'result'->v_field IS DISTINCT FROM v_reports->'AXIS_COMPARISON'->'result'->v_field THEN
                    RAISE EXCEPTION 'comparison authority differs' USING ERRCODE='23514';
                END IF;
            END LOOP;
            SELECT candidate_sha256,gate_sha256,generation INTO v_previous,v_old_gate,v_generation
                FROM app.grounded_release_active WHERE singleton FOR UPDATE;
            IF v_previous=p->>'candidate_sha256' AND v_old_gate=p->>'gate_sha256' THEN RETURN v_generation; END IF;
            IF v_previous IS DISTINCT FROM p_expected_active THEN
                RAISE EXCEPTION 'active grounded pair changed' USING ERRCODE='40001';
            END IF;
            INSERT INTO app.grounded_promotion_gates(gate_sha256,candidate_sha256,config_sha256,payload,verified_at)
                VALUES(p->>'gate_sha256',p->>'candidate_sha256',p->>'config_sha256',p,(p->>'verified_at')::timestamptz)
                ON CONFLICT DO NOTHING;
            v_generation:=COALESCE(v_generation,0)+1;
            INSERT INTO app.grounded_release_promotions(generation,candidate_sha256,gate_sha256,previous_candidate_sha256,activated_at)
                VALUES(v_generation,p->>'candidate_sha256',p->>'gate_sha256',v_previous,CURRENT_TIMESTAMP);
            INSERT INTO app.grounded_release_active(singleton,candidate_sha256,gate_sha256,generation,activated_at)
                VALUES(true,p->>'candidate_sha256',p->>'gate_sha256',v_generation,CURRENT_TIMESTAMP)
                ON CONFLICT(singleton) DO UPDATE SET candidate_sha256=EXCLUDED.candidate_sha256,
                    gate_sha256=EXCLUDED.gate_sha256,generation=EXCLUDED.generation,activated_at=EXCLUDED.activated_at;
            RETURN v_generation;
        END $fn$;
    """)
    for signature in (
        *_FUNCTIONS,
        "validate_grounded_report_v1(jsonb)",
        "reject_grounded_pair_mutation_v1()",
    ):
        op.execute(f"ALTER FUNCTION app.{signature} OWNER TO {_OWNER}")
        op.execute(f'REVOKE ALL ON FUNCTION app.{signature} FROM PUBLIC,"{runtime}",{_SERVICE}')
        if signature in _FUNCTIONS:
            op.execute(f'GRANT EXECUTE ON FUNCTION app.{signature} TO {_SERVICE},"{migrator}"')
        else:
            op.execute(f"GRANT EXECUTE ON FUNCTION app.{signature} TO {_OWNER}")


def downgrade() -> None:
    for signature in reversed(_FUNCTIONS):
        op.execute(f"DROP FUNCTION app.{signature}")
    op.execute("DROP FUNCTION app.validate_grounded_report_v1(jsonb)")
    for table in reversed(_TABLES):
        op.execute(f"DROP TABLE app.{table}")
    op.execute("DROP FUNCTION app.reject_grounded_pair_mutation_v1()")
