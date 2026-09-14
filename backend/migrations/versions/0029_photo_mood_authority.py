"""Add independent, owner-bound appearance analysis and immutable confirmations."""

from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision = "0029_photo_mood_authority"
down_revision = "0028_source_grounding_snapshots"
branch_labels = None
depends_on = None

_OWNER = "itda_photo_write_authority"
_SERVICE = "itda_photo_service"
_POLICY = "9e9687b4dce79ae4e592d8111c4876969d4f4a6db1af0497a72dbe4faef6e3c2"
_DIMENSIONS = (
    "greenery",
    "water",
    "open_composition",
    "traditional_appearance",
    "contemporary_design",
    "warm_light",
    "vivid_color",
    "night_lighting",
)
_TABLES = ("photo_mood_job_families", "photo_mood_batches", "photo_mood_confirmations")
_FUNCTIONS = (
    "create_photo_mood_job_v1(text,text)",
    "read_photo_mood_family_v1(text,text)",
    "record_photo_mood_batch_v1(text,text,jsonb)",
    "read_photo_mood_batches_v1(text,text)",
    "confirm_photo_moods_v1(text,text,jsonb,text)",
    "read_photo_mood_confirmation_v1(text,text)",
)
_GUARD = """
    IF session_user <> 'itda_photo_service' THEN
        RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='42501';
    END IF;
    IF p_job_id IS NULL OR p_job_id !~ '^[0-9a-f]{64}$'
       OR p_profile_id IS NULL OR char_length(p_profile_id) NOT BETWEEN 1 AND 160 THEN
        RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
"""


def _hash(value: str) -> str:
    return (
        "encode(pg_catalog.sha256(pg_catalog.convert_to("
        f"dev_eval.canonical_jsonb_compact_v2({value}), 'UTF8')), 'hex')"
    )


def _owned(states: str) -> str:
    return f"""
        SELECT j.status INTO v_status FROM dev_eval.photo_jobs j
        JOIN dev_eval.photo_mood_job_families f ON f.job_id=j.job_id
            AND f.profile_id=j.profile_id
        WHERE j.job_id=p_job_id AND j.profile_id=p_profile_id
            AND f.family='photo-mood-v1' FOR UPDATE OF j;
        IF NOT FOUND OR v_status NOT IN ({states}) THEN
            RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
        END IF;
    """


def upgrade() -> None:
    op.execute("""
        CREATE TABLE dev_eval.photo_mood_job_families (
            job_id text PRIMARY KEY REFERENCES dev_eval.photo_jobs(job_id) ON DELETE CASCADE,
            profile_id text NOT NULL,
            family text NOT NULL CHECK(family='photo-mood-v1'),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(job_id,profile_id)
        );
        CREATE TABLE dev_eval.photo_mood_batches (
            job_id text NOT NULL,
            profile_id text NOT NULL,
            image_index integer NOT NULL CHECK(image_index BETWEEN 1 AND 3),
            candidate_set_sha256 text NOT NULL CHECK(candidate_set_sha256 ~ '^[0-9a-f]{64}$'),
            payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(job_id,image_index),
            FOREIGN KEY(job_id,profile_id) REFERENCES
                dev_eval.photo_mood_job_families(job_id,profile_id) ON DELETE CASCADE
        );
        CREATE TABLE dev_eval.photo_mood_confirmations (
            job_id text PRIMARY KEY,
            profile_id text NOT NULL,
            draft_sha256 text NOT NULL CHECK(draft_sha256 ~ '^[0-9a-f]{64}$'),
            projection jsonb NOT NULL CHECK(jsonb_typeof(projection)='object'),
            created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(job_id,profile_id) REFERENCES
                dev_eval.photo_mood_job_families(job_id,profile_id) ON DELETE CASCADE
        );
    """)
    for table in _TABLES:
        op.execute(f"ALTER TABLE dev_eval.{table} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON dev_eval.{table} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON dev_eval.{table} FROM {_SERVICE}")
    # This existing canonicalizer is pure/immutable, not a mutation capability.
    op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb) TO {_OWNER}")

    # Preserve the exact generic-job guards without granting its definer owner
    # EXECUTE on a service-only mutation function merely to nest a call.
    legacy = (
        op.get_bind()
        .execute(
            text(
                "SELECT prosrc FROM pg_catalog.pg_proc WHERE oid="
                "'dev_eval.create_photo_job_v3(text,text,text)'::regprocedure"
            )
        )
        .scalar_one()
    )
    if (
        legacy.count("DECLARE v_inserted integer;") != 1
        or legacy.count("RETURN v_inserted=1;") != 1
    ):
        raise RuntimeError("generic photo creation authority changed")
    body = legacy.replace(
        "DECLARE v_inserted integer;", "DECLARE v_inserted integer; p_idempotency_key text := NULL;"
    ).replace(
        "RETURN v_inserted=1;",
        """
        IF v_inserted=1 THEN
            INSERT INTO dev_eval.photo_mood_job_families(job_id,profile_id,family)
                VALUES(p_job_id,p_profile_id,'photo-mood-v1');
        ELSIF NOT EXISTS(SELECT 1 FROM dev_eval.photo_mood_job_families
            WHERE job_id=p_job_id AND profile_id=p_profile_id AND family='photo-mood-v1') THEN
            RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
        END IF;
        RETURN v_inserted=1;
    """,
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.create_photo_mood_job_v1(p_job_id text,p_profile_id text)
        RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
    """
        + body
        + "$function$;"
    )
    op.execute(f"""
        CREATE FUNCTION dev_eval.read_photo_mood_family_v1(p_job_id text,p_profile_id text)
        RETURNS text LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_family text;
        BEGIN {_GUARD}
            PERFORM 1 FROM dev_eval.photo_jobs WHERE job_id=p_job_id AND profile_id=p_profile_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            SELECT family INTO v_family FROM dev_eval.photo_mood_job_families
                WHERE job_id=p_job_id AND profile_id=p_profile_id;
            RETURN v_family;
        END $function$;
    """)
    dimensions = "ARRAY[" + ",".join(f"'{x}'" for x in _DIMENSIONS) + "]"
    batch_hash = _hash("p_batch-'candidate_set_sha256'")
    candidate_hash = _hash(
        "jsonb_build_object('job_id',p_job_id,'image',p_batch->>'payload_sha256',"
        "'observation',v_observation,'provider_id',p_batch->>'provider_id',"
        "'policy_sha256',p_batch->>'policy_sha256')"
    )
    draft_hash = _hash(
        "jsonb_build_object('schema_version','photo-mood-draft.v1','job_id',p_job_id,"
        f"'preference_profile_id',p_profile_id,'policy_sha256','{_POLICY}',"
        "'candidate_set_sha256',v_hashes)"
    )
    op.execute(f"""
        CREATE FUNCTION dev_eval.record_photo_mood_batch_v1(
            p_job_id text,p_profile_id text,p_batch jsonb)
        RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_status text; v_image integer; v_prior jsonb; v_candidate jsonb;
            v_observation jsonb; v_index integer; v_expected text;
            v_dimensions text[] := {dimensions};
        BEGIN {_GUARD} {_owned("'running','succeeded'")}
            IF p_batch IS NULL OR jsonb_typeof(p_batch) IS DISTINCT FROM 'object'
                OR (SELECT array_agg(key ORDER BY key COLLATE "C")
                    FROM jsonb_object_keys(p_batch) key)
                    IS DISTINCT FROM ARRAY['analysis_kind','authority_scope','candidate_set_sha256',
                    'candidates','family','image_index','job_id','model','mood_version','payload_sha256',
                    'policy_sha256','provider_id','schema_version']
                OR p_batch->>'schema_version' IS DISTINCT FROM 'photo-mood-candidates.v1'
                OR p_batch->>'family' IS DISTINCT FROM 'photo-mood-v1'
                OR p_batch->>'authority_scope' IS DISTINCT FROM 'VISUAL_MOOD_ONLY'
                OR p_batch->>'mood_version' IS DISTINCT FROM 'visual-mood-v1'
                OR p_batch->>'job_id' IS DISTINCT FROM p_job_id
                OR p_batch->>'policy_sha256' IS DISTINCT FROM '{_POLICY}'
                OR jsonb_typeof(p_batch->'image_index') IS DISTINCT FROM 'number'
                OR p_batch->>'image_index' !~ '^[1-3]$'
                OR jsonb_typeof(p_batch->'payload_sha256') IS DISTINCT FROM 'string'
                OR p_batch->>'payload_sha256' !~ '^[0-9a-f]{{64}}$'
                OR jsonb_typeof(p_batch->'provider_id') IS DISTINCT FROM 'string'
                OR char_length(p_batch->>'provider_id') NOT BETWEEN 1 AND 100
                OR p_batch->>'analysis_kind' IS NULL
                OR p_batch->>'analysis_kind' NOT IN ('MODEL','SYNTHETIC')
                OR (p_batch->>'analysis_kind'='MODEL' AND (
                    p_batch->>'model' IS DISTINCT FROM 'glm-5.3-flash'
                    OR lower(p_batch->>'provider_id') LIKE '%synthetic%'))
                OR (p_batch->>'analysis_kind'='SYNTHETIC' AND p_batch->'model' <> 'null'::jsonb)
                OR jsonb_typeof(p_batch->'candidates') IS DISTINCT FROM 'array'
                OR jsonb_array_length(p_batch->'candidates') <> 8
                OR p_batch->>'candidate_set_sha256' IS DISTINCT FROM {batch_hash}
            THEN RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514'; END IF;
            v_image := (p_batch->>'image_index')::integer;
            IF NOT EXISTS(SELECT 1 FROM dev_eval.photo_job_image_slots
                WHERE job_id=p_job_id AND profile_id=p_profile_id
                    AND image_index=v_image AND state='stored') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            FOR v_candidate,v_index IN SELECT value,ordinality::integer
                FROM jsonb_array_elements(p_batch->'candidates') WITH ORDINALITY LOOP
                v_observation := v_candidate->'observation';
                IF jsonb_typeof(v_candidate) IS DISTINCT FROM 'object'
                    OR (SELECT array_agg(key ORDER BY key COLLATE "C")
                        FROM jsonb_object_keys(v_candidate) key)
                        IS DISTINCT FROM ARRAY['candidate_id','observation']
                    OR jsonb_typeof(v_observation) IS DISTINCT FROM 'object'
                    OR (SELECT array_agg(key ORDER BY key COLLATE "C")
                        FROM jsonb_object_keys(v_observation) key)
                        IS DISTINCT FROM ARRAY['certainty','dimension','level','state']
                    OR v_observation->>'dimension' IS DISTINCT FROM v_dimensions[v_index]
                    OR v_observation->>'state' IS NULL
                    OR v_observation->>'state' NOT IN ('OBSERVED','UNKNOWN')
                    OR (v_observation->>'state'='UNKNOWN' AND (
                        v_observation->'level' IS DISTINCT FROM 'null'::jsonb
                        OR v_observation->>'certainty' IS DISTINCT FROM 'LOW'))
                    OR (v_observation->>'state'='OBSERVED' AND (
                        jsonb_typeof(v_observation->'level') IS DISTINCT FROM 'number'
                        OR v_observation->>'level' !~ '^[0-4]$'
                        OR v_observation->>'certainty' IS DISTINCT FROM 'HIGH'
                        OR p_batch->>'analysis_kind'='SYNTHETIC')) THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
                END IF;
                v_expected := {candidate_hash};
                IF v_candidate->>'candidate_id' IS DISTINCT FROM v_expected THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
                END IF;
            END LOOP;
            SELECT payload INTO v_prior FROM dev_eval.photo_mood_batches
                WHERE job_id=p_job_id AND image_index=v_image;
            IF FOUND THEN
                IF v_prior <> p_batch THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
                END IF;
                RETURN 0;
            END IF;
            IF v_status <> 'running' OR EXISTS(SELECT 1 FROM dev_eval.photo_mood_confirmations
                WHERE job_id=p_job_id) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            IF EXISTS(SELECT 1 FROM dev_eval.photo_mood_batches
                WHERE job_id=p_job_id AND payload->>'payload_sha256'=p_batch->>'payload_sha256'
                AND payload->'candidates'<>p_batch->'candidates') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            INSERT INTO dev_eval.photo_mood_batches
                (job_id,profile_id,image_index,candidate_set_sha256,payload)
                VALUES(p_job_id,p_profile_id,v_image,p_batch->>'candidate_set_sha256',p_batch);
            RETURN 8;
        END $function$;
    """)
    op.execute(f"""
        CREATE FUNCTION dev_eval.read_photo_mood_batches_v1(p_job_id text,p_profile_id text)
        RETURNS SETOF jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_status text;
        BEGIN {_GUARD} {_owned("'running','succeeded'")}
            RETURN QUERY SELECT payload FROM dev_eval.photo_mood_batches
                WHERE job_id=p_job_id AND profile_id=p_profile_id ORDER BY image_index;
        END $function$;
    """)
    op.execute(f"""
        CREATE FUNCTION dev_eval.confirm_photo_moods_v1(
            p_job_id text,p_profile_id text,p_choices jsonb,p_draft text)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_status text; v_hashes jsonb; v_expected_draft text; v_choices jsonb;
            v_prior jsonb; v_moods jsonb; v_projection jsonb; v_slot_count integer;
        BEGIN {_GUARD} {_owned("'succeeded'")}
            SELECT count(*) INTO v_slot_count FROM dev_eval.photo_job_image_slots
                WHERE job_id=p_job_id AND profile_id=p_profile_id;
            IF v_slot_count NOT BETWEEN 1 AND 3 OR EXISTS(
                SELECT 1 FROM dev_eval.photo_job_image_slots s
                WHERE s.job_id=p_job_id AND (s.state<>'stored'
                    OR s.image_index>v_slot_count OR NOT EXISTS(
                        SELECT 1 FROM dev_eval.photo_mood_batches b
                        WHERE b.job_id=p_job_id AND b.image_index=s.image_index))) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            SELECT COALESCE(jsonb_agg(candidate_set_sha256
                ORDER BY candidate_set_sha256),'[]'::jsonb)
                INTO v_hashes FROM dev_eval.photo_mood_batches WHERE job_id=p_job_id;
            v_expected_draft := {draft_hash};
            IF p_draft IS DISTINCT FROM v_expected_draft OR p_choices IS NULL
                OR jsonb_typeof(p_choices) IS DISTINCT FROM 'array'
                OR jsonb_array_length(p_choices)>24
                OR (SELECT count(DISTINCT value->>'candidate_id')
                    FROM jsonb_array_elements(p_choices))
                    <>jsonb_array_length(p_choices) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_choices) c WHERE
                jsonb_typeof(c) IS DISTINCT FROM 'object'
                OR (SELECT array_agg(key ORDER BY key COLLATE "C") FROM jsonb_object_keys(c) key)
                    IS DISTINCT FROM ARRAY['candidate_id','included']
                OR jsonb_typeof(c->'included') IS DISTINCT FROM 'boolean'
                OR NOT EXISTS(SELECT 1 FROM dev_eval.photo_mood_batches b,
                    jsonb_array_elements(b.payload->'candidates') candidate
                    WHERE b.job_id=p_job_id AND candidate->>'candidate_id'=c->>'candidate_id'
                        AND ((c->>'included')::boolean=false
                            OR candidate->'observation'->>'state'='OBSERVED'))) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
            END IF;
            SELECT COALESCE(jsonb_agg(value ORDER BY value->>'candidate_id'),'[]'::jsonb)
                INTO v_choices FROM jsonb_array_elements(p_choices);
            WITH observations AS (
                SELECT DISTINCT b.payload->>'payload_sha256' image,
                    c->>'candidate_id' candidate_id,
                    c->'observation'->>'dimension' dimension,
                    (c->'observation'->>'level')::integer level
                FROM dev_eval.photo_mood_batches b,
                    jsonb_array_elements(b.payload->'candidates') c
                WHERE b.job_id=p_job_id AND c->'observation'->>'state'='OBSERVED'
                    AND EXISTS(SELECT 1 FROM jsonb_array_elements(v_choices) choice
                        WHERE choice->>'candidate_id'=c->>'candidate_id'
                            AND (choice->>'included')::boolean)
            ), projected AS (
                SELECT d.dimension,d.ord,count(o.candidate_id)::integer n,
                    CASE WHEN count(o.candidate_id)=0 THEN NULL
                        ELSE floor((2*sum(o.level*25)+count(o.candidate_id))::numeric
                            /(2*count(o.candidate_id)))::integer END value,
                    COALESCE(jsonb_agg(o.candidate_id ORDER BY o.candidate_id)
                        FILTER(WHERE o.candidate_id IS NOT NULL),'[]'::jsonb) refs
                FROM unnest({dimensions}) WITH ORDINALITY d(dimension,ord)
                LEFT JOIN observations o ON o.dimension=d.dimension GROUP BY d.dimension,d.ord
            ) SELECT jsonb_agg(jsonb_build_object('dimension',dimension,'value',value,
                    'distinct_images',n,'candidate_ids',refs) ORDER BY ord)
                INTO v_moods FROM projected;
            v_projection := jsonb_build_object('schema_version','photo-mood-projection.v1',
                'family','photo-mood-v1','job_id',p_job_id,'preference_profile_id',p_profile_id,
                'policy_sha256','{_POLICY}','draft_sha256',p_draft,'candidate_set_sha256',v_hashes,
                'choices',v_choices,'moods',v_moods);
            v_projection := v_projection
                || jsonb_build_object('receipt_id',{_hash("v_projection")});
            SELECT projection INTO v_prior FROM dev_eval.photo_mood_confirmations
                WHERE job_id=p_job_id;
            IF FOUND THEN
                IF v_prior<>v_projection THEN
                    RAISE EXCEPTION 'photo operation rejected' USING ERRCODE='23514';
                END IF;
                RETURN v_prior;
            END IF;
            INSERT INTO dev_eval.photo_mood_confirmations(job_id,profile_id,draft_sha256,projection)
                VALUES(p_job_id,p_profile_id,p_draft,v_projection);
            RETURN v_projection;
        END $function$;
    """)
    op.execute(f"""
        CREATE FUNCTION dev_eval.read_photo_mood_confirmation_v1(p_job_id text,p_profile_id text)
        RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
        SET search_path=pg_catalog,pg_temp AS $function$
        DECLARE v_status text; v_projection jsonb;
        BEGIN {_GUARD} {_owned("'succeeded'")}
            SELECT projection INTO v_projection FROM dev_eval.photo_mood_confirmations
                WHERE job_id=p_job_id AND profile_id=p_profile_id;
            RETURN v_projection;
        END $function$;
        CREATE FUNCTION dev_eval.purge_photo_mood_deleted_v1() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
        BEGIN
            IF NEW.status='deleted' AND OLD.status IS DISTINCT FROM 'deleted' THEN
                DELETE FROM dev_eval.photo_mood_confirmations WHERE job_id=NEW.job_id;
                DELETE FROM dev_eval.photo_mood_batches WHERE job_id=NEW.job_id;
            END IF;
            RETURN NEW;
        END $function$;
        CREATE TRIGGER purge_photo_mood_deleted_v1 AFTER UPDATE OF status ON dev_eval.photo_jobs
            FOR EACH ROW EXECUTE FUNCTION dev_eval.purge_photo_mood_deleted_v1();
    """)
    for signature in (*_FUNCTIONS, "purge_photo_mood_deleted_v1()"):
        op.execute(f"ALTER FUNCTION dev_eval.{signature} OWNER TO {_OWNER}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM {_OWNER}")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM CURRENT_USER")
        if signature in _FUNCTIONS:
            op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{signature} TO {_SERVICE}")


def downgrade() -> None:
    op.execute("DROP TRIGGER purge_photo_mood_deleted_v1 ON dev_eval.photo_jobs")
    op.execute("DROP FUNCTION dev_eval.purge_photo_mood_deleted_v1()")
    for signature in reversed(_FUNCTIONS):
        op.execute(f"DROP FUNCTION dev_eval.{signature}")
    for table in reversed(_TABLES):
        op.execute(f"DROP TABLE dev_eval.{table}")
    op.execute(
        f"REVOKE EXECUTE ON FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb) FROM {_OWNER}"
    )
