"""Persist versioned photo semantics without promoting legacy candidates."""

from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision = "0027_photo_semantic_authority"
down_revision = "0026_daily_glm_availability"
branch_labels = None
depends_on = None

_FUNCTIONS = (
    "record_photo_candidate_batch_v4(text,text,text[],text[],text[],text[],text[],text,text,text,integer)",
    "list_photo_candidates_v3(text,text)",
    "read_photo_recommendation_projection_v2(text,text)",
)


def upgrade() -> None:
    op.execute("""
        ALTER TABLE dev_eval.photo_trait_candidates
        ADD COLUMN analysis_kind text NOT NULL DEFAULT 'legacy',
        ADD COLUMN provider_id text,
        ADD COLUMN semantic_version text,
        ADD COLUMN semantic_id text,
        ADD COLUMN image_index integer,
        ADD CONSTRAINT photo_semantic_provenance CHECK (
            (analysis_kind = 'legacy' AND provider_id IS NULL AND semantic_version IS NULL
             AND semantic_id IS NULL AND image_index IS NULL)
            OR (analysis_kind IN ('synthetic', 'semantic')
                AND provider_id IS NOT NULL AND char_length(provider_id) BETWEEN 1 AND 100
                AND semantic_version IS NOT NULL AND semantic_version = 'photo-semantics-v2'
                AND image_index IS NOT NULL AND image_index BETWEEN 1 AND 3
                AND (analysis_kind = 'synthetic'
                     OR (semantic_id IS NOT NULL AND semantic_id ~ '^M[1-6]\\.[a-z_]+$'
                         AND split_part(semantic_id, '.', 1) = trait_id
                         AND lower(provider_id) NOT LIKE '%synthetic%')))
        );
        CREATE FUNCTION dev_eval.record_photo_candidate_batch_v4(
            p_job_id text, p_profile_id text, p_candidate_ids text[], p_trait_ids text[],
            p_texts_ko text[], p_digests text[], p_semantic_ids text[],
            p_analysis_kind text, p_provider_id text, p_semantic_version text,
            p_image_index integer
        ) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE v_count integer; v_status text;
        BEGIN
            IF session_user <> 'itda_photo_service' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '42501';
            END IF;
            IF p_semantic_ids IS NULL OR cardinality(p_semantic_ids)
               IS DISTINCT FROM cardinality(p_candidate_ids)
               OR p_analysis_kind IS NULL OR p_analysis_kind NOT IN ('synthetic', 'semantic')
               OR p_provider_id IS NULL OR char_length(p_provider_id) NOT BETWEEN 1 AND 100
               OR p_semantic_version IS DISTINCT FROM 'photo-semantics-v2'
               OR p_image_index IS NULL OR p_image_index NOT BETWEEN 1 AND 3
               OR (p_analysis_kind = 'semantic' AND (
                   array_position(p_semantic_ids, NULL) IS NOT NULL
                   OR lower(p_provider_id) LIKE '%synthetic%')) THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            PERFORM pg_catalog.pg_advisory_xact_lock(
                pg_catalog.hashtextextended('photo-fs-v1|' || p_job_id, 0));
            SELECT status INTO v_status FROM dev_eval.photo_jobs
            WHERE job_id=p_job_id AND profile_id=p_profile_id FOR UPDATE;
            IF NOT FOUND OR v_status NOT IN ('running','succeeded') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            v_count := dev_eval.record_photo_candidate_batch_v2(
                p_job_id, p_profile_id, p_candidate_ids, p_trait_ids, p_texts_ko, p_digests);
            IF NOT EXISTS (SELECT 1 FROM dev_eval.photo_job_image_slots slot
                WHERE slot.job_id = p_job_id AND slot.profile_id = p_profile_id
                  AND slot.image_index = p_image_index AND slot.state = 'stored') THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;
            UPDATE dev_eval.photo_trait_candidates stored SET
                analysis_kind = p_analysis_kind, provider_id = p_provider_id,
                semantic_version = p_semantic_version, semantic_id = u.semantic_id,
                image_index = p_image_index
            FROM unnest(p_candidate_ids, p_semantic_ids) AS u(candidate_id, semantic_id)
            WHERE stored.job_id = p_job_id AND stored.candidate_id = u.candidate_id;
            RETURN v_count;
        END $function$;

        CREATE FUNCTION dev_eval.list_photo_candidates_v3(p_job_id text, p_profile_id text)
        RETURNS TABLE (job_id text, candidate_id text, trait_id text, text_ko text,
            candidate_set_sha256 text, edited_text_ko text, excluded boolean, provenance text,
            analysis_kind text, provider_id text, semantic_version text, semantic_id text,
            image_index integer)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
        BEGIN
            IF session_user <> 'itda_photo_service' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '42501';
            END IF;
            RETURN QUERY SELECT stored.job_id, stored.candidate_id, stored.trait_id, stored.text_ko,
                stored.candidate_set_sha256, stored.edited_text_ko, stored.excluded,
                stored.provenance,
                stored.analysis_kind, stored.provider_id, stored.semantic_version,
                stored.semantic_id, stored.image_index
            FROM dev_eval.photo_trait_candidates stored JOIN dev_eval.photo_jobs job
              ON job.job_id = stored.job_id
            WHERE job.job_id = p_job_id AND job.profile_id = p_profile_id
            ORDER BY stored.recorded_at, stored.candidate_id;
        END $function$;

    """)
    # Preserve every existing owner, success, receipt and image-slot guard.
    # The old service-only function cannot be called from another definer:
    # its owner deliberately has no EXECUTE privilege. Reuse its verified
    # source guard prefix in the new version instead of widening that ACL.
    legacy_body = (
        op.get_bind()
        .execute(
            text(
                "SELECT prosrc FROM pg_catalog.pg_proc WHERE oid = "
                "'dev_eval.read_photo_recommendation_projection_v1(text,text)'::regprocedure"
            )
        )
        .scalar_one()
    )
    if legacy_body.count("RETURN QUERY") != 1:
        raise RuntimeError("photo projection authority source drifted")
    guard_prefix = legacy_body.split("RETURN QUERY", 1)[0]
    op.execute(
        """
        CREATE FUNCTION dev_eval.read_photo_recommendation_projection_v2(
            p_job_id text, p_profile_id text)
        RETURNS TABLE (draft_digest text, included_count integer, images_count integer,
            confirmation_seq integer, trait_id text, text_ko text, analysis_kind text,
            provider_id text, semantic_version text, semantic_id text, image_index integer)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
    """
        + guard_prefix
        + """
        RETURN QUERY SELECT v_draft_digest, v_included_count, v_stored_count,
            confirmed.confirmation_seq, confirmed.trait_id, confirmed.text_ko,
            candidate.analysis_kind, candidate.provider_id, candidate.semantic_version,
            candidate.semantic_id, candidate.image_index
        FROM dev_eval.photo_confirmed_traits confirmed
        JOIN dev_eval.photo_trait_candidates candidate ON candidate.job_id = confirmed.job_id
          AND candidate.candidate_id = confirmed.source_candidate_id
        WHERE confirmed.job_id = p_job_id AND confirmed.included
          AND NOT confirmed.text_ko_is_blank AND btrim(confirmed.text_ko) <> ''
        ORDER BY confirmed.confirmation_seq;
        END $function$;
    """
    )
    for signature in _FUNCTIONS:
        op.execute(f"ALTER FUNCTION dev_eval.{signature} OWNER TO itda_photo_write_authority")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM PUBLIC")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM itda_photo_write_authority")
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM CURRENT_USER")
        op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{signature} TO itda_photo_service")


def downgrade() -> None:
    for signature in reversed(_FUNCTIONS):
        op.execute(f"DROP FUNCTION dev_eval.{signature}")
    op.execute("""
        ALTER TABLE dev_eval.photo_trait_candidates DROP CONSTRAINT photo_semantic_provenance,
        DROP COLUMN image_index, DROP COLUMN semantic_id, DROP COLUMN semantic_version,
        DROP COLUMN provider_id, DROP COLUMN analysis_kind;
    """)
