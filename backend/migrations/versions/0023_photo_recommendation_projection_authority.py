"""Expose one owned, confirmed photo projection to recommendation creation."""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0023_photo_recommendation_projection_authority"
down_revision = "0022_questionnaire_v2_choice_answers"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OWNER = "itda_photo_write_authority"
_SERVICE = "itda_photo_service"
_FUNCTION = "dev_eval.read_photo_recommendation_projection_v1(text,text)"


def _configured_identifier(name: str) -> str:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RuntimeError("photo recommendation authority configuration rejected")
    return value


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def upgrade() -> None:
    runtime = _quote(_configured_identifier("runtime_role"))
    builder = _quote(_configured_identifier("label_builder_role"))
    op.execute(
        """
        CREATE FUNCTION dev_eval.read_photo_recommendation_projection_v1(
            p_job_id text, p_profile_id text
        ) RETURNS TABLE (
            draft_digest text, included_count integer, images_count integer,
            confirmation_seq integer, trait_id text, text_ko text
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp AS $function$
        DECLARE
            v_status text;
            v_receipt_count integer;
            v_draft_digest text;
            v_included_count integer;
            v_confirmed_count integer;
            v_slot_count integer;
            v_stored_count integer;
            v_min_index integer;
            v_max_index integer;
        BEGIN
            IF session_user <> 'itda_photo_service' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '42501';
            END IF;
            IF p_job_id IS NULL OR p_job_id !~ '^[0-9a-f]{64}$'
               OR p_profile_id IS NULL
               OR char_length(p_profile_id) NOT BETWEEN 1 AND 160 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;

            SELECT stored.status INTO v_status
            FROM dev_eval.photo_jobs stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            IF v_status IS DISTINCT FROM 'succeeded' THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;

            SELECT count(*), min(stored.draft_digest), min(stored.included_count)
            INTO v_receipt_count, v_draft_digest, v_included_count
            FROM dev_eval.photo_confirmation_receipts stored
            WHERE stored.job_id = p_job_id AND stored.profile_id = p_profile_id;
            IF v_receipt_count <> 1 OR v_included_count NOT BETWEEN 1 AND 6 THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;

            SELECT count(*) INTO v_confirmed_count
            FROM dev_eval.photo_confirmed_traits stored
            WHERE stored.job_id = p_job_id
              AND stored.included
              AND NOT stored.text_ko_is_blank
              AND btrim(stored.text_ko) <> '';
            IF v_confirmed_count <> v_included_count THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;

            SELECT count(*), count(*) FILTER (WHERE slot.state = 'stored'),
                   min(slot.image_index), max(slot.image_index)
            INTO v_slot_count, v_stored_count, v_min_index, v_max_index
            FROM dev_eval.photo_job_image_slots slot
            WHERE slot.job_id = p_job_id AND slot.profile_id = p_profile_id;
            IF v_slot_count NOT BETWEEN 1 AND 3 OR v_stored_count <> v_slot_count
               OR v_min_index <> 1 OR v_max_index <> v_slot_count THEN
                RAISE EXCEPTION 'photo operation rejected' USING ERRCODE = '23514';
            END IF;

            RETURN QUERY
            SELECT v_draft_digest, v_included_count, v_stored_count,
                   stored.confirmation_seq, stored.trait_id, stored.text_ko
            FROM dev_eval.photo_confirmed_traits stored
            WHERE stored.job_id = p_job_id
              AND stored.included
              AND NOT stored.text_ko_is_blank
              AND btrim(stored.text_ko) <> ''
            ORDER BY stored.confirmation_seq;
        END $function$;
        """
    )
    op.execute(f"ALTER FUNCTION {_FUNCTION} OWNER TO {_OWNER}")
    op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM PUBLIC")
    op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM {runtime}")
    op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM {builder}")
    op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM {_OWNER}")
    op.execute(f"REVOKE ALL ON FUNCTION {_FUNCTION} FROM CURRENT_USER")
    op.execute(f"GRANT EXECUTE ON FUNCTION {_FUNCTION} TO {_SERVICE}")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {_FUNCTION}")
