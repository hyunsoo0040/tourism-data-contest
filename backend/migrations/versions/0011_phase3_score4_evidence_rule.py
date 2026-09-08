"""Restore lane-independent distinct evidence for Phase 3 score four."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0011_phase3_score4_evidence_rule"
down_revision = "0010_phase3_profile_release_build_reconciliation"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EVALUATOR_CAPABILITIES = ("evaluator_a", "evaluator_b", "evaluator_c")
_PRIOR_SCORE_FOUR_PREDICATE = """NOT (
                        coalesce(cardinality(direct_lanes), 0) = 1
                        AND coalesce(cardinality(direct_clusters), 0) >= 2
                        OR coalesce(description_keys, ARRAY[]::text[])
                           && coalesce(odii_keys, ARRAY[]::text[])
                    )"""
_CORRECTED_SCORE_FOUR_PREDICATE = "coalesce(cardinality(direct_clusters), 0) < 2"


def _configured_identifier(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid PostgreSQL identifier for {name}")
    return value


def _quoted_identifier(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _configured_evaluator_roles() -> tuple[str, ...]:
    return tuple(
        role
        for capability in _EVALUATOR_CAPABILITIES
        if (role := _configured_identifier(f"label_{capability}_role")) is not None
    )


def _grant(statement: str, *roles: str) -> None:
    if not roles:
        return
    quoted = ", ".join(_quoted_identifier(role) for role in roles)
    op.execute(sa.text(f"{statement} TO {quoted}"))


def _submit_label_revision_sql(score_four_predicate: str) -> str:
    return f"""
        CREATE OR REPLACE FUNCTION dev_eval.submit_label_revision_v1(candidate_payload jsonb)
        RETURNS TABLE(revision_sha256 text, evaluator_principal text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $function$
        DECLARE
            normalized_payload jsonb;
            candidate_sha256 text;
            candidate_receipt_sha256 text;
            parent_row dev_eval.label_revisions%ROWTYPE;
            attribute_order text[];
            judgment jsonb;
            score_value integer;
            evidence_item jsonb;
            direct_count integer;
            direct_lanes text[];
            direct_clusters text[];
            description_keys text[];
            odii_keys text[];
            submitted_at_value timestamptz;
        BEGIN
            IF jsonb_typeof(candidate_payload) IS DISTINCT FROM 'object' THEN
                RAISE EXCEPTION 'label revision payload must be an object'
                    USING ERRCODE = '22023';
            END IF;
            IF candidate_payload ?| ARRAY[
                'actor_id', 'role', 'evaluator_principal', 'evaluator_pseudonym'
            ] THEN
                RAISE EXCEPTION 'client identity fields are forbidden'
                    USING ERRCODE = '22023';
            END IF;
            IF candidate_payload - ARRAY[
                'assignment_id', 'rubric_version', 'source_snapshot_version',
                'primary_axis', 'primary_axis_judgment', 'parent_revision_sha256',
                'correction_reason', 'submitted_at', 'judgments'
            ] <> '{{}}'::jsonb THEN
                RAISE EXCEPTION 'label revision payload has unknown fields'
                    USING ERRCODE = '22023';
            END IF;
            IF NOT candidate_payload ?& ARRAY[
                    'assignment_id', 'rubric_version', 'source_snapshot_version',
                    'parent_revision_sha256', 'correction_reason', 'submitted_at',
                    'judgments'
               ]
               OR (CASE WHEN candidate_payload ? 'primary_axis' THEN 1 ELSE 0 END
                   + CASE WHEN candidate_payload ? 'primary_axis_judgment' THEN 1 ELSE 0 END) <> 1
               OR jsonb_typeof(candidate_payload->'assignment_id') IS DISTINCT FROM 'string'
               OR length(candidate_payload->>'assignment_id') NOT BETWEEN 1 AND 160
               OR jsonb_typeof(candidate_payload->'rubric_version') IS DISTINCT FROM 'string'
               OR length(candidate_payload->>'rubric_version') NOT BETWEEN 1 AND 128
               OR candidate_payload->>'rubric_version'
                  !~ '^[a-z0-9][a-z0-9._-]*$'
               OR jsonb_typeof(candidate_payload->'source_snapshot_version')
                  IS DISTINCT FROM 'string'
               OR length(candidate_payload->>'source_snapshot_version') NOT BETWEEN 1 AND 128
               OR candidate_payload->>'source_snapshot_version'
                  !~ '^[a-z0-9][a-z0-9._-]*$'
               OR jsonb_typeof(candidate_payload->'parent_revision_sha256')
                  NOT IN ('null', 'string')
               OR (
                    jsonb_typeof(candidate_payload->'parent_revision_sha256') = 'string'
                    AND candidate_payload->>'parent_revision_sha256' !~ '^[0-9a-f]{{64}}$'
               )
               OR jsonb_typeof(candidate_payload->'correction_reason')
                  NOT IN ('null', 'string')
               OR (
                    jsonb_typeof(candidate_payload->'correction_reason') = 'string'
                    AND (
                        length(candidate_payload->>'correction_reason') NOT BETWEEN 1 AND 300
                        OR candidate_payload->>'correction_reason'
                           IS DISTINCT FROM btrim(
                                candidate_payload->>'correction_reason', E' \t\n\r\f\v'
                           )
                    )
               )
               OR jsonb_typeof(candidate_payload->'submitted_at') IS DISTINCT FROM 'string'
               OR candidate_payload->>'submitted_at'
                  !~ 'T.+(Z|[+]00:00)$'
               OR jsonb_typeof(candidate_payload->'judgments') IS DISTINCT FROM 'array'
               OR jsonb_array_length(candidate_payload->'judgments') <> 12 THEN
                RAISE EXCEPTION 'label revision payload is incomplete'
                    USING ERRCODE = '22023';
            END IF;
            IF jsonb_typeof(
                    coalesce(candidate_payload->'primary_axis',
                             candidate_payload->'primary_axis_judgment')
               ) NOT IN ('null', 'string') THEN
                RAISE EXCEPTION 'primary axis has invalid type' USING ERRCODE = '22023';
            END IF;
            IF coalesce(candidate_payload->>'primary_axis',
                        candidate_payload->>'primary_axis_judgment') IS NOT NULL
               AND coalesce(candidate_payload->>'primary_axis',
                            candidate_payload->>'primary_axis_judgment') NOT IN (
                    'HISTORY_TRADITION', 'EMOTION_IMAGE', 'REST_IMMERSION'
               ) THEN
                RAISE EXCEPTION 'primary axis is outside the closed vocabulary'
                    USING ERRCODE = '22023';
            END IF;
            BEGIN
                submitted_at_value := (candidate_payload->>'submitted_at')::timestamptz;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION 'submitted_at must be a valid UTC timestamp'
                    USING ERRCODE = '22023';
            END;

            SELECT array_agg(item->>'attribute_id' ORDER BY ordinal)
              INTO attribute_order
              FROM jsonb_array_elements(candidate_payload->'judgments')
                   WITH ORDINALITY AS entry(item, ordinal);
            IF attribute_order IS DISTINCT FROM ARRAY[
                'H1','H2','H3','H4','I1','I2','I3','I4','R1','R2','R3','R4'
            ] THEN
                RAISE EXCEPTION 'judgments must use canonical H1-R4 order'
                    USING ERRCODE = '22023';
            END IF;

            FOR judgment IN SELECT value FROM jsonb_array_elements(candidate_payload->'judgments')
            LOOP
                IF jsonb_typeof(judgment) IS DISTINCT FROM 'object'
                   OR judgment - ARRAY[
                    'attribute_id', 'score', 'unknown_reason', 'unknown_note', 'evidence'
                   ] <> '{{}}'::jsonb
                   OR NOT judgment ? 'attribute_id'
                   OR jsonb_typeof(judgment->'attribute_id') IS DISTINCT FROM 'string'
                   OR NOT judgment ? 'score'
                   OR jsonb_typeof(judgment->'evidence') IS DISTINCT FROM 'array' THEN
                    RAISE EXCEPTION 'judgment has invalid fields'
                        USING ERRCODE = '22023';
                END IF;
                IF jsonb_typeof(judgment->'score') IS NOT DISTINCT FROM 'null' THEN
                    IF jsonb_typeof(judgment->'unknown_note') IS DISTINCT FROM 'string'
                       OR judgment->>'unknown_reason' NOT IN (
                        'NO_EVIDENCE', 'INSUFFICIENT_EVIDENCE',
                        'CONFLICTING_EVIDENCE', 'OUT_OF_SCOPE_INFORMATION'
                       ) IS NOT FALSE
                       OR length(judgment->>'unknown_note') NOT BETWEEN 1 AND 300
                       OR judgment->>'unknown_note' IS DISTINCT FROM btrim(
                            judgment->>'unknown_note', E' \t\n\r\f\v'
                       ) THEN
                        RAISE EXCEPTION 'unknown judgment requires closed reason and note'
                            USING ERRCODE = '22023';
                    END IF;
                ELSE
                    IF jsonb_typeof(judgment->'score') IS DISTINCT FROM 'number'
                       OR judgment->>'score' !~ '^[0-4]$' THEN
                        RAISE EXCEPTION 'score must be an integer' USING ERRCODE = '22023';
                    END IF;
                    score_value := (judgment->>'score')::integer;
                    IF score_value NOT BETWEEN 0 AND 4
                       OR judgment->>'unknown_reason' IS NOT NULL
                       OR judgment->>'unknown_note' IS NOT NULL THEN
                        RAISE EXCEPTION 'numeric judgment violates score contract'
                            USING ERRCODE = '22023';
                    END IF;
                    IF score_value = 0 AND NOT EXISTS (
                        SELECT 1 FROM jsonb_array_elements(judgment->'evidence') AS evidence(value)
                         WHERE value->>'supports_absence' = 'true'
                            OR value->>'complete_context' = 'true'
                    ) THEN
                        RAISE EXCEPTION 'zero requires confirmed-absence evidence'
                            USING ERRCODE = '22023';
                    END IF;
                    SELECT count(*) FILTER (WHERE value->>'direct' = 'true'),
                           array_agg(DISTINCT value->>'lane')
                               FILTER (WHERE value->>'direct' = 'true'),
                           array_agg(DISTINCT value->>'dedup_cluster_id')
                               FILTER (WHERE value->>'direct' = 'true'),
                           array_agg(DISTINCT value->>'concordance_key')
                               FILTER (WHERE value->>'direct' = 'true'
                                       AND value->>'lane' = 'DESCRIPTION'),
                           array_agg(DISTINCT value->>'concordance_key')
                               FILTER (WHERE value->>'direct' = 'true'
                                       AND value->>'lane' = 'ODII')
                      INTO direct_count, direct_lanes, direct_clusters,
                           description_keys, odii_keys
                      FROM jsonb_array_elements(judgment->'evidence') AS evidence(value);
                    IF score_value = 3 AND coalesce(direct_count, 0) = 0 THEN
                        RAISE EXCEPTION 'score three requires direct evidence'
                            USING ERRCODE = '22023';
                    END IF;
                    IF score_value = 4 AND {score_four_predicate} THEN
                        RAISE EXCEPTION 'score four lacks distinct or concordant evidence'
                            USING ERRCODE = '22023';
                    END IF;
                END IF;
                FOR evidence_item IN SELECT value FROM jsonb_array_elements(judgment->'evidence')
                LOOP
                    IF jsonb_typeof(evidence_item) IS DISTINCT FROM 'object'
                       OR evidence_item - ARRAY[
                            'evidence_id', 'source_id', 'lane', 'dedup_cluster_id',
                            'direct', 'concordance_key', 'supports_absence',
                            'complete_context'
                       ] <> '{{}}'::jsonb
                       OR NOT evidence_item ?& ARRAY[
                            'evidence_id', 'source_id', 'lane', 'dedup_cluster_id',
                            'direct', 'concordance_key', 'supports_absence',
                            'complete_context'
                       ]
                       OR jsonb_typeof(evidence_item->'lane') IS DISTINCT FROM 'string'
                       OR evidence_item->>'lane' NOT IN ('DESCRIPTION', 'ODII')
                       OR jsonb_typeof(evidence_item->'evidence_id') IS DISTINCT FROM 'string'
                       OR length(evidence_item->>'evidence_id') NOT BETWEEN 1 AND 160
                       OR jsonb_typeof(evidence_item->'source_id') IS DISTINCT FROM 'string'
                       OR length(evidence_item->>'source_id') NOT BETWEEN 1 AND 160
                       OR jsonb_typeof(evidence_item->'dedup_cluster_id')
                          IS DISTINCT FROM 'string'
                       OR length(evidence_item->>'dedup_cluster_id') NOT BETWEEN 1 AND 160
                       OR jsonb_typeof(evidence_item->'concordance_key')
                          IS DISTINCT FROM 'string'
                       OR length(evidence_item->>'concordance_key') NOT BETWEEN 1 AND 160
                       OR jsonb_typeof(evidence_item->'direct') IS DISTINCT FROM 'boolean'
                       OR jsonb_typeof(evidence_item->'supports_absence')
                          IS DISTINCT FROM 'boolean'
                       OR jsonb_typeof(evidence_item->'complete_context')
                          IS DISTINCT FROM 'boolean' THEN
                        RAISE EXCEPTION 'evidence reference is invalid'
                            USING ERRCODE = '22023';
                    END IF;
                END LOOP;
            END LOOP;

            IF (candidate_payload->>'parent_revision_sha256' IS NULL)
               <> (candidate_payload->>'correction_reason' IS NULL) THEN
                RAISE EXCEPTION 'correction parent and reason must be paired'
                    USING ERRCODE = '22023';
            END IF;
            IF candidate_payload->>'parent_revision_sha256' IS NOT NULL THEN
                SELECT * INTO parent_row
                  FROM dev_eval.label_revisions
                 WHERE label_revisions.revision_sha256 =
                       candidate_payload->>'parent_revision_sha256'
                   AND label_revisions.evaluator_principal = session_user
                   AND label_revisions.assignment_id = candidate_payload->>'assignment_id';
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'correction parent is not owned by this principal'
                        USING ERRCODE = '22023';
                END IF;
            END IF;

            normalized_payload := candidate_payload
                - 'primary_axis_judgment'
                || jsonb_build_object(
                    'primary_axis', coalesce(candidate_payload->'primary_axis',
                                             candidate_payload->'primary_axis_judgment',
                                             'null'::jsonb)
                );
            candidate_sha256 := encode(
                sha256(convert_to(session_user || E'\n' || normalized_payload::text, 'UTF8')),
                'hex'
            );
            candidate_receipt_sha256 := encode(
                sha256(convert_to(candidate_sha256 || E'\nreceipt-v1', 'UTF8')),
                'hex'
            );
            INSERT INTO dev_eval.label_revisions (
                revision_sha256, receipt_sha256, assignment_id, evaluator_principal,
                parent_revision_sha256, correction_reason, payload, submitted_at
            ) VALUES (
                candidate_sha256, candidate_receipt_sha256,
                normalized_payload->>'assignment_id', session_user,
                normalized_payload->>'parent_revision_sha256',
                normalized_payload->>'correction_reason', normalized_payload,
                submitted_at_value
            ) ON CONFLICT ON CONSTRAINT pk_phase3_label_revisions DO NOTHING;
            RETURN QUERY SELECT candidate_sha256, session_user::text;
        END;
        $function$
    """


def _replace_submit_function(score_four_predicate: str) -> None:
    op.execute(_submit_label_revision_sql(score_four_predicate))
    op.execute("REVOKE ALL ON FUNCTION dev_eval.submit_label_revision_v1(jsonb) FROM PUBLIC")
    _grant(
        "GRANT EXECUTE ON FUNCTION dev_eval.submit_label_revision_v1(jsonb)",
        *_configured_evaluator_roles(),
    )


def upgrade() -> None:
    _replace_submit_function(_CORRECTED_SCORE_FOUR_PREDICATE)


def downgrade() -> None:
    _replace_submit_function(_PRIOR_SCORE_FOUR_PREDICATE)
