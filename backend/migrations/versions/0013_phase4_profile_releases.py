"""Persist immutable Phase 4 successor releases and exact predecessor proofs."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0013_phase4_profile_releases"
down_revision = "0012_phase3_profile_pin_provenance"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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


def _grant(statement: str, role: str | None) -> None:
    if role is not None:
        op.execute(sa.text(f"{statement} TO {_quoted_identifier(role)}"))


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    approver = _configured_identifier("label_approver_role")

    op.execute(
        """
        CREATE FUNCTION dev_eval.canonical_jsonb_compact_v2(value jsonb)
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        STRICT
        SET search_path = pg_catalog
        AS $$
            SELECT CASE jsonb_typeof(value)
                WHEN 'object' THEN COALESCE((
                    SELECT '{' || string_agg(
                        to_json(key)::text || ':' ||
                        dev_eval.canonical_jsonb_compact_v2(item),
                        ',' ORDER BY key COLLATE "C"
                    ) || '}'
                    FROM jsonb_each(value) AS entries(key, item)
                ), '{}')
                WHEN 'array' THEN COALESCE((
                    SELECT '[' || string_agg(
                        dev_eval.canonical_jsonb_compact_v2(item),
                        ',' ORDER BY ordinal
                    ) || ']'
                    FROM jsonb_array_elements(value)
                    WITH ORDINALITY AS entries(item, ordinal)
                ), '[]')
                ELSE value::text
            END
        $$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_candidate_payload_v2(
            candidate jsonb
        ) RETURNS boolean
        LANGUAGE plpgsql
        IMMUTABLE
        STRICT
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            member jsonb;
            fused_profile jsonb;
            attribute jsonb;
            lane jsonb;
            axis jsonb;
            confidence_axis jsonb;
            lineage jsonb;
            policy jsonb;
            expected_axis text;
            expected_base_weight integer;
            total_effective bigint;
            total_contribution bigint;
            display_total integer;
            expected_score integer;
            expected_axis_score integer;
            minimum_confidence integer;
            top_axis text;
            second_axis text;
            top_score integer;
            second_score integer;
            expected_label_state text;
            expected_label_id text;
            expected_label_ko text;
            expected_label_axes jsonb;
            expected_predecessor_member_set_sha256 text;
            expected_release_sha256 text;
            required_keys text[] := ARRAY[
                'schema_version', 'release_id', 'state', 'builder_principal',
                'adoption_state', 'adopted_attributes',
                'confidence_is_ranking_input', 'fusion_policy', 'lineage',
                'cohort', 'predecessor_member_set_sha256', 'release_sha256'
            ];
            required_lineage_keys text[] := ARRAY[
                'schema_version', 'predecessor_release_sha256',
                'predecessor_lifecycle_receipt_sha256',
                'canonical_lineage_sha256', 'dev_lineage_sha256',
                'rights_manifest_sha256', 'source_manifest_sha256',
                'reviewed_manifest_sha256', 'lane_baseline_sha256',
                'image_selection_manifest_sha256', 'prediction_batch_sha256',
                'prediction_freeze_receipt_sha256', 'provisional_report_sha256',
                'final_report_sha256', 'human_review_manifest_sha256',
                'zero_image_fallback_sha256', 'fusion_policy_sha256',
                'profile_schema_sha256', 'code_sha256', 'config_sha256',
                'lineage_sha256'
            ];
            required_lineage_digest_keys text[] := ARRAY[
                'predecessor_release_sha256',
                'predecessor_lifecycle_receipt_sha256',
                'canonical_lineage_sha256',
                'dev_lineage_sha256', 'rights_manifest_sha256',
                'source_manifest_sha256', 'reviewed_manifest_sha256',
                'lane_baseline_sha256', 'image_selection_manifest_sha256',
                'prediction_batch_sha256', 'prediction_freeze_receipt_sha256',
                'provisional_report_sha256', 'final_report_sha256',
                'fusion_policy_sha256', 'profile_schema_sha256',
                'code_sha256', 'config_sha256', 'lineage_sha256'
            ];
            required_member_keys text[] := ARRAY[
                'place_ref', 'predecessor_profile_sha256',
                'predecessor_member_sha256', 'media_state',
                'image_selection_member_sha256',
                'prediction_observation_sha256', 'fused_profile', 'member_sha256'
            ];
            required_fused_profile_keys text[] := ARRAY[
                'schema_version', 'place_ref', 'predecessor_profile_sha256',
                'baseline_member_sha256', 'image_observation_sha256',
                'attributes', 'axes', 'mismatch_traits', 'inherited_evidence',
                'mismatch_lineage_rule', 'confidence', 'display_label',
                'policy_sha256', 'profile_fusion_sha256'
            ];
            digest_key text;
            canonical_policy_sha256 constant text :=
                '301e8f953af5f606ce332fbc1c1bf1f83' ||
                '46e86dee97bad8caac33e4c64ed2d7a';
        BEGIN
            lineage := candidate -> 'lineage';
            policy := candidate -> 'fusion_policy';
            IF jsonb_typeof(candidate) IS DISTINCT FROM 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(candidate)) IS DISTINCT FROM 12
               OR NOT candidate ?& required_keys
               OR candidate ->> 'schema_version'
                    IS DISTINCT FROM 'itda.profile-release-candidate.v2'
               OR candidate ->> 'state' IS DISTINCT FROM 'BUILT_UNAPPROVED'
               OR jsonb_typeof(candidate -> 'release_id') IS DISTINCT FROM 'string'
               OR candidate ->> 'release_id' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
               OR jsonb_typeof(candidate -> 'builder_principal') IS DISTINCT FROM 'string'
               OR candidate ->> 'builder_principal'
                    !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
               OR jsonb_typeof(candidate -> 'adoption_state') IS DISTINCT FROM 'string'
               OR NOT (candidate ->> 'adoption_state' = ANY (ARRAY[
                    'ADOPT', 'CONDITIONAL_ADOPT',
                    'IMAGE_REJECTED_TEXT_ODII_ONLY', 'NO_IMAGE_TEXT_ODII_ONLY'
               ]))
               OR jsonb_typeof(candidate -> 'adopted_attributes') IS DISTINCT FROM 'array'
               OR candidate -> 'confidence_is_ranking_input' IS DISTINCT FROM 'false'::jsonb
               OR jsonb_typeof(policy) IS DISTINCT FROM 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(policy)) IS DISTINCT FROM 37
               OR policy ->> 'schema_version'
                    IS DISTINCT FROM 'itda.profile-fusion-policy.v1'
               OR policy ->> 'mode' IS DISTINCT FROM 'CANONICAL_RELEASE'
               OR policy -> 'release_eligible' IS DISTINCT FROM 'true'::jsonb
               OR policy ->> 'policy_sha256'
                    IS DISTINCT FROM canonical_policy_sha256
               OR encode(sha256(convert_to(
                    dev_eval.canonical_jsonb_compact_v2(policy - 'policy_sha256'),
                    'UTF8'
               )), 'hex') IS DISTINCT FROM canonical_policy_sha256
               OR jsonb_typeof(candidate -> 'cohort') IS DISTINCT FROM 'array'
               OR jsonb_array_length(candidate -> 'cohort') IS DISTINCT FROM 24
               OR jsonb_typeof(lineage) IS DISTINCT FROM 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(lineage)) IS DISTINCT FROM 21
               OR NOT lineage ?& required_lineage_keys
               OR lineage ->> 'schema_version'
                    IS DISTINCT FROM 'itda.profile-release-lineage.v2'
               OR lineage ->> 'fusion_policy_sha256'
                    IS DISTINCT FROM canonical_policy_sha256
               OR NOT (
                    jsonb_typeof(lineage -> 'human_review_manifest_sha256') = 'null'
                    OR (
                        jsonb_typeof(lineage -> 'human_review_manifest_sha256') = 'string'
                        AND lineage ->> 'human_review_manifest_sha256' ~ '^[0-9a-f]{64}$'
                    )
               )
               OR NOT (
                    jsonb_typeof(lineage -> 'zero_image_fallback_sha256') = 'null'
                    OR (
                        jsonb_typeof(lineage -> 'zero_image_fallback_sha256') = 'string'
                        AND lineage ->> 'zero_image_fallback_sha256' ~ '^[0-9a-f]{64}$'
                    )
               )
               OR candidate ->> 'predecessor_member_set_sha256' !~ '^[0-9a-f]{64}$'
               OR candidate ->> 'release_sha256' !~ '^[0-9a-f]{64}$' THEN
                RETURN false;
            END IF;
            FOREACH digest_key IN ARRAY required_lineage_digest_keys LOOP
                IF jsonb_typeof(lineage -> digest_key) IS DISTINCT FROM 'string'
                   OR lineage ->> digest_key !~ '^[0-9a-f]{64}$' THEN
                    RETURN false;
                END IF;
            END LOOP;
            IF encode(sha256(convert_to(
                    dev_eval.canonical_jsonb_compact_v2(lineage - 'lineage_sha256'),
                    'UTF8'
               )), 'hex') IS DISTINCT FROM lineage ->> 'lineage_sha256'
               OR EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(candidate -> 'adopted_attributes') AS rows(item)
                    WHERE jsonb_typeof(item) IS DISTINCT FROM 'string'
                       OR NOT (item #>> '{}' = ANY (ARRAY[
                            'H1', 'H2', 'H3', 'H4', 'I1', 'I2',
                            'I3', 'I4', 'R1', 'R2', 'R3', 'R4'
                       ]))
               )
               OR (SELECT count(*) FROM jsonb_array_elements(candidate -> 'adopted_attributes'))
                    IS DISTINCT FROM (
                        SELECT count(DISTINCT item #>> '{}')
                        FROM jsonb_array_elements(candidate -> 'adopted_attributes') AS rows(item)
                    )
               OR (
                    candidate ->> 'adoption_state' = 'ADOPT'
                    AND candidate -> 'adopted_attributes' IS DISTINCT FROM
                        '["H1","H2","H3","H4","I1","I2","I3","I4","R1","R2","R3","R4"]'::jsonb
               )
               OR (
                    candidate ->> 'adoption_state' = 'CONDITIONAL_ADOPT'
                    AND jsonb_array_length(candidate -> 'adopted_attributes') = 0
               )
               OR (
                    candidate ->> 'adoption_state' IN (
                        'IMAGE_REJECTED_TEXT_ODII_ONLY', 'NO_IMAGE_TEXT_ODII_ONLY'
                    )
                    AND candidate -> 'adopted_attributes' IS DISTINCT FROM '[]'::jsonb
               ) THEN
                RETURN false;
            END IF;
            FOR member IN SELECT value FROM jsonb_array_elements(candidate -> 'cohort') LOOP
                fused_profile := member -> 'fused_profile';
                IF jsonb_typeof(member) IS DISTINCT FROM 'object'
                   OR (SELECT count(*) FROM jsonb_object_keys(member)) IS DISTINCT FROM 8
                   OR NOT member ?& required_member_keys
                   OR jsonb_typeof(member -> 'place_ref') IS DISTINCT FROM 'string'
                   OR length(member ->> 'place_ref') NOT BETWEEN 1 AND 200
                   OR jsonb_typeof(member -> 'media_state') IS DISTINCT FROM 'string'
                   OR NOT (member ->> 'media_state' = ANY (ARRAY[
                        'QUALIFIED', 'MISSING', 'EMPTY', 'PROVENANCE_INCOMPLETE',
                        'RIGHTS_RESTRICTED', 'ANALYSIS_FAILED'
                   ]))
                   OR member ->> 'predecessor_profile_sha256' !~ '^[0-9a-f]{64}$'
                   OR member ->> 'predecessor_member_sha256' !~ '^[0-9a-f]{64}$'
                   OR member ->> 'image_selection_member_sha256' !~ '^[0-9a-f]{64}$'
                   OR member ->> 'prediction_observation_sha256' !~ '^[0-9a-f]{64}$'
                   OR member ->> 'member_sha256' !~ '^[0-9a-f]{64}$'
                   OR jsonb_typeof(fused_profile) IS DISTINCT FROM 'object'
                   OR (SELECT count(*) FROM jsonb_object_keys(fused_profile)) IS DISTINCT FROM 14
                   OR NOT fused_profile ?& required_fused_profile_keys
                   OR fused_profile ->> 'schema_version'
                        IS DISTINCT FROM 'itda.fused-profile-projection.v1'
                   OR fused_profile ->> 'place_ref' IS DISTINCT FROM member ->> 'place_ref'
                   OR fused_profile ->> 'predecessor_profile_sha256'
                        IS DISTINCT FROM member ->> 'predecessor_profile_sha256'
                   OR fused_profile ->> 'image_observation_sha256'
                        IS DISTINCT FROM member ->> 'prediction_observation_sha256'
                   OR fused_profile ->> 'policy_sha256'
                        IS DISTINCT FROM canonical_policy_sha256
                   OR fused_profile ->> 'mismatch_lineage_rule'
                        IS DISTINCT FROM 'EXACT_PREDECESSOR_COPY_V1'
                   OR jsonb_typeof(fused_profile -> 'attributes') IS DISTINCT FROM 'array'
                   OR jsonb_array_length(fused_profile -> 'attributes') IS DISTINCT FROM 12
                   OR jsonb_typeof(fused_profile -> 'axes') IS DISTINCT FROM 'array'
                   OR jsonb_array_length(fused_profile -> 'axes') IS DISTINCT FROM 3
                   OR jsonb_typeof(fused_profile -> 'mismatch_traits') IS DISTINCT FROM 'array'
                   OR jsonb_array_length(fused_profile -> 'mismatch_traits') IS DISTINCT FROM 6
                   OR (SELECT array_agg(item ->> 'attribute_id' ORDER BY ordinal)
                       FROM jsonb_array_elements(fused_profile -> 'attributes')
                       WITH ORDINALITY AS rows(item, ordinal)) IS DISTINCT FROM
                        ARRAY['H1','H2','H3','H4','I1','I2','I3','I4','R1','R2','R3','R4']
                   OR (SELECT array_agg(item ->> 'axis_id' ORDER BY ordinal)
                       FROM jsonb_array_elements(fused_profile -> 'axes')
                       WITH ORDINALITY AS rows(item, ordinal)) IS DISTINCT FROM
                        ARRAY['H','E','R']
                   OR fused_profile ->> 'profile_fusion_sha256' !~ '^[0-9a-f]{64}$'
                   OR encode(sha256(convert_to(
                        dev_eval.canonical_jsonb_compact_v2(
                            fused_profile - 'profile_fusion_sha256'
                        ), 'UTF8'
                   )), 'hex') IS DISTINCT FROM fused_profile ->> 'profile_fusion_sha256'
                   OR encode(sha256(convert_to(
                        dev_eval.canonical_jsonb_compact_v2(member - 'member_sha256'),
                        'UTF8'
                   )), 'hex') IS DISTINCT FROM member ->> 'member_sha256' THEN
                    RETURN false;
                END IF;
                FOR attribute IN
                    SELECT value FROM jsonb_array_elements(fused_profile -> 'attributes')
                LOOP
                    IF jsonb_typeof(attribute) IS DISTINCT FROM 'object'
                       OR jsonb_typeof(attribute -> 'lanes') IS DISTINCT FROM 'array'
                       OR jsonb_array_length(attribute -> 'lanes') IS DISTINCT FROM 3
                       OR (SELECT array_agg(item ->> 'lane_id' ORDER BY ordinal)
                           FROM jsonb_array_elements(attribute -> 'lanes')
                           WITH ORDINALITY AS rows(item, ordinal)) IS DISTINCT FROM
                            ARRAY['DESCRIPTION','ODII','IMAGE']
                       OR attribute ->> 'fusion_policy_sha256'
                            IS DISTINCT FROM canonical_policy_sha256
                       OR attribute ->> 'attribute_sha256' !~ '^[0-9a-f]{64}$'
                       OR encode(sha256(convert_to(
                            dev_eval.canonical_jsonb_compact_v2(
                                attribute - 'attribute_sha256'
                            ), 'UTF8'
                       )), 'hex') IS DISTINCT FROM attribute ->> 'attribute_sha256'
                       OR (
                            member ->> 'media_state' <> 'QUALIFIED'
                            AND attribute -> 'lanes' -> 2 -> 'included'
                                IS DISTINCT FROM 'false'::jsonb
                       ) THEN
                        RETURN false;
                    END IF;
                    expected_axis := CASE
                        WHEN attribute ->> 'attribute_id' IN ('H1','H2','H3','H4') THEN 'H'
                        WHEN attribute ->> 'attribute_id' IN ('I1','I2','I3','I4') THEN 'E'
                        ELSE 'R'
                    END;
                    IF attribute ->> 'axis_id' IS DISTINCT FROM expected_axis
                       OR jsonb_typeof(attribute -> 'score_milli') IS DISTINCT FROM 'number'
                       OR (attribute ->> 'score_milli')::integer NOT BETWEEN 0 AND 4000 THEN
                        RETURN false;
                    END IF;
                    total_effective := 0;
                    total_contribution := 0;
                    display_total := 0;
                    FOR lane IN SELECT value FROM jsonb_array_elements(attribute -> 'lanes') LOOP
                        expected_base_weight := CASE
                            WHEN expected_axis = 'H' AND lane ->> 'lane_id' = 'DESCRIPTION'
                                THEN 3500
                            WHEN expected_axis = 'H' AND lane ->> 'lane_id' = 'ODII'
                                THEN 4500
                            WHEN expected_axis = 'H' THEN 2000
                            WHEN expected_axis = 'E' AND lane ->> 'lane_id' = 'DESCRIPTION'
                                THEN 2000
                            WHEN expected_axis = 'E' AND lane ->> 'lane_id' = 'ODII'
                                THEN 1000
                            WHEN expected_axis = 'E' THEN 7000
                            WHEN lane ->> 'lane_id' = 'DESCRIPTION' THEN 3500
                            WHEN lane ->> 'lane_id' = 'ODII' THEN 1500
                            ELSE 5000
                        END;
                        IF jsonb_typeof(lane) IS DISTINCT FROM 'object'
                           OR (SELECT count(*) FROM jsonb_object_keys(lane)) IS DISTINCT FROM 14
                           OR (lane ->> 'base_weight_bp')::integer IS DISTINCT FROM
                                expected_base_weight
                           OR (lane ->> 'fidelity_bp')::integer NOT BETWEEN 0 AND 10000
                           OR (lane ->> 'normalized_weight_numerator')::bigint IS DISTINCT FROM
                                (lane ->> 'effective_weight_numerator')::bigint
                           OR (lane ->> 'contribution_denominator')::bigint IS DISTINCT FROM
                                (lane ->> 'normalized_weight_denominator')::bigint
                           OR jsonb_typeof(lane -> 'evidence_refs') IS DISTINCT FROM 'array' THEN
                            RETURN false;
                        END IF;
                        IF lane -> 'included' = 'true'::jsonb THEN
                            IF jsonb_typeof(lane -> 'score_milli') IS DISTINCT FROM 'number'
                               OR jsonb_typeof(lane -> 'exclusion_reason') <> 'null'
                               OR (lane ->> 'quality_bp')::integer <> 10000
                               OR (lane ->> 'effective_weight_numerator')::bigint < 1
                               OR (lane ->> 'effective_weight_numerator')::bigint <>
                                    (lane ->> 'base_weight_bp')::bigint
                                    * (lane ->> 'fidelity_bp')::bigint * 10000
                               OR (lane ->> 'contribution_numerator')::bigint <>
                                    (lane ->> 'score_milli')::bigint
                                    * (lane ->> 'effective_weight_numerator')::bigint THEN
                                RETURN false;
                            END IF;
                        ELSIF lane -> 'included' = 'false'::jsonb THEN
                            IF jsonb_typeof(lane -> 'score_milli') <> 'null'
                               OR jsonb_typeof(lane -> 'exclusion_reason') <> 'string'
                               OR (lane ->> 'quality_bp')::integer <> 0
                               OR (lane ->> 'effective_weight_numerator')::bigint <> 0
                               OR (lane ->> 'normalized_weight_numerator')::bigint <> 0
                               OR (lane ->> 'display_weight_percent')::integer <> 0
                               OR (lane ->> 'contribution_numerator')::bigint <> 0
                               OR lane -> 'evidence_refs' <> '[]'::jsonb THEN
                                RETURN false;
                            END IF;
                        ELSE
                            RETURN false;
                        END IF;
                        total_effective := total_effective
                            + (lane ->> 'effective_weight_numerator')::bigint;
                        total_contribution := total_contribution
                            + (lane ->> 'contribution_numerator')::bigint;
                        display_total := display_total
                            + (lane ->> 'display_weight_percent')::integer;
                    END LOOP;
                    expected_score := (2 * total_contribution + total_effective)
                        / (2 * total_effective);
                    IF total_effective < 1
                       OR display_total <> 100
                       OR EXISTS (
                            SELECT 1 FROM jsonb_array_elements(attribute -> 'lanes') rows(item)
                            WHERE (item ->> 'normalized_weight_denominator')::bigint
                                    <> total_effective
                               OR (item ->> 'contribution_denominator')::bigint
                                    <> total_effective
                       )
                       OR (attribute ->> 'score_milli')::integer <> expected_score THEN
                        RETURN false;
                    END IF;
                END LOOP;
                FOR axis IN SELECT value FROM jsonb_array_elements(fused_profile -> 'axes') LOOP
                    expected_axis_score := (
                        SELECT (sum((item ->> 'score_milli')::integer) + 2) / 4
                        FROM jsonb_array_elements(fused_profile -> 'attributes') rows(item)
                        WHERE item ->> 'axis_id' = axis ->> 'axis_id'
                    );
                    IF axis ->> 'aggregation_rule'
                            IS DISTINCT FROM 'HALF_UP_MEAN_EXACTLY_FOUR_V1'
                       OR axis ->> 'policy_sha256' IS DISTINCT FROM canonical_policy_sha256
                       OR (axis ->> 'score_milli')::integer <> expected_axis_score
                       OR (axis ->> 'score_percent')::integer
                            <> (expected_axis_score + 20) / 40 THEN
                        RETURN false;
                    END IF;
                END LOOP;
                minimum_confidence := 101;
                FOR confidence_axis IN
                    SELECT value FROM jsonb_array_elements(
                        fused_profile -> 'confidence' -> 'axes'
                    )
                LOOP
                    IF (confidence_axis ->> 'confidence_bp')::integer <>
                            (confidence_axis ->> 'fidelity_contribution_bp')::integer
                            + (confidence_axis ->> 'agreement_contribution_bp')::integer
                       OR (confidence_axis ->> 'confidence_percent')::integer <>
                            ((confidence_axis ->> 'confidence_bp')::integer + 50) / 100
                       OR confidence_axis ->> 'publication_state' IS DISTINCT FROM (CASE
                            WHEN (confidence_axis ->> 'confidence_percent')::integer >= 70
                                THEN 'PUBLISHABLE'
                            WHEN (confidence_axis ->> 'confidence_percent')::integer >= 55
                                THEN 'LIMITED_INFORMATION'
                            ELSE 'EXCLUDED_MANUAL_REVIEW'
                       END)
                       OR (confidence_axis -> 'mismatch_warning_authorized') IS DISTINCT FROM
                            to_jsonb((confidence_axis ->> 'confidence_percent')::integer >= 65)
                       OR confidence_axis ->> 'policy_sha256'
                            IS DISTINCT FROM canonical_policy_sha256 THEN
                        RETURN false;
                    END IF;
                    minimum_confidence := least(
                        minimum_confidence,
                        (confidence_axis ->> 'confidence_percent')::integer
                    );
                END LOOP;
                IF jsonb_array_length(fused_profile -> 'confidence' -> 'axes') <> 3
                   OR (fused_profile -> 'confidence' ->> 'overall_confidence_percent')::integer
                        <> minimum_confidence
                   OR fused_profile -> 'confidence' ->> 'publication_state' IS DISTINCT FROM (CASE
                        WHEN minimum_confidence >= 70 THEN 'PUBLISHABLE'
                        WHEN minimum_confidence >= 55 THEN 'LIMITED_INFORMATION'
                        ELSE 'EXCLUDED_MANUAL_REVIEW'
                   END)
                   OR fused_profile -> 'confidence' -> 'mismatch_warning_authorized'
                        IS DISTINCT FROM to_jsonb(minimum_confidence >= 65) THEN
                    RETURN false;
                END IF;
                SELECT ranked.axis_id, ranked.score_milli
                INTO top_axis, top_score
                FROM (
                    SELECT value ->> 'axis_id' AS axis_id,
                           (value ->> 'score_milli')::integer AS score_milli,
                           ordinal
                    FROM jsonb_array_elements(fused_profile -> 'axes')
                    WITH ORDINALITY rows(value, ordinal)
                    ORDER BY score_milli DESC, ordinal
                    LIMIT 1
                ) ranked;
                SELECT ranked.axis_id, ranked.score_milli
                INTO second_axis, second_score
                FROM (
                    SELECT value ->> 'axis_id' AS axis_id,
                           (value ->> 'score_milli')::integer AS score_milli,
                           ordinal
                    FROM jsonb_array_elements(fused_profile -> 'axes')
                    WITH ORDINALITY rows(value, ordinal)
                    ORDER BY score_milli DESC, ordinal
                    OFFSET 1 LIMIT 1
                ) ranked;
                IF top_score >= 2600 AND top_score - second_score >= 480 THEN
                    expected_label_state := 'SINGLE';
                    expected_label_axes := jsonb_build_array(top_axis);
                    expected_label_id := CASE top_axis
                        WHEN 'H' THEN 'history-tradition-type'
                        WHEN 'E' THEN 'emotion-image-type'
                        ELSE 'rest-immersion-type' END;
                    expected_label_ko := CASE top_axis
                        WHEN 'H' THEN '역사·전통형'
                        WHEN 'E' THEN '감성·이미지형'
                        ELSE '휴식·몰입형' END;
                ELSIF second_score >= 2400 AND top_score - second_score < 480 THEN
                    expected_label_state := 'COMPOSITE';
                    expected_label_axes := jsonb_build_array(top_axis, second_axis);
                    expected_label_id := (CASE top_axis
                        WHEN 'H' THEN 'history-tradition'
                        WHEN 'E' THEN 'emotion-image'
                        ELSE 'rest-immersion' END) || '+' || (CASE second_axis
                        WHEN 'H' THEN 'history-tradition'
                        WHEN 'E' THEN 'emotion-image'
                        ELSE 'rest-immersion' END);
                    expected_label_ko := (CASE top_axis
                        WHEN 'H' THEN '역사·전통'
                        WHEN 'E' THEN '감성·이미지'
                        ELSE '휴식·몰입' END) || '·' || (CASE second_axis
                        WHEN 'H' THEN '역사·전통'
                        WHEN 'E' THEN '감성·이미지'
                        ELSE '휴식·몰입' END) || ' 복합형';
                ELSE
                    expected_label_state := 'FALLBACK';
                    expected_label_axes := '[]'::jsonb;
                    expected_label_id := 'mixed-experience';
                    expected_label_ko := '복합 경험형';
                END IF;
                IF fused_profile -> 'display_label' ->> 'state'
                        IS DISTINCT FROM expected_label_state
                   OR fused_profile -> 'display_label' -> 'axis_ids'
                        IS DISTINCT FROM expected_label_axes
                   OR fused_profile -> 'display_label' ->> 'label_id'
                        IS DISTINCT FROM expected_label_id
                   OR fused_profile -> 'display_label' ->> 'label_ko'
                        IS DISTINCT FROM expected_label_ko
                   OR (fused_profile -> 'display_label' ->> 'top_score_milli')::integer
                        <> top_score
                   OR (fused_profile -> 'display_label' ->> 'second_score_milli')::integer
                        <> second_score
                   OR (fused_profile -> 'display_label' ->> 'gap_milli')::integer
                        <> top_score - second_score THEN
                    RETURN false;
                END IF;
            END LOOP;
            IF (SELECT count(DISTINCT item ->> 'place_ref')
                FROM jsonb_array_elements(candidate -> 'cohort') AS rows(item))
                    IS DISTINCT FROM 24
               OR (SELECT count(DISTINCT item ->> 'predecessor_member_sha256')
                   FROM jsonb_array_elements(candidate -> 'cohort') AS rows(item))
                    IS DISTINCT FROM 24
               OR (
                    candidate ->> 'adoption_state' IN ('ADOPT', 'CONDITIONAL_ADOPT')
                    AND (
                        jsonb_typeof(lineage -> 'human_review_manifest_sha256') <> 'string'
                        OR jsonb_typeof(lineage -> 'zero_image_fallback_sha256') <> 'null'
                        OR NOT EXISTS (
                            SELECT 1
                            FROM jsonb_array_elements(candidate -> 'cohort')
                                    cohort_rows(cohort_member),
                                 jsonb_array_elements(
                                    cohort_member -> 'fused_profile' -> 'attributes'
                                 ) attribute_rows(fused_attribute)
                            WHERE fused_attribute -> 'lanes' -> 2 -> 'included' = 'true'::jsonb
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM jsonb_array_elements(candidate -> 'cohort')
                                    cohort_rows(cohort_member),
                                 jsonb_array_elements(
                                    cohort_member -> 'fused_profile' -> 'attributes'
                                 ) attribute_rows(fused_attribute)
                            WHERE fused_attribute -> 'lanes' -> 2 -> 'included' = 'true'::jsonb
                              AND NOT (candidate -> 'adopted_attributes' ?
                                    (fused_attribute ->> 'attribute_id'))
                        )
                    )
               )
               OR (
                    candidate ->> 'adoption_state' IN (
                        'IMAGE_REJECTED_TEXT_ODII_ONLY', 'NO_IMAGE_TEXT_ODII_ONLY'
                    )
                    AND (
                        jsonb_typeof(lineage -> 'human_review_manifest_sha256') <> 'null'
                        OR jsonb_typeof(lineage -> 'zero_image_fallback_sha256') <> 'string'
                        OR EXISTS (
                            SELECT 1
                            FROM jsonb_array_elements(candidate -> 'cohort')
                                    cohort_rows(cohort_member),
                                 jsonb_array_elements(
                                    cohort_member -> 'fused_profile' -> 'attributes'
                                 ) attribute_rows(fused_attribute)
                            WHERE fused_attribute -> 'lanes' -> 2 -> 'included'
                                    IS DISTINCT FROM 'false'::jsonb
                               OR fused_attribute -> 'lanes' -> 2 -> 'score_milli'
                                    IS DISTINCT FROM 'null'::jsonb
                               OR fused_attribute -> 'lanes' -> 2 -> 'effective_weight_numerator'
                                    IS DISTINCT FROM '0'::jsonb
                               OR fused_attribute -> 'lanes' -> 2 -> 'normalized_weight_numerator'
                                    IS DISTINCT FROM '0'::jsonb
                               OR fused_attribute -> 'lanes' -> 2 -> 'display_weight_percent'
                                    IS DISTINCT FROM '0'::jsonb
                               OR fused_attribute -> 'lanes' -> 2 -> 'contribution_numerator'
                                    IS DISTINCT FROM '0'::jsonb
                               OR fused_attribute -> 'lanes' -> 2 -> 'evidence_refs'
                                    IS DISTINCT FROM '[]'::jsonb
                        )
                    )
               ) THEN
                RETURN false;
            END IF;
            expected_predecessor_member_set_sha256 := encode(sha256(convert_to(
                dev_eval.canonical_jsonb_compact_v2((
                    SELECT jsonb_agg(jsonb_build_object(
                        'place_ref', item ->> 'place_ref',
                        'predecessor_member_sha256', item ->> 'predecessor_member_sha256',
                        'predecessor_profile_sha256', item ->> 'predecessor_profile_sha256'
                    ) ORDER BY ordinal)
                    FROM jsonb_array_elements(candidate -> 'cohort')
                    WITH ORDINALITY AS rows(item, ordinal)
                )), 'UTF8'
            )), 'hex');
            IF expected_predecessor_member_set_sha256 IS DISTINCT FROM
                    candidate ->> 'predecessor_member_set_sha256' THEN
                RETURN false;
            END IF;
            expected_release_sha256 := encode(sha256(convert_to(
                dev_eval.canonical_jsonb_compact_v2(candidate - 'release_sha256'),
                'UTF8'
            )), 'hex');
            RETURN expected_release_sha256 IS NOT DISTINCT FROM candidate ->> 'release_sha256';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_candidate_payload_dispatch_v1(
            candidate jsonb
        ) RETURNS boolean
        LANGUAGE sql
        IMMUTABLE
        STRICT
        SET search_path = pg_catalog, dev_eval
        AS $$
            SELECT CASE candidate ->> 'schema_version'
                WHEN 'itda.profile-release-candidate.v1'
                    THEN dev_eval.validate_profile_release_candidate_payload_v1(candidate)
                WHEN 'itda.profile-release-candidate.v2'
                    THEN dev_eval.validate_profile_release_candidate_payload_v2(candidate)
                ELSE false
            END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_insert_dispatch_v1()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE lineage jsonb;
        BEGIN
            lineage := CASE WHEN NEW.payload ->> 'schema_version' =
                'itda.profile-release-candidate.v2' THEN NEW.payload -> 'lineage'
                ELSE NEW.payload END;
            IF NOT dev_eval.validate_profile_release_candidate_payload_dispatch_v1(NEW.payload)
               OR NEW.release_sha256 IS DISTINCT FROM NEW.payload ->> 'release_sha256'
               OR NEW.release_id IS DISTINCT FROM NEW.payload ->> 'release_id'
               OR NEW.builder_principal IS DISTINCT FROM NEW.payload ->> 'builder_principal'
               OR NEW.canonical_lineage_sha256 IS DISTINCT FROM
                    lineage ->> 'canonical_lineage_sha256'
               OR NEW.dev_lineage_sha256 IS DISTINCT FROM lineage ->> 'dev_lineage_sha256'
               OR NEW.profile_schema_sha256 IS DISTINCT FROM
                    lineage ->> 'profile_schema_sha256' THEN
                RAISE EXCEPTION 'profile release candidate payload is not canonical'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER validate_profile_release_insert_dispatch_v1 "
        "BEFORE INSERT ON dev_eval.profile_releases FOR EACH ROW "
        "EXECUTE FUNCTION dev_eval.validate_profile_release_insert_dispatch_v1()"
    )

    op.create_table(
        "profile_release_v2_transition_proofs",
        sa.Column("successor_release_sha256", sa.Text(), nullable=False),
        sa.Column("predecessor_release_sha256", sa.Text(), nullable=False),
        sa.Column("proof_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["successor_release_sha256"],
            ["dev_eval.profile_releases.release_sha256"],
            name="fk_phase4_profile_transition_successor",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["predecessor_release_sha256"],
            ["dev_eval.profile_releases.release_sha256"],
            name="fk_phase4_profile_transition_predecessor",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "proof_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase4_profile_transition_proof_hash",
        ),
        sa.PrimaryKeyConstraint(
            "successor_release_sha256",
            name="pk_phase4_profile_transition_proofs",
        ),
        sa.UniqueConstraint(
            "proof_sha256",
            name="uq_phase4_profile_transition_proof_digest",
        ),
        schema="dev_eval",
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.derive_profile_release_v2_transition_proof_v1(
            successor jsonb,
            predecessor jsonb
        ) RETURNS jsonb
        LANGUAGE plpgsql
        IMMUTABLE
        STRICT
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            predecessor_members jsonb;
            predecessor_member_count integer;
            predecessor_member_set_sha256 text;
            proof_without_sha256 jsonb;
            proof_sha256 text;
        BEGIN
            IF NOT dev_eval.validate_profile_release_candidate_payload_v2(successor)
               OR NOT dev_eval.validate_profile_release_candidate_payload_v1(predecessor)
               OR successor -> 'lineage' ->> 'predecessor_release_sha256'
                    IS DISTINCT FROM predecessor ->> 'release_sha256'
               OR successor -> 'lineage' ->> 'canonical_lineage_sha256'
                    IS DISTINCT FROM predecessor ->> 'canonical_lineage_sha256'
               OR successor -> 'lineage' ->> 'dev_lineage_sha256'
                    IS DISTINCT FROM predecessor ->> 'dev_lineage_sha256' THEN
                RAISE EXCEPTION 'profile release predecessor lineage differs'
                    USING ERRCODE = '23514';
            END IF;

            SELECT jsonb_agg(jsonb_build_object(
                       'place_ref', successor_member ->> 'place_ref',
                       'predecessor_profile_sha256', predecessor_member ->> 'profile_sha256',
                       'predecessor_member_sha256', encode(sha256(convert_to(
                           dev_eval.canonical_jsonb_compact_v2(predecessor_member),
                           'UTF8'
                       )), 'hex')
                   ) ORDER BY successor_ordinal),
                   count(*)
            INTO predecessor_members, predecessor_member_count
            FROM jsonb_array_elements(successor -> 'cohort')
                 WITH ORDINALITY AS successor_rows(successor_member, successor_ordinal)
            JOIN LATERAL (
                SELECT value AS predecessor_member
                FROM jsonb_array_elements(predecessor -> 'cohort')
                WHERE value ->> 'place_ref' = successor_member ->> 'place_ref'
            ) AS predecessor_rows ON true
            WHERE successor_member ->> 'predecessor_profile_sha256'
                    = predecessor_member ->> 'profile_sha256'
              AND successor_member ->> 'predecessor_member_sha256'
                    = encode(sha256(convert_to(
                        dev_eval.canonical_jsonb_compact_v2(predecessor_member),
                        'UTF8'
                    )), 'hex');
            IF predecessor_member_count IS DISTINCT FROM 24 THEN
                RAISE EXCEPTION 'profile release predecessor members differ'
                    USING ERRCODE = '23514';
            END IF;

            predecessor_member_set_sha256 := encode(sha256(convert_to(
                dev_eval.canonical_jsonb_compact_v2(predecessor_members),
                'UTF8'
            )), 'hex');
            IF predecessor_member_set_sha256 IS DISTINCT FROM
                    successor ->> 'predecessor_member_set_sha256' THEN
                RAISE EXCEPTION 'profile release predecessor member set differs'
                    USING ERRCODE = '23514';
            END IF;

            proof_without_sha256 := jsonb_build_object(
                'schema_version', 'itda.profile-release-transition-proof.v2',
                'successor_release_sha256', successor ->> 'release_sha256',
                'predecessor_release_sha256', predecessor ->> 'release_sha256',
                'predecessor_lifecycle_receipt_sha256',
                    successor -> 'lineage' ->> 'predecessor_lifecycle_receipt_sha256',
                'canonical_lineage_sha256', predecessor ->> 'canonical_lineage_sha256',
                'dev_lineage_sha256', predecessor ->> 'dev_lineage_sha256',
                'predecessor_members', predecessor_members,
                'predecessor_member_set_sha256', predecessor_member_set_sha256,
                'transition_rule_sha256',
                    'c26315aa9dc63310800b15c92268b4fb4a086596112bee163b01855ba0892586'
            );
            proof_sha256 := encode(sha256(convert_to(
                dev_eval.canonical_jsonb_compact_v2(proof_without_sha256),
                'UTF8'
            )), 'hex');
            RETURN proof_without_sha256 || jsonb_build_object('proof_sha256', proof_sha256);
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_v2_transition_proof_insert_v1()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            successor_payload jsonb;
            predecessor_payload jsonb;
            expected_payload jsonb;
        BEGIN
            SELECT successor.payload, predecessor.payload
            INTO successor_payload, predecessor_payload
            FROM dev_eval.profile_releases successor
            JOIN dev_eval.profile_release_active_pointer pointer
              ON pointer.slot = 'DEV'
             AND pointer.release_sha256 = NEW.predecessor_release_sha256
            JOIN dev_eval.profile_release_lifecycle_heads predecessor_head
              ON predecessor_head.release_sha256 = pointer.release_sha256
             AND predecessor_head.state = 'ACTIVE'
             AND predecessor_head.head_receipt_sha256 = pointer.receipt_sha256
            JOIN dev_eval.profile_releases predecessor
              ON predecessor.release_sha256 = pointer.release_sha256
            WHERE successor.release_sha256 = NEW.successor_release_sha256
              AND successor.payload -> 'lineage' ->> 'predecessor_release_sha256'
                    = NEW.predecessor_release_sha256
              AND successor.payload -> 'lineage' ->> 'predecessor_lifecycle_receipt_sha256'
                    = pointer.receipt_sha256
            FOR SHARE OF successor, predecessor, predecessor_head;
            IF successor_payload IS NULL OR predecessor_payload IS NULL THEN
                RAISE EXCEPTION 'profile release transition predecessor is not active'
                    USING ERRCODE = '23514';
            END IF;
            expected_payload := dev_eval.derive_profile_release_v2_transition_proof_v1(
                successor_payload,
                predecessor_payload
            );
            IF jsonb_typeof(NEW.payload) IS DISTINCT FROM 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(NEW.payload)) IS DISTINCT FROM 10
               OR NEW.payload IS DISTINCT FROM expected_payload
               OR NEW.successor_release_sha256 IS DISTINCT FROM
                    expected_payload ->> 'successor_release_sha256'
               OR NEW.predecessor_release_sha256 IS DISTINCT FROM
                    expected_payload ->> 'predecessor_release_sha256'
               OR NEW.proof_sha256 IS DISTINCT FROM expected_payload ->> 'proof_sha256' THEN
                RAISE EXCEPTION 'profile release transition proof is not canonical'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER validate_profile_release_v2_transition_proof_insert_v1 "
        "BEFORE INSERT ON dev_eval.profile_release_v2_transition_proofs FOR EACH ROW "
        "EXECUTE FUNCTION dev_eval.validate_profile_release_v2_transition_proof_insert_v1()"
    )
    op.execute(
        "CREATE TRIGGER reject_profile_release_v2_transition_proofs_mutation_v1 "
        "BEFORE UPDATE OR DELETE ON dev_eval.profile_release_v2_transition_proofs "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.insert_profile_release_v2_transition_proof_v1(
            p_successor_release_sha256 text
        ) RETURNS text
        LANGUAGE plpgsql
        STRICT
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            successor_payload jsonb;
            predecessor_payload jsonb;
            predecessor_release_sha256 text;
            proof_payload jsonb;
        BEGIN
            SELECT successor.payload,
                   successor.payload -> 'lineage' ->> 'predecessor_release_sha256',
                   predecessor.payload
            INTO successor_payload, predecessor_release_sha256, predecessor_payload
            FROM dev_eval.profile_releases successor
            JOIN dev_eval.profile_release_active_pointer pointer
              ON pointer.slot = 'DEV'
             AND pointer.release_sha256 =
                    successor.payload -> 'lineage' ->> 'predecessor_release_sha256'
            JOIN dev_eval.profile_release_lifecycle_heads predecessor_head
              ON predecessor_head.release_sha256 = pointer.release_sha256
             AND predecessor_head.state = 'ACTIVE'
             AND predecessor_head.head_receipt_sha256 = pointer.receipt_sha256
            JOIN dev_eval.profile_releases predecessor
              ON predecessor.release_sha256 = pointer.release_sha256
            WHERE successor.release_sha256 = p_successor_release_sha256
              AND successor.payload ->> 'schema_version'
                    = 'itda.profile-release-candidate.v2'
              AND successor.payload -> 'lineage' ->> 'predecessor_lifecycle_receipt_sha256'
                    = pointer.receipt_sha256
            FOR SHARE OF successor, predecessor, predecessor_head;
            IF successor_payload IS NULL OR predecessor_payload IS NULL THEN
                RAISE EXCEPTION 'profile release successor lacks exact active predecessor'
                    USING ERRCODE = '23514';
            END IF;
            proof_payload := dev_eval.derive_profile_release_v2_transition_proof_v1(
                successor_payload,
                predecessor_payload
            );
            INSERT INTO dev_eval.profile_release_v2_transition_proofs (
                successor_release_sha256,
                predecessor_release_sha256,
                proof_sha256,
                payload
            ) VALUES (
                p_successor_release_sha256,
                predecessor_release_sha256,
                proof_payload ->> 'proof_sha256',
                proof_payload
            );
            RETURN proof_payload ->> 'proof_sha256';
        END;
        $$
        """
    )
    op.execute("REVOKE ALL ON dev_eval.profile_release_v2_transition_proofs FROM PUBLIC")
    _grant("GRANT SELECT ON dev_eval.profile_release_v2_transition_proofs", builder)
    _grant("GRANT SELECT ON dev_eval.profile_release_v2_transition_proofs", approver)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "dev_eval.insert_profile_release_v2_transition_proof_v1(text) FROM PUBLIC"
    )
    _grant(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.insert_profile_release_v2_transition_proof_v1(text)",
        builder,
    )

    op.execute(
        "DROP TRIGGER validate_profile_release_build_receipt_insert_v1 "
        "ON dev_eval.profile_release_build_receipts"
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_build_receipt_dispatch_v1()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            candidate_payload jsonb;
            expected_binding_sha256 text;
            expected_receipt_sha256 text;
        BEGIN
            SELECT releases.payload INTO candidate_payload
            FROM dev_eval.profile_releases releases
            JOIN dev_eval.profile_release_lifecycle_heads heads USING (release_sha256)
            WHERE releases.release_sha256 = NEW.release_sha256
              AND releases.builder_principal = NEW.builder_principal
              AND heads.state = 'BUILT_UNAPPROVED'
              AND heads.head_receipt_sha256 IS NULL
            FOR SHARE OF releases, heads;
            IF candidate_payload IS NULL
               OR NOT dev_eval.validate_profile_release_candidate_payload_dispatch_v1(
                    candidate_payload
               ) THEN
                RAISE EXCEPTION 'profile release build provenance is incomplete'
                    USING ERRCODE = '23514';
            END IF;
            expected_binding_sha256 := encode(sha256(convert_to(
                '{"action":"BUILD","builder":' || to_json(NEW.builder_principal)::text ||
                ',"release_sha256":' || to_json(NEW.release_sha256)::text || '}',
                'UTF8'
            )), 'hex');
            expected_receipt_sha256 := encode(sha256(convert_to(
                '{"binding_sha256":' || to_json(NEW.binding_sha256)::text ||
                ',"builder_principal":' || to_json(NEW.builder_principal)::text ||
                ',"nonce_sha256":' || to_json(NEW.nonce_sha256)::text ||
                ',"release_sha256":' || to_json(NEW.release_sha256)::text ||
                ',"schema_version":"itda.profile-release-build-receipt.v1"}',
                'UTF8'
            )), 'hex');
            IF expected_binding_sha256 <> NEW.binding_sha256
               OR expected_receipt_sha256 <> NEW.receipt_sha256 THEN
                RAISE EXCEPTION 'profile release build provenance digest is invalid'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER validate_profile_release_build_receipt_insert_dispatch_v1 "
        "BEFORE INSERT ON dev_eval.profile_release_build_receipts FOR EACH ROW "
        "EXECUTE FUNCTION dev_eval.validate_profile_release_build_receipt_dispatch_v1()"
    )

    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_active_profile_release_for_pin_dispatch_v1(
            target_sha256 text,
            transition_receipt_sha256 text
        ) RETURNS boolean
        LANGUAGE plpgsql
        STABLE
        STRICT
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            candidate_schema text;
            valid_successor boolean;
        BEGIN
            SELECT release.payload ->> 'schema_version'
            INTO candidate_schema
            FROM dev_eval.profile_release_active_pointer pointer
            JOIN dev_eval.profile_releases release USING (release_sha256)
            WHERE pointer.slot = 'DEV'
              AND pointer.release_sha256 = target_sha256
              AND pointer.receipt_sha256 = transition_receipt_sha256;
            IF candidate_schema = 'itda.profile-release-candidate.v1' THEN
                RETURN dev_eval.validate_active_profile_release_for_pin_v1(
                    target_sha256,
                    transition_receipt_sha256
                );
            END IF;
            IF candidate_schema IS DISTINCT FROM 'itda.profile-release-candidate.v2' THEN
                RETURN false;
            END IF;
            WITH provenance AS (
                SELECT
                    release.payload AS release_payload,
                    release.release_sha256,
                    release.builder_principal,
                    release.canonical_lineage_sha256,
                    release.dev_lineage_sha256,
                    release.profile_schema_sha256,
                    head.state AS head_state,
                    head.head_receipt_sha256,
                    build.nonce_sha256 AS build_nonce_sha256,
                    build.binding_sha256 AS build_binding_sha256,
                    build.receipt_sha256 AS build_receipt_sha256,
                    approval.approval_sha256,
                    approval.builder_principal AS approval_builder_principal,
                    approval.approver_principal,
                    approval.payload AS approval_payload,
                    event.action AS event_action,
                    event.previous_release_sha256,
                    event.expected_current_sha256,
                    event.nonce_sha256 AS event_nonce_sha256,
                    event.payload AS event_payload,
                    ledger.binding_sha256 AS ledger_binding_sha256,
                    ledger.nonce_sha256 AS ledger_nonce_sha256,
                    ledger.receipt_sha256 AS ledger_receipt_sha256,
                    ledger.payload AS ledger_payload,
                    proof.predecessor_release_sha256,
                    proof.proof_sha256,
                    proof.payload AS proof_payload,
                    predecessor.payload AS predecessor_payload
                FROM dev_eval.profile_release_active_pointer pointer
                JOIN dev_eval.profile_releases release USING (release_sha256)
                JOIN dev_eval.profile_release_lifecycle_heads head USING (release_sha256)
                JOIN dev_eval.profile_release_build_receipts build USING (release_sha256)
                JOIN dev_eval.profile_release_approvals approval USING (release_sha256)
                JOIN dev_eval.profile_release_transition_events event
                  ON event.receipt_sha256 = pointer.receipt_sha256
                 AND event.release_sha256 = pointer.release_sha256
                JOIN dev_eval.profile_release_nonce_ledger ledger
                  ON ledger.nonce_sha256 = event.nonce_sha256
                 AND ledger.receipt_sha256 = event.receipt_sha256
                JOIN dev_eval.profile_release_v2_transition_proofs proof
                  ON proof.successor_release_sha256 = pointer.release_sha256
                JOIN dev_eval.profile_releases predecessor
                  ON predecessor.release_sha256 = proof.predecessor_release_sha256
                WHERE pointer.slot = 'DEV'
                  AND pointer.release_sha256 = target_sha256
                  AND pointer.receipt_sha256 = transition_receipt_sha256
            ), canonical AS (
                SELECT provenance.*,
                    pg_catalog.jsonb_build_object(
                        'action', 'BUILD',
                        'builder', builder_principal,
                        'release_sha256', release_sha256
                    ) AS expected_build_binding,
                    pg_catalog.jsonb_build_object(
                        'schema_version', 'itda.profile-release-build-receipt.v1',
                        'release_sha256', release_sha256,
                        'builder_principal', builder_principal,
                        'nonce_sha256', build_nonce_sha256,
                        'binding_sha256', build_binding_sha256
                    ) AS expected_build_receipt,
                    pg_catalog.jsonb_build_object(
                        'schema_version', 'itda.profile-release-approval.v1',
                        'release_sha256', release_sha256,
                        'builder_principal', approval_builder_principal,
                        'approver_principal', approver_principal,
                        'state', 'APPROVED_INACTIVE'
                    ) AS expected_approval,
                    pg_catalog.jsonb_build_object(
                        'schema_version', 'itda.profile-release-transition.v1',
                        'action', 'ACTIVATE',
                        'release_sha256', release_sha256,
                        'previous_release_sha256', previous_release_sha256,
                        'expected_current_sha256', expected_current_sha256,
                        'approver_principal', approver_principal,
                        'nonce_sha256', event_nonce_sha256,
                        'reason', 'null'::pg_catalog.jsonb,
                        'completion', 'MUTATION_COMMITTED'
                    ) AS expected_transition,
                    pg_catalog.jsonb_build_object(
                        'action', 'ACTIVATE',
                        'target', release_sha256,
                        'expected', expected_current_sha256
                    ) AS expected_transition_binding,
                    (
                        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                            'place_ref', member ->> 'place_ref',
                            'predecessor_profile_sha256',
                                member ->> 'predecessor_profile_sha256',
                            'predecessor_member_sha256',
                                member ->> 'predecessor_member_sha256'
                        ) ORDER BY ordinal)
                        FROM pg_catalog.jsonb_array_elements(release_payload -> 'cohort')
                        WITH ORDINALITY AS members(member, ordinal)
                    ) AS expected_predecessor_members
                FROM provenance
            )
            SELECT count(*) = 1 AND COALESCE(pg_catalog.bool_and(
                head_state = 'ACTIVE'
                AND head_receipt_sha256 = transition_receipt_sha256
                AND dev_eval.validate_profile_release_candidate_payload_v2(release_payload)
                AND release_payload ->> 'release_sha256' = release_sha256
                AND release_payload ->> 'builder_principal' = builder_principal
                AND release_payload -> 'lineage' ->> 'canonical_lineage_sha256' =
                    canonical_lineage_sha256
                AND release_payload -> 'lineage' ->> 'dev_lineage_sha256' =
                    dev_lineage_sha256
                AND release_payload -> 'lineage' ->> 'profile_schema_sha256' =
                    profile_schema_sha256
                AND build_binding_sha256 = pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        dev_eval.canonical_jsonb_compact_v1(expected_build_binding),
                        'UTF8'
                    )
                ), 'hex')
                AND build_receipt_sha256 = pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        dev_eval.canonical_jsonb_compact_v1(expected_build_receipt),
                        'UTF8'
                    )
                ), 'hex')
                AND approval_builder_principal = builder_principal
                AND approver_principal <> builder_principal
                AND approval_payload = expected_approval || pg_catalog.jsonb_build_object(
                    'approval_sha256', approval_sha256
                )
                AND approval_sha256 = pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        dev_eval.canonical_jsonb_compact_v1(expected_approval), 'UTF8'
                    )
                ), 'hex')
                AND event_action = 'ACTIVATE'
                AND previous_release_sha256 = predecessor_release_sha256
                AND expected_current_sha256 = predecessor_release_sha256
                AND event_payload = expected_transition || pg_catalog.jsonb_build_object(
                    'receipt_sha256', transition_receipt_sha256
                )
                AND transition_receipt_sha256 = pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        dev_eval.canonical_jsonb_compact_v1(expected_transition), 'UTF8'
                    )
                ), 'hex')
                AND ledger_nonce_sha256 = event_nonce_sha256
                AND ledger_receipt_sha256 = transition_receipt_sha256
                AND ledger_payload = event_payload
                AND ledger_binding_sha256 = pg_catalog.encode(pg_catalog.sha256(
                    pg_catalog.convert_to(
                        dev_eval.canonical_jsonb_compact_v1(expected_transition_binding),
                        'UTF8'
                    )
                ), 'hex')
                AND release_payload -> 'lineage' ->> 'predecessor_release_sha256' =
                    predecessor_release_sha256
                AND dev_eval.validate_profile_release_candidate_payload_v1(
                    predecessor_payload
                )
                AND predecessor_payload ->> 'release_sha256' =
                    predecessor_release_sha256
                AND proof_payload = dev_eval.derive_profile_release_v2_transition_proof_v1(
                    release_payload,
                    predecessor_payload
                )
                AND proof_payload ->> 'successor_release_sha256' = release_sha256
                AND proof_payload ->> 'predecessor_release_sha256' =
                    predecessor_release_sha256
                AND proof_payload ->> 'proof_sha256' = proof_sha256
                AND proof_payload ->> 'canonical_lineage_sha256' =
                    canonical_lineage_sha256
                AND proof_payload ->> 'dev_lineage_sha256' = dev_lineage_sha256
                AND proof_payload ->> 'predecessor_member_set_sha256' =
                    release_payload ->> 'predecessor_member_set_sha256'
                AND proof_payload ->> 'transition_rule_sha256' =
                    'c26315aa9dc63310800b15c92268b4fb4a086596112bee163b01855ba0892586'
                AND proof_payload -> 'predecessor_members' = expected_predecessor_members
            ), false) INTO valid_successor
            FROM canonical;
            RETURN valid_successor;
        END;
        $function$
        """
    )

    for function in (
        "validate_profile_release_candidate_payload_v2(jsonb)",
        "validate_profile_release_candidate_payload_dispatch_v1(jsonb)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{function} FROM PUBLIC")
        _grant(f"GRANT EXECUTE ON FUNCTION dev_eval.{function}", builder)
        _grant(f"GRANT EXECUTE ON FUNCTION dev_eval.{function}", approver)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "dev_eval.derive_profile_release_v2_transition_proof_v1(jsonb, jsonb) FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "dev_eval.validate_active_profile_release_for_pin_dispatch_v1(text, text) "
        "FROM PUBLIC"
    )
    _grant(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.validate_active_profile_release_for_pin_dispatch_v1(text, text)",
        builder,
    )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "LOCK TABLE dev_eval.profile_release_v2_transition_proofs, "
            "dev_eval.profile_release_active_pointer, "
            "dev_eval.profile_release_lifecycle_heads, "
            "dev_eval.profile_releases IN ACCESS EXCLUSIVE MODE"
        )
    )
    protected_v2_rows = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT count(*) FROM dev_eval.profile_releases "
            " WHERE payload ->> 'schema_version' = "
            "'itda.profile-release-candidate.v2') + "
            "(SELECT count(*) FROM dev_eval.profile_release_v2_transition_proofs)"
        )
    ).scalar_one()
    if protected_v2_rows:
        raise RuntimeError(
            "0013 downgrade is intentionally irreversible while v2 profile release data exists"
        )

    op.execute(
        "DROP FUNCTION dev_eval.validate_active_profile_release_for_pin_dispatch_v1(text, text)"
    )
    op.execute(
        "DROP TRIGGER validate_profile_release_build_receipt_insert_dispatch_v1 "
        "ON dev_eval.profile_release_build_receipts"
    )
    op.execute("DROP FUNCTION dev_eval.validate_profile_release_build_receipt_dispatch_v1()")
    op.execute(
        "CREATE TRIGGER validate_profile_release_build_receipt_insert_v1 "
        "BEFORE INSERT ON dev_eval.profile_release_build_receipts FOR EACH ROW "
        "EXECUTE FUNCTION dev_eval.validate_profile_release_build_receipt_v1()"
    )
    op.execute(
        "DROP TRIGGER reject_profile_release_v2_transition_proofs_mutation_v1 "
        "ON dev_eval.profile_release_v2_transition_proofs"
    )
    op.execute(
        "DROP FUNCTION dev_eval.insert_profile_release_v2_transition_proof_v1(text)"
    )
    op.execute(
        "DROP TRIGGER validate_profile_release_v2_transition_proof_insert_v1 "
        "ON dev_eval.profile_release_v2_transition_proofs"
    )
    op.execute("DROP FUNCTION dev_eval.validate_profile_release_v2_transition_proof_insert_v1()")
    op.drop_table("profile_release_v2_transition_proofs", schema="dev_eval")
    op.execute(
        "DROP FUNCTION dev_eval.derive_profile_release_v2_transition_proof_v1(jsonb, jsonb)"
    )
    op.execute(
        "DROP TRIGGER validate_profile_release_insert_dispatch_v1 ON dev_eval.profile_releases"
    )
    op.execute("DROP FUNCTION dev_eval.validate_profile_release_insert_dispatch_v1()")
    op.execute(
        "DROP FUNCTION dev_eval.validate_profile_release_candidate_payload_dispatch_v1(jsonb)"
    )
    op.execute("DROP FUNCTION dev_eval.validate_profile_release_candidate_payload_v2(jsonb)")
    op.execute("DROP FUNCTION dev_eval.canonical_jsonb_compact_v2(jsonb)")
