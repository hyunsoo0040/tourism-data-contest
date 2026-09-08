"""Add immutable, actor-isolated Phase 3 evaluator revision storage."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004_phase3_labels"
down_revision = "0003_real_manifest"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CAPABILITIES = (
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
)


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


def _configured_roles() -> dict[str, str]:
    return {
        capability: role
        for capability in _CAPABILITIES
        if (role := _configured_identifier(f"label_{capability}_role")) is not None
    }


def _grant(statement: str, *roles: str) -> None:
    if not roles:
        return
    quoted = ", ".join(_quoted_identifier(role) for role in roles)
    op.execute(sa.text(f"{statement} TO {quoted}"))


def upgrade() -> None:
    roles = _configured_roles()
    evaluator_roles = tuple(
        roles[name] for name in ("evaluator_a", "evaluator_b", "evaluator_c") if name in roles
    )

    op.create_table(
        "label_revisions",
        sa.Column("revision_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("assignment_id", sa.Text(), nullable=False),
        sa.Column("evaluator_principal", sa.Text(), nullable=False),
        sa.Column("parent_revision_sha256", sa.Text(), nullable=True),
        sa.Column("correction_reason", sa.Text(), nullable=True),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "revision_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_label_revision_sha256",
        ),
        sa.CheckConstraint(
            "receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_label_receipt_sha256",
        ),
        sa.CheckConstraint(
            "(parent_revision_sha256 IS NULL) = (correction_reason IS NULL)",
            name="ck_phase3_label_correction_pair",
        ),
        sa.ForeignKeyConstraint(
            ["parent_revision_sha256"],
            ["dev_eval.label_revisions.revision_sha256"],
            name="fk_phase3_label_parent",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("revision_sha256", name="pk_phase3_label_revisions"),
        sa.UniqueConstraint(
            "evaluator_principal",
            "parent_revision_sha256",
            name="uq_phase3_label_successor",
        ),
        schema="dev_eval",
    )
    op.create_table(
        "accepted_label_revisions",
        sa.Column("event_sha256", sa.Text(), nullable=False),
        sa.Column("assignment_id", sa.Text(), nullable=False),
        sa.Column("evaluator_principal", sa.Text(), nullable=False),
        sa.Column("revision_sha256", sa.Text(), nullable=False),
        sa.Column("selected_by", sa.Text(), nullable=False),
        sa.Column("selection_reason", sa.Text(), nullable=False),
        sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["revision_sha256"],
            ["dev_eval.label_revisions.revision_sha256"],
            name="fk_phase3_accepted_revision",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("event_sha256", name="pk_phase3_accepted_events"),
        schema="dev_eval",
    )
    op.create_table(
        "adjudicated_label_exports",
        sa.Column("export_sha256", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("export_sha256", name="pk_phase3_adjudicated_exports"),
        schema="dev_eval",
    )

    op.execute(
        """
        CREATE FUNCTION dev_eval.reject_phase3_label_mutation_v1()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'Phase 3 label rows are append-only' USING ERRCODE = '55000';
        END;
        $function$
        """
    )
    for relation in ("label_revisions", "accepted_label_revisions"):
        op.execute(
            f"CREATE TRIGGER reject_{relation}_mutation_v1 "
            f"BEFORE UPDATE OR DELETE ON dev_eval.{relation} "
            "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
        )

    op.execute(
        """
        CREATE FUNCTION dev_eval.submit_label_revision_v1(candidate_payload jsonb)
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
            ] <> '{}'::jsonb THEN
                RAISE EXCEPTION 'label revision payload has unknown fields'
                    USING ERRCODE = '22023';
            END IF;
            IF nullif(candidate_payload->>'assignment_id', '') IS NULL
               OR nullif(candidate_payload->>'rubric_version', '') IS NULL
               OR nullif(candidate_payload->>'source_snapshot_version', '') IS NULL
               OR jsonb_typeof(candidate_payload->'judgments') IS DISTINCT FROM 'array'
               OR jsonb_array_length(candidate_payload->'judgments') <> 12 THEN
                RAISE EXCEPTION 'label revision payload is incomplete'
                    USING ERRCODE = '22023';
            END IF;
            IF candidate_payload ? 'primary_axis'
               AND candidate_payload ? 'primary_axis_judgment' THEN
                RAISE EXCEPTION 'primary axis aliases cannot both be supplied'
                    USING ERRCODE = '22023';
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

            SELECT array_agg(item->>'attribute_id' ORDER BY ordinal)
              INTO attribute_order
              FROM jsonb_array_elements(candidate_payload->'judgments')
                   WITH ORDINALITY AS entry(item, ordinal);
            IF attribute_order <> ARRAY[
                'H1','H2','H3','H4','I1','I2','I3','I4','R1','R2','R3','R4'
            ] THEN
                RAISE EXCEPTION 'judgments must use canonical H1-R4 order'
                    USING ERRCODE = '22023';
            END IF;

            FOR judgment IN SELECT value FROM jsonb_array_elements(candidate_payload->'judgments')
            LOOP
                IF judgment - ARRAY[
                    'attribute_id', 'score', 'unknown_reason', 'unknown_note', 'evidence'
                ] <> '{}'::jsonb
                   OR jsonb_typeof(judgment->'evidence') IS DISTINCT FROM 'array' THEN
                    RAISE EXCEPTION 'judgment has invalid fields'
                        USING ERRCODE = '22023';
                END IF;
                IF judgment->'score' = 'null'::jsonb THEN
                    IF judgment->>'unknown_reason' NOT IN (
                        'NO_EVIDENCE', 'INSUFFICIENT_EVIDENCE',
                        'CONFLICTING_EVIDENCE', 'OUT_OF_SCOPE_INFORMATION'
                    ) OR length(
                        btrim(coalesce(judgment->>'unknown_note', ''))
                    ) NOT BETWEEN 1 AND 300
                    OR judgment->>'unknown_note' <> btrim(judgment->>'unknown_note') THEN
                        RAISE EXCEPTION 'unknown judgment requires closed reason and note'
                            USING ERRCODE = '22023';
                    END IF;
                ELSE
                    BEGIN
                        score_value := (judgment->>'score')::integer;
                    EXCEPTION WHEN invalid_text_representation THEN
                        RAISE EXCEPTION 'score must be an integer' USING ERRCODE = '22023';
                    END;
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
                    IF score_value = 4 AND NOT (
                        coalesce(cardinality(direct_lanes), 0) = 1
                        AND coalesce(cardinality(direct_clusters), 0) >= 2
                        OR coalesce(description_keys, ARRAY[]::text[])
                           && coalesce(odii_keys, ARRAY[]::text[])
                    ) THEN
                        RAISE EXCEPTION 'score four lacks distinct or concordant evidence'
                            USING ERRCODE = '22023';
                    END IF;
                END IF;
                FOR evidence_item IN SELECT value FROM jsonb_array_elements(judgment->'evidence')
                LOOP
                    IF evidence_item->>'lane' NOT IN ('DESCRIPTION', 'ODII')
                       OR nullif(evidence_item->>'evidence_id', '') IS NULL
                       OR nullif(evidence_item->>'source_id', '') IS NULL
                       OR nullif(evidence_item->>'dedup_cluster_id', '') IS NULL THEN
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
                (normalized_payload->>'submitted_at')::timestamptz
            ) ON CONFLICT ON CONSTRAINT pk_phase3_label_revisions DO NOTHING;
            RETURN QUERY SELECT candidate_sha256, session_user::text;
        END;
        $function$
        """
    )

    op.execute(
        """
        CREATE VIEW dev_eval.own_label_revisions_v1
        WITH (security_barrier = true) AS
        SELECT revision_sha256, receipt_sha256, assignment_id, evaluator_principal,
               parent_revision_sha256, correction_reason, payload, submitted_at, created_at
          FROM dev_eval.label_revisions
         WHERE evaluator_principal = session_user
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.get_label_revision_v1(requested_revision_sha256 text)
        RETURNS SETOF dev_eval.label_revisions
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $function$
            SELECT * FROM dev_eval.label_revisions
             WHERE revision_sha256 = requested_revision_sha256;
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.select_accepted_label_revision_v1(
            requested_revision_sha256 text,
            requested_reason text,
            requested_at timestamptz
        ) RETURNS TABLE(event_sha256 text, revision_sha256 text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $function$
        DECLARE
            selected dev_eval.label_revisions%ROWTYPE;
            event_digest text;
        BEGIN
            IF length(btrim(coalesce(requested_reason, ''))) NOT BETWEEN 1 AND 300
               OR requested_reason <> btrim(requested_reason) THEN
                RAISE EXCEPTION 'accepted-head reason is invalid' USING ERRCODE = '22023';
            END IF;
            SELECT * INTO selected FROM dev_eval.label_revisions
             WHERE label_revisions.revision_sha256 = requested_revision_sha256;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'accepted-head revision does not exist' USING ERRCODE = '22023';
            END IF;
            event_digest := encode(sha256(convert_to(
                requested_revision_sha256 || E'\n' || session_user || E'\n'
                || requested_reason || E'\n' || requested_at::text, 'UTF8'
            )), 'hex');
            INSERT INTO dev_eval.accepted_label_revisions (
                event_sha256, assignment_id, evaluator_principal, revision_sha256,
                selected_by, selection_reason, selected_at
            ) VALUES (
                event_digest, selected.assignment_id, selected.evaluator_principal,
                selected.revision_sha256, session_user, requested_reason, requested_at
            ) ON CONFLICT ON CONSTRAINT pk_phase3_accepted_events DO NOTHING;
            RETURN QUERY SELECT event_digest, requested_revision_sha256;
        END;
        $function$
        """
    )
    status_readers = tuple(roles[name] for name in ("builder", "adjudicator") if name in roles)
    status_reader_sql = ", ".join(f"'{role}'" for role in status_readers) or "NULL"
    op.execute(
        f"""
        CREATE VIEW dev_eval.label_submission_status_v1 AS
        SELECT evaluator_principal AS evaluator_pseudonym,
               'SUBMITTED'::text AS submission_status,
               max(created_at) AS latest_server_event_at,
               (SELECT count(DISTINCT evaluator_principal) >= 3
                  FROM dev_eval.label_revisions)
                   AS all_required_submissions_exist
          FROM dev_eval.label_revisions
         WHERE session_user IN ({status_reader_sql})
         GROUP BY evaluator_principal
        """
    )

    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA dev_eval FROM PUBLIC")
    op.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dev_eval FROM PUBLIC")
    op.execute("GRANT SELECT ON dev_eval.label_submission_status_v1 TO PUBLIC")
    if evaluator_roles:
        _grant("GRANT USAGE ON SCHEMA dev_eval", *evaluator_roles)
        _grant(
            "GRANT EXECUTE ON FUNCTION dev_eval.submit_label_revision_v1(jsonb)",
            *evaluator_roles,
        )
        _grant("GRANT SELECT ON dev_eval.own_label_revisions_v1", *evaluator_roles)
    adjudicator = roles.get("adjudicator")
    if adjudicator is not None:
        _grant("GRANT USAGE ON SCHEMA dev_eval", adjudicator)
        _grant("GRANT EXECUTE ON FUNCTION dev_eval.get_label_revision_v1(text)", adjudicator)
        _grant(
            "GRANT EXECUTE ON FUNCTION "
            "dev_eval.select_accepted_label_revision_v1(text, text, timestamptz)",
            adjudicator,
        )
        _grant("GRANT SELECT ON dev_eval.label_submission_status_v1", adjudicator)
    builder = roles.get("builder")
    if builder is not None:
        _grant("GRANT USAGE ON SCHEMA dev_eval", builder)
        _grant("GRANT SELECT ON dev_eval.label_submission_status_v1", builder)


def downgrade() -> None:
    op.execute("DROP VIEW dev_eval.label_submission_status_v1")
    op.execute("DROP FUNCTION dev_eval.select_accepted_label_revision_v1(text, text, timestamptz)")
    op.execute("DROP FUNCTION dev_eval.get_label_revision_v1(text)")
    op.execute("DROP VIEW dev_eval.own_label_revisions_v1")
    op.execute("DROP FUNCTION dev_eval.submit_label_revision_v1(jsonb)")
    for relation in ("accepted_label_revisions", "label_revisions"):
        op.execute(f"DROP TRIGGER reject_{relation}_mutation_v1 ON dev_eval.{relation}")
    op.execute("DROP FUNCTION dev_eval.reject_phase3_label_mutation_v1()")
    op.drop_table("adjudicated_label_exports", schema="dev_eval")
    op.drop_table("accepted_label_revisions", schema="dev_eval")
    op.drop_table("label_revisions", schema="dev_eval")
