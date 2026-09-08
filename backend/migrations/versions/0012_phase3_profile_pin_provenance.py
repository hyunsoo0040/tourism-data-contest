"""Expose one boolean active-release provenance check to the pin writer."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0012_phase3_profile_pin_provenance"
down_revision = "0011_phase3_score4_evidence_rule"
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


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    op.execute(
        sa.text(
            """
            CREATE FUNCTION dev_eval.validate_active_profile_release_for_pin_v1(
                target_sha256 text,
                transition_receipt_sha256 text
            ) RETURNS boolean
            LANGUAGE sql
            STABLE
            STRICT
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
                WITH provenance AS (
                    SELECT
                        pointer.release_sha256 AS active_release_sha256,
                        pointer.receipt_sha256 AS active_receipt_sha256,
                        release.payload AS release_payload,
                        release.builder_principal AS release_builder_principal,
                        head.state AS head_state,
                        head.head_receipt_sha256,
                        build.builder_principal AS build_builder_principal,
                        build.nonce_sha256 AS build_nonce_sha256,
                        build.binding_sha256 AS build_binding_sha256,
                        build.receipt_sha256 AS build_receipt_sha256,
                        approval.approval_sha256,
                        approval.builder_principal AS approval_builder_principal,
                        approval.approver_principal AS approval_approver_principal,
                        approval.payload AS approval_payload,
                        event.receipt_sha256 AS event_receipt_sha256,
                        event.action AS event_action,
                        event.release_sha256 AS event_release_sha256,
                        event.previous_release_sha256,
                        event.expected_current_sha256,
                        event.approver_principal AS event_approver_principal,
                        event.nonce_sha256 AS event_nonce_sha256,
                        event.payload AS event_payload,
                        ledger.binding_sha256 AS ledger_binding_sha256,
                        ledger.nonce_sha256 AS ledger_nonce_sha256,
                        ledger.receipt_sha256 AS ledger_receipt_sha256,
                        ledger.payload AS ledger_payload,
                        rollback.receipt_sha256 AS rollback_receipt_sha256,
                        rollback.transition_receipt_sha256 AS rollback_transition_receipt_sha256,
                        rollback.release_sha256 AS rollback_release_sha256,
                        rollback.approver_principal AS rollback_approver_principal,
                        rollback.reason AS rollback_reason,
                        rollback.reason_sha256 AS rollback_reason_sha256,
                        rollback.payload AS rollback_payload
                    FROM dev_eval.profile_release_active_pointer pointer
                    JOIN dev_eval.profile_releases release
                      ON release.release_sha256 = pointer.release_sha256
                    JOIN dev_eval.profile_release_lifecycle_heads head
                      ON head.release_sha256 = pointer.release_sha256
                    JOIN dev_eval.profile_release_build_receipts build
                      ON build.release_sha256 = pointer.release_sha256
                    JOIN dev_eval.profile_release_approvals approval
                      ON approval.release_sha256 = pointer.release_sha256
                    JOIN dev_eval.profile_release_transition_events event
                      ON event.receipt_sha256 = pointer.receipt_sha256
                    JOIN dev_eval.profile_release_nonce_ledger ledger
                      ON ledger.nonce_sha256 = event.nonce_sha256
                     AND ledger.receipt_sha256 = event.receipt_sha256
                    LEFT JOIN dev_eval.profile_release_rollback_receipts rollback
                      ON rollback.transition_receipt_sha256 = event.receipt_sha256
                    WHERE pointer.slot = 'DEV'
                      AND pointer.release_sha256 = $1
                      AND pointer.receipt_sha256 = $2
                ), canonical AS (
                    SELECT
                        provenance.*,
                        pg_catalog.jsonb_build_object(
                            'action', 'BUILD',
                            'builder', build_builder_principal,
                            'release_sha256', active_release_sha256
                        ) AS expected_build_binding,
                        pg_catalog.jsonb_build_object(
                            'schema_version', 'itda.profile-release-build-receipt.v1',
                            'release_sha256', active_release_sha256,
                            'builder_principal', build_builder_principal,
                            'nonce_sha256', build_nonce_sha256,
                            'binding_sha256', build_binding_sha256
                        ) AS expected_build_receipt,
                        pg_catalog.jsonb_build_object(
                            'schema_version', 'itda.profile-release-approval.v1',
                            'release_sha256', active_release_sha256,
                            'builder_principal', approval_builder_principal,
                            'approver_principal', approval_approver_principal,
                            'state', 'APPROVED_INACTIVE'
                        ) AS expected_approval,
                        pg_catalog.jsonb_build_object(
                            'schema_version', 'itda.profile-release-transition.v1',
                            'action', event_action,
                            'release_sha256', event_release_sha256,
                            'previous_release_sha256', previous_release_sha256,
                            'expected_current_sha256', expected_current_sha256,
                            'approver_principal', event_approver_principal,
                            'nonce_sha256', event_nonce_sha256,
                            'reason', CASE WHEN event_action = 'ROLLBACK'
                                THEN pg_catalog.to_jsonb(rollback_reason)
                                ELSE 'null'::pg_catalog.jsonb
                            END,
                            'completion', 'MUTATION_COMMITTED'
                        ) AS expected_transition,
                        CASE event_action
                            WHEN 'ACTIVATE' THEN pg_catalog.jsonb_build_object(
                                'action', 'ACTIVATE',
                                'target', event_release_sha256,
                                'expected', expected_current_sha256
                            )
                            WHEN 'ROLLBACK' THEN pg_catalog.jsonb_build_object(
                                'action', 'ROLLBACK',
                                'target', event_release_sha256,
                                'expected', expected_current_sha256,
                                'reason_sha256', rollback_reason_sha256,
                                'approver', event_approver_principal
                            )
                        END AS expected_transition_binding
                    FROM provenance
                )
                SELECT
                    count(*) = 1
                    AND COALESCE(pg_catalog.bool_and(
                        $1 ~ '^[0-9a-f]{64}$'
                        AND $2 ~ '^[0-9a-f]{64}$'
                        AND head_state = 'ACTIVE'
                        AND head_receipt_sha256 = active_receipt_sha256
                        AND dev_eval.validate_profile_release_candidate_payload_v1(
                            release_payload
                        )
                        AND release_payload ->> 'release_sha256' = active_release_sha256
                        AND release_payload ->> 'builder_principal' =
                            release_builder_principal
                        AND build_builder_principal = release_builder_principal
                        AND build_binding_sha256 = pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(
                                dev_eval.canonical_jsonb_compact_v1(
                                    expected_build_binding
                                ),
                                'UTF8'
                            )),
                            'hex'
                        )
                        AND build_receipt_sha256 = pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(
                                dev_eval.canonical_jsonb_compact_v1(
                                    expected_build_receipt
                                ),
                                'UTF8'
                            )),
                            'hex'
                        )
                        AND approval_builder_principal = release_builder_principal
                        AND approval_approver_principal <> release_builder_principal
                        AND approval_approver_principal = event_approver_principal
                        AND approval_sha256 = pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(
                                dev_eval.canonical_jsonb_compact_v1(expected_approval),
                                'UTF8'
                            )),
                            'hex'
                        )
                        AND approval_payload = expected_approval ||
                            pg_catalog.jsonb_build_object(
                                'approval_sha256', approval_sha256
                            )
                        AND event_release_sha256 = active_release_sha256
                        AND previous_release_sha256 IS NOT DISTINCT FROM
                            expected_current_sha256
                        AND event_payload = expected_transition ||
                            pg_catalog.jsonb_build_object(
                                'receipt_sha256', event_receipt_sha256
                            )
                        AND event_receipt_sha256 = pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(
                                dev_eval.canonical_jsonb_compact_v1(expected_transition),
                                'UTF8'
                            )),
                            'hex'
                        )
                        AND ledger_nonce_sha256 = event_nonce_sha256
                        AND ledger_receipt_sha256 = event_receipt_sha256
                        AND ledger_payload = event_payload
                        AND ledger_binding_sha256 = pg_catalog.encode(
                            pg_catalog.sha256(pg_catalog.convert_to(
                                dev_eval.canonical_jsonb_compact_v1(
                                    expected_transition_binding
                                ),
                                'UTF8'
                            )),
                            'hex'
                        )
                        AND (
                            (
                                event_action = 'ACTIVATE'
                                AND rollback_receipt_sha256 IS NULL
                            )
                            OR (
                                event_action = 'ROLLBACK'
                                AND previous_release_sha256 IS NOT NULL
                                AND rollback_receipt_sha256 = event_receipt_sha256
                                AND rollback_transition_receipt_sha256 =
                                    event_receipt_sha256
                                AND rollback_release_sha256 = event_release_sha256
                                AND rollback_approver_principal = event_approver_principal
                                AND rollback_payload = event_payload
                                AND rollback_reason_sha256 = pg_catalog.encode(
                                    pg_catalog.sha256(pg_catalog.convert_to(
                                        rollback_reason,
                                        'UTF8'
                                    )),
                                    'hex'
                                )
                            )
                        )
                    ), false)
                FROM canonical
            $function$
            """
        )
    )
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "dev_eval.validate_active_profile_release_for_pin_v1(text, text) FROM PUBLIC"
    )
    if builder is not None:
        op.execute(
            sa.text(
                "GRANT EXECUTE ON FUNCTION "
                "dev_eval.validate_active_profile_release_for_pin_v1(text, text) TO "
                f"{_quoted_identifier(builder)}"
            )
        )


def downgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    if builder is not None:
        op.execute(
            sa.text(
                "REVOKE EXECUTE ON FUNCTION "
                "dev_eval.validate_active_profile_release_for_pin_v1(text, text) FROM "
                f"{_quoted_identifier(builder)}"
            )
        )
    op.execute("DROP FUNCTION dev_eval.validate_active_profile_release_for_pin_v1(text, text)")
