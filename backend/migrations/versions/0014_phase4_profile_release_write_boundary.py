"""Route profile-release construction through candidate-bound capabilities."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0014_phase4_profile_release_write_boundary"
down_revision = "0013_phase4_profile_releases"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_WRITE_AUTHORITY = "itda_profile_release_write_authority"
_AUTHORITY_SERVICE = "itda_profile_release_authority_service"


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


def _require_role_topology(builder: str) -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            "SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
            "rolcreaterole, rolreplication, rolbypassrls FROM pg_catalog.pg_roles "
            "WHERE rolname IN (:owner, :service, :builder)"
        ),
        {"owner": _WRITE_AUTHORITY, "service": _AUTHORITY_SERVICE, "builder": builder},
    ).mappings()
    roles = {str(row["rolname"]): row for row in rows}
    if set(roles) != {_WRITE_AUTHORITY, _AUTHORITY_SERVICE, builder}:
        raise RuntimeError("profile release authority roles must be provisioned exactly")
    owner = roles[_WRITE_AUTHORITY]
    service = roles[_AUTHORITY_SERVICE]
    builder_role = roles[builder]
    if tuple(
        owner[key]
        for key in (
            "rolcanlogin",
            "rolinherit",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        )
    ) != (False, False, False, False, False, False, False):
        raise RuntimeError("profile release write authority role flags are unsafe")
    if tuple(
        service[key]
        for key in (
            "rolcanlogin",
            "rolinherit",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        )
    ) != (True, False, False, False, False, False, False):
        raise RuntimeError("profile release authority service role flags are unsafe")
    if tuple(
        builder_role[key]
        for key in (
            "rolcanlogin",
            "rolinherit",
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        )
    ) != (True, False, False, False, False, False, False):
        raise RuntimeError("profile release builder role flags are unsafe")
    if builder in {_WRITE_AUTHORITY, _AUTHORITY_SERVICE}:
        raise RuntimeError("profile release builder must be distinct from authority roles")
    related = connection.execute(
        sa.text(
            "SELECT pg_catalog.pg_has_role(:builder, :owner, 'MEMBER'), "
            "pg_catalog.pg_has_role(:owner, :builder, 'MEMBER'), "
            "pg_catalog.pg_has_role(:builder, :service, 'MEMBER'), "
            "pg_catalog.pg_has_role(:service, :builder, 'MEMBER')"
        ),
        {"builder": builder, "owner": _WRITE_AUTHORITY, "service": _AUTHORITY_SERVICE},
    ).one()
    if any(bool(value) for value in related):
        raise RuntimeError("profile release authority roles must not be member-related")


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    if builder is None:
        raise RuntimeError("profile release builder role is required")
    _require_role_topology(builder)
    quoted_builder = _quoted_identifier(builder)
    op.execute(
        """
        CREATE TABLE dev_eval.profile_release_fixed_root_authorities_v1 (
            authority_registry_id text PRIMARY KEY CHECK (
                authority_registry_id ~
                '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            ),
            candidate_payload jsonb NOT NULL,
            candidate_sha256 text NOT NULL UNIQUE CHECK (
                candidate_sha256 ~ '^[0-9a-f]{64}$'
            ),
            authority_root_sha256 text NOT NULL CHECK (
                authority_root_sha256 ~ '^[0-9a-f]{64}$'
            ),
            builder_database_principal text NOT NULL,
            expected_predecessor_sha256 text NULL CHECK (
                expected_predecessor_sha256 IS NULL
                OR expected_predecessor_sha256 ~ '^[0-9a-f]{64}$'
            ),
            expected_predecessor_lifecycle_receipt_sha256 text NULL CHECK (
                expected_predecessor_lifecycle_receipt_sha256 IS NULL
                OR expected_predecessor_lifecycle_receipt_sha256 ~ '^[0-9a-f]{64}$'
            ),
            resolution_sha256 text NOT NULL UNIQUE CHECK (
                resolution_sha256 ~ '^[0-9a-f]{64}$'
            ),
            registered_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            retired_at timestamptz NULL,
            CHECK (retired_at IS NULL OR retired_at >= registered_at)
        )
        """
    )
    op.execute(
        "ALTER TABLE dev_eval.profile_release_fixed_root_authorities_v1 "
        f"OWNER TO {_WRITE_AUTHORITY}"
    )
    op.execute("REVOKE ALL ON dev_eval.profile_release_fixed_root_authorities_v1 FROM PUBLIC")

    op.execute(
        """
        CREATE TABLE dev_eval.profile_release_build_authorizations_v1 (
            authorization_id uuid PRIMARY KEY,
            authority_registry_id text NOT NULL UNIQUE REFERENCES
                dev_eval.profile_release_fixed_root_authorities_v1(authority_registry_id),
            resolution_payload jsonb NOT NULL,
            resolution_sha256 text NOT NULL UNIQUE CHECK (
                resolution_sha256 ~ '^[0-9a-f]{64}$'
            ),
            authority_root_sha256 text NOT NULL CHECK (
                authority_root_sha256 ~ '^[0-9a-f]{64}$'
            ),
            candidate_sha256 text NOT NULL CHECK (
                candidate_sha256 ~ '^[0-9a-f]{64}$'
            ),
            builder_database_principal text NOT NULL,
            expected_predecessor_sha256 text NULL CHECK (
                expected_predecessor_sha256 IS NULL
                OR expected_predecessor_sha256 ~ '^[0-9a-f]{64}$'
            ),
            expected_predecessor_lifecycle_receipt_sha256 text NULL CHECK (
                expected_predecessor_lifecycle_receipt_sha256 IS NULL
                OR expected_predecessor_lifecycle_receipt_sha256 ~ '^[0-9a-f]{64}$'
            ),
            recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            consumed_at timestamptz NULL,
            CHECK (consumed_at IS NULL OR consumed_at >= recorded_at)
        )
        """
    )
    op.execute(
        f"ALTER TABLE dev_eval.profile_release_build_authorizations_v1 OWNER TO {_WRITE_AUTHORITY}"
    )
    op.execute("REVOKE ALL ON dev_eval.profile_release_build_authorizations_v1 FROM PUBLIC")

    op.execute(
        """
        CREATE TABLE dev_eval.profile_release_build_capabilities_v1 (
            capability_id uuid PRIMARY KEY,
            authorization_id uuid NOT NULL REFERENCES
                dev_eval.profile_release_build_authorizations_v1(authorization_id),
            candidate_payload jsonb NOT NULL,
            candidate_sha256 text NOT NULL CHECK (
                candidate_sha256 ~ '^[0-9a-f]{64}$'
            ),
            builder_database_principal text NOT NULL,
            expected_predecessor_sha256 text NULL CHECK (
                expected_predecessor_sha256 IS NULL
                OR expected_predecessor_sha256 ~ '^[0-9a-f]{64}$'
            ),
            expected_predecessor_lifecycle_receipt_sha256 text NULL CHECK (
                expected_predecessor_lifecycle_receipt_sha256 IS NULL
                OR expected_predecessor_lifecycle_receipt_sha256 ~ '^[0-9a-f]{64}$'
            ),
            issued_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz NULL,
            retired_at timestamptz NULL,
            CHECK (expires_at > issued_at),
            CHECK (consumed_at IS NULL OR consumed_at >= issued_at),
            CHECK (retired_at IS NULL OR retired_at >= issued_at),
            CHECK (consumed_at IS NULL OR retired_at IS NULL)
        )
        """
    )
    op.execute(
        f"ALTER TABLE dev_eval.profile_release_build_capabilities_v1 OWNER TO {_WRITE_AUTHORITY}"
    )
    op.execute("REVOKE ALL ON dev_eval.profile_release_build_capabilities_v1 FROM PUBLIC")
    op.execute(
        "CREATE UNIQUE INDEX profile_release_build_capabilities_v1_live_authorization_uidx "
        "ON dev_eval.profile_release_build_capabilities_v1 (authorization_id) "
        "WHERE retired_at IS NULL"
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.issue_profile_release_build_capability_v1(
            p_candidate jsonb,
            p_builder_database_principal text,
            p_expected_predecessor_sha256 text
        ) RETURNS TABLE(capability_id uuid, candidate_sha256 text)
        LANGUAGE plpgsql
        SECURITY INVOKER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        BEGIN
            RAISE EXCEPTION 'profile release legacy capability issuer retired'
                USING ERRCODE = '0A000';
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.issue_profile_release_build_capability_v1(jsonb,text,text) "
        f"OWNER TO {_WRITE_AUTHORITY}"
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.record_profile_release_build_authorization_v1(
            p_resolution jsonb
        ) RETURNS TABLE(authorization_id uuid, candidate_sha256 text)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            recorded_authorization uuid;
            candidate jsonb;
            computed_resolution_sha256 text;
            existing_authorization dev_eval.profile_release_build_authorizations_v1%ROWTYPE;
        BEGIN
            IF session_user <> 'itda_profile_release_authority_service' THEN
                RAISE EXCEPTION 'profile release authority rejected'
                    USING ERRCODE = '42501';
            END IF;
            candidate := p_resolution -> 'candidate';
            computed_resolution_sha256 := pg_catalog.encode(
                pg_catalog.sha256(pg_catalog.convert_to(
                    dev_eval.canonical_jsonb_compact_v2(
                        p_resolution - 'resolution_sha256'
                    ),
                    'UTF8'
                )),
                'hex'
            );
            IF (SELECT count(*) FROM pg_catalog.jsonb_object_keys(p_resolution)) <> 9
               OR p_resolution ->> 'schema_version' IS DISTINCT FROM
                    'itda.profile-release-build-authority-resolution.v1'
               OR p_resolution ->> 'resolution_sha256' IS DISTINCT FROM
                    computed_resolution_sha256
               OR p_resolution ->> 'candidate_sha256' IS DISTINCT FROM
                    candidate ->> 'release_sha256'
               OR p_resolution ->> 'authority_root_sha256' IS NULL
               OR pg_catalog.length(p_resolution ->> 'authority_root_sha256') <> 64
               OR pg_catalog.translate(
                    p_resolution ->> 'authority_root_sha256',
                    '0123456789abcdef',
                    ''
               ) <> ''
               OR p_resolution ->> 'builder_database_principal' IS DISTINCT FROM
                    '{builder}'
               OR NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles role
                    WHERE role.rolname = '{builder}'
                      AND role.rolcanlogin
                      AND NOT role.rolinherit
                      AND NOT role.rolsuper
                      AND NOT role.rolcreatedb
                      AND NOT role.rolcreaterole
                      AND NOT role.rolreplication
                      AND NOT role.rolbypassrls
               )
               OR pg_catalog.pg_has_role(
                    '{builder}', '{_WRITE_AUTHORITY}', 'MEMBER'
               )
               OR pg_catalog.pg_has_role(
                    '{builder}', '{_AUTHORITY_SERVICE}', 'MEMBER'
               )
               OR pg_catalog.pg_has_role(
                    '{_WRITE_AUTHORITY}', '{builder}', 'MEMBER'
               )
               OR pg_catalog.pg_has_role(
                    '{_AUTHORITY_SERVICE}', '{builder}', 'MEMBER'
               )
               OR NOT EXISTS (
                    SELECT 1
                    FROM dev_eval.profile_release_fixed_root_authorities_v1 fixed
                    WHERE fixed.authority_registry_id =
                            p_resolution ->> 'authority_registry_id'
                      AND fixed.retired_at IS NULL
                      AND fixed.candidate_payload = candidate
                      AND fixed.candidate_sha256 =
                            p_resolution ->> 'candidate_sha256'
                      AND fixed.authority_root_sha256 =
                            p_resolution ->> 'authority_root_sha256'
                      AND fixed.builder_database_principal =
                            p_resolution ->> 'builder_database_principal'
                      AND fixed.expected_predecessor_sha256 IS NOT DISTINCT FROM
                            p_resolution ->> 'expected_predecessor_sha256'
                      AND fixed.expected_predecessor_lifecycle_receipt_sha256
                            IS NOT DISTINCT FROM p_resolution ->>
                                'expected_predecessor_lifecycle_receipt_sha256'
                      AND fixed.resolution_sha256 =
                            p_resolution ->> 'resolution_sha256'
               )
               OR NOT dev_eval.validate_profile_release_candidate_payload_dispatch_v1(
                    candidate
               )
               OR (
                    candidate ->> 'schema_version' = 'itda.profile-release-candidate.v2'
                    AND (
                        p_resolution ->> 'expected_predecessor_sha256' IS DISTINCT FROM
                            candidate -> 'lineage' ->> 'predecessor_release_sha256'
                        OR p_resolution ->>
                            'expected_predecessor_lifecycle_receipt_sha256'
                            IS DISTINCT FROM candidate -> 'lineage' ->>
                                'predecessor_lifecycle_receipt_sha256'
                    )
               )
               OR (
                    candidate ->> 'schema_version' = 'itda.profile-release-candidate.v1'
                    AND (
                        p_resolution -> 'expected_predecessor_sha256' <> 'null'::jsonb
                        OR p_resolution ->
                            'expected_predecessor_lifecycle_receipt_sha256' <> 'null'::jsonb
                    )
               ) THEN
                RAISE EXCEPTION 'profile release authorization rejected'
                    USING ERRCODE = '23514';
            END IF;
            PERFORM 1
            FROM dev_eval.profile_release_fixed_root_authorities_v1 fixed
            WHERE fixed.authority_registry_id = p_resolution ->> 'authority_registry_id'
              AND fixed.retired_at IS NULL
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'profile release authorization rejected'
                    USING ERRCODE = '23514';
            END IF;
            SELECT stored.* INTO existing_authorization
            FROM dev_eval.profile_release_build_authorizations_v1 stored
            WHERE stored.authority_registry_id = p_resolution ->> 'authority_registry_id'
            FOR UPDATE;
            IF FOUND THEN
                IF existing_authorization.resolution_payload IS DISTINCT FROM p_resolution
                   OR existing_authorization.resolution_sha256 IS DISTINCT FROM
                        p_resolution ->> 'resolution_sha256'
                   OR existing_authorization.authority_root_sha256 IS DISTINCT FROM
                        p_resolution ->> 'authority_root_sha256'
                   OR existing_authorization.candidate_sha256 IS DISTINCT FROM
                        p_resolution ->> 'candidate_sha256'
                   OR existing_authorization.builder_database_principal IS DISTINCT FROM
                        p_resolution ->> 'builder_database_principal'
                   OR existing_authorization.expected_predecessor_sha256 IS DISTINCT FROM
                        p_resolution ->> 'expected_predecessor_sha256'
                   OR existing_authorization.expected_predecessor_lifecycle_receipt_sha256
                        IS DISTINCT FROM p_resolution ->>
                            'expected_predecessor_lifecycle_receipt_sha256' THEN
                    RAISE EXCEPTION 'profile release authorization conflicts'
                        USING ERRCODE = '23514';
                END IF;
                RETURN QUERY SELECT existing_authorization.authorization_id,
                    existing_authorization.candidate_sha256;
                RETURN;
            END IF;
            recorded_authorization := pg_catalog.gen_random_uuid();
            INSERT INTO dev_eval.profile_release_build_authorizations_v1 (
                authorization_id, authority_registry_id,
                resolution_payload, resolution_sha256,
                authority_root_sha256, candidate_sha256,
                builder_database_principal, expected_predecessor_sha256,
                expected_predecessor_lifecycle_receipt_sha256
            ) VALUES (
                recorded_authorization,
                p_resolution ->> 'authority_registry_id', p_resolution,
                p_resolution ->> 'resolution_sha256',
                p_resolution ->> 'authority_root_sha256',
                p_resolution ->> 'candidate_sha256',
                p_resolution ->> 'builder_database_principal',
                p_resolution ->> 'expected_predecessor_sha256',
                p_resolution ->> 'expected_predecessor_lifecycle_receipt_sha256'
            );
            RETURN QUERY SELECT recorded_authorization, p_resolution ->> 'candidate_sha256';
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.record_profile_release_build_authorization_v1(jsonb) "
        f"OWNER TO {_WRITE_AUTHORITY}"
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.issue_profile_release_build_capability_v2(
            p_authorization_id uuid
        ) RETURNS TABLE(capability_id uuid, candidate_sha256 text)
        LANGUAGE plpgsql
        STRICT
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            authorization_row dev_eval.profile_release_build_authorizations_v1%ROWTYPE;
            existing_capability dev_eval.profile_release_build_capabilities_v1%ROWTYPE;
            issued_capability uuid;
        BEGIN
            IF session_user <> 'itda_profile_release_authority_service' THEN
                RAISE EXCEPTION 'profile release authority rejected'
                    USING ERRCODE = '42501';
            END IF;
            SELECT stored.* INTO authorization_row
            FROM dev_eval.profile_release_build_authorizations_v1 stored
            WHERE stored.authorization_id = p_authorization_id
            FOR UPDATE;
            IF NOT FOUND
               OR authorization_row.consumed_at IS NOT NULL
               OR authorization_row.builder_database_principal IS DISTINCT FROM '{builder}'
               OR NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles role
                    WHERE role.rolname = '{builder}'
                      AND role.rolcanlogin
                      AND NOT role.rolinherit
                      AND NOT role.rolsuper
                      AND NOT role.rolcreatedb
                      AND NOT role.rolcreaterole
                      AND NOT role.rolreplication
                      AND NOT role.rolbypassrls
               ) THEN
                RAISE EXCEPTION 'profile release authorization rejected'
                    USING ERRCODE = '23514';
            END IF;
            SELECT stored.* INTO existing_capability
            FROM dev_eval.profile_release_build_capabilities_v1 stored
            WHERE stored.authorization_id = authorization_row.authorization_id
              AND stored.retired_at IS NULL
            FOR UPDATE;
            IF FOUND THEN
                IF existing_capability.candidate_payload IS DISTINCT FROM
                        authorization_row.resolution_payload -> 'candidate'
                   OR existing_capability.candidate_sha256 IS DISTINCT FROM
                        authorization_row.candidate_sha256
                   OR existing_capability.builder_database_principal IS DISTINCT FROM
                        authorization_row.builder_database_principal
                   OR existing_capability.expected_predecessor_sha256 IS DISTINCT FROM
                        authorization_row.expected_predecessor_sha256
                   OR existing_capability.expected_predecessor_lifecycle_receipt_sha256
                        IS DISTINCT FROM
                            authorization_row.expected_predecessor_lifecycle_receipt_sha256
                   OR existing_capability.consumed_at IS NOT NULL THEN
                    RAISE EXCEPTION 'profile release authorization rejected'
                        USING ERRCODE = '23514';
                END IF;
                IF existing_capability.expires_at > CURRENT_TIMESTAMP THEN
                    RETURN QUERY SELECT existing_capability.capability_id,
                        existing_capability.candidate_sha256;
                    RETURN;
                END IF;
                UPDATE dev_eval.profile_release_build_capabilities_v1 stored
                SET retired_at = CURRENT_TIMESTAMP
                WHERE stored.capability_id = existing_capability.capability_id
                  AND stored.consumed_at IS NULL
                  AND stored.retired_at IS NULL;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'profile release capability rotation conflicted'
                        USING ERRCODE = '40001';
                END IF;
            END IF;
            issued_capability := pg_catalog.gen_random_uuid();
            INSERT INTO dev_eval.profile_release_build_capabilities_v1 (
                capability_id, authorization_id, candidate_payload, candidate_sha256,
                builder_database_principal, expected_predecessor_sha256,
                expected_predecessor_lifecycle_receipt_sha256,
                expires_at
            ) VALUES (
                issued_capability, authorization_row.authorization_id,
                authorization_row.resolution_payload -> 'candidate',
                authorization_row.candidate_sha256,
                authorization_row.builder_database_principal,
                authorization_row.expected_predecessor_sha256,
                authorization_row.expected_predecessor_lifecycle_receipt_sha256,
                CURRENT_TIMESTAMP + INTERVAL '5 minutes'
            );
            RETURN QUERY SELECT issued_capability, authorization_row.candidate_sha256;
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.issue_profile_release_build_capability_v2(uuid) "
        f"OWNER TO {_WRITE_AUTHORITY}"
    )
    op.execute(
        f"""
        CREATE FUNCTION dev_eval.consume_profile_release_build_capability_v1(
            p_capability_id uuid
        ) RETURNS text
        LANGUAGE plpgsql
        STRICT
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            capability dev_eval.profile_release_build_capabilities_v1%ROWTYPE;
            candidate jsonb;
            schema_version text;
            active_release_sha256 text;
            active_receipt_sha256 text;
        BEGIN
            SELECT stored.* INTO capability
            FROM dev_eval.profile_release_build_capabilities_v1 stored
            WHERE stored.capability_id = p_capability_id
            FOR UPDATE;
            IF NOT FOUND
               OR capability.consumed_at IS NOT NULL
               OR capability.retired_at IS NOT NULL
               OR capability.expires_at <= CURRENT_TIMESTAMP
               OR session_user IS DISTINCT FROM '{builder}'
               OR capability.builder_database_principal IS DISTINCT FROM '{builder}'
               OR session_user <> capability.builder_database_principal
               OR NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles role
                    WHERE role.rolname = '{builder}'
                      AND role.rolcanlogin
                      AND NOT role.rolinherit
                      AND NOT role.rolsuper
                      AND NOT role.rolcreatedb
                      AND NOT role.rolcreaterole
                      AND NOT role.rolreplication
                      AND NOT role.rolbypassrls
               )
               OR pg_catalog.pg_has_role(
                    '{builder}', '{_WRITE_AUTHORITY}', 'MEMBER'
               )
               OR pg_catalog.pg_has_role(
                    '{builder}', '{_AUTHORITY_SERVICE}', 'MEMBER'
               ) THEN
                RAISE EXCEPTION 'profile release capability rejected'
                    USING ERRCODE = '23514';
            END IF;
            candidate := capability.candidate_payload;
            IF candidate ->> 'release_sha256' IS DISTINCT FROM capability.candidate_sha256
               OR NOT dev_eval.validate_profile_release_candidate_payload_dispatch_v1(
                    candidate
               ) THEN
                RAISE EXCEPTION 'profile release capability rejected'
                    USING ERRCODE = '23514';
            END IF;
            schema_version := candidate ->> 'schema_version';
            IF capability.expected_predecessor_sha256 IS NOT NULL THEN
                SELECT pointer.release_sha256, pointer.receipt_sha256
                INTO active_release_sha256, active_receipt_sha256
                FROM dev_eval.profile_release_active_pointer pointer
                JOIN dev_eval.profile_release_lifecycle_heads head
                  ON head.release_sha256 = pointer.release_sha256
                 AND head.state = 'ACTIVE'
                 AND head.head_receipt_sha256 = pointer.receipt_sha256
                WHERE pointer.slot = 'DEV'
                FOR SHARE OF pointer, head;
                IF active_release_sha256 IS DISTINCT FROM
                        capability.expected_predecessor_sha256
                   OR candidate -> 'lineage' ->> 'predecessor_release_sha256'
                        IS DISTINCT FROM active_release_sha256
                   OR candidate -> 'lineage' ->> 'predecessor_lifecycle_receipt_sha256'
                        IS DISTINCT FROM active_receipt_sha256 THEN
                    RAISE EXCEPTION 'profile release capability predecessor is stale'
                        USING ERRCODE = '23514';
                END IF;
                IF capability.expected_predecessor_lifecycle_receipt_sha256
                        IS DISTINCT FROM active_receipt_sha256 THEN
                    RAISE EXCEPTION 'profile release capability predecessor is stale'
                        USING ERRCODE = '23514';
                END IF;
            ELSIF schema_version <> 'itda.profile-release-candidate.v1' THEN
                RAISE EXCEPTION 'profile release capability predecessor is absent'
                    USING ERRCODE = '23514';
            END IF;
            INSERT INTO dev_eval.profile_releases (
                release_sha256, release_id, builder_principal,
                canonical_lineage_sha256, dev_lineage_sha256,
                profile_schema_sha256, payload
            ) VALUES (
                capability.candidate_sha256,
                candidate ->> 'release_id',
                candidate ->> 'builder_principal',
                CASE WHEN schema_version = 'itda.profile-release-candidate.v2'
                    THEN candidate -> 'lineage' ->> 'canonical_lineage_sha256'
                    ELSE candidate ->> 'canonical_lineage_sha256' END,
                CASE WHEN schema_version = 'itda.profile-release-candidate.v2'
                    THEN candidate -> 'lineage' ->> 'dev_lineage_sha256'
                    ELSE candidate ->> 'dev_lineage_sha256' END,
                CASE WHEN schema_version = 'itda.profile-release-candidate.v2'
                    THEN candidate -> 'lineage' ->> 'profile_schema_sha256'
                    ELSE candidate ->> 'profile_schema_sha256' END,
                candidate
            );
            INSERT INTO dev_eval.profile_release_lifecycle_heads (
                release_sha256, state, head_receipt_sha256
            ) VALUES (
                capability.candidate_sha256, 'BUILT_UNAPPROVED', NULL
            );
            UPDATE dev_eval.profile_release_build_capabilities_v1
            SET consumed_at = CURRENT_TIMESTAMP
            WHERE capability_id = p_capability_id;
            UPDATE dev_eval.profile_release_build_authorizations_v1
            SET consumed_at = CURRENT_TIMESTAMP
            WHERE authorization_id = capability.authorization_id
              AND consumed_at IS NULL;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'profile release authorization consumption conflicted'
                    USING ERRCODE = '23514';
            END IF;
            RETURN capability.candidate_sha256;
        END;
        $function$
        """
    )
    op.execute(
        "ALTER FUNCTION dev_eval.consume_profile_release_build_capability_v1(uuid) "
        f"OWNER TO {_WRITE_AUTHORITY}"
    )

    for signature in (
        "issue_profile_release_build_capability_v1(jsonb,text,text)",
        "record_profile_release_build_authorization_v1(jsonb)",
        "issue_profile_release_build_capability_v2(uuid)",
        "consume_profile_release_build_capability_v1(uuid)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION dev_eval.{signature} FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO " + _AUTHORITY_SERVICE)
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.record_profile_release_build_authorization_v1(jsonb), "
        "dev_eval.issue_profile_release_build_capability_v2(uuid) TO " + _AUTHORITY_SERVICE
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.consume_profile_release_build_capability_v1(uuid) TO " + quoted_builder
    )
    op.execute("GRANT USAGE ON SCHEMA dev_eval TO " + _WRITE_AUTHORITY)
    op.execute("GRANT SELECT, INSERT ON dev_eval.profile_releases TO " + _WRITE_AUTHORITY)
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON dev_eval.profile_release_lifecycle_heads TO "
        + _WRITE_AUTHORITY
    )
    op.execute(
        "GRANT SELECT, UPDATE ON dev_eval.profile_release_active_pointer TO " + _WRITE_AUTHORITY
    )
    for signature in (
        "canonical_jsonb_compact_v1(jsonb)",
        "canonical_jsonb_compact_v2(jsonb)",
        "validate_profile_release_candidate_payload_v1(jsonb)",
        "validate_profile_release_candidate_payload_v2(jsonb)",
        "validate_profile_release_candidate_payload_dispatch_v1(jsonb)",
    ):
        op.execute(f"GRANT EXECUTE ON FUNCTION dev_eval.{signature} TO {_WRITE_AUTHORITY}")
    op.execute(
        "REVOKE INSERT, UPDATE, DELETE ON dev_eval.profile_releases, "
        "dev_eval.profile_release_lifecycle_heads, "
        "dev_eval.profile_release_v2_transition_proofs, "
        "dev_eval.profile_release_build_receipts, "
        "dev_eval.profile_release_transition_events, "
        "dev_eval.profile_release_rollback_receipts FROM " + quoted_builder
    )


def downgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    if builder is None:
        raise RuntimeError("profile release builder role is required")
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "LOCK TABLE dev_eval.profile_release_build_capabilities_v1, "
            "dev_eval.profile_release_build_authorizations_v1, "
            "dev_eval.profile_release_fixed_root_authorities_v1 "
            "IN ACCESS EXCLUSIVE MODE"
        )
    )
    if connection.execute(
        sa.text(
            "SELECT (SELECT count(*) FROM dev_eval.profile_release_build_capabilities_v1) + "
            "(SELECT count(*) FROM dev_eval.profile_release_build_authorizations_v1) + "
            "(SELECT count(*) FROM dev_eval.profile_release_fixed_root_authorities_v1)"
        )
    ).scalar_one():
        raise RuntimeError(
            "0014 downgrade is intentionally irreversible after capability state exists"
        )
    op.execute("DROP FUNCTION dev_eval.consume_profile_release_build_capability_v1(uuid)")
    op.execute("DROP FUNCTION dev_eval.issue_profile_release_build_capability_v2(uuid)")
    op.execute("DROP FUNCTION dev_eval.record_profile_release_build_authorization_v1(jsonb)")
    op.execute("DROP FUNCTION dev_eval.issue_profile_release_build_capability_v1(jsonb,text,text)")
    op.drop_table("profile_release_build_capabilities_v1", schema="dev_eval")
    op.drop_table("profile_release_build_authorizations_v1", schema="dev_eval")
    op.drop_table("profile_release_fixed_root_authorities_v1", schema="dev_eval")
    quoted_builder = _quoted_identifier(builder)
    op.execute("REVOKE SELECT, INSERT ON dev_eval.profile_releases FROM " + _WRITE_AUTHORITY)
    op.execute(
        "REVOKE SELECT, INSERT, UPDATE ON dev_eval.profile_release_lifecycle_heads FROM "
        + _WRITE_AUTHORITY
    )
    op.execute(
        "REVOKE SELECT, UPDATE ON dev_eval.profile_release_active_pointer FROM " + _WRITE_AUTHORITY
    )
    for signature in (
        "canonical_jsonb_compact_v1(jsonb)",
        "canonical_jsonb_compact_v2(jsonb)",
        "validate_profile_release_candidate_payload_v1(jsonb)",
        "validate_profile_release_candidate_payload_v2(jsonb)",
        "validate_profile_release_candidate_payload_dispatch_v1(jsonb)",
    ):
        op.execute(f"REVOKE EXECUTE ON FUNCTION dev_eval.{signature} FROM {_WRITE_AUTHORITY}")
    op.execute(
        "GRANT INSERT ON dev_eval.profile_releases, "
        "dev_eval.profile_release_lifecycle_heads TO " + quoted_builder
    )
