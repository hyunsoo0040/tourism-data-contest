"""Create synthetic split storage and deny-by-construction role boundaries."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0002_split_boundaries"
down_revision = "0001_app_profiles"
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


def _validate_distinct_capability_roles() -> None:
    roles = [
        _configured_identifier(f"{capability}_role")
        for capability in ("runtime", "dev", "sealer", "evaluator")
    ]
    configured_roles = [role for role in roles if role is not None]
    if len(configured_roles) != len(set(configured_roles)):
        raise ValueError("capability role identifiers must be distinct")


def _configure_role_access() -> None:
    database_name = _configured_identifier("database_name")
    dev_role = _configured_identifier("dev_role")
    sealer_role = _configured_identifier("sealer_role")
    evaluator_role = _configured_identifier("evaluator_role")

    if dev_role is not None:
        quoted = _quoted_identifier(dev_role)
        op.execute(sa.text(f"GRANT USAGE ON SCHEMA app, dev_eval TO {quoted}"))
        op.execute(sa.text(f"GRANT SELECT ON ALL TABLES IN SCHEMA app TO {quoted}"))
        op.execute(sa.text(f"GRANT SELECT ON dev_eval.manifest_members TO {quoted}"))
        if database_name is not None:
            op.execute(
                sa.text(
                    f"ALTER ROLE {quoted} IN DATABASE {_quoted_identifier(database_name)} "
                    "SET search_path TO dev_eval, app, pg_catalog"
                )
            )

    if sealer_role is not None:
        quoted = _quoted_identifier(sealer_role)
        op.execute(sa.text(f"GRANT USAGE ON SCHEMA blind_eval TO {quoted}"))
        op.execute(
            sa.text(
                "GRANT EXECUTE ON FUNCTION blind_eval.seal_manifest_v1"
                "(text, text, timestamptz) "
                f"TO {quoted}"
            )
        )
        if database_name is not None:
            op.execute(
                sa.text(
                    f"ALTER ROLE {quoted} IN DATABASE {_quoted_identifier(database_name)} "
                    "SET search_path TO pg_catalog"
                )
            )

    if evaluator_role is not None:
        quoted = _quoted_identifier(evaluator_role)
        op.execute(sa.text(f"GRANT USAGE ON SCHEMA blind_eval TO {quoted}"))
        op.execute(sa.text(f"GRANT SELECT ON blind_eval.evaluator_manifest_v1 TO {quoted}"))
        if database_name is not None:
            op.execute(
                sa.text(
                    f"ALTER ROLE {quoted} IN DATABASE {_quoted_identifier(database_name)} "
                    "SET search_path TO blind_eval, pg_catalog"
                )
            )


def _reset_role_search_paths() -> None:
    database_name = _configured_identifier("database_name")
    if database_name is None:
        return
    quoted_database = _quoted_identifier(database_name)
    for capability in ("dev", "sealer", "evaluator"):
        role = _configured_identifier(f"{capability}_role")
        if role is not None:
            op.execute(
                sa.text(
                    f"ALTER ROLE {_quoted_identifier(role)} IN DATABASE {quoted_database} "
                    "RESET search_path"
                )
            )


def upgrade() -> None:
    _validate_distinct_capability_roles()

    op.execute("CREATE SCHEMA dev_eval")
    op.execute("CREATE SCHEMA blind_eval")
    op.execute("REVOKE ALL ON SCHEMA dev_eval, blind_eval FROM PUBLIC")

    op.create_table(
        "manifest_seals",
        sa.Column("manifest_version", sa.Text(), nullable=False),
        sa.Column("canonicalization_version", sa.Text(), nullable=False),
        sa.Column("manifest_sha256", sa.Text(), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "canonicalization_version = 'canonical-json-v1'",
            name="ck_manifest_seals_canonicalization",
        ),
        sa.CheckConstraint(
            "manifest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_manifest_seals_sha256",
        ),
        sa.PrimaryKeyConstraint("manifest_version", name="pk_manifest_seals"),
        schema="blind_eval",
    )
    op.create_table(
        "manifest_members",
        sa.Column("manifest_version", sa.Text(), nullable=False),
        sa.Column("member_ordinal", sa.Integer(), nullable=False),
        sa.Column("synthetic_place_id", sa.Text(), nullable=False),
        sa.Column("split", sa.Text(), nullable=False),
        sa.CheckConstraint("member_ordinal BETWEEN 25 AND 36", name="ck_blind_member_ordinal"),
        sa.CheckConstraint("split = 'BLIND'", name="ck_blind_member_split"),
        sa.CheckConstraint(
            "synthetic_place_id ~ '^synthetic:blind:'",
            name="ck_blind_member_synthetic_id",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_version"],
            ["blind_eval.manifest_seals.manifest_version"],
            name="fk_blind_member_seal",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "manifest_version", "member_ordinal", name="pk_blind_manifest_members"
        ),
        sa.UniqueConstraint(
            "manifest_version", "synthetic_place_id", name="uq_blind_manifest_member_id"
        ),
        schema="blind_eval",
    )
    op.create_table(
        "manifest_members",
        sa.Column("manifest_version", sa.Text(), nullable=False),
        sa.Column("member_ordinal", sa.Integer(), nullable=False),
        sa.Column("synthetic_place_id", sa.Text(), nullable=False),
        sa.Column("split", sa.Text(), nullable=False),
        sa.CheckConstraint("member_ordinal BETWEEN 1 AND 24", name="ck_dev_member_ordinal"),
        sa.CheckConstraint("split = 'DEV'", name="ck_dev_member_split"),
        sa.CheckConstraint(
            "synthetic_place_id ~ '^synthetic:dev:'",
            name="ck_dev_member_synthetic_id",
        ),
        sa.ForeignKeyConstraint(
            ["manifest_version"],
            ["blind_eval.manifest_seals.manifest_version"],
            name="fk_dev_member_seal",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "manifest_version", "member_ordinal", name="pk_dev_manifest_members"
        ),
        sa.UniqueConstraint(
            "manifest_version", "synthetic_place_id", name="uq_dev_manifest_member_id"
        ),
        schema="dev_eval",
    )

    op.execute(
        """
        CREATE FUNCTION blind_eval.seal_manifest_v1(
            p_manifest_canonical text,
            p_manifest_sha256 text,
            p_sealed_at timestamptz
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $function$
        DECLARE
            manifest_payload jsonb;
            expected_canonical text;
            computed_sha256 text;
            manifest_version text;
            canonicalization_version text;
            dev_count integer;
            blind_count integer;
            unique_count integer;
        BEGIN
            manifest_payload := p_manifest_canonical::jsonb;
            IF jsonb_typeof(manifest_payload) IS DISTINCT FROM 'object'
               OR jsonb_typeof(manifest_payload->'members') IS DISTINCT FROM 'array'
               OR jsonb_array_length(manifest_payload->'members') <> 36 THEN
                RAISE EXCEPTION 'manifest must contain exactly 36 members'
                    USING ERRCODE = '22023';
            END IF;
            manifest_version := manifest_payload->>'manifest_version';
            canonicalization_version := manifest_payload->>'canonicalization_version';
            IF manifest_version IS NULL
               OR canonicalization_version IS DISTINCT FROM 'canonical-json-v1'
               OR p_manifest_sha256 !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'manifest seal metadata does not match the payload'
                    USING ERRCODE = '22023';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM jsonb_array_elements(manifest_payload->'members') AS entry(member)
                WHERE jsonb_typeof(member) IS DISTINCT FROM 'object'
                   OR NOT member ?& ARRAY['synthetic_place_id', 'split']
                   OR (member - ARRAY['synthetic_place_id', 'split']) <> '{}'::jsonb
                   OR member->>'synthetic_place_id' !~ '^synthetic:(dev|blind):'
                   OR member->>'split' NOT IN ('DEV', 'BLIND')
                   OR (member->>'split' = 'DEV'
                       AND member->>'synthetic_place_id' !~ '^synthetic:dev:')
                   OR (member->>'split' = 'BLIND'
                       AND member->>'synthetic_place_id' !~ '^synthetic:blind:')
            ) THEN
                RAISE EXCEPTION 'manifest members must be synthetic DEV or BLIND rows'
                    USING ERRCODE = '22023';
            END IF;

            SELECT
                count(*) FILTER (WHERE member->>'split' = 'DEV'),
                count(*) FILTER (WHERE member->>'split' = 'BLIND'),
                count(DISTINCT convert_to(member->>'synthetic_place_id', 'UTF8'))
            INTO dev_count, blind_count, unique_count
            FROM jsonb_array_elements(manifest_payload->'members') AS entry(member);
            IF dev_count <> 24 OR blind_count <> 12 OR unique_count <> 36 THEN
                RAISE EXCEPTION 'manifest must contain unique 24 DEV and 12 BLIND IDs'
                    USING ERRCODE = '22023';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM (
                    SELECT
                        ordinal,
                        member->>'split' AS split,
                        (member->>'synthetic_place_id') COLLATE "C"
                            AS synthetic_place_id,
                        lag((member->>'synthetic_place_id') COLLATE "C") OVER (
                            PARTITION BY member->>'split' ORDER BY ordinal
                        ) AS previous_id
                    FROM jsonb_array_elements(manifest_payload->'members')
                        WITH ORDINALITY AS entry(member, ordinal)
                ) ordered
                WHERE (ordinal <= 24 AND split <> 'DEV')
                   OR (ordinal > 24 AND split <> 'BLIND')
                   OR (previous_id COLLATE "C") >= (synthetic_place_id COLLATE "C")
            ) THEN
                RAISE EXCEPTION 'manifest members are not in canonical split and ID order'
                    USING ERRCODE = '22023';
            END IF;

            SELECT
                '{"canonicalization_version":'
                || to_jsonb(canonicalization_version)::text
                || ',"manifest_version":'
                || to_jsonb(manifest_version)::text
                || ',"members":['
                || string_agg(
                    '{"split":' || to_jsonb(member->>'split')::text
                    || ',"synthetic_place_id":'
                    || to_jsonb(member->>'synthetic_place_id')::text || '}',
                    ',' ORDER BY ordinal
                )
                || ']}'
            INTO expected_canonical
            FROM jsonb_array_elements(manifest_payload->'members')
                WITH ORDINALITY AS entry(member, ordinal);
            IF p_manifest_canonical IS DISTINCT FROM expected_canonical THEN
                RAISE EXCEPTION 'manifest payload is not exact canonical UTF-8 JSON text'
                    USING ERRCODE = '22023';
            END IF;

            computed_sha256 := encode(
                sha256(convert_to(p_manifest_canonical, 'UTF8')),
                'hex'
            );
            IF p_manifest_sha256 IS DISTINCT FROM computed_sha256 THEN
                RAISE EXCEPTION 'manifest digest does not match canonical payload bytes'
                    USING ERRCODE = '22023';
            END IF;

            INSERT INTO blind_eval.manifest_seals (
                manifest_version,
                canonicalization_version,
                manifest_sha256,
                sealed_at
            ) VALUES (
                manifest_version,
                canonicalization_version,
                computed_sha256,
                p_sealed_at
            );
            INSERT INTO dev_eval.manifest_members (
                manifest_version, member_ordinal, synthetic_place_id, split
            )
            SELECT
                manifest_version,
                ordinal::integer,
                member->>'synthetic_place_id',
                member->>'split'
            FROM jsonb_array_elements(manifest_payload->'members')
                WITH ORDINALITY AS entry(member, ordinal)
            WHERE member->>'split' = 'DEV';
            INSERT INTO blind_eval.manifest_members (
                manifest_version, member_ordinal, synthetic_place_id, split
            )
            SELECT
                manifest_version,
                ordinal::integer,
                member->>'synthetic_place_id',
                member->>'split'
            FROM jsonb_array_elements(manifest_payload->'members')
                WITH ORDINALITY AS entry(member, ordinal)
            WHERE member->>'split' = 'BLIND';
        END;
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION blind_eval.seal_manifest_v1(text, text, timestamptz) FROM PUBLIC"
    )
    op.execute(
        """
        CREATE VIEW blind_eval.evaluator_manifest_v1 AS
        SELECT
            seal.manifest_version,
            member.member_ordinal,
            member.synthetic_place_id,
            member.split,
            seal.canonicalization_version,
            seal.manifest_sha256,
            seal.sealed_at
        FROM blind_eval.manifest_seals AS seal
        JOIN dev_eval.manifest_members AS member USING (manifest_version)
        UNION ALL
        SELECT
            seal.manifest_version,
            member.member_ordinal,
            member.synthetic_place_id,
            member.split,
            seal.canonicalization_version,
            seal.manifest_sha256,
            seal.sealed_at
        FROM blind_eval.manifest_seals AS seal
        JOIN blind_eval.manifest_members AS member USING (manifest_version)
        """
    )
    op.execute(
        "CREATE VIEW blind_eval.internal_manifest_v1 AS "
        "SELECT manifest_version, manifest_sha256 FROM blind_eval.manifest_seals"
    )
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA dev_eval, blind_eval FROM PUBLIC")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA dev_eval, blind_eval REVOKE ALL ON TABLES FROM PUBLIC"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA blind_eval REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    _configure_role_access()


def downgrade() -> None:
    _reset_role_search_paths()
    op.execute("DROP VIEW blind_eval.internal_manifest_v1")
    op.execute("DROP VIEW blind_eval.evaluator_manifest_v1")
    op.execute("DROP FUNCTION blind_eval.seal_manifest_v1(text, text, timestamptz)")
    op.drop_table("manifest_members", schema="dev_eval")
    op.drop_table("manifest_members", schema="blind_eval")
    op.drop_table("manifest_seals", schema="blind_eval")
    op.execute("DROP SCHEMA dev_eval")
    op.execute("DROP SCHEMA blind_eval")
