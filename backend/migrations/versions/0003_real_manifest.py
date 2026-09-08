"""Add insert-only real catalog manifest and split seal storage."""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0003_real_manifest"
down_revision = "0002_split_boundaries"
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
    op.create_table(
        "real_manifest_seals",
        sa.Column("manifest_version", sa.Text(), nullable=False),
        sa.Column("catalog_revision_sha256", sa.Text(), nullable=False),
        sa.Column("catalog_approval_sha256", sa.Text(), nullable=False),
        sa.Column("split_approval_sha256", sa.Text(), nullable=False),
        sa.Column("split_manifest_sha256", sa.Text(), nullable=False),
        sa.Column("membership_sha256", sa.Text(), nullable=False),
        sa.Column("canonicalization_version", sa.Text(), nullable=False),
        sa.Column("dev_count", sa.Integer(), nullable=False),
        sa.Column("blind_count", sa.Integer(), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("dev_count = 24", name="ck_real_manifest_dev_count"),
        sa.CheckConstraint("blind_count = 12", name="ck_real_manifest_blind_count"),
        sa.CheckConstraint("member_count = 36", name="ck_real_manifest_member_count"),
        sa.CheckConstraint(
            "canonicalization_version = 'canonical-json-v1'",
            name="ck_real_manifest_canonicalization",
        ),
        sa.PrimaryKeyConstraint("manifest_version", name="pk_real_manifest_seals"),
        schema="blind_eval",
    )
    for schema_name, minimum, maximum, split in (
        ("dev_eval", 1, 24, "DEV"),
        ("blind_eval", 25, 36, "BLIND"),
    ):
        op.create_table(
            "real_manifest_members",
            sa.Column("manifest_version", sa.Text(), nullable=False),
            sa.Column("member_ordinal", sa.Integer(), nullable=False),
            sa.Column("canonical_place_id", sa.Text(), nullable=False),
            sa.Column("split", sa.Text(), nullable=False),
            sa.ForeignKeyConstraint(
                ["manifest_version"],
                ["blind_eval.real_manifest_seals.manifest_version"],
                name=f"fk_{schema_name}_real_manifest_seal",
                ondelete="RESTRICT",
            ),
            sa.CheckConstraint(
                f"member_ordinal BETWEEN {minimum} AND {maximum}",
                name=f"ck_{schema_name}_real_member_ordinal",
            ),
            sa.CheckConstraint(f"split = '{split}'", name=f"ck_{schema_name}_real_split"),
            sa.PrimaryKeyConstraint(
                "manifest_version",
                "member_ordinal",
                name=f"pk_{schema_name}_real_manifest_members",
            ),
            sa.UniqueConstraint(
                "manifest_version",
                "canonical_place_id",
                name=f"uq_{schema_name}_real_manifest_place",
            ),
            schema=schema_name,
        )

    op.execute(
        """
        CREATE FUNCTION blind_eval.seal_real_manifest_v1(
            manifest_version text,
            seal_payload jsonb,
            dev_members jsonb,
            blind_members jsonb,
            sealed_at timestamptz
        ) RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, blind_eval, dev_eval
        AS $function$
        BEGIN
            IF jsonb_array_length(dev_members) <> 24
               OR jsonb_array_length(blind_members) <> 12 THEN
                RAISE EXCEPTION 'real manifest requires exact 24/12 membership';
            END IF;
            INSERT INTO blind_eval.real_manifest_seals (
                manifest_version, catalog_revision_sha256, catalog_approval_sha256,
                split_approval_sha256, split_manifest_sha256, membership_sha256,
                canonicalization_version, dev_count, blind_count, member_count, sealed_at
            ) VALUES (
                manifest_version,
                seal_payload->>'catalog_revision_sha256',
                seal_payload->>'catalog_approval_sha256',
                seal_payload->>'split_approval_sha256',
                seal_payload->>'split_manifest_sha256',
                seal_payload->>'membership_sha256',
                seal_payload->>'canonicalization_version', 24, 12, 36, sealed_at
            );
            INSERT INTO dev_eval.real_manifest_members (
                manifest_version, member_ordinal, canonical_place_id, split
            ) SELECT manifest_version, ordinal::integer, member#>>'{}', 'DEV'
              FROM jsonb_array_elements(dev_members) WITH ORDINALITY AS entry(member, ordinal);
            INSERT INTO blind_eval.real_manifest_members (
                manifest_version, member_ordinal, canonical_place_id, split
            ) SELECT manifest_version, (ordinal + 24)::integer, member#>>'{}', 'BLIND'
              FROM jsonb_array_elements(blind_members) WITH ORDINALITY AS entry(member, ordinal);
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE FUNCTION blind_eval.lookup_real_manifest_seal_v1(requested_version text)
        RETURNS jsonb
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, blind_eval
        AS $function$
            SELECT jsonb_build_object(
                'manifest_version', manifest_version,
                'catalog_revision_sha256', catalog_revision_sha256,
                'catalog_approval_sha256', catalog_approval_sha256,
                'split_approval_sha256', split_approval_sha256,
                'split_manifest_sha256', split_manifest_sha256,
                'membership_sha256', membership_sha256,
                'canonicalization_version', canonicalization_version,
                'dev_count', dev_count, 'blind_count', blind_count,
                'member_count', member_count, 'sealed_at', sealed_at
            ) FROM blind_eval.real_manifest_seals
              WHERE manifest_version = requested_version;
        $function$
        """
    )
    op.execute(
        "REVOKE ALL ON FUNCTION blind_eval.seal_real_manifest_v1"
        "(text, jsonb, jsonb, jsonb, timestamptz) FROM PUBLIC"
    )
    op.execute("REVOKE ALL ON FUNCTION blind_eval.lookup_real_manifest_seal_v1(text) FROM PUBLIC")
    op.execute(
        "REVOKE ALL ON blind_eval.real_manifest_seals, "
        "dev_eval.real_manifest_members, blind_eval.real_manifest_members FROM PUBLIC"
    )
    sealer_role = _configured_identifier("sealer_role")
    if sealer_role is not None:
        quoted = _quoted_identifier(sealer_role)
        op.execute(sa.text(f"GRANT USAGE ON SCHEMA blind_eval TO {quoted}"))
        op.execute(
            sa.text(
                "GRANT EXECUTE ON FUNCTION blind_eval.seal_real_manifest_v1"
                f"(text, jsonb, jsonb, jsonb, timestamptz) TO {quoted}"
            )
        )
        op.execute(
            sa.text(
                "GRANT EXECUTE ON FUNCTION blind_eval.lookup_real_manifest_seal_v1(text) "
                f"TO {quoted}"
            )
        )


def downgrade() -> None:
    op.execute("DROP FUNCTION blind_eval.lookup_real_manifest_seal_v1(text)")
    op.execute(
        "DROP FUNCTION blind_eval.seal_real_manifest_v1(text, jsonb, jsonb, jsonb, timestamptz)"
    )
    op.drop_table("real_manifest_members", schema="blind_eval")
    op.drop_table("real_manifest_members", schema="dev_eval")
    op.drop_table("real_manifest_seals", schema="blind_eval")
