"""Allow complete national source-only pairs without changing archived scoring contracts."""

# Keep SQL identity checks together for review.
# ruff: noqa: E501
from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision = "0031_national_grounded_catalog"
down_revision = "0030_grounded_release_pairs"
branch_labels = None
depends_on = None

_OLD_BOUND = "jsonb_array_length(p->'raw_release'->'profiles') NOT BETWEEN 80 AND 100"
_NEW_BOUND = """(CASE WHEN p->'raw_release'->>'schema_version' = 'grounded-source-release.v1'
                    THEN jsonb_array_length(p->'raw_release'->'profiles') NOT BETWEEN 1 AND 1000
                    ELSE jsonb_array_length(p->'raw_release'->'profiles') NOT BETWEEN 80 AND 100 END)"""
_INSERT_MARKER = "            INSERT INTO app.grounded_release_candidates("


def _hash(value: str) -> str:
    return f"encode(sha256(convert_to(dev_eval.canonical_jsonb_compact_v2({value}),'UTF8')),'hex')"


_SOURCE_CHECKS = f"""
            IF p->'raw_release'->>'schema_version' = 'grounded-source-release.v1' THEN
                IF p->'raw_release'->>'release_sha256' IS DISTINCT FROM {_hash("(p->'raw_release')-'release_sha256'")}
                    OR jsonb_typeof(p->'raw_release'->'published_count') IS DISTINCT FROM 'number'
                    OR (p->'raw_release'->>'published_count')::integer IS DISTINCT FROM jsonb_array_length(p->'raw_release'->'profiles')
                    OR (SELECT count(DISTINCT value->>'place_id') FROM jsonb_array_elements(p->'raw_release'->'profiles')) IS DISTINCT FROM jsonb_array_length(p->'raw_release'->'profiles')::bigint
                    OR p->'raw_release'->>'membership_sha256' IS DISTINCT FROM {_hash("(SELECT jsonb_agg(value->'place_id' ORDER BY value->>'place_id' COLLATE \"C\") FROM jsonb_array_elements(p->'raw_release'->'profiles'))")}
                    OR (SELECT jsonb_agg(value->'place_id') FROM jsonb_array_elements(p->'raw_release'->'profiles')) IS DISTINCT FROM (SELECT jsonb_agg(value->'place_id' ORDER BY value->>'place_id' COLLATE "C") FROM jsonb_array_elements(p->'raw_release'->'profiles'))
                    OR (SELECT count(DISTINCT value->'place'->>'place_id') FROM jsonb_array_elements(p->'source_snapshots')) IS DISTINCT FROM jsonb_array_length(p->'raw_release'->'profiles')::bigint THEN
                    RAISE EXCEPTION 'invalid national source membership' USING ERRCODE='23514';
                END IF;
                FOR i IN 0..jsonb_array_length(p->'raw_release'->'profiles')-1 LOOP
                    profile:=p->'raw_release'->'profiles'->i;
                    IF profile->>'schema_version' IS DISTINCT FROM 'grounded-source-profile.v1'
                        OR profile ? 'scores'
                        OR profile->>'profile_sha256' IS DISTINCT FROM {_hash("profile-'profile_sha256'")}
                        OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p->'source_snapshots') source
                            WHERE source->'place'->>'place_id'=profile->>'place_id'
                              AND source->>'catalog_row_sha256'=profile->>'catalog_row_sha256'
                              AND source->'place'->>'name_ko'=profile->>'place_name_ko') THEN
                        RAISE EXCEPTION 'national source profile binding differs' USING ERRCODE='23514';
                    END IF;
                END LOOP;
            END IF;
"""


def _definition() -> str:
    definition = (
        op.get_bind()
        .execute(
            text(
                "SELECT pg_get_functiondef('app.stage_grounded_release_candidate_v1(jsonb)'::regprocedure)"
            )
        )
        .scalar_one()
    )
    if not isinstance(definition, str):
        raise ValueError("grounded staging function definition is missing")
    return definition


def upgrade() -> None:
    definition = _definition()
    if definition.count(_OLD_BOUND) != 1 or definition.count(_INSERT_MARKER) != 1:
        raise ValueError("grounded staging authority differs from migration 0030")
    # CREATE OR REPLACE retains the existing SECURITY DEFINER owner, grants,
    # fixed search_path, session-user guard, immutable inserts and complete pair checks.
    updated = definition.replace(_OLD_BOUND, _NEW_BOUND).replace(
        _INSERT_MARKER, _SOURCE_CHECKS + _INSERT_MARKER
    )
    op.execute(text(updated))


def downgrade() -> None:
    definition = _definition()
    if definition.count(_NEW_BOUND) != 1 or definition.count(_SOURCE_CHECKS) != 1:
        raise ValueError("national staging authority differs from migration 0031")
    op.execute(text(definition.replace(_SOURCE_CHECKS, "").replace(_NEW_BOUND, _OLD_BOUND)))
