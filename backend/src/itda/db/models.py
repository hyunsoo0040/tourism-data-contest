"""Typed SQLAlchemy models for the application-owned profile schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def answers_check_sql(column: str = "answers") -> str:
    """Version-coupled answers check for questionnaire v1 and v2 rows.

    Reuses the explicit 0001 key/type/range form (jsonb object, exact keys,
    numeric values matching the per-version range) with no subqueries.
    """

    version_column = "questionnaire_version"
    v1_required = ", ".join(f"'q{number}'" for number in range(1, 10))
    v1_value_checks = " AND ".join(
        (f"jsonb_typeof({column}->'q{number}') = 'number' AND ({column}->>'q{number}') ~ '^[1-5]$'")
        for number in range(1, 10)
    )
    v1_check = (
        f"jsonb_typeof({column}) = 'object' "
        f"AND {column} ?& ARRAY[{v1_required}] "
        f"AND ({column} - ARRAY[{v1_required}]) = '{{}}'::jsonb "
        f"AND {v1_value_checks}"
    )
    v2_required = ", ".join(f"'q{number}'" for number in range(1, 13))
    v2_value_checks = " AND ".join(
        (f"jsonb_typeof({column}->'q{number}') = 'number' AND ({column}->>'q{number}') ~ '^[1-3]$'")
        for number in range(1, 13)
    )
    v2_check = (
        f"jsonb_typeof({column}) = 'object' "
        f"AND {column} ?& ARRAY[{v2_required}] "
        f"AND ({column} - ARRAY[{v2_required}]) = '{{}}'::jsonb "
        f"AND {v2_value_checks}"
    )
    return (
        f"(({version_column} = 'questionnaire-v1' AND ({v1_check})) "
        f"OR ({version_column} = 'questionnaire-v2' AND ({v2_check})))"
    )


class Base(DeclarativeBase):
    metadata = MetaData(schema="app", naming_convention=NAMING_CONVENTION)


class JourneyDraftRow(Base):
    __tablename__ = "journey_drafts"
    __table_args__ = (
        CheckConstraint("char_length(session_id) BETWEEN 1 AND 160", name="session_id"),
        CheckConstraint("jsonb_typeof(trip_conditions) = 'object'", name="trip_conditions"),
        CheckConstraint(answers_check_sql(), name="answers"),
        CheckConstraint(
            "char_length(questionnaire_version) BETWEEN 1 AND 128",
            name="questionnaire_version",
        ),
    )

    session_id: Mapped[str] = mapped_column(Text, primary_key=True)
    trip_conditions: Mapped[dict[str, Any]] = mapped_column(JSONB)
    answers: Mapped[dict[str, int]] = mapped_column(JSONB)
    questionnaire_version: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PreferenceProfileRow(Base):
    __tablename__ = "preference_profiles"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_preference_profiles_request_id"),
        CheckConstraint("char_length(profile_id) BETWEEN 1 AND 160", name="profile_id"),
        CheckConstraint("char_length(request_id) BETWEEN 1 AND 160", name="request_id"),
        CheckConstraint("jsonb_typeof(trip_conditions) = 'object'", name="trip_conditions"),
        CheckConstraint(answers_check_sql(), name="answers"),
        CheckConstraint("history_basis_points BETWEEN 0 AND 10000", name="history_bp"),
        CheckConstraint("emotion_basis_points BETWEEN 0 AND 10000", name="emotion_bp"),
        CheckConstraint("rest_basis_points BETWEEN 0 AND 10000", name="rest_bp"),
        CheckConstraint("history_display_score BETWEEN 0 AND 100", name="history_display"),
        CheckConstraint("emotion_display_score BETWEEN 0 AND 100", name="emotion_display"),
        CheckConstraint("rest_display_score BETWEEN 0 AND 100", name="rest_display"),
        CheckConstraint(
            "history_display_score = (history_basis_points + 50) / 100",
            name="history_rounding",
        ),
        CheckConstraint(
            "emotion_display_score = (emotion_basis_points + 50) / 100",
            name="emotion_rounding",
        ),
        CheckConstraint(
            "rest_display_score = (rest_basis_points + 50) / 100",
            name="rest_rounding",
        ),
        CheckConstraint("char_length(description_ko) BETWEEN 1 AND 500", name="description"),
        CheckConstraint("char_length(schema_version) BETWEEN 1 AND 128", name="schema_version"),
        CheckConstraint(
            "char_length(questionnaire_version) BETWEEN 1 AND 128",
            name="questionnaire_version",
        ),
        CheckConstraint("char_length(scoring_version) BETWEEN 1 AND 128", name="scoring_version"),
        CheckConstraint(
            "char_length(description_template_version) BETWEEN 1 AND 128",
            name="template_version",
        ),
        CheckConstraint("config_hash ~ '^[0-9a-f]{64}$'", name="config_hash"),
        CheckConstraint("is_current_trip_expectation", name="current_trip_expectation"),
    )

    profile_id: Mapped[str] = mapped_column(Text, primary_key=True)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    trip_conditions: Mapped[dict[str, Any]] = mapped_column(JSONB)
    answers: Mapped[dict[str, int]] = mapped_column(JSONB)
    history_basis_points: Mapped[int] = mapped_column(Integer)
    history_display_score: Mapped[int] = mapped_column(Integer)
    emotion_basis_points: Mapped[int] = mapped_column(Integer)
    emotion_display_score: Mapped[int] = mapped_column(Integer)
    rest_basis_points: Mapped[int] = mapped_column(Integer)
    rest_display_score: Mapped[int] = mapped_column(Integer)
    description_ko: Mapped[str] = mapped_column(Text)
    schema_version: Mapped[str] = mapped_column(Text)
    questionnaire_version: Mapped[str] = mapped_column(Text)
    scoring_version: Mapped[str] = mapped_column(Text)
    description_template_version: Mapped[str] = mapped_column(Text)
    config_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_current_trip_expectation: Mapped[bool] = mapped_column(Boolean)


class RecommendationRunRow(Base):
    """Immutable validated recommendation receipt bound to one request identity."""

    __tablename__ = "recommendation_runs"
    __table_args__ = (
        UniqueConstraint("request_id", name="uq_recommendation_runs_request_id"),
        UniqueConstraint("receipt_sha256", name="uq_recommendation_runs_receipt_sha256"),
        UniqueConstraint(
            "run_id",
            "preference_profile_id",
            "input_digest",
            name="uq_recommendation_runs_binding_metadata",
        ),
        CheckConstraint("char_length(run_id) BETWEEN 1 AND 160", name="run_id"),
        CheckConstraint("char_length(request_id) BETWEEN 1 AND 160", name="request_id"),
        CheckConstraint(
            "char_length(preference_profile_id) BETWEEN 1 AND 160",
            name="preference_profile_id",
        ),
        CheckConstraint("input_digest ~ '^[0-9a-f]{64}$'", name="input_digest"),
        CheckConstraint("release_sha256 ~ '^[0-9a-f]{64}$'", name="release_sha256"),
        CheckConstraint(
            "canonical_membership_sha256 ~ '^[0-9a-f]{64}$'",
            name="membership_sha256",
        ),
        CheckConstraint("config_sha256 ~ '^[0-9a-f]{64}$'", name="config_sha256"),
        CheckConstraint("receipt_sha256 ~ '^[0-9a-f]{64}$'", name="receipt_sha256"),
        CheckConstraint("jsonb_typeof(receipt) = 'object'", name="receipt_json"),
        Index("ix_recommendation_runs_release_sha256", "release_sha256"),
    )

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    preference_profile_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey(
            "app.preference_profiles.profile_id",
            name="fk_recommendation_runs_preference_profile",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    input_digest: Mapped[str] = mapped_column(Text, nullable=False)
    release_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_membership_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    config_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    kernel_version: Mapped[str] = mapped_column(Text, nullable=False)
    receipt_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    receipt: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RecommendationResultPinRow(Base):
    """Copy-once release snapshot pin used by every public read projection."""

    __tablename__ = "recommendation_result_pins"
    __table_args__ = (
        CheckConstraint("release_sha256 ~ '^[0-9a-f]{64}$'", name="release_sha256"),
        CheckConstraint(
            "canonical_membership_sha256 ~ '^[0-9a-f]{64}$'",
            name="membership_sha256",
        ),
        CheckConstraint("config_sha256 ~ '^[0-9a-f]{64}$'", name="config_sha256"),
        CheckConstraint("receipt_sha256 ~ '^[0-9a-f]{64}$'", name="receipt_sha256"),
        CheckConstraint("snapshot_sha256 ~ '^[0-9a-f]{64}$'", name="snapshot_sha256"),
        CheckConstraint("jsonb_typeof(release_snapshot) = 'object'", name="release_snapshot_json"),
        Index("ix_recommendation_result_pins_release_sha256", "release_sha256"),
    )

    run_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey(
            "app.recommendation_runs.run_id",
            name="fk_recommendation_result_pins_run",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )
    release_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    canonical_membership_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    config_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    kernel_version: Mapped[str] = mapped_column(Text, nullable=False)
    receipt_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    release_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RecommendationRequestBindingRow(Base):
    """Immutable request alias for one deterministic recommendation run."""

    __tablename__ = "recommendation_request_bindings"
    __table_args__ = (
        CheckConstraint("char_length(request_id) BETWEEN 1 AND 160", name="request_id"),
        CheckConstraint(
            "char_length(preference_profile_id) BETWEEN 1 AND 160",
            name="preference_profile_id",
        ),
        CheckConstraint("input_digest ~ '^[0-9a-f]{64}$'", name="input_digest"),
        ForeignKeyConstraint(
            ["run_id", "preference_profile_id", "input_digest"],
            [
                "app.recommendation_runs.run_id",
                "app.recommendation_runs.preference_profile_id",
                "app.recommendation_runs.input_digest",
            ],
            name="fk_request_binding_run_metadata",
            ondelete="RESTRICT",
        ),
    )

    request_id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    preference_profile_id: Mapped[str] = mapped_column(Text, nullable=False)
    input_digest: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ManifestSealRow(Base):
    """Alembic metadata for sealed evaluation manifests; no runtime repository maps it."""

    __tablename__ = "manifest_seals"
    __table_args__ = (
        CheckConstraint(
            "canonicalization_version = 'canonical-json-v1'",
            name="manifest_seals_canonicalization",
        ),
        CheckConstraint(
            "manifest_sha256 ~ '^[0-9a-f]{64}$'",
            name="manifest_seals_sha256",
        ),
        {"schema": "blind_eval"},
    )

    manifest_version: Mapped[str] = mapped_column(Text, primary_key=True)
    canonicalization_version: Mapped[str] = mapped_column(Text)
    manifest_sha256: Mapped[str] = mapped_column(Text)
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DevManifestMemberRow(Base):
    """Alembic metadata for DEV membership, intentionally without repository access."""

    __tablename__ = "manifest_members"
    __table_args__ = (
        CheckConstraint("member_ordinal BETWEEN 1 AND 24", name="dev_member_ordinal"),
        CheckConstraint("split = 'DEV'", name="dev_member_split"),
        CheckConstraint(
            "synthetic_place_id ~ '^synthetic:dev:'",
            name="dev_member_synthetic_id",
        ),
        UniqueConstraint(
            "manifest_version",
            "synthetic_place_id",
            name="uq_dev_manifest_member_id",
        ),
        {"schema": "dev_eval"},
    )

    manifest_version: Mapped[str] = mapped_column(
        Text,
        ForeignKey(
            "blind_eval.manifest_seals.manifest_version",
            name="fk_dev_member_seal",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )
    member_ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    synthetic_place_id: Mapped[str] = mapped_column(Text)
    split: Mapped[str] = mapped_column(Text)


class BlindManifestMemberRow(Base):
    """Alembic metadata for BLIND membership, intentionally without repository access."""

    __tablename__ = "manifest_members"
    __table_args__ = (
        CheckConstraint("member_ordinal BETWEEN 25 AND 36", name="blind_member_ordinal"),
        CheckConstraint("split = 'BLIND'", name="blind_member_split"),
        CheckConstraint(
            "synthetic_place_id ~ '^synthetic:blind:'",
            name="blind_member_synthetic_id",
        ),
        UniqueConstraint(
            "manifest_version",
            "synthetic_place_id",
            name="uq_blind_manifest_member_id",
        ),
        {"schema": "blind_eval"},
    )

    manifest_version: Mapped[str] = mapped_column(
        Text,
        ForeignKey(
            "blind_eval.manifest_seals.manifest_version",
            name="fk_blind_member_seal",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )
    member_ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    synthetic_place_id: Mapped[str] = mapped_column(Text)
    split: Mapped[str] = mapped_column(Text)


class RealManifestSealRow(Base):
    """Insert-only D-20 seal metadata; membership remains in restricted schemas."""

    __tablename__ = "real_manifest_seals"
    __table_args__ = (
        CheckConstraint("dev_count = 24", name="real_manifest_dev_count"),
        CheckConstraint("blind_count = 12", name="real_manifest_blind_count"),
        CheckConstraint("member_count = 36", name="real_manifest_member_count"),
        CheckConstraint(
            "canonicalization_version = 'canonical-json-v1'",
            name="real_manifest_canonicalization",
        ),
        {"schema": "blind_eval"},
    )

    manifest_version: Mapped[str] = mapped_column(Text, primary_key=True)
    catalog_revision_sha256: Mapped[str] = mapped_column(Text)
    catalog_approval_sha256: Mapped[str] = mapped_column(Text)
    split_approval_sha256: Mapped[str] = mapped_column(Text)
    split_manifest_sha256: Mapped[str] = mapped_column(Text)
    membership_sha256: Mapped[str] = mapped_column(Text)
    canonicalization_version: Mapped[str] = mapped_column(Text)
    dev_count: Mapped[int] = mapped_column(Integer)
    blind_count: Mapped[int] = mapped_column(Integer)
    member_count: Mapped[int] = mapped_column(Integer)
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RealDevManifestMemberRow(Base):
    __tablename__ = "real_manifest_members"
    __table_args__ = (
        CheckConstraint("member_ordinal BETWEEN 1 AND 24", name="dev_eval_real_member_ordinal"),
        CheckConstraint("split = 'DEV'", name="dev_eval_real_split"),
        UniqueConstraint(
            "manifest_version", "canonical_place_id", name="uq_dev_eval_real_manifest_place"
        ),
        {"schema": "dev_eval"},
    )

    manifest_version: Mapped[str] = mapped_column(
        Text,
        ForeignKey(
            "blind_eval.real_manifest_seals.manifest_version",
            name="fk_dev_eval_real_manifest_seal",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )
    member_ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    canonical_place_id: Mapped[str] = mapped_column(Text)
    split: Mapped[str] = mapped_column(Text)


class RealBlindManifestMemberRow(Base):
    __tablename__ = "real_manifest_members"
    __table_args__ = (
        CheckConstraint("member_ordinal BETWEEN 25 AND 36", name="blind_eval_real_member_ordinal"),
        CheckConstraint("split = 'BLIND'", name="blind_eval_real_split"),
        UniqueConstraint(
            "manifest_version",
            "canonical_place_id",
            name="uq_blind_eval_real_manifest_place",
        ),
        {"schema": "blind_eval"},
    )

    manifest_version: Mapped[str] = mapped_column(
        Text,
        ForeignKey(
            "blind_eval.real_manifest_seals.manifest_version",
            name="fk_blind_eval_real_manifest_seal",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )
    member_ordinal: Mapped[int] = mapped_column(Integer, primary_key=True)
    canonical_place_id: Mapped[str] = mapped_column(Text)
    split: Mapped[str] = mapped_column(Text)
