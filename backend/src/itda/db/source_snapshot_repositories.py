"""Immutable, content-addressed tourism sources and recommendation bindings."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal, cast

from sqlalchemy import JSON, Column, DateTime, MetaData, Table, Text, select, text
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.grounded_recommendation import GroundedRunBinding
from itda.contracts.source_assessment import AssessmentBundle
from itda.domain.canonical import canonical_json_bytes, canonical_sha256


class SourceSnapshotConflict(RuntimeError):
    """An immutable snapshot or run binding disagrees with stored content."""


class SourceSnapshotInvalid(RuntimeError):
    """Persisted snapshot content or ownership could not be verified."""


_metadata = MetaData(schema="app")
_json_type = JSON().with_variant(JSONB(), "postgresql")


def _snapshot_table(name: str) -> Table:
    return Table(
        name,
        _metadata,
        Column("snapshot_sha256", Text, primary_key=True),
        Column("payload", _json_type, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
    )


SOURCE_SNAPSHOTS = _snapshot_table("tourism_source_snapshots")
ASSESSMENT_SNAPSHOTS = _snapshot_table("place_assessment_snapshots")
RUN_BINDINGS = Table(
    "grounded_run_bindings",
    _metadata,
    Column("run_id", Text, nullable=False),
    Column("request_id", Text, primary_key=True),
    Column("preference_profile_id", Text, nullable=False),
    Column("binding_sha256", Text, nullable=False),
    Column("payload", _json_type, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


def _json_copy(value: Mapping[str, object]) -> dict[str, object]:
    return cast(dict[str, object], json.loads(canonical_json_bytes(dict(value))))


class SourceSnapshotRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    @staticmethod
    def _put(session: Session, table: Table, digest: str, payload: dict[str, object]) -> str:
        session.execute(
            insert(table)
            .values(snapshot_sha256=digest, payload=payload, created_at=datetime.now(UTC))
            .on_conflict_do_nothing(index_elements=["snapshot_sha256"])
        )
        stored = session.execute(
            select(table.c.payload).where(table.c.snapshot_sha256 == digest)
        ).scalar_one()
        if canonical_sha256(stored) != canonical_sha256(payload):
            raise SourceSnapshotConflict("snapshot hash already has different content")
        return digest

    def put_source(self, payload: Mapping[str, object], *, session: Session | None = None) -> str:
        value = _json_copy(payload)
        digest = canonical_sha256(value)
        if session is not None:
            return self._put(session, SOURCE_SNAPSHOTS, digest, value)
        with self._sessions.begin() as owned:
            return self._put(owned, SOURCE_SNAPSHOTS, digest, value)

    def put_assessment(self, bundle: AssessmentBundle, *, session: Session | None = None) -> str:
        validated = AssessmentBundle.model_validate_json(bundle.model_dump_json())
        value = validated.model_dump(mode="json")
        if session is not None:
            return self._put(session, ASSESSMENT_SNAPSHOTS, validated.bundle_sha256, value)
        with self._sessions.begin() as owned:
            return self._put(owned, ASSESSMENT_SNAPSHOTS, validated.bundle_sha256, value)

    @staticmethod
    def _get(
        session: Session, kind: Literal["source", "assessment"], digest: str
    ) -> dict[str, object] | None:
        table = SOURCE_SNAPSHOTS if kind == "source" else ASSESSMENT_SNAPSHOTS
        payload = session.execute(
            select(table.c.payload).where(table.c.snapshot_sha256 == digest)
        ).scalar_one_or_none()
        if payload is None:
            return None
        value = _json_copy(payload)
        if kind == "source":
            valid = canonical_sha256(value) == digest
        else:
            try:
                valid = AssessmentBundle.model_validate(value).bundle_sha256 == digest
            except ValueError as error:
                raise SourceSnapshotInvalid("invalid assessment snapshot") from error
        if not valid:
            raise SourceSnapshotInvalid("snapshot content hash mismatch")
        return value

    def get_source(self, digest: str) -> dict[str, object] | None:
        with self._sessions() as session:
            return self._get(session, "source", digest)

    def get_assessment(self, digest: str) -> AssessmentBundle | None:
        with self._sessions() as session:
            value = self._get(session, "assessment", digest)
            return AssessmentBundle.model_validate(value) if value is not None else None

    @classmethod
    def _validate_members(cls, session: Session, binding: GroundedRunBinding) -> None:
        for digest in binding.source_snapshot_sha256:
            if cls._get(session, "source", digest) is None:
                raise SourceSnapshotInvalid("run references a missing source snapshot")
        for digest in binding.assessment_bundle_sha256:
            payload = cls._get(session, "assessment", digest)
            if payload is None:
                raise SourceSnapshotInvalid("run references a missing assessment snapshot")
            bundle = AssessmentBundle.model_validate(payload)
            if bundle.source_release_sha256 != binding.source_release_sha256:
                raise SourceSnapshotInvalid("assessment source release differs from run binding")

    def bind_run_in_session(
        self, session: Session, binding: GroundedRunBinding
    ) -> GroundedRunBinding:
        """Join the caller's run insertion transaction; never commits independently."""
        validated = GroundedRunBinding.model_validate_json(binding.model_dump_json())
        self._validate_members(session, validated)
        payload = validated.model_dump(mode="json")
        if session.get_bind().dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                {"key": "grounded-run|" + validated.run_id},
            )
        existing = (
            session.execute(
                select(RUN_BINDINGS.c.payload).where(RUN_BINDINGS.c.run_id == validated.run_id)
            )
            .scalars()
            .all()
        )
        for previous in existing:
            if self._run_identity(previous) != self._run_identity(payload):
                raise SourceSnapshotConflict(
                    "same run cannot bind a different trip or source context"
                )
        session.execute(
            insert(RUN_BINDINGS)
            .values(
                run_id=validated.run_id,
                request_id=validated.request_id,
                preference_profile_id=validated.preference_profile_id,
                binding_sha256=validated.binding_sha256,
                payload=payload,
                created_at=validated.created_at,
            )
            .on_conflict_do_nothing()
        )
        stored = session.execute(
            select(RUN_BINDINGS.c.payload).where(RUN_BINDINGS.c.request_id == validated.request_id)
        ).scalar_one_or_none()
        if stored is None or self._run_identity(stored) != self._run_identity(payload):
            raise SourceSnapshotConflict(
                "recommendation source binding already exists with different content"
            )
        return GroundedRunBinding.model_validate(stored)

    @staticmethod
    def _run_identity(payload: Mapping[str, object]) -> str:
        return canonical_sha256(
            {
                key: value
                for key, value in payload.items()
                if key not in {"request_id", "created_at", "binding_sha256"}
            }
        )

    def bind_run(self, binding: GroundedRunBinding) -> GroundedRunBinding:
        with self._sessions.begin() as session:
            return self.bind_run_in_session(session, binding)

    def _binding(
        self, *, run_id: str | None = None, request_id: str | None = None
    ) -> GroundedRunBinding | None:
        query = (
            select(RUN_BINDINGS).where(RUN_BINDINGS.c.run_id == run_id)
            if run_id is not None
            else select(RUN_BINDINGS).where(RUN_BINDINGS.c.request_id == request_id)
        )
        with self._sessions() as session:
            rows = (
                session.execute(
                    query.order_by(RUN_BINDINGS.c.created_at, RUN_BINDINGS.c.request_id)
                )
                .mappings()
                .all()
            )
            if not rows:
                return None
            row = rows[0]
            if any(
                self._run_identity(other["payload"]) != self._run_identity(row["payload"])
                for other in rows
            ):
                raise SourceSnapshotInvalid("run aliases disagree on pinned source content")
            try:
                binding = GroundedRunBinding.model_validate(row["payload"])
            except ValueError as error:
                raise SourceSnapshotInvalid("stored run source binding is invalid") from error
            if any(
                row[key] != getattr(binding, key)
                for key in ("run_id", "request_id", "preference_profile_id", "binding_sha256")
            ):
                raise SourceSnapshotInvalid("stored run binding metadata mismatch")
            self._validate_members(session, binding)
            return binding

    def get_run_binding(self, run_id: str) -> GroundedRunBinding | None:
        return self._binding(run_id=run_id)

    def get_request_binding(self, request_id: str) -> GroundedRunBinding | None:
        return self._binding(request_id=request_id)
