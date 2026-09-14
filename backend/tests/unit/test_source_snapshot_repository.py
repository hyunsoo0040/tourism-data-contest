from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, update

from itda.contracts.grounded_recommendation import GroundedRunBinding, GroundedTripInput
from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS
from itda.contracts.source_assessment import (
    AssessmentBundle,
    ClaimKind,
    SourceObservation,
    SupportState,
)
from itda.db.session import create_session_factory
from itda.db.source_snapshot_repositories import (
    ASSESSMENT_SNAPSHOTS,
    RUN_BINDINGS,
    SOURCE_SNAPSHOTS,
    SourceSnapshotConflict,
    SourceSnapshotInvalid,
    SourceSnapshotRepository,
)
from itda.domain.canonical import canonical_sha256

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def bundle(source_release: str = "b" * 64) -> AssessmentBundle:
    dimensions = {
        key: SourceObservation(
            key=key,
            claim=ClaimKind.CROWD if key == "M3" else ClaimKind.EXPERIENCE,
            state=SupportState.UNKNOWN,
            value=None,
            evidence=(),
            reference_date=None,
            reason="미확인",
        )
        for key in SCORING_DIMENSIONS
    }
    row = AssessmentBundle.model_construct(
        place_id="place:one",
        raw_profile_sha256="a" * 64,
        source_release_sha256=source_release,
        assessed_at=NOW,
        dimensions=dimensions,
        facts={},
        bundle_sha256="0" * 64,
    )
    payload = row.model_dump(mode="json", exclude={"bundle_sha256"})
    return AssessmentBundle.model_validate({**payload, "bundle_sha256": canonical_sha256(payload)})


def binding(source: str, assessment: str | None = None, **changes: object) -> GroundedRunBinding:
    trip = GroundedTripInput()
    row = GroundedRunBinding.model_construct(
        run_id="run:one",
        request_id="request:one",
        preference_profile_id="profile:one",
        preference_input_sha256="a" * 64,
        trip_input=trip,
        trip_input_sha256=trip.input_sha256,
        raw_release_sha256="c" * 64,
        source_release_sha256="b" * 64,
        assessment_bundle_sha256=(assessment,) if assessment else (),
        source_snapshot_sha256=(source,),
        created_at=NOW,
        binding_sha256="0" * 64,
    )
    payload = row.model_dump(mode="json", exclude={"binding_sha256"})
    payload.update(changes)
    return GroundedRunBinding.model_validate(
        {**payload, "binding_sha256": canonical_sha256(payload)}
    )


@pytest.fixture
def repository() -> SourceSnapshotRepository:
    engine = create_engine("sqlite://", execution_options={"schema_translate_map": {"app": None}})
    for table in (SOURCE_SNAPSHOTS, ASSESSMENT_SNAPSHOTS, RUN_BINDINGS):
        table.create(engine)
    return SourceSnapshotRepository(create_session_factory(engine))


def test_immutable_snapshot_roundtrip_and_defensive_copy(
    repository: SourceSnapshotRepository,
) -> None:
    payload = {"place_id": "place:one", "raw": {"value": 4}}
    digest = repository.put_source(payload)
    assert digest == canonical_sha256(payload)
    assert repository.put_source(payload) == digest
    loaded = repository.get_source(digest)
    assert loaded == payload
    loaded["raw"] = "mutated"
    assert repository.get_source(digest) == payload
    assessed = bundle()
    assert repository.put_assessment(assessed) == assessed.bundle_sha256
    assert repository.get_assessment(assessed.bundle_sha256) == assessed


def test_hash_tampering_is_rejected_on_read(repository: SourceSnapshotRepository) -> None:
    digest = repository.put_source({"value": 1})
    # SQLite has no migration guards; simulate disk/admin corruption explicitly.
    with repository._sessions.begin() as session:
        session.execute(update(SOURCE_SNAPSHOTS).values(payload={"value": 2}))
    with pytest.raises(SourceSnapshotInvalid, match="hash"):
        repository.get_source(digest)


def test_binding_requires_all_snapshots_and_matching_source_release(
    repository: SourceSnapshotRepository,
) -> None:
    with pytest.raises(SourceSnapshotInvalid, match="missing source"):
        repository.bind_run(binding("d" * 64))
    digest = repository.put_source({"value": 1})
    foreign = repository.put_assessment(bundle("e" * 64))
    with pytest.raises(SourceSnapshotInvalid, match="source release"):
        repository.bind_run(binding(digest, foreign))


def test_request_aliases_share_exact_run_context_and_reject_changed_owner(
    repository: SourceSnapshotRepository,
) -> None:
    digest = repository.put_source({"value": 1})
    assessed = repository.put_assessment(bundle())
    first = binding(digest, assessed)
    repository.bind_run(first)
    assert repository.bind_run(first) == first
    alias = binding(digest, assessed, request_id="request:two")
    repository.bind_run(alias)
    assert repository.get_run_binding(first.run_id) == first
    assert repository.get_request_binding(alias.request_id) == alias
    for changes in (
        {"preference_profile_id": "profile:other"},
        {"source_release_sha256": "f" * 64},
    ):
        with pytest.raises((SourceSnapshotConflict, SourceSnapshotInvalid)):
            repository.bind_run(binding(digest, assessed, request_id="request:three", **changes))


def test_atomic_session_rollback_removes_new_source_and_binding(
    repository: SourceSnapshotRepository,
) -> None:
    with pytest.raises(RuntimeError, match="abort"), repository._sessions.begin() as session:
        digest = repository.put_source({"value": 1}, session=session)
        repository.bind_run_in_session(session, binding(digest))
        raise RuntimeError("abort")
    assert repository.get_source(digest) is None
    assert repository.get_run_binding("run:one") is None
