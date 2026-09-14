"""Source companions must agree with sealed receipts, even with valid own hashes.

SQLite supplies a real source repository without external I/O. PostgreSQL foreign
keys and transactional migration guards remain covered by the integration tracer.
"""

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, update

from itda.contracts.grounded_recommendation import (
    GroundedInputAuthority,
    GroundedRunBinding,
    GroundedTripInput,
)
from itda.contracts.recommendation import (
    QUALITY_RECOMMENDATION_CONFIG,
    PublicRelationAuthority,
    RecommendationQualityContext,
)
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    RecommendationRunRepository,
    _pin_row,
    _run_row,
    _validate_grounding_authority,
    _validate_pinned_rows,
)
from itda.db.session import create_session_factory
from itda.db.source_snapshot_repositories import (
    ASSESSMENT_SNAPSHOTS,
    RUN_BINDINGS,
    SOURCE_SNAPSHOTS,
    SourceSnapshotRepository,
)
from itda.domain.canonical import canonical_sha256
from itda.domain.mvp_recommendation import create_mvp_recommendation_run
from itda.domain.recommendation_projection import project_recommendation_preference
from tests.unit.test_mvp_recommendation_repository import _run
from tests.unit.test_mvp_recommendation_service import CREATED_AT, _preference


@pytest.fixture
def sources():
    engine = create_engine("sqlite://", execution_options={"schema_translate_map": {"app": None}})
    for table in (SOURCE_SNAPSHOTS, ASSESSMENT_SNAPSHOTS, RUN_BINDINGS):
        table.create(engine)
    factory = create_session_factory(engine)
    yield SourceSnapshotRepository(factory), factory
    engine.dispose()


def _rehash(binding: GroundedRunBinding, **changes: object) -> GroundedRunBinding:
    payload = binding.model_dump(mode="json", exclude={"binding_sha256"})
    payload.update(changes)
    return GroundedRunBinding.model_validate(
        {**payload, "binding_sha256": canonical_sha256(payload)}
    )


def _grounded(source_digest: str, *, source_release: str | None = None):
    snapshot, _ = _run()
    profile = _preference()
    trip = GroundedTripInput(required_facilities=("accessible_toilet",))
    release_digest = source_release or canonical_sha256(
        {
            "policy_version": "facility-requirements-v1",
            "raw_release_sha256": snapshot.release_sha256,
            "source_snapshot_sha256": (source_digest,),
        }
    )
    authority = GroundedInputAuthority(
        trip_input_sha256=trip.input_sha256,
        source_release_sha256=release_digest,
        source_snapshot_sha256=(source_digest,),
    )
    preference = project_recommendation_preference(
        profile,
        quality_context=RecommendationQualityContext(
            companion=profile.trip_conditions.companion.value,
            transport=profile.trip_conditions.transport.value,
            purpose="MIXED",
            eligible_place_ids=tuple(row.place_id for row in snapshot.profiles),
            grounding=authority,
        ),
    )
    run = create_mvp_recommendation_run(
        snapshot.profiles,
        release_sha256=snapshot.release_sha256,
        membership_sha256=snapshot.membership_sha256,
        relation_authority=PublicRelationAuthority(
            relation_sha256=snapshot.relation_sha256,
            place_ids=tuple(row.place_id for row in snapshot.profiles),
            pairs=snapshot.relation_pairs,
        ),
        preference=preference,
        config=QUALITY_RECOMMENDATION_CONFIG,
        created_at=CREATED_AT,
    )
    payload = {
        "schema_version": "grounded-run-binding.v1",
        "run_id": run.run_id,
        "request_id": "request:grounded-authority",
        "preference_profile_id": profile.profile_id,
        "preference_input_sha256": "a" * 64,
        "trip_input": trip.model_dump(mode="json"),
        "trip_input_sha256": trip.input_sha256,
        "raw_release_sha256": snapshot.release_sha256,
        "source_release_sha256": release_digest,
        "assessment_bundle_sha256": [],
        "source_snapshot_sha256": [source_digest],
        "created_at": CREATED_AT.isoformat().replace("+00:00", "Z"),
    }
    binding = GroundedRunBinding.model_validate(
        {**payload, "binding_sha256": canonical_sha256(payload)}
    )
    return snapshot, run, binding


def _rows(snapshot, run, binding):
    return (
        _run_row(
            request_id=binding.request_id,
            preference_profile_id=binding.preference_profile_id,
            run=run,
        ),
        _pin_row(run=run, release_snapshot=snapshot),
    )


def test_valid_grounding_and_request_alias_preserve_sealed_authority(sources) -> None:
    repository, factory = sources
    digest = repository.put_source({"fixture": "official-shape source"})
    snapshot, run, binding = _grounded(digest)
    alias = _rehash(
        binding,
        request_id="request:second-alias",
        created_at=(CREATED_AT + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
    )
    repository.bind_run(binding)
    repository.bind_run(alias)
    _validate_grounding_authority(run, alias, binding.preference_profile_id)
    with factory() as session:
        restored = _validate_pinned_rows(*_rows(snapshot, run, binding), session=session)
    assert restored.run.model_dump_json() == run.model_dump_json()


@pytest.mark.parametrize(
    "changes",
    [
        {"run_id": "run:other"},
        {"preference_profile_id": "profile:other"},
        {"raw_release_sha256": "c" * 64},
        {"source_release_sha256": "d" * 64},
        {"source_snapshot_sha256": ["e" * 64]},
        {"assessment_bundle_sha256": ["f" * 64]},
    ],
)
def test_valid_hash_does_not_authorize_foreign_companion_fields(changes) -> None:
    _, run, binding = _grounded("b" * 64)
    altered = _rehash(binding, **changes)
    with pytest.raises(RecommendationPinInvalid, match="authority differ"):
        _validate_grounding_authority(run, altered, binding.preference_profile_id)


def test_valid_hash_for_changed_trip_input_cannot_rebind_existing_run() -> None:
    _, run, binding = _grounded("b" * 64)
    trip = GroundedTripInput(required_facilities=("wheelchair_rental",))
    altered = _rehash(
        binding, trip_input=trip.model_dump(mode="json"), trip_input_sha256=trip.input_sha256
    )
    with pytest.raises(RecommendationPinInvalid, match="authority differ"):
        _validate_grounding_authority(run, altered, binding.preference_profile_id)


def test_matching_forged_release_digests_still_require_the_declared_recipe() -> None:
    _, run, binding = _grounded("b" * 64, source_release="f" * 64)
    with pytest.raises(RecommendationPinInvalid, match="source release digest"):
        _validate_grounding_authority(run, binding, binding.preference_profile_id)


def test_grounded_run_cannot_be_read_without_source_aware_repository() -> None:
    snapshot, run, binding = _grounded("b" * 64)
    with pytest.raises(RecommendationPinInvalid, match="source-aware"):
        _validate_pinned_rows(*_rows(snapshot, run, binding))


def test_grounded_pin_read_rejects_missing_companion(sources) -> None:
    _, factory = sources
    snapshot, run, binding = _grounded("b" * 64)
    with factory() as session, pytest.raises(RecommendationPinInvalid, match="no source binding"):
        _validate_pinned_rows(*_rows(snapshot, run, binding), session=session)


@pytest.mark.parametrize("damage", ["missing_source", "tampered_source", "foreign_companion"])
def test_grounded_pin_read_rejects_invalid_source_authority(sources, damage: str) -> None:
    repository, factory = sources
    digest = repository.put_source({"fixture": "source before damage"})
    snapshot, run, binding = _grounded(digest)
    if damage == "foreign_companion":
        repository.bind_run(_rehash(binding, source_release_sha256="d" * 64))
    else:
        repository.bind_run(binding)
        # SQLite intentionally permits simulated disk/admin damage; production
        # migration guards reject ordinary mutation before this read validator.
        with factory.begin() as session:
            if damage == "missing_source":
                session.execute(SOURCE_SNAPSHOTS.delete())
            else:
                session.execute(update(SOURCE_SNAPSHOTS).values(payload={"fixture": "altered"}))
    with factory() as session, pytest.raises(RecommendationPinInvalid, match="source pin"):
        _validate_pinned_rows(*_rows(snapshot, run, binding), session=session)


def test_real_insert_recovery_rejects_authority_added_to_historical_run(
    sources, monkeypatch
) -> None:
    source_repository, factory = sources
    digest = source_repository.put_source({"fixture": "unrelated source"})
    snapshot, historical = _run()
    _, _, binding = _grounded(digest)
    foreign = _rehash(
        binding,
        run_id=historical.run_id,
        preference_profile_id=historical.preference.profile_id,
        raw_release_sha256=snapshot.release_sha256,
    )
    repository = RecommendationRunRepository(factory)
    # Only the existing main-run lookup is stubbed. The actual insert/recovery
    # transaction and real source repository reproduce the original R-04 path.
    monkeypatch.setattr(repository, "_reconcile_request_binding", lambda *a, **kw: historical)
    with pytest.raises(RecommendationPinInvalid, match="ungrounded run"):
        repository.insert_or_recover(
            request_id=foreign.request_id,
            preference_profile_id=historical.preference.profile_id,
            run=historical,
            release_snapshot=snapshot,
            grounded_binding=foreign,
        )
    assert source_repository.get_request_binding(foreign.request_id) is None
    _validate_grounding_authority(historical, None, historical.preference.profile_id)


def test_real_insert_recovery_requires_companion_for_grounded_run(sources, monkeypatch) -> None:
    source_repository, factory = sources
    digest = source_repository.put_source({"fixture": "source"})
    snapshot, run, binding = _grounded(digest)
    repository = RecommendationRunRepository(factory)
    monkeypatch.setattr(repository, "_reconcile_request_binding", lambda *a, **kw: run)
    with pytest.raises(RecommendationPinInvalid, match="atomic source binding"):
        repository.insert_or_recover(
            request_id=binding.request_id,
            preference_profile_id=binding.preference_profile_id,
            run=run,
            release_snapshot=snapshot,
        )
    assert source_repository.get_request_binding(binding.request_id) is None
