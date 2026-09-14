"""Source-grounding behavior with the real collector and a local repository."""

from datetime import timedelta

import pytest
from sqlalchemy import create_engine

from itda.application.source_grounding import SourceGroundingService
from itda.contracts.grounded_recommendation import GroundedTripInput, RequiredFacility
from itda.db.session import create_session_factory
from itda.db.source_snapshot_repositories import (
    ASSESSMENT_SNAPSHOTS,
    RUN_BINDINGS,
    SOURCE_SNAPSHOTS,
    SourceSnapshotRepository,
)
from tests.unit.test_accessibility_source import _discovery, _service
from tests.unit.test_source_snapshot_repository import NOW, binding


@pytest.fixture
def repository() -> SourceSnapshotRepository:
    engine = create_engine("sqlite://", execution_options={"schema_translate_map": {"app": None}})
    for table in (SOURCE_SNAPSHOTS, ASSESSMENT_SNAPSHOTS, RUN_BINDINGS):
        table.create(engine)
    return SourceSnapshotRepository(create_session_factory(engine))


def test_explicit_absence_excludes_but_missing_and_rental_do_not(
    repository: SourceSnapshotRepository,
) -> None:
    for text, excluded in (
        ("장애인 화장실 없음", True),
        ("", False),
        ("장애인 화장실 있음", False),
    ):
        accessibility, calls, _ = _service(
            [_discovery()],
            {"contentid": "126166", "restroom": text, "wheelchair": "휠체어 무료 대여 가능함"},
        )
        service = SourceGroundingService(accessibility=accessibility, store=repository)
        result = service.prepare(
            trip_input=GroundedTripInput(required_facilities=(RequiredFacility.ACCESSIBLE_TOILET,)),
            raw_release_sha256="a" * 64,
            place_ids=("place:bulguksa",),
        )
        assert ("place:bulguksa" in result.excluded_place_ids) is excluded
        assert len(result.authority.source_snapshot_sha256) == 1
        assert calls == ["searchKeyword2", "detailWithTour2"]
        # A wheelchair rental statement is not a step-free entrance claim.
        entry = service.prepare(
            trip_input=GroundedTripInput(required_facilities=(RequiredFacility.STEP_FREE_ENTRY,)),
            raw_release_sha256="a" * 64,
            place_ids=("place:bulguksa",),
        )
        assert not entry.excluded_place_ids
        assert len(calls) == 2


def test_no_facility_requirement_does_not_infer_one_or_fetch(
    repository: SourceSnapshotRepository,
) -> None:
    accessibility, calls, _ = _service([_discovery()])
    service = SourceGroundingService(accessibility=accessibility, store=repository)
    result = service.prepare(
        trip_input=GroundedTripInput(), raw_release_sha256="a" * 64, place_ids=("place:bulguksa",)
    )
    assert result.authority.source_snapshot_sha256 == ()
    assert not result.excluded_place_ids
    assert calls == []


def test_pinned_context_uses_stored_facts_after_cache_expiry(
    repository: SourceSnapshotRepository,
) -> None:
    accessibility, calls, now = _service([_discovery()])
    service = SourceGroundingService(accessibility=accessibility, store=repository)
    trip = GroundedTripInput(required_facilities=(RequiredFacility.ACCESSIBLE_TOILET,))
    prepared = service.prepare(
        trip_input=trip, raw_release_sha256="a" * 64, place_ids=("place:bulguksa",)
    )
    saved = binding(
        prepared.authority.source_snapshot_sha256[0],
        trip_input=trip.model_dump(mode="json"),
        trip_input_sha256=trip.input_sha256,
        source_release_sha256=prepared.authority.source_release_sha256,
    )
    before = service.context(
        run_id=saved.run_id,
        place_names={"place:bulguksa": "불국사"},
        trip_input=trip,
        checked_at=NOW,
        binding=saved,
    )
    now[0] += timedelta(days=10)
    after = service.context(
        run_id=saved.run_id,
        place_names={"place:bulguksa": "불국사"},
        trip_input=trip,
        checked_at=NOW,
        binding=saved,
    )
    assert after == before
    assert after.mode == "PINNED"
    assert len(calls) == 2


def test_partial_pinned_bundle_never_fetches_missing_place(
    repository: SourceSnapshotRepository,
) -> None:
    accessibility, calls, _ = _service([_discovery()])
    snapshot = accessibility.fetch("place:bulguksa")
    digest = repository.put_source(snapshot.model_dump(mode="json"))
    service = SourceGroundingService(accessibility=accessibility, store=repository)
    context = service.context(
        run_id="run:one",
        place_names={"place:bulguksa": "불국사", "place:missing": "미연결 장소"},
        trip_input=GroundedTripInput(),
        checked_at=NOW,
        binding=binding(digest),
    )
    assert context.places[1].state == "UNAVAILABLE"
    assert context.places[1].facts == ()
    assert len(calls) == 2


def test_missing_pinned_source_is_an_error_not_live_repair(
    repository: SourceSnapshotRepository,
) -> None:
    accessibility, calls, _ = _service([_discovery()])
    service = SourceGroundingService(accessibility=accessibility, store=repository)
    with pytest.raises(ValueError, match="missing or altered"):
        service.context(
            run_id="run:one",
            place_names={"place:bulguksa": "불국사"},
            trip_input=GroundedTripInput(),
            checked_at=NOW,
            binding=binding("f" * 64),
        )
    assert calls == []
