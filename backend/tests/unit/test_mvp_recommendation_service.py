from __future__ import annotations

from datetime import UTC, datetime

from itda.application.recommendations import RecommendationService
from itda.contracts.preference import QuestionnaireSubmission
from itda.contracts.recommendation import (
    MvpRecommendationRun,
    PhotoMvpRecommendationRun,
    RecommendationRequest,
)
from itda.db.photo_repositories import (
    PhotoJobNotFound,
    PhotoRecommendationProjectionRecord,
    ProjectionTraitRow,
)
from itda.domain.preference import calculate_preference
from tests.contract.test_mvp_scored_release import release

CREATED_AT = datetime(2026, 8, 25, tzinfo=UTC)


class ProfileRepositoryStub:
    def __init__(self, profile: object) -> None:
        self.profile = profile

    def get(self, profile_id: str):
        return self.profile if profile_id == self.profile.profile_id else None


class PhotoProjectionReaderStub:
    def __init__(self, *, rejected: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.rejected = rejected

    def read(self, job_id: str, profile_id: str) -> PhotoRecommendationProjectionRecord:
        self.calls.append((job_id, profile_id))
        if self.rejected:
            raise PhotoJobNotFound(job_id)
        return PhotoRecommendationProjectionRecord(
            draft_digest="d" * 64,
            included_count=2,
            images_count=1,
            traits=(
                ProjectionTraitRow(trait_id="M1", text_ko="고요한", value=80, included=True),
                ProjectionTraitRow(trait_id="M5", text_ko="산책", value=70, included=True),
            ),
        )


class RunRepositoryStub:
    def __init__(self) -> None:
        self.run = None
        self.snapshot = None

    def recover_bound_request(self, **kwargs):
        return self.run

    def recover_by_request_id(self, **kwargs):
        return None

    def insert_or_recover(self, *, run, release_snapshot, **kwargs):
        self.run = run
        self.snapshot = release_snapshot
        return run, False

    def load_run(self, run_id: str):
        if self.run is None or self.run.run_id != run_id:
            raise AssertionError("unexpected run lookup")
        return self.run


def _preference():
    return calculate_preference(
        QuestionnaireSubmission.model_validate(
            {
                "request_id": "anonymous:mvp-service",
                "trip_conditions": {
                    "visit_date": "2026-10-09",
                    "visit_time": "EVENING",
                    "companion": "FAMILY_WITH_CHILDREN",
                    "transport": "CAR_OR_TAXI",
                    "walking_tolerance": "EXTENDED_WALKING_OK",
                    "indoor_outdoor_preference": "OUTDOOR",
                    "crowd_avoidance": "HIGH",
                },
                "answers": {f"q{index}": 3 for index in range(1, 13)},
            }
        ),
        created_at=CREATED_AT,
    )


def test_bound_v2_recovery_validates_preference_without_active_release() -> None:
    from itda.db.recommendation_repositories import RecommendationRequestConflict

    profile = _preference()
    snapshot = release(80)
    runs = RunRepositoryStub()
    events = []
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: snapshot,
        clock=lambda: CREATED_AT,
        event_sink=events.append,
    )
    request = RecommendationRequest(
        request_id="request:mvp-recover", preference_profile_id=profile.profile_id
    )
    created = service.create_run(request)
    service._release_resolver = lambda: (_ for _ in ()).throw(AssertionError("resolver called"))
    assert service.create_run(request) == created
    changed = profile.model_copy(
        update={"answers": profile.answers.model_copy(update={"q1": 1})}
    )
    service._profile_repository = ProfileRepositoryStub(changed)
    try:
        service.create_run(request)
    except RecommendationRequestConflict:
        pass
    else:
        raise AssertionError("changed preference recovered old run")


def test_bound_v1_recovery_validates_preference_without_active_release() -> None:
    from itda.application.recommendations import _recommendation_preference
    from itda.db.recommendation_repositories import RecommendationRequestConflict
    from tests.unit.test_recommendation_kernel import _rank

    profile = _preference()
    runs = RunRepositoryStub()
    runs.run = _rank(preference=_recommendation_preference(profile).model_dump(mode="json"))
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: (_ for _ in ()).throw(AssertionError("resolver called")),
        clock=lambda: CREATED_AT,
        event_sink=lambda event: None,
    )
    request = RecommendationRequest(
        request_id="request:v1-recover", preference_profile_id=profile.profile_id
    )
    assert service.create_run(request) == runs.run

    changed = profile.model_copy(
        update={"answers": profile.answers.model_copy(update={"q1": 1})}
    )
    service._profile_repository = ProfileRepositoryStub(changed)
    try:
        service.create_run(request)
    except RecommendationRequestConflict:
        pass
    else:
        raise AssertionError("changed preference recovered old v1 run")


def test_service_creates_v2_from_80_member_release_with_audit_only_candidates() -> None:
    profile = _preference()
    snapshot = release(80)
    runs = RunRepositoryStub()
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: snapshot,
        clock=lambda: CREATED_AT,
        event_sink=lambda event: None,
    )
    run = service.create_run(
        RecommendationRequest(
            request_id="request:mvp-service",
            preference_profile_id=profile.profile_id,
        )
    )
    assert isinstance(run, MvpRecommendationRun)
    assert len(run.candidate_place_ids) == 80
    assert len(run.items) == 5
    assert all(item.image_state == "ABSENT" for item in run.items)
    assert runs.snapshot == snapshot
    assert snapshot.profiles[0].scores.confidence == 0
    assert snapshot.profiles[0].recommendation_eligible is True


def test_photo_request_reads_owned_projection_and_creates_v3() -> None:
    profile = _preference()
    snapshot = release(80)
    runs = RunRepositoryStub()
    reader = PhotoProjectionReaderStub()
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: snapshot,
        photo_projection_reader=reader,
        clock=lambda: CREATED_AT,
        event_sink=lambda event: None,
    )
    job_id = "a" * 64
    run = service.create_run(
        RecommendationRequest(
            request_id="request:photo-service",
            preference_profile_id=profile.profile_id,
            photo_job_id=job_id,
        )
    )

    assert isinstance(run, PhotoMvpRecommendationRun)
    assert reader.calls == [(job_id, profile.profile_id)]
    assert run.authority.images_count == 1
    assert run.authority.included_count == 2
    assert run.authority.photo_job_reference_sha256 != job_id
    assert "고요한" not in str(run.model_dump(mode="json"))


def test_no_photo_request_never_reads_photo_projection() -> None:
    profile = _preference()
    snapshot = release(80)
    runs = RunRepositoryStub()
    reader = PhotoProjectionReaderStub()
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: snapshot,
        photo_projection_reader=reader,
        clock=lambda: CREATED_AT,
        event_sink=lambda event: None,
    )
    run = service.create_run(
        RecommendationRequest(
            request_id="request:no-photo-service",
            preference_profile_id=profile.profile_id,
        )
    )

    assert isinstance(run, MvpRecommendationRun)
    assert reader.calls == []


def test_operating_information_is_run_scoped_and_disabled_by_default() -> None:
    from itda.db.recommendation_repositories import RecommendationPlaceUnavailable

    profile = _preference()
    runs = RunRepositoryStub()
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: release(80),
        clock=lambda: CREATED_AT,
        event_sink=lambda event: None,
    )
    run = service.create_run(
        RecommendationRequest(
            request_id="request:operating-service",
            preference_profile_id=profile.profile_id,
        )
    )
    place_ids = tuple(item.place_id for item in run.items[:2])

    response = service.get_operating_information(run.run_id, place_ids)

    assert tuple(row.place_id for row in response.places) == place_ids
    assert all(row.unavailable_reason == "ENRICHMENT_DISABLED" for row in response.places)

    for invalid_ids in ((place_ids[0], place_ids[0]), ("public:gyeongju:outside",)):
        try:
            service.get_operating_information(run.run_id, invalid_ids)
        except RecommendationPlaceUnavailable:
            pass
        else:
            raise AssertionError("invalid operating-information scope was accepted")


def test_foreign_or_unconfirmed_photo_projection_fails_closed() -> None:
    from itda.application.recommendations import PhotoRecommendationUnavailable

    profile = _preference()
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=RunRepositoryStub(),
        release_resolver=lambda: release(80),
        photo_projection_reader=PhotoProjectionReaderStub(rejected=True),
        clock=lambda: CREATED_AT,
        event_sink=lambda event: None,
    )
    try:
        service.create_run(
            RecommendationRequest(
                request_id="request:photo-rejected",
                preference_profile_id=profile.profile_id,
                photo_job_id="b" * 64,
            )
        )
    except PhotoRecommendationUnavailable:
        pass
    else:
        raise AssertionError("rejected photo projection did not fail closed")
