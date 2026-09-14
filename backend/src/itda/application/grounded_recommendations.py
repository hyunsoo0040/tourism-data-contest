"""Version-dispatching application facade for staged/active grounded recommendations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

from itda.application.grounded_context import (
    build_candidates,
    build_grounded_preference,
    preference_submission_sha256,
)
from itda.application.recommendations import (
    InsufficientEligibleCandidates,
    NoActiveScoredRelease,
    PhotoRecommendationUnavailable,
    PreferenceProfileUnavailable,
    RecommendationService,
)
from itda.contracts.grounded_recommendation import (
    RequiredFacility,
    TripContextPlace,
    TripContextResponse,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_responses import RecommendationRegion, RecommendationRegionsResponse
from itda.contracts.recommendation import (
    OperatingInformationResponse,
    PlaceOperatingInformation,
    RecommendationRequest,
    RecommendationRunCreated,
)
from itda.contracts.visual_mood import ConfirmedMoodProjection
from itda.db.grounded_run_repositories import GROUNDED_RUN_SCHEMA, GroundedRunRepository
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    RecommendationPlaceUnavailable,
    RecommendationRequestConflict,
)
from itda.db.repositories import ProfileRepository
from itda.db.source_snapshot_repositories import SourceSnapshotRepository
from itda.domain.grounded_recommendation import GroundedRecommendationError, rank_grounded
from itda.tourism.registry import ProductionTourismRegistry


class MoodProjectionReader(Protocol):
    def read_projection(self, *, job_id: str, profile_id: str) -> ConfirmedMoodProjection: ...


class GroundedRecommendationService:
    def __init__(
        self,
        *,
        legacy: RecommendationService,
        profiles: ProfileRepository,
        runs: GroundedRunRepository,
        sources: SourceSnapshotRepository,
        candidate_resolver: Callable[[], GroundedReleaseCandidate | None],
        registry: ProductionTourismRegistry,
        mood_reader: MoodProjectionReader | None = None,
        enabled: bool = True,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.legacy = legacy
        self.profiles = profiles
        self.runs = runs
        self.sources = sources
        self.candidate_resolver = candidate_resolver
        self.registry = registry
        self.mood_reader = mood_reader
        self.enabled = enabled
        self.clock = clock

    def get_regions(self) -> RecommendationRegionsResponse:
        candidate = self.candidate_resolver() if self.enabled else None
        if candidate is None:
            return RecommendationRegionsResponse(candidate_sha256=None, regions=())
        groups: dict[str, tuple[str, int]] = {}
        assessments = {row.place_id: row for row in candidate.assessments}
        for source in candidate.source_snapshots:
            place = source["place"]
            # Labels come from the same official catalog as the active place profiles.
            label = place.get("region_name")
            code = place.get("region_code")
            if (
                not label
                or not code
                or source.get("category") not in {"관광지", "문화시설", "레포츠", "축제·공연·행사"}
            ):
                continue
            assessment = assessments[place["place_id"]]
            if sum(assessment.dimensions[axis].value is not None for axis in "HER") < 2:
                continue
            province = str(label).split()[0]
            prefix = str(code)[:2]
            previous = groups.get(prefix)
            if previous and previous[0] != province:
                raise RecommendationPinInvalid("official catalog province labels disagree")
            groups[prefix] = (province, (previous[1] if previous else 0) + 1)
        return RecommendationRegionsResponse(
            candidate_sha256=candidate.candidate_sha256,
            regions=tuple(
                RecommendationRegion(region_code=code, region_name=name, place_count=count)
                for code, (name, count) in sorted(groups.items())
            ),
        )

    def create_run(self, request: RecommendationRequest) -> Any:
        schema = self.runs.lookup_schema_for_request(request.request_id)
        if schema is not None and schema != GROUNDED_RUN_SCHEMA:
            return self.legacy.create_run(request)
        profile = self.profiles.get(request.preference_profile_id)
        if profile is None:
            raise PreferenceProfileUnavailable(request.preference_profile_id)
        if schema == GROUNDED_RUN_SCHEMA:
            stored = self.runs.recover_bound_request(
                request_id=request.request_id, preference_profile_id=profile.profile_id
            )
            if stored is None:
                raise RecommendationPinInvalid("grounded request binding missing")
            pinned = self.runs.load_pinned(stored.run_id)
            try:
                expected = build_grounded_preference(profile, request, pinned.confirmed_mood)
            except ValueError as error:
                raise RecommendationRequestConflict("RECOMMENDATION_REQUEST_CONFLICT") from error
            if stored.preference != expected:
                raise RecommendationRequestConflict("RECOMMENDATION_REQUEST_CONFLICT")
            return stored
        if not self.enabled:
            # Pausing new recommendations must never resurrect unsupported
            # legacy scoring. Previously pinned runs remain replayable above.
            raise NoActiveScoredRelease(
                request_id=request.request_id, preference_profile_id=profile.profile_id
            )
        candidate = self.candidate_resolver()
        if candidate is None:
            raise NoActiveScoredRelease(
                request_id=request.request_id, preference_profile_id=profile.profile_id
            )
        confirmed = None
        if request.photo_job_id is not None:
            if self.mood_reader is None:
                raise PhotoRecommendationUnavailable(request.photo_job_id)
            try:
                confirmed = self.mood_reader.read_projection(
                    job_id=request.photo_job_id, profile_id=profile.profile_id
                )
            except (ValueError, RuntimeError) as error:
                raise PhotoRecommendationUnavailable(request.photo_job_id) from error
        preference = build_grounded_preference(profile, request, confirmed)
        payloads: dict[str, dict[str, Any]] = {}
        if preference.trip_input.required_facilities:
            self.registry.refresh_credentials()
            # Facility facts, unlike forecasts/regional context, can enforce explicit needs.
            ids = tuple(p.place_id for p in candidate.raw_release.profiles)
            for snapshot in self.registry.accessibility.get_many(ids):
                payload = snapshot.model_dump(mode="json")
                payloads[self.sources.put_source(payload)] = payload
            for source in candidate.source_snapshots:
                if source.get("category") not in ("레포츠", "숙박"):
                    continue
                pid = source["place"]["place_id"]
                camp, batches = self.registry.camping.get_context_with_sources(pid)
                payload = camp.model_dump(mode="json")
                payloads[self.sources.put_source(payload)] = payload
                for batch in batches:
                    payload = batch.model_dump(mode="json")
                    payloads[self.sources.put_source(payload)] = payload
        candidates = build_candidates(candidate, tuple(payloads.values()), preference, profile)
        try:
            run = rank_grounded(
                candidates=candidates,
                preference=preference,
                release_sha256=candidate.raw_release.release_sha256,
                source_release_sha256=candidate.manifest.source_release_sha256,
                assessment_manifest_sha256=candidate.manifest.manifest_sha256,
                candidate_sha256=candidate.candidate_sha256,
                membership_sha256=candidate.raw_release.membership_sha256,
                relation_sha256=candidate.raw_release.relation_sha256,
                forbidden_pairs=candidate.raw_release.relation_pairs,
                contextual_snapshot_sha256=tuple(sorted(payloads)),
                created_at=self.clock(),
            )
        except GroundedRecommendationError as error:
            if str(error) == "INSUFFICIENT_ELIGIBLE_CANDIDATES":
                raise InsufficientEligibleCandidates(str(error)) from error
            raise RecommendationPinInvalid("grounded input or ranking failed validation") from error
        persisted, _ = self.runs.insert_or_recover(
            request_id=request.request_id,
            preference_profile_id=profile.profile_id,
            run=run,
            candidate=candidate,
            contextual_snapshot_sha256=tuple(sorted(payloads)),
            confirmed_mood=confirmed,
        )
        return persisted

    def create_run_response(self, request: RecommendationRequest) -> RecommendationRunCreated:
        run = self.create_run(request)
        profile = self.profiles.get(request.preference_profile_id)
        if profile is None:
            raise PreferenceProfileUnavailable(request.preference_profile_id)
        return RecommendationRunCreated(
            recommendation_run_id=run.run_id,
            request_id=request.request_id,
            preference_profile_id=profile.profile_id,
            preference_input_sha256=preference_submission_sha256(profile),
        )

    def _grounded(self, run_id: str) -> bool:
        return self.runs.lookup_schema_for_run(run_id) == GROUNDED_RUN_SCHEMA

    def get_run(self, run_id: str) -> Any:
        return self.runs.load_run(run_id) if self._grounded(run_id) else self.legacy.get_run(run_id)

    def get_results(self, run_id: str) -> Any:
        return (
            self.runs.load_results(run_id)
            if self._grounded(run_id)
            else self.legacy.get_results(run_id)
        )

    def get_detail(self, run_id: str, place_id: str) -> Any:
        return (
            self.runs.load_detail(run_id, place_id)
            if self._grounded(run_id)
            else self.legacy.get_detail(run_id, place_id)
        )

    def get_comparison(self, run_id: str, place_ids: tuple[str, ...]) -> Any:
        return (
            self.runs.load_comparison(run_id, place_ids)
            if self._grounded(run_id)
            else self.legacy.get_comparison(run_id, place_ids)
        )

    def get_operating_information(
        self, run_id: str, place_ids: tuple[str, ...]
    ) -> OperatingInformationResponse:
        if not self._grounded(run_id):
            return self.legacy.get_operating_information(run_id, place_ids)
        run = self.runs.load_run(run_id)
        if len(set(place_ids)) != len(place_ids) or not set(place_ids) <= {
            i.place_id for i in run.items
        }:
            raise RecommendationPlaceUnavailable("operating place outside pinned result")
        service = self.legacy._operating_information_service
        if service is not None:
            return service.load(run_id=run_id, place_ids=place_ids)
        return OperatingInformationResponse(
            run_id=run_id,
            places=tuple(
                PlaceOperatingInformation(
                    place_id=pid, state="UNVERIFIED", unavailable_reason="ENRICHMENT_DISABLED"
                )
                for pid in place_ids
            ),
        )

    def get_trip_context(self, run_id: str) -> TripContextResponse:
        if not self._grounded(run_id):
            return self.legacy.get_trip_context(run_id)
        pinned = self.runs.load_pinned(run_id)
        profile = self.profiles.get(pinned.preference_profile_id)
        if profile is None:
            raise PreferenceProfileUnavailable(pinned.preference_profile_id)
        prepared = {
            c.place_id: c
            for c in build_candidates(
                pinned.candidate, pinned.contextual_snapshots, pinned.run.preference, profile
            )
        }
        rows = []
        for item in pinned.run.items:
            facts = tuple(
                prepared[item.place_id].contextual_facts[k.value]
                for k in RequiredFacility
                if k.value in prepared[item.place_id].contextual_facts
            )
            rows.append(
                TripContextPlace(
                    place_id=item.place_id,
                    place_name_ko=item.place_name_ko,
                    facts=facts,
                    source_snapshot_sha256=None,
                    state="PARTIAL" if any(f.value is not None for f in facts) else "UNAVAILABLE",
                    reason_ko="추천에 사용한 시설 정보입니다. 현재 현장 상태와 다를 수 있습니다.",
                )
            )
        return TripContextResponse(
            recommendation_run_id=run_id,
            trip_input=pinned.run.preference.trip_input,
            checked_at=pinned.run.created_at,
            mode="PINNED",
            places=tuple(rows),
        )

    def get_tourism_context(self, run_id: str) -> Any:
        if not self._grounded(run_id):
            return self.legacy.get_tourism_context(run_id)
        pinned = self.runs.load_pinned(run_id)
        return self.registry.context(
            run_id=run_id,
            place_ids=tuple(i.place_id for i in pinned.run.items),
            trip_input=pinned.run.preference.trip_input,
            eligible_place_ids=pinned.run.eligible_place_ids,
            purpose=pinned.run.preference.purpose,
            selected_place_ids=tuple(i.place_id for i in pinned.run.items),
            condition_excluded_place_ids=tuple(
                e.place_id for e in pinned.run.exclusions if e.reason == "EXPLICIT_FACILITY_ABSENT"
            ),
            cannot_coappear_pairs=pinned.candidate.raw_release.relation_pairs,
        )

    def resolve_saved_place_reference(self, release_sha256: str, place_id: str) -> Any:
        from itda.db.assessment_release import AssessmentReleaseRepository

        candidate = AssessmentReleaseRepository(self.runs._factory).load_candidate(release_sha256)
        if candidate is None:
            return self.legacy.resolve_saved_place_reference(release_sha256, place_id)
        current = self.candidate_resolver()
        return self.runs.resolve_saved_place_reference(
            candidate_sha256=release_sha256,
            place_id=place_id,
            current_candidate_sha256=current.candidate_sha256 if current else None,
        )
