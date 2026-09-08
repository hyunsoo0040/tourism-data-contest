"""Server-owned recommendation orchestration over one validated active release."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast

from itda.contracts.base import DataSplit, ExperienceAxis
from itda.contracts.mvp_daily_refresh import MvpScoredReleaseV2, MvpScoredReleaseV3
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.contracts.place_profile import MismatchTraitId, SubattributeId
from itda.contracts.preference import PreferenceProfile
from itda.contracts.recommendation import (
    CANONICAL_RECOMMENDATION_CONFIG,
    EvidenceSnippet,
    ImageDisplayState,
    MvpRecommendationDetail,
    MvpRecommendationResultsResponse,
    MvpRecommendationRun,
    OperatingInformationResponse,
    PhotoMvpRecommendationRun,
    PlaceAxisSnapshot,
    PlaceSubattributeSnapshot,
    PlaceTraitSnapshot,
    PreferenceTraitTarget,
    PublicRelationAuthority,
    Publishability,
    RecommendationCandidate,
    RecommendationComparisonResponse,
    RecommendationConfig,
    RecommendationDetail,
    RecommendationPreference,
    RecommendationRequest,
    RecommendationResultsResponse,
    RecommendationRun,
    RecommendationRunCreated,
    SavedPlaceProjection,
)
from itda.db.photo_repositories import (
    PhotoJobNotFound,
    PhotoRecommendationProjectionRecord,
)
from itda.db.recommendation_repositories import (
    RecommendationRequestConflict,
    RecommendationRunRepository,
)
from itda.db.repositories import ProfileRepository
from itda.domain.canonical import canonical_sha256
from itda.domain.mvp_recommendation import (
    MvpRecommendationError,
    create_mvp_recommendation_run,
    create_photo_mvp_recommendation_run,
)
from itda.domain.photo_projection import project_photo_confirmed_profile
from itda.domain.recommendation_projection import (
    project_place_condition_scores,
    project_recommendation_preference,
)
from itda.operating.service import OperatingInformationService

if TYPE_CHECKING:
    from itda.contracts.demo_profile_materialization import PublicScoredReleaseSnapshot
    from itda.contracts.phase5_recovery_policy import Phase5RecoveryPolicy
else:
    PublicScoredReleaseSnapshot = Any

LOGGER = logging.getLogger(__name__)


ReleaseSnapshot = (
    PublicScoredReleaseSnapshot | MvpScoredRelease | MvpScoredReleaseV2 | MvpScoredReleaseV3
)
RecommendationRunRecord = RecommendationRun | MvpRecommendationRun | PhotoMvpRecommendationRun
RecommendationResultsRecord = RecommendationResultsResponse | MvpRecommendationResultsResponse


class ActivePublicScoredReleaseResolver(Protocol):
    def __call__(self) -> ReleaseSnapshot | None: ...


class PhotoRecommendationProjectionReaderProtocol(Protocol):
    def read(self, job_id: str, profile_id: str) -> PhotoRecommendationProjectionRecord: ...


class PhotoRecommendationUnavailable(RuntimeError):
    code = "PHOTO_RECOMMENDATION_UNAVAILABLE"


class NoActiveScoredRelease(RuntimeError):
    code = "NO_ACTIVE_SCORED_RELEASE"

    def __init__(self, *, request_id: str, preference_profile_id: str) -> None:
        super().__init__(self.code)
        self.request_id = request_id
        self.preference_profile_id = preference_profile_id


class PreferenceProfileUnavailable(RuntimeError):
    code = "PREFERENCE_PROFILE_UNAVAILABLE"


class InsufficientEligibleCandidates(RuntimeError):
    code = "INSUFFICIENT_ELIGIBLE_CANDIDATES"


class InvalidRecommendationOutput(RuntimeError):
    code = "INVALID_RECOMMENDATION_OUTPUT"


class LegacyRecommendationKernelError(RuntimeError):
    pass


def rank_recommendations(**kwargs: Any) -> RecommendationRun:
    from itda.domain.recommendation import RecommendationKernelError
    from itda.domain.recommendation import rank_recommendations as legacy_rank

    try:
        return legacy_rank(**kwargs)
    except RecommendationKernelError as error:
        raise LegacyRecommendationKernelError(str(error)) from error


def _preference_submission_sha256(profile: PreferenceProfile) -> str:
    return canonical_sha256(
        {
            "questionnaire_version": profile.questionnaire_version,
            "scoring_version": profile.scoring_version,
            "description_template_version": profile.description_template_version,
            "config_hash": profile.config_hash,
            "trip_conditions": profile.trip_conditions.model_dump(mode="json"),
            "answers": profile.answers.model_dump(mode="json"),
        }
    )


def _recommendation_preference(profile: PreferenceProfile) -> RecommendationPreference:
    return project_recommendation_preference(profile)


def _legacy_recovery_policy() -> Phase5RecoveryPolicy:
    from itda.contracts.phase5_recovery_policy import CANONICAL_PHASE5_RECOVERY_POLICY

    return CANONICAL_PHASE5_RECOVERY_POLICY


def _validate_recovery_snapshot(snapshot: PublicScoredReleaseSnapshot) -> None:
    policy = _legacy_recovery_policy()
    if snapshot.state != "ACTIVE":
        raise NoActiveScoredRelease(
            request_id="server",
            preference_profile_id="server",
        )
    # Synthetic fixtures remain valid for unit/integration coverage; they are
    # model-constructed without release identity fields. A present but wrong
    # production membership is never accepted.
    membership_sha256 = getattr(snapshot, "membership_sha256", None)
    if membership_sha256 is None:
        return
    if membership_sha256 != policy.cannot_coappear_authority.dev_membership_sha256:
        raise NoActiveScoredRelease(request_id="server", preference_profile_id="server")
    if len(snapshot.profiles) != policy.structural_profile_count:
        raise NoActiveScoredRelease(request_id="server", preference_profile_id="server")
    if snapshot.hard_duplicate_adjudication_sha256 != policy.hard_duplicate_adjudication_sha256:
        raise NoActiveScoredRelease(request_id="server", preference_profile_id="server")
    if (
        snapshot.hard_duplicate_adjudication_sha256
        != snapshot.hard_duplicate_adjudication.adjudication_sha256
    ):
        raise NoActiveScoredRelease(request_id="server", preference_profile_id="server")
    if tuple(profile.place_id for profile in snapshot.profiles) != tuple(
        sorted(profile.place_id for profile in snapshot.profiles)
    ):
        raise NoActiveScoredRelease(request_id="server", preference_profile_id="server")
    if (
        len(
            tuple(
                profile.place_id
                for profile in snapshot.profiles
                if profile.confidence >= policy.candidate_confidence_min
            )
        )
        < policy.minimum_effective_candidate_count
    ):
        raise NoActiveScoredRelease(request_id="server", preference_profile_id="server")


def _recommendation_candidates(
    snapshot: PublicScoredReleaseSnapshot,
) -> tuple[RecommendationCandidate, ...]:
    _validate_recovery_snapshot(snapshot)
    candidates: list[RecommendationCandidate] = []
    policy = _legacy_recovery_policy()
    for profile in snapshot.profiles:
        justifications = profile.evidence_justifications

        def evidence_for(
            dimension: str,
            *,
            _justifications: Mapping[str, tuple[str, ...]] = justifications,
        ) -> tuple[str, ...]:
            return tuple(_justifications[dimension])

        axis_value_by_id = {
            ExperienceAxis.HISTORY_TRADITION: profile.axis_scores["H"],
            ExperienceAxis.EMOTION_IMAGE: profile.axis_scores["E"],
            ExperienceAxis.REST_IMMERSION: profile.axis_scores["R"],
        }
        reference_date = profile.created_at.astimezone(UTC).date()
        evidence = tuple(
            EvidenceSnippet(
                evidence_id=source.evidence_id,
                excerpt_ko=source.excerpt_ko,
                source_label_ko=source.source_label_ko,
                attribution_ko=source.attribution_ko,
                contest_use_scope=source.contest_use_scope,
                contest_rights_qualified=source.contest_rights_qualified,
                reference_date=reference_date,
            )
            for source in profile.evidence_excerpts
        )
        candidates.append(
            RecommendationCandidate(
                place_id=profile.place_id,
                place_name_ko=profile.place_name_ko,
                split=DataSplit.DEV,
                exact_release_member=True,
                profile_score_truth="LOCAL_PROFILE_SCORES",
                analysis_origin=profile.analysis_origin,
                publishability=(
                    Publishability.PUBLISHABLE
                    if profile.confidence >= policy.ordinary_information_confidence_min
                    else Publishability.LIMITED_INFORMATION
                    if profile.confidence >= policy.candidate_confidence_min
                    else Publishability.EXCLUDED
                ),
                recommendation_eligible=profile.confidence >= policy.candidate_confidence_min,
                profile_sha256=profile.projection_sha256,
                duplicate_group_id=profile.duplicate_group_id,
                overall_confidence=profile.confidence,
                axis_scores=cast(
                    tuple[PlaceAxisSnapshot, PlaceAxisSnapshot, PlaceAxisSnapshot],
                    tuple(
                        PlaceAxisSnapshot(
                            axis=axis,
                            value=axis_value_by_id[axis],
                            evidence_ids=evidence_for(
                                {
                                    ExperienceAxis.HISTORY_TRADITION: "H",
                                    ExperienceAxis.EMOTION_IMAGE: "E",
                                    ExperienceAxis.REST_IMMERSION: "R",
                                }[axis]
                            ),
                        )
                        for axis in ExperienceAxis
                    ),
                ),
                subattributes=cast(
                    tuple[
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                        PlaceSubattributeSnapshot,
                    ],
                    tuple(
                        PlaceSubattributeSnapshot(
                            attribute_id=attribute,
                            value=profile.subattributes[attribute.value],
                            evidence_ids=evidence_for(attribute.value),
                        )
                        for attribute in SubattributeId
                    ),
                ),
                mismatch_traits=cast(
                    tuple[
                        PlaceTraitSnapshot,
                        PlaceTraitSnapshot,
                        PlaceTraitSnapshot,
                        PlaceTraitSnapshot,
                        PlaceTraitSnapshot,
                        PlaceTraitSnapshot,
                    ],
                    tuple(
                        PlaceTraitSnapshot(
                            trait_id=trait,
                            value=profile.mismatch_traits[trait.value],
                            evidence_ids=evidence_for(trait.value),
                        )
                        for trait in MismatchTraitId
                    ),
                ),
                condition_scores=project_place_condition_scores(profile),
                evidence=evidence,
                reference_date=reference_date,
                popularity=0,
                source_volume=0,
                image_state=ImageDisplayState.ABSENT,
            )
        )
    return tuple(candidates)


EventSink = Callable[[dict[str, object]], None]


def _default_event_sink(event: dict[str, object]) -> None:
    LOGGER.info("recommendation_event", extra={"itda_recommendation": event})


class RecommendationService:
    """Resolve authority, calculate once, persist atomically, and serve pinned reads."""

    def __init__(
        self,
        *,
        profile_repository: ProfileRepository,
        recommendation_repository: RecommendationRunRepository,
        release_resolver: ActivePublicScoredReleaseResolver,
        photo_projection_reader: PhotoRecommendationProjectionReaderProtocol | None = None,
        operating_information_service: OperatingInformationService | None = None,
        config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        event_sink: EventSink = _default_event_sink,
    ) -> None:
        self._profile_repository = profile_repository
        self._recommendation_repository = recommendation_repository
        self._release_resolver = release_resolver
        self._photo_projection_reader = photo_projection_reader
        self._operating_information_service = operating_information_service
        self._config = config
        self._clock = clock
        self._event_sink = event_sink

    def _emit(self, event: dict[str, object]) -> None:
        try:
            self._event_sink(event)
        except Exception:
            LOGGER.exception("recommendation event sink failed")

    def create_run(self, request: RecommendationRequest) -> RecommendationRunRecord:
        started = time.perf_counter()
        profile = self._profile_repository.get(request.preference_profile_id)
        if profile is None:
            raise PreferenceProfileUnavailable(request.preference_profile_id)
        no_photo_preference = _recommendation_preference(profile)
        projection: PhotoRecommendationProjectionRecord | None = None
        preference = no_photo_preference
        photo_projection_result = None
        if request.photo_job_id is not None:
            if self._photo_projection_reader is None:
                raise PhotoRecommendationUnavailable(request.photo_job_id)
            try:
                projection = self._photo_projection_reader.read(
                    request.photo_job_id,
                    profile.profile_id,
                )
                photo_projection_result = project_photo_confirmed_profile(
                    confirmed_traits=projection.traits,
                    images_count=projection.images_count,
                    no_photo_trait_values={
                        row.trait_id.value: row.value for row in no_photo_preference.trait_targets
                    },
                    trip_conditions=profile.trip_conditions.model_dump(mode="json"),
                    answers=profile.answers.model_dump(mode="json"),
                    questionnaire_version=profile.questionnaire_version,
                )
            except (PhotoJobNotFound, TypeError, ValueError) as error:
                raise PhotoRecommendationUnavailable(request.photo_job_id) from error
            if photo_projection_result.trait_targets is None:
                raise PhotoRecommendationUnavailable(request.photo_job_id)
            blended_values = {
                row.trait_id: row.value for row in photo_projection_result.trait_targets
            }
            preference = no_photo_preference.model_copy(
                update={
                    "trait_targets": tuple(
                        PreferenceTraitTarget(
                            trait_id=row.trait_id,
                            value=blended_values[row.trait_id],
                            important=row.important,
                        )
                        for row in no_photo_preference.trait_targets
                    )
                }
            )
        bound = self._recommendation_repository.recover_bound_request(
            request_id=request.request_id,
            preference_profile_id=profile.profile_id,
        )
        if isinstance(bound, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            expected_preference = preference
            if bound.preference != expected_preference or (
                isinstance(bound, PhotoMvpRecommendationRun) != (request.photo_job_id is not None)
            ):
                raise RecommendationRequestConflict(
                    RecommendationRunRepository.code_for_conflict(request.request_id)
                )
            if isinstance(bound, PhotoMvpRecommendationRun) and (
                photo_projection_result is None
                or projection is None
                or bound.authority.photo_projection_output_sha256
                != photo_projection_result.output_sha256
                or bound.authority.confirmation_draft_sha256 != projection.draft_digest
                or bound.authority.photo_job_reference_sha256
                != canonical_sha256({"photo_job_id": request.photo_job_id})
            ):
                raise RecommendationRequestConflict(
                    RecommendationRunRepository.code_for_conflict(request.request_id)
                )
            return bound
        if isinstance(bound, RecommendationRun):
            expected_legacy_digest = canonical_sha256(
                {
                    "preference": preference.model_dump(mode="json"),
                    "release_sha256": bound.release_sha256,
                    "canonical_membership_sha256": bound.canonical_membership_sha256,
                    "candidate_set_digest": bound.candidate_set_digest,
                    "config_sha256": bound.config_sha256,
                    "kernel_version": bound.kernel_version,
                    "recovery_policy_sha256": bound.authority.recovery_policy_sha256,
                    "hard_duplicate_adjudication_sha256": (
                        bound.authority.hard_duplicate_adjudication_sha256
                    ),
                    "cannot_coappear_authority_sha256": (
                        bound.authority.cannot_coappear_authority_sha256
                    ),
                    "activation_suite_sha256": bound.authority.activation_suite_sha256,
                    "contrast_suite_sha256": bound.authority.contrast_suite_sha256,
                }
            )
            if bound.input_digest != expected_legacy_digest:
                raise RecommendationRequestConflict(
                    RecommendationRunRepository.code_for_conflict(request.request_id)
                )
            return bound
        snapshot = self._release_resolver()
        if snapshot is None:
            self._emit(
                {
                    "event": "recommendation_run",
                    "outcome": NoActiveScoredRelease.code,
                    "request_id": request.request_id,
                    "candidate_count": 0,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    "recovered": False,
                }
            )
            raise NoActiveScoredRelease(
                request_id=request.request_id,
                preference_profile_id=request.preference_profile_id,
            )
        if isinstance(snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)):
            relation = PublicRelationAuthority(
                relation_sha256=snapshot.relation_sha256,
                place_ids=tuple(row.place_id for row in snapshot.profiles),
                pairs=snapshot.relation_pairs,
            )
            candidate_sha256 = canonical_sha256(
                [
                    {
                        "place_id": row.place_id,
                        "profile_sha256": row.profile_sha256,
                        "duplicate_group_id": row.duplicate_group_id,
                    }
                    for row in snapshot.profiles
                ]
            )
            authority: dict[str, object] = {
                "release_sha256": snapshot.release_sha256,
                "membership_sha256": snapshot.membership_sha256,
                "relation_sha256": relation.relation_sha256,
                "candidate_sha256": candidate_sha256,
                "config_sha256": self._config.config_sha256,
                "kernel_version": self._config.kernel_version,
            }
            if request.photo_job_id is not None:
                if photo_projection_result is None or projection is None:
                    raise PhotoRecommendationUnavailable(request.photo_job_id)
                authority.update(
                    {
                        "photo_projection_version": "photo-projection-v1",
                        "photo_projection_policy_sha256": photo_projection_result.policy_sha256,
                        "photo_projection_output_sha256": photo_projection_result.output_sha256,
                        "confirmation_draft_sha256": projection.draft_digest,
                        "photo_job_reference_sha256": canonical_sha256(
                            {"photo_job_id": request.photo_job_id}
                        ),
                        "images_count": projection.images_count,
                        "included_count": projection.included_count,
                    }
                )
            expected_input_digest = canonical_sha256(
                {
                    "preference": preference.model_dump(mode="json"),
                    "authority": authority,
                }
            )
            recovered_run = self._recommendation_repository.recover_by_request_id(
                request_id=request.request_id,
                preference_profile_id=profile.profile_id,
                input_digest=expected_input_digest,
            )
            if recovered_run is not None:
                return recovered_run
            try:
                if request.photo_job_id is None:
                    calculated: RecommendationRunRecord = create_mvp_recommendation_run(
                        snapshot.profiles,
                        release_sha256=snapshot.release_sha256,
                        membership_sha256=snapshot.membership_sha256,
                        relation_authority=relation,
                        preference=preference,
                        config=self._config,
                        created_at=self._clock(),
                    )
                else:
                    if photo_projection_result is None or projection is None:
                        raise PhotoRecommendationUnavailable(request.photo_job_id)
                    calculated = create_photo_mvp_recommendation_run(
                        snapshot.profiles,
                        release_sha256=snapshot.release_sha256,
                        membership_sha256=snapshot.membership_sha256,
                        relation_authority=relation,
                        preference=preference,
                        photo_projection_policy_sha256=photo_projection_result.policy_sha256,
                        photo_projection_output_sha256=photo_projection_result.output_sha256,
                        confirmation_draft_sha256=projection.draft_digest,
                        photo_job_reference_sha256=canonical_sha256(
                            {"photo_job_id": request.photo_job_id}
                        ),
                        images_count=projection.images_count,
                        included_count=projection.included_count,
                        config=self._config,
                        created_at=self._clock(),
                    )
            except MvpRecommendationError as error:
                if str(error) == InsufficientEligibleCandidates.code:
                    raise InsufficientEligibleCandidates(str(error)) from error
                raise InvalidRecommendationOutput(str(error)) from error
        else:
            if request.photo_job_id is not None:
                raise PhotoRecommendationUnavailable(request.photo_job_id)
            candidates = _recommendation_candidates(snapshot)
            cannot_coappear_authority = _legacy_recovery_policy().cannot_coappear_authority
            candidate_set_digest = canonical_sha256(
                [
                    {
                        "place_id": candidate.place_id,
                        "profile_sha256": candidate.profile_sha256,
                        "duplicate_group_id": candidate.duplicate_group_id,
                    }
                    for candidate in candidates
                ]
            )
            expected_input_digest = canonical_sha256(
                {
                    "preference": preference.model_dump(mode="json"),
                    "release_sha256": snapshot.release_sha256,
                    "canonical_membership_sha256": snapshot.membership_sha256,
                    "candidate_set_digest": candidate_set_digest,
                    "config_sha256": self._config.config_sha256,
                    "kernel_version": self._config.kernel_version,
                }
            )
            recovered_run = self._recommendation_repository.recover_by_request_id(
                request_id=request.request_id,
                preference_profile_id=profile.profile_id,
                input_digest=expected_input_digest,
            )
            if recovered_run is not None:
                return recovered_run
            try:
                calculated = rank_recommendations(
                    preference=preference,
                    candidates=candidates,
                    release_sha256=snapshot.release_sha256,
                    canonical_membership_sha256=snapshot.membership_sha256,
                    created_at=self._clock(),
                    config=self._config,
                    cannot_coappear_authority=cannot_coappear_authority,
                )
            except LegacyRecommendationKernelError as error:
                if str(error) == InsufficientEligibleCandidates.code:
                    raise InsufficientEligibleCandidates(str(error)) from error
                raise InvalidRecommendationOutput(str(error)) from error
        persisted, recovered = self._recommendation_repository.insert_or_recover(
            request_id=request.request_id,
            preference_profile_id=profile.profile_id,
            run=calculated,
            release_snapshot=snapshot,
        )
        release_sha256 = (
            persisted.authority.release_sha256
            if isinstance(persisted, (MvpRecommendationRun, PhotoMvpRecommendationRun))
            else persisted.release_sha256
        )
        config_sha256 = (
            persisted.authority.config_sha256
            if isinstance(persisted, (MvpRecommendationRun, PhotoMvpRecommendationRun))
            else persisted.config_sha256
        )
        kernel_version = (
            persisted.authority.kernel_version
            if isinstance(persisted, (MvpRecommendationRun, PhotoMvpRecommendationRun))
            else persisted.kernel_version
        )
        self._emit(
            {
                "event": "recommendation_run",
                "outcome": "RECOVERED" if recovered else "CREATED",
                "request_id": request.request_id,
                "run_id": persisted.run_id,
                "release_sha256": release_sha256,
                "config_sha256": config_sha256,
                "kernel_version": kernel_version,
                "candidate_count": len(persisted.candidate_place_ids),
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "recovered": recovered,
            }
        )
        return persisted

    def create_run_response(self, request: RecommendationRequest) -> RecommendationRunCreated:
        run = self.create_run(request)
        profile = self._profile_repository.get(request.preference_profile_id)
        if profile is None:
            raise PreferenceProfileUnavailable(request.preference_profile_id)
        return RecommendationRunCreated(
            recommendation_run_id=run.run_id,
            request_id=request.request_id,
            preference_profile_id=request.preference_profile_id,
            preference_input_sha256=_preference_submission_sha256(profile),
        )

    def get_run(self, run_id: str) -> RecommendationRunRecord:
        return self._recommendation_repository.load_run(run_id)

    def get_results(self, run_id: str) -> RecommendationResultsRecord:
        return self._recommendation_repository.load_results(run_id)

    def get_detail(
        self, run_id: str, place_id: str
    ) -> RecommendationDetail | MvpRecommendationDetail:
        return self._recommendation_repository.load_detail(run_id, place_id)

    def get_comparison(
        self,
        run_id: str,
        place_ids: tuple[str, ...],
    ) -> RecommendationComparisonResponse:
        return self._recommendation_repository.load_comparison(run_id, place_ids)

    def get_operating_information(
        self,
        run_id: str,
        place_ids: tuple[str, ...],
    ) -> OperatingInformationResponse:
        run = self._recommendation_repository.load_run(run_id)
        allowed = {item.place_id for item in run.items}
        if len(place_ids) != len(set(place_ids)) or any(
            place_id not in allowed for place_id in place_ids
        ):
            from itda.db.recommendation_repositories import RecommendationPlaceUnavailable

            raise RecommendationPlaceUnavailable("operating place is outside the pinned run")
        if self._operating_information_service is None:
            from itda.contracts.recommendation import PlaceOperatingInformation

            return OperatingInformationResponse(
                run_id=run_id,
                places=tuple(
                    PlaceOperatingInformation(
                        place_id=place_id,
                        state="UNVERIFIED",
                        unavailable_reason="ENRICHMENT_DISABLED",
                    )
                    for place_id in place_ids
                ),
            )
        return self._operating_information_service.load(run_id=run_id, place_ids=place_ids)

    def resolve_saved_place_reference(
        self,
        release_sha256: str,
        place_id: str,
    ) -> SavedPlaceProjection:
        current = self._release_resolver()
        return self._recommendation_repository.resolve_saved_place_reference(
            release_sha256=release_sha256,
            place_id=place_id,
            current_release_sha256=current.release_sha256 if current is not None else None,
        )


__all__ = [
    "InsufficientEligibleCandidates",
    "InvalidRecommendationOutput",
    "NoActiveScoredRelease",
    "PhotoRecommendationUnavailable",
    "PreferenceProfileUnavailable",
    "RecommendationService",
]
