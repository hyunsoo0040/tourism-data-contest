"""Server-owned recommendation orchestration over one validated active release."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast

from itda.application.source_grounding import PreparedGrounding, SourceGroundingService
from itda.contracts.base import DataSplit, ExperienceAxis
from itda.contracts.grounded_recommendation import (
    GroundedRunBinding,
    GroundedTripInput,
    TripContextPlace,
    TripContextResponse,
)
from itda.contracts.mvp_daily_refresh import MvpScoredReleaseV2, MvpScoredReleaseV3
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
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
    RecommendationPurpose,
    RecommendationQualityContext,
    RecommendationRequest,
    RecommendationResultsResponse,
    RecommendationRun,
    RecommendationRunCreated,
    SavedPlaceProjection,
)
from itda.contracts.tourism_context import TourismContextResponse
from itda.db.photo_repositories import (
    PhotoJobNotFound,
    PhotoRecommendationProjectionRecord,
)
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
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
from itda.tourism.registry import ProductionTourismRegistry

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
        source_grounding_service: SourceGroundingService | None = None,
        tourism_registry: ProductionTourismRegistry | None = None,
        catalog: PublicPlaceCatalog | None = None,
        config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        event_sink: EventSink = _default_event_sink,
    ) -> None:
        self._profile_repository = profile_repository
        self._recommendation_repository = recommendation_repository
        self._release_resolver = release_resolver
        self._photo_projection_reader = photo_projection_reader
        self._operating_information_service = operating_information_service
        self._source_grounding = source_grounding_service
        self._tourism_registry = tourism_registry
        self._config = config
        self._catalog = catalog
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
        bound = self._recommendation_repository.recover_bound_request(
            request_id=request.request_id,
            preference_profile_id=profile.profile_id,
        )
        trip_input = request.grounded_input or GroundedTripInput(
            visit_date=profile.trip_conditions.visit_date,
        )
        prepared_grounding: PreparedGrounding | None = None
        if isinstance(bound, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            grounding = (
                bound.preference.quality_context.grounding
                if bound.preference.quality_context
                else None
            )
            if grounding is not None:
                if self._source_grounding is None:
                    raise RecommendationPinInvalid("grounded replay storage is unavailable")
                binding = self._source_grounding.store.get_request_binding(request.request_id)
                if binding is None:
                    raise RecommendationPinInvalid("grounded request binding is missing")
                if (
                    binding.run_id != bound.run_id
                    or binding.preference_profile_id != profile.profile_id
                    or binding.preference_input_sha256 != _preference_submission_sha256(profile)
                    or binding.trip_input_sha256 != trip_input.input_sha256
                    or grounding.trip_input_sha256 != binding.trip_input_sha256
                    or grounding.source_release_sha256 != binding.source_release_sha256
                    or grounding.source_snapshot_sha256 != binding.source_snapshot_sha256
                    or bound.authority.release_sha256 != binding.raw_release_sha256
                ):
                    raise RecommendationRequestConflict(
                        RecommendationRunRepository.code_for_conflict(request.request_id)
                    )
            elif request.grounded_input is not None:
                raise RecommendationRequestConflict(
                    RecommendationRunRepository.code_for_conflict(request.request_id)
                )
        elif (
            bound is None and request.grounded_input is not None and self._source_grounding is None
        ):
            raise InvalidRecommendationOutput("explicit facility requirements are not available")
        quality_context = None
        preloaded_snapshot: MvpScoredRelease | MvpScoredReleaseV2 | MvpScoredReleaseV3 | None = None
        if isinstance(bound, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            quality_context = bound.preference.quality_context
            if request.purpose is not None and request.purpose != (
                quality_context.purpose if quality_context else RecommendationPurpose.MIXED
            ):
                raise RecommendationRequestConflict(
                    RecommendationRunRepository.code_for_conflict(request.request_id)
                )
        elif bound is None and self._config.kernel_version == "recommendation-kernel-v4":
            if self._catalog is None:
                raise NoActiveScoredRelease(
                    request_id=request.request_id,
                    preference_profile_id=profile.profile_id,
                )
            resolved = self._release_resolver()
            if not isinstance(resolved, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)):
                raise NoActiveScoredRelease(
                    request_id=request.request_id,
                    preference_profile_id=profile.profile_id,
                )
            preloaded_snapshot = resolved
            available_place_ids = {row.place_id for row in resolved.profiles}
            purpose = request.purpose or RecommendationPurpose.SIGHTSEEING
            categories = {
                RecommendationPurpose.SIGHTSEEING: {
                    "관광지",
                    "문화시설",
                    "레포츠",
                    "축제·공연·행사",
                },
                RecommendationPurpose.FOOD: {"음식점"},
                RecommendationPurpose.LODGING: {"숙박"},
            }
            allowed = tuple(
                sorted(
                    row.place_id
                    for row in self._catalog.places
                    if row.place_id in available_place_ids
                    and (
                        purpose is RecommendationPurpose.MIXED
                        or row.category in categories[purpose]
                    )
                )
            )
            quality_context = RecommendationQualityContext(
                companion=profile.trip_conditions.companion.value,
                transport=profile.trip_conditions.transport.value,
                purpose=purpose,
                eligible_place_ids=allowed,
            )
            if self._source_grounding is not None:
                prepared_grounding = self._source_grounding.prepare(
                    trip_input=trip_input,
                    raw_release_sha256=resolved.release_sha256,
                    place_ids=allowed,
                )
                quality_context = quality_context.model_copy(
                    update={
                        "eligible_place_ids": tuple(
                            p for p in allowed if p not in prepared_grounding.excluded_place_ids
                        ),
                        "grounding": prepared_grounding.authority,
                    }
                )
        no_photo_preference = project_recommendation_preference(
            profile,
            quality_context=quality_context,
        )
        if isinstance(bound, PhotoMvpRecommendationRun):
            if (
                request.photo_job_id is None
                or bound.authority.photo_job_reference_sha256
                != canonical_sha256({"photo_job_id": request.photo_job_id})
                or bound.preference.input_sha256 != no_photo_preference.input_sha256
                or bound.preference.axis_targets != no_photo_preference.axis_targets
                or bound.preference.condition_targets != no_photo_preference.condition_targets
            ):
                raise RecommendationRequestConflict(
                    RecommendationRunRepository.code_for_conflict(request.request_id)
                )
            # All sealed photo versions replay before projection/provider access.
            return bound
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
            if (
                photo_projection_result.trait_targets is None
                or not photo_projection_result.blend_applied
            ):
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
        snapshot = (
            preloaded_snapshot if preloaded_snapshot is not None else self._release_resolver()
        )
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
                        "photo_projection_version": photo_projection_result.projection_version,
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
                        photo_projection_version=photo_projection_result.projection_version,
                        observed_traits=tuple(
                            trait for trait, _ in photo_projection_result.photo_trait_values
                        ),
                        photo_trait_values=photo_projection_result.photo_trait_values,
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
        grounded_binding = None
        if prepared_grounding is not None:
            binding_data = {
                "schema_version": "grounded-run-binding.v1",
                "run_id": calculated.run_id,
                "request_id": request.request_id,
                "preference_profile_id": profile.profile_id,
                "preference_input_sha256": _preference_submission_sha256(profile),
                "trip_input": trip_input.model_dump(mode="json"),
                "trip_input_sha256": trip_input.input_sha256,
                "raw_release_sha256": snapshot.release_sha256,
                "source_release_sha256": prepared_grounding.authority.source_release_sha256,
                "assessment_bundle_sha256": list(
                    prepared_grounding.authority.assessment_bundle_sha256
                ),
                "source_snapshot_sha256": list(prepared_grounding.authority.source_snapshot_sha256),
                "created_at": calculated.created_at.isoformat().replace("+00:00", "Z"),
            }
            grounded_binding = GroundedRunBinding.model_validate(
                {
                    **binding_data,
                    "binding_sha256": canonical_sha256(binding_data),
                }
            )
        insert_extra = {"grounded_binding": grounded_binding} if grounded_binding else {}
        persisted, recovered = self._recommendation_repository.insert_or_recover(
            request_id=request.request_id,
            preference_profile_id=profile.profile_id,
            run=calculated,
            release_snapshot=snapshot,
            **insert_extra,
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

    def get_trip_context(self, run_id: str) -> TripContextResponse:
        run = self._recommendation_repository.load_run(run_id)
        names = {item.place_id: item.place_name_ko for item in run.items}
        profile_id = (
            run.preference.profile_id
            if isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun))
            else self._recommendation_repository.load_pinned(run_id).preference_profile_id
        )
        profile = self._profile_repository.get(profile_id)
        trip_input = GroundedTripInput(
            visit_date=profile.trip_conditions.visit_date if profile else None,
        )
        if self._source_grounding is None:
            return TripContextResponse(
                recommendation_run_id=run_id,
                trip_input=trip_input,
                checked_at=self._clock(),
                mode="REFRESHED",
                places=tuple(
                    TripContextPlace(
                        place_id=p,
                        place_name_ko=n,
                        facts=(),
                        source_snapshot_sha256=None,
                        state="UNAVAILABLE",
                        reason_ko="추가 관광정보 연결이 준비되지 않았습니다.",
                    )
                    for p, n in names.items()
                ),
            )
        binding = self._source_grounding.store.get_run_binding(run_id)
        expected_grounding = (
            run.preference.quality_context.grounding
            if isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun))
            and run.preference.quality_context
            else None
        )
        if expected_grounding is not None and binding is None:
            raise RecommendationPinInvalid("grounded run binding is missing")
        if binding is not None:
            if not isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
                raise RecommendationPinInvalid("grounding is not bound to an MVP run")
            authority = (
                run.preference.quality_context.grounding if run.preference.quality_context else None
            )
            if (
                authority is None
                or authority.source_release_sha256 != binding.source_release_sha256
                or authority.source_snapshot_sha256 != binding.source_snapshot_sha256
                or authority.trip_input_sha256 != binding.trip_input_sha256
            ):
                raise RecommendationPinInvalid("grounding authority mismatch")
            trip_input = binding.trip_input
        try:
            return self._source_grounding.context(
                run_id=run_id,
                place_names=names,
                trip_input=trip_input,
                checked_at=self._clock(),
                binding=binding,
            )
        except ValueError as error:
            raise RecommendationPinInvalid("invalid pinned trip context") from error

    def get_tourism_context(self, run_id: str) -> TourismContextResponse:
        """Explicit refresh endpoint, separate from immutable recommendation reads."""
        if self._tourism_registry is None:
            raise InvalidRecommendationOutput("tourism registry is not configured")
        run = self._recommendation_repository.load_run(run_id)
        if not isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            raise InvalidRecommendationOutput("tourism context requires a public source-pinned run")
        profile = self._profile_repository.get(run.preference.profile_id)
        if profile is None:
            raise PreferenceProfileUnavailable(run.preference.profile_id)
        trip = GroundedTripInput(visit_date=profile.trip_conditions.visit_date)
        quality = run.preference.quality_context
        if quality is not None and quality.grounding is not None:
            if self._source_grounding is None:
                raise RecommendationPinInvalid("grounded context storage is unavailable")
            binding = self._source_grounding.store.get_run_binding(run_id)
            if binding is None:
                raise RecommendationPinInvalid("grounded context binding is missing")
            trip = binding.trip_input
        if quality is not None:
            eligible = quality.eligible_place_ids
            purpose = quality.purpose.value
        else:
            eligible = run.candidate_place_ids
            purpose = "MIXED"
        pinned = self._recommendation_repository.load_pinned(run_id)
        pairs = (
            pinned.release_snapshot.relation_pairs
            if isinstance(
                pinned.release_snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)
            )
            else ()
        )
        return self._tourism_registry.context(
            run_id=run_id,
            place_ids=tuple(item.place_id for item in run.items),
            trip_input=trip,
            eligible_place_ids=eligible,
            purpose=purpose,
            selected_place_ids=tuple(item.place_id for item in run.items),
            cannot_coappear_pairs=pairs,
        )

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
