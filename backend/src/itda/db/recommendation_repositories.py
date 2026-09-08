"""Transactional immutable recommendation run and release-pin repository."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypeGuard, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.base import ExperienceAxis
from itda.contracts.mvp_daily_refresh import MvpScoredReleaseV2, MvpScoredReleaseV3
from itda.contracts.mvp_scored_release import MvpScoredProfile, MvpScoredRelease
from itda.contracts.place_profile import MismatchTraitId
from itda.contracts.recommendation import (
    ComparisonRow,
    EvidenceConfidenceState,
    EvidenceSnippet,
    MvpEvidenceSnippet,
    MvpRecommendationDetail,
    MvpRecommendationPublicItem,
    MvpRecommendationReleaseDisclosure,
    MvpRecommendationResultsResponse,
    MvpRecommendationRun,
    PhotoMvpRecommendationRun,
    PlaceTraitSnapshot,
    RecommendationComparisonResponse,
    RecommendationDetail,
    RecommendationItem,
    RecommendationOperatingState,
    RecommendationReleaseDisclosure,
    RecommendationResultsResponse,
    RecommendationRun,
    SavedPlaceProjection,
    SavedPlaceState,
    confidence_state_for,
    mvp_confidence_state_for,
)
from itda.db.models import (
    RecommendationRequestBindingRow,
    RecommendationResultPinRow,
    RecommendationRunRow,
)
from itda.domain.canonical import canonical_sha256

if TYPE_CHECKING:
    from itda.contracts.demo_profile_materialization import (
        PublicScoredProfile,
        PublicScoredReleaseSnapshot,
    )
else:
    PublicScoredProfile = Any
    PublicScoredReleaseSnapshot = Any


class RecommendationRequestConflict(RuntimeError):
    """One request ID is already permanently bound to a different input digest."""

    code = "RECOMMENDATION_REQUEST_CONFLICT"


class RecommendationRunNotFound(RuntimeError):
    code = "RECOMMENDATION_RUN_NOT_FOUND"


class RecommendationPinInvalid(RuntimeError):
    code = "RECOMMENDATION_PIN_INVALID"


class RecommendationPlaceUnavailable(RuntimeError):
    code = "RECOMMENDATION_PLACE_UNAVAILABLE"


def _is_mvp_profile(profile: object) -> TypeGuard[MvpScoredProfile]:
    return hasattr(profile, "scores")


def _profile_trait_value(profile: object, trait: MismatchTraitId) -> int:
    if _is_mvp_profile(profile):
        return cast(int, getattr(profile.scores, trait.value))
    legacy_profile = cast(PublicScoredProfile, profile)
    return legacy_profile.mismatch_traits[trait.value]


def _profile_confidence(profile: object) -> int:
    if _is_mvp_profile(profile):
        return profile.scores.confidence
    return cast(PublicScoredProfile, profile).confidence


def _profile_evidence_ids(profile: object, dimension: str) -> tuple[str, ...]:
    if _is_mvp_profile(profile):
        return next(
            row.evidence_ids
            for row in profile.scores.justifications
            if row.dimension.value == dimension
        )
    return tuple(cast(PublicScoredProfile, profile).evidence_justifications[dimension])


def _detail_traits(
    profile: object,
) -> tuple[
    PlaceTraitSnapshot,
    PlaceTraitSnapshot,
    PlaceTraitSnapshot,
    PlaceTraitSnapshot,
    PlaceTraitSnapshot,
    PlaceTraitSnapshot,
]:
    return cast(
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
                value=_profile_trait_value(profile, trait),
                evidence_ids=_profile_evidence_ids(profile, trait.value),
            )
            for trait in MismatchTraitId
        ),
    )


def _validate_detail_confidence(
    item: RecommendationItem | MvpRecommendationPublicItem,
    confidence_state: EvidenceConfidenceState,
    confidence_reason: str,
) -> None:
    if (
        item.evidence_confidence_state is not confidence_state
        or item.evidence_confidence_reason_ko != confidence_reason
    ):
        raise RecommendationPinInvalid("pinned confidence projection drifted")


def _similar_place_ids(
    run: RecommendationRun | MvpRecommendationRun | PhotoMvpRecommendationRun,
    place_id: str,
) -> tuple[str, ...]:
    return tuple(row.place_id for row in run.items if row.place_id != place_id)[:3]


RecommendationRunRecord = RecommendationRun | MvpRecommendationRun | PhotoMvpRecommendationRun
ReleaseSnapshotRecord = (
    PublicScoredReleaseSnapshot | MvpScoredRelease | MvpScoredReleaseV2 | MvpScoredReleaseV3
)
RecommendationResultsRecord = RecommendationResultsResponse | MvpRecommendationResultsResponse
RecommendationDetailRecord = RecommendationDetail | MvpRecommendationDetail


def _legacy_snapshot_type() -> type[PublicScoredReleaseSnapshot]:
    from itda.contracts.demo_profile_materialization import PublicScoredReleaseSnapshot

    return PublicScoredReleaseSnapshot


def _is_legacy_snapshot(snapshot: object) -> TypeGuard[PublicScoredReleaseSnapshot]:
    return isinstance(snapshot, _legacy_snapshot_type())


@dataclass(frozen=True)
class PinnedRecommendationRun:
    run: RecommendationRunRecord
    release_snapshot: ReleaseSnapshotRecord
    preference_profile_id: str
    request_id: str


def _validate_request_binding_metadata(
    binding: RecommendationRequestBindingRow,
    run_row: RecommendationRunRow,
) -> None:
    """Reject storage drift before comparing a caller's request with a binding."""

    if binding.preference_profile_id != run_row.preference_profile_id or not hmac.compare_digest(
        binding.input_digest, run_row.input_digest
    ):
        raise RecommendationPinInvalid("request binding metadata drifted from its run")


def _run_metadata(
    run: RecommendationRunRecord,
) -> tuple[str, str, str, str]:
    if isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
        return (
            run.authority.release_sha256,
            run.authority.membership_sha256,
            run.authority.config_sha256,
            run.authority.kernel_version,
        )
    return (
        run.release_sha256,
        run.canonical_membership_sha256,
        run.config_sha256,
        run.kernel_version,
    )


def _snapshot_digest(snapshot: ReleaseSnapshotRecord) -> str:
    return (
        snapshot.release_sha256
        if isinstance(snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3))
        else snapshot.snapshot_sha256
    )


def _run_release_sha256(run: RecommendationRunRecord) -> str:
    if isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
        return run.authority.release_sha256
    return run.release_sha256


def _run_row(
    *,
    request_id: str,
    preference_profile_id: str,
    run: RecommendationRunRecord,
) -> RecommendationRunRow:
    release_sha256, membership_sha256, config_sha256, kernel_version = _run_metadata(run)
    return RecommendationRunRow(
        run_id=run.run_id,
        request_id=request_id,
        preference_profile_id=preference_profile_id,
        input_digest=run.input_digest,
        release_sha256=release_sha256,
        canonical_membership_sha256=membership_sha256,
        config_sha256=config_sha256,
        kernel_version=kernel_version,
        receipt_sha256=run.canonical_sha256,
        receipt=run.model_dump(mode="json"),
        created_at=run.created_at,
    )


def _pin_row(
    *,
    run: RecommendationRunRecord,
    release_snapshot: ReleaseSnapshotRecord,
) -> RecommendationResultPinRow:
    release_sha256, membership_sha256, config_sha256, kernel_version = _run_metadata(run)
    return RecommendationResultPinRow(
        run_id=run.run_id,
        release_sha256=release_sha256,
        canonical_membership_sha256=membership_sha256,
        config_sha256=config_sha256,
        kernel_version=kernel_version,
        receipt_sha256=run.canonical_sha256,
        snapshot_sha256=_snapshot_digest(release_snapshot),
        release_snapshot=release_snapshot.model_dump(mode="json"),
        created_at=run.created_at,
    )


def _validate_pinned_rows(
    run_row: RecommendationRunRow,
    pin_row: RecommendationResultPinRow | None,
) -> PinnedRecommendationRun:
    if pin_row is None:
        raise RecommendationPinInvalid("recommendation result pin is missing")
    try:
        run_payload = run_row.receipt
        schema_version = run_payload.get("schema_version")
        run = (
            PhotoMvpRecommendationRun.model_validate(run_payload)
            if schema_version == "recommendation-run.v3"
            else MvpRecommendationRun.model_validate(run_payload)
            if schema_version == "recommendation-run.v2"
            else RecommendationRun.model_validate(run_payload)
        )
        snapshot_payload = pin_row.release_snapshot
        snapshot: ReleaseSnapshotRecord
        if snapshot_payload.get("schema_version") == "mvp-scored-release.v1":
            snapshot = MvpScoredRelease.model_validate(snapshot_payload)
        elif snapshot_payload.get("schema_version") == "mvp-scored-release.v2":
            snapshot = MvpScoredReleaseV2.model_validate(snapshot_payload)
        elif snapshot_payload.get("schema_version") == "mvp-scored-release.v3":
            snapshot = MvpScoredReleaseV3.model_validate(snapshot_payload)
        else:
            from itda.contracts.demo_profile_materialization import PublicScoredReleaseSnapshot

            snapshot = PublicScoredReleaseSnapshot.model_validate(snapshot_payload)
    except (AttributeError, TypeError, ValueError) as error:
        raise RecommendationPinInvalid("stored recommendation payload is invalid") from error

    release_sha256, membership_sha256, config_sha256, kernel_version = _run_metadata(run)
    run_values = (
        run.run_id,
        run.input_digest,
        release_sha256,
        membership_sha256,
        config_sha256,
        kernel_version,
        run.canonical_sha256,
    )
    row_values = (
        run_row.run_id,
        run_row.input_digest,
        run_row.release_sha256,
        run_row.canonical_membership_sha256,
        run_row.config_sha256,
        run_row.kernel_version,
        run_row.receipt_sha256,
    )
    pin_values = (
        pin_row.run_id,
        pin_row.release_sha256,
        pin_row.canonical_membership_sha256,
        pin_row.config_sha256,
        pin_row.kernel_version,
        pin_row.receipt_sha256,
    )
    expected_pin_values = (
        run.run_id,
        release_sha256,
        membership_sha256,
        config_sha256,
        kernel_version,
        run.canonical_sha256,
    )
    if run_values != row_values or pin_values != expected_pin_values:
        raise RecommendationPinInvalid("recommendation run and pin metadata drifted")
    if (
        not hmac.compare_digest(snapshot.release_sha256, release_sha256)
        or not hmac.compare_digest(snapshot.membership_sha256, membership_sha256)
        or not hmac.compare_digest(_snapshot_digest(snapshot), pin_row.snapshot_sha256)
    ):
        raise RecommendationPinInvalid("pinned release snapshot drifted")
    if isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
        if not isinstance(snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)):
            raise RecommendationPinInvalid("MVP run requires an MVP release snapshot")
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
        if (
            run.authority.relation_sha256 != snapshot.relation_sha256
            or run.authority.candidate_sha256 != candidate_sha256
            or run.candidate_place_ids != tuple(row.place_id for row in snapshot.profiles)
            or run.input_digest
            != canonical_sha256(
                {
                    "preference": run.preference.model_dump(mode="json"),
                    "authority": run.authority.model_dump(mode="json"),
                }
            )
        ):
            raise RecommendationPinInvalid("MVP run authority drifted from the pinned release")
    elif not _is_legacy_snapshot(snapshot):
        raise RecommendationPinInvalid("legacy run requires a legacy release snapshot")
    return PinnedRecommendationRun(
        run=run,
        release_snapshot=snapshot,
        preference_profile_id=run_row.preference_profile_id,
        request_id=run_row.request_id,
    )


class RecommendationRunRepository:
    """Insert/recover complete run+pin pairs and serve only verified pinned reads."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def insert_or_recover(
        self,
        *,
        request_id: str,
        preference_profile_id: str,
        run: RecommendationRunRecord,
        release_snapshot: ReleaseSnapshotRecord,
    ) -> tuple[RecommendationRunRecord, bool]:
        release_sha256, membership_sha256, _, _ = _run_metadata(run)
        if (
            release_sha256 != release_snapshot.release_sha256
            or membership_sha256 != release_snapshot.membership_sha256
        ):
            raise RecommendationPinInvalid("run does not bind the supplied release snapshot")
        snapshot_place_ids = tuple(profile.place_id for profile in release_snapshot.profiles)
        if isinstance(run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            if not isinstance(
                release_snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)
            ):
                raise RecommendationPinInvalid("MVP run requires an MVP release snapshot")
            expected_candidate_digest = canonical_sha256(
                [
                    {
                        "place_id": profile.place_id,
                        "profile_sha256": profile.profile_sha256,
                        "duplicate_group_id": profile.duplicate_group_id,
                    }
                    for profile in release_snapshot.profiles
                ]
            )
            if (
                run.candidate_place_ids != snapshot_place_ids
                or run.authority.candidate_sha256 != expected_candidate_digest
                or run.authority.relation_sha256 != release_snapshot.relation_sha256
            ):
                raise RecommendationPinInvalid(
                    "MVP run authority does not match the pinned release snapshot"
                )
        else:
            if not _is_legacy_snapshot(release_snapshot):
                raise RecommendationPinInvalid("legacy run requires a legacy release snapshot")
            expected_candidate_digest = canonical_sha256(
                [
                    {
                        "place_id": profile.place_id,
                        "profile_sha256": profile.projection_sha256,
                        "duplicate_group_id": profile.duplicate_group_id,
                    }
                    for profile in release_snapshot.profiles
                ]
            )
            if run.candidate_place_ids != snapshot_place_ids or not hmac.compare_digest(
                run.candidate_set_digest, expected_candidate_digest
            ):
                raise RecommendationPinInvalid(
                    "run candidate set does not match the pinned release snapshot"
                )
        with self._factory.begin() as session:
            existing = self._reconcile_request_binding(
                session,
                request_id=request_id,
                preference_profile_id=preference_profile_id,
                input_digest=run.input_digest,
            )
            if existing is not None:
                return existing, True
            try:
                with session.begin_nested():
                    session.add(
                        _run_row(
                            request_id=request_id,
                            preference_profile_id=preference_profile_id,
                            run=run,
                        )
                    )
                    session.flush()
                    session.add(_pin_row(run=run, release_snapshot=release_snapshot))
                    session.flush()
                    session.add(
                        RecommendationRequestBindingRow(
                            request_id=request_id,
                            run_id=run.run_id,
                            preference_profile_id=preference_profile_id,
                            input_digest=run.input_digest,
                            created_at=run.created_at,
                        )
                    )
                    session.flush()
                return run, False
            except IntegrityError:
                bound = self._reconcile_request_binding(
                    session,
                    request_id=request_id,
                    preference_profile_id=preference_profile_id,
                    input_digest=run.input_digest,
                )
                if bound is not None:
                    return bound, True
                existing_run_row = session.scalar(
                    select(RecommendationRunRow).where(
                        (RecommendationRunRow.run_id == run.run_id)
                        | (RecommendationRunRow.receipt_sha256 == run.canonical_sha256)
                    )
                )
                if existing_run_row is None:
                    raise RecommendationPinInvalid(
                        "concurrent recommendation insert could not be reconciled"
                    ) from None
                pin = session.get(RecommendationResultPinRow, existing_run_row.run_id)
                restored = _validate_pinned_rows(existing_run_row, pin)
                if (
                    not hmac.compare_digest(restored.run.input_digest, run.input_digest)
                    or restored.preference_profile_id != preference_profile_id
                ):
                    raise RecommendationRequestConflict(
                        self.code_for_conflict(request_id)
                    ) from None
                try:
                    with session.begin_nested():
                        session.add(
                            RecommendationRequestBindingRow(
                                request_id=request_id,
                                run_id=restored.run.run_id,
                                preference_profile_id=preference_profile_id,
                                input_digest=restored.run.input_digest,
                                created_at=run.created_at,
                            )
                        )
                        session.flush()
                except IntegrityError:
                    bound = self._reconcile_request_binding(
                        session,
                        request_id=request_id,
                        preference_profile_id=preference_profile_id,
                        input_digest=run.input_digest,
                    )
                    if bound is not None:
                        return bound, True
                    raise RecommendationPinInvalid(
                        "concurrent request binding could not be reconciled"
                    ) from None
                return restored.run, True

    @classmethod
    def _reconcile_request_binding(
        cls,
        session: Session,
        *,
        request_id: str,
        preference_profile_id: str,
        input_digest: str,
    ) -> RecommendationRunRecord | None:
        binding = session.get(RecommendationRequestBindingRow, request_id)
        if binding is None:
            return None
        existing = session.get(RecommendationRunRow, binding.run_id)
        if existing is None:
            raise RecommendationPinInvalid("request binding points to a missing run")
        _validate_request_binding_metadata(binding, existing)
        restored = _validate_pinned_rows(
            existing, session.get(RecommendationResultPinRow, existing.run_id)
        )
        if binding.preference_profile_id != preference_profile_id or not hmac.compare_digest(
            binding.input_digest, input_digest
        ):
            raise RecommendationRequestConflict(cls.code_for_conflict(request_id))
        return restored.run

    @staticmethod
    def code_for_conflict(request_id: str) -> str:
        return f"RECOMMENDATION_REQUEST_CONFLICT:{request_id}"

    def load_pinned(self, run_id: str) -> PinnedRecommendationRun:
        with self._factory() as session:
            run_row = session.get(RecommendationRunRow, run_id)
            if run_row is None:
                raise RecommendationRunNotFound(run_id)
            pin_row = session.get(RecommendationResultPinRow, run_id)
            return _validate_pinned_rows(run_row, pin_row)

    def recover_by_request_id(
        self,
        *,
        request_id: str,
        preference_profile_id: str,
        input_digest: str,
    ) -> RecommendationRunRecord | None:
        """Recover before kernel execution or reject a permanently rebound request."""

        with self._factory() as session:
            binding = session.get(RecommendationRequestBindingRow, request_id)
            if binding is None:
                return None
            run_row = session.get(RecommendationRunRow, binding.run_id)
            if run_row is None:
                raise RecommendationPinInvalid("request binding points to a missing run")
            _validate_request_binding_metadata(binding, run_row)
            pin_row = session.get(RecommendationResultPinRow, run_row.run_id)
            restored = _validate_pinned_rows(run_row, pin_row)
            if restored.preference_profile_id != preference_profile_id or not hmac.compare_digest(
                restored.run.input_digest, input_digest
            ):
                raise RecommendationRequestConflict(self.code_for_conflict(request_id))
            return restored.run

    def recover_bound_request(
        self, *, request_id: str, preference_profile_id: str
    ) -> RecommendationRunRecord | None:
        """Recover an immutable request binding without consulting the active pointer."""

        with self._factory() as session:
            binding = session.get(RecommendationRequestBindingRow, request_id)
            if binding is None:
                return None
            run_row = session.get(RecommendationRunRow, binding.run_id)
            if run_row is None:
                raise RecommendationPinInvalid("request binding points to a missing run")
            _validate_request_binding_metadata(binding, run_row)
            if binding.preference_profile_id != preference_profile_id:
                raise RecommendationRequestConflict(self.code_for_conflict(request_id))
            return _validate_pinned_rows(
                run_row, session.get(RecommendationResultPinRow, binding.run_id)
            ).run

    def load_run(self, run_id: str) -> RecommendationRunRecord:
        return self.load_pinned(run_id).run

    def load_results(self, run_id: str) -> RecommendationResultsRecord:
        pinned = self.load_pinned(run_id)
        if isinstance(pinned.run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            if not isinstance(
                pinned.release_snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)
            ):
                raise RecommendationPinInvalid("MVP run requires an MVP release snapshot")
            source_bundle_sha256 = canonical_sha256(
                [
                    {
                        "place_id": row.place_id,
                        "scoring_result_sha256": row.scoring_result.result_sha256,
                    }
                    for row in pinned.release_snapshot.profiles
                ]
            )
            return MvpRecommendationResultsResponse(
                preference_profile_id=pinned.preference_profile_id,
                analysis_origin="GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
                operating_states=cast(
                    tuple[
                        RecommendationOperatingState,
                        RecommendationOperatingState,
                        RecommendationOperatingState,
                        RecommendationOperatingState,
                        RecommendationOperatingState,
                    ],
                    tuple(
                        RecommendationOperatingState(
                            place_id=item.place_id,
                            state="OPERATING_INFORMATION_UNVERIFIED",
                        )
                        for item in pinned.run.items
                    ),
                ),
                release_disclosure=MvpRecommendationReleaseDisclosure(
                    analysis_origin="GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
                    model="glm-5.3-flash",
                    prompt_schema_version="mvp-place-scoring-request.v2",
                    profile_schema_version=pinned.release_snapshot.schema_version,
                    config_sha256=pinned.run.authority.config_sha256,
                    source_bundle_sha256=source_bundle_sha256,
                    release_sha256=pinned.run.authority.release_sha256,
                    reference_date=max(item.reference_date for item in pinned.run.items),
                ),
                run=pinned.run,
            )
        if not _is_legacy_snapshot(pinned.release_snapshot):
            raise RecommendationPinInvalid("legacy run requires a legacy release snapshot")
        profile_schema_version: Literal[
            "itda.demo-model-derived-profile.v1",
            "itda.nvidia-minimax-model-derived-profile.v4",
            "itda.nvidia-minimax-model-derived-profile.v5",
        ] = (
            "itda.demo-model-derived-profile.v1"
            if pinned.release_snapshot.model == "glm-5v-turbo"
            else (
                "itda.nvidia-minimax-model-derived-profile.v5"
                if pinned.release_snapshot.schema_version
                == "itda.public-scored-release-snapshot.v5"
                else "itda.nvidia-minimax-model-derived-profile.v4"
            )
        )
        source_bundle_sha256 = canonical_sha256(
            [
                {
                    "place_id": profile.place_id,
                    "source_bundle_sha256": profile.source_bundle_sha256,
                }
                for profile in pinned.release_snapshot.profiles
            ]
        )
        return RecommendationResultsResponse(
            preference_profile_id=pinned.preference_profile_id,
            analysis_origin=pinned.release_snapshot.analysis_origin,
            operating_states=cast(
                tuple[
                    RecommendationOperatingState,
                    RecommendationOperatingState,
                    RecommendationOperatingState,
                    RecommendationOperatingState,
                    RecommendationOperatingState,
                ],
                tuple(
                    RecommendationOperatingState(
                        place_id=item.place_id,
                        state="OPERATING_INFORMATION_UNVERIFIED",
                    )
                    for item in pinned.run.items
                ),
            ),
            release_disclosure=RecommendationReleaseDisclosure(
                analysis_origin=pinned.release_snapshot.analysis_origin,
                model=pinned.release_snapshot.model,
                prompt_schema_version=pinned.release_snapshot.prompt_version,
                profile_schema_version=profile_schema_version,
                config_sha256=pinned.run.config_sha256,
                source_bundle_sha256=source_bundle_sha256,
                release_sha256=_run_release_sha256(pinned.run),
                reference_date=max(item.reference_date for item in pinned.run.items),
            ),
            run=pinned.run,
        )

    def load_release_snapshot(self, release_sha256: str) -> ReleaseSnapshotRecord | None:
        with self._factory() as session:
            pin = session.scalar(
                select(RecommendationResultPinRow)
                .where(RecommendationResultPinRow.release_sha256 == release_sha256)
                .order_by(RecommendationResultPinRow.created_at, RecommendationResultPinRow.run_id)
                .limit(1)
            )
            if pin is None:
                return None
            run_row = session.get(RecommendationRunRow, pin.run_id)
            if run_row is None:
                raise RecommendationPinInvalid("pinned run is missing")
            return _validate_pinned_rows(run_row, pin).release_snapshot

    def load_detail(self, run_id: str, place_id: str) -> RecommendationDetailRecord:
        pinned = self.load_pinned(run_id)
        if isinstance(pinned.run, (MvpRecommendationRun, PhotoMvpRecommendationRun)):
            if not isinstance(
                pinned.release_snapshot, (MvpScoredRelease, MvpScoredReleaseV2, MvpScoredReleaseV3)
            ):
                raise RecommendationPinInvalid("MVP run requires an MVP release snapshot")
            mvp_item = next(
                (row for row in pinned.run.items if row.place_id == place_id),
                None,
            )
            mvp_profile = next(
                (row for row in pinned.release_snapshot.profiles if row.place_id == place_id),
                None,
            )
            if mvp_item is None or mvp_profile is None:
                raise RecommendationPlaceUnavailable(place_id)
            mvp_traits = _detail_traits(mvp_profile)
            mvp_evidence = tuple(
                MvpEvidenceSnippet(
                    evidence_id=source.evidence_id,
                    excerpt_ko=source.excerpt_ko,
                    source_label_ko=source.source_label_ko,
                    attribution_ko=source.attribution_ko,
                    reference_date=source.reference_date,
                    provider=source.evidence.provider,
                    official_dataset_id=source.evidence.official_dataset_id,
                    official_license_url=source.evidence.official_license_url,
                    license_type=source.evidence.license_type,
                    source_response_sha256=source.evidence.source_response_sha256,
                    permission_metadata_sha256=(
                        source.evidence.permission_metadata.metadata_sha256
                    ),
                    evidence_sha256=source.evidence.evidence_sha256,
                    usage_state="STRICT_PUBLIC_USAGE_ALLOWED",
                )
                for source in mvp_profile.evidence_excerpts
            )
            confidence_percent = _profile_confidence(mvp_profile)
            confidence_state, confidence_reason = mvp_confidence_state_for(confidence_percent)
            _validate_detail_confidence(mvp_item, confidence_state, confidence_reason)
            return MvpRecommendationDetail(
                run_id=pinned.run.run_id,
                release_sha256=pinned.run.authority.release_sha256,
                confidence_percent=confidence_percent,
                evidence_confidence_state=confidence_state,
                evidence_confidence_reason_ko=confidence_reason,
                item=mvp_item,
                mismatch_traits=mvp_traits,
                evidence=mvp_evidence,
                operating_state="OPERATING_INFORMATION_UNVERIFIED",
                similar_place_ids=_similar_place_ids(pinned.run, place_id),
            )

        if not _is_legacy_snapshot(pinned.release_snapshot):
            raise RecommendationPinInvalid("legacy run requires a legacy release snapshot")
        legacy_item = next(
            (row for row in pinned.run.items if row.place_id == place_id),
            None,
        )
        legacy_profile = next(
            (row for row in pinned.release_snapshot.profiles if row.place_id == place_id),
            None,
        )
        if legacy_item is None or legacy_profile is None:
            raise RecommendationPlaceUnavailable(place_id)
        legacy_traits = _detail_traits(legacy_profile)
        legacy_evidence = tuple(
            EvidenceSnippet(
                evidence_id=source.evidence_id,
                excerpt_ko=source.excerpt_ko,
                source_label_ko=source.source_label_ko,
                attribution_ko=source.attribution_ko,
                contest_use_scope=source.contest_use_scope,
                contest_rights_qualified=source.contest_rights_qualified,
                reference_date=legacy_item.reference_date,
            )
            for source in legacy_profile.evidence_excerpts
        )
        confidence_percent = _profile_confidence(legacy_profile)
        confidence_state, confidence_reason = confidence_state_for(confidence_percent)
        _validate_detail_confidence(legacy_item, confidence_state, confidence_reason)
        return RecommendationDetail(
            run_id=pinned.run.run_id,
            release_sha256=pinned.run.release_sha256,
            confidence_percent=confidence_percent,
            evidence_confidence_state=confidence_state,
            evidence_confidence_reason_ko=confidence_reason,
            item=legacy_item,
            mismatch_traits=legacy_traits,
            evidence=legacy_evidence,
            operating_state="OPERATING_INFORMATION_UNVERIFIED",
            similar_place_ids=_similar_place_ids(pinned.run, place_id),
        )

    def load_comparison(
        self,
        run_id: str,
        place_ids: tuple[str, ...],
    ) -> RecommendationComparisonResponse:
        if len(place_ids) not in (2, 3) or len(set(place_ids)) != len(place_ids):
            raise RecommendationPlaceUnavailable("comparison requires two or three unique places")
        pinned = self.load_pinned(run_id)
        items = {item.place_id: item for item in pinned.run.items}
        if any(place_id not in items for place_id in place_ids):
            raise RecommendationPlaceUnavailable("comparison place is outside the pinned run")

        profiles = {
            profile.place_id: profile
            for profile in pinned.release_snapshot.profiles
            if profile.place_id in place_ids
        }
        if set(profiles) != set(place_ids):
            raise RecommendationPlaceUnavailable("comparison profile is outside the pinned release")

        def values_for(axis: ExperienceAxis) -> tuple[str, ...]:
            return tuple(
                f"{next(row.value for row in items[place_id].axis_scores if row.axis is axis)}점"
                " / 100점"
                for place_id in place_ids
            )

        def mismatch_value(place_id: str) -> str:
            mismatch = items[place_id].mismatch
            if mismatch.state.value == "SUPPRESSED_LOW_CONFIDENCE":
                return "근거가 충분하지 않아 기대 차이 안내를 생략했어요."
            if mismatch.state.value == "NO_GUIDANCE":
                return "이번 여행의 기대와 크게 다르지 않아요."
            if mismatch.message_ko is None:
                raise RecommendationPinInvalid("visible mismatch guidance is missing")
            return mismatch.message_ko

        def media_value(place_id: str) -> str:
            values = {
                "ABSENT": "대표 이미지 없음",
                "RIGHTS_RESTRICTED": "이미지 표시 제한",
                "DISPLAY_ASSET_AVAILABLE": "검증된 대표 이미지",
            }
            return values[items[place_id].image_state.value]

        none_reasons = tuple(None for _ in place_ids)
        rows = [
            ComparisonRow(
                row_id="fit-score",
                label_ko="추천 적합도",
                values_ko=tuple(f"{items[place_id].fit_score}점 / 100점" for place_id in place_ids),
                missing_reasons=none_reasons,
            )
        ]
        labels = {
            ExperienceAxis.HISTORY_TRADITION: "역사·전통",
            ExperienceAxis.EMOTION_IMAGE: "감성·이미지",
            ExperienceAxis.REST_IMMERSION: "휴식·몰입",
        }
        rows.extend(
            ComparisonRow(
                row_id=f"axis-{axis.value.lower()}",
                label_ko=labels[axis],
                values_ko=values_for(axis),
                missing_reasons=none_reasons,
            )
            for axis in ExperienceAxis
        )
        for index in range(2):
            rows.append(
                ComparisonRow(
                    row_id=f"evidence-reason-{index + 1}",
                    label_ko=f"잘 맞는 이유 {index + 1}",
                    values_ko=tuple(
                        items[place_id].explanations[index].message_ko for place_id in place_ids
                    ),
                    missing_reasons=none_reasons,
                )
            )
        rows.append(
            ComparisonRow(
                row_id="mismatch-guidance",
                label_ko="이번 여행에서 기대한 것과 다른 점",
                values_ko=tuple(mismatch_value(place_id) for place_id in place_ids),
                missing_reasons=none_reasons,
            )
        )
        trait_labels = {
            "M1": "공간 성격",
            "M2": "방문객 성격",
            "M3": "현장 밀도",
            "M4": "경험 방식",
            "M5": "체류 방식",
            "M6": "시간 의존성",
        }
        for trait in MismatchTraitId:
            rows.append(
                ComparisonRow(
                    row_id=f"trait-{trait.value.lower()}",
                    label_ko=trait_labels[trait.value],
                    values_ko=tuple(
                        f"{_profile_trait_value(profiles[place_id], trait)}점 / 100점"
                        for place_id in place_ids
                    ),
                    missing_reasons=none_reasons,
                )
            )
        rows.append(
            ComparisonRow(
                row_id="time-season-context",
                label_ko="시간·계절 맥락",
                values_ko=tuple(
                    "저장된 시간 의존성은 "
                    f"{_profile_trait_value(profiles[place_id], MismatchTraitId.M6)}점"
                    " / 100점이에요. "
                    "야간·계절·특정 시간의 영향 가능성을 뜻해요."
                    for place_id in place_ids
                ),
                missing_reasons=none_reasons,
            )
        )
        rows.append(
            ComparisonRow(
                row_id="operating-state",
                label_ko="운영 정보",
                values_ko=tuple("정보 없음" for _ in place_ids),
                missing_reasons=tuple("OPERATING_INFORMATION_UNVERIFIED" for _ in place_ids),
            )
        )
        rows.extend(
            [
                ComparisonRow(
                    row_id="media-state",
                    label_ko="대표 이미지 상태",
                    values_ko=tuple(media_value(place_id) for place_id in place_ids),
                    missing_reasons=none_reasons,
                ),
                ComparisonRow(
                    row_id="reference-date",
                    label_ko="데이터 기준일",
                    values_ko=tuple(
                        items[place_id].reference_date.isoformat() for place_id in place_ids
                    ),
                    missing_reasons=none_reasons,
                ),
            ]
        )
        return RecommendationComparisonResponse(
            run_id=pinned.run.run_id,
            release_sha256=_run_release_sha256(pinned.run),
            place_ids=place_ids,
            rows=tuple(rows),
        )

    def resolve_saved_place_reference(
        self,
        *,
        release_sha256: str,
        place_id: str,
        current_release_sha256: str | None,
    ) -> SavedPlaceProjection:
        snapshot = self.load_release_snapshot(release_sha256)
        profile = (
            next(
                (row for row in snapshot.profiles if row.place_id == place_id),
                None,
            )
            if snapshot is not None
            else None
        )
        if profile is None:
            return SavedPlaceProjection(
                place_id=place_id,
                place_name_ko="저장된 장소",
                saved_release_sha256=release_sha256,
                resolved_release_sha256=None,
                state=SavedPlaceState.UNAVAILABLE,
                state_reason="SAVED_RELEASE_OR_PLACE_UNAVAILABLE",
            )
        if current_release_sha256 == release_sha256:
            return SavedPlaceProjection(
                place_id=place_id,
                place_name_ko=profile.place_name_ko,
                saved_release_sha256=release_sha256,
                resolved_release_sha256=release_sha256,
                state=SavedPlaceState.CURRENT,
                state_reason=None,
            )
        return SavedPlaceProjection(
            place_id=place_id,
            place_name_ko=profile.place_name_ko,
            saved_release_sha256=release_sha256,
            resolved_release_sha256=release_sha256,
            state=SavedPlaceState.STALE,
            state_reason="SAVED_RELEASE_IS_NOT_ACTIVE",
        )


__all__ = [
    "PinnedRecommendationRun",
    "RecommendationPinInvalid",
    "RecommendationPlaceUnavailable",
    "RecommendationRequestConflict",
    "RecommendationRunNotFound",
    "RecommendationRunRepository",
]
