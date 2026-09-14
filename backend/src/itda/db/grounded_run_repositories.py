"""Compact v5 run pins with full source-bound offline replay verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Self

from pydantic import model_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_responses import (
    GroundedComparisonResponse,
    GroundedDetailResponse,
    GroundedReleaseDisclosure,
    GroundedResultsResponse,
)
from itda.contracts.grounded_run import GroundedRecommendationRun
from itda.contracts.place_enrichment import CampingContext
from itda.contracts.recommendation import (
    RecommendationRequest,
    SavedPlaceProjection,
    SavedPlaceState,
)
from itda.contracts.visual_mood import ConfirmedMoodProjection
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.models import (
    PreferenceProfileRow,
    RecommendationRequestBindingRow,
    RecommendationResultPinRow,
    RecommendationRunRow,
)
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    RecommendationPlaceUnavailable,
    RecommendationRequestConflict,
    RecommendationRunNotFound,
    _validate_request_binding_metadata,
)
from itda.db.repositories import _row_to_profile
from itda.db.source_snapshot_repositories import SourceSnapshotRepository
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_recommendation import rank_grounded
from itda.tourism.accessibility import AccessibilitySnapshot
from itda.tourism.temporal_cache import TemporalSourceSnapshot

GROUNDED_RUN_SCHEMA = "itda.grounded-recommendation-run.v1"


class GroundedResultReference(StrictContract):
    schema_version: Literal["grounded-result-reference.v1"] = "grounded-result-reference.v1"
    candidate_sha256: Sha256
    contextual_snapshot_sha256: tuple[Sha256, ...]
    confirmed_mood: ConfirmedMoodProjection | None
    reference_sha256: Sha256

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.contextual_snapshot_sha256 != tuple(sorted(set(self.contextual_snapshot_sha256))):
            raise ValueError("context source references must be canonical")
        if self.reference_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"reference_sha256"})
        ):
            raise ValueError("grounded result reference hash differs")
        return self


@dataclass(frozen=True)
class PinnedGroundedRun:
    run: GroundedRecommendationRun
    candidate: GroundedReleaseCandidate
    request_id: str
    preference_profile_id: str
    contextual_snapshots: tuple[dict[str, Any], ...]
    confirmed_mood: ConfirmedMoodProjection | None


def _reference(candidate, contextual_snapshot_sha256, confirmed_mood) -> GroundedResultReference:
    payload = {
        "schema_version": "grounded-result-reference.v1",
        "candidate_sha256": candidate.candidate_sha256,
        "contextual_snapshot_sha256": list(contextual_snapshot_sha256),
        "confirmed_mood": confirmed_mood.model_dump(mode="json") if confirmed_mood else None,
    }
    return GroundedResultReference.model_validate(
        payload | {"reference_sha256": canonical_sha256(payload)}
    )


def _context_payloads(
    session: Session, digests: tuple[str, ...], candidate: GroundedReleaseCandidate
) -> tuple[dict[str, Any], ...]:
    ids = {p.place_id for p in candidate.raw_release.profiles}
    validated: dict[str, dict[str, Any]] = {}
    visiting: set[str] = set()

    def resolve(digest: str) -> dict[str, Any]:
        if digest in validated:
            return validated[digest]
        if digest in visiting:
            raise RecommendationPinInvalid("context source reference cycle")
        visiting.add(digest)
        payload = SourceSnapshotRepository._get(session, "source", digest)
        if payload is None:
            raise RecommendationPinInvalid("required contextual source snapshot missing")
        schema = payload.get("schema_version")
        value: AccessibilitySnapshot | TemporalSourceSnapshot | CampingContext
        if schema == "accessibility-snapshot.v1":
            value = AccessibilitySnapshot.model_validate(payload)
            if value.place_id not in ids:
                raise RecommendationPinInvalid("context belongs to another candidate place")
        elif schema == "temporal-source-snapshot.v1":
            value = TemporalSourceSnapshot.model_validate(payload)
        elif schema == "camping-context.v1":
            value = CampingContext.model_validate(payload)
            if value.place_id not in ids:
                raise RecommendationPinInvalid("camp context belongs to another place")
            child_receipts = []
            for child in value.source_snapshot_sha256:
                child_payload = resolve(child)
                child_receipts.extend(child_payload.get("receipts", []))
            if any(
                receipt.model_dump(mode="json") not in child_receipts for receipt in value.receipts
            ):
                raise RecommendationPinInvalid(
                    "camp context receipt is not pinned to actual source bytes"
                )
        else:
            raise RecommendationPinInvalid("unknown contextual source schema")
        normalized = value.model_dump(mode="json")
        if canonical_sha256(normalized) != digest:
            raise RecommendationPinInvalid("context schema normalization changes pinned bytes")
        visiting.remove(digest)
        validated[digest] = normalized
        return normalized

    return tuple(resolve(digest) for digest in digests)


def _verify_run(
    session: Session,
    run: GroundedRecommendationRun,
    candidate: GroundedReleaseCandidate,
    reference: GroundedResultReference,
    profile_id: str,
    request_id: str,
) -> tuple[dict[str, Any], ...]:
    from itda.application.grounded_context import build_candidates, build_grounded_preference

    if (
        run.preference.profile_id != profile_id
        or reference.candidate_sha256 != candidate.candidate_sha256
        or run.authority.candidate_sha256 != candidate.candidate_sha256
        or run.authority.release_sha256 != candidate.raw_release.release_sha256
        or run.authority.membership_sha256 != candidate.raw_release.membership_sha256
        or run.authority.source_release_sha256 != candidate.manifest.source_release_sha256
        or run.authority.assessment_manifest_sha256 != candidate.manifest.manifest_sha256
        or run.authority.relation_sha256 != candidate.raw_release.relation_sha256
        or run.authority.contextual_snapshot_sha256 != reference.contextual_snapshot_sha256
    ):
        raise RecommendationPinInvalid("grounded run and candidate/reference authority differ")
    if run.candidate_place_ids != tuple(p.place_id for p in candidate.raw_release.profiles):
        raise RecommendationPinInvalid("grounded run does not cover the complete candidate pair")
    for binding, assessment in zip(run.candidate_bindings, candidate.assessments, strict=True):
        if (
            binding.place_id != assessment.place_id
            or binding.raw_profile_sha256 != assessment.raw_profile_sha256
            or binding.assessment_bundle_sha256 != assessment.bundle_sha256
        ):
            raise RecommendationPinInvalid("candidate assessment membership differs")
    confirmed = reference.confirmed_mood
    if confirmed is not None and confirmed.preference_profile_id != profile_id:
        raise RecommendationPinInvalid("confirmed appearance belongs to another user profile")
    profile_row = session.get(PreferenceProfileRow, profile_id)
    if profile_row is None:
        raise RecommendationPinInvalid("pinned preference profile missing")
    profile = _row_to_profile(profile_row)
    request = RecommendationRequest.model_validate(
        {
            "request_id": request_id,
            "preference_profile_id": profile_id,
            "purpose": run.preference.purpose,
            "grounded_input": run.preference.trip_input.model_dump(mode="json"),
            "photo_job_id": confirmed.job_id if confirmed is not None else None,
        }
    )
    expected_preference = build_grounded_preference(profile, request, confirmed)
    if expected_preference != run.preference:
        raise RecommendationPinInvalid(
            "grounded preference differs from stored questionnaire or confirmation"
        )
    contexts = _context_payloads(session, reference.contextual_snapshot_sha256, candidate)
    candidates = build_candidates(candidate, contexts, run.preference, user_profile=profile)
    replayed = rank_grounded(
        candidates=candidates,
        preference=expected_preference,
        candidate_sha256=candidate.candidate_sha256,
        release_sha256=candidate.raw_release.release_sha256,
        source_release_sha256=candidate.manifest.source_release_sha256,
        assessment_manifest_sha256=candidate.manifest.manifest_sha256,
        membership_sha256=candidate.raw_release.membership_sha256,
        relation_sha256=candidate.raw_release.relation_sha256,
        forbidden_pairs=candidate.raw_release.relation_pairs,
        contextual_snapshot_sha256=reference.contextual_snapshot_sha256,
        created_at=run.created_at,
    )
    if replayed != run:
        raise RecommendationPinInvalid(
            "grounded receipt differs from exact source-backed kernel replay"
        )
    return contexts


class GroundedRunRepository:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def lookup_schema_for_request(self, request_id: str) -> str | None:
        with self._factory() as session:
            binding = session.get(RecommendationRequestBindingRow, request_id)
            if binding is None:
                return None
            row = session.get(RecommendationRunRow, binding.run_id)
            if row is None:
                raise RecommendationPinInvalid("request alias points to a missing run")
            _validate_request_binding_metadata(binding, row)
            schema = row.receipt.get("schema_version")
            if not isinstance(schema, str) or not schema:
                raise RecommendationPinInvalid("stored run has no schema discriminator")
            return schema

    def lookup_schema_for_run(self, run_id: str) -> str | None:
        with self._factory() as session:
            row = session.get(RecommendationRunRow, run_id)
            if row is None:
                return None
            schema = row.receipt.get("schema_version")
            if not isinstance(schema, str) or not schema:
                raise RecommendationPinInvalid("stored run has no schema discriminator")
            return schema

    @staticmethod
    def _load(session: Session, run_id: str) -> PinnedGroundedRun:
        row = session.get(RecommendationRunRow, run_id)
        if row is None:
            raise RecommendationRunNotFound(run_id)
        pin = session.get(RecommendationResultPinRow, run_id)
        if pin is None:
            raise RecommendationPinInvalid("grounded result reference missing")
        try:
            run = GroundedRecommendationRun.model_validate(row.receipt)
            reference = GroundedResultReference.model_validate(pin.release_snapshot)
            expected = (
                run.run_id,
                run.authority.release_sha256,
                run.authority.membership_sha256,
                run.authority.config_sha256,
                run.authority.kernel_version,
                run.canonical_sha256,
            )
            if expected != (
                row.run_id,
                row.release_sha256,
                row.canonical_membership_sha256,
                row.config_sha256,
                row.kernel_version,
                row.receipt_sha256,
            ):
                raise RecommendationPinInvalid("grounded run metadata differs")
            if expected != (
                pin.run_id,
                pin.release_sha256,
                pin.canonical_membership_sha256,
                pin.config_sha256,
                pin.kernel_version,
                pin.receipt_sha256,
            ):
                raise RecommendationPinInvalid("grounded pin metadata differs")
            if (
                row.input_digest != run.input_digest
                or pin.snapshot_sha256 != reference.reference_sha256
                or row.created_at != run.created_at
                or pin.created_at != run.created_at
            ):
                raise RecommendationPinInvalid(
                    "grounded input, timestamp or reference digest differs"
                )
            candidate = AssessmentReleaseRepository._candidate(session, reference.candidate_sha256)
            if candidate is None:
                raise RecommendationPinInvalid("staged candidate referenced by run is missing")
            contexts = _verify_run(
                session, run, candidate, reference, row.preference_profile_id, row.request_id
            )
            return PinnedGroundedRun(
                run,
                candidate,
                row.request_id,
                row.preference_profile_id,
                contexts,
                reference.confirmed_mood,
            )
        except (TypeError, ValueError, RuntimeError) as error:
            if isinstance(error, RecommendationPinInvalid):
                raise
            raise RecommendationPinInvalid("grounded source pin failed validation") from error

    @classmethod
    def _recover(
        cls, session: Session, request_id: str, profile_id: str, input_digest: str
    ) -> PinnedGroundedRun | None:
        alias = session.get(RecommendationRequestBindingRow, request_id)
        if alias is None:
            return None
        row = session.get(RecommendationRunRow, alias.run_id)
        if row is None:
            raise RecommendationPinInvalid("grounded request alias is orphaned")
        _validate_request_binding_metadata(alias, row)
        if alias.preference_profile_id != profile_id or alias.input_digest != input_digest:
            raise RecommendationRequestConflict("RECOMMENDATION_REQUEST_CONFLICT:" + request_id)
        return cls._load(session, alias.run_id)

    def insert_or_recover(
        self,
        *,
        request_id: str,
        preference_profile_id: str,
        run: GroundedRecommendationRun,
        candidate: GroundedReleaseCandidate,
        contextual_snapshot_sha256: tuple[str, ...] = (),
        confirmed_mood: ConfirmedMoodProjection | None = None,
    ) -> tuple[GroundedRecommendationRun, bool]:
        run = GroundedRecommendationRun.model_validate_json(run.model_dump_json())
        candidate = GroundedReleaseCandidate.model_validate_json(candidate.model_dump_json())
        reference = _reference(candidate, contextual_snapshot_sha256, confirmed_mood)
        with self._factory.begin() as session:
            stored_candidate = AssessmentReleaseRepository._candidate(
                session, candidate.candidate_sha256
            )
            if stored_candidate is None or stored_candidate != candidate:
                raise RecommendationPinInvalid(
                    "complete candidate must be staged before creating a run"
                )
            _verify_run(session, run, candidate, reference, preference_profile_id, request_id)
            recovered = self._recover(session, request_id, preference_profile_id, run.input_digest)
            if recovered:
                return recovered.run, True
            # Serialize deterministic-run aliases, then recheck the request after
            # acquiring the lock; all three immutable rows commit together.
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                {"key": "grounded-run|" + run.run_id},
            )
            recovered = self._recover(session, request_id, preference_profile_id, run.input_digest)
            if recovered:
                return recovered.run, True
            existing = session.get(RecommendationRunRow, run.run_id)
            if existing is not None:
                pinned = self._load(session, run.run_id)
                if (
                    pinned.preference_profile_id != preference_profile_id
                    or pinned.run.input_digest != run.input_digest
                    or pinned.candidate.candidate_sha256 != candidate.candidate_sha256
                    or pinned.confirmed_mood != confirmed_mood
                ):
                    raise RecommendationRequestConflict(
                        "RECOMMENDATION_REQUEST_CONFLICT:" + request_id
                    )
                try:
                    with session.begin_nested():
                        session.add(
                            RecommendationRequestBindingRow(
                                request_id=request_id,
                                run_id=run.run_id,
                                preference_profile_id=preference_profile_id,
                                input_digest=run.input_digest,
                                created_at=pinned.run.created_at,
                            )
                        )
                        session.flush()
                except IntegrityError:
                    recovered = self._recover(
                        session, request_id, preference_profile_id, run.input_digest
                    )
                    if recovered:
                        return recovered.run, True
                    raise RecommendationPinInvalid(
                        "concurrent grounded request alias could not reconcile"
                    ) from None
                return pinned.run, True
            authority = run.authority
            try:
                with session.begin_nested():
                    session.add(
                        RecommendationRunRow(
                            run_id=run.run_id,
                            request_id=request_id,
                            preference_profile_id=preference_profile_id,
                            input_digest=run.input_digest,
                            release_sha256=authority.release_sha256,
                            canonical_membership_sha256=authority.membership_sha256,
                            config_sha256=authority.config_sha256,
                            kernel_version=authority.kernel_version,
                            receipt_sha256=run.canonical_sha256,
                            receipt=run.model_dump(mode="json"),
                            created_at=run.created_at,
                        )
                    )
                    session.flush()
                    session.add(
                        RecommendationResultPinRow(
                            run_id=run.run_id,
                            release_sha256=authority.release_sha256,
                            canonical_membership_sha256=authority.membership_sha256,
                            config_sha256=authority.config_sha256,
                            kernel_version=authority.kernel_version,
                            receipt_sha256=run.canonical_sha256,
                            snapshot_sha256=reference.reference_sha256,
                            release_snapshot=reference.model_dump(mode="json"),
                            created_at=run.created_at,
                        )
                    )
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
                recovered = self._recover(
                    session, request_id, preference_profile_id, run.input_digest
                )
                if recovered:
                    return recovered.run, True
                raise RecommendationPinInvalid(
                    "grounded concurrent insertion could not reconcile"
                ) from None

    def recover_bound_request(
        self, *, request_id: str, preference_profile_id: str
    ) -> GroundedRecommendationRun | None:
        with self._factory() as session:
            alias = session.get(RecommendationRequestBindingRow, request_id)
            if alias is None:
                return None
            if alias.preference_profile_id != preference_profile_id:
                raise RecommendationRequestConflict("RECOMMENDATION_REQUEST_CONFLICT:" + request_id)
            row = session.get(RecommendationRunRow, alias.run_id)
            if row is None:
                raise RecommendationPinInvalid("grounded request alias is orphaned")
            _validate_request_binding_metadata(alias, row)
            return self._load(session, alias.run_id).run

    def load_pinned(self, run_id: str) -> PinnedGroundedRun:
        with self._factory() as session:
            return self._load(session, run_id)

    def load_run(self, run_id: str) -> GroundedRecommendationRun:
        return self.load_pinned(run_id).run

    def load_results(self, run_id: str) -> GroundedResultsResponse:
        pinned = self.load_pinned(run_id)
        candidate = pinned.candidate
        return GroundedResultsResponse(
            preference_profile_id=pinned.preference_profile_id,
            run=pinned.run,
            release_disclosure=GroundedReleaseDisclosure(
                raw_release_sha256=candidate.raw_release.release_sha256,
                source_release_sha256=candidate.manifest.source_release_sha256,
                assessment_manifest_sha256=candidate.manifest.manifest_sha256,
                candidate_sha256=candidate.candidate_sha256,
                config_sha256=pinned.run.authority.config_sha256,
            ),
        )

    @staticmethod
    def _detail(pinned: PinnedGroundedRun, place_id: str) -> GroundedDetailResponse:
        item = next((i for i in pinned.run.items if i.place_id == place_id), None)
        if item is None:
            raise RecommendationPlaceUnavailable("place is outside the saved grounded result")
        assessment = next(a for a in pinned.candidate.assessments if a.place_id == place_id)
        mood = next(m for m in pinned.candidate.moods if m.place_id == place_id)
        return GroundedDetailResponse(
            recommendation_run_id=pinned.run.run_id,
            release_sha256=pinned.candidate.candidate_sha256,
            item=item,
            assessment=assessment,
            mood=mood,
        )

    def load_detail(self, run_id: str, place_id: str) -> GroundedDetailResponse:
        return self._detail(self.load_pinned(run_id), place_id)

    def load_comparison(
        self, run_id: str, place_ids: tuple[str, ...]
    ) -> GroundedComparisonResponse:
        if not 2 <= len(place_ids) <= 3 or len(set(place_ids)) != len(place_ids):
            raise RecommendationPlaceUnavailable(
                "compare requires two or three different result places"
            )
        pinned = self.load_pinned(run_id)
        return GroundedComparisonResponse(
            recommendation_run_id=run_id,
            release_sha256=pinned.candidate.candidate_sha256,
            places=tuple(self._detail(pinned, pid) for pid in place_ids),
        )

    def resolve_saved_place_reference(
        self, *, candidate_sha256: str, place_id: str, current_candidate_sha256: str | None
    ) -> SavedPlaceProjection:
        candidate = AssessmentReleaseRepository(self._factory).load_candidate(candidate_sha256)
        place = (
            next((p for p in candidate.raw_release.profiles if p.place_id == place_id), None)
            if candidate
            else None
        )
        source_place = (
            next(
                (
                    source["place"]
                    for source in candidate.source_snapshots
                    if source["place"]["place_id"] == place_id
                ),
                None,
            )
            if candidate and place
            else None
        )
        location = source_place if source_place and source_place.get("region_name") else {}
        return SavedPlaceProjection(
            region_code=location.get("region_code"),
            region_name=location.get("region_name"),
            address_ko=location.get("address") or None,
            place_id=place_id,
            place_name_ko=place.place_name_ko if place else "저장된 장소",
            saved_release_sha256=candidate_sha256,
            resolved_release_sha256=candidate_sha256 if place else None,
            state=SavedPlaceState.UNAVAILABLE
            if place is None
            else SavedPlaceState.CURRENT
            if candidate_sha256 == current_candidate_sha256
            else SavedPlaceState.STALE,
            state_reason="SAVED_RELEASE_OR_PLACE_UNAVAILABLE"
            if place is None
            else None
            if candidate_sha256 == current_candidate_sha256
            else "SAVED_RELEASE_IS_NOT_ACTIVE",
        )
