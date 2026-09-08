"""Bounded confidence-neutral recommendation kernel for public MVP releases."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from itda.contracts.base import DataSplit, ExperienceAxis
from itda.contracts.mvp_scored_release import InformationState, MvpScoredProfile
from itda.contracts.place_profile import MismatchTraitId, SubattributeId
from itda.contracts.recommendation import (
    CANONICAL_RECOMMENDATION_CONFIG,
    ImageDisplayState,
    MvpEvidenceSnippet,
    MvpRecommendationAuthorityTrace,
    MvpRecommendationPublicItem,
    MvpRecommendationRun,
    PhotoMvpRecommendationRun,
    PhotoRecommendationAuthorityTrace,
    PhotoRecommendationScoreTrace,
    PhotoTraitFitComponent,
    PlaceAxisSnapshot,
    PlaceConditionSnapshot,
    PlaceSubattributeSnapshot,
    PlaceTraitSnapshot,
    PublicRelationAuthority,
    Publishability,
    RecommendationCandidate,
    RecommendationConfig,
    RecommendationPreference,
    ScoreContribution,
    TravelConditionId,
    mvp_confidence_state_for,
)
from itda.domain.canonical import canonical_sha256
from itda.domain.recommendation_scoring import (
    explanations as build_explanations,
)
from itda.domain.recommendation_scoring import (
    score_candidate,
)


class MvpRecommendationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RankedMvpPlace:
    place_id: str
    relevance_score: int
    novelty_score: int
    combined_score: int


def _half_up(numerator: int, denominator: int) -> int:
    return (2 * numerator + denominator) // (2 * denominator)


def _axis_values(profile: MvpScoredProfile) -> tuple[int, int, int]:
    return profile.scores.H, profile.scores.E, profile.scores.R


def _condition_values(profile: MvpScoredProfile) -> tuple[int, int, int, int, int, int]:
    row = profile.condition_scores
    return (
        row.visit_date_time,
        row.companions,
        row.transport,
        row.walking,
        row.indoor_outdoor,
        row.crowd,
    )


def _traits(profile: MvpScoredProfile) -> tuple[int, int, int, int, int, int]:
    row = profile.scores
    return row.M1, row.M2, row.M3, row.M4, row.M5, row.M6


def _photo_trait_trace(
    profile: MvpScoredProfile,
    *,
    base_relevance: int,
    trait_targets: tuple[int, int, int, int, int, int],
) -> PhotoRecommendationScoreTrace:
    components = cast(
        tuple[
            PhotoTraitFitComponent,
            PhotoTraitFitComponent,
            PhotoTraitFitComponent,
            PhotoTraitFitComponent,
            PhotoTraitFitComponent,
            PhotoTraitFitComponent,
        ],
        tuple(
            PhotoTraitFitComponent(
                trait_id=trait,
                expected=expected,
                actual=actual,
                fit=100 - abs(expected - actual),
            )
            for trait, expected, actual in zip(
                MismatchTraitId,
                trait_targets,
                _traits(profile),
                strict=True,
            )
        ),
    )
    photo_fit = _half_up(sum(row.fit for row in components), 6)
    strongest = max(components, key=lambda row: (row.fit, -int(row.trait_id.value[1:])))
    return PhotoRecommendationScoreTrace(
        base_relevance=base_relevance,
        trait_components=components,
        photo_trait_fit=photo_fit,
        effective_relevance=_half_up(base_relevance * 6_500 + photo_fit * 3_500, 10_000),
        explanation_ko=(
            f"확정한 사진 취향 중 {strongest.trait_id.value} 분위기와 "
            f"{strongest.fit}점만큼 잘 맞아요."
        ),
    )


def _relevance(
    profile: MvpScoredProfile,
    *,
    axis_targets: tuple[int, int, int],
    condition_targets: tuple[int, int, int, int, int, int],
) -> int:
    axis_fit = _half_up(
        sum(
            100 - abs(expected - actual)
            for expected, actual in zip(axis_targets, _axis_values(profile), strict=True)
        ),
        3,
    )
    weights = (400, 350, 350, 350, 300, 250)
    condition_fit = _half_up(
        sum(
            (100 - abs(expected - actual)) * weight
            for expected, actual, weight in zip(
                condition_targets, _condition_values(profile), weights, strict=True
            )
        ),
        2_000,
    )
    return _half_up(axis_fit * 8_000 + condition_fit * 2_000, 10_000)


def _novelty(profile: MvpScoredProfile, selected: Iterable[MvpScoredProfile]) -> int:
    distances = []
    for prior in selected:
        axis_distance = _half_up(
            sum(
                abs(left - right)
                for left, right in zip(_axis_values(profile), _axis_values(prior), strict=True)
            ),
            3,
        )
        trait_distance = _half_up(
            sum(
                abs(left - right)
                for left, right in zip(_traits(profile), _traits(prior), strict=True)
            ),
            6,
        )
        distances.append(_half_up(axis_distance * 6_500 + trait_distance * 3_500, 10_000))
    return min(distances) if distances else 100


def _can_complete_top_five(
    selected: tuple[MvpScoredProfile, ...],
    candidates: tuple[MvpScoredProfile, ...],
    relation_authority: PublicRelationAuthority,
) -> bool:
    needed = 5 - len(selected)
    if needed == 0:
        return True
    selected_groups = {row.duplicate_group_id for row in selected}
    eligible = tuple(
        row
        for row in candidates
        if row.duplicate_group_id not in selected_groups
        and all(not relation_authority.forbids(row.place_id, prior.place_id) for prior in selected)
    )
    if len({row.duplicate_group_id for row in eligible}) < needed:
        return False

    def search(start: int, chosen: tuple[MvpScoredProfile, ...]) -> bool:
        if len(chosen) == needed:
            return True
        remaining_needed = needed - len(chosen)
        if len(eligible) - start < remaining_needed:
            return False
        chosen_groups = {row.duplicate_group_id for row in chosen}
        for index in range(start, len(eligible)):
            candidate = eligible[index]
            if candidate.duplicate_group_id in chosen_groups:
                continue
            if any(
                relation_authority.forbids(candidate.place_id, prior.place_id) for prior in chosen
            ):
                continue
            if search(index + 1, chosen + (candidate,)):
                return True
        return False

    return search(0, ())


def rank_mvp_top_five(
    profiles: tuple[MvpScoredProfile, ...],
    *,
    relation_authority: PublicRelationAuthority,
    axis_targets: tuple[int, int, int],
    condition_targets: tuple[int, int, int, int, int, int],
) -> tuple[RankedMvpPlace, ...]:
    if not 80 <= len(profiles) <= 100:
        raise MvpRecommendationError("MVP_RELEASE_MEMBER_COUNT_INVALID")
    ordered = tuple(sorted(profiles, key=lambda row: row.place_id))
    if tuple(row.place_id for row in ordered) != relation_authority.place_ids:
        raise MvpRecommendationError("MVP_RELATION_MEMBERSHIP_INVALID")
    if len({row.duplicate_group_id for row in ordered}) < 5:
        raise MvpRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
    relevance = {
        row.place_id: _relevance(
            row,
            axis_targets=axis_targets,
            condition_targets=condition_targets,
        )
        for row in ordered
    }
    selected: list[MvpScoredProfile] = []
    ranked: list[RankedMvpPlace] = []
    remaining = list(ordered)
    while len(selected) < 5:
        selected_groups = {row.duplicate_group_id for row in selected}
        compatible = [
            candidate
            for candidate in remaining
            if candidate.duplicate_group_id not in selected_groups
            and all(
                not relation_authority.forbids(candidate.place_id, prior.place_id)
                for prior in selected
            )
        ]
        scored = []
        for candidate in compatible:
            novelty = _novelty(candidate, selected)
            scored.append(
                RankedMvpPlace(
                    place_id=candidate.place_id,
                    relevance_score=relevance[candidate.place_id],
                    novelty_score=novelty,
                    combined_score=_half_up(
                        relevance[candidate.place_id] * 8_500 + novelty * 1_500,
                        10_000,
                    ),
                )
            )
        ordered_scores = sorted(
            scored,
            key=lambda row: (
                -row.combined_score,
                -row.relevance_score,
                -row.novelty_score,
                row.place_id,
            ),
        )
        winner: RankedMvpPlace | None = None
        winner_profile: MvpScoredProfile | None = None
        by_id = {row.place_id: row for row in compatible}
        for score in ordered_scores:
            candidate = by_id[score.place_id]
            future = tuple(
                row
                for row in remaining
                if row.place_id != candidate.place_id
                and row.duplicate_group_id != candidate.duplicate_group_id
            )
            if _can_complete_top_five(
                tuple((*selected, candidate)),
                future,
                relation_authority,
            ):
                winner = score
                winner_profile = candidate
                break
        if winner is None or winner_profile is None:
            raise MvpRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
        selected.append(winner_profile)
        ranked.append(winner)
        remaining = [
            row
            for row in remaining
            if row.place_id != winner.place_id
            and row.duplicate_group_id != winner_profile.duplicate_group_id
        ]
    return tuple(ranked)


def rank_photo_mvp_top_five(
    profiles: tuple[MvpScoredProfile, ...],
    *,
    relation_authority: PublicRelationAuthority,
    axis_targets: tuple[int, int, int],
    condition_targets: tuple[int, int, int, int, int, int],
    trait_targets: tuple[int, int, int, int, int, int],
) -> tuple[tuple[RankedMvpPlace, ...], dict[str, PhotoRecommendationScoreTrace]]:
    if not 80 <= len(profiles) <= 100:
        raise MvpRecommendationError("MVP_RELEASE_MEMBER_COUNT_INVALID")
    ordered = tuple(sorted(profiles, key=lambda row: row.place_id))
    if tuple(row.place_id for row in ordered) != relation_authority.place_ids:
        raise MvpRecommendationError("MVP_RELATION_MEMBERSHIP_INVALID")
    traces = {
        row.place_id: _photo_trait_trace(
            row,
            base_relevance=_relevance(
                row,
                axis_targets=axis_targets,
                condition_targets=condition_targets,
            ),
            trait_targets=trait_targets,
        )
        for row in ordered
    }
    selected: list[MvpScoredProfile] = []
    ranked: list[RankedMvpPlace] = []
    remaining = list(ordered)
    while len(selected) < 5:
        selected_groups = {row.duplicate_group_id for row in selected}
        compatible = [
            candidate
            for candidate in remaining
            if candidate.duplicate_group_id not in selected_groups
            and all(
                not relation_authority.forbids(candidate.place_id, prior.place_id)
                for prior in selected
            )
        ]
        scored = [
            RankedMvpPlace(
                place_id=candidate.place_id,
                relevance_score=traces[candidate.place_id].effective_relevance,
                novelty_score=(novelty := _novelty(candidate, selected)),
                combined_score=_half_up(
                    traces[candidate.place_id].effective_relevance * 8_500
                    + novelty * 1_500,
                    10_000,
                ),
            )
            for candidate in compatible
        ]
        ordered_scores = sorted(
            scored,
            key=lambda row: (
                -row.combined_score,
                -row.relevance_score,
                -row.novelty_score,
                row.place_id,
            ),
        )
        winner: RankedMvpPlace | None = None
        winner_profile: MvpScoredProfile | None = None
        by_id = {row.place_id: row for row in compatible}
        for score in ordered_scores:
            candidate = by_id[score.place_id]
            future = tuple(
                row
                for row in remaining
                if row.place_id != candidate.place_id
                and row.duplicate_group_id != candidate.duplicate_group_id
            )
            if _can_complete_top_five(tuple((*selected, candidate)), future, relation_authority):
                winner = score
                winner_profile = candidate
                break
        if winner is None or winner_profile is None:
            raise MvpRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
        selected.append(winner_profile)
        ranked.append(winner)
        remaining = [
            row
            for row in remaining
            if row.place_id != winner.place_id
            and row.duplicate_group_id != winner_profile.duplicate_group_id
        ]
    return tuple(ranked), traces


def _evidence_ids(profile: MvpScoredProfile, dimension: str) -> tuple[str, ...]:
    return next(
        row.evidence_ids
        for row in profile.scores.justifications
        if row.dimension.value == dimension
    )


def _public_candidate(profile: MvpScoredProfile) -> RecommendationCandidate:
    axis_dimensions = ("H", "E", "R")
    axis_values = (profile.scores.H, profile.scores.E, profile.scores.R)
    condition_dimensions = ("M6", "M4", "M5", "M5", "R1", "M3")
    condition_values = tuple(profile.condition_scores.model_dump(mode="python").values())
    reference_date = max(row.reference_date for row in profile.evidence_excerpts)
    return RecommendationCandidate(
        place_id=profile.place_id,
        place_name_ko=profile.place_name_ko,
        split=DataSplit.PUBLIC,
        exact_release_member=True,
        profile_score_truth="LOCAL_PROFILE_SCORES",
        analysis_origin="GLM_CODING_PLAN_PUBLIC_MODEL_DERIVED",
        publishability=(
            Publishability.AUDIT_ONLY
            if profile.information_state is InformationState.AUDIT_ONLY
            else Publishability.LIMITED_INFORMATION
            if profile.information_state is InformationState.LIMITED_INFORMATION
            else Publishability.PUBLISHABLE
        ),
        recommendation_eligible=True,
        profile_sha256=profile.profile_sha256,
        duplicate_group_id=profile.duplicate_group_id,
        overall_confidence=profile.scores.confidence,
        axis_scores=cast(
            tuple[PlaceAxisSnapshot, PlaceAxisSnapshot, PlaceAxisSnapshot],
            tuple(
                PlaceAxisSnapshot(
                    axis=axis,
                    value=value,
                    evidence_ids=_evidence_ids(profile, dimension),
                )
                for axis, value, dimension in zip(
                    ExperienceAxis, axis_values, axis_dimensions, strict=True
                )
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
                    value=getattr(
                        profile.scores,
                        attribute.value.replace("I", "E", 1)
                        if attribute.value.startswith("I")
                        else attribute.value,
                    ),
                    evidence_ids=_evidence_ids(
                        profile,
                        attribute.value.replace("I", "E", 1)
                        if attribute.value.startswith("I")
                        else attribute.value,
                    ),
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
                    value=getattr(profile.scores, trait.value),
                    evidence_ids=_evidence_ids(profile, trait.value),
                )
                for trait in MismatchTraitId
            ),
        ),
        condition_scores=cast(
            tuple[
                PlaceConditionSnapshot,
                PlaceConditionSnapshot,
                PlaceConditionSnapshot,
                PlaceConditionSnapshot,
                PlaceConditionSnapshot,
                PlaceConditionSnapshot,
            ],
            tuple(
                PlaceConditionSnapshot(
                    condition_id=condition,
                    value=value,
                    evidence_ids=_evidence_ids(profile, dimension),
                )
                for condition, value, dimension in zip(
                    TravelConditionId, condition_values, condition_dimensions, strict=True
                )
            ),
        ),
        evidence=tuple(
            MvpEvidenceSnippet(
                evidence_id=row.evidence_id,
                excerpt_ko=row.excerpt_ko,
                source_label_ko=row.source_label_ko,
                attribution_ko=row.attribution_ko,
                reference_date=row.reference_date,
                provider=row.evidence.provider,
                official_dataset_id=row.evidence.official_dataset_id,
                official_license_url=row.evidence.official_license_url,
                license_type=row.evidence.license_type,
                source_response_sha256=row.evidence.source_response_sha256,
                permission_metadata_sha256=row.evidence.permission_metadata.metadata_sha256,
                evidence_sha256=row.evidence.evidence_sha256,
                usage_state="STRICT_PUBLIC_USAGE_ALLOWED",
            )
            for row in profile.evidence_excerpts
        ),
        reference_date=reference_date,
        popularity=0,
        source_volume=len(profile.evidence_excerpts),
        image_state=ImageDisplayState.ABSENT,
    )


def create_mvp_recommendation_run(
    profiles: tuple[MvpScoredProfile, ...],
    *,
    release_sha256: str,
    membership_sha256: str,
    relation_authority: PublicRelationAuthority,
    preference: RecommendationPreference,
    config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
    created_at: object,
) -> MvpRecommendationRun:
    axis_targets = tuple(row.value for row in preference.axis_targets)
    condition_targets = tuple(row.value for row in preference.condition_targets)
    ranked = rank_mvp_top_five(
        profiles,
        relation_authority=relation_authority,
        axis_targets=cast(tuple[int, int, int], axis_targets),
        condition_targets=cast(tuple[int, int, int, int, int, int], condition_targets),
    )
    candidates = {_public_candidate(row).place_id: _public_candidate(row) for row in profiles}
    public_items: list[MvpRecommendationPublicItem] = []
    for index, ranked_row in enumerate(ranked, start=1):
        candidate = candidates[ranked_row.place_id]
        base_contribution, mismatch = score_candidate(
            preference=preference,
            candidate=candidate,
            config=config,
        )
        if base_contribution.relevance_score != ranked_row.relevance_score:
            raise MvpRecommendationError("MVP_PUBLIC_SCORE_PROJECTION_DRIFT")
        contribution = ScoreContribution.model_validate(
            {
                **base_contribution.model_dump(mode="json"),
                "diversity_novelty_score": ranked_row.novelty_score,
                "rerank_score": ranked_row.combined_score,
                "rerank_numerator": (
                    ranked_row.relevance_score * config.relevance_rerank_bp
                    + ranked_row.novelty_score * config.diversity_rerank_bp
                ),
            }
        )
        evidence_by_id = {row.evidence_id: row for row in candidate.evidence}
        explanations = tuple(
            row.model_copy(
                update={"reference_date": evidence_by_id[row.evidence_id].reference_date}
            )
            for row in build_explanations(candidate, contribution)
        )
        evidence_ids = {row.evidence_id for row in explanations}
        displayed_evidence = tuple(
            cast(MvpEvidenceSnippet, row)
            for row in candidate.evidence
            if row.evidence_id in evidence_ids
        )
        confidence_state, confidence_reason = mvp_confidence_state_for(
            candidate.overall_confidence
        )
        public_items.append(
            MvpRecommendationPublicItem(
                rank=index,
                place_id=candidate.place_id,
                place_name_ko=candidate.place_name_ko,
                fit_score=ranked_row.relevance_score,
                evidence_confidence_state=confidence_state,
                evidence_confidence_reason_ko=confidence_reason,
                mismatch=mismatch,
                contribution=contribution,
                axis_scores=candidate.axis_scores,
                explanations=explanations,
                evidence=displayed_evidence,
                reference_date=max(row.reference_date for row in displayed_evidence),
                image_state=ImageDisplayState.ABSENT,
            )
        )
    candidate_ids = tuple(sorted(row.place_id for row in profiles))
    candidate_sha256 = canonical_sha256(
        [
            {
                "place_id": row.place_id,
                "profile_sha256": row.profile_sha256,
                "duplicate_group_id": row.duplicate_group_id,
            }
            for row in sorted(profiles, key=lambda value: value.place_id)
        ]
    )
    authority = MvpRecommendationAuthorityTrace(
        release_sha256=release_sha256,
        membership_sha256=membership_sha256,
        relation_sha256=relation_authority.relation_sha256,
        candidate_sha256=candidate_sha256,
        config_sha256=cast(str, config.config_sha256),
        kernel_version=config.kernel_version,
    )
    input_digest = canonical_sha256(
        {
            "preference": preference.model_dump(mode="json"),
            "authority": authority.model_dump(mode="json"),
        }
    )
    deterministic = {
        "schema_version": "recommendation-run.v2",
        "input_digest": input_digest,
        "preference": preference.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json"),
        "candidate_place_ids": list(candidate_ids),
        "items": [row.model_dump(mode="json") for row in public_items],
    }
    digest = canonical_sha256(deterministic)
    return MvpRecommendationRun.model_validate(
        {
            **deterministic,
            "run_id": f"recommendation-run:{digest[:32]}",
            "created_at": created_at,
            "canonical_sha256": digest,
        }
    )


def create_photo_mvp_recommendation_run(
    profiles: tuple[MvpScoredProfile, ...],
    *,
    release_sha256: str,
    membership_sha256: str,
    relation_authority: PublicRelationAuthority,
    preference: RecommendationPreference,
    photo_projection_policy_sha256: str,
    photo_projection_output_sha256: str,
    confirmation_draft_sha256: str,
    photo_job_reference_sha256: str,
    images_count: int,
    included_count: int,
    config: RecommendationConfig = CANONICAL_RECOMMENDATION_CONFIG,
    created_at: object,
) -> PhotoMvpRecommendationRun:
    axis_targets = cast(tuple[int, int, int], tuple(row.value for row in preference.axis_targets))
    condition_targets = cast(
        tuple[int, int, int, int, int, int],
        tuple(row.value for row in preference.condition_targets),
    )
    trait_targets = cast(
        tuple[int, int, int, int, int, int],
        tuple(row.value for row in preference.trait_targets),
    )
    ranked, traces = rank_photo_mvp_top_five(
        profiles,
        relation_authority=relation_authority,
        axis_targets=axis_targets,
        condition_targets=condition_targets,
        trait_targets=trait_targets,
    )
    candidates = {_public_candidate(row).place_id: _public_candidate(row) for row in profiles}
    public_items: list[MvpRecommendationPublicItem] = []
    photo_scores: list[PhotoRecommendationScoreTrace] = []
    for index, ranked_row in enumerate(ranked, start=1):
        candidate = candidates[ranked_row.place_id]
        base_contribution, mismatch = score_candidate(
            preference=preference,
            candidate=candidate,
            config=config,
        )
        trace = traces[candidate.place_id]
        if base_contribution.relevance_score != trace.base_relevance:
            raise MvpRecommendationError("MVP_PHOTO_BASE_SCORE_PROJECTION_DRIFT")
        contribution = ScoreContribution.model_validate(
            {
                **base_contribution.model_dump(mode="json"),
                "diversity_novelty_score": ranked_row.novelty_score,
                "rerank_score": _half_up(
                    base_contribution.relevance_score * config.relevance_rerank_bp
                    + ranked_row.novelty_score * config.diversity_rerank_bp,
                    10_000,
                ),
                "rerank_numerator": (
                    base_contribution.relevance_score * config.relevance_rerank_bp
                    + ranked_row.novelty_score * config.diversity_rerank_bp
                ),
            }
        )
        evidence_by_id = {row.evidence_id: row for row in candidate.evidence}
        explanations = tuple(
            row.model_copy(
                update={"reference_date": evidence_by_id[row.evidence_id].reference_date}
            )
            for row in build_explanations(candidate, contribution)
        )
        evidence_ids = {row.evidence_id for row in explanations}
        displayed_evidence = tuple(
            cast(MvpEvidenceSnippet, row)
            for row in candidate.evidence
            if row.evidence_id in evidence_ids
        )
        confidence_state, confidence_reason = mvp_confidence_state_for(
            candidate.overall_confidence
        )
        public_items.append(
            MvpRecommendationPublicItem(
                rank=index,
                place_id=candidate.place_id,
                place_name_ko=candidate.place_name_ko,
                fit_score=trace.effective_relevance,
                evidence_confidence_state=confidence_state,
                evidence_confidence_reason_ko=confidence_reason,
                mismatch=mismatch,
                contribution=contribution,
                axis_scores=candidate.axis_scores,
                explanations=explanations,
                evidence=displayed_evidence,
                reference_date=max(row.reference_date for row in displayed_evidence),
                image_state=ImageDisplayState.ABSENT,
            )
        )
        photo_scores.append(trace)
    candidate_ids = tuple(sorted(row.place_id for row in profiles))
    candidate_sha256 = canonical_sha256(
        [
            {
                "place_id": row.place_id,
                "profile_sha256": row.profile_sha256,
                "duplicate_group_id": row.duplicate_group_id,
            }
            for row in sorted(profiles, key=lambda value: value.place_id)
        ]
    )
    authority = PhotoRecommendationAuthorityTrace(
        release_sha256=release_sha256,
        membership_sha256=membership_sha256,
        relation_sha256=relation_authority.relation_sha256,
        candidate_sha256=candidate_sha256,
        config_sha256=cast(str, config.config_sha256),
        kernel_version=config.kernel_version,
        photo_projection_version="photo-projection-v1",
        photo_projection_policy_sha256=photo_projection_policy_sha256,
        photo_projection_output_sha256=photo_projection_output_sha256,
        confirmation_draft_sha256=confirmation_draft_sha256,
        photo_job_reference_sha256=photo_job_reference_sha256,
        images_count=images_count,
        included_count=included_count,
    )
    input_digest = canonical_sha256(
        {
            "preference": preference.model_dump(mode="json"),
            "authority": authority.model_dump(mode="json"),
        }
    )
    deterministic = {
        "schema_version": "recommendation-run.v3",
        "input_digest": input_digest,
        "preference": preference.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json"),
        "candidate_place_ids": list(candidate_ids),
        "items": [row.model_dump(mode="json") for row in public_items],
        "photo_scores": [row.model_dump(mode="json") for row in photo_scores],
    }
    digest = canonical_sha256(deterministic)
    return PhotoMvpRecommendationRun.model_validate(
        {
            **deterministic,
            "run_id": f"recommendation-run:{digest[:32]}",
            "created_at": created_at,
            "canonical_sha256": digest,
        }
    )
