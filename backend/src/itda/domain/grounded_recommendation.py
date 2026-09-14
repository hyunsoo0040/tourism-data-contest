"""Actual v5 ranking over immutable supported assessments and appearance moods."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime

from itda.contracts.grounded_run import (
    AXIS_KEYS,
    CONDITION_KEYS,
    GROUNDED_POLICY,
    TRAIT_KEYS,
    GroundedAuthority,
    GroundedCandidateBinding,
    GroundedDimension,
    GroundedExclusion,
    GroundedExplanation,
    GroundedMismatchTrace,
    GroundedNoveltyPair,
    GroundedPreference,
    GroundedRecommendationItem,
    GroundedRecommendationRun,
    GroundedScoreTrace,
)
from itda.contracts.grounded_source import GroundedSourceProfile
from itda.contracts.mvp_scored_release import MvpScoredProfile
from itda.contracts.source_assessment import (
    AssessmentBundle,
    ClaimKind,
    SourceObservation,
    SupportState,
)
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_scoring import (
    combine_groups,
    fit_trace,
    half_up,
    mismatch,
    novelty,
    observed_value,
    pair_novelty,
)


class GroundedRecommendationError(ValueError):
    pass


@dataclass(frozen=True)
class GroundedCandidate:
    profile: MvpScoredProfile | GroundedSourceProfile
    assessment: AssessmentBundle
    category: str
    region_code: str | None = None
    region_name: str | None = None
    address_ko: str | None = None
    conditions: Mapping[str, SourceObservation] = field(default_factory=dict)
    moods: Mapping[str, SourceObservation] = field(default_factory=dict)
    contextual_facts: Mapping[str, SourceObservation] = field(default_factory=dict)

    @property
    def place_id(self) -> str:
        return self.profile.place_id


def _snapshot(row: SourceObservation) -> GroundedDimension:
    return GroundedDimension(
        key=row.key,
        value=observed_value(row),
        state=row.state,
        evidence_ids=tuple(sorted({e.evidence_id for e in row.evidence})),
        reference_date=row.reference_date,
        reason=row.reason,
    )


def _shared_keys(
    keys: tuple[str, ...], left: GroundedCandidate, right: GroundedCandidate
) -> tuple[str, ...]:
    return tuple(
        k
        for k in keys
        if observed_value(left.assessment.dimensions[k]) is not None
        and observed_value(right.assessment.dimensions[k]) is not None
    )


def _excluded(candidate: GroundedCandidate, preference: GroundedPreference) -> str | None:
    if preference.trip_input.region_code is not None and (
        candidate.region_code is None
        or not candidate.region_code.startswith(preference.trip_input.region_code)
    ):
        return "REGION"
    categories = {
        "SIGHTSEEING": {"관광지", "문화시설", "레포츠", "축제·공연·행사"},
        "FOOD": {"음식점"},
        "LODGING": {"숙박"},
    }
    if preference.purpose != "MIXED" and candidate.category not in categories[preference.purpose]:
        return "PURPOSE"
    if not candidate.profile.recommendation_eligible:
        return "SUPPORT_GATE"
    if (
        sum(observed_value(candidate.assessment.dimensions[a]) is not None for a in AXIS_KEYS)
        < GROUNDED_POLICY.minimum_supported_axes
    ):
        return "INSUFFICIENT_SUPPORTED_AXES"
    for requirement in preference.trip_input.required_facilities:
        fact = candidate.contextual_facts.get(
            requirement.value, candidate.assessment.facts.get(requirement.value)
        )
        if (
            fact is not None
            and fact.state == SupportState.FACT
            and fact.claim == ClaimKind.FACILITY
            and fact.value is False
        ):
            return "EXPLICIT_FACILITY_ABSENT"
    return None


def _compatible(
    candidate: GroundedCandidate,
    selected: tuple[GroundedCandidate, ...],
    forbidden: frozenset[frozenset[str]],
) -> bool:
    return all(
        candidate.profile.duplicate_group_id != p.profile.duplicate_group_id
        and frozenset({candidate.place_id, p.place_id}) not in forbidden
        for p in selected
    )


def _can_complete(
    selected: tuple[GroundedCandidate, ...],
    candidates: tuple[GroundedCandidate, ...],
    forbidden: frozenset[frozenset[str]],
) -> bool:
    needed = 5 - len(selected)
    if needed == 0:
        return True
    remaining = tuple(
        c
        for c in candidates
        if c.place_id not in {s.place_id for s in selected} and _compatible(c, selected, forbidden)
    )
    if len({c.profile.duplicate_group_id for c in remaining}) < needed:
        return False

    def search(start: int, chosen: tuple[GroundedCandidate, ...]) -> bool:
        if len(chosen) == needed:
            return True
        if len(remaining) - start < needed - len(chosen):
            return False
        return any(
            _compatible(remaining[i], chosen, forbidden) and search(i + 1, (*chosen, remaining[i]))
            for i in range(start, len(remaining))
        )

    return search(0, ())


def rank_grounded(
    *,
    candidates: tuple[GroundedCandidate, ...],
    preference: GroundedPreference,
    release_sha256: str,
    source_release_sha256: str,
    assessment_manifest_sha256: str,
    candidate_sha256: str,
    membership_sha256: str,
    relation_sha256: str,
    forbidden_pairs: tuple[tuple[str, str], ...] = (),
    contextual_snapshot_sha256: tuple[str, ...] = (),
    created_at: datetime,
) -> GroundedRecommendationRun:
    if not candidates or len({c.place_id for c in candidates}) != len(candidates):
        raise GroundedRecommendationError("INVALID_CANDIDATE_MEMBERSHIP")
    ordered = tuple(sorted(candidates, key=lambda c: c.place_id))
    for candidate in ordered:
        type(candidate.profile).model_validate_json(candidate.profile.model_dump_json())
        assessment = AssessmentBundle.model_validate_json(candidate.assessment.model_dump_json())
        if (
            assessment.place_id != candidate.place_id
            or assessment.raw_profile_sha256 != candidate.profile.profile_sha256
            or assessment.source_release_sha256 != source_release_sha256
        ):
            raise GroundedRecommendationError("ASSESSMENT_PROFILE_BINDING_INVALID")
        # Core axes must be the versioned supported-subordinate aggregate, not caller supplied.
        from itda.pipeline.grounded_assessment import aggregate_axis

        for axis in AXIS_KEYS:
            if assessment.dimensions[axis] != aggregate_axis(axis, assessment.dimensions):
                raise GroundedRecommendationError("ASSESSMENT_AXIS_AGGREGATION_INVALID")
        for key, row in candidate.conditions.items():
            SourceObservation.model_validate_json(row.model_dump_json())
            if key not in CONDITION_KEYS or row.key != key:
                raise GroundedRecommendationError("CONDITION_IDENTITY_INVALID")
            if row.state != SupportState.UNKNOWN and (
                row.claim
                not in {
                    ClaimKind.EXPERIENCE,
                    ClaimKind.FACILITY,
                    ClaimKind.OPERATING,
                    ClaimKind.CROWD,
                }
                or any(e.modality == "IMAGE_PIXELS" or e.scope != "PLACE" for e in row.evidence)
                or key == "CROWD"
                and row.claim != ClaimKind.CROWD
            ):
                raise GroundedRecommendationError("CONDITION_SOURCE_AUTHORITY_INVALID")
        for key, row in candidate.moods.items():
            SourceObservation.model_validate_json(row.model_dump_json())
            if (
                key not in preference.mood_targets
                or row.key != key
                or row.claim != ClaimKind.VISUAL_MOOD
            ):
                raise GroundedRecommendationError("MOOD_SOURCE_AUTHORITY_INVALID")
        for key, row in candidate.contextual_facts.items():
            SourceObservation.model_validate_json(row.model_dump_json())
            if (
                key != row.key
                or row.claim != ClaimKind.FACILITY
                or any(
                    e.place_match is None or e.place_match.place_id != candidate.place_id
                    for e in row.evidence
                )
            ):
                raise GroundedRecommendationError("CONTEXTUAL_FACILITY_AUTHORITY_INVALID")
    forbidden = frozenset(frozenset(pair) for pair in forbidden_pairs)
    if any(len(pair) != 2 or not pair <= {c.place_id for c in ordered} for pair in forbidden):
        raise GroundedRecommendationError("RELATION_MEMBERSHIP_INVALID")
    if forbidden_pairs != tuple(sorted(set(forbidden_pairs))) or any(
        a >= b for a, b in forbidden_pairs
    ):
        raise GroundedRecommendationError("RELATION_ORDER_INVALID")
    if relation_sha256 != canonical_sha256(
        {"place_ids": [c.place_id for c in ordered], "pairs": [list(p) for p in forbidden_pairs]}
    ):
        raise GroundedRecommendationError("RELATION_DIGEST_INVALID")
    exclusions = []
    eligible = []
    for candidate in ordered:
        reason = _excluded(candidate, preference)
        if reason:
            exclusions.append(
                GroundedExclusion.model_validate({"place_id": candidate.place_id, "reason": reason})
            )
        else:
            eligible.append(candidate)
    pool = tuple(eligible)
    if not _can_complete((), pool, forbidden):
        raise GroundedRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
    initial = {}
    for c in pool:
        experience = fit_trace(
            preference.axis_targets, {k: c.assessment.dimensions[k] for k in AXIS_KEYS}
        )
        traits = fit_trace(
            preference.trait_targets, {k: c.assessment.dimensions[k] for k in TRAIT_KEYS}
        )
        conditions = fit_trace(preference.condition_targets, c.conditions)
        mood = fit_trace(preference.mood_targets, c.moods)
        base = combine_groups(((experience.score, 8000), (conditions.score, 2000)))
        if base is None:
            raise GroundedRecommendationError("NO_COMPARABLE_EXPERIENCE")
        mood_weight = 1500 if mood.score is not None else 0
        effective = combine_groups(((base, 10000 - mood_weight), (mood.score, mood_weight)))
        if effective is None:
            raise GroundedRecommendationError("NO_COMPARABLE_EXPERIENCE")
        initial[c.place_id] = (experience, traits, conditions, mood, base, effective, mood_weight)
    selected: tuple[GroundedCandidate, ...] = ()
    items = []
    for rank in range(1, 6):
        choices = []
        for candidate in pool:
            if not _compatible(candidate, selected, forbidden):
                continue
            if not _can_complete((*selected, candidate), pool, forbidden):
                continue
            diverse = novelty(
                candidate.assessment.dimensions, tuple(p.assessment.dimensions for p in selected)
            )
            numerator = initial[candidate.place_id][5] * 8500 + diverse * 1500
            choices.append((numerator, candidate))
        if not choices:
            raise GroundedRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")
        numerator, chosen = min(choices, key=lambda row: (-row[0], row[1].place_id))
        experience, traits, conditions, mood, base, effective, mood_weight = initial[
            chosen.place_id
        ]
        pair_traces = []
        for prior in selected:
            pair_traces.append(
                GroundedNoveltyPair(
                    place_id=prior.place_id,
                    shared_axes=_shared_keys(AXIS_KEYS, chosen, prior),
                    shared_traits=_shared_keys(TRAIT_KEYS, chosen, prior),
                    score=pair_novelty(chosen.assessment.dimensions, prior.assessment.dimensions),
                )
            )
        contribution = GroundedScoreTrace(
            experience=experience,
            conditions=conditions,
            traits=traits,
            mood=mood,
            base_relevance=base,
            effective_relevance=effective,
            mood_weight=mood_weight,
            novelty_pairs=tuple(pair_traces),
            novelty_score=min((p.score for p in pair_traces), default=0),
            rerank_numerator=numerator,
            rerank_score=half_up(numerator, 10000),
        )
        mismatch_value = mismatch(
            experience,
            traits,
            important_traits=frozenset(preference.important_traits),
            confidence=chosen.profile.scores.confidence
            if isinstance(chosen.profile, MvpScoredProfile)
            else 0,
        )
        messages = {
            "GENTLE_DIFFERENCE": "확인된 특성 중 기대와 조금 다른 부분이 있어요.",
            "MATERIAL_DIFFERENCE": "확인된 특성 중 기대와 다른 부분이 있어요.",
            "STRONG_DIFFERENCE": "기대와 다른 특성을 방문 전에 확인해 주세요.",
        }
        explanations = []
        for component in sorted(
            (c for c in experience.components if c.compared), key=lambda c: (-(c.fit or 0), c.key)
        )[:2]:
            row = chosen.assessment.dimensions[component.key]
            if row.reference_date is None:
                continue
            labels = {"H": "대상•원형형", "E": "의미•이미지형", "R": "자기•몰입형"}
            explanations.append(
                GroundedExplanation.model_validate(
                    {
                        "dimension": component.key,
                        "message_ko": f"{labels[component.key]}의 확인된 특성을 기대와 비교했어요.",
                        "evidence_ids": component.evidence_ids,
                        "reference_date": row.reference_date,
                    }
                )
            )
        evidence = {
            e.evidence_id: e for d in chosen.assessment.dimensions.values() for e in d.evidence
        }
        used = {eid for explanation in explanations for eid in explanation.evidence_ids}
        supported = sum(
            observed_value(chosen.assessment.dimensions[a]) is not None for a in AXIS_KEYS
        )
        items.append(
            GroundedRecommendationItem(
                rank=rank,
                place_id=chosen.place_id,
                region_code=chosen.region_code,
                region_name=chosen.region_name,
                address_ko=chosen.address_ko,
                place_name_ko=chosen.profile.place_name_ko,
                raw_profile_sha256=chosen.profile.profile_sha256,
                assessment_bundle_sha256=chosen.assessment.bundle_sha256,
                fit_score=effective,
                overall_confidence=chosen.profile.scores.confidence
                if isinstance(chosen.profile, MvpScoredProfile)
                else None,
                axis_scores=tuple(_snapshot(chosen.assessment.dimensions[a]) for a in AXIS_KEYS),
                mismatch_traits=tuple(
                    _snapshot(chosen.assessment.dimensions[t]) for t in TRAIT_KEYS
                ),
                contribution=contribution,
                mismatch=GroundedMismatchTrace(
                    **asdict(mismatch_value), message_ko=messages.get(mismatch_value.state)
                ),
                explanations=tuple(explanations),
                evidence=tuple(evidence[e] for e in sorted(used)),
                supported_axes=supported,
                information_state="SUPPORTED" if supported == 3 else "LIMITED",
                reference_date=min((e.reference_date for e in explanations), default=None),
            )
        )
        selected = (*selected, chosen)
    bindings = tuple(
        GroundedCandidateBinding(
            place_id=c.place_id,
            raw_profile_sha256=c.profile.profile_sha256,
            assessment_bundle_sha256=c.assessment.bundle_sha256,
        )
        for c in ordered
    )
    authority = GroundedAuthority(
        config_sha256=GROUNDED_POLICY.sha256,
        release_sha256=release_sha256,
        source_release_sha256=source_release_sha256,
        assessment_manifest_sha256=assessment_manifest_sha256,
        candidate_sha256=candidate_sha256,
        membership_sha256=membership_sha256,
        relation_sha256=relation_sha256,
        candidate_assessment_sha256=canonical_sha256([b.model_dump(mode="json") for b in bindings]),
        contextual_snapshot_sha256=tuple(sorted(set(contextual_snapshot_sha256))),
        photo_input_sha256=preference.photo_input_sha256,
    )
    payload = {
        "schema_version": "itda.grounded-recommendation-run.v1",
        "input_digest": canonical_sha256(
            {
                "preference": preference.model_dump(mode="json"),
                "authority": authority.model_dump(mode="json"),
            }
        ),
        "preference": preference.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json"),
        "candidate_bindings": [b.model_dump(mode="json") for b in bindings],
        "eligible_place_ids": [c.place_id for c in pool],
        "exclusions": [e.model_dump(mode="json") for e in exclusions],
        "items": [i.model_dump(mode="json") for i in items],
    }
    digest = canonical_sha256(payload)
    return GroundedRecommendationRun.model_validate(
        {
            **payload,
            "run_id": f"recommendation-run:{digest[:32]}",
            "created_at": created_at,
            "canonical_sha256": digest,
        }
    )
