"""Fail-closed publication eligibility for model-derived Phase 5 profiles."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from itda.contracts.hard_duplicate_adjudication import load_hard_duplicate_adjudication
from itda.contracts.phase5_recovery_policy import (
    CANONICAL_PHASE5_RECOVERY_POLICY,
    CannotCoappearAuthority,
)
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY

# Retain the import for callers that introspect the fusion contract; recovery
# thresholds are owned by the additive policy above.
_ = CANONICAL_FUSION_POLICY


_CANONICAL_POLICY = CANONICAL_PHASE5_RECOVERY_POLICY
_CANONICAL_HARD_DUPLICATES = load_hard_duplicate_adjudication()
_CANONICAL_DEV_IDS = _CANONICAL_POLICY.cannot_coappear_authority.dev_place_ids
_CANDIDATE_CONFIDENCE_MIN = _CANONICAL_POLICY.candidate_confidence_min
_MISMATCH_GUIDANCE_CONFIDENCE_MIN = _CANONICAL_POLICY.mismatch_guidance_confidence_min
_ORDINARY_INFORMATION_CONFIDENCE_MIN = _CANONICAL_POLICY.ordinary_information_confidence_min
_MINIMUM_EFFECTIVE_CANDIDATES = _CANONICAL_POLICY.minimum_effective_candidate_count
_PROFILE_STRUCTURE_COUNT = _CANONICAL_POLICY.structural_profile_count


def _decision(
    *,
    eligible: bool,
    recommendation_eligible: bool,
    reason: str,
    confidence_state: str = "AUDIT_ONLY",
    mismatch_guidance_eligible: bool = False,
    structural_profile_count: int = 0,
    candidate_count: int = 0,
    post_hard_duplicate_count: int = 0,
    post_cannot_coappear_count: int = 0,
    effective_candidate_count: int = 0,
    hard_duplicate_representative_ids: tuple[str, ...] = (),
    effective_candidate_ids: tuple[str, ...] = (),
    cannot_coappear_authority_sha256: str | None = None,
) -> "PublicationEligibilityDecision":
    return PublicationEligibilityDecision(
        eligible=eligible,
        recommendation_eligible=recommendation_eligible,
        reason=reason,
        confidence_state=confidence_state,
        mismatch_guidance_eligible=mismatch_guidance_eligible,
        structural_profile_count=structural_profile_count,
        candidate_count=candidate_count,
        post_hard_duplicate_count=post_hard_duplicate_count,
        post_cannot_coappear_count=post_cannot_coappear_count,
        effective_candidate_count=effective_candidate_count,
        hard_duplicate_representative_ids=hard_duplicate_representative_ids,
        effective_candidate_ids=effective_candidate_ids,
        cannot_coappear_authority_sha256=cannot_coappear_authority_sha256,
    )


def _confidence_classification(confidence: int) -> tuple[str, bool]:
    if confidence < _CANDIDATE_CONFIDENCE_MIN:
        return "EVIDENCE_AUDIT_ONLY", False
    if confidence < _MISMATCH_GUIDANCE_CONFIDENCE_MIN:
        return "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED", False
    if confidence < _ORDINARY_INFORMATION_CONFIDENCE_MIN:
        return "EVIDENCE_LIMITED_MISMATCH_AVAILABLE", True
    return "EVIDENCE_SUPPORTED", True


def _confidence_state(confidence: int) -> str:
    return _confidence_classification(confidence)[0]


def _mismatch_guidance_eligible(confidence: int) -> bool:
    return _confidence_classification(confidence)[1]


def _maximum_pairwise_compatible_capacity(
    place_ids: Sequence[str],
    authority: CannotCoappearAuthority,
) -> tuple[str, ...]:
    """Return the exact maximum independent set with canonical tie-breaking."""

    ordered = tuple(sorted(place_ids))
    if not authority.pairs:
        return ordered
    index_by_id = {place_id: index for index, place_id in enumerate(ordered)}
    adjacency = [0] * len(ordered)
    for left, right in authority.pairs:
        left_index = index_by_id[left]
        right_index = index_by_id[right]
        adjacency[left_index] |= 1 << right_index
        adjacency[right_index] |= 1 << left_index

    best: tuple[int, ...] = ()

    def search(candidates: int, selected: tuple[int, ...]) -> None:
        nonlocal best
        if len(selected) + candidates.bit_count() < len(best):
            return
        if not candidates:
            if len(selected) > len(best) or (
                len(selected) == len(best)
                and tuple(ordered[index] for index in selected)
                < tuple(ordered[index] for index in best)
            ):
                best = selected
            return
        lowest_bit = candidates & -candidates
        index = lowest_bit.bit_length() - 1
        search(
            candidates & ~lowest_bit & ~adjacency[index],
            selected + (index,),
        )
        search(candidates & ~lowest_bit, selected)

    search((1 << len(ordered)) - 1, ())
    return tuple(ordered[index] for index in best)


# The implementation above is intentionally bounded by the exact DEV-24
# universe.  Keep this alias private so downstream code has one capacity path.
_pairwise_capacity = _maximum_pairwise_compatible_capacity

_AXIS_KEYS = ("H", "E", "R")
_SUBATTRIBUTE_KEYS = tuple(
    f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)
)
_MISMATCH_KEYS = tuple(f"M{index}" for index in range(1, 7))
_JUSTIFICATION_KEYS = frozenset((*_AXIS_KEYS, *_SUBATTRIBUTE_KEYS, *_MISMATCH_KEYS))


@dataclass(frozen=True, slots=True)
class PublicationEligibilityDecision:
    eligible: bool
    recommendation_eligible: bool
    reason: str
    confidence_state: str = "AUDIT_ONLY"
    mismatch_guidance_eligible: bool = False
    structural_profile_count: int = 0
    candidate_count: int = 0
    post_hard_duplicate_count: int = 0
    post_cannot_coappear_count: int = 0
    effective_candidate_count: int = 0
    hard_duplicate_representative_ids: tuple[str, ...] = ()
    effective_candidate_ids: tuple[str, ...] = ()
    cannot_coappear_authority_sha256: str | None = None


_ELIGIBLE = _decision(eligible=True, recommendation_eligible=True, reason="ELIGIBLE")
_LOW_CONFIDENCE = _decision(eligible=True, recommendation_eligible=False, reason="LOW_CONFIDENCE")


def _rejected(reason: str, **kwargs: object) -> PublicationEligibilityDecision:
    return _decision(
        eligible=False,
        recommendation_eligible=False,
        reason=reason,
        **kwargs,
    )


def _strict_integer_inventory(
    value: object,
    *,
    keys: tuple[str, ...],
    minimum: int,
    maximum: int,
) -> tuple[int, ...] | None:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        return None
    values = tuple(value[key] for key in keys)
    if any(type(item) is not int or not minimum <= item <= maximum for item in values):
        return ()
    return values


def evaluate_nvidia_profile_publication(
    profile: Mapping[str, object],
) -> PublicationEligibilityDecision:
    """Compute one profile's eligibility from returned values only.

    The provider's `publishable` flag is intentionally absent from this API. It is
    an untrusted diagnostic and cannot make an otherwise ineligible profile pass or
    an otherwise eligible profile fail.
    """

    axis_values = _strict_integer_inventory(
        profile.get("axis_scores"),
        keys=_AXIS_KEYS,
        minimum=0,
        maximum=100,
    )
    if axis_values is None:
        return _rejected("PROFILE_SCORE_INVENTORY_INVALID")
    if not axis_values:
        return _rejected("PROFILE_SCORE_RANGE_INVALID")

    subattribute_values = _strict_integer_inventory(
        profile.get("subattributes"),
        keys=_SUBATTRIBUTE_KEYS,
        minimum=0,
        maximum=4,
    )
    if subattribute_values is None:
        return _rejected("PROFILE_SCORE_INVENTORY_INVALID")
    if not subattribute_values:
        return _rejected("PROFILE_SCORE_RANGE_INVALID")

    mismatch_values = _strict_integer_inventory(
        profile.get("mismatch_traits"),
        keys=_MISMATCH_KEYS,
        minimum=0,
        maximum=100,
    )
    if mismatch_values is None:
        return _rejected("PROFILE_SCORE_INVENTORY_INVALID")
    if not mismatch_values:
        return _rejected("PROFILE_SCORE_RANGE_INVALID")

    evidence_ids = profile.get("evidence_ids")
    if (
        not isinstance(evidence_ids, (list, tuple))
        or not 1 <= len(evidence_ids) <= 32
        or any(type(item) is not str or not item for item in evidence_ids)
        or len(evidence_ids) != len(set(evidence_ids))
    ):
        return _rejected("PROFILE_EVIDENCE_INVENTORY_INVALID")
    declared_evidence_ids = set(evidence_ids)

    justifications = profile.get("evidence_justifications")
    if not isinstance(justifications, Mapping) or set(justifications) != _JUSTIFICATION_KEYS:
        return _rejected("PROFILE_EVIDENCE_JUSTIFICATIONS_INVALID")
    for values in justifications.values():
        if (
            not isinstance(values, (list, tuple))
            or not 1 <= len(values) <= 8
            or any(type(item) is not str or not item for item in values)
            or not set(values) <= declared_evidence_ids
        ):
            return _rejected("PROFILE_EVIDENCE_JUSTIFICATIONS_INVALID")

    confidence = profile.get("confidence")
    if type(confidence) is not int or not 0 <= confidence <= 100:
        return _rejected("PROFILE_CONFIDENCE_INVALID")
    if all(value == 0 for value in axis_values):
        return _rejected("PROFILE_SCHEMA_ECHO_DETECTED")
    confidence_state, mismatch_guidance_eligible = _confidence_classification(confidence)
    expected_recommendation_eligible = confidence >= _CANDIDATE_CONFIDENCE_MIN
    expected_reason = "ELIGIBLE" if expected_recommendation_eligible else "LOW_CONFIDENCE"
    classification_fields = {
        "recommendation_eligible",
        "recommendation_eligibility_reason",
    }
    supplied_classification_fields = classification_fields & set(profile)
    if supplied_classification_fields and supplied_classification_fields != classification_fields:
        return _rejected("PROFILE_RECOMMENDATION_ELIGIBILITY_INVALID")
    supplied_recommendation_eligible = profile.get("recommendation_eligible")
    if "recommendation_eligible" in profile and (
        type(supplied_recommendation_eligible) is not bool
        or supplied_recommendation_eligible is not expected_recommendation_eligible
    ):
        return _rejected("PROFILE_RECOMMENDATION_ELIGIBILITY_INVALID")
    supplied_reason = profile.get("recommendation_eligibility_reason")
    if "recommendation_eligibility_reason" in profile and supplied_reason != expected_reason:
        return _rejected("PROFILE_RECOMMENDATION_ELIGIBILITY_INVALID")
    if expected_recommendation_eligible:
        return _decision(
            eligible=True,
            recommendation_eligible=True,
            reason="ELIGIBLE",
            confidence_state=confidence_state,
            mismatch_guidance_eligible=mismatch_guidance_eligible,
        )
    return _decision(
        eligible=True,
        recommendation_eligible=False,
        reason="LOW_CONFIDENCE",
        confidence_state=confidence_state,
        mismatch_guidance_eligible=mismatch_guidance_eligible,
    )


def _validate_cannot_coappear_authority(
    authority: CannotCoappearAuthority | None,
) -> CannotCoappearAuthority:
    if authority is None:
        return _CANONICAL_POLICY.cannot_coappear_authority
    canonical = _CANONICAL_POLICY.cannot_coappear_authority
    if (
        authority.scope != canonical.scope
        or authority.dev_place_ids != canonical.dev_place_ids
        or authority.source_dev_authority_sha256 != canonical.source_dev_authority_sha256
        or authority.dev_membership_sha256 != canonical.dev_membership_sha256
        or authority.catalog_revision_sha256 != canonical.catalog_revision_sha256
        or authority.catalog_approval_sha256 != canonical.catalog_approval_sha256
        or authority.catalog_activation_event_sha256 != canonical.catalog_activation_event_sha256
        or authority.relationship_automatic_leaves_root_sha256
        != canonical.relationship_automatic_leaves_root_sha256
        or authority.relationship_unresolved_leaves_root_sha256
        != canonical.relationship_unresolved_leaves_root_sha256
        or authority.reviewed_relationship_leaves_root_sha256
        != canonical.reviewed_relationship_leaves_root_sha256
        or authority.authoritative_relationship_leaves_sha256
        != canonical.authoritative_relationship_leaves_sha256
        or authority.hard_duplicate_adjudication_sha256
        != canonical.hard_duplicate_adjudication_sha256
    ):
        raise ValueError("caller relation authority is not bound to the fixed human roots")
    return authority


def _hard_duplicate_representatives(
    profiles: Sequence[Mapping[str, object]],
) -> tuple[Mapping[str, object], ...]:
    by_group: dict[str, Mapping[str, object]] = {}
    for profile in profiles:
        place_id = profile["place_id"]
        group_id = _CANONICAL_HARD_DUPLICATES.group_id_by_place.get(str(place_id))
        if group_id is None:
            raise ValueError("profile is outside the human-sealed hard-duplicate authority")
        previous = by_group.get(group_id)
        if previous is None or str(place_id) < str(previous["place_id"]):
            by_group[group_id] = profile
    return tuple(sorted(by_group.values(), key=lambda row: str(row["place_id"])))


def evaluate_nvidia_publication_cohort(
    profiles: Sequence[Mapping[str, object]],
    *,
    cannot_coappear_authority: CannotCoappearAuthority | None = None,
    cannot_coappear_pairs: Sequence[tuple[str, str]] | None = None,
) -> PublicationEligibilityDecision:
    """Compute exact-24 structural and dual-relation cohort eligibility.

    The optional relation arguments exist only to fail closed on legacy/caller
    attempts.  The fixed authority is always loaded from the repository policy;
    callers cannot supply replacement edges, counts, groups, or empty state.
    """

    if cannot_coappear_pairs is not None:
        raise ValueError("caller relation authority is not accepted")
    authority = _validate_cannot_coappear_authority(cannot_coappear_authority)
    if not profiles:
        return _rejected("PROFILE_COHORT_EMPTY")
    structural_profile_count = len(profiles)
    if structural_profile_count != _PROFILE_STRUCTURE_COUNT:
        return _rejected(
            "PROFILE_COHORT_STRUCTURE_INVALID",
            structural_profile_count=structural_profile_count,
            cannot_coappear_authority_sha256=authority.authority_sha256,
        )
    decisions: list[PublicationEligibilityDecision] = []
    for profile in profiles:
        decision = evaluate_nvidia_profile_publication(profile)
        if not decision.eligible:
            return decision
        decisions.append(decision)

    place_ids = tuple(profile.get("place_id") for profile in profiles)
    membership_invalid = (
        any(type(place_id) is not str or not place_id for place_id in place_ids)
        or len(place_ids) != len(set(place_ids))
        or tuple(place_ids) != tuple(sorted(place_ids))
        or tuple(place_ids) != _CANONICAL_DEV_IDS
    )
    if membership_invalid:
        return _rejected(
            "PROFILE_COHORT_MEMBERSHIP_INVALID",
            structural_profile_count=structural_profile_count,
            cannot_coappear_authority_sha256=authority.authority_sha256,
        )

    recommendation_profiles = tuple(
        profile
        for profile, decision in zip(profiles, decisions, strict=True)
        if decision.recommendation_eligible
    )
    candidate_count = len(recommendation_profiles)
    if candidate_count < _MINIMUM_EFFECTIVE_CANDIDATES:
        return _decision(
            eligible=True,
            recommendation_eligible=False,
            reason="INSUFFICIENT_RECOMMENDATION_ELIGIBLE_PROFILES",
            structural_profile_count=structural_profile_count,
            candidate_count=candidate_count,
            cannot_coappear_authority_sha256=authority.authority_sha256,
        )

    hard_representatives = _hard_duplicate_representatives(recommendation_profiles)
    hard_ids = tuple(str(profile["place_id"]) for profile in hard_representatives)
    effective_ids = _maximum_pairwise_compatible_capacity(hard_ids, authority)
    post_hard_count = len(hard_representatives)
    post_cannot_count = len(effective_ids)
    if post_cannot_count < _MINIMUM_EFFECTIVE_CANDIDATES:
        return _decision(
            eligible=True,
            recommendation_eligible=False,
            reason="INSUFFICIENT_EFFECTIVE_CANDIDATES",
            structural_profile_count=structural_profile_count,
            candidate_count=candidate_count,
            post_hard_duplicate_count=post_hard_count,
            post_cannot_coappear_count=post_cannot_count,
            effective_candidate_count=post_cannot_count,
            hard_duplicate_representative_ids=hard_ids,
            effective_candidate_ids=effective_ids,
            cannot_coappear_authority_sha256=authority.authority_sha256,
        )

    vectors = tuple(
        tuple(profile["axis_scores"][key] for key in _AXIS_KEYS)  # type: ignore[index]
        for profile in recommendation_profiles
    )
    if len(vectors) > 1 and len(set(vectors)) == 1:
        return _rejected(
            "PROFILE_COHORT_DEGENERATE",
            structural_profile_count=structural_profile_count,
            candidate_count=candidate_count,
            post_hard_duplicate_count=post_hard_count,
            post_cannot_coappear_count=post_cannot_count,
            effective_candidate_count=post_cannot_count,
            hard_duplicate_representative_ids=hard_ids,
            effective_candidate_ids=effective_ids,
            cannot_coappear_authority_sha256=authority.authority_sha256,
        )

    if len(vectors) > 1:
        axis_probes = ((100, 0, 0), (0, 100, 0), (0, 0, 100))
        top_count = _MINIMUM_EFFECTIVE_CANDIDATES
        probe_top_memberships = tuple(
            tuple(
                str(profile["place_id"])
                for profile, vector in sorted(
                    zip(recommendation_profiles, vectors, strict=True),
                    key=lambda item: (
                        -sum(value * weight for value, weight in zip(item[1], probe, strict=True)),
                        str(item[0]["place_id"]),
                    ),
                )[:top_count]
            )
            for probe in axis_probes
        )
        if len(set(probe_top_memberships)) != len(axis_probes):
            return _rejected(
                "PROFILE_RANK_INSENSITIVE",
                structural_profile_count=structural_profile_count,
                candidate_count=candidate_count,
                post_hard_duplicate_count=post_hard_count,
                post_cannot_coappear_count=post_cannot_count,
                effective_candidate_count=post_cannot_count,
                hard_duplicate_representative_ids=hard_ids,
                effective_candidate_ids=effective_ids,
                cannot_coappear_authority_sha256=authority.authority_sha256,
            )
    return _decision(
        eligible=True,
        recommendation_eligible=True,
        reason="ELIGIBLE",
        structural_profile_count=structural_profile_count,
        candidate_count=candidate_count,
        post_hard_duplicate_count=post_hard_count,
        post_cannot_coappear_count=post_cannot_count,
        effective_candidate_count=post_cannot_count,
        hard_duplicate_representative_ids=hard_ids,
        effective_candidate_ids=effective_ids,
        cannot_coappear_authority_sha256=authority.authority_sha256,
    )


# Public aliases for downstream policy consumers; these remain derived from the
# same fixed policy and never create a second authority.
def evaluate_nvidia_publication_cohort_with_policy(
    profiles: Sequence[Mapping[str, object]],
    *,
    cannot_coappear_authority: CannotCoappearAuthority | None = None,
) -> PublicationEligibilityDecision:
    return evaluate_nvidia_publication_cohort(
        profiles,
        cannot_coappear_authority=cannot_coappear_authority,
    )


def confidence_state_for_profile(profile: Mapping[str, object]) -> str:
    confidence = profile.get("confidence")
    if type(confidence) is not int or not 0 <= confidence <= 100:
        raise ValueError("profile confidence is invalid")
    return _confidence_state(confidence)


def mismatch_guidance_allowed_for_profile(profile: Mapping[str, object]) -> bool:
    confidence = profile.get("confidence")
    if type(confidence) is not int or not 0 <= confidence <= 100:
        raise ValueError("profile confidence is invalid")
    return _mismatch_guidance_eligible(confidence)


__all__ = [
    "PublicationEligibilityDecision",
    "confidence_state_for_profile",
    "evaluate_nvidia_profile_publication",
    "evaluate_nvidia_publication_cohort",
    "evaluate_nvidia_publication_cohort_with_policy",
    "mismatch_guidance_allowed_for_profile",
]
