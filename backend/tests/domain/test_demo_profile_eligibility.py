from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy

import pytest

from itda.contracts.phase5_recovery_policy import (
    CANONICAL_PHASE5_RECOVERY_POLICY,
    CannotCoappearAuthority,
)
from itda.domain.demo_profile_eligibility import (
    evaluate_nvidia_profile_publication,
    evaluate_nvidia_publication_cohort,
)

_SCORE_KEYS = (
    "H",
    "E",
    "R",
    *(f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)),
    *(f"M{index}" for index in range(1, 7)),
)


def _profile(*, place_id: str = "place:01", confidence: int = 70) -> dict[str, object]:
    evidence_id = "tour-description-01"
    return {
        "place_id": place_id,
        "axis_scores": {"H": 76, "E": 61, "R": 84},
        "subattributes": {
            **{f"H{index}": 3 for index in range(1, 5)},
            **{f"I{index}": 2 for index in range(1, 5)},
            **{f"R{index}": 4 for index in range(1, 5)},
        },
        "mismatch_traits": {f"M{index}": index * 10 for index in range(1, 7)},
        "evidence_justifications": {key: [evidence_id] for key in _SCORE_KEYS},
        "evidence_ids": [evidence_id],
        "confidence": confidence,
    }


def _canonical_place_ids() -> tuple[str, ...]:
    return CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority.dev_place_ids


def _cohort(*, confidences: Sequence[int] | None = None) -> list[dict[str, object]]:
    values = tuple(confidences or (70,) * 24)
    assert len(values) == 24
    profiles: list[dict[str, object]] = []
    for index, (place_id, confidence) in enumerate(zip(_canonical_place_ids(), values, strict=True)):
        profile = _profile(place_id=place_id, confidence=confidence)
        profile["axis_scores"] = {
            "H": (index * 11 + 17) % 100,
            "E": (index * 17 + 29) % 100,
            "R": (index * 23 + 41) % 100,
        }
        profiles.append(profile)
    return profiles


@pytest.mark.parametrize(
    ("confidence", "recommendation_eligible", "reason"),
    (
        (54, False, "LOW_CONFIDENCE"),
        (55, True, "ELIGIBLE"),
        (64, True, "ELIGIBLE"),
        (65, True, "ELIGIBLE"),
        (69, True, "ELIGIBLE"),
        (70, True, "ELIGIBLE"),
        (100, True, "ELIGIBLE"),
    ),
)
def test_profile_eligibility_uses_canonical_confidence_boundary(
    confidence: int,
    recommendation_eligible: bool,
    reason: str,
) -> None:
    decision = evaluate_nvidia_profile_publication(_profile(confidence=confidence))

    assert decision.eligible is True
    assert decision.recommendation_eligible is recommendation_eligible
    assert decision.reason == reason


def test_structurally_valid_confidence_55_is_materializable_and_recommendable() -> None:
    """D-28: confidence is a candidacy gate, not structural validity."""

    decision = evaluate_nvidia_profile_publication(_profile(confidence=55))

    assert decision.eligible is True
    assert decision.recommendation_eligible is True
    assert decision.reason == "ELIGIBLE"


def test_recovery_policy_freezes_exact_thresholds_and_activation_bindings() -> None:
    policy = CANONICAL_PHASE5_RECOVERY_POLICY

    assert policy.structural_profile_count == 24
    assert policy.candidate_confidence_min == 55
    assert policy.mismatch_guidance_confidence_min == 65
    assert policy.ordinary_information_confidence_min == 70
    assert policy.minimum_effective_candidate_count == 5
    assert policy.confidence_is_ranking_input is False
    assert policy.hard_duplicate_suppression_precedes_effective_count is True
    assert policy.activation_scenario_ids == (
        "critical-01-history-morning-solo",
        "critical-02-image-sunset-partner",
        "critical-03-rest-daytime-seniors",
        "critical-04-balanced-family-car",
        "critical-05-history-evening-walk",
        "critical-06-image-group-transit",
        "critical-07-rest-outdoor-low-crowd",
        "critical-08-balanced-undecided",
    )
    assert len(policy.contrast_pairs) == 7
    assert policy.cannot_coappear_authority.pairs == ()
    assert policy.cannot_coappear_authority.authority_sha256 == (
        "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70"
    )


def test_cannot_coappear_authority_rejects_unbound_or_malformed_graphs() -> None:
    authority = CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority
    payload = authority.model_dump(mode="json")

    for mutation in (
        {"pairs": [["place:unknown", "place:also-unknown"]]},
        {"pairs": [[authority.dev_place_ids[0], authority.dev_place_ids[0]]]},
        {"pairs": [[authority.dev_place_ids[0], authority.dev_place_ids[1]], [authority.dev_place_ids[1], authority.dev_place_ids[0]]]},
        {"authoritative_relationship_leaves_sha256": "0" * 64},
        {"pairs": [[authority.dev_place_ids[1], authority.dev_place_ids[0]]]},
    ):
        hostile = deepcopy(payload)
        hostile.update(mutation)
        with pytest.raises(ValueError):
            CannotCoappearAuthority.model_validate(hostile)


def test_exact_dev24_structural_count_is_distinct_from_candidacy_count() -> None:
    profiles = _cohort(confidences=(55,) * 24)

    decision = evaluate_nvidia_publication_cohort(profiles)

    assert decision.eligible is True
    assert decision.recommendation_eligible is True
    assert decision.reason == "ELIGIBLE"

    for count in (23, 25):
        malformed = profiles[:count]
        if count == 25:
            malformed.append(_profile(place_id="place:extra"))
        cohort = evaluate_nvidia_publication_cohort(malformed)
        assert cohort.reason == "PROFILE_COHORT_STRUCTURE_INVALID"
        assert cohort.eligible is False


def test_dual_relation_capacity_reports_four_and_five_without_caller_authority() -> None:
    profiles = _cohort()
    pairs = tuple(
        (profiles[index]["place_id"], profiles[index + 1]["place_id"])
        for index in range(0, 8, 2)
    )
    with pytest.raises(ValueError, match="caller relation"):
        evaluate_nvidia_publication_cohort(profiles, cannot_coappear_pairs=pairs)

    four_candidate_profiles = _cohort(
        confidences=(70, 70, 70, 70, *([54] * 20)),
    )
    four = evaluate_nvidia_publication_cohort(
        four_candidate_profiles,
        cannot_coappear_authority=CannotCoappearAuthority(
            **CANONICAL_PHASE5_RECOVERY_POLICY.cannot_coappear_authority.model_dump(mode="json")
        ),
    )
    assert four.reason == "INSUFFICIENT_RECOMMENDATION_ELIGIBLE_PROFILES"
    assert four.eligible is True
    assert four.recommendation_eligible is False
    assert four.candidate_count == 4
    assert four.effective_candidate_count == 0

    five_candidate_profiles = _cohort(
        confidences=(70, 70, 70, 70, 70, *([54] * 19)),
    )
    assert four.structural_profile_count == 24
    assert four.post_hard_duplicate_count == 0
    assert four.post_cannot_coappear_count == 0
    decision = evaluate_nvidia_publication_cohort(five_candidate_profiles)
    assert decision.effective_candidate_count == 5
    assert decision.post_hard_duplicate_count == 5
    assert decision.post_cannot_coappear_count == 5
    assert decision.candidate_count == 5
    assert decision.structural_profile_count == 24
    assert decision.effective_candidate_ids == tuple(
        profile["place_id"] for profile in five_candidate_profiles[:5]
    )

    for profile in five_candidate_profiles[5:]:
        assert profile["confidence"] == 54
    assert decision.cannot_coappear_authority_sha256 == (
        "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70"
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.update(recommendation_eligible=True),
        lambda value: value.update(recommendation_eligible=False),
        lambda value: value.update(recommendation_eligible=0),
        lambda value: value.update(recommendation_eligibility_reason="ELIGIBLE"),
        lambda value: value.update(recommendation_eligibility_reason="LOW_CONFIDENCE"),
    ),
    ids=(
        "contradictory-flag",
        "lone-correct-flag",
        "coerced-flag",
        "contradictory-reason",
        "lone-correct-reason",
    ),
)
def test_profile_eligibility_rejects_supplied_low_confidence_classification_drift(
    mutation: object,
) -> None:
    from collections.abc import Callable

    profile = _profile(confidence=55)
    assert isinstance(mutation, Callable)
    mutation(profile)

    decision = evaluate_nvidia_profile_publication(profile)

    assert decision.eligible is False
    assert decision.reason == "PROFILE_RECOMMENDATION_ELIGIBILITY_INVALID"


@pytest.mark.parametrize("confidence", (True, "70", -1, 101))
def test_profile_eligibility_fails_closed_for_malformed_confidence(
    confidence: object,
) -> None:
    profile = _profile()
    profile["confidence"] = confidence

    decision = evaluate_nvidia_profile_publication(profile)

    assert decision.eligible is False
    assert decision.reason == "PROFILE_CONFIDENCE_INVALID"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        (lambda value: value["axis_scores"].pop("R"), "PROFILE_SCORE_INVENTORY_INVALID"),
        (lambda value: value["axis_scores"].update(H=True), "PROFILE_SCORE_RANGE_INVALID"),
        (lambda value: value["axis_scores"].update(H=-1), "PROFILE_SCORE_RANGE_INVALID"),
        (lambda value: value["axis_scores"].update(H=101), "PROFILE_SCORE_RANGE_INVALID"),
        (
            lambda value: value["subattributes"].pop("R4"),
            "PROFILE_SCORE_INVENTORY_INVALID",
        ),
        (
            lambda value: value["subattributes"].update(R4=5),
            "PROFILE_SCORE_RANGE_INVALID",
        ),
        (
            lambda value: value["mismatch_traits"].pop("M6"),
            "PROFILE_SCORE_INVENTORY_INVALID",
        ),
        (
            lambda value: value["mismatch_traits"].update(M6=101),
            "PROFILE_SCORE_RANGE_INVALID",
        ),
    ),
)
def test_profile_eligibility_fails_closed_for_score_inventory_and_ranges(
    mutation: object,
    reason: str,
) -> None:
    from collections.abc import Callable

    profile = _profile()
    assert isinstance(mutation, Callable)
    mutation(profile)

    decision = evaluate_nvidia_profile_publication(profile)

    assert decision.eligible is False
    assert decision.reason == reason


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["evidence_justifications"].pop("M6"),
        lambda value: value["evidence_justifications"].update(M6=[]),
        lambda value: value["evidence_justifications"].update(M6=["unknown-evidence"]),
    ),
    ids=("missing-one-of-21", "empty-justification", "undeclared-evidence"),
)
def test_profile_eligibility_requires_exact_21_bound_justifications(
    mutation: object,
) -> None:
    from collections.abc import Callable

    profile = _profile()
    assert isinstance(mutation, Callable)
    mutation(profile)

    decision = evaluate_nvidia_profile_publication(profile)

    assert decision.eligible is False
    assert decision.reason == "PROFILE_EVIDENCE_JUSTIFICATIONS_INVALID"


@pytest.mark.parametrize(
    "evidence_ids",
    (None, [], ["tour-description-01", "tour-description-01"]),
    ids=("missing", "empty", "duplicate"),
)
def test_profile_eligibility_requires_a_nonempty_unique_evidence_inventory(
    evidence_ids: object,
) -> None:
    profile = _profile()
    if evidence_ids is None:
        profile.pop("evidence_ids")
    else:
        profile["evidence_ids"] = evidence_ids

    decision = evaluate_nvidia_profile_publication(profile)

    assert decision.eligible is False
    assert decision.reason == "PROFILE_EVIDENCE_INVENTORY_INVALID"


def test_profile_eligibility_rejects_all_zero_axis_scores() -> None:
    profile = _profile()
    profile["axis_scores"] = {"H": 0, "E": 0, "R": 0}

    decision = evaluate_nvidia_profile_publication(profile)

    assert decision.eligible is False
    assert decision.reason == "PROFILE_SCHEMA_ECHO_DETECTED"


def test_cohort_eligibility_rejects_identical_and_rank_insensitive_vectors() -> None:
    identical = _cohort()
    for profile in identical:
        profile["axis_scores"] = {"H": 50, "E": 50, "R": 50}
    identical_decision = evaluate_nvidia_publication_cohort(identical)
    assert identical_decision.eligible is False
    assert identical_decision.reason == "PROFILE_COHORT_DEGENERATE"

    diagonal = _cohort()
    for index, profile in enumerate(diagonal):
        profile["axis_scores"] = {
            "H": 10 + index,
            "E": 10 + index,
            "R": 10 + index,
        }
    diagonal_decision = evaluate_nvidia_publication_cohort(diagonal)
    assert diagonal_decision.eligible is False
    assert diagonal_decision.reason == "PROFILE_RANK_INSENSITIVE"


def test_cohort_eligibility_accepts_valid_rank_effective_boundary() -> None:
    vectors = (
        (100, 1, 1),
        (1, 100, 1),
        (1, 1, 100),
        (60, 20, 10),
        (10, 60, 20),
        (20, 10, 60),
    )
    profiles = _cohort()
    for index, profile in enumerate(profiles):
        vector = vectors[index % len(vectors)]
        profile["axis_scores"] = dict(zip(("H", "E", "R"), vector, strict=True))

    decision = evaluate_nvidia_publication_cohort(profiles)

    assert decision.eligible is True
    assert decision.reason == "ELIGIBLE"


def test_cohort_with_four_recommendation_eligible_profiles_remains_materializable() -> None:
    """Specified oracle: a sparse eligible subset produces no fabricated Top5 later."""

    profiles = _cohort(confidences=(70, 70, 70, 70, *([54] * 20)))
    decision = evaluate_nvidia_publication_cohort(profiles)

    assert decision.eligible is True
    assert decision.recommendation_eligible is False
    assert decision.reason == "INSUFFICIENT_RECOMMENDATION_ELIGIBLE_PROFILES"
    assert decision.candidate_count == 4
    assert decision.effective_candidate_count == 0
    assert decision.cannot_coappear_authority_sha256 == (
        "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70"
    )
