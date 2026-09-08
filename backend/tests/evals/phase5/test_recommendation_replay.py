from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from tests.unit.test_recommendation_kernel import (
    CREATED_AT,
    SHA_B,
    SHA_C,
    _candidate_payload,
    _preference_payload,
    _rank,
)

FIXTURE_PATH = Path(__file__).parent / "recommendation_scenarios.json"
SCENARIOS = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))["scenarios"]
ASYMMETRIC_AXIS_PROFILES = (
    (95, 20, 20),
    (85, 35, 30),
    (20, 95, 20),
    (35, 85, 30),
    (20, 20, 95),
    (30, 35, 85),
    (60, 60, 60),
)


def _asymmetric_candidates() -> list[dict[str, object]]:
    candidates = []
    for index, values in enumerate(ASYMMETRIC_AXIS_PROFILES, start=1):
        candidate = _candidate_payload(index, value=50)
        for axis, value in zip(candidate["axis_scores"], values, strict=True):
            axis["value"] = value
        candidates.append(candidate)
    return candidates


def test_all_twenty_four_scenarios_have_explicit_oracle_outcomes() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["policy_trace"] == {
        "experience_fit_bp": 8000,
        "travel_condition_fit_bp": 2000,
        "condition_weights": [400, 350, 350, 350, 300, 250],
        "mismatch_axis_bp": 6500,
        "mismatch_trait_bp": 3500,
        "important_trait_difference_threshold": 70,
        "important_trait_floor": 50,
        "mismatch_guidance_thresholds": [30, 45, 60],
        "mismatch_warning_confidence_min": 65,
        "rerank_weights": [8500, 1500],
        "top_k": 5,
    }
    for scenario in fixture["scenarios"]:
        assert scenario["oracle"]["status"] in {
            "SUCCESS",
            "INSUFFICIENT_ELIGIBLE_CANDIDATES",
            "INVALID_CANDIDATE_CONTRACT",
        }
        assert "top_k" in scenario["oracle"] or "reason_code" in scenario["oracle"]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda row: row["scenario_id"])
def test_each_canonical_scenario_executes_its_declared_oracle(
    scenario: dict[str, object],
) -> None:
    from pydantic import ValidationError

    from itda.contracts.recommendation import RecommendationCandidate
    from itda.domain.recommendation import RecommendationKernelError

    scenario_id = str(scenario["scenario_id"])
    parameters = scenario["parameters"]
    oracle = scenario["oracle"]
    assert isinstance(parameters, dict)
    assert isinstance(oracle, dict)

    if scenario_id.startswith("critical-"):
        preference = _preference_payload()
        for target, value in zip(
            preference["axis_targets"], parameters["axis_targets"], strict=True
        ):
            target["value"] = value
        run = _rank(candidates=_asymmetric_candidates(), preference=preference)
        assert [
            [
                item.place_id,
                item.fit_score,
                item.contribution.relevance_score,
                item.contribution.diversity_novelty_score,
            ]
            for item in run.items
        ] == oracle["ranking"]
        for item in run.items:
            profile_index = int(item.place_id.rsplit(":", 1)[1]) - 1
            assert [
                [
                    component.expected_value,
                    component.place_value,
                    component.absolute_difference,
                    component.fit_score,
                ]
                for component in item.contribution.axis_components
            ] == [
                [expected, actual, abs(expected - actual), 100 - abs(expected - actual)]
                for expected, actual in zip(
                    parameters["axis_targets"],
                    ASYMMETRIC_AXIS_PROFILES[profile_index],
                    strict=True,
                )
            ]
        return

    if "mismatch_values" in parameters:
        expected_states = oracle["guidance_states"]
        for value in parameters["mismatch_values"]:
            run = _rank(
                candidates=[_candidate_payload(index, value=value) for index in range(1, 7)],
                preference=_preference_payload(value=0),
            )
            assert (
                run.items[0].mismatch.state
                == expected_states[parameters["mismatch_values"].index(value)]
            )
        return

    if "confidence_values" in parameters:
        from itda.contracts.recommendation import (
            CANONICAL_RECOMMENDATION_CONFIG,
            RecommendationCandidate,
            RecommendationPreference,
        )
        from itda.domain.recommendation import _mismatch_guidance

        preference = RecommendationPreference.model_validate(_preference_payload(value=0))
        states = [
            _mismatch_guidance(
                preference=preference,
                candidate=RecommendationCandidate.model_validate(
                    _candidate_payload(index + 1, value=80, confidence=confidence)
                ),
                config=CANONICAL_RECOMMENDATION_CONFIG,
            ).state.value
            for index, confidence in enumerate(parameters["confidence_values"])
        ]
        assert states == oracle["guidance_states"]
        return

    if "important_difference_values" in parameters:
        floor_states = []
        effective_scores = []
        for difference in parameters["important_difference_values"]:
            candidates = [_candidate_payload(index, value=0) for index in range(1, 7)]
            for candidate in candidates:
                candidate["mismatch_traits"][0]["value"] = difference
            run = _rank(
                candidates=candidates,
                preference=_preference_payload(value=0, important_difference=True),
            )
            floor_states.append(run.items[0].mismatch.important_trait_floor_applied)
            effective_scores.append(run.items[0].mismatch.effective_score)
        assert floor_states == oracle["floor_applied"]
        assert effective_scores == oracle["effective_scores"]
        return

    if "eligible_candidates" in parameters:
        candidates = [
            _candidate_payload(index)
            for index in range(1, int(parameters["eligible_candidates"]) + 1)
        ]
        if oracle["status"] == "SUCCESS":
            assert len(_rank(candidates=candidates).items) == 5
        else:
            with pytest.raises(RecommendationKernelError) as captured:
                _rank(candidates=candidates)
            assert captured.value.code == oracle["reason_code"]
        return

    if scenario_id == "boundary-08-explicit-unknown-states":
        candidates = [_candidate_payload(index, value=45 + index) for index in range(1, 8)]
        candidates[0]["image_state"] = "RIGHTS_RESTRICTED"
        run = _rank(candidates=candidates)
        assert run.items[0].image_state in {"ABSENT", "RIGHTS_RESTRICTED"}
        return

    mutation = parameters.get("mutation")
    candidates = [_candidate_payload(index, value=45 + index) for index in range(1, 8)]
    if mutation in {
        "INPUT_ORDER",
        "POPULARITY",
        "CONFIDENCE_WITHIN_ELIGIBLE",
        "SOURCE_VOLUME",
        "IMAGE_PRESENCE",
    }:
        baseline = _rank(candidates=candidates)
        mutated = deepcopy(list(reversed(candidates)))
        for index, candidate in enumerate(mutated):
            if mutation == "POPULARITY":
                candidate["popularity"] = 100_000 - index
            elif mutation == "CONFIDENCE_WITHIN_ELIGIBLE":
                candidate["overall_confidence"] = 70 + index
            elif mutation == "SOURCE_VOLUME":
                candidate["source_volume"] = 100_000 - index
            elif mutation == "IMAGE_PRESENCE":
                candidate["image_state"] = "DISPLAY_ASSET_AVAILABLE"
        counterfactual = _rank(candidates=mutated)
        assert [row.place_id for row in counterfactual.items] == [
            row.place_id for row in baseline.items
        ]
        return
    if mutation == "DUPLICATE_GROUP":
        candidates[0]["duplicate_group_id"] = "duplicate:one"
        candidates[1]["duplicate_group_id"] = "duplicate:one"
        assert len(_rank(candidates=candidates).items) == 5
        return
    if mutation == "BLIND_MEMBER":
        candidates = [_candidate_payload(index) for index in range(1, 6)]
        candidates[0]["split"] = "BLIND"
        with pytest.raises(RecommendationKernelError) as captured:
            _rank(candidates=candidates)
        assert captured.value.code == oracle["reason_code"]
        return
    if mutation == "OWNED_CONTRIBUTIONS":
        from itda.contracts.recommendation import RecommendationCandidate

        baseline_candidates = [
            RecommendationCandidate.model_validate(_candidate_payload(index, value=50))
            for index in range(1, 7)
        ]
        baseline = _rank(candidates=[row.model_dump(mode="json") for row in baseline_candidates])
        baseline_item = next(
            row for row in baseline.scored_candidates if row.place_id == "place:dev:01"
        )
        for counterfactual in parameters["condition_counterfactuals"]:
            mutated = [row.model_dump(mode="json") for row in baseline_candidates]
            condition = counterfactual["condition_id"]
            target = next(
                row for row in mutated[0]["condition_scores"] if row["condition_id"] == condition
            )
            target["value"] = 0
            changed = _rank(candidates=mutated)
            changed_item = next(
                row for row in changed.scored_candidates if row.place_id == "place:dev:01"
            )
            changed_conditions = {
                after.condition_id
                for before, after in zip(
                    baseline_item.contribution.condition_components,
                    changed_item.contribution.condition_components,
                    strict=True,
                )
                if before != after
            }
            assert changed_conditions == {condition}
        for counterfactual in parameters["trait_counterfactuals"]:
            mutated = [row.model_dump(mode="json") for row in baseline_candidates]
            trait_id = counterfactual["trait_id"]
            target = next(
                row for row in mutated[0]["mismatch_traits"] if row["trait_id"] == trait_id
            )
            target["value"] = 0
            changed = _rank(candidates=mutated)
            changed_item = next(
                row for row in changed.scored_candidates if row.place_id == "place:dev:01"
            )
            assert (
                changed_item.contribution.axis_components
                == baseline_item.contribution.axis_components
            )
            assert (
                changed_item.contribution.condition_components
                == baseline_item.contribution.condition_components
            )
            assert changed_item.mismatch.axis_distance == baseline_item.mismatch.axis_distance
            assert changed_item.mismatch.trait_distance != baseline_item.mismatch.trait_distance
        return
    if mutation == "UNKNOWN_EVIDENCE_ID":
        candidate = _candidate_payload(1)
        candidate["axis_scores"][0]["evidence_ids"] = ["evidence:unknown"]
        with pytest.raises(ValidationError, match="unknown evidence id"):
            RecommendationCandidate.model_validate(candidate)
        return

    raise AssertionError(f"unhandled canonical scenario: {scenario_id}")


def test_one_hundred_replays_are_byte_identical_across_permutations() -> None:
    from itda.contracts.recommendation import (
        CANONICAL_RECOMMENDATION_CONFIG,
        RecommendationCandidate,
        RecommendationPreference,
    )
    from itda.domain.canonical import canonical_json_bytes
    from itda.domain.recommendation import replay_recommendation

    candidate_payloads = [_candidate_payload(index, value=42 + index) for index in range(1, 9)]
    preference = RecommendationPreference.model_validate(_preference_payload())
    candidates = tuple(RecommendationCandidate.model_validate(row) for row in candidate_payloads)
    original = _rank(candidates=candidate_payloads)
    expected = canonical_json_bytes(original.model_dump(mode="json"))

    for iteration in range(100):
        order = tuple(reversed(candidates)) if iteration % 2 else candidates
        replayed = replay_recommendation(
            original,
            preference=preference,
            candidates=order,
            release_sha256=SHA_B,
            canonical_membership_sha256=SHA_C,
            config=CANONICAL_RECOMMENDATION_CONFIG,
        )
        assert canonical_json_bytes(replayed.model_dump(mode="json")) == expected
        assert replayed.canonical_sha256 == original.canonical_sha256


def test_critical_oracle_detects_axis_swap_mutation() -> None:
    scenario = SCENARIOS[0]
    preference = _preference_payload()
    for target, value in zip(
        preference["axis_targets"], scenario["parameters"]["axis_targets"], strict=True
    ):
        target["value"] = value
    candidates = _asymmetric_candidates()
    for candidate in candidates:
        candidate["axis_scores"][0]["value"], candidate["axis_scores"][1]["value"] = (
            candidate["axis_scores"][1]["value"],
            candidate["axis_scores"][0]["value"],
        )
    mutated = _rank(candidates=candidates, preference=preference)
    assert [item.place_id for item in mutated.items] != [
        row[0] for row in scenario["oracle"]["ranking"]
    ]


@pytest.mark.parametrize(
    "field", ("popularity", "source_volume", "image_state", "overall_confidence")
)
def test_non_rank_metadata_mutations_preserve_canonical_receipt(field: str) -> None:
    candidates = [_candidate_payload(index, value=45 + index) for index in range(1, 8)]
    baseline = _rank(candidates=candidates)
    mutated = deepcopy(candidates)
    for index, candidate in enumerate(mutated):
        if field == "image_state":
            candidate[field] = "DISPLAY_ASSET_AVAILABLE"
        elif field == "overall_confidence":
            candidate[field] = 70 + index
        else:
            candidate[field] = 100_000 - index
    counterfactual = _rank(candidates=mutated)
    assert [item.place_id for item in counterfactual.items] == [
        item.place_id for item in baseline.items
    ]


def test_created_at_is_excluded_from_identity_but_preserved_in_receipt() -> None:
    from datetime import timedelta

    from itda.contracts.recommendation import (
        CANONICAL_RECOMMENDATION_CONFIG,
        RecommendationCandidate,
        RecommendationPreference,
    )
    from itda.domain.recommendation import rank_recommendations

    preference = RecommendationPreference.model_validate(_preference_payload())
    candidates = tuple(
        RecommendationCandidate.model_validate(_candidate_payload(index)) for index in range(1, 7)
    )
    later = rank_recommendations(
        preference=preference,
        candidates=candidates,
        release_sha256=SHA_B,
        canonical_membership_sha256=SHA_C,
        created_at=CREATED_AT + timedelta(minutes=5),
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )
    original = _rank(candidates=[_candidate_payload(index) for index in range(1, 7)])
    assert later.run_id == original.run_id
    assert later.canonical_sha256 == original.canonical_sha256
    assert later.created_at != original.created_at


def test_fixture_digest_and_policy_identity_are_self_consistent() -> None:
    from itda.contracts.recommendation import CANONICAL_RECOMMENDATION_CONFIG
    from itda.domain.canonical import canonical_sha256

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["kernel_version"] == CANONICAL_RECOMMENDATION_CONFIG.kernel_version
    assert fixture["config_sha256"] == CANONICAL_RECOMMENDATION_CONFIG.config_sha256
    assert fixture["dataset_sha256"] == canonical_sha256(fixture["scenarios"])
    assert fixture["ndcg_at_5"] == {
        "status": "NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS",
        "denominator": 0,
    }
