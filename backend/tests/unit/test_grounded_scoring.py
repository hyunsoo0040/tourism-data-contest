"""Unknown raw values cannot enter fit, mismatch or pairwise diversity."""

import pytest
from pydantic import ValidationError

from itda.contracts.grounded_recommendation import GroundedFitTrace
from itda.domain.grounded_scoring import combine_groups, fit_trace, mismatch, novelty, pair_novelty
from itda.pipeline.grounded_assessment import unknown_dimension
from tests.unit.test_grounded_axis_aggregation import judgment


def test_missing_pair_removes_weight_not_fills_zero_or_perfect_fit():
    trace = fit_trace(
        {"H": 80, "E": 70, "R": None},
        {"H": judgment("H", 60), "E": unknown_dimension("E", "missing"), "R": judgment("R", 50)},
    )
    assert trace.score == 80 and trace.numerator == 80 and trace.denominator == 1
    assert trace.compared_keys == ("H",)
    assert trace.components[0].fit is None and trace.components[0].weight == 0
    assert trace.components[2].exclusion_reason == "USER_UNSPECIFIED"


def test_no_supported_pairs_is_not_zero_distance_or_perfect_fit():
    trace = fit_trace({"M3": 0}, {"M3": unknown_dimension("M3", "no measurement")})
    assert trace.score is None
    result = mismatch(trace, trace, important_traits=frozenset({"M3"}), confidence=100)
    assert result.raw_score is None and result.effective_score is None
    assert result.state == "INSUFFICIENT_EVIDENCE" and not result.important_floor_applied


def test_unknown_raw_value_mutations_cannot_trigger_important_floor_or_novelty():
    axis = fit_trace({"H": 70}, {"H": judgment("H", 70)})
    results = []
    for value in [0, 50, 100]:
        # Deliberately bypass input validation to test the kernel's support mask.
        unknown = unknown_dimension("M3", "no measurement").model_copy(update={"value": value})
        traits = fit_trace({"M3": 0}, {"M3": unknown})
        results.append(
            (
                traits,
                mismatch(axis, traits, important_traits=frozenset({"M3"}), confidence=90),
                pair_novelty({"M3": unknown}, {"M3": judgment("M3", 100)}),
            )
        )
    assert results[0] == results[1] == results[2]
    assert not results[0][1].important_floor_applied and results[0][2] == 0


def test_actual_supported_important_difference_can_trigger_floor():
    axis = fit_trace({"H": 50}, {"H": judgment("H", 50)})
    traits = fit_trace({"M4": 0}, {"M4": judgment("M4", 100)})
    result = mismatch(axis, traits, important_traits=frozenset({"M4"}), confidence=90)
    assert result.raw_score == 35 and result.effective_score == 50
    assert result.important_floor_applied


def test_no_comparable_selected_pair_prevents_diversity_bonus():
    candidate = {"H": judgment("H", 100)}
    dissimilar = {"H": judgment("H", 0)}
    unknown = {"H": unknown_dimension("H", "missing")}
    assert novelty(candidate, ()) == 0
    assert novelty(candidate, (dissimilar,)) == 100
    assert novelty(candidate, (unknown, dissimilar)) == 0


def test_missing_mood_or_condition_group_keeps_baseline_exactly():
    assert combine_groups(((73, 8500), (None, 1500))) == 73
    assert combine_groups(((None, 8000), (None, 2000))) is None


def test_trace_rejects_forged_display_score():
    trace = fit_trace({"H": 50}, {"H": judgment("H", 70)})
    with pytest.raises(ValidationError, match="arithmetic"):
        GroundedFitTrace.model_validate({**trace.model_dump(), "score": 100})
