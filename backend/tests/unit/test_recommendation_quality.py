from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from itda.analysis.recommendation_quality import (
    DEFAULT_SCENARIO_SUITE,
    DEFAULT_SCENARIO_SUITE_SHA256,
    QualityEvaluationError,
    build_release_consistency_report,
    evaluate_scenarios,
    ndcg_at_k,
)
from itda.domain.canonical import canonical_sha256


def test_default_scenarios_are_reproducible_and_honestly_synthetic() -> None:
    first = evaluate_scenarios(DEFAULT_SCENARIO_SUITE)
    assert first == evaluate_scenarios(copy.deepcopy(DEFAULT_SCENARIO_SUITE))
    assert first["human_relevance"]["status"] == "unavailable"
    assert first["provenance"] == "SYNTHETIC_BEHAVIORAL_CASES"
    assert first["scenario_suite_sha256"] == DEFAULT_SCENARIO_SUITE_SHA256
    balanced = first["scenarios"][0]["policies"]
    assert balanced["distance"]["ranking"][0]["place_id"] == "synthetic:quiet-low"
    assert balanced["importance"]["ranking"][0]["place_id"] == "synthetic:rich-high"
    assert all(row["invariance"]["passed"] for row in first["scenarios"])


@pytest.mark.parametrize(
    "path", [("split",), ("scenarios", 0, "split"), ("scenarios", 0, "candidates", 0, "split")]
)
def test_blind_is_rejected_before_ranking(path: tuple[str | int, ...]) -> None:
    suite = copy.deepcopy(DEFAULT_SCENARIO_SUITE)
    target = suite
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = "BLIND"
    with pytest.raises((QualityEvaluationError, ValueError), match="(?i)blind|split"):
        evaluate_scenarios(suite)


def test_ndcg_only_counts_supplied_relevance_and_handles_zero_gain() -> None:
    labels = {"a": 3, "b": 2, "c": 0}
    assert ndcg_at_k(("a", "b", "c"), labels) == 1.0
    assert ndcg_at_k(("c", "b", "a"), labels) < 1.0
    assert ndcg_at_k(("a",), {"a": 0}) is None
    with pytest.raises(QualityEvaluationError):
        ndcg_at_k(("unknown",), labels)


def test_human_judgment_contract_rejects_synthetic_and_missing_provenance() -> None:
    with pytest.raises((ValueError, QualityEvaluationError)):
        evaluate_scenarios(DEFAULT_SCENARIO_SUITE, judgments={"labels": {"x": 3}})
    suite = copy.deepcopy(DEFAULT_SCENARIO_SUITE)
    suite["unexpected"] = "ignored?"
    with pytest.raises(ValueError):
        evaluate_scenarios(suite)


def test_reports_purpose_unavailable_and_missing_evidence_without_hiding_them() -> None:
    report = evaluate_scenarios(DEFAULT_SCENARIO_SUITE)
    case = next(row for row in report["scenarios"] if row["scenario_id"] == "purpose-and-access")
    for policy in case["policies"].values():
        assert policy["unavailable_inclusion_rate"] == 0
        assert policy["purpose_violation_rate"] == 0
        assert policy["unknown_condition_rate"] > 0
        assert policy["evidence"]["entailment_review"] == "unavailable"


def test_fixture_matches_packaged_suite() -> None:
    root = Path(__file__).resolve().parents[3]
    fixture = json.loads(
        (root / "fixtures/recommendation-quality/development-scenarios.json").read_text()
    )
    assert canonical_sha256(fixture) == DEFAULT_SCENARIO_SUITE_SHA256


def test_release_report_binds_exact_inputs_and_runs_live_kernel() -> None:
    from tests.contract.test_mvp_scored_release import release

    value = release(100)
    report = build_release_consistency_report(
        value,
        kernel_version="recommendation-kernel-v4",
        projection_version="recommendation-projection-v3",
        policy_version="source-bound-place-facts.v1",
    )
    assert report["binding"]["release_sha256"] == value.release_sha256
    assert report["binding"]["scenario_suite_sha256"] == DEFAULT_SCENARIO_SUITE_SHA256
    assert report["consistency"]["status"] == "pass"
    assert report["human_relevance"]["status"] == "unavailable"
    assert report["public_release_audit"]["profile_count"] == len(value.profiles)
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    assert report["report_sha256"] == canonical_sha256(body)


def _observed_test_inputs() -> tuple[dict, dict]:
    # Test-only contract/math values, never exported as a real participant collection.
    suite = copy.deepcopy(DEFAULT_SCENARIO_SUITE)
    suite["provenance"] = "DEVELOPMENT_OBSERVATIONS"
    suite["scenarios"] = suite["scenarios"][:1]
    scenario = suite["scenarios"][0]
    scenario["input_kind"] = "OBSERVED"
    scenario.pop("expected_first")
    for index, candidate in enumerate(scenario["candidates"]):
        candidate["split"] = "DEV"
        candidate["place_id"] = f"dev:test-{index}"
    judgments = {
        "schema_version": "recommendation-human-judgments.v1",
        "split": "DEV",
        "source_kind": "HUMAN_RELEVANCE",
        "collection_id": "unit-test-only-not-real-people",
        "protocol_version": "test-v1",
        "collected_at": "2026-09-08T00:00:00Z",
        "source_sha256": "0" * 64,
        "scenario_suite_sha256": canonical_sha256(suite),
        "genuine_human_collection_attested": True,
        "labels": [
            {
                "scenario_id": scenario["scenario_id"],
                "place_id": candidate["place_id"],
                "split": "DEV",
                "relevance": 3 if index == 0 else 0,
            }
            for index, candidate in enumerate(scenario["candidates"])
        ],
    }
    return suite, judgments


def test_supplied_complete_judgments_enable_ndcg_and_bind_collection() -> None:
    suite, judgments = _observed_test_inputs()
    report = evaluate_scenarios(suite, judgments=judgments)
    assert report["human_relevance"]["status"] == "available"
    assert report["human_relevance"]["judgments_sha256"] == canonical_sha256(judgments)
    scores = report["scenarios"][0]["policies"]
    assert scores["distance"]["ndcg_at_5"] == 1.0
    assert scores["importance"]["ndcg_at_5"] < 1.0
    assert report["promotion_decision"] == "NONE_COMPARISON_ONLY"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "blind", "stale", "attestation"])
def test_judgments_fail_closed(mutation: str) -> None:
    suite, judgments = _observed_test_inputs()
    if mutation == "missing":
        judgments["labels"].pop()
    elif mutation == "duplicate":
        judgments["labels"].append(judgments["labels"][0])
    elif mutation == "blind":
        judgments["labels"][0]["split"] = "BLIND"
    elif mutation == "stale":
        judgments["scenario_suite_sha256"] = "f" * 64
    else:
        judgments["genuine_human_collection_attested"] = 1
    with pytest.raises(ValueError):
        evaluate_scenarios(suite, judgments=judgments)


def test_version_mismatch_and_failed_behavior_are_not_passing_reports() -> None:
    from tests.contract.test_mvp_scored_release import release

    suite = copy.deepcopy(DEFAULT_SCENARIO_SUITE)
    suite["scenarios"][0]["expected_first"]["distance"] = "synthetic:rich-high"
    report = build_release_consistency_report(
        release(80),
        kernel_version="recommendation-kernel-v3",
        projection_version="recommendation-projection-v3",
        policy_version="source-bound-place-facts.v1",
        scenario_suite=suite,
    )
    assert report["consistency"]["status"] == "fail"
    failed = {row["name"] for row in report["consistency"]["checks"] if not row["passed"]}
    assert failed == {"executed_algorithm_versions", "synthetic_expected_order"}


def test_live_kernel_failure_returns_failed_gate_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from itda.domain import mvp_recommendation
    from tests.contract.test_mvp_scored_release import release

    def fail(*args, **kwargs):
        raise mvp_recommendation.MvpRecommendationError("INSUFFICIENT_ELIGIBLE_CANDIDATES")

    monkeypatch.setattr(mvp_recommendation, "rank_mvp_top_five", fail)
    report = build_release_consistency_report(
        release(80),
        kernel_version="recommendation-kernel-v4",
        projection_version="recommendation-projection-v3",
        policy_version="source-bound-place-facts.v1",
    )
    assert report["consistency"]["status"] == "fail"
    assert any(row["name"] == "live_kernel_failure" for row in report["consistency"]["checks"])


def test_public_audit_exposes_unknowns_and_zero_drift_without_entailment_claim() -> None:
    from itda.analysis.recommendation_quality import audit_public_release
    from tests.contract.test_mvp_scored_release import release

    value = release(80)
    audit = audit_public_release(value, previous_release=value)
    assert audit["fact_state_counts"]["UNKNOWN"] > 0
    assert audit["drift"]["max_axis_delta"] == 0
    assert audit["drift"]["matched_profiles"] == 80
    assert audit["entailment_review"] == "unavailable"


def test_cli_writes_deterministic_report_and_rejects_blind_path(tmp_path: Path) -> None:
    from itda.cli.evaluate_recommendation_quality import main

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    assert main(["--output", str(first)]) == 0
    assert main(["--output", str(second)]) == 0
    assert first.read_bytes() == second.read_bytes()
    blind = tmp_path / "blind-input.json"
    with pytest.raises(SystemExit) as error:
        main(["--scenarios", str(blind), "--output", str(tmp_path / "forbidden.json")])
    assert error.value.code == 2
    assert not (tmp_path / "forbidden.json").exists()
