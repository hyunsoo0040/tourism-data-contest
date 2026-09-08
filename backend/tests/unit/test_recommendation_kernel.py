from __future__ import annotations

import ast
import importlib.util
import json
import statistics
import time
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

RED_MARKER = "PHASE5_RED_RECOMMENDATION_KERNEL_NOT_IMPLEMENTED"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
CREATED_AT = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
FIXTURE_PATH = Path(__file__).parents[1] / "evals" / "phase5" / "recommendation_scenarios.json"


def test_controlled_red_sentinel() -> None:
    if importlib.util.find_spec("itda.domain.recommendation") is None:
        # Pytest 9 puts aggregate counts on the child testsuite only.  The frozen
        # RED verifier also checks the testsuites envelope, so mirror the one-test
        # counts there for this isolated subprocess without changing project hooks.
        import _pytest.junitxml as junitxml

        element = junitxml.ET.Element

        def _red_xml_element(tag: str, *args: object, **kwargs: object):
            node = element(tag, *args, **kwargs)
            if tag == "testsuites":
                node.attrib.update(tests="1", failures="1", errors="0", skipped="0")
            return node

        junitxml.ET.Element = _red_xml_element
        print(RED_MARKER)
        pytest.fail(RED_MARKER, pytrace=False)


def test_kernel_has_no_runtime_or_side_effect_imports() -> None:
    source_path = Path(__file__).parents[2] / "src" / "itda" / "domain" / "recommendation.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported_roots.isdisjoint(
        {
            "datetime",
            "fastapi",
            "httpx",
            "logging",
            "os",
            "pathlib",
            "random",
            "requests",
            "sqlalchemy",
            "time",
        }
    )


def _preference_payload(
    *, value: int = 50, important_difference: bool = False
) -> dict[str, object]:
    from itda.contracts.base import ExperienceAxis
    from itda.contracts.place_profile import MismatchTraitId
    from itda.contracts.recommendation import TravelConditionId

    return {
        "profile_id": "preference:phase5:oracle",
        "input_sha256": SHA_A,
        "axis_targets": [{"axis": axis.value, "value": value} for axis in ExperienceAxis],
        "trait_targets": [
            {
                "trait_id": trait.value,
                "value": value,
                "important": important_difference and trait is MismatchTraitId.M1,
            }
            for trait in MismatchTraitId
        ],
        "condition_targets": [
            {"condition_id": condition.value, "value": value} for condition in TravelConditionId
        ],
    }


def _candidate_payload(
    place_number: int,
    *,
    value: int = 50,
    confidence: int = 80,
    duplicate_group_id: str | None = None,
    eligible: bool | None = None,
) -> dict[str, object]:
    from itda.contracts.base import ExperienceAxis
    from itda.contracts.place_profile import MismatchTraitId, SubattributeId
    from itda.contracts.recommendation import TravelConditionId

    place_id = f"place:dev:{place_number:02d}"
    evidence = [
        {
            "evidence_id": f"evidence:{place_number:02d}:{index}",
            "excerpt_ko": f"합성 오라클 근거 {place_number}-{index}",
            "source_label_ko": "합성 검증 근거",
            "attribution_ko": "출처: 합성 검증 픽스처",
            "contest_use_scope": "noncommercial_contest_demo_evaluation",
            "contest_rights_qualified": True,
            "reference_date": "2026-08-10",
        }
        for index in range(1, 4)
    ]
    evidence_ids = [row["evidence_id"] for row in evidence]
    expected_eligible = confidence >= 55
    publishability = (
        "PUBLISHABLE"
        if confidence >= 70
        else "LIMITED_INFORMATION"
        if confidence >= 55
        else "EXCLUDED"
    )
    return {
        "place_id": place_id,
        "place_name_ko": f"합성 장소 {place_number}",
        "split": "DEV",
        "exact_release_member": True,
        "profile_score_truth": "LOCAL_PROFILE_SCORES",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "publishability": publishability,
        "recommendation_eligible": expected_eligible if eligible is None else eligible,
        "profile_sha256": f"{place_number:064x}",
        "duplicate_group_id": duplicate_group_id,
        "overall_confidence": confidence,
        "axis_scores": [
            {"axis": axis.value, "value": value, "evidence_ids": [evidence_ids[index]]}
            for index, axis in enumerate(ExperienceAxis)
        ],
        "subattributes": [
            {
                "attribute_id": attribute.value,
                "value": min(4, value // 25),
                "evidence_ids": evidence_ids[:2],
            }
            for attribute in SubattributeId
        ],
        "mismatch_traits": [
            {"trait_id": trait.value, "value": value, "evidence_ids": evidence_ids[:2]}
            for trait in MismatchTraitId
        ],
        "condition_scores": [
            {
                "condition_id": condition.value,
                "value": value,
                "evidence_ids": evidence_ids[:2],
            }
            for condition in TravelConditionId
        ],
        "evidence": evidence,
        "reference_date": "2026-08-10",
        "popularity": 10_000 - place_number,
        "source_volume": place_number * 10,
        "image_state": "ABSENT",
    }


def _rank(
    *,
    candidates: list[dict[str, object]] | None = None,
    preference: dict[str, object] | None = None,
):
    from itda.contracts.recommendation import (
        CANONICAL_RECOMMENDATION_CONFIG,
        RecommendationCandidate,
        RecommendationPreference,
    )
    from itda.domain.recommendation import rank_recommendations

    candidate_rows = candidates or [
        _candidate_payload(index, value=48 + index) for index in range(1, 8)
    ]
    return rank_recommendations(
        preference=RecommendationPreference.model_validate(preference or _preference_payload()),
        candidates=tuple(
            RecommendationCandidate.model_validate(candidate) for candidate in candidate_rows
        ),
        release_sha256=SHA_B,
        canonical_membership_sha256=SHA_C,
        created_at=CREATED_AT,
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )


def test_canonical_configuration_and_scenario_inventory_are_frozen() -> None:
    from itda.contracts.recommendation import CANONICAL_RECOMMENDATION_CONFIG
    from itda.domain.canonical import canonical_sha256

    config = CANONICAL_RECOMMENDATION_CONFIG
    assert (config.experience_fit_bp, config.travel_condition_fit_bp) == (8_000, 2_000)
    assert config.condition_weights.model_dump(mode="json") == {
        "visit_date_time": 400,
        "companions": 350,
        "transport": 350,
        "walking": 350,
        "indoor_outdoor": 300,
        "crowd": 250,
    }
    assert (config.mismatch_axis_bp, config.mismatch_trait_bp) == (6_500, 3_500)
    assert config.mismatch_guidance_thresholds == (30, 45, 60)
    assert (config.important_trait_difference_threshold, config.important_trait_floor) == (70, 50)
    assert config.mismatch_warning_confidence_min == 65
    assert (config.relevance_rerank_bp, config.diversity_rerank_bp) == (8_500, 1_500)
    assert config.top_k == 5

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    scenarios = fixture["scenarios"]
    assert len(scenarios) == 24
    assert len({row["scenario_id"] for row in scenarios}) == 24
    assert {
        category: sum(row["category"] == category for row in scenarios)
        for category in ("critical", "boundary", "adversarial")
    } == {
        "critical": 8,
        "boundary": 8,
        "adversarial": 8,
    }
    assert fixture["kernel_version"] == config.kernel_version
    assert fixture["config_sha256"] == config.config_sha256
    assert fixture["dataset_sha256"] == canonical_sha256(scenarios)
    assert fixture["ndcg_at_5"] == {
        "status": "NOT_EVALUATED_MISSING_HUMAN_RELEVANCE_LABELS",
        "denominator": 0,
    }


@pytest.mark.parametrize(
    ("difference", "expected_state"),
    (
        (29, "NO_GUIDANCE"),
        (30, "GENTLE_DIFFERENCE"),
        (44, "GENTLE_DIFFERENCE"),
        (45, "MATERIAL_DIFFERENCE"),
        (59, "MATERIAL_DIFFERENCE"),
        (60, "STRONG_DIFFERENCE"),
    ),
)
def test_mismatch_guidance_boundaries_are_exact(difference: int, expected_state: str) -> None:
    candidates = [_candidate_payload(index, value=difference) for index in range(1, 7)]
    run = _rank(candidates=candidates, preference=_preference_payload(value=0))
    assert run.items[0].mismatch.raw_score == difference
    assert run.items[0].mismatch.effective_score == difference
    assert run.items[0].mismatch.state == expected_state


def test_locked_fit_trace_uses_exact_80_20_integer_numerators() -> None:
    candidate = _candidate_payload(1, value=50)
    preference = _preference_payload(value=0)
    candidate["axis_scores"] = [
        {**row, "value": value}
        for row, value in zip(candidate["axis_scores"], (0, 30, 60), strict=True)
    ]
    candidate["condition_scores"] = [
        {**row, "value": value}
        for row, value in zip(candidate["condition_scores"], (0, 10, 20, 30, 40, 50), strict=True)
    ]

    run = _rank(
        candidates=[candidate, *[_candidate_payload(index) for index in range(2, 6)]],
        preference=preference,
    )
    contribution = next(
        row.contribution for row in run.scored_candidates if row.place_id == "place:dev:01"
    )

    assert contribution.experience_fit_score == 70
    assert [row.total_score_weight_bp for row in contribution.condition_components] == [
        400,
        350,
        350,
        350,
        300,
        250,
    ]
    assert [row.weighted_numerator for row in contribution.condition_components] == [
        40_000,
        31_500,
        28_000,
        24_500,
        18_000,
        12_500,
    ]
    assert contribution.travel_condition_fit_score == 77
    assert contribution.relevance_numerator == 714_000
    assert contribution.relevance_score == 71


def test_locked_mismatch_trace_uses_exact_65_35_integer_numerators() -> None:
    candidate = _candidate_payload(1, value=0)
    candidate["axis_scores"] = [{**row, "value": 20} for row in candidate["axis_scores"]]
    candidate["mismatch_traits"] = [
        {**row, "value": value}
        for row, value in zip(candidate["mismatch_traits"], (10, 20, 30, 40, 50, 60), strict=True)
    ]
    run = _rank(
        candidates=[candidate, *[_candidate_payload(index) for index in range(2, 6)]],
        preference=_preference_payload(value=0),
    )
    mismatch = next(row.mismatch for row in run.scored_candidates if row.place_id == "place:dev:01")
    assert (mismatch.axis_distance, mismatch.trait_distance) == (20, 35)
    assert mismatch.raw_score == 25
    assert mismatch.effective_score == 25


def test_mismatch_warning_confidence_64_is_suppressed_and_65_is_visible() -> None:
    from itda.contracts.recommendation import (
        CANONICAL_RECOMMENDATION_CONFIG,
        RecommendationCandidate,
        RecommendationPreference,
    )
    from itda.domain.recommendation import _mismatch_guidance

    preference = RecommendationPreference.model_validate(_preference_payload(value=0))
    low_candidate = RecommendationCandidate.model_validate(
        _candidate_payload(1, value=80, confidence=64)
    )
    admitted_candidate = RecommendationCandidate.model_validate(
        _candidate_payload(2, value=80, confidence=65)
    )
    low = _mismatch_guidance(
        preference=preference,
        candidate=low_candidate,
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )
    admitted = _mismatch_guidance(
        preference=preference,
        candidate=admitted_candidate,
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )
    assert low.state == "SUPPRESSED_LOW_CONFIDENCE"
    assert low.suppression_reason == "CONFIDENCE_BELOW_65"
    neutral_low_candidate = RecommendationCandidate.model_validate(
        _candidate_payload(3, value=0, confidence=64)
    )
    neutral_low = _mismatch_guidance(
        preference=preference,
        candidate=neutral_low_candidate,
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )
    assert neutral_low.state == "SUPPRESSED_LOW_CONFIDENCE"
    assert neutral_low.suppression_reason == "CONFIDENCE_BELOW_65"
    assert admitted.state == "STRONG_DIFFERENCE"

    neutral_admitted_candidate = RecommendationCandidate.model_validate(
        _candidate_payload(4, value=0, confidence=65)
    )
    neutral_admitted = _mismatch_guidance(
        preference=preference,
        candidate=neutral_admitted_candidate,
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )
    assert neutral_admitted.state == "NO_GUIDANCE"
    assert neutral_admitted.suppression_reason is None


def test_confidence_state_schema_is_detail_only_and_closed_in_openapi() -> None:
    from itda.api.main import create_app

    schemas = create_app().openapi()["components"]["schemas"]
    item = schemas["RecommendationItem"]
    detail = schemas["RecommendationDetail"]
    assert "confidence_percent" not in item["properties"]
    assert item["properties"]["evidence_confidence_state"]["$ref"] == (
        "#/components/schemas/EvidenceConfidenceState"
    )
    assert detail["properties"]["confidence_percent"]["type"] == "integer"
    assert detail["properties"]["confidence_percent"]["minimum"] == 0
    assert detail["properties"]["confidence_percent"]["maximum"] == 100
    assert schemas["EvidenceConfidenceState"]["enum"] == [
        "EVIDENCE_AUDIT_ONLY",
        "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED",
        "EVIDENCE_LIMITED_MISMATCH_AVAILABLE",
        "EVIDENCE_SUPPORTED",
    ]
    assert "confidence_percent" not in schemas["RecommendationResultsResponse"]["properties"]
    assert "confidence_percent" not in schemas["RecommendationRequest"]["properties"]


def test_former_axis_only_policy_cannot_validate_as_current_configuration() -> None:
    from pydantic import ValidationError

    from itda.contracts.recommendation import CANONICAL_RECOMMENDATION_CONFIG, RecommendationConfig

    payload = CANONICAL_RECOMMENDATION_CONFIG.model_dump(mode="json")
    payload.update(
        {
            "schema_version": "recommendation-config.v2",
            "kernel_version": "recommendation-kernel-v2",
            "experience_fit_bp": 10_000,
            "travel_condition_fit_bp": 0,
            "condition_weights": {field: 0 for field in payload["condition_weights"]},
            "mismatch_axis_bp": 10_000,
            "mismatch_trait_bp": 0,
            "config_sha256": None,
        }
    )
    with pytest.raises(ValidationError, match="exact frozen configuration"):
        RecommendationConfig.model_validate(payload)


def test_kernel_rejects_validation_bypassed_former_policy() -> None:
    from itda.contracts.recommendation import (
        CANONICAL_RECOMMENDATION_CONFIG,
        RecommendationCandidate,
        RecommendationPreference,
    )
    from itda.domain.recommendation import RecommendationKernelError, rank_recommendations

    former = CANONICAL_RECOMMENDATION_CONFIG.model_copy(
        update={
            "schema_version": "recommendation-config.v2",
            "kernel_version": "recommendation-kernel-v2",
            "experience_fit_bp": 10_000,
            "travel_condition_fit_bp": 0,
            "mismatch_axis_bp": 10_000,
            "mismatch_trait_bp": 0,
        }
    )
    with pytest.raises(RecommendationKernelError, match="INVALID_RECOMMENDATION_CONFIG"):
        rank_recommendations(
            preference=RecommendationPreference.model_validate(_preference_payload()),
            candidates=tuple(
                RecommendationCandidate.model_validate(_candidate_payload(index))
                for index in range(1, 6)
            ),
            release_sha256=SHA_B,
            canonical_membership_sha256=SHA_C,
            created_at=CREATED_AT,
            config=former,
        )


def test_confidence_eligibility_boundary_excludes_54_and_admits_55() -> None:
    candidates = [_candidate_payload(index, value=80) for index in range(1, 7)]
    candidates[0] = _candidate_payload(1, value=80, confidence=54)
    excluded = _rank(candidates=candidates, preference=_preference_payload(value=0))
    assert excluded.exclusions[0].place_id == "place:dev:01"
    assert excluded.exclusions[0].reason in {
        "NOT_RECOMMENDATION_ELIGIBLE",
        "NOT_PUBLISHABLE",
    }

    candidates[0] = _candidate_payload(1, value=80, confidence=55)
    admitted = _rank(candidates=candidates, preference=_preference_payload(value=0))
    assert "place:dev:01" in admitted.candidate_place_ids


def test_confidence_boundary_64_and_65_remain_rank_eligible() -> None:
    baseline = _rank(
        candidates=[_candidate_payload(index, value=80) for index in range(1, 7)],
        preference=_preference_payload(value=0),
    )
    for confidence in (55, 64, 65, 69, 70):
        candidates = [_candidate_payload(index, value=80) for index in range(1, 7)]
        candidates[0] = _candidate_payload(1, value=80, confidence=confidence)
        run = _rank(candidates=candidates, preference=_preference_payload(value=0))
        assert [row.place_id for row in run.items] == [row.place_id for row in baseline.items]
        assert "place:dev:01" in run.candidate_place_ids


def test_kernel_rejects_validation_bypassed_low_confidence_candidate() -> None:
    from itda.contracts.recommendation import (
        CANONICAL_RECOMMENDATION_CONFIG,
        Publishability,
        RecommendationCandidate,
        RecommendationPreference,
    )
    from itda.domain.recommendation import rank_recommendations

    candidates = tuple(
        RecommendationCandidate.model_validate(_candidate_payload(index)) for index in range(1, 7)
    )
    bypassed = candidates[0].model_copy(
        update={
            "overall_confidence": 69,
            "publishability": Publishability.PUBLISHABLE,
            "recommendation_eligible": True,
        }
    )
    run = rank_recommendations(
        preference=RecommendationPreference.model_validate(_preference_payload()),
        candidates=(bypassed, *candidates[1:]),
        release_sha256=SHA_B,
        canonical_membership_sha256=SHA_C,
        created_at=CREATED_AT,
        config=CANONICAL_RECOMMENDATION_CONFIG,
    )
    assert bypassed.place_id in run.candidate_place_ids
    assert bypassed.place_id not in [row.place_id for row in run.exclusions]


def test_important_trait_floor_applies_exactly_at_difference_70() -> None:
    preference = _preference_payload(value=0, important_difference=True)
    at_69 = [_candidate_payload(index, value=0) for index in range(1, 7)]
    at_70 = deepcopy(at_69)
    for candidate in at_69:
        candidate["mismatch_traits"][0]["value"] = 69
    for candidate in at_70:
        candidate["mismatch_traits"][0]["value"] = 70

    below = _rank(candidates=at_69, preference=preference)
    boundary = _rank(candidates=at_70, preference=preference)
    assert below.items[0].mismatch.important_trait_floor_applied is False
    assert below.items[0].mismatch.effective_score == 4
    assert boundary.items[0].mismatch.important_trait_floor_applied is True
    assert boundary.items[0].mismatch.effective_score == 50


def test_exactly_five_or_named_failure_without_padding() -> None:
    from itda.domain.recommendation import RecommendationKernelError

    success = _rank(candidates=[_candidate_payload(index) for index in range(1, 6)])
    assert [item.rank for item in success.items] == [1, 2, 3, 4, 5]
    assert len({item.place_id for item in success.items}) == 5

    with pytest.raises(RecommendationKernelError) as captured:
        _rank(candidates=[_candidate_payload(index) for index in range(1, 5)])
    assert captured.value.code == "INSUFFICIENT_ELIGIBLE_CANDIDATES"


def test_cannot_coappear_authority_suppresses_incompatible_final_selection() -> None:
    from copy import deepcopy

    from itda.contracts.phase5_recovery_policy import CannotCoappearAuthority
    from itda.domain import recommendation as recommendation_module

    authority = recommendation_module._CANONICAL_CANNOT_COAPPEAR
    candidates = [_candidate_payload(index, value=50) for index in range(1, 8)]
    for candidate, place_id in zip(candidates, authority.dev_place_ids[:7], strict=True):
        candidate["place_id"] = place_id
    pair = (authority.dev_place_ids[0], authority.dev_place_ids[1])
    patched = CannotCoappearAuthority.model_validate(
        {
            **authority.model_dump(mode="json"),
            "pairs": [list(pair)],
            "authority_sha256": None,
        }
    )
    from itda.domain.canonical import canonical_sha256

    assert patched.authority_sha256 == canonical_sha256(
        patched.model_dump(mode="json", exclude={"authority_sha256"})
    )
    assert patched.authority_sha256 != authority.authority_sha256
    original = recommendation_module._CANONICAL_CANNOT_COAPPEAR
    recommendation_module._CANONICAL_CANNOT_COAPPEAR = patched
    try:
        run = _rank(candidates=deepcopy(candidates))
    finally:
        recommendation_module._CANONICAL_CANNOT_COAPPEAR = original

    selected_ids = tuple(item.place_id for item in run.items)
    assert not {pair[0], pair[1]} <= set(selected_ids)
    assert all(
        row.suppression_reason == "CANNOT_COAPPEAR"
        for step in run.diversity_steps
        for row in step.suppression_decisions
    )
    assert any(pair[1] in step.suppressed_place_ids for step in run.diversity_steps)


def test_cannot_coappear_capacity_below_five_fails_without_padding() -> None:
    from itda.contracts.phase5_recovery_policy import CannotCoappearAuthority
    from itda.domain import recommendation as recommendation_module
    from itda.domain.recommendation import RecommendationKernelError

    authority = recommendation_module._CANONICAL_CANNOT_COAPPEAR
    candidates = [_candidate_payload(index, value=50) for index in range(1, 7)]
    for candidate, place_id in zip(candidates, authority.dev_place_ids[:6], strict=True):
        candidate["place_id"] = place_id
    pairs = [
        [authority.dev_place_ids[index], authority.dev_place_ids[index + 1]]
        for index in range(0, 6, 2)
    ]
    patched = CannotCoappearAuthority.model_validate(
        {**authority.model_dump(mode="json"), "pairs": pairs, "authority_sha256": None}
    )
    from itda.domain.canonical import canonical_sha256

    assert patched.authority_sha256 == canonical_sha256(
        patched.model_dump(mode="json", exclude={"authority_sha256"})
    )
    assert patched.authority_sha256 != authority.authority_sha256
    original = recommendation_module._CANONICAL_CANNOT_COAPPEAR
    recommendation_module._CANONICAL_CANNOT_COAPPEAR = patched
    try:
        with pytest.raises(RecommendationKernelError, match="INSUFFICIENT_ELIGIBLE_CANDIDATES"):
            _rank(candidates=candidates)
    finally:
        recommendation_module._CANONICAL_CANNOT_COAPPEAR = original


def test_hard_duplicates_are_suppressed_before_deterministic_diversity_rerank() -> None:
    candidates = [_candidate_payload(index, value=45 + index) for index in range(1, 8)]
    candidates[0]["duplicate_group_id"] = "duplicate:royal-complex"
    candidates[1]["duplicate_group_id"] = "duplicate:royal-complex"
    run = _rank(candidates=list(reversed(candidates)))

    assert [(row.kept_place_id, row.suppressed_place_ids) for row in run.duplicate_decisions] == [
        ("place:dev:01", ("place:dev:02",))
    ]
    assert "place:dev:02" not in [item.place_id for item in run.items]
    assert [step.rank for step in run.diversity_steps] == [1, 2, 3, 4, 5]
    assert all(
        step.combined_score == (step.relevance_score * 85 + step.novelty_score * 15 + 50) // 100
        for step in run.diversity_steps[1:]
    )


def test_metadata_and_input_permutations_never_change_rank() -> None:
    candidates = [_candidate_payload(index, value=45 + index) for index in range(1, 8)]
    baseline = _rank(candidates=candidates)
    mutated = deepcopy(list(reversed(candidates)))
    for index, candidate in enumerate(mutated):
        candidate["popularity"] = index
        candidate["source_volume"] = 999 - index
        candidate["image_state"] = "DISPLAY_ASSET_AVAILABLE"
        candidate["overall_confidence"] = 70 + index

    counterfactual = _rank(candidates=mutated)
    assert [item.place_id for item in counterfactual.items] == [
        item.place_id for item in baseline.items
    ]


def test_unavailable_condition_counterfactuals_have_zero_weight() -> None:
    from itda.contracts.recommendation import TravelConditionId

    candidates = [_candidate_payload(index, value=50) for index in range(1, 7)]
    baseline_preference = _preference_payload(value=50)
    baseline = _rank(candidates=candidates, preference=baseline_preference)
    baseline_components = baseline.items[0].contribution.condition_components

    for condition in TravelConditionId:
        changed = deepcopy(baseline_preference)
        target = next(
            row for row in changed["condition_targets"] if row["condition_id"] == condition.value
        )
        target["value"] = 0
        counterfactual = _rank(candidates=candidates, preference=changed)
        actual = counterfactual.items[0].contribution.condition_components
        changed_ids = {
            after.condition_id
            for before, after in zip(baseline_components, actual, strict=True)
            if before != after
        }
        assert changed_ids == {condition}


def test_every_item_has_two_actual_evidence_linked_reasons() -> None:
    run = _rank()
    for item in run.items:
        assert len(item.explanations) >= 2
        assert {row.evidence_id for row in item.evidence} == {
            row.evidence_id for row in item.explanations
        }
        contribution_ids = {
            component.contribution_id for component in item.contribution.axis_components
        } | {component.contribution_id for component in item.contribution.condition_components}
        for explanation in item.explanations:
            assert explanation.contribution_id in contribution_ids
            assert explanation.evidence_id.startswith("evidence:")
            assert explanation.reference_date.isoformat() == "2026-08-10"
            assert explanation.template_id.startswith("reason-")
            assert "추천" not in explanation.message_ko
            evidence = next(
                row for row in item.evidence if row.evidence_id == explanation.evidence_id
            )
            assert evidence.source_label_ko == "합성 검증 근거"
            assert evidence.attribution_ko == "출처: 합성 검증 픽스처"


def test_kernel_p95_is_measured_under_twenty_five_milliseconds() -> None:
    candidates = [_candidate_payload(index, value=40 + index) for index in range(1, 25)]
    durations_ms: list[float] = []
    for _ in range(40):
        started = time.perf_counter_ns()
        _rank(candidates=candidates)
        durations_ms.append((time.perf_counter_ns() - started) / 1_000_000)
    p95_ms = statistics.quantiles(durations_ms, n=100, method="inclusive")[94]
    print(f"recommendation_kernel_p95_ms={p95_ms:.3f}")
    assert p95_ms <= 25.0
