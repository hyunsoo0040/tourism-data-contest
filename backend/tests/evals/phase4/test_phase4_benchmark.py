from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from argparse import Namespace
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.phase4_benchmark import (
    ATTRIBUTE_IDS,
    BenchmarkCase,
    BenchmarkExperiment,
    BenchmarkRepeat,
    BenchmarkReportState,
    BenchmarkScoreVector,
    HumanReviewInventoryItem,
    HumanVisibleEvidenceReviewEntry,
    HumanVisibleEvidenceReviewManifest,
    ReviewVerdict,
    SensitivityEvidence,
    ZeroImageFallbackProof,
    benchmark_evidence_roots,
    build_provisional_report,
    finalize_benchmark,
)
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY
from itda.domain.canonical import canonical_sha256

NOW = datetime(2026, 8, 7, 10, 0, tzinfo=UTC)


def _vector(value: int | None) -> BenchmarkScoreVector:
    return BenchmarkScoreVector.from_mapping({attribute: value for attribute in ATTRIBUTE_IDS})


def _repeat(
    value: int | None,
    *,
    repeat_index: int,
    case_ref: str = "synthetic-case",
    terminal: str = "VALID",
    image_artifact: bool = True,
) -> BenchmarkRepeat:
    return BenchmarkRepeat.build(
        repeat_index=repeat_index,
        request_identity_sha256=hashlib.sha256(
            f"request:{case_ref}:{repeat_index}".encode()
        ).hexdigest(),
        prediction_batch_sha256="7" * 64,
        terminal_status=terminal,
        schema_compliant=True,
        scores=_vector(value),
        raw_prediction_ref=(
            hashlib.sha256(f"prediction:{case_ref}:{repeat_index}".encode()).hexdigest()
            if image_artifact
            else None
        ),
    )


def _case(
    case_ref: str,
    state: ImageMediumState,
    *,
    baseline: int = 1_000,
    candidate: int | None = 2_000,
    label: int = 2_000,
    confidence: int = 99,
) -> BenchmarkCase:
    repeats = tuple(
        _repeat(
            candidate,
            repeat_index=index,
            case_ref=case_ref,
            image_artifact=candidate is not None,
        )
        for index in (1, 2, 3)
    )
    return BenchmarkCase(
        case_ref=case_ref,
        image_medium_state=state,
        baseline_scores=_vector(baseline),
        candidate_repeats=repeats,
        dev_label_scores=_vector(label),
        baseline_display_label="mixed-experience",
        candidate_display_label="mixed-experience",
        dev_display_label="mixed-experience",
        confidence_percent=confidence,
        visible_claim_count=2 if candidate is not None else 0,
        automatic_supported_claim_count=2 if candidate is not None else 0,
        named_failures=(),
    )


def _experiment(
    *,
    evaluation_scope: str = "SYNTHETIC_PROVIDER_FREE",
    case_refs: tuple[str, ...] | None = None,
    cases: tuple[BenchmarkCase, ...] = (),
    review_inventory: tuple[HumanReviewInventoryItem, ...] = (),
) -> BenchmarkExperiment:
    if case_refs is None:
        case_refs = (
            tuple(f"synthetic-v2-place-{index:02d}" for index in range(24))
            if evaluation_scope == "DEV_24_PROTECTED"
            else ()
        )
    case_inventory_sha256 = canonical_sha256(list(case_refs))
    prediction_root, label_root, review_root = benchmark_evidence_roots(
        cases,
        review_inventory,
    )
    return BenchmarkExperiment.build(
        experiment_id="korean-global-v1",
        evaluation_scope=evaluation_scope,
        dev_authority_sha256="1" * 64,
        authority_binding_sha256="1" * 64,
        prompt_config_sha256="2" * 64,
        prompt_language="KOREAN",
        prompt_routing="GLOBAL",
        selection_manifest_sha256="3" * 64,
        selection_policy_sha256="3" * 64,
        fusion_policy_sha256=CANONICAL_FUSION_POLICY.policy_sha256,
        threshold_config_sha256="4" * 64,
        seed=1729,
        code_sha256="5" * 64,
        baseline_sha256="6" * 64,
        prediction_batch_sha256="7" * 64,
        dev_case_inventory_sha256=case_inventory_sha256,
        label_case_inventory_sha256=case_inventory_sha256,
        prediction_case_records_sha256=prediction_root,
        label_case_records_sha256=label_root,
        review_inventory_sha256=review_root,
        label_version="dev-labels-v1",
        predeclared_conditional_attributes=("H1", "I1"),
        created_at=NOW,
    )


def test_metrics_compare_baseline_and_image_candidate_without_missing_imputation() -> None:
    states = tuple(ImageMediumState)
    cases = tuple(
        _case(
            f"case-{state.value.casefold()}",
            state,
            candidate=2_000 if state is ImageMediumState.QUALIFIED else None,
        )
        for state in states
    )
    report = build_provisional_report(
        experiment=_experiment(),
        cases=cases,
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )

    assert report.state is BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW
    assert report.metrics.coverage.total_count == len(states)
    assert report.metrics.coverage.usable_count == 1
    by_state = {row.image_medium_state: row for row in report.metrics.coverage.by_state}
    assert set(by_state) == set(states)
    assert by_state[ImageMediumState.MISSING].total_count == 1
    assert by_state[ImageMediumState.MISSING].usable_count == 0
    assert report.metrics.candidate_attribute_mae.value == pytest.approx(0.0)
    assert report.metrics.baseline_attribute_mae.value == pytest.approx(1.0)
    assert report.metrics.macro_attribute_mae_improvement.value == pytest.approx(1.0)
    interval = report.metrics.macro_attribute_mae_improvement_ci95
    assert interval.seed == report.experiment.seed
    assert interval.resample_count == 2000
    assert interval.eligible_count == 1
    assert interval.lower == pytest.approx(1.0)
    assert interval.upper == pytest.approx(1.0)
    assert report.metrics.candidate_attribute_mae.denominator == 12
    assert report.metrics.missing_attribute_count == 5 * 12


def test_protected_dev_scope_requires_exactly_24_terminal_cases() -> None:
    with pytest.raises(ValueError, match="exact 24-case"):
        build_provisional_report(
            experiment=_experiment(evaluation_scope="DEV_24_PROTECTED"),
            cases=(_case("case-short", ImageMediumState.QUALIFIED),),
            review_inventory=(),
            sensitivity=(),
            generated_at=NOW,
        )


def test_protected_dev_scope_rejects_24_rehashed_arbitrary_cases() -> None:
    authorized_refs = tuple(f"authorized-case-{index:02d}" for index in range(24))
    arbitrary_cases = tuple(
        _case(f"arbitrary-case-{index:02d}", ImageMediumState.QUALIFIED) for index in range(24)
    )

    with pytest.raises(ValueError, match="evidence does not match authority roots"):
        build_provisional_report(
            experiment=_experiment(
                evaluation_scope="DEV_24_PROTECTED",
                case_refs=authorized_refs,
            ),
            cases=arbitrary_cases,
            review_inventory=(),
            sensitivity=(),
            generated_at=NOW,
        )


def test_protected_dev_scope_rejects_rehashed_evidence_for_authorized_case_refs() -> None:
    cases = tuple(
        _case(f"authorized-case-{index:02d}", ImageMediumState.QUALIFIED) for index in range(24)
    )
    experiment = _experiment(
        evaluation_scope="DEV_24_PROTECTED",
        case_refs=tuple(case.case_ref for case in cases),
        cases=cases,
    )
    first = cases[0]
    mutated_repeat = BenchmarkRepeat.build(
        **{
            **first.candidate_repeats[0].model_dump(
                exclude={"execution_receipt_sha256"}, mode="json"
            ),
            "scores": _vector(3_000),
        }
    )
    mutated_case = BenchmarkCase(
        **{
            **first.model_dump(),
            "candidate_repeats": (mutated_repeat, *first.candidate_repeats[1:]),
        }
    )

    with pytest.raises(ValueError, match="evidence does not match authority roots"):
        build_provisional_report(
            experiment=experiment,
            cases=(mutated_case, *cases[1:]),
            review_inventory=(),
            sensitivity=(),
            generated_at=NOW,
        )


def test_three_repeat_stability_and_visible_automatic_checks_are_explicit() -> None:
    drifting = BenchmarkCase(
        **{
            **_case("case-drift", ImageMediumState.QUALIFIED).model_dump(),
            "candidate_repeats": (
                _repeat(1_000, repeat_index=1),
                _repeat(1_250, repeat_index=2),
                _repeat(1_500, repeat_index=3),
            ),
        }
    )
    report = build_provisional_report(
        experiment=_experiment(),
        cases=(drifting,),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )

    assert report.metrics.repeat_count == 3
    assert report.metrics.terminal_observability_agreement.value == pytest.approx(1.0)
    assert report.metrics.median_raw_score_difference.value == pytest.approx(0.25)
    assert report.metrics.automatic_visible_support_precision.value == pytest.approx(1.0)


def test_copied_provider_artifact_cannot_satisfy_three_repeat_stability() -> None:
    original = _case("case-copied-repeat", ImageMediumState.QUALIFIED)
    copied = original.candidate_repeats[0]

    with pytest.raises(ValueError, match="ordered repeat indexes|distinct execution"):
        BenchmarkCase(
            **{
                **original.model_dump(),
                "candidate_repeats": (copied, copied, copied),
            }
        )


def test_repeat_receipt_must_bind_the_frozen_prediction_batch() -> None:
    case = _case("case-wrong-freeze", ImageMediumState.QUALIFIED)
    repeats = list(case.candidate_repeats)
    repeats[2] = BenchmarkRepeat.build(
        **{
            **repeats[2].model_dump(exclude={"execution_receipt_sha256"}),
            "prediction_batch_sha256": "8" * 64,
        }
    )
    mutated = BenchmarkCase(
        **{
            **case.model_dump(),
            "candidate_repeats": tuple(repeats),
        }
    )

    with pytest.raises(ValueError, match="frozen prediction batch"):
        build_provisional_report(
            experiment=_experiment(),
            cases=(mutated,),
            review_inventory=(),
            sensitivity=(),
            generated_at=NOW,
        )


def test_partial_repeat_median_uses_nonnegative_integer_half_up_rounding() -> None:
    case = _case("case-half-unit", ImageMediumState.QUALIFIED)
    partial = BenchmarkCase(
        **{
            **case.model_dump(),
            "candidate_repeats": (
                _repeat(1_000, repeat_index=1),
                _repeat(1_001, repeat_index=2),
                _repeat(None, repeat_index=3),
            ),
        }
    )

    report = build_provisional_report(
        experiment=_experiment(),
        cases=(partial,),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )

    assert dict(report.metrics.candidate_rank_scores)[partial.case_ref] == 1_001


def test_macro_f1_rejects_asserted_label_that_drifted_from_locked_d21_scores() -> None:
    scores = BenchmarkScoreVector.from_mapping(
        {
            **{attribute: 2_600 for attribute in ATTRIBUTE_IDS[:4]},
            **{attribute: 2_120 for attribute in ATTRIBUTE_IDS[4:8]},
            **{attribute: 1_000 for attribute in ATTRIBUTE_IDS[8:]},
        }
    )
    case = _case("case-label-drift", ImageMediumState.QUALIFIED)
    repeats = tuple(
        BenchmarkRepeat.build(
            **{
                **repeat.model_dump(exclude={"execution_receipt_sha256"}),
                "scores": scores,
            }
        )
        for repeat in case.candidate_repeats
    )
    drifted = BenchmarkCase(
        **{
            **case.model_dump(),
            "candidate_repeats": repeats,
            "candidate_display_label": "mixed-experience",
        }
    )

    with pytest.raises(ValueError, match="D-21 display label claim drifted.*candidate"):
        build_provisional_report(
            experiment=_experiment(),
            cases=(drifted,),
            review_inventory=(),
            sensitivity=(),
            generated_at=NOW,
        )


def test_confidence_is_reported_but_never_changes_candidate_rank_score() -> None:
    high_confidence = _case(
        "case-high-confidence",
        ImageMediumState.QUALIFIED,
        candidate=2_000,
        confidence=100,
    )
    low_confidence = _case(
        "case-low-confidence",
        ImageMediumState.QUALIFIED,
        candidate=2_000,
        confidence=1,
    )
    report = build_provisional_report(
        experiment=_experiment(),
        cases=(high_confidence, low_confidence),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )

    scores = dict(report.metrics.candidate_rank_scores)
    assert scores[high_confidence.case_ref] == scores[low_confidence.case_ref]
    assert report.metrics.confidence_is_ranking_input is False


def test_sensitivity_alternatives_are_never_release_eligible() -> None:
    sensitivity = SensitivityEvidence(
        section="SENSITIVITY_ONLY",
        config_sha256="8" * 64,
        changed_dimensions=("D13_BASE_WEIGHTS", "D18_PUBLICATION_THRESHOLDS"),
        release_eligible=False,
    )
    report = build_provisional_report(
        experiment=_experiment(),
        cases=(_case("case-image", ImageMediumState.QUALIFIED),),
        review_inventory=(),
        sensitivity=(sensitivity,),
        generated_at=NOW,
    )

    assert report.sensitivity[0].section == "SENSITIVITY_ONLY"
    assert report.sensitivity[0].release_eligible is False

    with pytest.raises(ValueError, match="sensitivity"):
        SensitivityEvidence(
            section="SENSITIVITY_ONLY",
            config_sha256="8" * 64,
            changed_dimensions=("D16_FIDELITY_BANDS",),
            release_eligible=True,
        )


def _inventory(item_id: str, *, critical: bool = False) -> HumanReviewInventoryItem:
    return HumanReviewInventoryItem.build(
        stable_observation_id=f"observation-{item_id}",
        claim_id=f"claim-{item_id}",
        evidence_ref_id=f"evidence-{item_id}",
        representative_id=f"representative-{item_id}",
        region_caption_sha256="9" * 64,
        critical=critical,
        prediction_batch_sha256="7" * 64,
        selection_manifest_sha256="3" * 64,
    )


def _review(
    report: object,
    inventory: tuple[HumanReviewInventoryItem, ...],
    *,
    critical_verdict: ReviewVerdict = ReviewVerdict.SUPPORTED,
) -> HumanVisibleEvidenceReviewManifest:
    entries = tuple(
        HumanVisibleEvidenceReviewEntry(
            inventory_item_sha256=item.inventory_item_sha256,
            verdict=critical_verdict if item.critical else ReviewVerdict.SUPPORTED,
            notes_sha256="a" * 64,
        )
        for item in inventory
    )
    return HumanVisibleEvidenceReviewManifest.build(
        prediction_batch_sha256="7" * 64,
        provisional_report_sha256=report.provisional_report_sha256,
        selection_manifest_sha256="3" * 64,
        expected_inventory=inventory,
        entries=entries,
        reviewer_pseudonym="reviewer-01",
        completed_at=NOW,
    )


def test_image_bearing_adoption_requires_complete_human_review() -> None:
    inventory = (_inventory("safe"), _inventory("critical", critical=True))
    cases = tuple(
        _case(
            f"case-{index:02d}",
            ImageMediumState.QUALIFIED,
            baseline=500 + index * 10,
            candidate=1_000 + index * 10,
            label=1_000 + index * 10,
        )
        for index in range(24)
    )
    provisional = build_provisional_report(
        experiment=_experiment(
            evaluation_scope="DEV_24_PROTECTED",
            case_refs=tuple(case.case_ref for case in cases),
            cases=cases,
            review_inventory=inventory,
        ),
        cases=cases,
        review_inventory=inventory,
        sensitivity=(),
        generated_at=NOW,
    )

    pending = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        finalized_at=NOW,
    )
    assert pending.state is BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW

    review = _review(provisional, inventory)
    adopted = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        human_review=review,
        finalized_at=NOW,
    )
    replay = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        human_review=review,
        finalized_at=NOW,
    )
    assert adopted.state is BenchmarkReportState.ADOPT
    assert adopted.evaluation_scope == "DEV_24_PROTECTED"
    assert adopted.dev_authority_sha256 == provisional.experiment.dev_authority_sha256
    assert adopted.human_review_manifest_sha256 == review.review_manifest_sha256
    assert adopted.final_report_sha256 == replay.final_report_sha256
    assert adopted.model_dump_json() == replay.model_dump_json()


def test_protected_benchmark_rejects_cross_case_repeat_reuse() -> None:
    cases = tuple(
        _case(
            f"case-{index:02d}",
            ImageMediumState.QUALIFIED,
            baseline=500 + index,
            candidate=1_000 + index,
            label=1_000 + index,
        )
        for index in range(24)
    )
    reused = tuple(
        case.model_copy(update={"candidate_repeats": cases[0].candidate_repeats}) for case in cases
    )
    experiment = _experiment(
        evaluation_scope="DEV_24_PROTECTED",
        case_refs=tuple(case.case_ref for case in reused),
        cases=reused,
    )

    with pytest.raises(ValueError, match="globally single-use"):
        build_provisional_report(
            experiment=experiment,
            cases=reused,
            review_inventory=(),
            sensitivity=(),
            generated_at=NOW,
        )


def test_finalization_rederives_rehashed_provisional_aggregates() -> None:
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(_case("case-a", ImageMediumState.QUALIFIED),),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )
    fields = provisional.model_dump(mode="json", exclude={"provisional_report_sha256"})
    metrics = provisional.metrics.model_copy(
        update={"stability_gates_pass": False, "global_value_gates_pass": False}
    )
    fields["metrics"] = metrics.model_dump(mode="json")
    forged = type(provisional).model_validate(
        {**fields, "provisional_report_sha256": canonical_sha256(fields)}
    )

    with pytest.raises(ValueError, match="authoritative case derivation"):
        finalize_benchmark(
            provisional=forged,
            selected_config_sha256=forged.experiment.experiment_sha256,
            finalized_at=NOW,
        )


def test_stability_denominator_excludes_unscheduled_no_image_cases() -> None:
    stable = _case("case-00", ImageMediumState.QUALIFIED)
    unstable_base = _case("case-01", ImageMediumState.QUALIFIED)
    unstable = unstable_base.model_copy(
        update={
            "candidate_repeats": (
                _repeat(2_000, repeat_index=1, case_ref="case-01", terminal="VALID"),
                _repeat(2_000, repeat_index=2, case_ref="case-01", terminal="VALID"),
                _repeat(2_000, repeat_index=3, case_ref="case-01", terminal="FAILED"),
            )
        }
    )
    missing = tuple(
        _case(f"case-{index:02d}", ImageMediumState.MISSING, candidate=None)
        for index in range(2, 24)
    )
    cases = (stable, unstable, *missing)
    experiment = _experiment(
        evaluation_scope="DEV_24_PROTECTED",
        case_refs=tuple(case.case_ref for case in cases),
        cases=cases,
    )

    report = build_provisional_report(
        experiment=experiment,
        cases=cases,
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )

    assert report.metrics.terminal_observability_agreement.numerator == 1
    assert report.metrics.terminal_observability_agreement.denominator == 2
    assert report.metrics.terminal_observability_agreement.value == 0.5
    assert report.metrics.stability_gates_pass is False


def test_synthetic_benchmark_finishes_in_distinct_non_release_state() -> None:
    inventory = (_inventory("synthetic"),)
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(
            _case(
                "case-synthetic-a",
                ImageMediumState.QUALIFIED,
                baseline=500,
                candidate=1_000,
                label=1_000,
            ),
            _case(
                "case-synthetic-b",
                ImageMediumState.QUALIFIED,
                baseline=1_500,
                candidate=2_000,
                label=2_000,
            ),
        ),
        review_inventory=inventory,
        sensitivity=(),
        generated_at=NOW,
    )

    decision = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        human_review=_review(provisional, inventory),
        finalized_at=NOW,
    )

    assert decision.state is BenchmarkReportState.SYNTHETIC_EVALUATION_ONLY
    assert decision.evaluation_scope == "SYNTHETIC_PROVIDER_FREE"
    assert decision.adopted_attributes == ()
    assert decision.inherited_baseline_attributes == ATTRIBUTE_IDS


def test_critical_nonvisible_review_forces_reject() -> None:
    inventory = (_inventory("critical", critical=True),)
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(
            _case("case-a", ImageMediumState.QUALIFIED, baseline=500, candidate=1_000, label=1_000),
            _case(
                "case-b", ImageMediumState.QUALIFIED, baseline=1_500, candidate=2_000, label=2_000
            ),
        ),
        review_inventory=inventory,
        sensitivity=(),
        generated_at=NOW,
    )
    rejected = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        human_review=_review(
            provisional,
            inventory,
            critical_verdict=ReviewVerdict.NON_VISIBLE,
        ),
        finalized_at=NOW,
    )
    assert rejected.state is BenchmarkReportState.REJECT
    assert "CRITICAL_VISIBLE_EVIDENCE_REJECTED" in rejected.failures


def test_explicit_zero_image_fallback_can_finalize_without_review() -> None:
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(
            _case(
                "case-no-image",
                ImageMediumState.MISSING,
                candidate=None,
                baseline=1_000,
                label=1_000,
            ),
        ),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )
    fallback = ZeroImageFallbackProof.build(
        outcome=BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
        source_media_state=ImageMediumState.MISSING,
        provisional_report_sha256=provisional.provisional_report_sha256,
        baseline_sha256=provisional.experiment.baseline_sha256,
    )
    finalized = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        zero_image_fallback=fallback,
        finalized_at=NOW,
    )
    assert finalized.state is BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY
    assert finalized.human_review_manifest_sha256 is None
    assert finalized.image_contribution_count == 0


def test_zero_image_fallback_rejects_retained_image_refs_and_claims() -> None:
    case = _case(
        "case-resealed-image-facts",
        ImageMediumState.QUALIFIED,
        candidate=None,
    )
    repeats = tuple(
        BenchmarkRepeat.build(
            **{
                **repeat.model_dump(exclude={"execution_receipt_sha256"}, mode="json"),
                "raw_prediction_ref": f"{index + 9:x}" * 64,
            }
        )
        for index, repeat in enumerate(case.candidate_repeats, start=1)
    )
    case = BenchmarkCase.model_validate(
        {
            **case.model_dump(mode="json"),
            "candidate_repeats": [repeat.model_dump(mode="json") for repeat in repeats],
            "visible_claim_count": 1,
            "automatic_supported_claim_count": 0,
        }
    )
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(case,),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )
    fallback = ZeroImageFallbackProof.build(
        outcome=BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
        source_media_state=ImageMediumState.QUALIFIED,
        provisional_report_sha256=provisional.provisional_report_sha256,
        baseline_sha256=provisional.experiment.baseline_sha256,
    )

    with pytest.raises(ValueError, match="zero image contributions and claims"):
        finalize_benchmark(
            provisional=provisional,
            selected_config_sha256=provisional.experiment.experiment_sha256,
            zero_image_fallback=fallback,
            finalized_at=NOW,
        )


def test_non_image_case_rejects_hidden_candidate_scores_and_refs() -> None:
    with pytest.raises(ValueError, match="non-image benchmark case cannot carry candidate scores"):
        _case(
            "case-hidden-score",
            ImageMediumState.MISSING,
            candidate=1_000,
        )

    clean = _case("case-hidden-ref", ImageMediumState.MISSING, candidate=None)
    repeats = list(clean.candidate_repeats)
    repeats[0] = BenchmarkRepeat.build(
        **{
            **repeats[0].model_dump(exclude={"execution_receipt_sha256"}),
            "raw_prediction_ref": "a" * 64,
        }
    )
    with pytest.raises(
        ValueError, match="non-image benchmark case cannot carry image artifact refs"
    ):
        BenchmarkCase(
            **{
                **clean.model_dump(),
                "candidate_repeats": tuple(repeats),
            }
        )


def test_rehashed_repeat_wrappers_cannot_reuse_one_prediction_artifact() -> None:
    case = _case("case-rewrapped", ImageMediumState.QUALIFIED)
    repeats = tuple(
        BenchmarkRepeat.build(
            **{
                **repeat.model_dump(exclude={"execution_receipt_sha256"}, mode="json"),
                "raw_prediction_ref": "a" * 64,
            }
        )
        for repeat in case.candidate_repeats
    )
    with pytest.raises(ValueError, match="distinct upstream prediction artifacts"):
        BenchmarkCase(
            **{
                **case.model_dump(),
                "candidate_repeats": repeats,
            }
        )


def test_zero_image_fallback_must_bind_exact_provisional_and_baseline() -> None:
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(_case("case-bound-fallback", ImageMediumState.MISSING, candidate=None),),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )
    wrong = ZeroImageFallbackProof.build(
        outcome=BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
        source_media_state=ImageMediumState.MISSING,
        provisional_report_sha256="a" * 64,
        baseline_sha256=provisional.experiment.baseline_sha256,
    )

    with pytest.raises(ValueError, match="exact provisional baseline"):
        finalize_benchmark(
            provisional=provisional,
            selected_config_sha256=provisional.experiment.experiment_sha256,
            zero_image_fallback=wrong,
            finalized_at=NOW,
        )


def test_sensitivity_digest_cannot_be_selected_for_terminal_decision() -> None:
    sensitivity = SensitivityEvidence(
        section="SENSITIVITY_ONLY",
        config_sha256="c" * 64,
        changed_dimensions=("D21_LABEL_THRESHOLDS",),
        release_eligible=False,
    )
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(_case("case-image", ImageMediumState.QUALIFIED),),
        review_inventory=(),
        sensitivity=(sensitivity,),
        generated_at=NOW,
    )
    with pytest.raises(ValueError, match="SENSITIVITY_ONLY"):
        finalize_benchmark(
            provisional=provisional,
            selected_config_sha256=sensitivity.config_sha256,
            finalized_at=NOW,
        )


def test_only_predeclared_passing_attributes_can_conditionally_adopt() -> None:
    def conditional_case(case_ref: str, label_value: int) -> BenchmarkCase:
        labels = {attribute: label_value for attribute in ATTRIBUTE_IDS}
        baseline = dict(labels)
        baseline["H1"] -= 500
        candidate = BenchmarkScoreVector.from_mapping(labels)
        return BenchmarkCase(
            case_ref=case_ref,
            image_medium_state=ImageMediumState.QUALIFIED,
            baseline_scores=BenchmarkScoreVector.from_mapping(baseline),
            candidate_repeats=tuple(
                BenchmarkRepeat.build(
                    repeat_index=index,
                    request_identity_sha256=hashlib.sha256(
                        f"request:{case_ref}:{index}".encode()
                    ).hexdigest(),
                    prediction_batch_sha256="7" * 64,
                    terminal_status="VALID",
                    schema_compliant=True,
                    scores=candidate,
                    raw_prediction_ref=hashlib.sha256(
                        f"prediction:{case_ref}:{index}".encode()
                    ).hexdigest(),
                )
                for index in (1, 2, 3)
            ),
            dev_label_scores=BenchmarkScoreVector.from_mapping(labels),
            baseline_display_label="mixed-experience",
            candidate_display_label="mixed-experience",
            dev_display_label="mixed-experience",
            confidence_percent=50,
            visible_claim_count=1,
            automatic_supported_claim_count=1,
            named_failures=(),
        )

    inventory = (_inventory("conditional"),)
    cases = tuple(conditional_case(f"case-{index:02d}", 1_000 + index * 40) for index in range(24))
    provisional = build_provisional_report(
        experiment=_experiment(
            evaluation_scope="DEV_24_PROTECTED",
            case_refs=tuple(case.case_ref for case in cases),
            cases=cases,
            review_inventory=inventory,
        ),
        cases=cases,
        review_inventory=inventory,
        sensitivity=(),
        generated_at=NOW,
    )
    assert provisional.metrics.global_value_gates_pass is False
    assert provisional.metrics.noninferiority_gates_pass is True

    decision = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        human_review=_review(provisional, inventory),
        finalized_at=NOW,
    )
    assert decision.state is BenchmarkReportState.CONDITIONAL_ADOPT
    assert decision.adopted_attributes == ("H1",)
    assert "I1" in decision.inherited_baseline_attributes


def test_missing_external_evidence_remains_pending() -> None:
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(_case("case-image", ImageMediumState.QUALIFIED),),
        review_inventory=(_inventory("pending"),),
        sensitivity=(),
        generated_at=NOW,
    )
    decision = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        external_evidence_complete=False,
        finalized_at=NOW,
    )
    assert decision.state is BenchmarkReportState.PENDING_EXTERNAL_EVIDENCE


def test_explicit_image_rejected_fallback_is_also_terminal_without_review() -> None:
    provisional = build_provisional_report(
        experiment=_experiment(),
        cases=(
            _case(
                "case-rejected-image",
                ImageMediumState.ANALYSIS_FAILED,
                candidate=None,
                baseline=1_000,
                label=1_000,
            ),
        ),
        review_inventory=(),
        sensitivity=(),
        generated_at=NOW,
    )
    fallback = ZeroImageFallbackProof.build(
        outcome=BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
        source_media_state=ImageMediumState.ANALYSIS_FAILED,
        provisional_report_sha256=provisional.provisional_report_sha256,
        baseline_sha256=provisional.experiment.baseline_sha256,
    )
    decision = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        zero_image_fallback=fallback,
        finalized_at=NOW,
    )
    assert decision.state is BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY
    assert decision.image_contribution_count == 0


def _phase4_demo_actual_inputs() -> tuple[Path, Path, Path, Path]:
    import itda.cli.run_phase4_demo as demo

    repository_root = demo._REPOSITORY_ROOT
    return (
        repository_root / "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json",
        repository_root
        / "artifacts/restricted/catalog/v2/sqlite/releases"
        / "e45fae2e591542c1ecd8cc041ce4d2af863944f57be593ad38bfc196cf289ed0"
        / "evaluation-authority.sqlite3",
        repository_root / "artifacts/restricted/catalog/v1/collection/snapshots",
        repository_root
        / "artifacts/catalog/optional-media-v2/policy"
        / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
        / "projected-candidates.json",
    )


def _materialize_phase4_demo_explicit(
    *,
    artifact_root: Path,
    receipt_output: Path,
    image_root: Path | None = None,
    rights_manifest: Path | None = None,
    image_selection_manifest: Path | None = None,
) -> int:
    from itda.cli.run_phase4_demo import _materialize_from_explicit_inputs

    catalog_audit, dev_sqlite, snapshot_root, optional_media = _phase4_demo_actual_inputs()
    return _materialize_from_explicit_inputs(
        Namespace(
            catalog_audit=catalog_audit,
            dev_sqlite=dev_sqlite,
            snapshot_root=snapshot_root,
            optional_media=optional_media,
            artifact_root=artifact_root,
            receipt_output=receipt_output,
            image_root=image_root,
            rights_manifest=rights_manifest,
            image_selection_manifest=image_selection_manifest,
        ),
        allow_synthetic_test_inputs=True,
    )


def test_phase4_demo_dev_membership_uses_the_exact_stable_sqlite_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import itda.cli.run_phase4_demo as demo

    database_path = tmp_path / "authority.sqlite3"
    hostile_path = tmp_path / "hostile.sqlite3"

    def write_database(path: Path, prefix: str) -> tuple[str, ...]:
        expected = tuple(f"place:{prefix}{index:062x}" for index in range(24))
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                "CREATE TABLE manifest_members ("
                "canonical_place_id TEXT NOT NULL, split TEXT NOT NULL, "
                "manifest_version INTEGER NOT NULL, member_ordinal INTEGER NOT NULL)"
            )
            connection.executemany(
                "INSERT INTO manifest_members VALUES (?, 'DEV', 1, ?)",
                tuple((place_ref, index) for index, place_ref in enumerate(expected)),
            )
            connection.commit()
        finally:
            connection.close()
        return expected

    trusted_refs = write_database(database_path, "aa")
    write_database(hostile_path, "bb")
    trusted_bytes = database_path.read_bytes()
    original_stable_read = demo._stable_read
    calls = 0

    def swapping_read(path: Path, *, max_bytes: int = demo._MAX_JSON_BYTES) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            result = original_stable_read(path, max_bytes=max_bytes)
            os.replace(hostile_path, path)
            return result
        path.write_bytes(trusted_bytes)
        return original_stable_read(path, max_bytes=max_bytes)

    monkeypatch.setattr(demo, "_stable_read", swapping_read)

    actual_refs, actual_bytes = demo._read_dev_place_refs(database_path)

    assert calls == 1
    assert actual_refs == trusted_refs
    assert actual_bytes == trusted_bytes


def _terminal_contract_fields(*, replay: bool) -> tuple[dict[str, object], dict[str, object]]:
    from itda.domain.canonical import canonical_sha256

    state = {
        "provider_mode": "PROVIDER_REPLAY" if replay else "NO_PROVIDER_NO_IMAGE",
        "terminal_decision": ("PROVIDER_REPLAY_REVIEWED" if replay else "NO_IMAGE_TEXT_ODII_ONLY"),
        "image_review_gate": "COMPLETED" if replay else "NOT_APPLICABLE",
        "image_claim_inventory_count": 1 if replay else 0,
        "human_decision_receipt_sha256": "a" * 64 if replay else None,
        "image_truth": "REAL_LOCAL_IMAGES" if replay else "NO_IMAGE_TEXT_ODII_ONLY",
    }
    shared: dict[str, object] = {
        "manifest_sha256": "1" * 64,
        "materialization_receipt_sha256": "2" * 64,
        "prediction_receipt_sha256": "3" * 64,
        "evaluation_preparation_sha256": "4" * 64,
        **state,
        "source_truth": "REAL_LOCAL_DATA",
        "profile_truth": "SOURCE_EVIDENCE_ONLY",
        "profile_score_truth": "NO_LOCAL_PROFILE_SCORES",
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    report = {
        "schema_version": "itda.phase4-demo-terminal-report.v1",
        **shared,
        "observation_batch_sha256": "5" * 64,
        "freeze_receipt_sha256": "6" * 64,
    }
    report["terminal_report_sha256"] = canonical_sha256(report)
    receipt = {
        "schema_version": "itda.phase4-demo-terminal-receipt.v1",
        **shared,
        "terminal_report_sha256": report["terminal_report_sha256"],
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return report, receipt


@pytest.mark.parametrize("contract", ["report", "receipt"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("terminal_decision", "PROVIDER_REPLAY_REVIEWED"),
        ("image_review_gate", "COMPLETED"),
        ("image_claim_inventory_count", 1),
        ("human_decision_receipt_sha256", "a" * 64),
        ("image_truth", "REAL_LOCAL_IMAGES"),
    ],
)
def test_phase4_terminal_contract_rejects_cross_product_truth_mutations(
    contract: str,
    field: str,
    value: object,
) -> None:
    from itda.contracts.phase4_demo import (
        Phase4DemoTerminalReceipt,
        Phase4DemoTerminalReport,
    )
    from itda.domain.canonical import canonical_sha256

    report, receipt = _terminal_contract_fields(replay=False)
    payload = report if contract == "report" else receipt
    digest_field = "terminal_report_sha256" if contract == "report" else "receipt_sha256"
    payload[field] = value
    payload[digest_field] = canonical_sha256(
        {key: nested for key, nested in payload.items() if key != digest_field}
    )
    model = Phase4DemoTerminalReport if contract == "report" else Phase4DemoTerminalReceipt

    with pytest.raises(ValueError, match="approved exhaustive state"):
        model.model_validate(payload)


def test_phase4_terminal_receipt_must_mirror_the_referenced_report() -> None:
    from itda.contracts.phase4_demo import (
        Phase4DemoTerminalReceipt,
        Phase4DemoTerminalReport,
        validate_terminal_receipt_report,
    )
    from itda.domain.canonical import canonical_sha256

    report_fields, _ = _terminal_contract_fields(replay=True)
    _, receipt_fields = _terminal_contract_fields(replay=False)
    receipt_fields["terminal_report_sha256"] = report_fields["terminal_report_sha256"]
    receipt_fields["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in receipt_fields.items() if key != "receipt_sha256"}
    )
    report = Phase4DemoTerminalReport.model_validate(report_fields)
    receipt = Phase4DemoTerminalReceipt.model_validate(receipt_fields)

    with pytest.raises(ValueError, match="does not mirror"):
        validate_terminal_receipt_report(receipt, report)


def _frozen_source_snapshot_payload() -> dict[str, object]:
    from itda.domain.canonical import canonical_json_bytes

    body = canonical_json_bytes({"response": {"body": {"items": []}}})
    return {
        "endpoint": "KorService2/areaBasedList2",
        "http_status": 200,
        "modifiedtime": None,
        "payload": json.loads(body),
        "provider": "TOUR_API",
        "provider_result_code": "0000",
        "provider_result_value": "OK",
        "raw_response_sha256": hashlib.sha256(body).hexdigest(),
        "raw_body_base64": b64encode(body).decode("ascii"),
        "request_scope": {"MobileOS": "ETC", "pageNo": "1"},
        "retrieved_at": "2026-08-07T10:00:00Z",
        "retry_disposition": "DO_NOT_RETRY",
        "rights": [],
        "normalized_outcome": "SUCCESS",
        "official_dataset_id": "15101578",
        "dataset_rights_identity": None,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_response_sha256", "b" * 64),
        ("endpoint", "KorService2/detailCommon2"),
        ("official_dataset_id", "15101971"),
        ("dataset_rights_identity", "KOGL_TYPE_1_ATTRIBUTION"),
        ("http_status", 500),
        ("provider_result_code", "00"),
        ("payload", {"tampered": True}),
    ],
)
def test_phase4_frozen_source_snapshot_rejects_mutated_authority(
    field: str,
    value: object,
) -> None:
    from itda.contracts.phase4_demo import FrozenDemoSourceSnapshot

    payload = _frozen_source_snapshot_payload()
    payload[field] = value

    with pytest.raises(ValueError):
        FrozenDemoSourceSnapshot.model_validate(payload)


def test_phase4_catalog_dev_rows_require_exact_tourapi_snapshot_lineage() -> None:
    from itda.cli.run_phase4_demo import _load_catalog_dev_rows
    from itda.domain.canonical import canonical_sha256

    trusted_hash = "a" * 64
    rows: list[dict[str, object]] = []
    for index in range(36):
        row: dict[str, object] = {
            "canonical_place_id": f"place:{index:064x}",
            "rights_provenance": {
                "assets": [
                    {
                        "official_dataset_id": "15101578",
                        "source_response_sha256": trusted_hash,
                    }
                ]
            },
        }
        row["canonical_row_sha256"] = canonical_sha256(row)
        rows.append(row)
    place_refs = tuple(str(row["canonical_place_id"]) for row in rows[:24])
    payload = {
        "schema_version": "itda.catalog-v2-final-audit.v1",
        "row_count": 36,
        "rows": rows,
    }

    selected, odii_lineage = _load_catalog_dev_rows(payload, place_refs, {trusted_hash}, set())
    assert len(selected) == 24
    assert set(odii_lineage.values()) == {"ODII_UNAVAILABLE"}

    first = rows[0]
    rights = first["rights_provenance"]
    assert isinstance(rights, dict)
    assets = rights["assets"]
    assert isinstance(assets, list)
    asset = assets[0]
    assert isinstance(asset, dict)
    asset["source_response_sha256"] = "b" * 64
    first["canonical_row_sha256"] = canonical_sha256(
        {key: value for key, value in first.items() if key != "canonical_row_sha256"}
    )

    with pytest.raises(ValueError, match="outside the validated snapshot inventory"):
        _load_catalog_dev_rows(payload, place_refs, {trusted_hash}, set())


def test_phase4_snapshot_inventory_must_exhaust_collection_successes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    import itda.cli.run_phase4_demo as demo
    from itda.domain.canonical import canonical_json_bytes

    snapshot_root = tmp_path / "collection" / "snapshots"
    snapshot_root.mkdir(parents=True)
    snapshot_payload = _frozen_source_snapshot_payload()
    (snapshot_root / "one.json").write_bytes(canonical_json_bytes(snapshot_payload) + b"\n")
    (snapshot_root.parent / "collection-report.json").write_bytes(b"placeholder")

    identities = []
    attempts = []
    first_hash = str(snapshot_payload["raw_response_sha256"])
    for index in range(33):
        request_identity = f"{index + 1:064x}"
        raw_hash = first_hash if index == 0 else hashlib.sha256(str(index).encode()).hexdigest()
        scope = {"MobileOS": "ETC", "pageNo": str(index + 1)}
        identities.append(
            SimpleNamespace(
                request_identity=request_identity,
                provider="TOUR_API",
                official_dataset_id="15101578",
                operation="areaBasedList2",
                secret_free_parameters=scope,
            )
        )
        attempts.append(
            SimpleNamespace(
                request_identity=request_identity,
                terminal_state="SUCCESS",
                raw_body_sha256=raw_hash,
                http_status=200,
                provider_result_code="0000",
                provider_result_value="OK",
                retry_classification="DO_NOT_RETRY",
            )
        )
    identities[0].secret_free_parameters = snapshot_payload["request_scope"]
    report = SimpleNamespace(
        request_identities=tuple(identities),
        attempts=tuple(attempts),
    )
    original_loader = demo._load_collector_mapping

    def load_artifact(path: Path) -> tuple[bytes, dict[str, object]]:
        if path.name == "collection-report.json":
            return b"report\n", {}
        return original_loader(path)

    monkeypatch.setattr(demo, "_load_collector_mapping", load_artifact)
    monkeypatch.setattr(
        demo.CollectionReport,
        "model_validate",
        classmethod(lambda _cls, _payload: report),
    )
    monkeypatch.setattr(demo, "_validate_permission_evidence", lambda _report: None)

    with pytest.raises(ValueError, match="does not exhaust"):
        demo._validated_snapshot_sources(snapshot_root)


def test_phase4_collection_authority_rejects_rehashed_report_root() -> None:
    import itda.cli.run_phase4_demo as demo

    _, _, snapshot_root, _ = _phase4_demo_actual_inputs()
    sources, report_raw = demo._validated_snapshot_sources(snapshot_root)
    demo._require_trusted_collection_authority(report_raw, sources)
    with pytest.raises(ValueError, match="trusted local authority receipt"):
        demo._require_trusted_collection_authority(report_raw + b" ", sources)


def test_phase4_demo_local_materialization_freezes_actual_no_image_inputs(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "restricted"
    receipt_path = tmp_path / "materialization-receipt.json"
    assert (
        _materialize_phase4_demo_explicit(
            artifact_root=artifact_root,
            receipt_output=receipt_path,
        )
        == 0
    )
    first_receipt_bytes = receipt_path.read_bytes()
    assert (
        _materialize_phase4_demo_explicit(
            artifact_root=artifact_root,
            receipt_output=receipt_path,
        )
        == 0
    )
    assert receipt_path.read_bytes() == first_receipt_bytes

    receipt = json.loads(first_receipt_bytes)
    assert receipt["schema_version"] == "itda.phase4-demo-materialization-receipt.v2"
    assert receipt["dev_row_count"] == 24
    assert receipt["snapshot_counts"] == {
        "ODII": 11,
        "TOURISM_PHOTO": 11,
        "TOUR_API": 11,
    }
    assert receipt["tourism_photo_included_count"] == 0
    assert receipt["tourism_photo_excluded_count"] == 11
    assert receipt["selected_image_count"] == 0
    assert receipt["source_truth"] == "LOCAL_COLLECTION_AUTHORITY_PARTIAL"
    assert receipt["profile_truth"] == "SOURCE_EVIDENCE_ONLY"
    assert receipt["profile_score_truth"] == "NO_LOCAL_PROFILE_SCORES"
    assert receipt["image_truth"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert receipt["benchmark_truth"] == "NO_REAL_IMAGE_BENCHMARK"

    private_manifest = artifact_root / receipt["manifest_sha256"] / "phase4-demo-manifest.json"
    payload = json.loads(private_manifest.read_bytes())
    assert len(payload["dev_places"]) == 24
    assert {row["odii_lineage"] for row in payload["dev_places"]} == {"ODII_UNAVAILABLE"}
    photo_rows = [row for row in payload["source_inventory"] if row["role"] == "TOURISM_PHOTO"]
    assert len(photo_rows) == 11
    assert {row["disposition"] for row in photo_rows} == {"NO_EXACT_DEV_CLAIM_BINDING"}
    assert all(len(row["source_sha256"]) == 64 for row in photo_rows)


def test_phase4_demo_local_materialization_rejects_partial_image_flag_set(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="all-or-none"):
        _materialize_phase4_demo_explicit(
            artifact_root=tmp_path / "restricted",
            receipt_output=tmp_path / "receipt.json",
            image_root=tmp_path,
        )


def _write_phase4_demo_image_authority(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    from itda.analysis.image.secure_read import ApprovedImageMaterialization
    from itda.contracts.catalog_optional_media import ImageMediumState
    from itda.contracts.image_selection import (
        AssetDecisionCode,
        AssetDecisionTrace,
        ImageSelectionBatchInput,
        ImageSelectionBatchManifest,
        ImageSelectionManifest,
        PlaceImageSelectionCandidate,
        SceneGroup,
        SelectedRepresentative,
        SelectionAssetSource,
        SelectionAuthorityScope,
    )
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256

    _, database_path, _, _ = _phase4_demo_actual_inputs()
    connection = sqlite3.connect(f"file:{database_path}?mode=ro&immutable=1", uri=True)
    try:
        place_ref = str(
            connection.execute(
                "SELECT canonical_place_id FROM manifest_members "
                "WHERE split = ? ORDER BY member_ordinal LIMIT 1",
                ("DEV",),
            ).fetchone()[0]
        )
    finally:
        connection.close()

    image_root = tmp_path / "images"
    image_root.mkdir(mode=0o700)
    image_path = image_root / "selected-image.bin"
    source_bytes = b"actual-local-public-tourism-image-bytes"
    image_path.write_bytes(source_bytes)
    image_path.chmod(0o600)
    content_sha256 = hashlib.sha256(source_bytes).hexdigest()
    approved = ApprovedImageMaterialization(
        rights_leaf_id="rights-leaf-1",
        rights_leaf_sha256="1" * 64,
        content_sha256=content_sha256,
    )
    assert approved.materialization_sha256 is not None
    source = SelectionAssetSource(
        source_asset_id="asset-1",
        relative_path=image_path.name,
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        content_sha256=approved.content_sha256,
        materialization_sha256=approved.materialization_sha256,
        temporary_event=False,
    )
    authority_sha256 = "2" * 64
    candidate = PlaceImageSelectionCandidate(
        place_entity_id=place_ref,
        authority_scope=SelectionAuthorityScope.AUTHORIZED_CALIBRATION,
        input_authority_sha256=authority_sha256,
        media_state=ImageMediumState.QUALIFIED,
        assets=(source,),
    )
    rights = ImageSelectionBatchInput.build(
        authority_scope=SelectionAuthorityScope.AUTHORIZED_CALIBRATION,
        input_authority_sha256=authority_sha256,
        places=(candidate,),
    )
    representative_id = "3" * 64
    scene_group_id = "4" * 64
    asset_sha256 = "5" * 64
    preprocessing_sha256 = "6" * 64
    trace_fields = {
        "source_asset_id": source.source_asset_id,
        "input_media_state": ImageMediumState.QUALIFIED,
        "decision_code": AssetDecisionCode.REPRESENTATIVE,
        "rights_leaf_id": source.rights_leaf_id,
        "rights_leaf_sha256": source.rights_leaf_sha256,
        "materialization_sha256": source.materialization_sha256,
        "preprocessing_policy_sha256": preprocessing_sha256,
        "asset_sha256": asset_sha256,
        "perceptual_hash": "0" * 16,
        "quality_score_milli": 900,
        "crop_quality_milli": 900,
        "temporary_event": False,
        "duplicate_of_asset_id": None,
        "scene_group_id": scene_group_id,
        "representative_id": representative_id,
    }
    trace = AssetDecisionTrace.model_validate(
        {**trace_fields, "decision_trace_sha256": canonical_sha256(trace_fields)}
    )
    representative = SelectedRepresentative(
        representative_id=representative_id,
        source_asset_id=source.source_asset_id,
        scene_group_id=scene_group_id,
        asset_sha256=asset_sha256,
        normalized_pixel_sha256="7" * 64,
        rights_leaf_id=source.rights_leaf_id,
        rights_leaf_sha256=source.rights_leaf_sha256,
        materialization_sha256=source.materialization_sha256,
        preprocessing_policy_sha256=preprocessing_sha256,
        quality_score_milli=900,
        temporary_event=False,
    )
    manifest_fields = {
        "schema_version": "itda.image-selection-manifest.v1",
        "place_entity_id": place_ref,
        "authority_scope": SelectionAuthorityScope.AUTHORIZED_CALIBRATION,
        "input_authority_sha256": authority_sha256,
        "input_candidate_sha256": candidate.recompute_input_sha256(),
        "media_state": ImageMediumState.QUALIFIED,
        "zero_image_reason": None,
        "selection_policy_sha256": "8" * 64,
        "preprocessing_policy_sha256": preprocessing_sha256,
        "model_id": "google/siglip2-base-patch16-224",
        "model_revision": "02c35f2c035e0ed4a367fb10a892c1fe2a3f364e",
        "model_weight_sha256": "9" * 64,
        "asset_decisions": [trace.model_dump(mode="json")],
        "scene_groups": [
            SceneGroup(
                scene_group_id=scene_group_id,
                member_asset_ids=(source.source_asset_id,),
                representative_asset_id=source.source_asset_id,
            ).model_dump(mode="json")
        ],
        "representatives": [representative.model_dump(mode="json")],
    }
    manifest = ImageSelectionManifest.model_validate(
        {**manifest_fields, "manifest_sha256": canonical_sha256(manifest_fields)}
    )
    selection = ImageSelectionBatchManifest.build(
        input_manifest_sha256=rights.input_manifest_sha256,
        selection_policy_sha256="8" * 64,
        manifests=(manifest,),
    )
    rights_path = tmp_path / "rights.json"
    selection_path = tmp_path / "selection.json"
    rights_path.write_bytes(canonical_json_bytes(rights.model_dump(mode="json")))
    selection_path.write_bytes(canonical_json_bytes(selection.model_dump(mode="json")))
    return image_root, rights_path, selection_path, image_path


def _materialize_phase4_demo_image(
    tmp_path: Path,
    image_root: Path,
    rights_path: Path,
    selection_path: Path,
) -> int:
    return _materialize_phase4_demo_explicit(
        artifact_root=tmp_path / "restricted",
        receipt_output=tmp_path / "receipt.json",
        image_root=image_root.resolve(),
        rights_manifest=rights_path,
        image_selection_manifest=selection_path,
    )


def test_phase4_demo_local_materialization_hashes_one_manifest_selected_image(
    tmp_path: Path,
) -> None:
    image_root, rights_path, selection_path, _ = _write_phase4_demo_image_authority(tmp_path)
    assert _materialize_phase4_demo_image(tmp_path, image_root, rights_path, selection_path) == 0
    receipt = json.loads((tmp_path / "receipt.json").read_bytes())
    assert receipt["selected_image_count"] == 1
    assert receipt["image_truth"] == "REAL_LOCAL_IMAGES"
    private = json.loads(
        (
            tmp_path / "restricted" / receipt["manifest_sha256"] / "phase4-demo-manifest.json"
        ).read_bytes()
    )
    assert len(private["selected_images"]) == 1


@pytest.mark.parametrize("attack", ["digest", "symlink", "hardlink"])
def test_phase4_demo_local_materialization_rejects_unsafe_selected_image(
    tmp_path: Path,
    attack: str,
) -> None:
    image_root, rights_path, selection_path, image_path = _write_phase4_demo_image_authority(
        tmp_path
    )
    if attack == "digest":
        image_path.write_bytes(b"changed-after-authority")
    elif attack == "symlink":
        target = tmp_path / "outside.bin"
        target.write_bytes(b"actual-local-public-tourism-image-bytes")
        image_path.unlink()
        image_path.symlink_to(target)
    else:
        os.link(image_path, image_root / "second-link.bin")
    with pytest.raises((ValueError, OSError)):
        _materialize_phase4_demo_image(tmp_path, image_root, rights_path, selection_path)


def _copy_phase4_demo_actual_materialization(tmp_path: Path) -> tuple[Path, Path]:
    from itda.cli.run_phase4_demo import main

    artifact_root = tmp_path / "restricted"
    receipt_path = tmp_path / "materialization-receipt.json"
    assert (
        main(
            [
                "materialize",
                "--artifact-root",
                str(artifact_root),
                "--receipt-output",
                str(receipt_path),
            ]
        )
        == 0
    )
    return receipt_path, artifact_root


def test_phase4_demo_no_image_observe_freezes_fact_free_batch_without_replay(
    tmp_path: Path,
) -> None:
    from itda.cli.run_phase4_demo import main

    materialization_receipt, artifact_root = _copy_phase4_demo_actual_materialization(tmp_path)
    prediction_receipt = tmp_path / "prediction-receipt.json"
    arguments = [
        "observe",
        "--materialization-receipt",
        str(materialization_receipt),
        "--artifact-root",
        str(artifact_root),
        "--provider-mode",
        "auto",
        "--replay-fixture",
        str(tmp_path / "must-not-be-opened.json"),
        "--receipt-output",
        str(prediction_receipt),
    ]

    assert main(arguments) == 0
    first = prediction_receipt.read_bytes()
    assert main(arguments) == 0
    assert prediction_receipt.read_bytes() == first

    receipt = json.loads(first)
    assert receipt["schema_version"] == "itda.phase4-demo-prediction-receipt.v1"
    assert receipt["provider_mode"] == "NO_PROVIDER_NO_IMAGE"
    assert receipt["observation_count"] == 24
    assert receipt["image_claim_inventory_count"] == 0
    assert receipt["image_truth"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert receipt["benchmark_truth"] == "NO_REAL_IMAGE_BENCHMARK"

    frozen_path = artifact_root / receipt["manifest_sha256"] / "frozen-observations.json"
    frozen = json.loads(frozen_path.read_bytes())
    assert len(frozen["observations"]) == 24
    assert all(row["provider_called"] is False for row in frozen["observations"])
    assert all(row["observation"]["observations"] == [] for row in frozen["observations"])


def test_phase4_demo_no_image_observe_rejects_explicit_live_mode(tmp_path: Path) -> None:
    from itda.cli.run_phase4_demo import main

    materialization_receipt, artifact_root = _copy_phase4_demo_actual_materialization(tmp_path)
    with pytest.raises(SystemExit, match="rejected invalid"):
        main(
            [
                "observe",
                "--materialization-receipt",
                str(materialization_receipt),
                "--artifact-root",
                str(artifact_root),
                "--provider-mode",
                "live",
                "--replay-fixture",
                str(tmp_path / "must-not-be-opened.json"),
                "--receipt-output",
                str(tmp_path / "prediction-receipt.json"),
            ]
        )


def test_phase4_demo_synthetic_image_receipt_is_rejected_by_observe(
    tmp_path: Path,
) -> None:
    from itda.cli.run_phase4_demo import main

    image_root, rights_path, selection_path, _ = _write_phase4_demo_image_authority(tmp_path)
    assert _materialize_phase4_demo_image(tmp_path, image_root, rights_path, selection_path) == 0
    with pytest.raises(SystemExit, match="rejected invalid"):
        main(
            [
                "observe",
                "--materialization-receipt",
                str(tmp_path / "receipt.json"),
                "--artifact-root",
                str(tmp_path / "restricted"),
                "--provider-mode",
                "auto",
                "--replay-fixture",
                str(tmp_path / "synthetic-replay.json"),
                "--receipt-output",
                str(tmp_path / "prediction-receipt.json"),
            ]
        )


def test_phase4_demo_synthetic_image_receipt_is_rejected_by_finalize(
    tmp_path: Path,
) -> None:
    from itda.cli.run_phase4_demo import main

    image_root, rights_path, selection_path, _ = _write_phase4_demo_image_authority(tmp_path)
    assert _materialize_phase4_demo_image(tmp_path, image_root, rights_path, selection_path) == 0
    with pytest.raises(SystemExit, match="rejected invalid"):
        main(
            [
                "finalize",
                "--materialization-receipt",
                str(tmp_path / "receipt.json"),
                "--prediction-receipt",
                str(tmp_path / "synthetic-prediction-receipt.json"),
                "--artifact-root",
                str(tmp_path / "restricted"),
                "--receipt-output",
                str(tmp_path / "terminal-receipt.json"),
            ]
        )


def _prepare_phase4_demo_no_image_run(tmp_path: Path) -> tuple[Path, Path, Path]:
    from itda.cli.run_phase4_demo import main

    materialization_receipt, artifact_root = _copy_phase4_demo_actual_materialization(tmp_path)
    prediction_receipt = tmp_path / "prediction-receipt.json"
    assert (
        main(
            [
                "observe",
                "--materialization-receipt",
                str(materialization_receipt),
                "--artifact-root",
                str(artifact_root),
                "--provider-mode",
                "auto",
                "--replay-fixture",
                str(tmp_path / "unused-replay.json"),
                "--receipt-output",
                str(prediction_receipt),
            ]
        )
        == 0
    )
    return materialization_receipt, prediction_receipt, artifact_root


def test_fact_free_batch_rejects_rehashed_provider_replay_receipt(tmp_path: Path) -> None:
    from itda.cli.run_phase4_demo import main
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256

    materialization_receipt, prediction_receipt, artifact_root = _prepare_phase4_demo_no_image_run(
        tmp_path
    )
    forged = json.loads(prediction_receipt.read_bytes())
    forged["provider_mode"] = "PROVIDER_REPLAY"
    forged["image_claim_inventory_count"] = 1
    forged["image_truth"] = "REAL_LOCAL_IMAGES"
    forged["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "receipt_sha256"}
    )
    prediction_receipt.write_bytes(canonical_json_bytes(forged))

    with pytest.raises(SystemExit, match="rejected invalid"):
        main(
            [
                "prepare-evaluation",
                "--materialization-receipt",
                str(materialization_receipt),
                "--prediction-receipt",
                str(prediction_receipt),
                "--artifact-root",
                str(artifact_root),
            ]
        )


def test_phase4_demo_no_image_evaluation_finalizes_without_review_or_metrics(
    tmp_path: Path,
) -> None:
    from itda.cli.run_phase4_demo import main

    materialization_receipt, prediction_receipt, artifact_root = _prepare_phase4_demo_no_image_run(
        tmp_path
    )
    prepare_arguments = [
        "prepare-evaluation",
        "--materialization-receipt",
        str(materialization_receipt),
        "--prediction-receipt",
        str(prediction_receipt),
        "--artifact-root",
        str(artifact_root),
    ]
    assert main(prepare_arguments) == 0

    terminal_receipt = tmp_path / "terminal-receipt.json"
    final_arguments = [
        "finalize",
        "--materialization-receipt",
        str(materialization_receipt),
        "--prediction-receipt",
        str(prediction_receipt),
        "--artifact-root",
        str(artifact_root),
        "--receipt-output",
        str(terminal_receipt),
    ]
    assert main(final_arguments) == 0
    first = terminal_receipt.read_bytes()
    assert main(final_arguments) == 0
    assert terminal_receipt.read_bytes() == first

    receipt = json.loads(first)
    assert receipt["terminal_decision"] == "NO_IMAGE_TEXT_ODII_ONLY"
    assert receipt["provider_mode"] == "NO_PROVIDER_NO_IMAGE"
    assert receipt["image_review_gate"] == "NOT_APPLICABLE"
    assert receipt["image_claim_inventory_count"] == 0
    assert receipt["human_decision_receipt_sha256"] is None
    assert receipt["benchmark_truth"] == "NO_REAL_IMAGE_BENCHMARK"
    run_root = artifact_root / receipt["manifest_sha256"]
    assert not (run_root / "image-review-inventory.json").exists()
    assert not (run_root / "human-review-receipt.json").exists()
    terminal = json.loads((run_root / "phase4-demo-terminal-report.json").read_bytes())
    assert "metrics" not in terminal
    assert "labels" not in terminal


def test_phase4_demo_no_image_finalize_rejects_human_review_input(tmp_path: Path) -> None:
    from itda.cli.run_phase4_demo import main

    materialization_receipt, prediction_receipt, artifact_root = _prepare_phase4_demo_no_image_run(
        tmp_path
    )
    assert (
        main(
            [
                "prepare-evaluation",
                "--materialization-receipt",
                str(materialization_receipt),
                "--prediction-receipt",
                str(prediction_receipt),
                "--artifact-root",
                str(artifact_root),
            ]
        )
        == 0
    )
    with pytest.raises(SystemExit, match="rejected invalid"):
        main(
            [
                "finalize",
                "--materialization-receipt",
                str(materialization_receipt),
                "--prediction-receipt",
                str(prediction_receipt),
                "--artifact-root",
                str(artifact_root),
                "--review-decisions",
                str(tmp_path / "must-not-be-opened.json"),
                "--receipt-output",
                str(tmp_path / "terminal-receipt.json"),
            ]
        )
