from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from itda.contracts.recommendation import (
    CANONICAL_RECOMMENDATION_CONFIG,
    EvidenceConfidenceState,
    PlaceTraitSnapshot,
    RecommendationConfig,
    RecommendationDetail,
    RecommendationItem,
    RecommendationReleaseDisclosure,
    SavedPlaceProjection,
)


def test_configuration_is_strict_self_digesting_and_exactly_totaled() -> None:
    payload = CANONICAL_RECOMMENDATION_CONFIG.model_dump(mode="json")
    assert RecommendationConfig.model_validate(payload) == CANONICAL_RECOMMENDATION_CONFIG

    bad = dict(payload)
    bad["experience_fit_bp"] = 7_999
    with pytest.raises(ValidationError, match="fit weights must total 10000"):
        RecommendationConfig.model_validate(bad)

    equal_sum_drift = dict(payload)
    equal_sum_drift["experience_fit_bp"] = 7_000
    equal_sum_drift["travel_condition_fit_bp"] = 3_000
    equal_sum_drift["config_sha256"] = None
    with pytest.raises(ValidationError, match="exact frozen configuration"):
        RecommendationConfig.model_validate(equal_sum_drift)

    extra = dict(payload)
    extra["confidence_rank_bonus"] = 1
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RecommendationConfig.model_validate(extra)


@pytest.mark.parametrize(
    ("model", "prompt_schema_version", "profile_schema_version"),
    (
        (
            "minimaxai/minimax-m3",
            "phase5-demo-profile.v1",
            "itda.demo-model-derived-profile.v1",
        ),
        (
            "glm-5v-turbo",
            "phase5-demo-profile-sentinel-json.v4",
            "itda.nvidia-minimax-model-derived-profile.v4",
        ),
    ),
)
def test_release_disclosure_rejects_crossed_provider_lineages(
    model: str,
    prompt_schema_version: str,
    profile_schema_version: str,
) -> None:
    with pytest.raises(ValidationError, match="lineage tuple is invalid"):
        RecommendationReleaseDisclosure.model_validate(
            {
                "analysis_origin": "DEMO_MODEL_DERIVED",
                "model": model,
                "prompt_schema_version": prompt_schema_version,
                "profile_schema_version": profile_schema_version,
                "config_sha256": "a" * 64,
                "source_bundle_sha256": "b" * 64,
                "release_sha256": "c" * 64,
                "reference_date": "2026-08-10",
            }
        )


@pytest.mark.parametrize("state", ("CURRENT", "STALE", "UNAVAILABLE"))
def test_saved_place_projection_is_bounded_release_bound_and_state_complete(state: str) -> None:
    payload = {
        "place_id": "place:dev:01",
        "place_name_ko": "합성 장소 1",
        "saved_release_sha256": "a" * 64,
        "resolved_release_sha256": "a" * 64 if state == "CURRENT" else None,
        "state": state,
        "state_reason": None if state == "CURRENT" else f"SAVED_PLACE_{state}",
    }
    projection = SavedPlaceProjection.model_validate(payload)
    assert projection.state == state
    assert not hasattr(projection, "score")
    assert not hasattr(projection, "evidence")


def test_saved_current_requires_matching_release_and_other_states_require_reason() -> None:
    common = {
        "place_id": "place:dev:01",
        "place_name_ko": "합성 장소 1",
        "saved_release_sha256": "a" * 64,
    }
    with pytest.raises(ValidationError, match="current saved place"):
        SavedPlaceProjection.model_validate(
            {
                **common,
                "resolved_release_sha256": "b" * 64,
                "state": "CURRENT",
                "state_reason": None,
            }
        )
    with pytest.raises(ValidationError, match="requires a state reason"):
        SavedPlaceProjection.model_validate(
            {**common, "resolved_release_sha256": None, "state": "STALE", "state_reason": None}
        )


def test_run_contract_rejects_non_utc_even_when_effective_instant_matches() -> None:
    from tests.unit.test_recommendation_kernel import _rank

    run = _rank()
    payload = run.model_dump(mode="json")
    payload["created_at"] = datetime(2026, 8, 10, 21, 0, tzinfo=timezone(timedelta(hours=9)))
    with pytest.raises(ValidationError, match="created_at must use UTC"):
        type(run).model_validate(payload)

    payload["created_at"] = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
    assert type(run).model_validate(payload) == run


def test_run_contract_rejects_rank_and_explanation_reference_tampering() -> None:
    from tests.unit.test_recommendation_kernel import _rank

    run = _rank()
    rank_payload = run.model_dump(mode="json")
    rank_payload["items"][0]["rank"] = 2
    with pytest.raises(ValidationError, match="canonical ranks"):
        type(run).model_validate(rank_payload)

    explanation_payload = run.model_dump(mode="json")
    explanation_payload["items"][0]["explanations"][0]["contribution_id"] = "unknown"
    with pytest.raises(ValidationError, match="unknown contribution"):
        type(run).model_validate(explanation_payload)

    missing_evidence_payload = run.model_dump(mode="json")
    missing_evidence_payload["items"][0]["evidence"] = missing_evidence_payload["items"][0][
        "evidence"
    ][1:]
    with pytest.raises(ValidationError, match="evidence attribution is missing"):
        type(run).model_validate(missing_evidence_payload)

    stale_evidence_payload = run.model_dump(mode="json")
    stale_evidence_payload["items"][0]["evidence"][0]["reference_date"] = "2026-08-09"
    with pytest.raises(ValidationError, match="evidence attribution is missing or stale"):
        type(run).model_validate(stale_evidence_payload)


def test_run_contract_rejects_rerank_contribution_drift_from_diversity_trace() -> None:
    from tests.unit.test_recommendation_kernel import _rank

    run = _rank()
    payload = run.model_dump(mode="json")
    contribution = payload["items"][0]["contribution"]
    novelty = (contribution["diversity_novelty_score"] + 1) % 101
    contribution["diversity_novelty_score"] = novelty
    numerator = contribution["relevance_score"] * 8_500 + novelty * 1_500
    contribution["rerank_numerator"] = numerator
    contribution["rerank_score"] = (numerator + 5_000) // 10_000

    with pytest.raises(ValidationError, match="rerank contribution does not match"):
        type(run).model_validate(payload)


def test_duplicate_suppression_ids_are_unique_in_backend_contract_and_schema() -> None:
    """Specified oracle: browser and backend expose the same uniqueness invariant."""

    from itda.contracts.recommendation import DuplicateDecision

    with pytest.raises(ValidationError, match="suppressed_place_ids.*unique|duplicate"):
        DuplicateDecision.model_validate(
            {
                "duplicate_group_id": "duplicate-group:01",
                "kept_place_id": "place:dev:01",
                "suppressed_place_ids": ["place:dev:02", "place:dev:02"],
            }
        )
    property_schema = DuplicateDecision.model_json_schema()["properties"]["suppressed_place_ids"]
    assert property_schema["uniqueItems"] is True


@pytest.mark.parametrize("confidence", (0, 54, 55, 69, 70))
def test_candidate_confidence_boundary_is_a_contract_invariant(confidence: int) -> None:
    from itda.contracts.recommendation import RecommendationCandidate
    from tests.unit.test_recommendation_kernel import _candidate_payload

    payload = _candidate_payload(1, confidence=confidence)
    candidate = RecommendationCandidate.model_validate(payload)
    assert candidate.recommendation_eligible is (confidence >= 55)

    contradictory = dict(payload)
    contradictory["recommendation_eligible"] = not candidate.recommendation_eligible
    with pytest.raises(ValidationError, match="eligibility drifted from confidence policy"):
        RecommendationCandidate.model_validate(contradictory)


def test_evidence_confidence_state_has_exact_boundary_copy_and_no_numeric_card_field() -> None:
    expected = {
        0: (
            EvidenceConfidenceState.EVIDENCE_AUDIT_ONLY,
            "확인된 근거가 매우 제한되어 참고 정보로만 보여드려요.",
        ),
        54: (
            EvidenceConfidenceState.EVIDENCE_AUDIT_ONLY,
            "확인된 근거가 매우 제한되어 참고 정보로만 보여드려요.",
        ),
        55: (
            EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED,
            "확인된 근거가 제한되어 기대 차이 안내를 생략했어요.",
        ),
        64: (
            EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_SUPPRESSED,
            "확인된 근거가 제한되어 기대 차이 안내를 생략했어요.",
        ),
        65: (
            EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_AVAILABLE,
            "확인된 근거 범위에서 기대 차이 안내를 함께 보여드려요.",
        ),
        69: (
            EvidenceConfidenceState.EVIDENCE_LIMITED_MISMATCH_AVAILABLE,
            "확인된 근거 범위에서 기대 차이 안내를 함께 보여드려요.",
        ),
        70: (
            EvidenceConfidenceState.EVIDENCE_SUPPORTED,
            "확인된 근거 범위에서 안내해요.",
        ),
        100: (
            EvidenceConfidenceState.EVIDENCE_SUPPORTED,
            "확인된 근거 범위에서 안내해요.",
        ),
    }
    from itda.contracts.recommendation import confidence_state_for

    for confidence, (state, reason) in expected.items():
        assert confidence_state_for(confidence) == (state, reason)
    with pytest.raises(ValueError):
        confidence_state_for(-1)

    assert "overall_confidence" not in RecommendationItem.model_fields
    assert "confidence_percent" not in RecommendationItem.model_fields


def test_detail_confidence_is_integer_and_repeats_item_state_reason() -> None:
    assert RecommendationDetail.model_fields["confidence_percent"].annotation is int
    assert (
        RecommendationDetail.model_fields["evidence_confidence_state"].annotation
        is EvidenceConfidenceState
    )
    assert "confidence_percent" not in RecommendationItem.model_fields
    assert "confidence_percent" in RecommendationDetail.model_fields
    assert "evidence_confidence_state" in RecommendationDetail.model_fields
    assert "evidence_confidence_reason_ko" in RecommendationDetail.model_fields
    assert "confidence_percent" not in RecommendationItem.model_fields
    assert "evidence_confidence_state" in RecommendationItem.model_fields
    assert "evidence_confidence_reason_ko" in RecommendationItem.model_fields


def test_detail_rejects_state_reason_and_numeric_confidence_drift() -> None:
    from tests.unit.test_recommendation_kernel import _candidate_payload, _rank

    run = _rank(candidates=[_candidate_payload(index, confidence=65) for index in range(1, 6)])
    item = run.items[0]
    detail_evidence = [row.model_dump(mode="json") for row in item.evidence]
    detail_evidence.append(
        {
            **detail_evidence[0],
            "evidence_id": "evidence:01:3",
            "excerpt_ko": "합성 오라클 근거 1-3",
        }
    )
    detail_payload = {
        "run_id": run.run_id,
        "release_sha256": run.release_sha256,
        "confidence_percent": 65,
        "evidence_confidence_state": item.evidence_confidence_state.value,
        "evidence_confidence_reason_ko": item.evidence_confidence_reason_ko,
        "item": item.model_dump(mode="json"),
        "mismatch_traits": [
            {
                "trait_id": trait,
                "value": 50,
                "evidence_ids": [item.evidence[0].evidence_id],
            }
            for trait in ("M1", "M2", "M3", "M4", "M5", "M6")
        ],
        "evidence": detail_evidence,
        "operating_state": "OPERATING_INFORMATION_UNVERIFIED",
        "similar_place_ids": [],
    }
    assert RecommendationDetail.model_validate(detail_payload).confidence_percent == 65

    for field, value in (
        ("confidence_percent", 70),
        ("evidence_confidence_state", "EVIDENCE_SUPPORTED"),
        ("evidence_confidence_reason_ko", "확인된 근거 범위에서 안내해요."),
    ):
        hostile = dict(detail_payload)
        hostile[field] = value
        with pytest.raises(ValidationError):
            RecommendationDetail.model_validate(hostile)

    hostile_item = dict(detail_payload)
    hostile_item["item"] = {**detail_payload["item"], "confidence_percent": 65}
    with pytest.raises(ValidationError):
        RecommendationDetail.model_validate(hostile_item)

    assert PlaceTraitSnapshot.model_fields["value"].annotation is not None


def test_item_rejects_numeric_confidence_even_when_extra_keys_arrive() -> None:
    from tests.unit.test_recommendation_kernel import _rank

    item_payload = _rank().items[0].model_dump(mode="json")
    item_payload["confidence_percent"] = 70
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RecommendationItem.model_validate(item_payload)
