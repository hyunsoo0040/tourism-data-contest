"""The v5 kernel ranks actual validated assessments, including sparse evidence."""

from dataclasses import replace
from datetime import UTC, date, datetime

import pytest

from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.grounded_run import (
    CONDITION_KEYS,
    TRAIT_KEYS,
    GroundedPreference,
    GroundedRecommendationRun,
)
from itda.contracts.mvp_scored_release import MvpScoredProfile
from itda.contracts.source_assessment import AssessmentBundle, ClaimKind, SupportState
from itda.contracts.visual_mood import VisualMoodDimension
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_recommendation import (
    GroundedCandidate,
    GroundedRecommendationError,
    rank_grounded,
)
from itda.pipeline.grounded_assessment import build_assessment
from tests.contract.test_mvp_scored_release import profile
from tests.unit.test_grounded_axis_aggregation import judgment

NOW = datetime(2026, 9, 9, tzinfo=UTC)


def candidate(index, *, axes="HER", level=2):
    raw = profile(index, confidence=75)
    judgments = {}
    for axis in axes:
        for number in (1, 2):
            key = f"{axis}{number}"
            row = judgment(key, level)
            evidence = row.evidence[0]
            evidence = evidence.model_copy(
                update={
                    "place_match": evidence.place_match.model_copy(
                        update={"place_id": raw.place_id}
                    )
                }
            )
            judgments[key] = row.model_copy(update={"evidence": (evidence,)})
    assessment = build_assessment(
        profile=raw, judgments=judgments, facts={}, source_release_sha256="b" * 64, assessed_at=NOW
    ).bundle
    return GroundedCandidate(raw, assessment, "관광지")


def preference(**changes):
    fields = dict(
        profile_id="profile:test",
        input_sha256="1" * 64,
        trip_input=GroundedTripInput(visit_date=date(2026, 9, 10)),
        purpose="SIGHTSEEING",
        axis_targets={a: 50 for a in "HER"},
        trait_targets={k: 50 for k in TRAIT_KEYS},
        important_traits=("M3",),
        condition_targets={k: None for k in CONDITION_KEYS},
        mood_targets={d.value: None for d in VisualMoodDimension},
    )
    fields.update(changes)
    return GroundedPreference(**fields)


def run(candidates, *, pairs=(), pref=None):
    ids = sorted(c.place_id for c in candidates)
    return rank_grounded(
        candidates=tuple(candidates),
        preference=pref or preference(),
        release_sha256="a" * 64,
        source_release_sha256="b" * 64,
        assessment_manifest_sha256="c" * 64,
        candidate_sha256="8" * 64,
        membership_sha256="d" * 64,
        relation_sha256=canonical_sha256({"place_ids": ids, "pairs": [list(p) for p in pairs]}),
        forbidden_pairs=pairs,
        created_at=NOW,
    )


def test_actual_rank_uses_sparse_axes_without_inventing_third_axis_or_crowd():
    candidates = [candidate(i, axes="ER" if i == 0 else "HER") for i in range(8)]
    result = run(candidates)
    assert result.authority.kernel_version == "recommendation-kernel-v5"
    assert [i.place_id for i in result.items] == [c.place_id for c in candidates[:5]]
    sparse = result.items[0]
    assert sparse.axis_scores[0].value is None and sparse.supported_axes == 2
    assert sparse.fit_score == 100 and sparse.information_state == "LIMITED"
    assert sparse.mismatch_traits[2].value is None
    assert not sparse.mismatch.important_floor_applied
    assert sparse.contribution.mood_weight == 0
    assert GroundedRecommendationRun.model_validate_json(result.model_dump_json()) == result


def test_candidate_order_invariance_and_relationship_feasibility():
    candidates = [candidate(i) for i in range(8)]
    pairs = ((candidates[0].place_id, candidates[1].place_id),)
    a = run(candidates, pairs=pairs)
    b = run(list(reversed(candidates)), pairs=pairs)
    assert a.model_dump_json() == b.model_dump_json()
    assert not {candidates[0].place_id, candidates[1].place_id} <= {i.place_id for i in a.items}


def test_single_supported_axis_is_excluded_without_falling_back_to_raw_axes():
    candidates = [candidate(i, axes="E") for i in range(8)]
    with pytest.raises(GroundedRecommendationError, match="INSUFFICIENT"):
        run(candidates)


def test_unchanged_unknown_support_ignores_raw_model_m3_but_rebinds_identity():
    candidates = [candidate(i) for i in range(8)]
    baseline = run(candidates)
    first = candidates[0]
    raw_data = first.profile.model_dump(mode="json", exclude={"profile_sha256"})
    raw_data["scores"]["M3"] = 100
    raw_data["scoring_result"]["scores"]["M3"] = 100
    raw_data["scoring_result"]["result_sha256"] = canonical_sha256(
        {k: v for k, v in raw_data["scoring_result"].items() if k != "result_sha256"}
    )
    changed_profile = MvpScoredProfile.model_validate(
        {**raw_data, "profile_sha256": canonical_sha256(raw_data)}
    )
    payload = first.assessment.model_dump(mode="json", exclude={"bundle_sha256"})
    payload["raw_profile_sha256"] = changed_profile.profile_sha256
    changed_bundle = AssessmentBundle.model_validate(
        {**payload, "bundle_sha256": canonical_sha256(payload)}
    )
    updated = run(
        [replace(first, profile=changed_profile, assessment=changed_bundle), *candidates[1:]]
    )
    assert [(i.place_id, i.fit_score, i.mismatch.model_dump()) for i in baseline.items] == [
        (i.place_id, i.fit_score, i.mismatch.model_dump()) for i in updated.items
    ]
    assert baseline.canonical_sha256 != updated.canonical_sha256


def test_unbound_aggregate_cannot_be_replaced_with_plausible_model_axis():
    candidates = [candidate(i) for i in range(8)]
    first = candidates[0]
    payload = first.assessment.model_dump(mode="json", exclude={"bundle_sha256"})
    payload["dimensions"]["H"]["value"] = 99
    altered = AssessmentBundle.model_validate(
        {**payload, "bundle_sha256": canonical_sha256(payload)}
    )
    with pytest.raises(GroundedRecommendationError, match="AGGREGATION"):
        run([replace(first, assessment=altered), *candidates[1:]])


def test_facility_absence_only_applies_to_explicit_requirement():
    candidates = [candidate(i) for i in range(8)]
    first = candidates[0]
    evidence = first.assessment.dimensions["H1"].evidence
    fact = first.assessment.dimensions["H1"].model_copy(
        update={
            "key": "accessible_toilet",
            "claim": ClaimKind.FACILITY,
            "state": SupportState.FACT,
            "value": False,
            "evidence": evidence,
        }
    )
    payload = first.assessment.model_dump(mode="json", exclude={"bundle_sha256"})
    payload["facts"] = {"accessible_toilet": fact.model_dump(mode="json")}
    altered = AssessmentBundle.model_validate(
        {**payload, "bundle_sha256": canonical_sha256(payload)}
    )
    candidates[0] = replace(first, assessment=altered)
    assert first.place_id in {i.place_id for i in run(candidates).items}
    explicit = preference(trip_input=GroundedTripInput(required_facilities=("accessible_toilet",)))
    assert first.place_id not in {i.place_id for i in run(candidates, pref=explicit).items}


def visual_observation(candidate, key="greenery", value=100):
    from itda.contracts.source_assessment import SourceEvidence, SourceObservation

    source = candidate.assessment.dimensions["H1"].evidence[0]
    receipt = source.receipt.model_copy(update={"operation": "detailImage2"})
    pixel = SourceEvidence.model_validate(
        {
            **source.model_dump(),
            "receipt": receipt,
            "modality": "IMAGE_PIXELS",
            "source_field": "original_image",
            "image_sha256": "f" * 64,
            "image_license": "KOGL_TYPE_1",
        }
    )
    return SourceObservation(
        key=key,
        claim=ClaimKind.VISUAL_MOOD,
        state=SupportState.INFERENCE,
        value=value,
        evidence=(pixel,),
        reference_date=date(2014, 4, 1),
        reason="appearance only",
    )


def test_actual_image_mood_cannot_enter_crowd_or_other_condition_path():
    candidates = [candidate(i) for i in range(8)]
    first = candidates[0]
    for key in ("CROWD", "VISIT_DATE_TIME", "WALKING"):
        injected = replace(first, conditions={key: visual_observation(first, key=key)})
        with pytest.raises(GroundedRecommendationError, match="CONDITION_SOURCE_AUTHORITY"):
            run([injected, *candidates[1:]])


def test_image_mood_changes_only_appearance_contribution_and_has_capped_weight():
    candidates = [candidate(i) for i in range(8)]
    first = candidates[0]
    targets = {d.value: None for d in VisualMoodDimension}
    targets["greenery"] = 100
    pref = preference(mood_targets=targets, photo_input_sha256="9" * 64)
    missing = run(candidates, pref=pref)
    seen = run(
        [replace(first, moods={"greenery": visual_observation(first, value=0)}), *candidates[1:]],
        pref=pref,
    )
    # Inspect rank-independent identity: a worse appearance match can move the place,
    # while every fact/axis/mismatch remains unchanged for any still-selected place.
    before = {i.place_id: i for i in missing.items}
    after = {i.place_id: i for i in seen.items}
    for place_id in before.keys() & after.keys():
        assert before[place_id].axis_scores == after[place_id].axis_scores
        assert before[place_id].mismatch == after[place_id].mismatch
    assert all(i.contribution.mood_weight <= 1500 for i in seen.items)
    assert first.place_id not in after
