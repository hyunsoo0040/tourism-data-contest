from __future__ import annotations

import time

import pytest

from itda.contracts.mvp_scored_release import MvpScoredProfile
from itda.contracts.recommendation import (
    PublicRelationAuthority,
    confidence_state_for,
    public_relation_sha256,
)
from itda.domain.canonical import canonical_sha256
from itda.domain.mvp_recommendation import (
    MvpRecommendationError,
    create_mvp_recommendation_run,
    create_photo_mvp_recommendation_run,
    rank_mvp_top_five,
    rank_photo_mvp_top_five,
)
from tests.contract.test_mvp_scored_release import profile

SHA = "0" * 64


def profiles(count: int, *, confidence_offset: int = 0) -> tuple[MvpScoredProfile, ...]:
    return tuple(
        profile(index, confidence=(index + confidence_offset) % 101) for index in range(count)
    )


def authority(
    rows: tuple[MvpScoredProfile, ...], *, dense: bool = False
) -> PublicRelationAuthority:
    ids = tuple(row.place_id for row in rows)
    pairs = (
        tuple(
            (ids[left], ids[right])
            for left in range(len(ids))
            for right in range(left + 1, len(ids))
            if dense and left >= 5
        )
        if dense
        else ()
    )
    return PublicRelationAuthority(
        relation_sha256=public_relation_sha256(ids, pairs),
        place_ids=ids,
        pairs=pairs,
    )


@pytest.mark.parametrize("count", [80, 100])
def test_top_five_is_deterministic_and_bounded(count: int) -> None:
    rows = profiles(count)
    relation = authority(rows)
    started = time.perf_counter()
    first = rank_mvp_top_five(
        rows,
        relation_authority=relation,
        axis_targets=(50, 50, 50),
        condition_targets=(50, 50, 50, 50, 50, 50),
    )
    second = rank_mvp_top_five(
        tuple(reversed(rows)),
        relation_authority=relation,
        axis_targets=(50, 50, 50),
        condition_targets=(50, 50, 50, 50, 50, 50),
    )
    assert first == second
    assert len(first) == 5
    assert time.perf_counter() - started < 1.0


def test_confidence_permutation_never_changes_rank() -> None:
    baseline = profiles(100)
    changed = profiles(100, confidence_offset=47)
    first = rank_mvp_top_five(
        baseline,
        relation_authority=authority(baseline),
        axis_targets=(40, 60, 70),
        condition_targets=(20, 30, 40, 50, 60, 70),
    )
    second = rank_mvp_top_five(
        changed,
        relation_authority=authority(changed),
        axis_targets=(40, 60, 70),
        condition_targets=(20, 30, 40, 50, 60, 70),
    )
    assert tuple(row.place_id for row in first) == tuple(row.place_id for row in second)


def test_dense_100_relation_fixture_fails_quickly_without_exponential_search() -> None:
    rows = profiles(100)
    relation = authority(rows, dense=True)
    started = time.perf_counter()
    ranked = rank_mvp_top_five(
        rows,
        relation_authority=relation,
        axis_targets=(50, 50, 50),
        condition_targets=(50, 50, 50, 50, 50, 50),
    )
    assert len(ranked) == 5
    assert time.perf_counter() - started < 1.0


def _perfect_fit(row: MvpScoredProfile) -> MvpScoredProfile:
    scores = row.scores.model_copy(
        update={
            "H": 100,
            "E": 100,
            "R": 100,
        }
    )
    conditions = row.condition_scores.model_copy(
        update={
            "visit_date_time": 100,
            "companions": 100,
            "transport": 100,
            "walking": 100,
            "indoor_outdoor": 100,
            "crowd": 100,
        }
    )
    return row.model_copy(update={"scores": scores, "condition_scores": conditions})


def test_highest_ranked_dead_end_is_skipped_when_another_five_exists() -> None:
    rows = list(profiles(80))
    rows[0] = _perfect_fit(rows[0])
    ids = tuple(row.place_id for row in rows)
    pairs = tuple((ids[0], ids[index]) for index in range(4, len(ids)))
    relation = PublicRelationAuthority(
        relation_sha256=public_relation_sha256(ids, pairs),
        place_ids=ids,
        pairs=pairs,
    )
    ranked = rank_mvp_top_five(
        tuple(rows),
        relation_authority=relation,
        axis_targets=(100, 100, 100),
        condition_targets=(100, 100, 100, 100, 100, 100),
    )
    assert len(ranked) == 5
    assert ids[0] not in {row.place_id for row in ranked}


def test_duplicate_group_uses_highest_ranked_representative_not_smallest_id() -> None:
    rows = list(profiles(80))
    duplicate_group = rows[0].duplicate_group_id
    rows[1] = _perfect_fit(rows[1]).model_copy(update={"duplicate_group_id": duplicate_group})
    ranked = rank_mvp_top_five(
        tuple(rows),
        relation_authority=authority(tuple(rows)),
        axis_targets=(100, 100, 100),
        condition_targets=(100, 100, 100, 100, 100, 100),
    )
    selected = {row.place_id for row in ranked}
    assert rows[1].place_id in selected
    assert rows[0].place_id not in selected


def test_low_confidence_state_is_valid_and_mismatch_threshold_remains_65() -> None:
    assert confidence_state_for(0)[0] == "EVIDENCE_AUDIT_ONLY"
    assert confidence_state_for(54)[0] == "EVIDENCE_AUDIT_ONLY"
    assert confidence_state_for(55)[0] == "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED"
    assert confidence_state_for(64)[0] == "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED"
    assert confidence_state_for(65)[0] == "EVIDENCE_LIMITED_MISMATCH_AVAILABLE"


def test_relation_hash_is_recomputed_from_membership_and_pairs() -> None:
    from pydantic import ValidationError

    rows = profiles(80)
    valid = authority(rows)
    with pytest.raises(ValidationError, match="relation hash"):
        PublicRelationAuthority(
            relation_sha256="f" * 64,
            place_ids=valid.place_ids,
            pairs=valid.pairs,
        )


def test_release_and_recommendation_authority_relation_hash_agree() -> None:
    snapshot = __import__("tests.contract.test_mvp_scored_release", fromlist=["release"]).release(
        80
    )
    relation = authority(snapshot.profiles)
    payload = snapshot.model_dump(mode="json")
    payload["relation_sha256"] = relation.relation_sha256
    payload["release_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "release_sha256"}
    )
    rebuilt = type(snapshot).model_validate(payload)
    from itda.contracts.recommendation import RecommendationPreference
    from tests.unit.test_recommendation_kernel import _preference_payload

    run = create_mvp_recommendation_run(
        rebuilt.profiles,
        release_sha256=rebuilt.release_sha256,
        membership_sha256=rebuilt.membership_sha256,
        relation_authority=relation,
        preference=RecommendationPreference.model_validate(_preference_payload()),
        created_at=rebuilt.created_at,
    )
    assert run.authority.relation_sha256 == rebuilt.relation_sha256


def test_relation_membership_mismatch_fails_closed() -> None:
    rows = profiles(80)
    wrong = authority(tuple(profile(index + 1) for index in range(80)))
    with pytest.raises(MvpRecommendationError, match="MVP_RELATION_MEMBERSHIP_INVALID"):
        rank_mvp_top_five(
            rows,
            relation_authority=wrong,
            axis_targets=(50, 50, 50),
            condition_targets=(50, 50, 50, 50, 50, 50),
        )


def test_displayed_scores_exactly_match_ranking_objective() -> None:
    from datetime import UTC, datetime

    from itda.contracts.recommendation import RecommendationPreference
    from tests.unit.test_recommendation_kernel import _preference_payload

    rows = profiles(80)
    preference = RecommendationPreference.model_validate(_preference_payload(value=37))
    relation = authority(rows)
    ranked = rank_mvp_top_five(
        rows,
        relation_authority=relation,
        axis_targets=tuple(row.value for row in preference.axis_targets),
        condition_targets=tuple(row.value for row in preference.condition_targets),
    )
    run = create_mvp_recommendation_run(
        rows,
        release_sha256="1" * 64,
        membership_sha256="2" * 64,
        relation_authority=relation,
        preference=preference,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    assert tuple(item.place_id for item in run.items) == tuple(row.place_id for row in ranked)
    assert tuple(item.fit_score for item in run.items) == tuple(
        row.relevance_score for row in ranked
    )
    assert tuple(item.contribution.relevance_score for item in run.items) == tuple(
        row.relevance_score for row in ranked
    )


def test_v2_run_binds_only_product_authority_and_replays() -> None:
    from datetime import UTC, datetime

    rows = profiles(80)
    relation = authority(rows)
    from itda.contracts.recommendation import RecommendationPreference
    from tests.unit.test_recommendation_kernel import _preference_payload

    kwargs = {
        "release_sha256": "1" * 64,
        "membership_sha256": "2" * 64,
        "relation_authority": relation,
        "preference": RecommendationPreference.model_validate(_preference_payload()),
        "created_at": datetime(2026, 8, 25, tzinfo=UTC),
    }
    first = create_mvp_recommendation_run(rows, **kwargs)
    second = create_mvp_recommendation_run(rows, **kwargs)
    assert first == second
    assert first.schema_version == "recommendation-run.v2"
    assert first.authority.release_sha256 == "1" * 64
    assert first.authority.membership_sha256 == "2" * 64
    dumped = first.model_dump(mode="json")
    assert "recovery_policy_sha256" not in str(dumped)
    assert "activation_suite_sha256" not in str(dumped)


def test_photo_v3_blends_base_and_trait_fit_without_changing_v2() -> None:
    from datetime import UTC, datetime

    from itda.contracts.recommendation import RecommendationPreference
    from tests.unit.test_recommendation_kernel import _preference_payload

    rows = profiles(80)
    relation = authority(rows)
    preference = RecommendationPreference.model_validate(_preference_payload(value=37))
    v2 = create_mvp_recommendation_run(
        rows,
        release_sha256="1" * 64,
        membership_sha256="2" * 64,
        relation_authority=relation,
        preference=preference,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    v3 = create_photo_mvp_recommendation_run(
        rows,
        release_sha256="1" * 64,
        membership_sha256="2" * 64,
        relation_authority=relation,
        preference=preference,
        photo_projection_policy_sha256="3" * 64,
        photo_projection_output_sha256="4" * 64,
        confirmation_draft_sha256="5" * 64,
        photo_job_reference_sha256="6" * 64,
        images_count=2,
        included_count=3,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    ranked, traces = rank_photo_mvp_top_five(
        rows,
        relation_authority=relation,
        axis_targets=tuple(row.value for row in preference.axis_targets),
        condition_targets=tuple(row.value for row in preference.condition_targets),
        trait_targets=tuple(row.value for row in preference.trait_targets),
    )

    assert v2.schema_version == "recommendation-run.v2"
    assert v3.schema_version == "recommendation-run.v3"
    assert tuple(row.place_id for row in v3.items) == tuple(row.place_id for row in ranked)
    assert tuple(row.fit_score for row in v3.items) == tuple(
        traces[row.place_id].effective_relevance for row in ranked
    )
    for trace in v3.photo_scores:
        assert trace.photo_trait_fit == (
            2 * sum(row.fit for row in trace.trait_components) + 6
        ) // 12
        assert trace.effective_relevance == (
            2 * (trace.base_relevance * 6_500 + trace.photo_trait_fit * 3_500) + 10_000
        ) // 20_000
    replay = create_photo_mvp_recommendation_run(
        rows,
        release_sha256="1" * 64,
        membership_sha256="2" * 64,
        relation_authority=relation,
        preference=preference,
        photo_projection_policy_sha256="3" * 64,
        photo_projection_output_sha256="4" * 64,
        confirmation_draft_sha256="5" * 64,
        photo_job_reference_sha256="6" * 64,
        images_count=2,
        included_count=3,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    assert replay == v3
    assert "photo_job_id" not in str(v3.model_dump(mode="json"))
