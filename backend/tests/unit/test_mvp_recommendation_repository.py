from __future__ import annotations

from datetime import UTC, datetime

import pytest

from itda.contracts.recommendation import (
    PhotoMvpRecommendationRun,
    RecommendationPreference,
)
from itda.db.recommendation_repositories import (
    PinnedRecommendationRun,
    RecommendationPinInvalid,
    RecommendationRunRepository,
    _pin_row,
    _run_row,
    _validate_pinned_rows,
)
from itda.domain.mvp_recommendation import (
    create_mvp_recommendation_run,
    create_photo_mvp_recommendation_run,
)
from tests.contract.test_mvp_scored_release import release
from tests.unit.test_recommendation_kernel import _preference_payload


def _run(*, trait_value: int = 50):
    snapshot = release(80)
    payload = _preference_payload()
    payload["trait_targets"][0]["value"] = trait_value
    preference = RecommendationPreference.model_validate(payload)
    from itda.contracts.recommendation import PublicRelationAuthority

    relation = PublicRelationAuthority(
        relation_sha256=snapshot.relation_sha256,
        place_ids=tuple(row.place_id for row in snapshot.profiles),
        pairs=snapshot.relation_pairs,
    )
    return snapshot, create_mvp_recommendation_run(
        snapshot.profiles,
        release_sha256=snapshot.release_sha256,
        membership_sha256=snapshot.membership_sha256,
        relation_authority=relation,
        preference=preference,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )


def test_v2_public_projections_use_only_the_pinned_release() -> None:
    snapshot, run = _run()
    repository = object.__new__(RecommendationRunRepository)
    pinned = PinnedRecommendationRun(
        run=run,
        release_snapshot=snapshot,
        preference_profile_id=run.preference.profile_id,
        request_id="request:mvp:v2",
    )
    repository.load_pinned = lambda run_id: pinned
    repository.load_release_snapshot = lambda release_sha256: snapshot

    results = repository.load_results(run.run_id)
    detail = repository.load_detail(run.run_id, run.items[0].place_id)
    comparison = repository.load_comparison(
        run.run_id, (run.items[0].place_id, run.items[1].place_id)
    )
    saved = repository.resolve_saved_place_reference(
        release_sha256=snapshot.release_sha256,
        place_id=run.items[0].place_id,
        current_release_sha256="f" * 64,
    )

    assert results.schema_version == "itda.recommendation-results.v2"
    assert results.run == run
    assert detail.item.image_state == "ABSENT"
    assert detail.evidence[0].attribution_ko == "합성 테스트 제공기관 · 합성 테스트 관광정보"
    assert detail.evidence[0].usage_state == "STRICT_PUBLIC_USAGE_ALLOWED"
    assert len(comparison.rows) >= 1
    assert saved.state == "STALE"


def test_v3_pin_round_trip_and_public_projections() -> None:
    snapshot, base_run = _run()
    from itda.contracts.recommendation import PublicRelationAuthority

    relation = PublicRelationAuthority(
        relation_sha256=snapshot.relation_sha256,
        place_ids=tuple(row.place_id for row in snapshot.profiles),
        pairs=snapshot.relation_pairs,
    )
    run = create_photo_mvp_recommendation_run(
        snapshot.profiles,
        release_sha256=snapshot.release_sha256,
        membership_sha256=snapshot.membership_sha256,
        relation_authority=relation,
        preference=base_run.preference,
        photo_projection_policy_sha256="3" * 64,
        photo_projection_output_sha256="4" * 64,
        confirmation_draft_sha256="5" * 64,
        photo_job_reference_sha256="6" * 64,
        images_count=2,
        included_count=3,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    restored = _validate_pinned_rows(
        _run_row(
            request_id="request:mvp:v3",
            preference_profile_id=run.preference.profile_id,
            run=run,
        ),
        _pin_row(run=run, release_snapshot=snapshot),
    )
    assert isinstance(restored.run, PhotoMvpRecommendationRun)
    assert restored.run == run

    repository = object.__new__(RecommendationRunRepository)
    repository.load_pinned = lambda run_id: restored
    results = repository.load_results(run.run_id)
    detail = repository.load_detail(run.run_id, run.items[0].place_id)
    comparison = repository.load_comparison(
        run.run_id, (run.items[0].place_id, run.items[1].place_id)
    )
    assert results.run == run
    assert detail.item == run.items[0]
    assert comparison.rows[0].values_ko[0] == f"{run.items[0].fit_score}점 / 100점"


def test_v3_stored_trace_tampering_fails_closed() -> None:
    snapshot, base_run = _run()
    from itda.contracts.recommendation import PublicRelationAuthority

    relation = PublicRelationAuthority(
        relation_sha256=snapshot.relation_sha256,
        place_ids=tuple(row.place_id for row in snapshot.profiles),
        pairs=snapshot.relation_pairs,
    )
    run = create_photo_mvp_recommendation_run(
        snapshot.profiles,
        release_sha256=snapshot.release_sha256,
        membership_sha256=snapshot.membership_sha256,
        relation_authority=relation,
        preference=base_run.preference,
        photo_projection_policy_sha256="3" * 64,
        photo_projection_output_sha256="4" * 64,
        confirmation_draft_sha256="5" * 64,
        photo_job_reference_sha256="6" * 64,
        images_count=2,
        included_count=3,
        created_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    run_row = _run_row(
        request_id="request:mvp:v3",
        preference_profile_id=run.preference.profile_id,
        run=run,
    )
    receipt = dict(run_row.receipt)
    photo_scores = [dict(row) for row in receipt["photo_scores"]]
    photo_scores[0]["base_relevance"] += 1
    receipt["photo_scores"] = photo_scores
    run_row.receipt = receipt
    with pytest.raises(RecommendationPinInvalid):
        _validate_pinned_rows(run_row, _pin_row(run=run, release_snapshot=snapshot))


def test_v2_pin_round_trip_and_full_preference_binding() -> None:
    snapshot, run = _run()
    run_row = _run_row(
        request_id="request:mvp:v2",
        preference_profile_id=run.preference.profile_id,
        run=run,
    )
    pin_row = _pin_row(run=run, release_snapshot=snapshot)
    restored = _validate_pinned_rows(run_row, pin_row)
    assert restored.run == run
    assert restored.release_snapshot == snapshot

    _, changed = _run(trait_value=51)
    assert changed.input_digest != run.input_digest
    assert changed.run_id != run.run_id


@pytest.mark.parametrize(
    "field",
    [
        "release_sha256",
        "canonical_membership_sha256",
        "config_sha256",
        "kernel_version",
        "receipt_sha256",
        "snapshot_sha256",
    ],
)
def test_v2_pin_metadata_tampering_fails_closed(field: str) -> None:
    snapshot, run = _run()
    run_row = _run_row(
        request_id="request:mvp:v2",
        preference_profile_id=run.preference.profile_id,
        run=run,
    )
    pin_row = _pin_row(run=run, release_snapshot=snapshot)
    setattr(pin_row, field, "f" * 64 if field != "kernel_version" else "wrong-kernel")
    with pytest.raises(RecommendationPinInvalid):
        _validate_pinned_rows(run_row, pin_row)
