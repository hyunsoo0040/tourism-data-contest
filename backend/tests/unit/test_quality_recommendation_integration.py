"""Active v4 service regression cases; public fixtures are not human judgments."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.application.recommendations import RecommendationService
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.contracts.recommendation import (
    QUALITY_RECOMMENDATION_CONFIG,
    PhotoMvpRecommendationRun,
    PublicRelationAuthority,
    RecommendationPurpose,
    RecommendationQualityContext,
    RecommendationRequest,
    observed_condition_weights,
    public_relation_sha256,
)
from itda.db.recommendation_repositories import RecommendationRequestConflict
from itda.domain.canonical import canonical_sha256
from itda.domain.mvp_recommendation import _public_candidate, create_photo_mvp_recommendation_run
from itda.domain.recommendation_projection import project_recommendation_preference
from itda.domain.recommendation_scoring import score_candidate
from tests.unit.test_mvp_recommendation_service import (
    ProfileRepositoryStub,
    RunRepositoryStub,
    _preference,
)

ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = ROOT / "fixtures/historical-gyeongju/catalog/public-place-catalog-v1.json"
RELEASE_PATH = (
    ROOT
    / "fixtures/historical-gyeongju/catalog/mvp-scored-releases/releases"
    / "1de50e3e4d4e0b32f0358f0f6fa9611e88dc36cbbf050f8811a3e91cc7b54e49"
    / "release.json"
)


def context(release: MvpScoredRelease) -> RecommendationQualityContext:
    return RecommendationQualityContext(
        companion="FAMILY_WITH_CHILDREN",
        transport="CAR_OR_TAXI",
        purpose="MIXED",
        eligible_place_ids=tuple(row.place_id for row in release.profiles),
    )


def test_v4_crowd_direction_and_absent_preferences() -> None:
    release = MvpScoredRelease.model_validate_json(RELEASE_PATH.read_bytes())
    profile = _preference()
    conditions = {
        **profile.trip_conditions.model_dump(),
        **{
            "visit_time": "UNDECIDED",
            "indoor_outdoor_preference": "NO_PREFERENCE",
        },
    }
    profile = type(profile).model_validate({**profile.model_dump(), "trip_conditions": conditions})
    preference = project_recommendation_preference(profile, quality_context=context(release))
    assert preference.condition_targets[0].value is None
    assert preference.condition_targets[4].value is None
    assert preference.trait_targets[2].value == 0
    assert preference.trait_targets[2].important
    candidate = _public_candidate(release.profiles[0], preference.quality_context)
    candidate = candidate.model_copy(
        update={
            "overall_confidence": 80,
            "axis_scores": tuple(
                actual.model_copy(update={"value": target.value})
                for actual, target in zip(
                    candidate.axis_scores, preference.axis_targets, strict=True
                )
            ),
            "mismatch_traits": tuple(
                actual.model_copy(update={"value": target.value})
                for actual, target in zip(
                    candidate.mismatch_traits, preference.trait_targets, strict=True
                )
            ),
        }
    )
    _, quiet = score_candidate(
        preference=preference, candidate=candidate, config=QUALITY_RECOMMENDATION_CONFIG
    )
    crowded = candidate.model_copy(
        update={
            "mismatch_traits": tuple(
                row.model_copy(update={"value": 100}) if row.trait_id.value == "M3" else row
                for row in candidate.mismatch_traits
            )
        }
    )
    _, noisy = score_candidate(
        preference=preference, candidate=crowded, config=QUALITY_RECOMMENDATION_CONFIG
    )
    assert quiet.effective_score == 0
    assert noisy.important_trait_floor_applied
    assert noisy.effective_score >= 50


def test_observed_weights_preserve_totals_and_missing_is_not_zero() -> None:
    assert observed_condition_weights((True,) * 6) == (400, 350, 350, 350, 300, 250)
    assert observed_condition_weights((False,) * 6) == (0,) * 6
    assert observed_condition_weights((False, True, False, False, False, False)) == (
        0,
        2000,
        0,
        0,
        0,
        0,
    )
    weights = observed_condition_weights((True, False, True, False, True, False))
    assert sum(weights) == 2000
    assert weights[1] == weights[3] == weights[5] == 0


@pytest.mark.parametrize("member_count", [80, 100])
def test_service_uses_facts_and_sightseeing_purpose_and_binds_recovery(member_count: int) -> None:
    release = MvpScoredRelease.model_validate_json(RELEASE_PATH.read_bytes())
    if member_count == 80:
        payload = release.model_dump(mode="json", exclude={"release_sha256"})
        payload["profiles"] = payload["profiles"][:80]
        ids = tuple(row["place_id"] for row in payload["profiles"])
        payload["published_count"] = 80
        payload["failed"] = [
            {"place_id": row.place_id, "reason": "PROVIDER_ATTEMPT_FAILED"}
            for row in release.profiles[80:]
        ]
        payload["membership_sha256"] = canonical_sha256(list(ids))
        pairs = tuple(
            (left, right) for left, right in release.relation_pairs if left in ids and right in ids
        )
        payload["relation_pairs"] = pairs
        payload["relation_sha256"] = public_relation_sha256(ids, pairs)
        release = MvpScoredRelease.model_validate(
            {**payload, "release_sha256": canonical_sha256(payload)}
        )
    catalog = PublicPlaceCatalog.model_validate_json(CATALOG_PATH.read_bytes())
    profile = _preference()
    runs = RunRepositoryStub()
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: release,
        catalog=catalog,
        config=QUALITY_RECOMMENDATION_CONFIG,
        clock=lambda: datetime(2026, 9, 8, tzinfo=UTC),
        event_sink=lambda event: None,
    )
    request = RecommendationRequest(
        request_id="quality-purpose", preference_profile_id=profile.profile_id
    )
    result = service.create_run(request)
    assert result.authority.kernel_version == "recommendation-kernel-v4"
    assert result.preference.quality_context.purpose is RecommendationPurpose.SIGHTSEEING
    assert set(result.preference.quality_context.eligible_place_ids).issubset(
        result.candidate_place_ids
    )
    categories = {place.place_id: place.category for place in catalog.places}
    assert all(
        categories[item.place_id] in {"관광지", "문화시설", "레포츠", "축제·공연·행사"}
        for item in result.items
    )
    assert any(
        row.place_value is None and row.total_score_weight_bp == 0
        for item in result.items
        for row in item.contribution.condition_components
    )
    assert service.create_run(request) == result
    with pytest.raises(RecommendationRequestConflict):
        service.create_run(request.model_copy(update={"purpose": RecommendationPurpose.FOOD}))
    assert type(result).model_validate(result.model_dump(mode="json")) == result


def test_legacy_preference_serialization_does_not_gain_quality_keys() -> None:
    legacy = project_recommendation_preference(_preference())
    assert "quality_context" not in legacy.model_dump(mode="json")
    assert legacy.trait_targets[2].value == 100


def test_old_photo_receipt_recovery_never_reinterprets_legacy_evidence() -> None:
    release = MvpScoredRelease.model_validate_json(RELEASE_PATH.read_bytes())
    profile = _preference()
    job_id = "e" * 64
    legacy = create_photo_mvp_recommendation_run(
        release.profiles,
        release_sha256=release.release_sha256,
        membership_sha256=release.membership_sha256,
        relation_authority=PublicRelationAuthority(
            place_ids=tuple(row.place_id for row in release.profiles),
            pairs=release.relation_pairs,
            relation_sha256=release.relation_sha256,
        ),
        preference=project_recommendation_preference(profile),
        photo_projection_policy_sha256="a" * 64,
        photo_projection_output_sha256="b" * 64,
        confirmation_draft_sha256="c" * 64,
        photo_job_reference_sha256=canonical_sha256({"photo_job_id": job_id}),
        images_count=1,
        included_count=1,
        created_at=datetime(2026, 9, 8, tzinfo=UTC),
    )
    runs = RunRepositoryStub()
    runs.run = legacy
    service = RecommendationService(
        profile_repository=ProfileRepositoryStub(profile),
        recommendation_repository=runs,
        release_resolver=lambda: (_ for _ in ()).throw(
            AssertionError("old recovery resolved release")
        ),
        config=QUALITY_RECOMMENDATION_CONFIG,
    )
    request = RecommendationRequest(
        request_id="old-photo-retry", preference_profile_id=profile.profile_id, photo_job_id=job_id
    )
    assert service.create_run(request) == legacy
    with pytest.raises(RecommendationRequestConflict):
        service.create_run(request.model_copy(update={"photo_job_id": "f" * 64}))


def test_photo_receipt_requires_one_shared_observation_mask() -> None:
    import json

    payload = json.loads((ROOT / "fixtures/quality-integration-v4.json").read_text())["photo"][
        "run"
    ]
    first = payload["photo_scores"][0]
    first["observed_traits"] = ["M1"]
    first["photo_trait_fit"] = first["trait_components"][0]["fit"]
    numerator = first["base_relevance"] * 6500 + first["photo_trait_fit"] * 3500
    first["effective_relevance"] = (numerator + 5000) // 10000
    payload["items"][0]["fit_score"] = first["effective_relevance"]
    with pytest.raises(ValueError, match="observation mask"):
        PhotoMvpRecommendationRun.model_validate(payload)
