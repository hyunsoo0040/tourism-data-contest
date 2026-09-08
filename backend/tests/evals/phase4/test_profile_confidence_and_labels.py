from __future__ import annotations

import inspect
from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.phase3_lane_baseline import Phase3LaneBaselineMember
from itda.contracts.place_profile import PlaceProfile
from itda.contracts.profile_fusion import (
    CANONICAL_FUSION_POLICY,
    FusedAxis,
    FusionPolicyConfig,
    PublicationState,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.profile_fusion import (
    build_fused_profile,
    classify_publication,
    compute_profile_confidence,
    derive_display_label,
    derive_final_axes,
    fuse_attributes,
    require_release_eligible_policy,
)
from tests.evals.phase4.test_phase4_vertical_slice import _profile
from tests.evals.phase4.test_profile_fusion import _baseline_member, _image_observation


def _single_lane_member() -> Phase3LaneBaselineMember:
    payload = _baseline_member().model_dump(mode="json", exclude={"member_sha256"})
    payload["odii"] = {
        "lane": "ODII",
        "status": "MISSING",
        "derivation_kind": "PHASE3_PROFILE_CONSTRUCTION_LANE",
        "source_sha256": None,
        "reviewed_evidence_sha256": None,
        "meaningful_character_count": 0,
        "directly_linked_odii": False,
        "attribute_scores": [],
    }
    return Phase3LaneBaselineMember.model_validate(payload)


def test_unavailable_agreement_is_null_zero_contribution_and_not_renormalized() -> None:
    fused = fuse_attributes(
        _single_lane_member(),
        _image_observation(ImageMediumState.MISSING),
    )

    confidence = compute_profile_confidence(fused)

    history = confidence.axes[0]
    assert history.axis_id == "H"
    assert history.fidelity_bp == 3_500
    assert history.agreement_status == "UNAVAILABLE"
    assert history.agreement_bp is None
    assert history.comparable_lane_pairs == ()
    assert history.fidelity_contribution_bp == 1_925
    assert history.agreement_contribution_bp == 0
    assert history.confidence_bp == 1_925
    assert history.confidence_percent == 19
    assert confidence.overall_confidence_percent == 11
    assert confidence.publication_state is PublicationState.EXCLUDED_MANUAL_REVIEW
    assert confidence.mismatch_warning_authorized is False


def test_two_lanes_make_agreement_available_with_exact_pair_distance_trace() -> None:
    fused = fuse_attributes(
        _baseline_member(),
        _image_observation(ImageMediumState.RIGHTS_RESTRICTED),
    )

    confidence = compute_profile_confidence(fused)

    history = confidence.axes[0]
    assert history.fidelity_bp == 8_000
    assert history.agreement_status == "AVAILABLE"
    assert history.agreement_bp == 7_500
    assert len(history.comparable_lane_pairs) == 1
    pair = history.comparable_lane_pairs[0]
    assert (pair.left_lane, pair.right_lane) == ("DESCRIPTION", "ODII")
    assert pair.shared_attribute_ids == ("H1", "H2", "H3", "H4")
    assert pair.absolute_distance_milli_sum == 4_000
    assert pair.agreement_numerator == 120_000_000
    assert pair.agreement_denominator == 16_000
    assert history.confidence_bp == 7_775
    assert history.confidence_percent == 78


@pytest.mark.parametrize(
    ("confidence", "state", "mismatch_allowed"),
    (
        (54, PublicationState.EXCLUDED_MANUAL_REVIEW, False),
        (55, PublicationState.LIMITED_INFORMATION, False),
        (64, PublicationState.LIMITED_INFORMATION, False),
        (65, PublicationState.LIMITED_INFORMATION, True),
        (69, PublicationState.LIMITED_INFORMATION, True),
        (70, PublicationState.PUBLISHABLE, True),
    ),
)
def test_publication_and_mismatch_boundaries_are_exact(
    confidence: int,
    state: PublicationState,
    mismatch_allowed: bool,
) -> None:
    assert classify_publication(confidence) == (state, mismatch_allowed)


def test_confidence_is_absent_from_ranking_score_calculation() -> None:
    source = inspect.getsource(fuse_attributes)
    assert "confidence" not in source.casefold()

    fused = fuse_attributes(_baseline_member(), _image_observation())
    before = tuple(row.score_milli for row in fused)
    compute_profile_confidence(fused)
    after = tuple(row.score_milli for row in fused)
    assert after == before


def test_alternative_publication_bands_are_sensitivity_only_and_not_releasable() -> None:
    payload = CANONICAL_FUSION_POLICY.model_dump(mode="json", exclude={"policy_sha256"})
    changed = deepcopy(payload)
    changed["publishable_min_percent"] = 71

    with pytest.raises(ValidationError):
        FusionPolicyConfig.model_validate(changed)

    changed["mode"] = "SENSITIVITY_ONLY"
    changed["release_eligible"] = False
    sensitivity = FusionPolicyConfig.model_validate(changed)
    with pytest.raises(ValueError, match="release eligible"):
        require_release_eligible_policy(sensitivity)


def _predecessor_profile() -> PlaceProfile:
    payload = _profile(3).model_dump(mode="json")
    evidence_id = "evidence:synthetic:fusion"
    payload["evidence"] = [
        {
            "evidence_id": evidence_id,
            "provider": "SYNTHETIC",
            "evidence_type": "SYNTHETIC",
            "source_id": "fusion-source",
            "source_url": "https://example.invalid/fusion-source",
            "endpoint": "fixture://profile-fusion",
            "request_scope": {"fixture": "profile-fusion"},
            "retrieved_at": "2026-08-06T00:00:00Z",
            "http_status": 200,
            "raw_response_sha256": "d" * 64,
            "parser_version": "synthetic-parser-v1",
            "source_version": "synthetic-source-v1",
            "excerpt_ko": "프로필 융합 보조 속성 계보를 검증하는 합성 근거입니다.",
            "rights": {
                "license_code": "NOT_APPLICABLE",
                "asset_usage_status": "NOT_APPLICABLE",
                "attribution_ko": "합성 테스트 자료",
                "author_or_photographer": None,
            },
        }
    ]
    for trait in payload["mismatch_traits"]:
        trait["evidence_ids"] = [evidence_id]
    return PlaceProfile.model_validate(payload)


def _bound_baseline(predecessor: PlaceProfile) -> Phase3LaneBaselineMember:
    payload = _baseline_member().model_dump(mode="json", exclude={"member_sha256"})
    payload["place_ref"] = predecessor.place_id
    payload["profile_sha256"] = canonical_sha256(predecessor.model_dump(mode="json"))
    payload["mismatch_traits"] = [
        {"trait_id": trait.trait_id.value, "value": trait.value}
        for trait in predecessor.mismatch_traits
    ]
    return Phase3LaneBaselineMember.model_validate(payload)


def _axis(axis_id: str, score_milli: int) -> FusedAxis:
    members = {
        "H": ("H1", "H2", "H3", "H4"),
        "E": ("I1", "I2", "I3", "I4"),
        "R": ("R1", "R2", "R3", "R4"),
    }
    return FusedAxis.model_validate(
        {
            "axis_id": axis_id,
            "member_attribute_ids": members[axis_id],
            "aggregation_rule": "HALF_UP_MEAN_EXACTLY_FOUR_V1",
            "score_milli": score_milli,
            "score_percent": (score_milli + 20) // 40,
            "policy_sha256": CANONICAL_FUSION_POLICY.policy_sha256,
        }
    )


def test_axes_use_exact_four_member_half_up_and_reject_one_milli_claim_drift() -> None:
    fused = fuse_attributes(_baseline_member(), _image_observation())

    axes = derive_final_axes(fused)

    assert tuple(axis.axis_id for axis in axes) == ("H", "E", "R")
    assert axes[0].member_attribute_ids == ("H1", "H2", "H3", "H4")
    assert axes[0].score_milli == (sum(row.score_milli for row in fused[:4]) + 2) // 4
    assert axes[1].member_attribute_ids == ("I1", "I2", "I3", "I4")
    assert axes[2].member_attribute_ids == ("R1", "R2", "R3", "R4")

    claimed = [axis.model_dump(mode="json") for axis in axes]
    claimed[0]["score_milli"] += 1
    claimed[0]["axis_sha256"] = canonical_sha256(
        {key: value for key, value in claimed[0].items() if key != "axis_sha256"}
    )
    with pytest.raises(ValueError, match="final axis claim drifted"):
        claims = tuple(FusedAxis.model_validate(row) for row in claimed)
        derive_final_axes(fused, claimed_axes=claims)


@pytest.mark.parametrize(
    ("scores", "state", "axis_ids", "label_ko"),
    (
        ((2_600, 2_120, 1_000), "SINGLE", ("H",), "역사·전통형"),
        ((2_600, 2_599, 1_000), "COMPOSITE", ("H", "E"), "역사·전통·감성·이미지 복합형"),
        ((2_400, 2_400, 2_400), "COMPOSITE", ("H", "E"), "역사·전통·감성·이미지 복합형"),
        ((2_599, 2_119, 1_000), "FALLBACK", (), "복합 경험형"),
        ((2_399, 2_399, 2_399), "FALLBACK", (), "복합 경험형"),
    ),
)
def test_label_state_machine_uses_exact_thresholds_and_h_e_r_ties(
    scores: tuple[int, int, int],
    state: str,
    axis_ids: tuple[str, ...],
    label_ko: str,
) -> None:
    label = derive_display_label(
        (_axis("H", scores[0]), _axis("E", scores[1]), _axis("R", scores[2]))
    )

    assert label.state == state
    assert label.axis_ids == axis_ids
    assert label.label_ko == label_ko
    assert label.top_score_milli == max(scores)
    assert label.label_rule_version == "D21_LABEL_STATE_MACHINE_V1"


def test_full_projection_inherits_auxiliary_evidence_and_replays_byte_identically() -> None:
    predecessor = _predecessor_profile()
    baseline = _bound_baseline(predecessor)
    image = _image_observation()

    first = build_fused_profile(baseline, image, predecessor_profile=predecessor)
    second = build_fused_profile(baseline, image, predecessor_profile=predecessor)

    assert tuple(row.attribute_id for row in first.attributes) == tuple(
        row.attribute_id for row in baseline.description.attribute_scores
    )
    assert tuple(axis.axis_id for axis in first.axes) == ("H", "E", "R")
    assert canonical_json_bytes(
        [row.model_dump(mode="json") for row in first.mismatch_traits]
    ) == canonical_json_bytes([row.model_dump(mode="json") for row in predecessor.mismatch_traits])
    assert canonical_json_bytes(
        [row.model_dump(mode="json") for row in first.inherited_evidence]
    ) == canonical_json_bytes([row.model_dump(mode="json") for row in predecessor.evidence])
    assert first.profile_fusion_sha256 == second.profile_fusion_sha256
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )

    wrong_predecessor = _profile(4)
    with pytest.raises(ValueError, match="predecessor profile digest"):
        build_fused_profile(baseline, image, predecessor_profile=wrong_predecessor)
