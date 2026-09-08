from __future__ import annotations

import random
from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import ImageObservationV2
from itda.contracts.phase3_lane_baseline import Phase3LaneBaselineMember
from itda.contracts.place_profile import MismatchTraitId, SubattributeId
from itda.contracts.profile_fusion import (
    CANONICAL_FUSION_POLICY,
    FusionPolicyConfig,
    LaneId,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.profile_fusion import (
    count_meaningful_characters,
    description_fidelity_bp,
    fuse_attributes,
    image_fidelity_bp,
    odii_fidelity_bp,
    require_release_eligible_policy,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
IMAGE_REF = f"selected-image:{'1' * 64}"


def _attribute_scores(offset: int) -> list[dict[str, object]]:
    return [
        {
            "attribute_id": attribute_id.value,
            "score_milli": min(4_000, offset + index),
            "evidence_refs": [SHA_A],
        }
        for index, attribute_id in enumerate(SubattributeId)
    ]


def _baseline_member(
    *,
    description_count: int = 500,
    odii_count: int = 800,
    description_offset: int = 1_000,
    odii_offset: int = 2_000,
) -> Phase3LaneBaselineMember:
    return Phase3LaneBaselineMember.model_validate(
        {
            "place_ref": "place:synthetic:fusion",
            "profile_sha256": SHA_C,
            "description": {
                "lane": "DESCRIPTION",
                "status": "READY",
                "derivation_kind": "PHASE3_PROFILE_CONSTRUCTION_LANE",
                "source_sha256": SHA_A,
                "reviewed_evidence_sha256": SHA_B,
                "meaningful_character_count": description_count,
                "directly_linked_odii": None,
                "attribute_scores": _attribute_scores(description_offset),
            },
            "odii": {
                "lane": "ODII",
                "status": "READY",
                "derivation_kind": "PHASE3_PROFILE_CONSTRUCTION_LANE",
                "source_sha256": SHA_B,
                "reviewed_evidence_sha256": SHA_A,
                "meaningful_character_count": odii_count,
                "directly_linked_odii": True,
                "attribute_scores": _attribute_scores(odii_offset),
            },
            "mismatch_traits": [
                {"trait_id": trait_id.value, "value": 10 + index}
                for index, trait_id in enumerate(MismatchTraitId)
            ],
        }
    )


def _seal_observation(payload: dict[str, object]) -> ImageObservationV2:
    payload["observation_sha256"] = canonical_sha256(payload)
    return ImageObservationV2.model_validate(payload)


def _image_observation(
    state: ImageMediumState = ImageMediumState.QUALIFIED,
    *,
    selected_count: int = 5,
    image_offset: int = 3_000,
) -> ImageObservationV2:
    if state is not ImageMediumState.QUALIFIED:
        return _seal_observation(
            {
                "schema_version": "photo-attributes.v2",
                "media_state": state.value,
                "representative_manifest_sha256": SHA_C,
                "selected_image_refs": [],
                "observations": [],
                "candidate_axes": [],
                "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
            }
        )

    selected_refs = [f"selected-image:{index:064x}" for index in range(1, selected_count + 1)]
    observations: list[dict[str, object]] = []
    for index, attribute_id in enumerate(SubattributeId):
        observations.append(
            {
                "attribute_id": attribute_id.value,
                "status": "observed",
                "score_milli": min(4_000, image_offset + index),
                "uncertainty_bp": 1_000,
                "visible_evidence": [
                    {
                        "image_ref": selected_refs[0],
                        "region": "전경 중앙",
                        "caption_ko": f"{attribute_id.value}의 직접 보이는 단서",
                        "evidence_kind": "VISIBLE_CUE",
                    }
                ],
            }
        )
    axis_members = (range(0, 4), range(4, 8), range(8, 12))
    axes = []
    for axis_id, members in zip(("H", "E", "R"), axis_members, strict=True):
        values = [min(4_000, image_offset + index) for index in members]
        axes.append(
            {
                "axis_id": axis_id,
                "status": "observed",
                "score_milli": (sum(values) + 2) // 4,
                "missing_attribute_ids": [],
                "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
            }
        )
    return _seal_observation(
        {
            "schema_version": "photo-attributes.v2",
            "media_state": "QUALIFIED",
            "representative_manifest_sha256": SHA_C,
            "selected_image_refs": selected_refs,
            "observations": observations,
            "candidate_axes": axes,
            "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
        }
    )


def _attribute(result: tuple[object, ...], attribute_id: SubattributeId):
    return next(row for row in result if row.attribute_id is attribute_id)


def test_canonical_weights_fidelity_boundaries_and_unicode_counter_are_frozen() -> None:
    weights = {
        row.axis_id: (row.description_bp, row.odii_bp, row.image_bp)
        for row in CANONICAL_FUSION_POLICY.base_weights
    }
    assert weights == {
        "H": (3_500, 4_500, 2_000),
        "E": (2_000, 1_000, 7_000),
        "R": (3_500, 1_500, 5_000),
    }
    assert [description_fidelity_bp(value) for value in (0, 199, 200, 499, 500)] == [
        4_000,
        4_000,
        7_000,
        7_000,
        10_000,
    ]
    assert [odii_fidelity_bp(value, directly_linked=True) for value in (1, 799, 800)] == [
        7_000,
        7_000,
        10_000,
    ]
    assert odii_fidelity_bp(0, directly_linked=False) == 0
    assert [image_fidelity_bp(value) for value in (0, 1, 2, 4, 5)] == [
        0,
        4_000,
        7_000,
        7_000,
        10_000,
    ]
    assert count_meaningful_characters("  경주! A-1\t") == 4
    assert count_meaningful_characters("경주") == 2


def test_full_fidelity_uses_exact_effective_weights_contributions_and_half_up() -> None:
    fused = fuse_attributes(_baseline_member(), _image_observation())
    h1 = _attribute(fused, SubattributeId.H1)

    assert h1.score_milli == 1_850
    assert [trace.lane_id for trace in h1.lanes] == list(LaneId)
    assert [trace.base_weight_bp for trace in h1.lanes] == [3_500, 4_500, 2_000]
    assert [trace.fidelity_bp for trace in h1.lanes] == [10_000, 10_000, 10_000]
    assert [trace.quality_bp for trace in h1.lanes] == [10_000, 10_000, 10_000]
    assert [trace.display_weight_percent for trace in h1.lanes] == [35, 45, 20]
    assert sum(trace.display_weight_percent for trace in h1.lanes) == 100
    assert all(trace.normalized_weight_denominator == 1_000_000_000_000 for trace in h1.lanes)
    assert h1.lanes[0].contribution_numerator == 1_000 * 350_000_000_000
    assert h1.lanes[0].contribution_denominator == 1_000_000_000_000


@pytest.mark.parametrize(
    "state",
    (
        ImageMediumState.MISSING,
        ImageMediumState.EMPTY,
        ImageMediumState.PROVENANCE_INCOMPLETE,
        ImageMediumState.RIGHTS_RESTRICTED,
        ImageMediumState.ANALYSIS_FAILED,
    ),
)
def test_each_non_image_state_is_exact_text_odii_identity_with_distinct_trace(
    state: ImageMediumState,
) -> None:
    fused = fuse_attributes(_baseline_member(), _image_observation(state))
    h1 = _attribute(fused, SubattributeId.H1)

    assert h1.score_milli == 1_563
    assert [trace.display_weight_percent for trace in h1.lanes] == [44, 56, 0]
    assert h1.lanes[2].score_milli is None
    assert h1.lanes[2].effective_weight_numerator == 0
    assert h1.lanes[2].exclusion_reason == state.value
    assert h1.lanes[2].evidence_refs == ()


def test_largest_remainder_is_total_ordered_and_property_stable() -> None:
    rng = random.Random(4_008)
    states = tuple(ImageMediumState)
    for _ in range(100):
        state = rng.choice(states)
        selected_count = rng.choice((1, 2, 4, 5))
        fused = fuse_attributes(
            _baseline_member(
                description_count=rng.choice((199, 200, 499, 500)),
                odii_count=rng.choice((799, 800)),
                description_offset=rng.randrange(0, 1_000),
                odii_offset=rng.randrange(1_000, 2_000),
            ),
            _image_observation(state, selected_count=selected_count),
        )
        for attribute in fused:
            included = [trace for trace in attribute.lanes if trace.included]
            assert sum(trace.display_weight_percent for trace in included) == 100
            assert all(
                trace.display_weight_percent == 0 for trace in attribute.lanes if not trace.included
            )
            assert 0 <= attribute.score_milli <= 4_000

    equal = fuse_attributes(
        _baseline_member(description_count=500, odii_count=800),
        _image_observation(selected_count=5),
    )
    replay = fuse_attributes(_baseline_member(), _image_observation())
    assert canonical_json_bytes(
        [row.model_dump(mode="json") for row in equal]
    ) == canonical_json_bytes([row.model_dump(mode="json") for row in replay])


def test_release_resolver_rejects_alternative_weights_or_fidelity_bands() -> None:
    canonical = CANONICAL_FUSION_POLICY.model_dump(mode="json", exclude={"policy_sha256"})
    changed = deepcopy(canonical)
    changed["base_weights"][0]["image_bp"] = 2_001
    changed["base_weights"][0]["description_bp"] = 3_499

    with pytest.raises(ValidationError):
        FusionPolicyConfig.model_validate(changed)

    changed["mode"] = "SENSITIVITY_ONLY"
    changed["release_eligible"] = False
    sensitivity = FusionPolicyConfig.model_validate(changed)
    with pytest.raises(ValueError, match="release eligible"):
        require_release_eligible_policy(sensitivity)
