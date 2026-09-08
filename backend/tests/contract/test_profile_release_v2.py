"""Behavior-first contracts for the additive Phase 4 profile release."""

from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY, FusionPolicyConfig
from itda.contracts.profile_release import ProfileReleaseCandidate, ProfileReleaseStore
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.profile_fusion import build_fused_profile
from tests.evals.phase4.test_profile_confidence_and_labels import (
    _bound_baseline,
    _predecessor_profile,
)
from tests.evals.phase4.test_profile_fusion import _image_observation


def _digest(label: str) -> str:
    return canonical_sha256({"synthetic": label})


def _v1_payload() -> dict[str, object]:
    cohort = [
        {
            "place_ref": f"synthetic-v1-place-{index:02d}",
            "label_ready": True,
            "rights_ready": True,
            "evidence_ready": True,
            "description_lane": "READY",
            "odii_lane": "MISSING" if index % 3 == 0 else "READY",
            "profile_sha256": _digest(f"v1-profile-{index}"),
            "label_export_sha256": _digest(f"v1-label-{index}"),
            "candidate_manifest_sha256": _digest(f"v1-candidate-{index}"),
            "reviewed_evidence_manifest_sha256": _digest(f"v1-reviewed-{index}"),
            "accepted_review_set_sha256": _digest(f"v1-review-set-{index}"),
            "rights_sha256": _digest(f"v1-rights-{index}"),
            "source_sha256": _digest(f"v1-source-{index}"),
        }
        for index in range(24)
    ]
    return {
        "schema_version": "itda.profile-release-candidate.v1",
        "release_id": "synthetic-v1-release",
        "state": "BUILT_UNAPPROVED",
        "builder_principal": "synthetic-v1-builder",
        "canonical_lineage_sha256": _digest("canonical"),
        "dev_lineage_sha256": _digest("dev"),
        "profile_schema_sha256": _digest("v1-profile-schema"),
        "label_freeze_sha256": _digest("label-freeze"),
        "candidate_run_sha256": _digest("candidate-run"),
        "reviewed_manifest_sha256": _digest("reviewed"),
        "rights_manifest_sha256": _digest("rights"),
        "source_manifest_sha256": _digest("source"),
        "code_sha256": _digest("v1-code"),
        "config_sha256": _digest("v1-config"),
        "cohort": cohort,
    }


def _fused_profile(index: int, media_state: ImageMediumState) -> dict[str, object]:
    predecessor = _predecessor_profile()
    baseline = _bound_baseline(predecessor)
    profile = build_fused_profile(
        baseline,
        _image_observation(media_state),
        predecessor_profile=predecessor,
    ).model_dump(mode="json", exclude={"profile_fusion_sha256"})
    profile["place_ref"] = f"synthetic-v2-place-{index:02d}"
    profile["predecessor_profile_sha256"] = _digest(f"predecessor-profile-{index}")
    profile["baseline_member_sha256"] = _digest(f"baseline-member-{index}")
    profile["image_observation_sha256"] = _digest(f"observation-{index}")
    return profile


def _member(index: int, media_state: ImageMediumState) -> dict[str, object]:
    return {
        "place_ref": f"synthetic-v2-place-{index:02d}",
        "predecessor_profile_sha256": _digest(f"predecessor-profile-{index}"),
        "predecessor_member_sha256": _digest(f"predecessor-member-{index}"),
        "media_state": media_state.value,
        "image_selection_member_sha256": _digest(f"selection-member-{index}"),
        "prediction_observation_sha256": _digest(f"observation-{index}"),
        "fused_profile": _fused_profile(index, media_state),
    }


def _lineage(*, image_bearing: bool) -> dict[str, object]:
    return {
        "predecessor_release_sha256": _digest("predecessor-release"),
        "predecessor_lifecycle_receipt_sha256": _digest("predecessor-lifecycle"),
        "canonical_lineage_sha256": _digest("canonical"),
        "dev_lineage_sha256": _digest("dev"),
        "rights_manifest_sha256": _digest("rights"),
        "source_manifest_sha256": _digest("source"),
        "reviewed_manifest_sha256": _digest("reviewed"),
        "lane_baseline_sha256": _digest("lane-baseline"),
        "image_selection_manifest_sha256": _digest("image-selection"),
        "prediction_batch_sha256": _digest("prediction-batch"),
        "prediction_freeze_receipt_sha256": _digest("prediction-freeze"),
        "provisional_report_sha256": _digest("provisional-report"),
        "final_report_sha256": _digest("final-report"),
        "human_review_manifest_sha256": _digest("human-review") if image_bearing else None,
        "zero_image_fallback_sha256": None if image_bearing else _digest("zero-fallback"),
        "fusion_policy_sha256": CANONICAL_FUSION_POLICY.policy_sha256,
        "profile_schema_sha256": _digest("profile-schema-v2"),
        "code_sha256": _digest("v2-code"),
        "config_sha256": _digest("v2-config"),
    }


def _candidate_payload(*, image_bearing: bool = True) -> dict[str, object]:
    state = ImageMediumState.QUALIFIED if image_bearing else ImageMediumState.MISSING
    return {
        "schema_version": "itda.profile-release-candidate.v2",
        "release_id": "synthetic-v2-release",
        "state": "BUILT_UNAPPROVED",
        "builder_principal": "synthetic-v2-builder",
        "adoption_state": "ADOPT" if image_bearing else "NO_IMAGE_TEXT_ODII_ONLY",
        "adopted_attributes": list(
            ("H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4")
            if image_bearing
            else ()
        ),
        "fusion_policy": CANONICAL_FUSION_POLICY.model_dump(mode="json"),
        "lineage": _lineage(image_bearing=image_bearing),
        "cohort": [_member(index, state) for index in range(24)],
    }


def test_additive_dispatch_preserves_v1_bytes_and_builds_only_unapproved_v2() -> None:
    from itda.contracts.profile_release_v2 import (
        ProfileReleaseCandidateV2,
        parse_profile_release_candidate,
    )

    v1_direct = ProfileReleaseCandidate.model_validate(_v1_payload())
    assert (
        v1_direct.release_sha256
        == "61f1e8ff14e6f370d26b30868e27591f8b2b93ae33b657f5b926dbd1e45ae793"
    )
    v1_dispatched = parse_profile_release_candidate(
        canonical_json_bytes(v1_direct.model_dump(mode="json"))
    )
    assert isinstance(v1_dispatched, ProfileReleaseCandidate)
    assert v1_dispatched.release_sha256 == v1_direct.release_sha256
    assert canonical_json_bytes(v1_dispatched.model_dump(mode="json")) == canonical_json_bytes(
        v1_direct.model_dump(mode="json")
    )

    successor = ProfileReleaseCandidateV2.model_validate(_candidate_payload())
    assert successor.state == "BUILT_UNAPPROVED"
    assert len(successor.cohort) == 24
    assert len({member.place_ref for member in successor.cohort}) == 24
    assert successor.lineage.predecessor_release_sha256 == _digest("predecessor-release")
    assert successor.predecessor_member_set_sha256 == canonical_sha256(
        [
            {
                "place_ref": member.place_ref,
                "predecessor_member_sha256": member.predecessor_member_sha256,
                "predecessor_profile_sha256": member.predecessor_profile_sha256,
            }
            for member in successor.cohort
        ]
    )
    assert successor.release_sha256 == canonical_sha256(
        successor.model_dump(mode="json", exclude={"release_sha256"})
    )

    payload = _candidate_payload()
    payload["state"] = "ACTIVE"
    with pytest.raises(ValidationError):
        ProfileReleaseCandidateV2.model_validate(payload)


def test_member_serialization_preserves_all_six_media_states_and_complete_trace() -> None:
    from itda.contracts.profile_release_v2 import ProfileReleaseCohortMemberV2

    for index, media_state in enumerate(ImageMediumState):
        member = ProfileReleaseCohortMemberV2.model_validate(_member(index, media_state))
        assert member.media_state is media_state
        assert len(member.fused_profile.attributes) == 12
        assert len(member.fused_profile.axes) == 3
        assert len(member.fused_profile.mismatch_traits) == 6
        assert member.fused_profile.confidence.profile_confidence_sha256
        assert member.fused_profile.display_label.label_sha256
        assert all(len(attribute.lanes) == 3 for attribute in member.fused_profile.attributes)

    alias = _member(0, ImageMediumState.MISSING)
    alias["media_state"] = "UNAVAILABLE"
    with pytest.raises(ValidationError):
        ProfileReleaseCohortMemberV2.model_validate(alias)

    stale = ProfileReleaseCohortMemberV2.model_validate(
        _member(0, ImageMediumState.MISSING)
    ).model_dump(mode="json")
    stale["place_ref"] = "synthetic-v2-place-stale"
    with pytest.raises(ValidationError):
        ProfileReleaseCohortMemberV2.model_validate(stale)


def test_release_policy_review_and_zero_image_paths_fail_closed() -> None:
    from itda.contracts.profile_release_v2 import ProfileReleaseCandidateV2

    image_candidate = ProfileReleaseCandidateV2.model_validate(_candidate_payload())
    assert image_candidate.lineage.human_review_manifest_sha256 == _digest("human-review")
    assert all(
        any(attribute.lanes[2].included for attribute in member.fused_profile.attributes)
        for member in image_candidate.cohort
    )

    no_review = _candidate_payload()
    no_review["lineage"]["human_review_manifest_sha256"] = None
    with pytest.raises(ValidationError):
        ProfileReleaseCandidateV2.model_validate(no_review)

    text_only = ProfileReleaseCandidateV2.model_validate(_candidate_payload(image_bearing=False))
    assert text_only.adopted_attributes == ()
    assert all(
        not attribute.lanes[2].included
        and attribute.lanes[2].score_milli is None
        and attribute.lanes[2].display_weight_percent == 0
        and attribute.lanes[2].contribution_numerator == 0
        and not attribute.lanes[2].evidence_refs
        for member in text_only.cohort
        for attribute in member.fused_profile.attributes
    )

    fabricated = _candidate_payload(image_bearing=False)
    image_attribute = fabricated["cohort"][0]["fused_profile"]["attributes"][0]
    image_attribute["lanes"][2] = deepcopy(
        _candidate_payload()["cohort"][0]["fused_profile"]["attributes"][0]["lanes"][2]
    )
    image_attribute.pop("attribute_sha256")
    fabricated["cohort"][0].pop("member_sha256", None)
    with pytest.raises(ValidationError):
        ProfileReleaseCandidateV2.model_validate(fabricated)

    sensitivity = CANONICAL_FUSION_POLICY.model_dump(mode="json", exclude={"policy_sha256"})
    sensitivity["mode"] = "SENSITIVITY_ONLY"
    sensitivity["release_eligible"] = False
    sensitivity["policy_sha256"] = canonical_sha256(
        {key: value for key, value in sensitivity.items() if key != "policy_sha256"}
    )
    assert FusionPolicyConfig.model_validate(sensitivity).release_eligible is False
    sensitivity_candidate = _candidate_payload()
    sensitivity_candidate["fusion_policy"] = sensitivity
    with pytest.raises(ValidationError):
        ProfileReleaseCandidateV2.model_validate(sensitivity_candidate)


def test_cross_schema_transition_proof_accepts_only_the_exact_declared_pair(
    tmp_path: object,
) -> None:
    from itda.contracts.profile_release_v2 import (
        ProfileReleaseTransitionProofV2,
        build_exact_predecessor_transition_proof,
        require_exact_predecessor_transition,
    )
    from tests.contract.test_profile_release_authority_v2 import (
        _authority_payloads,
        _predecessor_payload,
        _resolve,
    )

    predecessor = ProfileReleaseCandidate.model_validate(_predecessor_payload()[0])
    successor = _resolve(tmp_path, _authority_payloads())
    proof = build_exact_predecessor_transition_proof(
        successor=successor,
        predecessor=predecessor,
    )

    assert require_exact_predecessor_transition(
        successor=successor,
        predecessor=predecessor,
        proof=proof,
    )
    assert proof.successor_release_sha256 == successor.release_sha256
    assert proof.predecessor_release_sha256 == predecessor.release_sha256
    assert proof.canonical_lineage_sha256 == predecessor.canonical_lineage_sha256
    assert proof.dev_lineage_sha256 == predecessor.dev_lineage_sha256
    assert proof.predecessor_member_set_sha256 == successor.predecessor_member_set_sha256

    sibling_payload = successor.model_dump(mode="json", exclude={"release_sha256"})
    sibling_payload["release_id"] = "synthetic-v2-sibling"
    sibling = successor.__class__.model_validate(sibling_payload)
    with pytest.raises(ValueError, match="exact predecessor transition"):
        require_exact_predecessor_transition(
            successor=sibling,
            predecessor=predecessor,
            proof=proof,
        )

    stale_payload = _predecessor_payload()[0]
    stale_payload.pop("release_sha256")
    stale_payload["release_id"] = "synthetic-stale-predecessor"
    stale = ProfileReleaseCandidate.model_validate(stale_payload)
    with pytest.raises(ValueError, match="exact predecessor transition"):
        require_exact_predecessor_transition(
            successor=successor,
            predecessor=stale,
            proof=proof,
        )

    changed_payload = successor.model_dump(mode="json", exclude={"release_sha256"})
    changed_payload["cohort"][0].pop("member_sha256")
    changed_payload["cohort"][0]["predecessor_member_sha256"] = _digest(
        "changed-predecessor-member"
    )
    changed_payload.pop("predecessor_member_set_sha256")
    changed = successor.__class__.model_validate(changed_payload)
    with pytest.raises(ValueError, match="exact predecessor transition"):
        require_exact_predecessor_transition(
            successor=changed,
            predecessor=predecessor,
            proof=proof,
        )

    tampered = proof.model_dump(mode="json")
    tampered["transition_rule_sha256"] = _digest("generic-cross-schema-rule")
    tampered.pop("proof_sha256")
    with pytest.raises(ValidationError):
        ProfileReleaseTransitionProofV2.model_validate(tampered)

    same_schema_peer = ProfileReleaseCandidate.model_validate(
        {**_predecessor_payload()[0], "release_sha256": None}
    )
    assert ProfileReleaseStore._compatible(predecessor, same_schema_peer)
    incompatible_payload = same_schema_peer.model_dump(mode="json", exclude={"release_sha256"})
    incompatible_payload["profile_schema_sha256"] = _digest("other-v1-profile-schema")
    incompatible_peer = ProfileReleaseCandidate.model_validate(incompatible_payload)
    assert not ProfileReleaseStore._compatible(predecessor, incompatible_peer)
