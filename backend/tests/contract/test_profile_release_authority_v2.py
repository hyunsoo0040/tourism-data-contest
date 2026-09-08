"""Fail-closed authority tests for the additive profile-release v2 bundle."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import ImageObservationV2
from itda.contracts.phase3_lane_baseline import Phase3LaneBaselineMember
from itda.contracts.phase4_benchmark import (
    BenchmarkReportState,
    ZeroImageFallbackProof,
    build_provisional_report,
    finalize_benchmark,
)
from itda.contracts.profile_fusion import CANONICAL_FUSION_POLICY
from itda.contracts.profile_release import ProfileReleaseCandidate
from itda.contracts.profile_release_v2 import ProfileReleaseCohortMemberV2
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.profile_fusion import build_fused_profile
from tests.contract.test_profile_release_v2 import _v1_payload
from tests.evals.phase4.test_phase4_benchmark import (
    _case,
    _experiment,
    _inventory,
    _review,
)
from tests.evals.phase4.test_profile_confidence_and_labels import (
    _bound_baseline,
)
from tests.evals.phase4.test_profile_confidence_and_labels import (
    _predecessor_profile as _fusion_predecessor_profile,
)
from tests.evals.phase4.test_profile_fusion import _image_observation

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    return canonical_sha256({"synthetic": label})


def _self_hash(payload: dict[str, Any]) -> None:
    payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )


def _predecessor_payload() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = deepcopy(_v1_payload())
    payload["release_id"] = "synthetic-authority-v1-predecessor"
    profiles: list[dict[str, Any]] = []
    for index, member in enumerate(payload["cohort"]):
        place_ref = f"synthetic-v2-place-{index:02d}"
        profile_payload = _fusion_predecessor_profile().model_dump(mode="json")
        profile_payload["place_id"] = place_ref
        profile = type(_fusion_predecessor_profile()).model_validate(profile_payload)
        profile_body = profile.model_dump(mode="json")
        profiles.append(profile_body)
        member["place_ref"] = place_ref
        member["profile_sha256"] = canonical_sha256(profile_body)
    candidate = ProfileReleaseCandidate.model_validate(payload).model_dump(mode="json")
    return candidate, profiles


def _bound_observation(
    media_state: ImageMediumState,
    *,
    representative_manifest_sha256: str,
) -> ImageObservationV2:
    payload = _image_observation(media_state).model_dump(
        mode="json", exclude={"observation_sha256"}
    )
    payload["representative_manifest_sha256"] = representative_manifest_sha256
    payload["observation_sha256"] = canonical_sha256(payload)
    return ImageObservationV2.model_validate(payload)


def _authority_payloads(*, image_bearing: bool = True) -> dict[str, dict[str, Any]]:
    predecessor, predecessor_profiles = _predecessor_payload()
    place_refs = tuple(member["place_ref"] for member in predecessor["cohort"])
    predecessor_members = {
        member["place_ref"]: canonical_sha256(member) for member in predecessor["cohort"]
    }
    media_state = ImageMediumState.QUALIFIED if image_bearing else ImageMediumState.MISSING
    baseline_bodies = [
        _bound_baseline(type(_fusion_predecessor_profile()).model_validate(profile))
        for profile in predecessor_profiles
    ]

    rights = {
        "schema_version": "itda.profile-release-v2-rights-authority.v1",
        "predecessor_release_sha256": predecessor["release_sha256"],
        "canonical_lineage_sha256": predecessor["canonical_lineage_sha256"],
        "dev_lineage_sha256": predecessor["dev_lineage_sha256"],
        "source_manifest_sha256": predecessor["source_manifest_sha256"],
        "reviewed_manifest_sha256": predecessor["reviewed_manifest_sha256"],
        "members": [
            {
                "place_ref": member["place_ref"],
                "predecessor_profile_sha256": member["profile_sha256"],
                "predecessor_member_sha256": predecessor_members[member["place_ref"]],
                "source_sha256": member["source_sha256"],
                "rights_sha256": member["rights_sha256"],
                "reviewed_evidence_manifest_sha256": member["reviewed_evidence_manifest_sha256"],
            }
            for member in predecessor["cohort"]
        ],
    }
    _self_hash(rights)

    lane_baseline = {
        "schema_version": "itda.profile-release-v2-lane-baseline-authority.v1",
        "predecessor_release_sha256": predecessor["release_sha256"],
        "canonical_lineage_sha256": predecessor["canonical_lineage_sha256"],
        "dev_lineage_sha256": predecessor["dev_lineage_sha256"],
        "profile_schema_sha256": predecessor["profile_schema_sha256"],
        "baseline_sha256": "6" * 64,
        "members": [
            {
                "place_ref": place_ref,
                "predecessor_profile_sha256": predecessor["cohort"][index]["profile_sha256"],
                "predecessor_member_sha256": predecessor_members[place_ref],
                "baseline_member_sha256": baseline_bodies[index].member_sha256,
                "mismatch_traits_sha256": canonical_sha256(
                    [
                        trait.model_dump(mode="json")
                        for trait in type(_fusion_predecessor_profile())
                        .model_validate(predecessor_profiles[index])
                        .mismatch_traits
                    ]
                ),
                "baseline": baseline_bodies[index].model_dump(mode="json"),
            }
            for index, place_ref in enumerate(place_refs)
        ],
    }
    _self_hash(lane_baseline)

    selection = {
        "schema_version": "itda.profile-release-v2-selection-authority.v1",
        "selection_manifest_sha256": "3" * 64,
        "selection_policy_sha256": "3" * 64,
        "members": [
            {
                "place_ref": place_ref,
                "media_state": media_state.value,
                "selection_member_sha256": _digest(f"selection-member-{index}"),
            }
            for index, place_ref in enumerate(place_refs)
        ],
    }
    _self_hash(selection)

    observation_bodies = [
        _bound_observation(
            media_state,
            representative_manifest_sha256=selection["selection_manifest_sha256"],
        )
        for _ in place_refs
    ]

    prediction = {
        "schema_version": "itda.profile-release-v2-prediction-authority.v1",
        "selection_manifest_sha256": selection["selection_manifest_sha256"],
        "prediction_batch_sha256": "7" * 64,
        "prediction_freeze_receipt_sha256": _digest("prediction-freeze"),
        "members": [
            {
                "place_ref": place_ref,
                "media_state": media_state.value,
                "prediction_observation_sha256": observation_bodies[index].observation_sha256,
                "observation": observation_bodies[index].model_dump(mode="json"),
            }
            for index, place_ref in enumerate(place_refs)
        ],
    }
    _self_hash(prediction)

    if image_bearing:
        cases = tuple(
            _case(
                place_ref,
                ImageMediumState.QUALIFIED,
                baseline=500 + index * 10,
                candidate=1_000 + index * 10,
                label=1_000 + index * 10,
            )
            for index, place_ref in enumerate(place_refs)
        )
        inventory = (_inventory("authority-visible"),)
    else:
        cases = tuple(
            _case(
                place_ref,
                ImageMediumState.MISSING,
                baseline=1_000 + index * 10,
                candidate=None,
                label=1_000 + index * 10,
            )
            for index, place_ref in enumerate(place_refs)
        )
        inventory = ()
    experiment = _experiment(
        evaluation_scope="DEV_24_PROTECTED",
        case_refs=place_refs,
        cases=cases,
        review_inventory=inventory,
    )
    provisional_report = build_provisional_report(
        experiment=experiment,
        cases=cases,
        review_inventory=inventory,
        sensitivity=(),
        generated_at=NOW,
    )
    provisional = {
        "schema_version": "itda.profile-release-v2-provisional-authority.v1",
        "place_refs": list(place_refs),
        "report": provisional_report.model_dump(mode="json"),
    }
    _self_hash(provisional)

    if image_bearing:
        review = _review(provisional_report, inventory)
        final_report = finalize_benchmark(
            provisional=provisional_report,
            selected_config_sha256=provisional_report.experiment.experiment_sha256,
            human_review=review,
            finalized_at=NOW,
        )
        review_or_fallback = {
            "schema_version": "itda.profile-release-v2-review-authority.v1",
            "review": review.model_dump(mode="json"),
            "fallback": None,
        }
    else:
        fallback = ZeroImageFallbackProof.build(
            outcome=BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
            source_media_state=ImageMediumState.MISSING,
            provisional_report_sha256=provisional_report.provisional_report_sha256,
            baseline_sha256=provisional_report.experiment.baseline_sha256,
        )
        final_report = finalize_benchmark(
            provisional=provisional_report,
            selected_config_sha256=provisional_report.experiment.experiment_sha256,
            zero_image_fallback=fallback,
            finalized_at=NOW,
        )
        review_or_fallback = {
            "schema_version": "itda.profile-release-v2-review-authority.v1",
            "review": None,
            "fallback": fallback.model_dump(mode="json"),
        }
    _self_hash(review_or_fallback)

    final = {
        "schema_version": "itda.profile-release-v2-final-authority.v1",
        "place_refs": list(place_refs),
        "report": final_report.model_dump(mode="json"),
    }
    _self_hash(final)

    profile_members: list[dict[str, Any]] = []
    for index, place_ref in enumerate(place_refs):
        predecessor_profile = type(_fusion_predecessor_profile()).model_validate(
            predecessor_profiles[index]
        )
        fused_profile = build_fused_profile(
            baseline_bodies[index],
            observation_bodies[index],
            predecessor_profile=predecessor_profile,
        )
        member = {
            "place_ref": place_ref,
            "predecessor_profile_sha256": canonical_sha256(predecessor_profiles[index]),
            "predecessor_member_sha256": predecessor_members[place_ref],
            "media_state": media_state.value,
            "image_selection_member_sha256": selection["members"][index]["selection_member_sha256"],
            "prediction_observation_sha256": observation_bodies[index].observation_sha256,
            "fused_profile": fused_profile.model_dump(mode="json"),
        }
        profile_members.append(
            ProfileReleaseCohortMemberV2.model_validate(member).model_dump(mode="json")
        )
    profiles = {
        "schema_version": "itda.profile-release-v2-profile-authority.v1",
        "predecessor_release_sha256": predecessor["release_sha256"],
        "final_report_sha256": final_report.final_report_sha256,
        "fusion_policy_sha256": CANONICAL_FUSION_POLICY.policy_sha256,
        "profile_schema_sha256": _digest("profile-schema-v2"),
        "code_sha256": _digest("release-code"),
        "config_sha256": _digest("release-config"),
        "members": profile_members,
    }
    _self_hash(profiles)

    active_predecessor = {
        "schema_version": "itda.profile-release-v2-active-predecessor-authority.v1",
        "active_release_sha256": predecessor["release_sha256"],
        "lifecycle_state": "ACTIVE",
        "lifecycle_receipt_sha256": _digest("active-lifecycle-receipt"),
        "candidate": predecessor,
        "profiles": predecessor_profiles,
    }
    _self_hash(active_predecessor)

    return {
        "predecessor": active_predecessor,
        "rights": rights,
        "lane_baseline": lane_baseline,
        "selection": selection,
        "prediction": prediction,
        "provisional": provisional,
        "final": final,
        "review_or_fallback": review_or_fallback,
        "fusion_config": CANONICAL_FUSION_POLICY.model_dump(mode="json"),
        "profiles": profiles,
    }


def _request(payloads: dict[str, dict[str, Any]]) -> dict[str, Any]:
    predecessor = payloads["predecessor"]
    return {
        "release_id": "synthetic-v2-authority-release",
        "builder_principal": "synthetic-v2-builder",
        "active_predecessor_sha256": predecessor["active_release_sha256"],
        "active_predecessor_lifecycle_receipt_sha256": predecessor["lifecycle_receipt_sha256"],
        "active_predecessor_authority_sha256": predecessor["manifest_sha256"],
        "rights_manifest_sha256": payloads["rights"]["manifest_sha256"],
        "lane_baseline_manifest_sha256": payloads["lane_baseline"]["manifest_sha256"],
        "selection_authority_sha256": payloads["selection"]["manifest_sha256"],
        "prediction_authority_sha256": payloads["prediction"]["manifest_sha256"],
        "provisional_authority_sha256": payloads["provisional"]["manifest_sha256"],
        "final_authority_sha256": payloads["final"]["manifest_sha256"],
        "review_or_fallback_authority_sha256": payloads["review_or_fallback"]["manifest_sha256"],
        "fusion_policy_sha256": payloads["fusion_config"]["policy_sha256"],
        "profiles_manifest_sha256": payloads["profiles"]["manifest_sha256"],
    }


def _write_bundle(root: Path, payloads: dict[str, dict[str, Any]]) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    names: dict[str, str] = {}
    for key, payload in payloads.items():
        name = f"{key}.json"
        (root / name).write_bytes(canonical_json_bytes(payload))
        names[key] = name
    return names


def _resolve(
    tmp_path: Path,
    payloads: dict[str, dict[str, Any]],
    *,
    request: dict[str, Any] | None = None,
) -> Any:
    from itda.contracts.profile_release_authority import (
        ProfileReleaseAuthorityPathsV2,
        resolve_authoritative_profile_release_candidate_v2,
    )

    names = _write_bundle(tmp_path, payloads)
    return resolve_authoritative_profile_release_candidate_v2(
        request=_request(payloads) if request is None else request,
        paths=ProfileReleaseAuthorityPathsV2(root=tmp_path, **names),
    )


def test_coherent_server_bundle_resolves_one_unapproved_successor(tmp_path: Path) -> None:
    payloads = _authority_payloads()
    candidate = _resolve(tmp_path, payloads)

    assert candidate.state == "BUILT_UNAPPROVED"
    assert (
        candidate.lineage.predecessor_release_sha256
        == payloads["predecessor"]["active_release_sha256"]
    )
    assert (
        candidate.lineage.final_report_sha256 == payloads["final"]["report"]["final_report_sha256"]
    )
    assert (
        candidate.lineage.human_review_manifest_sha256
        == payloads["review_or_fallback"]["review"]["review_manifest_sha256"]
    )
    assert len(candidate.cohort) == 24
    assert candidate.confidence_is_ranking_input is False

    text_only_payloads = _authority_payloads(image_bearing=False)
    text_only = _resolve(tmp_path / "text-only", text_only_payloads)
    assert text_only.adoption_state == "NO_IMAGE_TEXT_ODII_ONLY"
    assert text_only.lineage.human_review_manifest_sha256 is None
    assert text_only.lineage.zero_image_fallback_sha256
    expected_text_only = build_fused_profile(
        Phase3LaneBaselineMember.model_validate(
            text_only_payloads["lane_baseline"]["members"][0]["baseline"]
        ),
        ImageObservationV2.model_validate(
            text_only_payloads["prediction"]["members"][0]["observation"]
        ),
        predecessor_profile=type(_fusion_predecessor_profile()).model_validate(
            text_only_payloads["predecessor"]["profiles"][0]
        ),
    )
    assert canonical_json_bytes(
        text_only.cohort[0].fused_profile.model_dump(mode="json")
    ) == canonical_json_bytes(expected_text_only.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("manifest", "body_field"),
    (
        ("predecessor", "profiles"),
        ("lane_baseline", "baseline"),
        ("prediction", "observation"),
    ),
)
def test_complete_source_bodies_are_required(
    tmp_path: Path,
    manifest: str,
    body_field: str,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    payloads = _authority_payloads()
    request = _request(payloads)
    if manifest == "predecessor":
        payloads[manifest].pop(body_field)
    else:
        payloads[manifest]["members"][0].pop(body_field)
    _self_hash(payloads[manifest])
    request_key = {
        "predecessor": "active_predecessor_authority_sha256",
        "lane_baseline": "lane_baseline_manifest_sha256",
        "prediction": "prediction_authority_sha256",
    }[manifest]
    request[request_key] = payloads[manifest]["manifest_sha256"]

    with pytest.raises(ProfileReleaseAuthorityError):
        _resolve(tmp_path / manifest, payloads, request=request)


def test_coherent_recalculation_from_non_authoritative_fidelity_is_rejected(
    tmp_path: Path,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    payloads = _authority_payloads()
    request = _request(payloads)
    lane_member = payloads["lane_baseline"]["members"][0]
    forged_baseline_payload = deepcopy(lane_member["baseline"])
    forged_baseline_payload.pop("member_sha256")
    forged_baseline_payload["description"]["meaningful_character_count"] = 499
    forged_baseline = Phase3LaneBaselineMember.model_validate(forged_baseline_payload)
    predecessor_profile = type(_fusion_predecessor_profile()).model_validate(
        payloads["predecessor"]["profiles"][0]
    )
    observation = ImageObservationV2.model_validate(
        payloads["prediction"]["members"][0]["observation"]
    )
    forged_profile = build_fused_profile(
        forged_baseline,
        observation,
        predecessor_profile=predecessor_profile,
    ).model_dump(mode="json")
    forged_profile["baseline_member_sha256"] = lane_member["baseline_member_sha256"]
    forged_profile["profile_fusion_sha256"] = canonical_sha256(
        {key: value for key, value in forged_profile.items() if key != "profile_fusion_sha256"}
    )
    profile_member = payloads["profiles"]["members"][0]
    profile_member["fused_profile"] = forged_profile
    profile_member.pop("member_sha256")
    payloads["profiles"]["members"][0] = ProfileReleaseCohortMemberV2.model_validate(
        profile_member
    ).model_dump(mode="json")
    _self_hash(payloads["profiles"])
    request["profiles_manifest_sha256"] = payloads["profiles"]["manifest_sha256"]

    with pytest.raises(ProfileReleaseAuthorityError):
        _resolve(tmp_path, payloads, request=request)


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate-predecessor-body",
        "partial-predecessor-body",
        "stale-baseline-identity",
        "observation-media-mismatch",
        "fact-bearing-non-qualified-observation",
    ),
)
def test_mixed_or_invalid_source_body_cohorts_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    payloads = _authority_payloads()
    request = _request(payloads)
    if mutation == "duplicate-predecessor-body":
        payloads["predecessor"]["profiles"][1]["place_id"] = payloads["predecessor"]["profiles"][0][
            "place_id"
        ]
        changed_manifest = "predecessor"
        request_key = "active_predecessor_authority_sha256"
    elif mutation == "partial-predecessor-body":
        payloads["predecessor"]["profiles"].pop()
        changed_manifest = "predecessor"
        request_key = "active_predecessor_authority_sha256"
    elif mutation == "stale-baseline-identity":
        baseline = payloads["lane_baseline"]["members"][0]["baseline"]
        baseline.pop("member_sha256")
        baseline["place_ref"] = "synthetic-v2-place-stale"
        sealed = Phase3LaneBaselineMember.model_validate(baseline)
        payloads["lane_baseline"]["members"][0]["baseline"] = sealed.model_dump(mode="json")
        changed_manifest = "lane_baseline"
        request_key = "lane_baseline_manifest_sha256"
    elif mutation == "observation-media-mismatch":
        payloads["prediction"]["members"][0]["observation"] = _bound_observation(
            ImageMediumState.MISSING,
            representative_manifest_sha256=payloads["selection"]["selection_manifest_sha256"],
        ).model_dump(mode="json")
        changed_manifest = "prediction"
        request_key = "prediction_authority_sha256"
    else:
        observation = payloads["prediction"]["members"][0]["observation"]
        observation["media_state"] = ImageMediumState.MISSING.value
        observation["observation_sha256"] = canonical_sha256(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )
        changed_manifest = "prediction"
        request_key = "prediction_authority_sha256"
    _self_hash(payloads[changed_manifest])
    request[request_key] = payloads[changed_manifest]["manifest_sha256"]

    with pytest.raises(ProfileReleaseAuthorityError):
        _resolve(tmp_path / mutation, payloads, request=request)


@pytest.mark.parametrize(
    "semantic",
    ("score", "confidence", "axis", "mismatch", "label"),
)
def test_rehashed_fused_profile_semantic_forgery_is_rejected(
    tmp_path: Path,
    semantic: str,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    payloads = _authority_payloads()
    request = _request(payloads)
    member = payloads["profiles"]["members"][0]
    profile = member["fused_profile"]
    if semantic == "score":
        attribute = profile["attributes"][0]
        attribute["score_milli"] += 1
        attribute["attribute_sha256"] = canonical_sha256(
            {key: value for key, value in attribute.items() if key != "attribute_sha256"}
        )
    elif semantic == "confidence":
        confidence = profile["confidence"]
        confidence["publication_state"] = (
            "EXCLUDED_MANUAL_REVIEW"
            if confidence["publication_state"] == "PUBLISHABLE"
            else "PUBLISHABLE"
        )
        confidence["profile_confidence_sha256"] = canonical_sha256(
            {key: value for key, value in confidence.items() if key != "profile_confidence_sha256"}
        )
    elif semantic == "axis":
        axis = profile["axes"][0]
        axis["score_milli"] += 1
        axis["score_percent"] = (axis["score_milli"] + 20) // 40
        axis["axis_sha256"] = canonical_sha256(
            {key: value for key, value in axis.items() if key != "axis_sha256"}
        )
    elif semantic == "mismatch":
        profile["mismatch_traits"][0]["value"] += 1
    else:
        label = profile["display_label"]
        label["label_ko"] = "위조된 표시 라벨"
        label["label_sha256"] = canonical_sha256(
            {key: value for key, value in label.items() if key != "label_sha256"}
        )
    profile["profile_fusion_sha256"] = canonical_sha256(
        {key: value for key, value in profile.items() if key != "profile_fusion_sha256"}
    )
    member["member_sha256"] = canonical_sha256(
        {key: value for key, value in member.items() if key != "member_sha256"}
    )
    _self_hash(payloads["profiles"])
    request["profiles_manifest_sha256"] = payloads["profiles"]["manifest_sha256"]

    with pytest.raises(ProfileReleaseAuthorityError):
        _resolve(tmp_path / semantic, payloads, request=request)


def test_recorded_active_predecessor_pointer_is_required_and_fail_closed(
    tmp_path: Path,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    payloads = _authority_payloads()
    resolved = _resolve(tmp_path / "active", payloads)
    assert (
        resolved.lineage.predecessor_release_sha256
        == payloads["predecessor"]["active_release_sha256"]
    )

    inactive = deepcopy(payloads)
    inactive["predecessor"]["lifecycle_state"] = "APPROVED_INACTIVE"
    _self_hash(inactive["predecessor"])
    with pytest.raises(ProfileReleaseAuthorityError) as captured:
        _resolve(tmp_path / "inactive", inactive)
    assert str(captured.value) == "profile release authority bundle is invalid"

    raw_candidate = deepcopy(payloads)
    wrapped_request = _request(payloads)
    raw_candidate["predecessor"] = raw_candidate["predecessor"]["candidate"]
    with pytest.raises(ProfileReleaseAuthorityError) as captured:
        _resolve(tmp_path / "raw-candidate", raw_candidate, request=wrapped_request)
    assert str(captured.value) == "profile release authority bundle is invalid"


def test_provider_evaluator_or_lifecycle_claims_cannot_replace_release_authority(
    tmp_path: Path,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    payloads = _authority_payloads()
    request = _request(payloads)
    request.update(
        {
            "provider_authority": "provider-canary",
            "evaluator_authority": "evaluator-canary",
            "approval_state": "ACTIVE",
        }
    )
    with pytest.raises(ProfileReleaseAuthorityError) as captured:
        _resolve(tmp_path, payloads, request=request)
    rendered = f"{captured.value!s} {captured.value!r}"
    assert rendered == (
        "profile release authority bundle is invalid "
        "ProfileReleaseAuthorityError('profile release authority bundle is invalid')"
    )
    assert "provider-canary" not in rendered
    assert "evaluator-canary" not in rendered


@pytest.mark.parametrize(
    "mutation",
    (
        "stale-active",
        "stale-epoch",
        "mixed-cohort",
        "partial-cohort",
        "digest-mismatch",
        "pending-final",
        "sensitivity-policy",
        "review-mismatch",
        "fabricated-zero-image",
    ),
)
def test_mixed_stale_partial_or_unapproved_authority_fails_generically(
    tmp_path: Path,
    mutation: str,
) -> None:
    from itda.contracts.profile_release_authority import ProfileReleaseAuthorityError

    image_bearing = mutation != "fabricated-zero-image"
    payloads = _authority_payloads(image_bearing=image_bearing)
    request = _request(payloads)
    if mutation == "stale-active":
        request["active_predecessor_sha256"] = _digest("stale-active")
    elif mutation == "stale-epoch":
        request["active_predecessor_lifecycle_receipt_sha256"] = _digest("stale-epoch")
    elif mutation == "mixed-cohort":
        payloads["selection"]["members"][0]["place_ref"] = "mixed-place"
        _self_hash(payloads["selection"])
        request["selection_authority_sha256"] = payloads["selection"]["manifest_sha256"]
    elif mutation == "partial-cohort":
        payloads["prediction"]["members"].pop()
        _self_hash(payloads["prediction"])
        request["prediction_authority_sha256"] = payloads["prediction"]["manifest_sha256"]
    elif mutation == "digest-mismatch":
        request["profiles_manifest_sha256"] = _digest("wrong-profiles")
    elif mutation == "pending-final":
        payloads["final"]["report"] = deepcopy(payloads["provisional"]["report"])
        _self_hash(payloads["final"])
        request["final_authority_sha256"] = payloads["final"]["manifest_sha256"]
    elif mutation == "sensitivity-policy":
        policy = payloads["fusion_config"]
        policy.pop("policy_sha256")
        policy["mode"] = "SENSITIVITY_ONLY"
        policy["release_eligible"] = False
        policy["policy_sha256"] = canonical_sha256(
            {key: value for key, value in policy.items() if key != "policy_sha256"}
        )
        request["fusion_policy_sha256"] = policy["policy_sha256"]
    elif mutation == "review-mismatch":
        payloads["review_or_fallback"]["review"]["provisional_report_sha256"] = _digest(
            "wrong-provisional"
        )
        _self_hash(payloads["review_or_fallback"])
        request["review_or_fallback_authority_sha256"] = payloads["review_or_fallback"][
            "manifest_sha256"
        ]
    else:
        member = payloads["profiles"]["members"][0]
        image_lane = member["fused_profile"]["attributes"][0]["lanes"][2]
        image_lane["included"] = True
        image_lane["exclusion_reason"] = None
        image_lane["score_milli"] = 1_000
        image_lane["effective_weight_numerator"] = 1
        image_lane["normalized_weight_numerator"] = 1
        image_lane["display_weight_percent"] = 1
        image_lane["contribution_numerator"] = 1
        image_lane["evidence_refs"] = ["fabricated-image-ref"]
        member.pop("member_sha256", None)
        _self_hash(payloads["profiles"])
        request["profiles_manifest_sha256"] = payloads["profiles"]["manifest_sha256"]

    with pytest.raises(ProfileReleaseAuthorityError) as captured:
        _resolve(tmp_path, payloads, request=request)
    assert str(captured.value) == "profile release authority bundle is invalid"


@pytest.mark.parametrize("entry_kind", ("traversal", "symlink", "oversized", "duplicate-key"))
def test_v2_authority_reads_are_root_bounded_canonical_and_no_follow(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    from itda.contracts.profile_release_authority import (
        ProfileReleaseAuthorityError,
        ProfileReleaseAuthorityPathsV2,
        resolve_authoritative_profile_release_candidate_v2,
    )

    payloads = _authority_payloads()
    names = _write_bundle(tmp_path, payloads)
    if entry_kind == "traversal":
        names["rights"] = "../rights.json"
    elif entry_kind == "symlink":
        target = tmp_path / "rights-target.json"
        (tmp_path / names["rights"]).unlink()
        target.write_bytes(canonical_json_bytes(payloads["rights"]))
        (tmp_path / names["rights"]).symlink_to(target)
    elif entry_kind == "oversized":
        (tmp_path / names["rights"]).write_bytes(b"{" + b" " * 2_000_000 + b"}")
    else:
        raw = canonical_json_bytes(payloads["rights"])
        duplicate = raw.replace(b'"schema_version":', b'"schema_version":"duplicate",', 1)
        (tmp_path / names["rights"]).write_bytes(duplicate)

    with pytest.raises(ProfileReleaseAuthorityError) as captured:
        resolve_authoritative_profile_release_candidate_v2(
            request=_request(payloads),
            paths=ProfileReleaseAuthorityPathsV2(root=tmp_path, **names),
        )
    assert str(captured.value) == "profile release authority bundle is invalid"
    rendered = repr(captured.value)
    assert str(tmp_path) not in rendered
    assert "synthetic-v2-place" not in rendered
