"""First synthetic RED-to-GREEN slice for the Phase 3 lane baseline."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

import pytest

from itda.contracts.phase3_lane_baseline import Phase3LaneAuthorityBundle
from itda.contracts.place_profile import MISMATCH_TRAIT_SPECS, SUBATTRIBUTE_SPECS, PlaceProfile
from itda.contracts.profile_release import ProfileReleaseCandidate, ProfileReleaseCohortMember
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.phase3_lane_baseline import (
    Phase3LaneBaselineAuthorityError,
    project_phase3_lane_baseline,
)


def _digest(label: str) -> str:
    return canonical_sha256({"synthetic": label})


def _profile(index: int) -> PlaceProfile:
    return PlaceProfile.model_validate(
        {
            "place_id": f"synthetic:phase4:{index:02d}",
            "split": "SYNTHETIC",
            "source_crosswalk": [
                {
                    "provider": "SYNTHETIC",
                    "source_id": f"phase4-{index:02d}",
                    "source_url": f"https://example.invalid/phase4-{index:02d}",
                    "name_ko": f"합성 장소 {index:02d}",
                }
            ],
            "axis_scores": [
                {
                    "axis": axis,
                    "assessment_status": "SCORED",
                    "score": score,
                    "confidence": 80,
                    "display_label_id": label_id,
                    "display_label_ko": label_ko,
                    "evidence_ids": [],
                }
                for axis, score, label_id, label_ko in (
                    ("HISTORY_TRADITION", 70, "history-tradition", "역사·전통"),
                    ("EMOTION_IMAGE", 55, "emotion-image", "감성·이미지"),
                    ("REST_IMMERSION", 60, "rest-immersion", "휴식·몰입"),
                )
            ],
            "subattributes": [
                spec.model_dump(mode="json")
                | {
                    "assessment_status": "SCORED",
                    "value": (index + offset) % 5,
                    "evidence_ids": [],
                }
                for offset, spec in enumerate(SUBATTRIBUTE_SPECS)
            ],
            "mismatch_traits": [
                spec.model_dump(mode="json")
                | {
                    "assessment_status": "SCORED",
                    "value": (index * 7 + offset * 11) % 101,
                    "evidence_ids": [],
                }
                for offset, spec in enumerate(MISMATCH_TRAIT_SPECS)
            ],
            "overall_confidence": 80,
            "recommendation_eligible": True,
            "evidence": [],
            "schema_version": "place-profile-v1",
            "questionnaire_version": "questionnaire-v1",
            "scoring_version": "place-scoring-v1",
            "config_hash": _digest("profile-config"),
            "data_version": "synthetic-phase4-data-v1",
            "release_version": "synthetic-phase3-release-v1",
            "source_version": "synthetic-source-v1",
            "display_copy_version": "place-display-v1",
            "created_at": datetime(2026, 8, 6, tzinfo=UTC),
        }
    )


def _lane(lane: str, index: int, *, missing: bool = False) -> dict[str, Any]:
    if missing:
        return {
            "lane": lane,
            "status": "MISSING",
            "derivation_kind": "PHASE3_PROFILE_CONSTRUCTION_LANE",
            "source_sha256": None,
            "reviewed_evidence_sha256": None,
            "meaningful_character_count": 0,
            "directly_linked_odii": False if lane == "ODII" else None,
            "attribute_scores": [],
        }
    return {
        "lane": lane,
        "status": "READY",
        "derivation_kind": "PHASE3_PROFILE_CONSTRUCTION_LANE",
        "source_sha256": _digest(f"{lane}-source-{index}"),
        "reviewed_evidence_sha256": _digest(f"{lane}-review-{index}"),
        "meaningful_character_count": 650 if lane == "DESCRIPTION" else 900,
        "directly_linked_odii": True if lane == "ODII" else None,
        "attribute_scores": [
            {
                "attribute_id": spec.attribute_id.value,
                "score_milli": ((index + offset) % 5) * 1000,
                "evidence_refs": [_digest(f"{lane}-evidence-{index}-{offset}")],
            }
            for offset, spec in enumerate(SUBATTRIBUTE_SPECS)
        ],
    }


def _fixture() -> tuple[
    ProfileReleaseCandidate,
    dict[str, bytes],
    dict[str, Any],
]:
    profiles = [_profile(index) for index in range(24)]
    profile_bodies = {
        profile.place_id: canonical_json_bytes(profile.model_dump(mode="json"))
        for profile in profiles
    }
    cohort = tuple(
        ProfileReleaseCohortMember(
            place_ref=profile.place_id,
            label_ready=True,
            rights_ready=True,
            evidence_ready=True,
            description_lane="READY",
            odii_lane="MISSING" if index == 0 else "READY",
            profile_sha256=canonical_sha256(profile.model_dump(mode="json")),
            label_export_sha256=_digest(f"label-{index}"),
            candidate_manifest_sha256=_digest(f"candidate-{index}"),
            reviewed_evidence_manifest_sha256=_digest(f"reviewed-{index}"),
            accepted_review_set_sha256=_digest(f"accepted-{index}"),
            rights_sha256=_digest(f"rights-{index}"),
            source_sha256=_digest(f"source-{index}"),
        )
        for index, profile in enumerate(profiles)
    )
    release = ProfileReleaseCandidate(
        release_id="synthetic-phase3-active",
        builder_principal="synthetic-builder",
        canonical_lineage_sha256=_digest("canonical-lineage"),
        dev_lineage_sha256=_digest("dev-lineage"),
        profile_schema_sha256=_digest("profile-schema"),
        label_freeze_sha256=_digest("label-freeze"),
        candidate_run_sha256=_digest("candidate-run"),
        reviewed_manifest_sha256=_digest("reviewed-manifest"),
        rights_manifest_sha256=_digest("rights-manifest"),
        source_manifest_sha256=_digest("source-manifest"),
        code_sha256=_digest("phase3-code"),
        config_sha256=_digest("phase3-config"),
        cohort=cohort,
    )
    authority: dict[str, Any] = {
        "schema_version": "itda.phase3-lane-authority.v1",
        "predecessor_release_sha256": release.release_sha256,
        "canonical_lineage_sha256": release.canonical_lineage_sha256,
        "dev_lineage_sha256": release.dev_lineage_sha256,
        "profile_schema_sha256": release.profile_schema_sha256,
        "source_manifest_sha256": release.source_manifest_sha256,
        "reviewed_manifest_sha256": release.reviewed_manifest_sha256,
        "members": [
            {
                "place_ref": member.place_ref,
                "profile_sha256": member.profile_sha256,
                "description": _lane("DESCRIPTION", index),
                "odii": _lane("ODII", index, missing=index == 0),
                "mismatch_traits": [
                    {
                        "trait_id": trait.trait_id.value,
                        "value": trait.value,
                    }
                    for trait in profiles[index].mismatch_traits
                ],
            }
            for index, member in enumerate(release.cohort)
        ],
    }
    for member in authority["members"]:
        member["member_sha256"] = canonical_sha256(member)
    authority["authority_sha256"] = canonical_sha256(authority)
    return release, profile_bodies, authority


def test_exact_authority_lane_projection_is_release_bound_and_complete() -> None:
    release, profile_bodies, authority_payload = _fixture()

    result = project_phase3_lane_baseline(
        predecessor_release=release,
        active_release_sha256=str(release.release_sha256),
        profile_bodies=profile_bodies,
        authority_bundle=Phase3LaneAuthorityBundle.model_validate(authority_payload),
        trusted_authority_sha256=authority_payload["authority_sha256"],
    )

    assert result.status == "READY"
    assert result.baseline is not None
    assert result.baseline.predecessor_release_sha256 == release.release_sha256
    assert len(result.baseline.members) == 24
    assert [member.profile_sha256 for member in result.baseline.members] == [
        member.profile_sha256 for member in release.cohort
    ]
    assert result.baseline.members[0].odii.status == "MISSING"
    assert result.baseline.members[0].odii.attribute_scores == ()
    assert result.baseline.members[0].odii.reviewed_evidence_sha256 is None
    assert result.baseline.members[1].description.attribute_scores != (
        result.baseline.members[1].odii.attribute_scores
    )


def test_absent_protected_lane_bundle_is_truthfully_pending_without_rescoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release, profile_bodies, _ = _fixture()

    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("raw Phase 3 text scoring must not run")

    monkeypatch.setattr(
        "itda.analysis.text.candidate_pipeline.build_candidate_manifest",
        forbidden,
    )
    result = project_phase3_lane_baseline(
        predecessor_release=release,
        active_release_sha256=str(release.release_sha256),
        profile_bodies=profile_bodies,
        authority_bundle=None,
    )

    assert result.status == "PENDING_PROTECTED_BASELINE"
    assert result.baseline is None
    assert result.reason == "PROTECTED_PHASE3_LANE_AUTHORITY_UNAVAILABLE"


def test_profile_body_mismatch_fails_the_whole_projection() -> None:
    release, profile_bodies, authority_payload = _fixture()
    first = release.cohort[0].place_ref
    profile_bodies[first] = profile_bodies[first].replace(
        b"synthetic:phase4:00", b"synthetic:phase4:99"
    )

    with pytest.raises(Phase3LaneBaselineAuthorityError) as captured:
        project_phase3_lane_baseline(
            predecessor_release=release,
            active_release_sha256=str(release.release_sha256),
            profile_bodies=profile_bodies,
            authority_bundle=authority_payload,
            trusted_authority_sha256=authority_payload["authority_sha256"],
        )

    assert str(captured.value) == "phase 3 lane baseline authority is invalid"


def test_stale_release_or_final_profile_lane_copy_is_rejected() -> None:
    release, profile_bodies, authority_payload = _fixture()
    stale = deepcopy(authority_payload)
    stale["predecessor_release_sha256"] = _digest("stale-release")
    stale["authority_sha256"] = canonical_sha256(
        {key: value for key, value in stale.items() if key != "authority_sha256"}
    )
    copied = deepcopy(authority_payload)
    copied["members"][0]["description"]["derivation_kind"] = "FINAL_PROFILE_COPY"
    copied["members"][0]["odii"] = deepcopy(copied["members"][0]["description"])
    copied["members"][0]["member_sha256"] = canonical_sha256(
        {key: value for key, value in copied["members"][0].items() if key != "member_sha256"}
    )
    copied["authority_sha256"] = canonical_sha256(
        {key: value for key, value in copied.items() if key != "authority_sha256"}
    )

    for invalid in (stale, copied):
        with pytest.raises(Phase3LaneBaselineAuthorityError):
            project_phase3_lane_baseline(
                predecessor_release=release,
                active_release_sha256=str(release.release_sha256),
                profile_bodies=profile_bodies,
                authority_bundle=invalid,
                trusted_authority_sha256=authority_payload["authority_sha256"],
            )
