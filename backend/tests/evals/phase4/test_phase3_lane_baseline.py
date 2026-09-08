"""Focused contract and hostile-input coverage for Phase 3 lane projection."""

from __future__ import annotations

import json
import os
from copy import deepcopy

import pytest
from pydantic import ValidationError
from test_phase4_vertical_slice import _fixture

from itda.cli.materialize_phase3_lane_baseline import main
from itda.contracts.phase3_lane_baseline import Phase3LaneAuthorityBundle
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.phase3_lane_baseline import (
    Phase3LaneBaselineAuthorityError,
    project_phase3_lane_baseline,
)


def _rehash_member_and_bundle(payload: dict[str, object], index: int = 0) -> None:
    member = payload["members"][index]
    member["member_sha256"] = canonical_sha256(
        {key: value for key, value in member.items() if key != "member_sha256"}
    )
    payload["authority_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "authority_sha256"}
    )


def test_contract_is_strict_self_authenticating_and_ordered() -> None:
    _, _, payload = _fixture()
    bundle = Phase3LaneAuthorityBundle.model_validate(payload)

    assert len(bundle.members) == 24
    assert [
        score.attribute_id.value for score in bundle.members[1].description.attribute_scores
    ] == ["H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"]
    assert [trait.trait_id.value for trait in bundle.members[1].mismatch_traits] == [
        "M1",
        "M2",
        "M3",
        "M4",
        "M5",
        "M6",
    ]
    assert bundle.authority_sha256 == canonical_sha256(
        bundle.model_dump(exclude={"authority_sha256"}, mode="json")
    )

    extra = deepcopy(payload)
    extra["candidate_similarity_scores"] = {"H1": 0.999}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Phase3LaneAuthorityBundle.model_validate(extra)


@pytest.mark.parametrize(
    "mutation",
    [
        "candidate-similarity-values",
        "partial-cohort",
        "duplicate-place",
        "lane-order",
        "missing-lane-fabrication",
        "member-digest",
        "authority-digest",
        "profile-set",
    ],
)
def test_malformed_partial_or_non_authoritative_material_fails_closed(mutation: str) -> None:
    release, profile_bodies, payload = _fixture()
    if mutation == "candidate-similarity-values":
        payload["members"][0]["description"]["attribute_scores"][0]["score"] = 0.987
        _rehash_member_and_bundle(payload)
    elif mutation == "partial-cohort":
        payload["members"].pop()
        payload["authority_sha256"] = canonical_sha256(
            {key: value for key, value in payload.items() if key != "authority_sha256"}
        )
    elif mutation == "duplicate-place":
        payload["members"][-1]["place_ref"] = payload["members"][0]["place_ref"]
        _rehash_member_and_bundle(payload, 23)
    elif mutation == "lane-order":
        scores = payload["members"][0]["description"]["attribute_scores"]
        scores[0], scores[1] = scores[1], scores[0]
        _rehash_member_and_bundle(payload)
    elif mutation == "missing-lane-fabrication":
        payload["members"][0]["odii"]["attribute_scores"] = deepcopy(
            payload["members"][0]["description"]["attribute_scores"]
        )
        _rehash_member_and_bundle(payload)
    elif mutation == "member-digest":
        payload["members"][0]["member_sha256"] = "f" * 64
        payload["authority_sha256"] = canonical_sha256(
            {key: value for key, value in payload.items() if key != "authority_sha256"}
        )
    elif mutation == "authority-digest":
        payload["authority_sha256"] = "f" * 64
    else:
        profile_bodies.pop(release.cohort[-1].place_ref)

    with pytest.raises(Phase3LaneBaselineAuthorityError) as captured:
        project_phase3_lane_baseline(
            predecessor_release=release,
            active_release_sha256=str(release.release_sha256),
            profile_bodies=profile_bodies,
            authority_bundle=payload,
            trusted_authority_sha256=payload["authority_sha256"],
        )
    assert str(captured.value) == "phase 3 lane baseline authority is invalid"


def test_projection_does_not_accept_reviewer_candidate_attribute_scores() -> None:
    release, profile_bodies, payload = _fixture()
    payload["members"][1]["description"]["attribute_scores"] = [
        {"attribute_id": "H1", "score": 0.91, "evidence_refs": []}
    ]
    _rehash_member_and_bundle(payload, 1)

    with pytest.raises(Phase3LaneBaselineAuthorityError):
        project_phase3_lane_baseline(
            predecessor_release=release,
            active_release_sha256=str(release.release_sha256),
            profile_bodies=profile_bodies,
            authority_bundle=payload,
            trusted_authority_sha256=payload["authority_sha256"],
        )


def test_cli_publishes_pending_result_once_without_authority(tmp_path) -> None:
    release, profile_bodies, _ = _fixture()
    release_path = tmp_path / "release.json"
    profiles_path = tmp_path / "profiles.json"
    output_path = tmp_path / "baseline-result.json"
    release_path.write_bytes(canonical_json_bytes(release.model_dump(mode="json")))
    profiles_path.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "itda.phase3-profile-bodies.v1",
                "profiles": [
                    {
                        "place_ref": member.place_ref,
                        "profile": json.loads(profile_bodies[member.place_ref]),
                    }
                    for member in release.cohort
                ],
            }
        )
    )

    assert (
        main(
            [
                "--release",
                str(release_path),
                "--profiles",
                str(profiles_path),
                "--active-release-sha256",
                str(release.release_sha256),
                "--output",
                str(output_path),
            ]
        )
        == 3
    )
    assert json.loads(output_path.read_bytes()) == {
        "status": "PENDING_PROTECTED_BASELINE",
        "reason": "PROTECTED_PHASE3_LANE_AUTHORITY_UNAVAILABLE",
        "baseline": None,
    }
    with pytest.raises(FileExistsError):
        main(
            [
                "--release",
                str(release_path),
                "--profiles",
                str(profiles_path),
                "--active-release-sha256",
                str(release.release_sha256),
                "--output",
                str(output_path),
            ]
        )


@pytest.mark.parametrize("entry_kind", ["symlink", "hardlink"])
def test_cli_rejects_followable_or_multi_link_release_input(tmp_path, entry_kind: str) -> None:
    release, profile_bodies, _ = _fixture()
    real_release = tmp_path / "real-release.json"
    release_path = tmp_path / "release.json"
    profiles_path = tmp_path / "profiles.json"
    real_release.write_bytes(canonical_json_bytes(release.model_dump(mode="json")))
    if entry_kind == "symlink":
        release_path.symlink_to(real_release)
    else:
        os.link(real_release, release_path)
    profiles_path.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "itda.phase3-profile-bodies.v1",
                "profiles": [
                    {
                        "place_ref": member.place_ref,
                        "profile": json.loads(profile_bodies[member.place_ref]),
                    }
                    for member in release.cohort
                ],
            }
        )
    )

    with pytest.raises((OSError, ValueError)):
        main(
            [
                "--release",
                str(release_path),
                "--profiles",
                str(profiles_path),
                "--active-release-sha256",
                str(release.release_sha256),
                "--output",
                str(tmp_path / "result.json"),
            ]
        )
