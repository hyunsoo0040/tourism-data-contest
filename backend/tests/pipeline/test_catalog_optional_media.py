from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.replay_catalog_optional_media import (
    build_optional_media_projection,
    publish_optional_media_projection,
)
from itda.contracts.catalog_optional_media import (
    IMAGE_OBSERVATION_LABELS,
    ImageMediumState,
    OptionalMediaPolicyV2,
    VlmObservationEnvelope,
    build_optional_media_policy,
    project_optional_media_candidate,
)
from itda.domain.canonical import canonical_json_bytes

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
PLACE_ID = f"place:{'1' * 64}"
REPO_ROOT = Path(__file__).resolve().parents[3]
TERMINAL_HISTORY = (
    REPO_ROOT
    / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
    / "02-49-TERMINAL-HISTORY.md"
)
TERMINAL_FAILURE = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/reentries"
    / "fab840841288cc0b0e1b31454cf65de5679e5cda0326a57ce42f22d0bdf377ac"
    / "reentry-exhausted.json"
)


def _source_row() -> dict[str, object]:
    return {
        "place_entity_id": PLACE_ID,
        "provider_place_candidate_id": "candidate:tour-api:123",
        "row_sha256": SHA_A,
        "objective_gate_states": {
            "coordinates": "PASS",
            "description": "PASS",
            "operating_info": "PASS",
            "dataset_rights": "PASS",
            "direct_media": "PASS",
        },
        "representation_assignment_status": "PRIMARY",
        "representation_primary_group": "history_culture",
    }


def _historical_row(
    image_state: ImageMediumState = ImageMediumState.QUALIFIED,
) -> dict[str, object]:
    unqualified = image_state is not ImageMediumState.QUALIFIED
    direct_media_state = {
        ImageMediumState.QUALIFIED: "PASS",
        ImageMediumState.MISSING: "MISSING",
        ImageMediumState.EMPTY: "MISSING",
        ImageMediumState.PROVENANCE_INCOMPLETE: "RIGHTS_BLOCKED",
        ImageMediumState.RIGHTS_RESTRICTED: "RIGHTS_BLOCKED",
        ImageMediumState.ANALYSIS_FAILED: "ANALYSIS_FAILED",
    }[image_state]
    asset_state = (
        "PASS"
        if image_state is ImageMediumState.QUALIFIED
        else "MISSING"
        if image_state in {ImageMediumState.MISSING, ImageMediumState.EMPTY}
        else "BLOCKED"
    )
    reason = {
        ImageMediumState.QUALIFIED: "RIGHTS_AND_PROVENANCE_QUALIFIED",
        ImageMediumState.MISSING: "NO_IMAGE_EVIDENCE",
        ImageMediumState.EMPTY: "SUCCESS_EMPTY_HAS_NO_ASSET_PROVENANCE",
        ImageMediumState.PROVENANCE_INCOMPLETE: "ASSET_PROVENANCE_INCOMPLETE",
        ImageMediumState.RIGHTS_RESTRICTED: "NARROWER_TYPE3_ASSET_RESTRICTION",
        ImageMediumState.ANALYSIS_FAILED: "IMAGE_ANALYSIS_FAILED",
    }[image_state]
    return {
        "place_entity_id": PLACE_ID,
        "identity_state": "PASS",
        "coordinates_state": "PASS",
        "description_state": "PASS",
        "operating_info_state": "PASS",
        "dataset_rights": {
            "state": "PASS",
            "attestation_sha256": SHA_B,
        },
        "direct_media_state": direct_media_state,
        "image_medium_state": image_state.value,
        "asset_rights": {
            "state": asset_state,
            "reason": reason,
            "provenance_complete": image_state
            not in {
                ImageMediumState.MISSING,
                ImageMediumState.EMPTY,
                ImageMediumState.PROVENANCE_INCOMPLETE,
            },
            "analysis_eligible": not unqualified,
            "ui_eligible": not unqualified,
            "demo_eligible": not unqualified,
            "attestation_sha256": SHA_C,
        },
        "response_evidence_sha256": SHA_C,
    }


def _observations() -> dict[str, dict[str, object]]:
    return {
        label: {
            "status": "observed",
            "score": 2.0,
            "evidence": [f"visible evidence for {label}"],
        }
        for label in IMAGE_OBSERVATION_LABELS
    }


def test_policy_manifest_is_strict_versioned_and_digest_bound() -> None:
    policy = build_optional_media_policy()
    restored = OptionalMediaPolicyV2.from_manifest(policy.model_dump(mode="json"))

    assert restored == policy
    assert restored.schema_version == "itda.catalog-optional-media-policy.v2"
    assert restored.policy_version == "optional-media-v2"
    assert restored.image_observation_labels == IMAGE_OBSERVATION_LABELS
    assert restored.model_boundary.model_id == "glm-5v-turbo"
    assert restored.model_boundary.live_spike_status == "PARTIAL"
    assert restored.model_boundary.production_user_photo_status == "BLOCKED"
    assert restored.model_boundary.model_may_select_or_rank is False
    assert restored.fusion_policy.renormalization_required_without_qualified_image

    tampered = policy.model_dump(mode="json")
    tampered["policy_sha256"] = SHA_A
    with pytest.raises(ValidationError, match="policy hash"):
        OptionalMediaPolicyV2.from_manifest(tampered)


@pytest.mark.parametrize("image_state", tuple(ImageMediumState))
def test_image_only_states_do_not_change_catalog_eligibility(
    image_state: ImageMediumState,
) -> None:
    candidate = project_optional_media_candidate(
        _source_row(),
        _historical_row(image_state),
        build_optional_media_policy(),
    )

    assert candidate.catalog_eligible is True
    assert candidate.non_image_failure_reasons == ()
    assert candidate.image_medium.state is image_state
    assert candidate.image_medium.image_observation_eligible is (
        image_state is ImageMediumState.QUALIFIED
    )
    assert candidate.renormalization_required is (image_state is not ImageMediumState.QUALIFIED)


@pytest.mark.parametrize(
    ("gate_name", "mutation"),
    [
        ("canonical_identity", ("historical", "identity_state")),
        ("coordinates", ("historical", "coordinates_state")),
        ("description", ("historical", "description_state")),
        ("operating_information", ("historical", "operating_info_state")),
        ("dataset_rights", ("dataset_rights", "state")),
        ("representation_assignment", ("source", "representation_assignment_status")),
    ],
)
def test_every_non_image_gate_remains_fail_closed(
    gate_name: str,
    mutation: tuple[str, str],
) -> None:
    source = _source_row()
    historical = _historical_row(ImageMediumState.MISSING)
    section, key = mutation
    if section == "source":
        source[key] = "UNCLASSIFIED"
    elif section == "dataset_rights":
        dataset_rights = historical["dataset_rights"]
        assert isinstance(dataset_rights, dict)
        dataset_rights[key] = "BLOCKED"
    else:
        historical[key] = "BLOCKED"

    candidate = project_optional_media_candidate(
        source,
        historical,
        build_optional_media_policy(),
    )

    assert candidate.catalog_eligible is False
    assert gate_name in candidate.non_image_failure_reasons
    assert candidate.image_medium.state is ImageMediumState.MISSING


def test_vlm_response_accepts_only_twelve_observations_without_authority_fields() -> None:
    valid = {
        "schema_version": "itda.photo-attributes.v1",
        "observations": _observations(),
    }
    parsed = VlmObservationEnvelope.model_validate(valid)
    assert tuple(parsed.observations) == IMAGE_OBSERVATION_LABELS

    for forbidden in (
        "axis_scores",
        "recommendation_score",
        "rank",
        "catalog_eligible",
        "admission",
        "selection",
    ):
        hostile = deepcopy(valid)
        hostile[forbidden] = 1
        with pytest.raises(ValidationError):
            VlmObservationEnvelope.model_validate(hostile)


def test_dataset_and_image_asset_rights_are_never_merged() -> None:
    historical = _historical_row(ImageMediumState.RIGHTS_RESTRICTED)
    candidate = project_optional_media_candidate(
        _source_row(),
        historical,
        build_optional_media_policy(),
    )

    assert candidate.catalog_eligible is True
    assert candidate.non_image_gates.dataset_rights == "PASS"
    assert candidate.image_medium.image_asset_rights_state == "BLOCKED"
    assert candidate.image_medium.analysis_eligible is False
    assert candidate.image_medium.ui_eligible is False
    assert candidate.image_medium.demo_eligible is False


def test_unknown_image_state_and_mixed_qualified_rights_fail_closed() -> None:
    unknown = _historical_row()
    unknown["image_medium_state"] = "AVAILABLE"
    with pytest.raises(ValueError, match="image medium state"):
        project_optional_media_candidate(
            _source_row(),
            unknown,
            build_optional_media_policy(),
        )

    mixed = _historical_row(ImageMediumState.QUALIFIED)
    asset_rights = mixed["asset_rights"]
    assert isinstance(asset_rights, dict)
    asset_rights["analysis_eligible"] = False
    with pytest.raises(ValidationError, match="qualified image"):
        project_optional_media_candidate(
            _source_row(),
            mixed,
            build_optional_media_policy(),
        )


def test_sealed_universe_projection_is_complete_and_byte_deterministic() -> None:
    history_before = TERMINAL_HISTORY.read_bytes()
    failure_before = TERMINAL_FAILURE.read_bytes()

    first = build_optional_media_projection(REPO_ROOT)
    second = build_optional_media_projection(REPO_ROOT)

    assert first == second
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )
    assert first.schema_version == "itda.catalog-optional-media-projection.v2"
    assert first.policy.policy_version == "optional-media-v2"
    assert first.universe_count == 718
    assert len(first.candidates) == 718
    assert tuple(row.place_entity_id for row in first.candidates) == tuple(
        sorted(row.place_entity_id for row in first.candidates)
    )
    assert first.historical_lineage.terminal_root_sha256 == (
        "fab840841288cc0b0e1b31454cf65de5679e5cda0326a57ce42f22d0bdf377ac"
    )
    assert first.capabilities.provider_traffic_allowed is False
    assert first.capabilities.credential_access_allowed is False
    assert first.capabilities.vlm_inference_allowed is False
    assert first.capabilities.catalog_membership_authority is False
    assert TERMINAL_HISTORY.read_bytes() == history_before
    assert TERMINAL_FAILURE.read_bytes() == failure_before


def test_content_addressed_publication_is_idempotent_and_canonical(
    tmp_path: Path,
) -> None:
    generation = build_optional_media_projection(REPO_ROOT)
    first_root = publish_optional_media_projection(
        generation,
        repository_root=REPO_ROOT,
        output_base=tmp_path / "policy",
    )
    second_root = publish_optional_media_projection(
        generation,
        repository_root=REPO_ROOT,
        output_base=tmp_path / "policy",
    )

    assert first_root == second_root
    assert first_root.name == generation.projection_sha256
    assert {path.name for path in first_root.iterdir()} == {
        "policy.json",
        "projected-candidates.json",
        "projection-manifest.json",
    }
    assert (first_root / "policy.json").read_bytes() == canonical_json_bytes(
        generation.policy.model_dump(mode="json")
    )
    assert (first_root / "projected-candidates.json").read_bytes() == (
        canonical_json_bytes(generation.candidate_set.model_dump(mode="json"))
    )
    assert (first_root / "projection-manifest.json").read_bytes() == (
        canonical_json_bytes(generation.model_dump(mode="json"))
    )


def test_replay_exposes_explicit_image_counts_and_non_image_states() -> None:
    generation = build_optional_media_projection(REPO_ROOT)

    assert sum(generation.image_state_counts.values()) == 718
    assert generation.image_state_counts["EMPTY"] == 2
    assert generation.image_state_counts["RIGHTS_RESTRICTED"] == 13
    assert generation.catalog_eligible_count == sum(
        candidate.catalog_eligible for candidate in generation.candidates
    )
    assert all(
        candidate.non_image_gates.operating_information
        in {"PASS", "MISSING", "BLOCKED", "REVIEW_REQUIRED"}
        for candidate in generation.candidates
    )
