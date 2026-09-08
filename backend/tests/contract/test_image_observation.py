from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.contracts.catalog_optional_media import (
    IMAGE_OBSERVATION_LABELS,
    ImageMediumState,
    VlmObservationEnvelope,
    observation_schema_sha256,
)
from itda.contracts.image_observation import (
    APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256,
    ImageObservationV2,
    image_observation_v2_schema_sha256,
    parse_image_observation,
)
from itda.contracts.place_profile import SubattributeId
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

SHA_A = "a" * 64
REF_A = f"selected-image:{'1' * 64}"
REF_B = f"selected-image:{'2' * 64}"
V1_SCHEMA_SHA256 = "fd406656363df021d3e51adba2e2ddb756c99f4ce85a04140a70560b1f5e96c9"
V1_FIXTURE_SHA256 = "c8a0665b4a86a2fa206c8f676c4edff7f3df6603cc1f967e5fdda2d411261b74"
V2_SCHEMA_SHA256 = "1551c1966f4239323423b69906a7ffe7ffa4daebc0920f8b9ab2a02bb80e0fe0"


def _seal(payload: dict[str, object]) -> dict[str, object]:
    payload["observation_sha256"] = canonical_sha256(payload)
    return payload


def _qualified_payload() -> dict[str, object]:
    scores = {
        "H1": 1000,
        "H2": 1001,
        "H3": 1002,
        "H4": 1003,
        "I1": 2000,
        "I2": 2000,
        "I3": 2000,
        "I4": 2000,
        "R1": 3000,
        "R2": None,
        "R3": 3002,
        "R4": 3003,
    }
    observations: list[dict[str, object]] = []
    for attribute_id in SubattributeId:
        score = scores[attribute_id.value]
        if score is None:
            observations.append(
                {
                    "attribute_id": attribute_id.value,
                    "status": "not_observable",
                    "score_milli": None,
                    "uncertainty_bp": 9000,
                    "visible_evidence": [],
                }
            )
        else:
            observations.append(
                {
                    "attribute_id": attribute_id.value,
                    "status": "observed",
                    "score_milli": score,
                    "uncertainty_bp": 1250,
                    "visible_evidence": [
                        {
                            "image_ref": REF_A,
                            "region": "전경 중앙",
                            "caption_ko": (
                                f"전경 중앙에서 {attribute_id.value}의 시각 단서가 보인다."
                            ),
                            "evidence_kind": "VISIBLE_CUE",
                        }
                    ],
                }
            )
    return _seal(
        {
            "schema_version": "photo-attributes.v2",
            "media_state": "QUALIFIED",
            "representative_manifest_sha256": SHA_A,
            "selected_image_refs": [REF_A, REF_B],
            "observations": observations,
            "candidate_axes": [
                {
                    "axis_id": "H",
                    "status": "observed",
                    "score_milli": 1002,
                    "missing_attribute_ids": [],
                    "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
                },
                {
                    "axis_id": "E",
                    "status": "observed",
                    "score_milli": 2000,
                    "missing_attribute_ids": [],
                    "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
                },
                {
                    "axis_id": "R",
                    "status": "not_observable",
                    "score_milli": None,
                    "missing_attribute_ids": ["R2"],
                    "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
                },
            ],
            "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
        }
    )


def _fact_free_payload(state: ImageMediumState) -> dict[str, object]:
    return _seal(
        {
            "schema_version": "photo-attributes.v2",
            "media_state": state.value,
            "representative_manifest_sha256": SHA_A,
            "selected_image_refs": [],
            "observations": [],
            "candidate_axes": [],
            "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
        }
    )


def test_v1_fixture_and_schema_hash_remain_byte_stable() -> None:
    payload = {
        "schema_version": "itda.photo-attributes.v1",
        "observations": {
            label: {
                "status": "observed",
                "score": 2.0,
                "evidence": [f"visible evidence for {label}"],
            }
            for label in IMAGE_OBSERVATION_LABELS
        },
    }
    fixture_bytes = canonical_json_bytes(payload)

    restored = VlmObservationEnvelope.model_validate_json(fixture_bytes)

    assert canonical_json_bytes(restored.model_dump(mode="json")) == fixture_bytes
    assert canonical_sha256(restored.model_dump(mode="json")) == V1_FIXTURE_SHA256
    assert observation_schema_sha256() == V1_SCHEMA_SHA256
    assert isinstance(parse_image_observation(payload), VlmObservationEnvelope)


def test_v2_qualified_observation_is_ordered_derived_and_digest_bound() -> None:
    payload = _qualified_payload()

    restored = ImageObservationV2.model_validate(payload)

    assert tuple(row.attribute_id for row in restored.observations) == tuple(SubattributeId)
    assert tuple(axis.axis_id for axis in restored.candidate_axes) == ("H", "E", "R")
    assert restored.candidate_axes[0].score_milli == 1002
    assert restored.candidate_axes[2].missing_attribute_ids == (SubattributeId.R2,)
    assert (
        canonical_sha256(restored.model_dump(mode="json", exclude={"observation_sha256"}))
        == restored.observation_sha256
    )
    assert isinstance(parse_image_observation(payload), ImageObservationV2)
    assert image_observation_v2_schema_sha256() == V2_SCHEMA_SHA256
    assert APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256 == V2_SCHEMA_SHA256


@pytest.mark.parametrize(
    "state",
    tuple(state for state in ImageMediumState if state is not ImageMediumState.QUALIFIED),
)
def test_non_qualified_states_are_explicit_and_fact_free(state: ImageMediumState) -> None:
    payload = _fact_free_payload(state)
    restored = ImageObservationV2.model_validate(payload)

    assert restored.media_state is state
    assert restored.selected_image_refs == ()
    assert restored.observations == ()
    assert restored.candidate_axes == ()

    for field, invented in (
        ("selected_image_refs", [REF_A]),
        ("observations", _qualified_payload()["observations"]),
        ("candidate_axes", _qualified_payload()["candidate_axes"]),
    ):
        hostile = deepcopy(payload)
        hostile[field] = invented
        hostile["observation_sha256"] = canonical_sha256(
            {key: value for key, value in hostile.items() if key != "observation_sha256"}
        )
        with pytest.raises(ValidationError):
            ImageObservationV2.model_validate(hostile)


def test_v2_rejects_order_ref_visibility_and_axis_derivation_drift() -> None:
    mutations: list[dict[str, object]] = []

    unordered = _qualified_payload()
    observations = unordered["observations"]
    assert isinstance(observations, list)
    observations[0], observations[1] = observations[1], observations[0]
    mutations.append(unordered)

    unknown_ref = _qualified_payload()
    unknown_observations = unknown_ref["observations"]
    assert isinstance(unknown_observations, list)
    visible = unknown_observations[0]["visible_evidence"]
    assert isinstance(visible, list)
    visible[0]["image_ref"] = f"selected-image:{'f' * 64}"
    mutations.append(unknown_ref)

    non_visible = _qualified_payload()
    non_visible_observations = non_visible["observations"]
    assert isinstance(non_visible_observations, list)
    non_visible_evidence = non_visible_observations[0]["visible_evidence"]
    assert isinstance(non_visible_evidence, list)
    non_visible_evidence[0]["evidence_kind"] = "INFERRED_FACT"
    mutations.append(non_visible)

    drift = _qualified_payload()
    axes = drift["candidate_axes"]
    assert isinstance(axes, list)
    axes[0]["score_milli"] = 1001
    mutations.append(drift)

    wrong_missing = _qualified_payload()
    wrong_axes = wrong_missing["candidate_axes"]
    assert isinstance(wrong_axes, list)
    wrong_axes[2]["missing_attribute_ids"] = ["R1"]
    mutations.append(wrong_missing)

    for hostile in mutations:
        hostile["observation_sha256"] = canonical_sha256(
            {key: value for key, value in hostile.items() if key != "observation_sha256"}
        )
        with pytest.raises(ValidationError):
            ImageObservationV2.model_validate(hostile)


def test_v2_rejects_aliases_and_unknown_schema_versions() -> None:
    hostile = _qualified_payload()
    hostile["schema_version"] = "itda.photo-attributes.v2"
    with pytest.raises(ValidationError):
        ImageObservationV2.model_validate(hostile)

    with pytest.raises(ValueError, match="unsupported image observation schema"):
        parse_image_observation({"schema_version": "photo-attributes.latest"})
