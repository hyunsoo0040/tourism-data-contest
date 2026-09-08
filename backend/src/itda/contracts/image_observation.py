"""Additive Phase 4 image-observation contract with no product authority."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_optional_media import ImageMediumState, VlmObservationEnvelope
from itda.contracts.place_profile import SubattributeId
from itda.domain.canonical import canonical_sha256

IMAGE_OBSERVATION_V2_SCHEMA_VERSION = "photo-attributes.v2"
IMAGE_OBSERVATION_V2_ATTRIBUTE_ORDER = tuple(SubattributeId)
IMAGE_OBSERVATION_V2_AXIS_ORDER = ("H", "E", "R")
IMAGE_OBSERVATION_V2_AXIS_MEMBERS: dict[str, tuple[SubattributeId, ...]] = {
    "H": (
        SubattributeId.H1,
        SubattributeId.H2,
        SubattributeId.H3,
        SubattributeId.H4,
    ),
    "E": (
        SubattributeId.I1,
        SubattributeId.I2,
        SubattributeId.I3,
        SubattributeId.I4,
    ),
    "R": (
        SubattributeId.R1,
        SubattributeId.R2,
        SubattributeId.R3,
        SubattributeId.R4,
    ),
}
FORBIDDEN_PROVIDER_AUTHORITY_FIELDS = (
    "admission",
    "admission_authority",
    "axis_score",
    "axis_scores",
    "catalog_eligible",
    "confidence",
    "display_label",
    "display_labels",
    "eligibility",
    "fusion",
    "fused_score",
    "fused_scores",
    "publishability",
    "publication",
    "rank",
    "ranking",
    "recommendation",
    "recommendation_score",
    "release",
    "release_authority",
    "selection",
)
APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256 = (
    "1551c1966f4239323423b69906a7ffe7ffa4daebc0920f8b9ab2a02bb80e0fe0"
)

SelectedImageRef = Annotated[
    str,
    Field(strict=True, pattern=r"^selected-image:[0-9a-f]{64}$"),
]
ScoreMilli = Annotated[int, Field(strict=True, ge=0, le=4000)]
UncertaintyBasisPoints = Annotated[int, Field(strict=True, ge=0, le=10_000)]
CandidateAxisId = Literal["H", "E", "R"]
ObservationStatus = Literal["observed", "not_observable"]
CandidateAuthorityScope = Literal["CANDIDATE_EVIDENCE_ONLY"]


def _contains_hangul(value: str) -> bool:
    return re.search(r"[가-힣ㄱ-ㅎㅏ-ㅣ]", value) is not None


def _reject_authority_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.casefold() in FORBIDDEN_PROVIDER_AUTHORITY_FIELDS:
                raise ValueError(f"forbidden provider authority field: {key.casefold()}")
            _reject_authority_fields(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _reject_authority_fields(nested)


class VisibleImageEvidence(StrictContract):
    image_ref: SelectedImageRef
    region: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    caption_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    evidence_kind: Literal["VISIBLE_CUE"]

    @model_validator(mode="after")
    def require_korean_caption(self) -> Self:
        if not _contains_hangul(self.caption_ko):
            raise ValueError("visible evidence caption must contain Korean text")
        return self


class ImageAttributeObservation(StrictContract):
    attribute_id: SubattributeId
    status: ObservationStatus
    score_milli: ScoreMilli | None
    uncertainty_bp: UncertaintyBasisPoints
    visible_evidence: tuple[VisibleImageEvidence, ...]

    @model_validator(mode="after")
    def validate_observability(self) -> Self:
        if self.status == "observed":
            if self.score_milli is None or not self.visible_evidence:
                raise ValueError("observed attribute requires score and visible evidence")
        elif self.score_milli is not None or self.visible_evidence:
            raise ValueError("not-observable attribute cannot carry score or visible evidence")
        return self


class CandidateAxisObservation(StrictContract):
    axis_id: CandidateAxisId
    status: ObservationStatus
    score_milli: ScoreMilli | None
    missing_attribute_ids: tuple[SubattributeId, ...]
    authority_scope: CandidateAuthorityScope

    @model_validator(mode="after")
    def validate_observability(self) -> Self:
        if self.status == "observed":
            if self.score_milli is None or self.missing_attribute_ids:
                raise ValueError("observed candidate axis requires a score and no missing members")
        elif self.score_milli is not None or not self.missing_attribute_ids:
            raise ValueError(
                "not-observable candidate axis requires exact missing members and no score"
            )
        return self


class ImageObservationV2(StrictContract):
    schema_version: Literal["photo-attributes.v2"]
    media_state: ImageMediumState
    representative_manifest_sha256: Sha256
    selected_image_refs: tuple[SelectedImageRef, ...]
    observations: tuple[ImageAttributeObservation, ...]
    candidate_axes: tuple[CandidateAxisObservation, ...]
    authority_scope: CandidateAuthorityScope
    observation_sha256: Sha256

    @model_validator(mode="before")
    @classmethod
    def reject_provider_authority(cls, value: object) -> object:
        _reject_authority_fields(value)
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if len(set(self.selected_image_refs)) != len(self.selected_image_refs):
            raise ValueError("selected image references must be unique")

        if self.media_state is not ImageMediumState.QUALIFIED:
            if self.selected_image_refs or self.observations or self.candidate_axes:
                raise ValueError("non-qualified image state must remain fact-free")
        else:
            self._validate_qualified_facts()

        expected_digest = canonical_sha256(
            self.model_dump(mode="json", exclude={"observation_sha256"})
        )
        if self.observation_sha256 != expected_digest:
            raise ValueError("image observation digest does not match canonical content")
        return self

    def _validate_qualified_facts(self) -> None:
        if not self.selected_image_refs:
            raise ValueError("qualified image observation requires selected image references")
        if tuple(row.attribute_id for row in self.observations) != (
            IMAGE_OBSERVATION_V2_ATTRIBUTE_ORDER
        ):
            raise ValueError("observations require exact ordered H1-H4, I1-I4, R1-R4")
        if tuple(row.axis_id for row in self.candidate_axes) != (IMAGE_OBSERVATION_V2_AXIS_ORDER):
            raise ValueError("candidate axes require exact H, E, R order")

        known_refs = set(self.selected_image_refs)
        by_attribute = {row.attribute_id: row for row in self.observations}
        for observation in self.observations:
            for evidence in observation.visible_evidence:
                if evidence.image_ref not in known_refs:
                    raise ValueError("unknown selected image reference")

        for candidate in self.candidate_axes:
            members = IMAGE_OBSERVATION_V2_AXIS_MEMBERS[candidate.axis_id]
            missing = tuple(
                member for member in members if by_attribute[member].status == "not_observable"
            )
            if missing:
                if (
                    candidate.status != "not_observable"
                    or candidate.score_milli is not None
                    or candidate.missing_attribute_ids != missing
                ):
                    raise ValueError("candidate axis missing-member derivation drifted")
                continue

            scores = tuple(by_attribute[member].score_milli for member in members)
            if any(score is None for score in scores):
                raise ValueError("observed candidate axis has an absent member score")
            numeric_scores = tuple(score for score in scores if score is not None)
            expected_score = (sum(numeric_scores) + 2) // 4
            if (
                candidate.status != "observed"
                or candidate.score_milli != expected_score
                or candidate.missing_attribute_ids
            ):
                raise ValueError("candidate axis half-up derivation drifted")


ImageObservation = VlmObservationEnvelope | ImageObservationV2


def image_observation_v2_schema_definition() -> dict[str, Any]:
    return {
        "schema_version": IMAGE_OBSERVATION_V2_SCHEMA_VERSION,
        "media_states": tuple(state.value for state in ImageMediumState),
        "attribute_order": tuple(item.value for item in IMAGE_OBSERVATION_V2_ATTRIBUTE_ORDER),
        "observation": {
            "status": ("observed", "not_observable"),
            "score_milli": {"type": "integer-or-null", "minimum": 0, "maximum": 4000},
            "uncertainty_bp": {"type": "integer", "minimum": 0, "maximum": 10_000},
            "visible_evidence": {
                "type": "ordered-list",
                "caption_language": "ko",
                "selected_image_ref_only": True,
            },
        },
        "candidate_axes": {
            "order": IMAGE_OBSERVATION_V2_AXIS_ORDER,
            "members": {
                axis: tuple(member.value for member in members)
                for axis, members in IMAGE_OBSERVATION_V2_AXIS_MEMBERS.items()
            },
            "rounding": "integer-half-up-mean-exactly-four",
            "missing_rule": (
                "any-not-observable-axis-not-observable-with-exact-missing-member-ids"
            ),
        },
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
        "authority_fields_forbidden": FORBIDDEN_PROVIDER_AUTHORITY_FIELDS,
    }


def image_observation_v2_schema_sha256() -> str:
    return canonical_sha256(image_observation_v2_schema_definition())


def parse_image_observation(payload: Mapping[str, object] | bytes | str) -> ImageObservation:
    value: object = payload
    if isinstance(payload, (bytes, str)):
        value = json.loads(payload)
    if not isinstance(value, Mapping):
        raise ValueError("image observation must be a JSON object")

    schema_version = value.get("schema_version")
    if schema_version == "itda.photo-attributes.v1":
        return VlmObservationEnvelope.model_validate(value)
    if schema_version == IMAGE_OBSERVATION_V2_SCHEMA_VERSION:
        return ImageObservationV2.model_validate(value)
    raise ValueError("unsupported image observation schema")


if image_observation_v2_schema_sha256() != APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256:
    raise RuntimeError("approved image observation v2 schema hash drifted")


__all__ = [
    "APPROVED_IMAGE_OBSERVATION_V2_SCHEMA_SHA256",
    "FORBIDDEN_PROVIDER_AUTHORITY_FIELDS",
    "IMAGE_OBSERVATION_V2_ATTRIBUTE_ORDER",
    "IMAGE_OBSERVATION_V2_AXIS_MEMBERS",
    "IMAGE_OBSERVATION_V2_AXIS_ORDER",
    "IMAGE_OBSERVATION_V2_SCHEMA_VERSION",
    "CandidateAxisObservation",
    "ImageAttributeObservation",
    "ImageObservation",
    "ImageObservationV2",
    "VisibleImageEvidence",
    "image_observation_v2_schema_definition",
    "image_observation_v2_schema_sha256",
    "parse_image_observation",
]
