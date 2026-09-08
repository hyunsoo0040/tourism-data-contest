"""Additive, immutable successor profile-release contracts for Phase 4.

The module deliberately leaves the shipped v1 contract and lifecycle store
untouched.  A v2 candidate is only a content-addressed BUILT_UNAPPROVED value;
approval and pointer mutation remain capabilities owned by the Phase 3 store.
"""

from __future__ import annotations

import hmac
import json
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.phase4_benchmark import BenchmarkReportState
from itda.contracts.place_profile import SubattributeId
from itda.contracts.profile_fusion import (
    CANONICAL_FUSION_POLICY,
    FusedProfileProjection,
    FusionPolicyConfig,
)
from itda.contracts.profile_release import ProfileReleaseCandidate, ProfileReleaseState
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_RELEASE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_PRINCIPAL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_IMAGE_RELEASE_STATES = {
    BenchmarkReportState.ADOPT,
    BenchmarkReportState.CONDITIONAL_ADOPT,
}
_ZERO_IMAGE_RELEASE_STATES = {
    BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
    BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
}
PROFILE_RELEASE_V2_TRANSITION_RULE_SHA256 = canonical_sha256(
    {
        "rule": "EXACT_V1_PREDECESSOR_ONLY",
        "successor_schema": "itda.profile-release-candidate.v2",
        "predecessor_schema": "itda.profile-release-candidate.v1",
        "compatibility": "CANONICAL_DEV_AND_ALL_PREDECESSOR_MEMBERS",
        "generic_cross_schema_compatibility": False,
    }
)


class ProfileReleaseV2Error(ValueError):
    """Generic additive-schema parsing failure."""


class SuccessorReleaseLineage(StrictContract):
    """Digest-only graph joining the exact protected Phase 2/3/4 artifacts."""

    schema_version: Literal["itda.profile-release-lineage.v2"] = "itda.profile-release-lineage.v2"
    predecessor_release_sha256: Sha256
    predecessor_lifecycle_receipt_sha256: Sha256
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    rights_manifest_sha256: Sha256
    source_manifest_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    lane_baseline_sha256: Sha256
    image_selection_manifest_sha256: Sha256
    prediction_batch_sha256: Sha256
    prediction_freeze_receipt_sha256: Sha256
    provisional_report_sha256: Sha256
    final_report_sha256: Sha256
    human_review_manifest_sha256: Sha256 | None
    zero_image_fallback_sha256: Sha256 | None
    fusion_policy_sha256: Sha256
    profile_schema_sha256: Sha256
    code_sha256: Sha256
    config_sha256: Sha256
    lineage_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_lineage_digest(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"lineage_sha256"}))
        if self.lineage_sha256 is None:
            object.__setattr__(self, "lineage_sha256", expected)
        elif not hmac.compare_digest(self.lineage_sha256, expected):
            raise ValueError("successor release lineage digest drifted")
        return self


class ProfileReleaseCohortMemberV2(StrictContract):
    """One provenance-complete successor member with the full fusion trace."""

    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    predecessor_profile_sha256: Sha256
    predecessor_member_sha256: Sha256
    media_state: ImageMediumState
    image_selection_member_sha256: Sha256
    prediction_observation_sha256: Sha256
    fused_profile: FusedProfileProjection
    member_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_exact_member(self) -> Self:
        if self.fused_profile.place_ref != self.place_ref:
            raise ValueError("successor member place differs from fused profile")
        if not hmac.compare_digest(
            self.fused_profile.predecessor_profile_sha256,
            self.predecessor_profile_sha256,
        ):
            raise ValueError("successor member predecessor profile drifted")
        if not hmac.compare_digest(
            self.fused_profile.image_observation_sha256,
            self.prediction_observation_sha256,
        ):
            raise ValueError("successor member prediction observation drifted")
        if self.fused_profile.policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256:
            raise ValueError("successor member fusion policy drifted")
        if self.media_state is not ImageMediumState.QUALIFIED and any(
            attribute.lanes[2].included for attribute in self.fused_profile.attributes
        ):
            raise ValueError("non-qualified media cannot contribute image values")

        expected = canonical_sha256(self.model_dump(mode="json", exclude={"member_sha256"}))
        if self.member_sha256 is None:
            object.__setattr__(self, "member_sha256", expected)
        elif not hmac.compare_digest(self.member_sha256, expected):
            raise ValueError("successor release member digest drifted")
        return self


def _image_trace_is_zero(member: ProfileReleaseCohortMemberV2) -> bool:
    return all(
        not image.included
        and image.score_milli is None
        and image.effective_weight_numerator == 0
        and image.normalized_weight_numerator == 0
        and image.display_weight_percent == 0
        and image.contribution_numerator == 0
        and not image.evidence_refs
        for attribute in member.fused_profile.attributes
        for image in (attribute.lanes[2],)
    )


class ProfileReleaseCandidateV2(StrictContract):
    """One immutable successor candidate before independent approval."""

    schema_version: Literal["itda.profile-release-candidate.v2"] = (
        "itda.profile-release-candidate.v2"
    )
    release_id: Annotated[str, Field(strict=True, pattern=_RELEASE_ID_PATTERN)]
    state: Literal[ProfileReleaseState.BUILT_UNAPPROVED] = ProfileReleaseState.BUILT_UNAPPROVED
    builder_principal: Annotated[str, Field(strict=True, pattern=_PRINCIPAL_PATTERN)]
    adoption_state: Literal[
        BenchmarkReportState.ADOPT,
        BenchmarkReportState.CONDITIONAL_ADOPT,
        BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
        BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
    ]
    adopted_attributes: tuple[SubattributeId, ...]
    confidence_is_ranking_input: Literal[False] = False
    fusion_policy: FusionPolicyConfig
    lineage: SuccessorReleaseLineage
    cohort: Annotated[tuple[ProfileReleaseCohortMemberV2, ...], Field(min_length=24, max_length=24)]
    predecessor_member_set_sha256: Sha256 | None = None
    release_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_complete_unapproved_successor(self) -> Self:
        place_refs = tuple(member.place_ref for member in self.cohort)
        predecessor_members = tuple(member.predecessor_member_sha256 for member in self.cohort)
        if len(set(place_refs)) != 24 or len(set(predecessor_members)) != 24:
            raise ValueError("successor release requires 24 unique predecessor-bound members")
        if (
            self.fusion_policy.mode != "CANONICAL_RELEASE"
            or not self.fusion_policy.release_eligible
            or self.fusion_policy.policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256
            or self.lineage.fusion_policy_sha256 != CANONICAL_FUSION_POLICY.policy_sha256
        ):
            raise ValueError("successor release requires the exact canonical fusion policy")

        adopted = tuple(self.adopted_attributes)
        if len(set(adopted)) != len(adopted):
            raise ValueError("successor adopted attributes must be unique")
        if self.adoption_state is BenchmarkReportState.ADOPT:
            if adopted != tuple(SubattributeId):
                raise ValueError("ADOPT must bind the complete canonical attribute inventory")
        elif self.adoption_state is BenchmarkReportState.CONDITIONAL_ADOPT:
            if not adopted:
                raise ValueError("conditional adoption requires an exact non-empty scope")
        elif adopted:
            raise ValueError("text-only successor cannot adopt image attributes")

        image_included_ids = {
            attribute.attribute_id
            for member in self.cohort
            for attribute in member.fused_profile.attributes
            if attribute.lanes[2].included
        }
        if self.adoption_state in _IMAGE_RELEASE_STATES:
            if (
                self.lineage.human_review_manifest_sha256 is None
                or self.lineage.zero_image_fallback_sha256 is not None
                or not image_included_ids
                or not image_included_ids.issubset(set(adopted))
            ):
                raise ValueError("image-bearing successor lacks complete reviewed adoption")
        elif self.adoption_state in _ZERO_IMAGE_RELEASE_STATES and (
            self.lineage.human_review_manifest_sha256 is not None
            or self.lineage.zero_image_fallback_sha256 is None
            or image_included_ids
            or not all(_image_trace_is_zero(member) for member in self.cohort)
        ):
            raise ValueError("text-only successor contains image authority")

        predecessor_set = canonical_sha256(
            [
                {
                    "place_ref": member.place_ref,
                    "predecessor_member_sha256": member.predecessor_member_sha256,
                    "predecessor_profile_sha256": member.predecessor_profile_sha256,
                }
                for member in self.cohort
            ]
        )
        if self.predecessor_member_set_sha256 is None:
            object.__setattr__(self, "predecessor_member_set_sha256", predecessor_set)
        elif not hmac.compare_digest(self.predecessor_member_set_sha256, predecessor_set):
            raise ValueError("successor predecessor member set drifted")

        expected = canonical_sha256(self.model_dump(mode="json", exclude={"release_sha256"}))
        if self.release_sha256 is None:
            object.__setattr__(self, "release_sha256", expected)
        elif not hmac.compare_digest(self.release_sha256, expected):
            raise ValueError("successor release digest drifted")
        return self


ProfileReleaseCandidateAny = ProfileReleaseCandidate | ProfileReleaseCandidateV2


class ExactPredecessorMemberBinding(StrictContract):
    """One exact v1 member identity copied into the transition proof."""

    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    predecessor_profile_sha256: Sha256
    predecessor_member_sha256: Sha256


class ProfileReleaseTransitionProofV2(StrictContract):
    """Narrow evidence for only one declared v2-to-v1 transition pair."""

    schema_version: Literal["itda.profile-release-transition-proof.v2"] = (
        "itda.profile-release-transition-proof.v2"
    )
    successor_release_sha256: Sha256
    predecessor_release_sha256: Sha256
    predecessor_lifecycle_receipt_sha256: Sha256
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    predecessor_members: Annotated[
        tuple[ExactPredecessorMemberBinding, ...], Field(min_length=24, max_length=24)
    ]
    predecessor_member_set_sha256: Sha256
    transition_rule_sha256: Sha256 = PROFILE_RELEASE_V2_TRANSITION_RULE_SHA256
    proof_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_exact_transition_proof(self) -> Self:
        if not hmac.compare_digest(
            self.transition_rule_sha256,
            PROFILE_RELEASE_V2_TRANSITION_RULE_SHA256,
        ):
            raise ValueError("transition proof rule is not the frozen exact-predecessor rule")
        if len({member.place_ref for member in self.predecessor_members}) != 24:
            raise ValueError("transition proof predecessor cohort is not unique")
        expected_set = canonical_sha256(
            [member.model_dump(mode="json") for member in self.predecessor_members]
        )
        if not hmac.compare_digest(self.predecessor_member_set_sha256, expected_set):
            raise ValueError("transition proof predecessor member set drifted")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"proof_sha256"}))
        if self.proof_sha256 is None:
            object.__setattr__(self, "proof_sha256", expected)
        elif not hmac.compare_digest(self.proof_sha256, expected):
            raise ValueError("transition proof digest drifted")
        return self


def build_exact_predecessor_transition_proof(
    *,
    successor: ProfileReleaseCandidateV2,
    predecessor: ProfileReleaseCandidate,
) -> ProfileReleaseTransitionProofV2:
    """Build proof only when every successor predecessor claim re-derives."""

    try:
        if not (
            _same_required_digest(
                successor.lineage.predecessor_release_sha256,
                predecessor.release_sha256,
            )
            and hmac.compare_digest(
                successor.lineage.canonical_lineage_sha256,
                predecessor.canonical_lineage_sha256,
            )
            and hmac.compare_digest(
                successor.lineage.dev_lineage_sha256,
                predecessor.dev_lineage_sha256,
            )
        ):
            raise ValueError("predecessor release lineage differs")
        predecessor_by_place = {member.place_ref: member for member in predecessor.cohort}
        if len(predecessor_by_place) != 24:
            raise ValueError("predecessor cohort is incomplete")
        bindings: list[ExactPredecessorMemberBinding] = []
        for successor_member in successor.cohort:
            predecessor_member = predecessor_by_place.get(successor_member.place_ref)
            if predecessor_member is None:
                raise ValueError("successor cohort differs from predecessor")
            predecessor_member_sha256 = canonical_sha256(predecessor_member.model_dump(mode="json"))
            if not (
                hmac.compare_digest(
                    successor_member.predecessor_profile_sha256,
                    predecessor_member.profile_sha256,
                )
                and hmac.compare_digest(
                    successor_member.predecessor_member_sha256,
                    predecessor_member_sha256,
                )
            ):
                raise ValueError("successor predecessor member differs")
            bindings.append(
                ExactPredecessorMemberBinding(
                    place_ref=successor_member.place_ref,
                    predecessor_profile_sha256=predecessor_member.profile_sha256,
                    predecessor_member_sha256=predecessor_member_sha256,
                )
            )
        predecessor_set = canonical_sha256(
            [binding.model_dump(mode="json") for binding in bindings]
        )
        if not _same_required_digest(predecessor_set, successor.predecessor_member_set_sha256):
            raise ValueError("successor predecessor set differs")
        return ProfileReleaseTransitionProofV2(
            successor_release_sha256=_require_digest(successor.release_sha256),
            predecessor_release_sha256=_require_digest(predecessor.release_sha256),
            predecessor_lifecycle_receipt_sha256=(
                successor.lineage.predecessor_lifecycle_receipt_sha256
            ),
            canonical_lineage_sha256=predecessor.canonical_lineage_sha256,
            dev_lineage_sha256=predecessor.dev_lineage_sha256,
            predecessor_members=tuple(bindings),
            predecessor_member_set_sha256=predecessor_set,
        )
    except Exception:
        raise ValueError("exact predecessor transition is invalid") from None


def _require_digest(value: str | None) -> str:
    if value is None:
        raise ValueError("required digest is absent")
    return value


def _same_required_digest(left: str, right: str | None) -> bool:
    return right is not None and hmac.compare_digest(left, right)


def require_exact_predecessor_transition(
    *,
    successor: ProfileReleaseCandidateV2,
    predecessor: ProfileReleaseCandidate,
    proof: ProfileReleaseTransitionProofV2,
) -> bool:
    """Accept only a byte-identical proof re-derived for the supplied pair."""

    try:
        expected = build_exact_predecessor_transition_proof(
            successor=successor,
            predecessor=predecessor,
        )
        if canonical_json_bytes(proof.model_dump(mode="json")) != canonical_json_bytes(
            expected.model_dump(mode="json")
        ):
            raise ValueError("transition proof pair differs")
        return True
    except Exception:
        raise ValueError("exact predecessor transition is invalid") from None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("profile release JSON contains duplicate keys")
        value[key] = item
    return value


def parse_profile_release_candidate(raw: bytes) -> ProfileReleaseCandidateAny:
    """Dispatch canonical bytes by exact schema without changing either schema."""

    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(parsed, dict):
            raise ValueError("profile release root is invalid")
        schema = parsed.get("schema_version")
        model: type[ProfileReleaseCandidate] | type[ProfileReleaseCandidateV2]
        if schema == "itda.profile-release-candidate.v1":
            model = ProfileReleaseCandidate
        elif schema == "itda.profile-release-candidate.v2":
            model = ProfileReleaseCandidateV2
        else:
            raise ValueError("profile release schema is unsupported")
        validated = model.model_validate(parsed)
        if raw != canonical_json_bytes(validated.model_dump(mode="json")):
            raise ValueError("profile release bytes are not canonical")
        return validated
    except ProfileReleaseV2Error:
        raise
    except Exception:
        raise ProfileReleaseV2Error("profile release candidate is invalid") from None


__all__ = [
    "ExactPredecessorMemberBinding",
    "PROFILE_RELEASE_V2_TRANSITION_RULE_SHA256",
    "ProfileReleaseCandidateAny",
    "ProfileReleaseCandidateV2",
    "ProfileReleaseCohortMemberV2",
    "ProfileReleaseTransitionProofV2",
    "ProfileReleaseV2Error",
    "SuccessorReleaseLineage",
    "build_exact_predecessor_transition_proof",
    "parse_profile_release_candidate",
    "require_exact_predecessor_transition",
]
