"""Strict release-bound contracts for the preserved Phase 3 medium lanes."""

from __future__ import annotations

import hmac
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.place_profile import MismatchTraitId, SubattributeId
from itda.domain.canonical import canonical_sha256


class Phase3LaneAttributeScore(StrictContract):
    """One already-computed Phase 3 lane value, never a similarity float."""

    attribute_id: SubattributeId
    score_milli: Annotated[int, Field(strict=True, ge=0, le=4_000)]
    evidence_refs: Annotated[tuple[Sha256, ...], Field(min_length=1)]


class Phase3MismatchTraitValue(StrictContract):
    """The exact inherited M1-M6 value from the predecessor PlaceProfile."""

    trait_id: MismatchTraitId
    value: Annotated[int, Field(strict=True, ge=0, le=100)]


class Phase3MediumLane(StrictContract):
    """A separate DESCRIPTION or ODII lane at the profile-construction seam."""

    lane: Literal["DESCRIPTION", "ODII"]
    status: Literal["READY", "MISSING"]
    derivation_kind: Literal["PHASE3_PROFILE_CONSTRUCTION_LANE"]
    source_sha256: Sha256 | None
    reviewed_evidence_sha256: Sha256 | None
    meaningful_character_count: Annotated[int, Field(strict=True, ge=0)]
    directly_linked_odii: StrictBool | None
    attribute_scores: tuple[Phase3LaneAttributeScore, ...]

    @model_validator(mode="after")
    def require_exact_lane_shape(self) -> Self:
        if self.lane == "DESCRIPTION" and self.directly_linked_odii is not None:
            raise ValueError("description lane cannot carry Odii linkage")
        if self.lane == "ODII" and self.directly_linked_odii is None:
            raise ValueError("Odii lane requires an explicit linkage decision")
        if self.status == "MISSING":
            if (
                self.source_sha256 is not None
                or self.reviewed_evidence_sha256 is not None
                or self.meaningful_character_count != 0
                or self.attribute_scores
                or self.directly_linked_odii is True
            ):
                raise ValueError("missing lane cannot contain fabricated values or evidence")
            return self
        if self.source_sha256 is None or self.reviewed_evidence_sha256 is None:
            raise ValueError("ready lane requires source and reviewed evidence lineage")
        if self.meaningful_character_count <= 0:
            raise ValueError("ready lane requires a positive meaningful-character count")
        if tuple(score.attribute_id for score in self.attribute_scores) != tuple(SubattributeId):
            raise ValueError("ready lane scores must use canonical H1-R4 order")
        if self.lane == "ODII" and self.directly_linked_odii is not True:
            raise ValueError("ready Odii lane must be directly linked")
        return self


class Phase3LaneAuthorityMember(StrictContract):
    """Authority-produced values retained before Phase 3 discarded its lanes."""

    place_ref: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    profile_sha256: Sha256
    description: Phase3MediumLane
    odii: Phase3MediumLane
    mismatch_traits: tuple[Phase3MismatchTraitValue, ...]
    member_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_exact_member(self) -> Self:
        if self.description.lane != "DESCRIPTION" or self.odii.lane != "ODII":
            raise ValueError("phase 3 lanes must remain separate and ordered")
        if tuple(trait.trait_id for trait in self.mismatch_traits) != tuple(MismatchTraitId):
            raise ValueError("mismatch traits must use canonical M1-M6 order")
        expected = canonical_sha256(self.model_dump(exclude={"member_sha256"}, mode="json"))
        if self.member_sha256 is None:
            object.__setattr__(self, "member_sha256", expected)
        elif not hmac.compare_digest(self.member_sha256, expected):
            raise ValueError("phase 3 lane authority member digest drifted")
        return self


class Phase3LaneAuthorityBundle(StrictContract):
    """Protected sidecar emitted only by the Phase 3 construction authority."""

    schema_version: Literal["itda.phase3-lane-authority.v1"] = "itda.phase3-lane-authority.v1"
    predecessor_release_sha256: Sha256
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    source_manifest_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    members: Annotated[tuple[Phase3LaneAuthorityMember, ...], Field(min_length=24, max_length=24)]
    authority_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def require_complete_self_authenticating_bundle(self) -> Self:
        place_refs = [member.place_ref for member in self.members]
        if len(set(place_refs)) != 24:
            raise ValueError("phase 3 lane authority requires 24 unique members")
        expected = canonical_sha256(self.model_dump(exclude={"authority_sha256"}, mode="json"))
        if self.authority_sha256 is None:
            object.__setattr__(self, "authority_sha256", expected)
        elif not hmac.compare_digest(self.authority_sha256, expected):
            raise ValueError("phase 3 lane authority digest drifted")
        return self


class Phase3LaneBaselineMember(Phase3LaneAuthorityMember):
    """Public projection retaining only exact lineage and already-computed values."""


class Phase3LaneBaseline(StrictContract):
    """Immutable lane baseline bound to one exact active predecessor release."""

    schema_version: Literal["itda.phase3-lane-baseline.v1"] = "itda.phase3-lane-baseline.v1"
    predecessor_release_sha256: Sha256
    canonical_lineage_sha256: Sha256
    dev_lineage_sha256: Sha256
    profile_schema_sha256: Sha256
    source_manifest_sha256: Sha256
    reviewed_manifest_sha256: Sha256
    authority_sha256: Sha256
    projection_rule_sha256: Sha256
    members: Annotated[tuple[Phase3LaneBaselineMember, ...], Field(min_length=24, max_length=24)]
    baseline_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def bind_baseline_digest(self) -> Self:
        if len({member.place_ref for member in self.members}) != 24:
            raise ValueError("phase 3 lane baseline requires 24 unique members")
        expected = canonical_sha256(self.model_dump(exclude={"baseline_sha256"}, mode="json"))
        if self.baseline_sha256 is None:
            object.__setattr__(self, "baseline_sha256", expected)
        elif not hmac.compare_digest(self.baseline_sha256, expected):
            raise ValueError("phase 3 lane baseline digest drifted")
        return self


class Phase3LaneBaselineResult(StrictContract):
    """One closed result: exact baseline or truthful protected-evidence pending."""

    status: Literal["READY", "PENDING_PROTECTED_BASELINE"]
    reason: Literal["PROTECTED_PHASE3_LANE_AUTHORITY_UNAVAILABLE"] | None = None
    baseline: Phase3LaneBaseline | None = None

    @model_validator(mode="after")
    def require_closed_result(self) -> Self:
        if self.status == "READY" and (self.baseline is None or self.reason is not None):
            raise ValueError("ready lane baseline result requires only a baseline")
        if self.status == "PENDING_PROTECTED_BASELINE" and (
            self.baseline is not None
            or self.reason != "PROTECTED_PHASE3_LANE_AUTHORITY_UNAVAILABLE"
        ):
            raise ValueError("pending lane baseline result requires the protected-evidence reason")
        return self


__all__ = [
    "Phase3LaneAttributeScore",
    "Phase3LaneAuthorityBundle",
    "Phase3LaneAuthorityMember",
    "Phase3LaneBaseline",
    "Phase3LaneBaselineMember",
    "Phase3LaneBaselineResult",
    "Phase3MediumLane",
    "Phase3MismatchTraitValue",
]
