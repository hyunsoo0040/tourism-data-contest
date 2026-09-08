"""Immutable public contract for an MVP scored release."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.mvp_place_scoring import (
    BoundScoringResult,
    LocalConditionScores,
    ProviderScoringResponse,
)
from itda.contracts.mvp_public_catalog import PublicEvidence, PublicPlaceId
from itda.domain.canonical import canonical_sha256


class InformationState(StrEnum):
    AUDIT_ONLY = "AUDIT_ONLY"
    LIMITED_INFORMATION = "LIMITED_INFORMATION"
    SUPPORTED = "SUPPORTED"


def information_state_for(confidence: int) -> InformationState:
    if confidence < 55:
        return InformationState.AUDIT_ONLY
    if confidence < 70:
        return InformationState.LIMITED_INFORMATION
    return InformationState.SUPPORTED


class MvpEvidenceExcerpt(StrictContract):
    evidence_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    excerpt_ko: Annotated[str, Field(strict=True, min_length=1, max_length=4_000)]
    source_label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    attribution_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    reference_date: date
    evidence: PublicEvidence

    @model_validator(mode="after")
    def validate_strict_evidence_projection(self) -> Self:
        if (
            self.evidence_id != self.evidence.evidence_id
            or self.excerpt_ko != self.evidence.excerpt
            or self.attribution_ko != self.evidence.attribution_text
            or self.reference_date != self.evidence.reference_date
        ):
            raise ValueError("MVP evidence excerpt does not match strict public evidence")
        return self


class MvpScoredProfile(StrictContract):
    place_id: PublicPlaceId
    place_name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    duplicate_group_id: Annotated[str, Field(strict=True, pattern=r"^duplicate:[0-9a-f]{64}$")]
    source_evidence_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=8)]
    evidence_excerpts: Annotated[tuple[MvpEvidenceExcerpt, ...], Field(min_length=1, max_length=8)]
    scores: ProviderScoringResponse
    condition_scores: LocalConditionScores
    information_state: InformationState
    recommendation_eligible: Literal[True]
    scoring_result: BoundScoringResult
    profile_sha256: Sha256

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        if self.source_evidence_ids != tuple(sorted(self.source_evidence_ids)):
            raise ValueError("profile evidence IDs must use canonical order")
        if len(self.source_evidence_ids) != len(set(self.source_evidence_ids)):
            raise ValueError("profile evidence IDs must be unique")
        if tuple(row.evidence_id for row in self.evidence_excerpts) != self.source_evidence_ids:
            raise ValueError("profile evidence excerpts must exactly cover source evidence IDs")
        referenced_evidence_ids = {
            evidence_id
            for justification in self.scores.justifications
            for evidence_id in justification.evidence_ids
        }
        if not referenced_evidence_ids.issubset(set(self.source_evidence_ids)):
            raise ValueError("profile score justifications reference evidence outside the profile")
        if (
            self.scoring_result.place_id != self.place_id
            or self.scoring_result.scores != self.scores
            or self.scoring_result.condition_scores != self.condition_scores
        ):
            raise ValueError("profile scoring result does not match its public projection")
        if self.information_state is not information_state_for(self.scores.confidence):
            raise ValueError("information state does not match confidence")
        expected = canonical_sha256(self.model_dump(exclude={"profile_sha256"}, mode="json"))
        if self.profile_sha256 != expected:
            raise ValueError("profile hash does not match")
        return self


class FailedPlace(StrictContract):
    place_id: PublicPlaceId
    reason: Literal[
        "PROVIDER_ATTEMPT_FAILED",
        "PROVIDER_RESPONSE_INVALID",
        "PROVIDER_RESPONSE_JSON_INVALID",
        "PROVIDER_RESPONSE_SCHEMA_INVALID",
        "PROVIDER_RESPONSE_SCORE_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATIONS_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_COUNT_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_DIMENSION_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_EVIDENCE_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_TEXT_INVALID",
        "PROVIDER_RESPONSE_JUSTIFICATION_SHAPE_INVALID",
        "PROVIDER_RESPONSE_SHAPE_INVALID",
        "PROVIDER_EVIDENCE_REFERENCE_INVALID",
        "REQUEST_INPUT_TOKEN_LIMIT_EXCEEDED",
    ]


class MvpReleaseLineage(StrictContract):
    model: Literal["glm-5.3-flash"] = "glm-5.3-flash"
    endpoint: Literal[
        "https://api.z.ai/api/coding/paas/v4/chat/completions"
    ] = "https://api.z.ai/api/coding/paas/v4/chat/completions"
    prompt_sha256: Sha256
    response_schema_sha256: Sha256
    source_sha256: Sha256
    entitlement_snapshot_sha256: Sha256
    canary_plan_sha256: Sha256
    canary_outcome_sha256: Sha256
    run_plan_sha256: Sha256


class MvpScoredRelease(StrictContract):
    schema_version: Literal["mvp-scored-release.v1"]
    attempted_count: Literal[100]
    published_count: Annotated[int, Field(strict=True, ge=80, le=100)]
    catalog_sha256: Sha256
    relation_sha256: Sha256
    evidence_inventory_sha256: Sha256
    membership_sha256: Sha256
    relation_pairs: tuple[tuple[PublicPlaceId, PublicPlaceId], ...]
    profiles: Annotated[tuple[MvpScoredProfile, ...], Field(min_length=80, max_length=100)]
    failed: Annotated[tuple[FailedPlace, ...], Field(max_length=20)]
    lineage: MvpReleaseLineage
    created_at: datetime
    release_sha256: Sha256

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        profile_ids = tuple(row.place_id for row in self.profiles)
        failed_ids = tuple(row.place_id for row in self.failed)
        if profile_ids != tuple(sorted(profile_ids)) or len(profile_ids) != len(set(profile_ids)):
            raise ValueError("release profiles must use unique canonical order")
        if failed_ids != tuple(sorted(failed_ids)) or len(failed_ids) != len(set(failed_ids)):
            raise ValueError("failed places must use unique canonical order")
        if set(profile_ids).intersection(failed_ids):
            raise ValueError("published and failed place sets overlap")
        if self.published_count != len(profile_ids):
            raise ValueError("published count does not match profiles")
        if len(profile_ids) + len(failed_ids) != self.attempted_count:
            raise ValueError("published and failed places must cover all 100 attempts")
        if (
            self.relation_pairs != tuple(sorted(self.relation_pairs))
            or len(self.relation_pairs) != len(set(self.relation_pairs))
            or any(left >= right for left, right in self.relation_pairs)
            or any(
                left not in set(profile_ids) or right not in set(profile_ids)
                for left, right in self.relation_pairs
            )
        ):
            raise ValueError("release relation pairs must use canonical member endpoints")
        from itda.contracts.recommendation import public_relation_sha256

        if self.relation_sha256 != public_relation_sha256(profile_ids, self.relation_pairs):
            raise ValueError("release relation hash does not match")
        expected_membership = canonical_sha256(list(profile_ids))
        if self.membership_sha256 != expected_membership:
            raise ValueError("release membership hash does not match")
        evidence_by_id: dict[str, PublicEvidence] = {}
        for profile in self.profiles:
            for excerpt in profile.evidence_excerpts:
                existing = evidence_by_id.setdefault(excerpt.evidence_id, excerpt.evidence)
                if existing != excerpt.evidence:
                    raise ValueError("release evidence ID resolves to conflicting public evidence")
        scoring_results = tuple(row.scoring_result for row in self.profiles)
        if any(
            result.catalog_sha256 != self.catalog_sha256
            or result.evidence_inventory_sha256 != self.evidence_inventory_sha256
            or result.prompt_sha256 != self.lineage.prompt_sha256
            or result.model != self.lineage.model
            for result in scoring_results
        ):
            raise ValueError("profile scoring lineage does not match release lineage")
        request_hashes = tuple(result.request_sha256 for result in scoring_results)
        result_hashes = tuple(result.result_sha256 for result in scoring_results)
        if len(set(request_hashes)) != len(request_hashes):
            raise ValueError("release scoring request hashes must be unique")
        if len(set(result_hashes)) != len(result_hashes):
            raise ValueError("release scoring result hashes must be unique")
        expected = canonical_sha256(self.model_dump(exclude={"release_sha256"}, mode="json"))
        if self.release_sha256 != expected:
            raise ValueError("release hash does not match")
        return self


class MvpActivePointer(StrictContract):
    schema_version: Literal["mvp-scored-release-active.v1"]
    release_sha256: Sha256
    previous_release_sha256: Sha256 | None
    pointer_sha256: Sha256

    @model_validator(mode="after")
    def validate_pointer(self) -> Self:
        if self.release_sha256 == self.previous_release_sha256:
            raise ValueError("active pointer cannot point back to itself")
        expected = canonical_sha256(self.model_dump(exclude={"pointer_sha256"}, mode="json"))
        if self.pointer_sha256 != expected:
            raise ValueError("active pointer hash does not match")
        return self
