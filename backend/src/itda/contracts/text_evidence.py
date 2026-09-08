"""Lossless, source-bound contracts for description and Odii text evidence."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, HttpUrl, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, Version, require_utc
from itda.contracts.candidate_review import SelectedOdiiStoryIdentity
from itda.domain.canonical import canonical_sha256


class EvidenceLane(StrEnum):
    """Independent official-source lanes that must never be merged."""

    DESCRIPTION = "DESCRIPTION"
    ODII = "ODII"


class SourceSpanKind(StrEnum):
    """Recoverable structural unit identified in the immutable source text."""

    TITLE = "TITLE"
    LIST_ITEM = "LIST_ITEM"
    ODII_SECTION_TITLE = "ODII_SECTION_TITLE"
    SENTENCE = "SENTENCE"
    PARENT_SECTION = "PARENT_SECTION"


class SourceSliceIdentity(StrictContract):
    """Exact source and byte-slice identity retained after normalization."""

    lane: EvidenceLane
    source_id: StableId
    source_url: HttpUrl
    raw_response_sha256: Sha256
    source_text_sha256: Sha256
    source_slice_sha256: Sha256


class ParentSpanEdge(StrictContract):
    """Lossless child-to-parent relation for an over-budget source unit."""

    parent_span_id: StableId
    child_span_id: StableId


class DedupEdgeKind(StrEnum):
    """Reason two original spans share one conservative evidence cluster."""

    EXACT = "EXACT"
    NEAR = "NEAR"


class LaneEvidenceStatus(StrEnum):
    """Availability of an independently approved evidence lane."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"


class NormalizationPolicy(StrictContract):
    """Frozen exact-normalization and conservative near-dedup policy."""

    version: Version
    char_trigram_jaccard: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
    length_ratio: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]

    @model_validator(mode="after")
    def validate_frozen_policy(self) -> NormalizationPolicy:
        if (
            self.version != "ko-conservative-dedup-v1"
            or self.char_trigram_jaccard != 0.92
            or self.length_ratio != 0.85
        ):
            raise ValueError("normalization policy must match ko-conservative-dedup-v1")
        return self


class DedupOriginal(StrictContract):
    """One original sentence retained inside a deduplication graph."""

    span_id: StableId
    lane: EvidenceLane
    source_id: StableId
    text: Annotated[str, Field(strict=True, min_length=1)]
    comparison_text: Annotated[str, Field(strict=True, min_length=1)]
    input_order: Annotated[int, Field(strict=True, ge=0)]


class DedupEdge(StrictContract):
    """Deterministic reversible relation between two original spans."""

    left_span_id: StableId
    right_span_id: StableId
    lane: EvidenceLane
    kind: DedupEdgeKind
    char_trigram_jaccard: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]
    length_ratio: Annotated[float, Field(strict=True, ge=0.0, le=1.0)]

    @model_validator(mode="after")
    def validate_distinct_endpoints(self) -> DedupEdge:
        if self.left_span_id == self.right_span_id:
            raise ValueError("dedup edge endpoints must be distinct")
        return self


class DedupCluster(StrictContract):
    """One canonical display choice with every original source edge retained."""

    cluster_id: StableId
    lane: EvidenceLane
    canonical_span_id: StableId
    originals: tuple[DedupOriginal, ...]

    @model_validator(mode="after")
    def validate_cluster_members(self) -> DedupCluster:
        if not self.originals:
            raise ValueError("dedup cluster must preserve at least one original")
        if any(original.lane is not self.lane for original in self.originals):
            raise ValueError("dedup cluster cannot merge evidence lanes")
        ids = tuple(original.span_id for original in self.originals)
        if len(set(ids)) != len(ids) or self.canonical_span_id not in ids:
            raise ValueError("dedup cluster canonical span must identify one unique original")
        return self

    @property
    def distinct_source_count(self) -> int:
        return len({original.source_id for original in self.originals})


class DedupGraph(StrictContract):
    """Complete lossless graph produced by one frozen normalization policy."""

    policy: NormalizationPolicy
    edges: tuple[DedupEdge, ...]
    clusters: tuple[DedupCluster, ...]


class LaneEvidence(StrictContract):
    """Explicit available or MISSING state for one independent lane."""

    lane: EvidenceLane
    status: LaneEvidenceStatus
    spans: tuple[DedupOriginal, ...]

    @model_validator(mode="after")
    def validate_missing_state(self) -> LaneEvidence:
        if self.status is LaneEvidenceStatus.MISSING and self.spans:
            raise ValueError("MISSING lane cannot contain evidence")
        if self.status is LaneEvidenceStatus.AVAILABLE and not self.spans:
            raise ValueError("AVAILABLE lane requires evidence")
        if any(span.lane is not self.lane for span in self.spans):
            raise ValueError("lane evidence cannot mix description and Odii")
        return self


class SourceSpan(StrictContract):
    """One exact character and UTF-8 byte slice of an official source."""

    span_id: StableId
    lane: EvidenceLane
    kind: SourceSpanKind
    source_id: StableId
    source_url: HttpUrl
    raw_response_sha256: Sha256
    source_text_sha256: Sha256
    source_slice_sha256: Sha256
    normalization_version: Version
    original_text: Annotated[str, Field(strict=True, min_length=1)]
    start_char: Annotated[int, Field(strict=True, ge=0)]
    end_char: Annotated[int, Field(strict=True, ge=1)]
    start_byte: Annotated[int, Field(strict=True, ge=0)]
    end_byte: Annotated[int, Field(strict=True, ge=1)]
    parent_span_id: StableId | None = None
    parent_section: Annotated[str | None, Field(strict=True, min_length=1)] = None
    selected_odii_story: SelectedOdiiStoryIdentity | None = None

    @model_validator(mode="after")
    def validate_offsets_and_lane_identity(self) -> SourceSpan:
        if self.start_char >= self.end_char or self.start_byte >= self.end_byte:
            raise ValueError("source span offsets must describe a non-empty slice")
        if self.lane is EvidenceLane.ODII:
            if self.selected_odii_story is None:
                raise ValueError("Odii span requires selected Odii story identity")
            if self.selected_odii_story.raw_response_sha256 != self.raw_response_sha256:
                raise ValueError("selected Odii story must match the source response digest")
        elif self.selected_odii_story is not None:
            raise ValueError("description span cannot carry selected Odii story identity")
        return self

    @property
    def slice_identity(self) -> SourceSliceIdentity:
        return SourceSliceIdentity(
            lane=self.lane,
            source_id=self.source_id,
            source_url=self.source_url,
            raw_response_sha256=self.raw_response_sha256,
            source_text_sha256=self.source_text_sha256,
            source_slice_sha256=self.source_slice_sha256,
        )


class EvidenceRelevanceDecision(StrEnum):
    """Closed relevance-only judgments for immutable model candidates."""

    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    NOT_CURRENT_SITE = "NOT_CURRENT_SITE"


class CandidateAttributeScore(StrictContract):
    """One immutable candidate score retained only for reviewer inspection."""

    attribute_id: StableId
    score: Annotated[float, Field(strict=True)]


class EvidenceCandidate(StrictContract):
    """Exact candidate projection copied from a verified 03-10 manifest."""

    candidate_id: Sha256
    candidate_sha256: Sha256
    lane: EvidenceLane
    source_id: StableId
    source_sha256: Sha256
    span_id: StableId
    slice_sha256: Sha256
    start_char: Annotated[int, Field(strict=True, ge=0)]
    end_char: Annotated[int, Field(strict=True, ge=1)]
    start_byte: Annotated[int, Field(strict=True, ge=0)]
    end_byte: Annotated[int, Field(strict=True, ge=1)]
    dedup_cluster_id: StableId
    dedup_edges: tuple[StableId, ...]
    original_order: Annotated[int, Field(strict=True, ge=0)]
    text: Annotated[str, Field(strict=True, min_length=1)]
    attribute_scores: tuple[CandidateAttributeScore, ...]
    score: Annotated[float, Field(strict=True)]

    @model_validator(mode="after")
    def validate_candidate_identity(self) -> Self:
        if self.start_char >= self.end_char or self.start_byte >= self.end_byte:
            raise ValueError("candidate offsets must describe a non-empty source slice")
        expected = canonical_sha256(self.model_dump(exclude={"candidate_sha256"}, mode="json"))
        if self.candidate_sha256 != expected:
            raise ValueError("candidate hash does not match immutable candidate fields")
        return self


class EvidenceReviewProvenance(StrictContract):
    """Complete 03-10 run lineage copied into every review-layer receipt."""

    freeze_receipt_sha256: Sha256
    accepted_revision_set_sha256: Sha256
    source_manifest_sha256: Sha256
    data_lineage_sha256: Sha256
    data_version: Version
    model_id: Annotated[str, Field(strict=True, min_length=1)]
    model_revision: Annotated[str, Field(strict=True, min_length=1)]
    model_config_sha256: Sha256
    tokenizer_sha256: Sha256
    weight_sha256: Sha256
    prompt_anchor_version: Version
    preprocessing_version: Version
    scoring_version: Version
    code_git_sha: Annotated[str, Field(strict=True, min_length=1)]
    config_sha256: Sha256
    started_at: datetime
    completed_at: datetime
    candidate_output_sha256: Sha256

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        require_utc(self.started_at, field_name="started_at")
        require_utc(self.completed_at, field_name="completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("candidate run cannot complete before it starts")
        return self


class EvidenceReviewRevision(StrictContract):
    """Append-only relevance decision or reason-bound correction."""

    schema_version: Literal["phase3-evidence-review-v1"] = "phase3-evidence-review-v1"
    candidate_manifest_sha256: Sha256
    candidate_id: Sha256
    candidate_sha256: Sha256
    lane: EvidenceLane
    decision: EvidenceRelevanceDecision
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    reviewer_pseudonym: StableId
    reviewed_at: datetime
    provenance: EvidenceReviewProvenance
    parent_review_sha256: Sha256 | None = None
    correction_reason: Annotated[str | None, Field(strict=True, min_length=1, max_length=300)] = (
        None
    )
    review_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_review(self) -> Self:
        require_utc(self.reviewed_at, field_name="reviewed_at")
        if (self.parent_review_sha256 is None) != (self.correction_reason is None):
            raise ValueError("review correction parent and reason must be paired")
        expected = canonical_sha256(self.model_dump(exclude={"review_sha256"}, mode="json"))
        if self.review_sha256 is None:
            object.__setattr__(self, "review_sha256", expected)
        elif self.review_sha256 != expected:
            raise ValueError("review hash does not match immutable decision fields")
        return self


class EvidenceReviewReceipt(StrictContract):
    """Immutable database receipt for one appended review revision."""

    receipt_sha256: Sha256
    revision: EvidenceReviewRevision
    created_at: datetime

    @model_validator(mode="after")
    def validate_created_at(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        return self


class EvidenceCandidateLane(StrictContract):
    """One immutable review queue lane from the current candidate manifest."""

    lane: EvidenceLane
    status: LaneEvidenceStatus
    candidates: tuple[EvidenceCandidate, ...]

    @model_validator(mode="after")
    def validate_lane(self) -> Self:
        if self.status is LaneEvidenceStatus.MISSING and self.candidates:
            raise ValueError("candidate MISSING lane cannot contain evidence")
        if self.status is LaneEvidenceStatus.AVAILABLE and not self.candidates:
            raise ValueError("candidate AVAILABLE lane requires evidence")
        if any(candidate.lane is not self.lane for candidate in self.candidates):
            raise ValueError("candidate queue cannot cross lanes")
        return self


class EvidenceReviewQueue(StrictContract):
    """Role-isolated immutable candidate payload available to one reviewer."""

    candidate_manifest_sha256: Sha256
    provenance: EvidenceReviewProvenance
    lanes: tuple[EvidenceCandidateLane, EvidenceCandidateLane]

    @model_validator(mode="after")
    def validate_lane_order(self) -> Self:
        if tuple(lane.lane for lane in self.lanes) != (
            EvidenceLane.DESCRIPTION,
            EvidenceLane.ODII,
        ):
            raise ValueError("candidate queue must preserve separate lane order")
        return self


class EvidenceReviewChain(StrictContract):
    """One linear immutable reviewer chain with its current accepted head."""

    candidate_manifest_sha256: Sha256
    candidate_id: Sha256
    candidate_sha256: Sha256
    lane: EvidenceLane
    revisions: tuple[EvidenceReviewRevision, ...]
    tip_review_sha256: Sha256
    chain_sha256: Sha256
    accepted_head: AcceptedEvidenceReviewHead | None = None


class AcceptedEvidenceReviewHead(StrictContract):
    """Explicit append-only selection of a current review-chain tip."""

    schema_version: Literal["phase3-evidence-review-head-v1"] = "phase3-evidence-review-head-v1"
    candidate_manifest_sha256: Sha256
    candidate_id: Sha256
    candidate_sha256: Sha256
    lane: EvidenceLane
    accepted_review_sha256: Sha256
    expected_chain_sha256: Sha256
    selected_by: StableId
    selection_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    selected_at: datetime
    provenance: EvidenceReviewProvenance
    event_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_head(self) -> Self:
        require_utc(self.selected_at, field_name="selected_at")
        expected = canonical_sha256(self.model_dump(exclude={"event_sha256"}, mode="json"))
        if self.event_sha256 is None:
            object.__setattr__(self, "event_sha256", expected)
        elif self.event_sha256 != expected:
            raise ValueError("accepted review head hash is stale")
        return self


class ReviewedEvidenceItem(StrictContract):
    """One accepted immutable candidate linked to its accepted review head."""

    candidate: EvidenceCandidate
    accepted_review_sha256: Sha256
    accepted_head_sha256: Sha256


class ReviewedEvidenceLane(StrictContract):
    """Separate publish lane containing at most three reviewed sentences or MISSING."""

    lane: EvidenceLane
    status: LaneEvidenceStatus
    evidence: Annotated[tuple[ReviewedEvidenceItem, ...], Field(max_length=3)]
    missing_reason: Literal["UPSTREAM_CANDIDATE_LANE_MISSING"] | None = None

    @model_validator(mode="after")
    def validate_lane(self) -> Self:
        if self.status is LaneEvidenceStatus.MISSING:
            if self.evidence or self.missing_reason is None:
                raise ValueError("reviewed MISSING lane cannot fabricate evidence")
        elif not self.evidence or self.missing_reason is not None:
            raise ValueError("reviewed AVAILABLE lane requires accepted evidence")
        if any(item.candidate.lane is not self.lane for item in self.evidence):
            raise ValueError("reviewed evidence cannot cross lanes")
        return self


class ReviewedEvidenceManifest(StrictContract):
    """Content-addressed D-12/D-13 release input produced without replacement."""

    schema_version: Literal["phase3-reviewed-evidence-manifest-v1"] = (
        "phase3-reviewed-evidence-manifest-v1"
    )
    candidate_manifest_sha256: Sha256
    accepted_review_set_sha256: Sha256
    provenance: EvidenceReviewProvenance
    lanes: tuple[ReviewedEvidenceLane, ReviewedEvidenceLane]
    finalized_by: StableId
    finalized_at: datetime
    manifest_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        require_utc(self.finalized_at, field_name="finalized_at")
        if tuple(lane.lane for lane in self.lanes) != (
            EvidenceLane.DESCRIPTION,
            EvidenceLane.ODII,
        ):
            raise ValueError("reviewed manifest must preserve separate lane order")
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 is None:
            object.__setattr__(self, "manifest_sha256", expected)
        elif self.manifest_sha256 != expected:
            raise ValueError("reviewed manifest hash is stale")
        return self


__all__ = [
    "AcceptedEvidenceReviewHead",
    "CandidateAttributeScore",
    "DedupCluster",
    "DedupEdge",
    "DedupEdgeKind",
    "DedupGraph",
    "DedupOriginal",
    "EvidenceCandidate",
    "EvidenceCandidateLane",
    "EvidenceLane",
    "EvidenceRelevanceDecision",
    "EvidenceReviewChain",
    "EvidenceReviewProvenance",
    "EvidenceReviewQueue",
    "EvidenceReviewReceipt",
    "EvidenceReviewRevision",
    "LaneEvidence",
    "LaneEvidenceStatus",
    "NormalizationPolicy",
    "ParentSpanEdge",
    "ReviewedEvidenceItem",
    "ReviewedEvidenceLane",
    "ReviewedEvidenceManifest",
    "SourceSliceIdentity",
    "SourceSpan",
    "SourceSpanKind",
]
