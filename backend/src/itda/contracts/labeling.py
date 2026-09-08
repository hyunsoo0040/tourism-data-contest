"""Strict Phase 3 labeling contracts and deterministic review triggers."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from fractions import Fraction
from typing import Annotated, Literal, Self, cast

from pydantic import AliasChoices, Field, StrictBool, field_validator, model_validator

from itda.contracts.base import (
    ExperienceAxis,
    Sha256,
    StableId,
    StrictContract,
    Version,
    require_utc,
)
from itda.contracts.place_profile import SUBATTRIBUTE_SPECS, SubattributeId
from itda.domain.canonical import canonical_sha256

_BOUNDARY_ASCII_WHITESPACE = " \t\n\r\f\v"


class UnknownReason(StrEnum):
    NO_EVIDENCE = "NO_EVIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    OUT_OF_SCOPE_INFORMATION = "OUT_OF_SCOPE_INFORMATION"


class PrimaryAxis(StrEnum):
    HISTORY_TRADITION = "HISTORY_TRADITION"
    EMOTION_IMAGE = "EMOTION_IMAGE"
    REST_IMMERSION = "REST_IMMERSION"


class EvidenceLane(StrEnum):
    DESCRIPTION = "DESCRIPTION"
    ODII = "ODII"


class RubricAnchor(StrictContract):
    score: Annotated[int, Field(strict=True, ge=0, le=4)]
    meaning_code: Literal["ABSENT", "WEAK", "MODERATE", "STRONG", "DOMINANT"]


SCORE_ANCHORS = (
    RubricAnchor(score=0, meaning_code="ABSENT"),
    RubricAnchor(score=1, meaning_code="WEAK"),
    RubricAnchor(score=2, meaning_code="MODERATE"),
    RubricAnchor(score=3, meaning_code="STRONG"),
    RubricAnchor(score=4, meaning_code="DOMINANT"),
)


class LabelSubattributeSpec(StrictContract):
    attribute_id: SubattributeId
    axis: ExperienceAxis
    label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    examples_ko: Annotated[tuple[str, ...], Field(min_length=1)]
    counterexamples_ko: Annotated[tuple[str, ...], Field(min_length=1)]

    @field_validator("examples_ko", "counterexamples_ko")
    @classmethod
    def guidance_must_be_nonempty(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("Korean rubric guidance must not be blank")
        return values


_GUIDANCE = {
    "H1": (("시대와 유래를 직접 설명한다",), ("유래 설명 없이 시설만 나열한다",)),
    "H2": (("보존 흔적이 경험의 중심이다",), ("원형과 무관한 임시 장식뿐이다",)),
    "H3": (("전통생활이 현재 경험과 이어진다",), ("현재와의 연결 근거가 없다",)),
    "H4": (("해설과 교육 탐색이 구체적이다",), ("학습 가능한 설명이 없다",)),
    "I1": (("기억되는 형태가 직접 묘사된다",), ("구별되는 장면 근거가 없다",)),
    "I2": (("경관의 구도와 계절감이 설명된다",), ("경관 정보가 전혀 없다",)),
    "I3": (("전통 요소를 현재 방식으로 잇는다",), ("재해석 근거가 없다",)),
    "I4": (("빛과 공간 분위기가 구체적이다",), ("감각 경험 설명이 없다",)),
    "R1": (("회복을 돕는 자연 요소가 있다",), ("자연 요소를 확인할 수 없다",)),
    "R2": (("천천히 걷고 머무는 동선이 있다",), ("체류 가능성을 뒷받침하지 않는다",)),
    "R3": (("조용히 머무를 수 있다고 설명한다",), ("정적 환경 근거가 없다",)),
    "R4": (("탐방과 이야기 몰입이 연결된다",), ("참여 또는 몰입 근거가 없다",)),
}

LABEL_RUBRIC_SPECS = tuple(
    LabelSubattributeSpec(
        attribute_id=spec.attribute_id,
        axis=spec.axis,
        label_ko=spec.label_ko,
        examples_ko=_GUIDANCE[spec.attribute_id.value][0],
        counterexamples_ko=_GUIDANCE[spec.attribute_id.value][1],
    )
    for spec in SUBATTRIBUTE_SPECS
)


class LabelRubric(StrictContract):
    subattributes: tuple[
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
        LabelSubattributeSpec,
    ]

    @model_validator(mode="after")
    def enforce_canonical_rows(self) -> Self:
        if self.subattributes != LABEL_RUBRIC_SPECS:
            raise ValueError("label rubric must match the canonical ordered H1-R4 rows")
        return self


class EvidenceReference(StrictContract):
    evidence_id: StableId
    source_id: StableId
    lane: EvidenceLane
    dedup_cluster_id: StableId
    direct: StrictBool
    concordance_key: StableId
    supports_absence: StrictBool = False
    complete_context: StrictBool = False


class _JudgmentFields(StrictContract):
    attribute_id: SubattributeId
    score: Annotated[int, Field(strict=True, ge=0, le=4)] | None
    unknown_reason: UnknownReason | None = None
    unknown_note: (
        Annotated[
            str,
            Field(strict=True, min_length=1, max_length=300),
        ]
        | None
    ) = None
    evidence: tuple[EvidenceReference, ...] = ()

    @field_validator("unknown_note")
    @classmethod
    def note_must_already_be_trimmed(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip(_BOUNDARY_ASCII_WHITESPACE):
            raise ValueError("unknown note must be trimmed")
        return value

    @model_validator(mode="after")
    def enforce_null_and_zero_meanings(self) -> Self:
        if self.score is None:
            if self.unknown_reason is None or self.unknown_note is None:
                raise ValueError("unknown score requires a closed reason and note")
        elif self.unknown_reason is not None or self.unknown_note is not None:
            raise ValueError("numeric score forbids unknown reason and note")
        if self.score == 0 and not any(
            item.supports_absence or item.complete_context for item in self.evidence
        ):
            raise ValueError("zero requires positive confirmed-absence evidence")
        return self


class AttributeJudgment(_JudgmentFields):
    """Validated API judgment; high anchors require direct supporting evidence."""

    @model_validator(mode="after")
    def enforce_high_anchor_evidence(self) -> Self:
        direct = tuple(item for item in self.evidence if item.direct)
        if self.score == 3 and not direct:
            raise ValueError("score three requires direct evidence")
        if self.score == 4:
            clusters = {item.dedup_cluster_id for item in direct}
            if len(clusters) < 2:
                raise ValueError("score four requires two distinct direct evidence clusters")
        return self


class RevisionJudgment(_JudgmentFields):
    """Persisted raw input used to derive missing-evidence review triggers."""


class RawLabelRevision(StrictContract):
    assignment_id: StableId
    evaluator_pseudonym: StableId
    primary_axis: PrimaryAxis | None = Field(
        validation_alias=AliasChoices("primary_axis", "primary_axis_judgment")
    )
    rubric_version: Version
    source_snapshot_version: Version
    parent_revision_sha256: Sha256 | None = None
    correction_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)] | None = (
        None
    )
    judgments: tuple[
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
    ]
    submitted_at: datetime

    @field_validator("correction_reason")
    @classmethod
    def correction_reason_must_already_be_trimmed(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip(_BOUNDARY_ASCII_WHITESPACE):
            raise ValueError("correction reason must be trimmed")
        return value

    @model_validator(mode="after")
    def revision_invariants(self) -> Self:
        require_utc(self.submitted_at, field_name="submitted_at")
        if tuple(item.attribute_id for item in self.judgments) != tuple(SubattributeId):
            raise ValueError("revision judgments must use canonical H1-R4 order")
        if (self.parent_revision_sha256 is None) != (self.correction_reason is None):
            raise ValueError("correction parent and reason must be supplied together")
        return self

    @property
    def revision_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class RevisionReceipt(StrictContract):
    schema_version: Literal["itda.phase3-label-revision-receipt.v1"] = (
        "itda.phase3-label-revision-receipt.v1"
    )
    revision_sha256: Sha256
    assignment_id: StableId
    evaluator_pseudonym: StableId
    accepted_head: StrictBool = False
    server_event_at: datetime
    receipt_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        require_utc(self.server_event_at, field_name="server_event_at")
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif self.receipt_sha256 != expected:
            raise ValueError("revision receipt sha256 is stale")
        return self


class AcceptedRevisionSelection(StrictContract):
    """One immutable operator choice of an exact evaluator revision."""

    schema_version: Literal["itda.phase3-accepted-revision-selection.v1"] = (
        "itda.phase3-accepted-revision-selection.v1"
    )
    assignment_id: StableId
    evaluator_pseudonym: StableId
    accepted_revision_sha256: Sha256
    operator_pseudonym: StableId
    selected_at: datetime
    selection_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        require_utc(self.selected_at, field_name="selected_at")
        expected = canonical_sha256(self.model_dump(exclude={"selection_sha256"}, mode="json"))
        if self.selection_sha256 is None:
            object.__setattr__(self, "selection_sha256", expected)
        elif self.selection_sha256 != expected:
            raise ValueError("accepted revision selection sha256 is stale")
        return self


class AdjudicationOfficialSource(StrictContract):
    """One allowlisted official source exposed to the adjudicator."""

    source_id: StableId
    lane: EvidenceLane
    original_text: Annotated[str, Field(strict=True, min_length=1, max_length=50_000)]
    source_text_sha256: Sha256
    evidence_ids: Annotated[tuple[StableId, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if (
            self.source_text_sha256
            != hashlib.sha256(self.original_text.encode("utf-8")).hexdigest()
        ):
            raise ValueError("official source text sha256 is stale")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("official source evidence IDs must use unique canonical order")
        return self


class AdjudicationSourceManifest(StrictContract):
    """Server-held source boundary accepted by the adjudicator repository."""

    assignment_id: StableId
    source_snapshot_version: Version
    sources: Annotated[tuple[AdjudicationOfficialSource, ...], Field(min_length=1)]
    official_source_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if self.sources != tuple(sorted(self.sources, key=lambda item: item.source_id)):
            raise ValueError("official sources must use canonical source ID order")
        source_ids = tuple(item.source_id for item in self.sources)
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("official source IDs must be unique")
        all_evidence_ids = tuple(
            evidence_id for source in self.sources for evidence_id in source.evidence_ids
        )
        if len(set(all_evidence_ids)) != len(all_evidence_ids):
            raise ValueError("official evidence IDs must resolve to exactly one source")
        expected = canonical_sha256(
            self.model_dump(exclude={"official_source_sha256"}, mode="json")
        )
        if self.official_source_sha256 is None:
            object.__setattr__(self, "official_source_sha256", expected)
        elif self.official_source_sha256 != expected:
            raise ValueError("official source manifest sha256 is stale")
        return self


class AdjudicatorRawRevision(StrictContract):
    """One immutable pseudonymous raw revision in the adjudicator projection."""

    revision_sha256: Sha256
    receipt_sha256: Sha256
    parent_revision_sha256: Sha256 | None = None
    correction_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)] | None = (
        None
    )
    primary_axis: PrimaryAxis | None
    judgments: tuple[
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
        RevisionJudgment,
    ]
    submitted_at: datetime
    created_at: datetime

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        require_utc(self.submitted_at, field_name="submitted_at")
        require_utc(self.created_at, field_name="created_at")
        if tuple(item.attribute_id for item in self.judgments) != tuple(SubattributeId):
            raise ValueError("adjudicator judgments must use canonical H1-R4 order")
        if (self.parent_revision_sha256 is None) != (self.correction_reason is None):
            raise ValueError("adjudicator correction parent and reason must be paired")
        return self


class AdjudicatorAcceptedHead(StrictContract):
    """Existing append-only accepted-head event projected without real principals."""

    event_sha256: Sha256
    selection: AcceptedRevisionSelection
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]


class AdjudicatorRevisionChain(StrictContract):
    """One complete immutable correction chain for a pseudonymous evaluator."""

    evaluator_pseudonym: StableId
    revisions: Annotated[tuple[AdjudicatorRawRevision, ...], Field(min_length=1)]
    tip_revision_sha256: Sha256
    accepted_head: AdjudicatorAcceptedHead | None = None
    chain_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_chain(self) -> Self:
        revision_ids = tuple(item.revision_sha256 for item in self.revisions)
        if len(set(revision_ids)) != len(revision_ids):
            raise ValueError("adjudicator revision chain contains duplicate revisions")
        if self.revisions[0].parent_revision_sha256 is not None:
            raise ValueError("adjudicator revision chain must begin at its root")
        for previous, current in zip(self.revisions, self.revisions[1:], strict=False):
            if current.parent_revision_sha256 != previous.revision_sha256:
                raise ValueError("adjudicator revision chain is forked or non-canonical")
        if self.tip_revision_sha256 != self.revisions[-1].revision_sha256:
            raise ValueError("adjudicator revision chain tip is stale")
        if (
            self.accepted_head is not None
            and self.accepted_head.selection.accepted_revision_sha256 != self.tip_revision_sha256
        ):
            raise ValueError("adjudicator accepted head is not the current chain tip")
        expected = canonical_sha256(self.model_dump(exclude={"chain_sha256"}, mode="json"))
        if self.chain_sha256 is None:
            object.__setattr__(self, "chain_sha256", expected)
        elif self.chain_sha256 != expected:
            raise ValueError("adjudicator chain sha256 is stale")
        return self


class AdjudicationProjection(StrictContract):
    """Canonical source-first adjudicator response with a closed field allowlist."""

    schema_version: Literal["itda.phase3-adjudication-projection.v1"] = (
        "itda.phase3-adjudication-projection.v1"
    )
    assignment_id: StableId
    rubric_version: Version
    source_snapshot_version: Version
    official_sources: Annotated[tuple[AdjudicationOfficialSource, ...], Field(min_length=1)]
    official_source_sha256: Sha256
    chains: Annotated[tuple[AdjudicatorRevisionChain, ...], Field(min_length=1)]
    accepted_revision_set_sha256: Sha256 | None = None
    review_triggers: tuple[ReviewTrigger, ...] = ()
    release_blocked: StrictBool
    projection_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if self.official_sources != tuple(
            sorted(self.official_sources, key=lambda item: item.source_id)
        ):
            raise ValueError("projection sources must use canonical source ID order")
        if self.chains != tuple(sorted(self.chains, key=lambda item: item.evaluator_pseudonym)):
            raise ValueError("projection chains must use canonical pseudonym order")
        pseudonyms = tuple(item.evaluator_pseudonym for item in self.chains)
        if len(set(pseudonyms)) != len(pseudonyms):
            raise ValueError("projection evaluator pseudonyms must be unique")
        selections = tuple(
            chain.accepted_head.selection
            for chain in self.chains
            if chain.accepted_head is not None
        )
        complete = len(self.chains) == 3 and len(selections) == 3
        if complete:
            expected_set = canonical_sha256(
                [selection.model_dump(mode="json") for selection in selections]
            )
            if self.accepted_revision_set_sha256 != expected_set:
                raise ValueError("projection accepted revision set sha256 is stale")
            if self.release_blocked:
                raise ValueError("complete accepted projection cannot be marked blocked")
        elif self.accepted_revision_set_sha256 is not None or not self.release_blocked:
            raise ValueError("incomplete accepted projection must remain visibly blocked")
        expected = canonical_sha256(self.model_dump(exclude={"projection_sha256"}, mode="json"))
        if self.projection_sha256 is None:
            object.__setattr__(self, "projection_sha256", expected)
        elif self.projection_sha256 != expected:
            raise ValueError("adjudication projection sha256 is stale")
        return self


class ReviewReason(StrEnum):
    ATTRIBUTE_RANGE_AT_LEAST_TWO = "ATTRIBUTE_RANGE_AT_LEAST_TWO"
    ALL_PRIMARY_AXES_DIFFER = "ALL_PRIMARY_AXES_DIFFER"
    REQUIRED_EVIDENCE_MISSING = "REQUIRED_EVIDENCE_MISSING"
    PRIMARY_AXIS_MISSING = "PRIMARY_AXIS_MISSING"


# Compatibility name retained for the Wave 0 contract without creating a second vocabulary.
ReviewTriggerKind = ReviewReason


class ReviewTrigger(StrictContract):
    kind: ReviewReason
    attribute_id: SubattributeId | None = None
    observed_numeric_values: tuple[int, ...] = ()
    review_trigger_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_trigger(self) -> Self:
        if (
            self.kind
            in {
                ReviewReason.ATTRIBUTE_RANGE_AT_LEAST_TWO,
                ReviewReason.REQUIRED_EVIDENCE_MISSING,
            }
            and self.attribute_id is None
        ):
            raise ValueError("attribute review reason requires an attribute ID")
        if (
            self.kind
            in {
                ReviewReason.ALL_PRIMARY_AXES_DIFFER,
                ReviewReason.PRIMARY_AXIS_MISSING,
            }
            and self.attribute_id is not None
        ):
            raise ValueError("primary-axis review reason forbids an attribute ID")
        expected = canonical_sha256(self.model_dump(exclude={"review_trigger_sha256"}, mode="json"))
        if self.review_trigger_sha256 is None:
            object.__setattr__(self, "review_trigger_sha256", expected)
        elif self.review_trigger_sha256 != expected:
            raise ValueError("review trigger sha256 is stale")
        return self


AdjudicationProjection.model_rebuild()


class ReviewTriggerResolution(StrictContract):
    """Append-only model-free resolution of one exact automatic review reason."""

    review_trigger_sha256: Sha256
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    adjudicator_pseudonym: StableId
    resolved_at: datetime
    resolution_sha256: Sha256 | None = None

    @field_validator("reason")
    @classmethod
    def reason_must_be_trimmed(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("review resolution reason must be trimmed")
        return value

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        require_utc(self.resolved_at, field_name="resolved_at")
        expected = canonical_sha256(self.model_dump(exclude={"resolution_sha256"}, mode="json"))
        if self.resolution_sha256 is None:
            object.__setattr__(self, "resolution_sha256", expected)
        elif self.resolution_sha256 != expected:
            raise ValueError("review trigger resolution sha256 is stale")
        return self


class AdjudicatedAttributeValue(StrictContract):
    """Explicit integer decision for a non-integer two-score median."""

    attribute_id: SubattributeId
    exact_median: Annotated[str, Field(strict=True, pattern=r"^[0-4]\.5$")]
    adjudicated_value: Annotated[int, Field(strict=True, ge=0, le=4)]
    reason: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    adjudicator_pseudonym: StableId
    adjudicated_at: datetime
    adjudication_sha256: Sha256 | None = None

    @field_validator("reason")
    @classmethod
    def adjudication_reason_must_be_trimmed(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("adjudication reason must be trimmed")
        return value

    @model_validator(mode="after")
    def validate_adjudication(self) -> Self:
        require_utc(self.adjudicated_at, field_name="adjudicated_at")
        midpoint = Fraction(self.exact_median)
        if self.adjudicated_value not in {midpoint.numerator // 2, midpoint.numerator // 2 + 1}:
            raise ValueError("adjudicated value must be adjacent to the exact half-step median")
        expected = canonical_sha256(self.model_dump(exclude={"adjudication_sha256"}, mode="json"))
        if self.adjudication_sha256 is None:
            object.__setattr__(self, "adjudication_sha256", expected)
        elif self.adjudication_sha256 != expected:
            raise ValueError("attribute adjudication sha256 is stale")
        return self


class AcceptedEvaluatorValue(StrictContract):
    evaluator_pseudonym: StableId
    accepted_revision_sha256: Sha256
    score: Annotated[int, Field(strict=True, ge=0, le=4)] | None
    unknown_reason: UnknownReason | None = None
    unknown_note: Annotated[str, Field(strict=True, min_length=1, max_length=300)] | None = None

    @model_validator(mode="after")
    def preserve_unknown_semantics(self) -> Self:
        if self.score is None and (self.unknown_reason is None or self.unknown_note is None):
            raise ValueError("unknown accepted value requires its original reason and note")
        if self.score is not None and (
            self.unknown_reason is not None or self.unknown_note is not None
        ):
            raise ValueError("numeric accepted value forbids unknown metadata")
        return self


class LabelAggregate(StrictContract):
    """One immutable per-attribute aggregate preserving every accepted input."""

    attribute_id: SubattributeId
    accepted_values: tuple[AcceptedEvaluatorValue, AcceptedEvaluatorValue, AcceptedEvaluatorValue]
    numeric_values: Annotated[tuple[int, ...], Field(min_length=2, max_length=3)]
    exact_median: Annotated[str, Field(strict=True, pattern=r"^[0-4](?:\.5)?$")]
    value: Annotated[int, Field(strict=True, ge=0, le=4)]
    aggregation_kind: Literal["EXACT_MEDIAN", "ADJUDICATED"]
    adjudication_sha256: Sha256 | None = None
    aggregate_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        if self.numeric_values != tuple(sorted(self.numeric_values)):
            raise ValueError("aggregate numeric values must use canonical order")
        observed = tuple(
            sorted(item.score for item in self.accepted_values if item.score is not None)
        )
        if self.numeric_values != observed:
            raise ValueError("aggregate numeric values differ from accepted inputs")
        if self.aggregation_kind == "ADJUDICATED" and self.adjudication_sha256 is None:
            raise ValueError("adjudicated aggregate requires an adjudication digest")
        if self.aggregation_kind == "EXACT_MEDIAN" and self.adjudication_sha256 is not None:
            raise ValueError("exact-median aggregate forbids an adjudication digest")
        expected = canonical_sha256(self.model_dump(exclude={"aggregate_sha256"}, mode="json"))
        if self.aggregate_sha256 is None:
            object.__setattr__(self, "aggregate_sha256", expected)
        elif self.aggregate_sha256 != expected:
            raise ValueError("label aggregate sha256 is stale")
        return self


class LabelExportBlocked(ValueError):
    """The accepted set is incomplete or cannot be exported safely."""


class AdjudicationRequired(LabelExportBlocked):
    """A half-step median lacks its explicit integer adjudication."""

    def __init__(self, attribute_id: str, exact_median: str) -> None:
        self.attribute_id = attribute_id
        self.exact_median = exact_median
        super().__init__(f"{attribute_id} exact median {exact_median} requires adjudication")


class AdjudicatedLabelExport(StrictContract):
    """Complete immutable accepted-set aggregate, distinct from every predecessor."""

    schema_version: Literal["itda.phase3-adjudicated-label-export.v1"] = (
        "itda.phase3-adjudicated-label-export.v1"
    )
    assignment_id: StableId
    rubric_version: Version
    source_snapshot_version: Version
    accepted_selections: tuple[
        AcceptedRevisionSelection, AcceptedRevisionSelection, AcceptedRevisionSelection
    ]
    accepted_revision_set_sha256: Sha256
    review_triggers: tuple[ReviewTrigger, ...]
    resolved_review_trigger_sha256s: tuple[Sha256, ...] = ()
    aggregates: tuple[
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
        LabelAggregate,
    ]
    adjudication_sha256: Sha256 | None = None
    export_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_export(self) -> Self:
        if tuple(item.attribute_id for item in self.aggregates) != tuple(SubattributeId):
            raise ValueError("label aggregates must use canonical H1-R4 order")
        if tuple(sorted(self.resolved_review_trigger_sha256s)) != (
            self.resolved_review_trigger_sha256s
        ) or len(set(self.resolved_review_trigger_sha256s)) != len(
            self.resolved_review_trigger_sha256s
        ):
            raise ValueError("resolved review trigger digests must use unique canonical order")
        expected_set = canonical_sha256(
            [
                selection.model_dump(mode="json")
                for selection in sorted(
                    self.accepted_selections, key=lambda item: item.evaluator_pseudonym
                )
            ]
        )
        if self.accepted_revision_set_sha256 != expected_set:
            raise ValueError("accepted revision set sha256 is stale")
        trigger_sha256s = {
            cast(str, trigger.review_trigger_sha256) for trigger in self.review_triggers
        }
        if not set(self.resolved_review_trigger_sha256s) <= trigger_sha256s:
            raise ValueError("resolved review trigger digest is absent from the export")
        expected = canonical_sha256(self.model_dump(exclude={"export_sha256"}, mode="json"))
        if self.export_sha256 is None:
            object.__setattr__(self, "export_sha256", expected)
        elif self.export_sha256 != expected:
            raise ValueError("adjudicated label export sha256 is stale")
        return self

    @property
    def unresolved_review_trigger_sha256s(self) -> tuple[str, ...]:
        resolved = frozenset(self.resolved_review_trigger_sha256s)
        return tuple(
            cast(str, trigger.review_trigger_sha256)
            for trigger in self.review_triggers
            if trigger.review_trigger_sha256 not in resolved
        )

    def value_for(self, attribute_id: str | SubattributeId) -> int:
        requested = SubattributeId(attribute_id)
        return next(item.value for item in self.aggregates if item.attribute_id is requested)

    def aggregation_kind_for(self, attribute_id: str | SubattributeId) -> str:
        requested = SubattributeId(attribute_id)
        return next(
            item.aggregation_kind for item in self.aggregates if item.attribute_id is requested
        )


def derive_review_triggers(revisions: tuple[RawLabelRevision, ...]) -> tuple[ReviewTrigger, ...]:
    """Derive the closed, deterministic Phase 3 review-trigger set."""

    triggers: list[ReviewTrigger] = []
    for attribute_id in SubattributeId:
        judgments = tuple(
            next(item for item in revision.judgments if item.attribute_id is attribute_id)
            for revision in revisions
        )
        values = tuple(sorted(item.score for item in judgments if item.score is not None))
        if values and values[-1] - values[0] >= 2:
            triggers.append(
                ReviewTrigger(
                    kind=ReviewTriggerKind.ATTRIBUTE_RANGE_AT_LEAST_TWO,
                    attribute_id=attribute_id,
                    observed_numeric_values=values,
                )
            )
        if any(
            item.score in {3, 4} and not any(evidence.direct for evidence in item.evidence)
            for item in judgments
        ):
            triggers.append(
                ReviewTrigger(
                    kind=ReviewTriggerKind.REQUIRED_EVIDENCE_MISSING,
                    attribute_id=attribute_id,
                    observed_numeric_values=values,
                )
            )

    axes = tuple(revision.primary_axis for revision in revisions)
    if len(axes) == 3 and None not in axes and len(set(axes)) == 3:
        triggers.append(ReviewTrigger(kind=ReviewTriggerKind.ALL_PRIMARY_AXES_DIFFER))
    elif any(axis is None for axis in axes):
        triggers.append(ReviewTrigger(kind=ReviewTriggerKind.PRIMARY_AXIS_MISSING))
    return tuple(triggers)


def aggregate_accepted_revisions(
    revisions: tuple[RawLabelRevision, ...],
    accepted_selections: tuple[AcceptedRevisionSelection, ...],
    *,
    adjudications: tuple[AdjudicatedAttributeValue, ...] = (),
    resolved_review_trigger_sha256s: tuple[str, ...] = (),
    persisted_revision_sha256s: Mapping[str, str] | None = None,
) -> AdjudicatedLabelExport:
    """Aggregate exactly three current accepted revisions without rewriting inputs."""

    if len(revisions) != 3 or len(accepted_selections) != 3:
        raise LabelExportBlocked("all three evaluator roles must have accepted submissions")
    if len({revision.evaluator_pseudonym for revision in revisions}) != 3:
        raise LabelExportBlocked("all three evaluator roles must be distinct")
    if len({selection.evaluator_pseudonym for selection in accepted_selections}) != 3:
        raise LabelExportBlocked("all three accepted evaluator roles must be distinct")
    assignment_ids = {revision.assignment_id for revision in revisions}
    rubric_versions = {revision.rubric_version for revision in revisions}
    source_versions = {revision.source_snapshot_version for revision in revisions}
    if len(assignment_ids) != 1 or len(rubric_versions) != 1 or len(source_versions) != 1:
        raise LabelExportBlocked(
            "accepted revisions must share assignment, rubric, and source lineage"
        )

    revisions_by_evaluator = {revision.evaluator_pseudonym: revision for revision in revisions}
    selections_by_evaluator = {
        selection.evaluator_pseudonym: selection for selection in accepted_selections
    }
    if set(revisions_by_evaluator) != set(selections_by_evaluator):
        raise LabelExportBlocked("accepted selections do not cover the exact evaluator set")
    revision_digests = persisted_revision_sha256s or {
        evaluator: revision.revision_sha256
        for evaluator, revision in revisions_by_evaluator.items()
    }
    if set(revision_digests) != set(revisions_by_evaluator):
        raise LabelExportBlocked("persisted revision digests do not cover the evaluator set")
    for evaluator, revision in revisions_by_evaluator.items():
        selection = selections_by_evaluator[evaluator]
        if (
            selection.assignment_id != revision.assignment_id
            or selection.accepted_revision_sha256 != revision_digests[evaluator]
        ):
            raise LabelExportBlocked("accepted selection is stale or names the wrong revision")

    adjudication_by_attribute: dict[SubattributeId, AdjudicatedAttributeValue] = {}
    for supplied_adjudication in adjudications:
        if supplied_adjudication.attribute_id in adjudication_by_attribute:
            raise LabelExportBlocked("duplicate attribute adjudication")
        adjudication_by_attribute[supplied_adjudication.attribute_id] = supplied_adjudication

    ordered_revisions = tuple(sorted(revisions, key=lambda revision: revision.evaluator_pseudonym))
    aggregates: list[LabelAggregate] = []
    used_adjudications: list[AdjudicatedAttributeValue] = []
    for attribute_id in SubattributeId:
        accepted_values = tuple(
            AcceptedEvaluatorValue(
                evaluator_pseudonym=revision.evaluator_pseudonym,
                accepted_revision_sha256=revision_digests[revision.evaluator_pseudonym],
                score=(
                    judgment := next(
                        item for item in revision.judgments if item.attribute_id is attribute_id
                    )
                ).score,
                unknown_reason=judgment.unknown_reason,
                unknown_note=judgment.unknown_note,
            )
            for revision in ordered_revisions
        )
        numeric_values = tuple(
            sorted(item.score for item in accepted_values if item.score is not None)
        )
        if len(numeric_values) < 2:
            raise LabelExportBlocked(f"{attribute_id.value} requires at least two numeric scores")
        exact = (
            Fraction(numeric_values[1], 1)
            if len(numeric_values) == 3
            else Fraction(numeric_values[0] + numeric_values[1], 2)
        )
        exact_text = (
            str(exact.numerator)
            if exact.denominator == 1
            else f"{exact.numerator // exact.denominator}.5"
        )
        adjudication = adjudication_by_attribute.get(attribute_id)
        if exact.denominator == 1:
            if adjudication is not None:
                raise LabelExportBlocked(
                    f"{attribute_id.value} exact integer median forbids adjudication"
                )
            aggregate = LabelAggregate(
                attribute_id=attribute_id,
                accepted_values=cast(
                    tuple[AcceptedEvaluatorValue, AcceptedEvaluatorValue, AcceptedEvaluatorValue],
                    accepted_values,
                ),
                numeric_values=numeric_values,
                exact_median=exact_text,
                value=exact.numerator,
                aggregation_kind="EXACT_MEDIAN",
            )
        else:
            if adjudication is None:
                raise AdjudicationRequired(attribute_id.value, exact_text)
            if adjudication.exact_median != exact_text:
                raise LabelExportBlocked("attribute adjudication exact median is stale")
            used_adjudications.append(adjudication)
            aggregate = LabelAggregate(
                attribute_id=attribute_id,
                accepted_values=cast(
                    tuple[AcceptedEvaluatorValue, AcceptedEvaluatorValue, AcceptedEvaluatorValue],
                    accepted_values,
                ),
                numeric_values=numeric_values,
                exact_median=exact_text,
                value=adjudication.adjudicated_value,
                aggregation_kind="ADJUDICATED",
                adjudication_sha256=adjudication.adjudication_sha256,
            )
        aggregates.append(aggregate)

    unused = set(adjudication_by_attribute) - {
        adjudication.attribute_id for adjudication in used_adjudications
    }
    if unused:
        raise LabelExportBlocked("attribute adjudication does not match a half-step median")
    ordered_selections = tuple(
        sorted(accepted_selections, key=lambda selection: selection.evaluator_pseudonym)
    )
    accepted_revision_set_sha256 = canonical_sha256(
        [selection.model_dump(mode="json") for selection in ordered_selections]
    )
    triggers = derive_review_triggers(revisions)
    adjudication_sha256 = (
        canonical_sha256(
            [
                cast(str, adjudication.adjudication_sha256)
                for adjudication in sorted(
                    used_adjudications, key=lambda item: item.attribute_id.value
                )
            ]
        )
        if used_adjudications
        else None
    )
    return AdjudicatedLabelExport(
        assignment_id=next(iter(assignment_ids)),
        rubric_version=next(iter(rubric_versions)),
        source_snapshot_version=next(iter(source_versions)),
        accepted_selections=cast(
            tuple[
                AcceptedRevisionSelection,
                AcceptedRevisionSelection,
                AcceptedRevisionSelection,
            ],
            ordered_selections,
        ),
        accepted_revision_set_sha256=accepted_revision_set_sha256,
        review_triggers=triggers,
        resolved_review_trigger_sha256s=tuple(sorted(resolved_review_trigger_sha256s)),
        aggregates=cast(
            tuple[
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
                LabelAggregate,
            ],
            tuple(aggregates),
        ),
        adjudication_sha256=adjudication_sha256,
    )


__all__ = [
    "AcceptedEvaluatorValue",
    "AcceptedRevisionSelection",
    "AdjudicationOfficialSource",
    "AdjudicationProjection",
    "AdjudicatedAttributeValue",
    "AdjudicatedLabelExport",
    "AdjudicationRequired",
    "AdjudicationSourceManifest",
    "AdjudicatorAcceptedHead",
    "AdjudicatorRawRevision",
    "AdjudicatorRevisionChain",
    "AttributeJudgment",
    "EvidenceReference",
    "LABEL_RUBRIC_SPECS",
    "LabelAggregate",
    "LabelExportBlocked",
    "LabelRubric",
    "PrimaryAxis",
    "RawLabelRevision",
    "ReviewReason",
    "ReviewTrigger",
    "ReviewTriggerKind",
    "ReviewTriggerResolution",
    "RevisionReceipt",
    "RubricAnchor",
    "SCORE_ANCHORS",
    "SUBATTRIBUTE_SPECS",
    "UnknownReason",
    "aggregate_accepted_revisions",
    "derive_review_triggers",
]
