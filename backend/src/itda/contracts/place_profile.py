"""Canonical place-profile vocabulary and assessment contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, model_validator

from itda.contracts.base import (
    AssessmentStatus,
    Confidence,
    DataSplit,
    ExperienceAxis,
    Score100,
    Sha256,
    StableId,
    StrictContract,
    Version,
    require_utc,
)
from itda.contracts.provenance import EvidenceReference, SourceIdentity


class SubattributeId(StrEnum):
    H1 = "H1"
    H2 = "H2"
    H3 = "H3"
    H4 = "H4"
    I1 = "I1"
    I2 = "I2"
    I3 = "I3"
    I4 = "I4"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class MismatchTraitId(StrEnum):
    M1 = "M1"
    M2 = "M2"
    M3 = "M3"
    M4 = "M4"
    M5 = "M5"
    M6 = "M6"


class SubattributeSpec(StrictContract):
    attribute_id: SubattributeId
    axis: ExperienceAxis
    label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    definition_ko: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    scale_min: Literal[0] = 0
    scale_max: Literal[4] = 4


class MismatchTraitSpec(StrictContract):
    trait_id: MismatchTraitId
    label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    left_endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    right_endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=120)]
    scale_kind: Literal["BIPOLAR"] = "BIPOLAR"


SUBATTRIBUTE_SPECS = (
    SubattributeSpec(
        attribute_id=SubattributeId.H1,
        axis=ExperienceAxis.HISTORY_TRADITION,
        label_ko="역사 서사 밀도",
        definition_ko="시대·인물·사건·유래·설화의 풍부성",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.H2,
        axis=ExperienceAxis.HISTORY_TRADITION,
        label_ko="문화유산·원형 기반성",
        definition_ko="유적·전통 건축·보존 흔적·문화유산이 장소의 중심인지",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.H3,
        axis=ExperienceAxis.HISTORY_TRADITION,
        label_ko="전통의 지속성",
        definition_ko="전통생활·의례·공예·지역문화가 현재 경험과 연결되는지",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.H4,
        axis=ExperienceAxis.HISTORY_TRADITION,
        label_ko="학습·해설 깊이",
        definition_ko="전시·해설·오디오가이드·교육 탐색 요소",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.I1,
        axis=ExperienceAxis.EMOTION_IMAGE,
        label_ko="시각적 상징성",
        definition_ko="랜드마크·독특한 외관·기억되는 장면",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.I2,
        axis=ExperienceAxis.EMOTION_IMAGE,
        label_ko="사진·경관 매력",
        definition_ko="색감·야경·계절경관·구도·포토존",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.I3,
        axis=ExperienceAxis.EMOTION_IMAGE,
        label_ko="현대적 재해석",
        definition_ko="전통과 현대의 결합·감각적 공간·트렌드",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.I4,
        axis=ExperienceAxis.EMOTION_IMAGE,
        label_ko="분위기·감각 경험",
        definition_ko="빛·색·공간연출·거리 분위기",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.R1,
        axis=ExperienceAxis.REST_IMMERSION,
        label_ko="자연·회복 환경",
        definition_ko="숲·물·해변·정원 등 회복 요소",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.R2,
        axis=ExperienceAxis.REST_IMMERSION,
        label_ko="산책·체류 적합성",
        definition_ko="천천히 걷기·오래 머무르기",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.R3,
        axis=ExperienceAxis.REST_IMMERSION,
        label_ko="정적·저자극 가능성",
        definition_ko="조용함·여유·혼자 머물기",
    ),
    SubattributeSpec(
        attribute_id=SubattributeId.R4,
        axis=ExperienceAxis.REST_IMMERSION,
        label_ko="참여·몰입 경험",
        definition_ko="체험·감상·탐방·이야기 몰입",
    ),
)

MISMATCH_TRAIT_SPECS = (
    MismatchTraitSpec(
        trait_id=MismatchTraitId.M1,
        label_ko="공간 성격",
        left_endpoint="원형·보존 중심",
        right_endpoint="현대적 재해석 중심",
    ),
    MismatchTraitSpec(
        trait_id=MismatchTraitId.M2,
        label_ko="방문객 성격",
        left_endpoint="생활·로컬 중심",
        right_endpoint="관광·상업 중심",
    ),
    MismatchTraitSpec(
        trait_id=MismatchTraitId.M3,
        label_ko="현장 밀도",
        left_endpoint="한적함",
        right_endpoint="혼잡함",
    ),
    MismatchTraitSpec(
        trait_id=MismatchTraitId.M4,
        label_ko="경험 방식",
        left_endpoint="감상·촬영",
        right_endpoint="참여·체험",
    ),
    MismatchTraitSpec(
        trait_id=MismatchTraitId.M5,
        label_ko="체류 방식",
        left_endpoint="짧은 관람",
        right_endpoint="산책·장시간 체류",
    ),
    MismatchTraitSpec(
        trait_id=MismatchTraitId.M6,
        label_ko="시간 의존성",
        left_endpoint="시간 영향 적음",
        right_endpoint="야간·계절·특정 시간 의존",
    ),
)

_SUBATTRIBUTE_BY_ID = {spec.attribute_id: spec for spec in SUBATTRIBUTE_SPECS}
_MISMATCH_BY_ID = {spec.trait_id: spec for spec in MISMATCH_TRAIT_SPECS}


class AxisPlaceScore(StrictContract):
    axis: ExperienceAxis
    assessment_status: AssessmentStatus
    score: Score100 | None
    confidence: Confidence | None
    display_label_id: StableId
    display_label_ko: Annotated[str, Field(strict=True, min_length=1, max_length=100)]
    evidence_ids: tuple[StableId, ...]

    @model_validator(mode="after")
    def status_matches_values(self) -> AxisPlaceScore:
        if self.assessment_status is AssessmentStatus.SCORED:
            if self.score is None or self.confidence is None:
                raise ValueError("SCORED axis requires score and confidence")
        elif self.score is not None or self.confidence is not None:
            raise ValueError("NOT_SCORED axis requires null score and confidence")
        return self


class SubattributeAssessment(SubattributeSpec):
    assessment_status: AssessmentStatus
    value: Annotated[int, Field(strict=True, ge=0, le=4)] | None
    evidence_ids: tuple[StableId, ...]

    @model_validator(mode="after")
    def canonical_and_status_invariants(self) -> SubattributeAssessment:
        canonical = _SUBATTRIBUTE_BY_ID[self.attribute_id]
        actual_metadata = (
            self.axis,
            self.label_ko,
            self.definition_ko,
            self.scale_min,
            self.scale_max,
        )
        expected_metadata = (
            canonical.axis,
            canonical.label_ko,
            canonical.definition_ko,
            canonical.scale_min,
            canonical.scale_max,
        )
        if actual_metadata != expected_metadata:
            raise ValueError("canonical subattribute metadata does not match attribute_id")
        if self.assessment_status is AssessmentStatus.SCORED and self.value is None:
            raise ValueError("SCORED subattribute requires a value")
        if self.assessment_status is AssessmentStatus.NOT_SCORED and self.value is not None:
            raise ValueError("NOT_SCORED subattribute requires a null value")
        return self


class MismatchTraitAssessment(MismatchTraitSpec):
    assessment_status: AssessmentStatus
    value: Score100 | None
    evidence_ids: tuple[StableId, ...]

    @model_validator(mode="after")
    def canonical_and_status_invariants(self) -> MismatchTraitAssessment:
        canonical = _MISMATCH_BY_ID[self.trait_id]
        actual_metadata = (
            self.label_ko,
            self.left_endpoint,
            self.right_endpoint,
            self.scale_kind,
        )
        expected_metadata = (
            canonical.label_ko,
            canonical.left_endpoint,
            canonical.right_endpoint,
            canonical.scale_kind,
        )
        if actual_metadata != expected_metadata:
            raise ValueError("canonical mismatch trait metadata does not match trait_id")
        if self.assessment_status is AssessmentStatus.SCORED and self.value is None:
            raise ValueError("SCORED mismatch trait requires a value")
        if self.assessment_status is AssessmentStatus.NOT_SCORED and self.value is not None:
            raise ValueError("NOT_SCORED mismatch trait requires a null value")
        return self


class PlaceProfile(StrictContract):
    place_id: StableId
    split: DataSplit
    source_crosswalk: Annotated[tuple[SourceIdentity, ...], Field(min_length=1)]
    axis_scores: tuple[AxisPlaceScore, AxisPlaceScore, AxisPlaceScore]
    subattributes: tuple[
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
        SubattributeAssessment,
    ]
    mismatch_traits: tuple[
        MismatchTraitAssessment,
        MismatchTraitAssessment,
        MismatchTraitAssessment,
        MismatchTraitAssessment,
        MismatchTraitAssessment,
        MismatchTraitAssessment,
    ]
    overall_confidence: Confidence | None
    recommendation_eligible: StrictBool
    evidence: tuple[EvidenceReference, ...]
    schema_version: Version
    questionnaire_version: Version
    scoring_version: Version
    config_hash: Sha256
    data_version: Version
    release_version: Version
    source_version: Version
    display_copy_version: Version
    created_at: datetime

    @model_validator(mode="after")
    def profile_invariants(self) -> PlaceProfile:
        require_utc(self.created_at, field_name="created_at")

        if tuple(score.axis for score in self.axis_scores) != tuple(ExperienceAxis):
            raise ValueError("axis_scores must use canonical H-E-R order")
        if tuple(item.attribute_id for item in self.subattributes) != tuple(SubattributeId):
            raise ValueError("subattributes must use canonical H1-R4 order")
        if tuple(item.trait_id for item in self.mismatch_traits) != tuple(MismatchTraitId):
            raise ValueError("mismatch_traits must use canonical M1-M6 order")

        scored_items = [
            item
            for item in (*self.axis_scores, *self.subattributes, *self.mismatch_traits)
            if item.assessment_status is AssessmentStatus.SCORED
        ]
        if scored_items and self.overall_confidence is None:
            raise ValueError("scored profiles require overall_confidence")
        if not scored_items and self.overall_confidence is not None:
            raise ValueError("unscored profiles require null overall_confidence")
        if self.recommendation_eligible and self.overall_confidence is None:
            raise ValueError("recommendation eligibility requires scored confidence")

        if self.split is DataSplit.PREVIEW:
            if scored_items:
                raise ValueError("PREVIEW profiles must remain NOT_SCORED")
            if self.recommendation_eligible:
                raise ValueError("PREVIEW profiles cannot be recommendation eligible")

        if self.split not in {DataSplit.PREVIEW, DataSplit.SYNTHETIC} and not self.evidence:
            raise ValueError("evidence is required outside PREVIEW or SYNTHETIC")

        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence ids must be unique")
        known_evidence_ids = set(evidence_ids)
        referenced_ids = {
            evidence_id
            for item in (*self.axis_scores, *self.subattributes, *self.mismatch_traits)
            for evidence_id in item.evidence_ids
        }
        unknown_ids = referenced_ids - known_evidence_ids
        if unknown_ids:
            raise ValueError(f"unknown evidence id: {sorted(unknown_ids)[0]}")

        crosswalk_keys = [
            (identity.provider, identity.source_id) for identity in self.source_crosswalk
        ]
        if len(crosswalk_keys) != len(set(crosswalk_keys)):
            raise ValueError("source crosswalk provider/id pairs must be unique")
        return self
