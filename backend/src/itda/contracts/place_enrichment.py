"""Source-scoped camping, walking and navigation context plus shared suitability."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.source_assessment import (
    ClaimKind,
    PlaceMatch,
    SourceObservation,
    SourceReceipt,
    SupportState,
)
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import CanonicalTourismPlace


class FacilityContext(Protocol):
    @property
    def place_id(self) -> str: ...

    @property
    def facts(self) -> Mapping[str, SourceObservation]: ...


def confirmed_facility_exclusions(
    contexts: Sequence[FacilityContext], requirements: Sequence[RequiredFacility]
) -> frozenset[str]:
    """Only explicit source-supported absence excludes; companion is not an input."""
    excluded = set()
    for context in contexts:
        for requirement in requirements:
            fact = context.facts.get(requirement.value)
            if (
                fact is not None
                and fact.claim == ClaimKind.FACILITY
                and fact.state == SupportState.FACT
                and fact.value is False
            ):
                excluded.add(context.place_id)
    return frozenset(excluded)


class EnrichmentContext(StrictContract):
    place_id: StableId
    state: Literal["AVAILABLE", "PARTIAL", "UNKNOWN"]
    reason: str
    source_snapshot_sha256: tuple[Sha256, ...]
    receipts: tuple[SourceReceipt, ...]
    retrieved_at: datetime
    expires_at: datetime
    context_sha256: Sha256

    @model_validator(mode="after")
    def verify_content(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        require_utc(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.retrieved_at:
            raise ValueError("enrichment source expiry must follow retrieval")
        if self.source_snapshot_sha256 != tuple(sorted(set(self.source_snapshot_sha256))):
            raise ValueError("source snapshot hashes must be unique and canonical")
        if self.context_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"context_sha256"})
        ):
            raise ValueError("enrichment context hash mismatch")
        return self


class CampingContext(EnrichmentContext):
    schema_version: Literal["camping-context.v1"] = "camping-context.v1"
    match: PlaceMatch
    facts: dict[str, SourceObservation]
    source_modified_date: date | None
    booking_url: str | None
    warning_ko: str = (
        "공식 등록 정보입니다. 예약 가능 수량이나 현재 입장·운영 여부를 "
        "실시간으로 확인한 정보가 아닙니다."
    )

    @model_validator(mode="after")
    def validate_facts(self) -> Self:
        if self.match.place_id != self.place_id:
            raise ValueError("camp match belongs to another canonical place")
        if self.match.service != "GoCamping" or any(
            receipt.service != "GoCamping" for receipt in self.receipts
        ):
            raise ValueError("camp context requires GoCamping evidence")
        for key, fact in self.facts.items():
            if fact.key != key or any(e.place_match != self.match for e in fact.evidence):
                raise ValueError("camp fact identity mismatch")
            if self.state == "UNKNOWN" and fact.state != SupportState.UNKNOWN:
                raise ValueError("unknown camp context cannot authorize facility facts")
        return self


class CuratedCourseCrosswalk(StrictContract):
    place_id: StableId
    course_id: StableId
    route_id: StableId
    review_sha256: Sha256
    evidence_ko: Annotated[str, Field(min_length=10, max_length=1000)]


class WalkingCourse(StrictContract):
    course_id: StableId
    route_id: StableId
    name_ko: str
    scope: Literal["COURSE"] = "COURSE"
    link_kind: Literal[
        "EXACT_CANONICAL_COURSE", "MENTIONED_ON_COURSE", "REGIONAL_COURSE", "VERIFIED_NEARBY_COURSE"
    ]
    state: Literal["AVAILABLE", "UNKNOWN"]
    reason: str
    distance_km: Annotated[Decimal, Field(gt=0)] | None
    duration_minutes: Annotated[int, Field(gt=0)] | None
    difficulty_code: Literal["1", "2", "3"] | None
    difficulty_label_ko: str | None
    unit_authority: Literal["DURUNUBI_MANUAL_4_1"] = "DURUNUBI_MANUAL_4_1"
    unit_authority_sha256: Literal[
        "2f164f46748a4f64b2d11b672f8001b9f844c6435449bc97e1ee1bfb5ed4ea08"
    ] = "2f164f46748a4f64b2d11b672f8001b9f844c6435449bc97e1ee1bfb5ed4ea08"
    exact_match_review_sha256: Sha256 | None = None
    source_modified_date: date | None
    source_field_values: dict[str, str]
    gpx_url: str | None
    geometry_sha256: Sha256 | None = None
    distance_from_place_meters: Annotated[float, Field(ge=0)] | None = None
    distance_method: Literal["LOCAL_PROJECTED_STRAIGHT_LINE"] = "LOCAL_PROJECTED_STRAIGHT_LINE"
    applies_to_place_walking_score: Literal[False] = False
    scope_label_ko: str

    @model_validator(mode="after")
    def validate_course(self) -> Self:
        if self.state == "UNKNOWN" and any(
            value is not None
            for value in (self.distance_km, self.duration_minutes, self.difficulty_code)
        ):
            raise ValueError("unknown course estimates must be null")
        if self.state == "AVAILABLE" and any(
            value is None
            for value in (self.distance_km, self.duration_minutes, self.difficulty_code)
        ):
            raise ValueError("course units must be fully validated")
        if self.link_kind == "VERIFIED_NEARBY_COURSE" and (
            self.geometry_sha256 is None or self.distance_from_place_meters is None
        ):
            raise ValueError("nearby route requires exact geometry and distance evidence")
        if (self.link_kind == "EXACT_CANONICAL_COURSE") != (
            self.exact_match_review_sha256 is not None
        ):
            raise ValueError("exact canonical course requires a curated review binding")
        return self


class WalkingContext(EnrichmentContext):
    schema_version: Literal["walking-context.v1"] = "walking-context.v1"
    courses: tuple[WalkingCourse, ...]
    warning_ko: str = (
        "거리·시간·난이도는 전체 걷기 코스의 공식 안내값입니다. "
        "이 관광지 한 곳의 체류시간·보행 부담이나 현장 통행 가능 여부를 뜻하지 않습니다."
    )


class RelatedCanonicalPlace(CanonicalTourismPlace):
    category: str
    duplicate_group_id: StableId


class RelatedSuggestion(StrictContract):
    place_id: StableId
    place_name_ko: str
    provider_entity_id: StableId
    source_provider_entity_id: StableId
    provider_rank: Annotated[int, Field(ge=1)]
    match_method: Literal["EXACT_NAME_AND_REGION"] = "EXACT_NAME_AND_REGION"
    relation_kind: Literal["NAVIGATION_ASSOCIATION"] = "NAVIGATION_ASSOCIATION"
    affinity_effect: Literal["NONE"] = "NONE"


class RelatedContext(EnrichmentContext):
    schema_version: Literal["related-destinations-context.v1"] = "related-destinations-context.v1"
    base_month: Annotated[str, Field(pattern=r"^\d{4}(0[1-9]|1[0-2])$")]
    suggestions: tuple[RelatedSuggestion, ...]
    eligibility_sha256: Sha256
    filtered_count: Annotated[int, Field(ge=0)]
    provider_result_code: str | None
    warning_ko: str = (
        "내비게이션 이용에 기반한 연관 방문 후보입니다. "
        "이 관계는 장소의 취향 점수나 인기도 가산점으로 사용하지 않습니다."
    )
