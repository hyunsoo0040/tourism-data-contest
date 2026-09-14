"""Typed source receipts and judgments for the new construct, without legacy aliases."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field, model_validator

from itda.authenticity.quotes import QuoteMatch
from itda.authenticity.rubric import (
    AUTHORITY_VERSION,
    CONSTRUCT_VERSION,
    FACET_KEYS,
    RUBRIC_SHA256,
    Axis,
    FacetKey,
)
from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256

Level = Annotated[int, Field(strict=True, ge=0, le=4)]
Score = Annotated[int, Field(strict=True, ge=0, le=100)]


class Claim(StrEnum):
    HERITAGE_FACT = "HERITAGE_FACT"
    HISTORICAL_NARRATIVE = "HISTORICAL_NARRATIVE"
    LIVING_TRADITION = "LIVING_TRADITION"
    HERITAGE_INTERPRETATION = "HERITAGE_INTERPRETATION"
    REPRESENTED_MEANING = "REPRESENTED_MEANING"
    MEDIA_REPRESENTATION = "MEDIA_REPRESENTATION"
    VISUAL_EXPRESSION = "VISUAL_EXPRESSION"
    IMAGE_ENACTMENT = "IMAGE_ENACTMENT"
    AUTONOMOUS_ACTIVITY = "AUTONOMOUS_ACTIVITY"
    ENVIRONMENT = "ENVIRONMENT"
    PARTICIPATORY_ACTIVITY = "PARTICIPATORY_ACTIVITY"
    RELATIONAL_ACTIVITY = "RELATIONAL_ACTIVITY"
    VISUAL_APPEARANCE = "VISUAL_APPEARANCE"
    SOCIAL_CIRCULATION = "SOCIAL_CIRCULATION"


class Receipt(StrictContract):
    schema_version: Literal["authenticity-receipt.v1"] = "authenticity-receipt.v1"
    provider: Literal["KorService2", "Odii", "PhotoGalleryService1", "APIFY_INSTAGRAM"]
    operation: str = Field(min_length=1, max_length=160)
    provider_record_id: str = Field(min_length=1, max_length=240)
    retrieved_at: datetime
    source_modified_at: datetime | None = None
    request_sha256: Sha256
    response_sha256: Sha256
    source_record_sha256: Sha256
    source_uri: str | None = Field(default=None, max_length=2000)
    actor_id: str | None = None
    actor_build_id: str | None = None
    actor_run_id: str | None = None

    @model_validator(mode="after")
    def authority(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        if self.source_modified_at is not None:
            require_utc(self.source_modified_at, field_name="source_modified_at")
        actor = (self.actor_id, self.actor_build_id, self.actor_run_id)
        if self.provider == "APIFY_INSTAGRAM" and not all(actor):
            raise ValueError("SOCIAL_RECEIPT_REQUIRES_ACTOR_LINEAGE")
        if self.provider != "APIFY_INSTAGRAM" and any(actor):
            raise ValueError("OFFICIAL_RECEIPT_CANNOT_CLAIM_ACTOR")
        if self.source_uri is not None:
            url = urlsplit(self.source_uri)
            if url.scheme not in {"http", "https"} or url.username or url.password:
                raise ValueError("INVALID_SOURCE_URI")
            if any(
                word in key.casefold().replace("_", "")
                for key, _ in parse_qsl(url.query)
                for word in ("token", "apikey", "servicekey", "secret", "authorization")
            ):
                raise ValueError("SOURCE_URI_CONTAINS_CREDENTIAL_PARAMETER")
        return self


class Appearance(StrictContract):
    key: Literal["visual_character", "natural_setting", "traditional_appearance"]
    state: Literal["OBSERVED", "UNKNOWN"]
    level: Level | None
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def known(self) -> Self:
        if (self.state == "UNKNOWN") != (self.level is None):
            raise ValueError("APPEARANCE_UNKNOWN_MUST_BE_NULL")
        return self


class Evidence(StrictContract):
    schema_version: Literal["authenticity-evidence.v1"] = "authenticity-evidence.v1"
    evidence_id: StableId
    place_id: StableId
    modality: Literal["TEXT", "IMAGE", "COUNT"]
    state: Literal["AVAILABLE", "EMPTY_CONFIRMED", "UNAVAILABLE", "AMBIGUOUS", "STALE"]
    receipt: Receipt
    place_match: Literal["VERIFIED", "AMBIGUOUS", "NOT_MATCHED"]
    match_basis: tuple[str, ...]
    source_role: Literal[
        "OFFICIAL_DESCRIPTION",
        "OFFICIAL_NARRATIVE",
        "OFFICIAL_PHOTO",
        "OFFICIAL_PROMOTION",
        "ADVERTISEMENT",
        "VISITOR_POST",
        "UNCLASSIFIED",
    ]
    field: str = Field(min_length=1, max_length=100)
    text: str | None = Field(default=None, max_length=8000)
    image_sha256: Sha256 | None = None
    image_license: Literal["KOGL_TYPE_1"] | None = None
    appearance: Appearance | None = None
    reported_count: Annotated[int, Field(strict=True, ge=0)] | None = None
    reported_count_raw: str | None = None
    primary_tag: str | None = None
    record_sha256: Sha256

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.place_match == "VERIFIED" and not self.match_basis:
            raise ValueError("VERIFIED_PLACE_REQUIRES_MATCH_EVIDENCE")
        if self.modality == "TEXT":
            if self.state == "AVAILABLE" and not self.text:
                raise ValueError("AVAILABLE_TEXT_IS_EMPTY")
            if (
                self.image_sha256
                or self.image_license
                or self.appearance
                or self.reported_count is not None
            ):
                raise ValueError("TEXT_CANNOT_CLAIM_PIXELS_OR_COUNTS")
        elif self.modality == "IMAGE":
            if self.receipt.provider not in {"KorService2", "PhotoGalleryService1"}:
                raise ValueError("UNLICENSED_PIXEL_SOURCE")
            if not self.image_sha256 or self.image_license is None or self.appearance is None:
                raise ValueError("IMAGE_REQUIRES_LICENSE_HASH_AND_OBSERVATION")
            if self.text is not None or self.reported_count is not None:
                raise ValueError("IMAGE_CANNOT_CLAIM_TEXT_OR_COUNT")
        else:
            if self.receipt.provider != "APIFY_INSTAGRAM":
                raise ValueError("COUNT_REQUIRES_SOCIAL_RECEIPT")
            if not self.primary_tag:
                raise ValueError("COUNT_REQUIRES_PRIMARY_TAG")
            if (self.state == "AVAILABLE") != (self.reported_count is not None):
                raise ValueError("MISSING_SOCIAL_COUNT_CANNOT_BECOME_ZERO")
            if self.image_sha256 or self.image_license or self.appearance or self.text is not None:
                raise ValueError("COUNT_CANNOT_CLAIM_TEXT_OR_PIXELS")
        if self.record_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"record_sha256"})
        ):
            raise ValueError("EVIDENCE_DIGEST_MISMATCH")
        return self


class Place(StrictContract):
    place_id: StableId
    name_ko: str = Field(min_length=1, max_length=240)
    address: str
    region_code: str = Field(min_length=2, max_length=10)
    region_name: str
    category: Literal["관광지", "문화시설", "레포츠"]
    duplicate_group_id: StableId
    provider_content_id: str
    cohort: Literal["initial", "additional", "new-evaluation", "synthetic"]


class SourceBundle(StrictContract):
    schema_version: Literal["authenticity-source.v1"] = "authenticity-source.v1"
    place: Place
    evidence: tuple[Evidence, ...]
    parent_source_sha256: Sha256
    bundle_sha256: Sha256

    @model_validator(mode="after")
    def bindings(self) -> Self:
        ids = tuple(e.evidence_id for e in self.evidence)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("SOURCE_IDS_MUST_BE_CANONICAL")
        if any(e.place_id != self.place.place_id for e in self.evidence):
            raise ValueError("EVIDENCE_PLACE_MISMATCH")
        if self.bundle_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"bundle_sha256"})
        ):
            raise ValueError("SOURCE_BUNDLE_DIGEST_MISMATCH")
        return self


class Citation(StrictContract):
    evidence_id: StableId
    claim: Claim
    quote: str = Field(min_length=4, max_length=2000)


class Judgment(StrictContract):
    key: FacetKey
    state: Literal["SUPPORTED", "UNKNOWN"]
    level: Level | None
    basis: Literal["DIRECT_SUPPORT", "EXPLICIT_LOW", "INSUFFICIENT"]
    subject: Literal["THIS_PLACE", "OTHER_SUBJECT", "UNRESOLVED"]
    citations: tuple[Citation, ...] = Field(max_length=8)
    reason: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def support(self) -> Self:
        if self.state == "UNKNOWN":
            if self.level is not None or self.citations or self.basis != "INSUFFICIENT":
                raise ValueError("UNKNOWN_IS_NOT_LOW_OR_CITED")
        else:
            if self.level is None or not self.citations or self.basis == "INSUFFICIENT":
                raise ValueError("SUPPORTED_REQUIRES_DIRECT_EVIDENCE")
            if self.subject != "THIS_PLACE":
                raise ValueError("JUDGMENT_SUBJECT_MISMATCH")
            if self.level == 0 and self.basis != "EXPLICIT_LOW":
                raise ValueError("ZERO_REQUIRES_EXPLICIT_LOW_EVIDENCE")
        if len({(c.evidence_id, c.quote, c.claim) for c in self.citations}) != len(self.citations):
            raise ValueError("DUPLICATED_CITATION")
        return self


class TextWire(StrictContract):
    judgments: tuple[Judgment, ...] = Field(min_length=12, max_length=12)

    @model_validator(mode="after")
    def vocabulary(self) -> Self:
        if {j.key for j in self.judgments} != set(FACET_KEYS):
            raise ValueError("EXACT_FACET_MEMBERSHIP_REQUIRED")
        return self


class BoundCitation(StrictContract):
    evidence_id: StableId
    record_sha256: Sha256
    claim: Claim
    quote: QuoteMatch


class Rejection(StrictContract):
    key: FacetKey | None
    code: str
    reason: str
    proposed: dict[str, object]


class BoundJudgment(StrictContract):
    key: FacetKey
    state: Literal["SUPPORTED", "UNKNOWN", "REJECTED"]
    level: Level | None
    citations: tuple[BoundCitation, ...]
    reason: str
    flags: tuple[str, ...] = ()

    @model_validator(mode="after")
    def support(self) -> Self:
        if self.state == "SUPPORTED" and (self.level is None or not self.citations):
            raise ValueError("BOUND_SUPPORT_REQUIRES_CITATIONS")
        if self.state != "SUPPORTED" and (self.level is not None or self.citations):
            raise ValueError("UNSUPPORTED_BOUND_JUDGMENT_CANNOT_SCORE")
        return self


class Policy(StrictContract):
    version: Literal["authenticity-aggregation-v1"] = "authenticity-aggregation-v1"
    construct_version: Literal["authenticity-construct-v1"] = CONSTRUCT_VERSION
    authority_version: Literal["authenticity-authority-v1"] = AUTHORITY_VERSION
    rubric_sha256: Sha256 = RUBRIC_SHA256
    photo_mode: Literal["NONE", "ER", "HER_CONDITIONAL"] = "NONE"
    photo_share_bp: int = Field(default=2500, strict=True, ge=0, le=3500)
    social_mode: Literal["NONE", "COUNT", "COUNT_AND_MEANING"] = "NONE"
    social_share_bp: int = Field(default=1000, strict=True, ge=0, le=1500)
    social_log_ceiling: int = Field(default=1000000, strict=True, ge=100, le=100000000)
    minimum_facets: int = Field(default=2, strict=True, ge=2, le=4)
    publication_status: Literal["EXPERIMENTAL"] = "EXPERIMENTAL"

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.rubric_sha256 != RUBRIC_SHA256:
            raise ValueError("POLICY_RUBRIC_MISMATCH")
        return self

    @property
    def policy_sha256(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class Contribution(StrictContract):
    channel: Literal["TEXT", "PHOTO", "SOCIAL"]
    value: Score
    weight_bp: int = Field(strict=True, ge=0, le=10000)
    evidence_ids: tuple[StableId, ...]
    rule: str


class FacetScore(StrictContract):
    key: FacetKey
    value: Score | None
    contributions: tuple[Contribution, ...]
    missing_channels: tuple[Literal["TEXT", "PHOTO", "SOCIAL"], ...]
    reason: str


class AxisScore(StrictContract):
    axis: Axis
    value: Score | None
    supported_facets: tuple[FacetKey, ...]
    missing_facets: tuple[FacetKey, ...]
    core_satisfied: bool
    reason: str


class Assessment(StrictContract):
    schema_version: Literal["authenticity-assessment.v1"] = "authenticity-assessment.v1"
    source: SourceBundle
    policy: Policy
    judgments: tuple[BoundJudgment, ...]
    rejections: tuple[Rejection, ...]
    facets: tuple[FacetScore, ...]
    axes: tuple[AxisScore, ...]
    model_request_sha256: Sha256 | None
    assessed_at: datetime
    assessment_sha256: Sha256

    @model_validator(mode="after")
    def identity(self) -> Self:
        require_utc(self.assessed_at, field_name="assessed_at")
        if tuple(j.key for j in self.judgments) != FACET_KEYS:
            raise ValueError("ASSESSMENT_JUDGMENT_MEMBERSHIP_MISMATCH")
        if tuple(f.key for f in self.facets) != FACET_KEYS:
            raise ValueError("ASSESSMENT_FACET_MEMBERSHIP_MISMATCH")
        if tuple(a.axis for a in self.axes) != ("H", "E", "R"):
            raise ValueError("ASSESSMENT_AXIS_MEMBERSHIP_MISMATCH")
        if self.assessment_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"assessment_sha256"})
        ):
            raise ValueError("ASSESSMENT_DIGEST_MISMATCH")
        return self
