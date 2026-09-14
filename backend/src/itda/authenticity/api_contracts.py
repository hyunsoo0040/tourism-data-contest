"""Public API shapes shared with generated frontend types."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from itda.authenticity.contracts import AxisScore, FacetScore, Level, Score
from itda.authenticity.intent import Intent
from itda.authenticity.rubric import Axis, FacetKey
from itda.contracts.base import Sha256, StableId, StrictContract


class Choice(StrictContract):
    value: Level | None
    label: str


class Question(StrictContract):
    key: FacetKey
    text: str
    axis: Axis


class AxisDescription(StrictContract):
    label: str
    theory: str


class Definition(StrictContract):
    schema_version: Literal["authenticity-questionnaire-v1"] = "authenticity-questionnaire-v1"
    title: str
    description: str
    choices: tuple[Choice, ...]
    questions: tuple[Question, ...]
    axes: dict[Axis, AxisDescription]
    interpretation: str
    questionnaire_sha256: Sha256


class SessionCreated(StrictContract):
    session_id: str
    token: str
    expires_at: datetime


class Region(StrictContract):
    code: str
    name: str
    places: int


class ServiceInfo(StrictContract):
    release_sha256: Sha256 | None
    scope: str | None
    places: int
    regions: tuple[Region, ...]
    photo_enabled: bool


class CreateRun(StrictContract):
    profile_id: Sha256
    request_id: StableId


class VisualPart(StrictContract):
    dimension: str
    target: Score
    actual: Score | None
    fit: Score | None


class FitPart(StrictContract):
    facet: FacetKey
    importance: Level
    avoidance: Level
    desired_level: Level | None
    place_value: Score | None
    utility: Score | None
    weight: Level
    compared: bool
    visual_comparison: tuple[VisualPart, ...]
    evidence_ids: tuple[str, ...]
    rule: str


class Coverage(StrictContract):
    known_weight: int
    total_weight: int
    percent: Score


class ResultItem(StrictContract):
    place_id: str
    name_ko: str
    region_name: str
    category: str
    assessment_sha256: Sha256
    duplicate_group_id: str
    score: Score
    coverage: Coverage
    axes: dict[Axis, Score | None]
    components: tuple[FitPart, ...]
    warnings: tuple[str, ...]
    rank: int = Field(ge=1, le=5)


class Exclusion(StrictContract):
    place_id: str
    reason: str


class RunResult(StrictContract):
    schema_version: Literal["authenticity-recommendation-run.v1"]
    ranking_version: str
    request_id: str
    intent_sha256: Sha256
    profile_id: Sha256
    candidate_membership_sha256: Sha256
    assessment_set_sha256: Sha256
    policy_sha256: Sha256 | None
    visual_reference_sha256: Sha256
    requested_count: int
    result_count: int
    state: Literal["COMPLETE", "LIMITED", "EMPTY"]
    items: tuple[ResultItem, ...]
    exclusions: tuple[Exclusion, ...]
    eligible_count: int
    created_at: datetime
    validation_scope: str
    run_sha256: Sha256


class FacetQuote(StrictContract):
    facet: FacetKey
    quote: str
    truncated: bool = False


class EvidenceView(StrictContract):
    evidence_id: str
    provider: str
    role: str
    modality: str
    quote: str | None
    quote_truncated: bool = False
    facet_quotes: tuple[FacetQuote, ...] = ()
    excerpt: str | None
    uri: str | None
    retrieved_at: datetime
    reference_date: datetime | None
    image_sha256: Sha256 | None
    appearance: dict[str, Any] | None
    reported_count: int | None
    state: str


class Detail(StrictContract):
    item: ResultItem
    address: str
    axes: tuple[AxisScore, ...]
    facets: tuple[FacetScore, ...]
    evidence: tuple[EvidenceView, ...]
    photos: tuple[dict[str, str], ...]
    limitations: tuple[str, ...]


class Comparison(StrictContract):
    places: tuple[Detail, ...] = Field(max_length=3)


class SaveRequest(StrictContract):
    saved: bool


class SavedItem(StrictContract):
    run_sha256: Sha256
    place_id: str
    saved_at: datetime


class FeedbackRequest(StrictContract):
    request_id: StableId
    visited: bool = False
    expectations_met: dict[Axis, Level | None] = Field(default_factory=dict)
    note: str = Field(default="", max_length=500)


class FeedbackCreated(StrictContract):
    feedback_id: Sha256
    research_use: Literal[False] = False


class PhotoConfirmation(StrictContract):
    candidate_ids: tuple[Sha256, ...] = Field(max_length=24)


class SessionProfile(StrictContract):
    profile: Intent
