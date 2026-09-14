"""Source-cited publication eligibility, separate from frozen H/E/R assessment."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Self

from pydantic import Field, model_validator

from itda.authenticity.contracts import SourceBundle
from itda.contracts.base import Sha256, StableId, StrictContract
from itda.domain.canonical import canonical_sha256


class ScopeDecision(StrictContract):
    place_id: StableId
    source_bundle_sha256: Sha256
    decision: Literal[
        "INCLUDE_ACTIVITY", "EXCLUDE_ACCOMMODATION", "EXCLUDE_FOOD_SERVICE", "EXCLUDE_RETAIL"
    ]
    reason_ko: str = Field(min_length=1, max_length=1000)
    evidence_id: StableId
    quote: str = Field(min_length=1, max_length=2000)
    start: int = Field(strict=True, ge=0)
    end: int = Field(strict=True, ge=1)


class PublicationSelection(StrictContract):
    schema_version: Literal[
        "authenticity-publication-selection.v1",
        "authenticity-publication-selection.v2",
        "authenticity-publication-selection.v3",
    ] = "authenticity-publication-selection.v1"
    rule: Literal[
        "EXCLUDE_LODGING_PARENTS_RETAIN_SEPARATELY_IDENTIFIED_ACTIVITIES",
        "EXCLUDE_LODGING_AND_FOOD_SERVICE_RETAIN_EXPLICIT_SIGHTSEEING_OR_ACTIVITIES",
        "SIGHTSEEING_OR_SEPARATELY_USABLE_ACTIVITY_ONLY",
    ] = "EXCLUDE_LODGING_PARENTS_RETAIN_SEPARATELY_IDENTIFIED_ACTIVITIES"
    review_scope: Literal[
        "AI_SOURCE_REVIEW_OF_NAME_FLAGGED_RECORDS_NOT_EXHAUSTIVE",
        "AI_SOURCE_REVIEW_OF_NAME_OR_DESCRIPTION_FLAGGED_RECORDS_NOT_EXHAUSTIVE",
    ] = "AI_SOURCE_REVIEW_OF_NAME_FLAGGED_RECORDS_NOT_EXHAUSTIVE"
    parent_manifest_sha256: Sha256
    analyzed_place_ids: tuple[StableId, ...] = Field(min_length=1)
    decisions: tuple[ScopeDecision, ...]
    selection_sha256: Sha256

    @model_validator(mode="after")
    def identity(self) -> Self:
        old = self.schema_version == "authenticity-publication-selection.v1"
        expected_rule = {
            "v1": "EXCLUDE_LODGING_PARENTS_RETAIN_SEPARATELY_IDENTIFIED_ACTIVITIES",
            "v2": "EXCLUDE_LODGING_AND_FOOD_SERVICE_RETAIN_EXPLICIT_SIGHTSEEING_OR_ACTIVITIES",
            "v3": "SIGHTSEEING_OR_SEPARATELY_USABLE_ACTIVITY_ONLY",
        }[self.schema_version.rsplit(".", 1)[1]]
        current = self.schema_version == "authenticity-publication-selection.v3"
        if (
            self.rule != expected_rule
            or (old and any(d.decision == "EXCLUDE_FOOD_SERVICE" for d in self.decisions))
            or (not current and any(d.decision == "EXCLUDE_RETAIL" for d in self.decisions))
            or current
            != (
                self.review_scope
                == "AI_SOURCE_REVIEW_OF_NAME_OR_DESCRIPTION_FLAGGED_RECORDS_NOT_EXHAUSTIVE"
            )
        ):
            raise ValueError("PUBLICATION_RULE_VERSION_MISMATCH")
        if self.analyzed_place_ids != tuple(sorted(set(self.analyzed_place_ids))):
            raise ValueError("PUBLICATION_ANALYZED_MEMBERSHIP_INVALID")
        ids = tuple(d.place_id for d in self.decisions)
        if ids != tuple(sorted(set(ids))) or not set(ids) <= set(self.analyzed_place_ids):
            raise ValueError("PUBLICATION_DECISION_MEMBERSHIP_INVALID")
        if any(d.end - d.start != len(d.quote) for d in self.decisions):
            raise ValueError("PUBLICATION_QUOTE_SPAN_INVALID")
        if self.selection_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"selection_sha256"})
        ):
            raise ValueError("PUBLICATION_SELECTION_DIGEST_MISMATCH")
        return self

    @property
    def eligible_ids(self) -> tuple[str, ...]:
        excluded = {d.place_id for d in self.decisions if d.decision != "INCLUDE_ACTIVITY"}
        return tuple(pid for pid in self.analyzed_place_ids if pid not in excluded)

    def verify_sources(self, sources: Mapping[str, SourceBundle]) -> None:
        if set(sources) != set(self.analyzed_place_ids):
            raise ValueError("PUBLICATION_SOURCE_MEMBERSHIP_MISMATCH")
        for decision in self.decisions:
            source = sources[decision.place_id]
            if source.bundle_sha256 != decision.source_bundle_sha256:
                raise ValueError("PUBLICATION_SOURCE_CHANGED")
            evidence = next(
                (e for e in source.evidence if e.evidence_id == decision.evidence_id), None
            )
            if (
                evidence is None
                or evidence.modality != "TEXT"
                or evidence.source_role != "OFFICIAL_DESCRIPTION"
                or evidence.receipt.provider != "KorService2"
                or evidence.place_match != "VERIFIED"
                or evidence.state != "AVAILABLE"
                or not evidence.text
                or evidence.text[decision.start : decision.end] != decision.quote
            ):
                raise ValueError("PUBLICATION_DECISION_REQUIRES_EXACT_OFFICIAL_QUOTE")

    def verify_release(self, ids: tuple[str, ...], parent: str) -> None:
        if parent != self.parent_manifest_sha256 or tuple(sorted(ids)) != self.eligible_ids:
            raise ValueError("PUBLICATION_RELEASE_SELECTION_MISMATCH")
