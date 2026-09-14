"""Combined additive tourism context for all seven provider consumers."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.grounded_recommendation import GroundedTripInput, TripContextPlace
from itda.contracts.place_enrichment import CampingContext, RelatedContext, WalkingContext
from itda.contracts.source_assessment import SourceService
from itda.contracts.trip_context import TripTemporalContext
from itda.domain.canonical import canonical_sha256

TOURISM_CONSUMERS: dict[SourceService, str] = {
    SourceService.ACCESSIBILITY: "places.accessibility",
    SourceService.CONCENTRATION: "temporal.forecasts",
    SourceService.VISITORS: "temporal.visitors",
    SourceService.DEMAND: "temporal.demand",
    SourceService.CAMPING: "places.camping",
    SourceService.WALKING: "places.walking",
    SourceService.RELATED: "places.related",
}


class TourismReferencePeriods(StrictContract):
    policy: Literal["EXPLICIT_OR_LAGGED_CALENDAR_PERIOD_V1"] = (
        "EXPLICIT_OR_LAGGED_CALENDAR_PERIOD_V1"
    )
    visitor_start: date
    visitor_end: date
    demand_month: str
    related_month: str
    lag_months: int
    availability_claim: Literal["REQUESTED_PERIOD_NOT_LATEST_GUARANTEE"] = (
        "REQUESTED_PERIOD_NOT_LATEST_GUARANTEE"
    )


class TourismSourceHealth(StrictContract):
    service: SourceService
    consumer: str
    state: Literal["AVAILABLE", "PARTIAL", "EMPTY", "UNAVAILABLE"]
    reason: str
    receipt_count: int = Field(ge=0)
    http_attempt_count: int = Field(ge=0)
    http_latency_ms: int = Field(ge=0)
    provider_result_codes: tuple[str, ...] = ()
    retrieved_at: datetime | None

    @model_validator(mode="after")
    def check_consumer(self) -> Self:
        if TOURISM_CONSUMERS.get(self.service) != self.consumer:
            raise ValueError("tourism source lacks its real registered consumer")
        if self.state in {"AVAILABLE", "PARTIAL", "EMPTY"} and self.receipt_count == 0:
            raise ValueError("source availability requires an actual receipt")
        if self.retrieved_at:
            require_utc(self.retrieved_at, field_name="retrieved_at")
        return self


class TourismPlaceContext(StrictContract):
    place_id: StableId
    place_name_ko: str
    accessibility: TripContextPlace
    camping: CampingContext
    walking: WalkingContext
    related: RelatedContext

    @model_validator(mode="after")
    def check_identity(self) -> Self:
        if any(
            row.place_id != self.place_id
            for row in (self.accessibility, self.camping, self.walking, self.related)
        ):
            raise ValueError("tourism context contains another place's enrichment")
        return self


class TourismContextResponse(StrictContract):
    schema_version: Literal["itda.tourism-context.v2"] = "itda.tourism-context.v2"
    recommendation_run_id: StableId
    trip_input: GroundedTripInput
    mode: Literal["REFRESHED", "PINNED"]
    checked_at: datetime
    reference_periods: TourismReferencePeriods
    places: tuple[TourismPlaceContext, ...]
    temporal: TripTemporalContext
    source_health: tuple[TourismSourceHealth, ...]
    source_snapshot_sha256: tuple[Sha256, ...]
    context_sha256: Sha256

    @model_validator(mode="after")
    def check_envelope(self) -> Self:
        require_utc(self.checked_at, field_name="checked_at")
        ids = tuple(row.place_id for row in self.places)
        if (
            len(ids) > 5
            or len(set(ids)) != len(ids)
            or {row.place_id for row in self.temporal.forecasts} != set(ids)
        ):
            raise ValueError("temporal and place context membership differs")
        if (
            self.trip_input.visit_date is not None
            and self.temporal.trip_date != self.trip_input.visit_date
        ):
            raise ValueError("tourism forecast date differs from requested trip")
        if (
            self.temporal.visitors.period_start != self.reference_periods.visitor_start
            or self.temporal.visitors.period_end != self.reference_periods.visitor_end
            or any(
                row.base_month != self.reference_periods.demand_month
                for row in self.temporal.demand
            )
            or any(
                row.related.base_month != self.reference_periods.related_month
                for row in self.places
            )
        ):
            raise ValueError("tourism observation periods differ from disclosed references")
        if any(
            len(row.walking.courses) > 5 or len(row.related.suggestions) > 5 for row in self.places
        ):
            raise ValueError("public tourism context exceeds bounded suggestion size")
        if {row.service for row in self.source_health} != set(TOURISM_CONSUMERS) or len(
            self.source_health
        ) != 7:
            raise ValueError("all seven tourism consumers must report source health")
        referenced = set(self.temporal.source_snapshot_sha256)
        for place in self.places:
            if place.accessibility.source_snapshot_sha256:
                referenced.add(place.accessibility.source_snapshot_sha256)
            for hashes in (
                place.camping.source_snapshot_sha256,
                place.walking.source_snapshot_sha256,
                place.related.source_snapshot_sha256,
            ):
                referenced.update(hashes)
        if self.source_snapshot_sha256 != tuple(sorted(referenced)):
            raise ValueError("combined context source snapshot membership differs")
        if self.context_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"context_sha256"})
        ):
            raise ValueError("combined tourism context hash mismatch")
        return self
