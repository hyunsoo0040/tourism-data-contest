"""Additional trip input and source-bound context without changing old profiles."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Score100, Sha256, StableId, StrictContract, require_utc
from itda.contracts.source_assessment import SourceObservation
from itda.domain.canonical import canonical_sha256


class RequiredFacility(StrEnum):
    WHEELCHAIR_RENTAL = "wheelchair_rental"
    STROLLER_RENTAL = "stroller_rental"
    ACCESSIBLE_TOILET = "accessible_toilet"
    ACCESSIBLE_PARKING = "accessible_parking"
    STEP_FREE_ENTRY = "step_free_entry"


class GroundedTripInput(StrictContract):
    visit_date: date | None = None
    visit_time: Annotated[str, Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")] | None = None
    required_facilities: tuple[RequiredFacility, ...] = ()
    region_code: Annotated[
        str | None,
        Field(
            pattern=r"^\d{2}$",
            exclude_if=lambda value: value is None,
        ),
    ] = None

    @model_validator(mode="after")
    def validate_input(self) -> Self:
        if len(set(self.required_facilities)) != len(self.required_facilities):
            raise ValueError("duplicate facility requirements")
        object.__setattr__(self, "required_facilities", tuple(sorted(self.required_facilities)))
        return self

    @property
    def input_sha256(self) -> str:
        return canonical_sha256(
            {
                "schema_version": "grounded-trip-input.v1",
                "visit_date": self.visit_date.isoformat() if self.visit_date else None,
                "visit_time": self.visit_time,
                "required_facilities": sorted(f.value for f in self.required_facilities),
                **({"region_code": self.region_code} if self.region_code is not None else {}),
            }
        )


class TripContextPlace(StrictContract):
    place_id: StableId
    place_name_ko: Annotated[str, Field(min_length=1, max_length=240)]
    facts: tuple[SourceObservation, ...]
    source_snapshot_sha256: Sha256 | None
    state: Literal["AVAILABLE", "PARTIAL", "UNAVAILABLE"]
    reason_ko: Annotated[str, Field(min_length=1, max_length=500)]

    @model_validator(mode="after")
    def validate_places(self) -> Self:
        if len({f.key for f in self.facts}) != len(self.facts):
            raise ValueError("duplicate trip context facts")
        if any(
            e.place_match is not None and e.place_match.place_id != self.place_id
            for f in self.facts
            for e in f.evidence
        ):
            raise ValueError("trip context evidence belongs to another place")
        return self


class TripContextResponse(StrictContract):
    schema_version: Literal["itda.trip-context.v1"] = "itda.trip-context.v1"
    recommendation_run_id: StableId
    trip_input: GroundedTripInput
    checked_at: datetime
    mode: Literal["PINNED", "REFRESHED"]
    places: tuple[TripContextPlace, ...]

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        require_utc(self.checked_at, field_name="checked_at")
        if len({p.place_id for p in self.places}) != len(self.places):
            raise ValueError("duplicate trip context places")
        return self


class GroundedRunBinding(StrictContract):
    """Immutable companion record for a run, not a rewrite of legacy receipts."""

    schema_version: Literal["grounded-run-binding.v1"] = "grounded-run-binding.v1"
    run_id: StableId
    request_id: StableId
    preference_profile_id: StableId
    preference_input_sha256: Sha256
    trip_input: GroundedTripInput
    trip_input_sha256: Sha256
    raw_release_sha256: Sha256
    source_release_sha256: Sha256
    assessment_bundle_sha256: tuple[Sha256, ...] = ()
    source_snapshot_sha256: tuple[Sha256, ...]
    created_at: datetime
    binding_sha256: Sha256

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.trip_input_sha256 != self.trip_input.input_sha256:
            raise ValueError("grounded trip input binding mismatch")
        for values in (self.assessment_bundle_sha256, self.source_snapshot_sha256):
            if values != tuple(sorted(set(values))):
                raise ValueError("snapshot bindings must be unique and canonical")
        if self.binding_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"binding_sha256"})
        ):
            raise ValueError("grounded run binding hash mismatch")
        return self


class GroundedInputAuthority(StrictContract):
    """Small digest in the run receipt; full source content is pinned separately."""

    schema_version: Literal["grounded-input-authority.v1"] = "grounded-input-authority.v1"
    trip_input_sha256: Sha256
    source_release_sha256: Sha256
    source_snapshot_sha256: tuple[Sha256, ...]
    assessment_bundle_sha256: tuple[Sha256, ...] = ()

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        for values in (self.source_snapshot_sha256, self.assessment_bundle_sha256):
            if values != tuple(sorted(set(values))):
                raise ValueError("grounded authority must use canonical snapshot hashes")
        return self


class GroundedFitComponent(StrictContract):
    key: StableId
    expected: Score100 | None
    actual: Score100 | None
    compared: bool
    difference: Score100 | None
    fit: Score100 | None
    weight: Annotated[int, Field(strict=True, ge=0, le=10_000)]
    evidence_ids: tuple[StableId, ...]
    exclusion_reason: Literal["USER_UNSPECIFIED", "PLACE_UNSUPPORTED"] | None

    @model_validator(mode="after")
    def validate_comparison(self) -> Self:
        compared = self.expected is not None and self.actual is not None
        if self.compared != compared:
            raise ValueError("comparison support mask mismatch")
        if compared:
            if (
                self.expected is None
                or self.actual is None
                or self.difference != abs(self.expected - self.actual)
                or self.fit != 100 - self.difference
                or self.weight == 0
                or not self.evidence_ids
                or self.exclusion_reason is not None
            ):
                raise ValueError("supported comparison arithmetic or evidence mismatch")
        elif (
            self.difference is not None
            or self.fit is not None
            or self.weight != 0
            or self.exclusion_reason is None
        ):
            raise ValueError("unobserved comparison cannot carry a score or weight")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("comparison evidence must be canonical")
        return self


class GroundedFitTrace(StrictContract):
    components: tuple[GroundedFitComponent, ...]
    numerator: Annotated[int, Field(strict=True, ge=0)]
    denominator: Annotated[int, Field(strict=True, ge=0)]
    score: Score100 | None
    compared_keys: tuple[StableId, ...]

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        keys = tuple(c.key for c in self.components)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("fit components must be canonical")
        denominator = sum(c.weight for c in self.components)
        numerator = sum(c.weight * c.fit for c in self.components if c.fit is not None)
        score = (2 * numerator + denominator) // (2 * denominator) if denominator else None
        if (
            self.denominator != denominator
            or self.numerator != numerator
            or self.score != score
            or self.compared_keys != tuple(c.key for c in self.components if c.compared)
        ):
            raise ValueError("fit trace arithmetic or support mismatch")
        return self
