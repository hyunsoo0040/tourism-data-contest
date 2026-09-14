"""Source-bound observations; unknown is never a negative facility finding."""

from datetime import date
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.mvp_public_catalog import PublicEvidenceId, PublicPlaceId

PLACE_FACT_POLICY_VERSION: Literal["source-bound-place-facts.v1"] = "source-bound-place-facts.v1"
FACT_KEYS = (
    "child_access",
    "senior_access",
    "stroller_rental",
    "wheelchair_access",
    "parking",
    "transit_access",
    "walking_minutes",
    "indoor_outdoor",
    "opening_hours",
    "visit_minutes",
)


class FactSource(StrictContract):
    place_id: PublicPlaceId
    evidence_id: PublicEvidenceId
    provider: Literal["TOUR_API", "ODII"]
    provider_source_id: Annotated[str, Field(min_length=1, max_length=160)]
    excerpt: Annotated[str, Field(min_length=1, max_length=4_000)]
    reference_date: date
    source_response_sha256: Sha256


class FactEvidence(StrictContract):
    source: FactSource
    quote: Annotated[str, Field(min_length=1, max_length=1_000)]
    field_name: str | None = None

    @model_validator(mode="after")
    def validate_quote(self) -> Self:
        if self.quote not in self.source.excerpt:
            raise ValueError("fact quote is not present in the bound source")
        return self


class PlaceFact(StrictContract):
    state: Literal["FACT", "INFERENCE", "UNKNOWN"]
    value: bool | int | str | None
    evidence: tuple[FactEvidence, ...]
    reason: str

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.state == "UNKNOWN" and self.value is not None:
            raise ValueError("unknown fact cannot carry a value")
        if self.state != "UNKNOWN" and (self.value is None or not self.evidence):
            raise ValueError("usable observation requires a value and evidence")
        return self


class PlaceFacts(StrictContract):
    policy_version: Literal["source-bound-place-facts.v1"] = PLACE_FACT_POLICY_VERSION
    place_id: PublicPlaceId
    observations: dict[str, PlaceFact]

    @model_validator(mode="after")
    def validate_source_binding(self) -> Self:
        if set(self.observations) != set(FACT_KEYS):
            raise ValueError("place facts must explicitly cover every known/unknown field")
        for fact in self.observations.values():
            if any(row.source.place_id != self.place_id for row in fact.evidence):
                raise ValueError("fact source place binding mismatch")
        return self
