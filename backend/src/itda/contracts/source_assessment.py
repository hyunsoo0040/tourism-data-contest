"""Versioned evidence sidecars; historical score/release contracts stay immutable.

Source authority is intentionally narrower than model inference: photographs may
support appearance only and a relative forecast never establishes physical crowd.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS
from itda.domain.canonical import canonical_sha256


class SupportState(StrEnum):
    FACT = "SUPPORTED_FACT"
    INFERENCE = "SUPPORTED_INFERENCE"
    UNKNOWN = "UNKNOWN"


class ClaimKind(StrEnum):
    EXPERIENCE = "EXPERIENCE"
    NARRATIVE = "NARRATIVE"
    HERITAGE = "HERITAGE"
    FACILITY = "FACILITY"
    OPERATING = "OPERATING"
    WALKING_ROUTE = "WALKING_ROUTE"
    CROWD = "CROWD"
    VISUAL_MOOD = "VISUAL_MOOD"
    CONCENTRATION_FORECAST = "CONCENTRATION_FORECAST"
    REGIONAL_VISITORS = "REGIONAL_VISITORS"
    REGIONAL_DEMAND = "REGIONAL_DEMAND"
    RELATED_PLACE = "RELATED_PLACE"


class SourceService(StrEnum):
    TOUR = "KorService2"
    ODII = "Odii"
    GALLERY = "PhotoGalleryService1"
    ACCESSIBILITY = "KorWithService2"
    CAMPING = "GoCamping"
    WALKING = "Durunubi"
    CONCENTRATION = "TatsCnctrRateService"
    VISITORS = "DataLabService"
    RELATED = "TarRlteTarService1"
    DEMAND = "AreaTarDemDsService"


SOURCE_DATASETS: dict[SourceService, str] = {
    SourceService.TOUR: "15101578",
    SourceService.ODII: "15101971",
    SourceService.GALLERY: "15101914",
    SourceService.ACCESSIBILITY: "15101897",
    SourceService.CAMPING: "15101933",
    SourceService.WALKING: "15101974",
    SourceService.CONCENTRATION: "15128555",
    SourceService.VISITORS: "15101972",
    SourceService.RELATED: "15128560",
    SourceService.DEMAND: "15151868",
}

SOURCE_OPERATIONS: dict[SourceService, frozenset[str]] = {
    SourceService.TOUR: frozenset(
        {
            "ldongCode2",
            "detailCommon2",
            "detailIntro2",
            "detailInfo2",
            "detailImage2",
            "searchKeyword2",
            "areaBasedList2",
        }
    ),
    SourceService.ODII: frozenset(
        {"themeSearchList", "themeBasedList", "storyBasedList", "storySearchList"}
    ),
    SourceService.GALLERY: frozenset({"gallerySearchList1", "galleryDetailList1"}),
    SourceService.ACCESSIBILITY: frozenset(
        {"searchKeyword2", "areaBasedList2", "detailCommon2", "detailWithTour2"}
    ),
    SourceService.CAMPING: frozenset(
        {"basedList", "basedSyncList", "searchList", "locationBasedList", "imageList"}
    ),
    SourceService.WALKING: frozenset({"courseList", "routeList"}),
    SourceService.CONCENTRATION: frozenset({"tatsCnctrRatedList"}),
    SourceService.VISITORS: frozenset({"locgoRegnVisitrDDList", "metcoRegnVisitrDDList"}),
    SourceService.RELATED: frozenset({"areaBasedList1", "searchKeyword1"}),
    SourceService.DEMAND: frozenset({"areaTarSjrnDsList", "areaTarExpDsList"}),
}

# Pixel input is governed separately from API metadata/text. It can never inherit
# the source service's authority to establish a facility or an operating claim.
_TEXT_CLAIMS: dict[SourceService, frozenset[ClaimKind]] = {
    SourceService.TOUR: frozenset(
        {
            ClaimKind.EXPERIENCE,
            ClaimKind.NARRATIVE,
            ClaimKind.HERITAGE,
            ClaimKind.FACILITY,
            ClaimKind.OPERATING,
        }
    ),
    SourceService.ODII: frozenset({ClaimKind.EXPERIENCE, ClaimKind.NARRATIVE}),
    SourceService.GALLERY: frozenset(),
    SourceService.ACCESSIBILITY: frozenset({ClaimKind.FACILITY}),
    SourceService.CAMPING: frozenset(
        {ClaimKind.EXPERIENCE, ClaimKind.FACILITY, ClaimKind.OPERATING}
    ),
    SourceService.WALKING: frozenset({ClaimKind.WALKING_ROUTE}),
    SourceService.CONCENTRATION: frozenset({ClaimKind.CONCENTRATION_FORECAST}),
    SourceService.VISITORS: frozenset({ClaimKind.REGIONAL_VISITORS}),
    SourceService.RELATED: frozenset({ClaimKind.RELATED_PLACE}),
    SourceService.DEMAND: frozenset({ClaimKind.REGIONAL_DEMAND}),
}


class SourceReceipt(StrictContract):
    schema_version: Literal["source-receipt.v1"] = "source-receipt.v1"
    service: SourceService
    operation: Annotated[str, Field(min_length=1, max_length=80)]
    dataset_id: Annotated[str, Field(pattern=r"^\d{8}$")]
    request_scope: dict[str, str]
    retrieved_at: datetime
    source_modified_at: datetime | None = None
    reference_date: date | None = None
    status: Literal["AVAILABLE", "EMPTY", "UNAVAILABLE"]
    http_status: Annotated[int, Field(ge=100, le=599)] | None
    response_sha256: Sha256 | None
    reason: Annotated[str, Field(min_length=1, max_length=300)]

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        if self.source_modified_at is not None:
            require_utc(self.source_modified_at, field_name="source_modified_at")
        if self.dataset_id != SOURCE_DATASETS[self.service]:
            raise ValueError("source dataset does not match service")
        if self.operation not in SOURCE_OPERATIONS[self.service]:
            raise ValueError("source operation is not authorized")
        if any(
            token in key.casefold().replace("_", "")
            for key in self.request_scope
            for token in ("servicekey", "apikey", "authorization", "secret", "token")
        ):
            raise ValueError("source receipt cannot contain credential parameters")
        if self.status != "UNAVAILABLE" and (
            self.http_status != 200 or self.response_sha256 is None
        ):
            raise ValueError("available source requires a successful hashed response")
        return self


class PlaceMatch(StrictContract):
    place_id: StableId
    service: SourceService
    provider_entity_id: StableId | None
    state: Literal["MATCHED", "NOT_MATCHED", "AMBIGUOUS"]
    method: (
        Literal[
            "EXACT_ID_AND_LOCATION",
            "EXACT_NAME_AND_LOCATION",
            "EXACT_NAME_AND_OFFICIAL_LOCATION",
            "CURATED_CROSSWALK",
        ]
        | None
    )
    region_code: Annotated[str, Field(pattern=r"^\d{2,5}$")]
    evidence: tuple[Annotated[str, Field(min_length=1, max_length=500)], ...]
    distance_meters: Annotated[float, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def validate_match(self) -> Self:
        if self.state == "MATCHED" and (
            self.provider_entity_id is None or self.method is None or not self.evidence
        ):
            raise ValueError("matched place requires an explicit identity crosswalk")
        if self.state != "MATCHED" and self.method is not None:
            raise ValueError("unmatched place cannot assert a matching method")
        return self


class SourceEvidence(StrictContract):
    evidence_id: StableId
    receipt: SourceReceipt
    place_match: PlaceMatch | None = None
    scope: Literal["PLACE", "ROUTE", "REGION"]
    modality: Literal["STRUCTURED", "TEXT", "IMAGE_PIXELS"]
    source_field: Annotated[str, Field(min_length=1, max_length=100)]
    excerpt: Annotated[str, Field(min_length=1, max_length=8_000)]
    quote: Annotated[str, Field(min_length=1, max_length=4_000)]
    image_sha256: Sha256 | None = None
    image_license: Literal["KOGL_TYPE_1"] | None = None

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.receipt.status != "AVAILABLE":
            raise ValueError("unavailable or empty source cannot support an observation")
        if self.quote not in self.excerpt:
            raise ValueError("evidence quote is not present in source excerpt")
        if self.scope == "PLACE" and (
            self.place_match is None or self.place_match.state != "MATCHED"
        ):
            raise ValueError("place evidence requires a verified place match")
        if self.place_match is not None and self.place_match.service != self.receipt.service:
            raise ValueError("place match source mismatch")
        if self.modality == "IMAGE_PIXELS":
            if (
                self.receipt.service
                not in {SourceService.TOUR, SourceService.GALLERY, SourceService.CAMPING}
                or self.image_sha256 is None
                or self.image_license is None
            ):
                raise ValueError("pixel evidence requires licensed original image provenance")
        elif self.image_sha256 is not None or self.image_license is not None:
            raise ValueError("text or metadata cannot claim pixel input")
        return self

    def authorizes(self, claim: ClaimKind) -> bool:
        if self.receipt.service == SourceService.TOUR and self.receipt.operation == "ldongCode2":
            # Administrative lookup proves coverage and identity metadata only.
            return False
        if self.modality == "IMAGE_PIXELS":
            return claim == ClaimKind.VISUAL_MOOD
        if claim not in _TEXT_CLAIMS[self.receipt.service]:
            return False
        if self.receipt.service == SourceService.TOUR:
            if self.receipt.operation == "detailImage2":
                return False
            if claim == ClaimKind.OPERATING and self.receipt.operation != "detailIntro2":
                return False
        if self.receipt.service == SourceService.ACCESSIBILITY:
            return self.receipt.operation == "detailWithTour2"
        return True


ObservationValue = StrictBool | StrictInt | StrictFloat | StrictStr | None


class SourceObservation(StrictContract):
    key: Annotated[str, Field(min_length=1, max_length=100)]
    claim: ClaimKind
    state: SupportState
    value: ObservationValue
    evidence: tuple[SourceEvidence, ...]
    reference_date: date | None
    reason: Annotated[str, Field(min_length=1, max_length=1_000)]

    @model_validator(mode="after")
    def validate_support(self) -> Self:
        if self.state == SupportState.UNKNOWN:
            if self.value is not None:
                raise ValueError("unknown is not zero, false or a midpoint")
            return self
        if self.value is None or not self.evidence or self.reference_date is None:
            raise ValueError("supported observation requires value, evidence and reference date")
        if any(not source.authorizes(self.claim) for source in self.evidence):
            raise ValueError("source cannot support this claim kind")
        if (
            self.claim
            in {ClaimKind.FACILITY, ClaimKind.OPERATING, ClaimKind.HERITAGE, ClaimKind.CROWD}
            and self.state != SupportState.FACT
        ):
            raise ValueError("core factual claims cannot be model inferences")
        if self.claim in {ClaimKind.REGIONAL_VISITORS, ClaimKind.REGIONAL_DEMAND} and any(
            e.scope != "REGION" for e in self.evidence
        ):
            raise ValueError("regional data cannot establish a place observation")
        if self.claim == ClaimKind.WALKING_ROUTE and any(e.scope != "ROUTE" for e in self.evidence):
            raise ValueError("course information must preserve route scope")
        if self.claim not in {
            ClaimKind.REGIONAL_VISITORS,
            ClaimKind.REGIONAL_DEMAND,
            ClaimKind.WALKING_ROUTE,
        } and any(e.scope != "PLACE" for e in self.evidence):
            raise ValueError("place claims require place-specific evidence")
        return self


class AssessmentBundle(StrictContract):
    schema_version: Literal["place-assessment.v1"] = "place-assessment.v1"
    policy_version: Literal["source-assessment-v1"] = "source-assessment-v1"
    place_id: StableId
    raw_profile_sha256: Sha256
    source_release_sha256: Sha256
    assessed_at: datetime
    dimensions: dict[str, SourceObservation]
    facts: dict[str, SourceObservation]
    bundle_sha256: Sha256

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        require_utc(self.assessed_at, field_name="assessed_at")
        if set(self.dimensions) != set(SCORING_DIMENSIONS):
            raise ValueError("assessment must explicitly cover all 21 score dimensions")
        for key, row in {**self.dimensions, **self.facts}.items():
            if key != row.key:
                raise ValueError("observation key mismatch")
            if any(
                e.place_match is not None and e.place_match.place_id != self.place_id
                for e in row.evidence
            ):
                raise ValueError("assessment evidence belongs to another place")
        for key, row in self.dimensions.items():
            if row.value is not None:
                maximum = 4 if key in {f"{a}{i}" for a in "HER" for i in range(1, 5)} else 100
                if type(row.value) is not int or not 0 <= row.value <= maximum:
                    raise ValueError("assessment dimension outside rubric range")
            if key == "M3" and row.claim != ClaimKind.CROWD:
                raise ValueError("M3 is physical crowd, never a mood or forecast")
            if row.claim == ClaimKind.VISUAL_MOOD:
                raise ValueError("visual mood cannot be projected into core score dimensions")
        if set(self.dimensions).intersection(self.facts):
            raise ValueError("fact keys cannot overwrite score dimensions")
        if self.bundle_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"bundle_sha256"})
        ):
            raise ValueError("assessment bundle hash mismatch")
        return self


class AssessmentMember(StrictContract):
    place_id: StableId
    raw_profile_sha256: Sha256
    assessment_bundle_sha256: Sha256


class AssessmentReleaseManifest(StrictContract):
    """Stable batch identity excludes trip-specific forecasts and facility refreshes."""

    schema_version: Literal["assessment-release.v1"] = "assessment-release.v1"
    policy_version: Literal["source-bundle-v1"] = "source-bundle-v1"
    raw_release_sha256: Sha256
    source_snapshot_sha256: tuple[Sha256, ...]
    source_release_sha256: Sha256
    members: tuple[AssessmentMember, ...]
    assessment_set_sha256: Sha256
    created_at: datetime
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.source_snapshot_sha256 != tuple(sorted(set(self.source_snapshot_sha256))):
            raise ValueError("source release snapshots must be canonical")
        places = tuple(m.place_id for m in self.members)
        if not places or places != tuple(sorted(set(places))):
            raise ValueError("assessment release members must be unique and canonical")
        expected_source = canonical_sha256(
            {
                "policy_version": self.policy_version,
                "raw_release_sha256": self.raw_release_sha256,
                "source_snapshot_sha256": self.source_snapshot_sha256,
            }
        )
        if self.source_release_sha256 != expected_source:
            raise ValueError("static source release digest mismatch")
        expected_set = canonical_sha256(
            {
                "source_release_sha256": expected_source,
                "members": [m.model_dump(mode="json") for m in self.members],
            }
        )
        if self.assessment_set_sha256 != expected_set:
            raise ValueError("assessment set digest mismatch")
        if self.manifest_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"manifest_sha256"})
        ):
            raise ValueError("assessment manifest digest mismatch")
        return self
