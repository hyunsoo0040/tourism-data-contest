"""Regression checks for the actual unsupported claims observed in the live audit."""

from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.source_assessment import (
    SOURCE_DATASETS,
    ClaimKind,
    PlaceMatch,
    SourceEvidence,
    SourceObservation,
    SourceReceipt,
    SourceService,
    SupportState,
)


def evidence(service=SourceService.ODII, operation="storyBasedList", **changes):
    source = SourceReceipt(
        service=service,
        operation=operation,
        dataset_id=SOURCE_DATASETS[service],
        request_scope={},
        retrieved_at=datetime(2026, 9, 9, tzinfo=UTC),
        status="AVAILABLE",
        http_status=200,
        response_sha256="a" * 64,
        reason="provider response",
    )
    match = PlaceMatch(
        place_id="place-1",
        service=service,
        provider_entity_id="provider-1",
        state="MATCHED",
        method="EXACT_NAME_AND_LOCATION",
        region_code="47130",
        evidence=("matching name/address/coordinates",),
    )
    data = dict(
        evidence_id="evidence-1",
        receipt=source,
        place_match=match,
        scope="PLACE",
        modality="TEXT",
        source_field="script",
        excerpt="우물이 남아 있습니다.",
        quote="우물이 남아 있습니다.",
    )
    data.update(changes)
    return SourceEvidence(**data)


@pytest.mark.parametrize("value", [0, 50, False, ""])
def test_missing_source_is_not_a_favorable_numeric_or_boolean_value(value):
    with pytest.raises(ValidationError, match="unknown is not"):
        SourceObservation(
            key="M3",
            claim=ClaimKind.CROWD,
            state=SupportState.UNKNOWN,
            value=value,
            evidence=(),
            reference_date=None,
            reason="not measured",
        )


@pytest.mark.parametrize(
    "claim", [ClaimKind.CROWD, ClaimKind.OPERATING, ClaimKind.FACILITY, ClaimKind.HERITAGE]
)
def test_odii_narrative_cannot_establish_core_facts(claim):
    with pytest.raises(ValidationError, match="source cannot support"):
        SourceObservation(
            key="claim",
            claim=claim,
            state=SupportState.FACT,
            value=25,
            evidence=(evidence(),),
            reference_date=date(2026, 9, 9),
            reason="model attempted unsupported inference",
        )


def test_relative_forecast_is_not_physical_density():
    source = evidence(SourceService.CONCENTRATION, "tatsCnctrRatedList")
    with pytest.raises(ValidationError, match="source cannot support"):
        SourceObservation(
            key="M3",
            claim=ClaimKind.CROWD,
            state=SupportState.FACT,
            value=25,
            evidence=(source,),
            reference_date=date(2026, 9, 9),
            reason="relative forecast",
        )


def test_pixels_authorize_appearance_only_even_when_provider_has_facility_information():
    source = evidence(
        SourceService.TOUR,
        "detailImage2",
        modality="IMAGE_PIXELS",
        image_sha256="b" * 64,
        image_license="KOGL_TYPE_1",
    )
    assert source.authorizes(ClaimKind.VISUAL_MOOD)
    assert not source.authorizes(ClaimKind.OPERATING)
    assert not source.authorizes(ClaimKind.CROWD)
    assert not source.authorizes(ClaimKind.EXPERIENCE)


def test_image_metadata_cannot_claim_that_pixels_were_analyzed():
    with pytest.raises(ValidationError, match="cannot claim pixel"):
        evidence(SourceService.TOUR, "detailImage2", image_sha256="b" * 64)


def test_region_statistic_cannot_be_assigned_to_a_place():
    source = evidence(SourceService.VISITORS, "locgoRegnVisitrDDList")
    with pytest.raises(ValidationError, match="regional data"):
        SourceObservation(
            key="visitors",
            claim=ClaimKind.REGIONAL_VISITORS,
            state=SupportState.FACT,
            value=83716.5,
            evidence=(source,),
            reference_date=date(2026, 7, 1),
            reason="regional estimate",
        )


def test_explicit_facilities_hash_is_order_independent_and_old_profile_is_not_an_input():
    a = GroundedTripInput(required_facilities=("wheelchair_rental", "accessible_toilet"))
    b = GroundedTripInput(required_facilities=("accessible_toilet", "wheelchair_rental"))
    assert a.input_sha256 == b.input_sha256
    assert a.model_dump(mode="json") == b.model_dump(mode="json")
    assert a.input_sha256 != GroundedTripInput().input_sha256


def test_receipt_rejects_credential_parameters():
    payload = evidence().receipt.model_dump()
    payload["request_scope"] = {"serviceKey": "must-not-be-stored"}
    with pytest.raises(ValidationError, match="credential parameters"):
        SourceReceipt.model_validate(payload)


def test_optional_grounding_preserves_exact_historical_quality_context_shape():
    from itda.contracts.recommendation import RecommendationQualityContext

    old = {
        "companion": "SOLO",
        "transport": "MIXED",
        "purpose": "MIXED",
        "eligible_place_ids": ["place-1"],
    }
    assert RecommendationQualityContext.model_validate(old).model_dump(mode="json") == old
