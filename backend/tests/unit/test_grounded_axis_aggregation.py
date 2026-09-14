"""Direct model axes cannot override supported subordinate evidence."""

from datetime import UTC, date, datetime

import pytest

from itda.contracts.source_assessment import (
    ClaimKind,
    PlaceMatch,
    SourceEvidence,
    SourceObservation,
    SourceReceipt,
    SourceService,
    SupportState,
)
from itda.pipeline.grounded_assessment import aggregate_axis, build_assessment, unknown_dimension
from tests.contract.test_mvp_scored_release import profile


def judgment(key, value, *, service=SourceService.TOUR, field="overview"):
    scored = profile(1)
    receipt = SourceReceipt(
        service=service,
        operation="detailCommon2" if service == SourceService.TOUR else "storyBasedList",
        dataset_id="15101578" if service == SourceService.TOUR else "15101971",
        request_scope={},
        retrieved_at=datetime(2026, 9, 9, tzinfo=UTC),
        status="AVAILABLE",
        http_status=200,
        response_sha256="a" * 64,
        reason="official record",
    )
    match = PlaceMatch(
        place_id=scored.place_id,
        service=service,
        provider_entity_id="1",
        state="MATCHED",
        method="EXACT_NAME_AND_LOCATION",
        region_code="47130",
        evidence=("exact canonical match",),
    )
    evidence = SourceEvidence(
        evidence_id=f"evidence:{key}",
        receipt=receipt,
        place_match=match,
        scope="PLACE",
        modality="TEXT",
        source_field=field,
        excerpt="공식 장소 설명",
        quote="공식 장소 설명",
    )
    return SourceObservation(
        key=key,
        claim=ClaimKind.EXPERIENCE,
        state=SupportState.INFERENCE,
        value=value,
        evidence=(evidence,),
        reference_date=date(2026, 9, 9),
        reason="rubric judgment",
    )


def dimensions(axis, values):
    return {
        f"{axis}{i}": judgment(f"{axis}{i}", v)
        if v is not None
        else unknown_dimension(f"{axis}{i}", "missing")
        for i, v in enumerate(values, 1)
    }


@pytest.mark.parametrize(
    "values,expected",
    [
        ([4, 0, None, None], 50),
        ([4, 4, 3, None], 92),
        ([0, 0, None, None], 0),
        ([4, None, None, None], None),
        ([None] * 4, None),
    ],
)
def test_equal_weight_aggregation_true_zero_and_minimum_support(values, expected):
    result = aggregate_axis("H", dimensions("H", values))
    assert result.value == expected
    assert (result.state == SupportState.UNKNOWN) == (expected is None)


def test_raw_independent_axes_are_audit_only_and_raw_profile_remains_unchanged():
    raw = profile(1)
    before = raw.model_dump_json()
    result = build_assessment(
        profile=raw,
        judgments=dimensions("H", [4, 4, 3, None]),
        facts={},
        source_release_sha256="b" * 64,
        assessed_at=datetime(2026, 9, 9, tzinfo=UTC),
    )
    assert result.bundle.dimensions["H"].value == 92
    assert result.raw_axes["H"] == 50 and result.axis_deltas["H"] == 42
    assert result.bundle.dimensions["E"].value is None
    assert result.bundle.dimensions["M3"].value is None
    assert raw.model_dump_json() == before


def test_odii_story_cannot_supply_physical_heritage_or_quietness_judgment():
    with pytest.raises(ValueError, match="does not authorize"):
        build_assessment(
            profile=profile(1),
            judgments={"R3": judgment("R3", 0, service=SourceService.ODII)},
            facts={},
            source_release_sha256="b" * 64,
            assessed_at=datetime(2026, 9, 9, tzinfo=UTC),
        )


def test_designation_flag_cannot_establish_general_heritage_axis():
    with pytest.raises(ValueError, match="does not authorize"):
        build_assessment(
            profile=profile(1),
            judgments={"H2": judgment("H2", 0, field="heritage1")},
            facts={},
            source_release_sha256="b" * 64,
            assessed_at=datetime(2026, 9, 9, tzinfo=UTC),
        )


def test_no_direct_model_axis_injection():
    with pytest.raises(ValueError, match="model axes"):
        build_assessment(
            profile=profile(1),
            judgments={"H": judgment("H", 100)},
            facts={},
            source_release_sha256="b" * 64,
            assessed_at=datetime(2026, 9, 9, tzinfo=UTC),
        )


def test_paired_axis_comparison_uses_independent_axes_from_the_same_analysis_response():
    result = build_assessment(
        profile=profile(1),
        judgments=dimensions("H", [4, 4, 3, None]),
        facts={},
        source_release_sha256="b" * 64,
        assessed_at=datetime(2026, 9, 9, tzinfo=UTC),
        independent_axes={"H": 85, "E": 20, "R": 30},
    )
    assert result.comparison_basis == "SAME_ANALYSIS_RESPONSE"
    assert result.raw_axes["H"] == 85 and result.axis_deltas["H"] == 7
    assert result.bundle.dimensions["H"].value == 92
