from datetime import date

import pytest

from itda.contracts.place_facts import FactEvidence, FactSource
from itda.pipeline.place_facts import extract_place_facts, project_fact_conditions

PLACE_ID = "public:gyeongju:" + "1" * 64


def source(text: str, *, place_id: str = PLACE_ID) -> FactSource:
    return FactSource(
        place_id=place_id,
        evidence_id="evidence:" + "2" * 64,
        provider="TOUR_API",
        provider_source_id="123",
        excerpt=text,
        reference_date=date(2026, 9, 8),
        source_response_sha256="3" * 64,
    )


def test_explicit_fields_keep_source_binding_and_absence() -> None:
    facts = extract_place_facts(
        PLACE_ID, (source("TourAPI parking: 주차 가능\n소개: 실내 전시관"),)
    )
    assert facts.observations["parking"].value is True
    assert facts.observations["parking"].state == "FACT"
    assert facts.observations["parking"].evidence[0].source.reference_date == date(2026, 9, 8)
    assert facts.observations["senior_access"].state == "UNKNOWN"
    assert facts.observations["senior_access"].value is None
    projected = project_fact_conditions(facts, transport="CAR_OR_TAXI")
    assert projected.values["transport"] == 100
    assert projected.values["indoor_outdoor"] == 0
    assert projected.values["companions"] is None


def test_unknown_conflicting_negated_and_foreign_sources_fail_closed() -> None:
    facts = extract_place_facts(PLACE_ID, (source("주차 가능 여부 확인 필요. 실내외 복합 공간"),))
    assert all(row.value is None for row in facts.observations.values())
    denied = extract_place_facts(PLACE_ID, (source("TourAPI parking: 주차 불가"),))
    assert project_fact_conditions(denied, transport="CAR_OR_TAXI").values["transport"] == 0
    conflicting = extract_place_facts(PLACE_ID, (source("주차 가능\n주차 불가"),))
    assert conflicting.observations["parking"].value is None
    with pytest.raises(ValueError, match="place binding"):
        extract_place_facts(
            PLACE_ID, (source("주차 가능", place_id="public:gyeongju:" + "4" * 64),)
        )


def test_child_and_senior_facts_have_distinct_meanings() -> None:
    facts = extract_place_facts(
        PLACE_ID, (source("어린이 입장 가능. 어르신 이용 불가. 보행 소요시간 30분"),)
    )
    assert (
        project_fact_conditions(facts, companion="FAMILY_WITH_CHILDREN").values["companions"] == 100
    )
    assert project_fact_conditions(facts, companion="WITH_SENIORS").values["companions"] == 0
    assert (
        project_fact_conditions(facts, companion="FRIEND_OR_PARTNER").values["companions"] is None
    )
    assert project_fact_conditions(facts).values["walking"] == 0


def test_rental_is_not_accessibility_and_hours_are_not_time_preference() -> None:
    facts = extract_place_facts(
        PLACE_ID, (source("TourAPI chkbabycarriage: 가능\nTourAPI usetime: 09:00~18:00"),)
    )
    assert facts.observations["stroller_rental"].value is True
    assert facts.observations["child_access"].value is None
    assert facts.observations["opening_hours"].value == "09:00~18:00"
    assert project_fact_conditions(facts).values["visit_date_time"] is None


def test_fabricated_quote_is_rejected() -> None:
    with pytest.raises(ValueError, match="not present"):
        FactEvidence(source=source("근거에는 주차정보가 없다"), quote="주차 가능")


def test_odii_narration_cannot_establish_current_facility_or_operating_facts():
    narration = source("주차 가능. 휠체어 이동 가능. TourAPI usetime: 09:00~18:00").model_copy(
        update={"provider": "ODII"}
    )
    facts = extract_place_facts(PLACE_ID, (narration,))
    assert all(f.state == "UNKNOWN" and f.value is None for f in facts.observations.values())


@pytest.mark.parametrize(
    ("key", "subject"),
    (
        ("parking", "주차"),
        ("child_access", "어린이 이용"),
        ("senior_access", "어르신 접근"),
        ("wheelchair_access", "휠체어 이동"),
        ("transit_access", "대중교통 접근"),
    ),
)
@pytest.mark.parametrize(
    "clause",
    (
        "가능 공간이 없습니다",
        "가능 시설이 없습니다",
        "가능하다고 볼 수 없습니다",
        "가능한 경우에만 이용할 수 있습니다",
        "가능하지 않습니다",
        "불가 시설이 없습니다",
    ),
)
def test_qualified_accessibility_claims_remain_unknown(key: str, subject: str, clause: str) -> None:
    facts = extract_place_facts(PLACE_ID, (source(f"{subject} {clause}."),))
    assert facts.observations[key].state == "UNKNOWN"
    assert facts.observations[key].value is None
    projected = project_fact_conditions(
        facts, companion="FAMILY_WITH_CHILDREN", transport="CAR_OR_TAXI"
    )
    assert projected.values["companions"] is None
    assert projected.values["transport"] is None


@pytest.mark.parametrize(
    ("key", "subject"),
    (
        ("parking", "주차"),
        ("child_access", "어린이 이용"),
        ("senior_access", "어르신 접근"),
        ("wheelchair_access", "휠체어 이동"),
        ("transit_access", "대중교통 접근"),
    ),
)
@pytest.mark.parametrize(("verdict", "expected"), (("가능", True), ("불가", False)))
def test_complete_accessibility_statements_retain_real_positive_and_zero(
    key: str,
    subject: str,
    verdict: str,
    expected: bool,
) -> None:
    facts = extract_place_facts(PLACE_ID, (source(f"{subject} {verdict}."),))
    assert facts.observations[key].state == "FACT"
    assert facts.observations[key].value is expected


@pytest.mark.parametrize(
    ("key", "text"),
    (
        ("indoor_outdoor", "실내 전시관이 아닐 수도 있습니다"),
        ("indoor_outdoor", "야외 공간으로 오해하지 마세요"),
        ("indoor_outdoor", "실내 시설 설계가 취소되었습니다"),
        ("walking_minutes", "보행 소요시간 30분이라고 보장할 수 없습니다"),
    ),
)
def test_qualified_space_and_walking_claims_remain_unknown(key: str, text: str) -> None:
    facts = extract_place_facts(PLACE_ID, (source(text),))
    assert facts.observations[key].state == "UNKNOWN"
    assert facts.observations[key].value is None
