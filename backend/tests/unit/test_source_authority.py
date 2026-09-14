import pytest

from itda.contracts.source_assessment import SourceService
from itda.pipeline.source_authority import (
    FIELD_MEANINGS,
    prepare_source_text,
    source_role_description,
    supports_experience_time,
)


def test_real_markup_is_removed_but_korean_book_titles_are_preserved():
    text = "<p><삼국사기>와 <삼국유사>에 남은 이야기<br/>입니다.</p>"
    result = prepare_source_text(text)
    assert result.text == "<삼국사기>와 <삼국유사>에 남은 이야기 입니다."
    assert result.original_chars == len(text) and not result.truncated


def test_hidden_script_and_truncation_are_explicit_without_claiming_raw_identity():
    source = "<script>do bad things</script><b>가나다라</b>"
    result = prepare_source_text(source, character_limit=3)
    assert result.text == "가나다" and result.truncated
    assert result.cleaned_chars == 4 and result.used_chars == 3
    assert result.original_sha256 != result.cleaned_sha256


def test_source_roles_and_misleading_field_names_are_explicit():
    assert "후기" in source_role_description(SourceService.ODII)
    assert "세계문화유산" in FIELD_MEANINGS["heritage1"]
    assert "(분)" in FIELD_MEANINGS["crsTotlRqrmHour"]
    assert "연중무휴로 확대하지 않음" in FIELD_MEANINGS["fairday"]


@pytest.mark.parametrize(
    "quote",
    [
        "가족과 친구와 함께 여름 피서지로 방문하기에도 좋다",
        "계절에 따라 재료와 디자인이 달라져",
        "사과 수확철에는 사과 따기 체험을 진행하는데",
        "사계절 즐거운 물놀이를 즐길 수 있는",
        "봄에는 벚꽃이 계곡을 따라 만개하고, 가을에는 단풍이 절경이다",
        "감포 골프존CC의 야경이 매력적입니다",
        "겨울철 가족나들이에 으뜸이다",
    ],
)
def test_m6_accepts_cited_experience_seasonality_or_explicit_constancy(quote):
    assert supports_experience_time(quote)


@pytest.mark.parametrize(
    "quote",
    [
        "오전 8시 30분부터 영업을 하기 때문에 아침식사도 가능하다",
        "재료가 모두 소진되면 조기에 영업을 마감한다",
        "수영장, 온천사우나",
        "경주 여행 시 방문하기 좋은 숙소이다",
        "제례가 있는 날을 제외하고는 일반에 개방하지 않는다",
        "주말 운영을 원칙으로 사계절 내내 운영한다",
        "연중무휴로 누구나 쉽게 이용이 가능하다",
        "점심시간에는 대기가 있을 정도로",
        "인터넷 사전 예약",
        "야간에 운영한다. 수영장이 있다.",
    ],
)
def test_m6_rejects_availability_and_uncited_assumptions(quote):
    assert not supports_experience_time(quote)
