"""Substantive regression: authority, absence, subjects, core semantics and fusion traces."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.quotes import match_quote, verify_quote
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.scoring import build_assessment, verify_assessment
from tests.authenticity.helpers import NOW, evidence, photo, raw, source


def bind(src, *rows):
    supplied = {r["key"] for r in rows}
    payload = {
        "judgments": list(rows)
        + [
            dict(
                key=k,
                state="UNKNOWN",
                level=None,
                basis="INSUFFICIENT",
                subject="UNRESOLVED",
                citations=[],
                reason="미확인",
            )
            for k in FACET_KEYS
            if k not in supplied
        ]
    }
    return bind_response(payload, src)


def assess(src, *rows, policy=None):
    judgments, rejections = bind(src, *rows)
    return build_assessment(
        source=src,
        judgments=judgments,
        rejections=rejections,
        policy=policy or Policy(),
        assessed_at=NOW,
    )


def test_typographic_quote_repair_preserves_original_offsets_and_content():
    text = "분수는 ‘세계최대 바닥분수’로 등재되었다.\n  원문이다."
    quoted = "분수는 '세계최대 바닥분수'로 등재되었다. 원문이다."
    result = match_quote(text, quoted)
    assert result.method == "NORMALIZED_AND_MAPPED"
    assert result.original == text
    verify_quote(text, result)
    for changed in [
        text.replace("등재되었다", "등재되지 않았다"),
        text.replace("세계최대", "국내최대"),
    ]:
        with pytest.raises(ValueError):
            match_quote(text, changed)


def test_quote_repair_never_drops_negation_changes_numbers_or_uses_nfkc():
    for original, proposal in [
        ("건립은 1930년이다.", "건립은 1931년이다."),
        ("산책이 가능하지 않다.", "산책이 가능하다."),
        ("표시는 ①이다.", "표시는 1이다."),
    ]:
        with pytest.raises(ValueError):
            match_quote(original, proposal)


def test_absent_description_does_not_become_supported_zero():
    text = "이면도로에 밀집한 인쇄소들의 거리이다."
    result = assess(
        source(evidence(text)),
        raw("R.b", text, "ENVIRONMENT", level=0, reason="자연환경에 대한 묘사가 없음."),
    )
    assert result.judgments[9].state == "REJECTED"
    assert result.rejections[0].code == "ABSENCE_OF_EVIDENCE_IS_NOT_ZERO"
    assert result.axes[2].value is None


def test_explicit_low_is_preserved_and_unknown_is_distinct():
    text = "원형 유산을 보존한 공간이 아니며 실제 전승 활동은 제공하지 않는다."
    result = assess(
        source(evidence(text)),
        raw("H.a", text, "HERITAGE_FACT", level=0),
        raw("H.c", text, "LIVING_TRADITION", level=0),
    )
    assert result.axes[0].value == 0
    assert result.axes[1].value is None


def test_general_learning_cannot_by_itself_create_history_axis():
    text = "세계 문화 강연과 독서교실을 운영한다."
    result = assess(
        source(evidence(text)),
        raw("H.b", text, "HISTORICAL_NARRATIVE"),
        raw("H.d", text, "HERITAGE_INTERPRETATION"),
    )
    assert len(result.axes[0].supported_facets) == 2
    assert result.axes[0].core_satisfied is False
    assert result.axes[0].value is None


def test_other_subject_and_social_caption_cannot_assert_heritage():
    text = "제작사는 다른 박물관의 실감 콘텐츠를 제작했다."
    r = assess(
        source(evidence(text)),
        raw(
            "H.b", text, "HISTORICAL_NARRATIVE", reason="제작사의 다른 박물관 납품 실적을 확인했다."
        ),
    )
    assert r.rejections[0].code == "OTHER_SUBJECT_HISTORY_TRANSFER"
    s = source(
        evidence(
            "이곳은 실제 유산이다.",
            provider="APIFY_INSTAGRAM",
            role="VISITOR_POST",
            field="caption",
        )
    )
    r = assess(s, raw("H.a", "이곳은 실제 유산이다.", "HERITAGE_FACT"))
    assert r.rejections[0].code == "SOURCE_CLAIM_FACET_NOT_AUTHORIZED"


def test_odii_cannot_establish_physical_heritage_but_can_describe_history():
    text = "이 유적은 조선 시대 사건과 연결된다."
    r = assess(
        source(evidence(text, provider="Odii", role="OFFICIAL_NARRATIVE", field="script")),
        raw("H.a", text, "HERITAGE_FACT"),
        raw("H.b", text, "HISTORICAL_NARRATIVE"),
    )
    assert r.judgments[0].state == "REJECTED"
    assert r.judgments[1].state == "SUPPORTED"


def test_photo_fusion_uses_only_authorized_facets_and_no_extra_mood_bonus():
    text = "실제 유적이 보존되어 있고 역사 해설을 제공한다."
    src = source(
        evidence(text),
        photo("traditional_appearance", 4),
        photo("natural_setting", 4, eid="photo:n"),
    )
    rows = (
        raw("H.a", text, "HERITAGE_FACT", level=2),
        raw("H.d", text, "HERITAGE_INTERPRETATION", level=2),
    )
    plain = assess(src, *rows)
    er = assess(src, *rows, policy=Policy(photo_mode="ER"))
    her = assess(src, *rows, policy=Policy(photo_mode="HER_CONDITIONAL"))
    assert plain.axes[0].value == er.axes[0].value == 50
    assert her.axes[0].value == 57
    assert her.facets[0].value == 63
    assert her.facets[9].value == 100
    assert her.axes[2].value is None  # one visually supported facet is insufficient
    assert sum(c.weight_bp for c in her.facets[0].contributions) == 10000
    verify_assessment(her)


def test_heritage_looking_photo_cannot_create_history_without_verified_text():
    r = assess(
        source(photo("traditional_appearance", 4)), policy=Policy(photo_mode="HER_CONDITIONAL")
    )
    assert r.facets[0].value is None and r.axes[0].value is None


def test_missing_photos_do_not_reduce_text_score_and_duplicate_image_does_not_add_points():
    text = "정원과 물이 있고 녹지가 이어진다."
    row = raw("R.b", text, "ENVIRONMENT", level=2)
    plain = assess(source(evidence(text)), row)
    missing = assess(source(evidence(text)), row, policy=Policy(photo_mode="ER"))
    assert plain.facets[9].value == missing.facets[9].value == 50
    one = assess(
        source(evidence(text), photo("natural_setting", 4)), row, policy=Policy(photo_mode="ER")
    )
    twice = assess(
        source(
            evidence(text),
            photo("natural_setting", 4),
            photo("natural_setting", 4, eid="photo:duplicate"),
        ),
        row,
        policy=Policy(photo_mode="ER"),
    )
    assert one.facets[9].value == twice.facets[9].value
    assert len(twice.facets[9].contributions[1].evidence_ids) == 1


def test_missing_duplicate_and_invalid_proposals_are_diagnosed_separately():
    src = source(evidence())
    row = raw("H.a", src.evidence[0].text, "HERITAGE_FACT")
    payload = {"judgments": [row, deepcopy(row), {"key": "E.a", "state": "SUPPORTED"}]}
    judgments, rejections = bind_response(payload, src)
    codes = {r.code for r in rejections}
    assert {"MISSING_FACET", "DUPLICATED_FACET", "FACET_SCHEMA_REJECTED"} <= codes
    assert all(j.level is None for j in judgments)


def test_receipt_cannot_contain_token_in_url():
    record = evidence()
    with pytest.raises(ValidationError, match="CREDENTIAL"):
        type(record.receipt).model_validate(
            record.receipt.model_dump() | {"source_uri": "https://api.apify.com/?token=secret"}
        )
