from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.review import review_assessment
from itda.authenticity.scoring import build_assessment
from itda.authenticity.social_batch import SOCIAL_KEYS, meaning_request, merge_meaning
from itda.authenticity.sources import extend_source
from tests.authenticity.helpers import NOW, evidence, raw, source
from tests.authenticity.test_ai_review import StubModel


def baseline():
    text = "원형 유산과 전통을 보존하며 지역의 상징으로 소개한다."
    src = source(evidence(text))
    judgments, rejections = bind_response(
        {"judgments": [raw("H.a", text, "HERITAGE_FACT"), raw("E.a", text, "REPRESENTED_MEANING")]},
        src,
    )
    return build_assessment(
        source=src, judgments=judgments, rejections=rejections, policy=Policy(), assessed_at=NOW
    )


def test_social_cannot_rewrite_other_axes_or_use_official_only_reroll():
    original = baseline()
    caption = "이곳을 낭만적인 옛 시간의 장소로 기억한다."
    social = evidence(
        caption, eid="post:1", provider="APIFY_INSTAGRAM", role="UNCLASSIFIED", field="caption"
    )
    combined = extend_source(original.source, (social,))
    changed, audit = merge_meaning(
        original,
        source=combined,
        output={
            "judgments": [
                raw("H.a", caption, "HERITAGE_FACT", eid="post:1", level=4),
                raw("E.a", caption, "REPRESENTED_MEANING", eid="post:1", level=1),
                raw("E.b", original.source.evidence[0].text, "MEDIA_REPRESENTATION", level=4),
            ]
        },
    )
    assert changed.judgments[0] == original.judgments[0]
    assert changed.judgments[4].level == 1  # May decrease: never pick the higher score.
    assert changed.judgments[5] == original.judgments[5]  # No social anchor, no replacement.
    assert audit["replaced_keys"] == ["E.a"]
    payload, bound = meaning_request(combined)
    assert bound.evidence == combined.evidence
    assert "reported_count" not in payload["messages"][1]["content"]


def test_targeted_social_ai_review_preserves_previous_official_judgments(tmp_path):
    original = baseline()
    reviewed, report = review_assessment(
        original,
        client=StubModel(
            {
                "reviews": [
                    {
                        "key": "E.a",
                        "decision": "UNCERTAIN",
                        "issues": ["INSUFFICIENT_CONTEXT"],
                        "reason": "의미 불명확",
                    }
                ]
            }
        ),
        directory=tmp_path,
        live=False,
        only_keys=SOCIAL_KEYS,
    )
    assert reviewed.judgments[0] == original.judgments[0]
    assert reviewed.judgments[4].level is None
    assert [r["key"] for r in report["reviews"]] == ["E.a"]
