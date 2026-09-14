from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.report import detail
from itda.authenticity.scoring import build_assessment
from tests.authenticity.helpers import NOW, evidence, photo, raw, source


def test_report_keeps_facet_specific_quotes_and_labels_photo_only_support():
    first = "원래의 유물을 직접 관람할 수 있다."
    second = "해설을 통해 유물의 시대별 맥락을 탐구한다."
    src = source(evidence(first + " " + second), photo("natural_setting", 3))
    judgments, rejections = bind_response(
        {
            "judgments": [
                raw("H.a", first, "HERITAGE_FACT"),
                raw("H.d", second, "HERITAGE_INTERPRETATION"),
            ]
        },
        src,
    )
    a = build_assessment(
        source=src,
        judgments=judgments,
        rejections=rejections,
        policy=Policy(photo_mode="ER"),
        assessed_at=NOW,
    )
    projection = detail(a, [])
    facets = {f["key"]: f for f in projection["facets"]}
    assert facets["H.a"]["contributions"][0]["evidence"][0]["quote"] == first
    assert facets["H.d"]["contributions"][0]["evidence"][0]["quote"] == second
    assert "텍스트 판단은 미확인" in facets["R.b"]["reason"]
    assert facets["R.b"]["contributions"][0]["evidence"][0]["image_sha256"]
