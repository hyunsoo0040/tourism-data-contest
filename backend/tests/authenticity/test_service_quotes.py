from types import SimpleNamespace

from itda.authenticity.auxiliary import Auxiliary
from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.ranking import rank
from itda.authenticity.scoring import build_assessment
from itda.authenticity.service import Service
from tests.authenticity.helpers import NOW, evidence, raw, source
from tests.authenticity.test_intent_and_ranking import intent


def test_same_source_keeps_distinct_facet_specific_quotations():
    history = "실제 유물을 전시하고 있다."
    interpretation = "시대별 유물 해설로 원래 생활 맥락을 설명한다."
    src = source(evidence(history + " " + interpretation))
    judgments, rejections = bind_response(
        {
            "judgments": [
                raw("H.a", history, "HERITAGE_FACT"),
                raw("H.d", interpretation, "HERITAGE_INTERPRETATION"),
            ]
        },
        src,
    )
    assessment = build_assessment(
        source=src, judgments=judgments, rejections=rejections, policy=Policy(), assessed_at=NOW
    )
    run = rank(assessments=(assessment,), intent=intent({"H.a": 4}), created_at=NOW)
    service = Service(SimpleNamespace(get_run=lambda *_: {"release_sha256": "a" * 64}))
    service.run = lambda *_: run
    service.pinned = lambda _: (None, (assessment,), Auxiliary())
    detail = service.detail("test-session", "test-run", src.place.place_id)
    quotes = {q.facet: q.quote for q in detail.evidence[0].facet_quotes}
    assert quotes == {"H.a": history, "H.d": interpretation}
