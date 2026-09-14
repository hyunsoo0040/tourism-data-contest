from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.review import repair_assessment, review_assessment
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.scoring import build_assessment
from tests.authenticity.helpers import NOW, evidence, raw, source


class StubModel:
    def __init__(self, output):
        self.output = output

    def complete(self, payload, **kwargs):
        return self.output, {"request_sha256": "b" * 64}


def prepared(*rows):
    text = "빛의 연출이 있는 공간에서 방문자가 직접 만드는 체험을 할 수 있다."
    src = source(evidence(text))
    supplied = {r["key"]: r for r in rows}
    wire = {
        "judgments": [
            supplied[k]
            if k in supplied
            else dict(
                key=k,
                state="UNKNOWN",
                level=None,
                basis="INSUFFICIENT",
                subject="UNRESOLVED",
                citations=[],
                reason="미확인",
            )
            for k in FACET_KEYS
        ]
    }
    judgments, rejections = bind_response(wire, src)
    return (
        build_assessment(
            source=src,
            judgments=judgments,
            rejections=rejections,
            policy=Policy(),
            model_request_sha256="a" * 64,
            assessed_at=NOW,
        ),
        wire,
        text,
    )


def test_targeted_repair_preserves_good_judgments_and_composite_lineage(tmp_path):
    text = "빛의 연출이 있는 공간에서 방문자가 직접 만드는 체험을 할 수 있다."
    before, wire, _ = prepared(
        raw("E.c", text, "VISUAL_APPEARANCE"), raw("R.c", text, "PARTICIPATORY_ACTIVITY")
    )
    assert before.judgments[6].state == "REJECTED"
    repaired, report = repair_assessment(
        before,
        original_wire=wire,
        client=StubModel({"judgments": [raw("E.c", text, "VISUAL_EXPRESSION")]}),
        directory=tmp_path,
        live=False,
    )
    assert repaired.judgments[6].state == "SUPPORTED"
    assert repaired.judgments[10] == before.judgments[10]
    assert repaired.model_request_sha256 is None
    assert report["original_model_request_sha256"] == "a" * 64
    assert report["analysis_lineage"] == "COMPOSITE_OF_RETAINED_ORIGINAL_AND_TARGETED_REPAIR"


def test_ai_review_does_not_invent_replacement_scores_or_claim_human_labels(tmp_path):
    text = "빛의 연출이 있는 공간에서 방문자가 직접 만드는 체험을 할 수 있다."
    before, _, _ = prepared(raw("H.a", text, "HERITAGE_FACT"))
    reviewed, report = review_assessment(
        before,
        client=StubModel(
            {
                "reviews": [
                    {
                        "key": "H.a",
                        "decision": "REJECTED",
                        "issues": ["WRONG_FACET"],
                        "reason": "체험 공간을 원형 유산으로 볼 근거가 없다.",
                    }
                ]
            }
        ),
        directory=tmp_path,
        live=False,
    )
    assert before.judgments[0].level == 3
    assert reviewed.judgments[0].level is None
    assert reviewed.rejections[-1].code == "AI_SEMANTIC_REJECTED"
    assert report["scope"] == "AI_ASSISTED_NOT_INDEPENDENT_HUMAN_GROUND_TRUTH"
    assert report["human_evaluation"] == "EXCLUDED_BY_USER"


def test_inconsistent_or_missing_review_is_not_promoted_as_supported():
    from itda.authenticity.review import normalize_review

    decisions, invalid = normalize_review(
        {
            "reviews": [
                {
                    "key": "H.a",
                    "decision": "SUPPORTED",
                    "issues": ["WRONG_FACET"],
                    "reason": "contradictory",
                }
            ]
        },
        {"H.a", "R.b"},
    )
    assert {d.decision for d in decisions} == {"UNCERTAIN"}
    assert set(invalid) == {"H.a", "R.b"}


def test_repair_ignores_attempt_to_change_an_accepted_facet(tmp_path):
    text = "빛의 연출이 있는 공간에서 방문자가 직접 만드는 체험을 할 수 있다."
    before, wire, _ = prepared(
        raw("E.c", text, "VISUAL_APPEARANCE"), raw("R.c", text, "PARTICIPATORY_ACTIVITY", level=2)
    )
    response = {
        "judgments": [
            raw("E.c", text, "VISUAL_EXPRESSION"),
            raw("R.c", text, "PARTICIPATORY_ACTIVITY", level=4),
        ]
    }
    after, report = repair_assessment(
        before, original_wire=wire, client=StubModel(response), directory=tmp_path, live=False
    )
    assert after.judgments[10] == before.judgments[10]
    assert len(report["ignored_out_of_scope_rows"]) == 1


def test_invalid_review_wire_has_a_persistent_two_attempt_bound(tmp_path):
    import json

    import httpx

    from itda.authenticity.model import MODEL, GlmClient

    text = "빛의 연출이 있는 공간에서 방문자가 직접 만드는 체험을 할 수 있다."
    before, _, _ = prepared(raw("E.c", text, "VISUAL_EXPRESSION"))
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "model": MODEL,
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "content": json.dumps({"reviews": []}) + " extra unsupported prose",
                        },
                    }
                ],
            },
        )

    client = GlmClient(api_key="test-key", transport=httpx.MockTransport(handle))
    first, report = review_assessment(before, client=client, directory=tmp_path, live=True)
    assert len(calls) == 2
    assert first.judgments[6].level is None
    assert report["model"]["status"] == "MODEL_WIRE_INVALID_AFTER_BOUNDED_ATTEMPTS"
    second, repeated = review_assessment(before, client=client, directory=tmp_path, live=True)
    assert len(calls) == 2 and second == first and repeated == report
