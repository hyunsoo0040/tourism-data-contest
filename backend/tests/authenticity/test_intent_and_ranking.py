import pytest
from pydantic import ValidationError

from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.intent import IntentSubmission, build_intent
from itda.authenticity.ranking import rank
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.scoring import build_assessment
from itda.authenticity.sources import seal_bundle, seal_evidence
from tests.authenticity.helpers import NOW, evidence, raw, source


def intent(chosen, **extra):
    return build_intent(
        IntentSubmission(
            request_id="request:test", answers={k: chosen.get(k, 0) for k in FACET_KEYS}, **extra
        ),
        created_at=NOW,
    )


def assessment(index, *, history=3, nature=3, rest_activity=3, missing=()):
    text = "유산을 보존하고 해설하며 자연 속에서 체험 활동을 제공한다."
    original = source(evidence(text))
    pid = "public:korea:" + f"{index:064x}"
    place = original.place.model_copy(
        update={
            "place_id": pid,
            "duplicate_group_id": "duplicate:" + f"{index:064x}",
            "name_ko": f"장소 {index}",
        }
    )
    record = seal_evidence(original.evidence[0].model_dump() | {"place_id": pid})
    src = seal_bundle(place, (record,), original.parent_source_sha256)
    data = [
        raw("H.a", text, "HERITAGE_FACT", level=history),
        raw("H.d", text, "HERITAGE_INTERPRETATION", level=history),
        raw("R.b", text, "ENVIRONMENT", level=nature),
        raw("R.c", text, "PARTICIPATORY_ACTIVITY", level=rest_activity),
    ]
    by_key = {r["key"]: r for r in data if r["key"] not in missing}
    rows = [
        by_key[k]
        if k in by_key
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
    judgments, rejections = bind_response({"judgments": rows}, src)
    return build_assessment(
        source=src, judgments=judgments, rejections=rejections, policy=Policy(), assessed_at=NOW
    )


def test_all_three_axes_can_be_high_without_total_normalization():
    profile = intent({k: 4 for k in FACET_KEYS})
    assert profile.axis_importance == {"H": 100, "E": 100, "R": 100}
    assert profile.required_axes == ("H", "E", "R")


def test_not_important_is_not_prefer_low_and_explicit_low_is_distinct():
    low = assessment(1, history=0, nature=1, rest_activity=1)
    high = assessment(2, history=4, nature=4, rest_activity=4)
    r = rank(assessments=(low, high), intent=intent({"R.b": 4}), created_at=NOW)
    assert r["items"][0]["place_id"] == high.source.place.place_id
    explicit = rank(
        assessments=(low, high),
        intent=intent({"R.b": 4}, desired_levels={"R.b": 0}),
        created_at=NOW,
    )
    assert explicit["items"][0]["place_id"] == low.source.place.place_id
    avoided = rank(assessments=(low, high), intent=intent({}, avoid={"R.b": 4}), created_at=NOW)
    assert avoided["items"][0]["place_id"] == low.source.place.place_id


def test_important_missing_axis_is_not_hidden_by_other_good_scores():
    candidate = assessment(1, missing=("H.a",))
    r = rank(assessments=(candidate,), intent=intent({"H.a": 4, "R.b": 4}), created_at=NOW)
    assert r["state"] == "EMPTY" and r["exclusions"][0]["reason"] == "IMPORTANT_AXIS_UNSUPPORTED"


def test_less_than_five_results_are_honest_and_no_expectation_does_not_invent_profile():
    a = assessment(1)
    r = rank(assessments=(a,), intent=intent({"R.b": 4}), created_at=NOW)
    assert r["state"] == "LIMITED" and r["result_count"] == 1
    assert rank(assessments=(a,), intent=intent({}), created_at=NOW)["state"] == "EMPTY"


def test_relation_lookahead_finds_five_even_when_best_candidate_blocks_the_set():
    rows = tuple(assessment(i, history=4 if i == 1 else 2) for i in range(1, 7))
    blocked = tuple((rows[0].source.place.place_id, a.source.place.place_id) for a in rows[1:])
    r = rank(assessments=rows, intent=intent({"H.a": 4}), created_at=NOW, forbidden_pairs=blocked)
    assert r["state"] == "COMPLETE" and r["result_count"] == 5
    assert rows[0].source.place.place_id not in {x["place_id"] for x in r["items"]}


def test_photo_targets_cannot_claim_confirmation_without_a_receipt():
    with pytest.raises(ValidationError, match="RECEIPT"):
        intent({"E.c": 4}, visual_targets={"warm_light": 3}, visual_input_kind="CONFIRMED_PHOTO")


def test_same_inputs_have_same_rank_and_trace_despite_candidate_order():
    rows = tuple(assessment(i, history=i % 4) for i in range(1, 7))
    profile = intent({"H.a": 4})
    a = rank(assessments=rows, intent=profile, created_at=NOW)
    b = rank(assessments=tuple(reversed(rows)), intent=profile, created_at=NOW)
    assert a == b
