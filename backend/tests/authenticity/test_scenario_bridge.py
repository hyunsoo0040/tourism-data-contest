import pytest
from pydantic import ValidationError

from itda.authenticity.api_contracts import RunResult
from itda.authenticity.intent import Intent, ScenarioSubmission, build_intent, scenario_weights
from itda.authenticity.ranking import rank
from itda.contracts.preference import VERSION_BOUND_BY_QUESTIONNAIRE_V2
from itda.contracts.questionnaire_v2 import SCORING_CONFIG_V2
from itda.domain.preference import score_choice_answers
from tests.authenticity.helpers import NOW
from tests.authenticity.test_intent_and_ranking import assessment, intent
from tests.authenticity.test_private_photo import TestMoodProvider
from tests.authenticity.test_visual_ranking import mood

CONDITIONS = dict(
    visit_date=None,
    visit_time="UNDECIDED",
    companion="SOLO",
    transport="MIXED",
    walking_tolerance="ABOUT_1_HOUR",
    indoor_outdoor_preference="NO_PREFERENCE",
    crowd_avoidance="LOW",
)
AXIS_NAMES = {"H": "HISTORY_TRADITION", "E": "EMOTION_IMAGE", "R": "REST_IMMERSION"}


def scenario(axis="H", **extra):
    matrix = SCORING_CONFIG_V2["scoring_matrix"]
    answers = {
        f"q{i}": max(range(1, 4), key=lambda value: matrix[f"q{i}o{value}"][AXIS_NAMES[axis]])
        for i in range(1, 13)
    }
    return ScenarioSubmission(
        request_id="scenario:test",
        questionnaire_config_hash=VERSION_BOUND_BY_QUESTIONNAIRE_V2["config_hash"],
        answers=answers,
        trip_conditions=CONDITIONS,
        **extra,
    )


def test_bridge_is_pinned_to_scenario_matrix_and_never_fabricates_facet_answers():
    sub = scenario()
    weights = scenario_weights(sub)
    scores = score_choice_answers(sub.answers)
    assert sum(weights.values()) == 10_000
    assert weights["H"] == max(weights.values())
    assert set(sub.answers.model_dump()) == {f"q{i}" for i in range(1, 13)}
    assert len(scores) == 3
    original = build_intent(sub, created_at=NOW)
    assert Intent.model_validate_json(original.model_dump_json()) == original
    with pytest.raises(ValidationError, match="VERSION_MISMATCH"):
        ScenarioSubmission.model_validate(
            sub.model_dump() | {"questionnaire_config_hash": "0" * 64}
        )
    with pytest.raises(ValidationError):
        ScenarioSubmission.model_validate(sub.model_dump() | {"axis_weights": {"H": 10000}})


def test_relative_axis_preferences_change_actual_order_and_trace():
    historic = assessment(1, history=4, nature=1, rest_activity=1)
    resting = assessment(2, history=1, nature=4, rest_activity=4)
    for axis, expected in [("H", historic), ("R", resting)]:
        profile = build_intent(scenario(axis), created_at=NOW)
        result = rank(assessments=(historic, resting), intent=profile, created_at=NOW)
        assert result["items"][0]["place_id"] == expected.source.place.place_id
        assert result["ranking_version"] == "scenario-axis-bridge-ranking.v1"
        assert all(
            c["importance"] is None and c["facet"] in "HER"
            for item in result["items"]
            for c in item["components"]
        )
        assert RunResult.model_validate(result)
        assert result == rank(assessments=(resting, historic), intent=profile, created_at=NOW)


def test_bridge_keeps_region_facility_and_missing_dominant_axis_gates():
    a = assessment(1, missing=("H.a",))
    profile = build_intent(scenario(), created_at=NOW)
    assert (
        rank(assessments=(a,), intent=profile, created_at=NOW)["exclusions"][0]["reason"]
        == "IMPORTANT_AXIS_UNSUPPORTED"
    )
    for requirements, reason in [
        ({"region_code": "26"}, "REGION"),
        ({"required_facilities": ["step_free_entry"]}, "REQUIRED_FACILITY_UNCONFIRMED"),
    ]:
        profile = build_intent(scenario(requirements=requirements), created_at=NOW)
        result = rank(assessments=(assessment(1),), intent=profile, created_at=NOW)
        assert result["state"] == "EMPTY" and result["exclusions"][0]["reason"] == reason


def test_photo_confirmation_is_required_and_missing_photo_evidence_is_not_zero(tmp_path):
    with pytest.raises(ValidationError, match="RECEIPT"):
        scenario(visual_targets={"greenery": 3}, visual_input_kind="CONFIRMED_PHOTO")
    a = assessment(1, nature=3, rest_activity=3)
    profile = build_intent(
        scenario(
            "R",
            visual_targets={"greenery": 3},
            visual_input_kind="CONFIRMED_PHOTO",
            photo_receipt_sha256="a" * 64,
        ),
        created_at=NOW,
    )
    missing = rank(assessments=(a,), intent=profile, created_at=NOW)
    assert missing["items"][0]["coverage"]["percent"] == 80
    assert missing["items"][0]["warnings"] == ["MISSING_EXPECTATION_EVIDENCE"]
    known = rank(
        assessments=(a,),
        intent=profile,
        created_at=NOW,
        visual_references={a.source.place.place_id: mood(tmp_path, a, TestMoodProvider())},
    )
    photo = next(
        c for c in known["items"][0]["components"] if c["rule"] == "CONFIRMED_VISUAL_FACET_MATCH"
    )
    assert photo["weight"] == 2000 and photo["utility"] == 100
    assert known["items"][0]["coverage"]["percent"] == 100


def test_conditions_are_preserved_without_claiming_unmeasured_live_effects():
    sub = scenario()
    other = ScenarioSubmission.model_validate(
        sub.model_dump() | {"trip_conditions": CONDITIONS | {"crowd_avoidance": "HIGH"}}
    )
    a, b = build_intent(sub, created_at=NOW), build_intent(other, created_at=NOW)
    assert a.intent_sha256 != b.intent_sha256
    rows = (assessment(1), assessment(2))
    assert (
        rank(assessments=rows, intent=a, created_at=NOW)["items"]
        == rank(assessments=rows, intent=b, created_at=NOW)["items"]
    )


def test_retained_trip_rank_snapshot_is_byte_stable():
    result = rank(
        assessments=(assessment(1), assessment(2)), intent=intent({"H.a": 4}), created_at=NOW
    )
    assert (
        result["run_sha256"] == "7d3f42f984f0b43de8d6cde18edf6266174c7fb3fa7464e0365628d73e84a9e6"
    )
