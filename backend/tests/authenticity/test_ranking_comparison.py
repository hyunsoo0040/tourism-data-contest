from itda.authenticity.ranking import rank
from itda.authenticity.ranking_comparison import distance_profile

from .helpers import NOW
from .test_intent_and_ranking import assessment, intent


def test_medium_importance_is_not_implicitly_a_request_for_medium_experience():
    rows = (assessment(1, history=2), assessment(2, history=4))
    profile = intent({"H.a": 2})
    fulfillment = rank(assessments=rows, intent=profile, created_at=NOW)
    distance = rank(assessments=rows, intent=distance_profile(profile), created_at=NOW)
    assert fulfillment["items"][0]["place_id"] == rows[1].source.place.place_id
    assert distance["items"][0]["place_id"] == rows[0].source.place.place_id
    assert fulfillment["exclusions"] == distance["exclusions"]
    assert fulfillment["assessment_set_sha256"] == distance["assessment_set_sha256"]


def test_explicit_zero_intensity_and_avoidance_are_not_overwritten():
    profile = intent({"H.a": 4}, desired_levels={"H.a": 0}, avoid={"R.b": 3})
    adapted = distance_profile(profile)
    assert adapted.submission.desired_levels == {"H.a": 0}
    assert adapted.submission.avoid == {"R.b": 3}
    rows = (assessment(1, history=0), assessment(2, history=4))
    before = rank(assessments=rows, intent=profile, created_at=NOW)
    after = rank(assessments=rows, intent=adapted, created_at=NOW)
    assert before == after


def test_no_importance_does_not_create_low_targets_or_false_recommendations():
    profile = intent({})
    assert distance_profile(profile) == profile
    result = rank(assessments=(assessment(1),), intent=distance_profile(profile), created_at=NOW)
    assert result["state"] == "EMPTY"
