from dataclasses import replace

from itda.authenticity.ranking import rank
from itda.pipeline.destination_mood import analyze_destination_mood
from tests.authenticity.helpers import NOW
from tests.authenticity.test_intent_and_ranking import assessment, intent
from tests.authenticity.test_private_photo import TestMoodProvider
from tests.pipeline.test_destination_mood import Provider, asset


def mood(tmp_path, a, provider):
    pid = a.source.place.place_id
    image = asset(tmp_path, pid.split(":")[-1])
    image = replace(image, place_id=pid, match=image.match.model_copy(update={"place_id": pid}))
    return analyze_destination_mood(
        place_id=pid,
        raw_profile_sha256="a" * 64,
        source_release_sha256="b" * 64,
        assets=(image,),
        provider=provider,
        assessed_at=NOW,
    )


def test_visual_match_changes_order_by_replacing_owned_facet_not_adding_a_bonus(tmp_path):
    a, b = assessment(1, nature=1), assessment(2, nature=4)
    references = {
        a.source.place.place_id: mood(tmp_path, a, Provider()),
        b.source.place.place_id: mood(tmp_path, b, TestMoodProvider()),
    }
    baseline = rank(assessments=(a, b), intent=intent({"R.b": 2}), created_at=NOW)
    assert baseline["items"][0]["place_id"] == b.source.place.place_id
    profile = intent({"R.b": 2}, visual_targets={"greenery": 1}, visual_input_kind="MANUAL")
    result = rank(assessments=(a, b), intent=profile, visual_references=references, created_at=NOW)
    assert result["items"][0]["place_id"] == a.source.place.place_id
    assert result["items"][0]["score"] == 100
    assert len(result["items"][0]["components"]) == 1
    assert result["items"][0]["components"][0]["rule"] == "CONFIRMED_VISUAL_FACET_MATCH"
    missing = rank(
        assessments=(a, b),
        intent=intent({"R.b": 3}, visual_targets={"greenery": 1}, visual_input_kind="MANUAL"),
        visual_references={a.source.place.place_id: references[a.source.place.place_id]},
        created_at=NOW,
    )
    assert missing["result_count"] == 1
    assert missing["exclusions"][0]["reason"] == "IMPORTANT_VISUAL_UNSUPPORTED"
