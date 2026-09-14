from itda.authenticity.social_validation import (
    decoded_tag,
    display_count_interval,
    validate_reported_count,
)


def test_real_pilot_scale_bug_is_quarantined_not_silently_corrected():
    result = validate_reported_count(
        {"name": "월드컵공원", "postsCount": 7113000, "posts": "71.13 K"}
    )
    assert result["state"] == "CONFLICT" and result["value"] is None
    assert result["reason"] == "DISPLAY_NUMERIC_SCALE_MISMATCH"
    assert (
        validate_reported_count({"name": "월드컵공원", "postsCount": 71130, "posts": "71.13 K"})[
            "value"
        ]
        == 71130
    )


def test_provider_zero_is_not_confirmed_absence_and_posts_prove_contradiction():
    assert validate_reported_count({"postsCount": 0})["value"] is None
    assert (
        validate_reported_count({"postsCount": 0}, observed_posts=5)["reason"]
        == "ZERO_WITH_OBSERVED_POSTS"
    )
    for value in [None, False, -1, "100"]:
        assert validate_reported_count({"postsCount": value})["state"] == "UNAVAILABLE"


def test_tag_identity_and_display_rounding():
    assert decoded_tag({"name": "%EC%9D%B8%EC%87%84%EA%B1%B0%EB%A6%AC"}) == "인쇄거리"
    assert (
        decoded_tag({"inputUrl": "https://www.instagram.com/explore/tags/인쇄거리/"}) == "인쇄거리"
    )
    assert decoded_tag({"url": "https://www.instagram.com/p/post/"}) is None
    assert display_count_interval("1,907") == (1907, 1907)
    assert (
        validate_reported_count({"postsCount": 1907, "posts": "1907"})["state"]
        == "AVAILABLE_REPORTED"
    )
