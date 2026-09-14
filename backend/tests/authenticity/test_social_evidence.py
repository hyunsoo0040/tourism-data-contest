from itda.authenticity.social_evidence import match_post, region_markers


def test_query_tag_alone_does_not_prove_place_but_name_and_region_are_audited():
    place = {"primary_tag": "인쇄거리", "region": "대전광역시 동구"}
    post = {
        "id": "1",
        "inputUrl": "https://www.instagram.com/explore/tags/인쇄거리/",
        "caption": "#인쇄거리",
    }
    assert match_post(post, place)["state"] == "AMBIGUOUS"
    matched = match_post(post | {"caption": "대전 여행에서 본 #인쇄거리"}, place)
    assert matched["state"] == "VERIFIED"
    assert matched["interpretation"] == "AUTOMATED_ASSOCIATION_NOT_VERIFIED_VISIT"
    assert match_post(post | {"caption": "대구의 인쇄거리"}, place)["state"] == "AMBIGUOUS"


def test_wrong_requested_tag_is_not_reassigned_by_a_matching_word():
    p = {"primary_tag": "뮤지엄엑스", "region": "강원특별자치도 속초시"}
    row = {
        "inputUrl": "https://www.instagram.com/explore/tags/다른장소/",
        "caption": "속초 뮤지엄엑스도 가보고 싶다.",
    }
    assert match_post(row, p)["state"] == "NOT_MATCHED"
    assert region_markers(p["region"]) == ("강원", "속초")
