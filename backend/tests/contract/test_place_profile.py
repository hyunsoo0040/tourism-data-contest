from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from itda.contracts.place_profile import (
    MISMATCH_TRAIT_SPECS,
    SUBATTRIBUTE_SPECS,
    PlaceProfile,
)

EXPECTED_SUBATTRIBUTES = [
    ("H1", "HISTORY_TRADITION", "역사 서사 밀도", "시대·인물·사건·유래·설화의 풍부성"),
    (
        "H2",
        "HISTORY_TRADITION",
        "문화유산·원형 기반성",
        "유적·전통 건축·보존 흔적·문화유산이 장소의 중심인지",
    ),
    (
        "H3",
        "HISTORY_TRADITION",
        "전통의 지속성",
        "전통생활·의례·공예·지역문화가 현재 경험과 연결되는지",
    ),
    (
        "H4",
        "HISTORY_TRADITION",
        "학습·해설 깊이",
        "전시·해설·오디오가이드·교육 탐색 요소",
    ),
    ("I1", "EMOTION_IMAGE", "시각적 상징성", "랜드마크·독특한 외관·기억되는 장면"),
    ("I2", "EMOTION_IMAGE", "사진·경관 매력", "색감·야경·계절경관·구도·포토존"),
    (
        "I3",
        "EMOTION_IMAGE",
        "현대적 재해석",
        "전통과 현대의 결합·감각적 공간·트렌드",
    ),
    ("I4", "EMOTION_IMAGE", "분위기·감각 경험", "빛·색·공간연출·거리 분위기"),
    ("R1", "REST_IMMERSION", "자연·회복 환경", "숲·물·해변·정원 등 회복 요소"),
    ("R2", "REST_IMMERSION", "산책·체류 적합성", "천천히 걷기·오래 머무르기"),
    ("R3", "REST_IMMERSION", "정적·저자극 가능성", "조용함·여유·혼자 머물기"),
    ("R4", "REST_IMMERSION", "참여·몰입 경험", "체험·감상·탐방·이야기 몰입"),
]

EXPECTED_MISMATCH_TRAITS = [
    ("M1", "공간 성격", "원형·보존 중심", "현대적 재해석 중심"),
    ("M2", "방문객 성격", "생활·로컬 중심", "관광·상업 중심"),
    ("M3", "현장 밀도", "한적함", "혼잡함"),
    ("M4", "경험 방식", "감상·촬영", "참여·체험"),
    ("M5", "체류 방식", "짧은 관람", "산책·장시간 체류"),
    ("M6", "시간 의존성", "시간 영향 적음", "야간·계절·특정 시간 의존"),
]


def _preview_payload() -> dict[str, object]:
    return {
        "place_id": "preview:gyeongju:126166",
        "split": "PREVIEW",
        "source_crosswalk": [
            {
                "provider": "TOUR_API",
                "source_id": "126166",
                "source_url": "https://data.visitkorea.or.kr/page/126166",
                "name_ko": "경주 불국사",
            }
        ],
        "axis_scores": [
            {
                "axis": axis,
                "assessment_status": "NOT_SCORED",
                "score": None,
                "confidence": None,
                "display_label_id": label_id,
                "display_label_ko": label_ko,
                "evidence_ids": [],
            }
            for axis, label_id, label_ko in (
                ("HISTORY_TRADITION", "history-tradition", "역사·전통"),
                ("EMOTION_IMAGE", "emotion-image", "감성·이미지"),
                ("REST_IMMERSION", "rest-immersion", "휴식·몰입"),
            )
        ],
        "subattributes": [
            spec.model_dump(mode="json")
            | {"assessment_status": "NOT_SCORED", "value": None, "evidence_ids": []}
            for spec in SUBATTRIBUTE_SPECS
        ],
        "mismatch_traits": [
            spec.model_dump(mode="json")
            | {"assessment_status": "NOT_SCORED", "value": None, "evidence_ids": []}
            for spec in MISMATCH_TRAIT_SPECS
        ],
        "overall_confidence": None,
        "recommendation_eligible": False,
        "evidence": [],
        "schema_version": "place-profile-v1",
        "questionnaire_version": "questionnaire-v1",
        "scoring_version": "place-scoring-v1",
        "config_hash": "a" * 64,
        "data_version": "preview-data-v1",
        "release_version": "preview-release-v1",
        "source_version": "tour-api-kor-service2-2026-07",
        "display_copy_version": "place-display-v1",
        "created_at": datetime(2026, 7, 22, 12, 0, tzinfo=UTC),
    }


def _evidence_payload() -> dict[str, object]:
    return {
        "evidence_id": "evidence:synthetic:1",
        "provider": "SYNTHETIC",
        "evidence_type": "SYNTHETIC",
        "source_id": "synthetic-source-1",
        "source_url": "https://example.invalid/synthetic-source-1",
        "endpoint": "fixture://place-profile-contract",
        "request_scope": {"fixture": "place-profile-contract"},
        "retrieved_at": datetime(2026, 7, 22, 11, 0, tzinfo=UTC),
        "http_status": 200,
        "raw_response_sha256": "b" * 64,
        "parser_version": "synthetic-parser-v1",
        "source_version": "synthetic-source-v1",
        "excerpt_ko": "스키마 계약 검증을 위한 합성 근거입니다.",
        "rights": {
            "license_code": "NOT_APPLICABLE",
            "asset_usage_status": "NOT_APPLICABLE",
            "attribution_ko": "합성 테스트 자료",
            "author_or_photographer": None,
        },
    }


def _scored_payload() -> dict[str, object]:
    payload = _preview_payload()
    payload["place_id"] = "synthetic:place-profile:1"
    payload["split"] = "SYNTHETIC"
    payload["source_crosswalk"] = [
        {
            "provider": "SYNTHETIC",
            "source_id": "synthetic-source-1",
            "source_url": "https://example.invalid/synthetic-source-1",
            "name_ko": "합성 계약 장소",
        }
    ]
    payload["axis_scores"] = [
        axis
        | {
            "assessment_status": "SCORED",
            "score": score,
            "confidence": 80,
            "evidence_ids": ["evidence:synthetic:1"],
        }
        for axis, score in zip(payload["axis_scores"], (75, 50, 25), strict=True)  # type: ignore[arg-type]
    ]
    payload["subattributes"] = [
        attribute
        | {
            "assessment_status": "SCORED",
            "value": index % 5,
            "evidence_ids": ["evidence:synthetic:1"],
        }
        for index, attribute in enumerate(payload["subattributes"])  # type: ignore[arg-type]
    ]
    payload["mismatch_traits"] = [
        trait
        | {
            "assessment_status": "SCORED",
            "value": index * 20,
            "evidence_ids": ["evidence:synthetic:1"],
        }
        for index, trait in enumerate(payload["mismatch_traits"])  # type: ignore[arg-type]
    ]
    payload["overall_confidence"] = 80
    payload["recommendation_eligible"] = True
    payload["evidence"] = [_evidence_payload()]
    return payload


def test_canonical_subattribute_vocabulary_is_exact_and_ordered() -> None:
    actual = [
        (spec.attribute_id, spec.axis, spec.label_ko, spec.definition_ko)
        for spec in SUBATTRIBUTE_SPECS
    ]

    assert actual == EXPECTED_SUBATTRIBUTES
    assert all(spec.scale_min == 0 and spec.scale_max == 4 for spec in SUBATTRIBUTE_SPECS)
    assert len({spec.attribute_id for spec in SUBATTRIBUTE_SPECS}) == 12


def test_canonical_mismatch_vocabulary_is_exact_bipolar_and_ordered() -> None:
    actual = [
        (spec.trait_id, spec.label_ko, spec.left_endpoint, spec.right_endpoint)
        for spec in MISMATCH_TRAIT_SPECS
    ]

    assert actual == EXPECTED_MISMATCH_TRAITS
    assert all(spec.scale_kind == "BIPOLAR" for spec in MISMATCH_TRAIT_SPECS)
    assert len({spec.trait_id for spec in MISMATCH_TRAIT_SPECS}) == 6


def test_preview_profile_allows_explicit_not_scored_nulls_and_empty_evidence() -> None:
    profile = PlaceProfile.model_validate(_preview_payload())

    assert profile.split == "PREVIEW"
    assert profile.overall_confidence is None
    assert profile.evidence == ()
    assert all(item.value is None for item in profile.subattributes)
    assert all(item.value is None for item in profile.mismatch_traits)
    assert all(item.score is None for item in profile.axis_scores)
    assert PlaceProfile.model_validate_json(profile.model_dump_json()) == profile


def test_scored_contract_requires_bounded_values_and_resolvable_evidence() -> None:
    profile = PlaceProfile.model_validate(_scored_payload())

    assert [item.score for item in profile.axis_scores] == [75, 50, 25]
    assert profile.overall_confidence == 80
    assert profile.recommendation_eligible is True
    assert {evidence.evidence_id for evidence in profile.evidence} == {"evidence:synthetic:1"}


@pytest.mark.parametrize(
    ("mutate", "error_fragment"),
    [
        (
            lambda payload: payload["subattributes"][0].update(value=5),  # type: ignore[index,union-attr]
            "less than or equal to 4",
        ),
        (
            lambda payload: payload["mismatch_traits"][0].update(left_endpoint="복원 중심"),  # type: ignore[index,union-attr]
            "canonical mismatch trait metadata",
        ),
        (
            lambda payload: payload["axis_scores"][0].update(score=None),  # type: ignore[index,union-attr]
            "SCORED axis requires score and confidence",
        ),
        (
            lambda payload: payload["subattributes"][0].update(  # type: ignore[index,union-attr]
                assessment_status="NOT_SCORED"
            ),
            "NOT_SCORED subattribute requires a null value",
        ),
        (
            lambda payload: (payload.update(split="DEV"), payload.update(evidence=[])),
            "evidence is required outside PREVIEW",
        ),
        (
            lambda payload: payload["evidence"][0].update(  # type: ignore[index,union-attr]
                retrieved_at=datetime(2026, 7, 22, 20, 0, tzinfo=timezone(timedelta(hours=9)))
            ),
            "retrieved_at must use UTC",
        ),
        (
            lambda payload: payload["evidence"][0].update(service_key="secret"),  # type: ignore[index,union-attr]
            "Extra inputs are not permitted",
        ),
        (
            lambda payload: payload["axis_scores"][0].update(score="75"),  # type: ignore[index,union-attr]
            "valid integer",
        ),
    ],
)
def test_invalid_profile_shapes_fail_closed(mutate: object, error_fragment: str) -> None:
    payload = deepcopy(_scored_payload())
    mutate(payload)  # type: ignore[operator]

    with pytest.raises(ValidationError, match=error_fragment):
        PlaceProfile.model_validate(payload)


def test_profile_rejects_noncanonical_order_and_unknown_evidence_reference() -> None:
    reordered = deepcopy(_scored_payload())
    reordered["subattributes"][0], reordered["subattributes"][1] = (  # type: ignore[index]
        reordered["subattributes"][1],  # type: ignore[index]
        reordered["subattributes"][0],  # type: ignore[index]
    )
    unknown_evidence = deepcopy(_scored_payload())
    unknown_evidence["axis_scores"][0]["evidence_ids"] = ["evidence:missing"]  # type: ignore[index]

    with pytest.raises(ValidationError, match="subattributes must use canonical H1-R4 order"):
        PlaceProfile.model_validate(reordered)
    with pytest.raises(ValidationError, match="unknown evidence id"):
        PlaceProfile.model_validate(unknown_evidence)
