"""Generate contracts/questionnaire-v2.json from the frozen upstream scenario copy."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

AXIS = {
    "history": "HISTORY_TRADITION",
    "image": "EMOTION_IMAGE",
    "rest": "REST_IMMERSION",
}

RESULT_TYPES = {
    "HISTORY_TRADITION": {
        "name_ko": "객관적 진정성",
        "character_ko": "오리지널 시커",
        "role_ko": "Original Seeker | 가치 발견가",
        "character_image": "./assets/characters/original-seeker.jpg",
        "lens_ko": (
            "장소가 오랫동안 간직해 온 고유한 가치와 진짜 모습을 중요하게 여깁니다."
        ),
        "description_ko": (
            "장소 자체와 그곳의 고유한 특성, 새롭게 발견한 맥락에서 여행의 의미를 찾는 여행자입니다."
        ),
        "recommend_ko": (
            "지역의 이야기, 생활문화, 오래된 거리, 해설이 있는 관광지처럼 장소의 본래 매력을 "
            "깊게 살필 수 있는 코스가 잘 맞습니다."
        ),
    },
    "EMOTION_IMAGE": {
        "name_ko": "구성적 진정성",
        "character_ko": "무드 위버",
        "role_ko": "Mood Weaver | 장면 수집가",
        "character_image": "./assets/characters/mood-weaver.jpg",
        "lens_ko": (
            "기대와 이미지, 사람들이 만들어낸 의미 속에서 여행의 특별함을 발견합니다."
        ),
        "description_ko": (
            "관광객과 사회가 부여한 의미, 기대했던 분위기, 기억하고 싶은 장면 속에서 여행의 "
            "의미를 찾는 여행자입니다."
        ),
        "recommend_ko": (
            "우연한 장면, 분위기 좋은 거리, 다시 보고 싶은 풍경처럼 나만의 해석과 기억을 쌓을 "
            "수 있는 장소가 잘 맞습니다."
        ),
    },
    "REST_IMMERSION": {
        "name_ko": "실존적 진정성",
        "character_ko": "플로우 워커",
        "role_ko": "Flow Walker | 순간 여행가",
        "character_image": "./assets/characters/flow-walker.jpg",
        "lens_ko": (
            "장소 자체보다 그곳에서 느끼는 감정과 경험을 더 중요하게 여깁니다."
        ),
        "description_ko": (
            "자신의 감정, 여유, 몰입 경험을 통해 여행이 나에게 남기는 감각을 중요하게 보는 "
            "여행자입니다."
        ),
        "recommend_ko": (
            "잠시 멈춰 서기 좋은 공간, 천천히 머물 수 있는 산책길, 기분의 흐름에 따라 움직일 "
            "수 있는 여유로운 코스가 잘 맞습니다."
        ),
    },
}


def _extract_questions(source_html: Path) -> list[dict[str, object]]:
    raw = source_html.read_text(encoding="utf-8")
    match = re.search(r"const questions = (\[.*?\n    \]);", raw, re.S)
    if match is None:
        raise SystemExit("questions array not found in source html")
    js_array = re.sub(r"(\w+):", r'"\1":', match.group(1)).replace("'", '"')
    return json.loads(js_array)  # type: ignore[no-any-return]


def build_payload(source_html: Path) -> dict[str, object]:
    upstream = _extract_questions(source_html)
    if len(upstream) != 12:
        raise SystemExit(f"expected 12 upstream questions, found {len(upstream)}")
    questions: list[dict[str, object]] = []
    for ordinal, question in enumerate(upstream, start=1):
        if len(question["options"]) != 3:  # type: ignore[arg-type]
            raise SystemExit(f"q{ordinal} does not have exactly 3 options")
        options: list[dict[str, object]] = []
        for value, option in enumerate(question["options"], start=1):  # type: ignore[union-attr]
            options.append(
                {
                    "choice_id": f"q{ordinal}o{value}",
                    "value": value,
                    "text_ko": option["text"],
                    "keywords_ko": list(option["keywords"]),
                    "axis": AXIS[next(iter(option["weights"]))],
                }
            )
        questions.append(
            {
                "question_id": f"q{ordinal}",
                "ordinal": ordinal,
                "title_ko": question["title"],
                "description_ko": question["desc"],
                "options": options,
            }
        )
    return {
        "questionnaire_version": "questionnaire-v2",
        "scoring_version": "choice-bp-v2",
        "description_template_version": "current-trip-expectation-v1",
        "question_order": list(range(1, 13)),
        "questions": questions,
        "axis_tie_break": ["HISTORY_TRADITION", "EMOTION_IMAGE", "REST_IMMERSION"],
        "axis_display": [
            {
                "axis": "HISTORY_TRADITION",
                "label_ko": "역사·전통",
                "connective_ko": "역사·전통과",
            },
            {
                "axis": "EMOTION_IMAGE",
                "label_ko": "감성·이미지",
                "connective_ko": "감성·이미지와",
            },
            {
                "axis": "REST_IMMERSION",
                "label_ko": "휴식·몰입",
                "connective_ko": "휴식·몰입과",
            },
        ],
        "description_template_ko": (
            "이번 여행에서는 {first_with_particle} {second} 경험을 더 기대하고 있어요."
        ),
        "result_types": RESULT_TYPES,
    }


def main() -> None:
    source_html = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    rendered = json.dumps(
        build_payload(source_html), ensure_ascii=False, indent=2, sort_keys=True
    )
    destination.write_text(rendered + "\n", encoding="utf-8")
    print(f"wrote {destination} ({len(rendered)} chars)")


if __name__ == "__main__":
    main()
