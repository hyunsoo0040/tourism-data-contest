"""Operational definitions, observable anchors and counterexamples for H/E/R."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Final, Literal

from itda.domain.canonical import canonical_sha256

Axis = Literal["H", "E", "R"]
FacetKey = Literal[
    "H.a", "H.b", "H.c", "H.d", "E.a", "E.b", "E.c", "E.d", "R.a", "R.b", "R.c", "R.d"
]
CONSTRUCT_VERSION: Final = "authenticity-construct-v1"
RUBRIC_VERSION: Final = "authenticity-rubric-v1"
AUTHORITY_VERSION: Final = "authenticity-authority-v1"
AXES: tuple[Axis, ...] = ("H", "E", "R")
AXIS_THEORY = {"H": "객관적 진정성 기반", "E": "구성적 진정성 기반", "R": "실존적 진정성 기반"}
# Preserve current public labels until a separate copy decision is made.
AXIS_LABELS = {"H": "대상•원형형", "E": "의미•이미지형", "R": "자기•몰입형"}
UNKNOWN_RULE = (
    "자료에 언급이 없거나 대상·의미·현재성·출처 범위가 불명확하면 UNKNOWN이다. "
    "0은 해당 경험이 낮음을 직접 뒷받침하는 근거가 있을 때만 사용한다."
)


@dataclass(frozen=True)
class FacetDefinition:
    key: FacetKey
    title: str
    question: str
    anchors: tuple[str, str, str, str, str]
    counterexample: str
    claims: tuple[str, ...]
    core: bool = False


FACETS: tuple[FacetDefinition, ...] = (
    FacetDefinition(
        "H.a",
        "원형·유산과의 접촉",
        "확인된 실제 원형·유산을 방문자가 경험할 수 있는가?",
        (
            "원형·유산 접촉이 없다고 명시",
            "원형 일부와 제한적 접촉",
            "확인된 원형·유산을 관람",
            "원형·유산의 공간이나 실물을 구체적으로 탐구",
            "원형·유산과의 접촉이 방문 경험의 중심",
        ),
        "새로 지은 전통풍 건물의 사진은 문화유산의 진위·원형을 증명하지 않는다.",
        ("HERITAGE_FACT",),
        True,
    ),
    FacetDefinition(
        "H.b",
        "역사·출처의 구체성",
        "그 장소의 실제 역사와 출처를 이해할 수 있는가?",
        (
            "역사 맥락을 다루지 않는다고 명시",
            "관련 연혁·유래를 간단히 소개",
            "그 장소의 사건·인물 맥락 제시",
            "여러 맥락을 대상과 연결해 설명",
            "구체적 역사 맥락의 탐구가 방문 경험의 중심",
        ),
        "제작사의 다른 박물관 납품 실적이나 단순 개관 연도는 이 장소의 역사 경험이 아니다.",
        ("HISTORICAL_NARRATIVE",),
    ),
    FacetDefinition(
        "H.c",
        "전통의 실제 지속",
        "지역 주체의 전승·생활문화와 실제로 연결되는가?",
        (
            "실제 전승이 아닌 재현만 제공한다고 명시",
            "전승 흔적을 제한적으로 접함",
            "확인된 전승·생활문화를 관람",
            "실제 지역 주체의 지속 활동을 경험",
            "전승·생활문화와의 직접 연결이 방문 경험의 중심",
        ),
        "전통풍 장식이나 옛 교육기관이라는 사실만으로 현재의 전승 활동을 추정하지 않는다.",
        ("LIVING_TRADITION",),
        True,
    ),
    FacetDefinition(
        "H.d",
        "원형 맥락의 탐구",
        "원형·유산·전통에 연결된 해설과 학습이 가능한가?",
        (
            "관련 해설·탐구를 제공하지 않는다고 명시",
            "짧은 역사 안내",
            "유산·전통에 연결된 설명·전시",
            "여러 자료·해설로 역사 맥락을 탐구",
            "원형·전통에 대한 깊은 해설·탐구가 중심",
        ),
        "일반 독서교실·과학체험·세계 문화 강연만으로 원형과 연결된 역사 학습이라 하지 않는다.",
        ("HERITAGE_INTERPRETATION",),
    ),
    FacetDefinition(
        "E.a",
        "공유되는 상징·의미",
        "그 장소에 어떤 이미지와 상징적 의미가 부여되는가?",
        (
            "해당 상징적 의미와의 연결이 없다고 명시",
            "장소에 연결된 간단한 이미지 표현",
            "구체적인 이미지·이야기가 장소와 연결",
            "여러 표현·장면에서 일관된 의미를 확인",
            "특정 이미지·상징을 경험하는 것이 방문 경험의 중심",
        ),
        "사람이 많이 찾거나 사진이 예쁘다는 사실만으로 공유되는 의미의 내용을 만들지 않는다.",
        ("REPRESENTED_MEANING",),
        True,
    ),
    FacetDefinition(
        "E.b",
        "매체를 통한 이미지 유통",
        "장소의 이미지가 어떤 매체를 통해 재현·확산되는가?",
        (
            "해당 매체·이미지와의 관련성이 없다고 확인",
            "명시된 한 매체의 장소 이미지 표현",
            "확인된 작품·홍보·SNS와 장소 이미지의 연결",
            "반복되는 매체 표현과 유통의 근거",
            "매체를 통해 형성된 이미지의 경험이 방문 목적의 중심",
        ),
        "해시태그 게시물 수는 확산의 대리 지표이며 의미의 내용·방문객 수·만족도가 아니다.",
        ("MEDIA_REPRESENTATION",),
    ),
    FacetDefinition(
        "E.c",
        "이미지의 시각적 표현",
        "외관·경관·연출이 장소의 이미지를 어떻게 표현하는가?",
        (
            "해당 시각적 표현이 약함을 직접 관찰·확인",
            "제한된 색·빛·형태의 표현",
            "장면에서 구별되는 시각적 성격",
            "분명한 외관·경관·연출의 표현",
            "일관된 시각적 성격·연출이 장면을 지배",
        ),
        "선명한 색이 적다고 매력이 낮은 것은 아니다. 시각적 성격의 표현을 평가한다.",
        ("VISUAL_EXPRESSION", "VISUAL_APPEARANCE"),
    ),
    FacetDefinition(
        "E.d",
        "이미지의 체험·재현",
        "대표 장면·구도·이야기를 현장에서 경험하고 재현할 수 있는가?",
        (
            "대표 이미지·장면을 현장에서 경험할 수 없다고 명시",
            "관련 장면을 제한적으로 관람",
            "대표 장면·상징을 직접 경험",
            "촬영·참여로 이미지나 장면을 재현",
            "이미지·이야기의 체험과 재현이 방문 경험의 중심",
        ),
        (
            "한 장의 사진으로 특정 구도가 유행하거나 "
            "모든 방문자가 같은 의미를 느낀다고 추정하지 않는다."
        ),
        ("IMAGE_ENACTMENT",),
        True,
    ),
    FacetDefinition(
        "R.a",
        "일상에서 벗어날 여지",
        "자율적 탐색·여유·자기 선택을 지원하는 경험이 있는가?",
        (
            "자율 탐색·선택이 제한된다고 명시",
            "짧고 제한된 자유 선택",
            "자율적으로 선택·탐색할 기회",
            "여유롭게 자신의 방식으로 탐색",
            "자율적 탐색과 일상 이탈의 경험이 중심",
        ),
        "외진 위치·무료 입장·운영시간만으로 자유나 여유를 추정하지 않는다.",
        ("AUTONOMOUS_ACTIVITY",),
        True,
    ),
    FacetDefinition(
        "R.b",
        "회복을 지원하는 환경",
        "자연·시각적 저자극·머무를 환경의 근거가 있는가?",
        (
            "해당 환경 단서가 약함을 직접 관찰·확인",
            "제한적인 환경 단서",
            "자연·환경 단서를 확인",
            "자연·시각적 저자극 환경이 두드러짐",
            "자연·환경 단서가 장면 또는 공간을 지배",
        ),
        "녹지·물 사진과 힐링 홍보 문구로 실제 고요함·혼잡·심리적 회복을 확정하지 않는다.",
        ("ENVIRONMENT", "VISUAL_APPEARANCE"),
        True,
    ),
    FacetDefinition(
        "R.c",
        "참여·도전·몰입",
        "만들기·신체 활동·탐방 등 집중할 활동의 기회가 있는가?",
        (
            "참여·집중 활동을 제공하지 않는다고 명시",
            "제한된 체험 기회",
            "구체적인 참여·탐방 활동",
            "지속적으로 참여·도전할 활동",
            "참여·도전·집중할 활동이 방문 경험의 중심",
        ),
        "체험 활동의 존재와 방문자가 실제로 몰입했다는 경험은 구분한다.",
        ("PARTICIPATORY_ACTIVITY",),
        True,
    ),
    FacetDefinition(
        "R.d",
        "관계·자기표현",
        "교류·공동 활동·자기표현의 기회를 제공하는가?",
        (
            "교류·자기표현 활동이 제한된다고 명시",
            "제한된 공동 활동",
            "구체적인 교류·표현 기회",
            "함께 만들거나 자신을 표현할 활동이 풍부",
            "교류·공동 활동·자기표현이 방문 경험의 중심",
        ),
        "사진에 단체 관광객이 있거나 가족 방문을 권장한다고 유대감을 추정하지 않는다.",
        ("RELATIONAL_ACTIVITY",),
        True,
    ),
)
FACET_BY_KEY = {row.key: row for row in FACETS}
FACET_KEYS = tuple(row.key for row in FACETS)
RUBRIC_PAYLOAD = {
    "construct_version": CONSTRUCT_VERSION,
    "rubric_version": RUBRIC_VERSION,
    "authority_version": AUTHORITY_VERSION,
    "axes": AXIS_THEORY,
    "unknown": UNKNOWN_RULE,
    "interpretation": "장소가 해당 경험을 지원하는 요소; 실제로 느낀 진정성은 사람의 응답으로 평가",
    "facets": [asdict(row) for row in FACETS],
}
RUBRIC_SHA256 = canonical_sha256(RUBRIC_PAYLOAD)
