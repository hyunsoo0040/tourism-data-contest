"""Field semantics and text preservation before any model sees source evidence."""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass

from itda.contracts.source_assessment import ClaimKind, SourceEvidence, SourceService

SOURCE_AUTHORITY_VERSION = "source-authority-v2"
FIELD_MEANINGS = {
    "heritage1": "세계문화유산 지정 여부 (국가·지방 문화재 전체 여부가 아님)",
    "heritage2": "세계자연유산 지정 여부 (자연환경 유무가 아님)",
    "heritage3": "세계기록유산 지정 여부 (역사성 유무가 아님)",
    "fairday": "공급자가 기재한 영업 요일 또는 장날. 연중무휴로 확대하지 않음",
    "restdate": "공급자가 기재한 휴무 안내. 누락은 휴무 없음이 아님",
    "restdateshopping": "공급자가 기재한 휴무 안내. 누락은 휴무 없음이 아님",
    "cnctrRate": "해당 관광지의 붐비는 시기 대비 상대적 방문 집중 예측. 현장 인원·밀도가 아님",
    "touNum": "해당 지역·일자·방문자 구분의 이동통신 기반 추정값. 개별 장소 입장객이 아님",
    "crsTotlRqrmHour": "코스 전체의 소요 시간 (분). 개별 관광지 체류 시간이 아님",
    "crsDstnc": "코스 전체의 거리 (km). 개별 관광지 내부 보행 거리가 아님",
}

_HTML_TAG = re.compile(
    r"</?(?:br|p|div|span|a|b|strong|em|i|ul|ol|li|table|tbody|tr|td|th|h[1-6]|sup|sub)"
    r"(?=[\s/>])[^>]*>",
    re.IGNORECASE,
)
_HIDDEN_HTML = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)

# M6 describes changes in the experience across time, not business availability.
# This is a conservative evidence gate, not a learned score or an entailment label.
# Match the actual citation (never an uncited sentence elsewhere in the excerpt).
_EXPERIENCE_TIME = re.compile(
    r"계절|봄|여름|가을|겨울|수확철|개화|만개|벚꽃|단풍|일출|일몰|해돋이|해넘이|"
    r"야경|야간|밤(?:에|에는|이면|의|하늘)|낮(?:에|에는|의)|해질|노을|황혼|새벽"
)
_EXPERIENCE_CONTENT = re.compile(
    r"피서|풍경|경관|절경|꽃|식물|단풍|야경|일출|일몰|해돋이|해넘이|노을|"
    r"별(?:빛|을|이|자리)|은하수|감상|관람|즐|체험|물놀이|수영|눈썰매|빙어|빙벽|"
    r"스키|재료|메뉴|디자인|따기|수확|사진|나들이|매력|아름다|산책"
)


def supports_experience_time(quote: str) -> bool:
    """Require a cited seasonal/day-night experience cue, including explicit constancy.

    An operating calendar, an assumed overnight stay, or a queue at lunchtime
    cannot establish M6. Rejected text remains available to its proper consumer.
    """
    return any(
        _EXPERIENCE_TIME.search(sentence) and _EXPERIENCE_CONTENT.search(sentence)
        for sentence in re.split(r"[.!?。！？;\n]+", quote)
    )


@dataclass(frozen=True)
class PreparedSourceText:
    original_sha256: str
    cleaned_sha256: str
    original_chars: int
    cleaned_chars: int
    used_chars: int
    truncated: bool
    text: str


def prepare_source_text(value: str, *, character_limit: int = 4_000) -> PreparedSourceText:
    if character_limit <= 0 or character_limit > 8_000:
        raise ValueError("invalid source character limit")
    cleaned = _HTML_TAG.sub(" ", _HIDDEN_HTML.sub(" ", value))
    cleaned = re.sub(r"\s+", " ", html.unescape(cleaned)).strip()
    excerpt = cleaned[:character_limit]
    return PreparedSourceText(
        original_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        cleaned_sha256=hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
        original_chars=len(value),
        cleaned_chars=len(cleaned),
        used_chars=len(excerpt),
        truncated=len(cleaned) > len(excerpt),
        text=excerpt,
    )


def source_role_description(service: SourceService) -> str:
    return {
        SourceService.TOUR: "공식 관광 설명·시설·운영 안내. 이후 현장 상태는 미확인.",
        SourceService.ODII: "관광 해설·서사 대본. 방문 후기·혼잡 실측·운영 정보가 아님.",
        SourceService.GALLERY: "관광사진과 촬영일·제목 메타데이터. 픽셀은 보이는 분위기만 판단.",
        SourceService.ACCESSIBILITY: "공식 시설 안내. 대여·접근성, 일부 구간·전체를 구분.",
        SourceService.CAMPING: "캠핑장 등록·시설·운영 안내. 현재 예약 가능 여부가 아님.",
        SourceService.WALKING: "코스 거리·분 단위 시간·난이도. 장소 전체 접근성이 아님.",
        SourceService.CONCENTRATION: "장소 내 날짜별 상대적 방문 집중 예측. 현장 실측이 아님.",
        SourceService.VISITORS: "지역·일자·구분별 방문 추정. 장소별 현장 인원이 아님.",
        SourceService.RELATED: "내비게이션 기반 연관 방문 관계. 장소의 품질·개인 취향 점수가 아님.",
        SourceService.DEMAND: "지역·월별 관광 체류·소비 지표. 개인 지출·장소별 체류 시간이 아님.",
    }[service]


def supports_dimension(evidence: SourceEvidence, dimension: str) -> bool:
    """Additional dimension scope; a valid source ID alone never grants every trait."""
    if evidence.modality == "IMAGE_PIXELS":
        return False
    if dimension == "M3":
        return evidence.authorizes(ClaimKind.CROWD)
    if evidence.receipt.service == SourceService.ODII:
        return dimension in {"H1", "H3", "H4", "R4"}
    if evidence.source_field in {"heritage1", "heritage2", "heritage3"}:
        # A specific world-designation flag is not an independent experience score.
        return False
    if evidence.receipt.service not in {SourceService.TOUR, SourceService.CAMPING}:
        return False
    if evidence.source_field in {
        "fairday",
        "opentime",
        "opentimefood",
        "opentimeculture",
        "restdate",
        "restdateshopping",
    }:
        return False
    if not evidence.authorizes(ClaimKind.EXPERIENCE):
        return False
    return dimension != "M6" or supports_experience_time(evidence.quote)
