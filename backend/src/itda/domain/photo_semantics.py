"""Server-owned photo anchors on the same M1–M6 scales as place analysis.

These are explicit preference anchors, not estimates of recognition accuracy.
Unrecognized words and old synthetic evidence never manufacture a number.
"""

import unicodedata
from dataclasses import dataclass
from typing import Final

PHOTO_SEMANTIC_VERSION: Final[str] = "photo-semantics-v2"


@dataclass(frozen=True, slots=True)
class PhotoSemanticAnchor:
    semantic_id: str
    trait_id: str
    text_ko: str
    value: int


PHOTO_SEMANTIC_ANCHORS: Final[tuple[PhotoSemanticAnchor, ...]] = (
    PhotoSemanticAnchor("M1.preserved", "M1", "원형·보존 중심", 0),
    PhotoSemanticAnchor("M1.reinterpreted", "M1", "현대적 재해석 중심", 100),
    PhotoSemanticAnchor("M2.local", "M2", "생활·로컬 중심", 0),
    PhotoSemanticAnchor("M2.tourism", "M2", "관광·상업 중심", 100),
    PhotoSemanticAnchor("M3.quiet", "M3", "한적함", 0),
    PhotoSemanticAnchor("M3.crowded", "M3", "혼잡함", 100),
    PhotoSemanticAnchor("M4.viewing", "M4", "감상·촬영", 0),
    PhotoSemanticAnchor("M4.participation", "M4", "참여·체험", 100),
    PhotoSemanticAnchor("M5.short_visit", "M5", "짧은 관람", 0),
    PhotoSemanticAnchor("M5.long_stay", "M5", "산책·장시간 체류", 100),
    PhotoSemanticAnchor("M6.flexible_time", "M6", "시간 영향 적음", 0),
    PhotoSemanticAnchor("M6.time_dependent", "M6", "야간·계절·특정 시간 의존", 100),
)
_BY_ID = {anchor.semantic_id: anchor for anchor in PHOTO_SEMANTIC_ANCHORS}


def _normalized(value: str) -> str:
    return "".join(unicodedata.normalize("NFKC", value).split())


def resolve_photo_semantic(trait_id: str, phrase_or_id: str) -> PhotoSemanticAnchor | None:
    normalized = _normalized(phrase_or_id)
    return next(
        (
            anchor
            for anchor in PHOTO_SEMANTIC_ANCHORS
            if anchor.trait_id == trait_id
            and normalized in (anchor.semantic_id, _normalized(anchor.text_ko))
        ),
        None,
    )


def trusted_photo_value(
    *,
    trait_id: str,
    text_ko: str,
    semantic_id: str | None,
    semantic_version: str | None,
    analysis_kind: str,
    provider_id: str | None,
) -> int | None:
    """Resolve confirmed text only after checking stored provider provenance.

    A supported user edit may switch anchors within the same dimension.
    Stored original semantic identity must still identify that dimension.
    This function consumes server-persisted metadata, never browser fields.
    """
    original = _BY_ID.get(semantic_id or "")
    if (
        analysis_kind != "semantic"
        or semantic_version != PHOTO_SEMANTIC_VERSION
        or not provider_id
        or "synthetic" in provider_id.casefold()
        or original is None
        or original.trait_id != trait_id
    ):
        return None
    resolved = resolve_photo_semantic(trait_id, text_ko)
    return None if resolved is None else resolved.value
