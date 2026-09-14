"""Explicit observation-to-claim authority, narrower than source availability."""

from __future__ import annotations

from itda.authenticity.contracts import Claim, Evidence
from itda.authenticity.rubric import FACET_BY_KEY, FacetKey

_DESCRIPTIVE_FIELDS = frozenset(
    {
        "overview",
        "script",
        "infotext",
        "expguide",
        "expguideleports",
        "caption",
        "media_reference",
    }
)
_OFFICIAL = frozenset(Claim) - {Claim.VISUAL_APPEARANCE, Claim.SOCIAL_CIRCULATION}
_ODII = frozenset(
    {
        Claim.HISTORICAL_NARRATIVE,
        Claim.HERITAGE_INTERPRETATION,
        Claim.REPRESENTED_MEANING,
        Claim.MEDIA_REPRESENTATION,
        Claim.IMAGE_ENACTMENT,
        Claim.PARTICIPATORY_ACTIVITY,
    }
)
_SOCIAL = frozenset({Claim.REPRESENTED_MEANING, Claim.MEDIA_REPRESENTATION})


def allowed_claims(record: Evidence) -> frozenset[Claim]:
    if record.state != "AVAILABLE" or record.place_match != "VERIFIED":
        return frozenset()
    if record.modality == "IMAGE":
        return (
            frozenset({Claim.VISUAL_APPEARANCE})
            if record.appearance is not None and record.appearance.state == "OBSERVED"
            else frozenset()
        )
    if record.modality == "COUNT":
        return frozenset({Claim.SOCIAL_CIRCULATION})
    if record.field not in _DESCRIPTIVE_FIELDS:
        return frozenset()
    if record.receipt.provider == "APIFY_INSTAGRAM":
        return _SOCIAL
    if record.receipt.provider == "Odii":
        return _ODII
    if record.receipt.provider == "KorService2":
        if record.source_role in {"OFFICIAL_PROMOTION", "ADVERTISEMENT"}:
            return _SOCIAL | {Claim.VISUAL_EXPRESSION, Claim.IMAGE_ENACTMENT}
        return _OFFICIAL
    return frozenset()


def authorizes_text(record: Evidence, key: FacetKey, claim: Claim) -> bool:
    return (
        record.modality == "TEXT"
        and claim in allowed_claims(record)
        and claim.value in FACET_BY_KEY[key].claims
    )


def allowed_text_facets(record: Evidence) -> tuple[FacetKey, ...]:
    return tuple(
        key
        for key, definition in FACET_BY_KEY.items()
        if record.modality == "TEXT"
        and any(Claim(c) in allowed_claims(record) for c in definition.claims)
    )
