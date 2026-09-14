"""Conservative parsing of collected fields and explicit passages, without model calls.

Exact field/quote matching establishes structural provenance, not human entailment.
No scores, popularity, facility rentals or missing text imply accessible facilities.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.mvp_scored_release import MvpScoredProfile
from itda.contracts.place_facts import (
    FACT_KEYS,
    FactEvidence,
    FactSource,
    PlaceFact,
    PlaceFacts,
)

INTRO_FACT_FIELDS = (
    "parking",
    "parkingculture",
    "parkingleports",
    "parkingshopping",
    "parkingfood",
    "parkinglodging",
    "chkbabycarriage",
    "chkbabycarriageculture",
    "chkbabycarriageleports",
    "chkbabycarriageshopping",
    "expagerange",
    "expagerangeleports",
    "agelimit",
    "usetime",
    "usetimeculture",
    "usetimeleports",
    "opentime",
    "opentimefood",
    "playtime",
    "checkintime",
    "checkouttime",
    "spendtime",
)
_AMBIGUOUS = re.compile(r"여부|확인\s*필요|문의|예정|가능할|불명|미확인|정보\s*없")
_YES = re.compile(r"^(?:가능|있음|있다|운영|제공|Y|YES)$", re.I)
_NO = re.compile(r"(?:주차\s*)?(?:불가|불가능|불허|없음|없다|미제공|미운영|N|NO)", re.I)
_CONDITIONS = ("visit_date_time", "companions", "transport", "walking", "indoor_outdoor", "crowd")


def intro_fact_lines(item: Mapping[str, object]) -> tuple[str, ...]:
    """Keep allowlisted supplied fields only; metadata changes do not change semantics."""
    lines = []
    for field in INTRO_FACT_FIELDS:
        raw = item.get(field)
        if not isinstance(raw, str):
            continue
        value = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", " ", raw))).strip()
        if value:
            lines.append(f"TourAPI {field}: {value[:240]}")
    return tuple(lines)


def _boolean(value: str) -> bool | None:
    if _AMBIGUOUS.search(value):
        return None
    if _NO.fullmatch(value):
        return False
    if _YES.fullmatch(value) or re.fullmatch(r"(?:주차|입장|이용|접근|이동)\s*가능", value):
        return True
    return None


def extract_place_facts(place_id: str, sources: Sequence[FactSource]) -> PlaceFacts:
    found: dict[str, list[tuple[bool | int | str, FactEvidence]]] = {key: [] for key in FACT_KEYS}
    for raw_source in sources:
        source = FactSource.model_validate(raw_source.model_dump(mode="json"))
        if source.place_id != place_id:
            raise ValueError("fact source place binding mismatch")
        if source.provider != "TOUR_API":
            # Odii is narration, not current facility/operating authority. Historical
            # model scores remain sealed; new fact extraction must respect source role.
            continue
        for match in re.finditer(r"[^\n.!?]+", source.excerpt):
            quote = match.group().strip()
            if not quote or len(quote) > 1_000 or _AMBIGUOUS.search(quote):
                continue
            field_match = re.fullmatch(r"TourAPI ([a-z]+): (.+)", quote)
            field = field_match[1] if field_match else None
            text = field_match[2] if field_match else quote
            evidence = FactEvidence(source=source, quote=quote, field_name=field)

            def add(
                key: str,
                value: bool | int | str | None,
                bound_evidence: FactEvidence = evidence,
            ) -> None:
                if value is not None:
                    found[key].append((value, bound_evidence))

            if field and field.startswith("parking"):
                add("parking", _boolean(text))
            elif field and field.startswith("chkbabycarriage"):
                add("stroller_rental", _boolean(text))
            elif field in {
                "usetime",
                "usetimeculture",
                "usetimeleports",
                "opentime",
                "opentimefood",
                "playtime",
            }:
                if re.search(r"\d{1,2}:\d{2}", text):
                    add("opening_hours", text)
            elif field == "spendtime":
                duration = re.fullmatch(r"(?:약\s*)?(\d{1,3})\s*분", text)
                if duration and 0 < int(duration[1]) <= 720:
                    add("visit_minutes", int(duration[1]))
            else:
                # A noun phrase containing "가능" may be negated or qualified by
                # the rest of its sentence. Accept complete simple statements,
                # never a favorable substring from a longer unknown proposition.
                statement = re.sub(r"^소개:\s*", "", text)
                for key, subject in (
                    ("parking", r"주차"),
                    ("child_access", r"(?:어린이|아동|아이)\s*(?:입장|이용)"),
                    ("senior_access", r"(?:어르신|고령자|노약자)\s*(?:입장|이용|접근)"),
                    ("wheelchair_access", r"휠체어\s*(?:이동|접근|이용)"),
                    ("transit_access", r"(?:대중교통|버스|지하철)\s*(?:이용|접근)"),
                ):
                    claim = re.fullmatch(
                        subject + r"\s*(?:이|가|은|는)?\s*(가능|불가|불가능|없음)"
                        r"(?:합니다|하다|입니다)?",
                        statement,
                    )
                    if claim:
                        add(key, _boolean(claim[1]))
                duration = re.fullmatch(
                    r"(?:보행|산책)\s*소요시간\s*(\d{1,3})\s*분(?:입니다)?", statement
                )
                if duration and 0 < int(duration[1]) <= 720:
                    add("walking_minutes", int(duration[1]))
                space = re.fullmatch(
                    r"(실내|야외|실외)\s*(?:공간|전시관|시설|관람)"
                    r"(?:(?:이|가)?\s*(?:있습니다|있다|있음)|입니다|이다|임)?",
                    statement,
                )
                if space:
                    add("indoor_outdoor", "INDOOR" if space[1] == "실내" else "OUTDOOR")
    observations = {}
    for key, rows in found.items():
        values = {str(value) for value, _ in rows}
        supported = bool(rows) and len(values) == 1
        observations[key] = PlaceFact(
            state="FACT" if supported else "UNKNOWN",
            value=rows[0][0] if supported else None,
            evidence=tuple(evidence for _, evidence in rows),
            reason="EXPLICIT_SOURCE_STATEMENT"
            if supported
            else "CONFLICTING_SOURCES"
            if rows
            else "NO_EXPLICIT_SOURCE_STATEMENT",
        )
    return PlaceFacts(place_id=place_id, observations=observations)


@dataclass(frozen=True, slots=True)
class ResolvedPlaceConditions:
    values: dict[str, int | None]
    evidence_ids: dict[str, tuple[str, ...]]
    facts: PlaceFacts


def project_fact_conditions(
    facts: PlaceFacts,
    *,
    companion: str | None = None,
    transport: str | None = None,
) -> ResolvedPlaceConditions:
    values: dict[str, int | None] = dict.fromkeys(_CONDITIONS)
    evidence_ids: dict[str, tuple[str, ...]] = {key: () for key in _CONDITIONS}

    def use(condition: str, fact_key: str, value: int | None) -> None:
        fact = facts.observations[fact_key]
        if fact.state == "FACT" and value is not None:
            values[condition] = value
            evidence_ids[condition] = tuple(
                sorted({row.source.evidence_id for row in fact.evidence})
            )

    companion_fact = {"FAMILY_WITH_CHILDREN": "child_access", "WITH_SENIORS": "senior_access"}.get(
        companion or ""
    )
    if companion_fact:
        observed = facts.observations[companion_fact].value
        use(
            "companions",
            companion_fact,
            100 if observed is True else 0 if observed is False else None,
        )
    transport_fact = {"CAR_OR_TAXI": "parking", "WALK_OR_TRANSIT": "transit_access"}.get(
        transport or ""
    )
    if transport_fact:
        observed = facts.observations[transport_fact].value
        use(
            "transport",
            transport_fact,
            100 if observed is True else 0 if observed is False else None,
        )
    observed = facts.observations["walking_minutes"].value
    if type(observed) is int:
        use("walking", "walking_minutes", 0 if observed <= 30 else 50 if observed <= 60 else 100)
    space = facts.observations["indoor_outdoor"].value
    use(
        "indoor_outdoor",
        "indoor_outdoor",
        0 if space == "INDOOR" else 100 if space == "OUTDOOR" else None,
    )
    return ResolvedPlaceConditions(values=values, evidence_ids=evidence_ids, facts=facts)


def resolve_profile_conditions(
    profile: MvpScoredProfile,
    *,
    companion: str | None = None,
    transport: str | None = None,
    expected_provider_source_ids: Mapping[str, tuple[str, ...]] | None = None,
) -> ResolvedPlaceConditions:
    sources = []
    for excerpt in profile.evidence_excerpts:
        evidence = excerpt.evidence
        if (
            expected_provider_source_ids is not None
            and evidence.provider_source_id
            not in expected_provider_source_ids.get(evidence.provider, ())
        ):
            raise ValueError("fact source provider/place binding mismatch")
        sources.append(
            FactSource(
                place_id=profile.place_id,
                evidence_id=evidence.evidence_id,
                provider=evidence.provider,
                provider_source_id=evidence.provider_source_id,
                excerpt=evidence.excerpt,
                reference_date=evidence.reference_date,
                source_response_sha256=evidence.source_response_sha256,
            )
        )
    return project_fact_conditions(
        extract_place_facts(profile.place_id, sources), companion=companion, transport=transport
    )


def catalog_metadata(catalog: PublicPlaceCatalog, place_id: str) -> dict[str, str] | None:
    for place in catalog.places:
        if place.place_id == place_id:
            category = place.category
            purpose = {
                "음식점": "FOOD",
                "숙박": "LODGING",
                "쇼핑": "SHOPPING",
                "레포츠": "SIGHTSEEING",
                "축제공연행사": "SIGHTSEEING",
                "문화시설": "SIGHTSEEING",
                "관광지": "SIGHTSEEING",
            }.get(category, "UNKNOWN")
            return {"category": category, "purpose": purpose, "region": place.administrative_area}
    return None
