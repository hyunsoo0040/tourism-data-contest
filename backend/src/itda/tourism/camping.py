"""Complete-city camping discovery and conservative published facility facts."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from itda.collectors.kto_camping import CampingClient
from itda.contracts.grounded_recommendation import RequiredFacility
from itda.contracts.place_enrichment import CampingContext, confirmed_facility_exclusions
from itda.contracts.source_assessment import (
    ClaimKind,
    PlaceMatch,
    SourceEvidence,
    SourceObservation,
    SourceService,
    SupportState,
)
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import (
    CanonicalTourismPlace,
    _assertion,
    _step_free_assertion,
    match_place,
    region_location_matches,
)
from itda.tourism.temporal import TemporalContextService, TemporalPolicy
from itda.tourism.temporal_cache import TemporalSourceSnapshot

_FACTS = {
    "accessible_parking": ClaimKind.FACILITY,
    "accessible_toilet": ClaimKind.FACILITY,
    "wheelchair_rental": ClaimKind.FACILITY,
    "stroller_rental": ClaimKind.FACILITY,
    "step_free_entry": ClaimKind.FACILITY,
    "toilet_count": ClaimKind.FACILITY,
    "shower_count": ClaimKind.FACILITY,
    "washing_stand_count": ClaimKind.FACILITY,
    "toilet_available": ClaimKind.FACILITY,
    "caravan_toilet": ClaimKind.FACILITY,
    "glamping_toilet": ClaimKind.FACILITY,
    "registered_operating_status": ClaimKind.OPERATING,
    "published_operating_days": ClaimKind.OPERATING,
    "published_operating_seasons": ClaimKind.OPERATING,
    "published_closure_start": ClaimKind.OPERATING,
    "published_closure_end": ClaimKind.OPERATING,
}


def unknown_camp_facts(reason: str) -> dict[str, SourceObservation]:
    return {
        key: SourceObservation(
            key=key,
            claim=claim,
            state=SupportState.UNKNOWN,
            value=None,
            evidence=(),
            reference_date=None,
            reason=reason,
        )
        for key, claim in _FACTS.items()
    }


def safe_reference_url(value: object, *, hostname: str | None = None) -> str | None:
    rendered = str(value or "").strip()
    if len(rendered) > 2000 or any(ord(char) < 32 for char in rendered):
        return None
    try:
        url = urlsplit(rendered)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
            return None
        if hostname and (url.scheme != "https" or url.hostname != hostname):
            return None
    except ValueError:
        return None
    return rendered


def source_modified_date(value: object) -> date | None:
    rendered = str(value or "")
    for pattern in ("%Y-%m-%d", "%Y%m%d%H%M%S", "%Y%m%d"):
        try:
            return datetime.strptime(rendered, pattern).date()
        except ValueError:
            continue
    return None


class CampingEnrichmentService:
    def __init__(
        self,
        *,
        places: Sequence[CanonicalTourismPlace],
        client: CampingClient | None,
        loader: TemporalContextService | None = None,
        policy: TemporalPolicy | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        max_source_age_days: int = 180,
    ) -> None:
        self.places = {row.place_id: row for row in places}
        if len(self.places) != len(places) or not 1 <= max_source_age_days <= 730:
            raise ValueError("invalid canonical camp catalog or bounded freshness policy")
        self.client = client
        self.clock = clock
        self.max_source_age_days = max_source_age_days
        self.loader = loader or TemporalContextService(places=places, policy=policy, clock=clock)

    def get_context_with_sources(
        self, place_id: str
    ) -> tuple[CampingContext, tuple[TemporalSourceSnapshot, ...]]:
        place = self.places[place_id]
        snapshot = self.loader.collect_source_batch(
            SourceService.CAMPING, "basedList", {}, self.client
        )
        # Exhaust the national catalog; exact name and coordinates/address establish locality.
        rows = [
            row
            for row in snapshot.rows
            if region_location_matches(place, f"{row.get('doNm', '')} {row.get('sigunguNm', '')}")
        ]
        projected = [
            {
                "contentid": row.get("contentId"),
                "title": row.get("facltNm"),
                "addr1": row.get("addr1"),
                "mapx": row.get("mapX"),
                "mapy": row.get("mapY"),
            }
            for row in rows
        ]
        identity = match_place(place, projected)
        match = PlaceMatch.model_validate(
            {**identity.model_dump(mode="json"), "service": SourceService.CAMPING.value}
        )
        reason: str = (
            snapshot.reason
            if not snapshot.complete
            else "PLACE_NOT_MATCHED"
            if match.state == "NOT_MATCHED"
            else "AMBIGUOUS_MATCH"
            if match.state == "AMBIGUOUS"
            else "NONE"
        )
        facts = unknown_camp_facts("정확하게 연결된 최신 공식 시설 근거가 없습니다.")
        modified = None
        booking_url = None
        matched = [row for row in rows if str(row.get("contentId")) == match.provider_entity_id]
        now = self.clock()
        today = now.astimezone(ZoneInfo("Asia/Seoul")).date()
        if reason == "NONE" and len(matched) != 1:
            reason = "AMBIGUOUS_MATCH"
        if reason == "NONE":
            row = matched[0]
            modified = source_modified_date(row.get("modifiedtime"))
            if (
                now >= snapshot.expires_at
                or modified
                and (today - modified).days > self.max_source_age_days
            ):
                reason = "STALE"
            elif modified and modified > today:
                reason = "INVALID_SOURCE_DATE"
            else:
                # Locate the actual page containing this row; never cite a different page.
                raw_response = next(
                    response
                    for response in snapshot.raw_responses
                    if any(item == row for item in _response_items(response))
                )
                receipt = next(
                    receipt
                    for receipt in snapshot.receipts
                    if receipt.response_sha256 == raw_response["raw_response_sha256"]
                )

                def record(key: str, field: str, value: int | bool | str) -> None:
                    raw_value = row.get(field)
                    excerpt = str(raw_value if raw_value is not None else "").strip()
                    if not excerpt or len(excerpt) > 4000:
                        return
                    evidence = SourceEvidence(
                        evidence_id="evidence:"
                        + canonical_sha256(
                            {
                                "receipt": receipt.model_dump(mode="json"),
                                "field": field,
                                "place": place_id,
                                "excerpt": excerpt,
                            }
                        ),
                        receipt=receipt,
                        place_match=match,
                        scope="PLACE",
                        modality="STRUCTURED",
                        source_field=field,
                        excerpt=excerpt,
                        quote=excerpt,
                    )
                    facts[key] = SourceObservation(
                        key=key,
                        claim=_FACTS[key],
                        state=SupportState.FACT,
                        value=value,
                        evidence=(evidence,),
                        reference_date=modified or receipt.retrieved_at.date(),
                        reason=(
                            "고캠핑의 해당 등록 필드 범위에서 확인한 정보입니다. "
                            "현장 상태나 예약 가능 수량을 보증하지 않습니다."
                        ),
                    )

                for key, field in (
                    ("toilet_count", "toiletCo"),
                    ("shower_count", "swrmCo"),
                    ("washing_stand_count", "wtrplCo"),
                ):
                    raw = str(row.get(field) if row.get(field) is not None else "").strip()
                    if re.fullmatch(r"\d{1,7}", raw):
                        record(key, field, int(raw))
                        if field == "toiletCo" and int(raw) > 0:
                            record("toilet_available", field, True)
                for key, field in (
                    ("registered_operating_status", "manageSttus"),
                    ("published_operating_days", "operDeCl"),
                    ("published_operating_seasons", "operPdCl"),
                    ("published_closure_start", "hvofBgnde"),
                    ("published_closure_end", "hvofEnddle"),
                ):
                    raw = str(row.get(field) or "").strip()
                    if raw:
                        record(key, field, raw)
                for key, field in (
                    ("caravan_toilet", "caravInnerFclty"),
                    ("glamping_toilet", "glampInnerFclty"),
                ):
                    text = str(row.get(field) or "")
                    if "화장실" in text and not re.search(r"없|불가|미확인|문의", text):
                        record(key, field, True)
                conflicts: set[str] = set()
                for field in ("sbrsEtc", "posblFcltyEtc", "eqpmnLendCl"):
                    text = str(row.get(field) or "").strip()
                    for key, subject, rental in (
                        ("accessible_toilet", r"장애인(?:전용)?화장실", False),
                        ("accessible_parking", r"장애인(?:전용)?주차(?:구역|장|공간)?", False),
                        ("wheelchair_rental", r"휠체어", True),
                        ("stroller_rental", r"유모차", True),
                    ):
                        value = _assertion(text, subject, rental=rental)
                        if value is not None and key not in conflicts:
                            previous = facts[key]
                            if previous.value is not None and previous.value != value:
                                conflicts.add(key)
                                facts[key] = unknown_camp_facts(
                                    "공식 필드 간 설명이 상충하여 확인을 보류합니다."
                                )[key]
                            else:
                                record(key, field, value)
                    step_free = _step_free_assertion(text)
                    if step_free is not None:
                        previous = facts["step_free_entry"]
                        if previous.value is not None and previous.value != step_free:
                            conflicts.add("step_free_entry")
                        if "step_free_entry" in conflicts:
                            facts["step_free_entry"] = unknown_camp_facts(
                                "출입구 정보가 상충합니다."
                            )["step_free_entry"]
                        else:
                            record("step_free_entry", field, step_free)
                booking_url = safe_reference_url(row.get("resveUrl"))
        known = sum(row.state != SupportState.UNKNOWN for row in facts.values())
        draft = CampingContext.model_construct(
            place_id=place_id,
            state="PARTIAL" if known else "UNKNOWN",
            reason=reason,
            match=match,
            facts=facts,
            source_modified_date=modified,
            booking_url=booking_url,
            source_snapshot_sha256=(canonical_sha256(snapshot.model_dump(mode="json")),),
            receipts=snapshot.receipts,
            retrieved_at=snapshot.retrieved_at,
            expires_at=snapshot.expires_at,
            context_sha256="0" * 64,
        )
        payload = draft.model_dump(mode="json", exclude={"context_sha256"})
        return CampingContext.model_validate(
            {**payload, "context_sha256": canonical_sha256(payload)}
        ), (snapshot,)

    def get_context(self, place_id: str) -> CampingContext:
        return self.get_context_with_sources(place_id)[0]

    def excluded_place_ids(
        self, place_ids: Sequence[str], requirements: Sequence[RequiredFacility]
    ) -> frozenset[str]:
        if not requirements:
            return frozenset()
        return confirmed_facility_exclusions(
            tuple(self.get_context(place_id) for place_id in place_ids), requirements
        )


def _response_items(response: dict[str, object]) -> tuple[dict[str, object], ...]:
    from itda.tourism.accessibility import provider_items

    return provider_items(response.get("payload"))
