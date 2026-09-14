"""Conservative, exact-place accessibility claims with explicit unknown states.

Published source assertions are not current-site guarantees. Rental availability
does not establish access; partial ramps do not establish whole-property access.
"""

from __future__ import annotations

import hashlib
import math
import re
from base64 import b64decode
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import BoundedSemaphore, Lock
from typing import Annotated, Literal, Self, cast

from pydantic import Field, model_validator

from itda.collectors.base import CollectedResponse, CollectionError
from itda.collectors.kto_accessibility import KorWithService2Client
from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.source_assessment import (
    ClaimKind,
    PlaceMatch,
    SourceEvidence,
    SourceObservation,
    SourceReceipt,
    SourceService,
    SupportState,
)
from itda.domain.canonical import canonical_sha256
from itda.tourism.settings import TourismSettings

FACILITY_KEYS = (
    "accessible_route",
    "accessible_route_segment",
    "accessible_parking",
    "accessible_toilet",
    "wheelchair_rental",
    "stroller_rental",
    "step_free_entry",
)


class CanonicalTourismPlace(StrictContract):
    place_id: StableId
    name_ko: Annotated[str, Field(min_length=1, max_length=300)]
    address: str = ""
    latitude: Annotated[float, Field(ge=-90, le=90)] | None = None
    longitude: Annotated[float, Field(ge=-180, le=180)] | None = None
    region_code: Annotated[str, Field(pattern=r"^\d{5}$")] = "47130"
    region_name: Annotated[
        str | None, Field(min_length=1, max_length=100, exclude_if=lambda value: value is None)
    ] = None
    provider_content_id: StableId | None = None
    aliases: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_national_region(self) -> Self:
        if self.place_id.startswith("public:korea:") and (
            "region_code" not in self.model_fields_set or self.region_name is None
        ):
            raise ValueError("national place needs explicit official region code and name")
        return self

    @property
    def tour_region_code(self) -> str:
        # The official ldongCode2/areaBasedList2 response uses the municipality
        # code in both fields for Sejong (which has no subordinate district).
        return self.region_code if self.region_code == "36110" else self.region_code[:2]

    @property
    def tour_district_code(self) -> str:
        return self.region_code if self.region_code == "36110" else self.region_code[2:]

    @property
    def region_label(self) -> str:
        if self.region_name:
            return self.region_name
        # Historical Gyeongju records predate explicit region labels.
        if self.region_code == "47130":
            return "경주시"
        return " ".join(self.address.split()[:2]) or self.region_code


_PROVINCE_ALIASES = {
    "서울특별시": "서울",
    "부산광역시": "부산",
    "대구광역시": "대구",
    "인천광역시": "인천",
    "광주광역시": "광주",
    "대전광역시": "대전",
    "울산광역시": "울산",
    "세종특별자치시": "세종",
    "경기도": "경기",
    "강원특별자치도": "강원",
    "강원도": "강원",
    "충청북도": "충북",
    "충청남도": "충남",
    "전북특별자치도": "전북",
    "전라북도": "전북",
    "전라남도": "전남",
    "경상북도": "경북",
    "경상남도": "경남",
    "제주특별자치도": "제주",
    "제주도": "제주",
}


def region_location_matches(place: CanonicalTourismPlace, locality: object) -> bool:
    """Require the actual province/municipality labels, accepting official short names."""

    def normalize(value: str) -> str:
        for official, short in _PROVINCE_ALIASES.items():
            value = value.replace(official, short)
        return re.sub(r"[\W_]+", "", value)

    expected = normalize(place.region_label)
    actual = normalize(str(locality or ""))
    return bool(expected and expected in actual)


class AccessibilitySnapshot(StrictContract):
    schema_version: Literal["accessibility-snapshot.v1"] = "accessibility-snapshot.v1"
    policy_version: Literal["accessibility-facts-v1"] = "accessibility-facts-v1"
    place_id: StableId
    cache_identity_sha256: Sha256
    retrieved_at: datetime
    expires_at: datetime
    receipts: tuple[SourceReceipt, ...]
    match: PlaceMatch
    facts: dict[str, SourceObservation]
    raw_responses: tuple[dict[str, object], ...]
    snapshot_sha256: Sha256

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        require_utc(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.retrieved_at or self.match.place_id != self.place_id:
            raise ValueError("invalid snapshot freshness or place")
        if set(self.facts) != set(FACILITY_KEYS):
            raise ValueError("accessibility snapshot must include explicit unknowns")
        for key, fact in self.facts.items():
            if key != fact.key or any(e.place_match != self.match for e in fact.evidence):
                raise ValueError("snapshot fact provenance mismatch")
            if any(e.receipt not in self.receipts for e in fact.evidence):
                raise ValueError("fact source receipt missing from snapshot")
        raw_hashes: set[str] = set()
        for response in self.raw_responses:
            raw_bytes = b64decode(str(response.get("raw_body_base64", "")), validate=True)
            digest = hashlib.sha256(raw_bytes).hexdigest()
            if digest != response.get("raw_response_sha256"):
                raise ValueError("source raw bytes hash mismatch")
            raw_hashes.add(digest)
        if any(
            receipt.status != "UNAVAILABLE" and receipt.response_sha256 not in raw_hashes
            for receipt in self.receipts
        ):
            raise ValueError("source receipt missing raw response bytes")
        if self.snapshot_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"snapshot_sha256"})
        ):
            raise ValueError("accessibility snapshot hash mismatch")
        return self


def provider_items(payload: object) -> tuple[dict[str, object], ...]:
    """Decode only the provider's documented response/body/items envelope."""
    if not isinstance(payload, dict):
        raise CollectionError("unexpected provider envelope")
    response = payload.get("response")
    body = response.get("body") if isinstance(response, dict) else None
    if not isinstance(body, dict):
        raise CollectionError("missing provider response body")
    wrapper = body.get("items")
    if wrapper in (None, ""):
        return ()
    items = wrapper.get("item") if isinstance(wrapper, dict) else None
    if items in (None, ""):
        return ()
    rows = [items] if isinstance(items, dict) else items
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise CollectionError("unexpected provider item shape")
    return tuple(cast(list[dict[str, object]], rows))


def _normalized(value: object) -> str:
    return re.sub(r"[\W_]+", "", str(value or "").casefold())


def _distance(place: CanonicalTourismPlace, row: Mapping[str, object]) -> float | None:
    if place.latitude is None or place.longitude is None:
        return None
    try:
        lat, lon = float(str(row.get("mapy", ""))), float(str(row.get("mapx", "")))
    except ValueError:
        return None
    if (
        not math.isfinite(lat)
        or not math.isfinite(lon)
        or not -90 <= lat <= 90
        or not -180 <= lon <= 180
    ):
        return None
    p, q = math.radians(place.latitude), math.radians(lat)
    dlat, dlon = q - p, math.radians(lon - place.longitude)
    a = math.sin(dlat / 2) ** 2 + math.cos(p) * math.cos(q) * math.sin(dlon / 2) ** 2
    return 6_371_000 * 2 * math.asin(min(1, math.sqrt(a)))


def match_place(
    place: CanonicalTourismPlace,
    rows: Sequence[Mapping[str, object]],
    *,
    maximum_distance_meters: float = 150.0,
) -> PlaceMatch:
    matches: dict[str, tuple[Mapping[str, object], float | None, bool]] = {}
    for row in rows:
        entity = str(row.get("contentid", "")).strip()
        if not entity or _normalized(row.get("title")) not in {
            _normalized(place.name_ko),
            *map(_normalized, place.aliases),
        }:
            continue
        region, district = str(row.get("lDongRegnCd", "")), str(row.get("lDongSignguCd", ""))
        if (
            region
            and region != place.tour_region_code
            or district
            and district != place.tour_district_code
        ):
            continue
        address = _normalized(row.get("addr1"))
        exact_address = bool(address and address == _normalized(place.address))
        distance = _distance(place, row)
        # Contradictory coordinates override equal names, addresses and content IDs.
        if distance is not None and distance > maximum_distance_meters:
            continue
        if distance is None and not exact_address:
            continue
        # Coordinates establish locality; when coordinates are absent exact address is required.
        matches[entity] = (row, distance, exact_address)
    state: Literal["MATCHED", "NOT_MATCHED", "AMBIGUOUS"] = (
        "MATCHED" if len(matches) == 1 else "AMBIGUOUS" if matches else "NOT_MATCHED"
    )
    if state != "MATCHED":
        return PlaceMatch(
            place_id=place.place_id,
            service=SourceService.ACCESSIBILITY,
            provider_entity_id=None,
            state=state,
            method=None,
            region_code=place.region_code,
            evidence=(
                "정확한 명칭과 위치가 일치하는 자료 없음"
                if not matches
                else "동일 명칭·위치의 복수 자료가 있어 연결 보류",
            ),
        )
    entity, (_, distance, exact_address) = next(iter(matches.items()))
    evidence = ["정규화한 정확한 명칭 일치"]
    if exact_address:
        evidence.append("정규화한 전체 주소 일치")
    if distance is not None:
        evidence.append(f"기준 좌표와 {distance:.1f}m 이내")
    return PlaceMatch(
        place_id=place.place_id,
        service=SourceService.ACCESSIBILITY,
        provider_entity_id=entity,
        state="MATCHED",
        region_code=place.region_code,
        method="EXACT_ID_AND_LOCATION"
        if entity == place.provider_content_id
        else "EXACT_NAME_AND_LOCATION",
        evidence=tuple(evidence),
        distance_meters=distance,
    )


def _unknown(key: str, reason: str) -> SourceObservation:
    return SourceObservation(
        key=key,
        claim=ClaimKind.FACILITY,
        state=SupportState.UNKNOWN,
        value=None,
        evidence=(),
        reference_date=None,
        reason=reason,
    )


def _assertion(text: str, subject: str, *, rental: bool = False) -> bool | None:
    compact = re.sub(r"\s+", "", text)
    matches = tuple(re.finditer(subject, compact))
    if not matches:
        return None
    outcomes: set[bool] = set()
    for match in matches:
        clause = compact[match.end() :]
        # A later statement about a different facility cannot negate this subject.
        clause = re.split(
            r"[;。]|일반주차|비장애인|유모차|휠체어|장애인(?:전용)?(?:주차|화장실)", clause
        )[0]
        # A rental statement about the next facility cannot turn this subject's
        # access/use statement into either rental availability or rental absence.
        if rental and "대여" not in clause:
            return None
        if re.search(r"미확인|문의|확인필요|여부|예정|계획|추정|알수없|정보없", clause):
            return None
        negative = bool(re.search(r"없[음다]|불가|미제공|제공하지않|대여하지않", clause))
        positive = bool(
            re.search(
                r"있[음다]|(?<!불)가능(?:함|합니다|$|\()|(?<!미)제공(?:함|합니다)"
                r"|설치(?:됨|되어|된)|구비(?:됨|되어|된)",
                clause,
            )
        )
        # Observed official 감은사지 wording names a concrete toilet location.
        if not rental and re.search(r"위치[:：].{2,}", clause):
            positive = True
        if positive == negative:
            return None
        outcomes.add(positive)
    return next(iter(outcomes)) if len(outcomes) == 1 else None


def _step_free_assertion(text: str) -> bool | None:
    """Recognize only unambiguous entrance assertions; never resolve contradictions."""
    compact = re.sub(r"\s+", "", text)
    if not re.search(r"주출입구|출입구|입구", compact):
        return None
    if re.search(
        r"미확인|문의|확인필요|여부|인지|예정|계획|추정|알수없|정보없|아님|아니|않", compact
    ):
        return None
    positive = bool(
        re.search(
            r"(?:문턱|단차|계단)(?:이|가)?없(?:음|다|습니다|어요|는|고|으며|$|[(_.,])|무단차",
            compact,
        )
    )
    negative = bool(re.search(r"계단만|휠체어(?:진입|출입|접근|이동|이용)불가", compact))
    # Earlier/other-entrance positive wording must not mask a current restriction.
    return positive if positive != negative else None


def facility_observations(
    row: Mapping[str, object], receipt: SourceReceipt, match: PlaceMatch
) -> dict[str, SourceObservation]:
    facts = {
        key: _unknown(key, "해당 시설을 확인할 수 있는 명시적 공식 정보가 없습니다.")
        for key in FACILITY_KEYS
    }

    def record(key: str, field: str, value: bool | str, text: str) -> None:
        if not text or len(text) > 4_000:
            return
        evidence = SourceEvidence(
            evidence_id="evidence:"
            + canonical_sha256(
                {
                    "receipt": receipt.model_dump(mode="json"),
                    "match": match.model_dump(mode="json"),
                    "field": field,
                    "text": text,
                }
            ),
            receipt=receipt,
            place_match=match,
            scope="PLACE",
            modality="STRUCTURED",
            source_field=field,
            excerpt=text,
            quote=text,
        )
        facts[key] = SourceObservation(
            key=key,
            claim=ClaimKind.FACILITY,
            state=SupportState.FACT,
            value=value,
            evidence=(evidence,),
            reference_date=receipt.reference_date or receipt.retrieved_at.date(),
            reason="공식 등록 문구의 범위에서 확인했습니다. 현장 상태를 실시간 보증하지 않습니다.",
        )

    for key, field, subject, rental in (
        ("accessible_parking", "parking", r"장애인(?:전용)?주차(?:구역|장|공간)?", False),
        ("accessible_toilet", "restroom", r"장애인(?:전용)?화장실", False),
        ("wheelchair_rental", "wheelchair", r"휠체어", True),
        ("stroller_rental", "stroller", r"유모차", True),
    ):
        text = str(row.get(field) or "").strip()
        value = _assertion(text, subject, rental=rental)
        if value is not None:
            record(key, field, value, text)
    for field in ("route", "publictransport"):
        text = str(row.get(field) or "").strip()
        # Provider headings have been swapped historically: inspect actual route text.
        if re.search(r"경사로|접근로|진입로|보행로|휠체어.*이동", text):
            record("accessible_route_segment", field, text, text)
    text = str(row.get("exit") or "").strip()
    entry = _step_free_assertion(text)
    if entry is not None:
        record("step_free_entry", "exit", entry, text)
    return facts


class AccessibilityService:
    """Canonical-only source lookup. Cache entries never mutate a previous snapshot."""

    def __init__(
        self,
        *,
        client: KorWithService2Client | None,
        places: Sequence[CanonicalTourismPlace],
        settings: TourismSettings | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.client = client
        self.settings = settings or TourismSettings()
        self.clock = clock
        self.places = {place.place_id: place for place in places}
        if len(self.places) != len(places):
            raise ValueError("duplicate canonical place IDs")
        self._cache: dict[str, AccessibilitySnapshot] = {}
        self._locks = {place_id: Lock() for place_id in self.places}
        self._requests = BoundedSemaphore(self.settings.http_concurrency)

    def get_many(self, place_ids: Sequence[str]) -> tuple[AccessibilitySnapshot, ...]:
        with ThreadPoolExecutor(max_workers=self.settings.http_concurrency) as executor:
            return tuple(executor.map(self.fetch, place_ids))

    def fetch(self, place_id: str) -> AccessibilitySnapshot:
        place = self.places[place_id]
        with self._locks[place_id]:
            now = require_utc(self.clock(), field_name="clock")
            cached = self._cache.get(place_id)
            if cached is not None and now < cached.expires_at:
                # Return a deep clone because nested dicts are not frozen by Pydantic.
                return cached.model_copy(deep=True)
            result = self._collect(place, now)
            self._cache[place_id] = result.model_copy(deep=True)
            return result

    def _collect(self, place: CanonicalTourismPlace, now: datetime) -> AccessibilitySnapshot:
        receipts: list[SourceReceipt] = []
        raw: list[dict[str, object]] = []
        rows: list[dict[str, object]] = []
        match = match_place(place, ())
        facts = {
            key: _unknown(key, "공식 무장애 자료를 연결하지 못했습니다.") for key in FACILITY_KEYS
        }

        def request(operation: str, params: dict[str, str | int]) -> CollectedResponse:
            if self.client is None or not self.settings.enabled:
                raise CollectionError("tourism source collection is not configured")
            with self._requests:
                response = self.client.request(operation, params, explicit_opt_in=True)
            items = provider_items(response.payload)
            raw.append(response.to_dict())
            receipts.append(
                SourceReceipt(
                    service=SourceService.ACCESSIBILITY,
                    operation=operation,
                    dataset_id="15101897",
                    request_scope=response.request_scope,
                    retrieved_at=response.retrieved_at,
                    reference_date=response.retrieved_at.date(),
                    status="AVAILABLE" if items else "EMPTY",
                    http_status=response.http_status,
                    response_sha256=response.raw_response_sha256,
                    reason="공식 API 조회 완료" if items else "검색 범위에서 반환 자료 없음",
                )
            )
            return response

        operation = "searchKeyword2"
        params: dict[str, str | int] = {
            "keyword": place.name_ko,
            "lDongRegnCd": place.tour_region_code,
            "lDongSignguCd": place.tour_district_code,
            "pageNo": 1,
            "numOfRows": self.settings.discovery_page_size,
        }
        try:
            exhausted = False
            for page in range(1, self.settings.discovery_max_pages + 1):
                params["pageNo"] = page
                response = request(operation, params)
                batch = provider_items(response.payload)
                rows.extend(batch)
                body = cast(
                    dict[str, object],
                    cast(dict[str, object], cast(dict[str, object], response.payload)["response"])[
                        "body"
                    ],
                )
                total = int(str(body.get("totalCount", len(rows))))
                if len(rows) >= total or len(batch) < self.settings.discovery_page_size:
                    exhausted = True
                    break
            if not exhausted:
                raise CollectionError("discovery pagination limit reached; matching incomplete")
            match = match_place(
                place, rows, maximum_distance_meters=self.settings.match_distance_meters
            )
            if match.state == "MATCHED":
                operation = "detailWithTour2"
                params = {"contentId": cast(str, match.provider_entity_id)}
                details = provider_items(request(operation, params).payload)
                matched = [
                    row for row in details if str(row.get("contentid")) == match.provider_entity_id
                ]
                if len(details) == len(matched) == 1:
                    facts = facility_observations(matched[0], receipts[-1], match)
                elif details:
                    raise CollectionError("detail identity disagrees with verified discovery")
        except (CollectionError, ValueError) as error:
            http_status = error.http_status if isinstance(error, CollectionError) else None
            code = error.provider_result_code if isinstance(error, CollectionError) else None
            reason = (
                "AUTHORIZATION_UNAVAILABLE"
                if http_status in (401, 403) or code == "30"
                else "SOURCE_UNAVAILABLE"
            )
            receipts.append(
                SourceReceipt(
                    service=SourceService.ACCESSIBILITY,
                    operation=operation,
                    dataset_id="15101897",
                    request_scope={k: str(v) for k, v in params.items()},
                    retrieved_at=now,
                    status="UNAVAILABLE",
                    http_status=http_status,
                    response_sha256=error.raw_body_sha256
                    if isinstance(error, CollectionError)
                    else None,
                    reason=reason,
                )
            )
        positive = match.state == "MATCHED" and receipts[-1].status == "AVAILABLE"
        ttl = self.settings.positive_ttl_seconds if positive else self.settings.negative_ttl_seconds
        payload = dict(
            place_id=place.place_id,
            cache_identity_sha256=canonical_sha256(
                {
                    "provider": SourceService.ACCESSIBILITY.value,
                    "operations": ["searchKeyword2", "detailWithTour2"],
                    "place": place.model_dump(mode="json"),
                    "source_match": match.model_dump(mode="json"),
                    "policy": self.settings.model_dump(mode="json"),
                    "requested_period": None,
                }
            ),
            retrieved_at=now,
            expires_at=now + timedelta(seconds=ttl),
            receipts=tuple(receipts),
            match=match,
            facts=facts,
            raw_responses=tuple(raw),
            snapshot_sha256="0" * 64,
        )
        draft = AccessibilitySnapshot.model_construct(_fields_set=None, **payload)
        value = draft.model_dump(mode="json", exclude={"snapshot_sha256"})
        return AccessibilitySnapshot.model_validate(
            {**value, "snapshot_sha256": canonical_sha256(value)}
        )
