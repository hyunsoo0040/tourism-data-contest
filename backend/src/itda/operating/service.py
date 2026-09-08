"""Bounded read-time operating information from official TourAPI data."""

from __future__ import annotations

import html
import math
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from itda.collectors.base import CollectedResponse, RequestPolicy
from itda.collectors.kto import KorService2Client
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.recommendation import (
    OperatingInformationEntry,
    OperatingInformationKind,
    OperatingInformationProviderField,
    OperatingInformationResponse,
    OperatingInformationSnapshot,
    OperatingInformationUnavailableReason,
    PlaceOperatingInformation,
)

CATEGORY_CONTENT_TYPE = {
    "관광지": "12",
    "문화시설": "14",
    "축제·공연·행사": "15",
    "레포츠": "28",
    "숙박": "32",
    "쇼핑": "38",
    "음식점": "39",
}

FIELD_COPY: dict[
    OperatingInformationProviderField,
    tuple[OperatingInformationKind, str],
] = {
    "opendate": ("OPENING_HOURS", "개장일"),
    "restdate": ("REST_DATES", "휴무일"),
    "usetime": ("OPENING_HOURS", "이용시간"),
    "useseason": ("USE_SEASON", "이용시기"),
    "restdateculture": ("REST_DATES", "휴무일"),
    "usetimeculture": ("OPENING_HOURS", "이용시간"),
    "eventstartdate": ("EVENT_DATES", "행사 시작일"),
    "eventenddate": ("EVENT_DATES", "행사 종료일"),
    "playtime": ("OPENING_HOURS", "공연시간"),
    "openperiod": ("USE_SEASON", "개장기간"),
    "restdateleports": ("REST_DATES", "휴무일"),
    "usetimeleports": ("OPENING_HOURS", "이용시간"),
    "checkintime": ("CHECK_IN_OUT", "체크인"),
    "checkouttime": ("CHECK_IN_OUT", "체크아웃"),
    "roomofftime": ("CHECK_IN_OUT", "객실 이용시간"),
    "opendateshopping": ("OPENING_HOURS", "개장일"),
    "opentime": ("OPENING_HOURS", "영업시간"),
    "restdateshopping": ("REST_DATES", "휴무일"),
    "opendatefood": ("OPENING_HOURS", "개장일"),
    "opentimefood": ("OPENING_HOURS", "영업시간"),
    "restdatefood": ("REST_DATES", "휴무일"),
}

FIELDS_BY_TYPE: dict[str, tuple[OperatingInformationProviderField, ...]] = {
    "12": ("opendate", "restdate", "usetime", "useseason"),
    "14": ("restdateculture", "usetimeculture"),
    "15": ("eventstartdate", "eventenddate", "playtime"),
    "28": ("openperiod", "restdateleports", "usetimeleports"),
    "32": ("checkintime", "checkouttime", "roomofftime"),
    "38": ("opendateshopping", "opentime", "restdateshopping"),
    "39": ("opendatefood", "opentimefood", "restdatefood"),
}

_TAG = re.compile(r"<[^>]*>")
_SPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class ProviderPlace:
    content_id: str
    content_type_id: str


class OperatingCatalog(Protocol):
    @property
    def catalog_sha256(self) -> str: ...

    def lookup(self, place_id: str) -> ProviderPlace | None: ...


class OperatingProvider(Protocol):
    def fetch(self, place: ProviderPlace) -> CollectedResponse: ...

    def close(self) -> None: ...


class TourApiOperatingProvider:
    def __init__(self, *, service_key: str, timeout_seconds: float) -> None:
        self._client = KorService2Client(
            service_key=service_key,
            policy=RequestPolicy(
                timeout_seconds=timeout_seconds,
                max_attempts=1,
                initial_backoff_seconds=0,
            ),
        )

    def fetch(self, place: ProviderPlace) -> CollectedResponse:
        return self._client.request(
            "detailIntro2",
            {
                "contentId": place.content_id,
                "contentTypeId": place.content_type_id,
                "numOfRows": "1",
                "pageNo": "1",
            },
            explicit_opt_in=True,
        )

    def close(self) -> None:
        self._client.close()


class PublicCatalogLookup:
    def __init__(self, *, catalog_path: Path) -> None:
        self._catalog = PublicPlaceCatalog.model_validate_json(catalog_path.read_bytes())
        self._places = {row.place_id: row for row in self._catalog.places}

    @property
    def catalog_sha256(self) -> str:
        return self._catalog.catalog_sha256

    def lookup(self, place_id: str) -> ProviderPlace | None:
        row = self._places.get(place_id)
        if row is None:
            return None
        content_type_id = CATEGORY_CONTENT_TYPE.get(row.category)
        source_id = next(
            (
                crosswalk.source_id
                for crosswalk in row.provider_crosswalk
                if crosswalk.provider == "TOUR_API"
            ),
            None,
        )
        if content_type_id is None or source_id is None:
            return None
        return ProviderPlace(content_id=source_id, content_type_id=content_type_id)


def _items(payload: object) -> tuple[Mapping[str, object], ...]:
    stack = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            item = current.get("item")
            if isinstance(item, Mapping):
                return (item,)
            if isinstance(item, list):
                return tuple(row for row in item if isinstance(row, Mapping))
            stack.extend(reversed(tuple(current.values())))
        elif isinstance(current, list):
            stack.extend(reversed(current))
    return ()


def _normalize(value: object) -> str | None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    rendered = html.unescape(_TAG.sub(" ", str(value)))
    rendered = _SPACE.sub(" ", rendered).strip()
    return rendered[:240] if rendered else None


def parse_operating_snapshot(
    response: CollectedResponse,
    *,
    place: ProviderPlace,
    cached: bool,
) -> OperatingInformationSnapshot | None:
    matching = [
        row
        for row in _items(response.payload)
        if str(row.get("contentid", row.get("contentId", ""))) == place.content_id
    ]
    if len(matching) != 1:
        return None
    row = matching[0]
    entries = []
    for field in FIELDS_BY_TYPE[place.content_type_id]:
        value = _normalize(row.get(field))
        if value is None:
            continue
        kind, label = FIELD_COPY[field]
        entries.append(
            OperatingInformationEntry(
                kind=kind,
                label_ko=label,
                value_ko=value,
                provider_field=field,
            )
        )
    if not entries:
        return None
    return OperatingInformationSnapshot(
        content_type_id=place.content_type_id,
        entries=tuple(entries),
        retrieved_at=response.retrieved_at,
        provider_modifiedtime=response.modifiedtime,
        cached=cached,
    )


@dataclass(slots=True)
class _CacheEntry:
    value: PlaceOperatingInformation
    expires_at: float


class OperatingInformationService:
    def __init__(
        self,
        *,
        catalog: OperatingCatalog,
        provider: OperatingProvider | None,
        ttl_seconds: float = 900,
        negative_ttl_seconds: float = 120,
        cache_size: int = 512,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        for field_name, value in (
            ("ttl_seconds", ttl_seconds),
            ("negative_ttl_seconds", negative_ttl_seconds),
        ):
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{field_name} must be finite and positive")
        if type(cache_size) is not int or cache_size < 1:
            raise ValueError("cache_size must be a positive integer")
        self._catalog = catalog
        self._provider = provider
        self._ttl = ttl_seconds
        self._negative_ttl = negative_ttl_seconds
        self._cache_size = cache_size
        self._monotonic = monotonic
        self._cache: OrderedDict[tuple[str, str, str], _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    def _unverified(
        self,
        place_id: str,
        reason: OperatingInformationUnavailableReason,
    ) -> PlaceOperatingInformation:
        return PlaceOperatingInformation(
            place_id=place_id,
            state="UNVERIFIED",
            unavailable_reason=reason,
        )

    def _get_cached(self, key: tuple[str, str, str]) -> PlaceOperatingInformation | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None or entry.expires_at <= self._monotonic():
                if entry is not None:
                    del self._cache[key]
                return None
            self._cache.move_to_end(key)
            value = entry.value
            if value.snapshot is not None:
                value = value.model_copy(
                    update={"snapshot": value.snapshot.model_copy(update={"cached": True})}
                )
            return value

    def _put_cached(self, key: tuple[str, str, str], value: PlaceOperatingInformation) -> None:
        ttl = self._ttl if value.state == "AVAILABLE" else self._negative_ttl
        with self._lock:
            self._cache[key] = _CacheEntry(value=value, expires_at=self._monotonic() + ttl)
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    def _fetch(
        self,
        place_id: str,
        provider_place: ProviderPlace,
        key: tuple[str, str, str],
    ) -> PlaceOperatingInformation:
        assert self._provider is not None
        try:
            response = self._provider.fetch(provider_place)
            snapshot = parse_operating_snapshot(response, place=provider_place, cached=False)
            value = (
                PlaceOperatingInformation(place_id=place_id, state="AVAILABLE", snapshot=snapshot)
                if snapshot is not None
                else self._unverified(place_id, "NO_OPERATING_FIELDS")
            )
        except Exception:
            value = self._unverified(place_id, "PROVIDER_UNAVAILABLE")
        self._put_cached(key, value)
        return value

    def load(self, *, run_id: str, place_ids: Sequence[str]) -> OperatingInformationResponse:
        resolved: dict[str, PlaceOperatingInformation] = {}
        misses: list[tuple[str, ProviderPlace, tuple[str, str, str]]] = []
        for place_id in place_ids:
            provider_place = self._catalog.lookup(place_id)
            if provider_place is None:
                resolved[place_id] = self._unverified(place_id, "NOT_IN_PROVIDER_SCOPE")
                continue
            key = (
                self._catalog.catalog_sha256,
                provider_place.content_id,
                provider_place.content_type_id,
            )
            cached = self._get_cached(key)
            if cached is not None:
                resolved[place_id] = cached.model_copy(update={"place_id": place_id})
            elif self._provider is None:
                resolved[place_id] = self._unverified(place_id, "ENRICHMENT_DISABLED")
            else:
                misses.append((place_id, provider_place, key))
        if misses:
            with ThreadPoolExecutor(max_workers=min(5, len(misses))) as executor:
                futures = {
                    executor.submit(self._fetch, place_id, provider_place, key): place_id
                    for place_id, provider_place, key in misses
                }
                for future in as_completed(futures):
                    place_id = futures[future]
                    try:
                        resolved[place_id] = future.result()
                    except Exception:
                        resolved[place_id] = self._unverified(place_id, "PROVIDER_UNAVAILABLE")
        return OperatingInformationResponse(
            run_id=run_id,
            places=tuple(resolved[place_id] for place_id in place_ids),
        )

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
