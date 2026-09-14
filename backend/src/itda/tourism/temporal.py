"""Date-aware, information-only official tourism context.

Dates retain provider meaning: baseYmd is a forecast/measurement date, not an
issue timestamp. Regional values never enter intrinsic place scores or M3.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from threading import BoundedSemaphore
from typing import Any, Literal, cast
from zoneinfo import ZoneInfo

from pydantic import Field

from itda.collectors.base import CollectionError, OfficialApiClient
from itda.collectors.kto_concentration import ConcentrationClient
from itda.collectors.kto_demand import RegionalDemandClient
from itda.collectors.kto_visitors import RegionalVisitorsClient
from itda.contracts.base import StrictContract, require_utc
from itda.contracts.source_assessment import SOURCE_DATASETS, SourceReceipt, SourceService
from itda.contracts.trip_context import (
    ForecastAlternative,
    PlaceConcentrationForecast,
    RegionalDemandContext,
    RegionalDemandMeasure,
    RegionalVisitorPoint,
    RegionalVisitorsContext,
    TemporalReason,
    TripTemporalContext,
)
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import CanonicalTourismPlace, provider_items
from itda.tourism.temporal_cache import TemporalCache, TemporalSourceSnapshot

_VISITOR_CATEGORIES = {"1": "현지인(a)", "2": "외지인(b)", "3": "외국인(c)"}


def _local_day(now: datetime) -> date:
    return now.astimezone(ZoneInfo("Asia/Seoul")).date()


class TemporalPolicy(StrictContract):
    enabled: bool = False
    http_concurrency: int = Field(default=3, ge=1, le=5)
    page_size: int = Field(default=1000, ge=1, le=1000)
    max_pages: int = Field(default=40, ge=1, le=100)
    positive_ttl_seconds: int = Field(default=21600, ge=1, le=86400)
    negative_ttl_seconds: int = Field(default=900, ge=1, le=3600)
    forecast_max_window_age_days: int = Field(default=2, ge=0, le=7)
    max_visitor_period_days: int = Field(default=31, ge=1, le=31)


def _name(value: object) -> str:
    return re.sub(r"[\W_]+", "", str(value or "").casefold())


def _date(value: object) -> date:
    rendered = str(value)
    if re.fullmatch(r"\d{8}", rendered) is None:
        raise ValueError("invalid source date")
    return datetime.strptime(rendered, "%Y%m%d").date()


def _decimal(value: object, maximum: int | None = None) -> Decimal:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ValueError("source value must be an exact decimal string or integer")
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("invalid source decimal") from error
    if not result.is_finite() or result < 0 or maximum is not None and result > maximum:
        raise ValueError("source value outside documented range")
    return result


def _source_fields(snapshot: TemporalSourceSnapshot | None) -> dict[str, object]:
    return {
        "source_snapshot_sha256": canonical_sha256(snapshot.model_dump(mode="json"))
        if snapshot
        else None,
        "receipts": snapshot.receipts if snapshot else (),
        "retrieved_at": snapshot.retrieved_at if snapshot else None,
        "expires_at": snapshot.expires_at if snapshot else None,
    }


class TemporalContextService:
    def __init__(
        self,
        *,
        places: Sequence[CanonicalTourismPlace],
        concentration: ConcentrationClient | None = None,
        visitors: RegionalVisitorsClient | None = None,
        demand: RegionalDemandClient | None = None,
        policy: TemporalPolicy | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        cache: TemporalCache | None = None,
    ) -> None:
        self.places = {row.place_id: row for row in places}
        if len(self.places) != len(places):
            raise ValueError("duplicate canonical places")
        self.concentration = concentration
        self.visitors = visitors
        self.demand = demand
        self.policy = policy or TemporalPolicy()
        self.clock = clock
        self.cache = cache or TemporalCache(clock=clock)
        self._requests = BoundedSemaphore(self.policy.http_concurrency)

    def collect_source_batch(
        self,
        service: SourceService,
        operation: str,
        params: dict[str, str],
        client: OfficialApiClient | None,
    ) -> TemporalSourceSnapshot:
        """Shared bounded complete-page collection for all official source families."""
        return self._batch(service, operation, params, client)

    def _batch(
        self,
        service: SourceService,
        operation: str,
        params: dict[str, str],
        client: OfficialApiClient | None,
    ) -> TemporalSourceSnapshot:
        # Camping rows contain long facility descriptions and over100 fields.
        # A1000-row page exceeds the shared2MB response limit on the live API.
        # Keep that limit intact and exhaust smaller pages instead.
        page_size = (
            min(self.policy.page_size, 200)
            if service == SourceService.CAMPING
            else self.policy.page_size
        )
        key = canonical_sha256(
            {
                "service": service.value,
                "operation": operation,
                "params": params,
                "policy": self.policy.model_dump(mode="json"),
                "version": "temporal-source-v2",
                "effective_page_size": page_size,
            }
        )

        def load() -> TemporalSourceSnapshot:
            now = require_utc(self.clock(), field_name="clock")
            rows: list[dict[str, object]] = []
            receipts: list[SourceReceipt] = []
            raw: list[dict[str, object]] = []
            reason: TemporalReason = "PARTIAL_SERIES"
            complete = False
            provider_code = None
            request_scope: dict[str, str] = dict(params)
            try:
                if not self.policy.enabled or client is None:
                    raise CollectionError("temporal source not configured")
                total_expected = None
                for page in range(1, self.policy.max_pages + 1):
                    request_scope = {
                        **params,
                        "pageNo": str(page),
                        "numOfRows": str(page_size),
                    }
                    with self._requests:
                        response = client.request(operation, request_scope, explicit_opt_in=True)
                    page_rows = provider_items(response.payload)
                    raw.append(response.to_dict())
                    receipts.append(
                        SourceReceipt(
                            service=service,
                            operation=operation,
                            dataset_id=SOURCE_DATASETS[service],
                            request_scope=response.request_scope,
                            retrieved_at=response.retrieved_at,
                            reference_date=None,
                            status="AVAILABLE" if page_rows else "EMPTY",
                            http_status=response.http_status,
                            response_sha256=response.raw_response_sha256,
                            reason="공식 날짜별 자료 조회",
                        )
                    )
                    body = cast(dict[str, Any], response.payload)["response"]["body"]
                    total = int(str(body.get("totalCount", "-1")))
                    if total < 0 or total_expected is not None and total != total_expected:
                        raise CollectionError("provider page totals changed or are missing")
                    total_expected = total
                    rows.extend(page_rows)
                    if len(rows) == total:
                        complete = True
                        reason = "NONE" if rows else "EMPTY"
                        break
                    if len(rows) > total or not page_rows:
                        raise CollectionError("incomplete provider pagination")
            except (CollectionError, ValueError) as error:
                status = error.http_status if isinstance(error, CollectionError) else None
                provider_code = (
                    error.provider_result_code if isinstance(error, CollectionError) else None
                )
                reason = (
                    "AUTHORIZATION_UNAVAILABLE"
                    if status in (401, 403) or provider_code == "30"
                    else "PARTIAL_SERIES"
                    if rows
                    else "SOURCE_UNAVAILABLE"
                )
                receipts.append(
                    SourceReceipt(
                        service=service,
                        operation=operation,
                        dataset_id=SOURCE_DATASETS[service],
                        request_scope=request_scope,
                        retrieved_at=now,
                        status="UNAVAILABLE",
                        http_status=status,
                        response_sha256=error.raw_body_sha256
                        if isinstance(error, CollectionError)
                        else None,
                        reason=reason,
                    )
                )
            ttl = (
                self.policy.positive_ttl_seconds
                if complete and rows
                else self.policy.negative_ttl_seconds
            )
            draft = TemporalSourceSnapshot.model_construct(
                service=service,
                operation=operation,
                cache_key_sha256=key,
                retrieved_at=now,
                expires_at=now + timedelta(seconds=ttl),
                complete=complete,
                reason=reason,
                provider_result_code=provider_code,
                rows=tuple(rows),
                receipts=tuple(receipts),
                raw_responses=tuple(raw),
                snapshot_sha256="0" * 64,
            )
            payload = draft.model_dump(mode="json", exclude={"snapshot_sha256"})
            return TemporalSourceSnapshot.model_validate(
                {**payload, "snapshot_sha256": canonical_sha256(payload)}
            )

        return self.cache.get_or_load(key, load)

    def _forecast(
        self,
        place: CanonicalTourismPlace,
        target: date,
        now: datetime,
        snapshot: TemporalSourceSnapshot,
    ) -> PlaceConcentrationForecast:
        fields: dict[str, object] = {
            "place_id": place.place_id,
            "region_code": place.region_code,
            "provider_name": None,
            "match_method": None,
            "state": "UNKNOWN",
            "reason": snapshot.reason,
            "target_date": target,
            "window_start": None,
            "window_end": None,
            "value": None,
            **_source_fields(snapshot),
        }

        def unknown(reason: TemporalReason) -> PlaceConcentrationForecast:
            return PlaceConcentrationForecast.model_validate({**fields, "reason": reason})

        if now >= snapshot.expires_at:
            return unknown("STALE")
        if not snapshot.complete or not snapshot.rows:
            return unknown(snapshot.reason)
        accepted_names = {_name(place.name_ko), *map(_name, place.aliases)}
        candidates = [
            row
            for row in snapshot.rows
            if str(row.get("areaCd")) == place.region_code[:2]
            and str(row.get("signguCd")) == place.region_code
            and _name(row.get("tAtsNm")) in accepted_names
        ]
        if not candidates:
            return unknown("PLACE_NOT_MATCHED")
        provider_names = {str(row.get("tAtsNm")) for row in candidates}
        # This API has no coordinates/content ID; the exact name/region crosswalk
        # must be unique in both source and canonical catalog. No fuzzy matching.
        if len(provider_names) != 1:
            return unknown("AMBIGUOUS_MATCH")
        provider_name = next(iter(provider_names))
        if (
            sum(
                _name(provider_name) in {_name(row.name_ko), *map(_name, row.aliases)}
                for row in self.places.values()
                if row.region_code == place.region_code
            )
            != 1
        ):
            return unknown("AMBIGUOUS_MATCH")
        fields.update(
            provider_name=provider_name,
            match_method="EXACT_NAME_AND_REGION"
            if _name(provider_name) == _name(place.name_ko)
            else "CURATED_NAME_AND_REGION",
        )
        points: dict[date, Decimal] = {}
        try:
            for row in candidates:
                day = _date(row.get("baseYmd"))
                if day in points:
                    return unknown("AMBIGUOUS_MATCH")
                points[day] = _decimal(row.get("cnctrRate"), maximum=100)
        except ValueError:
            return unknown("INVALID_VALUE")
        first, last = min(points), max(points)
        fields.update(window_start=first, window_end=last)
        if len(points) != 30 or (last - first).days != 29:
            return unknown("PARTIAL_SERIES")
        if first < _local_day(now) - timedelta(
            days=self.policy.forecast_max_window_age_days
        ) or first > _local_day(now):
            return unknown("STALE")
        if target < _local_day(now) or target not in points:
            return unknown("OUT_OF_WINDOW")
        alternatives = tuple(
            ForecastAlternative(target_date=day, value=value)
            for day, value in sorted(points.items(), key=lambda item: (item[1], item[0]))
            if day >= _local_day(now) and day != target and value < points[target]
        )[:3]
        return PlaceConcentrationForecast.model_validate(
            {
                **fields,
                "state": "AVAILABLE",
                "reason": "NONE",
                "value": points[target],
                "alternatives": alternatives,
            }
        )

    def _visitors(
        self,
        start: date | None,
        end: date | None,
        now: datetime,
        snapshot: TemporalSourceSnapshot | None,
        region_code: str = "47130",
        region_name: str = "경주시",
    ) -> RegionalVisitorsContext:
        fields = {
            "region_code": region_code,
            "region_name": region_name,
            "state": "UNKNOWN",
            "reason": "NOT_REQUESTED",
            "period_start": start,
            "period_end": end,
            **_source_fields(snapshot),
        }
        if start is None or end is None:
            return RegionalVisitorsContext.model_validate(fields)
        if end >= _local_day(now):
            return RegionalVisitorsContext.model_validate(
                {**fields, "reason": "FUTURE_OBSERVATION"}
            )
        assert snapshot is not None
        if not snapshot.complete or not snapshot.rows or now >= snapshot.expires_at:
            return RegionalVisitorsContext.model_validate(
                {**fields, "reason": "STALE" if now >= snapshot.expires_at else snapshot.reason}
            )
        scoped: dict[tuple[date, str], list[dict[str, object]]] = {}
        invalid_scope = False
        for row in snapshot.rows:
            if str(row.get("signguCode")) != region_code:
                continue
            try:
                day = _date(row.get("baseYmd"))
            except ValueError:
                invalid_scope = True
                continue
            category = str(row.get("touDivCd"))
            if start <= day <= end and category in _VISITOR_CATEGORIES:
                scoped.setdefault((day, category), []).append(row)
        points = []
        for offset in range((end - start).days + 1):
            day = start + timedelta(days=offset)
            for category, label in _VISITOR_CATEGORIES.items():
                rows = scoped.get((day, category), [])
                reason: TemporalReason = "AMBIGUOUS_MATCH" if len(rows) > 1 else "PARTIAL_SERIES"
                value = None
                raw_value = None
                if len(rows) == 1 and not invalid_scope:
                    raw_value = str(rows[0].get("touNum", ""))
                    try:
                        value = _decimal(raw_value)
                        if rows[0].get("touDivNm") != label:
                            raise ValueError("visitor category label mismatch")
                        reason = "NONE"
                    except ValueError:
                        value = None
                        reason = "INVALID_VALUE"
                points.append(
                    RegionalVisitorPoint(
                        measurement_date=day,
                        category_code=cast(Literal["1", "2", "3"], category),
                        category_name=label,
                        value=value,
                        raw_value=raw_value,
                        state="AVAILABLE" if value is not None else "UNKNOWN",
                        reason=reason,
                    )
                )
        known = sum(row.value is not None for row in points)
        return RegionalVisitorsContext.model_validate(
            {
                **fields,
                "state": "AVAILABLE" if known == len(points) else "PARTIAL" if known else "UNKNOWN",
                "reason": "NONE" if known == len(points) else "PARTIAL_SERIES",
                "points": tuple(points),
            }
        )

    def _demand(
        self,
        kind: Literal["REGIONAL_STAY_INTENSITY", "REGIONAL_SPENDING_INTENSITY"],
        month: str | None,
        now: datetime,
        snapshot: TemporalSourceSnapshot | None,
        region_code: str = "47130",
        region_name: str = "경주시",
    ) -> RegionalDemandContext:
        fields = {
            "region_code": region_code,
            "region_name": region_name,
            "measure_kind": kind,
            "state": "UNKNOWN",
            "reason": "NOT_REQUESTED",
            "base_month": month,
            "provider_result_code": snapshot.provider_result_code if snapshot else None,
            **_source_fields(snapshot),
        }
        if month is None:
            return RegionalDemandContext.model_validate(fields)
        if month >= _local_day(now).strftime("%Y%m"):
            return RegionalDemandContext.model_validate({**fields, "reason": "FUTURE_OBSERVATION"})
        assert snapshot is not None
        if not snapshot.complete or not snapshot.rows or now >= snapshot.expires_at:
            return RegionalDemandContext.model_validate(
                {**fields, "reason": "STALE" if now >= snapshot.expires_at else snapshot.reason}
            )
        prefix = "tarSjrnDsIx" if kind == "REGIONAL_STAY_INTENSITY" else "tarExpDsIx"
        code_prefix = "21" if kind == "REGIONAL_STAY_INTENSITY" else "22"
        measures = []
        seen = set()
        for row in snapshot.rows:
            if (
                row.get("areaCd") != region_code[:2]
                or row.get("signguCd") != region_code
                or row.get("baseYm") != month
            ):
                continue
            code = str(row.get(prefix + "Cd", ""))
            name = str(row.get(prefix + "Nm", ""))
            original = row.get(prefix + "Val", "")
            raw = str(original)
            if code in seen:
                return RegionalDemandContext.model_validate({**fields, "reason": "AMBIGUOUS_MATCH"})
            last_code = 5 if kind == "REGIONAL_STAY_INTENSITY" else 3
            allowed_codes = {
                code_prefix,
                *(f"{code_prefix}0{index}" for index in range(1, last_code + 1)),
            }
            if code not in allowed_codes or not name:
                return RegionalDemandContext.model_validate({**fields, "reason": "INVALID_VALUE"})
            try:
                if not isinstance(original, (str, int)) or isinstance(original, bool):
                    raise ValueError("regional index source must retain exact decimal text")
                value = Decimal(raw)
                if not value.is_finite():
                    raise ValueError("regional index must be finite")
            except (InvalidOperation, ValueError):
                return RegionalDemandContext.model_validate({**fields, "reason": "INVALID_VALUE"})
            seen.add(code)
            measures.append(
                RegionalDemandMeasure(indicator_code=code, indicator_name=name, raw_value=raw)
            )
        if len(measures) == 1 and measures[0].indicator_code == code_prefix:
            expected_name = "관광체류강도" if kind == "REGIONAL_STAY_INTENSITY" else "관광소비강도"
            if measures[0].indicator_name != expected_name:
                return RegionalDemandContext.model_validate({**fields, "reason": "INVALID_VALUE"})
            if snapshot.receipts and all(
                receipt.status == "AVAILABLE"
                and receipt.http_status == 200
                and receipt.request_scope.get("baseYm") == month
                and receipt.request_scope.get("areaCd") == region_code[:2]
                and receipt.request_scope.get("signguCd") == region_code
                and receipt.request_scope.get(prefix + "Cd") == code_prefix
                for receipt in snapshot.receipts
            ):
                measure = RegionalDemandMeasure(
                    indicator_code=code_prefix,
                    indicator_name=expected_name,
                    raw_value=measures[0].raw_value,
                    value=Decimal(measures[0].raw_value),
                    state="AVAILABLE",
                    reason="NONE",
                    unit="TOURISM_DEMAND_INDEX",
                )
                return RegionalDemandContext.model_validate(
                    {
                        **fields,
                        "state": "AVAILABLE",
                        "reason": "NONE",
                        "measures": (measure,),
                        "warning_ko": (
                            f"{region_name}·월별 관광 수요의 상대적 지수입니다. "
                            "비율(%)·금액·인원 또는 "
                            "개별 장소의 혼잡도가 아니며 추천 순서에 반영하지 않습니다."
                        ),
                    }
                )
        return RegionalDemandContext.model_validate(
            {
                **fields,
                "reason": "UNIT_UNVERIFIED" if measures else "EMPTY",
                "measures": tuple(measures),
            }
        )

    def get_context_with_sources(
        self,
        *,
        place_ids: tuple[str, ...],
        trip_date: date,
        visitor_start: date | None = None,
        visitor_end: date | None = None,
        demand_month: str | None = None,
    ) -> tuple[TripTemporalContext, tuple[TemporalSourceSnapshot, ...]]:
        if len(set(place_ids)) != len(place_ids) or any(
            place_id not in self.places for place_id in place_ids
        ):
            raise ValueError("only unique canonical place IDs are accepted")
        if (visitor_start is None) != (visitor_end is None):
            raise ValueError("visitor period requires both start and end")
        if (
            visitor_start
            and visitor_end
            and not 0 <= (visitor_end - visitor_start).days < self.policy.max_visitor_period_days
        ):
            raise ValueError("visitor period exceeds bounded range")
        if demand_month is not None and re.fullmatch(r"\d{4}(0[1-9]|1[0-2])", demand_month) is None:
            raise ValueError("invalid demand month")
        now = require_utc(self.clock(), field_name="clock")
        regions = {self.places[pid].region_code: self.places[pid].region_label for pid in place_ids}
        if not regions:
            catalog_regions = {row.region_code: row.region_label for row in self.places.values()}
            if len(catalog_regions) != 1:
                raise ValueError("regional-only context requires one unambiguous catalog region")
            regions = catalog_regions
        jobs: dict[str, Callable[[], TemporalSourceSnapshot]] = {}

        def forecast_job(code: str) -> Callable[[], TemporalSourceSnapshot]:
            return lambda: self._batch(
                SourceService.CONCENTRATION,
                "tatsCnctrRatedList",
                {"areaCd": code[:2], "signguCd": code},
                self.concentration,
            )

        def demand_job(code: str, operation: str) -> Callable[[], TemporalSourceSnapshot]:
            index_parameter, index_code = (
                ("tarSjrnDsIxCd", "21")
                if operation == "areaTarSjrnDsList"
                else ("tarExpDsIxCd", "22")
            )
            return lambda: self._batch(
                SourceService.DEMAND,
                operation,
                {
                    "baseYm": cast(str, demand_month),
                    "areaCd": code[:2],
                    "signguCd": code,
                    index_parameter: index_code,
                },
                self.demand,
            )

        for code in regions:
            if place_ids:
                jobs[f"forecast:{code}"] = forecast_job(code)
            if demand_month is not None and demand_month < _local_day(now).strftime("%Y%m"):
                jobs[f"stay:{code}"] = demand_job(code, "areaTarSjrnDsList")
                jobs[f"spend:{code}"] = demand_job(code, "areaTarExpDsList")
        if visitor_start and visitor_end and visitor_end < _local_day(now):
            jobs["visitors"] = lambda: self._batch(
                SourceService.VISITORS,
                "locgoRegnVisitrDDList",
                {
                    "startYmd": visitor_start.strftime("%Y%m%d"),
                    "endYmd": visitor_end.strftime("%Y%m%d"),
                },
                self.visitors,
            )
        with ThreadPoolExecutor(max_workers=self.policy.http_concurrency) as executor:
            futures = {name: executor.submit(job) for name, job in jobs.items()}
            snapshots = {name: future.result() for name, future in futures.items()}
        forecasts = tuple(
            self._forecast(
                self.places[pid],
                trip_date,
                now,
                snapshots[f"forecast:{self.places[pid].region_code}"],
            )
            for pid in place_ids
        )
        regional_visitors = tuple(
            self._visitors(visitor_start, visitor_end, now, snapshots.get("visitors"), code, name)
            for code, name in regions.items()
        )
        regional_demand = tuple(
            self._demand(
                cast(Literal["REGIONAL_STAY_INTENSITY", "REGIONAL_SPENDING_INTENSITY"], kind),
                demand_month,
                now,
                snapshots.get(f"{key}:{code}"),
                code,
                name,
            )
            for code, name in regions.items()
            for key, kind in (
                ("stay", "REGIONAL_STAY_INTENSITY"),
                ("spend", "REGIONAL_SPENDING_INTENSITY"),
            )
        )
        visitors = regional_visitors[0]
        demand = regional_demand[:2]
        draft = TripTemporalContext.model_construct(
            trip_date=trip_date,
            checked_at=now,
            forecasts=forecasts,
            visitors=visitors,
            demand=demand,
            regional_visitors=regional_visitors,
            regional_demand=regional_demand,
            source_snapshot_sha256=tuple(
                sorted(
                    {canonical_sha256(row.model_dump(mode="json")) for row in snapshots.values()}
                )
            ),
            context_sha256="0" * 64,
        )
        payload = draft.model_dump(mode="json", exclude={"context_sha256"})
        return TripTemporalContext.model_validate(
            {**payload, "context_sha256": canonical_sha256(payload)}
        ), tuple(snapshots.values())

    def get_context(
        self,
        *,
        place_ids: tuple[str, ...],
        trip_date: date,
        visitor_start: date | None = None,
        visitor_end: date | None = None,
        demand_month: str | None = None,
    ) -> TripTemporalContext:
        return self.get_context_with_sources(
            place_ids=place_ids,
            trip_date=trip_date,
            visitor_start=visitor_start,
            visitor_end=visitor_end,
            demand_month=demand_month,
        )[0]

    @staticmethod
    def replay(payload: dict[str, object]) -> TripTemporalContext:
        """Validate stored content verbatim without freshness checks or provider access."""
        return TripTemporalContext.model_validate(payload)
