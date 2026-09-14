"""Additive temporal context. No field is a place score or a ranking bonus."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.source_assessment import SourceReceipt, SourceService
from itda.domain.canonical import canonical_sha256

TemporalState = Literal["AVAILABLE", "PARTIAL", "UNKNOWN"]
TemporalReason = Literal[
    "NONE",
    "NOT_REQUESTED",
    "EMPTY",
    "SOURCE_UNAVAILABLE",
    "AUTHORIZATION_UNAVAILABLE",
    "PARTIAL_SERIES",
    "STALE",
    "OUT_OF_WINDOW",
    "PLACE_NOT_MATCHED",
    "AMBIGUOUS_MATCH",
    "INVALID_VALUE",
    "UNIT_UNVERIFIED",
    "FUTURE_OBSERVATION",
    "UNSUPPORTED_REGION",
]


class ForecastAlternative(StrictContract):
    target_date: date
    value: Annotated[Decimal, Field(ge=0, le=100)]


class PlaceConcentrationForecast(StrictContract):
    place_id: StableId
    provider_name: str | None
    match_method: Literal["EXACT_NAME_AND_REGION", "CURATED_NAME_AND_REGION"] | None
    region_code: Annotated[str, Field(pattern=r"^\d{5}$")] = "47130"
    scope: Literal["PLACE_RELATIVE_FORECAST"] = "PLACE_RELATIVE_FORECAST"
    state: TemporalState
    reason: TemporalReason
    target_date: date
    provider_issue_date: None = None
    issue_date_status: Literal["NOT_PROVIDED_BY_API"] = "NOT_PROVIDED_BY_API"
    window_start: date | None
    window_end: date | None
    value: Annotated[Decimal, Field(ge=0, le=100)] | None
    unit: Literal["WITHIN_PLACE_RELATIVE_INDEX_0_100"] = "WITHIN_PLACE_RELATIVE_INDEX_0_100"
    alternatives: tuple[ForecastAlternative, ...] = ()
    source_snapshot_sha256: Sha256 | None
    receipts: tuple[SourceReceipt, ...] = ()
    retrieved_at: datetime | None
    expires_at: datetime | None
    warning_ko: str = (
        "장소 자체의 붐비는 시기를 기준으로 한 방문 집중 예측입니다. "
        "실시간 인원이나 장소 간 혼잡 비교 수치가 아닙니다."
    )

    @model_validator(mode="after")
    def check_forecast(self) -> Self:
        if self.retrieved_at:
            require_utc(self.retrieved_at, field_name="retrieved_at")
        if self.expires_at:
            require_utc(self.expires_at, field_name="expires_at")
        if any(
            receipt.service != SourceService.CONCENTRATION
            or receipt.operation != "tatsCnctrRatedList"
            for receipt in self.receipts
        ):
            raise ValueError("forecast evidence must use concentration service")
        if self.state != "AVAILABLE" and (self.value is not None or self.alternatives):
            raise ValueError("unknown forecast cannot provide values or alternatives")
        if self.state == "AVAILABLE" and (
            self.value is None
            or self.source_snapshot_sha256 is None
            or self.provider_name is None
            or self.match_method is None
            or not self.receipts
            or self.window_start is None
            or self.window_end is None
            or not self.window_start <= self.target_date <= self.window_end
        ):
            raise ValueError("available forecast requires exact dated source binding")
        if (
            any(row.value >= self.value for row in self.alternatives)
            if self.value is not None
            else False
        ):
            raise ValueError("alternatives must be lower forecasts within the same place")
        if self.alternatives and (
            len({row.target_date for row in self.alternatives}) != len(self.alternatives)
            or any(
                row.target_date == self.target_date
                or self.window_start is None
                or self.window_end is None
                or not self.window_start <= row.target_date <= self.window_end
                for row in self.alternatives
            )
        ):
            raise ValueError("forecast alternatives must retain the same provider window")
        return self


class RegionalVisitorPoint(StrictContract):
    measurement_date: date
    category_code: Literal["1", "2", "3"]
    category_name: str
    state: TemporalState
    reason: TemporalReason
    value: Annotated[Decimal, Field(ge=0)] | None
    raw_value: str | None

    @model_validator(mode="after")
    def check_value(self) -> Self:
        if (self.state == "AVAILABLE") != (self.value is not None):
            raise ValueError("unavailable visitor measurement is null")
        if self.value is not None and (
            self.raw_value is None or Decimal(self.raw_value) != self.value
        ):
            raise ValueError("visitor count must preserve exact decimal source value")
        return self


class RegionalVisitorsContext(StrictContract):
    scope: Literal["REGION"] = "REGION"
    region_code: Annotated[str, Field(pattern=r"^\d{5}$")] = "47130"
    region_name: Annotated[str, Field(min_length=1, max_length=100)] = "경주시"
    unit: Literal["ESTIMATED_VISITOR_COUNT"] = "ESTIMATED_VISITOR_COUNT"
    state: TemporalState
    reason: TemporalReason
    period_start: date | None
    period_end: date | None
    provider_issue_date: None = None
    points: tuple[RegionalVisitorPoint, ...] = ()
    source_snapshot_sha256: Sha256 | None
    receipts: tuple[SourceReceipt, ...] = ()
    retrieved_at: datetime | None
    expires_at: datetime | None
    warning_ko: str = (
        "이동통신 기반 해당 시군구 전체 방문 추정치입니다. "
        "개별 관광지 인원이나 입장객 수가 아니며 구분별 값을 합산하지 않습니다."
    )

    @model_validator(mode="after")
    def validate_regional_series(self) -> Self:
        if any(
            row.service != SourceService.VISITORS or row.operation != "locgoRegnVisitrDDList"
            for row in self.receipts
        ):
            raise ValueError("municipal visitor evidence has wrong source or grain")
        keys = {(row.measurement_date, row.category_code) for row in self.points}
        if len(keys) != len(self.points):
            raise ValueError("duplicate regional visitor category/date")
        if self.points and (
            self.period_start is None
            or self.period_end is None
            or any(
                not self.period_start <= row.measurement_date <= self.period_end
                for row in self.points
            )
        ):
            raise ValueError("visitor date outside requested period")
        if self.state == "AVAILABLE" and (
            not self.points
            or self.period_start is None
            or self.period_end is None
            or len(self.points) != ((self.period_end - self.period_start).days + 1) * 3
            or any(row.state != "AVAILABLE" for row in self.points)
            or not self.receipts
            or self.source_snapshot_sha256 is None
        ):
            raise ValueError("available visitor series requires complete source-bound categories")
        return self


class RegionalDemandMeasure(StrictContract):
    indicator_code: str
    indicator_name: str
    raw_value: str
    value: Annotated[Decimal, Field(allow_inf_nan=False)] | None = None
    state: Literal["AVAILABLE", "UNKNOWN"] = "UNKNOWN"
    reason: Literal["NONE", "UNIT_UNVERIFIED"] = "UNIT_UNVERIFIED"
    unit: Literal["TOURISM_DEMAND_INDEX", "UNVERIFIED_PROVIDER_UNIT"] = "UNVERIFIED_PROVIDER_UNIT"

    @model_validator(mode="after")
    def validate_index(self) -> Self:
        if self.state == "UNKNOWN":
            if (
                self.value is not None
                or self.reason != "UNIT_UNVERIFIED"
                or self.unit != "UNVERIFIED_PROVIDER_UNIT"
            ):
                raise ValueError("unverified regional measure cannot provide a usable index")
            return self
        names = {"21": "관광체류강도", "22": "관광소비강도"}
        try:
            raw = Decimal(self.raw_value)
        except InvalidOperation as error:
            raise ValueError("regional index must preserve a finite decimal source") from error
        if (
            self.indicator_code not in names
            or self.indicator_name != names[self.indicator_code]
            or self.value is None
            or not raw.is_finite()
            or raw != self.value
            or self.reason != "NONE"
            or self.unit != "TOURISM_DEMAND_INDEX"
        ):
            raise ValueError("regional index identity, unit or exact source value differs")
        return self


class RegionalDemandContext(StrictContract):
    scope: Literal["REGION"] = "REGION"
    region_code: Annotated[str, Field(pattern=r"^\d{5}$")] = "47130"
    region_name: Annotated[str, Field(min_length=1, max_length=100)] = "경주시"
    measure_kind: Literal["REGIONAL_STAY_INTENSITY", "REGIONAL_SPENDING_INTENSITY"]
    state: TemporalState
    reason: TemporalReason
    base_month: Annotated[str, Field(pattern=r"^\d{4}(0[1-9]|1[0-2])$")] | None
    provider_issue_date: None = None
    measures: tuple[RegionalDemandMeasure, ...] = ()
    provider_result_code: str | None
    source_snapshot_sha256: Sha256 | None
    receipts: tuple[SourceReceipt, ...] = ()
    retrieved_at: datetime | None
    expires_at: datetime | None
    warning_ko: str = (
        "지역·월별 지표입니다. 개별 장소의 체류시간·혼잡·인기도로 환산하지 않습니다. "
        "단위가 확인되지 않은 수치는 공식 원문으로만 제공합니다."
    )

    @model_validator(mode="after")
    def validate_regional_demand(self) -> Self:
        operation = (
            "areaTarSjrnDsList"
            if self.measure_kind == "REGIONAL_STAY_INTENSITY"
            else "areaTarExpDsList"
        )
        if any(
            row.service != SourceService.DEMAND or row.operation != operation
            for row in self.receipts
        ):
            raise ValueError("regional indicator source does not match measure kind")
        if self.state == "AVAILABLE":
            code = "21" if self.measure_kind == "REGIONAL_STAY_INTENSITY" else "22"
            parameter = (
                "tarSjrnDsIxCd"
                if self.measure_kind == "REGIONAL_STAY_INTENSITY"
                else "tarExpDsIxCd"
            )
            if self.retrieved_at is not None:
                require_utc(self.retrieved_at, field_name="retrieved_at")
            if self.expires_at is not None:
                require_utc(self.expires_at, field_name="expires_at")
            if (
                self.reason != "NONE"
                or self.base_month is None
                or len(self.measures) != 1
                or self.measures[0].state != "AVAILABLE"
                or self.measures[0].indicator_code != code
                or self.source_snapshot_sha256 is None
                or self.retrieved_at is None
                or self.expires_at is None
                or self.expires_at <= self.retrieved_at
                or not self.receipts
                or any(
                    row.status != "AVAILABLE"
                    or row.http_status != 200
                    or row.request_scope.get("areaCd") != self.region_code[:2]
                    or row.request_scope.get("signguCd") != self.region_code
                    or row.request_scope.get("baseYm") != self.base_month
                    or row.request_scope.get(parameter) != code
                    for row in self.receipts
                )
            ):
                raise ValueError("available regional index requires exact dated source binding")
            return self
        if self.state != "UNKNOWN" or any(row.state != "UNKNOWN" for row in self.measures):
            raise ValueError("unverified provider units cannot establish a usable measurement")
        if self.measures and (
            self.source_snapshot_sha256 is None
            or not self.receipts
            or self.reason != "UNIT_UNVERIFIED"
        ):
            raise ValueError("raw unverified indicators require exact source provenance")
        return self


class TripTemporalContext(StrictContract):
    schema_version: Literal["trip-temporal-context.v1"] = "trip-temporal-context.v1"
    policy_version: Literal["temporal-context-v1"] = "temporal-context-v1"
    usage: Literal["INFORMATION_ONLY"] = "INFORMATION_ONLY"
    ranking_effect: Literal["NONE"] = "NONE"
    trip_date: date
    checked_at: datetime
    forecasts: tuple[PlaceConcentrationForecast, ...]
    visitors: RegionalVisitorsContext
    demand: tuple[RegionalDemandContext, RegionalDemandContext]
    regional_visitors: Annotated[
        tuple[RegionalVisitorsContext, ...], Field(exclude_if=lambda value: not value)
    ] = ()
    regional_demand: Annotated[
        tuple[RegionalDemandContext, ...], Field(exclude_if=lambda value: not value)
    ] = ()
    source_snapshot_sha256: tuple[Sha256, ...]
    context_sha256: Sha256

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        require_utc(self.checked_at, field_name="checked_at")
        if len({row.place_id for row in self.forecasts}) != len(self.forecasts):
            raise ValueError("duplicate forecast place")
        if any(row.target_date != self.trip_date for row in self.forecasts):
            raise ValueError("forecast target differs from trip date")
        references: tuple[
            PlaceConcentrationForecast | RegionalVisitorsContext | RegionalDemandContext, ...
        ] = (
            *self.forecasts,
            self.visitors,
            *self.demand,
            *self.regional_visitors,
            *self.regional_demand,
        )
        if self.regional_visitors and (
            len({row.region_code for row in self.regional_visitors}) != len(self.regional_visitors)
            or self.visitors != self.regional_visitors[0]
        ):
            raise ValueError("regional visitors must be unique and preserve the primary region")
        if self.regional_demand and (
            len({(row.region_code, row.measure_kind) for row in self.regional_demand})
            != len(self.regional_demand)
            or tuple(self.regional_demand[:2]) != self.demand
        ):
            raise ValueError("regional demand must be unique and preserve the primary region")
        referenced = tuple(
            sorted(
                {
                    row.source_snapshot_sha256
                    for row in references
                    if row.source_snapshot_sha256 is not None
                }
            )
        )
        if self.source_snapshot_sha256 != referenced:
            raise ValueError("temporal source snapshot membership mismatch")
        if self.context_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"context_sha256"})
        ):
            raise ValueError("temporal context hash mismatch")
        return self
