"""Production composition of all seven official tourism source consumers."""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime
from pathlib import Path
from threading import BoundedSemaphore, Lock
from typing import Any, Literal, cast
from urllib.parse import unquote
from zoneinfo import ZoneInfo

import httpx

from itda.collectors.base import CollectionError, OfficialApiClient, credential_material_present
from itda.collectors.kto_accessibility import KorWithService2Client
from itda.collectors.kto_camping import CampingClient
from itda.collectors.kto_concentration import ConcentrationClient
from itda.collectors.kto_demand import RegionalDemandClient
from itda.collectors.kto_related import RelatedDestinationsClient
from itda.collectors.kto_visitors import RegionalVisitorsClient
from itda.collectors.kto_walking import WalkingClient
from itda.contracts.grounded_recommendation import GroundedTripInput, TripContextPlace
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.contracts.place_enrichment import (
    RelatedCanonicalPlace,
    WalkingContext,
)
from itda.contracts.provenance import MAX_PROVIDER_RAW_BYTES
from itda.contracts.source_assessment import SourceReceipt, SourceService, SupportState
from itda.contracts.tourism_context import (
    TOURISM_CONSUMERS,
    TourismContextResponse,
    TourismPlaceContext,
    TourismReferencePeriods,
    TourismSourceHealth,
)
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import (
    AccessibilityService,
    CanonicalTourismPlace,
)
from itda.tourism.camping import CampingEnrichmentService
from itda.tourism.related import RelatedDestinationsService
from itda.tourism.settings import TourismSettings
from itda.tourism.temporal import TemporalContextService, TemporalPolicy
from itda.tourism.walking import WalkingEnrichmentService

_ADAPTERS: dict[SourceService, tuple[str, type[OfficialApiClient]]] = {
    SourceService.ACCESSIBILITY: ("ACCESSIBILITY", KorWithService2Client),
    SourceService.CONCENTRATION: ("CONCENTRATION", ConcentrationClient),
    SourceService.VISITORS: ("VISITORS", RegionalVisitorsClient),
    SourceService.DEMAND: ("DEMAND", RegionalDemandClient),
    SourceService.CAMPING: ("CAMPING", CampingClient),
    SourceService.WALKING: ("WALKING", WalkingClient),
    SourceService.RELATED: ("RELATED", RelatedDestinationsClient),
}
AttemptObserver = Callable[[dict[str, object], bytes | None], None]


def _read_secret(environment: Mapping[str, str], name: str, file_name: str) -> str:
    if path := environment.get(file_name, "").strip():
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ValueError("configured tourism credential file is unavailable") from error
    else:
        value = environment.get(name, "").strip()
    return unquote(value)


def tourism_credentials(environment: Mapping[str, str]) -> dict[SourceService, str]:
    common = _read_secret(environment, "TOUR_API_SERVICE_KEY", "ITDA_TOUR_API_SERVICE_KEY_FILE")
    return {
        service: (
            _read_secret(
                environment,
                f"ITDA_TOURISM_{name}_SERVICE_KEY",
                f"ITDA_TOURISM_{name}_SERVICE_KEY_FILE",
            )
            or common
        )
        for service, (name, _) in _ADAPTERS.items()
    }


class _BoundedHttpClient(httpx.Client):
    """One process-local cap covers accessibility and all shared batch collectors."""

    def __init__(
        self, delegate: httpx.Client, concurrency: int, observer: AttemptObserver | None = None
    ) -> None:
        super().__init__()
        self.delegate = delegate
        self.limit = BoundedSemaphore(concurrency)
        self.observer = observer
        self.credentials: tuple[str, ...] = ()
        self.events: list[dict[str, object]] = []
        self.event_lock = Lock()

    def get(self, url: Any, **kwargs: Any) -> httpx.Response:
        raw: bytes | None = None
        response = None
        error_type = None
        response_byte_count = None
        params = kwargs.get("params", {})
        scope = {
            str(key): str(value)
            for key, value in params.items()
            if not re.search(
                r"servicekey|apikey|authorization|secret|token", str(key).replace("_", ""), re.I
            )
        }
        started = time.perf_counter()
        try:
            with self.limit:
                response = self.delegate.get(url, **kwargs)
            raw = response.content
            response_byte_count = len(raw)
            if len(raw) > MAX_PROVIDER_RAW_BYTES:
                raw = None
                raise CollectionError("provider response exceeded bounded byte policy")
            if any(credential_material_present(raw, key) for key in self.credentials if key):
                raw = None
                raise CollectionError("provider response contained sensitive credential material")
            return response
        except (httpx.RequestError, CollectionError) as error:
            error_type = type(error).__name__
            raise
        finally:
            endpoint = str(url)
            event: dict[str, object] = {
                "endpoint": endpoint,
                "operation": endpoint.rsplit("/", 1)[-1],
                "service": endpoint.rsplit("/", 2)[-2],
                "request_scope": scope,
                "http_status": response.status_code if response else None,
                "exception_class": error_type,
                "response_byte_count": response_byte_count,
                "latency_ms": max(0, round((time.perf_counter() - started) * 1000)),
                "response_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            }
            with self.event_lock:
                self.events.append(event)
                if len(self.events) > 4096:
                    self.events.pop(0)
                if self.observer:
                    self.observer(event, raw)


def _periods(settings: TourismSettings, now: datetime) -> TourismReferencePeriods:
    today = now.astimezone(ZoneInfo("Asia/Seoul")).date()
    month_index = today.year * 12 + today.month - 1 - settings.reference_lag_months
    reference = date(month_index // 12, month_index % 12 + 1, 1)
    return TourismReferencePeriods(
        visitor_start=settings.visitor_reference_start or reference,
        visitor_end=settings.visitor_reference_end or reference,
        demand_month=settings.demand_reference_month or reference.strftime("%Y%m"),
        # Official dataset15128560 documents coverage through2025-04 (checked
        # 2026-09-09). Do not assume this service follows visitors' release lag.
        # Operators may select a newer month once provider coverage is verified.
        related_month=settings.related_reference_month or min(reference.strftime("%Y%m"), "202504"),
        lag_months=settings.reference_lag_months,
    )


def _clip_walking(context: WalkingContext, limit: int) -> WalkingContext:
    # Selection reduces the public response, while complete raw batches stay pinned.
    courses = sorted(
        context.courses, key=lambda row: (row.link_kind == "REGIONAL_COURSE", row.course_id)
    )[:limit]
    payload = context.model_dump(mode="json", exclude={"context_sha256"})
    payload["courses"] = [row.model_dump(mode="json") for row in courses]
    return WalkingContext.model_validate({**payload, "context_sha256": canonical_sha256(payload)})


class ProductionTourismRegistry:
    """Registry performs useful product reads; a configured client alone is insufficient."""

    def __init__(
        self,
        *,
        catalog: PublicPlaceCatalog,
        settings: TourismSettings,
        environment: Mapping[str, str],
        http_client: httpx.Client | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        observer: AttemptObserver | None = None,
    ) -> None:
        self.catalog = catalog
        self.settings = settings
        self.environment = environment
        self.clock = clock
        self._owned_http = http_client is None
        self._http = _BoundedHttpClient(
            http_client or httpx.Client(follow_redirects=False, trust_env=False),
            settings.http_concurrency,
            observer,
        )
        self._credential_lock = Lock()
        self._credential_fingerprint = ""
        self._canonical = {
            row.place_id: CanonicalTourismPlace(
                place_id=row.place_id,
                name_ko=row.name_ko,
                address=row.address_ko,
                latitude=row.latitude,
                longitude=row.longitude,
                region_code=row.region_code or "47130",
                region_name=row.administrative_area if row.region_code else None,
                provider_content_id=next(
                    (
                        cross.source_id
                        for cross in row.provider_crosswalk
                        if cross.provider == "TOUR_API"
                    ),
                    None,
                ),
            )
            for row in catalog.places
        }
        self._related_places = tuple(
            RelatedCanonicalPlace(
                **self._canonical[row.place_id].model_dump(),
                category=row.category,
                duplicate_group_id=row.duplicate_group_id,
            )
            for row in catalog.places
        )
        self._refresh_credentials()

    @classmethod
    def from_catalog(
        cls,
        catalog: PublicPlaceCatalog,
        *,
        settings: TourismSettings | None = None,
        environ: Mapping[str, str] | None = None,
        http_client: httpx.Client | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        observer: AttemptObserver | None = None,
    ) -> ProductionTourismRegistry:
        environment = os.environ if environ is None else environ
        return cls(
            catalog=catalog,
            settings=settings or TourismSettings.from_environment(environment),
            environment=environment,
            http_client=http_client,
            clock=clock,
            observer=observer,
        )

    def refresh_credentials(self) -> None:
        """Refresh privately before direct recommendation-time facility consumers."""
        self._refresh_credentials()

    def _refresh_credentials(self) -> None:
        keys = tourism_credentials(self.environment)
        fingerprint = canonical_sha256({service.value: key for service, key in keys.items()})
        with self._credential_lock:
            if fingerprint == self._credential_fingerprint:
                return
            self._credential_fingerprint = fingerprint  # Private only; never emitted or persisted.
            # In-flight calls may still hold the previous key after a rotation.
            # Retain private redaction material so diagnostic observers never
            # write an echoed previous credential before the old client rejects it.
            self._http.credentials = tuple(set(self._http.credentials) | set(keys.values()))
            self.clients = {
                service: adapter(
                    service_key=keys[service],
                    http_client=self._http,
                    policy=self.settings.request_policy(),
                    clock=self.clock,
                )
                if keys[service]
                else None
                for service, (_, adapter) in _ADAPTERS.items()
            }
            places = tuple(self._canonical.values())
            policy = TemporalPolicy(
                enabled=self.settings.enabled,
                http_concurrency=self.settings.http_concurrency,
                page_size=self.settings.national_page_size,
                max_pages=self.settings.national_max_pages,
                positive_ttl_seconds=self.settings.temporal_ttl_seconds,
                negative_ttl_seconds=self.settings.negative_ttl_seconds,
            )
            self.temporal = TemporalContextService(
                places=places,
                policy=policy,
                clock=self.clock,
                concentration=cast(
                    ConcentrationClient | None, self.clients[SourceService.CONCENTRATION]
                ),
                visitors=cast(RegionalVisitorsClient | None, self.clients[SourceService.VISITORS]),
                demand=cast(RegionalDemandClient | None, self.clients[SourceService.DEMAND]),
            )
            self.accessibility = AccessibilityService(
                places=places,
                settings=self.settings,
                clock=self.clock,
                client=cast(
                    KorWithService2Client | None, self.clients[SourceService.ACCESSIBILITY]
                ),
            )
            self.camping = CampingEnrichmentService(
                places=places,
                loader=self.temporal,
                clock=self.clock,
                client=cast(CampingClient | None, self.clients[SourceService.CAMPING]),
            )
            self.walking = WalkingEnrichmentService(
                places=places,
                loader=self.temporal,
                clock=self.clock,
                client=cast(WalkingClient | None, self.clients[SourceService.WALKING]),
            )
            self.related = RelatedDestinationsService(
                places=self._related_places,
                loader=self.temporal,
                clock=self.clock,
                client=cast(RelatedDestinationsClient | None, self.clients[SourceService.RELATED]),
            )

    def close(self) -> None:
        self._http.close()
        if self._owned_http:
            self._http.delegate.close()

    def context_with_sources(
        self,
        *,
        run_id: str,
        place_ids: tuple[str, ...],
        trip_input: GroundedTripInput,
        eligible_place_ids: tuple[str, ...],
        purpose: str = "SIGHTSEEING",
        condition_excluded_place_ids: tuple[str, ...] = (),
        selected_place_ids: tuple[str, ...] = (),
        cannot_coappear_pairs: tuple[tuple[str, str], ...] = (),
    ) -> tuple[TourismContextResponse, tuple[dict[str, object], ...]]:
        known = set(self._canonical)
        if (
            not run_id
            or len(place_ids) > self.settings.max_context_places
            or len(set(place_ids)) != len(place_ids)
            or not set(place_ids) <= set(eligible_place_ids)
            or not set(eligible_place_ids) <= known
            or not (set(condition_excluded_place_ids) | set(selected_place_ids)) <= known
            or any(
                left not in known or right not in known or left == right
                for left, right in cannot_coappear_pairs
            )
            or purpose not in {"SIGHTSEEING", "FOOD", "LODGING", "MIXED"}
        ):
            raise ValueError("context requires authorized canonical run membership")
        self._refresh_credentials()
        now = self.clock()
        periods = _periods(self.settings, now)
        target = trip_input.visit_date or now.astimezone(ZoneInfo("Asia/Seoul")).date()
        start_attempt = len(self._http.events)
        # Snapshot the composed service instances so a concurrent key rotation
        # cannot mix cache generations inside this request.
        accessibility, camping, walking, related, temporal = (
            self.accessibility,
            self.camping,
            self.walking,
            self.related,
            self.temporal,
        )
        with ThreadPoolExecutor(max_workers=self.settings.http_concurrency) as executor:
            temporal_future = executor.submit(
                temporal.get_context_with_sources,
                place_ids=place_ids,
                trip_date=target,
                visitor_start=periods.visitor_start,
                visitor_end=periods.visitor_end,
                demand_month=periods.demand_month,
            )
            access_future = executor.submit(accessibility.get_many, place_ids)
            camp_futures = {
                key: executor.submit(camping.get_context_with_sources, key) for key in place_ids
            }
            walk_futures = {
                key: executor.submit(walking.get_context_with_sources, key) for key in place_ids
            }
            related_futures = {
                key: executor.submit(
                    related.get_context_with_sources,
                    place_id=key,
                    base_month=periods.related_month,
                    eligible_place_ids=eligible_place_ids,
                    purpose=purpose,
                    condition_excluded_place_ids=condition_excluded_place_ids,
                    selected_place_ids=selected_place_ids,
                    cannot_coappear_pairs=cannot_coappear_pairs,
                    limit=self.settings.max_related_suggestions,
                )
                for key in place_ids
            }
            temporal_context, temporal_sources = temporal_future.result()
            access = {snapshot.place_id: snapshot for snapshot in access_future.result()}
            camps = {key: future.result() for key, future in camp_futures.items()}
            walks = {key: future.result() for key, future in walk_futures.items()}
            relations = {key: future.result() for key, future in related_futures.items()}
        all_sources: list[Any] = list(temporal_sources) + list(access.values())
        for mapping in (camps, walks, relations):
            for _, sources in mapping.values():
                all_sources.extend(sources)
        payloads = {
            canonical_sha256(source.model_dump(mode="json")): source.model_dump(mode="json")
            for source in all_sources
        }
        places = []
        for key in place_ids:
            snapshot = access[key]
            known_facts = sum(row.state != SupportState.UNKNOWN for row in snapshot.facts.values())
            facility = TripContextPlace(
                place_id=key,
                place_name_ko=self._canonical[key].name_ko,
                facts=tuple(snapshot.facts.values()),
                source_snapshot_sha256=canonical_sha256(snapshot.model_dump(mode="json")),
                state="PARTIAL" if known_facts else "UNAVAILABLE",
                reason_ko=(
                    "확인된 공식 시설 정보를 표시합니다. 미확인은 시설이 없다는 뜻이 아닙니다."
                    if known_facts
                    else (
                        "이 장소의 시설 정보를 확인하지 못했습니다. "
                        "미확인은 시설이 없다는 뜻이 아닙니다."
                    )
                ),
            )
            places.append(
                TourismPlaceContext(
                    place_id=key,
                    place_name_ko=self._canonical[key].name_ko,
                    accessibility=facility,
                    camping=camps[key][0],
                    walking=_clip_walking(walks[key][0], self.settings.max_walking_courses),
                    related=relations[key][0],
                )
            )
        receipts: dict[SourceService, dict[str, SourceReceipt]] = {
            service: {} for service in TOURISM_CONSUMERS
        }
        for source in all_sources:
            for receipt in getattr(source, "receipts", ()):
                receipts[receipt.service][canonical_sha256(receipt.model_dump(mode="json"))] = (
                    receipt
                )
        events = self._http.events[start_attempt:]
        health = []
        for service, consumer in TOURISM_CONSUMERS.items():
            rows = tuple(receipts[service].values())
            attempts = [event for event in events if event["service"] == service.value]
            state = (
                "PARTIAL"
                if any(row.status == "AVAILABLE" for row in rows)
                and any(row.status == "UNAVAILABLE" for row in rows)
                else "AVAILABLE"
                if any(row.status == "AVAILABLE" for row in rows)
                else "EMPTY"
                if any(row.status == "EMPTY" for row in rows)
                else "UNAVAILABLE"
            )
            codes = tuple(
                sorted(
                    {
                        str(source.provider_result_code)
                        for source in all_sources
                        if getattr(source, "service", None) == service
                        and getattr(source, "provider_result_code", None)
                    }
                )
            )
            reason = (
                "NONE"
                if state == "AVAILABLE"
                else "PARTIAL_SERIES"
                if state == "PARTIAL"
                else "EMPTY"
                if state == "EMPTY"
                else "AUTHORIZATION_UNAVAILABLE"
                if any(
                    row.http_status in (401, 403) or row.reason == "AUTHORIZATION_UNAVAILABLE"
                    for row in rows
                )
                else "SOURCE_UNAVAILABLE"
            )
            health.append(
                TourismSourceHealth(
                    service=service,
                    consumer=consumer,
                    state=cast(Literal["AVAILABLE", "PARTIAL", "EMPTY", "UNAVAILABLE"], state),
                    reason=reason,
                    receipt_count=len(rows),
                    http_attempt_count=len(attempts),
                    http_latency_ms=sum(cast(int, event["latency_ms"]) for event in attempts),
                    provider_result_codes=codes,
                    retrieved_at=max((row.retrieved_at for row in rows), default=None),
                )
            )
        draft = TourismContextResponse.model_construct(
            recommendation_run_id=run_id,
            trip_input=trip_input,
            mode="REFRESHED",
            checked_at=now,
            reference_periods=periods,
            places=tuple(places),
            temporal=temporal_context,
            source_health=tuple(health),
            source_snapshot_sha256=tuple(sorted(payloads)),
            context_sha256="0" * 64,
        )
        payload = draft.model_dump(mode="json", exclude={"context_sha256"})
        return TourismContextResponse.model_validate(
            {**payload, "context_sha256": canonical_sha256(payload)}
        ), tuple(payloads[key] for key in sorted(payloads))

    def context(
        self,
        *,
        run_id: str,
        place_ids: tuple[str, ...],
        trip_input: GroundedTripInput,
        eligible_place_ids: tuple[str, ...],
        purpose: str = "SIGHTSEEING",
        condition_excluded_place_ids: tuple[str, ...] = (),
        selected_place_ids: tuple[str, ...] = (),
        cannot_coappear_pairs: tuple[tuple[str, str], ...] = (),
    ) -> TourismContextResponse:
        return self.context_with_sources(
            run_id=run_id,
            place_ids=place_ids,
            trip_input=trip_input,
            eligible_place_ids=eligible_place_ids,
            purpose=purpose,
            condition_excluded_place_ids=condition_excluded_place_ids,
            selected_place_ids=selected_place_ids,
            cannot_coappear_pairs=cannot_coappear_pairs,
        )[0]

    @staticmethod
    def replay(payload: dict[str, object]) -> TourismContextResponse:
        """Stored read; no source request, timestamp refresh or mode/hash rewrite."""
        return TourismContextResponse.model_validate(payload)
