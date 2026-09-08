"""Complete, deterministic TourAPI input refresh for the fixed PUBLIC-100."""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from datetime import date, datetime
from typing import Protocol

from pydantic import BaseModel

from itda.collectors.base import CollectedResponse, CollectionError, RequestPolicy
from itda.collectors.kto import KorService2Client
from itda.contracts.catalog_collection import classify_provider_result
from itda.contracts.mvp_daily_refresh import (
    DAILY_REFRESH_AUTHORITY_V2,
    DAILY_REFRESH_CONCURRENCY,
    DAILY_REFRESH_MAXIMUM_CALLS,
    DAILY_REFRESH_MEMBERSHIP_SHA256,
    DAILY_REFRESH_RETRY_LIMIT,
    DailyCollectionFailure,
    DailyCollectionOperation,
    DailyExcludedPlace,
    DailyIncrementalScoringPlanV2,
    DailyInputDeltaV2,
    DailyPlaceInput,
    DailyProviderProvenance,
    DailyScoringInputSnapshotV2,
    DailySnapshot,
)
from itda.contracts.mvp_place_scoring import (
    GLM_CODING_ENDPOINT,
    GLM_MODEL,
    MVP_SCORING_PROMPT_SHA256,
    PUBLIC_SCORING_RUBRIC,
    PublicScoringRequest,
    reject_forbidden_fields,
)
from itda.contracts.mvp_public_catalog import (
    PublicEvidence,
    PublicEvidenceInventory,
    PublicPlace,
    PublicPlaceCatalog,
)
from itda.domain.canonical import canonical_sha256
from itda.operating.service import (
    CATEGORY_CONTENT_TYPE,
    FIELDS_BY_TYPE,
    ProviderPlace,
    parse_operating_snapshot,
)

_TAG = re.compile(r"<[^>]*>")
_SPACE = re.compile(r"\s+")


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        rendered = value.isoformat()
        return rendered.replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _json_fields(fields: Mapping[str, object]) -> dict[str, object]:
    return {str(key): _json_value(value) for key, value in fields.items()}


class DailyCollectionIncomplete(RuntimeError):
    def __init__(
        self,
        safe_reason: str,
        *,
        failure: DailyCollectionFailure | None = None,
    ) -> None:
        super().__init__(safe_reason)
        self.safe_reason = safe_reason
        self.failure = failure


def _safe_failure_code(error: Exception) -> str:
    if not isinstance(error, CollectionError):
        return "UNEXPECTED_PROVIDER_ERROR"
    value = error.normalized_failure_reason or error.outcome
    normalized = re.sub(r"[^A-Z0-9_]", "_", value.upper()).strip("_")
    return normalized[:80] if normalized else "TOUR_API_COLLECTION_FAILED"


def _safe_failure_category(error: Exception) -> str:
    if not isinstance(error, CollectionError):
        return "PROVIDER_TRANSPORT"
    normalized = re.sub(r"[^A-Z0-9_]", "_", error.category.upper()).strip("_")
    return normalized[:80] if normalized else "COLLECTION"


def _collection_failure(
    *,
    place_id: str,
    operation: DailyCollectionOperation,
    error: Exception,
) -> DailyCollectionIncomplete:
    return DailyCollectionIncomplete(
        "TOUR_API_COLLECTION_FAILED",
        failure=DailyCollectionFailure(
            place_id=place_id,
            operation=operation,
            failure_category=_safe_failure_category(error),
            failure_code=_safe_failure_code(error),
        ),
    )


def _response_validation_failure(
    *,
    place_id: str,
    operation: DailyCollectionOperation,
    safe_reason: str,
) -> DailyCollectionIncomplete:
    return DailyCollectionIncomplete(
        "TOUR_API_COLLECTION_FAILED",
        failure=DailyCollectionFailure(
            place_id=place_id,
            operation=operation,
            failure_category="RESPONSE_VALIDATION",
            failure_code=safe_reason,
        ),
    )


class DailyTourApiProvider(Protocol):
    def fetch_common(self, place: ProviderPlace) -> CollectedResponse: ...

    def fetch_intro(self, place: ProviderPlace) -> CollectedResponse: ...

    def close(self) -> None: ...


class LiveDailyTourApiProvider:
    def __init__(self, *, service_key: str, timeout_seconds: float = 15.0) -> None:
        self._client = KorService2Client(
            service_key=service_key,
            policy=RequestPolicy(
                timeout_seconds=timeout_seconds,
                max_attempts=1,
                initial_backoff_seconds=0,
            ),
        )

    def fetch_common(self, place: ProviderPlace) -> CollectedResponse:
        return self._client.request(
            "detailCommon2",
            {
                "contentId": place.content_id,
                "numOfRows": "1",
                "pageNo": "1",
            },
            explicit_opt_in=True,
        )

    def fetch_intro(self, place: ProviderPlace) -> CollectedResponse:
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


def _normalize(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    rendered = html.unescape(_TAG.sub(" ", str(value)))
    rendered = _SPACE.sub(" ", rendered).strip()
    return rendered[:maximum] if rendered else None


def _validated_item(
    response: CollectedResponse,
    place: ProviderPlace,
) -> Mapping[str, object] | None:
    if response.provider != "TOUR_API" or not 200 <= response.http_status < 300:
        raise DailyCollectionIncomplete("PROVIDER_RESPONSE_INVALID")
    payload = response.payload
    envelope = payload.get("response") if isinstance(payload, Mapping) else None
    header = envelope.get("header") if isinstance(envelope, Mapping) else None
    body = envelope.get("body") if isinstance(envelope, Mapping) else None
    if not isinstance(header, Mapping) or not isinstance(body, Mapping):
        raise DailyCollectionIncomplete("RESPONSE_ENVELOPE_INVALID")
    code = header.get("resultCode")
    if code not in ("00", "0000", "03") or classify_provider_result(code) not in (
        "SUCCESS",
        "NO_DATA",
    ):
        raise DailyCollectionIncomplete("PROVIDER_RESULT_REJECTED")
    if response.provider_result_code not in (None, code):
        raise DailyCollectionIncomplete("PROVIDER_RESULT_CONTRADICTED")
    if "items" not in body:
        raise DailyCollectionIncomplete("CONTENT_ITEMS_MISSING")
    container = body["items"]
    if container in (None, "", [], {}):
        items: tuple[Mapping[str, object], ...] = ()
    elif isinstance(container, Mapping) and set(container) == {"item"}:
        item = container["item"]
        if item in (None, "", [], {}):
            items = ()
        elif isinstance(item, Mapping):
            items = (item,)
        elif isinstance(item, list) and all(isinstance(row, Mapping) for row in item):
            items = tuple(item)
        else:
            raise DailyCollectionIncomplete("CONTENT_ITEMS_INVALID")
    else:
        raise DailyCollectionIncomplete("CONTENT_ITEMS_INVALID")
    total = body.get("totalCount")
    if total is not None and (
        isinstance(total, bool)
        or not isinstance(total, (str, int))
        or re.fullmatch(r"[0-9]+", str(total)) is None
    ):
        raise DailyCollectionIncomplete("TOTAL_COUNT_INVALID")
    count = int(total) if total is not None else None
    if not items:
        if count != 0:
            raise DailyCollectionIncomplete("CONTENT_ITEMS_MISSING")
        return None
    if code == "03" or count not in (None, 1):
        raise DailyCollectionIncomplete("TOTAL_COUNT_CONTRADICTED")
    if len(items) != 1:
        raise DailyCollectionIncomplete("CONTENT_ID_DUPLICATED")
    item = items[0]
    if str(item.get("contentid", item.get("contentId", ""))) != place.content_id:
        raise DailyCollectionIncomplete("CONTENT_ID_MISMATCH")
    content_type = item.get("contenttypeid", item.get("contentTypeId"))
    if content_type is not None and str(content_type) != place.content_type_id:
        raise DailyCollectionIncomplete("CONTENT_TYPE_MISMATCH")
    return item


def _common_item(response: CollectedResponse, content_id: str) -> Mapping[str, object]:
    items = _items(response.payload)
    if (
        len(items) != 1
        or str(items[0].get("contentid", items[0].get("contentId", ""))) != content_id
    ):
        raise DailyCollectionIncomplete("CONTENT_ID_MISMATCH")
    return items[0]


def _event_end(item: Mapping[str, object] | None, place: ProviderPlace) -> date | None:
    if item is None or place.content_type_id != "15":
        return None
    dates: dict[str, date | None] = {}
    for name in FIELDS_BY_TYPE["15"]:
        if name not in ("eventstartdate", "eventenddate"):
            continue
        value = item.get(name)
        if value in (None, ""):
            dates[name] = None
            continue
        if not isinstance(value, str) or re.fullmatch(r"[0-9]{8}", value) is None:
            raise DailyCollectionIncomplete("EVENT_DATE_INVALID")
        try:
            dates[name] = date(int(value[:4]), int(value[4:6]), int(value[6:]))
        except ValueError as error:
            raise DailyCollectionIncomplete("EVENT_DATE_INVALID") from error
    start, end = dates["eventstartdate"], dates["eventenddate"]
    if start is not None and end is not None and start > end:
        raise DailyCollectionIncomplete("EVENT_DATE_RANGE_INVALID")
    return end


def _provenance(response: CollectedResponse) -> DailyProviderProvenance:
    return DailyProviderProvenance.model_validate(
        {
            "operation": response.endpoint,
            "http_status": response.http_status,
            "response_sha256": response.raw_response_sha256,
            "retrieved_at": response.retrieved_at,
        }
    )


def _optional_text(item: Mapping[str, object], *names: str, maximum: int) -> str | None:
    for name in names:
        value = _normalize(item.get(name), maximum=maximum)
        if value is not None:
            return value
    return None


def _required_text(item: Mapping[str, object], *names: str, maximum: int) -> str:
    value = _optional_text(item, *names, maximum=maximum)
    if value is not None:
        return value
    raise DailyCollectionIncomplete("REQUIRED_TEXT_MISSING")


def _coordinate(item: Mapping[str, object], name: str, minimum: float, maximum: float) -> float:
    value = item.get(name)
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise DailyCollectionIncomplete("COORDINATE_INVALID")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise DailyCollectionIncomplete("COORDINATE_INVALID") from error
    if not minimum <= result <= maximum:
        raise DailyCollectionIncomplete("COORDINATE_OUTSIDE_GYEONGJU")
    return result


def _tour_api_permission(
    place: PublicPlace,
    inventory: PublicEvidenceInventory,
) -> PublicEvidence:
    evidence_by_id = {row.evidence_id: row for row in inventory.evidence}
    rows = [
        evidence_by_id[evidence_id]
        for evidence_id in place.evidence_ids
        if evidence_id in evidence_by_id and evidence_by_id[evidence_id].provider == "TOUR_API"
    ]
    if len(rows) != 1 or not rows[0].permission_metadata.permits_mvp_use:
        raise DailyCollectionIncomplete("TOUR_API_PERMISSION_BINDING_INVALID")
    return rows[0]


def _provider_place(place: PublicPlace) -> ProviderPlace:
    source_ids = [row.source_id for row in place.provider_crosswalk if row.provider == "TOUR_API"]
    content_type_id = CATEGORY_CONTENT_TYPE.get(place.category)
    if len(source_ids) != 1 or content_type_id is None:
        raise DailyCollectionIncomplete("TOUR_API_CROSSWALK_INVALID")
    return ProviderPlace(content_id=source_ids[0], content_type_id=content_type_id)


def _daily_place_input(
    *,
    place: PublicPlace,
    permission_source: PublicEvidence,
    common: CollectedResponse,
    intro: CollectedResponse,
    run_date: date,
) -> DailyPlaceInput:
    provider_place = _provider_place(place)
    common_item = _common_item(common, provider_place.content_id)
    provider_content_type = _optional_text(
        common_item,
        "contenttypeid",
        "contentTypeId",
        maximum=2,
    )
    if provider_content_type not in (None, provider_place.content_type_id):
        raise DailyCollectionIncomplete("CONTENT_TYPE_MISMATCH")
    name = _required_text(common_item, "title", "name", maximum=240)
    address = _required_text(common_item, "addr1", "address", maximum=500)
    overview = _required_text(common_item, "overview", maximum=3_200)
    provider_category_codes = tuple(
        value
        for name in ("cat1", "cat2", "cat3")
        if (value := _normalize(common_item.get(name), maximum=32)) is not None
    )
    provider_category = "/".join(provider_category_codes)
    category = f"{place.category} ({provider_category})" if provider_category else place.category
    latitude = _coordinate(common_item, "mapy", 35.0, 36.5)
    longitude = _coordinate(common_item, "mapx", 128.0, 130.5)
    operating = parse_operating_snapshot(intro, place=provider_place, cached=False)
    operating_lines = (
        tuple(f"{row.label_ko}: {row.value_ko}" for row in operating.entries)
        if operating is not None
        else ()
    )
    excerpt = "\n".join((f"소개: {overview}", *(f"운영 정보: {row}" for row in operating_lines)))
    excerpt = excerpt[:4_000]
    semantic_evidence_id = (
        f"evidence:{canonical_sha256({'place_id': place.place_id, 'excerpt': excerpt})}"
    )
    source_response_sha256 = canonical_sha256(
        {
            "detailCommon2": common.raw_response_sha256,
            "detailIntro2": intro.raw_response_sha256,
        }
    )
    evidence_fields = {
        **permission_source.model_dump(
            exclude={
                "evidence_id",
                "provider_source_id",
                "reference_date",
                "excerpt",
                "source_response_sha256",
                "evidence_sha256",
            },
            mode="json",
        ),
        "evidence_id": semantic_evidence_id,
        "provider_source_id": provider_place.content_id,
        "reference_date": run_date,
        "excerpt": excerpt,
        "source_response_sha256": source_response_sha256,
    }
    evidence = PublicEvidence.model_validate(
        {
            **evidence_fields,
            "evidence_sha256": canonical_sha256(_json_fields(evidence_fields)),
        }
    )
    request_fields = {
        "schema_version": "mvp-place-scoring-request.v2",
        "model": GLM_MODEL,
        "place": {
            "place_id": place.place_id,
            "name_ko": name,
            "category": category,
            "administrative_area": "경주시",
            "address_ko": address,
            "latitude": latitude,
            "longitude": longitude,
        },
        "evidence": (
            {
                "evidence_id": evidence.evidence_id,
                "excerpt": evidence.excerpt,
            },
        ),
        "rubric": PUBLIC_SCORING_RUBRIC,
    }
    reject_forbidden_fields(request_fields)
    request = PublicScoringRequest.model_validate(
        {**request_fields, "request_sha256": canonical_sha256(request_fields)}
    )
    row_fields = {
        "place_id": place.place_id,
        "content_id": provider_place.content_id,
        "content_type_id": provider_place.content_type_id,
        "request": request,
        "evidence": evidence,
        "common_response_sha256": common.raw_response_sha256,
        "intro_response_sha256": intro.raw_response_sha256,
        "common_provider_modifiedtime": common.modifiedtime,
        "intro_provider_modifiedtime": intro.modifiedtime,
    }
    return DailyPlaceInput.model_validate(
        {**row_fields, "row_sha256": canonical_sha256(_json_fields(row_fields))}
    )


def collect_daily_snapshot(
    *,
    catalog: PublicPlaceCatalog,
    evidence_inventory: PublicEvidenceInventory,
    provider: DailyTourApiProvider,
    run_date: date,
    collected_at: datetime,
    previous_snapshot_sha256: str | None,
) -> DailyScoringInputSnapshotV2:
    if catalog.evidence_inventory_sha256 != evidence_inventory.inventory_sha256:
        raise DailyCollectionIncomplete("CATALOG_EVIDENCE_BINDING_MISMATCH")
    if (
        canonical_sha256([row.place_id for row in catalog.places])
        != DAILY_REFRESH_MEMBERSHIP_SHA256
    ):
        raise DailyCollectionIncomplete("PUBLIC_MEMBERSHIP_AUTHORITY_MISMATCH")
    rows = []
    excluded = []
    for place in catalog.places:
        provider_place = _provider_place(place)
        try:
            common = provider.fetch_common(provider_place)
        except Exception as error:
            raise _collection_failure(
                place_id=place.place_id,
                operation=DailyCollectionOperation.DETAIL_COMMON,
                error=error,
            ) from error
        try:
            permission = _tour_api_permission(place, evidence_inventory)
            if permission.provider_source_id != provider_place.content_id:
                raise DailyCollectionIncomplete("TOUR_API_PERMISSION_BINDING_INVALID")
            common_item = _validated_item(common, provider_place)
            if common_item is None:
                fields: dict[str, object] = {
                    "place_id": place.place_id,
                    "content_id": provider_place.content_id,
                    "content_type_id": provider_place.content_type_id,
                    "state": "INFORMATION_UNAVAILABLE",
                    "safe_reason": "COMMON_INFORMATION_UNAVAILABLE",
                    "event_end_date": None,
                    "permission_evidence_sha256": permission.evidence_sha256,
                    "common": _provenance(common),
                    "intro": None,
                }
                excluded.append(
                    DailyExcludedPlace.model_validate(
                        {
                            **fields,
                            "row_sha256": canonical_sha256(_json_fields(fields)),
                        }
                    )
                )
                continue
        except (DailyCollectionIncomplete, ValueError) as error:
            raise _response_validation_failure(
                place_id=place.place_id,
                operation=DailyCollectionOperation.DETAIL_COMMON,
                safe_reason=error.safe_reason
                if isinstance(error, DailyCollectionIncomplete)
                else "PROVENANCE_INVALID",
            ) from error
        try:
            intro = provider.fetch_intro(provider_place)
        except Exception as error:
            raise _collection_failure(
                place_id=place.place_id,
                operation=DailyCollectionOperation.DETAIL_INTRO,
                error=error,
            ) from error
        try:
            intro_item = _validated_item(intro, provider_place)
            end = _event_end(intro_item, provider_place)
            if end is not None and end < run_date:
                fields = {
                    "place_id": place.place_id,
                    "content_id": provider_place.content_id,
                    "content_type_id": provider_place.content_type_id,
                    "state": "EVENT_ENDED",
                    "safe_reason": "OFFICIAL_EVENT_END_DATE_PASSED",
                    "event_end_date": end,
                    "permission_evidence_sha256": permission.evidence_sha256,
                    "common": _provenance(common),
                    "intro": _provenance(intro),
                }
                excluded.append(
                    DailyExcludedPlace.model_validate(
                        {
                            **fields,
                            "row_sha256": canonical_sha256(_json_fields(fields)),
                        }
                    )
                )
                continue
        except (DailyCollectionIncomplete, ValueError) as error:
            raise _response_validation_failure(
                place_id=place.place_id,
                operation=DailyCollectionOperation.DETAIL_INTRO,
                safe_reason=error.safe_reason
                if isinstance(error, DailyCollectionIncomplete)
                else "PROVENANCE_INVALID",
            ) from error
        try:
            rows.append(
                _daily_place_input(
                    place=place,
                    permission_source=_tour_api_permission(place, evidence_inventory),
                    common=common,
                    intro=intro,
                    run_date=run_date,
                )
            )
        except (DailyCollectionIncomplete, ValueError) as error:
            raise _response_validation_failure(
                place_id=place.place_id,
                operation=DailyCollectionOperation.DETAIL_COMMON,
                safe_reason=(
                    error.safe_reason
                    if isinstance(error, DailyCollectionIncomplete)
                    else "PUBLIC_INPUT_INVALID"
                ),
            ) from error
    places = tuple(sorted(rows, key=lambda row: row.place_id))
    fields = {
        "schema_version": "mvp-daily-scoring-input-snapshot.v2",
        "run_date": run_date,
        "collected_at": collected_at,
        "authority_sha256": DAILY_REFRESH_AUTHORITY_V2.authority_sha256,
        "membership_sha256": DAILY_REFRESH_MEMBERSHIP_SHA256,
        "previous_snapshot_sha256": previous_snapshot_sha256,
        "places": places,
        "excluded": tuple(sorted(excluded, key=lambda row: row.place_id)),
    }
    return DailyScoringInputSnapshotV2.model_validate(
        {**fields, "snapshot_sha256": canonical_sha256(_json_fields(fields))}
    )


def snapshot_semantics(snapshot: DailySnapshot) -> dict[str, object]:
    states: dict[str, object] = {
        row.place_id: ("AVAILABLE", row.request.request_sha256) for row in snapshot.places
    }
    if isinstance(snapshot, DailyScoringInputSnapshotV2):
        states.update({row.place_id: row.semantic_state for row in snapshot.excluded})
    return states


def build_daily_delta(
    previous: DailySnapshot,
    current: DailySnapshot,
) -> DailyInputDeltaV2:
    previous_by_id = snapshot_semantics(previous)
    current_by_id = snapshot_semantics(current)
    if set(previous_by_id) != set(current_by_id):
        raise ValueError("daily snapshots do not share PUBLIC-100 membership")
    changed = tuple(
        sorted(
            place_id
            for place_id, request_sha256 in current_by_id.items()
            if previous_by_id[place_id] != request_sha256
        )
    )
    unchanged = tuple(sorted(set(current_by_id) - set(changed)))
    fields = {
        "schema_version": "mvp-daily-input-delta.v2",
        "previous_snapshot_sha256": previous.snapshot_sha256,
        "snapshot_sha256": current.snapshot_sha256,
        "changed_place_ids": changed,
        "unchanged_place_ids": unchanged,
    }
    return DailyInputDeltaV2.model_validate({**fields, "delta_sha256": canonical_sha256(fields)})


def build_incremental_scoring_plan(
    *,
    snapshot: DailyScoringInputSnapshotV2,
    delta: DailyInputDeltaV2,
    scoring_place_ids: tuple[str, ...] | None = None,
) -> DailyIncrementalScoringPlanV2:
    rows = {row.place_id: row for row in snapshot.places}
    targets = (
        scoring_place_ids
        if scoring_place_ids is not None
        else tuple(place_id for place_id in delta.changed_place_ids if place_id in rows)
    )
    if delta.snapshot_sha256 != snapshot.snapshot_sha256 or not targets:
        raise ValueError("daily incremental scoring requires a non-empty matching delta")
    request_hashes = tuple(rows[place_id].request.request_sha256 for place_id in targets)
    fields = {
        "schema_version": "mvp-daily-incremental-scoring-plan.v2",
        "run_date": snapshot.run_date,
        "authority_sha256": DAILY_REFRESH_AUTHORITY_V2.authority_sha256,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "delta_sha256": delta.delta_sha256,
        "endpoint": GLM_CODING_ENDPOINT,
        "model": GLM_MODEL,
        "prompt_sha256": MVP_SCORING_PROMPT_SHA256,
        "scoring_place_ids": targets,
        "request_sha256": request_hashes,
        "first_pass_count": len(targets),
        "retry_limit_per_place": DAILY_REFRESH_RETRY_LIMIT,
        "maximum_calls": DAILY_REFRESH_MAXIMUM_CALLS,
        "concurrency": DAILY_REFRESH_CONCURRENCY,
        "fallback": False,
        "pay_as_you_go_fallback": False,
    }
    return DailyIncrementalScoringPlanV2.model_validate(
        {**fields, "plan_sha256": canonical_sha256(_json_fields(fields))}
    )
