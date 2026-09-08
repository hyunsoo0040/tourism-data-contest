"""Bounded TourAPI description enrichment for the MVP PUBLIC catalog."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

import httpx

from itda.collectors.base import credential_material_present, parse_provider_envelope
from itda.contracts.catalog_collection import classify_provider_result
from itda.contracts.mvp_catalog_enrichment import (
    CanaryOutcome,
    MvpCatalogEnrichmentOutcome,
    MvpCatalogEnrichmentPlan,
    MvpCatalogEnrichmentRequest,
    MvpCatalogEnrichmentResult,
    TourApiDiagnosticCanaryPlan,
    TourApiDiagnosticCanaryResult,
)
from itda.contracts.mvp_public_catalog import OfficialDatasetPermissionMetadata
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_public_catalog import build_catalog_gap_report
from itda.pipeline.offline_guard import LiveCollectionRefused

TOURAPI_BASE_URL = "https://apis.data.go.kr/B551011/KorService2/detailCommon2"
TOURAPI_CREDENTIAL_ENV = "TOUR_API_SERVICE_KEY"
APPROVAL_PREFIX = "approve-tourapi-public-catalog:"
CANARY_APPROVAL_PREFIX = "approve-tourapi-diagnostic-canary:"
RESPONSE_BODY_MAX_BYTES = 256 * 1024
REQUEST_TIMEOUT_SECONDS = 15
MAX_ENRICHMENT_REQUESTS = 80
DEFAULT_SPARE_COUNT = 20
PARSER_CONTRACT_VERSION = "provider-envelope.v1"
REQUEST_GRAMMAR_VERSION = "detail-common-fixed.v1"
CONSUMED_V3_PLAN_SHA256 = (
    "dc5f4adea93b0e94ebe597bdaf6e140bea73a09a70a8909ef43f7735b88277ce"
)
CONSUMED_V5_PLAN_SHA256 = (
    "7a70a63b472980b12afa17250be87aab7cefc1d26204ffb65ddb858f8c6aaeb9"
)
CONSUMED_V5_RESULT_SHA256 = (
    "b38ff474f8e4baabc0d61dbd6c0019dbb32bc437fe73f6fa5bd4255e6d4946fe"
)
CONSUMED_V6_PLAN_SHA256 = (
    "adad3f9b0b308aac2827258c9a9275f7fc01b9d20a6ebf4e43e4fb38a2fa414e"
)


@dataclass(frozen=True, slots=True)
class EnrichmentResponse:
    body: bytes
    content_type: str = "application/json"


class EnrichmentTransport(Protocol):
    def fetch(self, request: MvpCatalogEnrichmentRequest) -> EnrichmentResponse: ...

    def close(self) -> None: ...


class TourApiDetailTransport:
    """Single-operation live transport with a secret-free failure surface."""

    def __init__(
        self,
        service_key: str,
        *,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not service_key:
            raise ValueError("TourAPI credential is absent")
        self._service_key = service_key
        self._client = http_client or httpx.Client(
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def fetch(self, request: MvpCatalogEnrichmentRequest) -> EnrichmentResponse:
        try:
            with self._client.stream(
                "GET",
                TOURAPI_BASE_URL,
                params={
                    "MobileOS": "ETC",
                    "MobileApp": "IT-DA",
                    "_type": "json",
                    "contentId": request.provider_content_id,
                    "numOfRows": "1",
                    "pageNo": "1",
                    "serviceKey": self._service_key,
                },
                timeout=REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as response:
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > RESPONSE_BODY_MAX_BYTES:
                        raise ValueError("provider response exceeded the bounded body limit")
        except ValueError:
            raise
        except httpx.HTTPError as exc:
            raise RuntimeError("TourAPI request failed") from exc
        raw = bytes(body)
        if credential_material_present(raw, self._service_key):
            raise RuntimeError("provider response contained credential material")
        return EnrichmentResponse(body=raw, content_type=content_type)


class _NullTransport:
    def fetch(self, request: MvpCatalogEnrichmentRequest) -> EnrichmentResponse:
        raise AssertionError(f"transport unexpectedly used for {request.provider_content_id}")

    def close(self) -> None:
        return None


def require_mvp_collection_allowed(*, explicit_live: bool) -> None:
    truthy = {"1", "true", "yes", "on"}
    if os.environ.get("CI", "").strip().casefold() in truthy:
        raise LiveCollectionRefused("ci")
    if os.environ.get("ITDA_OFFLINE", "").strip().casefold() in truthy:
        raise LiveCollectionRefused("offline")
    if os.environ.get("ITDA_NO_NETWORK", "").strip().casefold() in truthy:
        raise LiveCollectionRefused("no-network")
    if not explicit_live:
        raise LiveCollectionRefused("explicit-opt-in-required")


def build_enrichment_plan(
    source_path: Path,
    *,
    permissions: Iterable[OfficialDatasetPermissionMetadata],
    permission_snapshots: Mapping[str, bytes],
    previous_attempt_result: MvpCatalogEnrichmentResult,
    successful_canary_result: TourApiDiagnosticCanaryResult,
    spare_count: int = DEFAULT_SPARE_COUNT,
) -> MvpCatalogEnrichmentPlan:
    continuation_version = _validate_consumed_attempt(previous_attempt_result)
    _validate_successful_canary(successful_canary_result)
    if not 0 <= spare_count <= DEFAULT_SPARE_COUNT:
        raise ValueError("spare count must be between zero and 20")
    gap = build_catalog_gap_report(
        source_path,
        permissions=permissions,
        permission_snapshots=permission_snapshots,
    )
    if gap.strict_rights_state != "PERMISSION_METADATA_VERIFIED":
        raise ValueError("official permission metadata is not verified")
    raw = source_path.read_bytes()
    payload = json.loads(raw)
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("catalog source candidates are missing")

    qualified_place_ids: set[str] = set()
    eligible: list[MvpCatalogEnrichmentRequest] = []
    seen_places: set[str] = set()
    seen_content_ids: set[str] = set()
    for row in candidates:
        if not isinstance(row, dict):
            continue
        gates = row.get("non_image_gates")
        place_id = row.get("place_entity_id")
        candidate_id = row.get("provider_place_candidate_id")
        source_sha = row.get("source_row_sha256")
        if not isinstance(gates, dict) or not isinstance(place_id, str):
            continue
        required = ("canonical_identity", "coordinates", "dataset_rights")
        base_qualified = all(gates.get(name) == "PASS" for name in required)
        if base_qualified and gates.get("description") == "PASS":
            qualified_place_ids.add(place_id)
            continue
        if not base_qualified or gates.get("description") == "PASS":
            continue
        if not isinstance(candidate_id, str) or not candidate_id.startswith("candidate:tour-api:"):
            continue
        content_id = candidate_id.removeprefix("candidate:tour-api:")
        if not content_id or not isinstance(source_sha, str):
            continue
        if place_id in seen_places or content_id in seen_content_ids:
            raise ValueError("duplicate enrichment identity in source candidates")
        seen_places.add(place_id)
        seen_content_ids.add(content_id)
        eligible.append(
            MvpCatalogEnrichmentRequest(
                provider="TOUR_API",
                official_dataset_id="15101578",
                operation="detailCommon2",
                place_entity_id=place_id,
                provider_content_id=content_id,
                source_row_sha256=source_sha,
            )
        )

    attempted_place_ids = {
        outcome.place_entity_id for outcome in previous_attempt_result.outcomes
    }
    if continuation_version == "v6":
        eligible = [
            request
            for request in eligible
            if request.place_entity_id not in attempted_place_ids
        ]
        historical_count = 0
        carried_success_count: int | None = previous_attempt_result.successful_count
        current = carried_success_count
    else:
        historical_count = min(100, len(qualified_place_ids))
        carried_success_count = None
        current = historical_count
    missing = 100 - current
    if missing == 0:
        raise ValueError("catalog does not require description enrichment")
    request_count = min(MAX_ENRICHMENT_REQUESTS, missing + spare_count)
    selected = tuple(
        sorted(eligible, key=lambda row: (row.place_entity_id, row.provider_content_id))[
            :request_count
        ]
    )
    if len(selected) < missing:
        raise ValueError("not enough TourAPI description-gap candidates")
    source_file_sha256 = hashlib.sha256(raw).hexdigest()
    fields = {
        "schema_version": f"mvp-public-catalog-enrichment-plan.{continuation_version}",
        "parser_contract_version": PARSER_CONTRACT_VERSION,
        "previous_attempt_result_sha256": previous_attempt_result.result_sha256,
        "request_grammar_version": REQUEST_GRAMMAR_VERSION,
        "successful_canary_result_sha256": successful_canary_result.result_sha256,
        "source_file_sha256": source_file_sha256,
        "catalog_gap_report_sha256": gap.report_sha256,
        "description_ready_historical_count": historical_count,
        **(
            {"carried_success_count": carried_success_count}
            if continuation_version == "v6"
            else {}
        ),
        "description_success_required": missing,
        "strict_rights_state": "PERMISSION_METADATA_VERIFIED",
        "permission_bindings": gap.permission_bindings,
        "spare_count": request_count - missing,
        "max_requests": request_count,
        "concurrency": 1,
        "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "response_body_max_bytes": RESPONSE_BODY_MAX_BYTES,
        "traffic_scope": "TOURAPI_PUBLIC_CATALOG_COLLECTION_ONLY",
        "requests": selected,
    }
    return MvpCatalogEnrichmentPlan(
        **fields,
        plan_sha256=canonical_sha256(_jsonable(fields)),
    )


def _validate_consumed_attempt(result: MvpCatalogEnrichmentResult) -> Literal["v5", "v6"]:
    if result.plan_sha256 == CONSUMED_V3_PLAN_SHA256:
        if result.attempted_count != 80 or result.successful_count != 0:
            raise ValueError("previous attempt does not record the consumed 80-call failure")
        if any(outcome.status == "SUCCESS" for outcome in result.outcomes):
            raise ValueError("previous attempt unexpectedly contains successful enrichment")
        return "v5"
    if result.plan_sha256 == CONSUMED_V5_PLAN_SHA256:
        if result.result_sha256 != CONSUMED_V5_RESULT_SHA256:
            raise ValueError("previous attempt does not match the consumed v5 result")
        if (
            result.attempted_count != 80
            or result.successful_count != 77
            or result.description_gap_remaining != 0
        ):
            raise ValueError("previous attempt does not record the verified v5 collection")
        return "v6"
    raise ValueError("previous attempt does not match a consumed collection plan")


def _validate_successful_canary(result: TourApiDiagnosticCanaryResult) -> None:
    if result.plan_sha256 != (
        "d0b614cb918f7d38d2a5c9194cc8c5a0dc844e44c24e067039ec660858dd51d0"
    ):
        raise ValueError("batch plan does not bind the corrected canary")
    if result.provider_result_code != "0000" or result.normalized_outcome != "SUCCESS":
        raise ValueError("batch plan requires the corrected canary success result")


def validate_collection_approval(
    plan: MvpCatalogEnrichmentPlan,
    *,
    expected_plan_sha256: str,
    approval: str,
) -> None:
    if plan.plan_sha256 in {CONSUMED_V5_PLAN_SHA256, CONSUMED_V6_PLAN_SHA256}:
        raise PermissionError("consumed collection plan cannot be executed")
    if plan.schema_version != "mvp-public-catalog-enrichment-plan.v6":
        raise PermissionError("superseded collection plan cannot be executed")
    if expected_plan_sha256 != plan.plan_sha256:
        raise PermissionError("collection plan SHA-256 mismatch")
    if approval != f"{APPROVAL_PREFIX}{plan.plan_sha256}":
        raise PermissionError("TourAPI catalog collection approval mismatch")


def build_diagnostic_canary_plan(
    enrichment_plan: MvpCatalogEnrichmentPlan,
    enrichment_result: MvpCatalogEnrichmentResult,
    *,
    previous_canary_result: TourApiDiagnosticCanaryResult | None = None,
) -> TourApiDiagnosticCanaryPlan:
    if enrichment_plan.schema_version != "mvp-public-catalog-enrichment-plan.v4":
        raise ValueError("diagnostic canary requires the v4 enrichment plan")
    if enrichment_result.plan_sha256 != enrichment_plan.plan_sha256:
        raise ValueError("diagnostic canary result lineage does not match the v4 plan")
    if enrichment_result.attempted_count != 80 or enrichment_result.successful_count != 0:
        raise ValueError("diagnostic canary requires the consumed 80-call rejection result")
    if {row.reason for row in enrichment_result.outcomes} != {"PROVIDER_REJECTED"}:
        raise ValueError("diagnostic canary requires uniform provider rejection")
    if previous_canary_result is None:
        schema_version = "tourapi-diagnostic-canary-plan.v1"
        grammar_fields: dict[str, object] = {}
    else:
        if previous_canary_result.plan_sha256 != (
            "9bb246e4b8842f8dda80f8b1929c4db74cd0767cc9a4c7683d824852857afca5"
        ):
            raise ValueError("corrected canary does not bind the consumed v1 plan")
        if (
            previous_canary_result.provider_result_code != "10"
            or previous_canary_result.normalized_outcome != "TERMINAL_OPERATOR_ACTION"
        ):
            raise ValueError("corrected canary requires the code-10 v1 result")
        schema_version = "tourapi-diagnostic-canary-plan.v2"
        grammar_fields = {
            "request_grammar_version": REQUEST_GRAMMAR_VERSION,
            "previous_canary_result_sha256": previous_canary_result.result_sha256,
        }
    fields = {
        "schema_version": schema_version,
        "enrichment_plan_sha256": enrichment_plan.plan_sha256,
        "enrichment_result_sha256": enrichment_result.result_sha256,
        "parser_contract_version": PARSER_CONTRACT_VERSION,
        **grammar_fields,
        "endpoint": TOURAPI_BASE_URL,
        "request": enrichment_plan.requests[0],
        "max_requests": 1,
        "concurrency": 1,
        "timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "response_body_max_bytes": RESPONSE_BODY_MAX_BYTES,
        "traffic_scope": "TOURAPI_PROVIDER_RESULT_DIAGNOSTIC_ONLY",
    }
    return TourApiDiagnosticCanaryPlan(
        **fields,
        plan_sha256=canonical_sha256(_jsonable(fields)),
    )


def validate_canary_approval(
    plan: TourApiDiagnosticCanaryPlan,
    *,
    expected_plan_sha256: str,
    approval: str,
) -> None:
    del plan, expected_plan_sha256, approval
    raise PermissionError("consumed diagnostic canary cannot be executed")


def run_diagnostic_canary(
    plan: TourApiDiagnosticCanaryPlan,
    *,
    transport: EnrichmentTransport,
    output_path: Path,
) -> TourApiDiagnosticCanaryResult:
    provider_code: str | None = None
    outcome: CanaryOutcome
    try:
        response = transport.fetch(plan.request)
        if len(response.body) > plan.response_body_max_bytes:
            raise ValueError("provider response exceeded the bounded body limit")
        _, provider_code, _ = parse_provider_envelope(
            response.body,
            content_type=response.content_type,
        )
        if provider_code is None:
            outcome = "MISSING_RESULT_CODE"
        elif not provider_code.isdigit() or not 2 <= len(provider_code) <= 4:
            provider_code = None
            outcome = "MALFORMED_RESPONSE"
        else:
            outcome = classify_provider_result(provider_code)
    except ValueError as exc:
        provider_code = None
        outcome = (
            "RESPONSE_BODY_LIMIT"
            if "body limit" in str(exc)
            else "MALFORMED_RESPONSE"
        )
    except Exception:
        provider_code = None
        outcome = "TRANSPORT_FAILURE"

    fields = {
        "schema_version": "tourapi-diagnostic-canary-result.v1",
        "plan_sha256": plan.plan_sha256,
        "attempted_count": 1,
        "provider_result_code": provider_code,
        "normalized_outcome": outcome,
        "raw_response_persisted": False,
    }
    result = TourApiDiagnosticCanaryResult(
        **fields,
        result_sha256=canonical_sha256(fields),
    )
    _write_atomic(output_path, canonical_json_bytes(result.model_dump(mode="json")) + b"\n")
    return result


def run_enrichment(
    plan: MvpCatalogEnrichmentPlan,
    *,
    transport: EnrichmentTransport,
    output_root: Path,
) -> MvpCatalogEnrichmentResult:
    outcomes: list[MvpCatalogEnrichmentOutcome] = []
    successful = 0
    for request in plan.requests:
        try:
            response = transport.fetch(request)
            raw = response.body
            if len(raw) > plan.response_body_max_bytes:
                raise ValueError("provider response exceeded the bounded body limit")
            payload, provider_code, _ = parse_provider_envelope(
                raw,
                content_type=response.content_type,
            )
            if provider_code is not None and classify_provider_result(provider_code) != "SUCCESS":
                raise ProviderRejected
            item = _extract_matching_item(payload, request.provider_content_id)
            overview = _text(item, "overview")
            if overview is None:
                outcomes.append(_outcome(request, "EMPTY", "DESCRIPTION_EMPTY"))
                continue
            raw_sha = hashlib.sha256(raw).hexdigest()
            relative = f"responses/{request.provider_content_id}-{raw_sha}.json"
            _write_atomic_once(output_root / relative, raw)
            outcomes.append(
                MvpCatalogEnrichmentOutcome(
                    place_entity_id=request.place_entity_id,
                    provider_content_id=request.provider_content_id,
                    status="SUCCESS",
                    reason="DESCRIPTION_COLLECTED",
                    raw_response_sha256=raw_sha,
                    raw_response_file=relative,
                    overview=overview[:4000],
                    name_ko=_text(item, "title", "name"),
                    address_ko=_text(item, "addr1", "address"),
                    latitude=_coordinate(item, "mapy", 35.0, 36.5),
                    longitude=_coordinate(item, "mapx", 128.0, 130.5),
                )
            )
            successful += 1
        except ContentIdMismatch:
            outcomes.append(_outcome(request, "FAILED", "CONTENT_ID_MISMATCH"))
        except ProviderRejected:
            outcomes.append(_outcome(request, "FAILED", "PROVIDER_REJECTED"))
        except ValueError as exc:
            if "body limit" in str(exc):
                outcomes.append(_outcome(request, "FAILED", "RESPONSE_BODY_LIMIT"))
            else:
                outcomes.append(_outcome(request, "FAILED", "MALFORMED_RESPONSE"))
        except Exception:
            outcomes.append(_outcome(request, "FAILED", "TRANSPORT_FAILURE"))

    remaining = max(0, plan.description_success_required - successful)
    fields = {
        "schema_version": "mvp-public-catalog-enrichment-result.v3",
        "plan_sha256": plan.plan_sha256,
        "catalog_gap_report_sha256": plan.catalog_gap_report_sha256,
        "attempted_count": len(outcomes),
        "successful_count": successful,
        "description_gap_remaining": remaining,
        "strict_rights_state": "PERMISSION_METADATA_VERIFIED",
        "permission_bindings": plan.permission_bindings,
        "catalog_ready": False,
        "public_artifact_written": False,
        "outcomes": tuple(outcomes),
    }
    result = MvpCatalogEnrichmentResult(
        **fields,
        result_sha256=canonical_sha256(_jsonable(fields)),
    )
    _write_atomic(
        output_root / "result.json",
        canonical_json_bytes(result.model_dump(mode="json")) + b"\n",
    )
    return result


class ContentIdMismatch(ValueError):
    pass


class ProviderRejected(RuntimeError):
    pass


def _extract_matching_item(
    payload: object,
    expected_content_id: str,
) -> Mapping[str, object]:
    items = tuple(_iter_items(payload))
    if not items:
        raise ProviderRejected
    matching = [
        item
        for item in items
        if _text(item, "contentid", "contentId") == expected_content_id
    ]
    if not matching:
        raise ContentIdMismatch("provider content ID did not match local plan")
    if len(matching) != 1:
        raise ValueError("provider response contains duplicate matching items")
    return matching[0]


def _iter_items(value: object) -> Iterator[Mapping[str, object]]:
    if isinstance(value, Mapping):
        if "contentid" in value or "contentId" in value:
            yield value
        for child in value.values():
            yield from _iter_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_items(child)


def _text(item: Mapping[str, object], *names: str) -> str | None:
    for name in names:
        value = item.get(name)
        if isinstance(value, str) and value.strip():
            return " ".join(value.strip().split())
        if isinstance(value, int):
            return str(value)
    return None


def _coordinate(
    item: Mapping[str, object],
    name: str,
    minimum: float,
    maximum: float,
) -> float | None:
    value = item.get(name)
    if value is None or value == "":
        return None
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValueError("provider coordinate is malformed")
    try:
        coordinate = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("provider coordinate is malformed") from exc
    if not minimum <= coordinate <= maximum:
        raise ValueError("provider coordinate is outside Gyeongju bounds")
    return coordinate


def _outcome(
    request: MvpCatalogEnrichmentRequest,
    status: Literal["SUCCESS", "EMPTY", "FAILED"],
    reason: Literal[
        "DESCRIPTION_COLLECTED",
        "DESCRIPTION_EMPTY",
        "CONTENT_ID_MISMATCH",
        "MALFORMED_RESPONSE",
        "PROVIDER_REJECTED",
        "RESPONSE_BODY_LIMIT",
        "TRANSPORT_FAILURE",
    ],
) -> MvpCatalogEnrichmentOutcome:
    return MvpCatalogEnrichmentOutcome(
        place_entity_id=request.place_entity_id,
        provider_content_id=request.provider_content_id,
        status=status,
        reason=reason,
    )


def _jsonable(value: object) -> object:
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")  # type: ignore[union-attr]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_atomic_once(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("immutable response path contains different bytes")
        return
    _write_atomic(path, payload)
