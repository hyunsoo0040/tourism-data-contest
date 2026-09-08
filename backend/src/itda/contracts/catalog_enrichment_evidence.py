"""Exact-round, exact-provider evidence sidecars for catalog enrichment."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.cli.collect_catalog_enrichment import (
    _canonical_lines,
    _load_selected_round,
    _regular_file_bytes,
    verify_authorization_receipt,
    verify_collection_log,
    verify_collection_report,
)
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_audit import CatalogAudit, DatasetGrantEvidence
from itda.contracts.catalog_enrichment import (
    APPROVED_OPERATIONS,
    OPERATION_FIELD_MAP,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

SCHEMA_VERSION = "itda.catalog-enrichment-evidence-sidecars.v1"
DATA_VERSION = "catalog-v2-enrichment-evidence-data-v1"
TOURAPI_DATASET_ID = "15101578"
TOURAPI_PROVIDER = "TOUR_API"
TERMINAL_STATUSES = (
    "SUCCESS",
    "TERMINAL_PROVIDER_FAILURE",
    "RETRYABLE_FOR_RESUME",
)
FIELD_STATES = ("POPULATED", "MISSING", "BLOCKED", "REVIEW_REQUIRED")
_HEX64 = frozenset("0123456789abcdef")
_CONTENT_IDENTITY_KEYS = frozenset({"contentid", "contentId", "content_id"})
_RESTRICTION_KEYS = (
    "explicit_asset_restriction",
    "restriction",
    "usage_restriction",
    "copyright_restriction",
)
_ATTEMPT_EVIDENCE_KEYS = (
    "attempt_number",
    "started_at",
    "completed_at",
    "elapsed_ms",
    "timeout_seconds",
    "http_status",
    "safe_headers",
    "provider_result_code",
    "provider_result_value",
    "raw_body_sha256",
    "raw_body_retention",
    "raw_relative_path",
    "normalized_reason",
    "retryable",
    "terminal",
)
_FINAL_ATTEMPT_REPORT_KEYS = (
    "http_status",
    "safe_headers",
    "provider_result_code",
    "provider_result_value",
    "raw_body_sha256",
    "raw_body_retention",
    "raw_relative_path",
    "normalized_reason",
)
KTO_MAX_RAW_BYTES = 8 * 1024 * 1024
KTO_MAX_JSON_DEPTH = 32
KTO_MAX_ITEMS = 100
KTO_OPERATING_FIELDS: dict[str, tuple[str, ...]] = {
    "12": ("opendate", "restdate", "usetime", "useseason"),
    "14": ("restdateculture", "usetimeculture"),
    "15": ("eventstartdate", "eventenddate", "playtime"),
    "28": ("openperiod", "restdateleports", "usetimeleports"),
    "32": ("checkintime", "checkouttime", "roomofftime"),
    "38": ("opendateshopping", "opentime", "restdateshopping"),
    "39": ("opendatefood", "opentimefood", "restdatefood"),
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _round_value(root: Path) -> str:
    parts = root.parts
    try:
        index = parts.index("artifacts")
    except ValueError:
        return root.as_posix()
    return Path(*parts[index:]).as_posix()


class ContentIdentity(StrictContract):
    provider: Literal["TOUR_API"]
    official_dataset_id: Literal["15101578"]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    provider_content_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[0-9]+$"),
    ]
    operation: Literal["detailCommon2", "detailIntro2", "detailImage2"]
    source_asset_id: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    content_identity_sha256: Sha256

    @model_validator(mode="after")
    def validate_identity_hash(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"content_identity_sha256"}, mode="json")
        )
        if self.content_identity_sha256 != expected:
            raise ValueError("content identity digest does not match")
        return self


class RightsEvidence(StrictContract):
    official_dataset_id: Literal["15101578"]
    official_page_url: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    retrieved_at: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    response_sha256: Sha256
    page_sha256: Sha256
    dataset_grant_sha256: Sha256
    grant_evidence_state: Literal["COMPLETE", "MISSING", "INCOMPLETE"]
    source_asset_id: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    source_request_sha256: Sha256
    source_response_sha256: Sha256
    original_url: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=2_000),
    ] = None
    explicit_asset_restriction: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    rights_state: Literal[
        "ALLOWED",
        "BLOCKED_EXPLICIT_ASSET_RESTRICTION",
        "BLOCKED_MISSING_PROVENANCE",
        "BLOCKED_GRANT_MISSING",
        "BLOCKED_GRANT_INCOMPLETE",
        "BLOCKED_DATASET_SCOPE_MISMATCH",
    ]
    reason_codes: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
        ...,
    ]
    analysis_eligible: Annotated[bool, Field(strict=True)]
    ui_eligible: Annotated[bool, Field(strict=True)]
    demo_eligible: Annotated[bool, Field(strict=True)]
    rights_evidence_sha256: Sha256

    @model_validator(mode="after")
    def validate_rights_hash_and_lanes(self) -> Self:
        lanes = (self.analysis_eligible, self.ui_eligible, self.demo_eligible)
        if (self.rights_state == "ALLOWED") != all(lanes):
            raise ValueError("rights state and downstream lanes disagree")
        if self.rights_state != "ALLOWED" and any(lanes):
            raise ValueError("blocked rights cannot authorize a downstream lane")
        if not self.reason_codes:
            raise ValueError("rights evidence requires a named reason")
        expected = canonical_sha256(
            self.model_dump(exclude={"rights_evidence_sha256"}, mode="json")
        )
        if self.rights_evidence_sha256 != expected:
            raise ValueError("rights evidence digest does not match")
        return self


class NormalizedFieldEvidence(StrictContract):
    field_name: Literal[
        "coordinates",
        "korean_description",
        "provider_specific_operating_information",
        "exact_provider_direct_media",
    ]
    state: Literal["POPULATED", "MISSING", "BLOCKED", "REVIEW_REQUIRED"]
    value: Any | None = None
    deficit_reason: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=200),
    ] = None
    round_id: Sha256
    request_identity: Sha256
    retrieved_at: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    raw_relative_path: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    raw_body_sha256: Sha256
    attempt_history_sha256: Sha256
    content_identity: ContentIdentity
    rights: RightsEvidence
    field_evidence_sha256: Sha256

    @model_validator(mode="after")
    def validate_field(self) -> Self:
        if self.state == "POPULATED":
            if self.value is None or self.deficit_reason is not None:
                raise ValueError("populated field requires a value and no deficit")
            if self.rights.rights_state != "ALLOWED":
                raise ValueError("populated field requires passing exact rights")
        elif self.value is not None or self.deficit_reason is None:
            raise ValueError("non-populated field requires one named deficit and no value")
        expected = canonical_sha256(self.model_dump(exclude={"field_evidence_sha256"}, mode="json"))
        if self.field_evidence_sha256 != expected:
            raise ValueError("field evidence digest does not match")
        return self


class NormalizedResponseEvidence(StrictContract):
    round_id: Sha256
    round_root: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    request_identity: Sha256
    provider: Literal["TourAPI"]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    operation: Literal["detailCommon2", "detailIntro2", "detailImage2"]
    terminal_status: Literal[
        "SUCCESS",
        "TERMINAL_PROVIDER_FAILURE",
        "RETRYABLE_FOR_RESUME",
    ]
    provider_result_code: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=120),
    ] = None
    provider_result_value: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    normalized_reason: Annotated[
        str | None,
        Field(strict=True, min_length=1, max_length=500),
    ] = None
    raw_relative_path: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    raw_body_sha256: Sha256
    attempts: tuple[dict[str, Any], ...]
    attempt_history_sha256: Sha256
    collection_log_history_sha256: Sha256
    fields: tuple[NormalizedFieldEvidence, ...]
    response_evidence_sha256: Sha256

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        if not self.attempts:
            raise ValueError("response evidence requires complete D-14 attempt history")
        if self.attempt_history_sha256 != canonical_sha256(list(self.attempts)):
            raise ValueError("attempt history digest does not match")
        expected_names = OPERATION_FIELD_MAP[self.operation]
        if tuple(field.field_name for field in self.fields) != expected_names:
            raise ValueError("normalized fields do not match their exact operation")
        if any(
            field.round_id != self.round_id
            or field.request_identity != self.request_identity
            or field.raw_body_sha256 != self.raw_body_sha256
            or field.attempt_history_sha256 != self.attempt_history_sha256
            for field in self.fields
        ):
            raise ValueError("field evidence is detached from its response")
        expected = canonical_sha256(
            self.model_dump(exclude={"response_evidence_sha256"}, mode="json")
        )
        if self.response_evidence_sha256 != expected:
            raise ValueError("response evidence digest does not match")
        return self


class EvidenceSidecarParents(StrictContract):
    request_plan_sha256: Sha256
    state_attestation_file_sha256: Sha256
    authorization_request_file_sha256: Sha256
    authorization_receipt_file_sha256: Sha256
    collection_report_file_sha256: Sha256
    collection_log_file_sha256: Sha256
    catalog_audit_file_sha256: Sha256
    catalog_audit_sha256: Sha256
    ancestry_sha256: Sha256


class EnrichmentEvidenceSidecar(StrictContract):
    schema_version: Literal["itda.catalog-enrichment-evidence-sidecars.v1"]
    data_version: Literal["catalog-v2-enrichment-evidence-data-v1"]
    round_id: Sha256
    round_root: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    ancestry_depth: Annotated[int, Field(strict=True, ge=1)]
    parents: EvidenceSidecarParents
    responses: tuple[NormalizedResponseEvidence, ...]
    response_count: Annotated[int, Field(strict=True, ge=0)]
    terminal_status_counts: dict[
        Literal["SUCCESS", "TERMINAL_PROVIDER_FAILURE", "RETRYABLE_FOR_RESUME"],
        Annotated[int, Field(strict=True, ge=0)],
    ]
    operation_status_counts: dict[
        Literal["detailCommon2", "detailIntro2", "detailImage2"],
        dict[
            Literal[
                "SUCCESS",
                "TERMINAL_PROVIDER_FAILURE",
                "RETRYABLE_FOR_RESUME",
            ],
            Annotated[int, Field(strict=True, ge=0)],
        ],
    ]
    field_state_counts: dict[
        Literal["POPULATED", "MISSING", "BLOCKED", "REVIEW_REQUIRED"],
        Annotated[int, Field(strict=True, ge=0)],
    ]
    responses_root: Sha256
    sidecar_sha256: Sha256

    @model_validator(mode="after")
    def validate_complete_sidecar(self) -> Self:
        request_ids = tuple(row.request_identity for row in self.responses)
        if len(set(request_ids)) != len(request_ids):
            raise ValueError("sidecar repeats a selected-round terminal response")
        if any(
            row.round_id != self.round_id or row.round_root != self.round_root
            for row in self.responses
        ):
            raise ValueError("sidecar contains a response from another round")
        if self.response_count != len(self.responses):
            raise ValueError("response count is not row-derived")
        expected_terminal = {
            status: sum(row.terminal_status == status for row in self.responses)
            for status in TERMINAL_STATUSES
        }
        if self.terminal_status_counts != expected_terminal:
            raise ValueError("terminal status counts are not row-derived")
        expected_operations = {
            operation: {
                status: sum(
                    row.operation == operation and row.terminal_status == status
                    for row in self.responses
                )
                for status in TERMINAL_STATUSES
            }
            for operation in APPROVED_OPERATIONS
        }
        if self.operation_status_counts != expected_operations:
            raise ValueError("operation status counts are not row-derived")
        state_counts = Counter(field.state for row in self.responses for field in row.fields)
        expected_fields = {state: state_counts[state] for state in FIELD_STATES}
        if self.field_state_counts != expected_fields:
            raise ValueError("field state counts are not row-derived")
        expected_root = canonical_sha256([row.model_dump(mode="json") for row in self.responses])
        if self.responses_root != expected_root:
            raise ValueError("response root is not row-derived")
        expected = canonical_sha256(self.model_dump(exclude={"sidecar_sha256"}, mode="json"))
        if self.sidecar_sha256 != expected:
            raise ValueError("sidecar digest does not match")
        return self


def _content_identity(
    request: Mapping[str, object],
    *,
    source_asset_id: str | None,
) -> ContentIdentity:
    parameters = request.get("parameters")
    if not isinstance(parameters, Mapping):
        raise ValueError("planned request parameters are missing")
    content_id = parameters.get("contentId")
    if not isinstance(content_id, str) or not content_id.isdigit():
        raise ValueError("planned request lacks an exact TourAPI content identity")
    fields = {
        "provider": TOURAPI_PROVIDER,
        "official_dataset_id": TOURAPI_DATASET_ID,
        "provider_candidate_id": request["provider_candidate_id"],
        "provider_content_id": content_id,
        "operation": request["operation"],
        "source_asset_id": source_asset_id,
    }
    return ContentIdentity(
        **fields,
        content_identity_sha256=canonical_sha256(fields),
    )


def _rights_evidence(
    *,
    grant: DatasetGrantEvidence,
    request_identity: str,
    raw_body_sha256: str,
    source_asset_id: str | None,
    original_url: str | None,
    explicit_asset_restriction: str | None = None,
    force_scope_mismatch: bool = False,
) -> RightsEvidence:
    if force_scope_mismatch or grant.official_dataset_id != TOURAPI_DATASET_ID:
        state = "BLOCKED_DATASET_SCOPE_MISMATCH"
        reasons = ("EXACT_PROVIDER_DATASET_SCOPE_MISMATCH",)
    elif grant.evidence_state == "MISSING":
        state = "BLOCKED_GRANT_MISSING"
        reasons = ("GRANT_EVIDENCE_MISSING",)
    elif grant.evidence_state == "INCOMPLETE":
        state = "BLOCKED_GRANT_INCOMPLETE"
        reasons = ("GRANT_EVIDENCE_INCOMPLETE",)
    elif source_asset_id is None or original_url is None:
        state = "BLOCKED_MISSING_PROVENANCE"
        reasons = ("ASSET_PROVENANCE_INCOMPLETE",)
    elif explicit_asset_restriction:
        state = "BLOCKED_EXPLICIT_ASSET_RESTRICTION"
        reasons = (explicit_asset_restriction,)
    elif not all(
        (
            grant.commercial_use_allowed,
            grant.transform_allowed,
            grant.display_allowed,
            grant.model_input_allowed,
        )
    ):
        state = "BLOCKED_DATASET_SCOPE_MISMATCH"
        reasons = ("DATASET_GRANT_DOES_NOT_AUTHORIZE_ALL_REQUIRED_LANES",)
    else:
        state = "ALLOWED"
        reasons = ("AUTHORITATIVE_DATASET_GRANT_AND_ASSET_PROVENANCE_COMPLETE",)
    allowed = state == "ALLOWED"
    fields = {
        "official_dataset_id": TOURAPI_DATASET_ID,
        "official_page_url": grant.official_page_url,
        "retrieved_at": grant.retrieved_at,
        "response_sha256": grant.response_sha256,
        "page_sha256": grant.page_sha256,
        "dataset_grant_sha256": grant.dataset_grant_sha256,
        "grant_evidence_state": grant.evidence_state,
        "source_asset_id": source_asset_id,
        "source_request_sha256": request_identity,
        "source_response_sha256": raw_body_sha256,
        "original_url": original_url,
        "explicit_asset_restriction": explicit_asset_restriction,
        "rights_state": state,
        "reason_codes": reasons,
        "analysis_eligible": allowed,
        "ui_eligible": allowed,
        "demo_eligible": allowed,
    }
    return RightsEvidence(
        **fields,
        rights_evidence_sha256=canonical_sha256(fields),
    )


def _response_items(raw_body: bytes) -> list[Mapping[str, object]]:
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("successful provider body is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("successful provider body must be an object")
    response = payload.get("response")
    if not isinstance(response, Mapping):
        raise ValueError("successful provider body lacks the exact response envelope")
    header = response.get("header")
    body = response.get("body")
    if (
        not isinstance(header, Mapping)
        or header.get("resultCode") != "0000"
        or not isinstance(body, Mapping)
    ):
        raise ValueError("successful provider body carries an invalid result envelope")
    items = body.get("items")
    if items is None or items == "":
        return []
    if not isinstance(items, Mapping):
        raise ValueError("successful provider body lacks items")
    if "item" not in items:
        return []
    value = items["item"]
    if value is None or value == "":
        return []
    if isinstance(value, Mapping):
        return [value]
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise ValueError("successful provider items are not an object list")
    return value


def _matching_items(
    items: list[Mapping[str, object]],
    *,
    content_id: str,
) -> list[Mapping[str, object]]:
    result: list[Mapping[str, object]] = []
    for item in items:
        identity_values = [item[key] for key in _CONTENT_IDENTITY_KEYS if key in item]
        if not identity_values or any(value != content_id for value in identity_values):
            raise ValueError("provider item content identity does not match the request")
        result.append(item)
    return result


def _asset_restriction(item: Mapping[str, object]) -> str | None:
    for key in _RESTRICTION_KEYS:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _narrowest_asset_restriction(
    items: list[Mapping[str, object]],
) -> str | None:
    """Let any item-level restriction veto aggregate media readiness."""

    return next(
        (restriction for item in items if (restriction := _asset_restriction(item)) is not None),
        None,
    )


def _media_set_identity(media_values: list[dict[str, object]]) -> str | None:
    if not media_values:
        return None
    return f"media-set:{canonical_sha256(media_values)}"


def _field(
    *,
    field_name: str,
    state: str,
    value: object | None,
    deficit_reason: str | None,
    round_id: str,
    request_identity: str,
    retrieved_at: str,
    raw_relative_path: str,
    raw_body_sha256: str,
    attempt_history_sha256: str,
    content_identity: ContentIdentity,
    rights: RightsEvidence,
) -> NormalizedFieldEvidence:
    fields = {
        "field_name": field_name,
        "state": state,
        "value": value,
        "deficit_reason": deficit_reason,
        "round_id": round_id,
        "request_identity": request_identity,
        "retrieved_at": retrieved_at,
        "raw_relative_path": raw_relative_path,
        "raw_body_sha256": raw_body_sha256,
        "attempt_history_sha256": attempt_history_sha256,
        "content_identity": content_identity.model_dump(mode="json"),
        "rights": rights.model_dump(mode="json"),
    }
    return NormalizedFieldEvidence(
        **fields,
        field_evidence_sha256=canonical_sha256(fields),
    )


def normalize_terminal_response(
    *,
    planned_request: Mapping[str, object],
    report_record: Mapping[str, object],
    raw_body: bytes,
    grant: DatasetGrantEvidence,
    round_id: str,
    round_root: Path | str,
    collection_log_records: tuple[Mapping[str, object], ...] = (),
) -> NormalizedResponseEvidence:
    """Normalize one terminal report without widening provider, field, or round scope."""

    operation = planned_request.get("operation")
    if operation not in APPROVED_OPERATIONS:
        raise ValueError("planned request operation is outside the exact allowlist")
    expected_fields = list(OPERATION_FIELD_MAP[str(operation)])
    if planned_request.get("mapped_mandatory_fields") != expected_fields:
        raise ValueError("planned operation owns the wrong mandatory fields")
    request_identity = _require_sha256(
        planned_request.get("request_identity"),
        field="request identity",
    )
    if report_record.get("round_id") != round_id:
        raise ValueError("report record belongs to a different selected round")
    expected_root = _round_value(Path(round_root).expanduser().resolve(strict=False))
    if report_record.get("round_root") != expected_root:
        raise ValueError("report record carries a different selected round root")
    if report_record.get("request_identity") != request_identity:
        raise ValueError("report record is detached from the planned request")
    if (
        report_record.get("operation") != operation
        or report_record.get("mapped_mandatory_fields") != expected_fields
    ):
        raise ValueError("report operation or field mapping is outside the exact allowlist")
    if planned_request.get("provider") != "TourAPI" or report_record.get("provider") != "TourAPI":
        raise ValueError("source-kind confusion: selected request is not exact TourAPI")
    raw_body_sha256 = _require_sha256(
        report_record.get("raw_body_sha256"),
        field="raw body digest",
    )
    if not hmac.compare_digest(_sha256(raw_body), raw_body_sha256):
        raise ValueError("raw body bytes do not match the report digest")
    raw_relative_path = report_record.get("raw_relative_path")
    if not isinstance(raw_relative_path, str) or not raw_relative_path:
        raise ValueError("terminal report lacks its raw body path")
    attempts_value = report_record.get("attempts")
    if not isinstance(attempts_value, list) or not attempts_value:
        raise ValueError("terminal report lacks D-14 attempt history")
    attempts: tuple[dict[str, Any], ...] = tuple(
        dict(attempt) for attempt in attempts_value if isinstance(attempt, Mapping)
    )
    if len(attempts) != len(attempts_value):
        raise ValueError("terminal report attempt history contains a non-object")
    if report_record.get("attempt_count") != len(attempts):
        raise ValueError("terminal report attempt count differs from D-14 history")
    attempt_history_sha256 = canonical_sha256(list(attempts))
    last_attempt = attempts[-1]
    if tuple(attempt.get("attempt_number") for attempt in attempts) != tuple(
        range(1, len(attempts) + 1)
    ):
        raise ValueError("terminal report attempt numbers are not consecutive")
    if last_attempt.get("terminal") is not True:
        raise ValueError("terminal report does not end in a terminal attempt")
    if any(report_record.get(key) != last_attempt.get(key) for key in _FINAL_ATTEMPT_REPORT_KEYS):
        raise ValueError("terminal report raw/result summary differs from final attempt")
    retrieved_at = last_attempt.get("completed_at")
    if not isinstance(retrieved_at, str) or not retrieved_at:
        raise ValueError("terminal report attempt lacks a retrieval completion time")
    terminal_status = report_record.get("terminal_status")
    if terminal_status not in TERMINAL_STATUSES:
        raise ValueError("terminal report has an unknown terminal status")
    provider_candidate_id = planned_request.get("provider_candidate_id")
    place_entity_id = planned_request.get("place_entity_id")
    if (
        not isinstance(provider_candidate_id, str)
        or not provider_candidate_id.startswith("candidate:tour-api:")
        or not isinstance(place_entity_id, str)
    ):
        raise ValueError("planned request lacks exact provider/place identity")

    log_records = tuple(dict(item) for item in collection_log_records)
    if log_records:
        expected_log_context = {
            "schema_version": "itda.catalog-enrichment-collection-log.v1",
            "round_id": round_id,
            "invocation_id": report_record.get("invocation_id"),
            "request_identity": request_identity,
            "provider": "TourAPI",
            "operation": operation,
        }
        for attempt, event in zip(attempts, log_records, strict=True):
            if any(event.get(key) != value for key, value in expected_log_context.items()):
                raise ValueError("collection log is detached from selected response")
            for key in _ATTEMPT_EVIDENCE_KEYS:
                if attempt.get(key) != event.get(key):
                    raise ValueError("collection log is detached from report attempts")
    log_history_sha256 = canonical_sha256(list(log_records))

    parameters = planned_request.get("parameters")
    assert isinstance(parameters, Mapping)
    content_id = str(parameters["contentId"])
    endpoint_url = f"https://apis.data.go.kr/B551011/KorService2/{operation}"
    default_source_asset = f"{content_id}:{operation}"
    default_identity = _content_identity(
        planned_request,
        source_asset_id=default_source_asset,
    )
    default_rights = _rights_evidence(
        grant=grant,
        request_identity=request_identity,
        raw_body_sha256=raw_body_sha256,
        source_asset_id=default_source_asset if terminal_status == "SUCCESS" else None,
        original_url=endpoint_url if terminal_status == "SUCCESS" else None,
    )
    fields: list[NormalizedFieldEvidence] = []

    if terminal_status != "SUCCESS":
        for field_name in OPERATION_FIELD_MAP[str(operation)]:
            fields.append(
                _field(
                    field_name=field_name,
                    state="MISSING",
                    value=None,
                    deficit_reason=str(terminal_status),
                    round_id=round_id,
                    request_identity=request_identity,
                    retrieved_at=retrieved_at,
                    raw_relative_path=raw_relative_path,
                    raw_body_sha256=raw_body_sha256,
                    attempt_history_sha256=attempt_history_sha256,
                    content_identity=default_identity,
                    rights=default_rights,
                )
            )
    else:
        items = _matching_items(_response_items(raw_body), content_id=content_id)
        first = items[0] if items else {}
        values: tuple[object | None, ...] | None
        default_rights = _rights_evidence(
            grant=grant,
            request_identity=request_identity,
            raw_body_sha256=raw_body_sha256,
            source_asset_id=default_source_asset,
            original_url=endpoint_url,
            explicit_asset_restriction=_asset_restriction(first),
        )
        if operation == "detailCommon2":
            try:
                longitude = float(str(first.get("mapx", "")))
                latitude = float(str(first.get("mapy", "")))
                coordinates: object | None = {
                    "latitude": latitude,
                    "longitude": longitude,
                }
                if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                    raise ValueError
            except (TypeError, ValueError):
                coordinates = None
            description_value = first.get("overview")
            description = (
                description_value.strip()
                if isinstance(description_value, str) and description_value.strip()
                else None
            )
            values = (coordinates, description)
        elif operation == "detailIntro2":
            operating = {
                str(key): value.strip()
                for key, value in first.items()
                if key not in _CONTENT_IDENTITY_KEYS
                and key != "contenttypeid"
                and isinstance(value, str)
                and value.strip()
            }
            values = (operating or None,)
        else:
            cross_provider = any(
                item.get("provider") not in (None, "TourAPI", "TOUR_API")
                or item.get("official_dataset_id")
                not in (
                    None,
                    TOURAPI_DATASET_ID,
                )
                for item in items
            )
            media_values = []
            for item in items:
                original_url = item.get("originimgurl")
                serial = item.get("serialnum")
                image_name = item.get("imgname")
                if not isinstance(original_url, str) or not original_url:
                    continue
                source_asset_id = (
                    serial
                    if isinstance(serial, str) and serial
                    else canonical_sha256(
                        {
                            "content_id": content_id,
                            "originimgurl": original_url,
                            "imgname": image_name,
                        }
                    )
                )
                media_values.append(
                    {
                        "source_asset_id": source_asset_id,
                        "originimgurl": original_url,
                        "smallimageurl": item.get("smallimageurl"),
                        "imgname": image_name,
                    }
                )
            if cross_provider:
                media_set_identity = _media_set_identity(media_values)
                identity = _content_identity(
                    planned_request,
                    source_asset_id=media_set_identity or default_source_asset,
                )
                rights = _rights_evidence(
                    grant=grant,
                    request_identity=request_identity,
                    raw_body_sha256=raw_body_sha256,
                    source_asset_id=identity.source_asset_id,
                    original_url=endpoint_url if media_values else None,
                    explicit_asset_restriction=_narrowest_asset_restriction(items),
                    force_scope_mismatch=True,
                )
                fields.append(
                    _field(
                        field_name="exact_provider_direct_media",
                        state="REVIEW_REQUIRED",
                        value=None,
                        deficit_reason="CROSS_PROVIDER_MEDIA_REQUIRES_HUMAN_REVIEW",
                        round_id=round_id,
                        request_identity=request_identity,
                        retrieved_at=retrieved_at,
                        raw_relative_path=raw_relative_path,
                        raw_body_sha256=raw_body_sha256,
                        attempt_history_sha256=attempt_history_sha256,
                        content_identity=identity,
                        rights=rights,
                    )
                )
                values = None
            else:
                source_asset_id = _media_set_identity(media_values)
                identity = _content_identity(
                    planned_request,
                    source_asset_id=source_asset_id,
                )
                rights = _rights_evidence(
                    grant=grant,
                    request_identity=request_identity,
                    raw_body_sha256=raw_body_sha256,
                    source_asset_id=source_asset_id,
                    original_url=endpoint_url if media_values else None,
                    explicit_asset_restriction=_narrowest_asset_restriction(items),
                )
                values = (media_values or None,)
                default_identity = identity
                default_rights = rights

        if values is not None:
            for field_name, value in zip(
                OPERATION_FIELD_MAP[str(operation)],
                values,
                strict=True,
            ):
                rights = default_rights
                if value is None:
                    state = "MISSING"
                    reason = "SUCCESS_RESPONSE_FIELD_EMPTY"
                elif rights.rights_state != "ALLOWED":
                    state = "BLOCKED"
                    reason = rights.reason_codes[0]
                    value = None
                else:
                    state = "POPULATED"
                    reason = None
                fields.append(
                    _field(
                        field_name=field_name,
                        state=state,
                        value=value,
                        deficit_reason=reason,
                        round_id=round_id,
                        request_identity=request_identity,
                        retrieved_at=retrieved_at,
                        raw_relative_path=raw_relative_path,
                        raw_body_sha256=raw_body_sha256,
                        attempt_history_sha256=attempt_history_sha256,
                        content_identity=default_identity,
                        rights=rights,
                    )
                )

    response_fields = {
        "round_id": round_id,
        "round_root": expected_root,
        "request_identity": request_identity,
        "provider": "TourAPI",
        "provider_candidate_id": provider_candidate_id,
        "place_entity_id": place_entity_id,
        "operation": operation,
        "terminal_status": terminal_status,
        "provider_result_code": report_record.get("provider_result_code"),
        "provider_result_value": report_record.get("provider_result_value"),
        "normalized_reason": report_record.get("normalized_reason"),
        "raw_relative_path": raw_relative_path,
        "raw_body_sha256": raw_body_sha256,
        "attempts": list(attempts),
        "attempt_history_sha256": attempt_history_sha256,
        "collection_log_history_sha256": log_history_sha256,
        "fields": [field.model_dump(mode="json") for field in fields],
    }
    return NormalizedResponseEvidence(
        **response_fields,
        response_evidence_sha256=canonical_sha256(response_fields),
    )


def _exact_raw_body(
    round_root: Path,
    raw_relative_path: object,
) -> bytes:
    if not isinstance(raw_relative_path, str) or not raw_relative_path:
        raise ValueError("terminal response lacks a raw evidence path")
    relative = Path(raw_relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("raw evidence path escapes the selected round")
    resolved = (round_root / relative).resolve(strict=True)
    if round_root not in resolved.parents:
        raise ValueError("raw evidence path escapes the selected round")
    return _regular_file_bytes(resolved)


def build_enrichment_sidecar(
    *,
    round_root: Path | str,
    round_id: str,
    catalog_audit_path: Path | str,
) -> EnrichmentEvidenceSidecar:
    """Build one byte-deterministic selected-round sidecar without provider traffic."""

    selected = _load_selected_round(round_root, round_id)
    root = selected.root
    receipt_path = root / "enrichment-authorization-receipt.json"
    report_path = root / "enrichment-collection-report.json"
    log_path = root / "enrichment-collection-log.jsonl"
    verify_authorization_receipt(
        receipt_path,
        round_root=root,
        round_id=round_id,
    )
    report_summary = verify_collection_report(
        report_path,
        round_root=root,
        round_id=round_id,
    )
    log_summary = verify_collection_log(
        log_path,
        round_root=root,
        round_id=round_id,
    )
    planned_requests = selected.plan["requests"]
    assert isinstance(planned_requests, list)
    if (
        report_summary["covered_request_count"] != len(planned_requests)
        or report_summary["missing_request_count"] != 0
        or log_summary["terminal_event_count"] < len(planned_requests)
    ):
        raise ValueError("selected round is not completely terminal")

    reports = _canonical_lines(report_path)
    if len(reports) != len(planned_requests):
        raise ValueError("every selected-round terminal response must appear exactly once")
    reports_by_id: dict[str, Mapping[str, object]] = {}
    for report in reports:
        identity = str(report.get("request_identity", ""))
        if identity in reports_by_id:
            raise ValueError("collection report repeats a request identity")
        reports_by_id[identity] = report
    logs = _canonical_lines(log_path)
    logs_by_id: dict[str, list[Mapping[str, object]]] = {}
    for event in logs:
        identity = str(event.get("request_identity", ""))
        logs_by_id.setdefault(identity, []).append(event)

    audit_path = Path(catalog_audit_path).expanduser().resolve(strict=True)
    audit_bytes = _regular_file_bytes(audit_path)
    audit = CatalogAudit.model_validate_json(audit_bytes)
    grant = next(
        (item for item in audit.grants if item.official_dataset_id == TOURAPI_DATASET_ID),
        None,
    )
    if grant is None:
        raise ValueError("catalog audit lacks the authoritative TourAPI dataset grant")

    responses: list[NormalizedResponseEvidence] = []
    for planned in planned_requests:
        if not isinstance(planned, Mapping):
            raise ValueError("selected plan contains a non-object request")
        identity = str(planned["request_identity"])
        report = reports_by_id.get(identity)
        if report is None:
            raise ValueError("selected plan has a dangling terminal response")
        events = tuple(logs_by_id.get(identity, ()))
        if not events:
            raise ValueError("selected plan has a dangling D-13 log parent")
        raw_body = _exact_raw_body(root, report.get("raw_relative_path"))
        responses.append(
            normalize_terminal_response(
                planned_request=planned,
                report_record=report,
                raw_body=raw_body,
                grant=grant,
                round_id=round_id,
                round_root=root,
                collection_log_records=events,
            )
        )

    receipt_bytes = _regular_file_bytes(receipt_path)
    report_bytes = _regular_file_bytes(report_path)
    log_bytes = _regular_file_bytes(log_path)
    state_bytes = _regular_file_bytes(root / "enrichment-state-attestation.json")
    request_bytes = _regular_file_bytes(root / "enrichment-authorization-request.json")
    ancestry_value = (
        selected.plan.get("remediation")
        if selected.ancestry_depth > 1
        else json.loads(_regular_file_bytes(root.parent.parent / "initial-round-ref.json"))
    )
    parent_fields = {
        "request_plan_sha256": round_id,
        "state_attestation_file_sha256": _sha256(state_bytes),
        "authorization_request_file_sha256": _sha256(request_bytes),
        "authorization_receipt_file_sha256": _sha256(receipt_bytes),
        "collection_report_file_sha256": _sha256(report_bytes),
        "collection_log_file_sha256": _sha256(log_bytes),
        "catalog_audit_file_sha256": _sha256(audit_bytes),
        "catalog_audit_sha256": audit.audit_sha256,
        "ancestry_sha256": canonical_sha256(ancestry_value),
    }
    parents = EvidenceSidecarParents(**parent_fields)
    ordered = tuple(responses)
    terminal_counts = {
        status: sum(row.terminal_status == status for row in ordered)
        for status in TERMINAL_STATUSES
    }
    operation_counts = {
        operation: {
            status: sum(
                row.operation == operation and row.terminal_status == status for row in ordered
            )
            for status in TERMINAL_STATUSES
        }
        for operation in APPROVED_OPERATIONS
    }
    states = Counter(field.state for row in ordered for field in row.fields)
    sidecar_fields = {
        "schema_version": SCHEMA_VERSION,
        "data_version": DATA_VERSION,
        "round_id": round_id,
        "round_root": _round_value(root),
        "ancestry_depth": selected.ancestry_depth,
        "parents": parents.model_dump(mode="json"),
        "responses": [row.model_dump(mode="json") for row in ordered],
        "response_count": len(ordered),
        "terminal_status_counts": terminal_counts,
        "operation_status_counts": operation_counts,
        "field_state_counts": {state: states[state] for state in FIELD_STATES},
        "responses_root": canonical_sha256([row.model_dump(mode="json") for row in ordered]),
    }
    return EnrichmentEvidenceSidecar(
        **sidecar_fields,
        sidecar_sha256=canonical_sha256(sidecar_fields),
    )


def canonical_sidecar_bytes(sidecar: EnrichmentEvidenceSidecar) -> bytes:
    """Return the exact canonical publication bytes for one validated sidecar."""

    return canonical_json_bytes(sidecar.model_dump(mode="json"))


def _scan_kto_json_depth(raw_body: bytes) -> None:
    """Reject depth bombs before JSON decoding allocates nested containers."""

    depth = 0
    in_string = False
    escaped = False
    for byte in raw_body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > KTO_MAX_JSON_DEPTH:
                raise ValueError("KTO response JSON depth exceeds 32")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise ValueError("KTO response JSON structure is unbalanced")
    if depth != 0 or in_string:
        raise ValueError("KTO response JSON structure is incomplete")


def _kto_dataset_rights(grant: DatasetGrantEvidence) -> dict[str, object]:
    allowed = (
        grant.official_dataset_id == TOURAPI_DATASET_ID
        and grant.evidence_state == "COMPLETE"
        and grant.commercial_use_allowed
        and grant.transform_allowed
        and grant.display_allowed
        and grant.model_input_allowed
    )
    fields: dict[str, object] = {
        "official_dataset_id": grant.official_dataset_id,
        "official_page_url": grant.official_page_url,
        "retrieved_at": grant.retrieved_at,
        "response_sha256": grant.response_sha256,
        "page_sha256": grant.page_sha256,
        "dataset_grant_sha256": grant.dataset_grant_sha256,
        "evidence_state": grant.evidence_state,
        "state": "PASS" if allowed else "BLOCKED",
        "analysis_eligible": allowed,
        "ui_eligible": allowed,
        "demo_eligible": allowed,
    }
    fields["attestation_sha256"] = canonical_sha256(fields)
    return fields


def _kto_asset_rights(
    items: list[Mapping[str, object]],
    *,
    dataset_rights: Mapping[str, object],
) -> dict[str, object]:
    assets: list[dict[str, object]] = []
    missing_provenance = False
    type3_present = False
    unknown_code = False
    for item in items:
        original_url = item.get("originimgurl")
        serial = item.get("serialnum")
        image_name = item.get("imgname")
        code = item.get("cpyrhtDivCd")
        if (
            not isinstance(original_url, str)
            or not original_url
            or not isinstance(serial, str)
            or not serial
            or not isinstance(image_name, str)
            or not image_name
            or not isinstance(code, str)
            or not code
        ):
            missing_provenance = True
        if code == "Type3":
            type3_present = True
        elif code != "Type1":
            unknown_code = True
        assets.append(
            {
                "source_asset_id": serial if isinstance(serial, str) and serial else None,
                "original_url": (
                    original_url if isinstance(original_url, str) and original_url else None
                ),
                "asset_title": (image_name if isinstance(image_name, str) and image_name else None),
                "creator_identity": ("Korea Tourism Organization" if code == "Type1" else None),
                "license_code": code if isinstance(code, str) and code else None,
                "transform_allowed": code == "Type1",
                "display_allowed": code == "Type1",
            }
        )
    dataset_pass = dataset_rights.get("state") == "PASS"
    if not items:
        state = "MISSING"
        reason = "SUCCESS_EMPTY_HAS_NO_ASSET_PROVENANCE"
    elif not dataset_pass:
        state = "BLOCKED"
        reason = "DATASET_RIGHTS_BLOCKED"
    elif type3_present:
        state = "BLOCKED"
        reason = "NARROWER_TYPE3_ASSET_RESTRICTION"
    elif missing_provenance:
        state = "REVIEW_REQUIRED"
        reason = "ASSET_PROVENANCE_INCOMPLETE"
    elif unknown_code:
        state = "REVIEW_REQUIRED"
        reason = "ASSET_LICENSE_CODE_UNSUPPORTED"
    else:
        state = "PASS"
        reason = "TYPE1_ASSET_PROVENANCE_AND_LANES_COMPLETE"
    allowed = state == "PASS"
    fields: dict[str, object] = {
        "state": state,
        "reason": reason,
        "assets": assets,
        "assets_root_sha256": canonical_sha256(assets),
        "analysis_eligible": allowed,
        "ui_eligible": allowed,
        "demo_eligible": allowed,
    }
    fields["attestation_sha256"] = canonical_sha256(fields)
    return fields


def normalize_kto_recovery_response(
    *,
    planned_request: Mapping[str, object],
    terminal_record: Mapping[str, object],
    raw_body: bytes,
    grant: DatasetGrantEvidence,
) -> dict[str, object]:
    """Normalize one Plan 48 response without authority, traffic, or inference."""

    if len(raw_body) > KTO_MAX_RAW_BYTES:
        raise ValueError("KTO accepted raw response exceeds 8 MiB")
    _scan_kto_json_depth(raw_body)
    request_identity = _require_sha256(
        planned_request.get("request_identity"),
        field="KTO request identity",
    )
    if terminal_record.get("request_identity") != request_identity:
        raise ValueError("KTO terminal row is detached from its request")
    raw_sha256 = _require_sha256(
        terminal_record.get("raw_body_sha256"),
        field="KTO raw response digest",
    )
    if not hmac.compare_digest(_sha256(raw_body), raw_sha256):
        raise ValueError("KTO raw response bytes differ from the terminal row")
    operation = planned_request.get("operation")
    if operation not in {"detailCommon2", "detailIntro2", "detailImage2"}:
        raise ValueError("KTO recovery operation is outside the fixed detail allowlist")
    parameters = planned_request.get("parameters")
    if not isinstance(parameters, Mapping):
        raise ValueError("KTO request parameters are missing")
    content_id = parameters.get("contentId")
    if not isinstance(content_id, str) or not content_id.isdigit():
        raise ValueError("KTO request has no exact contentId")
    try:
        declared_num_of_rows = int(str(parameters["numOfRows"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("KTO request has no valid declared numOfRows") from exc
    if not 1 <= declared_num_of_rows <= KTO_MAX_ITEMS:
        raise ValueError("KTO request declared numOfRows exceeds the absolute 100-item cap")
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("KTO response is not valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("KTO response must be an object")
    response = payload.get("response")
    if not isinstance(response, Mapping):
        raise ValueError("KTO response envelope is missing")
    header = response.get("header")
    body = response.get("body")
    if (
        not isinstance(header, Mapping)
        or header.get("resultCode") not in {"00", "0000"}
        or not isinstance(body, Mapping)
    ):
        raise ValueError("KTO response is not a structured provider success")
    item_container = body.get("items")
    item_shape: str
    if item_container in (None, ""):
        item_shape = "EMPTY"
        items: list[Mapping[str, object]] = []
    elif isinstance(item_container, Mapping):
        item_value = item_container.get("item")
        if item_value in (None, ""):
            item_shape = "EMPTY"
            items = []
        elif isinstance(item_value, Mapping):
            item_shape = "SINGLETON"
            items = [item_value]
        elif isinstance(item_value, list) and all(isinstance(item, Mapping) for item in item_value):
            item_shape = "ARRAY"
            items = list(item_value)
        else:
            raise ValueError("KTO response item shape is unsupported")
    else:
        raise ValueError("KTO response items container is unsupported")
    if len(items) > declared_num_of_rows:
        raise ValueError("KTO response item count exceeds declared numOfRows")
    if len(items) > KTO_MAX_ITEMS:
        raise ValueError("KTO response item count exceeds the absolute 100-item cap")
    if any(item.get("contentid") != content_id for item in items):
        raise ValueError("KTO response contentId differs from the exact request identity")
    actual_types = {
        str(item["contenttypeid"])
        for item in items
        if isinstance(item.get("contenttypeid"), (str, int)) and str(item["contenttypeid"])
    }
    if len(actual_types) > 1:
        raise ValueError("KTO response contains conflicting actual content types")
    actual_content_type_id = next(iter(actual_types), None)
    requested_type = parameters.get("contentTypeId")
    if (
        requested_type is not None
        and actual_content_type_id is not None
        and str(requested_type) != actual_content_type_id
    ):
        raise ValueError("KTO actual content type differs from the request binding")

    dataset_rights = _kto_dataset_rights(grant)
    normalized_items: list[dict[str, object]] = []
    description: str | None = None
    coordinates: dict[str, float] | None = None
    operating: dict[str, str] = {}
    operating_state = "NOT_APPLICABLE"
    operating_reason = "OPERATION_DOES_NOT_CARRY_OPERATING_INFORMATION"
    asset_rights = _kto_asset_rights([], dataset_rights=dataset_rights)
    if operation == "detailCommon2" and items:
        first = items[0]
        overview = first.get("overview")
        if isinstance(overview, str) and overview.strip():
            description = overview.strip()
        try:
            longitude = float(str(first["mapx"]))
            latitude = float(str(first["mapy"]))
            if not (-180 <= longitude <= 180 and -90 <= latitude <= 90):
                raise ValueError
            coordinates = {"latitude": latitude, "longitude": longitude}
        except (KeyError, TypeError, ValueError):
            coordinates = None
        normalized_items = [
            {
                "contentid": content_id,
                "contenttypeid": actual_content_type_id,
                "overview": description,
                "coordinates": coordinates,
            }
        ]
    elif operation == "detailIntro2":
        content_type_id = actual_content_type_id or (
            str(requested_type) if requested_type is not None else None
        )
        if content_type_id == "25":
            operating_state = "TYPE_INAPPLICABLE"
            operating_reason = "CONTENT_TYPE_25_POLICY_REQUIRED"
        elif content_type_id not in KTO_OPERATING_FIELDS:
            operating_state = "TYPE_UNSUPPORTED"
            operating_reason = "CONTENT_TYPE_OPERATING_POLICY_UNSUPPORTED"
        elif items:
            first = items[0]
            operating = {
                field: value.strip()
                for field in KTO_OPERATING_FIELDS[content_type_id]
                if isinstance((value := first.get(field)), str) and value.strip()
            }
            if operating:
                operating_state = "PASS"
                operating_reason = "ACTUAL_CONTENT_TYPE_NAMED_FIELD_PRESENT"
            else:
                operating_state = "MISSING"
                operating_reason = "ACTUAL_CONTENT_TYPE_NAMED_FIELDS_EMPTY"
        else:
            operating_state = "MISSING"
            operating_reason = "SUCCESS_EMPTY_HAS_NO_OPERATING_INFORMATION"
        normalized_items = (
            [
                {
                    "contentid": content_id,
                    "contenttypeid": content_type_id,
                    "operating_information": operating,
                }
            ]
            if items
            else []
        )
    elif operation == "detailImage2":
        asset_rights = _kto_asset_rights(items, dataset_rights=dataset_rights)
        normalized_items = [
            {
                "contentid": content_id,
                "source_asset_id": item.get("serialnum"),
                "originimgurl": item.get("originimgurl"),
                "smallimageurl": item.get("smallimageurl"),
                "imgname": item.get("imgname"),
                "cpyrhtDivCd": item.get("cpyrhtDivCd"),
            }
            for item in items
        ]

    transport_state = "SUCCESS_EMPTY" if not items else "SUCCESS_WITH_ITEMS"
    direct_media_state = (
        "MISSING" if not items else "PASS" if asset_rights["state"] == "PASS" else "RIGHTS_BLOCKED"
    )
    fields: dict[str, object] = {
        "schema_version": "itda.kto-recovery-normalized-response.v1",
        "request_identity": request_identity,
        "provider_candidate_id": planned_request.get("provider_candidate_id"),
        "place_entity_id": planned_request.get("place_entity_id"),
        "operation": operation,
        "provider_content_id": content_id,
        "actual_content_type_id": actual_content_type_id,
        "raw_relative_path": terminal_record.get("raw_relative_path"),
        "raw_body_sha256": raw_sha256,
        "raw_body_size": len(raw_body),
        "provider_result_code": header.get("resultCode"),
        "provider_result_value": header.get("resultMsg"),
        "terminal_normalized_reason": terminal_record.get("normalized_reason"),
        "item_shape": item_shape,
        "item_count": len(items),
        "transport_state": transport_state,
        "normalized_items": normalized_items,
        "normalized_items_root_sha256": canonical_sha256(normalized_items),
        "coordinates": coordinates,
        "coordinates_state": "PASS" if coordinates is not None else "MISSING",
        "description": description,
        "description_state": "PASS" if description is not None else "MISSING",
        "operating_information": operating,
        "operating_state": operating_state,
        "operating_reason": operating_reason,
        "direct_media_state": direct_media_state,
        "dataset_rights": dataset_rights,
        "asset_rights": asset_rights,
    }
    fields["response_evidence_sha256"] = canonical_sha256(fields)
    return fields


__all__ = [
    "ContentIdentity",
    "EnrichmentEvidenceSidecar",
    "EvidenceSidecarParents",
    "NormalizedFieldEvidence",
    "NormalizedResponseEvidence",
    "RightsEvidence",
    "KTO_MAX_ITEMS",
    "KTO_MAX_JSON_DEPTH",
    "KTO_MAX_RAW_BYTES",
    "KTO_OPERATING_FIELDS",
    "build_enrichment_sidecar",
    "canonical_sidecar_bytes",
    "normalize_kto_recovery_response",
    "normalize_terminal_response",
]
