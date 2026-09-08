"""Deterministic, secret-free planning for the Phase 2 TourAPI enrichment round."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from itda.contracts.authority import (
    derive_binding_sha256,
    derive_request_sha256,
    derive_state_attestation_sha256,
    derive_target_sha256,
)
from itda.domain.canonical import canonical_json_bytes as _canonical_json_bytes

LEGACY_SCHEMA_VERSION = "itda.catalog-enrichment-plan.v1"
SCHEMA_VERSION = "itda.catalog-enrichment-plan.v2"
STATE_SCHEMA_VERSION = "itda.catalog-enrichment-state-attestation.v1"
REQUEST_SCHEMA_VERSION = "itda.catalog-enrichment-authorization-request.v1"
APPROVED_OPERATIONS = ("detailCommon2", "detailIntro2", "detailImage2")
KOR_SERVICE2_SCHEMA_SOURCE = "https://www.data.go.kr/data/15101578/openapi.do"
KOR_SERVICE2_BASE_URL = "https://apis.data.go.kr/B551011/KorService2"
KTO_OFFICIAL_CONTRACT_PINS: Mapping[str, str] = {
    "dataset_page_modified_date": "2026-02-26",
    "swagger_sha256": ("da0c6611c711ca838bb24b8f57396a81dfa773f01a494faaa6b97b87531a2cd5"),
    "manual_zip_sha256": ("d1ad707f83d1ab42c9d7a0aeb959a84fe5407e71e1f46c95cc27bb7da914e54a"),
    "manual_docx_sha256": ("c6a28a0404f9f108ccc366b1875b3779d8d98c60156581eedaf7a5c046abfc58"),
    "manual_revision_date": "2026-02-10",
}
KOR_SERVICE2_PARAMETER_ALLOWLISTS: Mapping[str, frozenset[str]] = {
    "detailCommon2": frozenset(
        {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "numOfRows",
            "pageNo",
            "serviceKey",
        }
    ),
    "detailIntro2": frozenset(
        {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "contentTypeId",
            "numOfRows",
            "pageNo",
            "serviceKey",
        }
    ),
    "detailImage2": frozenset(
        {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "imageYN",
            "numOfRows",
            "pageNo",
            "serviceKey",
        }
    ),
}
KTO_COLLECTION_ATTEMPT_POLICY: Mapping[str, object] = {
    "per_attempt_timeout_seconds": 300,
    "maximum_total_attempts": 3,
    "redirects_allowed": False,
    "retryable_outcomes": [
        "TRANSIENT_TRANSPORT",
        "HTTP_408",
        "HTTP_429",
        "HTTP_5XX",
        "TRANSIENT_PROVIDER_CODE",
    ],
}
KTO_COLLECTION_RESPONSE_POLICY: Mapping[str, object] = {
    "maximum_body_bytes": 8 * 1024 * 1024,
    "maximum_json_depth": 32,
    "maximum_items": 100,
    "enforce_declared_num_of_rows": True,
}
OPERATION_FIELD_MAP: Mapping[str, tuple[str, ...]] = {
    "detailCommon2": ("coordinates", "korean_description"),
    "detailIntro2": ("provider_specific_operating_information",),
    "detailImage2": ("exact_provider_direct_media",),
}
PER_ATTEMPT_TIMEOUT_SECONDS = 300
MAX_CANDIDATES = 60
MAX_REQUESTS = 180
MIN_ATTEMPTS = 1
MAX_ATTEMPTS = 5
_HEX64 = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_REVIEWER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", flags=re.ASCII)
_PROHIBITED_PARAMETER_NAMES = frozenset(
    {"serviceKey", "service_key", "apiKey", "api_key", "token", "authorization"}
)

_KTO_PREFLIGHT_AUTHORITY_FIELDS = frozenset(
    {
        "attempt_policy",
        "base_url",
        "collection_root_sha256",
        "completed_nonce_inventory_sha256",
        "deadline",
        "decision_receipt_sha256",
        "issued_at",
        "kto_allowlist_revision_sha256",
        "kto_contract_sha256",
        "kto_eligibility_root",
        "kto_request_manifest_sha256",
        "output_root",
        "request_count",
        "response_policy",
        "reviewer_id",
        "summary_sha256",
        "typed_intro_policy_sha256",
        "unresolved_intro_target_root",
    }
)


def canonical_json_bytes(value: object) -> bytes:
    """Expose the project canonical JSON encoding used for all digest parents."""

    return _canonical_json_bytes(value)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hexadecimal characters")
    return value


def build_kto_collection_authority_parents(
    preflight: Mapping[str, object],
    *,
    nonce: str,
) -> dict[str, object]:
    """Build exact authority parents without issuing or serializing a token."""

    missing = _KTO_PREFLIGHT_AUTHORITY_FIELDS - set(preflight)
    if missing:
        raise ValueError(
            "KTO collection preflight lacks authority fields: " + ", ".join(sorted(missing))
        )
    _require_sha256(nonce, field_name="nonce")
    request_count = preflight["request_count"]
    if not isinstance(request_count, int) or isinstance(request_count, bool) or request_count <= 0:
        raise ValueError("KTO request count must be a positive integer")
    attempt_policy = preflight["attempt_policy"]
    response_policy = preflight["response_policy"]
    if attempt_policy != KTO_COLLECTION_ATTEMPT_POLICY:
        raise ValueError("KTO attempt policy drifted from the exact contract")
    if response_policy != KTO_COLLECTION_RESPONSE_POLICY:
        raise ValueError("KTO response policy drifted from the exact contract")
    base_url = preflight["base_url"]
    if base_url != KOR_SERVICE2_BASE_URL:
        raise ValueError("KTO base URL drifted from the fixed HTTPS host")

    request = {
        "schema_version": "itda.kto-recovery-collection-request.v1",
        "kto_eligibility_root": _require_sha256(
            str(preflight["kto_eligibility_root"]),
            field_name="kto_eligibility_root",
        ),
        "kto_request_manifest_sha256": _require_sha256(
            str(preflight["kto_request_manifest_sha256"]),
            field_name="kto_request_manifest_sha256",
        ),
        "kto_allowlist_revision_sha256": _require_sha256(
            str(preflight["kto_allowlist_revision_sha256"]),
            field_name="kto_allowlist_revision_sha256",
        ),
        "request_count": request_count,
        "base_url": base_url,
        "attempt_policy": attempt_policy,
        "response_policy": response_policy,
    }
    state_attestation = {
        "schema_version": "itda.kto-recovery-collection-state.v1",
        "summary_sha256": _require_sha256(
            str(preflight["summary_sha256"]),
            field_name="summary_sha256",
        ),
        "decision_receipt_sha256": _require_sha256(
            str(preflight["decision_receipt_sha256"]),
            field_name="decision_receipt_sha256",
        ),
        "kto_contract_sha256": _require_sha256(
            str(preflight["kto_contract_sha256"]),
            field_name="kto_contract_sha256",
        ),
        "typed_intro_policy_sha256": _require_sha256(
            str(preflight["typed_intro_policy_sha256"]),
            field_name="typed_intro_policy_sha256",
        ),
        "unresolved_intro_target_root": _require_sha256(
            str(preflight["unresolved_intro_target_root"]),
            field_name="unresolved_intro_target_root",
        ),
        "completed_nonce_inventory_sha256": _require_sha256(
            str(preflight["completed_nonce_inventory_sha256"]),
            field_name="completed_nonce_inventory_sha256",
        ),
        "issued_at": str(preflight["issued_at"]),
        "deadline": str(preflight["deadline"]),
    }
    target = {
        "schema_version": "itda.kto-recovery-collection-target.v1",
        "collection_root_sha256": _require_sha256(
            str(preflight["collection_root_sha256"]),
            field_name="collection_root_sha256",
        ),
        "output_root": str(preflight["output_root"]),
        "deadline": str(preflight["deadline"]),
        "request_count": request_count,
        "base_url": base_url,
        "attempt_policy": attempt_policy,
        "response_policy": response_policy,
    }
    request_sha256 = derive_request_sha256(request)
    state_sha256 = derive_state_attestation_sha256(state_attestation)
    target_sha256 = derive_target_sha256(target)
    reviewer_id = preflight["reviewer_id"]
    if not isinstance(reviewer_id, str) or _REVIEWER.fullmatch(reviewer_id) is None:
        raise ValueError("KTO reviewer ID is not canonical")
    binding = {
        "schema_version": "itda.kto-recovery-authority-binding.v1",
        "action": "enrichment-collect",
        "request_sha256": request_sha256,
        "state_attestation_sha256": state_sha256,
        "target_sha256": target_sha256,
        "reviewer_id": reviewer_id,
        "nonce": nonce,
        "kto_request_manifest_sha256": request["kto_request_manifest_sha256"],
        "kto_allowlist_revision_sha256": request["kto_allowlist_revision_sha256"],
        "request_count": request_count,
        "base_url": base_url,
        "deadline": target["deadline"],
        "attempt_policy": attempt_policy,
        "response_policy": response_policy,
        "output_root": target["output_root"],
    }
    return {
        "request": request,
        "state_attestation": state_attestation,
        "target": target,
        "binding": binding,
        "request_sha256": request_sha256,
        "state_attestation_sha256": state_sha256,
        "target_sha256": target_sha256,
        "binding_sha256": derive_binding_sha256(binding),
    }


def _request_parameters(
    content_id: str,
    operation: str,
    *,
    actual_content_type_id: str = "12",
) -> dict[str, str]:
    common = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
        "contentId": content_id,
        "numOfRows": "1",
        "pageNo": "1",
    }
    if operation == "detailCommon2":
        return common
    if operation == "detailIntro2":
        return {**common, "contentTypeId": actual_content_type_id}
    if operation == "detailImage2":
        return {
            **common,
            "imageYN": "Y",
            "numOfRows": "100",
        }
    raise ValueError(f"unapproved TourAPI detail operation: {operation}")


def build_kto_recovery_request(
    *,
    operation: str,
    provider_candidate_id: str,
    place_entity_id: str,
    source_candidate_row_sha256: str,
    actual_content_type_id: str | None = None,
    bound_actual_content_type_id: str | None = None,
) -> dict[str, object]:
    """Build one official, secret-free KorService2 request identity.

    Recovery callers must bind Intro to immutable list evidence before the
    request identity is derived. Common and Image deliberately reject a type
    value because the current official contracts do not accept it.
    """

    if operation not in APPROVED_OPERATIONS:
        raise ValueError("unapproved KTO recovery operation")
    if (
        not provider_candidate_id.startswith("candidate:tour-api:")
        or not provider_candidate_id.removeprefix("candidate:tour-api:").isdigit()
    ):
        raise ValueError("provider_candidate_id must be an exact TourAPI identity")
    content_id = provider_candidate_id.removeprefix("candidate:tour-api:")
    if (
        not place_entity_id.startswith("place:")
        or _HEX64.fullmatch(place_entity_id.removeprefix("place:")) is None
    ):
        raise ValueError("place_entity_id must be a source-neutral place identity")
    _require_sha256(
        source_candidate_row_sha256,
        field_name="source_candidate_row_sha256",
    )
    if operation != "detailIntro2" and actual_content_type_id is not None:
        raise ValueError(f"{operation} must not accept contentTypeId")
    if operation == "detailIntro2":
        if actual_content_type_id is None:
            raise ValueError("detailIntro2 requires actual_content_type_id")
        if bound_actual_content_type_id is None:
            raise ValueError("detailIntro2 requires a bound actual KTO type")
        if not actual_content_type_id.isdigit():
            raise ValueError("actual_content_type_id must contain decimal digits")
        if actual_content_type_id != bound_actual_content_type_id:
            raise ValueError("contentTypeId does not match the bound actual KTO type")
    parameters = _request_parameters(
        content_id,
        operation,
        actual_content_type_id=actual_content_type_id or "12",
    )
    unsigned: dict[str, object] = {
        "provider": "TourAPI",
        "service": "KorService2",
        "base_url": KOR_SERVICE2_BASE_URL,
        "operation": operation,
        "provider_candidate_id": provider_candidate_id,
        "place_entity_id": place_entity_id,
        "parameters": parameters,
        "mapped_mandatory_fields": list(OPERATION_FIELD_MAP[operation]),
        "source_candidate_row_sha256": source_candidate_row_sha256,
    }
    documented_secret_free = KOR_SERVICE2_PARAMETER_ALLOWLISTS[operation] - {"serviceKey"}
    if set(parameters) != documented_secret_free:
        raise ValueError("request parameters do not match the official allowlist")
    return {**unsigned, "request_identity": _request_identity(unsigned)}


def _request_identity(request: Mapping[str, object]) -> str:
    return _sha256_bytes(canonical_json_bytes(request))


def _validate_pool(
    pool: Mapping[str, object],
    *,
    remediation: bool,
) -> list[Mapping[str, object]]:
    expected_schema = (
        "enrichment-remediation-candidate-pool-v1"
        if remediation
        else "enrichment-candidate-pool-v1"
    )
    if pool.get("schema_version") != expected_schema:
        raise ValueError("unsupported enrichment candidate pool schema")
    pool_count = pool.get("pool_count")
    if (
        not isinstance(pool_count, int)
        or isinstance(pool_count, bool)
        or (not 1 <= pool_count <= MAX_CANDIDATES if remediation else pool_count != MAX_CANDIDATES)
    ):
        qualifier = "between 1 and 60" if remediation else "exactly 60"
        raise ValueError(f"candidate pool must contain {qualifier} identities")
    rows_value = pool.get("rows")
    ids_value = pool.get("ordered_pool_ids")
    if not isinstance(rows_value, list) or len(rows_value) != pool_count:
        qualifier = "between 1 and 60" if remediation else "exactly 60"
        raise ValueError(f"candidate pool must contain {qualifier} rows")
    if not isinstance(ids_value, list) or len(ids_value) != pool_count:
        qualifier = "between 1 and 60" if remediation else "exactly 60"
        raise ValueError(f"candidate pool must contain {qualifier} ordered identities")
    rows: list[Mapping[str, object]] = []
    row_ids: list[str] = []
    for row in rows_value:
        if not isinstance(row, Mapping):
            raise ValueError("candidate pool rows must be objects")
        candidate_id = row.get("provider_candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id.startswith("candidate:tour-api:"):
            raise ValueError("every candidate must be an exact TourAPI identity")
        content_id = candidate_id.removeprefix("candidate:tour-api:")
        if not content_id.isdigit():
            raise ValueError("TourAPI contentId must contain decimal digits only")
        row_ids.append(candidate_id)
        rows.append(row)
    for identity in ids_value:
        if (
            not isinstance(identity, str)
            or not identity.startswith("candidate:tour-api:")
            or not identity.removeprefix("candidate:tour-api:").isdigit()
        ):
            raise ValueError("every ordered identity must be an exact TourAPI identity")
    if row_ids != ids_value:
        raise ValueError("ordered pool identities do not match candidate rows")
    if len(set(row_ids)) != pool_count:
        raise ValueError("candidate pool identities must be unique")
    return rows


def _validate_plan(plan: Mapping[str, object]) -> None:
    schema_version = plan.get("schema_version")
    if schema_version not in {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION}:
        raise ValueError("unsupported enrichment request-plan schema")
    remediation = plan.get("remediation")
    candidate_count = plan.get("candidate_count")
    if (
        not isinstance(candidate_count, int)
        or isinstance(candidate_count, bool)
        or (
            not 1 <= candidate_count <= MAX_CANDIDATES
            if remediation is not None
            else candidate_count != MAX_CANDIDATES
        )
    ):
        qualifier = "between 1 and 60" if remediation is not None else "exactly 60"
        raise ValueError(f"enrichment plan must bind {qualifier} candidates")
    requests_value = plan.get("requests")
    if (
        not isinstance(requests_value, list)
        or not requests_value
        or len(requests_value) > MAX_REQUESTS
    ):
        raise ValueError("enrichment plan must contain between 1 and 180 requests")
    if plan.get("request_count") != len(requests_value):
        raise ValueError("request count does not match request identities")
    attempts = plan.get("attempts_per_request")
    if not isinstance(attempts, int) or isinstance(attempts, bool):
        raise ValueError("attempts_per_request must be an integer")
    if not MIN_ATTEMPTS <= attempts <= MAX_ATTEMPTS:
        raise ValueError("attempts_per_request is outside the bounded retry policy")
    expected_quota = len(requests_value) * attempts
    if plan.get("quota_estimate") != expected_quota:
        raise ValueError("quota estimate must equal request count times attempts")
    quota_limit = plan.get("quota_limit")
    if not isinstance(quota_limit, int) or quota_limit < expected_quota:
        raise ValueError("configured quota is insufficient for the exact plan")
    if plan.get("per_attempt_timeout_seconds") != PER_ATTEMPT_TIMEOUT_SECONDS:
        raise ValueError("every provider request attempt must allow 300 seconds")
    expected_overall = expected_quota * PER_ATTEMPT_TIMEOUT_SECONDS
    if plan.get("overall_timeout_seconds") != expected_overall:
        raise ValueError("overall timeout must derive from exact request and attempt counts")

    operations: list[str] = []
    identities: list[str] = []
    for request_value in requests_value:
        if not isinstance(request_value, Mapping):
            raise ValueError("request identities must be objects")
        operation = request_value.get("operation")
        if operation not in APPROVED_OPERATIONS:
            raise ValueError("request contains an unrelated detail operation")
        parameters = request_value.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ValueError("request parameters must be an object")
        if _PROHIBITED_PARAMETER_NAMES.intersection(parameters):
            raise ValueError("request parameters must never contain credentials")
        candidate_id = request_value.get("provider_candidate_id")
        if (
            not isinstance(candidate_id, str)
            or not candidate_id.startswith("candidate:tour-api:")
            or not candidate_id.removeprefix("candidate:tour-api:").isdigit()
        ):
            raise ValueError("request provider candidate is not an exact TourAPI identity")
        if schema_version == SCHEMA_VERSION:
            expected_parameters = _request_parameters(
                candidate_id.removeprefix("candidate:tour-api:"),
                str(operation),
            )
            documented_secret_free = KOR_SERVICE2_PARAMETER_ALLOWLISTS[str(operation)] - {
                "serviceKey"
            }
            if set(parameters) != documented_secret_free or dict(parameters) != expected_parameters:
                raise ValueError(
                    "request parameters do not match the current KorService2 endpoint allowlist"
                )
        expected_fields = list(OPERATION_FIELD_MAP[str(operation)])
        if request_value.get("mapped_mandatory_fields") != expected_fields:
            raise ValueError("mandatory fields map to an unapproved detail operation")
        identity = request_value.get("request_identity")
        if not isinstance(identity, str):
            raise ValueError("request identity digest is missing")
        unsigned = dict(request_value)
        unsigned.pop("request_identity", None)
        if not hmac.compare_digest(identity, _request_identity(unsigned)):
            raise ValueError("request identity digest is stale")
        operations.append(str(operation))
        identities.append(identity)
    if len(set(identities)) != len(identities):
        raise ValueError("request identities must be unique")
    if remediation is None:
        if operations != list(APPROVED_OPERATIONS) * MAX_CANDIDATES:
            raise ValueError("request operation order is not canonical")
    else:
        candidate_operations: dict[str, list[str]] = {}
        candidate_order: list[str] = []
        for request_value in requests_value:
            assert isinstance(request_value, Mapping)
            candidate_id = str(request_value.get("provider_candidate_id", ""))
            if candidate_id not in candidate_operations:
                candidate_operations[candidate_id] = []
                candidate_order.append(candidate_id)
            candidate_operations[candidate_id].append(str(request_value["operation"]))
        if len(candidate_order) != candidate_count:
            raise ValueError("remediation candidate count is not request-derived")
        approved_order = {operation: index for index, operation in enumerate(APPROVED_OPERATIONS)}
        if any(
            not values
            or len(values) != len(set(values))
            or values != sorted(values, key=approved_order.__getitem__)
            for values in candidate_operations.values()
        ):
            raise ValueError("remediation request operation order is not canonical")


def build_enrichment_plan(
    pool: Mapping[str, object],
    *,
    attempts: int,
    quota_limit: int | None = None,
    remediation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Expand an exact initial or ancestry-bound remediation pool."""

    if not isinstance(attempts, int) or isinstance(attempts, bool):
        raise ValueError("attempts must be an integer")
    if not MIN_ATTEMPTS <= attempts <= MAX_ATTEMPTS:
        raise ValueError(f"attempts must be between {MIN_ATTEMPTS} and {MAX_ATTEMPTS}")
    rows = _validate_pool(pool, remediation=remediation is not None)
    requests: list[dict[str, object]] = []
    for row in rows:
        candidate_id = str(row["provider_candidate_id"])
        content_id = candidate_id.removeprefix("candidate:tour-api:")
        operations_value = row.get("missing_operations", APPROVED_OPERATIONS)
        if (
            not isinstance(operations_value, (list, tuple))
            or not operations_value
            or any(operation not in APPROVED_OPERATIONS for operation in operations_value)
        ):
            raise ValueError("remediation row contains an unapproved missing operation")
        operations = tuple(str(operation) for operation in operations_value)
        if len(operations) != len(set(operations)) or operations != tuple(
            operation for operation in APPROVED_OPERATIONS if operation in set(operations)
        ):
            raise ValueError("remediation row operations must use canonical approved order")
        if remediation is None and operations != APPROVED_OPERATIONS:
            raise ValueError("initial round requires all three approved operations")
        for operation in operations:
            unsigned: dict[str, object] = {
                "provider": "TourAPI",
                "service": "KorService2",
                "operation": operation,
                "provider_candidate_id": candidate_id,
                "place_entity_id": row["place_entity_id"],
                "parameters": _request_parameters(content_id, operation),
                "mapped_mandatory_fields": list(OPERATION_FIELD_MAP[operation]),
                "source_candidate_row_sha256": row["row_sha256"],
            }
            requests.append(
                {
                    **unsigned,
                    "request_identity": _request_identity(unsigned),
                }
            )
    if len(requests) > MAX_REQUESTS:
        raise ValueError("request identity count exceeds the 180-request cap")
    quota_estimate = len(requests) * attempts
    effective_quota_limit = quota_estimate if quota_limit is None else quota_limit
    if (
        not isinstance(effective_quota_limit, int)
        or isinstance(effective_quota_limit, bool)
        or effective_quota_limit < quota_estimate
    ):
        raise ValueError("configured quota is insufficient for the exact request plan")

    parents = pool.get("parents")
    if not isinstance(parents, Mapping):
        raise ValueError("candidate pool parent evidence is missing")
    permission_refs = {
        "formal_policy_sha256": _require_sha256(
            str(parents.get("formal_policy_sha256", "")),
            field_name="formal_policy_sha256",
        ),
        "rights_projection_sha256": _require_sha256(
            str(parents.get("rights_projection_sha256", "")),
            field_name="rights_projection_sha256",
        ),
        "rights_projection_file_sha256": _require_sha256(
            str(parents.get("rights_projection_file_sha256", "")),
            field_name="rights_projection_file_sha256",
        ),
        "authorization_required_before_network": True,
    }
    plan: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "data_version": "catalog-v2-enrichment-request-plan-v2",
        "source_pool_sha256": _require_sha256(
            str(pool.get("pool_sha256", "")),
            field_name="pool_sha256",
        ),
        "source_pool_file_sha256": _sha256_bytes(canonical_json_bytes(pool)),
        "source_pool_rows_root": _require_sha256(
            str(pool.get("rows_root", "")),
            field_name="rows_root",
        ),
        "source_parents": dict(sorted((str(key), value) for key, value in parents.items())),
        "candidate_count": len(rows),
        "request_count": len(requests),
        "attempts_per_request": attempts,
        "quota_estimate": quota_estimate,
        "quota_limit": effective_quota_limit,
        "per_attempt_timeout_seconds": PER_ATTEMPT_TIMEOUT_SECONDS,
        "overall_timeout_seconds": quota_estimate * PER_ATTEMPT_TIMEOUT_SECONDS,
        "global_timeout_policy": "no-shorter-global-timeout",
        "retry_policy": {
            "strategy": "bounded-exponential",
            "maximum_attempts": attempts,
            "retryable_conditions": [
                "transport-timeout",
                "http-429",
                "http-500",
                "http-502",
                "http-503",
                "http-504",
            ],
            "base_delay_seconds": 1,
            "maximum_delay_seconds": 30,
            "jitter": "full",
        },
        "permission_evidence": permission_refs,
        "raw_body_policy": {
            "persist_raw_body": False,
            "record_sha256_before_discard": True,
            "record_http_status": True,
            "record_retrieved_at_utc": True,
        },
        "structured_log_policy": {
            "fields": [
                "request_identity",
                "attempt_number",
                "provider",
                "operation",
                "http_status",
                "latency_ms",
                "response_sha256",
                "outcome_code",
            ],
            "forbidden_fields": [
                "service_key",
                "authorization",
                "raw_response_body",
                "raw_token",
            ],
        },
        "diagnostics_contract": {
            "terminal_outcomes": [
                "success",
                "provider-failure",
                "schema-failure",
                "timeout",
                "retry-exhausted",
            ],
            "failure_records_are_addressable": True,
            "response_sha256_required_when_body_received": True,
        },
        "resume_contract": {
            "ledger_key": "request_identity",
            "skip_only_verified_success": True,
            "record_every_attempt": True,
            "partial_completion_is_not_authority": True,
        },
        "requests": requests,
    }
    if remediation is not None:
        plan["remediation"] = dict(remediation)
    _validate_plan(plan)
    return plan


@dataclass(frozen=True)
class FrozenEnrichmentIssuance:
    """The one-time inputs shared by both deterministic bundle builds."""

    issued_at: datetime
    expires_at: datetime
    nonce: str
    reviewer_id: str
    code_sha256: str
    config_sha256: str
    permission_evidence_sha256: str
    previous_round_ref_sha256: str | None

    def validate(self) -> None:
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("issued_at must be timezone-aware")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expiry must follow issuance")
        _require_sha256(self.nonce, field_name="nonce")
        _require_sha256(self.code_sha256, field_name="code_sha256")
        _require_sha256(self.config_sha256, field_name="config_sha256")
        _require_sha256(
            self.permission_evidence_sha256,
            field_name="permission_evidence_sha256",
        )
        if _REVIEWER.fullmatch(self.reviewer_id) is None:
            raise ValueError("reviewer_id is not canonical")
        if self.previous_round_ref_sha256 is not None:
            _require_sha256(
                self.previous_round_ref_sha256,
                field_name="previous_round_ref_sha256",
            )


def _round_root_value(round_root: Path) -> str:
    resolved = round_root.expanduser().resolve(strict=False)
    parts = resolved.parts
    try:
        artifact_index = parts.index("artifacts")
    except ValueError:
        return resolved.as_posix()
    return Path(*parts[artifact_index:]).as_posix()


def validate_round_pair(
    round_root: Path | str,
    round_id: str,
    plan_bytes: bytes,
) -> Path:
    """Canonicalize and bind the required root/ID pair to the exact plan bytes."""

    _require_sha256(round_id, field_name="round_id")
    root = Path(round_root).expanduser().resolve(strict=False)
    if root.name != round_id:
        raise ValueError("round root basename must equal the supplied round ID")
    plan_sha256 = _sha256_bytes(plan_bytes)
    if not hmac.compare_digest(round_id, plan_sha256):
        raise ValueError("round ID must equal the canonical request-plan digest")
    return root


@dataclass(frozen=True)
class EnrichmentBundle:
    round_root: Path
    round_id: str
    plan: dict[str, object]
    state_attestation: dict[str, object]
    authorization_request: dict[str, object]
    files: dict[str, bytes]

    @property
    def plan_bytes(self) -> bytes:
        return self.files["enrichment-plan.json"]

    @property
    def state_bytes(self) -> bytes:
        return self.files["enrichment-state-attestation.json"]

    @property
    def request_bytes(self) -> bytes:
        return self.files["enrichment-authorization-request.json"]


def build_enrichment_bundle(
    *,
    plan: Mapping[str, object],
    round_root: Path | str,
    round_id: str,
    frozen: FrozenEnrichmentIssuance,
) -> EnrichmentBundle:
    """Build all authority parents twice-safe from one frozen issuance context."""

    if plan.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("new bundle issuance requires the current plan schema")
    frozen.validate()
    _validate_plan(plan)
    plan_copy = json.loads(canonical_json_bytes(plan))
    plan_bytes = canonical_json_bytes(plan_copy)
    root = validate_round_pair(round_root, round_id, plan_bytes)
    remediation = plan_copy.get("remediation")
    if remediation is not None and frozen.previous_round_ref_sha256 is None:
        raise ValueError("a remediation round requires a verified previous-round parent hash")
    if remediation is None and frozen.previous_round_ref_sha256 is not None:
        raise ValueError("an initial round cannot claim a previous-round parent hash")
    expected_permission_digest = _sha256_bytes(
        canonical_json_bytes(plan_copy["permission_evidence"])
    )
    if not hmac.compare_digest(
        frozen.permission_evidence_sha256,
        expected_permission_digest,
    ):
        raise ValueError("permission evidence digest does not match the request plan")

    round_root_value = _round_root_value(root)
    repository_root = _find_repository_root(root)
    prohibited_live_output_paths = [
        "artifacts/restricted/catalog/v2/enrichment/collection-results.jsonl",
        "artifacts/restricted/catalog/v2/enrichment/raw",
    ]
    if repository_root is not None:
        for relative_value in prohibited_live_output_paths:
            if (repository_root / relative_value).exists():
                raise ValueError(f"live collection output already exists: {relative_value}")
    state_attestation: dict[str, object] = {
        "schema_version": STATE_SCHEMA_VERSION,
        "round_id": round_id,
        "round_root": round_root_value,
        "request_plan_sha256": round_id,
        "source_pool_sha256": plan_copy["source_pool_sha256"],
        "source_pool_file_sha256": plan_copy["source_pool_file_sha256"],
        "readiness_file_sha256": plan_copy["source_parents"]["readiness_file_sha256"],
        "readiness_report_sha256": plan_copy["source_parents"]["readiness_report_sha256"],
        "rights_projection_file_sha256": plan_copy["source_parents"][
            "rights_projection_file_sha256"
        ],
        "rights_projection_sha256": plan_copy["source_parents"]["rights_projection_sha256"],
        "permission_evidence_sha256": frozen.permission_evidence_sha256,
        "code_sha256": frozen.code_sha256,
        "config_sha256": frozen.config_sha256,
        "raw_outputs_absent": True,
        "live_collection_outputs_absent": True,
        "prohibited_live_output_paths": prohibited_live_output_paths,
        "previous_round_ref_sha256": frozen.previous_round_ref_sha256,
        "issued_at": frozen.issued_at.isoformat(),
        "expires_at": frozen.expires_at.isoformat(),
    }
    state_bytes = canonical_json_bytes(state_attestation)
    state_sha256 = _sha256_bytes(state_bytes)
    binding = {
        "schema_version": "itda.authority-binding.v2",
        "action": "enrichment-collect",
        "request_sha256": round_id,
        "state_attestation_sha256": state_sha256,
        "target_sha256": round_id,
        "reviewer_id": frozen.reviewer_id,
        "nonce": frozen.nonce,
        "round_id": round_id,
        "round_root": round_root_value,
        "previous_round_ref_sha256": frozen.previous_round_ref_sha256,
        "issued_at": frozen.issued_at.isoformat(),
        "expires_at": frozen.expires_at.isoformat(),
    }
    authorization_request: dict[str, object] = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "action": "enrichment-collect",
        "request_sha256": round_id,
        "state_attestation_sha256": state_sha256,
        "target_sha256": round_id,
        "reviewer_id": frozen.reviewer_id,
        "binding_sha256": derive_binding_sha256(binding),
        "nonce": frozen.nonce,
        "issued_at": frozen.issued_at.isoformat(),
        "expires_at": frozen.expires_at.isoformat(),
        "round_id": round_id,
        "round_root": round_root_value,
        "previous_round_ref_sha256": frozen.previous_round_ref_sha256,
        "authority_token_issued": False,
        "authority_token_prefix": "itda-auth-v2",
        "reviewer_authentication": {
            "mechanism": "single-operator-local-authenticated-channel",
            "cryptographic_reviewer_identity_claimed": False,
            "accepted_risk": (
                "reviewer_id is channel-bound metadata, not a cryptographic identity"
            ),
        },
        "replacement_policy": {
            "reuse_nonce": False,
            "reuse_binding": False,
            "reuse_authority": False,
            "replacement_requires_tombstone": True,
            "new_failed_round_requires_previous_round_ref_sha256": True,
        },
    }
    request_bytes = canonical_json_bytes(authorization_request)
    return EnrichmentBundle(
        round_root=root,
        round_id=round_id,
        plan=plan_copy,
        state_attestation=state_attestation,
        authorization_request=authorization_request,
        files={
            "enrichment-plan.json": plan_bytes,
            "enrichment-state-attestation.json": state_bytes,
            "enrichment-authorization-request.json": request_bytes,
        },
    )


def _initial_reference(bundle: EnrichmentBundle) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "round_id": bundle.round_id,
        "round_root": _round_root_value(bundle.round_root),
        "plan_sha256": _sha256_bytes(bundle.plan_bytes),
    }
    return {
        **unsigned,
        "reference_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def publish_enrichment_bundle(
    bundle: EnrichmentBundle,
    *,
    initial_reference_path: Path | str,
) -> None:
    """Publish an immutable bundle by exclusive root and file creation only."""

    root = bundle.round_root
    reference_path = Path(initial_reference_path).expanduser().resolve(strict=False)
    if root.exists():
        raise FileExistsError(f"round root already exists: {root}")
    if reference_path.exists():
        raise FileExistsError(f"initial round reference already exists: {reference_path}")
    root.parent.mkdir(parents=True, exist_ok=True)
    reference_path.parent.mkdir(parents=True, exist_ok=True)
    root.mkdir(mode=0o700, exist_ok=False)
    try:
        for name, payload in bundle.files.items():
            with (root / name).open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        reference_bytes = canonical_json_bytes(_initial_reference(bundle))
        with reference_path.open("xb") as handle:
            handle.write(reference_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        for path in root.iterdir():
            if path.name in bundle.files and path.is_file():
                path.unlink()
        root.rmdir()
        raise


def _read_canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = path.read_bytes()
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    if canonical_json_bytes(value) != payload:
        raise ValueError(f"{path.name} is not encoded as canonical JSON")
    return value, payload


def verify_enrichment_bundle(
    plan_path: Path | str,
    state_path: Path | str,
    request_path: Path | str,
    *,
    round_root: Path | str,
    round_id: str,
) -> None:
    """Rederive every digest and cross-reference in an immutable bundle."""

    plan_file = Path(plan_path).expanduser().resolve(strict=True)
    state_file = Path(state_path).expanduser().resolve(strict=True)
    request_file = Path(request_path).expanduser().resolve(strict=True)
    plan, plan_bytes = _read_canonical_object(plan_file)
    state, state_bytes = _read_canonical_object(state_file)
    request, _ = _read_canonical_object(request_file)
    root = validate_round_pair(round_root, round_id, plan_bytes)
    expected_files = {plan_file.parent, state_file.parent, request_file.parent}
    if expected_files != {root}:
        raise ValueError("bundle files are outside the canonical round root")
    _validate_plan(plan)
    state_sha256 = _sha256_bytes(state_bytes)
    root_value = _round_root_value(root)
    expected_state = {
        "round_id": round_id,
        "round_root": root_value,
        "request_plan_sha256": round_id,
        "source_pool_sha256": plan["source_pool_sha256"],
        "source_pool_file_sha256": plan["source_pool_file_sha256"],
    }
    for field, expected in expected_state.items():
        if state.get(field) != expected:
            raise ValueError(f"state attestation {field} does not match the plan")
    expected_request = {
        "action": "enrichment-collect",
        "request_sha256": round_id,
        "state_attestation_sha256": state_sha256,
        "target_sha256": round_id,
        "round_id": round_id,
        "round_root": root_value,
        "previous_round_ref_sha256": state.get("previous_round_ref_sha256"),
    }
    for field, expected in expected_request.items():
        if request.get(field) != expected:
            raise ValueError(
                f"authorization request {field.replace('_', ' ')} does not match its parents"
            )
    binding = {
        "schema_version": "itda.authority-binding.v2",
        "action": request["action"],
        "request_sha256": request["request_sha256"],
        "state_attestation_sha256": request["state_attestation_sha256"],
        "target_sha256": request["target_sha256"],
        "reviewer_id": request["reviewer_id"],
        "nonce": request["nonce"],
        "round_id": request["round_id"],
        "round_root": request["round_root"],
        "previous_round_ref_sha256": request["previous_round_ref_sha256"],
        "issued_at": request["issued_at"],
        "expires_at": request["expires_at"],
    }
    if not hmac.compare_digest(
        str(request.get("binding_sha256", "")),
        derive_binding_sha256(binding),
    ):
        raise ValueError("authorization request binding digest is stale")
    _require_sha256(str(request.get("nonce", "")), field_name="nonce")
    if request.get("authority_token_issued") is not False:
        raise ValueError("authorization request must not claim issued authority")


def _find_repository_root(path: Path) -> Path | None:
    for parent in (path, *path.parents):
        if (parent / ".git").exists():
            return parent
    return None


def verify_authorization_preconditions(
    request_path: Path | str,
    *,
    round_root: Path | str,
    round_id: str,
    now: datetime,
) -> None:
    """Verify Plan 16 inputs without consuming or constructing authority."""

    request_file = Path(request_path).expanduser().resolve(strict=True)
    root = Path(round_root).expanduser().resolve(strict=True)
    plan_file = root / "enrichment-plan.json"
    state_file = root / "enrichment-state-attestation.json"
    verify_enrichment_bundle(
        plan_file,
        state_file,
        request_file,
        round_root=root,
        round_id=round_id,
    )
    state, _ = _read_canonical_object(state_file)
    request, _ = _read_canonical_object(request_file)
    if state.get("raw_outputs_absent") is not True:
        raise ValueError("state attestation does not prove raw outputs absent")
    if state.get("live_collection_outputs_absent") is not True:
        raise ValueError("state attestation does not prove collection outputs absent")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("precondition verification time must be timezone-aware")
    expires_at = datetime.fromisoformat(str(request["expires_at"]))
    issued_at = datetime.fromisoformat(str(request["issued_at"]))
    if not issued_at <= now < expires_at:
        raise ValueError("authorization request is not currently valid")
    repository_root = _find_repository_root(request_file)
    if repository_root is not None:
        paths = state.get("prohibited_live_output_paths")
        if not isinstance(paths, list):
            raise ValueError("state attestation lacks prohibited output paths")
        for relative_value in paths:
            if not isinstance(relative_value, str):
                raise ValueError("prohibited output paths must be strings")
            candidate = (repository_root / relative_value).resolve(strict=False)
            if candidate != repository_root and repository_root not in candidate.parents:
                raise ValueError("prohibited output path escapes the repository")
            if candidate.exists():
                raise ValueError(f"live collection output already exists: {relative_value}")
