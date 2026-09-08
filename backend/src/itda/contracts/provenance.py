"""Source, evidence, and rights provenance contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import Field, HttpUrl, field_validator

from itda.contracts.base import Sha256, StableId, StrictContract, Version, require_utc

_RIGHTS_FIELDS = (
    "cpyrhtDivCd",
    "copyright",
    "copyrightCode",
    "licenseCode",
    "rights",
)
MAX_PROVIDER_JSON_DEPTH = 64
MAX_PROVIDER_JSON_NODES = 50_000
MAX_PROVIDER_RAW_BYTES = 2_000_000
MAX_PROVIDER_RAW_BASE64_CHARS = 4 * ((MAX_PROVIDER_RAW_BYTES + 2) // 3)


def validate_provider_raw_bytes(raw_body: bytes) -> None:
    """Enforce the collector/reviewer decoded provider byte boundary."""

    if len(raw_body) > MAX_PROVIDER_RAW_BYTES:
        raise ValueError(f"provider raw body exceeds the {MAX_PROVIDER_RAW_BYTES}-byte limit")


def parse_provider_json_bytes(raw_body: bytes) -> object:
    """Decode exact provider bytes and enforce the shared bounded JSON shape."""

    validate_provider_raw_bytes(raw_body)
    try:
        payload: object = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("provider raw body must be valid JSON") from exc
    if not isinstance(payload, (Mapping, list)):
        raise ValueError("provider raw body JSON root must be an object or array")
    _walk_provider_mappings(payload)
    return payload


def _walk_provider_mappings(value: object) -> list[Mapping[str, object]]:
    """Return mappings in pre-order while bounding all JSON values.

    Root depth is zero. Object keys are labels rather than JSON value nodes and
    are not included in the total-node count.
    """

    found: list[Mapping[str, object]] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    node_count = 0
    while stack:
        current, depth = stack.pop()
        node_count += 1
        if node_count > MAX_PROVIDER_JSON_NODES:
            raise ValueError(
                f"provider raw body JSON exceeds {MAX_PROVIDER_JSON_NODES} total values"
            )
        if depth > MAX_PROVIDER_JSON_DEPTH:
            raise ValueError(
                f"provider raw body JSON exceeds maximum depth {MAX_PROVIDER_JSON_DEPTH}"
            )
        if isinstance(current, Mapping):
            found.append(current)
            child_count = len(current)
            if child_count == 0:
                continue
            if depth >= MAX_PROVIDER_JSON_DEPTH:
                raise ValueError(
                    f"provider raw body JSON exceeds maximum depth {MAX_PROVIDER_JSON_DEPTH}"
                )
            if node_count + len(stack) + child_count > MAX_PROVIDER_JSON_NODES:
                raise ValueError(
                    f"provider raw body JSON exceeds {MAX_PROVIDER_JSON_NODES} total values"
                )
            children = tuple(current.values())
            stack.extend((child, depth + 1) for child in reversed(children))
        elif isinstance(current, list):
            child_count = len(current)
            if child_count == 0:
                continue
            if depth >= MAX_PROVIDER_JSON_DEPTH:
                raise ValueError(
                    f"provider raw body JSON exceeds maximum depth {MAX_PROVIDER_JSON_DEPTH}"
                )
            if node_count + len(stack) + child_count > MAX_PROVIDER_JSON_NODES:
                raise ValueError(
                    f"provider raw body JSON exceeds {MAX_PROVIDER_JSON_NODES} total values"
                )
            stack.extend((child, depth + 1) for child in reversed(current))
        else:
            continue
    return found


def extract_provider_modifiedtime(payload: object) -> str | None:
    """Apply the collector's stable first-value modified-time projection."""

    for mapping in _walk_provider_mappings(payload):
        value = mapping.get("modifiedtime")
        if value not in (None, ""):
            return str(value)
    return None


def extract_upstream_rights(payload: object) -> tuple[dict[str, str], ...]:
    """Apply the collector's ordered, recursive, de-duplicated rights projection."""

    rows: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for mapping in _walk_provider_mappings(payload):
        row = {
            key: str(mapping[key]) for key in _RIGHTS_FIELDS if mapping.get(key) not in (None, "")
        }
        identity = tuple(row.items())
        if row and identity not in seen:
            seen.add(identity)
            rows.append(row)
    return tuple(rows)


class SourceProvider(StrEnum):
    TOUR_API = "TOUR_API"
    ODII = "ODII"
    TOURISM_PHOTO = "TOURISM_PHOTO"
    SYNTHETIC = "SYNTHETIC"


class EvidenceType(StrEnum):
    TOUR_DESCRIPTION = "TOUR_DESCRIPTION"
    ODII_TRANSCRIPT = "ODII_TRANSCRIPT"
    PHOTO = "PHOTO"
    SYNTHETIC = "SYNTHETIC"


class AssetUsageStatus(StrEnum):
    ALLOWED_WITH_ATTRIBUTION = "ALLOWED_WITH_ATTRIBUTION"
    BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW = "BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RightsMetadata(StrictContract):
    license_code: Annotated[str, Field(strict=True, min_length=1, max_length=80)]
    asset_usage_status: AssetUsageStatus
    attribution_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    author_or_photographer: Annotated[
        str | None, Field(strict=True, min_length=1, max_length=200)
    ] = None


class SourceIdentity(StrictContract):
    provider: SourceProvider
    source_id: StableId
    source_url: HttpUrl
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=240)]


class EvidenceReference(StrictContract):
    evidence_id: StableId
    provider: SourceProvider
    evidence_type: EvidenceType
    source_id: StableId
    source_url: HttpUrl
    endpoint: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    request_scope: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=100)],
        Annotated[str, Field(strict=True, max_length=500)],
    ]
    retrieved_at: datetime
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)]
    raw_response_sha256: Sha256
    parser_version: Version
    source_version: Version
    excerpt_ko: Annotated[str | None, Field(strict=True, min_length=1, max_length=4_000)] = None
    rights: RightsMetadata

    @field_validator("retrieved_at")
    @classmethod
    def retrieved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="retrieved_at")

    @field_validator("request_scope")
    @classmethod
    def request_scope_must_not_contain_secrets(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden_fragments = (
            "servicekey",
            "api_key",
            "apikey",
            "token",
            "secret",
            "authorization",
        )
        if any(fragment in key.casefold() for key in value for fragment in forbidden_fragments):
            raise ValueError("request_scope must exclude credentials and secret-bearing keys")
        return value
