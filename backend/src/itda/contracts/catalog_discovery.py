"""Strict contracts for Phase 2 staged provider discovery."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, ValidationInfo, field_validator, model_validator

from itda.contracts.authority import freeze_issuance_context
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.provenance import MAX_PROVIDER_RAW_BYTES
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

D1_DATASET_ID = "15114464"
D1_SCHEME = "https"
D1_HOST = "apis.data.go.kr"
D1_PATH = "/5050000/dstrctsTrrsrtService/getDstrctsTrrsrt"
D1_OPERATION = "getDstrctsTrrsrt"
D1_PAGE_COUNT = 20
D1_ROWS_PER_PAGE = 10
D1_ROW_CEILING = 200
D1_MAX_ATTEMPTS = 3
D1_ATTEMPT_TIMEOUT_SECONDS = 300
D1_OVERALL_TIMEOUT_SECONDS = D1_PAGE_COUNT * D1_MAX_ATTEMPTS * D1_ATTEMPT_TIMEOUT_SECONDS
D1_EARLY_STOP = "ALL_TARGETS_UNAMBIGUOUS_OR_TOTAL_COUNT_EXHAUSTED"
D1_SAFE_FAILURE_FIELDS = (
    "http_status",
    "provider_result_code",
    "provider_result_value",
    "safe_headers",
    "raw_body_sha256",
    "raw_relative_path",
    "normalized_reason",
)


class CapabilityState(StrEnum):
    DOCUMENTED_ONLY = "DOCUMENTED_ONLY"
    OBSERVED_RECORD = "OBSERVED_RECORD"


class DeficitServiceability(StrEnum):
    CONFIRMED_PRESENT = "CONFIRMED_PRESENT"
    CONFIRMED_MISSING = "CONFIRMED_MISSING"
    NOT_SERVICEABLE_MEDIA_RIGHTS = "NOT_SERVICEABLE_MEDIA_RIGHTS"
    NOT_SERVICEABLE_OPERATING_INFO = "NOT_SERVICEABLE_OPERATING_INFO"
    UNKNOWN = "UNKNOWN"


class MatchDisposition(StrEnum):
    EXACT_PROVIDER_SCOPED_EVIDENCE = "EXACT_PROVIDER_SCOPED_EVIDENCE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NO_MATCH = "NO_MATCH"


class RightsDisposition(StrEnum):
    PENDING_DATASET_REVIEW = "PENDING_DATASET_REVIEW"
    PENDING_ASSET_REVIEW = "PENDING_ASSET_REVIEW"
    BLOCKED = "BLOCKED"


class ApprovalEvidence(StrictContract):
    """Secret-free, dataset-specific utilization-approval evidence."""

    dataset_id: Literal["15114464"]
    account_stage: Annotated[str, Field(strict=True, min_length=1, max_length=64)]
    approval_state: Literal[
        "PENDING_HUMAN_VERIFICATION",
        "APPROVED",
        "REJECTED",
    ]
    observed_at: datetime
    reviewer_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]
    evidence_sha256: Sha256

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="observed_at")

    @classmethod
    def pending(
        cls,
        *,
        dataset_id: str,
        reviewer_id: str,
        observed_at: datetime | None = None,
    ) -> ApprovalEvidence:
        if dataset_id != D1_DATASET_ID:
            raise ValueError("D1 approval contract is restricted to dataset 15114464")
        timestamp = observed_at or datetime(1970, 1, 1, tzinfo=UTC)
        evidence_parent = {
            "dataset_id": "15114464",
            "account_stage": "UNVERIFIED",
            "approval_state": "PENDING_HUMAN_VERIFICATION",
            "observed_at": timestamp.isoformat(),
            "reviewer_id": reviewer_id,
        }
        return cls(
            dataset_id="15114464",
            account_stage="UNVERIFIED",
            approval_state="PENDING_HUMAN_VERIFICATION",
            observed_at=timestamp,
            reviewer_id=reviewer_id,
            evidence_sha256=canonical_sha256(evidence_parent),
        )


class D1Request(StrictContract):
    """One secret-free page identity for the bounded D1 inventory."""

    dataset_id: Literal["15114464"] = "15114464"
    scheme: Literal["https"] = "https"
    host: Literal["apis.data.go.kr"] = "apis.data.go.kr"
    path: Literal["/5050000/dstrctsTrrsrtService/getDstrctsTrrsrt"] = (
        "/5050000/dstrctsTrrsrtService/getDstrctsTrrsrt"
    )
    method: Literal["GET"] = "GET"
    page_no: Annotated[int, Field(strict=True, ge=1, le=20)]
    num_of_rows: Literal[10] = 10
    response_type: Literal["json"] = "json"
    row_ceiling: Literal[10] = 10
    response_byte_ceiling: Literal[2_000_000] = 2_000_000
    max_attempts: Literal[3] = 3
    attempt_timeout_seconds: Literal[300] = 300
    follow_redirects: Literal[False] = False
    early_stop: Literal["ALL_TARGETS_UNAMBIGUOUS_OR_TOTAL_COUNT_EXHAUSTED"] = (
        "ALL_TARGETS_UNAMBIGUOUS_OR_TOTAL_COUNT_EXHAUSTED"
    )
    retryable_http_statuses: tuple[int, ...] = (408, 429, 500, 502, 503, 504)
    request_identity_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def derive_identity(self) -> Self:
        parent = self.model_dump(exclude={"request_identity_sha256"}, mode="json")
        expected = canonical_sha256(parent)
        if self.request_identity_sha256 is None:
            object.__setattr__(self, "request_identity_sha256", expected)
        elif not hmac.compare_digest(self.request_identity_sha256, expected):
            raise ValueError("D1 request identity digest is stale")
        return self


def build_d1_request_inventory() -> tuple[D1Request, ...]:
    """Freeze all twenty page identities before approval or credential access."""

    return tuple(D1Request(page_no=page_no) for page_no in range(1, 21))


class DiscoveryObservation(StrictContract):
    """Source-neutral proposal derived from one untrusted provider row."""

    target_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    provider_row_id: str | None
    capability_state: CapabilityState
    match_disposition: MatchDisposition
    media_rights_serviceability: DeficitServiceability
    operating_info_serviceability: DeficitServiceability
    rights_disposition: RightsDisposition
    observed_fields: dict[str, str]

    @classmethod
    def from_d1_row(
        cls,
        *,
        target_id: str,
        provider_row: Mapping[str, object],
        matched_target_count: int,
        hierarchy_unambiguous: bool,
        coordinate_conflict: bool,
    ) -> DiscoveryObservation:
        provider_row_id = provider_row.get("CON_UID")
        rendered_row_id = (
            provider_row_id if isinstance(provider_row_id, str) and provider_row_id else None
        )
        exact = (
            rendered_row_id is not None
            and matched_target_count == 1
            and hierarchy_unambiguous
            and not coordinate_conflict
        )
        # A provider-row ID is evidence, never the source-neutral target identity.
        match = (
            MatchDisposition.EXACT_PROVIDER_SCOPED_EVIDENCE
            if exact and not provider_row.get("CON_TITLE")
            else MatchDisposition.REVIEW_REQUIRED
        )
        allowlisted_fields = (
            "CON_UID",
            "CON_TITLE",
            "CON_IMGFILENAME",
            "SRC_TITLE",
            "LINKURL",
            "CON_ISENABLED",
        )
        observed = {
            field: value
            for field in allowlisted_fields
            if isinstance((value := provider_row.get(field)), str) and value
        }
        return cls(
            target_id=target_id,
            provider_row_id=rendered_row_id,
            capability_state=CapabilityState.OBSERVED_RECORD,
            match_disposition=match,
            media_rights_serviceability=(DeficitServiceability.NOT_SERVICEABLE_MEDIA_RIGHTS),
            operating_info_serviceability=(DeficitServiceability.NOT_SERVICEABLE_OPERATING_INFO),
            rights_disposition=RightsDisposition.PENDING_ASSET_REVIEW,
            observed_fields=observed,
        )


class FrozenDiscoveryIssuance(StrictContract):
    """One runtime-frozen, deterministic issuance context."""

    issued_at: datetime
    expires_at: datetime
    nonce: Sha256
    reviewer_id: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ]

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(
        cls,
        value: datetime,
        info: ValidationInfo,
    ) -> datetime:
        return require_utc(value, field_name=info.field_name or "timestamp")

    @model_validator(mode="after")
    def expiry_must_follow_issuance(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("discovery authority expiry must follow issuance")
        return self


@dataclass(frozen=True)
class DiscoveryRequestGeneration:
    request_generation_sha256: str
    request: dict[str, object]
    state_attestation: dict[str, object]
    target: dict[str, object]
    binding: dict[str, object]
    issuance_context: dict[str, object]
    manifest: dict[str, object]
    files: dict[str, bytes]


def _request_parent(
    *,
    failure_generation_sha256: str,
    failure_round_id: str,
    failure_attestation_sha256: str,
    target_matrix_sha256: str,
    approval_evidence: ApprovalEvidence,
) -> dict[str, object]:
    inventory = build_d1_request_inventory()
    approval_contract = {
        "dataset_id": D1_DATASET_ID,
        "required_fields": [
            "dataset_id",
            "account_stage",
            "approval_state",
            "observed_at",
            "reviewer_id",
            "evidence_sha256",
        ],
        "separate_human_verification_required": True,
        "cross_dataset_approval_transfer": False,
        "service_key_is_approval_evidence": False,
    }
    return {
        "schema_version": "itda.catalog-discovery-request.v1",
        "source": "d1",
        "dataset_id": D1_DATASET_ID,
        "scheme": D1_SCHEME,
        "host": D1_HOST,
        "path": D1_PATH,
        "method": "GET",
        "operation": D1_OPERATION,
        "requests": [row.model_dump(mode="json") for row in inventory],
        "request_count": D1_PAGE_COUNT,
        "page_range": {"first": 1, "last": 20},
        "rows_per_page": D1_ROWS_PER_PAGE,
        "row_ceiling": D1_ROW_CEILING,
        "response_byte_ceiling": MAX_PROVIDER_RAW_BYTES,
        "attempts_per_request": D1_MAX_ATTEMPTS,
        "per_attempt_timeout_seconds": D1_ATTEMPT_TIMEOUT_SECONDS,
        "overall_timeout_seconds": D1_OVERALL_TIMEOUT_SECONDS,
        "shorter_global_timeout_permitted": False,
        "follow_redirects": False,
        "early_stop": D1_EARLY_STOP,
        "unused_request_outcome": "NOT_SENT_EARLY_STOP",
        "bound_exceeded_outcome": "DISCOVERY_BOUND_EXCEEDED",
        "credential_parameter": "serviceKey",
        "credential_in_request_identity": False,
        "safe_failure_fields": list(D1_SAFE_FAILURE_FIELDS),
        "raw_body_retention": "PRIVATE_IMMUTABLE_0600",
        "failure_generation_sha256": failure_generation_sha256,
        "failure_round_id": failure_round_id,
        "failure_attestation_sha256": failure_attestation_sha256,
        "target_matrix_sha256": target_matrix_sha256,
        "approval_evidence_contract": approval_contract,
        "forbidden_outputs": [
            "canonical_membership",
            "split_membership",
            "schema_mutation",
            "seal",
            "review_activation",
            "scoring",
        ],
    }


def build_d1_request_generation(
    *,
    repository_relative_root: str,
    failure_generation_sha256: str,
    failure_round_id: str,
    failure_attestation_sha256: str,
    target_matrix_sha256: str,
    target_ids: tuple[str, ...],
    approval_evidence: ApprovalEvidence,
    frozen: FrozenDiscoveryIssuance,
) -> DiscoveryRequestGeneration:
    """Build every pre-traffic authority parent from one frozen context."""

    if len(target_ids) != 24 or len(set(target_ids)) != 24:
        raise ValueError("D1 target matrix must contain exactly 24 unique target IDs")
    if (
        approval_evidence.dataset_id != D1_DATASET_ID
        or approval_evidence.reviewer_id != frozen.reviewer_id
    ):
        raise ValueError("D1 approval-evidence contract identity drifted")
    request = _request_parent(
        failure_generation_sha256=failure_generation_sha256,
        failure_round_id=failure_round_id,
        failure_attestation_sha256=failure_attestation_sha256,
        target_matrix_sha256=target_matrix_sha256,
        approval_evidence=approval_evidence,
    )
    request_sha256 = canonical_sha256(request)
    state_attestation = {
        "schema_version": "itda.catalog-discovery-state-attestation.v1",
        "source": "d1",
        "request_sha256": request_sha256,
        "failure_generation_sha256": failure_generation_sha256,
        "failure_round_id": failure_round_id,
        "failure_attestation_sha256": failure_attestation_sha256,
        "target_matrix_sha256": target_matrix_sha256,
        "approval_receipt_absent": True,
        "credential_access_absent": True,
        "provider_traffic_absent": True,
        "authority_consumption_absent": True,
        "nonce_ledger_mutation_absent": True,
        "collection_root_absent": True,
        "downstream_outputs_absent": True,
    }
    target = {
        "schema_version": "itda.catalog-discovery-target.v1",
        "source": "d1",
        "dataset_id": D1_DATASET_ID,
        "target_matrix_sha256": target_matrix_sha256,
        "target_ids": list(target_ids),
        "observation_only": True,
        "rights_pending": True,
    }
    approval_contract = request["approval_evidence_contract"]
    binding: dict[str, object] = {
        "schema_version": "itda.catalog-discovery-binding.v1",
        "action": "enrichment-collect",
        "source": "d1",
        "dataset_id": D1_DATASET_ID,
        "request_sha256": request_sha256,
        "state_attestation_sha256": canonical_sha256(state_attestation),
        "target_sha256": canonical_sha256(target),
        "reviewer_id": frozen.reviewer_id,
        "repository_relative_root": repository_relative_root,
        "approval_evidence_contract_sha256": canonical_sha256(approval_contract),
    }
    context = freeze_issuance_context(
        action="enrichment-collect",
        request=request,
        state_attestation=state_attestation,
        target=target,
        reviewer_id=frozen.reviewer_id,
        binding=binding,
        nonce=frozen.nonce,
        issued_at=frozen.issued_at,
        expires_at=frozen.expires_at,
        reviewer_channel_risk=(
            "reviewer_id is accepted local-channel metadata, not a cryptographic identity claim"
        ),
    ).model_dump(mode="json")
    request_bytes = canonical_json_bytes(request)
    request_generation_sha256 = hashlib.sha256(request_bytes).hexdigest()
    base_files = {
        "discovery-request.json": request_bytes,
        "discovery-state-attestation.json": canonical_json_bytes(state_attestation),
        "discovery-target.json": canonical_json_bytes(target),
        "discovery-binding.json": canonical_json_bytes(binding),
        "discovery-issuance-context.json": canonical_json_bytes(context),
    }
    manifest = {
        "schema_version": "itda.catalog-discovery-request-generation-manifest.v1",
        "source": "d1",
        "dataset_id": D1_DATASET_ID,
        "request_generation_sha256": request_generation_sha256,
        "reviewer_id": frozen.reviewer_id,
        "files": {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in sorted(base_files.items())
        },
        "provider_requests_sent": 0,
        "credential_file_opened": False,
        "authority_token_issued": False,
        "authority_consumed": False,
        "nonce_ledger_mutated": False,
        "collection_root_created": False,
        "forbidden_outputs_absent": True,
    }
    files = {
        **base_files,
        "discovery-request-manifest.json": canonical_json_bytes(manifest),
    }
    return DiscoveryRequestGeneration(
        request_generation_sha256=request_generation_sha256,
        request=request,
        state_attestation=state_attestation,
        target=target,
        binding=binding,
        issuance_context=context,
        manifest=manifest,
        files=files,
    )


def _write_exclusive_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while publishing discovery request")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise ValueError("published discovery request file is not private")
    finally:
        os.close(descriptor)


def publish_request_generation(
    generation: DiscoveryRequestGeneration,
    root: Path,
) -> None:
    """Publish one digest-addressed request generation without replacement."""

    if root.name != generation.request_generation_sha256:
        raise ValueError("request root basename must equal request-generation SHA-256")
    if root.exists():
        raise FileExistsError(f"request generation already exists: {root}")
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.mkdir(mode=0o700, exist_ok=False)
    os.chmod(root, 0o700)
    created: list[Path] = []
    try:
        for name, payload in sorted(generation.files.items()):
            path = root / name
            _write_exclusive_private_file(path, payload)
            created.append(path)
        directory_descriptor = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        root.rmdir()
        raise


def _read_private_canonical(path: Path) -> tuple[dict[str, object], bytes]:
    if path.is_symlink():
        raise ValueError("discovery request file must not be a symlink")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ValueError("discovery request file must be a single-link 0600 file")
    payload = path.read_bytes()
    value = json.loads(payload)
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ValueError("discovery request file is not canonical JSON")
    return value, payload


def verify_request_generation(root: Path) -> dict[str, object]:
    """Recompute the exact request root and every private file digest."""

    if root.is_symlink() or not root.is_dir():
        raise ValueError("discovery request root must be a regular directory")
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError("discovery request root must have mode 0700")
    manifest, _ = _read_private_canonical(root / "discovery-request-manifest.json")
    request, request_bytes = _read_private_canonical(root / "discovery-request.json")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    if root.name != request_sha256:
        raise ValueError("request generation basename does not match request bytes")
    if manifest.get("request_generation_sha256") != request_sha256:
        raise ValueError("request generation manifest digest is stale")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("request generation manifest lacks a file inventory")
    for name, expected in files.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise ValueError("request generation file inventory is malformed")
        _, payload = _read_private_canonical(root / name)
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected):
            raise ValueError(f"request generation file digest is stale: {name}")
    if request.get("dataset_id") != D1_DATASET_ID:
        raise ValueError("request generation dataset drifted")
    return manifest


__all__ = [
    "ApprovalEvidence",
    "CapabilityState",
    "D1Request",
    "DeficitServiceability",
    "DiscoveryObservation",
    "DiscoveryRequestGeneration",
    "FrozenDiscoveryIssuance",
    "MatchDisposition",
    "RightsDisposition",
    "build_d1_request_generation",
    "build_d1_request_inventory",
    "publish_request_generation",
    "verify_request_generation",
]
