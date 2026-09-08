"""Offline, fail-closed REINF-18 grammar-correction successor contracts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from itda.contracts.catalog_enrichment import (
    KOR_SERVICE2_PARAMETER_ALLOWLISTS,
    KOR_SERVICE2_SCHEMA_SOURCE,
    SCHEMA_VERSION,
    EnrichmentBundle,
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    build_enrichment_plan,
    canonical_json_bytes,
    verify_enrichment_bundle,
)
from itda.contracts.catalog_readiness import (
    CatalogRoundManifest,
    RoundOrderManifest,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_PARAMETER_ERROR = re.compile(
    r"^INVALID_REQUEST_PARAMETER_ERROR\(([A-Za-z][A-Za-z0-9_]*)\)$",
    flags=re.ASCII,
)
_REPORT_SCHEMA = "itda.catalog-grammar-correction-report.v1"
_SUPERSESSION_SCHEMA = "itda.catalog-grammar-successor-supersession.v1"
_LINEAGE_SCHEMA = "itda.catalog-grammar-failure-lineage.v1"
_POOL_SCHEMA = "enrichment-remediation-candidate-pool-v1"
_CORRECTION_REPORT_NAME = "grammar-correction-report.json"
_SUPERSESSION_REPORT_NAME = "grammar-successor-supersession.json"
_SUPERSESSION_DIRECTORY = "grammar-successor-supersessions"
_INVALID_CORRECTION_REPORT_SHA256 = (
    "a14e2c49a62759a9dc4342fae243a6ec6234ef8c7ec747bb6919795301f7d6cc"
)
_INVALID_CORRECTION_FILE_SHA256 = (
    "cd2f6a8b04379f4e32c135d8253a081064cd23cdc78f27f508e33088a9097aea"
)
_INVALID_SUCCESSOR_ROUND_ID = (
    "cb59feb1cac076c61f15f52cc5e1001641191acfa4854d0f6e22e22ed34725af"
)
_INVALID_SUCCESSOR_ARTIFACT_SHA256 = {
    "remediation-candidate-pool.json": (
        "1ab37296ec06da070959950c7b60a74e0588b5b461db7fdf6550942134f9f9d0"
    ),
    "enrichment-plan.json": _INVALID_SUCCESSOR_ROUND_ID,
    "enrichment-state-attestation.json": (
        "c3955f9635fa8a5035e07995c0a3fb2f89afd9362745d1a1532610a2ca343fdb"
    ),
    "enrichment-authorization-request.json": (
        "1ca7d5655f2bcfb1ffe7ae80e54f97f743d07a691e48a935c2889d00409d78fc"
    ),
}
_INVALID_COLLECTOR_PRECONDITION_ERROR = (
    "remediation previous-round ancestry is incomplete"
)
_SUCCESSOR_FILE_NAMES = frozenset(
    {
        "remediation-candidate-pool.json",
        "enrichment-plan.json",
        "enrichment-state-attestation.json",
        "enrichment-authorization-request.json",
    }
)
_PREVIOUS_ROUND_REF_FIELDS = frozenset(
    {
        "round_id",
        "round_root",
        "round_manifest_sha256",
        "ancestry_depth",
    }
)
_EVIDENCE_FILES = (
    "enrichment-authorization-receipt.json",
    "enrichment-collection-report.json",
    "enrichment-collection-log.jsonl",
    "evidence-sidecars.json",
    "enrichment-round-manifest.json",
    "round-order-manifest.json",
    "aggregate-readiness.json",
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(canonical_json_bytes(value))


def _read_regular(path: Path) -> bytes:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{path.name} must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{path.name} changed while it was read")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(path)
    value = json.loads(payload)
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ValueError(f"{path.name} must be one canonical JSON object")
    return value, payload


def _historical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    """Parse a hash-bound legacy object without rewriting its original encoding."""

    payload = _read_regular(path)
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value, payload


def _json_lines(path: Path) -> tuple[dict[str, Any], ...]:
    payload = _read_regular(path)
    rows: list[dict[str, Any]] = []
    for line in payload.splitlines():
        value = json.loads(line)
        if not isinstance(value, dict) or canonical_json_bytes(value) != line:
            raise ValueError(f"{path.name} contains a non-canonical JSON line")
        rows.append(value)
    if not rows:
        raise ValueError(f"{path.name} must not be empty")
    return tuple(rows)


def allowlist_revision_sha256() -> str:
    """Digest the exact public schema and secret-free per-operation allowlists."""

    fields = {
        "request_plan_schema_version": SCHEMA_VERSION,
        "schema_source": KOR_SERVICE2_SCHEMA_SOURCE,
        "secret_free_parameter_allowlists": {
            operation: sorted(parameters - {"serviceKey"})
            for operation, parameters in sorted(KOR_SERVICE2_PARAMETER_ALLOWLISTS.items())
        },
    }
    return _canonical_sha256(fields)


class _FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GrammarFailureLineage(_FrozenContract):
    """One exact immutable terminal failure eligible for grammar correction."""

    schema_version: str = _LINEAGE_SCHEMA
    failed_request_identity: str
    provider_candidate_id: str
    place_entity_id: str
    operation: str
    provider_result_code: str
    offending_parameter: str
    predecessor_request_parameters_sha256: str
    raw_response_sha256: str

    @model_validator(mode="after")
    def validate_lineage(self) -> Self:
        for name in (
            "failed_request_identity",
            "predecessor_request_parameters_sha256",
            "raw_response_sha256",
        ):
            if _HEX64.fullmatch(str(getattr(self, name))) is None:
                raise ValueError(f"{name} must be a sha256 digest")
        if not self.provider_candidate_id.startswith("candidate:tour-api:"):
            raise ValueError("provider candidate is not addressable TourAPI evidence")
        if not self.provider_candidate_id.removeprefix("candidate:tour-api:").isdigit():
            raise ValueError("provider candidate is not addressable TourAPI evidence")
        if not self.place_entity_id.startswith("place:"):
            raise ValueError("place identity is not addressable")
        if self.operation not in KOR_SERVICE2_PARAMETER_ALLOWLISTS:
            raise ValueError("operation is not addressable")
        return self


class GrammarCorrectionRow(_FrozenContract):
    correction_ordinal: int = Field(ge=0)
    failed_request_identity: str
    corrected_request_identity: str
    provider_candidate_id: str
    place_entity_id: str
    operation: str
    provider_result_code: str
    offending_parameter: str
    predecessor_request_parameters_sha256: str
    corrected_request_parameters_sha256: str
    raw_response_sha256: str


class GrammarCorrectionReport(_FrozenContract):
    schema_version: str = _REPORT_SCHEMA
    predecessor_round_id: str
    predecessor_round_root: str
    predecessor_round_manifest_sha256: str
    ordered_round_manifest_sha256: str
    receipt_sha256: str
    collection_report_sha256: str
    collection_log_sha256: str
    evidence_sidecars_sha256: str
    aggregate_file_sha256: str
    aggregate_sha256: str
    accepted_predecessor_outcome_code: int
    accepted_predecessor_outcome_reason: str
    accepted_predecessor_frontier_count: int
    request_plan_schema_version: str
    schema_source: str
    allowlist_revision_sha256: str
    provider_candidate_count: int
    correction_count: int
    operation_counts: dict[str, int]
    rows: tuple[GrammarCorrectionRow, ...]
    report_sha256: str

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.correction_count != len(self.rows):
            raise ValueError("correction count is not row-derived")
        if self.provider_candidate_count != len(
            {row.provider_candidate_id for row in self.rows}
        ):
            raise ValueError("provider candidate count is not row-derived")
        if tuple(row.correction_ordinal for row in self.rows) != tuple(
            range(len(self.rows))
        ):
            raise ValueError("correction ordinals are not canonical")
        counts: dict[str, int] = {}
        for row in self.rows:
            counts[row.operation] = counts.get(row.operation, 0) + 1
        if self.operation_counts != dict(sorted(counts.items())):
            raise ValueError("operation counts are not row-derived")
        expected = _canonical_sha256(
            self.model_dump(exclude={"report_sha256"}, mode="json")
        )
        if not hmac.compare_digest(self.report_sha256, expected):
            raise ValueError("grammar correction report digest drifted")
        return self


class GrammarSuccessorSupersessionReport(_FrozenContract):
    schema_version: str = _SUPERSESSION_SCHEMA
    reason_code: str
    invalid_correction_report_sha256: str
    invalid_correction_root: str
    invalid_correction_file_sha256: str
    correction_pair_set_sha256: str
    allowlist_revision_sha256: str
    invalid_successor_round_id: str
    invalid_successor_round_root: str
    invalid_successor_artifact_sha256: dict[str, str]
    invalid_collector_precondition_error: str
    invalid_authority_token_issued: bool
    invalid_forbidden_output_count: int = Field(ge=0)
    previous_round_ref: dict[str, object]
    previous_round_ref_sha256: str
    corrected_successor_round_id: str
    corrected_successor_round_root: str
    corrected_successor_artifact_sha256: dict[str, str]
    request_count: int
    candidate_count: int
    attempts_per_request: int
    quota_estimate: int
    per_attempt_timeout_seconds: int
    overall_timeout_seconds: int
    invalid_nonce_sha256: str
    corrected_nonce_sha256: str
    authority_token_issued_or_consumed: bool
    provider_call_performed: bool
    credential_read: bool
    report_sha256: str

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.reason_code != "MISSING_REMEDIATION_PREVIOUS_ROUND_REF":
            raise ValueError("grammar supersession reason is not exact")
        for name in (
            "invalid_correction_report_sha256",
            "invalid_correction_file_sha256",
            "correction_pair_set_sha256",
            "allowlist_revision_sha256",
            "invalid_successor_round_id",
            "previous_round_ref_sha256",
            "corrected_successor_round_id",
            "invalid_nonce_sha256",
            "corrected_nonce_sha256",
            "report_sha256",
        ):
            if _HEX64.fullmatch(str(getattr(self, name))) is None:
                raise ValueError(f"{name} must be a sha256 digest")
        for artifacts in (
            self.invalid_successor_artifact_sha256,
            self.corrected_successor_artifact_sha256,
        ):
            if set(artifacts) != _SUCCESSOR_FILE_NAMES or any(
                _HEX64.fullmatch(value) is None for value in artifacts.values()
            ):
                raise ValueError("grammar supersession artifact hashes are incomplete")
        if set(self.previous_round_ref) != _PREVIOUS_ROUND_REF_FIELDS:
            raise ValueError("grammar supersession previous-round reference is incomplete")
        if not hmac.compare_digest(
            self.previous_round_ref_sha256,
            _canonical_sha256(self.previous_round_ref),
        ):
            raise ValueError("grammar supersession previous-round digest drifted")
        if (
            self.invalid_collector_precondition_error
            != _INVALID_COLLECTOR_PRECONDITION_ERROR
            or self.invalid_authority_token_issued
            or self.invalid_forbidden_output_count != 0
            or self.authority_token_issued_or_consumed
            or self.provider_call_performed
            or self.credential_read
        ):
            raise ValueError("grammar supersession is not pre-network")
        if (
            self.request_count,
            self.candidate_count,
            self.attempts_per_request,
            self.quota_estimate,
            self.per_attempt_timeout_seconds,
            self.overall_timeout_seconds,
        ) != (32, 16, 3, 96, 300, 28_800):
            raise ValueError("grammar supersession execution bounds drifted")
        expected = _canonical_sha256(
            self.model_dump(exclude={"report_sha256"}, mode="json")
        )
        if not hmac.compare_digest(self.report_sha256, expected):
            raise ValueError("grammar supersession report digest drifted")
        return self


@dataclass(frozen=True)
class GrammarSuccessorIssuance:
    issued_at: datetime
    expires_at: datetime
    nonce: str
    reviewer_id: str
    code_sha256: str
    config_sha256: str


@dataclass(frozen=True)
class GrammarCorrectionSuccessor:
    correction_report: GrammarCorrectionReport
    remediation_pool: dict[str, object]
    bundle: EnrichmentBundle


@dataclass(frozen=True)
class GrammarCorrectionSupersession:
    supersession_report: GrammarSuccessorSupersessionReport
    correction_report: GrammarCorrectionReport
    remediation_pool: dict[str, object]
    bundle: EnrichmentBundle


@dataclass(frozen=True)
class _InvalidSupersessionSource:
    repository_root: Path
    correction_report: GrammarCorrectionReport
    correction_report_raw: bytes
    plan: dict[str, Any]
    state: dict[str, Any]
    request: dict[str, Any]
    pool: dict[str, Any]
    pool_raw: bytes
    artifact_sha256: dict[str, str]


def classify_terminal_grammar_failure(
    *,
    planned_request: Mapping[str, object],
    report_record: Mapping[str, object],
    raw_body: bytes,
) -> GrammarFailureLineage:
    """Admit only exact code-10 named-parameter failures for a changed allowlist."""

    if report_record.get("terminal_status") != "TERMINAL_PROVIDER_FAILURE":
        raise ValueError("record is not a terminal provider failure")
    if planned_request.get("provider") != "TourAPI":
        raise ValueError("provider candidate is not addressable TourAPI evidence")
    candidate_id = planned_request.get("provider_candidate_id")
    if (
        not isinstance(candidate_id, str)
        or not candidate_id.startswith("candidate:tour-api:")
        or not candidate_id.removeprefix("candidate:tour-api:").isdigit()
    ):
        raise ValueError("provider candidate is not addressable TourAPI evidence")
    place_id = planned_request.get("place_entity_id")
    if not isinstance(place_id, str) or not place_id.startswith("place:"):
        raise ValueError("place identity is not addressable")
    operation = planned_request.get("operation")
    if operation not in KOR_SERVICE2_PARAMETER_ALLOWLISTS:
        raise ValueError("operation is not addressable")
    identity = planned_request.get("request_identity")
    if not isinstance(identity, str) or report_record.get("request_identity") != identity:
        raise ValueError("report does not bind the failed request identity")
    raw_sha256 = _sha256(raw_body)
    if not hmac.compare_digest(str(report_record.get("raw_body_sha256", "")), raw_sha256):
        raise ValueError("immutable raw response hash differs from the report")
    attempts = report_record.get("attempts")
    if (
        not isinstance(attempts, list)
        or not attempts
        or attempts[-1].get("raw_body_sha256") != raw_sha256
    ):
        raise ValueError("terminal attempt does not bind the immutable raw response")
    try:
        envelope = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("provider body is not a structured named parameter failure") from error
    header: object = envelope
    if isinstance(envelope, dict) and set(envelope) == {"response"}:
        response = envelope.get("response")
        if isinstance(response, dict) and set(response) == {"header"}:
            header = response.get("header")
    if not isinstance(header, dict) or not {
        "resultCode",
        "resultMsg",
    }.issubset(header):
        raise ValueError("provider body is not a structured named parameter failure")
    allowed_header_keys = {"resultCode", "resultMsg", "responseTime"}
    if not set(header).issubset(allowed_header_keys):
        raise ValueError("provider body is not a structured named parameter failure")
    if header.get("resultCode") != "10":
        raise ValueError("provider result is not exact grammar code 10")
    message = header.get("resultMsg")
    match = _PARAMETER_ERROR.fullmatch(message) if isinstance(message, str) else None
    if match is None:
        raise ValueError("provider failure is not an exact named parameter error")
    offending = match.group(1)
    parameters = planned_request.get("parameters")
    if offending in KOR_SERVICE2_PARAMETER_ALLOWLISTS[str(operation)]:
        raise ValueError("named parameter remains in the current endpoint allowlist")
    if not isinstance(parameters, Mapping) or offending not in parameters:
        raise ValueError("named parameter is missing from the predecessor request")
    return GrammarFailureLineage(
        failed_request_identity=identity,
        provider_candidate_id=candidate_id,
        place_entity_id=place_id,
        operation=str(operation),
        provider_result_code="10",
        offending_parameter=offending,
        predecessor_request_parameters_sha256=_canonical_sha256(dict(parameters)),
        raw_response_sha256=raw_sha256,
    )


def _repository_root(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    raise ValueError("predecessor round is not beneath a repository root")


def _lexical_absolute(path: Path | str) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _reject_symlink_components(
    path: Path,
    *,
    repository_root: Path,
) -> None:
    lexical = _lexical_absolute(path)
    root = repository_root.resolve(strict=True)
    try:
        relative = lexical.relative_to(root)
    except ValueError as error:
        raise ValueError("publication path is outside the repository") from error
    current = root
    for part in relative.parts:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            break
        if stat.S_ISLNK(mode):
            raise ValueError("publication path contains a symlink")


def _open_directory_at(parent_fd: int, name: str) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ValueError("publication path contains a symlink or non-directory") from error


def _open_relative_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            next_descriptor = _open_directory_at(descriptor, part)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _entry_exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _directory_identity_matches(
    parent_fd: int,
    name: str,
    child_fd: int,
) -> bool:
    opened = os.fstat(child_fd)
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and current.st_dev == opened.st_dev
        and current.st_ino == opened.st_ino
    )


def _require_directory_identity(
    parent_fd: int,
    name: str,
    child_fd: int,
) -> None:
    if not _directory_identity_matches(parent_fd, name, child_fd):
        raise ValueError("published directory identity changed")


def _rmdir_if_same_directory(
    parent_fd: int,
    name: str,
    child_fd: int,
) -> None:
    if not _directory_identity_matches(parent_fd, name, child_fd):
        return
    with suppress(OSError):
        os.rmdir(name, dir_fd=parent_fd)


def _load_verified_ancestry(
    *,
    predecessor_root: Path,
    predecessor_round_id: str,
    order_path: Path,
) -> tuple[Path, RoundOrderManifest, CatalogRoundManifest]:
    repository_root = _repository_root(predecessor_root)
    order_raw = _read_regular(order_path)
    ordered = RoundOrderManifest.model_validate_json(order_raw)
    if canonical_json_bytes(ordered.model_dump(mode="json")) != order_raw:
        raise ValueError("round-order manifest bytes are not canonical")
    if (
        ordered.newest_round_id != predecessor_round_id
        or (repository_root / ordered.newest_round_root).resolve()
        != predecessor_root.resolve()
    ):
        raise ValueError("round-order manifest does not terminate at the predecessor")
    selected: CatalogRoundManifest | None = None
    for entry in ordered.entries:
        root = (repository_root / entry.round_root).resolve(strict=True)
        manifest_path = root / "enrichment-round-manifest.json"
        manifest_raw = _read_regular(manifest_path)
        unsigned = json.loads(manifest_raw)
        if not isinstance(unsigned, dict) or canonical_json_bytes(unsigned) != manifest_raw:
            raise ValueError("round manifest is not canonical")
        manifest = CatalogRoundManifest.model_validate(
            {**unsigned, "manifest_sha256": _sha256(manifest_raw)}
        )
        if (
            manifest.manifest_sha256 != entry.round_manifest_sha256
            or manifest.round_id != entry.round_id
            or manifest.round_root != entry.round_root
        ):
            raise ValueError("ordered round manifest identity drifted")
        for item in manifest.immutable_files:
            file_path = root / item.relpath
            raw = _read_regular(file_path)
            mode = f"0{stat.S_IMODE(os.lstat(file_path).st_mode):03o}"
            if (
                len(raw) != item.size
                or mode != item.mode
                or not hmac.compare_digest(_sha256(raw), item.file_sha256)
            ):
                raise ValueError("round immutable file tree drifted")
        if entry.round_id == predecessor_round_id:
            selected = manifest
    if selected is None:
        raise ValueError("predecessor round is absent from ordered ancestry")
    return repository_root, ordered, selected


def _derive_previous_round_ref(
    manifest: CatalogRoundManifest,
) -> dict[str, object]:
    return {
        "round_id": manifest.round_id,
        "round_root": manifest.round_root,
        "round_manifest_sha256": manifest.manifest_sha256,
        "ancestry_depth": manifest.ancestry_depth,
    }


def _verify_previous_round_ref(
    *,
    plan: Mapping[str, Any],
    state: Mapping[str, Any],
    request: Mapping[str, Any],
    expected: Mapping[str, object],
) -> None:
    remediation = plan.get("remediation")
    previous = (
        remediation.get("previous_round_ref")
        if isinstance(remediation, Mapping)
        else None
    )
    if not isinstance(previous, Mapping) or set(previous) != _PREVIOUS_ROUND_REF_FIELDS:
        raise ValueError("grammar successor previous-round ancestry is incomplete")
    if dict(previous) != dict(expected):
        raise ValueError(
            "grammar successor previous-round ancestry differs from verified predecessor"
        )
    expected_sha256 = _canonical_sha256(dict(expected))
    if not hmac.compare_digest(
        str(state.get("previous_round_ref_sha256", "")),
        expected_sha256,
    ) or not hmac.compare_digest(
        str(request.get("previous_round_ref_sha256", "")),
        expected_sha256,
    ):
        raise ValueError("grammar successor previous-round ancestry digest is broken")


def _verify_predecessor(
    *,
    predecessor_root: Path,
    predecessor_round_id: str,
    order_path: Path,
) -> tuple[
    dict[str, Any],
    tuple[dict[str, Any], ...],
    dict[str, Any],
    RoundOrderManifest,
    CatalogRoundManifest,
    dict[str, str],
]:
    if predecessor_root.name != predecessor_round_id:
        raise ValueError("predecessor round root and ID differ")
    for name in _EVIDENCE_FILES:
        if not (predecessor_root / name).exists():
            raise ValueError(f"predecessor evidence is missing {name}")
    verify_enrichment_bundle(
        predecessor_root / "enrichment-plan.json",
        predecessor_root / "enrichment-state-attestation.json",
        predecessor_root / "enrichment-authorization-request.json",
        round_root=predecessor_root,
        round_id=predecessor_round_id,
    )
    repository_root, ordered, manifest = _load_verified_ancestry(
        predecessor_root=predecessor_root,
        predecessor_round_id=predecessor_round_id,
        order_path=order_path,
    )
    plan, plan_raw = _canonical_object(predecessor_root / "enrichment-plan.json")
    if not hmac.compare_digest(_sha256(plan_raw), predecessor_round_id):
        raise ValueError("predecessor request plan does not match the round ID")
    aggregate, aggregate_raw = _canonical_object(
        predecessor_root / "aggregate-readiness.json"
    )
    if (
        aggregate.get("outcome_code"),
        aggregate.get("outcome_reason"),
        aggregate.get("addressable_frontier_count"),
    ) != (21, "EVIDENCE_FRONTIER_EXHAUSTED", 0):
        raise ValueError("accepted predecessor outcome is not exact Plan 18 result")
    aggregate_unsigned = dict(aggregate)
    aggregate_digest = aggregate_unsigned.pop("aggregate_sha256", None)
    if aggregate_digest != _canonical_sha256(aggregate_unsigned):
        raise ValueError("aggregate readiness digest drifted")
    if (predecessor_root / "remediation-round-ref.json").exists():
        raise ValueError("Plan 18 predecessor unexpectedly has a remediation child")
    reports = _json_lines(predecessor_root / "enrichment-collection-report.json")
    _json_lines(predecessor_root / "enrichment-collection-log.jsonl")
    _historical_object(predecessor_root / "enrichment-authorization-receipt.json")
    _canonical_object(predecessor_root / "evidence-sidecars.json")
    hashes = {
        "predecessor_round_manifest_sha256": manifest.manifest_sha256,
        "ordered_round_manifest_sha256": _sha256(_read_regular(order_path)),
        "receipt_sha256": _sha256(
            _read_regular(predecessor_root / "enrichment-authorization-receipt.json")
        ),
        "collection_report_sha256": _sha256(
            _read_regular(predecessor_root / "enrichment-collection-report.json")
        ),
        "collection_log_sha256": _sha256(
            _read_regular(predecessor_root / "enrichment-collection-log.jsonl")
        ),
        "evidence_sidecars_sha256": _sha256(
            _read_regular(predecessor_root / "evidence-sidecars.json")
        ),
        "aggregate_file_sha256": _sha256(aggregate_raw),
        "aggregate_sha256": str(aggregate_digest),
        "repository_root": repository_root.as_posix(),
    }
    return plan, reports, aggregate, ordered, manifest, hashes


def _existing_pairs(
    root: Path,
    *,
    ignore_report_sha256: str | None = None,
) -> frozenset[tuple[str, str]]:
    if not root.exists():
        return frozenset()
    pairs: set[tuple[str, str]] = set()
    for path in sorted(root.glob("*/grammar-correction-report.json")):
        if path.parent.name == ignore_report_sha256:
            continue
        report, _ = _canonical_object(path)
        revision = report.get("allowlist_revision_sha256")
        rows = report.get("rows")
        if not isinstance(revision, str) or not isinstance(rows, list):
            raise ValueError("ancestor grammar correction report is malformed")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(
                row.get("failed_request_identity"), str
            ):
                raise ValueError("ancestor grammar correction lineage is malformed")
            pairs.add((row["failed_request_identity"], revision))
    return frozenset(pairs)


def _build_pool(
    *,
    plan: Mapping[str, object],
    lineages: tuple[GrammarFailureLineage, ...],
    parents: Mapping[str, object],
) -> dict[str, object]:
    requests = {
        str(request["request_identity"]): request
        for request in plan["requests"]  # type: ignore[index]
        if isinstance(request, dict)
    }
    grouped: dict[str, list[GrammarFailureLineage]] = {}
    for lineage in lineages:
        grouped.setdefault(lineage.provider_candidate_id, []).append(lineage)
    rows: list[dict[str, object]] = []
    for candidate_id in sorted(grouped):
        group = sorted(
            grouped[candidate_id],
            key=lambda row: ("detailCommon2", "detailIntro2", "detailImage2").index(
                row.operation
            ),
        )
        first_request = requests[group[0].failed_request_identity]
        unsigned = {
            "provider_candidate_id": candidate_id,
            "place_entity_id": group[0].place_entity_id,
            "missing_operations": [row.operation for row in group],
            "predecessor_failed_request_identities": [
                row.failed_request_identity for row in group
            ],
            "source_candidate_row_sha256": first_request[
                "source_candidate_row_sha256"
            ],
        }
        rows.append({**unsigned, "row_sha256": _canonical_sha256(unsigned)})
    ordered_ids = [str(row["provider_candidate_id"]) for row in rows]
    rows_root = _canonical_sha256(rows)
    fields: dict[str, object] = {
        "schema_version": _POOL_SCHEMA,
        "data_version": "catalog-v2-grammar-correction-pool-v1",
        "parents": dict(sorted((str(key), value) for key, value in parents.items())),
        "pool_count": len(rows),
        "ordered_pool_ids": ordered_ids,
        "rows": rows,
        "rows_root": rows_root,
    }
    return {**fields, "pool_sha256": _canonical_sha256(fields)}


def _fresh_against_ancestry(
    *,
    repository_root: Path,
    ordered: RoundOrderManifest,
    bundle: EnrichmentBundle,
) -> None:
    new_request = bundle.authorization_request
    fields = (
        "request_sha256",
        "state_attestation_sha256",
        "target_sha256",
        "binding_sha256",
        "nonce",
    )
    for entry in ordered.entries:
        ancestor, _ = _canonical_object(
            repository_root
            / entry.round_root
            / "enrichment-authorization-request.json"
        )
        for field in fields:
            if hmac.compare_digest(
                str(new_request.get(field, "")), str(ancestor.get(field, ""))
            ):
                raise ValueError(f"successor authority {field} is not fresh")


def _correction_pair_set_sha256(report: GrammarCorrectionReport) -> str:
    pairs = [
        {
            "failed_request_identity": row.failed_request_identity,
            "allowlist_revision_sha256": report.allowlist_revision_sha256,
        }
        for row in report.rows
    ]
    return _canonical_sha256(
        sorted(
            pairs,
            key=lambda row: (
                row["failed_request_identity"],
                row["allowlist_revision_sha256"],
            ),
        )
    )


def _verify_exact_invalid_supersession_source(
    *,
    invalid_correction_root: Path | str,
    invalid_successor_root: Path | str,
    ignore_supersession_report_sha256: str | None = None,
) -> _InvalidSupersessionSource:
    correction_path = _lexical_absolute(invalid_correction_root)
    successor_path = _lexical_absolute(invalid_successor_root)
    repository_root = _repository_root(successor_path)
    expected_correction = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment/grammar-corrections"
        / _INVALID_CORRECTION_REPORT_SHA256
    )
    expected_successor = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment/rounds"
        / _INVALID_SUCCESSOR_ROUND_ID
    )
    _reject_symlink_components(
        correction_path,
        repository_root=repository_root,
    )
    _reject_symlink_components(
        successor_path,
        repository_root=repository_root,
    )
    if correction_path != expected_correction or successor_path != expected_successor:
        raise ValueError("supersession source is not the exact a14e/cb59 issuance")
    if {path.name for path in correction_path.iterdir()} != {
        _CORRECTION_REPORT_NAME
    }:
        raise ValueError("invalid correction root contains undeclared artifacts")
    if {path.name for path in successor_path.iterdir()} != _SUCCESSOR_FILE_NAMES:
        raise ValueError("invalid successor contains execution evidence")
    report_value, report_raw = _canonical_object(
        correction_path / _CORRECTION_REPORT_NAME
    )
    rows_value = report_value.get("rows")
    if not isinstance(rows_value, list):
        raise ValueError("invalid correction report rows are malformed")
    report = GrammarCorrectionReport.model_validate(
        {**report_value, "rows": tuple(rows_value)}
    )
    if (
        correction_path.name != _INVALID_CORRECTION_REPORT_SHA256
        or report.report_sha256 != _INVALID_CORRECTION_REPORT_SHA256
        or not hmac.compare_digest(
            _sha256(report_raw),
            _INVALID_CORRECTION_FILE_SHA256,
        )
        or not hmac.compare_digest(
            report.allowlist_revision_sha256,
            allowlist_revision_sha256(),
        )
    ):
        raise ValueError("invalid correction report is not the exact published report")
    artifact_sha256 = {
        name: _sha256(_read_regular(successor_path / name))
        for name in sorted(_SUCCESSOR_FILE_NAMES)
    }
    if artifact_sha256 != _INVALID_SUCCESSOR_ARTIFACT_SHA256:
        raise ValueError("invalid successor artifacts differ from the published issuance")
    for path in (
        correction_path / _CORRECTION_REPORT_NAME,
        *(successor_path / name for name in _SUCCESSOR_FILE_NAMES),
    ):
        if stat.S_IMODE(os.lstat(path).st_mode) != 0o600:
            raise ValueError("invalid issuance file mode drifted")
    verify_enrichment_bundle(
        successor_path / "enrichment-plan.json",
        successor_path / "enrichment-state-attestation.json",
        successor_path / "enrichment-authorization-request.json",
        round_root=successor_path,
        round_id=_INVALID_SUCCESSOR_ROUND_ID,
    )
    plan, _ = _canonical_object(successor_path / "enrichment-plan.json")
    state, _ = _canonical_object(
        successor_path / "enrichment-state-attestation.json"
    )
    request, _ = _canonical_object(
        successor_path / "enrichment-authorization-request.json"
    )
    pool, pool_raw = _canonical_object(
        successor_path / "remediation-candidate-pool.json"
    )
    remediation = plan.get("remediation")
    if (
        not isinstance(remediation, Mapping)
        or "previous_round_ref" in remediation
        or remediation.get("predecessor_round_id") != report.predecessor_round_id
    ):
        raise ValueError("invalid successor does not have the exact collector defect")
    legacy_previous_sha256 = str(
        remediation.get("predecessor_round_manifest_sha256", "")
    )
    if (
        request.get("authority_token_issued") is not False
        or not hmac.compare_digest(
            str(request.get("previous_round_ref_sha256", "")),
            legacy_previous_sha256,
        )
        or not hmac.compare_digest(
            str(state.get("previous_round_ref_sha256", "")),
            legacy_previous_sha256,
        )
    ):
        raise ValueError("invalid successor authority state differs from the defect")
    if (
        plan.get("request_count"),
        plan.get("candidate_count"),
        plan.get("attempts_per_request"),
        plan.get("quota_estimate"),
        plan.get("per_attempt_timeout_seconds"),
        plan.get("overall_timeout_seconds"),
    ) != (32, 16, 3, 96, 300, 28_800):
        raise ValueError("invalid successor execution bounds drifted")
    payload = report_raw + pool_raw + b"".join(
        _read_regular(successor_path / name) for name in sorted(_SUCCESSOR_FILE_NAMES)
    )
    if b"serviceKey" in payload or b"itda-auth-v2:" in payload:
        raise ValueError("invalid successor contains secret-bearing material")
    slot = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment"
        / _SUPERSESSION_DIRECTORY
        / _INVALID_SUCCESSOR_ROUND_ID
    )
    _reject_symlink_components(slot, repository_root=repository_root)
    if slot.exists():
        if ignore_supersession_report_sha256 is None:
            raise ValueError("failed request already has a correction successor")
        expected_leaf = slot / ignore_supersession_report_sha256
        _reject_symlink_components(
            expected_leaf / _SUPERSESSION_REPORT_NAME,
            repository_root=repository_root,
        )
        if (
            {path.name for path in slot.iterdir()}
            != {ignore_supersession_report_sha256}
            or not expected_leaf.is_dir()
            or {path.name for path in expected_leaf.iterdir()}
            != {_SUPERSESSION_REPORT_NAME}
        ):
            raise ValueError("grammar supersession singleton slot is malformed")
    return _InvalidSupersessionSource(
        repository_root=repository_root,
        correction_report=report,
        correction_report_raw=report_raw,
        plan=plan,
        state=state,
        request=request,
        pool=pool,
        pool_raw=pool_raw,
        artifact_sha256=artifact_sha256,
    )


def _fresh_against_superseded_request(
    *,
    invalid_request: Mapping[str, Any],
    bundle: EnrichmentBundle,
) -> None:
    for field in (
        "request_sha256",
        "state_attestation_sha256",
        "target_sha256",
        "binding_sha256",
        "nonce",
    ):
        if hmac.compare_digest(
            str(bundle.authorization_request.get(field, "")),
            str(invalid_request.get(field, "")),
        ):
            raise ValueError(f"superseding authority {field} is not fresh")


def _build_grammar_correction_successor(
    *,
    predecessor_round_root: Path | str,
    predecessor_round_id: str,
    round_roots_manifest: Path | str,
    rounds_root: Path | str,
    issuance: GrammarSuccessorIssuance,
    existing_correction_pairs: frozenset[tuple[str, str]] = frozenset(),
    _ignore_report_sha256: str | None = None,
    _supersession_binding: Mapping[str, object] | None = None,
) -> GrammarCorrectionSuccessor:
    """Build the deterministic correction report, pool, and fresh authority bundle."""

    predecessor_root = Path(predecessor_round_root).expanduser().resolve(strict=True)
    order_path = Path(round_roots_manifest).expanduser().resolve(strict=True)
    rounds_path = Path(rounds_root).expanduser().resolve(strict=False)
    plan, reports, aggregate, ordered, manifest, hashes = _verify_predecessor(
        predecessor_root=predecessor_root,
        predecessor_round_id=predecessor_round_id,
        order_path=order_path,
    )
    requests = {
        str(request["request_identity"]): request
        for request in plan["requests"]
        if isinstance(request, dict)
    }
    lineages: list[GrammarFailureLineage] = []
    for record in reports:
        identity = record.get("request_identity")
        if not isinstance(identity, str) or identity not in requests:
            raise ValueError("collection report contains an unknown request identity")
        if record.get("terminal_status") != "TERMINAL_PROVIDER_FAILURE":
            continue
        raw_relative = record.get("raw_relative_path")
        if (
            not isinstance(raw_relative, str)
            or raw_relative.startswith("/")
            or ".." in Path(raw_relative).parts
        ):
            raise ValueError("terminal report raw response path is not addressable")
        raw_body = _read_regular(predecessor_root / raw_relative)
        try:
            lineage = classify_terminal_grammar_failure(
                planned_request=requests[identity],
                report_record=record,
                raw_body=raw_body,
            )
        except ValueError as error:
            if "exact grammar code 10" in str(error) or "name one rejected parameter" in str(
                error
            ):
                continue
            raise
        lineages.append(lineage)
    lineages_tuple = tuple(
        sorted(
            lineages,
            key=lambda row: (
                row.provider_candidate_id,
                ("detailCommon2", "detailIntro2", "detailImage2").index(row.operation),
                row.failed_request_identity,
            ),
        )
    )
    if len(lineages_tuple) != 32:
        raise ValueError("exact predecessor grammar correction count must be 32")
    revision = allowlist_revision_sha256()
    correction_root = rounds_path.parent / "grammar-corrections"
    known_pairs = set(existing_correction_pairs) | set(
        _existing_pairs(
            correction_root,
            ignore_report_sha256=_ignore_report_sha256,
        )
    )
    for lineage in lineages_tuple:
        if (lineage.failed_request_identity, revision) in known_pairs:
            raise ValueError("failed request already has a correction successor")
    parents = dict(plan["source_parents"])
    parents.update(
        {
            "grammar_correction_allowlist_revision_sha256": revision,
            "grammar_correction_predecessor_round_manifest_sha256": hashes[
                "predecessor_round_manifest_sha256"
            ],
            "grammar_correction_ordered_round_manifest_sha256": hashes[
                "ordered_round_manifest_sha256"
            ],
        }
    )
    pool = _build_pool(plan=plan, lineages=lineages_tuple, parents=parents)
    previous_round_ref = _derive_previous_round_ref(manifest)
    remediation = {
        "schema_version": "itda.catalog-grammar-correction-remediation.v1",
        "predecessor_round_id": predecessor_round_id,
        "predecessor_round_manifest_sha256": hashes[
            "predecessor_round_manifest_sha256"
        ],
        "ordered_round_manifest_sha256": hashes["ordered_round_manifest_sha256"],
        "allowlist_revision_sha256": revision,
        "failed_request_count": len(lineages_tuple),
        "one_successor_per_failed_request_revision": True,
        "previous_round_ref": previous_round_ref,
    }
    if _supersession_binding is not None:
        remediation["supersession"] = dict(_supersession_binding)
    successor_plan = build_enrichment_plan(
        pool,
        attempts=3,
        quota_limit=96,
        remediation=remediation,
    )
    corrected_by_key = {
        (request["provider_candidate_id"], request["operation"]): request
        for request in successor_plan["requests"]
    }
    rows: list[GrammarCorrectionRow] = []
    for ordinal, lineage in enumerate(lineages_tuple):
        corrected = corrected_by_key[
            (lineage.provider_candidate_id, lineage.operation)
        ]
        corrected_identity = str(corrected["request_identity"])
        if hmac.compare_digest(lineage.failed_request_identity, corrected_identity):
            raise ValueError("corrected request identity did not change")
        rows.append(
            GrammarCorrectionRow(
                correction_ordinal=ordinal,
                failed_request_identity=lineage.failed_request_identity,
                corrected_request_identity=corrected_identity,
                provider_candidate_id=lineage.provider_candidate_id,
                place_entity_id=lineage.place_entity_id,
                operation=lineage.operation,
                provider_result_code=lineage.provider_result_code,
                offending_parameter=lineage.offending_parameter,
                predecessor_request_parameters_sha256=lineage.predecessor_request_parameters_sha256,
                corrected_request_parameters_sha256=_canonical_sha256(
                    corrected["parameters"]
                ),
                raw_response_sha256=lineage.raw_response_sha256,
            )
        )
    report_fields: dict[str, object] = {
        "schema_version": _REPORT_SCHEMA,
        "predecessor_round_id": predecessor_round_id,
        "predecessor_round_root": predecessor_root.relative_to(
            Path(hashes["repository_root"])
        ).as_posix(),
        **{key: value for key, value in hashes.items() if key != "repository_root"},
        "accepted_predecessor_outcome_code": aggregate["outcome_code"],
        "accepted_predecessor_outcome_reason": aggregate["outcome_reason"],
        "accepted_predecessor_frontier_count": aggregate[
            "addressable_frontier_count"
        ],
        "request_plan_schema_version": SCHEMA_VERSION,
        "schema_source": KOR_SERVICE2_SCHEMA_SOURCE,
        "allowlist_revision_sha256": revision,
        "provider_candidate_count": len(
            {row.provider_candidate_id for row in rows}
        ),
        "correction_count": len(rows),
        "operation_counts": {
            operation: sum(row.operation == operation for row in rows)
            for operation in sorted({row.operation for row in rows})
        },
        "rows": tuple(row.model_dump(mode="json") for row in rows),
    }
    report = GrammarCorrectionReport(
        **report_fields,
        report_sha256=_canonical_sha256(report_fields),
    )
    plan_bytes = canonical_json_bytes(successor_plan)
    round_id = _sha256(plan_bytes)
    permission_sha256 = _canonical_sha256(successor_plan["permission_evidence"])
    bundle = build_enrichment_bundle(
        plan=successor_plan,
        round_root=rounds_path / round_id,
        round_id=round_id,
        frozen=FrozenEnrichmentIssuance(
            issued_at=issuance.issued_at,
            expires_at=issuance.expires_at,
            nonce=issuance.nonce,
            reviewer_id=issuance.reviewer_id,
            code_sha256=issuance.code_sha256,
            config_sha256=issuance.config_sha256,
            permission_evidence_sha256=permission_sha256,
            previous_round_ref_sha256=_canonical_sha256(previous_round_ref),
        ),
    )
    _fresh_against_ancestry(
        repository_root=Path(hashes["repository_root"]),
        ordered=ordered,
        bundle=bundle,
    )
    if bundle.authorization_request["authority_token_issued"] is not False:
        raise ValueError("grammar successor must not issue authority")
    return GrammarCorrectionSuccessor(
        correction_report=report,
        remediation_pool=pool,
        bundle=bundle,
    )


def build_grammar_correction_successor(
    *,
    predecessor_round_root: Path | str,
    predecessor_round_id: str,
    round_roots_manifest: Path | str,
    rounds_root: Path | str,
    issuance: GrammarSuccessorIssuance,
    existing_correction_pairs: frozenset[tuple[str, str]] = frozenset(),
) -> GrammarCorrectionSuccessor:
    """Build a normal successor without exposing replay or supersession bypasses."""

    return _build_grammar_correction_successor(
        predecessor_round_root=predecessor_round_root,
        predecessor_round_id=predecessor_round_id,
        round_roots_manifest=round_roots_manifest,
        rounds_root=rounds_root,
        issuance=issuance,
        existing_correction_pairs=existing_correction_pairs,
    )


def _build_grammar_correction_supersession(
    *,
    predecessor_round_root: Path | str,
    predecessor_round_id: str,
    round_roots_manifest: Path | str,
    invalid_correction_root: Path | str,
    invalid_successor_root: Path | str,
    rounds_root: Path | str,
    issuance: GrammarSuccessorIssuance,
    _ignore_supersession_report_sha256: str | None = None,
) -> GrammarCorrectionSupersession:
    """Reissue only the exact pre-network cb59 defect into one fresh successor."""

    source = _verify_exact_invalid_supersession_source(
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        ignore_supersession_report_sha256=_ignore_supersession_report_sha256,
    )
    rounds_path = _lexical_absolute(rounds_root)
    expected_rounds_path = (
        source.repository_root
        / "artifacts/restricted/catalog/v2/enrichment/rounds"
    )
    _reject_symlink_components(
        rounds_path,
        repository_root=source.repository_root,
    )
    if rounds_path != expected_rounds_path:
        raise ValueError("supersession must use the canonical rounds root")
    predecessor_path = (
        Path(predecessor_round_root).expanduser().resolve(strict=True)
    )
    if (
        predecessor_path.name != source.correction_report.predecessor_round_id
        or predecessor_round_id != source.correction_report.predecessor_round_id
        or predecessor_path
        != (
            source.repository_root
            / source.correction_report.predecessor_round_root
        ).resolve(strict=True)
    ):
        raise ValueError("supersession predecessor differs from the exact correction")
    invalid_correction_path = (
        Path(invalid_correction_root).expanduser().resolve(strict=True)
    )
    invalid_successor_path = (
        Path(invalid_successor_root).expanduser().resolve(strict=True)
    )
    pair_set_sha256 = _correction_pair_set_sha256(source.correction_report)
    supersession_binding: dict[str, object] = {
        "schema_version": _SUPERSESSION_SCHEMA,
        "reason_code": "MISSING_REMEDIATION_PREVIOUS_ROUND_REF",
        "invalid_correction_report_sha256": _INVALID_CORRECTION_REPORT_SHA256,
        "invalid_correction_root": invalid_correction_path.relative_to(
            source.repository_root
        ).as_posix(),
        "invalid_correction_file_sha256": _INVALID_CORRECTION_FILE_SHA256,
        "correction_pair_set_sha256": pair_set_sha256,
        "invalid_successor_round_id": _INVALID_SUCCESSOR_ROUND_ID,
        "invalid_successor_round_root": invalid_successor_path.relative_to(
            source.repository_root
        ).as_posix(),
        "invalid_successor_authorization_request_sha256": source.artifact_sha256[
            "enrichment-authorization-request.json"
        ],
        "one_time": True,
    }
    successor = _build_grammar_correction_successor(
        predecessor_round_root=predecessor_round_root,
        predecessor_round_id=predecessor_round_id,
        round_roots_manifest=round_roots_manifest,
        rounds_root=rounds_path,
        issuance=issuance,
        _ignore_report_sha256=_INVALID_CORRECTION_REPORT_SHA256,
        _supersession_binding=supersession_binding,
    )
    if (
        canonical_json_bytes(successor.correction_report.model_dump(mode="json"))
        != source.correction_report_raw
        or canonical_json_bytes(successor.remediation_pool) != source.pool_raw
    ):
        raise ValueError("supersession changed the accepted correction or pool")
    _fresh_against_superseded_request(
        invalid_request=source.request,
        bundle=successor.bundle,
    )
    remediation = successor.bundle.plan.get("remediation")
    previous_round_ref = (
        remediation.get("previous_round_ref")
        if isinstance(remediation, Mapping)
        else None
    )
    if not isinstance(previous_round_ref, dict):
        raise ValueError("supersession previous-round reference is incomplete")
    corrected_artifact_sha256 = {
        "remediation-candidate-pool.json": _sha256(
            canonical_json_bytes(successor.remediation_pool)
        ),
        **{
            name: _sha256(payload)
            for name, payload in successor.bundle.files.items()
        },
    }
    report_fields: dict[str, object] = {
        "schema_version": _SUPERSESSION_SCHEMA,
        "reason_code": "MISSING_REMEDIATION_PREVIOUS_ROUND_REF",
        "invalid_correction_report_sha256": _INVALID_CORRECTION_REPORT_SHA256,
        "invalid_correction_root": supersession_binding["invalid_correction_root"],
        "invalid_correction_file_sha256": _INVALID_CORRECTION_FILE_SHA256,
        "correction_pair_set_sha256": pair_set_sha256,
        "allowlist_revision_sha256": (
            source.correction_report.allowlist_revision_sha256
        ),
        "invalid_successor_round_id": _INVALID_SUCCESSOR_ROUND_ID,
        "invalid_successor_round_root": supersession_binding[
            "invalid_successor_round_root"
        ],
        "invalid_successor_artifact_sha256": source.artifact_sha256,
        "invalid_collector_precondition_error": (
            _INVALID_COLLECTOR_PRECONDITION_ERROR
        ),
        "invalid_authority_token_issued": False,
        "invalid_forbidden_output_count": 0,
        "previous_round_ref": previous_round_ref,
        "previous_round_ref_sha256": _canonical_sha256(previous_round_ref),
        "corrected_successor_round_id": successor.bundle.round_id,
        "corrected_successor_round_root": successor.bundle.round_root.relative_to(
            source.repository_root
        ).as_posix(),
        "corrected_successor_artifact_sha256": corrected_artifact_sha256,
        "request_count": successor.bundle.plan["request_count"],
        "candidate_count": successor.bundle.plan["candidate_count"],
        "attempts_per_request": successor.bundle.plan["attempts_per_request"],
        "quota_estimate": successor.bundle.plan["quota_estimate"],
        "per_attempt_timeout_seconds": successor.bundle.plan[
            "per_attempt_timeout_seconds"
        ],
        "overall_timeout_seconds": successor.bundle.plan[
            "overall_timeout_seconds"
        ],
        "invalid_nonce_sha256": _sha256(
            str(source.request["nonce"]).encode("ascii")
        ),
        "corrected_nonce_sha256": _sha256(issuance.nonce.encode("ascii")),
        "authority_token_issued_or_consumed": False,
        "provider_call_performed": False,
        "credential_read": False,
    }
    report = GrammarSuccessorSupersessionReport(
        **report_fields,
        report_sha256=_canonical_sha256(report_fields),
    )
    return GrammarCorrectionSupersession(
        supersession_report=report,
        correction_report=successor.correction_report,
        remediation_pool=successor.remediation_pool,
        bundle=successor.bundle,
    )


def build_grammar_correction_supersession(
    *,
    predecessor_round_root: Path | str,
    predecessor_round_id: str,
    round_roots_manifest: Path | str,
    invalid_correction_root: Path | str,
    invalid_successor_root: Path | str,
    rounds_root: Path | str,
    issuance: GrammarSuccessorIssuance,
) -> GrammarCorrectionSupersession:
    """Build the single exact cb59 reissuance without a public bypass flag."""

    return _build_grammar_correction_supersession(
        predecessor_round_root=predecessor_round_root,
        predecessor_round_id=predecessor_round_id,
        round_roots_manifest=round_roots_manifest,
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        rounds_root=rounds_root,
        issuance=issuance,
    )


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive_at(parent_fd: int, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_grammar_correction_successor(
    successor: GrammarCorrectionSuccessor,
    *,
    correction_root: Path | str,
) -> None:
    """Publish both digest roots using exclusive root and file creation."""

    correction_path = Path(correction_root).expanduser().resolve(strict=False)
    successor_root = successor.bundle.round_root
    if correction_path.name != successor.correction_report.report_sha256:
        raise ValueError("correction root basename must equal report digest")
    if successor_root.name != successor.bundle.round_id:
        raise ValueError("successor root basename must equal request-plan digest")
    if correction_path.exists() or successor_root.exists():
        raise FileExistsError("correction or successor root already exists")
    for parent in (correction_path.parent, successor_root.parent):
        parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(os.lstat(parent).st_mode):
            raise ValueError("publication parent must not be a symlink")
    created: list[Path] = []
    try:
        os.mkdir(correction_path, 0o700)
        created.append(correction_path)
        os.mkdir(successor_root, 0o700)
        created.append(successor_root)
        _write_exclusive(
            correction_path / _CORRECTION_REPORT_NAME,
            canonical_json_bytes(successor.correction_report.model_dump(mode="json")),
        )
        _write_exclusive(
            successor_root / "remediation-candidate-pool.json",
            canonical_json_bytes(successor.remediation_pool),
        )
        for name, payload in successor.bundle.files.items():
            _write_exclusive(successor_root / name, payload)
    except BaseException:
        for root in reversed(created):
            for path in root.iterdir():
                if path.is_file():
                    path.unlink()
            root.rmdir()
        raise


def publish_grammar_correction_supersession(
    supersession: GrammarCorrectionSupersession,
    *,
    supersession_root: Path | str,
) -> None:
    """Publish one singleton supersession record and one fresh successor root."""

    supersession_path = _lexical_absolute(supersession_root)
    slot = supersession_path.parent
    successor_root = _lexical_absolute(supersession.bundle.round_root)
    report = supersession.supersession_report
    repository_root = _repository_root(successor_root)
    expected_successor_root = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment/rounds"
        / report.corrected_successor_round_id
    )
    expected_supersession_root = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment"
        / _SUPERSESSION_DIRECTORY
        / _INVALID_SUCCESSOR_ROUND_ID
        / report.report_sha256
    )
    _reject_symlink_components(
        successor_root,
        repository_root=repository_root,
    )
    _reject_symlink_components(
        supersession_path,
        repository_root=repository_root,
    )
    if successor_root != expected_successor_root:
        raise ValueError("superseding successor is outside the canonical rounds root")
    if supersession_path != expected_supersession_root:
        raise ValueError("supersession report is outside the canonical supersession root")
    if (
        supersession_path.name != report.report_sha256
        or slot.name != _INVALID_SUCCESSOR_ROUND_ID
        or slot.parent.name != _SUPERSESSION_DIRECTORY
    ):
        raise ValueError("supersession root does not bind the invalid round and report")
    if successor_root.name != supersession.bundle.round_id:
        raise ValueError("superseding root basename must equal request-plan digest")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    repository_fd = os.open(repository_root, directory_flags)
    enrichment_fd: int | None = None
    rounds_fd: int | None = None
    supersessions_fd: int | None = None
    slot_fd: int | None = None
    report_fd: int | None = None
    successor_fd: int | None = None
    created_supersessions = False
    created_slot = False
    created_report = False
    created_successor = False
    try:
        enrichment_fd = _open_relative_directory(
            repository_fd,
            ("artifacts", "restricted", "catalog", "v2", "enrichment"),
        )
        rounds_fd = _open_directory_at(enrichment_fd, "rounds")
        try:
            supersessions_fd = _open_directory_at(
                enrichment_fd,
                _SUPERSESSION_DIRECTORY,
            )
        except FileNotFoundError:
            os.mkdir(
                _SUPERSESSION_DIRECTORY,
                0o700,
                dir_fd=enrichment_fd,
            )
            created_supersessions = True
            supersessions_fd = _open_directory_at(
                enrichment_fd,
                _SUPERSESSION_DIRECTORY,
            )
        if _entry_exists_at(
            supersessions_fd,
            _INVALID_SUCCESSOR_ROUND_ID,
        ) or _entry_exists_at(rounds_fd, supersession.bundle.round_id):
            raise FileExistsError(
                "supersession slot or corrected successor already exists"
            )
        os.mkdir(
            _INVALID_SUCCESSOR_ROUND_ID,
            0o700,
            dir_fd=supersessions_fd,
        )
        created_slot = True
        slot_fd = _open_directory_at(
            supersessions_fd,
            _INVALID_SUCCESSOR_ROUND_ID,
        )
        os.mkdir(report.report_sha256, 0o700, dir_fd=slot_fd)
        created_report = True
        report_fd = _open_directory_at(slot_fd, report.report_sha256)
        os.mkdir(
            supersession.bundle.round_id,
            0o700,
            dir_fd=rounds_fd,
        )
        created_successor = True
        successor_fd = _open_directory_at(
            rounds_fd,
            supersession.bundle.round_id,
        )
        _write_exclusive_at(
            report_fd,
            _SUPERSESSION_REPORT_NAME,
            canonical_json_bytes(report.model_dump(mode="json")),
        )
        _write_exclusive_at(
            successor_fd,
            "remediation-candidate-pool.json",
            canonical_json_bytes(supersession.remediation_pool),
        )
        for name, payload in supersession.bundle.files.items():
            _write_exclusive_at(successor_fd, name, payload)
        for descriptor in (
            report_fd,
            successor_fd,
            slot_fd,
            supersessions_fd,
            rounds_fd,
            enrichment_fd,
        ):
            os.fsync(descriptor)
        _require_directory_identity(enrichment_fd, "rounds", rounds_fd)
        _require_directory_identity(
            enrichment_fd,
            _SUPERSESSION_DIRECTORY,
            supersessions_fd,
        )
        _require_directory_identity(
            supersessions_fd,
            _INVALID_SUCCESSOR_ROUND_ID,
            slot_fd,
        )
        _require_directory_identity(slot_fd, report.report_sha256, report_fd)
        _require_directory_identity(
            rounds_fd,
            supersession.bundle.round_id,
            successor_fd,
        )
    except BaseException:
        if successor_fd is not None:
            for name in (
                "remediation-candidate-pool.json",
                *supersession.bundle.files,
            ):
                with suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=successor_fd)
        if report_fd is not None:
            with suppress(FileNotFoundError):
                os.unlink(_SUPERSESSION_REPORT_NAME, dir_fd=report_fd)
        if (
            created_successor
            and rounds_fd is not None
            and successor_fd is not None
        ):
            _rmdir_if_same_directory(
                rounds_fd,
                supersession.bundle.round_id,
                successor_fd,
            )
        if created_report and slot_fd is not None and report_fd is not None:
            _rmdir_if_same_directory(
                slot_fd,
                report.report_sha256,
                report_fd,
            )
        if (
            created_slot
            and supersessions_fd is not None
            and slot_fd is not None
        ):
            _rmdir_if_same_directory(
                supersessions_fd,
                _INVALID_SUCCESSOR_ROUND_ID,
                slot_fd,
            )
        if (
            created_supersessions
            and enrichment_fd is not None
            and supersessions_fd is not None
        ):
            _rmdir_if_same_directory(
                enrichment_fd,
                _SUPERSESSION_DIRECTORY,
                supersessions_fd,
            )
        raise
    finally:
        for descriptor in (
            successor_fd,
            report_fd,
            slot_fd,
            supersessions_fd,
            rounds_fd,
            enrichment_fd,
            repository_fd,
        ):
            if descriptor is not None:
                os.close(descriptor)


def verify_published_grammar_correction_supersession(
    *,
    predecessor_round_root: Path | str,
    predecessor_round_id: str,
    round_roots_manifest: Path | str,
    invalid_correction_root: Path | str,
    invalid_successor_root: Path | str,
    supersession_root: Path | str,
    successor_root: Path | str,
) -> None:
    """Verify and deterministically replay the one exact offline supersession."""

    supersession_path = _lexical_absolute(supersession_root)
    successor_path = _lexical_absolute(successor_root)
    candidate_report_sha256 = supersession_path.name
    if _HEX64.fullmatch(candidate_report_sha256) is None:
        raise ValueError("supersession report root is not digest-addressed")
    source = _verify_exact_invalid_supersession_source(
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        ignore_supersession_report_sha256=candidate_report_sha256,
    )
    _reject_symlink_components(
        supersession_path / _SUPERSESSION_REPORT_NAME,
        repository_root=source.repository_root,
    )
    _reject_symlink_components(
        successor_path,
        repository_root=source.repository_root,
    )
    if {path.name for path in supersession_path.iterdir()} != {
        _SUPERSESSION_REPORT_NAME
    }:
        raise ValueError("supersession root has undeclared artifacts")
    if {path.name for path in successor_path.iterdir()} != _SUCCESSOR_FILE_NAMES:
        raise ValueError("superseding successor root has undeclared artifacts")
    report_value, report_raw = _canonical_object(
        supersession_path / _SUPERSESSION_REPORT_NAME
    )
    report = GrammarSuccessorSupersessionReport.model_validate(report_value)
    if (
        supersession_path.name != report.report_sha256
        or supersession_path.parent.name != _INVALID_SUCCESSOR_ROUND_ID
        or supersession_path.parent.parent.name != _SUPERSESSION_DIRECTORY
    ):
        raise ValueError("published supersession root identity drifted")
    expected_successor_path = (
        source.repository_root
        / "artifacts/restricted/catalog/v2/enrichment/rounds"
        / report.corrected_successor_round_id
    )
    expected_supersession_path = (
        source.repository_root
        / "artifacts/restricted/catalog/v2/enrichment"
        / _SUPERSESSION_DIRECTORY
        / _INVALID_SUCCESSOR_ROUND_ID
        / report.report_sha256
    )
    if successor_path != expected_successor_path:
        raise ValueError("verified successor is outside the canonical rounds root")
    if supersession_path != expected_supersession_path:
        raise ValueError("verified report is outside the canonical supersession root")
    plan, _ = _canonical_object(successor_path / "enrichment-plan.json")
    state, _ = _canonical_object(
        successor_path / "enrichment-state-attestation.json"
    )
    request, _ = _canonical_object(
        successor_path / "enrichment-authorization-request.json"
    )
    _, _, predecessor_manifest = _load_verified_ancestry(
        predecessor_root=Path(predecessor_round_root).expanduser().resolve(strict=True),
        predecessor_round_id=predecessor_round_id,
        order_path=Path(round_roots_manifest).expanduser().resolve(strict=True),
    )
    _verify_previous_round_ref(
        plan=plan,
        state=state,
        request=request,
        expected=_derive_previous_round_ref(predecessor_manifest),
    )
    verify_enrichment_bundle(
        successor_path / "enrichment-plan.json",
        successor_path / "enrichment-state-attestation.json",
        successor_path / "enrichment-authorization-request.json",
        round_root=successor_path,
        round_id=successor_path.name,
    )
    pool, pool_raw = _canonical_object(
        successor_path / "remediation-candidate-pool.json"
    )
    actual_artifacts = {
        name: _sha256(
            pool_raw
            if name == "remediation-candidate-pool.json"
            else _read_regular(successor_path / name)
        )
        for name in sorted(_SUCCESSOR_FILE_NAMES)
    }
    if actual_artifacts != report.corrected_successor_artifact_sha256:
        raise ValueError("superseding successor artifact hashes drifted")
    issuance = GrammarSuccessorIssuance(
        issued_at=datetime.fromisoformat(str(state["issued_at"])),
        expires_at=datetime.fromisoformat(str(state["expires_at"])),
        nonce=str(request["nonce"]),
        reviewer_id=str(request["reviewer_id"]),
        code_sha256=str(state["code_sha256"]),
        config_sha256=str(state["config_sha256"]),
    )
    rebuilt = _build_grammar_correction_supersession(
        predecessor_round_root=predecessor_round_root,
        predecessor_round_id=predecessor_round_id,
        round_roots_manifest=round_roots_manifest,
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        rounds_root=successor_path.parent,
        issuance=issuance,
        _ignore_supersession_report_sha256=report.report_sha256,
    )
    expected = {
        _SUPERSESSION_REPORT_NAME: canonical_json_bytes(
            rebuilt.supersession_report.model_dump(mode="json")
        ),
        "remediation-candidate-pool.json": canonical_json_bytes(
            rebuilt.remediation_pool
        ),
        **rebuilt.bundle.files,
    }
    actual = {
        _SUPERSESSION_REPORT_NAME: report_raw,
        "remediation-candidate-pool.json": pool_raw,
        **{
            name: _read_regular(successor_path / name)
            for name in rebuilt.bundle.files
        },
    }
    if (
        expected != actual
        or rebuilt.bundle.round_id != successor_path.name
        or pool != rebuilt.remediation_pool
        or source.correction_report != rebuilt.correction_report
    ):
        raise ValueError("published grammar supersession differs from replay")
    payload = b"".join(actual.values())
    if b"serviceKey" in payload or b"itda-auth-v2:" in payload:
        raise ValueError("published grammar supersession contains secret-bearing material")


def verify_published_grammar_correction_successor(
    *,
    predecessor_round_root: Path | str,
    predecessor_round_id: str,
    round_roots_manifest: Path | str,
    correction_root: Path | str,
    successor_root: Path | str,
) -> None:
    """Rebuild a published successor from its frozen authority inputs and compare bytes."""

    correction_path = Path(correction_root).expanduser().resolve(strict=True)
    successor_path = Path(successor_root).expanduser().resolve(strict=True)
    if {path.name for path in correction_path.iterdir()} != {_CORRECTION_REPORT_NAME}:
        raise ValueError("correction root has undeclared artifacts")
    if {path.name for path in successor_path.iterdir()} != _SUCCESSOR_FILE_NAMES:
        raise ValueError("successor root has undeclared artifacts")
    report_value, report_raw = _canonical_object(
        correction_path / _CORRECTION_REPORT_NAME
    )
    rows_value = report_value.get("rows")
    if not isinstance(rows_value, list):
        raise ValueError("correction report rows must be a JSON array")
    report = GrammarCorrectionReport.model_validate(
        {**report_value, "rows": tuple(rows_value)}
    )
    if correction_path.name != report.report_sha256 or _sha256(
        canonical_json_bytes(
            report.model_dump(exclude={"report_sha256"}, mode="json")
        )
    ) != report.report_sha256:
        raise ValueError("correction report root or digest drifted")
    plan, _ = _canonical_object(successor_path / "enrichment-plan.json")
    state, _ = _canonical_object(
        successor_path / "enrichment-state-attestation.json"
    )
    request, _ = _canonical_object(
        successor_path / "enrichment-authorization-request.json"
    )
    _, _, predecessor_manifest = _load_verified_ancestry(
        predecessor_root=Path(predecessor_round_root).expanduser().resolve(strict=True),
        predecessor_round_id=predecessor_round_id,
        order_path=Path(round_roots_manifest).expanduser().resolve(strict=True),
    )
    _verify_previous_round_ref(
        plan=plan,
        state=state,
        request=request,
        expected=_derive_previous_round_ref(predecessor_manifest),
    )
    verify_enrichment_bundle(
        successor_path / "enrichment-plan.json",
        successor_path / "enrichment-state-attestation.json",
        successor_path / "enrichment-authorization-request.json",
        round_root=successor_path,
        round_id=successor_path.name,
    )
    pool, pool_raw = _canonical_object(
        successor_path / "remediation-candidate-pool.json"
    )
    issuance = GrammarSuccessorIssuance(
        issued_at=datetime.fromisoformat(str(state["issued_at"])),
        expires_at=datetime.fromisoformat(str(state["expires_at"])),
        nonce=str(request["nonce"]),
        reviewer_id=str(request["reviewer_id"]),
        code_sha256=str(state["code_sha256"]),
        config_sha256=str(state["config_sha256"]),
    )
    rebuilt = _build_grammar_correction_successor(
        predecessor_round_root=predecessor_round_root,
        predecessor_round_id=predecessor_round_id,
        round_roots_manifest=round_roots_manifest,
        rounds_root=successor_path.parent,
        issuance=issuance,
        existing_correction_pairs=frozenset(),
        _ignore_report_sha256=report.report_sha256,
    )
    expected = {
        _CORRECTION_REPORT_NAME: canonical_json_bytes(
            rebuilt.correction_report.model_dump(mode="json")
        ),
        "remediation-candidate-pool.json": canonical_json_bytes(
            rebuilt.remediation_pool
        ),
        **rebuilt.bundle.files,
    }
    actual = {
        _CORRECTION_REPORT_NAME: report_raw,
        "remediation-candidate-pool.json": pool_raw,
        **{
            name: _read_regular(successor_path / name)
            for name in rebuilt.bundle.files
        },
    }
    if expected != actual or rebuilt.bundle.round_id != successor_path.name:
        raise ValueError("published grammar successor differs from deterministic replay")
    if pool != rebuilt.remediation_pool:
        raise ValueError("published remediation pool differs from deterministic replay")
    payload = b"".join(actual.values())
    for prohibited in (
        b"serviceKey",
        b"itda-auth-v2:",
    ):
        if prohibited in payload:
            raise ValueError("published grammar successor contains secret-bearing material")


def classify_typed_intro_recovery(
    predecessor: Mapping[str, object],
) -> dict[str, str]:
    """Fail closed after an exact typed-Intro success-empty predecessor."""
    expected_fields = {
        "operation": "detailIntro2",
        "provider_result_code": "0000",
        "provider_result_value": "OK",
        "deficit_reason": "SUCCESS_RESPONSE_FIELD_EMPTY",
    }
    for field, expected in expected_fields.items():
        if predecessor.get(field) != expected:
            raise ValueError(
                "typed Intro recovery requires an exact success-empty predecessor"
            )
    requested_type = predecessor.get("requested_content_type_id")
    actual_type = predecessor.get("actual_content_type_id")
    if (
        not isinstance(requested_type, str)
        or not requested_type.isdigit()
        or not isinstance(actual_type, str)
        or not actual_type.isdigit()
        or requested_type == actual_type
    ):
        raise ValueError(
            "typed Intro recovery requires distinct numeric requested and actual types"
        )
    return {
        "reinforcement_18_eligibility": "INELIGIBLE",
        "semantic_successor_eligibility": "INELIGIBLE",
        "permitted_resolution": "EXACT_KTO_TARGET_SUBSTITUTION_OR_STOP",
    }
