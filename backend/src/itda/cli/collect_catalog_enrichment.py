"""Authority-gated, round-explicit TourAPI enrichment collection.

The module is intentionally usable with an injected requester so hostile tests can
exercise the complete collection path without contacting a provider.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TypedDict, cast

import httpx

from itda.contracts.authority import (
    AuthorityIssuanceContext,
    AuthorityReplayError,
    AuthorityTokenV2,
    FileNonceLedger,
    ValidatedAuthority,
    validate_authority_token,
)
from itda.contracts.catalog_enrichment import (
    APPROVED_OPERATIONS,
    KOR_SERVICE2_BASE_URL,
    KOR_SERVICE2_PARAMETER_ALLOWLISTS,
    KTO_COLLECTION_ATTEMPT_POLICY,
    KTO_COLLECTION_RESPONSE_POLICY,
    OPERATION_FIELD_MAP,
    build_kto_collection_authority_parents,
    canonical_json_bytes,
    verify_enrichment_bundle,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$", flags=re.ASCII)
_REVIEWER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", flags=re.ASCII)
_SAFE_HEADERS = frozenset(
    {"content-type", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"}
)
_SECRET_FIELD_FRAGMENTS = ("servicekey", "service_key", "apikey", "api_key", "token")
_BASE_URL = "https://apis.data.go.kr/B551011/KorService2"
_RECEIPT_NAME = "enrichment-authorization-receipt.json"
_REPORT_NAME = "enrichment-collection-report.json"
_LOG_NAME = "enrichment-collection-log.jsonl"
_RAW_DIRECTORY = "raw"
_RECEIPT_SCHEMA = "itda.catalog-enrichment-authorization-receipt.v1"
_REPORT_SCHEMA = "itda.catalog-enrichment-collection-report-record.v1"
_LOG_SCHEMA = "itda.catalog-enrichment-collection-log.v1"
_KTO_SUMMARY_REL = (
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-47-SUMMARY.md"
)
_KTO_ELIGIBILITY_BASE_REL = "artifacts/restricted/catalog/v2/supplemental/kto-recovery/eligibility"
KTO_COLLECTIONS_BASE = Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/collections")
_KTO_PREFLIGHT_SCHEMA = "itda.kto-recovery-collection-preflight.v1"
_KTO_ATTEMPT_SCHEMA = "itda.kto-recovery-attempt.v1"
_KTO_TERMINAL_SCHEMA = "itda.kto-recovery-terminal.v1"
_KTO_AUTHORITY_RECEIPT_SCHEMA = "itda.kto-recovery-authority-receipt.v1"
_KTO_ATTEMPT_LOG = "attempt-ledger.jsonl"
_KTO_TERMINAL_LOG = "terminal-ledger.jsonl"
_KTO_AUTHORITY_RECEIPT_LOG = "authority-receipt.jsonl"
_KTO_PREFLIGHT_FILE = "preflight.json"
_KTO_RAW_DIRECTORY = "raw"
_KTO_RAW_MANIFEST_FILE = "raw-manifest.json"
_KTO_COLLECTION_MANIFEST_FILE = "collection-manifest.json"
_KTO_RAW_MANIFEST_SCHEMA = "itda.kto-recovery-raw-manifest.v1"
_KTO_COLLECTION_MANIFEST_SCHEMA = "itda.kto-recovery-collection-manifest.v1"
_KTO_MAX_BODY_BYTES = 8 * 1024 * 1024
_KTO_MAX_JSON_DEPTH = 32
_KTO_MAX_ITEMS = 100
_KTO_TRANSIENT_PROVIDER_CODES = frozenset({"01", "02", "04", "05", "22"})
_KTO_TRANSIENT_TRANSPORT_REASONS = frozenset({"timeout", "connection-reset"})
_KTO_SUMMARY_FIELDS = (
    "kto_contract_sha256",
    "kto_allowlist_revision_sha256",
    "decision_receipt_sha256",
    "kto_eligibility_root",
    "typed_intro_policy_sha256",
    "kto_request_manifest_sha256",
    "request_count",
    "unresolved_intro_target_root",
)


class ResponseLike(Protocol):
    status_code: int
    content: bytes
    headers: Mapping[str, str]


class Requester(Protocol):
    def get(self, url: str, **kwargs: Any) -> ResponseLike: ...


class KtoStreamResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def iter_bytes(self) -> Iterator[bytes]: ...


class KtoStreamRequester(Protocol):
    def stream(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> contextlib.AbstractContextManager[KtoStreamResponse]: ...


class KtoInspectedResponse(TypedDict):
    raw_body: bytes
    raw_body_size: int
    raw_body_sha256: str
    provider_result_code: str
    provider_result_value: str
    item_count: int
    json_depth: int


@dataclass(frozen=True)
class SelectedRound:
    root: Path
    round_id: str
    plan: dict[str, Any]
    state: dict[str, Any]
    request: dict[str, Any]
    ancestry_depth: int


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _require_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return value


def discover_exact_kto_eligibility_success(
    repository_root: Path,
    eligibility_base: Path,
) -> Path:
    """Lazily invoke Plan 47 discovery to avoid its legacy contract import cycle."""

    from itda.cli.plan_catalog_kto_recovery import (
        discover_exact_kto_eligibility_success as discover,
    )

    return discover(repository_root, eligibility_base)


def _reject_lexical_traversal(path: Path, *, field: str) -> None:
    if ".." in path.parts:
        raise ValueError(f"{field} must not contain path traversal")


def _regular_file_bytes(path: Path, *, maximum: int = 64 * 1024 * 1024) -> bytes:
    """Read one stable regular single-link file without following a symlink."""

    _reject_lexical_traversal(path, field=path.name or "file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    for _attempt in range(3):
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ValueError(f"{path.name} must be an existing regular non-symlink file") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
                raise ValueError(f"{path.name} must be a bounded regular single-link file")
            chunks: list[bytes] = []
            size = 0
            while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - size)):
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise ValueError(f"{path.name} exceeds the maximum safe size")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            return b"".join(chunks)
    raise ValueError(f"{path.name} changed while it was being read")


def _canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    payload = _regular_file_bytes(path)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} must contain canonical JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ValueError(f"{path.name} must contain one canonical JSON object")
    return value, payload


def _canonical_lines(path: Path) -> tuple[dict[str, Any], ...]:
    payload = _regular_file_bytes(path)
    if not payload or not payload.endswith(b"\n"):
        raise ValueError(f"{path.name} must contain newline-terminated canonical records")
    records: list[dict[str, Any]] = []
    for line in payload.splitlines():
        if not line:
            raise ValueError(f"{path.name} contains a blank record")
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path.name} contains invalid JSON") from exc
        if not isinstance(record, dict) or canonical_json_bytes(record) != line:
            raise ValueError(f"{path.name} contains a noncanonical record")
        records.append(record)
    return tuple(records)


def _summary_kto_fields(repository_root: Path) -> tuple[dict[str, object], str]:
    summary_path = repository_root / _KTO_SUMMARY_REL
    payload = _regular_file_bytes(summary_path, maximum=2 * 1024 * 1024)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Plan 47 Summary must be canonical UTF-8 text") from exc
    result: dict[str, object] = {}
    for field in _KTO_SUMMARY_FIELDS:
        matches = re.findall(
            rf"^{re.escape(field)}:\s*([^\s]+)\s*$",
            text,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            raise ValueError(f"Plan 47 Summary field is missing or ambiguous: {field}")
        value: object = matches[0]
        if field == "request_count":
            try:
                value = int(str(value))
            except ValueError as exc:
                raise ValueError("Plan 47 request_count is not an integer") from exc
        result[field] = value
    return result, _sha256(payload)


def _kto_collections_base(repository_root: Path) -> Path:
    configured = Path(KTO_COLLECTIONS_BASE).expanduser()
    candidate = configured if configured.is_absolute() else repository_root / configured
    return candidate.resolve(strict=False)


def _completed_nonce_inventory_sha256(collections_base: Path) -> str:
    """Digest prior safe consumption rows without exposing a nonce or token."""

    ledger = collections_base / "authority-consumption-ledger.jsonl"
    if not collections_base.exists():
        return _sha256(canonical_json_bytes([]))
    metadata = collections_base.lstat()
    if collections_base.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("KTO collections base must be a no-follow directory")
    if not ledger.exists():
        return _sha256(canonical_json_bytes([]))
    rows = _canonical_lines(ledger)
    inventory: list[dict[str, str]] = []
    for row in rows:
        binding_sha256 = _require_sha256(
            row.get("binding_sha256"),
            field="completed binding",
        )
        nonce_sha256 = _require_sha256(
            row.get("nonce_sha256"),
            field="completed nonce",
        )
        receipt_sha256 = _require_sha256(
            row.get("receipt_sha256"),
            field="completed receipt",
        )
        inventory.append(
            {
                "binding_sha256": binding_sha256,
                "nonce_sha256": nonce_sha256,
                "receipt_sha256": receipt_sha256,
            }
        )
    return _sha256(canonical_json_bytes(inventory))


def _kto_collection_root_seed(preflight: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": "itda.kto-recovery-collection-root.v1",
        "kto_eligibility_root": preflight["kto_eligibility_root"],
        "kto_request_manifest_sha256": preflight["kto_request_manifest_sha256"],
        "kto_allowlist_revision_sha256": preflight["kto_allowlist_revision_sha256"],
        "request_count": preflight["request_count"],
        "base_url": preflight["base_url"],
        "attempt_policy": preflight["attempt_policy"],
        "response_policy": preflight["response_policy"],
    }


def _validate_kto_manifest(
    manifest: Mapping[str, object],
    *,
    summary: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    if manifest.get("schema_version") != "itda.kto-recovery-request-manifest.v1":
        raise ValueError("KTO request manifest schema drifted")
    if manifest.get("base_url") != KOR_SERVICE2_BASE_URL:
        raise ValueError("KTO request manifest host drifted")
    if manifest.get("kto_contract_sha256") != summary["kto_contract_sha256"]:
        raise ValueError("KTO contract pin drifted from Plan 47")
    if manifest.get("kto_allowlist_revision_sha256") != summary["kto_allowlist_revision_sha256"]:
        raise ValueError("KTO allowlist revision drifted from Plan 47")
    if manifest.get("decision_receipt_sha256") != summary["decision_receipt_sha256"]:
        raise ValueError("KTO policy receipt drifted from Plan 47")
    if manifest.get("attempt_policy") != KTO_COLLECTION_ATTEMPT_POLICY:
        raise ValueError("KTO attempt policy drifted")
    requests = manifest.get("requests")
    if not isinstance(requests, list) or len(requests) != manifest.get("request_count"):
        raise ValueError("KTO request inventory count drifted")
    if len(requests) != summary["request_count"]:
        raise ValueError("KTO request count drifted from Plan 47")
    identities: list[str] = []
    validated: list[Mapping[str, object]] = []
    for row in requests:
        if not isinstance(row, Mapping):
            raise ValueError("KTO request row must be an object")
        operation = row.get("operation")
        if operation not in {"detailCommon2", "detailImage2"}:
            raise ValueError("KTO packet contains an operation outside exact Common/Image")
        if row.get("base_url") != KOR_SERVICE2_BASE_URL:
            raise ValueError("KTO request row host drifted")
        parameters = row.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ValueError("KTO request parameters must be an object")
        expected_keys = KOR_SERVICE2_PARAMETER_ALLOWLISTS[str(operation)] - {"serviceKey"}
        if set(parameters) != expected_keys:
            raise ValueError("KTO request parameters drifted from the official allowlist")
        declared = parameters.get("numOfRows")
        if (
            not isinstance(declared, str)
            or not declared.isdigit()
            or not 1 <= int(declared) <= _KTO_MAX_ITEMS
        ):
            raise ValueError("KTO request declares an unsafe numOfRows")
        identity = _require_sha256(row.get("request_identity"), field="request identity")
        identities.append(identity)
        validated.append(row)
    if len(set(identities)) != len(identities):
        raise ValueError("KTO request packet contains duplicate identities")
    return tuple(validated)


def build_kto_collection_preflight(
    repository_root: Path | str,
    *,
    issued_at: datetime,
    deadline: datetime,
    reviewer_id: str,
) -> dict[str, object]:
    """Rederive the exact Plan 47 packet without credentials, sockets, or writes."""

    root = Path(repository_root).resolve(strict=True)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("KTO authority issued_at must be timezone-aware")
    if deadline.tzinfo is None or deadline.utcoffset() is None:
        raise ValueError("KTO authority deadline must be timezone-aware")
    if deadline <= issued_at:
        raise ValueError("KTO authority deadline must follow issued_at")
    if _REVIEWER.fullmatch(reviewer_id) is None:
        raise ValueError("KTO reviewer ID is not canonical")

    summary, summary_sha256 = _summary_kto_fields(root)
    eligibility_base = (root / _KTO_ELIGIBILITY_BASE_REL).resolve(strict=True)
    eligibility_root = discover_exact_kto_eligibility_success(root, eligibility_base)
    if eligibility_root.name != summary["kto_eligibility_root"]:
        raise ValueError("Plan 47 Summary and exact eligibility root drifted")
    request_manifest_path = eligibility_root / "request-manifest.json"
    manifest, manifest_bytes = _canonical_object(request_manifest_path)
    manifest_sha256 = _sha256(manifest_bytes)
    if not hmac.compare_digest(
        manifest_sha256,
        str(summary["kto_request_manifest_sha256"]),
    ):
        raise ValueError("Plan 47 request manifest digest drifted")
    _validate_kto_manifest(manifest, summary=summary)
    eligibility, _ = _canonical_object(eligibility_root / "eligibility.json")
    if (
        eligibility.get("plan48_reachable") is not True
        or eligibility.get("status") != "SUCCESS"
        or eligibility.get("request_count") != summary["request_count"]
        or eligibility.get("typed_intro_policy_sha256") != summary["typed_intro_policy_sha256"]
        or eligibility.get("unresolved_intro_target_root")
        != summary["unresolved_intro_target_root"]
    ):
        raise ValueError("KTO eligibility policy or request count drifted")

    collections_base = _kto_collections_base(root)
    preflight: dict[str, object] = {
        "schema_version": _KTO_PREFLIGHT_SCHEMA,
        "status": "AWAITING_SEPARATE_AUTHORITY",
        "summary_sha256": summary_sha256,
        "decision_receipt_sha256": summary["decision_receipt_sha256"],
        "kto_eligibility_root": eligibility_root.name,
        "kto_request_manifest_sha256": manifest_sha256,
        "kto_contract_sha256": summary["kto_contract_sha256"],
        "kto_allowlist_revision_sha256": summary["kto_allowlist_revision_sha256"],
        "typed_intro_policy_sha256": summary["typed_intro_policy_sha256"],
        "unresolved_intro_target_root": summary["unresolved_intro_target_root"],
        "request_count": summary["request_count"],
        "base_url": KOR_SERVICE2_BASE_URL,
        "attempt_policy": dict(KTO_COLLECTION_ATTEMPT_POLICY),
        "response_policy": dict(KTO_COLLECTION_RESPONSE_POLICY),
        "reviewer_id": reviewer_id,
        "reviewer_id_grammar": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "issued_at": issued_at.astimezone(UTC).isoformat(),
        "deadline": deadline.astimezone(UTC).isoformat(),
        "completed_nonce_inventory_sha256": _completed_nonce_inventory_sha256(collections_base),
    }
    collection_root_sha256 = _sha256(canonical_json_bytes(_kto_collection_root_seed(preflight)))
    preflight["collection_root_sha256"] = collection_root_sha256
    preflight["output_root"] = (collections_base / collection_root_sha256).as_posix()
    parents = build_kto_collection_authority_parents(preflight, nonce="0" * 64)
    preflight["request_sha256"] = parents["request_sha256"]
    preflight["state_attestation_sha256"] = parents["state_attestation_sha256"]
    preflight["target_sha256"] = parents["target_sha256"]
    return preflight


def _validate_kto_preflight(preflight: Mapping[str, object]) -> None:
    if preflight.get("schema_version") != _KTO_PREFLIGHT_SCHEMA:
        raise ValueError("KTO collection preflight schema is stale")
    expected_root = _sha256(canonical_json_bytes(_kto_collection_root_seed(preflight)))
    if not hmac.compare_digest(
        str(preflight.get("collection_root_sha256", "")),
        expected_root,
    ):
        raise ValueError("KTO collection root is stale or caller-patched")
    output_root = Path(str(preflight.get("output_root", "")))
    if output_root.name != expected_root:
        raise ValueError("KTO output root is stale or caller-selected")
    parents = build_kto_collection_authority_parents(preflight, nonce="0" * 64)
    expected_digests = {
        "request_sha256": parents["request_sha256"],
        "state_attestation_sha256": parents["state_attestation_sha256"],
        "target_sha256": parents["target_sha256"],
    }
    if any(preflight.get(key) != value for key, value in expected_digests.items()):
        raise ValueError("KTO authority parent digest is stale or caller-patched")


def derive_kto_authority_context(
    preflight: Mapping[str, object],
    *,
    nonce: str,
) -> AuthorityIssuanceContext:
    """Derive expected fields for a separate issuer without creating a token."""

    _validate_kto_preflight(preflight)
    parents = build_kto_collection_authority_parents(preflight, nonce=nonce)
    return AuthorityIssuanceContext(
        action="enrichment-collect",
        request_sha256=str(parents["request_sha256"]),
        state_attestation_sha256=str(parents["state_attestation_sha256"]),
        target_sha256=str(parents["target_sha256"]),
        reviewer_id=str(preflight["reviewer_id"]),
        binding_sha256=str(parents["binding_sha256"]),
        nonce=nonce,
        issued_at=datetime.fromisoformat(str(preflight["issued_at"])),
        expires_at=datetime.fromisoformat(str(preflight["deadline"])),
        reviewer_channel_risk=(
            "reviewer_id is separately supplied local-channel metadata, "
            "not a cryptographic identity claim"
        ),
    )


def validate_kto_collection_authority(
    preflight: Mapping[str, object],
    *,
    raw_token: str,
    now: datetime,
) -> ValidatedAuthority:
    """Validate an externally supplied strict authority against live preflight."""

    _validate_kto_preflight(preflight)
    token = AuthorityTokenV2.parse(raw_token)
    if token.reviewer_id != preflight.get("reviewer_id"):
        raise ValueError("KTO authority reviewer is stale")
    context = derive_kto_authority_context(preflight, nonce=token.nonce)
    parents = build_kto_collection_authority_parents(preflight, nonce=token.nonce)
    try:
        return validate_authority_token(
            raw_token,
            issuance_context=context,
            request=parents["request"],
            state_attestation=parents["state_attestation"],
            target=parents["target"],
            binding=parents["binding"],
            reviewer_id=str(preflight["reviewer_id"]),
            now=now,
            revocation_tombstones=(),
        )
    except ValueError as exc:
        raise ValueError("KTO authority is stale, replayed, or preflight-mismatched") from exc


def _round_root(round_root: Path | str, round_id: str) -> Path:
    supplied = Path(round_root).expanduser()
    _reject_lexical_traversal(supplied, field="round root")
    _require_sha256(round_id, field="round_id")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError("round root must exist") from exc
    metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("round root must be a regular non-symlink directory")
    if root.name != round_id:
        raise ValueError("round root basename must equal the supplied round ID")
    if root.parent.name != "rounds":
        raise ValueError("round root must be an explicit child of a rounds directory")
    return root


def _round_value(root: Path) -> str:
    parts = root.parts
    try:
        index = parts.index("artifacts")
    except ValueError:
        return root.as_posix()
    return Path(*parts[index:]).as_posix()


def _exact_path(root: Path, supplied: Path | str, expected_name: str) -> Path:
    path = Path(supplied).expanduser()
    _reject_lexical_traversal(path, field=expected_name)
    resolved = path.resolve(strict=True)
    expected = root / expected_name
    if resolved != expected:
        raise ValueError(f"{expected_name} is outside the exact selected round")
    return resolved


def _verify_initial_reference(root: Path, round_id: str) -> int:
    reference_path = root.parent.parent / "initial-round-ref.json"
    reference, reference_bytes = _canonical_object(reference_path)
    unsigned = {
        "round_id": round_id,
        "round_root": _round_value(root),
        "plan_sha256": round_id,
    }
    expected = {
        **unsigned,
        "reference_sha256": _sha256(canonical_json_bytes(unsigned)),
    }
    if reference != expected:
        raise ValueError("initial round reference does not match the selected round")
    if _sha256(reference_bytes) == round_id:
        raise ValueError("initial reference must not alias the request plan")
    return 1


def _verify_remediation_ancestry(
    root: Path,
    plan: Mapping[str, Any],
    state: Mapping[str, Any],
    request: Mapping[str, Any],
) -> int:
    remediation = plan.get("remediation")
    if not isinstance(remediation, Mapping):
        raise ValueError("remediation plan lacks a closed ancestry record")
    previous = remediation.get("previous_round_ref")
    if not isinstance(previous, Mapping) or set(previous) != {
        "round_id",
        "round_root",
        "round_manifest_sha256",
        "ancestry_depth",
    }:
        raise ValueError("remediation previous-round ancestry is incomplete")
    previous_id = _require_sha256(previous["round_id"], field="previous round ID")
    previous_root_value = previous["round_root"]
    if not isinstance(previous_root_value, str):
        raise ValueError("previous round root must be text")
    previous_root_path = Path(previous_root_value)
    _reject_lexical_traversal(previous_root_path, field="previous round root")
    if previous_root_path.is_absolute():
        previous_root = previous_root_path.resolve(strict=True)
    else:
        repository_root = root
        while repository_root.parent != repository_root and not (repository_root / ".git").exists():
            repository_root = repository_root.parent
        previous_root = (repository_root / previous_root_path).resolve(strict=True)
    if previous_root.name != previous_id or previous_root.parent != root.parent:
        raise ValueError("previous round is outside the selected round chain")
    manifest = previous_root / "enrichment-round-manifest.json"
    manifest_bytes = _regular_file_bytes(manifest)
    expected_manifest = _require_sha256(
        previous["round_manifest_sha256"], field="previous round manifest"
    )
    if not hmac.compare_digest(_sha256(manifest_bytes), expected_manifest):
        raise ValueError("previous round manifest digest is stale")
    previous_ref_sha256 = _sha256(canonical_json_bytes(dict(previous)))
    if not hmac.compare_digest(
        str(state.get("previous_round_ref_sha256", "")), previous_ref_sha256
    ) or not hmac.compare_digest(
        str(request.get("previous_round_ref_sha256", "")), previous_ref_sha256
    ):
        raise ValueError("previous round ancestry digest is broken")
    depth = previous.get("ancestry_depth")
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1:
        raise ValueError("previous round ancestry depth is invalid")
    return depth + 1


def _load_selected_round(round_root: Path | str, round_id: str) -> SelectedRound:
    root = _round_root(round_root, round_id)
    plan_path = root / "enrichment-plan.json"
    state_path = root / "enrichment-state-attestation.json"
    request_path = root / "enrichment-authorization-request.json"
    plan, plan_bytes = _canonical_object(plan_path)
    state, _ = _canonical_object(state_path)
    request, _ = _canonical_object(request_path)
    if not hmac.compare_digest(_sha256(plan_bytes), round_id):
        raise ValueError("round ID does not match the selected request plan")
    verify_enrichment_bundle(
        plan_path,
        state_path,
        request_path,
        round_root=root,
        round_id=round_id,
    )
    if state.get("previous_round_ref_sha256") is None:
        if request.get("previous_round_ref_sha256") is not None:
            raise ValueError("initial round ancestry differs between state and request")
        ancestry_depth = _verify_initial_reference(root, round_id)
    else:
        ancestry_depth = _verify_remediation_ancestry(root, plan, state, request)
    if plan.get("per_attempt_timeout_seconds") != 300:
        raise ValueError("every request attempt must allow exactly 300 seconds")
    request_count = plan.get("request_count")
    attempts = plan.get("attempts_per_request")
    if (
        not isinstance(request_count, int)
        or isinstance(request_count, bool)
        or not isinstance(attempts, int)
        or isinstance(attempts, bool)
        or plan.get("overall_timeout_seconds") != request_count * attempts * 300
    ):
        raise ValueError("overall diagnostics budget is not derived from the exact plan")
    requests = plan.get("requests")
    if not isinstance(requests, list):
        raise ValueError("selected request plan lacks an ordered request inventory")
    for planned in requests:
        if not isinstance(planned, Mapping):
            raise ValueError("planned request must be an object")
        operation = planned.get("operation")
        if operation not in APPROVED_OPERATIONS:
            raise ValueError("selected round contains an unplanned operation")
        if planned.get("mapped_mandatory_fields") != list(OPERATION_FIELD_MAP[str(operation)]):
            raise ValueError("selected round operation does not own its mandatory fields")
        parameters = planned.get("parameters")
        if not isinstance(parameters, Mapping) or any(
            fragment in str(key).casefold()
            for key in parameters
            for fragment in _SECRET_FIELD_FRAGMENTS
        ):
            raise ValueError("selected round parameters are not secret-safe")
    return SelectedRound(
        root=root,
        round_id=round_id,
        plan=plan,
        state=state,
        request=request,
        ancestry_depth=ancestry_depth,
    )


def _binding(selected: SelectedRound) -> dict[str, object]:
    request = selected.request
    return {
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


def _issuance_context(selected: SelectedRound) -> AuthorityIssuanceContext:
    request = selected.request
    risk = request.get("reviewer_authentication")
    if not isinstance(risk, Mapping) or not isinstance(risk.get("accepted_risk"), str):
        raise ValueError("authorization request lacks reviewer-channel risk metadata")
    return AuthorityIssuanceContext(
        action="enrichment-collect",
        request_sha256=_require_sha256(request["request_sha256"], field="request"),
        state_attestation_sha256=_require_sha256(
            request["state_attestation_sha256"], field="state"
        ),
        target_sha256=_require_sha256(request["target_sha256"], field="target"),
        reviewer_id=str(request["reviewer_id"]),
        binding_sha256=_require_sha256(request["binding_sha256"], field="binding"),
        nonce=_require_sha256(request["nonce"], field="nonce"),
        issued_at=datetime.fromisoformat(str(request["issued_at"])),
        expires_at=datetime.fromisoformat(str(request["expires_at"])),
        reviewer_channel_risk=str(risk["accepted_risk"]),
    )


def verify_authorization_preconditions(
    request_path: Path | str,
    *,
    round_root: Path | str,
    round_id: str,
    now: datetime,
) -> dict[str, object]:
    """Read-only verification for the exact selected round and authority parents."""

    selected = _load_selected_round(round_root, round_id)
    _exact_path(selected.root, request_path, "enrichment-authorization-request.json")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("precondition verification time must be timezone-aware")
    context = _issuance_context(selected)
    if not context.issued_at <= now < context.expires_at:
        raise ValueError("authorization request is not currently valid")
    return {
        "ancestry_depth": selected.ancestry_depth,
        "attempts_per_request": selected.plan["attempts_per_request"],
        "overall_timeout_seconds": selected.plan["overall_timeout_seconds"],
        "per_attempt_timeout_seconds": selected.plan["per_attempt_timeout_seconds"],
        "quota_estimate": selected.plan["quota_estimate"],
        "request_count": selected.plan["request_count"],
        "round_id": round_id,
    }


def _read_credential(path: Path, variable_name: str) -> str:
    if variable_name != "TOUR_API_SERVICE_KEY":
        raise ValueError("credential variable is not allowlisted for TourAPI")
    payload = _regular_file_bytes(path, maximum=16_384)
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("credential file must be owned by the current user with mode 0600")
    values: dict[str, str] = {}
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("credential file must be UTF-8") from exc
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("credential file contains an invalid assignment")
        name, value = line.split("=", 1)
        if not name or not value or name in values:
            raise ValueError("credential file contains an invalid assignment")
        values[name] = value
    try:
        return values[variable_name]
    except KeyError as exc:
        raise ValueError("credential variable is absent") from exc


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("restricted output directory must be a non-symlink directory")
    path.chmod(0o700)


def _exclusive_private_file(path: Path, payload: bytes) -> None:
    _ensure_private_directory(path.parent)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if os.write(descriptor, payload) != len(payload):
            raise OSError("short write while publishing restricted evidence")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _append_canonical_record(path: Path, record: Mapping[str, object]) -> None:
    _ensure_private_directory(path.parent)
    payload = canonical_json_bytes(dict(record)) + b"\n"
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("append-only evidence must be a regular single-link file")
        if os.write(descriptor, payload) != len(payload):
            raise OSError("short write while appending restricted evidence")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _contains_secret(payload: bytes, secrets: Sequence[str]) -> bool:
    return any(secret and secret.encode("utf-8") in payload for secret in secrets)


def _safe_headers(headers: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        normalized = str(key).casefold()
        if normalized in _SAFE_HEADERS:
            result[normalized] = str(value)[:500]
    return dict(sorted(result.items()))


def _maximum_json_depth(value: object) -> int:
    maximum = 1
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        maximum = max(maximum, depth)
        if maximum > _KTO_MAX_JSON_DEPTH:
            return maximum
        if isinstance(current, Mapping):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return maximum


def read_kto_response_bounded(
    response: KtoStreamResponse,
    *,
    declared_num_of_rows: int,
) -> KtoInspectedResponse:
    """Bound untrusted bytes before JSON parsing and item projection."""

    if (
        not isinstance(declared_num_of_rows, int)
        or isinstance(declared_num_of_rows, bool)
        or not 1 <= declared_num_of_rows <= _KTO_MAX_ITEMS
    ):
        raise ValueError("declared numOfRows is outside the 1..100 response bound")
    content_length_value = next(
        (
            str(value)
            for key, value in response.headers.items()
            if str(key).casefold() == "content-length"
        ),
        None,
    )
    if content_length_value is not None:
        if not content_length_value.isdigit():
            raise ValueError("response Content-Length is invalid")
        if int(content_length_value) > _KTO_MAX_BODY_BYTES:
            raise ValueError("response exceeds the 8 MiB body limit before buffering")
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        if not isinstance(chunk, bytes):
            chunk = bytes(chunk)
        remaining = _KTO_MAX_BODY_BYTES + 1 - total
        if remaining <= 0:
            raise ValueError("response exceeds the 8 MiB body limit")
        bounded = chunk[:remaining]
        chunks.append(bounded)
        total += len(bounded)
        if total > _KTO_MAX_BODY_BYTES or len(chunk) > len(bounded):
            raise ValueError("response exceeds the 8 MiB body limit")
    body = b"".join(chunks)
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("provider response is not valid bounded JSON") from exc
    if _maximum_json_depth(parsed) > _KTO_MAX_JSON_DEPTH:
        raise ValueError("provider response exceeds maximum JSON depth 32")
    try:
        response_value = parsed["response"]
        header = response_value["header"]
    except (KeyError, TypeError) as exc:
        raise ValueError("provider response lacks the exact result envelope") from exc
    if not isinstance(header, Mapping):
        raise ValueError("provider response header must be an object")
    provider_code = str(header.get("resultCode", ""))
    provider_value = str(header.get("resultMsg", ""))[:200]
    body_value = response_value.get("body", {})
    if body_value is None:
        body_value = {}
    if not isinstance(body_value, Mapping):
        raise ValueError("provider response body must be an object")
    items_value = body_value.get("items")
    if items_value in (None, ""):
        item_value: object = []
    elif isinstance(items_value, Mapping):
        item_value = items_value.get("item", [])
    else:
        raise ValueError("provider response items must be an object or empty")
    if item_value in (None, ""):
        item_count = 0
    elif isinstance(item_value, list):
        item_count = len(item_value)
    elif isinstance(item_value, Mapping):
        item_count = 1
    else:
        raise ValueError("provider response item must be an object, list, or empty")
    if item_count > declared_num_of_rows or item_count > _KTO_MAX_ITEMS:
        raise ValueError("provider item count exceeds declared numOfRows or absolute maximum")
    return {
        "raw_body": body,
        "raw_body_size": len(body),
        "raw_body_sha256": _sha256(body),
        "provider_result_code": provider_code,
        "provider_result_value": provider_value,
        "item_count": item_count,
        "json_depth": _maximum_json_depth(parsed),
    }


def is_kto_retryable(
    *,
    http_status: int | None,
    provider_code: str | None,
    transport_reason: str | None,
) -> bool:
    """Return true only for the closed transient KTO outcome set."""

    if transport_reason is not None:
        return transport_reason in _KTO_TRANSIENT_TRANSPORT_REASONS
    if http_status in {408, 429}:
        return True
    if http_status is not None and 500 <= http_status <= 599:
        return True
    return http_status == 200 and provider_code in _KTO_TRANSIENT_PROVIDER_CODES


def _read_kto_credential(path: Path | str) -> str:
    supplied = Path(path).expanduser()
    _reject_lexical_traversal(supplied, field="credential path")
    payload = _regular_file_bytes(supplied, maximum=16_384)
    metadata = supplied.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(
            "credential file must be a regular single-link current-UID file with mode 0600"
        )
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("credential file must be UTF-8") from exc
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("credential file contains an invalid assignment")
        name, value = line.split("=", 1)
        if not name or not value or name in values:
            raise ValueError("credential file contains an invalid assignment")
        values[name] = value
    credential = values.get("TOUR_API_SERVICE_KEY")
    if not credential:
        raise ValueError("credential file lacks TOUR_API_SERVICE_KEY")
    return credential


def _provider_fields(body: bytes) -> tuple[str | None, str | None, str | None]:
    try:
        payload = json.loads(body)
        header = payload["response"]["header"]
        code = str(header["resultCode"])
        value = str(header.get("resultMsg", ""))[:200] or None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None, None, "provider response is not a valid result envelope"
    if code in {"00", "0000"}:
        return code, value, None
    return code, value, f"provider returned result code {code}"


def _retryable(http_status: int | None, provider_code: str | None, error: str | None) -> bool:
    if error == "transport-error":
        return True
    if http_status in {408, 429} or (http_status is not None and 500 <= http_status <= 599):
        return True
    if http_status == 200 and provider_code not in {None, "00", "0000", "03"}:
        return provider_code not in {"01", "02", "04", "05", "20", "21", "22", "30", "31", "32"}
    return False


def _latest_results(selected: SelectedRound) -> dict[str, dict[str, Any]]:
    report_path = selected.root / _REPORT_NAME
    if not report_path.exists():
        return {}
    latest: dict[str, dict[str, Any]] = {}
    for record in _canonical_lines(report_path):
        if record.get("schema_version") != _REPORT_SCHEMA:
            raise ValueError("collection report contains an unknown schema")
        identity = record.get("request_identity")
        if isinstance(identity, str):
            latest[identity] = record
    return latest


def _verified_successes(selected: SelectedRound) -> set[str]:
    successes: set[str] = set()
    for identity, record in _latest_results(selected).items():
        if record.get("terminal_status") != "SUCCESS":
            continue
        raw_path = record.get("raw_relative_path")
        raw_sha256 = record.get("raw_body_sha256")
        if not isinstance(raw_path, str) or not isinstance(raw_sha256, str):
            raise ValueError("successful report row lacks immutable raw evidence")
        candidate = Path(raw_path)
        _reject_lexical_traversal(candidate, field="raw evidence path")
        resolved = (selected.root / candidate).resolve(strict=True)
        if selected.root not in resolved.parents:
            raise ValueError("successful raw evidence escapes the selected round")
        if not hmac.compare_digest(_sha256(_regular_file_bytes(resolved)), raw_sha256):
            raise ValueError("successful raw evidence digest is stale")
        successes.add(identity)
    return successes


def _consume_authority(
    selected: SelectedRound,
    *,
    raw_token: str,
    now: datetime,
) -> tuple[str, str]:
    context = _issuance_context(selected)
    validated = validate_authority_token(
        raw_token,
        issuance_context=context,
        request=selected.plan,
        state_attestation=selected.state,
        target=selected.plan,
        binding=_binding(selected),
        reviewer_id=str(selected.request["reviewer_id"]),
        now=now,
        revocation_tombstones=(),
    )
    token_sha256 = validated.token_sha256
    invocation_id = _sha256(
        canonical_json_bytes(
            {
                "round_id": selected.round_id,
                "token_sha256": token_sha256,
                "nonce_sha256": _sha256(context.nonce.encode("ascii")),
            }
        )
    )
    receipt_path = selected.root / _RECEIPT_NAME
    lock_path = selected.root / ".enrichment-authority.lock"
    lock_descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if receipt_path.exists():
            for receipt in _canonical_lines(receipt_path):
                if hmac.compare_digest(
                    str(receipt.get("binding_sha256", "")), context.binding_sha256
                ) and hmac.compare_digest(
                    str(receipt.get("nonce_sha256", "")),
                    _sha256(context.nonce.encode("ascii")),
                ):
                    raise AuthorityReplayError("binding-global authority nonce already consumed")
        receipt = {
            "schema_version": _RECEIPT_SCHEMA,
            "action": context.action,
            "request_sha256": context.request_sha256,
            "state_attestation_sha256": context.state_attestation_sha256,
            "target_sha256": context.target_sha256,
            "reviewer_id": context.reviewer_id,
            "binding_sha256": context.binding_sha256,
            "nonce_sha256": _sha256(context.nonce.encode("ascii")),
            "token_sha256": token_sha256,
            "issuance_context_sha256": context.context_sha256,
            "invocation_id": invocation_id,
            "round_id": selected.round_id,
            "round_root": _round_value(selected.root),
            "ancestry_depth": selected.ancestry_depth,
            "reviewer_channel_risk": context.reviewer_channel_risk,
            "authority_consumed_at": now.astimezone(UTC).isoformat(),
            "completion": "AUTHORITY_CONSUMED_FOR_INVOCATION",
        }
        _append_canonical_record(receipt_path, receipt)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    return token_sha256, invocation_id


def _request_result(
    *,
    selected: SelectedRound,
    planned: Mapping[str, Any],
    credential: str,
    requester: Requester,
    token_sha256: str,
    invocation_id: str,
) -> dict[str, Any]:
    identity = str(planned["request_identity"])
    operation = str(planned["operation"])
    attempts_allowed = int(selected.plan["attempts_per_request"])
    attempts: list[dict[str, Any]] = []
    terminal_status = "RETRYABLE_FOR_RESUME"
    raw_relative_path: str | None = None
    raw_body_sha256 = hashlib.sha256(b"").hexdigest()
    normalized_reason: str | None = None
    provider_code: str | None = None
    provider_value: str | None = None
    http_status: int | None = None
    retention = "NO_BODY"
    for attempt_number in range(1, attempts_allowed + 1):
        started_at = datetime.now(UTC)
        started_ns = time.monotonic_ns()
        transport_error: str | None = None
        body = b""
        headers: dict[str, str] = {}
        try:
            response = requester.get(
                f"{_BASE_URL}/{operation}",
                params={**dict(planned["parameters"]), "serviceKey": credential},
                timeout=300,
                follow_redirects=False,
            )
            http_status = int(response.status_code)
            body = bytes(response.content)
            headers = _safe_headers(response.headers)
            provider_code, provider_value, envelope_failure = _provider_fields(body)
            if http_status != 200:
                normalized_reason = f"provider returned HTTP {http_status}"
            else:
                normalized_reason = envelope_failure
        except (httpx.RequestError, OSError) as exc:
            http_status = None
            provider_code = None
            provider_value = None
            transport_error = "transport-error"
            normalized_reason = f"bounded transport failure: {type(exc).__name__}"
        completed_at = datetime.now(UTC)
        elapsed_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
        raw_body_sha256 = _sha256(body)
        if body:
            raw_root = selected.root / _RAW_DIRECTORY
            _ensure_private_directory(raw_root)
            raw_directory = raw_root / identity
            file_name = f"{token_sha256[:16]}-attempt-{attempt_number:03d}.response"
            raw_path = raw_directory / file_name
            if _contains_secret(body, (credential,)):
                snapshot = canonical_json_bytes(
                    {
                        "redacted": True,
                        "reason": "provider-reflected-credential",
                        "retention": "REDACTED_SECRET_REFLECTION",
                        "raw_body_sha256": raw_body_sha256,
                    }
                )
                retention = "REDACTED_SECRET_REFLECTION"
                raw_relative_path = raw_path.relative_to(selected.root).as_posix()
                _exclusive_private_file(raw_path, snapshot)
            else:
                retention = "IMMUTABLE_ATTEMPT_SNAPSHOT"
                raw_relative_path = raw_path.relative_to(selected.root).as_posix()
                _exclusive_private_file(raw_path, body)
        retryable = _retryable(http_status, provider_code, transport_error)
        success = http_status == 200 and provider_code in {"00", "0000"}
        terminal = success or not retryable or attempt_number == attempts_allowed
        attempt_record = {
            "attempt_number": attempt_number,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "elapsed_ms": elapsed_ms,
            "timeout_seconds": 300,
            "http_status": http_status,
            "safe_headers": headers,
            "provider_result_code": provider_code,
            "provider_result_value": provider_value,
            "raw_body_sha256": raw_body_sha256,
            "raw_body_retention": retention,
            "raw_relative_path": raw_relative_path,
            "normalized_reason": normalized_reason,
            "retryable": retryable,
            "terminal": terminal,
        }
        attempts.append(attempt_record)
        _append_canonical_record(
            selected.root / _LOG_NAME,
            {
                "schema_version": _LOG_SCHEMA,
                "round_id": selected.round_id,
                "invocation_id": invocation_id,
                "request_identity": identity,
                "provider": planned["provider"],
                "operation": operation,
                **attempt_record,
            },
        )
        if success:
            terminal_status = "SUCCESS"
            normalized_reason = None
            break
        if not retryable:
            terminal_status = "TERMINAL_PROVIDER_FAILURE"
            break
        if attempt_number == attempts_allowed:
            terminal_status = "RETRYABLE_FOR_RESUME"
            normalized_reason = normalized_reason or "bounded attempts exhausted"
    return {
        "schema_version": _REPORT_SCHEMA,
        "round_id": selected.round_id,
        "round_root": _round_value(selected.root),
        "ancestry_depth": selected.ancestry_depth,
        "invocation_id": invocation_id,
        "token_sha256": token_sha256,
        "request_identity": identity,
        "provider": planned["provider"],
        "operation": operation,
        "mapped_mandatory_fields": planned["mapped_mandatory_fields"],
        "attempt_count": len(attempts),
        "attempts": attempts,
        "terminal_status": terminal_status,
        "http_status": http_status,
        "provider_result_code": provider_code,
        "provider_result_value": provider_value,
        "safe_headers": attempts[-1]["safe_headers"],
        "raw_body_sha256": raw_body_sha256,
        "raw_body_retention": retention,
        "raw_relative_path": raw_relative_path,
        "normalized_reason": normalized_reason,
        "per_attempt_timeout_seconds": 300,
        "attempts_per_request": attempts_allowed,
        "overall_timeout_seconds": selected.plan["overall_timeout_seconds"],
    }


def collect_authorized_round(
    *,
    round_root: Path | str,
    round_id: str,
    authorization_token: str,
    credential_path: Path | str,
    credential_variable: str,
    now: datetime | None = None,
    requester: Requester | None = None,
) -> dict[str, object]:
    """Consume exact authority once and collect only the selected round identities."""

    selected = _load_selected_round(round_root, round_id)
    credential_file = Path(credential_path).expanduser()
    _reject_lexical_traversal(credential_file, field="credential path")
    try:
        resolved_credential = credential_file.resolve(strict=True)
    except OSError as exc:
        raise ValueError("credential file is absent") from exc
    credential = _read_credential(resolved_credential, credential_variable)
    canonical_now = now or datetime.now(UTC)
    if canonical_now.tzinfo is None or canonical_now.utcoffset() is None:
        raise ValueError("collection time must be timezone-aware")
    token_sha256, invocation_id = _consume_authority(
        selected,
        raw_token=authorization_token,
        now=canonical_now,
    )
    completed = _verified_successes(selected)
    planned_requests = selected.plan["requests"]
    assert isinstance(planned_requests, list)
    pending = [
        planned
        for planned in planned_requests
        if isinstance(planned, Mapping) and str(planned["request_identity"]) not in completed
    ]
    owned_requester = requester is None
    client = cast(Requester, requester or httpx.Client(follow_redirects=False))
    results: list[dict[str, Any]] = []
    try:
        for planned in pending:
            result = _request_result(
                selected=selected,
                planned=planned,
                credential=credential,
                requester=client,
                token_sha256=token_sha256,
                invocation_id=invocation_id,
            )
            _append_canonical_record(selected.root / _REPORT_NAME, result)
            results.append(result)
    finally:
        if owned_requester and isinstance(client, httpx.Client):
            client.close()
    successful = sum(item["terminal_status"] == "SUCCESS" for item in results)
    return {
        "round_id": selected.round_id,
        "invocation_id": invocation_id,
        "attempted_request_count": len(results),
        "successful_request_count": successful,
        "resumable_request_count": sum(
            item["terminal_status"] == "RETRYABLE_FOR_RESUME" for item in results
        ),
        "provider_requests_sent": len(results),
        "authority_consumed": True,
    }


def _kto_terminal_rows(
    output_root: Path,
    *,
    planned_ids: set[str],
) -> dict[str, dict[str, Any]]:
    path = output_root / _KTO_TERMINAL_LOG
    if not path.exists():
        return {}
    terminal: dict[str, dict[str, Any]] = {}
    for row in _canonical_lines(path):
        if row.get("schema_version") != _KTO_TERMINAL_SCHEMA:
            raise ValueError("KTO terminal ledger schema drifted")
        identity = row.get("request_identity")
        if not isinstance(identity, str) or identity not in planned_ids:
            raise ValueError("KTO terminal ledger contains an unplanned identity")
        if identity in terminal:
            raise ValueError("KTO terminal ledger contains a duplicate identity")
        raw_relative_path = row.get("raw_relative_path")
        if isinstance(raw_relative_path, str):
            relative = Path(raw_relative_path)
            _reject_lexical_traversal(relative, field="KTO raw path")
            raw_path = (output_root / relative).resolve(strict=True)
            if output_root not in raw_path.parents:
                raise ValueError("KTO raw evidence escapes the collection root")
            publication_sha256 = _require_sha256(
                row.get("publication_sha256"),
                field="KTO raw publication",
            )
            if not hmac.compare_digest(
                _sha256(_regular_file_bytes(raw_path)),
                publication_sha256,
            ):
                raise ValueError("KTO raw evidence publication digest drifted")
        terminal[identity] = row
    return terminal


def _kto_attempt_counts(
    output_root: Path,
    *,
    planned_ids: set[str],
) -> dict[str, int]:
    path = output_root / _KTO_ATTEMPT_LOG
    if not path.exists():
        return {}
    counts: dict[str, int] = {}
    for row in _canonical_lines(path):
        if row.get("schema_version") != _KTO_ATTEMPT_SCHEMA:
            raise ValueError("KTO attempt ledger schema drifted")
        identity = row.get("request_identity")
        if not isinstance(identity, str) or identity not in planned_ids:
            raise ValueError("KTO attempt ledger contains an unplanned identity")
        ordinal = row.get("attempt_ordinal")
        if (
            not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal != counts.get(identity, 0) + 1
            or ordinal > 3
        ):
            raise ValueError("KTO attempt ledger violates the three-attempt ceiling")
        counts[identity] = ordinal
    return counts


def _kto_authority_receipt_record(
    preflight: Mapping[str, object],
    validated: ValidatedAuthority,
    *,
    consumed_at: datetime,
) -> dict[str, object]:
    context = validated.issuance_context
    if context.context_sha256 is None:
        raise ValueError("KTO authority context lacks its canonical digest")
    return {
        "schema_version": _KTO_AUTHORITY_RECEIPT_SCHEMA,
        "action": context.action,
        "request_sha256": context.request_sha256,
        "state_attestation_sha256": context.state_attestation_sha256,
        "target_sha256": context.target_sha256,
        "reviewer_id": context.reviewer_id,
        "binding_sha256": context.binding_sha256,
        "nonce_sha256": _sha256(context.nonce.encode("ascii")),
        "token_sha256": validated.token_sha256,
        "issuance_context_sha256": context.context_sha256,
        "collection_root_sha256": preflight["collection_root_sha256"],
        "kto_request_manifest_sha256": preflight["kto_request_manifest_sha256"],
        "request_count": preflight["request_count"],
        "deadline": preflight["deadline"],
        "consumed_at": consumed_at.astimezone(UTC).isoformat(),
    }


def _find_kto_authority_receipt(
    output_root: Path,
    validated: ValidatedAuthority,
) -> Mapping[str, object] | None:
    path = output_root / _KTO_AUTHORITY_RECEIPT_LOG
    if not path.exists():
        return None
    expected_nonce = _sha256(validated.issuance_context.nonce.encode("ascii"))
    for row in _canonical_lines(path):
        if (
            row.get("schema_version") == _KTO_AUTHORITY_RECEIPT_SCHEMA
            and row.get("binding_sha256") == validated.issuance_context.binding_sha256
            and row.get("nonce_sha256") == expected_nonce
        ):
            return {"result_sha256": output_root.name}
    return None


def _initialize_kto_collection_root(
    preflight: Mapping[str, object],
    validated: ValidatedAuthority,
    *,
    consumed_at: datetime,
) -> Mapping[str, object]:
    output_root = Path(str(preflight["output_root"]))
    _ensure_private_directory(output_root.parent)
    if not output_root.exists():
        output_root.mkdir(mode=0o700, exist_ok=False)
        _exclusive_private_file(
            output_root / _KTO_PREFLIGHT_FILE,
            canonical_json_bytes(dict(preflight)),
        )
    else:
        metadata = output_root.lstat()
        if output_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("KTO output root must be a no-follow directory")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("KTO output root must retain mode 0700")
        saved_preflight, _ = _canonical_object(output_root / _KTO_PREFLIGHT_FILE)
        stable_fields = {
            key: value
            for key, value in preflight.items()
            if key
            not in {
                "completed_nonce_inventory_sha256",
                "state_attestation_sha256",
            }
        }
        saved_stable = {
            key: value
            for key, value in saved_preflight.items()
            if key
            not in {
                "completed_nonce_inventory_sha256",
                "state_attestation_sha256",
            }
        }
        if saved_stable != stable_fields:
            raise ValueError("existing KTO output root belongs to another target")
    _append_canonical_record(
        output_root / _KTO_AUTHORITY_RECEIPT_LOG,
        _kto_authority_receipt_record(
            preflight,
            validated,
            consumed_at=consumed_at,
        ),
    )
    return {"result_sha256": output_root.name}


def _persist_kto_attempt_raw(
    output_root: Path,
    *,
    identity: str,
    ordinal: int,
    raw_body: bytes,
    credential: str,
) -> tuple[str | None, str | None, str, str]:
    raw_body_sha256 = _sha256(raw_body)
    if not raw_body:
        return None, None, raw_body_sha256, "NO_BODY"
    raw_base = output_root / _KTO_RAW_DIRECTORY
    _ensure_private_directory(raw_base)
    raw_directory = raw_base / identity
    _ensure_private_directory(raw_directory)
    raw_path = raw_directory / f"attempt-{ordinal:03d}.response"
    if _contains_secret(raw_body, (credential,)):
        publication = canonical_json_bytes(
            {
                "raw_body_sha256": raw_body_sha256,
                "reason": "provider-reflected-credential",
                "redacted": True,
                "retention": "REDACTED_SECRET_REFLECTION",
            }
        )
        retention = "REDACTED_SECRET_REFLECTION"
    else:
        publication = raw_body
        retention = "IMMUTABLE_ATTEMPT_SNAPSHOT"
    _exclusive_private_file(raw_path, publication)
    return (
        raw_path.relative_to(output_root).as_posix(),
        _sha256(publication),
        raw_body_sha256,
        retention,
    )


def _kto_transport_reason(exc: BaseException) -> str:
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "connection-reset"
    cause = exc.__cause__
    if isinstance(cause, ConnectionResetError):
        return "connection-reset"
    return "transport-policy-rejected"


def _collect_one_kto_request(
    *,
    output_root: Path,
    planned: Mapping[str, Any],
    credential: str,
    requester: KtoStreamRequester,
    existing_attempts: int,
) -> dict[str, object]:
    identity = str(planned["request_identity"])
    operation = str(planned["operation"])
    parameters = planned["parameters"]
    if not isinstance(parameters, Mapping):
        raise ValueError("KTO planned parameters must be an object")
    declared_rows = int(str(parameters["numOfRows"]))
    terminal_status = "RETRY_EXHAUSTED"
    normalized_reason: str | None = "three-attempt ceiling already exhausted"
    last: dict[str, object] = {
        "http_status": None,
        "provider_result_code": None,
        "provider_result_value": None,
        "safe_response_headers": {},
        "raw_body_size": 0,
        "raw_body_sha256": _sha256(b""),
        "raw_relative_path": None,
        "publication_sha256": None,
        "raw_body_retention": "NO_BODY",
        "item_count": None,
    }
    final_ordinal = existing_attempts
    for ordinal in range(existing_attempts + 1, 4):
        final_ordinal = ordinal
        started_at = datetime.now(UTC)
        started_ns = time.monotonic_ns()
        http_status: int | None = None
        provider_code: str | None = None
        provider_value: str | None = None
        transport_reason: str | None = None
        policy_failure: str | None = None
        raw_body = b""
        raw_body_size = 0
        item_count: int | None = None
        safe_headers: dict[str, str] = {}
        try:
            with requester.stream(
                "GET",
                f"{KOR_SERVICE2_BASE_URL}/{operation}",
                params={**dict(parameters), "serviceKey": credential},
                timeout=300,
                follow_redirects=False,
            ) as response:
                http_status = int(response.status_code)
                safe_headers = _safe_headers(response.headers)
                try:
                    inspected = read_kto_response_bounded(
                        response,
                        declared_num_of_rows=declared_rows,
                    )
                    raw_body = bytes(inspected["raw_body"])
                    raw_body_size = int(inspected["raw_body_size"])
                    provider_code = str(inspected["provider_result_code"])
                    provider_value = str(inspected["provider_result_value"])
                    item_count = int(inspected["item_count"])
                except ValueError as exc:
                    policy_failure = str(exc)
        except (httpx.RequestError, OSError, TimeoutError) as exc:
            transport_reason = _kto_transport_reason(exc)
        completed_at = datetime.now(UTC)
        elapsed_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
        raw_path, publication_sha256, raw_body_sha256, retention = _persist_kto_attempt_raw(
            output_root,
            identity=identity,
            ordinal=ordinal,
            raw_body=raw_body,
            credential=credential,
        )
        retryable = is_kto_retryable(
            http_status=http_status,
            provider_code=provider_code,
            transport_reason=transport_reason,
        )
        if retention == "REDACTED_SECRET_REFLECTION":
            retryable = False
            terminal_status = "SECRET_REFLECTION_REJECTED"
            normalized_reason = "provider response reflected credential material"
        elif transport_reason is not None:
            normalized_reason = transport_reason
            terminal_status = "RETRY_EXHAUSTED" if retryable else "TRANSPORT_POLICY_REJECTED"
        elif policy_failure is not None:
            normalized_reason = policy_failure
            terminal_status = "RETRY_EXHAUSTED" if retryable else "RESPONSE_POLICY_REJECTED"
        elif http_status == 200 and provider_code in {"00", "0000"}:
            terminal_status = "SUCCESS_EMPTY" if item_count == 0 else "SUCCESS_WITH_ITEMS"
            normalized_reason = "successful response contains no items" if item_count == 0 else None
            retryable = False
        elif retryable:
            terminal_status = "RETRY_EXHAUSTED"
            normalized_reason = "bounded transient provider outcome"
        else:
            terminal_status = "TERMINAL_PROVIDER_FAILURE"
            normalized_reason = (
                f"terminal provider result {provider_code}"
                if provider_code
                else f"terminal HTTP status {http_status}"
            )
        terminal = not retryable or ordinal == 3
        attempt = {
            "schema_version": _KTO_ATTEMPT_SCHEMA,
            "request_identity": identity,
            "provider": "TourAPI",
            "operation": operation,
            "attempt_ordinal": ordinal,
            "attempt_started_at": started_at.isoformat(),
            "attempt_completed_at": completed_at.isoformat(),
            "elapsed_ms": elapsed_ms,
            "timeout_seconds": 300,
            "http_status": http_status,
            "safe_response_headers": safe_headers,
            "provider_result_code": provider_code,
            "provider_result_value": provider_value,
            "raw_body_size": raw_body_size,
            "raw_body_sha256": raw_body_sha256,
            "raw_relative_path": raw_path,
            "publication_sha256": publication_sha256,
            "raw_body_retention": retention,
            "item_count": item_count,
            "transport_reason": transport_reason,
            "normalized_reason": normalized_reason,
            "retryable": retryable,
            "terminal": terminal,
        }
        _append_canonical_record(output_root / _KTO_ATTEMPT_LOG, attempt)
        last = {
            key: attempt[key]
            for key in (
                "http_status",
                "provider_result_code",
                "provider_result_value",
                "safe_response_headers",
                "raw_body_size",
                "raw_body_sha256",
                "raw_relative_path",
                "publication_sha256",
                "raw_body_retention",
                "item_count",
            )
        }
        if terminal:
            break
    return {
        "schema_version": _KTO_TERMINAL_SCHEMA,
        "request_identity": identity,
        "provider": planned["provider"],
        "operation": operation,
        "mapped_mandatory_fields": planned["mapped_mandatory_fields"],
        "terminal_status": terminal_status,
        "normalized_reason": normalized_reason,
        "attempt_count": final_ordinal,
        **last,
    }


def collect_kto_recovery_packet(
    repository_root: Path | str,
    *,
    authorization_token: str,
    credential_path: Path | str,
    issued_at: datetime,
    deadline: datetime,
    reviewer_id: str,
    now: datetime | None = None,
    requester: KtoStreamRequester | None = None,
) -> dict[str, object]:
    """Collect only the live-rederived Plan 47 packet under separate authority."""

    root = Path(repository_root).resolve(strict=True)
    preflight = build_kto_collection_preflight(
        root,
        issued_at=issued_at,
        deadline=deadline,
        reviewer_id=reviewer_id,
    )
    canonical_now = now or datetime.now(UTC)
    validated = validate_kto_collection_authority(
        preflight,
        raw_token=authorization_token,
        now=canonical_now,
    )
    credential = _read_kto_credential(credential_path)
    output_root = Path(str(preflight["output_root"]))
    collections_base = output_root.parent
    _ensure_private_directory(collections_base)
    ledger = FileNonceLedger(collections_base)
    ledger.consume_with_mutation(
        validated,
        mutation=lambda: _initialize_kto_collection_root(
            preflight,
            validated,
            consumed_at=canonical_now,
        ),
        relookup=lambda: _find_kto_authority_receipt(output_root, validated),
    )

    eligibility_root = root / _KTO_ELIGIBILITY_BASE_REL / str(preflight["kto_eligibility_root"])
    manifest, _ = _canonical_object(eligibility_root / "request-manifest.json")
    planned_requests = _validate_kto_manifest(
        manifest,
        summary={
            "kto_contract_sha256": preflight["kto_contract_sha256"],
            "kto_allowlist_revision_sha256": preflight["kto_allowlist_revision_sha256"],
            "decision_receipt_sha256": preflight["decision_receipt_sha256"],
            "request_count": preflight["request_count"],
        },
    )
    planned_ids = {str(row["request_identity"]) for row in planned_requests}
    terminal = _kto_terminal_rows(output_root, planned_ids=planned_ids)
    attempt_counts = _kto_attempt_counts(output_root, planned_ids=planned_ids)
    pending = [row for row in planned_requests if str(row["request_identity"]) not in terminal]
    owned_requester = requester is None
    client = cast(
        KtoStreamRequester,
        requester or httpx.Client(follow_redirects=False),
    )
    provider_requests_sent = 0
    try:
        for planned in pending:
            identity = str(planned["request_identity"])
            before_count = attempt_counts.get(identity, 0)
            result = _collect_one_kto_request(
                output_root=output_root,
                planned=planned,
                credential=credential,
                requester=client,
                existing_attempts=before_count,
            )
            attempt_count = result["attempt_count"]
            if not isinstance(attempt_count, int) or isinstance(attempt_count, bool):
                raise ValueError("KTO terminal result has an invalid attempt count")
            provider_requests_sent += max(0, attempt_count - before_count)
            _append_canonical_record(output_root / _KTO_TERMINAL_LOG, result)
            terminal[identity] = result
    finally:
        credential = ""
        if owned_requester and isinstance(client, httpx.Client):
            client.close()
    failure_count = sum(
        row.get("terminal_status") not in {"SUCCESS_WITH_ITEMS", "SUCCESS_EMPTY"}
        for row in terminal.values()
    )
    return {
        "status": (
            "TERMINAL_COVERAGE_COMPLETE"
            if len(terminal) == len(planned_ids) and failure_count == 0
            else "TERMINAL_FAILURE"
            if len(terminal) == len(planned_ids)
            else "INCOMPLETE"
        ),
        "collection_root_sha256": output_root.name,
        "request_count": len(planned_ids),
        "terminal_request_count": len(terminal),
        "missing_request_count": len(planned_ids) - len(terminal),
        "terminal_failure_count": failure_count,
        "provider_requests_sent": provider_requests_sent,
        "authority_consumed": True,
    }


def _kto_private_tree_files(root: Path) -> tuple[Path, ...]:
    """Return a no-follow private tree inventory while enforcing 0700/0600."""

    files: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("KTO collection tree contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("KTO collection directory mode is not 0700")
            children = sorted(current.iterdir(), key=lambda path: path.name, reverse=True)
            stack.extend(children)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("KTO collection file is not private regular single-link evidence")
        files.append(current)
    return tuple(sorted(files, key=lambda path: path.relative_to(root).as_posix()))


def _publish_exact_private_file(path: Path, payload: bytes) -> None:
    if path.exists():
        if not hmac.compare_digest(_regular_file_bytes(path), payload):
            raise ValueError(f"{path.name} already exists with different bytes")
        return
    _exclusive_private_file(path, payload)


def _discover_kto_collection_candidate(collections_base: Path) -> Path:
    if not collections_base.exists():
        raise ValueError("KTO collection base does not exist")
    metadata = collections_base.lstat()
    if (
        collections_base.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("KTO collection base must be a private no-follow directory")
    candidates: list[Path] = []
    for child in sorted(collections_base.iterdir(), key=lambda path: path.name):
        child_metadata = child.lstat()
        if (
            _HEX64.fullmatch(child.name) is not None
            and stat.S_ISDIR(child_metadata.st_mode)
            and not child.is_symlink()
            and (child / _KTO_PREFLIGHT_FILE).exists()
        ):
            candidates.append(child)
    if len(candidates) != 1:
        raise ValueError("expected exactly one direct KTO collection generation")
    return candidates[0]


def _replay_kto_collection_inputs(
    repository_root: Path,
    output_root: Path,
) -> tuple[dict[str, object], tuple[Mapping[str, object], ...]]:
    preflight, preflight_bytes = _canonical_object(output_root / _KTO_PREFLIGHT_FILE)
    _validate_kto_preflight(preflight)
    if output_root.name != preflight.get("collection_root_sha256"):
        raise ValueError("KTO collection directory does not match its preflight")
    if Path(str(preflight.get("output_root", ""))).resolve(strict=False) != output_root:
        raise ValueError("KTO collection preflight points to another output root")

    summary, summary_sha256 = _summary_kto_fields(repository_root)
    if not hmac.compare_digest(str(preflight.get("summary_sha256", "")), summary_sha256):
        raise ValueError("KTO collection preflight no longer matches Plan 47 Summary")
    eligibility_base = (repository_root / _KTO_ELIGIBILITY_BASE_REL).resolve(strict=True)
    eligibility_root = discover_exact_kto_eligibility_success(
        repository_root,
        eligibility_base,
    )
    if eligibility_root.name != preflight.get("kto_eligibility_root"):
        raise ValueError("KTO collection eligibility root drifted")
    manifest, manifest_bytes = _canonical_object(eligibility_root / "request-manifest.json")
    if not hmac.compare_digest(
        _sha256(manifest_bytes),
        str(preflight.get("kto_request_manifest_sha256", "")),
    ):
        raise ValueError("KTO collection request manifest drifted")
    requests = _validate_kto_manifest(manifest, summary=summary)
    if len(requests) != preflight.get("request_count"):
        raise ValueError("KTO collection request count drifted")
    if canonical_json_bytes(preflight) != preflight_bytes:
        raise ValueError("KTO collection preflight is not canonical")
    return preflight, requests


def _build_kto_seal_generation(
    repository_root: Path,
    output_root: Path,
) -> tuple[bytes, bytes, dict[str, object]]:
    preflight, requests = _replay_kto_collection_inputs(repository_root, output_root)
    planned = {str(row["request_identity"]): row for row in requests}
    planned_ids = set(planned)
    terminal = _kto_terminal_rows(output_root, planned_ids=planned_ids)
    attempt_rows = _canonical_lines(output_root / _KTO_ATTEMPT_LOG)
    attempt_counts = _kto_attempt_counts(output_root, planned_ids=planned_ids)
    receipts = _canonical_lines(output_root / _KTO_AUTHORITY_RECEIPT_LOG)
    if len(receipts) != 1:
        raise ValueError("KTO collection requires exactly one authority receipt")
    receipt = receipts[0]
    expected_receipt = {
        "schema_version": _KTO_AUTHORITY_RECEIPT_SCHEMA,
        "action": "enrichment-collect",
        "request_sha256": preflight["request_sha256"],
        "state_attestation_sha256": preflight["state_attestation_sha256"],
        "target_sha256": preflight["target_sha256"],
        "reviewer_id": preflight["reviewer_id"],
        "collection_root_sha256": preflight["collection_root_sha256"],
        "kto_request_manifest_sha256": preflight["kto_request_manifest_sha256"],
        "request_count": preflight["request_count"],
        "deadline": preflight["deadline"],
    }
    if any(receipt.get(key) != value for key, value in expected_receipt.items()):
        raise ValueError("KTO authority receipt is not bound to the exact preflight")
    for field in (
        "binding_sha256",
        "nonce_sha256",
        "token_sha256",
        "issuance_context_sha256",
    ):
        _require_sha256(receipt.get(field), field=f"KTO authority receipt {field}")

    nonce_ledger = _canonical_lines(output_root.parent / "authority-consumption-ledger.jsonl")
    matching_nonce_rows = [
        row
        for row in nonce_ledger
        if row.get("binding_sha256") == receipt["binding_sha256"]
        and row.get("nonce_sha256") == receipt["nonce_sha256"]
    ]
    if len(matching_nonce_rows) != 1:
        raise ValueError("KTO authority nonce was not consumed exactly once")
    nonce_row = matching_nonce_rows[0]
    if (
        nonce_row.get("token_sha256") != receipt["token_sha256"]
        or nonce_row.get("request_sha256") != preflight["request_sha256"]
        or nonce_row.get("state_attestation_sha256") != preflight["state_attestation_sha256"]
        or nonce_row.get("target_sha256") != preflight["target_sha256"]
        or nonce_row.get("result_sha256") != output_root.name
        or nonce_row.get("completion") not in {"MUTATION_COMMITTED", "RELOOKUP_CONFIRMED"}
    ):
        raise ValueError("KTO global nonce receipt drifted from the collection receipt")

    if set(terminal) != planned_ids or set(attempt_counts) != planned_ids:
        raise ValueError("KTO collection does not cover the exact request inventory")
    failures = {
        identity: row.get("terminal_status")
        for identity, row in terminal.items()
        if row.get("terminal_status") not in {"SUCCESS_WITH_ITEMS", "SUCCESS_EMPTY"}
    }
    if failures:
        raise ValueError("KTO collection contains a terminal request failure")

    attempts_by_identity: dict[str, list[dict[str, Any]]] = {
        identity: [] for identity in planned_ids
    }
    for row in attempt_rows:
        identity = str(row["request_identity"])
        attempts_by_identity[identity].append(row)
    raw_entries: list[dict[str, object]] = []
    raw_paths: set[str] = set()
    for identity in sorted(planned_ids):
        rows = attempts_by_identity[identity]
        final = terminal[identity]
        if (
            not rows
            or len(rows) != attempt_counts[identity]
            or final.get("attempt_count") != len(rows)
            or rows[-1].get("terminal") is not True
            or any(row.get("terminal") is True for row in rows[:-1])
            or any(row.get("retryable") is not True for row in rows[:-1])
        ):
            raise ValueError("KTO collection attempt chain is incomplete or unbounded")
        planned_operation = planned[identity]["operation"]
        for ordinal, row in enumerate(rows, start=1):
            if (
                row.get("attempt_ordinal") != ordinal
                or row.get("timeout_seconds") != 300
                or row.get("operation") != planned_operation
                or row.get("provider") != "TourAPI"
                or not isinstance(row.get("safe_response_headers"), Mapping)
                or not set(row["safe_response_headers"]).issubset(_SAFE_HEADERS)
            ):
                raise ValueError("KTO collection attempt violates D-13/D-15")
            raw_relative_path = row.get("raw_relative_path")
            if not isinstance(raw_relative_path, str):
                raise ValueError("successful KTO attempt lacks immutable raw evidence")
            if raw_relative_path in raw_paths:
                raise ValueError("KTO raw evidence path is reused")
            raw_paths.add(raw_relative_path)
            expected_path = (
                Path(_KTO_RAW_DIRECTORY) / identity / f"attempt-{ordinal:03d}.response"
            ).as_posix()
            if raw_relative_path != expected_path:
                raise ValueError("KTO raw evidence path is not identity-addressed")
            raw_path = output_root / raw_relative_path
            publication = _regular_file_bytes(raw_path)
            publication_sha256 = _sha256(publication)
            if (
                row.get("raw_body_retention") != "IMMUTABLE_ATTEMPT_SNAPSHOT"
                or row.get("publication_sha256") != publication_sha256
                or row.get("raw_body_sha256") != publication_sha256
                or row.get("raw_body_size") != len(publication)
            ):
                raise ValueError("KTO raw evidence digest or retention drifted")
            raw_entries.append(
                {
                    "attempt_ordinal": ordinal,
                    "mode": "0600",
                    "path": raw_relative_path,
                    "publication_sha256": publication_sha256,
                    "raw_body_sha256": publication_sha256,
                    "raw_body_size": len(publication),
                    "request_identity": identity,
                    "retention": "IMMUTABLE_ATTEMPT_SNAPSHOT",
                }
            )
        last = rows[-1]
        for terminal_key, attempt_key in (
            ("http_status", "http_status"),
            ("provider_result_code", "provider_result_code"),
            ("provider_result_value", "provider_result_value"),
            ("safe_response_headers", "safe_response_headers"),
            ("raw_body_size", "raw_body_size"),
            ("raw_body_sha256", "raw_body_sha256"),
            ("raw_relative_path", "raw_relative_path"),
            ("publication_sha256", "publication_sha256"),
            ("raw_body_retention", "raw_body_retention"),
            ("item_count", "item_count"),
            ("normalized_reason", "normalized_reason"),
        ):
            if final.get(terminal_key) != last.get(attempt_key):
                raise ValueError("KTO terminal row does not match its final attempt")
        expected_status = "SUCCESS_EMPTY" if last.get("item_count") == 0 else "SUCCESS_WITH_ITEMS"
        if (
            final.get("terminal_status") != expected_status
            or last.get("http_status") != 200
            or last.get("provider_result_code") not in {"00", "0000"}
            or last.get("retryable") is not False
        ):
            raise ValueError("KTO terminal success is not an exact provider success")

    expected_raw_files = {
        path.relative_to(output_root).as_posix()
        for path in _kto_private_tree_files(output_root)
        if _KTO_RAW_DIRECTORY in path.relative_to(output_root).parts
    }
    if expected_raw_files != raw_paths:
        raise ValueError("KTO raw inventory contains an extra or missing file")

    structured_paths = (
        output_root / _KTO_PREFLIGHT_FILE,
        output_root / _KTO_AUTHORITY_RECEIPT_LOG,
        output_root / _KTO_ATTEMPT_LOG,
        output_root / _KTO_TERMINAL_LOG,
    )
    forbidden_markers = (
        b"itda-auth-v2:",
        b"serviceKey",
        b"TOUR_API_SERVICE_KEY=",
        b"KorService2?",
    )
    if any(
        marker in _regular_file_bytes(path)
        for path in structured_paths
        for marker in forbidden_markers
    ):
        raise ValueError("KTO structured evidence contains secret-bearing material")

    raw_payload = {
        "schema_version": _KTO_RAW_MANIFEST_SCHEMA,
        "collection_root_sha256": output_root.name,
        "kto_request_manifest_sha256": preflight["kto_request_manifest_sha256"],
        "request_count": len(planned_ids),
        "raw_file_count": len(raw_entries),
        "files": raw_entries,
    }
    raw_manifest = {
        "payload": raw_payload,
        "root_sha256": _sha256(canonical_json_bytes(raw_payload)),
    }
    raw_manifest_bytes = canonical_json_bytes(raw_manifest)
    authority_receipt_sha256 = _sha256(
        _regular_file_bytes(output_root / _KTO_AUTHORITY_RECEIPT_LOG)
    )
    attempt_ledger_sha256 = _sha256(_regular_file_bytes(output_root / _KTO_ATTEMPT_LOG))
    terminal_ledger_sha256 = _sha256(_regular_file_bytes(output_root / _KTO_TERMINAL_LOG))
    collection_payload = {
        "schema_version": _KTO_COLLECTION_MANIFEST_SCHEMA,
        "status": "SUCCESS",
        "decision_receipt_sha256": preflight["decision_receipt_sha256"],
        "kto_eligibility_root": preflight["kto_eligibility_root"],
        "kto_request_manifest_sha256": preflight["kto_request_manifest_sha256"],
        "kto_collection_base": output_root.name,
        "kto_raw_manifest_sha256": _sha256(raw_manifest_bytes),
        "kto_terminal_ledger_sha256": terminal_ledger_sha256,
        "kto_attempt_ledger_sha256": attempt_ledger_sha256,
        "kto_authority_receipt_sha256": authority_receipt_sha256,
        "request_count": len(planned_ids),
        "terminal_request_count": len(terminal),
        "successful_request_count": len(terminal),
        "success_empty_count": sum(
            row.get("terminal_status") == "SUCCESS_EMPTY" for row in terminal.values()
        ),
        "typed_intro_policy_sha256": preflight["typed_intro_policy_sha256"],
        "plan49_reachable": True,
    }
    success_root = _sha256(canonical_json_bytes(collection_payload))
    collection_manifest = {
        "payload": collection_payload,
        "kto_collection_success_root": success_root,
    }
    collection_manifest_bytes = canonical_json_bytes(collection_manifest)
    result = {
        **collection_payload,
        "kto_collection_success_root": success_root,
        "kto_collection_manifest_sha256": _sha256(collection_manifest_bytes),
    }
    return raw_manifest_bytes, collection_manifest_bytes, result


def verify_and_seal_kto_recovery_collection(
    repository_root: Path | str,
    *,
    collections_base: Path | str,
) -> dict[str, object]:
    """Replay exact terminal coverage twice, then publish immutable seal manifests."""

    root = Path(repository_root).resolve(strict=True)
    base = Path(collections_base).expanduser().resolve(strict=True)
    output_root = _discover_kto_collection_candidate(base)
    first = _build_kto_seal_generation(root, output_root)
    second = _build_kto_seal_generation(root, output_root)
    if first != second:
        raise ValueError("isolated KTO collection manifest replays are nondeterministic")
    raw_manifest_bytes, collection_manifest_bytes, result = first
    _publish_exact_private_file(
        output_root / _KTO_RAW_MANIFEST_FILE,
        raw_manifest_bytes,
    )
    _publish_exact_private_file(
        output_root / _KTO_COLLECTION_MANIFEST_FILE,
        collection_manifest_bytes,
    )
    _kto_private_tree_files(output_root)
    return result


def verify_authorization_receipt(
    path: Path | str,
    *,
    round_root: Path | str,
    round_id: str,
) -> dict[str, object]:
    selected = _load_selected_round(round_root, round_id)
    receipt_path = _exact_path(selected.root, path, _RECEIPT_NAME)
    records = _canonical_lines(receipt_path)
    seen: set[tuple[str, str]] = set()
    for record in records:
        if record.get("schema_version") != _RECEIPT_SCHEMA:
            raise ValueError("authorization receipt schema is invalid")
        expected = {
            "action": "enrichment-collect",
            "request_sha256": selected.round_id,
            "state_attestation_sha256": selected.request["state_attestation_sha256"],
            "target_sha256": selected.round_id,
            "binding_sha256": selected.request["binding_sha256"],
            "round_id": selected.round_id,
            "round_root": _round_value(selected.root),
            "ancestry_depth": selected.ancestry_depth,
            "completion": "AUTHORITY_CONSUMED_FOR_INVOCATION",
        }
        if any(record.get(field) != value for field, value in expected.items()):
            raise ValueError("authorization receipt is not bound to the selected round")
        token_sha256 = _require_sha256(record.get("token_sha256"), field="token hash")
        nonce_sha256 = _require_sha256(record.get("nonce_sha256"), field="nonce hash")
        key = (str(record["binding_sha256"]), nonce_sha256)
        if key in seen:
            raise ValueError("authorization receipt repeats a consumed nonce")
        seen.add(key)
        serialized = canonical_json_bytes(record)
        if b"itda-auth-v2:" in serialized or str(selected.request["nonce"]).encode() in serialized:
            raise ValueError("authorization receipt contains raw authority material")
        if token_sha256 == str(selected.request["nonce"]):
            raise ValueError("authorization receipt stores a raw nonce instead of its hash")
    return {"receipt_count": len(records), "round_id": selected.round_id}


def verify_collection_report(
    path: Path | str,
    *,
    round_root: Path | str,
    round_id: str,
) -> dict[str, object]:
    selected = _load_selected_round(round_root, round_id)
    report_path = _exact_path(selected.root, path, _REPORT_NAME)
    records = _canonical_lines(report_path)
    plan_requests = selected.plan["requests"]
    assert isinstance(plan_requests, list)
    planned = {
        str(item["request_identity"]): item for item in plan_requests if isinstance(item, Mapping)
    }
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.get("schema_version") != _REPORT_SCHEMA:
            raise ValueError("collection report schema is invalid")
        identity = str(record.get("request_identity", ""))
        if identity not in planned:
            raise ValueError("collection report contains an identity outside the selected round")
        request = planned[identity]
        if (
            record.get("operation") != request["operation"]
            or record.get("mapped_mandatory_fields") != request["mapped_mandatory_fields"]
        ):
            raise ValueError("collection report operation is outside the exact allowlist")
        attempts = record.get("attempts")
        if (
            not isinstance(attempts, list)
            or not attempts
            or len(attempts) > int(selected.plan["attempts_per_request"])
            or any(
                not isinstance(attempt, Mapping)
                or attempt.get("timeout_seconds") != 300
                or not isinstance(attempt.get("safe_headers"), Mapping)
                or not set(attempt["safe_headers"]).issubset(_SAFE_HEADERS)
                for attempt in attempts
            )
        ):
            raise ValueError("collection report violates bounded D-13/D-15 attempts")
        if record.get("overall_timeout_seconds") != selected.plan["overall_timeout_seconds"]:
            raise ValueError("collection report carries a shorter global timeout")
        raw_path = record.get("raw_relative_path")
        if isinstance(raw_path, str):
            candidate = Path(raw_path)
            _reject_lexical_traversal(candidate, field="raw evidence path")
            resolved = (selected.root / candidate).resolve(strict=True)
            if selected.root not in resolved.parents:
                raise ValueError("raw evidence path escapes the selected round")
            snapshot = _regular_file_bytes(resolved)
            if record.get("raw_body_retention") != "REDACTED_SECRET_REFLECTION" and not (
                isinstance(record.get("raw_body_sha256"), str)
                and hmac.compare_digest(_sha256(snapshot), record["raw_body_sha256"])
            ):
                raise ValueError("raw evidence digest does not match its report")
        latest[identity] = record
    success_count = sum(record.get("terminal_status") == "SUCCESS" for record in latest.values())
    return {
        "round_id": selected.round_id,
        "record_count": len(records),
        "covered_request_count": len(latest),
        "successful_request_count": success_count,
        "resumable_request_count": sum(
            record.get("terminal_status") == "RETRYABLE_FOR_RESUME" for record in latest.values()
        ),
        "missing_request_count": len(planned) - len(latest),
    }


def verify_collection_log(
    path: Path | str,
    *,
    round_root: Path | str,
    round_id: str,
) -> dict[str, object]:
    selected = _load_selected_round(round_root, round_id)
    log_path = _exact_path(selected.root, path, _LOG_NAME)
    records = _canonical_lines(log_path)
    planned_ids = {
        str(item["request_identity"])
        for item in selected.plan["requests"]
        if isinstance(item, Mapping)
    }
    for record in records:
        if (
            record.get("schema_version") != _LOG_SCHEMA
            or record.get("round_id") != selected.round_id
            or record.get("request_identity") not in planned_ids
            or record.get("operation") not in APPROVED_OPERATIONS
            or record.get("timeout_seconds") != 300
            or not isinstance(record.get("safe_headers"), Mapping)
            or not set(record["safe_headers"]).issubset(_SAFE_HEADERS)
        ):
            raise ValueError("collection log contains an invalid or unplanned event")
        serialized = canonical_json_bytes(record)
        if b"serviceKey" in serialized or b"itda-auth-v2:" in serialized:
            raise ValueError("collection log contains secret-bearing material")
    terminal_events = sum(record.get("terminal") is True for record in records)
    return {
        "round_id": selected.round_id,
        "event_count": len(records),
        "terminal_event_count": terminal_events,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Collect or verify one explicit authority-bound enrichment round."
    )
    result.add_argument("--round-root", type=Path, required=True)
    result.add_argument("--round-id", required=True)
    result.add_argument("--collect", action="store_true")
    result.add_argument(
        "--authorization-token-stdin",
        action="store_true",
        help="read the ephemeral authority token from stdin instead of a hidden prompt",
    )
    result.add_argument(
        "--credential-file",
        type=Path,
        default=Path("../.secrets/itda-api.env"),
    )
    result.add_argument(
        "--credential-variable",
        default="TOUR_API_SERVICE_KEY",
        choices=("TOUR_API_SERVICE_KEY",),
    )
    result.add_argument("--verify-authorization-preconditions", type=Path)
    result.add_argument("--verify-authorization-receipt", type=Path)
    result.add_argument("--verify-report", type=Path)
    result.add_argument("--verify-log", type=Path)
    return result


def kto_recovery_parser() -> argparse.ArgumentParser:
    """Build the dedicated Plan 48 interface without raw secret arguments."""

    result = argparse.ArgumentParser(
        description="Preflight or consume the exact Plan 47 KTO recovery packet."
    )
    result.add_argument("--repo-root", type=Path, required=True)
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument("--kto-recovery-preflight", action="store_true")
    mode.add_argument("--collect-kto-recovery", action="store_true")
    mode.add_argument("--verify-kto-recovery", action="store_true")
    result.add_argument("--authority-issued-at")
    result.add_argument("--authority-deadline")
    result.add_argument("--reviewer-id")
    result.add_argument(
        "--authorization-token-stdin",
        action="store_true",
        help="read the separately issued authority token from bounded stdin",
    )
    result.add_argument(
        "--credential-file",
        type=Path,
        help="protected 0600 file containing TOUR_API_SERVICE_KEY",
    )
    result.add_argument(
        "--discover-exact-success-under",
        type=Path,
        help="fixed collection base for exact sealed-success discovery",
    )
    return result


def _parse_utc_boundary(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(UTC)


def _read_authorization_token(*, from_stdin: bool) -> str:
    if from_stdin:
        payload = sys.stdin.read(65_537)
        if len(payload) > 65_536:
            raise ValueError("stdin authority input exceeds the bounded size")
        lines = payload.splitlines()
        if len(lines) != 1 or not lines[0]:
            raise ValueError("stdin must contain exactly one non-empty authority token line")
        return lines[0]
    token = getpass.getpass("Authorization token: ")
    if not token:
        raise ValueError("collection requires an ephemeral authorization token")
    return token


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    if {
        "--kto-recovery-preflight",
        "--collect-kto-recovery",
        "--verify-kto-recovery",
    }.intersection(raw_args):
        kto_args = kto_recovery_parser().parse_args(raw_args)
        if kto_args.verify_kto_recovery:
            if (
                kto_args.discover_exact_success_under is None
                or kto_args.authorization_token_stdin
                or kto_args.credential_file is not None
                or kto_args.authority_issued_at is not None
                or kto_args.authority_deadline is not None
                or kto_args.reviewer_id is not None
            ):
                raise ValueError("verification accepts only the exact collection discovery base")
            result = verify_and_seal_kto_recovery_collection(
                kto_args.repo_root,
                collections_base=kto_args.discover_exact_success_under,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if (
            kto_args.authority_issued_at is None
            or kto_args.authority_deadline is None
            or kto_args.reviewer_id is None
            or kto_args.discover_exact_success_under is not None
        ):
            raise ValueError(
                "preflight and collection require issued-at, deadline, and reviewer only"
            )
        issued_at = _parse_utc_boundary(
            kto_args.authority_issued_at,
            field="authority-issued-at",
        )
        deadline = _parse_utc_boundary(
            kto_args.authority_deadline,
            field="authority-deadline",
        )
        if kto_args.kto_recovery_preflight:
            if kto_args.authorization_token_stdin or kto_args.credential_file is not None:
                raise ValueError("preflight does not accept authority or credential inputs")
            preflight = build_kto_collection_preflight(
                kto_args.repo_root,
                issued_at=issued_at,
                deadline=deadline,
                reviewer_id=kto_args.reviewer_id,
            )
            print(canonical_json_bytes(preflight).decode())
            return 0
        if kto_args.credential_file is None:
            raise ValueError("collection requires an explicit credential file")
        authorization_token = _read_authorization_token(
            from_stdin=kto_args.authorization_token_stdin
        )
        result = collect_kto_recovery_packet(
            kto_args.repo_root,
            authorization_token=authorization_token,
            credential_path=kto_args.credential_file,
            issued_at=issued_at,
            deadline=deadline,
            reviewer_id=kto_args.reviewer_id,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["status"] == "TERMINAL_COVERAGE_COMPLETE" else 2

    args = parser().parse_args(raw_args)
    verifier_modes = (
        args.verify_authorization_preconditions,
        args.verify_authorization_receipt,
        args.verify_report,
        args.verify_log,
    )
    if not args.collect and not any(verifier_modes):
        raise ValueError("select collection or at least one read-only verifier")
    if args.collect:
        if any(verifier_modes):
            raise ValueError("collection and read-only verification are separate invocations")
        authorization_token = _read_authorization_token(from_stdin=args.authorization_token_stdin)
        result = collect_authorized_round(
            round_root=args.round_root,
            round_id=args.round_id,
            authorization_token=authorization_token,
            credential_path=args.credential_file,
            credential_variable=args.credential_variable,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    summaries: dict[str, object] = {}
    if args.verify_authorization_preconditions is not None:
        summaries["authorization_preconditions"] = verify_authorization_preconditions(
            args.verify_authorization_preconditions,
            round_root=args.round_root,
            round_id=args.round_id,
            now=datetime.now(UTC),
        )
    if args.verify_authorization_receipt is not None:
        summaries["authorization_receipt"] = verify_authorization_receipt(
            args.verify_authorization_receipt,
            round_root=args.round_root,
            round_id=args.round_id,
        )
    if args.verify_report is not None:
        summaries["report"] = verify_collection_report(
            args.verify_report,
            round_root=args.round_root,
            round_id=args.round_id,
        )
    if args.verify_log is not None:
        summaries["log"] = verify_collection_log(
            args.verify_log,
            round_root=args.round_root,
            round_id=args.round_id,
        )
    print(json.dumps(summaries, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
