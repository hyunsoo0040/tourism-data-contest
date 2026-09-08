"""Traffic-free optional-media closure planning and immutable terminal publication."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import BaseModel

from itda.cli.audit_catalog_optional_media_frontier import (
    EXPECTED_PLAN51_PROJECTION_ROOT,
    build_optional_media_frontier_audit,
)
from itda.contracts.authority import (
    AuthorityIssuanceContext,
    AuthorityTokenV2,
    FileNonceLedger,
    ValidatedAuthority,
    validate_authority_token,
)
from itda.contracts.catalog_optional_media import (
    GateState,
    NonImageEligibilityGates,
    OptionalMediaCandidate,
)
from itda.contracts.catalog_optional_media_closure import (
    CapturedEvidenceRoute,
    ClosureAttemptReceipt,
    ClosureAuthorityRequest,
    ClosureEvidence,
    ClosureEvidenceCoverage,
    ClosureExecutionMode,
    ClosureNormalizedEvidenceRow,
    ClosurePlan,
    ClosureTargetRow,
    FreshCollectionBounds,
    FreshCollectionRoute,
    NonAddressableClosureTerminal,
)
from itda.contracts.catalog_optional_media_frontier import (
    OptionalMediaAccountingRow,
    OptionalMediaFrontier,
    compare_frontier_replays,
    evaluate_optional_media_frontier,
)
from itda.contracts.catalog_readiness import GROUP_ORDER
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

OUTPUT_ROOT_REL = Path("artifacts/catalog/optional-media-v2/closure-plan")
PLAN51_MANIFEST_REL = Path(
    "artifacts/catalog/optional-media-v2/policy"
    f"/{EXPECTED_PLAN51_PROJECTION_ROOT}/projection-manifest.json"
)
EXPECTED_AGGREGATE_REL = Path(
    "artifacts/restricted/catalog/v2/enrichment/rounds"
    "/01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55"
    "/aggregate-readiness.json"
)
MAX_LOCAL_ARTIFACT_BYTES = 16 * 1024 * 1024
SAFE_RESPONSE_HEADERS = frozenset(
    {"content-type", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"}
)


class OptionalMediaClosureError(ValueError):
    """Fail-closed local planner or publication error."""


def _read_regular_bytes_nofollow(path: Path) -> bytes:
    absolute_path = path.absolute()
    for ancestor in reversed(absolute_path.parents):
        try:
            ancestor_metadata = os.lstat(ancestor)
        except OSError as exc:
            raise OptionalMediaClosureError("closure input ancestry is unavailable") from exc
        if stat.S_ISLNK(ancestor_metadata.st_mode):
            raise OptionalMediaClosureError("closure input ancestry contains a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute_path, flags)
    except OSError as exc:
        raise OptionalMediaClosureError("closure input is not a no-follow regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_LOCAL_ARTIFACT_BYTES:
            raise OptionalMediaClosureError("closure input is not bounded regular data")
        payload = b""
        while len(payload) <= MAX_LOCAL_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_LOCAL_ARTIFACT_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload += chunk
        final_metadata = os.fstat(descriptor)
        stable_identity = (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
        )
        initial_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        if len(payload) != metadata.st_size or stable_identity != initial_identity:
            raise OptionalMediaClosureError("closure input changed during read")
        return payload
    finally:
        os.close(descriptor)


def _load_object(path: Path) -> dict[str, Any]:
    payload = _read_regular_bytes_nofollow(path)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OptionalMediaClosureError("closure input is not canonical JSON data") from exc
    if not isinstance(parsed, dict):
        raise OptionalMediaClosureError("closure input root must be an object")
    if payload != canonical_json_bytes(parsed):
        raise OptionalMediaClosureError("closure input bytes are not canonical JSON")
    return parsed


def _provider_bindings(repository_root: Path) -> tuple[dict[str, str], frozenset[str]]:
    manifest = _load_object(repository_root / PLAN51_MANIFEST_REL)
    source_files = manifest.get("source_files")
    if not isinstance(source_files, Mapping):
        raise OptionalMediaClosureError("Plan 51 source-file binding is absent")
    aggregate_rel = EXPECTED_AGGREGATE_REL.as_posix()
    expected_digest = source_files.get(aggregate_rel)
    if not isinstance(expected_digest, str):
        raise OptionalMediaClosureError("Plan 51 aggregate source binding is absent")
    aggregate_bytes = _read_regular_bytes_nofollow(repository_root / EXPECTED_AGGREGATE_REL)
    if hashlib.sha256(aggregate_bytes).hexdigest() != expected_digest:
        raise OptionalMediaClosureError("aggregate source file digest drifted")
    aggregate = json.loads(aggregate_bytes)
    if not isinstance(aggregate, dict):
        raise OptionalMediaClosureError("aggregate source root must be an object")
    rows = aggregate.get("rows")
    attempted = aggregate.get("attempted_provider_ids")
    if not isinstance(rows, list) or not isinstance(attempted, list):
        raise OptionalMediaClosureError("aggregate provider ancestry is incomplete")
    provider_ids: dict[str, str] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise OptionalMediaClosureError("aggregate row is not an object")
        place_id = raw.get("place_entity_id")
        provider_id = raw.get("provider_place_candidate_id")
        if isinstance(place_id, str) and isinstance(provider_id, str):
            if place_id in provider_ids:
                raise OptionalMediaClosureError("aggregate provider binding is duplicated")
            provider_ids[place_id] = provider_id
    attempted_ids = tuple(str(value) for value in attempted)
    if len(attempted_ids) != len(set(attempted_ids)):
        raise OptionalMediaClosureError("aggregate attempted-provider inventory is duplicated")
    return provider_ids, frozenset(attempted_ids)


def _target_row(
    row: OptionalMediaAccountingRow,
    *,
    provider_candidate_id: str,
) -> ClosureTargetRow:
    deficit_fields = {
        "place_entity_id": row.place_entity_id,
        "candidate_row_sha256": row.candidate_row_sha256,
        "non_image_deficits": row.non_image_deficits,
    }
    fields: dict[str, Any] = {
        "place_entity_id": row.place_entity_id,
        "provider_candidate_id": provider_candidate_id,
        "representation_primary_group": row.representation_primary_group,
        "candidate_row_sha256": row.candidate_row_sha256,
        "non_image_deficits": row.non_image_deficits,
        "frontier_deficit_sha256": canonical_sha256(deficit_fields),
    }
    return ClosureTargetRow(
        **fields,
        target_row_sha256=canonical_sha256(fields),
    )


def _target_set(
    frontier: OptionalMediaFrontier,
    provider_ids_by_place: Mapping[str, str],
) -> tuple[ClosureTargetRow, ...]:
    candidates: list[OptionalMediaAccountingRow] = []
    for row in frontier.accounting_rows:
        if (
            not row.eligible
            and row.representation_primary_group is not None
            and row.place_entity_id in provider_ids_by_place
            and row.non_image_deficits
            and set(row.non_image_deficits) <= {"description", "operating_information"}
        ):
            candidates.append(row)
    counts = dict(frontier.group_counts)
    selected: list[ClosureTargetRow] = []

    def feasible() -> bool:
        return (
            frontier.eligible_count + len(selected) >= 36
            and all(counts[group] >= 6 for group in GROUP_ORDER)
            and sum(min(12, counts[group]) for group in GROUP_ORDER) >= 36
        )

    remaining = list(candidates)

    def priority(row: OptionalMediaAccountingRow) -> tuple[int, bool, int, int, bytes]:
        group = row.representation_primary_group
        if group is None:
            raise OptionalMediaClosureError("closure candidate lacks a representation group")
        return (
            -max(0, 6 - counts[group]),
            counts[group] >= 12,
            len(row.non_image_deficits),
            GROUP_ORDER.index(group),
            row.place_entity_id.encode("utf-8"),
        )

    while not feasible() and remaining:
        remaining.sort(key=priority)
        row = remaining.pop(0)
        assert row.representation_primary_group is not None
        selected.append(
            _target_row(
                row,
                provider_candidate_id=provider_ids_by_place[row.place_entity_id],
            )
        )
        counts[row.representation_primary_group] += 1
    if not feasible():
        raise OptionalMediaClosureError("REPRESENTATION_TARGET_SET_INFEASIBLE")
    return tuple(sorted(selected, key=lambda row: row.place_entity_id))


def _coverage_matches(
    coverage: tuple[ClosureEvidenceCoverage, ...],
    targets: tuple[ClosureTargetRow, ...],
) -> bool:
    expected = {
        (row.place_entity_id, row.provider_candidate_id): row.non_image_deficits for row in targets
    }
    actual = {
        (row.place_entity_id, row.provider_candidate_id): row.evidence_types for row in coverage
    }
    return actual == expected


def _fresh_route_addressable(
    route: FreshCollectionRoute,
    *,
    targets: tuple[ClosureTargetRow, ...],
    attempted_provider_ids: frozenset[str],
) -> tuple[bool, bool]:
    if not _coverage_matches(route.coverage, targets):
        return False, False
    intersects_attempted = any(
        target.provider_candidate_id in attempted_provider_ids for target in targets
    )
    if route.alternate_approved_source:
        return True, False
    materially_changed = (
        route.predecessor_request_identity_sha256 is not None
        and route.request_identity_sha256 != route.predecessor_request_identity_sha256
        and bool(route.changed_fields)
        and bool(route.expected_evidence_types)
    )
    if intersects_attempted and not materially_changed:
        return False, True
    return True, False


def _plan_fields(
    *,
    execution_mode: ClosureExecutionMode,
    frontier: OptionalMediaFrontier,
    provider_ids_by_place: Mapping[str, str],
    attempted_provider_ids: frozenset[str],
    targets: tuple[ClosureTargetRow, ...],
    captured: CapturedEvidenceRoute | None,
    fresh: FreshCollectionRoute | None,
    authority: ClosureAuthorityRequest | None,
    terminal: NonAddressableClosureTerminal | None,
) -> dict[str, Any]:
    return {
        "schema_version": "itda.catalog-optional-media-closure-plan.v1",
        "execution_mode": execution_mode,
        "frontier_sha256": frontier.frontier_sha256,
        "universe_root_sha256": frontier.universe_root_sha256,
        "frontier": frontier,
        "provider_ids_by_place": dict(sorted(provider_ids_by_place.items())),
        "attempted_provider_ids": tuple(sorted(attempted_provider_ids)),
        "target_rows": targets,
        "target_root_sha256": canonical_sha256([row.model_dump(mode="json") for row in targets]),
        "captured_replay": captured,
        "fresh_collection": fresh,
        "authority_request": authority,
        "terminal": terminal,
        "authority_required": execution_mode is ClosureExecutionMode.FRESH_COLLECTION,
        "credential_required": execution_mode is ClosureExecutionMode.FRESH_COLLECTION,
        "provider_traffic_allowed": False,
        "attempt_inventory": (),
        "plan54_reachable": execution_mode is not ClosureExecutionMode.TERMINAL,
    }


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _plan_digest(fields: Mapping[str, object]) -> str:
    return canonical_sha256(_json_value(fields))


def derive_closure_plan(
    *,
    frontier: OptionalMediaFrontier,
    provider_ids_by_place: Mapping[str, str],
    attempted_provider_ids: frozenset[str],
    captured_routes: tuple[CapturedEvidenceRoute, ...],
    fresh_routes: tuple[FreshCollectionRoute, ...],
) -> ClosurePlan:
    """Choose exactly one local replay, bounded collection route, or terminal."""

    targets = _target_set(frontier, provider_ids_by_place)
    captured = tuple(
        route for route in captured_routes if _coverage_matches(route.coverage, targets)
    )
    if captured:
        chosen = sorted(captured, key=lambda route: route.evidence_root_sha256)[0]
        fields = _plan_fields(
            execution_mode=ClosureExecutionMode.CAPTURED_REPLAY,
            frontier=frontier,
            provider_ids_by_place=provider_ids_by_place,
            attempted_provider_ids=attempted_provider_ids,
            targets=targets,
            captured=chosen,
            fresh=None,
            authority=None,
            terminal=None,
        )
        return ClosurePlan(**fields, plan_sha256=_plan_digest(fields))

    addressable: list[FreshCollectionRoute] = []
    same_identity_exhausted = False
    for route in fresh_routes:
        accepted, exhausted = _fresh_route_addressable(
            route,
            targets=targets,
            attempted_provider_ids=attempted_provider_ids,
        )
        same_identity_exhausted = same_identity_exhausted or exhausted
        if accepted:
            addressable.append(route)
    if addressable:
        chosen_fresh = sorted(
            addressable,
            key=lambda route: route.request_identity_sha256 or "",
        )[0]
        request_payload = chosen_fresh.model_dump(mode="json")
        state_payload = {
            "frontier_sha256": frontier.frontier_sha256,
            "universe_root_sha256": frontier.universe_root_sha256,
            "attempted_provider_ids": sorted(attempted_provider_ids),
        }
        target_payload = [row.model_dump(mode="json") for row in targets]
        binding_payload = {
            "schema_version": "itda.catalog-optional-media-authority-binding.v1",
            "execution_mode": "fresh_collection",
            "source_manifest_sha256": chosen_fresh.source_manifest_sha256,
            "source_approval_sha256": chosen_fresh.source_approval_sha256,
            "request_sha256": canonical_sha256(request_payload),
            "state_attestation_sha256": canonical_sha256(state_payload),
            "target_sha256": canonical_sha256(target_payload),
            "operation": "catalog-optional-media-close",
        }
        authority = ClosureAuthorityRequest(
            operation="catalog-optional-media-close",
            request_sha256=canonical_sha256(request_payload),
            state_attestation_sha256=canonical_sha256(state_payload),
            target_sha256=canonical_sha256(target_payload),
            binding_sha256=canonical_sha256(binding_payload),
        )
        fields = _plan_fields(
            execution_mode=ClosureExecutionMode.FRESH_COLLECTION,
            frontier=frontier,
            provider_ids_by_place=provider_ids_by_place,
            attempted_provider_ids=attempted_provider_ids,
            targets=targets,
            captured=None,
            fresh=chosen_fresh,
            authority=authority,
            terminal=None,
        )
        return ClosurePlan(**fields, plan_sha256=_plan_digest(fields))

    reason_codes: list[str] = ["CAPTURED_ADMISSIBLE_EVIDENCE_ABSENT"]
    if same_identity_exhausted or all(
        row.provider_candidate_id in attempted_provider_ids for row in targets
    ):
        reason_codes.append("SAME_REQUEST_IDENTITY_EXHAUSTED")
    if not any(route.alternate_approved_source for route in fresh_routes):
        reason_codes.append("NO_APPROVED_ALTERNATE_OFFICIAL_SOURCE")
    reason_codes.append("NO_ROUTE_COVERS_EXACT_TARGET")
    target_root = canonical_sha256([row.model_dump(mode="json") for row in targets])
    terminal_fields: dict[str, Any] = {
        "schema_version": "itda.catalog-optional-media-closure-terminal.v1",
        "code": "NON_ADDRESSABLE_REPRESENTATION_FRONTIER",
        "exit_code": 24,
        "frontier_sha256": frontier.frontier_sha256,
        "universe_root_sha256": frontier.universe_root_sha256,
        "target_rows": targets,
        "target_root_sha256": target_root,
        "reason_codes": tuple(reason_codes),
        "authority_request_created": False,
        "credential_accessed": False,
        "provider_traffic_performed": False,
        "plan54_reachable": False,
    }
    terminal = NonAddressableClosureTerminal(
        **terminal_fields,
        terminal_sha256=canonical_sha256(
            {
                **terminal_fields,
                "target_rows": [row.model_dump(mode="json") for row in targets],
            }
        ),
    )
    fields = _plan_fields(
        execution_mode=ClosureExecutionMode.TERMINAL,
        frontier=frontier,
        provider_ids_by_place=provider_ids_by_place,
        attempted_provider_ids=attempted_provider_ids,
        targets=targets,
        captured=None,
        fresh=None,
        authority=None,
        terminal=terminal,
    )
    return ClosurePlan(**fields, plan_sha256=_plan_digest(fields))


def build_current_closure_plan(repository_root: Path | str) -> ClosurePlan:
    """Rebuild the immutable local frontier and derive current addressability."""

    root = Path(repository_root).resolve(strict=True)
    audit = build_optional_media_frontier_audit(root)
    provider_ids, attempted = _provider_bindings(root)
    return derive_closure_plan(
        frontier=audit.first_frontier,
        provider_ids_by_place=provider_ids,
        attempted_provider_ids=attempted,
        captured_routes=(),
        fresh_routes=(),
    )


def _assert_nofollow_ancestors(path: Path) -> None:
    current = path.absolute()
    while True:
        if current.is_symlink():
            raise OptionalMediaClosureError("closure output ancestor is a symlink")
        if current.parent == current:
            return
        current = current.parent


def publish_current_closure_plan(
    repository_root: Path | str,
    *,
    output_root: Path | str | None = None,
) -> Path:
    """Publish only the immutable terminal for the current no-route branch."""

    root = Path(repository_root).resolve(strict=True)
    plan = build_current_closure_plan(root)
    if plan.execution_mode is not ClosureExecutionMode.TERMINAL or plan.terminal is None:
        raise OptionalMediaClosureError("current closure plan is addressable; terminal forbidden")
    base = (
        root / OUTPUT_ROOT_REL if output_root is None else Path(output_root).expanduser().absolute()
    )
    if ".." in Path(output_root).parts if output_root is not None else False:
        raise OptionalMediaClosureError("closure output path escape is forbidden")
    _assert_nofollow_ancestors(base)
    base.mkdir(parents=True, exist_ok=True)
    if base.is_symlink() or not base.is_dir():
        raise OptionalMediaClosureError("closure output root is invalid")
    target = base / "closure-terminal.json"
    payload = canonical_json_bytes(plan.terminal.model_dump(mode="json"))
    entries = list(base.iterdir())
    if entries:
        if len(entries) != 1 or entries[0] != target:
            raise OptionalMediaClosureError("closure terminal output inventory differs")
        if _read_regular_bytes_nofollow(target) != payload:
            raise OptionalMediaClosureError("existing closure terminal bytes differ")
        return target
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        if os.write(descriptor, payload) != len(payload):
            raise OSError("short write while publishing closure terminal")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


class ClosureStreamResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def iter_bytes(self) -> Any: ...


class ClosureStreamRequester(Protocol):
    def stream(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> contextlib.AbstractContextManager[ClosureStreamResponse]: ...


def _authority_parents(plan: ClosurePlan) -> dict[str, object]:
    route = plan.fresh_collection
    request = plan.authority_request
    if (
        plan.execution_mode is not ClosureExecutionMode.FRESH_COLLECTION
        or route is None
        or request is None
    ):
        raise OptionalMediaClosureError("fresh authority requires one exact fresh plan")
    request_parent = route.model_dump(mode="json")
    state_parent = {
        "frontier_sha256": plan.frontier_sha256,
        "universe_root_sha256": plan.universe_root_sha256,
        "attempted_provider_ids": list(plan.attempted_provider_ids),
    }
    target_parent = [row.model_dump(mode="json") for row in plan.target_rows]
    binding_parent = {
        "schema_version": "itda.catalog-optional-media-authority-binding.v1",
        "execution_mode": "fresh_collection",
        "source_manifest_sha256": route.source_manifest_sha256,
        "source_approval_sha256": route.source_approval_sha256,
        "request_sha256": canonical_sha256(request_parent),
        "state_attestation_sha256": canonical_sha256(state_parent),
        "target_sha256": canonical_sha256(target_parent),
        "operation": "catalog-optional-media-close",
    }
    actual = (
        canonical_sha256(request_parent),
        canonical_sha256(state_parent),
        canonical_sha256(target_parent),
        canonical_sha256(binding_parent),
    )
    expected = (
        request.request_sha256,
        request.state_attestation_sha256,
        request.target_sha256,
        request.binding_sha256,
    )
    if actual != expected:
        raise OptionalMediaClosureError("fresh authority parent digests drifted")
    return {
        "request": request_parent,
        "state": state_parent,
        "target": target_parent,
        "binding": binding_parent,
    }


def build_closure_authority_context(
    plan: ClosurePlan,
    *,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> AuthorityIssuanceContext:
    """Freeze the exact Plan 54 authority context without issuing a token."""

    parents = _authority_parents(plan)
    return AuthorityIssuanceContext(
        action="catalog-optional-media-close",
        request_sha256=canonical_sha256(parents["request"]),
        state_attestation_sha256=canonical_sha256(parents["state"]),
        target_sha256=canonical_sha256(parents["target"]),
        reviewer_id=reviewer_id,
        binding_sha256=canonical_sha256(parents["binding"]),
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        reviewer_channel_risk=(
            "reviewer_id is local-channel metadata and is not a cryptographic identity claim"
        ),
    )


def _validate_closure_authority(
    plan: ClosurePlan,
    *,
    authorization_token: str,
    issuance_context: AuthorityIssuanceContext,
    reviewer_id: str,
    now: datetime,
) -> ValidatedAuthority:
    parents = _authority_parents(plan)
    token = AuthorityTokenV2.parse(authorization_token)
    if token.action != "catalog-optional-media-close":
        raise OptionalMediaClosureError("closure authority operation is stale")
    return validate_authority_token(
        authorization_token,
        issuance_context=issuance_context,
        request=parents["request"],
        state_attestation=parents["state"],
        target=parents["target"],
        binding=parents["binding"],
        reviewer_id=reviewer_id,
        now=now,
        revocation_tombstones=(),
    )


def preflight_fresh_collection(
    plan: ClosurePlan,
    *,
    authorization_token: str | None,
    issuance_context: AuthorityIssuanceContext | None = None,
    reviewer_id: str | None = None,
    now: datetime | None = None,
    credential_opener: Any = None,
    dns_resolver: Any = None,
    requester_factory: Any = None,
    nonce_mutator: Any = None,
) -> dict[str, object]:
    """Return the authentication gate before touching any external capability."""

    del credential_opener, dns_resolver, requester_factory, nonce_mutator
    _authority_parents(plan)
    request = plan.authority_request
    if request is None:
        raise OptionalMediaClosureError("fresh authority request is absent")
    if authorization_token is None:
        return {
            "status": "AUTHORIZATION_REQUIRED",
            "operation": "catalog-optional-media-close",
            "request_sha256": request.request_sha256,
            "state_attestation_sha256": request.state_attestation_sha256,
            "target_sha256": request.target_sha256,
            "binding_sha256": request.binding_sha256,
            "credential_opened": False,
            "dns_resolved": False,
            "network_client_opened": False,
            "provider_attempted": False,
            "nonce_mutated": False,
        }
    if issuance_context is None or reviewer_id is None:
        raise OptionalMediaClosureError("fresh authority context and reviewer are required")
    validated = _validate_closure_authority(
        plan,
        authorization_token=authorization_token,
        issuance_context=issuance_context,
        reviewer_id=reviewer_id,
        now=now or datetime.now(UTC),
    )
    return {
        "status": "AUTHORIZED",
        "token_sha256": validated.token_sha256,
        "credential_opened": False,
        "dns_resolved": False,
        "network_client_opened": False,
        "provider_attempted": False,
        "nonce_mutated": False,
    }


def _normalized_row(
    *,
    target: ClosureTargetRow,
    facts: Mapping[str, str],
    source_manifest_sha256: str,
    evidence_sha256: str,
    rights_manifest_sha256: str,
    identity_manifest_sha256: str,
    lineage_manifest_sha256: str,
    response_sha256: str,
    rejected_raw_sha256: str | None = None,
) -> ClosureNormalizedEvidenceRow:
    expected = set(target.non_image_deficits)
    if set(facts) != expected or any(not value for value in facts.values()):
        raise OptionalMediaClosureError("closure normalized facts do not cover the exact target")
    fields: dict[str, object] = {
        "place_entity_id": target.place_entity_id,
        "provider_candidate_id": target.provider_candidate_id,
        "target_row_sha256": target.target_row_sha256,
        "normalized_facts": dict(facts),
        "source_manifest_sha256": source_manifest_sha256,
        "evidence_sha256": evidence_sha256,
        "rights_manifest_sha256": rights_manifest_sha256,
        "identity_manifest_sha256": identity_manifest_sha256,
        "lineage_manifest_sha256": lineage_manifest_sha256,
        "response_sha256": response_sha256,
        "rejected_raw_sha256": rejected_raw_sha256,
    }
    return ClosureNormalizedEvidenceRow.model_validate(
        {**fields, "row_sha256": canonical_sha256(fields)}
    )


def _evidence_envelope(
    *,
    plan: ClosurePlan,
    rows: tuple[ClosureNormalizedEvidenceRow, ...],
    captured_root: str | None,
    request_identity: str | None,
    authority_receipt_sha256: str | None,
    credential_reference_sha256: str | None,
    attempts: tuple[ClosureAttemptReceipt, ...],
    traffic: bool,
) -> ClosureEvidence:
    canonical_rows = tuple(sorted(rows, key=lambda row: row.place_entity_id))
    rows_root = canonical_sha256([row.model_dump(mode="json") for row in canonical_rows])
    fields: dict[str, object] = {
        "schema_version": "itda.catalog-optional-media-closure-evidence.v1",
        "execution_mode": plan.execution_mode.value,
        "closure_plan_sha256": plan.plan_sha256,
        "frontier_sha256": plan.frontier_sha256,
        "universe_root_sha256": plan.universe_root_sha256,
        "target_root_sha256": plan.target_root_sha256,
        "normalized_rows": canonical_rows,
        "normalized_rows_root_sha256": rows_root,
        "captured_evidence_root_sha256": captured_root,
        "fresh_request_identity_sha256": request_identity,
        "authority_receipt_sha256": authority_receipt_sha256,
        "credential_reference_sha256": credential_reference_sha256,
        "attempts": attempts,
        "provider_traffic_performed": traffic,
    }
    digest_fields = {
        **fields,
        "normalized_rows": [row.model_dump(mode="json") for row in canonical_rows],
        "attempts": [attempt.model_dump(mode="json") for attempt in attempts],
    }
    return ClosureEvidence.model_validate(
        {**fields, "evidence_sha256": canonical_sha256(digest_fields)}
    )


def execute_captured_replay(
    repository_root: Path | str,
    *,
    plan: ClosurePlan,
    authorization_token: str | None = None,
    credential_path: Path | str | None = None,
    dns_resolver: Any = None,
    requester: Any = None,
) -> ClosureEvidence:
    """Normalize only bound local evidence while denying all external inputs."""

    if any(
        value is not None
        for value in (authorization_token, credential_path, dns_resolver, requester)
    ):
        raise OptionalMediaClosureError("captured replay forbids every external capability")
    route = plan.captured_replay
    if plan.execution_mode is not ClosureExecutionMode.CAPTURED_REPLAY or route is None:
        raise OptionalMediaClosureError("captured replay requires one exact captured plan")
    root = Path(repository_root).resolve(strict=True)
    manifest = _load_object(root / route.manifest_relative_path)
    expected_manifest = {
        "schema_version": "itda.catalog-optional-media-captured-evidence.v1",
        "source_root_sha256": route.source_root_sha256,
        "evidence_root_sha256": route.evidence_root_sha256,
        "rights_manifest_sha256": route.rights_manifest_sha256,
        "identity_manifest_sha256": route.identity_manifest_sha256,
        "lineage_manifest_sha256": route.lineage_manifest_sha256,
    }
    if any(manifest.get(key) != value for key, value in expected_manifest.items()):
        raise OptionalMediaClosureError("captured evidence manifest binding drifted")
    files = manifest.get("evidence_files")
    if not isinstance(files, Mapping) or tuple(sorted(files)) != route.evidence_relative_paths:
        raise OptionalMediaClosureError("captured evidence file inventory drifted")
    file_digests: list[str] = []
    raw_rows: list[Mapping[str, object]] = []
    for relative in route.evidence_relative_paths:
        payload = _read_regular_bytes_nofollow(root / relative)
        digest = hashlib.sha256(payload).hexdigest()
        if files.get(relative) != digest:
            raise OptionalMediaClosureError("captured evidence file digest drifted")
        file_digests.append(digest)
        parsed = json.loads(payload)
        if not isinstance(parsed, Mapping) or payload != canonical_json_bytes(parsed):
            raise OptionalMediaClosureError("captured evidence file is not canonical")
        rows = parsed.get("rows")
        if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
            raise OptionalMediaClosureError("captured evidence rows are invalid")
        raw_rows.extend(rows)
    if canonical_sha256({"evidence_files": dict(files)}) != route.source_root_sha256:
        raise OptionalMediaClosureError("captured source root drifted")
    if canonical_sha256(file_digests) != route.evidence_root_sha256:
        raise OptionalMediaClosureError("captured evidence root drifted")
    targets = {row.place_entity_id: row for row in plan.target_rows}
    if {str(row.get("place_entity_id")) for row in raw_rows} != set(targets):
        raise OptionalMediaClosureError("captured evidence target coverage is incomplete")
    normalized: list[ClosureNormalizedEvidenceRow] = []
    for raw in raw_rows:
        place_id = str(raw["place_entity_id"])
        target = targets[place_id]
        facts = raw.get("normalized_facts")
        if (
            raw.get("provider_candidate_id") != target.provider_candidate_id
            or not isinstance(facts, Mapping)
            or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in facts.items()
            )
        ):
            raise OptionalMediaClosureError("captured evidence identity or facts drifted")
        normalized.append(
            _normalized_row(
                target=target,
                facts={str(key): str(value) for key, value in facts.items()},
                source_manifest_sha256=route.source_root_sha256,
                evidence_sha256=str(raw["evidence_sha256"]),
                rights_manifest_sha256=route.rights_manifest_sha256,
                identity_manifest_sha256=route.identity_manifest_sha256,
                lineage_manifest_sha256=route.lineage_manifest_sha256,
                response_sha256=str(raw["response_sha256"]),
            )
        )
    return _evidence_envelope(
        plan=plan,
        rows=tuple(normalized),
        captured_root=route.evidence_root_sha256,
        request_identity=None,
        authority_receipt_sha256=None,
        credential_reference_sha256=None,
        attempts=(),
        traffic=False,
    )


def _json_depth(value: object) -> int:
    maximum = 1
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        maximum = max(maximum, depth)
        if isinstance(current, Mapping):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return maximum


def inspect_closure_response_bounded(
    response: ClosureStreamResponse,
    *,
    bounds: FreshCollectionBounds,
) -> dict[str, object]:
    """Buffer hostile bytes within route bounds before parsing any JSON."""

    status = int(response.status_code)
    if 300 <= status <= 399:
        raise OptionalMediaClosureError("provider redirect is forbidden")
    if status != 200:
        raise OptionalMediaClosureError(f"provider HTTP status {status} is not successful")
    length = next(
        (
            str(value)
            for key, value in response.headers.items()
            if str(key).casefold() == "content-length"
        ),
        None,
    )
    if length is not None and (not length.isdigit() or int(length) > bounds.max_response_bytes):
        raise OptionalMediaClosureError("provider response byte limit exceeded")
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        value = bytes(chunk)
        total += len(value)
        if total > bounds.max_response_bytes:
            raise OptionalMediaClosureError("provider response byte size limit exceeded")
        chunks.append(value)
    raw = b"".join(chunks)
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OptionalMediaClosureError("provider response is not bounded JSON") from exc
    if _json_depth(parsed) > bounds.max_json_depth:
        raise OptionalMediaClosureError("provider response JSON depth limit exceeded")
    try:
        header = parsed["response"]["header"]
        body = parsed["response"].get("body", {})
    except (KeyError, TypeError, AttributeError) as exc:
        raise OptionalMediaClosureError("provider response envelope is invalid") from exc
    if not isinstance(header, Mapping) or str(header.get("resultCode")) not in {"00", "0000"}:
        raise OptionalMediaClosureError("provider response result is not successful")
    items_value = body.get("items", {}) if isinstance(body, Mapping) else {}
    items = items_value.get("item", []) if isinstance(items_value, Mapping) else []
    if isinstance(items, Mapping):
        rows = [dict(items)]
    elif isinstance(items, list) and all(isinstance(item, Mapping) for item in items):
        rows = [dict(item) for item in items]
    elif items in (None, ""):
        rows = []
    else:
        raise OptionalMediaClosureError("provider response item shape is invalid")
    if len(rows) > bounds.max_items:
        raise OptionalMediaClosureError("provider response item limit exceeded")
    return {
        "raw": raw,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "rows": rows,
        "safe_headers": {
            str(key).casefold(): str(value)[:500]
            for key, value in response.headers.items()
            if str(key).casefold() in SAFE_RESPONSE_HEADERS
        },
    }


def _read_closure_credential(path: Path, *, reference: str) -> str:
    expected_path, variable = reference.split(":", 1)
    if path.as_posix().endswith(expected_path) is False and path.name != Path(expected_path).name:
        raise OptionalMediaClosureError("credential descriptor does not match the route reference")
    payload = _read_regular_bytes_nofollow(path)
    metadata = path.stat(follow_symlinks=False)
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise OptionalMediaClosureError("credential descriptor must be private mode 0600")
    values: dict[str, str] = {}
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise OptionalMediaClosureError("credential descriptor is not UTF-8") from exc
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise OptionalMediaClosureError("credential descriptor assignment is invalid")
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            raise OptionalMediaClosureError("credential descriptor assignment is invalid")
        values[key] = value
    if variable not in values:
        raise OptionalMediaClosureError("credential descriptor lacks the required variable")
    return values[variable]


def execute_fresh_collection(
    repository_root: Path | str,
    *,
    plan: ClosurePlan,
    authorization_token: str,
    issuance_context: AuthorityIssuanceContext,
    reviewer_id: str,
    now: datetime,
    credential_path: Path | str | None = None,
    credential_opener: Any = None,
    requester: Any,
) -> ClosureEvidence:
    """Execute one exact bounded fresh route after complete authority validation."""

    validated = _validate_closure_authority(
        plan,
        authorization_token=authorization_token,
        issuance_context=issuance_context,
        reviewer_id=reviewer_id,
        now=now,
    )
    route = plan.fresh_collection
    if route is None:
        raise OptionalMediaClosureError("fresh route is absent")
    if credential_opener is not None:
        credential = credential_opener()
    elif credential_path is not None:
        credential = _read_closure_credential(
            Path(credential_path).expanduser(),
            reference=route.credential_reference,
        )
    else:
        raise OptionalMediaClosureError("fresh collection requires a credential descriptor")
    if not isinstance(credential, str) or not credential:
        raise OptionalMediaClosureError("credential descriptor returned no secret")
    if not hasattr(requester, "stream"):
        raise OptionalMediaClosureError("fresh requester does not implement bounded streaming")
    root = Path(repository_root).resolve(strict=True)
    private_root = root / "artifacts/restricted/catalog/v2/closure-runtime"
    attempts: list[ClosureAttemptReceipt] = []
    inspected: dict[str, object] | None = None

    def mutation() -> Mapping[str, object]:
        nonlocal inspected
        url = f"https://{route.host}{route.path}"
        for ordinal in range(1, route.bounds.max_attempts + 1):
            status: int | None = None
            try:
                with requester.stream(
                    "GET",
                    url,
                    params={**route.secret_free_parameters, "serviceKey": credential},
                    timeout=route.bounds.per_attempt_timeout_seconds,
                    follow_redirects=False,
                ) as response:
                    status = int(response.status_code)
                    inspected = inspect_closure_response_bounded(response, bounds=route.bounds)
            except (OSError, TimeoutError, OptionalMediaClosureError):
                transient = (
                    status is None
                    or status in {408, 429}
                    or (status is not None and 500 <= status <= 599)
                )
                outcome = (
                    "TRANSIENT_RETRY"
                    if transient and ordinal < route.bounds.max_attempts
                    else "TERMINAL_FAILURE"
                )
                failure_fields: dict[str, object] = {
                    "ordinal": ordinal,
                    "request_identity_sha256": route.request_identity_sha256,
                    "provider": route.provider,
                    "operation": route.operation,
                    "http_status": status,
                    "outcome": outcome,
                    "raw_response_sha256": hashlib.sha256(b"").hexdigest(),
                    "private_response_ref_sha256": canonical_sha256(
                        {"retained": False, "ordinal": ordinal}
                    ),
                    "safe_headers": {},
                }
                attempts.append(
                    ClosureAttemptReceipt.model_validate(
                        {
                            **failure_fields,
                            "receipt_sha256": canonical_sha256(failure_fields),
                        }
                    )
                )
                if outcome == "TRANSIENT_RETRY":
                    continue
                raise
            raw_value = inspected["raw"]
            if not isinstance(raw_value, bytes):
                raise OptionalMediaClosureError("inspected provider body is not bytes")
            raw = raw_value
            if credential.encode("utf-8") in raw:
                raise OptionalMediaClosureError("provider response reflected credential material")
            raw_sha = str(inspected["raw_sha256"])
            response_root = private_root / raw_sha
            response_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            raw_path = response_root / "response.json"
            if raw_path.exists():
                if _read_regular_bytes_nofollow(raw_path) != raw:
                    raise OptionalMediaClosureError("private response digest substitution")
            else:
                descriptor = os.open(
                    raw_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    if os.write(descriptor, raw) != len(raw):
                        raise OSError("short write while storing private response")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            receipt_fields: dict[str, object] = {
                "ordinal": ordinal,
                "request_identity_sha256": route.request_identity_sha256,
                "provider": route.provider,
                "operation": route.operation,
                "http_status": 200,
                "outcome": "SUCCESS",
                "raw_response_sha256": raw_sha,
                "private_response_ref_sha256": canonical_sha256(
                    {"root": raw_sha, "name": "response.json"}
                ),
                "safe_headers": inspected["safe_headers"],
            }
            attempts.append(
                ClosureAttemptReceipt.model_validate(
                    {
                        **receipt_fields,
                        "receipt_sha256": canonical_sha256(receipt_fields),
                    }
                )
            )
            return {"result_sha256": raw_sha}
        raise OptionalMediaClosureError("fresh collection exhausted its bounded attempts")

    ledger = FileNonceLedger(private_root)
    authority_receipt = ledger.consume_with_mutation(validated, mutation=mutation)
    if inspected is None:
        raise OptionalMediaClosureError("fresh collection produced no inspected response")
    request_identity = route.request_identity_sha256
    if request_identity is None:
        raise OptionalMediaClosureError("fresh request identity is absent")
    targets_by_provider = {
        row.provider_candidate_id.removeprefix("candidate:tour-api:"): row
        for row in plan.target_rows
    }
    normalized: list[ClosureNormalizedEvidenceRow] = []
    inspected_rows = inspected["rows"]
    if not isinstance(inspected_rows, list):
        raise OptionalMediaClosureError("inspected provider rows are not a list")
    for item in inspected_rows:
        if not isinstance(item, Mapping):
            continue
        provider_id = str(item.get("contentid", ""))
        target = targets_by_provider.get(provider_id)
        if target is None:
            continue
        facts: dict[str, str] = {}
        if "description" in target.non_image_deficits:
            description = str(item.get("overview", "")).strip()
            if description:
                facts["description"] = description
        if "operating_information" in target.non_image_deficits:
            excluded = {"contentid", "contenttypeid", "overview"}
            values = [
                f"{key}={value}"
                for key, value in sorted(item.items())
                if key not in excluded and str(value).strip()
            ]
            if values:
                facts["operating_information"] = "\n".join(values)
        normalized.append(
            _normalized_row(
                target=target,
                facts=facts,
                source_manifest_sha256=route.source_manifest_sha256,
                evidence_sha256=canonical_sha256(dict(item)),
                rights_manifest_sha256=route.source_approval_sha256,
                identity_manifest_sha256=route.deterministic_id_join_sha256,
                lineage_manifest_sha256=request_identity,
                response_sha256=str(inspected["raw_sha256"]),
            )
        )
    credential = ""
    return _evidence_envelope(
        plan=plan,
        rows=tuple(normalized),
        captured_root=None,
        request_identity=request_identity,
        authority_receipt_sha256=authority_receipt.receipt_sha256,
        credential_reference_sha256=canonical_sha256(
            {"credential_reference": route.credential_reference}
        ),
        attempts=tuple(attempts),
        traffic=True,
    )


def _candidate_with_closure(
    candidate: OptionalMediaCandidate,
    evidence: ClosureNormalizedEvidenceRow,
) -> OptionalMediaCandidate:
    gates_payload = candidate.non_image_gates.model_dump(mode="json")
    for field in evidence.normalized_facts:
        gates_payload[field] = GateState.PASS
    gates = NonImageEligibilityGates.model_validate(gates_payload)
    fields = candidate.model_dump(exclude={"row_sha256"}, mode="json")
    fields.update(
        {
            "non_image_gates": gates,
            "catalog_eligible": gates.eligible,
            "non_image_failure_reasons": gates.failure_reasons,
            "historical_row_sha256": canonical_sha256(
                {
                    "previous_historical_row_sha256": candidate.historical_row_sha256,
                    "closure_evidence_row_sha256": evidence.row_sha256,
                }
            ),
        }
    )
    digest_fields = {
        **fields,
        "non_image_gates": gates.model_dump(mode="json"),
        "image_medium": candidate.image_medium.model_dump(mode="json"),
    }
    return OptionalMediaCandidate(
        **fields,
        row_sha256=canonical_sha256(digest_fields),
    )


def _failure_finalization(
    plan: ClosurePlan,
    evidence: ClosureEvidence,
    status: str,
    reason: str,
) -> dict[str, object]:
    fields: dict[str, object] = {
        "schema_version": "itda.catalog-optional-media-closure-finalization.v1",
        "status": status,
        "reason": reason,
        "execution_mode": evidence.execution_mode,
        "closure_plan_sha256": plan.plan_sha256,
        "base_universe_root_sha256": plan.universe_root_sha256,
        "normalized_evidence_root_sha256": evidence.normalized_rows_root_sha256,
        "plan20_reachable": False,
        "review_files_created": False,
    }
    return {**fields, "finalization_sha256": canonical_sha256(fields)}


def _verify_historical_review_finalization(
    finalization: Mapping[str, object],
) -> dict[str, object]:
    """Validate the immutable Plan 53 schema at its historical adapter boundary."""

    value = dict(finalization)
    if value.get("schema_version") != "itda.catalog-optional-media-closure-finalization.v1":
        raise OptionalMediaClosureError("historical review finalization schema is stale")
    if value.get("status") != "FEASIBLE" or value.get("plan20_reachable") is not True:
        raise OptionalMediaClosureError("historical review requires exact FEASIBLE success")
    digest_fields = {key: item for key, item in value.items() if key != "finalization_sha256"}
    if value.get("finalization_sha256") != canonical_sha256(digest_fields):
        raise OptionalMediaClosureError("historical review finalization digest is stale")
    first = value.get("first_frontier_sha256")
    second = value.get("second_frontier_sha256")
    if value.get("replays_byte_identical") is not True or first != second:
        raise OptionalMediaClosureError("historical review replay roots differ")
    group_counts = value.get("group_counts")
    quotas = value.get("final_quotas")
    if (
        not isinstance(group_counts, Mapping)
        or tuple(group_counts) != GROUP_ORDER
        or any(
            not isinstance(group_counts[group], int)
            or isinstance(group_counts[group], bool)
            or group_counts[group] < 6
            for group in GROUP_ORDER
        )
    ):
        raise OptionalMediaClosureError("historical review group counts are infeasible")
    if (
        not isinstance(quotas, Mapping)
        or tuple(quotas) != GROUP_ORDER
        or any(
            not isinstance(quotas[group], int)
            or isinstance(quotas[group], bool)
            or not 6 <= quotas[group] <= 12
            for group in GROUP_ORDER
        )
        or sum(int(quotas[group]) for group in GROUP_ORDER) != 36
        or value.get("quota_sum") != 36
    ):
        raise OptionalMediaClosureError("historical review quota proof is invalid")
    eligible = value.get("eligible_pool")
    if (
        not isinstance(eligible, list)
        or value.get("eligible_count") != len(eligible)
        or value.get("eligible_pool_sha256") != canonical_sha256(eligible)
    ):
        raise OptionalMediaClosureError("historical review eligible pool is stale")
    decisions = value.get("unresolved_human_decisions")
    if (
        not isinstance(decisions, list)
        or value.get("unresolved_human_decision_count") != len(decisions)
        or len(decisions) > 6
    ):
        raise OptionalMediaClosureError("historical review decisions are invalid")
    if value.get("ordering_rule") != (
        "group-ordinal-then-canonical-utf8-source-neutral-id"
    ):
        raise OptionalMediaClosureError("historical review ordering rule is stale")
    return value


def _historical_review_payloads(
    finalization: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    success = _verify_historical_review_finalization(finalization)
    eligible_pool = success["eligible_pool"]
    if not isinstance(eligible_pool, list):
        raise OptionalMediaClosureError("historical review eligible pool is unavailable")
    request_fields: dict[str, object] = {
        "schema_version": "itda.catalog-v2-review-request.v1",
        "operation": "catalog-adjudicate-select",
        "finalization_sha256": success["finalization_sha256"],
        "execution_mode": success["execution_mode"],
        "policy_version": success["policy_version"],
        "policy_sha256": success["policy_sha256"],
        "base_universe_root_sha256": success["base_universe_root_sha256"],
        "extended_universe_root_sha256": success["extended_universe_root_sha256"],
        "normalized_evidence_root_sha256": success["normalized_evidence_root_sha256"],
        "frontier_sha256": success["first_frontier_sha256"],
        "eligible_pool": eligible_pool,
        "eligible_pool_sha256": success["eligible_pool_sha256"],
        "eligible_count": success["eligible_count"],
        "group_counts": success["group_counts"],
        "final_quotas": success["final_quotas"],
        "quota_sum": 36,
        "unresolved_human_decisions": success["unresolved_human_decisions"],
        "unresolved_human_decision_count": success["unresolved_human_decision_count"],
        "ordering_rule": success["ordering_rule"],
        "plan20_reachable": True,
        "catalog_membership_selected": False,
        "authority_issued": False,
    }
    request = {**request_fields, "request_sha256": canonical_sha256(request_fields)}
    state_fields: dict[str, object] = {
        "schema_version": "itda.catalog-v2-review-state-attestation.v1",
        "request_sha256": request["request_sha256"],
        "finalization_sha256": success["finalization_sha256"],
        "policy_sha256": success["policy_sha256"],
        "extended_universe_root_sha256": success["extended_universe_root_sha256"],
        "normalized_evidence_root_sha256": success["normalized_evidence_root_sha256"],
        "eligible_pool_sha256": success["eligible_pool_sha256"],
        "frontier_sha256": success["first_frontier_sha256"],
        "plan20_reachable": True,
    }
    state = {
        **state_fields,
        "state_attestation_sha256": canonical_sha256(state_fields),
    }
    view_fields: dict[str, object] = {
        "schema_version": "itda.catalog-v2-review-view.v1",
        "request_sha256": request["request_sha256"],
        "state_attestation_sha256": state["state_attestation_sha256"],
        "eligible_place_ids": [
            row["place_entity_id"] for row in eligible_pool if isinstance(row, Mapping)
        ],
        "final_quotas": success["final_quotas"],
        "unresolved_human_decisions": success["unresolved_human_decisions"],
        "ordering_rule": success["ordering_rule"],
        "informational_only": True,
        "plan20_reachable": True,
    }
    view = {**view_fields, "view_sha256": canonical_sha256(view_fields)}
    return {
        "catalog-review-request.json": request,
        "catalog-review-view.json": view,
        "catalog-state-attestation.json": state,
    }


def _publish_historical_review_bundle(
    finalization: Mapping[str, object],
    destination: Path | str,
) -> None:
    output = Path(destination)
    if output.exists():
        raise FileExistsError("historical review bundle is immutable and already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    prepared = Path(tempfile.mkdtemp(prefix=f".{output.name}.prepared-", dir=output.parent))
    published = False
    try:
        for filename, payload in _historical_review_payloads(finalization).items():
            path = prepared / filename
            content = canonical_json_bytes(payload)
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                if os.write(descriptor, content) != len(content):
                    raise OSError("short write while publishing historical review bundle")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.rename(prepared, output)
        published = True
    finally:
        if not published and prepared.exists():
            shutil.rmtree(prepared)


def finalize_closure_evidence(
    repository_root: Path | str,
    *,
    plan: ClosurePlan,
    evidence: ClosureEvidence,
    review_output_root: Path | str | None = None,
) -> dict[str, object]:
    """Apply exact evidence and independently replay the full universe twice."""

    if (
        plan.execution_mode is ClosureExecutionMode.TERMINAL
        or evidence.closure_plan_sha256 != plan.plan_sha256
        or evidence.frontier_sha256 != plan.frontier_sha256
        or evidence.universe_root_sha256 != plan.universe_root_sha256
        or evidence.target_root_sha256 != plan.target_root_sha256
        or evidence.execution_mode != plan.execution_mode.value
    ):
        return _failure_finalization(
            plan,
            evidence,
            "CLOSURE_EVIDENCE_INSUFFICIENT",
            "closure evidence binding differs from the plan",
        )
    target_ids = {row.place_entity_id for row in plan.target_rows}
    evidence_by_id = {row.place_entity_id: row for row in evidence.normalized_rows}
    if set(evidence_by_id) != target_ids:
        return _failure_finalization(
            plan,
            evidence,
            "CLOSURE_EVIDENCE_INSUFFICIENT",
            "normalized evidence does not cover every exact target",
        )
    base_projection = build_optional_media_frontier_audit(
        Path(repository_root).resolve(strict=True)
    ).first_projection
    first_candidates = tuple(
        _candidate_with_closure(candidate, evidence_by_id[candidate.place_entity_id])
        if candidate.place_entity_id in evidence_by_id
        else candidate
        for candidate in base_projection.candidates
    )
    second_candidates = tuple(
        _candidate_with_closure(candidate, evidence_by_id[candidate.place_entity_id])
        if candidate.place_entity_id in evidence_by_id
        else candidate
        for candidate in base_projection.candidates
    )
    extended_root = canonical_sha256(
        {
            "schema_version": "itda.catalog-optional-media-extended-universe.v1",
            "base_universe_root_sha256": plan.universe_root_sha256,
            "closure_plan_sha256": plan.plan_sha256,
            "closure_evidence_sha256": evidence.evidence_sha256,
            "normalized_evidence_root_sha256": evidence.normalized_rows_root_sha256,
            "candidate_rows_root_sha256": canonical_sha256(
                [row.model_dump(mode="json") for row in first_candidates]
            ),
        }
    )
    first = evaluate_optional_media_frontier(
        first_candidates,
        base_projection.policy,
        extended_root,
    )
    second = evaluate_optional_media_frontier(
        second_candidates,
        base_projection.policy,
        extended_root,
    )
    try:
        compare_frontier_replays(first, second)
    except ValueError:
        return _failure_finalization(
            plan,
            evidence,
            "REPRESENTATION_INFEASIBLE_AFTER_CLOSURE",
            "full-universe closure replays differ",
        )
    feasible = (
        first.eligible_count >= 36
        and all(first.group_counts[group] >= 6 for group in GROUP_ORDER)
        and first.capped_capacity >= 36
        and first.representation_quota.feasible
        and first.representation_quota.quota_sum == 36
    )
    if not feasible:
        return _failure_finalization(
            plan,
            evidence,
            "REPRESENTATION_INFEASIBLE_AFTER_CLOSURE",
            "representation constraints remain infeasible",
        )

    def eligible_sort_key(row: OptionalMediaAccountingRow) -> tuple[int, bytes]:
        group = row.representation_primary_group
        if group is None:
            raise OptionalMediaClosureError("eligible replay row lacks a representation group")
        return GROUP_ORDER.index(group), row.place_entity_id.encode("utf-8")

    eligible_pool = [
        {
            "place_entity_id": row.place_entity_id,
            "representation_primary_group": row.representation_primary_group,
            "candidate_row_sha256": row.candidate_row_sha256,
        }
        for row in sorted(
            (row for row in first.accounting_rows if row.eligible),
            key=eligible_sort_key,
        )
    ]
    fields: dict[str, object] = {
        "schema_version": "itda.catalog-optional-media-closure-finalization.v1",
        "status": "FEASIBLE",
        "execution_mode": evidence.execution_mode,
        "closure_plan_sha256": plan.plan_sha256,
        "policy_version": base_projection.policy.policy_version,
        "policy_sha256": base_projection.policy.policy_sha256,
        "base_universe_root_sha256": plan.universe_root_sha256,
        "extended_universe_root_sha256": extended_root,
        "normalized_evidence_root_sha256": evidence.normalized_rows_root_sha256,
        "first_frontier_sha256": first.frontier_sha256,
        "second_frontier_sha256": second.frontier_sha256,
        "replays_byte_identical": True,
        "eligible_count": first.eligible_count,
        "group_counts": first.group_counts,
        "capped_capacity": first.capped_capacity,
        "final_quotas": first.representation_quota.final_quotas,
        "quota_sum": first.representation_quota.quota_sum,
        "eligible_pool": eligible_pool,
        "eligible_pool_sha256": canonical_sha256(eligible_pool),
        "unresolved_human_decisions": [],
        "unresolved_human_decision_count": 0,
        "ordering_rule": "group-ordinal-then-canonical-utf8-source-neutral-id",
        "plan20_reachable": True,
    }
    result = {**fields, "finalization_sha256": canonical_sha256(fields)}
    if review_output_root is not None:
        _publish_historical_review_bundle(result, review_output_root)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    plan = subcommands.add_parser("plan")
    modes = plan.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--check", action="store_true")
    execute = subcommands.add_parser("execute")
    execute_modes = execute.add_mutually_exclusive_group(required=True)
    execute_modes.add_argument("--captured-replay", action="store_true")
    execute_modes.add_argument("--fresh-preflight", action="store_true")
    execute_modes.add_argument("--fresh-collection", action="store_true")
    execute_modes.add_argument("--finalize", action="store_true")
    execute.add_argument("--repo-root", type=Path)
    execute.add_argument("--plan-file", type=Path, required=True)
    execute.add_argument("--evidence-file", type=Path)
    execute.add_argument("--issuance-context-file", type=Path)
    execute.add_argument("--reviewer-id")
    execute.add_argument("--credential-file", type=Path)
    execute.add_argument("--authorization-token-stdin", action="store_true")
    execute.add_argument("--output-file", type=Path)
    execute.add_argument("--review-output-root", type=Path)
    return parser


def _load_contract(path: Path, model: type[BaseModel]) -> BaseModel:
    payload = _load_object(path)
    parsed = model.model_validate(payload)
    if canonical_json_bytes(parsed.model_dump(mode="json")) != canonical_json_bytes(payload):
        raise OptionalMediaClosureError("closure contract contains noncanonical fields")
    return parsed


def _publish_no_replace(path: Path, payload: Mapping[str, object]) -> None:
    if path.exists():
        raise FileExistsError("closure output is immutable and already exists")
    _assert_nofollow_ancestors(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = canonical_json_bytes(payload)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        if os.write(descriptor, content) != len(content):
            raise OSError("short write while publishing closure output")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stdin_authority_token() -> str:
    payload = sys.stdin.read(65_537)
    lines = payload.splitlines()
    if len(payload) > 65_536 or len(lines) != 1 or not lines[0]:
        raise OptionalMediaClosureError("stdin must contain one bounded authority token")
    return lines[0]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository_root = Path(__file__).resolve().parents[4]
    if args.command == "plan":
        plan = build_current_closure_plan(repository_root)
        if args.build:
            publish_current_closure_plan(repository_root)
        else:
            target = repository_root / OUTPUT_ROOT_REL / "closure-terminal.json"
            if plan.terminal is None or _read_regular_bytes_nofollow(target) != (
                canonical_json_bytes(plan.terminal.model_dump(mode="json"))
            ):
                raise OptionalMediaClosureError("recorded closure terminal differs")
        print(plan.plan_sha256)
        return 24 if plan.execution_mode is ClosureExecutionMode.TERMINAL else 0
    if args.command == "execute":
        root = (
            args.repo_root.resolve(strict=True) if args.repo_root is not None else repository_root
        )
        plan_model = _load_contract(args.plan_file, ClosurePlan)
        if not isinstance(plan_model, ClosurePlan):
            raise AssertionError("closure plan model dispatch failed")
        if args.captured_replay:
            if (
                args.output_file is None
                or any(
                    value is not None
                    for value in (
                        args.evidence_file,
                        args.issuance_context_file,
                        args.reviewer_id,
                        args.credential_file,
                        args.review_output_root,
                    )
                )
                or args.authorization_token_stdin
            ):
                raise OptionalMediaClosureError(
                    "captured replay accepts only repo, plan, and output"
                )
            evidence = execute_captured_replay(root, plan=plan_model)
            _publish_no_replace(args.output_file, evidence.model_dump(mode="json"))
            print(evidence.evidence_sha256)
            return 0
        if args.fresh_preflight:
            if (
                any(
                    value is not None
                    for value in (
                        args.evidence_file,
                        args.issuance_context_file,
                        args.reviewer_id,
                        args.credential_file,
                        args.output_file,
                        args.review_output_root,
                    )
                )
                or args.authorization_token_stdin
            ):
                raise OptionalMediaClosureError("fresh preflight accepts no external input")
            result = preflight_fresh_collection(
                plan_model,
                authorization_token=None,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 25
        if args.fresh_collection:
            if (
                args.issuance_context_file is None
                or args.reviewer_id is None
                or args.credential_file is None
                or args.output_file is None
                or not args.authorization_token_stdin
                or args.evidence_file is not None
                or args.review_output_root is not None
            ):
                raise OptionalMediaClosureError(
                    "fresh collection requires context, reviewer, credential, token stdin, output"
                )
            context_model = _load_contract(
                args.issuance_context_file,
                AuthorityIssuanceContext,
            )
            if not isinstance(context_model, AuthorityIssuanceContext):
                raise AssertionError("authority context model dispatch failed")
            token = _stdin_authority_token()
            with httpx.Client(follow_redirects=False) as client:
                evidence = execute_fresh_collection(
                    root,
                    plan=plan_model,
                    authorization_token=token,
                    issuance_context=context_model,
                    reviewer_id=args.reviewer_id,
                    now=datetime.now(UTC),
                    credential_path=args.credential_file,
                    requester=client,
                )
            token = ""
            _publish_no_replace(args.output_file, evidence.model_dump(mode="json"))
            print(evidence.evidence_sha256)
            return 0
        if (
            args.evidence_file is None
            or args.output_file is None
            or args.review_output_root is None
            or any(
                value is not None
                for value in (
                    args.issuance_context_file,
                    args.reviewer_id,
                    args.credential_file,
                )
            )
            or args.authorization_token_stdin
        ):
            raise OptionalMediaClosureError(
                "finalize requires plan, evidence, result output, and review output root"
            )
        evidence_model = _load_contract(args.evidence_file, ClosureEvidence)
        if not isinstance(evidence_model, ClosureEvidence):
            raise AssertionError("closure evidence model dispatch failed")
        result = finalize_closure_evidence(
            root,
            plan=plan_model,
            evidence=evidence_model,
            review_output_root=args.review_output_root,
        )
        _publish_no_replace(args.output_file, result)
        print(result["finalization_sha256"])
        return 0 if result["status"] == "FEASIBLE" else 26
    raise AssertionError("unreachable closure command")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OUTPUT_ROOT_REL",
    "OptionalMediaClosureError",
    "build_closure_authority_context",
    "build_current_closure_plan",
    "derive_closure_plan",
    "execute_captured_replay",
    "execute_fresh_collection",
    "finalize_closure_evidence",
    "inspect_closure_response_bounded",
    "main",
    "preflight_fresh_collection",
    "publish_current_closure_plan",
]
