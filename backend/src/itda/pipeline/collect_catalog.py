"""Deterministic planning and validation for the Phase 2 catalog collection."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from itda.collectors import snapshots as snapshot_store
from itda.collectors.base import CollectionError, OfficialApiClient
from itda.contracts.catalog_collection import (
    EXPECTED_PERMISSION_DATASET_IDS,
    CatalogRequest,
    CollectionAttempt,
    CollectionPlan,
    CollectionReport,
    CoverageSeedManifest,
    CredentialPreflightResult,
    CredentialReference,
    LiveReportValidation,
    NormalizedCandidate,
    PermissionEvidenceSet,
    PermissionPageSnapshot,
    PermissionRequirement,
    PermissionTermsProjection,
    RequestIdentity,
    SeedCoverageDisposition,
    SuccessfulSnapshotEvidence,
    build_request_identity,
    select_resume_identities,
)
from itda.domain.canonical import canonical_sha256

if TYPE_CHECKING:
    from collections.abc import Callable

    from itda.collectors.diagnostics import ProviderDiagnostics

COLLECTION_PLAN_VERSION = "catalog-v1"
COLLECTOR_VERSION = "catalog-collector-v1"
COLLECTION_SCHEMA_VERSION = "catalog-collection-v1"
RESTRICTED_OUTPUT_ROOT = "artifacts/restricted/catalog/v1/collection"
_EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest()

_PERMISSION_REQUIREMENTS = (
    PermissionRequirement(
        provider="TOUR_API",
        official_dataset_id="15101578",
        official_url="https://www.data.go.kr/data/15101578/openapi.do",
        expected_terms="PUBLIC_DATASET_TERMS_REVIEW_REQUIRED",
    ),
    PermissionRequirement(
        provider="ODII",
        official_dataset_id="15101971",
        official_url="https://www.data.go.kr/data/15101971/openapi.do",
        expected_terms="PUBLIC_DATASET_TERMS_REVIEW_REQUIRED",
    ),
    PermissionRequirement(
        provider="TOURISM_PHOTO",
        official_dataset_id="15101914",
        official_url="https://www.data.go.kr/data/15101914/openapi.do",
        expected_terms="KOGL_TYPE_1_ATTRIBUTION",
    ),
)


def load_coverage_seed(path: Path) -> CoverageSeedManifest:
    """Load the immutable public seed without rewriting or assigning membership."""

    try:
        payload = json.loads(path.read_bytes())
        return CoverageSeedManifest.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ValueError("coverage seed is unavailable or invalid") from exc


def _catalog_request(
    *,
    provider: str,
    official_dataset_id: str,
    operation: str,
    transport_operation: str,
    scope: str,
    parameters: dict[str, str],
    page_ceiling: int,
    credential_reference: CredentialReference,
) -> CatalogRequest:
    fields = {
        "provider": provider,
        "official_dataset_id": official_dataset_id,
        "operation": operation,
        "transport_operation": transport_operation,
        "scope": scope,
        "secret_free_parameters": parameters,
        "page_ceiling": page_ceiling,
        "per_attempt_timeout_seconds": 300,
        "max_attempts": 3,
        "initial_backoff_seconds": 1.0,
        "max_backoff_seconds": 300.0,
        "credential_reference": credential_reference.model_dump(mode="json"),
    }
    return CatalogRequest.model_validate(
        {**fields, "request_template_sha256": canonical_sha256(fields)}
    )


def build_collection_plan(seed: CoverageSeedManifest) -> CollectionPlan:
    """Build the one canonical tiny-then-broad, three-provider request plan."""

    tour_ref = CredentialReference(
        provider_label="tourapi",
        path=".secrets/itda-api.env",
        variable_name="TOUR_API_SERVICE_KEY",
        reference=".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
    )
    odii_ref = CredentialReference(
        provider_label="odii",
        path=".secrets/itda-odii.env",
        variable_name="ODII_SERVICE_KEY",
        reference=".secrets/itda-odii.env:ODII_SERVICE_KEY",
    )
    photo_ref = CredentialReference(
        provider_label="tourism-photo",
        path=".secrets/itda-api.env",
        variable_name="TOUR_API_SERVICE_KEY",
        reference=".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
    )
    tiny_rows = "1"
    broad_rows = "100"
    requests = (
        _catalog_request(
            provider="TOUR_API",
            official_dataset_id="15101578",
            operation="areaBasedList2",
            transport_operation="areaBasedList2",
            scope="TINY",
            parameters={
                "MobileApp": "IT-DA",
                "MobileOS": "ETC",
                "_type": "json",
                "lDongRegnCd": "47",
                "lDongSignguCd": "130",
                "numOfRows": tiny_rows,
            },
            page_ceiling=1,
            credential_reference=tour_ref,
        ),
        _catalog_request(
            provider="ODII",
            official_dataset_id="15101971",
            operation="themeSearchList",
            transport_operation="themeSearchList",
            scope="TINY",
            parameters={
                "MobileApp": "IT-DA",
                "MobileOS": "ETC",
                "_type": "json",
                "langCode": "ko",
                "keyword": "경주",
                "numOfRows": tiny_rows,
            },
            page_ceiling=1,
            credential_reference=odii_ref,
        ),
        _catalog_request(
            provider="TOURISM_PHOTO",
            official_dataset_id="15101914",
            operation="search",
            transport_operation="gallerySearchList1",
            scope="TINY",
            parameters={
                "MobileApp": "IT-DA",
                "MobileOS": "ETC",
                "_type": "json",
                "keyword": "경주",
                "numOfRows": tiny_rows,
            },
            page_ceiling=1,
            credential_reference=photo_ref,
        ),
        _catalog_request(
            provider="TOUR_API",
            official_dataset_id="15101578",
            operation="areaBasedList2",
            transport_operation="areaBasedList2",
            scope="BROAD",
            parameters={
                "MobileApp": "IT-DA",
                "MobileOS": "ETC",
                "_type": "json",
                "lDongRegnCd": "47",
                "lDongSignguCd": "130",
                "numOfRows": broad_rows,
            },
            page_ceiling=10,
            credential_reference=tour_ref,
        ),
        _catalog_request(
            provider="ODII",
            official_dataset_id="15101971",
            operation="themeSearchList",
            transport_operation="themeSearchList",
            scope="BROAD",
            parameters={
                "MobileApp": "IT-DA",
                "MobileOS": "ETC",
                "_type": "json",
                "langCode": "ko",
                "keyword": "경주",
                "numOfRows": broad_rows,
            },
            page_ceiling=10,
            credential_reference=odii_ref,
        ),
        _catalog_request(
            provider="TOURISM_PHOTO",
            official_dataset_id="15101914",
            operation="search",
            transport_operation="gallerySearchList1",
            scope="BROAD",
            parameters={
                "MobileApp": "IT-DA",
                "MobileOS": "ETC",
                "_type": "json",
                "keyword": "경주",
                "numOfRows": broad_rows,
            },
            page_ceiling=10,
            credential_reference=photo_ref,
        ),
    )
    permission_requirements_sha256 = canonical_sha256(
        [item.model_dump(mode="json") for item in _PERMISSION_REQUIREMENTS]
    )
    fields = {
        "collection_plan_version": COLLECTION_PLAN_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "schema_version": COLLECTION_SCHEMA_VERSION,
        "seed_manifest_sha256": seed.seed_manifest_sha256,
        "permission_requirements": [
            item.model_dump(mode="json") for item in _PERMISSION_REQUIREMENTS
        ],
        "permission_requirements_sha256": permission_requirements_sha256,
        "requests": [item.model_dump(mode="json") for item in requests],
        "restricted_output_root": RESTRICTED_OUTPUT_ROOT,
    }
    return CollectionPlan.model_validate(
        {**fields, "collection_plan_sha256": canonical_sha256(fields)}
    )


def build_permission_snapshot(
    *,
    official_dataset_id: str,
    official_url: str,
    retrieved_at: datetime,
    terms_projection: PermissionTermsProjection | dict[str, object],
    response_bytes: bytes,
) -> PermissionPageSnapshot:
    """Project one exact page body into a hash-bound, independently usable record."""

    terms = PermissionTermsProjection.model_validate(terms_projection)
    fields = {
        "schema_version": "permission-page-snapshot-v1",
        "official_dataset_id": official_dataset_id,
        "official_url": official_url,
        "retrieved_at": retrieved_at.isoformat().replace("+00:00", "Z"),
        "terms_projection": terms.model_dump(mode="json"),
        "page_response_sha256": hashlib.sha256(response_bytes).hexdigest(),
    }
    return PermissionPageSnapshot.model_validate(
        {**fields, "snapshot_sha256": canonical_sha256(fields)}
    )


def _has_symlinked_component(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    return any(component.is_symlink() for component in (absolute, *absolute.parents))


def _variable_name_present(path: Path, expected_variable_name: str) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > 16_384:
            raise ValueError("credential file exceeds the preflight size limit")
        payload = os.read(descriptor, 16_385)
        if len(payload) != metadata.st_size:
            raise ValueError("credential file changed during preflight")
    finally:
        os.close(descriptor)
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("credential file must be valid UTF-8") from exc
    names: list[str] = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("credential file contains an invalid assignment")
        name, value = line.split("=", maxsplit=1)
        if not name or not value or name in names:
            raise ValueError("credential file contains an invalid assignment")
        names.append(name)
    return names.count(expected_variable_name) == 1


def preflight_credential_reference(
    *,
    provider_label: str,
    credential_reference: str,
    expected_path: Path,
    expected_variable_name: str,
) -> CredentialPreflightResult:
    """Verify only file/name shape and return no credential material."""

    expected_reference = f"{expected_path}:{expected_variable_name}"
    if credential_reference != expected_reference:
        raise ValueError("credential reference does not match the plan-bound reference")
    if _has_symlinked_component(expected_path):
        raise ValueError("credential path must not traverse a symlink")
    try:
        metadata = expected_path.lstat()
    except OSError as exc:
        raise ValueError("credential file is unavailable") from exc
    regular_file = stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
    no_symlink = not expected_path.is_symlink()
    owned = metadata.st_uid == os.getuid()
    private = stat.S_IMODE(metadata.st_mode) == 0o600
    if not (regular_file and no_symlink and owned and private):
        raise ValueError("credential file fails regular/owner/mode preflight")
    present = _variable_name_present(expected_path, expected_variable_name)
    if not present:
        raise ValueError("credential variable name is absent")
    return CredentialPreflightResult(
        provider_label=provider_label,
        reference=credential_reference,
        regular_file=regular_file,
        no_symlink=no_symlink,
        owned_by_current_user=owned,
        mode_0600=private,
        variable_name_present=present,
    )


def validate_permission_evidence(
    snapshots: Iterable[PermissionPageSnapshot],
) -> PermissionEvidenceSet:
    return PermissionEvidenceSet.from_snapshots(snapshots)


def _iter_candidate_items(value: object) -> Iterable[dict[str, object]]:
    if isinstance(value, dict):
        if any(key in value for key in ("contentid", "contentId", "storyId", "galContentId")):
            yield value
        for child in value.values():
            yield from _iter_candidate_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_candidate_items(child)


def _first_text(
    item: Mapping[str, object],
    names: tuple[str, ...],
) -> str | None:
    for name in names:
        value = item.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int):
            return str(value)
    return None


def _normalize_candidates(
    *,
    provider: str,
    official_dataset_id: str,
    payload: object,
    request_identity: str,
    raw_response_sha256: str,
    permission_snapshot_sha256: str,
    region_bound_request: bool,
) -> tuple[NormalizedCandidate, ...]:
    id_fields = {
        "TOUR_API": ("contentid", "contentId"),
        "ODII": ("storyId", "tid", "tlid"),
        "TOURISM_PHOTO": ("galContentId",),
    }[provider]
    name_fields = {
        "TOUR_API": ("title", "name"),
        "ODII": ("storyTitle", "themeName", "title"),
        "TOURISM_PHOTO": ("galTitle",),
    }[provider]
    location_fields = (
        "addr1",
        "addr2",
        "address",
        "galPhotographyLocation",
        "themeName",
        "storyTitle",
    )
    provider_label = provider.casefold().replace("_", "-")
    normalized: list[NormalizedCandidate] = []
    seen_content_ids: set[str] = set()
    for item in _iter_candidate_items(payload):
        content_id = _first_text(item, id_fields)
        name = _first_text(item, name_fields)
        location = _first_text(item, location_fields)
        if content_id is None or name is None or content_id in seen_content_ids:
            continue
        if not region_bound_request and not (location is not None and "경주" in location):
            continue
        seen_content_ids.add(content_id)
        normalized.append(
            NormalizedCandidate.model_validate(
                {
                    "candidate_id": f"candidate:{provider_label}:{content_id}",
                    "name_ko": name,
                    "gyeongju_evidence": (
                        "request:lDongRegnCd=47,lDongSignguCd=130"
                        if region_bound_request
                        else f"response:{location}"
                    ),
                    "provider": provider,
                    "official_dataset_id": official_dataset_id,
                    "provider_content_id": content_id,
                    "request_identity": request_identity,
                    "raw_response_sha256": raw_response_sha256,
                    "permission_snapshot_sha256": permission_snapshot_sha256,
                }
            )
        )
    return tuple(normalized)


def _derive_seed_dispositions(
    seed: CoverageSeedManifest,
    candidates: tuple[NormalizedCandidate, ...],
    evidence_hashes: tuple[str, ...],
) -> tuple[SeedCoverageDisposition, ...]:
    by_exact_name: dict[str, NormalizedCandidate] = {}
    for normalized_candidate in candidates:
        by_exact_name.setdefault(
            normalized_candidate.name_ko.replace(" ", ""),
            normalized_candidate,
        )
    fallback_evidence = evidence_hashes or (_EMPTY_BODY_SHA256,)
    dispositions: list[SeedCoverageDisposition] = []
    for row in seed.rows:
        matched_candidate = by_exact_name.get(row.name_ko.replace(" ", ""))
        if matched_candidate is None:
            dispositions.append(
                SeedCoverageDisposition(
                    seed_id=row.seed_id,
                    status="MISSING_WITH_EVIDENCE",
                    candidate_id=None,
                    reason=("no exact normalized Korean name match in the authorized collection"),
                    evidence_sha256=fallback_evidence,
                )
            )
        else:
            dispositions.append(
                SeedCoverageDisposition(
                    seed_id=row.seed_id,
                    status="LINKED",
                    candidate_id=matched_candidate.candidate_id,
                    reason=("exact normalized Korean name match in collected provider evidence"),
                    evidence_sha256=(matched_candidate.raw_response_sha256,),
                )
            )
    return tuple(dispositions)


def _snapshot_evidence(
    *,
    request_identity: str,
    path: Path,
    output_root: Path,
    before: tuple[str, int] | None,
) -> SuccessfulSnapshotEvidence:
    after_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    after_mtime = path.stat().st_mtime_ns
    before_hash, before_mtime = before or (after_hash, after_mtime)
    return SuccessfulSnapshotEvidence(
        request_identity=request_identity,
        relative_path=path.relative_to(output_root).as_posix(),
        before_sha256=before_hash,
        after_sha256=after_hash,
        before_mtime_ns=before_mtime,
        after_mtime_ns=after_mtime,
    )


def _planned_identities(
    plan: CollectionPlan,
) -> tuple[tuple[CatalogRequest, RequestIdentity], ...]:
    planned: list[tuple[CatalogRequest, RequestIdentity]] = []
    for request in plan.requests:
        for page in range(1, request.page_ceiling + 1):
            parameters = dict(request.secret_free_parameters)
            parameters["pageNo"] = str(page)
            identity = build_request_identity(
                provider=request.provider,
                official_dataset_id=request.official_dataset_id,
                operation=request.operation,
                secret_free_parameters=parameters,
                page=page,
                collection_plan_version=plan.collection_plan_version,
                collector_version=plan.collector_version,
                schema_version=plan.schema_version,
                plan_sha256=plan.collection_plan_sha256,
            )
            planned.append((request, identity))
    return tuple(planned)


def collect_catalog(
    *,
    plan: CollectionPlan,
    seed: CoverageSeedManifest,
    permission_evidence: PermissionEvidenceSet,
    clients: Mapping[str, OfficialApiClient],
    output_root: Path,
    resume_report: CollectionReport | None = None,
    terminal_recovery_dataset_id: str | None = None,
    diagnostics: ProviderDiagnostics | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> CollectionReport:
    """Execute an already authorized plan with injected fixed-host clients."""

    if any(
        snapshot.terms_projection.availability != "AVAILABLE"
        or not snapshot.terms_projection.commercial_use
        or not snapshot.terms_projection.derivative_use
        for snapshot in permission_evidence.snapshots
    ):
        raise ValueError("permission evidence is unavailable or does not permit use")
    if (
        resume_report is not None
        and resume_report.collection_plan_sha256 != plan.collection_plan_sha256
    ):
        raise ValueError("resume report does not match the current plan")
    if terminal_recovery_dataset_id is None:
        if set(clients) != {"TOUR_API", "ODII", "TOURISM_PHOTO"}:
            raise ValueError("collection requires exactly three provider clients")
    elif (
        terminal_recovery_dataset_id != "15101914"
        or resume_report is None
        or set(clients) != {"TOURISM_PHOTO"}
    ):
        raise ValueError("terminal recovery is restricted to PhotoGallery dataset 15101914")

    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_root.chmod(0o700)
    snapshot_directory = output_root / "snapshots"
    previous_attempts = () if resume_report is None else resume_report.attempts
    previous_identities = () if resume_report is None else resume_report.request_identities
    previous_candidates = () if resume_report is None else resume_report.candidates
    previous_snapshot_by_identity = {
        item.request_identity: item
        for item in (() if resume_report is None else resume_report.resume_evidence)
    }
    identities: list[RequestIdentity] = list(previous_identities)
    identity_ids = {item.request_identity for item in identities}
    attempts: list[CollectionAttempt] = list(previous_attempts)
    candidates_by_id = {item.candidate_id: item for item in previous_candidates}
    snapshot_evidence_by_identity: dict[str, SuccessfulSnapshotEvidence] = {}
    permission_by_dataset = {
        item.official_dataset_id: item for item in permission_evidence.snapshots
    }
    generated = _planned_identities(plan)
    if terminal_recovery_dataset_id is None:
        resume_ids = {
            item.request_identity
            for item in select_resume_identities(
                (identity for _, identity in generated),
                attempts,
            )
        }
    else:
        generated_ids = {identity.request_identity for _, identity in generated}
        if {item.request_identity for item in previous_identities} != generated_ids:
            raise ValueError("recovery report does not contain the exact planned identities")
        latest_attempts: dict[str, CollectionAttempt] = {}
        for attempt in attempts:
            previous = latest_attempts.get(attempt.request_identity)
            if previous is None or attempt.attempt_number >= previous.attempt_number:
                latest_attempts[attempt.request_identity] = attempt
        recovery_identities = tuple(
            identity
            for request, identity in generated
            if request.provider == "TOURISM_PHOTO"
            and request.official_dataset_id == terminal_recovery_dataset_id
        )
        if len(recovery_identities) != 11:
            raise ValueError("PhotoGallery recovery must contain exactly 11 identities")
        if any(
            latest_attempts.get(identity.request_identity) is None
            or latest_attempts[identity.request_identity].terminal_state
            != "TERMINAL_OPERATOR_ACTION"
            or latest_attempts[identity.request_identity].retry_classification != "DO_NOT_RETRY"
            for identity in recovery_identities
        ):
            raise ValueError(
                "PhotoGallery recovery requires the prior 11 terminal operator-action attempts"
            )
        non_recovery_ids = generated_ids - {
            identity.request_identity for identity in recovery_identities
        }
        if len(non_recovery_ids) != 22 or any(
            latest_attempts.get(identity_id) is None
            or latest_attempts[identity_id].terminal_state != "SUCCESS"
            for identity_id in non_recovery_ids
        ):
            raise ValueError("PhotoGallery recovery requires 22 prior provider successes")
        resume_ids = {identity.request_identity for identity in recovery_identities}

    for request, identity in generated:
        if identity.request_identity not in identity_ids:
            identities.append(identity)
            identity_ids.add(identity.request_identity)
        previous_snapshot = previous_snapshot_by_identity.get(identity.request_identity)
        if identity.request_identity not in resume_ids:
            if previous_snapshot is not None:
                snapshot_evidence_by_identity[identity.request_identity] = _snapshot_evidence(
                    request_identity=identity.request_identity,
                    path=output_root / previous_snapshot.relative_path,
                    output_root=output_root,
                    before=(
                        previous_snapshot.after_sha256,
                        previous_snapshot.after_mtime_ns,
                    ),
                )
            continue

        diagnostic_operation = None
        if diagnostics is not None:
            diagnostic_operation = diagnostics.operation(
                candidate_place_id=identity.request_identity,
                candidate_name=(f"{request.scope}:{request.provider}:{identity.page}"),
                provider=request.provider,
                operation=request.transport_operation,
                plan_sha256=plan.collection_plan_sha256,
            )
        parameters = dict(request.secret_free_parameters)
        parameters["pageNo"] = str(identity.page)
        client = clients[request.provider]
        for name, expected_value in client.common_parameters.items():
            if parameters.get(name) != expected_value:
                raise ValueError("authorized common parameter does not match the provider adapter")
            del parameters[name]
        previous_attempt_number = max(
            (
                item.attempt_number
                for item in attempts
                if item.request_identity == identity.request_identity
            ),
            default=0,
        )
        try:
            collected = client.request(
                request.transport_operation,
                parameters,
                explicit_opt_in=True,
                diagnostics=diagnostics,
                diagnostic_operation=diagnostic_operation,
            )
            path = snapshot_store.write_snapshot_for_resume(collected, snapshot_directory)
            no_data = collected.normalized_outcome == "NO_DATA"
            attempts.append(
                CollectionAttempt(
                    request_identity=identity.request_identity,
                    attempt_number=min(5, previous_attempt_number + 1),
                    terminal_state="NO_DATA" if no_data else "SUCCESS",
                    http_status=collected.http_status,
                    provider_result_code=collected.provider_result_code,
                    provider_result_value=collected.provider_result_value,
                    normalized_failure_reason=(
                        "provider returned a valid no-data result" if no_data else None
                    ),
                    terminal_reason="provider returned no data" if no_data else None,
                    retry_classification="DO_NOT_RETRY",
                    raw_body_sha256=collected.raw_response_sha256,
                    raw_body_retention="IMMUTABLE",
                    safe_headers={},
                )
            )
            snapshot_evidence_by_identity[identity.request_identity] = _snapshot_evidence(
                request_identity=identity.request_identity,
                path=path,
                output_root=output_root,
                before=None,
            )
            permission = permission_by_dataset[request.official_dataset_id]
            for candidate in _normalize_candidates(
                provider=request.provider,
                official_dataset_id=request.official_dataset_id,
                payload=collected.payload,
                request_identity=identity.request_identity,
                raw_response_sha256=collected.raw_response_sha256,
                permission_snapshot_sha256=permission.snapshot_sha256,
                region_bound_request=(
                    request.provider == "TOUR_API" and request.operation == "areaBasedList2"
                ),
            ):
                candidates_by_id.setdefault(candidate.candidate_id, candidate)
        except CollectionError as exc:
            retryable = exc.retry_disposition == "RETRYABLE_FOR_RESUME"
            attempts.append(
                CollectionAttempt(
                    request_identity=identity.request_identity,
                    attempt_number=min(
                        5,
                        previous_attempt_number + (request.max_attempts if retryable else 1),
                    ),
                    terminal_state=(
                        "RETRYABLE_FOR_RESUME" if retryable else "TERMINAL_OPERATOR_ACTION"
                    ),
                    http_status=exc.http_status,
                    provider_result_code=exc.provider_result_code,
                    provider_result_value=exc.provider_result_value,
                    normalized_failure_reason=(exc.normalized_failure_reason or str(exc)),
                    terminal_reason=str(exc),
                    retry_classification=("RETRYABLE_FOR_RESUME" if retryable else "DO_NOT_RETRY"),
                    raw_body_sha256=exc.raw_body_sha256 or _EMPTY_BODY_SHA256,
                    raw_body_retention=(
                        "IMMUTABLE_ATTEMPT_SNAPSHOT"
                        if exc.raw_body_sha256
                        else "REDACTED_SECRET_REFLECTION"
                    ),
                    safe_headers={},
                )
            )

    candidates = tuple(candidates_by_id.values())
    evidence_hashes = tuple(dict.fromkeys(attempt.raw_body_sha256 for attempt in attempts))
    dispositions = _derive_seed_dispositions(seed, candidates, evidence_hashes)
    report_fields = {
        "schema_version": "catalog-collection-report-v1",
        "collection_plan_sha256": plan.collection_plan_sha256,
        "seed_manifest_sha256": seed.seed_manifest_sha256,
        "permission_evidence": permission_evidence.model_dump(mode="json"),
        "request_identities": [item.model_dump(mode="json") for item in identities],
        "attempts": [item.model_dump(mode="json") for item in attempts],
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "seed_dispositions": [item.model_dump(mode="json") for item in dispositions],
        "resume_evidence": [
            item.model_dump(mode="json") for item in snapshot_evidence_by_identity.values()
        ],
        "generated_at": clock().isoformat().replace("+00:00", "Z"),
    }
    return CollectionReport.model_validate(
        {**report_fields, "report_sha256": canonical_sha256(report_fields)}
    )


def load_collection_report(path: Path) -> CollectionReport:
    try:
        return CollectionReport.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise ValueError("collection report is unavailable or invalid") from exc


def validate_collection_report(
    *,
    report: CollectionReport,
    current_plan: CollectionPlan,
    required_dataset_ids: tuple[str, ...] = EXPECTED_PERMISSION_DATASET_IDS,
    minimum_candidate_count: int = 60,
    require_terminal_plan_completeness: bool = True,
    require_resume_proof: bool = True,
) -> LiveReportValidation:
    """Read-only validation of completeness, provenance, and immutable resume proof."""

    if report.collection_plan_sha256 != current_plan.collection_plan_sha256:
        raise ValueError("collection report does not match the current plan")
    permission_ids = tuple(
        item.official_dataset_id for item in report.permission_evidence.snapshots
    )
    if permission_ids != required_dataset_ids:
        raise ValueError("collection report permission datasets do not match")
    identity_ids = {item.request_identity for item in report.request_identities}
    latest_attempts: dict[str, CollectionAttempt] = {}
    for attempt in report.attempts:
        if attempt.request_identity not in identity_ids:
            raise ValueError("attempt is not bound to a planned request identity")
        previous = latest_attempts.get(attempt.request_identity)
        if previous is None or attempt.attempt_number >= previous.attempt_number:
            latest_attempts[attempt.request_identity] = attempt
    terminal_complete = bool(identity_ids) and identity_ids == set(latest_attempts)
    if require_terminal_plan_completeness and not terminal_complete:
        raise ValueError("not every planned request has a terminal state")
    detailed_failures = all(
        attempt.terminal_state == "SUCCESS"
        or bool(attempt.normalized_failure_reason or attempt.terminal_reason)
        for attempt in report.attempts
    )
    if not detailed_failures:
        raise ValueError("collection report contains an undetailed failure")
    resume_valid = bool(report.resume_evidence) and all(
        item.before_sha256 == item.after_sha256 and item.before_mtime_ns == item.after_mtime_ns
        for item in report.resume_evidence
    )
    if require_resume_proof and not resume_valid:
        raise ValueError("collection report lacks immutable resume proof")
    unique_candidates = len({item.candidate_id for item in report.candidates})
    if unique_candidates < minimum_candidate_count:
        raise ValueError("collection report does not meet the candidate threshold")
    all_seed_dispositions = len(report.seed_dispositions) == 36
    if not all_seed_dispositions:
        raise ValueError("collection report does not cover all seed rows")
    return LiveReportValidation(
        schema_version="catalog-live-report-validation-v1",
        report_sha256=report.report_sha256,
        collection_plan_sha256=current_plan.collection_plan_sha256,
        required_dataset_ids=required_dataset_ids,
        terminal_plan_complete=terminal_complete,
        minimum_candidate_count=minimum_candidate_count,
        actual_unique_candidate_count=unique_candidates,
        all_seed_dispositions_present=all_seed_dispositions,
        detailed_failures_present=detailed_failures,
        resume_proof_valid=resume_valid,
        valid=True,
    )


__all__ = [
    "COLLECTION_PLAN_VERSION",
    "COLLECTION_SCHEMA_VERSION",
    "COLLECTOR_VERSION",
    "RESTRICTED_OUTPUT_ROOT",
    "build_collection_plan",
    "build_permission_snapshot",
    "collect_catalog",
    "load_collection_report",
    "load_coverage_seed",
    "preflight_credential_reference",
    "validate_collection_report",
    "validate_permission_evidence",
]
