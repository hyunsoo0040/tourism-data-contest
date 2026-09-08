"""Strict network-disabled contracts for the supplemental catalog preflight."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_readiness import GROUP_ORDER, RepresentationGroup
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

SOURCE_PRIORITY = ("15114464", "15109381", "3070426")
TARGET_VECTOR: dict[RepresentationGroup, int] = {
    "history_culture": 12,
    "history_scenery_boundary": 6,
    "image_modern_content": 6,
    "rest_walk_immersion": 0,
}
REQUIRED_TARGET_COUNT = 24
MAX_FRONTIER_COUNT = 60
REQUIRED_PROJECTED_TOTAL = 37
REQUIRED_GROUP_FLOOR = 6
REQUIRED_CAPPED_SUM = 36
ATTEMPT_SECONDS = 300

MandatoryDeficit = Literal[
    "DESCRIPTION_MISSING",
    "DIRECT_MEDIA_MISSING",
    "OPERATING_INFO_MISSING",
]
RequiredField = Literal[
    "korean_description",
    "media_url",
    "media_creator",
    "media_license",
    "operating_information",
]


class SourceCapabilityState(StrEnum):
    """Documentation-derived source capability states."""

    RESEARCH_RECORDED_CAPABILITY = "RESEARCH_RECORDED_CAPABILITY"
    SCHEMA_CAPABLE = "SCHEMA_CAPABLE"


class RecordAvailabilityState(StrEnum):
    """Record-level states that never alias schema capability."""

    RECORD_AVAILABILITY_UNVERIFIED = "RECORD_AVAILABILITY_UNVERIFIED"
    EXACT_LOCAL_ID_MATCH = "EXACT_LOCAL_ID_MATCH"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNAVAILABLE = "UNAVAILABLE"


def _validate_repo_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "://" in value
        or value.startswith("/")
        or path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
    ):
        raise ValueError("path must be repository-contained and relative")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_single_regular(repo_root: Path, relpath: str) -> bytes:
    """Read one repository-contained regular file without following a symlink."""

    _validate_repo_relative(relpath)
    root = repo_root.resolve(strict=True)
    candidate = root.joinpath(*PurePosixPath(relpath).parts)
    parent = candidate.parent.resolve(strict=True)
    if parent != root and root not in parent.parents:
        raise ValueError("capture path escapes repository root")
    before = os.lstat(candidate)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("capture must be a single-link regular file")
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("capture identity changed before read")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("capture changed during read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


class OfficialSourceCapability(StrictContract):
    """One unrefreshed research-recorded field-capability claim."""

    source_priority: Annotated[int, Field(strict=True, ge=0, le=2)]
    official_source_id: Literal["15114464", "15109381", "3070426"]
    official_source_url: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=2_000),
    ]
    capability_state: SourceCapabilityState
    documented_fields: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=120)],
        ...,
    ]
    research_file_sha256: Sha256
    research_date: Literal["2026-07-30"]
    refreshed_during_preflight: Literal[False]
    proves_record_availability: Literal[False]
    proves_rights: Literal[False]

    @model_validator(mode="after")
    def validate_priority(self) -> Self:
        if SOURCE_PRIORITY[self.source_priority] != self.official_source_id:
            raise ValueError("official source priority drifted")
        if self.documented_fields != tuple(sorted(set(self.documented_fields))):
            raise ValueError("documented fields require canonical unique order")
        return self


class PredeclaredLocalCapture(StrictContract):
    """One exact local capture supplied before this preflight generation."""

    repository_relative_path: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    file_sha256: Sha256
    official_source_id: Literal["15114464", "15109381", "3070426"]
    official_record_or_page_id: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=500),
    ]
    place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    present_required_fields: tuple[RequiredField, ...]
    supplied_before_preflight: Literal[True]
    import_disposition: Literal[
        "PREDECLARED_CAPTURE_REQUIRES_PLAN39_RIGHTS_VERIFICATION"
    ]

    @model_validator(mode="after")
    def validate_capture(self) -> Self:
        _validate_repo_relative(self.repository_relative_path)
        if len(set(self.present_required_fields)) != len(
            self.present_required_fields
        ):
            raise ValueError("capture fields must be unique")
        return self


class TargetRow(StrictContract):
    """One source-neutral acquisition target with no membership or score."""

    place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    existing_provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    primary_coverage_group: RepresentationGroup
    mandatory_deficits: tuple[MandatoryDeficit, ...]
    mandatory_deficit_count: Annotated[int, Field(strict=True, ge=1, le=3)]
    under_target_group_need: Annotated[int, Field(strict=True, ge=0, le=12)]
    proposed_source_ids: tuple[Literal["15114464", "15109381", "3070426"], ...]
    required_fields: tuple[RequiredField, ...]
    record_availability: RecordAvailabilityState
    predeclared_capture: PredeclaredLocalCapture | None
    confidence_adds_score: Literal[False]
    canonical_membership_created: Literal[False]
    split_membership_created: Literal[False]

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.primary_coverage_group == "rest_walk_immersion":
            raise ValueError("fixed 24-addition vector contains no rest target")
        if self.mandatory_deficit_count != len(self.mandatory_deficits):
            raise ValueError("mandatory deficit count is not row-derived")
        if len(set(self.mandatory_deficits)) != len(self.mandatory_deficits):
            raise ValueError("mandatory deficits must be unique")
        if self.proposed_source_ids != SOURCE_PRIORITY:
            raise ValueError("official source priority drifted")
        if len(set(self.required_fields)) != len(self.required_fields):
            raise ValueError("required fields must be unique")
        exact = self.record_availability is RecordAvailabilityState.EXACT_LOCAL_ID_MATCH
        if exact != (self.predeclared_capture is not None):
            raise ValueError("exact record availability requires one predeclared capture")
        if self.predeclared_capture is not None and (
            self.predeclared_capture.place_entity_id != self.place_entity_id
        ):
            raise ValueError("capture is bound to a different place identity")
        return self


class TargetMatrix(StrictContract):
    schema_version: Literal["itda.catalog-remediation-target-matrix.v1"]
    ordered_ancestry: tuple[Sha256, ...]
    attempted_provider_ids: tuple[str, ...]
    attempted_provider_ids_root: Sha256
    frontier_count_before_cap: Annotated[int, Field(strict=True, ge=24)]
    frontier_cap: Literal[60]
    comparator: Literal[
        "mandatory-deficit-count-asc_group-need-desc_source-neutral-id-utf8-asc"
    ]
    rows: tuple[TargetRow, ...]
    target_count: Literal[24]
    addition_vector: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    terminal_objective_eligible_count: Literal[13]
    terminal_eligible_group_counts: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    confidence_adds_score: Literal[False]
    canonical_membership_created: Literal[False]
    split_membership_created: Literal[False]
    matrix_sha256: Sha256

    @model_validator(mode="after")
    def validate_matrix(self) -> Self:
        if len(self.ordered_ancestry) < 4 or len(set(self.ordered_ancestry)) != len(
            self.ordered_ancestry
        ):
            raise ValueError("ordered terminal-plus-supplemental ancestry is incomplete")
        if self.attempted_provider_ids != tuple(
            sorted(set(self.attempted_provider_ids))
        ):
            raise ValueError("attempted provider identities are not canonical")
        if self.attempted_provider_ids_root != canonical_sha256(
            list(self.attempted_provider_ids)
        ):
            raise ValueError("attempted provider identity root drifted")
        if self.addition_vector != TARGET_VECTOR:
            raise ValueError("fixed 12/6/6 target vector drifted")
        if set(self.terminal_eligible_group_counts) != set(GROUP_ORDER):
            raise ValueError("terminal group inventory is incomplete")
        if len(self.rows) != self.target_count:
            raise ValueError("target count is not row-derived")
        if len({row.place_entity_id for row in self.rows}) != len(self.rows):
            raise ValueError("target matrix repeats a source-neutral identity")
        if any(
            row.existing_provider_candidate_id in self.attempted_provider_ids
            for row in self.rows
        ):
            raise ValueError("target matrix includes an ancestry-attempted provider ID")
        counts = Counter(row.primary_coverage_group for row in self.rows)
        if {group: counts[group] for group in GROUP_ORDER} != TARGET_VECTOR:
            raise ValueError("target rows do not satisfy the fixed 12/6/6 vector")
        expected = canonical_sha256(
            self.model_dump(exclude={"matrix_sha256"}, mode="json")
        )
        if self.matrix_sha256 != expected:
            raise ValueError("target matrix digest drifted")
        return self


def build_target_matrix(
    *,
    frontier: Sequence[TargetRow],
    ordered_ancestry: Sequence[str],
    attempted_provider_ids: Sequence[str],
    terminal_eligible_group_counts: Mapping[RepresentationGroup, int],
    terminal_objective_eligible_count: int,
) -> TargetMatrix:
    """Filter the full frontier first, then preserve the exact fixed vector."""

    attempted = tuple(sorted(set(attempted_provider_ids)))
    available = [
        row
        for row in frontier
        if row.existing_provider_candidate_id not in set(attempted)
    ]
    ranked = sorted(
        available,
        key=lambda row: (
            row.mandatory_deficit_count,
            -row.under_target_group_need,
            row.place_entity_id.encode("utf-8"),
        ),
    )[:MAX_FRONTIER_COUNT]
    selected: list[TargetRow] = []
    remaining = dict(TARGET_VECTOR)
    for row in ranked:
        if remaining[row.primary_coverage_group] <= 0:
            continue
        selected.append(row)
        remaining[row.primary_coverage_group] -= 1
        if not any(remaining.values()):
            break
    if any(remaining.values()) or len(selected) != REQUIRED_TARGET_COUNT:
        raise ValueError("frontier cannot preserve the fixed 12/6/6 target vector")
    if sum(
        row.mandatory_deficits
        == ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING")
        for row in selected
    ) != 21 or sum(
        row.mandatory_deficits == ("OPERATING_INFO_MISSING",)
        for row in selected
    ) != 3:
        raise ValueError("fixed 21 description/media plus three operating shape drifted")
    fields = {
        "schema_version": "itda.catalog-remediation-target-matrix.v1",
        "ordered_ancestry": tuple(ordered_ancestry),
        "attempted_provider_ids": attempted,
        "attempted_provider_ids_root": canonical_sha256(list(attempted)),
        "frontier_count_before_cap": len(available),
        "frontier_cap": 60,
        "comparator": (
            "mandatory-deficit-count-asc_group-need-desc_"
            "source-neutral-id-utf8-asc"
        ),
        "rows": [row.model_dump(mode="json") for row in selected],
        "target_count": 24,
        "addition_vector": TARGET_VECTOR,
        "terminal_objective_eligible_count": terminal_objective_eligible_count,
        "terminal_eligible_group_counts": {
            group: terminal_eligible_group_counts[group] for group in GROUP_ORDER
        },
        "confidence_adds_score": False,
        "canonical_membership_created": False,
        "split_membership_created": False,
    }
    return TargetMatrix(**fields, matrix_sha256=canonical_sha256(fields))


class ConfirmedCoverageBound(StrictContract):
    """Schema-capable ceiling and separately capture-confirmed floor."""

    schema_version: Literal["itda.catalog-confirmed-coverage-bound.v1"]
    schema_capable_target_count: Literal[24]
    confirmed_target_count: Annotated[int, Field(strict=True, ge=0, le=24)]
    terminal_objective_eligible_count: Literal[13]
    confirmed_projected_total: Annotated[int, Field(strict=True, ge=13)]
    confirmed_group_counts: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    confirmed_capped_sum: Annotated[int, Field(strict=True, ge=0, le=48)]
    target_serviceability: tuple[bool, ...]
    all_target_deficits_serviceable: bool
    representation_feasible: bool
    rights_status: Literal["PENDING_PLAN39_VERIFICATION"]
    outcome: Literal["FEASIBLE", "INSUFFICIENT_CONFIRMED_COVERAGE"]
    bound_sha256: Sha256

    @model_validator(mode="after")
    def validate_bound(self) -> Self:
        if self.confirmed_projected_total != (
            self.terminal_objective_eligible_count + self.confirmed_target_count
        ):
            raise ValueError("confirmed total is not row-derived")
        if set(self.confirmed_group_counts) != set(GROUP_ORDER):
            raise ValueError("confirmed group inventory is incomplete")
        if self.confirmed_capped_sum != sum(
            min(12, self.confirmed_group_counts[group]) for group in GROUP_ORDER
        ):
            raise ValueError("confirmed capped sum is not row-derived")
        if len(self.target_serviceability) != 24:
            raise ValueError("target serviceability must cover all 24 rows")
        if self.all_target_deficits_serviceable != all(self.target_serviceability):
            raise ValueError("target serviceability aggregate drifted")
        expected_feasible = (
            self.confirmed_projected_total >= REQUIRED_PROJECTED_TOTAL
            and all(
                self.confirmed_group_counts[group] >= REQUIRED_GROUP_FLOOR
                for group in GROUP_ORDER
            )
            and self.confirmed_capped_sum >= REQUIRED_CAPPED_SUM
            and self.all_target_deficits_serviceable
        )
        if self.representation_feasible != expected_feasible:
            raise ValueError("confirmed feasibility is not row-derived")
        if self.outcome != (
            "FEASIBLE"
            if expected_feasible
            else "INSUFFICIENT_CONFIRMED_COVERAGE"
        ):
            raise ValueError("confirmed coverage outcome drifted")
        expected = canonical_sha256(
            self.model_dump(exclude={"bound_sha256"}, mode="json")
        )
        if self.bound_sha256 != expected:
            raise ValueError("confirmed coverage bound digest drifted")
        return self


def _capture_services_target(
    *,
    target: TargetRow,
    repo_root: Path,
) -> bool:
    capture = target.predeclared_capture
    if capture is None:
        return False
    raw = _read_single_regular(repo_root, capture.repository_relative_path)
    if _sha256(raw) != capture.file_sha256:
        raise ValueError("capture hash does not match predeclared bytes")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("capture is not JSON") from error
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError("capture must be canonical JSON")
    if (
        payload.get("official_dataset_id") != capture.official_source_id
        or payload.get("official_record_id")
        != capture.official_record_or_page_id
        or payload.get("place_entity_id") != target.place_entity_id
    ):
        raise ValueError("capture does not prove the exact source/record identity")
    values = payload.get("fields")
    if not isinstance(values, dict):
        raise ValueError("capture lacks an exact field object")
    required = set(target.required_fields)
    if not required.issubset(capture.present_required_fields):
        raise ValueError("capture declaration omits target-required fields")
    return all(field in values and values[field] not in (None, "", [], {}) for field in required)


def build_confirmed_coverage_bound(
    *,
    matrix: TargetMatrix,
    repo_root: Path,
) -> ConfirmedCoverageBound:
    serviceability = tuple(
        _capture_services_target(target=row, repo_root=repo_root)
        for row in matrix.rows
    )
    confirmed_rows = tuple(
        row
        for row, confirmed in zip(matrix.rows, serviceability, strict=True)
        if confirmed
    )
    confirmed_group_counts = {
        group: matrix.terminal_eligible_group_counts[group]
        + sum(row.primary_coverage_group == group for row in confirmed_rows)
        for group in GROUP_ORDER
    }
    confirmed_count = len(confirmed_rows)
    fields = {
        "schema_version": "itda.catalog-confirmed-coverage-bound.v1",
        "schema_capable_target_count": 24,
        "confirmed_target_count": confirmed_count,
        "terminal_objective_eligible_count": matrix.terminal_objective_eligible_count,
        "confirmed_projected_total": (
            matrix.terminal_objective_eligible_count + confirmed_count
        ),
        "confirmed_group_counts": confirmed_group_counts,
        "confirmed_capped_sum": sum(
            min(12, confirmed_group_counts[group]) for group in GROUP_ORDER
        ),
        "target_serviceability": serviceability,
        "all_target_deficits_serviceable": all(serviceability),
        "representation_feasible": (
            matrix.terminal_objective_eligible_count + confirmed_count
            >= REQUIRED_PROJECTED_TOTAL
            and all(
                confirmed_group_counts[group] >= REQUIRED_GROUP_FLOOR
                for group in GROUP_ORDER
            )
            and sum(
                min(12, confirmed_group_counts[group]) for group in GROUP_ORDER
            )
            >= REQUIRED_CAPPED_SUM
            and all(serviceability)
        ),
        "rights_status": "PENDING_PLAN39_VERIFICATION",
        "outcome": (
            "FEASIBLE"
            if (
                matrix.terminal_objective_eligible_count + confirmed_count
                >= REQUIRED_PROJECTED_TOTAL
                and all(
                    confirmed_group_counts[group] >= REQUIRED_GROUP_FLOOR
                    for group in GROUP_ORDER
                )
                and sum(
                    min(12, confirmed_group_counts[group]) for group in GROUP_ORDER
                )
                >= REQUIRED_CAPPED_SUM
                and all(serviceability)
            )
            else "INSUFFICIENT_CONFIRMED_COVERAGE"
        ),
    }
    return ConfirmedCoverageBound(**fields, bound_sha256=canonical_sha256(fields))


class SourceRequest(StrictContract):
    target_place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    official_source_id: Literal["15114464", "15109381", "3070426"]
    operation_or_page_kind: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=120),
    ]
    secret_free_filters: dict[str, str]
    expected_fields: tuple[RequiredField, ...]
    max_retries: Annotated[int, Field(strict=True, ge=0, le=3)]
    max_attempts: Annotated[int, Field(strict=True, ge=1, le=4)]
    backoff_schedule_seconds: tuple[Annotated[int, Field(strict=True, ge=0)], ...]
    max_seconds_per_attempt: Literal[300]
    nonnetwork_step_ceiling_seconds: Annotated[
        int,
        Field(strict=True, ge=0, le=300),
    ]
    redirects_allowed: Literal[False]
    fixed_host: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    capture_import_disposition: Literal[
        "POST_PREFLIGHT_CAPTURE_REQUIRES_SECOND_IMPORT_APPROVAL"
    ]

    @model_validator(mode="after")
    def validate_attempts(self) -> Self:
        if self.max_attempts != 1 + self.max_retries:
            raise ValueError("max attempts must equal one plus max retries")
        if len(self.backoff_schedule_seconds) != self.max_retries:
            raise ValueError("backoff schedule must match retry count")
        return self


class SupplementalSourcePlan(StrictContract):
    schema_version: Literal["itda.catalog-supplemental-source-plan.v1"]
    requests: tuple[SourceRequest, ...]
    request_count: Annotated[int, Field(strict=True, ge=1)]
    total_attempts: Annotated[int, Field(strict=True, ge=1)]
    network_elapsed_budget_seconds: Annotated[int, Field(strict=True, ge=300)]
    bounded_nonnetwork_overhead_seconds: Annotated[int, Field(strict=True, ge=0)]
    total_elapsed_budget_seconds: Annotated[int, Field(strict=True, ge=300)]
    global_deadline_seconds: Annotated[int, Field(strict=True, ge=300)]
    deadline_may_interrupt_inflight_attempt: Literal[False]
    dataset_rights_required: Literal[True]
    asset_rights_required: Literal[True]
    collections_base: Literal[
        "artifacts/restricted/catalog/v2/supplemental/collections"
    ]
    authorizes_provider_execution: Literal[False]
    authorizes_import: Literal[False]
    confidence_adds_score: Literal[False]
    source_plan_sha256: Sha256

    @model_validator(mode="after")
    def validate_budget(self) -> Self:
        if self.request_count != len(self.requests):
            raise ValueError("source-plan request count is not row-derived")
        attempts = sum(row.max_attempts for row in self.requests)
        network = ATTEMPT_SECONDS * attempts + sum(
            sum(row.backoff_schedule_seconds) for row in self.requests
        )
        nonnetwork = sum(
            row.nonnetwork_step_ceiling_seconds for row in self.requests
        )
        if (
            self.total_attempts != attempts
            or self.network_elapsed_budget_seconds != network
            or self.bounded_nonnetwork_overhead_seconds != nonnetwork
            or self.total_elapsed_budget_seconds != network + nonnetwork
        ):
            raise ValueError("source-plan elapsed budgets are not row-derived")
        if self.global_deadline_seconds < self.total_elapsed_budget_seconds:
            raise ValueError("global deadline is shorter than derived total budget")
        expected = canonical_sha256(
            self.model_dump(exclude={"source_plan_sha256"}, mode="json")
        )
        if self.source_plan_sha256 != expected:
            raise ValueError("source-plan digest drifted")
        return self


def build_source_plan(
    *,
    targets: Sequence[TargetRow],
    coverage: ConfirmedCoverageBound,
) -> SupplementalSourcePlan:
    if not coverage.representation_feasible:
        raise ValueError("confirmed coverage is insufficient for a source plan")
    requests = tuple(
        SourceRequest(
            target_place_entity_id=row.place_entity_id,
            official_source_id=(
                row.proposed_source_ids[1]
                if row.mandatory_deficits == ("OPERATING_INFO_MISSING",)
                else row.proposed_source_ids[0]
            ),
            operation_or_page_kind=(
                "regional-attraction-record"
                if "DESCRIPTION_MISSING" in row.mandatory_deficits
                else "attraction-status-record"
            ),
            secret_free_filters={"place_entity_id": row.place_entity_id},
            expected_fields=row.required_fields,
            max_retries=2,
            max_attempts=3,
            backoff_schedule_seconds=(1, 2),
            max_seconds_per_attempt=300,
            nonnetwork_step_ceiling_seconds=5,
            redirects_allowed=False,
            fixed_host="apis.data.go.kr",
            capture_import_disposition=(
                "POST_PREFLIGHT_CAPTURE_REQUIRES_SECOND_IMPORT_APPROVAL"
            ),
        )
        for row in targets
    )
    attempts = sum(row.max_attempts for row in requests)
    network = ATTEMPT_SECONDS * attempts + sum(
        sum(row.backoff_schedule_seconds) for row in requests
    )
    nonnetwork = sum(row.nonnetwork_step_ceiling_seconds for row in requests)
    fields = {
        "schema_version": "itda.catalog-supplemental-source-plan.v1",
        "requests": [row.model_dump(mode="json") for row in requests],
        "request_count": len(requests),
        "total_attempts": attempts,
        "network_elapsed_budget_seconds": network,
        "bounded_nonnetwork_overhead_seconds": nonnetwork,
        "total_elapsed_budget_seconds": network + nonnetwork,
        "global_deadline_seconds": network + nonnetwork,
        "deadline_may_interrupt_inflight_attempt": False,
        "dataset_rights_required": True,
        "asset_rights_required": True,
        "collections_base": (
            "artifacts/restricted/catalog/v2/supplemental/collections"
        ),
        "authorizes_provider_execution": False,
        "authorizes_import": False,
        "confidence_adds_score": False,
    }
    return SupplementalSourcePlan(
        **fields,
        source_plan_sha256=canonical_sha256(fields),
    )


class PacketManifest(StrictContract):
    """Exactly one canonical self-excluding payload and its digest."""

    payload: dict[str, object]
    root_sha256: Sha256

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        forbidden = {
            "root_sha256",
            "packet_manifest_sha256",
            "self",
            "self_path",
            "manifest_path",
        }
        if forbidden.intersection(self.payload):
            raise ValueError("packet payload contains a circular self/root field")
        if self.root_sha256 != canonical_sha256(self.payload):
            raise ValueError("packet root does not match canonical payload")
        return self


def build_packet_manifest(
    *,
    ordered_child_digests: Sequence[tuple[str, str]],
    ordered_parents: Sequence[str],
    policy_identities: Sequence[str],
    confirmed_facts_sha256: str,
    round_id: str,
    publication_state: Literal["SUCCESS", "FAILURE"],
) -> PacketManifest:
    payload: dict[str, object] = {
        "schema_version": "itda.catalog-remediation-packet.v1",
        "children": [
            {"relpath": relpath, "file_sha256": digest}
            for relpath, digest in ordered_child_digests
        ],
        "ordered_parents": list(ordered_parents),
        "policy_identities": list(policy_identities),
        "confirmed_facts_sha256": confirmed_facts_sha256,
        "round_id": round_id,
        "publication_state": publication_state,
    }
    return PacketManifest(
        payload=payload,
        root_sha256=canonical_sha256(payload),
    )


__all__ = [
    "ATTEMPT_SECONDS",
    "GROUP_ORDER",
    "SOURCE_PRIORITY",
    "ConfirmedCoverageBound",
    "OfficialSourceCapability",
    "PacketManifest",
    "PredeclaredLocalCapture",
    "RecordAvailabilityState",
    "SourceCapabilityState",
    "SourceRequest",
    "SupplementalSourcePlan",
    "TargetMatrix",
    "TargetRow",
    "build_confirmed_coverage_bound",
    "build_packet_manifest",
    "build_source_plan",
    "build_target_matrix",
]
