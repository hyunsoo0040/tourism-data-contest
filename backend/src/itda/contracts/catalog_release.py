"""Fail-closed contracts for canonical catalog review and release."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Self, cast

from pydantic import Field, field_validator, model_validator

from itda.contracts.authority import (
    AuthorityIssuanceContext,
    FileNonceLedger,
    freeze_issuance_context,
    validate_authority_token,
)
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.catalog_contest_profile import ContestSelectionFrontier, ContestUsePolicy
from itda.contracts.catalog_readiness import (
    GROUP_ORDER,
    RepresentationGroup,
    RepresentationQuotaAttestation,
    RepresentationQuotaConfig,
    build_representation_quota_artifacts,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

GateStatus = Literal["PASS", "BLOCKED", "EXTERNAL_BLOCKER"]
CatalogGateStatus = Literal["READY_FOR_ADJUDICATION", "BLOCKED"]
GateId = Literal[
    "candidate_pool_minimum",
    "proposal_seed_dispositions",
    "coordinates",
    "meaningful_description",
    "confirmed_operation",
    "rights_eligibility",
    "nonduplicate_poi_unit",
    "media_sufficiency",
    "representation_coverage",
    "human_identity_review",
    "human_relationship_review",
    "exactly_36",
]


class GateOutcome(StrictContract):
    """One objective catalog gate and its explicit result."""

    gate_id: GateId
    status: GateStatus
    passed_count: Annotated[int, Field(strict=True, ge=0)]
    required_count: Annotated[int, Field(strict=True, ge=0)]
    reason_codes: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...] = ()

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.status == "PASS" and self.passed_count < self.required_count:
            raise ValueError("passing gate cannot be below its required count")
        if self.status != "PASS" and not self.reason_codes:
            raise ValueError("blocked gate requires explicit reason codes")
        return self


class CatalogGateReport(StrictContract):
    """Deterministic exactly-36 decision report, including honest blocked states."""

    schema_version: Literal["catalog-gate-report-v1"] = "catalog-gate-report-v1"
    source_version: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    status: CatalogGateStatus
    candidate_count: Annotated[int, Field(strict=True, ge=0)]
    seed_disposition_count: Annotated[int, Field(strict=True, ge=0)]
    selection_eligible_count: Annotated[int, Field(strict=True, ge=0)]
    crosswalk_review_required_count: Annotated[int, Field(strict=True, ge=0)]
    relationship_review_required_count: Annotated[int, Field(strict=True, ge=0)]
    rights_disposition_counts: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
        Annotated[int, Field(strict=True, ge=0)],
    ] = Field(default_factory=dict)
    seed_disposition_counts: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
        Annotated[int, Field(strict=True, ge=0)],
    ] = Field(default_factory=dict)
    proposal_seed_dispositions: dict[
        Annotated[
            str,
            Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$"),
        ],
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
    ] = Field(default_factory=dict)
    representation_check_outcomes: dict[
        Literal[
            "history_culture",
            "history_scenery_boundary",
            "image_modern_content",
            "rest_walk_immersion",
        ],
        Annotated[bool, Field(strict=True)],
    ]
    ordered_catalog_ids: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...
    ] = ()
    ordered_catalog_count: Annotated[int, Field(strict=True, ge=0)]
    catalog_manifest_sha256: Sha256
    all_required_gates_passed: Annotated[bool, Field(strict=True)]
    gate_outcomes: tuple[GateOutcome, ...]
    unresolved_review_rows: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=240)], ...
    ] = ()
    parent_hashes: dict[Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256]
    projection_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256
    ]
    report_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.ordered_catalog_count != len(self.ordered_catalog_ids):
            raise ValueError("ordered catalog count does not match ordered IDs")
        if self.seed_disposition_count != len(self.proposal_seed_dispositions):
            raise ValueError("seed disposition count does not match explicit seed outcomes")
        if len(set(self.ordered_catalog_ids)) != len(self.ordered_catalog_ids):
            raise ValueError("ordered catalog IDs must be unique")
        if tuple(sorted(self.unresolved_review_rows)) != self.unresolved_review_rows:
            raise ValueError("unresolved review rows must use canonical order")
        if len(set(self.unresolved_review_rows)) != len(self.unresolved_review_rows):
            raise ValueError("unresolved review rows must be unique")
        expected_catalog = canonical_catalog_sha256(self.ordered_catalog_ids)
        if self.catalog_manifest_sha256 != expected_catalog:
            raise ValueError("catalog manifest sha256 does not match ordered IDs")
        expected_gate_ids = {
            "candidate_pool_minimum",
            "proposal_seed_dispositions",
            "coordinates",
            "meaningful_description",
            "confirmed_operation",
            "rights_eligibility",
            "nonduplicate_poi_unit",
            "media_sufficiency",
            "representation_coverage",
            "human_identity_review",
            "human_relationship_review",
            "exactly_36",
        }
        if {item.gate_id for item in self.gate_outcomes} != expected_gate_ids:
            raise ValueError("catalog gate report must contain every gate exactly once")
        all_pass = all(item.status == "PASS" for item in self.gate_outcomes)
        if self.all_required_gates_passed != all_pass:
            raise ValueError("all_required_gates_passed does not match gate outcomes")
        ready = all_pass and self.ordered_catalog_count == 36 and not self.unresolved_review_rows
        if (self.status == "READY_FOR_ADJUDICATION") != ready:
            raise ValueError("catalog gate status does not match exact gate truth")
        expected = canonical_sha256(self.model_dump(exclude={"report_sha256"}, mode="json"))
        if self.report_sha256 is None:
            object.__setattr__(self, "report_sha256", expected)
        elif self.report_sha256 != expected:
            raise ValueError("report_sha256 does not match canonical gate report")
        return self


class CatalogApproval(StrictContract):
    """Human approval bound to exact catalog and adjudication digests."""

    schema_version: Literal["catalog-approval-v1"] = "catalog-approval-v1"
    catalog_gate_report_sha256: Sha256
    catalog_manifest_sha256: Sha256
    catalog_adjudication_sha256: Sha256
    projection_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256
    ]
    proposal_seed_dispositions: dict[
        Annotated[
            str,
            Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$"),
        ],
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
    ]
    reviewer_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    approved_at: datetime
    catalog_approval_sha256: Sha256 | None = None

    @field_validator("approved_at")
    @classmethod
    def approved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="approved_at")

    @model_validator(mode="after")
    def validate_approval_hash(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"catalog_approval_sha256"}, mode="json")
        )
        if self.catalog_approval_sha256 is None:
            object.__setattr__(self, "catalog_approval_sha256", expected)
        elif self.catalog_approval_sha256 != expected:
            raise ValueError("catalog approval sha256 does not match canonical fields")
        return self


class CatalogReviewRequestRow(StrictContract):
    """One immutable human decision row sourced from a pending proposal."""

    row_id: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^(crosswalk|relationship):[0-9a-f]{64}$",
        ),
    ]
    row_kind: Literal["CROSSWALK", "RELATIONSHIP"]
    source_proposal_id: Sha256
    source_revision_sha256: Sha256
    evidence_refs: tuple[Sha256, ...]
    parent_hashes: dict[Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256]

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        expected_prefix = self.row_kind.casefold() + ":"
        if not self.row_id.startswith(expected_prefix):
            raise ValueError("review row kind does not match row ID namespace")
        if self.row_id.split(":", maxsplit=1)[1] != self.source_proposal_id:
            raise ValueError("review row ID does not match source proposal")
        if not self.evidence_refs:
            raise ValueError("review row requires at least one evidence reference")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("review row evidence refs must be unique canonical order")
        return self


class CatalogReviewRequest(StrictContract):
    """Pre-adjudication parent over every unresolved catalog review row."""

    schema_version: Literal["catalog-review-request-v1"] = "catalog-review-request-v1"
    status: Literal["READY_FOR_ADJUDICATION", "BLOCKED_AWAITING_ADJUDICATION"]
    gate_report_sha256: Sha256
    gate_report_file_sha256: Sha256
    parent_hashes: dict[Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256]
    projection_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256
    ]
    proposal_seed_dispositions: dict[
        Annotated[
            str,
            Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$"),
        ],
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
    ]
    code_version_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=300)], Sha256
    ]
    config_version_hashes: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=300)], Sha256
    ]
    ordered_proposed_catalog_ids: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...
    ] = ()
    proposed_catalog_sha256: Sha256
    required_rows: tuple[CatalogReviewRequestRow, ...]
    required_adjudication_rows_sha256: Sha256
    catalog_review_request_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        row_ids = tuple(row.row_id for row in self.required_rows)
        if tuple(sorted(row_ids)) != row_ids or len(set(row_ids)) != len(row_ids):
            raise ValueError("review request rows must use unique canonical order")
        if self.proposed_catalog_sha256 != canonical_catalog_sha256(
            self.ordered_proposed_catalog_ids
        ):
            raise ValueError("proposed catalog sha256 does not match ordered IDs")
        expected_rows = canonical_sha256(
            [row.model_dump(mode="json") for row in self.required_rows]
        )
        if self.required_adjudication_rows_sha256 != expected_rows:
            raise ValueError("required adjudication rows sha256 does not match inventory")
        expected = canonical_sha256(
            self.model_dump(exclude={"catalog_review_request_sha256"}, mode="json")
        )
        if self.catalog_review_request_sha256 is None:
            object.__setattr__(self, "catalog_review_request_sha256", expected)
        elif self.catalog_review_request_sha256 != expected:
            raise ValueError("catalog review request sha256 does not match canonical fields")
        return self


class CatalogAdjudicationRow(StrictContract):
    """One canonical human decision, with exact source and evidence binding."""

    row_id: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^(crosswalk|relationship):[0-9a-f]{64}$",
        ),
    ]
    decision: Literal["ACCEPT", "REJECT", "CORRECT", "KEEP_DISTINCT"]
    disposition: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    reviewer_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    reviewed_at: datetime
    evidence_refs: tuple[Sha256, ...]
    source_revision_sha256: Sha256
    parent_hashes: dict[Annotated[str, Field(strict=True, min_length=1, max_length=160)], Sha256]
    row_adjudication_sha256: Sha256 | None = None

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="reviewed_at")

    @model_validator(mode="after")
    def validate_row_hash(self) -> Self:
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("adjudication evidence refs must use unique canonical order")
        expected = canonical_sha256(
            self.model_dump(exclude={"row_adjudication_sha256"}, mode="json")
        )
        if self.row_adjudication_sha256 is None:
            object.__setattr__(self, "row_adjudication_sha256", expected)
        elif self.row_adjudication_sha256 != expected:
            raise ValueError("row adjudication sha256 does not match canonical fields")
        return self


class CatalogAdjudication(StrictContract):
    """Complete canonical decision bytes for one exact review request."""

    schema_version: Literal["catalog-adjudication-v1"] = "catalog-adjudication-v1"
    catalog_review_request_sha256: Sha256
    catalog_manifest_sha256: Sha256
    required_adjudication_rows_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    reviewed_at: datetime
    rows: tuple[CatalogAdjudicationRow, ...]
    catalog_adjudication_sha256: Sha256 | None = None

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="reviewed_at")

    @model_validator(mode="after")
    def validate_adjudication(self) -> Self:
        row_ids = tuple(row.row_id for row in self.rows)
        if tuple(sorted(row_ids)) != row_ids or len(set(row_ids)) != len(row_ids):
            raise ValueError("adjudication rows must use unique canonical order")
        if any(
            row.reviewer_id != self.reviewer_id or row.reviewed_at != self.reviewed_at
            for row in self.rows
        ):
            raise ValueError("every adjudication row must bind the same reviewer and UTC")
        expected = canonical_sha256(
            self.model_dump(exclude={"catalog_adjudication_sha256"}, mode="json")
        )
        if self.catalog_adjudication_sha256 is None:
            object.__setattr__(self, "catalog_adjudication_sha256", expected)
        elif self.catalog_adjudication_sha256 != expected:
            raise ValueError("catalog adjudication sha256 does not match canonical fields")
        return self


class VerifiedCatalogAdjudication(StrictContract):
    """In-memory verification token required by catalog materialization."""

    schema_version: Literal["verified-catalog-adjudication-v1"] = "verified-catalog-adjudication-v1"
    gate_report: CatalogGateReport
    review_request: CatalogReviewRequest
    adjudication: CatalogAdjudication
    verified_by: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    verification_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_verification_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"verification_sha256"}, mode="json"))
        if self.verification_sha256 is None:
            object.__setattr__(self, "verification_sha256", expected)
        elif self.verification_sha256 != expected:
            raise ValueError("verification sha256 does not match canonical fields")
        return self


class RevisionActivationEvent(StrictContract):
    """Append-only reviewed catalog revision activation or rollback."""

    schema_version: Literal["catalog-revision-activation-event-v1"] = (
        "catalog-revision-activation-event-v1"
    )
    sequence: Annotated[int, Field(strict=True, ge=1)]
    action: Literal["ACTIVATE", "ROLLBACK"]
    target_revision_sha256: Sha256
    catalog_adjudication_sha256: Sha256
    previous_active_revision_sha256: Sha256 | None = None
    previous_event_sha256: Sha256 | None = None
    reviewer_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    occurred_at: datetime
    evidence_refs: tuple[Sha256, ...]
    event_sha256: Sha256 | None = None

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="occurred_at")

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        if not self.evidence_refs:
            raise ValueError("activation event requires evidence")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("activation evidence refs must use unique canonical order")
        if (
            self.previous_active_revision_sha256 is not None
            and self.target_revision_sha256 == self.previous_active_revision_sha256
        ):
            raise ValueError("target revision is already active")
        expected = canonical_sha256(self.model_dump(exclude={"event_sha256"}, mode="json"))
        if self.event_sha256 is None:
            object.__setattr__(self, "event_sha256", expected)
        elif self.event_sha256 != expected:
            raise ValueError("activation event sha256 does not match canonical fields")
        return self


def canonical_catalog_sha256(ordered_catalog_ids: Iterable[str]) -> str:
    """Hash the exact ordered source-neutral catalog membership."""

    return canonical_sha256(list(ordered_catalog_ids))


def build_catalog_review_request(
    *,
    gate_report: CatalogGateReport,
    required_rows: Iterable[CatalogReviewRequestRow | Mapping[str, object]],
    code_version_hashes: Mapping[str, str],
    config_version_hashes: Mapping[str, str],
    gate_report_file_sha256: str | None = None,
) -> CatalogReviewRequest:
    """Bind every pending proposal row and all immutable gate parents."""

    if gate_report.report_sha256 is None:
        raise ValueError("catalog gate report requires a canonical sha256")
    parsed = tuple(
        row
        if isinstance(row, CatalogReviewRequestRow)
        else CatalogReviewRequestRow.model_validate(row)
        for row in required_rows
    )
    parsed_rows = tuple(sorted(parsed, key=lambda row: row.row_id))
    expected_rows = tuple(gate_report.unresolved_review_rows)
    if tuple(row.row_id for row in parsed_rows) != expected_rows:
        raise ValueError("review request must contain every unresolved gate row exactly once")
    return CatalogReviewRequest(
        status=(
            "READY_FOR_ADJUDICATION"
            if gate_report.status == "READY_FOR_ADJUDICATION"
            else "BLOCKED_AWAITING_ADJUDICATION"
        ),
        gate_report_sha256=gate_report.report_sha256,
        gate_report_file_sha256=(
            gate_report_file_sha256 or canonical_sha256(gate_report.model_dump(mode="json"))
        ),
        parent_hashes=gate_report.parent_hashes,
        projection_hashes=gate_report.projection_hashes,
        proposal_seed_dispositions=gate_report.proposal_seed_dispositions,
        code_version_hashes=dict(code_version_hashes),
        config_version_hashes=dict(config_version_hashes),
        ordered_proposed_catalog_ids=gate_report.ordered_catalog_ids,
        proposed_catalog_sha256=gate_report.catalog_manifest_sha256,
        required_rows=parsed_rows,
        required_adjudication_rows_sha256=canonical_sha256(
            [row.model_dump(mode="json") for row in parsed_rows]
        ),
    )


def _outcome(
    gate_id: GateId,
    *,
    passed_count: int,
    required_count: int,
    reason_code: str,
) -> GateOutcome:
    passed = passed_count >= required_count
    return GateOutcome(
        gate_id=gate_id,
        status="PASS" if passed else "BLOCKED",
        passed_count=passed_count,
        required_count=required_count,
        reason_codes=() if passed else (reason_code,),
    )


def evaluate_catalog_gate_report(
    *,
    candidates: Iterable[Mapping[str, object]],
    ordered_catalog_ids: Iterable[str],
    proposal_seed_dispositions: Mapping[str, str],
    parent_hashes: Mapping[str, str],
    projection_hashes: Mapping[str, str],
    unresolved_review_rows: Iterable[str] = (),
    crosswalk_review_required_count: int = 0,
    relationship_review_required_count: int = 0,
    rights_disposition_counts: Mapping[str, int] | None = None,
    seed_disposition_counts: Mapping[str, int] | None = None,
    source_version: str = "catalog-gate-input-v1",
) -> CatalogGateReport:
    """Evaluate all gates without converting a blocked state into an exception."""

    candidate_rows = tuple(candidates)
    ordered_ids = tuple(ordered_catalog_ids)
    selected = {
        str(row.get("canonical_place_id")): row
        for row in candidate_rows
        if row.get("canonical_place_id") is not None
    }
    selected_rows = tuple(selected[item] for item in ordered_ids if item in selected)
    gate_fields: tuple[tuple[GateId, str, str], ...] = (
        ("coordinates", "coordinates_gate", "COORDINATES_GATE_FAILED"),
        ("meaningful_description", "description_gate", "DESCRIPTION_GATE_FAILED"),
        ("confirmed_operation", "operational_gate", "OPERATIONAL_GATE_FAILED"),
        ("rights_eligibility", "rights_gate", "RIGHTS_GATE_FAILED"),
        ("nonduplicate_poi_unit", "nonduplicate_gate", "DUPLICATE_GATE_FAILED"),
        ("media_sufficiency", "media_gate", "MEDIA_GATE_FAILED"),
    )
    outcomes = [
        _outcome(
            "candidate_pool_minimum",
            passed_count=len(candidate_rows),
            required_count=60,
            reason_code="CANDIDATE_POOL_BELOW_60",
        ),
        _outcome(
            "proposal_seed_dispositions",
            passed_count=len(proposal_seed_dispositions),
            required_count=36,
            reason_code="PROPOSAL_SEED_DISPOSITION_MISSING",
        ),
    ]
    for gate_id, field_name, reason_code in gate_fields:
        passed_count = sum(row.get(field_name) is True for row in selected_rows)
        outcomes.append(
            _outcome(
                gate_id,
                passed_count=passed_count,
                required_count=36,
                reason_code=reason_code,
            )
        )
    outcomes.extend(
        (
            _outcome(
                "representation_coverage",
                passed_count=4 if len(ordered_ids) == 36 else 0,
                required_count=4,
                reason_code="REPRESENTATION_COVERAGE_NOT_ESTABLISHED",
            ),
            _outcome(
                "human_identity_review",
                passed_count=0 if crosswalk_review_required_count else 1,
                required_count=1,
                reason_code="CROSSWALK_REVIEW_REQUIRED",
            ),
            _outcome(
                "human_relationship_review",
                passed_count=0 if relationship_review_required_count else 1,
                required_count=1,
                reason_code="RELATIONSHIP_REVIEW_REQUIRED",
            ),
            _outcome(
                "exactly_36",
                passed_count=len(ordered_ids),
                required_count=36,
                reason_code="EXACTLY_36_NOT_ESTABLISHED",
            ),
        )
    )
    unresolved = tuple(sorted(unresolved_review_rows))
    representation_check_outcomes = {
        "history_culture": len(ordered_ids) == 36,
        "history_scenery_boundary": len(ordered_ids) == 36,
        "image_modern_content": len(ordered_ids) == 36,
        "rest_walk_immersion": len(ordered_ids) == 36,
    }
    all_passed = all(item.status == "PASS" for item in outcomes)
    selection_eligible_count = sum(
        (
            row.get("selection_eligible") is True
            if "selection_eligible" in row
            else all(row.get(field_name) is True for _, field_name, _ in gate_fields)
        )
        for row in candidate_rows
    )
    return CatalogGateReport(
        source_version=source_version,
        status=(
            "READY_FOR_ADJUDICATION"
            if all_passed and len(ordered_ids) == 36 and not unresolved
            else "BLOCKED"
        ),
        candidate_count=len(candidate_rows),
        seed_disposition_count=len(proposal_seed_dispositions),
        selection_eligible_count=selection_eligible_count,
        crosswalk_review_required_count=crosswalk_review_required_count,
        relationship_review_required_count=relationship_review_required_count,
        rights_disposition_counts=dict(rights_disposition_counts or {}),
        seed_disposition_counts=dict(seed_disposition_counts or {}),
        proposal_seed_dispositions=dict(proposal_seed_dispositions),
        representation_check_outcomes=cast(
            dict[RepresentationGroup, bool], representation_check_outcomes
        ),
        ordered_catalog_ids=ordered_ids,
        ordered_catalog_count=len(ordered_ids),
        catalog_manifest_sha256=canonical_catalog_sha256(ordered_ids),
        all_required_gates_passed=all_passed,
        gate_outcomes=tuple(outcomes),
        unresolved_review_rows=unresolved,
        parent_hashes=dict(parent_hashes),
        projection_hashes=dict(projection_hashes),
    )


def build_catalog_gate_report(
    *,
    candidates: Iterable[Mapping[str, object]],
    ordered_catalog_ids: Iterable[str],
    proposal_seed_dispositions: Mapping[str, str],
    parent_hashes: Mapping[str, str],
    projection_hashes: Mapping[str, str],
) -> CatalogGateReport:
    """Build a ready report or fail closed for synthetic/final materialization."""

    expected_seeds = {f"proposal:gyeongju:{index:03d}" for index in range(1, 37)}
    if set(proposal_seed_dispositions) != expected_seeds:
        raise ValueError("all 36 proposal seed dispositions are required")
    report = evaluate_catalog_gate_report(
        candidates=candidates,
        ordered_catalog_ids=ordered_catalog_ids,
        proposal_seed_dispositions=proposal_seed_dispositions,
        parent_hashes=parent_hashes,
        projection_hashes=projection_hashes,
    )
    if report.candidate_count < 60:
        raise ValueError("catalog gate requires at least 60 candidates")
    if report.ordered_catalog_count != 36:
        raise ValueError("catalog gate requires exactly 36 ordered places")
    if not report.all_required_gates_passed:
        failed = ", ".join(item.gate_id for item in report.gate_outcomes if item.status != "PASS")
        raise ValueError(f"catalog gate failed: {failed}")
    return report


def approve_catalog(
    *,
    gate_report: CatalogGateReport,
    catalog_adjudication_sha256: str,
    confirm_catalog_sha256: str,
    confirm_adjudication_sha256: str,
    reviewer_id: str,
    approved_at: str | datetime,
) -> CatalogApproval:
    """Create a dual-full-digest approval only for a passing report."""

    if len(confirm_catalog_sha256) != 64 or (
        confirm_catalog_sha256 != gate_report.catalog_manifest_sha256
    ):
        raise ValueError("catalog sha256 confirmation must match the full current digest")
    if len(confirm_adjudication_sha256) != 64 or (
        confirm_adjudication_sha256 != catalog_adjudication_sha256
    ):
        raise ValueError("adjudication sha256 confirmation must match the full current digest")
    if not gate_report.all_required_gates_passed:
        raise ValueError("catalog approval requires every gate to pass")
    if gate_report.report_sha256 is None:
        raise ValueError("catalog gate report is missing its canonical sha256")
    approval_time = (
        datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        if isinstance(approved_at, str)
        else approved_at
    )
    return CatalogApproval(
        catalog_gate_report_sha256=gate_report.report_sha256,
        catalog_manifest_sha256=gate_report.catalog_manifest_sha256,
        catalog_adjudication_sha256=catalog_adjudication_sha256,
        projection_hashes=gate_report.projection_hashes,
        proposal_seed_dispositions=gate_report.proposal_seed_dispositions,
        reviewer_id=reviewer_id,
        approved_at=approval_time,
    )


def _parse_utc(value: str | datetime, *, field_name: str) -> datetime:
    parsed = (
        datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    )
    return require_utc(parsed, field_name=field_name)


def prepare_catalog_adjudication(
    *,
    review_request: CatalogReviewRequest,
    decisions: Iterable[CatalogAdjudicationRow | Mapping[str, object]],
    reviewer_id: str,
    reviewed_at: str | datetime,
) -> CatalogAdjudication:
    """Canonicalize exact human decisions for every requested row once."""

    decision_payloads = tuple(decisions)
    decision_ids = tuple(
        (item.row_id if isinstance(item, CatalogAdjudicationRow) else str(item.get("row_id", "")))
        for item in decision_payloads
    )
    if len(set(decision_ids)) != len(decision_ids):
        raise ValueError("duplicate adjudication row")
    requested = {row.row_id: row for row in review_request.required_rows}
    provided = set(decision_ids)
    missing = set(requested) - provided
    extra = provided - set(requested)
    if missing:
        raise ValueError(f"missing adjudication rows: {sorted(missing)}")
    if extra:
        raise ValueError(f"extra adjudication rows: {sorted(extra)}")
    canonical_time = _parse_utc(reviewed_at, field_name="reviewed_at")
    parsed_by_id: dict[str, CatalogAdjudicationRow] = {}
    for item in decision_payloads:
        if isinstance(item, CatalogAdjudicationRow):
            parsed = item
        else:
            payload = dict(item)
            payload["reviewer_id"] = reviewer_id
            payload["reviewed_at"] = canonical_time
            parsed = CatalogAdjudicationRow.model_validate(payload)
        request_row = requested[parsed.row_id]
        if parsed.reviewer_id != reviewer_id or parsed.reviewed_at != canonical_time:
            raise ValueError("adjudication reviewer or UTC does not match command input")
        if parsed.evidence_refs != request_row.evidence_refs:
            raise ValueError("adjudication evidence refs do not match review request")
        if parsed.source_revision_sha256 != request_row.source_revision_sha256:
            raise ValueError("adjudication source revision does not match review request")
        if parsed.parent_hashes != request_row.parent_hashes:
            raise ValueError("adjudication parent hashes do not match review request")
        parsed_by_id[parsed.row_id] = parsed
    if review_request.catalog_review_request_sha256 is None:
        raise ValueError("catalog review request requires a canonical sha256")
    return CatalogAdjudication(
        catalog_review_request_sha256=review_request.catalog_review_request_sha256,
        catalog_manifest_sha256=review_request.proposed_catalog_sha256,
        required_adjudication_rows_sha256=(review_request.required_adjudication_rows_sha256),
        reviewer_id=reviewer_id,
        reviewed_at=canonical_time,
        rows=tuple(parsed_by_id[row.row_id] for row in review_request.required_rows),
    )


def verify_catalog_adjudication(
    *,
    gate_report: CatalogGateReport,
    review_request: CatalogReviewRequest,
    adjudication: CatalogAdjudication,
    confirm_catalog_sha256: str,
    confirm_adjudication_sha256: str,
    reviewer_id: str,
    repository_root: Path,
) -> VerifiedCatalogAdjudication:
    """Re-derive request, catalog, and adjudication digests before materialization."""

    if any(len(value) != 64 for value in (confirm_catalog_sha256, confirm_adjudication_sha256)):
        raise ValueError("catalog and adjudication confirmations require full 64-char sha256")
    if gate_report.report_sha256 != review_request.gate_report_sha256:
        raise ValueError("review request does not bind the current gate report")
    if review_request.parent_hashes != gate_report.parent_hashes:
        raise ValueError("review request parent hashes are stale")
    if review_request.projection_hashes != gate_report.projection_hashes:
        raise ValueError("review request projection hashes are stale")
    if review_request.proposal_seed_dispositions != gate_report.proposal_seed_dispositions:
        raise ValueError("review request seed dispositions are stale")
    _verify_version_hashes(review_request, repository_root)
    if review_request.catalog_review_request_sha256 is None:
        raise ValueError("catalog review request requires a canonical sha256")
    if adjudication.catalog_review_request_sha256 != review_request.catalog_review_request_sha256:
        raise ValueError("adjudication does not bind the current review request")
    if adjudication.catalog_manifest_sha256 != gate_report.catalog_manifest_sha256:
        raise ValueError("adjudication catalog digest is stale")
    if confirm_catalog_sha256 != gate_report.catalog_manifest_sha256:
        raise ValueError("confirmed catalog digest is stale")
    if adjudication.catalog_adjudication_sha256 is None or (
        confirm_adjudication_sha256 != adjudication.catalog_adjudication_sha256
    ):
        raise ValueError("confirmed adjudication digest is stale")
    if adjudication.reviewer_id != reviewer_id:
        raise ValueError("verification reviewer does not match adjudication reviewer")
    if tuple(row.row_id for row in adjudication.rows) != tuple(
        row.row_id for row in review_request.required_rows
    ):
        raise ValueError("adjudication does not contain every requested row")
    if (
        adjudication.required_adjudication_rows_sha256
        != review_request.required_adjudication_rows_sha256
    ):
        raise ValueError("adjudication required-row inventory is stale")
    for requested, decided in zip(
        review_request.required_rows,
        adjudication.rows,
        strict=True,
    ):
        if decided.evidence_refs != requested.evidence_refs:
            raise ValueError("adjudication evidence does not match requested row")
        if decided.source_revision_sha256 != requested.source_revision_sha256:
            raise ValueError("adjudication source revision does not match requested row")
        if decided.parent_hashes != requested.parent_hashes:
            raise ValueError("adjudication parent hashes do not match requested row")
    blocked_objective_gates = {
        item.gate_id for item in gate_report.gate_outcomes if item.status != "PASS"
    } - {"human_identity_review", "human_relationship_review"}
    if blocked_objective_gates:
        raise ValueError(
            "objective catalog gates remain blocked: " + ", ".join(sorted(blocked_objective_gates))
        )
    return VerifiedCatalogAdjudication(
        gate_report=gate_report,
        review_request=review_request,
        adjudication=adjudication,
        verified_by=reviewer_id,
    )


def _verify_version_hashes(
    review_request: CatalogReviewRequest,
    repository_root: Path,
) -> None:
    root = repository_root.resolve(strict=True)
    for category, expected_hashes in (
        ("code", review_request.code_version_hashes),
        ("config", review_request.config_version_hashes),
    ):
        for relative, expected in expected_hashes.items():
            candidate = Path(relative)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError(f"{category} version path is unsafe")
            path = root / candidate
            if (
                path.is_symlink()
                or not path.is_file()
                or not path.resolve(strict=True).is_relative_to(root)
            ):
                raise ValueError(f"{category} version input is not a regular repository file")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"{category} version hash is stale: {relative}")


def materialize_reviewed_catalog(
    verified: VerifiedCatalogAdjudication,
    destination: Path,
) -> None:
    """Publish one verified reviewed revision with durable no-replace semantics."""

    from itda.cli.freeze_preview import (  # noqa: PLC0415
        prepared_directory_snapshot,
        publish_immutable_directory,
    )

    if verified.verification_sha256 is None:
        raise ValueError("reviewed catalog requires a verified adjudication token")
    destination.parent.mkdir(parents=True, exist_ok=True)
    prepared = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.prepared-", dir=destination.parent)
    )
    published = False
    try:
        catalog_payload = {
            "schema_version": "reviewed-catalog-v1",
            "ordered_catalog_ids": verified.gate_report.ordered_catalog_ids,
            "catalog_manifest_sha256": verified.gate_report.catalog_manifest_sha256,
            "catalog_adjudication_sha256": verified.adjudication.catalog_adjudication_sha256,
            "verification_sha256": verified.verification_sha256,
        }
        catalog_payload["revision_sha256"] = canonical_sha256(catalog_payload)
        artifacts = {
            "catalog-gate-report.json": verified.gate_report.model_dump(mode="json"),
            "catalog-review-request.json": verified.review_request.model_dump(mode="json"),
            "catalog-adjudication.json": verified.adjudication.model_dump(mode="json"),
            "catalog.json": catalog_payload,
        }
        for name, payload in artifacts.items():
            (prepared / name).write_bytes(canonical_json_bytes(payload))
        with prepared_directory_snapshot(prepared) as snapshot:
            publish_immutable_directory(
                prepared=prepared,
                output=destination,
                snapshot=snapshot,
            )
        published = True
    finally:
        if not published and prepared.exists():
            shutil.rmtree(prepared)


def _load_canonical_model[ModelT: StrictContract](
    path: Path,
    model: type[ModelT],
) -> ModelT:
    if path.is_symlink() or not path.is_file():
        raise ValueError("reviewed catalog contains a non-regular artifact")
    raw = path.read_bytes()
    parsed = model.model_validate(json.loads(raw))
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("reviewed catalog artifact is not canonical JSON")
    return parsed


def load_reviewed_catalog_revision(
    revision_root: Path,
    *,
    repository_root: Path,
) -> tuple[str, str]:
    """Verify an immutable reviewed revision before activation or rollback."""

    if revision_root.is_symlink() or not revision_root.is_dir() or revision_root.suffix == ".json":
        raise ValueError("reviewed catalog revision must be a directory")
    expected_names = {
        "catalog-gate-report.json",
        "catalog-review-request.json",
        "catalog-adjudication.json",
        "catalog.json",
    }
    if {path.name for path in revision_root.iterdir()} != expected_names:
        raise ValueError("reviewed catalog revision has an invalid artifact inventory")
    gate_report = _load_canonical_model(
        revision_root / "catalog-gate-report.json",
        CatalogGateReport,
    )
    review_request = _load_canonical_model(
        revision_root / "catalog-review-request.json",
        CatalogReviewRequest,
    )
    adjudication = _load_canonical_model(
        revision_root / "catalog-adjudication.json",
        CatalogAdjudication,
    )
    if adjudication.catalog_adjudication_sha256 is None:
        raise ValueError("reviewed catalog adjudication requires a canonical sha256")
    verified = verify_catalog_adjudication(
        gate_report=gate_report,
        review_request=review_request,
        adjudication=adjudication,
        confirm_catalog_sha256=gate_report.catalog_manifest_sha256,
        confirm_adjudication_sha256=adjudication.catalog_adjudication_sha256,
        reviewer_id=adjudication.reviewer_id,
        repository_root=repository_root,
    )
    catalog_path = revision_root / "catalog.json"
    if catalog_path.is_symlink() or not catalog_path.is_file():
        raise ValueError("reviewed catalog identity must be a regular file")
    raw = catalog_path.read_bytes()
    catalog = json.loads(raw)
    if not isinstance(catalog, dict) or raw != canonical_json_bytes(catalog):
        raise ValueError("reviewed catalog identity is not canonical JSON")
    revision_sha256 = catalog.get("revision_sha256")
    if not isinstance(revision_sha256, str) or len(revision_sha256) != 64:
        raise ValueError("reviewed catalog revision lacks a canonical sha256")
    expected_revision = canonical_sha256(
        {key: value for key, value in catalog.items() if key != "revision_sha256"}
    )
    if revision_sha256 != expected_revision:
        raise ValueError("reviewed catalog revision sha256 is stale")
    expected_catalog = {
        "schema_version": "reviewed-catalog-v1",
        "ordered_catalog_ids": list(gate_report.ordered_catalog_ids),
        "catalog_manifest_sha256": gate_report.catalog_manifest_sha256,
        "catalog_adjudication_sha256": adjudication.catalog_adjudication_sha256,
        "verification_sha256": verified.verification_sha256,
        "revision_sha256": revision_sha256,
    }
    if catalog != expected_catalog:
        raise ValueError("reviewed catalog identity does not bind verified artifacts")
    return revision_sha256, adjudication.catalog_adjudication_sha256


def load_adjudication_decisions(path: Path) -> list[dict[str, object]]:
    """Accept machine decision arrays from canonical JSON only."""

    if path.suffix != ".json":
        raise ValueError("adjudication decisions must be canonical JSON")
    payload = json.loads(path.read_bytes())
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ValueError("canonical adjudication decisions must be a JSON array of objects")
    return payload


def _load_activation_events(events_root: Path) -> tuple[RevisionActivationEvent, ...]:
    if not events_root.exists():
        return ()
    if events_root.is_symlink() or not events_root.is_dir():
        raise ValueError("activation events root must be a regular directory")
    events: list[RevisionActivationEvent] = []
    for path in sorted(events_root.iterdir()):
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise ValueError("activation events root contains an invalid entry")
        payload = json.loads(path.read_bytes())
        events.append(RevisionActivationEvent.model_validate(payload))
    if tuple(event.sequence for event in events) != tuple(range(1, len(events) + 1)):
        raise ValueError("activation event sequence is not append-only")
    for previous, current in zip(events, events[1:], strict=False):
        if current.previous_event_sha256 != previous.event_sha256:
            raise ValueError("activation event chain is broken")
    return tuple(events)


def append_revision_activation_event(
    *,
    action: Literal["ACTIVATE", "ROLLBACK"],
    target_revision_sha256: str,
    catalog_adjudication_sha256: str,
    expected_active_revision_sha256: str | None,
    reviewer_id: str,
    occurred_at: str | datetime,
    evidence_refs: Iterable[str],
    events_root: Path,
    reviewed_revision_sha256s: Iterable[str],
) -> RevisionActivationEvent:
    """Append one immutable activation event; no mutable active pointer exists."""

    reviewed = frozenset(reviewed_revision_sha256s)
    if target_revision_sha256 not in reviewed:
        raise ValueError("target revision is absent from reviewed revision history")
    events = _load_activation_events(events_root)
    active = events[-1].target_revision_sha256 if events else None
    if active != expected_active_revision_sha256:
        raise ValueError("expected active revision does not match append-only history")
    if active == target_revision_sha256:
        raise ValueError("target revision is already active")
    if action == "ROLLBACK" and not events:
        raise ValueError("rollback requires an existing active revision")
    event = RevisionActivationEvent(
        sequence=len(events) + 1,
        action=action,
        target_revision_sha256=target_revision_sha256,
        catalog_adjudication_sha256=catalog_adjudication_sha256,
        previous_active_revision_sha256=active,
        previous_event_sha256=events[-1].event_sha256 if events else None,
        reviewer_id=reviewer_id,
        occurred_at=_parse_utc(occurred_at, field_name="occurred_at"),
        evidence_refs=tuple(sorted(set(evidence_refs))),
    )
    if event.event_sha256 is None:
        raise ValueError("activation event requires a canonical sha256")
    events_root.mkdir(parents=True, exist_ok=True)
    if events_root.is_symlink() or not events_root.is_dir():
        raise ValueError("activation events root must be a regular directory")
    destination = events_root / f"{event.sequence:06d}-{event.event_sha256}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        payload = canonical_json_bytes(event.model_dump(mode="json"))
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError("short write while appending activation event")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(
        events_root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return event


def load_catalog_review_truth(path: Path) -> dict[str, object]:
    """Load canonical JSON only; human projections are never approval truth."""

    if path.suffix != ".json":
        raise ValueError("catalog review truth must be canonical JSON")
    payload = json.loads(path.read_bytes())
    if not isinstance(payload, dict):
        raise ValueError("canonical catalog review JSON root must be an object")
    return payload


def publish_catalog_release(
    report: CatalogGateReport,
    approval: CatalogApproval,
    destination: Path,
) -> None:
    """Publish immutable reviewed bytes into a newly-created directory."""

    if approval.catalog_gate_report_sha256 != report.report_sha256:
        raise ValueError("catalog approval does not bind the gate report")
    destination.mkdir(parents=False, exist_ok=False)
    (destination / "catalog-gate-report.json").write_bytes(
        canonical_json_bytes(report.model_dump(mode="json"))
    )
    (destination / "catalog-approval.json").write_bytes(
        canonical_json_bytes(approval.model_dump(mode="json"))
    )


class CatalogRepresentationAttestationV2(StrictContract):
    """Complete independently rederived REINF-12 proof for one catalog revision."""

    schema_version: Literal["itda.catalog-representation-attestation.v2"] = (
        "itda.catalog-representation-attestation.v2"
    )
    representation_policy_version: Literal["contest-use-official-public-data-v1"]
    representation_policy_sha256: Sha256
    representation_rule_table_sha256: Sha256
    eligible_pool_sha256: Sha256
    eligible_pool_count: Annotated[int, Field(strict=True, ge=0)]
    raw_eligible_group_counts: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    exact_quotas: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    quota_sum: Literal[36]
    capped_capacity: Annotated[int, Field(strict=True, ge=0)]
    quota_algorithm: Literal["bounded-largest-remainder-v1"]
    quota_tie_break: Literal["fixed-group-order-v1"]
    quota_config_sha256: Sha256
    quota_proof_sha256: Sha256
    quota_config: RepresentationQuotaConfig
    quota_attestation: RepresentationQuotaAttestation
    feasibility_result: Literal["FEASIBLE"]
    source_neutral_comparator: Literal["canonical-utf8-source-neutral-id-v1"]
    fixed_group_tie_order: tuple[RepresentationGroup, ...]
    selection_ordering_rule: Literal["group-ordinal-then-canonical-utf8-source-neutral-id"]
    representation_attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        required = set(GROUP_ORDER)
        if set(self.raw_eligible_group_counts) != required or set(self.exact_quotas) != required:
            raise ValueError("representation attestation group keys drifted")
        if self.fixed_group_tie_order != GROUP_ORDER:
            raise ValueError("representation attestation fixed tie order drifted")
        if self.eligible_pool_count != sum(self.raw_eligible_group_counts.values()):
            raise ValueError("representation attestation eligible count drifted")
        if self.quota_sum != sum(self.exact_quotas.values()):
            raise ValueError("representation attestation quota sum drifted")
        if any(
            not 6 <= self.exact_quotas[group] <= min(12, self.raw_eligible_group_counts[group])
            for group in GROUP_ORDER
        ):
            raise ValueError("representation attestation quota bounds drifted")
        if self.capped_capacity != sum(
            min(12, self.raw_eligible_group_counts[group]) for group in GROUP_ORDER
        ):
            raise ValueError("representation attestation capacity drifted")
        if (
            self.quota_config.config_sha256 != self.quota_config_sha256
            or self.quota_attestation.attestation_sha256 != self.quota_proof_sha256
            or self.quota_attestation.config_sha256 != self.quota_config_sha256
            or self.quota_attestation.eligible_pool_sha256 != self.eligible_pool_sha256
            or self.quota_attestation.raw_eligible_group_counts != self.raw_eligible_group_counts
            or self.quota_attestation.final_quotas != self.exact_quotas
            or not self.quota_attestation.feasible
        ):
            raise ValueError("representation full quota config or attestation drifted")
        expected = canonical_sha256(
            self.model_dump(exclude={"representation_attestation_sha256"}, mode="json")
        )
        if self.representation_attestation_sha256 is None:
            object.__setattr__(self, "representation_attestation_sha256", expected)
        elif not hmac.compare_digest(self.representation_attestation_sha256, expected):
            raise ValueError("representation attestation sha256 drifted")
        return self


class CatalogRevisionV2(StrictContract):
    """One immutable human-selected catalog revision that is not yet approved or active."""

    schema_version: Literal["itda.catalog-revision.v2"] = "itda.catalog-revision.v2"
    status: Literal["SELECTED_UNAPPROVED"] = "SELECTED_UNAPPROVED"
    adjudication_bundle_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    adjudication_bundle_root_sha256: Sha256
    combined_target_sha256: Sha256
    ordered_place_ids: tuple[
        Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")], ...
    ]
    ordered_place_ids_sha256: Sha256
    catalog_selection_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    objective_replay_sha256: Sha256
    representation_attestation: CatalogRepresentationAttestationV2
    code_version_hashes: dict[Annotated[str, Field(strict=True, min_length=1)], Sha256]
    config_version_hashes: dict[Annotated[str, Field(strict=True, min_length=1)], Sha256]
    previous_revision_sha256: Sha256 | None = None
    rollback_target_revision_sha256: Sha256 | None = None
    active_revision_sha256: Sha256 | None = None
    approval_sha256: Sha256 | None = None
    activation_event_sha256: Sha256 | None = None
    v1_lineage_root_sha256: Sha256
    catalog_revision_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        if len(self.ordered_place_ids) != 36 or len(set(self.ordered_place_ids)) != 36:
            raise ValueError("catalog v2 revision requires exactly 36 unique places")
        if self.ordered_place_ids_sha256 != canonical_sha256(list(self.ordered_place_ids)):
            raise ValueError("catalog v2 revision ordered place digest drifted")
        if any(
            value is not None
            for value in (
                self.active_revision_sha256,
                self.approval_sha256,
                self.activation_event_sha256,
            )
        ):
            raise ValueError("SELECTED_UNAPPROVED revision cannot be approved or active")
        expected = canonical_sha256(
            self.model_dump(exclude={"catalog_revision_sha256"}, mode="json")
        )
        if self.catalog_revision_sha256 is None:
            object.__setattr__(self, "catalog_revision_sha256", expected)
        elif not hmac.compare_digest(self.catalog_revision_sha256, expected):
            raise ValueError("catalog v2 revision sha256 drifted")
        return self


class CatalogApprovalStateAttestationV2(StrictContract):
    """Exact inactive state against which catalog approval authority is issued."""

    schema_version: Literal["itda.catalog-approval-state-attestation.v2"] = (
        "itda.catalog-approval-state-attestation.v2"
    )
    status: Literal["SELECTED_UNAPPROVED"] = "SELECTED_UNAPPROVED"
    catalog_revision_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    catalog_revision_file_sha256: Sha256
    catalog_revision_sha256: Sha256
    combined_target_sha256: Sha256
    approval_target_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    representation_attestation: CatalogRepresentationAttestationV2
    code_version_hashes: dict[Annotated[str, Field(strict=True, min_length=1)], Sha256]
    config_version_hashes: dict[Annotated[str, Field(strict=True, min_length=1)], Sha256]
    v1_lineage_root_sha256: Sha256
    catalog_approval_sha256: Sha256 | None = None
    active_revision_sha256: Sha256 | None = None
    activation_event_sha256: Sha256 | None = None
    state_attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if any(
            value is not None
            for value in (
                self.catalog_approval_sha256,
                self.active_revision_sha256,
                self.activation_event_sha256,
            )
        ):
            raise ValueError("approval state is not inactive and unapproved")
        if self.approval_target_sha256 != self.catalog_revision_sha256:
            raise ValueError("approval target does not equal exact revision semantics")
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif not hmac.compare_digest(self.state_attestation_sha256, expected):
            raise ValueError("catalog approval state sha256 drifted")
        return self


class CatalogApprovalRequestV2(StrictContract):
    """Fresh one-use authority request for approval of an exact inactive revision."""

    schema_version: Literal["itda.catalog-approval-request.v2"] = "itda.catalog-approval-request.v2"
    action: Literal["catalog-approve"] = "catalog-approve"
    catalog_revision_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    representation_attestation_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    binding_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    expires_at: datetime
    replaces_request_sha256: Sha256 | None = None
    reviewer_channel_risk: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    request_sha256: Sha256 | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="approval_request_timestamp")

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("catalog approval request expiry must follow issuance")
        expected = canonical_sha256(self.model_dump(exclude={"request_sha256"}, mode="json"))
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif not hmac.compare_digest(self.request_sha256, expected):
            raise ValueError("catalog approval request sha256 drifted")
        return self


class CatalogApprovalV2(StrictContract):
    """Human approval receipt that deliberately leaves the revision inactive."""

    schema_version: Literal["itda.catalog-approval.v2"] = "itda.catalog-approval.v2"
    status: Literal["APPROVED_INACTIVE"] = "APPROVED_INACTIVE"
    catalog_revision_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    approval_request_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    approval_state_path: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    catalog_revision_sha256: Sha256
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    representation_attestation_sha256: Sha256
    independently_rederived_fields_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    reviewer_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    approved_at: datetime
    token_sha256: Sha256
    nonce_sha256: Sha256
    issuance_context_sha256: Sha256
    reviewer_channel_risk: Annotated[str, Field(strict=True, min_length=1, max_length=500)]
    active_revision_sha256: Sha256 | None = None
    activation_event_sha256: Sha256 | None = None
    catalog_approval_sha256: Sha256 | None = None

    @field_validator("approved_at")
    @classmethod
    def approved_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="approved_at")

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        if self.active_revision_sha256 is not None or self.activation_event_sha256 is not None:
            raise ValueError("catalog approval cannot activate a revision")
        expected = canonical_sha256(
            self.model_dump(exclude={"catalog_approval_sha256"}, mode="json")
        )
        if self.catalog_approval_sha256 is None:
            object.__setattr__(self, "catalog_approval_sha256", expected)
        elif not hmac.compare_digest(self.catalog_approval_sha256, expected):
            raise ValueError("catalog v2 approval sha256 drifted")
        return self


_V2_CODE_VERSION_PATHS = (
    "backend/src/itda/contracts/catalog_release.py",
    "backend/src/itda/contracts/catalog_readiness.py",
    "backend/src/itda/contracts/catalog_contest_profile.py",
    "backend/src/itda/cli/approve_catalog.py",
    "backend/src/itda/cli/build_catalog_v2_review.py",
    "backend/src/itda/cli/build_catalog_contest_profile.py",
)
_V2_CONFIG_VERSION_PATHS = ("backend/pyproject.toml", "backend/uv.lock")


def _stable_regular_bytes(path: Path, *, max_bytes: int = 8_000_000) -> bytes:
    if path.is_symlink():
        raise ValueError("catalog v2 input cannot be a symlink")
    before = path.stat()
    if not path.is_file() or before.st_size > max_bytes:
        raise ValueError("catalog v2 input must be a bounded regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise ValueError("catalog v2 input identity changed before open")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > max_bytes or (opened.st_dev, opened.st_ino, opened.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ValueError("catalog v2 input changed during stable read")
        return raw
    finally:
        os.close(descriptor)


def _load_canonical_mapping(path: Path) -> dict[str, Any]:
    raw = _stable_regular_bytes(path)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("catalog v2 input is invalid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        raise ValueError("catalog v2 input is not a canonical JSON object")
    return cast(dict[str, Any], value)


def _relative_or_absolute(path: Path, repository_root: Path) -> str:
    resolved = path.resolve(strict=False)
    try:
        return resolved.relative_to(repository_root).as_posix()
    except ValueError:
        return resolved.as_posix()


def _version_hashes(repository_root: Path, paths: Iterable[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in paths:
        path = repository_root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"version input is not a regular file: {relative}")
        hashes[relative] = hashlib.sha256(_stable_regular_bytes(path)).hexdigest()
    return hashes


def _verify_hash_map(
    repository_root: Path,
    expected: Mapping[str, str],
    *,
    category: str,
) -> None:
    if not expected:
        raise ValueError(f"{category} version hash inventory is empty")
    for relative, digest in expected.items():
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"{category} version path is unsafe")
        path = repository_root / candidate
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve(strict=True).is_relative_to(repository_root)
        ):
            raise ValueError(f"{category} version input is not a repository file")
        if hashlib.sha256(_stable_regular_bytes(path)).hexdigest() != digest:
            raise ValueError(f"{category} version hash is stale: {relative}")


def _catalog_v2_parent_payloads(
    bundle_manifest_path: Path,
    *,
    repository_root: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    ContestUsePolicy,
    ContestSelectionFrontier,
]:
    from itda.cli.build_catalog_contest_profile import project_contest_profile  # noqa: PLC0415
    from itda.cli.build_catalog_v2_review import verify_adjudication_bundle  # noqa: PLC0415

    bundle = verify_adjudication_bundle(
        bundle_manifest_path,
        repository_root=repository_root,
    )
    expected_bundle = (
        repository_root
        / "artifacts/restricted/catalog/v2/review/adjudication-bundles"
        / str(bundle["bundle_root_sha256"])
        / "catalog-adjudication-bundle.json"
    ).resolve(strict=True)
    if bundle_manifest_path.resolve(strict=True) != expected_bundle:
        raise ValueError("catalog adjudication bundle is outside the exact restricted namespace")
    receipt_path = (
        repository_root
        / "artifacts/restricted/catalog/v2/review/catalog-adjudication-materialization-receipt.json"
    )
    receipt = _load_canonical_mapping(receipt_path)
    if (
        receipt.get("bundle_manifest_path")
        != _relative_or_absolute(expected_bundle, repository_root)
        or receipt.get("bundle_root_sha256") != bundle["bundle_root_sha256"]
        or receipt.get("publication_disposition") not in {"PUBLISHED", "ALREADY_PRESENT_VERIFIED"}
    ):
        raise ValueError("catalog adjudication receipt does not bind the verified bundle")
    directory = expected_bundle.parent
    target = _load_canonical_mapping(directory / "catalog-adjudication-selection-target.json")
    selection = _load_canonical_mapping(directory / "catalog-selection.json")
    relationships = _load_canonical_mapping(directory / "authoritative-relationship-leaves.json")
    bridge_rel = target.get("bridge_directory")
    if not isinstance(bridge_rel, str):
        raise ValueError("catalog adjudication target lacks its Plan 54 bridge")
    bridge_request = _load_canonical_mapping(
        repository_root / bridge_rel / "catalog-review-request.json"
    )
    generation_rel = bridge_request.get("generation_manifest_path")
    if not isinstance(generation_rel, str):
        raise ValueError("Plan 54 bridge lacks its generation manifest")
    generation_root = (repository_root / generation_rel).parent
    policy_raw = _load_canonical_mapping(generation_root / "policy.json")
    frontier_raw = _load_canonical_mapping(generation_root / "selection-frontier.json")
    policy = ContestUsePolicy.model_validate(policy_raw)
    frontier = ContestSelectionFrontier.model_validate(frontier_raw)
    replay = project_contest_profile(repository_root)
    if canonical_json_bytes(replay.policy.model_dump(mode="json")) != canonical_json_bytes(
        policy.model_dump(mode="json")
    ) or canonical_json_bytes(replay.frontier.model_dump(mode="json")) != canonical_json_bytes(
        frontier.model_dump(mode="json")
    ):
        raise ValueError("catalog representation parents differ from independent live replay")
    return target, selection, relationships, policy, frontier


def _derive_catalog_v2_representation(
    *,
    target: Mapping[str, Any],
    policy: ContestUsePolicy,
    frontier: ContestSelectionFrontier,
) -> CatalogRepresentationAttestationV2:
    quota_config, quota = build_representation_quota_artifacts(
        eligible_pool_sha256=frontier.eligible_pool_sha256,
        representation_rule_sha256=policy.representation_rule_sha256,
        raw_eligible_group_counts=frontier.eligible_group_counts,
    )
    if (
        not quota.feasible
        or quota.failure_reason is not None
        or quota.final_quotas != frontier.final_quotas
        or quota_config.config_sha256 != frontier.quota_config_sha256
        or quota.attestation_sha256 != frontier.quota_proof_sha256
        or target.get("eligible_pool_sha256") != frontier.eligible_pool_sha256
        or target.get("eligible_group_counts") != frontier.eligible_group_counts
        or target.get("exact_quotas") != quota.final_quotas
        or target.get("representation_state") != "FEASIBLE"
        or target.get("capped_capacity") != frontier.capped_capacity
    ):
        raise ValueError("representation policy, pool, count, quota, or feasibility parent drifted")
    return CatalogRepresentationAttestationV2(
        representation_policy_version=policy.policy_version,
        representation_policy_sha256=policy.policy_sha256,
        representation_rule_table_sha256=policy.representation_rule_sha256,
        eligible_pool_sha256=frontier.eligible_pool_sha256,
        eligible_pool_count=frontier.eligible_candidate_count,
        raw_eligible_group_counts=frontier.eligible_group_counts,
        exact_quotas=quota.final_quotas,
        quota_sum=36,
        capped_capacity=frontier.capped_capacity,
        quota_algorithm=quota_config.algorithm,
        quota_tie_break=quota_config.tie_break,
        quota_config_sha256=quota_config.config_sha256,
        quota_proof_sha256=quota.attestation_sha256,
        quota_config=quota_config,
        quota_attestation=quota,
        feasibility_result="FEASIBLE",
        source_neutral_comparator="canonical-utf8-source-neutral-id-v1",
        fixed_group_tie_order=GROUP_ORDER,
        selection_ordering_rule=frontier.ordering_rule,
    )


def build_catalog_v2_revision(
    bundle_manifest_path: Path | str,
    *,
    repository_root: Path | str,
) -> CatalogRevisionV2:
    """Independently replay Plan 20 and freeze one exact inactive revision."""

    root = Path(repository_root).resolve(strict=True)
    bundle_path = Path(bundle_manifest_path)
    target, selection, relationships, policy, frontier = _catalog_v2_parent_payloads(
        bundle_path,
        repository_root=root,
    )
    ordered = target.get("ordered_place_ids")
    if not isinstance(ordered, list) or len(ordered) != 36 or len(set(ordered)) != 36:
        raise ValueError("catalog v2 revision requires the exact ordered 36")
    if (
        selection.get("ordered_place_ids") != ordered
        or selection.get("ordered_place_ids_sha256") != canonical_sha256(ordered)
        or selection.get("selected_group_counts") != selection.get("exact_quotas")
        or selection.get("representation_state") != "FEASIBLE"
    ):
        raise ValueError("catalog selection objective replay drifted")
    representation = _derive_catalog_v2_representation(
        target=target,
        policy=policy,
        frontier=frontier,
    )
    objective_replay = {
        "combined_target_sha256": target.get("target_sha256"),
        "ordered_place_ids_sha256": canonical_sha256(ordered),
        "eligible_pool_sha256": representation.eligible_pool_sha256,
        "selected_group_counts": selection.get("selected_group_counts"),
        "exact_quotas": representation.exact_quotas,
        "representation_attestation_sha256": representation.representation_attestation_sha256,
    }
    selection_sha = selection.get("catalog_selection_sha256")
    relationship_sha = relationships.get("authoritative_relationship_leaves_sha256")
    if not isinstance(selection_sha, str) or not isinstance(relationship_sha, str):
        raise ValueError("catalog selection or relationship digest is missing")
    return CatalogRevisionV2(
        adjudication_bundle_path=_relative_or_absolute(bundle_path, root),
        adjudication_bundle_root_sha256=bundle_path.parent.name,
        combined_target_sha256=cast(str, target.get("target_sha256")),
        ordered_place_ids=tuple(cast(list[str], ordered)),
        ordered_place_ids_sha256=canonical_sha256(ordered),
        catalog_selection_sha256=selection_sha,
        authoritative_relationship_leaves_sha256=relationship_sha,
        objective_replay_sha256=canonical_sha256(objective_replay),
        representation_attestation=representation,
        code_version_hashes=_version_hashes(root, _V2_CODE_VERSION_PATHS),
        config_version_hashes=_version_hashes(root, _V2_CONFIG_VERSION_PATHS),
        v1_lineage_root_sha256=canonical_sha256([]),
    )


def _write_exclusive_canonical(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.path.lexists(path):
        raise FileExistsError(f"catalog v2 destination already exists: {path}")
    prepared = Path(tempfile.mkdtemp(prefix=f".{path.name}.prepared-", dir=path.parent))
    temporary = prepared / path.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        encoded = canonical_json_bytes(payload)
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    finally:
        shutil.rmtree(prepared)


def publish_catalog_v2_revision(revision: CatalogRevisionV2, destination: Path | str) -> None:
    """Publish canonical revision bytes once; a partial/replacement write is impossible."""

    path = Path(destination)
    _write_exclusive_canonical(path, revision.model_dump(mode="json"))


def verify_catalog_v2_revision(
    revision_path: Path | str,
    *,
    repository_root: Path | str,
    require_inactive: bool = False,
) -> CatalogRevisionV2:
    """Rebuild every parent-derived field and byte-compare the immutable revision."""

    path = Path(revision_path)
    raw = _stable_regular_bytes(path)
    try:
        revision = CatalogRevisionV2.model_validate(json.loads(raw))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("catalog v2 revision or representation fields are invalid") from exc
    if raw != canonical_json_bytes(revision.model_dump(mode="json")):
        raise ValueError("catalog v2 revision is not canonical JSON")
    if require_inactive and revision.active_revision_sha256 is not None:
        raise ValueError("catalog v2 revision is active")
    root = Path(repository_root).resolve(strict=True)
    _verify_hash_map(root, revision.code_version_hashes, category="code")
    _verify_hash_map(root, revision.config_version_hashes, category="config")
    expected = build_catalog_v2_revision(
        root / revision.adjudication_bundle_path,
        repository_root=root,
    )
    if canonical_json_bytes(revision.model_dump(mode="json")) != canonical_json_bytes(
        expected.model_dump(mode="json")
    ):
        raise ValueError("catalog v2 revision differs from independently rederived parents")
    return revision


def _approval_binding(
    revision: CatalogRevisionV2,
    state: CatalogApprovalStateAttestationV2,
) -> dict[str, object]:
    return {
        "schema_version": "itda.catalog-approval-authority-binding.v2",
        "catalog_revision_sha256": revision.catalog_revision_sha256,
        "state_attestation_sha256": state.state_attestation_sha256,
        "target_sha256": state.approval_target_sha256,
        "combined_target_sha256": revision.combined_target_sha256,
        "representation_attestation_sha256": (
            revision.representation_attestation.representation_attestation_sha256
        ),
        "authoritative_relationship_leaves_sha256": (
            revision.authoritative_relationship_leaves_sha256
        ),
    }


def build_catalog_v2_approval_request(
    revision_path: Path | str,
    *,
    repository_root: Path | str,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    replaces_request_sha256: str | None = None,
    reviewer_channel_risk: str = (
        "Local-channel reviewer identity is accepted metadata and is not cryptographic."
    ),
) -> tuple[CatalogApprovalStateAttestationV2, CatalogApprovalRequestV2]:
    """Freeze one issuance context, after rederiving the exact inactive revision twice."""

    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError("catalog approval nonce must be 64 lowercase hex characters")
    root = Path(repository_root).resolve(strict=True)
    path = Path(revision_path)
    revision = verify_catalog_v2_revision(path, repository_root=root, require_inactive=True)
    again = verify_catalog_v2_revision(path, repository_root=root, require_inactive=True)
    if canonical_json_bytes(revision.model_dump(mode="json")) != canonical_json_bytes(
        again.model_dump(mode="json")
    ):
        raise ValueError("catalog revision changed between approval request replays")
    revision_raw = _stable_regular_bytes(path)
    if revision.catalog_revision_sha256 is None:
        raise ValueError("catalog revision lacks its semantic digest")
    state = CatalogApprovalStateAttestationV2(
        catalog_revision_path=_relative_or_absolute(path, root),
        catalog_revision_file_sha256=hashlib.sha256(revision_raw).hexdigest(),
        catalog_revision_sha256=revision.catalog_revision_sha256,
        combined_target_sha256=revision.combined_target_sha256,
        approval_target_sha256=revision.catalog_revision_sha256,
        authoritative_relationship_leaves_sha256=(
            revision.authoritative_relationship_leaves_sha256
        ),
        representation_attestation=revision.representation_attestation,
        code_version_hashes=revision.code_version_hashes,
        config_version_hashes=revision.config_version_hashes,
        v1_lineage_root_sha256=revision.v1_lineage_root_sha256,
    )
    if state.state_attestation_sha256 is None:
        raise ValueError("catalog approval state lacks its digest")
    binding = _approval_binding(revision, state)
    request = CatalogApprovalRequestV2(
        catalog_revision_sha256=revision.catalog_revision_sha256,
        state_attestation_sha256=state.state_attestation_sha256,
        target_sha256=revision.catalog_revision_sha256,
        representation_attestation_sha256=cast(
            str,
            revision.representation_attestation.representation_attestation_sha256,
        ),
        reviewer_id=reviewer_id,
        binding_sha256=canonical_sha256(binding),
        nonce=nonce,
        issued_at=require_utc(issued_at, field_name="issued_at"),
        expires_at=require_utc(expires_at, field_name="expires_at"),
        replaces_request_sha256=replaces_request_sha256,
        reviewer_channel_risk=reviewer_channel_risk,
    )
    return state, request


def publish_catalog_v2_approval_request(
    state: CatalogApprovalStateAttestationV2,
    request: CatalogApprovalRequestV2,
    *,
    state_path: Path | str,
    request_path: Path | str,
) -> None:
    """Install the state/request pair with rollback on a second-link collision."""

    state_destination = Path(state_path)
    request_destination = Path(request_path)
    if state_destination.exists() or request_destination.exists():
        raise FileExistsError("catalog approval request bundle is no-replace")
    if request.state_attestation_sha256 != state.state_attestation_sha256:
        raise ValueError("catalog approval request and state digests differ")
    parent = state_destination.parent
    if request_destination.parent != parent:
        raise ValueError("catalog approval request files require one atomic parent")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    prepared = Path(tempfile.mkdtemp(prefix=".approval-request-prepared-", dir=parent))
    state_temp = prepared / state_destination.name
    request_temp = prepared / request_destination.name
    state_temp.write_bytes(canonical_json_bytes(state.model_dump(mode="json")))
    request_temp.write_bytes(canonical_json_bytes(request.model_dump(mode="json")))
    state_temp.chmod(0o600)
    request_temp.chmod(0o600)
    for temporary in (state_temp, request_temp):
        descriptor = os.open(temporary, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    installed_state = False
    try:
        os.link(state_temp, state_destination, follow_symlinks=False)
        installed_state = True
        os.link(request_temp, request_destination, follow_symlinks=False)
        directory_descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        if installed_state:
            state_destination.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(prepared)


def _load_v2_model[ModelT: StrictContract](path: Path, model: type[ModelT]) -> ModelT:
    raw = _stable_regular_bytes(path)
    try:
        parsed = model.model_validate(json.loads(raw))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("catalog v2 approval artifact fields are invalid") from exc
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("catalog v2 approval artifact is not canonical JSON")
    return parsed


def check_catalog_v2_approval_request(
    request_path: Path | str,
    state_path: Path | str,
    *,
    revision_path: Path | str | None = None,
    repository_root: Path | str,
) -> CatalogApprovalRequestV2:
    """Verify the actual request/state pair against a live parent replay."""

    root = Path(repository_root).resolve(strict=True)
    state = _load_v2_model(Path(state_path), CatalogApprovalStateAttestationV2)
    request = _load_v2_model(Path(request_path), CatalogApprovalRequestV2)
    revision_candidate = (
        Path(revision_path) if revision_path is not None else root / state.catalog_revision_path
    )
    revision = verify_catalog_v2_revision(
        revision_candidate,
        repository_root=root,
        require_inactive=True,
    )
    if revision.catalog_revision_sha256 is None or state.state_attestation_sha256 is None:
        raise ValueError("catalog approval parent digest is missing")
    revision_raw = _stable_regular_bytes(revision_candidate)
    expected_state, expected_request = build_catalog_v2_approval_request(
        revision_candidate,
        repository_root=root,
        reviewer_id=request.reviewer_id,
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
        replaces_request_sha256=request.replaces_request_sha256,
        reviewer_channel_risk=request.reviewer_channel_risk,
    )
    if (
        state.catalog_revision_file_sha256 != hashlib.sha256(revision_raw).hexdigest()
        or canonical_json_bytes(state.model_dump(mode="json"))
        != canonical_json_bytes(expected_state.model_dump(mode="json"))
        or canonical_json_bytes(request.model_dump(mode="json"))
        != canonical_json_bytes(expected_request.model_dump(mode="json"))
        or request.binding_sha256 != canonical_sha256(_approval_binding(revision, state))
    ):
        raise ValueError("catalog approval request or state differs from live inactive revision")
    return request


def catalog_v2_approval_issuance_context(
    request_path: Path | str,
    state_path: Path | str,
    *,
    revision_path: Path | str | None = None,
    repository_root: Path | str,
) -> AuthorityIssuanceContext:
    """Rederive the sole authority context accepted by the approval consumer."""

    root = Path(repository_root).resolve(strict=True)
    request = check_catalog_v2_approval_request(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=root,
    )
    state = _load_v2_model(Path(state_path), CatalogApprovalStateAttestationV2)
    actual_revision_path = (
        Path(revision_path) if revision_path is not None else root / state.catalog_revision_path
    )
    revision = verify_catalog_v2_revision(
        actual_revision_path,
        repository_root=root,
        require_inactive=True,
    )
    return freeze_issuance_context(
        action="catalog-approve",
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=revision.model_dump(exclude={"catalog_revision_sha256"}, mode="json"),
        reviewer_id=request.reviewer_id,
        binding=_approval_binding(revision, state),
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
        replaces_request_sha256=request.replaces_request_sha256,
        reviewer_channel_risk=request.reviewer_channel_risk,
    )


def _load_catalog_v2_authority_descriptor(
    path: Path,
) -> tuple[AuthorityIssuanceContext, str]:
    visible = path.lstat()
    if (
        not stat.S_ISREG(visible.st_mode)
        or stat.S_IMODE(visible.st_mode) != 0o600
        or visible.st_nlink != 1
    ):
        raise ValueError("catalog approval authority descriptor must be a protected 0600 file")
    raw = _stable_regular_bytes(path, max_bytes=2_000_000)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("catalog approval authority descriptor is invalid JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        raise ValueError("catalog approval authority descriptor must be canonical JSON")
    if set(value) != {"schema_version", "issuance_context", "authority_token"} or (
        value.get("schema_version") != "itda.catalog-approval-authority-descriptor.v2"
    ):
        raise ValueError("catalog approval authority descriptor fields or schema differ")
    token = value.get("authority_token")
    if not isinstance(token, str):
        raise ValueError("catalog approval authority token is missing")
    return AuthorityIssuanceContext.model_validate(value.get("issuance_context")), token


def _catalog_v2_independent_fields(revision: CatalogRevisionV2) -> dict[str, object]:
    return {
        "combined_target_sha256": revision.combined_target_sha256,
        "ordered_place_ids_sha256": revision.ordered_place_ids_sha256,
        "catalog_selection_sha256": revision.catalog_selection_sha256,
        "authoritative_relationship_leaves_sha256": (
            revision.authoritative_relationship_leaves_sha256
        ),
        "objective_replay_sha256": revision.objective_replay_sha256,
        "representation_attestation": revision.representation_attestation.model_dump(mode="json"),
        "code_version_hashes": revision.code_version_hashes,
        "config_version_hashes": revision.config_version_hashes,
    }


def approve_catalog_v2(
    *,
    authority_descriptor_path: Path | str,
    request_path: Path | str,
    state_path: Path | str,
    revision_path: Path | str,
    approval_path: Path | str,
    nonce_ledger_root: Path | str,
    repository_root: Path | str,
    approved_at: datetime,
) -> CatalogApprovalV2:
    """Consume exact one-use authority and publish an approved-but-inactive receipt."""

    root = Path(repository_root).resolve(strict=True)
    request = check_catalog_v2_approval_request(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=root,
    )
    state = _load_v2_model(Path(state_path), CatalogApprovalStateAttestationV2)
    revision = verify_catalog_v2_revision(
        revision_path,
        repository_root=root,
        require_inactive=True,
    )
    expected_context = catalog_v2_approval_issuance_context(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=root,
    )
    supplied_context, raw_token = _load_catalog_v2_authority_descriptor(
        Path(authority_descriptor_path)
    )
    if supplied_context.model_dump(mode="json") != expected_context.model_dump(mode="json"):
        raise ValueError("catalog approval authority context differs from live parents")
    canonical_approved_at = require_utc(approved_at, field_name="approved_at")
    validated = validate_authority_token(
        raw_token,
        issuance_context=expected_context,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=revision.model_dump(exclude={"catalog_revision_sha256"}, mode="json"),
        binding=_approval_binding(revision, state),
        reviewer_id=request.reviewer_id,
        now=canonical_approved_at,
        revocation_tombstones=(),
    )
    if (
        revision.catalog_revision_sha256 is None
        or request.request_sha256 is None
        or state.state_attestation_sha256 is None
        or expected_context.context_sha256 is None
        or revision.representation_attestation.representation_attestation_sha256 is None
    ):
        raise ValueError("catalog approval parent digest is missing")
    approval = CatalogApprovalV2(
        catalog_revision_path=_relative_or_absolute(Path(revision_path), root),
        approval_request_path=_relative_or_absolute(Path(request_path), root),
        approval_state_path=_relative_or_absolute(Path(state_path), root),
        catalog_revision_sha256=revision.catalog_revision_sha256,
        request_sha256=request.request_sha256,
        state_attestation_sha256=state.state_attestation_sha256,
        target_sha256=request.target_sha256,
        representation_attestation_sha256=(
            revision.representation_attestation.representation_attestation_sha256
        ),
        independently_rederived_fields_sha256=canonical_sha256(
            _catalog_v2_independent_fields(revision)
        ),
        authoritative_relationship_leaves_sha256=(
            revision.authoritative_relationship_leaves_sha256
        ),
        reviewer_id=request.reviewer_id,
        approved_at=canonical_approved_at,
        token_sha256=validated.token_sha256,
        nonce_sha256=hashlib.sha256(request.nonce.encode("ascii")).hexdigest(),
        issuance_context_sha256=expected_context.context_sha256,
        reviewer_channel_risk=request.reviewer_channel_risk,
    )
    destination = Path(approval_path)

    def publish() -> Mapping[str, object]:
        _write_exclusive_canonical(destination, approval.model_dump(mode="json"))
        return {"result_sha256": revision.catalog_revision_sha256}

    def relookup() -> Mapping[str, object] | None:
        if not destination.exists():
            return None
        existing = _load_v2_model(destination, CatalogApprovalV2)
        if existing.model_dump(mode="json") != approval.model_dump(mode="json"):
            raise FileExistsError("existing catalog approval differs")
        return {"result_sha256": revision.catalog_revision_sha256}

    FileNonceLedger(Path(nonce_ledger_root)).consume_with_mutation(
        validated,
        mutation=publish,
        relookup=relookup,
    )
    return approval


def verify_catalog_v2_approval(
    approval_path: Path | str,
    *,
    repository_root: Path | str,
    require_inactive: bool = False,
) -> CatalogApprovalV2:
    """Verify a later human approval without treating it as activation."""

    root = Path(repository_root).resolve(strict=True)
    approval = _load_v2_model(Path(approval_path), CatalogApprovalV2)
    revision_path = root / approval.catalog_revision_path
    request_path = root / approval.approval_request_path
    state_path = root / approval.approval_state_path
    request = check_catalog_v2_approval_request(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=root,
    )
    revision = verify_catalog_v2_revision(
        revision_path,
        repository_root=root,
        require_inactive=require_inactive,
    )
    context = catalog_v2_approval_issuance_context(
        request_path,
        state_path,
        revision_path=revision_path,
        repository_root=root,
    )
    if context.context_sha256 is None:
        raise ValueError("catalog approval issuance context digest is missing")
    expected_token_sha256 = hashlib.sha256(
        context.expected_token().serialize().encode("ascii")
    ).hexdigest()
    if (
        approval.request_sha256 != request.request_sha256
        or approval.state_attestation_sha256 != request.state_attestation_sha256
        or approval.target_sha256 != request.target_sha256
        or approval.reviewer_id != request.reviewer_id
        or approval.reviewer_channel_risk != request.reviewer_channel_risk
        or approval.catalog_revision_sha256 != revision.catalog_revision_sha256
        or approval.representation_attestation_sha256
        != revision.representation_attestation.representation_attestation_sha256
        or approval.independently_rederived_fields_sha256
        != canonical_sha256(_catalog_v2_independent_fields(revision))
        or approval.authoritative_relationship_leaves_sha256
        != revision.authoritative_relationship_leaves_sha256
        or approval.token_sha256 != expected_token_sha256
        or approval.nonce_sha256 != hashlib.sha256(request.nonce.encode("ascii")).hexdigest()
        or approval.issuance_context_sha256 != context.context_sha256
        or approval.approved_at < request.issued_at
        or approval.approved_at >= request.expires_at
        or approval.active_revision_sha256 is not None
        or approval.activation_event_sha256 is not None
    ):
        raise ValueError("catalog approval differs from independently rederived inactive state")
    return approval


__all__ = [
    "CatalogAdjudication",
    "CatalogAdjudicationRow",
    "CatalogApproval",
    "CatalogApprovalRequestV2",
    "CatalogApprovalStateAttestationV2",
    "CatalogApprovalV2",
    "CatalogRepresentationAttestationV2",
    "CatalogRevisionV2",
    "CatalogGateReport",
    "CatalogReviewRequest",
    "CatalogReviewRequestRow",
    "GateOutcome",
    "RevisionActivationEvent",
    "VerifiedCatalogAdjudication",
    "append_revision_activation_event",
    "approve_catalog",
    "approve_catalog_v2",
    "build_catalog_review_request",
    "build_catalog_gate_report",
    "canonical_catalog_sha256",
    "catalog_v2_approval_issuance_context",
    "check_catalog_v2_approval_request",
    "evaluate_catalog_gate_report",
    "load_adjudication_decisions",
    "load_catalog_review_truth",
    "load_reviewed_catalog_revision",
    "materialize_reviewed_catalog",
    "prepare_catalog_adjudication",
    "publish_catalog_v2_approval_request",
    "publish_catalog_v2_revision",
    "publish_catalog_release",
    "verify_catalog_adjudication",
    "verify_catalog_v2_approval",
    "verify_catalog_v2_revision",
    "build_catalog_v2_approval_request",
    "build_catalog_v2_revision",
]
