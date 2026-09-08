"""Build, check, consume, and verify confidential real-split approval authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.cli.build_real_split import (
    ACTIVE_BINDING_FIELDS,
    COMPLETENESS_BIN_ORDER,
    OBJECTIVE_ORDER,
    _current_active_parents,
    build_authoritative_hard_components,
    build_balance_outcome,
    verify_human_axis_authority,
    verify_materialized_bundle,
)
from itda.contracts.authority import (
    AuthorityConsumptionReceipt,
    AuthorityIssuanceContext,
    AuthorityMutationUncertain,
    AuthorityReplayError,
    AuthorityTokenV2,
    FileNonceLedger,
    validate_authority_token,
)
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.catalog_manifest import (
    AuthoritativeSafeInputRoot,
    HumanAxisJudgmentApproval,
    HumanAxisRuleRoot,
    MaterializedRealSplitManifest,
    RealSplitBalanceOutcome,
    RealSplitDeterminismReport,
    RealSplitMaterializationBundle,
    RealSplitMaterializationRequest,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

DEFAULT_BUNDLE = Path(
    "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json"
)
DEFAULT_STATE = Path(
    "artifacts/restricted/catalog/v2/split/split-approval-state-attestation.json"
)
DEFAULT_REQUEST = Path("artifacts/public/catalog/v2/split-approval-request.json")
DEFAULT_APPROVAL = Path("artifacts/restricted/catalog/v2/split/real-split-approval.json")
MATERIALIZATION_REQUEST = Path("artifacts/public/catalog/v2/split-materialization-request.json")
MATERIALIZER_LEDGER = Path(
    "artifacts/restricted/catalog/v2/split/.authority-ledger/authority-consumption-ledger.jsonl"
)
APPROVAL_LEDGER = Path(
    "artifacts/restricted/catalog/v2/split/.split-approval-authority-ledger"
)

_REVIEWER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "dev_members",
        "blind_members",
        "members",
        "safe_input_rows",
        "components",
        "component_priority_rows",
        "deviation_numerators",
        "exact_targets",
        "ordered_place_ids",
    }
)
_PUBLIC_PROOF_HASH_FIELDS = (
    "active_bindings_sha256",
    "materialized_bundle_sha256",
    "manifest_sha256",
    "determinism_report_sha256",
    "materialization_result_sha256",
    "materialization_receipt_sha256",
    "split_semantic_sha256",
    "authoritative_safe_input_root_sha256",
    "safe_input_sha256",
    "completeness_rule_sha256",
    "completeness_bins_sha256",
    "tolerance_sha256",
    "objective_order_sha256",
    "objective_tuple_sha256",
    "component_universe_sha256",
    "component_priority_root_sha256",
    "deviation_numerators_sha256",
    "exact_targets_sha256",
    "reachability_certificate_sha256",
    "proof_certificate_sha256",
    "outcome_sha256",
    "candidate_sha256",
)
_raise_uncertain_after_write = False


def _sha(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _read_canonical(path: Path, *, private: bool | None = None) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("approval input must be a regular canonical JSON file")
    if private is not None:
        expected_mode = 0o600 if private else 0o644
        if path.stat().st_mode & 0o777 != expected_mode:
            raise ValueError("approval input mode is not canonical")
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or raw != canonical_json_bytes(payload):
        raise ValueError("approval input bytes are not canonical")
    return payload


def _repo_path(repo_root: Path, value: Path) -> Path:
    candidate = (
        value.resolve()
        if value.is_absolute() or (value.parts and value.parts[0] == "..")
        else (repo_root / value).resolve()
    )
    if candidate != repo_root and repo_root not in candidate.parents:
        raise ValueError("split approval path escapes the repository root")
    return candidate


def _active_bindings_sha256(parents: Mapping[str, object]) -> str:
    if set(parents) != set(ACTIVE_BINDING_FIELDS):
        raise ValueError("active catalog parent set is incomplete")
    return canonical_sha256(
        {field: _sha(parents[field], field) for field in ACTIVE_BINDING_FIELDS}
    )


class ReverifiedSplitFacts(StrictContract):
    """Restricted in-memory facts; never serialize this model publicly."""

    manifest: MaterializedRealSplitManifest
    report: RealSplitDeterminismReport
    bundle: RealSplitMaterializationBundle
    outcome: RealSplitBalanceOutcome
    active_parents: dict[str, Sha256]
    active_bindings_sha256: Sha256
    materializer_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    materialization_receipt_sha256: Sha256
    authoritative_safe_input_root_sha256: Sha256


class SplitApprovalStateAttestation(StrictContract):
    schema_version: Literal["itda.real-split-approval-state.v2"] = (
        "itda.real-split-approval-state.v2"
    )
    status: Literal["MATERIALIZED_UNAPPROVED"] = "MATERIALIZED_UNAPPROVED"
    dev_count: Literal[24] = 24
    blind_count: Literal[12] = 12
    materializer_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    split_approver_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    active_bindings_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    catalog_approval_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    active_ordered_place_ids_sha256: Sha256
    materialized_bundle_sha256: Sha256
    manifest_sha256: Sha256
    determinism_report_sha256: Sha256
    materialization_result_sha256: Sha256
    materialization_receipt_sha256: Sha256
    split_semantic_sha256: Sha256
    authoritative_safe_input_root_sha256: Sha256
    safe_input_sha256: Sha256
    completeness_rule_sha256: Sha256
    completeness_bins_sha256: Sha256
    tolerance_sha256: Sha256
    objective_order_sha256: Sha256
    objective_tuple_sha256: Sha256
    component_universe_sha256: Sha256
    component_priority_root_sha256: Sha256
    deviation_numerators_sha256: Sha256
    exact_targets_sha256: Sha256
    reachability_certificate_sha256: Sha256
    proof_certificate_sha256: Sha256
    outcome_sha256: Sha256
    candidate_sha256: Sha256
    split_approval_sha256: None = None
    seal_sha256: None = None
    state_attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.materializer_id == self.split_approver_id:
            raise ValueError("split approver must be distinct from materializer")
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif self.state_attestation_sha256 != expected:
            raise ValueError("split approval state attestation is stale")
        return self


class RealSplitApprovalRequestV2(StrictContract):
    schema_version: Literal["itda.real-split-approval-request.v2"] = (
        "itda.real-split-approval-request.v2"
    )
    action: Literal["split-approve"] = "split-approve"
    request_sha256: Sha256 | None = None
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    materializer_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    split_approver_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    nonce: Sha256
    issued_at: datetime
    expires_at: datetime
    dev_count: Literal[24] = 24
    blind_count: Literal[12] = 12
    active_bindings_sha256: Sha256
    materialized_bundle_sha256: Sha256
    manifest_sha256: Sha256
    determinism_report_sha256: Sha256
    materialization_result_sha256: Sha256
    materialization_receipt_sha256: Sha256
    split_semantic_sha256: Sha256
    authoritative_safe_input_root_sha256: Sha256
    safe_input_sha256: Sha256
    completeness_rule_sha256: Sha256
    completeness_bins_sha256: Sha256
    tolerance_sha256: Sha256
    objective_order_sha256: Sha256
    objective_tuple_sha256: Sha256
    component_universe_sha256: Sha256
    component_priority_root_sha256: Sha256
    deviation_numerators_sha256: Sha256
    exact_targets_sha256: Sha256
    reachability_certificate_sha256: Sha256
    proof_certificate_sha256: Sha256
    outcome_sha256: Sha256
    candidate_sha256: Sha256

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime, info: Any) -> datetime:
        return require_utc(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if self.materializer_id == self.split_approver_id:
            raise ValueError("split approver must be distinct from materializer")
        if self.expires_at <= self.issued_at:
            raise ValueError("split approval request expiry must follow issuance")
        expected = canonical_sha256(
            self.model_dump(exclude={"request_sha256"}, mode="json")
        )
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif self.request_sha256 != expected:
            raise ValueError("split approval request hash is stale")
        return self

    def expected_token(self) -> AuthorityTokenV2:
        return AuthorityTokenV2(
            action=self.action,
            request_sha256=_sha(self.request_sha256, "request"),
            state_attestation_sha256=self.state_attestation_sha256,
            target_sha256=self.target_sha256,
            reviewer_id=self.split_approver_id,
            binding_sha256=self.binding_sha256,
            nonce=self.nonce,
        )


class RealSplitApprovalReceiptV2(StrictContract):
    schema_version: Literal["itda.real-split-approval.v2"] = "itda.real-split-approval.v2"
    status: Literal["APPROVED_UNSEALED"] = "APPROVED_UNSEALED"
    request_sha256: Sha256
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    binding_sha256: Sha256
    materializer_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    split_approver_id: Annotated[str, Field(strict=True, pattern=_REVIEWER_PATTERN)]
    approved_at: datetime
    token_sha256: Sha256
    nonce_sha256: Sha256
    active_bindings_sha256: Sha256
    materialized_bundle_sha256: Sha256
    manifest_sha256: Sha256
    determinism_report_sha256: Sha256
    materialization_result_sha256: Sha256
    materialization_receipt_sha256: Sha256
    split_semantic_sha256: Sha256
    authoritative_safe_input_root_sha256: Sha256
    safe_input_sha256: Sha256
    completeness_rule_sha256: Sha256
    completeness_bins_sha256: Sha256
    tolerance_sha256: Sha256
    objective_order_sha256: Sha256
    objective_tuple_sha256: Sha256
    component_universe_sha256: Sha256
    component_priority_root_sha256: Sha256
    deviation_numerators_sha256: Sha256
    exact_targets_sha256: Sha256
    reachability_certificate_sha256: Sha256
    proof_certificate_sha256: Sha256
    outcome_sha256: Sha256
    candidate_sha256: Sha256
    seal_sha256: None = None
    approval_sha256: Sha256 | None = None

    @field_validator("approved_at")
    @classmethod
    def approved_at_is_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="approved_at")

    @model_validator(mode="after")
    def validate_approval(self) -> Self:
        if self.materializer_id == self.split_approver_id:
            raise ValueError("split approver must be distinct from materializer")
        expected = canonical_sha256(self.model_dump(exclude={"approval_sha256"}, mode="json"))
        if self.approval_sha256 is None:
            object.__setattr__(self, "approval_sha256", expected)
        elif self.approval_sha256 != expected:
            raise ValueError("split approval receipt hash is stale")
        return self


def _load_model[ModelT: StrictContract](path: Path, model: type[ModelT]) -> ModelT:
    payload = _read_canonical(path)
    parsed = model.model_validate(payload)
    if path.read_bytes() != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("approval input differs from its typed canonical form")
    return parsed


def _find_authoritative_safe_input(
    split_root: Path,
    *,
    expected_safe_input_sha256: str,
    active_parents: Mapping[str, str],
) -> AuthoritativeSafeInputRoot:
    base = split_root / "authoritative-safe-inputs"
    if base.is_symlink() or not base.is_dir():
        raise ValueError("authoritative safe-input root is unavailable")
    matches: list[AuthoritativeSafeInputRoot] = []
    for directory in sorted(base.iterdir()):
        path = directory / "authoritative-safe-input.json"
        if directory.is_symlink() or not directory.is_dir() or not path.exists():
            continue
        safe = _load_model(path, AuthoritativeSafeInputRoot)
        if safe.safe_input_sha256 != expected_safe_input_sha256:
            continue
        if any(getattr(safe, field) != active_parents[field] for field in ACTIVE_BINDING_FIELDS):
            continue
        if safe.authoritative_safe_input_root_sha256 != directory.name:
            raise ValueError("authoritative safe-input address is stale")
        matches.append(safe)
    if len(matches) != 1:
        raise ValueError("exactly one current authoritative safe-input root is required")
    safe = matches[0]
    rule_path = (
        split_root
        / "human-axis-rule-roots"
        / safe.human_axis_rule_root_sha256
        / "human-axis-rule.json"
    )
    approval_path = (
        split_root
        / "human-axis-judgment-approvals"
        / safe.human_axis_approval_sha256
        / "human-axis-judgment-approval.json"
    )
    verify_human_axis_authority(
        rule=_load_model(rule_path, HumanAxisRuleRoot),
        approval=_load_model(approval_path, HumanAxisJudgmentApproval),
        safe_input=safe,
    )
    return safe


def verify_reinf13_models(
    *,
    outcome: Mapping[str, object] | RealSplitBalanceOutcome,
    manifest: Mapping[str, object] | MaterializedRealSplitManifest,
    report: Mapping[str, object] | RealSplitDeterminismReport,
    bundle: Mapping[str, object] | RealSplitMaterializationBundle,
    rebuilt: Mapping[str, object] | RealSplitBalanceOutcome,
) -> RealSplitBalanceOutcome:
    outcome_model = RealSplitBalanceOutcome.model_validate(outcome)
    manifest_model = MaterializedRealSplitManifest.model_validate(manifest)
    report_model = RealSplitDeterminismReport.model_validate(report)
    bundle_model = RealSplitMaterializationBundle.model_validate(bundle)
    rebuilt_model = RealSplitBalanceOutcome.model_validate(rebuilt)
    if outcome_model.status != "FEASIBLE" or outcome_model.candidate is None:
        raise ValueError("BALANCE_INFEASIBLE split cannot receive an approval request")
    if outcome_model != rebuilt_model:
        raise ValueError("stored split proof is not the independently rebuilt global optimum")
    proof = outcome_model.proof
    candidate = outcome_model.candidate
    if (
        proof.objective_order != OBJECTIVE_ORDER
        or proof.priority_rule_version != "seeded-component-additive-priority-v1"
        or proof.seed != 42
        or proof.tolerance != 1
        or proof.tolerance_numerator != 3
        or proof.completeness_bin_order != COMPLETENESS_BIN_ORDER
        or proof.objective_tuple is None
        or proof.objective_tuple != proof.unconstrained_objective_tuple
        or any(value > 3 for value in proof.deviation_numerators.values())
    ):
        raise ValueError("REINF-13 objective, tolerance, bins, or deviation proof drifted")
    if (
        manifest_model.status != "MATERIALIZED_UNAPPROVED"
        or manifest_model.split_approval_sha256 is not None
        or manifest_model.seal_sha256 is not None
        or manifest_model.dev_members != candidate.dev_members
        or manifest_model.blind_members != candidate.blind_members
        or manifest_model.membership_sha256 != candidate.membership_sha256
        or manifest_model.outcome_sha256 != outcome_model.outcome_sha256
        or manifest_model.proof_certificate_sha256 != proof.proof_certificate_sha256
        or report_model.seed != 42
        or report_model.safe_input_sha256 != proof.safe_input_sha256
        or report_model.component_universe_sha256 != proof.component_universe_sha256
        or report_model.proof_certificate_sha256 != proof.proof_certificate_sha256
        or report_model.outcome_sha256 != outcome_model.outcome_sha256
        or report_model.membership_sha256 != candidate.membership_sha256
        or bundle_model.manifest_sha256 != manifest_model.manifest_sha256
        or bundle_model.report_sha256 != report_model.report_sha256
    ):
        raise ValueError("materialized split, determinism report, or optimum proof drifted")
    expected_result = canonical_sha256(
        {
            "manifest_sha256": manifest_model.manifest_sha256,
            "report_sha256": report_model.report_sha256,
        }
    )
    if bundle_model.result_sha256 != expected_result:
        raise ValueError("materialization result commitment drifted")
    return outcome_model


def _materialization_receipt(
    repo_root: Path,
    *,
    request: RealSplitMaterializationRequest,
    bundle: RealSplitMaterializationBundle,
) -> AuthorityConsumptionReceipt:
    ledger_path = repo_root / MATERIALIZER_LEDGER
    if ledger_path.is_symlink() or not ledger_path.is_file():
        raise ValueError("materialization authority receipt ledger is unavailable")
    matches: list[AuthorityConsumptionReceipt] = []
    for raw in ledger_path.read_bytes().splitlines():
        receipt = AuthorityConsumptionReceipt.model_validate(json.loads(raw))
        if raw != canonical_json_bytes(receipt.model_dump(mode="json")):
            raise ValueError("materialization authority receipt is noncanonical")
        if (
            receipt.action == "real-split-materialize"
            and receipt.request_sha256 == request.request_sha256
            and receipt.state_attestation_sha256 == bundle.state_attestation_sha256
            and receipt.target_sha256 == bundle.target_sha256
            and receipt.result_sha256 == bundle.result_sha256
        ):
            matches.append(receipt)
    if len(matches) != 1 or matches[0].reviewer_id != request.reviewer_id:
        raise ValueError("materialization requires one exact committed authority receipt")
    return matches[0]


def reverify_materialized_split(
    repo_root: Path | str,
    materialized_bundle_path: Path | str,
) -> ReverifiedSplitFacts:
    root = Path(repo_root).resolve(strict=True)
    bundle_path = Path(materialized_bundle_path)
    if not bundle_path.is_absolute():
        bundle_path = root / bundle_path
    bundle = verify_materialized_bundle(bundle_path)
    split_root = bundle_path.parent
    manifest = _load_model(split_root / "real-split-manifest.json", MaterializedRealSplitManifest)
    report = _load_model(
        split_root / "real-split-determinism-report.json", RealSplitDeterminismReport
    )
    outcome = _load_model(split_root / "real-split-balance-outcome.json", RealSplitBalanceOutcome)
    active_parents, ordered_ids, relationship_path = _current_active_parents(root)
    active_bindings = _active_bindings_sha256(active_parents)
    safe = _find_authoritative_safe_input(
        split_root,
        expected_safe_input_sha256=report.safe_input_sha256,
        active_parents=active_parents,
    )
    if {row.source_neutral_place_id for row in safe.rows} != set(ordered_ids):
        raise ValueError("authoritative safe inputs differ from the active catalog universe")
    components = build_authoritative_hard_components(
        ordered_ids,
        relationship_path,
        active_revision_sha256=active_parents["catalog_revision_sha256"],
    )
    if components.component_universe_sha256 != report.component_universe_sha256:
        raise ValueError("active D-09..D-11 component universe drifted")
    rebuilt = build_balance_outcome(
        safe.rows,
        components.components,
        blind_size=12,
        seed=42,
        authority_bindings_sha256=outcome.proof.authority_bindings_sha256,
    )
    verified = verify_reinf13_models(
        outcome=outcome,
        manifest=manifest,
        report=report,
        bundle=bundle,
        rebuilt=rebuilt,
    )
    materialization_request = _load_model(
        root / MATERIALIZATION_REQUEST, RealSplitMaterializationRequest
    )
    if materialization_request.request_sha256 != bundle.request_sha256:
        raise ValueError("materializer identity request differs from the committed bundle")
    materialization_receipt = _materialization_receipt(
        root, request=materialization_request, bundle=bundle
    )
    return ReverifiedSplitFacts(
        manifest=manifest,
        report=report,
        bundle=bundle,
        outcome=verified,
        active_parents={field: active_parents[field] for field in ACTIVE_BINDING_FIELDS},
        active_bindings_sha256=active_bindings,
        materializer_id=materialization_request.reviewer_id,
        materialization_receipt_sha256=_sha(
            materialization_receipt.receipt_sha256, "materialization receipt"
        ),
        authoritative_safe_input_root_sha256=_sha(
            safe.authoritative_safe_input_root_sha256, "authoritative safe input root"
        ),
    )


def _proof_hashes(facts: ReverifiedSplitFacts) -> dict[str, str]:
    proof = facts.outcome.proof
    candidate = facts.outcome.candidate
    if candidate is None or proof.objective_tuple is None:
        raise ValueError("a feasible candidate and objective are required")
    return {
        "split_semantic_sha256": candidate.membership_sha256,
        "authoritative_safe_input_root_sha256": facts.authoritative_safe_input_root_sha256,
        "safe_input_sha256": proof.safe_input_sha256,
        "completeness_rule_sha256": proof.completeness_rule_sha256,
        "completeness_bins_sha256": canonical_sha256(list(proof.completeness_bin_order)),
        "tolerance_sha256": canonical_sha256(
            {"tolerance": proof.tolerance, "tolerance_numerator": proof.tolerance_numerator}
        ),
        "objective_order_sha256": canonical_sha256(list(proof.objective_order)),
        "objective_tuple_sha256": canonical_sha256(list(proof.objective_tuple)),
        "component_universe_sha256": proof.component_universe_sha256,
        "component_priority_root_sha256": proof.component_priority_root_sha256,
        "deviation_numerators_sha256": canonical_sha256(proof.deviation_numerators),
        "exact_targets_sha256": proof.exact_targets_sha256,
        "reachability_certificate_sha256": _sha(
            proof.reachability.certificate_sha256, "reachability certificate"
        ),
        "proof_certificate_sha256": _sha(
            proof.proof_certificate_sha256, "proof certificate"
        ),
        "outcome_sha256": _sha(facts.outcome.outcome_sha256, "outcome"),
        "candidate_sha256": _sha(candidate.candidate_sha256, "candidate"),
    }


def _state_from_facts(
    facts: ReverifiedSplitFacts, *, split_approver_id: str
) -> SplitApprovalStateAttestation:
    hashes = _proof_hashes(facts)
    return SplitApprovalStateAttestation.model_validate(
        {
            "materializer_id": facts.materializer_id,
            "split_approver_id": split_approver_id,
            "active_bindings_sha256": facts.active_bindings_sha256,
            **facts.active_parents,
            "materialized_bundle_sha256": _sha(facts.bundle.bundle_sha256, "bundle"),
            "manifest_sha256": _sha(facts.manifest.manifest_sha256, "manifest"),
            "determinism_report_sha256": _sha(facts.report.report_sha256, "report"),
            "materialization_result_sha256": facts.bundle.result_sha256,
            "materialization_receipt_sha256": facts.materialization_receipt_sha256,
            **hashes,
        }
    )


def _target(state: SplitApprovalStateAttestation) -> dict[str, object]:
    excluded = {
        "schema_version",
        "status",
        "split_approval_sha256",
        "seal_sha256",
        "state_attestation_sha256",
    }
    return {
        "action": "split-approve",
        "state_attestation_sha256": state.state_attestation_sha256,
        **{
            key: value
            for key, value in state.model_dump(mode="json").items()
            if key not in excluded
        },
    }


def _binding(
    state: SplitApprovalStateAttestation,
    target: Mapping[str, object],
) -> dict[str, object]:
    return {
        "consumer": "itda.real-split-approve.v2",
        "active_parents_sha256": state.active_bindings_sha256,
        "materialized_bundle_sha256": state.materialized_bundle_sha256,
        "target": dict(target),
    }


def _request_from_state(
    state: SplitApprovalStateAttestation,
    *,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> RealSplitApprovalRequestV2:
    target = _target(state)
    binding = _binding(state, target)
    fields = state.model_dump(mode="json")
    public_hash_fields = {key: fields[key] for key in _PUBLIC_PROOF_HASH_FIELDS}
    return RealSplitApprovalRequestV2(
        state_attestation_sha256=_sha(state.state_attestation_sha256, "state"),
        target_sha256=canonical_sha256(target),
        binding_sha256=canonical_sha256(binding),
        materializer_id=state.materializer_id,
        split_approver_id=state.split_approver_id,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        **public_hash_fields,
    )


def build_split_approval_authority(
    *,
    repo_root: Path | str,
    materialized_bundle_path: Path | str,
    split_approver_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> tuple[SplitApprovalStateAttestation, RealSplitApprovalRequestV2]:
    materialization_request = _load_model(
        Path(repo_root).resolve(strict=True) / MATERIALIZATION_REQUEST,
        RealSplitMaterializationRequest,
    )
    if split_approver_id == materialization_request.reviewer_id:
        raise ValueError("split approver must be distinct from materializer")
    facts = reverify_materialized_split(repo_root, materialized_bundle_path)
    state = _state_from_facts(facts, split_approver_id=split_approver_id)
    request = _request_from_state(
        state,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    _assert_public_request_safe(request)
    return state, request


def _assert_public_request_safe(request: RealSplitApprovalRequestV2) -> None:
    payload = request.model_dump(mode="json")
    serialized = canonical_json_bytes(payload).decode("utf-8").casefold()
    if "place:" in serialized or _FORBIDDEN_PUBLIC_KEYS & set(payload):
        raise ValueError("public split approval request leaks restricted membership")


def _write_no_replace(path: Path, payload: Mapping[str, object], *, private: bool) -> None:
    data = canonical_json_bytes(payload)
    mode = 0o600 if private else 0o644
    parent_mode = 0o700 if private else 0o755
    path.parent.mkdir(parents=True, exist_ok=True, mode=parent_mode)
    if path.exists():
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_mode & 0o777 != mode
            or path.read_bytes() != data
        ):
            raise ValueError("existing no-replace approval artifact drifted")
        return
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode
    )
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short write while publishing split approval artifact")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def publish_split_approval_authority(
    state: SplitApprovalStateAttestation,
    request: RealSplitApprovalRequestV2,
    *,
    state_path: Path,
    request_path: Path,
) -> None:
    _assert_public_request_safe(request)
    if request.state_attestation_sha256 != state.state_attestation_sha256:
        raise ValueError("split approval state and request differ")
    state_preexisted = state_path.exists()
    _write_no_replace(state_path, state.model_dump(mode="json"), private=True)
    try:
        _write_no_replace(request_path, request.model_dump(mode="json"), private=False)
    except Exception:
        expected_state_bytes = canonical_json_bytes(state.model_dump(mode="json"))
        if (
            not state_preexisted
            and state_path.exists()
            and state_path.read_bytes() == expected_state_bytes
        ):
            state_path.unlink()
        raise


def check_split_approval_request(
    *,
    request_path: Path,
    state_path: Path,
    repo_root: Path | str,
    materialized_bundle_path: Path | str,
) -> RealSplitApprovalRequestV2:
    state = _load_model(state_path, SplitApprovalStateAttestation)
    request = _load_model(request_path, RealSplitApprovalRequestV2)
    facts = reverify_materialized_split(repo_root, materialized_bundle_path)
    expected_state = _state_from_facts(facts, split_approver_id=request.split_approver_id)
    expected_request = _request_from_state(
        expected_state,
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
    )
    if state != expected_state or request != expected_request:
        raise ValueError("split approval request or state drifted from live protected parents")
    _assert_public_request_safe(request)
    return request


def _authority_context(request: RealSplitApprovalRequestV2) -> AuthorityIssuanceContext:
    return AuthorityIssuanceContext(
        action=request.action,
        request_sha256=_sha(request.request_sha256, "request"),
        state_attestation_sha256=request.state_attestation_sha256,
        target_sha256=request.target_sha256,
        reviewer_id=request.split_approver_id,
        binding_sha256=request.binding_sha256,
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
        reviewer_channel_risk=(
            "Reviewer identity is accepted local-channel metadata, "
            "not a cryptographic identity claim."
        ),
    )


def _approval_from_request(
    request: RealSplitApprovalRequestV2,
    *,
    approved_at: datetime,
    token_sha256: str,
) -> RealSplitApprovalReceiptV2:
    values = request.model_dump(mode="json")
    proof_fields = {key: values[key] for key in _PUBLIC_PROOF_HASH_FIELDS}
    return RealSplitApprovalReceiptV2(
        request_sha256=_sha(request.request_sha256, "request"),
        state_attestation_sha256=request.state_attestation_sha256,
        target_sha256=request.target_sha256,
        binding_sha256=request.binding_sha256,
        materializer_id=request.materializer_id,
        split_approver_id=request.split_approver_id,
        approved_at=approved_at,
        token_sha256=token_sha256,
        nonce_sha256=hashlib.sha256(request.nonce.encode("ascii")).hexdigest(),
        **proof_fields,
    )


def consume_split_approval(
    *,
    raw_token: str,
    request_path: Path,
    state_path: Path,
    materialized_bundle_path: Path | str,
    approval_path: Path,
    nonce_ledger_root: Path,
    repo_root: Path | str,
    approved_at: datetime,
    require_independent: bool,
) -> RealSplitApprovalReceiptV2:
    if not require_independent:
        raise ValueError("split approval consumption requires independent reviewer enforcement")
    request = check_split_approval_request(
        request_path=request_path,
        state_path=state_path,
        repo_root=repo_root,
        materialized_bundle_path=materialized_bundle_path,
    )
    state = _load_model(state_path, SplitApprovalStateAttestation)
    if request.materializer_id == request.split_approver_id:
        raise ValueError("split approver must be distinct from materializer")
    target = _target(state)
    binding = _binding(state, target)
    context = _authority_context(request)
    validated = validate_authority_token(
        raw_token,
        issuance_context=context,
        request=request.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        binding=binding,
        reviewer_id=request.split_approver_id,
        now=approved_at,
        revocation_tombstones=(),
    )
    approval = _approval_from_request(
        request, approved_at=approved_at, token_sha256=validated.token_sha256
    )

    def relookup() -> Mapping[str, object] | None:
        if not approval_path.exists():
            return None
        existing = _load_model(approval_path, RealSplitApprovalReceiptV2)
        if existing != approval:
            raise ValueError("existing split approval receipt drifted")
        return {"result_sha256": _sha(existing.approval_sha256, "approval")}

    def mutate() -> Mapping[str, object]:
        _write_no_replace(approval_path, approval.model_dump(mode="json"), private=True)
        if _raise_uncertain_after_write:
            raise AuthorityMutationUncertain("simulated uncertain split approval publication")
        return {"result_sha256": _sha(approval.approval_sha256, "approval")}

    ledger = FileNonceLedger(nonce_ledger_root)
    try:
        receipt = ledger.consume_with_mutation(
            validated,
            mutation=mutate,
            relookup=relookup,
        )
    except AuthorityReplayError:
        existing = relookup()
        if existing is None:
            raise
        return _load_model(approval_path, RealSplitApprovalReceiptV2)
    if receipt.result_sha256 != approval.approval_sha256:
        raise ValueError("split approval nonce receipt result drifted")
    return _load_model(approval_path, RealSplitApprovalReceiptV2)


def verify_split_approval(
    approval_path: Path | str,
    *,
    repo_root: Path | str,
    materialized_bundle_path: Path | str,
    require_independent: bool,
    request_path: Path | None = None,
    state_path: Path | None = None,
    nonce_ledger_root: Path | None = None,
) -> RealSplitApprovalReceiptV2:
    if not require_independent:
        raise ValueError("split approval verification requires independent reviewer enforcement")
    approval = _load_model(Path(approval_path), RealSplitApprovalReceiptV2)
    root = Path(repo_root).resolve(strict=True)
    checked_request_path = request_path or root / DEFAULT_REQUEST
    checked_state_path = state_path or root / DEFAULT_STATE
    request = check_split_approval_request(
        request_path=checked_request_path,
        state_path=checked_state_path,
        repo_root=repo_root,
        materialized_bundle_path=materialized_bundle_path,
    )
    expected_fields = _approval_from_request(
        request,
        approved_at=approval.approved_at,
        token_sha256=approval.token_sha256,
    )
    if approval != expected_fields or approval.materializer_id == approval.split_approver_id:
        raise ValueError("split approval receipt differs from independently rebuilt authority")
    ledger_root = nonce_ledger_root or root / APPROVAL_LEDGER
    ledger_path = ledger_root / "authority-consumption-ledger.jsonl"
    if ledger_path.is_symlink() or not ledger_path.is_file():
        raise ValueError("split approval authority receipt ledger is unavailable")
    matches: list[AuthorityConsumptionReceipt] = []
    for raw in ledger_path.read_bytes().splitlines():
        receipt = AuthorityConsumptionReceipt.model_validate(json.loads(raw))
        if raw != canonical_json_bytes(receipt.model_dump(mode="json")):
            raise ValueError("split approval authority receipt is noncanonical")
        if (
            receipt.action == "split-approve"
            and receipt.request_sha256 == approval.request_sha256
            and receipt.state_attestation_sha256 == approval.state_attestation_sha256
            and receipt.target_sha256 == approval.target_sha256
            and receipt.binding_sha256 == approval.binding_sha256
            and receipt.reviewer_id == approval.split_approver_id
            and receipt.nonce_sha256 == approval.nonce_sha256
            and receipt.token_sha256 == approval.token_sha256
            and receipt.result_sha256 == approval.approval_sha256
        ):
            matches.append(receipt)
    if len(matches) != 1:
        raise ValueError("split approval requires one exact nonce-consumption receipt")
    return approval


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("build", "consume"))
    parser.add_argument("--check-request", type=Path)
    parser.add_argument("--check-state", type=Path)
    parser.add_argument("--verify-approval", type=Path)
    parser.add_argument("--require-independent", action="store_true")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--materialized-bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--state-output", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--request-output", type=Path, default=DEFAULT_REQUEST)
    parser.add_argument("--approval-output", type=Path, default=DEFAULT_APPROVAL)
    parser.add_argument("--nonce-ledger-root", type=Path, default=APPROVAL_LEDGER)
    parser.add_argument("--split-approver-id")
    parser.add_argument("--nonce")
    parser.add_argument("--issued-at")
    parser.add_argument("--expires-at")
    parser.add_argument("--approved-at")
    parser.add_argument("--authority-token-file", type=Path)
    return parser


def _root(value: Path) -> Path:
    root = value.resolve()
    if not (root / ".planning").is_dir() and (root.parent / ".planning").is_dir():
        root = root.parent
    return root.resolve(strict=True)


def _timestamp(value: str | None, *, default: datetime) -> datetime:
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value is not None
        else default
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _root(args.repo_root)
    bundle_path = _repo_path(root, args.materialized_bundle)
    if args.check_request is not None or args.check_state is not None:
        if args.check_request is None or args.check_state is None or args.command is not None:
            raise ValueError("--check-request and --check-state must be supplied together")
        checked = check_split_approval_request(
            request_path=_repo_path(root, args.check_request),
            state_path=_repo_path(root, args.check_state),
            repo_root=root,
            materialized_bundle_path=bundle_path,
        )
        print(checked.request_sha256)
        return 0
    if args.verify_approval is not None:
        approval = verify_split_approval(
            _repo_path(root, args.verify_approval),
            repo_root=root,
            materialized_bundle_path=bundle_path,
            require_independent=args.require_independent,
        )
        print(approval.approval_sha256)
        return 0
    if args.command == "build":
        if args.split_approver_id is None:
            raise ValueError("build requires --split-approver-id")
        issued_at = _timestamp(
            args.issued_at, default=datetime.now(UTC).replace(microsecond=0)
        )
        expires_at = _timestamp(args.expires_at, default=issued_at + timedelta(days=7))
        nonce = args.nonce or secrets.token_hex(32)
        first = build_split_approval_authority(
            repo_root=root,
            materialized_bundle_path=bundle_path,
            split_approver_id=args.split_approver_id,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        second = build_split_approval_authority(
            repo_root=root,
            materialized_bundle_path=bundle_path,
            split_approver_id=args.split_approver_id,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        first_bytes = canonical_json_bytes(
            [item.model_dump(mode="json") for item in first]
        )
        second_bytes = canonical_json_bytes(
            [item.model_dump(mode="json") for item in second]
        )
        if first_bytes != second_bytes:
            raise ValueError("frozen split approval authority builds differ")
        state, request = first
        publish_split_approval_authority(
            state,
            request,
            state_path=_repo_path(root, args.state_output),
            request_path=_repo_path(root, args.request_output),
        )
        print(request.request_sha256)
        return 0
    if args.command == "consume":
        if args.authority_token_file is None:
            raise ValueError("consume requires --authority-token-file")
        token_path = _repo_path(root, args.authority_token_file)
        if (
            token_path.is_symlink()
            or not token_path.is_file()
            or token_path.stat().st_mode & 0o777 != 0o600
        ):
            raise ValueError("authority token file must be a protected regular 0600 file")
        raw_token = token_path.read_text(encoding="ascii")
        if raw_token.endswith("\n"):
            raw_token = raw_token[:-1]
        approval = consume_split_approval(
            raw_token=raw_token,
            request_path=_repo_path(root, args.request_output),
            state_path=_repo_path(root, args.state_output),
            materialized_bundle_path=bundle_path,
            approval_path=_repo_path(root, args.approval_output),
            nonce_ledger_root=_repo_path(root, args.nonce_ledger_root),
            repo_root=root,
            approved_at=_timestamp(
                args.approved_at, default=datetime.now(UTC).replace(microsecond=0)
            ),
            require_independent=args.require_independent,
        )
        print(approval.approval_sha256)
        return 0
    raise ValueError("one of build, consume, --check-request, or --verify-approval is required")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RealSplitApprovalReceiptV2",
    "RealSplitApprovalRequestV2",
    "ReverifiedSplitFacts",
    "SplitApprovalStateAttestation",
    "build_parser",
    "build_split_approval_authority",
    "check_split_approval_request",
    "consume_split_approval",
    "publish_split_approval_authority",
    "reverify_materialized_split",
    "verify_reinf13_models",
    "verify_split_approval",
]
