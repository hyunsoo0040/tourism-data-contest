"""Exact-state schema authority and insert-only real-manifest boundary."""

from __future__ import annotations

import hmac
from contextlib import AbstractContextManager
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self, cast

from pydantic import Field, field_validator, model_validator

from itda.contracts.authority import AuthorityAction, AuthorityTokenV2
from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256

EXACT_0002 = "0002_split_boundaries"
EXACT_0003 = "0003_real_manifest"


class LiveSchemaClassification(StrEnum):
    EXACT_0002 = "EXACT_0002"
    EXACT_0003 = "EXACT_0003"
    ABSENT = "ABSENT"
    OLDER = "OLDER"
    DIVERGENT = "DIVERGENT"
    MULTI_HEAD = "MULTI_HEAD"


class SchemaInspection(StrictContract):
    """Secret-free result of one named-connection inspection."""

    schema_version: Literal["schema-inspection-v1"] = "schema-inspection-v1"
    heads: tuple[str, ...]
    schema_objects_sha256: Sha256
    constraints_sha256: Sha256
    functions_sha256: Sha256
    acls_sha256: Sha256
    schema_contract_sha256: Sha256
    expected_schema_contract_sha256: Sha256
    effective_role: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9._-]{1,64}$")]
    connection_binding_sha256: Sha256

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        expected = canonical_sha256(
            {
                "heads": list(self.heads),
                "schema_objects_sha256": self.schema_objects_sha256,
                "constraints_sha256": self.constraints_sha256,
                "functions_sha256": self.functions_sha256,
                "acls_sha256": self.acls_sha256,
            }
        )
        if not hmac.compare_digest(self.schema_contract_sha256, expected):
            raise ValueError("schema contract aggregate digest is stale")
        return self


def classify_live_schema(inspection: SchemaInspection) -> LiveSchemaClassification:
    if len(inspection.heads) > 1:
        return LiveSchemaClassification.MULTI_HEAD
    if not inspection.heads:
        return LiveSchemaClassification.ABSENT
    head = inspection.heads[0]
    if head == "0001_app_profiles":
        return LiveSchemaClassification.OLDER
    if head not in {EXACT_0002, EXACT_0003}:
        return LiveSchemaClassification.DIVERGENT
    if not hmac.compare_digest(
        inspection.schema_contract_sha256, inspection.expected_schema_contract_sha256
    ):
        return LiveSchemaClassification.DIVERGENT
    return (
        LiveSchemaClassification.EXACT_0002
        if head == EXACT_0002
        else LiveSchemaClassification.EXACT_0003
    )


def inspect_schema_twice(connection: SchemaConnection) -> SchemaInspection:
    """Freeze request issuance only from two identical reads under one read lock."""

    with connection.read_lock():
        first = connection.inspect()
        second = connection.inspect()
    if first != second:
        raise ValueError("named schema connection changed between read inspections")
    return first


class SchemaConnection(Protocol):
    def read_lock(self) -> AbstractContextManager[None]: ...
    def mutation_lock(self) -> AbstractContextManager[None]: ...
    def inspect(self) -> SchemaInspection: ...
    def upgrade_exactly_one(self, expected_from: str, target: str) -> None: ...


class SchemaActionResult(StrictContract):
    schema_version: Literal["schema-action-result-v1"] = "schema-action-result-v1"
    action: Literal["schema-apply-0003", "schema-verify-0003"]
    classification: Literal[LiveSchemaClassification.EXACT_0003]
    before_schema_contract_sha256: Sha256
    after_schema_contract_sha256: Sha256
    connection_binding_sha256: Sha256
    mutation_count: Literal[0, 1]
    result_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def derive_result_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"result_sha256"}, mode="json"))
        if self.result_sha256 is None:
            object.__setattr__(self, "result_sha256", expected)
        elif not hmac.compare_digest(self.result_sha256, expected):
            raise ValueError("schema action result digest is stale")
        return self


def _require_actionable(inspection: SchemaInspection, action: str) -> None:
    classification = classify_live_schema(inspection)
    expected = {
        "schema-apply-0003": LiveSchemaClassification.EXACT_0002,
        "schema-verify-0003": LiveSchemaClassification.EXACT_0003,
    }.get(action)
    if expected is None or classification is not expected:
        raise ValueError(f"{classification.value} cannot execute {action}")


def execute_schema_action(
    connection: SchemaConnection,
    *,
    action: Literal["schema-apply-0003", "schema-verify-0003"],
) -> SchemaActionResult:
    """Reinspect under one lock and never fall through from verify to apply."""

    with connection.mutation_lock():
        before = connection.inspect()
        _require_actionable(before, action)
        mutation_count: Literal[0, 1]
        if action == "schema-apply-0003":
            connection.upgrade_exactly_one(EXACT_0002, EXACT_0003)
            mutation_count = 1
        else:
            mutation_count = 0
        after = connection.inspect()
        if classify_live_schema(after) is not LiveSchemaClassification.EXACT_0003:
            raise ValueError("schema action did not leave exact 0003")
        if before.connection_binding_sha256 != after.connection_binding_sha256:
            raise ValueError("named connection binding changed during schema action")
        return SchemaActionResult(
            action=action,
            classification=LiveSchemaClassification.EXACT_0003,
            before_schema_contract_sha256=before.schema_contract_sha256,
            after_schema_contract_sha256=after.schema_contract_sha256,
            connection_binding_sha256=after.connection_binding_sha256,
            mutation_count=mutation_count,
        )


class SchemaStateAttestation(StrictContract):
    schema_version: Literal["schema-state-attestation-v1"] = "schema-state-attestation-v1"
    status: Literal["SCHEMA_ACTION_READY"] = "SCHEMA_ACTION_READY"
    classification: Literal[
        LiveSchemaClassification.EXACT_0002, LiveSchemaClassification.EXACT_0003
    ]
    live_revision: Literal["0002_split_boundaries", "0003_real_manifest"]
    schema_contract_sha256: Sha256
    schema_objects_sha256: Sha256
    constraints_sha256: Sha256
    functions_sha256: Sha256
    acls_sha256: Sha256
    effective_role: str
    connection_binding_sha256: Sha256
    approved_split_sha256: Sha256
    approval_receipt_sha256: Sha256
    predecessor_sha256: Sha256
    predecessor_blob_sha1: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    predecessor_index_mode: Literal["100644"]
    predecessor_index_stage: Literal[0]
    predecessor_clean: Literal[True]
    predecessor_revision: Literal["0002_split_boundaries"]
    predecessor_down_revision: Literal["0001_app_profiles"]
    worktree_head_sha1: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    state_attestation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def derive_hash(self) -> Self:
        expected = canonical_sha256(
            self.model_dump(exclude={"state_attestation_sha256"}, mode="json")
        )
        if self.state_attestation_sha256 is None:
            object.__setattr__(self, "state_attestation_sha256", expected)
        elif not hmac.compare_digest(self.state_attestation_sha256, expected):
            raise ValueError("schema state attestation digest is stale")
        return self


class SchemaActionRequest(StrictContract):
    schema_version: Literal["schema-action-request-v1"] = "schema-action-request-v1"
    action: Literal["schema-apply-0003", "schema-verify-0003"]
    state_attestation_sha256: Sha256
    target_sha256: Sha256
    reviewer_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    binding_sha256: Sha256
    approved_split_sha256: Sha256
    approval_receipt_sha256: Sha256
    predecessor_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    expires_at: datetime
    request_sha256: Sha256 | None = None

    @field_validator("issued_at", "expires_at")
    @classmethod
    def utc_timestamps(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="schema_authority_timestamp")

    @model_validator(mode="after")
    def validate_and_hash(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("schema action request expiry must follow issuance")
        expected = canonical_sha256(self.model_dump(exclude={"request_sha256"}, mode="json"))
        if self.request_sha256 is None:
            object.__setattr__(self, "request_sha256", expected)
        elif not hmac.compare_digest(self.request_sha256, expected):
            raise ValueError("schema action request digest is stale")
        return self

    def expected_token(self) -> AuthorityTokenV2:
        return AuthorityTokenV2(
            action=cast(AuthorityAction, self.action),
            request_sha256=cast(str, self.request_sha256),
            state_attestation_sha256=self.state_attestation_sha256,
            target_sha256=self.target_sha256,
            reviewer_id=self.reviewer_id,
            binding_sha256=self.binding_sha256,
            nonce=self.nonce,
        )


def schema_action_target(state: SchemaStateAttestation, action: str) -> dict[str, object]:
    return {
        "action": action,
        "from_revision": state.live_revision,
        "to_revision": EXACT_0003,
        "schema_contract_sha256": state.schema_contract_sha256,
        "approved_split_sha256": state.approved_split_sha256,
        "approval_receipt_sha256": state.approval_receipt_sha256,
        "predecessor_sha256": state.predecessor_sha256,
        "connection_binding_sha256": state.connection_binding_sha256,
        "mutation_count": 1 if action == "schema-apply-0003" else 0,
    }


def schema_action_binding(state: SchemaStateAttestation, target: object) -> dict[str, object]:
    return {
        "consumer": "itda.schema-action.v1",
        "state_attestation_sha256": state.state_attestation_sha256,
        "connection_binding_sha256": state.connection_binding_sha256,
        "target": target,
    }


def build_schema_action_authority(
    inspection: SchemaInspection,
    *,
    approved_split_sha256: str,
    approval_receipt_sha256: str,
    predecessor_sha256: str,
    predecessor_blob_sha1: str,
    predecessor_index_mode: Literal["100644"] = "100644",
    predecessor_index_stage: Literal[0] = 0,
    predecessor_clean: Literal[True] = True,
    predecessor_revision: Literal["0002_split_boundaries"] = "0002_split_boundaries",
    predecessor_down_revision: Literal["0001_app_profiles"] = "0001_app_profiles",
    worktree_head_sha1: str = "0" * 40,
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> tuple[SchemaStateAttestation, SchemaActionRequest]:
    classification = classify_live_schema(inspection)
    if classification not in {
        LiveSchemaClassification.EXACT_0002,
        LiveSchemaClassification.EXACT_0003,
    }:
        raise ValueError(f"{classification.value} cannot issue a schema action request")
    action: Literal["schema-apply-0003", "schema-verify-0003"] = (
        "schema-apply-0003"
        if classification is LiveSchemaClassification.EXACT_0002
        else "schema-verify-0003"
    )
    state = SchemaStateAttestation(
        classification=classification,
        live_revision=cast(
            Literal["0002_split_boundaries", "0003_real_manifest"],
            inspection.heads[0],
        ),
        schema_contract_sha256=inspection.schema_contract_sha256,
        schema_objects_sha256=inspection.schema_objects_sha256,
        constraints_sha256=inspection.constraints_sha256,
        functions_sha256=inspection.functions_sha256,
        acls_sha256=inspection.acls_sha256,
        effective_role=inspection.effective_role,
        connection_binding_sha256=inspection.connection_binding_sha256,
        approved_split_sha256=approved_split_sha256,
        approval_receipt_sha256=approval_receipt_sha256,
        predecessor_sha256=predecessor_sha256,
        predecessor_blob_sha1=predecessor_blob_sha1,
        predecessor_index_mode=predecessor_index_mode,
        predecessor_index_stage=predecessor_index_stage,
        predecessor_clean=predecessor_clean,
        predecessor_revision=predecessor_revision,
        predecessor_down_revision=predecessor_down_revision,
        worktree_head_sha1=worktree_head_sha1,
    )
    target = schema_action_target(state, action)
    binding = schema_action_binding(state, target)
    request = SchemaActionRequest(
        action=action,
        state_attestation_sha256=cast(str, state.state_attestation_sha256),
        target_sha256=canonical_sha256(target),
        reviewer_id=reviewer_id,
        binding_sha256=canonical_sha256(binding),
        approved_split_sha256=approved_split_sha256,
        approval_receipt_sha256=approval_receipt_sha256,
        predecessor_sha256=predecessor_sha256,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return state, request


__all__ = [
    "EXACT_0002",
    "EXACT_0003",
    "LiveSchemaClassification",
    "SchemaActionRequest",
    "SchemaActionResult",
    "SchemaConnection",
    "SchemaInspection",
    "SchemaStateAttestation",
    "build_schema_action_authority",
    "classify_live_schema",
    "execute_schema_action",
    "inspect_schema_twice",
    "schema_action_binding",
    "schema_action_target",
]
