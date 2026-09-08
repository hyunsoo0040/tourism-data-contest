"""Fail-closed schema authority and public-artifact security contract."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from itda.contracts.real_manifest_seal import (
    LiveSchemaClassification,
    SchemaInspection,
    build_schema_action_authority,
)
from itda.domain.canonical import canonical_sha256

NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def _inspection(head: str | None, *, exact: bool = True) -> SchemaInspection:
    heads = () if head is None else (head,)
    fields = {
        "heads": list(heads),
        "schema_objects_sha256": "9" * 64,
        "constraints_sha256": "a" * 64,
        "functions_sha256": "b" * 64,
        "acls_sha256": "c" * 64,
    }
    aggregate = canonical_sha256(fields)
    return SchemaInspection(
        heads=heads,
        schema_objects_sha256="9" * 64,
        constraints_sha256="a" * 64,
        functions_sha256="b" * 64,
        acls_sha256="c" * 64,
        schema_contract_sha256=aggregate,
        expected_schema_contract_sha256=aggregate if exact else "2" * 64,
        effective_role="phase2-schema-admin",
        connection_binding_sha256="3" * 64,
    )


@pytest.mark.parametrize(
    "inspection,classification",
    [
        (_inspection(None), LiveSchemaClassification.ABSENT),
        (_inspection("0001_app_profiles"), LiveSchemaClassification.OLDER),
        (_inspection("unexpected"), LiveSchemaClassification.DIVERGENT),
        (_inspection("0002_split_boundaries", exact=False), LiveSchemaClassification.DIVERGENT),
        (
            _inspection("0002_split_boundaries").model_copy(
                update={"heads": ("0002_split_boundaries", "other")}
            ),
            LiveSchemaClassification.MULTI_HEAD,
        ),
    ],
)
def test_unsafe_states_issue_no_action_request(
    inspection: SchemaInspection, classification: LiveSchemaClassification
) -> None:
    with pytest.raises(ValueError, match=classification.value):
        build_schema_action_authority(
            inspection,
            approved_split_sha256="4" * 64,
            approval_receipt_sha256="5" * 64,
            predecessor_sha256="6" * 64,
            predecessor_blob_sha1="7" * 40,
            reviewer_id="phase2-schema-reviewer",
            nonce="8" * 64,
            issued_at=NOW,
            expires_at=NOW + timedelta(days=7),
        )


@pytest.mark.parametrize(
    "head,action",
    [
        ("0002_split_boundaries", "schema-apply-0003"),
        ("0003_real_manifest", "schema-verify-0003"),
    ],
)
def test_exact_branch_builds_digest_only_membership_free_request(head: str, action: str) -> None:
    state, request = build_schema_action_authority(
        _inspection(head),
        approved_split_sha256="4" * 64,
        approval_receipt_sha256="5" * 64,
        predecessor_sha256="6" * 64,
        predecessor_blob_sha1="7" * 40,
        reviewer_id="phase2-schema-reviewer",
        nonce="8" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=7),
    )
    assert request.action == action
    assert request.state_attestation_sha256 == state.state_attestation_sha256
    assert request.expected_token().action == action
    serialized = json.dumps(request.model_dump(mode="json"), sort_keys=True).casefold()
    for forbidden in ("place:", "members", "dev_members", "blind_members", "password", "dsn"):
        assert forbidden not in serialized
    assert request.request_sha256 is not None


def test_request_expiry_and_reviewer_are_exactly_bound() -> None:
    _, request = build_schema_action_authority(
        _inspection("0002_split_boundaries"),
        approved_split_sha256="4" * 64,
        approval_receipt_sha256="5" * 64,
        predecessor_sha256="6" * 64,
        predecessor_blob_sha1="7" * 40,
        reviewer_id="phase2-schema-reviewer",
        nonce="8" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=7),
    )
    assert request.reviewer_id == "phase2-schema-reviewer"
    assert request.issued_at == NOW
    assert request.expires_at == NOW + timedelta(days=7)
    assert request.expected_token().serialize().count(":") == 7
