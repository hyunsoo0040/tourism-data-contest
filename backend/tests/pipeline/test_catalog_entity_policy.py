"""Controlled boundary and contract tests for the v2 entity projection.

The production projection is owned by Plan 02-10.  The later disposition policy
is intentionally a separate capability, so this module tests only source-neutral
entity identities and typed relationship inputs.
"""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType

import pytest

PROJECTION_MODULE = "itda.cli.project_catalog_entities"
POLICY_CONTRACT_MODULE = "itda.contracts.catalog_entity"


def _projection_or_skip() -> ModuleType:
    if importlib.util.find_spec(PROJECTION_MODULE) is None:
        pytest.skip("catalog entity projection is implemented in Plan 02-10")
    return importlib.import_module(PROJECTION_MODULE)


def _policy_contract_or_skip() -> ModuleType:
    if importlib.util.find_spec(POLICY_CONTRACT_MODULE) is None:
        pytest.skip("catalog entity contract is implemented in Plan 02-10")
    return importlib.import_module(POLICY_CONTRACT_MODULE)


def test_missing_catalog_entity_projection_is_controlled_red() -> None:
    if importlib.util.find_spec(PROJECTION_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-entity-projection", pytrace=False)
    importlib.import_module(PROJECTION_MODULE)


def test_missing_catalog_entity_policy_is_controlled_red() -> None:
    if importlib.util.find_spec(POLICY_CONTRACT_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-entity-policy", pytrace=False)
    importlib.import_module(POLICY_CONTRACT_MODULE)


def test_entity_kinds_and_relationship_types_are_closed() -> None:
    capability = _policy_contract_or_skip()
    assert tuple(kind.value for kind in capability.EntityKind) == (
        "DATASET_RECORD",
        "PLACE",
        "ODII_CONTENT",
        "PHOTO_ASSET",
    )
    assert tuple(kind.value for kind in capability.RelationshipType) == (
        "DUPLICATE_EQUIVALENT",
        "PARENT_CHILD",
        "CANNOT_COAPPEAR",
    )


def test_exact_provider_scope_is_the_only_automatic_t0_evidence() -> None:
    capability = _policy_contract_or_skip()
    exact = capability.EntityEvidence(
        evidence_tier="T0_EXACT_PROVIDER_SCOPED_ID",
        provider="TOUR_API",
        official_dataset_id="15101578",
        provider_record_id="content:123",
        source_row_sha256="1" * 64,
        address=None,
        latitude=None,
        longitude=None,
        hierarchy=(),
    )
    assert exact.automatic_identity_eligible is True

    for tier in (
        "T1_STRUCTURED_AMBIGUOUS",
        "T2_TITLE_OR_PROXIMITY_ONLY",
        "MISSING",
    ):
        evidence = exact.model_copy(update={"evidence_tier": tier})
        assert evidence.automatic_identity_eligible is False


def test_parent_child_direction_is_preserved_without_identity_merge() -> None:
    capability = _policy_contract_or_skip()
    parent = capability.EntityRef(kind="PLACE", entity_id="place:" + "1" * 64)
    child = capability.EntityRef(kind="PLACE", entity_id="place:" + "2" * 64)
    relationship = capability.TypedRelationshipProjection(
        source_row_id="relationship:" + "3" * 64,
        source_row_sha256="4" * 64,
        relationship_type="PARENT_CHILD",
        left=parent,
        right=child,
        evidence_refs=("evidence:" + "5" * 64,),
        automatic_identity_merge=False,
    )
    assert relationship.left == parent
    assert relationship.right == child
    assert relationship.automatic_identity_merge is False
    assert relationship.model_copy(update={"left": child, "right": parent}) != relationship


def test_projection_api_does_not_accept_caller_supplied_aggregate_totals() -> None:
    capability = _projection_or_skip()
    assert "candidate_count" not in capability.build_projection.__annotations__
    assert "crosswalk_count" not in capability.build_projection.__annotations__
    assert "relationship_count" not in capability.build_projection.__annotations__
