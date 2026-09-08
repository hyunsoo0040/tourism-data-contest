"""Wave 0 contract for DATA-04 (02-W0-DATA04; T-02-05, T-02-07)."""

from __future__ import annotations

import importlib
import importlib.util
from types import ModuleType

import pytest

from itda.cli.build_real_split import build_authoritative_hard_components
from itda.domain.canonical import canonical_sha256

CAPABILITY_MODULE = "itda.contracts.crosswalk"
RELATIONSHIP_TYPES = (
    "DUPLICATE_EQUIVALENT",
    "PARENT_CHILD",
    "SAME_COMPLEX",
    "NEARBY_DISTINCT",
    "CANNOT_COAPPEAR",
)


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("catalog relationship production capability is implemented in Plan 02-06")
    return importlib.import_module(CAPABILITY_MODULE)


def _reviewed_relationship(
    capability: ModuleType,
    left: str,
    right: str,
    relationship_type: str,
    digest_digit: str,
) -> object:
    return capability.RelationshipRevision(
        left_member=left,
        right_member=right,
        relationship_type=relationship_type,
        status="REVIEWED",
        reviewer_id="relationship-reviewer",
        reviewed_at="2026-07-27T05:00:00Z",
        evidence_sha256=digest_digit * 64,
        parent_revision_sha256=None,
    )


@pytest.mark.parametrize("relationship_type", RELATIONSHIP_TYPES)
def test_relationship_types_remain_semantically_distinct(relationship_type: str) -> None:
    capability = _capability_or_skip()
    revision = _reviewed_relationship(
        capability,
        "place:a",
        "place:b",
        relationship_type,
        "1",
    )
    assert revision.relationship_type == relationship_type
    if relationship_type == "PARENT_CHILD":
        assert revision.merges_identity is False


def test_reviewed_typed_edges_form_deterministic_transitive_hard_components() -> None:
    capability = _capability_or_skip()
    edges = (
        _reviewed_relationship(
            capability,
            "place:a",
            "place:b",
            "PARENT_CHILD",
            "1",
        ),
        _reviewed_relationship(
            capability,
            "place:b",
            "photo:c",
            "CANNOT_COAPPEAR",
            "2",
        ),
        _reviewed_relationship(
            capability,
            "story:d",
            "photo:c",
            "DUPLICATE_EQUIVALENT",
            "3",
        ),
    )
    forward = capability.build_hard_components(edges)
    reversed_result = capability.build_hard_components(tuple(reversed(edges)))
    assert forward.component_sha256 == reversed_result.component_sha256
    assert forward.components == (("photo:c", "place:a", "place:b", "story:d"),)
    assert forward.input_order_sha256 == reversed_result.input_order_sha256


def test_hard_component_cannot_cross_dev_and_blind_membership() -> None:
    capability = _capability_or_skip()
    edges = (
        _reviewed_relationship(
            capability,
            "place:a",
            "place:b",
            "PARENT_CHILD",
            "1",
        ),
    )
    components = capability.build_hard_components(edges)
    with pytest.raises(ValueError, match="hard component"):
        capability.validate_split_components(
            components,
            {"place:a": "DEV", "place:b": "BLIND"},
        )


def test_same_complex_is_hard_but_nearby_distinct_is_not_collapsed() -> None:
    capability = _capability_or_skip()
    same_complex = _reviewed_relationship(
        capability,
        "place:a",
        "place:b",
        "SAME_COMPLEX",
        "1",
    )
    nearby_distinct = _reviewed_relationship(
        capability,
        "place:c",
        "place:d",
        "NEARBY_DISTINCT",
        "2",
    )
    components = capability.build_hard_components((same_complex, nearby_distinct))
    assert components.components == (("place:a", "place:b"),)
    assert same_complex.relationship_type != nearby_distinct.relationship_type
    assert nearby_distinct.merges_identity is False


def test_reviewed_relationship_revision_supersedes_parent_without_deleting_it() -> None:
    capability = _capability_or_skip()
    initial = _reviewed_relationship(
        capability,
        "place:a",
        "place:b",
        "SAME_COMPLEX",
        "1",
    )
    corrected = capability.RelationshipRevision(
        left_member="place:a",
        right_member="place:b",
        relationship_type="NEARBY_DISTINCT",
        status="REVIEWED",
        reviewer_id="relationship-reviewer-2",
        reviewed_at="2026-07-27T06:00:00Z",
        evidence_sha256="2" * 64,
        parent_revision_sha256=initial.revision_sha256,
    )
    components = capability.build_hard_components((initial, corrected))
    assert components.components == ()
    assert components.input_revision_sha256s == (corrected.revision_sha256,)
    assert initial.relationship_type == "SAME_COMPLEX"


@pytest.mark.parametrize(
    "case",
    [
        "self-edge",
        "duplicate-edge",
        "unknown-member",
        "contradictory",
        "unreviewed",
        "stale-parent",
    ],
)
def test_invalid_relationship_history_fails_closed(case: str) -> None:
    capability = _capability_or_skip()
    with pytest.raises(ValueError):
        capability.validate_relationship_case(case)


def test_missing_catalog_relationships_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-relationships", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)


def _authoritative_artifact(leaves: list[dict[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "itda.authoritative-relationship-leaves.v1",
        "request_sha256": "1" * 64,
        "state_attestation_sha256": "2" * 64,
        "target_sha256": "3" * 64,
        "relationship_leaf_count": len(leaves),
        "relationship_leaves": leaves,
        "relationship_leaves_sha256": canonical_sha256(leaves),
    }
    payload["authoritative_relationship_leaves_sha256"] = canonical_sha256(payload)
    return payload


def _active_leaf(
    relation_type: str,
    left: dict[str, object],
    right: dict[str, object],
    *,
    revision: str = "a" * 64,
) -> dict[str, object]:
    leaf = {
        "schema_version": "itda.authoritative-relationship-leaf.v1",
        "leaf_id": "0" * 64,
        "status": "APPROVED",
        "current": True,
        "catalog_revision_sha256": revision,
        "relation_type": relation_type,
        "left": left,
        "right": right,
    }
    leaf["leaf_id"] = canonical_sha256({key: value for key, value in leaf.items() if key != "leaf_id"})
    return leaf


def _place_endpoint(place_id: str) -> dict[str, object]:
    return {"kind": "PLACE", "stable_id": place_id, "provider": None, "owner_place_id": place_id}


@pytest.mark.parametrize(
    "relation_type",
    ["DUPLICATE_EQUIVALENT", "PARENT_CHILD", "CANNOT_COAPPEAR"],
)
def test_plan25_each_authoritative_hard_type_is_indivisible(relation_type: str) -> None:
    left = "place:" + "1" * 64
    right = "place:" + "2" * 64
    result = build_authoritative_hard_components(
        (left, right),
        _authoritative_artifact(
            [_active_leaf(relation_type, _place_endpoint(left), _place_endpoint(right))]
        ),
        active_revision_sha256="a" * 64,
    )
    assert result.components[0].members == (left, right)


def test_plan25_mixed_hard_chain_and_media_owner_projection_are_transitive() -> None:
    places = tuple("place:" + str(index) * 64 for index in range(1, 5))
    photo = {
        "kind": "PHOTO",
        "stable_id": "photo:TOURISM_PHOTO:asset-1",
        "provider": "TOURISM_PHOTO",
        "owner_place_id": places[2],
    }
    story = {
        "kind": "ODII_SCRIPT",
        "stable_id": "story:ODII:script-1",
        "provider": "ODII",
        "owner_place_id": places[3],
    }
    leaves = [
        _active_leaf("PARENT_CHILD", _place_endpoint(places[0]), _place_endpoint(places[1])),
        _active_leaf("CANNOT_COAPPEAR", _place_endpoint(places[1]), _place_endpoint(places[2])),
        _active_leaf("DUPLICATE_EQUIVALENT", photo, story),
    ]
    result = build_authoritative_hard_components(
        places,
        _authoritative_artifact(leaves),
        active_revision_sha256="a" * 64,
    )
    assert result.components == (
        type(result.components[0])(
            component_id=result.components[0].component_id,
            members=places,
        ),
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda leaf: leaf.__setitem__("status", "PENDING"),
        lambda leaf: leaf.__setitem__("current", False),
        lambda leaf: leaf.__setitem__("relation_type", "SAME_COMPLEX"),
        lambda leaf: leaf.__setitem__("catalog_revision_sha256", "b" * 64),
        lambda leaf: leaf["left"].__setitem__("owner_place_id", None),
        lambda leaf: leaf["right"].__setitem__("provider", "ODII"),
    ],
)
def test_plan25_stale_untyped_or_ambiguous_authoritative_leaf_fails_closed(
    mutate: object,
) -> None:
    left = "place:" + "1" * 64
    right = "place:" + "2" * 64
    leaf = _active_leaf(
        "DUPLICATE_EQUIVALENT",
        {
            "kind": "PHOTO",
            "stable_id": "photo:TOURISM_PHOTO:a",
            "provider": "TOURISM_PHOTO",
            "owner_place_id": left,
        },
        {
            "kind": "PHOTO",
            "stable_id": "photo:TOURISM_PHOTO:b",
            "provider": "TOURISM_PHOTO",
            "owner_place_id": right,
        },
    )
    mutate(leaf)
    leaf["leaf_id"] = canonical_sha256({key: value for key, value in leaf.items() if key != "leaf_id"})
    with pytest.raises(Exception):
        build_authoritative_hard_components(
            (left, right),
            _authoritative_artifact([leaf]),
            active_revision_sha256="a" * 64,
        )


def test_plan25_proposal_era_relationship_review_is_rejected() -> None:
    with pytest.raises(ValueError, match="authoritative"):
        build_authoritative_hard_components(
            ("place:" + "1" * 64,),
            {"schema_version": "relationship-review-v1", "relationships": []},
            active_revision_sha256="a" * 64,
        )
