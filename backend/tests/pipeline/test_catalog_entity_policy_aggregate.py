"""Controlled RED boundary for the later aggregate entity-policy owner."""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

POLICY_MODULE = "itda.contracts.catalog_entity_policy"
AGGREGATE_MODULE = "itda.cli.evaluate_catalog_entity_policy"


def test_missing_catalog_entity_policy_aggregate_is_controlled_red() -> None:
    if importlib.util.find_spec(AGGREGATE_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-entity-policy-aggregate", pytrace=False)
    importlib.import_module(AGGREGATE_MODULE)


def test_policy_capability_is_not_satisfied_by_projection_only() -> None:
    if importlib.util.find_spec(POLICY_MODULE) is None:
        pytest.skip("deterministic policy implementation is owned by Plan 02-11")
    policy = importlib.import_module(POLICY_MODULE)
    assert policy.POLICY_VERSION


def test_live_policy_replay_derives_exact_aggregate_without_caller_totals() -> None:
    aggregate = importlib.import_module(AGGREGATE_MODULE)
    repo_root = Path(__file__).resolve().parents[3]
    report = aggregate.build_policy_report(
        repo_root=repo_root,
        entity_projection=repo_root
        / "artifacts/restricted/catalog/v2/projection/entity-projection.json",
        immutability_manifest=repo_root
        / "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json",
        collection_report=repo_root
        / "artifacts/restricted/catalog/v1/collection/collection-report.json",
        crosswalk_review=repo_root
        / "artifacts/restricted/catalog/v1/review/crosswalk-review.json",
        relationship_review=repo_root
        / "artifacts/restricted/catalog/v1/review/relationship-review.json",
        catalog_audit=repo_root
        / "artifacts/restricted/catalog/v1/review/catalog-audit.json",
    )

    assert report.counts.crosswalk_total == 718
    assert report.counts.crosswalk_automatic == 715
    assert report.counts.crosswalk_unresolved == 3
    assert report.counts.relationship_total == 874
    assert report.counts.relationship_automatic == 871
    assert report.counts.relationship_unresolved == 3
    assert report.counts.media_attachment_count == 8
    assert report.counts.cross_provider_place_auto_link_count == 0
    assert report.automatic_decisions_authoritative is False


def test_build_policy_report_does_not_accept_caller_aggregate_totals() -> None:
    aggregate = importlib.import_module(AGGREGATE_MODULE)
    annotations = aggregate.build_policy_report.__annotations__
    assert not {
        "counts",
        "crosswalk_total",
        "relationship_total",
        "media_attachment_count",
    } & annotations.keys()
