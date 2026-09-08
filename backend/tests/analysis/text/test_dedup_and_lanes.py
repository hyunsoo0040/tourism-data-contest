"""Wave 0 RED contracts for reversible deduplication and lane isolation."""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

CAPABILITY_MODULE = "itda.analysis.text.normalization"
FIXTURE_PATH = Path(__file__).resolve().parents[4] / "fixtures/synthetic/phase3/text-evidence.json"


def _capability() -> ModuleType:
    try:
        available = importlib.util.find_spec(CAPABILITY_MODULE) is not None
    except ModuleNotFoundError:
        available = False
    if not available:
        pytest.fail("PHASE3-MISSING:text-normalization", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _cluster(capability: ModuleType) -> Any:
    fixture = _fixture()["dedup"]
    policy = capability.NormalizationPolicy.model_validate(fixture["policy"])
    return capability.cluster_near_duplicates(tuple(fixture["items"]), policy=policy)


def test_exact_normalization_precedes_conservative_near_duplicate_clustering() -> None:
    capability = _capability()
    fixture = _fixture()["dedup"]

    first, second = fixture["items"][:2]
    assert capability.normalize_for_comparison(
        first["text"]
    ) == capability.normalize_for_comparison(second["text"])

    graph = _cluster(capability)
    edges = {(edge.left_span_id, edge.right_span_id, edge.kind.value) for edge in graph.edges}
    assert edges == {tuple(row) for row in fixture["expected_edges"]}
    assert graph.policy.char_trigram_jaccard == 0.92
    assert graph.policy.length_ratio == 0.85


def test_false_merge_and_cross_lane_merge_are_rejected() -> None:
    capability = _capability()
    graph = _cluster(capability)
    connected = {frozenset((edge.left_span_id, edge.right_span_id)) for edge in graph.edges}

    assert frozenset(("synthetic-span-exact-a", "synthetic-span-distinct")) not in connected
    assert frozenset(("synthetic-span-exact-a", "synthetic-span-odii")) not in connected
    assert all(edge.lane.value == "DESCRIPTION" for edge in graph.edges)


def test_every_original_and_source_edge_survives_canonical_display_selection() -> None:
    capability = _capability()
    fixture = _fixture()["dedup"]
    graph = _cluster(capability)

    original_ids = {item["span_id"] for item in fixture["items"]}
    recovered_ids = {span.span_id for cluster in graph.clusters for span in cluster.originals}
    assert recovered_ids == original_ids
    assert sum(len(cluster.originals) for cluster in graph.clusters) == len(fixture["items"])
    assert all(
        cluster.canonical_span_id in {span.span_id for span in cluster.originals}
        for cluster in graph.clusters
    )


def test_duplicate_clusters_do_not_inflate_distinct_evidence_count() -> None:
    capability = _capability()
    graph = _cluster(capability)

    selected = capability.select_diverse_evidence(
        graph,
        ranked_span_ids=(
            "synthetic-span-exact-a",
            "synthetic-span-exact-b",
            "synthetic-span-near",
            "synthetic-span-distinct",
        ),
        limit=3,
    )

    assert len(selected) == 2
    assert selected[0].span_id == "synthetic-span-exact-a"
    assert selected[1].span_id == "synthetic-span-distinct"


def test_missing_lane_is_explicit_and_cannot_fabricate_evidence() -> None:
    capability = _capability()

    missing = capability.build_lane_evidence(lane="ODII", spans=())
    assert missing.status.value == "MISSING"
    assert missing.spans == ()

    with pytest.raises(ValueError, match="MISSING|evidence"):
        capability.build_lane_evidence(
            lane="ODII",
            spans=(),
            fabricated_text="합성된 근거",
        )
