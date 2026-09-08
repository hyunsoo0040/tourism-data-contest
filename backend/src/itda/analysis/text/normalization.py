"""Versioned exact normalization and reversible conservative near-deduplication."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence

from itda.contracts.text_evidence import (
    DedupCluster,
    DedupEdge,
    DedupEdgeKind,
    DedupGraph,
    DedupOriginal,
    EvidenceLane,
    LaneEvidence,
    LaneEvidenceStatus,
    NormalizationPolicy,
)

_WHITESPACE = re.compile(r"\s+", re.UNICODE)


def normalize_for_comparison(value: str) -> str:
    """Return a comparison-only NFKC/casefold/whitespace projection."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("comparison text must be a non-empty string")
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", value).casefold()).strip()


def _char_trigrams(value: str) -> frozenset[str]:
    if len(value) < 3:
        return frozenset((value,))
    return frozenset(value[index : index + 3] for index in range(len(value) - 2))


def _char_trigram_jaccard(left: str, right: str) -> float:
    left_trigrams = _char_trigrams(left)
    right_trigrams = _char_trigrams(right)
    union = left_trigrams | right_trigrams
    return len(left_trigrams & right_trigrams) / len(union) if union else 1.0


def _length_ratio(left: str, right: str) -> float:
    longest = max(len(left), len(right))
    return min(len(left), len(right)) / longest if longest else 1.0


def _original(item: Mapping[str, object], *, input_order: int) -> DedupOriginal:
    span_id = item.get("span_id")
    lane = item.get("lane")
    source_id = item.get("source_id")
    text = item.get("text")
    if not isinstance(span_id, str) or not span_id:
        raise ValueError("dedup item span_id must be a non-empty string")
    if not isinstance(source_id, str) or not source_id:
        raise ValueError("dedup item source_id must be a non-empty string")
    if not isinstance(lane, (EvidenceLane, str)):
        raise ValueError("dedup item lane must identify a supported evidence lane")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("dedup item text must be a non-empty string")
    return DedupOriginal(
        span_id=span_id,
        lane=EvidenceLane(lane),
        source_id=source_id,
        text=text,
        comparison_text=normalize_for_comparison(text),
        input_order=input_order,
    )


def _canonical_key(original: DedupOriginal) -> tuple[str, int, str, str]:
    return (
        original.lane.value,
        original.input_order,
        original.source_id,
        original.span_id,
    )


def _cluster_id(lane: EvidenceLane, members: Sequence[DedupOriginal]) -> str:
    payload = "\0".join(("dedup-cluster-v1", lane.value, *(member.span_id for member in members)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def cluster_near_duplicates(
    items: Iterable[Mapping[str, object]],
    *,
    policy: NormalizationPolicy,
) -> DedupGraph:
    """Cluster exact then near duplicates without dropping any original edge."""

    originals = tuple(_original(item, input_order=index) for index, item in enumerate(items))
    if len({original.span_id for original in originals}) != len(originals):
        raise ValueError("dedup span IDs must be unique")

    edges: list[DedupEdge] = []
    exact_groups: list[list[DedupOriginal]] = []
    exact_group_by_key: dict[tuple[EvidenceLane, str], int] = {}
    for original in originals:
        key = (original.lane, original.comparison_text)
        group_index = exact_group_by_key.get(key)
        if group_index is None:
            exact_group_by_key[key] = len(exact_groups)
            exact_groups.append([original])
            continue
        representative = exact_groups[group_index][0]
        exact_groups[group_index].append(original)
        edges.append(
            DedupEdge(
                left_span_id=representative.span_id,
                right_span_id=original.span_id,
                lane=original.lane,
                kind=DedupEdgeKind.EXACT,
                char_trigram_jaccard=1.0,
                length_ratio=1.0,
            )
        )

    parent = list(range(len(exact_groups)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    representatives = tuple(group[0] for group in exact_groups)
    for right_index, right in enumerate(representatives):
        for left_index in range(right_index):
            left = representatives[left_index]
            if left.lane is not right.lane:
                continue
            jaccard = _char_trigram_jaccard(left.comparison_text, right.comparison_text)
            ratio = _length_ratio(left.comparison_text, right.comparison_text)
            if jaccard >= policy.char_trigram_jaccard and ratio >= policy.length_ratio:
                edges.append(
                    DedupEdge(
                        left_span_id=left.span_id,
                        right_span_id=right.span_id,
                        lane=left.lane,
                        kind=DedupEdgeKind.NEAR,
                        char_trigram_jaccard=jaccard,
                        length_ratio=ratio,
                    )
                )
                union(left_index, right_index)
                break

    grouped: dict[int, list[DedupOriginal]] = {}
    for exact_index, exact_group in enumerate(exact_groups):
        grouped.setdefault(find(exact_index), []).extend(exact_group)

    clusters: list[DedupCluster] = []
    for members in grouped.values():
        ordered = tuple(sorted(members, key=_canonical_key))
        canonical = ordered[0]
        clusters.append(
            DedupCluster(
                cluster_id=_cluster_id(canonical.lane, ordered),
                lane=canonical.lane,
                canonical_span_id=canonical.span_id,
                originals=ordered,
            )
        )
    clusters.sort(key=lambda cluster: _canonical_key(cluster.originals[0]))
    return DedupGraph(policy=policy, edges=tuple(edges), clusters=tuple(clusters))


def select_diverse_evidence(
    graph: DedupGraph,
    *,
    ranked_span_ids: Sequence[str],
    limit: int,
) -> tuple[DedupOriginal, ...]:
    """Select at most one ranked original from each reversible cluster."""

    if limit < 0:
        raise ValueError("evidence limit must be non-negative")
    by_span: dict[str, tuple[str, DedupOriginal]] = {}
    for cluster in graph.clusters:
        for original in cluster.originals:
            by_span[original.span_id] = (cluster.cluster_id, original)
    selected: list[DedupOriginal] = []
    seen_clusters: set[str] = set()
    for span_id in ranked_span_ids:
        try:
            cluster_id, original = by_span[span_id]
        except KeyError as exc:
            raise ValueError("ranked span ID is absent from the dedup graph") from exc
        if cluster_id in seen_clusters:
            continue
        selected.append(original)
        seen_clusters.add(cluster_id)
        if len(selected) == limit:
            break
    return tuple(selected)


def build_lane_evidence(
    *,
    lane: EvidenceLane | str,
    spans: Iterable[DedupOriginal | Mapping[str, object]],
    fabricated_text: str | None = None,
) -> LaneEvidence:
    """Represent an approved lane explicitly; never synthesize missing evidence."""

    if fabricated_text is not None:
        raise ValueError("MISSING lane cannot fabricate evidence text")
    evidence_lane = EvidenceLane(lane)
    materialized: list[DedupOriginal] = []
    for input_order, span in enumerate(spans):
        if isinstance(span, DedupOriginal):
            materialized.append(span)
        else:
            materialized.append(_original(span, input_order=input_order))
    return LaneEvidence(
        lane=evidence_lane,
        status=(LaneEvidenceStatus.AVAILABLE if materialized else LaneEvidenceStatus.MISSING),
        spans=tuple(materialized),
    )


__all__ = [
    "DedupCluster",
    "DedupEdge",
    "NormalizationPolicy",
    "build_lane_evidence",
    "cluster_near_duplicates",
    "normalize_for_comparison",
    "select_diverse_evidence",
]
