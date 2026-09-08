"""Freeze-first deterministic retrieval for separate description and Odii lanes."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from itda.analysis.text.model_artifacts import VerifiedFreezeGuard
from itda.domain.canonical import canonical_sha256

_LANES = ("DESCRIPTION", "ODII")
_FORBIDDEN_INPUT_KEYS = (
    "expert_score",
    "peer_score",
    "model_target",
    "protected_partition_member",
    "individual_label",
    "evaluator_identity",
    "blind_membership",
)
_PROVENANCE_KEYS = {
    "freeze_receipt_sha256",
    "accepted_revision_set_sha256",
    "source_manifest_sha256",
    "data_lineage_sha256",
    "data_version",
    "model_id",
    "model_revision",
    "model_config_sha256",
    "tokenizer_sha256",
    "weight_sha256",
    "prompt_anchor_version",
    "preprocessing_version",
    "scoring_version",
    "code_git_sha",
    "config_sha256",
    "started_at",
    "completed_at",
    "output_sha256",
}


class CandidateEncoder(Protocol):
    def encode_document(self, texts: list[str], **kwargs: object) -> Sequence[Sequence[float]]: ...

    def encode_query(self, texts: list[str], **kwargs: object) -> Sequence[Sequence[float]]: ...


def _reject_protected_inputs(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, nested in current.items():
                folded = str(key).casefold()
                if any(forbidden in folded for forbidden in _FORBIDDEN_INPUT_KEYS):
                    raise ValueError("candidate input contains a prohibited protected field")
                stack.append(nested)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)


def _require_mapping(value: object, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"candidate {name} must be an object")
    return value


def _require_string(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"candidate {name} must be a non-empty string")
    return value


def _parse_now(value: str | datetime) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(value.replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("candidate run time must be a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("candidate run time must be UTC")
    return parsed


def _dot(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        raise ValueError("candidate embeddings must have one stable non-empty dimension")
    value = sum(float(a) * float(b) for a, b in zip(left, right, strict=True))
    if not math.isfinite(value):
        raise ValueError("candidate score must be finite")
    return round(value, 12)


def _validate_source_manifest(source_manifest: Mapping[str, Any]) -> None:
    if source_manifest.get("schema_version") != "phase3-candidate-input-v1":
        raise ValueError("candidate source manifest schema is invalid")
    if (
        source_manifest.get("synthetic_only") is not True
        or source_manifest.get("partition") != "SYNTHETIC_ONLY"
    ):
        raise ValueError("candidate synthetic source scope is invalid")
    attributes = source_manifest.get("attributes")
    sources = source_manifest.get("sources")
    if not isinstance(attributes, list) or not attributes or not isinstance(sources, list):
        raise ValueError("candidate source manifest is incomplete")
    for source in sources:
        source_row = _require_mapping(source, name="source")
        lane = source_row.get("lane")
        if lane not in _LANES:
            raise ValueError("candidate source lane is invalid")
        spans = source_row.get("spans")
        if not isinstance(spans, list):
            raise ValueError("candidate source spans are invalid")
        if source_row.get("status") == "MISSING":
            if spans or source_row.get("source_sha256") is not None:
                raise ValueError("candidate MISSING lane cannot contain source evidence")
            continue
        raw_text = _require_string(source_row.get("raw_text"), name="source text")
        if hashlib.sha256(raw_text.encode("utf-8")).hexdigest() != source_row.get("source_sha256"):
            raise ValueError("candidate source digest has drifted")
        raw_bytes = raw_text.encode("utf-8")
        for span in spans:
            span_row = _require_mapping(span, name="source span")
            try:
                char_slice = raw_text[int(span_row["start_char"]) : int(span_row["end_char"])]
                byte_slice = raw_bytes[
                    int(span_row["start_byte"]) : int(span_row["end_byte"])
                ].decode("utf-8")
            except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
                raise ValueError("candidate source span offsets are invalid") from exc
            if char_slice != byte_slice or hashlib.sha256(
                char_slice.encode()
            ).hexdigest() != span_row.get("slice_sha256"):
                raise ValueError("candidate source span digest has drifted")


def _receipt_bindings(receipt: Mapping[str, Any]) -> tuple[str, str]:
    freeze = receipt.get("freeze")
    if isinstance(freeze, Mapping):
        return (
            _require_string(
                freeze.get("accepted_revision_set_sha256"),
                name="accepted revision digest",
            ),
            _require_string(freeze.get("data_lineage_sha256"), name="data lineage digest"),
        )
    return (
        _require_string(
            receipt.get("accepted_revision_set_sha256"), name="accepted revision digest"
        ),
        _require_string(receipt.get("dev_lineage_sha256"), name="data lineage digest"),
    )


def build_candidate_manifest(
    *,
    source_manifest: Mapping[str, Any],
    freeze_receipt: Mapping[str, Any] | None,
    expected_authority_sha256: str | None,
    now: str | datetime,
    resolve_model_location: Callable[[], str],
    resolve_cache_location: Callable[[], str],
    encoder_factory: Callable[[str], CandidateEncoder],
    observation_hook: Callable[..., None] | None = None,
) -> dict[str, Any]:
    """Build canonical-ready lane candidates after the complete freeze gate."""

    _reject_protected_inputs(source_manifest)
    _validate_source_manifest(source_manifest)
    source_digest = canonical_sha256(source_manifest)
    freeze_digest = VerifiedFreezeGuard.verify(
        freeze_receipt,
        expected_source_manifest_sha256=source_digest,
        expected_authority_sha256=expected_authority_sha256,
        now=now,
    )
    if freeze_receipt is None:  # retained for static narrowing after the fail-closed guard
        raise ValueError("freeze receipt is required")
    accepted_digest, lineage_digest = _receipt_bindings(freeze_receipt)
    if observation_hook is not None:
        observation_hook("FREEZE_VERIFIED", freeze_receipt_sha256=freeze_digest)

    model_location = resolve_model_location()
    resolve_cache_location()
    encoder = encoder_factory(model_location)

    attributes = [
        _require_mapping(item, name="attribute") for item in source_manifest["attributes"]
    ]
    query_texts = [
        _require_string(item.get("query_ko"), name="attribute query") for item in attributes
    ]
    query_vectors = encoder.encode_query(query_texts)
    if len(query_vectors) != len(attributes):
        raise ValueError("candidate query embedding count has drifted")

    lane_outputs: dict[str, dict[str, Any]] = {}
    for lane in _LANES:
        source_rows = [
            _require_mapping(source, name="source")
            for source in source_manifest["sources"]
            if _require_mapping(source, name="source").get("lane") == lane
        ]
        available = [source for source in source_rows if source.get("status") != "MISSING"]
        if not available:
            lane_outputs[lane] = {"status": "MISSING", "candidates": [], "published_evidence": []}
            continue
        documents: list[str] = []
        identities: list[tuple[Mapping[str, Any], Mapping[str, Any], str]] = []
        for source in available:
            raw_text = _require_string(source.get("raw_text"), name="source text")
            for span in source["spans"]:
                span_row = _require_mapping(span, name="source span")
                text = raw_text[int(span_row["start_char"]) : int(span_row["end_char"])]
                documents.append(text)
                identities.append((source, span_row, text))
        document_vectors = encoder.encode_document(documents)
        if len(document_vectors) != len(identities):
            raise ValueError("candidate document embedding count has drifted")
        candidates: list[dict[str, Any]] = []
        for (source, span, text), vector in zip(identities, document_vectors, strict=True):
            attribute_scores: list[dict[str, Any]] = [
                {
                    "attribute_id": _require_string(
                        attribute.get("attribute_id"), name="attribute ID"
                    ),
                    "score": _dot(query_vector, vector),
                }
                for attribute, query_vector in zip(attributes, query_vectors, strict=True)
            ]
            score = max(float(item["score"]) for item in attribute_scores)
            identity_payload = {
                "lane": lane,
                "source_id": source["source_id"],
                "span_id": span["span_id"],
                "scoring_version": _require_mapping(
                    source_manifest.get("versions"), name="versions"
                )["scoring_version"],
            }
            candidates.append(
                {
                    "candidate_id": canonical_sha256(identity_payload),
                    "lane": lane,
                    "source_id": source["source_id"],
                    "source_sha256": source["source_sha256"],
                    "span_id": span["span_id"],
                    "slice_sha256": span["slice_sha256"],
                    "start_char": span["start_char"],
                    "end_char": span["end_char"],
                    "start_byte": span["start_byte"],
                    "end_byte": span["end_byte"],
                    "dedup_cluster_id": span["dedup_cluster_id"],
                    "dedup_edges": span["dedup_edges"],
                    "original_order": span["original_order"],
                    "text": text,
                    "attribute_scores": attribute_scores,
                    "score": score,
                }
            )
        candidates.sort(
            key=lambda item: (
                -float(item["score"]),
                str(item["source_id"]),
                int(item["original_order"]),
                str(item["span_id"]),
            )
        )
        published: list[dict[str, Any]] = []
        seen_clusters: set[str] = set()
        for candidate in candidates:
            cluster = str(candidate["dedup_cluster_id"])
            if cluster in seen_clusters:
                continue
            published.append(candidate)
            seen_clusters.add(cluster)
            if len(published) == 3:
                break
        lane_outputs[lane] = {
            "status": "AVAILABLE",
            "candidates": candidates,
            "published_evidence": published,
        }

    versions = _require_mapping(source_manifest.get("versions"), name="versions")
    run = _require_mapping(source_manifest.get("run"), name="run")
    _parse_now(now)
    provenance = {
        "freeze_receipt_sha256": freeze_digest,
        "accepted_revision_set_sha256": accepted_digest,
        "source_manifest_sha256": source_digest,
        "data_lineage_sha256": lineage_digest,
        "data_version": versions["data_version"],
        "model_id": versions["model_id"],
        "model_revision": versions["model_revision"],
        "model_config_sha256": versions["model_config_sha256"],
        "tokenizer_sha256": versions["tokenizer_sha256"],
        "weight_sha256": versions["weight_sha256"],
        "prompt_anchor_version": versions["prompt_anchor_version"],
        "preprocessing_version": versions["preprocessing_version"],
        "scoring_version": versions["scoring_version"],
        "code_git_sha": versions["code_git_sha"],
        "config_sha256": versions["config_sha256"],
        "started_at": run["started_at"],
        "completed_at": run["completed_at"],
    }
    result: dict[str, Any] = {
        "schema_version": "phase3-candidate-run-manifest-v1",
        "lanes": lane_outputs,
        "provenance": provenance,
    }
    provenance["output_sha256"] = canonical_sha256(result)
    validate_candidate_manifest(result)
    return result


def validate_candidate_manifest(value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != "phase3-candidate-run-manifest-v1":
        raise ValueError("candidate manifest schema is invalid")
    provenance = _require_mapping(value.get("provenance"), name="provenance")
    if set(provenance) != _PROVENANCE_KEYS:
        raise ValueError("candidate provenance is incomplete")
    started_at = _parse_now(_require_string(provenance.get("started_at"), name="run started_at"))
    completed_at = _parse_now(
        _require_string(provenance.get("completed_at"), name="run completed_at")
    )
    if completed_at < started_at:
        raise ValueError("candidate completed_at cannot precede started_at")
    output_sha = provenance.get("output_sha256")
    without_hash = dict(value)
    without_hash["provenance"] = {
        key: nested for key, nested in provenance.items() if key != "output_sha256"
    }
    if output_sha != canonical_sha256(without_hash):
        raise ValueError("candidate provenance output digest has drifted")
    lanes = _require_mapping(value.get("lanes"), name="lanes")
    if set(lanes) != set(_LANES):
        raise ValueError("candidate manifest lane inventory is incomplete")
    for lane in _LANES:
        lane_row = _require_mapping(lanes[lane], name="lane")
        candidates = lane_row.get("candidates")
        published = lane_row.get("published_evidence")
        if not isinstance(candidates, list) or not isinstance(published, list):
            raise ValueError("candidate lane evidence is invalid")
        if lane_row.get("status") == "MISSING":
            if candidates or published:
                raise ValueError("candidate MISSING lane cannot fabricate evidence")
            continue
        if lane_row.get("status") != "AVAILABLE" or not candidates:
            raise ValueError("candidate AVAILABLE lane requires evidence")
        if len(published) > 3:
            raise ValueError("candidate published evidence exceeds the limit")
        if any(item.get("lane") != lane for item in (*candidates, *published)):
            raise ValueError("candidate lane separation has been violated")


__all__ = ["CandidateEncoder", "build_candidate_manifest", "validate_candidate_manifest"]
