"""Offline, model-free text segmentation and deduplication entrypoint."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import os
import secrets
import subprocess
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from stat import S_ISDIR, S_ISREG
from typing import Annotated, Any, Literal, cast

from pydantic import Field, HttpUrl, ValidationError, model_validator

from itda.analysis.text.candidate_pipeline import validate_candidate_manifest
from itda.analysis.text.model_artifacts import (
    ModelArtifactManifest,
    VerifiedFreezeGuard,
    verify_local_snapshot,
)
from itda.analysis.text.normalization import cluster_near_duplicates
from itda.analysis.text.segmentation import segment_official_source
from itda.contracts.base import Sha256, StableId, StrictContract, Version
from itda.contracts.candidate_review import SelectedOdiiStoryIdentity
from itda.contracts.labeling import LABEL_RUBRIC_SPECS
from itda.contracts.text_evidence import (
    EvidenceLane,
    NormalizationPolicy,
    ParentSpanEdge,
    SourceSpan,
    SourceSpanKind,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_MAX_SOURCE_MANIFEST_BYTES = 2_000_000
_FORBIDDEN_INPUT_KEY_PARTS = (
    "blind",
    "evaluation",
    "expert",
    "label",
    "membership",
    "model",
    "partition",
    "peer",
    "score",
)

CandidateRunClock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_candidate_run_clock(clock: CandidateRunClock) -> datetime:
    instant = clock()
    if not isinstance(instant, datetime):
        raise ValueError("candidate run clock must return a datetime")
    if instant.tzinfo is None or instant.utcoffset() != UTC.utcoffset(instant):
        raise ValueError("candidate run clock must return UTC")
    return instant


def _format_candidate_run_time(instant: datetime) -> str:
    if instant.tzinfo is None or instant.utcoffset() != UTC.utcoffset(instant):
        raise ValueError("candidate run time must be UTC")
    return instant.isoformat().replace("+00:00", "Z")


class _ApprovedTextSource(StrictContract):
    lane: EvidenceLane
    source_id: StableId
    source_url: HttpUrl
    raw_response_sha256: Sha256
    source_text_sha256: Sha256
    rights_approved: Literal[True]
    raw_text: Annotated[str, Field(strict=True, min_length=1, max_length=1_000_000)]
    selected_odii_story: SelectedOdiiStoryIdentity | None = None

    @model_validator(mode="after")
    def validate_lane_identity(self) -> _ApprovedTextSource:
        if (self.lane is EvidenceLane.ODII) != (self.selected_odii_story is not None):
            raise ValueError("Odii identity must exist only for the Odii lane")
        if (
            self.selected_odii_story is not None
            and self.selected_odii_story.raw_response_sha256 != self.raw_response_sha256
        ):
            raise ValueError("selected Odii story response digest mismatch")
        return self


class _ApprovedSourceManifest(StrictContract):
    schema_version: Literal["approved-text-source-manifest-v1"]
    source_scope: Literal["APPROVED_DEV_SOURCE_ONLY"]
    normalization_version: Version
    dedup_policy: NormalizationPolicy
    sources: tuple[_ApprovedTextSource, ...]

    @model_validator(mode="after")
    def validate_source_identity(self) -> _ApprovedSourceManifest:
        identities = tuple((source.lane, source.source_id) for source in self.sources)
        if len(set(identities)) != len(identities):
            raise ValueError("source manifest identities must be unique within each lane")
        return self


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject_evaluation_shaped_keys(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            if any(
                fragment in str(key).casefold()
                for key in current
                for fragment in _FORBIDDEN_INPUT_KEY_PARTS
            ):
                raise ValueError("source manifest contains a forbidden input field")
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _secure_flags() -> tuple[int, int]:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(directory_flag, int) or not isinstance(nofollow_flag, int):
        raise ValueError("platform lacks stable no-follow source reads")
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise ValueError("platform lacks descriptor-relative source reads")
    return directory_flag, nofollow_flag


def _read_stable_source_manifest(path: Path) -> bytes:
    """Read one bounded regular manifest through pinned no-follow descriptors."""

    directory_flag, nofollow_flag = _secure_flags()
    directory_descriptor = os.open(path.parent, os.O_RDONLY | directory_flag | nofollow_flag)
    try:
        if not S_ISDIR(os.fstat(directory_descriptor).st_mode):
            raise ValueError("source manifest parent is not a regular directory")
        before = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            not S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_SOURCE_MANIFEST_BYTES
        ):
            raise ValueError("source manifest must be a bounded single-link regular file")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | nofollow_flag,
            dir_fd=directory_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise ValueError("source manifest changed before open")
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    raise ValueError("source manifest ended before its pinned size")
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                raise ValueError("source manifest changed while being read")
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def _write_no_replace(path: Path, payload: bytes) -> None:
    """Atomically link a complete canonical payload into a fresh destination."""

    directory_flag, nofollow_flag = _secure_flags()
    directory_descriptor = os.open(path.parent, os.O_RDONLY | directory_flag | nofollow_flag)
    temporary_name = f".{path.name}.{os.getpid()}.{_sha256(payload)[:16]}.tmp"
    descriptor: int | None = None
    try:
        if not S_ISDIR(os.fstat(directory_descriptor).st_mode):
            raise ValueError("output parent is not a regular directory")
        try:
            os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("output already exists; no-replace publication denied")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow_flag,
            0o600,
            dir_fd=directory_descriptor,
        )
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        os.close(directory_descriptor)


def _load_source_manifest(path: Path) -> tuple[_ApprovedSourceManifest, bytes]:
    payload = _read_stable_source_manifest(path)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("source manifest is not valid bounded JSON") from exc
    _reject_evaluation_shaped_keys(parsed)
    return _ApprovedSourceManifest.model_validate(parsed), payload


def build_segment_manifest(source_manifest_path: Path) -> bytes:
    """Build deterministic span, parent-edge, dedup, and lane-state bytes."""

    source_manifest, source_bytes = _load_source_manifest(source_manifest_path)
    all_spans: list[SourceSpan] = []
    source_roots: list[dict[str, object]] = []
    dedup_items: list[dict[str, object]] = []
    for source_order, source in enumerate(source_manifest.sources):
        spans = segment_official_source(
            raw_text=source.raw_text,
            lane=source.lane,
            source_id=source.source_id,
            source_url=str(source.source_url),
            raw_response_sha256=source.raw_response_sha256,
            normalization_version=source_manifest.normalization_version,
            rights_approved=source.rights_approved,
            selected_odii_story=source.selected_odii_story,
            expected_source_text_sha256=source.source_text_sha256,
        )
        source_roots.append(
            {
                "lane": source.lane.value,
                "source_id": source.source_id,
                "source_order": source_order,
                "source_text_sha256": source.source_text_sha256,
                "raw_response_sha256": source.raw_response_sha256,
            }
        )
        all_spans.extend(spans)
        for span_order, span in enumerate(spans):
            if span.kind is SourceSpanKind.PARENT_SECTION:
                continue
            dedup_items.append(
                {
                    "span_id": span.span_id,
                    "lane": span.lane.value,
                    "source_id": span.source_id,
                    "text": span.original_text,
                    "source_order": source_order,
                    "span_order": span_order,
                }
            )

    # The normalization API intentionally accepts only its four-field public item contract.
    graph = cluster_near_duplicates(
        tuple(
            {
                "span_id": item["span_id"],
                "lane": item["lane"],
                "source_id": item["source_id"],
                "text": item["text"],
            }
            for item in dedup_items
        ),
        policy=source_manifest.dedup_policy,
    )
    parent_edges = tuple(
        ParentSpanEdge(parent_span_id=span.parent_span_id, child_span_id=span.span_id)
        for span in all_spans
        if span.parent_span_id is not None
    )
    lane_rows = []
    for lane in EvidenceLane:
        lane_span_ids = tuple(
            span.span_id
            for span in all_spans
            if span.lane is lane and span.kind is not SourceSpanKind.PARENT_SECTION
        )
        lane_rows.append(
            {
                "lane": lane.value,
                "status": "AVAILABLE" if lane_span_ids else "MISSING",
                "span_ids": lane_span_ids,
            }
        )
    payload = {
        "schema_version": "text-span-dedup-manifest-v1",
        "source_manifest_sha256": _sha256(source_bytes),
        "normalization_version": source_manifest.normalization_version,
        "dedup_policy": source_manifest.dedup_policy.model_dump(mode="json"),
        "source_roots": source_roots,
        "lanes": lane_rows,
        "spans": [span.model_dump(mode="json") for span in all_spans],
        "parent_edges": [edge.model_dump(mode="json") for edge in parent_edges],
        "dedup_edges": [edge.model_dump(mode="json") for edge in graph.edges],
        "dedup_clusters": [cluster.model_dump(mode="json") for cluster in graph.clusters],
    }
    return canonical_json_bytes(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--segment-only", action="store_true")
    modes.add_argument("--candidate-run", action="store_true")
    modes.add_argument("--verify-candidate-output", action="store_true")
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--freeze-receipt", type=Path)
    parser.add_argument("--model-manifest", type=Path)
    parser.add_argument("--span-manifest", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def _candidate_arguments(args: argparse.Namespace) -> tuple[Path, Path, Path, Path]:
    values = (args.freeze_receipt, args.model_manifest, args.span_manifest, args.output)
    if any(value is None for value in values):
        raise ValueError(
            "candidate mode requires freeze receipt, model manifest, span manifest, and output"
        )
    return cast(tuple[Path, Path, Path, Path], values)


def _freeze_bindings(receipt: Mapping[str, object]) -> tuple[str, str, str]:
    freeze = receipt.get("freeze")
    if isinstance(freeze, Mapping):
        frozen_at = freeze.get("frozen_at")
        accepted = freeze.get("accepted_revision_set_sha256")
        lineage = freeze.get("data_lineage_sha256")
    else:
        frozen_at = receipt.get("frozen_at")
        accepted = receipt.get("accepted_revision_set_sha256")
        lineage = receipt.get("dev_lineage_sha256")
    if not all(isinstance(value, str) and value for value in (frozen_at, accepted, lineage)):
        raise ValueError("candidate freeze bindings are incomplete")
    return cast(tuple[str, str, str], (frozen_at, accepted, lineage))


class _SentenceTransformerAdapter:
    def __init__(self, root: Path) -> None:
        transformer = importlib.import_module("sentence_transformers").SentenceTransformer
        self._encoder = transformer(
            str(root),
            device="cpu",
            local_files_only=True,
            trust_remote_code=False,
        )

    def encode_query(self, texts: list[str]) -> Sequence[Sequence[float]]:
        return self._encoder.encode_query(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )

    def encode_document(self, texts: list[str]) -> Sequence[Sequence[float]]:
        return self._encoder.encode_document(
            texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )


def _dot(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or len(left) == 0:
        raise ValueError("candidate embedding dimensions have drifted")
    return round(sum(float(a) * float(b) for a, b in zip(left, right, strict=True)), 12)


def _span_candidate_manifest(
    *,
    span_manifest: Mapping[str, object],
    span_manifest_sha256: str,
    freeze_receipt_sha256: str,
    accepted_revision_set_sha256: str,
    data_lineage_sha256: str,
    started_at: datetime,
    clock: CandidateRunClock,
    model_manifest: ModelArtifactManifest,
    model_root: Path,
) -> dict[str, object]:
    if span_manifest.get("schema_version") != "text-span-dedup-manifest-v1":
        raise ValueError("candidate span manifest schema is invalid")
    spans = span_manifest.get("spans")
    clusters = span_manifest.get("dedup_clusters")
    if not isinstance(spans, list) or not isinstance(clusters, list):
        raise ValueError("candidate span manifest is incomplete")
    cluster_by_span: dict[str, str] = {}
    for cluster in clusters:
        if not isinstance(cluster, Mapping) or not isinstance(cluster.get("originals"), list):
            raise ValueError("candidate dedup cluster is invalid")
        cluster_id = cluster.get("cluster_id")
        if not isinstance(cluster_id, str):
            raise ValueError("candidate dedup cluster identity is invalid")
        originals = cluster.get("originals")
        if not isinstance(originals, list):
            raise ValueError("candidate dedup originals are invalid")
        for original in originals:
            if isinstance(original, Mapping) and isinstance(original.get("span_id"), str):
                cluster_by_span[original["span_id"]] = cluster_id
    edges_by_span: dict[str, set[str]] = {}
    dedup_edges = span_manifest.get("dedup_edges", [])
    if not isinstance(dedup_edges, list):
        raise ValueError("candidate dedup edge inventory is invalid")
    for edge in dedup_edges:
        if not isinstance(edge, Mapping):
            raise ValueError("candidate dedup edge is invalid")
        left = edge.get("left_span_id")
        right = edge.get("right_span_id")
        if not isinstance(left, str) or not isinstance(right, str):
            raise ValueError("candidate dedup edge identity is invalid")
        edges_by_span.setdefault(left, set()).add(right)
        edges_by_span.setdefault(right, set()).add(left)

    query_rows = [
        (
            spec.attribute_id.value,
            f"{spec.label_ko}: {spec.examples_ko[0]}",
        )
        for spec in LABEL_RUBRIC_SPECS
    ]
    encoder = _SentenceTransformerAdapter(model_root)
    query_vectors = encoder.encode_query([text for _, text in query_rows])
    lanes: dict[str, dict[str, object]] = {}
    for lane in ("DESCRIPTION", "ODII"):
        rows = [
            span
            for span in spans
            if isinstance(span, Mapping)
            and span.get("lane") == lane
            and span.get("kind") != "PARENT_SECTION"
        ]
        if not rows:
            lanes[lane] = {"status": "MISSING", "candidates": [], "published_evidence": []}
            continue
        texts = [str(row.get("original_text")) for row in rows]
        if any(not text for text in texts):
            raise ValueError("candidate source span text is missing")
        vectors = encoder.encode_document(texts)
        candidates: list[dict[str, Any]] = []
        for original_order, (row, text, vector) in enumerate(
            zip(rows, texts, vectors, strict=True)
        ):
            span_id = row.get("span_id")
            source_id = row.get("source_id")
            if not isinstance(span_id, str) or not isinstance(source_id, str):
                raise ValueError("candidate source identity is invalid")
            scores: list[dict[str, Any]] = [
                {"attribute_id": attribute_id, "score": _dot(query, vector)}
                for (attribute_id, _), query in zip(query_rows, query_vectors, strict=True)
            ]
            candidates.append(
                {
                    "candidate_id": canonical_sha256(
                        {
                            "lane": lane,
                            "source_id": source_id,
                            "span_id": span_id,
                            "scoring_version": "bge-m3-normalized-dot-v1",
                        }
                    ),
                    "lane": lane,
                    "source_id": source_id,
                    "source_sha256": row.get("source_text_sha256"),
                    "span_id": span_id,
                    "slice_sha256": row.get("source_slice_sha256"),
                    "start_char": row.get("start_char"),
                    "end_char": row.get("end_char"),
                    "start_byte": row.get("start_byte"),
                    "end_byte": row.get("end_byte"),
                    "dedup_cluster_id": cluster_by_span.get(span_id, span_id),
                    "dedup_edges": sorted(edges_by_span.get(span_id, set())),
                    "original_order": original_order,
                    "text": text,
                    "attribute_scores": scores,
                    "score": max(float(item["score"]) for item in scores),
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
        published: list[dict[str, object]] = []
        seen: set[str] = set()
        for candidate in candidates:
            cluster_id = str(candidate["dedup_cluster_id"])
            if cluster_id not in seen:
                published.append(candidate)
                seen.add(cluster_id)
            if len(published) == 3:
                break
        lanes[lane] = {
            "status": "AVAILABLE",
            "candidates": candidates,
            "published_evidence": published,
        }

    lane_payloads = {
        lane: {
            "schema_version": "phase3-lane-candidates-v1",
            "lane": lane,
            **lane_row,
        }
        for lane, lane_row in lanes.items()
    }
    lane_bytes = {lane: canonical_json_bytes(payload) for lane, payload in lane_payloads.items()}
    artifact_hashes = {
        "description-candidates.json": _sha256(lane_bytes["DESCRIPTION"]),
        "odii-candidates.json": _sha256(lane_bytes["ODII"]),
    }
    completed_at = _read_candidate_run_clock(clock)
    code_git_sha = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), text=True, timeout=10
    ).strip()
    provenance: dict[str, object] = {
        "freeze_receipt_sha256": freeze_receipt_sha256,
        "accepted_revision_set_sha256": accepted_revision_set_sha256,
        "source_manifest_sha256": span_manifest_sha256,
        "data_lineage_sha256": data_lineage_sha256,
        "data_version": f"span-{span_manifest_sha256[:16]}",
        "model_id": model_manifest.model_id,
        "model_revision": model_manifest.model_revision,
        "model_config_sha256": model_manifest.model_config_sha256,
        "tokenizer_sha256": model_manifest.tokenizer_sha256,
        "weight_sha256": model_manifest.weight_sha256,
        "prompt_anchor_version": "ko-attribute-anchor-v1",
        "preprocessing_version": span_manifest.get("normalization_version"),
        "scoring_version": "bge-m3-normalized-dot-v1",
        "code_git_sha": code_git_sha,
        "config_sha256": canonical_sha256(query_rows),
        "started_at": _format_candidate_run_time(started_at),
        "completed_at": _format_candidate_run_time(completed_at),
    }
    result: dict[str, object] = {
        "schema_version": "phase3-candidate-run-manifest-v1",
        "lanes": lanes,
        "artifacts": {
            "file_sha256s": artifact_hashes,
            "directory_output_sha256": canonical_sha256(artifact_hashes),
        },
        "provenance": provenance,
    }
    provenance["output_sha256"] = canonical_sha256(result)
    validate_candidate_manifest(result)
    result["_lane_payloads"] = lane_payloads
    return result


def _publish_candidate_directory(output: Path, manifest: dict[str, object]) -> None:
    lane_payloads = manifest.pop("_lane_payloads")
    if not isinstance(lane_payloads, Mapping):
        raise ValueError("candidate lane publication payload is invalid")
    validate_candidate_manifest(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    directory_flag, nofollow_flag = _secure_flags()
    if any(
        operation not in os.supports_dir_fd
        for operation in (os.mkdir, os.unlink, os.rmdir)
    ):
        raise ValueError("platform lacks descriptor-relative candidate publication")
    parent_descriptor = os.open(
        output.parent,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    staging_descriptor: int | None = None
    staging_name: str | None = None
    published = False
    files = {
        "description-candidates.json": lane_payloads["DESCRIPTION"],
        "odii-candidates.json": lane_payloads["ODII"],
        "candidate-run-manifest.json": manifest,
    }
    try:
        if not S_ISDIR(os.fstat(parent_descriptor).st_mode):
            raise ValueError("candidate output parent must be a regular directory")
        try:
            os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("candidate output directory already exists")

        for _ in range(32):
            candidate = f".{output.name}.{secrets.token_hex(12)}"
            try:
                os.mkdir(candidate, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError:
                continue
            staging_name = candidate
            break
        if staging_name is None:
            raise FileExistsError("could not reserve a private candidate staging directory")
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY | directory_flag | nofollow_flag,
            dir_fd=parent_descriptor,
        )
        staged_identity = _directory_identity(os.fstat(staging_descriptor))
        visible_staging = os.stat(
            staging_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _directory_identity(visible_staging) != staged_identity:
            raise OSError("candidate staging directory changed before publication")
        for name, payload in files.items():
            _write_candidate_file_at(
                staging_descriptor,
                name,
                canonical_json_bytes(payload),
                nofollow_flag=nofollow_flag,
            )
        os.fsync(staging_descriptor)
        if _directory_identity(os.fstat(staging_descriptor)) != staged_identity:
            raise OSError("candidate staging directory identity changed before publication")
        _rename_directory_noreplace_at(parent_descriptor, staging_name, output.name)
        published = True
        visible_output = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _directory_identity(visible_output) != staged_identity:
            raise OSError("published candidate directory has an unexpected identity")
        os.fsync(parent_descriptor)
    finally:
        if staging_descriptor is not None:
            if not published and staging_name is not None:
                with suppress(OSError):
                    visible_staging = os.stat(
                        staging_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if _directory_identity(visible_staging) == _directory_identity(
                        os.fstat(staging_descriptor)
                    ):
                        for name in files:
                            with suppress(FileNotFoundError):
                                os.unlink(name, dir_fd=staging_descriptor)
                        os.rmdir(staging_name, dir_fd=parent_descriptor)
            os.close(staging_descriptor)
        os.close(parent_descriptor)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode)


def _file_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _write_candidate_file_at(
    directory_descriptor: int,
    name: str,
    payload: bytes,
    *,
    nofollow_flag: int,
) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow_flag,
        0o600,
        dir_fd=directory_descriptor,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("candidate artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace_at(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Atomically publish one sibling directory without replacing any entry."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
    if hasattr(library, "renameat2"):
        renameat2 = library.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            destination_bytes,
            1,
        )
    elif hasattr(library, "renameatx_np"):
        renameatx_np = library.renameatx_np
        renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            destination_bytes,
            0x00000004,
        )
    else:
        raise OSError("platform does not provide atomic no-replace candidate publication")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _read_candidate_file_at(directory_descriptor: int, name: str) -> bytes:
    _, nofollow_flag = _secure_flags()
    before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    if (
        not S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= _MAX_SOURCE_MANIFEST_BYTES
    ):
        raise ValueError("candidate artifact must be a bounded single-link regular file")
    descriptor = os.open(
        name,
        os.O_RDONLY | nofollow_flag,
        dir_fd=directory_descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if _file_signature(opened) != _file_signature(before):
            raise ValueError("candidate artifact changed before read")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        visible_after = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            len(payload) != opened.st_size
            or _file_signature(after) != _file_signature(opened)
            or _file_signature(visible_after) != _file_signature(opened)
        ):
            raise ValueError("candidate artifact changed during read")
        return payload
    finally:
        os.close(descriptor)


def _verify_candidate_directory(output: Path) -> dict[str, object]:
    directory_flag, nofollow_flag = _secure_flags()
    expected = {
        "description-candidates.json",
        "odii-candidates.json",
        "candidate-run-manifest.json",
    }
    parent_descriptor = os.open(
        output.parent,
        os.O_RDONLY | directory_flag | nofollow_flag,
    )
    output_descriptor: int | None = None
    try:
        before = os.stat(output.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not S_ISDIR(before.st_mode):
            raise ValueError("candidate output must be a regular directory")
        output_descriptor = os.open(
            output.name,
            os.O_RDONLY | directory_flag | nofollow_flag,
            dir_fd=parent_descriptor,
        )
        opened_identity = _directory_identity(os.fstat(output_descriptor))
        if opened_identity != _directory_identity(before):
            raise ValueError("candidate output directory changed before verification")
        actual = set(os.listdir(output_descriptor))
        if actual != expected:
            raise ValueError("candidate output inventory is incomplete")
        payloads = {
            name: _read_candidate_file_at(output_descriptor, name) for name in expected
        }
        if set(os.listdir(output_descriptor)) != expected:
            raise ValueError("candidate output inventory changed during verification")
        visible_after = os.stat(
            output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _directory_identity(os.fstat(output_descriptor)) != opened_identity
            or _directory_identity(visible_after) != opened_identity
        ):
            raise ValueError("candidate output directory identity changed during verification")
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)
        os.close(parent_descriptor)
    parsed = {name: json.loads(payload) for name, payload in payloads.items()}
    manifest = parsed["candidate-run-manifest.json"]
    if not isinstance(manifest, dict):
        raise ValueError("candidate run manifest is invalid")
    validate_candidate_manifest(manifest)
    lanes = manifest.get("lanes")
    if not isinstance(lanes, Mapping):
        raise ValueError("candidate run lane inventory is invalid")
    if parsed["description-candidates.json"] != {
        "schema_version": "phase3-lane-candidates-v1",
        "lane": "DESCRIPTION",
        **cast(Mapping[str, object], lanes["DESCRIPTION"]),
    } or parsed["odii-candidates.json"] != {
        "schema_version": "phase3-lane-candidates-v1",
        "lane": "ODII",
        **cast(Mapping[str, object], lanes["ODII"]),
    }:
        raise ValueError("candidate lane file does not match the run manifest")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or not isinstance(artifacts.get("file_sha256s"), Mapping):
        raise ValueError("candidate artifact hashes are incomplete")
    hashes = {
        "description-candidates.json": _sha256(payloads["description-candidates.json"]),
        "odii-candidates.json": _sha256(payloads["odii-candidates.json"]),
    }
    if artifacts["file_sha256s"] != hashes or artifacts.get(
        "directory_output_sha256"
    ) != canonical_sha256(hashes):
        raise ValueError("candidate artifact hashes have drifted")
    return manifest


def _run_candidate(
    args: argparse.Namespace,
    *,
    clock: CandidateRunClock = _utc_now,
) -> dict[str, object]:
    freeze_path, model_path, span_path, output = _candidate_arguments(args)
    # D-11 is fully read and verified before either model/cache or span paths are touched.
    receipt, freeze_digest = VerifiedFreezeGuard.from_path(freeze_path)
    _frozen_at, accepted_digest, lineage_digest = _freeze_bindings(receipt)
    started_at = _read_candidate_run_clock(clock)
    model_manifest, model_root = verify_local_snapshot(model_path)
    if model_manifest.freeze_receipt_sha256 != freeze_digest:
        raise ValueError("candidate model manifest has a different freeze parent")
    span_bytes = _read_stable_source_manifest(span_path)
    span_manifest = json.loads(span_bytes)
    _reject_evaluation_shaped_keys(span_manifest)
    if not isinstance(span_manifest, Mapping):
        raise ValueError("candidate span manifest must be an object")
    built = _span_candidate_manifest(
        span_manifest=span_manifest,
        span_manifest_sha256=_sha256(span_bytes),
        freeze_receipt_sha256=freeze_digest,
        accepted_revision_set_sha256=accepted_digest,
        data_lineage_sha256=lineage_digest,
        started_at=started_at,
        clock=clock,
        model_manifest=model_manifest,
        model_root=model_root,
    )
    _publish_candidate_directory(output, built)
    return _verify_candidate_directory(output)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    response: dict[str, object]
    try:
        if args.segment_only:
            if args.source_manifest is None or args.output is None:
                raise ValueError("segment-only requires --source-manifest and --output")
            payload = build_segment_manifest(args.source_manifest)
            _write_no_replace(args.output, payload)
            response = {"manifest_sha256": _sha256(payload), "status": "WRITTEN"}
        elif args.candidate_run:
            manifest = _run_candidate(args)
            provenance = cast(Mapping[str, object], manifest["provenance"])
            response = {
                "manifest_sha256": provenance["output_sha256"],
                "status": "CANDIDATE_DIRECTORY_WRITTEN",
            }
        else:
            _, _, _, output = _candidate_arguments(args)
            manifest = _verify_candidate_directory(output)
            provenance = cast(Mapping[str, object], manifest["provenance"])
            response = {
                "manifest_sha256": provenance["output_sha256"],
                "status": "CANDIDATE_DIRECTORY_VERIFIED",
            }
    except (OSError, ValueError, ValidationError) as exc:
        raise SystemExit(f"text candidate operation failed: {exc}") from exc
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
