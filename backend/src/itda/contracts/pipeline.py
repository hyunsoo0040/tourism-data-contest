"""Deterministic seven-stage pipeline manifest and integrity validator."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Self

from pydantic import Field, ValidationError, field_validator, model_validator

from itda.contracts.base import Sha256, StrictContract, Version

PIPELINE_STAGE_ORDER = (
    "collect",
    "normalize",
    "analyze",
    "fuse",
    "publish",
    "recommend",
    "evaluate",
)
MATERIALIZED_STAGES = ("collect", "normalize")
STAGE_ARTIFACT_PATHS = tuple(
    f"stages/{index:02d}-{stage}.json" for index, stage in enumerate(PIPELINE_STAGE_ORDER, start=1)
)


class PipelineValidationError(ValueError):
    """Raised when pipeline order, hashes, lineage, or artifact bytes are invalid."""


class PipelineStage(StrEnum):
    COLLECT = "collect"
    NORMALIZE = "normalize"
    ANALYZE = "analyze"
    FUSE = "fuse"
    PUBLISH = "publish"
    RECOMMEND = "recommend"
    EVALUATE = "evaluate"


class PipelineStageStatus(StrEnum):
    MATERIALIZED = "MATERIALIZED"
    NOT_SCORED = "NOT_SCORED"


def canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class StageLineage(StrictContract):
    stage: PipelineStage
    output_hash: Sha256


def lineage_input_hash(lineage: tuple[StageLineage, ...]) -> str:
    descriptor = [{"output_hash": item.output_hash, "stage": item.stage.value} for item in lineage]
    return sha256_bytes(canonical_json_bytes(descriptor))


class PipelineStageRow(StrictContract):
    stage: PipelineStage
    status: PipelineStageStatus
    artifact_path: Annotated[str, Field(strict=True, min_length=1, max_length=200)]
    input_hash: Sha256
    output_hash: Sha256
    upstream_lineage: tuple[StageLineage, ...]

    @field_validator("artifact_path")
    @classmethod
    def artifact_path_must_be_safe_relative(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or not path.name:
            raise ValueError("artifact_path must be a safe relative path")
        return value


class PipelineManifest(StrictContract):
    schema_version: Version
    source_input_hash: Sha256
    stages: tuple[
        PipelineStageRow,
        PipelineStageRow,
        PipelineStageRow,
        PipelineStageRow,
        PipelineStageRow,
        PipelineStageRow,
        PipelineStageRow,
    ]

    @model_validator(mode="after")
    def validate_order_status_and_lineage(self) -> Self:
        names = tuple(row.stage.value for row in self.stages)
        if names != PIPELINE_STAGE_ORDER:
            raise ValueError("pipeline must contain the exact ordered seven stages")
        paths = tuple(row.artifact_path for row in self.stages)
        if paths != STAGE_ARTIFACT_PATHS:
            raise ValueError("stage artifact paths must match the exact ordered contract")

        for index, row in enumerate(self.stages):
            expected_status = (
                PipelineStageStatus.MATERIALIZED
                if row.stage.value in MATERIALIZED_STAGES
                else PipelineStageStatus.NOT_SCORED
            )
            if row.status is not expected_status:
                raise ValueError(f"invalid status for stage {row.stage.value}")
            if index == 0:
                if row.upstream_lineage:
                    raise ValueError("collect must not have upstream lineage")
                if row.input_hash != self.source_input_hash:
                    raise ValueError("collect input_hash must equal source_input_hash")
                continue

            previous = self.stages[index - 1]
            expected_lineage = (
                StageLineage(stage=previous.stage, output_hash=previous.output_hash),
            )
            if row.upstream_lineage != expected_lineage:
                raise ValueError(f"broken immediate lineage for stage {row.stage.value}")
            if row.input_hash != lineage_input_hash(expected_lineage):
                raise ValueError(f"broken input_hash for stage {row.stage.value}")
        return self


def _safe_artifact_path(output_root: Path, relative_path: str) -> Path:
    root = output_root.resolve(strict=True)
    candidate = root / relative_path
    current = root
    for part in PurePosixPath(relative_path).parts:
        current /= part
        if current.is_symlink():
            raise PipelineValidationError("stage artifact path must not traverse symlinks")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise PipelineValidationError("stage artifact path escapes output root")
    return resolved


def validate_pipeline_output(output_root: Path) -> PipelineManifest:
    """Recompute every output hash and validate exact stage order and lineage."""

    try:
        root_entries = {entry.name for entry in output_root.iterdir()}
        if root_entries != {"stage-manifest.json", "stages"}:
            raise PipelineValidationError("pipeline output contains missing or extra root entries")
        manifest_path = output_root / "stage-manifest.json"
        stages_path = output_root / "stages"
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or stages_path.is_symlink()
            or not stages_path.is_dir()
        ):
            raise PipelineValidationError("pipeline root entries must be regular local objects")
        manifest = PipelineManifest.model_validate_json(manifest_path.read_bytes())
        expected_stage_files = {
            PurePosixPath(row.artifact_path).relative_to("stages").as_posix()
            for row in manifest.stages
        }
        stage_entries = list(stages_path.rglob("*"))
        actual_stage_files = {path.relative_to(stages_path).as_posix() for path in stage_entries}
        if actual_stage_files != expected_stage_files or any(
            path.is_symlink() or not path.is_file() for path in stage_entries
        ):
            raise PipelineValidationError(
                "pipeline stages must contain exactly seven recursive regular files"
            )

        for row in manifest.stages:
            artifact_path = _safe_artifact_path(output_root, row.artifact_path)
            artifact_bytes = artifact_path.read_bytes()
            if sha256_bytes(artifact_bytes) != row.output_hash:
                raise PipelineValidationError(f"output_hash mismatch for stage {row.stage.value}")
            artifact = json.loads(artifact_bytes)
            if not isinstance(artifact, dict):
                raise PipelineValidationError("stage artifact must be a JSON object")
            if (
                artifact.get("stage") != row.stage.value
                or artifact.get("status") != row.status.value
            ):
                raise PipelineValidationError(
                    f"artifact contract mismatch for stage {row.stage.value}"
                )
            if row.status is PipelineStageStatus.NOT_SCORED:
                proof = artifact.get("procedure_proof")
                if not isinstance(proof, dict) or proof.get("executed") is not True:
                    raise PipelineValidationError(
                        f"deferred stage {row.stage.value} lacks procedure proof"
                    )
                if proof.get("result_emitted") is not False:
                    raise PipelineValidationError(
                        f"deferred stage {row.stage.value} emitted a scored result"
                    )
        return manifest
    except PipelineValidationError:
        raise
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        raise PipelineValidationError(str(exc)) from exc
