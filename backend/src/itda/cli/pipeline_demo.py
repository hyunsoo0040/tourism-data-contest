"""Run or validate the deterministic frozen PREVIEW seven-stage pipeline."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from stat import S_ISDIR, S_ISREG

from pydantic import ValidationError

from itda.cli.freeze_preview import (
    PublicationStateUncertainError,
    _fsync_tree,
    prepared_directory_snapshot,
    publish_immutable_directory,
)
from itda.contracts.candidate_review import (
    CHECK_RESOLVED,
    CandidateReview,
    check_candidate_review,
)
from itda.contracts.pipeline import (
    MATERIALIZED_STAGES,
    PIPELINE_STAGE_ORDER,
    STAGE_ARTIFACT_PATHS,
    PipelineManifest,
    PipelineStage,
    PipelineStageRow,
    PipelineStageStatus,
    PipelineValidationError,
    StageLineage,
    canonical_json_bytes,
    lineage_input_hash,
    sha256_bytes,
    validate_pipeline_output,
)

_FROZEN_SOURCE_FILES = (
    "candidate-review.json",
    "provider-bundle.json",
    "freeze-manifest.json",
)


@dataclass(frozen=True)
class _FrozenSnapshot:
    review: CandidateReview
    source_files: list[dict[str, str]]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--check-stage-manifest", type=Path)
    parser.add_argument("--source-lock", type=Path)
    return parser


def _read_frozen_source_bytes(frozen_root: Path) -> dict[str, bytes]:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory_flag
        or not nofollow_flag
        or os.open not in getattr(os, "supports_dir_fd", frozenset())
        or os.stat not in getattr(os, "supports_dir_fd", frozenset())
        or os.stat not in getattr(os, "supports_follow_symlinks", frozenset())
        or os.listdir not in getattr(os, "supports_fd", frozenset())
    ):
        raise PipelineValidationError("platform lacks secure frozen snapshot capabilities")

    try:
        root_descriptor = os.open(
            frozen_root,
            os.O_RDONLY | directory_flag | nofollow_flag,
        )
    except OSError as exc:
        raise PipelineValidationError("frozen input must be a regular directory") from exc
    try:
        if not S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise PipelineValidationError("frozen input must be a regular directory")
        if set(os.listdir(root_descriptor)) != set(_FROZEN_SOURCE_FILES):
            raise PipelineValidationError("frozen input must contain the exact approved file set")

        snapshot: dict[str, bytes] = {}
        for name in _FROZEN_SOURCE_FILES:
            before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            if not S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise PipelineValidationError(f"{name} must be a private regular non-symlink file")
            descriptor = os.open(
                name,
                os.O_RDONLY | nofollow_flag,
                dir_fd=root_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    not S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino, opened.st_size)
                    != (before.st_dev, before.st_ino, before.st_size)
                ):
                    raise PipelineValidationError(f"{name} changed before snapshot read")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    payload = handle.read()
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
                ) or len(payload) != opened.st_size:
                    raise PipelineValidationError(f"{name} changed during snapshot read")
                snapshot[name] = payload
            finally:
                os.close(descriptor)
        return snapshot
    except OSError as exc:
        raise PipelineValidationError("frozen input snapshot could not be read safely") from exc
    finally:
        os.close(root_descriptor)


def _load_frozen_snapshot(frozen_root: Path) -> _FrozenSnapshot:
    snapshot = _read_frozen_source_bytes(frozen_root)
    with tempfile.TemporaryDirectory(prefix=".pipeline-frozen-snapshot-") as temporary_name:
        temporary = Path(temporary_name)
        (temporary / "candidate-review.json").write_bytes(snapshot["candidate-review.json"])
        (temporary / "provider-bundle.json").write_bytes(snapshot["provider-bundle.json"])
        review_result = check_candidate_review(temporary / "candidate-review.json")
    if review_result.exit_code != CHECK_RESOLVED:
        raise PipelineValidationError("frozen candidate review is not resolved and bundle-matched")
    assert review_result.review is not None
    review_bytes = snapshot["candidate-review.json"]
    bundle_bytes = snapshot["provider-bundle.json"]
    freeze_manifest = json.loads(snapshot["freeze-manifest.json"])
    if not isinstance(freeze_manifest, dict):
        raise PipelineValidationError("freeze manifest must be a JSON object")
    expected_freeze_manifest = {
        "bundle_sha256": sha256_bytes(bundle_bytes),
        "candidate_count": len(review_result.review.candidates),
        "review_sha256": sha256_bytes(review_bytes),
        "status": "FROZEN_PREVIEW",
    }
    if freeze_manifest != expected_freeze_manifest:
        raise PipelineValidationError("freeze manifest does not bind approved input bytes")
    return _FrozenSnapshot(
        review=review_result.review,
        source_files=[
            {"path": name, "sha256": sha256_bytes(snapshot[name])} for name in _FROZEN_SOURCE_FILES
        ],
    )


def _collect_artifact(source_files: list[dict[str, str]]) -> dict[str, object]:
    return {
        "assessment_status": "NOT_SCORED",
        "source_files": source_files,
        "split": "PREVIEW",
        "stage": "collect",
        "status": "MATERIALIZED",
    }


def _normalize_artifact(review: CandidateReview) -> dict[str, object]:
    rows = []
    for candidate in review.candidates:
        rows.append(
            {
                "assessment_status": candidate.assessment_status.value,
                "evidence": [
                    {
                        "asset_usage_status": evidence.asset_usage_status.value,
                        "provider": evidence.provider.value,
                        "raw_response_sha256": evidence.raw_response_sha256,
                        "source_id": evidence.source_id,
                    }
                    for evidence in candidate.evidence
                ],
                "name_ko": candidate.name_ko,
                "place_id": candidate.place_id,
                "split": candidate.split.value,
            }
        )
    return {
        "rows": rows,
        "stage": "normalize",
        "status": "MATERIALIZED",
    }


def _deferred_artifact(stage: str, input_hash: str) -> dict[str, object]:
    return {
        "input_hash": input_hash,
        "procedure_proof": {
            "executed": True,
            "reason": "DEFERRED_PHASE_1_CONTRACT_ONLY",
            "result_emitted": False,
        },
        "stage": stage,
        "status": "NOT_SCORED",
    }


def run_pipeline_demo(*, frozen_root: Path, output_root: Path) -> PipelineManifest:
    """Execute all seven stages from approved frozen bytes without live imports or I/O."""

    if os.path.lexists(output_root):
        raise PipelineValidationError("output already exists; pipeline runs are immutable")
    frozen_snapshot = _load_frozen_snapshot(frozen_root)
    source_files = frozen_snapshot.source_files
    source_input_hash = sha256_bytes(canonical_json_bytes(source_files))
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_root.parent))
    try:
        (temporary / "stages").mkdir()
        rows: list[PipelineStageRow] = []
        for index, (stage, artifact_path) in enumerate(
            zip(PIPELINE_STAGE_ORDER, STAGE_ARTIFACT_PATHS, strict=True)
        ):
            if index == 0:
                lineage: tuple[StageLineage, ...] = ()
                input_hash = source_input_hash
                artifact = _collect_artifact(source_files)
            else:
                previous = rows[index - 1]
                lineage = (StageLineage(stage=previous.stage, output_hash=previous.output_hash),)
                input_hash = lineage_input_hash(lineage)
                artifact = (
                    _normalize_artifact(frozen_snapshot.review)
                    if stage == "normalize"
                    else _deferred_artifact(stage, input_hash)
                )
            artifact_bytes = canonical_json_bytes(artifact)
            (temporary / artifact_path).write_bytes(artifact_bytes)
            rows.append(
                PipelineStageRow(
                    stage=PipelineStage(stage),
                    status=(
                        PipelineStageStatus.MATERIALIZED
                        if stage in MATERIALIZED_STAGES
                        else PipelineStageStatus.NOT_SCORED
                    ),
                    artifact_path=artifact_path,
                    input_hash=input_hash,
                    output_hash=sha256_bytes(artifact_bytes),
                    upstream_lineage=lineage,
                )
            )
        manifest = PipelineManifest(
            schema_version="pipeline-demo-v1",
            source_input_hash=source_input_hash,
            stages=tuple(rows),  # type: ignore[arg-type]
        )
        (temporary / "stage-manifest.json").write_bytes(
            canonical_json_bytes(manifest.model_dump(mode="json"))
        )
        _fsync_tree(temporary)
        with prepared_directory_snapshot(temporary) as prepared_snapshot:
            with tempfile.TemporaryDirectory(prefix=".pipeline-validation-") as validation_parent:
                validation_root = Path(validation_parent) / "output"
                prepared_snapshot.materialize(validation_root)
                validate_pipeline_output(validation_root)
            publish_immutable_directory(
                prepared=temporary,
                output=output_root,
                snapshot=prepared_snapshot,
            )
        return manifest
    except PublicationStateUncertainError:
        raise
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check_stage_manifest is not None:
            if args.check is not None or args.frozen_input is not None or args.output is not None:
                raise PipelineValidationError(
                    "--check-stage-manifest cannot be combined with other arguments"
                )
            from itda.cli.freeze_preview import validate_frozen_preview_boundary

            source_lock_path = (
                args.source_lock
                if args.source_lock is not None
                else args.check_stage_manifest.parent.parent
                / "source-locks"
                / "preview-v1-source-lock.json"
            )
            validate_frozen_preview_boundary(
                args.check_stage_manifest,
                source_lock_path=source_lock_path,
            )
        elif args.check is not None:
            if (
                args.frozen_input is not None
                or args.output is not None
                or args.source_lock is not None
            ):
                raise PipelineValidationError("--check cannot be combined with run arguments")
            validate_pipeline_output(args.check)
        else:
            if args.frozen_input is None or args.output is None or args.source_lock is not None:
                raise PipelineValidationError("run requires --frozen-input and --output")
            run_pipeline_demo(frozen_root=args.frozen_input, output_root=args.output)
    except (OSError, ValueError, ValidationError, PipelineValidationError) as exc:
        print(f"pipeline-demo refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
