from __future__ import annotations

import hashlib
import json
import os
import socket
from base64 import b64encode
from pathlib import Path
from stat import S_ISDIR, S_ISREG

import pytest

import itda.cli.freeze_preview as freeze_preview_module
import itda.cli.pipeline_demo as pipeline_demo_module
from itda.cli.pipeline_demo import main as pipeline_demo_main
from itda.contracts.candidate_review import (
    BLOCKED_RIGHTS_STATUS,
    LOCKED_PREVIEW_CANDIDATES,
)
from itda.contracts.pipeline import (
    MATERIALIZED_STAGES,
    PIPELINE_STAGE_ORDER,
    PipelineValidationError,
    validate_pipeline_output,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _frozen_source(root: Path) -> Path:
    root.mkdir()
    candidates: list[dict[str, object]] = []
    bundle_rows: list[dict[str, object]] = []
    for index, name in enumerate(LOCKED_PREVIEW_CANDIDATES):
        evidence = []
        for provider, endpoint in (
            ("TOUR_API", "KorService2/detailCommon2"),
            ("ODII", "Odii/storyBasedList"),
        ):
            raw_body = _canonical(
                {
                    "candidate": index,
                    "provider": provider,
                    "rightsRows": ([{"cpyrhtDivCd": "Type3"}] if provider == "TOUR_API" else []),
                }
            )
            source_id = f"{provider.lower()}-{index}"
            evidence_row = {
                "provider": provider,
                "source_id": source_id,
                "endpoint": endpoint,
                "request_scope": {"candidate": name},
                "retrieved_at": "2026-07-22T12:00:00Z",
                "http_status": 200,
                "raw_response_sha256": _sha(raw_body),
                "modifiedtime": None,
                "upstream_rights": ([{"cpyrhtDivCd": "Type3"}] if provider == "TOUR_API" else []),
                "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                "unresolved_reason": None,
            }
            evidence.append(evidence_row)
            bundle_rows.append(
                {
                    "candidate_place_id": f"preview:{index + 1}",
                    "provider": provider,
                    "endpoint": endpoint,
                    "request_scope": {"candidate": name},
                    "source_id": source_id,
                    "retrieved_at": "2026-07-22T12:00:00Z",
                    "http_status": 200,
                    "raw_response_sha256": _sha(raw_body),
                    "raw_body_base64": b64encode(raw_body).decode(),
                    "modifiedtime": None,
                    "rights": ([{"cpyrhtDivCd": "Type3"}] if provider == "TOUR_API" else []),
                    "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                }
            )
        candidates.append(
            {
                "place_id": f"preview:{index + 1}",
                "name_ko": name,
                "split": "PREVIEW",
                "assessment_status": "NOT_SCORED",
                "resolution_status": "RESOLVED",
                "evidence": evidence,
            }
        )
    bundle_bytes = _canonical(
        {
            "schema_version": "provider-bundle-v1",
            "redacted": True,
            "rows": bundle_rows,
        }
    )
    (root / "provider-bundle.json").write_bytes(bundle_bytes)
    review_bytes = _canonical(
        {
            "schema_version": "candidate-review-v1",
            "artifact_status": "REVIEW_ONLY",
            "bundle_path": "provider-bundle.json",
            "redacted_bundle_sha256": _sha(bundle_bytes),
            "candidates": candidates,
        }
    )
    (root / "candidate-review.json").write_bytes(review_bytes)
    (root / "freeze-manifest.json").write_bytes(
        _canonical(
            {
                "bundle_sha256": _sha(bundle_bytes),
                "candidate_count": 6,
                "review_sha256": _sha(review_bytes),
                "status": "FROZEN_PREVIEW",
            }
        )
    )
    return root


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_pipeline_demo_runs_exact_seven_stage_offline_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("ITDA_NO_NETWORK", "1")
    monkeypatch.setenv("TOUR_API_SERVICE_KEY", "must-not-be-read-or-recorded")
    socket_calls = 0

    def forbidden_socket(*args: object, **kwargs: object) -> None:
        nonlocal socket_calls
        socket_calls += 1
        raise AssertionError("pipeline-demo must never create a socket")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 0
    manifest = validate_pipeline_output(output)

    assert socket_calls == 0
    assert tuple(row.stage.value for row in manifest.stages) == PIPELINE_STAGE_ORDER
    assert len(manifest.stages) == 7
    assert len(list((output / "stages").glob("*.json"))) == 7
    for index, row in enumerate(manifest.stages):
        assert row.status.value == (
            "MATERIALIZED" if row.stage.value in MATERIALIZED_STAGES else "NOT_SCORED"
        )
        assert len(row.input_hash) == len(row.output_hash) == 64
        if index == 0:
            assert row.upstream_lineage == ()
            assert row.input_hash == manifest.source_input_hash
        else:
            previous = manifest.stages[index - 1]
            assert len(row.upstream_lineage) == 1
            assert row.upstream_lineage[0].stage is previous.stage
            assert row.upstream_lineage[0].output_hash == previous.output_hash
    all_bytes = b"".join(_tree_bytes(output).values())
    assert b"must-not-be-read-or-recorded" not in all_bytes


def test_pipeline_uses_one_pinned_frozen_snapshot_across_lineage_and_normalize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    replacement = _frozen_source(tmp_path / "replacement")
    replacement_bundle_path = replacement / "provider-bundle.json"
    replacement_review_path = replacement / "candidate-review.json"
    replacement_manifest_path = replacement / "freeze-manifest.json"
    replacement_bundle = json.loads(replacement_bundle_path.read_bytes())
    replacement_review = json.loads(replacement_review_path.read_bytes())
    replacement_source_id = "tour-api-replacement-0"
    replacement_bundle["rows"][0]["source_id"] = replacement_source_id
    replacement_review["candidates"][0]["evidence"][0]["source_id"] = replacement_source_id
    replacement_bundle_bytes = _canonical(replacement_bundle)
    replacement_review["redacted_bundle_sha256"] = _sha(replacement_bundle_bytes)
    replacement_review_bytes = _canonical(replacement_review)
    replacement_bundle_path.write_bytes(replacement_bundle_bytes)
    replacement_review_path.write_bytes(replacement_review_bytes)
    replacement_manifest_path.write_bytes(
        _canonical(
            {
                "bundle_sha256": _sha(replacement_bundle_bytes),
                "candidate_count": 6,
                "review_sha256": _sha(replacement_review_bytes),
                "status": "FROZEN_PREVIEW",
            }
        )
    )

    expected_source_files = [
        {"path": name, "sha256": _sha((frozen / name).read_bytes())}
        for name in pipeline_demo_module._FROZEN_SOURCE_FILES
    ]
    real_read_snapshot = pipeline_demo_module._read_frozen_source_bytes
    displaced = tmp_path / "displaced"
    swapped = False

    def read_then_swap(root: Path) -> dict[str, bytes]:
        nonlocal swapped
        snapshot = real_read_snapshot(root)
        root.rename(displaced)
        replacement.rename(root)
        swapped = True
        return snapshot

    monkeypatch.setattr(
        pipeline_demo_module,
        "_read_frozen_source_bytes",
        read_then_swap,
    )
    output = tmp_path / "output"

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 0
    assert swapped
    collected = json.loads((output / "stages/01-collect.json").read_bytes())
    normalized = json.loads((output / "stages/02-normalize.json").read_bytes())
    assert collected["source_files"] == expected_source_files
    assert normalized["rows"][0]["evidence"][0]["source_id"] == "tour_api-0"
    assert replacement_source_id not in json.dumps(normalized, sort_keys=True)


def test_identical_frozen_input_is_byte_identical_across_output_roots(tmp_path: Path) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    first = tmp_path / "first"
    second = tmp_path / "second"

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(first)]) == 0
    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(second)]) == 0

    assert _tree_bytes(first) == _tree_bytes(second)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "reordered", "broken-lineage", "broken-input", "broken-output"],
)
def test_pipeline_validation_rejects_stage_or_hash_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 0
    manifest_path = output / "stage-manifest.json"
    payload = json.loads(manifest_path.read_text())

    if mutation == "missing":
        payload["stages"].pop(3)
    elif mutation == "duplicate":
        payload["stages"][3] = payload["stages"][2]
    elif mutation == "reordered":
        payload["stages"][2], payload["stages"][3] = (
            payload["stages"][3],
            payload["stages"][2],
        )
    elif mutation == "broken-lineage":
        payload["stages"][4]["upstream_lineage"][0]["output_hash"] = "0" * 64
    elif mutation == "broken-input":
        payload["stages"][4]["input_hash"] = "0" * 64
    else:
        payload["stages"][4]["output_hash"] = "0" * 64
    manifest_path.write_bytes(_canonical(payload))

    with pytest.raises(PipelineValidationError):
        validate_pipeline_output(output)


def test_pipeline_validation_rejects_missing_stage_artifact(tmp_path: Path) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 0
    (output / "stages" / "04-fuse.json").unlink()

    with pytest.raises(PipelineValidationError):
        validate_pipeline_output(output)


@pytest.mark.parametrize("mutation", ["nested-file", "nested-dir", "symlink-file", "symlink-dir"])
def test_pipeline_validation_requires_exact_recursive_regular_file_tree(
    tmp_path: Path,
    mutation: str,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 0
    stages = output / "stages"
    if mutation == "nested-file":
        nested = stages / "nested"
        nested.mkdir()
        (nested / "extra.json").write_text("{}", encoding="utf-8")
    elif mutation == "nested-dir":
        (stages / "empty").mkdir()
    elif mutation == "symlink-file":
        os.symlink(stages / "01-collect.json", stages / "linked.json")
    else:
        os.symlink(tmp_path, stages / "linked-dir", target_is_directory=True)

    with pytest.raises(PipelineValidationError):
        validate_pipeline_output(output)


def test_pipeline_publication_never_replaces_a_racing_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    real_rename = freeze_preview_module._rename_noreplace_at

    def racing_rename(
        source_parent_descriptor: int,
        source_name: str,
        destination_parent_descriptor: int,
        destination_name: str,
    ) -> None:
        os.mkdir(destination_name, dir_fd=destination_parent_descriptor)
        winner_descriptor = os.open(
            f"{destination_name}/winner.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=destination_parent_descriptor,
        )
        try:
            os.write(winner_descriptor, b"concurrent winner")
        finally:
            os.close(winner_descriptor)
        real_rename(
            source_parent_descriptor,
            source_name,
            destination_parent_descriptor,
            destination_name,
        )

    monkeypatch.setattr(freeze_preview_module, "_rename_noreplace_at", racing_rename)

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 1
    assert (output / "winner.txt").read_text(encoding="utf-8") == "concurrent winner"
    assert not (output / "stage-manifest.json").exists()


def test_pipeline_rejects_pre_rename_prepared_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    displaced = tmp_path / "validated-pipeline-output"
    real_rename = freeze_preview_module._rename_noreplace_at

    def replace_prepared_before_rename(
        source_parent_descriptor: int,
        source_name: str,
        destination_parent_descriptor: int,
        destination_name: str,
    ) -> None:
        os.rename(
            source_name,
            displaced.name,
            src_dir_fd=source_parent_descriptor,
            dst_dir_fd=source_parent_descriptor,
        )
        os.mkdir(source_name, dir_fd=source_parent_descriptor)
        winner_descriptor = os.open(
            f"{source_name}/winner.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=source_parent_descriptor,
        )
        try:
            os.write(winner_descriptor, b"unvalidated replacement")
        finally:
            os.close(winner_descriptor)
        real_rename(
            source_parent_descriptor,
            source_name,
            destination_parent_descriptor,
            destination_name,
        )

    monkeypatch.setattr(
        freeze_preview_module,
        "_rename_noreplace_at",
        replace_prepared_before_rename,
    )

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 1
    assert (output / "winner.txt").read_text(encoding="utf-8") == "unvalidated replacement"
    validate_pipeline_output(displaced)


def test_pipeline_publishes_a_direct_directory_and_detects_later_mutation(
    tmp_path: Path,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 0
    assert output.is_dir()
    assert not output.is_symlink()
    assert not (tmp_path / ".output.objects").exists()

    (output / "stages/collect.json").write_text('{"mutated":true}\n', encoding="utf-8")
    with pytest.raises(PipelineValidationError):
        validate_pipeline_output(output)


def test_pipeline_preserves_publication_on_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    real_fsync = freeze_preview_module.os.fsync
    parent_identity = (output.parent.stat().st_dev, output.parent.stat().st_ino)
    failed = False

    def fail_first_post_rename_parent_fsync(descriptor: int) -> None:
        nonlocal failed
        metadata = freeze_preview_module.os.fstat(descriptor)
        if (
            not failed
            and os.path.lexists(output)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        ):
            failed = True
            raise OSError("injected post-rename parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        freeze_preview_module.os,
        "fsync",
        fail_first_post_rename_parent_fsync,
    )

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 1
    assert failed
    assert output.is_dir() and not output.is_symlink()
    validate_pipeline_output(output)
    assert not list(tmp_path.glob(".output-*"))

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 1
    validate_pipeline_output(output)


def test_pipeline_uncertain_publication_never_deletes_racing_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _frozen_source(tmp_path / "frozen")
    output = tmp_path / "output"
    displaced = tmp_path / "published-by-this-run"
    real_rename = freeze_preview_module._rename_noreplace_at
    real_fsync = freeze_preview_module.os.fsync
    staging_name: str | None = None

    def observed_rename(
        source_parent_descriptor: int,
        source_name: str,
        destination_parent_descriptor: int,
        destination_name: str,
    ) -> None:
        nonlocal staging_name
        real_rename(
            source_parent_descriptor,
            source_name,
            destination_parent_descriptor,
            destination_name,
        )
        staging_name = source_name

    def replace_after_identity_check(descriptor: int) -> None:
        if staging_name is not None and output.exists() and not displaced.exists():
            output.rename(displaced)
            output.mkdir()
            (output / "winner.txt").write_text("destination winner", encoding="utf-8")
            racing_staging = tmp_path / staging_name
            racing_staging.mkdir()
            (racing_staging / "winner.txt").write_text("staging winner", encoding="utf-8")
            raise OSError("injected parent fsync failure after replacement")
        real_fsync(descriptor)

    monkeypatch.setattr(freeze_preview_module, "_rename_noreplace_at", observed_rename)
    monkeypatch.setattr(freeze_preview_module.os, "fsync", replace_after_identity_check)

    assert pipeline_demo_main(["--frozen-input", str(frozen), "--output", str(output)]) == 1
    assert (output / "winner.txt").read_text(encoding="utf-8") == "destination winner"
    assert staging_name is not None
    assert (tmp_path / staging_name / "winner.txt").read_text(encoding="utf-8") == "staging winner"
    validate_pipeline_output(displaced)


@pytest.mark.parametrize("entry_kind", ["symlink-file", "symlink-dir", "fifo", "hardlink"])
def test_immutable_publication_rejects_externally_mutable_entries(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    prepared = tmp_path / "prepared"
    prepared.mkdir()
    source = prepared / "source.txt"
    source.write_text("stable", encoding="utf-8")
    unsafe = prepared / "unsafe"
    if entry_kind == "symlink-file":
        unsafe.symlink_to(source)
    elif entry_kind == "symlink-dir":
        unsafe.symlink_to(tmp_path, target_is_directory=True)
    elif entry_kind == "fifo":
        os.mkfifo(unsafe)
    else:
        os.link(source, unsafe)

    # The publication boundary intentionally uses specific diagnostics for
    # each unsafe entry shape; assert the behavioral rejection rather than
    # coupling the test to one wording variant.
    with pytest.raises(ValueError, match="(immutable|durable tree|prepared publication)"):
        freeze_preview_module.publish_immutable_directory(
            prepared=prepared,
            output=tmp_path / "output",
        )
    assert not (tmp_path / "output").exists()


def test_immutable_directory_digest_includes_empty_dirs_and_complete_files(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline"
    with_empty = tmp_path / "with-empty"
    with_complete = tmp_path / "with-complete"
    for root in (baseline, with_empty, with_complete):
        root.mkdir()
        (root / "payload.txt").write_text("same", encoding="utf-8")
    (with_empty / "empty").mkdir()
    (with_complete / ".complete").write_text("marker", encoding="utf-8")

    digests = {
        freeze_preview_module._directory_digest(root)
        for root in (baseline, with_empty, with_complete)
    }
    assert len(digests) == 3


def test_durable_tree_fsyncs_every_file_and_directory_bottom_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "tree"
    nested = root / "nested"
    empty = nested / "empty"
    empty.mkdir(parents=True)
    (root / "root.txt").write_text("root", encoding="utf-8")
    (nested / "nested.txt").write_text("nested", encoding="utf-8")
    real_fsync = os.fsync
    synced_modes: list[int] = []

    def observed_fsync(descriptor: int) -> None:
        synced_modes.append(os.fstat(descriptor).st_mode)
        real_fsync(descriptor)

    monkeypatch.setattr(freeze_preview_module.os, "fsync", observed_fsync)
    freeze_preview_module._fsync_tree(root)

    assert sum(S_ISREG(mode) for mode in synced_modes) == 2
    assert sum(S_ISDIR(mode) for mode in synced_modes) == 3
