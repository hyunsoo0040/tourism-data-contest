"""Offline DAG reproducibility and Phase 4 public-artifact leakage gates."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from itda.cli.phase4_artifact_dag import (
    DAG_STAGE_ORDER,
    ArtifactLeakageError,
    assert_public_artifact_safe,
    run_stage,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DVC_YAML = REPOSITORY_ROOT / "dvc.yaml"
DVC_LOCK = REPOSITORY_ROOT / "dvc.lock"
PARAMS = REPOSITORY_ROOT / "params.yaml"
CHALLENGE_PACK = REPOSITORY_ROOT / "fixtures/synthetic/phase4/challenge-pack.json"
DAG_SEED = REPOSITORY_ROOT / "fixtures/synthetic/phase4/dag-seed.json"
PROVIDER_REPLAY = REPOSITORY_ROOT / "fixtures/synthetic/phase4/provider-replay.json"
GENERATED_ROOT = REPOSITORY_ROOT / "artifacts/synthetic/phase4"
PUBLIC_ARTIFACT_ROOT = REPOSITORY_ROOT / "artifacts/public"
PHASE_DIR = REPOSITORY_ROOT / ".planning/phases/04-dev-24-image-benchmark-and-multimodal-fusion"


def _load_yaml(path: Path) -> dict[str, object]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_dvc_declares_exact_offline_stage_order_and_immutable_inputs() -> None:
    payload = _load_yaml(DVC_YAML)
    stages = payload["stages"]
    assert isinstance(stages, dict)
    assert tuple(stages) == DAG_STAGE_ORDER == ("select", "observe", "evaluate", "fuse", "export")

    outputs: set[str] = set()
    for stage_name, raw_stage in stages.items():
        assert isinstance(raw_stage, dict)
        command = str(raw_stage["cmd"])
        assert "env -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY" in command
        assert "ITDA_OFFLINE=1" in command
        assert "HF_HUB_OFFLINE=1" in command
        assert "TRANSFORMERS_OFFLINE=1" in command
        assert "mise exec -- uv run --project backend --frozen --no-sync" in command
        assert "--live" not in command
        assert "phase4_artifact_dag" in command
        assert f"--stage {stage_name}" in command
        assert isinstance(raw_stage["deps"], list) and raw_stage["deps"]
        assert raw_stage["params"] == ["phase4"]
        assert isinstance(raw_stage["outs"], list) and len(raw_stage["outs"]) == 1
        outputs.update(str(item) for item in raw_stage["outs"])

    assert outputs == {
        "artifacts/synthetic/phase4/selection.json",
        "artifacts/synthetic/phase4/observations.json",
        "artifacts/synthetic/phase4/benchmark.json",
        "artifacts/synthetic/phase4/fusion.json",
        "artifacts/synthetic/phase4/export.json",
    }
    assert "backend/src/itda/cli/evaluate_phase4.py" in stages["evaluate"]["deps"]
    assert DVC_LOCK.is_file()


def test_stage_replay_is_byte_identical_and_config_mutation_changes_downstream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    changed = tmp_path / "changed.json"
    params = _load_yaml(PARAMS)["phase4"]
    assert isinstance(params, dict)

    run_stage(
        stage="select",
        inputs=(CHALLENGE_PACK, DAG_SEED),
        params=params,
        output=first,
    )
    run_stage(
        stage="select",
        inputs=(CHALLENGE_PACK, DAG_SEED),
        params=params,
        output=second,
    )
    assert first.read_bytes() == second.read_bytes()

    mutated = dict(params)
    mutated["config_revision"] = "phase4-synthetic-dag-v2"
    run_stage(
        stage="select",
        inputs=(CHALLENGE_PACK, DAG_SEED),
        params=mutated,
        output=changed,
    )
    assert canonical_sha256(json.loads(first.read_bytes())) != canonical_sha256(
        json.loads(changed.read_bytes())
    )


def test_dag_runner_is_no_replace_and_has_no_release_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    output = tmp_path / "stage.json"
    params = _load_yaml(PARAMS)["phase4"]
    assert isinstance(params, dict)
    run_stage(
        stage="select",
        inputs=(CHALLENGE_PACK, DAG_SEED),
        params=params,
        output=output,
    )
    with pytest.raises(FileExistsError):
        run_stage(
            stage="select",
            inputs=(CHALLENGE_PACK, DAG_SEED),
            params=params,
            output=output,
        )
    for forbidden in ("approve", "activate", "rollback", "pin", "release"):
        with pytest.raises(ValueError, match="offline artifact stage"):
            run_stage(
                stage=forbidden,
                inputs=(CHALLENGE_PACK,),
                params=params,
                output=tmp_path / f"{forbidden}.json",
            )


def test_downstream_stages_require_exact_predecessors_and_never_claim_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    params = _load_yaml(PARAMS)["phase4"]
    assert isinstance(params, dict)
    selection = tmp_path / "selection.json"
    observations = tmp_path / "observations.json"
    benchmark = tmp_path / "benchmark.json"
    fusion = tmp_path / "fusion.json"
    export = tmp_path / "export.json"

    run_stage(
        stage="select",
        inputs=(CHALLENGE_PACK, DAG_SEED),
        params=params,
        output=selection,
    )
    run_stage(
        stage="observe",
        inputs=(CHALLENGE_PACK, DAG_SEED, PROVIDER_REPLAY, selection),
        params=params,
        output=observations,
    )
    evaluated = run_stage(
        stage="evaluate",
        inputs=(CHALLENGE_PACK, DAG_SEED, observations, PROVIDER_REPLAY, selection),
        params=params,
        output=benchmark,
    )
    fused = run_stage(
        stage="fuse",
        inputs=(benchmark, CHALLENGE_PACK, DAG_SEED, observations, PROVIDER_REPLAY, selection),
        params=params,
        output=fusion,
    )
    exported = run_stage(
        stage="export",
        inputs=(
            benchmark,
            CHALLENGE_PACK,
            DAG_SEED,
            fusion,
            observations,
            PROVIDER_REPLAY,
            selection,
        ),
        params=params,
        output=export,
    )

    assert evaluated["details"]["report_state"] == "NOT_EXECUTED_NO_BENCHMARK_AUTHORITY"
    assert fused["details"]["fusion_state"] == "NOT_EXECUTED_NO_PHASE3_LANE_BASELINE"
    assert exported["details"]["export_state"] == "LINEAGE_VALIDATED_NOT_A_RELEASE_EXPORT"

    with pytest.raises(ValueError, match="input inventory"):
        run_stage(
            stage="fuse",
            inputs=(DAG_SEED,),
            params=params,
            output=tmp_path / "missing-parent.json",
        )

    wrong_parent = tmp_path / "benchmark.json"
    wrong_parent.write_bytes(selection.read_bytes())
    with pytest.raises(ValueError, match="predecessor"):
        run_stage(
            stage="fuse",
            inputs=(
                wrong_parent,
                CHALLENGE_PACK,
                DAG_SEED,
                observations,
                PROVIDER_REPLAY,
                selection,
            ),
            params=params,
            output=tmp_path / "wrong-parent.json",
        )

    fabricated_fields = {
        "artifact_schema_version": "itda.phase4-dag-artifact.v1",
        "authority": "REPRODUCIBILITY_ONLY",
        "details": {"fabricated": True},
        "input_digests": [],
        "offline": True,
        "params_sha256": canonical_sha256(dict(sorted(params.items()))),
        "release_eligible": False,
        "stage": "evaluate",
    }
    fabricated = {
        **fabricated_fields,
        "artifact_sha256": canonical_sha256(fabricated_fields),
    }
    fabricated_parent = tmp_path / "fabricated" / "benchmark.json"
    fabricated_parent.parent.mkdir()
    fabricated_parent.write_bytes(canonical_json_bytes(fabricated))
    with pytest.raises(ValueError, match="predecessor details"):
        run_stage(
            stage="fuse",
            inputs=(
                fabricated_parent,
                CHALLENGE_PACK,
                DAG_SEED,
                observations,
                PROVIDER_REPLAY,
                selection,
            ),
            params=params,
            output=tmp_path / "fabricated-fusion.json",
        )


def test_shape_correct_resealed_parent_cannot_fabricate_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    params = _load_yaml(PARAMS)["phase4"]
    assert isinstance(params, dict)
    selection = tmp_path / "selection.json"
    run_stage(
        stage="select",
        inputs=(CHALLENGE_PACK, DAG_SEED),
        params=params,
        output=selection,
    )
    hostile = json.loads(selection.read_bytes())
    hostile["details"] = {
        "case_count": 999,
        "scenario_inventory_sha256": "0" * 64,
        "selection_state": "SYNTHETIC_SELECTION_FROZEN",
    }
    hostile["input_digests"] = [
        {"input_id": "challenge-pack.json", "sha256": "1" * 64},
        {"input_id": "dag-seed.json", "sha256": "2" * 64},
    ]
    hostile["artifact_sha256"] = canonical_sha256(
        {key: value for key, value in hostile.items() if key != "artifact_sha256"}
    )
    selection.write_bytes(canonical_json_bytes(hostile))

    with pytest.raises(ValueError, match="typed stage result|input inventory"):
        run_stage(
            stage="observe",
            inputs=(CHALLENGE_PACK, DAG_SEED, PROVIDER_REPLAY, selection),
            params=params,
            output=tmp_path / "hostile-observations.json",
        )


def test_dag_runner_rejects_missing_offline_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    params = _load_yaml(PARAMS)["phase4"]
    assert isinstance(params, dict)

    with pytest.raises(ValueError, match="ITDA_OFFLINE=1"):
        run_stage(
            stage="select",
            inputs=(CHALLENGE_PACK, DAG_SEED),
            params=params,
            output=tmp_path / "stage.json",
        )


def test_recursive_public_surface_scan_is_clean_and_detects_canaries() -> None:
    scan_paths = [DVC_YAML, DVC_LOCK, PARAMS, CHALLENGE_PACK, DAG_SEED]
    scan_paths.extend(sorted((REPOSITORY_ROOT / "fixtures/synthetic/phase4").glob("*.json")))
    if GENERATED_ROOT.exists():
        scan_paths.extend(sorted(GENERATED_ROOT.rglob("*")))
    scan_paths.extend(sorted(PHASE_DIR.glob("04-*-SUMMARY.md")))
    scan_paths.append(PHASE_DIR / "04-TOOLING-MATERIALIZATION-RECEIPT.json")
    if PUBLIC_ARTIFACT_ROOT.exists():
        scan_paths.extend(sorted(PUBLIC_ARTIFACT_ROOT.rglob("*")))

    for path in scan_paths:
        if path.is_file():
            assert_public_artifact_safe(path, path.read_bytes())

    canaries = (
        {"service_key": "synthetic-secret-value"},
        {"raw_image_bytes": "c3ludGhldGljLWJ5dGVz"},
        {"dev_label_scores": {"H1": 1000}},
        {"blind_members": ["synthetic-member-1"]},
        {"reconciliation_nonce": "synthetic-nonce"},
        {"relative_path": "/artifacts/restricted/phase4/image.jpg"},
    )
    for canary in canaries:
        with pytest.raises(ArtifactLeakageError):
            assert_public_artifact_safe(
                Path("synthetic-canary.json"),
                canonical_json_bytes(canary),
            )


def test_dvc_metadata_has_no_network_remote_or_lifecycle_command() -> None:
    metadata = DVC_YAML.read_text(encoding="utf-8") + DVC_LOCK.read_text(encoding="utf-8")
    assert not re.search(r"https?://|s3://|gs://|ssh://", metadata)
    assert "remote" not in metadata.casefold()
    for forbidden in (
        "manage_profile_release",
        "activate_profile_release",
        "rollback_profile_release",
        "approve_profile_release",
    ):
        assert forbidden not in metadata
