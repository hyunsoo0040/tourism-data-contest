"""Exact-once ownership contract for the credential-unset Phase 4 Make gate."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]

OWNERS = {
    "fast": {
        "backend/tests/contract/test_image_observation.py",
        "backend/tests/contract/test_profile_release_authority_v2.py",
        "backend/tests/contract/test_profile_release_v2.py",
        "backend/tests/contract/test_phase4_test_ownership.py",
        "backend/tests/evals/phase4/test_image_preprocessing.py",
        "backend/tests/evals/phase4/test_image_selection.py",
        "backend/tests/evals/phase4/test_phase3_lane_baseline.py",
        "backend/tests/evals/phase4/test_phase4_benchmark.py",
        "backend/tests/evals/phase4/test_phase4_challenge_pack.py",
        "backend/tests/evals/phase4/test_phase4_vertical_slice.py",
        "backend/tests/evals/phase4/test_profile_confidence_and_labels.py",
        "backend/tests/evals/phase4/test_profile_fusion.py",
    },
    "provider-replay": {
        "backend/tests/contract/test_vlm_inference.py",
        "backend/tests/evals/phase4/test_dev_image_observations.py",
        "backend/tests/providers/test_zhipu_glm5v.py",
    },
    "db": {
        "backend/tests/integration/test_phase4_demo_release_sqlite.py",
        "backend/tests/integration/test_profile_release_pin_v2.py",
        "backend/tests/integration/test_profile_release_v2.py",
    },
    "security": {
        "backend/tests/security/test_phase4_artifact_leakage.py",
        "backend/tests/security/test_phase4_capability_boundaries.py",
        "backend/tests/security/test_phase4_dependency_gate.py",
        "backend/tests/security/test_phase4_evaluator_boundary.py",
        "backend/tests/security/test_phase4_image_preprocessing.py",
        "backend/tests/security/test_phase4_image_selection.py",
        "backend/tests/security/test_phase4_observation_authority.py",
        "backend/tests/security/test_phase4_provider_boundary.py",
    },
    "gap-clean": {
        "backend/tests/integration/test_phase4_challenge_repository.py",
        "backend/tests/security/test_phase4_checked_artifact_chain.py",
    },
    "private-evidence": {
        "backend/tests/security/test_phase4_provisioned_chain.py",
        "backend/tests/security/test_phase4_regeneration_commands.py",
        "backend/tests/security/test_phase4_staged_chain.py",
    },
}

OWNER_TARGETS = {
    "fast": "phase-04-check-fast",
    "provider-replay": "phase-04-check-provider-replay",
    "db": "phase-04-check-db",
    "security": "phase-04-check-security",
    "gap-clean": "phase-04-gap-clean-check",
    "private-evidence": "phase-04-private-evidence-check",
}
CANONICAL_OWNERS = frozenset(OWNERS) - {"private-evidence"}


def _phase4_suite_inventory(repository_root: Path = REPOSITORY_ROOT) -> set[str]:
    inventory = {
        path.relative_to(repository_root).as_posix()
        for root in (
            repository_root / "backend/tests/evals/phase4",
            repository_root / "backend/tests/security",
        )
        for path in root.rglob("test_*.py")
        if root.name != "security" or path.name.startswith("test_phase4_")
    }
    inventory.update(
        {
            "backend/tests/contract/test_image_observation.py",
            "backend/tests/contract/test_profile_release_authority_v2.py",
            "backend/tests/contract/test_profile_release_v2.py",
            "backend/tests/contract/test_phase4_test_ownership.py",
            "backend/tests/contract/test_vlm_inference.py",
            "backend/tests/integration/test_phase4_demo_release_sqlite.py",
            "backend/tests/integration/test_phase4_challenge_repository.py",
            "backend/tests/integration/test_profile_release_pin_v2.py",
            "backend/tests/integration/test_profile_release_v2.py",
            "backend/tests/providers/test_zhipu_glm5v.py",
        }
    )
    return inventory


def test_phase4_suite_inventory_recursively_discovers_nested_suites(tmp_path: Path) -> None:
    eval_canary = tmp_path / "backend/tests/evals/phase4/nested/test_canary.py"
    security_canary = tmp_path / "backend/tests/security/nested/test_phase4_canary.py"
    unrelated_security = tmp_path / "backend/tests/security/nested/test_other_phase.py"
    for path in (eval_canary, security_canary, unrelated_security):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    inventory = _phase4_suite_inventory(tmp_path)

    assert eval_canary.relative_to(tmp_path).as_posix() in inventory
    assert security_canary.relative_to(tmp_path).as_posix() in inventory
    assert unrelated_security.relative_to(tmp_path).as_posix() not in inventory


def _dry_run(target: str) -> str:
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", target],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_every_phase4_suite_has_exactly_one_canonical_owner() -> None:
    flattened = [path for paths in OWNERS.values() for path in paths]
    assert len(flattened) == len(set(flattened))
    assert set(flattened) == _phase4_suite_inventory()


def test_make_dry_run_expands_each_owned_suite_exactly_once() -> None:
    aggregate = _dry_run("phase-04-check")
    for owner, paths in OWNERS.items():
        owner_output = _dry_run(OWNER_TARGETS[owner])
        for path in paths:
            assert len(re.findall(rf"(?<!\S){re.escape(path)}(?!\S)", owner_output)) == 1
            expected_in_aggregate = 1 if owner in CANONICAL_OWNERS else 0
            assert (
                len(re.findall(rf"(?<!\S){re.escape(path)}(?!\S)", aggregate))
                == expected_in_aggregate
            )

    assert "uv sync" not in aggregate
    assert "pip install" not in aggregate
    assert "--live" not in aggregate
    python_commands = [line for line in aggregate.splitlines() if "uv run" in line]
    assert python_commands
    for command in python_commands:
        assert "env -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY" in command
        assert "ITDA_OFFLINE=1" in command
        assert "HF_HUB_OFFLINE=1" in command
        assert "TRANSFORMERS_OFFLINE=1" in command
        assert "--frozen --no-sync" in command


def test_aggregate_has_one_ordered_expansion_of_each_canonical_target() -> None:
    aggregate = _dry_run("phase-04-check")
    markers = re.findall(
        r"PHASE04_TARGET=(fast|provider-replay|db|security|gap-clean|private-evidence)",
        aggregate,
    )
    assert markers == ["fast", "provider-replay", "db", "security", "gap-clean"]
    assert aggregate.count("backend/tests/evals/phase4/test_phase4_challenge_pack.py") == 1
    assert "ITDA_PHASE4_PRIVATE_EVIDENCE=1" not in aggregate
    assert "artifacts/restricted" not in aggregate


def test_gap_targets_are_disjoint_and_review_expands_both_once() -> None:
    clean = _dry_run("phase-04-gap-clean-check")
    private = _dry_run("phase-04-private-evidence-check")
    review = _dry_run("phase-04-gap-review")

    assert "test_phase4_challenge_pack.py" not in clean
    assert "test_phase4_challenge_pack.py" not in private
    for path in OWNERS["gap-clean"]:
        assert clean.count(path) == 1
        assert private.count(path) == 0
        assert review.count(path) == 1
    for path in OWNERS["private-evidence"]:
        assert private.count(path) == 1
        assert clean.count(path) == 0
        assert review.count(path) == 1
    assert "ITDA_PHASE4_PRIVATE_EVIDENCE=1" not in clean
    assert "ITDA_PHASE4_PRIVATE_EVIDENCE=1" in private
