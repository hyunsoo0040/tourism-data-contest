"""Read-only regression for the Plan 29-32 PostgreSQL supersession boundary."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PHASE_DIR = (
    REPOSITORY_ROOT
    / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
)
GSD_TOOLS = Path("/Users/penggin/.codex/gsd-core/bin/gsd-tools.cjs")

HISTORY = {
    "29": {
        "sha256": "1dc5d4c970c23dd49d9b52a867b7fb798f8fb89336209fb822007c54b028d29b",
        "blob": "2ec904cc0ae14a9a7da81a6aa2859a8330980b23",
        "successor": "56",
    },
    "30": {
        "sha256": "c0e4d7fd8fe91d4bacd2d1fec71a23e0d2c44b0fc4786649fa632220f327edb6",
        "blob": "b2480b410b485e2063a198162b7f9a2fe08a14be",
        "successor": "57",
    },
    "31": {
        "sha256": "263eb1d0fa992b58779524dcaa51c156b95556cb566710189550f4f9de8706af",
        "blob": "e2102f1b2e9271f4298466e0f23e14782495e5fe",
        "successor": "58",
    },
    "32": {
        "sha256": "174abf5087fb75e276d669a87cc466f2f7094f256bb3719631c9c3e0a48f9a1d",
        "blob": "40a595c1032dfac38d5c39a923aba2bcfdbf3837",
        "successor": "59",
    },
}
PARTIAL_PLAN_29_COMMITS = (
    "faa1f75115c37544475f29e77efbb743d9a0b097",
    "607bb0ea14e0c7b939da407e6813338c5fd62f5d",
    "cf8a63d774de9bd9e03749e4c1ddfe97bc81926a",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_blob(path: Path) -> str:
    payload = path.read_bytes()
    return hashlib.sha1(  # noqa: S324 - Git SHA-1 object identity, not security crypto.
        f"blob {len(payload)}\0".encode("ascii") + payload
    ).hexdigest()


def _assert_history_fixture(phase_dir: Path) -> None:
    for plan_id, expected in HISTORY.items():
        executable = phase_dir / f"02-{plan_id}-PLAN.md"
        summary = phase_dir / f"02-{plan_id}-SUMMARY.md"
        history = phase_dir / f"02-{plan_id}-POSTGRESQL-HISTORY.md"
        pointer = phase_dir / f"02-{plan_id}-SUPERSEDED.md"
        assert not executable.exists()
        assert not summary.exists()
        assert _sha256(history) == expected["sha256"]
        assert _git_blob(history) == expected["blob"]
        pointer_text = pointer.read_text(encoding="utf-8")
        required = (
            f"02-{plan_id}-PLAN.md",
            f"02-{plan_id}-POSTGRESQL-HISTORY.md",
            expected["sha256"],
            expected["blob"],
            f"02-{expected['successor']}-PLAN.md",
            "Summary exists",
            "`false`",
            "Reason:",
        )
        assert all(value in pointer_text for value in required)


def _query_gsd(*arguments: str) -> dict[str, object]:
    completed = subprocess.run(
        ["node", str(GSD_TOOLS), "query", *arguments],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def _assert_discovery(init_payload: dict[str, object], index_payload: dict[str, object]) -> None:
    plans = init_payload.get("plans")
    assert isinstance(plans, list)
    assert not {
        "02-29-PLAN.md",
        "02-30-PLAN.md",
        "02-31-PLAN.md",
        "02-32-PLAN.md",
    }.intersection(plans)
    waves = index_payload.get("waves")
    assert isinstance(waves, dict)
    assert waves.get("38") == ["02-56"]


def test_live_postgresql_history_is_exact_summary_free_and_non_executable() -> None:
    _assert_history_fixture(PHASE_DIR)
    for commit in PARTIAL_PLAN_29_COMMITS:
        subprocess.run(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        )
    _assert_discovery(
        _query_gsd("init.execute-phase", "02"),
        _query_gsd("phase-plan-index", "02"),
    )


def test_hostile_history_and_pointer_copies_fail_without_touching_planning(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "phase"
    fixture.mkdir()
    for plan_id in HISTORY:
        for suffix in ("POSTGRESQL-HISTORY.md", "SUPERSEDED.md"):
            shutil.copyfile(
                PHASE_DIR / f"02-{plan_id}-{suffix}",
                fixture / f"02-{plan_id}-{suffix}",
            )
    _assert_history_fixture(fixture)

    history = fixture / "02-29-POSTGRESQL-HISTORY.md"
    history.write_bytes(history.read_bytes() + b"\n")
    with pytest.raises(AssertionError):
        _assert_history_fixture(fixture)

    shutil.copyfile(PHASE_DIR / history.name, history)
    pointer = fixture / "02-30-SUPERSEDED.md"
    pointer.write_text(
        pointer.read_text(encoding="utf-8").replace("02-57-PLAN.md", "02-58-PLAN.md"),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError):
        _assert_history_fixture(fixture)


def test_hostile_discovery_payloads_cannot_reactivate_history_or_share_wave_38() -> None:
    init_payload = {"plans": ["02-56-PLAN.md"]}
    index_payload = {"waves": {"38": ["02-56"]}}
    _assert_discovery(init_payload, index_payload)

    with pytest.raises(AssertionError):
        _assert_discovery(
            {"plans": ["02-29-PLAN.md", "02-56-PLAN.md"]},
            index_payload,
        )
    with pytest.raises(AssertionError):
        _assert_discovery(init_payload, {"waves": {"38": ["02-56", "02-57"]}})
