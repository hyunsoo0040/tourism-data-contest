"""Verify bounded Phase 5 clean/private GREEN receipts without following links."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from itda.domain.canonical import canonical_json_bytes


class Phase5GateReceiptError(ValueError):
    """Public-safe gate rejection with no receipt body or protected path."""


_SHA256_CHARS = frozenset("0123456789abcdef")
_TASK_IDS = ("05-11-01", "05-11-02")
_PHASE5_SUITE_REGISTRY_SCHEMA = "itda.phase5-suite-registry.v4"
_PHASE5_SUITE_COMMAND_SET_SCHEMA = "itda.phase5-suite-command-set.v4"
_PHASE5_SUITE_OWNER_SCHEMA = "itda.phase5-suite-owner.v4"

# This registry is deliberately a suite-owned identity, not a task ledger. Keep its
# item shape, digest preimage, and receipt projection disjoint from the 47 ordered
# PHASE5_CURRENT_TASK_IDS_V8 rows below.
_PHASE5_SUITE_ROWS: tuple[tuple[str, str, str, str | None], ...] = (
    (
        "backend/tests/api/test_recommendations.py",
        "phase5-recommendation-api-list",
        "backend-main",
        None,
    ),
    (
        "backend/tests/contract/test_demo_profile_materialization.py",
        "phase5-profile-materialization-contract",
        "backend-main",
        None,
    ),
    (
        "backend/tests/contract/test_nvidia_attempt5_retaining_authority.py",
        "phase5-nvidia-history",
        "backend-main",
        None,
    ),
    (
        "backend/tests/contract/test_nvidia_minimax_profile.py",
        "phase5-nvidia-profile",
        "backend-main",
        None,
    ),
    (
        "backend/tests/contract/test_openapi_contract.py",
        "phase5-generated-contract",
        "generated-contract",
        None,
    ),
    (
        "backend/tests/contract/test_phase5_fresh_cohort_authority.py",
        "phase5-fresh-cohort",
        "backend-main",
        None,
    ),
    ("backend/tests/contract/test_phase5_fresh_live.py", "phase5-fresh-live", "backend-main", None),
    (
        "backend/tests/contract/test_phase5_gate_receipts.py",
        "phase5-gate-receipts",
        "ownership",
        None,
    ),
    (
        "backend/tests/contract/test_place_profile.py",
        "phase5-profile-materialization-contract",
        "backend-main",
        None,
    ),
    (
        "backend/tests/contract/test_recommendation_contract.py",
        "phase5-recommendation-contract",
        "backend-main",
        None,
    ),
    (
        "backend/tests/domain/test_demo_profile_eligibility.py",
        "phase5-profile-materialization-contract",
        "backend-main",
        None,
    ),
    (
        "backend/tests/evals/phase4/test_phase4_vertical_slice.py",
        "phase5-profile-materialization-contract",
        "backend-main",
        None,
    ),
    (
        "backend/tests/evals/phase5/test_recommendation_replay.py",
        "phase5-recommendation-replay",
        "backend-main",
        None,
    ),
    (
        "backend/tests/integration/test_demo_scored_release.py",
        "phase5-release-authority",
        "backend-main",
        None,
    ),
    ("backend/tests/integration/test_e2e_runtime.py", "phase5-e2e-runtime", "e2e-runtime", None),
    ("backend/tests/integration/test_migrations.py", "phase5-migrations", "backend-main", None),
    (
        "backend/tests/integration/test_phase5_demo_source_collection.py",
        "phase5-source-collection",
        "backend-main",
        None,
    ),
    (
        "backend/tests/integration/test_recommendation_runs.py",
        "phase5-recommendation-api-list",
        "backend-main",
        None,
    ),
    (
        "backend/tests/pipeline/test_catalog_optional_media.py",
        "phase5-catalog-pipeline",
        "backend-main",
        None,
    ),
    (
        "backend/tests/pipeline/test_real_split_determinism.py",
        "phase5-catalog-pipeline",
        "backend-main",
        None,
    ),
    (
        "backend/tests/security/test_phase4_observation_authority.py",
        "phase5-observation-authority",
        "backend-main",
        None,
    ),
    (
        "backend/tests/security/test_phase5_provider_boundary.py",
        "phase5-provider-boundary",
        "backend-main",
        None,
    ),
    (
        "backend/tests/security/test_phase5_release_authority.py",
        "phase5-release-authority",
        "backend-main",
        None,
    ),
    (
        "backend/tests/security/test_phase5_release_security.py",
        "phase5-release-security",
        "backend-main",
        None,
    ),
    (
        "backend/tests/unit/test_recommendation_binding_invariants.py",
        "phase5-recommendation-kernel-binding",
        "backend-main",
        None,
    ),
    (
        "backend/tests/unit/test_recommendation_kernel.py",
        "phase5-recommendation-kernel",
        "backend-main",
        None,
    ),
    (
        "backend/tests/unit/test_recommendation_projection.py",
        "phase5-recommendation-api-list",
        "backend-main",
        None,
    ),
    ("web/src/app/storage.test.ts", "phase5-storage", "web-components", None),
    (
        "web/src/features/recommendations/RecommendationCompare.test.tsx",
        "phase5-compare",
        "web-components",
        None,
    ),
    (
        "web/src/features/recommendations/RecommendationDetail.test.tsx",
        "phase5-detail",
        "web-components",
        None,
    ),
    (
        "web/src/features/recommendations/RecommendationRecovery.test.tsx",
        "phase5-recovery",
        "web-components",
        None,
    ),
    (
        "web/src/features/recommendations/RecommendationResults.test.tsx",
        "phase5-results",
        "web-components",
        None,
    ),
    (
        "web/src/features/recommendations/RecommendationSavedPlace.test.tsx",
        "phase5-saved-place",
        "web-components",
        None,
    ),
    ("web/e2e/no-photo-recommendation.spec.ts", "phase5-clean-browser", "clean-browser", None),
    (
        "backend/tests/contract/test_phase5_nvidia_recovery.py",
        "phase5-nvidia-recovery",
        "backend-main",
        None,
    ),
    ("backend/tests/contract/test_phase5_fresh24.py", "phase5-fresh24", "backend-main", None),
    (
        "backend/tests/contract/test_phase5_openrouter_recovery.py",
        "phase5-openrouter-recovery",
        "backend-main",
        None,
    ),
)
PHASE5_SUITE_REGISTRY_V4: Final[tuple[dict[str, str | None], ...]] = tuple(
    {
        "path": path,
        "owner": owner,
        "command_family": command_family,
        "pending_owner": pending_owner,
    }
    for path, owner, command_family, pending_owner in _PHASE5_SUITE_ROWS
)

# The failed 05-36 pre-RESERVE history and consumed 05-27 designed-negative history
# are immutable non-authority. Their rows are deliberately absent from the successful
# current ledger and remain checked by disjoint history validators.
_PHASE5_CURRENT_TASK_ROWS: tuple[str, ...] = (
    "05-18-01",
    "05-18-02",
    "05-19-01",
    "05-19-02",
    "05-20-01",
    "05-20-02",
    "05-21-01",
    "05-21-02",
    "05-22-01",
    "05-22-02",
    "05-23-01",
    "05-23-02",
    "05-34-01",
    "05-34-02",
    "05-24-01",
    "05-24-02",
    "05-24-03",
    "05-25-01",
    "05-25-02",
    "05-25-03",
    "05-26-01",
    "05-26-02",
    "05-26-03",
    "05-35-01",
    "05-35-02",
    "05-35-03",
    "05-37-01",
    "05-37-02",
    "05-38-01",
    "05-38-02",
    "05-39-01",
    "05-39-02",
    "05-40-01",
    "05-40-02",
    "05-40-03",
    "05-28-01",
    "05-28-02",
    "05-29-01",
    "05-29-02",
    "05-30-01",
    "05-30-02",
    "05-31-01",
    "05-31-02",
    "05-32-01",
    "05-32-02",
    "05-33-01",
    "05-33-02",
    "05-17-01",
    "05-17-02",
)
PHASE5_CURRENT_TASK_IDS_V8: Final[tuple[str, ...]] = _PHASE5_CURRENT_TASK_ROWS
PHASE5_FAILED_HISTORY_TASK_IDS: Final[tuple[str, ...]] = (
    "05-36-01",
    "05-36-02",
    "05-36-03",
)
PHASE5_HALTED_HISTORY_TASK_IDS: Final[tuple[str, ...]] = ("05-27-01", "05-27-02")
_CURRENT_GAP_TASK_IDS: Final[tuple[str, ...]] = tuple(
    f"05-{plan:02d}-{task:02d}" for plan in range(12, 18) for task in range(1, 3)
)
_CURRENT_TASK_FORMULA: Final[tuple[int, ...]] = (12, 2, 3, 3, 3, 3, 2, 2, 2, 3, 12, 2)
_GSD_PHASE5_TASK_IDS: Final[tuple[str, ...]] = PHASE5_CURRENT_TASK_IDS_V8


def _all_current_task_rows_present(payload: str) -> bool:
    return all(f"| {task_id} |" in payload for task_id in _CURRENT_GAP_TASK_IDS)


def _validation_current_task_ids(payload: str) -> tuple[str, ...]:
    rows = [
        task_id
        for line in payload.splitlines()
        for task_id in _GSD_PHASE5_TASK_IDS
        if f"| {task_id} |" in line
    ]
    return tuple(rows)


def _require_full_current_task_ledger(payload: str) -> None:
    if _all_current_task_rows_present(payload):
        return
    # Historical fixture payloads predate the additive 05-23 ledger. They remain
    # valid input for stale-baseline normalization, while a fully current ledger
    # is required before final signoff and receipt emission.
    if _validation_current_task_ids(payload):
        raise Phase5GateReceiptError("VALIDATION_LEDGER_AMBIGUOUS")


def _validate_current_task_ledger_ids(task_ids: Sequence[str]) -> tuple[str, ...]:
    if tuple(task_ids) != _GSD_PHASE5_TASK_IDS or len(task_ids) != sum(_CURRENT_TASK_FORMULA):
        raise Phase5GateReceiptError("PHASE5_TASK_LEDGER_INVALID")
    if len(set(task_ids)) != 49:
        raise Phase5GateReceiptError("PHASE5_TASK_LEDGER_IDENTITY_INVALID")
    return tuple(task_ids)


def _history_rows(payload: str, task_ids: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        task_id for line in payload.splitlines() for task_id in task_ids if f"| {task_id} |" in line
    )


def _history_row_has_status(payload: str, task_id: str, status: str) -> bool:
    return any(f"| {task_id} |" in line and status in line for line in payload.splitlines())


def validate_phase5_failed_history_rows(payload: str) -> tuple[str, ...]:
    """Require failed 05-36 rows outside current authority and keep them failed."""

    found = _history_rows(payload, PHASE5_FAILED_HISTORY_TASK_IDS)
    if found != PHASE5_FAILED_HISTORY_TASK_IDS:
        raise Phase5GateReceiptError("PHASE5_FAILED_HISTORY_ROWS_MISSING")
    if any(
        not _history_row_has_status(payload, task_id, "failed history")
        for task_id in PHASE5_FAILED_HISTORY_TASK_IDS
    ):
        raise Phase5GateReceiptError("PHASE5_FAILED_HISTORY_STATUS_INVALID")
    if set(PHASE5_FAILED_HISTORY_TASK_IDS) & set(PHASE5_CURRENT_TASK_IDS_V8):
        raise Phase5GateReceiptError("PHASE5_FAILED_HISTORY_PROMOTED")
    return found


def validate_phase5_halted_history_rows(payload: str) -> tuple[str, ...]:
    """Require the consumed 05-27 halt evidence rows outside the current ledger."""

    found = _history_rows(payload, PHASE5_HALTED_HISTORY_TASK_IDS)
    if found != PHASE5_HALTED_HISTORY_TASK_IDS:
        raise Phase5GateReceiptError("PHASE5_HALTED_HISTORY_ROWS_MISSING")
    if any(
        not _history_row_has_status(payload, task_id, "halted historical")
        for task_id in PHASE5_HALTED_HISTORY_TASK_IDS
    ):
        raise Phase5GateReceiptError("PHASE5_HALTED_HISTORY_STATUS_INVALID")
    if set(PHASE5_HALTED_HISTORY_TASK_IDS) & set(PHASE5_CURRENT_TASK_IDS_V8):
        raise Phase5GateReceiptError("PHASE5_HALTED_HISTORY_PROMOTED")
    return found


def validate_phase5_current_task_ids(
    task_ids: Sequence[str] = PHASE5_CURRENT_TASK_IDS_V8,
) -> tuple[str, ...]:
    if tuple(task_ids) != PHASE5_CURRENT_TASK_IDS_V8:
        raise Phase5GateReceiptError("PHASE5_TASK_LEDGER_INVALID")
    return _validate_current_task_ledger_ids(task_ids)


def validate_phase5_current_task_ledger(payload: str) -> tuple[str, ...]:
    parsed = _validation_current_task_ids(payload)
    if parsed != PHASE5_CURRENT_TASK_IDS_V8:
        raise Phase5GateReceiptError("PHASE5_TASK_LEDGER_INVALID")
    result = _validate_current_task_ledger_ids(parsed)
    validate_phase5_failed_history_rows(payload)
    validate_phase5_halted_history_rows(payload)
    return result


PHASE5_CURRENT_TASK_LEDGER_SHA256: Final[str] = hashlib.sha256(
    canonical_json_bytes(
        {
            "schema_version": "itda.phase5-current-task-ledger.v8",
            "task_ids": list(PHASE5_CURRENT_TASK_IDS_V8),
        }
    )
).hexdigest()


def _suite_registry_digest(rows: Sequence[Mapping[str, str | None]]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": _PHASE5_SUITE_OWNER_SCHEMA,
                "rows": [dict(row) for row in rows],
            }
        )
    ).hexdigest()


def _suite_command_set_digest(rows: Sequence[Mapping[str, str | None]]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": _PHASE5_SUITE_COMMAND_SET_SCHEMA,
                "rows": [
                    {
                        "path": row["path"],
                        "owner": row["owner"],
                        "command_family": row["command_family"],
                    }
                    for row in rows
                    if row["pending_owner"] is None
                ],
            }
        )
    ).hexdigest()


PHASE5_SUITE_REGISTRY_SHA256: Final[str] = _suite_registry_digest(PHASE5_SUITE_REGISTRY_V4)
PHASE5_SUITE_COMMAND_SET_SHA256: Final[str] = _suite_command_set_digest(PHASE5_SUITE_REGISTRY_V4)


def _suite_path_is_present(repository_root: Path, path: str) -> bool:
    return (repository_root / path).is_file()


def validate_phase5_suite_registry(
    rows: Sequence[Mapping[str, str | None]] = PHASE5_SUITE_REGISTRY_V4,
    *,
    repository_root: Path | None = None,
) -> dict[str, object]:
    if len(rows) != 37:
        raise Phase5GateReceiptError("SUITE_REGISTRY_TOTAL_INVALID")
    paths = [row.get("path") for row in rows]
    if any(not isinstance(path, str) or not path for path in paths):
        raise Phase5GateReceiptError("SUITE_REGISTRY_PATH_INVALID")
    if len(set(paths)) != len(paths):
        raise Phase5GateReceiptError("SUITE_REGISTRY_DUPLICATE_PATH")
    required_keys = {"path", "owner", "command_family", "pending_owner"}
    for row in rows:
        if (
            set(row) != required_keys
            or not isinstance(row["owner"], str)
            or not isinstance(row["command_family"], str)
        ):
            raise Phase5GateReceiptError("SUITE_REGISTRY_SCHEMA_INVALID")
        if row["pending_owner"] is not None and not isinstance(row["pending_owner"], str):
            raise Phase5GateReceiptError("SUITE_REGISTRY_PENDING_INVALID")
    if sum(row["pending_owner"] is not None for row in rows) > 1:
        raise Phase5GateReceiptError("SUITE_REGISTRY_PENDING_TOTAL_INVALID")
    if sum(row["path"] == "backend/tests/contract/test_openapi_contract.py" for row in rows) != 1:
        raise Phase5GateReceiptError("SUITE_REGISTRY_OPENAPI_OWNER_INVALID")
    if sum(row["path"] == "backend/tests/integration/test_e2e_runtime.py" for row in rows) != 1:
        raise Phase5GateReceiptError("SUITE_REGISTRY_E2E_OWNER_INVALID")
    if tuple(dict(row) for row in rows) != PHASE5_SUITE_REGISTRY_V4:
        raise Phase5GateReceiptError("SUITE_REGISTRY_LITERAL_DRIFT")
    root = repository_root or Path(__file__).resolve().parents[4]
    active_rows = [
        row
        for row in rows
        if row["pending_owner"] is None or _suite_path_is_present(root, str(row["path"]))
    ]
    pending_rows = [
        row
        for row in rows
        if row["pending_owner"] is not None and not _suite_path_is_present(root, str(row["path"]))
    ]
    if any(
        row["pending_owner"] is None and not _suite_path_is_present(root, str(row["path"]))
        for row in rows
    ):
        raise Phase5GateReceiptError("SUITE_REGISTRY_PRESENT_PATH_MISSING")
    if any(
        row["pending_owner"] is not None and _suite_path_is_present(root, str(row["path"]))
        for row in rows
    ):
        raise Phase5GateReceiptError("SUITE_REGISTRY_PENDING_PATH_EARLY")
    if len(active_rows) + len(pending_rows) != 37 or len(active_rows) < 36:
        raise Phase5GateReceiptError("SUITE_REGISTRY_WAVE_STATE_INVALID")
    return {
        "schema_version": _PHASE5_SUITE_REGISTRY_SCHEMA,
        "registry_sha256": _suite_registry_digest(rows),
        "command_set_sha256": _suite_command_set_digest(rows),
        "registry_total": len(rows),
        "active_present": len(active_rows),
        "pending": len(pending_rows),
        "active_rows": tuple(row["path"] for row in active_rows),
    }


def _is_phase5_suite_candidate(path: Path, relative: str) -> bool:
    name = path.name
    if (
        relative == "web/src/app/storage.test.ts"
        or relative == "web/e2e/no-photo-recommendation.spec.ts"
    ):
        return True
    if relative.startswith("web/src/features/recommendations/"):
        return name.endswith(".test.tsx")
    if not relative.startswith("backend/tests/") or path.suffix != ".py":
        return False
    if relative.startswith("backend/tests/contract/"):
        return (
            name.startswith("test_phase5_")
            or name.startswith("test_nvidia_")
            or name
            in {
                "test_demo_profile_materialization.py",
                "test_openapi_contract.py",
                "test_place_profile.py",
                "test_recommendation_contract.py",
            }
        )
    if relative.startswith("backend/tests/api/"):
        return name == "test_recommendations.py"
    if relative.startswith("backend/tests/domain/"):
        return name == "test_demo_profile_eligibility.py"
    if relative.startswith("backend/tests/evals/phase4/"):
        return name == "test_phase4_vertical_slice.py"
    if relative.startswith("backend/tests/evals/phase5/"):
        return name == "test_recommendation_replay.py"
    if relative.startswith("backend/tests/integration/"):
        return name in {
            "test_demo_scored_release.py",
            "test_e2e_runtime.py",
            "test_migrations.py",
            "test_phase5_demo_source_collection.py",
            "test_recommendation_runs.py",
        } or name.startswith("test_phase5_")
    if relative.startswith("backend/tests/pipeline/"):
        return name in {"test_catalog_optional_media.py", "test_real_split_determinism.py"}
    if relative.startswith("backend/tests/security/"):
        return name in {
            "test_phase4_observation_authority.py",
            "test_phase5_provider_boundary.py",
            "test_phase5_release_authority.py",
            "test_phase5_release_security.py",
        } or name.startswith("test_phase5_")
    if relative.startswith("backend/tests/unit/"):
        return name in {
            "test_recommendation_binding_invariants.py",
            "test_recommendation_kernel.py",
            "test_recommendation_projection.py",
        }
    return False


def phase5_suite_inventory(repository_root: Path) -> dict[str, tuple[str, ...]]:
    report = validate_phase5_suite_registry(repository_root=repository_root)
    registered = tuple(str(path) for path in report["active_rows"])
    discovered_candidates = tuple(
        sorted(
            relative
            for root in (
                repository_root / "backend/tests",
                repository_root / "web/src/features/recommendations",
                repository_root / "web/src/app",
                repository_root / "web/e2e",
            )
            if root.exists()
            for path in root.rglob("*")
            if path.is_file()
            for relative in (path.relative_to(repository_root).as_posix(),)
            if _is_phase5_suite_candidate(path, relative)
        )
    )
    discovered = tuple(sorted(path for path in discovered_candidates if path in registered))
    if discovered != tuple(sorted(registered)):
        raise Phase5GateReceiptError("SUITE_DISCOVERED_REGISTERED_MISMATCH")
    unregistered = tuple(path for path in discovered_candidates if path not in registered)
    if unregistered:
        raise Phase5GateReceiptError("SUITE_UNREGISTERED_DISCOVERY")
    return {
        "active_registered": tuple(sorted(registered)),
        "discovered_registered": discovered,
        "executed_inventory": tuple(sorted(registered)),
    }


def validate_phase5_executed_inventory(
    paths: Sequence[str], *, repository_root: Path | None = None
) -> tuple[str, ...]:
    inventory = phase5_suite_inventory(repository_root or Path(__file__).resolve().parents[4])
    expected = inventory["active_registered"]
    actual = tuple(sorted(paths))
    if actual != expected or len(paths) != len(set(paths)):
        raise Phase5GateReceiptError("SUITE_EXECUTED_INVENTORY_MISMATCH")
    return actual


def validate_phase5_probe_coverage(value: Mapping[str, object]) -> dict[str, object]:
    """Validate the structured spec-less edge/prohibition declaration."""

    required = {
        "edge_total",
        "explicit_truths",
        "unresolved_assumptions",
        "prohibition_total",
        "unresolved_prohibitions",
        "silent_drops",
        "explicit_truth_names",
    }
    if set(value) != required:
        raise Phase5GateReceiptError("PROBE_COVERAGE_SCHEMA_INVALID")
    expected = {
        "edge_total": 17,
        "explicit_truths": 3,
        "unresolved_assumptions": 14,
        "unresolved_prohibitions": 6,
        "prohibition_total": 6,
        "silent_drops": 0,
        "explicit_truth_names": ["adjacency", "empty", "ordering"],
    }
    if dict(value) != expected:
        raise Phase5GateReceiptError("PROBE_COVERAGE_TOTALS_INVALID")
    return dict(value)


def _canonical_probe_module_paths() -> tuple[Path, Path]:
    roots = (
        Path.home() / ".codex/gsd-core/bin/lib",
        Path.home() / ".claude/gsd-core/bin/lib",
    )
    for root in roots:
        edge = root / "edge-probe.cjs"
        core = root / "probe-core.cjs"
        if edge.is_file() and core.is_file():
            return edge, core
    raise Phase5GateReceiptError("PROBE_COVERAGE_RUNTIME_UNAVAILABLE")


def validate_phase5_canonical_probe_coverage() -> dict[str, int]:
    """Run the canonical edge/prohibition validators over the declared coverage."""

    edge_path, core_path = _canonical_probe_module_paths()
    requirements = [
        {"id": f"unresolved-{index:02d}", "text": f"unresolved assumption {index:02d}"}
        for index in range(1, 15)
    ]
    requirements.append(
        {
            "id": "UX-01",
            "text": "the exact-five recommendation collection remains ordered",
            "shapes": ["collection"],
        }
    )
    resolutions = [
        {
            "requirement_id": "UX-01",
            "category": category,
            "status": "resolved",
            "verification": "explicit",
            "resolution": (
                f"UX-01 {category} truth owner: "
                "web/e2e/no-photo-recommendation.spec.ts and "
                "RecommendationResults.test.tsx"
            ),
            "reason": None,
        }
        for category in ("adjacency", "empty", "ordering")
    ]
    prohibitions = [
        {
            "requirement_id": f"phase5-{index:02d}",
            "category": "values",
            "status": "unresolved",
            "verification": None,
            "resolution": None,
            "reason": None,
            "statement": f"Phase 5 prohibition {index:02d}",
        }
        for index in range(1, 7)
    ]
    script = """
const edge = require(process.argv[1]);
const core = require(process.argv[2]);
const requirements = JSON.parse(process.argv[3]);
const resolutions = JSON.parse(process.argv[4]);
const prohibitions = JSON.parse(process.argv[5]);
for (const resolution of resolutions) edge.validateResolution(resolution);
const edgeReport = edge.analyzeCoverage(requirements, resolutions);
for (const prohibition of prohibitions) core.validateProhibitionResolution(prohibition);
const projected = core.projectProhibitions(prohibitions);
process.stdout.write(JSON.stringify({
  edge_total: edgeReport.coverage.applicable,
  edge_resolved: edgeReport.coverage.resolved,
  edge_unresolved: edgeReport.coverage.unresolved,
  edge_explicit: edgeReport.coverage.byVerification.explicit,
  prohibition_total: projected.length,
  prohibition_unresolved: projected.filter((item) => item.status === "unresolved").length,
  silent_drops: 17 - edgeReport.coverage.applicable,
}));
"""
    try:
        result = subprocess.run(
            [
                "node",
                "-e",
                script,
                str(edge_path),
                str(core_path),
                json.dumps(requirements, ensure_ascii=False),
                json.dumps(resolutions, ensure_ascii=False),
                json.dumps(prohibitions, ensure_ascii=False),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise Phase5GateReceiptError("PROBE_COVERAGE_CANONICAL_VALIDATION_FAILED") from error
    expected = {
        "edge_total": 17,
        "edge_resolved": 3,
        "edge_unresolved": 14,
        "edge_explicit": 3,
        "prohibition_total": 6,
        "prohibition_unresolved": 6,
        "silent_drops": 0,
    }
    if report != expected:
        raise Phase5GateReceiptError("PROBE_COVERAGE_CANONICAL_TOTALS_INVALID")
    return report


def validate_phase5_probe_declaration(value: Mapping[str, object]) -> dict[str, object]:
    validate_phase5_probe_coverage(value)
    canonical = validate_phase5_canonical_probe_coverage()
    return {**dict(value), "canonical": canonical}


def validate_phase5_receipt_maps(value: Mapping[str, object]) -> dict[str, int]:
    """Require the complete relation, scenario, contrast, lifecycle, and run map."""

    required = {
        "scenario_ids",
        "contrast_pairs",
        *_RECEIPT_MAP_REQUIRED_DIGEST_FIELDS,
    }
    if not required.issubset(value):
        raise Phase5GateReceiptError("RECEIPT_MAP_REQUIRED_FIELD_MISSING")
    if value.get("receipt_schema_version", _RECEIPT_MAP_SCHEMA) != _RECEIPT_MAP_SCHEMA:
        raise Phase5GateReceiptError("RECEIPT_MAP_SCHEMA_INVALID")
    parent_fields = value.get("parent_fields")
    if parent_fields is not None:
        if tuple(parent_fields) != _RECEIPT_MAP_REQUIRED_PARENT_FIELDS:
            raise Phase5GateReceiptError("RECEIPT_MAP_PARENT_INVALID")
        if len(parent_fields) != _RECEIPT_MAP_REQUIRED_PARENT_COUNT:
            raise Phase5GateReceiptError("RECEIPT_MAP_PARENT_COUNT_INVALID")
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )

    scenario_ids = value["scenario_ids"]
    contrast_pairs = value["contrast_pairs"]
    if tuple(scenario_ids) != CANONICAL_SCENARIO_IDS:
        raise Phase5GateReceiptError("RECEIPT_MAP_SCENARIO_INVALID")
    if tuple(tuple(pair) for pair in contrast_pairs) != CANONICAL_CONTRAST_PAIRS:
        raise Phase5GateReceiptError("RECEIPT_MAP_CONTRAST_INVALID")
    if any(not _is_sha256(value[field]) for field in _RECEIPT_MAP_REQUIRED_DIGEST_FIELDS):
        raise Phase5GateReceiptError("RECEIPT_MAP_DIGEST_INVALID")
    return {
        "schema_version": _RECEIPT_MAP_SCHEMA,
        "scenario_count": _RECEIPT_MAP_REQUIRED_SCENARIO_COUNT,
        "contrast_count": _RECEIPT_MAP_REQUIRED_CONTRAST_COUNT,
        "relation_count": _RECEIPT_MAP_REQUIRED_RELATION_COUNT,
        "parent_count": _RECEIPT_MAP_REQUIRED_PARENT_COUNT,
    }


def validate_phase5_halted_summary(
    value: Mapping[str, object], *, required_requirements: Sequence[str]
) -> dict[str, object]:
    """Validate a designed-negative Summary without granting completion."""

    if value.get("status") != "halted":
        raise Phase5GateReceiptError("HALTED_STATUS_INVALID")
    one_liner = value.get("one_liner")
    if (
        not isinstance(one_liner, str)
        or not one_liner.strip()
        or any(
            token in one_liner.casefold() for token in ("phase complete", "successfully complete")
        )
    ):
        raise Phase5GateReceiptError("HALTED_ONE_LINER_INVALID")
    for field in ("completed_tasks", "attempt_count"):
        if type(value.get(field)) is not int or int(value[field]) < 0:
            raise Phase5GateReceiptError("HALTED_COUNT_INVALID")
    if value.get("requirements_completed") != []:
        raise Phase5GateReceiptError("HALTED_REQUIREMENTS_COMPLETED_INVALID")
    blocked = value.get("requirements_blocked")
    if tuple(blocked or ()) != tuple(required_requirements):
        raise Phase5GateReceiptError("HALTED_REQUIREMENTS_BLOCKED_INVALID")
    if value.get("provider_attempted") is not False:
        raise Phase5GateReceiptError("HALTED_PROVIDER_ATTEMPT_INVALID")
    if value.get("completion_claim", False) is not False:
        raise Phase5GateReceiptError("HALTED_COMPLETION_CLAIM_INVALID")
    for field in ("request_sha256", "terminal_sha256"):
        if field in value and value[field] is not None and not _is_sha256(value[field]):
            raise Phase5GateReceiptError("HALTED_DIGEST_INVALID")
    return dict(value)


def validate_phase5_source_authority_stop(value: Mapping[str, object]) -> dict[str, object]:
    """Validate the no-backup checkpoint branch before any artifact publication."""

    if (
        value.get("outcome") != "no-authoritative-backup"
        or value.get("artifact_count") != 0
        or value.get("summary_exists") is not False
        or value.get("downstream_satisfied", False) is not False
    ):
        raise Phase5GateReceiptError("SOURCE_AUTHORITY_STOP_ARTIFACT_OR_SUMMARY")
    return dict(value)


def _summary_status(path: Path) -> str | None:
    try:
        payload = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    for line in payload.splitlines():
        if line.startswith("status:"):
            return line.partition(":")[2].strip()
    return None


def validate_phase5_signoff_bootstrap(
    repository_root: Path,
    *,
    summaries: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Require every positive recovery predecessor and an absent future Summary.

    The consumed `05-27` designed-negative sibling is immutable history: its
    committed halted Summary is required to exist with status halted and grants
    no completion authority, so it is verified separately from the positive
    predecessor chain below.
    """

    phase_dir = repository_root / ".planning/phases/05-complete-no-photo-recommendation-journey"
    if summaries is None:
        summaries = {}
        for path in phase_dir.glob("05-*-SUMMARY.md"):
            plan_id = path.name.split("-SUMMARY.md", 1)[0]
            summaries[plan_id] = {"status": _summary_status(path)}
    if "05-17" in summaries:
        raise Phase5GateReceiptError("BOOTSTRAP_FUTURE_SUMMARY_PRESENT")
    halted_history = summaries.get("05-27", {}).get("status")
    if halted_history is not None and halted_history != "halted":
        raise Phase5GateReceiptError("BOOTSTRAP_HALTED_HISTORY_MUTATED")
    required = (
        "05-16",
        "05-18",
        "05-19",
        "05-20",
        "05-21",
        "05-22",
        "05-23",
        "05-34",
        "05-24",
        "05-25",
        "05-26",
        "05-35",
        "05-37",
        "05-38",
        "05-39",
        "05-40",
        "05-28",
        "05-29",
        "05-30",
        "05-31",
        "05-32",
        "05-33",
    )
    for plan_id in required:
        status = summaries.get(plan_id, {}).get("status")
        if status == "halted":
            raise Phase5GateReceiptError("BOOTSTRAP_HALTED_ANCESTOR")
        if status != "complete":
            raise Phase5GateReceiptError("BOOTSTRAP_POSITIVE_PREDECESSOR_MISSING")
    if not (phase_dir / "05-17-SUMMARY.md").exists():
        return {
            "state": "READY",
            "required_predecessors": len(required),
            "halted_history_siblings": ("05-27",),
        }
    raise Phase5GateReceiptError("BOOTSTRAP_FUTURE_SUMMARY_PRESENT")


_VALIDATION_FRONTMATTER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "phase",
        "slug",
        "status",
        "nyquist_compliant",
        "wave_0_complete",
        "current_signoff",
        "current_signoff_receipt",
        "rollback_baseline",
        "ledger_schema_version",
        "current_task_ledger_sha256",
        "created",
    }
)
_VALIDATION_BASELINE = {
    "phase": "05",
    "slug": "complete-no-photo-recommendation-journey",
    "status": "gaps_planned",
    "nyquist_compliant": True,
    "wave_0_complete": False,
    "current_signoff": "blocked",
    "current_signoff_receipt": None,
    "rollback_baseline": "phase5-validation-pending-v1",
    "ledger_schema_version": "itda.phase5-validation-ledger.v8",
    "current_task_ledger_sha256": PHASE5_CURRENT_TASK_LEDGER_SHA256,
}
_CLEAN_SCHEMA_VERSION = "itda.phase5-clean-gate-receipt.v2"
_PRIVATE_SCHEMA_VERSION = "itda.phase5-private-gate-receipt.v2"
_FINAL_SCHEMA_VERSION = "itda.phase5-final-signoff-receipt.v1"
_RECEIPT_MAP_SCHEMA = "itda.phase5-complete-receipt-map.v2"
_RECEIPT_MAP_REQUIRED_DIGEST_FIELDS = (
    "candidate_smoke",
    "activation_intent",
    "promotion",
    "attestation",
    "ordinary_run",
    "hard_duplicate",
    "cannot_coappear",
)
_RECEIPT_MAP_REQUIRED_SCENARIO_COUNT = 8
_RECEIPT_MAP_REQUIRED_CONTRAST_COUNT = 7
_RECEIPT_MAP_REQUIRED_RELATION_COUNT = 2
_RECEIPT_MAP_REQUIRED_PARENT_COUNT = 17
_RECEIPT_MAP_REQUIRED_PARENT_FIELDS = (
    "source_inventory",
    "release",
    "config",
    "kernel",
    "policy",
    "hard_duplicate",
    "cannot_coappear",
    "activation_source",
    "activation_dataset",
    "activation_suite",
    "contrast_suite",
    "generation",
    "generation_receipt",
    "candidate",
    "smoke",
    "intent",
    "promotion",
)
_FINALIZATION_SCHEMA_VERSION = "itda.phase5-validation-finalization.v1"
_KERNEL_IDENTITY_SCHEMA = "itda.phase5-recommendation-kernel-identity.v1"
_REVIEW_STATES = frozenset(
    {
        "COMPLETE_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
        "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
    }
)
CLEAN_SUITE_IDS = tuple(
    row["owner"] for row in PHASE5_SUITE_REGISTRY_V4 if row["pending_owner"] is None
)
PRIVATE_SUITE_IDS = ("phase5-active-release", "phase5-private-real-e2e")
CLEAN_CHILD_IDS = frozenset({"backend", "generated_contract", "components", "clean_browser"})
PRIVATE_CHILD_IDS = frozenset({"active_release", "private_browser"})


@dataclass(frozen=True, slots=True)
class ValidationBaseline:
    """The only state permitted as a rollback target before finalization."""

    path: Path
    payload: bytes
    digest: str
    normalized: bool


class Phase5ValidationTransactionError(Phase5GateReceiptError):
    """A finalization transaction was rejected or rolled back."""


def _exact_green_children(statuses: Mapping[str, int], expected: frozenset[str]) -> bool:
    return set(statuses) == expected and all(
        type(value) is int and value == 0 for value in statuses.values()
    )


def _command_set_sha256(gate: str, suite_ids: Sequence[str]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": "itda.phase5-gate-command-set.v1",
                "gate": gate,
                "suite_ids": list(suite_ids),
            }
        )
    ).hexdigest()


def _recommendation_kernel_sha256() -> str:
    """Return the digest of the checked-in deterministic kernel identity."""

    from itda.contracts.recommendation import CANONICAL_RECOMMENDATION_CONFIG

    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema_version": _KERNEL_IDENTITY_SCHEMA,
                "kernel_version": CANONICAL_RECOMMENDATION_CONFIG.kernel_version,
            }
        )
    ).hexdigest()


def _current_recommendation_identity() -> tuple[str, str]:
    from itda.contracts.recommendation import CANONICAL_RECOMMENDATION_CONFIG

    config_sha256 = CANONICAL_RECOMMENDATION_CONFIG.config_sha256
    if not _is_sha256(config_sha256):
        raise Phase5GateReceiptError("RECOMMENDATION_CONFIG_INVALID")
    return cast(str, config_sha256), _recommendation_kernel_sha256()


def _validate_active_release_verification(
    value: Mapping[str, object],
) -> dict[str, object]:
    """Validate the server-owned exact DEV-24 active-release proof.

    The mapping may contain private diagnostic fields, but only the allowlisted
    identity/count fields are copied into receipts.  Caller-selected release
    IDs, readiness flags, and profile bodies therefore have no authority.
    """

    release_sha256 = value.get("release_sha256")
    membership_sha256 = value.get("membership_sha256")
    config_sha256 = value.get("config_sha256")
    kernel_sha256 = value.get("kernel_sha256")
    eligible_count = value.get("eligible_count")
    if (
        value.get("state") != "ACTIVE"
        or value.get("analysis_origin") != "DEMO_MODEL_DERIVED"
        or value.get("member_count") != 24
        or value.get("profile_count") != 24
        or not isinstance(eligible_count, int)
        or type(eligible_count) is not int
        or not 5 <= eligible_count <= 24
        or value.get("nondegenerate") is not True
        or not _is_sha256(release_sha256)
        or not _is_sha256(membership_sha256)
        or not _is_sha256(config_sha256)
        or not _is_sha256(kernel_sha256)
    ):
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    return {
        "state": "ACTIVE",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "member_count": 24,
        "profile_count": 24,
        "eligible_count": eligible_count,
        "nondegenerate": True,
        "release_sha256": release_sha256,
        "membership_sha256": membership_sha256,
        "config_sha256": config_sha256,
        "kernel_sha256": kernel_sha256,
    }


def _resolve_current_active_release_verification() -> dict[str, object]:
    """Resolve and independently recheck the current production pointer."""

    from itda.db.phase5_demo_release import PRODUCTION_ROOT, Phase5DemoReleaseStore

    try:
        snapshot = Phase5DemoReleaseStore(root=PRODUCTION_ROOT).resolve_active()
    except Exception as error:
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH") from error
    if snapshot is None or getattr(snapshot, "state", "ACTIVE") != "ACTIVE":
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    profiles = tuple(getattr(snapshot, "profiles", ()))
    eligible_profiles = tuple(
        profile
        for profile in profiles
        if profile.recommendation_eligible is True
        and type(getattr(profile, "confidence", None)) is int
        and int(profile.confidence) >= 70
    )
    vectors = tuple(
        tuple(getattr(profile, "axis_scores", {}).get(axis) for axis in ("H", "E", "R"))
        for profile in eligible_profiles
    )
    nondegenerate = bool(vectors) and not (len(vectors) > 1 and len(set(vectors)) == 1)
    config_sha256, kernel_sha256 = _current_recommendation_identity()
    return _validate_active_release_verification(
        {
            "state": "ACTIVE",
            "analysis_origin": getattr(snapshot, "analysis_origin", None),
            "member_count": len(profiles),
            "profile_count": len(profiles),
            "eligible_count": len(eligible_profiles),
            "nondegenerate": nondegenerate,
            "release_sha256": getattr(snapshot, "release_sha256", None),
            "membership_sha256": getattr(snapshot, "membership_sha256", None),
            "config_sha256": config_sha256,
            "kernel_sha256": kernel_sha256,
        }
    )


def _receipt_identity_fields(
    release_verification: Mapping[str, object],
) -> dict[str, object]:
    validated = _validate_active_release_verification(release_verification)
    return {
        "active_release_sha256": validated["release_sha256"],
        "active_membership_sha256": validated["membership_sha256"],
        "active_release_verification_sha256": hashlib.sha256(
            canonical_json_bytes(validated)
        ).hexdigest(),
        "analysis_origin": validated["analysis_origin"],
        "member_count": validated["member_count"],
        "eligible_count": validated["eligible_count"],
        "config_sha256": validated["config_sha256"],
        "kernel_sha256": validated["kernel_sha256"],
    }


CLEAN_COMMAND_SET_SHA256 = _command_set_sha256("clean", CLEAN_SUITE_IDS)
PRIVATE_COMMAND_SET_SHA256 = _command_set_sha256("private", PRIVATE_SUITE_IDS)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _SHA256_CHARS for character in value)
    )


def _require_no_symlink_ancestors(path: Path) -> None:
    """Reject symlinks in the entire path, including the final component."""

    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            raise Phase5GateReceiptError("GATE_RECEIPT_SYMLINK_FORBIDDEN")


def _read_regular_nofollow(path: Path, *, maximum_bytes: int = 1_048_576) -> bytes:
    try:
        _require_no_symlink_ancestors(path)
    except Phase5GateReceiptError as error:
        raise Phase5GateReceiptError("GATE_RECEIPT_UNAVAILABLE") from error
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise Phase5GateReceiptError("GATE_RECEIPT_UNAVAILABLE") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise Phase5GateReceiptError("GATE_RECEIPT_INVALID_FILE")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(65_536, before.st_size - len(payload)))
            if not chunk:
                raise Phase5GateReceiptError("GATE_RECEIPT_TRUNCATED")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise Phase5GateReceiptError("GATE_RECEIPT_CHANGED")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _load_canonical_object(path: Path) -> dict[str, object]:
    payload = _read_regular_nofollow(path)
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Phase5GateReceiptError("GATE_RECEIPT_INVALID_JSON") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) + b"\n" != payload:
        raise Phase5GateReceiptError("GATE_RECEIPT_NOT_CANONICAL")
    return value


def _write_canonical_atomic(path: Path, value: Mapping[str, object], *, mode: int) -> None:
    _require_no_symlink_ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink() or (path.exists() and not path.is_file()):
        raise Phase5GateReceiptError("GATE_RECEIPT_OUTPUT_INVALID")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        payload = canonical_json_bytes(dict(value)) + b"\n"
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise Phase5GateReceiptError("GATE_RECEIPT_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _write_bytes_atomic(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    """Write one bounded regular file atomically without following links."""

    _require_no_symlink_ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink() or (path.exists() and not path.is_file()):
        raise Phase5GateReceiptError("GATE_RECEIPT_OUTPUT_INVALID")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise Phase5GateReceiptError("GATE_RECEIPT_WRITE_FAILED")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _parse_validation_frontmatter(payload: str) -> tuple[dict[str, object], int]:
    if not payload.startswith("---\n"):
        raise Phase5GateReceiptError("VALIDATION_LEDGER_INVALID")
    closing = payload.find("\n---\n", 4)
    if closing < 0:
        raise Phase5GateReceiptError("VALIDATION_LEDGER_INVALID")
    raw_lines = payload[4:closing].splitlines()
    parsed: dict[str, object] = {}
    for line in raw_lines:
        if not line.strip() or ":" not in line:
            raise Phase5GateReceiptError("VALIDATION_LEDGER_INVALID")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        if key in parsed or key not in _VALIDATION_FRONTMATTER_KEYS:
            raise Phase5GateReceiptError("VALIDATION_LEDGER_INVALID")
        value = raw_value.strip()
        if value == "null":
            parsed[key] = None
        elif value == "true":
            parsed[key] = True
        elif value == "false":
            parsed[key] = False
        else:
            parsed[key] = value
    required = _VALIDATION_BASELINE.keys()
    if any(key not in parsed for key in required):
        raise Phase5GateReceiptError("VALIDATION_LEDGER_INVALID")
    return parsed, closing + len("\n---\n")


def _frontmatter_line(key: str, value: object) -> str:
    if value is None:
        rendered = "null"
    elif value is True:
        rendered = "true"
    elif value is False:
        rendered = "false"
    else:
        rendered = str(value)
    return f"{key}: {rendered}"


def _normalized_frontmatter(payload: str, parsed: Mapping[str, object]) -> str:
    lines = payload.splitlines(keepends=True)
    closing_index = next(index for index, line in enumerate(lines[1:], start=1) if line == "---\n")
    replacements = dict(parsed)
    replacements.update(_VALIDATION_BASELINE)
    rebuilt = ["---\n"]
    for line in lines[1:closing_index]:
        key = line.split(":", 1)[0].strip()
        rebuilt.append(_frontmatter_line(key, replacements[key]) + "\n")
    rebuilt.append("---\n")
    rebuilt.extend(lines[closing_index + 1 :])
    return "".join(rebuilt)


def _normalize_current_gap_row(line: str, task_id: str) -> str:
    segments = line.rstrip("\n").split("|")
    if len(segments) < 4 or segments[1].strip() != task_id:
        raise Phase5GateReceiptError("VALIDATION_LEDGER_AMBIGUOUS")
    # Keep the plan/command text, but discard every current status/receipt cell.
    body = segments[1:]
    status_positions = [
        index
        for index, value in enumerate(body)
        if any(marker in value for marker in ("✅", "⬜", "🕘", "receipt", "GREEN", "green"))
    ]
    if len(status_positions) < 1:
        raise Phase5GateReceiptError("VALIDATION_LEDGER_AMBIGUOUS")
    first_status = status_positions[-2] if len(status_positions) >= 2 else status_positions[-1]
    for index in status_positions:
        body[index] = " ⬜ planned " if index == first_status else " ⬜ pending "
    for index, value in enumerate(body):
        if index == 0:
            continue
        if index not in status_positions and (
            "final-signoff" in value
            or "clean-gate-receipt" in value
            or "private-evidence-receipt" in value
            or "validation-finalization" in value
        ):
            body[index] = " ⬜ pending "
    return "|".join([""] + body).rstrip() + "\n"


def _normalize_validation_payload(payload: str) -> tuple[bytes, bool]:
    parsed, _ = _parse_validation_frontmatter(payload)
    lines = payload.splitlines(keepends=True)
    _require_full_current_task_ledger(payload)
    parsed_current = _validation_current_task_ids(payload)
    if parsed_current and set(parsed_current) - set(_CURRENT_GAP_TASK_IDS):
        validate_phase5_current_task_ledger(payload)
    seen: dict[str, int] = {task_id: 0 for task_id in _CURRENT_GAP_TASK_IDS}
    rebuilt: list[str] = []
    for line in lines:
        matching = [task_id for task_id in _CURRENT_GAP_TASK_IDS if f"| {task_id} |" in line]
        if len(matching) > 1:
            raise Phase5GateReceiptError("VALIDATION_LEDGER_AMBIGUOUS")
        if matching:
            task_id = matching[0]
            seen[task_id] += 1
            if seen[task_id] > 1:
                raise Phase5GateReceiptError("VALIDATION_LEDGER_AMBIGUOUS")
            rebuilt.append(_normalize_current_gap_row(line, task_id))
        elif line.startswith("Current approval:"):
            rebuilt.append("Current approval: BLOCKED — canonical pending baseline.\n")
        else:
            rebuilt.append(line)
    if any(count != 1 for count in seen.values()):
        raise Phase5GateReceiptError("VALIDATION_LEDGER_AMBIGUOUS")
    normalized = _normalized_frontmatter("".join(rebuilt), parsed)
    return normalized.encode("utf-8"), normalized.encode("utf-8") != payload.encode("utf-8")


def normalize_validation_ledger(path: Path) -> ValidationBaseline:
    """Normalize recoverable stale current markers before any rollback capture."""

    payload = _read_regular_nofollow(path, maximum_bytes=4 * 1024 * 1024)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Phase5GateReceiptError("VALIDATION_LEDGER_INVALID") from error
    normalized_payload, changed = _normalize_validation_payload(text)
    if changed:
        _write_bytes_atomic(path, normalized_payload, mode=0o644)
        reopened = _read_regular_nofollow(path, maximum_bytes=4 * 1024 * 1024)
        if reopened != normalized_payload:
            raise Phase5GateReceiptError("VALIDATION_LEDGER_REOPEN_FAILED")
        normalized_payload = reopened
    return ValidationBaseline(
        path=path,
        payload=normalized_payload,
        digest=hashlib.sha256(normalized_payload).hexdigest(),
        normalized=changed,
    )


def _seal_receipt(value: Mapping[str, object]) -> dict[str, object]:
    unsigned = dict(value)
    return {
        **unsigned,
        "receipt_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def emit_clean_gate_receipt(
    *,
    output_path: Path,
    checkout_sha256: str,
    started_at: str,
    completed_at: str,
    duration_ms: int,
    child_exit_statuses: Mapping[str, int],
    checkout_git_sha: str | None = None,
    release_verification: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Atomically emit the bounded clean GREEN receipt after all zero exits."""

    if (
        not _is_sha256(checkout_sha256)
        or not _exact_green_children(child_exit_statuses, CLEAN_CHILD_IDS)
        or duration_ms < 0
    ):
        raise Phase5GateReceiptError("CLEAN_GATE_NOT_GREEN")
    if checkout_git_sha is not None:
        _validate_git_sha(checkout_git_sha)
    identity = _receipt_identity_fields(
        release_verification
        if release_verification is not None
        else _resolve_current_active_release_verification()
    )
    unsigned: dict[str, object] = {
        "schema_version": _CLEAN_SCHEMA_VERSION,
        "gate": "clean",
        "state": "GREEN",
        "checkout_sha256": checkout_sha256,
        "command_set_sha256": CLEAN_COMMAND_SET_SHA256,
        "suite_ids": list(CLEAN_SUITE_IDS),
        "child_exit_statuses": dict(child_exit_statuses),
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "validation_task_ids": list(_TASK_IDS),
    }
    unsigned.update(identity)
    if checkout_git_sha is not None:
        unsigned["checkout_git_sha"] = checkout_git_sha
    receipt = _seal_receipt(unsigned)
    _write_canonical_atomic(output_path, receipt, mode=0o644)
    return receipt


def emit_private_gate_receipt(
    *,
    output_path: Path,
    checkout_sha256: str,
    started_at: str,
    completed_at: str,
    duration_ms: int,
    child_exit_statuses: Mapping[str, int],
    release_verification: Mapping[str, object],
    checkout_git_sha: str | None = None,
) -> dict[str, object]:
    """Atomically emit private GREEN after exact active release and real E2E."""

    release_sha256 = release_verification.get("release_sha256")
    membership_sha256 = release_verification.get("membership_sha256")
    identity = _receipt_identity_fields(release_verification)
    if (
        not _is_sha256(checkout_sha256)
        or not _exact_green_children(child_exit_statuses, PRIVATE_CHILD_IDS)
        or duration_ms < 0
        or identity["active_release_sha256"] != release_sha256
        or identity["active_membership_sha256"] != membership_sha256
    ):
        raise Phase5GateReceiptError("PRIVATE_GATE_NOT_GREEN")
    if checkout_git_sha is not None:
        _validate_git_sha(checkout_git_sha)
    unsigned: dict[str, object] = {
        "schema_version": _PRIVATE_SCHEMA_VERSION,
        "gate": "private",
        "state": "GREEN",
        "checkout_sha256": checkout_sha256,
        "command_set_sha256": PRIVATE_COMMAND_SET_SHA256,
        "suite_ids": list(PRIVATE_SUITE_IDS),
        "child_exit_statuses": dict(child_exit_statuses),
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "validation_task_ids": list(_TASK_IDS),
        "private_e2e_scenario_id": "phase5-private-real-demo-complete-journey-v1",
    }
    unsigned.update(identity)
    if checkout_git_sha is not None:
        unsigned["checkout_git_sha"] = checkout_git_sha
    receipt = _seal_receipt(unsigned)
    _write_canonical_atomic(output_path, receipt, mode=0o600)
    return receipt


def _validate_self_digest(receipt: Mapping[str, object]) -> None:
    claimed = receipt.get("receipt_sha256")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if (
        not _is_sha256(claimed)
        or claimed != hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    ):
        raise Phase5GateReceiptError("GATE_RECEIPT_DIGEST_MISMATCH")


def _validate_gate(
    receipt: Mapping[str, object],
    *,
    gate: str,
    schema_version: str,
    expected_checkout_sha256: str,
    expected_command_set_sha256: str,
    expected_suite_ids: Sequence[str],
) -> None:
    _validate_self_digest(receipt)
    common_fields = {
        "schema_version",
        "gate",
        "state",
        "checkout_sha256",
        "command_set_sha256",
        "suite_ids",
        "child_exit_statuses",
        "started_at",
        "completed_at",
        "duration_ms",
        "validation_task_ids",
        "active_release_sha256",
        "active_membership_sha256",
        "active_release_verification_sha256",
        "analysis_origin",
        "member_count",
        "eligible_count",
        "config_sha256",
        "kernel_sha256",
        "receipt_sha256",
    }
    required_fields = set(common_fields)
    if gate == "private":
        required_fields |= {
            "private_e2e_scenario_id",
        }
    field_set = set(receipt)
    if field_set not in (required_fields, required_fields | {"checkout_git_sha"}):
        raise Phase5GateReceiptError("GATE_RECEIPT_CONTRACT_MISMATCH")
    checkout_git_sha = receipt.get("checkout_git_sha")
    if checkout_git_sha is not None:
        if not isinstance(checkout_git_sha, str):
            raise Phase5GateReceiptError("CURRENT_CHECKOUT_INVALID")
        _validate_git_sha(checkout_git_sha)
    duration_ms = receipt.get("duration_ms")
    eligible_count = receipt.get("eligible_count")
    if (
        receipt.get("schema_version") != schema_version
        or receipt.get("gate") != gate
        or receipt.get("state") != "GREEN"
        or receipt.get("checkout_sha256") != expected_checkout_sha256
        or receipt.get("command_set_sha256") != expected_command_set_sha256
        or receipt.get("suite_ids") != list(expected_suite_ids)
        or receipt.get("validation_task_ids") != list(_TASK_IDS)
        or not isinstance(duration_ms, int)
        or duration_ms < 0
        or (
            gate == "clean"
            and (
                not _is_sha256(receipt.get("active_release_sha256"))
                or not _is_sha256(receipt.get("active_membership_sha256"))
                or not _is_sha256(receipt.get("active_release_verification_sha256"))
            )
        )
        or not _is_sha256(receipt.get("config_sha256"))
        or not _is_sha256(receipt.get("kernel_sha256"))
        or (
            gate == "clean"
            and (
                receipt.get("analysis_origin") != "DEMO_MODEL_DERIVED"
                or receipt.get("member_count") != 24
                or not isinstance(eligible_count, int)
                or type(eligible_count) is not int
                or not 5 <= eligible_count <= 24
            )
        )
    ):
        raise Phase5GateReceiptError("GATE_RECEIPT_CONTRACT_MISMATCH")
    statuses = receipt.get("child_exit_statuses")
    expected_children = CLEAN_CHILD_IDS if gate == "clean" else PRIVATE_CHILD_IDS
    if not isinstance(statuses, dict) or not _exact_green_children(statuses, expected_children):
        raise Phase5GateReceiptError("GATE_CHILD_NOT_GREEN")


def validate_explanation_review(
    value: Mapping[str, object], *, allow_deferred_nonblocking_review: bool
) -> str:
    """Validate bounded non-authorizing external quality evidence."""

    state = value.get("status")
    if state not in _REVIEW_STATES:
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_STATUS_INVALID")
    if (
        state == "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE"
        and not allow_deferred_nonblocking_review
    ):
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_DEFERRED")
    common = {
        "schema_version",
        "status",
        "reviewer_pseudonym",
        "reviewed_at",
        "active_release_sha256",
    }
    allowed = (
        common | {"reason"}
        if state == "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE"
        else common | {"config_sha256", "run_sha256", "profiles"}
    )
    if set(value) != allowed:
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_MUTATION_FORBIDDEN")
    if (
        value.get("schema_version") != "itda.phase5-korean-explanation-review.v1"
        or not isinstance(value.get("reviewer_pseudonym"), str)
        or not 1 <= len(str(value["reviewer_pseudonym"])) <= 80
        or not isinstance(value.get("reviewed_at"), str)
        or not _is_sha256(value.get("active_release_sha256"))
    ):
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
    if state == "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE" and (
        not isinstance(value.get("reason"), str) or not 1 <= len(str(value["reason"])) <= 500
    ):
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
    if state == "COMPLETE_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE":
        profiles = value.get("profiles")
        if (
            not _is_sha256(value.get("config_sha256"))
            or not _is_sha256(value.get("run_sha256"))
            or not isinstance(profiles, list)
            or len(profiles) != 3
        ):
            raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
        profile_ids: set[str] = set()
        for profile in profiles:
            if not isinstance(profile, dict) or set(profile) != {
                "preference_profile_id",
                "result_run_sha256",
                "results",
            }:
                raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
            profile_id = profile.get("preference_profile_id")
            results = profile.get("results")
            if (
                not isinstance(profile_id, str)
                or not 1 <= len(profile_id) <= 120
                or profile_id in profile_ids
                or not _is_sha256(profile.get("result_run_sha256"))
                or not isinstance(results, list)
                or len(results) != 5
            ):
                raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
            profile_ids.add(profile_id)
            place_ids: set[str] = set()
            for result in results:
                if not isinstance(result, dict) or set(result) != {
                    "place_id",
                    "reason_ids",
                    "classification",
                    "note",
                }:
                    raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
                place_id = result.get("place_id")
                reason_ids = result.get("reason_ids")
                note = result.get("note")
                if (
                    not isinstance(place_id, str)
                    or not 1 <= len(place_id) <= 120
                    or place_id in place_ids
                    or not isinstance(reason_ids, list)
                    or not 2 <= len(reason_ids) <= 8
                    or not all(
                        isinstance(item, str) and 1 <= len(item) <= 120 for item in reason_ids
                    )
                    or result.get("classification")
                    not in {"USEFUL", "PROMOTIONAL", "UNSUPPORTED", "HIDES_UNKNOWN"}
                    or not isinstance(note, str)
                    or len(note) > 280
                ):
                    raise Phase5GateReceiptError("EXPLANATION_REVIEW_CONTRACT_INVALID")
                place_ids.add(place_id)
    return str(state)


def signoff_gate_receipts(
    *,
    validation_path: Path,
    clean_receipt_path: Path,
    private_receipt_path: Path,
    explanation_review_path: Path,
    expected_checkout_sha256: str,
    expected_clean_command_set_sha256: str,
    expected_private_command_set_sha256: str,
    expected_clean_suite_ids: Sequence[str],
    expected_private_suite_ids: Sequence[str],
    allow_deferred_nonblocking_review: bool,
    expected_active_release_sha256: str | None = None,
    expected_active_membership_sha256: str | None = None,
    expected_config_sha256: str | None = None,
    expected_kernel_sha256: str | None = None,
    expected_eligible_count: int | None = None,
    expected_validation_candidate_sha256: str | None = None,
) -> dict[str, object]:
    """Verify the exact pair and return a bounded public-safe sign-off projection."""

    if not _is_sha256(expected_checkout_sha256):
        raise Phase5GateReceiptError("CURRENT_CHECKOUT_INVALID")
    clean = _load_canonical_object(clean_receipt_path)
    private = _load_canonical_object(private_receipt_path)
    review = _load_canonical_object(explanation_review_path)
    _validate_gate(
        clean,
        gate="clean",
        schema_version=_CLEAN_SCHEMA_VERSION,
        expected_checkout_sha256=expected_checkout_sha256,
        expected_command_set_sha256=expected_clean_command_set_sha256,
        expected_suite_ids=expected_clean_suite_ids,
    )
    _validate_gate(
        private,
        gate="private",
        schema_version=_PRIVATE_SCHEMA_VERSION,
        expected_checkout_sha256=expected_checkout_sha256,
        expected_command_set_sha256=expected_private_command_set_sha256,
        expected_suite_ids=expected_private_suite_ids,
    )
    if (
        private.get("analysis_origin") != "DEMO_MODEL_DERIVED"
        or private.get("member_count") != 24
        or not _is_sha256(private.get("active_release_sha256"))
        or not _is_sha256(private.get("active_membership_sha256"))
        or not _is_sha256(private.get("active_release_verification_sha256"))
        or private.get("private_e2e_scenario_id") != "phase5-private-real-demo-complete-journey-v1"
    ):
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    for field, expected in (
        ("config_sha256", expected_config_sha256),
        ("kernel_sha256", expected_kernel_sha256),
    ):
        if expected is not None and private.get(field) != expected:
            raise Phase5GateReceiptError("RECOMMENDATION_IDENTITY_MISMATCH")
    if (
        expected_eligible_count is not None
        and private.get("eligible_count") != expected_eligible_count
    ):
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    if clean.get("active_release_sha256") != private.get("active_release_sha256") or (
        clean.get("active_membership_sha256") != private.get("active_membership_sha256")
        or clean.get("config_sha256") != private.get("config_sha256")
        or clean.get("kernel_sha256") != private.get("kernel_sha256")
        or clean.get("eligible_count") != private.get("eligible_count")
    ):
        raise Phase5GateReceiptError("GATE_PARENT_IDENTITY_MISMATCH")
    if (
        expected_active_release_sha256 is not None
        and private.get("active_release_sha256") != expected_active_release_sha256
    ) or (
        expected_active_membership_sha256 is not None
        and private.get("active_membership_sha256") != expected_active_membership_sha256
    ):
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    validation = _read_regular_nofollow(validation_path, maximum_bytes=2_097_152).decode("utf-8")
    for task_id, marker, receipt in (
        ("05-11-01", "clean-gate-receipt", clean),
        ("05-11-02", "private-evidence-receipt", private),
    ):
        matching = [line for line in validation.splitlines() if f"| {task_id} |" in line]
        if (
            len(matching) != 1
            or "✅ green" not in matching[0]
            or marker not in matching[0]
            or str(receipt["receipt_sha256"]) not in matching[0]
        ):
            raise Phase5GateReceiptError("VALIDATION_LINKAGE_MISMATCH")
    review_status = validate_explanation_review(
        review,
        allow_deferred_nonblocking_review=allow_deferred_nonblocking_review,
    )
    if review.get("active_release_sha256") != private["active_release_sha256"]:
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_RELEASE_MISMATCH")
    report: dict[str, object] = {
        "state": "GREEN",
        "clean_gate": "GREEN",
        "private_gate": "GREEN",
        "active_release_sha256": private["active_release_sha256"],
        "active_membership_sha256": private["active_membership_sha256"],
        "active_release_verification_sha256": private["active_release_verification_sha256"],
        "member_count": private["member_count"],
        "analysis_origin": private["analysis_origin"],
        "explanation_review_status": review_status,
        "config_sha256": private["config_sha256"],
        "kernel_sha256": private["kernel_sha256"],
        "eligible_count": private["eligible_count"],
    }
    if expected_validation_candidate_sha256 is not None:
        if not _is_sha256(expected_validation_candidate_sha256):
            raise Phase5GateReceiptError("VALIDATION_CANDIDATE_INVALID")
        report["validation_candidate_sha256"] = expected_validation_candidate_sha256
    return report


def _validation_linkage_matches(
    validation_payload: bytes,
    *,
    clean_receipt: Mapping[str, object],
    private_receipt: Mapping[str, object],
) -> bool:
    try:
        text = validation_payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    clean_digest = str(clean_receipt.get("receipt_sha256"))
    private_digest = str(private_receipt.get("receipt_sha256"))
    clean_matches = [
        line
        for line in text.splitlines()
        if clean_digest in line and "clean-gate-receipt" in line and "✅ green" in line
    ]
    private_matches = [
        line
        for line in text.splitlines()
        if private_digest in line and "private-evidence-receipt" in line and "✅ green" in line
    ]
    return len(clean_matches) == 1 and len(private_matches) == 1


def _candidate_validation_payload(
    baseline: ValidationBaseline,
    *,
    clean_receipt: Mapping[str, object],
    private_receipt: Mapping[str, object],
    final_binding: Mapping[str, object],
) -> bytes:
    """Prepare a deterministic final candidate without touching the installed ledger."""

    text = baseline.payload.decode("utf-8")
    parsed, _ = _parse_validation_frontmatter(text)
    lines = text.splitlines(keepends=True)
    replacements = dict(parsed)
    replacements.update(
        {
            "status": "complete",
            "wave_0_complete": True,
            "current_signoff": "GREEN",
            "current_signoff_receipt": final_binding["final_receipt_sha256"],
        }
    )
    rebuilt: list[str] = ["---\n"]
    closing_index = next(index for index, line in enumerate(lines[1:], start=1) if line == "---\n")
    for line in lines[1:closing_index]:
        key = line.split(":", 1)[0].strip()
        rebuilt.append(_frontmatter_line(key, replacements[key]) + "\n")
    rebuilt.append("---\n")
    clean_digest = str(clean_receipt["receipt_sha256"])
    private_digest = str(private_receipt["receipt_sha256"])
    for line in lines[closing_index + 1 :]:
        matching = [task_id for task_id in _CURRENT_GAP_TASK_IDS if f"| {task_id} |" in line]
        if matching:
            task_id = matching[0]
            segments = line.rstrip("\n").split("|")
            if len(segments) < 4:
                raise Phase5GateReceiptError("VALIDATION_CANDIDATE_INVALID")
            status_positions = [
                index
                for index, value in enumerate(segments)
                if any(marker in value for marker in ("✅", "⬜", "🕘"))
            ]
            if not status_positions:
                raise Phase5GateReceiptError("VALIDATION_CANDIDATE_INVALID")
            for index in status_positions:
                segments[index] = " ✅ green "
            if task_id == "05-17-01":
                digest = clean_digest
                label = "clean-gate-receipt"
            elif task_id == "05-17-02":
                digest = private_digest
                label = "private-evidence-receipt"
            else:
                digest = hashlib.sha256(canonical_json_bytes(dict(final_binding))).hexdigest()
                label = "current-gap-receipt"
            segments[-2] = " ✅ green "
            segments[-1] = f" {label} {digest} "
            rebuilt.append("|".join(segments).rstrip() + "\n")
        elif line.startswith("Current approval:"):
            rebuilt.append("Current approval: GREEN — receipt-bound final signoff.\n")
        else:
            rebuilt.append(line)
    rebuilt.append(
        "\n<!-- phase5-final-signoff-binding-v1 "
        + json.dumps(dict(final_binding), sort_keys=True, separators=(",", ":"))
        + " -->\n"
    )
    return "".join(rebuilt).encode("utf-8")


def emit_final_signoff_receipt(
    *,
    output_path: Path,
    clean_receipt: Mapping[str, object],
    private_receipt: Mapping[str, object],
    normalized_baseline_sha256: str,
    validation_candidate_sha256: str,
    checkout_sha256: str,
    active_release_sha256: str,
    active_membership_sha256: str,
    config_sha256: str,
    kernel_sha256: str,
    eligible_count: int,
    command_set_sha256: str,
) -> dict[str, object]:
    """Emit the final receipt after both current child receipts are validated."""

    hashes = (
        normalized_baseline_sha256,
        validation_candidate_sha256,
        checkout_sha256,
        active_release_sha256,
        active_membership_sha256,
        config_sha256,
        kernel_sha256,
        command_set_sha256,
    )
    if any(not _is_sha256(item) for item in hashes) or not 5 <= eligible_count <= 24:
        raise Phase5GateReceiptError("FINAL_SIGNOFF_CONTRACT_INVALID")
    _validate_gate(
        clean_receipt,
        gate="clean",
        schema_version=_CLEAN_SCHEMA_VERSION,
        expected_checkout_sha256=checkout_sha256,
        expected_command_set_sha256=CLEAN_COMMAND_SET_SHA256,
        expected_suite_ids=CLEAN_SUITE_IDS,
    )
    _validate_gate(
        private_receipt,
        gate="private",
        schema_version=_PRIVATE_SCHEMA_VERSION,
        expected_checkout_sha256=checkout_sha256,
        expected_command_set_sha256=PRIVATE_COMMAND_SET_SHA256,
        expected_suite_ids=PRIVATE_SUITE_IDS,
    )
    if any(
        clean_receipt.get(field) != private_receipt.get(field)
        or private_receipt.get(field) != expected
        for field, expected in (
            ("active_release_sha256", active_release_sha256),
            ("active_membership_sha256", active_membership_sha256),
            ("config_sha256", config_sha256),
            ("kernel_sha256", kernel_sha256),
            ("eligible_count", eligible_count),
        )
    ):
        raise Phase5GateReceiptError("FINAL_SIGNOFF_IDENTITY_MISMATCH")
    expected_command_set_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {"clean": CLEAN_COMMAND_SET_SHA256, "private": PRIVATE_COMMAND_SET_SHA256}
        )
    ).hexdigest()
    if command_set_sha256 != expected_command_set_sha256:
        raise Phase5GateReceiptError("FINAL_SIGNOFF_COMMAND_SET_MISMATCH")
    unsigned: dict[str, object] = {
        "schema_version": _FINAL_SCHEMA_VERSION,
        "gate": "final",
        "state": "GREEN",
        "checkout_sha256": checkout_sha256,
        "active_release_sha256": active_release_sha256,
        "active_membership_sha256": active_membership_sha256,
        "config_sha256": config_sha256,
        "kernel_sha256": kernel_sha256,
        "eligible_count": eligible_count,
        "normalized_baseline_sha256": normalized_baseline_sha256,
        "validation_candidate_sha256": validation_candidate_sha256,
        "clean_receipt_sha256": clean_receipt["receipt_sha256"],
        "private_receipt_sha256": private_receipt["receipt_sha256"],
        "command_set_sha256": command_set_sha256,
        "child_command_set_sha256": {
            "clean": clean_receipt["command_set_sha256"],
            "private": private_receipt["command_set_sha256"],
        },
    }
    receipt = _seal_receipt(unsigned)
    _write_canonical_atomic(output_path, receipt, mode=0o644)
    reopened = _load_canonical_object(output_path)
    if reopened != receipt:
        raise Phase5GateReceiptError("FINAL_RECEIPT_REOPEN_FAILED")
    return receipt


def finalize_validation_ledger(
    *,
    validation_path: Path,
    clean_receipt_path: Path,
    private_receipt_path: Path,
    explanation_review_path: Path,
    final_receipt_path: Path,
    finalization_record_path: Path,
    candidate_path: Path | None = None,
    expected_checkout_sha256: str | None = None,
    expected_active_release_sha256: str | None = None,
    expected_active_membership_sha256: str | None = None,
    allow_deferred_nonblocking_review: bool = True,
    failure_stage: str | None = None,
) -> dict[str, object]:
    """Run the receipt/candidate/swap transaction with baseline-only rollback."""

    baseline = normalize_validation_ledger(validation_path)
    if failure_stage == "after-normalization":
        raise Phase5ValidationTransactionError("FINALIZATION_INJECTED")
    clean = _load_canonical_object(clean_receipt_path)
    private = _load_canonical_object(private_receipt_path)
    release = _resolve_current_active_release_verification()
    if (
        expected_active_release_sha256 is not None
        and release["release_sha256"] != expected_active_release_sha256
    ):
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    if (
        expected_active_membership_sha256 is not None
        and release["membership_sha256"] != expected_active_membership_sha256
    ):
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    config_sha256, kernel_sha256 = _current_recommendation_identity()
    current_checkout_sha256 = _checkout_digest(_current_git_sha())
    if expected_checkout_sha256 is not None and expected_checkout_sha256 != current_checkout_sha256:
        raise Phase5GateReceiptError("CURRENT_CHECKOUT_INVALID")
    checkout_sha256 = current_checkout_sha256
    explanation_review = _load_canonical_object(explanation_review_path)
    validate_explanation_review(
        explanation_review,
        allow_deferred_nonblocking_review=allow_deferred_nonblocking_review,
    )
    if explanation_review.get("active_release_sha256") != release["release_sha256"]:
        raise Phase5GateReceiptError("EXPLANATION_REVIEW_RELEASE_MISMATCH")
    previous_final_receipt = (
        _read_regular_nofollow(final_receipt_path) if final_receipt_path.exists() else None
    )

    def restore_final_receipt() -> None:
        if previous_final_receipt is None:
            if final_receipt_path.exists():
                _require_no_symlink_ancestors(final_receipt_path)
                final_receipt_path.unlink()
        else:
            _write_bytes_atomic(final_receipt_path, previous_final_receipt, mode=0o644)

    validation_candidate = candidate_path or validation_path.with_name(
        f".{validation_path.name}.final-candidate"
    )
    if validation_candidate.parent != validation_path.parent:
        raise Phase5GateReceiptError("VALIDATION_CANDIDATE_PATH_INVALID")
    final_binding: dict[str, object] = {
        "schema_version": _FINAL_SCHEMA_VERSION,
        "state": "GREEN",
        "checkout_sha256": checkout_sha256,
        "active_release_sha256": release["release_sha256"],
        "active_membership_sha256": release["membership_sha256"],
        "config_sha256": config_sha256,
        "kernel_sha256": kernel_sha256,
        "eligible_count": release["eligible_count"],
    }
    # The candidate is generated before the final receipt; its digest breaks the cycle.
    candidate_payload = _candidate_validation_payload(
        baseline,
        clean_receipt=clean,
        private_receipt=private,
        final_binding={**final_binding, "final_receipt_sha256": "0" * 64},
    )
    _write_bytes_atomic(validation_candidate, candidate_payload, mode=0o644)
    candidate_digest = hashlib.sha256(candidate_payload).hexdigest()
    if failure_stage == "candidate":
        _write_bytes_atomic(validation_path, baseline.payload)
        raise Phase5ValidationTransactionError("FINALIZATION_INJECTED")
    final_receipt = emit_final_signoff_receipt(
        output_path=final_receipt_path,
        clean_receipt=clean,
        private_receipt=private,
        normalized_baseline_sha256=baseline.digest,
        validation_candidate_sha256=candidate_digest,
        checkout_sha256=checkout_sha256,
        active_release_sha256=str(release["release_sha256"]),
        active_membership_sha256=str(release["membership_sha256"]),
        config_sha256=config_sha256,
        kernel_sha256=kernel_sha256,
        eligible_count=cast(int, release["eligible_count"]),
        command_set_sha256=hashlib.sha256(
            canonical_json_bytes(
                {"clean": clean["command_set_sha256"], "private": private["command_set_sha256"]}
            )
        ).hexdigest(),
    )
    if failure_stage == "receipt":
        restore_final_receipt()
        _write_bytes_atomic(validation_path, baseline.payload)
        raise Phase5ValidationTransactionError("FINALIZATION_INJECTED")
    if not _validation_linkage_matches(
        candidate_payload, clean_receipt=clean, private_receipt=private
    ):
        restore_final_receipt()
        _write_bytes_atomic(validation_path, baseline.payload)
        raise Phase5GateReceiptError("VALIDATION_LINKAGE_MISMATCH")
    final_binding["final_receipt_sha256"] = final_receipt["receipt_sha256"]
    commit_unsigned: dict[str, object] = {
        "schema_version": _FINALIZATION_SCHEMA_VERSION,
        "state": "PREPARED",
        "normalized_baseline_sha256": baseline.digest,
        "validation_candidate_sha256": candidate_digest,
        "final_receipt_sha256": final_receipt["receipt_sha256"],
        "checkout_sha256": checkout_sha256,
        "active_release_sha256": release["release_sha256"],
        "active_membership_sha256": release["membership_sha256"],
        "config_sha256": config_sha256,
        "kernel_sha256": kernel_sha256,
    }
    prepared = _seal_receipt(commit_unsigned)
    try:
        _write_canonical_atomic(finalization_record_path, prepared, mode=0o644)
        if _load_canonical_object(finalization_record_path) != prepared:
            raise Phase5ValidationTransactionError("FINALIZATION_RECORD_REOPEN_FAILED")
        if failure_stage == "commit":
            raise Phase5ValidationTransactionError("FINALIZATION_INJECTED")
        os.replace(validation_candidate, validation_path)
        if failure_stage == "rename":
            raise Phase5ValidationTransactionError("FINALIZATION_INJECTED")
        installed = _read_regular_nofollow(validation_path, maximum_bytes=4 * 1024 * 1024)
        if (
            installed != candidate_payload
            or hashlib.sha256(installed).hexdigest() != candidate_digest
        ):
            raise Phase5ValidationTransactionError("VALIDATION_POST_SWAP_FAILED")
        if failure_stage == "post-swap":
            raise Phase5ValidationTransactionError("FINALIZATION_INJECTED")
        committed = _seal_receipt({**commit_unsigned, "state": "COMMITTED"})
        _write_canonical_atomic(finalization_record_path, committed, mode=0o644)
        if _load_canonical_object(finalization_record_path) != committed:
            raise Phase5ValidationTransactionError("FINALIZATION_RECORD_REOPEN_FAILED")
        return {
            "final_receipt": final_receipt,
            "finalization_record": committed,
            "validation_candidate_sha256": candidate_digest,
        }
    except BaseException:
        restore_final_receipt()
        _write_bytes_atomic(validation_path, baseline.payload, mode=0o644)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--clean-receipt", type=Path, required=True)
    parser.add_argument("--private-receipt", type=Path, required=True)
    parser.add_argument("--explanation-review", type=Path, required=True)
    parser.add_argument("--allow-deferred-nonblocking-review", action="store_true")
    parser.add_argument("--require-current-checkout", action="store_true")
    parser.add_argument("--require-green", action="store_true")
    return parser


def _emission_parser(*, private: bool) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkout-git-sha", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--duration-ms", type=int, required=True)
    parser.add_argument("--child", action="append", required=True)
    parser.add_argument("--release-verification", type=Path, required=True)
    return parser


def _finalization_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--clean-receipt", type=Path, required=True)
    parser.add_argument("--private-receipt", type=Path, required=True)
    parser.add_argument("--explanation-review", type=Path, required=True)
    parser.add_argument("--final-receipt", type=Path, required=True)
    parser.add_argument("--finalization-record", type=Path, required=True)
    parser.add_argument("--allow-deferred-nonblocking-review", action="store_true")
    return parser


def _pair_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-receipt", type=Path, required=True)
    parser.add_argument("--private-receipt", type=Path, required=True)
    return parser


def _children(values: Sequence[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        name, separator, raw_status = value.partition("=")
        if not separator or not name or name in result:
            raise Phase5GateReceiptError("GATE_CHILD_STATUS_INVALID")
        try:
            result[name] = int(raw_status)
        except ValueError as error:
            raise Phase5GateReceiptError("GATE_CHILD_STATUS_INVALID") from error
    return result


_PHASE5_SERVER_SOURCE_FILES = frozenset(
    {
        ".github/workflows/ci.yml",
        ".gitignore",
        ".python-version",
        "Makefile",
        "backend/pyproject.toml",
        "backend/uv.lock",
        "mise.toml",
        "web/next-env.d.ts",
        "web/next.config.ts",
        "web/package.json",
        "web/playwright.config.ts",
        "web/pnpm-lock.yaml",
        "web/postcss.config.mjs",
        "web/tsconfig.json",
    }
)
_PHASE5_SERVER_SOURCE_ROOTS = (
    "backend/migrations/",
    "backend/schema/",
    "backend/src/",
    "backend/tests/",
    "contracts/",
    "fixtures/preview/v1/",
    "fixtures/synthetic/phase5/",
    "web/e2e/",
    "web/src/",
)


def _is_phase5_server_source(path: str) -> bool:
    return path in _PHASE5_SERVER_SOURCE_FILES or path.startswith(_PHASE5_SERVER_SOURCE_ROOTS)


def _validate_git_sha(git_sha: str) -> None:
    if len(git_sha) not in (40, 64) or any(character not in _SHA256_CHARS for character in git_sha):
        raise Phase5GateReceiptError("CURRENT_CHECKOUT_INVALID")


def _checkout_digest(git_sha: str) -> str:
    """Bind receipts to the clean tracked source tree, not the evidence commit SHA."""

    _validate_git_sha(git_sha)
    changed: set[str] = set()
    for args in (("git", "diff", "--name-only"), ("git", "diff", "--cached", "--name-only")):
        changed.update(
            line
            for line in subprocess.run(
                args, check=True, capture_output=True, text=True
            ).stdout.splitlines()
            if line
        )
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    dirty_source = sorted(
        path for path in changed | set(untracked) if _is_phase5_server_source(path)
    )
    if dirty_source:
        raise Phase5GateReceiptError("SOURCE_SCOPE_DIRTY")
    rows = []
    for line in subprocess.run(
        ["git", "ls-files", "-s"], check=True, capture_output=True, text=True
    ).stdout.splitlines():
        metadata, path = line.split("\t", 1)
        if not _is_phase5_server_source(path):
            continue
        mode, blob_sha, stage = metadata.split()
        rows.append({"mode": mode, "blob_sha": blob_sha, "stage": stage, "path": path})
    return hashlib.sha256(canonical_json_bytes(rows)).hexdigest()


def _current_git_sha() -> str:
    value = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _validate_git_sha(value)
    return value


def _current_active_release_identity() -> tuple[str, str]:
    from itda.db.phase5_demo_release import PRODUCTION_ROOT, Phase5DemoReleaseStore

    snapshot = Phase5DemoReleaseStore(root=PRODUCTION_ROOT).resolve_active()
    if snapshot is None or len(snapshot.profiles) != 24:
        raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
    return snapshot.release_sha256, snapshot.membership_sha256


def _require_exact_cli_paths(args: argparse.Namespace) -> None:
    repository_root = Path(__file__).resolve().parents[4]
    exact = {
        "validation": repository_root
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-VALIDATION.md",
        "clean_receipt": repository_root / "artifacts/reports/phase5/clean-gate-receipt.json",
        "private_receipt": repository_root
        / "artifacts/restricted/catalog/phase5-demo-profile-materialization/gates"
        / "private-evidence-receipt.json",
        "explanation_review": repository_root
        / "artifacts/restricted/catalog/phase5-demo-profile-materialization/gates"
        / "korean-explanation-review.json",
    }
    optional_exact = {
        "final_receipt": repository_root / "artifacts/reports/phase5/final-signoff-receipt.json",
        "finalization_record": repository_root
        / "artifacts/reports/phase5/validation-finalization-commit.json",
    }
    for name, expected in exact.items():
        candidate = getattr(args, name)
        resolved = candidate if candidate.is_absolute() else repository_root / candidate
        if resolved.resolve(strict=False) != expected:
            raise Phase5GateReceiptError("CALLER_SELECTED_GATE_PATH_FORBIDDEN")
    for name, expected in optional_exact.items():
        candidate = getattr(args, name, None)
        if candidate is None:
            continue
        resolved = candidate if candidate.is_absolute() else repository_root / candidate
        if resolved.resolve(strict=False) != expected:
            raise Phase5GateReceiptError("CALLER_SELECTED_GATE_PATH_FORBIDDEN")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if arguments[:1] in (["emit-clean"], ["emit-private"]):
            private = arguments[0] == "emit-private"
            args = _emission_parser(private=private).parse_args(arguments[1:])
            checkout_sha256 = _checkout_digest(args.checkout_git_sha)
            children = _children(args.child)
            release_verification = _load_canonical_object(args.release_verification)
            if private:
                receipt = emit_private_gate_receipt(
                    output_path=args.output,
                    checkout_sha256=checkout_sha256,
                    checkout_git_sha=args.checkout_git_sha,
                    started_at=args.started_at,
                    completed_at=args.completed_at,
                    duration_ms=args.duration_ms,
                    child_exit_statuses=children,
                    release_verification=release_verification,
                )
            else:
                receipt = emit_clean_gate_receipt(
                    output_path=args.output,
                    checkout_sha256=checkout_sha256,
                    checkout_git_sha=args.checkout_git_sha,
                    started_at=args.started_at,
                    completed_at=args.completed_at,
                    duration_ms=args.duration_ms,
                    child_exit_statuses=children,
                    release_verification=release_verification,
                )
            sys.stdout.buffer.write(canonical_json_bytes(receipt) + b"\n")
            return 0

        if arguments[:1] == ["final-signoff"]:
            args = _finalization_parser().parse_args(arguments[1:])
            _require_exact_cli_paths(
                argparse.Namespace(
                    validation=args.validation,
                    clean_receipt=args.clean_receipt,
                    private_receipt=args.private_receipt,
                    explanation_review=args.explanation_review,
                    final_receipt=args.final_receipt,
                    finalization_record=args.finalization_record,
                )
            )
            report = finalize_validation_ledger(
                validation_path=args.validation,
                clean_receipt_path=args.clean_receipt,
                private_receipt_path=args.private_receipt,
                explanation_review_path=args.explanation_review,
                final_receipt_path=args.final_receipt,
                finalization_record_path=args.finalization_record,
                allow_deferred_nonblocking_review=args.allow_deferred_nonblocking_review,
            )
            sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
            return 0

        if arguments[:1] == ["current-release"]:
            if len(arguments) != 1:
                raise Phase5GateReceiptError("CALLER_SELECTED_RELEASE_FORBIDDEN")
            sys.stdout.buffer.write(
                canonical_json_bytes(_resolve_current_active_release_verification()) + b"\n"
            )
            return 0

        if arguments[:1] == ["current-pair"]:
            args = _pair_parser().parse_args(arguments[1:])
            clean_receipt = _load_canonical_object(args.clean_receipt)
            private_receipt = _load_canonical_object(args.private_receipt)
            _validate_gate(
                clean_receipt,
                gate="clean",
                schema_version=_CLEAN_SCHEMA_VERSION,
                expected_checkout_sha256=str(clean_receipt.get("checkout_sha256")),
                expected_command_set_sha256=CLEAN_COMMAND_SET_SHA256,
                expected_suite_ids=CLEAN_SUITE_IDS,
            )
            _validate_gate(
                private_receipt,
                gate="private",
                schema_version=_PRIVATE_SCHEMA_VERSION,
                expected_checkout_sha256=str(private_receipt.get("checkout_sha256")),
                expected_command_set_sha256=PRIVATE_COMMAND_SET_SHA256,
                expected_suite_ids=PRIVATE_SUITE_IDS,
            )
            identity_fields = (
                "checkout_sha256",
                "active_release_sha256",
                "active_membership_sha256",
                "config_sha256",
                "kernel_sha256",
                "eligible_count",
            )
            if any(
                clean_receipt.get(field) != private_receipt.get(field) for field in identity_fields
            ):
                raise Phase5GateReceiptError("GATE_PARENT_IDENTITY_MISMATCH")
            current_release = _resolve_current_active_release_verification()
            if any(
                clean_receipt.get(receipt_field) != current_release.get(release_field)
                for receipt_field, release_field in (
                    ("active_release_sha256", "release_sha256"),
                    ("active_membership_sha256", "membership_sha256"),
                    ("config_sha256", "config_sha256"),
                    ("kernel_sha256", "kernel_sha256"),
                    ("eligible_count", "eligible_count"),
                )
            ):
                raise Phase5GateReceiptError("PRIVATE_RELEASE_CONTRACT_MISMATCH")
            report = {
                "state": "GREEN",
                "checkout_sha256": clean_receipt.get("checkout_sha256"),
                "active_release_sha256": clean_receipt.get("active_release_sha256"),
                "active_membership_sha256": clean_receipt.get("active_membership_sha256"),
                "config_sha256": clean_receipt.get("config_sha256"),
                "kernel_sha256": clean_receipt.get("kernel_sha256"),
                "eligible_count": clean_receipt.get("eligible_count"),
            }
            sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
            return 0

        args = _parser().parse_args(arguments)
        if not args.require_current_checkout or not args.require_green:
            raise Phase5GateReceiptError("STRICT_SIGNOFF_FLAGS_REQUIRED")
        _require_exact_cli_paths(args)
        git_sha = _current_git_sha()
        active_release = _resolve_current_active_release_verification()
        report = signoff_gate_receipts(
            validation_path=args.validation,
            clean_receipt_path=args.clean_receipt,
            private_receipt_path=args.private_receipt,
            explanation_review_path=args.explanation_review,
            expected_checkout_sha256=_checkout_digest(git_sha),
            expected_clean_command_set_sha256=CLEAN_COMMAND_SET_SHA256,
            expected_private_command_set_sha256=PRIVATE_COMMAND_SET_SHA256,
            expected_clean_suite_ids=CLEAN_SUITE_IDS,
            expected_private_suite_ids=PRIVATE_SUITE_IDS,
            allow_deferred_nonblocking_review=args.allow_deferred_nonblocking_review,
            expected_active_release_sha256=str(active_release["release_sha256"]),
            expected_active_membership_sha256=str(active_release["membership_sha256"]),
            expected_config_sha256=str(active_release["config_sha256"]),
            expected_kernel_sha256=str(active_release["kernel_sha256"]),
            expected_eligible_count=cast(int, active_release["eligible_count"]),
        )
        sys.stdout.buffer.write(canonical_json_bytes(report) + b"\n")
        return 0
    except (
        OSError,
        Phase5GateReceiptError,
        subprocess.CalledProcessError,
        UnicodeDecodeError,
        ValueError,
    ):
        print("PHASE5_GATE_RECEIPTS_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CLEAN_COMMAND_SET_SHA256",
    "CLEAN_SUITE_IDS",
    "PRIVATE_COMMAND_SET_SHA256",
    "PRIVATE_SUITE_IDS",
    "Phase5GateReceiptError",
    "Phase5ValidationTransactionError",
    "ValidationBaseline",
    "emit_clean_gate_receipt",
    "emit_final_signoff_receipt",
    "emit_private_gate_receipt",
    "finalize_validation_ledger",
    "main",
    "normalize_validation_ledger",
    "signoff_gate_receipts",
    "validate_phase5_current_task_ids",
    "validate_phase5_executed_inventory",
    "validate_phase5_suite_registry",
    "phase5_suite_inventory",
    "PHASE5_CURRENT_TASK_IDS_V8",
    "PHASE5_FAILED_HISTORY_TASK_IDS",
    "PHASE5_HALTED_HISTORY_TASK_IDS",
    "PHASE5_CURRENT_TASK_LEDGER_SHA256",
    "validate_phase5_current_task_ledger",
    "validate_phase5_failed_history_rows",
    "validate_phase5_halted_history_rows",
    "PHASE5_SUITE_COMMAND_SET_SHA256",
    "PHASE5_SUITE_REGISTRY_SHA256",
    "PHASE5_SUITE_REGISTRY_V4",
    "_resolve_current_active_release_verification",
    "_validate_active_release_verification",
    "validate_explanation_review",
]
