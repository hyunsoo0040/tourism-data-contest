"""Regression contract for the archived Phase 5 historical authority paths.

Commit ``c43b58e`` moved the frozen ``05-16-PLAN.md`` / ``05-16-SUMMARY.md``
planning artifacts from the active phase directory into the v1.0 milestone
archive.  The recovery policy must therefore read its two historical public
sources from ``.planning/milestones/v1.0-phases/`` while keeping the frozen
digests, the regular-file boundary, and the single-path (no fallback)
authority exactly as before.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_historical_paths_resolve_inside_the_v1_milestone_archive() -> None:
    from itda.contracts.phase5_recovery_policy import (
        HISTORICAL_05_16_PLAN_PATH,
        HISTORICAL_05_16_SUMMARY_PATH,
        REPOSITORY_ROOT,
    )

    assert _repository_root() == REPOSITORY_ROOT
    archive = (
        REPOSITORY_ROOT
        / ".planning/milestones/v1.0-phases/05-complete-no-photo-recommendation-journey"
    )
    assert (archive / "05-16-PLAN.md") == HISTORICAL_05_16_PLAN_PATH
    assert (archive / "05-16-SUMMARY.md") == HISTORICAL_05_16_SUMMARY_PATH
    # The old phase-directory location must stay absent so a silent regression
    # to pre-archive paths is caught by the file-existence assertions below.
    legacy_dir = (
        REPOSITORY_ROOT / ".planning/phases/05-complete-no-photo-recommendation-journey"
    )
    assert not (legacy_dir / "05-16-PLAN.md").exists()
    assert not (legacy_dir / "05-16-SUMMARY.md").exists()
    # Single-path authority: the constants must point at regular files only.
    assert HISTORICAL_05_16_PLAN_PATH.is_file()
    assert not HISTORICAL_05_16_PLAN_PATH.is_symlink()
    assert HISTORICAL_05_16_SUMMARY_PATH.is_file()
    assert not HISTORICAL_05_16_SUMMARY_PATH.is_symlink()


def test_frozen_05_16_digests_validate_through_the_policy_reader() -> None:
    from itda.contracts.phase5_recovery_policy import (
        HISTORICAL_05_16_PLAN_PATH,
        HISTORICAL_05_16_PLAN_SHA256,
        HISTORICAL_05_16_SUMMARY_PATH,
        HISTORICAL_05_16_SUMMARY_SHA256,
        _historical_file_sha256,
    )

    assert (
        _historical_file_sha256(HISTORICAL_05_16_PLAN_PATH, HISTORICAL_05_16_PLAN_SHA256)
        == HISTORICAL_05_16_PLAN_SHA256
    )
    assert (
        _historical_file_sha256(
            HISTORICAL_05_16_SUMMARY_PATH, HISTORICAL_05_16_SUMMARY_SHA256
        )
        == HISTORICAL_05_16_SUMMARY_SHA256
    )
    # Independent recomputation binds the constants to the archived bytes.
    assert hashlib.sha256(HISTORICAL_05_16_PLAN_PATH.read_bytes()).hexdigest() == (
        HISTORICAL_05_16_PLAN_SHA256
    )
    assert hashlib.sha256(HISTORICAL_05_16_SUMMARY_PATH.read_bytes()).hexdigest() == (
        HISTORICAL_05_16_SUMMARY_SHA256
    )


def test_canonical_policy_import_passes_historical_validation() -> None:
    """Import-time construction succeeds against the archive in a clean tree."""

    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_PHASE5_RECOVERY_POLICY,
        HISTORICAL_05_16_PLAN_SHA256,
        HISTORICAL_05_16_SUMMARY_SHA256,
    )

    assert (
        CANONICAL_PHASE5_RECOVERY_POLICY.historical_05_16_plan_sha256
        == HISTORICAL_05_16_PLAN_SHA256
    )
    assert (
        CANONICAL_PHASE5_RECOVERY_POLICY.historical_05_16_summary_sha256
        == HISTORICAL_05_16_SUMMARY_SHA256
    )
    assert CANONICAL_PHASE5_RECOVERY_POLICY.policy_sha256  # self-digest present


def test_tampered_archive_bytes_still_fail_closed(tmp_path: Path) -> None:
    """The bounded reader keeps rejecting drift after the path re-point."""

    from itda.contracts.phase5_recovery_policy import (
        HISTORICAL_05_16_PLAN_SHA256,
        _historical_file_sha256,
    )

    forged = tmp_path / "05-16-PLAN.md"
    forged.write_bytes(b"tampered planning prose\n")
    with pytest.raises(ValueError, match="historical public artifact drifted"):
        _historical_file_sha256(forged, HISTORICAL_05_16_PLAN_SHA256)
