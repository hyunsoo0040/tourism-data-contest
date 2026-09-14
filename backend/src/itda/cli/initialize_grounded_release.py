"""Initialize an empty production store from a complete, measured release bundle."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sqlalchemy.exc import DBAPIError

from itda.catalog_paths import NATIONAL_CURRENT_DIRECTORY, is_national_candidate
from itda.contracts.grounded_promotion import (
    GroundedPromotionGate,
    GroundedPromotionReport,
    validate_promotion_reports,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY
from itda.db.assessment_release import ActiveGroundedRelease, AssessmentReleaseRepository
from itda.db.session import create_database_engine, create_session_factory

INITIAL_PATH_ENV = (
    "ITDA_GROUNDED_INITIAL_CANDIDATE_FILE",
    "ITDA_GROUNDED_INITIAL_GATE_FILE",
    "ITDA_GROUNDED_INITIAL_REPORT_DIR",
)
DEFAULT_BUNDLE_DIRECTORY = NATIONAL_CURRENT_DIRECTORY


@dataclass(frozen=True, slots=True)
class InitialGroundedReleaseStatus:
    state: Literal["initialized", "retained"]
    candidate_sha256: str
    gate_sha256: str
    generation: int


def _read_regular(path: Path, *, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ValueError("invalid grounded artifact file")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise ValueError("grounded artifact changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("grounded artifact identity changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _ready(
    active: ActiveGroundedRelease | None, *, state: Literal["initialized", "retained"]
) -> InitialGroundedReleaseStatus:
    # Repository reads already revalidate the candidate, gate and actual report
    # bodies. Policy compatibility is a server decision, never a bundle override.
    if (
        active is None
        or active.gate.config_sha256 != GROUNDED_POLICY.sha256
        or not is_national_candidate(active.candidate)
    ):
        raise ValueError("no compatible active grounded release")
    return InitialGroundedReleaseStatus(
        state, active.candidate.candidate_sha256, active.gate.gate_sha256, active.generation
    )


def ensure_initial_grounded_release(
    environment: Mapping[str, str], *, admin_dsn: str
) -> InitialGroundedReleaseStatus:
    """Keep verified active authority, or seed an empty store with measured reports.

    A concurrent publisher always wins over the bundled initial candidate. No
    report, gate, placeholder result or provider inference is generated here.
    """
    engine = None
    try:
        engine = create_database_engine(admin_dsn)
        store = AssessmentReleaseRepository(create_session_factory(engine))
        current = store.load_active_record()
        if current is not None:
            return _ready(current, state="retained")

        values = tuple(environment.get(name, "").strip() for name in INITIAL_PATH_ENV)
        if any(name in environment for name in INITIAL_PATH_ENV):
            if not all(values):
                raise ValueError("initial grounded release requires all three artifact paths")
            candidate_path, gate_path, report_dir = (Path(value).expanduser() for value in values)
        else:
            candidate_path = DEFAULT_BUNDLE_DIRECTORY / "candidate.json"
            gate_path = DEFAULT_BUNDLE_DIRECTORY / "gate.json"
            report_dir = DEFAULT_BUNDLE_DIRECTORY / "reports"
        candidate = GroundedReleaseCandidate.model_validate_json(
            _read_regular(candidate_path, maximum=64 * 1024 * 1024)
        )
        gate = GroundedPromotionGate.model_validate_json(
            _read_regular(gate_path, maximum=1024 * 1024)
        )
        if (
            not is_national_candidate(candidate)
            or gate.candidate_sha256 != candidate.candidate_sha256
            or gate.config_sha256 != GROUNDED_POLICY.sha256
        ):
            raise ValueError("initial gate does not bind the candidate and current policy")
        if report_dir.is_symlink() or not report_dir.is_dir():
            raise ValueError("initial report directory must be regular")
        reports = tuple(
            GroundedPromotionReport.model_validate_json(
                _read_regular(report_dir / (digest + ".json"), maximum=32 * 1024 * 1024)
            )
            for digest in (
                gate.source_ablation_sha256,
                gate.axis_comparison_sha256,
                gate.api_ui_verification_sha256,
            )
        )
        validate_promotion_reports(gate, reports, candidate_created_at=candidate.created_at)

        # Every artifact and cross-reference above must pass before any mutation.
        store.stage(candidate)
        for report in reports:
            store.store_report(report)
        try:
            generation = store.promote(gate, expected_active_sha256=None)
        except DBAPIError as error:
            if getattr(error.orig, "sqlstate", None) != "40001":
                raise
            return _ready(store.load_active_record(), state="retained")
        promoted = store.load_promotion(generation)
        if promoted is None or promoted.candidate != candidate or promoted.gate != gate:
            raise ValueError("initial promotion did not read back identically")
        active = store.load_active_record()
        return _ready(
            active,
            state="initialized"
            if active is not None and active.generation == generation
            else "retained",
        )
    except Exception:
        # Parser and SQL exceptions can contain artifact contents, paths or DSNs.
        raise RuntimeError("initial grounded release initialization rejected") from None
    finally:
        if engine is not None:
            engine.dispose()
