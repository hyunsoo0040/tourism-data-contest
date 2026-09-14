"""Optional measured-gate bootstrap for the disposable, offline local test runtime."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path

from itda.contracts.grounded_promotion import (
    GroundedPromotionGate,
    GroundedPromotionReport,
    validate_promotion_reports,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY
from itda.db.assessment_release import AssessmentReleaseRepository
from itda.db.session import create_database_engine, create_session_factory

BOOTSTRAP_PATH_ENV = (
    "ITDA_E2E_GROUNDED_CANDIDATE_FILE",
    "ITDA_E2E_GROUNDED_GATE_FILE",
    "ITDA_E2E_GROUNDED_REPORT_DIR",
)


def _read_regular(path: Path, *, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
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


def bootstrap_grounded_preview(environment: Mapping[str, str], *, admin_dsn: str) -> dict[str, str]:
    """Validate every file before DB access and return only server-owned child flags.

    The generated admin DSN remains in this parent process. No activation is
    possible without all three candidate-bound measured report bodies.
    """
    values = tuple(environment.get(name, "") for name in BOOTSTRAP_PATH_ENV)
    if not any(values):
        return {}
    engine = None
    try:
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("grounded preview needs its complete artifact triplet")
        if environment.get("ITDA_NO_NETWORK") != "1":
            raise ValueError("grounded preview must keep the offline boundary")
        candidate_path, gate_path, report_dir = (Path(value).expanduser() for value in values)
        candidate = GroundedReleaseCandidate.model_validate_json(
            _read_regular(candidate_path, maximum=64 * 1024 * 1024)
        )
        gate = GroundedPromotionGate.model_validate_json(
            _read_regular(gate_path, maximum=1024 * 1024)
        )
        if (
            gate.candidate_sha256 != candidate.candidate_sha256
            or gate.config_sha256 != GROUNDED_POLICY.sha256
        ):
            raise ValueError("preview gate does not bind the selected candidate and current policy")
        if report_dir.is_symlink() or not report_dir.is_dir():
            raise ValueError("preview report directory must be regular")
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
        # No generated credential, engine or mutation exists above this point.
        engine = create_database_engine(admin_dsn)
        store = AssessmentReleaseRepository(create_session_factory(engine))
        current = store.load_active()
        store.stage(candidate)
        for report in reports:
            store.store_report(report)
        store.promote(gate, expected_active_sha256=current.candidate_sha256 if current else None)
        active = store.load_active_record()
        if active is None or active.candidate != candidate or active.gate != gate:
            raise ValueError("grounded preview activation did not read back identically")
        return {
            "ITDA_GROUNDED_RECOMMENDATIONS_ENABLED": "1",
            "ITDA_PHOTO_MOOD_ENABLED": "1",
            "ITDA_TOURISM_ENABLED": "0",
            "ITDA_NO_NETWORK": "1",
        }
    except Exception:
        # Artifact/parser/SQL errors can contain paths, response text or DSNs;
        # diagnostics expose one closed message, never the original exception.
        raise RuntimeError("grounded offline preview bootstrap rejected") from None
    finally:
        if engine is not None:
            engine.dispose()
