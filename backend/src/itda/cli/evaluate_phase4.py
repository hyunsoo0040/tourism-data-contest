"""Provider-free Phase 4 benchmark evaluator and immutable report writer."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from pydantic import ValidationError

from itda.contracts.base import StrictContract
from itda.contracts.phase4_benchmark import (
    BenchmarkAuthorityBinding,
    BenchmarkReportState,
    FinalizationInput,
    ProvisionalEvaluationInput,
    build_provisional_report,
    finalize_benchmark,
)
from itda.domain.canonical import canonical_json_bytes

_MAX_INPUT_BYTES = 8_000_000
_PROTECTED_AUTHORITY_ROOT = Path("/var/lib/itda/phase4-benchmark-authority")


def _require_protected_authority_path(path: Path, *, artifact_name: str) -> None:
    expected = _PROTECTED_AUTHORITY_ROOT / artifact_name
    if path != expected:
        raise PermissionError(
            "protected benchmark inputs must resolve from the server-held authority root"
        )


def safe_read_canonical(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_INPUT_BYTES
        ):
            raise ValueError("benchmark input must be a bounded single-link regular file")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError("benchmark input changed during verification")
        return payload
    finally:
        os.close(descriptor)


def write_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-authority", action="store_true")
    mode.add_argument("--provisional", action="store_true")
    mode.add_argument("--finalize", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = safe_read_canonical(args.manifest)
        if args.verify_authority:
            authority = BenchmarkAuthorityBinding.model_validate_json(raw)
            report: StrictContract = authority
            exit_code = 0
        elif args.provisional:
            provisional_input = ProvisionalEvaluationInput.model_validate_json(raw)
            if provisional_input.experiment.evaluation_scope == "DEV_24_PROTECTED":
                _require_protected_authority_path(
                    args.manifest,
                    artifact_name="provisional-input.json",
                )
            report = build_provisional_report(
                experiment=provisional_input.experiment,
                cases=provisional_input.cases,
                review_inventory=provisional_input.review_inventory,
                sensitivity=provisional_input.sensitivity,
                generated_at=provisional_input.generated_at,
            )
            exit_code = 3
        else:
            finalization_input = FinalizationInput.model_validate_json(raw)
            if finalization_input.provisional.experiment.evaluation_scope == "DEV_24_PROTECTED":
                _require_protected_authority_path(
                    args.manifest,
                    artifact_name="finalization-input.json",
                )
            decision = finalize_benchmark(
                provisional=finalization_input.provisional,
                selected_config_sha256=finalization_input.selected_config_sha256,
                human_review=finalization_input.human_review,
                zero_image_fallback=finalization_input.zero_image_fallback,
                external_evidence_complete=finalization_input.external_evidence_complete,
                finalized_at=finalization_input.finalized_at,
            )
            report = decision
            exit_code = (
                0
                if decision.state
                in {
                    BenchmarkReportState.ADOPT,
                    BenchmarkReportState.CONDITIONAL_ADOPT,
                    BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY,
                    BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY,
                }
                else 2
            )
        canonical = canonical_json_bytes(report.model_dump(mode="json"))
        if raw != canonical and args.verify_authority:
            raise ValueError("benchmark authority is not canonical JSON")
        write_no_replace(args.report, canonical)
    except (OSError, PermissionError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        raise SystemExit("phase4 evaluator rejected invalid authority") from exc
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "safe_read_canonical", "write_no_replace"]
