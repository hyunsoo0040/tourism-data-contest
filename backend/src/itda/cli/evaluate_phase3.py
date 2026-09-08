"""Write canonical aggregate-only Phase 3 synthetic threshold reports."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from pydantic import ValidationError

from itda.contracts.phase3_evaluation import (
    Phase3EvaluationManifest,
    build_evaluation_report,
)
from itda.domain.canonical import canonical_json_bytes

_MAX_MANIFEST_BYTES = 1_000_000
_FORBIDDEN_KEY_PARTS = (
    "individual_label",
    "evaluator_identity",
    "membership",
    "restricted_location",
    "source_text",
    "expert_agreement_claim",
    "retrieval_quality_claim",
)


def _safe_read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_MANIFEST_BYTES
        ):
            raise ValueError("evaluation manifest must be a bounded single-link regular file")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise OSError("evaluation manifest changed during verification")
        return payload
    finally:
        os.close(descriptor)


def _reject_prohibited_keys(value: object) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, nested in current.items():
                folded = str(key).casefold()
                if any(part in folded for part in _FORBIDDEN_KEY_PARTS):
                    raise ValueError("evaluation manifest contains prohibited protected input")
                stack.append(nested)
        elif isinstance(current, list):
            stack.extend(current)


def _write_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--assert-thresholds", action="store_true")
    parser.add_argument("--report", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.assert_thresholds:
        raise SystemExit("evaluation requires --assert-thresholds")
    try:
        raw = _safe_read(args.manifest)
        parsed = json.loads(raw)
        _reject_prohibited_keys(parsed)
        manifest = Phase3EvaluationManifest.model_validate(parsed)
        if raw != canonical_json_bytes(manifest.model_dump(mode="json")):
            raise ValueError("evaluation manifest is not canonical JSON")
        report = build_evaluation_report(manifest)
        _write_no_replace(args.report, canonical_json_bytes(report.model_dump(mode="json")))
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        raise SystemExit("phase3 evaluation rejected invalid aggregate input") from exc
    return 0 if report.status == "THRESHOLDS_PASSED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
