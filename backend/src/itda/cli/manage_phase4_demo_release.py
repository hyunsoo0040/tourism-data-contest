"""Manage the isolated Phase 4 SQLite contest-demo evidence lifecycle."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from itda.db.phase4_demo_release import (
    LOCAL_APPROVAL_MARKER,
    LOCAL_SQLITE_MARKER,
    Phase4DemoReleaseRepository,
    initialize_demo_release,
    verify_demo_release,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("initialize", "status", "exercise-lifecycle", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--terminal-receipt", required=True, type=Path)
        command.add_argument("--artifact-root", required=True, type=Path)
        if name == "exercise-lifecycle":
            command.add_argument("--final-state", required=True, choices=("successor",))
        if name == "verify":
            command.add_argument("--receipt-output", required=True, type=Path)
    return parser


def _safe_result(result: dict[str, object]) -> dict[str, object]:
    allowed = {
        "active_release_sha256",
        "activation_receipt_sha256",
        "approval_receipt_sha256",
        "database_sha256",
        "disposition",
        "foreign_key_check_count",
        "generation",
        "image_truth",
        "integrity_check",
        "manifest_sha256",
        "pin_inventory_sha256",
        "predecessor_sha256",
        "profile_score_truth",
        "profile_truth",
        "provider_mode",
        "production_mutation",
        "receipt_count",
        "receipt_inventory_sha256",
        "receipt_sha256",
        "receipt_type_counts",
        "result_pin_count",
        "reactivation_receipt_sha256",
        "rollback_receipt_sha256",
        "session_pin_count",
        "source_truth",
        "successor_sha256",
        "successor_state",
        "terminal_decision",
        "terminal_report_sha256",
        "transition_count",
        "upstream_terminal_receipt_sha256",
    }
    return {
        **{key: value for key, value in result.items() if key in allowed},
        "local_storage_scope": LOCAL_SQLITE_MARKER,
        "approval_authority": LOCAL_APPROVAL_MARKER,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "initialize":
        result = initialize_demo_release(
            terminal_receipt_path=args.terminal_receipt,
            artifact_root=args.artifact_root,
        )
    elif args.command == "status":
        repository = Phase4DemoReleaseRepository.from_terminal_receipt(
            terminal_receipt_path=args.terminal_receipt,
            artifact_root=args.artifact_root,
        )
        result = repository.status(create_receipt=False)
    elif args.command == "exercise-lifecycle":
        repository = Phase4DemoReleaseRepository.from_terminal_receipt(
            terminal_receipt_path=args.terminal_receipt,
            artifact_root=args.artifact_root,
        )
        result = repository.exercise_lifecycle(final_state=args.final_state)
    elif args.command == "verify":
        result = verify_demo_release(
            terminal_receipt_path=args.terminal_receipt,
            artifact_root=args.artifact_root,
            receipt_output=args.receipt_output,
        )
    else:  # pragma: no cover
        raise AssertionError("unreachable local demo command")
    print(
        json.dumps(
            _safe_result(result),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
