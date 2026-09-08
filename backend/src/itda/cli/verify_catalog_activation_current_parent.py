"""Diagnose and verify the versioned catalog activation current parent."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from itda.contracts.catalog_activation_current_parent import (
    HISTORICAL_PROOF_COMMIT,
    build_current_parent_attestation,
    capture_protected_manifest_file,
    compare_protected_manifest_files,
    diagnose_current_parent,
    verify_current_parent_attestation_file,
    verify_protected_manifest_file,
)
from itda.domain.canonical import canonical_json_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--capture-protected-manifest", type=Path, metavar="MANIFEST")
    mode.add_argument("--verify-protected-manifest", type=Path, metavar="MANIFEST")
    mode.add_argument(
        "--compare-protected-manifests",
        nargs=2,
        type=Path,
        metavar=("BEFORE", "AFTER"),
    )
    mode.add_argument("--diagnose-current-parent", type=Path, metavar="EVENT")
    mode.add_argument(
        "--build-current-parent-attestation",
        type=Path,
        metavar="ATTESTATION",
    )
    mode.add_argument(
        "--verify-current-parent-attestation",
        type=Path,
        metavar="ATTESTATION",
    )
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--plan-id")
    parser.add_argument("--stage", choices=("before", "after"))
    parser.add_argument("--historical-proof-commit", default=HISTORICAL_PROOF_COMMIT)
    parser.add_argument("--event", type=Path)
    parser.add_argument("--protected-before", type=Path)
    parser.add_argument("--protected-after", type=Path)
    parser.add_argument("--require-current", action="store_true")
    parser.add_argument("--require-exact", action="store_true")
    return parser


def _root(value: Path | None) -> Path:
    return value.resolve(strict=True) if value is not None else Path(__file__).resolve().parents[4]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _root(args.repository_root)
    if args.capture_protected_manifest is not None:
        if args.plan_id is None or args.stage is None:
            raise ValueError("protected capture requires --plan-id and --stage")
        manifest = capture_protected_manifest_file(
            root,
            args.capture_protected_manifest,
            plan_id=args.plan_id,
            stage=args.stage,
        )
        print(manifest["protected_manifest_sha256"])
        return 0
    if args.verify_protected_manifest is not None:
        if args.plan_id is None or args.stage is None:
            raise ValueError("protected verification requires --plan-id and --stage")
        manifest = verify_protected_manifest_file(
            root,
            args.verify_protected_manifest,
            plan_id=args.plan_id,
            stage=args.stage,
        )
        print(manifest["protected_manifest_sha256"])
        return 0
    if args.compare_protected_manifests is not None:
        if not args.require_exact:
            raise ValueError("protected comparison requires --require-exact")
        print(
            compare_protected_manifest_files(
                root,
                args.compare_protected_manifests[0],
                args.compare_protected_manifests[1],
            )
        )
        return 0
    if args.build_current_parent_attestation is not None:
        if args.event is None or args.protected_before is None:
            raise ValueError("attestation build requires --event and --protected-before")
        attestation = build_current_parent_attestation(
            root,
            args.build_current_parent_attestation,
            args.event,
            args.protected_before,
            historical_proof_commit=args.historical_proof_commit,
        )
        print(attestation.attestation_sha256)
        return 0
    if args.verify_current_parent_attestation is not None:
        if args.event is None or not args.require_current:
            raise ValueError("attestation verification requires --event and --require-current")
        attestation = verify_current_parent_attestation_file(
            root,
            args.verify_current_parent_attestation,
            args.event,
            require_current=True,
            protected_before_path=args.protected_before,
            protected_after_path=args.protected_after,
        )
        print(attestation.attestation_sha256)
        return 0
    if args.diagnose_current_parent is None:
        raise ValueError("current-parent diagnostic mode is missing")
    diagnosis = diagnose_current_parent(
        root,
        args.diagnose_current_parent,
        historical_proof_commit=args.historical_proof_commit,
    )
    print(canonical_json_bytes(diagnosis.model_dump(mode="json")).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
