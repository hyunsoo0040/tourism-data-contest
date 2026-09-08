"""Build, publish, or verify the offline REINF-18 grammar successor."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from itda.contracts.catalog_enrichment import canonical_json_bytes
from itda.contracts.catalog_grammar_successor import (
    GrammarSuccessorIssuance,
    build_grammar_correction_successor,
    build_grammar_correction_supersession,
    publish_grammar_correction_successor,
    publish_grammar_correction_supersession,
    verify_published_grammar_correction_successor,
    verify_published_grammar_correction_supersession,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan the exact offline TourAPI grammar-correction successor."
    )
    parser.add_argument("--predecessor-round-root", type=Path, required=True)
    parser.add_argument("--predecessor-round-id", required=True)
    parser.add_argument("--round-roots-manifest", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--publish", action="store_true")
    modes.add_argument(
        "--verify-published",
        nargs=2,
        metavar=("CORRECTION_ROOT", "SUCCESSOR_ROOT"),
        type=Path,
    )
    modes.add_argument(
        "--supersede-invalid",
        nargs=2,
        metavar=("INVALID_CORRECTION_ROOT", "INVALID_SUCCESSOR_ROOT"),
        type=Path,
    )
    modes.add_argument(
        "--verify-supersession",
        nargs=4,
        metavar=(
            "INVALID_CORRECTION_ROOT",
            "INVALID_SUCCESSOR_ROOT",
            "SUPERSESSION_ROOT",
            "SUCCESSOR_ROOT",
        ),
        type=Path,
    )
    return parser


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _issuance() -> GrammarSuccessorIssuance:
    issued_at = datetime.now(UTC)
    source = Path(__file__).read_bytes()
    return GrammarSuccessorIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=7),
        nonce=secrets.token_hex(32),
        reviewer_id="phase2-operator",
        code_sha256=_sha256(source),
        config_sha256=_sha256(b"itda.catalog-grammar-successor.config.v1"),
    )


def _safe_output(successor: object) -> dict[str, object]:
    report = successor.correction_report
    bundle = successor.bundle
    return {
        "status": "BUILT_OFFLINE_NO_AUTHORITY",
        "correction_report_sha256": report.report_sha256,
        "correction_count": report.correction_count,
        "provider_candidate_count": report.provider_candidate_count,
        "successor_round_id": bundle.round_id,
        "successor_round_root": bundle.round_root.as_posix(),
        "request_count": bundle.plan["request_count"],
        "quota_estimate": bundle.plan["quota_estimate"],
        "overall_timeout_seconds": bundle.plan["overall_timeout_seconds"],
        "authority_token_issued": bundle.authorization_request[
            "authority_token_issued"
        ],
        "artifact_sha256": {
            name: _sha256(payload)
            for name, payload in sorted(
                {
                    "grammar-correction-report.json": canonical_json_bytes(
                        report.model_dump(mode="json")
                    ),
                    "remediation-candidate-pool.json": canonical_json_bytes(
                        successor.remediation_pool
                    ),
                    **bundle.files,
                }.items()
            )
        },
    }


def _safe_supersession_output(supersession: object) -> dict[str, object]:
    report = supersession.supersession_report
    bundle = supersession.bundle
    return {
        "status": "BUILT_SUPERSESSION_OFFLINE_NO_AUTHORITY",
        "supersession_report_sha256": report.report_sha256,
        "invalid_correction_report_sha256": (
            report.invalid_correction_report_sha256
        ),
        "invalid_successor_round_id": report.invalid_successor_round_id,
        "successor_round_id": bundle.round_id,
        "successor_round_root": bundle.round_root.as_posix(),
        "request_count": bundle.plan["request_count"],
        "quota_estimate": bundle.plan["quota_estimate"],
        "overall_timeout_seconds": bundle.plan["overall_timeout_seconds"],
        "authority_token_issued": bundle.authorization_request[
            "authority_token_issued"
        ],
        "artifact_sha256": {
            "grammar-successor-supersession.json": _sha256(
                canonical_json_bytes(report.model_dump(mode="json"))
            ),
            "remediation-candidate-pool.json": _sha256(
                canonical_json_bytes(supersession.remediation_pool)
            ),
            **{
                name: _sha256(payload)
                for name, payload in sorted(bundle.files.items())
            },
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.verify_published is not None:
        correction_root, successor_root = args.verify_published
        verify_published_grammar_correction_successor(
            predecessor_round_root=args.predecessor_round_root,
            predecessor_round_id=args.predecessor_round_id,
            round_roots_manifest=args.round_roots_manifest,
            correction_root=correction_root,
            successor_root=successor_root,
        )
        print(
            json.dumps(
                {
                    "status": "VERIFIED_OFFLINE_NO_AUTHORITY",
                    "correction_root": correction_root.as_posix(),
                    "successor_root": successor_root.as_posix(),
                },
                sort_keys=True,
            )
        )
        return 0

    if args.verify_supersession is not None:
        (
            invalid_correction_root,
            invalid_successor_root,
            supersession_root,
            successor_root,
        ) = args.verify_supersession
        verify_published_grammar_correction_supersession(
            predecessor_round_root=args.predecessor_round_root,
            predecessor_round_id=args.predecessor_round_id,
            round_roots_manifest=args.round_roots_manifest,
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            supersession_root=supersession_root,
            successor_root=successor_root,
        )
        print(
            json.dumps(
                {
                    "status": "VERIFIED_SUPERSESSION_OFFLINE_NO_AUTHORITY",
                    "invalid_correction_root": invalid_correction_root.as_posix(),
                    "invalid_successor_root": invalid_successor_root.as_posix(),
                    "supersession_root": supersession_root.as_posix(),
                    "successor_root": successor_root.as_posix(),
                },
                sort_keys=True,
            )
        )
        return 0

    issuance = _issuance()
    rounds_root = args.predecessor_round_root.resolve(strict=True).parent
    if args.supersede_invalid is not None:
        invalid_correction_root, invalid_successor_root = args.supersede_invalid
        first_supersession = build_grammar_correction_supersession(
            predecessor_round_root=args.predecessor_round_root,
            predecessor_round_id=args.predecessor_round_id,
            round_roots_manifest=args.round_roots_manifest,
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=rounds_root,
            issuance=issuance,
        )
        second_supersession = build_grammar_correction_supersession(
            predecessor_round_root=args.predecessor_round_root,
            predecessor_round_id=args.predecessor_round_id,
            round_roots_manifest=args.round_roots_manifest,
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=rounds_root,
            issuance=issuance,
        )
        first_output = canonical_json_bytes(
            _safe_supersession_output(first_supersession)
        )
        second_output = canonical_json_bytes(
            _safe_supersession_output(second_supersession)
        )
        if (
            first_output != second_output
            or first_supersession.bundle.files
            != second_supersession.bundle.files
        ):
            raise ValueError("frozen grammar supersession is not byte deterministic")
        result = _safe_supersession_output(first_supersession)
        supersession_root = (
            rounds_root.parent
            / "grammar-successor-supersessions"
            / invalid_successor_root.name
            / first_supersession.supersession_report.report_sha256
        )
        publish_grammar_correction_supersession(
            first_supersession,
            supersession_root=supersession_root,
        )
        result["supersession_root"] = supersession_root.as_posix()
        result["status"] = "PUBLISHED_SUPERSESSION_OFFLINE_NO_AUTHORITY"
        print(json.dumps(result, sort_keys=True))
        return 0

    first = build_grammar_correction_successor(
        predecessor_round_root=args.predecessor_round_root,
        predecessor_round_id=args.predecessor_round_id,
        round_roots_manifest=args.round_roots_manifest,
        rounds_root=rounds_root,
        issuance=issuance,
    )
    second = build_grammar_correction_successor(
        predecessor_round_root=args.predecessor_round_root,
        predecessor_round_id=args.predecessor_round_id,
        round_roots_manifest=args.round_roots_manifest,
        rounds_root=rounds_root,
        issuance=issuance,
    )
    first_output = canonical_json_bytes(_safe_output(first))
    second_output = canonical_json_bytes(_safe_output(second))
    if first_output != second_output or first.bundle.files != second.bundle.files:
        raise ValueError("frozen grammar successor build is not byte deterministic")
    result = _safe_output(first)
    correction_root = (
        rounds_root.parent
        / "grammar-corrections"
        / first.correction_report.report_sha256
    )
    result["correction_root"] = correction_root.as_posix()
    if args.publish:
        publish_grammar_correction_successor(
            first,
            correction_root=correction_root,
        )
        result["status"] = "PUBLISHED_OFFLINE_NO_AUTHORITY"
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
