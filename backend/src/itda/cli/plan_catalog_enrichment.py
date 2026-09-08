"""Build and verify the immutable Phase 2 TourAPI enrichment authority bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from itda.contracts.catalog_enrichment import (
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    build_enrichment_plan,
    canonical_json_bytes,
    publish_enrichment_bundle,
    validate_round_pair,
    verify_authorization_preconditions,
    verify_enrichment_bundle,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or verify an authority-gated TourAPI enrichment round."
    )
    parser.add_argument(
        "--round-root",
        type=Path,
        required=True,
        help="Immutable round root whose basename is the request-plan SHA-256.",
    )
    parser.add_argument(
        "--round-id",
        required=True,
        help="Canonical request-plan SHA-256 and immutable round ID.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--publish",
        action="store_true",
        help="Build twice and exclusively publish the initial authority bundle.",
    )
    mode.add_argument(
        "--check-bundle",
        nargs=3,
        metavar=("PLAN", "STATE", "REQUEST"),
        type=Path,
        help="Rederive all bundle digests and cross-references.",
    )
    mode.add_argument(
        "--verify-authorization-preconditions",
        metavar="REQUEST",
        type=Path,
        help="Verify current authorization parents without consuming authority.",
    )
    parser.add_argument(
        "--pool",
        type=Path,
        default=Path(
            "../artifacts/restricted/catalog/v2/enrichment/"
            "enrichment-candidate-pool.json"
        ),
        help="The immutable 60-candidate enrichment pool.",
    )
    parser.add_argument(
        "--initial-round-ref",
        type=Path,
        default=Path(
            "../artifacts/restricted/catalog/v2/enrichment/initial-round-ref.json"
        ),
        help="Exclusive initial-round reference destination.",
    )
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument(
        "--quota-limit",
        type=int,
        default=540,
        help="Operator-declared request-attempt budget; never fetched from a provider.",
    )
    parser.add_argument("--reviewer-id", default="phase2-operator")
    parser.add_argument(
        "--valid-for-seconds",
        type=int,
        default=86_400,
        help="Authorization request lifetime from the one frozen issuance timestamp.",
    )
    return parser


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_canonical_pool(path: Path) -> dict[str, object]:
    payload = path.expanduser().resolve(strict=True).read_bytes()
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("candidate pool must contain a JSON object")
    if canonical_json_bytes(value) != payload:
        raise ValueError("candidate pool must use canonical JSON bytes")
    return value


def _source_digest() -> str:
    source_paths = (
        Path(__file__).resolve(),
        Path(__file__).parents[1] / "contracts/catalog_enrichment.py",
        Path(__file__).parents[1] / "contracts/authority.py",
    )
    digest = hashlib.sha256()
    for path in source_paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _configuration_digest(
    *,
    attempts: int,
    quota_limit: int,
    reviewer_id: str,
    valid_for_seconds: int,
) -> str:
    return _sha256_bytes(
        canonical_json_bytes(
            {
                "attempts": attempts,
                "quota_limit": quota_limit,
                "reviewer_id": reviewer_id,
                "valid_for_seconds": valid_for_seconds,
                "per_attempt_timeout_seconds": 300,
            }
        )
    )


def _permission_digest(plan: dict[str, object]) -> str:
    return _sha256_bytes(canonical_json_bytes(plan["permission_evidence"]))


def _publish(args: argparse.Namespace) -> None:
    if args.valid_for_seconds <= 0:
        raise ValueError("--valid-for-seconds must be positive")
    pool = _read_canonical_pool(args.pool)
    plan = build_enrichment_plan(
        pool,
        attempts=args.attempts,
        quota_limit=args.quota_limit,
    )
    plan_bytes = canonical_json_bytes(plan)
    root = validate_round_pair(args.round_root, args.round_id, plan_bytes)
    issued_at = datetime.now(timezone.utc)
    frozen = FrozenEnrichmentIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=args.valid_for_seconds),
        nonce=secrets.token_hex(32),
        reviewer_id=args.reviewer_id,
        code_sha256=_source_digest(),
        config_sha256=_configuration_digest(
            attempts=args.attempts,
            quota_limit=args.quota_limit,
            reviewer_id=args.reviewer_id,
            valid_for_seconds=args.valid_for_seconds,
        ),
        permission_evidence_sha256=_permission_digest(plan),
        previous_round_ref_sha256=None,
    )
    first = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=args.round_id,
        frozen=frozen,
    )
    second = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=args.round_id,
        frozen=frozen,
    )
    if first.files != second.files:
        raise RuntimeError("frozen issuance produced non-identical canonical bytes")
    publish_enrichment_bundle(
        first,
        initial_reference_path=args.initial_round_ref,
    )
    print(
        json.dumps(
            {
                "published": True,
                "round_id": args.round_id,
                "round_root": first.state_attestation["round_root"],
                "request_count": plan["request_count"],
                "quota_estimate": plan["quota_estimate"],
                "plan_sha256": _sha256_bytes(first.plan_bytes),
                "state_attestation_sha256": _sha256_bytes(first.state_bytes),
                "authorization_request_sha256": _sha256_bytes(first.request_bytes),
                "provider_requests_sent": 0,
                "authority_token_issued": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.publish:
        _publish(args)
        return 0
    if args.check_bundle is not None:
        verify_enrichment_bundle(
            *args.check_bundle,
            round_root=args.round_root,
            round_id=args.round_id,
        )
        print(
            json.dumps(
                {
                    "bundle_valid": True,
                    "round_id": args.round_id,
                    "authority_consumed": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if args.verify_authorization_preconditions is not None:
        verify_authorization_preconditions(
            args.verify_authorization_preconditions,
            round_root=args.round_root,
            round_id=args.round_id,
            now=datetime.now(timezone.utc),
        )
        print(
            json.dumps(
                {
                    "authorization_preconditions_valid": True,
                    "round_id": args.round_id,
                    "authority_consumed": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    raise AssertionError("argparse must select a planner mode")


if __name__ == "__main__":
    raise SystemExit(main())
