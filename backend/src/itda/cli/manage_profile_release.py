"""Approve, activate, roll back, retain, or pin the DEV profile release."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence

from itda.api.dependencies import (
    Phase3Principal,
    get_evaluation_repository,
    resolve_phase3_principal,
)

_CAPABILITY_ENVIRONMENT = "ITDA_PHASE3_CAPABILITY"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--approve", metavar="RELEASE_SHA256")
    mode.add_argument("--activate", metavar="RELEASE_SHA256")
    mode.add_argument("--rollback", metavar="RELEASE_SHA256")
    mode.add_argument("--pin-session", metavar="SESSION_REF")
    mode.add_argument("--pin-result", metavar="RESULT_REF")
    mode.add_argument("--purge-expired-build-drafts", action="store_true")
    parser.add_argument("--expected-current", metavar="RELEASE_SHA256_OR_NONE")
    parser.add_argument("--nonce")
    parser.add_argument("--reason")
    return parser


def _principal() -> Phase3Principal:
    raw_capability = os.environ.get(_CAPABILITY_ENVIRONMENT)
    if raw_capability is None:
        raise RuntimeError(f"{_CAPABILITY_ENVIRONMENT} is required")
    return resolve_phase3_principal(raw_capability)


def _expected(value: str | None) -> str | None:
    if value in {None, "NONE"}:
        return None
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.purge_expired_build_drafts:
        try:
            principal = _principal()
            if principal.role != "builder":
                raise ValueError(
                    "profile release draft retention requires server-derived builder"
                )
            repository = get_evaluation_repository(principal)
            result = repository.purge_expired_profile_release_build_drafts(
                authenticated_principal=principal.actor_id,
            )
        except Exception:
            print(
                json.dumps(
                    {
                        "event": "profile_release_build_draft_purge",
                        "status": "FAILED",
                        "error_code": "PURGE_UNAVAILABLE",
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1
        print(result.model_dump_json())
        return 0

    principal = _principal()
    repository = get_evaluation_repository(principal)
    if args.approve is not None:
        if principal.role != "approver":
            raise ValueError("profile release approval requires server-derived approver")
        approval = repository.approve_profile_release(
            args.approve,
            authenticated_principal=principal.actor_id,
        )
        print(approval.approval_sha256)
        return 0
    if args.activate is not None:
        if principal.role != "approver" or args.nonce is None:
            raise ValueError("activation requires server-derived approver and nonce")
        activation_result = repository.activate_profile_release(
            args.activate,
            expected_current=_expected(args.expected_current),
            authenticated_principal=principal.actor_id,
            nonce=args.nonce,
        )
        print(activation_result.receipt_sha256)
        return 0
    if args.rollback is not None:
        if (
            principal.role != "approver"
            or args.expected_current in {None, "NONE"}
            or args.nonce is None
            or args.reason is None
        ):
            raise ValueError(
                "rollback requires server-derived approver, expected current, nonce, and reason"
            )
        rollback_result = repository.rollback_profile_release(
            args.rollback,
            expected_current=args.expected_current,
            authenticated_principal=principal.actor_id,
            reason=args.reason,
            nonce=args.nonce,
        )
        print(rollback_result.receipt_sha256)
        return 0
    if principal.role != "builder":
        raise ValueError("profile release pinning requires server-derived builder")
    if args.pin_session is not None:
        print(repository.pin_profile_release_session(args.pin_session).pin_sha256)
        return 0
    if args.pin_result is not None:
        print(repository.pin_profile_release_result(args.pin_result).pin_sha256)
        return 0
    raise ValueError("profile release action is missing")


if __name__ == "__main__":
    raise SystemExit(main())
