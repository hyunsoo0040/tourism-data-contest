"""Issue, check, consume, or verify catalog-v2 activation transitions."""

from __future__ import annotations

import argparse
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from itda.contracts.catalog_activation import (
    build_catalog_activation_request,
    check_catalog_activation_request,
    consume_catalog_activation,
    publish_catalog_activation_request,
    verify_catalog_activation_event,
)
from itda.domain.canonical import canonical_json_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--issue-request", type=Path, metavar="APPROVAL")
    mode.add_argument("--check-request", nargs=2, type=Path, metavar=("REQUEST", "STATE"))
    mode.add_argument("--activate", type=Path, metavar="AUTHORITY_DESCRIPTOR")
    mode.add_argument("--rollback", type=Path, metavar="AUTHORITY_DESCRIPTOR")
    mode.add_argument("--verify-event", type=Path, metavar="EVENT")
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--events-root", type=Path)
    parser.add_argument("--state-output", type=Path)
    parser.add_argument("--request-output", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--nonce-ledger-root", type=Path)
    parser.add_argument("--reviewer", default="phase2-operator")
    parser.add_argument("--nonce")
    parser.add_argument("--issued-at")
    parser.add_argument("--expires-at")
    parser.add_argument("--occurred-at")
    parser.add_argument("--require-current", action="store_true")
    return parser


def _root(value: Path | None) -> Path:
    return value.resolve(strict=True) if value is not None else Path(__file__).resolve().parents[4]


def _utc(value: str | None, *, fallback: datetime) -> datetime:
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value is not None
        else fallback
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _root(args.repository_root)
    activation_root = (
        args.events_root
        if args.events_root is not None
        else root / "artifacts/restricted/catalog/v2/activation"
    )
    approval = (
        args.approval
        if args.approval is not None
        else root / "artifacts/restricted/catalog/v2/approval/catalog-approval.json"
    )
    if args.issue_request is not None:
        now = _utc(args.issued_at, fallback=datetime.now(UTC).replace(microsecond=0))
        expiry = _utc(args.expires_at, fallback=now + timedelta(days=7))
        state, request = build_catalog_activation_request(
            args.issue_request,
            repository_root=root,
            events_root=activation_root,
            action="catalog-activate",
            reviewer_id=args.reviewer,
            nonce=args.nonce or secrets.token_hex(32),
            issued_at=now,
            expires_at=expiry,
        )
        second_state, second_request = build_catalog_activation_request(
            args.issue_request,
            repository_root=root,
            events_root=activation_root,
            action="catalog-activate",
            reviewer_id=args.reviewer,
            nonce=request.nonce,
            issued_at=now,
            expires_at=expiry,
        )
        if canonical_json_bytes(state.model_dump(mode="json")) != canonical_json_bytes(
            second_state.model_dump(mode="json")
        ) or canonical_json_bytes(request.model_dump(mode="json")) != canonical_json_bytes(
            second_request.model_dump(mode="json")
        ):
            raise ValueError("catalog activation request replays differ")
        if args.state_output is None or args.request_output is None:
            raise ValueError("--state-output and --request-output are required")
        publish_catalog_activation_request(
            state,
            request,
            state_path=args.state_output,
            request_path=args.request_output,
        )
        print(request.request_sha256)
        return 0
    if args.check_request is not None:
        request_path, state_path = args.check_request
        request = check_catalog_activation_request(
            request_path,
            state_path,
            approval_path=approval,
            events_root=activation_root,
            repository_root=root,
        )
        print(request.request_sha256)
        return 0
    if args.verify_event is not None:
        event = verify_catalog_activation_event(
            args.verify_event,
            events_root=activation_root,
            approval_path=approval,
            repository_root=root,
            require_current=args.require_current,
        )
        print(event.event_sha256)
        return 0
    descriptor = args.activate if args.activate is not None else args.rollback
    if descriptor is None:
        raise ValueError("catalog activation action is missing")
    if args.request is None or args.state is None:
        raise ValueError("--request and --state are required for action consumption")
    occurred_at = _utc(args.occurred_at, fallback=datetime.now(UTC).replace(microsecond=0))
    event = consume_catalog_activation(
        authority_descriptor_path=descriptor,
        request_path=args.request,
        state_path=args.state,
        approval_path=approval,
        events_root=activation_root,
        nonce_ledger_root=(
            args.nonce_ledger_root
            if args.nonce_ledger_root is not None
            else activation_root / ".authority-ledger"
        ),
        repository_root=root,
        occurred_at=occurred_at,
    )
    expected_action = "catalog-activate" if args.activate is not None else "catalog-rollback"
    if event.action != expected_action:
        raise ValueError("authority request action differs from selected consumer")
    print(event.event_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
