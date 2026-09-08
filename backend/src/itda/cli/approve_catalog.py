"""Prepare, verify, materialize, activate, or roll back reviewed catalog revisions."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel

from itda.contracts.catalog_release import (
    CatalogAdjudication,
    CatalogGateReport,
    CatalogReviewRequest,
    VerifiedCatalogAdjudication,
    append_revision_activation_event,
    approve_catalog_v2,
    build_catalog_v2_approval_request,
    build_catalog_v2_revision,
    check_catalog_v2_approval_request,
    load_adjudication_decisions,
    load_reviewed_catalog_revision,
    materialize_reviewed_catalog,
    prepare_catalog_adjudication,
    publish_catalog_v2_approval_request,
    publish_catalog_v2_revision,
    verify_catalog_adjudication,
    verify_catalog_v2_approval,
    verify_catalog_v2_revision,
)
from itda.domain.canonical import canonical_json_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-adjudication", action="store_true")
    mode.add_argument("--verify-adjudication", action="store_true")
    mode.add_argument("--materialize-reviewed-catalog", action="store_true")
    mode.add_argument("--activate-reviewed-revision", type=Path)
    mode.add_argument("--rollback-to-revision", type=Path)
    mode.add_argument("--materialize-v2-revision", type=Path)
    mode.add_argument("--verify-v2-revision", type=Path)
    mode.add_argument("--issue-v2-approval-request", type=Path)
    mode.add_argument("--check-v2-approval-request", nargs=2, type=Path)
    mode.add_argument("--approve-v2", type=Path)
    mode.add_argument("--verify-v2-approval", type=Path)
    parser.add_argument("--gate-report", type=Path)
    parser.add_argument("--review-request", type=Path)
    parser.add_argument("--decisions", type=Path)
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--reviewer")
    parser.add_argument("--reviewed-at")
    parser.add_argument("--occurred-at")
    parser.add_argument("--confirm-catalog-sha256")
    parser.add_argument("--confirm-adjudication-sha256")
    parser.add_argument("--expected-active-revision-sha256")
    parser.add_argument("--evidence-ref", action="append", default=[])
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--reviewed-revisions-root", type=Path)
    parser.add_argument("--events-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--state-output", type=Path)
    parser.add_argument("--request-output", type=Path)
    parser.add_argument("--revision", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--nonce-ledger-root", type=Path)
    parser.add_argument("--approved-at")
    parser.add_argument("--nonce")
    parser.add_argument("--expires-at")
    parser.add_argument("--require-inactive", action="store_true")
    return parser


def _repo_root(value: Path | None) -> Path:
    return value.resolve(strict=True) if value is not None else Path(__file__).resolve().parents[4]


def _require(args: argparse.Namespace, *names: str) -> tuple[object, ...]:
    values: list[object] = []
    for name in names:
        value = getattr(args, name)
        if value is None or value == []:
            raise ValueError(f"--{name.replace('_', '-')} is required for this mode")
        values.append(value)
    return tuple(values)


def _as_path(value: object) -> Path:
    if isinstance(value, Path):
        return value
    if isinstance(value, str):
        return Path(value)
    raise TypeError("expected a filesystem path")


def _load_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    if path.suffix != ".json" or path.is_symlink() or not path.is_file():
        raise ValueError("approval inputs must be canonical JSON regular files")
    raw = path.read_bytes()
    payload = json.loads(raw)
    parsed = model.model_validate(payload)
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("approval input is not canonical JSON")
    return parsed


def _write_exclusive(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        encoded = canonical_json_bytes(payload)
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise OSError("short write while publishing catalog approval bytes")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verified(args: argparse.Namespace) -> VerifiedCatalogAdjudication:
    (
        gate_path,
        request_path,
        adjudication_path,
        catalog_hash,
        adjudication_hash,
        reviewer,
        repository_root,
    ) = _require(
        args,
        "gate_report",
        "review_request",
        "adjudication",
        "confirm_catalog_sha256",
        "confirm_adjudication_sha256",
        "reviewer",
        "repository_root",
    )
    return verify_catalog_adjudication(
        gate_report=_load_model(_as_path(gate_path), CatalogGateReport),
        review_request=_load_model(_as_path(request_path), CatalogReviewRequest),
        adjudication=_load_model(_as_path(adjudication_path), CatalogAdjudication),
        confirm_catalog_sha256=str(catalog_hash),
        confirm_adjudication_sha256=str(adjudication_hash),
        reviewer_id=str(reviewer),
        repository_root=_as_path(repository_root),
    )


def _reviewed_revision_identities(
    root: Path,
    *,
    repository_root: Path,
) -> dict[Path, tuple[str, str]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("reviewed revisions root must be a regular directory")
    identities: dict[Path, tuple[str, str]] = {}
    for path in sorted(root.iterdir()):
        if path.is_symlink() or not path.is_dir():
            raise ValueError("reviewed revisions root contains an invalid entry")
        identities[path.resolve(strict=True)] = load_reviewed_catalog_revision(
            path,
            repository_root=repository_root,
        )
    if not identities:
        raise ValueError("reviewed revisions root contains no verified revisions")
    return identities


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _repo_root(args.repository_root)
    if args.materialize_v2_revision is not None:
        (output,) = _require(args, "output")
        first = build_catalog_v2_revision(
            args.materialize_v2_revision,
            repository_root=root,
        )
        second = build_catalog_v2_revision(
            args.materialize_v2_revision,
            repository_root=root,
        )
        if canonical_json_bytes(first.model_dump(mode="json")) != canonical_json_bytes(
            second.model_dump(mode="json")
        ):
            raise ValueError("catalog v2 revision replays differ")
        publish_catalog_v2_revision(first, _as_path(output))
        print(first.catalog_revision_sha256)
        return 0
    if args.verify_v2_revision is not None:
        revision = verify_catalog_v2_revision(
            args.verify_v2_revision,
            repository_root=root,
            require_inactive=args.require_inactive,
        )
        print(revision.catalog_revision_sha256)
        return 0
    if args.issue_v2_approval_request is not None:
        state_output, request_output, reviewer = _require(
            args,
            "state_output",
            "request_output",
            "reviewer",
        )
        issued_at = (
            datetime.fromisoformat(args.reviewed_at.replace("Z", "+00:00"))
            if args.reviewed_at is not None
            else datetime.now(UTC).replace(microsecond=0)
        )
        expires_at = (
            datetime.fromisoformat(args.expires_at.replace("Z", "+00:00"))
            if args.expires_at is not None
            else issued_at + timedelta(days=7)
        )
        state, approval_request = build_catalog_v2_approval_request(
            args.issue_v2_approval_request,
            repository_root=root,
            reviewer_id=str(reviewer),
            nonce=args.nonce or secrets.token_hex(32),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        publish_catalog_v2_approval_request(
            state,
            approval_request,
            state_path=_as_path(state_output),
            request_path=_as_path(request_output),
        )
        print(approval_request.request_sha256)
        return 0
    if args.check_v2_approval_request is not None:
        request_path, state_path = args.check_v2_approval_request
        checked_request = check_catalog_v2_approval_request(
            request_path,
            state_path,
            revision_path=args.revision,
            repository_root=root,
        )
        print(checked_request.request_sha256)
        return 0
    if args.verify_v2_approval is not None:
        approval = verify_catalog_v2_approval(
            args.verify_v2_approval,
            repository_root=root,
            require_inactive=args.require_inactive,
        )
        print(approval.catalog_approval_sha256)
        return 0
    if args.approve_v2 is not None:
        request_path, state_path, revision_path, output = _require(
            args,
            "request",
            "state",
            "revision",
            "output",
        )
        approved_at = (
            datetime.fromisoformat(args.approved_at.replace("Z", "+00:00"))
            if args.approved_at is not None
            else datetime.now(UTC).replace(microsecond=0)
        )
        approval = approve_catalog_v2(
            authority_descriptor_path=args.approve_v2,
            request_path=_as_path(request_path),
            state_path=_as_path(state_path),
            revision_path=_as_path(revision_path),
            approval_path=_as_path(output),
            nonce_ledger_root=(
                args.nonce_ledger_root
                if args.nonce_ledger_root is not None
                else root / "artifacts/restricted/catalog/v2/approval/.authority-ledger"
            ),
            repository_root=root,
            approved_at=approved_at,
        )
        print(approval.catalog_approval_sha256)
        return 0
    if args.prepare_adjudication:
        request_path, decisions_path, reviewer, reviewed_at, output = _require(
            args,
            "review_request",
            "decisions",
            "reviewer",
            "reviewed_at",
            "output",
        )
        catalog_request = _load_model(_as_path(request_path), CatalogReviewRequest)
        adjudication = prepare_catalog_adjudication(
            review_request=catalog_request,
            decisions=load_adjudication_decisions(_as_path(decisions_path)),
            reviewer_id=str(reviewer),
            reviewed_at=str(reviewed_at),
        )
        _write_exclusive(_as_path(output), adjudication.model_dump(mode="json"))
        print(adjudication.catalog_adjudication_sha256)
        return 0
    if args.verify_adjudication:
        verified = _verified(args)
        print(verified.verification_sha256)
        return 0
    if args.materialize_reviewed_catalog:
        (output_root,) = _require(args, "output_root")
        materialize_reviewed_catalog(_verified(args), _as_path(output_root))
        return 0

    target_path = (
        args.activate_reviewed_revision
        if args.activate_reviewed_revision is not None
        else args.rollback_to_revision
    )
    reviewer, occurred_at, events_root, revisions_root, repository_root = _require(
        args,
        "reviewer",
        "occurred_at",
        "events_root",
        "reviewed_revisions_root",
        "repository_root",
    )
    if target_path is None:
        raise ValueError("activation mode requires a reviewed revision path")
    identities = _reviewed_revision_identities(
        _as_path(revisions_root),
        repository_root=_as_path(repository_root),
    )
    target = _as_path(target_path)
    if target.is_symlink() or not target.is_dir():
        raise ValueError("activation target must be a reviewed catalog directory")
    target_resolved = target.resolve(strict=True)
    if target_resolved not in identities:
        raise ValueError("activation target is absent from reviewed revision history")
    revision_sha256, adjudication_sha256 = identities[target_resolved]
    event = append_revision_activation_event(
        action=("ACTIVATE" if args.activate_reviewed_revision is not None else "ROLLBACK"),
        target_revision_sha256=revision_sha256,
        catalog_adjudication_sha256=adjudication_sha256,
        expected_active_revision_sha256=args.expected_active_revision_sha256,
        reviewer_id=str(reviewer),
        occurred_at=str(occurred_at),
        evidence_refs=tuple(str(item) for item in args.evidence_ref),
        events_root=_as_path(events_root),
        reviewed_revision_sha256s=tuple(revision for revision, _ in identities.values()),
    )
    print(event.event_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
