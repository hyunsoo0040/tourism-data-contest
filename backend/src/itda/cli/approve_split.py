"""Approve one membership-free request against an exact restricted split manifest."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from itda.contracts.catalog_manifest import (
    RealSplitManifest,
    SplitApproval,
    SplitApprovalRequest,
    verify_split_approval_request,
)
from itda.domain.canonical import canonical_json_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--restricted-manifest", required=True, type=Path)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--approved-at", required=True)
    parser.add_argument("--confirm-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _load_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    if path.suffix != ".json" or path.is_symlink() or not path.is_file():
        raise ValueError("split approval inputs must be canonical JSON regular files")
    raw = path.read_bytes()
    payload = json.loads(raw)
    parsed = model.model_validate(payload)
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("split approval input is not canonical JSON")
    return parsed


def _write_exclusive(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        encoded = canonical_json_bytes(payload)
        written = os.write(descriptor, encoded)
        if written != len(encoded):
            raise OSError("short write while publishing split approval")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    request = _load_model(args.request, SplitApprovalRequest)
    manifest = _load_model(args.restricted_manifest, RealSplitManifest)
    verify_split_approval_request(request, manifest)
    if request.split_approval_request_sha256 is None:
        raise ValueError("split approval request requires a canonical sha256")
    approval = SplitApproval(
        catalog_manifest_sha256=request.catalog_manifest_sha256,
        catalog_approval_sha256=request.catalog_approval_sha256,
        split_manifest_sha256=request.split_manifest_sha256,
        confirm_sha256=args.confirm_sha256,
        reviewer_id=args.reviewer,
        approved_at=args.approved_at,
        split_approval_request_sha256=request.split_approval_request_sha256,
    )
    _write_exclusive(args.output, approval.model_dump(mode="json"))
    print(approval.split_approval_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
