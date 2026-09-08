"""Manage additive v2 profile releases with digest-only lifecycle receipts."""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from itda.api.dependencies import (
    Phase3Principal,
    get_evaluation_repository,
    resolve_phase3_principal,
)
from itda.contracts.profile_release_authority import (
    ProfileReleaseAuthorityPathsV2,
    ProfileReleaseAuthorityRequestV2,
    ProfileReleaseBuildAuthorityResolution,
    parse_profile_release_authority_registry_id,
    resolve_authoritative_profile_release_build_authority_v2,
)
from itda.contracts.profile_release_v2 import (
    ProfileReleaseCandidateV2,
)
from itda.domain.canonical import canonical_json_bytes

_CAPABILITY_ENVIRONMENT = "ITDA_PHASE3_CAPABILITY"
_AUTHORITY_ROOT = Path("/var/lib/itda/profile-release-v2-authority")
_AUTHORITY_REQUEST_FILENAME = "request.json"
_MAX_REQUEST_BYTES = 64_000
_AUTHORITY_FILENAMES = {
    "predecessor": "predecessor.json",
    "rights": "rights.json",
    "lane_baseline": "lane_baseline.json",
    "selection": "selection.json",
    "prediction": "prediction.json",
    "provisional": "provisional.json",
    "final": "final.json",
    "review_or_fallback": "review_or_fallback.json",
    "fusion_config": "fusion_config.json",
    "profiles": "profiles.json",
}


def _read_authority_request() -> bytes:
    """Read the fixed authority request without following caller-controlled paths."""

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_descriptor = os.open(_AUTHORITY_ROOT, directory_flags)
    try:
        descriptor = os.open(
            _AUTHORITY_REQUEST_FILENAME,
            file_flags,
            dir_fd=root_descriptor,
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > _MAX_REQUEST_BYTES
            ):
                raise ValueError("successor authority request must be a bounded regular file")
            chunks: list[bytes] = []
            remaining = _MAX_REQUEST_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(16_384, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)

            def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
                return (
                    value.st_dev,
                    value.st_ino,
                    value.st_size,
                    value.st_mtime_ns,
                    value.st_ctime_ns,
                )

            if (
                len(raw) != before.st_size
                or len(raw) > _MAX_REQUEST_BYTES
                or identity(before) != identity(after)
            ):
                raise ValueError("successor authority request changed during bounded read")
            return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--nonce")

    approve = subparsers.add_parser("approve")
    approve.add_argument("--release")

    activate = subparsers.add_parser("activate")
    activate.add_argument("--release")
    activate.add_argument("--expected-current")
    activate.add_argument("--nonce")

    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--release")
    rollback.add_argument("--expected-current")
    rollback.add_argument("--nonce")
    rollback.add_argument("--reason")

    status = subparsers.add_parser("status")
    status.add_argument("--release")
    return parser


def _principal() -> Phase3Principal:
    capability = os.environ.get(_CAPABILITY_ENVIRONMENT)
    if capability is None:
        raise RuntimeError(f"{_CAPABILITY_ENVIRONMENT} is required")
    return resolve_phase3_principal(capability)


def _required(value: Any, *, field: str) -> Any:
    if value is None:
        raise ValueError(f"{field} is required")
    return value


def _emit(action: str, values: Mapping[str, object]) -> None:
    payload = {
        "schema_version": "itda.profile-release-cli-receipt.v2",
        "action": action,
        **values,
    }
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


def _resolve_build_candidate(
    *,
    authenticated_principal: str,
    builder_database_principal: str,
) -> ProfileReleaseBuildAuthorityResolution:
    raw = _read_authority_request()
    request = ProfileReleaseAuthorityRequestV2.model_validate_json(raw)
    if canonical_json_bytes(request.model_dump(mode="json")) != raw:
        raise ValueError("successor authority request must be canonical JSON")
    if request.builder_principal != authenticated_principal:
        raise ValueError("successor authority request builder does not match principal")
    return resolve_authoritative_profile_release_build_authority_v2(
        request=request,
        paths=ProfileReleaseAuthorityPathsV2(
            root=_AUTHORITY_ROOT,
            **_AUTHORITY_FILENAMES,
        ),
        authority_registry_id=parse_profile_release_authority_registry_id(
            os.environ.get("ITDA_PROFILE_RELEASE_AUTHORITY_REGISTRY_ID")
        ),
        builder_database_principal=builder_database_principal,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    principal = _principal()

    if args.action == "build":
        if principal.role != "builder":
            raise ValueError("successor build requires server-derived builder")
        repository = get_evaluation_repository(principal)
        resolution = _resolve_build_candidate(
            authenticated_principal=principal.actor_id,
            builder_database_principal=(repository.profile_release_builder_database_principal()),
        )
        candidate = resolution.candidate
        if not isinstance(candidate, ProfileReleaseCandidateV2):
            raise TypeError("successor authority returned a legacy candidate")
        outcome = repository.build_profile_release(
            resolution,
            authenticated_principal=principal.actor_id,
            reconciliation_nonce=_required(args.nonce, field="nonce"),
        )
        _emit(
            "BUILD",
            {
                "release_sha256": outcome.release_sha256,
                "receipt_sha256": outcome.receipt_sha256,
                "nonce_sha256": outcome.nonce_sha256,
            },
        )
        return 0

    repository = get_evaluation_repository(principal)

    if args.action == "status":
        if args.release is None:
            pointer = repository.get_profile_release_active_pointer()
            _emit(
                "STATUS",
                {
                    "release_sha256": pointer.active_release_sha256,
                    "receipt_sha256": pointer.receipt_sha256,
                },
            )
        else:
            state = repository.get_profile_release_state(args.release)
            if state is None:
                raise ValueError("profile release does not exist")
            _emit(
                "STATUS",
                {
                    "release_sha256": state.release_sha256,
                    "state": state.state.value,
                    "receipt_sha256": state.provenance_receipt_sha256,
                },
            )
        return 0

    if principal.role != "approver":
        raise ValueError("successor lifecycle mutation requires server-derived approver")
    release_sha256 = _required(args.release, field="release")
    if args.action == "approve":
        approval = repository.approve_profile_release(
            release_sha256,
            authenticated_principal=principal.actor_id,
        )
        _emit(
            "APPROVE",
            {
                "release_sha256": approval.release_sha256,
                "approval_sha256": approval.approval_sha256,
            },
        )
        return 0
    if args.action == "activate":
        result = repository.activate_profile_release(
            release_sha256,
            expected_current=_required(args.expected_current, field="expected-current"),
            authenticated_principal=principal.actor_id,
            nonce=_required(args.nonce, field="nonce"),
        )
        _emit(
            "ACTIVATE",
            {
                "release_sha256": result.receipt.release_sha256,
                "receipt_sha256": result.receipt_sha256,
                "nonce_sha256": result.receipt.nonce_sha256,
            },
        )
        return 0
    if args.action == "rollback":
        result = repository.rollback_profile_release(
            release_sha256,
            expected_current=_required(args.expected_current, field="expected-current"),
            authenticated_principal=principal.actor_id,
            reason=_required(args.reason, field="reason"),
            nonce=_required(args.nonce, field="nonce"),
        )
        _emit(
            "ROLLBACK",
            {
                "release_sha256": result.receipt.release_sha256,
                "receipt_sha256": result.receipt_sha256,
                "nonce_sha256": result.receipt.nonce_sha256,
            },
        )
        return 0
    raise ValueError("unsupported successor lifecycle action")


if __name__ == "__main__":
    raise SystemExit(main())
