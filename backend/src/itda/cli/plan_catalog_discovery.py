"""Build and verify the traffic-free D1 discovery request generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import stat
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from itda.contracts.catalog_discovery import (
    ApprovalEvidence,
    DiscoveryRequestGeneration,
    FrozenDiscoveryIssuance,
    build_d1_request_generation,
    publish_request_generation,
    verify_request_generation,
)
from itda.domain.canonical import canonical_json_bytes

_REQUESTS_RELATIVE = Path("artifacts/restricted/catalog/v2/supplemental/discovery/requests")
_ATTESTATION_RELATIVE = Path(
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-38-FAILURE-ATTESTATION.md"
)
_SUMMARY_RELATIVE = Path(
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-41-SUMMARY.md"
)
_TARGET_MATRIX_NAME = "supplemental-target-matrix.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish or verify the exact traffic-free D1 request generation."
    )
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--source", choices=("d1",), required=True)
    parser.add_argument("--failure-root", required=True, type=Path)
    parser.add_argument("--failure-round-id", required=True)
    parser.add_argument("--reviewer-id", default="phase2-operator")
    parser.add_argument("--valid-for-seconds", type=int, default=86_400)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--publish-request", action="store_true")
    return parser


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular_file(path: Path, *, expected_mode: int | None = None) -> bytes:
    if path.is_symlink():
        raise ValueError(f"refusing symlink input: {path}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"input must be a single-link regular file: {path}")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise ValueError(f"input mode drifted: {path}")
    return path.read_bytes()


def _canonical_object(path: Path, *, expected_mode: int | None = None) -> dict[str, object]:
    payload = _read_regular_file(path, expected_mode=expected_mode)
    value = json.loads(payload)
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ValueError(f"input is not a canonical JSON object: {path}")
    return value


def _target_context(failure_root: Path) -> tuple[str, tuple[str, ...]]:
    matrix_path = failure_root / _TARGET_MATRIX_NAME
    matrix = _canonical_object(matrix_path, expected_mode=0o600)
    if matrix.get("target_count") != 24:
        raise ValueError("failure target matrix must contain exactly 24 rows")
    rows = matrix.get("rows")
    if not isinstance(rows, list) or len(rows) != 24:
        raise ValueError("failure target matrix rows drifted")
    target_ids: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("failure target matrix contains a malformed row")
        target_id = row.get("place_entity_id")
        if not isinstance(target_id, str) or not target_id.startswith("place:"):
            raise ValueError("failure target matrix target identity drifted")
        target_ids.append(target_id)
    if len(set(target_ids)) != 24:
        raise ValueError("failure target matrix target identities are not unique")
    matrix_sha256 = matrix.get("matrix_sha256")
    if not isinstance(matrix_sha256, str) or len(matrix_sha256) != 64:
        raise ValueError("failure target matrix lacks its canonical digest")
    return matrix_sha256, tuple(target_ids)


def _validate_failure_root(
    failure_root: Path,
    *,
    failure_round_id: str,
) -> str:
    resolved = failure_root.resolve(strict=True)
    if resolved.is_symlink() or stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise ValueError("failure generation root must be a no-follow 0700 directory")
    packet = _canonical_object(resolved / "packet-manifest.json", expected_mode=0o600)
    if packet.get("root_sha256") != resolved.name:
        raise ValueError("failure generation root digest drifted")
    payload = packet.get("payload")
    if not isinstance(payload, dict) or payload.get("round_id") != failure_round_id:
        raise ValueError("failure generation round ID drifted")
    if payload.get("publication_state") != "FAILURE":
        raise ValueError("D1 planning requires the exact fail-closed predecessor")
    return resolved.name


def _build(args: argparse.Namespace) -> tuple[DiscoveryRequestGeneration, str]:
    repo_root = args.repo_root.resolve(strict=True)
    failure_root = args.failure_root.resolve(strict=True)
    if repo_root not in failure_root.parents:
        raise ValueError("failure generation root escapes the repository")
    failure_generation_sha256 = _validate_failure_root(
        failure_root,
        failure_round_id=args.failure_round_id,
    )
    target_matrix_sha256, target_ids = _target_context(failure_root)
    attestation_sha256 = _sha256(_read_regular_file(repo_root / _ATTESTATION_RELATIVE))
    predecessor_summary_sha256 = _sha256(_read_regular_file(repo_root / _SUMMARY_RELATIVE))
    observed_at = datetime(1970, 1, 1, tzinfo=UTC)
    approval = ApprovalEvidence.pending(
        dataset_id="15114464",
        reviewer_id=args.reviewer_id,
        observed_at=observed_at,
    )
    if args.valid_for_seconds <= 0:
        raise ValueError("--valid-for-seconds must be positive")
    issued_at = datetime.now(UTC)

    # Freeze all non-secret parents first. The placeholder never leaves memory.
    placeholder = FrozenDiscoveryIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=args.valid_for_seconds),
        nonce="0" * 64,
        reviewer_id=args.reviewer_id,
    )
    prepared = build_d1_request_generation(
        repository_relative_root=_REQUESTS_RELATIVE.as_posix(),
        failure_generation_sha256=failure_generation_sha256,
        failure_round_id=args.failure_round_id,
        failure_attestation_sha256=attestation_sha256,
        target_matrix_sha256=target_matrix_sha256,
        target_ids=target_ids,
        approval_evidence=approval,
        frozen=placeholder,
    )
    if prepared.request["failure_attestation_sha256"] != attestation_sha256:
        raise ValueError("failure attestation parent did not freeze")

    # Only after request/state/target/binding parents freeze is a fresh nonce made.
    frozen = FrozenDiscoveryIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=args.valid_for_seconds),
        nonce=secrets.token_hex(32),
        reviewer_id=args.reviewer_id,
    )
    first = build_d1_request_generation(
        repository_relative_root=_REQUESTS_RELATIVE.as_posix(),
        failure_generation_sha256=failure_generation_sha256,
        failure_round_id=args.failure_round_id,
        failure_attestation_sha256=attestation_sha256,
        target_matrix_sha256=target_matrix_sha256,
        target_ids=target_ids,
        approval_evidence=approval,
        frozen=frozen,
    )
    second = build_d1_request_generation(
        repository_relative_root=_REQUESTS_RELATIVE.as_posix(),
        failure_generation_sha256=failure_generation_sha256,
        failure_round_id=args.failure_round_id,
        failure_attestation_sha256=attestation_sha256,
        target_matrix_sha256=target_matrix_sha256,
        target_ids=target_ids,
        approval_evidence=approval,
        frozen=frozen,
    )
    if first.files != second.files:
        raise RuntimeError("frozen D1 request generation was not byte-identical")
    if first.request_generation_sha256 != prepared.request_generation_sha256:
        raise RuntimeError("fresh nonce changed the frozen request identity")
    return first, predecessor_summary_sha256


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.check and not args.publish_request:
        raise ValueError("D1 planning requires --check and/or --publish-request")
    generation, predecessor_summary_sha256 = _build(args)
    repo_root = args.repo_root.resolve(strict=True)
    root = repo_root / _REQUESTS_RELATIVE / generation.request_generation_sha256
    if args.publish_request:
        if root.exists():
            verify_request_generation(root)
        else:
            publish_request_generation(generation, root)
    if args.check:
        verify_request_generation(root)
    print(
        json.dumps(
            {
                "source": "d1",
                "dataset_id": "15114464",
                "request_generation_sha256": generation.request_generation_sha256,
                "reviewer_id": generation.manifest["reviewer_id"],
                "predecessor_summary_sha256": predecessor_summary_sha256,
                "request_count": 20,
                "row_ceiling": 200,
                "attempts_per_request": 3,
                "per_attempt_timeout_seconds": 300,
                "overall_timeout_seconds": 18_000,
                "follow_redirects": False,
                "provider_requests_sent": 0,
                "credential_file_opened": False,
                "authority_consumed": False,
                "nonce_ledger_mutated": False,
                "collection_root_created": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
