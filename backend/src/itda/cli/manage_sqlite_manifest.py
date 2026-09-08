"""Build, request, initialize, or verify the isolated SQLite manifest authority."""

from __future__ import annotations

import argparse
import getpass
import json
import secrets
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from itda.contracts.sqlite_manifest_authority import (
    INITIALIZATION_RESTRICTED_ROOT,
    build_initialization_authority,
    build_seal_authority,
    build_tracked_empty_projection,
    check_initialization_request,
    check_seal_request,
    initialize_restricted_empty_database,
    seal_restricted_manifest,
    verify_empty_projection,
    verify_initialization_receipt,
    verify_restricted_empty_database,
    verify_seal_receipt,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build-tracked-empty-projection", action="store_true")
    action.add_argument("--verify-tracked-empty-projection", action="store_true")
    action.add_argument("--prepare-initialization-request", action="store_true")
    action.add_argument("--check-initialization-request", type=Path)
    action.add_argument("--initialize-restricted-empty", type=Path)
    action.add_argument("--verify-initialization-receipt", type=Path)
    action.add_argument("--verify-restricted-empty", action="store_true")
    action.add_argument("--verify-seal-state", type=Path)
    action.add_argument("--prepare-seal-request", action="store_true")
    action.add_argument("--check-seal-request", type=Path)
    action.add_argument("--verify-seal-receipt", type=Path)
    parser.add_argument("--schema-dir", type=Path)
    parser.add_argument("--authority-stdin", action="store_true")
    parser.add_argument("--state", type=Path)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--receipt-output", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--issuance-context", type=Path)
    parser.add_argument("--reviewer-id")
    return parser


def _paths(args: argparse.Namespace) -> dict[str, Path]:
    repository_root = Path(__file__).resolve().parents[4]
    restricted_root = repository_root / INITIALIZATION_RESTRICTED_ROOT
    schema_dir = args.schema_dir or (repository_root / "backend/schema/evaluation_manifest_v1")
    state_path = args.state or (restricted_root / "initialization-state-attestation.json")
    issuance_path = args.issuance_context or (
        restricted_root / "initialization-issuance-context.json"
    )
    request_path = args.request or (
        repository_root / "artifacts/public/catalog/v2/sqlite-initialization-request.json"
    )
    receipt_path = args.receipt or (restricted_root / "initialization-receipt.json")
    if args.initialize_restricted_empty is not None and args.receipt_output is not None:
        receipt_path = args.receipt_output
    return {
        "repository_root": repository_root,
        "restricted_root": restricted_root,
        "schema_dir": schema_dir,
        "state_path": state_path,
        "issuance_path": issuance_path,
        "request_path": request_path,
        "receipt_path": receipt_path,
        "split_approval_path": repository_root
        / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
        "materialized_bundle_path": repository_root
        / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
        "seal_state_path": args.state or (restricted_root / "seal-state-attestation.json"),
        "seal_issuance_path": args.issuance_context
        or (restricted_root / "seal-issuance-context.json"),
        "seal_request_path": args.request
        or (repository_root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json"),
        "seal_receipt_path": args.receipt_output
        or (restricted_root / "real-manifest-seal-receipt.json"),
    }


def _request_result(request: Any, *, disposition: str) -> dict[str, object]:
    return {
        "action": request.action,
        "disposition": disposition,
        "request_sha256": request.request_sha256,
        "state_attestation_sha256": request.state_attestation_sha256,
        "target_sha256": request.target_sha256,
        "binding_sha256": request.binding_sha256,
        "ddl_sha256": request.ddl_sha256,
        "logical_schema_manifest_sha256": request.logical_schema_manifest_sha256,
        "logical_schema_sha256": request.logical_schema_sha256,
        "empty_proof_sha256": request.empty_proof_sha256,
        "restricted_root": request.restricted_root,
        "directory_mode": request.directory_mode,
        "database_mode": request.database_mode,
        "empty_counts": request.empty_counts,
    }


def _receipt_result(receipt: Any, *, disposition: str) -> dict[str, object]:
    return {
        "action": receipt.action,
        "disposition": disposition,
        "request_sha256": receipt.request_sha256,
        "state_attestation_sha256": receipt.state_attestation_sha256,
        "target_sha256": receipt.target_sha256,
        "binding_sha256": receipt.binding_sha256,
        "ddl_sha256": receipt.ddl_sha256,
        "logical_schema_manifest_sha256": receipt.logical_schema_manifest_sha256,
        "logical_schema_sha256": receipt.logical_schema_sha256,
        "empty_proof_sha256": receipt.empty_proof_sha256,
        "database_sha256": receipt.file_identity.sha256,
        "empty_counts": receipt.empty_counts,
        "integrity_check": receipt.integrity_check,
        "foreign_key_check_count": receipt.foreign_key_check_count,
        "sidecars": receipt.sidecars,
    }


def _readiness_result(readiness: Any, *, disposition: str) -> dict[str, object]:
    return {
        "action": "sqlite-real-manifest-seal-readiness",
        "disposition": disposition,
        "status": readiness.status,
        "readiness_sha256": readiness.readiness_sha256,
        "initialization_receipt_sha256": readiness.initialization_receipt_sha256,
        "initialized_file_sha256": readiness.initialized_file_sha256,
        "ddl_sha256": readiness.ddl_sha256,
        "logical_schema_manifest_sha256": readiness.logical_schema_manifest_sha256,
        "logical_schema_sha256": readiness.logical_schema_sha256,
        "split_approval_sha256": readiness.split_approval_sha256,
        "split_approval_receipt_sha256": readiness.split_approval_receipt_sha256,
        "empty_counts": readiness.empty_counts,
        "sidecars": readiness.sidecars,
        "same_uid_root_residual": readiness.same_uid_root_residual,
    }


def _seal_request_result(request: Any, *, disposition: str) -> dict[str, object]:
    return {
        "action": request.action,
        "binding_sha256": request.binding_sha256,
        "catalog_revision_sha256": request.catalog_revision_sha256,
        "counts": request.counts,
        "disposition": disposition,
        "logical_schema_sha256": request.logical_schema_sha256,
        "logical_seal_input_sha256": request.logical_seal_input_sha256,
        "request_sha256": request.request_sha256,
        "split_approval_sha256": request.split_approval_sha256,
        "split_approval_receipt_sha256": request.split_approval_receipt_sha256,
        "split_manifest_sha256": request.split_manifest_sha256,
        "state_attestation_sha256": request.state_attestation_sha256,
        "target_sha256": request.target_sha256,
    }


def _seal_receipt_result(receipt: Any, *, disposition: str) -> dict[str, object]:
    return {
        "action": receipt.action,
        "binding_sha256": receipt.binding_sha256,
        "counts": receipt.counts,
        "database_sha256": receipt.database_sha256,
        "disposition": disposition,
        "integrity_check": receipt.integrity_check,
        "foreign_key_check_count": receipt.foreign_key_check_count,
        "logical_schema_sha256": receipt.logical_schema_sha256,
        "logical_seal_sha256": receipt.logical_seal_sha256,
        "publication_disposition": receipt.publication_disposition,
        "receipt_sha256": receipt.receipt_sha256,
        "request_sha256": receipt.request_sha256,
        "sidecars": receipt.sidecars,
        "state_attestation_sha256": receipt.state_attestation_sha256,
        "target_sha256": receipt.target_sha256,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    paths = _paths(args)
    schema_dir = paths["schema_dir"].resolve(strict=True)
    result: dict[str, object]

    if args.build_tracked_empty_projection:
        research_path = (
            paths["repository_root"]
            / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
            / "02-SQLITE-TRANSITION-RESEARCH.md"
        )
        manifest, proof = build_tracked_empty_projection(
            schema_dir,
            research_path=research_path,
            as_of=date.today(),
        )
        result = {
            "action": "built",
            "logical_schema_sha256": manifest.logical_schema_sha256,
            "empty_file_sha256": proof.empty_file_sha256,
            "row_counts": proof.row_counts,
        }
    elif args.verify_tracked_empty_projection:
        proof = verify_empty_projection(schema_dir, as_of=date.today())
        result = {
            "action": "verified",
            "logical_schema_sha256": proof.logical_schema_sha256,
            "empty_file_sha256": proof.empty_file_sha256,
            "row_counts": proof.row_counts,
        }
    elif args.prepare_initialization_request:
        if args.authority_stdin:
            raise ValueError("request preparation does not accept authority input")
        now = datetime.now(UTC)
        _, request, _ = build_initialization_authority(
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            split_approval_path=paths["split_approval_path"],
            restricted_root=paths["restricted_root"],
            state_output=paths["state_path"],
            issuance_output=paths["issuance_path"],
            request_output=paths["request_path"],
            reviewer_id=args.reviewer_id or "phase2-sqlite-initializer",
            nonce=secrets.token_hex(32),
            issued_at=now,
            expires_at=now + timedelta(hours=2),
        )
        result = _request_result(request, disposition="PREPARED")
    elif args.check_initialization_request is not None:
        if args.authority_stdin:
            raise ValueError("request verification does not accept authority input")
        request_path = args.check_initialization_request.resolve(strict=True)
        request = check_initialization_request(
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            state_path=paths["state_path"].resolve(strict=True),
            issuance_context_path=paths["issuance_path"].resolve(strict=True),
            request_path=request_path,
        )
        result = _request_result(request, disposition="VERIFIED")
    elif args.initialize_restricted_empty is not None:
        if not args.authority_stdin:
            raise ValueError("restricted initialization requires --authority-stdin")
        if args.request is not None:
            raise ValueError("use --initialize-restricted-empty as the request path")
        raw_token = getpass.getpass("Protected initialization authority token: ")
        receipt = initialize_restricted_empty_database(
            raw_token=raw_token,
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            state_path=paths["state_path"].resolve(strict=True),
            issuance_context_path=paths["issuance_path"].resolve(strict=True),
            request_path=args.initialize_restricted_empty.resolve(strict=True),
            receipt_output=paths["receipt_path"],
            initialized_at=datetime.now(UTC),
        )
        result = _receipt_result(receipt, disposition="CREATED")
    elif args.verify_initialization_receipt is not None:
        if args.authority_stdin:
            raise ValueError("receipt verification does not accept authority input")
        receipt = verify_initialization_receipt(
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            state_path=paths["state_path"].resolve(strict=True),
            issuance_context_path=paths["issuance_path"].resolve(strict=True),
            request_path=paths["request_path"].resolve(strict=True),
            receipt_path=args.verify_initialization_receipt.resolve(strict=True),
        )
        result = _receipt_result(receipt, disposition="VERIFIED")
    elif args.verify_restricted_empty:
        if args.authority_stdin:
            raise ValueError("restricted readiness does not accept authority input")
        receipt_path = paths["receipt_path"].resolve(strict=True)
        readiness = verify_restricted_empty_database(
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            receipt_path=receipt_path,
        )
        result = _readiness_result(readiness, disposition="VERIFIED")
    elif args.prepare_seal_request:
        if args.authority_stdin:
            raise ValueError("seal request preparation does not accept authority input")
        now = datetime.now(UTC)
        _, seal_request, _ = build_seal_authority(
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            receipt_path=paths["receipt_path"].resolve(strict=True),
            materialized_bundle_path=paths["materialized_bundle_path"].resolve(strict=True),
            split_approval_path=paths["split_approval_path"].resolve(strict=True),
            reviewer_id=args.reviewer_id or "phase2-sqlite-sealer",
            nonce=secrets.token_hex(32),
            issued_at=now,
            expires_at=now + timedelta(hours=2),
            state_output=paths["seal_state_path"],
            issuance_output=paths["seal_issuance_path"],
            request_output=paths["seal_request_path"],
        )
        result = _seal_request_result(seal_request, disposition="PREPARED")
    elif args.check_seal_request is not None:
        if args.authority_stdin:
            raise ValueError("seal request verification does not accept authority input")
        seal_request = check_seal_request(
            repo_root=paths["repository_root"],
            schema_dir=schema_dir,
            receipt_path=paths["receipt_path"].resolve(strict=True),
            materialized_bundle_path=paths["materialized_bundle_path"].resolve(strict=True),
            split_approval_path=paths["split_approval_path"].resolve(strict=True),
            state_path=paths["seal_state_path"].resolve(strict=True),
            issuance_context_path=paths["seal_issuance_path"].resolve(strict=True),
            request_path=args.check_seal_request.resolve(strict=True),
        )
        result = _seal_request_result(seal_request, disposition="VERIFIED")
    else:
        if args.verify_seal_state is not None:
            if args.authority_stdin:
                raw_token = getpass.getpass("Protected seal authority token: ")
                seal_receipt = seal_restricted_manifest(
                    raw_token=raw_token,
                    repo_root=paths["repository_root"],
                    schema_dir=schema_dir,
                    receipt_path=paths["receipt_path"].resolve(strict=True),
                    materialized_bundle_path=paths["materialized_bundle_path"].resolve(strict=True),
                    split_approval_path=paths["split_approval_path"].resolve(strict=True),
                    state_path=args.verify_seal_state.resolve(strict=True),
                    issuance_context_path=paths["seal_issuance_path"].resolve(strict=True),
                    request_path=paths["seal_request_path"].resolve(strict=True),
                    seal_receipt_output=paths["seal_receipt_path"].resolve(strict=False),
                    now=datetime.now(UTC),
                )
                result = _seal_receipt_result(seal_receipt, disposition="COMMITTED_OR_RECOVERED")
            else:
                seal_request = check_seal_request(
                    repo_root=paths["repository_root"],
                    schema_dir=schema_dir,
                    receipt_path=paths["receipt_path"].resolve(strict=True),
                    materialized_bundle_path=paths["materialized_bundle_path"].resolve(strict=True),
                    split_approval_path=paths["split_approval_path"].resolve(strict=True),
                    state_path=args.verify_seal_state.resolve(strict=True),
                    issuance_context_path=paths["seal_issuance_path"].resolve(strict=True),
                    request_path=paths["seal_request_path"].resolve(strict=True),
                )
                result = _seal_request_result(seal_request, disposition="EXACT_UNSEALED")
        elif args.verify_seal_receipt is not None:
            if args.authority_stdin:
                raise ValueError("seal receipt verification does not accept authority input")
            seal_receipt = verify_seal_receipt(
                repo_root=paths["repository_root"],
                schema_dir=schema_dir,
                receipt_path=paths["receipt_path"].resolve(strict=True),
                materialized_bundle_path=paths["materialized_bundle_path"].resolve(strict=True),
                split_approval_path=paths["split_approval_path"].resolve(strict=True),
                state_path=paths["seal_state_path"].resolve(strict=True),
                issuance_context_path=paths["seal_issuance_path"].resolve(strict=True),
                request_path=paths["seal_request_path"].resolve(strict=True),
                seal_receipt_path=args.verify_seal_receipt.resolve(strict=True),
            )
            result = _seal_receipt_result(seal_receipt, disposition="VERIFIED")
        else:
            raise AssertionError("unreachable SQLite manifest action")

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
