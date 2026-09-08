"""Provider-free verification commands for MVP scored releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from itda.contracts.mvp_place_scoring import BoundScoringResult, PublicScoringRequest
from itda.contracts.mvp_public_catalog import (
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.db.mvp_scored_release import MvpScoredReleaseError, MvpScoredReleaseStore
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.mvp_place_scoring import verify_run_plan
from itda.pipeline.mvp_scored_release import materialize_scored_release, verify_release_inputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage an MVP scored release store")
    parser.add_argument("--root", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--require-active", action="store_true")
    verify.add_argument("--minimum-published-count", type=int, default=80)
    verify.add_argument("--expected-attempted-count", type=int, default=100)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("--catalog", type=Path, required=True)
    materialize.add_argument("--evidence-inventory", type=Path, required=True)
    materialize.add_argument("--relations", type=Path, required=True)
    materialize.add_argument("--results-root", type=Path, required=True)
    materialize.add_argument("--attempt-state", type=Path, required=True)
    materialize.add_argument("--run-plan", type=Path, required=True)
    materialize.add_argument("--requests", type=Path, required=True)
    materialize.add_argument("--canary-outcome", type=Path, required=True)
    materialize.add_argument("--entitlement-snapshot", type=Path, required=True)
    materialize.add_argument("--created-at", type=datetime.fromisoformat, required=True)
    materialize.add_argument("--output", type=Path, required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("path", type=Path)
    publish.add_argument("--catalog", type=Path, required=True)
    publish.add_argument("--evidence-inventory", type=Path, required=True)
    publish.add_argument("--relations", type=Path, required=True)
    publish.add_argument(
        "--permission-snapshot",
        action="append",
        default=[],
        metavar="METADATA_SHA256=PATH",
        required=True,
    )
    activate = commands.add_parser("activate")
    activate.add_argument("release_sha256")
    activate.add_argument("--expected-current")
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--expected-current", required=True)
    return parser


def _read_regular_bounded(path: Path, *, maximum_bytes: int = 2 * 1024 * 1024) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum_bytes:
        raise ValueError("permission snapshot file is invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != metadata.st_size:
            raise ValueError("permission snapshot file changed")
        raw = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size:
        raise ValueError("permission snapshot file changed")
    return raw


def _permission_snapshots(values: list[str]) -> dict[str, bytes]:
    snapshots: dict[str, bytes] = {}
    for value in values:
        metadata_sha256, separator, raw_path = value.partition("=")
        if (
            separator != "="
            or len(metadata_sha256) != 64
            or any(character not in "0123456789abcdef" for character in metadata_sha256)
            or not raw_path
            or metadata_sha256 in snapshots
        ):
            raise ValueError("permission snapshot binding is invalid")
        snapshots[metadata_sha256] = _read_regular_bounded(Path(raw_path))
    return snapshots


def _verify_completed_attempts(
    attempts: object,
    request_sha_by_id: Mapping[str, str],
) -> dict[str, list[dict[str, object]]]:
    if not isinstance(attempts, list):
        raise ValueError("release attempt state is incomplete")
    attempts_by_place: dict[str, list[dict[str, object]]] = {}
    for row in attempts:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "place_id",
                "request_sha256",
                "attempt_number",
                "status",
                "reason",
            }
            or not isinstance(row.get("place_id"), str)
            or row.get("status") not in {"SUCCEEDED", "FAILED"}
            or request_sha_by_id.get(row["place_id"]) != row.get("request_sha256")
        ):
            raise ValueError("release attempt state is incomplete")
        attempts_by_place.setdefault(row["place_id"], []).append(row)
    expected_place_ids = list(request_sha_by_id)
    first_passes = attempts[:100]
    if (
        set(attempts_by_place) != set(request_sha_by_id)
        or not 100 <= len(attempts) <= 200
        or [row["place_id"] for row in first_passes] != expected_place_ids
        or any(row["attempt_number"] != 1 for row in first_passes)
    ):
        raise ValueError("release attempt state does not cover exactly 100 first passes")
    expected_retries = [
        row["place_id"] for row in first_passes if row["status"] == "FAILED"
    ]
    retries = attempts[100:]
    if [row["place_id"] for row in retries] != expected_retries or any(
        row["attempt_number"] != 2 for row in retries
    ):
        raise ValueError("release attempt retry order is invalid")
    for place_attempts in attempts_by_place.values():
        if (
            len(place_attempts) not in {1, 2}
            or [row["attempt_number"] for row in place_attempts]
            != list(range(1, len(place_attempts) + 1))
            or any(
                (row["status"] == "SUCCEEDED" and row["reason"] is not None)
                or (row["status"] == "FAILED" and not isinstance(row["reason"], str))
                for row in place_attempts
            )
            or (len(place_attempts) == 2 and place_attempts[0]["status"] != "FAILED")
        ):
            raise ValueError("release attempt sequence is invalid")
    return attempts_by_place


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = MvpScoredReleaseStore(args.root)
    if args.command == "materialize":
        if args.output.exists():
            raise FileExistsError("release output already exists")
        catalog = PublicPlaceCatalog.model_validate_json(args.catalog.read_bytes())
        evidence_inventory = PublicEvidenceInventory.model_validate_json(
            args.evidence_inventory.read_bytes()
        )
        relations = PublicPlaceRelations.model_validate_json(args.relations.read_bytes())
        run_plan = json.loads(args.run_plan.read_bytes())
        verify_run_plan(run_plan)
        canary_outcome = json.loads(args.canary_outcome.read_bytes())
        entitlement = json.loads(args.entitlement_snapshot.read_bytes())
        attempt_state = json.loads(args.attempt_state.read_bytes())
        requests_payload = json.loads(args.requests.read_bytes())
        if not isinstance(requests_payload, list):
            raise ValueError("release request corpus is invalid")
        requests = tuple(
            PublicScoringRequest.model_validate(row) for row in requests_payload
        )
        if (
            len(requests) != 100
            or hashlib.sha256(args.requests.read_bytes()).hexdigest()
            != run_plan.get("corpus_file_sha256")
            or [row.place.place_id for row in requests] != run_plan.get("place_ids")
            or [row.request_sha256 for row in requests]
            != run_plan.get("place_request_sha256")
            or hashlib.sha256(args.canary_outcome.read_bytes()).hexdigest()
            != run_plan.get("canary_outcome_sha256")
        ):
            raise ValueError("release request lineage is invalid")
        if (
            not isinstance(run_plan, dict)
            or not isinstance(canary_outcome, dict)
            or not isinstance(entitlement, dict)
            or not isinstance(attempt_state, dict)
            or attempt_state.get("run_plan_sha256") != run_plan.get("run_plan_sha256")
            or not isinstance(attempt_state.get("attempts"), list)
            or canary_outcome.get("successful") is not True
            or canary_outcome.get("canary_plan_sha256")
            != run_plan.get("canary_plan_sha256")
            or entitlement.get("snapshot_sha256")
            != run_plan.get("entitlement_snapshot_sha256")
        ):
            raise ValueError("release lineage inputs are invalid")
        request_sha_by_id = {
            request.place.place_id: request.request_sha256 for request in requests
        }
        attempts_by_place = _verify_completed_attempts(
            attempt_state["attempts"], request_sha_by_id
        )
        attempted_place_ids = tuple(attempts_by_place)
        results = tuple(
            BoundScoringResult.model_validate_json(path.read_bytes())
            for path in sorted(args.results_root.glob("*.json"))
        )
        successful_place_ids = {
            place_id
            for place_id, place_attempts in attempts_by_place.items()
            if place_attempts[-1]["status"] == "SUCCEEDED"
        }
        if (
            {result.place_id for result in results} != successful_place_ids
            or any(
                request_sha_by_id.get(result.place_id) != result.request_sha256
                for result in results
            )
        ):
            raise ValueError("release result request binding is invalid")
        release = materialize_scored_release(
            catalog=catalog,
            evidence_inventory=evidence_inventory,
            relations=relations,
            results=results,
            attempted_place_ids=attempted_place_ids,
            source_sha256=hashlib.sha256(args.requests.read_bytes()).hexdigest(),
            entitlement_snapshot_sha256=str(run_plan["entitlement_snapshot_sha256"]),
            canary_plan_sha256=str(run_plan["canary_plan_sha256"]),
            canary_outcome_sha256=hashlib.sha256(args.canary_outcome.read_bytes()).hexdigest(),
            run_plan_sha256=str(run_plan["run_plan_sha256"]),
            created_at=args.created_at,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json_bytes(release.model_dump(mode="json")) + b"\n")
        print(
            f"release_sha256={release.release_sha256} attempted=100 "
            f"published={release.published_count}"
        )
        return 0
    if args.command == "verify":
        try:
            release = store.resolve_active()
        except MvpScoredReleaseError as error:
            if str(error) != "NO_ACTIVE_MVP_SCORED_RELEASE":
                raise
            print("state=NO_ACTIVE_MVP_SCORED_RELEASE")
            return 2 if args.require_active else 0
        if (
            release.published_count < args.minimum_published_count
            or release.attempted_count != args.expected_attempted_count
        ):
            return 2
        print(
            f"state=ACTIVE release_sha256={release.release_sha256} "
            f"attempted={release.attempted_count} published={release.published_count}"
        )
        return 0
    if args.command == "publish":
        release = MvpScoredRelease.model_validate_json(args.path.read_bytes())
        catalog = PublicPlaceCatalog.model_validate_json(args.catalog.read_bytes())
        evidence_inventory = PublicEvidenceInventory.model_validate_json(
            args.evidence_inventory.read_bytes()
        )
        relations = PublicPlaceRelations.model_validate_json(args.relations.read_bytes())
        permission_snapshots = _permission_snapshots(args.permission_snapshot)
        verify_release_inputs(
            release,
            catalog,
            evidence_inventory,
            relations,
            permission_snapshots,
        )
        store.publish(release)
        print(f"published={release.release_sha256}")
        return 0
    if args.command == "activate":
        pointer = store.activate(args.release_sha256, expected_current=args.expected_current)
    else:
        pointer = store.rollback(expected_current=args.expected_current)
    print(f"active={pointer.release_sha256} previous={pointer.previous_release_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
