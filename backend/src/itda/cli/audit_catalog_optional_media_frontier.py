"""Offline double replay and immutable optional-media frontier publication."""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from itda.cli.replay_catalog_optional_media import build_optional_media_projection
from itda.contracts.catalog_optional_media import OptionalMediaProjection
from itda.contracts.catalog_optional_media_frontier import (
    FrontierReplayAttestation,
    OptionalMediaFrontier,
    compare_frontier_replays,
    evaluate_optional_media_frontier,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

OUTPUT_BASE_REL = Path("artifacts/catalog/optional-media-v2/readiness")
EXPECTED_PLAN51_PROJECTION_ROOT = "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
EXPECTED_UNIVERSE_COUNT = 718
EXPECTED_ELIGIBLE_COUNT = 32
EXPECTED_GROUP_COUNTS = {
    "history_culture": 10,
    "history_scenery_boundary": 6,
    "image_modern_content": 3,
    "rest_walk_immersion": 13,
}
EXPECTED_GROUP_SHORTFALLS = {
    "history_culture": 0,
    "history_scenery_boundary": 0,
    "image_modern_content": 3,
    "rest_walk_immersion": 0,
}
EXPECTED_CAPPED_CAPACITY = 31
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
FRONTIER_ARTIFACT_FILENAMES = (
    "universe-accounting.json",
    "eligibility-replay.json",
    "representation-frontier.json",
    "representation-quota-config.json",
    "representation-quota-attestation.json",
    "frontier-replay-attestation.json",
)


class OptionalMediaFrontierAuditError(ValueError):
    """Fail-closed frontier replay or publication error."""


@dataclass(frozen=True)
class OptionalMediaFrontierAudit:
    first_projection: OptionalMediaProjection
    second_projection: OptionalMediaProjection
    first_frontier: OptionalMediaFrontier
    second_frontier: OptionalMediaFrontier
    replay_attestation: FrontierReplayAttestation

    @property
    def exit_code(self) -> int:
        return 23 if self.first_frontier.status == "REPRESENTATION_INFEASIBLE" else 0


def _digest_artifact(payload: Mapping[str, object]) -> dict[str, object]:
    return {
        **payload,
        "artifact_sha256": canonical_sha256(payload),
    }


def _artifact_bytes(
    frontier: OptionalMediaFrontier,
    replay_attestation: FrontierReplayAttestation,
) -> dict[str, bytes]:
    universe = _digest_artifact(
        {
            "schema_version": "itda.catalog-optional-media-universe-accounting.v2",
            "policy_version": frontier.policy_version,
            "policy_sha256": frontier.policy_sha256,
            "universe_root_sha256": frontier.universe_root_sha256,
            "universe_candidates_root_sha256": frontier.universe_candidates_root_sha256,
            "universe_count": frontier.universe_count,
            "accounting_rows": [row.model_dump(mode="json") for row in frontier.accounting_rows],
            "accounting_rows_root_sha256": frontier.accounting_rows_root_sha256,
        }
    )
    eligibility = _digest_artifact(
        {
            "schema_version": "itda.catalog-optional-media-eligibility-replay.v2",
            "policy_version": frontier.policy_version,
            "policy_sha256": frontier.policy_sha256,
            "universe_root_sha256": frontier.universe_root_sha256,
            "eligible_count": frontier.eligible_count,
            "eligible_pool_sha256": frontier.eligible_pool_sha256,
            "group_counts": frontier.group_counts,
            "group_shortfalls": frontier.group_shortfalls,
            "capped_capacity": frontier.capped_capacity,
            "closure_frontier": [row.model_dump(mode="json") for row in frontier.closure_frontier],
            "image_medium_is_not_a_place_gate": True,
            "catalog_ready": False,
            "plan20_reachable": False,
        }
    )
    return {
        "universe-accounting.json": canonical_json_bytes(universe),
        "eligibility-replay.json": canonical_json_bytes(eligibility),
        "representation-frontier.json": canonical_json_bytes(frontier.model_dump(mode="json")),
        "representation-quota-config.json": canonical_json_bytes(
            frontier.representation_quota_config.model_dump(mode="json")
        ),
        "representation-quota-attestation.json": canonical_json_bytes(
            frontier.representation_quota.model_dump(mode="json")
        ),
        "frontier-replay-attestation.json": canonical_json_bytes(
            replay_attestation.model_dump(mode="json")
        ),
    }


def _assert_current_evidence(
    projection: OptionalMediaProjection,
    frontier: OptionalMediaFrontier,
) -> None:
    if projection.projection_sha256 != EXPECTED_PLAN51_PROJECTION_ROOT:
        raise OptionalMediaFrontierAuditError("Plan 51 projection root drifted")
    if frontier.universe_root_sha256 != projection.projection_sha256:
        raise OptionalMediaFrontierAuditError("frontier uses a mixed universe root")
    if frontier.universe_candidates_root_sha256 != (
        projection.candidate_set.candidates_root_sha256
    ):
        raise OptionalMediaFrontierAuditError("frontier candidate root drifted")
    exact_evidence = (
        frontier.universe_count == EXPECTED_UNIVERSE_COUNT
        and frontier.eligible_count == EXPECTED_ELIGIBLE_COUNT
        and frontier.group_counts == EXPECTED_GROUP_COUNTS
        and frontier.group_shortfalls == EXPECTED_GROUP_SHORTFALLS
        and frontier.capped_capacity == EXPECTED_CAPPED_CAPACITY
        and frontier.status == "REPRESENTATION_INFEASIBLE"
        and frontier.representation_quota.outcome_code == 23
        and not frontier.representation_quota.feasible
        and frontier.representation_quota.final_quotas == {}
        and frontier.representation_quota.quota_sum == 0
    )
    if not exact_evidence:
        raise OptionalMediaFrontierAuditError("CURRENT_FRONTIER_EVIDENCE_DRIFT")


def build_optional_media_frontier_audit(
    repository_root: Path | str,
) -> OptionalMediaFrontierAudit:
    """Independently reconstruct and compare the sealed policy-v2 universe twice."""

    root = Path(repository_root).resolve(strict=True)
    first_projection = build_optional_media_projection(root)
    second_projection = build_optional_media_projection(root)
    if canonical_json_bytes(first_projection.model_dump(mode="json")) != canonical_json_bytes(
        second_projection.model_dump(mode="json")
    ):
        raise OptionalMediaFrontierAuditError("POLICY_V2_PROJECTION_REPLAY_MISMATCH")
    first_frontier = evaluate_optional_media_frontier(
        first_projection.candidates,
        first_projection.policy,
        first_projection.projection_sha256,
    )
    second_frontier = evaluate_optional_media_frontier(
        second_projection.candidates,
        second_projection.policy,
        second_projection.projection_sha256,
    )
    try:
        replay_attestation = compare_frontier_replays(
            first_frontier,
            second_frontier,
        )
    except ValueError as exc:
        raise OptionalMediaFrontierAuditError(str(exc)) from exc
    _assert_current_evidence(first_projection, first_frontier)
    _assert_current_evidence(second_projection, second_frontier)
    first_files = _artifact_bytes(first_frontier, replay_attestation)
    second_files = _artifact_bytes(second_frontier, replay_attestation)
    if first_files != second_files:
        raise OptionalMediaFrontierAuditError("FRONTIER_ARTIFACT_REPLAY_MISMATCH")
    return OptionalMediaFrontierAudit(
        first_projection=first_projection,
        second_projection=second_projection,
        first_frontier=first_frontier,
        second_frontier=second_frontier,
        replay_attestation=replay_attestation,
    )


def _assert_nofollow_ancestors(path: Path) -> None:
    current = path.absolute()
    while True:
        if current.is_symlink():
            raise OptionalMediaFrontierAuditError("frontier path ancestor is a symlink")
        if current.parent == current:
            return
        current = current.parent


def _read_regular_bytes_nofollow(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OptionalMediaFrontierAuditError(
            "frontier artifact is not a no-follow regular file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARTIFACT_BYTES:
            raise OptionalMediaFrontierAuditError("frontier artifact is not bounded regular data")
        payload = b""
        while len(payload) <= MAX_ARTIFACT_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_ARTIFACT_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        if len(payload) != metadata.st_size:
            raise OptionalMediaFrontierAuditError("frontier artifact changed during read")
        return payload
    finally:
        os.close(descriptor)


def _verify_existing_publication(target: Path, files: Mapping[str, bytes]) -> None:
    _assert_nofollow_ancestors(target)
    if target.is_symlink() or not target.is_dir():
        raise OptionalMediaFrontierAuditError("content-addressed frontier root cannot be a symlink")
    entries = list(target.iterdir())
    if {path.name for path in entries} != set(FRONTIER_ARTIFACT_FILENAMES):
        raise OptionalMediaFrontierAuditError("existing frontier inventory differs")
    for filename, expected in files.items():
        if _read_regular_bytes_nofollow(target / filename) != expected:
            raise OptionalMediaFrontierAuditError(
                "existing frontier publication differs from replay"
            )


def publish_optional_media_frontier_audit(
    audit: OptionalMediaFrontierAudit,
    *,
    repository_root: Path | str,
    output_base: Path | str | None = None,
) -> Path:
    """Rederive and publish one immutable content-addressed frontier root."""

    root = Path(repository_root).resolve(strict=True)
    rebuilt = build_optional_media_frontier_audit(root)
    if audit != rebuilt:
        raise OptionalMediaFrontierAuditError(
            "caller-supplied frontier audit was patched or replay-divergent"
        )
    if output_base is None:
        base = root / OUTPUT_BASE_REL
    else:
        raw_base = Path(output_base).expanduser()
        if ".." in raw_base.parts:
            raise OptionalMediaFrontierAuditError("frontier output path escape is forbidden")
        base = raw_base.absolute()
    _assert_nofollow_ancestors(base)
    if base.is_symlink():
        raise OptionalMediaFrontierAuditError("frontier output base cannot be a symlink")
    base.mkdir(parents=True, exist_ok=True)
    target = base / rebuilt.first_frontier.frontier_sha256
    files = _artifact_bytes(
        rebuilt.first_frontier,
        rebuilt.replay_attestation,
    )
    if tuple(files) != FRONTIER_ARTIFACT_FILENAMES:
        raise OptionalMediaFrontierAuditError("frontier publication inventory drifted")
    if target.exists() or target.is_symlink():
        _verify_existing_publication(target, files)
        return target

    with tempfile.TemporaryDirectory(prefix=".optional-media-frontier-", dir=base) as raw_stage:
        stage = Path(raw_stage)
        for filename, payload in files.items():
            descriptor = os.open(
                stage / filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )
            try:
                written = os.write(descriptor, payload)
                if written != len(payload):
                    raise OSError("short write while staging optional-media frontier")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        created_target = False
        created_files: list[Path] = []
        try:
            target.mkdir(mode=0o755)
            created_target = True
            for filename in files:
                destination = target / filename
                os.link(stage / filename, destination)
                created_files.append(destination)
            descriptor = os.open(target, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            descriptor = os.open(base, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BaseException:
            for path in created_files:
                path.unlink(missing_ok=True)
            if created_target:
                target.rmdir()
            raise
    _verify_existing_publication(target, files)
    return target


def _only_frontier_root(base: Path) -> Path:
    _assert_nofollow_ancestors(base)
    if base.is_symlink() or not base.is_dir():
        raise OptionalMediaFrontierAuditError("optional-media readiness base is invalid")
    entries = list(base.iterdir())
    roots = [
        path
        for path in entries
        if path.is_dir()
        and not path.is_symlink()
        and len(path.name) == 64
        and all(character in "0123456789abcdef" for character in path.name)
    ]
    if len(entries) != 1 or len(roots) != 1:
        raise OptionalMediaFrontierAuditError(
            "expected exactly one content-addressed frontier root"
        )
    return roots[0]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository_root = Path(__file__).resolve().parents[4]
    audit = build_optional_media_frontier_audit(repository_root)
    files = _artifact_bytes(audit.first_frontier, audit.replay_attestation)
    if args.build:
        published = publish_optional_media_frontier_audit(
            audit,
            repository_root=repository_root,
        )
    else:
        published = _only_frontier_root(repository_root / OUTPUT_BASE_REL)
        if published.name != audit.first_frontier.frontier_sha256:
            raise OptionalMediaFrontierAuditError("recorded frontier root differs from replay")
        _verify_existing_publication(published, files)
    print(audit.first_frontier.frontier_sha256)
    return audit.exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXPECTED_CAPPED_CAPACITY",
    "EXPECTED_ELIGIBLE_COUNT",
    "EXPECTED_GROUP_COUNTS",
    "EXPECTED_GROUP_SHORTFALLS",
    "EXPECTED_PLAN51_PROJECTION_ROOT",
    "EXPECTED_UNIVERSE_COUNT",
    "FRONTIER_ARTIFACT_FILENAMES",
    "OUTPUT_BASE_REL",
    "OptionalMediaFrontierAudit",
    "OptionalMediaFrontierAuditError",
    "build_optional_media_frontier_audit",
    "main",
    "publish_optional_media_frontier_audit",
]
