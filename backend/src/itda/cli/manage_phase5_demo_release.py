"""Secret-free verification, status, and activation for the Phase 5 demo release."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from itda.db.phase5_demo_release import (
    PRODUCTION_ROOT,
    Phase5DemoReleaseError,
    Phase5DemoReleaseStore,
)
from itda.domain.canonical import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_SAFE_ROOT = "artifacts/restricted/catalog/phase5-demo-profile-materialization"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "status", "activate", "verify-candidate"):
        command = commands.add_parser(name)
        command.add_argument("--artifact-root", type=Path, default=PRODUCTION_ROOT)
        command.add_argument("--public-safe", action="store_true")
        command.add_argument("--expected-member-count", type=int, default=24)
        command.add_argument("--expected-origin", default="DEMO_MODEL_DERIVED")
    commands.choices["verify"].add_argument("--require-active", action="store_true")
    commands.choices["activate"].add_argument("--generation-sha256")
    commands.choices["activate"].add_argument("--expected-current-sha256")
    commands.choices["verify-candidate"].add_argument("--release-sha256", required=True)
    commands.choices["verify-candidate"].add_argument(
        "--require-state", default="DRAFT_QUARANTINED"
    )
    commands.choices["verify-candidate"].add_argument(
        "--require-all-activation-scenarios", action="store_true"
    )
    commands.choices["verify-candidate"].add_argument(
        "--require-all-contrasts", action="store_true"
    )
    commands.choices["verify-candidate"].add_argument("--json", action="store_true")
    return parser


def _fixed_root(value: Path) -> Path:
    resolved = (REPOSITORY_ROOT / value).resolve(strict=False)
    if resolved != PRODUCTION_ROOT:
        raise Phase5DemoReleaseError("CALLER_SELECTED_ROOT_FORBIDDEN")
    return resolved


def _generation_ids(root: Path) -> tuple[str, ...]:
    generations = root / "generations"
    if not generations.is_dir() or generations.is_symlink():
        raise Phase5DemoReleaseError("GENERATION_ROOT_UNAVAILABLE")
    values = tuple(
        sorted(
            child.name
            for child in generations.iterdir()
            if child.is_dir()
            and not child.is_symlink()
            and len(child.name) == 64
            and all(character in "0123456789abcdef" for character in child.name)
        )
    )
    if len(values) != 1:
        raise Phase5DemoReleaseError("EXACT_GENERATION_REQUIRED")
    return values


def _safe_candidate(candidate: object) -> dict[str, object]:
    value = candidate.model_dump(mode="json")  # type: ignore[attr-defined]
    payload = {
        "state": value["state"],
        "analysis_origin": value["analysis_origin"],
        "member_count": len(value["profiles"]),
        "release_sha256": value["release_sha256"],
        "membership_sha256": value["membership_sha256"],
        "hard_duplicate_adjudication_sha256": value["hard_duplicate_adjudication_sha256"],
        "generation_sha256": value["generation_sha256"],
        "generation_receipt_sha256": value["generation_receipt_sha256"],
        "attempt_count": value["attempt_count"],
        "retry_count": value["retry_count"],
        "model": value["model"],
        "prompt_version": value["prompt_version"],
        "artifact_root": _SAFE_ROOT,
    }
    if value["schema_version"] == "itda.phase5-coding-plan-release-candidate.v2":
        payload.update(
            {
                "provider_lane": value["provider_lane"],
                "accounting_mode": "CODING_PLAN_WEIGHT",
                "model_weight": value["model_weight"],
                "subscription_total_weight": value["subscription_total_weight"],
            }
        )
    elif value["schema_version"] == "itda.phase5-nvidia-minimax-release-candidate.v4":
        payload.update(
            {
                "provider_lane": value["provider_lane"],
                "endpoint": value["endpoint"],
                "authority_sha256": value["authority_sha256"],
                "config_sha256": value["config_sha256"],
            }
        )
    else:
        payload.update(
            {
                "pricing_snapshot_sha256": value["pricing_snapshot_sha256"],
                "committed_cost_micro_usd": value["committed_cost_micro_usd"],
            }
        )
    return payload


def _safe_recovery_candidate(candidate: object) -> dict[str, object]:
    value = candidate.model_dump(mode="json")  # type: ignore[attr-defined]
    return {
        "state": value["state"],
        "analysis_origin": value["analysis_origin"],
        "member_count": value["structural_profile_count"],
        "release_sha256": value["release_sha256"],
        "membership_sha256": value["membership_sha256"],
        "hard_duplicate_adjudication_sha256": value["hard_duplicate_adjudication_sha256"],
        "cannot_coappear_authority_sha256": value["cannot_coappear_authority_sha256"],
        "policy_sha256": value["policy_sha256"],
        "candidate_profile_count": value["candidate_profile_count"],
        "post_hard_duplicate_count": value["post_hard_duplicate_count"],
        "post_cannot_coappear_count": value["post_cannot_coappear_count"],
        "effective_candidate_count": value["effective_candidate_count"],
        "activation_suite_sha256": value["activation_suite_sha256"],
        "contrast_suite_sha256": value["contrast_suite_sha256"],
        "artifact_root": _SAFE_ROOT,
    }


def _emit(value: dict[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = _fixed_root(args.artifact_root)
        if args.expected_member_count != 24 or args.expected_origin != "DEMO_MODEL_DERIVED":
            raise Phase5DemoReleaseError("EXPECTED_RELEASE_CONTRACT_MISMATCH")
        store = Phase5DemoReleaseStore(root=root)
        if args.command == "verify-candidate":
            candidate = store.resolve_candidate_private(args.release_sha256)
            if candidate.state != args.require_state:
                raise Phase5DemoReleaseError("CANDIDATE_STATE_MISMATCH")
            payload = _safe_recovery_candidate(candidate)
            _emit(payload)
            return 0
        if args.command == "status":
            _emit(store.status())
            return 0
        if args.command == "activate":
            generation = args.generation_sha256 or _generation_ids(root)[0]
            candidate = store.build(generation)
            receipt = store.activate(
                candidate.release_sha256,
                expected_current_sha256=args.expected_current_sha256,
            )
            payload = _safe_candidate(candidate)
            payload.update(
                {
                    "state": receipt.state,
                    "activation_receipt_sha256": receipt.receipt_sha256,
                }
            )
            _emit(payload)
            return 0

        if args.require_active:
            snapshot = store.resolve_active()
            if snapshot is None:
                raise Phase5DemoReleaseError("NO_ACTIVE_SCORED_RELEASE")
            candidate = store.verify(snapshot.release_sha256)
        else:
            candidate = store.build(_generation_ids(root)[0])
        payload = _safe_candidate(candidate)
        if args.require_active:
            payload["state"] = "ACTIVE"
        _emit(payload)
        return 0
    except (
        FileExistsError,
        json.JSONDecodeError,
        OSError,
        Phase5DemoReleaseError,
        ValidationError,
        ValueError,
    ):
        print("PHASE5_DEMO_RELEASE_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
