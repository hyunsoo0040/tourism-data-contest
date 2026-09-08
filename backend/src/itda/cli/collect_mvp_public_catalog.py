"""Build, verify, and explicitly execute bounded MVP catalog enrichment."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from itda.cli.prepare_mvp_public_catalog import permission_inputs_from_cli
from itda.contracts.mvp_catalog_enrichment import (
    MvpCatalogEnrichmentPlan,
    MvpCatalogEnrichmentResult,
    TourApiDiagnosticCanaryPlan,
    TourApiDiagnosticCanaryResult,
)
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.mvp_catalog_enrichment import (
    APPROVAL_PREFIX,
    CANARY_APPROVAL_PREFIX,
    TOURAPI_CREDENTIAL_ENV,
    TourApiDetailTransport,
    build_diagnostic_canary_plan,
    build_enrichment_plan,
    require_mvp_collection_allowed,
    run_diagnostic_canary,
    run_enrichment,
    validate_canary_approval,
    validate_collection_approval,
)
from itda.pipeline.mvp_public_catalog import build_catalog_gap_report


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _default_source() -> Path:
    return (
        _repository_root()
        / "artifacts/catalog/optional-media-v2/policy"
        / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
        / "projected-candidates.json"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded TourAPI PUBLIC catalog enrichment")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect-gap")
    inspect.add_argument("--source", type=Path, default=_default_source())

    build = subparsers.add_parser("build-plan")
    build.add_argument("--source", type=Path, default=_default_source())
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--spare-count", type=int, default=20)
    build.add_argument("--previous-attempt-result", type=Path, required=True)
    build.add_argument("--successful-canary-result", type=Path, required=True)
    build.add_argument(
        "--permission",
        action="append",
        required=True,
        metavar="METADATA_JSON=RAW_SNAPSHOT",
    )

    verify = subparsers.add_parser("verify-plan")
    verify.add_argument("plan", type=Path)

    build_canary = subparsers.add_parser("build-canary")
    build_canary.add_argument("--plan", type=Path, required=True)
    build_canary.add_argument("--result", type=Path, required=True)
    build_canary.add_argument("--previous-canary-result", type=Path)
    build_canary.add_argument("--output", type=Path, required=True)

    verify_canary = subparsers.add_parser("verify-canary")
    verify_canary.add_argument("plan", type=Path)

    execute_canary = subparsers.add_parser("execute-canary")
    execute_canary.add_argument("plan", type=Path)
    execute_canary.add_argument("--expected-plan-sha256", required=True)
    execute_canary.add_argument("--approval", required=True)
    execute_canary.add_argument("--output", type=Path, required=True)
    execute_canary.add_argument("--live", action="store_true")

    execute = subparsers.add_parser("execute")
    execute.add_argument("plan", type=Path)
    execute.add_argument("--expected-plan-sha256", required=True)
    execute.add_argument("--approval", required=True)
    execute.add_argument("--output-root", type=Path, required=True)
    execute.add_argument("--live", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inspect-gap":
        gap = build_catalog_gap_report(args.source)
        print(
            f"description_ready_historical={gap.description_ready_historical_count} "
            f"description_enrichment_candidates={gap.description_enrichment_candidate_count} "
            f"description_gap={gap.preliminary_description_gap_count} "
            f"strict_rights_state={gap.strict_rights_state.lower()} "
            "catalog_ready=false provider_traffic=false"
        )
        return 2

    if args.command == "build-plan":
        permissions, permission_snapshots = permission_inputs_from_cli(args.permission)
        previous_attempt_result = MvpCatalogEnrichmentResult.model_validate_json(
            args.previous_attempt_result.read_bytes()
        )
        successful_canary_result = TourApiDiagnosticCanaryResult.model_validate_json(
            args.successful_canary_result.read_bytes()
        )
        plan = build_enrichment_plan(
            args.source,
            permissions=permissions,
            permission_snapshots=permission_snapshots,
            previous_attempt_result=previous_attempt_result,
            successful_canary_result=successful_canary_result,
            spare_count=args.spare_count,
        )
        _write_new(args.output, canonical_json_bytes(plan.model_dump(mode="json")) + b"\n")
        print(
            f"plan_sha256={plan.plan_sha256} requests={plan.max_requests} "
            f"description_success_required={plan.description_success_required} "
            "strict_rights_state=permission_metadata_verified provider_traffic=false"
        )
        return 0

    if args.command == "build-canary":
        enrichment_plan = MvpCatalogEnrichmentPlan.model_validate_json(
            args.plan.read_bytes()
        )
        enrichment_result = MvpCatalogEnrichmentResult.model_validate_json(
            args.result.read_bytes()
        )
        previous_canary_result = (
            TourApiDiagnosticCanaryResult.model_validate_json(
                args.previous_canary_result.read_bytes()
            )
            if args.previous_canary_result is not None
            else None
        )
        canary = build_diagnostic_canary_plan(
            enrichment_plan,
            enrichment_result,
            previous_canary_result=previous_canary_result,
        )
        _write_new(args.output, canonical_json_bytes(canary.model_dump(mode="json")) + b"\n")
        print(
            f"plan_sha256={canary.plan_sha256} requests=1 "
            "provider_traffic=false"
        )
        return 0

    if args.command in {"verify-canary", "execute-canary"}:
        canary = TourApiDiagnosticCanaryPlan.model_validate_json(
            args.plan.read_bytes()
        )
        if args.command == "verify-canary":
            print(
                f"plan_sha256={canary.plan_sha256} requests=1 "
                f"approval={CANARY_APPROVAL_PREFIX}<PLAN_SHA256>"
            )
            return 0
        validate_canary_approval(
            canary,
            expected_plan_sha256=args.expected_plan_sha256,
            approval=args.approval,
        )
        require_mvp_collection_allowed(explicit_live=args.live)
        transport = TourApiDetailTransport(_service_key())
        try:
            result = run_diagnostic_canary(
                canary,
                transport=transport,
                output_path=args.output,
            )
        finally:
            transport.close()
        print(
            f"attempted=1 normalized_outcome={result.normalized_outcome.lower()} "
            f"provider_result_code={result.provider_result_code or 'none'} "
            "raw_response_persisted=false"
        )
        return 0 if result.normalized_outcome == "SUCCESS" else 2

    plan = MvpCatalogEnrichmentPlan.model_validate_json(args.plan.read_bytes())
    if args.command == "verify-plan":
        print(
            f"plan_sha256={plan.plan_sha256} requests={plan.max_requests} "
            f"approval={APPROVAL_PREFIX}<PLAN_SHA256>"
        )
        return 0

    validate_collection_approval(
        plan,
        expected_plan_sha256=args.expected_plan_sha256,
        approval=args.approval,
    )
    require_mvp_collection_allowed(explicit_live=args.live)
    transport = TourApiDetailTransport(_service_key())
    try:
        result = run_enrichment(plan, transport=transport, output_root=args.output_root)
    finally:
        transport.close()
    print(
        f"attempted={result.attempted_count} successful={result.successful_count} "
        f"description_gap_remaining={result.description_gap_remaining} "
        "strict_rights_state=permission_metadata_verified catalog_ready=false "
        "public_artifact_written=false"
    )
    return _execution_exit_code(result)


def _service_key() -> str:
    service_key = os.environ.get(TOURAPI_CREDENTIAL_ENV)
    if not service_key:
        raise PermissionError("TourAPI credential is absent")
    return service_key


def _execution_exit_code(result: MvpCatalogEnrichmentResult) -> int:
    if (
        result.description_gap_remaining
        or not result.catalog_ready
        or not result.public_artifact_written
    ):
        return 2
    return 0


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


if __name__ == "__main__":
    raise SystemExit(main())
