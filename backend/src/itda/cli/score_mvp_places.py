"""Provider-free plan commands and explicitly approved MVP scoring execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from itda.contracts.mvp_place_scoring import (
    GLM_CODING_ENDPOINT,
    GLM_MODEL,
    MVP_SCORING_PROMPT_SHA256,
    PUBLIC_SCORING_RUBRIC,
    ProviderWireScoringResponse,
    PublicScoringRequest,
    reject_forbidden_fields,
)
from itda.contracts.mvp_public_catalog import PublicEvidenceInventory, PublicPlaceCatalog
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_place_scoring import (
    CONSUMED_INTERRUPTED_RUN_PLAN_SHA256S,
    GlmCodingScoringTransport,
    MvpScoringError,
    build_canary_plan,
    build_continuation_plan,
    build_run_plan,
    build_scoring_requests,
    consume_execution_authority,
    execute_batch,
    execute_diagnostic,
    load_attempt_counts,
    load_resumed_results,
    persist_attempt_event,
    persist_scoring_result,
    prepare_continuation_state,
    require_live_network_allowed,
    result_manifest,
    verify_canary_plan,
    verify_requests_match_run_plan,
    verify_run_plan,
)


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, payload: object) -> None:
    if path.exists():
        raise FileExistsError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload) + b"\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare bounded MVP scoring")
    commands = parser.add_subparsers(dest="command", required=True)

    build_requests = commands.add_parser("build-requests")
    build_requests.add_argument("--catalog", type=Path, required=True)
    build_requests.add_argument("--evidence", type=Path, required=True)
    build_requests.add_argument("--output", type=Path, required=True)

    build_canary_inputs = commands.add_parser("build-canary-inputs")
    build_canary_inputs.add_argument("--catalog", type=Path, required=True)
    build_canary_inputs.add_argument("--evidence", type=Path, required=True)
    build_canary_inputs.add_argument("--selection-output", type=Path, required=True)
    build_canary_inputs.add_argument("--evidence-output", type=Path, required=True)
    build_canary_inputs.add_argument("--request-output", type=Path, required=True)

    build_canary = commands.add_parser("build-canary-plan")
    build_canary.add_argument("--request", type=Path, required=True)
    build_canary.add_argument("--selection", type=Path, required=True)
    build_canary.add_argument("--output", type=Path, required=True)
    build_canary.add_argument("--catalog-sha256", required=True)
    build_canary.add_argument("--evidence-inventory-sha256", required=True)
    build_canary.add_argument("--prompt-sha256", required=True)
    build_canary.add_argument("--entitlement-snapshot-sha256", required=True)

    verify_canary = commands.add_parser("verify-canary-plan")
    verify_canary.add_argument("path", type=Path)

    execute_canary = commands.add_parser("execute-canary")
    execute_canary.add_argument("--plan", type=Path, required=True)
    execute_canary.add_argument("--request", type=Path, required=True)
    execute_canary.add_argument("--selection", type=Path, required=True)
    execute_canary.add_argument("--output-root", type=Path, required=True)
    execute_canary.add_argument("--reviewed-plan-sha256", required=True)
    execute_canary.add_argument("--approval", required=True)
    execute_canary.add_argument("--live", action="store_true")

    build_continuation = commands.add_parser("build-continuation-plan")
    build_continuation.add_argument("--predecessor-plan", type=Path, required=True)
    build_continuation.add_argument("--predecessor-root", type=Path, required=True)
    build_continuation.add_argument("--requests", type=Path, required=True)
    build_continuation.add_argument("--output", type=Path, required=True)

    build = commands.add_parser("build-plan")
    build.add_argument("--requests", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--catalog-sha256", required=True)
    build.add_argument("--evidence-inventory-sha256", required=True)
    build.add_argument("--prompt-sha256", required=True)
    build.add_argument("--entitlement-snapshot-sha256", required=True)
    build.add_argument("--canary-plan-sha256", required=True)
    build.add_argument("--canary-outcome-sha256", required=True)

    verify = commands.add_parser("verify-plan")
    verify.add_argument("path", type=Path)

    prepare_continuation = commands.add_parser("prepare-continuation")
    prepare_continuation.add_argument("--plan", type=Path, required=True)
    prepare_continuation.add_argument("--predecessor-root", type=Path, required=True)
    prepare_continuation.add_argument("--requests", type=Path, required=True)
    prepare_continuation.add_argument("--output-root", type=Path, required=True)

    execute = commands.add_parser("execute")
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument("--requests", type=Path, required=True)
    execute.add_argument("--canary-outcome", type=Path, required=True)
    execute.add_argument("--output-root", type=Path, required=True)
    execute.add_argument("--reviewed-plan-sha256", required=True)
    execute.add_argument("--approval", required=True)
    execute.add_argument("--live", action="store_true")
    return parser


def _load_request(path: Path) -> PublicScoringRequest:
    return PublicScoringRequest.model_validate(_load_json(path))


def _load_requests(path: Path) -> tuple[PublicScoringRequest, ...]:
    value = _load_json(path)
    if not isinstance(value, list):
        raise MvpScoringError("REQUEST_CORPUS_INVALID")
    return tuple(PublicScoringRequest.model_validate(row) for row in value)


def _validate_canary_selection(
    path: Path,
    request: PublicScoringRequest,
    *,
    catalog_sha256: str,
    evidence_inventory_sha256: str,
) -> str:
    value = _load_json(path)
    expected_fields = {
        "schema_version",
        "selection_rule",
        "selected_place_id",
        "public_catalog_sha256",
        "public_catalog_file_sha256",
        "public_catalog_overlap_count",
        "canary_evidence_inventory_sha256",
        "request_sha256",
        "full_campaign_attempt_credit",
        "release_eligible",
        "provider_traffic",
        "secret_access",
        "selection_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise MvpScoringError("CANARY_SELECTION_FIELDS_INVALID")
    supplied = value["selection_sha256"]
    expected = canonical_sha256(
        {key: item for key, item in value.items() if key != "selection_sha256"}
    )
    if supplied != expected:
        raise MvpScoringError("CANARY_SELECTION_HASH_INVALID")
    if (
        value["schema_version"] != "mvp-place-scoring-canary-selection.v3"
        or value["selection_rule"] != "FIRST_PUBLIC_PLACE_BY_CANONICAL_PLACE_ID"
        or value["selected_place_id"] != request.place.place_id
        or value["request_sha256"] != request.request_sha256
        or value["public_catalog_sha256"] != catalog_sha256
        or value["canary_evidence_inventory_sha256"] != evidence_inventory_sha256
        or value["public_catalog_overlap_count"] != 0
        or value["full_campaign_attempt_credit"] is not False
        or value["release_eligible"] is not False
        or value["provider_traffic"] is not False
        or value["secret_access"] is not False
    ):
        raise MvpScoringError("CANARY_SELECTION_BINDING_INVALID")
    if not isinstance(supplied, str):
        raise MvpScoringError("CANARY_SELECTION_HASH_INVALID")
    return supplied


def _build_canary_inputs(
    catalog_path: Path,
    evidence_path: Path,
) -> tuple[dict[str, object], PublicEvidenceInventory, PublicScoringRequest]:
    catalog = PublicPlaceCatalog.model_validate_json(catalog_path.read_bytes())
    evidence_inventory = PublicEvidenceInventory.model_validate_json(evidence_path.read_bytes())
    if (
        catalog.evidence_inventory_sha256 != evidence_inventory.inventory_sha256
        or catalog.blind_overlap_count != 0
    ):
        raise MvpScoringError("CANARY_SOURCE_BINDING_INVALID")
    place = catalog.places[0]
    evidence_by_id = {row.evidence_id: row for row in evidence_inventory.evidence}
    if not set(place.evidence_ids).issubset(evidence_by_id):
        raise MvpScoringError("CANARY_SOURCE_EVIDENCE_INVALID")
    selected_evidence = tuple(evidence_by_id[evidence_id] for evidence_id in place.evidence_ids)
    inventory_fields = {
        "schema_version": "public-evidence-inventory.v1",
        "evidence": selected_evidence,
    }
    canary_evidence = PublicEvidenceInventory.model_validate(
        {
            **inventory_fields,
            "inventory_sha256": canonical_sha256(
                {
                    "schema_version": inventory_fields["schema_version"],
                    "evidence": [row.model_dump(mode="json") for row in selected_evidence],
                }
            ),
        }
    )
    request_fields = {
        "schema_version": "mvp-place-scoring-request.v2",
        "model": GLM_MODEL,
        "place": {
            "place_id": place.place_id,
            "name_ko": place.name_ko,
            "category": place.category,
            "administrative_area": place.administrative_area,
            "address_ko": place.address_ko,
            "latitude": place.latitude,
            "longitude": place.longitude,
        },
        "evidence": tuple(
            {"evidence_id": row.evidence_id, "excerpt": row.excerpt}
            for row in selected_evidence
        ),
        "rubric": PUBLIC_SCORING_RUBRIC,
    }
    reject_forbidden_fields(request_fields)
    request = PublicScoringRequest.model_validate(
        {**request_fields, "request_sha256": canonical_sha256(request_fields)}
    )
    selection_fields: dict[str, object] = {
        "schema_version": "mvp-place-scoring-canary-selection.v3",
        "selection_rule": "FIRST_PUBLIC_PLACE_BY_CANONICAL_PLACE_ID",
        "selected_place_id": place.place_id,
        "public_catalog_sha256": catalog.catalog_sha256,
        "public_catalog_file_sha256": _sha256_file(catalog_path),
        "public_catalog_overlap_count": catalog.blind_overlap_count,
        "canary_evidence_inventory_sha256": canary_evidence.inventory_sha256,
        "request_sha256": request.request_sha256,
        "full_campaign_attempt_credit": False,
        "release_eligible": False,
        "provider_traffic": False,
        "secret_access": False,
    }
    selection = {
        **selection_fields,
        "selection_sha256": canonical_sha256(selection_fields),
    }
    return selection, canary_evidence, request


def _response_schema_sha256() -> str:
    return hashlib.sha256(
        canonical_json_bytes(ProviderWireScoringResponse.model_json_schema())
    ).hexdigest()


def _validate_canary_outcome(path: Path, plan: dict[str, object]) -> None:
    if _sha256_file(path) != plan["canary_outcome_sha256"]:
        raise MvpScoringError("CANARY_OUTCOME_HASH_MISMATCH")
    value = _load_json(path)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "canary_plan_sha256",
            "endpoint",
            "model",
            "successful",
            "failure",
            "completion_call_count",
        }
        or value["schema_version"] != "mvp-place-scoring-canary-outcome.v1"
        or value["canary_plan_sha256"] != plan["canary_plan_sha256"]
        or value["endpoint"] != GLM_CODING_ENDPOINT
        or value["model"] != GLM_MODEL
        or value["successful"] is not True
        or value["failure"] is not None
        or value["completion_call_count"] != 1
    ):
        raise MvpScoringError("CANARY_OUTCOME_INVALID")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "build-requests":
        catalog = PublicPlaceCatalog.model_validate_json(args.catalog.read_bytes())
        evidence = PublicEvidenceInventory.model_validate_json(args.evidence.read_bytes())
        requests = build_scoring_requests(catalog, evidence)
        _write_new(args.output, [row.model_dump(mode="json") for row in requests])
        print(
            f"requests={len(requests)} catalog_sha256={catalog.catalog_sha256} "
            f"evidence_inventory_sha256={evidence.inventory_sha256} "
            f"prompt_sha256={MVP_SCORING_PROMPT_SHA256} traffic_authorization=false"
        )
        return 0

    if args.command == "build-canary-inputs":
        outputs = (args.selection_output, args.evidence_output, args.request_output)
        if len(set(outputs)) != 3 or any(path.exists() for path in outputs):
            raise FileExistsError("canary inputs require three new output paths")
        selection, evidence, request = _build_canary_inputs(args.catalog, args.evidence)
        _write_new(args.selection_output, selection)
        _write_new(args.evidence_output, evidence.model_dump(mode="json"))
        _write_new(args.request_output, request.model_dump(mode="json"))
        print(
            f"selection_sha256={selection['selection_sha256']} "
            f"request_sha256={request.request_sha256} "
            f"evidence_inventory_sha256={evidence.inventory_sha256} "
            "traffic_authorization=false"
        )
        return 0

    if args.command == "build-canary-plan":
        request = _load_request(args.request)
        selection_sha256 = _validate_canary_selection(
            args.selection,
            request,
            catalog_sha256=args.catalog_sha256,
            evidence_inventory_sha256=args.evidence_inventory_sha256,
        )
        plan = build_canary_plan(
            request,
            catalog_sha256=args.catalog_sha256,
            evidence_inventory_sha256=args.evidence_inventory_sha256,
            prompt_sha256=args.prompt_sha256,
            response_schema_sha256=_response_schema_sha256(),
            entitlement_snapshot_sha256=args.entitlement_snapshot_sha256,
            canary_selection_sha256=selection_sha256,
        )
        _write_new(args.output, plan)
        print(
            f"canary_plan_sha256={plan['canary_plan_sha256']} maximum_calls=1 "
            "traffic_authorization=false"
        )
        return 0

    if args.command == "build-continuation-plan":
        requests = _load_requests(args.requests)
        predecessor = _load_json(args.predecessor_plan)
        if not isinstance(predecessor, dict):
            raise MvpScoringError("CONTINUATION_PREDECESSOR_PLAN_INVALID")
        predecessor_sha256 = verify_run_plan(predecessor)
        if predecessor_sha256 not in CONSUMED_INTERRUPTED_RUN_PLAN_SHA256S:
            raise MvpScoringError("CONTINUATION_PREDECESSOR_NOT_CONSUMED")
        attempt_path = args.predecessor_root / "attempt-state.json"
        attempt_state = _load_json(attempt_path)
        if (
            not isinstance(attempt_state, dict)
            or attempt_state.get("run_plan_sha256") != predecessor_sha256
            or not isinstance(attempt_state.get("attempts"), list)
        ):
            raise MvpScoringError("CONTINUATION_PREDECESSOR_STATE_INVALID")
        attempts = attempt_state["attempts"]
        manifest = result_manifest(args.predecessor_root, requests)
        completed_first_passes = sum(
            isinstance(row, dict) and row.get("attempt_number") == 1
            for row in attempts
        )
        carried_result_count = len(manifest)
        retry_candidate_count = completed_first_passes - carried_result_count
        remaining_first_pass_count = 100 - completed_first_passes
        maximum_new_calls = retry_candidate_count + 2 * remaining_first_pass_count
        plan = build_continuation_plan(
            requests,
            predecessor_plan=predecessor,
            predecessor_attempt_state_sha256=_sha256_file(attempt_path),
            predecessor_result_manifest=manifest,
            consumed_completion_calls=len(attempts),
            completed_first_passes=completed_first_passes,
            carried_result_count=carried_result_count,
            retry_candidate_count=retry_candidate_count,
            remaining_first_pass_count=remaining_first_pass_count,
            maximum_new_calls=maximum_new_calls,
        )
        _write_new(args.output, plan)
        print(
            f"run_plan_sha256={plan['run_plan_sha256']} "
            f"consumed_calls={len(attempts)} maximum_new_calls={maximum_new_calls} "
            f"maximum_aggregate_calls={plan['maximum_aggregate_calls']} "
            "traffic_authorization=false"
        )
        return 0

    if args.command == "prepare-continuation":
        continuation_value = _load_json(args.plan)
        if not isinstance(continuation_value, dict):
            raise MvpScoringError("CONTINUATION_PLAN_INVALID")
        requests = _load_requests(args.requests)
        verify_requests_match_run_plan(requests, continuation_value)
        prepare_continuation_state(
            plan=continuation_value,
            predecessor_root=args.predecessor_root,
            output_root=args.output_root,
            requests=requests,
        )
        print(
            f"run_plan_sha256={continuation_value['run_plan_sha256']} "
            f"carried_results={continuation_value['carried_result_count']} "
            f"consumed_calls={continuation_value['consumed_completion_calls']} "
            "traffic_authorization=false"
        )
        return 0

    if args.command == "build-plan":
        requests = _load_requests(args.requests)
        plan = build_run_plan(
            requests,
            catalog_sha256=args.catalog_sha256,
            evidence_inventory_sha256=args.evidence_inventory_sha256,
            prompt_sha256=args.prompt_sha256,
            corpus_file_sha256=_sha256_file(args.requests),
            entitlement_snapshot_sha256=args.entitlement_snapshot_sha256,
            canary_plan_sha256=args.canary_plan_sha256,
            canary_outcome_sha256=args.canary_outcome_sha256,
        )
        _write_new(args.output, plan)
        print(f"run_plan_sha256={plan['run_plan_sha256']} traffic_authorization=false")
        return 0

    plan_path = args.path if args.command in {"verify-plan", "verify-canary-plan"} else args.plan
    value = _load_json(plan_path)
    if not isinstance(value, dict):
        raise MvpScoringError("RUN_PLAN_INVALID")
    plan = value

    if args.command in {"verify-canary-plan", "execute-canary"}:
        actual = verify_canary_plan(plan)
        if args.command == "verify-canary-plan":
            print(f"canary_plan_sha256={actual} traffic_authorization=false")
            return 0
        if args.reviewed_plan_sha256 != actual:
            raise MvpScoringError("REVIEWED_PLAN_HASH_MISMATCH")
        if args.approval != f"approve-glm-mvp-canary:{actual}":
            raise MvpScoringError("CANARY_APPROVAL_MISMATCH")
        if not args.live:
            raise MvpScoringError("SCORING_EXPLICIT_OPT_IN_REQUIRED")
        request = _load_request(args.request)
        selection_sha256 = _validate_canary_selection(
            args.selection,
            request,
            catalog_sha256=str(plan["catalog_sha256"]),
            evidence_inventory_sha256=str(plan["evidence_inventory_sha256"]),
        )
        if (
            request.place.place_id != plan["place_id"]
            or request.request_sha256 != plan["request_sha256"]
            or selection_sha256 != plan["canary_selection_sha256"]
        ):
            raise MvpScoringError("CANARY_REQUEST_BINDING_MISMATCH")
        if (args.output_root / "attempt-state.json").exists():
            raise MvpScoringError("CANARY_PLAN_ALREADY_CONSUMED")
        require_live_network_allowed()
        api_key = os.environ.get("ZHIPUAI_API_KEY")
        if not api_key:
            raise MvpScoringError("GLM_CREDENTIAL_ABSENT")
        transport = GlmCodingScoringTransport(api_key)
        try:
            canary_outcome = execute_diagnostic(
                request,
                transport=transport,
                diagnostic_plan_sha256=actual,
                catalog_sha256=str(plan["catalog_sha256"]),
                evidence_inventory_sha256=str(plan["evidence_inventory_sha256"]),
                prompt_sha256=str(plan["prompt_sha256"]),
                on_attempt=lambda event: persist_attempt_event(args.output_root, event),
                on_result=lambda result: None,
            )
        finally:
            transport.close()
        outcome_payload = {
            "schema_version": "mvp-place-scoring-canary-outcome.v1",
            "canary_plan_sha256": actual,
            "endpoint": GLM_CODING_ENDPOINT,
            "model": GLM_MODEL,
            "successful": canary_outcome.result is not None,
            "failure": canary_outcome.failure,
            "completion_call_count": 1,
        }
        _write_new(args.output_root / "canary-outcome.json", outcome_payload)
        print(
            f"successful={canary_outcome.result is not None} "
            f"failure={canary_outcome.failure or 'NONE'} "
            "calls=1 completion_traffic=true"
        )
        return 0 if canary_outcome.result is not None else 2

    actual = verify_run_plan(plan)
    if args.command == "verify-plan":
        print(f"run_plan_sha256={actual} traffic_authorization=false")
        return 0
    if args.reviewed_plan_sha256 != actual:
        raise MvpScoringError("REVIEWED_PLAN_HASH_MISMATCH")
    if actual in CONSUMED_INTERRUPTED_RUN_PLAN_SHA256S:
        raise MvpScoringError("CONSUMED_INTERRUPTED_RUN_PLAN")
    if args.approval != f"approve-glm-mvp-scoring:{actual}":
        raise MvpScoringError("SCORING_APPROVAL_MISMATCH")
    if not args.live:
        raise MvpScoringError("SCORING_EXPLICIT_OPT_IN_REQUIRED")
    requests = _load_requests(args.requests)
    verify_requests_match_run_plan(requests, plan)
    if _sha256_file(args.requests) != plan["corpus_file_sha256"]:
        raise MvpScoringError("REQUEST_CORPUS_FILE_HASH_MISMATCH")
    _validate_canary_outcome(args.canary_outcome, plan)
    require_live_network_allowed()
    api_key = os.environ.get("ZHIPUAI_API_KEY")
    if not api_key:
        raise MvpScoringError("GLM_CREDENTIAL_ABSENT")
    resumed = load_resumed_results(args.output_root, requests)
    resumed_attempt_counts = load_attempt_counts(
        args.output_root,
        run_plan_sha256=actual,
        requests=requests,
    )
    maximum_new_calls = plan.get("maximum_new_calls", 200)
    if not isinstance(maximum_new_calls, int) or isinstance(maximum_new_calls, bool):
        raise MvpScoringError("MAXIMUM_NEW_CALLS_INVALID")
    consume_execution_authority(args.output_root, actual)
    transport = GlmCodingScoringTransport(api_key)
    try:
        outcome = execute_batch(
            requests,
            transport=transport,
            run_plan_sha256=actual,
            catalog_sha256=str(plan["catalog_sha256"]),
            evidence_inventory_sha256=str(plan["evidence_inventory_sha256"]),
            prompt_sha256=str(plan["prompt_sha256"]),
            resumed_results=resumed,
            resumed_attempt_counts=resumed_attempt_counts,
            on_attempt=lambda event: persist_attempt_event(args.output_root, event),
            on_result=lambda result: persist_scoring_result(args.output_root, result),
            maximum_new_calls=maximum_new_calls,
        )
    finally:
        transport.close()
    print(
        f"results={len(outcome.results)} failed={len(outcome.failed)} "
        f"calls={outcome.call_count} completion_traffic=true"
    )
    return 0 if len(outcome.results) >= 80 else 2


if __name__ == "__main__":
    raise SystemExit(main())
