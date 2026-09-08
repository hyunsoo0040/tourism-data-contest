from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.build_catalog_v2_review import verify_plan54_success
from itda.cli.catalog_optional_media_closure import (
    build_current_closure_plan,
    derive_closure_plan,
    finalize_closure_evidence,
    publish_current_closure_plan,
)
from itda.contracts.catalog_optional_media_closure import (
    CapturedEvidenceRoute,
    ClosureEvidence,
    ClosureEvidenceCoverage,
    ClosureExecutionMode,
    ClosureNormalizedEvidenceRow,
    ClosurePlan,
    FreshCollectionBounds,
    FreshCollectionRoute,
)
from itda.domain.canonical import canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPECTED_FRONTIER_ROOT = "2ed73e220e34c9b060a68ab40c9af3d2649537ef6baee556533aebf1afbe8414"


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _coverage(plan: ClosurePlan) -> tuple[ClosureEvidenceCoverage, ...]:
    return tuple(
        ClosureEvidenceCoverage(
            place_entity_id=row.place_entity_id,
            provider_candidate_id=row.provider_candidate_id,
            evidence_types=row.non_image_deficits,
        )
        for row in plan.target_rows
    )


def test_current_frontier_is_a_named_non_addressable_terminal(tmp_path: Path) -> None:
    plan = build_current_closure_plan(REPO_ROOT)

    assert plan.frontier_sha256 == EXPECTED_FRONTIER_ROOT
    assert plan.execution_mode is ClosureExecutionMode.TERMINAL
    assert plan.terminal is not None
    assert plan.terminal.code == "NON_ADDRESSABLE_REPRESENTATION_FRONTIER"
    assert plan.terminal.exit_code == 24
    assert plan.terminal.plan54_reachable is False
    assert plan.authority_required is False
    assert plan.credential_required is False
    assert plan.provider_traffic_allowed is False
    assert plan.authority_request is None
    assert plan.fresh_collection is None
    assert plan.captured_replay is None
    assert plan.attempt_inventory == ()
    assert len(plan.target_rows) == 5
    assert (
        sum(row.representation_primary_group == "image_modern_content" for row in plan.target_rows)
        >= 3
    )

    output = publish_current_closure_plan(
        REPO_ROOT,
        output_root=tmp_path / "closure-plan",
    )
    assert output == tmp_path / "closure-plan" / "closure-terminal.json"
    assert {path.name for path in output.parent.iterdir()} == {"closure-terminal.json"}
    payload = json.loads(output.read_bytes())
    assert payload["code"] == "NON_ADDRESSABLE_REPRESENTATION_FRONTIER"
    assert payload["plan54_reachable"] is False
    assert payload["authority_request_created"] is False


def test_captured_replay_is_local_and_has_no_attempt_inventory() -> None:
    terminal = build_current_closure_plan(REPO_ROOT)
    coverage = _coverage(terminal)
    captured = CapturedEvidenceRoute(
        source_id="captured:official-local-evidence:v1",
        source_root_sha256=_digest("captured-source"),
        evidence_root_sha256=_digest("captured-evidence"),
        rights_manifest_sha256=_digest("captured-rights"),
        identity_manifest_sha256=_digest("captured-identity"),
        lineage_manifest_sha256=_digest("captured-lineage"),
        manifest_relative_path="captured/manifest.json",
        evidence_relative_paths=("captured/evidence.json",),
        coverage=coverage,
        admissible=True,
    )

    plan = derive_closure_plan(
        frontier=terminal.frontier,
        provider_ids_by_place=terminal.provider_ids_by_place,
        attempted_provider_ids=frozenset(terminal.attempted_provider_ids),
        captured_routes=(captured,),
        fresh_routes=(),
    )

    assert plan.execution_mode is ClosureExecutionMode.CAPTURED_REPLAY
    assert plan.captured_replay == captured
    assert plan.fresh_collection is None
    assert plan.authority_required is False
    assert plan.credential_required is False
    assert plan.provider_traffic_allowed is False
    assert plan.authority_request is None
    assert plan.attempt_inventory == ()
    assert plan.plan54_reachable is True


def test_same_request_identity_is_exhausted_but_material_change_is_addressable() -> None:
    terminal = build_current_closure_plan(REPO_ROOT)
    coverage = _coverage(terminal)
    target_ids = tuple(row.provider_candidate_id for row in terminal.target_rows)
    attempted = frozenset(terminal.attempted_provider_ids)
    assert set(target_ids) <= attempted

    route_fields = {
        "source_id": "official:tour-api:15101578",
        "provider": "TOUR_API",
        "official_dataset_id": "15101578",
        "source_manifest_sha256": _digest("tour-api-source"),
        "source_approval_sha256": _digest("tour-api-approval"),
        "deterministic_id_join_sha256": _digest("tour-api-join"),
        "host": "apis.data.go.kr",
        "path": "/B551011/KorService2/detailIntro2",
        "operation": "detailIntro2",
        "secret_free_parameters": {
            "MobileOS": "ETC",
            "MobileApp": "IT-DA",
            "_type": "json",
        },
        "expected_evidence_types": ("operating_information",),
        "coverage": coverage,
        "bounds": FreshCollectionBounds(),
        "credential_reference": ".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
        "alternate_approved_source": False,
    }
    initial = FreshCollectionRoute(
        **route_fields,
        predecessor_request_identity_sha256=None,
        predecessor_secret_free_parameters=None,
        changed_fields=(),
    )
    unchanged = FreshCollectionRoute(
        **route_fields,
        request_identity_sha256=initial.request_identity_sha256,
        predecessor_request_identity_sha256=initial.request_identity_sha256,
        predecessor_secret_free_parameters=initial.secret_free_parameters,
        changed_fields=(),
    )
    rejected = derive_closure_plan(
        frontier=terminal.frontier,
        provider_ids_by_place=terminal.provider_ids_by_place,
        attempted_provider_ids=attempted,
        captured_routes=(),
        fresh_routes=(unchanged,),
    )
    assert rejected.execution_mode is ClosureExecutionMode.TERMINAL
    assert rejected.terminal is not None
    assert "SAME_REQUEST_IDENTITY_EXHAUSTED" in rejected.terminal.reason_codes

    predecessor_parameters = {
        **initial.secret_free_parameters,
        "contentTypeId": "12",
    }
    changed = FreshCollectionRoute(
        **route_fields,
        predecessor_request_identity_sha256=None,
        predecessor_secret_free_parameters=predecessor_parameters,
        changed_fields=("contentTypeId",),
    )
    accepted = derive_closure_plan(
        frontier=terminal.frontier,
        provider_ids_by_place=terminal.provider_ids_by_place,
        attempted_provider_ids=attempted,
        captured_routes=(),
        fresh_routes=(changed,),
    )
    assert accepted.execution_mode is ClosureExecutionMode.FRESH_COLLECTION
    assert accepted.fresh_collection is not None
    assert accepted.authority_required is True
    assert accepted.credential_required is True
    assert accepted.provider_traffic_allowed is False
    assert accepted.authority_request is not None
    assert accepted.authority_request.operation == "catalog-optional-media-close"
    assert accepted.plan54_reachable is True


def test_mixed_mode_fields_fail_closed() -> None:
    terminal = build_current_closure_plan(REPO_ROOT)
    captured = CapturedEvidenceRoute(
        source_id="captured:official-local-evidence:v1",
        source_root_sha256=_digest("captured-source"),
        evidence_root_sha256=_digest("captured-evidence"),
        rights_manifest_sha256=_digest("captured-rights"),
        identity_manifest_sha256=_digest("captured-identity"),
        lineage_manifest_sha256=_digest("captured-lineage"),
        manifest_relative_path="captured/manifest.json",
        evidence_relative_paths=("captured/evidence.json",),
        coverage=_coverage(terminal),
        admissible=True,
    )
    payload = terminal.model_dump(mode="json")
    payload.update(
        {
            "execution_mode": "captured_replay",
            "captured_replay": captured.model_dump(mode="json"),
            "plan54_reachable": True,
        }
    )
    with pytest.raises(ValidationError, match="captured_replay"):
        ClosurePlan.model_validate(payload)


def _captured_plan() -> ClosurePlan:
    terminal = build_current_closure_plan(REPO_ROOT)
    captured = CapturedEvidenceRoute(
        source_id="captured:closure-fixture:v1",
        source_root_sha256=_digest("fixture-source"),
        evidence_root_sha256=_digest("fixture-evidence"),
        rights_manifest_sha256=_digest("fixture-rights"),
        identity_manifest_sha256=_digest("fixture-identity"),
        lineage_manifest_sha256=_digest("fixture-lineage"),
        manifest_relative_path="captured/manifest.json",
        evidence_relative_paths=("captured/evidence.json",),
        coverage=_coverage(terminal),
        admissible=True,
    )
    return derive_closure_plan(
        frontier=terminal.frontier,
        provider_ids_by_place=terminal.provider_ids_by_place,
        attempted_provider_ids=frozenset(terminal.attempted_provider_ids),
        captured_routes=(captured,),
        fresh_routes=(),
    )


def _normalized_evidence(plan: ClosurePlan, *, omit_last: bool = False) -> ClosureEvidence:
    assert plan.captured_replay is not None
    targets = plan.target_rows[:-1] if omit_last else plan.target_rows
    rows = []
    for target in targets:
        facts = {field: f"{target.place_entity_id}:{field}" for field in target.non_image_deficits}
        fields = {
            "place_entity_id": target.place_entity_id,
            "provider_candidate_id": target.provider_candidate_id,
            "target_row_sha256": target.target_row_sha256,
            "normalized_facts": facts,
            "source_manifest_sha256": plan.captured_replay.source_root_sha256,
            "evidence_sha256": _digest(target.place_entity_id + ":evidence"),
            "rights_manifest_sha256": plan.captured_replay.rights_manifest_sha256,
            "identity_manifest_sha256": plan.captured_replay.identity_manifest_sha256,
            "lineage_manifest_sha256": plan.captured_replay.lineage_manifest_sha256,
            "response_sha256": _digest(target.place_entity_id + ":response"),
            "rejected_raw_sha256": None,
        }
        rows.append(
            ClosureNormalizedEvidenceRow(
                **fields,
                row_sha256=canonical_sha256(fields),
            )
        )
    rows_root = canonical_sha256([row.model_dump(mode="json") for row in rows])
    fields = {
        "schema_version": "itda.catalog-optional-media-closure-evidence.v1",
        "execution_mode": "captured_replay",
        "closure_plan_sha256": plan.plan_sha256,
        "frontier_sha256": plan.frontier_sha256,
        "universe_root_sha256": plan.universe_root_sha256,
        "target_root_sha256": plan.target_root_sha256,
        "normalized_rows": tuple(rows),
        "normalized_rows_root_sha256": rows_root,
        "captured_evidence_root_sha256": plan.captured_replay.evidence_root_sha256,
        "fresh_request_identity_sha256": None,
        "authority_receipt_sha256": None,
        "credential_reference_sha256": None,
        "attempts": (),
        "provider_traffic_performed": False,
    }
    return ClosureEvidence(
        **fields,
        evidence_sha256=canonical_sha256(
            {
                **fields,
                "normalized_rows": [row.model_dump(mode="json") for row in rows],
            }
        ),
    )


def test_complete_closure_evidence_double_replay_is_feasible(tmp_path: Path) -> None:
    plan = _captured_plan()
    result = finalize_closure_evidence(
        REPO_ROOT,
        plan=plan,
        evidence=_normalized_evidence(plan),
        review_output_root=tmp_path / "review",
    )

    assert result["status"] == "FEASIBLE"
    assert result["replays_byte_identical"] is True
    assert result["eligible_count"] >= 36
    assert all(count >= 6 for count in result["group_counts"].values())
    assert result["capped_capacity"] >= 36
    assert sum(result["final_quotas"].values()) == 36
    assert result["unresolved_human_decision_count"] <= 6
    assert result["plan20_reachable"] is True
    with pytest.raises(ValueError, match="contest schema"):
        verify_plan54_success(result, repository_root=REPO_ROOT)
    assert {path.name for path in (tmp_path / "review").iterdir()} == {
        "catalog-review-request.json",
        "catalog-review-view.json",
        "catalog-state-attestation.json",
    }


def test_incomplete_closure_evidence_emits_no_review_bundle(tmp_path: Path) -> None:
    plan = _captured_plan()
    review_root = tmp_path / "review"
    result = finalize_closure_evidence(
        REPO_ROOT,
        plan=plan,
        evidence=_normalized_evidence(plan, omit_last=True),
        review_output_root=review_root,
    )

    assert result["status"] == "CLOSURE_EVIDENCE_INSUFFICIENT"
    assert result["plan20_reachable"] is False
    assert not review_root.exists()
