"""Selection-independent readiness and REINF-12 classification contracts."""

from __future__ import annotations

import inspect
import json
from hashlib import sha256
from pathlib import Path

import pytest

from itda.cli.audit_catalog_readiness import _build_remediation_supersession
from itda.contracts.catalog_enrichment_evidence import EnrichmentEvidenceSidecar
from itda.contracts.catalog_entity_policy import EntityPolicyReport
from itda.contracts.catalog_readiness import (
    AggregateReadiness,
    CandidateRepresentationAssignment,
    CatalogRoundManifest,
    ClassificationEvidenceRef,
    ProviderCandidateEvidence,
    RepresentationQuotaAttestation,
    RepresentationQuotaConfig,
    build_aggregate_readiness,
    build_default_representation_rules,
    build_representation_quota_artifacts,
    build_round_order_manifest,
    classify_representation_candidate,
    evaluate_readiness_candidate,
    rank_remediation_frontier,
)
from itda.contracts.catalog_rights_v2 import (
    CandidateObjectiveRow,
    GateState,
    ObjectiveGate,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

PLACE_ID = f"place:{'1' * 64}"
CANDIDATE_ID = "candidate:tour-api:125405"
DATASET_ID = f"dataset:{'2' * 64}"
RULE_TABLE_SHA256 = "4" * 64
SOURCE_ROW_SHA256 = "5" * 64
REPO_ROOT = Path(__file__).parents[3]
INITIAL_ROUND_ID = "a59fabf3371845fbacb4e32510b178b03d7a784d0becfea6edfd7f7b2e4f2c25"
INITIAL_ROUND_ROOT = (
    REPO_ROOT / "artifacts/restricted/catalog/v2/enrichment/rounds" / INITIAL_ROUND_ID
)


def _remediation_reference(marker: str) -> dict[str, object]:
    alphabet = "0123456789abcdef"
    marker_index = alphabet.index(marker)
    fields: dict[str, object] = {
        "schema_version": "itda.catalog-remediation-round-ref.v1",
        "round_id": marker * 64,
        "round_root": ("artifacts/restricted/catalog/v2/enrichment/rounds/" + marker * 64),
        "remediation_report_sha256": marker * 64,
        "request_plan_sha256": marker * 64,
        "state_attestation_file_sha256": alphabet[marker_index + 1] * 64,
        "authorization_request_file_sha256": alphabet[marker_index + 2] * 64,
        "binding_sha256": alphabet[marker_index + 3] * 64,
        "nonce_sha256": alphabet[marker_index + 4] * 64,
        "previous_round_manifest_sha256": "f" * 64,
        "candidate_count": 16,
        "request_count": 48,
        "quota_estimate": 144,
        "overall_timeout_seconds": 43200,
    }
    fields["reference_sha256"] = canonical_sha256(fields)
    return fields


def test_remediation_supersession_is_append_only_safe_and_deterministic() -> None:
    superseded = _remediation_reference("1")
    replacement = _remediation_reference("6")

    first = _build_remediation_supersession(
        superseded_reference=superseded,
        replacement_reference=replacement,
    )
    second = _build_remediation_supersession(
        superseded_reference=superseded,
        replacement_reference=replacement,
    )

    assert first == second
    assert first["superseded_reference"] == superseded
    assert first["replacement_reference"] == replacement
    assert first["authority_token_issued_or_consumed"] is False
    assert first["provider_call_performed"] is False
    assert first["supersession_sha256"] == canonical_sha256(
        {key: value for key, value in first.items() if key != "supersession_sha256"}
    )
    assert "nonce_sha256" in json.dumps(first, sort_keys=True)
    assert '"nonce":' not in json.dumps(first, sort_keys=True)


def _gate(state: GateState = GateState.PASS) -> ObjectiveGate:
    return ObjectiveGate(
        state=state,
        current_values=("evidence-present",) if state is GateState.PASS else (),
        reason_codes=(f"TEST_{state.value}",),
        evidence_refs=("6" * 64,),
    )


def _objective_row(
    *,
    description: GateState = GateState.PASS,
) -> CandidateObjectiveRow:
    fields = {
        "place_entity_id": PLACE_ID,
        "source_crosswalk_row_id": f"crosswalk:{'7' * 64}",
        "source_crosswalk_row_sha256": SOURCE_ROW_SHA256,
        "source_candidate_ids": (CANDIDATE_ID,),
        "source_dataset_entity_ids": (DATASET_ID,),
        "coordinates": _gate().model_dump(mode="json"),
        "description": _gate(description).model_dump(mode="json"),
        "operating_info": _gate().model_dump(mode="json"),
        "dataset_rights": _gate().model_dump(mode="json"),
        "direct_media": _gate().model_dump(mode="json"),
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
    }
    return CandidateObjectiveRow(**fields, row_sha256=canonical_sha256(fields))


def _assignment(
    status: str = "PRIMARY",
    *,
    primary_group: str | None = "history_culture",
    matched_groups: tuple[str, ...] = ("history_culture",),
) -> CandidateRepresentationAssignment:
    fields = {
        "place_entity_id": PLACE_ID,
        "status": status,
        "primary_group": primary_group,
        "matched_groups": matched_groups,
        "matched_rule_ids": tuple(f"GROUP_{item.upper()}_V1" for item in matched_groups),
        "evidence_field_refs": (
            ClassificationEvidenceRef(
                field_path="entity_projection.dataset_records.name_ko",
                source_candidate_id=CANDIDATE_ID,
                source_dataset_entity_id=DATASET_ID,
                source_row_sha256=SOURCE_ROW_SHA256,
                value_sha256="8" * 64,
            ).model_dump(mode="json"),
        ),
        "objective_evidence_row_sha256": _objective_row().row_sha256,
        "rule_table_sha256": RULE_TABLE_SHA256,
    }
    return CandidateRepresentationAssignment(
        **fields,
        assignment_row_sha256=canonical_sha256(fields),
    )


def test_circular_gate_has_no_selection_input_and_counts_eligible_candidate() -> None:
    assert "ordered_catalog_ids" not in inspect.signature(evaluate_readiness_candidate).parameters
    assert "selection" not in inspect.signature(evaluate_readiness_candidate).parameters

    row = evaluate_readiness_candidate(
        objective_row=_objective_row(),
        assignment=_assignment(),
        assignment_hash_valid=True,
        expected_rule_table_sha256=RULE_TABLE_SHA256,
        t0_provider_candidate_ids=frozenset({CANDIDATE_ID}),
    )

    assert row.objective_eligible is True
    assert row.named_deficits == ()
    assert row.confidence_is_qualification_filter_only is True
    assert row.confidence_adds_score is False


@pytest.mark.parametrize(
    ("assignment", "hash_valid", "expected_deficit"),
    [
        (None, True, "REPRESENTATION_ASSIGNMENT_MISSING"),
        (
            _assignment(
                "UNCLASSIFIED",
                primary_group=None,
                matched_groups=(),
            ),
            True,
            "REPRESENTATION_ASSIGNMENT_UNCLASSIFIED",
        ),
        (
            _assignment(
                "AMBIGUOUS",
                primary_group=None,
                matched_groups=("history_culture", "rest_walk_immersion"),
            ),
            True,
            "REPRESENTATION_ASSIGNMENT_AMBIGUOUS",
        ),
        (_assignment(), False, "REPRESENTATION_ASSIGNMENT_HASH_INVALID"),
    ],
)
def test_representation_failures_are_named_and_fail_closed(
    assignment: CandidateRepresentationAssignment | None,
    hash_valid: bool,
    expected_deficit: str,
) -> None:
    row = evaluate_readiness_candidate(
        objective_row=_objective_row(),
        assignment=assignment,
        assignment_hash_valid=hash_valid,
        expected_rule_table_sha256=RULE_TABLE_SHA256,
        t0_provider_candidate_ids=frozenset({CANDIDATE_ID}),
    )

    assert row.objective_eligible is False
    assert expected_deficit in row.named_deficits


def test_missing_objective_evidence_remains_a_named_deficit() -> None:
    row = evaluate_readiness_candidate(
        objective_row=_objective_row(description=GateState.MISSING),
        assignment=_assignment(),
        assignment_hash_valid=True,
        expected_rule_table_sha256=RULE_TABLE_SHA256,
        t0_provider_candidate_ids=frozenset({CANDIDATE_ID}),
    )

    assert row.objective_eligible is False
    assert "DESCRIPTION_MISSING" in row.named_deficits
    assert row.already_passing_objective_gate_count == 4


def _provider_name(
    name_ko: str,
    *,
    candidate_id: str = CANDIDATE_ID,
    dataset_id: str = DATASET_ID,
) -> ProviderCandidateEvidence:
    return ProviderCandidateEvidence(
        source_candidate_id=candidate_id,
        source_dataset_entity_id=dataset_id,
        source_row_sha256=SOURCE_ROW_SHA256,
        provider="TOUR_API",
        official_dataset_id="15101578",
        name_ko=name_ko,
    )


def test_default_group_rules_are_fixed_order_evidence_only_and_byte_stable() -> None:
    first = build_default_representation_rules(
        seed_manifest_sha256="9" * 64,
        source_attachment_sha256="a" * 64,
    )
    second = build_default_representation_rules(
        seed_manifest_sha256="9" * 64,
        source_attachment_sha256="a" * 64,
    )

    assert first.group_order == (
        "history_culture",
        "history_scenery_boundary",
        "image_modern_content",
        "rest_walk_immersion",
    )
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )
    dumped = first.model_dump(mode="json")
    assert (
        not {
            "quotas",
            "allocation_counts",
            "balance_targets",
            "selection_budget",
        }
        & dumped.keys()
    )


def test_exact_one_zero_and_multiple_group_matches_fail_closed() -> None:
    rules = build_default_representation_rules(
        seed_manifest_sha256="9" * 64,
        source_attachment_sha256="a" * 64,
    )

    exact_one = classify_representation_candidate(
        place_entity_id=PLACE_ID,
        objective_evidence_row_sha256=_objective_row().row_sha256,
        provider_evidence=(_provider_name("불국사"),),
        rules=rules,
    )
    assert exact_one.status == "PRIMARY"
    assert exact_one.primary_group == "history_culture"

    zero = classify_representation_candidate(
        place_entity_id=PLACE_ID,
        objective_evidence_row_sha256=_objective_row().row_sha256,
        provider_evidence=(_provider_name("가마솥 양푼이 밥상"),),
        rules=rules,
    )
    assert zero.status == "UNCLASSIFIED"
    assert zero.primary_group is None

    multiple = classify_representation_candidate(
        place_entity_id=PLACE_ID,
        objective_evidence_row_sha256=_objective_row().row_sha256,
        provider_evidence=(
            _provider_name("불국사"),
            _provider_name(
                "경주 남산",
                candidate_id="candidate:tour-api:128704",
                dataset_id=f"dataset:{'b' * 64}",
            ),
        ),
        rules=rules,
    )
    assert multiple.status == "AMBIGUOUS"
    assert multiple.matched_groups == (
        "history_culture",
        "rest_walk_immersion",
    )


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "model_score",
        "embedding",
        "expert_label",
        "split_membership",
        "evaluation_outcome",
        "human_place_override",
    ],
)
def test_downstream_or_override_injection_is_rejected(forbidden_field: str) -> None:
    payload = _provider_name("불국사").model_dump(mode="json")
    payload[forbidden_field] = "forbidden"
    with pytest.raises(ValueError, match="Extra inputs"):
        ProviderCandidateEvidence.model_validate(payload)


def test_rule_order_and_assignment_hash_tampering_are_rejected() -> None:
    rules = build_default_representation_rules(
        seed_manifest_sha256="9" * 64,
        source_attachment_sha256="a" * 64,
    )
    payload = rules.model_dump(mode="json")
    payload["group_order"] = list(reversed(payload["group_order"]))
    with pytest.raises(ValueError, match="fixed group order"):
        type(rules).model_validate(payload)

    assignment = classify_representation_candidate(
        place_entity_id=PLACE_ID,
        objective_evidence_row_sha256=_objective_row().row_sha256,
        provider_evidence=(_provider_name("불국사"),),
        rules=rules,
    )
    assignment_payload = assignment.model_dump(mode="json")
    assignment_payload["assignment_row_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="assignment row sha256"):
        CandidateRepresentationAssignment.model_validate(assignment_payload)


def _actual_readiness_inputs() -> tuple[
    object,
    EntityPolicyReport,
    EnrichmentEvidenceSidecar,
]:
    readiness = json.loads(
        (
            REPO_ROOT
            / "artifacts/restricted/catalog/v2/enrichment/readiness-before-enrichment.json"
        ).read_bytes()
    )
    policy = EntityPolicyReport.model_validate_json(
        (
            REPO_ROOT / "artifacts/restricted/catalog/v2/projection/entity-policy-report.json"
        ).read_bytes()
    )
    sidecar = EnrichmentEvidenceSidecar.model_validate_json(
        (INITIAL_ROUND_ROOT / "evidence-sidecars.json").read_bytes()
    )
    return readiness, policy, sidecar


def _manifest(
    round_id: str,
    *,
    depth: int,
    previous_sha256: str | None,
    sidecar_file_sha256: str = "a" * 64,
    sidecar_sha256: str = "b" * 64,
) -> CatalogRoundManifest:
    fields = {
        "schema_version": "itda.catalog-enrichment-round-manifest.v1",
        "round_id": round_id,
        "round_root": ("artifacts/restricted/catalog/v2/enrichment/rounds/" + round_id),
        "ancestry_depth": depth,
        "previous_round_manifest_sha256": previous_sha256,
        "immutable_files": (),
        "immutable_files_root": canonical_sha256([]),
        "sidecar_file_sha256": sidecar_file_sha256,
        "sidecar_sha256": sidecar_sha256,
    }
    return CatalogRoundManifest(
        **fields,
        manifest_sha256=canonical_sha256(fields),
    )


def test_ordered_round_manifest_accepts_two_and_three_round_chains_only() -> None:
    first = _manifest("1" * 64, depth=1, previous_sha256=None)
    second = _manifest(
        "2" * 64,
        depth=2,
        previous_sha256=first.manifest_sha256,
    )
    third = _manifest(
        "3" * 64,
        depth=3,
        previous_sha256=second.manifest_sha256,
    )

    two = build_round_order_manifest((first, second))
    three = build_round_order_manifest((first, second, third))

    assert tuple(row.round_id for row in two.entries) == ("1" * 64, "2" * 64)
    assert three.newest_round_id == "3" * 64
    assert three.newest_round_manifest_sha256 == third.manifest_sha256
    with pytest.raises(ValueError, match="ancestry"):
        build_round_order_manifest((first, third))
    with pytest.raises(ValueError, match="ancestry"):
        build_round_order_manifest((second, first))


def test_actual_round_fold_recomputes_full_pool_and_exact_human_decisions() -> None:
    raw_readiness, policy, sidecar = _actual_readiness_inputs()
    base = __import__(
        "itda.contracts.catalog_readiness",
        fromlist=["CatalogReadinessReport"],
    ).CatalogReadinessReport.model_validate(raw_readiness)
    manifest = _manifest(
        INITIAL_ROUND_ID,
        depth=1,
        previous_sha256=None,
        sidecar_file_sha256=sha256(
            (INITIAL_ROUND_ROOT / "evidence-sidecars.json").read_bytes()
        ).hexdigest(),
        sidecar_sha256=sidecar.sidecar_sha256,
    )
    ordered = build_round_order_manifest((manifest,))

    aggregate = build_aggregate_readiness(
        base_readiness=base,
        entity_policy=policy,
        ordered_manifest=ordered,
        sidecars=(sidecar,),
        require_objective_eligible=36,
        max_human_decisions=6,
    )

    assert aggregate.potential_candidate_count == 718
    assert aggregate.objective_eligible_count == 0
    assert aggregate.human_identity_relationship_decisions == 6
    assert aggregate.named_deficit_counts["DESCRIPTION_MISSING"] == 718
    assert aggregate.named_deficit_counts["OPERATING_INFO_MISSING"] == 667
    assert aggregate.outcome_code == 20
    assert aggregate.outcome_reason == "REMEDIATION_ROUND_ISSUED"


def test_actual_frontier_excludes_all_attempted_and_uses_exact_mapping() -> None:
    raw_readiness, policy, sidecar = _actual_readiness_inputs()
    base = __import__(
        "itda.contracts.catalog_readiness",
        fromlist=["CatalogReadinessReport"],
    ).CatalogReadinessReport.model_validate(raw_readiness)
    manifest = _manifest(
        INITIAL_ROUND_ID,
        depth=1,
        previous_sha256=None,
        sidecar_file_sha256=sha256(
            (INITIAL_ROUND_ROOT / "evidence-sidecars.json").read_bytes()
        ).hexdigest(),
        sidecar_sha256=sidecar.sidecar_sha256,
    )
    aggregate = build_aggregate_readiness(
        base_readiness=base,
        entity_policy=policy,
        ordered_manifest=build_round_order_manifest((manifest,)),
        sidecars=(sidecar,),
        require_objective_eligible=36,
        max_human_decisions=6,
    )

    frontier = rank_remediation_frontier(aggregate, maximum_candidates=60)

    assert len(frontier) == 16
    assert {row.primary_group for row in frontier} == {
        "image_modern_content",
        "rest_walk_immersion",
    }
    assert all(row.mandatory_deficit_count == 3 for row in frontier)
    assert all(
        row.missing_operations == ("detailCommon2", "detailIntro2", "detailImage2")
        for row in frontier
    )
    attempted = {row.provider_candidate_id for row in frontier}
    assert not attempted.intersection(
        response.provider_candidate_id for response in sidecar.responses
    )
    assert tuple(row.source_neutral_id for row in frontier) == tuple(
        sorted(row.source_neutral_id for row in frontier)
    )


def test_aggregate_outcome_exact_frontier_and_overflow_stops() -> None:
    raw_readiness, policy, sidecar = _actual_readiness_inputs()
    base = __import__(
        "itda.contracts.catalog_readiness",
        fromlist=["CatalogReadinessReport"],
    ).CatalogReadinessReport.model_validate(raw_readiness)
    manifest = _manifest(
        INITIAL_ROUND_ID,
        depth=1,
        previous_sha256=None,
        sidecar_file_sha256=sha256(
            (INITIAL_ROUND_ROOT / "evidence-sidecars.json").read_bytes()
        ).hexdigest(),
        sidecar_sha256=sidecar.sidecar_sha256,
    )
    ordered = build_round_order_manifest((manifest,))

    exhausted = build_aggregate_readiness(
        base_readiness=base,
        entity_policy=policy,
        ordered_manifest=ordered,
        sidecars=(sidecar,),
        require_objective_eligible=36,
        max_human_decisions=6,
        attempted_provider_ids=frozenset(
            row.provider_place_candidate_id
            for row in base.rows
            if row.provider_place_candidate_id is not None
        ),
    )
    overflow = build_aggregate_readiness(
        base_readiness=base,
        entity_policy=policy,
        ordered_manifest=ordered,
        sidecars=(sidecar,),
        require_objective_eligible=36,
        max_human_decisions=5,
    )

    assert (exhausted.outcome_code, exhausted.outcome_reason) == (
        21,
        "EVIDENCE_FRONTIER_EXHAUSTED",
    )
    assert (overflow.outcome_code, overflow.outcome_reason) == (
        22,
        "NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW",
    )
    assert AggregateReadiness.model_validate(exhausted.model_dump(mode="json")) == exhausted


def _quota_artifacts(
    counts: dict[str, int],
    *,
    missing_assignments: int = 0,
    ambiguous_assignments: int = 0,
) -> tuple[RepresentationQuotaConfig, RepresentationQuotaAttestation]:
    return build_representation_quota_artifacts(
        eligible_pool_sha256="c" * 64,
        representation_rule_sha256=RULE_TABLE_SHA256,
        raw_eligible_group_counts=counts,
        missing_assignment_count=missing_assignments,
        ambiguous_assignment_count=ambiguous_assignments,
    )


def test_representation_quota_proportional_allocation_and_clamps() -> None:
    config, attestation = _quota_artifacts(
        {
            "history_culture": 18,
            "history_scenery_boundary": 28,
            "image_modern_content": 11,
            "rest_walk_immersion": 19,
        }
    )

    assert config.fixed_group_order == (
        "history_culture",
        "history_scenery_boundary",
        "image_modern_content",
        "rest_walk_immersion",
    )
    assert (config.seat_count, config.lower_bound, config.upper_bound) == (36, 6, 12)
    assert attestation.final_quotas == {
        "history_culture": 9,
        "history_scenery_boundary": 12,
        "image_modern_content": 6,
        "rest_walk_immersion": 9,
    }
    assert attestation.quota_sum == 36
    assert attestation.feasible is True
    assert attestation.outcome_code == 0
    assert attestation.failure_reason is None


def test_representation_quota_add_and_remove_ties_use_fixed_group_order() -> None:
    _, add_tie = _quota_artifacts(
        {
            "history_culture": 6,
            "history_scenery_boundary": 7,
            "image_modern_content": 15,
            "rest_walk_immersion": 20,
        }
    )
    _, remove_tie = _quota_artifacts(
        {
            "history_culture": 6,
            "history_scenery_boundary": 30,
            "image_modern_content": 30,
            "rest_walk_immersion": 34,
        }
    )

    assert add_tie.final_quotas == {
        "history_culture": 6,
        "history_scenery_boundary": 7,
        "image_modern_content": 11,
        "rest_walk_immersion": 12,
    }
    assert remove_tie.final_quotas == {
        "history_culture": 6,
        "history_scenery_boundary": 9,
        "image_modern_content": 10,
        "rest_walk_immersion": 11,
    }


@pytest.mark.parametrize(
    ("counts", "missing", "ambiguous"),
    [
        (
            {
                "history_culture": 5,
                "history_scenery_boundary": 20,
                "image_modern_content": 20,
                "rest_walk_immersion": 20,
            },
            0,
            0,
        ),
        (
            {
                "history_culture": 9,
                "history_scenery_boundary": 9,
                "image_modern_content": 9,
                "rest_walk_immersion": 9,
            },
            1,
            0,
        ),
        (
            {
                "history_culture": 9,
                "history_scenery_boundary": 9,
                "image_modern_content": 9,
                "rest_walk_immersion": 9,
            },
            0,
            1,
        ),
    ],
)
def test_representation_infeasible_is_exact_and_fail_closed(
    counts: dict[str, int],
    missing: int,
    ambiguous: int,
) -> None:
    _, attestation = _quota_artifacts(
        counts,
        missing_assignments=missing,
        ambiguous_assignments=ambiguous,
    )

    assert attestation.feasible is False
    assert attestation.outcome_code == 23
    assert attestation.failure_reason == "REPRESENTATION_INFEASIBLE"
    assert attestation.final_quotas == {}
    assert attestation.quota_sum == 0


def test_representation_quota_artifacts_are_byte_stable_and_tamper_evident() -> None:
    counts = {
        "history_culture": 10,
        "history_scenery_boundary": 10,
        "image_modern_content": 10,
        "rest_walk_immersion": 11,
    }
    first = _quota_artifacts(counts)
    second = _quota_artifacts(counts)

    assert canonical_json_bytes(first[0].model_dump(mode="json")) == canonical_json_bytes(
        second[0].model_dump(mode="json")
    )
    assert canonical_json_bytes(first[1].model_dump(mode="json")) == canonical_json_bytes(
        second[1].model_dump(mode="json")
    )

    config_payload = first[0].model_dump(mode="json")
    config_payload["upper_bound"] = 11
    with pytest.raises(ValueError, match="12|config"):
        RepresentationQuotaConfig.model_validate(config_payload)

    attestation_payload = first[1].model_dump(mode="json")
    attestation_payload["final_quotas"]["history_culture"] = 8
    with pytest.raises(ValueError, match="attestation|quota"):
        RepresentationQuotaAttestation.model_validate(attestation_payload)
