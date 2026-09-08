"""Plan 02-25 deterministic REINF-13 split owner contract."""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.cli.build_real_split import (
    build_balance_outcome,
    build_human_axis_authority,
    build_safe_input_candidate_review,
    optimize_component_assignment,
    verify_balance_outcome,
    verify_human_axis_authority,
    verify_safe_input_candidate_review,
)
from itda.contracts.catalog_manifest import (
    AuditedProviderFieldPresence,
    RealSplitBalanceRow,
    RealSplitComponent,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256


def _place(index: int) -> str:
    return f"place:{index:064x}"


def _row(
    index: int,
    *,
    history: bool,
    emotion: bool,
    rest: bool,
    completeness: int,
) -> RealSplitBalanceRow:
    fields = {
        "official_description": completeness >= 1,
        "odii_script": completeness >= 2,
        "official_metadata": completeness >= 3,
        "qualified_image": completeness >= 4,
        "operating_information": completeness >= 5,
    }
    return RealSplitBalanceRow(
        source_neutral_place_id=_place(index),
        history_tradition=history,
        emotion_image=emotion,
        rest_immersion=rest,
        audited_provider_fields=AuditedProviderFieldPresence(**fields),
    )


def _singleton_components(rows: tuple[RealSplitBalanceRow, ...]) -> tuple[RealSplitComponent, ...]:
    return tuple(
        RealSplitComponent(
            component_id=f"component:{row.source_neutral_place_id[6:]}",
            members=(row.source_neutral_place_id,),
        )
        for row in rows
    )


def _small_rows() -> tuple[RealSplitBalanceRow, ...]:
    return tuple(
        _row(
            index,
            history=index % 2 == 0,
            emotion=index % 3 == 0,
            rest=index % 4 in {0, 1},
            completeness=index % 6,
        )
        for index in range(1, 9)
    )


def _full_rows() -> tuple[RealSplitBalanceRow, ...]:
    return tuple(
        _row(
            index,
            history=index <= 18,
            emotion=index % 3 == 0,
            rest=index % 4 == 0,
            completeness=index % 6,
        )
        for index in range(1, 37)
    )


def test_exact_optimizer_matches_exhaustive_small_universe_oracle() -> None:
    rows = _small_rows()
    components = _singleton_components(rows)
    result = optimize_component_assignment(rows, components, blind_size=3, seed=42)

    oracle = []
    for blind in itertools.combinations((row.source_neutral_place_id for row in rows), 3):
        oracle.append(result.score_membership(blind))
    assert result.objective_tuple == min(oracle)
    assert result.candidate_count == len(oracle)
    assert result.priority_rule_version == "seeded-component-additive-priority-v1"
    assert sum(result.component_priorities.values()).bit_count() == len(components)


def test_seeded_component_priority_is_additive_unique_and_catalog_order_free() -> None:
    rows = _small_rows()
    components = _singleton_components(rows)
    first = optimize_component_assignment(rows, components, blind_size=3, seed=42)
    second = optimize_component_assignment(
        tuple(reversed(rows)), tuple(reversed(components)), blind_size=3, seed=42
    )

    assert first.objective_tuple == second.objective_tuple
    assert first.blind_members == second.blind_members
    assert first.component_priorities == second.component_priorities
    assert sorted(first.component_priorities.values()) == [1 << index for index in range(8)]
    assert first.objective_order[-1] == "seed_42_component_priority_sum"


def test_balance_outcome_is_byte_identical_and_uses_exact_rational_targets() -> None:
    rows = _full_rows()
    components = _singleton_components(rows)
    first = build_balance_outcome(rows, components, blind_size=12, seed=42)
    second = build_balance_outcome(
        tuple(reversed(rows)), tuple(reversed(components)), blind_size=12, seed=42
    )

    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )
    assert first.status == "FEASIBLE"
    assert first.proof is not None
    assert first.proof.exact_targets["history_tradition"] == "18/3"
    assert all(value <= 3 for value in first.proof.deviation_numerators.values())
    verify_balance_outcome(first, require_feasible=True)


def test_safe_balance_rows_reject_later_stage_and_split_fields() -> None:
    payload = _row(1, history=True, emotion=False, rest=False, completeness=3).model_dump(
        mode="json"
    )
    for forbidden in (
        "human_label",
        "model_output",
        "embedding",
        "prompt",
        "recommendation_score",
        "user_feedback",
        "blind_membership",
        "catalog_position",
        "mutable_name",
    ):
        hostile = dict(payload)
        hostile[forbidden] = "forbidden"
        with pytest.raises(ValueError):
            RealSplitBalanceRow.model_validate(hostile)


def test_no_exact_twelve_reachability_emits_infeasible_without_candidate() -> None:
    rows = tuple(
        _row(index, history=True, emotion=False, rest=False, completeness=5)
        for index in range(1, 37)
    )
    components = (
        RealSplitComponent(
            component_id="component:a",
            members=tuple(row.source_neutral_place_id for row in rows[:20]),
        ),
        RealSplitComponent(
            component_id="component:b",
            members=tuple(row.source_neutral_place_id for row in rows[20:]),
        ),
    )
    outcome = build_balance_outcome(rows, components, blind_size=12, seed=42)

    assert outcome.status == "BALANCE_INFEASIBLE"
    assert outcome.candidate is None
    assert outcome.proof is not None
    assert outcome.proof.reachability.exact_size_reachable is False
    verify_balance_outcome(outcome)


def test_proof_tampering_objective_order_tolerance_or_hash_is_rejected() -> None:
    rows = _full_rows()
    outcome = build_balance_outcome(rows, _singleton_components(rows), blind_size=12, seed=42)
    payload = outcome.model_dump(mode="json")
    assert payload["proof"] is not None

    for mutation in (
        lambda proof: proof.__setitem__("tolerance", 2),
        lambda proof: proof.__setitem__(
            "objective_order", list(reversed(proof["objective_order"]))
        ),
        lambda proof: proof.__setitem__("proof_certificate_sha256", "0" * 64),
    ):
        hostile = json.loads(json.dumps(payload))
        mutation(hostile["proof"])
        with pytest.raises(ValueError):
            verify_balance_outcome(hostile)


def test_balance_outcome_canonical_file_round_trip(tmp_path: Path) -> None:
    rows = _full_rows()
    outcome = build_balance_outcome(rows, _singleton_components(rows), blind_size=12, seed=42)
    path = tmp_path / "outcome.json"
    path.write_bytes(canonical_json_bytes(outcome.model_dump(mode="json")))
    assert verify_balance_outcome(path).outcome_sha256 == outcome.outcome_sha256


def test_safe_input_candidate_review_is_separate_pending_and_split_free() -> None:
    place_ids = tuple(_place(index) for index in range(1, 37))
    evidence_rows = tuple(
        {
            "source_neutral_place_id": place_id,
            "audited_provider_fields": {
                "official_description": True,
                "odii_script": False,
                "official_metadata": True,
                "qualified_image": index % 2 == 0,
                "operating_information": True,
            },
            "evidence_refs": [f"evidence:{index:02d}"],
            "evidence_digest": f"{index:064x}",
            "missing_evidence": ["ODII_SCRIPT"],
        }
        for index, place_id in enumerate(place_ids, start=1)
    )
    package = build_safe_input_candidate_review(
        place_ids=place_ids,
        evidence_rows=evidence_rows,
        active_bindings={
            "catalog_revision_sha256": "1" * 64,
            "catalog_activation_event_sha256": "2" * 64,
            "catalog_approval_sha256": "3" * 64,
            "authoritative_relationship_leaves_sha256": "4" * 64,
            "active_ordered_place_ids_sha256": "5" * 64,
        },
    )

    assert package.status == "HUMAN_REVIEW_REQUIRED"
    assert package.authoritative is False
    assert len(package.rows) == 36
    assert all(row.history_tradition is None for row in package.rows)
    assert all(row.emotion_image is None for row in package.rows)
    assert all(row.rest_immersion is None for row in package.rows)
    serialized = json.dumps(package.model_dump(mode="json"), sort_keys=True).casefold()
    assert "blind" not in serialized
    assert "dev" not in serialized
    assert "model" not in serialized
    assert "representation_primary_group" not in serialized
    verify_safe_input_candidate_review(package)


def test_safe_input_candidate_review_rejects_missing_or_foreign_active_rows() -> None:
    place_ids = tuple(_place(index) for index in range(1, 37))
    rows = [
        {
            "source_neutral_place_id": place_id,
            "audited_provider_fields": {
                "official_description": True,
                "odii_script": False,
                "official_metadata": True,
                "qualified_image": False,
                "operating_information": True,
            },
            "evidence_refs": [],
            "evidence_digest": f"{index:064x}",
            "missing_evidence": ["ODII_SCRIPT", "QUALIFIED_IMAGE"],
        }
        for index, place_id in enumerate(place_ids, start=1)
    ]
    bindings = {
        "catalog_revision_sha256": "1" * 64,
        "catalog_activation_event_sha256": "2" * 64,
        "catalog_approval_sha256": "3" * 64,
        "authoritative_relationship_leaves_sha256": "4" * 64,
        "active_ordered_place_ids_sha256": "5" * 64,
    }
    with pytest.raises(ValueError, match="exact active 36"):
        build_safe_input_candidate_review(
            place_ids=place_ids,
            evidence_rows=rows[:-1],
            active_bindings=bindings,
        )
    rows[-1]["source_neutral_place_id"] = _place(99)
    with pytest.raises(ValueError, match="exact active 36"):
        build_safe_input_candidate_review(
            place_ids=place_ids,
            evidence_rows=rows,
            active_bindings=bindings,
        )


def test_exact_human_choice_resolves_only_bound_unresolved_rows_and_preserves_evidence() -> None:
    place_ids = tuple(_place(index) for index in range(1, 37))
    evidence_rows = tuple(
        {
            "source_neutral_place_id": place_id,
            "audited_provider_fields": {
                "official_description": True,
                "odii_script": False,
                "official_metadata": True,
                "qualified_image": False,
                "operating_information": True,
            },
            "evidence_refs": [f"official-description:{index:02d}"],
            "evidence_digest": f"{index:064x}",
            "missing_evidence": ["ODII_SCRIPT", "QUALIFIED_IMAGE"],
        }
        for index, place_id in enumerate(place_ids, start=1)
    )
    review = build_safe_input_candidate_review(
        place_ids=place_ids,
        evidence_rows=evidence_rows,
        active_bindings={
            "catalog_revision_sha256": "1" * 64,
            "catalog_activation_event_sha256": "2" * 64,
            "catalog_approval_sha256": "3" * 64,
            "authoritative_relationship_leaves_sha256": "4" * 64,
            "active_ordered_place_ids_sha256": "5" * 64,
        },
    )
    draft = {
        "schema_version": "itda.real-split-candidate-axis-judgment-draft.v1",
        "status": "HUMAN_REVIEW_REQUIRED",
        "authoritative": False,
        "split_publication_blocked": True,
        "source_review_package_sha256": review.review_package_sha256,
        "active_ordered_place_ids_sha256": review.active_ordered_place_ids_sha256,
        "axis_rule_candidate_sha256": review.axis_rule_candidate_sha256,
        "review_method": {"completed_row_level_description_review": True},
        "rows": [
            {
                "ordinal": index,
                "id": place_id,
                "name": f"place-{index}",
                "provider": f"provider-{index}",
                "description_sha256": f"{index + 100:064x}",
                "qualified_image_metadata": False,
                "H": {
                    "value": "UNRESOLVED" if index <= 17 else "TRUE",
                    "reason": "original history reason",
                },
                "E": {"value": "TRUE", "reason": "original emotion reason"},
                "R": {"value": "FALSE", "reason": "original rest reason"},
            }
            for index, place_id in enumerate(place_ids, start=1)
        ],
    }
    draft_sha = canonical_sha256(draft)

    rule, approval, safe_root = build_human_axis_authority(
        source_review=review,
        draft=draft,
        expected_draft_semantic_sha256=draft_sha,
        reviewer_id="phase2-operator",
        approved_at=datetime(2026, 8, 1, 16, tzinfo=UTC),
    )

    assert approval.unresolved_before == 17
    assert approval.unresolved_after == 0
    assert safe_root.unresolved_count == 0
    assert sum(row.history_tradition for row in safe_root.rows) == 19
    assert approval.rows[0].source_evidence_digest == evidence_rows[0]["evidence_digest"]
    assert "not an automatic mapping" in rule.non_inference_guard
    verify_human_axis_authority(rule=rule, approval=approval, safe_input=safe_root)

    hostile = json.loads(json.dumps(draft))
    hostile["rows"][0]["H"]["reason"] = "drifted"
    with pytest.raises(ValueError, match="semantic hash drifted"):
        build_human_axis_authority(
            source_review=review,
            draft=hostile,
            expected_draft_semantic_sha256=draft_sha,
            reviewer_id="phase2-operator",
            approved_at=datetime(2026, 8, 1, 16, tzinfo=UTC),
        )
