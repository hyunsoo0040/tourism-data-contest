from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from itda.cli.audit_catalog_optional_media_frontier import (
    FRONTIER_ARTIFACT_FILENAMES,
    build_optional_media_frontier_audit,
    publish_optional_media_frontier_audit,
)
from itda.cli.replay_catalog_optional_media import build_optional_media_projection
from itda.contracts.catalog_optional_media import (
    GateState,
    ImageMediumState,
    OptionalMediaCandidate,
    build_optional_media_policy,
    project_optional_media_candidate,
)
from itda.contracts.catalog_optional_media_frontier import (
    evaluate_optional_media_frontier,
)
from itda.contracts.catalog_readiness import GROUP_ORDER
from itda.domain.canonical import canonical_json_bytes

REPO_ROOT = Path(__file__).resolve().parents[3]
EXPECTED_PROJECTION_ROOT = "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _eligible_candidate(
    *,
    ordinal: int,
    group: str,
    operating_information: str = "PASS",
    image_state: ImageMediumState = ImageMediumState.MISSING,
) -> OptionalMediaCandidate:
    policy = build_optional_media_policy()
    source_row = {
        "place_entity_id": f"place:{_digest(f'place-{ordinal}')}",
        "provider_place_candidate_id": f"candidate:tour-api:{ordinal}",
        "row_sha256": _digest(f"source-{ordinal}"),
        "objective_gate_states": {
            "coordinates": "PASS",
            "description": "PASS",
            "operating_info": operating_information,
            "dataset_rights": "PASS",
        },
        "representation_assignment_status": "PRIMARY",
        "representation_primary_group": group,
    }
    qualified = image_state is ImageMediumState.QUALIFIED
    historical_row = {
        "place_entity_id": source_row["place_entity_id"],
        "identity_state": "PASS",
        "coordinates_state": "PASS",
        "description_state": "PASS",
        "operating_info_state": operating_information,
        "dataset_rights": {
            "state": "PASS",
            "attestation_sha256": _digest(f"dataset-rights-{ordinal}"),
        },
        "direct_media_state": "PASS" if qualified else "MISSING",
        "image_medium_state": image_state.value,
        "asset_rights": {
            "state": "PASS" if qualified else "MISSING",
            "reason": ("RIGHTS_AND_PROVENANCE_QUALIFIED" if qualified else "NO_IMAGE_EVIDENCE"),
            "provenance_complete": qualified,
            "analysis_eligible": qualified,
            "ui_eligible": qualified,
            "demo_eligible": qualified,
            "attestation_sha256": _digest(f"asset-rights-{ordinal}"),
        },
        "response_evidence_sha256": _digest(f"response-{ordinal}"),
    }
    return project_optional_media_candidate(source_row, historical_row, policy)


def test_sealed_projection_derives_exact_infeasible_frontier() -> None:
    projection = build_optional_media_projection(REPO_ROOT)

    frontier = evaluate_optional_media_frontier(
        projection.candidates,
        projection.policy,
        projection.projection_sha256,
    )

    assert projection.projection_sha256 == EXPECTED_PROJECTION_ROOT
    assert frontier.universe_root_sha256 == EXPECTED_PROJECTION_ROOT
    assert frontier.universe_count == 718
    assert len(frontier.accounting_rows) == 718
    assert frontier.eligible_count == 32
    assert frontier.group_counts == {
        "history_culture": 10,
        "history_scenery_boundary": 6,
        "image_modern_content": 3,
        "rest_walk_immersion": 13,
    }
    assert frontier.group_shortfalls == {
        "history_culture": 0,
        "history_scenery_boundary": 0,
        "image_modern_content": 3,
        "rest_walk_immersion": 0,
    }
    assert frontier.capped_capacity == 31
    assert frontier.status == "REPRESENTATION_INFEASIBLE"
    assert frontier.representation_quota.feasible is False
    assert frontier.representation_quota.outcome_code == 23
    assert frontier.catalog_ready is False
    assert frontier.plan20_reachable is False


def test_frontier_deficits_are_non_image_and_operating_information_blocks() -> None:
    projection = build_optional_media_projection(REPO_ROOT)
    frontier = evaluate_optional_media_frontier(
        projection.candidates,
        projection.policy,
        projection.projection_sha256,
    )

    allowed_deficits = set(projection.policy.non_image_gate_names)
    assert all(set(row.non_image_deficits) <= allowed_deficits for row in frontier.accounting_rows)
    assert all(
        row.image_medium_state not in row.non_image_deficits for row in frontier.accounting_rows
    )

    candidate = _eligible_candidate(
        ordinal=900,
        group="history_culture",
        operating_information="REVIEW_REQUIRED",
        image_state=ImageMediumState.QUALIFIED,
    )
    assert candidate.non_image_gates.operating_information is GateState.REVIEW_REQUIRED
    blocked = evaluate_optional_media_frontier(
        (candidate,),
        build_optional_media_policy(),
        _digest("synthetic-operating-universe"),
    )
    assert blocked.eligible_count == 0
    assert blocked.accounting_rows[0].non_image_deficits == ("operating_information",)


def test_feasible_fixture_reuses_exact_frozen_quota_contract() -> None:
    candidates = tuple(
        sorted(
            (
                _eligible_candidate(ordinal=group_index * 9 + item, group=group)
                for group_index, group in enumerate(GROUP_ORDER)
                for item in range(9)
            ),
            key=lambda candidate: candidate.place_entity_id,
        )
    )
    policy = build_optional_media_policy()

    first = evaluate_optional_media_frontier(
        candidates,
        policy,
        _digest("feasible-universe"),
    )
    second = evaluate_optional_media_frontier(
        candidates,
        policy,
        _digest("feasible-universe"),
    )

    assert first.status == "REPRESENTATION_FEASIBLE"
    assert first.eligible_count == 36
    assert first.capped_capacity == 36
    assert first.representation_quota.final_quotas == dict.fromkeys(GROUP_ORDER, 9)
    assert first.representation_quota.quota_sum == 36
    assert first.representation_quota.feasible is True
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )


def test_double_replay_publishes_only_canonical_infeasible_evidence(
    tmp_path: Path,
) -> None:
    audit = build_optional_media_frontier_audit(REPO_ROOT)

    assert audit.exit_code == 23
    assert audit.first_projection.projection_sha256 == EXPECTED_PROJECTION_ROOT
    assert audit.second_projection.projection_sha256 == EXPECTED_PROJECTION_ROOT
    assert canonical_json_bytes(
        audit.first_projection.model_dump(mode="json")
    ) == canonical_json_bytes(audit.second_projection.model_dump(mode="json"))
    assert canonical_json_bytes(
        audit.first_frontier.model_dump(mode="json")
    ) == canonical_json_bytes(audit.second_frontier.model_dump(mode="json"))
    assert audit.replay_attestation.byte_identical is True

    first_root = publish_optional_media_frontier_audit(
        audit,
        repository_root=REPO_ROOT,
        output_base=tmp_path / "readiness",
    )
    second_root = publish_optional_media_frontier_audit(
        audit,
        repository_root=REPO_ROOT,
        output_base=tmp_path / "readiness",
    )

    assert first_root == second_root
    assert first_root.name == audit.first_frontier.frontier_sha256
    assert {path.name for path in first_root.iterdir()} == set(FRONTIER_ARTIFACT_FILENAMES)
    frontier_payload = json.loads((first_root / "representation-frontier.json").read_bytes())
    assert frontier_payload["status"] == "REPRESENTATION_INFEASIBLE"
    assert frontier_payload["universe_count"] == 718
    assert frontier_payload["eligible_count"] == 32
    assert frontier_payload["group_counts"] == {
        "history_culture": 10,
        "history_scenery_boundary": 6,
        "image_modern_content": 3,
        "rest_walk_immersion": 13,
    }
    assert frontier_payload["capped_capacity"] == 31
    assert frontier_payload["catalog_ready"] is False
    assert frontier_payload["plan20_reachable"] is False
    forbidden = (
        "authority",
        "catalog-review",
        "schema",
        "seal",
        "selection",
        "split",
    )
    assert not any(fragment in path.name for path in first_root.iterdir() for fragment in forbidden)
