from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from itda.contracts.catalog_discovery import (
    ApprovalEvidence,
    CapabilityState,
    DeficitServiceability,
    DiscoveryObservation,
    FrozenDiscoveryIssuance,
    MatchDisposition,
    RightsDisposition,
    build_d1_request_generation,
    build_d1_request_inventory,
)


def _frozen() -> FrozenDiscoveryIssuance:
    issued_at = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    return FrozenDiscoveryIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        nonce="a" * 64,
        reviewer_id="phase2-operator",
    )


def test_d1_contract_inventory_is_exact_secret_free_and_bounded() -> None:
    inventory = build_d1_request_inventory()

    assert len(inventory) == 20
    assert [row.page_no for row in inventory] == list(range(1, 21))
    assert {row.dataset_id for row in inventory} == {"15114464"}
    assert {row.method for row in inventory} == {"GET"}
    assert {row.host for row in inventory} == {"apis.data.go.kr"}
    assert {row.path for row in inventory} == {"/5050000/dstrctsTrrsrtService/getDstrctsTrrsrt"}
    assert {row.num_of_rows for row in inventory} == {10}
    assert {row.max_attempts for row in inventory} == {3}
    assert {row.attempt_timeout_seconds for row in inventory} == {300}
    assert {row.follow_redirects for row in inventory} == {False}
    assert len({row.request_identity_sha256 for row in inventory}) == 20
    assert all("serviceKey" not in row.model_dump(mode="json") for row in inventory)


def test_d1_contract_keeps_capability_observation_serviceability_and_rights_separate() -> None:
    observation = DiscoveryObservation.from_d1_row(
        target_id="target-001",
        provider_row={
            "CON_UID": "provider-77",
            "CON_TITLE": "동궁과 월지",
            "CON_IMGFILENAME": "image.jpg",
            "SRC_TITLE": "관광사진",
            "LINKURL": "https://example.invalid/image.jpg",
            "CON_ISENABLED": "Y",
        },
        matched_target_count=1,
        hierarchy_unambiguous=True,
        coordinate_conflict=False,
    )

    assert observation.capability_state is CapabilityState.OBSERVED_RECORD
    assert observation.match_disposition is MatchDisposition.REVIEW_REQUIRED
    assert (
        observation.media_rights_serviceability
        is DeficitServiceability.NOT_SERVICEABLE_MEDIA_RIGHTS
    )
    assert (
        observation.operating_info_serviceability
        is DeficitServiceability.NOT_SERVICEABLE_OPERATING_INFO
    )
    assert observation.rights_disposition is RightsDisposition.PENDING_ASSET_REVIEW
    assert observation.target_id == "target-001"
    assert observation.provider_row_id == "provider-77"


def test_d1_generation_is_byte_identical_from_one_frozen_context() -> None:
    approval = ApprovalEvidence.pending(
        dataset_id="15114464",
        reviewer_id="phase2-operator",
    )
    kwargs = {
        "repository_relative_root": (
            "artifacts/restricted/catalog/v2/supplemental/discovery/requests"
        ),
        "failure_generation_sha256": "0" * 64,
        "failure_round_id": "1" * 64,
        "failure_attestation_sha256": "2" * 64,
        "target_matrix_sha256": "3" * 64,
        "target_ids": tuple(f"target-{index:02d}" for index in range(24)),
        "approval_evidence": approval,
        "frozen": _frozen(),
    }

    first = build_d1_request_generation(**kwargs)
    second = build_d1_request_generation(**kwargs)

    assert first.files == second.files
    assert first.request_generation_sha256 == second.request_generation_sha256
    assert first.manifest["provider_requests_sent"] == 0
    assert first.manifest["credential_file_opened"] is False
    assert first.manifest["collection_root_created"] is False
    assert first.request["request_count"] == 20
    assert first.request["row_ceiling"] == 200
    assert first.request["overall_timeout_seconds"] == 20 * 3 * 300


def test_d1_approval_evidence_is_dataset_specific() -> None:
    with pytest.raises(ValueError, match="15114464"):
        ApprovalEvidence(
            dataset_id="15109381",
            account_stage="production",
            approval_state="APPROVED",
            observed_at=datetime(2026, 7, 30, tzinfo=UTC),
            reviewer_id="phase2-operator",
            evidence_sha256="4" * 64,
        )
