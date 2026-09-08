from __future__ import annotations

import json
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.collectors.base import RequestPolicy
from itda.collectors.gyeongju_district import GyeongjuDistrictClient
from itda.contracts.catalog_discovery import (
    ApprovalEvidence,
    D1Request,
    FrozenDiscoveryIssuance,
    build_d1_request_generation,
    publish_request_generation,
    verify_request_generation,
)


def _generation(tmp_path: Path):
    issued_at = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    return build_d1_request_generation(
        repository_relative_root=(
            "artifacts/restricted/catalog/v2/supplemental/discovery/requests"
        ),
        failure_generation_sha256="0" * 64,
        failure_round_id="1" * 64,
        failure_attestation_sha256="2" * 64,
        target_matrix_sha256="3" * 64,
        target_ids=tuple(f"target-{index:02d}" for index in range(24)),
        approval_evidence=ApprovalEvidence.pending(
            dataset_id="15114464",
            reviewer_id="phase2-operator",
        ),
        frozen=FrozenDiscoveryIssuance(
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=24),
            nonce="a" * 64,
            reviewer_id="phase2-operator",
        ),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dataset_id", "15109381"),
        ("scheme", "http"),
        ("host", "evil.example"),
        ("path", "/wrong"),
        ("method", "POST"),
        ("page_no", 21),
        ("num_of_rows", 11),
        ("max_attempts", 4),
        ("attempt_timeout_seconds", 299),
        ("follow_redirects", True),
    ],
)
def test_d1_contract_rejects_scope_transport_or_budget_drift(
    field: str,
    value: object,
) -> None:
    payload = {
        "dataset_id": "15114464",
        "scheme": "https",
        "host": "apis.data.go.kr",
        "path": "/5050000/dstrctsTrrsrtService/getDstrctsTrrsrt",
        "method": "GET",
        "page_no": 1,
        "num_of_rows": 10,
        "response_type": "json",
        "row_ceiling": 10,
        "response_byte_ceiling": 2_000_000,
        "max_attempts": 3,
        "attempt_timeout_seconds": 300,
        "follow_redirects": False,
        "early_stop": "ALL_TARGETS_UNAMBIGUOUS_OR_TOTAL_COUNT_EXHAUSTED",
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        D1Request.model_validate(payload)


def test_d1_contract_rejects_service_key_in_identity() -> None:
    payload = {
        "dataset_id": "15114464",
        "scheme": "https",
        "host": "apis.data.go.kr",
        "path": "/5050000/dstrctsTrrsrtService/getDstrctsTrrsrt",
        "method": "GET",
        "page_no": 1,
        "num_of_rows": 10,
        "response_type": "json",
        "row_ceiling": 10,
        "response_byte_ceiling": 2_000_000,
        "max_attempts": 3,
        "attempt_timeout_seconds": 300,
        "follow_redirects": False,
        "early_stop": "ALL_TARGETS_UNAMBIGUOUS_OR_TOTAL_COUNT_EXHAUSTED",
        "serviceKey": "must-not-appear",
    }

    with pytest.raises(ValidationError):
        D1Request.model_validate(payload)


def test_d1_transport_adapter_has_fixed_endpoint_and_exact_policy() -> None:
    client = GyeongjuDistrictClient(
        service_key="secret-not-used",
        policy=RequestPolicy(timeout_seconds=300, max_attempts=3),
    )
    try:
        assert client.base_url == "https://apis.data.go.kr/5050000/dstrctsTrrsrtService"
        assert client.allowed_operations == frozenset({"getDstrctsTrrsrt"})
        assert client.policy == RequestPolicy(timeout_seconds=300, max_attempts=3)
    finally:
        client.close()


def test_d1_pretraffic_generation_is_private_no_replace_and_reverifiable(
    tmp_path: Path,
) -> None:
    generation = _generation(tmp_path)
    root = tmp_path / generation.request_generation_sha256

    publish_request_generation(generation, root)
    verify_request_generation(root)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for child in root.iterdir():
        assert child.is_file()
        assert stat.S_IMODE(child.stat().st_mode) == 0o600
    manifest = json.loads((root / "discovery-request-manifest.json").read_bytes())
    assert manifest["provider_requests_sent"] == 0
    assert manifest["credential_file_opened"] is False
    assert manifest["collection_root_created"] is False
    with pytest.raises(FileExistsError):
        publish_request_generation(generation, root)


def test_d1_pretraffic_generation_contains_no_secret_or_collection_receipt(
    tmp_path: Path,
) -> None:
    generation = _generation(tmp_path)
    serialized = b"".join(generation.files.values())

    assert b"must-not-appear" not in serialized
    assert b"secret-not-used" not in serialized
    assert b"TOUR_API_SERVICE_KEY" not in serialized
    assert b"authority-consumption" not in serialized
    assert b"collection-generation" not in serialized
    assert b"canonical-36" not in serialized
    assert b"split-manifest" not in serialized


def test_d1_pretraffic_collector_refuses_collection_without_human_gate(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "itda.cli.collect_catalog_discovery",
            "--repo-root",
            str(tmp_path),
            "--source",
            "d1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "blocking-human checkpoint" in result.stderr
    assert "serviceKey" not in result.stderr
