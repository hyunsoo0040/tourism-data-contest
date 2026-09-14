"""Opt-in actual national candidate → isolated PostgreSQL → real API verification.

No tourism or model requests are made. The shared verifier uses scripted answers
and a synthetic UNKNOWN photo provider; this is not human relevance evaluation.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.catalog_paths import is_national_catalog
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_source import GroundedSourceRelease
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json
from tests.integration.test_grounded_real_candidate import (
    test_actual_candidate_api_postgres_and_unknown_photo_baseline as verify_candidate_api,
)

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def national_selected_candidate():
    configured = os.environ.get("ITDA_NATIONAL_VERIFY_CANDIDATE")
    catalog_path = os.environ.get("ITDA_NATIONAL_VERIFY_CATALOG")
    if not configured or not catalog_path:
        pytest.skip("explicit national candidate and catalog paths are required")
    candidate = GroundedReleaseCandidate.model_validate_json(Path(configured).read_bytes())
    catalog = PublicPlaceCatalog.model_validate_json(Path(catalog_path).read_bytes())
    assert isinstance(candidate.raw_release, GroundedSourceRelease)
    assert 800 <= candidate.raw_release.published_count <= 1000
    assert catalog.region == "전국"
    assert is_national_catalog(catalog)
    assert candidate.raw_release.catalog_sha256 == catalog.catalog_sha256
    assert {p.place_id for p in candidate.raw_release.profiles} == {
        p.place_id for p in catalog.places
    }
    assert all(p.place_id.startswith("public:korea:") for p in catalog.places)
    assert all(s["place"]["provider_content_id"] for s in candidate.source_snapshots)
    return candidate, catalog


def test_actual_national_candidate_api_postgres_full_membership_and_photo_replay(
    national_selected_candidate, postgres_harness, tmp_path, monkeypatch
):
    candidate, catalog = national_selected_candidate
    output = Path(
        os.environ.get(
            "ITDA_NATIONAL_VERIFY_OUTPUT",
            str(ROOT / "artifacts/national/20260909/verification/api"),
        )
    )
    capture = output / "candidate-api-fixture.json"
    monkeypatch.setenv("ITDA_GROUNDED_VERIFY_REPORT", str(capture))
    verify_candidate_api(national_selected_candidate, postgres_harness, tmp_path, monkeypatch)
    result = json.loads(capture.read_text())
    assert result["candidate_sha256"] == candidate.candidate_sha256
    assert result["artifact_sha256"] == canonical_sha256(
        {key: value for key, value in result.items() if key != "artifact_sha256"}
    )
    run = result["results"]["run"]
    assert {r["place_id"] for r in run["candidate_bindings"]} == {
        p.place_id for p in catalog.places
    }
    sources = {s["place"]["place_id"]: s for s in candidate.source_snapshots}
    for item in run["items"]:
        source = sources[item["place_id"]]
        assert item["region_code"] == source["place"]["region_code"]
        assert item["region_name"] == source["place"]["region_name"]
        assert item["address_ko"] == source["place"]["address"]
        assert item["overall_confidence"] is None
        assert item["evidence"]
        evidence = {row["evidence_id"]: row for row in source["evidence"]}
        for row in item["evidence"]:
            assert row["quote"] in evidence[row["evidence_id"]]["excerpt"]
            assert row["receipt"] == evidence[row["evidence_id"]]["receipt"]
    summary = {
        "schema_version": "national-real-candidate-api-verification.v1",
        "completed_at": datetime.now(UTC).isoformat(),
        "candidate_sha256": candidate.candidate_sha256,
        "catalog_sha256": catalog.catalog_sha256,
        "actual_candidate_members": len(candidate.raw_release.profiles),
        "verified_run_bindings": len(run["candidate_bindings"]),
        "api_capture_sha256": result["artifact_sha256"],
        "checks": result["checks"],
        "additional_checks": ["full_national_membership", "region_identity", "source_quotes"],
        "human_relevance_status": "NOT_MEASURED",
        "browser_executed": False,
        "external_api_calls": 0,
        "paid_model_calls": 0,
        "outcome": "PASS",
    }
    summary["artifact_sha256"] = canonical_sha256(summary)
    atomic_json(output / "verification.json", summary)
