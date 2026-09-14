"""The delivery bundle must match actual measured data and the current API contract."""

import hashlib
import json
from pathlib import Path

from itda.catalog_paths import NATIONAL_CURRENT_DIRECTORY, is_national_candidate
from itda.cli.export_openapi import openapi_document_bytes
from itda.contracts.grounded_promotion import (
    GroundedPromotionGate,
    GroundedPromotionReport,
    validate_promotion_reports,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog
from itda.domain.canonical import canonical_sha256

ROOT = Path(__file__).resolve().parents[3]


def test_initial_delivery_bundle_is_measured_and_matches_current_api():
    directory = ROOT / NATIONAL_CURRENT_DIRECTORY
    candidate = GroundedReleaseCandidate.model_validate_json(
        (directory / "candidate.json").read_bytes()
    )
    catalog = PublicPlaceCatalog.model_validate_json((directory / "catalog.json").read_bytes())
    assert is_national_candidate(candidate, catalog)
    assert 800 <= len(catalog.places) <= 1000
    gate = GroundedPromotionGate.model_validate_json((directory / "gate.json").read_bytes())
    reports = tuple(
        GroundedPromotionReport.model_validate_json(
            (directory / "reports" / f"{digest}.json").read_bytes()
        )
        for digest in (
            gate.source_ablation_sha256,
            gate.axis_comparison_sha256,
            gate.api_ui_verification_sha256,
        )
    )
    validate_promotion_reports(gate, reports, candidate_created_at=candidate.created_at)
    assert gate.candidate_sha256 == candidate.candidate_sha256
    assert gate.config_sha256 == GROUNDED_POLICY.sha256
    api_ui = next(report for report in reports if report.kind == "API_UI")
    assert api_ui.result["openapi_sha256"] == hashlib.sha256(openapi_document_bytes()).hexdigest()
    package = json.loads((directory / "package.json").read_bytes())
    assert package["package_sha256"] == canonical_sha256(
        {key: value for key, value in package.items() if key != "package_sha256"}
    )
    assert package["candidate_sha256"] == candidate.candidate_sha256
    assert package["gate_sha256"] == gate.gate_sha256
