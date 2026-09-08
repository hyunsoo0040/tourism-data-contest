"""Wave 0 contract for DATA-05/06 (02-W0-DATA05/06; D-05 through D-08).

Threat coverage: T-02-02, T-02-03, and T-02-05A.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

CAPABILITY_MODULE = "itda.contracts.catalog_audit"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PHASE1_RIGHTS_BYTES = {
    "fixtures/preview/v1/review/candidate-review.json": (
        "12875e60d591e8824b32642df204ea2ce626bada22000e75ca1dd16e37a6d89d"
    ),
    "fixtures/preview/v1/review/candidate-review.md": (
        "1308a2544fdff7eb2c662644a4e3b0b473be62e479f51e0a03529243004fa39c"
    ),
    "fixtures/preview/v1/review/raw-provider-bundle.redacted.json": (
        "f0fc68aa465015611219e6a233f91f8f133d9cee323eb84a3b7d288a5689114f"
    ),
    "fixtures/preview/v1/review/review-manifest.json": (
        "172ef4a7ce940c052384861aef907f917971d2e762311d303361af2112260bb6"
    ),
    "fixtures/preview/v1/review/APPROVAL.md": (
        "8ea915e8a2f975d4612e81bd139d142b48a9159cfcc768cd02ab847b6af2b6d2"
    ),
    "fixtures/preview/source-locks/preview-v1-source-lock.json": (
        "5e4f29f9495a7d4561d0c334a36ed06f155789520af8760961989314cfbb2d6b"
    ),
}


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("catalog rights production capability is implemented in Plan 02-07")
    return importlib.import_module(CAPABILITY_MODULE)


def _grant(
    capability: ModuleType,
    *,
    official_dataset_id: str,
    license_type: str,
    attribution_text: str | None,
) -> object:
    return capability.DatasetGrantEvidence(
        official_dataset_id=official_dataset_id,
        official_page_url=f"https://www.data.go.kr/data/{official_dataset_id}/openapi.do",
        retrieved_at="2026-07-27T05:00:00Z",
        response_sha256="1" * 64,
        page_sha256="2" * 64,
        dataset_grant_sha256="3" * 64,
        evidence_state="COMPLETE",
        license_type=license_type,
        attribution_text=attribution_text,
        commercial_use_allowed=True,
        transform_allowed=True,
        display_allowed=True,
        model_input_allowed=True,
    )


def _asset(
    capability: ModuleType,
    *,
    official_dataset_id: str = "15101914",
    restriction: str | None = None,
    source_asset_id: str | None = "photo-001",
    original_url: str | None = "https://tong.visitkorea.or.kr/photo-001.jpg",
) -> object:
    return capability.CatalogAsset(
        official_dataset_id=official_dataset_id,
        source_asset_id=source_asset_id,
        source_request_sha256="4" * 64 if source_asset_id else None,
        source_response_sha256="5" * 64 if source_asset_id else None,
        original_url=original_url,
        creator_or_photographer="한국관광공사",
        license_type="KOGL_TYPE_1_ATTRIBUTION",
        attribution_text="한국관광공사 포토코리아-홍길동",
        explicit_asset_restriction=restriction,
    )


def test_official_odii_and_photo_grants_are_distinct_and_attribution_bound() -> None:
    capability = _capability_or_skip()
    odii = _grant(
        capability,
        official_dataset_id="15101971",
        license_type="PUBLIC_DATA_GRANT",
        attribution_text=None,
    )
    photo = _grant(
        capability,
        official_dataset_id="15101914",
        license_type="KOGL_TYPE_1_ATTRIBUTION",
        attribution_text="한국관광공사 포토코리아",
    )

    assert odii.official_dataset_id == "15101971"
    assert photo.official_dataset_id == "15101914"
    assert photo.license_type == "KOGL_TYPE_1_ATTRIBUTION"
    assert photo.attribution_text
    assert odii.dataset_grant_sha256 != photo.dataset_grant_sha256 or (
        odii.official_dataset_id != photo.official_dataset_id
    )


def test_asset_restriction_wins_but_asset_remains_auditable() -> None:
    capability = _capability_or_skip()
    disposition = capability.decide_asset_rights(
        _asset(capability, restriction="NO_DERIVATIVES_OR_MODEL_INPUT"),
        _grant(
            capability,
            official_dataset_id="15101914",
            license_type="KOGL_TYPE_1_ATTRIBUTION",
            attribution_text="한국관광공사 포토코리아",
        ),
    )

    assert disposition.rights_state == "BLOCKED_EXPLICIT_ASSET_RESTRICTION"
    assert disposition.audit_evidence_retained is True
    assert disposition.transform_allowed is False
    assert disposition.display_allowed is False
    assert disposition.model_input_allowed is False
    assert disposition.analysis_eligible is False
    assert disposition.ui_eligible is False
    assert disposition.demo_eligible is False


@pytest.mark.parametrize(
    "asset_overrides",
    [
        {"source_asset_id": None},
        {"original_url": None},
    ],
    ids=["missing-source-id", "missing-original-url"],
)
def test_missing_asset_provenance_fails_closed(asset_overrides: dict[str, object]) -> None:
    capability = _capability_or_skip()
    disposition = capability.decide_asset_rights(
        _asset(capability, **asset_overrides),
        _grant(
            capability,
            official_dataset_id="15101914",
            license_type="KOGL_TYPE_1_ATTRIBUTION",
            attribution_text="한국관광공사 포토코리아",
        ),
    )
    assert disposition.rights_state == "BLOCKED_MISSING_PROVENANCE"
    assert not any(
        (
            disposition.analysis_eligible,
            disposition.ui_eligible,
            disposition.demo_eligible,
        )
    )


@pytest.mark.parametrize("grant_state", ["MISSING", "INCOMPLETE"])
def test_missing_or_incomplete_grant_blocks_every_downstream_lane(grant_state: str) -> None:
    capability = _capability_or_skip()
    grant = _grant(
        capability,
        official_dataset_id="15101914",
        license_type="KOGL_TYPE_1_ATTRIBUTION",
        attribution_text="한국관광공사 포토코리아",
    )
    grant = grant.model_copy(update={"evidence_state": grant_state})
    disposition = capability.decide_asset_rights(_asset(capability), grant)
    assert disposition.rights_state == f"BLOCKED_GRANT_{grant_state}"
    assert disposition.audit_evidence_retained is True
    assert disposition.analysis_eligible is False
    assert disposition.ui_eligible is False
    assert disposition.demo_eligible is False


def test_odii_grant_cannot_authorize_photo_gallery_asset() -> None:
    capability = _capability_or_skip()
    with pytest.raises(ValueError, match="dataset"):
        capability.decide_asset_rights(
            _asset(capability, official_dataset_id="15101914"),
            _grant(
                capability,
                official_dataset_id="15101971",
                license_type="PUBLIC_DATA_GRANT",
                attribution_text=None,
            ),
        )


def test_phase1_rights_history_and_type3_exclusion_bytes_are_unchanged() -> None:
    for relative_path, expected_sha256 in PHASE1_RIGHTS_BYTES.items():
        assert hashlib.sha256((REPOSITORY_ROOT / relative_path).read_bytes()).hexdigest() == (
            expected_sha256
        )

    candidate_review = json.loads(
        (REPOSITORY_ROOT / "fixtures/preview/v1/review/candidate-review.json").read_text(
            encoding="utf-8"
        )
    )
    donggung = next(
        row
        for row in candidate_review["rights_review"]["candidates"]
        if row["place_id"] == "preview:4"
    )
    representative = donggung["representative_image"]
    assert representative["cpyrht_div_cd"] == "Type3"
    assert representative["status"] == "ORIGINAL_DISPLAY_ONLY"
    assert representative["transform_allowed"] is False
    assert representative["model_input_allowed"] is False
    assert representative["normalized_asset_allowed"] is False


def test_missing_catalog_rights_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-rights", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)
