"""Wave 0 contract for DATA-08 real catalog split (T-02-05, T-02-07)."""

from __future__ import annotations

import importlib
import importlib.util
import json
from types import ModuleType

import pytest
from pydantic import ValidationError

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

CAPABILITY_MODULE = "itda.contracts.catalog_manifest"


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("real manifest production capability is implemented in Plan 02-08")
    return importlib.import_module(CAPABILITY_MODULE)


def _manifest_payload() -> dict[str, object]:
    members = [
        {
            "canonical_place_id": f"place:{index:03d}",
            "split": "DEV" if index <= 24 else "BLIND",
            "component_id": f"component:{index:03d}",
        }
        for index in range(1, 37)
    ]
    return {
        "schema_version": "real-split-manifest-v1",
        "manifest_version": "catalog-split-v1",
        "canonicalization_version": "canonical-json-v1",
        "catalog_manifest_sha256": "1" * 64,
        "catalog_approval_sha256": "2" * 64,
        "catalog_adjudication_sha256": "3" * 64,
        "relationship_revision_sha256": "4" * 64,
        "algorithm_version": "exact-component-split-v1",
        "seed": 20260727,
        "component_inputs_sha256": "5" * 64,
        "balance_inputs_sha256": "6" * 64,
        "objective_score": "0.000000",
        "members": members,
    }


def test_real_manifest_is_exact_catalog_bound_group_safe_24_12() -> None:
    capability = _capability_or_skip()
    manifest = capability.RealSplitManifest.model_validate(_manifest_payload())
    assert len(manifest.members) == 36
    assert sum(member.split == "DEV" for member in manifest.members) == 24
    assert sum(member.split == "BLIND" for member in manifest.members) == 12
    assert len({member.canonical_place_id for member in manifest.members}) == 36
    assert all(member.canonical_place_id.startswith("place:") for member in manifest.members)
    assert manifest.catalog_manifest_sha256 == "1" * 64
    assert manifest.catalog_approval_sha256 == "2" * 64
    assert capability.validate_component_closure(manifest) is None


def test_real_manifest_rejects_split_component_and_impossible_counts() -> None:
    capability = _capability_or_skip()
    split_component = _manifest_payload()
    split_component["members"][23]["component_id"] = "component:shared"
    split_component["members"][24]["component_id"] = "component:shared"
    with pytest.raises((ValidationError, ValueError), match="component"):
        capability.RealSplitManifest.model_validate(split_component)

    wrong_count = _manifest_payload()
    wrong_count["members"][23]["split"] = "BLIND"
    with pytest.raises((ValidationError, ValueError), match="24.*12|12.*24"):
        capability.RealSplitManifest.model_validate(wrong_count)


def test_real_manifest_bytes_are_deterministic_across_clean_orderings() -> None:
    capability = _capability_or_skip()
    payload = _manifest_payload()
    first = capability.RealSplitManifest.model_validate(payload)
    reordered = dict(reversed(list(payload.items())))
    reordered["members"] = list(reversed(payload["members"]))
    second = capability.RealSplitManifest.model_validate(reordered)
    assert first.canonical_payload() == second.canonical_payload()
    assert canonical_json_bytes(first.canonical_payload()) == canonical_json_bytes(
        second.canonical_payload()
    )
    assert canonical_sha256(first.canonical_payload()) == canonical_sha256(
        second.canonical_payload()
    )


@pytest.mark.parametrize(
    "forbidden",
    ["label", "score", "prompt", "model", "embedding", "blind_result"],
)
def test_balance_inputs_reject_later_evaluation_or_model_information(forbidden: str) -> None:
    capability = _capability_or_skip()
    with pytest.raises(ValueError, match="balance|forbidden"):
        capability.validate_balance_inputs(
            {
                "proposal_coverage_version": "proposal-coverage-seed-v1",
                "completeness_version": "catalog-audit-v1",
                forbidden: "must-not-enter-split",
            }
        )


def test_catalog_and_split_approvals_are_separate_and_full_digest_bound() -> None:
    capability = _capability_or_skip()
    manifest = capability.RealSplitManifest.model_validate(_manifest_payload())
    manifest_sha256 = canonical_sha256(manifest.canonical_payload())
    approval = capability.SplitApproval(
        schema_version="split-approval-v1",
        catalog_manifest_sha256=manifest.catalog_manifest_sha256,
        catalog_approval_sha256=manifest.catalog_approval_sha256,
        split_manifest_sha256=manifest_sha256,
        confirm_sha256=manifest_sha256,
        reviewer_id="split-reviewer",
        approved_at="2026-07-27T05:00:00Z",
    )
    assert approval.split_manifest_sha256 == manifest_sha256
    assert approval.catalog_approval_sha256 != approval.split_approval_sha256

    with pytest.raises((ValidationError, ValueError), match="64|sha256|digest"):
        capability.SplitApproval(
            schema_version="split-approval-v1",
            catalog_manifest_sha256=manifest.catalog_manifest_sha256,
            catalog_approval_sha256=manifest.catalog_approval_sha256,
            split_manifest_sha256=manifest_sha256,
            confirm_sha256=manifest_sha256[:12],
            reviewer_id="split-reviewer",
            approved_at="2026-07-27T05:00:00Z",
        )


def test_public_split_request_is_membership_free_and_not_complement_reconstructable() -> None:
    capability = _capability_or_skip()
    manifest = capability.RealSplitManifest.model_validate(_manifest_payload())
    request = capability.build_split_approval_request(manifest)
    payload = json.loads(canonical_json_bytes(request.canonical_payload()))
    serialized = json.dumps(payload, sort_keys=True).casefold()
    assert payload["dev_count"] == 24
    assert payload["blind_count"] == 12
    assert payload["split_manifest_sha256"] == canonical_sha256(manifest.canonical_payload())
    assert not {
        "members",
        "canonical_place_ids",
        "dev_members",
        "blind_members",
        "catalog_members",
    }.intersection(payload)
    assert "place:" not in serialized


def test_membership_digest_and_request_bind_every_split_input() -> None:
    capability = _capability_or_skip()
    manifest = capability.RealSplitManifest.model_validate(_manifest_payload())
    request = capability.build_split_approval_request(manifest)

    assert manifest.membership_sha256 == canonical_sha256(
        [member.model_dump(mode="json") for member in manifest.canonical_members()]
    )
    assert request.catalog_manifest_sha256 == manifest.catalog_manifest_sha256
    assert request.catalog_approval_sha256 == manifest.catalog_approval_sha256
    assert request.catalog_adjudication_sha256 == manifest.catalog_adjudication_sha256
    assert request.relationship_revision_sha256 == manifest.relationship_revision_sha256
    assert request.algorithm_version == manifest.algorithm_version
    assert request.seed == manifest.seed
    assert request.component_inputs_sha256 == manifest.component_inputs_sha256
    assert request.balance_inputs_sha256 == manifest.balance_inputs_sha256
    assert request.membership_sha256 == manifest.membership_sha256
    assert request.component_closure_valid is True
    assert request.exact_counts_valid is True
    assert len(request.split_approval_request_sha256) == 64


def test_split_approval_rejects_stale_request_or_manifest_parent() -> None:
    capability = _capability_or_skip()
    manifest = capability.RealSplitManifest.model_validate(_manifest_payload())
    request = capability.build_split_approval_request(manifest)
    stale_payload = request.model_dump(mode="json")
    stale_payload["catalog_approval_sha256"] = "0" * 64
    stale_payload["split_approval_request_sha256"] = None
    stale = capability.SplitApprovalRequest.model_validate(stale_payload)

    with pytest.raises(ValueError, match="request|catalog approval|parent"):
        capability.verify_split_approval_request(stale, manifest)


def test_public_split_request_omits_restricted_provider_and_complement_material() -> None:
    capability = _capability_or_skip()
    request = capability.build_split_approval_request(
        capability.RealSplitManifest.model_validate(_manifest_payload())
    )
    payload = request.canonical_payload()
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()

    assert "place:" not in serialized
    assert "provider" not in serialized
    assert "raw_" not in serialized
    assert "permission" not in serialized
    assert "asset" not in serialized
    assert "catalog_members" not in serialized
    assert "dev_members" not in serialized
    assert "blind_members" not in serialized


def test_split_is_impossible_before_catalog_approval() -> None:
    capability = _capability_or_skip()
    payload = _manifest_payload()
    payload["catalog_approval_sha256"] = None
    with pytest.raises((ValidationError, ValueError), match="catalog.*approval"):
        capability.RealSplitManifest.model_validate(payload)


def test_missing_real_manifest_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:real-manifest", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)
