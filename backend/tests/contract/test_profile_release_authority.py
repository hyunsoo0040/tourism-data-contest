"""Behavior-first authority graph tests for PROF-08 release eligibility."""

from __future__ import annotations

import importlib
import os
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import ValidationError

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_DIGEST_FIELDS = (
    "label_freeze_sha256",
    "candidate_manifest_sha256",
    "reviewed_manifest_sha256",
    "rights_manifest_sha256",
    "source_manifest_sha256",
)


def _digest(label: str) -> str:
    return canonical_sha256({"synthetic": label})


def _self_hash(payload: dict[str, Any], field: str = "manifest_sha256") -> None:
    payload[field] = canonical_sha256(
        {key: value for key, value in payload.items() if key != field}
    )


def _member_hash(payload: dict[str, Any], field: str) -> None:
    payload[field] = canonical_sha256(
        {key: value for key, value in payload.items() if key != field}
    )


def _bundle_payloads() -> dict[str, dict[str, Any]]:
    canonical = _digest("canonical-lineage")
    dev = _digest("dev-lineage")
    profile_schema = _digest("profile-schema")
    label_source_root = _digest("label-source-root")
    accepted_revisions = _digest("accepted-label-revisions")
    adjudicated_label_export = _digest("adjudicated-export")

    freeze: dict[str, Any] = {
        "schema_version": "phase3-label-freeze-receipt-v1",
        "status": "APPROVED_FROZEN",
        "accepted_revision_set_sha256": accepted_revisions,
        "adjudicated_label_export_sha256": adjudicated_label_export,
        "aggregate_set_sha256": _digest("aggregate-set"),
        "rubric_sha256": _digest("rubric"),
        "source_root_sha256": label_source_root,
        "dev_lineage_sha256": dev,
        "code_version_sha256": _digest("freeze-code"),
        "config_version_sha256": _digest("freeze-config"),
        "authority_grants": [],
        "frozen_at": "2026-08-06T00:00:00Z",
    }
    _self_hash(freeze, "receipt_sha256")

    source_members: list[dict[str, Any]] = []
    rights_members: list[dict[str, Any]] = []
    candidate_members: list[dict[str, Any]] = []
    reviewed_members: list[dict[str, Any]] = []
    for index in range(24):
        place_ref = f"synthetic-authority-place-{index:02d}"
        source_sha256 = _digest(f"source-{index}")
        lanes = {
            "description_lane": "READY",
            "odii_lane": "MISSING" if index % 3 == 0 else "READY",
        }
        source_members.append(
            {
                "place_ref": place_ref,
                "source_sha256": source_sha256,
                **lanes,
                "source_eligible": True,
            }
        )
        rights_members.append(
            {
                "place_ref": place_ref,
                "source_sha256": source_sha256,
                "rights_sha256": _digest(f"rights-{index}"),
                "rights_eligible": True,
            }
        )
        candidate_member = {
            "place_ref": place_ref,
            "source_sha256": source_sha256,
            "label_export_sha256": adjudicated_label_export,
            "profile_sha256": _digest(f"profile-{index}"),
            **lanes,
            "complete": True,
        }
        _member_hash(candidate_member, "candidate_manifest_sha256")
        candidate_members.append(candidate_member)
        reviewed_member = {
            "place_ref": place_ref,
            "candidate_manifest_sha256": candidate_member["candidate_manifest_sha256"],
            "accepted_review_set_sha256": _digest(f"accepted-review-{index}"),
            **lanes,
            "evidence_eligible": True,
        }
        _member_hash(reviewed_member, "reviewed_evidence_manifest_sha256")
        reviewed_members.append(reviewed_member)

    source: dict[str, Any] = {
        "schema_version": "itda.profile-release-source-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "label_source_root_sha256": label_source_root,
        "members": source_members,
    }
    _self_hash(source)
    rights: dict[str, Any] = {
        "schema_version": "itda.profile-release-rights-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "source_manifest_sha256": source["manifest_sha256"],
        "members": rights_members,
    }
    _self_hash(rights)
    candidate: dict[str, Any] = {
        "schema_version": "itda.profile-release-candidate-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "profile_schema_sha256": profile_schema,
        "label_freeze_sha256": freeze["receipt_sha256"],
        "adjudicated_label_export_sha256": adjudicated_label_export,
        "source_manifest_sha256": source["manifest_sha256"],
        "accepted_revision_set_sha256": accepted_revisions,
        "code_sha256": _digest("candidate-code"),
        "config_sha256": _digest("candidate-config"),
        "members": candidate_members,
    }
    _self_hash(candidate)
    reviewed: dict[str, Any] = {
        "schema_version": "itda.profile-release-reviewed-authority.v1",
        "canonical_lineage_sha256": canonical,
        "dev_lineage_sha256": dev,
        "profile_schema_sha256": profile_schema,
        "candidate_manifest_sha256": candidate["manifest_sha256"],
        "members": reviewed_members,
    }
    _self_hash(reviewed)
    return {
        "label_freeze": freeze,
        "candidate_manifest": candidate,
        "reviewed_manifest": reviewed,
        "rights_manifest": rights,
        "source_manifest": source,
    }


def _write_bundle(tmp_path: Path, payloads: dict[str, dict[str, Any]]) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for name, payload in payloads.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_json_bytes(payload))
        paths[name] = path
    return paths


def _request(payloads: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "release_id": "synthetic-authority-release",
        "builder_principal": "synthetic-builder",
        "canonical_lineage_sha256": payloads["source_manifest"]["canonical_lineage_sha256"],
        "dev_lineage_sha256": payloads["source_manifest"]["dev_lineage_sha256"],
        "profile_schema_sha256": payloads["candidate_manifest"]["profile_schema_sha256"],
        "label_freeze_sha256": payloads["label_freeze"]["receipt_sha256"],
        "candidate_manifest_sha256": payloads["candidate_manifest"]["manifest_sha256"],
        "reviewed_manifest_sha256": payloads["reviewed_manifest"]["manifest_sha256"],
        "rights_manifest_sha256": payloads["rights_manifest"]["manifest_sha256"],
        "source_manifest_sha256": payloads["source_manifest"]["manifest_sha256"],
    }


def _capability() -> ModuleType:
    try:
        return importlib.import_module("itda.contracts.profile_release_authority")
    except ModuleNotFoundError:
        pytest.fail("PHASE3-MISSING:profile-release-authority", pytrace=False)


def _resolve(
    tmp_path: Path,
    payloads: dict[str, dict[str, Any]],
    request: dict[str, Any] | None = None,
) -> Any:
    capability = _capability()
    paths = _write_bundle(tmp_path, payloads)
    return capability.resolve_authoritative_profile_release_candidate(
        request=_request(payloads) if request is None else request,
        paths=capability.ProfileReleaseAuthorityPaths(**paths),
    )


def _rehash_manifest(payloads: dict[str, dict[str, Any]], name: str) -> None:
    _self_hash(payloads[name])


def test_complete_server_bundle_derives_release_eligibility(tmp_path: Path) -> None:
    payloads = _bundle_payloads()
    candidate = _resolve(tmp_path, payloads)

    assert candidate.label_freeze_sha256 == payloads["label_freeze"]["receipt_sha256"]
    assert candidate.candidate_run_sha256 == payloads["candidate_manifest"]["manifest_sha256"]
    assert candidate.reviewed_manifest_sha256 == payloads["reviewed_manifest"]["manifest_sha256"]
    assert candidate.rights_manifest_sha256 == payloads["rights_manifest"]["manifest_sha256"]
    assert candidate.source_manifest_sha256 == payloads["source_manifest"]["manifest_sha256"]
    assert len(candidate.cohort) == 24
    assert all(
        member.label_ready and member.rights_ready and member.evidence_ready
        for member in candidate.cohort
    )
    assert all(
        member.candidate_manifest_sha256
        and member.reviewed_evidence_manifest_sha256
        and member.accepted_review_set_sha256
        for member in candidate.cohort
    )

    complete_payload = candidate.model_dump(mode="json")
    for field_name in (
        "label_freeze_sha256",
        "candidate_run_sha256",
        "reviewed_manifest_sha256",
        "rights_manifest_sha256",
        "source_manifest_sha256",
        "code_sha256",
        "config_sha256",
    ):
        missing = deepcopy(complete_payload)
        missing.pop(field_name)
        with pytest.raises(ValidationError):
            candidate.__class__.model_validate(missing)
    for field_name in (
        "label_export_sha256",
        "candidate_manifest_sha256",
        "reviewed_evidence_manifest_sha256",
        "accepted_review_set_sha256",
        "rights_sha256",
        "source_sha256",
    ):
        missing = deepcopy(complete_payload)
        missing["cohort"][0].pop(field_name)
        with pytest.raises(ValidationError):
            candidate.__class__.model_validate(missing)


def test_reviewed_member_digest_names_the_persisted_external_manifest(tmp_path: Path) -> None:
    payloads = _bundle_payloads()
    external_manifest_sha256 = _digest("persisted-reviewed-evidence-manifest")
    payloads["reviewed_manifest"]["members"][0][
        "reviewed_evidence_manifest_sha256"
    ] = external_manifest_sha256
    _rehash_manifest(payloads, "reviewed_manifest")

    candidate = _resolve(tmp_path, payloads)

    assert candidate.cohort[0].reviewed_evidence_manifest_sha256 == external_manifest_sha256


def test_client_readiness_booleans_cannot_replace_authoritative_manifests(
    tmp_path: Path,
) -> None:
    payloads = _bundle_payloads()
    request = _request(payloads)
    request.update(
        {
            "label_ready": True,
            "rights_ready": True,
            "evidence_ready": True,
            "completeness_ready": True,
        }
    )
    paths = _write_bundle(tmp_path, payloads)
    paths["candidate_manifest"].unlink()

    capability = _capability()
    with pytest.raises(capability.ProfileReleaseAuthorityError) as captured:
        capability.resolve_authoritative_profile_release_candidate(
            request=request,
            paths=capability.ProfileReleaseAuthorityPaths(**paths),
        )
    assert str(captured.value) == "profile release authority bundle is invalid"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-critical-digest",
        "digest-substitution",
        "stale-freeze-parent",
        "candidate-review-parent-mismatch",
        "rights-source-mismatch",
        "mixed-lineage",
        "incomplete-cohort",
        "duplicate-member",
        "swapped-manifest",
    ],
)
def test_hostile_authority_graph_mutations_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    payloads = _bundle_payloads()
    request = _request(payloads)
    if mutation == "missing-critical-digest":
        request.pop("reviewed_manifest_sha256")
    elif mutation == "digest-substitution":
        request["candidate_manifest_sha256"] = _digest("substituted")
    elif mutation == "stale-freeze-parent":
        payloads["candidate_manifest"]["label_freeze_sha256"] = _digest("stale-freeze")
        _rehash_manifest(payloads, "candidate_manifest")
        request["candidate_manifest_sha256"] = payloads["candidate_manifest"]["manifest_sha256"]
    elif mutation == "candidate-review-parent-mismatch":
        payloads["reviewed_manifest"]["candidate_manifest_sha256"] = _digest("other-candidate")
        _rehash_manifest(payloads, "reviewed_manifest")
        request["reviewed_manifest_sha256"] = payloads["reviewed_manifest"]["manifest_sha256"]
    elif mutation == "rights-source-mismatch":
        payloads["rights_manifest"]["source_manifest_sha256"] = _digest("other-source")
        _rehash_manifest(payloads, "rights_manifest")
        request["rights_manifest_sha256"] = payloads["rights_manifest"]["manifest_sha256"]
    elif mutation == "mixed-lineage":
        payloads["rights_manifest"]["dev_lineage_sha256"] = _digest("other-dev")
        _rehash_manifest(payloads, "rights_manifest")
        request["rights_manifest_sha256"] = payloads["rights_manifest"]["manifest_sha256"]
    elif mutation == "incomplete-cohort":
        payloads["reviewed_manifest"]["members"].pop()
        _rehash_manifest(payloads, "reviewed_manifest")
        request["reviewed_manifest_sha256"] = payloads["reviewed_manifest"]["manifest_sha256"]
    elif mutation == "duplicate-member":
        members = payloads["source_manifest"]["members"]
        members[-1] = deepcopy(members[0])
        _rehash_manifest(payloads, "source_manifest")
        request["source_manifest_sha256"] = payloads["source_manifest"]["manifest_sha256"]
    else:
        payloads["source_manifest"], payloads["rights_manifest"] = (
            payloads["rights_manifest"],
            payloads["source_manifest"],
        )

    capability = _capability()
    with pytest.raises(capability.ProfileReleaseAuthorityError) as captured:
        _resolve(tmp_path, payloads, request)
    assert str(captured.value) == "profile release authority bundle is invalid"


@pytest.mark.parametrize("entry_kind", ["symlink", "hardlink", "oversized"])
def test_server_held_reads_are_bounded_and_no_follow(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    payloads = _bundle_payloads()
    paths = _write_bundle(tmp_path, payloads)
    source = paths["source_manifest"]
    replacement = tmp_path / "substituted-source.json"
    if entry_kind == "symlink":
        source.unlink()
        source.symlink_to(replacement)
        replacement.write_bytes(canonical_json_bytes(payloads["source_manifest"]))
    elif entry_kind == "hardlink":
        source.unlink()
        replacement.write_bytes(canonical_json_bytes(payloads["source_manifest"]))
        os.link(replacement, source)
    else:
        source.write_bytes(b"{" + b" " * 2_000_000 + b"}")

    capability = _capability()
    with pytest.raises(capability.ProfileReleaseAuthorityError) as captured:
        capability.resolve_authoritative_profile_release_candidate(
            request=_request(payloads),
            paths=capability.ProfileReleaseAuthorityPaths(**paths),
        )
    assert str(captured.value) == "profile release authority bundle is invalid"


def test_failure_payload_reveals_no_protected_or_private_material(tmp_path: Path) -> None:
    payloads = _bundle_payloads()
    canaries = {
        "membership": "PROTECTED-MEMBERSHIP-CANARY",
        "order": "PROTECTED-ORDER-CANARY",
        "label": "PROTECTED-LABEL-CANARY",
        "evidence": "PROTECTED-EVIDENCE-CANARY",
        "capability": "PROTECTED-CAPABILITY-CANARY",
        "token": "PROTECTED-TOKEN-CANARY",
        "nonce": "PROTECTED-RAW-NONCE-CANARY",
        "dsn": "postgresql://secret-dsn",
        "path": str(tmp_path / "private-authority-root"),
    }
    payloads["source_manifest"]["members"][0]["place_ref"] = canaries["membership"]
    _rehash_manifest(payloads, "source_manifest")
    request = _request(payloads)
    request["source_manifest_sha256"] = payloads["source_manifest"]["manifest_sha256"]
    request["candidate_manifest_sha256"] = _digest("wrong-candidate")
    request.update({f"untrusted_{key}": value for key, value in canaries.items()})

    capability = _capability()
    with pytest.raises(capability.ProfileReleaseAuthorityError) as captured:
        _resolve(tmp_path, payloads, request)
    rendered = f"{captured.value!s} {captured.value!r}"
    assert rendered == (
        "profile release authority bundle is invalid "
        "ProfileReleaseAuthorityError('profile release authority bundle is invalid')"
    )
    assert all(value not in rendered for value in canaries.values())
    assert all(field not in rendered for field in _DIGEST_FIELDS)
