from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.cli.build_catalog_supplemental_evidence import (
    build_round_envelope,
    publish_immutable_generation,
    verify_round_envelope,
)
from itda.contracts.catalog_supplemental_evidence import (
    SupplementalEvidenceAtom,
    build_supplemental_evidence_atom,
)
from itda.domain.canonical import canonical_sha256


def _valid_atom() -> SupplementalEvidenceAtom:
    grant_fields = {
        "official_dataset_id": "15101578",
        "official_page_url": "https://www.data.go.kr/data/15101578/openapi.do",
        "retrieved_at": "2026-07-30T00:00:00Z",
        "response_sha256": "1" * 64,
        "page_sha256": "2" * 64,
        "evidence_state": "COMPLETE",
        "license_type": "KOGL_TYPE_1",
        "commercial_use_allowed": True,
        "transform_allowed": True,
        "display_allowed": True,
        "model_input_allowed": True,
        "explicit_restrictions": (),
    }
    grant = {
        **grant_fields,
        "dataset_grant_sha256": canonical_sha256(grant_fields),
    }
    return build_supplemental_evidence_atom(
        place_entity_id=f"place:{'3' * 64}",
        source_kind="OFFICIAL_PAGE",
        source_owner="경주시",
        official_dataset_or_page_id="gyeongju-tour-page-1015",
        operation_or_page_identity="page:1015",
        provider_candidate_id=None,
        source_record_or_asset_id="page-1015",
        original_url="https://www.gyeongju.go.kr/tour/page.do?area_uid=252",
        retrieved_at="2026-07-30T00:00:00Z",
        immutable_relative_path="fixtures/preview/v1/manifest.json",
        raw_or_page_sha256="4" * 64,
        value_sha256="5" * 64,
        parent_manifest_sha256="6" * 64,
        field_name="korean_description",
        binding_state="EXACT",
        binding_method="EXACT_OFFICIAL_PAGE_ID",
        binding_evidence_sha256="7" * 64,
        dataset_grant=grant,
        asset_provenance={
            "source_asset_id": "page-1015",
            "creator_or_photographer": "경주시",
            "license_type": "KOGL_TYPE_1",
            "attribution_text": "경주시",
            "explicit_asset_restriction": None,
            "attachment_rights_granting": False,
        },
    )


@pytest.mark.parametrize(
    "forbidden_field",
    (
        "canonical_members",
        "ordered_catalog_ids",
        "dev_members",
        "blind_members",
        "split_membership",
        "catalog_approval",
        "activation_state",
        "seal_manifest",
        "raw_response_body",
        "permission_page_body",
        "service_key",
        "credential",
        "authority_token",
        "authority_receipt",
        "nonce",
        "confidence_score",
        "popularity_score",
        "data_volume_score",
        "quota_pressure_score",
        "ranking_score",
        "selection_score",
    ),
)
def test_forbidden_membership_secret_raw_and_score_fields_are_rejected(
    forbidden_field: str,
) -> None:
    payload = _valid_atom().model_dump(mode="json")
    payload[forbidden_field] = "forbidden"
    with pytest.raises(ValidationError, match="extra"):
        SupplementalEvidenceAtom.model_validate(payload)


@pytest.mark.parametrize(
    "relative_path",
    (
        "../escape.json",
        "/absolute/path.json",
        "fixtures/preview/v1/../../escape.json",
        "https://example.com/not-a-local-path",
    ),
)
def test_historical_evidence_path_is_relative_and_cannot_escape(
    relative_path: str,
) -> None:
    payload = _valid_atom().model_dump(mode="json")
    payload["immutable_relative_path"] = relative_path
    payload["atom_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "atom_sha256"}
    )
    with pytest.raises(ValidationError, match="path"):
        SupplementalEvidenceAtom.model_validate(payload)


def test_canonical_membership_and_attachment_rights_cannot_be_enabled() -> None:
    payload = _valid_atom().model_dump(mode="json")
    payload["canonical_membership_created"] = True
    payload["atom_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "atom_sha256"}
    )
    with pytest.raises(ValidationError):
        SupplementalEvidenceAtom.model_validate(payload)


def test_round_envelope_rejects_every_self_alias_and_authority_field() -> None:
    base = {
        "schema_version": "itda.catalog-supplemental-round.v1",
        "code_policy_identity": "1" * 64,
        "ancestry": [],
        "terminal_aggregate": {"aggregate_sha256": "2" * 64},
        "non_authorizing_identities": {
            "request_sha256": "3" * 64,
            "state_attestation_sha256": "4" * 64,
            "target_sha256": "5" * 64,
            "binding_sha256": "6" * 64,
            "nonce_sha256": "7" * 64,
        },
        "generation_state": "SUCCESS",
        "successor_disposition": {
            "outcome_code": 21,
            "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
        },
        "children": [],
    }
    for forbidden in (
        "root_sha256",
        "round_id",
        "round_root",
        "manifest_sha256",
        "final_path",
        "directory_basename",
        "authority_token",
        "authority_receipt",
        "credential",
        "service_key",
    ):
        with pytest.raises(ValueError, match="forbidden"):
            build_round_envelope({**base, forbidden: "8" * 64})


def test_publication_is_mode_pinned_no_replace_and_live_verified(tmp_path) -> None:
    children = {
        "prior-lineage-attestation.json": b'{"ok":true}',
        "supplemental-target-ledger.json": b'{"rows":[]}',
        "supplemental-evidence-atoms.json": b'{"atoms":[]}',
        "supplemental-evidence-manifest.json": b'{"children":[]}',
    }
    child_rows = [
        {
            "relpath": name,
            "entry_type": "REGULAR_FILE",
            "mode": "0600",
            "size": len(payload),
            "file_sha256": __import__("hashlib").sha256(payload).hexdigest(),
        }
        for name, payload in children.items()
    ]
    envelope = build_round_envelope(
        {
            "schema_version": "itda.catalog-supplemental-round.v1",
            "code_policy_identity": "1" * 64,
            "ancestry": [],
            "terminal_aggregate": {"aggregate_sha256": "2" * 64},
            "non_authorizing_identities": {
                "request_sha256": "3" * 64,
                "state_attestation_sha256": "4" * 64,
                "target_sha256": "5" * 64,
                "binding_sha256": "6" * 64,
                "nonce_sha256": "7" * 64,
            },
            "generation_state": "SUCCESS",
            "successor_disposition": {
                "outcome_code": 21,
                "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
            },
            "children": child_rows,
        }
    )
    destination = tmp_path / envelope["round_id"]

    publish_immutable_generation(
        destination=destination,
        round_id=envelope["round_id"],
        children=children,
        envelope=envelope,
    )

    assert destination.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in destination.iterdir())
    assert verify_round_envelope(destination) == envelope
    with pytest.raises(FileExistsError):
        publish_immutable_generation(
            destination=destination,
            round_id=envelope["round_id"],
            children=children,
            envelope=envelope,
        )
    assert verify_round_envelope(destination) == envelope


def test_publication_rejects_basename_substitution_and_symlink_parent(tmp_path) -> None:
    envelope = build_round_envelope(
        {
            "schema_version": "itda.catalog-supplemental-round.v1",
            "code_policy_identity": "1" * 64,
            "ancestry": [],
            "terminal_aggregate": {"aggregate_sha256": "2" * 64},
            "non_authorizing_identities": {
                "request_sha256": "3" * 64,
                "state_attestation_sha256": "4" * 64,
                "target_sha256": "5" * 64,
                "binding_sha256": "6" * 64,
                "nonce_sha256": "7" * 64,
            },
            "generation_state": "SUCCESS",
            "successor_disposition": {
                "outcome_code": 21,
                "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
            },
            "children": [],
        }
    )
    with pytest.raises(ValueError, match="basename"):
        publish_immutable_generation(
            destination=tmp_path / ("f" * 64),
            round_id=envelope["round_id"],
            children={},
            envelope=envelope,
        )

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        publish_immutable_generation(
            destination=linked_parent / envelope["round_id"],
            round_id=envelope["round_id"],
            children={},
            envelope=envelope,
        )

    payload = deepcopy(_valid_atom().model_dump(mode="json"))
    payload["asset_provenance"]["attachment_rights_granting"] = True
    payload["atom_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "atom_sha256"}
    )
    with pytest.raises(ValidationError):
        SupplementalEvidenceAtom.model_validate(payload)
