from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from itda.cli.build_catalog_supplemental_evidence import (
    EVIDENCE_FRONTIER_EXHAUSTED,
    NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW,
    build_non_authorizing_identities,
    build_round_envelope,
    decide_successor,
    rank_addressable_candidates,
)
from itda.contracts.catalog_supplemental_evidence import (
    SupplementalEvidenceAtom,
    build_supplemental_atom_set,
    build_supplemental_evidence_atom,
)
from itda.domain.canonical import canonical_sha256

PLACE_ID = f"place:{'1' * 64}"
SOURCE_PATH = "fixtures/preview/v1/review/raw-provider-bundle.redacted.json"


def _dataset_grant(
    *,
    dataset_id: str = "15101578",
    evidence_state: str = "COMPLETE",
    license_type: str = "KOGL_TYPE_1",
    commercial: bool = True,
    transform: bool = True,
    display: bool = True,
    model_input: bool = True,
) -> dict[str, object]:
    fields = {
        "official_dataset_id": dataset_id,
        "official_page_url": f"https://www.data.go.kr/data/{dataset_id}/openapi.do",
        "retrieved_at": "2026-07-30T00:00:00Z",
        "response_sha256": "2" * 64,
        "page_sha256": "3" * 64,
        "evidence_state": evidence_state,
        "license_type": license_type,
        "commercial_use_allowed": commercial,
        "transform_allowed": transform,
        "display_allowed": display,
        "model_input_allowed": model_input,
        "explicit_restrictions": (),
    }
    return {**fields, "dataset_grant_sha256": canonical_sha256(fields)}


def _atom_kwargs(
    *,
    source_kind: str = "OFFICIAL_API_ROW",
    binding_state: str = "EXACT",
    binding_method: str = "EXACT_PROVIDER_RECORD_ID",
    dataset_grant: dict[str, object] | None = None,
    asset_restriction: str | None = None,
    creator: str | None = "한국관광공사",
    source_asset_id: str | None = "asset-123",
    original_url: str | None = "https://tong.visitkorea.or.kr/asset-123.jpg",
) -> dict[str, object]:
    return {
        "place_entity_id": PLACE_ID,
        "source_kind": source_kind,
        "source_owner": "한국관광공사",
        "official_dataset_or_page_id": "15101578",
        "operation_or_page_identity": "detailCommon2",
        "provider_candidate_id": "candidate:tour-api:123",
        "source_record_or_asset_id": source_asset_id,
        "original_url": original_url,
        "retrieved_at": "2026-07-30T00:00:00Z",
        "immutable_relative_path": SOURCE_PATH,
        "raw_or_page_sha256": "4" * 64,
        "value_sha256": "5" * 64,
        "parent_manifest_sha256": "6" * 64,
        "field_name": "korean_description",
        "binding_state": binding_state,
        "binding_method": binding_method,
        "binding_evidence_sha256": "7" * 64,
        "dataset_grant": dataset_grant or _dataset_grant(),
        "asset_provenance": {
            "source_asset_id": source_asset_id,
            "creator_or_photographer": creator,
            "license_type": "KOGL_TYPE_1" if creator is not None else None,
            "attribution_text": "한국관광공사" if creator is not None else None,
            "explicit_asset_restriction": asset_restriction,
            "attachment_rights_granting": False,
        },
    }


def test_exact_fixed_id_and_fully_cleared_rights_can_populate_a_field() -> None:
    atom = build_supplemental_evidence_atom(**_atom_kwargs())

    assert atom.place_entity_id == PLACE_ID
    assert atom.binding_state == "EXACT"
    assert atom.field_state == "POPULATED"
    assert atom.analysis_eligible is True
    assert atom.ui_eligible is True
    assert atom.demo_eligible is True
    assert atom.confidence_adds_score is False
    assert atom.canonical_membership_created is False


@pytest.mark.parametrize(
    "binding_method",
    (
        "NAME_SIMILARITY",
        "PROXIMITY",
        "HIERARCHY",
        "MUTABLE_TITLE",
        "SOURCE_ORDER",
        "REVIEWER_PREFERENCE",
        "QUOTA_NEED",
        "EVIDENCE_VOLUME",
    ),
)
def test_non_exact_binding_inputs_are_review_required_and_never_populate(
    binding_method: str,
) -> None:
    atom = build_supplemental_evidence_atom(
        **_atom_kwargs(
            binding_state="REVIEW_REQUIRED",
            binding_method=binding_method,
        )
    )

    assert atom.field_state == "REVIEW_REQUIRED"
    assert atom.analysis_eligible is False
    assert atom.ui_eligible is False
    assert atom.demo_eligible is False


@pytest.mark.parametrize(
    "grant,restriction,creator,expected_reason",
    (
        (
            _dataset_grant(
                evidence_state="INCOMPLETE",
                commercial=False,
                transform=False,
                display=False,
                model_input=False,
            ),
            None,
            "한국관광공사",
            "DATASET_GRANT_INCOMPLETE",
        ),
        (
            _dataset_grant(license_type="KOGL_TYPE_3", transform=False),
            None,
            "한국관광공사",
            "DATASET_TYPE_3_OR_4_BLOCKED",
        ),
        (
            _dataset_grant(),
            "NO_DERIVATIVES",
            "한국관광공사",
            "EXPLICIT_ASSET_RESTRICTION",
        ),
        (
            _dataset_grant(),
            None,
            None,
            "ASSET_PROVENANCE_INCOMPLETE",
        ),
    ),
)
def test_dataset_and_asset_rights_are_separate_and_narrower_restrictions_win(
    grant: dict[str, object],
    restriction: str | None,
    creator: str | None,
    expected_reason: str,
) -> None:
    atom = build_supplemental_evidence_atom(
        **_atom_kwargs(
            dataset_grant=grant,
            asset_restriction=restriction,
            creator=creator,
        )
    )

    assert atom.field_state == "BLOCKED"
    assert expected_reason in atom.reason_codes
    assert not atom.analysis_eligible
    assert not atom.ui_eligible
    assert not atom.demo_eligible


def test_source_kind_confusion_and_wrong_candidate_binding_fail_closed() -> None:
    with pytest.raises(ValueError, match="source kind"):
        build_supplemental_evidence_atom(
            **_atom_kwargs(source_kind="OFFICIAL_SCRIPT"),
        )

    atom = build_supplemental_evidence_atom(**_atom_kwargs())
    payload = atom.model_dump(mode="json")
    payload["place_entity_id"] = f"place:{'9' * 64}"
    with pytest.raises(ValidationError, match="atom digest|binding"):
        SupplementalEvidenceAtom.model_validate(payload)


def test_atom_set_counts_and_root_are_row_derived_and_duplicates_fail() -> None:
    exact = build_supplemental_evidence_atom(**_atom_kwargs())
    review = build_supplemental_evidence_atom(
        **_atom_kwargs(
            binding_state="REVIEW_REQUIRED",
            binding_method="NAME_SIMILARITY",
            source_asset_id="asset-456",
            original_url="https://tong.visitkorea.or.kr/asset-456.jpg",
        )
    )
    atom_set = build_supplemental_atom_set(
        terminal_aggregate_sha256="8" * 64,
        atoms=(exact, review),
    )

    assert atom_set.atom_count == 2
    assert atom_set.field_state_counts == {
        "POPULATED": 1,
        "MISSING": 0,
        "BLOCKED": 0,
        "REVIEW_REQUIRED": 1,
    }
    assert atom_set.atoms_root == canonical_sha256(
        [row.model_dump(mode="json") for row in atom_set.atoms]
    )

    duplicate = deepcopy(atom_set.model_dump(mode="json"))
    duplicate["atoms"] = [duplicate["atoms"][0], duplicate["atoms"][0]]
    duplicate["atom_count"] = 2
    duplicate["field_state_counts"] = {
        "POPULATED": 2,
        "MISSING": 0,
        "BLOCKED": 0,
        "REVIEW_REQUIRED": 0,
    }
    duplicate["atoms_root"] = canonical_sha256(duplicate["atoms"])
    duplicate["atom_set_sha256"] = canonical_sha256(
        {key: value for key, value in duplicate.items() if key != "atom_set_sha256"}
    )
    with pytest.raises(ValidationError, match="duplicate"):
        type(atom_set).model_validate(duplicate)


def _successor_row(
    ordinal: int,
    *,
    deficits: tuple[str, ...],
    group: str,
    provider_id: str | None = None,
) -> dict[str, object]:
    return {
        "place_entity_id": f"place:{ordinal:064x}",
        "provider_place_candidate_id": (
            provider_id or f"candidate:tour-api:{1000 + ordinal}"
        ),
        "representation_primary_group": group,
        "named_deficits": list(deficits),
    }


def test_reinf15_excludes_complete_ancestry_and_uses_all_sort_keys_and_cap() -> None:
    rows = [
        _successor_row(
            index,
            deficits=("DESCRIPTION_MISSING",) if index % 2 else (
                "DESCRIPTION_MISSING",
                "DIRECT_MEDIA_MISSING",
            ),
            group="HERITAGE" if index % 3 else "REST",
        )
        for index in range(1, 75)
    ]
    attempted_by_round = (
        ("candidate:tour-api:1001",),
        ("candidate:tour-api:1002",),
        ("candidate:tour-api:1003",),
        ("candidate:tour-api:1004",),
        ("candidate:tour-api:1005",),
    )

    ranked = rank_addressable_candidates(
        rows,
        attempted_provider_ids_by_round=attempted_by_round,
        representation_group_need={"HERITAGE": 2, "REST": 9},
    )

    assert len(ranked) == 60
    assert not {
        row["provider_place_candidate_id"] for row in ranked
    }.intersection({item for group in attempted_by_round for item in group})
    assert [
        (
            row["mandatory_deficit_count"],
            -row["representation_group_need"],
            row["place_entity_id"],
        )
        for row in ranked
    ] == sorted(
        (
            row["mandatory_deficit_count"],
            -row["representation_group_need"],
            row["place_entity_id"],
        )
        for row in ranked
    )


def test_reinf15_rejects_nonapproved_or_unmapped_operations() -> None:
    rows = (
        _successor_row(
            1,
            deficits=("DESCRIPTION_MISSING",),
            group="HERITAGE",
        ),
        _successor_row(
            2,
            deficits=("REPRESENTATION_ASSIGNMENT_UNCLASSIFIED",),
            group="REST",
        ),
        _successor_row(
            3,
            deficits=("ODII_PRESENCE_MISSING",),
            group="REST",
        ),
    )

    ranked = rank_addressable_candidates(
        rows,
        attempted_provider_ids_by_round=(),
        representation_group_need={"HERITAGE": 0, "REST": 1},
    )

    assert [row["place_entity_id"] for row in ranked] == [rows[0]["place_entity_id"]]
    assert ranked[0]["approved_operations"] == ["detailCommon2"]


def test_successor_disposition_has_exact_terminal_polarity() -> None:
    addressable = (
        _successor_row(
            1,
            deficits=("DESCRIPTION_MISSING",),
            group="HERITAGE",
        ),
    )
    reentry = decide_successor(
        objective_eligible_count=13,
        human_decisions=6,
        ranked_candidates=rank_addressable_candidates(
            addressable,
            attempted_provider_ids_by_round=(),
            representation_group_need={"HERITAGE": 1},
        ),
    )
    exhausted = decide_successor(
        objective_eligible_count=13,
        human_decisions=6,
        ranked_candidates=(),
    )
    overflow = decide_successor(
        objective_eligible_count=36,
        human_decisions=7,
        ranked_candidates=(),
    )
    addressable_overflow = decide_successor(
        objective_eligible_count=36,
        human_decisions=7,
        ranked_candidates=reentry["successor_candidates"],
    )

    assert reentry["outcome_code"] == 20
    assert reentry["successor_required"] is True
    assert exhausted["outcome_code"] == EVIDENCE_FRONTIER_EXHAUSTED
    assert exhausted["outcome_reason"] == "EVIDENCE_FRONTIER_EXHAUSTED"
    assert overflow["outcome_code"] == NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW
    assert overflow["outcome_reason"] == "NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW"
    assert addressable_overflow["outcome_code"] == 20
    assert addressable_overflow["successor_required"] is True


def test_round_envelope_is_self_excluding_and_fresh_across_supplemental_ancestry() -> None:
    ancestry = [
        {"round_id": f"{index:064x}", "request_sha256": f"{index + 10:064x}"}
        for index in range(1, 7)
    ]
    identities = build_non_authorizing_identities(
        generation_seed="a" * 64,
        ancestry=ancestry,
    )
    payload = {
        "schema_version": "itda.catalog-supplemental-round.v1",
        "code_policy_identity": "b" * 64,
        "ancestry": ancestry,
        "terminal_aggregate": {"aggregate_sha256": "c" * 64},
        "non_authorizing_identities": identities,
        "generation_state": "SUCCESS",
        "successor_disposition": {
            "outcome_code": EVIDENCE_FRONTIER_EXHAUSTED,
            "outcome_reason": "EVIDENCE_FRONTIER_EXHAUSTED",
        },
        "children": [],
    }

    envelope = build_round_envelope(payload)

    assert tuple(envelope) == ("payload", "root_sha256", "round_id")
    assert envelope["root_sha256"] == canonical_sha256(payload)
    assert envelope["round_id"] == envelope["root_sha256"]
    assert not {
        "root_sha256",
        "round_id",
        "round_root",
        "manifest_sha256",
        "final_path",
    }.intersection(payload)
    prior_hashes = {
        value
        for row in ancestry
        for value in row.values()
        if isinstance(value, str) and len(value) == 64
    }
    assert not prior_hashes.intersection(identities.values())
