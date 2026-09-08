from __future__ import annotations

from pathlib import Path

import pytest

from itda.cli.plan_catalog_kto_recovery import (
    build_kto_eligibility_generation,
    build_policy_decision_receipt,
    build_traffic_free_preflight,
    discover_exact_kto_eligibility_success,
    publish_kto_eligibility_generation,
    publish_policy_decision_receipt,
    verify_kto_eligibility_root,
    verify_policy_decision_receipt,
)
from itda.contracts.catalog_enrichment import (
    KOR_SERVICE2_BASE_URL,
    KTO_OFFICIAL_CONTRACT_PINS,
    build_kto_recovery_request,
)

REPOSITORY_ROOT = Path(__file__).parents[3]
DECISION_ROOT = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/decisions"
    / "d14f733655b846b08f2f058bd05ac0615956f8c8124524f45fc0e52b34f17084"
)


def test_official_kto_contract_and_operation_grammars_are_exact() -> None:
    assert KOR_SERVICE2_BASE_URL == "https://apis.data.go.kr/B551011/KorService2"
    assert KTO_OFFICIAL_CONTRACT_PINS == {
        "dataset_page_modified_date": "2026-02-26",
        "swagger_sha256": ("da0c6611c711ca838bb24b8f57396a81dfa773f01a494faaa6b97b87531a2cd5"),
        "manual_zip_sha256": ("d1ad707f83d1ab42c9d7a0aeb959a84fe5407e71e1f46c95cc27bb7da914e54a"),
        "manual_docx_sha256": ("c6a28a0404f9f108ccc366b1875b3779d8d98c60156581eedaf7a5c046abfc58"),
        "manual_revision_date": "2026-02-10",
    }

    common = build_kto_recovery_request(
        operation="detailCommon2",
        provider_candidate_id="candidate:tour-api:123",
        place_entity_id="place:" + "a" * 64,
        source_candidate_row_sha256="b" * 64,
    )
    image = build_kto_recovery_request(
        operation="detailImage2",
        provider_candidate_id="candidate:tour-api:123",
        place_entity_id="place:" + "a" * 64,
        source_candidate_row_sha256="b" * 64,
    )
    intro = build_kto_recovery_request(
        operation="detailIntro2",
        provider_candidate_id="candidate:tour-api:123",
        place_entity_id="place:" + "a" * 64,
        source_candidate_row_sha256="b" * 64,
        actual_content_type_id="14",
        bound_actual_content_type_id="14",
    )

    assert set(common["parameters"]) == {
        "MobileOS",
        "MobileApp",
        "_type",
        "contentId",
        "numOfRows",
        "pageNo",
    }
    assert set(image["parameters"]) == {
        "MobileOS",
        "MobileApp",
        "_type",
        "contentId",
        "imageYN",
        "numOfRows",
        "pageNo",
    }
    assert image["parameters"]["imageYN"] == "Y"
    assert intro["parameters"]["contentTypeId"] == "14"
    assert "serviceKey" not in str((common, image, intro))


@pytest.mark.parametrize(
    ("operation", "actual_content_type_id", "message"),
    [
        ("detailCommon2", "14", "must not accept contentTypeId"),
        ("detailImage2", "14", "must not accept contentTypeId"),
        ("detailIntro2", None, "requires actual_content_type_id"),
        ("detailIntro2", "12", "does not match the bound actual KTO type"),
    ],
)
def test_kto_request_builder_rejects_wrong_or_unbound_content_types(
    operation: str,
    actual_content_type_id: str | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_kto_recovery_request(
            operation=operation,
            provider_candidate_id="candidate:tour-api:3486762",
            place_entity_id=(
                "place:37e3729256a2f1a01ab40b5cbf6b4017f13fbeb2cfa789e3b5683418a3a34cab"
            ),
            source_candidate_row_sha256="b" * 64,
            actual_content_type_id=actual_content_type_id,
            bound_actual_content_type_id="14",
        )


def test_kto_intro_request_rejects_caller_selected_unbound_type() -> None:
    with pytest.raises(ValueError, match="requires a bound actual KTO type"):
        build_kto_recovery_request(
            operation="detailIntro2",
            provider_candidate_id="candidate:tour-api:3486762",
            place_entity_id=(
                "place:37e3729256a2f1a01ab40b5cbf6b4017f13fbeb2cfa789e3b5683418a3a34cab"
            ),
            source_candidate_row_sha256="b" * 64,
            actual_content_type_id="14",
        )


def test_preflight_rederives_exact_recovery_frontier_and_substitutions() -> None:
    packet = build_traffic_free_preflight(REPOSITORY_ROOT)

    assert packet["target_count"] == 24
    assert packet["common_image_correction_count"] == 42
    assert packet["typed_intro_deficit_count"] == 3
    assert [
        (row["provider_candidate_id"], row["name_ko"], row["actual_content_type_id"])
        for row in packet["typed_intro_deficits"]
    ] == [
        ("candidate:tour-api:3486762", "오아르미술관", "14"),
        ("candidate:tour-api:3056660", "바니베어 뮤지엄", "14"),
        ("candidate:tour-api:3032546", "경주루지월드", "28"),
    ]
    assert all(
        row["predecessor"]["provider_result_code"] == "0000"
        and row["predecessor"]["deficit_reason"] == "SUCCESS_RESPONSE_FIELD_EMPTY"
        and row["reinforcement_18_eligibility"] == "INELIGIBLE"
        and row["semantic_successor_eligibility"] == "INELIGIBLE"
        for row in packet["typed_intro_deficits"]
    )
    assert [
        (row["provider_candidate_id"], row["name_ko"], row["operations"])
        for row in packet["proposed_substitutions"]
    ] == [
        (
            "candidate:tour-api:127487",
            "경주엑스포대공원",
            ["detailCommon2", "detailImage2"],
        ),
        (
            "candidate:tour-api:2603463",
            "경주 동궁원",
            ["detailCommon2", "detailImage2"],
        ),
        (
            "candidate:tour-api:1959160",
            "장산서원",
            ["detailCommon2", "detailImage2"],
        ),
    ]
    assert packet["request_count_if_substitution_approved"] == 48
    assert packet["side_effects"] == {
        "network": False,
        "credential_read": False,
        "authority_issued_or_consumed": False,
        "nonce_created_or_consumed": False,
        "canonical_or_split_mutation": False,
    }


def test_preflight_is_byte_deterministic() -> None:
    assert build_traffic_free_preflight(REPOSITORY_ROOT) == build_traffic_free_preflight(
        REPOSITORY_ROOT
    )


def test_policy_decision_receipt_is_exact_private_and_replayable(
    tmp_path: Path,
) -> None:
    preflight = build_traffic_free_preflight(REPOSITORY_ROOT)
    receipt = build_policy_decision_receipt(
        preflight,
        selected_policy="require-kto-substitution",
        reviewer_id="phase2-operator",
        rationale="REINF-18을 유지하면서 KTO 공식 데이터만으로 결손을 보강",
    )

    assert receipt == {
        "actual_type_evidence_root": (
            "e1bf88c869fa9c506684fba502420af790979d0e9d2db26acd03748fb8037492"
        ),
        "kto_allowlist_revision_sha256": preflight["kto_allowlist_revision_sha256"],
        "kto_contract_sha256": preflight["kto_contract_sha256"],
        "kto_substitution_set_sha256": preflight["kto_substitution_set_sha256"],
        "policy_version": "itda.typed-intro-substitution.v1",
        "rationale": "REINF-18을 유지하면서 KTO 공식 데이터만으로 결손을 보강",
        "reviewer_id": "phase2-operator",
        "selected_policy": "require-kto-substitution",
        "typed_intro_predecessor_root": (
            "0c60d5ed90b8165bac84421aa1421ecf500393cf5bfdb2d0060f507e2cad5f85"
        ),
        "unresolved_intro_target_root": preflight["unresolved_intro_target_root"],
    }

    root = publish_policy_decision_receipt(
        repository_root=REPOSITORY_ROOT,
        selected_policy="require-kto-substitution",
        reviewer_id="phase2-operator",
        rationale="REINF-18을 유지하면서 KTO 공식 데이터만으로 결손을 보강",
        output_base=tmp_path / "decisions",
    )

    assert root.name == ("d14f733655b846b08f2f058bd05ac0615956f8c8124524f45fc0e52b34f17084")
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "policy-decision.json").stat().st_mode & 0o777 == 0o600
    assert verify_policy_decision_receipt(REPOSITORY_ROOT, root) == receipt
    with pytest.raises(FileExistsError, match="immutable"):
        publish_policy_decision_receipt(
            repository_root=REPOSITORY_ROOT,
            selected_policy="require-kto-substitution",
            reviewer_id="phase2-operator",
            rationale="REINF-18을 유지하면서 KTO 공식 데이터만으로 결손을 보강",
            output_base=tmp_path / "decisions",
        )


def test_decision_bound_eligibility_generation_is_exact_and_deterministic() -> None:
    first = build_kto_eligibility_generation(REPOSITORY_ROOT, DECISION_ROOT)
    second = build_kto_eligibility_generation(REPOSITORY_ROOT, DECISION_ROOT)

    assert first == second
    assert set(first.files) == {
        "contract-pins.json",
        "operation-allowlists.json",
        "eligibility.json",
        "policy-decision-ref.json",
        "request-manifest.json",
        "root-manifest.json",
    }
    request_manifest = first.json_value("request-manifest.json")
    eligibility = first.json_value("eligibility.json")
    root_manifest = first.json_value("root-manifest.json")
    requests = request_manifest["requests"]

    assert request_manifest["request_count"] == 48
    assert sum(row["operation"] == "detailCommon2" for row in requests) == 24
    assert sum(row["operation"] == "detailImage2" for row in requests) == 24
    assert all(row["operation"] != "detailIntro2" for row in requests)
    assert {
        row["provider_candidate_id"]
        for row in requests
        if row["provider_candidate_id"]
        in {
            "candidate:tour-api:127487",
            "candidate:tour-api:2603463",
            "candidate:tour-api:1959160",
        }
    } == {
        "candidate:tour-api:127487",
        "candidate:tour-api:2603463",
        "candidate:tour-api:1959160",
    }
    assert eligibility["common_image_correction_count"] == 42
    assert eligibility["substitute_request_count"] == 6
    assert eligibility["request_count"] == 48
    assert eligibility["typed_intro_policy"] == "PERMANENTLY_INELIGIBLE"
    assert eligibility["plan48_reachable"] is True
    assert root_manifest["payload"]["plan48_reachable"] is True
    assert root_manifest["root_sha256"] == first.root_sha256


def test_eligibility_publication_is_private_no_replace_and_discoverable(
    tmp_path: Path,
) -> None:
    output_base = tmp_path / "eligibility"
    generation = build_kto_eligibility_generation(REPOSITORY_ROOT, DECISION_ROOT)
    published = publish_kto_eligibility_generation(
        generation,
        repository_root=REPOSITORY_ROOT,
        decision_receipt_root=DECISION_ROOT,
        output_base=output_base,
    )

    assert published.name == generation.root_sha256
    assert published.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in published.iterdir())
    verified = verify_kto_eligibility_root(
        REPOSITORY_ROOT,
        published,
        decision_receipt_root=DECISION_ROOT,
    )
    assert verified.root_sha256 == generation.root_sha256
    assert (
        discover_exact_kto_eligibility_success(
            REPOSITORY_ROOT,
            output_base,
            decision_receipt_root=DECISION_ROOT,
        )
        == published
    )
    with pytest.raises(FileExistsError, match="immutable"):
        publish_kto_eligibility_generation(
            generation,
            repository_root=REPOSITORY_ROOT,
            decision_receipt_root=DECISION_ROOT,
            output_base=output_base,
        )
