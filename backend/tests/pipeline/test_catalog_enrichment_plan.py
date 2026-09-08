from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from itda.cli.plan_catalog_enrichment import _parser
from itda.contracts.catalog_enrichment import (
    KOR_SERVICE2_PARAMETER_ALLOWLISTS,
    KOR_SERVICE2_SCHEMA_SOURCE,
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    build_enrichment_plan,
    canonical_json_bytes,
    publish_enrichment_bundle,
    validate_round_pair,
    verify_authorization_preconditions,
    verify_enrichment_bundle,
)

POOL_PATH = (
    Path(__file__).parents[3]
    / "artifacts/restricted/catalog/v2/enrichment/enrichment-candidate-pool.json"
)
HEX_A = "a" * 64
IMMUTABLE_ROUND_IDS = (
    "a59fabf3371845fbacb4e32510b178b03d7a784d0becfea6edfd7f7b2e4f2c25",
    "8d8742ca9a7f5b9e29fb76f842271d6bf242d806db07b819c761f9d7d0f456c8",
    "f53bd3a2abff43f551af1b15ad74d99f801ef1fd2b92cd0306b714139dfa2711",
)


def _pool() -> dict[str, object]:
    return json.loads(POOL_PATH.read_text(encoding="utf-8"))


def _frozen(plan: dict[str, object]) -> FrozenEnrichmentIssuance:
    issued_at = datetime(2026, 7, 29, tzinfo=UTC)
    return FrozenEnrichmentIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        nonce="1" * 64,
        reviewer_id="phase2-operator",
        code_sha256="2" * 64,
        config_sha256="3" * 64,
        permission_evidence_sha256=sha256(
            canonical_json_bytes(plan["permission_evidence"])
        ).hexdigest(),
        previous_round_ref_sha256=None,
    )


def test_exact_pool_expands_to_only_three_approved_operations() -> None:
    plan = build_enrichment_plan(_pool(), attempts=3)

    assert plan["schema_version"] == "itda.catalog-enrichment-plan.v2"
    assert plan["candidate_count"] == 60
    assert plan["request_count"] == 180
    assert plan["quota_estimate"] == 540
    assert plan["per_attempt_timeout_seconds"] == 300
    assert plan["overall_timeout_seconds"] == 180 * 3 * 300
    assert {request["operation"] for request in plan["requests"]} == {
        "detailCommon2",
        "detailIntro2",
        "detailImage2",
    }
    assert len({request["request_identity"] for request in plan["requests"]}) == 180
    assert all("serviceKey" not in request["parameters"] for request in plan["requests"])
    assert all("api_key" not in request["parameters"] for request in plan["requests"])


def test_endpoint_parameters_match_korservice2_fixed_contract() -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)

    parameter_keys = {
        request["operation"]: set(request["parameters"]) for request in plan["requests"][:3]
    }

    assert parameter_keys == {
        "detailCommon2": {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "numOfRows",
            "pageNo",
        },
        "detailIntro2": {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "contentTypeId",
            "numOfRows",
            "pageNo",
        },
        "detailImage2": {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "imageYN",
            "numOfRows",
            "pageNo",
        },
    }


def test_official_korservice2_endpoint_allowlists_are_complete() -> None:
    assert KOR_SERVICE2_SCHEMA_SOURCE == ("https://www.data.go.kr/data/15101578/openapi.do")
    assert {
        "detailCommon2": frozenset(
            {
                "MobileOS",
                "MobileApp",
                "_type",
                "contentId",
                "numOfRows",
                "pageNo",
                "serviceKey",
            }
        ),
        "detailIntro2": frozenset(
            {
                "MobileOS",
                "MobileApp",
                "_type",
                "contentId",
                "contentTypeId",
                "numOfRows",
                "pageNo",
                "serviceKey",
            }
        ),
        "detailImage2": frozenset(
            {
                "MobileOS",
                "MobileApp",
                "_type",
                "contentId",
                "imageYN",
                "numOfRows",
                "pageNo",
                "serviceKey",
            }
        ),
    } == KOR_SERVICE2_PARAMETER_ALLOWLISTS


def test_immutable_v1_rounds_remain_verifiable_as_historical_evidence() -> None:
    rounds_root = Path(__file__).parents[3] / "artifacts/restricted/catalog/v2/enrichment/rounds"

    for round_id in IMMUTABLE_ROUND_IDS:
        root = rounds_root / round_id
        verify_enrichment_bundle(
            root / "enrichment-plan.json",
            root / "enrichment-state-attestation.json",
            root / "enrichment-authorization-request.json",
            round_root=root,
            round_id=round_id,
        )


def test_new_bundle_issuance_rejects_legacy_v1_plan_even_with_valid_digest(
    tmp_path: Path,
) -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)
    plan["schema_version"] = "itda.catalog-enrichment-plan.v1"
    plan_bytes = canonical_json_bytes(plan)
    round_id = sha256(plan_bytes).hexdigest()

    with pytest.raises(ValueError, match="current plan schema"):
        build_enrichment_bundle(
            plan=plan,
            round_root=tmp_path / "rounds" / round_id,
            round_id=round_id,
            frozen=_frozen(plan),
        )


@pytest.mark.parametrize(
    ("operation", "forbidden_parameter"),
    [
        ("detailCommon2", "contentTypeId"),
        ("detailCommon2", "defaultYN"),
        ("detailCommon2", "firstImageYN"),
        ("detailCommon2", "areacodeYN"),
        ("detailCommon2", "catcodeYN"),
        ("detailCommon2", "addrinfoYN"),
        ("detailCommon2", "mapinfoYN"),
        ("detailCommon2", "overviewYN"),
        ("detailImage2", "subImageYN"),
    ],
)
def test_current_korservice2_schema_rejects_retired_selectors_after_redigest(
    tmp_path: Path,
    operation: str,
    forbidden_parameter: str,
) -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)
    request = next(item for item in plan["requests"] if item["operation"] == operation)
    request["parameters"][forbidden_parameter] = "Y"
    unsigned = dict(request)
    unsigned.pop("request_identity")
    request["request_identity"] = sha256(canonical_json_bytes(unsigned)).hexdigest()
    plan_bytes = canonical_json_bytes(plan)
    round_id = sha256(plan_bytes).hexdigest()

    with pytest.raises(ValueError, match="parameters"):
        build_enrichment_bundle(
            plan=plan,
            round_root=tmp_path / "rounds" / round_id,
            round_id=round_id,
            frozen=_frozen(plan),
        )


def test_remediation_pool_allows_one_to_sixty_without_loosening_initial_round() -> None:
    pool = _pool()
    pool["rows"] = list(pool["rows"])[:16]
    pool["ordered_pool_ids"] = list(pool["ordered_pool_ids"])[:16]
    pool["pool_count"] = 16
    pool["schema_version"] = "enrichment-remediation-candidate-pool-v1"
    for row in pool["rows"]:
        row["missing_operations"] = ["detailCommon2", "detailImage2"]

    remediation = {
        "previous_round_ref": {
            "round_id": HEX_A,
            "round_root": f"artifacts/restricted/catalog/v2/enrichment/rounds/{HEX_A}",
            "round_manifest_sha256": "b" * 64,
            "ancestry_depth": 1,
        },
        "exact_deficits_sha256": "c" * 64,
    }
    plan = build_enrichment_plan(
        pool,
        attempts=3,
        remediation=remediation,
    )

    assert plan["candidate_count"] == 16
    assert plan["request_count"] == 32
    assert plan["quota_estimate"] == 96
    assert [request["operation"] for request in plan["requests"][:2]] == [
        "detailCommon2",
        "detailImage2",
    ]
    assert plan["remediation"] == remediation

    initial_pool = _pool()
    initial_pool["rows"] = list(initial_pool["rows"])[:16]
    initial_pool["ordered_pool_ids"] = list(initial_pool["ordered_pool_ids"])[:16]
    initial_pool["pool_count"] = 16
    with pytest.raises(ValueError, match="exactly 60"):
        build_enrichment_plan(initial_pool, attempts=3)


@pytest.mark.parametrize("candidate_count", [0, 61])
def test_remediation_pool_retains_hard_one_to_sixty_bound(
    candidate_count: int,
) -> None:
    pool = _pool()
    pool["schema_version"] = "enrichment-remediation-candidate-pool-v1"
    if candidate_count == 0:
        rows: list[object] = []
        identities: list[object] = []
    else:
        rows = list(pool["rows"]) + [dict(pool["rows"][0])]
        rows[-1]["provider_candidate_id"] = "candidate:tour-api:9999999"
        identities = list(pool["ordered_pool_ids"]) + ["candidate:tour-api:9999999"]
    pool["rows"] = rows
    pool["ordered_pool_ids"] = identities
    pool["pool_count"] = candidate_count
    with pytest.raises(ValueError, match="between 1 and 60"):
        build_enrichment_plan(
            pool,
            attempts=3,
            remediation={"previous_round_ref": {"round_id": HEX_A}},
        )


def test_mandatory_fields_map_only_to_approved_detail_operations() -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)
    mappings = {
        request["operation"]: tuple(request["mapped_mandatory_fields"])
        for request in plan["requests"][:3]
    }

    assert mappings == {
        "detailCommon2": ("coordinates", "korean_description"),
        "detailIntro2": ("provider_specific_operating_information",),
        "detailImage2": ("exact_provider_direct_media",),
    }
    assert all(request["parameters"]["contentId"].isdigit() for request in plan["requests"])
    assert all(
        (
            request["parameters"].get("contentTypeId") is None
            if request["operation"] != "detailIntro2"
            else request["parameters"].get("contentTypeId") == "12"
        )
        for request in plan["requests"]
    )


@pytest.mark.parametrize("attempts", [0, 6])
def test_attempts_are_bounded(attempts: int) -> None:
    with pytest.raises(ValueError, match="attempts"):
        build_enrichment_plan(_pool(), attempts=attempts)


def test_pool_and_request_allowlists_fail_closed() -> None:
    pool = _pool()
    pool["rows"] = list(pool["rows"])[:-1]
    with pytest.raises(ValueError, match="exactly 60"):
        build_enrichment_plan(pool, attempts=1)

    pool = _pool()
    pool["ordered_pool_ids"] = list(pool["ordered_pool_ids"])
    pool["ordered_pool_ids"][0] = "candidate:other:2603509"
    with pytest.raises(ValueError, match="TourAPI"):
        build_enrichment_plan(pool, attempts=1)


def test_canonical_plan_is_self_reference_free_and_addresses_round() -> None:
    plan_bytes = canonical_json_bytes(build_enrichment_plan(_pool(), attempts=2))
    round_id = sha256(plan_bytes).hexdigest()
    round_root = Path("artifacts/restricted/catalog/v2/enrichment/rounds") / round_id

    assert b"round_id" not in plan_bytes
    assert b"round_root" not in plan_bytes
    assert (
        validate_round_pair(round_root, round_id, plan_bytes)
        .as_posix()
        .endswith(f"/rounds/{round_id}")
    )
    with pytest.raises(ValueError, match="basename"):
        validate_round_pair(round_root.parent / HEX_A, round_id, plan_bytes)
    with pytest.raises(ValueError, match="digest"):
        validate_round_pair(round_root.parent / HEX_A, HEX_A, plan_bytes)


def test_every_cli_mode_requires_explicit_round_root_and_id() -> None:
    parser = _parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--publish"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--round-root", "/tmp/example", "--publish"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--round-id", HEX_A, "--publish"])


def test_frozen_issuance_builds_identical_parent_bound_bundle(tmp_path: Path) -> None:
    plan = build_enrichment_plan(_pool(), attempts=2)
    plan_bytes = canonical_json_bytes(plan)
    round_id = sha256(plan_bytes).hexdigest()
    root = tmp_path / "rounds" / round_id

    first = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=_frozen(plan),
    )
    second = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=_frozen(plan),
    )

    assert first == second
    assert first.authorization_request["action"] == "enrichment-collect"
    assert first.authorization_request["request_sha256"] == round_id
    assert first.authorization_request["target_sha256"] == round_id
    assert (
        first.authorization_request["state_attestation_sha256"]
        == sha256(first.state_bytes).hexdigest()
    )
    assert first.authorization_request["authority_token_issued"] is False
    serialized = b"".join(first.files.values())
    assert b"serviceKey" not in serialized
    assert b"itda-auth-v2:" not in serialized


def test_remediation_round_requires_fresh_parent_bound_inputs(tmp_path: Path) -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)
    plan["remediation"] = {"failed_request_identity": HEX_A}
    plan_bytes = canonical_json_bytes(plan)
    round_id = sha256(plan_bytes).hexdigest()
    root = tmp_path / "rounds" / round_id

    with pytest.raises(ValueError, match="previous-round"):
        build_enrichment_bundle(
            plan=plan,
            round_root=root,
            round_id=round_id,
            frozen=_frozen(plan),
        )

    frozen = FrozenEnrichmentIssuance(
        **{
            **_frozen(plan).__dict__,
            "nonce": "5" * 64,
            "previous_round_ref_sha256": "6" * 64,
        }
    )
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=frozen,
    )
    assert bundle.state_attestation["previous_round_ref_sha256"] == "6" * 64
    assert bundle.authorization_request["nonce"] == "5" * 64


def test_publication_is_exclusive_and_replay_preserves_bytes(tmp_path: Path) -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)
    plan_bytes = canonical_json_bytes(plan)
    round_id = sha256(plan_bytes).hexdigest()
    root = tmp_path / "rounds" / round_id
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=_frozen(plan),
    )

    reference_path = tmp_path / "initial-round-ref.json"
    publish_enrichment_bundle(bundle, initial_reference_path=reference_path)
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*.json")}
    with pytest.raises(FileExistsError):
        publish_enrichment_bundle(bundle, initial_reference_path=reference_path)
    after = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob("*.json")}
    assert after == before


def test_bundle_check_and_authorization_preconditions_fail_on_drift(
    tmp_path: Path,
) -> None:
    plan = build_enrichment_plan(_pool(), attempts=1)
    plan_bytes = canonical_json_bytes(plan)
    round_id = sha256(plan_bytes).hexdigest()
    root = tmp_path / "rounds" / round_id
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=_frozen(plan),
    )
    publish_enrichment_bundle(
        bundle,
        initial_reference_path=tmp_path / "initial-round-ref.json",
    )

    verify_enrichment_bundle(
        root / "enrichment-plan.json",
        root / "enrichment-state-attestation.json",
        root / "enrichment-authorization-request.json",
        round_root=root,
        round_id=round_id,
    )
    verify_authorization_preconditions(
        root / "enrichment-authorization-request.json",
        round_root=root,
        round_id=round_id,
        now=datetime(2026, 7, 29, 1, tzinfo=UTC),
    )

    state_path = root / "enrichment-state-attestation.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["raw_outputs_absent"] = False
    state_path.write_bytes(canonical_json_bytes(state))
    with pytest.raises(ValueError, match="state attestation"):
        verify_authorization_preconditions(
            root / "enrichment-authorization-request.json",
            round_root=root,
            round_id=round_id,
            now=datetime(2026, 7, 29, 1, tzinfo=UTC),
        )
