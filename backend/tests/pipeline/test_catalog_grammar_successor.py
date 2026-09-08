from __future__ import annotations

import copy
import hashlib
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import itda.contracts.catalog_grammar_successor as grammar_contract
from itda.cli.collect_catalog_enrichment import verify_authorization_preconditions
from itda.cli.plan_catalog_grammar_successor import main as grammar_successor_main
from itda.contracts.catalog_enrichment import (
    KOR_SERVICE2_PARAMETER_ALLOWLISTS,
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    canonical_json_bytes,
    verify_enrichment_bundle,
)
from itda.contracts.catalog_grammar_successor import (
    GrammarCorrectionSuccessor,
    GrammarSuccessorIssuance,
    build_grammar_correction_successor,
    build_grammar_correction_supersession,
    classify_terminal_grammar_failure,
    publish_grammar_correction_successor,
    publish_grammar_correction_supersession,
    verify_published_grammar_correction_successor,
    verify_published_grammar_correction_supersession,
)

REPO_ROOT = Path(__file__).parents[3]
ROUNDS_ROOT = REPO_ROOT / "artifacts/restricted/catalog/v2/enrichment/rounds"
F53_ID = "f53bd3a2abff43f551af1b15ad74d99f801ef1fd2b92cd0306b714139dfa2711"
F53_ROOT = ROUNDS_ROOT / F53_ID
ORDER_MANIFEST = F53_ROOT / "round-order-manifest.json"
INVALID_CORRECTION_ID = (
    "a14e2c49a62759a9dc4342fae243a6ec6234ef8c7ec747bb6919795301f7d6cc"
)
INVALID_SUCCESSOR_ID = (
    "cb59feb1cac076c61f15f52cc5e1001641191acfa4854d0f6e22e22ed34725af"
)
INVALID_CORRECTION_ROOT = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/enrichment/grammar-corrections"
    / INVALID_CORRECTION_ID
)
INVALID_SUCCESSOR_ROOT = ROUNDS_ROOT / INVALID_SUCCESSOR_ID
IMMUTABLE_ROUND_IDS = (
    "a59fabf3371845fbacb4e32510b178b03d7a784d0becfea6edfd7f7b2e4f2c25",
    "8d8742ca9a7f5b9e29fb76f842271d6bf242d806db07b819c761f9d7d0f456c8",
    F53_ID,
)
INVALID_SUCCESSOR_FILES = {
    "remediation-candidate-pool.json",
    "enrichment-plan.json",
    "enrichment-state-attestation.json",
    "enrichment-authorization-request.json",
}


def _issuance() -> GrammarSuccessorIssuance:
    issued_at = datetime(2026, 7, 29, 14, 0, tzinfo=UTC)
    return GrammarSuccessorIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        nonce="1" * 64,
        reviewer_id="phase2-operator",
        code_sha256="2" * 64,
        config_sha256="3" * 64,
    )


def _supersession_issuance() -> GrammarSuccessorIssuance:
    issued_at = datetime(2026, 7, 29, 15, 0, tzinfo=UTC)
    return GrammarSuccessorIssuance(
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=24),
        nonce="4" * 64,
        reviewer_id="phase2-operator",
        code_sha256="5" * 64,
        config_sha256="6" * 64,
    )


def _copy_supersession_topology(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path]:
    repository_root = tmp_path / "repository"
    (repository_root / ".git").mkdir(parents=True)
    rounds_root = (
        repository_root / "artifacts/restricted/catalog/v2/enrichment/rounds"
    )
    for round_id in (*IMMUTABLE_ROUND_IDS, INVALID_SUCCESSOR_ID):
        shutil.copytree(ROUNDS_ROOT / round_id, rounds_root / round_id)
    corrections_root = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment/grammar-corrections"
    )
    shutil.copytree(
        INVALID_CORRECTION_ROOT,
        corrections_root / INVALID_CORRECTION_ID,
    )
    predecessor_root = rounds_root / F53_ID
    return (
        repository_root,
        rounds_root,
        predecessor_root,
        corrections_root / INVALID_CORRECTION_ID,
        rounds_root / INVALID_SUCCESSOR_ID,
    )


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def _actual_failure() -> tuple[dict[str, object], dict[str, object], bytes]:
    plan = json.loads((F53_ROOT / "enrichment-plan.json").read_bytes())
    reports = [
        json.loads(line)
        for line in (F53_ROOT / "enrichment-collection-report.json").read_bytes().splitlines()
    ]
    report = next(
        row
        for row in reports
        if row["operation"] == "detailCommon2"
        and row["terminal_status"] == "TERMINAL_PROVIDER_FAILURE"
    )
    request = next(
        row for row in plan["requests"] if row["request_identity"] == report["request_identity"]
    )
    raw_body = (F53_ROOT / report["raw_relative_path"]).read_bytes()
    return request, report, raw_body


def test_actual_f53_builds_only_changed_common_and_image_successors(
    tmp_path: Path,
) -> None:
    successor = build_grammar_correction_successor(
        predecessor_round_root=F53_ROOT,
        predecessor_round_id=F53_ID,
        round_roots_manifest=ORDER_MANIFEST,
        rounds_root=tmp_path / "rounds",
        issuance=_issuance(),
    )

    report = successor.correction_report
    plan = successor.bundle.plan
    assert report.correction_count == 32
    assert report.provider_candidate_count == 16
    assert report.operation_counts == {"detailCommon2": 16, "detailImage2": 16}
    assert {row.provider_result_code for row in report.rows} == {"10"}
    assert {row.offending_parameter for row in report.rows} == {
        "areacodeYN",
        "subImageYN",
    }
    assert plan["candidate_count"] == 16
    assert plan["request_count"] == 32
    assert plan["attempts_per_request"] == 3
    assert plan["quota_estimate"] == 96
    assert plan["overall_timeout_seconds"] == 28_800
    assert {row["operation"] for row in plan["requests"]} == {
        "detailCommon2",
        "detailImage2",
    }
    assert all(
        set(request["parameters"])
        == KOR_SERVICE2_PARAMETER_ALLOWLISTS[request["operation"]] - {"serviceKey"}
        for request in plan["requests"]
    )
    assert all(
        row.failed_request_identity != row.corrected_request_identity for row in report.rows
    )
    assert {
        row.failed_request_identity for row in report.rows
    }.isdisjoint({row.corrected_request_identity for row in report.rows})
    assert report.accepted_predecessor_outcome_code == 21
    assert report.accepted_predecessor_outcome_reason == "EVIDENCE_FRONTIER_EXHAUSTED"
    assert report.accepted_predecessor_frontier_count == 0
    assert successor.bundle.authorization_request["authority_token_issued"] is False
    assert successor.bundle.authorization_request["previous_round_ref_sha256"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("success", "terminal provider failure"),
        ("timeout", "terminal provider failure"),
        ("authentication", "terminal provider failure"),
        ("transport", "terminal provider failure"),
        ("schema", "terminal provider failure"),
        ("generic", "named parameter"),
        ("unknown_parameter", "current endpoint allowlist"),
        ("missing_parameter", "predecessor request"),
        ("non_addressable", "provider candidate"),
    ],
)
def test_every_broader_terminal_class_fails_closed(
    mutation: str,
    message: str,
) -> None:
    request, report, raw_body = _actual_failure()
    request = copy.deepcopy(request)
    report = copy.deepcopy(report)

    if mutation == "success":
        report["terminal_status"] = "SUCCESS"
    elif mutation == "timeout":
        report["terminal_status"] = "RETRYABLE_FOR_RESUME"
        report["normalized_reason"] = "bounded attempts exhausted"
    elif mutation == "authentication":
        report["terminal_status"] = "AUTHENTICATION_FAILURE"
    elif mutation == "transport":
        report["terminal_status"] = "TRANSPORT_FAILURE"
    elif mutation == "schema":
        report["terminal_status"] = "SCHEMA_FAILURE"
    elif mutation == "generic":
        raw_body = canonical_json_bytes(
            {
                "response": {
                    "header": {
                        "resultCode": "10",
                        "resultMsg": "INVALID_REQUEST_PARAMETER_ERROR",
                    }
                }
            }
        )
    elif mutation == "unknown_parameter":
        raw_body = canonical_json_bytes(
            {
                "response": {
                    "header": {
                        "resultCode": "10",
                        "resultMsg": "INVALID_REQUEST_PARAMETER_ERROR(serviceKey)",
                    }
                }
            }
        )
    elif mutation == "missing_parameter":
        request["parameters"].pop("areacodeYN")
    elif mutation == "non_addressable":
        request["provider_candidate_id"] = "candidate:other:2603509"

    report["raw_body_sha256"] = hashlib.sha256(raw_body).hexdigest()
    report["attempts"][-1]["raw_body_sha256"] = report["raw_body_sha256"]
    with pytest.raises(ValueError, match=message):
        classify_terminal_grammar_failure(
            planned_request=request,
            report_record=report,
            raw_body=raw_body,
        )


def test_existing_failed_request_allowlist_pair_blocks_second_correction(
    tmp_path: Path,
) -> None:
    first = build_grammar_correction_successor(
        predecessor_round_root=F53_ROOT,
        predecessor_round_id=F53_ID,
        round_roots_manifest=ORDER_MANIFEST,
        rounds_root=tmp_path / "rounds",
        issuance=_issuance(),
    )
    existing_pair = (
        first.correction_report.rows[0].failed_request_identity,
        first.correction_report.allowlist_revision_sha256,
    )

    with pytest.raises(ValueError, match="already has a correction successor"):
        build_grammar_correction_successor(
            predecessor_round_root=F53_ROOT,
            predecessor_round_id=F53_ID,
            round_roots_manifest=ORDER_MANIFEST,
            rounds_root=tmp_path / "rounds",
            issuance=_issuance(),
            existing_correction_pairs=frozenset({existing_pair}),
        )


def test_publication_and_replay_are_no_replace_and_secret_free(
    tmp_path: Path,
) -> None:
    successor = build_grammar_correction_successor(
        predecessor_round_root=F53_ROOT,
        predecessor_round_id=F53_ID,
        round_roots_manifest=ORDER_MANIFEST,
        rounds_root=tmp_path / "rounds",
        issuance=_issuance(),
    )
    correction_root = (
        tmp_path
        / "grammar-corrections"
        / successor.correction_report.report_sha256
    )

    publish_grammar_correction_successor(
        successor,
        correction_root=correction_root,
    )
    before = {
        path.relative_to(tmp_path).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    verify_published_grammar_correction_successor(
        predecessor_round_root=F53_ROOT,
        predecessor_round_id=F53_ID,
        round_roots_manifest=ORDER_MANIFEST,
        correction_root=correction_root,
        successor_root=successor.bundle.round_root,
    )
    with pytest.raises(FileExistsError):
        publish_grammar_correction_successor(
            successor,
            correction_root=correction_root,
        )
    after = {
        path.relative_to(tmp_path).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert set(path.name for path in correction_root.iterdir()) == {
        "grammar-correction-report.json"
    }
    assert set(path.name for path in successor.bundle.round_root.iterdir()) == {
        "remediation-candidate-pool.json",
        "enrichment-plan.json",
        "enrichment-state-attestation.json",
        "enrichment-authorization-request.json",
    }
    payload = b"".join(
        path.read_bytes()
        for path in (*correction_root.iterdir(), *successor.bundle.round_root.iterdir())
    )
    assert b"serviceKey" not in payload
    assert b"itda-auth-v2:" not in payload


def test_offline_verifier_rejects_self_consistent_forged_previous_round_ref(
    tmp_path: Path,
) -> None:
    issuance = _issuance()
    successor = build_grammar_correction_successor(
        predecessor_round_root=F53_ROOT,
        predecessor_round_id=F53_ID,
        round_roots_manifest=ORDER_MANIFEST,
        rounds_root=tmp_path / "rounds",
        issuance=issuance,
    )
    forged_plan = copy.deepcopy(successor.bundle.plan)
    remediation = forged_plan["remediation"]
    assert isinstance(remediation, dict)
    previous_round_ref = remediation["previous_round_ref"]
    assert isinstance(previous_round_ref, dict)
    previous_round_ref["ancestry_depth"] = 1
    plan_bytes = canonical_json_bytes(forged_plan)
    forged_round_id = hashlib.sha256(plan_bytes).hexdigest()
    forged_bundle = build_enrichment_bundle(
        plan=forged_plan,
        round_root=tmp_path / "rounds" / forged_round_id,
        round_id=forged_round_id,
        frozen=FrozenEnrichmentIssuance(
            issued_at=issuance.issued_at,
            expires_at=issuance.expires_at,
            nonce=issuance.nonce,
            reviewer_id=issuance.reviewer_id,
            code_sha256=issuance.code_sha256,
            config_sha256=issuance.config_sha256,
            permission_evidence_sha256=hashlib.sha256(
                canonical_json_bytes(forged_plan["permission_evidence"])
            ).hexdigest(),
            previous_round_ref_sha256=hashlib.sha256(
                canonical_json_bytes(previous_round_ref)
            ).hexdigest(),
        ),
    )
    forged_successor = GrammarCorrectionSuccessor(
        correction_report=successor.correction_report,
        remediation_pool=successor.remediation_pool,
        bundle=forged_bundle,
    )
    correction_root = (
        tmp_path
        / "grammar-corrections"
        / forged_successor.correction_report.report_sha256
    )
    publish_grammar_correction_successor(
        forged_successor,
        correction_root=correction_root,
    )
    verify_enrichment_bundle(
        forged_bundle.round_root / "enrichment-plan.json",
        forged_bundle.round_root / "enrichment-state-attestation.json",
        forged_bundle.round_root / "enrichment-authorization-request.json",
        round_root=forged_bundle.round_root,
        round_id=forged_bundle.round_id,
    )

    with pytest.raises(ValueError, match="differs from verified predecessor"):
        verify_published_grammar_correction_successor(
            predecessor_round_root=F53_ROOT,
            predecessor_round_id=F53_ID,
            round_roots_manifest=ORDER_MANIFEST,
            correction_root=correction_root,
            successor_root=forged_bundle.round_root,
        )


def test_built_successor_passes_real_collector_authorization_preconditions(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "repository"
    (repository_root / ".git").mkdir(parents=True)
    rounds_root = (
        repository_root / "artifacts/restricted/catalog/v2/enrichment/rounds"
    )
    for round_id in IMMUTABLE_ROUND_IDS:
        shutil.copytree(ROUNDS_ROOT / round_id, rounds_root / round_id)
    predecessor_root = rounds_root / F53_ID
    issuance = _issuance()
    successor = build_grammar_correction_successor(
        predecessor_round_root=predecessor_root,
        predecessor_round_id=F53_ID,
        round_roots_manifest=predecessor_root / "round-order-manifest.json",
        rounds_root=rounds_root,
        issuance=issuance,
    )
    correction_root = (
        repository_root
        / "artifacts/restricted/catalog/v2/enrichment/grammar-corrections"
        / successor.correction_report.report_sha256
    )
    publish_grammar_correction_successor(
        successor,
        correction_root=correction_root,
    )

    summary = verify_authorization_preconditions(
        successor.bundle.round_root / "enrichment-authorization-request.json",
        round_root=successor.bundle.round_root,
        round_id=successor.bundle.round_id,
        now=issuance.issued_at + timedelta(hours=1),
    )

    assert summary["ancestry_depth"] == 3
    assert summary["round_id"] == successor.bundle.round_id


def test_exact_invalid_publication_can_be_superseded_once_offline(
    tmp_path: Path,
) -> None:
    (
        _repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    invalid_before = {
        "correction": _tree_hashes(invalid_correction_root),
        "successor": _tree_hashes(invalid_successor_root),
    }
    invalid_request = json.loads(
        (
            invalid_successor_root / "enrichment-authorization-request.json"
        ).read_bytes()
    )
    invalid_plan = json.loads(
        (invalid_successor_root / "enrichment-plan.json").read_bytes()
    )
    with pytest.raises(
        ValueError,
        match="remediation previous-round ancestry is incomplete",
    ):
        verify_authorization_preconditions(
            invalid_successor_root / "enrichment-authorization-request.json",
            round_root=invalid_successor_root,
            round_id=INVALID_SUCCESSOR_ID,
            now=_supersession_issuance().issued_at,
        )

    supersession = build_grammar_correction_supersession(
        predecessor_round_root=predecessor_root,
        predecessor_round_id=F53_ID,
        round_roots_manifest=predecessor_root / "round-order-manifest.json",
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        rounds_root=rounds_root,
        issuance=_supersession_issuance(),
    )
    report = supersession.supersession_report
    plan = supersession.bundle.plan
    request = supersession.bundle.authorization_request
    assert report.invalid_correction_report_sha256 == INVALID_CORRECTION_ID
    assert report.invalid_successor_round_id == INVALID_SUCCESSOR_ID
    assert report.invalid_collector_precondition_error == (
        "remediation previous-round ancestry is incomplete"
    )
    assert report.invalid_authority_token_issued is False
    assert report.invalid_forbidden_output_count == 0
    assert report.corrected_successor_round_id == supersession.bundle.round_id
    assert plan["candidate_count"] == 16
    assert plan["request_count"] == 32
    assert plan["quota_estimate"] == 96
    assert plan["overall_timeout_seconds"] == 28_800
    assert plan["remediation"]["previous_round_ref"] == {
        "round_id": F53_ID,
        "round_root": (
            "artifacts/restricted/catalog/v2/enrichment/rounds/" + F53_ID
        ),
        "round_manifest_sha256": (
            "380759d9665e8f5f08487de4f94010cd56f19c01a50cdd65fe4097b36906d6f2"
        ),
        "ancestry_depth": 2,
    }
    assert all(
        "serviceKey" not in planned["parameters"] for planned in plan["requests"]
    )
    assert {planned["request_identity"] for planned in plan["requests"]} == {
        planned["request_identity"] for planned in invalid_plan["requests"]
    }
    for field in (
        "request_sha256",
        "state_attestation_sha256",
        "target_sha256",
        "binding_sha256",
        "nonce",
    ):
        assert request[field] != invalid_request[field]
    assert request["authority_token_issued"] is False
    report_bytes = canonical_json_bytes(report.model_dump(mode="json"))
    assert str(invalid_request["nonce"]).encode() not in report_bytes
    assert str(request["nonce"]).encode() not in report_bytes
    assert b"serviceKey" not in report_bytes
    assert b"itda-auth-v2:" not in report_bytes

    supersession_root = (
        rounds_root.parent
        / "grammar-successor-supersessions"
        / INVALID_SUCCESSOR_ID
        / report.report_sha256
    )
    publish_grammar_correction_supersession(
        supersession,
        supersession_root=supersession_root,
    )
    assert set(path.name for path in supersession_root.parent.iterdir()) == {
        report.report_sha256
    }
    assert set(path.name for path in supersession_root.iterdir()) == {
        "grammar-successor-supersession.json"
    }
    assert set(
        path.name for path in supersession.bundle.round_root.iterdir()
    ) == INVALID_SUCCESSOR_FILES
    verify_published_grammar_correction_supersession(
        predecessor_round_root=predecessor_root,
        predecessor_round_id=F53_ID,
        round_roots_manifest=predecessor_root / "round-order-manifest.json",
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        supersession_root=supersession_root,
        successor_root=supersession.bundle.round_root,
    )
    summary = verify_authorization_preconditions(
        supersession.bundle.round_root / "enrichment-authorization-request.json",
        round_root=supersession.bundle.round_root,
        round_id=supersession.bundle.round_id,
        now=_supersession_issuance().issued_at + timedelta(hours=1),
    )
    assert summary["ancestry_depth"] == 3
    assert invalid_before == {
        "correction": _tree_hashes(invalid_correction_root),
        "successor": _tree_hashes(invalid_successor_root),
    }
    with pytest.raises(FileExistsError):
        publish_grammar_correction_supersession(
            supersession,
            supersession_root=supersession_root,
        )
    with pytest.raises(ValueError, match="already has a correction successor"):
        build_grammar_correction_supersession(
            predecessor_round_root=predecessor_root,
            predecessor_round_id=F53_ID,
            round_roots_manifest=predecessor_root / "round-order-manifest.json",
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=rounds_root,
            issuance=GrammarSuccessorIssuance(
                issued_at=_supersession_issuance().issued_at,
                expires_at=_supersession_issuance().expires_at,
                nonce="7" * 64,
                reviewer_id="phase2-operator",
                code_sha256="8" * 64,
                config_sha256="9" * 64,
            ),
        )


@pytest.mark.parametrize(
    ("relative_path", "directory"),
    [
        ("enrichment-authorization-receipt.json", False),
        (".enrichment-authority.lock", False),
        ("raw", True),
        ("enrichment-collection-report.json", False),
        ("enrichment-collection-log.jsonl", False),
        ("evidence-sidecars.json", False),
        ("enrichment-round-manifest.json", False),
        ("round-order-manifest.json", False),
        ("aggregate-readiness.json", False),
        ("representation-quota-config.json", False),
        ("representation-quota-attestation.json", False),
    ],
)
def test_supersession_rejects_any_execution_evidence(
    tmp_path: Path,
    relative_path: str,
    directory: bool,
) -> None:
    (
        _repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    evidence_path = invalid_successor_root / relative_path
    if directory:
        evidence_path.mkdir()
    else:
        evidence_path.write_bytes(b"")

    with pytest.raises(ValueError, match="execution evidence"):
        build_grammar_correction_supersession(
            predecessor_round_root=predecessor_root,
            predecessor_round_id=F53_ID,
            round_roots_manifest=predecessor_root / "round-order-manifest.json",
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=rounds_root,
            issuance=_supersession_issuance(),
        )
    assert set(path.name for path in rounds_root.iterdir()) == set(
        (*IMMUTABLE_ROUND_IDS, INVALID_SUCCESSOR_ID)
    )


@pytest.mark.parametrize(
    ("root_kind", "relative_path"),
    [
        ("correction", "grammar-correction-report.json"),
        ("successor", "remediation-candidate-pool.json"),
        ("successor", "enrichment-plan.json"),
        ("successor", "enrichment-state-attestation.json"),
        ("successor", "enrichment-authorization-request.json"),
    ],
)
def test_supersession_rejects_any_mutated_historical_byte(
    tmp_path: Path,
    root_kind: str,
    relative_path: str,
) -> None:
    (
        _repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    root = (
        invalid_correction_root
        if root_kind == "correction"
        else invalid_successor_root
    )
    path = root / relative_path
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(ValueError):
        build_grammar_correction_supersession(
            predecessor_round_root=predecessor_root,
            predecessor_round_id=F53_ID,
            round_roots_manifest=predecessor_root / "round-order-manifest.json",
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=rounds_root,
            issuance=_supersession_issuance(),
        )
    assert not (
        rounds_root.parent / "grammar-successor-supersessions"
    ).exists()


def test_supersession_rejects_any_other_historical_root(
    tmp_path: Path,
) -> None:
    (
        _repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    wrong_correction = invalid_correction_root.parent / ("a" * 64)
    wrong_successor = invalid_successor_root.parent / ("b" * 64)
    shutil.copytree(invalid_correction_root, wrong_correction)
    shutil.copytree(invalid_successor_root, wrong_successor)

    for correction_root, successor_root in (
        (wrong_correction, invalid_successor_root),
        (invalid_correction_root, wrong_successor),
    ):
        with pytest.raises(ValueError, match="exact a14e/cb59 issuance"):
            build_grammar_correction_supersession(
                predecessor_round_root=predecessor_root,
                predecessor_round_id=F53_ID,
                round_roots_manifest=predecessor_root
                / "round-order-manifest.json",
                invalid_correction_root=correction_root,
                invalid_successor_root=successor_root,
                rounds_root=rounds_root,
                issuance=_supersession_issuance(),
            )


def test_supersession_rejects_shadow_publication_paths(
    tmp_path: Path,
) -> None:
    (
        repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    shadow_rounds = repository_root / "shadow/rounds"

    with pytest.raises(ValueError, match="canonical rounds root"):
        build_grammar_correction_supersession(
            predecessor_round_root=predecessor_root,
            predecessor_round_id=F53_ID,
            round_roots_manifest=predecessor_root / "round-order-manifest.json",
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=shadow_rounds,
            issuance=_supersession_issuance(),
        )

    supersession = build_grammar_correction_supersession(
        predecessor_round_root=predecessor_root,
        predecessor_round_id=F53_ID,
        round_roots_manifest=predecessor_root / "round-order-manifest.json",
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        rounds_root=rounds_root,
        issuance=_supersession_issuance(),
    )
    shadow_supersession_root = (
        repository_root
        / "shadow/grammar-successor-supersessions"
        / INVALID_SUCCESSOR_ID
        / supersession.supersession_report.report_sha256
    )
    with pytest.raises(ValueError, match="canonical supersession root"):
        publish_grammar_correction_supersession(
            supersession,
            supersession_root=shadow_supersession_root,
        )
    assert not shadow_supersession_root.exists()
    assert not supersession.bundle.round_root.exists()


def test_supersession_rejects_retargetable_canonical_parent_symlink(
    tmp_path: Path,
) -> None:
    (
        repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    supersession = build_grammar_correction_supersession(
        predecessor_round_root=predecessor_root,
        predecessor_round_id=F53_ID,
        round_roots_manifest=predecessor_root / "round-order-manifest.json",
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        rounds_root=rounds_root,
        issuance=_supersession_issuance(),
    )
    canonical_parent = (
        rounds_root.parent / "grammar-successor-supersessions"
    )
    first_shadow = repository_root / "shadow-one/grammar-successor-supersessions"
    second_shadow = repository_root / "shadow-two/grammar-successor-supersessions"
    first_shadow.mkdir(parents=True)
    second_shadow.mkdir(parents=True)
    canonical_parent.symlink_to(first_shadow, target_is_directory=True)
    supersession_root = (
        canonical_parent
        / INVALID_SUCCESSOR_ID
        / supersession.supersession_report.report_sha256
    )

    with pytest.raises(ValueError, match="symlink"):
        publish_grammar_correction_supersession(
            supersession,
            supersession_root=supersession_root,
        )
    canonical_parent.unlink()
    canonical_parent.symlink_to(second_shadow, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        build_grammar_correction_supersession(
            predecessor_round_root=predecessor_root,
            predecessor_round_id=F53_ID,
            round_roots_manifest=predecessor_root / "round-order-manifest.json",
            invalid_correction_root=invalid_correction_root,
            invalid_successor_root=invalid_successor_root,
            rounds_root=rounds_root,
            issuance=GrammarSuccessorIssuance(
                issued_at=_supersession_issuance().issued_at,
                expires_at=_supersession_issuance().expires_at,
                nonce="7" * 64,
                reviewer_id="phase2-operator",
                code_sha256="8" * 64,
                config_sha256="9" * 64,
            ),
        )
    assert not any(first_shadow.iterdir())
    assert not any(second_shadow.iterdir())
    assert not supersession.bundle.round_root.exists()


def test_supersession_rejects_canonical_successor_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _repository_root,
        rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    supersession = build_grammar_correction_supersession(
        predecessor_round_root=predecessor_root,
        predecessor_round_id=F53_ID,
        round_roots_manifest=predecessor_root / "round-order-manifest.json",
        invalid_correction_root=invalid_correction_root,
        invalid_successor_root=invalid_successor_root,
        rounds_root=rounds_root,
        issuance=_supersession_issuance(),
    )
    supersession_root = (
        rounds_root.parent
        / "grammar-successor-supersessions"
        / INVALID_SUCCESSOR_ID
        / supersession.supersession_report.report_sha256
    )
    canonical_successor_root = supersession.bundle.round_root
    moved_successor_root = rounds_root / f"{supersession.bundle.round_id}.moved"
    original_write = grammar_contract._write_exclusive_at
    swapped = False

    def swap_before_first_successor_write(
        parent_fd: int,
        name: str,
        payload: bytes,
    ) -> None:
        nonlocal swapped
        if name == "remediation-candidate-pool.json" and not swapped:
            canonical_successor_root.rename(moved_successor_root)
            canonical_successor_root.mkdir(mode=0o700)
            swapped = True
        original_write(parent_fd, name, payload)

    monkeypatch.setattr(
        grammar_contract,
        "_write_exclusive_at",
        swap_before_first_successor_write,
    )

    with pytest.raises(ValueError, match="directory identity changed"):
        publish_grammar_correction_supersession(
            supersession,
            supersession_root=supersession_root,
        )

    assert swapped is True
    assert canonical_successor_root.is_dir()
    assert not any(canonical_successor_root.iterdir())
    assert not supersession_root.exists()


def test_offline_cli_publishes_and_verifies_exact_supersession(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (
        _repository_root,
        _rounds_root,
        predecessor_root,
        invalid_correction_root,
        invalid_successor_root,
    ) = _copy_supersession_topology(tmp_path)
    common = [
        "--predecessor-round-root",
        str(predecessor_root),
        "--predecessor-round-id",
        F53_ID,
        "--round-roots-manifest",
        str(predecessor_root / "round-order-manifest.json"),
    ]
    assert (
        grammar_successor_main(
            [
                *common,
                "--supersede-invalid",
                str(invalid_correction_root),
                str(invalid_successor_root),
            ]
        )
        == 0
    )
    published = json.loads(capsys.readouterr().out)
    assert published["status"] == "PUBLISHED_SUPERSESSION_OFFLINE_NO_AUTHORITY"
    assert (
        grammar_successor_main(
            [
                *common,
                "--verify-supersession",
                str(invalid_correction_root),
                str(invalid_successor_root),
                published["supersession_root"],
                published["successor_round_root"],
            ]
        )
        == 0
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["status"] == "VERIFIED_SUPERSESSION_OFFLINE_NO_AUTHORITY"


def test_legacy_rounds_and_plan18_outcome_remain_verifiable() -> None:
    for round_id in IMMUTABLE_ROUND_IDS:
        root = ROUNDS_ROOT / round_id
        verify_enrichment_bundle(
            root / "enrichment-plan.json",
            root / "enrichment-state-attestation.json",
            root / "enrichment-authorization-request.json",
            round_root=root,
            round_id=round_id,
        )

    aggregate = json.loads((F53_ROOT / "aggregate-readiness.json").read_bytes())
    assert (
        aggregate["outcome_code"],
        aggregate["outcome_reason"],
        aggregate["addressable_frontier_count"],
    ) == (21, "EVIDENCE_FRONTIER_EXHAUSTED", 0)
    assert not (F53_ROOT / "remediation-round-ref.json").exists()
