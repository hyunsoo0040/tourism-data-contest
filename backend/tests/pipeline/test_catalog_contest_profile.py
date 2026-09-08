from __future__ import annotations

import importlib
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPLETED_PLAN55_SUMMARY_REL = Path(
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-55-SUMMARY.md"
)
EXPECTED_GROUPS = {
    "history_culture": 13,
    "history_scenery_boundary": 6,
    "image_modern_content": 8,
    "rest_walk_immersion": 13,
}
EXPECTED_QUOTAS = {
    "history_culture": 12,
    "history_scenery_boundary": 6,
    "image_modern_content": 7,
    "rest_walk_immersion": 11,
}
TERMINAL_CODES = (
    "FORBIDDEN_CAPABILITY_REQUESTED",
    "HISTORICAL_LINEAGE_DRIFT",
    "NONCANONICAL_HELD_INPUT",
    "INCOMPLETE_UNIVERSE",
    "RIGHTS_OR_SOURCE_AMBIGUITY",
    "HUMAN_DECISION_LIMIT_EXCEEDED",
    "REPRESENTATION_QUOTA_INFEASIBLE",
    "SELECTABLE_COUNT_SHORTFALL",
    "REPLAY_MISMATCH",
)


def _api() -> tuple[object, object]:
    contracts = importlib.import_module("itda.contracts.catalog_contest_profile")
    cli = importlib.import_module("itda.cli.build_catalog_contest_profile")
    return contracts, cli


@pytest.fixture(autouse=True)
def _historical_plan55_pending_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, cli = _api()
    assert cli.SUMMARY_REL == COMPLETED_PLAN55_SUMMARY_REL
    assert (REPO_ROOT / COMPLETED_PLAN55_SUMMARY_REL).is_file()
    monkeypatch.setattr(cli, "SUMMARY_REL", tmp_path / "02-55-SUMMARY.pending.md")


def test_contest_profile_interface_contract_is_present() -> None:
    try:
        contracts, cli = _api()
    except ModuleNotFoundError as exc:
        if exc.name in {
            "itda.contracts.catalog_contest_profile",
            "itda.cli.build_catalog_contest_profile",
        }:
            try:
                pytest.fail("ITDA_CONTEST_PROFILE_INTERFACE_MISSING", pytrace=False)
            except pytest.fail.Exception as failure:
                # pytest 9 omits the historical ``Failed:`` text from JUnit when
                # pytrace is false. Preserve the specified conversion call while
                # retaining the exact cross-version JUnit classification.
                failure.pytrace = True
                raise failure from None
        raise

    expected_contracts = {
        "ContestUseScope",
        "DatasetPermissionDisposition",
        "EvidenceAvailability",
        "AxisEvidenceBasis",
        "ContestProfileConfidence",
        "ContestUsePolicy",
        "ContestCandidateAccounting",
        "ContestSelectionFrontier",
        "ContestReplayAttestation",
        "ContestPlan54Handoff",
        "ContestProfileTerminalCode",
        "ContestProfileTerminal",
        "ContestGenerationChild",
        "ContestGenerationManifest",
    }
    expected_cli = {
        "project_contest_profile",
        "replay_contest_profile",
        "publish_contest_generation",
        "verify_contest_generation",
        "finalize_plan54_handoff",
    }
    assert expected_contracts <= set(dir(contracts))
    assert expected_cli <= set(dir(cli))


def test_contest_scope_grants_and_asset_veto_are_orthogonal() -> None:
    contracts, cli = _api()
    qualified = cli.derive_dataset_permission(
        dataset_bound=True,
        portal_terms="이용허락범위 제한 없음",
        explicit_restriction=None,
        third_party_identified=True,
    )
    narrower = cli.derive_dataset_permission(
        dataset_bound=True,
        portal_terms="이용허락범위 제한 없음",
        explicit_restriction="NO_DERIVATIVES",
        third_party_identified=True,
    )
    unidentified = cli.derive_dataset_permission(
        dataset_bound=True,
        portal_terms="이용허락범위 제한 없음",
        explicit_restriction=None,
        third_party_identified=False,
    )

    assert qualified is contracts.DatasetPermissionDisposition.DATASET_UNRESTRICTED_QUALIFIED
    assert narrower is contracts.DatasetPermissionDisposition.EXPLICIT_NARROWER_EXCLUDED
    assert unidentified is contracts.DatasetPermissionDisposition.UNIDENTIFIED_THIRD_PARTY_EXCLUDED


@pytest.mark.parametrize(
    ("image_state", "operating_state", "expected_channels", "warning_count"),
    [
        ("QUALIFIED", "QUALIFIED", ("official_description", "odii", "metadata", "image"), 0),
        ("MISSING", "QUALIFIED", ("official_description", "odii", "metadata"), 1),
        ("EXCLUDED", "MISSING", ("official_description", "odii", "metadata"), 2),
    ],
)
def test_axis_evidence_falls_back_without_fabricating_facts(
    image_state: str,
    operating_state: str,
    expected_channels: tuple[str, ...],
    warning_count: int,
) -> None:
    _, cli = _api()
    basis, confidence = cli.derive_axis_evidence_basis(
        image_availability=image_state,
        operating_information_availability=operating_state,
        known_operating_facts={},
    )

    assert basis.qualified_channels == expected_channels
    assert basis.inferred_image_facts == ()
    assert basis.inferred_operating_facts == ()
    assert len(basis.availability_warnings) == warning_count
    assert confidence.selection_score_contribution == 0
    assert confidence.affects_representation_group is False
    assert confidence.affects_quota is False
    assert confidence.affects_ordering is False
    assert confidence.qualification_filter_only is True


def test_policy_is_strict_frozen_scope_bound_and_commercially_unqualified() -> None:
    contracts, cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    policy = result.payloads["policy.json"]
    parsed = contracts.ContestUsePolicy.model_validate(policy)

    assert parsed.scope is contracts.ContestUseScope.NONCOMMERCIAL_CONTEST_DEMO_EVALUATION
    assert parsed.commercial_production_rights_review_required is True
    assert parsed.confidence_is_qualification_filter_only is True
    assert parsed.confidence_adds_score is False
    hostile = {**policy, "commercial_clearance": True}
    with pytest.raises(ValidationError):
        contracts.ContestUsePolicy.model_validate(hostile)


def test_project_current_rederives_exact_40_pool_and_quota_valid_preview() -> None:
    _, cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    frontier = result.payloads["selection-frontier.json"]

    assert result.publication_state == "SUCCESS"
    assert result.exit_code == 0
    assert frontier["universe_count"] == 718
    assert frontier["eligible_candidate_count"] == 40
    assert frontier["eligible_group_counts"] == EXPECTED_GROUPS
    assert frontier["capped_capacity"] == 38
    assert frontier["final_quotas"] == EXPECTED_QUOTAS
    assert len(frontier["eligible_pool"]) == 40
    assert len(frontier["noncanonical_preview_ids"]) == 36
    assert len(set(frontier["noncanonical_preview_ids"])) == 36
    assert frontier["preview_is_canonical_catalog"] is False
    assert frontier["human_choice_and_order_required"] is True
    assert result.payloads["plan54-handoff.json"]["plan54_reachable"] is True


def test_two_separate_complete_universe_reads_are_byte_identical() -> None:
    _, cli = _api()
    first = cli.replay_contest_profile(REPO_ROOT)
    second = cli.replay_contest_profile(REPO_ROOT)

    assert first.publication_state == second.publication_state == "SUCCESS"
    assert canonical_json_bytes(first.payloads) == canonical_json_bytes(second.payloads)
    assert first.generation_sha256 == second.generation_sha256
    assert (
        first.payloads["first-replay.json"]["replay_sha256"]
        == first.payloads["second-replay.json"]["replay_sha256"]
    )


def test_terminal_enum_and_precedence_are_closed_and_exhaustive() -> None:
    contracts, cli = _api()
    assert tuple(member.value for member in contracts.ContestProfileTerminalCode) == TERMINAL_CODES
    mapping = cli.TERMINAL_PREDICATE_ORDER
    assert tuple(mapping) == TERMINAL_CODES[:-1]

    for index, code in enumerate(TERMINAL_CODES[:-1]):
        predicates = {name: position >= index for position, name in enumerate(mapping)}
        assert cli.evaluate_terminal_code(predicates) == contracts.ContestProfileTerminalCode(code)
    assert cli.evaluate_terminal_code({name: False for name in mapping}) is None


def test_replay_divergence_overrides_and_equal_failures_retain_semantic_code() -> None:
    contracts, cli = _api()
    equal = {"state": "TERMINAL", "terminal_code": "INCOMPLETE_UNIVERSE", "reasons": ["x"]}
    assert (
        cli.resolve_replay_terminal(equal, deepcopy(equal))
        is contracts.ContestProfileTerminalCode.INCOMPLETE_UNIVERSE
    )
    divergent = {**equal, "reasons": ["y"]}
    assert (
        cli.resolve_replay_terminal(equal, divergent)
        is contracts.ContestProfileTerminalCode.REPLAY_MISMATCH
    )


def test_success_manifest_is_non_self_referential_and_inventory_exact() -> None:
    contracts, cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    manifest = contracts.ContestGenerationManifest.model_validate(
        result.manifest.model_dump(mode="json")
    )

    assert tuple(child.relpath for child in manifest.payload_inventory) == cli.SUCCESS_PAYLOAD_NAMES
    descriptor = manifest.model_dump(exclude={"generation_sha256"}, mode="json")
    assert manifest.generation_sha256 == canonical_sha256(descriptor)
    assert "generation-manifest.json" not in {child.relpath for child in manifest.payload_inventory}
    assert "generation_sha256" not in result.payloads["plan54-handoff.json"]


def test_success_publish_verify_and_exact_existing_recovery_change_no_inode_or_byte(
    tmp_path: Path,
) -> None:
    _, cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    output = tmp_path / "contest" / "generations"

    first = cli.publish_contest_generation(result, output_base=output, repository_root=REPO_ROOT)
    root = output / result.generation_sha256
    before = {
        path.name: (
            path.stat().st_ino,
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            path.read_bytes(),
        )
        for path in root.iterdir()
    }
    second = cli.publish_contest_generation(result, output_base=output, repository_root=REPO_ROOT)
    after = {
        path.name: (
            path.stat().st_ino,
            path.stat().st_mode,
            path.stat().st_mtime_ns,
            path.read_bytes(),
        )
        for path in root.iterdir()
    }

    assert first["publication_disposition"] == "PUBLISHED"
    assert second["publication_disposition"] == "ALREADY_PRESENT_VERIFIED"
    assert before == after
    verified = cli.verify_contest_generation(root, repository_root=REPO_ROOT)
    assert verified["publication_disposition"] == "VERIFIED_EXISTING"


def test_terminal_generation_has_exact_two_file_branch_and_exit_27(tmp_path: Path) -> None:
    _, cli = _api()
    result = cli.build_terminal_generation(
        code="INCOMPLETE_UNIVERSE",
        reasons=({"reason_code": "UNIVERSE_COUNT_NOT_718", "evidence_root_sha256": "a" * 64},),
        repository_root=REPO_ROOT,
    )
    receipt = cli.publish_contest_generation(
        result,
        output_base=tmp_path / "contest" / "generations",
        repository_root=REPO_ROOT,
    )
    root = tmp_path / "contest" / "generations" / result.generation_sha256

    assert result.exit_code == receipt["exit_code"] == 27
    assert {path.name for path in root.iterdir()} == {"terminal.json", "generation-manifest.json"}
    assert receipt["invariants"]["plan54_reachable"] is False
    assert receipt["invariants"]["handoff_created"] is False
    assert receipt["invariants"]["summary_disposition"] == "FORBIDDEN"


def test_receipt_triplet_differs_only_by_enumerated_disposition(tmp_path: Path) -> None:
    _, cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    output = tmp_path / "contest" / "generations"
    check = cli.receipt_for_result(result, repository_root=REPO_ROOT, disposition="CHECK_ONLY")
    publish = cli.publish_contest_generation(result, output_base=output, repository_root=REPO_ROOT)
    verify = cli.verify_contest_generation(
        output / result.generation_sha256,
        repository_root=REPO_ROOT,
    )

    assert cli.verify_receipt_triplet(check, publish, verify, repository_root=REPO_ROOT) == 0
    common = []
    for receipt in (check, publish, verify):
        copy = deepcopy(receipt)
        copy.pop("publication_disposition")
        common.append(canonical_json_bytes(copy))
    assert common[0] == common[1] == common[2]
