"""Security contract for independent approval of the materialized real split."""

from __future__ import annotations

import importlib
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.contracts.authority import AuthorityTokenV2
from itda.domain.canonical import canonical_json_bytes

MODULE = "itda.cli.approve_real_split"
REPO_ROOT = Path(__file__).resolve().parents[3]
PUBLIC_REQUEST = REPO_ROOT / "artifacts/public/catalog/v2/split-approval-request.json"
RESTRICTED_STATE = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/split/split-approval-state-attestation.json"
)
MATERIALIZED_BUNDLE = (
    REPO_ROOT / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json"
)


def _module():
    assert importlib.util.find_spec(MODULE) is not None, (
        "PHASE2-MISSING:real-split-approval-consumer"
    )
    return importlib.import_module(MODULE)


def _build(*, approver: str = "phase2-split-approver", nonce: str = "a" * 64):
    cli = _module()
    issued_at = datetime(2026, 8, 2, 7, tzinfo=UTC)
    return cli.build_split_approval_authority(
        repo_root=REPO_ROOT,
        materialized_bundle_path=MATERIALIZED_BUNDLE,
        split_approver_id=approver,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=7),
    )


def test_module_and_required_cli_modes_exist() -> None:
    cli = _module()
    help_text = cli.build_parser().format_help()
    assert "build" in help_text
    assert "consume" in help_text
    assert "--check-request" in help_text
    assert "--verify-approval" in help_text
    assert "--require-independent" in help_text


def test_cli_paths_cannot_escape_repository_root() -> None:
    cli = _module()
    with pytest.raises(ValueError, match="escapes"):
        cli._repo_path(REPO_ROOT, Path("../../outside-approval.json"))


def test_build_is_byte_reproducible_membership_free_and_independent() -> None:
    first_state, first_request = _build()
    second_state, second_request = _build()
    assert canonical_json_bytes(first_state.model_dump(mode="json")) == canonical_json_bytes(
        second_state.model_dump(mode="json")
    )
    public_bytes = canonical_json_bytes(first_request.model_dump(mode="json"))
    assert public_bytes == canonical_json_bytes(second_request.model_dump(mode="json"))
    rendered = public_bytes.decode("utf-8").casefold()
    assert "place:" not in rendered
    assert "membership" not in rendered
    assert not {
        "dev_members",
        "blind_members",
        "safe_input_rows",
        "components",
        "deviation_numerators",
    } & set(first_request.model_dump(mode="json"))
    assert first_request.action == "split-approve"
    assert first_request.dev_count == 24
    assert first_request.blind_count == 12
    assert first_state.status == "MATERIALIZED_UNAPPROVED"
    assert first_state.materializer_id != first_state.split_approver_id


def test_same_person_cannot_build_approval_authority() -> None:
    with pytest.raises(ValueError, match="distinct"):
        _build(approver="phase2-operator")


def test_request_binds_complete_reinf13_digest_surface() -> None:
    _, request = _build()
    values = request.model_dump(mode="json")
    required_hashes = {
        "active_bindings_sha256",
        "materialized_bundle_sha256",
        "manifest_sha256",
        "determinism_report_sha256",
        "materialization_result_sha256",
        "split_semantic_sha256",
        "safe_input_sha256",
        "completeness_rule_sha256",
        "completeness_bins_sha256",
        "tolerance_sha256",
        "objective_order_sha256",
        "objective_tuple_sha256",
        "component_universe_sha256",
        "deviation_numerators_sha256",
        "exact_targets_sha256",
        "reachability_certificate_sha256",
        "proof_certificate_sha256",
        "outcome_sha256",
    }
    assert required_hashes <= set(values)
    assert all(len(values[field]) == 64 for field in required_hashes)


def test_check_request_rejects_mixed_or_stale_fields_without_side_effects(
    tmp_path: Path,
) -> None:
    cli = _module()
    state, request = _build()
    state_path = tmp_path / "state.json"
    request_path = tmp_path / "request.json"
    state_path.write_bytes(canonical_json_bytes(state.model_dump(mode="json")))
    request_path.write_bytes(canonical_json_bytes(request.model_dump(mode="json")))
    checked = cli.check_split_approval_request(
        request_path=request_path,
        state_path=state_path,
        repo_root=REPO_ROOT,
        materialized_bundle_path=MATERIALIZED_BUNDLE,
    )
    assert checked.request_sha256 == request.request_sha256

    stale = request.model_dump(mode="json")
    stale["proof_certificate_sha256"] = "0" * 64
    stale["request_sha256"] = None
    request_path.write_bytes(canonical_json_bytes(stale))
    with pytest.raises(ValueError):
        cli.check_split_approval_request(
            request_path=request_path,
            state_path=state_path,
            repo_root=REPO_ROOT,
            materialized_bundle_path=MATERIALIZED_BUNDLE,
        )
    assert not (tmp_path / "approval.json").exists()


def test_infeasible_forbidden_and_nonoptimal_proofs_are_rejected() -> None:
    cli = _module()
    facts = cli.reverify_materialized_split(REPO_ROOT, MATERIALIZED_BUNDLE)
    infeasible = facts.outcome.model_dump(mode="json")
    infeasible["status"] = "BALANCE_INFEASIBLE"
    infeasible["candidate"] = None
    infeasible["outcome_sha256"] = None
    with pytest.raises(ValueError):
        cli.verify_reinf13_models(
            outcome=infeasible,
            manifest=facts.manifest,
            report=facts.report,
            bundle=facts.bundle,
            rebuilt=facts.outcome,
        )

    forbidden = facts.outcome.model_dump(mode="json")
    forbidden["proof"]["safe_input_rows"][0]["model_output_sha256"] = "1" * 64
    forbidden["outcome_sha256"] = None
    with pytest.raises(ValueError):
        cli.verify_reinf13_models(
            outcome=forbidden,
            manifest=facts.manifest,
            report=facts.report,
            bundle=facts.bundle,
            rebuilt=facts.outcome,
        )

    nonoptimal = facts.outcome.model_dump(mode="json")
    nonoptimal["proof"]["objective_tuple"][0] += 1
    nonoptimal["proof"]["proof_certificate_sha256"] = None
    nonoptimal["outcome_sha256"] = None
    with pytest.raises(ValueError):
        cli.verify_reinf13_models(
            outcome=nonoptimal,
            manifest=facts.manifest,
            report=facts.report,
            bundle=facts.bundle,
            rebuilt=facts.outcome,
        )


def test_changed_bin_tolerance_objective_tie_order_and_deviation_are_rejected() -> None:
    cli = _module()
    facts = cli.reverify_materialized_split(REPO_ROOT, MATERIALIZED_BUNDLE)
    for mutator in (
        lambda proof: proof.__setitem__("completeness_bin_order", [1, 0, 2, 3, 4, 5]),
        lambda proof: proof.__setitem__("tolerance_numerator", 2),
        lambda proof: proof.__setitem__(
            "objective_order", list(reversed(proof["objective_order"]))
        ),
        lambda proof: proof.__setitem__("priority_rule_version", "changed-tie-order"),
        lambda proof: proof["deviation_numerators"].__setitem__("history_tradition", 4),
    ):
        changed = facts.outcome.model_dump(mode="json")
        mutator(changed["proof"])
        changed["proof"]["proof_certificate_sha256"] = None
        changed["outcome_sha256"] = None
        with pytest.raises(ValueError):
            cli.verify_reinf13_models(
                outcome=changed,
                manifest=facts.manifest,
                report=facts.report,
                bundle=facts.bundle,
                rebuilt=facts.outcome,
            )


def test_consume_requires_exact_token_and_replay_is_read_only(tmp_path: Path) -> None:
    cli = _module()
    state, request = _build(nonce="b" * 64)
    state_path = tmp_path / "state.json"
    request_path = tmp_path / "request.json"
    approval_path = tmp_path / "approval.json"
    state_path.write_bytes(canonical_json_bytes(state.model_dump(mode="json")))
    request_path.write_bytes(canonical_json_bytes(request.model_dump(mode="json")))
    with pytest.raises(ValueError):
        cli.consume_split_approval(
            raw_token="",
            request_path=request_path,
            state_path=state_path,
            materialized_bundle_path=MATERIALIZED_BUNDLE,
            approval_path=approval_path,
            nonce_ledger_root=tmp_path / "ledger",
            repo_root=REPO_ROOT,
            approved_at=datetime(2026, 8, 2, 7, 1, tzinfo=UTC),
            require_independent=True,
        )
    assert not approval_path.exists()

    token = AuthorityTokenV2(
        action=request.action,
        request_sha256=request.request_sha256,
        state_attestation_sha256=request.state_attestation_sha256,
        target_sha256=request.target_sha256,
        reviewer_id=request.split_approver_id,
        binding_sha256=request.binding_sha256,
        nonce=request.nonce,
    ).serialize()
    first = cli.consume_split_approval(
        raw_token=token,
        request_path=request_path,
        state_path=state_path,
        materialized_bundle_path=MATERIALIZED_BUNDLE,
        approval_path=approval_path,
        nonce_ledger_root=tmp_path / "ledger",
        repo_root=REPO_ROOT,
        approved_at=datetime(2026, 8, 2, 7, 1, tzinfo=UTC),
        require_independent=True,
    )
    before = approval_path.read_bytes()
    replay = cli.consume_split_approval(
        raw_token=token,
        request_path=request_path,
        state_path=state_path,
        materialized_bundle_path=MATERIALIZED_BUNDLE,
        approval_path=approval_path,
        nonce_ledger_root=tmp_path / "ledger",
        repo_root=REPO_ROOT,
        approved_at=datetime(2026, 8, 2, 7, 1, tzinfo=UTC),
        require_independent=True,
    )
    assert replay == first
    assert approval_path.read_bytes() == before
    serialized = before.decode("utf-8").casefold()
    assert "place:" not in serialized
    assert "itda-auth-v2:" not in serialized
    assert '"nonce"' not in serialized


def test_uncertain_result_relookup_publishes_one_secret_safe_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _module()
    state, request = _build(nonce="c" * 64)
    state_path = tmp_path / "state.json"
    request_path = tmp_path / "request.json"
    approval_path = tmp_path / "approval.json"
    state_path.write_bytes(canonical_json_bytes(state.model_dump(mode="json")))
    request_path.write_bytes(canonical_json_bytes(request.model_dump(mode="json")))
    token = request.expected_token().serialize()
    monkeypatch.setattr(cli, "_raise_uncertain_after_write", True)
    approval = cli.consume_split_approval(
        raw_token=token,
        request_path=request_path,
        state_path=state_path,
        materialized_bundle_path=MATERIALIZED_BUNDLE,
        approval_path=approval_path,
        nonce_ledger_root=tmp_path / "ledger",
        repo_root=REPO_ROOT,
        approved_at=datetime(2026, 8, 2, 7, 1, tzinfo=UTC),
        require_independent=True,
    )
    rows = (tmp_path / "ledger/authority-consumption-ledger.jsonl").read_bytes().splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0])["completion"] == "RELOOKUP_CONFIRMED"
    assert cli.verify_split_approval(
        approval_path,
        repo_root=REPO_ROOT,
        materialized_bundle_path=MATERIALIZED_BUNDLE,
        require_independent=True,
        request_path=request_path,
        state_path=state_path,
        nonce_ledger_root=tmp_path / "ledger",
    ) == approval
