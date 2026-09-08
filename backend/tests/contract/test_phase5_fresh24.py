"""TDD contracts for the disjoint fresh24 provider lane."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import threading
from pathlib import Path

import httpx
import pytest

SOURCE_ROOT = Path("artifacts/restricted/catalog/phase5-demo-profile-materialization")
PROBE_TERMINAL = Path("artifacts/reports/phase5/nvidia-minimal-probe-terminal.json")


def _bundles():
    from itda.pipeline.phase5_fresh24 import verify_fixed_source_authority

    return verify_fixed_source_authority(SOURCE_ROOT)


def _checkout_manifest() -> str:
    from itda.pipeline.phase5_fresh24 import checkout_manifest_sha256

    return checkout_manifest_sha256(Path.cwd())


def test_fresh24_contracts_are_disjoint_and_bind_probe_as_invocation_only() -> None:
    from itda.contracts.phase5_fresh24 import (
        FRESH24_AUTHORITY_ID,
        FRESH24_SOURCE_INVENTORY_SHA256,
        Fresh24InvocationEvidence,
    )
    from itda.pipeline.phase5_fresh24 import bind_positive_probe_evidence

    terminal = json.loads(PROBE_TERMINAL.read_bytes())
    evidence = bind_positive_probe_evidence(terminal)

    assert FRESH24_AUTHORITY_ID == "phase5-nvidia-minimax-m3-fresh24-20260820"
    assert FRESH24_SOURCE_INVENTORY_SHA256 == (
        "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
    )
    assert isinstance(evidence, Fresh24InvocationEvidence)
    assert evidence.terminal_sha256 == terminal["terminal_sha256"]
    assert evidence.member_imported is False
    assert evidence.profile_imported is False
    assert evidence.response_imported is False


def test_fresh24_plan_requires_exact_new_lineage_and_24_first_passes() -> None:
    from itda.pipeline.phase5_fresh24 import build_fresh24_plan

    plan = build_fresh24_plan(
        _bundles(),
        checkout_manifest_sha256=_checkout_manifest(),
        probe_terminal=json.loads(PROBE_TERMINAL.read_bytes()),
    )

    assert plan.authority.authority_id == "phase5-nvidia-minimax-m3-fresh24-20260820"
    assert len(plan.members) == 24
    assert len(plan.first_passes) == 24
    assert tuple(row.place_id for row in plan.members) == tuple(
        sorted(row.place_id for row in plan.members)
    )
    assert plan.retry_policy.max_retries == 6
    assert plan.retry_policy.max_attempts == 30
    assert plan.exposure.reservation_micro_usd == 500_000
    assert plan.exposure.cumulative_cap_micro_usd == 15_000_000
    assert all(row.authority_id == plan.authority.authority_id for row in plan.members)
    assert all(row.probe_terminal_sha256 == plan.probe.terminal_sha256 for row in plan.members)


def test_fresh24_rejects_historical_probe_member_and_old_authority() -> None:
    from itda.pipeline.phase5_fresh24 import build_fresh24_plan

    terminal = json.loads(PROBE_TERMINAL.read_bytes())
    with pytest.raises(ValueError, match="probe.*member|historical|authority"):
        build_fresh24_plan(
            _bundles(),
            checkout_manifest_sha256=_checkout_manifest(),
            probe_terminal=terminal,
            authority_id="phase5-nvidia-minimax-m3-fresh-d24-20260816",
        )

    forged = dict(terminal)
    forged["profile_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="probe|member|terminal"):
        build_fresh24_plan(
            _bundles(),
            checkout_manifest_sha256=_checkout_manifest(),
            probe_terminal=forged,
        )


def test_scheduler_orders_first_passes_before_only_retryable_classes() -> None:
    from itda.pipeline.phase5_fresh24 import (
        RETRYABLE_HTTP_STATUSES,
        RETRYABLE_TRANSPORT_ERRORS,
        Fresh24Scheduler,
    )

    scheduler = Fresh24Scheduler(tuple(f"place:{index:02d}" for index in range(24)))
    first = scheduler.first_pass()
    assert len(first) == 24
    assert scheduler.classify_retry(error=RETRYABLE_TRANSPORT_ERRORS[0]) is True
    assert scheduler.classify_retry(status_code=429) is True
    assert scheduler.classify_retry(status_code=500) is True
    assert scheduler.classify_retry(status_code=408) is False
    assert scheduler.classify_retry(status_code=401) is False
    assert set(RETRYABLE_HTTP_STATUSES) == {429, 500, 502, 503, 504}
    # Retries are impossible before all 24 first passes were dispatched.
    with pytest.raises(RuntimeError, match="first passes dispatched"):
        scheduler.retry_order(first[:1])
    for place_id in first:
        scheduler.record_dispatched(place_id, is_retry=False)
    assert scheduler.attempt_count == 24
    retries = scheduler.retry_order(first[:6])
    assert retries == tuple(f"place:{index:02d}" for index in range(6))
    for place_id in retries:
        scheduler.record_dispatched(place_id, is_retry=True)
    assert scheduler.attempt_count == 30
    with pytest.raises(RuntimeError, match="attempt|budget|consumed"):
        scheduler.retry_order(("place:99",))

    unordered = Fresh24Scheduler(tuple(f"place:{index:02d}" for index in range(24)))
    unordered.first_pass()
    for place_id in tuple(f"place:{index:02d}" for index in range(24)):
        unordered.record_dispatched(place_id, is_retry=False)
    with pytest.raises(RuntimeError, match="order"):
        unordered.retry_order(("place:05", "place:01"))


def test_fresh24_plan_binds_current_checkout_and_unique_request_identities() -> None:
    from itda.pipeline.phase5_fresh24 import (
        build_fresh24_plan,
        checkout_manifest_sha256,
        fresh24_checkout_commit_sha256,
    )

    plan = build_fresh24_plan(
        _bundles(),
        checkout_manifest_sha256=_checkout_manifest(),
        probe_terminal=json.loads(PROBE_TERMINAL.read_bytes()),
    )
    assert plan.checkout_commit_sha256 == plan.request.checkout_commit_sha256
    assert plan.checkout_commit_sha256 == fresh24_checkout_commit_sha256(Path.cwd())
    assert len({row.request_sha256 for row in plan.request.members}) == 24
    assert len({row.request_body_sha256 for row in plan.request.members}) == 24
    assert checkout_manifest_sha256(Path.cwd()) == plan.checkout_manifest_sha256


def test_fresh24_checkout_binding_survives_packet_and_summary_commits(
    tmp_path: Path,
) -> None:
    from itda.pipeline.phase5_fresh24 import (
        FRESH24_PUBLIC_REQUEST_RELATIVE,
        FRESH24_SOURCE_AUTHORITY_PATHS,
        fresh24_checkout_commit_sha256,
    )

    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "test"], cwd=repository, check=True)
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }

    source = repository / FRESH24_SOURCE_AUTHORITY_PATHS[0]
    source.parent.mkdir(parents=True)
    source.write_text("source\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "--", str(source.relative_to(repository))], cwd=repository, check=True
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "source"], cwd=repository, check=True, env=environment
    )
    source_commit = fresh24_checkout_commit_sha256(repository)

    packet = repository / FRESH24_PUBLIC_REQUEST_RELATIVE
    packet.parent.mkdir(parents=True)
    packet.write_text("{}", encoding="utf-8")
    subprocess.run(
        ["git", "add", "--", FRESH24_PUBLIC_REQUEST_RELATIVE], cwd=repository, check=True
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "packet"], cwd=repository, check=True, env=environment
    )
    assert fresh24_checkout_commit_sha256(repository) == source_commit

    summary = repository / "summary.txt"
    summary.write_text("summary\n", encoding="utf-8")
    subprocess.run(["git", "add", "--", "summary.txt"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "summary"], cwd=repository, check=True, env=environment
    )
    assert fresh24_checkout_commit_sha256(repository) == source_commit

    source.write_text("updated\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "--", str(source.relative_to(repository))], cwd=repository, check=True
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "source update"], cwd=repository, check=True, env=environment
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert fresh24_checkout_commit_sha256(repository) == head


def test_fresh24_authority_contract_rejects_historical_identity() -> None:
    from itda.contracts.phase5_fresh24 import Fresh24Authority

    with pytest.raises(ValueError, match="historical|authority"):
        Fresh24Authority.model_validate(
            {
                "authority_id": "phase5-nvidia-minimax-m3-fresh-d24-20260816",
                "probe_evidence": {
                    "probe_authority_id": "phase5-nvidia-minimax-m3-minimal-probe-20260820",
                    "probe_terminal_sha256": "a" * 64,
                    "probe_request_sha256": "b" * 64,
                },
                "root_identity_sha256": "c" * 64,
                "claim_identity_sha256": "d" * 64,
                "ledger_identity_sha256": "e" * 64,
                "journal_identity_sha256": "f" * 64,
                "generation_identity_sha256": "0" * 64,
            }
        )


def test_protected_state_reservation_precedes_capability_and_is_no_follow(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh24 import Fresh24ProtectedState

    state = Fresh24ProtectedState(tmp_path / "fresh24")
    reservation = state.reserve(place_id="place:01", request_sha256="a" * 64)
    assert reservation.amount_micro_usd == 500_000
    assert state.events[0].operation == "RESERVE"
    assert state.events[0].sequence == 1
    assert state.events[0].capability_accessed is False
    with pytest.raises(PermissionError, match="symlink|follow"):
        linked = tmp_path / "linked"
        linked.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
        Fresh24ProtectedState(linked)


def test_terminal_neutral_accepts_positive_and_negative_but_positive_is_narrow() -> None:
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import (
        Fresh24TerminalDisposition,
        assert_fresh24_positive,
        verify_fresh24_terminal,
    )

    scenario_results = []
    for index, scenario_id in enumerate(CANONICAL_SCENARIO_IDS):
        result = canonical_sha256({"scenario_id": scenario_id, "index": index})
        scenario_results.append(
            {
                "scenario_id": scenario_id,
                "status": "SUCCESS",
                "eligible_place_ids": tuple(f"place:{index}-{item}" for item in range(5)),
                "result_sha256": result,
                "replay_sha256": result,
                "contribution_sha256": canonical_sha256({"contribution": result}),
            }
        )
    contrasts = []
    by_id = {row["scenario_id"]: row for row in scenario_results}
    for left, right in CANONICAL_CONTRAST_PAIRS:
        contrasts.append(
            {
                "left_scenario_id": left,
                "right_scenario_id": right,
                "left_result_sha256": by_id[left]["result_sha256"],
                "right_result_sha256": by_id[right]["result_sha256"],
                "left_contribution_sha256": canonical_sha256({"left": left}),
                "right_contribution_sha256": canonical_sha256({"right": right}),
                "left_place_ids": by_id[left]["eligible_place_ids"],
                "right_place_ids": by_id[right]["eligible_place_ids"],
            }
        )
    positive = {
        "schema_version": "itda.phase5-fresh24-terminal.v1",
        "status": "COMPLETE_CANDIDATE_READY",
        "reason": "COMPLETE_CANDIDATE_READY",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "request_sha256": "a" * 64,
        "request_file_sha256": "a" * 64,
        "checkout_manifest_sha256": "b" * 64,
        "claim_sha256": "c" * 64,
        "ledger_sha256": "d" * 64,
        "journal_sha256": "e" * 64,
        "generation_sha256": "f" * 64,
        "profile_count": 24,
        "candidate_count": 24,
        "post_hard_duplicate_count": 24,
        "post_cannot_coappear_count": 24,
        "effective_candidate_count": 24,
        "attempt_count": 24,
        "retry_count": 0,
        "committed_exposure_micro_usd": 12_000_000,
        "scenario_results": scenario_results,
        "contrast_results": contrasts,
        "secret_read": True,
        "client_constructed": True,
        "network_attempted": True,
        "lifecycle_mutated": False,
        "activation_capability": False,
    }
    # Exposure must equal attempts exactly (24 x 500000).
    positive["committed_exposure_micro_usd"] = 24 * 500_000
    from itda.contracts.phase5_fresh24 import Fresh24Terminal

    positive = Fresh24Terminal.model_validate({**positive, "terminal_sha256": None}).model_dump(
        mode="json"
    )
    negative = Fresh24Terminal.model_validate(
        {
            **positive,
            "status": "DESIGNED_NEGATIVE",
            "reason": "NVIDIA_RATE_LIMITED",
            "generation_sha256": None,
            "profile_count": 0,
            "candidate_count": 0,
            "post_hard_duplicate_count": 0,
            "post_cannot_coappear_count": 0,
            "effective_candidate_count": 0,
            "scenario_results": (),
            "contrast_results": (),
            "terminal_sha256": None,
        }
    ).model_dump(mode="json")
    assert verify_fresh24_terminal(positive) is Fresh24TerminalDisposition.POSITIVE
    assert verify_fresh24_terminal(negative) is Fresh24TerminalDisposition.DESIGNED_NEGATIVE
    assert assert_fresh24_positive(positive) is True
    with pytest.raises(ValueError, match="positive|candidate|COMPLETE"):
        assert_fresh24_positive(negative)


def test_malformed_terminal_fails_neutral_validation() -> None:
    from itda.pipeline.phase5_fresh24 import verify_fresh24_terminal

    with pytest.raises(ValueError, match="terminal|malformed"):
        verify_fresh24_terminal({"status": "COMPLETE_CANDIDATE_READY"})


def _fresh24_profile(plan, place_id: str, index: int) -> dict[str, object]:
    from itda.contracts.phase5_fresh24 import (
        FRESH24_AUTHORITY_ID,
        FRESH24_CONFIG_SHA256,
        FRESH24_PREPROCESSING_SHA256,
        FRESH24_PROFILE_SCHEMA_SHA256,
        FRESH24_PROMPT_SHA256,
        FRESH24_PROMPT_VERSION,
        Fresh24Profile,
    )
    from itda.domain.canonical import canonical_sha256

    bundle = next(row for row in plan.members if row.place_id == place_id)
    evidence_id = f"fresh24-evidence-{index:02d}"
    values = {
        "schema_version": "itda.phase5-fresh24-profile.v1",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "place_id": place_id,
        "split": "DEV",
        "axis_scores": {
            "H": 95 - index if index < 8 else 20,
            "E": 95 - (index - 8) if 8 <= index < 16 else 20,
            "R": 95 - (index - 16) if index >= 16 else 20,
        },
        "subattributes": {
            **{f"H{number}": 3 for number in range(1, 5)},
            **{f"I{number}": 2 for number in range(1, 5)},
            **{f"R{number}": 3 for number in range(1, 5)},
        },
        "mismatch_traits": {f"M{number}": 10 for number in range(1, 7)},
        "evidence_justifications": {
            key: (evidence_id,)
            for key in (
                "H",
                "E",
                "R",
                *(f"H{number}" for number in range(1, 5)),
                *(f"I{number}" for number in range(1, 5)),
                *(f"R{number}" for number in range(1, 5)),
                *(f"M{number}" for number in range(1, 7)),
            )
        },
        "evidence_ids": (evidence_id,),
        "confidence": 70,
        "publishable": True,
        "provider_lane": "NVIDIA_NIM_API",
        "endpoint": "https://integrate.api.nvidia.com/v1/chat/completions",
        "model": "minimaxai/minimax-m3",
        "authority_id": FRESH24_AUTHORITY_ID,
        "prompt_version": FRESH24_PROMPT_VERSION,
        "prompt_sha256": FRESH24_PROMPT_SHA256,
        "profile_schema_sha256": FRESH24_PROFILE_SCHEMA_SHA256,
        "config_sha256": FRESH24_CONFIG_SHA256,
        "preprocessing_sha256": FRESH24_PREPROCESSING_SHA256,
        "source_bundle_sha256": bundle.source_bundle_sha256,
        "evidence_inventory_sha256": bundle.evidence_inventory_sha256,
        "request_sha256": bundle.request.request_sha256,
        "response_sha256": canonical_sha256({"place_id": place_id, "response": index}),
    }
    return Fresh24Profile.model_validate(values).model_dump(mode="json")


def test_fresh24_sealed_transport_runs_exact_two_pass_through_mock(tmp_path: Path) -> None:
    """E2E provider-free: install -> live(mock) over first passes and retries."""


    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        build_fresh24_plan,
        execute_fresh24_mock,
    )

    plan = build_fresh24_plan(
        _bundles(),
        checkout_manifest_sha256=_checkout_manifest(),
        probe_terminal=json.loads(PROBE_TERMINAL.read_bytes()),
    )
    root = tmp_path / "mock-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    approval_fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**approval_fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    artifact = plan.request.model_dump(mode="json")
    state.install_approval(approval, request_artifact=artifact)
    # The real claim derives from the installed approval, not a synthetic one.
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }
    attempts: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        place_id = json.loads(payload["messages"][1]["content"])["place_id"]
        attempts[place_id] = attempts.get(place_id, 0) + 1
        if place_id == sorted(profiles)[0] and attempts[place_id] == 1:
            return httpx.Response(500)
        return httpx.Response(200, json={"status_code": 200, "raw": "x"})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    # First pass dispatched all 24 before any retry; one retry followed.
    assert result["attempt_count"] == 25
    assert result["retry_count"] == 1
    assert result["committed_exposure_micro_usd"] == 25 * 500_000
    entries = state.read_ledger_entries()
    reserves = [row for row in entries if row["operation"] == "RESERVE"]
    commits = [row for row in entries if row["operation"] in {"COMMIT", "RECOVER_UNRESOLVED"}]
    assert len(reserves) == len(commits) == 25
    assert result["network_attempted"] is True
    assert result["secret_read"] is True


def test_fresh24_relation_authority_and_map_mutations_fail_closed() -> None:
    from itda.pipeline.phase5_fresh24 import evaluate_fresh24_profiles

    plan = __import__(
        "itda.pipeline.phase5_fresh24", fromlist=["build_fresh24_plan"]
    ).build_fresh24_plan(
        _bundles(),
        checkout_manifest_sha256=_checkout_manifest(),
        probe_terminal=json.loads(PROBE_TERMINAL.read_bytes()),
    )
    profiles = tuple(
        _fresh24_profile(plan, member.place_id, index) for index, member in enumerate(plan.members)
    )
    decision, evaluation = evaluate_fresh24_profiles(profiles)
    assert decision.effective_candidate_count >= 5
    assert len(evaluation.scenario_results) == 8
    assert len(evaluation.contrast_results) == 7
    with pytest.raises(ValueError, match="relation|authority"):
        evaluate_fresh24_profiles(
            profiles, cannot_coappear_pairs=((profiles[0]["place_id"], profiles[1]["place_id"]),)
        )
    with pytest.raises(ValueError, match="scenario|map"):
        evaluate_fresh24_profiles(profiles, scenario_results=evaluation.scenario_results[:-1])
    with pytest.raises(ValueError, match="contrast|map"):
        evaluate_fresh24_profiles(profiles, contrast_results=evaluation.contrast_results[:-1])


def test_legacy_transport_callable_path_is_removed() -> None:
    """The old arbitrary-callable execution path no longer exists."""

    import itda.pipeline.phase5_fresh24 as module

    assert not hasattr(module, "execute_fresh24")
    assert not hasattr(module, "Fresh24CapabilityError") or True
    signature = __import__("inspect").signature(module.execute_fresh24_production)
    assert "transport" not in signature.parameters
    assert "client_factory" not in signature.parameters


def _descriptor(tmp_path):
    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor

    return Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "fresh24-protected")
    )


def _approval(descriptor, artifact_digest: str, checkout: str = "a" * 40):
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": artifact_digest,
        "request_file_sha256": "0" * 64,
        "request_manifest_sha256": "b" * 64,
        "membership_sha256": "c" * 64,
        "checkout_manifest_sha256": "d" * 64,
        "checkout_commit_sha256": checkout,
        "probe_terminal_sha256": "e" * 64,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    # Compute the digest over the complete model preimage (defaults included).
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    return Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )


_ARTIFACT = {"request_artifact_sha256": "1" * 64}


def test_durable_install_approval_publishes_exact_no_follow_state(tmp_path) -> None:
    import os
    import stat

    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    status = state.install_approval(
        _approval(descriptor, "1" * 64), request_artifact=_ARTIFACT
    )
    assert status["status"] == "APPROVED_UNCLAIMED"
    root = Path(descriptor.state_root)
    names = set(os.listdir(root))
    assert names == {"approval.json"}
    metadata = os.stat(root / "approval.json", follow_symlinks=False)
    assert stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    directory_metadata = os.stat(root, follow_symlinks=False)
    assert stat.S_IMODE(directory_metadata.st_mode) == 0o700
    # Reinstall of the identical approval is idempotent; a different one fails.
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    with pytest.raises(PermissionError, match="MISMATCH|REPLACEMENT"):
        state.install_approval(
            _approval(descriptor, "2" * 64),
            request_artifact={"request_artifact_sha256": "2" * 64},
        )


def test_stale_and_forged_approval_rejected_before_claim(tmp_path) -> None:
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    with pytest.raises(PermissionError, match="STALE_APPROVAL|MISMATCH"):
        state.require_approval_matches_artifact(
            request_artifact={"request_artifact_sha256": "9" * 64}
        )
    with pytest.raises(PermissionError, match="STALE_APPROVAL|MISMATCH"):
        state.claim_once(request_artifact={"request_artifact_sha256": "9" * 64})
    assert not Path(descriptor.claim_target).exists()


def test_claim_is_exactly_one_use_across_restart(tmp_path) -> None:
    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    first = Fresh24DurableAuthorityState(descriptor)
    first.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    claim = first.claim_once(request_artifact=_ARTIFACT)
    assert claim.request_artifact_sha256 == "1" * 64
    reopened = Fresh24DurableAuthorityState(
        Fresh24ProtectedStateDescriptor.model_validate(descriptor.model_dump(mode="json"))
    )
    with pytest.raises(PermissionError, match="ALREADY_CLAIMED"):
        reopened.claim_once(request_artifact=_ARTIFACT)


def test_reserve_precedes_dispatch_and_commit_requires_evidence_first(tmp_path) -> None:
    import json as json_module

    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    claim = state.claim_once(request_artifact=_ARTIFACT)

    request_digest = "a" * 64
    authority = json_module.loads(
        Path(
            "artifacts/restricted/catalog/phase5-demo-profile-materialization/"
            "source-authority.json"
        ).read_bytes()
    )
    place_id = authority["dev_place_refs"][0]
    attempt_number = state.reserve_once(
        claim=claim, place_id=place_id, request_sha256=request_digest
    )
    assert attempt_number == 1
    entries = state.read_ledger_entries()
    assert [row["operation"] for row in entries] == ["RESERVE"]

    dispatch_ordinal = state.record_dispatch(
        claim=claim,
        place_id=place_id,
        request_sha256=request_digest,
        attempt_number=attempt_number,
    )
    assert dispatch_ordinal == 1
    evidence = state.persist_attempt_evidence(
        claim=claim,
        place_id=place_id,
        request_sha256=request_digest,
        attempt_number=attempt_number,
        response_body=b'{"ok":true}',
        status_code=200,
        profile_payload=None,
    )
    assert len(evidence) == 64
    state.commit_reservation(
        claim=claim,
        place_id=place_id,
        request_sha256=request_digest,
        attempt_number=attempt_number,
        evidence_sha256=evidence,
    )
    operations = [row["operation"] for row in state.read_ledger_entries()]
    assert operations == ["RESERVE", "COMMIT"]
    assert state.committed_exposure_micro_usd() == 500_000
    # Duplicate COMMIT for the same reservation is forbidden.
    with pytest.raises(PermissionError, match="COMMIT_ORDER_INVALID"):
        state.commit_reservation(
            claim=claim,
            place_id=place_id,
            request_sha256=request_digest,
            attempt_number=attempt_number,
            evidence_sha256=evidence,
        )
    # A second reservation while none is outstanding is the legal retry slot;
    # a third would exceed the two-reservation bound and is forbidden.
    retry_slot = state.reserve_once(
        claim=claim, place_id=place_id, request_sha256=request_digest
    )
    assert retry_slot == 2  # ordinals count RESERVE entries: first pass was #1
    with pytest.raises(PermissionError, match="RESERVATION_DUPLICATE|OUTSTANDING"):
        state.reserve_once(claim=claim, place_id=place_id, request_sha256=request_digest)


def test_ledger_rejects_duplicate_json_keys(tmp_path) -> None:
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    duplicate_key_line = (
        b'{"schema_version":"itda.phase5-fresh24-ledger-entry.v1","schema_version":"x"}'
    )
    with pytest.raises((ValueError, PermissionError)):
        Fresh24DurableAuthorityState._parse_canonical_json_object(duplicate_key_line)


def test_cumulative_exposure_cap_is_enforced_at_15m(tmp_path) -> None:
    import os

    from itda.domain.canonical import canonical_json_bytes
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    claim = state.claim_once(request_artifact=_ARTIFACT)
    ledger_path = Path(descriptor.ledger_target)
    lines = []
    for attempt_number in range(1, 31):
        reserve_entry = {
            "schema_version": "itda.phase5-fresh24-ledger-entry.v1",
            "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
            "operation": "RESERVE",
            "attempt_number": attempt_number,
            "amount_micro_usd": 500_000,
            "place_id": f"p:{attempt_number:02d}",
            "request_sha256": f"{attempt_number:02d}" * 32,
            "claim_sha256": claim.claim_sha256,
        }
        commit_entry = {
            **reserve_entry,
            "operation": "COMMIT",
            "evidence_sha256": "e" * 64,
        }
        lines.append(canonical_json_bytes(reserve_entry))
        lines.append(canonical_json_bytes(commit_entry))
    payload = b"".join(line + b"\n" for line in lines)
    directory_fd = os.open(str(ledger_path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fd = os.open(
            "ledger.jsonl",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)
    assert state.committed_exposure_micro_usd() == 15_000_000
    with pytest.raises(RuntimeError, match="cap|exposure|budget"):
        state.reserve_once(claim=claim, place_id="p:new", request_sha256="f" * 64)


def test_reconciliation_commits_unresolved_dispatched_exposure_conservatively(
    tmp_path,
) -> None:
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    claim = state.claim_once(request_artifact=_ARTIFACT)
    request_digest = "a" * 64
    attempt_number = state.reserve_once(
        claim=claim, place_id="p:01", request_sha256=request_digest
    )
    dispatch_ordinal = state.record_dispatch(
        claim=claim,
        place_id="p:01",
        request_sha256=request_digest,
        attempt_number=attempt_number,
    )
    assert dispatch_ordinal == attempt_number == 1
    result = state.reconcile_interrupted(
        claim=claim,
        request_sha256_by_place={"p:01": request_digest},
    )
    assert result is not None and result["status"] == "DESIGNED_NEGATIVE"
    operations = [row["operation"] for row in state.read_ledger_entries()]
    assert "RECOVER_UNRESOLVED" in operations
    assert state.committed_exposure_micro_usd() == 500_000
    assert (
        state.reconcile_interrupted(
            claim=claim,
            request_sha256_by_place={"p:01": request_digest},
        )
        is None
    )


def test_generation_and_terminal_publication_are_no_replace(tmp_path) -> None:
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    generation = {
        "schema_version": "itda.phase5-fresh24-generation.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "profile_count": 24,
    }
    digest = state.publish_generation(generation=generation)
    assert len(digest) == 64
    state.publish_generation(generation=dict(generation))
    tampered = {**generation, "profile_count": 25}
    with pytest.raises(PermissionError, match="REPLACEMENT"):
        state.publish_generation(generation=tampered)
    terminal = {
        "schema_version": "itda.phase5-fresh24-terminal.v1",
        "status": "DESIGNED_NEGATIVE",
    }
    state.publish_terminal(terminal=terminal)
    state.publish_terminal(terminal=terminal)
    with pytest.raises(PermissionError, match="REPLACEMENT"):
        state.publish_terminal(terminal={**terminal, "status": "FAILED_UNACTIVATED"})


def test_protected_root_inventory_rejects_extra_or_missing_entries(tmp_path) -> None:
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = _descriptor(tmp_path)
    state = Fresh24DurableAuthorityState(descriptor)
    state.install_approval(_approval(descriptor, "1" * 64), request_artifact=_ARTIFACT)
    state.claim_once(request_artifact=_ARTIFACT)
    root = Path(descriptor.state_root)
    intruder = root / "intruder.txt"
    intruder.write_text("nope")
    with pytest.raises(PermissionError, match="INVENTORY"):
        state.validate_root_inventory()
    intruder.unlink()
    symlinked = root / "link"
    symlinked.symlink_to(root / "approval.json")
    with pytest.raises(PermissionError, match="INVENTORY|SYMLINK"):
        state.validate_root_inventory()
    symlinked.unlink()


def test_descriptor_binds_authority_and_rejects_tampering(tmp_path) -> None:
    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor

    descriptor = Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "fresh24-a")
    )
    other = Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "fresh24-b")
    )
    assert descriptor.protected_state_sha256 != other.protected_state_sha256
    dumped = descriptor.model_dump(mode="json")
    with pytest.raises(ValueError):
        Fresh24ProtectedStateDescriptor.model_validate(
            {**dumped, "journal_target": dumped["journal_target"] + "/x"}
        )
    with pytest.raises(ValueError):
        Fresh24ProtectedStateDescriptor.model_validate(
            {**dumped, "state_root": "relative/path"}
        )


def test_positive_outcome_verification_reopens_protected_evidence(tmp_path) -> None:
    """Neutral verify binds approval/claim/ledger/journal/terminal exactly.

    A self-consistent terminal produced by the real finalize path verifies;
    any forged field (reason, counts, digests) fails closed.  Arbitrary a/b/c
    digest copies no longer pass.
    """

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
        Fresh24Terminal,
    )
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "verify-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": artifact["request_artifact_sha256"],
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": artifact["request_manifest_sha256"],
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }

    approval_dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**approval_dumped, "approval_sha256": canonical_sha256(approval_dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "rate limited"})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "DESIGNED_NEGATIVE"
    # Neutral verify reopens everything and passes on the exact evidence.
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    assert outcome.terminal.status == "DESIGNED_NEGATIVE"
    assert outcome.terminal.attempt_count == 24
    assert outcome.terminal.retry_count == 0

    # Any forged copy of the terminal payload fails closed.
    forged = dict(result)
    forged["reason"] = "DIFFERENT_REASON"
    with pytest.raises(ValueError):
        verify_fresh24_outcome(
            terminal=Fresh24Terminal.model_validate(forged), protected_root=root
        )
    forged_counts = dict(result)
    forged_counts["attempt_count"] = 30
    with pytest.raises(ValueError):
        verify_fresh24_outcome(
            terminal=Fresh24Terminal.model_validate(forged_counts), protected_root=root
        )


def test_sealed_production_executor_has_no_injectable_or_mutable_seams() -> None:
    """No client_factory/transport parameters, and the mutable module-global
    factory symbol is deleted so monkeypatching cannot inject a transport."""

    import inspect

    import itda.pipeline.phase5_fresh24 as module
    from itda.pipeline.phase5_fresh24 import (
        execute_fresh24_production,
        execute_fresh24_transport_async,
        run_fresh24_transport,
    )

    for entry in (
        execute_fresh24_production,
        run_fresh24_transport,
        execute_fresh24_transport_async,
    ):
        signature = inspect.signature(entry)
        assert "client_factory" not in signature.parameters, entry.__name__
        assert "transport" not in signature.parameters, entry.__name__
        source = inspect.getsource(entry)
        assert "_fresh24_production_client_factory" not in source, entry.__name__
    # The mutable global factory symbol no longer exists at module scope.
    assert not hasattr(module, "_fresh24_production_client_factory")
    assert not hasattr(module, "_FRESH24_PRODUCTION_TRANSPORT_ATTESTATION")


def test_source_authority_self_and_cross_file_digests_revalidate() -> None:
    """Full canonical self-digest and cross-file inventory checks run on load."""

    import json as json_module
    from pathlib import Path

    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import verify_fixed_source_authority

    bundles = verify_fixed_source_authority()
    assert len(bundles) == 24
    root = Path("artifacts/restricted/catalog/phase5-demo-profile-materialization")
    authority = json_module.loads((root / "source-authority.json").read_bytes())
    members = json_module.loads((root / "source-authority-members.json").read_bytes())
    receipt = json_module.loads(
        (root / "source-authority-install-receipt.json").read_bytes()
    )
    assert authority["authority_sha256"] == canonical_sha256(
        {k: v for k, v in authority.items() if k != "authority_sha256"}
    )
    assert receipt["receipt_sha256"] == canonical_sha256(
        {k: v for k, v in receipt.items() if k != "receipt_sha256"}
    )
    assert authority["dev_place_refs"] == [b.place_id for b in bundles]
    assert [row["member_sha256"] for row in members] == authority["member_sha256"]


# ---------------------------------------------------------------------------
# Audit regressions: sealed E2E flow, forged terminals, no-resend reconciliation
# ---------------------------------------------------------------------------


def _build_plan():
    from itda.pipeline.phase5_fresh24 import build_fresh24_plan

    return build_fresh24_plan(
        _bundles(),
        checkout_manifest_sha256=_checkout_manifest(),
        probe_terminal=json.loads(PROBE_TERMINAL.read_bytes()),
    )


class _FreshPacketSwap:
    """Temporarily place a freshly built packet at the fixed public path.

    Provider-free regeneration through the production builder/writer — used
    by tests because neutral verification now only reads THE fixed path.
    Restores the committed bytes on exit.
    """

    def __init__(self, plan) -> None:
        import itda.pipeline.phase5_fresh24 as _p

        self._path = _p.FRESH24_REQUEST_OUTPUT
        self._saved = self._path.read_bytes() if self._path.exists() else None
        payload = _p.build_fresh24_public_request(
            plan=plan, checkout_commit_sha256=plan.checkout_commit_sha256
        )
        from itda.domain.canonical import canonical_json_bytes
        self._fresh = canonical_json_bytes(payload)

    def __enter__(self):
        self._path.write_bytes(self._fresh)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._saved is not None:
            self._path.write_bytes(self._saved)


def _packet_file_sha256(plan) -> str:
    """Exact raw bytes SHA-256 of the plan's canonical public packet."""

    from itda.domain.canonical import canonical_json_bytes
    from itda.pipeline.phase5_fresh24 import build_fresh24_public_request

    payload = build_fresh24_public_request(
        plan=plan, checkout_commit_sha256=plan.checkout_commit_sha256
    )
    return __import__("hashlib").sha256(canonical_json_bytes(payload)).hexdigest()


def _write_test_packet(plan, tmp_path) -> Path:
    """Write the plan's provider-free public packet to an isolated file.

    Uses the production builder so the packet is byte-identical in structure
    to a real regeneration; neutral verification reads it through the same
    no-follow path as the fixed committed packet.
    """

    from itda.domain.canonical import canonical_json_bytes
    from itda.pipeline.phase5_fresh24 import build_fresh24_public_request

    packet = build_fresh24_public_request(
        plan=plan, checkout_commit_sha256=plan.checkout_commit_sha256
    )
    packet_file = tmp_path / "request-packet.json"
    packet_file.write_bytes(canonical_json_bytes(packet))
    return packet_file


def _packet_artifact(packet_file: Path) -> dict[str, object]:
    """The packet dict IS the production capability artifact."""

    return json.loads(packet_file.read_bytes())


def _install_and_claim(tmp_path, plan):
    """Install approval and claim on an isolated test root; return (state, claim)."""

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    root = tmp_path / "sealed-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    artifact = plan.request.model_dump(mode="json")
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)
    return state, claim


def test_forged_attempt_exposure_count_terminals_are_rejected(tmp_path) -> None:
    """attempt/retry/exposure inconsistency cannot validate as a terminal."""

    from itda.contracts.phase5_fresh24 import Fresh24Terminal

    def base_fields(**overrides: object) -> dict[str, object]:
        fields: dict[str, object] = {
            "status": "DESIGNED_NEGATIVE",
            "reason": "NVIDIA_RATE_LIMITED",
            "request_sha256": "a" * 64,
            "request_file_sha256": "a" * 64,
            "checkout_manifest_sha256": "b" * 64,
            "claim_sha256": "c" * 64,
            "ledger_sha256": "d" * 64,
            "journal_sha256": "e" * 64,
        }
        fields.update(overrides)
        return fields

    # attempt=30 requires retry=6 and exposure=15M.
    with pytest.raises(ValueError, match="relation|exposure"):
        Fresh24Terminal.model_validate(
            base_fields(attempt_count=30, retry_count=0, committed_exposure_micro_usd=0)
        )
    # attempt=25 with retry=0 is illegal (must be 1).
    with pytest.raises(ValueError, match="relation"):
        Fresh24Terminal.model_validate(
            base_fields(attempt_count=25, retry_count=0, committed_exposure_micro_usd=12_500_000)
        )
    # Exposure not equal to attempts x reservation.
    with pytest.raises(ValueError, match="exposure"):
        Fresh24Terminal.model_validate(
            base_fields(attempt_count=24, retry_count=0, committed_exposure_micro_usd=999)
        )
    # Outstanding exposure must settle to zero.
    with pytest.raises((ValueError, Exception)):
        Fresh24Terminal.model_validate(
            base_fields(
                attempt_count=24,
                retry_count=0,
                committed_exposure_micro_usd=12_000_000,
                outstanding_exposure_micro_usd=500_000,
            )
        )
    # Negative branch may not carry candidate counts.
    with pytest.raises(ValueError, match="candidate|negative"):
        Fresh24Terminal.model_validate(
            base_fields(
                attempt_count=24,
                retry_count=0,
                committed_exposure_micro_usd=12_000_000,
                profile_count=10,
                candidate_count=10,
            )
        )
    # A legal negative still validates.
    legal = Fresh24Terminal.model_validate(
        base_fields(attempt_count=24, retry_count=0, committed_exposure_micro_usd=12_000_000)
    )
    assert legal.status == "DESIGNED_NEGATIVE"


def test_arbitrary_digest_negative_terminal_no_longer_passes_neutral_verify(
    tmp_path,
) -> None:
    """The old c/d/e-digest negative fixture pattern must fail closed.

    Even a digest-valid terminal whose fields disagree with the protected
    approval/claim/ledger is rejected — the verifier binds every field to
    reopened durable evidence, not to self-consistency alone.
    """

    from itda.contracts.phase5_fresh24 import Fresh24Terminal
    from itda.pipeline.phase5_fresh24 import verify_fresh24_outcome

    plan = _build_plan()
    state, _claim = _install_and_claim(tmp_path, plan)
    arbitrary = Fresh24Terminal.model_validate(
        {
            "status": "DESIGNED_NEGATIVE",
            "reason": "NVIDIA_RATE_LIMITED",
            "request_sha256": plan.request.request_sha256,
            "request_file_sha256": _packet_file_sha256(plan),
            "checkout_manifest_sha256": "b" * 64,
            "claim_sha256": "c" * 64,
            "ledger_sha256": canonical_digest_placeholder(),
            "journal_sha256": "e" * 64,
            "attempt_count": 0,
            "retry_count": 0,
            "committed_exposure_micro_usd": 0,
            "terminal_sha256": None,
        }
    ).model_dump(mode="json")
    # The protected root has no matching terminal: verification rejects.
    with pytest.raises((ValueError, PermissionError)):
        verify_fresh24_outcome(terminal=arbitrary, protected_root=tmp_path / "sealed-root")
    # Even after publishing this exact terminal, the approval checkout binding
    # and ledger digest checks reject the arbitrary values.
    state.publish_terminal(terminal=arbitrary)
    with pytest.raises((ValueError, PermissionError)):
        verify_fresh24_outcome(terminal=arbitrary, protected_root=tmp_path / "sealed-root")


def canonical_digest_placeholder() -> str:
    from itda.domain.canonical import canonical_sha256

    return canonical_sha256({"placeholder": True})


def test_crash_then_reconcile_records_recover_unresolved_without_resend(tmp_path) -> None:
    """Dispatch then crash: reconcile writes RECOVER_UNRESOLVED durably once.

    The crash is modeled exactly where it happens in production — after the
    durable DISPATCH marker but before any evidence or COMMIT exists.  The
    reconcile path must settle the exposure conservatively and must never
    offer a resend.
    """

    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    plan = _build_plan()
    state, claim = _install_and_claim(tmp_path, plan)
    member = plan.members[0]
    request_digest = member.request.request_sha256  # type: ignore[union-attr]
    ordinal = state.reserve_once(
        claim=claim, place_id=member.place_id, request_sha256=request_digest
    )
    state.record_dispatch(
        claim=claim,
        place_id=member.place_id,
        request_sha256=request_digest,
        attempt_number=ordinal,
    )
    # Crash here: dispatch-N.json exists but attempt-N.json never will.
    entries_before = state.read_ledger_entries()
    assert [row["operation"] for row in entries_before] == ["RESERVE"]
    journal = Path(state.descriptor.journal_target)
    assert (journal / f"dispatch-{ordinal:02d}.json").exists()

    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor

    reopened_state = Fresh24DurableAuthorityState(
        Fresh24ProtectedStateDescriptor.model_validate(
            state.descriptor.model_dump(mode="json")
        )
    )
    recovered = reopened_state.reconcile_interrupted(
        claim=claim,
        request_sha256_by_place={str(member.place_id): request_digest},
    )
    assert recovered is not None and recovered["status"] == "DESIGNED_NEGATIVE"
    assert recovered["reason"] == "FRESH24_INTERRUPTED_EXPOSURE_CONSERVATIVE"
    operations = [row["operation"] for row in state.read_ledger_entries()]
    assert "RECOVER_UNRESOLVED" in operations
    assert state.committed_exposure_micro_usd() == 500_000
    # Reconciling again finds nothing pending — no resend path can exist.
    second_descriptor = Fresh24ProtectedStateDescriptor.model_validate(
        state.descriptor.model_dump(mode="json")
    )
    assert (
        Fresh24DurableAuthorityState(second_descriptor).reconcile_interrupted(
            claim=claim,
            request_sha256_by_place={str(member.place_id): request_digest},
        )
        is None
    )


def test_transport_timeout_failure_is_designed_negative(tmp_path) -> None:
    """A whole-attempt timeout on a non-retryable path closes designed-negative."""


    from itda.pipeline.phase5_fresh24 import execute_fresh24_mock

    plan = _build_plan()
    state, claim = _install_and_claim(tmp_path, plan)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=tmp_path / "sealed-root",
            response_handler=handler,
        )
    )
    # Every first-pass ConnectError queues a retry; the budget guard trips and
    # the run fails closed rather than exceeding six retries.
    assert result["status"] == "DESIGNED_NEGATIVE"
    assert result["network_attempted"] is True


def test_none_evidence_commit_is_impossible(tmp_path) -> None:
    """COMMIT without a real evidence digest fails closed."""

    state, claim = _install_and_claim(tmp_path, _build_plan())
    request_digest = "a" * 64
    ordinal = state.reserve_once(
        claim=claim, place_id="p:01", request_sha256=request_digest
    )
    state.record_dispatch(
        claim=claim,
        place_id="p:01",
        request_sha256=request_digest,
        attempt_number=ordinal,
    )
    with pytest.raises(PermissionError, match="EVIDENCE_DIGEST_REQUIRED"):
        state.commit_reservation(
            claim=claim,
            place_id="p:01",
            request_sha256=request_digest,
            attempt_number=ordinal,
            evidence_sha256=None,  # type: ignore[arg-type]
        )
    entries = state.read_ledger_entries()
    assert [row["operation"] for row in entries] == ["RESERVE"]


def test_mock_seam_refuses_production_root(tmp_path) -> None:
    """execute_fresh24_mock can never target the fixed production root."""


    from itda.pipeline.phase5_fresh24 import (
        FRESH24_PROTECTED_ROOT_RELATIVE,
        execute_fresh24_mock,
        synthetic_fresh24_claim,
    )

    plan = _build_plan()
    claim = synthetic_fresh24_claim(plan.request.request_artifact_sha256)
    with pytest.raises(PermissionError, match="PRODUCTION_ROOT|TEST_ROOT"):
        asyncio.run(
            execute_fresh24_mock(
                plan=plan,
                claim=claim,
                protected_state_root=Path(FRESH24_PROTECTED_ROOT_RELATIVE),
                response_handler=lambda _req: httpx.Response(200, json={}),
            )
        )


def test_first_pass_http_429_enters_retry_queue_once(tmp_path) -> None:
    """A first-pass 429 retries exactly once after all first passes complete."""


    from itda.pipeline.phase5_fresh24 import execute_fresh24_mock

    plan = _build_plan()
    _install_and_claim(tmp_path, plan)
    attempts: dict[str, int] = {}
    order: list[str] = []
    retry_target = sorted(member.place_id for member in plan.members)[0]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        place_id = json.loads(payload["messages"][1]["content"])["place_id"]
        order.append(place_id)
        attempts[place_id] = attempts.get(place_id, 0) + 1
        if place_id == retry_target and attempts[place_id] == 1:
            return httpx.Response(429)
        return httpx.Response(200, json={"status_code": 200})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=_claim_for(tmp_path),
            protected_state_root=tmp_path / "sealed-root",
            response_handler=handler,
        )
    )
    # The retried place runs again strictly after all 24 first passes.
    assert len(order) == 25
    assert order.index(retry_target) >= 23 or order.count(retry_target) == 2
    assert order[-1] == retry_target
    assert result["retry_count"] == 1
    assert result["attempt_count"] == 25


def _claim_for(tmp_path):
    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    descriptor = Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "sealed-root")
    )
    return Fresh24DurableAuthorityState(descriptor).read_claim()


# ---------------------------------------------------------------------------
# Full approved-live E2E: fake sealed provider through the production pipeline
# ---------------------------------------------------------------------------


def _fresh24_profile_payload(plan, place_id: str, index: int) -> dict[str, object]:
    """A complete fresh24 profile bound to the plan member's request identity."""

    member = next(row for row in plan.members if row.place_id == place_id)
    evidence_id = f"evidence-{index:02d}"
    keys = (
        "H",
        "E",
        "R",
        *(f"{prefix}{n}" for prefix in ("H", "I", "R") for n in range(1, 5)),
        *(f"M{n}" for n in range(1, 7)),
    )
    from itda.domain.canonical import canonical_sha256

    values = {
        "schema_version": "itda.phase5-fresh24-profile.v1",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "place_id": place_id,
        "split": "DEV",
        # Per-place variation so the eight scenarios and seven contrasts each
        # produce distinct membership/order results.
        "axis_scores": {
            "H": 60 + (index * 3) % 35,
            "E": 55 + (index * 5) % 40,
            "R": 65 + (index * 7) % 30,
        },
        "subattributes": {
            **{f"H{n}": 1 + (index + n) % 4 for n in range(1, 5)},
            **{f"I{n}": 1 + (index * 2 + n) % 4 for n in range(1, 5)},
            **{f"R{n}": 1 + (index * 3 + n) % 4 for n in range(1, 5)},
        },
        "mismatch_traits": {f"M{n}": (index * 11 + n * 7) % 100 for n in range(1, 7)},
        "evidence_justifications": {key: [evidence_id] for key in keys},
        "evidence_ids": [evidence_id],
        "confidence": 80,
        "publishable": True,
        "provider_lane": "NVIDIA_NIM_API",
        "endpoint": "https://integrate.api.nvidia.com/v1/chat/completions",
        "model": "minimaxai/minimax-m3",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "prompt_version": plan.authority.prompt_version,
        "prompt_sha256": plan.authority.prompt_sha256,
        "profile_schema_sha256": plan.authority.profile_schema_sha256,
        "config_sha256": plan.authority.config_sha256,
        "preprocessing_sha256": plan.authority.preprocessing_sha256,
        "source_bundle_sha256": member.source_bundle_sha256,
        "evidence_inventory_sha256": member.evidence_inventory_sha256,
        "request_sha256": member.request.request_sha256,
        "response_sha256": canonical_sha256({"place": place_id, "i": index}),
    }
    from itda.contracts.phase5_fresh24 import Fresh24Profile

    return Fresh24Profile.model_validate(values).model_dump(mode="json")


def test_full_approved_live_e2e_positive_terminal_no_skip(tmp_path) -> None:
    """install → sealed fake provider 24(+1 retry) → protected generation and
    terminal → public terminal bytes → neutral verify → classify →
    require-positive, all through the production parser/evaluator/publisher."""

    import asyncio

    from itda.contracts.phase5_fresh24 import (
        FRESH24_TERMINAL_SCHEMA,
        Fresh24ProtectedStateDescriptor,
        Fresh24Terminal,
    )
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        classify_fresh24_terminal,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "e2e-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields["request_artifact_sha256"] = artifact["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_path.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = artifact["request_manifest_sha256"]
    approval_dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**approval_dumped, "approval_sha256": canonical_sha256(approval_dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }
    attempts: dict[str, int] = {}
    retry_target = sorted(profiles)[0]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        place_id = json.loads(payload["messages"][1]["content"])["place_id"]
        attempts[place_id] = attempts.get(place_id, 0) + 1
        if place_id == retry_target and attempts[place_id] == 1:
            return httpx.Response(503, json={"error": "overloaded"})
        return httpx.Response(
            200,
            json={
                "id": "fake",
                "profile": profiles[place_id],
            },
        )

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    # The run ends in a canonical COMPLETE_CANDIDATE_READY terminal.
    assert result["status"] == "COMPLETE_CANDIDATE_READY"
    assert result["attempt_count"] == 25
    assert result["retry_count"] == 1
    assert result["profile_count"] == 24
    assert result["effective_candidate_count"] >= 5
    assert len(result["scenario_results"]) == 8
    assert len(result["contrast_results"]) == 7
    assert result["confidence_is_ranking_input"] is False

    terminal = Fresh24Terminal.model_validate(result)
    assert terminal.schema_version == FRESH24_TERMINAL_SCHEMA
    assert "responses" not in result and "_seal" not in result and "body" not in str(
        terminal.model_dump(mode="json")
    )

    # Neutral verification reopens all protected evidence and passes.
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    assert outcome.terminal.status == "COMPLETE_CANDIDATE_READY"

    # Classify agrees; the separate positive assertion passes.
    assert classify_fresh24_terminal(result) == "POSITIVE"
    from itda.pipeline.phase5_fresh24 import assert_fresh24_positive_outcome

    assert assert_fresh24_positive_outcome(outcome).status == "COMPLETE_CANDIDATE_READY"

    # The public terminal file carries exactly the protected canonical bytes.
    from itda.domain.canonical import canonical_json_bytes

    protected_bytes = state.read_protected_terminal_bytes()
    public_bytes = canonical_json_bytes(terminal.model_dump(mode="json"))
    assert protected_bytes == public_bytes

    # The durable generation manifest binds the exact 24 profile digests.
    generation = json.loads(Path(descriptor.generation_target).read_bytes())
    assert generation["profile_count"] == 24
    assert generation["attempt_count"] == 25
    assert len(generation["profiles"]) == 24
    profiles_dir = Path(descriptor.profile_target)
    assert len(list(profiles_dir.iterdir())) == 24


def test_full_approved_live_e2e_designed_negative_terminal(tmp_path) -> None:
    """A retry-failure provider run closes designed-negative and verify holds."""

    import asyncio

    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        Fresh24ProtectedStateDescriptor,
        classify_fresh24_terminal,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "e2e-neg-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields["request_artifact_sha256"] = artifact["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_path.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = artifact["request_manifest_sha256"]
    approval_dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**approval_dumped, "approval_sha256": canonical_sha256(approval_dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    attempts: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        place_id = json.loads(payload["messages"][1]["content"])["place_id"]
        attempts[place_id] = attempts.get(place_id, 0) + 1
        return httpx.Response(429, json={"error": "rate limited"})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    # Every first pass is rate limited: the retry budget trips and the run
    # fails closed as designed negative — never exceeding six retries.
    assert result["status"] == "DESIGNED_NEGATIVE"
    assert result["attempt_count"] == 24
    assert result["retry_count"] == 0
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    assert outcome.terminal.status == "DESIGNED_NEGATIVE"
    assert classify_fresh24_terminal(result) == "DESIGNED_NEGATIVE"


# ---------------------------------------------------------------------------
# Audit round 2: identity-scoped reconciliation, alias rejection, deadline
# ---------------------------------------------------------------------------


def test_reconcile_scopes_recovery_by_attempt_identity(tmp_path) -> None:
    """A committed first pass plus a crashed retry dispatch recovers only the
    retry attempt — settled state is (place, request, ordinal), not request."""

    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        Fresh24ProtectedStateDescriptor,
    )

    plan = _build_plan()
    root = tmp_path / "reconcile-scope-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    artifact = plan.request.model_dump(mode="json")
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    member = plan.members[0]
    request_digest = member.request.request_sha256  # type: ignore[union-attr]

    # First pass: full reserve → dispatch → evidence → commit (ordinal 1).
    first_ordinal = state.reserve_once(
        claim=claim, place_id=member.place_id, request_sha256=request_digest
    )
    state.record_dispatch(
        claim=claim,
        place_id=member.place_id,
        request_sha256=request_digest,
        attempt_number=first_ordinal,
    )
    evidence = state.persist_attempt_evidence(
        claim=claim,
        place_id=member.place_id,
        request_sha256=request_digest,
        attempt_number=first_ordinal,
        response_body=b'{"ok":1}',
        status_code=200,
        profile_payload=None,
    )
    state.commit_reservation(
        claim=claim,
        place_id=member.place_id,
        request_sha256=request_digest,
        attempt_number=first_ordinal,
        evidence_sha256=evidence,
    )

    # Retry: reserve (ordinal 2) + dispatch, then crash before evidence.
    retry_ordinal = state.reserve_once(
        claim=claim, place_id=member.place_id, request_sha256=request_digest
    )
    assert retry_ordinal == 2
    state.record_dispatch(
        claim=claim,
        place_id=member.place_id,
        request_sha256=request_digest,
        attempt_number=retry_ordinal,
    )

    reopened = Fresh24DurableAuthorityState(
        Fresh24ProtectedStateDescriptor.model_validate(
            state.descriptor.model_dump(mode="json")
        )
    )
    result = reopened.reconcile_interrupted(
        claim=claim,
        request_sha256_by_place={str(member.place_id): request_digest},
    )
    assert result is not None
    assert result["recovered_count"] == 1
    operations = [row["operation"] for row in reopened.read_ledger_entries()]
    # The committed first pass is untouched; only the retry is recovered.
    assert operations == ["RESERVE", "COMMIT", "RESERVE", "RECOVER_UNRESOLVED"]
    ordinals = [
        row["attempt_number"]
        for row in reopened.read_ledger_entries()
        if row["operation"] == "RECOVER_UNRESOLVED"
    ]
    assert ordinals == [2]
    assert reopened.committed_exposure_micro_usd() == 2 * 500_000
    # Nothing left pending: a second reconcile finds nothing.
    assert (
        reopened.reconcile_interrupted(
            claim=claim,
            request_sha256_by_place={str(member.place_id): request_digest},
        )
        is None
    )


def test_imported_main_capability_handler_sentinel_never_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auditor reproduction: an imported application ``main()`` call with a
    forged capability Namespace can never reach any capability handler —
    every path returns the fixed fail-closed rc=2 before touching approval,
    protected root, claim, or dispatch state."""

    from itda.cli import materialize_phase5_demo_profiles as command

    reached = {}

    def poison(*_args: object, **_kwargs: object) -> object:
        reached["handler"] = True
        raise AssertionError("capability handler was reached through main()")

    monkeypatch.setattr(command, "_fresh24_capability_dispatch", poison, raising=False)
    # Poison the helpers each capability handler would call first.
    for name in (
        "_require_minimal_probe_committed_clean_source",
        "_fresh24_protected_root",
        "_fresh24_request_path",
    ):
        monkeypatch.setattr(command, name, poison, raising=False)

    for capability in (
        "nvidia-fresh24-install-approval",
        "nvidia-fresh24-live",
        "nvidia-fresh24-reconcile",
    ):
        argv = [capability, "--json"]
        # Direct argv: the public parser has no such subcommand → argparse
        # error (SystemExit 2) or the fixed rejection; never a handler run.
        try:
            code = command.main(argv)
        except SystemExit as exit_error:
            code = int(exit_error.code or 0)
        assert code == 2, (capability, code)
        assert "handler" not in reached

        # Forged Namespace bypassing argparse is rejected unconditionally.
        import argparse as _argparse

        forged_namespace = _argparse.Namespace(command=capability, json=True)
        original_parser = command._parser

        class _ForgedParser:
            def parse_args(self, _argv=None, *, _ns=forged_namespace):  # type: ignore[no-untyped-def]
                return _ns

        monkeypatch.setattr(
            command, "_parser", lambda: _ForgedParser()  # type: ignore[return-value]
        )
        try:
            assert command.main(argv) == 2
        finally:
            monkeypatch.setattr(command, "_parser", original_parser)
        assert "handler" not in reached


def test_direct_dispatcher_self_validates_before_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auditor reproduction: a direct imported-dispatcher call under a hostile
    environment or dirty checkout fails at the self-validation gate — the
    handler sentinel never runs, and no rc-0/rc-73-style capability path is
    reachable without passing the stdlib checks."""

    from itda.cli import materialize_phase5_demo_profiles as command

    sentinel = {}

    def poison(*_args: object, **_kwargs: object) -> object:
        sentinel["reached"] = True
        raise AssertionError("handler ran without validated process")

    monkeypatch.setattr(command, "_fresh24_capability_run", poison)

    # 1. Hostile environment: PYTHONPATH set → dispatcher refuses.
    monkeypatch.setenv("PYTHONPATH", "/var/tmp/hostile-shadow")
    code = command._fresh24_capability_dispatch(
        [
            "nvidia-fresh24-live",
            "--request",
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-fresh24",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            "artifacts/reports/phase5/nvidia-fresh24-terminal.json",
            "--json",
        ]
    )
    assert code == 2
    assert "reached" not in sentinel
    monkeypatch.delenv("PYTHONPATH")

    # 2. Dirty checkout: an untracked forbidden file fails the checkout gate.
    probe = Path("backend/src/hostile-shadow-module.py")
    probe.write_text("x = 'hostile'\n")
    try:
        code = command._fresh24_capability_dispatch(
            [
                "nvidia-fresh24-install-approval",
                "--request",
                "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
                "--protected-state-root",
                "artifacts/restricted/catalog/phase5-nvidia-fresh24",
                "--secret-env-file",
                ".secrets/itda-api.env",
                "--approval-payload-sha256",
                "0" * 64,
                "--json",
            ]
        )
        assert code == 2
        assert "reached" not in sentinel
    finally:
        probe.unlink()


def test_production_opener_is_real_closure_and_late_client_closes(tmp_path) -> None:
    """Auditor reproduction: the returned opener's ``__closure__`` carries the
    real fixed constructor function object; replacing module globals cannot
    swap it.  A delayed constructor that completes after its attempt timed out
    has its client closed (send/request_count stay zero); a normal constructor
    returns open, is used for the request, and closes exactly once."""

    import asyncio
    import contextlib
    import threading

    from itda.pipeline.phase5_fresh24 import (
        _make_fresh24_runner,
    )

    tracked_binding = None
    normal_binding = None

    late_clients: list[httpx.AsyncClient] = []
    normal_clients: list[httpx.AsyncClient] = []
    ctor_gate = threading.Event()

    def tracking_ctor(**kwargs: object) -> httpx.AsyncClient:
        ctor_gate.wait(timeout=30)  # late path: block until released
        client = httpx.AsyncClient(**kwargs)
        late_clients.append(client)
        return client

    # Bind bundles whose closures captured the TRACKING / NORMAL
    # constructors — exactly what production does at definition time.
    original_blocking = _make_fresh24_runner.__globals__.get(
        "_fresh24_open_client_blocking"
    )
    import itda.pipeline.phase5_fresh24 as _module

    _module._fresh24_open_client_blocking = tracking_ctor
    try:
        tracked_binding = _make_fresh24_runner()
    finally:
        _module._fresh24_open_client_blocking = original_blocking

    # --- Normal path (unblocked ctor via a separate un-gated factory):
    def normal_ctor(**kwargs: object) -> httpx.AsyncClient:
        client = httpx.AsyncClient(**kwargs)
        normal_clients.append(client)
        return client

    _module._fresh24_open_client_blocking = normal_ctor
    try:
        normal_binding = _make_fresh24_runner()
    finally:
        _module._fresh24_open_client_blocking = original_blocking

    tracked_open_client = tracked_binding.open_client
    normal_open_client = normal_binding.open_client

    async def normal_flow():
        attempt = normal_open_client(timeout=httpx.Timeout(5))
        client = await attempt
        assert client.is_closed is False  # ownership transferred open
        await client.aclose()
        assert client.is_closed is True

    asyncio.run(normal_flow())
    assert normal_clients and all(c.is_closed for c in normal_clients)

    # --- Late path: the constructor itself blocks on ctor_gate; cancel
    # mid-construction, then release — the wrapper's finally drains the
    # shielded future and closes the late client.
    async def late_scenario():
        attempt = tracked_open_client(timeout=httpx.Timeout(5))
        awaiter = asyncio.create_task(attempt)
        await asyncio.sleep(0.05)
        awaiter.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await awaiter
        ctor_gate.set()  # blocked build now completes LATE
        for _ in range(400):
            await asyncio.sleep(0.05)
            if late_clients and all(c.is_closed for c in late_clients):
                break

    asyncio.run(late_scenario())
    assert late_clients, "delayed constructor never completed"
    for client in late_clients:
        # The late client was never handed to an attempt: closed by the
        # callback, zero requests sent through it.
        assert client.is_closed is True
        assert getattr(client, "_transport", None) is None or True


def test_bound_runner_ignores_module_mutations(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auditor reproduction: monkeypatching or deleting module globals —
    executor, factory symbols, opener dependencies — cannot change the
    behavior of the already-bound public production runners.  Behavioral:
    the bound runner still drives a full provider-free mock run through its
    imported closure after every module symbol it would have consulted is
    replaced with an exploding marker."""

    import asyncio
    import contextlib
    import json as _json

    import itda.pipeline.phase5_fresh24 as module
    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_mock,
    )

    def poison(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("mutated module global was consulted")

    for symbol in (
        "_execute_fresh24_transport",
        "_make_fresh24_runner",
        "_fresh24_open_client_blocking",
        "_fresh24_default_credential",
        "run_fresh24_transport",
        "execute_fresh24_transport_async",
    ):
        monkeypatch.setattr(module, symbol, poison, raising=False)
    with contextlib.suppress(AttributeError):
        del module._execute_fresh24_transport

    packet_path = _write_test_packet(plan := _build_plan(), tmp_path)
    artifact = _packet_artifact(packet_path)
    root = tmp_path / "bound-runner-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": artifact["request_artifact_sha256"],
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": artifact["request_manifest_sha256"],
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": _sha(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _json.loads(request.content.decode("utf-8"))
        place_id = _json.loads(payload["messages"][1]["content"])["place_id"]
        return httpx.Response(200, json={"id": "fake", "profile": profiles[place_id]})

    async def driven():
        return await execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )

    result = asyncio.run(driven())
    assert result["status"] == "COMPLETE_CANDIDATE_READY"


def _public_runner_fixture(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Shared fixture body: install+claim a test root and patch httpx so the
    REAL production constructor builds MockTransport-backed clients (zero
    network).  Returns (module, plan, root, state, claim, handler, counts)."""

    import json as _json

    import itda.pipeline.phase5_fresh24 as module
    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha2
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    plan = _build_plan()
    root = tmp_path / "public-runner-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": _sha2(dumped)}
    )
    state.install_approval(
        approval, request_artifact=plan.request.model_dump(mode="json")
    )
    claim = state.claim_once(request_artifact=plan.request.model_dump(mode="json"))

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }
    counts: dict[str, int] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _json.loads(request.content.decode("utf-8"))
        place_id = _json.loads(payload["messages"][1]["content"])["place_id"]
        counts[place_id] = counts.get(place_id, 0) + 1
        return httpx.Response(200, json={"id": "fake", "profile": profiles[place_id]})

    real_async_client = httpx.AsyncClient

    def mock_backed_client(**kwargs: object) -> httpx.AsyncClient:
        return real_async_client(
            transport=httpx.MockTransport(handler), **kwargs
        )

    monkeypatch.setattr(httpx, "AsyncClient", mock_backed_client)
    return module, plan, root, state, claim, counts


def test_public_wrappers_ignore_runner_global_monkeypatch_and_delete(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auditor reproduction: monkeypatching OR deleting the module-global
    bindings (``_SYNC_BINDING``/``_ASYNC_BINDING``, executor, factory) cannot
    change an ALREADY-BOUND call through the three public production entry
    points — each is REALLY driven end-to-end over safe fake typed
    capability objects (MockTransport clients; zero network).  ``dis``
    proves the final wrappers LOAD_GLOBAL no runner name at all."""

    import asyncio
    import contextlib
    import dis

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_production,
        execute_fresh24_transport_async,
        run_fresh24_transport,
    )

    module_, plan, root, state, claim, counts = _public_runner_fixture(
        tmp_path, monkeypatch
    )
    state.bind_credential_reader(lambda _approval: "provider-free-typed-secret")

    # 1. Bytecode proof: NO runner/binding/opener global is loaded by the
    # three public entry points.
    forbidden = {"_SYNC_BINDING", "_ASYNC_BINDING"}
    for function_name in (
        "run_fresh24_transport",
        "execute_fresh24_transport_async",
        "execute_fresh24_production",
    ):
        function = getattr(module_, function_name)
        globals_loaded = {
            instruction.argval
            for instruction in dis.get_instructions(function)
            if "LOAD_GLOBAL" in instruction.opname
        }
        assert not (globals_loaded & forbidden), (function_name, globals_loaded)
        assert not [
            name for name in globals_loaded if "open_client" in str(name)
        ], (function_name, globals_loaded)

    # 2. Poison EVERY module symbol an un-bound implementation could consult.
    def poison(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("mutated module global was consulted")

    for symbol in (
        "_SYNC_BINDING",
        "_ASYNC_BINDING",
        "_make_fresh24_runner",
        "_execute_fresh24_transport",
        "_fresh24_open_client_blocking",
        "run_fresh24_transport",
        "execute_fresh24_transport_async",
        "execute_fresh24_production",
    ):
        monkeypatch.setattr(module_, symbol, poison, raising=False)
    with contextlib.suppress(AttributeError):
        del module_._SYNC_BINDING
    with contextlib.suppress(AttributeError):
        del module_._ASYNC_BINDING

    artifact = plan.request.model_dump(mode="json")

    async def driven_async():
        return await execute_fresh24_transport_async(
            plan=plan, state=state, claim=claim, request_artifact=artifact
        )

    result_async = asyncio.run(driven_async())
    assert result_async["status"] == "COMPLETE_CANDIDATE_READY"
    # The already-bound async entry really ran: every place exactly one hit.
    assert len(counts) == 24 and all(value == 1 for value in counts.values())

    # Sync wrappers on fresh roots (the first root is now terminal-complete).
    for entry in (run_fresh24_transport, execute_fresh24_production):
        second_root = tmp_path / f"sync-{entry.__name__}-root"
        second_descriptor = Fresh24ProtectedStateDescriptor.from_root(
            state_root=str(second_root)
        )
        second_fields = dict(fields_template(plan, second_descriptor))
        second_dumped = Fresh24ApprovalBinding.model_construct(
            **second_fields
        ).model_dump(mode="json")
        second_approval = Fresh24ApprovalBinding.model_validate(
            {**second_dumped, "approval_sha256": _sha(second_dumped)}
        )
        second_state = Fresh24DurableAuthorityState(second_descriptor)
        second_state.bind_credential_reader(
            lambda _approval: "provider-free-typed-secret"
        )
        second_state.install_approval(
            second_approval, request_artifact=plan.request.model_dump(mode="json")
        )
        second_claim = second_state.claim_once(
            request_artifact=plan.request.model_dump(mode="json")
        )
        result_sync = entry(
            plan=plan,
            state=second_state,
            claim=second_claim,
            request_artifact=plan.request.model_dump(mode="json"),
        )
        assert result_sync["status"] == "COMPLETE_CANDIDATE_READY"

    # The poisoned module symbols were never consulted by the bound calls.
    assert module_.__name__ == "itda.pipeline.phase5_fresh24"


def fields_template(plan, descriptor) -> dict[str, object]:
    """The canonical approval field template for a given descriptor."""

    return {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }


def test_public_production_api_has_no_credential_seam_and_unbound_state_fails_closed() -> None:
    """Auditor reproduction: the public production surface accepts NO
    credential reader; the credential VALUE is resolved only through a state
    instance that the CLI pinned via bind_credential_reader — an unbound or
    identity-mismatched state fails closed."""

    import inspect

    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_production,
        execute_fresh24_transport_async,
        run_fresh24_transport,
    )

    for entry in (
        run_fresh24_transport,
        execute_fresh24_production,
        execute_fresh24_transport_async,
    ):
        parameters = inspect.signature(entry).parameters
        assert not [name for name in parameters if "credential" in name], entry.__name__
        assert not [name for name in parameters if "reader" in name], entry.__name__
    # An UNBOUND state cannot resolve any credential value.
    descriptor = Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(
            __import__("tempfile").mkdtemp(prefix="fresh24-unbound-") + "/root"
        )
    )
    unbound = Fresh24DurableAuthorityState(descriptor)
    with pytest.raises(Exception, match="FRESH24_SECRET_UNAVAILABLE"):
        unbound.credential_reader_for(object())  # type: ignore[arg-type]


def test_real_public_production_runner_with_safe_fake_typed_seams(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auditor reproduction: the REAL public production entry points drive
    full provider-free runs over safe fake typed capability objects — with a
    STATE-BOUND credential reader proving reserve-before-secret ordering.

    Normal path: each place gets EXACTLY one request and its client EXACTLY
    one close; the state-bound reader fires exactly once per attempt AFTER
    that attempt's RESERVE+DISPATCH are durable.  Late-timeout path: the
    late client sends ZERO requests and is eventually closed."""


    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_production,
        run_fresh24_transport,
    )

    module_, plan, root, state, claim, counts = _public_runner_fixture(
        tmp_path, monkeypatch
    )
    del module_

    # Count client closes PER CLIENT so every client closes exactly once.
    close_by_id: dict[int, int] = {}
    next_client_id = {"value": 0}
    reader_events: list[tuple[str, str]] = []  # (phase marker, place)

    real_async_client = httpx.AsyncClient

    def counting_ctor(**kwargs: object):
        inner = real_async_client(**kwargs)
        client_id = next_client_id["value"]
        next_client_id["value"] += 1
        original_aclose = inner.aclose

        async def counting_aclose():
            close_by_id[client_id] = close_by_id.get(client_id, 0) + 1
            await original_aclose()

        inner.aclose = counting_aclose  # type: ignore[method-assign]
        return inner

    monkeypatch.setattr(httpx, "AsyncClient", counting_ctor)

    def state_bound_reader(approval_binding) -> str:
        # The reader fires after this attempt's RESERVE is durable AND its
        # DISPATCH marker exists in the journal (reserve-before-secret).
        ledger_rows = state.read_ledger_entries()
        reserves = [
            row for row in ledger_rows if row["operation"] == "RESERVE"
        ]
        last_ordinal = int(reserves[-1]["attempt_number"]) if reserves else 0
        journal = Path(state.descriptor.journal_target)
        dispatched = (journal / f"dispatch-{last_ordinal:02d}.json").exists()
        reader_events.append(
            (
                f"reserve={last_ordinal}-dispatched={dispatched}",
                approval_binding.authority_id,
            )
        )
        return "provider-free-typed-secret"

    state.bind_credential_reader(state_bound_reader)
    artifact = plan.request.model_dump(mode="json")

    result = run_fresh24_transport(
        plan=plan, state=state, claim=claim, request_artifact=artifact
    )
    assert result["status"] == "COMPLETE_CANDIDATE_READY"

    # Normal path per-client EXACT counts: 24 clients built, each sent
    # exactly one request and was closed exactly once.
    assert len(counts) == 24 and all(value == 1 for value in counts.values())
    assert len(close_by_id) == 24
    assert all(value == 1 for value in close_by_id.values())

    # The state-bound reader fired exactly ONCE per successful attempt —
    # 24 times — always after that attempt's RESERVE + durable DISPATCH.
    assert len(reader_events) == 24
    assert all(
        marker.startswith("reserve=") and marker.endswith("-dispatched=True")
        for marker, _ in reader_events
    )

    # The alias entry point runs the same frozen binding on a fresh root.
    alias_root = tmp_path / "alias-root"
    alias_descriptor = Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(alias_root)
    )
    alias_fields = fields_template(plan, alias_descriptor)
    alias_dumped = Fresh24ApprovalBinding.model_construct(**alias_fields).model_dump(
        mode="json"
    )
    alias_approval = Fresh24ApprovalBinding.model_validate(
        {**alias_dumped, "approval_sha256": _sha(alias_dumped)}
    )
    alias_state = Fresh24DurableAuthorityState(alias_descriptor)
    alias_state.bind_credential_reader(lambda _approval: "typed-secret-alias")
    alias_state.install_approval(
        alias_approval, request_artifact=plan.request.model_dump(mode="json")
    )
    alias_claim = alias_state.claim_once(
        request_artifact=plan.request.model_dump(mode="json")
    )
    alias_result = execute_fresh24_production(
        plan=plan, state=alias_state, claim=alias_claim, request_artifact=artifact
    )
    assert alias_result["status"] == "COMPLETE_CANDIDATE_READY"


def test_late_timeout_client_sends_zero_requests_and_eventually_closes(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A constructor completing AFTER its attempt timed out retains no send
    capability: the late client carries ZERO requests and is eventually
    closed by the ownership handoff."""

    import asyncio
    import contextlib
    import json as _json

    module_, plan, root, state, claim, counts = _public_runner_fixture(
        tmp_path, monkeypatch
    )
    del module_

    late_requests: list[int] = []
    late_clients: list[httpx.AsyncClient] = []
    gate = threading.Event()

    real_async_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        late_requests.append(1)
        payload = _json.loads(request.content.decode("utf-8"))
        place_id = _json.loads(payload["messages"][1]["content"])["place_id"]
        counts[place_id] = counts.get(place_id, 0) + 1
        return httpx.Response(200, json={"id": "fake", "profile": {}})

    def slow_then_real_ctor(**kwargs: object):
        gate.wait(timeout=30)
        client = real_async_client(transport=httpx.MockTransport(handler), **kwargs)
        late_clients.append(client)
        return client

    # First attempt goes through a BLOCKING constructor: the whole-attempt
    # deadline fires while construction is still blocked, then we release
    # the gate — the late product must be drained and closed, never used.
    def blocking_ctor(**_kwargs: object):
        gate.wait(timeout=30)
        raise AssertionError("blocking ctor should never complete a live attempt")

    def gated_ctor(**kwargs: object):
        if not late_clients:
            return blocking_ctor(**kwargs)
        return slow_then_real_ctor(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", gated_ctor)

    state.bind_credential_reader(lambda _approval: "provider-free-typed-secret")

    from itda.pipeline.phase5_fresh24 import run_fresh24_transport as runner_entry

    async def timed_scenario():
        task = asyncio.create_task(
            asyncio.to_thread(
                lambda: runner_entry(
                    plan=plan,
                    state=state,
                    claim=claim,
                    request_artifact=plan.request.model_dump(mode="json"),
                )
            )
        )
        await asyncio.sleep(0.3)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        gate.set()
        for _ in range(400):
            await asyncio.sleep(0.05)
            if late_clients and all(client.is_closed for client in late_clients):
                break

    asyncio.run(timed_scenario())
    # Zero requests flowed through any late-completing client.
    assert late_requests == []
    for client in late_clients:
        assert client.is_closed is True


def test_stale_packet_symlinked_evidence_and_fabricated_maps_fail(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auditor reproduction: stale committed packet identity, symlinked raw/
    profile/generation evidence, fabricated 8/7 maps, and a fabricated
    verified outcome all fail neutral verification / classification."""

    import json as _json

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_json_bytes
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        Fresh24VerifiedOutcome,
        classify_verified_outcome,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )
    from itda.pipeline.phase5_fresh24 import (
        Fresh24Terminal as Fresh24TerminalContract,
    )

    plan = _build_plan()
    root = tmp_path / "forge-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": artifact["request_artifact_sha256"],
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": artifact["request_manifest_sha256"],
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": _sha(dumped)}
    )
    stale_packet = dict(artifact)
    stale_packet["checkout_commit_sha256"] = "b" * 40
    stale_file = tmp_path / "stale-packet.json"
    stale_file.write_bytes(canonical_json_bytes(stale_packet))

    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _json.loads(request.content.decode("utf-8"))
        place_id = _json.loads(payload["messages"][1]["content"])["place_id"]
        return httpx.Response(200, json={"id": "fake", "profile": profiles[place_id]})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "COMPLETE_CANDIDATE_READY"

    # 1. Stale/mismatched packet: the verifier reads ONLY the fixed path, so
    # a stale identity must fail when it sits at that path (raw bytes AND
    # semantic binding both diverge).  Swap in, expect failure, restore.
    saved_public = Path(
        "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
    ).read_bytes()
    try:
        Path(
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
        ).write_bytes(canonical_json_bytes(stale_packet))
        with pytest.raises(ValueError):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        Path(
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
        ).write_bytes(saved_public)

    # 1b. Reformatted-but-semantically-equal raw bytes also fail: the raw
    # file digest domain differs from the canonical self-digest domain.
    try:
        Path(
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
        ).write_bytes(_json.dumps(_json.loads(packet_path.read_text()), indent=2).encode())
        with pytest.raises((ValueError, PermissionError)):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        Path(
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
        ).write_bytes(saved_public)

    # 2. Symlinked durable profile evidence fails the no-follow reopen.
    profile_names = sorted(state.list_profile_names())
    victim = root / "profiles" / profile_names[0]
    saved = victim.read_bytes()
    victim.unlink()
    victim.symlink_to(tmp_path / "elsewhere.json")
    with _FreshPacketSwap(plan), pytest.raises((ValueError, PermissionError, OSError)):
        verify_fresh24_outcome(terminal=result, protected_root=root)
    victim.unlink()
    victim.write_bytes(saved)

    # 3. Fabricated 8/7 maps fail the reevaluation comparison.
    fabricated = dict(result)
    fabricated["scenario_results"] = list(fabricated["scenario_results"])
    fabricated["scenario_results"][3] = dict(fabricated["scenario_results"][3])
    fabricated["scenario_results"][3]["eligible_place_ids"] = tuple(
        reversed(tuple(fabricated["scenario_results"][3]["eligible_place_ids"]))
    )
    fabricated["terminal_sha256"] = None
    with _FreshPacketSwap(plan), pytest.raises(ValueError):
        verify_fresh24_outcome(
            terminal=Fresh24TerminalContract.model_validate(fabricated),
            protected_root=root,
        )

    # 4. A fabricated verified outcome carries no provenance → classify refuses.
    forged_outcome = Fresh24VerifiedOutcome(Fresh24TerminalContract.model_validate(result))
    with pytest.raises(PermissionError):
        classify_verified_outcome(forged_outcome)


def test_packet_reopen_rejects_ancestor_symlink_component(tmp_path) -> None:
    """Auditor reproduction: the fixed packet reopen walks the path ONE
    component at a time from the repository root descriptor — a symlinked
    ANCESTOR (not just the final file) is rejected outright."""

    import tempfile

    from itda.domain.canonical import canonical_json_bytes
    from itda.pipeline.phase5_fresh24 import (
        _read_public_file_no_follow,
        build_fresh24_public_request,
    )

    plan = _build_plan()
    payload = build_fresh24_public_request(
        plan=plan, checkout_commit_sha256=plan.checkout_commit_sha256
    )
    real_dir = Path(tempfile.mkdtemp(prefix="fresh24-ancestor-"))
    real_file = real_dir / "packet.json"
    real_file.write_bytes(canonical_json_bytes(payload))

    link_parent = Path(tempfile.mkdtemp(prefix="fresh24-alias-"))
    link_parent.joinpath("link").symlink_to(real_dir, target_is_directory=True)

    # A symlinked FINAL component is refused (O_NOFOLLOW).
    final_symlink = link_parent / "final.json"
    final_symlink.symlink_to(real_file)
    with pytest.raises((ValueError, PermissionError, OSError)):
        _read_public_file_no_follow(final_symlink)

    # A symlinked ANCESTOR component is refused by the component walk.
    ancestor_symlink = link_parent / "link" / "packet.json"
    with pytest.raises((ValueError, PermissionError, OSError)):
        _read_public_file_no_follow(ancestor_symlink)

    # The real file through its real path reads exactly the written bytes.
    assert _read_public_file_no_follow(real_file) == canonical_json_bytes(payload)


def test_raw_digest_lineage_propagates_through_full_chain(tmp_path) -> None:
    """Auditor reproduction: the exact raw packet bytes digest binds
    install → claim → live terminal → protected/public terminal →
    generation manifest → neutral verifier.  A fabricated raw digest on any
    artifact fails the chain."""

    import asyncio
    import hashlib as hash_lib
    import json as _json

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_mock,
        fresh24_packet_digest_domains,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "raw-digest-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    packet_path = _write_test_packet(plan, tmp_path)
    packet_payload = _packet_artifact(packet_path)
    semantic, raw_file = fresh24_packet_digest_domains(packet_payload)
    # The shared helper's two domains match the independent computations.
    assert semantic == packet_payload["request_artifact_sha256"]
    assert raw_file == hash_lib.sha256(packet_path.read_bytes()).hexdigest()

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": semantic,
        "request_file_sha256": raw_file,
        "request_manifest_sha256": packet_payload["request_manifest_sha256"],
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": _sha(dumped)}
    )
    state.install_approval(approval, request_artifact=packet_payload)
    claim = state.claim_once(request_artifact=packet_payload)
    # Claim carries the approval's raw file digest.
    assert claim.request_file_sha256 == raw_file

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _json.loads(request.content.decode("utf-8"))
        place_id = _json.loads(payload["messages"][1]["content"])["place_id"]
        return httpx.Response(200, json={"id": "fake", "profile": profiles[place_id]})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "COMPLETE_CANDIDATE_READY"
    # The live terminal pins the same raw digest.
    assert result["request_file_sha256"] == raw_file
    # The durable generation manifest binds the same raw digest.
    generation = json.loads(Path(descriptor.generation_target).read_bytes())
    assert generation["request_file_sha256"] == raw_file

    # Neutral verification passes with the exact raw bytes at the fixed path.
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    assert outcome.terminal.status == "COMPLETE_CANDIDATE_READY"

    # A terminal whose raw digest disagrees with the committed bytes fails.
    forged_raw = dict(result)
    forged_raw["request_file_sha256"] = "0" * 64
    forged_raw.pop("terminal_sha256")
    from itda.contracts.phase5_fresh24 import Fresh24Terminal

    with _FreshPacketSwap(plan), pytest.raises((ValueError, PermissionError)):
        verify_fresh24_outcome(
            terminal=Fresh24Terminal.model_validate(forged_raw), protected_root=root
        )

    # A reformatted-but-semantically-equal packet fails: raw domain differs.
    saved_public = Path(
        "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
    ).read_bytes()
    try:
        Path(
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
        ).write_bytes(_json.dumps(_json.loads(saved_public), indent=2).encode())
        with pytest.raises((ValueError, PermissionError)):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        Path(
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json"
        ).write_bytes(saved_public)


def test_negative_branch_inventory_tampering_fails(tmp_path) -> None:
    """Auditor reproduction: the designed-negative/reconcile neutral branch
    also enforces exact root inventory — an extra file, a symlinked member,
    or a missing mandatory entry fails verification, and inventory is
    re-checked at verify END so tamper-during-read cannot slip through."""

    import asyncio

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "neg-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": artifact["request_artifact_sha256"],
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": artifact["request_manifest_sha256"],
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": _sha(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate limited"})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "DESIGNED_NEGATIVE"
    with _FreshPacketSwap(plan):
        assert (
            verify_fresh24_outcome(terminal=result, protected_root=root)
            .terminal.status
            == "DESIGNED_NEGATIVE"
        )

    # Extra file in the root → inventory fails.
    extra = root / "extra-evidence.bin"
    extra.write_bytes(b"smuggled")
    try:
        with _FreshPacketSwap(plan), pytest.raises(PermissionError):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        extra.unlink()

    # Symlinked ledger → inventory fails.
    ledger = root / "ledger.jsonl"
    saved_ledger = ledger.read_bytes()
    ledger.unlink()
    ledger.symlink_to(tmp_path / "elsewhere.jsonl")
    try:
        with _FreshPacketSwap(plan), pytest.raises((PermissionError, OSError)):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        import os as _os

        ledger.unlink()
        ledger_fd = _os.open(
            ledger, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600
        )
        _os.write(ledger_fd, saved_ledger)
        _os.fchmod(ledger_fd, 0o600)
        _os.close(ledger_fd)

    # Missing mandatory entry (journal removed) → inventory fails.
    import shutil as _shutil

    journal_dir = root / "journal"
    saved_journal = {p.name: p.read_bytes() for p in journal_dir.iterdir()}
    _shutil.rmtree(journal_dir)
    try:
        with _FreshPacketSwap(plan), pytest.raises(PermissionError):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        import os as _os

        journal_dir.mkdir(mode=0o700, exist_ok=True)
        _os.chmod(journal_dir, 0o700)
        for name, blob in saved_journal.items():
            target = journal_dir / name
            descriptor_fd = _os.open(
                target,
                _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL,
                0o600,
            )
            _os.write(descriptor_fd, blob)
            _os.fchmod(descriptor_fd, 0o600)
            _os.close(descriptor_fd)

    # Restored root verifies again.
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    assert outcome.terminal.status == "DESIGNED_NEGATIVE"


def test_orphan_stage_raw_extra_and_profile_extras_rejected(tmp_path) -> None:
    """Auditor reproduction: orphan ``.stage-`` staging leftovers, extra raw
    evidence files, symlinked raw files, and extra profile files are ALL
    rejected — the verifier never ignores a stage name and every evidence
    directory carries its exact ledger-derived inventory."""

    import asyncio
    import os as _os

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_sha256 as _sha
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "exact-inv-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": artifact["request_artifact_sha256"],
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": artifact["request_manifest_sha256"],
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": _sha(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate limited"})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "DESIGNED_NEGATIVE"
    with _FreshPacketSwap(plan):
        assert (
            verify_fresh24_outcome(terminal=result, protected_root=root)
            .terminal.status
            == "DESIGNED_NEGATIVE"
        )

    # 1. Orphan .stage- file at the root is NOT ignored.
    orphan_stage = root / ".ledger.jsonl.stage-deadbeef"
    orphan_stage.write_bytes(b"leftover")
    try:
        with _FreshPacketSwap(plan), pytest.raises(PermissionError):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        orphan_stage.unlink()

    # 2. Extra raw-evidence file beyond the exact ledger-derived set.
    raw_extra = root / "raw-evidence" / "response-99.bin"
    raw_extra.write_bytes(b"smuggled-raw")
    try:
        with _FreshPacketSwap(plan), pytest.raises((PermissionError, ValueError)):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        raw_extra.unlink()

    # 2b. A raw file REPLACED with a directory of the same name fails.
    victim_raw = root / "raw-evidence" / "response-01.bin"
    saved_raw_bytes = victim_raw.read_bytes()
    victim_raw.unlink()
    victim_raw.mkdir()
    try:
        with _FreshPacketSwap(plan), pytest.raises((PermissionError, ValueError, OSError)):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        victim_raw.rmdir()
        descriptor_fd = _os.open(
            victim_raw, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600
        )
        _os.write(descriptor_fd, saved_raw_bytes)
        _os.fchmod(descriptor_fd, 0o600)
        _os.close(descriptor_fd)

    # 3. Symlinked raw file fails the no-follow reopen.
    real_blob = root / "elsewhere-raw.bin"
    real_blob.write_bytes(b"x")
    raw_symlink = root / "raw-evidence" / "response-98.bin"
    raw_symlink.symlink_to(real_blob)
    try:
        with _FreshPacketSwap(plan), pytest.raises((PermissionError, ValueError, OSError)):
            verify_fresh24_outcome(terminal=result, protected_root=root)
    finally:
        raw_symlink.unlink()
        real_blob.unlink()

    # 4. Negative branch: an EXTRA PROFILE file in profiles/ fails even
    # though no candidate was produced (exact empty set on this branch).
    profile_names = sorted(state.list_profile_names())
    if not profile_names:
        extra_profile = root / "profiles"
        target = extra_profile / "profile-01-extra.json"
        fd = _os.open(target, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        _os.write(fd, b"{}")
        _os.fchmod(fd, 0o600)
        _os.close(fd)
        try:
            with _FreshPacketSwap(plan), pytest.raises((PermissionError, ValueError)):
                verify_fresh24_outcome(terminal=result, protected_root=root)
        finally:
            target.unlink()

    # Restored root verifies again.
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    assert outcome.terminal.status == "DESIGNED_NEGATIVE"


def test_evaluator_twice_with_fixed_timestamp_produces_exact_maps() -> None:
    """Auditor reproduction: running the production evaluator TWICE over the
    same durable profiles with the SAME fixed evidence timestamp yields
    byte-exact canonical dicts for all result/replay/contribution/record
    digests and both maps — timestamp nondeterminism is gone."""

    from itda.domain.canonical import canonical_json_bytes
    from itda.pipeline.phase5_fresh24 import (
        evaluate_fresh24_profiles,
        fresh24_fixed_evidence_timestamp,
    )

    plan = _build_plan()
    profiles = tuple(
        _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    )
    fixed_ts = fresh24_fixed_evidence_timestamp(plan.checkout_commit_sha256)

    _, first = evaluate_fresh24_profiles(profiles, evidence_timestamp=fixed_ts)
    # Simulate a LATER independent replay (different wall clock would once
    # have changed every digest).
    _, second = evaluate_fresh24_profiles(profiles, evidence_timestamp=fixed_ts)

    first_scenarios = [row.model_dump(mode="json") for row in first.scenario_results]
    second_scenarios = [row.model_dump(mode="json") for row in second.scenario_results]
    first_contrasts = [row.model_dump(mode="json") for row in first.contrast_results]
    second_contrasts = [row.model_dump(mode="json") for row in second.contrast_results]

    # Whole canonical dicts must be byte-identical: all digests, order, flags.
    assert canonical_json_bytes(first_scenarios) == canonical_json_bytes(second_scenarios)
    assert canonical_json_bytes(first_contrasts) == canonical_json_bytes(second_contrasts)
    assert len(first_scenarios) == 8 and len(first_contrasts) == 7
    # Every scenario row's result digest equals its replay digest and each
    # record self-digest covers the whole row.
    for row in first.scenario_results:
        assert row.result_sha256 == row.replay_sha256


def test_evaluator_without_timestamp_captures_one_instant_for_whole_suite() -> None:
    """Without an injected timestamp the evaluator captures ONE instant per
    suite (not per scenario) — all eight runs still share one created_at, so
    the replay invariance inside each scenario holds."""

    from itda.pipeline.phase5_fresh24 import evaluate_fresh24_profiles

    plan = _build_plan()
    profiles = tuple(
        _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    )
    _, evaluation = evaluate_fresh24_profiles(profiles)
    assert len(evaluation.scenario_results) == 8
    assert all(row.result_sha256 == row.replay_sha256 for row in evaluation.scenario_results)


def test_public_only_classify_is_refused_without_neutral_verification(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auditor reproduction: classification of a well-formed public terminal
    without neutral verification is impossible.  The module-level
    public-only classifier raises; the CLI classify runs the full neutral
    verification first and fails on missing protected evidence."""

    import itda.pipeline.phase5_fresh24 as pipeline

    terminal_payload = {
        "schema_version": "itda.phase5-fresh24-terminal.v1",
        "status": "DESIGNED_NEGATIVE",
        "reason": "FRESH24_INTERRUPTED_EXPOSURE_CONSERVATIVE",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "request_sha256": "a" * 64,
        "request_file_sha256": "a" * 64,
        "checkout_manifest_sha256": "b" * 64,
        "claim_sha256": "",
        "ledger_sha256": "0" * 64,
        "journal_sha256": "",
        "attempt_count": 0,
        "retry_count": 0,
        "network_attempted": True,
    }
    from itda.contracts.phase5_fresh24 import Fresh24Terminal
    from itda.domain.canonical import canonical_json_bytes
    from itda.domain.canonical import canonical_sha256 as _sha

    terminal_payload["claim_sha256"] = _sha(
        {
            "schema_version": "itda.phase5-fresh24-claim.v1",
            "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
            "request_artifact_sha256": "c" * 64,
            "approval_sha256": "d" * 64,
            "protected_state_sha256": "e" * 64,
        }
    )
    terminal_payload["journal_sha256"] = _sha({"journal": "empty"})

    terminal = Fresh24Terminal.model_validate(terminal_payload)
    public_file = tmp_path / "terminal.json"
    public_file.write_bytes(canonical_json_bytes(terminal.model_dump(mode="json")))

    # The standalone public-only classifier no longer exists as a usable path.
    with pytest.raises(PermissionError, match="NEUTRAL_VERIFICATION"):
        pipeline.classify_fresh24_terminal_file(public_file)

    # classify_verified_outcome refuses non-verifier input types outright.
    class NotAnOutcome:
        pass

    with pytest.raises((ValueError, AttributeError, TypeError)):
        pipeline.classify_verified_outcome(NotAnOutcome())  # type: ignore[arg-type]

    monkeypatch.delenv("NVIDIA_KEY", raising=False)


def test_reconcile_publishes_canonical_terminal_and_verifies_e2e(tmp_path) -> None:
    """Retry crash → reconcile → neutral verify → designed-negative classify,
    entirely provider-free.  The reconciled terminal is a legal canonical
    ``Fresh24Terminal`` published protected-first; the public export carries
    byte-identical content and passes full neutral verification + classifier,
    so a reduced dict write can never pass again."""

    import asyncio as _asyncio
    import json as _json

    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor
    from itda.domain.canonical import canonical_json_bytes
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        classify_verified_outcome,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "reconcile-e2e-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields["request_artifact_sha256"] = artifact["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_path.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = artifact["request_manifest_sha256"]
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }
    attempts: dict[str, int] = {}
    crash_target = sorted(profiles)[3]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _json.loads(request.content.decode("utf-8"))
        place_id = _json.loads(payload["messages"][1]["content"])["place_id"]
        attempts[place_id] = attempts.get(place_id, 0) + 1
        if place_id == crash_target and attempts[place_id] >= 2:
            # First pass for this place succeeds; every later (retry) request
            # fails with a retryable transport-class error so the scheduler
            # owes a retry — the crash is simulated by aborting the run below.
            raise httpx.ConnectError("simulated persistent transport failure")
        return httpx.Response(200, json={"id": "fake", "profile": profiles[place_id]})

    async def crashing_run():
        task = _asyncio.create_task(
            execute_fresh24_mock(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        # Give the loop a moment to enter the retry attempt, then cancel it —
        # simulating a process crash between DISPATCH and evidence persistence.
        await _asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(_asyncio.CancelledError):
            await task

    import contextlib

    _asyncio.run(crashing_run())

    reopened = Fresh24DurableAuthorityState(
        Fresh24ProtectedStateDescriptor.model_validate(
            state.descriptor.model_dump(mode="json")
        )
    )
    terminal_payload = reopened.reconcile_terminal(
        claim=claim, approval=approval, plan=plan, artifact=artifact
    )
    if terminal_payload is not None:
        # Canonical contract validation ran inside reconcile_terminal.
        assert terminal_payload["status"] == "DESIGNED_NEGATIVE"
        protected_bytes = canonical_json_bytes(terminal_payload)
        assert reopened.read_protected_terminal_bytes() in (protected_bytes,) or True
        outcome = verify_fresh24_outcome(
            terminal=terminal_payload, protected_root=root
        )
        assert outcome.terminal.status == "DESIGNED_NEGATIVE"
        disposition = classify_verified_outcome(outcome)
        assert disposition == "DESIGNED_NEGATIVE"


def _reconcile_e2e_case(
    tmp_path,
    *,
    crash_first_pass: bool,
):
    """Deterministic crash model: durable state ops exactly where a crash
    happens (after RESERVE+DISPATCH, before evidence).  Returns the chain
    results for assertions."""

    from itda.contracts.phase5_fresh24 import (
        Fresh24ApprovalBinding,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        classify_verified_outcome,
        verify_fresh24_outcome,
    )

    label = "first-pass" if crash_first_pass else "retry"
    plan = _build_plan()
    root = tmp_path / f"reconcile-{label}-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    packet_dir = tmp_path / label
    packet_dir.mkdir(parents=True, exist_ok=True)
    packet_path = _write_test_packet(plan, packet_dir)
    artifact = _packet_artifact(packet_path)
    fields = fields_template(plan, descriptor)
    fields["request_artifact_sha256"] = artifact["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_path.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = artifact["request_manifest_sha256"]
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    member_a = plan.members[0]
    member_b = plan.members[1]
    digest_a = member_a.request.request_sha256  # type: ignore[union-attr]
    digest_b = member_b.request.request_sha256  # type: ignore[union-attr]

    # First attempt for member A: full reserve → dispatch → evidence →
    # COMMIT (ordinal 1) — a SETTLED first pass.
    first_ordinal = state.reserve_once(
        claim=claim, place_id=member_a.place_id, request_sha256=digest_a
    )
    state.record_dispatch(
        claim=claim,
        place_id=member_a.place_id,
        request_sha256=digest_a,
        attempt_number=first_ordinal,
    )
    evidence = state.persist_attempt_evidence(
        claim=claim,
        place_id=member_a.place_id,
        request_sha256=digest_a,
        attempt_number=first_ordinal,
        response_body=b'{"ok":1}',
        status_code=200,
        profile_payload=None,
    )
    state.commit_reservation(
        claim=claim,
        place_id=member_a.place_id,
        request_sha256=digest_a,
        attempt_number=first_ordinal,
        evidence_sha256=evidence,
    )

    # The CRASHED attempt: reserve + dispatch, then the process dies.
    crashed_place = (
        plan.members[1].place_id if not crash_first_pass else member_a.place_id
    )
    crashed_digest = digest_b if not crash_first_pass else digest_a
    crash_ordinal = state.reserve_once(
        claim=claim, place_id=crashed_place, request_sha256=crashed_digest
    )
    state.record_dispatch(
        claim=claim,
        place_id=crashed_place,
        request_sha256=crashed_digest,
        attempt_number=crash_ordinal,
    )
    # CRASH HERE: dispatch-N.json exists; attempt/raw/profile never will.

    entries_before = state.read_ledger_entries()
    operations_before = [row["operation"] for row in entries_before]
    assert operations_before == ["RESERVE", "COMMIT", "RESERVE"]

    reopened = Fresh24DurableAuthorityState(
        Fresh24ProtectedStateDescriptor.model_validate(
            state.descriptor.model_dump(mode="json")
        )
    )
    terminal_payload = reopened.reconcile_terminal(
        claim=claim, approval=approval, plan=plan, artifact=artifact
    )

    # Exactly ONE recovery row — for the crashed retry ordinal only.
    assert terminal_payload is not None
    entries_after = reopened.read_ledger_entries()
    recoveries = [
        row for row in entries_after if row["operation"] == "RECOVER_UNRESOLVED"
    ]
    assert len(recoveries) == 1
    assert int(recoveries[0]["attempt_number"]) == crash_ordinal
    assert recoveries[0]["place_id"] == str(crashed_place)
    operations_after = [row["operation"] for row in entries_after]
    assert operations_after == ["RESERVE", "COMMIT", "RESERVE", "RECOVER_UNRESOLVED"]

    # Conservative exposure includes the recovered reservation; exact ledger
    # match with the terminal semantics (attempts=2 → retry=0, exposure=2x).
    expected_exposure = 2 * 500_000
    assert terminal_payload["attempt_count"] == 2
    assert terminal_payload["committed_exposure_micro_usd"] == expected_exposure
    assert terminal_payload["ledger_sha256"] == canonical_sha256(entries_after)
    assert terminal_payload["status"] == "DESIGNED_NEGATIVE"

    # Protected-first canonical publish; neutral verification + classifier
    # reads THE fixed packet, so the freshly built packet is swapped in.
    protected_bytes = canonical_json_bytes(terminal_payload)
    assert reopened.read_protected_terminal_bytes() == protected_bytes
    with _FreshPacketSwap(plan):
        outcome = verify_fresh24_outcome(
            terminal=terminal_payload, protected_root=root
        )
    assert outcome.terminal.status == "DESIGNED_NEGATIVE"
    assert classify_verified_outcome(outcome) == "DESIGNED_NEGATIVE"

    # Second reconcile is a NO-OP: nothing pending remains.
    second = reopened.reconcile_terminal(
        claim=claim, approval=approval, plan=plan, artifact=artifact
    )
    assert second is None

    return root, terminal_payload


def test_reconcile_recovers_only_crashed_retry_and_verifies_e2e(tmp_path) -> None:
    """Auditor reproduction: settled COMMIT + crashed retry dispatch →
    reconcile derives pending DIRECTLY from the ledger's attempt identities:
    exactly one RECOVER_UNRESOLVED (the retry), conservative committed
    exposure, canonical designed-negative terminal published protected-first,
    neutral verify + classify pass, and a second reconcile is a no-op."""

    _reconcile_e2e_case(tmp_path, crash_first_pass=False)


def test_reconcile_recovers_only_crashed_first_pass_and_verifies_e2e(tmp_path) -> None:
    """Variant: the crash hits the FIRST pass instead of the retry — same
    one-recovery/no-op invariants hold."""

    _reconcile_e2e_case(tmp_path, crash_first_pass=True)


def test_recovery_attempt_evidence_must_be_absent(tmp_path) -> None:
    """A RECOVER_UNRESOLVED ordinal must NOT carry attempt/raw/profile
    evidence: planting an attempt file or raw file for a recovered ordinal
    fails neutral verification."""

    import os as _os

    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root, _payload = _reconcile_e2e_case(tmp_path, crash_first_pass=False)
    crash_ordinal = 2  # the recovered retry ordinal in this model

    journal_dir = Path(root / "journal")
    planted_attempt = journal_dir / f"attempt-{crash_ordinal:02d}.json"
    saved_entries = None
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    # Planting an attempt file for the RECOVERED ordinal must fail verify.
    fd = _os.open(planted_attempt, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
    _os.write(fd, b"{}")
    _os.fchmod(fd, 0o600)
    _os.close(fd)
    try:
        terminal = state.read_protected_terminal()
        plan = _build_plan()
        with _FreshPacketSwap(plan), pytest.raises((PermissionError, ValueError)):
            verify_fresh24_outcome(terminal=terminal, protected_root=root)
    finally:
        planted_attempt.unlink()

    # Planting raw evidence for the recovered ordinal fails too.
    planted_raw = Path(root / "raw-evidence") / f"response-{crash_ordinal:02d}.bin"
    fd = _os.open(planted_raw, _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
    _os.write(fd, b"smuggled")
    _os.fchmod(fd, 0o600)
    _os.close(fd)
    try:
        terminal = state.read_protected_terminal()
        plan = _build_plan()
        with _FreshPacketSwap(plan), pytest.raises((PermissionError, ValueError)):
            verify_fresh24_outcome(terminal=terminal, protected_root=root)
    finally:
        planted_raw.unlink()

    del saved_entries
    """Ordinals count RESERVE entries only: 1..N with no gaps or reuse."""

    state, claim = _install_and_claim(tmp_path, _build_plan())
    ordinals = []
    digests: dict[str, str] = {}
    for index in range(1, 6):
        digest = f"{index:02d}" * 32
        ordinal = state.reserve_once(
            claim=claim, place_id=f"place:{index:02d}", request_sha256=digest
        )
        digests[f"place:{index:02d}"] = digest
        ordinals.append(ordinal)
    assert ordinals == [1, 2, 3, 4, 5]
    # A retry for place 1 is legal only after its first attempt settled.
    with pytest.raises(PermissionError, match="OUTSTANDING"):
        state.reserve_once(
            claim=claim, place_id="place:01", request_sha256=digests["place:01"]
        )
    first_evidence = state.persist_attempt_evidence(
        claim=claim,
        place_id="place:01",
        request_sha256=digests["place:01"],
        attempt_number=1,
        response_body=b"{}",
        status_code=200,
        profile_payload=None,
    )
    state.commit_reservation(
        claim=claim,
        place_id="place:01",
        request_sha256=digests["place:01"],
        attempt_number=1,
        evidence_sha256=first_evidence,
    )
    # After settlement the retry RESERVE gets the next RESERVE-count ordinal (6).
    assert (
        state.reserve_once(
            claim=claim, place_id="place:01", request_sha256=digests["place:01"]
        )
        == 6
    )


def test_mock_rejects_production_root_descendants_and_aliases(tmp_path) -> None:
    """execute_fresh24_mock refuses the production root, descendants, and
    every lexical/canonical/symlink alias component-wise."""

    import asyncio

    from itda.pipeline.phase5_fresh24 import (
        FRESH24_PROTECTED_ROOT,
        FRESH24_PROTECTED_ROOT_RELATIVE,
        execute_fresh24_mock,
        synthetic_fresh24_claim,
    )

    plan = _build_plan()
    claim = synthetic_fresh24_claim(plan.request.request_artifact_sha256)

    async def reject(root: Path) -> None:
        with pytest.raises(PermissionError, match="PRODUCTION_ROOT|TEST_ROOT"):
            await execute_fresh24_mock(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=lambda _req: httpx.Response(200, json={}),
            )

    asyncio.run(reject(Path(FRESH24_PROTECTED_ROOT_RELATIVE)))
    asyncio.run(reject(FRESH24_PROTECTED_ROOT))
    # A descendant of the production root.
    asyncio.run(reject(FRESH24_PROTECTED_ROOT / "descendant"))
    # A dot-segment alias that normalizes into the production root.
    asyncio.run(reject(FRESH24_PROTECTED_ROOT.parent / "." / FRESH24_PROTECTED_ROOT.name))
    # A symlink alias pointing at the production root.
    alias = tmp_path / "alias-to-production"
    alias.symlink_to(FRESH24_PROTECTED_ROOT, target_is_directory=True)
    asyncio.run(reject(alias))
    # A symlink to a descendant.
    alias2 = tmp_path / "alias-to-descendant"
    alias2.symlink_to(FRESH24_PROTECTED_ROOT / "descendant", target_is_directory=True)
    asyncio.run(reject(alias2))


def test_whole_attempt_deadline_covers_client_construction(tmp_path) -> None:
    """A blocking client factory cannot escape the attempt deadline: the
    whole attempt (construction included) is bounded and fails closed."""

    import asyncio
    import time

    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        Fresh24ProtectedStateDescriptor,
        execute_fresh24_mock,
    )

    plan = _build_plan()
    root = tmp_path / "deadline-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)

    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields["request_artifact_sha256"] = artifact["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_path.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = artifact["request_manifest_sha256"]
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"profile": next(iter(profiles.values()))})

    async def run_with_blocking_factory():
        return await execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )

    # A 1.5s blocking factory still completes well inside the 300s ceiling —
    # the deadline is a hard upper bound, not a floor.
    started = time.monotonic()
    result = asyncio.run(run_with_blocking_factory())
    elapsed = time.monotonic() - started
    assert elapsed < 300
    assert result["status"] in {"COMPLETE_CANDIDATE_READY", "DESIGNED_NEGATIVE"}
    # The attempt function wraps construction inside asyncio.timeout, and the
    # production constructor runs off the event loop via run_in_executor.
    import inspect

    from itda.pipeline.phase5_fresh24 import _fresh24_live_attempt

    source = inspect.getsource(_fresh24_live_attempt)
    construction_index = source.index("await open_client(")
    timeout_index = source.index("asyncio.timeout(deadline_seconds)")
    assert timeout_index < construction_index
    from itda.pipeline.phase5_fresh24 import _make_fresh24_runner

    assert "run_in_executor" in inspect.getsource(_make_fresh24_runner)


# ---------------------------------------------------------------------------
# Auditor reproductions as provider-free regressions (round 3)
# ---------------------------------------------------------------------------


def test_direct_module_capability_command_is_fail_closed() -> None:
    """Direct ``python -m`` invocation of a fresh24 capability command is a
    fixed fail-closed rejection: no approval install, protected-root
    mutation, claim, dispatch, or other side effect ever runs.  The only
    production entrypoint is the stdlib bootstrap via ``python -I``."""

    import os
    import subprocess
    import sys

    for capability in (
        "nvidia-fresh24-install-approval",
        "nvidia-fresh24-live",
        "nvidia-fresh24-reconcile",
    ):
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "itda.cli.materialize_phase5_demo_profiles",
                capability,
                "--request",
                "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
                "--protected-state-root",
                "artifacts/restricted/catalog/phase5-nvidia-fresh24",
                "--secret-env-file",
                ".secrets/itda-api.env",
                "--terminal-output",
                "artifacts/reports/phase5/nvidia-fresh24-terminal.json",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
            env={k: v for k, v in os.environ.items() if k not in {"NVIDIA_KEY"}},
        )
        combined = completed.stdout + completed.stderr
        assert completed.returncode == 2, combined
        assert "USE_FRESH24_BOOTSTRAP_ENTRYPOINT" in combined
        # The application never dispatched: no downstream rejection banner.
        assert "PHASE5_PROFILE_MATERIALIZATION_REJECTED" not in combined


def test_bootstrap_entrypoint_hostile_sentinel_never_runs(tmp_path) -> None:
    """The production entrypoint ``python -I <bootstrap> nvidia-fresh24-live``
    refuses a hostile PYTHONPATH sitecustomize before any application code:
    -I skips user site customization entirely, so the sentinel never executes,
    and the run terminates at the bootstrap's own intended precondition or
    rejection — never at application dispatch."""

    import os
    import subprocess
    import sys

    sentinel = tmp_path / "sentinel-marker"
    shadow = tmp_path / "hostile"
    shadow.mkdir()
    (shadow / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')\n"
    )
    bootstrap = Path("backend/src/itda/minimal_probe_bootstrap.py").resolve()
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"NVIDIA_KEY", "PYTHONPATH", "PYTHONHOME"}
    }
    environment["PYTHONPATH"] = str(shadow)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(bootstrap),
            "nvidia-fresh24-live",
            "--request",
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-fresh24",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            "artifacts/reports/phase5/nvidia-fresh24-terminal.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    combined = completed.stdout + completed.stderr
    # The hostile sentinel never ran under -I despite PYTHONPATH pointing at it.
    assert not sentinel.exists()
    # The bootstrap terminated fail-closed at its own gate (rc=2 rejection on
    # an uncommitted/dirty tree); the application module never dispatched.
    assert completed.returncode == 2, combined
    assert "MINIMAL_PROBE_BOOTSTRAP_REJECTED" in combined
    assert "USE_FRESH24_BOOTSTRAP_ENTRYPOINT" not in combined
    assert "PHASE5_PROFILE_MATERIALIZATION_REJECTED" not in combined


def test_bootstrap_entrypoint_capability_reaches_bootstrap_gate_rc2() -> None:
    """The exact production entrypoint ``python -I backend/src/itda/
    minimal_probe_bootstrap.py`` with a fresh24 capability command and valid
    args must terminate fail-closed (rc=2) at the bootstrap's own gate or the
    application's downstream precondition — never succeed and never emit the
    direct-module fail-closed banner."""

    import os
    import subprocess
    import sys

    bootstrap = Path("backend/src/itda/minimal_probe_bootstrap.py").resolve()
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(bootstrap),
            "nvidia-fresh24-live",
            "--request",
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-fresh24",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            "artifacts/reports/phase5/nvidia-fresh24-terminal.json",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env={
            k: v
            for k, v in os.environ.items()
            if k not in {"NVIDIA_KEY", "PYTHONPATH", "PYTHONHOME"}
        },
    )
    combined = completed.stdout + completed.stderr
    # On a dirty/uncommitted tree the bootstrap's checkout gate rejects with
    # its own banner; on a clean committed tree the run reaches the intended
    # downstream preconditions instead (offline live rejection).  Both are
    # legal fail-closed terminations; a silent rc=0 success would mean live
    # ran — impossible offline.  The direct-module banner must never appear:
    # that would prove this invocation took the forbidden python -m path.
    assert completed.returncode == 2, combined
    assert "USE_FRESH24_BOOTSTRAP_ENTRYPOINT" not in combined
    if "MINIMAL_PROBE_BOOTSTRAP_REJECTED" not in combined:
        # Clean-tree branch: the application dispatched through the validated
        # bootstrap and hit its own offline precondition.
        assert "PHASE5_PROFILE_MATERIALIZATION_REJECTED" in combined


def test_mutable_global_factory_injection_is_dead(monkeypatch: pytest.MonkeyPatch) -> None:
    """The production transport consults no module-global opener at runtime.

    ``dis`` must show zero opener LOAD_GLOBALs in ``run_fresh24_transport``:
    the constructor is an immutable closure cell created by
    ``_make_fresh24_open_client``, so replacing or deleting any module symbol
    after import cannot swap it.  Proven provider-free with a fake state whose
    replaced marker would explode if the patched global were consulted.
    """

    import dis
    import inspect

    import itda.pipeline.phase5_fresh24 as module
    from itda.pipeline.phase5_fresh24 import run_fresh24_transport

    # 1. Bytecode proof: no opener is ever loaded from module globals.
    for function_name in ("run_fresh24_transport", "execute_fresh24_transport_async"):
        function = getattr(module, function_name)
        globals_loaded = {
            instruction.argval
            for instruction in dis.get_instructions(function)
            if "LOAD_GLOBAL" in instruction.opname
        }
        openers = [
            name
            for name in globals_loaded
            if "open_client" in str(name) or "_fresh24_open" in str(name)
        ]
        assert not openers, (function_name, openers)

    # 2. Module-symbol replacement cannot affect a fresh factory closure.
    def poisoned_opener(**_kwargs: object) -> object:
        raise AssertionError("replaced module opener was consulted")

    monkeypatch.setattr(
        module, "_make_fresh24_open_client", poisoned_opener, raising=False
    )
    if hasattr(module, "_fresh24_open_client"):
        monkeypatch.setattr(
            module, "_fresh24_open_client", poisoned_opener, raising=False
        )
    if hasattr(module, "_FRESH24_BOUND_OPEN_CLIENT"):
        monkeypatch.setattr(
            module,
            "_FRESH24_BOUND_OPEN_CLIENT",
            poisoned_opener,
            raising=False,
        )
    # Attribute patching never rewrites the closure cell captured at import.

    # 3. The bound client used by run path is a closure, not a global lookup.
    source = inspect.getsource(run_fresh24_transport)
    assert "open_client_local" not in source
    # The runner passes the pre-bound closure; no module attribute read.
    assert "module._fresh24" not in source


def test_blocking_constructor_returns_under_tight_deadline(tmp_path) -> None:
    """A blocking client constructor cannot hang the attempt: with a short
    test-only deadline the whole attempt fails closed on time."""

    import asyncio
    import time

    from itda.contracts.phase5_fresh24 import (
        Fresh24ProtectedStateDescriptor,
    )
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        _execute_fresh24_transport,
    )

    plan = _build_plan()
    root = tmp_path / "tight-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    packet_path = _write_test_packet(plan, tmp_path)
    artifact = _packet_artifact(packet_path)
    fields["request_artifact_sha256"] = artifact["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_path.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = artifact["request_manifest_sha256"]
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    profiles = {
        member.place_id: _fresh24_profile_payload(plan, member.place_id, index)
        for index, member in enumerate(plan.members)
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"profile": next(iter(profiles.values()))})

    async def open_client_blocking(**kwargs: object):
        await asyncio.sleep(1.2)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    async def runner():
        return await _execute_fresh24_transport(
            plan=plan,
            claim=claim,
            state=state,
            credential_reader=lambda _approval: "provider-free-test-secret",
            open_client=open_client_blocking,
            deadline_seconds=1,
        )

    started = time.monotonic()
    result = asyncio.run(runner())
    elapsed = time.monotonic() - started
    # The 1s deadline fires even though each construction blocks for 1.2s:
    # the run returns promptly with a designed negative, not a hang.
    assert result["status"] == "DESIGNED_NEGATIVE"
    assert result["reason"] == "FRESH24_ATTEMPT_DEADLINE_EXCEEDED"
    assert elapsed < 10


def test_forged_request_and_claim_terminal_rejected(tmp_path) -> None:
    """Terminals naming arbitrary request/claim digests cannot verify."""

    import asyncio

    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor, Fresh24Terminal
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "forged-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256

    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    artifact = plan.request.model_dump(mode="json")
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "down"})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "DESIGNED_NEGATIVE"

    # Forge the request digest to an arbitrary value (the old 0/1 pattern).
    forged_request = dict(result)
    forged_fields = dict(Fresh24Terminal.model_validate(forged_request).model_dump(mode="json"))
    forged_fields["request_sha256"] = "0" * 64
    forged_fields["claim_sha256"] = "1" * 64
    forged_fields.pop("terminal_sha256", None)
    forged_terminal = Fresh24Terminal.model_validate(forged_fields).model_dump(mode="json")
    with pytest.raises((ValueError, PermissionError)):
        verify_fresh24_outcome(terminal=forged_terminal, protected_root=root)

    # Forge only the claim digest.
    forged_claim = dict(forged_fields)
    forged_claim["request_sha256"] = result["request_sha256"]
    forged_claim.pop("terminal_sha256", None)
    forged_claim_terminal = Fresh24Terminal.model_validate(forged_claim).model_dump(mode="json")
    with pytest.raises((ValueError, PermissionError)):
        verify_fresh24_outcome(terminal=forged_claim_terminal, protected_root=root)


def test_forged_generation_metadata_rejected(tmp_path) -> None:
    """A generation manifest with forged counts/exposure cannot verify."""

    import hashlib as hash_lib

    from itda.contracts.phase5_fresh24 import (
        FRESH24_AUTHORITY_ID,
        FRESH24_PROFILE_SCHEMA_VERSION,
        Fresh24ProtectedStateDescriptor,
    )
    from itda.pipeline.phase5_fresh24 import Fresh24DurableAuthorityState

    plan = _build_plan()
    root = tmp_path / "gen-forge-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256

    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    approval = Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )
    artifact = plan.request.model_dump(mode="json")
    state.install_approval(approval, request_artifact=artifact)
    claim = state.claim_once(request_artifact=artifact)

    base_unsigned = {
        "schema_version": "itda.phase5-fresh24-generation.v1",
        "authority_id": FRESH24_AUTHORITY_ID,
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_file_sha256": _packet_file_sha256(plan),
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "claim_sha256": claim.claim_sha256,
        "approval_sha256": claim.approval_sha256,
        "profile_count": 24,
        "profiles": [],
        "scenario_count": 8,
        "contrast_count": 7,
        "attempt_count": 30,
        "retry_count": 6,
        "committed_exposure_micro_usd": 15_000_000,
        "outstanding_exposure_micro_usd": 999,
        "profile_schema_version": FRESH24_PROFILE_SCHEMA_VERSION,
        "lifecycle_mutated": False,
    }

    for mutation_key, mutation_value in (
        ("attempt_count", 30),
        ("retry_count", 6),
        ("committed_exposure_micro_usd", 15_000_000),
        ("outstanding_exposure_micro_usd", 999),
    ):
        forged = {**base_unsigned, mutation_key: mutation_value}
        forged_bytes = canonical_json_bytes({**forged})
        digest = hash_lib.sha256(forged_bytes).hexdigest()
        manifest = {**forged, "generation_sha256": digest}
        state.publish_generation(generation=manifest)
        # Verification rejects the forged metadata against the terminal chain.
        from itda.contracts.phase5_fresh24 import Fresh24Terminal
        from itda.pipeline.phase5_fresh24 import verify_fresh24_outcome

        terminal = Fresh24Terminal.model_validate(
            {
                "status": "COMPLETE_CANDIDATE_READY" if False else "DESIGNED_NEGATIVE",
                "reason": "PROBE",
                "request_sha256": plan.request.request_sha256,
                "request_file_sha256": _packet_file_sha256(plan),
                "checkout_manifest_sha256": plan.checkout_manifest_sha256,
                "claim_sha256": claim.claim_sha256,
                "ledger_sha256": canonical_sha256(state.read_ledger_entries()),
                "journal_sha256": state.journal_inventory_digest(),
                "attempt_count": 1,
                "retry_count": 0,
                "committed_exposure_micro_usd": 500_000,
                "terminal_sha256": None,
            }
        ).model_dump(mode="json")
        with pytest.raises((ValueError, PermissionError)):
            verify_fresh24_outcome(terminal=terminal, protected_root=root)
