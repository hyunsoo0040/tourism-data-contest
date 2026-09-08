from __future__ import annotations

import json
import os
import stat
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


def _sources():
    from itda.pipeline.demo_profile_materialization import build_synthetic_replay_sources

    return build_synthetic_replay_sources(
        {"place_ids": [f"canonical-dev-{index:02d}" for index in range(1, 25)]}
    )


def _profile(place_id: str, confidence: int = 70, axis: tuple[int, int, int] = (80, 50, 20)):
    evidence_id = f"evidence-{place_id}"
    keys = (
        "H",
        "E",
        "R",
        *(f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)),
        *(f"M{index}" for index in range(1, 7)),
    )
    return {
        "place_id": place_id,
        "axis_scores": dict(zip(("H", "E", "R"), axis, strict=True)),
        "subattributes": {
            **{f"H{index}": 3 for index in range(1, 5)},
            **{f"I{index}": 2 for index in range(1, 5)},
            **{f"R{index}": 3 for index in range(1, 5)},
        },
        "mismatch_traits": {f"M{index}": 10 for index in range(1, 7)},
        "evidence_ids": [evidence_id],
        "evidence_justifications": {key: [evidence_id] for key in keys},
        "confidence": confidence,
    }


def test_fresh_plan_public_request_is_path_free_and_exact_dev24() -> None:
    from itda.pipeline.phase5_fresh_cohort import build_fresh_cohort_plan

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="a" * 64)
    payload = plan.public_request.model_dump(mode="json")
    assert len(plan.request_bodies) == 24
    assert payload["authority_id"] == "phase5-nvidia-minimax-m3-fresh-d24-20260816"
    assert payload["cumulative_exposure_cap_micro_usd"] == 15_000_000
    assert payload["reservation_micro_usd"] == 500_000
    assert payload["max_new_http_attempts"] == 30
    assert payload["price_status"] == "UNKNOWN"
    assert payload["network_attempted"] is False
    assert all("path" not in key.lower() for key in payload)
    assert not any(
        value.startswith(("/", "~/", "file://"))
        for value in payload.values()
        if isinstance(value, str)
    )


def test_checkout_manifest_excludes_public_request_self_binding(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh_cohort import checkout_manifest_sha256

    public_request = (
        tmp_path
        / "artifacts"
        / "public"
        / "phase5"
        / "fresh-provider-materialization-request.json"
    )
    public_request.parent.mkdir(parents=True)
    public_request.write_text("first", encoding="utf-8")
    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "add", "source.py", str(public_request.relative_to(tmp_path))],
        cwd=tmp_path,
        check=True,
    )

    first = checkout_manifest_sha256(tmp_path)
    public_request.write_text("second", encoding="utf-8")

    assert checkout_manifest_sha256(tmp_path) == first


def test_fresh_authority_claim_is_one_use_and_protected_state_is_not_public(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_approval_binding,
        build_fresh_cohort_plan,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="b" * 64)
    resolver = FreshProtectedStateResolver(protected_state_root=tmp_path / "fresh")
    descriptor = resolver.resolve(plan.authority_id)
    approval = build_fresh_approval_binding(
        plan=plan,
        descriptor=descriptor,
        trusted_decision_sha256="c" * 64,
    )
    state = FreshAuthorityState(plan=plan, descriptor=descriptor)
    state.install_approval(approval)
    claim = state.claim_once()
    assert claim.authority_id == plan.authority_id
    with pytest.raises(PermissionError, match="ALREADY_CLAIMED"):
        state.claim_once()
    public = json.dumps(plan.public_request.model_dump(mode="json"))
    assert str(descriptor.state_root) not in public
    assert str(descriptor.raw_evidence_target) not in public


def test_fresh_executor_keeps_confidence_69_low_and_70_eligible() -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_approval_binding,
        build_fresh_cohort_plan,
        execute_fresh_cohort,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="d" * 64)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=Path("/tmp/fresh-state")
    ).descriptor
    state = FreshAuthorityState(plan=plan, descriptor=descriptor)
    state.install_approval(
        build_fresh_approval_binding(
            plan=plan,
            descriptor=descriptor,
            trusted_decision_sha256="e" * 64,
        )
    )
    returned = {
        place_id: _profile(
            place_id,
            confidence=69 if index == 1 else 70,
            axis=(
                (90 - index) if index < 8 else 20,
                (90 - (index - 8)) if 8 <= index < 16 else 20,
                (90 - (index - 16)) if index >= 16 else 20,
            ),
        )
        for index, (place_id, _) in enumerate(plan.request_bodies)
    }
    result = execute_fresh_cohort(
        plan=plan,
        authority=state,
        transport=lambda place_id, _: returned[place_id],
    )
    assert result.terminal_reason is None
    assert result.release_build_eligible is True
    assert result.observations[1].decision.reason == "LOW_CONFIDENCE"
    assert result.observations[1].profile["confidence"] == 69  # type: ignore[index]
    assert result.observations[0].decision.recommendation_eligible is True


def test_fresh_durable_approval_survives_restart_and_claims_once(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshDurableAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_approval_binding,
        build_fresh_approval_decision,
        build_fresh_cohort_plan,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="f" * 64)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor
    decision = build_fresh_approval_decision(
        plan=plan,
        request_artifact_sha256="8" * 64,
        approval_payload_sha256="1" * 64,
    )
    approval = build_fresh_approval_binding(
        plan=plan,
        descriptor=descriptor,
        trusted_decision_sha256=decision.decision_sha256,
        request_artifact_sha256=decision.request_artifact_sha256,
        approval_payload_sha256=decision.approval_payload_sha256,
    )
    installed = FreshDurableAuthorityState(plan=plan, descriptor=descriptor)

    projection = installed.install_approval(approval, decision=decision)

    assert projection == {
        "schema_version": "itda.phase5-fresh-authority-status.v1",
        "status": "APPROVED_UNCLAIMED",
        "authority_id": plan.authority_id,
        "public_request_sha256": plan.public_request.public_request_sha256,
        "approval_sha256": approval.approval_sha256,
        "claimed": False,
    }
    assert stat.S_IMODE(Path(descriptor.approval_target).stat().st_mode) == 0o600
    assert not any("path" in key.lower() for key in projection)
    assert not any(
        value.startswith(("/", "~/", "file://"))
        for value in projection.values()
        if isinstance(value, str)
    )

    restarted = FreshDurableAuthorityState(plan=plan, descriptor=descriptor)
    assert restarted.preflight() == projection
    claim = restarted.claim_once()
    assert claim.authority_id == plan.authority_id
    assert stat.S_IMODE(Path(descriptor.claim_target).stat().st_mode) == 0o600
    with pytest.raises(PermissionError, match="ALREADY_CLAIMED"):
        FreshDurableAuthorityState(plan=plan, descriptor=descriptor).claim_once()


def test_fresh_durable_state_requires_decision_and_rejects_mode_or_link_tamper(
    tmp_path: Path,
) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshDurableAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_approval_binding,
        build_fresh_approval_decision,
        build_fresh_cohort_plan,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="9" * 64)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor
    decision = build_fresh_approval_decision(
        plan=plan,
        request_artifact_sha256="a" * 64,
        approval_payload_sha256="b" * 64,
    )
    approval = build_fresh_approval_binding(
        plan=plan,
        descriptor=descriptor,
        trusted_decision_sha256=decision.decision_sha256,
        request_artifact_sha256=decision.request_artifact_sha256,
        approval_payload_sha256=decision.approval_payload_sha256,
    )
    state = FreshDurableAuthorityState(plan=plan, descriptor=descriptor)
    with pytest.raises(PermissionError, match="DECISION_REQUIRED"):
        state.install_approval(approval)
    assert not Path(descriptor.approval_target).exists()

    state.install_approval(approval, decision=decision)
    approval_path = Path(descriptor.approval_target)
    approval_path.chmod(0o644)
    with pytest.raises(PermissionError, match="STATE_FILE_INVALID"):
        state.preflight()
    approval_path.chmod(0o600)
    os.link(approval_path, approval_path.with_name("approval-alias.json"))
    with pytest.raises(PermissionError, match="STATE_FILE_INVALID"):
        state.preflight()


def test_fresh_durable_install_rejects_symlinked_state_ancestor(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshProtectedStateResolver,
        build_fresh_cohort_plan,
        install_fresh_approval_from_public_artifact,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="8" * 64)
    redirected = tmp_path / "redirected"
    redirected.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(redirected, target_is_directory=True)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=alias / "fresh"
    ).descriptor
    artifact = _public_approval_artifact(plan)

    with pytest.raises(ValueError, match="symlink"):
        install_fresh_approval_from_public_artifact(
            plan=plan,
            descriptor=descriptor,
            artifact=artifact,
            approved_payload_sha256=artifact["approval_payload_sha256"],
        )

    assert not (redirected / "fresh" / "state" / "approval.json").exists()


def test_fresh_durable_claim_is_atomic_under_concurrent_consumers(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshDurableAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_cohort_plan,
        install_fresh_approval_from_public_artifact,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="c" * 64)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor
    artifact = _public_approval_artifact(plan)
    install_fresh_approval_from_public_artifact(
        plan=plan,
        descriptor=descriptor,
        artifact=artifact,
        approved_payload_sha256=artifact["approval_payload_sha256"],
    )
    barrier = threading.Barrier(2)

    def claim() -> str:
        barrier.wait(timeout=5)
        try:
            FreshDurableAuthorityState(plan=plan, descriptor=descriptor).claim_once()
        except PermissionError as error:
            return str(error)
        return "CLAIMED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(claim) for _ in range(2)]
        outcomes = sorted(future.result() for future in futures)

    assert outcomes == ["CLAIMED", "FRESH_AUTHORITY_ALREADY_CLAIMED"]


def test_fresh_durable_claim_partial_write_does_not_consume_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline import phase5_fresh_cohort as cohort

    plan = cohort.build_fresh_cohort_plan(_sources(), checkout_manifest="1" * 64)
    descriptor = cohort.FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor
    artifact = _public_approval_artifact(plan)
    cohort.install_fresh_approval_from_public_artifact(
        plan=plan,
        descriptor=descriptor,
        artifact=artifact,
        approved_payload_sha256=artifact["approval_payload_sha256"],
    )
    state = cohort.FreshDurableAuthorityState(plan=plan, descriptor=descriptor)
    real_write = cohort.os.write
    writes = 0

    def interrupted_write(file_descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(file_descriptor, payload[:1])
        raise OSError("simulated claim write interruption")

    monkeypatch.setattr(cohort.os, "write", interrupted_write)
    with pytest.raises(OSError, match="simulated claim write interruption"):
        state.claim_once()
    assert not Path(descriptor.claim_target).exists()

    monkeypatch.setattr(cohort.os, "write", real_write)
    assert state.claim_once().authority_id == plan.authority_id


def test_fresh_durable_approval_rejects_missing_and_request_drift(tmp_path: Path) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshDurableAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_approval_binding,
        build_fresh_cohort_plan,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="2" * 64)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor
    state = FreshDurableAuthorityState(plan=plan, descriptor=descriptor)
    with pytest.raises(PermissionError, match="FRESH_APPROVAL_REQUIRED"):
        state.preflight()

    drifted_plan = build_fresh_cohort_plan(_sources(), checkout_manifest="3" * 64)
    drifted_approval = build_fresh_approval_binding(
        plan=drifted_plan,
        descriptor=descriptor,
        trusted_decision_sha256="4" * 64,
    )
    with pytest.raises(PermissionError, match="CHECKOUT_MISMATCH"):
        state.install_approval(drifted_approval)
    assert not Path(descriptor.approval_target).exists()


def test_fresh_cli_exposes_durable_install_and_documented_live_grammar() -> None:
    from itda.cli.materialize_phase5_demo_profiles import _parser

    parser = _parser()
    install = parser.parse_args(
        [
            "nvidia-fresh-cohort-install-approval",
            "--request",
            "artifacts/public/phase5/fresh-provider-materialization-request.json",
            "--authority-id",
            "phase5-nvidia-minimax-m3-fresh-d24-20260816",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-demo-profile-materialization/fresh",
            "--approval-payload-sha256",
            "5" * 64,
            "--json",
        ]
    )
    live = parser.parse_args(
        [
            "nvidia-fresh-cohort-live",
            "--request",
            "artifacts/public/phase5/fresh-provider-materialization-request.json",
            "--authority-id",
            "phase5-nvidia-minimax-m3-fresh-d24-20260816",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-demo-profile-materialization/fresh",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            "artifacts/reports/phase5/fresh-provider-terminal.json",
            "--json",
        ]
    )

    assert install.command == "nvidia-fresh-cohort-install-approval"
    assert live.command == "nvidia-fresh-cohort-live"


def _public_approval_artifact(plan) -> dict[str, object]:
    from itda.domain.canonical import canonical_sha256

    active_state = "INVALIDATED_LEGACY_PREDECESSOR"
    approval_payload = {
        "authority_id": plan.authority_id,
        "public_request_sha256": plan.public_request.public_request_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "endpoint": plan.public_request.endpoint,
        "model": plan.public_request.model,
        "provider_lane": plan.public_request.provider_lane,
        "cumulative_exposure_cap_micro_usd": 15_000_000,
        "reservation_micro_usd": 500_000,
        "max_new_http_attempts": 30,
        "attempt_deadline_seconds": 300,
        "price_status": "UNKNOWN",
        "invocation_policy": "SINGLE_INVOCATION",
        "confidence_threshold": 70,
        "minimum_eligible_profiles": 5,
        "active_release_state": active_state,
        "blind_access": False,
    }
    artifact = {
        **plan.public_request.model_dump(mode="json"),
        "source_count": 24,
        "dev_member_count": 24,
        "dev_membership_order_sha256": plan.membership_sha256,
        "active_release_state": active_state,
        "active_release_state_sha256": canonical_sha256({"state": active_state}),
        "implementation_commit": "a" * 40,
        "approval_payload_sha256": canonical_sha256(approval_payload),
        "approval_sentence": "approved exact local test payload",
        "secret_read": False,
        "provider_client_constructed": False,
        "network_attempted": False,
    }
    artifact["request_artifact_sha256"] = canonical_sha256(artifact)
    return artifact


def test_fresh_installer_binds_exact_artifact_and_rejects_digest_drift(
    tmp_path: Path,
) -> None:
    from itda.pipeline.phase5_fresh_cohort import (
        FreshDurableAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_cohort_plan,
        install_fresh_approval_from_public_artifact,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="6" * 64)
    artifact = _public_approval_artifact(plan)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor

    projection = install_fresh_approval_from_public_artifact(
        plan=plan,
        descriptor=descriptor,
        artifact=artifact,
        approved_payload_sha256=artifact["approval_payload_sha256"],
    )

    assert projection["status"] == "APPROVED_UNCLAIMED"
    assert FreshDurableAuthorityState(
        plan=plan,
        descriptor=descriptor,
    ).preflight() == projection
    assert Path(descriptor.decision_target).is_file()

    other_descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "other"
    ).descriptor
    with pytest.raises(PermissionError, match="APPROVAL_PAYLOAD_MISMATCH"):
        install_fresh_approval_from_public_artifact(
            plan=plan,
            descriptor=other_descriptor,
            artifact=artifact,
            approved_payload_sha256="7" * 64,
        )
    assert not Path(other_descriptor.approval_target).exists()


def test_fresh_live_dispatch_rejects_local_preflight_before_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as cli

    events: list[str] = []

    def reject_preflight(**_: object) -> object:
        events.append("preflight")
        raise PermissionError("FRESH_PROVIDER_EXECUTION_APPROVAL_REQUIRED")

    monkeypatch.setattr(cli, "_fresh_live_preflight_context", reject_preflight, raising=False)
    monkeypatch.setattr(
        cli,
        "_read_nvidia_secret",
        lambda *_args, **_kwargs: events.append("secret"),
    )
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.setenv("ITDA_PROVIDER_NETWORK", "1")

    code = cli.main(
        [
            "nvidia-fresh-cohort-live",
            "--request",
            "artifacts/public/phase5/fresh-provider-materialization-request.json",
            "--authority-id",
            "phase5-nvidia-minimax-m3-fresh-d24-20260816",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-demo-profile-materialization/fresh",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            "artifacts/reports/phase5/fresh-provider-terminal.json",
            "--json",
        ]
    )

    assert code == 2
    assert events == ["preflight"]
