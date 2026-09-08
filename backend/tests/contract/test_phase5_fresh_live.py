from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest


def _sources():
    from itda.pipeline.demo_profile_materialization import build_synthetic_replay_sources

    return build_synthetic_replay_sources(
        {"place_ids": [f"canonical-dev-{index:02d}" for index in range(1, 25)]}
    )


def _profile(
    *,
    place_id: str,
    evidence_ids: list[str],
    index: int,
    confidence: int = 70,
) -> dict[str, object]:
    keys = (
        "H",
        "E",
        "R",
        *(f"{prefix}{number}" for prefix in ("H", "I", "R") for number in range(1, 5)),
        *(f"M{number}" for number in range(1, 7)),
    )
    return {
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
        "evidence_justifications": {key: [evidence_ids[0]] for key in keys},
        "evidence_ids": evidence_ids,
        "confidence": confidence,
        "publishable": True,
    }


def _response(
    *,
    place_id: str,
    evidence_ids: list[str],
    index: int,
    confidence: int = 70,
) -> dict[str, object]:
    from itda.contracts.demo_profile_materialization import (
        NVIDIA_JSON_END_SENTINEL,
        NVIDIA_JSON_START_SENTINEL,
    )

    content = json.dumps(
        _profile(
            place_id=place_id,
            evidence_ids=evidence_ids,
            index=index,
            confidence=confidence,
        ),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "model": "minimaxai/minimax-m3",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": f"{NVIDIA_JSON_START_SENTINEL}{content}{NVIDIA_JSON_END_SENTINEL}",
                    "tool_calls": [],
                },
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


def _installed_state(tmp_path: Path):
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh_cohort import (
        FreshDurableAuthorityState,
        FreshProtectedStateResolver,
        build_fresh_cohort_plan,
        install_fresh_approval_from_public_artifact,
    )

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="a" * 64)
    descriptor = FreshProtectedStateResolver(
        protected_state_root=tmp_path / "fresh"
    ).descriptor
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
    install_fresh_approval_from_public_artifact(
        plan=plan,
        descriptor=descriptor,
        artifact=artifact,
        approved_payload_sha256=artifact["approval_payload_sha256"],
    )
    return plan, descriptor, FreshDurableAuthorityState(plan=plan, descriptor=descriptor)


def test_fresh_public_terminal_partial_write_never_publishes_final_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline import phase5_fresh_live as live

    output = tmp_path / "fresh-terminal.json"
    real_write = live.os.write
    writes = 0

    def interrupted_write(descriptor: int, payload: bytes) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(descriptor, payload[:1])
        raise OSError("simulated terminal write interruption")

    monkeypatch.setattr(live.os, "write", interrupted_write)

    with pytest.raises(OSError, match="simulated terminal write interruption"):
        live._publish_exact_file(output, b'{"status":"FAILED_UNACTIVATED"}')

    assert not output.exists()


def test_fresh_request_manifest_contains_exact_chat_completion_bytes() -> None:
    from itda.pipeline.phase5_fresh_cohort import build_fresh_cohort_plan

    plan = build_fresh_cohort_plan(_sources(), checkout_manifest="b" * 64)

    for place_id, body in plan.request_bodies:
        payload = json.loads(body)
        assert set(payload) == {
            "model",
            "messages",
            "temperature",
            "max_tokens",
            "stream",
            "seed",
            "chat_template_kwargs",
        }
        assert payload["model"] == "minimaxai/minimax-m3"
        assert payload["messages"][0]["role"] == "system"
        user = json.loads(payload["messages"][1]["content"])
        assert user["place_id"] == place_id
        assert user["evidence"]


@pytest.mark.asyncio
async def test_fresh_live_runner_claims_once_and_persists_before_lazy_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_fresh_live import (
        execute_fresh_live_cohort,
        reconcile_fresh_claimed_run,
    )
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    by_place = {bundle.place_id: bundle for bundle in plan.source_bundles}
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append("socket")
        payload = json.loads(request.content)
        user = json.loads(payload["messages"][1]["content"])
        place_id = user["place_id"]
        bundle = by_place[place_id]
        return httpx.Response(
            200,
            json=_response(
                place_id=place_id,
                evidence_ids=[source.evidence_id for source in bundle.sources],
                index=tuple(by_place).index(place_id),
            ),
        )

    def sealed_client(**kwargs: object) -> httpx.AsyncClient:
        calls.append("client")
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(provider, "_new_httpx_async_client", sealed_client)

    def read_secret() -> str:
        calls.append("secret")
        ledger = Path(descriptor.ledger_target)
        assert ledger.is_file()
        assert '"operation":"RESERVE"' in ledger.read_text(encoding="utf-8")
        return "synthetic-fresh-secret"

    terminal = tmp_path / "fresh-terminal.json"
    result = await execute_fresh_live_cohort(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=terminal,
        credential_reader=read_secret,
    )

    assert result["status"] == "COMPLETE_ELIGIBLE_UNACTIVATED"
    assert result["profile_count"] == 24
    assert result["active_member_count"] == 0
    assert result["eligible_count"] == 24
    assert result["attempt_count"] == 24
    assert result["committed_micro_usd"] == 12_000_000
    assert calls[:3] == ["secret", "client", "socket"]
    assert calls.count("socket") == 24
    assert Path(descriptor.claim_target).is_file()
    assert Path(descriptor.ledger_target).read_text(encoding="utf-8").count("\n") == 48
    terminal_bytes = terminal.read_bytes()
    assert b"synthetic-fresh-secret" not in terminal_bytes
    assert str(descriptor.state_root).encode() not in terminal_bytes
    generation = Path(descriptor.state_root).parent / "generations" / str(
        result["generation_sha256"]
    )
    assert generation.is_dir()
    assert {path.name for path in generation.iterdir()} == {
        "profiles.json",
        "attempts.json",
        "publication-decisions.json",
        "receipt.json",
    }
    with pytest.raises(PermissionError, match="ALREADY_CLAIMED"):
        state.claim_once()
    reconciled = reconcile_fresh_claimed_run(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=terminal,
    )
    assert reconciled["terminal_sha256"] == result["terminal_sha256"]


@pytest.mark.asyncio
async def test_fresh_live_preserves_low_confidence_profile_and_explicit_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_fresh_live import execute_fresh_live_cohort
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    by_place = {bundle.place_id: bundle for bundle in plan.source_bundles}

    def handler(request: httpx.Request) -> httpx.Response:
        place_id = json.loads(json.loads(request.content)["messages"][1]["content"])[
            "place_id"
        ]
        index = tuple(by_place).index(place_id)
        bundle = by_place[place_id]
        return httpx.Response(
            200,
            json=_response(
                place_id=place_id,
                evidence_ids=[source.evidence_id for source in bundle.sources],
                index=index,
                confidence=69 if index == 0 else 70,
            ),
        )

    monkeypatch.setattr(
        provider,
        "_new_httpx_async_client",
        lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs),
    )
    result = await execute_fresh_live_cohort(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=tmp_path / "fresh-terminal.json",
        credential_reader=lambda: "synthetic-fresh-secret",
    )

    assert result["status"] == "COMPLETE_ELIGIBLE_UNACTIVATED"
    assert result["eligible_count"] == 23
    assert result["low_confidence_count"] == 1
    generation = Path(descriptor.state_root).parent / "generations" / str(
        result["generation_sha256"]
    )
    profiles = json.loads((generation / "profiles.json").read_bytes())
    assert [profile["confidence"] for profile in profiles].count(69) == 1
    decisions = json.loads((generation / "publication-decisions.json").read_bytes())
    low = [row for row in decisions if not row["recommendation_eligible"]]
    assert len(low) == 1
    assert low[0]["reason"] == "LOW_CONFIDENCE"


@pytest.mark.asyncio
async def test_fresh_live_retries_six_transport_failures_at_exact_thirty_attempt_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_fresh_live import execute_fresh_live_cohort
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    by_place = {bundle.place_id: bundle for bundle in plan.source_bundles}
    failed_once: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        place_id = json.loads(json.loads(request.content)["messages"][1]["content"])[
            "place_id"
        ]
        index = tuple(by_place).index(place_id)
        if index < 6 and place_id not in failed_once:
            failed_once.add(place_id)
            raise httpx.ConnectError("synthetic connect failure", request=request)
        bundle = by_place[place_id]
        return httpx.Response(
            200,
            json=_response(
                place_id=place_id,
                evidence_ids=[source.evidence_id for source in bundle.sources],
                index=index,
            ),
        )

    monkeypatch.setattr(
        provider,
        "_new_httpx_async_client",
        lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs),
    )
    result = await execute_fresh_live_cohort(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=tmp_path / "fresh-terminal.json",
        credential_reader=lambda: "synthetic-fresh-secret",
    )

    assert result["status"] == "COMPLETE_ELIGIBLE_UNACTIVATED"
    assert result["attempt_count"] == 30
    assert result["committed_micro_usd"] == 15_000_000
    assert len(failed_once) == 6


@pytest.mark.asyncio
async def test_fresh_live_runner_terminalizes_first_rate_limit_without_retry_or_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_fresh_live import execute_fresh_live_cohort
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    socket_count = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal socket_count
        socket_count += 1
        return httpx.Response(
            429,
            headers={"retry-after": "60", "x-debug-secret": "synthetic-fresh-secret"},
            json={"error": {"code": 429, "message": "synthetic-fresh-secret limited"}},
        )

    monkeypatch.setattr(
        provider,
        "_new_httpx_async_client",
        lambda **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs),
    )
    terminal = tmp_path / "fresh-terminal.json"

    result = await execute_fresh_live_cohort(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=terminal,
        credential_reader=lambda: "synthetic-fresh-secret",
    )

    assert result["status"] == "FAILED_UNACTIVATED"
    assert result["failure_reason"] == "NVIDIA_RATE_LIMITED"
    assert result["attempt_count"] == 1
    assert result["committed_micro_usd"] == 500_000
    assert socket_count == 1
    assert b"synthetic-fresh-secret" not in terminal.read_bytes()
    raw_files = tuple(Path(descriptor.raw_evidence_target).rglob("*.bin"))
    assert len(raw_files) == 1
    assert b"synthetic-fresh-secret" not in raw_files[0].read_bytes()


@pytest.mark.asyncio
async def test_fresh_claimed_reconciliation_rejects_still_live_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_fresh_live import (
        execute_fresh_live_cohort,
        reconcile_fresh_claimed_run,
    )
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    by_place = {bundle.place_id: bundle for bundle in plan.source_bundles}
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        entered.set()
        await release.wait()
        payload = json.loads(request.content)
        place_id = json.loads(payload["messages"][1]["content"])["place_id"]
        bundle = by_place[place_id]
        return httpx.Response(
            200,
            json=_response(
                place_id=place_id,
                evidence_ids=[source.evidence_id for source in bundle.sources],
                index=tuple(by_place).index(place_id),
            ),
        )

    monkeypatch.setattr(
        provider,
        "_new_httpx_async_client",
        lambda **kwargs: httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            **kwargs,
        ),
    )
    task = asyncio.create_task(
        execute_fresh_live_cohort(
            plan=plan,
            authority=state,
            descriptor=descriptor,
            terminal_output=tmp_path / "fresh-terminal.json",
            credential_reader=lambda: "synthetic-fresh-secret",
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=2)
    outcome: object
    try:
        with pytest.raises(PermissionError, match="FRESH_LIVE_RUN_ACTIVE"):
            reconcile_fresh_claimed_run(
                plan=plan,
                authority=state,
                descriptor=descriptor,
                terminal_output=tmp_path / "fresh-terminal.json",
            )
    finally:
        release.set()
        outcome = (await asyncio.gather(task, return_exceptions=True))[0]
    assert isinstance(outcome, dict)
    assert outcome["status"] == "COMPLETE_ELIGIBLE_UNACTIVATED"


@pytest.mark.asyncio
async def test_fresh_live_cancellation_recovers_outstanding_before_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_fresh_live import (
        execute_fresh_live_cohort,
        reconcile_fresh_claimed_run,
    )
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    entered = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(
        provider,
        "_new_httpx_async_client",
        lambda **kwargs: httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            **kwargs,
        ),
    )
    terminal_output = tmp_path / "fresh-terminal.json"
    task = asyncio.create_task(
        execute_fresh_live_cohort(
            plan=plan,
            authority=state,
            descriptor=descriptor,
            terminal_output=terminal_output,
            credential_reader=lambda: "synthetic-fresh-secret",
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    ledger_bytes = Path(descriptor.ledger_target).read_bytes()
    assert b'"operation":"RECOVER_UNRESOLVED"' in ledger_bytes
    terminal = json.loads(terminal_output.read_bytes())
    assert terminal["outstanding_micro_usd"] == 0
    assert terminal["committed_micro_usd"] == 500_000
    assert (
        reconcile_fresh_claimed_run(
            plan=plan,
            authority=state,
            descriptor=descriptor,
            terminal_output=terminal_output,
        )["terminal_sha256"]
        == terminal["terminal_sha256"]
    )


@pytest.mark.asyncio
async def test_fresh_claimed_recovery_rejects_forged_public_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256
    from itda.pipeline.phase5_fresh_live import (
        execute_fresh_live_cohort,
        reconcile_fresh_claimed_run,
    )
    from itda.providers import nvidia_minimax_profile as provider

    plan, descriptor, state = _installed_state(tmp_path)
    monkeypatch.setattr(
        provider,
        "_new_httpx_async_client",
        lambda **kwargs: httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(429, json={"error": {"code": 429}})
            ),
            **kwargs,
        ),
    )
    terminal_output = tmp_path / "fresh-terminal.json"
    result = await execute_fresh_live_cohort(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=terminal_output,
        credential_reader=lambda: "synthetic-fresh-secret",
    )
    assert result["status"] == "FAILED_UNACTIVATED"
    forged = {
        **json.loads(terminal_output.read_bytes()),
        "status": "COMPLETE_ELIGIBLE_UNACTIVATED",
        "failure_reason": None,
        "activation_capability": True,
    }
    forged["terminal_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "terminal_sha256"}
    )
    terminal_output.write_bytes(canonical_json_bytes(forged))
    terminal_output.chmod(0o600)

    with pytest.raises(PermissionError, match="FRESH_PROVIDER_TERMINAL_INVALID"):
        reconcile_fresh_claimed_run(
            plan=plan,
            authority=state,
            descriptor=descriptor,
            terminal_output=terminal_output,
        )


def test_fresh_claimed_restart_conservatively_commits_unresolved_reservation(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_fresh_cohort import FreshNvidiaExposureLedger
    from itda.pipeline.phase5_fresh_live import (
        FreshDurableRunJournal,
        reconcile_fresh_claimed_run,
    )

    plan, descriptor, state = _installed_state(tmp_path)
    approval_status = state.preflight()
    approval_sha256 = approval_status["approval_sha256"]
    assert isinstance(approval_sha256, str)
    ledger = FreshNvidiaExposureLedger(authority_id=plan.authority_id)
    journal = FreshDurableRunJournal(
        plan=plan,
        descriptor=descriptor,
        ledger=ledger,
        approval_sha256=approval_sha256,
    )
    journal.require_pristine()
    claim = state.claim_once()
    journal.record_live_start(claim_sha256=claim.claim_sha256)
    reservation = ledger.reserve()
    journal.record_reservation(
        {
            "schema_version": "itda.phase5-fresh-exposure-reservation.v1",
            "authority_id": plan.authority_id,
            "provider_lane": "NVIDIA_NIM_API",
            "endpoint": "https://integrate.api.nvidia.com/v1/chat/completions",
            "model": "minimaxai/minimax-m3",
            "attempt_number": reservation.attempt_number,
            "reservation_id": reservation.reservation_id,
            "reservation_micro_usd": reservation.amount_micro_usd,
            "predecessor_sha256": reservation.predecessor_sha256,
            "reservation_sha256": reservation.reservation_sha256,
            "place_id": plan.request_bodies[0][0],
            "request_sha256": "c" * 64,
            "provider_price_status": "UNKNOWN",
        }
    )

    terminal = reconcile_fresh_claimed_run(
        plan=plan,
        authority=state,
        descriptor=descriptor,
        terminal_output=tmp_path / "recovered-terminal.json",
    )

    assert terminal["status"] == "FAILED_UNACTIVATED"
    assert terminal["failure_reason"] == "FRESH_INTERRUPTED_UNRESOLVED_COMMITTED"
    assert terminal["attempt_count"] == 1
    assert terminal["committed_micro_usd"] == 500_000
    assert terminal["outstanding_micro_usd"] == 0
    ledger_rows = Path(descriptor.ledger_target).read_text(encoding="utf-8")
    assert '"operation":"RESERVE"' in ledger_rows
    assert '"operation":"RECOVER_UNRESOLVED"' in ledger_rows


def test_fresh_durable_ledger_rejects_permission_drift_instead_of_repairing_it(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_fresh_cohort import FreshNvidiaExposureLedger
    from itda.pipeline.phase5_fresh_live import FreshDurableRunJournal

    plan, descriptor, state = _installed_state(tmp_path)
    approval_sha256 = state.preflight()["approval_sha256"]
    assert isinstance(approval_sha256, str)
    ledger = FreshNvidiaExposureLedger(authority_id=plan.authority_id)
    journal = FreshDurableRunJournal(
        plan=plan,
        descriptor=descriptor,
        ledger=ledger,
        approval_sha256=approval_sha256,
    )
    journal.require_pristine()
    claim = state.claim_once()
    journal.record_live_start(claim_sha256=claim.claim_sha256)
    first = ledger.reserve()
    journal.record_reservation(
        {
            "authority_id": plan.authority_id,
            "attempt_number": first.attempt_number,
            "reservation_id": first.reservation_id,
            "reservation_micro_usd": first.amount_micro_usd,
            "request_sha256": "d" * 64,
        }
    )
    ledger.release_before_socket(first)
    journal.sync_ledger()
    Path(descriptor.ledger_target).chmod(0o644)

    second = ledger.reserve()
    with pytest.raises(PermissionError, match="FRESH_DURABLE_LEDGER_INVALID"):
        journal.record_reservation(
            {
                "authority_id": plan.authority_id,
                "attempt_number": second.attempt_number,
                "reservation_id": second.reservation_id,
                "reservation_micro_usd": second.amount_micro_usd,
                "request_sha256": "e" * 64,
            }
        )


def test_fresh_claimed_recovery_rejects_canonical_chain_above_attempt_cap(
    tmp_path: Path,
) -> None:
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256
    from itda.pipeline.phase5_fresh_live import reconcile_fresh_claimed_run

    plan, descriptor, state = _installed_state(tmp_path)
    state.claim_once()
    predecessor = "0" * 64
    rows: list[dict[str, object]] = []
    for sequence in range(1, 32):
        digest_fields = {
            "authority_id": plan.authority_id,
            "sequence": sequence,
            "operation": "RESERVE",
            "reservation_id": sequence,
            "amount_micro_usd": 500_000,
            "predecessor_sha256": predecessor,
        }
        predecessor = canonical_sha256(digest_fields)
        rows.append(
            {
                "schema_version": "itda.phase5-fresh-ledger-entry.v1",
                **digest_fields,
                "entry_sha256": predecessor,
            }
        )
    ledger_path = Path(descriptor.ledger_target)
    ledger_path.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))
    ledger_path.chmod(0o600)

    with pytest.raises(PermissionError, match="FRESH_DURABLE_LEDGER_DRIFT"):
        reconcile_fresh_claimed_run(
            plan=plan,
            authority=state,
            descriptor=descriptor,
            terminal_output=tmp_path / "recovered-terminal.json",
        )


def test_fresh_live_cli_reconciles_claimed_run_without_secret_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as cli

    events: list[str] = []
    fake_state = SimpleNamespace(descriptor=object())
    monkeypatch.setattr(
        cli,
        "_fresh_live_preflight_context",
        lambda **_kwargs: (object(), fake_state, {"reconciliation_required": True}),
    )
    monkeypatch.setattr(
        cli,
        "reconcile_fresh_claimed_run",
        lambda **_kwargs: events.append("reconcile")
        or {
            "status": "FAILED_UNACTIVATED",
            "failure_reason": "FRESH_INTERRUPTED_UNRESOLVED_COMMITTED",
        },
    )
    monkeypatch.setattr(
        cli,
        "_read_nvidia_secret",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret read")),
    )
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.delenv("ITDA_PROVIDER_NETWORK", raising=False)

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
    assert events == ["reconcile"]
