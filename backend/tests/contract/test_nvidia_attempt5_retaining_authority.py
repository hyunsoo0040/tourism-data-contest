from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Literal

import httpx
import pytest

_AUTHORITY_COMMIT = "a" * 40
_AUTHORITY_TREE = "b" * 40
_ATTEMPT5_PLACE = "place:119da6ea8756c8731f65f3fae9c5553ac16c8317f6688a68013cf3ead04916d8"
_ATTEMPT5_PROFILE = "4feff1d3e1c1bc727c6511d879706b0fbace2527c731d5e6df5580590f5596ae"
_ATTEMPT5_AUTHORITY = "2d6067aa3eb3c03ad419ab915e16ebda43a9524d5ed2eeb767556259efccd170"
_TRUSTED_DECISION_RECORD = "d" * 64
_SEALED_CLIENT_PATCHER: pytest.MonkeyPatch | None = None


@pytest.fixture(autouse=True)
def _bind_sealed_client_patcher(monkeypatch: pytest.MonkeyPatch):
    global _SEALED_CLIENT_PATCHER
    assert _SEALED_CLIENT_PATCHER is None
    _SEALED_CLIENT_PATCHER = monkeypatch
    try:
        yield
    finally:
        _SEALED_CLIENT_PATCHER = None


def _inputs() -> tuple[tuple[object, ...], Path, Path, Path]:
    from itda.contracts.demo_profile_materialization import DemoSourceBundle

    repository_root = Path(__file__).resolve().parents[3]
    artifact_root = (
        repository_root / "artifacts/restricted/catalog/phase5-demo-profile-materialization"
    )
    source_path = artifact_root / "source-bundles.json"
    namespace = (
        artifact_root
        / "nvidia-resume"
        / "459e25977d4704a48f1007f1ad84ecc7c71ff914b8590ce917ef3589f9478011"
    )
    failure = (
        artifact_root
        / "failures"
        / "d7f373f45036728e02f1f16526b893b2e8bf1d02daf27b835500a0f928fc0db7"
    )
    active = artifact_root / "active/current.json"
    if not all(path.exists() for path in (source_path, namespace, failure, active)):
        pytest.skip("exact local restricted attempt-8 evidence is unavailable")
    sources = tuple(
        DemoSourceBundle.model_validate(item) for item in json.loads(source_path.read_bytes())
    )
    return sources, namespace, failure, active


def _plan() -> tuple[tuple[object, ...], object]:
    from itda.pipeline.phase5_attempt5_retaining import build_attempt5_retaining_plan

    sources, namespace, failure, active = _inputs()
    return sources, build_attempt5_retaining_plan(
        source_bundles=sources,
        predecessor_root=namespace,
        failure_root=failure,
        active_pointer_path=active,
    )


def _authority(sources: tuple[object, ...], plan: object) -> object:
    from itda.pipeline.phase5_attempt5_retaining import derive_attempt5_retaining_authority

    return derive_attempt5_retaining_authority(
        source_bundles=sources,
        plan=plan,
        implementation_commit=_AUTHORITY_COMMIT,
        implementation_tree=_AUTHORITY_TREE,
    )


def _execution_approval(authority: object) -> object:
    from itda.pipeline.phase5_attempt5_retaining import (
        derive_attempt5_retaining_execution_approval,
    )

    return derive_attempt5_retaining_execution_approval(
        authority=authority,
        decision_record_sha256=_TRUSTED_DECISION_RECORD,
    )


def _profile_content(
    *,
    index: int,
    evidence_ids: list[str],
    confidence: int = 70,
    cohort: Literal["effective", "identical", "diagonal"] = "effective",
) -> dict[str, object]:
    score_keys = (
        "H",
        "E",
        "R",
        *(f"{prefix}{number}" for prefix in ("H", "I", "R") for number in range(1, 5)),
        *(f"M{number}" for number in range(1, 7)),
    )
    if cohort == "identical":
        axes = {"H": 50, "E": 50, "R": 50}
    elif cohort == "diagonal":
        axes = {"H": 10 + index, "E": 10 + index, "R": 10 + index}
    else:
        axes = {"H": (index * 4) + 1, "E": 100 - (index * 4), "R": (index * 17) % 101}
    return {
        "axis_scores": axes,
        "subattributes": {
            **{f"H{number}": 3 for number in range(1, 5)},
            **{f"I{number}": 2 for number in range(1, 5)},
            **{f"R{number}": 4 for number in range(1, 5)},
        },
        "mismatch_traits": {f"M{number}": number * 10 for number in range(1, 7)},
        "evidence_justifications": {key: [evidence_ids[0]] for key in score_keys},
        "evidence_ids": evidence_ids,
        "confidence": confidence,
        "publishable": True,
    }


def _success_response(content: dict[str, object]) -> httpx.Response:
    from itda.contracts.demo_profile_materialization import (
        NVIDIA_JSON_END_SENTINEL,
        NVIDIA_JSON_START_SENTINEL,
    )

    bounded = (
        NVIDIA_JSON_START_SENTINEL
        + json.dumps(content, ensure_ascii=False, separators=(",", ":"))
        + NVIDIA_JSON_END_SENTINEL
    )
    return httpx.Response(
        200,
        json={
            "model": "minimaxai/minimax-m3",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": bounded},
                }
            ],
            "usage": {
                "prompt_tokens": 1_000,
                "completion_tokens": 100,
                "total_tokens": 1_100,
            },
        },
    )


def _adapter(
    transport: httpx.MockTransport,
    *,
    sleeper: object | None = None,
    config: object | None = None,
    unknown_price_request_exposure: bool = True,
) -> object:
    import itda.providers.nvidia_minimax_profile as provider
    from itda.providers.nvidia_minimax_profile import (
        NvidiaAttemptLedger,
        NvidiaMinimaxProfileAdapter,
        NvidiaRateLimitPolicy,
    )

    def client_factory(*, headers: object, timeout: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,  # type: ignore[arg-type]
            timeout=timeout,  # type: ignore[arg-type]
            transport=transport,
        )

    async def no_wait(_: float) -> None:
        return None

    adapter = NvidiaMinimaxProfileAdapter(
        secret="mock-only-never-persist",
        config=config,  # type: ignore[arg-type]
        ledger=NvidiaAttemptLedger.for_v5_attempt5_retaining(),
        unknown_price_request_exposure=unknown_price_request_exposure,
        sleeper=sleeper if sleeper is not None else no_wait,  # type: ignore[arg-type]
        rate_limit_policy=NvidiaRateLimitPolicy(minimum_interval_seconds=60),
    )
    assert _SEALED_CLIENT_PATCHER is not None
    assert adapter.release_authorizing_transport is True
    _SEALED_CLIENT_PATCHER.setattr(provider, "_new_httpx_async_client", client_factory)
    return adapter


def _execute(
    tmp_path: Path,
    *,
    events: list[str] | None = None,
    confidence: int = 70,
    cohort: Literal["effective", "identical", "diagonal"] = "effective",
    state_sha256: str | None = None,
    observed_calls: list[str] | None = None,
    sleeper: object | None = None,
    state_guard: object | None = None,
) -> tuple[object, list[str], object]:
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal
    from itda.pipeline.phase5_attempt5_retaining import (
        execute_attempt5_retaining_materialization,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    calls = observed_calls if observed_calls is not None else []
    scripted = list(events or [])
    successful_places = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal successful_places
        event = scripted.pop(0) if scripted else "success"
        calls.append(event)
        if event == "connect":
            raise httpx.ConnectError("mock connect failure", request=request)
        if event == "read":
            raise httpx.ReadError("mock read failure", request=request)
        if event == "write":
            raise httpx.WriteError("mock write failure", request=request)
        if event == "deadline":
            raise TimeoutError
        if event == "429":
            return httpx.Response(429, json={"error": {"code": 1113, "message": "limited"}})
        if event == "500":
            return httpx.Response(500, json={"error": {"message": "failed"}})
        if event == "invalid":
            return httpx.Response(200, json={"model": "minimaxai/minimax-m3", "choices": []})
        place_id = plan.remaining_place_ids[successful_places]
        bundle = next(item for item in sources if item.place_id == place_id)
        content = _profile_content(
            index=successful_places,
            evidence_ids=[source.evidence_id for source in bundle.sources],
            confidence=confidence,
            cohort=cohort,
        )
        successful_places += 1
        return _success_response(content)

    journal = DurableNvidiaJournal(
        root=tmp_path / "journal",
        authority_receipt=authority.receipt,
        resume_authority_sha256=authority.authority_sha256,
    )
    journal.require_pristine()
    approval = _execution_approval(authority)
    journal.record_live_start(execution_approval_receipt=approval.receipt)
    result = asyncio.run(
        execute_attempt5_retaining_materialization(
            source_bundles=sources,
            plan=plan,
            authority=authority,
            adapter=_adapter(httpx.MockTransport(handler), sleeper=sleeper),
            journal=journal,
            execution_approval_text=approval.text,
            execution_approval_sha256=approval.approval_sha256,
            trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
            state_guard=(
                state_guard  # type: ignore[arg-type]
                if state_guard is not None
                else lambda: state_sha256 or plan.state_sha256
            ),
        )
    )
    return result, calls, journal


def test_attempt5_retaining_plan_reconstructs_exact_eligibility_and_order() -> None:
    sources, plan = _plan()

    assert tuple(attempt.attempt_number for attempt in plan.predecessor_attempts) == tuple(
        range(1, 9)
    )
    assert plan.eligibility_by_attempt == {
        3: False,
        4: False,
        5: True,
        6: False,
        7: False,
        8: False,
    }
    assert plan.retained_profile.place_id == _ATTEMPT5_PLACE
    assert plan.retained_profile.profile_sha256 == _ATTEMPT5_PROFILE
    assert plan.retained_resume_authority_sha256 == _ATTEMPT5_AUTHORITY
    assert plan.remaining_place_ids == tuple(
        source.place_id for source in sources if source.place_id != _ATTEMPT5_PLACE
    )
    assert len(plan.remaining_place_ids) == 23
    assert plan.active_pointer_sha256 == (
        "9c3d28fb770b3c8b53acee419abdefe1fed21fb14d2854c9f2f5fd685566d0fc"
    )


def test_attempt5_retaining_authority_is_canonical_exact_and_network_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.pipeline.phase5_attempt5_retaining import (
        preflight_attempt5_retaining_authority,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network forbidden")),
    )
    receipt = preflight_attempt5_retaining_authority(
        authority_text=authority.text,
        authority_sha256=authority.authority_sha256,
        source_bundles=sources,
        plan=plan,
        implementation_commit=_AUTHORITY_COMMIT,
        implementation_tree=_AUTHORITY_TREE,
    )
    assert authority.text.encode("utf-8") == authority.canonical_bytes
    assert hashlib.sha256(authority.canonical_bytes).hexdigest() == authority.authority_sha256
    assert receipt == authority.receipt
    assert receipt["new_http_attempt_cap"] == 26
    assert receipt["cumulative_http_attempt_cap"] == 34
    assert receipt["provider_request_config_max_http_attempts"] == 30
    assert receipt["execution_ledger_max_attempts"] == 34
    assert (
        receipt["execution_budget_config_sha256"]
        == hashlib.sha256(
            json.dumps(
                {
                    "cumulative_http_attempt_cap": 34,
                    "historical_attempt_count": 8,
                    "new_http_attempt_cap": 26,
                    "provider_request_config_sha256": receipt["provider_request_config_sha256"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )
    assert receipt["execution_approval_required"] is True
    assert receipt["provider_execution_approved"] is False
    assert receipt["network_attempted"] is False


def test_attempt5_retaining_authority_binds_official_separately_gated_cli_grammar() -> None:
    import itda.cli.materialize_phase5_demo_profiles as command

    sources, plan = _plan()
    authority = _authority(sources, plan)
    preflight = command._parser().parse_args(  # noqa: SLF001 - exact command contract
        [
            "nvidia-v5-attempt5-retaining-preflight",
            "--authority-text",
            authority.text,
            "--authority-sha256",
            authority.authority_sha256,
        ]
    )
    live = command._parser().parse_args(  # noqa: SLF001 - exact command contract
        [
            "nvidia-v5-attempt5-retaining-live",
            "--authority-text",
            authority.text,
            "--authority-sha256",
            authority.authority_sha256,
            "--execution-approval-text",
            "<EXACT_SEPARATE_APPROVAL_TEXT>",
            "--execution-approval-sha256",
            "c" * 64,
        ]
    )
    assert preflight.command == "nvidia-v5-attempt5-retaining-preflight"
    assert not hasattr(preflight, "secret_env_file")
    assert live.command == "nvidia-v5-attempt5-retaining-live"
    assert authority.receipt["preflight_command_grammar"] == (
        "nvidia-v5-attempt5-retaining-preflight --authority-text <EXACT_TEXT> "
        "--authority-sha256 <EXACT_SHA256>"
    )
    assert authority.receipt["live_command_grammar"] == (
        "nvidia-v5-attempt5-retaining-live --authority-text <EXACT_TEXT> "
        "--authority-sha256 <EXACT_SHA256> --execution-approval-text "
        "<EXACT_SEPARATE_APPROVAL_TEXT> --execution-approval-sha256 "
        "<SEPARATE_APPROVAL_SHA256> --secret-env-file .secrets/itda-api.env"
    )


def test_attempt5_retaining_execution_approval_is_canonical_and_authority_bound() -> None:
    from itda.pipeline.phase5_attempt5_retaining import (
        preflight_attempt5_retaining_execution_approval,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    approval = _execution_approval(authority)
    receipt = preflight_attempt5_retaining_execution_approval(
        authority=authority,
        approval_text=approval.text,
        approval_sha256=approval.approval_sha256,
        trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
    )
    assert receipt == approval.receipt
    assert receipt["authority_sha256"] == authority.authority_sha256
    assert receipt["authority_receipt_sha256"] == authority.receipt["receipt_sha256"]
    with pytest.raises(PermissionError, match="TRUSTED_DECISION_ROOT_REQUIRED"):
        preflight_attempt5_retaining_execution_approval(
            authority=authority,
            approval_text=approval.text,
            approval_sha256=approval.approval_sha256,
            trusted_decision_record_sha256=None,
        )


def test_attempt5_retaining_official_live_denies_without_post_checkpoint_root(
    tmp_path: Path,
) -> None:
    import itda.cli.materialize_phase5_demo_profiles as command
    from itda.pipeline.phase5_attempt5_retaining import (
        preflight_attempt5_retaining_execution_approval,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    approval = _execution_approval(authority)
    with pytest.raises(PermissionError, match="trusted execution decision root"):
        command._installed_attempt5_execution_approval(  # noqa: SLF001
            authority=authority,
            approval_text=approval.text,
            approval_sha256=approval.approval_sha256,
            artifact_root=tmp_path,
        )
    assert authority.receipt["trusted_execution_decision_root_installed"] is False
    root = tmp_path / "execution-approvals" / authority.authority_sha256
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    decision = root / "trusted-decision-record.sha256"
    decision.write_bytes(_TRUSTED_DECISION_RECORD.encode())
    decision.chmod(0o600)
    receipt, trusted = command._installed_attempt5_execution_approval(  # noqa: SLF001
        authority=authority,
        approval_text=approval.text,
        approval_sha256=approval.approval_sha256,
        artifact_root=tmp_path,
    )
    assert receipt == approval.receipt
    assert trusted == _TRUSTED_DECISION_RECORD
    with pytest.raises(PermissionError):
        preflight_attempt5_retaining_execution_approval(
            authority=authority,
            approval_text=approval.text.replace(authority.authority_sha256, "f" * 64),
            approval_sha256=approval.approval_sha256,
            trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
        )
    with pytest.raises(PermissionError):
        preflight_attempt5_retaining_execution_approval(
            authority=authority,
            approval_text='{"decision":"APPROVED"}',
            approval_sha256="c" * 64,
            trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
        )


def test_attempt5_retaining_repository_identity_rejects_dirty_implementation_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import itda.cli.materialize_phase5_demo_profiles as command

    calls: list[tuple[str, ...]] = []

    class Completed:
        def __init__(self, stdout: str = "", returncode: int = 0) -> None:
            self.stdout = stdout
            self.returncode = returncode

    def dirty_run(arguments: list[str], **_kwargs: object) -> Completed:
        calls.append(tuple(arguments))
        if arguments[1:3] == ["rev-parse", "HEAD"]:
            return Completed("a" * 40 + "\n")
        if arguments[1:3] == ["rev-parse", "HEAD^{tree}"]:
            return Completed("b" * 40 + "\n")
        if arguments[1:3] == ["status", "--porcelain=v1"]:
            return Completed(" M backend/src/itda/domain/demo_profile_eligibility.py\n")
        raise AssertionError(arguments)

    monkeypatch.setattr(command.subprocess, "run", dirty_run)
    with pytest.raises(PermissionError, match="implementation scope is dirty"):
        command._repository_identity()  # noqa: SLF001
    status_calls = [
        arguments for arguments in calls if arguments[1:3] == ("status", "--porcelain=v1")
    ]
    assert status_calls
    assert "backend/src/itda" in status_calls[0]
    assert "backend/uv.lock" in status_calls[0]


def test_attempt5_retaining_official_cli_context_uses_committed_identity_without_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import itda.cli.materialize_phase5_demo_profiles as command

    sources, plan = _plan()
    monkeypatch.setattr(
        command, "_repository_identity", lambda: (_AUTHORITY_COMMIT, _AUTHORITY_TREE)
    )
    commit, tree = command._repository_identity()  # noqa: SLF001 - exact local identity
    authority = command.derive_attempt5_retaining_authority(
        source_bundles=sources,
        plan=plan,
        implementation_commit=commit,
        implementation_tree=tree,
    )
    loaded_sources, loaded_plan, loaded_authority = command._attempt5_retaining_cli_context(  # noqa: SLF001
        authority_text=authority.text,
        authority_sha256=authority.authority_sha256,
        artifact_root=command.OUTPUT_ROOT.parent,
    )
    assert tuple(source.place_id for source in loaded_sources) == tuple(
        source.place_id for source in sources
    )
    assert loaded_plan.state_sha256 == plan.state_sha256
    assert loaded_authority == authority
    with pytest.raises(PermissionError):
        command._require_fixed_artifact_root(Path("elsewhere"))  # noqa: SLF001


@pytest.mark.parametrize("mutation", ("attempt5_hash", "attempt5_lineage", "low_confidence", "v4"))
def test_attempt5_retaining_rejects_retained_content_hash_and_lineage_tamper(
    mutation: str,
) -> None:
    from itda.contracts.demo_profile_materialization import seal_demo_contract

    sources, plan = _plan()
    profile = plan.retained_profile
    if mutation == "attempt5_hash":
        profile = profile.model_copy(update={"profile_sha256": "f" * 64})
    elif mutation == "attempt5_lineage":
        profile = profile.model_copy(update={"request_sha256": "f" * 64})
    elif mutation == "v4":
        profile = profile.model_copy(
            update={"schema_version": "itda.nvidia-minimax-model-derived-profile.v4"}
        )
    else:
        fields = profile.model_dump(mode="json", exclude={"profile_sha256"})
        fields["confidence"] = 69
        profile = type(profile).model_validate(
            seal_demo_contract(fields, digest_field="profile_sha256"),
            context={"known_evidence_ids": set(profile.evidence_ids)},
        )

    with pytest.raises(ValueError):
        _authority(sources, replace(plan, retained_profile=profile))


@pytest.mark.parametrize("mutation", ("membership", "order", "attempt", "active"))
def test_attempt5_retaining_rejects_membership_order_attempt_and_state_drift(
    mutation: str,
) -> None:
    sources, plan = _plan()
    changed = plan
    if mutation == "membership":
        changed = replace(plan, remaining_place_ids=plan.remaining_place_ids[:-1])
    elif mutation == "order":
        changed = replace(plan, remaining_place_ids=tuple(reversed(plan.remaining_place_ids)))
    elif mutation == "attempt":
        attempts = list(plan.predecessor_attempts)
        attempts[4] = attempts[4].model_copy(update={"request_sha256": "f" * 64})
        changed = replace(plan, predecessor_attempts=tuple(attempts))
    else:
        changed = replace(plan, active_pointer_sha256="f" * 64)

    with pytest.raises(ValueError):
        _authority(sources, changed)


def test_attempt5_retaining_preflight_rejects_stale_and_duplicate_authority() -> None:
    from itda.pipeline.phase5_attempt5_retaining import (
        preflight_attempt5_retaining_authority,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    kwargs = {
        "authority_sha256": authority.authority_sha256,
        "source_bundles": sources,
        "plan": plan,
        "implementation_commit": _AUTHORITY_COMMIT,
        "implementation_tree": _AUTHORITY_TREE,
    }
    with pytest.raises(PermissionError):
        preflight_attempt5_retaining_authority(authority_text=authority.text + "\n", **kwargs)
    duplicate = authority.text[:-1] + ',"schema_version":"duplicate"}'
    with pytest.raises(PermissionError):
        preflight_attempt5_retaining_authority(authority_text=duplicate, **kwargs)


def test_attempt5_retaining_success_requests_ordered_dev23_and_seals_lineage(
    tmp_path: Path,
) -> None:
    from itda.pipeline.phase5_attempt5_retaining import (
        publish_attempt5_retaining_generation,
    )

    result, calls, journal = _execute(tmp_path)

    assert calls == ["success"] * 23
    assert len(result.profiles) == 24
    assert tuple(attempt.attempt_number for attempt in result.attempts) == tuple(range(1, 32))
    assert len(result.profile_lineage) == 24
    retained = next(item for item in result.profile_lineage if item.role == "RETAINED_ATTEMPT5")
    assert retained.attempt_number == 5
    assert retained.resume_authority_sha256 == _ATTEMPT5_AUTHORITY
    assert all(
        item.resume_authority_sha256 == result.authority_sha256
        for item in result.profile_lineage
        if item.role == "NEW_DEV23"
    )
    assert result.receipt["retry_count"] == 0
    assert result.receipt["http_attempt_count"] == 31
    generation = publish_attempt5_retaining_generation(
        result,
        output_root=tmp_path / "generations",
    )
    reservations = sorted((journal.root / "reservations").glob("*/reservation.json"))
    assert len(reservations) == 23
    first_reservation = json.loads(reservations[0].read_bytes())
    assert first_reservation["provider_price_status"] == "UNKNOWN"
    assert first_reservation["cost_exposure_request_equivalents"] == 1
    assert first_reservation["worst_case_charge_micro_usd"] is None
    journal.record_attempt5_retaining_complete(result.receipt, generation_path=generation)
    assert {path.name for path in generation.iterdir()} == {
        "profiles.json",
        "attempts.json",
        "receipt.json",
    }
    assert (journal.root / "complete/complete.json").is_file()


def test_attempt5_retaining_generation_and_complete_reject_forged_receipt(
    tmp_path: Path,
) -> None:
    from itda.pipeline.phase5_attempt5_retaining import (
        publish_attempt5_retaining_generation,
    )

    result, _calls, journal = _execute(tmp_path / "run")
    forged_receipt = {**result.receipt, "generation_sha256": "f" * 64}
    forged_result = replace(result, receipt=forged_receipt)
    with pytest.raises(ValueError, match="GENERATION|RECEIPT"):
        publish_attempt5_retaining_generation(
            forged_result,
            output_root=tmp_path / "generations",
        )
    with pytest.raises((ValueError, PermissionError), match="generation"):
        journal.record_attempt5_retaining_complete(
            result.receipt,
            generation_path=tmp_path / "absent-generation",
        )
    generation = publish_attempt5_retaining_generation(
        result,
        output_root=tmp_path / "valid-generations",
    )
    (generation / "profiles.json").write_bytes(b"[]")
    with pytest.raises((ValueError, PermissionError), match="profile|generation"):
        journal.record_attempt5_retaining_complete(
            result.receipt,
            generation_path=generation,
        )


def test_attempt5_retaining_official_cli_main_preflight_dispatch_is_secret_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import itda.cli.materialize_phase5_demo_profiles as command

    sources, plan = _plan()
    authority = _authority(sources, plan)
    printed: list[dict[str, object]] = []
    monkeypatch.setattr(
        command,
        "_attempt5_retaining_cli_context",
        lambda **_kwargs: (sources, plan, authority),
    )
    monkeypatch.setattr(command, "_require_fixed_artifact_root", lambda value: value)
    monkeypatch.setattr(
        command,
        "_read_nvidia_secret",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret forbidden")),
    )
    monkeypatch.setattr(
        command,
        "_print_payload",
        lambda payload, **_kwargs: printed.append(payload),
    )
    assert (
        command.main(
            [
                "nvidia-v5-attempt5-retaining-preflight",
                "--authority-text",
                authority.text,
                "--authority-sha256",
                authority.authority_sha256,
            ]
        )
        == 0
    )
    assert printed == [dict(authority.receipt)]


def test_attempt5_retaining_official_cli_main_live_dispatch_uses_mock_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import itda.cli.materialize_phase5_demo_profiles as command

    sources, plan = _plan()
    authority = _authority(sources, plan)
    approval = _execution_approval(authority)
    calls: list[str] = []
    index = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal index
        place_id = plan.remaining_place_ids[index]
        bundle = next(item for item in sources if item.place_id == place_id)
        calls.append(place_id)
        response = _success_response(
            _profile_content(
                index=index,
                evidence_ids=[source.evidence_id for source in bundle.sources],
            )
        )
        index += 1
        return response

    printed: list[dict[str, object]] = []
    monkeypatch.setenv("ITDA_PROVIDER_NETWORK", "1")
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(
        command,
        "_require_fixed_cli_paths",
        lambda **_kwargs: (tmp_path / "synthetic-secret", tmp_path / "artifacts"),
    )
    monkeypatch.setattr(
        command,
        "_attempt5_retaining_cli_context",
        lambda **_kwargs: (sources, plan, authority),
    )
    monkeypatch.setattr(
        command,
        "_installed_attempt5_execution_approval",
        lambda **_kwargs: (approval.receipt, _TRUSTED_DECISION_RECORD),
    )
    monkeypatch.setattr(command, "_read_nvidia_secret", lambda *_args, **_kwargs: (True, "mock"))
    monkeypatch.setattr(
        command,
        "NvidiaMinimaxProfileAdapter",
        lambda **_kwargs: _adapter(httpx.MockTransport(handler)),
    )
    monkeypatch.setattr(command, "build_attempt5_retaining_plan", lambda **_kwargs: plan)
    monkeypatch.setattr(
        command,
        "_print_payload",
        lambda payload, **_kwargs: printed.append(payload),
    )
    assert (
        command.main(
            [
                "nvidia-v5-attempt5-retaining-live",
                "--authority-text",
                authority.text,
                "--authority-sha256",
                authority.authority_sha256,
                "--execution-approval-text",
                approval.text,
                "--execution-approval-sha256",
                approval.approval_sha256,
            ]
        )
        == 0
    )
    assert calls == list(plan.remaining_place_ids)
    assert printed[0]["status"] == "COMPLETE_UNACTIVATED"
    assert next((tmp_path / "artifacts/nvidia-resume").glob("*/complete/complete.json")).is_file()


@pytest.mark.parametrize(
    ("event", "expected_code"),
    (
        ("429", "NVIDIA_RATE_LIMITED"),
        ("500", "NVIDIA_ATTEMPT5_RETAINING_HTTP_FAILED"),
        ("invalid", "NVIDIA_ATTEMPT5_RETAINING_MEMBER_FAILED"),
        ("read", "NVIDIA_ATTEMPT5_RETAINING_TRANSPORT_FAILED"),
        ("write", "NVIDIA_ATTEMPT5_RETAINING_TRANSPORT_FAILED"),
        ("deadline", "NVIDIA_ATTEMPT5_RETAINING_DEADLINE"),
    ),
)
def test_attempt5_retaining_terminal_failures_stop_without_retry(
    tmp_path: Path,
    event: str,
    expected_code: str,
) -> None:
    from itda.pipeline.demo_profile_materialization import DemoProfileMaterializationFailure

    calls: list[str] = []
    with pytest.raises(DemoProfileMaterializationFailure, match=expected_code):
        _execute(tmp_path, events=[event], observed_calls=calls)
    assert calls == [event]
    attempt_payload = json.loads(
        next((tmp_path / "journal/attempts").glob("*/attempt.json")).read_bytes()
    )
    assert attempt_payload["attempt"]["retry"] is False


def test_attempt5_retaining_failure_publication_is_nvidia_and_cost_exposed(
    tmp_path: Path,
) -> None:
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        publish_demo_profile_failure,
    )

    with pytest.raises(DemoProfileMaterializationFailure) as raised:
        _execute(tmp_path / "run", events=["429"])
    destination = publish_demo_profile_failure(
        raised.value,
        output_root=tmp_path / "failures",
    )
    descriptor = json.loads((destination / "failure.json").read_bytes())
    assert descriptor["schema_version"] == (
        "itda.nvidia-minimax-profile-materialization-failure.v1"
    )
    assert descriptor["resume_authority_sha256"] == _authority(*_plan()).authority_sha256
    assert descriptor["provider_price_status"] == "UNKNOWN"
    assert descriptor["cost_exposure_request_equivalents"] == 1
    assert "pricing_snapshot_sha256" not in descriptor


def test_attempt5_retaining_connect_retry_is_per_place_and_total_bounded(tmp_path: Path) -> None:
    sleeps: list[float] = []

    async def sleeper(seconds: float) -> None:
        sleeps.append(seconds)

    result, calls, _journal = _execute(
        tmp_path,
        events=["connect", "success"],
        sleeper=sleeper,
    )
    assert calls[:2] == ["connect", "success"]
    assert len(calls) == 24
    assert result.receipt["retry_count"] == 1
    assert result.receipt["http_attempt_count"] == 32
    assert 60.0 in sleeps

    per_place_calls: list[str] = []
    with pytest.raises(Exception, match="CONNECT_RETRY_EXHAUSTED"):
        _execute(
            tmp_path / "per-place",
            events=["connect", "connect"],
            observed_calls=per_place_calls,
        )
    assert per_place_calls == ["connect", "connect"]
    total_calls: list[str] = []
    with pytest.raises(Exception, match="CONNECT_RETRY_EXHAUSTED"):
        _execute(
            tmp_path / "total",
            events=[
                "connect",
                "success",
                "connect",
                "success",
                "connect",
                "success",
                "connect",
            ],
            observed_calls=total_calls,
        )
    assert total_calls == [
        "connect",
        "success",
        "connect",
        "success",
        "connect",
        "success",
        "connect",
    ]


def test_attempt5_retaining_confidence_boundary_is_69_reject_70_accept(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="MEMBER_FAILED"):
        _execute(tmp_path / "low", confidence=69)
    result, _calls, _journal = _execute(tmp_path / "boundary", confidence=70)
    assert result.receipt["status"] == "COMPLETE_UNACTIVATED"


@pytest.mark.parametrize("cohort", ("identical", "diagonal"))
def test_attempt5_retaining_final_cohort_requires_diversity_and_rank_effectiveness(
    tmp_path: Path,
    cohort: Literal["identical", "diagonal"],
) -> None:
    from itda.pipeline.demo_profile_materialization import DemoProfileMaterializationFailure

    with pytest.raises(
        DemoProfileMaterializationFailure,
        match="NVIDIA_ATTEMPT5_RETAINING_COHORT_REJECTED",
    ):
        _execute(tmp_path, cohort=cohort)
    terminal = json.loads((tmp_path / "journal/terminal/terminal.json").read_bytes())
    assert terminal["failure_code"] == "NVIDIA_ATTEMPT5_RETAINING_COHORT_REJECTED"
    assert terminal["attempt_count"] == 31
    assert terminal["failed_place_id"] == "COHORT_POSTFLIGHT"


def test_attempt5_retaining_durable_claim_no_restart_and_state_guard(tmp_path: Path) -> None:
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal
    from itda.pipeline.phase5_attempt5_retaining import (
        execute_attempt5_retaining_materialization,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    journal = DurableNvidiaJournal(
        root=tmp_path / "journal",
        authority_receipt=authority.receipt,
        resume_authority_sha256=authority.authority_sha256,
    )
    journal.require_pristine()
    approval = _execution_approval(authority)
    journal.record_live_start(execution_approval_receipt=approval.receipt)
    with pytest.raises(PermissionError):
        journal.require_pristine()
    with pytest.raises((FileExistsError, PermissionError)):
        journal.record_live_start()

    transport = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(AssertionError("transport must remain unreachable"))
    )
    with pytest.raises(PermissionError, match="POST_CLAIM_STATE_DRIFT"):
        asyncio.run(
            execute_attempt5_retaining_materialization(
                source_bundles=sources,
                plan=plan,
                authority=authority,
                adapter=_adapter(transport),
                journal=journal,
                execution_approval_text=approval.text,
                execution_approval_sha256=approval.approval_sha256,
                trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
                state_guard=lambda: "f" * 64,
            )
        )

    calls: list[str] = []
    state_checks = iter((plan.state_sha256, "f" * 64))
    with pytest.raises(PermissionError, match="POST_CLAIM_STATE_DRIFT"):
        _execute(
            tmp_path / "between-reservations",
            observed_calls=calls,
            state_guard=lambda: next(state_checks),
        )
    assert calls == []


def test_attempt5_retaining_requires_matching_journal_and_separate_execution_approval(
    tmp_path: Path,
) -> None:
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal
    from itda.pipeline.phase5_attempt5_retaining import (
        execute_attempt5_retaining_materialization,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    forged_receipt = dict(authority.receipt)
    forged_receipt["implementation_tree"] = "f" * 40
    forged = DurableNvidiaJournal(
        root=tmp_path / "forged",
        authority_receipt=forged_receipt,
        resume_authority_sha256=authority.authority_sha256,
    )
    approval = _execution_approval(authority)
    forged.record_live_start(execution_approval_receipt=approval.receipt)
    unreachable = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(AssertionError("transport must remain unreachable"))
    )
    with pytest.raises(PermissionError):
        asyncio.run(
            execute_attempt5_retaining_materialization(
                source_bundles=sources,
                plan=plan,
                authority=authority,
                adapter=_adapter(unreachable),
                journal=forged,
                execution_approval_text=approval.text,
                execution_approval_sha256=approval.approval_sha256,
                trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
                state_guard=lambda: plan.state_sha256,
            )
        )
    with pytest.raises(PermissionError, match="SEPARATE_EXECUTION_APPROVAL_REQUIRED"):
        asyncio.run(
            execute_attempt5_retaining_materialization(
                source_bundles=sources,
                plan=plan,
                authority=authority,
                adapter=_adapter(unreachable),
                journal=forged,
                execution_approval_text=None,
                execution_approval_sha256=None,
                trusted_decision_record_sha256=None,
                state_guard=lambda: plan.state_sha256,
            )
        )


def test_attempt5_retaining_rejects_forged_authority_receipt_and_adapter_config(
    tmp_path: Path,
) -> None:
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal
    from itda.pipeline.phase5_attempt5_retaining import (
        execute_attempt5_retaining_materialization,
    )

    sources, plan = _plan()
    authority = _authority(sources, plan)
    approval = _execution_approval(authority)
    unreachable = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(AssertionError("transport must remain unreachable"))
    )

    forged_receipt = {**authority.receipt, "new_http_attempt_cap": 25}
    forged_receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in forged_receipt.items() if key != "receipt_sha256"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    forged_authority = replace(authority, receipt=forged_receipt)
    forged_approval = _execution_approval(forged_authority)
    forged_journal = DurableNvidiaJournal(
        root=tmp_path / "forged-receipt",
        authority_receipt=forged_receipt,
        resume_authority_sha256=authority.authority_sha256,
    )
    forged_journal.record_live_start(execution_approval_receipt=forged_approval.receipt)
    with pytest.raises(PermissionError, match="AUTHORITY_RECEIPT_MISMATCH"):
        asyncio.run(
            execute_attempt5_retaining_materialization(
                source_bundles=sources,
                plan=plan,
                authority=forged_authority,
                adapter=_adapter(unreachable),
                journal=forged_journal,
                execution_approval_text=forged_approval.text,
                execution_approval_sha256=forged_approval.approval_sha256,
                trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
                state_guard=lambda: plan.state_sha256,
            )
        )

    mutated_config = _adapter(unreachable).config.model_copy(
        update={"endpoint": "https://invalid.example/v1/chat/completions"}
    )
    for name, adapter in (
        ("config", _adapter(unreachable, config=mutated_config)),
        ("exposure", _adapter(unreachable, unknown_price_request_exposure=False)),
    ):
        journal = DurableNvidiaJournal(
            root=tmp_path / name,
            authority_receipt=authority.receipt,
            resume_authority_sha256=authority.authority_sha256,
        )
        journal.record_live_start(execution_approval_receipt=approval.receipt)
        with pytest.raises(PermissionError, match="ADAPTER_(?:CONFIG|COST_EXPOSURE)_INVALID"):
            asyncio.run(
                execute_attempt5_retaining_materialization(
                    source_bundles=sources,
                    plan=plan,
                    authority=authority,
                    adapter=adapter,
                    journal=journal,
                    execution_approval_text=approval.text,
                    execution_approval_sha256=approval.approval_sha256,
                    trusted_decision_record_sha256=_TRUSTED_DECISION_RECORD,
                    state_guard=lambda: plan.state_sha256,
                )
            )


def test_attempt5_retaining_ledger_counts_connect_failures_through_cumulative_34() -> None:
    from itda.providers.nvidia_minimax_profile import NvidiaAttemptLedger

    ledger = NvidiaAttemptLedger.for_v5_attempt5_retaining()
    assert ledger.attempt_count == 8
    assert [ledger.reserve().attempt_number for _ in range(26)] == list(range(9, 35))
    with pytest.raises(RuntimeError, match="NVIDIA_ATTEMPT_BUDGET_EXHAUSTED"):
        ledger.reserve()
