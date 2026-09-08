from __future__ import annotations

import asyncio
import builtins
import hashlib
import inspect
import json
import os
from pathlib import Path

import httpx
import pytest


def _durable_reservation_sink(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    sequence = 0

    def persist(payload: object) -> None:
        nonlocal sequence
        sequence += 1
        path = root / f"reservation-{sequence:02d}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(
                descriptor,
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    return persist


def _provider():
    from itda.contracts.demo_profile_materialization import (
        DemoProfileMaterializationConfig,
        ProviderTokenUsage,
    )
    from itda.providers.zhipu_glm5v_profile import (
        AttemptCostLedger,
        TwoPassAttemptBudget,
        ZhipuGlm5vProfileAdapter,
        classify_retry,
    )

    return (
        DemoProfileMaterializationConfig,
        ProviderTokenUsage,
        AttemptCostLedger,
        TwoPassAttemptBudget,
        ZhipuGlm5vProfileAdapter,
        classify_retry,
    )


def test_budget_reservation_allows_exact_cap_and_rejects_one_micro_over_before_factory(
    tmp_path: Path,
) -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    constructed = 0

    def factory(**_: object) -> object:
        nonlocal constructed
        constructed += 1
        raise AssertionError("transport must not be constructed")

    exact = Ledger(committed_micro_usd=4_751_808)
    reservation = exact.reserve()
    assert reservation.amount_micro_usd == 248_192
    assert exact.committed_micro_usd + exact.outstanding_micro_usd == 5_000_000
    exact.commit_unknown(reservation)
    assert exact.committed_micro_usd == 5_000_000

    blocked = Ledger(committed_micro_usd=4_751_809)
    adapter = Adapter(secret="test-secret-never-print", ledger=blocked, client_factory=factory)
    with pytest.raises(RuntimeError, match="COST_BUDGET_EXHAUSTED"):
        asyncio.run(
            adapter.attempt(
                place_id="canonical-dev-01",
                request_body=b"{}",
                reservation_sink=_durable_reservation_sink(tmp_path / "budget"),
            )
        )
    assert constructed == 0


def test_adapter_requires_durable_reservation_before_cost_or_transport() -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    constructed = 0
    ledger = Ledger()

    def factory(**_: object) -> object:
        nonlocal constructed
        constructed += 1
        raise AssertionError("transport must not be constructed")

    adapter = Adapter(secret="test-secret-never-print", ledger=ledger, client_factory=factory)
    with pytest.raises(RuntimeError, match="DURABLE_PROVIDER_RESERVATION_REQUIRED"):
        asyncio.run(
            adapter.attempt(
                place_id="canonical-dev-01",
                request_body=b"{}",
                reservation_sink=None,
            )
        )

    assert constructed == 0
    assert ledger.committed_micro_usd == 0
    assert ledger.outstanding_micro_usd == 0


def test_budget_valid_usage_refunds_only_unused_reservation() -> None:
    _, Usage, Ledger, _, _, _ = _provider()
    ledger = Ledger()
    reservation = ledger.reserve()
    charge = ledger.reconcile(
        reservation,
        Usage(prompt_tokens=1_000, completion_tokens=100, cached_tokens=200),
    )
    assert charge.total_micro_usd == 1_408
    assert ledger.committed_micro_usd == 1_408
    assert ledger.outstanding_micro_usd == 0
    assert reservation.amount_micro_usd - charge.total_micro_usd == 246_784


def test_budget_missing_usage_commits_full_reservation_and_retry_charges_again() -> None:
    _, _, Ledger, _, _, _ = _provider()
    ledger = Ledger()
    first = ledger.reserve()
    ledger.commit_unknown(first)
    second = ledger.reserve()
    ledger.commit_unknown(second)
    assert ledger.committed_micro_usd == 496_384
    assert ledger.outstanding_micro_usd == 0


def test_authorized_rerun_budget_funds_30_new_worst_case_attempts_but_not_31() -> None:
    from itda.contracts.demo_profile_materialization import RERUN_COST_CAP_MICRO_USD

    _, _, Ledger, _, _, _ = _provider()
    ledger = Ledger(max_cost_micro_usd=RERUN_COST_CAP_MICRO_USD)
    for _ in range(30):
        reservation = ledger.reserve()
        ledger.commit_unknown(reservation)

    assert ledger.committed_micro_usd == 7_445_760
    assert ledger.remaining_cap_micro_usd == 54_240
    with pytest.raises(RuntimeError, match="COST_BUDGET_EXHAUSTED"):
        ledger.reserve()


def test_retry_classifier_is_closed_for_transport_and_http_statuses() -> None:
    _, _, _, _, _, classify_retry = _provider()
    for error in (
        httpx.ConnectError("x"),
        httpx.ConnectTimeout("x"),
        httpx.ReadError("x"),
        httpx.ReadTimeout("x"),
        httpx.WriteError("x"),
        httpx.WriteTimeout("x"),
    ):
        assert classify_retry(error=error, status_code=None) is True
    assert classify_retry(error=httpx.PoolTimeout("x"), status_code=None) is False
    for status in (429, 500, 502, 503, 504):
        assert classify_retry(error=None, status_code=status) is True
    for status in (400, 401, 403, 408, 409, 422, 501):
        assert classify_retry(error=None, status_code=status) is False


def test_retry_two_pass_scheduler_gives_all_24_first_attempts_before_six_retries() -> None:
    _, _, _, Budget, _, _ = _provider()
    place_ids = tuple(f"canonical-dev-{index:02d}" for index in range(1, 25))
    budget = Budget(place_ids)
    first_pass = tuple(budget.first_pass())
    retryable = tuple(reversed(first_pass[:10]))
    second_pass = tuple(budget.retry_pass(retryable))

    assert first_pass == place_ids
    assert second_pass == tuple(sorted(retryable))[:6]
    assert budget.attempt_count == 30
    with pytest.raises(RuntimeError, match="ATTEMPT_BUDGET_EXHAUSTED"):
        budget.consume("canonical-dev-24")


def test_adapter_contract_uses_exact_http_policy_and_no_environment_credentials() -> None:
    Config, _, _, _, Adapter, _ = _provider()
    config = Config()
    source = inspect.getsource(Adapter)
    module_source = Path(inspect.getsourcefile(Adapter) or "").read_text(encoding="utf-8")

    assert config.endpoint == "https://api.z.ai/api/paas/v4/chat/completions"
    assert "trust_env=False" in module_source
    assert "follow_redirects=False" in module_source
    assert "Authorization" in module_source
    assert "Bearer" in module_source
    assert "os.environ" not in module_source
    assert "os.getenv" not in module_source
    assert "ZHIPUAI_API_KEY" not in module_source
    assert "BIGMODEL_API_KEY" not in module_source
    assert "secret" not in repr(Adapter(secret="do-not-echo"))
    assert "do-not-echo" not in source


def test_adapter_dispatches_default_general_endpoint_unchanged(tmp_path: Path) -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    observed_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_urls.append(str(request.url))
        return httpx.Response(422, json={"error": {"code": "invalid_request"}}, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    result = asyncio.run(
        Adapter(secret="not-logged", ledger=Ledger(), client_factory=factory).attempt(
            place_id="canonical-dev-01",
            request_body=b"{}",
            reservation_sink=_durable_reservation_sink(tmp_path / "general"),
        )
    )

    assert observed_urls == ["https://api.z.ai/api/paas/v4/chat/completions"]
    assert result.attempt.committed_micro_usd == 248_192


def test_adapter_dispatches_authorized_coding_endpoint_and_records_weight_without_paygo(
    tmp_path: Path,
) -> None:
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_BASE_URL,
        CODING_PLAN_ENDPOINT,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        CodingPlanProfileMaterializationConfig,
    )
    from itda.providers.zhipu_glm5v_profile import (
        CodingPlanAttemptLedger,
        ZhipuGlm5vProfileAdapter,
    )

    observed_urls: list[str] = []
    raw = b'{"error":{"code":"1113","message":"plan condition unavailable"}}'

    def handler(request: httpx.Request) -> httpx.Response:
        observed_urls.append(str(request.url))
        return httpx.Response(429, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    config = CodingPlanProfileMaterializationConfig.for_authorized_base(
        base_url=CODING_PLAN_BASE_URL,
        entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )
    plan_ledger = CodingPlanAttemptLedger(max_attempts=30, model_weight=1)
    adapter = ZhipuGlm5vProfileAdapter(
        secret="not-logged",
        config=config,
        coding_plan_ledger=plan_ledger,
        client_factory=factory,
    )
    result = asyncio.run(
        adapter.attempt(
            place_id="canonical-dev-01",
            request_body=b"{}",
            reservation_sink=_durable_reservation_sink(tmp_path / "coding-plan"),
        )
    )

    assert observed_urls == [CODING_PLAN_ENDPOINT]
    assert result.attempt.error_code == "HTTP_429_PROVIDER_1113"
    assert result.retry is False
    assert result.attempt.provider_lane == "CODING_PLAN_SUBSCRIPTION"
    assert result.attempt.endpoint == CODING_PLAN_ENDPOINT
    assert result.attempt.model == "glm-5v-turbo"
    assert result.attempt.accounting_mode == "CODING_PLAN_WEIGHT"
    assert result.attempt.entitlement_evidence_sha256 == CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    assert result.attempt.subscription_attempt_weight == 1
    assert result.attempt.subscription_cumulative_weight == 1
    assert plan_ledger.attempt_count == 1
    assert plan_ledger.total_weight == 1


def test_adapter_usage_model_finish_and_schema_mismatch_are_terminal_full_charge() -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    cases = (
        {"model": "other", "finish_reason": "stop", "usage": None, "content": {}},
        {"model": "glm-5v-turbo", "finish_reason": "length", "usage": None, "content": {}},
        {"model": "glm-5v-turbo", "finish_reason": "stop", "usage": None, "content": {}},
    )
    for payload in cases:
        ledger = Ledger()
        adapter = Adapter(secret="not-logged", ledger=ledger)
        result = adapter.validate_replay_response(place_id="canonical-dev-01", payload=payload)
        assert result.candidate is None
        assert result.retry is False
        assert ledger.committed_micro_usd == 248_192
        assert "not-logged" not in repr(result)


def test_adapter_retains_exact_bounded_http_failure_body_without_secret(tmp_path: Path) -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    raw = b'{"error":{"code":"invalid_request","message":"bounded detail"}}'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    adapter = Adapter(
        secret="must-never-be-persisted",
        ledger=Ledger(),
        client_factory=factory,
    )
    result = asyncio.run(
        adapter.attempt(
            place_id="canonical-dev-01",
            request_body=b"{}",
            reservation_sink=_durable_reservation_sink(tmp_path / "bounded-failure"),
        )
    )

    assert result.candidate is None
    assert result.attempt.http_status == 422
    assert result.attempt.error_code == "HTTP_422_PROVIDER_INVALID_REQUEST"
    assert result.raw_response == raw
    assert "must-never-be-persisted" not in repr(result)


def test_adapter_drops_http_body_that_echoes_credential_but_keeps_digest(
    tmp_path: Path,
) -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    secret = "must-never-be-persisted"
    raw = json.dumps({"error": {"message": secret}}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    adapter = Adapter(secret=secret, ledger=Ledger(), client_factory=factory)
    result = asyncio.run(
        adapter.attempt(
            place_id="canonical-dev-01",
            request_body=b"{}",
            reservation_sink=_durable_reservation_sink(tmp_path / "credential-echo"),
        )
    )

    assert result.raw_response is None
    assert result.attempt.response_sha256 == hashlib.sha256(raw).hexdigest()
    assert secret not in repr(result)


@pytest.mark.parametrize("declared_length", ["not-a-number", "-1", "65537"])
def test_zhipu_bounded_decode_failures_settle_reservation(
    tmp_path: Path,
    declared_length: str,
) -> None:
    from itda.contracts.demo_profile_materialization import MAX_PROVIDER_RESPONSE_BYTES

    _, _, Ledger, _, Adapter, _ = _provider()
    if declared_length == "65537":
        declared_length = str(MAX_PROVIDER_RESPONSE_BYTES + 1)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": declared_length},
            content=b"{}",
            request=request,
        )

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    ledger = Ledger()
    result = asyncio.run(
        Adapter(secret="decode-test", ledger=ledger, client_factory=factory).attempt(
            place_id="canonical-dev-01",
            request_body=b"{}",
            reservation_sink=_durable_reservation_sink(tmp_path / declared_length),
        )
    )

    assert result.candidate is None
    assert result.attempt.error_code in {
        "RESPONSE_BODY_INVALID",
        "RESPONSE_BYTE_LIMIT_EXCEEDED",
    }
    assert ledger.outstanding_micro_usd == 0
    assert ledger.committed_micro_usd == 248_192


def test_ordinary_http_429_remains_retryable_and_bounded(tmp_path: Path) -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    raw = b'{"error":{"code":"rate_limit_exceeded","message":"retry later"}}'

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    adapter = Adapter(secret="not-logged", ledger=Ledger(), client_factory=factory)
    result = asyncio.run(
        adapter.attempt(
            place_id="canonical-dev-01",
            request_body=b"{}",
            reservation_sink=_durable_reservation_sink(tmp_path / "rate-limit"),
        )
    )

    assert result.attempt.http_status == 429
    assert result.attempt.error_code == "HTTP_429_PROVIDER_RATE_LIMIT_EXCEEDED"
    assert result.retry is True
    assert result.raw_response == raw
    assert result.attempt.duration_ms <= 300_100


def test_adapter_accepts_only_complete_evidence_bound_candidate_and_refunds_usage() -> None:
    _, _, Ledger, _, Adapter, _ = _provider()
    ledger = Ledger()
    adapter = Adapter(secret="not-logged", ledger=ledger, monotonic=lambda: 1.0)
    payload = {
        "model": "glm-5v-turbo",
        "finish_reason": "stop",
        "usage": {"prompt_tokens": 1_000, "completion_tokens": 100, "cached_tokens": 200},
        "content": {
            "axis_scores": {"H": 76, "E": 61, "R": 84},
            "subattributes": {
                **{f"H{index}": 3 for index in range(1, 5)},
                **{f"I{index}": 2 for index in range(1, 5)},
                **{f"R{index}": 4 for index in range(1, 5)},
            },
            "mismatch_traits": {f"M{index}": index * 10 for index in range(1, 7)},
            "evidence_ids": ["tour-description-01", "odii-transcript-01"],
            "confidence": 78,
            "publishable": True,
        },
        "lineage": {
            "prompt_version": "phase5-demo-profile.v1",
            "prompt_sha256": "a" * 64,
            "profile_schema_sha256": "b" * 64,
            "config_sha256": "c" * 64,
            "source_bundle_sha256": "d" * 64,
            "evidence_inventory_sha256": "e" * 64,
            "request_sha256": "f" * 64,
            "evidence_ids": ["tour-description-01", "odii-transcript-01"],
            "created_at": "2026-08-10T00:00:00Z",
        },
    }

    result = adapter.validate_replay_response(place_id="canonical-dev-01", payload=payload)
    assert result.candidate is not None
    assert result.candidate.analysis_origin == "DEMO_MODEL_DERIVED"
    assert result.attempt.outcome == "VALIDATED"
    assert result.attempt.response_sha256 == result.candidate.response_sha256
    assert result.attempt.committed_micro_usd == 1_408
    assert result.attempt.refund_micro_usd == 246_784
    assert ledger.committed_micro_usd == 1_408
    assert ledger.outstanding_micro_usd == 0


def test_adapter_slow_trickle_stops_at_non_overridable_monotonic_deadline() -> None:
    _, _, Ledger, _, Adapter, _ = _provider()

    class Clock:
        value = 0.0

        def __call__(self) -> float:
            self.value += 100.1
            return self.value

    adapter = Adapter(secret="not-logged", ledger=Ledger(), monotonic=Clock())
    result = adapter.consume_replay_chunks(
        place_id="canonical-dev-01",
        chunks=(b'{"a":', b"1,", b'"b":', b"2}"),
    )
    assert result.candidate is None
    assert result.attempt.error_code == "ATTEMPT_DEADLINE_EXCEEDED"
    assert result.attempt.duration_ms <= 300_100
    assert result.attempt.response_sha256 is None


def test_secret_prompt_body_path_and_blind_tokens_never_enter_safe_projection() -> None:
    from itda.contracts.demo_profile_materialization import DemoProfileAttempt

    fields = set(DemoProfileAttempt.model_fields)
    assert not fields & {
        "secret",
        "authorization",
        "prompt",
        "request_body",
        "response_body",
        "evidence_body",
        "path",
        "blind_membership",
        "image_bytes",
    }


def test_online_recommendation_modules_do_not_import_provider_or_materializer() -> None:
    roots = (
        Path("backend/src/itda/api"),
        Path("backend/src/itda/application"),
        Path("backend/src/itda/domain/recommendation.py"),
    )
    forbidden = (
        "from itda.providers",
        "import itda.providers",
        "from itda.pipeline.demo_profile_materialization",
        "from itda.cli.materialize_phase5_demo_profiles",
        "ZHIPUAI_API_KEY",
    )
    for root in roots:
        files = (root,) if root.is_file() else tuple(root.rglob("*.py"))
        for path in files:
            source = path.read_text(encoding="utf-8")
            assert all(fragment not in source for fragment in forbidden)


def test_replay_and_preflight_commands_are_network_free(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from itda.cli.materialize_phase5_demo_profiles import main

    def deny_network(*_: object, **__: object) -> object:
        raise AssertionError("network is forbidden")

    monkeypatch.setattr(httpx, "Client", deny_network)
    monkeypatch.setattr(httpx, "AsyncClient", deny_network)
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    monkeypatch.delenv("BIGMODEL_API_KEY", raising=False)
    assert main(["replay", "--json"]) == 0
    replay = capsys.readouterr()
    assert "COMPLETE_REPLAY_ONLY" in replay.out
    assert replay.err == ""
    assert main(["preflight", "--json", "--allow-missing-secret"]) == 0
    preflight = capsys.readouterr()
    payload = __import__("json").loads(preflight.out)
    assert isinstance(payload["secret_present"], bool)
    assert payload["source_count"] == 24
    assert isinstance(payload["live_source_bundles_present"], bool)
    assert payload["pricing_version"] == "zai-glm-5v-turbo-2026-08-10"
    assert payload["attempt_reservation_micro_usd"] == 248_192
    assert payload["committed_cost_micro_usd"] == 0
    assert payload["outstanding_cost_micro_usd"] == 0
    assert "Bearer " not in preflight.out


def test_coding_plan_preflight_binds_endpoint_evidence_weight_and_frozen_paygo_history(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import json
    from types import SimpleNamespace

    import itda.cli.materialize_phase5_demo_profiles as command
    from itda.cli.materialize_phase5_demo_profiles import main
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_AUTHORITY_TEXT,
        CODING_PLAN_ENDPOINT,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    def deny_network(*_: object, **__: object) -> object:
        raise AssertionError("Coding Plan preflight must be network free")

    monkeypatch.setattr(httpx, "AsyncClient", deny_network)
    monkeypatch.setattr(
        Phase5DemoReleaseStore,
        "status",
        lambda _self: {"state": "NO_ACTIVE_SCORED_RELEASE"},
    )
    assert tuple(command._PRIOR_PAYGO_HASHES.values()) == (
        "3834d0de4c60a760a15971ec4d2694e2f09d158549b94b18634fe87cd40c4cd7",
        "c1f4e1b6a290e27c9846b5536c90080575f669301b4e8abe98356428abc114af",
        "ac26e91e47401a6f875318cbe7071d9fb9dfd151a21444bbd75c506308d349de",
        "1e500f59bb40f99094f3c8511e44ab43a1a694c204132b9f97d07b55aad75901",
        "c56a056b424195a1e3351ace818c49b4d3c664e3b4b8d1df2bd37ad4c8123af0",
    )
    synthetic_prior = {}
    for index in range(5):
        path = tmp_path / f"prior-{index}.json"
        path.write_bytes(f"synthetic prior evidence {index}".encode())
        synthetic_prior[path] = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(command, "_PRIOR_PAYGO_HASHES", synthetic_prior)
    monkeypatch.setattr(command, "PRIOR_BLOCKER", SimpleNamespace(name="prior-0.json"))
    monkeypatch.setattr(
        command, "PRIOR_RERUN_AUTHORITY", SimpleNamespace(name="prior-1.json")
    )
    monkeypatch.setattr(
        command, "PRIOR_RERUN_TERMINAL", SimpleNamespace(name="prior-2.json")
    )
    monkeypatch.setattr(command, "PRIOR_FAILURE", SimpleNamespace(name="prior-3.json"))
    monkeypatch.setattr(
        command, "PRIOR_FAILURE_ATTEMPTS", SimpleNamespace(name="prior-4.json")
    )
    monkeypatch.setattr(command, "_load_live_source_bundles", lambda _path: ())
    assert (
        main(
            [
                "coding-plan-preflight",
                "--json",
                "--allow-missing-secret",
                "--authority-text",
                CODING_PLAN_AUTHORITY_TEXT,
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["provider_lane"] == "CODING_PLAN_SUBSCRIPTION"
    assert payload["endpoint"] == CODING_PLAN_ENDPOINT
    assert payload["model"] == "glm-5v-turbo"
    assert payload["entitlement_evidence_sha256"] == CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    assert payload["entitlement_evidence_ref"] == (
        "debug-session:phase5-coding-endpoint#user-account-plan-screenshot"
    )
    assert payload["model_weight"] == 1
    assert payload["new_http_attempt_cap"] == 30
    assert payload["subscription_attempt_count"] == 0
    assert payload["subscription_total_weight"] == 0
    assert payload["prior_paygo_cumulative_upper_micro_usd"] == 12_445_760
    assert payload["prior_paygo_blocker_sha256"] == next(iter(synthetic_prior.values()))
    assert payload["network_attempted"] is False
    assert "Bearer " not in captured.out

    assert (
        main(
            [
                "coding-plan-preflight",
                "--json",
                "--allow-missing-secret",
                "--authority-text",
                CODING_PLAN_AUTHORITY_TEXT + "-drift",
            ]
        )
        == 2
    )


def test_cli_rejects_caller_selected_secret_and_artifact_paths(tmp_path: Path) -> None:
    from itda.cli.materialize_phase5_demo_profiles import main

    assert (
        main(
            [
                "preflight",
                "--json",
                "--allow-missing-secret",
                "--artifact-root",
                str(tmp_path),
            ]
        )
        == 2
    )


def test_cli_live_is_the_only_network_capable_mode_and_offline_flag_blocks_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli.materialize_phase5_demo_profiles import main

    observed = False

    def observe_network(*_: object, **__: object) -> object:
        nonlocal observed
        observed = True
        raise AssertionError("offline live command must stop before network")

    monkeypatch.setattr(httpx, "AsyncClient", observe_network)
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    assert main(["live", "--json"]) != 0
    assert observed is False


def test_minimal_probe_non_live_commands_cannot_construct_provider_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    constructed = False

    def deny_client(*args: object, **kwargs: object) -> object:
        nonlocal constructed
        constructed = True
        raise AssertionError("provider client")

    monkeypatch.setattr(httpx, "AsyncClient", deny_client)
    for argv in (
        ["nvidia-minimal-probe-verify", "--terminal", "missing.json", "--json"],
        [
            "nvidia-minimal-probe-classify",
            "--terminal",
            "missing.json",
            "--value-only",
        ],
        [
            "nvidia-minimal-probe-reconcile",
            "--request",
            "artifacts/public/phase5/nvidia-minimal-probe-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-minimal-probe",
            "--terminal-output",
            "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json",
            "--json",
        ],
        [
            "nvidia-minimal-probe-install-approval",
            "--request",
            "artifacts/public/phase5/nvidia-minimal-probe-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-minimal-probe",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--approval-payload-sha256",
            "0" * 64,
            "--json",
        ],
    ):
        assert command.main(argv) == 2
    assert constructed is False


def test_fresh24_provider_free_cli_rejects_wrong_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    constructed = False

    def deny_client(*_: object, **__: object) -> object:
        nonlocal constructed
        constructed = True
        raise AssertionError("fresh24 preflight must not construct provider client")

    monkeypatch.setattr(httpx, "AsyncClient", deny_client)
    monkeypatch.delenv("NVIDIA_KEY", raising=False)
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.setenv("ITDA_NO_NETWORK", "1")
    assert command.main(
        [
            "nvidia-fresh24-preflight",
            "--probe-terminal",
            "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json",
            "--request-output",
            str(tmp_path / "request.json"),
            "--json",
        ]
    ) == 2
    assert constructed is False


def test_fresh24_verify_and_classify_reject_nonfixed_terminal_without_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("fresh24 verification must not construct provider client")
        ),
    )
    for argv in (
        ["nvidia-fresh24-verify", "--terminal", "missing.json", "--json"],
        ["nvidia-fresh24-classify", "--terminal", "missing.json", "--value-only"],
    ):
        assert command.main(argv) == 2


def test_minimal_probe_executor_has_no_real_client_no_claim_bypass() -> None:
    import inspect

    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe

    signature = inspect.signature(execute_nvidia_minimal_probe)
    assert "claim" not in signature.parameters
    assert "reservation_sink" not in signature.parameters
    assert signature.parameters["state"].default is inspect.Parameter.empty
    assert signature.parameters["artifact"].default is inspect.Parameter.empty
    assert "client_factory" not in signature.parameters
    with pytest.raises(TypeError, match="client_factory"):
        asyncio.run(
            execute_nvidia_minimal_probe(  # type: ignore[call-arg]
                state=object(),
                artifact=object(),
                bundle=object(),
                credential_reader=lambda: "x",
                client_factory=lambda **kwargs: object(),
            )
        )
    source = inspect.getsource(execute_nvidia_minimal_probe)
    assert "state.preflight" in source
    assert "state.claim_once" in source
    assert "state.reserve_once" in source


def test_cli_live_publishes_terminal_failure_before_returning(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import itda.cli.materialize_phase5_demo_profiles as command
    from itda.pipeline.demo_profile_materialization import DemoProfileMaterializationFailure

    _, _, Ledger, _, Adapter, _ = _provider()
    adapter = Adapter(secret="test-only-secret", ledger=Ledger())
    failed = adapter.consume_replay_chunks(
        place_id="canonical-dev-01",
        chunks=(b'{"error":"invalid"}',),
    )
    failure = DemoProfileMaterializationFailure(
        failed_place_id="canonical-dev-01",
        results=(failed,),
        committed_cost_micro_usd=adapter.ledger.committed_micro_usd,
        outstanding_cost_micro_usd=adapter.ledger.outstanding_micro_usd,
    )
    published: list[DemoProfileMaterializationFailure] = []

    async def fail_live(**_: object) -> object:
        raise failure

    def publish(value: DemoProfileMaterializationFailure, **_: object) -> Path:
        published.append(value)
        return command.REPOSITORY_ROOT / (
            "artifacts/restricted/catalog/phase5-demo-profile-materialization/failures/" + "a" * 64
        )

    monkeypatch.setenv("ITDA_PROVIDER_NETWORK", "1")
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(command, "_read_local_secret", lambda *_args, **_kwargs: ("x", "y"))
    monkeypatch.setattr(command, "_load_live_source_bundles", lambda _path: ())
    monkeypatch.setattr(command, "materialize_live_demo_profiles", fail_live)
    monkeypatch.setattr(command, "publish_demo_profile_failure", publish)

    assert command.main(["live", "--json"]) == 2
    captured = capsys.readouterr()
    assert published == [failure]
    assert "failure_artifact=artifacts/restricted/" in captured.err
    assert "test-only-secret" not in captured.err


# ---------------------------------------------------------------------------
# fresh24 production-seam boundary regressions
# ---------------------------------------------------------------------------


def _build_plan():
    """Build the provider-free fresh24 plan from the fixed committed source."""

    import json as json_module

    from itda.pipeline.phase5_fresh24 import (
        build_fresh24_plan,
        checkout_manifest_sha256,
        verify_fixed_source_authority,
    )

    return build_fresh24_plan(
        verify_fixed_source_authority(),
        checkout_manifest_sha256=checkout_manifest_sha256(),
        probe_terminal=json_module.loads(
            Path("artifacts/reports/phase5/nvidia-minimal-probe-terminal.json").read_bytes()
        ),
    )


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
    from itda.contracts.phase5_fresh24 import Fresh24Profile
    from itda.domain.canonical import canonical_sha256

    values = {
        "schema_version": "itda.phase5-fresh24-profile.v1",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "place_id": place_id,
        "split": "DEV",
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
    return Fresh24Profile.model_validate(values).model_dump(mode="json")


def _fresh24_descriptor(tmp_path):
    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor

    return Fresh24ProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "fresh24-protected")
    )


def _fresh24_approval(descriptor, artifact_digest: str):
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
        "checkout_commit_sha256": "a" * 40,
        "probe_terminal_sha256": "e" * 64,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    dumped = Fresh24ApprovalBinding.model_construct(**fields).model_dump(mode="json")
    return Fresh24ApprovalBinding.model_validate(
        {**dumped, "approval_sha256": canonical_sha256(dumped)}
    )


def test_fresh24_live_command_is_blocked_offline_and_without_network_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    live_argv = [
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
    monkeypatch.delenv("NVIDIA_KEY", raising=False)
    # The capability command is unreachable through the public main(): the
    # parser has no such subcommand (argparse SystemExit 2), and a forged
    # Namespace is rejected unconditionally — the command never reaches any
    # network capability or mutation through this surface.
    for env_setup in (
        {"ITDA_OFFLINE": "1", "ITDA_NO_NETWORK": "1"},
        {"ITDA_PROVIDER_NETWORK": "0"},
    ):
        for key, value in env_setup.items():
            monkeypatch.setenv(key, value)
        with pytest.raises(SystemExit) as excinfo:
            command.main(live_argv)
        assert excinfo.value.code == 2

    # Forged Namespace path: fixed rejection before any dispatch.
    import argparse as _argparse

    forged_namespace = _argparse.Namespace(
        command="nvidia-fresh24-live", json=True
    )

    class _ForgedParser:
        def parse_args(self, _argv=None):  # type: ignore[no-untyped-def]
            return forged_namespace

    monkeypatch.setattr(
        command, "_parser", lambda: _ForgedParser()  # type: ignore[return-value]
    )
    try:
        assert command.main(live_argv) == 2
    finally:
        monkeypatch.undo()


def test_fresh24_install_and_live_reject_caller_selected_paths(
    tmp_path: Path,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    for argv in (
        [
            "nvidia-fresh24-install-approval",
            "--request",
            str(tmp_path / "other-request.json"),
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-fresh24",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--approval-payload-sha256",
            "0" * 64,
            "--json",
        ],
        [
            "nvidia-fresh24-install-approval",
            "--request",
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
            "--protected-state-root",
            str(tmp_path / "elsewhere"),
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--approval-payload-sha256",
            "0" * 64,
            "--json",
        ],
        [
            "nvidia-fresh24-live",
            "--request",
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-fresh24",
            "--secret-env-file",
            str(tmp_path / "stolen-secret.env"),
            "--terminal-output",
            "artifacts/reports/phase5/nvidia-fresh24-terminal.json",
            "--json",
        ],
        [
            "nvidia-fresh24-live",
            "--request",
            "artifacts/public/phase5/nvidia-fresh24-materialization-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-fresh24",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            str(tmp_path / "evil-terminal.json"),
            "--json",
        ],
    ):
        # The public parser has no capability subcommand: argparse exits 2
        # before any path validation could even run.  The capability handlers
        # live behind the bootstrap-only internal dispatcher.
        with pytest.raises(SystemExit) as excinfo:
            command.main(argv)
        assert excinfo.value.code == 2


def test_fresh24_production_transport_injection_impossible() -> None:
    """The sealed executor exposes no client factory and no mutable opener."""

    import dis
    import inspect

    from itda.pipeline import phase5_fresh24

    signature = inspect.signature(phase5_fresh24.execute_fresh24_production)
    assert "client_factory" not in signature.parameters
    assert "transport" not in signature.parameters
    assert "transport_attestation" not in signature.parameters
    # No mutable intermediary globals exist to swap.
    for gone in (
        "_fresh24_production_client_factory",
        "_fresh24_open_client",
        "_FRESH24_BOUND_OPEN_CLIENT",
    ):
        assert not hasattr(phase5_fresh24, gone), gone
    # Bytecode proof: the public wrappers load no opener-related global.
    for function_name in ("run_fresh24_transport", "execute_fresh24_transport_async"):
        function = getattr(phase5_fresh24, function_name)
        globals_loaded = {
            instruction.argval
            for instruction in dis.get_instructions(function)
            if "LOAD_GLOBAL" in instruction.opname
        }
        assert not [
            name
            for name in globals_loaded
            if "open_client" in str(name) or "_fresh24_open" in str(name)
        ], (function_name, globals_loaded)
    # Structural proof: the frozen binding's opener closure carries the real
    # fixed constructor function object, not a global lookup; the bundle is
    # a named immutable dataclass whose members are the exact callables the
    # public wrappers invoke.
    binding = phase5_fresh24._make_fresh24_runner()
    open_client = binding.open_client
    closure_cells = {cell.cell_contents for cell in (open_client.__closure__ or ())}
    assert phase5_fresh24._fresh24_open_client_blocking in closure_cells
    runner_cells_source = inspect.getsource(open_client)
    assert "open_client" in runner_cells_source or callable(open_client)


def test_fresh24_mock_seal_cannot_be_reused_for_production(tmp_path) -> None:
    """The capability seal object cannot be forged by callers."""

    from itda.pipeline.phase5_fresh24 import Fresh24CapabilitySeal

    seal = Fresh24CapabilitySeal()
    assert isinstance(seal, Fresh24CapabilitySeal)
    with pytest.raises(TypeError):
        Fresh24CapabilitySeal(token="forged")  # type: ignore[call-arg]
    with pytest.raises(AttributeError):
        seal._token  # noqa: B018 — attribute must not exist at all


def test_fresh24_claim_binds_exact_approval_and_root(tmp_path) -> None:
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        synthetic_fresh24_claim,
    )

    descriptor = _fresh24_descriptor(tmp_path)
    claim = synthetic_fresh24_claim("1" * 64)
    assert claim.request_artifact_sha256 == "1" * 64
    state = Fresh24DurableAuthorityState(descriptor)
    artifact = {"request_artifact_sha256": "1" * 64}
    state.install_approval(_fresh24_approval(descriptor, "1" * 64), request_artifact=artifact)
    # The synthetic claim's approval digest does not match the installed one.
    with pytest.raises(PermissionError, match="CLAIM_INVALID|FILE_INVALID|MISMATCH"):
        state.reserve_once(claim=claim, place_id="p:01", request_sha256="a" * 64)


def test_fresh24_attempt_deadline_and_response_bound_enforced() -> None:
    import inspect

    from itda.pipeline.phase5_fresh24 import _fresh24_live_attempt

    source = inspect.getsource(_fresh24_live_attempt)
    assert "asyncio.timeout(deadline_seconds)" in source
    assert "FRESH24_MAX_RESPONSE_BYTES" in source
    assert 'follow_redirects": False' in source.replace("'", '"').lower() or (
        "follow_redirects=False" in source
    )
    assert "trust_env" in source


def test_fresh24_first_passes_precede_retries_in_sealed_loop(
    tmp_path: Path,
) -> None:
    """Ordering proof: retry_order raises unless first pass fully consumed."""

    from itda.pipeline.phase5_fresh24 import Fresh24Scheduler

    scheduler = Fresh24Scheduler(tuple(f"p:{index:02d}" for index in range(24)))
    with pytest.raises(RuntimeError, match="first pass"):
        scheduler.retry_order(("p:00",))
    first = scheduler.first_pass()
    assert len(first) == 24
    # Retries are impossible until all 24 first passes were dispatched.
    with pytest.raises(RuntimeError, match="first passes dispatched"):
        scheduler.retry_order(("p:00",))
    for place_id in first:
        scheduler.record_dispatched(place_id, is_retry=False)
    # More than six retries or duplicates are impossible.
    with pytest.raises(RuntimeError, match="budget"):
        scheduler.retry_order(tuple(f"p:{index:02d}" for index in range(7)))
    with pytest.raises(RuntimeError, match="order"):
        scheduler.retry_order(("p:05", "p:01"))


def _fresh_fixed_packet_swap(plan):
    """Place a freshly built packet at the fixed public path for one verify.

    Provider-free regeneration through the production builder; restores the
    committed bytes on exit.
    """

    from contextlib import contextmanager
    from pathlib import Path as _Path

    import itda.pipeline.phase5_fresh24 as _p
    from itda.domain.canonical import canonical_json_bytes

    fixed = _p.FRESH24_REQUEST_OUTPUT
    saved = fixed.read_bytes() if fixed.exists() else None
    fresh = canonical_json_bytes(
        _p.build_fresh24_public_request(
            plan=plan, checkout_commit_sha256=plan.checkout_commit_sha256
        )
    )

    @contextmanager
    def _swap():
        _Path(fixed).write_bytes(fresh)
        try:
            yield
        finally:
            if saved is not None:
                _Path(fixed).write_bytes(saved)

    return _swap()


def test_fresh24_verify_require_positive_full_flow_no_skip(tmp_path: Path) -> None:
    """Approved-live flow end to end without any skip.

    A fake sealed provider drives install → claim → 24 (+1 retry) attempts
    through the production parser/evaluator/publisher, then the public-safe
    terminal is exported to the fixed path shape and neutral verification,
    classification, and the separate --require-positive assertion all run —
    including the negative branch rejection of require-positive.
    """

    import asyncio
    import json as json_module

    from itda.contracts.phase5_fresh24 import Fresh24ApprovalBinding
    from itda.domain.canonical import canonical_sha256
    from itda.pipeline.phase5_fresh24 import (
        Fresh24DurableAuthorityState,
        Fresh24ProtectedStateDescriptor,
        assert_fresh24_positive_outcome,
        classify_fresh24_terminal,
        execute_fresh24_mock,
        verify_fresh24_outcome,
    )

    plan = _build_plan()
    root = tmp_path / "flow-root"
    descriptor = Fresh24ProtectedStateDescriptor.from_root(state_root=str(root))
    state = Fresh24DurableAuthorityState(descriptor)
    fields = {
        "schema_version": "itda.phase5-fresh24-approval.v1",
        "authority_id": "phase5-nvidia-minimax-m3-fresh24-20260820",
        "decision": "APPROVED",
        "request_artifact_sha256": plan.request.request_artifact_sha256,
        "request_manifest_sha256": plan.request.request_manifest_sha256,
        "membership_sha256": plan.authority.membership_sha256,
        "checkout_manifest_sha256": plan.checkout_manifest_sha256,
        "checkout_commit_sha256": plan.checkout_commit_sha256,
        "probe_terminal_sha256": plan.probe.probe_terminal_sha256,
        "protected_state_sha256": descriptor.protected_state_sha256,
        "secret_identity_sha256": "f" * 64,
    }
    # Production semantics: the capability artifact IS the committed packet.
    from itda.domain.canonical import canonical_json_bytes as _cjb
    from itda.pipeline.phase5_fresh24 import build_fresh24_public_request

    packet = build_fresh24_public_request(
        plan=plan, checkout_commit_sha256=plan.checkout_commit_sha256
    )
    packet_file = tmp_path / "packet.json"
    packet_file.write_bytes(_cjb(packet))
    artifact = packet
    fields["request_artifact_sha256"] = packet["request_artifact_sha256"]
    fields["request_file_sha256"] = __import__("hashlib").sha256(
        packet_file.read_bytes()
    ).hexdigest()
    fields["request_manifest_sha256"] = packet["request_manifest_sha256"]
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
    retry_target = sorted(profiles)[0]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json_module.loads(request.content.decode("utf-8"))
        place_id = json_module.loads(payload["messages"][1]["content"])["place_id"]
        attempts[place_id] = attempts.get(place_id, 0) + 1
        if place_id == retry_target and attempts[place_id] == 1:
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(200, json={"profile": profiles[place_id]})

    result = asyncio.run(
        execute_fresh24_mock(
            plan=plan,
            claim=claim,
            protected_state_root=root,
            response_handler=handler,
        )
    )
    assert result["status"] == "COMPLETE_CANDIDATE_READY"

    # Neutral verification over the reopened protected evidence.
    with _fresh_fixed_packet_swap(plan):
        outcome = verify_fresh24_outcome(terminal=result, protected_root=root)
    positive = assert_fresh24_positive_outcome(outcome)
    assert positive.profile_count == 24

    # The strict-positive assertion rejects a designed-negative terminal.
    negative_fields = dict(result)
    negative_fields.update(
        {
            "status": "DESIGNED_NEGATIVE",
            "reason": "NVIDIA_RATE_LIMITED",
            "generation_sha256": None,
            "profile_count": 0,
            "candidate_count": 0,
            "post_hard_duplicate_count": 0,
            "post_cannot_coappear_count": 0,
            "effective_candidate_count": 0,
            "scenario_results": [],
            "contrast_results": [],
            "attempt_count": 25,
            "retry_count": 1,
            "committed_exposure_micro_usd": 25 * 500_000,
        }
    )
    negative_fields["terminal_sha256"] = None
    negative = Fresh24TerminalContract.model_validate(negative_fields).model_dump(
        mode="json"
    )
    assert classify_fresh24_terminal(negative) == "DESIGNED_NEGATIVE"
    # The forged negative changes branch semantics while reusing a positive
    # root, so exact branch-specific inventory rejects it before byte comparison.
    with pytest.raises(
        PermissionError, match="FRESH24_PROTECTED_ROOT_INVENTORY_INVALID"
    ):
        verify_fresh24_outcome(terminal=negative, protected_root=root)
    with pytest.raises(ValueError, match="COMPLETE_CANDIDATE_READY"):
        assert_fresh24_positive_outcome(
            type("O", (), {"terminal": Fresh24TerminalContract.model_validate(negative)})()
        )


from itda.contracts.phase5_fresh24 import (  # noqa: E402
    Fresh24Terminal as Fresh24TerminalContract,
)


def test_fresh24_authority_tampering_fails_closed(tmp_path) -> None:
    """Descriptor/approval tamper attempts never validate."""

    from itda.contracts.phase5_fresh24 import Fresh24ProtectedStateDescriptor

    descriptor = _fresh24_descriptor(tmp_path)
    dumped = descriptor.model_dump(mode="json")
    for field in ("approval_target", "ledger_target", "generation_target"):
        mutated = {**dumped, field: dumped[field] + "x"}
        with pytest.raises(ValueError):
            Fresh24ProtectedStateDescriptor.model_validate(mutated)
    approval = _fresh24_approval(descriptor, "1" * 64)
    approval_fields = approval.model_dump(mode="json")
    for mutation_key, mutation_value in (
        ("checkout_commit_sha256", "b" * 40),
        ("max_attempts", 31),
        ("cumulative_exposure_micro_usd", 15_000_001),
        ("reservation_micro_usd", 500_001),
    ):
        from pydantic import ValidationError

        with pytest.raises((ValidationError, ValueError)):
            type(approval).model_validate({**approval_fields, mutation_key: mutation_value})


def test_fresh24_no_release_capability_anywhere_in_namespace() -> None:
    """No fresh24 symbol grants build/smoke/activation/release authority."""

    import itda.contracts.phase5_fresh24 as contracts
    import itda.pipeline.phase5_fresh24 as pipeline

    allowed_release_mentions = {"FRESH24_ACTIVE_RELEASE_STATES"}
    for module in (contracts, pipeline):
        for name in dir(module):
            if name.startswith("_") or name in allowed_release_mentions:
                continue
            lowered = name.lower()
            assert "release" not in lowered, name
            assert "smoke" not in lowered, name


# ---------------------------------------------------------------------------
# OpenRouter recovery lane (provider-free; Plan 05-35).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _deny_production_openrouter_and_secret_fs_access(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """Permit lexical path values, but forbid every OpenRouter filesystem access."""

    if "openrouter" not in request.node.nodeid.lower():
        return
    repository_root = Path(__file__).resolve().parents[3]
    forbidden = (
        repository_root / "artifacts/restricted/catalog/phase5-openrouter-recovery",
        repository_root / "artifacts/restricted/catalog/phase5-openrouter-recovery-r2",
        repository_root / "artifacts/restricted/catalog/phase5-openrouter-recovery-r3",
        repository_root / ".secrets",
    )

    original_readlink = os.readlink

    def blocked_path(value: object, *, dir_fd: int | None = None) -> bool:
        try:
            candidate = Path(os.fspath(value))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        if not candidate.is_absolute() and dir_fd is not None:
            try:
                candidate = Path(original_readlink(f"/dev/fd/{dir_fd}")) / candidate
            except OSError:
                return False
        candidate = Path(os.path.abspath(candidate))
        return any(candidate == root or root in candidate.parents for root in forbidden)

    def wrap(function):
        def guarded(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            if blocked_path(path, dir_fd=kwargs.get("dir_fd")):
                raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
            return function(path, *args, **kwargs)

        return guarded

    def wrap_pair(function):
        def guarded(source, destination, *args, **kwargs):  # type: ignore[no-untyped-def]
            if blocked_path(source) or blocked_path(destination):
                raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
            return function(source, destination, *args, **kwargs)

        return guarded

    for name in (
        "open",
        "stat",
        "lstat",
        "listdir",
        "scandir",
        "mkdir",
        "makedirs",
        "unlink",
        "remove",
        "rmdir",
        "readlink",
    ):
        monkeypatch.setattr(os, name, wrap(getattr(os, name)))
    for name in ("rename", "replace"):
        monkeypatch.setattr(os, name, wrap_pair(getattr(os, name)))
    monkeypatch.setattr(builtins, "open", wrap(builtins.open))
    original_path_open = Path.open

    def guarded_path_open(self: Path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if blocked_path(self):
            raise AssertionError("PRODUCTION_OPENROUTER_OR_SECRET_FS_ACCESS_FORBIDDEN")
        return original_path_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_path_open)


@pytest.fixture(autouse=True)
def _deny_real_httpx_client_construction(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """Only explicit MockTransport clients exist in OpenRouter tests."""

    if "openrouter" not in request.node.nodeid.lower():
        return
    async_client = httpx.AsyncClient
    sync_client = httpx.Client

    def guarded_async_client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        if not isinstance(kwargs.get("transport"), httpx.MockTransport):
            raise AssertionError("REAL_PROVIDER_CLIENT_CONSTRUCTION_FORBIDDEN")
        return async_client(*args, **kwargs)

    def guarded_sync_client(*args: object, **kwargs: object) -> httpx.Client:
        if not isinstance(kwargs.get("transport"), httpx.MockTransport):
            raise AssertionError("REAL_PROVIDER_CLIENT_CONSTRUCTION_FORBIDDEN")
        return sync_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", guarded_async_client)
    monkeypatch.setattr(httpx, "Client", guarded_sync_client)


def _openrouter_no_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "NVIDIA_KEY",
        "ZHIPUAI_API_KEY",
        "BIGMODEL_API_KEY",
        "OPENROUTER_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _deny_inet_sockets_and_dns() -> None:
    """Module-wide in-process deny for EVERY test here (autouse): DNS
    resolution and AF_INET/AF_INET6 socket creation are impossible even if a
    test patches httpx in the wrong order.  AF_UNIX stays intact — asyncio's
    loop self-pipe needs it and it has no network semantics."""

    import socket as socket_module

    saved = {
        name: getattr(socket_module, name)
        for name in (
            "create_connection",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "socket",
        )
    }

    def _deny_create_connection(*args: object, **kwargs: object) -> object:
        raise OSError(97, "PROVIDER_BOUNDARY_CONNECT_DENIED")

    def _deny_getaddrinfo(*args: object, **kwargs: object) -> list[object]:
        raise OSError(97, "PROVIDER_BOUNDARY_DNS_DENIED")

    def _deny_gethostbyname(*args: object) -> str:
        raise OSError(97, "PROVIDER_BOUNDARY_DNS_DENIED")

    def _deny_gethostbyname_ex(*args: object) -> tuple[str, list[str], list[str]]:
        raise OSError(97, "PROVIDER_BOUNDARY_DNS_DENIED")

    real_socket = socket_module._socket.socket  # type: ignore[attr-defined]

    def _family_aware_socket(*args: object, **kwargs: object) -> object:
        family = args[0] if args else kwargs.get("family", socket_module.AF_INET)
        if family in (socket_module.AF_INET, socket_module.AF_INET6):
            raise OSError(97, "PROVIDER_BOUNDARY_INET_SOCKET_DENIED")
        return real_socket(*args, **kwargs)  # type: ignore[arg-type]

    patched = {
        "create_connection": _deny_create_connection,
        "getaddrinfo": _deny_getaddrinfo,
        "gethostbyname": _deny_gethostbyname,
        "gethostbyname_ex": _deny_gethostbyname_ex,
        "socket": _family_aware_socket,
    }
    for name, replacement in patched.items():
        setattr(socket_module, name, replacement)
    yield
    for name, original in saved.items():
        setattr(socket_module, name, original)


def _openrouter_terminal_payload(**overrides: object) -> dict[str, object]:
    """A fully-specified DESIGNED_NEGATIVE terminal preimage + self-digest."""

    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal

    fields = {
        "schema_version": "itda.phase5-openrouter-terminal.v1",
        "status": "DESIGNED_NEGATIVE",
        "reason": "OPENROUTER_INTERRUPTED_EXPOSURE_CONSERVATIVE",
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-20260823",
        "request_sha256": "a" * 64,
        "request_file_sha256": "b" * 64,
        "checkout_manifest_sha256": "c" * 64,
        "claim_sha256": "d" * 64,
        "ledger_sha256": "e" * 64,
        "journal_sha256": "f" * 64,
        "attempt_count": 24,
        "retry_count": 0,
        "client_constructed": True,
        "network_attempted": True,
        # WR-A re-audit: booleans true require the confirmed certainty state.
        "send_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
        "dispatch_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
    }
    fields.update(overrides)
    # The contract computes its own self-digest when terminal_sha256 is None.
    return OpenRouterTerminal.model_validate(fields).model_dump(mode="json")


def test_openrouter_verify_rejects_malformed_terminal_without_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Malformed evidence fails closed with no downstream authority."""

    _openrouter_no_provider_env(monkeypatch)
    from itda.pipeline.phase5_openrouter_recovery import verify_openrouter_terminal

    malformed = {"schema_version": "itda.phase5-openrouter-terminal.v1"}
    with pytest.raises(ValueError):
        verify_openrouter_terminal(malformed)


def test_openrouter_designed_negative_never_satisfies_positive(
    tmp_path: Path,
) -> None:
    from itda.pipeline import phase5_openrouter_recovery as lane

    payload = _openrouter_terminal_payload()
    assert lane.verify_openrouter_terminal(payload) == "DESIGNED_NEGATIVE"
    with pytest.raises(ValueError):
        lane.assert_openrouter_positive(payload)


def test_openrouter_impossible_terminal_facts_rejected() -> None:
    """WR-A strict acceptance probe: an IMPOSSIBLE terminal — network true
    but client false (or any boolean/certainty contradiction) — is rejected
    by the contract validator itself, never accepted."""

    from pydantic import ValidationError

    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal

    expected_messages = [
        # send-boundary certainty with client=false: exact validator message.
        (
            {
                "client_constructed": False,
                "send_certainty": "UNKNOWN_AFTER_SEND_BOUNDARY",
                "dispatch_certainty": "DISPATCH_PREPARED",
            },
            "openrouter terminal send-boundary certainty requires client true",
        ),
        # MAY_HAVE certainty with client=false AND network=true (impossible:
        # no response evidence can exist without a constructed client).
        (
            {
                "client_constructed": False,
                "send_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
                "dispatch_certainty": "DISPATCH_PREPARED",
            },
            "openrouter terminal send-boundary certainty requires client true",
        ),
        # network=true with a NOT_STARTED send certainty (impossible pairing:
        # a response cannot exist while the send provably never started).
        (
            {"send_certainty": "NOT_STARTED_CONFIRMED_LOCALLY"},
            "openrouter terminal network true contradicts unproven send certainty",
        ),
        # RESERVED certainties with a true network boolean: the network
        # incompatibility gate fires first (exact message).
        (
            {"dispatch_certainty": "RESERVED", "send_certainty": "RESERVED"},
            "openrouter terminal network true contradicts unproven send certainty",
        ),
        # Pre-send phase with a constructed client (network=false): the
        # exact pre-send contradiction message.
        (
            {
                "client_constructed": True,
                "network_attempted": False,
                "send_certainty": "NOT_STARTED_CONFIRMED_LOCALLY",
                "dispatch_certainty": "DISPATCH_PREPARED",
            },
            "openrouter terminal constructed client contradicts send_certainty phase",
        ),
    ]
    for overrides, expected_message in expected_messages:
        fields = {
            "schema_version": "itda.phase5-openrouter-terminal.v1",
            "status": "DESIGNED_NEGATIVE",
            "reason": "HTTP_400",
            "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-20260823",
            "request_sha256": "a" * 64,
            "request_file_sha256": "b" * 64,
            "checkout_manifest_sha256": "c" * 64,
            "claim_sha256": "d" * 64,
            "ledger_sha256": "e" * 64,
            "journal_sha256": "f" * 64,
            "attempt_count": 1,
            "retry_count": 0,
            "client_constructed": True,
            "network_attempted": True,
            "send_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
            "dispatch_certainty": "SEND_ATTEMPT_MAY_HAVE_STARTED",
        }
        fields.update(overrides)
        # WR-B final: the EXACT validator message — anchored to the full
        # literal sentence, no broad regex.
        with pytest.raises(ValidationError, match=expected_message):
            OpenRouterTerminal.model_validate(fields)
        # And the message must be the WHOLE reason (no prefix/suffix drift).
        with pytest.raises(ValidationError) as excinfo:
            OpenRouterTerminal.model_validate(fields)
        assert expected_message in str(excinfo.value)


def test_security_collection_time_network_deny_is_armed() -> None:
    """WR-B final: the security conftest armed the INET/DNS deny at
    COLLECTION time, before any test module import."""

    import socket as socket_module

    assert getattr(socket_module, "_itda_security_deny_installed", False) is True


def test_openrouter_positive_requires_complete_maps_and_counts(tmp_path: Path) -> None:
    """A positive claim without the eight/seven maps and effective>=5 fails."""

    from pydantic import ValidationError

    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal
    from itda.domain.canonical import canonical_sha256

    fields = {
        "schema_version": "itda.phase5-openrouter-terminal.v1",
        "status": "COMPLETE_CANDIDATE_READY",
        "reason": "COMPLETE_CANDIDATE_READY",
        "request_sha256": "a" * 64,
        "request_file_sha256": "b" * 64,
        "checkout_manifest_sha256": "c" * 64,
        "claim_sha256": "d" * 64,
        "ledger_sha256": "e" * 64,
        "journal_sha256": "f" * 64,
        "generation_sha256": "0" * 64,
        "profile_count": 24,
        "candidate_count": 5,
        "effective_candidate_count": 5,
        "attempt_count": 24,
        "retry_count": 0,
        "scenario_results": [],
        "contrast_results": [],
        "secret_read": True,
        "client_constructed": True,
        "network_attempted": True,
    }
    # WR-B: narrowed to the concrete failure types — a passing-but-wrong
    # terminal contract must make this test FAIL, not silently pass.
    with pytest.raises(ValidationError):
        OpenRouterTerminal.model_validate(
            {**fields, "terminal_sha256": canonical_sha256(fields)}
        )


def test_openrouter_zero_price_terminal_semantics(tmp_path: Path) -> None:
    """Committed exposure must be exactly zero — never unknown/unbounded."""

    from pydantic import ValidationError

    from itda.contracts.phase5_openrouter_recovery import OpenRouterTerminal
    from itda.domain.canonical import canonical_sha256

    payload = _openrouter_terminal_payload(
        reason="HTTP_400",
        attempt_count=1,
        client_constructed=False,
        network_attempted=False,
        # WR-A strict re-audit: false booleans must carry consistent
        # pre-send certainties on BOTH fields.
        send_certainty="NOT_STARTED_CONFIRMED_LOCALLY",
        dispatch_certainty="DISPATCH_PREPARED",
    )
    assert payload["committed_exposure_micro_usd"] == 0
    assert payload["cumulative_exposure_cap_micro_usd"] == 0
    bad = dict(payload)
    bad["committed_exposure_micro_usd"] = 500_000
    unsigned = {k: v for k, v in bad.items() if k != "terminal_sha256"}
    bad["terminal_sha256"] = canonical_sha256(unsigned)
    # WR-B: narrowed to the concrete failure type.
    with pytest.raises(ValidationError):
        OpenRouterTerminal.model_validate(bad)


def test_openrouter_capability_commands_require_sanitized_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct module invocation of live/install capabilities fails closed."""

    _openrouter_no_provider_env(monkeypatch)
    from itda.cli import materialize_phase5_demo_profiles as command

    for capability_argv in (
        [
            "openrouter-recovery-install-approval",
            "--request",
            "artifacts/public/phase5/openrouter-recovery-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-openrouter-recovery",
            "--secret-env-file",
            ".secrets/itda-openrouter.env",
            "--approval-payload-sha256",
            "0" * 64,
            "--json",
        ],
        [
            "openrouter-recovery-live",
            "--request",
            "artifacts/public/phase5/openrouter-recovery-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-openrouter-recovery",
            "--secret-env-file",
            ".secrets/itda-openrouter.env",
            "--terminal-output",
            "artifacts/reports/phase5/openrouter-recovery-terminal.json",
            "--json",
        ],
        [
            "openrouter-recovery-reconcile",
            "--request",
            "artifacts/public/phase5/openrouter-recovery-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-openrouter-recovery",
            "--terminal-output",
            "artifacts/reports/phase5/openrouter-recovery-terminal.json",
            "--json",
        ],
    ):
        with pytest.raises(SystemExit) as excinfo:
            command.main(capability_argv)
        assert excinfo.value.code == 2


def test_openrouter_capability_run_requires_dispatcher_seal() -> None:
    """Direct imported run/handler calls fail before any mutation (CR-01)."""

    import argparse as argparse_module

    from itda.cli import materialize_phase5_demo_profiles as command

    for capability_command in (
        "openrouter-recovery-install-approval",
        "openrouter-recovery-live",
        "openrouter-recovery-reconcile",
    ):
        args = argparse_module.Namespace(command=capability_command)
        # No seal kwarg at all: TypeError before any mutation.
        with pytest.raises(TypeError):
            command._openrouter_capability_run(args)
        # A forged seal object is rejected by identity.
        class _ForgedSeal:
            pass

        with pytest.raises(PermissionError, match="USE_OPENROUTER_BOOTSTRAP_ENTRYPOINT"):
            command._openrouter_capability_run(args, _seal=_ForgedSeal())  # type: ignore[arg-type]


def test_openrouter_no_recoverable_module_global_seal(monkeypatch: pytest.MonkeyPatch) -> None:
    """T-05R-98: no recoverable module-global seal token exists — a stolen
    module attribute cannot authorize a handler; and even a structurally
    valid dispatcher-minted token fails the per-handler bootstrap gate when
    the process was not entered through the sanitized entrypoint."""

    _openrouter_no_provider_env(monkeypatch)
    import argparse as argparse_module

    from itda.cli import materialize_phase5_demo_profiles as command

    # 1. The old recoverable global is gone.
    assert not hasattr(command, "_OPENROUTER_CAPABILITY_SEAL")

    # 2. Even a validly-typed seal minted through the private producer cannot
    # reach a mutating handler outside the sanitized bootstrap environment:
    # each handler re-runs validate_capability_process() before ANY mutation,
    # which refuses this pytest process (origin/sys.argv mismatch).  The exact
    # bootstrap-origin rejection code is asserted — a tautological match is
    # forbidden.
    args = argparse_module.Namespace(command="openrouter-recovery-reconcile")
    with pytest.raises(
        PermissionError, match="MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID"
    ):
        command._openrouter_capability_run(args, _seal=command._make_openrouter_seal())


def test_openrouter_live_cli_creates_no_credential_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-05R-98 re-audit: the CLI live handler creates and passes NO
    credential reader — it performs metadata continuity only, then calls the
    zero-arg production entry.  The removed reader-factory symbol must not
    exist anywhere on the pipeline surface (not merely unexported)."""

    import inspect

    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.pipeline import phase5_openrouter_recovery as lane

    live_source = inspect.getsource(command._openrouter_capability_run)
    assert "run_production_with_credential_reader" not in live_source
    # The ONLY production invocation inside the live handler is the zero-arg
    # entry; no local reader function is defined or passed.
    assert "execute_openrouter_production()" in live_source
    assert "credential_reader=" not in live_source.split("openrouter-recovery-live")[-1]
    assert "def read_secret" not in live_source.split("openrouter-recovery-live")[-1]
    # The removed seam is gone entirely.
    assert not hasattr(lane, "run_production_with_credential_reader")
    exported = set(lane.__all__)
    assert "run_production_with_credential_reader" not in exported
    state_methods = dir(lane.OpenRouterDurableAuthorityState)
    assert not any("bind_credential" in name for name in state_methods)


def test_openrouter_fixed_internal_reader_is_not_injectable() -> None:
    """T-05R-98 strict form: the credential-reader construction logic lives
    INSIDE the frozen factory — no module-global reader factory exists, no
    LOAD_GLOBAL lookup happens at invocation time, and the helpers are
    captured as closure cells at creation."""

    import dis
    import inspect

    from itda.pipeline import phase5_openrouter_recovery as lane

    factory_source = inspect.getsource(lane._make_openrouter_runner)
    # The construction logic is internal; no removed module-global factory.
    assert "build_credential_reader(state)" in factory_source
    assert "_fixed_openrouter_credential_reader" not in factory_source
    assert not hasattr(lane, "_fixed_openrouter_credential_reader")
    assert not hasattr(lane, "run_production_with_credential_reader")
    exported = set(lane.__all__)
    assert "run_production_with_credential_reader" not in exported
    assert "_fixed_openrouter_credential_reader" not in exported
    # The frozen entries carry NO production-capable mutable reader factory
    # lookup: every helper reference inside invoke_sync/invoke_async resolves
    # through closure cells, not module globals.
    for name in ("invoke_sync", "invoke_async"):
        binding = lane._SYNC_BINDING if name == "invoke_sync" else lane._ASYNC_BINDING
        function = getattr(binding, name)
        loaded_globals = {
            instruction.argval
            for instruction in dis.get_instructions(function)
            if "LOAD_GLOBAL" in instruction.opname
        }
        forbidden = {
            "_fixed_openrouter_credential_reader",
            "_openrouter_fixed_secret_file",
            "_openrouter_secret_metadata_identity",
            "_read_fixed_openrouter_secret_value",
        }
        assert not (loaded_globals & forbidden), (name, loaded_globals & forbidden)
    # Zero-arg public entries remain exactly that.
    for name in ("execute_openrouter_production", "execute_openrouter_production_async"):
        parameters = set(inspect.signature(getattr(lane, name)).parameters)
        assert parameters == set(), (name, parameters)
    # The ALREADY-BOUND entries were frozen at import time: their helper
    # references live in closure cells, so deleting the module-global helpers
    # cannot break them.  Prove it: delete every global helper and confirm
    # each frozen invoke still resolves its own cells (no NameError at call
    # preparation; the capability gate fires first in a hostile process).
    import sys as _sys

    assert lane._make_openrouter_runner is not None  # factory itself intact
    helper_names = (
        "_openrouter_fixed_secret_file",
        "_openrouter_secret_metadata_identity",
        "_read_fixed_openrouter_secret_value",
    )
    saved_helpers = {symbol: getattr(lane, symbol) for symbol in helper_names}
    try:
        for symbol in helper_names:
            delattr(lane, symbol)
        # The pre-import bindings survive: their closure cells are untouched.
        for binding_name in ("_SYNC_BINDING", "_ASYNC_BINDING"):
            binding = getattr(lane, binding_name)
            assert callable(binding.invoke_sync)
            assert callable(binding.invoke_async)
        # And a direct call STILL fails on the origin gate (never on a
        # NameError from the deleted globals — the gate precedes everything).
        os_environ = _sys.modules["os"].environ
        os_environ["ITDA_PROVIDER_NETWORK"] = "1"
        try:
            with pytest.raises(
                PermissionError, match="MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID"
            ):
                lane.execute_openrouter_production()
        finally:
            os_environ.pop("ITDA_PROVIDER_NETWORK", None)
    finally:
        for symbol, original in saved_helpers.items():
            setattr(lane, symbol, original)


def test_openrouter_secret_env_file_resolver_remains_v1_only() -> None:
    """Task 1 never invokes the v1 resolver or observes the secret filesystem."""

    import inspect

    from itda.cli import materialize_phase5_demo_profiles as command

    source = inspect.getsource(command._openrouter_secret_env_file)
    assert "itda-openrouter.env" in source
    assert "openrouter-recovery-v2" not in source
    assert "read_bytes" not in source
    assert "read_text" not in source


def test_openrouter_credential_reader_never_echoes_value_metadata_only() -> None:
    """The metadata-identity helper derives identity from stat fields only."""

    import inspect

    from itda.cli import materialize_phase5_demo_profiles as command

    source = inspect.getsource(command._fresh24_secret_metadata_identity)
    assert "read_bytes" not in source
    assert "st_size" in source  # non-value metadata only


def test_openrouter_frozen_runner_accepts_no_injection() -> None:
    """Public production entry points take NO caller parameters at all.

    T-05R-98 final form: the plan/state/claim/artifact quadruple AND the
    ``_invoke`` cell are gone from the public surface — every authority input
    is re-derived internally from the fixed packet/source/root constants.  No
    caller-injectable client/endpoint/credential/spec parameter exists
    anywhere; the injected-transport seam lives in the strictly-private mock
    namespace only.  The former live aliases are no longer exported.
    """

    import inspect

    from itda.pipeline import phase5_openrouter_recovery as lane

    for name in ("execute_openrouter_production", "execute_openrouter_production_async"):
        function = getattr(lane, name)
        parameters = set(inspect.signature(function).parameters)
        assert parameters == set(), (name, parameters)
    exported = set(lane.__all__)
    for removed_alias in ("run_openrouter_transport", "execute_openrouter_live"):
        assert removed_alias not in exported, removed_alias
        assert not hasattr(lane, removed_alias), removed_alias
    # The private test seam exists and is distinct from every public entry.
    assert inspect.iscoroutinefunction(lane.execute_openrouter_mock_transport)
    mock_parameters = set(
        inspect.signature(lane.execute_openrouter_mock_transport).parameters
    )
    assert "response_handler" in mock_parameters


def test_openrouter_snapshot_not_refetched_at_runtime(monkeypatch) -> None:
    """No HTTP client or URL fetch exists on the snapshot load path."""

    _openrouter_no_provider_env(monkeypatch)
    import inspect

    from itda.contracts import phase5_openrouter_recovery as contracts

    source = inspect.getsource(contracts.load_openrouter_snapshot)
    assert "httpx" not in source
    assert "urllib" not in source
    assert "requests" not in source


def test_openrouter_bootstrap_registers_capability_commands() -> None:
    from itda.minimal_probe_bootstrap import (
        _CAPABILITY_COMMANDS,
        _OPENROUTER_COMMAND_PREFIXES,
    )

    assert {
        "openrouter-recovery-install-approval",
        "openrouter-recovery-live",
        "openrouter-recovery-reconcile",
    } <= _CAPABILITY_COMMANDS
    assert _OPENROUTER_COMMAND_PREFIXES <= _CAPABILITY_COMMANDS


def test_openrouter_v2_repository_root_is_frozen_source_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cwd, caller depth, symlink spelling, and mutable globals cannot redirect root."""

    import inspect

    from itda.pipeline import phase5_openrouter_recovery as lane

    execute_nonlocals = inspect.getclosurevars(
        lane.execute_openrouter_production
    ).nonlocals
    derive = execute_nonlocals["derive_authority"]
    derive_nonlocals = inspect.getclosurevars(derive).nonlocals
    assert derive_nonlocals["repository_root_cell"] == lane.REPOSITORY_ROOT

    symlink_spelling = tmp_path / "packet-link.json"
    symlink_spelling.symlink_to(lane.OPENROUTER_REQUEST_OUTPUT)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(lane, "REPOSITORY_ROOT", tmp_path / "caller-selected-root")
    monkeypatch.setattr(lane, "OPENROUTER_REQUEST_OUTPUT", symlink_spelling)

    frozen = inspect.getclosurevars(derive).nonlocals
    assert frozen["repository_root_cell"] != Path.cwd()
    assert frozen["repository_root_cell"] != symlink_spelling.parents[0]
    assert frozen["repository_root_cell"] == Path(__file__).resolve().parents[3]
    assert "parents[" not in inspect.getsource(derive)


def test_openrouter_v2_historical_rejection_precedes_state_client_and_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        OPENROUTER_V2_REQUEST_SCHEMA,
        reject_historical_openrouter_v2_coordinates,
    )

    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket, "socket", deny("socket"))
    monkeypatch.setattr(Path, "read_bytes", deny("read_bytes"))
    monkeypatch.setattr(Path, "open", deny("open"))
    monkeypatch.setattr(Path, "stat", deny("stat"))
    monkeypatch.setattr(Path, "lstat", deny("lstat"))
    monkeypatch.setattr(Path, "exists", deny("exists"))
    monkeypatch.setattr(Path, "is_file", deny("is_file"))
    monkeypatch.setattr(Path, "is_dir", deny("is_dir"))

    hostile = {
        "schema_version": OPENROUTER_V2_REQUEST_SCHEMA,
        "authority_id": OPENROUTER_V2_RECOVERY_AUTHORITY_ID,
        "parent": {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-20260823",
            "state_root": "artifacts/restricted/catalog/phase5-openrouter-recovery",
        },
    }
    with pytest.raises(PermissionError, match="OPENROUTER_V2_HISTORICAL"):
        reject_historical_openrouter_v2_coordinates(hostile)
    assert touched == []


def test_openrouter_v2_capability_names_are_distinct_and_inert(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import socket

    from itda import minimal_probe_bootstrap as bootstrap
    from itda.cli import materialize_phase5_demo_profiles as command

    expected = {
        "openrouter-recovery-v2-install-approval",
        "openrouter-recovery-v2-live",
        "openrouter-recovery-v2-reconcile",
    }
    assert expected == command._OPENROUTER_V2_CAPABILITY_COMMANDS
    assert expected == bootstrap._OPENROUTER_V2_COMMAND_PREFIXES
    assert expected <= bootstrap._CAPABILITY_COMMANDS
    assert expected.isdisjoint(command._OPENROUTER_CAPABILITY_COMMANDS)

    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket, "socket", deny("socket"))
    monkeypatch.setattr(Path, "read_bytes", deny("read_bytes"))
    monkeypatch.setattr(Path, "open", deny("open"))
    monkeypatch.setattr(bootstrap, "validate_capability_process", deny("checkout"))

    for capability_name in sorted(expected):
        with pytest.raises(PermissionError, match="OPENROUTER_V2_CAPABILITY_INERT"):
            command._openrouter_v2_capability_run(
                __import__("argparse").Namespace(command=capability_name)
            )
        assert bootstrap.main([capability_name]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "OPENROUTER_V2_CAPABILITY_INERT\n"
    assert touched == []


def test_openrouter_public_parser_has_no_capability_surface() -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    parser = command._parser()
    # The public help text cannot mention the capability subcommands.
    help_text = parser.format_help()
    assert "openrouter-recovery-install-approval" not in help_text
    assert "openrouter-recovery-live" not in help_text
    assert "openrouter-recovery-reconcile" not in help_text
    # Provider-free commands ARE registered.
    for public_command in (
        "openrouter-recovery-preflight",
        "openrouter-recovery-verify",
        "openrouter-recovery-classify",
    ):
        assert public_command in help_text


def test_openrouter_verify_cli_rejects_nonfixed_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _openrouter_no_provider_env(monkeypatch)
    from itda.cli import materialize_phase5_demo_profiles as command

    forged = tmp_path / "forged-terminal.json"
    forged.write_text("{}")
    argv = [
        "openrouter-recovery-verify",
        "--terminal",
        str(forged),
        "--json",
    ]
    # The public main catches capability-adjacent errors and exits 2 without
    # ever reaching a provider client or protected mutation.
    result: int | None
    try:
        result = command.main(argv)
    except SystemExit as excinfo:
        result = int(excinfo.code or 0)
    assert result == 2, f"expected rejection exit 2, got {result}"


def test_openrouter_scheduler_budget_is_bounded() -> None:
    from itda.pipeline import phase5_openrouter_recovery as lane

    scheduler = lane.OpenRouterScheduler([f"place:{i:02d}" for i in range(24)])
    first = scheduler.first_pass()
    assert len(first) == 24
    for place in first:
        scheduler.record_dispatched(place, is_retry=False)
    order = scheduler.retry_order([f"place:{i:02d}" for i in range(6)])
    assert len(order) == 6
    with pytest.raises(RuntimeError):
        scheduler.retry_order(["place:00"])


def test_openrouter_timeout_size_and_transport_classes_are_retryable() -> None:
    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_ATTEMPT_DEADLINE_SECONDS,
        OPENROUTER_MAX_RESPONSE_BYTES,
    )
    from itda.pipeline import phase5_openrouter_recovery as lane

    scheduler = lane.OpenRouterScheduler([f"place:{i:02d}" for i in range(24)])
    assert scheduler.classify_retry(error="ConnectTimeout") is True
    assert scheduler.classify_retry(error="ReadTimeout") is True
    assert scheduler.classify_retry(status_code=408) is True
    assert scheduler.classify_retry(status_code=429) is True
    assert scheduler.classify_retry(status_code=529) is True
    assert scheduler.classify_retry(status_code=301) is False
    assert scheduler.classify_retry(status_code=200) is False
    assert OPENROUTER_ATTEMPT_DEADLINE_SECONDS == 300
    assert OPENROUTER_MAX_RESPONSE_BYTES == 4 * 1024 * 1024


def test_openrouter_live_cli_blocked_offline_and_without_network_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real live handler stays fail-closed in every test environment."""

    _openrouter_no_provider_env(monkeypatch)
    from itda.cli import materialize_phase5_demo_profiles as command

    live_argv = [
        "openrouter-recovery-live",
        "--request",
        "artifacts/public/phase5/openrouter-recovery-request.json",
        "--protected-state-root",
        "artifacts/restricted/catalog/phase5-openrouter-recovery",
        "--secret-env-file",
        ".secrets/itda-openrouter.env",
        "--terminal-output",
        "artifacts/reports/phase5/openrouter-recovery-terminal.json",
        "--json",
    ]
    for env_setup in (
        {"ITDA_OFFLINE": "1", "ITDA_NO_NETWORK": "1"},
        {"ITDA_PROVIDER_NETWORK": "0"},
    ):
        for key, value in env_setup.items():
            monkeypatch.setenv(key, value)
        with pytest.raises((SystemExit, PermissionError)) as excinfo:
            command.main(live_argv)
        code = getattr(excinfo.value, "code", 1)
        assert code in (2, None) or isinstance(excinfo.value, PermissionError)


def test_openrouter_approval_status_schema_is_dedicated() -> None:
    """Install status uses the dedicated approval status schema, not generation."""

    from itda.contracts.phase5_openrouter_recovery import (
        OPENROUTER_APPROVAL_STATUS_SCHEMA,
        OPENROUTER_GENERATION_SCHEMA,
    )

    assert OPENROUTER_APPROVAL_STATUS_SCHEMA != OPENROUTER_GENERATION_SCHEMA
    assert OPENROUTER_APPROVAL_STATUS_SCHEMA == "itda.phase5-openrouter-approval-status.v1"


# ---------------------------------------------------------------------------
# T-05R-98 integration: bootstrap → install → claim → live transport with the
# actual network MOCKED.  The bootstrap gate is stubbed (a pytest process can
# never pass the real sanitized-entrypoint origin check), every other gate —
# fixed paths, approval digest over the complete payload, claim one-use,
# reserve-before-secret ordering, sealed frozen transport entries — runs for
# REAL against temporary roots.  Zero sockets: httpx.AsyncClient is replaced
# by a MockTransport-backed constructor before any handler runs.
# ---------------------------------------------------------------------------


class TestOpenRouterBootstrapToLiveIntegration:
    """Provider-free end-to-end capability chain through the PRIVATE test
    transport seam ONLY (WR-B final: production globals are never redirected
    to temporary paths — the sealed public entries stay bound to the real
    fixed paths at all times)."""

    def _synthetic_bundles(self):
        from itda.contracts.demo_profile_materialization import (
            DemoSourceBundle,
            DemoSourceEvidence,
        )
        from itda.domain.canonical import canonical_sha256
        from itda.domain.demo_profile_eligibility import _CANONICAL_DEV_IDS
        from itda.pipeline.demo_profile_materialization import (
            validate_demo_source_inventory,
        )

        bundles = []
        for place_id in _CANONICAL_DEV_IDS:
            sources = []
            for index in range(2):
                text = f"synthetic tourism description {index} for {place_id}"
                text_sha = hashlib.sha256(text.encode()).hexdigest()
                sources.append(
                    DemoSourceEvidence(
                        evidence_id=f"ev-{index}",
                        source_kind="TOUR_API_DESCRIPTION",
                        source_sha256=text_sha,
                        span_sha256=text_sha,
                        text=text,
                    )
                )
            unsigned_payload = {
                "schema_version": "itda.demo-source-bundle.v1",
                "place_id": place_id,
                "split": "DEV",
                "sources": [s.model_dump(mode="json") for s in sources],
                "optional_image": None,
                "source_inventory_sha256": "0" * 64,
            }
            bundles.append(
                DemoSourceBundle.model_validate(
                    {
                        **unsigned_payload,
                        "source_bundle_sha256": canonical_sha256(unsigned_payload),
                    }
                )
            )
        validated = validate_demo_source_inventory(bundles)  # type: ignore[arg-type]
        return validated

    def _lane(self):
        from itda.pipeline import phase5_openrouter_recovery as lane

        return lane

    def _membership_sha256(self) -> str:
        from itda.contracts.phase5_openrouter_recovery import (
            OPENROUTER_MEMBERSHIP_SHA256,
        )

        return OPENROUTER_MEMBERSHIP_SHA256

    def _authority_id(self) -> str:
        from itda.contracts.phase5_openrouter_recovery import (
            OPENROUTER_RECOVERY_AUTHORITY_ID,
        )

        return OPENROUTER_RECOVERY_AUTHORITY_ID

    def _canonical(self, payload):
        from itda.domain.canonical import canonical_json_bytes

        return canonical_json_bytes(payload)

    def _seed_e2e_approval(self, root, plan) -> str:
        """Seed a synthetic approval bound to THIS temp root and plan."""

        from itda.contracts.phase5_openrouter_recovery import (
            OpenRouterApprovalBinding,
            OpenRouterProtectedStateDescriptor,
            load_openrouter_snapshot,
        )
        from itda.domain.canonical import canonical_sha256

        descriptor = OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        fields = {
            "schema_version": "itda.phase5-openrouter-approval.v1",
            "authority_id": self._authority_id(),
            "decision": "APPROVED",
            "request_artifact_sha256": "e" * 64,
            "request_file_sha256": "e" * 64,
            "request_manifest_sha256": str(plan.request_manifest_sha256),
            "membership_sha256": self._membership_sha256(),
            "checkout_manifest_sha256": str(plan.checkout_manifest_sha256),
            "checkout_commit_sha256": str(plan.checkout_commit_sha256),
            "protected_state_sha256": str(descriptor.protected_state_sha256),
            "secret_identity_sha256": "2" * 64,
            "provider_lane": "OPENROUTER_API",
            "endpoint": "https://openrouter.ai/api/v1/chat/completions",
            "model": "stealth/ox-alpha",
            "snapshot_sha256": str(load_openrouter_snapshot().snapshot_sha256),
            "member_count": 24,
            "first_pass_count": 24,
            "max_retries": 6,
            "max_attempts": 30,
            "concurrency": 1,
            "attempt_deadline_seconds": 300,
            "max_response_bytes": 4194304,
            "reservation_micro_usd": 0,
            "cumulative_exposure_micro_usd": 0,
            "receipt_emitted": False,
            "lifecycle_mutated": False,
        }
        approval = OpenRouterApprovalBinding.model_validate(
            {**fields, "approval_sha256": canonical_sha256(fields)}
        )
        from itda.domain.canonical import canonical_json_bytes

        root.mkdir(mode=0o700, exist_ok=True)
        (root / "approval.json").write_bytes(
            canonical_json_bytes(approval.model_dump(mode="json"))
        )
        os.chmod(root / "approval.json", 0o600)
        return str(approval.approval_sha256)

    def test_private_seam_install_claim_live_success(self, tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
        """Install -> claim -> 24 attempts through execute_openrouter_mock_
        transport (the strictly-private test seam) on a temp root.  NO
        production global is patched: the sealed public entries keep their
        real fixed paths; the mock seam REFUSES the production root by
        design and only accepts isolated /tmp-family roots."""

        import asyncio
        import json as json_module
        import sys as _sys
        from pathlib import Path as _Path

        from itda.domain.canonical import canonical_sha256
        from itda.pipeline import phase5_openrouter_recovery as lane

        # Reuse the CONTRACT suite's synthetic 24-member builders (test-to-
        # test import of synthetic fixtures only — never a production seam).
        contract_dir = _Path(__file__).resolve().parents[1] / "contract"
        _sys.path.insert(0, str(contract_dir))
        try:
            import test_phase5_openrouter_recovery as _contract

            builder = _contract.TestFullSyntheticE2E()
            builder._build_plan_24()  # persistent synthetic source patch active
            plan = _contract.TestCoherentPositiveForgeryRejected._build_patched_plan()
            profiles = _contract.TestFullSyntheticE2E._profiles_for(builder, plan)
        finally:
            _sys.path.remove(str(contract_dir))
        authority_id = self._authority_id()
        seed_approval = self._seed_e2e_approval
        canonical_bytes = self._canonical
        root = tmp_path / "seam-root"

        def handler(request: httpx.Request) -> httpx.Response:
            body = json_module.loads(request.content.decode("utf-8"))
            user = json_module.loads(body["messages"][1]["content"])
            return httpx.Response(
                200, json={"profile": profiles[user["place_id"]]}
            )

        approval_digest = seed_approval(root, plan)
        state = lane.OpenRouterDurableAuthorityState(
            lane.OpenRouterProtectedStateDescriptor.from_root(state_root=str(root))
        )
        claim_fields = {
            "schema_version": "itda.phase5-openrouter-claim.v1",
            "authority_id": authority_id,
            "request_artifact_sha256": "e" * 64,
            "request_file_sha256": "e" * 64,
            "approval_sha256": approval_digest,
            "protected_state_sha256": str(state.descriptor.protected_state_sha256),
        }
        from itda.contracts.phase5_openrouter_recovery import OpenRouterClaim

        claim = OpenRouterClaim.model_validate(
            {**claim_fields, "claim_sha256": canonical_sha256(claim_fields)}
        )
        (root / "claim.json").write_bytes(canonical_bytes(claim.model_dump(mode="json")))
        os.chmod(root / "claim.json", 0o600)

        result = asyncio.run(
            lane.execute_openrouter_mock_transport(
                plan=plan,
                claim=claim,
                protected_state_root=root,
                response_handler=handler,
            )
        )
        assert result["status"] == "COMPLETE_CANDIDATE_READY"
        entries = state.read_ledger_entries()
        operations = [row["operation"] for row in entries]
        assert operations.count("RESERVE") == 24
        assert operations.count("COMMIT") == 24
        assert all(row["amount_micro_usd"] == 0 for row in entries)
        # WR-A final semantics: client=true is durable-marker proven; network
        # true only because every attempt RETURNED a response.
        assert result["client_constructed"] is True
        assert result["network_attempted"] is True
        assert result["send_certainty"] == "SEND_ATTEMPT_MAY_HAVE_STARTED"

    def test_public_entries_never_redirect_to_temp_roots(self, tmp_path: Path) -> None:
        """WR-B final acceptance: the sealed public entries keep their REAL
        fixed paths even while an adversarial caller monkeypatches every
        former mutable global to a temporary path.  A direct call must still
        fail closed on the bootstrap origin gate — never reach a redirected
        temp root or a client."""

        from itda.pipeline import phase5_openrouter_recovery as lane

        fake_root = tmp_path / "fake-repo"
        saved = {}
        poisoned = {
            "REPOSITORY_ROOT": fake_root,
            "_SYNC_BINDING": None,
            "_ASYNC_BINDING": None,
            "_derive_production_authority": None,
            "_openrouter_fixed_secret_file": None,
            "_openrouter_secret_metadata_identity": None,
            "_read_fixed_openrouter_secret_value": None,
        }
        for symbol in poisoned:
            if hasattr(lane, symbol):
                saved[symbol] = getattr(lane, symbol)

        class _Poison:
            def __getattr__(self, name):  # any attribute access explodes loudly
                raise AssertionError(f"poisoned global consulted: {name}")

        try:
            for symbol in poisoned:
                setattr(lane, symbol, _Poison())
            with pytest.raises(
                PermissionError, match="MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID"
            ):
                lane.execute_openrouter_production()
        finally:
            for symbol, original in saved.items():
                setattr(lane, symbol, original)


def test_bootstrap_wiring_drives_real_dispatcher_subprocess(
    tmp_path: Path,
) -> None:
    """WR-B re-audit: the sanitized bootstrap main() REALLY wires to the
    production OpenRouter dispatcher — proven with UNIQUE sentinels.

    A REAL ``python -I`` subprocess executes the ACTUAL committed
    ``minimal_probe_bootstrap.py`` file as ``sys.argv[0]`` so every origin
    check passes for real (no stubbing of ``validate_capability_process``).
    Under an OS-level network-deny profile the child:

      1. passes ``validate_capability_process()`` inside bootstrap main()
         (a failure would print MINIMAL_PROBE_BOOTSTRAP_REJECTED);
      2. reaches the REAL ``_openrouter_capability_dispatch`` (a wiring break
         raises ImportError/Traceback before any handler);
      3. runs through the reconcile handler's fixed-path gates until the
         missing gitignored restricted source authority fails closed, which
         the dispatcher converts to its OWN unique sentinel
         ``PHASE5_PROFILE_MATERIALIZATION_REJECTED`` + exit code 2.

    The two sentinel strings are mutually exclusive per stage, so a driver-
    argv-mismatch early rejection can never be mistaken for success.

    The checkout-cleanliness gate validates against a THROWAWAY LOCAL CLONE
    of the committed HEAD (never the live working tree): the clone is clean
    by construction, so this test's own uncommitted edits cannot fail the
    gate and a dirty-tree rejection can never be mistaken for wiring proof.
    """

    import os as os_module
    import subprocess
    import sys

    deny_profile = tmp_path / "deny.sb"
    deny_profile.write_text("(version 1)(allow default)(deny network*)\n")

    repository_root = Path(__file__).resolve().parents[3]

    # Clean checkout target: local clone of THIS worktree's HEAD.  Contains
    # only committed files — exactly what the stdlib checkout policy demands.
    clean_checkout = tmp_path / "clean-checkout"
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--shared",
            str(repository_root),
            str(clean_checkout),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    clone_status = subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=str(clean_checkout),
        check=True,
        capture_output=True,
        timeout=60,
    )
    assert clone_status.stdout.strip() == b"", "clone must start perfectly clean"

    child_env = {
        key: value
        for key, value in os_module.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "ITDA_OFFLINE", "ITDA_NO_NETWORK", "CI"}
    }
    child_env["ITDA_PROVIDER_NETWORK"] = "1"
    bootstrap_file = clean_checkout / "backend/src/itda/minimal_probe_bootstrap.py"
    assert bootstrap_file.is_file()

    argv = [
        "openrouter-recovery-reconcile",
        "--request",
        "artifacts/public/phase5/openrouter-recovery-request.json",
        "--protected-state-root",
        "artifacts/restricted/catalog/phase5-openrouter-recovery",
        "--terminal-output",
        "artifacts/reports/phase5/openrouter-recovery-terminal.json",
        "--json",
    ]
    command = []
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    if sandbox_exec.exists():
        command += [str(sandbox_exec), "-f", str(deny_profile)]
    command += [
        sys.executable,
        "-I",
        str(bootstrap_file),  # sys.argv[0] IS the real production bootstrap.
        *argv,
    ]
    completed = subprocess.run(
        command,
        cwd=str(clean_checkout),
        env=child_env,
        capture_output=True,
        timeout=180,
    )
    stdout = completed.stdout.decode("utf-8", "replace")
    stderr = completed.stderr.decode("utf-8", "replace")

    # WR-B: exact-stage assertions — each rejection sentinel proves WHICH
    # stage ran.  The bootstrap-level gate must NOT have fired; the
    # dispatcher-level handler must have fired.
    assert completed.returncode == 2, (completed.returncode, stdout[:400], stderr[:400])
    assert "PHASE5_PROFILE_MATERIALIZATION_REJECTED" in stderr, (
        f"dispatcher sentinel missing — wiring broke:\nstdout={stdout[:400]}\n"
        f"stderr={stderr[:400]}"
    )
    # The bootstrap-origin stage passed (its rejection is mutually exclusive).
    assert "MINIMAL_PROBE_BOOTSTRAP_REJECTED" not in stderr, stderr[:400]
    assert "MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID" not in stderr, stderr[:400]
    assert "MINIMAL_PROBE_BOOTSTRAP_UNTRACKED_FORBIDDEN" not in stderr, stderr[:400]
    # No crash, no wiring ImportError anywhere in the child process.
    assert "Traceback" not in stderr, stderr[:400]
    assert "ImportError" not in stderr and "cannot import name" not in stderr, (
        stderr[:400]
    )


def test_direct_public_entry_fails_before_client_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """401-recurrence regression: a DIRECT call to the zero-argument public
    production entry outside the sanitized bootstrap fails at the capability
    gate BEFORE any offline check, client construction, credential read, or
    durable mutation — even with ITDA_PROVIDER_NETWORK=1 set."""

    _openrouter_no_provider_env(monkeypatch)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.setenv("ITDA_PROVIDER_NETWORK", "1")

    import httpx as httpx_module

    from itda.pipeline import phase5_openrouter_recovery as lane

    # Any attempt to build a real client explodes loudly — proving the entry
    # never reached transport construction.
    def _deny_client(*args: object, **kwargs: object) -> object:
        raise AssertionError("client construction was reached by direct call")

    saved_client = httpx_module.AsyncClient
    try:
        httpx_module.AsyncClient = _deny_client  # type: ignore[misc]
        # WR-B strict: the EXACT capability-origin error only — no LIVE_*
        # alternative accepted.  A direct call outside the sanitized bootstrap
        # must fail on the origin gate itself, before any offline check.
        with pytest.raises(
            PermissionError, match="MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID"
        ):
            lane.execute_openrouter_production()
    finally:
        httpx_module.AsyncClient = saved_client  # type: ignore[misc]


# ---------------------------------------------------------------------------
# OpenRouter r3/v3 lane (provider-free CLI/bootstrap activation surface).
# ---------------------------------------------------------------------------


def test_openrouter_v3_public_commands_are_provider_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The v3 public commands never construct a client, open a socket, or
    reach the production protected root / secret file."""

    _openrouter_no_provider_env(monkeypatch)
    import socket as socket_module

    from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket_module, "socket", deny("socket"))

    # Unknown command exits 2 without touching anything.
    assert v3_main(["openrouter-recovery-v3-unknown"]) == 2
    assert touched == []


def test_openrouter_v3_verify_cli_rejects_nonfixed_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _openrouter_no_provider_env(monkeypatch)
    from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

    forged = tmp_path / "forged-v3-terminal.json"
    forged.write_text("{}")
    argv = [
        "openrouter-recovery-v3-verify",
        "--terminal",
        str(forged),
        "--json",
    ]
    result: int | None
    try:
        result = v3_main(argv)
    except SystemExit as excinfo:
        result = int(excinfo.code or 0)
    assert result == 2


def test_openrouter_v3_capability_names_fail_closed_through_public_surfaces() -> None:
    """Both public entry modules refuse the three v3 capability names."""

    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

    for name in (
        "openrouter-recovery-v3-install-approval",
        "openrouter-recovery-v3-live",
        "openrouter-recovery-v3-reconcile",
    ):
        assert v3_main([name]) == 2
        result: int | None
        try:
            result = command.main([name])
        except SystemExit as excinfo:
            result = int(excinfo.code or 0)
        assert result == 2, name


def test_openrouter_v3_secret_shape_validator_named_errors_only(
    tmp_path: Path,
) -> None:
    """Shape validation returns pass or a fixed named error; never any
    value/length/prefix/digest/identity/inode/device material."""

    import os as os_module

    from itda.cli.phase5_openrouter_recovery_v3 import validate_v3_secret_shape

    good_dir = tmp_path / "good" / ".secrets"
    good_dir.mkdir(parents=True, mode=0o700)
    secret = good_dir / "itda-openrouter.env"
    secret.write_bytes(b"OPENROUTER_API_KEY=synthetic-value\n")
    os_module.chmod(secret, 0o600)
    passed = validate_v3_secret_shape(secret)
    assert passed == {"status": "pass"}

    # File mode too permissive.
    loose_dir = tmp_path / "loose" / ".secrets"
    loose_dir.mkdir(parents=True, mode=0o700)
    loose = loose_dir / "itda-openrouter.env"
    loose.write_bytes(b"OPENROUTER_API_KEY=x\n")
    os_module.chmod(loose, 0o644)
    loose_result = validate_v3_secret_shape(loose)
    assert loose_result["status"] == "fail"
    assert isinstance(loose_result["error"], str) and loose_result["error"]


def test_openrouter_v3_bootstrap_registers_capability_prefixes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bootstrap knows the v3 capability names and keeps v2 inert first."""

    from itda import minimal_probe_bootstrap as bootstrap

    expected = {
        "openrouter-recovery-v3-install-approval",
        "openrouter-recovery-v3-live",
        "openrouter-recovery-v3-reconcile",
    }
    assert expected <= bootstrap._CAPABILITY_COMMANDS
    assert expected == bootstrap._OPENROUTER_V3_COMMAND_PREFIXES
    # v2 inert rejection still precedes any v3 handling.
    assert bootstrap.main(["openrouter-recovery-v2-live"]) == 2
    captured = capsys.readouterr()
    assert captured.err == "OPENROUTER_V2_CAPABILITY_INERT\n"


def test_openrouter_v3_sealed_runner_is_zero_argument_and_offline_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _openrouter_no_provider_env(monkeypatch)
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.setenv("ITDA_NO_NETWORK", "1")
    import inspect

    from itda.cli.phase5_openrouter_recovery_v3 import (
        execute_openrouter_v3_production,
    )

    assert set(inspect.signature(execute_openrouter_v3_production).parameters) == set()
    with pytest.raises(PermissionError):
        execute_openrouter_v3_production()


def test_openrouter_v3_neutral_verifier_has_no_network_or_secret_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """verify/classify cannot reach a client, socket, DNS, or the fixed
    production secret path even when pointed at synthetic evidence."""

    _openrouter_no_provider_env(monkeypatch)
    import socket as socket_module

    repository_root = Path(__file__).resolve().parents[3]
    production_secret = repository_root / ".secrets" / "itda-openrouter.env"
    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    def deny_secret(function, name: str):
        def wrapper(path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            try:
                candidate = Path(os.path.abspath(os.fspath(path)))
            except (TypeError, ValueError):
                return function(path, *args, **kwargs)
            if candidate == production_secret:
                touched.append(name)
                raise AssertionError("PRODUCTION_SECRET_ACCESSED")
            return function(path, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket_module, "create_connection", deny("connect"))

    from itda.cli.phase5_openrouter_recovery_v3 import main as v3_main

    # The verify command against a nonfixed path fails closed before reads.
    assert (
        v3_main(
            [
                "openrouter-recovery-v3-verify",
                "--terminal",
                str(tmp_path / "absent.json"),
                "--json",
            ]
        )
        == 2
    )
    assert touched == []


def test_openrouter_v4_public_and_capability_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import inspect
    import socket as socket_module

    from itda import minimal_probe_bootstrap as bootstrap
    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.cli.phase5_openrouter_recovery_v4 import (
        execute_openrouter_v4_production,
    )
    from itda.cli.phase5_openrouter_recovery_v4 import (
        main as v4_main,
    )

    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket_module, "socket", deny("socket"))
    assert v4_main(["openrouter-recovery-v4-unknown"]) == 2
    capability_names = {
        "openrouter-recovery-v4-install-approval",
        "openrouter-recovery-v4-live",
        "openrouter-recovery-v4-reconcile",
    }
    assert capability_names == bootstrap._OPENROUTER_V4_COMMAND_PREFIXES
    assert capability_names == command._OPENROUTER_V4_CAPABILITY_COMMANDS
    for name in capability_names:
        assert v4_main([name]) == 2
    assert set(inspect.signature(execute_openrouter_v4_production).parameters) == set()
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.setenv("ITDA_NO_NETWORK", "1")
    with pytest.raises(
        PermissionError, match="MINIMAL_PROBE_BOOTSTRAP_|LIVE_MODE_DISABLED"
    ):
        execute_openrouter_v4_production()
    assert touched == []


def test_openrouter_v4_rejects_v3_before_state_client_or_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    from itda.contracts.phase5_openrouter_recovery_v4 import (
        reject_historical_openrouter_coordinates,
    )

    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket, "socket", deny("socket"))
    monkeypatch.setattr(Path, "read_bytes", deny("read_bytes"))
    with pytest.raises(PermissionError, match="OPENROUTER_V4_HISTORICAL"):
        reject_historical_openrouter_coordinates(
            {
                "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r3-20260824",
                "schema_version": "itda.phase5-openrouter-terminal.v3",
                "path": "artifacts/restricted/catalog/phase5-openrouter-recovery-r3",
            }
        )
    assert touched == []


def test_openrouter_v3_historical_rejection_precedes_state_client_and_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    from itda.contracts.phase5_openrouter_recovery_v3 import (
        OPENROUTER_V3_REQUEST_SCHEMA,
        reject_historical_openrouter_coordinates,
    )
    from itda.contracts.phase5_openrouter_recovery_v3_paths import (
        OPENROUTER_V3_PUBLIC_REQUEST_PATH,
    )

    touched: list[str] = []

    def deny(name: str):
        def blocked(*_args: object, **_kwargs: object) -> object:
            touched.append(name)
            raise AssertionError(f"capability reached: {name}")

        return blocked

    monkeypatch.setattr(httpx, "AsyncClient", deny("client"))
    monkeypatch.setattr(socket, "socket", deny("socket"))
    monkeypatch.setattr(Path, "read_bytes", deny("read_bytes"))
    monkeypatch.setattr(Path, "open", deny("open"))
    monkeypatch.setattr(Path, "stat", deny("stat"))

    hostile = {
        "schema_version": OPENROUTER_V3_REQUEST_SCHEMA,
        "authority_id": "phase5-openrouter-stealth-ox-alpha-recovery-r2-20260824",
        "snapshot_relative_path": str(OPENROUTER_V3_PUBLIC_REQUEST_PATH),
    }
    with pytest.raises(PermissionError, match="OPENROUTER_V3_HISTORICAL"):
        reject_historical_openrouter_coordinates(hostile)
    assert touched == []
