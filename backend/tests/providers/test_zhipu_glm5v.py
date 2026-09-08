from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime

import httpx
import pytest

from itda.contracts.vlm_inference import (
    Glm5VProviderConfig,
    InferenceTerminalStatus,
    SafeInferenceRequest,
    seal_inference_contract,
)
from itda.domain.canonical import canonical_sha256
from itda.providers.zhipu_glm5v import (
    LiveProviderApprovalReceipt,
    PreparedProviderImage,
    ZhipuGlm5VAdapter,
    build_glm5v_async_client,
)
from tests.contract.test_image_observation import REF_A, REF_B, SHA_A, _qualified_payload
from tests.contract.test_vlm_inference import _config_payload, _request_payload

NOW = datetime(2026, 8, 7, tzinfo=UTC)
IMAGE_BYTES = (b"synthetic-jpeg-a", b"synthetic-jpeg-b")


def _clock() -> datetime:
    return NOW


def _config() -> Glm5VProviderConfig:
    payload = _config_payload()
    payload["selection_manifest_sha256"] = SHA_A
    return Glm5VProviderConfig.model_validate(
        seal_inference_contract(payload, digest_field="config_sha256")
    )


def _request(config: Glm5VProviderConfig | None = None) -> SafeInferenceRequest:
    resolved = config or _config()
    payload = _request_payload(refs=(REF_A, REF_B))
    payload["provider_config_sha256"] = resolved.config_sha256
    payload["selection_manifest_sha256"] = SHA_A
    payload["selected_image_sha256"] = [hashlib.sha256(raw).hexdigest() for raw in IMAGE_BYTES]
    return SafeInferenceRequest.model_validate(
        seal_inference_contract(payload, digest_field="semantic_request_sha256")
    )


def _images() -> tuple[PreparedProviderImage, ...]:
    return (
        PreparedProviderImage(image_ref=REF_A, jpeg_bytes=IMAGE_BYTES[0]),
        PreparedProviderImage(image_ref=REF_B, jpeg_bytes=IMAGE_BYTES[1]),
    )


def test_live_client_fails_closed_before_accepting_missing_operator_approval() -> None:
    with pytest.raises(PermissionError, match="numeric pricing is unknown"):
        build_glm5v_async_client(
            api_key="synthetic-not-a-credential",
            config=_config(),
        )


def _approval(config: Glm5VProviderConfig) -> LiveProviderApprovalReceipt:
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-live-provider-approval.v1",
        "provider_endpoint": config.endpoint,
        "provider_model": "glm-5v-turbo",
        "provider_config_sha256": config.config_sha256,
        "selection_manifest_sha256": config.selection_manifest_sha256,
        "protected_image_capability_sha256": "a" * 64,
        "quota_receipt_sha256": "b" * 64,
        "output_capability_sha256": "c" * 64,
        "maximum_requests": 1,
        "maximum_cost_microusd": 500_000,
        "approver_identity": "phase4-operator",
        "valid_from": "2026-08-07T00:00:00Z",
        "expires_at": "2026-08-08T00:00:00Z",
    }
    return LiveProviderApprovalReceipt.model_validate(
        {**fields, "approval_sha256": canonical_sha256(fields)}
    )


def test_live_client_rejects_forged_and_stale_operator_approval() -> None:
    config = _config()
    approval = _approval(config)
    forged = approval.model_dump(mode="json")
    forged["maximum_cost_microusd"] = 1_000_000
    with pytest.raises(ValueError, match="digest"):
        LiveProviderApprovalReceipt.model_validate(forged)

    with pytest.raises(PermissionError, match="currently valid"):
        approval.authorize_provider(
            config=config,
            at=datetime(2026, 8, 8, tzinfo=UTC),
        )


def test_live_client_fails_closed_while_numeric_pricing_is_unknown() -> None:
    config = _config()
    with pytest.raises(PermissionError, match="numeric pricing is unknown"):
        build_glm5v_async_client(
            api_key="synthetic-not-a-credential",
            config=config,
            live_approval=_approval(config),
            approval_time=NOW,
        )


def _provider_response(
    *,
    observation: dict[str, object] | str | None = None,
    model: str = "glm-5v-turbo",
    finish_reason: str = "stop",
    request_id: str = "provider-request-1",
) -> dict[str, object]:
    content = (
        observation
        if isinstance(observation, str)
        else json.dumps(
            observation or _qualified_payload(), ensure_ascii=False, separators=(",", ":")
        )
    )
    return {
        "id": "completion-1",
        "request_id": request_id,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


async def _adapter(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    sleeper: Callable[[float], object] | None = None,
) -> AsyncIterator[ZhipuGlm5VAdapter]:
    config = _config()
    client = build_glm5v_async_client(
        api_key="synthetic-not-a-credential",
        config=config,
        transport=httpx.MockTransport(handler),
    )

    async def no_sleep(_seconds: float) -> None:
        return None

    resolved_sleeper = sleeper if sleeper is not None else no_sleep
    adapter = ZhipuGlm5VAdapter(
        config=config,
        client=client,
        clock=_clock,
        request_id_factory=lambda attempt: f"attempt-{attempt}",
        sleeper=resolved_sleeper,
    )
    try:
        yield adapter
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_shared_client_and_success_request_are_frozen_and_safe() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_provider_response())

    async for adapter in _adapter(handler):
        result = await adapter.extract(request=_request(adapter.config), images=_images())
        client = adapter.client

        assert client.follow_redirects is False
        assert client.timeout.connect == 10
        assert client.timeout.read == 180
        assert client.timeout.write == 60
        assert client.timeout.pool == 10
        assert result.manifest.terminal_status is InferenceTerminalStatus.VALID
        assert result.observation is not None
        assert result.observation.selected_image_refs == (REF_A, REF_B)

    assert len(seen) == 1
    wire = json.loads(seen[0].content)
    assert seen[0].url == "https://open.bigmodel.cn/api/paas/v4/chat/completions"
    assert wire["model"] == "glm-5v-turbo"
    assert wire["stream"] is False
    assert wire["do_sample"] is False
    assert wire["max_tokens"] == 2048
    assert "tools" not in wire
    assert "response_format" not in wire
    assert (
        sum(
            part["type"] == "image_url"
            for message in wire["messages"]
            for part in message["content"]
            if isinstance(message["content"], list)
        )
        == 2
    )


@pytest.mark.asyncio
async def test_retryable_statuses_stop_at_three_total_attempts() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, content=b"protected-provider-body")

    async def sleeper(seconds: float) -> None:
        sleeps.append(seconds)

    async for adapter in _adapter(handler, sleeper=sleeper):
        result = await adapter.extract(request=_request(adapter.config), images=_images())

    assert calls == 3
    assert sleeps == [1.0, 2.0]
    assert result.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED
    assert [attempt.retry_disposition.value for attempt in result.manifest.attempts] == [
        "RETRY",
        "RETRY",
        "DO_NOT_RETRY",
    ]
    assert all("protected-provider-body" not in repr(row) for row in result.manifest.attempts)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("declared", "chunked"))
async def test_oversized_provider_responses_are_bounded_and_never_retried(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    monkeypatch.setattr("itda.providers.zhipu_glm5v._MAX_PROVIDER_RESPONSE_BYTES", 32)
    calls = 0

    class OversizedStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"x" * 20
            yield b"y" * 20

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if mode == "declared":
            return httpx.Response(
                500,
                headers={"Content-Length": "33"},
                content=b"small",
                request=request,
            )
        return httpx.Response(200, stream=OversizedStream(), request=request)

    async for adapter in _adapter(handler):
        result = await adapter.extract(request=_request(adapter.config), images=_images())

    assert calls == 1
    assert result.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED
    assert result.manifest.attempts[0].error_code == "RESPONSE_BYTE_LIMIT_EXCEEDED"
    assert result.manifest.attempts[0].retry_disposition.value == "DO_NOT_RETRY"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 408, 413])
async def test_non_retryable_statuses_terminate_after_one_attempt(status: int) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, content=b"never-persist-this-body")

    async for adapter in _adapter(handler):
        result = await adapter.extract(request=_request(adapter.config), images=_images())

    assert calls == 1
    assert len(result.manifest.attempts) == 1
    assert result.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED


@pytest.mark.asyncio
async def test_allowlisted_network_failures_retry_but_pool_timeout_does_not() -> None:
    retry_calls = 0

    def retry_handler(request: httpx.Request) -> httpx.Response:
        nonlocal retry_calls
        retry_calls += 1
        if retry_calls == 1:
            raise httpx.ConnectError("synthetic connect failure", request=request)
        return httpx.Response(200, json=_provider_response())

    async for adapter in _adapter(retry_handler):
        recovered = await adapter.extract(request=_request(adapter.config), images=_images())

    assert retry_calls == 2
    assert recovered.manifest.terminal_status is InferenceTerminalStatus.VALID
    assert recovered.manifest.attempts[0].error_code == "CONNECT_ERROR"

    pool_calls = 0

    def pool_handler(request: httpx.Request) -> httpx.Response:
        nonlocal pool_calls
        pool_calls += 1
        raise httpx.PoolTimeout("synthetic local backpressure", request=request)

    async for adapter in _adapter(pool_handler):
        failed = await adapter.extract(request=_request(adapter.config), images=_images())

    assert pool_calls == 1
    assert failed.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED
    assert failed.manifest.attempts[0].error_code == "POOL_TIMEOUT"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        _provider_response(observation="not-json"),
        _provider_response(observation={"schema_version": "photo-attributes.v2"}),
        _provider_response(model="substituted-model"),
        _provider_response(finish_reason="length"),
    ],
)
async def test_invalid_envelope_or_semantics_receive_zero_repair_retries(
    response: dict[str, object],
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=response)

    async for adapter in _adapter(handler):
        result = await adapter.extract(request=_request(adapter.config), images=_images())

    assert calls == 1
    assert result.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED
    assert result.observation is None


@pytest.mark.asyncio
async def test_self_consistent_wrong_image_lineage_is_rejected_without_retry() -> None:
    hostile = _qualified_payload()
    hostile["representative_manifest_sha256"] = "9" * 64
    hostile["observation_sha256"] = hashlib.sha256(b"invalid-until-resealed").hexdigest()
    hostile = seal_inference_contract(hostile, digest_field="observation_sha256")
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_provider_response(observation=hostile))

    async for adapter in _adapter(handler):
        result = await adapter.extract(request=_request(adapter.config), images=_images())

    assert calls == 1
    assert result.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED
    assert result.observation is None


@pytest.mark.asyncio
async def test_mock_replay_produces_byte_identical_safe_artifacts() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_provider_response())

    manifests: list[bytes] = []
    for _ in range(2):
        async for adapter in _adapter(handler):
            result = await adapter.extract(request=_request(adapter.config), images=_images())
            manifests.append(
                json.dumps(
                    result.manifest.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )

    assert manifests[0] == manifests[1]


@pytest.mark.asyncio
async def test_concurrency_is_one_and_cancellation_releases_the_semaphore() -> None:
    active = 0
    maximum = 0
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal active, maximum, calls
        calls += 1
        active += 1
        maximum = max(maximum, active)
        entered.set()
        try:
            await release.wait()
            return httpx.Response(200, json=_provider_response(request_id=f"provider-{calls}"))
        finally:
            active -= 1

    config = _config()
    client = build_glm5v_async_client(
        api_key="synthetic-not-a-credential",
        config=config,
        transport=httpx.MockTransport(handler),
    )
    adapter = ZhipuGlm5VAdapter(
        config=config,
        client=client,
        clock=_clock,
        request_id_factory=lambda attempt: f"attempt-{attempt}",
        sleeper=lambda _seconds: asyncio.sleep(0),
    )
    try:
        first = asyncio.create_task(adapter.extract(request=_request(config), images=_images()))
        await entered.wait()
        second = asyncio.create_task(adapter.extract(request=_request(config), images=_images()))
        await asyncio.sleep(0)
        assert maximum == 1

        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        release.set()
        completed = await second
    finally:
        await client.aclose()

    assert maximum == 1
    assert completed.manifest.terminal_status is InferenceTerminalStatus.VALID


def test_preflight_rejects_image_digest_drift_before_transport() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_provider_response())

    async def run() -> None:
        async for adapter in _adapter(handler):
            hostile = list(_images())
            hostile[0] = PreparedProviderImage(image_ref=REF_A, jpeg_bytes=b"changed")
            with pytest.raises(ValueError, match="image digest"):
                await adapter.extract(request=_request(adapter.config), images=tuple(hostile))

    asyncio.run(run())
    assert calls == 0
