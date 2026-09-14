"""Provider wire verification uses only a local HTTP mock transport."""

import json

import httpx
import pytest

from itda.photo.provider.live import PhotoLiveAnalysisUnavailable
from itda.photo.provider.vlm import SemanticVlmPhotoAnalysisProvider
from itda.pipeline.offline_guard import LiveCollectionRefused


def _provider(handler):
    return SemanticVlmPhotoAnalysisProvider(
        endpoint="https://example.invalid/v1/chat/completions",
        model="glm-4.6v",
        api_key="test-only-secret",
        explicit_opt_in=True,
        transport=httpx.MockTransport(handler),
    )


def _analyze(provider):
    return provider.analyze(
        image_png=b"\x89PNG\r\n\x1a\nmock-sanitized", rubric_ko="여행 사진", job_id="a" * 64
    )


@pytest.fixture(autouse=True)
def _isolated_mock_configuration(monkeypatch):
    for key in ("CI", "ITDA_OFFLINE", "ITDA_NO_NETWORK"):
        monkeypatch.delenv(key, raising=False)


def test_semantic_adapter_sends_bounded_image_and_accepts_only_canonical_ids() -> None:
    requests = []

    def handler(request):
        requests.append(request)
        payload = json.loads(request.content)
        assert payload["model"] == "glm-4.6v"
        assert payload["stream"] is False and payload["max_tokens"] == 512
        image = payload["messages"][1]["content"][1]["image_url"]["url"]
        assert image.startswith("data:image/png;base64,")
        assert "tools" not in payload and "a" * 64 not in request.content.decode()
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"semantic_ids": ["M3.quiet", "M5.long_stay"]}'},
                    }
                ]
            },
        )

    result = _analyze(_provider(handler))
    assert len(requests) == 1
    assert result.analysis_kind == "semantic"
    assert [(row.trait_id, row.semantic_id) for row in result.candidates] == [
        ("M3", "M3.quiet"),
        ("M5", "M5.long_stay"),
    ]


@pytest.mark.parametrize(
    "content",
    [
        '{"semantic_ids": ["M4.wide_walk"]}',
        '{"semantic_ids": ["M3.quiet", "M3.crowded"]}',
        '{"semantic_ids": ["M3.quiet"], "score": 100}',
        '```json\n{"semantic_ids": ["M3.quiet"]}\n```',
    ],
)
def test_unknown_or_fabricated_output_fails_closed(content) -> None:
    provider = _provider(
        lambda _request: httpx.Response(
            200, json={"choices": [{"finish_reason": "stop", "message": {"content": content}}]}
        )
    )
    with pytest.raises(PhotoLiveAnalysisUnavailable):
        _analyze(provider)


def test_timeout_has_no_retry_or_secret_details() -> None:
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("test-only-secret", request=request)

    with pytest.raises(TimeoutError) as failure:
        _analyze(_provider(handler))
    assert len(calls) == 1 and "test-only-secret" not in str(failure.value)


def test_offline_guard_runs_before_any_transport(monkeypatch) -> None:
    monkeypatch.setenv("ITDA_NO_NETWORK", "1")

    def handler(_request):
        pytest.fail("offline mode must not call transport")

    with pytest.raises(LiveCollectionRefused):
        _analyze(_provider(handler))


def test_explicit_configuration_is_required() -> None:
    with pytest.raises(PhotoLiveAnalysisUnavailable):
        SemanticVlmPhotoAnalysisProvider(
            endpoint="https://example.invalid/v1/chat/completions",
            model="glm-4.6v",
            api_key="test-only-secret",
        )


@pytest.mark.parametrize("image_count,per_image", [(2, 3), (3, 2)])
def test_gateway_caps_validated_candidates_equally_per_image(
    image_count,
    per_image,
    monkeypatch,
    tmp_path,
) -> None:
    from contextlib import nullcontext

    from itda.api.routes import photo as route
    from itda.db.photo_repositories import _semantic_projection_row
    from itda.domain.photo_projection import combine_confirmed_photo_traits

    ids = ["M1.preserved", "M2.local", "M3.quiet", "M4.viewing", "M5.long_stay", "M6.flexible_time"]

    def handler(_request):
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps({"semantic_ids": list(reversed(ids))})},
                    }
                ]
            },
        )

    gateway = route.PhotoLifecycleGateway(
        factory=None,
        service_dsn="test-only",
        quarantine_root=tmp_path,
        runtime_role="unused",
        builder_role="unused",
        provider=_provider(handler),
        synthetic_test_mode=True,  # Historical cohort fixture, never production inference.
    )
    tmp_path.chmod(0o700)
    monkeypatch.setattr(gateway._mood_store, "family", lambda **_kw: None)
    monkeypatch.setattr(route.psycopg, "connect", lambda *_a, **_kw: nullcontext(None))
    monkeypatch.setattr(
        gateway,
        "_durable_slot_inventory",
        lambda *_a, **_kw: {
            index: ("a" * 32, 128, "image/png") for index in range(1, image_count + 1)
        },
    )
    monkeypatch.setattr(
        gateway, "_sanitized_bytes", lambda **_kw: b"\x89PNG\r\n\x1a\nmock-sanitized"
    )
    batches = gateway._analyze_stored_images(job_id="a" * 64, profile_id="test-owner")
    assert len(batches) == image_count
    assert [len(batch) for batch in batches] == [per_image] * image_count
    assert sum(map(len, batches)) == 6
    assert [[row["semantic_id"] for row in batch] for batch in batches] == [
        ids[:per_image]
    ] * image_count
    assert len({row["candidate_id"] for batch in batches for row in batch}) == 6
    observations = tuple(
        _semantic_projection_row(
            **{
                field: row[field]
                for field in (
                    "trait_id",
                    "text_ko",
                    "analysis_kind",
                    "provider_id",
                    "semantic_version",
                    "semantic_id",
                    "image_index",
                )
            }
        )
        for batch in batches
        for row in batch
    )
    result = combine_confirmed_photo_traits(confirmed_traits=observations, images_count=image_count)
    assert len(result.photo_trait_values) == per_image
    assert all(value == 0 for _trait, value in result.photo_trait_values)
