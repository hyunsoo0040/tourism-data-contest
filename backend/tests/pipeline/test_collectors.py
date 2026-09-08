from __future__ import annotations

import hashlib
import json
import math
from base64 import b64decode
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, quote_plus

import httpx
import pytest

from itda.collectors.base import CollectionError, RequestPolicy
from itda.collectors.kto import KorService2Client
from itda.collectors.odii import OdiiClient
from itda.collectors.snapshots import write_snapshot
from itda.contracts.provenance import (
    MAX_PROVIDER_JSON_DEPTH,
    MAX_PROVIDER_JSON_NODES,
    extract_provider_modifiedtime,
    extract_upstream_rights,
    parse_provider_json_bytes,
)
from itda.pipeline.offline_guard import LiveCollectionRefused

FIXED_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
SERVICE_KEY = "decoding-key-must-never-be-recorded"
PROVIDER_RAW_LIMIT = 2_000_000


def _pathological_provider_json(shape: str) -> bytes:
    if shape == "deep":
        return b"[" * 1_100 + b"{}" + b"]" * 1_100
    assert shape == "wide"
    return ("[" + ",".join("0" for _ in range(MAX_PROVIDER_JSON_NODES)) + "]").encode()


def _provider_json_body_of_size(size: int) -> bytes:
    prefix = b'{"payload":"'
    suffix = b'"}'
    assert size >= len(prefix) + len(suffix)
    return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix


def test_korservice2_retries_bounded_status_and_preserves_provenance() -> None:
    attempts: list[httpx.Request] = []
    raw_body = (
        b'{"response":{"body":{"items":{"item":[{"contentid":"126166",'
        b'"modifiedtime":"20260722120000","cpyrhtDivCd":"Type3"}]}}}}'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        if len(attempts) == 1:
            return httpx.Response(503, content=b"temporary", request=request)
        return httpx.Response(
            200,
            content=raw_body,
            headers={"content-type": "application/json"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        result = KorService2Client(
            service_key=SERVICE_KEY,
            http_client=http_client,
            policy=RequestPolicy(timeout_seconds=1.25, max_attempts=2),
            clock=lambda: FIXED_NOW,
        ).request(
            "detailCommon2",
            {"contentId": "126166"},
            explicit_opt_in=True,
        )

    assert len(attempts) == 2
    assert attempts[-1].url.host == "apis.data.go.kr"
    assert attempts[-1].url.path == "/B551011/KorService2/detailCommon2"
    assert attempts[-1].url.params["serviceKey"] == SERVICE_KEY
    assert attempts[-1].url.params["_type"] == "json"
    assert result.provider == "TOUR_API"
    assert result.endpoint == "KorService2/detailCommon2"
    assert result.request_scope == {
        "MobileApp": "IT-DA",
        "MobileOS": "ETC",
        "_type": "json",
        "contentId": "126166",
    }
    assert result.retrieved_at == FIXED_NOW
    assert result.http_status == 200
    assert result.raw_response_sha256 == hashlib.sha256(raw_body).hexdigest()
    assert result.modifiedtime == "20260722120000"
    assert result.rights == ({"cpyrhtDivCd": "Type3"},)
    assert b64decode(result.raw_body_base64) == raw_body
    assert SERVICE_KEY not in result.to_json_bytes().decode()


@pytest.mark.parametrize("raw_body", [b"not-json", b'"scalar"', b"1", b"null"])
def test_provider_response_rejects_invalid_or_scalar_json_roots(raw_body: bytes) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=raw_body,
            headers={"content-type": "application/json"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(service_key=SERVICE_KEY, http_client=http_client)
        with pytest.raises(CollectionError, match="valid container JSON"):
            client.request(
                "detailCommon2",
                {"contentId": "126166"},
                explicit_opt_in=True,
            )


@pytest.mark.parametrize("shape", ["deep", "wide"])
def test_provider_response_rejects_pathological_valid_json(shape: str) -> None:
    raw_body = _pathological_provider_json(shape)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=raw_body,
            headers={"content-type": "application/json"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(service_key=SERVICE_KEY, http_client=http_client)
        with pytest.raises(CollectionError, match="valid container JSON"):
            client.request(
                "detailCommon2",
                {"contentId": "126166"},
                explicit_opt_in=True,
            )


@pytest.mark.parametrize(
    ("size", "accepted"),
    [(PROVIDER_RAW_LIMIT, True), (PROVIDER_RAW_LIMIT + 1, False)],
)
def test_provider_response_raw_byte_limit_is_exact(size: int, accepted: bool) -> None:
    raw_body = _provider_json_body_of_size(size)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=raw_body,
            headers={"content-type": "application/json"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(service_key=SERVICE_KEY, http_client=http_client)
        if accepted:
            result = client.request(
                "detailCommon2",
                {"contentId": "126166"},
                explicit_opt_in=True,
            )
            assert len(b64decode(result.raw_body_base64)) == PROVIDER_RAW_LIMIT
        else:
            with pytest.raises(CollectionError, match="2000000-byte limit"):
                client.request(
                    "detailCommon2",
                    {"contentId": "126166"},
                    explicit_opt_in=True,
                )


def test_provider_json_depth_and_total_value_limits_are_exact() -> None:
    accepted_depth = b"[" * MAX_PROVIDER_JSON_DEPTH + b"{}" + b"]" * MAX_PROVIDER_JSON_DEPTH
    rejected_depth = b"[" + accepted_depth + b"]"
    accepted_width = (
        "[" + ",".join("0" for _ in range(MAX_PROVIDER_JSON_NODES - 1)) + "]"
    ).encode()
    rejected_width = b"[" + accepted_width[1:-1] + b",0]"

    assert isinstance(parse_provider_json_bytes(accepted_depth), list)
    assert isinstance(parse_provider_json_bytes(accepted_width), list)
    with pytest.raises(ValueError, match="maximum depth"):
        parse_provider_json_bytes(rejected_depth)
    with pytest.raises(ValueError, match="total values"):
        parse_provider_json_bytes(rejected_width)


def test_provider_projection_preserves_preorder_and_deduplicates_rights() -> None:
    payload = parse_provider_json_bytes(
        b'{"first":{"modifiedtime":"first","cpyrhtDivCd":"Type1"},'
        b'"later":[{"modifiedtime":"second","cpyrhtDivCd":"Type3"},'
        b'{"cpyrhtDivCd":"Type1"}]}'
    )

    assert extract_provider_modifiedtime(payload) == "first"
    assert extract_upstream_rights(payload) == (
        {"cpyrhtDivCd": "Type1"},
        {"cpyrhtDivCd": "Type3"},
    )


def test_retry_budget_is_finite() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(429, content=b"quota", request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(
            service_key=SERVICE_KEY,
            http_client=http_client,
            policy=RequestPolicy(timeout_seconds=0.5, max_attempts=3),
            clock=lambda: FIXED_NOW,
        )
        with pytest.raises(CollectionError, match="after 3 attempts"):
            client.request("searchKeyword2", {"keyword": "경주"}, explicit_opt_in=True)

    assert attempts == 3


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", True),
        ("timeout_seconds", "1"),
        ("timeout_seconds", 0),
        ("timeout_seconds", -1),
        ("timeout_seconds", math.inf),
        ("timeout_seconds", math.nan),
        ("max_attempts", True),
        ("max_attempts", 1.5),
        ("max_attempts", "2"),
        ("max_attempts", 0),
    ],
)
def test_request_policy_rejects_non_finite_or_non_exact_numeric_types(
    field: str,
    value: object,
) -> None:
    arguments: dict[str, object] = {"timeout_seconds": 1.0, "max_attempts": 2}
    arguments[field] = value

    with pytest.raises((TypeError, ValueError)):
        RequestPolicy(**arguments)  # type: ignore[arg-type]


def test_request_policy_timeout_has_explicit_five_minute_ceiling() -> None:
    assert RequestPolicy(timeout_seconds=300.0).timeout_seconds == 300.0
    with pytest.raises(ValueError):
        RequestPolicy(timeout_seconds=300.0001)


def test_callers_cannot_override_fixed_common_parameters() -> None:
    transport_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        raise AssertionError("invalid parameters must be rejected before transport")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(service_key=SERVICE_KEY, http_client=http_client)
        with pytest.raises(CollectionError, match="reserved parameter"):
            client.request(
                "detailCommon2",
                {"contentId": "126166", "MobileApp": "attacker"},
                explicit_opt_in=True,
            )

    assert transport_calls == 0


@pytest.mark.parametrize("service_key", ["a+b/c==%", "한글 키+/=%"])
def test_provider_response_with_encoded_key_variants_is_never_snapshotted(
    service_key: str,
) -> None:
    percent = quote(service_key, safe="")
    plus = quote_plus(service_key, safe="")
    json_escaped = json.dumps(service_key, ensure_ascii=True)[1:-1]
    variants = {
        service_key,
        percent,
        percent.lower(),
        plus,
        quote(percent, safe=""),
        quote_plus(plus, safe=""),
        json_escaped,
    }

    for reflected in variants:

        def handler(request: httpx.Request, body: str = reflected) -> httpx.Response:
            return httpx.Response(200, content=body.encode(), request=request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
            client = KorService2Client(service_key=service_key, http_client=http_client)
            with pytest.raises(CollectionError) as caught:
                client.request(
                    "detailCommon2",
                    {"contentId": "126166"},
                    explicit_opt_in=True,
                )

        assert "sensitive credential material" in str(caught.value)
        assert service_key not in str(caught.value)


@pytest.mark.parametrize(
    "reflected",
    [
        pytest.param(r"\uD55C\uAE00", id="uppercase-json-unicode"),
        pytest.param(r"\ud55c\uae00", id="lowercase-json-unicode"),
        pytest.param(r"\uD55c\uAe00", id="mixed-json-unicode"),
        pytest.param("%ED%95%9c%EA%B8%80", id="mixed-percent-hex"),
        pytest.param("%25eD%2595%259C%25EA%25b8%2580", id="mixed-double-percent"),
    ],
)
def test_provider_response_rejects_case_independent_nested_key_encodings(
    reflected: str,
) -> None:
    service_key = "한글"
    raw_body = f'{{"echo":"{reflected}"}}'.encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=raw_body,
            headers={"content-type": "application/json"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(service_key=service_key, http_client=http_client)
        with pytest.raises(CollectionError) as caught:
            client.request(
                "detailCommon2",
                {"contentId": "126166"},
                explicit_opt_in=True,
            )

    assert "sensitive credential material" in str(caught.value)
    assert service_key not in str(caught.value)


def test_recorded_scope_matches_httpx_transmitted_bool_and_null_query_values() -> None:
    seen_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_request
        seen_request = request
        return httpx.Response(200, json={"ok": True}, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        result = KorService2Client(
            service_key=SERVICE_KEY,
            http_client=http_client,
            clock=lambda: FIXED_NOW,
        ).request(
            "searchKeyword2",
            {"enabled": True, "optional": None, "count": 2},
            explicit_opt_in=True,
        )

    assert seen_request is not None
    assert result.request_scope["enabled"] == seen_request.url.params["enabled"] == "true"
    assert result.request_scope["optional"] == seen_request.url.params["optional"] == ""
    assert result.request_scope["count"] == seen_request.url.params["count"] == "2"
    assert "serviceKey" not in result.request_scope


def test_query_parameter_container_values_are_rejected_before_transport() -> None:
    transport_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return httpx.Response(200, json={"ok": True}, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(service_key=SERVICE_KEY, http_client=http_client)
        with pytest.raises(CollectionError, match="query parameter"):
            client.request(
                "searchKeyword2",
                {"keyword": ["경주"]},  # type: ignore[dict-item]
                explicit_opt_in=True,
            )

    assert transport_calls == 0


def test_offline_guard_runs_before_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    transport_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        raise AssertionError("transport must not run while CI blocks live collection")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = OdiiClient(
            service_key=SERVICE_KEY,
            http_client=http_client,
            clock=lambda: FIXED_NOW,
        )
        with pytest.raises(LiveCollectionRefused, match="ci"):
            client.request(
                "storyBasedList",
                {"tid": "2", "tlid": "5"},
                explicit_opt_in=True,
            )

    assert transport_calls == 0


def test_odii_uses_only_official_api_and_preserves_missing_metadata() -> None:
    seen_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_request
        seen_request = request
        return httpx.Response(
            200,
            json={"response": {"body": {"items": {"item": []}}}},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        result = OdiiClient(
            service_key=SERVICE_KEY,
            http_client=http_client,
            clock=lambda: FIXED_NOW,
        ).request(
            "storyBasedList",
            {"tid": "2", "tlid": "5"},
            explicit_opt_in=True,
        )

    assert seen_request is not None
    assert str(seen_request.url).startswith("https://apis.data.go.kr/B551011/Odii/")
    assert "odii.kr/smarttour_web" not in str(seen_request.url)
    assert seen_request.url.params["langCode"] == "ko"
    assert result.provider == "ODII"
    assert result.endpoint == "Odii/storyBasedList"
    assert result.modifiedtime is None
    assert result.rights == ()


def test_snapshot_writer_is_append_only_and_secret_free(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"response": {"body": {"items": {"item": []}}}},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        collected = OdiiClient(
            service_key=SERVICE_KEY,
            http_client=http_client,
            clock=lambda: FIXED_NOW,
        ).request(
            "storyBasedList",
            {"tid": "2", "tlid": "5"},
            explicit_opt_in=True,
        )

    path = write_snapshot(collected, tmp_path)
    stored = path.read_bytes()
    assert path.name == f"ODII-storyBasedList-{collected.raw_response_sha256}.json"
    assert stored.endswith(b"\n")
    assert SERVICE_KEY.encode() not in stored
    assert json.loads(stored)["raw_response_sha256"] == collected.raw_response_sha256

    with pytest.raises(FileExistsError):
        write_snapshot(collected, tmp_path)
