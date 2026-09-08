"""Wave 0 controlled-RED contracts for the Phase 6 photo provider boundary.

Every test lazily imports the absent Phase 6 owners (``itda.photo.provider``,
``itda.photo.contracts``) so the module fails only on the missing
implementation. The live seam must stay inert: credential resolution, client
construction, DNS, INET sockets, and send attempts are counted and must remain
exactly zero. Isolation is expressed with generic forbidden-field and
path-root predicates; no sealed evaluation artifact is opened or enumerated.
"""

from __future__ import annotations

import hashlib
import inspect
import socket as socket_module
from pathlib import Path
from typing import Any

import httpx
import pytest

EXPECTED_GATE_ORDER = (
    "authentication_ownership",
    "consent",
    "offline_guard",
    "phase_authority_unavailable",
    "durable_prepared_marker",
    "credential_resolution",
    "client_construction",
    "send_boundary",
)
JOB_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0" * 2
PUBLIC_RUBRIC_KO = "사진에서 나타나는 여행 선호를 공개 기준으로 분석합니다"
SANITIZED_PNG_BYTES = b"\x89PNG\r\n\x1a\nitda-sanitized-analysis-bytes"
CANARY = "itda-phase6-redaction-canary-93f4c1"
CREDENTIAL_CANARY_ENV = "ITDA_PHASE6_PROVIDER_CREDENTIAL_CANARY"

_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        # ranking / tie-break authority
        "rank",
        "ranking",
        "ranking_score",
        "ranking_order",
        "placement",
        "position_index",
        "tie_break",
        "tiebreak",
        "tie_breaker",
        # recommendation authority
        "recommendation",
        "recommendations",
        "recommendation_score",
        "recommendation_copy",
        "recommended",
        "copy",
        # release / publication authority
        "release",
        "release_authority",
        "publication",
        "publishability",
        "publishable",
        "catalog_eligible",
        "eligibility",
        "eligible",
        "admission",
        "admission_authority",
        # internal score authority
        "score",
        "scores",
        "axis_score",
        "axis_scores",
        "fused_score",
        "fused_scores",
        "internal_score",
        "score_milli",
        "confidence",
        # internal label authority
        "label",
        "labels",
        "display_label",
        "display_labels",
        "internal_label",
        # path / filename categories
        "path",
        "paths",
        "file_path",
        "image_path",
        "private_path",
        "filename",
        "filenames",
        "original_filename",
        "basename",
        # secret categories
        "secret",
        "secrets",
        "api_key",
        "token",
        "authorization",
        "credential",
        "credentials",
        "password",
        # sealed-evaluation categories (generic tokens only, never artifacts)
        "blind",
        "blind_membership",
        "blind_label",
        "blind_payload",
        "blind_identity",
    }
)


def _provider_package():
    import itda.photo.provider as provider_package

    return provider_package


def _live_module():
    import itda.photo.provider.live as live_module

    return live_module


def _photo_contracts():
    import itda.photo.contracts as photo_contracts

    return photo_contracts


@pytest.fixture(autouse=True)
def _phase6_provider_capability_spies(monkeypatch: pytest.MonkeyPatch):
    """Count every DNS, INET-socket, client-construction, and send attempt.

    The Phase 6 provider boundary must keep every capability counter at
    exactly zero, including the synthetic adapter (no I/O at all). The
    credential canary environment value must never surface anywhere.
    """

    counters = {"dns": 0, "inet_socket": 0, "client_constructed": 0, "send": 0}

    current_getaddrinfo = socket_module.getaddrinfo
    current_gethostbyname = socket_module.gethostbyname
    current_gethostbyname_ex = socket_module.gethostbyname_ex

    def counting_getaddrinfo(*args: object, **kwargs: object) -> object:
        counters["dns"] += 1
        return current_getaddrinfo(*args, **kwargs)  # type: ignore[arg-type]

    def counting_gethostbyname(*args: object, **kwargs: object) -> object:
        counters["dns"] += 1
        return current_gethostbyname(*args, **kwargs)  # type: ignore[arg-type]

    def counting_gethostbyname_ex(*args: object, **kwargs: object) -> object:
        counters["dns"] += 1
        return current_gethostbyname_ex(*args, **kwargs)  # type: ignore[arg-type]

    real_socket = socket_module.socket

    def counting_socket(*args: object, **kwargs: object) -> object:
        family = args[0] if args else kwargs.get("family", socket_module.AF_INET)
        if family in (socket_module.AF_INET, socket_module.AF_INET6):
            counters["inet_socket"] += 1
        return real_socket(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(socket_module, "getaddrinfo", counting_getaddrinfo)
    monkeypatch.setattr(socket_module, "gethostbyname", counting_gethostbyname)
    monkeypatch.setattr(socket_module, "gethostbyname_ex", counting_gethostbyname_ex)
    monkeypatch.setattr(socket_module, "socket", counting_socket)

    async_client_init = httpx.AsyncClient.__init__
    sync_client_init = httpx.Client.__init__
    async_client_send = httpx.AsyncClient.send
    sync_client_send = httpx.Client.send

    def counting_async_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> object:
        counters["client_constructed"] += 1
        return async_client_init(self, *args, **kwargs)  # type: ignore[arg-type]

    def counting_sync_init(self: httpx.Client, *args: object, **kwargs: object) -> object:
        counters["client_constructed"] += 1
        return sync_client_init(self, *args, **kwargs)  # type: ignore[arg-type]

    async def counting_async_send(
        self: httpx.AsyncClient, *args: object, **kwargs: object
    ) -> object:
        counters["send"] += 1
        return await async_client_send(self, *args, **kwargs)  # type: ignore[arg-type]

    def counting_sync_send(self: httpx.Client, *args: object, **kwargs: object) -> object:
        counters["send"] += 1
        return sync_client_send(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx.AsyncClient, "__init__", counting_async_init)
    monkeypatch.setattr(httpx.Client, "__init__", counting_sync_init)
    monkeypatch.setattr(httpx.AsyncClient, "send", counting_async_send)
    monkeypatch.setattr(httpx.Client, "send", counting_sync_send)
    monkeypatch.setenv(CREDENTIAL_CANARY_ENV, CANARY)

    yield

    assert counters == {
        "dns": 0,
        "inet_socket": 0,
        "client_constructed": 0,
        "send": 0,
    }, f"provider capability spies must remain zero: {counters}"


def _forbidden_key_variants() -> tuple[tuple[str, str], ...]:
    """Case-varied probes for every generic forbidden-key category."""

    probes: list[tuple[str, str]] = []
    for key in sorted(_FORBIDDEN_KEYS):
        probes.append((key, key))
        probes.append((key.upper(), key))
        probes.append((key.title(), key))
    return tuple(probes)


def _attack_payload(base: dict[str, Any], forbidden_key: str) -> dict[str, Any]:
    """Inject one forbidden key at nested depth (list-wrapped, dict-nested)."""

    attacked = {
        **base,
        "candidates": [
            {
                **base["candidates"][0],
                "metadata": [{"nested": {forbidden_key: 1}}],
            }
        ],
        forbidden_key: {"nested": [forbidden_key]},
    }
    return attacked


def _walk_mapping(value: object) -> list[tuple[str, object]]:
    items: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            items.append((str(key), nested))
            items.extend(_walk_mapping(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            items.extend(_walk_mapping(nested))
    return items


def _assert_no_forbidden_fields(dump: object) -> None:
    for key, _value in _walk_mapping(dump):
        assert key.casefold() not in _FORBIDDEN_KEYS, f"forbidden key leaked: {key}"


def _assert_no_path_escaping_values(dump: object) -> None:
    for _key, value in _walk_mapping(dump):
        if not isinstance(value, str):
            continue
        assert not value.startswith("/"), f"absolute path value leaked: {value!r}"
        assert ".." not in value, f"path traversal value leaked: {value!r}"
        assert "\\" not in value, f"backslash path separator leaked: {value!r}"
        assert "/artifacts/" not in value, f"restricted root value leaked: {value!r}"


def _sealed_candidate_set(
    contracts_module: object,
    *,
    payload_sha256: str,
    candidate_count: int = 1,
) -> tuple[dict[str, Any], str]:
    """Build a sealed valid candidate-set payload plus one candidate id."""

    candidates = [
        {
            "candidate_id": hashlib.sha256(f"{JOB_ID}:{index}".encode()).hexdigest(),
            "trait_id": "M5",
            "text_ko": "조용한 산책로",
        }
        for index in range(1, candidate_count + 1)
    ]
    payload: dict[str, Any] = {
        "schema_version": "photo-trait-candidates.v1",
        "job_id": JOB_ID,
        "payload_sha256": payload_sha256,
        "candidates": candidates,
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    payload["candidate_set_sha256"] = contracts_module.canonical_sha256_for_tests(payload)  # type: ignore[attr-defined]
    return payload, candidates[0]["candidate_id"]


def test_inert_seam_surface_and_gate_order() -> None:
    provider_package = _provider_package()

    assert provider_package.PHOTO_PROVIDER_GATE_ORDER == EXPECTED_GATE_ORDER
    authority_index = EXPECTED_GATE_ORDER.index("phase_authority_unavailable")
    assert EXPECTED_GATE_ORDER.index("authentication_ownership") == 0
    assert EXPECTED_GATE_ORDER.index("consent") == 1
    assert EXPECTED_GATE_ORDER.index("offline_guard") < authority_index
    assert EXPECTED_GATE_ORDER.index("durable_prepared_marker") < EXPECTED_GATE_ORDER.index(
        "credential_resolution"
    )
    assert EXPECTED_GATE_ORDER.index("credential_resolution") < EXPECTED_GATE_ORDER.index(
        "client_construction"
    )
    assert EXPECTED_GATE_ORDER.index("client_construction") < EXPECTED_GATE_ORDER.index(
        "send_boundary"
    )

    assert issubclass(provider_package.PhotoLiveAnalysisUnavailable, RuntimeError)
    assert hasattr(provider_package.SyntheticPhotoAnalysisProvider, "analyze")
    assert hasattr(provider_package.LivePhotoAnalysisProvider, "analyze")


def test_live_adapter_fails_closed_in_every_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_package = _provider_package()

    environments = (
        {"CI": "1"},
        {"ITDA_NO_NETWORK": "1"},
        {},
    )
    for environment in environments:
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        adapter = provider_package.LivePhotoAnalysisProvider()
        with pytest.raises(RuntimeError) as excinfo:
            adapter.analyze(
                image_png=SANITIZED_PNG_BYTES,
                rubric_ko=PUBLIC_RUBRIC_KO,
                job_id=JOB_ID,
            )
        assert type(excinfo.value).__name__ in {
            "LiveCollectionRefused",
            "PhotoLiveAnalysisUnavailable",
        }


def test_live_gate_order_runs_offline_guard_before_unavailable_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import itda.pipeline.offline_guard as offline_guard_module

    live_module = _live_module()
    provider_package = _provider_package()
    calls: list[str] = []

    real_guard = offline_guard_module.require_live_collection_allowed
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    def spy_guard(**kwargs: object) -> None:
        calls.append("offline_guard")
        real_guard(**kwargs)  # type: ignore[arg-type]

    def spy_authority() -> None:
        calls.append("phase_authority_unavailable")
        raise provider_package.PhotoLiveAnalysisUnavailable("PHOTO_ANALYSIS_UNAVAILABLE")

    monkeypatch.setattr(live_module, "require_live_collection_allowed", spy_guard)
    monkeypatch.setattr(live_module, "require_unavailable_phase6_authority", spy_authority)

    adapter = provider_package.LivePhotoAnalysisProvider()
    with pytest.raises(provider_package.PhotoLiveAnalysisUnavailable):
        adapter.analyze(
            image_png=SANITIZED_PNG_BYTES,
            rubric_ko=PUBLIC_RUBRIC_KO,
            job_id=JOB_ID,
        )
    assert calls == ["offline_guard", "phase_authority_unavailable"]

    calls.clear()
    monkeypatch.setenv("ITDA_NO_NETWORK", "1")
    from itda.pipeline.offline_guard import LiveCollectionRefused

    with pytest.raises(LiveCollectionRefused):
        adapter.analyze(
            image_png=SANITIZED_PNG_BYTES,
            rubric_ko=PUBLIC_RUBRIC_KO,
            job_id=JOB_ID,
        )
    assert calls == ["offline_guard"]


def test_live_module_has_no_transport_or_credential_capability() -> None:
    live_module = _live_module()

    source = Path(inspect.getsourcefile(live_module) or "").read_text(encoding="utf-8")
    assert "require_live_collection_allowed" in source
    assert "require_unavailable_phase6_authority" in source
    assert "PhotoLiveAnalysisUnavailable" in source
    for forbidden_fragment in (
        "httpx",
        "urllib",
        "asyncio.open_connection",
        "socket.socket",
        "getaddrinfo",
        "create_connection",
        "os.environ",
        "os.getenv",
        "https://",
        "http://",
        "OPENROUTER_API_KEY",
        "ZHIPUAI_API_KEY",
        "NVIDIA_KEY",
        "BIGMODEL_API_KEY",
        CREDENTIAL_CANARY_ENV,
    ):
        assert forbidden_fragment not in source, forbidden_fragment


def test_synthetic_analysis_is_deterministic_and_capability_free() -> None:
    from itda.domain.canonical import canonical_json_bytes

    provider_package = _provider_package()
    synthetic = provider_package.SyntheticPhotoAnalysisProvider()

    first = synthetic.analyze(
        image_png=SANITIZED_PNG_BYTES,
        rubric_ko=PUBLIC_RUBRIC_KO,
        job_id=JOB_ID,
    )
    second = synthetic.analyze(
        image_png=SANITIZED_PNG_BYTES,
        rubric_ko=PUBLIC_RUBRIC_KO,
        job_id=JOB_ID,
    )
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )

    contracts_module = _photo_contracts()
    assert isinstance(synthetic, provider_package.PhotoAnalysisProvider)
    assert first.job_id == JOB_ID
    assert first.authority_scope == "CANDIDATE_EVIDENCE_ONLY"
    assert isinstance(first, contracts_module.PhotoTraitCandidateSet), (
        "synthetic output must validate as the strict candidate set contract"
    )


def test_synthetic_output_under_generic_forbidden_field_and_path_scan() -> None:
    provider_package = _provider_package()
    synthetic = provider_package.SyntheticPhotoAnalysisProvider()

    result = synthetic.analyze(
        image_png=SANITIZED_PNG_BYTES,
        rubric_ko=PUBLIC_RUBRIC_KO,
        job_id=JOB_ID,
    )
    dump = result.model_dump(mode="json")
    _assert_no_forbidden_fields(dump)
    _assert_no_path_escaping_values(dump)
    assert CANARY not in str(dump)


def test_synthetic_binds_sanitized_byte_identity() -> None:
    provider_package = _provider_package()
    synthetic = provider_package.SyntheticPhotoAnalysisProvider()

    result = synthetic.analyze(
        image_png=SANITIZED_PNG_BYTES,
        rubric_ko=PUBLIC_RUBRIC_KO,
        job_id=JOB_ID,
    )
    assert result.payload_sha256 == hashlib.sha256(SANITIZED_PNG_BYTES).hexdigest()

    tampered = SANITIZED_PNG_BYTES[:-1] + bytes([SANITIZED_PNG_BYTES[-1] ^ 0x01])
    tampered_result = synthetic.analyze(
        image_png=tampered,
        rubric_ko=PUBLIC_RUBRIC_KO,
        job_id=JOB_ID,
    )
    assert tampered_result.payload_sha256 == hashlib.sha256(tampered).hexdigest()
    assert tampered_result.payload_sha256 != result.payload_sha256


def test_synthetic_rejects_unsanitized_or_unbounded_input() -> None:
    provider_package = _provider_package()
    synthetic = provider_package.SyntheticPhotoAnalysisProvider()

    hostile_inputs = (
        {"image_png": b"", "rubric_ko": PUBLIC_RUBRIC_KO, "job_id": JOB_ID},
        {"image_png": "not-bytes", "rubric_ko": PUBLIC_RUBRIC_KO, "job_id": JOB_ID},
        {"image_png": None, "rubric_ko": PUBLIC_RUBRIC_KO, "job_id": JOB_ID},
        {"image_png": SANITIZED_PNG_BYTES, "rubric_ko": "", "job_id": JOB_ID},
        {"image_png": SANITIZED_PNG_BYTES, "rubric_ko": "english only", "job_id": JOB_ID},
        {"image_png": SANITIZED_PNG_BYTES, "rubric_ko": PUBLIC_RUBRIC_KO, "job_id": ""},
    )
    for case in hostile_inputs:
        with pytest.raises((TypeError, ValueError)):
            synthetic.analyze(**case)  # type: ignore[arg-type]


def test_redaction_canaries_never_reflect_in_outputs_or_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_package = _provider_package()
    synthetic = provider_package.SyntheticPhotoAnalysisProvider()

    canary_bytes = b"prefix:" + CANARY.encode() + b":suffix"
    result = synthetic.analyze(
        image_png=canary_bytes,
        rubric_ko=PUBLIC_RUBRIC_KO,
        job_id=JOB_ID,
    )
    assert CANARY not in repr(result)
    assert CANARY not in str(result.model_dump(mode="json"))

    with pytest.raises((TypeError, ValueError)) as excinfo:
        synthetic.analyze(image_png=canary_bytes, rubric_ko="", job_id=JOB_ID)
    assert CANARY not in str(excinfo.value)
    assert CANARY not in repr(excinfo.value)

    live = provider_package.LivePhotoAnalysisProvider()
    with pytest.raises(RuntimeError) as live_error:
        live.analyze(
            image_png=canary_bytes,
            rubric_ko=PUBLIC_RUBRIC_KO,
            job_id=JOB_ID,
        )
    assert CANARY not in str(live_error.value)
    assert CANARY not in repr(live_error.value)


def test_collection_time_network_deny_remains_armed() -> None:
    _provider_package()

    assert getattr(socket_module, "_itda_security_deny_installed", False) is True


def test_f01_synthetic_rejects_shortened_32_hex_job_identity() -> None:
    """F-01: the provider seam accepts only the canonical 64-hex identity."""

    provider_package = _provider_package()
    synthetic = provider_package.SyntheticPhotoAnalysisProvider()
    for shortened in ("0f1e2d3c4b5a69788796a5b4c3d2e1f0", "0" * 63, "0" * 65):
        with pytest.raises((TypeError, ValueError)):
            synthetic.analyze(
                image_png=SANITIZED_PNG_BYTES,
                rubric_ko=PUBLIC_RUBRIC_KO,
                job_id=shortened,
            )
