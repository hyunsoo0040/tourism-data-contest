from __future__ import annotations

import asyncio
import hashlib
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

SOURCE_ROOT = Path("artifacts/restricted/catalog/phase5-demo-profile-materialization")


def _bundles():
    from itda.contracts.demo_profile_materialization import DemoSourceBundle

    return tuple(
        DemoSourceBundle.model_validate(item)
        for item in json.loads((SOURCE_ROOT / "source-bundles.json").read_bytes())
    )


def _profile(evidence_ids: list[str], *, confidence: int = 78) -> dict[str, object]:
    keys = (
        "H",
        "E",
        "R",
        *(f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)),
        *(f"M{index}" for index in range(1, 7)),
    )
    return {
        "axis_scores": {"H": 76, "E": 61, "R": 84},
        "subattributes": {
            **{f"H{index}": 3 for index in range(1, 5)},
            **{f"I{index}": 2 for index in range(1, 5)},
            **{f"R{index}": 4 for index in range(1, 5)},
        },
        "mismatch_traits": {f"M{index}": index * 10 for index in range(1, 7)},
        "evidence_justifications": {key: [evidence_ids[0]] for key in keys},
        "evidence_ids": evidence_ids,
        "confidence": confidence,
        "publishable": True,
    }


def _public_artifact(
    request,
    *,
    checkout: str = "a" * 64,
    commit: str = "b" * 40,
) -> dict[str, object]:
    from itda.contracts.phase5_nvidia_recovery import (
        MINIMAL_PROBE_CONFIG_SHA256,
        MINIMAL_PROBE_PROFILE_SCHEMA_SHA256,
        MINIMAL_PROBE_PROMPT_SHA256,
        MINIMAL_PROBE_PROMPT_VERSION,
    )

    preimage = {
        "schema_version": "itda.phase5-nvidia-minimal-probe-approval-request.v1",
        "authority_id": request.authority_id,
        "provider_lane": request.invocation.provider_lane,
        "endpoint": request.invocation.endpoint,
        "model": request.invocation.model,
        "prompt_version": MINIMAL_PROBE_PROMPT_VERSION,
        "prompt_sha256": MINIMAL_PROBE_PROMPT_SHA256,
        "profile_schema_sha256": MINIMAL_PROBE_PROFILE_SCHEMA_SHA256,
        "config_sha256": MINIMAL_PROBE_CONFIG_SHA256,
        "source_inventory_sha256": request.source_inventory_sha256,
        "source_bundle_sha256": request.source_bundle_sha256,
        "evidence_inventory_sha256": request.evidence_inventory_sha256,
        "place_id": request.place_id,
        "request_sha256": request.request_sha256,
        "request_body_sha256": request.request_body_sha256,
        "checkout_manifest_sha256": checkout,
        "checkout_commit_sha256": commit,
        "attempt_deadline_seconds": 300,
        "max_response_bytes": 4_194_304,
        "sentinel_payload_bytes": 65_536,
        "max_attempts": 1,
        "concurrency": 1,
        "cumulative_exposure_micro_usd": 500_000,
        "reservation_micro_usd": 500_000,
        "secret_file_mode": "0600",
        "secret_file_format": "UTF8_SINGLE_NVIDIA_KEY_RECORD",
        "receipt_emitted": False,
        "cohort_capability": False,
        "candidate_capability": False,
        "smoke_capability": False,
        "activation_capability": False,
        "release_capability": False,
        "secret_read": False,
        "client_constructed": False,
        "network_attempted": False,
        "lifecycle_mutated": False,
    }
    approval = canonical_sha256(preimage)
    artifact = {**preimage, "approval_payload_sha256": approval}
    return {**artifact, "request_artifact_sha256": canonical_sha256(artifact)}


def _artifact_model(request, *, artifact: dict[str, object] | None = None):
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbePublicArtifact

    return NvidiaMinimalProbePublicArtifact.model_validate(
        artifact if artifact is not None else _public_artifact(request)
    )


def _response(bundle, *, confidence: int = 78, status: int = 200) -> httpx.Response:
    from itda.contracts.demo_profile_materialization import (
        NVIDIA_JSON_END_SENTINEL,
        NVIDIA_JSON_START_SENTINEL,
    )

    content = json.dumps(
        _profile([source.evidence_id for source in bundle.sources], confidence=confidence),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return httpx.Response(
        status,
        json={
            "model": "minimaxai/minimax-m3",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": (
                            f"{NVIDIA_JSON_START_SENTINEL}{content}{NVIDIA_JSON_END_SENTINEL}"
                        ),
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150,
            },
        },
    )


def test_minimal_probe_durable_approval_claim_and_no_replace_evidence(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeApprovalBinding,
        NvidiaMinimalProbeProtectedStateDescriptor,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    request = build_minimal_probe_request(_bundles()[0])
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    artifact = _public_artifact(request)
    approval = build_minimal_probe_approval_binding(
        request=request,
        artifact=artifact,
        protected_state_sha256=descriptor.protected_state_sha256,
        secret_identity_sha256="c" * 64,
        secret_content_fingerprint="d" * 64,
    )
    assert isinstance(approval, NvidiaMinimalProbeApprovalBinding)
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    assert state.install_approval(approval)["status"] == "APPROVED_UNCLAIMED"
    assert (
        state.preflight(expected_artifact=_artifact_model(request, artifact=artifact))[
            "claimed"
        ]
        is False
    )
    approval_path = Path(descriptor.approval_target)
    assert stat.S_IMODE(approval_path.stat().st_mode) == 0o600
    assert approval_path.stat().st_nlink == 1
    with pytest.raises(PermissionError, match="REPLACEMENT"):
        state.install_approval(approval.model_copy(update={"request_sha256": "b" * 64}))
    claim = state.claim_once(expected_artifact=_artifact_model(request))
    state.reserve_once(claim=claim, request=request)
    assert claim.authority_id == request.authority_id
    with pytest.raises(PermissionError, match="ALREADY_CLAIMED"):
        MinimalProbeDurableAuthorityState(descriptor=descriptor).claim_once(expected_artifact=_artifact_model(request))
    approval_path.write_bytes(approval_path.read_bytes())
    assert approval_path.stat().st_nlink == 1


def test_minimal_probe_durable_evidence_reopens_without_provider(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeProtectedStateDescriptor
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    approval = build_minimal_probe_approval_binding(
        request=request,
        artifact=_public_artifact(request),
        protected_state_sha256=descriptor.protected_state_sha256,
        secret_identity_sha256="c" * 64,
        secret_content_fingerprint="d" * 64,
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(approval)
    claim = state.claim_once(expected_artifact=_artifact_model(request))
    state.reserve_once(claim=claim, request=request)
    events: list[str] = []

    def factory(**kwargs: object) -> httpx.AsyncClient:
        events.append("client")
        def handler(request: httpx.Request) -> httpx.Response:
            events.append("socket")
            return _response(bundle)

        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            **kwargs,
        )

    events.append("reservation")
    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: events.append("secret") or "probe-secret",
            client_factory=factory,
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=lambda _result: None,
        )
    )
    state.record_outcome(result)
    state.verify_outcome(request=request, terminal=result.terminal)
    assert events == ["reservation", "secret", "client", "socket"]
    assert stat.S_IMODE(Path(descriptor.ledger_target).stat().st_mode) == 0o600
    assert (
        stat.S_IMODE(Path(descriptor.journal_target, "terminal.json").stat().st_mode)
        == 0o600
    )
    assert (
        stat.S_IMODE(Path(descriptor.raw_evidence_target, "response.bin").stat().st_mode)
        == 0o600
    )


def test_minimal_probe_secret_reader_enforces_exact_private_single_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    secret_dir = tmp_path / ".secrets"
    secret_dir.mkdir(mode=0o700)
    secret = secret_dir / "itda-api.env"
    monkeypatch.setattr(command, "SECRET_FILE", secret)
    secret.write_text("NVIDIA_KEY=test-only-secret\n", encoding="utf-8")
    secret.chmod(0o600)
    identity, fingerprint = command._minimal_probe_secret_binding(secret)
    assert (
        command._read_minimal_probe_secret(
            secret,
            expected_identity_sha256=identity,
            expected_content_fingerprint=fingerprint,
        )
        == "test-only-secret"
    )

    link = secret_dir / "link.env"
    link.symlink_to(secret)
    with pytest.raises(PermissionError, match="identity|forbidden"):
        command._minimal_probe_secret_identity(link)

    alias = secret_dir / "alias.env"
    alias.hardlink_to(secret)
    with pytest.raises(PermissionError, match="identity|forbidden"):
        command._minimal_probe_secret_identity(secret)

    invalid_contents = (
        "NVIDIA_KEY=x\nOTHER=y\n",
        "# comment\nNVIDIA_KEY=x\n",
        "NVIDIA_KEY=x\n\n",
    )
    for content in invalid_contents:
        candidate = secret_dir / f"{len(content)}.env"
        candidate.write_text(content, encoding="utf-8")
        candidate.chmod(0o600)
        monkeypatch.setattr(command, "SECRET_FILE", candidate)
        with pytest.raises(PermissionError, match="exactly one|record"):
            command._minimal_probe_secret_identity(candidate)


def test_minimal_probe_live_cli_stays_before_secret_in_offline_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli.materialize_phase5_demo_profiles import main

    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.setenv("ITDA_PROVIDER_NETWORK", "1")
    assert (
        main(
            [
                "nvidia-minimal-probe-live",
                "--request",
                "artifacts/public/phase5/nvidia-minimal-probe-request.json",
                "--protected-state-root",
                "artifacts/restricted/catalog/phase5-nvidia-minimal-probe",
                "--secret-env-file",
                ".secrets/itda-api.env",
                "--terminal-output",
                "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json",
                "--json",
            ]
        )
        == 2
    )


def test_minimal_probe_request_contract_is_exact_and_omits_unsupported_keys() -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        MINIMAL_PROBE_AUTHORITY_ID,
        MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD,
        MINIMAL_PROBE_MAX_RESPONSE_BYTES,
        MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES,
        NvidiaInvocationContract,
    )
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    payload = json.loads(request.request_body)
    assert request.authority_id == MINIMAL_PROBE_AUTHORITY_ID
    assert request.cumulative_exposure_micro_usd == 500_000
    assert MINIMAL_PROBE_CUMULATIVE_EXPOSURE_MICRO_USD == 500_000
    assert request.max_response_bytes == MINIMAL_PROBE_MAX_RESPONSE_BYTES == 4 * 1024 * 1024
    assert request.sentinel_payload_bytes == MINIMAL_PROBE_SENTINEL_PAYLOAD_BYTES == 65_536
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
    assert payload["temperature"] == 0
    assert payload["max_tokens"] == 8192
    assert payload["stream"] is False
    assert payload["seed"] == 0
    assert payload["chat_template_kwargs"] == {"thinking_mode": "disabled"}
    assert "top_p" not in payload
    assert "response_format" not in payload
    assert "tools" not in payload
    assert "tool_choice" not in payload
    assert "nvext" not in payload
    assert len(payload["messages"]) == 2
    assert payload["messages"][0]["role"] == "system"
    user = json.loads(payload["messages"][1]["content"])
    assert user["place_id"] == bundle.place_id
    assert user["evidence"]
    assert "instruction" in user
    assert "untrusted data" in payload["messages"][0]["content"]
    assert (
        NvidiaInvocationContract.model_validate(request.invocation.model_dump(mode="json"))
        == request.invocation
    )


def test_minimal_probe_commands_use_fixed_four_file_authority_without_canonical36(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.pipeline.phase5_nvidia_recovery import (
        build_minimal_probe_request,
        load_minimal_probe_bundle,
        preflight_nvidia_invocation,
    )

    def reject_historical(_path: Path):
        raise AssertionError("historical canonical-36 loader must not run")

    monkeypatch.setattr(command, "_load_live_source_bundles", reject_historical)
    bundle = load_minimal_probe_bundle(SOURCE_ROOT)
    request = build_minimal_probe_request(bundle)
    preflight = preflight_nvidia_invocation(
        source_root=SOURCE_ROOT,
        checkout_manifest_sha256="a" * 64,
    )
    assert request.request_sha256 == preflight.request.request_sha256
    source = Path(command.__file__).read_text(encoding="utf-8")
    start = source.index('if args.command == "nvidia-minimal-probe-install-approval"')
    minimal_section = source[start:]
    assert "_load_live_source_bundles(FIXED_LIVE_SOURCE_BUNDLES)" not in minimal_section
    assert minimal_section.count("load_minimal_probe_bundle()") >= 4


def test_minimal_probe_install_provider_free_with_fixed_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbePublicArtifact
    from itda.pipeline.phase5_nvidia_recovery import (
        build_minimal_probe_request,
        load_minimal_probe_bundle,
    )

    bundle = load_minimal_probe_bundle(SOURCE_ROOT)
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    request_path = tmp_path / "request.json"
    request_path.write_bytes(canonical_json_bytes(artifact.model_dump(mode="json")))
    secret_dir = tmp_path / ".secrets"
    secret_dir.mkdir(mode=0o700)
    secret = secret_dir / "itda-api.env"
    secret.write_text("NVIDIA_KEY=synthetic-test-only\n")
    secret.chmod(0o600)
    protected = tmp_path / "protected"
    monkeypatch.setattr(command, "SECRET_FILE", secret)
    monkeypatch.setattr(command, "_require_minimal_probe_committed_clean_source", lambda: None)
    monkeypatch.setattr(command, "_minimal_probe_request_output", lambda path: request_path)
    monkeypatch.setattr(command, "_minimal_probe_secret_file", lambda path: secret)
    monkeypatch.setattr(command, "_minimal_probe_protected_state_root", lambda path: protected)
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.checkout_manifest_sha256",
        lambda root: artifact.checkout_manifest_sha256,
    )
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.checkout_commit_sha256",
        lambda root: artifact.checkout_commit_sha256,
    )
    assert command.main(
        [
            "nvidia-minimal-probe-install-approval",
            "--request",
            str(request_path),
            "--protected-state-root",
            str(protected),
            "--secret-env-file",
            str(secret),
            "--approval-payload-sha256",
            artifact.approval_payload_sha256,
            "--json",
        ]
    ) == 0
    assert (protected / "approval.json").is_file()
    assert not (protected / "claim.json").exists()


def test_minimal_probe_preflight_rebuilds_source_and_request_digests_without_provider() -> None:
    from itda.pipeline.phase5_nvidia_recovery import preflight_nvidia_invocation

    result = preflight_nvidia_invocation(source_root=SOURCE_ROOT, checkout_manifest_sha256="a" * 64)
    assert result.secret_read is False
    assert result.client_constructed is False
    assert result.network_attempted is False
    assert result.lifecycle_mutated is False
    assert (
        result.source_inventory_sha256
        == "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
    )
    assert (
        result.request.request_body_sha256
        == hashlib.sha256(result.request.request_body).hexdigest()
    )


def test_minimal_probe_strict_response_accepts_confidence_without_release_threshold() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]
    for confidence in (0, 55, 100):
        result = execute_nvidia_minimal_probe_mock(
            bundle=bundle,
            response_handler=lambda request, value=confidence: _response(
                bundle, confidence=value
            ),
        )
        assert result.terminal.status == "POSITIVE"
        assert result.terminal.confidence == confidence
        assert result.terminal.release_eligible is False


def test_minimal_probe_rejects_malformed_response_and_secret_echo() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def malformed(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "minimaxai/minimax-m3", "choices": []})

    malformed_result = execute_nvidia_minimal_probe_mock(
        bundle=bundle, response_handler=malformed
    )
    assert malformed_result.terminal.status == "MALFORMED"
    assert malformed_result.terminal.reason == "PROBE_RESPONSE_INVALID"

    def echo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"error":"provider-free-test-secret"}')

    echo_result = execute_nvidia_minimal_probe_mock(bundle=bundle, response_handler=echo)
    assert echo_result.terminal.status == "MALFORMED"
    assert echo_result.terminal.reason == "PROBE_SECRET_ECHO"


def test_probe_terminal_production_verifier_rejects_forged_public_terminal() -> None:
    from itda.pipeline.phase5_nvidia_recovery import (
        classify_nvidia_probe_terminal,
        verify_nvidia_probe_terminal,
    )

    with pytest.raises(ValueError, match="durable verified outcome"):
        verify_nvidia_probe_terminal({"status": "DESIGNED_NEGATIVE"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="durable verified outcome"):
        classify_nvidia_probe_terminal({"status": "POSITIVE"})  # type: ignore[arg-type]


def test_probe_public_facts_have_no_cohort_or_release_capability() -> None:
    from itda.contracts.phase5_nvidia_recovery import minimal_probe_public_facts

    facts = minimal_probe_public_facts()
    assert {
        name: facts[f"{name}_capability"]
        for name in ("cohort", "candidate", "smoke", "activation", "release")
    } == {
        "cohort": False,
        "candidate": False,
        "smoke": False,
        "activation": False,
        "release": False,
    }


def test_minimal_probe_pre_socket_client_failure_releases_and_never_reaches_socket() -> None:
    from itda.pipeline.phase5_nvidia_recovery import (
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_request,
        synthetic_minimal_probe_claim,
    )

    bundle = _bundles()[0]
    events: list[str] = []
    request = build_minimal_probe_request(bundle)
    claim = synthetic_minimal_probe_claim(request)

    def factory(**_kwargs: object) -> httpx.AsyncClient:
        events.append("client")
        raise RuntimeError("constructor failed")

    with pytest.raises(ValueError, match="PROBE_CLIENT_CONSTRUCTION_FAILED"):
        asyncio.run(
            _execute_nvidia_minimal_probe_transport(
                bundle=bundle,
                credential_reader=lambda: events.append("secret") or "probe-secret",
                client_factory=factory,
                claim=claim,
                expected_request=request,
                dispatch_marker=lambda: None,
                terminal_sink=lambda _result: None,
            )
        )
    assert events == ["secret", "client"]


def test_minimal_probe_low_level_checksum_helper_is_private_and_digest_bound() -> None:
    from itda.pipeline.phase5_nvidia_recovery import (
        _attempted_result,
        _validate_nvidia_probe_terminal_checksum,
        build_minimal_probe_request,
        synthetic_minimal_probe_claim,
    )

    request = build_minimal_probe_request(_bundles()[0])
    result = _attempted_result(
        status="DESIGNED_NEGATIVE",
        reason="HTTP_404",
        request=request,
        claim=synthetic_minimal_probe_claim(request),
        raw_response=b"negative",
    )
    assert _validate_nvidia_probe_terminal_checksum(
        result.terminal,
        request=request,
        raw_response=b"negative",
    ).status == "DESIGNED_NEGATIVE"
    with pytest.raises(ValueError, match="raw response digest"):
        _validate_nvidia_probe_terminal_checksum(
            result.terminal,
            request=request,
            raw_response=b"different",
        )


def test_minimal_probe_classifier_requires_neutral_verification() -> None:
    from itda.pipeline.phase5_nvidia_recovery import classify_nvidia_probe_terminal

    with pytest.raises(ValueError, match="durable verified outcome"):
        classify_nvidia_probe_terminal({"status": "POSITIVE"})  # type: ignore[arg-type]


def test_minimal_probe_clean_source_guard_rejects_staged_unstaged_and_untracked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    monkeypatch.setattr(
        "itda.minimal_probe_bootstrap._validate_checkout",
        lambda root: (_ for _ in ()).throw(
            PermissionError("MINIMAL_PROBE_BOOTSTRAP_TRACKED_DIRTY")
        ),
    )
    with pytest.raises(RuntimeError, match="not committed and clean"):
        command._require_minimal_probe_committed_clean_source()


def test_minimal_probe_command_names_are_provider_free_until_explicit_live_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    monkeypatch.setattr(command, "_require_minimal_probe_committed_clean_source", lambda: None)

    assert (
        command.main(
            ["nvidia-minimal-probe-classify", "--terminal", "missing.json", "--value-only"]
        )
        == 2
    )
    assert (
        command.main(["nvidia-minimal-probe-verify", "--terminal", "missing.json", "--json"])
        == 2
    )
    assert (
        command.main(
            [
                "nvidia-recovery-preflight",
                "--request-output",
                "artifacts/public/phase5/nvidia-minimal-probe-request.json",
                "--json",
            ]
        )
        in {0, 2}
    )


def test_minimal_probe_low_confidence_is_invocation_positive_not_release_eligible() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: _response(bundle, confidence=55)),
            **kwargs,
        )

    result = execute_nvidia_minimal_probe_mock(
        bundle=bundle,
        response_handler=lambda request: _response(bundle, confidence=55),
    )
    assert result.terminal.status == "POSITIVE"
    assert result.terminal.confidence == 55
    assert result.terminal.release_eligible is False
    assert result.terminal.committed_exposure_micro_usd == 500_000


def test_minimal_probe_provider_response_must_match_strict_profile_schema() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def invalid(_request: httpx.Request) -> httpx.Response:
        response = _response(bundle)
        payload = response.json()
        content_text = payload["choices"][0]["message"]["content"]
        start = content_text.index("{")
        end = content_text.rindex("}") + 1
        content = json.loads(content_text[start:end])
        content["unexpected"] = True
        from itda.contracts.demo_profile_materialization import (
            NVIDIA_JSON_END_SENTINEL,
            NVIDIA_JSON_START_SENTINEL,
        )

        payload["choices"][0]["message"]["content"] = (
            f"{NVIDIA_JSON_START_SENTINEL}{json.dumps(content)}{NVIDIA_JSON_END_SENTINEL}"
        )
        return httpx.Response(200, json=payload)

    result = execute_nvidia_minimal_probe_mock(bundle=bundle, response_handler=invalid)
    assert result.terminal.status == "MALFORMED"
    assert result.terminal.reason == "PROBE_RESPONSE_INVALID"


def test_minimal_probe_request_excludes_cohort_release_and_historical_fields() -> None:
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    dumped = build_minimal_probe_request(_bundles()[0]).public_payload()
    serialized = json.dumps(dumped, sort_keys=True)
    assert "fresh-d24" not in serialized
    assert "fresh24" not in serialized
    assert "cohort" in serialized
    assert "release" in serialized
    assert "attempts" in serialized
    assert "ledger" not in serialized
    assert "raw" not in serialized


def test_minimal_probe_request_rejects_path_and_secret_fields() -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeRequest
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    request = build_minimal_probe_request(_bundles()[0]).model_dump(mode="json")
    with pytest.raises(ValueError, match="protected path"):
        NvidiaMinimalProbeRequest.model_validate({**request, "secret_path": "/tmp/key"})


def test_minimal_probe_terminal_negative_classes_remain_non_positive() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]
    for status in (401, 403, 404, 429, 503):
        terminal = execute_nvidia_minimal_probe_mock(
            bundle=bundle,
            response_handler=lambda request, code=status: httpx.Response(code, content=b"negative"),
        ).terminal
        assert terminal.status == "DESIGNED_NEGATIVE"
        assert terminal.reason == f"HTTP_{status}"


def test_minimal_probe_positive_assertion_requires_opaque_verified_outcome() -> None:
    from itda.pipeline.phase5_nvidia_recovery import assert_nvidia_probe_positive

    with pytest.raises(ValueError, match="durable verified outcome"):
        assert_nvidia_probe_positive({"status": "POSITIVE"})  # type: ignore[arg-type]


def test_minimal_probe_private_transport_order_is_secret_client_socket() -> None:
    from itda.pipeline.phase5_nvidia_recovery import (
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_request,
        synthetic_minimal_probe_claim,
    )

    events: list[str] = []
    bundle = _bundles()[0]

    def handler(request: httpx.Request) -> httpx.Response:
        events.append("socket")
        return _response(bundle)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        events.append("client")
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    request = build_minimal_probe_request(bundle)
    claim = synthetic_minimal_probe_claim(request)
    asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: events.append("secret") or "probe-secret",
            client_factory=factory,
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: None,
            terminal_sink=lambda _result: None,
        )
    )
    assert events == ["secret", "client", "socket"]


def test_minimal_probe_response_usage_must_be_complete_and_consistent() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def invalid(_request: httpx.Request) -> httpx.Response:
        response = _response(bundle)
        payload = response.json()
        payload["usage"]["total_tokens"] = 999
        return httpx.Response(200, json=payload)

    result = execute_nvidia_minimal_probe_mock(bundle=bundle, response_handler=invalid)
    assert result.terminal.status == "MALFORMED"
    assert result.terminal.reason == "PROBE_RESPONSE_INVALID"


def test_minimal_probe_digest_mismatch_fails_low_level_checksum() -> None:
    from itda.pipeline.phase5_nvidia_recovery import (
        _validate_nvidia_probe_terminal_checksum,
        execute_nvidia_minimal_probe_mock,
    )

    terminal = execute_nvidia_minimal_probe_mock(
        bundle=_bundles()[0],
        response_handler=lambda request: httpx.Response(503, content=b"negative"),
    ).terminal
    with pytest.raises(ValueError, match="digest"):
        _validate_nvidia_probe_terminal_checksum(
            terminal.model_copy(update={"terminal_sha256": "0" * 64})
        )


def test_minimal_probe_request_contains_only_one_message_pair_and_fixed_model() -> None:
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    request = build_minimal_probe_request(_bundles()[0])
    payload = json.loads(request.request_body)
    assert payload["model"] == "minimaxai/minimax-m3"
    assert [message["role"] for message in payload["messages"]] == ["system", "user"]


def test_minimal_probe_source_inventory_digest_is_fixed_authority() -> None:
    from itda.pipeline.phase5_nvidia_recovery import preflight_nvidia_invocation

    assert preflight_nvidia_invocation(
        source_root=SOURCE_ROOT, checkout_manifest_sha256="a" * 64
    ).source_inventory_sha256 == (
        "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
    )


def test_minimal_probe_request_digest_is_canonical_and_stable() -> None:
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    first = build_minimal_probe_request(_bundles()[0])
    second = build_minimal_probe_request(_bundles()[0])
    assert first.request_sha256 == second.request_sha256
    assert first.request_body == second.request_body


def test_minimal_probe_terminal_does_not_grant_activation() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]
    result = execute_nvidia_minimal_probe_mock(
        bundle=bundle,
        response_handler=lambda request: _response(bundle),
    )
    assert result.terminal.release_eligible is False


def test_minimal_probe_does_not_call_provider_in_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from itda.pipeline.phase5_nvidia_recovery import preflight_nvidia_invocation

    def deny_client(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("client")

    monkeypatch.setattr(httpx, "AsyncClient", deny_client)
    preflight_nvidia_invocation(source_root=SOURCE_ROOT, checkout_manifest_sha256="a" * 64)


def test_minimal_probe_terminal_rejects_release_capability_field() -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeTerminal

    with pytest.raises(ValueError, match="extra"):
        NvidiaMinimalProbeTerminal.model_validate({"status": "POSITIVE", "release": True})


def test_minimal_probe_request_rejects_alternate_endpoint_model() -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaInvocationContract

    with pytest.raises(ValueError):
        NvidiaInvocationContract(endpoint="https://example.invalid", model="other")


def test_minimal_probe_response_rejects_duplicate_sentinels() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def duplicate(request: httpx.Request) -> httpx.Response:
        response = _response(bundle)
        return httpx.Response(200, content=response.content + response.content)

    result = execute_nvidia_minimal_probe_mock(bundle=bundle, response_handler=duplicate)
    assert result.terminal.status == "MALFORMED"
    assert result.terminal.reason == "PROBE_RESPONSE_INVALID"


def test_minimal_probe_response_rejects_prose_outside_sentinels() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def prose(request: httpx.Request) -> httpx.Response:
        response = _response(bundle)
        payload = response.json()
        payload["choices"][0]["message"]["content"] = (
            "prose" + payload["choices"][0]["message"]["content"]
        )
        return httpx.Response(200, json=payload)

    result = execute_nvidia_minimal_probe_mock(bundle=bundle, response_handler=prose)
    assert result.terminal.status == "MALFORMED"
    assert result.terminal.reason == "PROBE_RESPONSE_INVALID"


def test_minimal_probe_response_rejects_unknown_evidence_ids() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def unknown(request: httpx.Request) -> httpx.Response:
        response = _response(bundle)
        payload = response.json()
        start = payload["choices"][0]["message"]["content"].find("{")
        end = payload["choices"][0]["message"]["content"].rfind("}") + 1
        content = json.loads(payload["choices"][0]["message"]["content"][start:end])
        content["evidence_ids"] = ["unknown"]
        payload["choices"][0]["message"]["content"] = (
            "<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"
            + json.dumps(content)
            + "<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"
        )
        return httpx.Response(200, json=payload)

    result = execute_nvidia_minimal_probe_mock(bundle=bundle, response_handler=unknown)
    assert result.terminal.status == "MALFORMED"
    assert result.terminal.reason == "PROBE_RESPONSE_INVALID"


def test_minimal_probe_terminal_rejects_missing_raw_digest() -> None:
    from itda.pipeline.phase5_nvidia_recovery import (
        _validate_nvidia_probe_terminal_checksum,
        execute_nvidia_minimal_probe_mock,
    )

    terminal = execute_nvidia_minimal_probe_mock(
        bundle=_bundles()[0],
        response_handler=lambda request: _response(_bundles()[0]),
    ).terminal
    fields = terminal.model_dump(mode="json", exclude={"terminal_sha256"})
    fields["raw_response_sha256"] = None
    with pytest.raises(ValueError, match="raw digest"):
        _validate_nvidia_probe_terminal_checksum(
            {**fields, "terminal_sha256": canonical_sha256(fields)}
        )


def test_minimal_probe_terminal_rejects_confidence_as_release_threshold() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]
    result = execute_nvidia_minimal_probe_mock(
        bundle=bundle,
        response_handler=lambda request: _response(bundle, confidence=0),
    )
    assert result.terminal.status == "POSITIVE"
    assert result.terminal.confidence == 0


def test_minimal_probe_authority_scope_is_not_fresh24() -> None:
    from itda.contracts.phase5_nvidia_recovery import MINIMAL_PROBE_AUTHORITY_ID

    assert "fresh-d24" not in MINIMAL_PROBE_AUTHORITY_ID


def test_minimal_probe_public_artifact_is_exact_closed_and_fully_digested() -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbePublicArtifact
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    request = build_minimal_probe_request(_bundles()[0])
    artifact = _public_artifact(request)
    assert NvidiaMinimalProbePublicArtifact.model_validate(artifact).request_sha256 == (
        request.request_sha256
    )
    for mutation in (
        {**artifact, "extra": True},
        {**artifact, "model": "other"},
        {**artifact, "approval_payload_sha256": "0" * 64},
        {**artifact, "request_artifact_sha256": "0" * 64},
    ):
        with pytest.raises(ValueError):
            NvidiaMinimalProbePublicArtifact.model_validate(mutation)


def test_stale_approval_rejects_different_artifact_with_same_request(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    request = build_minimal_probe_request(_bundles()[0])
    first_artifact = NvidiaMinimalProbePublicArtifact.model_validate(
        _public_artifact(request, checkout="a" * 64, commit="b" * 40)
    )
    second_artifact = NvidiaMinimalProbePublicArtifact.model_validate(
        _public_artifact(request, checkout="c" * 64, commit="d" * 40)
    )
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    approval = build_minimal_probe_approval_binding(
        request=request,
        artifact=first_artifact.model_dump(mode="json"),
        protected_state_sha256=descriptor.protected_state_sha256,
        secret_identity_sha256="e" * 64,
        secret_content_fingerprint="f" * 64,
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(approval)
    with pytest.raises(PermissionError, match="STALE_APPROVAL"):
        state.preflight(expected_artifact=second_artifact)
    with pytest.raises(PermissionError, match="STALE_APPROVAL"):
        state.claim_once(expected_artifact=second_artifact)
    assert not Path(descriptor.claim_target).exists()


def test_application_clean_source_helper_reuses_bootstrap_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from itda.cli import materialize_phase5_demo_profiles as command

    repository = tmp_path / "repo"
    planning = repository / ".planning"
    planning.mkdir(parents=True)
    config = planning / "config.json"
    config.write_text('{"mode":"first"}\n')
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
    subprocess.run(["git", "add", ".planning/config.json"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repository, check=True)
    config.write_text('{"mode":"second"}\n')
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.checkout_commit_sha256",
        lambda root: "a" * 40,
    )
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.checkout_manifest_sha256",
        lambda root: "b" * 64,
    )
    command._require_minimal_probe_committed_clean_source(repository)

    shadow = repository / ".planning" / "sitecustomize.py"
    shadow.write_text("malicious\n")
    with pytest.raises(RuntimeError, match="not committed and clean"):
        command._require_minimal_probe_committed_clean_source(repository)
    shadow.unlink()

    other = planning / "STATE.md"
    other.write_text("tracked\n")
    subprocess.run(["git", "add", ".planning/STATE.md"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "state"], cwd=repository, check=True)
    other.write_text("dirty\n")
    with pytest.raises(RuntimeError, match="not committed and clean"):
        command._require_minimal_probe_committed_clean_source(repository)


def test_application_preflight_with_clean_flag_accepts_config_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.pipeline.phase5_nvidia_recovery import build_minimal_probe_request

    repository = tmp_path / "repo"
    planning = repository / ".planning"
    planning.mkdir(parents=True)
    config = planning / "config.json"
    config.write_text('{"mode":"first"}\n')
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
    subprocess.run(["git", "add", ".planning/config.json"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repository, check=True)
    config.write_text('{"mode":"second"}\n')
    monkeypatch.setattr(command, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(
        command,
        "_minimal_probe_request_output",
        lambda path: repository / "request.json",
    )
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.checkout_commit_sha256",
        lambda root: "a" * 40,
    )
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.checkout_manifest_sha256",
        lambda root: "b" * 64,
    )
    monkeypatch.setattr(
        "itda.pipeline.phase5_nvidia_recovery.preflight_nvidia_invocation",
        lambda **kwargs: SimpleNamespace(
            request=build_minimal_probe_request(_bundles()[0]),
            source_inventory_sha256=(
                "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
            ),
            checkout_manifest_sha256="b" * 64,
        ),
    )
    command._require_minimal_probe_committed_clean_source(repository)
    payload = command._minimal_probe_preflight_payload(
        Path("request.json"),
        regenerate=True,
        repository_root=repository,
    )
    assert payload["checkout_commit_sha256"] == "a" * 40
    assert payload["checkout_manifest_sha256"] == "b" * 64


def test_manifest_binds_transitive_tracked_file_and_full_commit(tmp_path: Path) -> None:
    import subprocess

    from itda.pipeline.phase5_nvidia_recovery import (
        checkout_commit_sha256,
        checkout_manifest_sha256,
    )

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    transitive = tmp_path / "backend/src/itda/cli/freeze_preview.py"
    transitive.parent.mkdir(parents=True)
    transitive.write_text("before\n")
    lockfile = tmp_path / "backend/uv.lock"
    lockfile.write_text("lock\n")
    subprocess.run(["git", "add", "backend"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    first_manifest = checkout_manifest_sha256(tmp_path)
    first_commit = checkout_commit_sha256(tmp_path)
    transitive.write_text("after\n")
    subprocess.run(["git", "add", str(transitive.relative_to(tmp_path))], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "change"], cwd=tmp_path, check=True)
    assert checkout_manifest_sha256(tmp_path) != first_manifest
    assert checkout_commit_sha256(tmp_path) != first_commit


def test_strict_probe_profile_rejects_bad_scores_and_invented_evidence() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]

    def mutate(field: str, value: object) -> httpx.Response:
        payload = _response(bundle).json()
        content_text = payload["choices"][0]["message"]["content"]
        start = content_text.index("{")
        end = content_text.rindex("}") + 1
        content = json.loads(content_text[start:end])
        if field == "invented":
            content["evidence_ids"] = ["invented-id"]
            for key in content["evidence_justifications"]:
                content["evidence_justifications"][key] = ["invented-id"]
        else:
            content["axis_scores"]["H"] = value
        payload["choices"][0]["message"]["content"] = (
            "<<<ITDA_PROFILE_JSON_V3_START_4F3A6C91>>>"
            + json.dumps(content)
            + "<<<ITDA_PROFILE_JSON_V3_END_9B7D2E65>>>"
        )
        return httpx.Response(200, json=payload)

    for field, value in (("score", "76"), ("score", 101), ("invented", None)):
        result = execute_nvidia_minimal_probe_mock(
            bundle=bundle,
            response_handler=lambda request, f=field, v=value: mutate(f, v),
        )
        assert result.terminal.status == "MALFORMED"
        assert result.terminal.reason == "PROBE_RESPONSE_INVALID"


def test_secret_same_inode_restored_mtime_rewrite_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command

    secret_dir = tmp_path / ".secrets"
    secret_dir.mkdir(mode=0o700)
    secret = secret_dir / "itda-api.env"
    secret.write_text("NVIDIA_KEY=aaaaaaaa\n")
    secret.chmod(0o600)
    monkeypatch.setattr(command, "SECRET_FILE", secret)
    identity, fingerprint = command._minimal_probe_secret_binding(secret)
    before = secret.stat()
    secret.write_text("NVIDIA_KEY=bbbbbbbb\n")
    secret.chmod(0o600)
    __import__("os").utime(secret, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(PermissionError, match="continuity"):
        command._read_minimal_probe_secret(
            secret,
            expected_identity_sha256=identity,
            expected_content_fingerprint=fingerprint,
        )


def test_production_executor_rejects_missing_or_request_mismatched_claim() -> None:
    import inspect

    from itda.pipeline.phase5_nvidia_recovery import (
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_request,
        execute_nvidia_minimal_probe,
        synthetic_minimal_probe_claim,
    )

    signature = inspect.signature(execute_nvidia_minimal_probe)
    assert "claim" not in signature.parameters
    assert "reservation_sink" not in signature.parameters
    assert signature.parameters["state"].default is inspect.Parameter.empty
    assert signature.parameters["artifact"].default is inspect.Parameter.empty
    assert "client_factory" not in signature.parameters
    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    claim = synthetic_minimal_probe_claim(request).model_copy(
        update={"request_sha256": "0" * 64}
    )
    with pytest.raises(PermissionError, match="CLAIM_REQUIRED"):
        asyncio.run(
            _execute_nvidia_minimal_probe_transport(
                bundle=bundle,
                credential_reader=lambda: "never-read",
                client_factory=lambda **kwargs: (_ for _ in ()).throw(
                    AssertionError("client")
                ),
                claim=claim,
                expected_request=request,
                dispatch_marker=lambda: (_ for _ in ()).throw(
                    AssertionError("dispatch")
                ),
                terminal_sink=lambda result: (_ for _ in ()).throw(
                    AssertionError("terminal")
                ),
            )
        )


def test_attempted_malformed_and_negative_terminals_are_fully_charged() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    bundle = _bundles()[0]
    outcomes = (
        execute_nvidia_minimal_probe_mock(
            bundle=bundle,
            response_handler=lambda request: httpx.Response(503, content=b""),
        ).terminal,
        execute_nvidia_minimal_probe_mock(
            bundle=bundle,
            response_handler=lambda request: httpx.Response(
                200, content=b"not-json", headers={"content-length": "8"}
            ),
        ).terminal,
    )
    assert {terminal.status for terminal in outcomes} == {
        "DESIGNED_NEGATIVE",
        "MALFORMED",
    }
    for terminal in outcomes:
        assert terminal.attempt_count == 1
        assert terminal.committed_exposure_micro_usd == 500_000
        assert terminal.outstanding_exposure_micro_usd == 0
        assert terminal.secret_read is True
        assert terminal.client_constructed is True
        assert terminal.network_attempted is True


def test_zero_byte_non_200_response_is_retained_and_verifiable() -> None:
    from itda.pipeline.phase5_nvidia_recovery import execute_nvidia_minimal_probe_mock

    result = execute_nvidia_minimal_probe_mock(
        bundle=_bundles()[0],
        response_handler=lambda request: httpx.Response(503, content=b""),
    )
    assert result.raw_response == b""
    assert result.terminal.raw_response_sha256 == hashlib.sha256(b"").hexdigest()
    assert result.terminal.status == "DESIGNED_NEGATIVE"


def test_durable_outcome_writes_evidence_before_commit_and_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeProtectedStateDescriptor
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    approval = build_minimal_probe_approval_binding(
        request=request,
        artifact=_public_artifact(request),
        protected_state_sha256=descriptor.protected_state_sha256,
        secret_identity_sha256="c" * 64,
        secret_content_fingerprint="d" * 64,
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(approval)
    claim = state.claim_once(expected_artifact=_artifact_model(request))
    state.reserve_once(claim=claim, request=request)
    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: "test-secret",
            client_factory=lambda **kwargs: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(503, content=b"")
                ),
                **kwargs,
            ),
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=lambda result: None,
        )
    )
    original = state._persist_outcome_evidence

    def fail_after_evidence(**kwargs: object) -> None:
        original(**kwargs)  # type: ignore[arg-type]
        raise OSError("fault after fsync")

    monkeypatch.setattr(state, "_persist_outcome_evidence", fail_after_evidence)
    with pytest.raises(OSError, match="fault after fsync"):
        state.record_outcome(result)
    ledger = Path(descriptor.ledger_target).read_text(encoding="utf-8").splitlines()
    assert len(ledger) == 1
    monkeypatch.setattr(state, "_persist_outcome_evidence", original)
    state.record_outcome(result)
    state.record_outcome(result)
    assert len(Path(descriptor.ledger_target).read_text(encoding="utf-8").splitlines()) == 2
    state.verify_outcome(request=request, terminal=result.terminal)


def test_protected_verifier_rejects_extra_ledger_fields(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeProtectedStateDescriptor
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    approval = build_minimal_probe_approval_binding(
        request=request,
        artifact=_public_artifact(request),
        protected_state_sha256=descriptor.protected_state_sha256,
        secret_identity_sha256="c" * 64,
        secret_content_fingerprint="d" * 64,
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(approval)
    claim = state.claim_once(expected_artifact=_artifact_model(request))
    state.reserve_once(claim=claim, request=request)
    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: "test-secret",
            client_factory=lambda **kwargs: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(503, content=b"negative")
                ),
                **kwargs,
            ),
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=lambda result: None,
        )
    )
    state.record_outcome(result)
    ledger_path = Path(descriptor.ledger_target)
    rows = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    rows[0]["extra"] = True
    ledger_path.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))
    with pytest.raises(ValueError, match="ledger entry"):
        state.verify_outcome(request=request, terminal=result.terminal)


def test_malformed_terminal_persists_but_neutral_verifier_rejects(
    tmp_path: Path,
) -> None:
    from itda.contracts.phase5_nvidia_recovery import NvidiaMinimalProbeProtectedStateDescriptor
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    approval = build_minimal_probe_approval_binding(
        request=request,
        artifact=_public_artifact(request),
        protected_state_sha256=descriptor.protected_state_sha256,
        secret_identity_sha256="c" * 64,
        secret_content_fingerprint="d" * 64,
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(approval)
    claim = state.claim_once(expected_artifact=_artifact_model(request))
    state.reserve_once(claim=claim, request=request)
    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: "test-secret",
            client_factory=lambda **kwargs: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, content=b"not-json")
                ),
                **kwargs,
            ),
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=state.record_outcome,
        )
    )
    assert result.terminal.status == "MALFORMED"
    with pytest.raises(ValueError, match="malformed terminal"):
        state.verify_outcome(request=request, terminal=result.terminal)


def test_cancellation_persists_dispatch_and_interrupted_terminal(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="c" * 64,
            secret_content_fingerprint="d" * 64,
        )
    )
    claim = state.claim_once(expected_artifact=artifact)
    state.reserve_once(claim=claim, request=request)

    class CancelStream:
        async def __aenter__(self):
            raise asyncio.CancelledError

        async def __aexit__(self, *args: object) -> None:
            return None

    class CancelClient:
        def stream(self, *args: object, **kwargs: object) -> CancelStream:
            return CancelStream()

        async def aclose(self) -> None:
            return None

    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: "test-secret",
            client_factory=lambda **kwargs: CancelClient(),  # type: ignore[return-value]
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=state.record_outcome,
        )
    )
    assert result.terminal.reason == "PROBE_INTERRUPTED"
    assert (Path(descriptor.journal_target) / "dispatch.json").exists()
    assert len(Path(descriptor.ledger_target).read_text().splitlines()) == 2


def test_fresh_state_reconciles_unresolved_dispatch_without_provider(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    first = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    first.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="c" * 64,
            secret_content_fingerprint="d" * 64,
        )
    )
    claim = first.claim_once(expected_artifact=artifact)
    first.reserve_once(claim=claim, request=request)
    first.record_dispatch(claim=claim, request=request)
    recovered = MinimalProbeDurableAuthorityState(
        descriptor=descriptor
    ).reconcile_interrupted(request=request, expected_artifact=artifact)
    assert recovered is not None
    assert recovered.terminal.reason == "PROBE_INTERRUPTED"
    assert len(Path(descriptor.ledger_target).read_text().splitlines()) == 2
    reopened = MinimalProbeDurableAuthorityState(
        descriptor=descriptor
    ).reconcile_interrupted(request=request, expected_artifact=artifact)
    assert reopened is not None
    assert reopened.terminal == recovered.terminal


def test_fresh_state_reconciles_existing_evidence_before_commit(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _attempted_result,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    first = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    first.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="c" * 64,
            secret_content_fingerprint="d" * 64,
        )
    )
    claim = first.claim_once(expected_artifact=artifact)
    first.reserve_once(claim=claim, request=request)
    first.record_dispatch(claim=claim, request=request)
    result = _attempted_result(
        status="DESIGNED_NEGATIVE",
        reason="HTTP_503",
        request=request,
        claim=claim,
        raw_response=b"negative",
    )
    directory = first._open_root(create=False)
    try:
        first._persist_outcome_evidence(
            directory=directory,
            result=result,
            terminal=result.terminal,
        )
    finally:
        __import__("os").close(directory)
    assert len(Path(descriptor.ledger_target).read_text().splitlines()) == 1
    recovered = MinimalProbeDurableAuthorityState(
        descriptor=descriptor
    ).reconcile_interrupted(request=request, expected_artifact=artifact)
    assert recovered is not None
    assert recovered.terminal == result.terminal
    assert recovered.raw_response == b"negative"
    assert len(Path(descriptor.ledger_target).read_text().splitlines()) == 2


def test_reconcile_rejects_stale_artifact_without_mutation(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    request = build_minimal_probe_request(_bundles()[0])
    first_artifact = NvidiaMinimalProbePublicArtifact.model_validate(
        _public_artifact(request, checkout="a" * 64, commit="b" * 40)
    )
    second_artifact = NvidiaMinimalProbePublicArtifact.model_validate(
        _public_artifact(request, checkout="c" * 64, commit="d" * 40)
    )
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=first_artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="e" * 64,
            secret_content_fingerprint="f" * 64,
        )
    )
    claim = state.claim_once(expected_artifact=first_artifact)
    state.reserve_once(claim=claim, request=request)
    state.record_dispatch(claim=claim, request=request)
    before = {
        path.relative_to(descriptor.state_root).as_posix(): path.read_bytes()
        for path in Path(descriptor.state_root).rglob("*")
        if path.is_file()
    }
    with pytest.raises(PermissionError, match="STALE_APPROVAL"):
        MinimalProbeDurableAuthorityState(descriptor=descriptor).reconcile_interrupted(
            request=request,
            expected_artifact=second_artifact,
        )
    after = {
        path.relative_to(descriptor.state_root).as_posix(): path.read_bytes()
        for path in Path(descriptor.state_root).rglob("*")
        if path.is_file()
    }
    assert after == before


def test_verifier_rejects_noncanonical_ledger_and_extra_journal_file(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="c" * 64,
            secret_content_fingerprint="d" * 64,
        )
    )
    claim = state.claim_once(expected_artifact=artifact)
    state.reserve_once(claim=claim, request=request)
    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: "test-secret",
            client_factory=lambda **kwargs: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(503, content=b"negative")
                ),
                **kwargs,
            ),
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=state.record_outcome,
        )
    )
    ledger = Path(descriptor.ledger_target)
    canonical = ledger.read_bytes()
    ledger.write_bytes(canonical.replace(b'"amount_micro_usd"', b' "amount_micro_usd"', 1))
    with pytest.raises(ValueError, match="canonical"):
        state.verify_outcome(request=request, terminal=result.terminal)
    ledger.write_bytes(canonical)
    extra = Path(descriptor.journal_target) / "extra.json"
    extra.write_text("{}")
    extra.chmod(0o600)
    with pytest.raises(ValueError, match="journal inventory"):
        state.verify_outcome(request=request, terminal=result.terminal)


def test_cancellation_barrier_persists_exactly_once_without_task_leak(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="c" * 64,
            secret_content_fingerprint="d" * 64,
        )
    )
    claim = state.claim_once(expected_artifact=artifact)
    state.reserve_once(claim=claim, request=request)
    entered = __import__("threading").Event()
    release = __import__("threading").Event()
    calls = 0

    def sink(result: object) -> None:
        nonlocal calls
        calls += 1
        entered.set()
        release.wait(timeout=5)
        state.record_outcome(result)  # type: ignore[arg-type]

    async def run() -> object:
        task = asyncio.create_task(
            _execute_nvidia_minimal_probe_transport(
                bundle=bundle,
                credential_reader=lambda: "test-secret",
                client_factory=lambda **kwargs: httpx.AsyncClient(
                    transport=httpx.MockTransport(
                        lambda request: httpx.Response(503, content=b"negative")
                    ),
                    **kwargs,
                ),
                claim=claim,
                expected_request=request,
                dispatch_marker=lambda: state.record_dispatch(
                    claim=claim, request=request
                ),
                terminal_sink=sink,
            )
        )
        await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        release.set()
        return await task

    result = asyncio.run(run())
    assert calls == 1
    assert result.terminal.status == "DESIGNED_NEGATIVE"  # type: ignore[union-attr]
    assert [json.loads(line)["operation"] for line in Path(
        descriptor.ledger_target
    ).read_text().splitlines()] == ["RESERVE", "COMMIT"]


def test_protected_verifier_rejects_extra_root_entry(tmp_path: Path) -> None:
    from itda.contracts.phase5_nvidia_recovery import (
        NvidiaMinimalProbeProtectedStateDescriptor,
        NvidiaMinimalProbePublicArtifact,
    )
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        _execute_nvidia_minimal_probe_transport,
        build_minimal_probe_approval_binding,
        build_minimal_probe_request,
    )

    bundle = _bundles()[0]
    request = build_minimal_probe_request(bundle)
    artifact = NvidiaMinimalProbePublicArtifact.model_validate(_public_artifact(request))
    descriptor = NvidiaMinimalProbeProtectedStateDescriptor.from_root(
        state_root=str(tmp_path / "probe")
    )
    state = MinimalProbeDurableAuthorityState(descriptor=descriptor)
    state.install_approval(
        build_minimal_probe_approval_binding(
            request=request,
            artifact=artifact.model_dump(mode="json"),
            protected_state_sha256=descriptor.protected_state_sha256,
            secret_identity_sha256="c" * 64,
            secret_content_fingerprint="d" * 64,
        )
    )
    claim = state.claim_once(expected_artifact=artifact)
    state.reserve_once(claim=claim, request=request)
    result = asyncio.run(
        _execute_nvidia_minimal_probe_transport(
            bundle=bundle,
            credential_reader=lambda: "test-secret",
            client_factory=lambda **kwargs: httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(503, content=b"negative")
                ),
                **kwargs,
            ),
            claim=claim,
            expected_request=request,
            dispatch_marker=lambda: state.record_dispatch(claim=claim, request=request),
            terminal_sink=state.record_outcome,
        )
    )
    extra = Path(descriptor.state_root) / "extra.json"
    extra.write_text("{}")
    extra.chmod(0o600)
    with pytest.raises(PermissionError, match="ROOT_INVENTORY"):
        state.verify_outcome(request=request, terminal=result.terminal)


def test_minimal_probe_paths_reject_ancestor_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli import materialize_phase5_demo_profiles as command
    from itda.pipeline.phase5_nvidia_recovery import (
        MinimalProbeDurableAuthorityState,
        MinimalProbeProtectedStateResolver,
    )

    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    secret = real / "itda-api.env"
    secret.write_text("NVIDIA_KEY=x\n")
    secret.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(command, "SECRET_FILE", alias / "itda-api.env")
    with pytest.raises((OSError, PermissionError, ValueError)):
        command._minimal_probe_secret_identity(alias / "itda-api.env")
    protected = alias / "protected"
    with pytest.raises((OSError, PermissionError, ValueError)):
        descriptor = MinimalProbeProtectedStateResolver(
            protected_state_root=protected
        ).descriptor
        MinimalProbeDurableAuthorityState(descriptor=descriptor).read_approval()


def test_bootstrap_rejects_before_application_import(tmp_path: Path) -> None:
    import subprocess

    bootstrap = Path("backend/src/itda/minimal_probe_bootstrap.py").resolve()
    marker = tmp_path / "imported.marker"
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('imported')\n"
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(bootstrap),
            "nvidia-minimal-probe-live",
        ],
        cwd=Path.cwd(),
        env={**__import__("os").environ, "PYTHONPATH": str(shadow)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 2
    assert not marker.exists()
    assert "itda.cli.materialize_phase5_demo_profiles" not in completed.stderr


def test_bootstrap_accepts_legitimate_virtualenv_origins_and_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda import minimal_probe_bootstrap as bootstrap

    paths = __import__("sysconfig").get_paths()
    purelib = Path(paths["purelib"])
    virtualenv = SimpleNamespace(__file__=str(purelib / "_virtualenv.py"))
    distutils_hack = SimpleNamespace(
        __file__=str(purelib / "_distutils_hack/__init__.py")
    )
    package = Path(bootstrap.__file__).absolute().parent
    environment_src = purelib.parents[3] / "src"
    legitimate_modules = {
        "_virtualenv": virtualenv,
        "_distutils_hack": distutils_hack,
    }
    legitimate_paths = [
        paths["stdlib"],
        paths["platstdlib"],
        paths["purelib"],
        str(environment_src),
        str(package.parent),
    ]
    monkeypatch.setattr(sys, "argv", [str(Path(bootstrap.__file__).absolute())])
    bootstrap._validate_import_origin(
        Path.cwd(),
        modules=legitimate_modules,
        search_path=legitimate_paths,
    )

    malicious = SimpleNamespace(__file__="/tmp/malicious-hook.py")
    with pytest.raises(PermissionError, match="MODULE_ORIGIN|SYMLINKED_ORIGIN"):
        bootstrap._validate_import_origin(
            Path.cwd(),
            modules={**legitimate_modules, "malicious_hook": malicious},
            search_path=legitimate_paths,
        )


def test_bootstrap_accepts_only_exact_tracked_config_drift(tmp_path: Path) -> None:
    import subprocess

    from itda import minimal_probe_bootstrap as bootstrap

    repository = tmp_path / "repo"
    repository.mkdir()
    planning = repository / ".planning"
    planning.mkdir()
    config = planning / "config.json"
    config.write_text('{"mode":"first"}\n')
    other = planning / "STATE.md"
    other.write_text("clean\n")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
    subprocess.run(["git", "add", ".planning"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=repository, check=True)

    config.write_text('{"mode":"second"}\n')
    bootstrap._validate_checkout(repository)

    other.write_text("dirty\n")
    with pytest.raises(PermissionError, match="TRACKED_DIRTY"):
        bootstrap._validate_checkout(repository)
    other.write_text("clean\n")

    real_config = planning / "real-config.json"
    config.rename(real_config)
    config.symlink_to(real_config.name)
    with pytest.raises(PermissionError, match="CONFIG_INVALID"):
        bootstrap._validate_checkout(repository)


def test_bootstrap_environment_cannot_redirect_repository_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from itda import minimal_probe_bootstrap as bootstrap

    expected = Path(bootstrap.__file__).absolute().parents[3]
    monkeypatch.setenv("ITDA_MINIMAL_PROBE_BOOTSTRAP_ROOT", str(tmp_path))
    assert bootstrap._repository_root() == expected


def test_install_and_live_are_distinct_cli_commands_without_live_approval_flag() -> None:
    from itda.cli.materialize_phase5_demo_profiles import _parser

    help_text = _parser().format_help()
    assert "nvidia-minimal-probe-install-approval" in help_text
    parser = _parser()
    live = parser.parse_args(
        [
            "nvidia-minimal-probe-live",
            "--request",
            "artifacts/public/phase5/nvidia-minimal-probe-request.json",
            "--protected-state-root",
            "artifacts/restricted/catalog/phase5-nvidia-minimal-probe",
            "--secret-env-file",
            ".secrets/itda-api.env",
            "--terminal-output",
            "artifacts/reports/phase5/nvidia-minimal-probe-terminal.json",
        ]
    )
    assert not hasattr(live, "approval_sha256")
