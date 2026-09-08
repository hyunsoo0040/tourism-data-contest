from __future__ import annotations

import hashlib
import io
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from itda.cli import collect_catalog_enrichment as collector_cli
from itda.cli.collect_catalog_enrichment import (
    _regular_file_bytes,
    collect_authorized_round,
    parser,
    verify_authorization_preconditions,
    verify_authorization_receipt,
    verify_collection_log,
    verify_collection_report,
)
from itda.contracts.authority import AuthorityTokenV2
from itda.contracts.catalog_enrichment import (
    FrozenEnrichmentIssuance,
    build_enrichment_bundle,
    build_enrichment_plan,
    canonical_json_bytes,
    publish_enrichment_bundle,
)

POOL_PATH = (
    Path(__file__).parents[3]
    / "artifacts/restricted/catalog/v2/enrichment/enrichment-candidate-pool.json"
)
NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


class FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = body or (
            b'{"response":{"header":{"resultCode":"0000","resultMsg":"OK"},'
            b'"body":{"items":{"item":[]}}}}'
        )
        self.headers = headers or {"content-type": "application/json"}


class RecordingRequester:
    def __init__(self, responses: list[FakeResponse] | None = None) -> None:
        self.responses = responses or []
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if self.responses:
            return self.responses.pop(0)
        return FakeResponse()


def _current_plan() -> dict[str, object]:
    pool = json.loads(POOL_PATH.read_bytes())
    return build_enrichment_plan(pool, attempts=3)


def _build_round(tmp_path: Path) -> tuple[Path, str, dict[str, object]]:
    plan = _current_plan()
    plan_bytes = canonical_json_bytes(plan)
    round_id = hashlib.sha256(plan_bytes).hexdigest()
    root = tmp_path / "enrichment" / "rounds" / round_id
    issued_at = NOW - timedelta(minutes=5)
    frozen = FrozenEnrichmentIssuance(
        issued_at=issued_at,
        expires_at=NOW + timedelta(hours=1),
        nonce="1" * 64,
        reviewer_id="phase2-operator",
        code_sha256="2" * 64,
        config_sha256="3" * 64,
        permission_evidence_sha256=hashlib.sha256(
            canonical_json_bytes(plan["permission_evidence"])
        ).hexdigest(),
        previous_round_ref_sha256=None,
    )
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=frozen,
    )
    publish_enrichment_bundle(
        bundle,
        initial_reference_path=root.parents[1] / "initial-round-ref.json",
    )
    return root, round_id, bundle.authorization_request


def _build_remediation_round(
    previous_root: Path,
    previous_round_id: str,
    *,
    nonce: str,
    ancestry_depth: int,
) -> tuple[Path, str, dict[str, object]]:
    manifest_path = previous_root / "enrichment-round-manifest.json"
    manifest_bytes = canonical_json_bytes(
        {
            "schema_version": "test-round-manifest-v1",
            "round_id": previous_round_id,
            "ancestry_depth": ancestry_depth,
        }
    )
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o600)
    previous_ref = {
        "round_id": previous_round_id,
        "round_root": previous_root.as_posix(),
        "round_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "ancestry_depth": ancestry_depth,
    }
    previous_ref_sha256 = hashlib.sha256(canonical_json_bytes(previous_ref)).hexdigest()
    plan = _current_plan()
    plan["remediation"] = {
        "failed_request_identity": str(plan["requests"][0]["request_identity"]),
        "previous_round_ref": previous_ref,
    }
    plan_bytes = canonical_json_bytes(plan)
    round_id = hashlib.sha256(plan_bytes).hexdigest()
    root = previous_root.parent / round_id
    frozen = FrozenEnrichmentIssuance(
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(hours=1),
        nonce=nonce,
        reviewer_id="phase2-operator",
        code_sha256="2" * 64,
        config_sha256="3" * 64,
        permission_evidence_sha256=hashlib.sha256(
            canonical_json_bytes(plan["permission_evidence"])
        ).hexdigest(),
        previous_round_ref_sha256=previous_ref_sha256,
    )
    bundle = build_enrichment_bundle(
        plan=plan,
        round_root=root,
        round_id=round_id,
        frozen=frozen,
    )
    root.mkdir(mode=0o700)
    for name, payload in bundle.files.items():
        path = root / name
        path.write_bytes(payload)
        path.chmod(0o600)
    return root, round_id, bundle.authorization_request


def _token(request: dict[str, object]) -> str:
    return AuthorityTokenV2(
        action="enrichment-collect",
        request_sha256=str(request["request_sha256"]),
        state_attestation_sha256=str(request["state_attestation_sha256"]),
        target_sha256=str(request["target_sha256"]),
        reviewer_id=str(request["reviewer_id"]),
        binding_sha256=str(request["binding_sha256"]),
        nonce=str(request["nonce"]),
    ).serialize()


def _credential(tmp_path: Path, value: str = "fixture-secret-value") -> Path:
    path = tmp_path / "tourapi.env"
    path.write_text(f"TOUR_API_SERVICE_KEY={value}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_stable_file_read_retries_transient_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "immutable.response"
    payload = b'{"response":{"header":{"resultCode":"0000"}}}'
    path.write_bytes(payload)
    actual_fstat = os.fstat
    calls = 0

    def transient_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = actual_fstat(descriptor)
        if calls == 2:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns + 1,
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
            )
        return metadata

    monkeypatch.setattr(
        "itda.cli.collect_catalog_enrichment.os.fstat",
        transient_fstat,
    )

    assert _regular_file_bytes(path) == payload
    assert calls == 4


def test_stable_file_read_fails_closed_after_bounded_instability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "changing.response"
    path.write_bytes(b'{"response":{"header":{"resultCode":"0000"}}}')
    actual_fstat = os.fstat
    calls = 0

    def unstable_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = actual_fstat(descriptor)
        if calls % 2 == 0:
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns + calls,
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
            )
        return metadata

    monkeypatch.setattr(
        "itda.cli.collect_catalog_enrichment.os.fstat",
        unstable_fstat,
    )

    with pytest.raises(ValueError, match="changed while it was being read"):
        _regular_file_bytes(path)
    assert calls == 6


def test_every_mode_requires_explicit_round_root_and_round_id() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(["--verify-report", "report.json"])
    with pytest.raises(SystemExit):
        parser().parse_args(["--round-root", "/tmp/round", "--verify-report", "report.json"])
    with pytest.raises(SystemExit):
        parser().parse_args(["--round-id", "a" * 64, "--verify-report", "report.json"])

    args = parser().parse_args(
        [
            "--round-root",
            "/tmp/" + "a" * 64,
            "--round-id",
            "a" * 64,
            "--verify-authorization-receipt",
            "receipt.json",
            "--verify-report",
            "report.json",
            "--verify-log",
            "log.jsonl",
        ]
    )
    assert args.verify_authorization_receipt == Path("receipt.json")
    assert args.verify_report == Path("report.json")
    assert args.verify_log == Path("log.jsonl")


def test_cli_has_no_value_taking_authority_token_option() -> None:
    command_parser = parser()
    option_strings = {
        option for action in command_parser._actions for option in action.option_strings
    }

    assert "--authorization-token" not in option_strings
    assert "--authorization-token-stdin" in option_strings
    with pytest.raises(SystemExit):
        command_parser.parse_args(
            [
                "--round-root",
                "/tmp/example",
                "--round-id",
                "a" * 64,
                "--collect",
                "--authorization-token",
                "synthetic-secret-authority",
            ]
        )


def test_cli_reads_authority_from_stdin_without_putting_it_in_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw_token = "synthetic-secret-authority"
    argv = [
        "--round-root",
        str(tmp_path / "round"),
        "--round-id",
        "a" * 64,
        "--collect",
        "--authorization-token-stdin",
    ]
    captured: dict[str, object] = {}

    def fake_collect(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"authority_consumed": True}

    monkeypatch.setattr(collector_cli, "collect_authorized_round", fake_collect)
    monkeypatch.setattr(
        collector_cli,
        "sys",
        SimpleNamespace(stdin=io.StringIO(raw_token + "\n")),
        raising=False,
    )

    assert raw_token not in argv
    assert collector_cli.main(argv) == 0
    assert captured["authorization_token"] == raw_token
    output = capsys.readouterr()
    assert raw_token not in output.out
    assert raw_token not in output.err


def test_cli_defaults_to_hidden_prompt_without_putting_authority_in_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw_token = "synthetic-secret-authority"
    argv = [
        "--round-root",
        str(tmp_path / "round"),
        "--round-id",
        "a" * 64,
        "--collect",
    ]
    captured: dict[str, object] = {}

    def fake_collect(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"authority_consumed": True}

    monkeypatch.setattr(collector_cli, "collect_authorized_round", fake_collect)
    monkeypatch.setattr(collector_cli.getpass, "getpass", lambda _prompt: raw_token)

    assert raw_token not in argv
    assert collector_cli.main(argv) == 0
    assert captured["authorization_token"] == raw_token
    output = capsys.readouterr()
    assert raw_token not in output.out
    assert raw_token not in output.err


def test_preconditions_rederive_round_and_exact_d15_budget(tmp_path: Path) -> None:
    root, round_id, _ = _build_round(tmp_path)

    summary = verify_authorization_preconditions(
        root / "enrichment-authorization-request.json",
        round_root=root,
        round_id=round_id,
        now=NOW,
    )

    assert summary == {
        "ancestry_depth": 1,
        "attempts_per_request": 3,
        "overall_timeout_seconds": 180 * 3 * 300,
        "per_attempt_timeout_seconds": 300,
        "quota_estimate": 540,
        "request_count": 180,
        "round_id": round_id,
    }
    assert not (root / "enrichment-authorization-receipt.json").exists()
    assert not (root / "enrichment-collection-report.json").exists()
    assert not (root / "enrichment-collection-log.jsonl").exists()
    assert not (root / "raw").exists()


def test_missing_credentials_stop_before_nonce_consumption_or_output(
    tmp_path: Path,
) -> None:
    root, round_id, request = _build_round(tmp_path)
    missing = tmp_path / "missing.env"
    requester = RecordingRequester()

    with pytest.raises(ValueError, match="credential"):
        collect_authorized_round(
            round_root=root,
            round_id=round_id,
            authorization_token=_token(request),
            credential_path=missing,
            credential_variable="TOUR_API_SERVICE_KEY",
            now=NOW,
            requester=requester,
        )

    assert requester.calls == []
    assert not (root / "enrichment-authorization-receipt.json").exists()
    assert not (root / "enrichment-collection-report.json").exists()
    assert not (root / "enrichment-collection-log.jsonl").exists()
    assert not (root / "raw").exists()


def test_authorized_collection_is_exact_bounded_append_only_and_secret_safe(
    tmp_path: Path,
) -> None:
    root, round_id, request = _build_round(tmp_path)
    credential = _credential(tmp_path)
    requester = RecordingRequester()
    raw_token = _token(request)

    result = collect_authorized_round(
        round_root=root,
        round_id=round_id,
        authorization_token=raw_token,
        credential_path=credential,
        credential_variable="TOUR_API_SERVICE_KEY",
        now=NOW,
        requester=requester,
    )

    assert result["attempted_request_count"] == 180
    assert result["successful_request_count"] == 180
    assert len(requester.calls) == 180
    assert all(call["timeout"] == 300 for call in requester.calls)
    assert all(call["follow_redirects"] is False for call in requester.calls)
    assert {call["url"].rsplit("/", 1)[-1] for call in requester.calls} == {
        "detailCommon2",
        "detailIntro2",
        "detailImage2",
    }
    assert all("serviceKey" in call["params"] for call in requester.calls)

    receipt_path = root / "enrichment-authorization-receipt.json"
    report_path = root / "enrichment-collection-report.json"
    log_path = root / "enrichment-collection-log.jsonl"
    receipt = verify_authorization_receipt(
        receipt_path,
        round_root=root,
        round_id=round_id,
    )
    report = verify_collection_report(
        report_path,
        round_root=root,
        round_id=round_id,
    )
    log = verify_collection_log(
        log_path,
        round_root=root,
        round_id=round_id,
    )
    assert receipt["receipt_count"] == 1
    assert report["successful_request_count"] == 180
    assert report["resumable_request_count"] == 0
    assert log["terminal_event_count"] == 180

    durable = b"".join(path.read_bytes() for path in (receipt_path, report_path, log_path))
    assert raw_token.encode("ascii") not in durable
    assert b"fixture-secret-value" not in durable
    assert b"serviceKey" not in durable
    collector_files = [receipt_path, report_path, log_path, *list((root / "raw").rglob("*"))]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in collector_files if path.is_file())
    collector_directories = [
        root / "raw",
        *(path for path in (root / "raw").rglob("*") if path.is_dir()),
    ]
    assert all(
        path.stat().st_mode & 0o777 == 0o700 for path in collector_directories
    )


def test_traversal_mismatched_round_and_stale_state_fail_without_side_effects(
    tmp_path: Path,
) -> None:
    root, round_id, _ = _build_round(tmp_path)
    outputs = (
        root / "enrichment-authorization-receipt.json",
        root / "enrichment-collection-report.json",
        root / "enrichment-collection-log.jsonl",
        root / "raw",
    )

    with pytest.raises(ValueError, match="traversal"):
        verify_authorization_preconditions(
            root / ".." / round_id / "enrichment-authorization-request.json",
            round_root=root / ".." / round_id,
            round_id=round_id,
            now=NOW,
        )
    with pytest.raises(ValueError, match="basename"):
        verify_authorization_preconditions(
            root / "enrichment-authorization-request.json",
            round_root=root,
            round_id="a" * 64,
            now=NOW,
        )

    state_path = root / "enrichment-state-attestation.json"
    state = json.loads(state_path.read_bytes())
    state["request_plan_sha256"] = "b" * 64
    state_path.write_bytes(canonical_json_bytes(state))
    with pytest.raises(ValueError, match="state attestation|parents|digest"):
        verify_authorization_preconditions(
            root / "enrichment-authorization-request.json",
            round_root=root,
            round_id=round_id,
            now=NOW,
        )
    assert not any(path.exists() for path in outputs)


def test_two_and_three_round_ancestry_is_exact_and_cannot_be_mixed(
    tmp_path: Path,
) -> None:
    first_root, first_id, _ = _build_round(tmp_path)
    second_root, second_id, _ = _build_remediation_round(
        first_root,
        first_id,
        nonce="4" * 64,
        ancestry_depth=1,
    )
    third_root, third_id, _ = _build_remediation_round(
        second_root,
        second_id,
        nonce="5" * 64,
        ancestry_depth=2,
    )

    assert (
        verify_authorization_preconditions(
            second_root / "enrichment-authorization-request.json",
            round_root=second_root,
            round_id=second_id,
            now=NOW,
        )["ancestry_depth"]
        == 2
    )
    assert (
        verify_authorization_preconditions(
            third_root / "enrichment-authorization-request.json",
            round_root=third_root,
            round_id=third_id,
            now=NOW,
        )["ancestry_depth"]
        == 3
    )
    with pytest.raises(ValueError, match="basename|selected round"):
        verify_authorization_preconditions(
            second_root / "enrichment-authorization-request.json",
            round_root=second_root,
            round_id=third_id,
            now=NOW,
        )

    second_manifest = second_root / "enrichment-round-manifest.json"
    second_manifest.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="manifest digest"):
        verify_authorization_preconditions(
            third_root / "enrichment-authorization-request.json",
            round_root=third_root,
            round_id=third_id,
            now=NOW,
        )


def test_replay_and_concurrent_nonce_use_are_rejected_without_second_traffic(
    tmp_path: Path,
) -> None:
    root, round_id, request = _build_round(tmp_path)
    credential = _credential(tmp_path)
    token = _token(request)
    winner = RecordingRequester()
    collect_authorized_round(
        round_root=root,
        round_id=round_id,
        authorization_token=token,
        credential_path=credential,
        credential_variable="TOUR_API_SERVICE_KEY",
        now=NOW,
        requester=winner,
    )
    before = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name != ".enrichment-authority.lock"
    }
    loser = RecordingRequester()
    with pytest.raises(Exception, match="nonce|consumed"):
        collect_authorized_round(
            round_root=root,
            round_id=round_id,
            authorization_token=token,
            credential_path=credential,
            credential_variable="TOUR_API_SERVICE_KEY",
            now=NOW,
            requester=loser,
        )
    after = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name != ".enrichment-authority.lock"
    }
    assert loser.calls == []
    assert after == before

    other_root, other_id, other_request = _build_round(tmp_path / "other")
    other_credential = _credential(tmp_path / "other")
    requesters = (RecordingRequester(), RecordingRequester())

    def submit(index: int) -> object:
        return collect_authorized_round(
            round_root=other_root,
            round_id=other_id,
            authorization_token=_token(other_request),
            credential_path=other_credential,
            credential_variable="TOUR_API_SERVICE_KEY",
            now=NOW,
            requester=requesters[index],
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(submit, index) for index in range(2)]
    successes = 0
    replays = 0
    for future in futures:
        try:
            future.result()
            successes += 1
        except Exception as exc:
            assert "nonce" in str(exc) or "consumed" in str(exc)
            replays += 1
    assert (successes, replays) == (1, 1)
    assert sorted(len(requester.calls) for requester in requesters) == [0, 180]


def test_provider_failures_secret_reflection_and_partial_results_remain_addressable(
    tmp_path: Path,
) -> None:
    root, round_id, request = _build_round(tmp_path)
    credential = _credential(tmp_path)
    reflected = (
        b'{"response":{"header":{"resultCode":"0000","resultMsg":"OK"},'
        b'"body":{"echo":"fixture-secret-value"}}}'
    )
    requester = RecordingRequester(
        responses=[
            FakeResponse(status_code=503, body=b'{"error":"busy"}'),
            FakeResponse(status_code=503, body=b'{"error":"busy"}'),
            FakeResponse(status_code=503, body=b'{"error":"busy"}'),
            FakeResponse(body=reflected),
        ]
    )

    result = collect_authorized_round(
        round_root=root,
        round_id=round_id,
        authorization_token=_token(request),
        credential_path=credential,
        credential_variable="TOUR_API_SERVICE_KEY",
        now=NOW,
        requester=requester,
    )
    report = verify_collection_report(
        root / "enrichment-collection-report.json",
        round_root=root,
        round_id=round_id,
    )
    log = verify_collection_log(
        root / "enrichment-collection-log.jsonl",
        round_root=root,
        round_id=round_id,
    )
    assert result["successful_request_count"] == 179
    assert result["resumable_request_count"] == 1
    assert report["covered_request_count"] == 180
    assert report["resumable_request_count"] == 1
    assert log["event_count"] == 182
    assert any(
        b"REDACTED_SECRET_REFLECTION" in path.read_bytes()
        for path in (root / "raw").rglob("*.response")
    )
    durable = b"".join(
        path.read_bytes()
        for path in (
            root / "enrichment-authorization-receipt.json",
            root / "enrichment-collection-report.json",
            root / "enrichment-collection-log.jsonl",
        )
    )
    assert b"fixture-secret-value" not in durable
    assert _token(request).encode("ascii") not in durable


def test_transport_failure_is_bounded_and_does_not_follow_redirects(
    tmp_path: Path,
) -> None:
    root, round_id, request = _build_round(tmp_path)
    credential = _credential(tmp_path)

    class TimeoutThenSuccess(RecordingRequester):
        def get(self, url: str, **kwargs: Any) -> FakeResponse:
            self.calls.append({"url": url, **kwargs})
            if len(self.calls) <= 3:
                raise httpx.ReadTimeout("fixture timeout")
            return FakeResponse()

    requester = TimeoutThenSuccess()
    result = collect_authorized_round(
        round_root=root,
        round_id=round_id,
        authorization_token=_token(request),
        credential_path=credential,
        credential_variable="TOUR_API_SERVICE_KEY",
        now=NOW,
        requester=requester,
    )
    assert result["resumable_request_count"] == 1
    assert len(requester.calls) == 182
    assert all(call["timeout"] == 300 for call in requester.calls)
    assert all(call["follow_redirects"] is False for call in requester.calls)
