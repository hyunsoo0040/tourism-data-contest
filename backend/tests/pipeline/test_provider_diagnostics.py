from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import httpx
import pytest

import itda.cli.collect_preview as collect_preview_module
import itda.collectors.diagnostics as diagnostics_module
from itda.cli.collect_preview import CHECK_MALFORMED
from itda.cli.collect_preview import main as collect_preview_main
from itda.collectors.base import RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnostics, ProviderDiagnosticsError

SYNTHETIC_TOUR_KEY = "synthetic-tour-diagnostics-key"
SYNTHETIC_ODII_KEY = "synthetic-odii-diagnostics-key"
REAL_KTO_CLIENT = collect_preview_module.KorService2Client
REAL_ODII_CLIENT = collect_preview_module.OdiiClient


def _refuse_provider_client_construction(
    *,
    service_key: str,
    policy: RequestPolicy | None = None,
) -> object:
    del service_key, policy
    raise AssertionError("provider client construction requires an explicit fake transport")


@pytest.fixture(autouse=True)
def _block_real_provider_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        collect_preview_module,
        "KorService2Client",
        _refuse_provider_client_construction,
    )
    monkeypatch.setattr(
        collect_preview_module,
        "OdiiClient",
        _refuse_provider_client_construction,
    )


def _install_real_transport_clients(
    monkeypatch: pytest.MonkeyPatch,
    http_client: httpx.Client,
) -> None:
    monkeypatch.setattr(
        collect_preview_module,
        "KorService2Client",
        lambda *, service_key, policy: REAL_KTO_CLIENT(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
        ),
    )
    monkeypatch.setattr(
        collect_preview_module,
        "OdiiClient",
        lambda *, service_key, policy: REAL_ODII_CLIENT(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
        ),
    )
    monkeypatch.setattr(
        collect_preview_module,
        "_load_live_credentials",
        lambda: (SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY),
    )
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)


def _read_events(diagnostics: Path) -> tuple[Path, list[dict[str, object]]]:
    logs = list(diagnostics.glob("provider-collection-*.jsonl"))
    assert len(logs) == 1
    return logs[0], [json.loads(line) for line in logs[0].read_text(encoding="utf-8").splitlines()]


def test_live_diagnostics_never_reuse_stale_status_after_transport_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                503,
                json={"response": {"header": {"resultCode": "TEMP"}}},
                request=request,
            )
        raise httpx.ConnectError(
            "terminal transport detail must remain private",
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    _install_real_transport_clients(monkeypatch, http_client)
    output = tmp_path / "review"
    diagnostics = tmp_path / "diagnostics"
    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(output),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert attempts == 3
    assert not output.exists()
    log, events = _read_events(diagnostics)
    attempt_events = [event for event in events if event["event"] == "request_attempt"]
    assert [event["outcome"] for event in attempt_events] == [
        "response",
        "transport_error",
        "transport_error",
    ]
    assert [event.get("http_status") for event in attempt_events] == [503, None, None]
    terminal = events[-1]
    assert terminal["event"] == "terminal_failure"
    assert terminal["outcome"] == "retryable_for_resume"
    assert terminal["category"] == "network"
    assert "http_status" not in terminal
    assert "terminal transport detail" not in log.read_text(encoding="utf-8")


@pytest.mark.parametrize("status", [408, 429, 500, 501, 502, 503, 504, 599])
def test_live_diagnostics_preserve_retryable_status_policy(
    status: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(status, json={"status": "temporary"}, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    _install_real_transport_clients(monkeypatch, http_client)
    diagnostics = tmp_path / "diagnostics"
    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert attempts == 3
    _, events = _read_events(diagnostics)
    attempt_events = [event for event in events if event["event"] == "request_attempt"]
    assert [event["http_status"] for event in attempt_events] == [status, status, status]
    assert [event["retryable"] for event in attempt_events] == [True, True, True]
    assert [event["terminal_failure"] for event in attempt_events] == [False, False, True]
    assert events[-1]["http_status"] == status


@pytest.mark.parametrize("status", [300, 400, 499])
def test_live_diagnostics_preserve_nonretryable_status_policy(
    status: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(status, json={"status": "terminal"}, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    _install_real_transport_clients(monkeypatch, http_client)
    diagnostics = tmp_path / "diagnostics"
    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert attempts == 1
    _, events = _read_events(diagnostics)
    attempt_events = [event for event in events if event["event"] == "request_attempt"]
    assert len(attempt_events) == 1
    assert attempt_events[0]["http_status"] == status
    assert attempt_events[0]["retryable"] is False
    assert attempt_events[0]["terminal_failure"] is True
    assert events[-1]["http_status"] == status


def test_live_diagnostics_record_safe_result_and_partial_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                200,
                json={
                    "response": {
                        "header": {"resultCode": "0000", "resultMsg": "NORMAL SERVICE"},
                        "body": {"opaque_payload_marker": "must-not-be-logged"},
                    }
                },
                request=request,
            )
        raise httpx.ConnectError(
            (
                "must-not-be-logged "
                + str(request.url)
                + " "
                + SYNTHETIC_TOUR_KEY
                + " "
                + SYNTHETIC_ODII_KEY
            ),
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    _install_real_transport_clients(monkeypatch, http_client)
    diagnostics = tmp_path / "diagnostics"
    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert attempts == 4
    log, events = _read_events(diagnostics)
    success = next(event for event in events if event["event"] == "request_succeeded")
    assert success["upstream_result_code"] == "0000"
    assert success["upstream_result_message"] == "NORMAL SERVICE"
    terminal = events[-1]
    assert terminal["event"] == "terminal_failure"
    assert terminal["completed_operation_count"] == 1
    assert terminal["completed_operations"] == [
        {
            "candidate_place_id": "preview:1",
            "provider": "TOUR_API",
            "operation": "searchKeyword2",
        }
    ]
    serialized = log.read_text(encoding="utf-8")
    for forbidden in (
        SYNTHETIC_TOUR_KEY,
        SYNTHETIC_ODII_KEY,
        "must-not-be-logged",
        "opaque_payload_marker",
        "apis.data.go.kr",
        "serviceKey",
    ):
        assert forbidden not in serialized


def test_live_diagnostics_fsync_every_private_jsonl_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    regular_file_fsyncs = 0
    real_fsync = os.fsync

    def fsync_spy(file_descriptor: int) -> None:
        nonlocal regular_file_fsyncs
        if stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            regular_file_fsyncs += 1
        real_fsync(file_descriptor)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private transport detail", request=request)

    monkeypatch.setattr(diagnostics_module.os, "fsync", fsync_spy)
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    _install_real_transport_clients(monkeypatch, http_client)
    diagnostics = tmp_path / "diagnostics"
    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    log, events = _read_events(diagnostics)
    assert regular_file_fsyncs == len(events)
    assert stat.S_IMODE(diagnostics.stat().st_mode) == 0o700
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_ISREG(log.lstat().st_mode)
    assert not log.is_symlink()


def test_live_diagnostics_fsync_failure_prevents_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport_calls = 0
    regular_file_fsyncs = 0
    real_fsync = os.fsync

    def fsync_spy(file_descriptor: int) -> None:
        nonlocal regular_file_fsyncs
        if stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            regular_file_fsyncs += 1
            if regular_file_fsyncs == 2:
                raise OSError("private filesystem detail")
        real_fsync(file_descriptor)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(diagnostics_module.os, "fsync", fsync_spy)
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    _install_real_transport_clients(monkeypatch, http_client)
    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(tmp_path / "diagnostics"),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert regular_file_fsyncs == 2
    assert transport_calls == 0
    assert not (tmp_path / "review").exists()


@pytest.mark.parametrize("unsafe_kind", ["symlink-directory", "wrong-mode-directory"])
def test_live_diagnostics_reject_unsafe_directory_before_credentials_or_transport(
    unsafe_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_loads = 0
    client_constructions = 0
    diagnostics = tmp_path / "diagnostics"
    if unsafe_kind == "symlink-directory":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        diagnostics.symlink_to(target, target_is_directory=True)
    else:
        diagnostics.mkdir(mode=0o755)
        diagnostics.chmod(0o755)

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    def construct_client(
        *,
        service_key: str,
        policy: RequestPolicy | None = None,
    ) -> object:
        nonlocal client_constructions
        client_constructions += 1
        del service_key, policy
        raise AssertionError("provider client construction was not expected")

    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.setattr(collect_preview_module, "KorService2Client", construct_client)
    monkeypatch.setattr(collect_preview_module, "OdiiClient", construct_client)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    exit_code = collect_preview_main(
        [
            "--live",
            "--output",
            str(tmp_path / "review"),
            "--diagnostics-dir",
            str(diagnostics),
        ]
    )

    assert exit_code == CHECK_MALFORMED
    assert credential_loads == 0
    assert client_constructions == 0
    assert not (tmp_path / "review").exists()


def test_diagnostics_location_rejects_output_parent_symlink_alias(
    tmp_path: Path,
) -> None:
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir(mode=0o700)
    diagnostics.chmod(0o700)
    output_alias = tmp_path / "output-alias"
    output_alias.symlink_to(diagnostics, target_is_directory=True)

    with pytest.raises(ProviderDiagnosticsError):
        collect_preview_module._validate_diagnostics_location(
            output_alias / "review",
            diagnostics,
        )


def test_diagnostics_location_rejects_missing_parent_traversal_both_directions(
    tmp_path: Path,
) -> None:
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir(mode=0o700)
    diagnostics.chmod(0o700)
    with pytest.raises(ProviderDiagnosticsError):
        collect_preview_module._validate_diagnostics_location(
            tmp_path / "missing-output" / ".." / "diagnostics" / "review",
            diagnostics,
        )

    with pytest.raises(ProviderDiagnosticsError):
        collect_preview_module._validate_diagnostics_location(
            tmp_path / "review",
            tmp_path / "missing-diagnostics" / ".." / "review" / "diagnostics",
        )


def test_live_collection_revalidates_after_diagnostics_directory_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validation_calls = 0
    credential_loads = 0
    real_validate = collect_preview_module._validate_diagnostics_location

    def validate_after_creation(output: Path, diagnostics_dir: Path) -> None:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 2:
            raise ProviderDiagnosticsError
        real_validate(output, diagnostics_dir)

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    monkeypatch.setattr(
        collect_preview_module,
        "_validate_diagnostics_location",
        validate_after_creation,
    )
    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    diagnostics = tmp_path / "diagnostics"

    assert (
        collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
        == CHECK_MALFORMED
    )
    assert validation_calls == 2
    assert credential_loads == 0
    assert diagnostics.is_dir()
    assert list(diagnostics.iterdir()) == []


@pytest.mark.parametrize("collision_kind", ["regular", "symlink"])
def test_live_diagnostics_create_is_exclusive_and_never_overwrites(
    collision_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_loads = 0
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir(mode=0o700)
    diagnostics.chmod(0o700)
    fixed_hex = "a" * 32
    collision = diagnostics / f"provider-collection-{fixed_hex}.jsonl"
    target = tmp_path / "collision-target"
    target.write_text("unchanged", encoding="utf-8")
    if collision_kind == "regular":
        collision.write_text("unchanged", encoding="utf-8")
        collision.chmod(0o600)
    else:
        collision.symlink_to(target)

    class _FixedUuid:
        hex = fixed_hex

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    monkeypatch.setattr(diagnostics_module, "uuid4", lambda: _FixedUuid())
    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    assert (
        collect_preview_main(
            [
                "--live",
                "--output",
                str(tmp_path / "review"),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
        == CHECK_MALFORMED
    )
    assert credential_loads == 0
    assert collision.read_text(encoding="utf-8") == "unchanged"
    assert target.read_text(encoding="utf-8") == "unchanged"
    assert not (tmp_path / "review").exists()


def test_live_cli_rejects_duplicate_diagnostics_arguments_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_loads = 0

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    first = tmp_path / "first-diagnostics"
    second = tmp_path / "second-diagnostics"
    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    exit_code = collect_preview_main(
        [
            "--live",
            "--output",
            str(tmp_path / "review"),
            "--diagnostics-dir",
            str(first),
            "--diagnostics-dir",
            str(second),
        ]
    )

    assert exit_code == CHECK_MALFORMED
    assert credential_loads == 0
    assert not first.exists()
    assert not second.exists()


@pytest.mark.parametrize(
    "argv_builder",
    [
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
            "0",
        ],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
            "-1",
        ],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
            "nan",
        ],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
            "inf",
        ],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
            "300.0001",
        ],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
            "5",
            "--request-timeout-seconds",
            "6",
        ],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
            "--request-timeout-seconds",
        ],
        lambda root: [
            "--check-review",
            str(root / "review-manifest.json"),
            "--request-timeout-seconds",
            "5",
        ],
    ],
    ids=[
        "zero",
        "negative",
        "nan",
        "infinity",
        "over-maximum",
        "duplicate",
        "missing",
        "outside-live",
    ],
)
def test_cli_rejects_invalid_request_timeout_before_sensitive_execution(
    argv_builder: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_loads = 0
    client_constructions = 0

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    def construct_client(*, service_key: str, policy: RequestPolicy | None = None) -> object:
        nonlocal client_constructions
        client_constructions += 1
        del service_key, policy
        raise AssertionError("provider client construction was not expected")

    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.setattr(collect_preview_module, "KorService2Client", construct_client)
    monkeypatch.setattr(collect_preview_module, "OdiiClient", construct_client)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    assert callable(argv_builder)
    assert collect_preview_main(argv_builder(tmp_path)) == CHECK_MALFORMED
    assert credential_loads == 0
    assert client_constructions == 0
    assert not (tmp_path / "diagnostics").exists()
    assert not (tmp_path / "review").exists()


@pytest.mark.parametrize(
    ("timeout_args", "expected_timeout"),
    [
        ([], 5.0),
        (["--request-timeout-seconds", "300"], 300.0),
    ],
    ids=["default", "explicit-maximum"],
)
def test_live_request_timeout_policy_reaches_both_clients_and_diagnostics(
    timeout_args: list[str],
    expected_timeout: float,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    observed_policies: list[tuple[str, RequestPolicy]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("private transport detail", request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))

    def kto_client(*, service_key: str, policy: RequestPolicy) -> object:
        observed_policies.append(("TOUR_API", policy))
        return REAL_KTO_CLIENT(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
        )

    def odii_client(*, service_key: str, policy: RequestPolicy) -> object:
        observed_policies.append(("ODII", policy))
        return REAL_ODII_CLIENT(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
        )

    monkeypatch.setattr(collect_preview_module, "KorService2Client", kto_client)
    monkeypatch.setattr(collect_preview_module, "OdiiClient", odii_client)
    monkeypatch.setattr(
        collect_preview_module,
        "_load_live_credentials",
        lambda: (SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY),
    )
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    output = tmp_path / "review"
    diagnostics = tmp_path / "diagnostics"

    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(output),
                "--diagnostics-dir",
                str(diagnostics),
                *timeout_args,
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert attempts == 3
    assert [(provider, policy.timeout_seconds) for provider, policy in observed_policies] == [
        ("TOUR_API", expected_timeout),
        ("ODII", expected_timeout),
    ]
    _, events = _read_events(diagnostics)
    attempt_events = [event for event in events if event["event"] == "request_attempt"]
    assert [event["timeout_seconds"] for event in attempt_events] == [
        expected_timeout,
        expected_timeout,
        expected_timeout,
    ]
    assert not output.exists()


def test_live_cli_rejects_control_character_diagnostics_path_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_loads = 0

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    unsafe = tmp_path / "diagnostics\nprivate"
    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    exit_code = collect_preview_main(
        [
            "--live",
            "--output",
            str(tmp_path / "review"),
            "--diagnostics-dir",
            str(unsafe),
        ]
    )

    assert exit_code == CHECK_MALFORMED
    assert credential_loads == 0
    assert not unsafe.exists()


def test_diagnostics_scan_both_credentials_before_each_write(tmp_path: Path) -> None:
    diagnostics_dir = tmp_path / "diagnostics"
    diagnostics = ProviderDiagnostics.create(diagnostics_dir)
    diagnostics.bind_credentials(SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY)
    diagnostics.run_started()
    operation = diagnostics.operation(
        candidate_place_id="preview:1",
        candidate_name="불국사",
        provider="TOUR_API",
        operation="searchKeyword2",
    )

    try:
        with pytest.raises(ProviderDiagnosticsError, match="provider diagnostics unavailable"):
            diagnostics.request_succeeded(
                operation,
                attempt=1,
                http_status=200,
                upstream_result_code="0000",
                upstream_result_message=SYNTHETIC_ODII_KEY,
            )
    finally:
        diagnostics.close()

    log, events = _read_events(diagnostics_dir)
    assert [event["event"] for event in events] == ["run_started"]
    serialized = log.read_text(encoding="utf-8")
    assert SYNTHETIC_TOUR_KEY not in serialized
    assert SYNTHETIC_ODII_KEY not in serialized


def test_diagnostics_post_open_setup_failure_closes_and_unlinks_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics_dir = tmp_path / "diagnostics"
    opened_file_descriptor: int | None = None
    real_open = os.open
    real_fsync = os.fsync

    def open_spy(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_file_descriptor
        file_descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if isinstance(path, str) and path.startswith("provider-collection-"):
            opened_file_descriptor = file_descriptor
        return file_descriptor

    def fsync_spy(file_descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
            raise OSError("private directory sync detail")
        real_fsync(file_descriptor)

    monkeypatch.setattr(diagnostics_module.os, "open", open_spy)
    monkeypatch.setattr(diagnostics_module.os, "fsync", fsync_spy)

    with pytest.raises(ProviderDiagnosticsError, match="provider diagnostics unavailable"):
        ProviderDiagnostics.create(diagnostics_dir)

    assert opened_file_descriptor is not None
    with pytest.raises(OSError):
        os.fstat(opened_file_descriptor)
    assert list(diagnostics_dir.iterdir()) == []


@pytest.mark.parametrize(
    "argv_builder",
    [
        lambda root: [
            "--check-review",
            str(root / "review-manifest.json"),
            "--diagnostics-dir",
            str(root / "diagnostics"),
        ],
        lambda root: ["--live", "--output", str(root / "review"), "--diagnostics-dir"],
        lambda root: [
            "--live",
            "--output",
            str(root / "review"),
            "--diagnostics-dir",
            str(root / "review" / "diagnostics"),
        ],
    ],
    ids=["check-review-combination", "missing-value", "output-overlap"],
)
def test_cli_rejects_malformed_diagnostics_arguments_without_credentials(
    argv_builder: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_loads = 0

    def load_credentials() -> tuple[str, str]:
        nonlocal credential_loads
        credential_loads += 1
        return SYNTHETIC_TOUR_KEY, SYNTHETIC_ODII_KEY

    monkeypatch.setattr(collect_preview_module, "_load_live_credentials", load_credentials)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    assert callable(argv_builder)
    assert collect_preview_main(argv_builder(tmp_path)) == CHECK_MALFORMED
    assert credential_loads == 0
    assert not (tmp_path / "diagnostics").exists()
    assert not (tmp_path / "review").exists()
